import Combine
import Foundation

public struct EnrollmentDraft: Equatable, Sendable {
    public var server = ""
    public var email = ""
    public var itemID = ""

    fileprivate init(provider: SettingsProvider?) {
        server = provider?.binding.server ?? ""
        email = provider?.binding.email ?? ""
        itemID = provider?.binding.itemID ?? ""
    }

    fileprivate var normalized: Self {
        var result = self
        result.server = server.trimmingCharacters(in: .whitespacesAndNewlines)
        result.email = email.trimmingCharacters(in: .whitespacesAndNewlines)
        result.itemID = itemID.trimmingCharacters(in: .whitespacesAndNewlines)
        return result
    }
}

@MainActor
public final class SettingsEditor: ObservableObject {
    private enum Selection {
        case keep, forget
        case staged(ticket: String, provider: SettingsProvider)

        var choice: SettingsProviderChoice {
            switch self {
            case .keep: .keep
            case .forget: .forget
            case .staged(let ticket, _): .staged(ticket)
            }
        }
    }

    public enum Failure: LocalizedError {
        case unverifiedEnrollment, noChanges
        public var errorDescription: String? {
            switch self {
            case .unverifiedEnrollment: "Enrolment details changed. Verify Vault before reviewing changes."
            case .noChanges: "There are no changes to review."
            }
        }
    }
    @Published public var draft = BrokerSettings() {
        didSet { if draft.github == nil { pendingRepositories = [] } }
    }
    @Published public private(set) var pendingRepositories: [RepositoryName] = []
    @Published public var enrollment = EnrollmentDraft(provider: nil) {
        didSet {
            guard enrollment.normalized != oldValue.normalized else { return }
            selection = .keep
            if enrollmentNeedsVerification { message = Failure.unverifiedEnrollment.localizedDescription }
        }
    }
    @Published public private(set) var snapshot: SettingsSnapshot?
    @Published private var selection: Selection = .keep
    @Published public private(set) var busy = false
    @Published public private(set) var message = "Connecting to Quartermaster…"
    private let call: @MainActor (BrokerCommand) async throws -> BrokerReply
    private var generation = UUID()

    public init(call: @escaping @MainActor (BrokerCommand) async throws -> BrokerReply) { self.call = call }

    public var available: Bool {
        snapshot?.session != nil && ["configured", "unconfigured", "migrationRequired"].contains(snapshot?.state ?? "")
    }

    public var enrollmentNeedsVerification: Bool {
        if case .keep = selection {
            return enrollment.normalized != EnrollmentDraft(provider: snapshot?.provider).normalized
        }
        return false
    }

    public var stagedProvider: SettingsProvider? {
        if case .staged(_, let provider) = selection { return provider }
        return nil
    }

    private var hasChanges: Bool {
        if !pendingRepositories.isEmpty { return true }
        if draft != (snapshot?.settings ?? BrokerSettings()) { return true }
        switch selection {
        case .keep: return false
        case .forget: return snapshot?.provider != nil
        case .staged: return true
        }
    }

    public var canReview: Bool {
        available && !busy && snapshot?.migration == nil && !enrollmentNeedsVerification && hasChanges
    }
    public var canImport: Bool { available && !busy && snapshot?.migration?.source.supported == true }

    public func load() async {
        await perform {
            let generation = generation
            let snapshot = try await currentSnapshot()
            guard generation == self.generation else { throw CancellationError() }
            self.snapshot = snapshot
            discardDraft()
            message =
                snapshot.state == "unavailable"
                ? "Protected settings are unavailable. Reconnect to retry."
                : snapshot.migration != nil
                    ? "Import your previous settings or discard them before configuring Quartermaster."
                    : "Changes take effect only after you review and approve them with Touch ID."
        }
    }

    public func enroll(password: String) async {
        await perform {
            guard available else { throw BrokerControlError.unavailable }
            let inputs = enrollment.normalized
            let generation = generation
            selection = .keep
            guard
                case .enrollmentStaged(let ticket, let provider) = try await call(
                    .stageEnrollment(
                        server: inputs.server, email: inputs.email, password: password,
                        itemID: inputs.itemID.isEmpty ? nil : inputs.itemID))
            else { throw BrokerControlError.invalidMessage }
            guard generation == self.generation else {
                _ = try? await call(.settingsCancel(id: nil))
                throw CancellationError()
            }
            guard enrollment.normalized == inputs else { throw Failure.unverifiedEnrollment }
            selection = .staged(ticket: ticket, provider: provider)
            message = "Vault verified. Review and approve to select this enrolment."
        }
    }

    public func forget() {
        enrollment = EnrollmentDraft(provider: snapshot?.provider)
        selection = .forget
        message = "Review and approve to disconnect the vault. Encrypted cache files are retained."
    }

    public func review() async throws -> SettingsReview {
        guard !busy, available, let snapshot, snapshot.migration == nil else { throw BrokerControlError.busy }
        guard !enrollmentNeedsVerification else { throw Failure.unverifiedEnrollment }
        guard hasChanges else { throw Failure.noChanges }
        return try await prepareReview(
            .prepareSettings(
                revision: snapshot.revision, settings: draft, provider: selection.choice, additions: pendingRepositories
            ))
    }

    public func reviewMigration(_ action: SettingsMigrationAction = .importSettings) async throws -> SettingsReview {
        guard canImport, let migration = snapshot?.migration else { throw BrokerControlError.unavailable }
        let command: BrokerCommand =
            action == .importSettings
            ? .prepareSettingsImport(id: migration.source.id) : .prepareSettingsDiscard(id: migration.source.id)
        return try await prepareReview(command, expectedMigration: migration, action: action)
    }

    private func prepareReview(
        _ command: BrokerCommand, expectedMigration: SettingsMigration? = nil,
        action: SettingsMigrationAction = .importSettings
    ) async throws
        -> SettingsReview
    {
        let generation = generation
        busy = true
        defer { busy = false }
        guard
            case .settingsReview(let review) = try await call(command)
        else { throw BrokerControlError.invalidMessage }
        guard generation == self.generation else {
            _ = try? await call(.settingsCancel(id: review.id))
            throw CancellationError()
        }
        if let expected = expectedMigration {
            let document = try? JSONDecoder().decode(SettingsDocument.self, from: review.document)
            guard document?.migration == expected.source, document?.previous.revision == expected.revision,
                document?.proposed.settings == (action == .importSettings ? expected.settings : BrokerSettings()),
                document?.proposed.provider == (action == .importSettings ? expected.provider : nil),
                document?.additions == nil
            else {
                _ = try? await call(.settingsCancel(id: review.id))
                throw BrokerControlError.invalidMessage
            }
        }
        return review
    }

    public func discardDraft() {
        generation = UUID()
        draft = snapshot?.settings ?? BrokerSettings()
        enrollment = EnrollmentDraft(provider: snapshot?.provider)
        selection = .keep
        pendingRepositories = []
        message =
            snapshot?.migration == nil
            ? "Changes discarded." : "Import postponed. Your previous settings are unchanged."
    }

    public func cancel() async {
        await perform {
            let generation = generation
            let reply = try await call(.settingsCancel(id: nil))
            guard generation == self.generation else { throw CancellationError() }
            switch reply {
            case .canceled:
                discardDraft()
            case .alreadyAdmitted:
                message = "This change is already being saved. Checking the approved revision…"
                let current = try await currentSnapshot()
                guard generation == self.generation else { throw CancellationError() }
                snapshot = current
                discardDraft()
                message = "The change was already admitted. Current approved revision: \(current.revision)."
            default: throw BrokerControlError.invalidMessage
            }
        }
    }

    public func canAddRepository(_ value: String) -> Bool {
        guard !busy, available, snapshot?.migration == nil, let name = RepositoryName(fullName: value),
            let github = draft.github,
            github.repositories.count + pendingRepositories.count < 64,
            !pendingRepositories.contains(where: { $0.id == name.id }),
            !github.repositories.contains(where: { "\($0.owner)/\($0.name)".lowercased() == name.id })
        else { return false }
        return true
    }

    @discardableResult public func addRepository(_ value: String) -> Bool {
        guard canAddRepository(value), let name = RepositoryName(fullName: value) else { return false }
        pendingRepositories.append(name)
        message = "Repository identities will be verified when you save."
        return true
    }

    public func removeRepository(_ name: RepositoryName) { pendingRepositories.removeAll { $0.id == name.id } }

    private func currentSnapshot() async throws -> SettingsSnapshot {
        let generation = generation
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(30))
        while true {
            guard generation == self.generation else { throw CancellationError() }
            guard case .settingsStatus(let current) = try await call(.settingsStatus) else {
                throw BrokerControlError.invalidMessage
            }
            guard generation == self.generation else { throw CancellationError() }
            if current.state != "applying" { return current }
            guard clock.now < deadline else { throw BrokerControlError.unavailable }
            try await Task.sleep(for: .milliseconds(100))
        }
    }

    public func report(_ error: any Error) {
        message =
            "Could not complete this change: \(error). Approved settings remain in the backend; reconnect to inspect the current revision."
    }

    public func connectionLost(_ error: any Error) {
        invalidateSession()
        report(error)
    }

    public func connecting() {
        invalidateSession()
        message = "Connecting to Quartermaster…"
    }

    private func invalidateSession() {
        generation = UUID()
        if let snapshot {
            self.snapshot = SettingsSnapshot(
                state: "unavailable", revision: snapshot.revision, session: nil,
                settings: snapshot.settings, provider: snapshot.provider, migration: snapshot.migration)
        }
    }

    private func perform(_ operation: () async throws -> Void) async {
        guard !busy else { return }
        busy = true
        let generation = generation
        defer { busy = false }
        do { try await operation() } catch is CancellationError {} catch {
            if generation == self.generation { report(error) }
        }
    }
}
