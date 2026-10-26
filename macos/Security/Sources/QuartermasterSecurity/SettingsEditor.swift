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
        case existing(SettingsProvider)
        case staged(ticket: String, provider: SettingsProvider)

        var choice: SettingsProviderChoice {
            switch self {
            case .keep: .keep
            case .forget: .forget
            case .existing(let provider): .existing(provider)
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
    @Published public var draft = BrokerSettings()
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

    public init(call: @escaping @MainActor (BrokerCommand) async throws -> BrokerReply) { self.call = call }

    public var available: Bool {
        snapshot?.session != nil && ["configured", "unconfigured"].contains(snapshot?.state ?? "")
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

    public var retainedProvider: SettingsProvider? {
        if case .existing(let provider) = selection { return provider }
        return nil
    }

    private var hasChanges: Bool {
        if draft != (snapshot?.settings ?? BrokerSettings()) { return true }
        switch selection {
        case .keep: return false
        case .forget: return snapshot?.provider != nil
        case .existing(let provider): return provider != snapshot?.provider
        case .staged: return true
        }
    }

    public var canReview: Bool { available && !busy && !enrollmentNeedsVerification && hasChanges }

    public func load() async {
        await perform {
            let snapshot = try await currentSnapshot()
            self.snapshot = snapshot
            draft = snapshot.settings ?? BrokerSettings()
            enrollment = EnrollmentDraft(provider: snapshot.provider)
            selection = .keep
            message =
                snapshot.state == "unavailable"
                ? "Protected settings are unavailable. Reconnect to retry."
                : "Changes take effect only after you review and approve them with Touch ID."
        }
    }

    public func enroll(password: String) async {
        await perform {
            guard available else { throw BrokerControlError.unavailable }
            let inputs = enrollment.normalized
            selection = .keep
            guard
                case .enrollmentStaged(let ticket, let provider) = try await call(
                    .stageEnrollment(
                        server: inputs.server, email: inputs.email, password: password,
                        itemID: inputs.itemID.isEmpty ? nil : inputs.itemID))
            else { throw BrokerControlError.invalidMessage }
            guard enrollment.normalized == inputs else { throw Failure.unverifiedEnrollment }
            selection = .staged(ticket: ticket, provider: provider)
            message = "Vault verified. Review and approve to select this enrolment."
        }
    }

    public func useExisting(_ provider: SettingsProvider) {
        guard available, !busy, snapshot?.retained.contains(provider) == true else { return }
        enrollment = EnrollmentDraft(provider: provider)
        selection = .existing(provider)
        message = "The retained enrolment will be verified and unlocked when you approve."
    }
    public func forget() {
        enrollment = EnrollmentDraft(provider: snapshot?.provider)
        selection = .forget
        message = "Review and approve to disconnect the vault. Encrypted cache files are retained."
    }

    public func review() async throws -> SettingsReview {
        guard !busy, available, let snapshot else { throw BrokerControlError.busy }
        guard !enrollmentNeedsVerification else { throw Failure.unverifiedEnrollment }
        guard hasChanges else { throw Failure.noChanges }
        busy = true
        defer { busy = false }
        guard
            case .settingsReview(let review) = try await call(
                .prepareSettings(revision: snapshot.revision, settings: draft, provider: selection.choice))
        else { throw BrokerControlError.invalidMessage }
        return review
    }

    public func cancel() async {
        await perform {
            switch try await call(.settingsCancel(id: nil)) {
            case .canceled:
                draft = snapshot?.settings ?? BrokerSettings()
                message = "Changes discarded."
            case .alreadyAdmitted:
                message = "This change is already being saved. Checking the approved revision…"
                let current = try await currentSnapshot()
                snapshot = current
                draft = current.settings ?? BrokerSettings()
                message = "The change was already admitted. Current approved revision: \(current.revision)."
            default: throw BrokerControlError.invalidMessage
            }
            selection = .keep
            enrollment = EnrollmentDraft(provider: snapshot?.provider)
        }
    }

    private func currentSnapshot() async throws -> SettingsSnapshot {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(30))
        while true {
            guard case .settingsStatus(let current) = try await call(.settingsStatus) else {
                throw BrokerControlError.invalidMessage
            }
            if current.state != "applying" { return current }
            guard clock.now < deadline else { throw BrokerControlError.unavailable }
            try await Task.sleep(for: .milliseconds(100))
        }
    }

    public func report(_ error: any Error) {
        message =
            "Could not complete this change: \(error). Approved settings remain in the backend; reconnect to inspect the current revision."
    }

    private func perform(_ operation: () async throws -> Void) async {
        guard !busy else { return }
        busy = true
        defer { busy = false }
        do { try await operation() } catch { report(error) }
    }
}
