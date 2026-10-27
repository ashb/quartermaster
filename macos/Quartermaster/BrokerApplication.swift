import AppKit
import Darwin
import QuartermasterApprovalUI
import QuartermasterSecurity

@MainActor
final class BrokerApplication: NSObject, NSApplicationDelegate, ObservableObject {
    private enum ConnectionPhase { case disconnected, connecting, connected }
    @Published private(set) var status = "Disconnected"
    @Published private(set) var vaultStatus: BrokerVaultStatus?
    private var client: (any BrokerClient)?
    private var task: Task<Void, Never>?
    private var active: (any ApprovalWindow)?
    private var presentation: Int32?
    private var settingsIsOpen = false
    private var operationEnrolled = false
    private var connectionPhase: ConnectionPhase = .disconnected
    private let setActivationPolicy: (NSApplication.ActivationPolicy) -> Void
    private let openConnection: () async throws -> any BrokerClient
    private let loadApprovalKey: () throws -> Data
    private let controls = ApprovalControlWorkflow()
    lazy var preferences = SettingsEditor { [weak self] command in
        guard let client = self?.client else { throw BrokerFailure.disconnected }
        return try await client.call(command)
    }

    override convenience init() {
        self.init(setActivationPolicy: { NSApplication.shared.setActivationPolicy($0) })
    }

    init(
        setActivationPolicy: @escaping (NSApplication.ActivationPolicy) -> Void,
        openConnection: @escaping () async throws -> any BrokerClient = { try await BrokerConnection.connect() },
        loadApprovalKey: @escaping () throws -> Data = { try ApprovalKeyStore().loadOrCreate() }
    ) {
        self.setActivationPolicy = setActivationPolicy
        self.openConnection = openConnection
        self.loadApprovalKey = loadApprovalKey
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        setActivationPolicy(.accessory)
        connectIfNeeded()
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        connectIfNeeded()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        connectIfNeeded()
        active?.show(centred: false)
        updateActivationPolicy()
        return false
    }

    private func connectIfNeeded() {
        if connectionPhase == .disconnected || client?.disconnected == true { reconnect() }
    }

    func reconnect() {
        connectionPhase = .connecting
        preferences.connecting()
        status = "Starting Quartermaster…"
        vaultStatus = nil
        active?.cancel()
        task?.cancel()
        client?.cancel()
        client = nil
        operationEnrolled = false
        task = Task {
            do {
                let connection = try await openConnection()
                try Task.checkCancellation()
                client = connection
                guard case .hello("development") = try await connection.call(.hello) else {
                    throw BrokerFailure.invalidMessage
                }
                let key = try loadApprovalKey()
                guard case .settingsStatus = try await connection.call(.settingsRegister(publicKey: key)) else {
                    throw BrokerFailure.invalidMessage
                }
                await reloadPreferences()
                try Task.checkCancellation()
                connectionPhase = .connected
                while !Task.isCancelled {
                    guard !connection.disconnected else { throw BrokerFailure.disconnected }
                    if active == nil && !controls.busy && !preferences.busy,
                        preferences.snapshot?.provider != nil, preferences.snapshot?.settings?.github != nil
                    {
                        do { try await poll(connection, key: key) } catch let error as BrokerControlError
                            where [.denied, .sessionEnded, .expired, .busy, .providerChanged].contains(error)
                        {
                            operationEnrolled = false
                        }
                    }
                    try await Task.sleep(for: .milliseconds(200))
                }
            } catch {
                guard !Task.isCancelled else { return }
                active?.cancel()
                client?.cancel()
                client = nil
                vaultStatus = nil
                status = "Backend unavailable: \(error)"
                connectionPhase = .disconnected
                preferences.connectionLost(error)
            }
        }
    }

    private func poll(_ connection: any BrokerClient, key: Data) async throws {
        if !operationEnrolled {
            guard case .enrolled = try await connection.call(.enroll(publicKey: key)) else {
                throw BrokerFailure.invalidMessage
            }
            operationEnrolled = true
        }
        switch try await connection.call(.next) {
        case .idle: break
        case .review(let review):
            guard active == nil, !controls.busy, !preferences.busy else {
                _ = try await connection.call(.cancel(id: review.id))
                return
            }
            let pending = try BrokerPending(client: connection, review: review)
            do { presentation = try DialogPresentationLease.acquire() } catch DialogPresentationLease.Failure
                .alreadyPresented
            {
                pending.cancel()
                return
            }
            let dialog = ApprovalDialog(
                presentation: ApprovalPresentation(
                    request: pending.request, provider: pending.provider, readGrant: pending.readGrant,
                    apiRequest: pending.apiRequest), backend: pending)
            present(dialog)
        default: throw BrokerFailure.invalidMessage
        }
    }

    func reviewPreferences() {
        reviewSettings(importing: false)
    }

    func reviewMigration() {
        reviewSettings(importing: true)
    }

    private func reviewSettings(importing: Bool) {
        if let active {
            active.show(centred: false)
            return
        }
        guard !controls.busy, !preferences.busy else {
            preferences.report(BrokerControlError.busy)
            return
        }
        guard let client, !client.disconnected else {
            preferences.connectionLost(BrokerFailure.disconnected)
            return
        }
        Task {
            await controls.perform {
                var reviewID: String?
                do {
                    let review: SettingsReview
                    if importing {
                        review = try await preferences.reviewMigration()
                    } else {
                        review = try await preferences.review()
                    }
                    reviewID = review.id
                    let pending = try SettingsPending(client: client, review: review)
                    presentation = try DialogPresentationLease.acquire()
                    let dialog = SettingsApprovalDialog(review: review, document: pending.document, backend: pending)
                    present(dialog, settings: true)
                } catch {
                    if let reviewID { _ = try? await client.call(.settingsCancel(id: reviewID)) }
                    if !(error is CancellationError) { preferences.report(error) }
                }
            }
        }
    }

    func stageEnrollment(password: String) {
        guard active == nil, !controls.busy else { return }
        Task {
            await controls.perform {
                await preferences.enroll(password: password)
            }
        }
    }

    func discardChanges() {
        (active as? SettingsApprovalDialog)?.cancel()
        preferences.discardDraft()
        Task { await controls.perform { await preferences.cancel() } }
    }

    func settingsOpened() {
        settingsIsOpen = true
        updateActivationPolicy()
        connectIfNeeded()
    }

    func settingsClosed() {
        settingsIsOpen = false
        (active as? SettingsApprovalDialog)?.cancel()
        updateActivationPolicy()
        preferences.discardDraft()
        Task { await preferences.cancel() }
    }

    private func updateActivationPolicy() {
        setActivationPolicy(settingsIsOpen || active != nil ? .regular : .accessory)
    }

    func revokeReads() {
        Task {
            await controls.revokeReadAccess(cancelApproval: { self.active?.cancel() }) {
                do {
                    guard let client = self.client, case .readGrantsRevoked = try await client.call(.revokeReadGrants)
                    else { throw BrokerFailure.disconnected }
                    self.operationEnrolled = false
                    self.status = "Read access revoked"
                } catch { self.preferences.report(error) }
            }
        }
    }

    func vault(_ command: BrokerCommand) {
        if case .vaultLock = command { active?.cancel() }
        Task {
            do {
                guard let client, case .vaultStatus(let vault) = try await client.call(command) else {
                    throw BrokerFailure.disconnected
                }
                operationEnrolled = false
                vaultStatus = vault
                status = "Vault: \(vault.state.rawValue)"
            } catch { preferences.report(error) }
        }
    }

    private func refreshVaultStatus() async {
        do {
            guard let client, case .vaultStatus(let vault) = try await client.call(.vaultStatus) else {
                throw BrokerFailure.disconnected
            }
            try Task.checkCancellation()
            vaultStatus = vault
        } catch {
            guard !Task.isCancelled else { return }
            vaultStatus = nil
        }
    }

    func reloadPreferences() async {
        await preferences.load()
        await refreshVaultStatus()
        guard !Task.isCancelled else { return }
        if preferences.available {
            status = preferences.snapshot?.migration == nil ? "Connected" : "Settings import required — open Settings"
        } else {
            status = "Protected settings unavailable"
        }
    }

    func present(_ dialog: any ApprovalWindow, settings: Bool = false) {
        dialog.onClose = { [weak self] in
            guard let self else { return }
            active = nil
            releasePresentation()
            updateActivationPolicy()
            if settings {
                operationEnrolled = false
                Task { await reloadPreferences() }
            }
        }
        active = dialog
        updateActivationPolicy()
        dialog.show(centred: true)
    }

    private func releasePresentation() {
        if let presentation { close(presentation) }
        presentation = nil
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        active?.cancel()
        task?.cancel()
        client?.cancel()
        releasePresentation()
        return .terminateNow
    }
}
