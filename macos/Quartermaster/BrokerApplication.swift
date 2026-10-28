import AppKit
import Darwin
import QuartermasterApprovalUI
import QuartermasterSecurity

@MainActor
final class BrokerApplication: NSObject, NSApplicationDelegate, ObservableObject {
    private enum ConnectionPhase { case disconnected, connecting, connected }
    enum VaultActivity: Equatable {
        case idle, locking, syncing, unlocking, locked, synced, unlocked
        case failed(String)

        var busy: Bool { self == .locking || self == .syncing || self == .unlocking }
        var message: String? {
            switch self {
            case .idle: nil
            case .locking: "Locking vault…"
            case .syncing: "Syncing vault…"
            case .unlocking: "Unlocking vault…"
            case .locked: "Vault locked."
            case .synced: "Vault synced."
            case .unlocked: "Vault unlocked."
            case .failed(let message): message
            }
        }
    }
    private enum VaultAction { case lock, sync, unlock }
    @Published private(set) var status = "Disconnected"
    @Published private(set) var vaultStatus: BrokerVaultStatus?
    @Published private(set) var vaultActivity = VaultActivity.idle
    private var client: (any BrokerClient)?
    private var task: Task<Void, Never>?
    private var vaultTask: Task<Void, Never>?
    private var active: (any ApprovalWindow)?
    private var presentation: Int32?
    private var settingsIsOpen = false
    private weak var settingsWindow: NSWindow?
    private var operationEnrolled = false
    private var connectionPhase: ConnectionPhase = .disconnected
    private let setActivationPolicy: (NSApplication.ActivationPolicy) -> Void
    private let openConnection: () async throws -> any BrokerClient
    private let loadApprovalKey: () throws -> Data
    private let acquirePresentation: () throws -> Int32
    private let makeUnlockWindow: (VaultUnlockReview, any VaultUnlockBackend, Bool) -> any VaultUnlockWindow
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
        loadApprovalKey: @escaping () throws -> Data = { try ApprovalKeyStore().loadOrCreate() },
        acquirePresentation: @escaping () throws -> Int32 = { try DialogPresentationLease.acquire() },
        makeUnlockWindow: @escaping (VaultUnlockReview, any VaultUnlockBackend, Bool) -> any VaultUnlockWindow = {
            VaultUnlockDialog(review: $0, backend: $1, forSync: $2)
        }
    ) {
        self.setActivationPolicy = setActivationPolicy
        self.openConnection = openConnection
        self.loadApprovalKey = loadApprovalKey
        self.acquirePresentation = acquirePresentation
        self.makeUnlockWindow = makeUnlockWindow
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
        vaultTask?.cancel()
        vaultActivity = .idle
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
                    if active == nil && !controls.busy && !preferences.busy && !vaultActivity.busy,
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
                vaultTask?.cancel()
                if vaultActivity.busy {
                    vaultActivity = .failed("The backend disconnected. Reconnect and try again.")
                }
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
            guard active == nil, !controls.busy, !preferences.busy, !vaultActivity.busy else {
                _ = try await connection.call(.cancel(id: review.id))
                return
            }
            let pending = try BrokerPending(client: connection, review: review)
            do { presentation = try acquirePresentation() } catch DialogPresentationLease.Failure
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
        reviewSettings(migration: nil)
    }

    func reviewMigration(_ action: SettingsMigrationAction) {
        reviewSettings(migration: action)
    }

    private func reviewSettings(migration: SettingsMigrationAction?) {
        if let active {
            active.show(centred: false)
            return
        }
        guard !controls.busy, !preferences.busy, !vaultActivity.busy else {
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
                    if let migration {
                        review = try await preferences.reviewMigration(migration)
                    } else {
                        review = try await preferences.review()
                    }
                    reviewID = review.id
                    let pending = try SettingsPending(client: client, review: review)
                    presentation = try acquirePresentation()
                    let dialog = SettingsApprovalDialog(
                        review: review, document: pending.document, backend: pending, migration: migration)
                    present(dialog, settings: true)
                } catch {
                    if let reviewID { _ = try? await client.call(.settingsCancel(id: reviewID)) }
                    if !(error is CancellationError) { preferences.report(error) }
                }
            }
        }
    }

    func stageEnrollment(password: String) {
        guard active == nil, !controls.busy, !vaultActivity.busy else { return }
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

    func settingsOpened(_ window: NSWindow) {
        settingsWindow = window
        settingsIsOpen = true
        updateActivationPolicy()
        connectIfNeeded()
    }

    func settingsClosed() {
        settingsWindow = nil
        settingsIsOpen = false
        if vaultActivity == .unlocking || vaultActivity == .syncing {
            vaultTask?.cancel()
            vaultActivity = .failed("Vault operation dismissed.")
            status = vaultActivity.message ?? status
        }
        (active as? SettingsApprovalDialog)?.cancel()
        (active as? any VaultUnlockWindow)?.cancel()
        updateActivationPolicy()
        preferences.discardDraft()
        Task { await preferences.cancel() }
    }

    func postponeMigration() {
        guard preferences.snapshot?.migration != nil else { return }
        settingsWindow?.performClose(nil)
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
        switch command {
        case .vaultLock: runVault(.lock)
        case .vaultSync: runVault(.sync)
        default: return
        }
    }

    func unlockVault() { runVault(.unlock) }

    private func runVault(_ action: VaultAction) {
        if action == .lock {
            active?.cancel()
            vaultTask?.cancel()
        } else {
            guard !vaultActivity.busy else { return }
            guard active == nil, !controls.busy, !preferences.busy else {
                active?.show(centred: false)
                vaultActivity = .failed("Finish the current approval before continuing.")
                return
            }
        }
        vaultActivity =
            switch action {
            case .lock: .locking
            case .sync: .syncing
            case .unlock: .unlocking
            }
        status = vaultActivity.message ?? status
        vaultTask = Task {
            do {
                try Task.checkCancellation()
                guard let client else { throw BrokerFailure.disconnected }
                let vault: BrokerVaultStatus
                switch action {
                case .lock:
                    guard case .vaultStatus(let reply) = try await client.call(.vaultLock) else {
                        throw BrokerFailure.invalidMessage
                    }
                    vault = reply
                case .sync: vault = try await syncVault(client)
                case .unlock: vault = try await requestVaultUnlock(client, forSync: false)
                }
                operationEnrolled = false
                await refreshVaultStatus()
                try Task.checkCancellation()
                if vault.error != nil {
                    vaultActivity = .failed(vaultFailure(vault))
                } else {
                    vaultActivity =
                        switch action {
                        case .lock: .locked
                        case .sync: .synced
                        case .unlock: .unlocked
                        }
                }
                status = "Vault: \(vault.state.rawValue)"
            } catch {
                guard !Task.isCancelled else { return }
                await refreshVaultStatus()
                guard !Task.isCancelled else { return }
                let message: String
                switch error {
                case is CancellationError: message = "Unlock not completed."
                case VaultOperationFailure.reported(let vault): message = vaultFailure(vault)
                case BrokerControlError.expired: message = "The unlock timed out. Try again."
                case BrokerControlError.providerChanged, BrokerControlError.sessionEnded:
                    message = "The vault selection or session changed. Try again."
                case BrokerControlError.busy, DialogPresentationLease.Failure.alreadyPresented:
                    message = "Another approval is open. Finish it and try again."
                default: message = "Could not complete the vault operation. Reconnect and try again."
                }
                vaultActivity = .failed(message)
                status = vaultActivity.message ?? status
            }
        }
    }

    private func syncVault(_ client: any BrokerClient) async throws -> BrokerVaultStatus {
        var unlocked = false
        if vaultStatus?.state == .locked {
            _ = try await requestVaultUnlock(client, forSync: true)
            unlocked = true
        }
        vaultActivity = .syncing
        guard case .vaultStatus(let reply) = try await client.call(.vaultSync) else {
            throw BrokerFailure.invalidMessage
        }
        guard reply.state == .locked, reply.error != nil, !unlocked else { return reply }
        _ = try await requestVaultUnlock(client, forSync: true)
        vaultActivity = .syncing
        guard case .vaultStatus(let retry) = try await client.call(.vaultSync) else {
            throw BrokerFailure.invalidMessage
        }
        return retry
    }

    private func requestVaultUnlock(_ client: any BrokerClient, forSync: Bool) async throws -> BrokerVaultStatus {
        guard let snapshot = preferences.snapshot else { throw BrokerControlError.denied }
        vaultActivity = .unlocking
        guard
            case .vaultUnlockReview(let review) = try await client.call(
                .prepareVaultUnlock(revision: snapshot.revision), context: nil)
        else { throw BrokerFailure.invalidMessage }
        do {
            try Task.checkCancellation()
            let pending = try VaultUnlockPending(client: client, review: review, snapshot: snapshot)
            presentation = try acquirePresentation()
            let dialog = makeUnlockWindow(review, pending, forSync)
            let result: BrokerVaultStatus = try await withCheckedThrowingContinuation { continuation in
                present(dialog) { [weak dialog] in
                    if dialog?.approved == true, let result = pending.result {
                        continuation.resume(returning: result)
                    } else {
                        continuation.resume(throwing: pending.failure ?? CancellationError())
                    }
                }
            }
            try Task.checkCancellation()
            vaultStatus = result
            return result
        } catch {
            _ = try? await client.call(.vaultUnlockCancel(id: review.id), context: nil)
            throw error
        }
    }

    private func vaultFailure(_ reply: BrokerVaultStatus) -> String {
        switch reply.state {
        case .locked: "The vault is locked. Unlock it before syncing."
        case .busy: "Another vault operation is running. Try again shortly."
        case .serverUnavailable: "Could not contact Vaultwarden. Try again when it is available."
        case .reauthRequired: "Vaultwarden requires you to sign in again. Verify the vault again in Settings."
        case .keyInvalidated: "This vault can no longer be unlocked on this Mac. Verify it again in Settings."
        case .keychainIssue: "macOS could not unlock the vault. Try again."
        case .ambiguousItem: "More than one vault item matches this enrolment."
        case .itemNotFound: "The selected vault item could not be found."
        case .incompatibleCache, .incompleteEnrollment:
            "The saved vault data could not be read. Verify the vault again in Settings."
        case .unenrolled: "Configure a vault before syncing."
        case .settingsImportRequired: "Import or discard your previous settings first."
        case .onlineUnlocked: "The vault operation failed. Try again."
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

    func present(_ dialog: any ApprovalWindow, settings: Bool = false, completion: (() -> Void)? = nil) {
        dialog.onClose = { [weak self, weak dialog] in
            guard let self, let dialog else { return }
            dialog.onClose = nil
            active = nil
            releasePresentation()
            updateActivationPolicy()
            if settings {
                operationEnrolled = false
                Task { await reloadPreferences() }
            }
            completion?()
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
        vaultTask?.cancel()
        client?.cancel()
        releasePresentation()
        return .terminateNow
    }
}
