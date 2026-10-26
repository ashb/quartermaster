import AppKit
import Darwin
import QuartermasterApprovalUI
import QuartermasterSecurity

@MainActor
final class BrokerApplication: NSObject, NSApplicationDelegate, ObservableObject {
    @Published private(set) var status = "Disconnected"
    @Published private(set) var vaultStatus: BrokerVaultStatus?
    private var client: BrokerConnection?
    private var task: Task<Void, Never>?
    private var active: (any ApprovalWindow)?
    private var presentation: Int32?
    private var operationEnrolled = false
    private let controls = ApprovalControlWorkflow()
    lazy var preferences = SettingsEditor { [weak self] command in
        guard let client = self?.client else { throw BrokerFailure.disconnected }
        return try await client.call(command)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.setActivationPolicy(.accessory)
        reconnect()
    }

    func reconnect() {
        status = "Starting Quartermaster…"
        vaultStatus = nil
        active?.cancel()
        task?.cancel()
        client?.cancel()
        operationEnrolled = false
        task = Task {
            do {
                let executable = BrokerConnection.executable
                try await Task.detached {
                    let process = Process()
                    process.executableURL = executable
                    process.arguments = ["start"]
                    try process.run()
                    process.waitUntilExit()
                    guard process.terminationStatus == 0 else { throw BrokerFailure.disconnected }
                }.value
                try Task.checkCancellation()
                let connection = try BrokerConnection()
                client = connection
                guard case .hello("development") = try await connection.call(.hello) else {
                    throw BrokerFailure.invalidMessage
                }
                let key = try ApprovalKeyStore().loadOrCreate()
                guard case .settingsStatus = try await connection.call(.settingsRegister(publicKey: key)) else {
                    throw BrokerFailure.invalidMessage
                }
                await preferences.load()
                await refreshVaultStatus()
                try Task.checkCancellation()
                status = "Connected"
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
                preferences.report(error)
            }
        }
    }

    private func poll(_ connection: BrokerConnection, key: Data) async throws {
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
        guard active == nil, !controls.busy, !preferences.busy, let client else { return }
        Task {
            await controls.perform {
                var reviewID: String?
                do {
                    let review = try await preferences.review()
                    reviewID = review.id
                    let pending = try SettingsPending(client: client, review: review)
                    presentation = try DialogPresentationLease.acquire()
                    let dialog = SettingsApprovalDialog(review: review, document: pending.document, backend: pending)
                    present(dialog, settings: true)
                } catch {
                    if let reviewID { _ = try? await client.call(.settingsCancel(id: reviewID)) }
                    preferences.report(error)
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
        active?.cancel()
        Task { await controls.perform { await preferences.cancel() } }
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

    private func present(_ dialog: any ApprovalWindow, settings: Bool = false) {
        dialog.onClose = { [weak self] in
            guard let self else { return }
            active = nil
            releasePresentation()
            if settings {
                operationEnrolled = false
                Task {
                    await preferences.load()
                    await refreshVaultStatus()
                }
            }
        }
        active = dialog
        dialog.window.center()
        dialog.window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
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
