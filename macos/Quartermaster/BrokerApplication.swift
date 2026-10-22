import AppKit
import Darwin
import QuartermasterApprovalUI
import QuartermasterSecurity

@MainActor
final class BrokerApplication: NSObject, NSApplicationDelegate, NSMenuItemValidation {
    private var client: BrokerConnection?
    private var task: Task<Void, Never>?
    private var active: ApprovalDialog?
    private var statusItem: NSStatusItem?
    private var presentation: Int32?
    private let controls = ApprovalControlWorkflow()
    private var vaultSource: (server: String, email: String)?
    private var selectedVaultItem: String?

    static func run(enrollment: (server: String, email: String)? = nil, itemId: String? = nil) -> Int32 {
        let application = NSApplication.shared
        let delegate = BrokerApplication()
        delegate.vaultSource = enrollment
        delegate.selectedVaultItem = itemId
        application.setActivationPolicy(.accessory)
        application.delegate = delegate
        delegate.start()
        application.run()
        delegate.task?.cancel()
        delegate.client?.cancel()
        delegate.releasePresentation()
        return 0
    }

    func start() {
        let mainMenu = NSMenu()
        let applicationMenu = NSMenu()
        applicationMenu.addItem(
            withTitle: "Quit Quartermaster", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        let applicationItem = mainMenu.addItem(withTitle: "Quartermaster", action: nil, keyEquivalent: "")
        applicationItem.submenu = applicationMenu
        let editMenu = NSMenu(title: "Edit")
        for (title, action, key) in [
            ("Cut", #selector(NSText.cut(_:)), "x"),
            ("Copy", #selector(NSText.copy(_:)), "c"),
            ("Paste", #selector(NSText.paste(_:)), "v"),
            ("Select All", #selector(NSText.selectAll(_:)), "a"),
        ] {
            editMenu.addItem(withTitle: title, action: action, keyEquivalent: key)
        }
        let editItem = mainMenu.addItem(withTitle: "Edit", action: nil, keyEquivalent: "")
        editItem.submenu = editMenu
        NSApplication.shared.mainMenu = mainMenu
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = "QM [DEBUG]"
        let menu = NSMenu()
        menu.addItem(withTitle: "Quartermaster development", action: nil, keyEquivalent: "")
        for (title, action) in [
            ("Enrol dedicated vault…", #selector(enrollVault)),
            ("Vault status", #selector(vaultStatus)),
            ("Unlock offline cache", #selector(unlockVault)),
            ("Sync vault", #selector(syncVault)),
            ("Lock vault", #selector(lockVault)),
            ("Revoke read access", #selector(revokeReads)),
            ("Discard offline cache…", #selector(discardVault)),
        ] {
            let entry = menu.addItem(withTitle: title, action: action, keyEquivalent: "")
            entry.target = self
        }
        let quit = menu.addItem(withTitle: "Quit Quartermaster UI", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        item.menu = menu
        statusItem = item
        task = Task { [self] in
            do {
                let process = Process()
                process.executableURL = BrokerConnection.executable
                process.arguments = ["start"]
                try process.run()
                process.waitUntilExit()
                guard process.terminationStatus == 0 else { throw BrokerFailure.disconnected }
                let connection = try BrokerConnection()
                client = connection
                let hello = try await connection.call(.hello)
                guard case .hello("development") = hello else { throw BrokerFailure.invalidMessage }
                let publicKey = try ApprovalKeyStore().loadOrCreate()
                let enrolled = try await connection.call(.enroll(publicKey: publicKey))
                guard case .enrolled = enrolled else { throw BrokerFailure.invalidMessage }
                if vaultSource != nil { enrollVault() }
                while !Task.isCancelled {
                    guard !connection.disconnected else { throw BrokerFailure.disconnected }
                    if active == nil && !controls.busy {
                        let reply = try await connection.call(.next)
                        switch reply {
                        case .review(let review):
                            if controls.busy {
                                _ = try await connection.call(.cancel(id: review.id))
                                continue
                            }
                            let pending = try BrokerPending(client: connection, review: review)
                            do { presentation = try DialogPresentationLease.acquire() } catch DialogPresentationLease
                                .Failure.alreadyPresented
                            {
                                pending.cancel()
                                continue
                            }
                            let presentation = ApprovalPresentation(
                                request: pending.request, provider: pending.provider, readGrant: pending.readGrant)
                            let dialog = ApprovalDialog(presentation: presentation, backend: pending)
                            dialog.onClose = { [weak self] in
                                self?.active = nil
                                self?.releasePresentation()
                            }
                            active = dialog
                            dialog.window.center()
                            dialog.window.makeKeyAndOrderFront(nil)
                            NSApplication.shared.activate(ignoringOtherApps: true)
                        case .idle: break
                        default: throw BrokerFailure.invalidMessage
                        }
                    }
                    try await Task.sleep(for: .milliseconds(200))
                }
            } catch {
                guard !Task.isCancelled else { return }
                active?.cancel()
                client?.cancel()
                let alert = NSAlert()
                alert.messageText = "Quartermaster development backend unavailable"
                alert.informativeText = "\(error). Restart the development build before approving further requests."
                alert.runModal()
                NSApplication.shared.terminate(nil)
            }
        }
    }

    @objc private func enrollVault() {
        guard !controls.busy, active == nil, client != nil else { return }
        Task { await controls.perform { await self.enrollVaultInteractively() } }
    }

    private func enrollVaultInteractively() async {
        // Temporary development enrolment until native preferences are available.
        let alert = NSAlert()
        alert.messageText = "Enrol the dedicated vault"
        alert.informativeText =
            "Sign in to discover the account and pin the selected Login item. The offline cache will be protected by Touch ID."
        alert.addButton(withTitle: "Sign in and enrol")
        alert.addButton(withTitle: "Cancel")
        let server = NSTextField(string: vaultSource?.server ?? "")
        server.placeholderString = "Vaultwarden server URL"
        let email = NSTextField(string: vaultSource?.email ?? "")
        email.placeholderString = "Account email"
        let password = NSSecureTextField(string: "")
        password.placeholderString = "Master password"
        let item = NSTextField(string: selectedVaultItem ?? "")
        item.placeholderString = "Login item UUID (blank requires a single item)"
        let fields = NSStackView(views: [server, email, item, password])
        fields.orientation = .vertical
        fields.alignment = .leading
        fields.spacing = 8
        fields.frame = NSRect(x: 0, y: 0, width: 420, height: 112)
        for field in [server, email, item, password] {
            field.widthAnchor.constraint(equalToConstant: 420).isActive = true
        }
        alert.accessoryView = fields
        NSApplication.shared.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else {
            password.stringValue = ""
            return
        }
        let itemId = item.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let request = BrokerCommand.vaultLogin(
            server: server.stringValue, email: email.stringValue, password: password.stringValue,
            itemID: itemId.isEmpty ? nil : itemId)
        password.stringValue = ""
        await executeVault(request, reenroll: true)
    }

    @objc private func vaultStatus() { performVault(.vaultStatus, reenroll: false) }
    @objc private func unlockVault() { performVault(.vaultUnlock, reenroll: true) }
    @objc private func syncVault() { performVault(.vaultSync, reenroll: false) }
    @objc private func lockVault() { performVault(.vaultLock, reenroll: true) }
    @objc private func revokeReads() {
        guard client != nil else { return }
        statusItem?.button?.title = "QM [DEBUG] · revocation pending"
        Task {
            await controls.revokeReadAccess(
                cancelApproval: {
                    active?.cancel()
                }, revoke: { await self.performReadRevocation() })
        }
    }

    private func performReadRevocation() async {
        defer { statusItem?.button?.title = "QM [DEBUG]" }
        do {
            guard let client else { throw BrokerFailure.disconnected }
            let reply = try await client.call(.revokeReadGrants)
            guard case .readGrantsRevoked = reply else { throw BrokerFailure.invalidMessage }
            let key = try ApprovalKeyStore().loadOrCreate()
            let enrolled = try await client.call(.enroll(publicKey: key))
            guard case .enrolled = enrolled else { throw BrokerFailure.invalidMessage }
        } catch {
            let alert = NSAlert()
            alert.messageText = "Could not revoke read access"
            alert.informativeText = "\(error)"
            alert.runModal()
        }
    }

    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        if menuItem.action == #selector(revokeReads) {
            switch controls.phase {
            case .revocationQueued: menuItem.title = "Read revocation queued…"
            case .revoking: menuItem.title = "Revoking read access…"
            default: menuItem.title = "Revoke read access"
            }
            return client != nil && controls.phase != .revocationQueued && controls.phase != .revoking
        }
        return true
    }
    @objc private func discardVault() {
        guard !controls.busy, active == nil else { return }
        let alert = NSAlert()
        alert.messageText = "Discard this offline cache?"
        alert.informativeText = "Sign in again to rebuild it from the dedicated vault."
        alert.addButton(withTitle: "Discard cache")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            performVault(.vaultDiscard, reenroll: true)
        }
    }

    private func performVault(_ request: BrokerCommand, reenroll: Bool) {
        guard !controls.busy, active == nil, client != nil else { return }
        Task { await controls.perform { await self.executeVault(request, reenroll: reenroll) } }
    }

    private func executeVault(_ request: BrokerCommand, reenroll: Bool) async {
        guard let client else { return }
        do {
            let reply = try await client.call(request)
            guard case .vaultStatus(let status) = reply else { throw BrokerFailure.invalidMessage }
            if reenroll {
                let key = try ApprovalKeyStore().loadOrCreate()
                let enrolled = try await client.call(.enroll(publicKey: key))
                guard case .enrolled = enrolled else { throw BrokerFailure.invalidMessage }
            }
            if let binding = status.binding {
                vaultSource = (binding.server, binding.email)
                selectedVaultItem = binding.itemID
            }
            let alert = NSAlert()
            alert.messageText = "Vault: \(status.state.rawValue)"
            if let binding = status.binding {
                alert.informativeText =
                    "Account: \(binding.email)\nAccount ID: \(binding.accountID)\nLogin item ID: \(binding.itemID)\nRole: \(binding.role)"
            } else {
                alert.informativeText = status.error ?? "No vault is enrolled."
            }
            alert.runModal()
        } catch {
            let alert = NSAlert()
            alert.messageText = "Vault operation failed"
            alert.informativeText = "\(error)"
            alert.runModal()
        }
    }

    @objc private func quit() {
        NSApplication.shared.terminate(nil)
    }

    private func cancelApprovals() {
        active?.cancel()
        task?.cancel()
        client?.cancel()
        releasePresentation()
    }

    private func releasePresentation() {
        if let presentation { close(presentation) }
        presentation = nil
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        cancelApprovals()
        return .terminateNow
    }
}
