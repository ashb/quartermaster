import QuartermasterSecurity
import SwiftUI

@main
struct QuartermasterApp: App {
    @NSApplicationDelegateAdaptor(BrokerApplication.self) private var application

    init() {
        if CommandLine.arguments.dropFirst().first == "--approval-key-status" {
            do {
                let key = try ApprovalKeyStore().existingPublicKey()
                let report: [String: Any] = [
                    "profile": "development", "enrolled": key != nil, "public_key": key?.base64EncodedString() ?? "",
                ]
                print(
                    String(
                        decoding: try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]),
                        as: UTF8.self))
                exit(0)
            } catch { exit(1) }
        }
        if CommandLine.arguments.dropFirst().first?.hasPrefix("--approval-key-") == true
            || CommandLine.arguments.dropFirst().first == "--vault-enroll"
        {
            print(
                "Open Quartermaster Settings to change enrolment. Approval keys cannot be reset from the command line."
            )
            exit(2)
        }
    }

    var body: some Scene {
        Settings {
            PreferencesView(editor: application.preferences, application: application)
        }
        MenuBarExtra("Quartermaster", systemImage: "key.horizontal") {
            Text(application.status)
            SettingsLink { Text("Settings…") }.keyboardShortcut(",")
            Divider()
            Button("Revoke read access", action: application.revokeReads)
            Button("Lock vault") { application.vault(.vaultLock) }
            Button("Sync vault") { application.vault(.vaultSync) }
            Button("Reconnect", action: application.reconnect)
            Divider()
            Button("Quit Quartermaster") { NSApplication.shared.terminate(nil) }.keyboardShortcut("q")
        }
    }
}
