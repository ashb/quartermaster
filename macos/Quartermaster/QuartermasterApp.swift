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
        .defaultLaunchBehavior(.suppressed)
        .restorationBehavior(.disabled)
        MenuBarExtra("Quartermaster", systemImage: "key.horizontal") {
            QuartermasterMenu(application: application)
        }
    }
}

struct QuartermasterMenu: View {
    @ObservedObject var application: BrokerApplication

    var body: some View {
        Group {
            if let failure = application.connectionFailure {
                Text("Quartermaster backend unavailable")
                Text(failure)
                Button("Retry", action: application.reconnect)
                Divider()
            }
            SettingsMenuItem()
            Divider()
            Group {
                Button("Revoke read access", action: application.revokeReads)
                Button("Lock vault") { application.vault(.vaultLock) }
                Button("Sync vault") { application.vault(.vaultSync) }
            }.disabled(!application.connected)
            #if DEBUG
                Divider()
                Text("Debug status: \(application.status)")
                BuildMenuItems(component: "App", build: application.frontendBuild)
                BuildMenuItems(component: "Backend", build: application.backendBuild)
            #endif
            Divider()
            Button("Quit Quartermaster") { NSApplication.shared.terminate(nil) }.keyboardShortcut("q")
        }
    }
}

private struct BuildMenuItems: View {
    let component: String
    let build: BrokerBuildInfo?

    var body: some View {
        if let build {
            Text("\(component): \(build.revision)\(build.modified ? " (modified)" : "")")
            Text(
                "Built \(Date(timeIntervalSince1970: TimeInterval(build.builtAt)).formatted(date: .abbreviated, time: .standard))"
            )
        } else {
            Text("\(component) build: unavailable")
        }
    }
}

private struct SettingsMenuItem: View {
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        Button("Settings…") {
            NSApplication.shared.setActivationPolicy(.regular)
            NSApplication.shared.activate(ignoringOtherApps: true)
            openSettings()
        }.keyboardShortcut(",")
    }
}
