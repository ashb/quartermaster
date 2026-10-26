import QuartermasterSecurity
import SwiftUI

struct SettingsMigrationView: View {
    let migration: SettingsMigration

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            Label("Import your previous settings", systemImage: "arrow.down.document")
                .font(.title2.weight(.semibold))
            Text(
                "Quartermaster's settings format has changed. Review your previous settings and approve their import with Touch ID before this version can use them."
            )
            PreferencesGroup(title: "Previous vault") {
                if let provider = migration.provider {
                    Text(verbatim: provider.binding.email).fontWeight(.semibold)
                    Text(verbatim: provider.binding.server).foregroundStyle(.secondary)
                    Text(verbatim: "Login item: \(provider.binding.itemID)")
                        .font(.caption.monospaced())
                } else {
                    Text("No vault selected")
                }
            }
            PreferencesGroup(title: "Previous access settings") {
                if let github = migration.settings.github {
                    Text("GitHub request mediation enabled")
                    ForEach(github.repositories) { repository in
                        Text(verbatim: "\(repository.owner)/\(repository.name)")
                    }
                    Text(
                        github.approveUnverifiedRequests
                            ? "Unfamiliar requests: fingerprint per use" : "Unfamiliar requests: denied")
                } else {
                    Text("GitHub request mediation disabled")
                }
                Text(
                    migration.settings.mutations == .deny
                        ? "Recognized mutations: denied" : "Recognized mutations: fingerprint per use")
            }
            Text(
                "Nothing changes until you choose Import and Trust. You can close Settings and import later; your previous settings and encrypted cache will remain intact."
            )
            .font(.callout).foregroundStyle(.secondary)
        }.textSelection(.enabled)
    }
}
