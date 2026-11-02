import AppKit
import Luminare
import QuartermasterApprovalUI
import QuartermasterSecurity
import SwiftUI

struct ResticPreferencesView: View {
    @ObservedObject var editor: SettingsEditor
    @ObservedObject var application: BrokerApplication
    let openVault: () -> Void
    @State private var showingItems = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PreferencesGroup(title: "Password from your vault") {
                if let provider = editor.stagedProvider ?? editor.snapshot?.provider {
                    Text(verbatim: provider.binding.email).font(.system(size: 12)).textSelection(.enabled)
                } else {
                    Text("Select a vault before using Restic.").font(.system(size: 12)).foregroundStyle(.secondary)
                }
                PreferencesField(title: "Login item") {
                    Text(verbatim: selectedItemName).font(.system(size: 12)).lineLimit(2)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Button("Choose…") {
                        showingItems = true
                    }.buttonStyle(CompactButtonStyle())
                        .disabled(!editor.canChooseVaultItems || application.vaultActivity.busy)
                }
                DisclosureGroup("Item UUID (manual)") {
                    TextField(
                        "Vault login item UUID",
                        text: Binding(
                            get: { editor.draft.restic?.itemId ?? "" },
                            set: { value in
                                edit {
                                    $0.itemId = value
                                    $0.itemName = nil
                                }
                            })
                    )
                    .font(.system(size: 11, design: .monospaced)).padding(.top, 6)
                }
                Text(
                    "The selected item's login password is released to Restic after each approval. Your vault master password is never sent to Restic."
                )
                .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            PreferencesGroup(title: "Restic executable") {
                PreferencesField(title: "Binary path") {
                    TextField(
                        "/absolute/path/to/restic",
                        text: Binding(
                            get: { editor.draft.restic?.executable ?? "" },
                            set: { value in edit { $0.executable = value } }))
                    Button("Choose…", action: chooseExecutable).buttonStyle(CompactButtonStyle())
                }
                Text(
                    "Choose the native binary. For Nix, select .restic-wrapped rather than the launcher named restic."
                )
                .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if let message = editor.draft.restic?.validationMessage {
                Label(message, systemImage: "exclamationmark.triangle")
                    .font(.system(size: 12)).foregroundStyle(.orange)
            }
            if application.vaultStatus?.state != .onlineUnlocked {
                LuminareSection {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("The vault must be reachable. Touch ID approval also unlocks it when needed.")
                            .font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
                        HStack {
                            if application.vaultStatus?.state == .locked {
                                Button("Unlock Vault", action: application.unlockVault)
                                    .buttonStyle(CompactButtonStyle())
                                    .disabled(application.vaultActivity.busy)
                            }
                            Button("Open Vault", action: openVault).buttonStyle(CompactButtonStyle())
                        }
                        if let message = application.vaultActivity.message {
                            Text(message).font(.caption).foregroundStyle(.secondary)
                        }
                    }.padding(10)
                }
            }
            Text(
                "Each invocation asks to release the password once. Restic can retain or copy it; Quartermaster cannot restrict later operations or retract it."
            )
            .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }.disabled(editor.busy)
            .sheet(isPresented: $showingItems) {
                VaultItemPicker(
                    application: application, selectedID: editor.draft.restic?.itemId, choose: editor.selectResticItem)
            }
    }

    private var selectedItemName: String {
        guard let restic = editor.draft.restic, !restic.itemId.isEmpty else { return "No login item selected" }
        return restic.itemName.map { VaultItemSummary(id: restic.itemId, name: $0).displayName } ?? restic.itemId
    }

    private func edit(_ change: (inout ResticSettings) -> Void) {
        var restic = editor.draft.restic ?? ResticSettings(enabled: false)
        change(&restic)
        editor.draft.restic = restic
    }

    private func chooseExecutable() {
        let panel = NSOpenPanel()
        panel.title = "Choose the native Restic executable"
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        if let path = editor.draft.restic?.executable, path.hasPrefix("/") {
            panel.directoryURL = URL(fileURLWithPath: path).deletingLastPathComponent()
        }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        edit { $0.executable = url.path }
    }
}
