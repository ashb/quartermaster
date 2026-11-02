import Luminare
import QuartermasterApprovalUI
import QuartermasterSecurity
import SwiftUI

struct VaultItemPicker: View {
    @ObservedObject var application: BrokerApplication
    @ObservedObject var editor: SettingsEditor
    let selectedID: String?
    let choose: (VaultItemSummary) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var items: [VaultItemSummary] = []
    @State private var loadedSource: String?
    @State private var search = ""
    @State private var loading = false
    @State private var error: String?
    @State private var refresh = UUID()

    init(application: BrokerApplication, selectedID: String?, choose: @escaping (VaultItemSummary) -> Void) {
        self.application = application
        self.editor = application.preferences
        self.selectedID = selectedID
        self.choose = choose
    }

    private var requiresUnlock: Bool { editor.stagedProvider == nil && application.vaultStatus?.state == .locked }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Choose a vault item").font(.title2.weight(.semibold))
                Spacer()
                Button("Cancel") { dismiss() }.buttonStyle(CompactButtonStyle())
            }
            if requiresUnlock {
                Text("Unlock your vault to choose an item.").foregroundStyle(.secondary)
                Button("Unlock Vault", action: application.unlockVault)
                    .buttonStyle(CompactButtonStyle()).disabled(application.vaultActivity.busy)
                if let message = application.vaultActivity.message {
                    Text(message).font(.caption).foregroundStyle(.secondary)
                }
            } else if loading {
                ProgressView("Loading login items…")
            } else if let error {
                Text(error).foregroundStyle(.secondary)
                Button("Retry") { refresh = UUID() }.buttonStyle(CompactButtonStyle())
            } else {
                TextField("Search login items", text: $search)
                ScrollView {
                    LazyVStack(spacing: 4) {
                        ForEach(matches) { item in
                            Button {
                                guard loadedSource == editor.vaultItemSource else {
                                    dismiss()
                                    return
                                }
                                choose(item)
                                dismiss()
                            } label: {
                                HStack {
                                    Text(verbatim: item.displayName).lineLimit(2)
                                    Spacer()
                                    if item.id == selectedID { Image(systemName: "checkmark") }
                                }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
                            }.buttonStyle(.luminare)
                        }
                        if matches.isEmpty {
                            Text(items.isEmpty ? "No eligible login items found." : "No matching login items.")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding(20).frame(width: 440, height: 360)
        .task(id: refresh) {
            guard !requiresUnlock else { return }
            let source = editor.vaultItemSource
            loading = true
            error = nil
            do {
                let loaded = try await application.loadVaultItems()
                try Task.checkCancellation()
                guard source == editor.vaultItemSource else {
                    dismiss()
                    return
                }
                loadedSource = source
                items = loaded.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
            } catch {
                guard !Task.isCancelled else { return }
                if let failure = error as? SettingsEditor.Failure, case .stagedCatalogueUnavailable = failure {
                    self.error = failure.localizedDescription
                } else {
                    self.error = "Could not load vault items. Check the vault connection and try again."
                }
            }
            loading = false
        }
        .onChange(of: application.vaultStatus?.state) { _, _ in
            items = []
            refresh = UUID()
        }
        .onChange(of: editor.vaultItemSource) { _, _ in
            items = []
            dismiss()
        }
        .onChange(of: application.preferences.available) { _, available in if !available { dismiss() } }
    }

    private var matches: [VaultItemSummary] {
        items.filter {
            search.isEmpty || $0.name.localizedCaseInsensitiveContains(search)
                || $0.id.localizedCaseInsensitiveContains(search)
        }
    }
}
