import QuartermasterApprovalUI
import QuartermasterSecurity
import SwiftUI

struct PreferencesView: View {
    private enum Pane: String, CaseIterable, Identifiable {
        case vault = "Vault"
        case github = "GitHub"
        case access = "Access"
        var id: Self { self }
        var symbol: String {
            switch self {
            case .vault: "lock.shield"
            case .github: "network"
            case .access: "hand.raised"
            }
        }
    }

    @ObservedObject var editor: SettingsEditor
    @ObservedObject var application: BrokerApplication
    @State private var selection: Pane? = .vault
    @State private var password = ""
    @State private var repository = ""

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Section {
                    ForEach(Pane.allCases) { pane in
                        Label(pane.rawValue, systemImage: pane.symbol)
                            .font(.system(size: 14)).frame(height: 30).tag(pane)
                    }
                } header: {
                    VStack(alignment: .leading, spacing: 5) {
                        Image(systemName: "key.horizontal.fill")
                            .font(.system(size: 28)).foregroundStyle(.indigo)
                        Text("Quartermaster")
                            .font(.system(size: 23, weight: .semibold)).foregroundStyle(.primary)
                    }.padding(.top, 12).padding(.bottom, 20)
                }.collapsible(false)
            }
            .listStyle(.sidebar).scrollDisabled(true)
            .frame(minWidth: 220, idealWidth: 220, maxWidth: 220)
            .navigationSplitViewColumnWidth(min: 220, ideal: 220, max: 220)
            .toolbar(removing: .sidebarToggle)
            .disabled(editor.snapshot?.migration != nil)
        } detail: {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 22) {
                        if let migration = editor.snapshot?.migration {
                            SettingsMigrationView(migration: migration)
                        } else {
                            switch selection ?? .vault {
                            case .vault: vault
                            case .github: github
                            case .access: access
                            }
                        }
                    }.padding(24).frame(maxWidth: .infinity, alignment: .leading)
                }
                Divider()
                HStack {
                    Text(editor.busy ? "Working…" : editor.message)
                        .font(.caption).foregroundStyle(.secondary)
                        .lineLimit(3).help(editor.message).textSelection(.enabled)
                    Spacer()
                    if editor.snapshot?.migration != nil {
                        Button("Later", action: application.postponeMigration).disabled(editor.busy)
                        Button("Discard…") { application.reviewMigration(.discard) }.disabled(!editor.canImport)
                        Button("Review Import…") { application.reviewMigration(.importSettings) }.disabled(
                            !editor.canImport)
                    } else {
                        Button("Review Changes…", action: application.reviewPreferences).disabled(!editor.canReview)
                    }
                }.padding(.horizontal, 24).padding(.vertical, 15)
            }.navigationTitle(editor.snapshot?.migration == nil ? (selection ?? .vault).rawValue : "Import settings")
        }
        .frame(minWidth: 820, idealWidth: 900, minHeight: 580, idealHeight: 625)
        .onDisappear { password = "" }
        .background(
            PreferencesWindowLifecycle(
                opened: application.settingsOpened,
                closed: {
                    password = ""
                    repository = ""
                    application.settingsClosed()
                }))
    }

    private var vault: some View {
        Group {
            PreferencesGroup(title: "Vault") {
                if let provider = editor.snapshot?.provider {
                    providerIdentity(provider)
                    HStack {
                        Text("Last synced")
                        Spacer()
                        if let vault = application.vaultStatus, vault.binding == provider.binding {
                            Text(vault.lastSync?.formatted(date: .abbreviated, time: .standard) ?? "Never")
                                .foregroundStyle(.secondary)
                        } else {
                            Text("Unavailable").foregroundStyle(.secondary)
                        }
                    }
                    DisclosureSection("Enrolment details") {
                        VStack(alignment: .leading, spacing: 5) {
                            Text(verbatim: "Account: \(provider.binding.accountID)")
                        }.font(.caption.monospaced()).textSelection(.enabled)
                    }
                } else {
                    Text("No vault selected")
                }
                Divider()
                vaultControls
            }
            if let staged = editor.stagedProvider {
                PreferencesGroup(title: "Verified replacement · awaiting approval") {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(verbatim: staged.binding.email).fontWeight(.semibold)
                        Text(verbatim: staged.binding.server).foregroundStyle(.secondary)
                    }.textSelection(.enabled)
                }
            }
            PreferencesGroup(title: "Add or replace a vault") {
                PreferencesField(title: "Server URL") {
                    TextField("https://vault.example.com", text: $editor.enrollment.server).textContentType(.URL)
                }
                Divider()
                PreferencesField(title: "Email") {
                    TextField("you@example.com", text: $editor.enrollment.email).textContentType(.username)
                }
                Divider()
                PreferencesField(title: "Password") {
                    SecureField("Master password", text: $password).textContentType(.password)
                }
                Divider()
                HStack {
                    Button("GitHub Token Source…") { selection = .github }
                        .buttonStyle(.link)
                    Spacer()
                    Button(editor.busy ? "Verifying…" : "Verify Vault…") {
                        let secret = password
                        password = ""
                        application.stageEnrollment(password: secret)
                    }.disabled(
                        !editor.available || editor.busy || editor.enrollment.server.isEmpty
                            || editor.enrollment.email.isEmpty || password.isEmpty)
                }
            }.disabled(editor.busy)
            Label {
                Text("Your current vault stays selected until you review and approve the replacement with Touch ID.")
                    .font(.callout).foregroundStyle(.secondary)
            } icon: {
                Image(systemName: "touchid").font(.title3).foregroundStyle(.secondary)
            }
        }
    }

    private func providerIdentity(_ provider: SettingsProvider) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "lock.shield.fill").font(.system(size: 23)).foregroundStyle(.indigo)
                .frame(width: 38, height: 38).background(.indigo.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 4) {
                Text(verbatim: provider.binding.email).fontWeight(.semibold)
                Text(verbatim: provider.binding.server).font(.callout).foregroundStyle(.secondary)
            }.textSelection(.enabled)
            Spacer()
            Button("Disconnect…") { editor.forget() }.disabled(!editor.available || editor.busy)
        }
    }

    private var github: some View {
        Group {
            PreferencesGroup(title: "GitHub") {
                Toggle(
                    "Enable request mediation",
                    isOn: Binding(
                        get: { editor.draft.github != nil }, set: { editor.draft.github = $0 ? GitHubSettings() : nil })
                )
            }
            PreferencesGroup(title: "Token source") {
                PreferencesField(title: "Login item") {
                    TextField("Vaultwarden item UUID", text: $editor.enrollment.itemID)
                }
                Divider()
                HStack {
                    Text("Credential field")
                    Spacer()
                    Text("Login password").foregroundStyle(.secondary)
                }
                if let provider = editor.snapshot?.provider {
                    DisclosureSection("Approved token source") {
                        VStack(alignment: .leading, spacing: 5) {
                            Text(verbatim: provider.binding.email)
                            Text(verbatim: "Login item: \(provider.binding.itemID)")
                            Text(verbatim: "Role: \(provider.binding.role)")
                        }.font(.caption.monospaced()).textSelection(.enabled)
                    }
                }
                if let staged = editor.stagedProvider {
                    Text(verbatim: "Verified replacement: \(staged.binding.itemID) · awaiting approval")
                        .font(.caption.monospaced()).textSelection(.enabled)
                }
                if editor.enrollmentNeedsVerification {
                    Text("Token source changed. Verify Vault before reviewing changes.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text(
                    "The Login item's password supplies the GitHub token. Choose the item here, then verify the vault. Leave blank only if that Login is the vault's only item."
                )
                .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Verify in Vault…") { selection = .vault }
                }
            }
            if editor.draft.github != nil {
                PreferencesGroup(title: "Repositories") {
                    ForEach(editor.draft.github?.repositories ?? []) { repo in
                        HStack {
                            Text(verbatim: "\(repo.owner)/\(repo.name)")
                            Spacer()
                            Button {
                                editor.draft.github?.repositories.removeAll { $0.id == repo.id }
                            } label: {
                                Image(systemName: "minus.circle")
                            }
                            .buttonStyle(.borderless).accessibilityLabel("Remove \(repo.owner)/\(repo.name)")
                        }
                        Divider()
                    }
                    ForEach(editor.pendingRepositories) { repo in
                        HStack {
                            Text(verbatim: repo.fullName)
                            Spacer()
                            Text("Verify on save").foregroundStyle(.secondary)
                            Button {
                                editor.removeRepository(repo)
                            } label: {
                                Image(systemName: "minus.circle")
                            }
                            .buttonStyle(.borderless).accessibilityLabel("Remove \(repo.fullName)")
                        }
                        Divider()
                    }
                    HStack {
                        TextField("owner/repository", text: $repository)
                            .onSubmit(addRepository)
                        Button("Add", action: addRepository).disabled(!editor.canAddRepository(repository))
                    }.textFieldStyle(.roundedBorder)
                    Text("Eligible for issue read grants. A grant still requires a separate approval.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                PreferencesGroup(title: "Individual approvals") {
                    Toggle(
                        "Allow unfamiliar requests",
                        isOn: Binding(
                            get: { editor.draft.github?.approveUnverifiedRequests ?? false },
                            set: { editor.draft.github?.approveUnverifiedRequests = $0 }))
                    Text("Each unfamiliar request requires Touch ID.").font(.caption).foregroundStyle(.secondary)
                    Divider()
                    Picker("Recognized mutations", selection: $editor.draft.mutations) {
                        Text("Require Touch ID").tag(BrokerSettings.MutationRule.requireApproval)
                        Text("Deny").tag(BrokerSettings.MutationRule.deny)
                    }
                }
                Text(
                    "Individual approvals can use the selected token’s full GitHub permissions. Keep its upstream permissions limited."
                )
                .font(.caption).foregroundStyle(.secondary)
            }
        }.toggleStyle(.switch).controlSize(.small).disabled(editor.busy)
    }

    private var access: some View {
        Group {
            PreferencesGroup(title: "Read access") {
                HStack {
                    Text("Grant lifetime")
                    Spacer()
                    Text("1 hour").foregroundStyle(.secondary)
                }
                Divider()
                HStack {
                    Text("End existing read grants")
                    Spacer()
                    Button("Revoke Read Access", action: application.revokeReads)
                }
                Text("Restarting the backend also removes read grants.").font(.caption).foregroundStyle(.secondary)
            }
            PreferencesGroup(title: "Connection") {
                HStack {
                    Text("Backend")
                    Spacer()
                    Text(application.status).foregroundStyle(.secondary)
                }
                Divider()
                HStack {
                    Text("Approved revision")
                    Spacer()
                    Text(editor.snapshot.map { String($0.revision) } ?? "Unavailable").foregroundStyle(.secondary)
                }
                Divider()
                HStack {
                    Button("Reconnect", action: application.reconnect)
                    Spacer()
                    Button("Discard Changes", action: application.discardChanges).disabled(editor.busy)
                }
            }
        }
    }

    private var vaultControls: some View {
        Group {
            HStack {
                Text("Lock vault")
                Spacer()
                Button("Lock Now") { application.vault(.vaultLock) }
            }
            Divider()
            HStack {
                Text("Refresh from Vaultwarden")
                Spacer()
                Button("Sync Vault") { application.vault(.vaultSync) }
                    .disabled(application.vaultActivity.busy)
            }
            if let message = application.vaultActivity.message {
                Text(message).font(.callout).foregroundStyle(.secondary)
            }
        }.disabled(editor.busy || editor.snapshot?.provider == nil)
    }

    private func addRepository() {
        guard editor.addRepository(repository) else { return }
        repository = ""
    }
}
