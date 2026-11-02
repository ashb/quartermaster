import Luminare
import QuartermasterApprovalUI
import QuartermasterSecurity
import SwiftUI

struct PreferencesView: View {
    enum Pane: String, CaseIterable, Identifiable {
        case vault = "Vault"
        case tools = "Tools"
        case access = "Access"
        var id: Self { self }
        var symbol: String {
            switch self {
            case .vault: "lock.shield"
            case .tools: "terminal"
            case .access: "hand.raised"
            }
        }
        var subtitle: String {
            switch self {
            case .vault: "Your credentials, kept in your vault."
            case .tools: "Manage credentials and approvals for your tools."
            case .access: "See what can run without asking again."
            }
        }
    }

    @ObservedObject var editor: SettingsEditor
    @ObservedObject var application: BrokerApplication
    @State private var selection: Pane = .vault
    @State private var showingGitHub = false
    @State private var showingEnrollment = false
    @State private var showingGitHubItems = false
    @State private var vaultDraft: EnrollmentDraft
    @Environment(\.colorScheme) private var colorScheme
    @State private var password = ""
    @State private var repository = ""
    private let accent = ApprovalAppearance.accent

    init(
        editor: SettingsEditor, application: BrokerApplication, pane: Pane = .vault, showingGitHub: Bool = false,
        editingVault: Bool = false
    ) {
        self.editor = editor
        self.application = application
        _selection = State(initialValue: pane)
        _showingGitHub = State(initialValue: showingGitHub)
        _showingEnrollment = State(initialValue: editingVault)
        _vaultDraft = State(initialValue: editor.enrollment)
    }

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider().opacity(0.45)
            VStack(alignment: .leading, spacing: 0) {
                header
                ScrollView {
                    VStack(alignment: .leading, spacing: 24) {
                        if let migration = editor.snapshot?.migration {
                            SettingsMigrationView(migration: migration)
                        } else {
                            switch selection {
                            case .vault: vault
                            case .tools:
                                if showingGitHub {
                                    github
                                } else {
                                    tools
                                }
                            case .access: access
                            }
                        }
                    }.padding(.horizontal, 24).padding(.bottom, 18)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                footer
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .tint(accent)
        .luminareTint(overridingWith: accent)
        .luminareCornerRadius(12)
        .luminareMinHeight(24)
        .frame(minWidth: 820, idealWidth: 880, minHeight: 520, idealHeight: 540)
        .onDisappear {
            password = ""
        }
        .onChange(of: editor.stagedProvider) { _, provider in
            if provider != nil { closeVaultEditor() }
        }
        .background(
            PreferencesWindowLifecycle(
                opened: application.settingsOpened,
                closed: {
                    password = ""
                    repository = ""
                    showingEnrollment = false
                    closeVaultEditor()
                    application.settingsClosed()
                }))
    }

    private var sidebar: some View {
        VStack(spacing: 5) {
            ForEach(Pane.allCases) { pane in
                Button {
                    closeVaultEditor()
                    selection = pane
                    showingGitHub = false
                } label: {
                    HStack(spacing: 12) {
                        Image(systemName: pane.symbol).font(.system(size: 15)).frame(width: 20)
                        Text(pane.rawValue).font(.system(size: 13, weight: selection == pane ? .semibold : .regular))
                        Spacer()
                    }.padding(.horizontal, 13).frame(height: 34)
                        .foregroundStyle(selection == pane ? Color.primary : Color.secondary)
                        .background(
                            selection == pane ? accent.opacity(0.2) : .clear, in: RoundedRectangle(cornerRadius: 9))
                }.buttonStyle(.plain)
            }
            Spacer()
        }.padding(.horizontal, 12).padding(.top, 16)
            .frame(width: 220).frame(maxHeight: .infinity)
            .background(.black.opacity(colorScheme == .dark ? 0.13 : 0.025))
            .disabled(editor.snapshot?.migration != nil)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 10) {
                if selection == .tools && showingGitHub && editor.snapshot?.migration == nil {
                    Button {
                        closeVaultEditor()
                        showingGitHub = false
                    } label: {
                        Image(systemName: "chevron.left").font(.system(size: 15, weight: .medium))
                            .frame(width: 24, height: 28)
                    }.buttonStyle(.plain).help("Back to Tools").accessibilityLabel("Back to Tools")
                }
                Text(
                    editor.snapshot?.migration != nil
                        ? "Import settings"
                        : showingGitHub && selection == .tools
                            ? "GitHub CLI" : selection.rawValue
                )
                .font(.system(size: 26, weight: .semibold))
                Spacer()
                if selection == .tools && showingGitHub && editor.snapshot?.migration == nil {
                    Toggle(
                        "Enable GitHub",
                        isOn: Binding(
                            get: { editor.githubEnabled },
                            set: { editor.githubEnabled = $0 }
                        )
                    )
                    .toggleStyle(.switch).controlSize(.small).font(.system(size: 12))
                    .fixedSize().disabled(editor.busy)
                }
            }
            if editor.snapshot?.migration == nil {
                if selection == .tools && showingGitHub {
                    Text(
                        "Credential and approval rules for \(Text("gh").font(.system(size: 13, design: .monospaced)).foregroundColor(accent))."
                    )
                    .font(.system(size: 13)).foregroundStyle(.secondary)
                } else {
                    Text(selection.subtitle).font(.system(size: 13)).foregroundStyle(.secondary)
                }
            }
        }.padding(.horizontal, 24).padding(.top, 16).padding(.bottom, 18)
    }

    @ViewBuilder private var footer: some View {
        if (editor.busy && !editor.isLoggingIn) || !editor.message.isEmpty || editor.canDiscard
            || editor.snapshot?.migration != nil
        {
            Divider()
            VStack(alignment: .leading, spacing: 9) {
                if editor.busy && !editor.isLoggingIn {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Working…").font(.caption).foregroundStyle(.secondary)
                    }
                }
                if !editor.message.isEmpty {
                    Text(editor.message)
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                        .lineLimit(3).help(editor.message).textSelection(.enabled)
                }
                if editor.snapshot?.migration != nil {
                    HStack {
                        Button("Later", action: application.postponeMigration).disabled(editor.busy)
                        Spacer()
                        Button("Discard…") { application.reviewMigration(.discard) }.disabled(!editor.canImport)
                        Button("Review Import…") { application.reviewMigration(.importSettings) }.disabled(
                            !editor.canImport)
                    }.buttonStyle(CompactButtonStyle())
                } else if editor.canDiscard {
                    HStack {
                        Text("Unsaved changes").font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button("Discard") {
                            closeVaultEditor()
                            application.discardChanges()
                        }.buttonStyle(CompactButtonStyle())
                        Button("Review Changes…", action: application.reviewPreferences)
                            .buttonStyle(CompactButtonStyle()).disabled(!editor.canReview)
                    }
                }
            }.padding(.horizontal, 18).padding(.vertical, 10)
        }
    }

    private var tools: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Configured tools").font(.system(size: 14, weight: .semibold))
            Button {
                showingGitHub = true
            } label: {
                HStack(spacing: 12) {
                    PreferencesGitHubIcon().frame(width: 24, height: 24)
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 8) {
                            Text("GitHub CLI").font(.system(size: 13, weight: .semibold))
                            Text("gh").font(.system(size: 11, design: .monospaced)).foregroundStyle(accent)
                        }
                        Text(
                            !editor.githubEnabled
                                ? "Disabled" : editor.snapshot?.provider?.binding.email ?? "No credential selected"
                        )
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Image(systemName: "chevron.right").font(.system(size: 11, weight: .medium)).foregroundStyle(
                        .secondary)
                }.padding(.horizontal, 12).padding(.vertical, 10).frame(maxWidth: .infinity, alignment: .leading)
            }.buttonStyle(.luminare)
        }
    }

    private var vault: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let provider = editor.snapshot?.provider {
                LuminareSection {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(spacing: 14) {
                            Image(systemName: "lock.shield.fill").font(.system(size: 27)).foregroundStyle(accent)
                            VStack(alignment: .leading, spacing: 5) {
                                Text("Personal vault").font(.headline)
                                Text(verbatim: provider.binding.email)
                                    .font(.system(size: 12)).foregroundStyle(.secondary)
                            }
                            Spacer()
                            if !showingEnrollment {
                                Button("Change…", action: openVaultEditor)
                                    .buttonStyle(CompactButtonStyle()).font(.system(size: 12))
                            }
                            if let status = application.vaultStatus, status.binding == provider.binding {
                                Label(
                                    status.state == .onlineUnlocked
                                        ? "Unlocked" : status.state == .locked ? "Locked" : "Unavailable",
                                    systemImage: status.state == .onlineUnlocked ? "lock.open" : "lock"
                                )
                                .font(.system(size: 11))
                                .foregroundStyle(status.state == .onlineUnlocked ? Color.teal : Color.secondary)
                            }
                        }
                        Divider()
                        vaultInfo("Server", provider.binding.server)
                        if let status = application.vaultStatus, status.binding == provider.binding {
                            vaultInfo(
                                "Last synced", status.lastSync?.formatted(.relative(presentation: .named)) ?? "Never")
                        } else {
                            vaultInfo("Last synced", "Unavailable")
                        }
                        HStack {
                            if application.vaultStatus?.state == .onlineUnlocked {
                                Button("Lock Now") { application.vault(.vaultLock) }
                                    .buttonStyle(CompactButtonStyle())
                            } else {
                                Button("Unlock", action: application.unlockVault)
                                    .buttonStyle(CompactButtonStyle())
                            }
                            Spacer()
                            Button("Sync Vault") { application.vault(.vaultSync) }
                                .buttonStyle(CompactButtonStyle())
                        }.disabled(editor.busy || application.vaultActivity.busy)
                        if let message = application.vaultActivity.message {
                            Text(message).font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        if showingEnrollment {
                            Divider()
                            enrollmentForm
                        }
                    }.padding(10)
                }
                Text("Credentials stay in your vault. Quartermaster requests access when you approve an operation.")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            } else if editor.stagedProvider == nil {
                PreferencesGroup(title: "Connect your vault") { enrollmentForm }
            }
            if let staged = editor.stagedProvider {
                PreferencesGroup(
                    title: editor.snapshot?.provider == nil ? "Ready to save" : "Replacement ready to save"
                ) {
                    VStack(alignment: .leading, spacing: 5) {
                        Label("Logged in", systemImage: "checkmark.circle.fill")
                            .font(.system(size: 11, weight: .medium)).foregroundStyle(.teal)
                        Text(verbatim: staged.binding.email).font(.system(size: 14, weight: .semibold))
                        Text(verbatim: staged.binding.server).font(.system(size: 12)).foregroundStyle(.secondary)
                        Text("Review the connection below, then authorise with Touch ID.")
                            .font(.system(size: 12)).foregroundStyle(.secondary).padding(.top, 4)
                    }.padding(4).textSelection(.enabled)
                }
            }
        }
    }

    private func vaultInfo(_ title: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
            Text(verbatim: value).textSelection(.enabled)
        }.font(.system(size: 11))
    }

    private var enrollmentForm: some View {
        VaultLoginForm(
            editor: editor, application: application, draft: $vaultDraft, password: $password,
            cancel: cancelVaultLogin)
    }

    private var cancelVaultLogin: (() -> Void)? {
        guard editor.snapshot?.provider != nil else { return nil }
        return { closeVaultEditor() }
    }

    private var github: some View {
        VStack(alignment: .leading, spacing: 16) {
            credentialCard
            if editor.githubEnabled {
                PreferencesGroup(title: "Approvals") {
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Allow unfamiliar requests")
                            Text("Each request needs your approval with Touch ID.")
                                .font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Toggle(
                            "Allow unfamiliar requests",
                            isOn: Binding(
                                get: { editor.draft.github?.approveUnverifiedRequests ?? false },
                                set: { editor.draft.github?.approveUnverifiedRequests = $0 })
                        )
                        .labelsHidden()
                    }
                    Divider()
                    HStack {
                        Text("Recognised writes")
                        Spacer()
                        Picker("Recognised writes", selection: $editor.draft.mutations) {
                            Text("Require Touch ID").tag(BrokerSettings.MutationRule.requireApproval)
                            Text("Deny").tag(BrokerSettings.MutationRule.deny)
                        }.labelsHidden().fixedSize()
                    }
                }
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
                            .textFieldStyle(.roundedBorder)
                            .onSubmit(addRepository)
                        Button("Add", action: addRepository)
                            .buttonStyle(CompactButtonStyle()).disabled(!editor.canAddRepository(repository))
                    }
                    Text("Enter a repository, for example octocat/Hello-World, to add it.")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
                Text("Eligible for read access after approval.")
                    .font(.system(size: 11)).foregroundStyle(.secondary).padding(.top, -9)
            }
        }.toggleStyle(.switch).controlSize(.small).disabled(editor.busy)
    }

    private var credentialCard: some View {
        LuminareSection {
            HStack(spacing: 12) {
                PreferencesGitHubIcon().frame(width: 28, height: 28)
                VStack(alignment: .leading, spacing: 4) {
                    Text("GitHub credential").font(.system(size: 14, weight: .semibold))
                    if let provider = editor.stagedProvider ?? editor.snapshot?.provider {
                        Text(verbatim: editor.draft.githubCredential?.displayName ?? "No vault item selected")
                            .font(.system(size: 12)).foregroundStyle(.secondary)
                        Text(verbatim: provider.binding.email).font(.caption).foregroundStyle(.secondary)
                        if editor.stagedProvider != nil {
                            Text("Verified replacement · awaiting approval")
                                .font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                    } else {
                        Text("No vault item selected").font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Button("Change…") { showingGitHubItems = true }
                    .buttonStyle(CompactButtonStyle()).font(.system(size: 12))
                    .disabled(!editor.canChooseVaultItems)
            }.padding(.horizontal, 10).padding(.vertical, 8)
        }.sheet(isPresented: $showingGitHubItems) {
            VaultItemPicker(
                application: application, selectedID: editor.draft.githubCredential?.itemId,
                choose: editor.selectGitHubItem)
        }
    }

    private func openVaultEditor() {
        vaultDraft = editor.enrollment
        password = ""
        selection = .vault
        showingEnrollment = true
    }

    private func closeVaultEditor() {
        editor.clearVaultLoginError()
        password = ""
        vaultDraft = editor.enrollment
        showingEnrollment = false
    }

    private var access: some View {
        Group {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Active access").font(.system(size: 14, weight: .semibold))
                    Text("\(application.readGrants.count)").font(.system(size: 11, weight: .semibold))
                        .padding(.horizontal, 7).padding(.vertical, 3).background(.quinary, in: Capsule())
                    Spacer()
                    Button("Refresh") { Task { await application.refreshReadGrants() } }
                        .buttonStyle(.plain).disabled(application.refreshingGrants)
                    Button("Revoke All", action: application.revokeReads)
                        .buttonStyle(.plain)
                }
                ForEach(application.readGrants) { grant in
                    PreferencesGrantCard(grant: grant) { application.revokeRead(grant.id) }
                }
                if application.readGrants.isEmpty {
                    VStack(spacing: 10) {
                        Image(systemName: "hand.raised").font(.system(size: 28)).foregroundStyle(.tertiary)
                        Text("No active read access").font(.headline)
                        Text("Reusable read access appears here after approval.").font(.caption).foregroundStyle(
                            .secondary)
                    }.frame(maxWidth: .infinity).padding(.vertical, 28)
                }
                Label(
                    "Writes still need separate approval. Read access lasts at most one hour.", systemImage: "touchid"
                )
                .font(.caption).foregroundStyle(.secondary)
            }.task { await application.refreshReadGrants() }
            DisclosureGroup("Diagnostics") {
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
                }
            }
        }
    }

    private func addRepository() {
        guard editor.addRepository(repository) else { return }
        repository = ""
    }
}
