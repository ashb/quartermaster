import Luminare
import QuartermasterApprovalUI
import QuartermasterSecurity
import SwiftUI

struct VaultLoginForm: View {
    @ObservedObject var editor: SettingsEditor
    @ObservedObject var application: BrokerApplication
    @Binding var draft: EnrollmentDraft
    @Binding var password: String
    let cancel: (() -> Void)?
    private enum Field { case server, email, password }
    @FocusState private var focus: Field?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Log in to your vault account. You’ll choose items for each tool after connecting.")
                .font(.system(size: 12)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            VStack(spacing: 12) {
                PreferencesField(title: "Server URL", labelWidth: 110) {
                    TextField("https://vault.example.com", text: $draft.server)
                        .textContentType(.URL).focused($focus, equals: .server)
                        .onSubmit { focus = .email }.disabled(editor.busy)
                }
                PreferencesField(title: "Email", labelWidth: 110) {
                    TextField("you@example.com", text: $draft.email)
                        .textContentType(.username).focused($focus, equals: .email)
                        .onSubmit { focus = .password }.disabled(editor.busy)
                }
                PreferencesField(title: "Master password", labelWidth: 110) {
                    SecureField("Master password", text: $password)
                        .textContentType(.password).focused($focus, equals: .password)
                        .onSubmit(logIn)
                }
            }
            if let error = editor.vaultLoginError {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.red)
                    Text(error).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                }
                .font(.system(size: 12)).padding(10).frame(maxWidth: .infinity, alignment: .leading)
                .background(.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                .accessibilityIdentifier("vaultLoginError")
            }
            HStack(spacing: 10) {
                if let cancel {
                    Button("Cancel", action: cancel).buttonStyle(CompactButtonStyle()).disabled(editor.busy)
                    Button("Disconnect…") {
                        cancel()
                        editor.forget()
                    }.buttonStyle(CompactButtonStyle()).disabled(!editor.available || editor.busy)
                }
                Spacer()
                if editor.isLoggingIn { ProgressView().controlSize(.small) }
                Button(action: logIn) {
                    Text(editor.isLoggingIn ? "Logging in…" : "Log in")
                        .fontWeight(.medium).padding(.horizontal, 16).padding(.vertical, 3)
                }
                .buttonStyle(LuminareSurfaceButtonStyle(tinted: true)).luminareMinHeight(30)
                .fixedSize().disabled(!canLogIn)
            }.padding(.top, 2)
        }.font(.system(size: 12)).padding(4)
    }

    private var canLogIn: Bool {
        editor.available && !editor.busy && !draft.server.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !draft.email.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !password.isEmpty
    }

    private func logIn() {
        guard canLogIn else { return }
        focus = .password
        application.stageEnrollment(password: password, replacement: draft)
    }
}
