import AppKit
import QuartermasterSecurity
import SwiftUI

private struct SettingsApprovalView: View {
    let review: SettingsReview
    let document: SettingsDocument
    @ObservedObject var controller: ApprovalController
    let close: () -> Void
    @State private var saving = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Label("Approve preferences", systemImage: "gearshape.fill").font(.title2.bold())
            Text("Revision \(document.previous.revision) → \(document.proposed.revision)")
                .foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    record(document.previous, title: "Currently approved")
                    Divider()
                    record(document.proposed, title: "Proposed", additions: document.additions ?? [])
                    DisclosureSection("Complete proposal · literal byte escapes") {
                        ScrollView(.horizontal) {
                            Text(verbatim: review.text).font(.caption.monospaced()).textSelection(.enabled)
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading).padding()
            }.frame(height: 330).background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 10))
            Text("This selects the vault and rules. API requests still require their own applicable authorization.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Button(controller.phase == .stopped ? "Close" : "Cancel") {
                    controller.cancel()
                    close()
                }
                .keyboardShortcut(.cancelAction)
                Spacer()
                if saving {
                    Text(controller.detail.isEmpty ? "Save with Touch ID" : controller.detail).font(.callout)
                    EmbeddedAuthentication(
                        context: controller.context, onVisible: { Task { await controller.approve() } }
                    )
                    .frame(width: 32, height: 32)
                } else {
                    Button("Save Changes") { saving = true }
                        .keyboardShortcut(.defaultAction)
                        .disabled(controller.phase != .review)
                }
            }
        }
        .padding(24).frame(width: 600)
        .onChange(of: controller.phase) { _, phase in if phase == .approved { close() } }
    }

    private func record(_ record: SettingsRecord, title: String, additions: [RepositoryName] = []) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            if let provider = record.provider {
                Text(verbatim: "\(provider.binding.email) · \(provider.binding.server)")
                Text(
                    verbatim:
                        "Account: \(provider.binding.accountID)\nLogin item: \(provider.binding.itemID)\nField: \(provider.binding.field) · role: \(provider.binding.role)"
                )
                .font(.caption.monospaced())
            } else {
                Text("No vault selected")
            }
            if let github = record.settings?.github {
                Text("GitHub enabled · \(github.repositories.count + additions.count) repositories")
                ForEach(github.repositories) { repo in
                    Text(verbatim: "\(repo.owner)/\(repo.name)").font(.caption.monospaced())
                }
                ForEach(additions) { repo in Text(verbatim: repo.fullName).font(.caption.monospaced()) }
                if !additions.isEmpty {
                    Text("Repository identities will be checked using the selected token before saving.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text(
                    github.approveUnverifiedRequests
                        ? "Unfamiliar requests: fingerprint per use" : "Unfamiliar requests: denied")
            } else {
                Text("GitHub disabled")
            }
            Text(
                record.settings?.mutations == .deny
                    ? "Recognized mutations: denied" : "Recognized mutations: fingerprint per use")
        }.textSelection(.enabled)
    }
}

@MainActor
public final class SettingsApprovalDialog: NSObject, NSWindowDelegate, ApprovalWindow {
    public let window: NSWindow
    public let controller: ApprovalController
    public var onClose: (() -> Void)?

    public init(review: SettingsReview, document: SettingsDocument, backend: any ApprovalBackend) {
        controller = ApprovalController(backend: backend, reason: "approve these Quartermaster preferences")
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 648, height: 530), styleMask: [.titled, .closable],
            backing: .buffered, defer: false)
        super.init()
        window.title = "Quartermaster preferences approval"
        window.isReleasedWhenClosed = false
        window.delegate = self
        let window = window
        window.contentView = NSHostingView(
            rootView: SettingsApprovalView(
                review: review, document: document, controller: controller,
                close: { [weak window] in window?.performClose(nil) }))
    }

    public func cancel() {
        controller.cancel()
        window.performClose(nil)
    }
    public func windowWillClose(_ notification: Notification) {
        controller.cancel()
        onClose?()
    }
}
