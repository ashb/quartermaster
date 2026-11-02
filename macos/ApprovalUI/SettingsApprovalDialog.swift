import AppKit
import Luminare
import QuartermasterSecurity
import SwiftUI

private struct SettingsApprovalView: View {
    let review: SettingsReview
    let document: SettingsDocument
    let migration: SettingsMigrationAction?
    @ObservedObject var controller: ApprovalController
    let close: () -> Void
    private var importing: Bool { migration == .importSettings }
    private var discarding: Bool { migration == .discard }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Label(
                importing
                    ? "Import and trust previous settings"
                    : discarding ? "Discard previous settings" : "Approve preferences", systemImage: "gearshape.fill"
            ).font(.title2.bold())
            Text(
                importing
                    ? "Review these settings before importing them."
                    : discarding
                        ? "Start afresh with no vault selected and GitHub disabled. Your encrypted cache is kept."
                        : "Revision \(document.previous.revision) → \(document.proposed.revision)"
            )
            .foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if migration == nil {
                        record(document.previous, title: "Currently approved")
                        Divider()
                    }
                    record(
                        document.proposed,
                        title: importing ? "Settings to import" : discarding ? "Settings after discarding" : "Proposed",
                        additions: document.additions ?? [])
                    DisclosureSection("Complete proposal · literal byte escapes") {
                        ScrollView(.horizontal) {
                            Text(verbatim: review.text).font(.caption.monospaced()).textSelection(.enabled)
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading).padding()
            }.frame(height: 330).luminareSurface()
            Text(
                "This selects the vault and rules. API requests still require their own applicable authorisation."
            )
            .font(.caption).foregroundStyle(.secondary)
            HStack {
                Button(controller.phase == .stopped ? "Close" : "Cancel") {
                    controller.cancel()
                    close()
                }
                .keyboardShortcut(.cancelAction)
                Spacer()
                Text(controller.detail.isEmpty ? "Save with Touch ID" : controller.detail).font(.callout)
                EmbeddedAuthentication(
                    context: controller.context, onVisible: { Task { await controller.approve() } }
                )
                .frame(width: 32, height: 32)
            }
        }
        .padding(24).frame(width: 600)
        .buttonStyle(CompactButtonStyle())
        .luminareTint(overridingWith: ApprovalAppearance.accent)
        .luminareCornerRadius(12)
        .luminareMinHeight(28)
        .onChange(of: controller.phase) { _, phase in if phase == .approved { close() } }
    }

    private func record(_ record: SettingsRecord, title: String, additions: [RepositoryName] = []) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            if let provider = record.provider {
                Text(verbatim: "\(provider.binding.email) · \(provider.binding.server)")
                Text(
                    verbatim:
                        "Account: \(provider.binding.accountID)"
                )
                .font(.caption.monospaced())
            } else {
                Text("No vault selected")
            }
            if let github = record.settings?.github {
                Text(
                    "GitHub \(github.enabled ? "enabled" : "disabled") · \(github.repositories.count + additions.count) repositories"
                )
                if let credential = record.settings?.githubCredential {
                    Text(
                        verbatim:
                            "Login item: \(credential.displayName) · \(escapeApprovalText(credential.itemId))"
                    )
                    .font(.caption.monospaced())
                } else {
                    Text("No GitHub credential selected").font(.caption)
                }
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
                    ? "Recognised writes: denied" : "Recognised writes: fingerprint per use")

        }.textSelection(.enabled)
    }
}

@MainActor private final class SettingsDialogDismissal {
    weak var window: NSWindow?
    func close() { window?.performClose(nil) }
}

@MainActor
public final class SettingsApprovalDialog: NSObject, NSWindowDelegate, ApprovalWindow {
    public let window: NSWindow
    public let controller: ApprovalController
    public var onClose: (() -> Void)?

    public init(
        review: SettingsReview, document: SettingsDocument, backend: any ApprovalBackend,
        migration: SettingsMigrationAction? = nil
    ) {
        let controller = ApprovalController(
            backend: backend,
            reason: migration == .importSettings
                ? "import and trust these Quartermaster settings"
                : migration == .discard
                    ? "discard these previous Quartermaster settings"
                    : "approve these Quartermaster preferences")
        self.controller = controller
        let dismissal = SettingsDialogDismissal()
        window = LuminareWindow(titleBarButtonConfiguration: nil) {
            SettingsApprovalView(
                review: review, document: document, migration: migration, controller: controller,
                close: dismissal.close)
        }
        dismissal.window = window
        super.init()
        window.title =
            switch migration {
            case .importSettings: "Quartermaster settings import"
            case .discard: "Quartermaster settings reset"
            case nil: "Quartermaster preferences approval"
            }
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.isMovableByWindowBackground = true
        window.hidesOnDeactivate = false
        window.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        window.delegate = self
    }

    public func show(centred: Bool) {
        if centred { window.center() }
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
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
