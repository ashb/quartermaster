import AppKit
import Luminare
import QuartermasterSecurity
import SwiftUI

struct CredentialHandoffView: View {
    let request: CredentialHandoffRequest
    @ObservedObject var controller: ApprovalController
    let close: () -> Void
    @State var showsDetails = false
    @State private var showsFullRequest = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            ApprovalHeader()
            Text("Allow Restic to use this password?").font(.system(size: 26, weight: .semibold))
            ApprovalCommandCard(
                name: "Restic", command: request.compactCommand,
                directory: CredentialHandoffRequest.escaped(request.workingDirectory),
                access: "Password access", symbol: "key", colour: ApprovalAppearance.accent
            ) {
                Image(systemName: "externaldrive").font(.system(size: 18)).foregroundStyle(.secondary)
                    .frame(width: 20, height: 20)
            }
            Text(request.releaseSummary).font(.system(size: 12)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 10) {
                Text("Started by").font(.system(size: 13, weight: .semibold))
                ProcessScopeTree(
                    rows: request.processRows(), selection: .request, enabled: false,
                    ancestryNote: request.requester.ancestryNote.map(CredentialHandoffRequest.escaped), choose: { _ in }
                )
            }
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Button {
                        showsDetails.toggle()
                    } label: {
                        Label("Request details", systemImage: showsDetails ? "chevron.down" : "chevron.right")
                    }.buttonStyle(.plain)
                    Spacer()
                    Button("Full request…") { showsFullRequest = true }.buttonStyle(.plain)
                        .foregroundStyle(ApprovalAppearance.accent)
                }.font(.system(size: 12))
                if showsDetails {
                    VStack(alignment: .leading, spacing: 12) {
                        detail(
                            "Recipient",
                            "\(URL(fileURLWithPath: request.recipient.executable).lastPathComponent) · PID \(request.recipient.pid)"
                        )
                        detail("Executable", request.recipient.executable)
                        detail("On approval", "Share the password with Restic")
                    }.padding(14).frame(maxWidth: .infinity, alignment: .leading).luminareSurface()
                }
            }
            HStack(spacing: 8) {
                Image(systemName: "key").foregroundStyle(.secondary)
                Text("Vault item").foregroundStyle(.secondary)
                Text(verbatim: request.displayCredentialName).fontWeight(.medium)
                    .lineLimit(2).textSelection(.enabled)
            }.font(.system(size: 12))
            ApprovalAuthenticationFooter(controller: controller, close: close)
        }
        .padding(24).frame(width: 540).fixedSize(horizontal: false, vertical: true)
        .luminareTint(overridingWith: ApprovalAppearance.accent)
        .luminareCornerRadius(12).tint(ApprovalAppearance.accent)
        .sheet(isPresented: $showsFullRequest) { CredentialHandoffDetails(request: request) }
        .onChange(of: controller.phase) { _, phase in if phase == .approved { close() } }
        .transaction { transaction in
            transaction.animation = nil
            transaction.disablesAnimations = true
        }
    }

    private func detail(_ title: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(title).foregroundStyle(.secondary).frame(width: 70, alignment: .leading)
            Text(verbatim: CredentialHandoffRequest.escaped(value))
                .font(.system(size: 11, design: .monospaced)).lineLimit(2).truncationMode(.middle).help(value)
                .frame(maxWidth: .infinity, alignment: .leading)
        }.font(.system(size: 11)).textSelection(.enabled)
    }
}

struct CredentialHandoffDetails: View {
    let request: CredentialHandoffRequest
    @State var tab = Tab.approval
    enum Tab: String, CaseIterable {
        case approval = "Approval"
        case caller = "Caller & ancestry"
        case command = "Command"
    }
    private var text: String {
        switch tab {
        case .approval: request.approvalDetails
        case .caller: request.callerDetails
        case .command: request.commandDetails
        }
    }
    var body: some View {
        ApprovalDetailsSheet(subtitle: request.displayCredentialName, text: text, fullDetails: request.fullDetails) {
            Picker("Details", selection: $tab) {
                ForEach(Tab.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }.pickerStyle(.segmented).labelsHidden()
        }
    }
}

@MainActor private final class HandoffDialogDismissal {
    weak var window: NSWindow?
    func close() { window?.performClose(nil) }
}

@MainActor
public final class CredentialHandoffDialog: NSObject, NSWindowDelegate, ApprovalWindow {
    public let window: NSWindow
    public let controller: ApprovalController
    public var onClose: (() -> Void)?

    public init(
        request: CredentialHandoffRequest, backend: any ApprovalBackend, keys: ApprovalKeyStore = ApprovalKeyStore()
    ) {
        let controller = ApprovalController(
            backend: backend, reason: "release this vault password to this Restic process once", keys: keys)
        self.controller = controller
        let dismissal = HandoffDialogDismissal()
        window = LuminareWindow(titleBarButtonConfiguration: nil) {
            CredentialHandoffView(request: request, controller: controller, close: dismissal.close)
        }
        dismissal.window = window
        super.init()
        window.title = "Quartermaster credential handoff"
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
