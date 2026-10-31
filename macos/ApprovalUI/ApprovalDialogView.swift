import AppKit
import Luminare
import QuartermasterSecurity
import SwiftUI

struct ApprovalDialogView: View {
    let presentation: ApprovalPresentation
    @ObservedObject var controller: ApprovalController
    let close: () -> Void
    var selectRoot: ((String?) async -> Void)? = nil
    @State private var selecting = false
    @State private var showsDetails = false
    @State private var showsFullRequest = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "key.fill").font(.system(size: 18)).foregroundStyle(ApprovalAppearance.accent)
                Text("Quartermaster").font(.system(size: 14, weight: .semibold))
                Spacer()
                #if DEBUG
                    Text("DEBUG BUILD · Insecure")
                        .font(.system(size: 10, weight: .semibold)).foregroundStyle(.orange)
                #endif
            }
            VStack(alignment: .leading, spacing: 7) {
                Text(presentation.operationTitle).font(.system(size: 26, weight: .semibold))
                if let repository = presentation.repository {
                    Label {
                        Text(verbatim: repository)
                    } icon: {
                        Image(systemName: "folder")
                    }
                    .font(.system(size: 14)).foregroundStyle(.secondary).textSelection(.enabled)
                }
                if let title = presentation.display.resourceTitle {
                    Text(verbatim: title).font(.system(size: 13)).lineLimit(3).help(title)
                }
            }
            LuminareSection {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 8) {
                        GitHubIcon(size: 20)
                        Text(presentation.callerName).font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(.secondary)
                        Spacer()
                        Label(presentation.accessLabel, systemImage: presentation.isReadOnly ? "eye" : "pencil")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(presentation.isReadOnly ? Color.teal : Color.orange)
                            .padding(.horizontal, 10).padding(.vertical, 5)
                            .background(
                                (presentation.isReadOnly ? Color.teal : Color.orange).opacity(0.12),
                                in: RoundedRectangle(cornerRadius: 7))
                    }
                    let command = Text(
                        verbatim: presentation.request.peer?.commandLine ?? "Command arguments unavailable"
                    )
                    .font(.system(size: 14, design: .monospaced)).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    ViewThatFits(in: .vertical) {
                        command
                        ScrollView(.vertical) { command }.frame(height: 80)
                    }.frame(maxHeight: 80).fixedSize(horizontal: false, vertical: true)
                    if let directory = presentation.request.peer?.workingDirectory {
                        Label {
                            Text(verbatim: directory)
                        } icon: {
                            Image(systemName: "folder")
                        }
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                        .lineLimit(2).truncationMode(.middle).help(directory)
                    }
                }.padding(12)
            }
            if presentation.readScope != nil {
                Text(
                    presentation.readGrant?.permission.compactSummary
                        ?? "This request only. Later requests need approval."
                )
                .font(.system(size: 12)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
            VStack(alignment: .leading, spacing: 10) {
                Text(presentation.readScope == nil ? "Started by" : "Allow for")
                    .font(.system(size: 13, weight: .semibold))
                if let peer = presentation.request.peer, let processes = peer.processes {
                    ProcessScopeTree(
                        rows: ProcessTreeRow.make(
                            processes: processes, peerPID: peer.pid,
                            roots: presentation.readScope?.roots ?? [],
                            allowsSelection: presentation.readScope != nil),
                        selection: presentation.readGrant.map { .root($0.root.id) } ?? .request,
                        enabled: selectRoot != nil && !selecting && controller.canChangeScope,
                        ancestryNote: presentation.ancestryNotice
                    ) { choice in
                        if let selectRoot { choose(choice.rootID, using: selectRoot) }
                    }
                } else {
                    ForEach(Array(presentation.request.processChain.enumerated()), id: \.offset) { index, process in
                        Text(verbatim: process).font(.system(size: 13, design: .monospaced))
                            .padding(.leading, CGFloat(index) * 18)
                    }
                }
            }
            if presentation.readGrant == nil {
                if !presentation.additionalEffects.isEmpty {
                    Text("Requested actions: \(presentation.additionalEffects.joined(separator: ", "))")
                        .font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
                }
                if let notice = presentation.understandingNotice {
                    Label(notice, systemImage: "exclamationmark.triangle")
                        .font(.system(size: 12)).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
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
                    ApprovalInlineDetails(presentation: presentation)
                }
            }
            HStack(spacing: 8) {
                Image(systemName: "lock.shield").foregroundStyle(.secondary)
                Text("Vault").foregroundStyle(.secondary)
                Spacer()
                Text(verbatim: presentation.provider.email).lineLimit(1).truncationMode(.middle)
                    .help(presentation.provider.server)
            }.font(.system(size: 12))
            if !controller.detail.isEmpty {
                Text(controller.detail).font(.caption).foregroundStyle(.secondary)
            }
            HStack(spacing: 12) {
                Button {
                    controller.cancel()
                    close()
                } label: {
                    Text(cancelTitle).frame(width: 70)
                }.buttonStyle(CompactButtonStyle()).luminareMinHeight(36)
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Text(authenticationTitle).font(.system(size: 13, weight: .medium))
                    .foregroundStyle(.secondary)
                EmbeddedAuthentication(context: controller.context, onVisible: { Task { await controller.approve() } })
                    .id(ObjectIdentifier(controller.context)).frame(width: 32, height: 32)
            }
        }
        .onChange(of: controller.phase) { _, phase in
            if phase == .approved { close() }
        }
        .sheet(isPresented: $showsFullRequest) { ApprovalRequestDetails(presentation: presentation) }
        .padding(24).frame(width: 540).fixedSize(horizontal: false, vertical: true)
        .luminareTint(overridingWith: ApprovalAppearance.accent)
        .luminareCornerRadius(12)
        .tint(ApprovalAppearance.accent)
        .transaction { transaction in
            transaction.animation = nil
            transaction.disablesAnimations = true
        }
    }

    private func choose(_ root: String?, using selectRoot: @escaping (String?) async -> Void) {
        guard presentation.readGrant?.root.id != root else { return }
        selecting = true
        Task {
            await selectRoot(root)
            selecting = false
        }
    }

    var cancelTitle: String { controller.phase == .stopped ? "Close" : "Cancel" }

    var authenticationTitle: String {
        switch controller.phase {
        case .review, .authenticating, .superseded: "Use Touch ID to authorise"
        case .authorizing: "Approving request"
        case .approved: "Request approved"
        case .stopped: "Request stopped"
        }
    }
}
