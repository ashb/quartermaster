import AppKit
import Darwin
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import QuartermasterSecurity
import SwiftUI

public enum DialogPresentationLease {
    public enum Failure: Error {
        case alreadyPresented
        case invalidLock
        case system(Int32)
    }

    public static func acquire() throws -> Int32 {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true)
        let directory = support.appendingPathComponent("Quartermaster/Development", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        var parent = stat()
        guard lstat(directory.path, &parent) == 0, parent.st_uid == geteuid(),
            parent.st_mode & S_IFMT == S_IFDIR, parent.st_mode & 0o077 == 0
        else { throw Failure.invalidLock }
        let path = directory.appendingPathComponent("approval-presentation.lock").path
        let descriptor = open(path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw Failure.system(errno) }
        var attributes = stat()
        guard fstat(descriptor, &attributes) == 0,
            attributes.st_uid == geteuid(), attributes.st_nlink == 1,
            attributes.st_mode & S_IFMT == S_IFREG, attributes.st_mode & 0o077 == 0
        else {
            close(descriptor)
            throw Failure.invalidLock
        }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            let code = errno
            close(descriptor)
            if code == EWOULDBLOCK { throw Failure.alreadyPresented }
            throw Failure.system(code)
        }
        return descriptor
    }
}

public struct DialogPeer: Codable, Equatable {
    let pid: UInt32
    let executable: String
    let signingIdentifier: String
    let teamIdentifier: String?
    let cdHash: String
    let adHoc: Bool
    let ancestryComplete: Bool
    let commandLine: String?
}

public struct DialogRequest: Codable, Equatable {
    public let repository: String
    public let issue: UInt64?
    public let method: String
    public let path: String
    public let body: String
    public let processChain: [String]
    public var origin: String? = nil
    public var peer: DialogPeer? = nil

}

public struct ApprovalPresentation {
    let request: DialogRequest
    let provider: ApprovalProviderIdentity
    let readGrant: ReadGrantReview?

    public init(request: DialogRequest, provider: ApprovalProviderIdentity, readGrant: ReadGrantReview?) {
        self.request = request
        self.provider = provider
        self.readGrant = readGrant
    }

    var operationTitle: String {
        readGrant == nil ? "Close issue #\(request.issue.map(String.init) ?? "?")" : "Allow issue reads"
    }

    var authenticationReason: String {
        readGrant == nil
            ? "approve closing issue \(request.issue.map(String.init) ?? "?") in \(request.repository)"
            : "allow issue reads in \(request.repository)"
    }
}

@MainActor
final class EmbeddedAuthenticationHost: NSView {
    let onVisible: @MainActor () -> Void

    init(context: LAContext, onVisible: @escaping @MainActor () -> Void) {
        self.onVisible = onVisible
        super.init(frame: NSRect(x: 0, y: 0, width: 32, height: 32))
        let authentication = LAAuthenticationView(context: context, controlSize: .small)
        authentication.translatesAutoresizingMaskIntoConstraints = false
        addSubview(authentication)
        NSLayoutConstraint.activate([
            authentication.leadingAnchor.constraint(equalTo: leadingAnchor),
            authentication.trailingAnchor.constraint(equalTo: trailingAnchor),
            authentication.topAnchor.constraint(equalTo: topAnchor),
            authentication.bottomAnchor.constraint(equalTo: bottomAnchor),
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        guard window != nil else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self, self.window?.isVisible == true else { return }
            self.onVisible()
        }
    }
}

struct EmbeddedAuthentication: NSViewRepresentable {
    let context: LAContext
    let onVisible: @MainActor () -> Void

    func makeNSView(context: Context) -> EmbeddedAuthenticationHost {
        EmbeddedAuthenticationHost(context: self.context, onVisible: onVisible)
    }

    func updateNSView(_ view: EmbeddedAuthenticationHost, context: Context) {}
}

struct ApprovalDialogView: View {
    let presentation: ApprovalPresentation
    @ObservedObject var controller: ApprovalController
    let close: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            HStack(spacing: 14) {
                Image(systemName: "key.horizontal.fill")
                    .font(.system(size: 27)).foregroundStyle(.white)
                    .frame(width: 58, height: 58).background(.indigo, in: RoundedRectangle(cornerRadius: 14))
                VStack(alignment: .leading, spacing: 4) {
                    Text("Quartermaster").font(.headline).foregroundStyle(.secondary)
                    Text("Approve this request").font(.title2.bold())
                }
            }

            VStack(alignment: .leading, spacing: 12) {
                Text(presentation.operationTitle).font(.headline)
                Text(presentation.request.repository).foregroundStyle(.secondary)
                if let grant = presentation.readGrant {
                    Text("List and read issues · up to \(grant.budget) requests")
                    Text(grant.principalScope).font(.caption)
                    if grant.isSimulation { Text("Simulation · no GitHub request").font(.caption) }
                    Text("Until \(grant.expires.formatted(date: .omitted, time: .standard)) or backend restart")
                        .font(.caption).foregroundStyle(.secondary)
                }
                let provider = presentation.provider
                Group {
                    Text("\(provider.email) · \(provider.server)").font(.caption)
                    DisclosureGroup("Vault selection") {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Account: \(provider.account)")
                            Text("Item: \(provider.item)")
                            Text("Login password · \(provider.role)")
                            Text("Enrolment: \(provider.enrollment) · generation \(provider.generation)")
                        }.font(.caption.monospaced()).textSelection(.enabled)
                    }.font(.caption)
                }
                if let peer = presentation.request.peer {
                    Text(peer.commandLine ?? "Command arguments unavailable")
                        .font(.system(.caption, design: .monospaced)).lineLimit(3)
                        .help(peer.commandLine ?? "Command arguments unavailable")
                    DisclosureGroup("HTTP request") {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(
                                "\(presentation.request.method) \(presentation.request.origin ?? "")\(presentation.request.path)"
                            )
                            Text(presentation.request.body)
                        }.font(.caption.monospaced()).textSelection(.enabled)
                    }.font(.caption)
                    DisclosureGroup("Socket peer: PID \(peer.pid) · signature checked") {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(peer.executable)
                            Text(
                                "\(peer.signingIdentifier) · \(peer.adHoc ? "ad-hoc signature" : peer.teamIdentifier ?? "no Team ID")"
                            )
                            Text("CDHash: \(peer.cdHash)")
                        }.font(.caption.monospaced()).textSelection(.enabled)
                    }.font(.caption)
                }
                Divider()
                Text("OBSERVED PROCESS CHAIN · CONTEXT ONLY")
                    .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                ForEach(Array(presentation.request.processChain.enumerated()), id: \.offset) { index, process in
                    HStack(spacing: 8) {
                        Image(systemName: index == 0 ? "terminal" : "arrow.turn.down.right").foregroundStyle(.secondary)
                        Text(process).font(.system(.body, design: .monospaced)).lineLimit(1).help(process)
                    }.padding(.leading, CGFloat(index) * 18)
                }
                Text(statusDetail)
                    .font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1).help(statusDetail)
            }
            .padding(18).frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))

            HStack(spacing: 12) {
                Button(controller.phase == .stopped ? "Close" : "Cancel") {
                    controller.cancel()
                    close()
                }.keyboardShortcut(.cancelAction)
                Spacer()
                Text(authenticationTitle).font(.headline)
                EmbeddedAuthentication(context: controller.context, onVisible: { Task { await controller.approve() } })
                    .frame(width: 32, height: 32)
            }
        }
        .onChange(of: controller.phase) { _, phase in
            if phase == .approved { close() }
        }
        .padding(28).frame(width: 540)
        .fixedSize(horizontal: false, vertical: true)
        .background(Color(nsColor: .windowBackgroundColor))
        .overlay(alignment: .topTrailing) {
            Text("[DEBUG BUILD. Insecure]")
                .font(.caption.bold()).foregroundStyle(.yellow)
                .padding(.horizontal, 10).padding(.vertical, 5)
                .background(.red.opacity(0.3), in: RoundedRectangle(cornerRadius: 6))
                .padding(28)
        }
    }

    private var statusDetail: String {
        if !controller.detail.isEmpty { return controller.detail }
        if presentation.readGrant != nil {
            return "Further permitted reads need no prompt while this grant remains valid."
        }
        return "Local simulation — no GitHub action will run."
    }

    private var authenticationTitle: String {
        switch controller.phase {
        case .review: "Preparing Touch ID"
        case .authenticating: "Authorize with Touch ID"
        case .approved: "Request approved"
        case .stopped: "Request stopped"
        }
    }
}

@MainActor
public final class ApprovalDialog: NSObject, NSWindowDelegate {
    public let controller: ApprovalController
    public let window: NSWindow
    public var onClose: (() -> Void)?

    public init(
        presentation: ApprovalPresentation, backend: any ApprovalBackend, keys: ApprovalKeyStore = ApprovalKeyStore()
    ) {
        controller = ApprovalController(backend: backend, reason: presentation.authenticationReason, keys: keys)
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 596, height: 460),
            styleMask: [.titled, .closable], backing: .buffered, defer: false)
        super.init()
        window.title = "Quartermaster approval"
        window.isReleasedWhenClosed = false
        window.delegate = self
        let window = self.window
        window.contentView = NSHostingView(
            rootView: ApprovalDialogView(
                presentation: presentation, controller: controller,
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
