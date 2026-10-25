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
    public let body: String?
    public let processChain: [String]
    public var origin: String? = nil
    public var peer: DialogPeer? = nil

}

public struct ApprovalPresentation {
    let request: DialogRequest
    let provider: ApprovalProviderIdentity
    let readGrant: ReadGrantReview?
    let apiRequest: APIRequestReview?

    public init(
        request: DialogRequest, provider: ApprovalProviderIdentity, readGrant: ReadGrantReview?,
        apiRequest: APIRequestReview? = nil
    ) {
        self.request = request
        self.provider = provider
        self.readGrant = readGrant
        self.apiRequest = apiRequest
    }

    var operationTitle: String {
        if let api = apiRequest, readGrant == nil, api.complete, api.effects == ["Close issue"],
            let issue = request.issue
        {
            return "Close issue #\(issue)"
        }
        return readGrant == nil ? "Approve one GitHub request" : "Allow issue reads"
    }

    var authenticationReason: String {
        return readGrant == nil
            ? "approve this GitHub request once"
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
    @State private var showsDetails = false
    @State private var showsVault = false
    @State private var showsHTTP = false
    @State private var showsPeer = false

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 14) {
                Image(systemName: "key.horizontal.fill")
                    .font(.system(size: 23)).foregroundStyle(.white)
                    .frame(width: 48, height: 48).background(.indigo, in: RoundedRectangle(cornerRadius: 12))
                VStack(alignment: .leading, spacing: 4) {
                    Text("Quartermaster").font(.headline).foregroundStyle(.secondary)
                    Text(presentation.operationTitle).font(.title2.bold())
                }
                Spacer()
                Text("[DEBUG BUILD. Insecure]")
                    .font(.caption2.bold()).foregroundStyle(.yellow)
                    .padding(.horizontal, 8).padding(.vertical, 5)
                    .background(.red.opacity(0.3), in: RoundedRectangle(cornerRadius: 6))
            }

            if let peer = presentation.request.peer {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Command").font(.caption).foregroundStyle(.secondary)
                    Text(verbatim: peer.commandLine ?? "Command arguments unavailable")
                        .font(.system(.body, design: .monospaced)).textSelection(.enabled)
                }
            }

            VStack(alignment: .leading, spacing: 6) {
                Text(presentation.request.repository.isEmpty ? "Destination" : "Repository")
                    .font(.caption).foregroundStyle(.secondary)
                Text(
                    presentation.request.repository.isEmpty
                        ? presentation.request.origin ?? "" : presentation.request.repository
                ).font(.headline)
                if let grant = presentation.readGrant {
                    Text("Until \(grant.expires.formatted(date: .omitted, time: .shortened)) or backend restart")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
            }

            VStack(alignment: .leading, spacing: 10) {
                Text("Process tree").font(.subheadline.weight(.semibold))
                ForEach(Array(presentation.request.processChain.reversed().enumerated()), id: \.offset) {
                    index, process in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: index == 0 ? "terminal" : "arrow.turn.down.right").foregroundStyle(.secondary)
                        Text(verbatim: process).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    }.padding(.leading, CGFloat(index) * 14)
                }
                Text("Observed process ancestry").font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            if let api = presentation.apiRequest, presentation.readGrant == nil {
                VStack(alignment: .leading, spacing: 12) {
                    Text("One request · no reusable access")
                    Text(
                        "Repository scope is unverified. This request may use the selected credential’s full upstream permissions."
                    )
                    .font(.caption)
                    if !api.effects.isEmpty {
                        Text("Recognized effects: \(api.effects.joined(separator: ", "))").font(.caption)
                    }
                    if !api.complete {
                        Text("Some inputs are unfamiliar; the complete effects are unverified.").font(.caption)
                    }
                    ScrollView([.horizontal, .vertical]) {
                        Text(verbatim: api.text).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }.frame(height: 180)
                    Text(
                        "Authentication is replaced with the selected credential. HTTP framing uses a fixed body length and closes the connection. Byte escapes are shown literally."
                    )
                    .font(.caption).foregroundStyle(.secondary)
                }
            }

            DisclosureGroup("Details", isExpanded: $showsDetails) {
                ViewThatFits(in: .vertical) {
                    detailsContent
                    ScrollView(.vertical) {
                        detailsContent
                    }.frame(height: 300)
                }
                .frame(maxHeight: 300)
                .fixedSize(horizontal: false, vertical: true)
            }

            if !controller.detail.isEmpty {
                Text(controller.detail).font(.caption).foregroundStyle(.secondary)
            }

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
        .padding(24).frame(width: 540)
        .fixedSize(horizontal: false, vertical: true)
        // AppKit resizes immediately, so disclosure layout must not animate independently.
        .transaction { transaction in
            transaction.animation = nil
            transaction.disablesAnimations = true
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var detailsContent: some View {
        VStack(alignment: .leading, spacing: 12) {
            let provider = presentation.provider
            Group {
                Text("\(provider.email) · \(provider.server)").font(.caption)
                DisclosureGroup("Vault selection", isExpanded: $showsVault) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Account: \(provider.account)")
                        Text("Item: \(provider.item)")
                        Text("Login password · \(provider.role)")
                        Text("Enrolment: \(provider.enrollment) · generation \(provider.generation)")
                    }.font(.caption.monospaced()).textSelection(.enabled)
                }.font(.caption)
            }
            if let peer = presentation.request.peer {
                DisclosureGroup("HTTP request", isExpanded: $showsHTTP) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(
                            "\(presentation.request.method) \(presentation.request.origin ?? "")\(presentation.request.path)"
                        )
                        if let api = presentation.apiRequest {
                            ScrollView([.horizontal, .vertical]) {
                                Text(verbatim: api.text)
                            }.frame(height: 180)
                        } else {
                            Text(presentation.request.body ?? "")
                        }
                    }.font(.caption.monospaced()).textSelection(.enabled)
                }.font(.caption)
                DisclosureGroup(isExpanded: $showsPeer) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(peer.executable)
                        Text(
                            "\(peer.signingIdentifier) · \(peer.adHoc ? "ad-hoc signature" : peer.teamIdentifier ?? "no Team ID")"
                        )
                        Text("CDHash: \(peer.cdHash)")
                    }.font(.caption.monospaced()).textSelection(.enabled)
                } label: {
                    Text(verbatim: "Socket peer: PID \(String(peer.pid)) · signature checked")
                }.font(.caption)
            }
        }
        .padding(.top, 10).frame(maxWidth: .infinity, alignment: .leading)
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
public protocol ApprovalWindow: AnyObject {
    var window: NSWindow { get }
    var onClose: (() -> Void)? { get set }
    func cancel()
}

@MainActor
public final class ApprovalDialog: NSObject, NSWindowDelegate, ApprovalWindow {
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
