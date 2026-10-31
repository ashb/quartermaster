import AppKit
import Darwin
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import Luminare
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
    let ancestryNote: String?
    let commandLine: String?
    var workingDirectory: String? = nil
    var processes: [DialogProcess]? = nil
    var startedUnixMicros: UInt64? = nil
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
    let display: ApprovalDisplay
    var readGrant: ReadGrantReview? { display.grant }
    let apiRequest: APIRequestReview?
    let readScope: ReadScopeReview?

    public init(
        request: DialogRequest, provider: ApprovalProviderIdentity, display: ApprovalDisplay,
        apiRequest: APIRequestReview? = nil, readScope: ReadScopeReview? = nil
    ) {
        self.request = request
        self.provider = provider
        self.display = display
        self.apiRequest = apiRequest
        self.readScope = readScope
    }

    var repository: String? { display.repository }
    var additionalEffects: [String] { display.additionalEffects.map(\.label) }
    var understandingNotice: String? { display.understandingNotice?.text }
    var operationTitle: String { display.title }
    var authenticationReason: String { display.authenticationReason }

    var ancestryNotice: String? {
        guard let peer = request.peer, !peer.ancestryComplete else { return nil }
        return peer.ancestryNote ?? "Earlier ancestors could not be inspected."
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

@MainActor
public protocol ApprovalWindow: AnyObject {
    var onClose: (() -> Void)? { get set }
    func show(centred: Bool)
    func cancel()
}

@MainActor private final class ApprovalDialogContent: ObservableObject {
    @Published var presentation: ApprovalPresentation
    @Published var controller: ApprovalController
    var close: () -> Void = {}
    var selectRoot: ((String?) async -> Void)?

    init(presentation: ApprovalPresentation, controller: ApprovalController) {
        self.presentation = presentation
        self.controller = controller
    }
}

private struct ApprovalDialogHost: View {
    @ObservedObject var content: ApprovalDialogContent

    var body: some View {
        ApprovalDialogView(
            presentation: content.presentation, controller: content.controller,
            close: content.close, selectRoot: content.selectRoot)
    }
}

@MainActor
public final class ApprovalDialog: NSObject, NSWindowDelegate, ApprovalWindow {
    public private(set) var controller: ApprovalController
    public let window: NSWindow
    public var onClose: (() -> Void)?
    private let backend: any ApprovalBackend
    private let keys: ApprovalKeyStore
    private let selectRoot: ((String?) async throws -> ApprovalPresentation)?
    private let content: ApprovalDialogContent

    public init(
        presentation: ApprovalPresentation, backend: any ApprovalBackend, keys: ApprovalKeyStore = ApprovalKeyStore(),
        selectRoot: ((String?) async throws -> ApprovalPresentation)? = nil
    ) {
        self.backend = backend
        self.keys = keys
        self.selectRoot = selectRoot
        controller = ApprovalController(backend: backend, reason: presentation.authenticationReason, keys: keys)
        let content = ApprovalDialogContent(presentation: presentation, controller: controller)
        self.content = content
        window = LuminareWindow(titleBarButtonConfiguration: nil) { ApprovalDialogHost(content: content) }
        super.init()
        window.title = "Quartermaster approval"
        window.level = .floating
        window.isMovableByWindowBackground = true
        window.hidesOnDeactivate = false
        window.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        window.isReleasedWhenClosed = false
        window.delegate = self
        content.close = { [weak self] in self?.window.performClose(nil) }
        content.selectRoot = selectRoot == nil ? nil : { [weak self] root in await self?.choose(root) }
        install(presentation)
    }

    func install(_ presentation: ApprovalPresentation) {
        content.presentation = presentation
        content.controller = controller
    }

    func choose(_ root: String?) async {
        guard let selectRoot, controller.supersedeReview() else { return }
        do {
            let presentation = try await selectRoot(root)
            guard window.isVisible else {
                backend.cancel()
                return
            }
            controller = ApprovalController(backend: backend, reason: presentation.authenticationReason, keys: keys)
            install(presentation)
        } catch {
            controller.scopeChangeFailed()
        }
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
        if controller.phase == .stopped || controller.phase == .superseded { backend.cancel() }
        controller.cancel()
        onClose?()
    }
}
