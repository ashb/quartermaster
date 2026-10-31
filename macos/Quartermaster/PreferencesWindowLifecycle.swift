import AppKit
import SwiftUI

struct PreferencesWindowLifecycle: NSViewRepresentable {
    let opened: @MainActor (NSWindow) -> Void
    let closed: @MainActor () -> Void

    func makeNSView(context: Context) -> PreferencesWindowObserver {
        PreferencesWindowObserver(opened: opened, closed: closed)
    }

    func updateNSView(_ view: PreferencesWindowObserver, context: Context) {}
}

final class PreferencesWindowObserver: NSView {
    private let opened: @MainActor (NSWindow) -> Void
    private let closed: @MainActor () -> Void
    private let titleLabel = NSHostingView(rootView: PreferencesWindowTitle())

    init(opened: @escaping @MainActor (NSWindow) -> Void, closed: @escaping @MainActor () -> Void) {
        self.opened = opened
        self.closed = closed
        super.init(frame: .zero)
        titleLabel.identifier = NSUserInterfaceItemIdentifier("QuartermasterTitle")
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        NotificationCenter.default.removeObserver(self)
        titleLabel.removeFromSuperview()
        guard let window else { return }
        window.title = "Quartermaster"
        window.titleVisibility = .hidden
        window.level = .normal
        window.styleMask.insert([.resizable, .fullSizeContentView])
        window.titlebarAppearsTransparent = true
        if let titleBar = window.standardWindowButton(.closeButton)?.superview {
            titleBar.addSubview(titleLabel)
            NSLayoutConstraint.activate([
                titleLabel.leadingAnchor.constraint(equalTo: titleBar.leadingAnchor, constant: 86),
                titleLabel.centerYAnchor.constraint(equalTo: titleBar.centerYAnchor),
                titleLabel.heightAnchor.constraint(equalToConstant: 22),
                titleLabel.widthAnchor.constraint(equalToConstant: 160),
            ])
        }
        NotificationCenter.default.addObserver(
            self, selector: #selector(becameKey(_:)), name: NSWindow.didBecomeKeyNotification, object: window)
        NotificationCenter.default.addObserver(
            self, selector: #selector(willClose(_:)), name: NSWindow.willCloseNotification, object: window)
        if window.isKeyWindow { opened(window) }
    }

    @objc private func becameKey(_ notification: Notification) {
        if let window { opened(window) }
    }
    @objc private func willClose(_ notification: Notification) { closed() }
}

private struct PreferencesWindowTitle: View {
    var body: some View {
        Text("Quartermaster")
            .font(.system(size: 13, weight: .semibold))
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}
