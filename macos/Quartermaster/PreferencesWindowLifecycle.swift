import AppKit
import SwiftUI

struct PreferencesWindowLifecycle: NSViewRepresentable {
    let opened: @MainActor () -> Void
    let closed: @MainActor () -> Void

    func makeNSView(context: Context) -> PreferencesWindowObserver {
        PreferencesWindowObserver(opened: opened, closed: closed)
    }

    func updateNSView(_ view: PreferencesWindowObserver, context: Context) {}
}

final class PreferencesWindowObserver: NSView {
    private let opened: @MainActor () -> Void
    private let closed: @MainActor () -> Void

    init(opened: @escaping @MainActor () -> Void, closed: @escaping @MainActor () -> Void) {
        self.opened = opened
        self.closed = closed
        super.init(frame: .zero)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        NotificationCenter.default.removeObserver(self)
        guard let window else { return }
        NotificationCenter.default.addObserver(
            self, selector: #selector(becameKey(_:)), name: NSWindow.didBecomeKeyNotification, object: window)
        NotificationCenter.default.addObserver(
            self, selector: #selector(willClose(_:)), name: NSWindow.willCloseNotification, object: window)
        if window.isKeyWindow { opened() }
    }

    @objc private func becameKey(_ notification: Notification) { opened() }
    @objc private func willClose(_ notification: Notification) { closed() }
}
