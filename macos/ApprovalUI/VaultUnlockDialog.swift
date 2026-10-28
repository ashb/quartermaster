import AppKit
import QuartermasterSecurity

@MainActor public protocol VaultUnlockWindow: ApprovalWindow {
    var approved: Bool { get }
}

@MainActor public final class VaultUnlockDialog: VaultUnlockWindow {
    public let controller: ApprovalController
    public var onClose: (() -> Void)?
    public var approved: Bool { controller.phase == .approved }
    private let activate: () -> Void
    private var task: Task<Void, Never>?

    public convenience init(review: VaultUnlockReview, backend: any VaultUnlockBackend, forSync: Bool) {
        let vault = review.provider.binding.email
        let reason = forSync ? "unlock your vault (\(vault)) to sync with Vaultwarden" : "unlock your vault (\(vault))"
        self.init(
            controller: ApprovalController(unlock: backend, reason: reason),
            activate: { NSApplication.shared.activate(ignoringOtherApps: true) })
    }

    init(controller: ApprovalController, activate: @escaping () -> Void) {
        self.controller = controller
        self.activate = activate
    }

    public func show(centred: Bool) {
        activate()
        guard task == nil else { return }
        task = Task { [weak self] in
            guard let self, !Task.isCancelled else { return }
            await controller.approve()
            guard !Task.isCancelled else { return }
            finish()
        }
    }

    public func cancel() {
        task?.cancel()
        controller.cancel()
        finish()
    }

    private func finish() {
        let completion = onClose
        onClose = nil
        completion?()
    }
}
