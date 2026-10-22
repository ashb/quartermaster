import Combine
import Foundation
import LocalAuthentication

@MainActor public protocol ApprovalBackend: AnyObject {
    func challenge(authenticated: MonotonicTimestamp, context: LAContext) async throws -> Data
    func submit(_ signature: Data) async throws
    func cancel()
}

@MainActor protocol ApprovalAuthentication {
    var context: LAContext { get }
    func authenticate(reason: String) async throws -> MonotonicTimestamp
    func invalidate()
}

@MainActor private final class TouchIDAuthentication: ApprovalAuthentication {
    enum Failure: Error {
        case unavailable
        case rejected(Int)
    }
    let context: LAContext

    init() {
        context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedFallbackTitle = ""
    }

    func authenticate(reason: String) async throws -> MonotonicTimestamp {
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error),
            context.biometryType == .touchID
        else { throw Failure.unavailable }
        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) {
                success, error in
                let authenticated = MonotonicTimestamp.now
                if success {
                    continuation.resume(returning: authenticated)
                } else {
                    continuation.resume(throwing: Failure.rejected(error?._code ?? 0))
                }
            }
        }
    }

    func invalidate() { context.invalidate() }
}

@MainActor public final class ApprovalController: ObservableObject {
    public enum Phase: Equatable { case review, authenticating, approved, stopped }
    enum Failure: Error { case invalidAuthentication }
    @Published public private(set) var phase: Phase = .review
    @Published public private(set) var detail = ""
    public var context: LAContext { authentication.context }
    private let backend: any ApprovalBackend
    private let reason: String
    private let authentication: any ApprovalAuthentication
    private let keys: ApprovalKeyStore
    private let now: () -> MonotonicTimestamp
    private var timeout: Task<Void, Never>?

    public convenience init(backend: any ApprovalBackend, reason: String, keys: ApprovalKeyStore = ApprovalKeyStore()) {
        self.init(
            backend: backend, reason: reason, authentication: TouchIDAuthentication(),
            keys: keys, now: { .now })
    }

    init(
        backend: any ApprovalBackend, reason: String, authentication: any ApprovalAuthentication,
        keys: ApprovalKeyStore, now: @escaping () -> MonotonicTimestamp
    ) {
        self.backend = backend
        self.reason = reason
        self.authentication = authentication
        self.keys = keys
        self.now = now
    }

    deinit { timeout?.cancel() }

    public func approve() async {
        guard phase == .review else { return }
        phase = .authenticating
        timeout = Task { [weak self] in
            try? await Task.sleep(for: .seconds(120))
            guard !Task.isCancelled else { return }
            self?.finish(.stopped, detail: "Authentication timed out.")
        }
        do {
            guard let publicKey = try keys.existingPublicKey() else { throw ApprovalKeyError.missingEnrolledKey }
            let requested = now()
            let authenticated = try await authentication.authenticate(reason: reason)
            guard phase == .authenticating else { return }
            try checkTiming(requested: requested, authenticated: authenticated)
            context.interactionNotAllowed = true
            let message = try await backend.challenge(authenticated: authenticated, context: context)
            guard phase == .authenticating else { return }
            try checkTiming(requested: requested, authenticated: authenticated)
            let signature = try keys.sign(message, expectedPublicKey: publicKey, context: context)
            try checkTiming(requested: requested, authenticated: authenticated)
            try await backend.submit(signature)
            guard phase == .authenticating else { return }
            finish(.approved, detail: "Approval received.")
        } catch {
            finish(.stopped, detail: "Approval failed. Request denied.")
        }
    }

    public func cancel() { finish(.stopped, detail: "Request cancelled.") }

    private func finish(_ phase: Phase, detail: String) {
        guard self.phase != .approved, self.phase != .stopped else { return }
        timeout?.cancel()
        authentication.invalidate()
        if phase == .stopped { backend.cancel() }
        self.detail = detail
        self.phase = phase
    }

    private func checkTiming(requested: MonotonicTimestamp, authenticated: MonotonicTimestamp) throws {
        guard !requested.isZero, authenticated >= requested,
            try authenticated.duration(since: requested) < .seconds(120),
            try now().duration(since: authenticated) < .seconds(30)
        else { throw Failure.invalidAuthentication }
    }
}
