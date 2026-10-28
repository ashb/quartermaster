import Combine
import Foundation
import LocalAuthentication

@MainActor public protocol ApprovalBackend: AnyObject {
    var reviewCreated: MonotonicTimestamp { get }
    func challenge(authenticated: MonotonicTimestamp, context: LAContext) async throws -> Data
    func submit(_ signature: Data) async throws
    func cancel()
}

@MainActor public protocol VaultUnlockBackend: AnyObject {
    var reviewCreated: MonotonicTimestamp { get }
    func unlock(authenticated: MonotonicTimestamp, context: LAContext) async throws
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
    @MainActor private enum Operation {
        case signed(any ApprovalBackend, ApprovalKeyStore)
        case unlock(any VaultUnlockBackend)

        var created: MonotonicTimestamp {
            switch self {
            case .signed(let backend, _): backend.reviewCreated
            case .unlock(let backend): backend.reviewCreated
            }
        }

        func prepare() throws -> PreparedOperation {
            switch self {
            case .signed(let backend, let keys):
                guard let key = try keys.existingPublicKey() else { throw ApprovalKeyError.missingEnrolledKey }
                return .signed(backend, keys, key)
            case .unlock(let backend): return .unlock(backend)
            }
        }

        func cancel() {
            switch self {
            case .signed(let backend, _): backend.cancel()
            case .unlock(let backend): backend.cancel()
            }
        }
    }

    @MainActor private enum PreparedOperation {
        case signed(any ApprovalBackend, ApprovalKeyStore, Data)
        case unlock(any VaultUnlockBackend)

        func perform(authenticated: MonotonicTimestamp, context: LAContext, validate: () throws -> Void) async throws {
            switch self {
            case .signed(let backend, let keys, let publicKey):
                let message = try await backend.challenge(authenticated: authenticated, context: context)
                try validate()
                let signature = try keys.sign(message, expectedPublicKey: publicKey, context: context)
                try validate()
                try await backend.submit(signature)
            case .unlock(let backend):
                try await backend.unlock(authenticated: authenticated, context: context)
                try validate()
            }
        }
    }
    public enum Phase: Equatable { case review, authenticating, approved, stopped }
    enum Failure: Error { case invalidAuthentication, reviewExpired }
    @Published public private(set) var phase: Phase = .review
    @Published public private(set) var detail = ""
    public var context: LAContext { authentication.context }
    private let operation: Operation
    private let reason: String
    private let authentication: any ApprovalAuthentication
    private let now: () -> MonotonicTimestamp
    private var timeout: Task<Void, Never>?

    public convenience init(backend: any ApprovalBackend, reason: String, keys: ApprovalKeyStore = ApprovalKeyStore()) {
        self.init(
            backend: backend, reason: reason, authentication: TouchIDAuthentication(),
            keys: keys, now: { .now })
    }

    convenience init(
        backend: any ApprovalBackend, reason: String, authentication: any ApprovalAuthentication,
        keys: ApprovalKeyStore, now: @escaping () -> MonotonicTimestamp
    ) {
        self.init(operation: .signed(backend, keys), reason: reason, authentication: authentication, now: now)
    }

    public convenience init(unlock: any VaultUnlockBackend, reason: String) {
        self.init(unlock: unlock, reason: reason, authentication: TouchIDAuthentication(), now: { .now })
    }

    convenience init(
        unlock: any VaultUnlockBackend, reason: String, authentication: any ApprovalAuthentication,
        now: @escaping () -> MonotonicTimestamp
    ) {
        self.init(operation: .unlock(unlock), reason: reason, authentication: authentication, now: now)
    }

    private init(
        operation: Operation, reason: String, authentication: any ApprovalAuthentication,
        now: @escaping () -> MonotonicTimestamp
    ) {
        self.operation = operation
        self.reason = reason
        self.authentication = authentication
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
            try checkReview(at: now())
            let prepared = try operation.prepare()
            let requested = now()
            try checkReview(at: requested)
            let authenticated = try await authentication.authenticate(reason: reason)
            guard phase == .authenticating else { return }
            try checkTiming(requested: requested, authenticated: authenticated)
            context.interactionNotAllowed = true
            try await prepared.perform(authenticated: authenticated, context: context) {
                guard phase == .authenticating else { throw CancellationError() }
                try checkTiming(requested: requested, authenticated: authenticated)
            }
            guard phase == .authenticating else { return }
            finish(.approved, detail: "Approval received.")
        } catch Failure.reviewExpired {
            finish(.stopped, detail: "This review has expired. Close it and review the request again.")
        } catch {
            finish(.stopped, detail: "Approval failed. Request denied.")
        }
    }

    public func cancel() { finish(.stopped, detail: "Request cancelled.") }

    private func finish(_ phase: Phase, detail: String) {
        guard self.phase != .approved, self.phase != .stopped else { return }
        timeout?.cancel()
        authentication.invalidate()
        if phase == .stopped { operation.cancel() }
        self.detail = detail
        self.phase = phase
    }

    private func checkTiming(requested: MonotonicTimestamp, authenticated: MonotonicTimestamp) throws {
        try checkReview(at: authenticated)
        guard !requested.isZero, authenticated >= requested,
            try authenticated.duration(since: requested) < .seconds(120),
            try now().duration(since: authenticated) < .seconds(30)
        else { throw Failure.invalidAuthentication }
    }

    private func checkReview(at timestamp: MonotonicTimestamp) throws {
        guard !operation.created.isZero,
            let age = try? timestamp.duration(since: operation.created), age < .seconds(120)
        else { throw Failure.reviewExpired }
    }
}
