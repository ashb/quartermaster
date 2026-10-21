import Foundation
import LocalAuthentication
import Testing
@testable import QuartermasterSecurity

@MainActor private final class AuthenticationFixture: ApprovalAuthentication {
    let context = LAContext()
    let timestamp: MonotonicTimestamp
    var failure = false
    var requests = 0
    var invalidations = 0

    init(timestamp: MonotonicTimestamp) { self.timestamp = timestamp }

    func authenticate(reason: String) async throws -> MonotonicTimestamp {
        requests += 1
        if failure { throw CancellationError() }
        return timestamp
    }

    func invalidate() { invalidations += 1 }
}

@MainActor private final class ApprovalBackendFixture: ApprovalBackend {
    var challenges = 0
    var signatures: [Data] = []
    var cancellations = 0
    var onChallenge: (() -> Void)?
    var context: LAContext?

    func challenge(authenticated: MonotonicTimestamp, context: LAContext) async throws -> Data {
        challenges += 1
        self.context = context
        onChallenge?()
        return Data([42])
    }

    func submit(_ signature: Data) async throws { signatures.append(signature) }
    func cancel() { cancellations += 1 }
}

@Test @MainActor func approvalControllerSignsAndSubmitsOnlyTheBackendChallenge() async throws {
    let storage = MemoryKeyStorage()
    let keys = ApprovalKeyStore(storage: storage)
    _ = try keys.loadOrCreate()
    let now = MonotonicTimestamp.now
    let authentication = AuthenticationFixture(timestamp: now)
    let backend = ApprovalBackendFixture()
    let controller = ApprovalController(backend: backend, reason: "Approve request", authentication: authentication,
                                        keys: keys, now: { now })

    await controller.approve()
    await controller.approve()

    #expect(controller.phase == .approved)
    #expect(authentication.requests == 1)
    #expect(authentication.invalidations == 1)
    #expect(authentication.context.interactionNotAllowed)
    #expect(backend.context === authentication.context)
    #expect(storage.signatures == 1)
    #expect(storage.messages == [Data([42])])
    #expect(backend.signatures == [Data([1])])
    #expect(backend.cancellations == 0)
}

@Test @MainActor func approvalControllerCannotSignAfterCancellationDuringBackendWork() async throws {
    let storage = MemoryKeyStorage()
    let keys = ApprovalKeyStore(storage: storage)
    _ = try keys.loadOrCreate()
    let now = MonotonicTimestamp.now
    let authentication = AuthenticationFixture(timestamp: now)
    let backend = ApprovalBackendFixture()
    let controller = ApprovalController(backend: backend, reason: "Approve request", authentication: authentication,
                                        keys: keys, now: { now })
    backend.onChallenge = { controller.cancel() }

    await controller.approve()
    controller.cancel()

    #expect(controller.phase == .stopped)
    #expect(storage.signatures == 0)
    #expect(backend.signatures.isEmpty)
    #expect(backend.cancellations == 1)
    #expect(authentication.invalidations == 1)
}

@Test @MainActor func approvalControllerRejectsFailedAuthenticationWithoutSigning() async throws {
    let storage = MemoryKeyStorage()
    let keys = ApprovalKeyStore(storage: storage)
    _ = try keys.loadOrCreate()
    let now = MonotonicTimestamp.now
    let authentication = AuthenticationFixture(timestamp: now)
    authentication.failure = true
    let backend = ApprovalBackendFixture()
    let controller = ApprovalController(backend: backend, reason: "Approve request", authentication: authentication,
                                        keys: keys, now: { now })

    await controller.approve()

    #expect(controller.phase == .stopped)
    #expect(backend.challenges == 0)
    #expect(storage.signatures == 0)
    #expect(backend.signatures.isEmpty)
    #expect(backend.cancellations == 1)
}

@Test @MainActor func approvalControllerCannotCreateAnUnenrolledKey() async {
    let storage = MemoryKeyStorage()
    let now = MonotonicTimestamp.now
    let authentication = AuthenticationFixture(timestamp: now)
    let backend = ApprovalBackendFixture()
    let controller = ApprovalController(backend: backend, reason: "Approve request", authentication: authentication,
                                        keys: ApprovalKeyStore(storage: storage), now: { now })

    await controller.approve()

    #expect(controller.phase == .stopped)
    #expect(storage.creations == 0)
    #expect(authentication.requests == 0)
    #expect(backend.signatures.isEmpty)
}

@Test @MainActor func approvalControllerRejectsAnAuthenticationEventBeforeItsRequest() async throws {
    let storage = MemoryKeyStorage()
    let keys = ApprovalKeyStore(storage: storage)
    _ = try keys.loadOrCreate()
    let authenticated = MonotonicTimestamp.now
    let requested = try authenticated.advanced(by: .seconds(1))
    let authentication = AuthenticationFixture(timestamp: authenticated)
    let backend = ApprovalBackendFixture()
    let controller = ApprovalController(backend: backend, reason: "Approve request", authentication: authentication,
                                        keys: keys, now: { requested })

    await controller.approve()

    #expect(controller.phase == .stopped)
    #expect(backend.challenges == 0)
    #expect(storage.signatures == 0)
}
