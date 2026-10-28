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
    var onAuthenticate: (() throws -> Void)?

    init(timestamp: MonotonicTimestamp) { self.timestamp = timestamp }

    func authenticate(reason: String) async throws -> MonotonicTimestamp {
        requests += 1
        if failure { throw CancellationError() }
        try onAuthenticate?()
        return timestamp
    }

    func invalidate() { invalidations += 1 }
}

@MainActor private final class ApprovalBackendFixture: ApprovalBackend {
    let reviewCreated: MonotonicTimestamp
    var challenges = 0
    var signatures: [Data] = []
    var cancellations = 0
    var onChallenge: (() -> Void)?
    var context: LAContext?

    init(created: MonotonicTimestamp) { reviewCreated = created }

    func challenge(authenticated: MonotonicTimestamp, context: LAContext) async throws -> Data {
        challenges += 1
        self.context = context
        onChallenge?()
        return Data([42])
    }

    func submit(_ signature: Data) async throws { signatures.append(signature) }
    func cancel() { cancellations += 1 }
}

@MainActor private final class UnlockBackendFixture: VaultUnlockBackend {
    let reviewCreated: MonotonicTimestamp
    var unlocks = 0
    var cancellations = 0
    var onUnlock: (() -> Void)?
    var context: LAContext?

    init(created: MonotonicTimestamp) { reviewCreated = created }

    func unlock(authenticated: MonotonicTimestamp, context: LAContext) async throws {
        unlocks += 1
        self.context = context
        onUnlock?()
    }
    func cancel() { cancellations += 1 }
}

@Test @MainActor func vaultUnlockUsesOneAuthenticationWithoutAnApprovalKey() async {
    let now = MonotonicTimestamp.now
    let authentication = AuthenticationFixture(timestamp: now)
    let backend = UnlockBackendFixture(created: now)
    let controller = ApprovalController(
        unlock: backend, reason: "Unlock vault", authentication: authentication, now: { now })
    await controller.approve()
    await controller.approve()
    #expect(controller.phase == .approved)
    #expect(authentication.requests == 1)
    #expect(authentication.invalidations == 1)
    #expect(backend.unlocks == 1)
    #expect(backend.context === authentication.context)
    #expect(authentication.context.interactionNotAllowed)
    #expect(backend.cancellations == 0)
}

@Test @MainActor func cancelingDuringVaultUnlockCannotCompleteTheApproval() async {
    let now = MonotonicTimestamp.now
    let authentication = AuthenticationFixture(timestamp: now)
    let backend = UnlockBackendFixture(created: now)
    let controller = ApprovalController(
        unlock: backend, reason: "Unlock vault", authentication: authentication, now: { now })
    backend.onUnlock = { controller.cancel() }
    await controller.approve()
    #expect(controller.phase == .stopped)
    #expect(backend.cancellations == 1)
    #expect(authentication.invalidations == 1)
}

@Test(arguments: [119, 120]) @MainActor func vaultUnlockKeepsTheOriginalAuthenticationWindow(_ reviewAge: Int)
    async throws
{
    let created = MonotonicTimestamp.now
    let authenticated = try created.advanced(by: .seconds(reviewAge))
    let completed = try authenticated.advanced(by: .seconds(29))
    var clock = authenticated
    let authentication = AuthenticationFixture(timestamp: authenticated)
    let backend = UnlockBackendFixture(created: created)
    backend.onUnlock = { clock = completed }
    let controller = ApprovalController(
        unlock: backend, reason: "Unlock vault", authentication: authentication, now: { clock })
    await controller.approve()
    #expect(controller.phase == (reviewAge == 119 ? .approved : .stopped))
    #expect(authentication.requests == (reviewAge == 119 ? 1 : 0))
    #expect(backend.unlocks == (reviewAge == 119 ? 1 : 0))
}

@Test @MainActor func vaultUnlockDoesNotAcceptACompletionAfterAuthenticationExpires() async throws {
    let authenticated = MonotonicTimestamp.now
    let expired = try authenticated.advanced(by: .seconds(30))
    var clock = authenticated
    let authentication = AuthenticationFixture(timestamp: authenticated)
    let backend = UnlockBackendFixture(created: authenticated)
    backend.onUnlock = { clock = expired }
    let controller = ApprovalController(
        unlock: backend, reason: "Unlock vault", authentication: authentication, now: { clock })
    await controller.approve()
    #expect(controller.phase == .stopped)
    #expect(backend.cancellations == 1)
    #expect(authentication.invalidations == 1)
}

@Test @MainActor func approvalControllerSignsAndSubmitsOnlyTheBackendChallenge() async throws {
    let storage = MemoryKeyStorage()
    let keys = ApprovalKeyStore(storage: storage)
    _ = try keys.loadOrCreate()
    let now = MonotonicTimestamp.now
    let authentication = AuthenticationFixture(timestamp: now)
    let backend = ApprovalBackendFixture(created: now)
    let controller = ApprovalController(
        backend: backend, reason: "Approve request", authentication: authentication,
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
    let backend = ApprovalBackendFixture(created: now)
    let controller = ApprovalController(
        backend: backend, reason: "Approve request", authentication: authentication,
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
    let backend = ApprovalBackendFixture(created: now)
    let controller = ApprovalController(
        backend: backend, reason: "Approve request", authentication: authentication,
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
    let backend = ApprovalBackendFixture(created: now)
    let controller = ApprovalController(
        backend: backend, reason: "Approve request", authentication: authentication,
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
    let backend = ApprovalBackendFixture(created: authenticated)
    let controller = ApprovalController(
        backend: backend, reason: "Approve request", authentication: authentication,
        keys: keys, now: { requested })

    await controller.approve()

    #expect(controller.phase == .stopped)
    #expect(backend.challenges == 0)
    #expect(storage.signatures == 0)
}

@Test(arguments: [120, 121]) @MainActor
func anExpiredReviewDoesNotRequestAFingerprint(_ elapsed: Int) async throws {
    let storage = MemoryKeyStorage()
    let keys = ApprovalKeyStore(storage: storage)
    _ = try keys.loadOrCreate()
    let created = MonotonicTimestamp.now
    let requested = try created.advanced(by: .seconds(elapsed))
    let authentication = AuthenticationFixture(timestamp: requested)
    let backend = ApprovalBackendFixture(created: created)
    let controller = ApprovalController(
        backend: backend, reason: "Approve request", authentication: authentication,
        keys: keys, now: { requested })

    await controller.approve()

    #expect(controller.phase == .stopped)
    #expect(controller.detail.contains("expired"))
    #expect(authentication.requests == 0)
    #expect(authentication.invalidations == 1)
    #expect(backend.challenges == 0)
    #expect(storage.signatures == 0)
    #expect(backend.signatures.isEmpty)
    #expect(backend.cancellations == 1)
}

@Test(arguments: [119, 120]) @MainActor
func authenticationMustFinishBeforeTheOriginalReviewExpires(_ elapsed: Int) async throws {
    let storage = MemoryKeyStorage()
    let keys = ApprovalKeyStore(storage: storage)
    _ = try keys.loadOrCreate()
    let created = MonotonicTimestamp.now
    let requested = try created.advanced(by: .seconds(119))
    let authenticated = try created.advanced(by: .seconds(elapsed))
    let completed = try authenticated.advanced(by: .seconds(29))
    var current = requested
    let authentication = AuthenticationFixture(timestamp: authenticated)
    let backend = ApprovalBackendFixture(created: created)
    authentication.onAuthenticate = { current = authenticated }
    backend.onChallenge = { current = completed }
    let controller = ApprovalController(
        backend: backend, reason: "Approve request", authentication: authentication,
        keys: keys, now: { current })

    await controller.approve()

    #expect(authentication.requests == 1)
    #expect(controller.phase == (elapsed == 119 ? .approved : .stopped))
    #expect(storage.signatures == (elapsed == 119 ? 1 : 0))
    #expect(backend.challenges == (elapsed == 119 ? 1 : 0))
}

@Test @MainActor func aReviewExpiringDuringKeyLookupDoesNotRequestAFingerprint() async throws {
    let storage = MemoryKeyStorage()
    let keys = ApprovalKeyStore(storage: storage)
    _ = try keys.loadOrCreate()
    let created = MonotonicTimestamp.now
    let beforeLookup = try created.advanced(by: .seconds(119))
    let expired = try created.advanced(by: .seconds(120))
    var current = beforeLookup
    let authentication = AuthenticationFixture(timestamp: expired)
    let backend = ApprovalBackendFixture(created: created)
    let controller = ApprovalController(
        backend: backend, reason: "Approve request", authentication: authentication,
        keys: keys,
        now: {
            defer { current = expired }
            return current
        })

    await controller.approve()

    #expect(controller.phase == .stopped)
    #expect(authentication.requests == 0)
    #expect(backend.challenges == 0)
    #expect(storage.signatures == 0)
    #expect(backend.signatures.isEmpty)
}

@Test @MainActor func supersedingAReviewInvalidatesItsContextWithoutCancelingTheOperation() async {
    let now = MonotonicTimestamp.now
    let authentication = AuthenticationFixture(timestamp: now)
    let backend = UnlockBackendFixture(created: now)
    let controller = ApprovalController(unlock: backend, reason: "test", authentication: authentication, now: { now })
    #expect(controller.supersedeReview())
    #expect(!controller.supersedeReview())
    await controller.approve()
    #expect(authentication.invalidations == 1)
    #expect(authentication.requests == 0)
    #expect(backend.cancellations == 0)
    #expect(backend.unlocks == 0)
}

@Test(arguments: [false, true]) @MainActor
func changingScopeWhileWaitingForTouchIDRejectsTheOldAuthentication(_ fails: Bool) async throws {
    let storage = MemoryKeyStorage()
    let keys = ApprovalKeyStore(storage: storage)
    _ = try keys.loadOrCreate()
    let now = MonotonicTimestamp.now
    let authentication = AuthenticationFixture(timestamp: now)
    let backend = ApprovalBackendFixture(created: now)
    let controller = ApprovalController(
        backend: backend, reason: "Approve request", authentication: authentication, keys: keys, now: { now })
    authentication.onAuthenticate = {
        #expect(controller.supersedeReview())
        if fails { throw CancellationError() }
    }
    await controller.approve()

    #expect(controller.phase == .superseded)
    #expect(authentication.invalidations == 1)
    #expect(backend.challenges == 0)
    #expect(storage.signatures == 0)
    #expect(backend.signatures.isEmpty)
    #expect(backend.cancellations == 0)

    let replacementAuthentication = AuthenticationFixture(timestamp: now)
    let replacement = ApprovalController(
        backend: backend, reason: "Approve new scope", authentication: replacementAuthentication,
        keys: keys, now: { now })
    await replacement.approve()
    #expect(replacement.phase == .approved)
    #expect(replacementAuthentication.requests == 1)
    #expect(backend.signatures == [Data([1])])
    #expect(backend.cancellations == 0)
}

@Test @MainActor func completedAuthenticationPreventsChangingTheReviewedScope() async throws {
    let storage = MemoryKeyStorage()
    let keys = ApprovalKeyStore(storage: storage)
    _ = try keys.loadOrCreate()
    let now = MonotonicTimestamp.now
    let authentication = AuthenticationFixture(timestamp: now)
    let backend = ApprovalBackendFixture(created: now)
    let controller = ApprovalController(
        backend: backend, reason: "Approve request", authentication: authentication, keys: keys, now: { now })
    backend.onChallenge = { #expect(!controller.supersedeReview()) }
    await controller.approve()
    #expect(!controller.supersedeReview())
    #expect(controller.phase == .approved)
    #expect(backend.signatures == [Data([1])])
}
