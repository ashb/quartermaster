import Foundation
import LocalAuthentication
import Testing

@testable import QuartermasterApprovalUI
@testable import QuartermasterSecurity

@MainActor private final class UnlockAuthentication: ApprovalAuthentication {
    let context = LAContext()
    private(set) var requests = 0
    private(set) var invalidations = 0
    var pending: CheckedContinuation<MonotonicTimestamp, any Error>?

    func authenticate(reason: String) async throws -> MonotonicTimestamp {
        requests += 1
        return try await withCheckedThrowingContinuation { pending = $0 }
    }

    func invalidate() {
        invalidations += 1
        context.invalidate()
        complete(.failure(CancellationError()))
    }

    func complete(_ result: Result<MonotonicTimestamp, any Error>) {
        let reply = pending
        pending = nil
        reply?.resume(with: result)
    }
}

@MainActor private final class UnlockBackend: VaultUnlockBackend {
    let reviewCreated = MonotonicTimestamp.now
    private(set) var unwraps = 0
    private(set) var cancellations = 0

    func unlock(authenticated: MonotonicTimestamp, context: LAContext) async throws {
        #expect(context.interactionNotAllowed)
        unwraps += 1
    }

    func cancel() { cancellations += 1 }
}

@MainActor private func waitForUnlock(_ condition: () -> Bool) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while !condition(), clock.now < deadline { try await clock.sleep(for: .milliseconds(10)) }
    try #require(condition())
}

@Test(arguments: [true, false]) @MainActor
private func systemUnlockStartsWithoutAnEmbeddedViewAndCompletesOnce(_ approved: Bool) async throws {
    let authentication = UnlockAuthentication()
    let backend = UnlockBackend()
    let controller = ApprovalController(
        unlock: backend, reason: "Unlock vault", authentication: authentication, now: { .now })
    var activations = 0
    let dialog = VaultUnlockDialog(controller: controller, activate: { activations += 1 })
    var completions = 0
    dialog.onClose = { completions += 1 }
    defer { dialog.cancel() }

    dialog.show(centred: true)
    dialog.show(centred: false)
    try await waitForUnlock { authentication.pending != nil }
    #expect(authentication.requests == 1)
    #expect(activations == 2)
    authentication.complete(approved ? .success(.now) : .failure(CancellationError()))
    try await waitForUnlock { completions == 1 }
    #expect(dialog.approved == approved)
    #expect(backend.unwraps == (approved ? 1 : 0))
    #expect(backend.cancellations == (approved ? 0 : 1))
    #expect(authentication.invalidations == 1)
    dialog.cancel()
    #expect(completions == 1)
}

@Test(arguments: [true, false]) @MainActor
private func cancellingSystemUnlockInvalidatesAuthenticationBeforeCompletion(_ afterStarting: Bool) async throws {
    let authentication = UnlockAuthentication()
    let backend = UnlockBackend()
    let controller = ApprovalController(
        unlock: backend, reason: "Unlock vault", authentication: authentication, now: { .now })
    let dialog = VaultUnlockDialog(controller: controller, activate: {})
    var completions = 0
    dialog.onClose = { completions += 1 }
    dialog.show(centred: true)
    if afterStarting { try await waitForUnlock { authentication.pending != nil } }

    dialog.cancel()
    #expect(completions == 1)
    #expect(!dialog.approved)
    #expect(authentication.invalidations == 1)
    #expect(backend.cancellations == 1)
    #expect(backend.unwraps == 0)
    await Task.yield()
    #expect(completions == 1)
    #expect(authentication.requests == (afterStarting ? 1 : 0))
}
