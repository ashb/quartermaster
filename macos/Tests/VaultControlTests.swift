import Darwin
import Foundation
import LocalAuthentication
import QuartermasterApprovalUI
import QuartermasterSecurity
import Synchronization
import Testing

@testable import Quartermaster

private final class VaultClientFixture: BrokerClient, Sendable {
    private let lost = Mutex(false)
    let snapshot: SettingsSnapshot
    @MainActor private(set) var calls: [String] = []
    @MainActor private(set) var locked: Bool
    @MainActor private var refreshed = false
    @MainActor private var pending = false
    @MainActor private var lockOnSync: Bool
    @MainActor var rejectUnlock: BrokerControlError?
    @MainActor var relockAfterUnlock = false
    @MainActor var pausePreparation = false
    @MainActor var preparation: CheckedContinuation<Void, Never>?

    @MainActor init(locked: Bool, lockOnSync: Bool = false) throws {
        self.locked = locked
        self.lockOnSync = lockOnSync
        let provider: [String: Any] = [
            "slot": String(repeating: "a", count: 32), "scope": String(repeating: "b", count: 32),
            "deviceKey": Array(repeating: 7, count: 32),
            "binding": [
                "server": "https://vault.example.invalid", "email": "dummy@example.invalid",
                "account_id": "11111111-1111-4111-8111-111111111111", "item_id": "22222222-2222-4222-8222-222222222222",
                "field": "LoginPassword", "role": "github-write",
            ],
        ]
        snapshot = try JSONDecoder().decode(
            SettingsSnapshot.self,
            from: JSONSerialization.data(withJSONObject: [
                "state": "configured", "revision": 1, "session": Data(repeating: 1, count: 16).base64EncodedString(),
                "settings": ["github": NSNull(), "mutations": "requireApproval"], "provider": provider,
                "migration": NSNull(),
            ]))
    }

    var disconnected: Bool { lost.withLock { $0 } }
    func cancel() { lost.withLock { $0 = true } }

    @MainActor func status(error: Bool = false) throws -> BrokerVaultStatus {
        let binding = try JSONSerialization.jsonObject(with: JSONEncoder().encode(#require(snapshot.provider).binding))
        let bytes = try JSONSerialization.data(withJSONObject: [
            "state": locked ? "locked" : "online_unlocked", "binding": binding,
            "lastSync": refreshed ? 1_700_000_060 : 1_700_000_000,
            "error": error ? "Lifecycle(Locked)" : NSNull(),
        ])
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try decoder.decode(BrokerVaultStatus.self, from: bytes)
    }

    @MainActor func call(_ command: BrokerCommand, context: LAContext?) async throws -> BrokerReply {
        guard !disconnected else { throw BrokerFailure.disconnected }
        switch command {
        case .hello: return .hello(profile: "development")
        case .settingsRegister, .settingsStatus: return .settingsStatus(snapshot)
        case .settingsCancel: return .canceled
        case .vaultStatus: return .vaultStatus(try status())
        case .prepareVaultUnlock(let revision):
            #expect(revision == 1)
            #expect(context == nil)
            calls.append("prepare")
            pending = true
            let bytes = try JSONSerialization.data(withJSONObject: [
                "id": Data(repeating: 2, count: 16).base64EncodedString(),
                "created": MonotonicTimestamp.now.serializedNanoseconds, "revision": 1,
                "session": Data(repeating: 1, count: 16).base64EncodedString(),
                "provider": try JSONSerialization.jsonObject(with: JSONEncoder().encode(#require(snapshot.provider))),
            ])
            let review = try JSONDecoder().decode(VaultUnlockReview.self, from: bytes)
            if pausePreparation { await withCheckedContinuation { preparation = $0 } }
            return .vaultUnlockReview(review)
        case .vaultUnlockPresence:
            #expect(pending)
            #expect(context?.interactionNotAllowed == true)
            calls.append("unlock")
            if let rejectUnlock { throw rejectUnlock }
            pending = false
            locked = false
            return .vaultStatus(try status())
        case .vaultUnlockCancel:
            calls.append("cancel")
            pending = false
            return .canceled
        case .vaultSync:
            #expect(context == nil)
            calls.append("sync")
            if lockOnSync || relockAfterUnlock {
                locked = true
                lockOnSync = false
            }
            if locked { return .vaultStatus(try status(error: true)) }
            refreshed = true
            return .vaultStatus(try status())
        case .vaultLock:
            calls.append("lock")
            locked = true
            return .vaultStatus(try status())
        default: throw BrokerFailure.invalidMessage
        }
    }
}

@MainActor private final class UnlockWindowFixture: VaultUnlockWindow {
    let backend: any VaultUnlockBackend
    var onClose: (() -> Void)?
    private(set) var approved = false
    private(set) var presented = false
    init(backend: any VaultUnlockBackend) { self.backend = backend }
    func show(centred: Bool) { presented = true }
    func cancel() {
        backend.cancel()
        presented = false
        onClose?()
    }
    func approve() async throws {
        let context = LAContext()
        context.interactionNotAllowed = true
        defer { context.invalidate() }
        try await backend.unlock(authenticated: .now, context: context)
        approved = true
        presented = false
        onClose?()
    }
}

@MainActor private func waitFor(_ condition: () -> Bool) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while !condition(), clock.now < deadline { try await clock.sleep(for: .milliseconds(10)) }
    try #require(condition())
}

@Test(arguments: [true, false]) @MainActor private func syncUnlocksOnceBeforeRefreshing(_ initiallyLocked: Bool)
    async throws
{
    let client = try VaultClientFixture(locked: initiallyLocked, lockOnSync: !initiallyLocked)
    defer { client.cancel() }
    var windows: [UnlockWindowFixture] = []
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1, 2, 3]) },
        acquirePresentation: { dup(STDERR_FILENO) },
        makeUnlockWindow: { _, backend, _ in
            let window = UnlockWindowFixture(backend: backend)
            windows.append(window)
            return window
        })
    application.reconnect()
    try await waitFor { application.status == "Connected" }
    application.vault(.vaultSync)
    try await waitFor { windows.count == 1 && windows[0].presented }
    #expect(client.calls == (initiallyLocked ? ["prepare"] : ["sync", "prepare"]))
    try await windows[0].approve()
    try await waitFor { application.vaultActivity == .synced }
    #expect(client.calls == (initiallyLocked ? ["prepare", "unlock", "sync"] : ["sync", "prepare", "unlock", "sync"]))
    #expect(application.vaultStatus?.lastSync == Date(timeIntervalSince1970: 1_700_000_060))
    #expect(!application.preferences.canReview)
}

@Test @MainActor private func unlockingAloneDoesNotSyncOrChangeSettings() async throws {
    let client = try VaultClientFixture(locked: true)
    defer { client.cancel() }
    var window: UnlockWindowFixture?
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1, 2, 3]) },
        acquirePresentation: { dup(STDERR_FILENO) },
        makeUnlockWindow: { _, backend, _ in
            let result = UnlockWindowFixture(backend: backend)
            window = result
            return result
        })
    application.reconnect()
    try await waitFor { application.status == "Connected" }
    application.unlockVault()
    try await waitFor { window?.presented == true }
    try await #require(window).approve()
    try await waitFor { application.vaultActivity == .unlocked }
    #expect(client.calls == ["prepare", "unlock"])
    #expect(application.vaultStatus?.lastSync == Date(timeIntervalSince1970: 1_700_000_000))
    #expect(application.preferences.snapshot?.revision == 1)
    #expect(!application.preferences.canReview)
}

@Test(arguments: ["cancel", "closeSettings", "lock"]) @MainActor
private func dismissingUnlockDoesNotStartSync(_ action: String) async throws {
    let client = try VaultClientFixture(locked: true)
    defer { client.cancel() }
    var window: UnlockWindowFixture?
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1, 2, 3]) },
        acquirePresentation: { dup(STDERR_FILENO) },
        makeUnlockWindow: { _, backend, _ in
            let result = UnlockWindowFixture(backend: backend)
            window = result
            return result
        })
    application.reconnect()
    try await waitFor { application.status == "Connected" }
    application.vault(.vaultSync)
    try await waitFor { window?.presented == true }
    switch action {
    case "closeSettings": application.settingsClosed()
    case "lock": application.vault(.vaultLock)
    default: window?.cancel()
    }
    try await waitFor { !application.vaultActivity.busy && client.calls.contains("cancel") }
    if action == "lock" { #expect(application.vaultActivity == .locked) }
    #expect(!client.calls.contains("sync"))
    #expect(client.locked)
    #expect(application.vaultStatus?.lastSync == Date(timeIntervalSince1970: 1_700_000_000))
}

@Test(arguments: ["expired", "relocked"]) @MainActor
private func aFailedOrSupersededUnlockDoesNotPromptAgain(_ failure: String) async throws {
    let client = try VaultClientFixture(locked: true)
    client.rejectUnlock = failure == "expired" ? .expired : nil
    client.relockAfterUnlock = failure == "relocked"
    defer { client.cancel() }
    var windows: [UnlockWindowFixture] = []
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1, 2, 3]) },
        acquirePresentation: { dup(STDERR_FILENO) },
        makeUnlockWindow: { _, backend, _ in
            let window = UnlockWindowFixture(backend: backend)
            windows.append(window)
            return window
        })
    application.reconnect()
    try await waitFor { application.status == "Connected" }
    application.vault(.vaultSync)
    try await waitFor { windows.first?.presented == true }
    if failure == "expired" {
        await #expect(throws: BrokerControlError.expired) { try await windows[0].approve() }
        windows[0].cancel()
    } else {
        try await windows[0].approve()
    }
    try await waitFor { !application.vaultActivity.busy }
    #expect(windows.count == 1)
    #expect(
        application.vaultActivity.message
            == (failure == "expired"
                ? "The unlock timed out. Try again." : "The vault is locked. Unlock it before syncing."))
    #expect(client.calls.filter { $0 == "sync" }.count == (failure == "expired" ? 0 : 1))
    #expect(application.vaultStatus?.lastSync == Date(timeIntervalSince1970: 1_700_000_000))
}

@Test @MainActor private func anOccupiedPresentationCancelsThePreparedUnlock() async throws {
    let client = try VaultClientFixture(locked: true)
    defer { client.cancel() }
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1, 2, 3]) },
        acquirePresentation: { throw DialogPresentationLease.Failure.alreadyPresented })
    application.reconnect()
    try await waitFor { application.status == "Connected" }
    application.unlockVault()
    try await waitFor { !application.vaultActivity.busy && client.calls.contains("cancel") }
    #expect(client.calls == ["prepare", "cancel"])
    #expect(client.locked)
    #expect(application.vaultActivity.message == "Another approval is open. Finish it and try again.")
}

@Test @MainActor private func closingSettingsDuringPreparationPreventsALateUnlockDialog() async throws {
    let client = try VaultClientFixture(locked: true)
    client.pausePreparation = true
    defer {
        client.cancel()
        client.preparation?.resume()
        client.preparation = nil
    }
    var windows: [UnlockWindowFixture] = []
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1, 2, 3]) },
        acquirePresentation: { dup(STDERR_FILENO) },
        makeUnlockWindow: { _, backend, _ in
            let window = UnlockWindowFixture(backend: backend)
            windows.append(window)
            return window
        })
    application.reconnect()
    try await waitFor { application.status == "Connected" }
    application.vault(.vaultSync)
    try await waitFor { client.preparation != nil }
    application.settingsClosed()
    client.preparation?.resume()
    client.preparation = nil
    try await waitFor { client.calls.contains("cancel") }
    #expect(windows.isEmpty)
    #expect(client.calls == ["prepare", "cancel"])
    #expect(!application.vaultActivity.busy)
    #expect(client.locked)
}
