import AppKit
import Foundation
import LocalAuthentication
import QuartermasterSecurity
import Synchronization
import Testing

@testable import Quartermaster

private final class RecoveryClient: BrokerClient, Sendable {
    enum Suspension: CaseIterable, Sendable { case enrolment, poll }
    enum VaultOutcome: CaseIterable, Sendable { case locked, syncLocked, syncFailed, synced }
    private let lost = Mutex(false)
    private let snapshot: SettingsSnapshot
    private let vault: BrokerVaultStatus
    private let syncedVault: BrokerVaultStatus
    private let vaultOutcome: VaultOutcome?
    private let rejectsRegistration: Bool
    private let suspension: Suspension?
    private let pauseVault: Bool
    @MainActor private(set) var registrationKeys: [Data] = []
    @MainActor private(set) var enrolmentKeys: [Data] = []
    @MainActor private(set) var polls = 0
    @MainActor private(set) var vaultOperations = 0
    @MainActor private(set) var unexpectedCommands: [BrokerCommand] = []
    @MainActor private(set) var pending: CheckedContinuation<BrokerReply, any Error>?
    @MainActor private(set) var pendingVaults: [CheckedContinuation<BrokerReply, any Error>] = []

    init(
        rejectsRegistration: Bool = false, suspension: Suspension? = nil,
        vaultOutcome: VaultOutcome? = nil, pauseVault: Bool = false
    ) throws {
        self.rejectsRegistration = rejectsRegistration
        self.suspension = suspension
        self.vaultOutcome = vaultOutcome
        self.pauseVault = pauseVault
        snapshot = try JSONDecoder().decode(
            SettingsSnapshot.self,
            from: Data(
                #"{"state":"configured","revision":4,"session":"AQEBAQEBAQEBAQEBAQ==","settings":{"github":{"version":1,"mode":"github","repositories":[],"approveUnverifiedRequests":true},"mutations":"requireApproval"},"provider":{"slot":"dummy","binding":{"server":"https://vault.example.invalid","email":"dummy@example.invalid","account_id":"dummy","item_id":"dummy","field":"LoginPassword","role":"github-write"},"scope":"dummy","deviceKey":[1]},"migration":null}"#
                    .utf8))
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let binding = try JSONSerialization.jsonObject(with: JSONEncoder().encode(#require(snapshot.provider).binding))
        vault = try decoder.decode(
            BrokerVaultStatus.self,
            from: JSONSerialization.data(withJSONObject: [
                "state": "locked", "binding": binding, "lastSync": 1_700_000_000,
            ]))
        syncedVault = try decoder.decode(
            BrokerVaultStatus.self,
            from: JSONSerialization.data(withJSONObject: [
                "state": "online_unlocked", "binding": binding, "lastSync": 1_700_000_060,
            ]))
    }

    var disconnected: Bool { lost.withLock { $0 } }
    func cancel() { lost.withLock { $0 = true } }

    @MainActor func call(_ command: BrokerCommand, context: LAContext?) async throws -> BrokerReply {
        guard !disconnected else { throw BrokerFailure.disconnected }
        #expect(context == nil)
        switch command {
        case .hello: return .hello(profile: "development")
        case .settingsRegister(let key):
            registrationKeys.append(key)
            if rejectsRegistration { throw BrokerControlError.denied }
            return .settingsStatus(snapshot)
        case .settingsStatus: return .settingsStatus(snapshot)
        case .vaultStatus:
            return .vaultStatus(vaultOutcome == .synced && vaultOperations > 0 ? syncedVault : vault)
        case .vaultLock, .vaultSync:
            vaultOperations += 1
            if pauseVault { return try await withCheckedThrowingContinuation { pendingVaults.append($0) } }
            switch vaultOutcome {
            case .locked:
                return .vaultStatus(
                    try JSONDecoder().decode(BrokerVaultStatus.self, from: Data(#"{"state":"locked"}"#.utf8)))
            case .syncFailed:
                return .vaultStatus(
                    try JSONDecoder().decode(
                        BrokerVaultStatus.self,
                        from: Data(#"{"state":"server_unavailable","error":"Provider(ServerUnavailable)"}"#.utf8)))
            case .syncLocked:
                return .vaultStatus(
                    try JSONDecoder().decode(
                        BrokerVaultStatus.self, from: Data(#"{"state":"locked","error":"Lifecycle(Locked)"}"#.utf8)))
            case .synced: return .vaultStatus(syncedVault)
            case nil: throw BrokerFailure.invalidMessage
            }
        case .enroll(let key):
            enrolmentKeys.append(key)
            if suspension == .enrolment { return try await withCheckedThrowingContinuation { pending = $0 } }
            return .enrolled
        case .next:
            polls += 1
            if suspension == .poll { return try await withCheckedThrowingContinuation { pending = $0 } }
            return .idle
        default:
            unexpectedCommands.append(command)
            throw BrokerFailure.invalidMessage
        }
    }

    @MainActor func complete(_ result: Result<BrokerReply, any Error>) {
        let reply = pending
        pending = nil
        reply?.resume(with: result)
    }

    @MainActor func completeVaults(_ result: Result<BrokerReply, any Error>) {
        let replies = pendingVaults
        pendingVaults = []
        for reply in replies { reply.resume(with: result) }
    }
}

@MainActor private func activate(_ application: BrokerApplication) {
    (application as NSApplicationDelegate).applicationDidBecomeActive?(
        Notification(name: NSApplication.didBecomeActiveNotification))
}

@MainActor private func eventually(_ condition: () -> Bool) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while !condition(), clock.now < deadline { try await clock.sleep(for: .milliseconds(10)) }
    try #require(condition())
}

@Test(arguments: RecoveryClient.Suspension.allCases, [true, false]) @MainActor
private func cancelledControlCallsRejectLateReplies(_ suspension: RecoveryClient.Suspension, _ successful: Bool)
    async throws
{
    let client = try RecoveryClient(suspension: suspension)
    let command: BrokerCommand = suspension == .enrolment ? .enroll(publicKey: Data([1, 2, 3])) : .next
    let call = Task { try await client.call(command) }
    defer {
        call.cancel()
        client.complete(.failure(CancellationError()))
    }
    try await eventually { client.pending != nil }
    call.cancel()
    let reply: BrokerReply = suspension == .enrolment ? .enrolled : .idle
    client.complete(successful ? .success(reply) : .failure(BrokerControlError.denied))
    await #expect(throws: CancellationError.self) { try await call.value }
}

@Test(arguments: [true, false]) @MainActor
func activationReRegistersAfterThePreviousTransportWasInvalidated(_ afterPollingStops: Bool) async throws {
    let first = try RecoveryClient()
    let second = try RecoveryClient()
    defer {
        first.cancel()
        second.cancel()
    }
    let key = Data([1, 2, 3])
    var opens = 0
    let application = BrokerApplication(
        setActivationPolicy: { _ in },
        openConnection: {
            opens += 1
            return opens == 1 ? first : second
        },
        loadApprovalKey: { key })

    activate(application)
    try await eventually { first.polls > 0 }
    #expect(first.registrationKeys == [key])
    #expect(first.enrolmentKeys == [key])
    first.cancel()
    if afterPollingStops { try await eventually { application.status.hasPrefix("Backend unavailable:") } }

    activate(application)
    try await eventually { second.polls > 0 }
    #expect(opens == 2)
    #expect(second.registrationKeys == [key])
    #expect(second.enrolmentKeys == [key])
    #expect(first.unexpectedCommands.isEmpty && second.unexpectedCommands.isEmpty)

    let approval = InertApprovalWindow()
    application.present(approval)
    activate(application)
    #expect(opens == 2)
    #expect(!second.disconnected)
    #expect(approval.isPresented && !approval.cancelled)
    approval.close()
}

@Test @MainActor func failedRegistrationCannotResumeApprovalPolling() async throws {
    let rejected = try RecoveryClient(rejectsRegistration: true)
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { rejected }, loadApprovalKey: { Data([1, 2, 3]) })
    activate(application)
    try await eventually { application.status.hasPrefix("Backend unavailable:") }
    #expect(rejected.disconnected)
    #expect(rejected.registrationKeys.count == 1)
    #expect(rejected.enrolmentKeys.isEmpty)
    #expect(rejected.polls == 0)
}

@Test @MainActor func repeatedActivationKeepsOnePendingConnectionAttempt() async throws {
    let client = try RecoveryClient()
    var openings: [CheckedContinuation<any BrokerClient, Never>] = []
    defer {
        client.cancel()
        for opening in openings { opening.resume(returning: client) }
    }
    let application = BrokerApplication(
        setActivationPolicy: { _ in },
        openConnection: { await withCheckedContinuation { openings.append($0) } },
        loadApprovalKey: { Data([1, 2, 3]) })
    activate(application)
    try await eventually { !openings.isEmpty }
    activate(application)
    await Task.yield()
    #expect(openings.count == 1)
    let pending = openings
    openings.removeAll()
    for opening in pending { opening.resume(returning: client) }
    try await eventually { client.polls > 0 }
    #expect(client.registrationKeys.count == 1)
    #expect(client.enrolmentKeys.count == 1)
}

@Test(arguments: RecoveryClient.VaultOutcome.allCases) @MainActor
private func vaultActionsKeepTheLastSuccessfulSyncTime(_ outcome: RecoveryClient.VaultOutcome) async throws {
    let client = try RecoveryClient(vaultOutcome: outcome)
    defer { client.cancel() }
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1, 2, 3]) })
    activate(application)
    try await eventually { client.polls > 0 }
    #expect(application.vaultStatus?.lastSync == Date(timeIntervalSince1970: 1_700_000_000))

    application.vault(outcome == .locked ? .vaultLock : .vaultSync)
    try await eventually { client.vaultOperations == 1 && application.status.hasPrefix("Vault:") }

    let expectedStatus =
        switch outcome {
        case .locked, .syncLocked: "Vault: locked"
        case .syncFailed: "Vault: server_unavailable"
        case .synced: "Vault: online_unlocked"
        }
    #expect(application.status == expectedStatus)
    let expectedFeedback =
        switch outcome {
        case .locked: "Vault locked."
        case .synced: "Vault synced."
        case .syncLocked: "The vault is locked. Unlock it before syncing."
        case .syncFailed: "Could not contact Vaultwarden. Try again when it is available."
        }
    #expect(application.vaultActivity.message == expectedFeedback)
    #expect(!application.vaultActivity.busy)
    #expect(application.vaultStatus?.binding == application.preferences.snapshot?.provider?.binding)
    #expect(
        application.vaultStatus?.lastSync
            == Date(timeIntervalSince1970: outcome == .synced ? 1_700_000_060 : 1_700_000_000))
    #expect(!application.preferences.canReview)
}

@Test @MainActor private func syncShowsProgressAndCannotStartTwice() async throws {
    let client = try RecoveryClient(vaultOutcome: .synced, pauseVault: true)
    defer {
        client.cancel()
        client.completeVaults(.failure(CancellationError()))
    }
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1, 2, 3]) })
    activate(application)
    try await eventually { client.polls > 0 }

    application.vault(.vaultSync)
    #expect(application.status == "Syncing vault…")
    #expect(application.vaultActivity.busy)
    try await eventually { !client.pendingVaults.isEmpty }
    application.vault(.vaultSync)
    await Task.yield()
    #expect(client.vaultOperations == 1)
}

@Test @MainActor private func syncTransportFailureStopsProgressAndKeepsThePreviousSyncTime() async throws {
    let client = try RecoveryClient(vaultOutcome: .synced, pauseVault: true)
    defer {
        client.cancel()
        client.completeVaults(.failure(CancellationError()))
    }
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1, 2, 3]) })
    activate(application)
    try await eventually { client.polls > 0 }
    application.vault(.vaultSync)
    try await eventually { !client.pendingVaults.isEmpty }
    client.completeVaults(.failure(BrokerFailure.timeout))
    try await eventually { !application.vaultActivity.busy }
    #expect(application.vaultActivity.message == "Could not complete the vault operation. Reconnect and try again.")
    #expect(application.vaultStatus?.lastSync == Date(timeIntervalSince1970: 1_700_000_000))
    #expect(!application.preferences.canReview)
}

@Test @MainActor private func lockingBeforeSyncStartsPreventsTheCancelledSyncFromBeingSent() async throws {
    let client = try RecoveryClient(vaultOutcome: .locked)
    defer { client.cancel() }
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1, 2, 3]) })
    activate(application)
    try await eventually { client.polls > 0 }
    application.vault(.vaultSync)
    application.vault(.vaultLock)
    try await eventually { application.vaultActivity == .locked }
    #expect(client.vaultOperations == 1)
    #expect(application.vaultStatus?.lastSync == Date(timeIntervalSince1970: 1_700_000_000))
}
