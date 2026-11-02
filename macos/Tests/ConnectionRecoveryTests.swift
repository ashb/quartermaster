import AppKit
import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import QuartermasterApprovalUI
import QuartermasterSecurity
import SwiftUI
import Synchronization
import Testing

@testable import Quartermaster

private final class RecoveryClient: BrokerClient, Sendable {
    enum Suspension: CaseIterable, Sendable { case enrolment, poll }
    enum VaultOutcome: CaseIterable, Sendable { case locked, syncFailed, synced }
    private let lost = Mutex(false)
    let snapshot: SettingsSnapshot
    private let vault: BrokerVaultStatus
    private let syncedVault: BrokerVaultStatus
    private let vaultOutcome: VaultOutcome?
    private let rejectsRegistration: Bool
    private let suspension: Suspension?
    private let pauseVault: Bool
    private let build: BrokerBuildInfo?
    private let settingsReply: BrokerReply?
    @MainActor private(set) var registrationKeys: [Data] = []
    @MainActor private(set) var enrolmentKeys: [Data] = []
    @MainActor private(set) var polls = 0
    @MainActor private(set) var cancellations: [String] = []
    @MainActor private(set) var vaultOperations = 0
    @MainActor private var synchronized = false
    @MainActor private(set) var unexpectedCommands: [BrokerCommand] = []
    @MainActor private(set) var pending: CheckedContinuation<BrokerReply, any Error>?
    @MainActor private(set) var pendingVaults: [CheckedContinuation<BrokerReply, any Error>] = []

    init(
        rejectsRegistration: Bool = false, suspension: Suspension? = nil,
        vaultOutcome: VaultOutcome? = nil, pauseVault: Bool = false, build: BrokerBuildInfo? = nil,
        settingsReply: BrokerReply? = nil
    ) throws {
        self.rejectsRegistration = rejectsRegistration
        self.suspension = suspension
        self.vaultOutcome = vaultOutcome
        self.pauseVault = pauseVault
        self.build = build
        self.settingsReply = settingsReply
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
                "state": vaultOutcome == .syncFailed || vaultOutcome == .synced ? "online_unlocked" : "locked",
                "binding": binding, "lastSync": 1_700_000_000,
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
        case .hello: return .hello(profile: "development", build: build)
        case .settingsRegister(let key):
            registrationKeys.append(key)
            if rejectsRegistration { throw BrokerControlError.denied }
            return .settingsStatus(snapshot)
        case .settingsStatus: return settingsReply ?? .settingsStatus(snapshot)
        case .vaultStatus:
            return .vaultStatus(synchronized ? syncedVault : vault)
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
            case .synced:
                synchronized = true
                return .vaultStatus(syncedVault)
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
        case .revokeReadGrant, .revokeReadGrants: return .readGrantsRevoked
        case .readGrants: return .readGrants([])
        case .cancel(let id):
            cancellations.append(id)
            return .canceled
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

@MainActor private func eventually(sourceLocation: SourceLocation = #_sourceLocation, _ condition: () -> Bool)
    async throws
{
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while !condition(), clock.now < deadline { try await clock.sleep(for: .milliseconds(10)) }
    try #require(condition(), sourceLocation: sourceLocation)
}

@Test @MainActor func menuFollowsConnectionAndReconnectResults() async throws {
    let client = try RecoveryClient()
    defer { client.cancel() }
    var attempts = 0
    let application = BrokerApplication(
        setActivationPolicy: { _ in },
        openConnection: {
            attempts += 1
            if attempts == 1 { throw BrokerFailure.invalidCode }
            return client
        },
        loadApprovalKey: { Data([1, 2, 3]) })
    let host = NSHostingView(rootView: VStack { QuartermasterMenu(application: application) })
    let window = NSWindow(
        contentRect: NSRect(x: -10000, y: -10000, width: 500, height: 400), styleMask: [.borderless],
        backing: .buffered, defer: false)
    window.isReleasedWhenClosed = false
    defer { window.close() }
    window.contentView = host
    host.setFrameSize(NSSize(width: 500, height: 400))
    host.layoutSubtreeIfNeeded()
    window.orderFront(nil)
    func rendered() throws -> Data {
        host.layoutSubtreeIfNeeded()
        let bitmap = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: bitmap)
        return try #require(bitmap.representation(using: .png, properties: [:]))
    }
    let disconnected = try rendered()
    #expect(try rendered() == disconnected)
    application.reconnect()
    try await eventually { application.status.hasPrefix("Backend unavailable:") }
    try await eventually { (try? rendered()) != disconnected }
    let failed = try rendered()
    application.reconnect()
    try await eventually { client.polls > 0 }
    #expect(application.status == "Connected")
    try await eventually { (try? rendered()) != failed }
    #expect(attempts == 2)
}

@Test @MainActor func resticWithoutGitHubStillEnrollsAndPollsForApproval() async throws {
    let baseline = try RecoveryClient()
    var settings = BrokerSettings()
    settings.restic = ResticSettings(executable: "/bin/restic", itemId: "22222222-2222-4222-8222-222222222222")
    let snapshot = try JSONDecoder().decode(
        SettingsSnapshot.self,
        from: JSONSerialization.data(withJSONObject: [
            "state": "configured", "revision": 4, "session": Data(repeating: 1, count: 16).base64EncodedString(),
            "settings": JSONSerialization.jsonObject(with: JSONEncoder().encode(settings)),
            "provider": JSONSerialization.jsonObject(
                with: JSONEncoder().encode(try #require(baseline.snapshot.provider))),
        ]))
    let client = try RecoveryClient(settingsReply: .settingsStatus(snapshot))
    defer { client.cancel() }
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1, 2, 3]) })
    activate(application)
    try await eventually { client.polls > 0 }
    #expect(client.enrolmentKeys == [Data([1, 2, 3])])
    #expect(application.preferences.snapshot?.settings?.github == nil)
}

@Test @MainActor func handoffPresentationHoldsAndReleasesTheGlobalDialogLease() async throws {
    let client = try RecoveryClient(suspension: .poll)
    let window = InertApprovalWindow()
    let descriptor = open("/dev/null", O_RDONLY)
    #expect(descriptor >= 0)
    var acquisitions = 0
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1]) },
        acquirePresentation: {
            acquisitions += 1
            return descriptor
        },
        makeHandoffWindow: { request, _ in
            #expect(request.credentialName == "Backup password")
            return window
        })
    defer {
        window.close()
        client.cancel()
        client.complete(.failure(CancellationError()))
    }
    activate(application)
    try await eventually { client.pending != nil }
    client.complete(.success(.handoffReview(try handoffReview())))
    try await eventually { window.isPresented }
    #expect(acquisitions == 1)
    #expect(fcntl(descriptor, F_GETFD) >= 0)
    window.close()
    #expect(fcntl(descriptor, F_GETFD) == -1)
    #expect(client.cancellations.isEmpty)
}

@Test(arguments: [true, false]) @MainActor
private func handoffWaitsWithoutReplacingAnExistingDialog(_ otherProcess: Bool) async throws {
    let client = try RecoveryClient(suspension: .poll)
    let existing = InertApprovalWindow()
    let successor = InertApprovalWindow()
    var blocked = otherProcess
    var acquisitions = 0
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1]) },
        acquirePresentation: {
            acquisitions += 1
            if blocked { throw DialogPresentationLease.Failure.alreadyPresented }
            return open("/dev/null", O_RDONLY)
        },
        makeHandoffWindow: { _, _ in
            return successor
        })
    defer {
        existing.close()
        successor.close()
        client.cancel()
        client.complete(.failure(CancellationError()))
    }
    activate(application)
    try await eventually { client.pending != nil }
    if !otherProcess { application.present(existing) }
    client.complete(.success(.handoffReview(try handoffReview())))
    try await Task.sleep(for: .milliseconds(300))
    #expect(client.cancellations.isEmpty)
    #expect(!successor.isPresented)
    #expect(existing.isPresented == !otherProcess)
    blocked = false
    existing.close()
    try await eventually { successor.isPresented }
    #expect(client.cancellations.isEmpty)
    #expect(acquisitions > 0)
}

@Test(arguments: [true, false]) @MainActor
private func expiredReviewsDoNotDisconnectTheApprovalClient(_ handoff: Bool) async throws {
    let client = try RecoveryClient(suspension: .poll)
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1]) },
        acquirePresentation: {
            Issue.record("Expired reviews must not acquire presentation")
            throw DialogPresentationLease.Failure.alreadyPresented
        })
    defer {
        client.cancel()
        client.complete(.failure(CancellationError()))
    }
    activate(application)
    try await eventually { client.pending != nil }
    let created = try JSONDecoder().decode(MonotonicTimestamp.self, from: Data("1".utf8))
    let review = try handoffReview(created: created)
    client.complete(.success(handoff ? .handoffReview(review) : .review(review)))
    try await eventually { client.polls == 2 }
    #expect(client.cancellations == [review.id])
    #expect(application.connected)
    #expect(!client.disconnected)
}

@Test(arguments: [BrokerCommand.vaultLock, .revokeReadGrant(id: String(repeating: "a", count: 32)), .revokeReadGrants])
@MainActor private func invalidationDiscardsDeferredReviews(_ command: BrokerCommand) async throws {
    let client = try RecoveryClient(suspension: .poll, vaultOutcome: .locked)
    var acquisitions = 0
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1]) },
        acquirePresentation: {
            acquisitions += 1
            throw DialogPresentationLease.Failure.alreadyPresented
        })
    defer {
        client.cancel()
        client.complete(.failure(CancellationError()))
    }
    activate(application)
    try await eventually { client.pending != nil }
    client.complete(.success(.handoffReview(try handoffReview())))
    try await eventually { acquisitions > 0 }
    switch command {
    case .vaultLock: application.vault(command)
    case .revokeReadGrant(let id): application.revokeRead(id)
    default: application.revokeReads()
    }
    try await eventually { client.polls == 2 }
    #expect(application.connected)
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
    let build = try JSONDecoder().decode(
        BrokerBuildInfo.self,
        from: Data(#"{"revision":"a0b936c","builtAt":1793448000,"modified":true}"#.utf8))
    let first = try RecoveryClient(build: build)
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
    #expect(application.backendBuild == build)
    #expect(first.registrationKeys == [key])
    #expect(first.enrolmentKeys == [key])
    first.cancel()
    if afterPollingStops {
        try await eventually { application.status.hasPrefix("Backend unavailable:") }
        #expect(application.backendBuild == nil)
    }

    activate(application)
    try await eventually { second.polls > 0 }
    #expect(application.backendBuild == nil)
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

@Test @MainActor func interruptedConnectionRecoversWithoutActivation() async throws {
    let first = try RecoveryClient()
    let second = try RecoveryClient()
    var opens = 0
    let application = BrokerApplication(
        setActivationPolicy: { _ in },
        openConnection: {
            opens += 1
            return opens == 1 ? first : second
        },
        loadApprovalKey: { Data([1, 2, 3]) })
    defer { _ = application.applicationShouldTerminate(NSApplication.shared) }
    application.reconnect()
    try await eventually { first.polls > 0 }
    let approval = InertApprovalWindow()
    application.present(approval)
    first.cancel()
    try await eventually { second.polls > 0 }
    #expect(opens == 2)
    #expect(application.connectionFailure == nil)
    #expect(second.registrationKeys.count == 1)
    #expect(second.enrolmentKeys.count == 1)
    #expect(approval.cancelled)
    #expect(second.vaultOperations == 0)
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
    #expect(application.connectionFailure != nil)
}

@Test(arguments: [true, false]) @MainActor
func foregroundRetriesRegistrationAfterRecoveryWasRefused(_ reopen: Bool) async throws {
    let first = try RecoveryClient()
    let refused = try RecoveryClient(rejectsRegistration: true)
    let recovered = try RecoveryClient()
    let clients = [first, refused, recovered]
    var opens = 0
    let key = Data([1, 2, 3])
    let application = BrokerApplication(
        setActivationPolicy: { _ in },
        openConnection: {
            let client = clients[min(opens, clients.count - 1)]
            opens += 1
            return client
        },
        recoveryDelays: [.zero], loadApprovalKey: { key })
    defer { _ = application.applicationShouldTerminate(NSApplication.shared) }

    application.reconnect()
    try await eventually { first.polls > 0 }
    let approval = InertApprovalWindow()
    application.present(approval)
    first.cancel()
    try await eventually { application.connectionFailure != nil }
    #expect(opens == 2)
    #expect(approval.cancelled)
    #expect(refused.disconnected)
    #expect(refused.enrolmentKeys.isEmpty && refused.polls == 0)

    if reopen {
        _ = application.applicationShouldHandleReopen(NSApplication.shared, hasVisibleWindows: false)
    } else {
        activate(application)
    }
    try await eventually { recovered.polls > 0 }
    #expect(opens == 3)
    #expect(application.connected && application.connectionFailure == nil)
    #expect(recovered.registrationKeys == [key])
    #expect(recovered.enrolmentKeys == [key])
    #expect(recovered.vaultOperations == 0)
    #expect(approval.cancelled)
}

@Test(arguments: ["invalid", "unavailable", "unconfigured"]) @MainActor
func settingsInitializationMustSucceedBeforeHidingRecovery(_ state: String) async throws {
    let snapshot = try JSONDecoder().decode(
        SettingsSnapshot.self,
        from: JSONSerialization.data(withJSONObject: [
            "state": state, "revision": 0, "session": Data([1, 2, 3]).base64EncodedString(),
        ]))
    let client = try RecoveryClient(settingsReply: state == "invalid" ? .idle : .settingsStatus(snapshot))
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, recoveryDelays: [],
        loadApprovalKey: { Data([1, 2, 3]) })
    defer { _ = application.applicationShouldTerminate(NSApplication.shared) }
    application.reconnect()
    if state == "unconfigured" {
        try await eventually { application.connected }
        #expect(application.connectionFailure == nil)
        #expect(application.preferences.available)
    } else {
        try await eventually { application.connectionFailure != nil }
        #expect(!application.connected)
        #expect(!application.preferences.available)
        #expect(client.polls == 0)
    }
}

@Test @MainActor func recoveryStopsAfterItsBudgetAndManualRetryClearsTheFailure() async throws {
    let client = try RecoveryClient()
    var attempts = 0
    var available = false
    let application = BrokerApplication(
        setActivationPolicy: { _ in },
        openConnection: {
            attempts += 1
            if !available { throw BrokerFailure.timeout }
            return client
        },
        recoveryDelays: [.zero, .zero],
        loadApprovalKey: { Data([1, 2, 3]) })
    defer { _ = application.applicationShouldTerminate(NSApplication.shared) }
    application.reconnect()
    try await eventually { application.connectionFailure != nil }
    #expect(attempts == 3)
    #expect(!application.connected)
    #expect(application.connectionFailure?.contains("did not respond") == true)
    available = true
    application.reconnect()
    #expect(application.connectionFailure == nil)
    try await eventually { client.polls > 0 }
    #expect(attempts == 4)
    #expect(application.connected)
}

@Test(arguments: [BrokerFailure.invalidCode, .invalidMessage]) @MainActor
func identityAndProtocolFailuresDoNotRetry(_ failure: BrokerFailure) async throws {
    var attempts = 0
    let application = BrokerApplication(
        setActivationPolicy: { _ in },
        openConnection: {
            attempts += 1
            throw failure
        },
        recoveryDelays: [.zero, .zero])
    defer { _ = application.applicationShouldTerminate(NSApplication.shared) }
    application.reconnect()
    try await eventually { application.connectionFailure != nil }
    #expect(attempts == 1)
}

@Test @MainActor func aLateConnectionCannotReplaceTheSuccessfulRetry() async throws {
    let obsolete = try RecoveryClient()
    let current = try RecoveryClient()
    var pending: CheckedContinuation<any BrokerClient, Never>?
    var attempts = 0
    let application = BrokerApplication(
        setActivationPolicy: { _ in },
        openConnection: {
            attempts += 1
            if attempts == 1 { return await withCheckedContinuation { pending = $0 } }
            return current
        },
        loadApprovalKey: { Data([1, 2, 3]) })
    defer {
        _ = application.applicationShouldTerminate(NSApplication.shared)
        pending?.resume(returning: obsolete)
    }
    application.reconnect()
    try await eventually { pending != nil }
    application.reconnect()
    try await eventually { current.polls > 0 }
    pending?.resume(returning: obsolete)
    pending = nil
    try await eventually { obsolete.disconnected }
    #expect(obsolete.registrationKeys.isEmpty)
    #expect(!current.disconnected)
    #expect(application.connected)
    #expect(attempts == 2)
}

@Test @MainActor func quittingDuringRecoveryCancelsTheScheduledRetry() async throws {
    var attempts = 0
    let application = BrokerApplication(
        setActivationPolicy: { _ in },
        openConnection: {
            attempts += 1
            throw BrokerFailure.disconnected
        },
        recoveryDelays: [.seconds(1)])
    application.reconnect()
    try await eventually { application.status.hasPrefix("Backend unavailable:") }
    #expect(application.connectionFailure == nil)
    _ = application.applicationShouldTerminate(NSApplication.shared)
    try await Task.sleep(for: .milliseconds(1100))
    #expect(attempts == 1)
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
        case .locked: "Vault: locked"
        case .syncFailed: "Vault: server_unavailable"
        case .synced: "Vault: online_unlocked"
        }
    #expect(application.status == expectedStatus)
    let expectedFeedback: String? =
        switch outcome {
        case .locked: nil
        case .synced: "Vault synced."
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

private func queuedGitHubReview() throws -> ApprovalReview {
    let id = String(repeating: "a", count: 32)
    let created = MonotonicTimestamp.now
    let provider: [String: Any] = [
        "server": "https://vault.example.invalid", "account": "dummy", "email": "dummy@example.invalid",
        "item": "dummy", "field": "LoginPassword", "role": "github-write",
        "enrollment": String(repeating: "b", count: 32), "generation": 1,
    ]
    let stamp = try JSONSerialization.jsonObject(with: JSONEncoder().encode(created), options: .fragmentsAllowed)
    let request = try JSONSerialization.data(withJSONObject: [
        "provider": provider, "operationId": id, "created": stamp,
        "repository": "", "method": "PATCH", "body": "", "path": "/unfamiliar",
        "origin": "https://api.github.com", "processChain": ["gh"], "readRoots": [],
        "presentation": ["intent": ["kind": "request"], "additionalEffects": [], "allowsReadScope": false],
    ])
    return try JSONDecoder().decode(
        ApprovalReview.self,
        from: JSONSerialization.data(withJSONObject: [
            "id": id, "created": stamp, "provider": provider,
            "session": Data(repeating: 1, count: 16).base64EncodedString(),
            "policy": Data(repeating: 2, count: 32).base64EncodedString(),
            "nonce": Data(repeating: 3, count: 32).base64EncodedString(),
            "request": request.base64EncodedString(),
            "requestDigest": Data(SHA256.hash(data: request)).base64EncodedString(),
        ]))
}

@Test(arguments: [true, false]) @MainActor
private func queuedGitHubReviewWaitsForTheVisibleDialogOrPresentationLease(_ otherProcess: Bool) async throws {
    let client = try RecoveryClient(suspension: .poll)
    let existing = InertApprovalWindow()
    var acquisitions = 0
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { client }, loadApprovalKey: { Data([1]) },
        acquirePresentation: {
            acquisitions += 1
            throw DialogPresentationLease.Failure.alreadyPresented
        })
    defer {
        existing.close()
        _ = application.applicationShouldTerminate(NSApplication.shared)
        client.complete(.failure(CancellationError()))
    }
    activate(application)
    try await eventually { client.pending != nil }
    if !otherProcess { application.present(existing) }
    client.complete(.success(.review(try queuedGitHubReview())))
    try await Task.sleep(for: .milliseconds(300))
    #expect(client.cancellations.isEmpty)
    #expect(existing.isPresented == !otherProcess)
    #expect(client.polls == 1)
    if !otherProcess { existing.close() }
    try await eventually { acquisitions > 0 }
    application.revokeReads()
    try await eventually { client.polls == 2 }
    #expect(client.cancellations.isEmpty)
    #expect(application.connected)
}

@Test @MainActor func aLateWindowCloseCannotDismissTheCurrentApproval() throws {
    let application = BrokerApplication(setActivationPolicy: { _ in })
    let first = InertApprovalWindow()
    let second = InertApprovalWindow()
    application.present(first)
    application.present(second)
    first.close()
    #expect(second.isPresented)
    second.close()
}
