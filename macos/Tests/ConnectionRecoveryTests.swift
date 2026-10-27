import AppKit
import Foundation
import LocalAuthentication
import QuartermasterSecurity
import Synchronization
import Testing

@testable import Quartermaster

private final class RecoveryClient: BrokerClient, Sendable {
    enum Suspension: CaseIterable, Sendable { case enrolment, poll }
    private let lost = Mutex(false)
    private let snapshot: SettingsSnapshot
    private let vault: BrokerVaultStatus
    private let rejectsRegistration: Bool
    private let suspension: Suspension?
    @MainActor private(set) var registrationKeys: [Data] = []
    @MainActor private(set) var enrolmentKeys: [Data] = []
    @MainActor private(set) var polls = 0
    @MainActor private(set) var unexpectedCommands: [BrokerCommand] = []
    @MainActor private(set) var pending: CheckedContinuation<BrokerReply, any Error>?

    init(rejectsRegistration: Bool = false, suspension: Suspension? = nil) throws {
        self.rejectsRegistration = rejectsRegistration
        self.suspension = suspension
        snapshot = try JSONDecoder().decode(
            SettingsSnapshot.self,
            from: Data(
                #"{"state":"configured","revision":4,"session":"AQEBAQEBAQEBAQEBAQ==","settings":{"github":{"version":1,"mode":"github","repositories":[],"approveUnverifiedRequests":true},"mutations":"requireApproval"},"provider":{"slot":"dummy","binding":{"server":"https://vault.example.invalid","email":"dummy@example.invalid","account_id":"dummy","item_id":"dummy","field":"LoginPassword","role":"github-write"},"scope":"dummy","deviceKey":[1]},"migration":null}"#
                    .utf8))
        vault = try JSONDecoder().decode(BrokerVaultStatus.self, from: Data(#"{"state":"locked"}"#.utf8))
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
        case .vaultStatus: return .vaultStatus(vault)
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
