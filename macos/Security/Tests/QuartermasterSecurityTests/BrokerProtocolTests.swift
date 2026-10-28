import Foundation
import Testing

@testable import QuartermasterSecurity

@Test(arguments: [
    #"{"kind":"unknown"}"#,
    #"{"kind":"hello"}"#,
    #"{"kind":"review"}"#,
    #"{"kind":"challenge"}"#,
    #"{"kind":"vaultStatus"}"#,
    #"{"kind":"vaultStatus","state":"unknown"}"#,
    #"{"kind":"error"}"#,
    #"{"kind":"error","code":"unknown"}"#,
])
func brokerRepliesRejectUnknownCasesAndMissingRequiredPayloads(_ json: String) {
    #expect(throws: DecodingError.self) {
        try JSONDecoder().decode(BrokerReply.self, from: Data(json.utf8))
    }
}

private func brokerFixtures(_ section: String) throws -> [[String: Any]] {
    let url = try #require(
        Bundle.module.url(forResource: "broker-protocol", withExtension: "json", subdirectory: "Fixtures"))
    let fixture = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    return try #require(fixture[section] as? [[String: Any]])
}

private func brokerTimestamp(_ nanoseconds: UInt64) throws -> MonotonicTimestamp {
    try JSONDecoder().decode(MonotonicTimestamp.self, from: Data(String(nanoseconds).utf8))
}

@Test func brokerCommandsEncodeTheSharedRustWireFixtures() throws {
    let id = String(repeating: "a", count: 32)
    let commands: [BrokerCommand] = [
        .hello, .enroll(publicKey: Data([1, 2])), .next,
        .presence(id: id, authenticated: try brokerTimestamp(105_000_000_000)),
        .proof(id: id, signature: Data([3, 4])), .cancel(id: id), .vaultStatus,
        .vaultLogin(
            server: "https://vault.example.invalid", email: "dummy@example.invalid", password: "dummy master password",
            itemID: nil),
        .vaultLogin(
            server: "https://vault.example.invalid", email: "dummy@example.invalid", password: "dummy master password",
            itemID: "22222222-2222-4222-8222-222222222222"),
        .vaultLock, .vaultUnlock, .vaultSync, .vaultDiscard, .revokeReadGrants,
        .prepareVaultUnlock(revision: 4),
        .vaultUnlockPresence(id: id, authenticated: try brokerTimestamp(105_000_000_000)),
        .vaultUnlockCancel(id: id),
    ]
    let fixtures = try brokerFixtures("commands")
    #expect(commands.count == fixtures.count)
    for (command, fixture) in zip(commands, fixtures) {
        let encoded = try #require(JSONSerialization.jsonObject(with: command.encoded()) as? [String: Any])
        #expect(NSDictionary(dictionary: encoded).isEqual(to: fixture))
    }
}

@Test func brokerRepliesDecodeTheSharedRustWireFixtures() throws {
    let fixtures = try brokerFixtures("replies")
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .secondsSince1970
    for fixture in fixtures {
        let bytes = try JSONSerialization.data(withJSONObject: fixture)
        let reply = try decoder.decode(BrokerReply.self, from: bytes)
        let kind: String
        switch reply {
        case .hello(let profile):
            kind = "hello"
            #expect(profile == "development")
        case .enrolled: kind = "enrolled"
        case .idle: kind = "idle"
        case .review(let review):
            kind = "review"
            #expect(review.id == String(repeating: "a", count: 32))
            #expect(review.provider.generation == 7)
        case .challenge(let challenge):
            kind = "challenge"
            #expect(challenge.authenticated == (try brokerTimestamp(105_000_000_000)))
            #expect(challenge.expires == (try brokerTimestamp(135_000_000_000)))
            #expect(challenge.credentialDigest == Data(repeating: 4, count: 32))
        case .accepted: kind = "accepted"
        case .canceled: kind = "canceled"
        case .alreadyAdmitted: kind = "alreadyAdmitted"
        case .unknownOperation: kind = "unknownOperation"
        case .readGrantsRevoked: kind = "readGrantsRevoked"
        case .vaultUnlockReview(let review):
            kind = "vaultUnlockReview"
            #expect(review.revision == 4)
            #expect(review.provider.binding.email == "dummy@example.invalid")
        case .settingsStatus, .settingsReview, .settingsChallenge, .enrollmentStaged, .settingsApplied:
            Issue.record("Unexpected settings reply in the operation fixture")
            kind = "unexpectedSettings"
        case .error(let code):
            kind = "error"
            #expect(code.rawValue == (fixture["code"] as? String))
        case .vaultStatus(let status):
            kind = "vaultStatus"
            #expect(status.state.rawValue == (fixture["state"] as? String))
            if status.state == .locked {
                #expect(status.binding?.accountID == "11111111-1111-4111-8111-111111111111")
                #expect(status.binding?.itemID == "22222222-2222-4222-8222-222222222222")
                #expect(status.binding?.field == "LoginPassword")
                #expect(status.lastSync == Date(timeIntervalSince1970: 123))
                #expect(status.observation == .persistedCache)
            } else {
                #expect(status.binding == nil)
                #expect(status.lastSync == nil)
                #expect(status.error == "StorageBusy")
            }
        }
        #expect(kind == (fixture["kind"] as? String))
    }
}

@Test(arguments: [
    BrokerControlError.invalidMessage, .denied, .expired, .busy, .providerChanged, .sessionEnded, .unavailable,
])
func brokerBackendRejectionsRetainTheirTypedError(_ code: BrokerControlError) throws {
    let fixture = try #require(brokerFixtures("replies").first { ($0["code"] as? String) == code.rawValue })
    let bytes = try JSONSerialization.data(withJSONObject: fixture)
    #expect(throws: code) { try BrokerReply.decodeSuccess(bytes) }
}

@Test func brokerCodecBoundsBothDirectionsWithoutReturningAPartialMessage() throws {
    let command = BrokerCommand.vaultLogin(
        server: "https://vault.example.invalid", email: "dummy@example.invalid",
        password: String(repeating: "x", count: 1024 * 1024), itemID: nil)
    #expect(throws: BrokerProtocolFailure.oversizedPayload) { try command.encoded() }
    #expect(throws: BrokerProtocolFailure.oversizedPayload) {
        try BrokerReply.decodeSuccess(Data(repeating: 32, count: 1024 * 1024 + 1))
    }
}

@Test func brokerChallengeEnvelopePreservesTheFrozenReviewAndOriginalAuthenticationEvent() throws {
    let fixtures = try brokerFixtures("replies")
    let reviewBytes = try JSONSerialization.data(
        withJSONObject: #require(fixtures.first { ($0["kind"] as? String) == "review" }))
    let challengeBytes = try JSONSerialization.data(
        withJSONObject: #require(fixtures.first { ($0["kind"] as? String) == "challenge" }))
    guard case .review(let review) = try BrokerReply.decodeSuccess(reviewBytes),
        case .challenge(let challenge) = try BrokerReply.decodeSuccess(challengeBytes)
    else {
        Issue.record("shared approval fixtures did not decode to their required payloads")
        return
    }
    #expect(challenge.review == review)
    var workflow = try AuthorizationWorkflow(review: review, now: brokerTimestamp(101_000_000_000))
    try workflow.recordAuthentication(at: challenge.authenticated, now: brokerTimestamp(106_000_000_000))
    let signingBytes = try workflow.validate(challenge, now: brokerTimestamp(107_000_000_000))
    #expect(signingBytes == challenge.bytes)
}
