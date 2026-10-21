import CryptoKit
import Foundation
import Testing
@testable import QuartermasterSecurity

private func stamp(_ seconds: UInt64) throws -> MonotonicTimestamp {
    try JSONDecoder().decode(MonotonicTimestamp.self, from: Data("\(seconds * 1_000_000_000)".utf8))
}

private func review(changing change: (inout [String: Any]) -> Void = { _ in }) throws -> ApprovalReview {
    let provider: [String: Any] = ["server": "https://vault.example", "account": "account-id", "email": "dummy@example.test",
                                   "item": "item-id", "field": "LoginPassword", "role": "github-write",
                                   "enrollment": String(repeating: "b", count: 32), "generation": 7]
    let request = try JSONSerialization.data(withJSONObject: ["provider": provider, "operationId": String(repeating: "a", count: 32),
                                                              "created": 100_000_000_000 as UInt64, "operation": "close issue"])
    var fields: [String: Any] = [
        "id": String(repeating: "a", count: 32), "created": 100_000_000_000 as UInt64,
        "session": Data(repeating: 1, count: 16).base64EncodedString(),
        "policy": Data(repeating: 2, count: 32).base64EncodedString(),
        "nonce": Data(repeating: 3, count: 32).base64EncodedString(),
        "request": request.base64EncodedString(),
        "requestDigest": Data(SHA256.hash(data: request)).base64EncodedString(),
        "provider": provider,
    ]
    change(&fields)
    return try JSONDecoder().decode(ApprovalReview.self, from: JSONSerialization.data(withJSONObject: fields))
}

@Test func approvalWorkflowRequiresProviderIdentityInsideTheSignedRequest() throws {
    let changed = try review { fields in
        var provider = fields["provider"] as! [String: Any]
        provider["email"] = "different@example.test"
        fields["provider"] = provider
    }

    #expect(throws: AuthorizationWorkflow.Failure.self) { try AuthorizationWorkflow(review: changed, now: stamp(101)) }
}

private func finalChallenge(_ review: ApprovalReview, authenticated: MonotonicTimestamp,
                            digest: Data = Data(repeating: 4, count: 32)) throws -> ApprovalChallenge {
    var offset = Data(repeating: 0, count: 8)
    var elapsed = try authenticated.duration(since: review.created).components.seconds * 1_000_000_000
    withUnsafeBytes(of: &elapsed) { offset.append(contentsOf: $0.reversed()) }
    let bytes = Data("quartermaster.credential-approval.v1\0allow-once\0".utf8)
        + review.session + review.policy + review.requestDigest + digest + review.nonce + offset
    return ApprovalChallenge(review: review, credentialDigest: digest, authenticated: authenticated,
                             expires: try authenticated.advanced(by: .seconds(30)), bytes: bytes)
}

@Test func approvalWorkflowValidatesTheCompleteFrozenChallengeOnce() throws {
    let initial = try review()
    var workflow = try AuthorizationWorkflow(review: initial, now: stamp(101))
    let authenticated = try stamp(105)
    try workflow.recordAuthentication(at: authenticated, now: stamp(106))
    let challenge = try finalChallenge(initial, authenticated: authenticated)

    #expect(try workflow.validate(challenge, now: stamp(134)) == challenge.bytes)
    #expect(throws: AuthorizationWorkflow.Failure.self) { try workflow.validate(challenge, now: stamp(134)) }
    try workflow.checkSubmission(now: stamp(134))
    #expect(throws: AuthorizationWorkflow.Failure.self) { try workflow.checkSubmission(now: stamp(135)) }
}

@Test(arguments: ["id", "created", "session", "policy", "nonce", "request", "requestDigest",
                  "server", "account", "email", "item", "field", "role", "enrollment", "generation"])
func approvalWorkflowRejectsEveryChangedFrozenField(_ field: String) throws {
    let initial = try review()
    var workflow = try AuthorizationWorkflow(review: initial, now: stamp(101))
    let authenticated = try stamp(105)
    try workflow.recordAuthentication(at: authenticated, now: stamp(106))
    let changed = try review { fields in
        if var provider = fields["provider"] as? [String: Any], provider[field] != nil {
            provider[field] = field == "generation" ? 8 : "replacement"
            fields["provider"] = provider
        } else {
            switch field {
            case "created": fields[field] = 101_000_000_000 as UInt64
            case "id": fields[field] = String(repeating: "c", count: 32)
            case "request": fields[field] = Data("other request".utf8).base64EncodedString()
            case "session": fields[field] = Data(repeating: 9, count: 16).base64EncodedString()
            default: fields[field] = Data(repeating: 9, count: 32).base64EncodedString()
            }
        }
    }
    let challenge = try finalChallenge(changed, authenticated: authenticated)

    #expect(throws: AuthorizationWorkflow.Failure.self) { try workflow.validate(challenge, now: stamp(107)) }
}

@Test(arguments: ["authentication", "deadline", "offset", "digest", "zeroDigest", "nonce", "length"])
func approvalWorkflowRejectsChangedAuthenticationOrSigningBytes(_ field: String) throws {
    let initial = try review()
    var workflow = try AuthorizationWorkflow(review: initial, now: stamp(101))
    let authenticated = try stamp(105)
    try workflow.recordAuthentication(at: authenticated, now: stamp(106))
    let valid = try finalChallenge(initial, authenticated: authenticated)
    var fields = try JSONSerialization.jsonObject(with: JSONEncoder().encode(valid)) as! [String: Any]
    switch field {
    case "authentication": fields["authenticated"] = 106_000_000_000 as UInt64
    case "deadline": fields["expires"] = 136_000_000_000 as UInt64
    case "digest": fields["credentialDigest"] = Data(repeating: 8, count: 32).base64EncodedString()
    case "zeroDigest": fields["credentialDigest"] = Data(repeating: 0, count: 32).base64EncodedString()
    default:
        var bytes = valid.bytes
        if field == "length" { bytes.append(0) }
        else { bytes[bytes.count - (field == "nonce" ? 17 : 1)] ^= 1 }
        fields["bytes"] = bytes.base64EncodedString()
    }
    let changed = try JSONDecoder().decode(ApprovalChallenge.self, from: JSONSerialization.data(withJSONObject: fields))

    #expect(throws: AuthorizationWorkflow.Failure.self) { try workflow.validate(changed, now: stamp(107)) }
}

@Test func approvalWorkflowRejectsMissingDuplicateFutureAndExpiredAuthentication() throws {
    let initial = try review()
    let challenge = try finalChallenge(initial, authenticated: stamp(105))
    var workflow = try AuthorizationWorkflow(review: initial, now: stamp(101))
    #expect(throws: AuthorizationWorkflow.Failure.self) { try workflow.validate(challenge, now: stamp(107)) }
    #expect(throws: AuthorizationWorkflow.Failure.self) { try workflow.recordAuthentication(at: stamp(108), now: stamp(107)) }
    #expect(throws: AuthorizationWorkflow.Failure.self) { try workflow.recordAuthentication(at: stamp(99), now: stamp(107)) }
    try workflow.recordAuthentication(at: stamp(105), now: stamp(107))
    #expect(throws: AuthorizationWorkflow.Failure.self) { try workflow.recordAuthentication(at: stamp(106), now: stamp(107)) }
    #expect(throws: AuthorizationWorkflow.Failure.self) { try workflow.validate(challenge, now: stamp(135)) }
    #expect(throws: AuthorizationWorkflow.Failure.self) { try AuthorizationWorkflow(review: initial, now: stamp(220)) }
}

@Test func canceledApprovalWorkflowCannotResumeAndDoesNotAffectAnotherWorkflow() throws {
    let initial = try review()
    var canceled = try AuthorizationWorkflow(review: initial, now: stamp(101))
    var independent = try AuthorizationWorkflow(review: initial, now: stamp(101))
    canceled.cancel()

    #expect(throws: AuthorizationWorkflow.Failure.self) { try canceled.recordAuthentication(at: stamp(105), now: stamp(106)) }
    try independent.recordAuthentication(at: stamp(105), now: stamp(106))
    let challenge = try finalChallenge(initial, authenticated: stamp(105))
    #expect(try independent.validate(challenge, now: stamp(107)) == challenge.bytes)
}
