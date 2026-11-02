import CryptoKit
import Foundation
import LocalAuthentication
import Testing

@testable import Quartermaster
@testable import QuartermasterApprovalUI
@testable import QuartermasterSecurity

func handoffReview(created: MonotonicTimestamp = .now, change: (inout [String: Any]) -> Void = { _ in }) throws
    -> ApprovalReview
{
    let provider: [String: Any] = [
        "server": "https://vault.example.invalid", "account": "account-id", "email": "dummy@example.invalid",
        "item": "22222222-2222-4222-8222-222222222222", "field": "LoginPassword", "role": "restic-password",
        "enrollment": String(repeating: "b", count: 32), "generation": 7,
    ]
    var request: [String: Any] = [
        "kind": "credentialHandoff", "tool": "restic", "credentialName": "Backup password",
        "recipient": [
            "pid": 123, "execution": "native-binding", "executable": "/nix/store/example/bin/.restic-wrapped",
            "requirement": "cdhash binding",
        ],
        "command": ["/nix/store/example/bin/.restic-wrapped", "snapshots", "--repo", "/tmp/disposable"],
        "workingDirectory": "/tmp/work", "provider": provider,
        "requester": [
            "pid": 100, "executable": "/Applications/Quartermaster.app/Contents/MacOS/qm", "signingIdentifier": "qm",
            "cdHash": "dummy", "adHoc": false, "ancestryComplete": false,
            "ancestryNote": "Earlier ancestors unavailable.",
        ],
        "created": created.serializedNanoseconds, "operationId": String(repeating: "a", count: 32),
    ]
    change(&request)
    let bytes = try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys])
    return ApprovalReview(
        id: String(repeating: "a", count: 32), created: created, session: Data(repeating: 1, count: 16),
        policy: Data(repeating: 2, count: 32), nonce: Data(repeating: 3, count: 32), request: bytes,
        requestDigest: Data(SHA256.hash(data: bytes)),
        provider: try JSONDecoder().decode(
            ApprovalProviderIdentity.self, from: JSONSerialization.data(withJSONObject: provider)))
}

@Test func handoffReplyRetainsTheFrozenApprovalForItsDedicatedDialog() throws {
    let review = try handoffReview()
    let encoded = try JSONSerialization.data(withJSONObject: [
        "kind": "handoffReview", "approval": JSONSerialization.jsonObject(with: JSONEncoder().encode(review)),
    ])
    guard case .handoffReview(let decoded) = try BrokerReply.decodeSuccess(encoded) else {
        Issue.record("Expected a handoff review")
        return
    }
    #expect(decoded == review)
    let request = try CredentialHandoffRequest.parse(review: decoded)
    #expect(request.credentialName == "Backup password")
    #expect(request.recipient.executable == "/nix/store/example/bin/.restic-wrapped")
    #expect(request.requester.pid == 100)
}

@Test(arguments: [
    "kind", "tool", "credentialName", "pid", "execution", "executable", "requirement", "command", "workingDirectory",
    "provider", "operationId", "created",
])
func handoffReviewRejectsUnsupportedOrInconsistentPresentation(_ field: String) throws {
    let review = try handoffReview { fields in
        switch field {
        case "kind": fields[field] = "github"
        case "tool": fields[field] = "unknown"
        case "credentialName": fields[field] = ""
        case "command": fields[field] = ["/different/restic"]
        case "workingDirectory": fields[field] = "relative"
        case "provider": fields.removeValue(forKey: field)
        case "operationId": fields[field] = String(repeating: "c", count: 32)
        case "created": fields[field] = 1
        default:
            var recipient = fields["recipient"] as! [String: Any]
            recipient[field] = field == "pid" ? 0 : ""
            fields["recipient"] = recipient
        }
    }
    #expect(throws: (any Error).self) { try CredentialHandoffRequest.parse(review: review) }
}

@Test func handoffPresentationEscapesUntrustedNamesAndPreservesArgumentBoundaries() throws {
    let review = try handoffReview { fields in
        fields["credentialName"] = "Backup\n\u{202e}password"
        fields["command"] = ["/nix/store/example/bin/.restic-wrapped", "backup", "a b", "a\nb", ""]
    }
    let request = try CredentialHandoffRequest.parse(review: review)
    #expect(request.displayCredentialName == "Backup\\n\\u{202e}password")
    #expect(request.displayCommand.contains("\"a b\""))
    #expect(request.displayCommand.contains("\"a\\nb\""))
    #expect(request.displayCommand.hasSuffix("\"\""))
}

@Test func handoffCallerTreePreservesAncestryWithoutInventingRecipientParentageOrGrants() throws {
    let review = try handoffReview { fields in
        var requester = fields["requester"] as! [String: Any]
        requester["processes"] = [
            [
                "pid": 80, "name": "Terminal", "executable": "/Applications/Terminal.app/Contents/MacOS/Terminal",
                "limited": false,
            ],
            ["pid": 90, "name": "login", "executable": "/usr/bin/login", "limited": true],
            ["pid": 95, "name": "zsh", "executable": "/bin/zsh", "limited": false],
            ["pid": 100, "name": "qm", "executable": requester["executable"]!, "limited": false],
        ]
        fields["requester"] = requester
    }
    let request = try CredentialHandoffRequest.parse(review: review)
    let rows = request.callerRows(shimExecutable: request.requester.executable)
    #expect(rows.map(\.id) == [80, 95])
    #expect(rows.allSatisfy { $0.choice == nil && !$0.scopeOffered })
    #expect(!rows.contains { $0.id == request.recipient.pid })
    #expect(request.callerDetails.contains("login · PID 90"))
    #expect(request.callerDetails.contains("qm · PID 100"))
    #expect(request.fullDetails.contains(request.recipient.execution))
    #expect(request.fullDetails.contains(request.recipient.executable))
}

@Test(arguments: [nil, "/Applications/Quartermaster.app/Contents/MacOS/qm"] as [String?])
func handoffCallerTreeFallsBackToKnownRequesterWhenAncestryIsMissing(shim: String?) throws {
    let request = try CredentialHandoffRequest.parse(review: handoffReview())
    let rows = request.callerRows(shimExecutable: shim)
    #expect(rows.map(\.id) == [request.requester.pid])
    #expect(rows.first?.process.executable == request.requester.executable)
    #expect(rows.first?.choice == nil)
    #expect(request.compactCommand.hasPrefix("restic "))
    #expect(request.displayCommand.contains(request.recipient.executable))
}

@Test func handoffProjectsTheRecipientWithoutAddingItToObservedAncestryOrOfferingGrants() throws {
    let request = try CredentialHandoffRequest.parse(review: handoffReview())
    let rows = request.processRows(shimExecutable: nil)
    let recipient = try #require(rows.last)
    #expect(recipient.id == request.recipient.pid)
    #expect(recipient.process.executable == request.recipient.executable)
    #expect(recipient.process.name == "restic")
    #expect(recipient.isProjected)
    #expect(recipient.label == "On approval")
    #expect(rows.dropLast().allSatisfy { !$0.isProjected })
    #expect(rows.allSatisfy { $0.choice == nil && !$0.scopeOffered })
    #expect(!request.callerDetails.contains(request.recipient.executable))
    #expect(request.approvalDetails.contains(request.recipient.executable))
}

@MainActor private final class HandoffClient: BrokerClient {
    nonisolated var disconnected: Bool { false }
    nonisolated func cancel() {}
    let review: ApprovalReview
    var replaceRequest = false
    private(set) var proofs: [Data] = []
    private(set) var cancellations: [String] = []

    init(review: ApprovalReview) { self.review = review }

    func call(_ command: BrokerCommand, context: LAContext?) async throws -> BrokerReply {
        switch command {
        case .presence(let id, let authenticated):
            #expect(id == review.id)
            #expect(context != nil)
            let frozen =
                replaceRequest
                ? try handoffReview(created: review.created) { $0["credentialName"] = "Other password" } : review
            let digest = Data(repeating: 4, count: 32)
            let components = try authenticated.duration(since: frozen.created).components
            var nanoseconds =
                (UInt64(components.seconds) * 1_000_000_000 + UInt64(components.attoseconds / 1_000_000_000)).bigEndian
            var offset = Data(repeating: 0, count: 8)
            withUnsafeBytes(of: &nanoseconds) { offset.append(contentsOf: $0) }
            return .challenge(
                ApprovalChallenge(
                    review: frozen, credentialDigest: digest, authenticated: authenticated,
                    expires: try authenticated.advanced(by: .seconds(30)),
                    bytes: Data("quartermaster.credential-approval.v1\0allow-once\0".utf8)
                        + frozen.session + frozen.policy + frozen.requestDigest + digest + frozen.nonce + offset))
        case .proof(let id, let signature):
            #expect(context == nil)
            #expect(id == review.id)
            proofs.append(signature)
            return .accepted
        case .cancel(let id):
            cancellations.append(id)
            return .canceled
        default: throw BrokerFailure.invalidMessage
        }
    }
}

@Test @MainActor func handoffUsesTheExistingPresenceProofAndCancellationCommands() async throws {
    let review = try handoffReview()
    let client = HandoffClient(review: review)
    let pending = try BrokerHandoffPending(client: client, review: review)
    let bytes = try await pending.challenge(authenticated: .now, context: LAContext())
    #expect(bytes.starts(with: Data("quartermaster.credential-approval.v1\0allow-once\0".utf8)))
    let signature = Data([1, 2, 3])
    try await pending.submit(signature)
    #expect(client.proofs == [signature])
    await #expect(throws: BrokerFailure.self) { try await pending.submit(signature) }
    #expect(client.proofs.count == 1)
    pending.cancel()
    for _ in 0..<100 where client.cancellations.isEmpty { await Task.yield() }
    #expect(client.cancellations == [review.id])
    await #expect(throws: AuthorizationWorkflow.Failure.self) { try await pending.submit(signature) }
    #expect(client.proofs.count == 1)
}

@Test @MainActor func handoffCannotSubmitWithoutValidatedPresence() async throws {
    let client = HandoffClient(review: try handoffReview())
    let pending = try BrokerHandoffPending(client: client, review: client.review)
    await #expect(throws: AuthorizationWorkflow.Failure.self) { try await pending.submit(Data([1])) }
    #expect(client.proofs.isEmpty)
}

@Test @MainActor func handoffRejectsAChangedCredentialAtTheChallengeBoundary() async throws {
    let client = HandoffClient(review: try handoffReview())
    client.replaceRequest = true
    let pending = try BrokerHandoffPending(client: client, review: client.review)
    await #expect(throws: AuthorizationWorkflow.Failure.self) {
        try await pending.challenge(authenticated: .now, context: LAContext())
    }
    #expect(client.proofs.isEmpty)
}
