import Foundation
import LocalAuthentication
import QuartermasterApprovalUI
import QuartermasterSecurity

@MainActor
final class BrokerHandoffPending: ApprovalBackend {
    let reviewCreated: MonotonicTimestamp
    let request: CredentialHandoffRequest
    private let client: any BrokerClient
    private let id: String
    private var workflow: AuthorizationWorkflow
    private var submitted = false

    init(client: any BrokerClient, review: ApprovalReview) throws {
        workflow = try AuthorizationWorkflow(review: review, now: .now)
        request = try CredentialHandoffRequest.parse(review: review)
        reviewCreated = review.created
        self.client = client
        id = review.id
    }

    func challenge(authenticated: MonotonicTimestamp, context: LAContext) async throws -> Data {
        try workflow.recordAuthentication(at: authenticated, now: .now)
        guard
            case .challenge(let challenge) = try await client.call(
                .presence(id: id, authenticated: authenticated), context: context)
        else { throw BrokerFailure.invalidMessage }
        return try workflow.validate(challenge, now: .now)
    }

    func submit(_ signature: Data) async throws {
        try workflow.checkSubmission(now: .now)
        guard !submitted else { throw BrokerFailure.invalidMessage }
        submitted = true
        guard case .accepted = try await client.call(.proof(id: id, signature: signature)) else {
            throw BrokerFailure.invalidMessage
        }
    }

    func cancel() {
        workflow.cancel()
        Task { _ = try? await client.call(.cancel(id: id)) }
    }
}
