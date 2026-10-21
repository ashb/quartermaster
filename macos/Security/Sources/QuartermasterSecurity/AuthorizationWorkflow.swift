import CryptoKit
import Foundation

public struct ApprovalProviderIdentity: Codable, Equatable, Sendable {
    public let server: String
    public let account: String
    public let email: String
    public let item: String
    public let field: String
    public let role: String
    public let enrollment: String
    public let generation: UInt64
}

public struct ApprovalReview: Codable, Equatable, Sendable {
    public let id: String
    public let created: MonotonicTimestamp
    public let session: Data
    public let policy: Data
    public let nonce: Data
    public let request: Data
    public let requestDigest: Data
    public let provider: ApprovalProviderIdentity
}

public struct ApprovalChallenge: Codable, Sendable {
    public let review: ApprovalReview
    public let credentialDigest: Data
    public let authenticated: MonotonicTimestamp
    public let expires: MonotonicTimestamp
    public let bytes: Data

    public init(review: ApprovalReview, credentialDigest: Data, authenticated: MonotonicTimestamp,
                expires: MonotonicTimestamp, bytes: Data) {
        self.review = review
        self.credentialDigest = credentialDigest
        self.authenticated = authenticated
        self.expires = expires
        self.bytes = bytes
    }
}

public struct AuthorizationWorkflow: Sendable {
    public enum Failure: Error { case invalidReview, invalidState, invalidAuthentication, invalidChallenge, expired }
    private enum Phase: Sendable { case review, authenticated(MonotonicTimestamp), validated(MonotonicTimestamp), canceled }
    private let review: ApprovalReview
    private var phase: Phase = .review

    public init(review: ApprovalReview, now: MonotonicTimestamp) throws {
        struct RequestClaims: Decodable {
            let provider: ApprovalProviderIdentity
            let operationId: String
            let created: MonotonicTimestamp
        }
        guard review.id.count == 32, review.id.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              !review.created.isZero, let age = try? now.duration(since: review.created), age < .seconds(120),
              review.session.count == 16, review.policy.count == 32, review.nonce.count == 32,
              review.nonce.contains(where: { $0 != 0 }), review.request.count <= 12000,
              Data(SHA256.hash(data: review.request)) == review.requestDigest,
              review.provider.field == "LoginPassword", !review.provider.server.isEmpty,
              !review.provider.account.isEmpty, !review.provider.email.isEmpty,
              !review.provider.item.isEmpty, !review.provider.role.isEmpty,
              review.provider.enrollment.count == 32,
              review.provider.enrollment.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw Failure.invalidReview
        }
        guard let claims = try? JSONDecoder().decode(RequestClaims.self, from: review.request),
              claims.provider == review.provider, claims.operationId == review.id, claims.created == review.created else {
            throw Failure.invalidReview
        }
        self.review = review
    }

    public mutating func recordAuthentication(at authenticated: MonotonicTimestamp, now: MonotonicTimestamp) throws {
        guard case .review = phase else { throw Failure.invalidState }
        guard let pending = try? authenticated.duration(since: review.created), pending < .seconds(120),
              let age = try? now.duration(since: authenticated), age < .seconds(30) else { throw Failure.invalidAuthentication }
        phase = .authenticated(authenticated)
    }

    public mutating func validate(_ challenge: ApprovalChallenge, now: MonotonicTimestamp) throws -> Data {
        guard case .authenticated(let authenticated) = phase else { throw Failure.invalidState }
        try checkDeadline(authenticated, now: now)
        guard challenge.review == review, challenge.authenticated == authenticated,
              challenge.expires == (try authenticated.advanced(by: .seconds(30))),
              challenge.credentialDigest.count == 32, challenge.credentialDigest.contains(where: { $0 != 0 }) else {
            throw Failure.invalidChallenge
        }
        let (seconds, attoseconds) = try authenticated.duration(since: review.created).components
        let nanoseconds = UInt64(seconds) * 1_000_000_000 + UInt64(attoseconds / 1_000_000_000)
        var bigEndian = nanoseconds.bigEndian
        var offset = Data(repeating: 0, count: 8)
        withUnsafeBytes(of: &bigEndian) { offset.append(contentsOf: $0) }
        let expected = Data("quartermaster.credential-approval.v1\0allow-once\0".utf8)
            + review.session + review.policy + review.requestDigest + challenge.credentialDigest + review.nonce + offset
        guard challenge.bytes == expected else { throw Failure.invalidChallenge }
        phase = .validated(authenticated)
        return challenge.bytes
    }

    public func checkSubmission(now: MonotonicTimestamp) throws {
        guard case .validated(let authenticated) = phase else { throw Failure.invalidState }
        try checkDeadline(authenticated, now: now)
    }

    public mutating func cancel() { phase = .canceled }

    private func checkDeadline(_ authenticated: MonotonicTimestamp, now: MonotonicTimestamp) throws {
        guard let age = try? now.duration(since: authenticated), age < .seconds(30) else { throw Failure.expired }
    }
}
