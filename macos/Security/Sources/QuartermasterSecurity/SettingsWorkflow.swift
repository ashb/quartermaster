import CryptoKit
import Foundation

public struct RepositorySetting: Codable, Equatable, Sendable, Identifiable {
    public var id: UInt64
    public var owner: String
    public var name: String
    public var writes: Bool = false

    public init(id: UInt64, owner: String, name: String) {
        self.id = id
        self.owner = owner
        self.name = name
    }
}

public struct GitHubSettings: Codable, Equatable, Sendable {
    public var version = 1
    public var mode = "github"
    public var repositories: [RepositorySetting] = []
    public var approveUnverifiedRequests = false

    public init() {}
}

public struct BrokerSettings: Codable, Equatable, Sendable {
    public enum MutationRule: String, Codable, Sendable { case requireApproval, deny }
    public var github: GitHubSettings?
    public var mutations: MutationRule = .requireApproval

    public init() {}
}

public struct SettingsProvider: Codable, Equatable, Sendable {
    public let slot: String
    public let binding: VaultBinding
    public let scope: String
    public let deviceKey: [UInt8]
}

public struct SettingsSnapshot: Decodable, Sendable {
    public let state: String
    public let revision: UInt64
    public let session: Data?
    public let settings: BrokerSettings?
    public let provider: SettingsProvider?
    public let retained: [SettingsProvider]
}

public struct SettingsRecord: Decodable, Equatable, Sendable {
    public let version: UInt8
    public let profile: String
    public let revision: UInt64
    public let publicKey: [UInt8]
    public let settings: BrokerSettings?
    public let provider: SettingsProvider?
}

public struct SettingsDocument: Decodable, Sendable {
    public let version: String
    public let previous: SettingsRecord
    public let proposed: SettingsRecord
}

public struct SettingsReview: Codable, Equatable, Sendable {
    public let id: String
    public let created: MonotonicTimestamp
    public let session: Data
    public let nonce: Data
    public let revision: UInt64
    public let document: Data
    public let digest: Data
    public let approvalKey: Data

    public var text: String {
        document.map { byte in
            switch byte {
            case 10: "\n"
            case 32...91, 93...126: String(UnicodeScalar(byte))
            case 92: "\\\\"
            default: String(format: "\\x%02x", byte)
            }
        }.joined()
    }
}

public struct SettingsChallenge: Codable, Sendable {
    public let review: SettingsReview
    public let authenticated: MonotonicTimestamp
    public let expires: MonotonicTimestamp
    public let bytes: Data
}

public enum SettingsProviderChoice: Encodable, Sendable {
    case keep, forget
    case existing(SettingsProvider)
    case staged(String)

    private enum CodingKeys: String, CodingKey { case kind, ticket, provider }

    public func encode(to encoder: any Encoder) throws {
        var fields = encoder.container(keyedBy: CodingKeys.self)
        let kind: String
        switch self {
        case .keep: kind = "keep"
        case .forget: kind = "forget"
        case .existing(let provider):
            kind = "existing"
            try fields.encode(provider, forKey: .provider)
        case .staged(let ticket):
            kind = "staged"
            try fields.encode(ticket, forKey: .ticket)
        }
        try fields.encode(kind, forKey: .kind)
    }
}

public struct SettingsWorkflow: Sendable {
    public enum Failure: Error { case invalidReview, invalidState, invalidChallenge, expired }
    private enum Phase: Sendable {
        case review
        case authenticated(MonotonicTimestamp)
        case validated(MonotonicTimestamp)
        case submitted, canceled
    }
    public let document: SettingsDocument
    private let review: SettingsReview
    private var phase: Phase = .review

    public init(review: SettingsReview, expectedKey: Data, now: MonotonicTimestamp) throws {
        guard Data(base64Encoded: review.id)?.count == 16,
            !review.created.isZero, let age = try? now.duration(since: review.created), age < .seconds(120),
            review.session.count == 16, review.nonce.count == 32, review.nonce.contains(where: { $0 != 0 }),
            review.document.count <= 192 * 1024,
            Data(SHA256.hash(data: review.document)) == review.digest,
            review.approvalKey == expectedKey, expectedKey.count == 65, expectedKey.first == 4,
            let document = try? JSONDecoder().decode(SettingsDocument.self, from: review.document),
            document.version == "quartermaster.settings-review.v1",
            document.previous.version == 1, document.proposed.version == 1,
            document.previous.profile == "development", document.proposed.profile == "development",
            Data(document.previous.publicKey) == expectedKey, Data(document.proposed.publicKey) == expectedKey,
            document.previous.revision == review.revision, review.revision < UInt64.max,
            document.proposed.revision == review.revision + 1, document.proposed.settings != nil
        else { throw Failure.invalidReview }
        self.document = document
        self.review = review
    }

    public mutating func recordAuthentication(at authenticated: MonotonicTimestamp, now: MonotonicTimestamp) throws {
        guard case .review = phase else { throw Failure.invalidState }
        guard let pending = try? authenticated.duration(since: review.created), pending < .seconds(120),
            let age = try? now.duration(since: authenticated), age < .seconds(30)
        else { throw Failure.expired }
        phase = .authenticated(authenticated)
    }

    public mutating func validate(_ challenge: SettingsChallenge, now: MonotonicTimestamp) throws -> Data {
        guard case .authenticated(let authenticated) = phase else { throw Failure.invalidState }
        try deadline(authenticated, now: now)
        var revision = review.revision.bigEndian
        var timestamp = authenticated.serializedNanoseconds.bigEndian
        var expected = Data("quartermaster.settings-approval.v1\0".utf8) + review.session + review.nonce
        withUnsafeBytes(of: &revision) { expected.append(contentsOf: $0) }
        expected.append(review.digest)
        withUnsafeBytes(of: &timestamp) { expected.append(contentsOf: $0) }
        guard challenge.review == review, challenge.authenticated == authenticated,
            challenge.expires == (try authenticated.advanced(by: .seconds(30))), challenge.bytes == expected
        else { throw Failure.invalidChallenge }
        phase = .validated(authenticated)
        return challenge.bytes
    }

    public mutating func checkSubmission(now: MonotonicTimestamp) throws {
        guard case .validated(let authenticated) = phase else { throw Failure.invalidState }
        try deadline(authenticated, now: now)
        phase = .submitted
    }

    public mutating func cancel() { phase = .canceled }

    private func deadline(_ authenticated: MonotonicTimestamp, now: MonotonicTimestamp) throws {
        guard let age = try? now.duration(since: authenticated), age < .seconds(30) else { throw Failure.expired }
    }
}
