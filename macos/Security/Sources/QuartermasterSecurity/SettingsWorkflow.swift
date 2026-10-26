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
    public let migration: SettingsMigration?
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
    public let additions: [RepositoryName]?
    public let migration: SettingsMigrationSource?
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
    case staged(String)

    private enum CodingKeys: String, CodingKey { case kind, ticket }

    public func encode(to encoder: any Encoder) throws {
        var fields = encoder.container(keyedBy: CodingKeys.self)
        let kind: String
        switch self {
        case .keep: kind = "keep"
        case .forget: kind = "forget"
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
        if let migration = document.migration {
            guard migration.supported, document.previous.settings == nil, document.previous.provider == nil,
                document.additions == nil
            else { throw Failure.invalidReview }
        }
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
        let resolved = try resolvedReview(challenge.review, authenticated: authenticated)
        var revision = review.revision.bigEndian
        var timestamp = authenticated.serializedNanoseconds.bigEndian
        var expected = Data("quartermaster.settings-approval.v1\0".utf8) + review.session + review.nonce
        withUnsafeBytes(of: &revision) { expected.append(contentsOf: $0) }
        expected.append(resolved.digest)
        withUnsafeBytes(of: &timestamp) { expected.append(contentsOf: $0) }
        guard challenge.authenticated == authenticated,
            challenge.expires == (try authenticated.advanced(by: .seconds(30))), challenge.bytes == expected
        else { throw Failure.invalidChallenge }
        phase = .validated(authenticated)
        return challenge.bytes
    }

    private func resolvedReview(_ final: SettingsReview, authenticated: MonotonicTimestamp) throws -> SettingsReview {
        guard let additions = document.additions, !additions.isEmpty else {
            guard final == review else { throw Failure.invalidChallenge }
            return final
        }
        guard final.id == review.id, final.created == review.created, final.session == review.session,
            final.nonce == review.nonce, final.revision == review.revision, final.approvalKey == review.approvalKey,
            Set(additions.map(\.id)).count == additions.count,
            additions.allSatisfy({ RepositoryName(fullName: $0.fullName) == $0 })
        else { throw Failure.invalidChallenge }
        let completed = try SettingsWorkflow(review: final, expectedKey: review.approvalKey, now: authenticated)
            .document
        guard completed.additions == nil, let repositories = completed.proposed.settings?.github?.repositories,
            let base = document.proposed.settings?.github?.repositories,
            repositories.count == base.count + additions.count,
            Set(repositories.map(\.id)).count == repositories.count, repositories.allSatisfy({ $0.id > 0 }),
            var expected = try JSONSerialization.jsonObject(with: review.document) as? [String: Any],
            var proposed = expected["proposed"] as? [String: Any],
            var settings = proposed["settings"] as? [String: Any],
            var github = settings["github"] as? [String: Any],
            var encodedRepositories = github["repositories"] as? [[String: Any]]
        else { throw Failure.invalidReview }
        for addition in additions {
            let matches = repositories.filter { "\($0.owner)/\($0.name)".lowercased() == addition.id }
            guard matches.count == 1, let repository = matches.first, !repository.writes,
                RepositoryName(fullName: "\(repository.owner)/\(repository.name)") != nil,
                let encoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(repository)) as? [String: Any]
            else { throw Failure.invalidReview }
            encodedRepositories.append(encoded)
        }
        try encodedRepositories.sort {
            guard let leftOwner = $0["owner"] as? String, let leftName = $0["name"] as? String,
                let rightOwner = $1["owner"] as? String, let rightName = $1["name"] as? String
            else { throw Failure.invalidReview }
            return (leftOwner.lowercased(), leftName.lowercased()) < (rightOwner.lowercased(), rightName.lowercased())
        }
        github["repositories"] = encodedRepositories
        settings["github"] = github
        proposed["settings"] = settings
        expected["proposed"] = proposed
        expected.removeValue(forKey: "additions")
        guard let actual = try JSONSerialization.jsonObject(with: final.document) as? [String: Any],
            NSDictionary(dictionary: expected).isEqual(to: actual)
        else { throw Failure.invalidReview }
        return final
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
