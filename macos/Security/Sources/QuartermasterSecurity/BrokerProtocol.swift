import Dispatch
import Foundation

private let maximumBrokerPayload = 16384

public enum BrokerProtocolFailure: Error { case oversizedPayload }

public enum BrokerCommand: Encodable, Sendable {
    case hello
    case enroll(publicKey: Data)
    case next
    case presence(id: String, authenticated: MonotonicTimestamp)
    case proof(id: String, signature: Data)
    case cancel(id: String)
    case vaultStatus
    case vaultLogin(server: String, email: String, password: String, itemID: String?)
    case vaultLock
    case vaultUnlock
    case vaultSync
    case vaultDiscard
    case revokeReadGrants

    public var timeout: DispatchTimeInterval {
        switch self {
        case .presence: .seconds(30)
        case .vaultLogin, .vaultLock, .vaultUnlock, .vaultSync, .vaultDiscard: .seconds(120)
        case .hello, .enroll, .next, .proof, .cancel, .vaultStatus, .revokeReadGrants: .seconds(5)
        }
    }

    public func encoded() throws -> Data {
        let bytes = try JSONEncoder().encode(self)
        guard bytes.count <= maximumBrokerPayload else { throw BrokerProtocolFailure.oversizedPayload }
        return bytes
    }

    private enum CodingKeys: String, CodingKey {
        case kind, id, publicKey, authenticated, signature, server, email, password, itemId
    }

    public func encode(to encoder: any Encoder) throws {
        var fields = encoder.container(keyedBy: CodingKeys.self)
        let kind: String
        switch self {
        case .hello: kind = "hello"
        case .enroll(let key):
            kind = "enroll"
            try fields.encode(key, forKey: .publicKey)
        case .next: kind = "next"
        case .presence(let id, let authenticated):
            kind = "presence"
            try fields.encode(id, forKey: .id)
            try fields.encode(authenticated, forKey: .authenticated)
        case .proof(let id, let signature):
            kind = "proof"
            try fields.encode(id, forKey: .id)
            try fields.encode(signature, forKey: .signature)
        case .cancel(let id):
            kind = "cancel"
            try fields.encode(id, forKey: .id)
        case .vaultStatus: kind = "vaultStatus"
        case .vaultLogin(let server, let email, let password, let itemID):
            kind = "vaultLogin"
            try fields.encode(server, forKey: .server)
            try fields.encode(email, forKey: .email)
            try fields.encode(password, forKey: .password)
            try fields.encodeIfPresent(itemID, forKey: .itemId)
        case .vaultLock: kind = "vaultLock"
        case .vaultUnlock: kind = "vaultUnlock"
        case .vaultSync: kind = "vaultSync"
        case .vaultDiscard: kind = "vaultDiscard"
        case .revokeReadGrants: kind = "revokeReadGrants"
        }
        try fields.encode(kind, forKey: .kind)
    }
}

public enum BrokerControlError: String, Codable, Error, Sendable {
    case invalidMessage, denied, expired, busy, providerChanged, sessionEnded, unavailable
}

public struct VaultBinding: Decodable, Equatable, Sendable {
    public let server: String
    public let email: String
    public let accountID: String
    public let itemID: String
    public let field: String
    public let role: String

    private enum CodingKeys: String, CodingKey {
        case server, email, field, role
        case accountID = "account_id"
        case itemID = "item_id"
    }
}

public struct BrokerVaultStatus: Decodable, Sendable {
    public enum State: String, Decodable, Sendable {
        case unenrolled
        case incompleteEnrollment = "incomplete_enrollment"
        case locked
        case onlineUnlocked = "online_unlocked"
        case busy
        case reauthRequired = "reauth_required"
        case incompatibleCache = "incompatible_cache"
        case keyInvalidated = "key_invalidated"
        case keychainIssue = "keychain_issue"
        case serverUnavailable = "server_unavailable"
        case ambiguousItem = "ambiguous_item"
        case itemNotFound = "item_not_found"
    }

    public enum Observation: String, Decodable, Sendable {
        case persistedCache = "persisted_cache"
    }

    public let state: State
    public let binding: VaultBinding?
    public let lastSync: Date?
    public let error: String?
    public let observation: Observation?
}

public enum BrokerReply: Decodable, Sendable {
    case hello(profile: String)
    case enrolled
    case idle
    case review(ApprovalReview)
    case challenge(ApprovalChallenge)
    case accepted
    case canceled
    case alreadyAdmitted
    case unknownOperation
    case readGrantsRevoked
    case error(BrokerControlError)
    case vaultStatus(BrokerVaultStatus)

    public static func decodeSuccess(_ bytes: Data) throws -> Self {
        guard bytes.count <= maximumBrokerPayload else { throw BrokerProtocolFailure.oversizedPayload }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let reply = try decoder.decode(Self.self, from: bytes)
        if case .error(let error) = reply { throw error }
        return reply
    }

    private enum Kind: String, Decodable {
        case hello, enrolled, idle, review, challenge, accepted, canceled
        case alreadyAdmitted, unknownOperation, readGrantsRevoked, error, vaultStatus
    }

    private enum CodingKeys: String, CodingKey {
        case kind, profile, approval, authorization, code
    }

    public init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        switch try fields.decode(Kind.self, forKey: .kind) {
        case .hello: self = .hello(profile: try fields.decode(String.self, forKey: .profile))
        case .enrolled: self = .enrolled
        case .idle: self = .idle
        case .review: self = .review(try fields.decode(ApprovalReview.self, forKey: .approval))
        case .challenge: self = .challenge(try fields.decode(ApprovalChallenge.self, forKey: .authorization))
        case .accepted: self = .accepted
        case .canceled: self = .canceled
        case .alreadyAdmitted: self = .alreadyAdmitted
        case .unknownOperation: self = .unknownOperation
        case .readGrantsRevoked: self = .readGrantsRevoked
        case .error: self = .error(try fields.decode(BrokerControlError.self, forKey: .code))
        case .vaultStatus: self = .vaultStatus(try BrokerVaultStatus(from: decoder))
        }
    }
}
