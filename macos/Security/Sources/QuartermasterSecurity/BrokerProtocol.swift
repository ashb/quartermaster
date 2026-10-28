import Dispatch
import Foundation

private let maximumBrokerPayload = BrokerLimits.payloadBytes

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
    case settingsRegister(publicKey: Data)
    case settingsStatus
    case prepareSettingsImport(id: String)
    case prepareSettingsDiscard(id: String)
    case stageEnrollment(server: String, email: String, password: String, itemID: String?)
    case prepareSettings(
        revision: UInt64, settings: BrokerSettings, provider: SettingsProviderChoice, additions: [RepositoryName] = [])
    case settingsPresence(id: String, authenticated: MonotonicTimestamp)
    case settingsProof(id: String, signature: Data)
    case settingsCancel(id: String?)

    public var timeout: DispatchTimeInterval {
        switch self {
        case .presence, .settingsPresence, .settingsProof, .settingsRegister, .prepareSettings, .prepareSettingsImport,
            .prepareSettingsDiscard:
            .seconds(30)
        case .vaultLogin, .vaultLock, .vaultUnlock, .vaultSync, .vaultDiscard, .stageEnrollment: .seconds(120)
        case .hello, .enroll, .next, .proof, .cancel, .vaultStatus, .revokeReadGrants: .seconds(5)
        case .settingsStatus, .settingsCancel: .seconds(5)
        }
    }

    public func encoded() throws -> Data {
        let bytes = try JSONEncoder().encode(self)
        guard bytes.count <= maximumBrokerPayload else { throw BrokerProtocolFailure.oversizedPayload }
        return bytes
    }

    private enum CodingKeys: String, CodingKey {
        case kind, id, publicKey, authenticated, signature, server, email, password, itemId, revision, settings,
            provider, additions
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
        case .settingsRegister(let key):
            kind = "settingsRegister"
            try fields.encode(key, forKey: .publicKey)
        case .settingsStatus: kind = "settingsStatus"
        case .prepareSettingsImport(let id):
            kind = "prepareSettingsImport"
            try fields.encode(id, forKey: .id)
        case .prepareSettingsDiscard(let id):
            kind = "prepareSettingsDiscard"
            try fields.encode(id, forKey: .id)
        case .stageEnrollment(let server, let email, let password, let itemID):
            kind = "stageEnrollment"
            try fields.encode(server, forKey: .server)
            try fields.encode(email, forKey: .email)
            try fields.encode(password, forKey: .password)
            try fields.encodeIfPresent(itemID, forKey: .itemId)
        case .prepareSettings(let revision, let settings, let provider, let additions):
            kind = "prepareSettings"
            try fields.encode(revision, forKey: .revision)
            try fields.encode(settings, forKey: .settings)
            try fields.encode(provider, forKey: .provider)
            if !additions.isEmpty { try fields.encode(additions, forKey: .additions) }
        case .settingsPresence(let id, let authenticated):
            kind = "settingsPresence"
            try fields.encode(id, forKey: .id)
            try fields.encode(authenticated, forKey: .authenticated)
        case .settingsProof(let id, let signature):
            kind = "settingsProof"
            try fields.encode(id, forKey: .id)
            try fields.encode(signature, forKey: .signature)
        case .settingsCancel(let id):
            kind = "settingsCancel"
            try fields.encodeIfPresent(id, forKey: .id)
        }
        try fields.encode(kind, forKey: .kind)
    }
}

public enum BrokerControlError: String, Codable, Error, Sendable {
    case invalidMessage, denied, expired, busy, providerChanged, sessionEnded, unavailable
}

public struct VaultBinding: Codable, Equatable, Sendable {
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
        case settingsImportRequired = "settings_import_required"
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
    case settingsStatus(SettingsSnapshot)
    case settingsReview(SettingsReview)
    case settingsChallenge(SettingsChallenge)
    case enrollmentStaged(ticket: String, provider: SettingsProvider)
    case settingsApplied(revision: UInt64)

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
        case settingsStatus, settingsReview, settingsChallenge, enrollmentStaged, settingsApplied
    }

    private enum CodingKeys: String, CodingKey {
        case kind, profile, approval, authorization, code, settings, review, ticket, provider, revision
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
        case .settingsStatus: self = .settingsStatus(try fields.decode(SettingsSnapshot.self, forKey: .settings))
        case .settingsReview: self = .settingsReview(try fields.decode(SettingsReview.self, forKey: .review))
        case .settingsChallenge:
            self = .settingsChallenge(try fields.decode(SettingsChallenge.self, forKey: .authorization))
        case .enrollmentStaged:
            self = .enrollmentStaged(
                ticket: try fields.decode(String.self, forKey: .ticket),
                provider: try fields.decode(SettingsProvider.self, forKey: .provider))
        case .settingsApplied: self = .settingsApplied(revision: try fields.decode(UInt64.self, forKey: .revision))
        }
    }
}
