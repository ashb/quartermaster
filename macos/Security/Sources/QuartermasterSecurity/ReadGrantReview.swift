import Foundation

public struct ApprovalDisplay: Decodable, Sendable {
    public let intent: GitHubApprovalIntent
    public let repository: String?
    public let resourceTitle: String?
    public let additionalEffects: [GitHubEffect]
    public let understandingNotice: UnderstandingNotice?
    public let allowsReadScope: Bool

    public var grant: ReadGrantReview? {
        if case .readGrant(let grant) = intent { return grant }
        return nil
    }

    public static func parse(request: Data) throws -> Self {
        struct Envelope: Decodable { let presentation: ApprovalDisplay }
        return try JSONDecoder().decode(Envelope.self, from: request).presentation
    }
}

public enum GitHubApprovalIntent: Decodable, Sendable {
    case request
    case issue(action: GitHubEffect, number: UInt64?)
    case readGrant(ReadGrantReview)

    private enum Kind: String, Decodable { case request, issue, readGrant }
    private enum CodingKeys: String, CodingKey { case kind, action, number, grant }

    public init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        switch try fields.decode(Kind.self, forKey: .kind) {
        case .request: self = .request
        case .issue:
            self = .issue(
                action: try fields.decode(GitHubEffect.self, forKey: .action),
                number: try fields.decodeIfPresent(UInt64.self, forKey: .number))
        case .readGrant:
            self = .readGrant(try fields.decode(ReadGrantReview.self, forKey: .grant))
        }
    }
}

public enum UnderstandingNotice: String, Decodable, Sendable {
    case incompleteRequest
}

public struct ReadGrantReview: Decodable, Sendable, Identifiable {
    public let id: String
    public let repository: String
    public let root: ReadRootChoice
    public let permission: ReadPermission
    private let expiresUnix: Int64
    public var expires: Date { Date(timeIntervalSince1970: TimeInterval(expiresUnix)) }
}

public enum ReadPermission: Decodable, Sendable {
    case issueReads

    private enum Kind: String, Decodable { case issueReads }
    private enum CodingKeys: String, CodingKey { case kind, categories }

    public init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        switch try fields.decode(Kind.self, forKey: .kind) {
        case .issueReads: self = .issueReads

        }
    }
}

public struct ReadRootChoice: Codable, Equatable, Sendable, Identifiable {
    public let id: String
    public let pid: UInt32
    public let executable: String
}

public struct ReadScopeReview: Sendable {
    public let roots: [ReadRootChoice]

    public static func parse(request: Data) throws -> Self? {
        struct Envelope: Decodable {
            let presentation: ApprovalDisplay
            let readRoots: [ReadRootChoice]
        }
        let value = try JSONDecoder().decode(Envelope.self, from: request)
        return value.presentation.allowsReadScope ? Self(roots: value.readRoots) : nil
    }
}

public typealias ActiveReadGrant = ReadGrantReview

public enum GitHubEffect: String, Decodable, Sendable {
    case readRepository
    case listIssues
    case readIssue
    case closeIssue
    case deleteIssue
    case deleteRepository
}
