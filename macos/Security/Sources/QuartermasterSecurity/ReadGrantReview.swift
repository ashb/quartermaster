import Foundation

public struct ReadGrantReview: Sendable {
    public enum Failure: Error { case invalidGrant }
    public let repository: String
    public let repositoryID: UInt64
    public let expires: Date
    public let root: ReadRootChoice

    private struct Authorization: Decodable {
        let purpose: String
        let grant: Rule
    }

    private struct Rule: Decodable {
        let id: String
        let uid: UInt32
        let codeHash: String
        let effects: ReadEffectSet
        let root: ReadRootChoice
        let repository: String
        let role: String
        let expiresUnix: Int64
    }

    private struct Request: Decodable {
        struct Peer: Decodable { let cdHash: String }
        let method: String
        let path: String
        let body: String
        let origin: String
        let repository: String
        let repositoryId: UInt64
        let peer: Peer
        let authorization: Authorization
        let readRoots: [ReadRootChoice]
    }

    public static func parse(request: Data, role: String, uid: UInt32, now: Date) throws -> Self? {
        struct Presence: Decodable {
            struct Purpose: Decodable { let purpose: String }
            let authorization: Purpose?
        }
        guard try JSONDecoder().decode(Presence.self, from: request).authorization != nil else { return nil }
        return try Self(request: request, role: role, uid: uid, now: now)
    }

    public init(request: Data, role: String, uid: UInt32, now: Date) throws {
        guard let request = try? JSONDecoder().decode(Request.self, from: request) else { throw Failure.invalidGrant }
        let authorization = request.authorization
        let grant = authorization.grant
        let expires = Date(timeIntervalSince1970: TimeInterval(grant.expiresUnix))
        let path = String(request.path.split(separator: "?", maxSplits: 1)[0])
        let prefixes = ["/repos/\(request.repository)/issues", "/repositories/\(request.repositoryId)/issues"]
        guard request.origin == "https://api.github.com", request.repositoryId > 0,
            prefixes.contains(where: { prefix in
                if path == prefix { return true }
                guard path.hasPrefix(prefix + "/") else { return false }
                let number = path.dropFirst(prefix.count + 1)
                return !number.isEmpty && number.utf8.allSatisfy({ (48...57).contains($0) })
                    && (UInt64(number) ?? 0) > 0
            })
        else { throw Failure.invalidGrant }
        let hex = { (text: String) in text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
        guard authorization.purpose == "quartermaster.read-grant.v2", grant.effects.version == 1,
            grant.effects.effects == ["listIssues", "readIssue"], grant.root.valid,
            request.readRoots.contains(grant.root),
            grant.id.count == 32, hex(grant.id), grant.uid == uid,
            [40, 64].contains(grant.codeHash.count), hex(grant.codeHash), grant.codeHash == request.peer.cdHash,
            grant.repository == request.repository,
            grant.role == role, ["github-read", "github-write"].contains(role),
            expires > now, expires.timeIntervalSince(now) <= 3601,
            request.method == "GET", request.body.isEmpty
        else {
            throw Failure.invalidGrant
        }
        repository = request.repository
        repositoryID = request.repositoryId
        self.expires = expires
        root = grant.root
    }
}

public struct ReadRootChoice: Codable, Equatable, Sendable, Identifiable {
    public let id: String
    public let pid: UInt32
    public let executable: String

    var valid: Bool {
        let parts = id.split(separator: ":")
        return pid > 1 && parts.count == 3 && parts[0] == String(pid)
            && parts[1].count == 16 && parts[2].count == 8
            && parts.dropFirst().allSatisfy { $0.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
            && executable.hasPrefix("/") && executable.utf8.count <= 4096
            && !executable.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }
}

private struct ReadEffectSet: Decodable, Sendable {
    let version: UInt8
    let effects: [String]
}

public struct ReadScopeReview: Sendable {
    public let roots: [ReadRootChoice]

    public static func parse(request: Data) throws -> Self? {
        struct Request: Decodable {
            let method: String
            let body: String?
            let path: String
            let origin: String
            let repository: String?
            let repositoryId: UInt64?
            let readRoots: [ReadRootChoice]?
        }
        let value = try JSONDecoder().decode(Request.self, from: request)
        guard let roots = value.readRoots else { return nil }
        let path = String(value.path.split(separator: "?", maxSplits: 1)[0])
        let prefixes = ["/repos/\(value.repository ?? "")/issues", "/repositories/\(value.repositoryId ?? 0)/issues"]
        let issueRead =
            value.origin == "https://api.github.com" && value.method == "GET" && value.body == ""
            && (value.repositoryId ?? 0) > 0 && RepositoryName(fullName: value.repository ?? "") != nil
            && prefixes.contains { prefix in
                if path == prefix { return true }
                guard path.hasPrefix(prefix + "/") else { return false }
                let number = path.dropFirst(prefix.count + 1)
                return !number.isEmpty && number.utf8.allSatisfy({ (48...57).contains($0) })
                    && (UInt64(number) ?? 0) > 0
            }
        guard issueRead else {
            guard roots.isEmpty else { throw ReadGrantReview.Failure.invalidGrant }
            return nil
        }
        guard roots.count <= 32, roots.allSatisfy(\.valid), Set(roots.map(\.id)).count == roots.count else {
            throw ReadGrantReview.Failure.invalidGrant
        }
        return Self(roots: roots)
    }
}

public struct ActiveReadGrant: Decodable, Sendable, Identifiable {
    private struct Rule: Decodable, Sendable {
        let id: String
        let repository: String
        let root: ReadRootChoice
        let effects: ReadEffectSet
        let expiresUnix: Int64
    }
    private let purpose: String
    private let grant: Rule
    public var id: String { grant.id }
    public var repository: String { grant.repository }
    public var root: ReadRootChoice { grant.root }
    public var expires: Date { Date(timeIntervalSince1970: TimeInterval(grant.expiresUnix)) }
    public var valid: Bool {
        purpose == "quartermaster.read-grant.v2" && grant.root.valid && grant.effects.version == 1
            && grant.effects.effects == ["listIssues", "readIssue"]
            && id.count == 32 && id.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
            && RepositoryName(fullName: repository) != nil
    }
}
