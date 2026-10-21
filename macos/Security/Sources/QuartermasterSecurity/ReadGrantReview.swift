import Foundation

public struct ReadGrantReview: Sendable {
    public enum Failure: Error { case invalidGrant }
    public let repository: String
    public enum Destination: Sendable {
        case simulation
        case github(repositoryID: UInt64)
    }
    public let destination: Destination
    public var repositoryID: UInt64? {
        if case .github(let id) = destination { return id }
        return nil
    }
    public var isSimulation: Bool { repositoryID == nil }
    public var principalScope: String {
        "All instances of this executable running as your macOS user share this request budget."
    }
    public let budget: UInt32
    public let expires: Date

    private struct Authorization: Decodable {
        let purpose: String
        let grant: Rule
    }

    private struct Rule: Decodable {
        let id: String
        let uid: UInt32
        let codeHash: String
        let action: String
        let repository: String
        let role: String
        let expiresUnix: Int64
        let budget: UInt32
    }

    private struct Request: Decodable {
        enum Origin: String, Decodable {
            case simulation = "https://github.example.invalid"
            case github = "https://api.github.com"
        }
        struct Peer: Decodable { let cdHash: String }
        let method: String
        let path: String
        let body: String
        let origin: Origin
        let repository: String
        let repositoryId: UInt64?
        let issue: UInt64?
        let peer: Peer
        let authorization: Authorization
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
        switch request.origin {
        case .simulation:
            guard request.repositoryId == nil, request.repository == "quartermaster/demo",
                  request.issue == 42, request.path == "/api/v3/repos/quartermaster/demo/issues/42" else {
                throw Failure.invalidGrant
            }
            destination = .simulation
        case .github:
            guard let id = request.repositoryId, id > 0 else { throw Failure.invalidGrant }
            let path = String(request.path.split(separator: "?", maxSplits: 1)[0])
            let prefixes = ["/repos/\(request.repository)/issues", "/repositories/\(id)/issues"]
            guard prefixes.contains(where: { prefix in
                if path == prefix { return true }
                guard path.hasPrefix(prefix + "/") else { return false }
                let number = path.dropFirst(prefix.count + 1)
                return !number.isEmpty && number.utf8.allSatisfy({ (48...57).contains($0) }) && (UInt64(number) ?? 0) > 0
            }) else { throw Failure.invalidGrant }
            destination = .github(repositoryID: id)
        }
        let hex = { (text: String) in text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
        guard authorization.purpose == "quartermaster.issue-read-grant.v1", grant.action == "issueReads",
              grant.id.count == 32, hex(grant.id), grant.uid == uid,
              [40, 64].contains(grant.codeHash.count), hex(grant.codeHash), grant.codeHash == request.peer.cdHash,
              grant.repository == request.repository,
              grant.role == role, ["github-read", "github-write"].contains(role),
              grant.budget > 0, grant.budget <= 100, expires > now, expires.timeIntervalSince(now) <= 3601,
              request.method == "GET", request.body.isEmpty else {
            throw Failure.invalidGrant
        }
        repository = request.repository
        budget = grant.budget
        self.expires = expires
    }
}
