import Foundation
import Testing

@testable import QuartermasterSecurity

private func grantRequest(changing change: (inout [String: Any]) -> Void = { _ in }) throws -> Data {
    var request: [String: Any] = [
        "method": "GET", "path": "/repos/example/one/issues", "body": "",
        "repository": "example/one", "repositoryId": 123, "origin": "https://api.github.com",
        "readRoots": [["id": "123:0000000000000001:00000001", "pid": 123, "executable": "/bin/zsh"]],
        "peer": ["cdHash": String(repeating: "1", count: 40)],
        "authorization": [
            "purpose": "quartermaster.read-grant.v2",
            "grant": [
                "id": String(repeating: "a", count: 32), "uid": 501,
                "codeHash": String(repeating: "1", count: 40),
                "effects": ["version": 1, "effects": ["listIssues", "readIssue"]],
                "root": ["id": "123:0000000000000001:00000001", "pid": 123, "executable": "/bin/zsh"],
                "repository": "example/one", "role": "github-write", "expiresUnix": 4600,
            ],
        ],
    ]
    change(&request)
    return try JSONSerialization.data(withJSONObject: request)
}

@Test func readGrantReviewDescribesTheCompletePermission() throws {
    let grant = try ReadGrantReview(
        request: grantRequest(), role: "github-write", uid: 501, now: Date(timeIntervalSince1970: 1000))
    #expect(grant.repository == "example/one")
    #expect(grant.repositoryID == 123)
    #expect(grant.expires == Date(timeIntervalSince1970: 4600))
}

@Test func readGrantReviewRejectsTheRetiredSimulationDestination() throws {
    let url = try #require(
        Bundle.module.url(forResource: "simulation-read-grant", withExtension: "json", subdirectory: "Fixtures"))
    let bytes = try Data(contentsOf: url)
    #expect(throws: ReadGrantReview.Failure.self) {
        try ReadGrantReview(request: bytes, role: "github-write", uid: 501, now: Date(timeIntervalSince1970: 1000))
    }
}

@Test(arguments: [
    "purpose", "effects", "root", "readRoots", "repository", "role", "codeHash", "uid", "expiresUnix", "method",
    "origin", "path",
    "repositoryId",
])
func readGrantReviewRejectsMisrepresentedOrUnboundedPermissions(_ field: String) throws {
    let bytes = try grantRequest { request in
        var authorization = request["authorization"] as! [String: Any]
        var grant = authorization["grant"] as! [String: Any]
        switch field {
        case "purpose": authorization[field] = "approve-write"
        case "effects": grant[field] = ["version": 1, "effects": ["closeIssue"]]
        case "root": grant[field] = ["id": "999:0000000000000001:00000001", "pid": 999, "executable": "/bin/zsh"]
        case "readRoots": request[field] = []
        case "repository": grant[field] = "example/two"
        case "role": grant[field] = "github-read"
        case "codeHash": grant[field] = String(repeating: "2", count: 40)
        case "uid": grant[field] = 502
        case "expiresUnix": grant[field] = 100000
        case "method": request[field] = "PATCH"
        case "origin": request[field] = "https://elsewhere.invalid"
        case "path": request[field] = "/user"
        case "repositoryId": request[field] = 0
        default: break
        }
        authorization["grant"] = grant
        request["authorization"] = authorization
    }
    #expect(throws: ReadGrantReview.Failure.self) {
        try ReadGrantReview(request: bytes, role: "github-write", uid: 501, now: Date(timeIntervalSince1970: 1000))
    }
}

@Test func requestOnceRetainsValidatedRootChoices() throws {
    let bytes = try grantRequest { $0.removeValue(forKey: "authorization") }
    #expect(
        try ReadGrantReview.parse(
            request: bytes, role: "github-write", uid: 501, now: Date(timeIntervalSince1970: 1000)) == nil)
    let scope = try #require(try ReadScopeReview.parse(request: bytes))
    #expect(scope.roots.count == 1)
    #expect(scope.roots[0].pid == 123)
}

@Test(arguments: ["oldVersion", "unknownEffect", "duplicateEffect", "unknownRoot", "duplicateRoot", "malformedRoot"])
func rootClaimsRejectIncompatibleOrAmbiguousScope(_ change: String) throws {
    let bytes = try grantRequest { request in
        var authorization = request["authorization"] as! [String: Any]
        var grant = authorization["grant"] as! [String: Any]
        switch change {
        case "oldVersion": authorization["purpose"] = "quartermaster.issue-read-grant.v1"
        case "unknownEffect":
            grant["effects"] = ["version": 1, "effects": ["listIssues", "readIssue", "readPullRequest"]]
        case "duplicateEffect": grant["effects"] = ["version": 1, "effects": ["readIssue", "readIssue"]]
        case "unknownRoot": request["readRoots"] = []
        case "duplicateRoot": request["readRoots"] = [grant["root"]!, grant["root"]!]
        case "malformedRoot": request["readRoots"] = [["id": "123", "pid": 123, "executable": "/bin/zsh"]]
        default: break
        }
        authorization["grant"] = grant
        request["authorization"] = authorization
    }
    #expect(throws: (any Error).self) {
        _ = try ReadScopeReview.parse(request: bytes)
        _ = try ReadGrantReview(request: bytes, role: "github-write", uid: 501, now: Date(timeIntervalSince1970: 1000))
    }
}
