import Foundation
import Testing

@testable import QuartermasterSecurity

private func grantRequest(changing change: (inout [String: Any]) -> Void = { _ in }) throws -> Data {
    var request: [String: Any] = [
        "method": "GET", "path": "/repos/example/one/issues", "body": "",
        "repository": "example/one", "repositoryId": 123, "origin": "https://api.github.com",
        "peer": ["cdHash": String(repeating: "1", count: 40)],
        "authorization": [
            "purpose": "quartermaster.issue-read-grant.v1",
            "grant": [
                "id": String(repeating: "a", count: 32), "uid": 501,
                "codeHash": String(repeating: "1", count: 40), "action": "issueReads",
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
    "purpose", "action", "repository", "role", "codeHash", "uid", "expiresUnix", "method", "origin", "path",
    "repositoryId",
])
func readGrantReviewRejectsMisrepresentedOrUnboundedPermissions(_ field: String) throws {
    let bytes = try grantRequest { request in
        var authorization = request["authorization"] as! [String: Any]
        var grant = authorization["grant"] as! [String: Any]
        switch field {
        case "purpose": authorization[field] = "approve-write"
        case "action": grant[field] = "closeIssue"
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
