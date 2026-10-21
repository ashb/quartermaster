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
                "repository": "example/one", "role": "github-write", "expiresUnix": 4600, "budget": 100,
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
    #expect(grant.budget == 100)
    #expect(grant.expires == Date(timeIntervalSince1970: 4600))
    #expect(
        grant.principalScope == "All instances of this executable running as your macOS user share this request budget."
    )
    #expect(!grant.isSimulation)
}

@Test func simulationReadGrantHasAnExplicitlySeparateDestination() throws {
    let url = try #require(
        Bundle.module.url(forResource: "simulation-read-grant", withExtension: "json", subdirectory: "Fixtures"))
    let bytes = try Data(contentsOf: url)
    let grant = try ReadGrantReview(
        request: bytes, role: "github-write", uid: 501, now: Date(timeIntervalSince1970: 1000))
    #expect(grant.isSimulation)
    #expect(grant.repositoryID == nil)
}

@Test(arguments: ["repository", "path", "issue", "repositoryId"])
func simulationGrantRejectsAnythingOutsideTheFixedDummyRead(_ field: String) throws {
    let bytes = try grantRequest { request in
        request["origin"] = "https://github.example.invalid"
        request["repository"] = "quartermaster/demo"
        request["path"] = "/api/v3/repos/quartermaster/demo/issues/42"
        request["issue"] = 42
        request["repositoryId"] = nil
        var authorization = request["authorization"] as! [String: Any]
        var grant = authorization["grant"] as! [String: Any]
        grant["repository"] = "quartermaster/demo"
        if field == "repository" {
            request[field] = "example/one"
            grant[field] = "example/one"
        } else if field == "path" {
            request[field] = "/repos/quartermaster/demo/issues/42"
        } else if field == "issue" {
            request[field] = 43
        } else {
            request[field] = 123
        }
        authorization["grant"] = grant
        request["authorization"] = authorization
    }
    #expect(throws: ReadGrantReview.Failure.self) {
        try ReadGrantReview(request: bytes, role: "github-write", uid: 501, now: Date(timeIntervalSince1970: 1000))
    }
}

@Test(arguments: [
    "purpose", "action", "repository", "role", "codeHash", "uid", "budget", "expiresUnix", "method", "origin", "path",
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
        case "budget": grant[field] = 100000
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
