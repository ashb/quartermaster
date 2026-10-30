import Foundation
import Testing

@testable import QuartermasterSecurity

private func displayRequest(allowsReadScope: Bool = true) throws -> Data {
    try JSONSerialization.data(withJSONObject: [
        "method": "POST", "path": "/unfamiliar",
        "readRoots": [["id": "backend-root", "pid": 123, "executable": "/bin/zsh"]],
        "presentation": [
            "intent": [
                "kind": "readGrant",
                "grant": [
                    "id": "backend-grant", "repository": "example/project",
                    "root": ["id": "backend-root", "pid": 123, "executable": "/bin/zsh"],
                    "expiresUnix": 4600, "permission": ["kind": "issueReads"],
                ],
            ],
            "repository": "example/project", "additionalEffects": ["closeIssue"],
            "understandingNotice": "incompleteRequest", "allowsReadScope": allowsReadScope,
        ],
    ])
}

@Test func approvalDecodesTypedScopeWithoutReconstructingPermissions() throws {
    let display = try ApprovalDisplay.parse(request: displayRequest())
    #expect(display.repository == "example/project")
    #expect(display.additionalEffects == [.closeIssue])
    #expect(display.understandingNotice == .incompleteRequest)
    let grant = try #require(display.grant)
    guard case .issueReads = grant.permission else {
        Issue.record("Expected issue read permission")
        return
    }
    #expect(grant.expires == Date(timeIntervalSince1970: 4600))
}

@Test(arguments: [true, false])
func scopeAvailabilityUsesTheBackendChoice(_ allowed: Bool) throws {
    let scope = try ReadScopeReview.parse(request: displayRequest(allowsReadScope: allowed))
    #expect((scope != nil) == allowed)
    if allowed { #expect(scope?.roots.first?.id == "backend-root") }
}

@Test func activeGrantDecodesTheTypedScope() throws {
    let request = try #require(JSONSerialization.jsonObject(with: displayRequest()) as? [String: Any])
    let display = try #require(request["presentation"] as? [String: Any])
    let intent = try #require(display["intent"] as? [String: Any])
    let bytes = try JSONSerialization.data(withJSONObject: intent["grant"]!)
    let grant = try JSONDecoder().decode(ActiveReadGrant.self, from: bytes)
    #expect(grant.id == "backend-grant")
    guard case .issueReads = grant.permission else {
        Issue.record("Expected issue read permission")
        return
    }
}

@Test func approvalDecodesTypedIntentWithoutRenderedEnglish() throws {
    let bytes = Data(
        #"{"presentation":{"intent":{"kind":"issue","action":"closeIssue","number":42},"repository":"example/project","additionalEffects":[],"allowsReadScope":false}}"#
            .utf8)
    let display = try ApprovalDisplay.parse(request: bytes)
    #expect(display.repository == "example/project")
    guard case .issue(let action, let number) = display.intent else {
        Issue.record("Expected an issue action")
        return
    }
    #expect(action == .closeIssue)
    #expect(number == 42)
}

@Test(arguments: [
    #"{"kind":"futureIntent"}"#,
    #"{"kind":"issue","action":"futureAction","number":42}"#,
    #"{"kind":"readGrant"}"#,
])
func unknownOrIncompleteIntentFailsDecoding(_ intent: String) {
    let bytes = Data(
        "{\"presentation\":{\"intent\":\(intent),\"additionalEffects\":[],\"allowsReadScope\":false}}".utf8)
    #expect(throws: DecodingError.self) { try ApprovalDisplay.parse(request: bytes) }
}

@Test func missingPresentationFailsDecoding() {
    #expect(throws: DecodingError.self) { try ApprovalDisplay.parse(request: Data("{}".utf8)) }
}

@Test func approvalWireMatchesTheRustPresentationFixture() throws {
    let url = try #require(
        Bundle.module.url(forResource: "approval-presentation", withExtension: "json", subdirectory: "Fixtures"))
    let display = try ApprovalDisplay.parse(request: Data(contentsOf: url))
    guard case .issue(let action, let number) = display.intent else {
        Issue.record("Expected an issue action")
        return
    }
    #expect(action == .closeIssue)
    #expect(number == 42)
    #expect(display.repository == "example/one")
    #expect(display.additionalEffects.isEmpty)
    #expect(display.understandingNotice == nil)
    #expect(!display.allowsReadScope)
}
