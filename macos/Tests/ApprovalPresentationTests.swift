import Foundation
import QuartermasterSecurity
import Testing

@testable import QuartermasterApprovalUI

private func approvalPresentation(
    complete: Bool = true, effects: [String] = ["Close issue"], repository: String? = "quartermaster/one",
    ancestryComplete: Bool? = nil, ancestryNote: String? = nil
) throws -> ApprovalPresentation {
    let path = "/repos/quartermaster/one/issues/42"
    var application: [String: Any] = [
        "version": "quartermaster.github-request.v1", "complete": complete, "effects": effects,
        "originalDigest": Data(repeating: 1, count: 32).base64EncodedString(),
        "request": Data("PATCH \(path) HTTP/1.1\r\nHost: api.github.com\r\n\r\n{\"state\":\"closed\"}".utf8)
            .base64EncodedString(),
    ]
    if complete, let repository { application["requestedRepository"] = repository }
    var payload: [String: Any] = [
        "repository": "", "issue": 42, "method": "PATCH", "path": path, "origin": "https://api.github.com",
        "processChain": ["codex", "gh"], "application": application,
    ]
    if let ancestryComplete {
        var peer: [String: Any] = [
            "pid": 30, "executable": "/bin/gh", "signingIdentifier": "gh", "cdHash": "dummy",
            "adHoc": false, "ancestryComplete": ancestryComplete,
        ]
        if let ancestryNote { peer["ancestryNote"] = ancestryNote }
        payload["peer"] = peer
    }
    let bytes = try JSONSerialization.data(withJSONObject: payload)
    let request = try JSONDecoder().decode(DialogRequest.self, from: bytes)
    let provider = try JSONDecoder().decode(
        ApprovalProviderIdentity.self,
        from: Data(
            #"{"server":"https://vault.example.invalid","account":"dummy","email":"dummy@example.invalid","item":"dummy","field":"LoginPassword","role":"github-write","enrollment":"disposable","generation":1}"#
                .utf8))
    return ApprovalPresentation(
        request: request, provider: provider, readGrant: nil, apiRequest: try APIRequestReview.parse(request: bytes))
}

@Test func aRecognisedCloseShowsItsNamedRepositoryAndDoesNotRepeatTheTitleAsAnEffect() throws {
    let presentation = try approvalPresentation()
    #expect(presentation.operationTitle == "Close issue #42")
    #expect(presentation.repository == "quartermaster/one")
    #expect(presentation.additionalEffects.isEmpty)
}

@Test(arguments: [true, false]) func extraActionsRemainVisibleAndCannotHideBehindACloseTitle(_ complete: Bool) throws {
    let presentation = try approvalPresentation(complete: complete, effects: ["Close issue", "Delete repository"])
    #expect(presentation.operationTitle == "Approve GitHub request")
    #expect(presentation.additionalEffects == ["Close issue", "Delete repository"])
}

@Test func unfamiliarRequestsRetainKnownActionsWithoutPretendingToBeASimpleClose() throws {
    let presentation = try approvalPresentation(complete: false, repository: nil)
    #expect(presentation.operationTitle == "Approve GitHub request")
    #expect(presentation.repository == nil)
    #expect(presentation.additionalEffects == ["Close issue"])
    #expect(presentation.apiRequest?.complete == false)
}

@Test func incompleteAncestryShowsTheBackendsExplanation() throws {
    let presentation = try approvalPresentation(
        ancestryComplete: false,
        ancestryNote: "Earlier ancestors unavailable: macOS denied access to process information.")
    #expect(
        presentation.ancestryNotice
            == "Earlier ancestors unavailable: macOS denied access to process information.")
}

@Test func incompleteAncestryWithoutAnExplanationStillShowsTheGap() throws {
    let presentation = try approvalPresentation(ancestryComplete: false)
    #expect(presentation.ancestryNotice == "Earlier ancestors could not be inspected.")
}

@Test func completeAncestryDoesNotShowAGap() throws {
    let presentation = try approvalPresentation(ancestryComplete: true)
    #expect(presentation.ancestryNotice == nil)
}
