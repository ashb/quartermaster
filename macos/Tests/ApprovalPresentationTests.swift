import AppKit
import Foundation
import LocalAuthentication
import QuartermasterSecurity
import SwiftUI
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
        "processChain": ["codex", "gh"], "application": application, "readRoots": [],
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
        request: request, provider: provider, readGrant: nil, apiRequest: try APIRequestReview.parse(request: bytes),
        readScope: try ReadScopeReview.parse(request: bytes))
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

@MainActor private final class ScopeReviewBackend: ApprovalBackend {
    let reviewCreated = MonotonicTimestamp.now
    func challenge(authenticated: MonotonicTimestamp, context: LAContext) async throws -> Data {
        throw CancellationError()
    }
    func submit(_ signature: Data) async throws { throw CancellationError() }
    func cancel() {}
}

@Test @MainActor func switchingReadScopeKeepsTheApprovalWindowHeight() throws {
    let root: [String: Any] = [
        "id": "123:0000000000000001:00000001", "pid": 123,
        "executable": "/nix/store/example-zsh/bin/zsh",
    ]
    var request: [String: Any] = [
        "repository": "quartermaster/one", "repositoryId": 123,
        "method": "GET", "path": "/repos/quartermaster/one/issues/42", "body": "",
        "origin": "https://api.github.com", "processChain": ["zsh", "gh"],
        "peer": ["cdHash": String(repeating: "1", count: 40)], "readRoots": [root],
    ]
    let provider = try approvalPresentation().provider
    let controller = ApprovalController(backend: ScopeReviewBackend(), reason: "Test scope layout")
    func view(_ bytes: Data) throws -> NSHostingView<ApprovalDialogView> {
        var display = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        display.removeValue(forKey: "peer")
        let presentation = ApprovalPresentation(
            request: try JSONDecoder().decode(
                DialogRequest.self, from: JSONSerialization.data(withJSONObject: display)),
            provider: provider,
            readGrant: try ReadGrantReview.parse(
                request: bytes, role: "github-write", uid: 501, now: Date(timeIntervalSince1970: 1000)),
            readScope: try ReadScopeReview.parse(request: bytes))
        return NSHostingView(
            rootView: ApprovalDialogView(
                presentation: presentation, controller: controller, close: {}, selectRoot: { _ in }))
    }
    let once = try view(JSONSerialization.data(withJSONObject: request))
    request["authorization"] = [
        "purpose": "quartermaster.read-grant.v2",
        "grant": [
            "id": String(repeating: "a", count: 32), "uid": 501,
            "codeHash": String(repeating: "1", count: 40), "root": root,
            "effects": ["version": 1, "effects": ["listIssues", "readIssue"]],
            "repository": "quartermaster/one", "role": "github-write", "expiresUnix": 4600,
        ],
    ]
    let shell = try view(JSONSerialization.data(withJSONObject: request))
    #expect(once.fittingSize.height > 0)
    #expect(once.fittingSize == shell.fittingSize)
}
