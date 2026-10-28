import AppKit
import Foundation
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import QuartermasterSecurity
import SwiftUI
import Testing

@testable import QuartermasterApprovalUI

private func approvalPresentation(
    complete: Bool = true, effects: [String] = ["Close issue"], repository: String? = "quartermaster/one",
    ancestryComplete: Bool? = nil, ancestryNote: String? = nil, read: Bool = false
) throws -> ApprovalPresentation {
    let path = "/repos/quartermaster/one/issues/42"
    let method = read ? "GET" : "PATCH"
    let body = read ? "" : #"{"state":"closed"}"#
    var application: [String: Any] = [
        "version": "quartermaster.github-request.v1", "complete": complete, "effects": effects,
        "originalDigest": Data(repeating: 1, count: 32).base64EncodedString(),
        "request": Data("\(method) \(path) HTTP/1.1\r\nHost: api.github.com\r\n\r\n\(body)".utf8)
            .base64EncodedString(),
    ]
    if complete, let repository { application["requestedRepository"] = repository }
    var payload: [String: Any] = [
        "repository": read ? "quartermaster/one" : "", "repositoryId": 123,
        "issue": 42, "method": method, "body": body, "path": path, "origin": "https://api.github.com",
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

@Test func theReadScopeSummaryDoesNotRepeatTheRequestedAction() throws {
    let presentation = try approvalPresentation(effects: ["Read issue"], read: true)
    #expect(presentation.readScope != nil)
    #expect(presentation.additionalEffects.isEmpty)
}

@Test(arguments: [true, false]) func unexpectedReadActionsRemainVisible(_ complete: Bool) throws {
    let presentation = try approvalPresentation(
        complete: complete, effects: ["Read issue", "Delete repository"], read: true)
    #expect(presentation.additionalEffects == ["Read issue", "Delete repository"])
}

@Test func anIncompleteReadStillShowsItsKnownActions() throws {
    let presentation = try approvalPresentation(complete: false, effects: ["Read issue"], read: true)
    #expect(presentation.additionalEffects == ["Read issue"])
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

@Test func processRowsOnlyOfferMatchingVerifiedRootsAndTheRequestLeaf() throws {
    let root = try JSONDecoder().decode(
        ReadRootChoice.self,
        from: Data(
            #"{"id":"20:0000000000000001:00000001","pid":20,"executable":"/bin/zsh"}"#.utf8))
    let processes = [
        DialogProcess(pid: 10, name: "login", executable: "/usr/bin/login", limited: true),
        DialogProcess(pid: 20, name: "zsh", executable: "/bin/zsh", limited: false),
        DialogProcess(pid: 30, name: "gh", executable: "/bin/gh", limited: false),
    ]
    let rows = ProcessTreeRow.make(processes: processes, peerPID: 30, roots: [root], allowsSelection: true)
    #expect(rows.map(\.choice) == [nil, .root(root.id), .request])
    #expect(rows.map(\.label) == ["", "This shell", "This request"])
    #expect(rows[0].help.contains("Limited process information."))
    #expect(rows[0].help.contains("/usr/bin/login"))
    #expect(!rows[1].help.contains("Limited process information."))
    for process in [
        DialogProcess(pid: 20, name: "zsh", executable: "/other/zsh", limited: false),
        DialogProcess(pid: 20, name: "zsh", executable: "/bin/zsh", limited: true),
    ] {
        #expect(
            ProcessTreeRow.make(processes: [process], peerPID: 30, roots: [root], allowsSelection: true)[0].choice
                == nil)
    }
    #expect(
        ProcessTreeRow.make(processes: processes, peerPID: 30, roots: [root], allowsSelection: false).allSatisfy {
            $0.choice == nil
        })
}

@Test @MainActor func deepProcessTreesScrollWithoutGrowingTheDialog() {
    func tree(count: UInt32) -> NSHostingView<some View> {
        let processes = (1...count).map {
            DialogProcess(pid: $0, name: "zsh", executable: "/bin/zsh", limited: false)
        }
        return NSHostingView(
            rootView: ProcessScopeTree(
                rows: ProcessTreeRow.make(processes: processes, peerPID: count, roots: [], allowsSelection: true),
                selection: .request, enabled: true, choose: { _ in }
            ).frame(width: 492))
    }
    #expect(tree(count: 4).fittingSize == tree(count: 32).fittingSize)
}

@Test func perRequestTreesDoNotDescribeProcessesAsIneligibleForGrants() {
    let rows = ProcessTreeRow.make(
        processes: [
            DialogProcess(pid: 10, name: "login", executable: "/usr/bin/login", limited: true),
            DialogProcess(pid: 20, name: "zsh", executable: "/bin/zsh", limited: false),
            DialogProcess(pid: 30, name: "gh", executable: "/bin/gh", limited: false),
        ], peerPID: 30, roots: [], allowsSelection: false)
    #expect(rows.allSatisfy { !$0.help.contains("cannot receive a read grant") })
    #expect(rows.allSatisfy { !$0.scopeOffered && $0.choice == nil })
    #expect(rows[0].dimmed)
    #expect(rows[0].help.contains("Limited process information."))
    #expect(!rows[1].dimmed && !rows[2].dimmed)
    #expect(rows[1].help == "/bin/zsh")
}

@Test func appBundleLookupUsesTheContainingApplicationAndIgnoresOrdinaryExecutables() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let app = directory.appendingPathComponent("Example.app")
    let executable = app.appendingPathComponent("Contents/MacOS/helper")
    try FileManager.default.createDirectory(
        at: executable.deletingLastPathComponent(), withIntermediateDirectories: true)
    try PropertyListSerialization.data(
        fromPropertyList: ["CFBundlePackageType": "APPL", "CFBundleName": "Example"], format: .xml, options: 0
    )
    .write(to: app.appendingPathComponent("Contents/Info.plist"))
    #expect(ProcessApplication(executable: executable.path)?.name == "Example")
    #expect(ProcessApplication(executable: "/bin/zsh") == nil)
    #expect(ProcessApplication(executable: nil) == nil)
}

@Test func malformedTreesAndMissingSelectedRootsCannotBePresentedAsValidGrants() throws {
    let root = try JSONDecoder().decode(
        ReadRootChoice.self,
        from: Data(
            #"{"id":"20:0000000000000001:00000001","pid":20,"executable":"/bin/zsh"}"#.utf8))
    let shell = DialogProcess(pid: 20, name: "zsh", executable: "/bin/zsh", limited: false)
    let leaf = DialogProcess(pid: 30, name: "gh", executable: "/bin/gh", limited: false)
    var request = try approvalPresentation(ancestryComplete: true).request
    request.peer?.processes = [shell, leaf]
    #expect(request.validProcessTree)
    #expect(request.canDisplay(root: root))
    for rows in [
        [], [shell], [shell, leaf, leaf],
        [shell, DialogProcess(pid: 30, name: "gh", executable: "/other/gh", limited: false)],
        [shell, DialogProcess(pid: 30, name: "gh", executable: "/bin/gh", limited: true)],
        (100...131).map { DialogProcess(pid: $0, name: "ancestor", executable: "/bin/zsh", limited: false) } + [leaf],
    ] {
        request.peer?.processes = rows
        #expect(!request.validProcessTree)
    }
    for rows in [
        [leaf],
        [DialogProcess(pid: 20, name: "zsh", executable: "/other/zsh", limited: false), leaf],
        [DialogProcess(pid: 20, name: "zsh", executable: "/bin/zsh", limited: true), leaf],
    ] {
        request.peer?.processes = rows
        #expect(!request.canDisplay(root: root))
    }
}

@MainActor private final class ScopeReviewBackend: ApprovalBackend {
    let reviewCreated = MonotonicTimestamp.now
    func challenge(authenticated: MonotonicTimestamp, context: LAContext) async throws -> Data {
        throw CancellationError()
    }
    func submit(_ signature: Data) async throws { throw CancellationError() }
    func cancel() {}
}

@Test @MainActor func refreshingTheScopePreservesTheHostingView() throws {
    let presentation = try approvalPresentation(effects: ["Read issue"], read: true)
    let dialog = ApprovalDialog(presentation: presentation, backend: ScopeReviewBackend())
    let content = try #require(dialog.window.contentView)
    _ = content.fittingSize
    dialog.install(presentation)
    #expect(dialog.window.contentView === content)
    dialog.cancel()
}

@Test @MainActor func replacingTheScopeKeepsTheFooterLabelsSteady() throws {
    let presentation = try approvalPresentation(effects: ["Read issue"], read: true)
    let controller = ApprovalController(backend: ScopeReviewBackend(), reason: "Test scope layout")
    let view = ApprovalDialogView(presentation: presentation, controller: controller, close: {})
    let cancel = view.cancelTitle
    let authentication = view.authenticationTitle
    #expect(controller.supersedeReview())
    #expect(view.cancelTitle == cancel)
    #expect(view.authenticationTitle == authentication)
}

@Test @MainActor func aRetainedDialogBindsTheFingerprintViewToTheReplacementContext() throws {
    let presentation = try approvalPresentation(effects: ["Read issue"], read: true)
    func view(_ controller: ApprovalController) -> ApprovalDialogView {
        ApprovalDialogView(presentation: presentation, controller: controller, close: {})
    }
    func authentication(in view: NSView) -> LAAuthenticationView? {
        if let authentication = view as? LAAuthenticationView { return authentication }
        return view.subviews.lazy.compactMap { authentication(in: $0) }.first
    }
    let original = ApprovalController(backend: ScopeReviewBackend(), reason: "Original scope")
    let replacement = ApprovalController(backend: ScopeReviewBackend(), reason: "Replacement scope")
    let host = NSHostingView(rootView: view(original))
    host.setFrameSize(host.fittingSize)
    host.layoutSubtreeIfNeeded()
    #expect(try #require(authentication(in: host)).context === original.context)
    host.rootView = view(replacement)
    host.layoutSubtreeIfNeeded()
    #expect(try #require(authentication(in: host)).context === replacement.context)
}

@Test(arguments: [
    ("Read issue", "/repos/quartermaster/one/issues/42"), ("List issues", "/repos/quartermaster/one/issues"),
])
@MainActor func switchingReadScopeKeepsTheApprovalWindowHeight(_ effect: String, _ path: String) throws {
    let root: [String: Any] = [
        "id": "123:0000000000000001:00000001", "pid": 123,
        "executable": "/nix/store/example-zsh/bin/zsh",
    ]
    let parent: [String: Any] = [
        "id": "100:0000000000000002:00000001", "pid": 100,
        "executable": "/bin/bash",
    ]
    var request: [String: Any] = [
        "repository": "quartermaster/one", "repositoryId": 123,
        "method": "GET", "path": path, "body": "",
        "origin": "https://api.github.com", "processChain": ["zsh", "gh"],
        "peer": [
            "cdHash": String(repeating: "1", count: 40), "pid": 200, "executable": "/bin/gh",
            "signingIdentifier": "gh", "adHoc": false, "ancestryComplete": false,
            "processes": [
                ["pid": 50, "name": "login", "executable": "/usr/bin/login", "limited": true],
                ["pid": 100, "name": "bash", "executable": "/bin/bash", "limited": false],
                ["pid": 123, "name": "zsh", "executable": "/nix/store/example-zsh/bin/zsh", "limited": false],
                ["pid": 200, "name": "gh", "executable": "/bin/gh", "limited": false],
            ],
        ], "readRoots": [root, parent],
        "application": [
            "version": "quartermaster.github-request.v1", "complete": true, "effects": [effect],
            "requestedRepository": "quartermaster/one",
            "originalDigest": Data(repeating: 1, count: 32).base64EncodedString(),
            "request": Data("GET \(path) HTTP/1.1\r\nHost: api.github.com\r\n\r\n".utf8).base64EncodedString(),
        ],
    ]
    let provider = try approvalPresentation().provider
    let controller = ApprovalController(backend: ScopeReviewBackend(), reason: "Test scope layout")
    func view(_ bytes: Data) throws -> NSHostingView<ApprovalDialogView> {
        let presentation = ApprovalPresentation(
            request: try JSONDecoder().decode(DialogRequest.self, from: bytes),
            provider: provider,
            readGrant: try ReadGrantReview.parse(
                request: bytes, role: "github-write", uid: 501, now: Date(timeIntervalSince1970: 1000)),
            apiRequest: try APIRequestReview.parse(request: bytes),
            readScope: try ReadScopeReview.parse(request: bytes))
        return NSHostingView(
            rootView: ApprovalDialogView(
                presentation: presentation, controller: controller, close: {}, selectRoot: { _ in }))
    }
    let once = try view(JSONSerialization.data(withJSONObject: request))
    for selected in [root, parent] {
        request["authorization"] = [
            "purpose": "quartermaster.read-grant.v2",
            "grant": [
                "id": String(repeating: "a", count: 32), "uid": 501,
                "codeHash": String(repeating: "1", count: 40), "root": selected,
                "effects": ["version": 1, "effects": ["listIssues", "readIssue"]],
                "repository": "quartermaster/one", "role": "github-write", "expiresUnix": 4600,
            ],
        ]
        let shell = try view(JSONSerialization.data(withJSONObject: request))
        #expect(once.fittingSize.height > 0)
        #expect(once.fittingSize == shell.fittingSize)
    }
}
