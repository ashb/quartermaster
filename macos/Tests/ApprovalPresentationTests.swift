import AppKit
import Foundation
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import QuartermasterSecurity
import SwiftUI
import Testing

@testable import QuartermasterApprovalUI

private func approvalPresentation(
    intent: [String: Any] = ["kind": "issue", "action": "closeIssue", "number": 42], effects: [String] = [],
    repository: String? = "quartermaster/one",
    notice: String? = nil, resourceTitle: String? = nil,
    ancestryComplete: Bool? = nil, ancestryNote: String? = nil, read: Bool = false
) throws -> ApprovalPresentation {
    var display: [String: Any] = [
        "intent": intent,
        "additionalEffects": effects, "allowsReadScope": read,
    ]
    display["repository"] = repository
    display["understandingNotice"] = notice
    display["resourceTitle"] = resourceTitle
    var payload: [String: Any] = [
        "repository": "", "repositoryId": 123, "issue": 42, "method": "PATCH", "body": "",
        "path": "/unfamiliar", "origin": "https://example.invalid",
        "processChain": ["codex", "gh"], "readRoots": [], "presentation": display,
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
        request: request, provider: provider, display: try ApprovalDisplay.parse(request: bytes),
        apiRequest: try APIRequestReview.parse(request: bytes),
        readScope: try ReadScopeReview.parse(request: bytes))
}

@Test func approvalRendersBackendDescriptionsWithoutInterpretingTheRequest() throws {
    let presentation = try approvalPresentation(
        intent: ["kind": "request"], effects: ["closeIssue", "deleteIssue"],
        repository: "example/records", notice: "incompleteRequest")
    #expect(presentation.operationTitle == "Approve GitHub request")
    #expect(presentation.repository == "example/records")
    #expect(presentation.additionalEffects == ["Close issue", "Delete issue"])
    #expect(
        presentation.understandingNotice
            == "This request isn't fully understood. Review the HTTP details before approving.")
    #expect(presentation.authenticationReason == "approve this GitHub request once")
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

@Test func processRootIsSelectableWithoutReplacingItWithSingleRequestApproval() throws {
    let roots = try JSONDecoder().decode(
        [ReadRootChoice].self,
        from: Data(
            #"[{"id":"process","pid":30,"executable":"/bin/gh","scope":"process"},{"id":"shell","pid":20,"executable":"/bin/zsh","scope":"descendants"}]"#
                .utf8))
    let rows = ProcessTreeRow.make(
        processes: [
            DialogProcess(pid: 20, name: "zsh", executable: "/bin/zsh", limited: false),
            DialogProcess(pid: 30, name: "gh", executable: "/bin/gh", limited: false),
        ], peerPID: 30, roots: roots, allowsSelection: true)
    #expect(rows.map(\.choice) == [.root("shell"), .root("process")])
    #expect(rows.map(\.label) == ["This shell", "This process"])
}

@Test func processRowsOnlyOfferMatchingVerifiedRootsAndTheRequestLeaf() throws {
    let root = try JSONDecoder().decode(
        ReadRootChoice.self,
        from: Data(
            #"{"id":"20:0000000000000001:00000001","pid":20,"executable":"/bin/zsh","scope":"descendants"}"#.utf8))
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

@MainActor private final class ScopeReviewBackend: ApprovalBackend {
    let reviewCreated = MonotonicTimestamp.now
    func challenge(authenticated: MonotonicTimestamp, context: LAContext) async throws -> Data {
        throw CancellationError()
    }
    func submit(_ signature: Data) async throws { throw CancellationError() }
    func cancel() {}
}

@Test @MainActor func refreshingTheScopePreservesTheHostingView() throws {
    let presentation = try approvalPresentation(read: true)
    let dialog = ApprovalDialog(presentation: presentation, backend: ScopeReviewBackend())
    let content = try #require(dialog.window.contentView)
    _ = content.fittingSize
    dialog.install(presentation)
    #expect(dialog.window.contentView === content)
    dialog.cancel()
}

@Test @MainActor func replacingTheScopeKeepsTheFooterLabelsSteady() throws {
    let presentation = try approvalPresentation(read: true)
    let controller = ApprovalController(backend: ScopeReviewBackend(), reason: "Test scope layout")
    let view = ApprovalDialogView(presentation: presentation, controller: controller, close: {})
    let cancel = view.cancelTitle
    let authentication = view.authenticationTitle
    #expect(controller.supersedeReview())
    #expect(view.cancelTitle == cancel)
    #expect(view.authenticationTitle == authentication)
}

@Test @MainActor func aRetainedDialogBindsTheFingerprintViewToTheReplacementContext() throws {
    let presentation = try approvalPresentation(read: true)
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
        "executable": "/nix/store/example-zsh/bin/zsh", "scope": "descendants",
    ]
    let parent: [String: Any] = [
        "id": "100:0000000000000002:00000001", "pid": 100,
        "executable": "/bin/bash", "scope": "descendants",
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
            display: try ApprovalDisplay.parse(request: bytes),
            apiRequest: try APIRequestReview.parse(request: bytes),
            readScope: try ReadScopeReview.parse(request: bytes))
        return NSHostingView(
            rootView: ApprovalDialogView(
                presentation: presentation, controller: controller, close: {}, selectRoot: { _ in }))
    }
    var display: [String: Any] = [
        "intent": ["kind": "request"],
        "repository": "quartermaster/one", "additionalEffects": [], "allowsReadScope": true,
    ]
    request["presentation"] = display
    let once = try view(JSONSerialization.data(withJSONObject: request))
    for selected in [root, parent] {
        display["intent"] = [
            "kind": "readGrant",
            "grant": [
                "id": "grant", "root": selected, "repository": "quartermaster/one", "expiresUnix": 4600,
                "permission": ["kind": "issueReads"],
            ],
        ]
        request["presentation"] = display
        let shell = try view(JSONSerialization.data(withJSONObject: request))
        #expect(once.fittingSize.height > 0)
        #expect(once.fittingSize == shell.fittingSize)
    }
}

@Test(arguments: ["Test issue", "Fix 👩‍💻 workflow", "العربية / עברית / 日本語 / café"])
func suppliedResourceTitlesPreserveUnicode(_ title: String) throws {
    let presentation = try approvalPresentation(resourceTitle: title)
    #expect(presentation.display.resourceTitle == title)
}

@Test func issueIntentRendersTheSuppliedActionAndNumber() throws {
    let presentation = try approvalPresentation(intent: ["kind": "issue", "action": "closeIssue", "number": 42])
    #expect(presentation.operationTitle == "Close issue #42?")
    #expect(presentation.additionalEffects.isEmpty)
}

@Test(arguments: [
    (["repository"], "Allow repository reads", "README", "Repository"),
    (["issues"], "Allow issue and PR reads", "pull requests", "Issues and PRs"),
    (["actions"], "Allow Actions metadata reads", "artifact lists", "Actions metadata"),
    (["output"], "Allow build output reads", "sensitive", "Build output"),
    (["repository", "issues"], "Allow selected GitHub reads", "across repositories", "Repository, Issues and PRs"),
    (
        ["repository", "issues", "actions", "output"], "Allow GitHub reads", "logs",
        "Repository, Issues and PRs, Actions metadata, Build output"
    ),
])
func typedReadScopesRenderOnlyTheirSelectedDescriptions(
    categories: [String], title: String, summary: String, name: String
) throws {
    let presentation = try approvalPresentation(intent: [
        "kind": "readGrant",
        "grant": [
            "id": "grant", "repository": "example/project", "expiresUnix": 4600,
            "root": ["id": "root", "pid": 123, "executable": "/bin/zsh", "scope": "descendants"],
            "permission": ["kind": "githubCategories", "categories": categories],
        ],
    ])
    let grant = try #require(presentation.readGrant)
    #expect(presentation.operationTitle == title)
    #expect(grant.summary.contains(summary))
    #expect(grant.summary.contains("logs") == categories.contains("output"))
    #expect(grant.scopeName == name)
    #expect(presentation.authenticationReason == "\(title) in example/project")
}

@Test(arguments: ["process", "descendants"])
func grantDescriptionDistinguishesProcessFromShellLifetime(_ scope: String) throws {
    let presentation = try approvalPresentation(intent: [
        "kind": "readGrant",
        "grant": [
            "id": "grant", "repository": "example/project", "expiresUnix": 4600,
            "root": ["id": "root", "pid": 123, "executable": "/bin/gh", "scope": scope],
            "permission": ["kind": "githubCategories", "categories": ["repository", "issues", "actions", "output"]],
        ],
    ])
    let grant = try #require(presentation.readGrant)
    #expect(grant.summary.contains("Only this running process") == (scope == "process"))
    #expect(grant.summary.contains("shell's descendants") == (scope == "descendants"))
    #expect(grant.summary.contains("Writes need separate approval"))
    #expect(grant.lifetimeDescription.contains(scope == "process" ? "process exits" : "shell exits"))
}
