import AppKit
import BazelRunfiles
import Foundation
import LocalAuthentication
import Luminare
import ScreenCaptureKit
import SwiftUI

@testable import Quartermaster
@testable import QuartermasterApprovalUI
@testable import QuartermasterSecurity

private enum CaptureFailure: Error {
    case usage, rendering, unexpectedOperation, connectionTimeout, authenticationNotPending
}

@MainActor private final class InertUnlock: VaultUnlockBackend {
    let reviewCreated = MonotonicTimestamp.now
    func unlock(authenticated: MonotonicTimestamp, context: LAContext) async throws {
        throw CaptureFailure.unexpectedOperation
    }
    func cancel() {}
}

private final class DocumentationClient: BrokerClient, Sendable {
    private let fresh: Bool
    private let acceptsLogin: Bool

    init(fresh: Bool = false, acceptsLogin: Bool = false) {
        self.fresh = fresh
        self.acceptsLogin = acceptsLogin
    }

    let disconnected = false
    func cancel() {}

    @MainActor func call(_ command: BrokerCommand, context: LAContext?) async throws -> BrokerReply {
        switch command {
        case .hello: return .hello(profile: "development")
        case .enroll: return .enrolled
        case .next: return .idle
        case .readGrants: return .readGrants([])
        case .settingsRegister, .settingsStatus: return .settingsStatus(try Self.snapshot(fresh: fresh))
        case .stageEnrollment:
            guard fresh, acceptsLogin else { throw BrokerControlError.invalidCredentials }
            let configured = try Self.snapshot()
            return .enrollmentStaged(ticket: "documentation-ticket", provider: try Self.provider(configured))
        case .settingsCancel: return .canceled
        case .vaultStatus:
            if fresh {
                return .vaultStatus(
                    try JSONDecoder().decode(BrokerVaultStatus.self, from: Data(#"{"state":"unenrolled"}"#.utf8)))
            }
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .secondsSince1970
            return .vaultStatus(
                try decoder.decode(
                    BrokerVaultStatus.self,
                    from: JSONSerialization.data(withJSONObject: [
                        "state": "locked", "binding": Self.binding, "lastSync": 1_793_188_800,
                    ])))
        default: throw CaptureFailure.unexpectedOperation
        }
    }

    private static let binding = [
        "server": "https://vault.example.invalid", "email": "demo@example.invalid",
        "account_id": "11111111-1111-4111-8111-111111111111",
    ]

    private static func provider(_ snapshot: SettingsSnapshot) throws -> SettingsProvider {
        guard let provider = snapshot.provider else { throw CaptureFailure.unexpectedOperation }
        return provider
    }

    private static func snapshot(fresh: Bool = false) throws -> SettingsSnapshot {
        if fresh {
            return SettingsSnapshot(
                state: "unconfigured", revision: 0, session: Data(repeating: 1, count: 16), settings: nil,
                provider: nil, migration: nil)
        }
        return try JSONDecoder().decode(
            SettingsSnapshot.self,
            from: JSONSerialization.data(withJSONObject: [
                "state": "configured", "revision": 5,
                "session": Data(repeating: 1, count: 16).base64EncodedString(),
                "settings": [
                    "github": [
                        "version": 1, "mode": "github",
                        "repositories": [["id": 123, "owner": "example", "name": "project", "writes": false]],
                        "approveUnverifiedRequests": true,
                    ],
                    "githubCredential": [
                        "itemId": "22222222-2222-4222-8222-222222222222", "itemName": "GitHub — example",
                    ],
                    "mutations": "requireApproval",
                ],
                "provider": [
                    "slot": String(repeating: "a", count: 32), "scope": String(repeating: "b", count: 32),
                    "deviceKey": Array(repeating: 7, count: 32), "binding": binding,
                ],
                "migration": NSNull(),
            ]))
    }
}

@MainActor private func approval(graphQL: Bool = false) throws -> ApprovalPresentation {
    let path = graphQL ? "/graphql" : "/repos/example/project/issues/42"
    let body =
        graphQL
        ? #"{"query":"query IssueByNumber($number: Int!) { repository(owner: \"example\", name: \"project\") { issue(number: $number) { title } } }","variables":{"number":42}}"#
        : ""
    let wireRequest =
        graphQL
        ? "POST \(path) HTTP/1.1\r\nHost: api.github.com\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"
        : "GET \(path) HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n\r\n"
    let shell: [String: Any] = [
        "id": "1200:0000000000000001:00000001", "pid": 1200, "executable": "/bin/zsh", "scope": "descendants",
    ]
    let root: [String: Any] = [
        "id": "1201:0000000000000001:00000001", "pid": 1201, "executable": "/usr/local/bin/gh", "scope": "process",
    ]
    let request: [String: Any] = [
        "repository": "example/project", "repositoryId": 123, "issue": 42,
        "method": graphQL ? "POST" : "GET", "path": path, "body": body, "origin": "https://api.github.com",
        "processChain": ["Terminal", "login", "zsh", "gh"], "readRoots": [root, shell],
        "peer": [
            "pid": 1201, "executable": "/usr/local/bin/gh", "signingIdentifier": "gh",
            "cdHash": String(repeating: "1", count: 40), "adHoc": true, "ancestryComplete": true,
            "commandLine": graphQL
                ? "gh issue view 42 --repo example/project"
                : "gh api -H 'Accept: application/vnd.github+json' repos/example/project/issues/42",
            "workingDirectory": "/Users/example/code/project",
            "startedUnixMicros": 1_793_188_700_123_456,
            "processes": [
                [
                    "pid": 1100, "name": "Terminal",
                    "executable": "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                    "limited": false,
                    "startedUnixMicros": 1_793_188_000_000_000,
                ],
                ["pid": 1199, "name": "login", "executable": "/usr/bin/login", "limited": true],
                [
                    "pid": 1200, "name": "zsh", "executable": "/bin/zsh", "limited": false,
                    "startedUnixMicros": 1_793_188_500_000_000,
                ],
                [
                    "pid": 1201, "name": "gh", "executable": "/usr/local/bin/gh", "limited": false,
                    "startedUnixMicros": 1_793_188_700_123_456,
                ],
            ],
        ],
        "application": [
            "version": "quartermaster.github-request.v1", "complete": true, "effects": ["Read issue"],
            "requestedRepository": "example/project",
            "originalDigest": Data(repeating: 1, count: 32).base64EncodedString(),
            "request": Data(wireRequest.utf8).base64EncodedString(),
        ],
        "presentation": [
            "intent": [
                "kind": "readGrant",
                "grant": [
                    "id": "sample", "root": root, "repository": "example/project", "expiresUnix": 1_793_192_400,
                    "permission": ["kind": "issueReads"],
                ],
            ],
            "repository": "example/project", "additionalEffects": [], "allowsReadScope": true,
        ],
        "authorization": [
            "purpose": "quartermaster.read-grant",
            "grant": [
                "id": String(repeating: "a", count: 32), "uid": 501, "codeHash": String(repeating: "1", count: 40),
                "root": root, "effects": ["kind": "issueReads", "effects": ["listIssues", "readIssue"]],
                "repository": "example/project", "role": "github-write", "expiresUnix": 1_793_192_400,
            ],
        ],
    ]
    let bytes = try JSONSerialization.data(withJSONObject: request)
    let provider = try JSONDecoder().decode(
        ApprovalProviderIdentity.self,
        from: Data(
            #"{"server":"https://vault.example.invalid","account":"sample","email":"demo@example.invalid","item":"sample","field":"LoginPassword","role":"github-write","enrollment":"sample","generation":1}"#
                .utf8))
    return ApprovalPresentation(
        request: try JSONDecoder().decode(DialogRequest.self, from: bytes), provider: provider,
        display: try ApprovalDisplay.parse(request: bytes),
        apiRequest: try APIRequestReview.parse(request: bytes), readScope: try ReadScopeReview.parse(request: bytes))
}

@MainActor private func handoffSample() throws -> CredentialHandoffRequest {
    let rex =
        NSHomeDirectory()
        + "/Library/Application Support/com.superlogical.rex/RexServer/Versions/Current/Rex Server.app/Contents/MacOS/rex"
    let shim =
        Bundle.main.url(forAuxiliaryExecutable: "qm")?.path ?? "/Applications/Quartermaster.app/Contents/MacOS/qm"
    let fields: [String: Any] = [
        "kind": "credentialHandoff", "tool": "restic", "credentialName": "Restic",
        "recipient": [
            "pid": 1202, "execution": "sample-execution", "executable": "/nix/store/example-restic/bin/.restic-wrapped",
            "requirement": "sample-code-requirement",
        ],
        "command": [
            "/nix/store/example-restic/bin/.restic-wrapped", "--repo", "/tmp/quartermaster-demo", "backup",
            "/tmp/example-data",
        ],
        "workingDirectory": "/Users/example/code/quartermaster",
        "requester": [
            "pid": 1201, "executable": shim, "signingIdentifier": "qm", "cdHash": "sample", "adHoc": false,
            "ancestryComplete": true,
            "commandLine": "qm run restic -- --repo /tmp/quartermaster-demo backup /tmp/example-data",
            "processes": [
                ["pid": 1100, "name": "rex", "executable": rex, "limited": false],
                ["pid": 1199, "name": "login", "executable": "/usr/bin/login", "limited": false],
                ["pid": 1200, "name": "zsh", "executable": "/bin/zsh", "limited": false],
            ],
        ],
        "provider": [
            "server": "https://vault.example.invalid", "account": "sample", "email": "demo@example.invalid",
            "item": "sample", "field": "LoginPassword", "role": "restic-password", "enrollment": "sample",
            "generation": 1,
        ],
        "created": MonotonicTimestamp.now.serializedNanoseconds, "operationId": "sample",
    ]
    return try JSONDecoder().decode(CredentialHandoffRequest.self, from: JSONSerialization.data(withJSONObject: fields))
}

@MainActor private func render(
    _ view: some View, size: NSSize?, title: String, to output: URL,
    floating: Bool = false, bitmap: Bool = false, settling: Duration = .milliseconds(500), prepare: () -> Void = {},
    validate: () throws -> Void = {}
) async throws {
    let content = view.environment(\.locale, Locale(identifier: "en_GB"))
    let window: NSWindow
    if floating {
        window = LuminareWindow(titleBarButtonConfiguration: nil) { content }
        window.level = .floating
    } else {
        let host = NSHostingView(rootView: content)
        let dimensions = size ?? host.fittingSize
        host.setFrameSize(dimensions)
        window = NSWindow(
            contentRect: NSRect(origin: .zero, size: dimensions), styleMask: [.titled, .closable], backing: .buffered,
            defer: false)
        window.contentView = host
    }
    window.isReleasedWhenClosed = false
    window.title = title
    defer { window.close() }
    window.center()
    window.makeKeyAndOrderFront(nil)
    NSApplication.shared.activate(ignoringOtherApps: true)
    try await Task.sleep(for: settling)
    prepare()
    try await Task.sleep(for: .milliseconds(100))
    window.contentView?.layoutSubtreeIfNeeded()
    if bitmap {
        guard let view = window.contentView,
            let image = view.bitmapImageRepForCachingDisplay(in: view.bounds)
        else { throw CaptureFailure.rendering }
        view.cacheDisplay(in: view.bounds, to: image)
        guard let data = image.representation(using: .png, properties: [:]) else { throw CaptureFailure.rendering }
        try data.write(to: output, options: .atomic)
        print(output.lastPathComponent)
        return
    }
    let shareable = try await SCShareableContent.currentProcess
    guard let captured = shareable.windows.first(where: { $0.windowID == CGWindowID(window.windowNumber) }) else {
        throw CaptureFailure.rendering
    }
    let configuration = SCStreamConfiguration()
    configuration.width = Int(window.frame.width * 2)
    configuration.height = Int(window.frame.height * 2)
    configuration.ignoreShadowsSingleWindow = true
    configuration.scalesToFit = true
    configuration.showsCursor = false
    configuration.captureResolution = .best
    let image = try await SCScreenshotManager.captureImage(
        contentFilter: SCContentFilter(desktopIndependentWindow: captured), configuration: configuration)
    let bitmap = NSBitmapImageRep(cgImage: image)
    guard let data = bitmap.representation(using: .png, properties: [:]) else { throw CaptureFailure.rendering }
    try validate()
    try data.write(to: output, options: .atomic)
    print("\(output.lastPathComponent): \(bitmap.pixelsWide)×\(bitmap.pixelsHigh)")
}

@main private enum DocumentationScreenshots {
    @MainActor static func main() async {
        do { try await capture() } catch {
            FileHandle.standardError.write(Data("Screenshot capture failed: \(error)\n".utf8))
            exit(1)
        }
    }

    @MainActor private static func capture() async throws {
        guard CommandLine.arguments.count == 3,
            ["--settings-only", "--authentication-ui", "--handoff-preview", "--vault-pane-preview"].contains(
                CommandLine.arguments[2])
        else {
            print(
                "Usage: DocumentationScreenshots OUTPUT (--settings-only | --authentication-ui | --handoff-preview | --vault-pane-preview)"
            )
            print("--authentication-ui briefly shows and cancels a real Touch ID prompt. Do not touch the reader.")
            throw CaptureFailure.usage
        }
        let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        let runfiles = try Runfiles.create()
        let iconURL = try runfiles.rlocation("_main/macos/ApprovalUI/Assets.xcassets/GitHub.imageset/github.svg")
        guard let icon = NSImage(contentsOf: iconURL) else { throw CaptureFailure.rendering }
        icon.isTemplate = true
        icon.setName("GitHub")
        UserDefaults.standard.setVolatileDomain(
            ["AppleLocale": "en_GB", "AppleLanguages": ["en-GB"], "AppleAccentColor": 4],
            forName: UserDefaults.argumentDomain)
        NSTimeZone.default = TimeZone(secondsFromGMT: 0)!
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        app.appearance = NSAppearance(named: .darkAqua)
        if CommandLine.arguments[2] == "--vault-pane-preview" {
            try await vaultPanePreview(output)
            return
        }
        if CommandLine.arguments[2] == "--handoff-preview" {
            let request = try handoffSample()
            let controller = ApprovalController(unlock: InertUnlock(), reason: "Inert documentation preview")
            guard controller.supersedeReview() else { throw CaptureFailure.unexpectedOperation }
            for expanded in [false, true] {
                try await render(
                    VStack(spacing: 0) {
                        CredentialHandoffView(
                            request: request, controller: controller, close: {}, showsDetails: expanded)
                        Text("Preview · sample data · authentication inactive")
                            .font(.caption).foregroundStyle(.secondary).padding(.bottom, 16)
                    },
                    size: nil, title: "Restic approval preview",
                    to: output.appendingPathComponent(expanded ? "restic-expanded.png" : "restic-approval.png"),
                    floating: true)
            }
            try await render(
                CredentialHandoffDetails(request: request), size: NSSize(width: 660, height: 520),
                title: "Full request",
                to: output.appendingPathComponent("restic-full-request.png"))
            return
        }
        if CommandLine.arguments[2] == "--authentication-ui" {
            let controller = ApprovalController(
                unlock: InertUnlock(), reason: "Capture Quartermaster documentation; do not authenticate")
            let cancellation = Task {
                try await Task.sleep(for: .seconds(8))
                controller.cancel()
            }
            defer {
                controller.cancel()
                cancellation.cancel()
            }
            try await render(
                ApprovalDialogView(
                    presentation: try approval(graphQL: true), controller: controller, close: {}, selectRoot: { _ in }),
                size: nil, title: "Quartermaster approval", to: output.appendingPathComponent("approval-dialog.png"),
                floating: true, settling: .seconds(2),
                validate: {
                    guard controller.phase == .authenticating else { throw CaptureFailure.authenticationNotPending }
                })
        }
        let details = try approval(graphQL: true)
        try await render(
            ApprovalRequestDetails(presentation: details),
            size: NSSize(width: 660, height: 520), title: "Full request",
            to: output.appendingPathComponent("request-approval.png"))
        try await render(
            ApprovalRequestDetails(presentation: details, tab: .caller),
            size: NSSize(width: 660, height: 520), title: "Full request",
            to: output.appendingPathComponent("request-caller.png"))
        try await render(
            ApprovalInlineDetails(presentation: details).padding(24)
                .frame(width: 540).fixedSize(horizontal: false, vertical: true),
            size: NSSize(width: 540, height: 260), title: "Request details",
            to: output.appendingPathComponent("request-details.png"))
        let application = BrokerApplication(
            setActivationPolicy: { _ in }, openConnection: { DocumentationClient() },
            loadApprovalKey: { Data(repeating: 1, count: 65) },
            acquirePresentation: { throw CaptureFailure.unexpectedOperation })
        application.reconnect()
        for _ in 0..<100 {
            if application.vaultStatus != nil { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        guard application.vaultStatus != nil, application.preferences.available else {
            throw CaptureFailure.connectionTimeout
        }
        try await render(
            PreferencesView(editor: application.preferences, application: application),
            size: NSSize(width: 880, height: 540), title: "Quartermaster",
            to: output.appendingPathComponent("settings-vault.png"))
        await application.reloadPreferences()
        try await render(
            PreferencesView(editor: application.preferences, application: application, pane: .tools),
            size: NSSize(width: 880, height: 540), title: "Quartermaster",
            to: output.appendingPathComponent("settings-tools.png"))
        await application.reloadPreferences()
        try await render(
            PreferencesView(
                editor: application.preferences, application: application, pane: .tools, showingGitHub: true),
            size: NSSize(width: 880, height: 540), title: "Quartermaster",
            to: output.appendingPathComponent("settings-github.png"))
        await application.reloadPreferences()
        try await render(
            PreferencesView(
                editor: application.preferences, application: application, pane: .vault,
                editingVault: true),
            size: NSSize(width: 880, height: 660), title: "Quartermaster",
            to: output.appendingPathComponent("settings-vault-edit.png"),
            prepare: { application.preferences.draft.mutations = .deny })
    }
    @MainActor private static func vaultPanePreview(_ output: URL) async throws {
        for stage in ["initial", "error", "ready"] {
            let application = BrokerApplication(
                setActivationPolicy: { _ in },
                openConnection: { DocumentationClient(fresh: true, acceptsLogin: stage == "ready") },
                loadApprovalKey: { Data(repeating: 1, count: 65) },
                acquirePresentation: { throw CaptureFailure.unexpectedOperation })
            application.reconnect()
            for _ in 0..<100 where !application.preferences.available { try await Task.sleep(for: .milliseconds(10)) }
            guard application.preferences.available else { throw CaptureFailure.connectionTimeout }
            var draft = application.preferences.enrollment
            draft.server = "https://vault.example.com"
            draft.email = "ash@example.com"
            if stage != "initial" {
                await application.preferences.enroll(password: "documentation-only", replacement: draft)
            }
            if stage == "error" {
                try await render(
                    PreferencesGroup(title: "Connect your vault") {
                        VaultLoginForm(
                            editor: application.preferences, application: application,
                            draft: .constant(draft), password: .constant("documentation-only"), cancel: nil)
                    }
                    .padding(24).frame(width: 660, height: 310, alignment: .topLeading)
                    .background(Color(nsColor: .windowBackgroundColor))
                    .tint(ApprovalAppearance.accent).luminareTint(overridingWith: ApprovalAppearance.accent)
                    .luminareCornerRadius(12).luminareMinHeight(24),
                    size: NSSize(width: 660, height: 310), title: "Vault login",
                    to: output.appendingPathComponent("vault-login-error.png"), bitmap: true)
            } else {
                try await render(
                    PreferencesView(editor: application.preferences, application: application),
                    size: NSSize(width: 880, height: 540), title: "Quartermaster",
                    to: output.appendingPathComponent("vault-\(stage).png"), bitmap: true)
            }
        }
    }

}
