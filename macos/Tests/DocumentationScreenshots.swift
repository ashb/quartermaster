import AppKit
import Foundation
import LocalAuthentication
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
    let disconnected = false
    func cancel() {}

    @MainActor func call(_ command: BrokerCommand, context: LAContext?) async throws -> BrokerReply {
        switch command {
        case .hello: return .hello(profile: "development")
        case .settingsRegister, .settingsStatus: return .settingsStatus(try Self.snapshot())
        case .settingsCancel: return .canceled
        case .vaultStatus:
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
        "item_id": "22222222-2222-4222-8222-222222222222", "field": "LoginPassword", "role": "github-write",
    ]

    private static func snapshot() throws -> SettingsSnapshot {
        try JSONDecoder().decode(
            SettingsSnapshot.self,
            from: JSONSerialization.data(withJSONObject: [
                "state": "configured", "revision": 5,
                "session": Data(repeating: 1, count: 16).base64EncodedString(),
                "settings": ["github": NSNull(), "mutations": "requireApproval"],
                "provider": [
                    "slot": String(repeating: "a", count: 32), "scope": String(repeating: "b", count: 32),
                    "deviceKey": Array(repeating: 7, count: 32), "binding": binding,
                ],
                "migration": NSNull(),
            ]))
    }
}

@MainActor private func approval() throws -> ApprovalPresentation {
    let path = "/repos/example/project/issues/42"
    let root: [String: Any] = ["id": "1200:0000000000000001:00000001", "pid": 1200, "executable": "/bin/zsh"]
    let request: [String: Any] = [
        "repository": "example/project", "repositoryId": 123, "issue": 42,
        "method": "GET", "path": path, "body": "", "origin": "https://api.github.com",
        "processChain": ["Terminal", "login", "zsh", "gh"], "readRoots": [root],
        "peer": [
            "pid": 1201, "executable": "/usr/local/bin/gh", "signingIdentifier": "gh",
            "cdHash": String(repeating: "1", count: 40), "adHoc": true, "ancestryComplete": true,
            "commandLine": "gh api -H 'Accept: application/vnd.github+json' repos/example/project/issues/42",
            "processes": [
                [
                    "pid": 1100, "name": "Terminal",
                    "executable": "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                    "limited": false,
                ],
                ["pid": 1199, "name": "login", "executable": "/usr/bin/login", "limited": true],
                ["pid": 1200, "name": "zsh", "executable": "/bin/zsh", "limited": false],
                ["pid": 1201, "name": "gh", "executable": "/usr/local/bin/gh", "limited": false],
            ],
        ],
        "application": [
            "version": "quartermaster.github-request.v1", "complete": true, "effects": ["Read issue"],
            "requestedRepository": "example/project",
            "originalDigest": Data(repeating: 1, count: 32).base64EncodedString(),
            "request": Data(
                "GET \(path) HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n\r\n"
                    .utf8
            ).base64EncodedString(),
        ],
        "authorization": [
            "purpose": "quartermaster.read-grant.v2",
            "grant": [
                "id": String(repeating: "a", count: 32), "uid": 501, "codeHash": String(repeating: "1", count: 40),
                "root": root, "effects": ["version": 1, "effects": ["listIssues", "readIssue"]],
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
        readGrant: try ReadGrantReview.parse(
            request: bytes, role: "github-write", uid: 501, now: Date(timeIntervalSince1970: 1_793_188_800)),
        apiRequest: try APIRequestReview.parse(request: bytes), readScope: try ReadScopeReview.parse(request: bytes))
}

@MainActor private func render(
    _ view: some View, size: NSSize?, title: String, to output: URL,
    settling: Duration = .milliseconds(500), validate: () throws -> Void = {}
) async throws {
    let host = NSHostingView(rootView: view.environment(\.locale, Locale(identifier: "en_GB")))
    let dimensions = size ?? host.fittingSize
    host.setFrameSize(dimensions)
    let window = NSWindow(
        contentRect: NSRect(origin: .zero, size: dimensions), styleMask: [.titled, .closable], backing: .buffered,
        defer: false)
    window.isReleasedWhenClosed = false
    window.title = title
    window.contentView = host
    defer { window.close() }
    window.center()
    window.makeKeyAndOrderFront(nil)
    NSApplication.shared.activate(ignoringOtherApps: true)
    try await Task.sleep(for: settling)
    host.layoutSubtreeIfNeeded()
    let content = try await SCShareableContent.currentProcess
    guard let captured = content.windows.first(where: { $0.windowID == CGWindowID(window.windowNumber) }) else {
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
            ["--settings-only", "--authentication-ui"].contains(CommandLine.arguments[2])
        else {
            print("Usage: DocumentationScreenshots OUTPUT (--settings-only | --authentication-ui)")
            print("--authentication-ui briefly shows and cancels a real Touch ID prompt. Do not touch the reader.")
            throw CaptureFailure.usage
        }
        let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        UserDefaults.standard.setVolatileDomain(
            ["AppleLocale": "en_GB", "AppleLanguages": ["en-GB"], "AppleAccentColor": 4],
            forName: UserDefaults.argumentDomain)
        NSTimeZone.default = TimeZone(secondsFromGMT: 0)!
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        app.appearance = NSAppearance(named: .darkAqua)
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
                    presentation: try approval(), controller: controller, close: {}, selectRoot: { _ in }),
                size: nil, title: "Quartermaster approval", to: output.appendingPathComponent("approval-dialog.png"),
                settling: .seconds(2),
                validate: {
                    guard controller.phase == .authenticating else { throw CaptureFailure.authenticationNotPending }
                })
        }
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
            size: NSSize(width: 920, height: 700), title: "Vault",
            to: output.appendingPathComponent("settings-vault.png"))
    }
}
