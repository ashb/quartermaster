import AppKit
import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import QuartermasterApprovalUI
import QuartermasterIPC
import QuartermasterSecurity
import Security

struct FixtureConfig: Decodable {
    let service: String
    let serverRequirement: String
    let scope: String
    let approvalGroup: String
    let cacheGroup: String
    let `case`: String
}

enum FixtureFailure: Error {
    case assertion(String)
}

func require(_ condition: Bool, _ message: String) throws {
    guard condition else { throw FixtureFailure.assertion(message) }
}

@MainActor
final class IPCFixture: ApprovalBackend {
    let config: FixtureConfig
    let connection: NSXPCConnection
    let keys: ApprovalKeyStore
    let message = Data("quartermaster native integration dummy request v1".utf8)
    var publicKey: Data?
    var submitted = false

    init(_ config: FixtureConfig, directory: URL) {
        self.config = config
        keys = ApprovalKeyStore(
            namespace: "dev.quartermaster.test.approval.\(config.scope)", accessGroup: config.approvalGroup,
            lockDirectory: directory.appendingPathComponent("approval-key", isDirectory: true))
        connection = NSXPCConnection(machServiceName: config.service)
        connection.setCodeSigningRequirement(config.serverRequirement)
        connection.remoteObjectInterface = qm_context_interface()
        connection.resume()
    }

    func send(_ text: String, context: LAContext? = nil) async throws -> String {
        let response = try await send(Data(text.utf8), context: context)
        return String(decoding: response, as: UTF8.self)
    }

    func send(_ data: Data, context: LAContext? = nil) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            let proxy =
                connection.remoteObjectProxyWithErrorHandler {
                    continuation.resume(throwing: $0)
                } as! QuartermasterContextProtocol
            let reply: @Sendable (Data) -> Void = { continuation.resume(returning: $0) }
            if let context {
                proxy.authenticate(data, context: context, reply: reply)
            } else {
                proxy.send(data, reply: reply)
            }
        }
    }

    func cleanup() throws {
        try keys.reset()
        try require(try keys.existingPublicKey() == nil, "dummy approval key or enrolment remains")
    }

    func challenge(authenticated: MonotonicTimestamp, context: LAContext) async throws -> Data {
        try require(!authenticated.isZero && context.interactionNotAllowed, "controller did not freeze authentication")
        if config.case == "frontend-exit" {
            try require(try await send("hold", context: context) == "context", "context transfer failed")
            try require(try await send("finish") == "finished", "finish failed")
            // Exit without invalidating the source context; the backend must clear its own copy.
            _exit(0)
        }
        try require(try await send("unwrap", context: context) == "unwrapped", "backend unwrap failed")
        return message
    }

    func submit(_ signature: Data) async throws {
        let key = try P256.Signing.PublicKey(x963Representation: publicKey!)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        try require(key.isValidSignature(signature, for: message), "invalid signature")
        try require(!key.isValidSignature(signature, for: message + Data([0])), "signature accepted changed request")
        let context = LAContext()
        context.interactionNotAllowed = true
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: Data("Quartermaster development cache \(config.scope)".utf8),
            kSecAttrAccessGroup: config.cacheGroup, kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecUseDataProtectionKeychain: true, kSecUseAuthenticationContext: context,
        ]
        try require(
            SecItemCopyMatching(query as CFDictionary, nil) == errSecMissingEntitlement,
            "frontend accessed backend key group")
        try require(try await send("isolation") == "isolated", "backend accessed frontend key group")
        submitted = true
    }

    func cancel() {}

    func approve() async throws {
        publicKey = try keys.loadOrCreate()
        if config.case == "hardware" {
            let unauthenticated = LAContext()
            unauthenticated.interactionNotAllowed = true
            var denied = false
            do {
                _ = try keys.sign(message, expectedPublicKey: publicKey!, context: unauthenticated)
            } catch ApprovalKeyError.security {
                denied = true
            }
            try require(denied, "signing succeeded without authentication")
            try require(
                try await send("unauthenticated", context: unauthenticated) == "denied",
                "unauthenticated unwrap succeeded")
        }
        let request = try JSONDecoder().decode(
            DialogRequest.self,
            from: Data(
                #"{"repository":"quartermaster/demo","issue":42,"method":"PATCH","path":"/api/v3/repos/quartermaster/demo/issues/42","body":"{\"state\":\"closed\"}","processChain":["Integration test · disposable keys only"]}"#
                    .utf8))
        let provider = try JSONDecoder().decode(
            ApprovalProviderIdentity.self,
            from: Data(
                #"{"server":"https://vault.example.invalid","account":"dummy","email":"dummy@example.invalid","item":"dummy","field":"password","role":"github-write","enrollment":"disposable","generation":1}"#
                    .utf8))
        let presentation = ApprovalPresentation(request: request, provider: provider, readGrant: nil)
        let dialog = ApprovalDialog(presentation: presentation, backend: self, keys: keys)
        let controller = dialog.controller
        defer {
            dialog.onClose = nil
            dialog.window.close()
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            dialog.onClose = {
                if controller.phase == .approved && self.submitted {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: FixtureFailure.assertion("production approval did not complete"))
                }
            }
            NSApp.setActivationPolicy(.regular)
            dialog.window.center()
            dialog.window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }
        try require(controller.phase == .approved, "approval dialog closed without approval")
        try require(try await send("reuse") == "reused", "imported context lost approval before receiver cleanup")
        try require(try await send("invalidate") == "invalidated", "receiver invalidation failed")
    }

    func run() async throws {
        defer { connection.invalidate() }
        let rejected = "{\"kind\":\"error\",\"code\":\"unavailable\"}"
        try require(try await send("plain") == "plain", "plain message changed")
        if config.case == "transport" {
            let context = LAContext()
            context.interactionNotAllowed = true
            try require(try await send("first", context: context) == "context", "context transfer failed")
            try require(try await send("duplicate", context: context) == rejected, "duplicate context accepted")
            try require(try await send("release") == "released", "lease release failed")
            let second = LAContext()
            second.interactionNotAllowed = true
            try require(try await send("second", context: second) == "context", "replacement context failed")
            try require(
                try await send(Data(repeating: 120, count: 1024 * 1024 + 1)) == Data(rejected.utf8),
                "oversized request accepted"
            )
        } else {
            try await approve()
        }
        try require(try await send("finish") == "finished", "finish failed")
    }
}

@main
struct IPCClientMain {
    @MainActor
    static func main() {
        do {
            let path = URL(fileURLWithPath: CommandLine.arguments[1])
            let config = try JSONDecoder().decode(FixtureConfig.self, from: Data(contentsOf: path))
            let fixture = IPCFixture(config, directory: path.deletingLastPathComponent())
            if CommandLine.arguments.dropFirst(2).first == "--cleanup" {
                try fixture.cleanup()
                return
            }
            _ = NSApplication.shared
            DispatchQueue.global().asyncAfter(deadline: .now() + (config.case == "transport" ? 20 : 150)) {
                print("Integration test timed out")
                exit(124)
            }
            Task {
                do {
                    try await fixture.run()
                    print("Swift assertions passed: \(config.case)")
                    exit(0)
                } catch {
                    print("Swift assertion failed: \(error)")
                    exit(1)
                }
            }
            NSApp.run()
        } catch {
            print("Fixture setup failed: \(error)")
            exit(1)
        }
    }
}
