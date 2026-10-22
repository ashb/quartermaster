import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import QuartermasterIPC
import QuartermasterSecurity
import Security
import Synchronization

enum BrokerFailure: Error { case invalidCode, invalidMessage, disconnected, timeout }

final class BrokerConnection: @unchecked Sendable {
    private final class State: Sendable {
        let lost = Mutex(false)
    }
    static let service = "dev.quartermaster.debug.backend"
    let connection: NSXPCConnection
    let queue = DispatchQueue(label: "dev.quartermaster.debug.ui-xpc")
    private let state = State()
    var disconnected: Bool { state.lost.withLock { $0 } }

    static var executable: URL {
        Bundle.main.bundleURL.appendingPathComponent(
            "Contents/Helpers/QuartermasterBackend.app/Contents/MacOS/quartermasterd")
    }

    static func requirement(for path: URL) throws -> String {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(path as CFURL, SecCSFlags(), &code) == errSecSuccess, let code else {
            throw BrokerFailure.invalidCode
        }
        var information: CFDictionary?
        guard
            SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
                == errSecSuccess,
            let information = information as? [String: Any],
            let hash = information[kSecCodeInfoUnique as String] as? Data,
            [20, 32].contains(hash.count)
        else { throw BrokerFailure.invalidCode }
        let text = "cdhash H\"" + hash.map { String(format: "%02x", $0) }.joined() + "\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, SecCSFlags(), &requirement) == errSecSuccess,
            SecStaticCodeCheckValidity(
                code, SecCSFlags(rawValue: kSecCSStrictValidate | SecCSFlags.noNetworkAccess.rawValue), requirement)
                == errSecSuccess
        else {
            throw BrokerFailure.invalidCode
        }
        return text
    }

    init() throws {
        let requirement = try Self.requirement(for: Self.executable)
        connection = NSXPCConnection(machServiceName: Self.service)
        connection.remoteObjectInterface = qm_context_interface()
        let state = self.state
        connection.interruptionHandler = { state.lost.withLock { $0 = true } }
        connection.invalidationHandler = { state.lost.withLock { $0 = true } }
        connection.setCodeSigningRequirement(requirement)
        connection.resume()
    }

    func cancel() {
        state.lost.withLock { $0 = true }
        connection.invalidate()
    }
    deinit { connection.invalidate() }

    @MainActor
    func call(_ command: BrokerCommand, context: LAContext? = nil) async throws -> BrokerReply {
        let bytes = try command.encoded()
        guard !disconnected else { throw BrokerFailure.disconnected }
        return try await withCheckedThrowingContinuation { continuation in
            let completion = Mutex<CheckedContinuation<BrokerReply, any Error>?>(continuation)
            queue.asyncAfter(deadline: .now() + command.timeout) { [self] in
                if let pending = completion.withLock({ value in
                    defer { value = nil }
                    return value
                }) {
                    cancel()
                    pending.resume(throwing: BrokerFailure.timeout)
                }
            }
            let remote = connection.remoteObjectProxyWithErrorHandler { _ in
                if let pending = completion.withLock({ value in
                    defer { value = nil }
                    return value
                }) {
                    pending.resume(throwing: BrokerFailure.disconnected)
                }
            }
            guard let remote = remote as? QuartermasterContextProtocol else {
                if let pending = completion.withLock({ value in
                    defer { value = nil }
                    return value
                }) {
                    pending.resume(throwing: BrokerFailure.invalidMessage)
                }
                return
            }
            let receive: @Sendable (Data) -> Void = { data in
                guard
                    let pending = completion.withLock({ value in
                        defer { value = nil }
                        return value
                    })
                else { return }
                do {
                    pending.resume(returning: try BrokerReply.decodeSuccess(data))
                } catch { pending.resume(throwing: error) }
            }
            if let context {
                remote.authenticate(bytes, context: context, reply: receive)
            } else {
                remote.send(bytes, reply: receive)
            }
        }
    }

}

@MainActor
final class BrokerPending: ApprovalBackend {
    let client: BrokerConnection
    let id: String
    let request: DialogRequest
    let provider: ApprovalProviderIdentity
    let readGrant: ReadGrantReview?
    private var workflow: AuthorizationWorkflow

    init(client: BrokerConnection, review: ApprovalReview) throws {
        workflow = try AuthorizationWorkflow(review: review, now: .now)
        let id = review.id
        let bytes = review.request
        let request = try JSONDecoder().decode(DialogRequest.self, from: bytes)
        let readGrant = try ReadGrantReview.parse(
            request: bytes, role: review.provider.role, uid: geteuid(), now: Date())
        guard request.peer != nil, !request.processChain.isEmpty, request.processChain.count <= 6 else {
            throw BrokerFailure.invalidMessage
        }
        if readGrant == nil {
            guard request.repository == "quartermaster/demo", request.issue == 42, request.method == "PATCH",
                request.path == "/api/v3/repos/quartermaster/demo/issues/42", request.body == "{\"state\":\"closed\"}",
                request.origin == "https://github.example.invalid"
            else { throw BrokerFailure.invalidMessage }
        }
        self.client = client
        self.id = id
        self.request = request
        self.provider = review.provider
        self.readGrant = readGrant
    }

    func challenge(authenticated: MonotonicTimestamp, context: LAContext) async throws -> Data {
        try workflow.recordAuthentication(at: authenticated, now: .now)
        let reply = try await client.call(
            .presence(id: id, authenticated: authenticated), context: context)
        guard case .challenge(let authorization) = reply else {
            throw BrokerFailure.invalidMessage
        }
        return try workflow.validate(authorization, now: .now)
    }

    func submit(_ signature: Data) async throws {
        try workflow.checkSubmission(now: .now)
        let reply = try await client.call(.proof(id: id, signature: signature))
        guard case .accepted = reply else { throw BrokerFailure.invalidMessage }
    }

    func cancel() {
        workflow.cancel()
        Task { _ = try? await client.call(.cancel(id: id)) }
    }
}
