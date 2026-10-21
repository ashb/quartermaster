import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import QuartermasterIPC
import QuartermasterSecurity
import Security
import Synchronization

struct BrokerMessage: Encodable, Sendable {
    let kind: String
    var id: String? = nil
    var publicKey: Data? = nil
    var authenticated: MonotonicTimestamp? = nil
    var signature: Data? = nil
    var server: String? = nil
    var email: String? = nil
    var password: String? = nil
    var itemId: String? = nil
}

struct VaultBinding: Decodable, Sendable {
    let server: String
    let email: String
    let account_id: String
    let item_id: String
    let role: String
}

struct BrokerReply: Decodable, Sendable {
    let kind: String
    let profile: String?
    let id: String?
    let created: MonotonicTimestamp?
    let session: Data?
    let policy: Data?
    let requestDigest: Data?
    let credentialDigest: Data?
    let request: Data?
    let challenge: Data?
    let state: String?
    let error: String?
    let binding: VaultBinding?
    let lastSync: Date?
    let approval: ApprovalReview?
    let authorization: ApprovalChallenge?
}

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
    func call(_ fields: BrokerMessage, context: LAContext? = nil) async throws -> BrokerReply {
        let bytes = try JSONEncoder().encode(fields)
        guard bytes.count <= 16384, !disconnected else { throw BrokerFailure.disconnected }
        return try await withCheckedThrowingContinuation { continuation in
            let completion = Mutex<CheckedContinuation<BrokerReply, any Error>?>(continuation)
            let timeout: Double =
                fields.kind.hasPrefix("vault") && fields.kind != "vaultStatus" ? 120 : (context == nil ? 5 : 30)
            queue.asyncAfter(deadline: .now() + timeout) { [self] in
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
                    guard data.count <= 16384 else { throw BrokerFailure.invalidMessage }
                    let decoder = JSONDecoder()
                    decoder.dateDecodingStrategy = .secondsSince1970
                    let reply = try decoder.decode(BrokerReply.self, from: data)
                    guard reply.kind != "error" else { throw BrokerFailure.invalidMessage }
                    pending.resume(returning: reply)
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

    init(client: BrokerConnection, reply: BrokerReply) throws {
        guard reply.kind == "review", let review = reply.approval else { throw BrokerFailure.invalidMessage }
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
            BrokerMessage(kind: "presence", id: id, authenticated: authenticated), context: context)
        guard reply.kind == "challenge", let authorization = reply.authorization else {
            throw BrokerFailure.invalidMessage
        }
        return try workflow.validate(authorization, now: .now)
    }

    func submit(_ signature: Data) async throws {
        try workflow.checkSubmission(now: .now)
        let reply = try await client.call(BrokerMessage(kind: "proof", id: id, signature: signature))
        guard reply.kind == "accepted" else { throw BrokerFailure.invalidMessage }
    }

    func cancel() {
        workflow.cancel()
        Task { _ = try? await client.call(BrokerMessage(kind: "cancel", id: id)) }
    }
}
