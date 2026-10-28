import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import QuartermasterApprovalUI
import QuartermasterIPC
import QuartermasterSecurity
import Security
import Synchronization

enum BrokerFailure: Error { case invalidCode, invalidMessage, disconnected, timeout }

protocol BrokerClient: AnyObject, Sendable {
    var disconnected: Bool { get }
    func cancel()
    @MainActor func call(_ command: BrokerCommand, context: LAContext?) async throws -> BrokerReply
}

extension BrokerClient {
    @MainActor func call(_ command: BrokerCommand) async throws -> BrokerReply {
        try Task.checkCancellation()
        let reply: Result<BrokerReply, any Error>
        do { reply = .success(try await call(command, context: nil)) } catch { reply = .failure(error) }
        try Task.checkCancellation()
        return try reply.get()
    }
}

final class BrokerConnection: BrokerClient, @unchecked Sendable {
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

    @MainActor
    static func connect() async throws -> BrokerConnection {
        try Task.checkCancellation()
        let executable = executable
        try await Task.detached {
            let process = Process()
            process.executableURL = executable
            process.arguments = ["start"]
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw BrokerFailure.disconnected }
        }.value
        try Task.checkCancellation()
        return try BrokerConnection()
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
            let remote = connection.remoteObjectProxyWithErrorHandler { @Sendable _ in
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
    let reviewCreated: MonotonicTimestamp
    let client: any BrokerClient
    let id: String
    let request: DialogRequest
    let provider: ApprovalProviderIdentity
    let readGrant: ReadGrantReview?
    let apiRequest: APIRequestReview?
    private var workflow: AuthorizationWorkflow

    init(client: any BrokerClient, review: ApprovalReview) throws {
        workflow = try AuthorizationWorkflow(review: review, now: .now)
        reviewCreated = review.created
        let id = review.id
        let bytes = review.request
        let request = try JSONDecoder().decode(DialogRequest.self, from: bytes)
        let readGrant = try ReadGrantReview.parse(
            request: bytes, role: review.provider.role, uid: geteuid(), now: Date())
        let apiRequest = try APIRequestReview.parse(request: bytes)
        guard request.peer != nil, !request.processChain.isEmpty, request.processChain.count <= 6 else {
            throw BrokerFailure.invalidMessage
        }
        guard readGrant != nil || apiRequest != nil else { throw BrokerFailure.invalidMessage }
        self.client = client
        self.id = id
        self.request = request
        self.provider = review.provider
        self.readGrant = readGrant
        self.apiRequest = apiRequest
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

@MainActor
final class SettingsPending: ApprovalBackend {
    let reviewCreated: MonotonicTimestamp
    private let client: any BrokerClient
    private let id: String
    private var workflow: SettingsWorkflow
    var document: SettingsDocument { workflow.document }

    init(client: any BrokerClient, review: SettingsReview) throws {
        guard let key = try ApprovalKeyStore().existingPublicKey() else { throw ApprovalKeyError.missingEnrolledKey }
        workflow = try SettingsWorkflow(review: review, expectedKey: key, now: .now)
        reviewCreated = review.created
        self.client = client
        id = review.id
    }

    func challenge(authenticated: MonotonicTimestamp, context: LAContext) async throws -> Data {
        try workflow.recordAuthentication(at: authenticated, now: .now)
        guard
            case .settingsChallenge(let challenge) = try await client.call(
                .settingsPresence(id: id, authenticated: authenticated), context: context)
        else { throw BrokerFailure.invalidMessage }
        return try workflow.validate(challenge, now: .now)
    }

    func submit(_ signature: Data) async throws {
        try workflow.checkSubmission(now: .now)
        guard case .settingsApplied = try await client.call(.settingsProof(id: id, signature: signature)) else {
            throw BrokerFailure.invalidMessage
        }
    }

    func cancel() {
        workflow.cancel()
        Task { _ = try? await client.call(.settingsCancel(id: id)) }
    }
}
