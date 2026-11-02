import Foundation
import QuartermasterSecurity

public struct CredentialHandoffRequest: Decodable {
    public struct Recipient: Decodable {
        public let pid: UInt32
        public let execution: String
        public let executable: String
        public let requirement: String
    }

    public enum Failure: Error { case invalidRequest }
    public let kind: String
    public let tool: String
    public let credentialName: String
    public let recipient: Recipient
    public let command: [String]
    public let workingDirectory: String
    public let requester: DialogPeer
    public let provider: ApprovalProviderIdentity
    public let created: MonotonicTimestamp
    public let operationId: String

    public static func parse(review: ApprovalReview) throws -> Self {
        _ = try AuthorizationWorkflow(review: review, now: .now)
        let request = try JSONDecoder().decode(Self.self, from: review.request)
        guard request.kind == "credentialHandoff", request.tool == "restic",
            !request.credentialName.isEmpty, request.recipient.pid > 0,
            !request.recipient.execution.isEmpty, !request.recipient.requirement.isEmpty,
            request.recipient.executable.hasPrefix("/"), request.command.first == request.recipient.executable,
            request.workingDirectory.hasPrefix("/"), request.requester.pid > 0,
            request.requester.executable.hasPrefix("/"), request.provider == review.provider,
            request.operationId == review.id, request.created == review.created
        else { throw Failure.invalidRequest }
        return request
    }

    var displayCredentialName: String { Self.escaped(credentialName) }
    var displayCommand: String { command.map { "\"\(Self.escaped($0))\"" }.joined(separator: " ") }

    var compactCommand: String {
        ([tool] + command.dropFirst()).map { argument in
            let escaped = Self.escaped(argument)
            return !argument.isEmpty
                && argument.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "-_/.:=".contains($0)) }
                ? escaped : "\"\(escaped)\""
        }.joined(separator: " ")
    }

    private var callerProcesses: [DialogProcess] {
        if let processes = requester.processes, !processes.isEmpty { return processes }
        return [
            DialogProcess(
                pid: requester.pid, name: URL(fileURLWithPath: requester.executable).lastPathComponent,
                executable: requester.executable, limited: false, startedUnixMicros: requester.startedUnixMicros)
        ]
    }

    func callerRows(shimExecutable: String? = Bundle.main.url(forAuxiliaryExecutable: "qm")?.path) -> [ProcessTreeRow] {
        let rows = ProcessTreeRow.make(
            processes: callerProcesses.map {
                DialogProcess(
                    pid: $0.pid, name: Self.escaped($0.name), executable: $0.executable,
                    limited: $0.limited, startedUnixMicros: $0.startedUnixMicros)
            }, peerPID: recipient.pid, roots: [], allowsSelection: false, shimExecutable: shimExecutable)
        if !rows.isEmpty { return rows }
        return ProcessTreeRow.make(
            processes: [
                DialogProcess(
                    pid: requester.pid,
                    name: Self.escaped(URL(fileURLWithPath: requester.executable).lastPathComponent),
                    executable: requester.executable, limited: false, startedUnixMicros: requester.startedUnixMicros)
            ],
            peerPID: requester.pid, roots: [], allowsSelection: false, shimExecutable: nil)
    }

    var releaseSummary: String {
        "Release this password once. Restic can retain or copy it; later operations are not controlled by Quartermaster."
    }

    func processRows(shimExecutable: String? = Bundle.main.url(forAuxiliaryExecutable: "qm")?.path) -> [ProcessTreeRow]
    {
        callerRows(shimExecutable: shimExecutable) + [
            ProcessTreeRow(
                process: DialogProcess(
                    pid: recipient.pid, name: tool, executable: recipient.executable, limited: false),
                choice: nil, label: "On approval", duration: "", scopeOffered: false, isProjected: true)
        ]
    }

    var approvalDetails: String {
        """
        Permission: Release password once
        Vault item: \(displayCredentialName)

        Recipient\n\(Self.escaped(recipient.executable)) · PID \(recipient.pid)
        Execution: \(Self.escaped(recipient.execution))
        Signature: \(Self.escaped(recipient.requirement))

        \(releaseSummary)

        Vault\n\(Self.escaped(provider.email))\n\(Self.escaped(provider.server))
        Account: \(Self.escaped(provider.account))
        Item: \(Self.escaped(provider.item))
        Field: \(Self.escaped(provider.field))
        Role: \(Self.escaped(provider.role))
        Enrolment: \(Self.escaped(provider.enrollment)) · generation \(provider.generation)
        """
    }

    var callerDetails: String {
        let ancestry = callerProcesses.map {
            "\(Self.escaped($0.name)) · PID \($0.pid)\($0.limited ? " · limited information" : "")\n\(Self.escaped($0.executable ?? "Executable unavailable"))\nStarted: \(processStarted($0.startedUnixMicros))"
        }.joined(separator: "\n\n")
        return """
            Command\n\(Self.escaped(requester.commandLine ?? "Command arguments unavailable"))

            Working directory\n\(Self.escaped(requester.workingDirectory ?? workingDirectory))

            Executable\n\(Self.escaped(requester.executable)) · PID \(requester.pid)
            Started: \(processStarted(requester.startedUnixMicros))

            Signature\n\(requester.adHoc ? "Ad-hoc" : "Team ID: \(Self.escaped(requester.teamIdentifier ?? "None"))")
            Signing identifier: \(Self.escaped(requester.signingIdentifier))
            CDHash: \(Self.escaped(requester.cdHash))

            Caller ancestry\n\(ancestry)
            \(requester.ancestryNote.map(Self.escaped) ?? "")
            """
    }

    var commandDetails: String {
        "Command\n\(displayCommand)\n\nWorking directory\n\(Self.escaped(workingDirectory))"
    }

    var fullDetails: String { [approvalDetails, callerDetails, commandDetails].joined(separator: "\n\n") }

    static func escaped(_ text: String) -> String { escapeApprovalText(text) }
}
