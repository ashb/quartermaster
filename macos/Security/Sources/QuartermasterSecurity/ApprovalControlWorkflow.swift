@MainActor
public final class ApprovalControlWorkflow {
    public enum Phase { case idle, operation, revocationQueued, revoking }
    public private(set) var phase: Phase = .idle
    private var pendingRevocation: (@MainActor () async -> Void)?
    public var busy: Bool { phase != .idle }

    public init() {}

    public func perform(_ operation: @MainActor () async -> Void) async {
        guard !busy else { return }
        phase = .operation
        await operation()
        if let revoke = pendingRevocation {
            pendingRevocation = nil
            phase = .revoking
            await revoke()
        }
        phase = .idle
    }

    public func revokeReadAccess(
        cancelApproval: @MainActor () -> Void,
        revoke: @escaping @MainActor () async -> Void
    ) async {
        cancelApproval()
        switch phase {
        case .operation, .revocationQueued:
            pendingRevocation = revoke
            phase = .revocationQueued
        case .revoking:
            break
        case .idle:
            phase = .revoking
            await revoke()
            phase = .idle
        }
    }
}
