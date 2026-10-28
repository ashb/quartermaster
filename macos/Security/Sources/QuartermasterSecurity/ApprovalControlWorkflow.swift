@MainActor
public final class ApprovalControlWorkflow {
    public enum Phase { case idle, operation, revocationQueued, revoking }
    public private(set) var phase: Phase = .idle
    private var pendingRevocations: [@MainActor () async -> Void] = []
    public var busy: Bool { phase != .idle }

    public init() {}

    public func perform(_ operation: @MainActor () async -> Void) async {
        guard !busy else { return }
        phase = .operation
        await operation()
        await drainRevocations()
    }

    public func revokeReadAccess(
        cancelApproval: @MainActor () -> Void,
        revoke: @escaping @MainActor () async -> Void
    ) async {
        cancelApproval()
        switch phase {
        case .operation, .revocationQueued:
            pendingRevocations.append(revoke)
            phase = .revocationQueued
        case .revoking:
            pendingRevocations.append(revoke)
        case .idle:
            phase = .revoking
            await revoke()
            await drainRevocations()
        }
    }

    private func drainRevocations() async {
        while !pendingRevocations.isEmpty {
            let revoke = pendingRevocations.removeFirst()
            phase = .revoking
            await revoke()
        }
        phase = .idle
    }

}
