import Testing

@testable import QuartermasterSecurity

@Test @MainActor func revocationCancelsAnActiveApprovalAndRunsItsBackendOperation() async {
    let workflow = ApprovalControlWorkflow()
    var approvalVisible = true
    var revoked = false
    await workflow.revokeReadAccess(
        cancelApproval: { approvalVisible = false },
        revoke: {
            #expect(!approvalVisible)
            #expect(workflow.busy)
            revoked = true
        })
    #expect(revoked)
    #expect(!workflow.busy)
}

@Test @MainActor func revocationWaitsForAnExistingControlOperationAndBlocksPolling() async {
    let workflow = ApprovalControlWorkflow()
    var calls: [String] = []
    await workflow.perform {
        calls.append("operation")
        await workflow.revokeReadAccess(
            cancelApproval: { calls.append("cancel") },
            revoke: {
                calls.append("revoke")
                #expect(workflow.phase == .revoking)
            })
        #expect(workflow.phase == .revocationQueued)
        await workflow.perform { calls.append("must not run") }
        calls.append("operation completed")
    }
    #expect(calls == ["operation", "cancel", "operation completed", "revoke"])
    #expect(!workflow.busy)
}

@Test @MainActor func targetedRevocationsAreNotLostWhileAnotherOperationOrRevocationWaits() async {
    let workflow = ApprovalControlWorkflow()
    var revoked: [String] = []
    await workflow.perform {
        await workflow.revokeReadAccess(cancelApproval: {}) {
            revoked.append("first")
            await workflow.revokeReadAccess(cancelApproval: {}) { revoked.append("third") }
        }
        await workflow.revokeReadAccess(cancelApproval: {}) { revoked.append("second") }
    }
    #expect(revoked == ["first", "second", "third"])
    #expect(!workflow.busy)
}
