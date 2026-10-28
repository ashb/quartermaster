import AppKit
import Foundation
import QuartermasterApprovalUI
import QuartermasterSecurity
import Testing

@testable import Quartermaster

@MainActor private func preferencesEditor() throws -> SettingsEditor {
    let snapshot = try JSONDecoder().decode(
        SettingsSnapshot.self,
        from: Data(
            """
            {"state":"configured","revision":4,"session":"AQEBAQEBAQEBAQEBAQEBAQ==","settings":{"mutations":"deny"},"provider":null,"migration":null}
            """.utf8))
    return SettingsEditor { command in
        if case .settingsCancel = command { return .canceled }
        return .settingsStatus(snapshot)
    }
}

@Test @MainActor func theRealReviewActionRejectsACachedSessionWhenItsConnectionIsGone() async throws {
    let application = BrokerApplication()
    let editor = try preferencesEditor()
    application.preferences = editor
    await editor.load()
    editor.draft.mutations = .requireApproval
    #expect(editor.canReview)
    application.reviewPreferences()
    #expect(!editor.canReview)
    #expect(editor.message.contains("disconnected"))
}

@Test @MainActor func closingSettingsDiscardsItsDraft() async throws {
    var policy: NSApplication.ActivationPolicy?
    let application = BrokerApplication(setActivationPolicy: { policy = $0 })
    let editor = try preferencesEditor()
    application.preferences = editor
    await editor.load()
    editor.draft.mutations = .requireApproval
    #expect(editor.canReview)
    application.settingsClosed()
    #expect(editor.draft.mutations == .deny)
    #expect(!editor.canReview)
    #expect(policy == .accessory)
}

@MainActor final class InertApprovalWindow: ApprovalWindow {
    var onClose: (() -> Void)?
    private(set) var cancelled = false
    private(set) var isPresented = false

    func show(centred: Bool) { isPresented = true }

    func cancel() {
        cancelled = true
        close()
    }

    func close() {
        isPresented = false
        onClose?()
    }
}

@Test @MainActor func closingSettingsPreservesAnApprovalAndRequestsRegularActivation() {
    var policy: NSApplication.ActivationPolicy?
    let application = BrokerApplication(setActivationPolicy: { policy = $0 })
    let approval = InertApprovalWindow()
    application.present(approval)
    #expect(policy == .regular)
    application.settingsClosed()
    #expect(approval.isPresented)
    #expect(!approval.cancelled)
    #expect(policy == .regular)
    approval.close()
    #expect(policy == .accessory)
}

@Test @MainActor func completingAnImportRefreshesTheApplicationsMigrationStatus() async throws {
    let pending = try JSONDecoder().decode(
        SettingsSnapshot.self,
        from: Data(
            #"{"state":"migrationRequired","revision":4,"session":"AQEBAQEBAQEBAQEBAQEBAQ==","settings":null,"provider":null,"migration":{"source":{"id":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","fromFormat":"unsignedV1","toFormat":"signedV1"},"revision":4,"settings":{"github":null,"mutations":"deny"},"provider":null}}"#
                .utf8))
    let applied = try JSONDecoder().decode(
        SettingsSnapshot.self,
        from: Data(
            #"{"state":"configured","revision":5,"session":"AQEBAQEBAQEBAQEBAQEBAQ==","settings":{"github":null,"mutations":"deny"},"provider":null,"migration":null}"#
                .utf8))
    var reads = 0
    let application = BrokerApplication()
    application.preferences = SettingsEditor { _ in
        reads += 1
        return .settingsStatus(reads == 1 ? pending : applied)
    }
    await application.reloadPreferences()
    #expect(application.preferences.canImport)
    #expect(application.status.contains("Settings import required"))
    await application.reloadPreferences()
    #expect(application.preferences.snapshot?.revision == 5)
    #expect(!application.preferences.canImport)
    #expect(application.status == "Connected")
}

@MainActor private final class MigrationWindow: NSWindow {
    private(set) var closeRequests = 0
    override func performClose(_ sender: Any?) { closeRequests += 1 }
}

@Test @MainActor func postponingMigrationClosesItsSettingsWindowAndPreservesTheCandidate() async throws {
    let snapshot = try JSONDecoder().decode(
        SettingsSnapshot.self,
        from: Data(
            #"{"state":"migrationRequired","revision":4,"session":"AQEBAQEBAQEBAQEBAQEBAQ==","settings":null,"provider":null,"migration":{"source":{"id":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","fromFormat":"unsignedV1","toFormat":"signedV1"},"revision":4,"settings":{"github":null,"mutations":"deny"},"provider":null}}"#
                .utf8))
    var commands = 0
    let application = BrokerApplication(
        setActivationPolicy: { _ in }, openConnection: { throw CancellationError() })
    application.preferences = SettingsEditor { _ in
        commands += 1
        return .settingsStatus(snapshot)
    }
    await application.preferences.load()
    let window = MigrationWindow(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: true)
    application.settingsOpened(window)
    application.postponeMigration()
    #expect(window.closeRequests == 1)
    #expect(application.preferences.snapshot?.migration == snapshot.migration)
    #expect(!application.preferences.canReview)
    #expect(commands == 1)
}
