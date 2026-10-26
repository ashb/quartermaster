import AppKit
import Foundation
import QuartermasterSecurity
import Testing

@testable import Quartermaster

@MainActor private func preferencesEditor() throws -> SettingsEditor {
    let snapshot = try JSONDecoder().decode(
        SettingsSnapshot.self,
        from: Data(
            """
            {"state":"configured","revision":4,"session":"AQEBAQEBAQEBAQEBAQEBAQ==","settings":{"mutations":"deny"},"provider":null,"retained":[]}
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

@Test @MainActor func closingTheNativeSettingsWindowDiscardsItsDraft() async throws {
    _ = NSApplication.shared
    let application = BrokerApplication()
    let editor = try preferencesEditor()
    application.preferences = editor
    await editor.load()
    editor.draft.mutations = .requireApproval
    let window = NSWindow(
        contentRect: NSRect(x: 0, y: 0, width: 100, height: 100), styleMask: [.titled], backing: .buffered, defer: false
    )
    window.isReleasedWhenClosed = false
    window.contentView = PreferencesWindowObserver(opened: {}, closed: application.settingsClosed)
    #expect(editor.canReview)
    window.close()
    #expect(editor.draft.mutations == .deny)
    #expect(!editor.canReview)
    #expect(NSApplication.shared.activationPolicy() == .accessory)
}
