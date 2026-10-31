import Luminare
import QuartermasterApprovalUI
import QuartermasterSecurity
import SwiftUI

private let preferencesAccent = ApprovalAppearance.accent

struct PreferencesGitHubIcon: View {
    var body: some View {
        if let icon = NSImage(named: "GitHub") {
            Image(nsImage: icon).resizable().scaledToFit()
        } else {
            Image(systemName: "terminal").resizable().scaledToFit().foregroundStyle(preferencesAccent)
        }
    }
}

struct PreferencesGroup<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title).font(.system(size: 14, weight: .semibold))
            LuminareSection {
                VStack(alignment: .leading, spacing: 7) { content }
                    .font(.system(size: 12))
                    .padding(.horizontal, 10).padding(.vertical, 7)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}

struct PreferencesField<Content: View>: View {
    let title: String
    var labelWidth: CGFloat = 85
    @ViewBuilder var content: Content

    var body: some View {
        HStack(spacing: 16) {
            Text(title).frame(width: labelWidth, alignment: .leading)
            content.textFieldStyle(.roundedBorder)
        }
    }
}

struct PreferencesGrantCard: View {
    let grant: ReadGrantReview
    let revoke: () -> Void
    @State private var showingDetails = false

    var body: some View {
        LuminareSection {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 10) {
                    PreferencesGitHubIcon().frame(width: 20, height: 20)
                    Text(verbatim: grant.repository).font(.system(size: 14, weight: .semibold))
                    Spacer()
                    Text("Read only").font(.system(size: 10, weight: .medium)).foregroundStyle(.teal)
                        .padding(.horizontal, 8).padding(.vertical, 4).background(.teal.opacity(0.1), in: Capsule())
                }
                HStack(spacing: 8) {
                    Image(systemName: grant.root.scope == .process ? "terminal" : "terminal.fill")
                        .foregroundStyle(preferencesAccent)
                    Text(verbatim: URL(fileURLWithPath: grant.root.executable).lastPathComponent)
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                    Text("PID \(grant.root.pid)").font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text(grant.processScopeName).foregroundStyle(.secondary)
                }.font(.system(size: 12))
                HStack(spacing: 8) {
                    Image(systemName: "clock").foregroundStyle(.secondary)
                    TimelineView(.periodic(from: .now, by: 60)) { context in
                        let minutes = max(0, Int(ceil(grant.expires.timeIntervalSince(context.date) / 60)))
                        Text(minutes == 0 ? "Expired" : "\(minutes) min remaining")
                            .foregroundStyle(.secondary)
                    }.help(grant.lifetimeDescription)
                    Spacer()
                    Button(showingDetails ? "Hide details" : "Details") { showingDetails.toggle() }
                        .buttonStyle(.plain)
                    Button("Revoke", action: revoke).buttonStyle(CompactButtonStyle())
                }.font(.system(size: 11))
                if showingDetails {
                    Divider()
                    VStack(alignment: .leading, spacing: 6) {
                        Text(verbatim: grant.root.executable).font(.caption.monospaced())
                        Text(grant.scopeName).font(.caption.weight(.medium))
                        Text(grant.summary).font(.caption).foregroundStyle(.secondary)
                        Text(grant.lifetimeDescription).font(.caption).foregroundStyle(.secondary)
                    }.textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                }
            }.padding(.horizontal, 12).padding(.top, 10).padding(.bottom, 6)
        }
    }
}
