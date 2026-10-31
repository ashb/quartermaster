import AppKit
import Luminare
import SwiftUI

public enum ApprovalAppearance {
    public static let accent = Color(red: 0.38, green: 0.36, blue: 0.88)

    @MainActor static var githubIcon: NSImage? { NSImage(named: "GitHub") }
}

struct GitHubIcon: View {
    var size: CGFloat = 24

    var body: some View {
        Group {
            if let icon = ApprovalAppearance.githubIcon {
                Image(nsImage: icon).resizable().renderingMode(.template).scaledToFit()
            } else {
                Image(systemName: "terminal").resizable().scaledToFit()
            }
        }.frame(width: size, height: size)
    }
}

public struct CompactButtonStyle: PrimitiveButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        Button(role: configuration.role, action: configuration.trigger) {
            configuration.label.padding(.horizontal, 12)
        }
        .buttonStyle(.luminare)
        .fixedSize()
    }
}
