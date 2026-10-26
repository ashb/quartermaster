import SwiftUI

public struct DisclosureSection<Content: View>: View {
    private let title: String
    private let content: Content
    private let expansion: Binding<Bool>?
    @State private var expanded = false

    public init(_ title: String, isExpanded: Binding<Bool>? = nil, @ViewBuilder content: () -> Content) {
        self.title = title
        expansion = isExpanded
        self.content = content()
    }

    private var isExpanded: Binding<Bool> { expansion ?? $expanded }

    public var body: some View {
        DisclosureGroup(isExpanded: isExpanded) {
            content
        } label: {
            Button {
                isExpanded.wrappedValue.toggle()
            } label: {
                Text(verbatim: title)
            }.buttonStyle(.plain)
        }
    }
}
