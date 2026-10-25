import SwiftUI

struct PreferencesGroup<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline).padding(.leading, 2)
            VStack(alignment: .leading, spacing: 11) { content }
                .padding(13)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.quinary, in: RoundedRectangle(cornerRadius: 8))
                .overlay { RoundedRectangle(cornerRadius: 8).strokeBorder(.quaternary) }
        }
    }
}

struct PreferencesField<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content

    var body: some View {
        HStack(spacing: 16) {
            Text(title).frame(width: 85, alignment: .leading)
            content.textFieldStyle(.roundedBorder)
        }
    }
}
