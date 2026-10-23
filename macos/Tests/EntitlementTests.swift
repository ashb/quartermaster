import Foundation
import Testing

@Test(arguments: [
    ("Quartermaster.entitlements", "$(AppIdentifierPrefix)dev.quartermaster.phase0"),
    ("Backend.entitlements", "$(AppIdentifierPrefix)dev.quartermaster.cache.debug"),
])
func eachRoleHasOnlyItsOwnKeychainEntitlement(filename: String, group: String) throws {
    let environment = ProcessInfo.processInfo.environment
    let root = try #require(environment["TEST_SRCDIR"])
    let workspace = try #require(environment["TEST_WORKSPACE"])
    let url = URL(fileURLWithPath: root)
        .appending(path: workspace)
        .appending(path: "macos/Quartermaster")
        .appending(path: filename)
    let document = try PropertyListSerialization.propertyList(
        from: Data(contentsOf: url), options: [], format: nil)

    #expect(document as? [String: [String]] == ["keychain-access-groups": [group]])
}
