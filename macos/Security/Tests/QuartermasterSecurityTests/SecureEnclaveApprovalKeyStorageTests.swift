import Foundation
import Security
import Testing

@testable import QuartermasterSecurity

@Test func scopedApprovalKeysAndEnrollmentUseOnlyTheirSelectedKeychainGroup() {
    let first = SecureEnclaveApprovalKeyStorage(
        namespace: "dev.quartermaster.test.first", accessGroup: "TEAM.first",
        lockDirectory: URL(fileURLWithPath: "/unused/first"))
    let second = SecureEnclaveApprovalKeyStorage(
        namespace: "dev.quartermaster.test.second", accessGroup: "TEAM.second",
        lockDirectory: URL(fileURLWithPath: "/unused/second"))

    #expect(first.keyQuery[kSecAttrApplicationTag] as? Data == Data("dev.quartermaster.test.first".utf8))
    #expect(second.keyQuery[kSecAttrApplicationTag] as? Data == Data("dev.quartermaster.test.second".utf8))
    #expect(first.enrollmentQuery[kSecAttrService] as? String == "dev.quartermaster.test.first.enrollment")
    #expect(second.enrollmentQuery[kSecAttrService] as? String == "dev.quartermaster.test.second.enrollment")
    for query in [first.keyQuery, first.enrollmentQuery] {
        #expect(query[kSecAttrAccessGroup] as? String == "TEAM.first")
        #expect(query[kSecUseDataProtectionKeychain] as? Bool == true)
    }
    for query in [second.keyQuery, second.enrollmentQuery] {
        #expect(query[kSecAttrAccessGroup] as? String == "TEAM.second")
    }
}

@Test func defaultApprovalKeyLocationPreservesExistingEnrollment() {
    let storage = SecureEnclaveApprovalKeyStorage()

    #expect(storage.keyQuery[kSecAttrApplicationTag] as? Data == Data("dev.quartermaster.approval.debug.v1".utf8))
    #expect(storage.enrollmentQuery[kSecAttrService] as? String == "dev.quartermaster.approval.debug.enrollment.v1")
    #expect(storage.keyQuery[kSecAttrAccessGroup] == nil)
    #expect(storage.enrollmentQuery[kSecAttrAccessGroup] == nil)
}
