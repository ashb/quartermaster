import CryptoKit
import Foundation
import LocalAuthentication
import Testing
@testable import QuartermasterSecurity

final class MemoryKeyStorage: ApprovalKeyStorage {
    var key: Data?
    var pin: Data?
    var lookupFailure: ApprovalKeyError?
    var saveFailure: ApprovalKeyError?
    var deleteFailure: ApprovalKeyError?
    var creations = 0
    var signatures = 0
    var messages: [Data] = []

    func withExclusiveAccess<T>(_ body: () throws -> T) throws -> T { try body() }
    func publicKey() throws -> Data? {
        if let lookupFailure { throw lookupFailure }
        return key
    }
    func create() throws -> Data {
        creations += 1
        let bytes = P256.Signing.PrivateKey().publicKey.x963Representation
        key = bytes
        return bytes
    }
    func enrollment() throws -> Data? { pin }
    func saveEnrollment(_ publicKey: Data) throws {
        if let saveFailure { throw saveFailure }
        pin = publicKey
    }
    func deleteKey() throws {
        if let deleteFailure { throw deleteFailure }
        key = nil
    }
    func deleteEnrollment() throws { pin = nil }
    func sign(_ message: Data, context: LAContext) throws -> Data {
        signatures += 1
        messages.append(message)
        return Data([1])
    }
}

@Test func repeatedLoadsAndNewStoreInstancesReuseOneEnrolledKey() throws {
    let storage = MemoryKeyStorage()
    let first = try ApprovalKeyStore(storage: storage).loadOrCreate()
    let second = try ApprovalKeyStore(storage: storage).loadOrCreate()
    #expect(first == second)
    #expect(storage.pin == first)
    #expect(storage.creations == 1)
}

@Test func statusDoesNotCreateAKey() throws {
    let storage = MemoryKeyStorage()
    #expect(try ApprovalKeyStore(storage: storage).existingPublicKey() == nil)
    #expect(storage.creations == 0)
}

@Test func lookupErrorsCannotTriggerReplacement() {
    let storage = MemoryKeyStorage()
    storage.lookupFailure = .security("locked", errSecInteractionNotAllowed)
    #expect(throws: storage.lookupFailure!) { try ApprovalKeyStore(storage: storage).loadOrCreate() }
    #expect(storage.creations == 0)
}

@Test func missingEnrolledKeyRequiresExplicitReset() throws {
    let storage = MemoryKeyStorage()
    let store = ApprovalKeyStore(storage: storage)
    let original = try store.loadOrCreate()
    storage.key = nil
    #expect(throws: ApprovalKeyError.missingEnrolledKey) { try store.loadOrCreate() }
    #expect(storage.creations == 1)
    #expect(storage.pin == original)
    try store.reset()
    #expect(try store.loadOrCreate() != original)
    #expect(storage.creations == 2)
}

@Test func substitutedKeyCannotReplaceEnrollmentOrSign() throws {
    let storage = MemoryKeyStorage()
    let store = ApprovalKeyStore(storage: storage)
    let enrolled = try store.loadOrCreate()
    storage.key = P256.Signing.PrivateKey().publicKey.x963Representation
    #expect(throws: ApprovalKeyError.changedKey) { try store.loadOrCreate() }
    #expect(throws: ApprovalKeyError.changedKey) {
        try store.sign(Data([42]), expectedPublicKey: enrolled, context: LAContext())
    }
    #expect(storage.pin == enrolled)
    #expect(storage.signatures == 0)
}

@Test func interruptedEnrollmentRetainsAndRecoversTheCreatedKey() throws {
    let storage = MemoryKeyStorage()
    storage.saveFailure = .security("save", errSecNotAvailable)
    #expect(throws: storage.saveFailure!) { try ApprovalKeyStore(storage: storage).loadOrCreate() }
    let created = storage.key
    storage.saveFailure = nil
    #expect(try ApprovalKeyStore(storage: storage).loadOrCreate() == created)
    #expect(storage.pin == created)
    #expect(storage.creations == 1)
}

@Test func failedDeletionPreservesEnrollment() throws {
    let storage = MemoryKeyStorage()
    let store = ApprovalKeyStore(storage: storage)
    let enrolled = try store.loadOrCreate()
    storage.deleteFailure = .security("delete", errSecNotAvailable)
    #expect(throws: storage.deleteFailure!) { try store.reset() }
    #expect(storage.pin == enrolled)
    #expect(storage.key == enrolled)
}

@Test func oldApprovalCannotUseAResetKey() throws {
    let storage = MemoryKeyStorage()
    let store = ApprovalKeyStore(storage: storage)
    let enrolled = try store.loadOrCreate()
    try store.reset()
    _ = try store.loadOrCreate()
    #expect(throws: ApprovalKeyError.changedKey) {
        try store.sign(Data([42]), expectedPublicKey: enrolled, context: LAContext())
    }
    #expect(storage.signatures == 0)
}

@Test func signingUsesEnrolledKeyWithoutEnablingAuthenticationPrompts() throws {
    let storage = MemoryKeyStorage()
    let store = ApprovalKeyStore(storage: storage)
    let enrolled = try store.loadOrCreate()
    let context = LAContext()
    _ = try store.sign(Data([42]), expectedPublicKey: enrolled, context: context)
    #expect(context.interactionNotAllowed)
    #expect(storage.signatures == 1)
    #expect(storage.creations == 1)
}
