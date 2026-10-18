import CryptoKit
import Foundation
import LocalAuthentication
import Security

public enum ApprovalKeyError: Error, Equatable {
    case security(String, Int32)
    case missingEnrolledKey
    case changedKey
    case invalidKey
    case duplicateKeys
    case unsafeLock
}

protocol ApprovalKeyStorage {
    func withExclusiveAccess<T>(_ body: () throws -> T) throws -> T
    func publicKey() throws -> Data?
    func create() throws -> Data
    func enrollment() throws -> Data?
    func saveEnrollment(_ publicKey: Data) throws
    func deleteKey() throws
    func deleteEnrollment() throws
    func sign(_ message: Data, context: LAContext) throws -> Data
}

public final class ApprovalKeyStore {
    private let storage: any ApprovalKeyStorage

    public init() {
        storage = SecureEnclaveApprovalKeyStorage()
    }

    init(storage: any ApprovalKeyStorage) {
        self.storage = storage
    }

    public func loadOrCreate() throws -> Data {
        try storage.withExclusiveAccess {
            if let key = try checkedExistingKey() { return key }
            let key = try storage.create()
            try validate(key)
            try storage.saveEnrollment(key)
            return key
        }
    }

    public func existingPublicKey() throws -> Data? {
        try storage.withExclusiveAccess { try checkedExistingKey() }
    }

    private func checkedExistingKey() throws -> Data? {
        let enrolled = try storage.enrollment()
        guard let key = try storage.publicKey() else {
            if enrolled != nil { throw ApprovalKeyError.missingEnrolledKey }
            return nil
        }
        try validate(key)
        if let enrolled {
            guard enrolled == key else { throw ApprovalKeyError.changedKey }
        } else {
            // Recover a crash between key creation and saving its public enrolment.
            try storage.saveEnrollment(key)
        }
        return key
    }

    private func validate(_ publicKey: Data) throws {
        guard (try? P256.Signing.PublicKey(x963Representation: publicKey)) != nil else {
            throw ApprovalKeyError.invalidKey
        }
    }

    public func sign(_ message: Data, expectedPublicKey: Data, context: LAContext) throws -> Data {
        try storage.withExclusiveAccess {
            guard let key = try checkedExistingKey() else { throw ApprovalKeyError.missingEnrolledKey }
            guard key == expectedPublicKey else { throw ApprovalKeyError.changedKey }
            context.interactionNotAllowed = true
            return try storage.sign(message, context: context)
        }
    }

    public func reset() throws {
        try storage.withExclusiveAccess {
            try storage.deleteKey()
            guard try storage.publicKey() == nil else { throw ApprovalKeyError.duplicateKeys }
            try storage.deleteEnrollment()
        }
    }
}
