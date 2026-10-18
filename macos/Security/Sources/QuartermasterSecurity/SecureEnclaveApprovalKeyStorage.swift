import Darwin
import Foundation
import LocalAuthentication
import Security

final class SecureEnclaveApprovalKeyStorage: ApprovalKeyStorage {
    private let tag = Data("dev.quartermaster.approval.debug.v1".utf8)
    private let enrollmentService = "dev.quartermaster.approval.debug.enrollment.v1"

    private func noInteraction(_ query: [CFString: Any]) -> [CFString: Any] {
        let context = LAContext()
        context.interactionNotAllowed = true
        var query = query
        query[kSecUseAuthenticationContext] = context
        return query
    }

    func withExclusiveAccess<T>(_ body: () throws -> T) throws -> T {
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                  appropriateFor: nil, create: true)
        let directory = support.appendingPathComponent("Quartermaster/Development", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        let parent = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw ApprovalKeyError.unsafeLock }
        defer { close(parent) }
        var attributes = stat()
        guard fstat(parent, &attributes) == 0, attributes.st_uid == geteuid(),
              attributes.st_mode & 0o077 == 0 else { throw ApprovalKeyError.unsafeLock }
        let descriptor = openat(parent, "approval-key.lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw ApprovalKeyError.unsafeLock }
        defer { close(descriptor) }
        guard fstat(descriptor, &attributes) == 0, attributes.st_uid == geteuid(),
              attributes.st_nlink == 1, attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_mode & 0o077 == 0, flock(descriptor, LOCK_EX) == 0 else {
            throw ApprovalKeyError.unsafeLock
        }
        return try body()
    }

    private func keyQuery(_ applicationTag: Data) -> [CFString: Any] {
        [kSecClass: kSecClassKey, kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
         kSecAttrApplicationTag: applicationTag, kSecUseDataProtectionKeychain: true]
    }

    private func key() throws -> SecKey? {
        var query = keyQuery(tag)
        query[kSecAttrKeyClass] = kSecAttrKeyClassPrivate
        query[kSecMatchLimit] = kSecMatchLimitAll
        query[kSecReturnRef] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(noInteraction(query) as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw ApprovalKeyError.security("lookup", status) }
        guard let keys = result as? [SecKey], keys.count == 1 else { throw ApprovalKeyError.duplicateKeys }
        let key = keys[0]
        guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
              attributes[kSecAttrTokenID] as? String == kSecAttrTokenIDSecureEnclave as String,
              attributes[kSecAttrKeySizeInBits] as? Int == 256 else { throw ApprovalKeyError.invalidKey }
        return key
    }

    private func publicBytes(_ key: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCopyPublicKey(key),
              let bytes = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw ApprovalKeyError.invalidKey
        }
        return bytes
    }

    func publicKey() throws -> Data? {
        guard let key = try key() else { return nil }
        return try publicBytes(key)
    }

    func create() throws -> Data {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                          [.biometryCurrentSet, .privateKeyUsage], &error) else {
            throw ApprovalKeyError.security("access_control", Int32(error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? 0))
        }
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave, kSecUseDataProtectionKeychain: true,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: true, kSecAttrApplicationTag: tag,
                                 kSecAttrLabel: "Quartermaster development approval key",
                                 kSecAttrAccessControl: access],
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw ApprovalKeyError.security("create", Int32(error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? 0))
        }
        return try publicBytes(key)
    }

    private var enrollmentQuery: [CFString: Any] {
        [kSecClass: kSecClassGenericPassword, kSecAttrService: enrollmentService,
         kSecAttrAccount: "public-key", kSecUseDataProtectionKeychain: true]
    }

    func enrollment() throws -> Data? {
        var query = enrollmentQuery
        query[kSecReturnData] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(noInteraction(query) as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw ApprovalKeyError.security("enrollment_lookup", status) }
        guard let bytes = result as? Data else { throw ApprovalKeyError.invalidKey }
        return bytes
    }

    func saveEnrollment(_ publicKey: Data) throws {
        var query = enrollmentQuery
        query[kSecValueData] = publicKey
        query[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw ApprovalKeyError.security("enrollment_save", status) }
    }

    private func delete(_ query: [CFString: Any]) throws {
        let status = SecItemDelete(noInteraction(query) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ApprovalKeyError.security("delete", status)
        }
    }

    func deleteKey() throws { try delete(keyQuery(tag)) }
    func deleteEnrollment() throws { try delete(enrollmentQuery) }

    func sign(_ message: Data, context: LAContext) throws -> Data {
        var query = keyQuery(tag)
        query[kSecAttrKeyClass] = kSecAttrKeyClassPrivate
        query[kSecReturnRef] = true
        query[kSecUseAuthenticationContext] = context
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
            throw ApprovalKeyError.security("sign_lookup", status)
        }
        let key = item as! SecKey
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                                    message as CFData, &error) as Data? else {
            throw ApprovalKeyError.security("sign", Int32(error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? 0))
        }
        return signature
    }
}
