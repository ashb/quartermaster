use core_foundation::{
    array::CFArray,
    base::{CFType, CFTypeRef, TCFType},
    boolean::CFBoolean,
    data::{CFData, CFDataRef},
    dictionary::{CFDictionary, CFDictionaryRef},
    error::{CFError, CFErrorRef},
    number::CFNumber,
    string::{CFString, CFStringRef},
};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::key::{Algorithm, SecKey};
use security_framework::os::macos::code_signing::{Flags, SecCode};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
};
use security_framework_sys::{
    item::*,
    key::{SecKeyCopyExternalRepresentation, SecKeyCreateRandomKey},
    keychain_item::SecItemCopyMatching,
};
use std::{
    ffi::{CStr, OsStr},
    marker::PhantomData,
    mem::MaybeUninit,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    rc::Rc,
};
use zeroize::Zeroizing;

use super::lock::EnrollmentLock;
use super::{CacheKeyError, CacheKeyScope, WrappedCacheKey};

const WRAPPING: Algorithm = Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrApplicationTag: CFStringRef;
    static kSecUseAuthenticationUIFail: CFStringRef;
    static kSecCodeInfoEntitlementsDict: CFStringRef;
    fn SecCodeCopySigningInformation(
        code: CFTypeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
}

pub struct DeviceCacheKey {
    scope: CacheKeyScope,
    group: String,
    public: SecKey,
    identity: [u8; 32],
}

pub struct SnapshotKey(Zeroizing<Vec<u8>>);

/// A queue-confined borrow of a native LAContext, never write authorization.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<qm_macos::cache_key::NativeAuthenticationContext<'static>>();
/// ```
pub struct NativeAuthenticationContext<'a> {
    raw: CFTypeRef,
    _queue: PhantomData<(&'a (), Rc<()>)>,
}

impl<'a> NativeAuthenticationContext<'a> {
    /// # Safety
    /// `raw` must be a live LAContext from the authenticated native IPC adapter.
    /// Its owning queue must retain it for `'a`, forbid UI and exclude invalidation
    /// during this borrow. Neither archives nor caller-supplied pointers qualify.
    pub unsafe fn from_borrowed(raw: CFTypeRef) -> Self {
        Self {
            raw,
            _queue: PhantomData,
        }
    }
}

impl SnapshotKey {
    /// The sink is trusted Rust cache code; it must keep these bytes out of IPC and logs.
    pub fn with_bytes<T>(&self, sink: impl FnOnce(&[u8]) -> T) -> T {
        sink(&self.0)
    }
}

impl DeviceCacheKey {
    /// Explicit recovery for the recorded cache scope, including an interrupted
    /// first enrolment whose public pin was not persisted. Never call on lookup failure.
    pub fn discard_for_reenrollment(scope: CacheKeyScope) -> Result<(), CacheKeyError> {
        let group = own_access_group()?;
        let _lock = enrollment_lock(&scope)?;
        let Some(key) = lookup(&scope, &group, false)? else {
            return Ok(());
        };
        validate_hardware_key(&key)?;
        key.delete().map_err(|error| {
            status_error(
                "discard_enrollment",
                "NSOSStatusErrorDomain",
                error.code().into(),
            )
        })
    }
    pub fn enroll(scope: CacheKeyScope) -> Result<Self, CacheKeyError> {
        let group = own_access_group()?;
        let _lock = enrollment_lock(&scope)?;
        if lookup(&scope, &group, false)?.is_some() {
            return Err(CacheKeyError::AlreadyEnrolled);
        }
        let attributes = creation_attributes(&scope, &group)?;
        let mut error = std::ptr::null_mut();
        let raw = unsafe { SecKeyCreateRandomKey(attributes.as_concrete_TypeRef(), &mut error) };
        if !error.is_null() {
            return Err(framework_error("enroll", unsafe {
                CFError::wrap_under_create_rule(error)
            }));
        }
        if raw.is_null() {
            return Err(CacheKeyError::InvalidKey);
        }
        let key = unsafe { SecKey::wrap_under_create_rule(raw) };
        validate_hardware_key(&key)?;
        let (public, identity) = public_identity(&key)?;
        Ok(Self {
            scope,
            group,
            public,
            identity,
        })
    }

    pub fn load(scope: CacheKeyScope, expected: [u8; 32]) -> Result<Self, CacheKeyError> {
        let group = own_access_group()?;
        let key = lookup(&scope, &group, false)?.ok_or(CacheKeyError::KeyMissing)?;
        validate_hardware_key(&key)?;
        let (public, identity) = public_identity(&key)?;
        if identity != expected {
            return Err(CacheKeyError::KeyChanged);
        }
        Ok(Self {
            scope,
            group,
            public,
            identity,
        })
    }

    pub fn identity(&self) -> &[u8; 32] {
        &self.identity
    }

    pub fn wrap_new_snapshot_key(&self) -> Result<(SnapshotKey, WrappedCacheKey), CacheKeyError> {
        wrap_snapshot_key(&self.public, self.identity)
    }

    pub fn unwrap(self, wrapped: &WrappedCacheKey) -> Result<SnapshotKey, CacheKeyError> {
        if wrapped.identity() != &self.identity {
            return Err(CacheKeyError::KeyChanged);
        }
        // Reacquire a private reference so metadata lookup cannot carry a no-UI context into unwrap.
        let key = lookup(&self.scope, &self.group, true)?.ok_or(CacheKeyError::KeyMissing)?;
        validate_hardware_key(&key)?;
        let (_, identity) = public_identity(&key)?;
        unwrap_snapshot_key(&key, identity, wrapped)
    }

    pub fn unwrap_authenticated(
        self,
        wrapped: &WrappedCacheKey,
        context: &NativeAuthenticationContext<'_>,
    ) -> Result<SnapshotKey, CacheKeyError> {
        if wrapped.identity() != &self.identity {
            return Err(CacheKeyError::KeyChanged);
        }
        let mut pairs = query_pairs(&self.scope, &self.group, false);
        pairs.push(unsafe {
            (
                CFString::wrap_under_get_rule(kSecUseAuthenticationContext),
                CFType::wrap_under_get_rule(context.raw),
            )
        });
        let query = CFDictionary::from_CFType_pairs(&pairs);
        let key = lookup_query(&query)?.ok_or(CacheKeyError::KeyMissing)?;
        validate_hardware_key(&key)?;
        let (_, identity) = public_identity(&key)?;
        unwrap_snapshot_key(&key, identity, wrapped)
    }

    pub fn delete(self) -> Result<(), CacheKeyError> {
        let _lock = enrollment_lock(&self.scope)?;
        let key = lookup(&self.scope, &self.group, false)?.ok_or(CacheKeyError::KeyMissing)?;
        validate_hardware_key(&key)?;
        if public_identity(&key)?.1 != self.identity {
            return Err(CacheKeyError::KeyChanged);
        }
        key.delete()
            .map_err(|error| status_error("delete", "NSOSStatusErrorDomain", error.code().into()))
    }
}

fn enrollment_lock(scope: &CacheKeyScope) -> Result<EnrollmentLock, CacheKeyError> {
    let mut record = MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = vec![0; 16384];
    let mut found = std::ptr::null_mut();
    let status = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            record.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        )
    };
    if status != 0 || found.is_null() {
        return Err(CacheKeyError::Storage {
            operation: "home",
            code: (status != 0).then_some(status),
        });
    }
    let record = unsafe { record.assume_init() };
    if record.pw_dir.is_null() {
        return Err(CacheKeyError::Storage {
            operation: "home",
            code: None,
        });
    }
    let home = unsafe { CStr::from_ptr(record.pw_dir) };
    let directory = PathBuf::from(OsStr::from_bytes(home.to_bytes()))
        .join("Library/Application Support/Quartermaster/Development");
    EnrollmentLock::acquire(&directory, scope).map_err(|error| CacheKeyError::Storage {
        operation: "enrollment_lock",
        code: error.raw_os_error(),
    })
}

fn wrap_snapshot_key(
    public: &SecKey,
    identity: [u8; 32],
) -> Result<(SnapshotKey, WrappedCacheKey), CacheKeyError> {
    let mut bytes = Zeroizing::new(vec![0; 32]);
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| CacheKeyError::RandomnessUnavailable)?;
    let ciphertext = public
        .encrypt_data(WRAPPING, &bytes)
        .map_err(|error| framework_error("wrap", error))?;
    let wrapped = WrappedCacheKey::from_parts(identity, ciphertext)?;
    Ok((SnapshotKey(bytes), wrapped))
}

fn unwrap_snapshot_key(
    key: &SecKey,
    identity: [u8; 32],
    wrapped: &WrappedCacheKey,
) -> Result<SnapshotKey, CacheKeyError> {
    if wrapped.identity() != &identity {
        return Err(CacheKeyError::KeyChanged);
    }
    let bytes = Zeroizing::new(
        key.decrypt_data(WRAPPING, wrapped.ciphertext())
            .map_err(|error| framework_error("unwrap", error))?,
    );
    if bytes.len() != 32 {
        return Err(CacheKeyError::InvalidWrappedKey);
    }
    Ok(SnapshotKey(bytes))
}

fn public_identity(key: &SecKey) -> Result<(SecKey, [u8; 32]), CacheKeyError> {
    let public = key.public_key().ok_or(CacheKeyError::InvalidKey)?;
    let bytes = public
        .external_representation()
        .ok_or(CacheKeyError::InvalidKey)?;
    if bytes.len() != 65 || bytes[0] != 4 {
        return Err(CacheKeyError::InvalidKey);
    }
    let identity = digest(&SHA256, &bytes)
        .as_ref()
        .try_into()
        .map_err(|_| CacheKeyError::InvalidKey)?;
    Ok((public, identity))
}

fn own_access_group() -> Result<String, CacheKeyError> {
    let code = SecCode::for_self(Flags::NONE).map_err(|_| CacheKeyError::InvalidEntitlements)?;
    let mut information = std::ptr::null();
    let status = unsafe { SecCodeCopySigningInformation(code.as_CFTypeRef(), 2, &mut information) };
    if status != 0 || information.is_null() {
        return Err(CacheKeyError::InvalidEntitlements);
    }
    let information =
        unsafe { CFDictionary::<CFString, CFType>::wrap_under_create_rule(information) };
    let entitlement_key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoEntitlementsDict) };
    let entitlements = information
        .find(&entitlement_key)
        .and_then(|value| value.downcast::<CFDictionary>())
        .ok_or(CacheKeyError::InvalidEntitlements)?;
    let entitlements = unsafe {
        CFDictionary::<CFString, CFType>::wrap_under_get_rule(entitlements.as_concrete_TypeRef())
    };
    let groups = entitlements
        .find(CFString::new("keychain-access-groups"))
        .and_then(|value| value.downcast::<CFArray>())
        .ok_or(CacheKeyError::InvalidEntitlements)?;
    let groups = unsafe { CFArray::<CFType>::wrap_under_get_rule(groups.as_concrete_TypeRef()) };
    let groups = groups
        .iter()
        .map(|value| {
            value
                .downcast::<CFString>()
                .map(|value| value.to_string())
                .ok_or(CacheKeyError::InvalidEntitlements)
        })
        .collect::<Result<Vec<_>, _>>()?;
    validated_group(&groups)
}

fn query(
    scope: &CacheKeyScope,
    group: &str,
    allow_authentication: bool,
) -> CFDictionary<CFString, CFType> {
    CFDictionary::from_CFType_pairs(&query_pairs(scope, group, allow_authentication))
}

fn query_pairs(
    scope: &CacheKeyScope,
    group: &str,
    allow_authentication: bool,
) -> Vec<(CFString, CFType)> {
    let mut pairs = unsafe {
        vec![
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassKey).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyClass),
                CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrApplicationTag),
                CFData::from_buffer(scope.label().as_bytes()).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccessGroup),
                CFString::new(group).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                CFBoolean::true_value().into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFBoolean::false_value().into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecReturnRef),
                CFBoolean::true_value().into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecMatchLimit),
                CFString::wrap_under_get_rule(kSecMatchLimitAll).into_CFType(),
            ),
        ]
    };
    if !allow_authentication {
        pairs.push(unsafe {
            (
                CFString::wrap_under_get_rule(kSecUseAuthenticationUI),
                CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail).into_CFType(),
            )
        });
    }
    pairs
}

fn lookup(
    scope: &CacheKeyScope,
    group: &str,
    allow_authentication: bool,
) -> Result<Option<SecKey>, CacheKeyError> {
    let query = query(scope, group, allow_authentication);
    lookup_query(&query)
}

fn lookup_query(query: &CFDictionary<CFString, CFType>) -> Result<Option<SecKey>, CacheKeyError> {
    let mut raw = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut raw) };
    if status == -25300 {
        return Ok(None);
    }
    if status != 0 {
        return Err(status_error(
            "lookup",
            "NSOSStatusErrorDomain",
            status.into(),
        ));
    }
    if raw.is_null() {
        return Err(CacheKeyError::InvalidKey);
    }
    let value = unsafe { CFType::wrap_under_create_rule(raw) };
    let keys = value
        .downcast::<CFArray>()
        .ok_or(CacheKeyError::InvalidKey)?;
    let keys = unsafe { CFArray::<CFType>::wrap_under_get_rule(keys.as_concrete_TypeRef()) };
    if keys.len() != 1 {
        return Err(CacheKeyError::AmbiguousKey);
    }
    keys.get(0)
        .and_then(|value| value.downcast::<SecKey>())
        .map(Some)
        .ok_or(CacheKeyError::InvalidKey)
}

fn creation_attributes(
    scope: &CacheKeyScope,
    group: &str,
) -> Result<CFDictionary<CFString, CFType>, CacheKeyError> {
    let access = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
    )
    .map_err(|error| {
        status_error(
            "access_control",
            "NSOSStatusErrorDomain",
            error.code().into(),
        )
    })?;
    let private = unsafe {
        CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrIsPermanent),
                CFBoolean::true_value().into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrApplicationTag),
                CFData::from_buffer(scope.label().as_bytes()).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrLabel),
                CFString::new(&scope.label()).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccessControl),
                access.into_CFType(),
            ),
        ])
    };
    Ok(unsafe {
        CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                CFNumber::from(256i32).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrTokenID),
                CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                CFBoolean::true_value().into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFBoolean::false_value().into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccessGroup),
                CFString::new(group).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecPrivateKeyAttrs),
                private.into_CFType(),
            ),
        ])
    })
}

fn framework_error(operation: &'static str, error: CFError) -> CacheKeyError {
    status_error(operation, &error.domain().to_string(), error.code() as i64)
}

fn status_error(operation: &'static str, domain: &str, code: i64) -> CacheKeyError {
    match (domain, code) {
        ("NSOSStatusErrorDomain", -128) => CacheKeyError::UserCancelled,
        ("com.apple.LocalAuthentication", -2 | -4 | -9) => CacheKeyError::UserCancelled,
        ("NSOSStatusErrorDomain", -25308) => CacheKeyError::InteractionUnavailable,
        _ => CacheKeyError::Security { operation, code },
    }
}

fn validated_group(groups: &[String]) -> Result<String, CacheKeyError> {
    let [group] = groups else {
        return Err(CacheKeyError::InvalidEntitlements);
    };
    let prefix = group
        .strip_suffix(".dev.quartermaster.cache.debug")
        .ok_or(CacheKeyError::InvalidEntitlements)?;
    if prefix.len() != 10
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(CacheKeyError::InvalidEntitlements);
    }
    Ok(group.clone())
}

fn validate_hardware_key(key: &SecKey) -> Result<(), CacheKeyError> {
    let attributes = key.attributes();
    let attributes = unsafe {
        CFDictionary::<CFString, CFType>::wrap_under_get_rule(attributes.as_concrete_TypeRef())
    };
    let token = attributes
        .find(unsafe { CFString::wrap_under_get_rule(kSecAttrTokenID) })
        .and_then(|value| value.downcast::<CFString>());
    let size = attributes
        .find(unsafe { CFString::wrap_under_get_rule(kSecAttrKeySizeInBits) })
        .and_then(|value| value.downcast::<CFNumber>())
        .and_then(|value| value.to_i64());
    if token.as_ref()
        != Some(&unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave) })
        || size != Some(256)
        || key_is_exportable(key)
    {
        return Err(CacheKeyError::InvalidKey);
    }
    Ok(())
}

fn key_is_exportable(key: &SecKey) -> bool {
    let mut error = std::ptr::null_mut();
    let data = unsafe { SecKeyCopyExternalRepresentation(key.as_concrete_TypeRef(), &mut error) };
    unsafe { consume_export_result(data, error) }
}

unsafe fn consume_export_result(data: CFDataRef, error: CFErrorRef) -> bool {
    if !error.is_null() {
        drop(unsafe { CFError::wrap_under_create_rule(error) });
    }
    if data.is_null() {
        return false;
    }
    drop(unsafe { CFData::wrap_under_create_rule(data) });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use security_framework::key::{GenerateKeyOptions, KeyType, Token};

    fn software_key() -> SecKey {
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::Software);
        SecKey::new(&options).unwrap()
    }

    #[test]
    fn snapshot_keys_roundtrip_inside_rust_with_fresh_random_material() {
        let key = software_key();
        let (public, identity) = public_identity(&key).unwrap();
        let (first, wrapped) = wrap_snapshot_key(&public, identity).unwrap();
        let (second, second_wrapped) = wrap_snapshot_key(&public, identity).unwrap();
        first.with_bytes(|bytes| assert_eq!(bytes.len(), 32));
        first.with_bytes(|a| second.with_bytes(|b| assert_ne!(a, b)));
        assert_ne!(wrapped.ciphertext(), second_wrapped.ciphertext());
        assert_eq!(wrapped.identity(), &identity);
        let opened = unwrap_snapshot_key(&key, identity, &wrapped).unwrap();
        first.with_bytes(|a| opened.with_bytes(|b| assert_eq!(a, b)));
    }

    #[test]
    fn altered_ecies_ciphertext_is_rejected() {
        let key = software_key();
        let (public, identity) = public_identity(&key).unwrap();
        let (_, wrapped) = wrap_snapshot_key(&public, identity).unwrap();
        let mut ciphertext = wrapped.ciphertext().to_vec();
        *ciphertext.last_mut().unwrap() ^= 1;
        let altered = WrappedCacheKey::from_parts(*wrapped.identity(), ciphertext).unwrap();
        assert!(unwrap_snapshot_key(&key, identity, &altered).is_err());
    }

    #[test]
    fn substituted_enrolled_key_is_rejected_before_unwrap() {
        let (public, identity) = public_identity(&software_key()).unwrap();
        let other = software_key();
        let (_, other_identity) = public_identity(&other).unwrap();
        let (_, wrapped) = wrap_snapshot_key(&public, identity).unwrap();
        assert!(matches!(
            unwrap_snapshot_key(&other, other_identity, &wrapped),
            Err(CacheKeyError::KeyChanged)
        ));
    }

    #[test]
    fn only_the_single_signed_debug_cache_group_is_accepted() {
        for groups in [
            vec![],
            vec!["ABCDEFGHIJ.dev.quartermaster.phase0".to_owned()],
            vec!["ABCDEFGHIJ.dev.quartermaster.cache.release".to_owned()],
            vec!["ABCDEFGHIJ.dev.quartermaster.cache.debug.extra".to_owned()],
            vec!["ABCDEFGHIJ.*".to_owned()],
            vec!["bad.dev.quartermaster.cache.debug".to_owned()],
            vec![
                "ABCDEFGHIJ.dev.quartermaster.cache.debug".to_owned(),
                "ABCDEFGHIJ.dev.quartermaster.phase0".to_owned(),
            ],
        ] {
            assert_eq!(
                validated_group(&groups),
                Err(CacheKeyError::InvalidEntitlements)
            );
        }
        assert_eq!(
            validated_group(&["ABCDEFGHIJ.dev.quartermaster.cache.debug".to_owned()]),
            Ok("ABCDEFGHIJ.dev.quartermaster.cache.debug".to_owned())
        );
    }

    #[test]
    fn cancellation_and_interaction_errors_do_not_imply_key_loss() {
        assert_eq!(
            status_error("unwrap", "NSOSStatusErrorDomain", -128),
            CacheKeyError::UserCancelled
        );
        assert_eq!(
            status_error("lookup", "NSOSStatusErrorDomain", -25308),
            CacheKeyError::InteractionUnavailable
        );
        for code in [-2, -4, -9] {
            assert_eq!(
                status_error("unwrap", "com.apple.LocalAuthentication", code),
                CacheKeyError::UserCancelled
            );
        }
        for (domain, code) in [
            ("other", -128),
            ("NSOSStatusErrorDomain", -25293),
            ("other", -2),
        ] {
            assert_eq!(
                status_error("unwrap", domain, code),
                CacheKeyError::Security {
                    operation: "unwrap",
                    code
                }
            );
        }
    }

    #[test]
    fn production_key_validation_rejects_exportable_software_keys() {
        assert_eq!(
            validate_hardware_key(&software_key()),
            Err(CacheKeyError::InvalidKey)
        );
    }

    #[test]
    fn metadata_queries_are_scoped_and_cannot_prompt_for_authentication() {
        let scope = CacheKeyScope::new("0123456789abcdef0123456789abcdef").unwrap();
        let query = query(&scope, "ABCDEFGHIJ.dev.quartermaster.cache.debug", false);
        for (attribute, expected) in unsafe {
            [
                (
                    kSecUseDataProtectionKeychain,
                    CFBoolean::true_value().into_CFType(),
                ),
                (
                    kSecAttrSynchronizable,
                    CFBoolean::false_value().into_CFType(),
                ),
                (
                    kSecAttrAccessGroup,
                    CFString::new("ABCDEFGHIJ.dev.quartermaster.cache.debug").into_CFType(),
                ),
                (
                    kSecUseAuthenticationUI,
                    CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail).into_CFType(),
                ),
                (
                    kSecAttrApplicationTag,
                    CFData::from_buffer(
                        b"Quartermaster development cache 0123456789abcdef0123456789abcdef",
                    )
                    .into_CFType(),
                ),
            ]
        } {
            assert_eq!(
                *query
                    .find(unsafe { CFString::wrap_under_get_rule(attribute) })
                    .unwrap(),
                expected
            );
        }
        let interactive = super::query(&scope, "ABCDEFGHIJ.dev.quartermaster.cache.debug", true);
        assert!(
            interactive
                .find(unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationUI) })
                .is_none()
        );
    }

    #[test]
    fn native_enrollment_attributes_request_a_persistent_device_only_hardware_key() {
        let scope = CacheKeyScope::new("0123456789abcdef0123456789abcdef").unwrap();
        let attributes =
            creation_attributes(&scope, "ABCDEFGHIJ.dev.quartermaster.cache.debug").unwrap();
        assert_eq!(
            *attributes
                .find(unsafe { CFString::wrap_under_get_rule(kSecAttrTokenID) })
                .unwrap(),
            unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave) }.into_CFType()
        );
        assert_eq!(
            attributes
                .find(unsafe { CFString::wrap_under_get_rule(kSecAttrKeySizeInBits) })
                .unwrap()
                .downcast::<CFNumber>()
                .unwrap()
                .to_i64(),
            Some(256)
        );
        let private = attributes
            .find(unsafe { CFString::wrap_under_get_rule(kSecPrivateKeyAttrs) })
            .unwrap()
            .downcast::<CFDictionary>()
            .unwrap();
        let private = unsafe {
            CFDictionary::<CFString, CFType>::wrap_under_get_rule(private.as_concrete_TypeRef())
        };
        assert_eq!(
            *private
                .find(unsafe { CFString::wrap_under_get_rule(kSecAttrIsPermanent) })
                .unwrap(),
            CFBoolean::true_value().into_CFType()
        );
        assert!(
            private
                .find(unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) })
                .is_some()
        );
    }

    #[test]
    fn an_unentitled_process_cannot_enroll_or_load_a_cache_key() {
        assert!(matches!(
            DeviceCacheKey::discard_for_reenrollment(
                CacheKeyScope::new("0123456789abcdef0123456789abcdef").unwrap()
            ),
            Err(CacheKeyError::InvalidEntitlements)
        ));
        assert_eq!(own_access_group(), Err(CacheKeyError::InvalidEntitlements));
        assert!(matches!(
            DeviceCacheKey::enroll(CacheKeyScope::new("0123456789abcdef0123456789abcdef").unwrap()),
            Err(CacheKeyError::InvalidEntitlements)
        ));
        assert!(matches!(
            DeviceCacheKey::load(
                CacheKeyScope::new("0123456789abcdef0123456789abcdef").unwrap(),
                [1; 32]
            ),
            Err(CacheKeyError::InvalidEntitlements)
        ));
    }

    #[test]
    fn denied_key_export_releases_the_owned_native_error() {
        let domain = CFString::new("quartermaster.test.export-denied");
        let error = unsafe {
            CFError::wrap_under_create_rule(core_foundation::error::CFErrorCreate(
                std::ptr::null(),
                domain.as_concrete_TypeRef(),
                -128,
                std::ptr::null(),
            ))
        };
        let retained = error.retain_count();
        for _ in 0..3 {
            let returned = error.clone();
            let raw = returned.as_concrete_TypeRef();
            std::mem::forget(returned);
            assert!(!unsafe { consume_export_result(std::ptr::null(), raw) });
            assert_eq!(error.retain_count(), retained);
        }
    }

    #[test]
    fn successful_key_export_releases_the_owned_native_data() {
        let data = CFData::from_buffer(b"public test bytes");
        let retained = data.retain_count();
        let returned = data.clone();
        let raw = returned.as_concrete_TypeRef();
        std::mem::forget(returned);
        assert!(unsafe { consume_export_result(raw, std::ptr::null_mut()) });
        assert_eq!(data.retain_count(), retained);
        assert!(key_is_exportable(&software_key()));
    }
}
