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
