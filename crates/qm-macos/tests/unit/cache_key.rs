use super::*;

#[test]
fn enrollment_scope_rejects_tags_that_could_select_another_key() {
    for invalid in [
        "",
        "0123456789ABCDEF0123456789ABCDEF",
        "0123456789abcdef0123456789abcdeg",
        "0123456789abcdef0123456789abcdefx",
        "dev.quartermaster.approval.debug.v1",
        "../../approval-key",
    ] {
        assert!(matches!(
            CacheKeyScope::new(invalid),
            Err(CacheKeyError::InvalidScope)
        ));
    }
    let scope = CacheKeyScope::new("0123456789abcdef0123456789abcdef").unwrap();
    assert_eq!(
        scope.label(),
        "Quartermaster development cache 0123456789abcdef0123456789abcdef"
    );
}

#[test]
fn wrapped_snapshot_key_requires_the_fixed_ecies_envelope_length() {
    for length in [0, 32, 65, 112, 114, 8192] {
        assert!(matches!(
            WrappedCacheKey::from_parts([1; 32], vec![0; length]),
            Err(CacheKeyError::InvalidWrappedKey)
        ));
    }
    let wrapped = WrappedCacheKey::from_parts([1; 32], vec![0x42; 113]).unwrap();
    assert_eq!(wrapped.identity(), &[1; 32]);
    assert_eq!(wrapped.ciphertext(), &[0x42; 113]);
}
