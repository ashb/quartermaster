use super::*;
use qm_providers::{CredentialField, ProviderBinding};

fn binding() -> ProviderBinding {
    ProviderBinding::new(
        "https://vault.example.invalid",
        "11111111-1111-4111-8111-111111111111",
        "dummy@example.invalid",
        "22222222-2222-4222-8222-222222222222",
        CredentialField::LoginPassword,
        "github-write",
    )
    .unwrap()
}

#[test]
fn item_selection_errors_do_not_claim_the_cache_is_incompatible() {
    for (error, expected) in [
        (ProviderError::AmbiguousItem, "ambiguous_item"),
        (ProviderError::ItemNotFound, "item_not_found"),
    ] {
        let reply = error_reply(Error::Provider(error));
        assert_eq!(serde_json::to_value(&reply).unwrap()["state"], expected);
        assert_eq!(reply.error.unwrap(), format!("Provider({error:?})"));
    }
}

#[test]
fn status_reports_interrupted_and_ready_enrollments_without_authenticating() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let store = store(&root).unwrap();
    let mut manifest =
        VaultEnrollment::begin(binding(), "0123456789abcdef0123456789abcdef".into()).unwrap();
    store.save_enrollment(&manifest.encode().unwrap()).unwrap();
    assert_eq!(status(&root, None).state, VaultState::IncompleteEnrollment);
    assert!(matches!(
        Source::capture(&root).and_then(Source::unlock),
        Err(Error::Incomplete)
    ));

    manifest.record_key([7; 32]).unwrap();
    manifest
        .record_ready(crate::owner::test_support::wall(10))
        .unwrap();
    store.save_enrollment(&manifest.encode().unwrap()).unwrap();
    store.save(b"invalid dummy encrypted cache").unwrap();
    let before = store.load().unwrap().unwrap();

    assert_eq!(status(&root, None).state, VaultState::Locked);
    assert!(matches!(
        Source::capture(&root).and_then(Source::unlock),
        Err(Error::Cache(CacheError::InvalidFormat))
    ));
    assert_eq!(store.load().unwrap().unwrap(), before);
}

#[test]
fn unentitled_reset_cannot_delete_an_enrollment_or_its_cache() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let store = store(&root).unwrap();
    let manifest =
        VaultEnrollment::begin(binding(), "0123456789abcdef0123456789abcdef".into()).unwrap();
    store.save_enrollment(&manifest.encode().unwrap()).unwrap();
    store.save(b"preserve dummy encrypted cache").unwrap();

    assert!(matches!(
        discard(&root),
        Err(Error::Key(CacheKeyError::InvalidEntitlements))
    ));

    assert!(store.load_enrollment().unwrap().is_some());
    assert_eq!(
        store.load().unwrap().unwrap(),
        b"preserve dummy encrypted cache"
    );
}

#[test]
fn explicit_discard_removes_unenrolled_cache_data_without_key_queries() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let store = store(&root).unwrap();
    store.save(b"discard dummy encrypted cache").unwrap();

    discard(&root).unwrap();

    assert_eq!(store.load().unwrap(), None);
    assert_eq!(status(&root, None).state, VaultState::Unenrolled);
}

#[test]
fn persist_rejects_a_backward_sync_before_key_access_or_cache_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let cache = store(&root).unwrap();
    let snapshot = crate::owner::test_support::vault::snapshot("github-write");
    let mut manifest = VaultEnrollment::begin(
        snapshot.binding().clone(),
        "0123456789abcdef0123456789abcdef".into(),
    )
    .unwrap();
    manifest.record_key([7; 32]).unwrap();
    manifest
        .record_ready(snapshot.synchronized_at() + std::time::Duration::from_secs(1))
        .unwrap();
    cache.save_enrollment(&manifest.encode().unwrap()).unwrap();
    cache
        .save(b"preserve the previous authenticated cache")
        .unwrap();
    let before_enrollment = cache.load_enrollment().unwrap();
    let before_cache = cache.load().unwrap();

    let source = Source::capture(&root).unwrap();
    let mut provider = ProviderState::default();
    let mut operation = provider
        .begin_login(source.binding(), source.minimum_sync(), source.revision)
        .unwrap();
    let result = begin_persistence(&root, &provider, &mut operation, &snapshot);

    assert!(matches!(result, Err(Error::Cache(CacheError::Stale))));
    assert_eq!(cache.load_enrollment().unwrap(), before_enrollment);
    assert_eq!(cache.load().unwrap(), before_cache);
}

fn discard(root: &Path) -> Result<(), Error> {
    let source = Source::capture(root)?;
    let mut provider = ProviderState::default();
    let operation = provider.begin_discard(source.revision)?;
    source.delete_device()?;
    finish_discard(root, &mut provider, operation)
}

#[test]
fn a_late_unlock_after_lock_cannot_install_or_change_persisted_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let snapshot = crate::owner::test_support::vault::snapshot("github-write");
    let source = fixture::put(&root, &snapshot);
    let cache = store(&root).unwrap();
    let before = (cache.load().unwrap(), cache.load_enrollment().unwrap());
    let mut provider = ProviderState::default();
    let operation = provider.begin_unlock(source.identity().unwrap()).unwrap();
    provider.lock().unwrap();

    assert!(matches!(
        finish_unlock(&root, &mut provider, operation, snapshot),
        Err(Error::Lifecycle(provider_lifecycle::Error::Superseded))
    ));
    assert!(provider.snapshot().is_none());
    assert_eq!(
        (cache.load().unwrap(), cache.load_enrollment().unwrap()),
        before
    );
}

#[test]
fn late_refresh_after_lock_discard_or_replacement_cannot_publish_any_files() {
    for event in 0..3 {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let snapshot = crate::owner::test_support::vault::snapshot("github-write");
        let source = fixture::put(&root, &snapshot);
        let mut provider = ProviderState::default();
        let identity = source.identity().unwrap();
        let unlock = provider.begin_unlock(identity.clone()).unwrap();
        provider.finish_unlock(unlock, &identity, snapshot).unwrap();
        let (refresh, _) = provider.begin_refresh(&identity).unwrap();
        let refreshed = crate::owner::test_support::vault::snapshot_at(
            "github-write",
            identity.binding.item_id(),
            [9; 16],
            identity.synchronized_at + std::time::Duration::from_secs(1),
        );
        let mut prepared = fixture::prepared(&root, refreshed);
        let cache = store(&root).unwrap();
        let before = (cache.load().unwrap(), cache.load_enrollment().unwrap());
        match event {
            0 => provider.lock().unwrap(),
            1 => assert!(matches!(
                provider.begin_discard(source.revision),
                Err(provider_lifecycle::Error::Busy)
            )),
            2 => assert!(matches!(
                provider.begin_login(source.binding(), source.minimum_sync(), source.revision),
                Err(provider_lifecycle::Error::Busy)
            )),
            _ => unreachable!(),
        }

        assert!(matches!(
            publish_update(&root, &mut provider, refresh, &mut prepared),
            Err(Error::Lifecycle(provider_lifecycle::Error::Superseded))
        ));
        assert!(provider.snapshot().is_none());
        assert_eq!(
            (cache.load().unwrap(), cache.load_enrollment().unwrap()),
            before
        );
    }
}

#[test]
fn valid_refresh_publishes_a_new_checkpoint_and_preserves_the_selected_binding() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let snapshot = crate::owner::test_support::vault::snapshot("github-write");
    let source = fixture::put(&root, &snapshot);
    let identity = source.identity().unwrap();
    let mut provider = ProviderState::default();
    let unlock = provider.begin_unlock(identity.clone()).unwrap();
    provider.finish_unlock(unlock, &identity, snapshot).unwrap();
    let (refresh, _) = provider.begin_refresh(&identity).unwrap();
    let refreshed = crate::owner::test_support::vault::snapshot_at(
        "github-write",
        identity.binding.item_id(),
        [9; 16],
        identity.synchronized_at + std::time::Duration::from_secs(1),
    );
    let mut prepared = fixture::prepared(&root, refreshed);

    publish_update(&root, &mut provider, refresh, &mut prepared).unwrap();

    let persisted = Source::capture(&root).unwrap();
    let opened = SealedSnapshot::decode(
        persisted.cache.as_deref().unwrap(),
        &identity.binding,
        &identity.device_key,
    )
    .unwrap()
    .open(&[6; 32], identity.synchronized_at)
    .unwrap();
    assert_eq!(opened.checkpoint(), [9; 16]);
    assert_eq!(opened.binding(), &identity.binding);
    assert_eq!(provider.snapshot().unwrap().checkpoint(), [9; 16]);
    assert_eq!(
        persisted.manifest.as_ref().unwrap().identity(),
        Some([7; 32])
    );
    assert_ne!(persisted.revision.0, source.revision.0);
}

#[test]
fn a_changed_device_key_during_refresh_is_rejected_before_cache_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let snapshot = crate::owner::test_support::vault::snapshot("github-write");
    let source = fixture::put(&root, &snapshot);
    let identity = source.identity().unwrap();
    let mut provider = ProviderState::default();
    let unlock = provider.begin_unlock(identity.clone()).unwrap();
    provider.finish_unlock(unlock, &identity, snapshot).unwrap();
    let (refresh, _) = provider.begin_refresh(&identity).unwrap();
    let refreshed = crate::owner::test_support::vault::snapshot_at(
        "github-write",
        identity.binding.item_id(),
        [9; 16],
        identity.synchronized_at + std::time::Duration::from_secs(1),
    );
    let mut prepared = fixture::prepared(&root, refreshed);
    let cache = store(&root).unwrap();
    let mut enrollment: Value =
        serde_json::from_slice(&cache.load_enrollment().unwrap().unwrap()).unwrap();
    enrollment["identity"] = json!(([8; 32]));
    cache
        .save_enrollment(&serde_json::to_vec(&enrollment).unwrap())
        .unwrap();
    let before = (cache.load().unwrap(), cache.load_enrollment().unwrap());

    assert!(matches!(
        publish_update(&root, &mut provider, refresh, &mut prepared),
        Err(Error::Lifecycle(provider_lifecycle::Error::Changed))
    ));
    assert_eq!(
        (cache.load().unwrap(), cache.load_enrollment().unwrap()),
        before
    );
}
