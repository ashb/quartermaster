use super::error::{Error, Fault, Result};
use super::{ServicePaths, Shared};
use crate::owner::protocol::Client;
use crate::owner::provider_lifecycle::ProviderOperation;
use crate::{
    owner::vault::{self, Source},
    platform::macos::ipc,
};
use qm_providers::{RbwProvider, VaultProvider, VaultSnapshot};
use std::sync::Arc;

enum VaultWork {
    Unlock(Box<Source>),
    Sync(Arc<VaultSnapshot>),
}

enum Output {
    Unlocked(VaultSnapshot),
    Updated(VaultSnapshot),
}

impl VaultWork {
    async fn execute(self) -> Result<Output, vault::Error> {
        match self {
            VaultWork::Sync(snapshot) => {
                match RbwProvider::new(snapshot.binding().clone(), vault::LIMITS) {
                    Ok(provider) => provider
                        .sync(&snapshot)
                        .await
                        .map(Output::Updated)
                        .map_err(Into::into),
                    Err(error) => Err(error.into()),
                }
            }
            VaultWork::Unlock(source) => tokio::task::spawn_blocking(move || source.unlock())
                .await
                .map_err(|_| vault::Error::Storage)
                .and_then(|result| result.map(Output::Unlocked)),
        }
    }
}

pub(super) async fn vault_operation(
    message: Client,
    connection: &ipc::PeerHandle,
    shared: &Shared,
    paths: &ServicePaths,
    generation: crate::owner::provider_lifecycle::ProviderGeneration,
) -> Result<crate::CacheStatus> {
    let source_paths = paths.clone();
    let source = match tokio::task::spawn_blocking(move || source_paths.vault_source())
        .await
        .map_err(Error::from)?
    {
        Ok(source) => source,
        Err(error) => return Ok(vault::error_reply(error)),
    };
    let (operation, work) = {
        let mut state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        state.ensure_host_session()?;
        if state.provider.generation() != generation {
            return Ok(vault::error_reply(
                crate::owner::provider_lifecycle::Error::Superseded.into(),
            ));
        }
        if !connection.is_connected()
            || (state
                .ui
                .as_ref()
                .is_none_or(|ui| ui.connection != Some(connection.id()))
                && !state.administration.manages_cache(connection))
        {
            return Err(Error::State(Fault::UiNotEnrolled));
        }
        if !matches!(&message, Client::VaultSync {}) {
            state.disconnect_ui();
        }
        let reservation = match message {
            Client::VaultUnlock {} => source.identity().and_then(|identity| {
                state
                    .provider
                    .begin_unlock(identity)
                    .map(|operation| (operation, VaultWork::Unlock(Box::new(source))))
                    .map_err(Into::into)
            }),
            Client::VaultSync {} => source.identity().and_then(|identity| {
                state
                    .provider
                    .begin_refresh(&identity)
                    .map(|(operation, snapshot)| (operation, VaultWork::Sync(snapshot)))
                    .map_err(Into::into)
            }),
            _ => return Err(Error::State(Fault::UnsupportedVaultCommand)),
        };
        match reservation {
            Ok(reservation) => reservation,
            Err(error) => return Ok(vault::error_reply(error)),
        }
    };
    let completion = match work.execute().await {
        Ok(Output::Updated(snapshot)) => {
            match prepare_cache_update(shared, paths, operation, snapshot).await {
                Ok((operation, prepared)) => {
                    CacheCompletion::Publish(operation, Box::new(prepared))
                }
                Err(error) => return Ok(vault::error_reply(error)),
            }
        }
        Ok(Output::Unlocked(snapshot)) => CacheCompletion::Unlock(operation, Box::new(snapshot)),
        Err(error) => return Ok(vault::error_reply(error)),
    };
    let root = paths.vault_root()?;
    let shared = Arc::clone(shared);
    tokio::task::spawn_blocking(move || match completion.finish(&root, &shared) {
        Ok(()) => cache_status(&root, &shared),
        Err(Error::Vault(error)) => Ok(vault::error_reply(error)),
        Err(Error::Provider(error)) => Ok(vault::error_reply(error.into())),
        Err(error) => Err(error),
    })
    .await?
}

enum CacheCompletion {
    Publish(ProviderOperation, Box<vault::PreparedCache>),
    Unlock(ProviderOperation, Box<VaultSnapshot>),
}

impl CacheCompletion {
    fn finish(self, root: &std::path::Path, shared: &Shared) -> Result<()> {
        match self {
            Self::Publish(operation, prepared) => {
                finish_publication(vault::publication(root, *prepared)?, operation, shared)?;
            }
            Self::Unlock(operation, snapshot) => {
                let identity = Source::capture(root)?.identity()?;
                let mut state = shared
                    .0
                    .lock()
                    .map_err(|_| Error::State(Fault::StateUnavailable))?;
                state.ensure_host_session()?;
                state
                    .provider
                    .finish_unlock(operation, &identity, *snapshot)?;
            }
        }
        Ok(())
    }
}

fn finish_publication<B: qm_macos::cache_store::BackupExclusion>(
    mut publication: vault::Publication<B>,
    operation: ProviderOperation,
    shared: &Shared,
) -> Result<()> {
    let update = {
        let mut state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        state.ensure_host_session()?;
        publication.admit(&mut state.provider, operation)?
    };
    let identity = publication.publish()?;
    let mut state = shared
        .0
        .lock()
        .map_err(|_| Error::State(Fault::StateUnavailable))?;
    state.ensure_host_session()?;
    update.install(&mut state.provider, identity)?;
    Ok(())
}

async fn prepare_cache_update(
    shared: &Shared,
    paths: &ServicePaths,
    mut operation: crate::owner::provider_lifecycle::ProviderOperation,
    snapshot: VaultSnapshot,
) -> Result<
    (
        crate::owner::provider_lifecycle::ProviderOperation,
        vault::PreparedCache,
    ),
    vault::Error,
> {
    let shared = Arc::clone(shared);
    let root = paths.vault_root()?;
    tokio::task::spawn_blocking(move || {
        let cache = crate::owner::persistence::store(&root)?.transaction()?;
        let source = Source::capture_store(&cache)?;
        {
            let mut state = shared.0.lock().map_err(|_| vault::Error::Storage)?;
            state.ensure_host_session().map_err(|_| {
                vault::Error::Lifecycle(crate::owner::provider_lifecycle::Error::Superseded)
            })?;
            state.provider.check(&operation, source.revision)?;
        }
        let intent = vault::persistence_intent(&cache, source, &snapshot)?;
        let revision = Source::capture_store(&cache)?.revision;
        {
            let mut state = shared.0.lock().map_err(|_| vault::Error::Storage)?;
            state.ensure_host_session().map_err(|_| {
                vault::Error::Lifecycle(crate::owner::provider_lifecycle::Error::Superseded)
            })?;
            state.provider.revise_source(&mut operation, revision)?;
        }
        drop(cache);
        intent.seal(snapshot).map(|prepared| (operation, prepared))
    })
    .await
    .map_err(|_| vault::Error::Storage)?
}

pub(super) fn cache_status(root: &std::path::Path, shared: &Shared) -> Result<crate::CacheStatus> {
    let mut status = vault::status(root, None);
    let state = shared
        .0
        .lock()
        .map_err(|_| Error::State(Fault::StateUnavailable))?;
    if status.error.is_none() && state.provider.snapshot().is_some() {
        status.state = crate::VaultState::OnlineUnlocked;
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner::{
        persistence,
        runtime::{control::handle, tests::fixture},
    };
    use qm_macos::cache_store::{BackupExclusion, CacheStore};
    use std::{
        fs::File,
        io,
        sync::{Condvar, Mutex, mpsc},
        thread,
        time::Duration,
    };

    struct StalledBackup {
        remaining: std::sync::atomic::AtomicUsize,
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl BackupExclusion for StalledBackup {
        fn exclude_and_verify(&self, _: &File) -> io::Result<()> {
            if self
                .remaining
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed)
                == 1
            {
                self.entered.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
            Ok(())
        }
    }

    #[test]
    fn cancellation_and_host_revocation_proceed_during_storage_preparation_and_publication() {
        for stall_at in [1, 3] {
            for (event, lock) in [
                (None, false),
                (None, true),
                (Some(crate::platform::HostSessionEvent::ScreenLock), false),
                (Some(crate::platform::HostSessionEvent::Logout), false),
            ] {
                let (_directory, paths, _key, mut state, _completion) = fixture();
                let pending = state.pending.as_ref().unwrap();
                let id = pending.id.to_string();
                let source = vault::Source::capture(&paths.root).unwrap();
                let identity = source.identity().unwrap();
                let (operation, _) = state.provider.begin_refresh(&identity).unwrap();
                let snapshot = crate::owner::test_support::vault::snapshot_at(
                    "github-write",
                    identity.binding.item_id(),
                    [9; 16],
                    identity.synchronized_at + Duration::from_secs(1),
                );
                let prepared = vault::fixture::prepared(&paths.root, snapshot);
                let shared = Arc::new((Mutex::new(state), Condvar::new()));
                let (entered, ready) = mpsc::sync_channel(1);
                let (release, wait) = mpsc::sync_channel(1);
                let root = paths.root.clone();
                let publishing = Arc::clone(&shared);
                let worker = thread::spawn(move || {
                    let backup = StalledBackup {
                        remaining: stall_at.into(),
                        entered,
                        release: Mutex::new(wait),
                    };
                    let cache = CacheStore::open(&root.join("vault"), backup).unwrap();
                    let publication = vault::Publication::new(cache, prepared).unwrap();
                    finish_publication(publication, operation, &publishing)
                });
                ready.recv_timeout(Duration::from_secs(2)).unwrap();
                let (finished, acknowledged) = mpsc::sync_channel(1);
                let control_shared = Arc::clone(&shared);
                let control_paths = paths.clone();
                let control = thread::spawn(move || {
                    let mut state = control_shared.0.lock().unwrap();
                    if let Some(event) = event {
                        state.host_events.record(event);
                        state.synchronize_host_events().unwrap();
                    } else {
                        let request = if lock {
                            Client::VaultLock {}
                        } else {
                            Client::Cancel { id }
                        };
                        handle(request, &mut state, &control_paths.load_policy()).unwrap();
                    }
                    assert!(state.pending.is_none());
                    finished.send(()).unwrap();
                });
                let result = acknowledged.recv_timeout(Duration::from_secs(1));
                release.send(()).unwrap();
                control.join().unwrap();
                let installed = worker.join().unwrap();
                result.expect("authority waited for storage");
                assert_eq!(installed.is_err(), lock || event.is_some());
                assert_eq!(
                    shared.0.lock().unwrap().provider.snapshot().is_none(),
                    lock || event == Some(crate::platform::HostSessionEvent::Logout)
                );
                assert!(
                    persistence::store(&paths.root)
                        .unwrap()
                        .load()
                        .unwrap()
                        .is_some()
                );
            }
        }
    }
}
