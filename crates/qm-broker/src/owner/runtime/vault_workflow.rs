use super::{ServicePaths, Shared, failure};
use crate::owner::protocol::Client;
use crate::{
    owner::vault::{self, Source},
    platform::macos::ipc,
};
use qm_providers::{RbwProvider, VaultProvider, VaultSnapshot};
use std::{io, sync::Arc};
use zeroize::Zeroizing;

enum VaultWork {
    Login {
        server: String,
        email: String,
        password: Zeroizing<String>,
        item_id: Option<String>,
    },
    Unlock(Source),
    Sync(Arc<VaultSnapshot>),
    Discard(Source),
}

enum Output {
    Unlocked(VaultSnapshot),
    Updated(VaultSnapshot),
    Discarded,
}

impl VaultWork {
    async fn execute(self) -> Result<Output, vault::Error> {
        match self {
            VaultWork::Login {
                server,
                email,
                password,
                item_id,
            } => {
                if password.is_empty() || password.len() > 4096 {
                    Err(qm_providers::ProviderError::InvalidCredentials.into())
                } else {
                    let snapshot = match item_id {
                        Some(item_id) => {
                            RbwProvider::enroll_selected_login(
                                &server,
                                &email,
                                &item_id,
                                password.as_bytes(),
                                vault::LIMITS,
                                "github-write",
                            )
                            .await
                        }
                        None => {
                            RbwProvider::enroll_sole_login(
                                &server,
                                &email,
                                password.as_bytes(),
                                vault::LIMITS,
                                "github-write",
                            )
                            .await
                        }
                    };
                    snapshot.map(Output::Updated).map_err(Into::into)
                }
            }
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
            VaultWork::Discard(source) => {
                tokio::task::spawn_blocking(move || source.delete_device())
                    .await
                    .map_err(|_| vault::Error::Storage)
                    .and_then(|result| result.map(|()| Output::Discarded))
            }
        }
    }
}

pub(super) async fn vault_operation(
    message: Client,
    connection: &ipc::Connection<'_>,
    shared: &Shared,
    paths: &ServicePaths,
) -> io::Result<crate::CacheStatus> {
    let (mut operation, work) = {
        let mut state = shared.0.lock().map_err(|_| failure("state unavailable"))?;
        state.ensure_host_session()?;
        if !connection.is_connected()
            || state
                .ui
                .as_ref()
                .is_none_or(|ui| ui.connection != Some(connection.id()))
        {
            return Err(failure("UI enrolment required"));
        }
        if !matches!(&message, Client::VaultSync {}) {
            state.disconnect_ui();
        }
        let source = match Source::capture(&paths.root) {
            Ok(source) => source,
            Err(error) => return Ok(vault::error_reply(error)),
        };
        let reservation = match message {
            Client::VaultLogin {
                server,
                email,
                password,
                item_id,
            } => state
                .provider
                .begin_login(source.binding(), source.minimum_sync(), source.revision)
                .map(|operation| {
                    (
                        operation,
                        VaultWork::Login {
                            server,
                            email,
                            password,
                            item_id,
                        },
                    )
                })
                .map_err(vault::Error::from),
            Client::VaultUnlock {} => source.identity().and_then(|identity| {
                state
                    .provider
                    .begin_unlock(identity)
                    .map(|operation| (operation, VaultWork::Unlock(source)))
                    .map_err(Into::into)
            }),
            Client::VaultSync {} => source.identity().and_then(|identity| {
                state
                    .provider
                    .begin_refresh(&identity)
                    .map(|(operation, snapshot)| (operation, VaultWork::Sync(snapshot)))
                    .map_err(Into::into)
            }),
            Client::VaultDiscard {} => state
                .provider
                .begin_discard(source.revision)
                .map(|operation| (operation, VaultWork::Discard(source)))
                .map_err(Into::into),
            _ => return Err(failure("unsupported vault operation")),
        };
        match reservation {
            Ok(reservation) => reservation,
            Err(error) => return Ok(vault::error_reply(error)),
        }
    };
    let result = work.execute().await;
    let error = match result {
        Ok(Output::Updated(snapshot)) => {
            let prepared = prepare_cache_update(shared, paths, &mut operation, snapshot).await;
            match prepared {
                Ok(mut prepared) => {
                    let reply = {
                        let mut state =
                            shared.0.lock().map_err(|_| failure("state unavailable"))?;
                        match vault::publish_update(
                            &paths.root,
                            &mut state.provider,
                            operation,
                            &mut prepared,
                        ) {
                            Ok(()) => vault::status(&paths.root, state.provider.snapshot()),
                            Err(error) => vault::error_reply(error),
                        }
                    };
                    drop(prepared);
                    return Ok(reply);
                }
                Err(error) => error,
            }
        }
        Ok(Output::Unlocked(snapshot)) => {
            let mut state = shared.0.lock().map_err(|_| failure("state unavailable"))?;
            return Ok(
                match vault::finish_unlock(&paths.root, &mut state.provider, operation, snapshot) {
                    Ok(()) => vault::status(&paths.root, state.provider.snapshot()),
                    Err(error) => vault::error_reply(error),
                },
            );
        }
        Ok(Output::Discarded) => {
            let mut state = shared.0.lock().map_err(|_| failure("state unavailable"))?;
            return Ok(
                match vault::finish_discard(&paths.root, &mut state.provider, operation) {
                    Ok(()) => vault::status(&paths.root, None),
                    Err(error) => vault::error_reply(error),
                },
            );
        }
        Err(error) => error,
    };
    let mut state = shared.0.lock().map_err(|_| failure("state unavailable"))?;
    state.provider.release(&operation);
    Ok(vault::error_reply(error))
}

async fn prepare_cache_update(
    shared: &Shared,
    paths: &ServicePaths,
    operation: &mut crate::owner::provider_lifecycle::ProviderOperation,
    snapshot: VaultSnapshot,
) -> Result<vault::PreparedCache, vault::Error> {
    let intent = {
        let state = shared.0.lock().map_err(|_| vault::Error::Storage)?;
        vault::begin_persistence(&paths.root, &state.provider, operation, &snapshot)?
    };
    tokio::task::spawn_blocking(move || intent.seal(snapshot))
        .await
        .map_err(|_| vault::Error::Storage)?
}
