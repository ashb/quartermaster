#![forbid(unsafe_code)]

use super::configuration::GitHubConfig;
#[cfg(unix)]
use super::{https::AuthenticatedMetadata, response::MetadataFailure};
use crate::owner::{
    dispatch::{self, CredentialSelection},
    operation::OperationId,
    request::FrozenOperation,
};
use ring::digest::{SHA256, digest};
use serde::Deserialize;
use std::{io::Cursor, num::NonZeroU64};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub(in crate::owner) struct Error;

pub(in crate::owner) struct RepositoryLookup {
    repository_id: NonZeroU64,
    repository: String,
    path: String,
    configuration_digest: [u8; 32],
    selection: CredentialSelection,
    policy_generation: u64,
    configuration: GitHubConfig,
}

pub(in crate::owner) struct RepositoryBinding {
    repository_id: NonZeroU64,
    repository: String,
    configuration_digest: [u8; 32],
    selection: CredentialSelection,
    policy_generation: u64,
    configuration: GitHubConfig,
}

pub(in crate::owner) struct PreparedMetadata {
    id: OperationId,
    lookup: RepositoryLookup,
    bytes: Zeroizing<Vec<u8>>,
    credential: Zeroizing<Vec<u8>>,
    wire_digest: [u8; 32],
}

impl RepositoryLookup {
    pub(in crate::owner) fn new(
        config: &GitHubConfig,
        request: &FrozenOperation,
        selection: CredentialSelection,
        policy_generation: u64,
    ) -> Result<Self, Error> {
        if !request.matches_configuration(config) {
            return Err(Error);
        }
        let (owner, name) = request.repository().split_once('/').ok_or(Error)?;
        let repository = config.repository(owner, name).ok_or(Error)?;
        Ok(Self {
            repository_id: repository.id(),
            repository: repository.full_name(),
            path: format!("/repos/{}", repository.full_name()),
            configuration_digest: config.digest(),
            selection,
            policy_generation,
            configuration: config.clone(),
        })
    }

    pub(in crate::owner) fn path(&self) -> &str {
        &self.path
    }

    fn matches(
        &self,
        request: &FrozenOperation,
        selection: &CredentialSelection,
        policy_generation: u64,
    ) -> bool {
        self.policy_generation == policy_generation
            && &self.selection == selection
            && request.repository() == self.repository
            && request.github_identity() == Some((self.repository_id, self.configuration_digest))
    }

    fn verify(&self, bytes: &[u8]) -> Result<RepositoryBinding, Error> {
        #[derive(Deserialize)]
        struct Metadata {
            id: NonZeroU64,
            full_name: String,
        }
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(Error);
        }
        let metadata: Metadata = serde_json::from_slice(bytes).map_err(|_| Error)?;
        if metadata.id != self.repository_id || metadata.full_name != self.repository {
            return Err(Error);
        }
        Ok(RepositoryBinding {
            repository_id: self.repository_id,
            repository: self.repository.clone(),
            configuration_digest: self.configuration_digest,
            selection: self.selection.clone(),
            policy_generation: self.policy_generation,
            configuration: self.configuration.clone(),
        })
    }

    #[cfg(test)]
    pub(in crate::owner) fn verify_fixture(
        &self,
        bytes: &[u8],
    ) -> Result<RepositoryBinding, Error> {
        self.verify(bytes)
    }
}

impl PreparedMetadata {
    pub(in crate::owner) fn new(
        id: OperationId,
        lookup: RepositoryLookup,
        snapshot: &qm_providers::VaultSnapshot,
    ) -> Result<Self, dispatch::Error> {
        if !lookup.selection.matches_snapshot(snapshot) {
            return Err(dispatch::Error::CredentialMismatch);
        }
        let credential = snapshot
            .decrypt_selected_for_owner()
            .map_err(dispatch::Error::Provider)?;
        dispatch::validate_token(&credential)?;
        let mut bytes = Zeroizing::new(
            format!(
                "GET {} HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer ",
                lookup.path()
            )
            .into_bytes(),
        );
        bytes.extend_from_slice(&credential);
        bytes.extend_from_slice(b"\r\nUser-Agent: Quartermaster\r\nAccept: application/vnd.github+json\r\nAccept-Encoding: identity\r\nX-GitHub-Api-Version: 2026-03-10\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let wire_digest = digest(&SHA256, &bytes).as_ref().try_into().unwrap();
        Ok(Self {
            id,
            lookup,
            bytes,
            credential,
            wire_digest,
        })
    }

    pub(in crate::owner) fn id(&self) -> OperationId {
        self.id
    }
    pub(in crate::owner) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(in crate::owner) fn credential(&self) -> &[u8] {
        &self.credential
    }
    pub(in crate::owner) fn wire_digest(&self) -> [u8; 32] {
        self.wire_digest
    }
    pub(in crate::owner) fn intact(&self) -> bool {
        digest(&SHA256, &self.bytes).as_ref() == self.wire_digest
    }
    pub(in crate::owner) fn matches(
        &self,
        id: OperationId,
        request: &FrozenOperation,
        selection: &CredentialSelection,
        policy_generation: u64,
    ) -> bool {
        self.id == id && self.lookup.matches(request, selection, policy_generation) && self.intact()
    }
}

impl RepositoryBinding {
    #[cfg(unix)]
    pub(super) fn from_authenticated(
        response: AuthenticatedMetadata,
    ) -> Result<Self, MetadataFailure> {
        let (request, wire) = response.into_parts();
        let bytes = wire.metadata_bytes(request.credential())?;
        request
            .lookup
            .verify(bytes)
            .map_err(|_| MetadataFailure::Invalid)
    }

    pub(in crate::owner) fn redirect(
        &self,
        from: &FrozenOperation,
        target: &str,
    ) -> Result<FrozenOperation, Error> {
        if from.github_identity() != Some((self.repository_id, self.configuration_digest))
            || from.repository() != self.repository
        {
            return Err(Error);
        }
        let path = target
            .strip_prefix("https://api.github.com:443/")
            .or_else(|| target.strip_prefix("https://api.github.com/"))
            .map(|path| format!("/{path}"))
            .or_else(|| target.starts_with('/').then(|| target.to_owned()))
            .ok_or(Error)?;
        let numeric = format!("/repositories/{}/", self.repository_id);
        let path = path.strip_prefix(&numeric).map_or_else(
            || path.clone(),
            |suffix| format!("/repos/{}/{suffix}", self.repository),
        );
        let operation = crate::owner::request::read_configured(
            &mut Cursor::new(format!(
                "GET {path} HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
            )),
            Some(&self.configuration),
        )
        .map_err(|_| Error)?;
        if operation.repository() != self.repository {
            return Err(Error);
        }
        Ok(operation)
    }

    pub(in crate::owner) fn matches(
        &self,
        request: &FrozenOperation,
        selection: &CredentialSelection,
        policy_generation: u64,
    ) -> bool {
        self.policy_generation == policy_generation
            && &self.selection == selection
            && request.repository() == self.repository
            && request.github_identity() == Some((self.repository_id, self.configuration_digest))
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/github_repository.rs"]
mod tests;
