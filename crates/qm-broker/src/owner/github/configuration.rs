#![forbid(unsafe_code)]

use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(in crate::owner) enum Mode {
    Simulation,
    Github,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::owner) struct Repository {
    id: NonZeroU64,
    owner: String,
    name: String,
    #[serde(default)]
    writes: bool,
}

#[derive(Clone, Serialize)]
pub(in crate::owner) struct GitHubConfig {
    version: u8,
    mode: Mode,
    repositories: Vec<Repository>,
}

#[derive(Debug, PartialEq, Eq)]
pub(in crate::owner) struct Error;

impl GitHubConfig {
    pub(in crate::owner) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 65536 {
            return Err(Error);
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Document {
            version: u8,
            mode: Mode,
            repositories: Vec<Repository>,
        }
        let document: Document = serde_json::from_slice(bytes).map_err(|_| Error)?;
        let mut config = Self {
            version: document.version,
            mode: document.mode,
            repositories: document.repositories,
        };
        if config.version != 1 || config.repositories.len() > 64 {
            return Err(Error);
        }
        for (index, repository) in config.repositories.iter().enumerate() {
            let owner = &repository.owner;
            let name = &repository.name;
            if !valid_repository_name(&repository.full_name())
                || config.repositories[..index].iter().any(|previous| {
                    previous.id == repository.id
                        || (previous.owner.eq_ignore_ascii_case(owner)
                            && previous.name.eq_ignore_ascii_case(name))
                })
            {
                return Err(Error);
            }
        }
        config.repositories.sort_by_cached_key(|repository| {
            (
                repository.owner.to_ascii_lowercase(),
                repository.name.to_ascii_lowercase(),
            )
        });
        Ok(config)
    }

    pub(in crate::owner) fn mode(&self) -> Mode {
        self.mode
    }

    pub(in crate::owner) fn repository(&self, owner: &str, name: &str) -> Option<&Repository> {
        self.repositories.iter().find(|repository| {
            repository.owner.eq_ignore_ascii_case(owner)
                && repository.name.eq_ignore_ascii_case(name)
        })
    }

    pub(in crate::owner) fn digest(&self) -> [u8; 32] {
        digest(
            &SHA256,
            &serde_json::to_vec(self).expect("validated GitHub configuration is serializable"),
        )
        .as_ref()
        .try_into()
        .unwrap()
    }
}

pub(in crate::owner) fn valid_repository_name(value: &str) -> bool {
    let Some((owner, name)) = value.split_once('/') else {
        return false;
    };
    !owner.is_empty()
        && owner.len() <= 39
        && owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && owner.as_bytes()[0].is_ascii_alphanumeric()
        && owner.as_bytes()[owner.len() - 1].is_ascii_alphanumeric()
        && !name.is_empty()
        && name.len() <= 100
        && !matches!(name, "." | "..")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

impl Repository {
    pub(in crate::owner) fn id(&self) -> NonZeroU64 {
        self.id
    }
    pub(in crate::owner) fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/github_configuration.rs"]
mod tests;
