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
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn configuration() -> Value {
        json!({"version":1,"mode":"github","repositories":[
            {"id":123,"owner":"Quartermaster","name":"one"},
            {"id":456,"owner":"Quartermaster","name":"two","writes":false}
        ]})
    }

    fn decode(value: &Value) -> Result<GitHubConfig, Error> {
        GitHubConfig::decode(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn github_configuration_requires_an_explicit_mode_and_defaults_writes_to_false() {
        let config = decode(&configuration()).unwrap();
        assert_eq!(config.mode, Mode::Github);
        assert_eq!(config.repositories.len(), 2);
        assert!(
            config
                .repositories
                .iter()
                .all(|repository| !repository.writes)
        );
        assert!(decode(&json!({"version":1,"mode":"simulation","repositories":[]})).is_ok());
        assert!(decode(&json!({"version":1,"repositories":[]})).is_err());
    }

    #[test]
    fn github_configuration_rejects_unknown_settings_and_unsafe_repository_names() {
        for field in ["endpoint", "proxy", "token", "trustRoots", "ignored"] {
            let mut value = configuration();
            value[field] = "override".into();
            assert!(decode(&value).is_err(), "accepted field {field}");
        }
        for owner in [
            "",
            "-owner",
            "owner-",
            "owner/name",
            "owner%2fname",
            "owner..",
            "owner\r\nx: y",
        ] {
            let mut value = configuration();
            value["repositories"][0]["owner"] = owner.into();
            assert!(decode(&value).is_err(), "accepted owner {owner:?}");
        }
        for name in [
            "",
            ".",
            "..",
            "../repo",
            "repo/name",
            "repo%2fname",
            "repo?x=1",
            "repo\r\n",
            "repo#fragment",
        ] {
            let mut value = configuration();
            value["repositories"][0]["name"] = name.into();
            assert!(decode(&value).is_err(), "accepted name {name:?}");
        }
    }

    #[test]
    fn github_configuration_rejects_duplicate_ids_case_aliases_and_invalid_numbers() {
        for change in [
            "id",
            "name",
            "zero",
            "negative",
            "version",
            "mode",
            "unknownRepositoryField",
        ] {
            let mut value = configuration();
            match change {
                "id" => value["repositories"][1]["id"] = 123.into(),
                "name" => {
                    value["repositories"][1]["owner"] = "quartermaster".into();
                    value["repositories"][1]["name"] = "ONE".into();
                }
                "zero" => value["repositories"][0]["id"] = 0.into(),
                "negative" => value["repositories"][0]["id"] = (-1).into(),
                "version" => value["version"] = 2.into(),
                "mode" => value["mode"] = "automatic".into(),
                _ => value["repositories"][0]["url"] = "https://elsewhere.invalid".into(),
            }
            assert!(decode(&value).is_err(), "accepted {change}");
        }
        assert!(
            GitHubConfig::decode(
                br#"{"version":1,"mode":"simulation","mode":"github","repositories":[]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn github_configuration_digest_is_stable_for_equivalent_defaults_and_repository_order() {
        let original = decode(&configuration()).unwrap();
        let mut equivalent = configuration();
        equivalent["repositories"][0]["writes"] = false.into();
        equivalent["repositories"].as_array_mut().unwrap().reverse();

        assert_eq!(original.digest(), decode(&equivalent).unwrap().digest());
        for field in ["id", "owner", "name", "writes"] {
            let mut changed = configuration();
            changed["repositories"][0][field] = match field {
                "id" => 789.into(),
                "writes" => true.into(),
                _ => "different".into(),
            };
            assert_ne!(original.digest(), decode(&changed).unwrap().digest());
        }
    }

    #[test]
    fn github_configuration_bounds_file_and_repository_counts() {
        assert!(GitHubConfig::decode(&vec![b' '; 65537]).is_err());
        let mut value = configuration();
        value["repositories"] = (1..=65)
            .map(|id| json!({"id":id,"owner":"test","name":format!("repo{id}")}))
            .collect();
        assert!(decode(&value).is_err());
    }
}
