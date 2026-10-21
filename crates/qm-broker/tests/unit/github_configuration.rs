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
