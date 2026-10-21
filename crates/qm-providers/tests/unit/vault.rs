use super::*;
use crate::{KdfAlgorithm, KdfParameters};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use rbw::cipherstring::CipherString;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
const ITEM: &str = "22222222-2222-4222-8222-222222222222";
const EMAIL: &str = "dummy@example.invalid";
const PASSWORD: &[u8] = b"quartermaster-dummy-master-password";
const CANARY: &[u8] = b"quartermaster-dummy-canary";
const LIMITS: KdfLimits = KdfLimits {
    pbkdf2_iterations: 2,
    argon2_iterations: 2,
    argon2_memory_mib: 8,
    argon2_parallelism: 2,
};

type CapturedRequest = (Method, String, HeaderMap, Vec<u8>);

#[derive(Clone)]
struct Fixture {
    profile: Value,
    sync: Value,
    protected_key: String,
    token_error: Option<(StatusCode, Value)>,
    refresh_error: Option<StatusCode>,
    prelogin_error: Option<(StatusCode, Value)>,
    redirect: Option<String>,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

impl Fixture {
    fn new() -> Self {
        let identity = KdfParameters {
            algorithm: KdfAlgorithm::Pbkdf2,
            iterations: 1,
            memory_mib: None,
            parallelism: None,
        }
        .validate(&LIMITS)
        .unwrap()
        .derive(EMAIL, PASSWORD)
        .unwrap();
        let key_bytes: Vec<_> = (0..64).collect();
        let protected_key = CipherString::encrypt_symmetric(identity.keys(), &key_bytes)
            .unwrap()
            .to_string();
        Self {
            profile: json!({"id": ACCOUNT, "email": EMAIL}),
            sync: json!({
                "profile": {"key": protected_key, "privateKey": "", "organizations": []},
                "folders": [],
                "ciphers": [{
                    "id": ITEM, "name": include_str!("../fixtures/dummy.type2").trim(),
                    "reprompt": 0,
                    "login": {"password": include_str!("../fixtures/dummy.type2").trim()}
                }]
            }),
            protected_key,
            token_error: None,
            refresh_error: None,
            prelogin_error: None,
            redirect: None,
            requests: Arc::default(),
        }
    }

    async fn serve(self) -> Server {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().fallback(handle).with_state(self);
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Server {
            url: format!("http://{address}"),
            task,
        }
    }
}

struct Server {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle(
    State(fixture): State<Fixture>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    fixture
        .requests
        .lock()
        .unwrap()
        .push((method, uri.path().into(), headers, body.to_vec()));
    if let Some(destination) = fixture.redirect {
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [("location", format!("{destination}{}", uri.path()))],
        )
            .into_response();
    }
    match uri.path() {
        "/identity/accounts/prelogin" => match fixture.prelogin_error {
            Some((status, error)) => (status, Json(error)).into_response(),
            None => Json(json!({"kdf": 0, "kdfIterations": 1})).into_response(),
        },
        "/identity/connect/token" => {
            if body
                .windows(b"grant_type=refresh_token".len())
                .any(|b| b == b"grant_type=refresh_token")
            {
                if let Some(status) = fixture.refresh_error {
                    return (status, Json(json!({"error": "invalid_grant"}))).into_response();
                }
                return Json(json!({"access_token": "dummy-new-access", "refresh_token": "dummy-rotated-refresh"})).into_response();
            }
            if let Some((status, error)) = fixture.token_error {
                return (status, Json(error)).into_response();
            }
            Json(json!({"access_token": "dummy-access", "refresh_token": "dummy-refresh", "key": fixture.protected_key})).into_response()
        }
        "/api/accounts/profile" => Json(fixture.profile).into_response(),
        "/api/sync" => Json(fixture.sync).into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

fn binding() -> ProviderBinding {
    ProviderBinding::new(
        "https://vault.example.invalid",
        ACCOUNT,
        EMAIL,
        ITEM,
        CredentialField::LoginPassword,
        "github-write",
    )
    .unwrap()
}

fn provider(server: &Server) -> RbwProvider {
    provider_with_field(server, CredentialField::LoginPassword)
}

fn provider_with_field(server: &Server, field: CredentialField) -> RbwProvider {
    let mut binding = binding();
    binding.server = server.url.clone();
    binding.field = field;
    RbwProvider::new(binding, LIMITS).unwrap()
}

fn assert_selected_credential(snapshot: &VaultSnapshot) {
    assert_eq!(
        snapshot.decrypt_selected_for_owner().unwrap().as_slice(),
        CANARY
    );
}

#[tokio::test]
async fn owner_decryption_reads_authenticated_material_without_fabricating_approval() {
    let server = Fixture::new().serve().await;
    let snapshot = provider(&server).login(PASSWORD).await.unwrap();

    let plaintext = snapshot.decrypt_selected_for_owner().unwrap();

    assert_eq!(&*plaintext, CANARY);
}

#[tokio::test]
async fn owner_decryption_rejects_changed_keys_and_ciphertext() {
    let server = Fixture::new().serve().await;
    for change_ciphertext in [false, true] {
        let mut snapshot = provider(&server).login(PASSWORD).await.unwrap();
        if change_ciphertext {
            let mut cipher = CipherString::new(snapshot.credential.encoded()).unwrap();
            let CipherString::Symmetric { ciphertext, .. } = &mut cipher else {
                unreachable!()
            };
            ciphertext[0] ^= 1;
            snapshot.credential = EncryptedCredential::parse(&cipher.to_string()).unwrap();
        } else {
            snapshot.selected_key[32] ^= 1;
        }

        assert!(matches!(
            snapshot.decrypt_selected_for_owner(),
            Err(ProviderError::InvalidResponse)
        ));
    }
}

#[tokio::test]
async fn owner_decryption_rejects_invalid_key_lengths() {
    let server = Fixture::new().serve().await;
    let mut snapshot = provider(&server).login(PASSWORD).await.unwrap();
    snapshot.selected_key = Zeroizing::new(vec![0; 63]);

    assert!(matches!(
        snapshot.decrypt_selected_for_owner(),
        Err(ProviderError::CacheIncompatible)
    ));
}

#[test]
fn configured_binding_rejects_ambiguous_identity_and_insecure_server_urls() {
    for server in [
        "http://vault.example.invalid",
        "https://user:password@vault.example.invalid",
        "https://vault.example.invalid?token=secret",
        "https://vault.example.invalid/#fragment",
    ] {
        assert!(
            ProviderBinding::new(
                server,
                ACCOUNT,
                EMAIL,
                ITEM,
                CredentialField::LoginPassword,
                "github-write"
            )
            .is_err()
        );
    }
    assert!(
        ProviderBinding::new(
            "https://vault.example.invalid",
            "",
            EMAIL,
            ITEM,
            CredentialField::LoginPassword,
            "github-write"
        )
        .is_err()
    );
    assert!(
        ProviderBinding::new(
            "https://vault.example.invalid",
            ACCOUNT,
            EMAIL,
            "first item",
            CredentialField::LoginPassword,
            "github-write"
        )
        .is_err()
    );
}

#[tokio::test]
async fn login_selects_and_preserves_the_exact_credential() {
    let mut fixture = Fixture::new();
    let mut unrelated = fixture.sync["ciphers"][0].clone();
    unrelated["id"] = json!("33333333-3333-4333-8333-333333333333");
    unrelated["login"]["password"] = json!("unrelated-invalid-ciphertext");
    fixture.sync["ciphers"]
        .as_array_mut()
        .unwrap()
        .insert(0, unrelated);
    let requests = fixture.requests.clone();
    let server = fixture.serve().await;

    let snapshot = provider(&server).login(PASSWORD).await.unwrap();

    assert_selected_credential(&snapshot);
    assert!(snapshot.synchronized_at() > OffsetDateTime::UNIX_EPOCH);
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|(method, _, _, _)| method == Method::GET || method == Method::POST)
    );
}

#[tokio::test]
async fn configured_server_307_preserves_login_and_refresh_bodies_across_origins() {
    let destination_fixture = Fixture::new();
    let requests = destination_fixture.requests.clone();
    let destination = destination_fixture.serve().await;
    let mut redirect_fixture = Fixture::new();
    redirect_fixture.redirect = Some(destination.url.clone());
    let server = redirect_fixture.serve().await;
    let provider = provider(&server);

    let snapshot = provider.login(PASSWORD).await.unwrap();
    let refreshed = provider.sync(&snapshot).await.unwrap();

    assert_selected_credential(&refreshed);
    assert_eq!(refreshed.refresh_token.as_str(), "dummy-rotated-refresh");
    let requests = requests.lock().unwrap();
    let token_requests: Vec<_> = requests
        .iter()
        .filter(|(_, path, _, _)| path == "/identity/connect/token")
        .collect();
    assert_eq!(token_requests.len(), 2);
    assert!(
        token_requests
            .iter()
            .all(|(method, _, _, body)| method == Method::POST && !body.is_empty())
    );
    let login: std::collections::HashMap<_, _> = url_form(&token_requests[0].3);
    assert_eq!(login.get("username").unwrap(), EMAIL);
    assert!(!login.get("password").unwrap().is_empty());
    let refresh = url_form(&token_requests[1].3);
    assert_eq!(refresh.get("refresh_token").unwrap(), "dummy-refresh");
}

fn url_form(bytes: &[u8]) -> std::collections::HashMap<String, String> {
    reqwest::Url::parse(&format!(
        "http://localhost/?{}",
        std::str::from_utf8(bytes).unwrap()
    ))
    .unwrap()
    .query_pairs()
    .into_owned()
    .collect()
}

#[tokio::test]
async fn wrong_account_missing_or_duplicate_item_reprompt_and_organization_fail_closed() {
    for (kind, expected) in [
        ("account", ProviderError::AccountMismatch),
        ("email", ProviderError::AccountMismatch),
        ("missing", ProviderError::ItemNotFound),
        ("duplicate", ProviderError::AmbiguousItem),
        ("reprompt", ProviderError::MasterPasswordRepromptRequired),
        ("organization", ProviderError::OrganizationUnsupported),
        ("cipher", ProviderError::CipherUnsupported),
    ] {
        let mut fixture = Fixture::new();
        match kind {
            "account" => fixture.profile["id"] = json!("33333333-3333-4333-8333-333333333333"),
            "email" => fixture.profile["email"] = json!("other@example.invalid"),
            "missing" => fixture.sync["ciphers"] = json!([]),
            "duplicate" => {
                let duplicate = fixture.sync["ciphers"][0].clone();
                fixture.sync["ciphers"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            "reprompt" => fixture.sync["ciphers"][0]["reprompt"] = json!(1),
            "organization" => fixture.sync["ciphers"][0]["organizationId"] = json!(ACCOUNT),
            "cipher" => fixture.sync["ciphers"][0]["login"]["password"] = json!("0.invalid"),
            _ => unreachable!(),
        }
        let server = fixture.serve().await;
        assert!(
            matches!(provider(&server).login(PASSWORD).await, Err(error) if error == expected),
            "{kind}"
        );
    }
}

#[tokio::test]
async fn invalid_credentials_and_mfa_requirements_are_typed_without_server_text() {
    for (description, extra, expected) in [
        (
            "invalid_username_or_password",
            json!({"errorModel": {"message": "SENSITIVE_SERVER_CANARY"}}),
            ProviderError::InvalidCredentials,
        ),
        (
            "Two factor required.",
            json!({"twoFactorProviders": [0]}),
            ProviderError::MfaUnsupported,
        ),
    ] {
        let mut fixture = Fixture::new();
        let mut error = json!({"error": "invalid_grant", "error_description": description});
        error
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        fixture.token_error = Some((StatusCode::BAD_REQUEST, error));
        let server = fixture.serve().await;
        let result = provider(&server).login(PASSWORD).await;
        assert!(matches!(result, Err(error) if error == expected));
        assert!(!format!("{expected:?}").contains("SENSITIVE_SERVER_CANARY"));
    }
}

#[tokio::test]
async fn rejected_refresh_is_reauthentication_and_connection_failure_is_offline() {
    let mut fixture = Fixture::new();
    fixture.refresh_error = Some(StatusCode::BAD_REQUEST);
    let mut server = fixture.serve().await;
    let provider = provider(&server);
    let snapshot = provider.login(PASSWORD).await.unwrap();

    assert!(matches!(
        provider.sync(&snapshot).await,
        Err(ProviderError::ReauthRequired)
    ));
    server.task.abort();
    (&mut server.task).await.unwrap_err();
    assert!(matches!(
        provider.sync(&snapshot).await,
        Err(ProviderError::ServerUnavailable)
    ));
    assert_selected_credential(&snapshot);
}

#[tokio::test]
async fn selected_item_key_and_exact_hidden_field_are_used_without_fallback() {
    let mut fixture = Fixture::new();
    let vault_keys = locked_keys(&(0..64).collect::<Vec<_>>()).unwrap();
    let item_key: Vec<_> = (64..128).collect();
    let item_keys = locked_keys(&item_key).unwrap();
    let encrypt = |bytes: &[u8]| {
        CipherString::encrypt_symmetric(&item_keys, bytes)
            .unwrap()
            .to_string()
    };
    fixture.sync["ciphers"][0]["key"] = json!(
        CipherString::encrypt_symmetric(&vault_keys, &item_key)
            .unwrap()
            .to_string()
    );
    fixture.sync["ciphers"][0]["fields"] = json!([
        {"type": 1, "name": encrypt(b"other"), "value": encrypt(b"other-secret")},
        {"type": 1, "name": encrypt(b"selected"), "value": encrypt(CANARY)}
    ]);
    let server = fixture.clone().serve().await;
    let provider = provider_with_field(&server, CredentialField::HiddenField("selected".into()));
    let snapshot = provider.login(PASSWORD).await.unwrap();
    assert_selected_credential(&snapshot);

    let mut duplicate = fixture.clone();
    let field = duplicate.sync["ciphers"][0]["fields"][1].clone();
    duplicate.sync["ciphers"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(field);
    let server = duplicate.serve().await;
    let other = provider_with_field(&server, CredentialField::HiddenField("selected".into()));
    assert!(matches!(
        other.login(PASSWORD).await,
        Err(ProviderError::AmbiguousItem)
    ));
}

#[tokio::test]
async fn invalid_mac_or_changed_vault_key_cannot_replace_a_valid_snapshot() {
    for rotate in [false, true] {
        let mut fixture = Fixture::new();
        if rotate {
            fixture.sync["profile"]["key"] = json!("2.different-vault-key");
        } else {
            let mut cipher = CipherString::new(
                fixture.sync["ciphers"][0]["login"]["password"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            let CipherString::Symmetric {
                mac: Some(ref mut mac),
                ..
            } = cipher
            else {
                unreachable!()
            };
            mac[0] ^= 1;
            fixture.sync["ciphers"][0]["login"]["password"] = json!(cipher.to_string());
        }
        let server = fixture.serve().await;
        let expected = if rotate {
            ProviderError::KeyChanged
        } else {
            ProviderError::InvalidResponse
        };
        assert!(matches!(provider(&server).login(PASSWORD).await, Err(error) if error == expected));
    }
}

#[tokio::test]
async fn server_failure_during_refresh_preserves_the_offline_snapshot() {
    for status in [StatusCode::UNAUTHORIZED, StatusCode::SERVICE_UNAVAILABLE] {
        let mut fixture = Fixture::new();
        fixture.refresh_error = Some(status);
        let server = fixture.serve().await;
        let provider = provider(&server);
        let snapshot = provider.login(PASSWORD).await.unwrap();
        let expected = if status == StatusCode::UNAUTHORIZED {
            ProviderError::ReauthRequired
        } else {
            ProviderError::ServerUnavailable
        };

        assert!(matches!(provider.sync(&snapshot).await, Err(error) if error == expected));
        assert_selected_credential(&snapshot);
    }
}

#[tokio::test]
async fn prelogin_rate_limits_and_outages_do_not_attempt_password_authentication() {
    for status in [
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let mut fixture = Fixture::new();
        fixture.prelogin_error = Some((status, json!({"error": "dummy unavailable"})));
        let requests = fixture.requests.clone();
        let server = fixture.serve().await;

        assert!(matches!(
            provider(&server).login(PASSWORD).await,
            Err(ProviderError::ServerUnavailable)
        ));
        assert!(
            requests
                .lock()
                .unwrap()
                .iter()
                .all(|(_, path, _, _)| path == "/identity/accounts/prelogin")
        );
    }
}

static DEPENDENCY_LOGS: DependencyLogs = DependencyLogs(Mutex::new(Vec::new()));
struct DependencyLogs(Mutex<Vec<String>>);
impl log::Log for DependencyLogs {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        self.0.lock().unwrap().push(record.args().to_string());
    }
    fn flush(&self) {}
}

#[tokio::test]
async fn upstream_error_bodies_and_session_tokens_stay_out_of_enabled_dependency_logs() {
    static LOGGER: std::sync::Once = std::sync::Once::new();
    LOGGER.call_once(|| {
        log::set_logger(&DEPENDENCY_LOGS).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
    });
    for error in [
        json!("DEPENDENCY_LOG_CANARY"),
        json!({
            "error": "unknown", "error_description": "DEPENDENCY_LOG_CANARY",
            "ssoEmail2faSessionToken": "DEPENDENCY_LOG_CANARY"
        }),
    ] {
        let mut fixture = Fixture::new();
        fixture.token_error = Some((StatusCode::BAD_REQUEST, error));
        let server = fixture.serve().await;
        assert!(provider(&server).login(PASSWORD).await.is_err());
    }
    assert!(
        DEPENDENCY_LOGS
            .0
            .lock()
            .unwrap()
            .iter()
            .all(|line| !line.contains("DEPENDENCY_LOG_CANARY"))
    );
}

#[tokio::test]
async fn deliberate_enrollment_discovers_and_pins_the_sole_personal_login() {
    let fixture = Fixture::new();
    let server = fixture.serve().await;
    let mut provider = provider(&server);
    provider.binding.account_id = "33333333-3333-4333-8333-333333333333".into();
    provider.binding.item_id = "44444444-4444-4444-8444-444444444444".into();

    let snapshot = provider.discover(PASSWORD).await.unwrap();

    assert_eq!(snapshot.binding().account_id(), ACCOUNT);
    assert_eq!(snapshot.binding().item_id(), ITEM);
    assert_eq!(snapshot.binding().email(), EMAIL);
    assert_selected_credential(&snapshot);
}

#[tokio::test]
async fn selected_enrollment_discovers_the_account_without_opening_other_items() {
    let mut fixture = Fixture::new();
    let mut unrelated = fixture.sync["ciphers"][0].clone();
    unrelated["id"] = json!("33333333-3333-4333-8333-333333333333");
    unrelated["login"]["password"] = json!("unrelated-invalid-ciphertext");
    fixture.sync["ciphers"]
        .as_array_mut()
        .unwrap()
        .insert(0, unrelated);
    let server = fixture.serve().await;
    let mut provider = provider(&server);
    provider.binding.account_id = uuid::Uuid::nil().to_string();

    let snapshot = provider
        .login_selected(PASSWORD, Selection::DiscoverAccount)
        .await
        .unwrap();

    assert_eq!(snapshot.binding().account_id(), ACCOUNT);
    assert_eq!(snapshot.binding().item_id(), ITEM);
    assert_selected_credential(&snapshot);
}

#[tokio::test]
async fn selected_enrollment_rejects_missing_duplicate_or_wrong_account_items() {
    for (kind, expected) in [
        ("missing", ProviderError::ItemNotFound),
        ("duplicate", ProviderError::AmbiguousItem),
        ("wrong-email", ProviderError::AccountMismatch),
    ] {
        let mut fixture = Fixture::new();
        match kind {
            "missing" => {
                fixture.sync["ciphers"][0]["id"] = json!("33333333-3333-4333-8333-333333333333")
            }
            "duplicate" => {
                let duplicate = fixture.sync["ciphers"][0].clone();
                fixture.sync["ciphers"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            "wrong-email" => fixture.profile["email"] = json!("other@example.invalid"),
            _ => unreachable!(),
        }
        let server = fixture.serve().await;
        let mut provider = provider(&server);
        provider.binding.account_id = uuid::Uuid::nil().to_string();

        assert!(
            matches!(provider.login_selected(PASSWORD, Selection::DiscoverAccount).await,
                         Err(error) if error == expected),
            "{kind}"
        );
    }
}

#[tokio::test]
async fn selected_enrollment_rejects_malformed_item_ids_before_network_access() {
    assert!(matches!(
        RbwProvider::enroll_selected_login(
            "https://vault.example.invalid",
            EMAIL,
            "not-a-uuid",
            PASSWORD,
            LIMITS,
            "github-write"
        )
        .await,
        Err(ProviderError::InvalidBinding)
    ));
}

#[tokio::test]
async fn enrollment_discovery_rejects_empty_ambiguous_or_wrong_account_vaults() {
    for (kind, expected) in [
        ("empty", ProviderError::ItemNotFound),
        ("multiple", ProviderError::AmbiguousItem),
        ("wrong-email", ProviderError::AccountMismatch),
    ] {
        let mut fixture = Fixture::new();
        match kind {
            "empty" => fixture.sync["ciphers"] = json!([]),
            "multiple" => {
                let mut other = fixture.sync["ciphers"][0].clone();
                other["id"] = json!("33333333-3333-4333-8333-333333333333");
                fixture.sync["ciphers"].as_array_mut().unwrap().push(other);
            }
            "wrong-email" => fixture.profile["email"] = json!("other@example.invalid"),
            _ => unreachable!(),
        }
        let server = fixture.serve().await;
        assert!(
            matches!(provider(&server).discover(PASSWORD).await, Err(error) if error == expected),
            "{kind}"
        );
    }
}
