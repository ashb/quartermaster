use crate::owner::{
    identity::VerifiedPrincipal,
    operation::{OperationId, OperationRegistry},
    policy::{ApprovalRequirement, AuthorizationOutcome, Authorizer},
    test_support::close_request,
};
use qm_providers::{ApprovalSession, VaultSnapshot};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use std::time::{Duration, Instant};

pub(crate) fn session(authorizer: &Authorizer) -> (ApprovalSession, EcdsaKeyPair) {
    let random = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
        .unwrap();
    let session = ApprovalSession::new(
        [2; 16],
        authorizer.policy_digest().unwrap(),
        key.public_key().as_ref(),
    )
    .unwrap();
    (session, key)
}

pub(crate) fn read_grant(
    registry: &mut OperationRegistry,
    authorizer: &mut Authorizer,
    principal: &VerifiedPrincipal,
    snapshot: &VaultSnapshot,
) -> (OperationId, ApprovalSession, EcdsaKeyPair, [u8; 32]) {
    let result = read_grant_at(registry, authorizer, principal, snapshot, Instant::now());
    let prepared = crate::owner::execution::prepare_simulation(
        registry,
        result.0,
        principal,
        authorizer,
        snapshot,
        Instant::now(),
    )
    .unwrap();
    registry.ready(result.0, principal, &prepared).unwrap();
    registry
        .admit(result.0, principal, authorizer, Instant::now())
        .unwrap();
    result
}

pub(crate) fn read_grant_at(
    registry: &mut OperationRegistry,
    authorizer: &Authorizer,
    principal: &VerifiedPrincipal,
    snapshot: &VaultSnapshot,
    created: Instant,
) -> (OperationId, ApprovalSession, EcdsaKeyPair, [u8; 32]) {
    let requirement = authorizer
        .request_read_grant(principal, super::read_request(), snapshot.binding().role())
        .unwrap();
    sign(
        registry,
        authorizer,
        principal,
        snapshot,
        requirement,
        created,
        Duration::ZERO,
    )
}

pub(crate) fn write(
    registry: &mut OperationRegistry,
    authorizer: &Authorizer,
    principal: &VerifiedPrincipal,
    snapshot: &VaultSnapshot,
) -> (OperationId, ApprovalSession) {
    write_at(
        registry,
        authorizer,
        principal,
        snapshot,
        Instant::now(),
        Duration::ZERO,
    )
}

pub(crate) fn write_at(
    registry: &mut OperationRegistry,
    authorizer: &Authorizer,
    principal: &VerifiedPrincipal,
    snapshot: &VaultSnapshot,
    created: Instant,
    proof_delay: Duration,
) -> (OperationId, ApprovalSession) {
    let AuthorizationOutcome::RequireApproval(requirement) = authorizer
        .authorize(principal, close_request(), created)
        .unwrap()
    else {
        panic!()
    };
    let (id, session, _, _) = sign(
        registry,
        authorizer,
        principal,
        snapshot,
        requirement,
        created,
        proof_delay,
    );
    (id, session)
}

fn sign(
    registry: &mut OperationRegistry,
    authorizer: &Authorizer,
    principal: &VerifiedPrincipal,
    snapshot: &VaultSnapshot,
    requirement: ApprovalRequirement,
    created: Instant,
    proof_delay: Duration,
) -> (OperationId, ApprovalSession, EcdsaKeyPair, [u8; 32]) {
    let document = review(requirement.request().clone(), requirement.grant_claims());
    let request_digest = ring::digest::digest(&ring::digest::SHA256, document.bytes())
        .as_ref()
        .try_into()
        .unwrap();
    let id = registry
        .register(AuthorizationOutcome::RequireApproval(requirement), created)
        .unwrap();
    registry.bind_review(id, principal, &document).unwrap();
    let (session, key) = session(authorizer);
    registry.begin_approval(id, principal, &session).unwrap();
    let authenticated = Instant::now();
    registry
        .authentication(
            id,
            principal,
            authenticated,
            authenticated,
            authenticated.duration_since(created),
        )
        .unwrap();
    let challenge = registry
        .challenge(id, principal, super::vault::selection(snapshot))
        .unwrap();
    let signature = key.sign(&SystemRandom::new(), &challenge.bytes).unwrap();
    registry
        .proof(
            id,
            principal,
            authorizer,
            signature.as_ref(),
            authenticated + proof_delay,
        )
        .unwrap();
    (id, session, key, request_digest)
}

pub(crate) fn review(
    request: crate::owner::request::FrozenOperation,
    claims: Option<crate::owner::grant::ReadGrantClaims>,
) -> crate::owner::review::ReviewDocument<std::collections::BTreeMap<String, String>> {
    crate::owner::review::ReviewDocument::new(request, claims, std::collections::BTreeMap::new())
        .unwrap()
}
