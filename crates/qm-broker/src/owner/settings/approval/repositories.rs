use super::{
    BASE64, Challenge, Engine, Error, Manager, Pending, Phase, Record, Review, signing_bytes,
};
use crate::owner::{dispatch, github::configuration::valid_repository_name};
use qm_providers::VaultSnapshot;
use qm_types::MonotonicTimestamp;
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, num::NonZeroU64};
use zeroize::Zeroizing;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::owner) struct RepositoryName {
    owner: String,
    name: String,
}

impl RepositoryName {
    fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

pub(in crate::owner) struct PreparedLookup {
    id: String,
    connection: u64,
    index: usize,
    name: RepositoryName,
    bytes: Zeroizing<Vec<u8>>,
    credential: Zeroizing<Vec<u8>>,
    digest: [u8; 32],
}

pub(in crate::owner) struct LookupAdmission<'a> {
    digest: [u8; 32],
    expires: MonotonicTimestamp,
    _transaction: PhantomData<&'a mut ()>,
}

pub(in crate::owner) struct LookupResult {
    id: String,
    connection: u64,
    index: usize,
    requested: RepositoryName,
    repository_id: NonZeroU64,
    full_name: String,
}

fn document(
    previous: &Record,
    proposed: &Record,
    additions: &[RepositoryName],
) -> Result<Vec<u8>, Error> {
    #[derive(Serialize)]
    struct Document<'a> {
        version: &'static str,
        previous: &'a Record,
        proposed: &'a Record,
        #[serde(skip_serializing_if = "<[RepositoryName]>::is_empty")]
        additions: &'a [RepositoryName],
    }
    let bytes = serde_json::to_vec(&Document {
        version: "quartermaster.settings-review.v1",
        previous,
        proposed,
        additions,
    })
    .map_err(|_| Error::Invalid)?;
    if bytes.len() > 2 * super::super::RECORD_LIMIT {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

impl<C> Manager<C> {
    pub(in crate::owner) fn add_repositories(
        &mut self,
        id: &str,
        connection: u64,
        additions: Vec<RepositoryName>,
    ) -> Result<Review, Error> {
        let Phase::Reviewing(pending) = &mut self.phase else {
            return Err(Error::Stale);
        };
        if pending.review.id != id
            || pending.connection != connection
            || pending.authentication.is_some()
            || !pending.additions.is_empty()
        {
            return Err(Error::Stale);
        }
        let config = pending
            .proposed
            .settings()
            .and_then(|settings| settings.github.as_ref())
            .ok_or(Error::Invalid)?;
        if pending.proposed.provider().is_none()
            || additions.is_empty()
            || config.repositories().len() + additions.len() > 64
        {
            return Err(Error::Invalid);
        }
        for (index, name) in additions.iter().enumerate() {
            if !valid_repository_name(&name.full_name())
                || config.repository(&name.owner, &name.name).is_some()
                || additions[..index]
                    .iter()
                    .any(|old| old.full_name().eq_ignore_ascii_case(&name.full_name()))
            {
                return Err(Error::Invalid);
            }
        }
        let bytes = document(&self.record, &pending.proposed, &additions)?;
        pending.review.document = BASE64.encode(&bytes);
        pending.review.digest = BASE64.encode(digest(&SHA256, &bytes));
        pending.additions = additions;
        Ok(pending.review.clone())
    }

    pub(in crate::owner) fn lookup_count(&self, id: &str, connection: u64) -> Result<usize, Error> {
        match &self.phase {
            Phase::Reviewing(p) if p.review.id == id && p.connection == connection => {
                Ok(p.additions.len())
            }
            _ => Err(Error::Stale),
        }
    }

    fn lookup_pending(
        &self,
        id: &str,
        connection: u64,
        now: MonotonicTimestamp,
    ) -> Result<&Pending<C>, Error> {
        let Phase::Reviewing(pending) = &self.phase else {
            return Err(Error::Stale);
        };
        if pending.review.id != id
            || pending.connection != connection
            || pending.additions.is_empty()
        {
            return Err(Error::Stale);
        }
        let (authenticated, expires, _) = pending.authentication.as_ref().ok_or(Error::Stale)?;
        if now < *authenticated || now >= *expires {
            return Err(Error::Expired);
        }
        Ok(pending)
    }

    pub(in crate::owner) fn prepare_lookup(
        &self,
        id: &str,
        connection: u64,
        snapshot: &VaultSnapshot,
        now: MonotonicTimestamp,
    ) -> Result<PreparedLookup, Error> {
        let pending = self.lookup_pending(id, connection, now)?;
        if pending.lookup_next != pending.lookup_complete
            || pending
                .proposed
                .provider()
                .is_none_or(|pin| &pin.binding != snapshot.binding())
        {
            return Err(Error::Invalid);
        }
        let name = pending
            .additions
            .get(pending.lookup_next)
            .ok_or(Error::Stale)?
            .clone();
        let credential = snapshot
            .decrypt_selected_for_owner()
            .map_err(|_| Error::Invalid)?;
        dispatch::validate_token(&credential).map_err(|_| Error::Invalid)?;
        let mut bytes = Zeroizing::new(
            format!(
                "GET /repos/{} HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer ",
                name.full_name()
            )
            .into_bytes(),
        );
        bytes.extend_from_slice(&credential);
        bytes.extend_from_slice(b"\r\nUser-Agent: Quartermaster\r\nAccept: application/vnd.github+json\r\nAccept-Encoding: identity\r\nX-GitHub-Api-Version: 2022-11-28\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let hash = digest(&SHA256, &bytes).as_ref().try_into().unwrap();
        Ok(PreparedLookup {
            id: id.into(),
            connection,
            index: pending.lookup_next,
            name,
            bytes,
            credential,
            digest: hash,
        })
    }

    pub(in crate::owner) fn admit_lookup<'a>(
        &'a mut self,
        request: &PreparedLookup,
        now: MonotonicTimestamp,
    ) -> Result<LookupAdmission<'a>, Error> {
        let pending = self.lookup_pending(&request.id, request.connection, now)?;
        if pending.lookup_next != pending.lookup_complete
            || pending.lookup_next != request.index
            || pending.additions.get(request.index) != Some(&request.name)
            || !request.intact()
        {
            return Err(Error::Stale);
        }
        let expires = pending.authentication.as_ref().ok_or(Error::Stale)?.1;
        let Phase::Reviewing(pending) = &mut self.phase else {
            unreachable!()
        };
        pending.lookup_next += 1;
        Ok(LookupAdmission {
            digest: request.digest,
            expires,
            _transaction: PhantomData,
        })
    }

    pub(in crate::owner) fn accept_lookup(
        &mut self,
        result: LookupResult,
        now: MonotonicTimestamp,
    ) -> Result<(), Error> {
        let pending = self.lookup_pending(&result.id, result.connection, now)?;
        if pending.lookup_complete != result.index
            || pending.lookup_next != result.index + 1
            || pending.additions.get(result.index) != Some(&result.requested)
        {
            return Err(Error::Stale);
        }
        let Phase::Reviewing(pending) = &mut self.phase else {
            unreachable!()
        };
        let settings = pending.proposed.settings.as_mut().ok_or(Error::Invalid)?;
        settings.github = Some(
            settings
                .github
                .as_ref()
                .ok_or(Error::Invalid)?
                .with_repository(result.repository_id, &result.full_name)
                .map_err(|_| Error::Invalid)?,
        );
        pending.lookup_complete += 1;
        Ok(())
    }

    pub(in crate::owner) fn resolved_challenge(
        &mut self,
        id: &str,
        connection: u64,
        now: MonotonicTimestamp,
    ) -> Result<Challenge, Error> {
        let pending = self.lookup_pending(id, connection, now)?;
        if pending.lookup_complete != pending.additions.len() {
            return Err(Error::Stale);
        }
        let Phase::Reviewing(pending) = &mut self.phase else {
            unreachable!()
        };
        let bytes = document(&self.record, &pending.proposed, &[])?;
        Record::decode(&serde_json::to_vec(&pending.proposed).map_err(|_| Error::Invalid)?)?;
        pending.review.document = BASE64.encode(&bytes);
        pending.review.digest = BASE64.encode(digest(&SHA256, &bytes));
        let (authenticated, expires, bytes) =
            pending.authentication.as_mut().ok_or(Error::Stale)?;
        *bytes = signing_bytes(&pending.review, *authenticated)?;
        pending.additions.clear();
        Ok(Challenge {
            review: pending.review.clone(),
            authenticated: *authenticated,
            expires: *expires,
            bytes: BASE64.encode(bytes),
        })
    }
}

impl PreparedLookup {
    pub(in crate::owner) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(in crate::owner) fn credential(&self) -> &[u8] {
        &self.credential
    }
    pub(in crate::owner) fn intact(&self) -> bool {
        digest(&SHA256, &self.bytes).as_ref() == self.digest
    }
}

impl LookupAdmission<'_> {
    pub(in crate::owner) fn accepts(
        self,
        request: &PreparedLookup,
        now: MonotonicTimestamp,
    ) -> bool {
        now < self.expires && self.digest == request.digest && request.intact()
    }
}

impl LookupResult {
    #[cfg(target_os = "macos")]
    pub(in crate::owner) fn from_authenticated(
        response: crate::owner::github::https::AuthenticatedLookup,
    ) -> Result<Self, crate::owner::github::response::MetadataFailure> {
        let (request, bytes) = response.into_parts();
        Self::parse(request, &bytes)
            .map_err(|_| crate::owner::github::response::MetadataFailure::Invalid)
    }
    fn parse(request: PreparedLookup, bytes: &[u8]) -> Result<Self, Error> {
        #[derive(Deserialize)]
        struct Metadata {
            id: NonZeroU64,
            full_name: String,
        }
        let metadata: Metadata = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if !valid_repository_name(&metadata.full_name)
            || !metadata
                .full_name
                .eq_ignore_ascii_case(&request.name.full_name())
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            id: request.id,
            connection: request.connection,
            index: request.index,
            requested: request.name,
            repository_id: metadata.id,
            full_name: metadata.full_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner::settings::{
        Proposal, Revision,
        tests::{fixture, pin, rules},
    };
    use ring::{rand::SystemRandom, signature::EcdsaKeyPair};
    use std::time::Duration;

    fn name(value: &str) -> RepositoryName {
        let (owner, name) = value.split_once('/').unwrap();
        RepositoryName {
            owner: owner.into(),
            name: name.into(),
        }
    }

    fn setup() -> (EcdsaKeyPair, Manager, Review) {
        let (key, mut manager) = fixture();
        let review = manager
            .prepare(
                7,
                [1; 16],
                Proposal {
                    revision: Revision(0),
                    settings: rules(),
                    provider: Some(pin()),
                },
                1_000.into(),
                (),
            )
            .unwrap();
        let review = manager
            .add_repositories(&review.id, 7, vec![name("example/new")])
            .unwrap();
        (key, manager, review)
    }

    #[test]
    fn named_additions_require_presence_and_a_signature_over_the_completed_settings() {
        let (key, mut manager, review) = setup();
        let snapshot = crate::owner::test_support::vault::snapshot("github-write");
        assert!(
            manager
                .prepare_lookup(&review.id, 7, &snapshot, 1_001.into())
                .is_err()
        );
        let challenge = manager
            .authenticate(&review.id, 7, 1_001.into(), 1_002.into())
            .unwrap();
        let request = manager
            .prepare_lookup(&review.id, 7, &snapshot, 1_003.into())
            .unwrap();
        assert!(
            request
                .bytes()
                .starts_with(b"GET /repos/example/new HTTP/1.1\r\nHost: api.github.com\r\n")
        );
        assert!(
            request
                .bytes()
                .ends_with(b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        );
        let admission = manager.admit_lookup(&request, 1_004.into()).unwrap();
        assert!(admission.accepts(&request, 1_004.into()));
        assert!(manager.admit_lookup(&request, 1_005.into()).is_err());
        let result =
            LookupResult::parse(request, br#"{"id":456,"full_name":"Example/New"}"#).unwrap();
        manager.accept_lookup(result, 1_006.into()).unwrap();
        let resolved = manager
            .resolved_challenge(&review.id, 7, 1_007.into())
            .unwrap();
        assert_eq!(resolved.authenticated, challenge.authenticated);
        assert_eq!(resolved.expires, challenge.expires);
        assert_eq!(resolved.review.id, review.id);
        assert_ne!(resolved.bytes, challenge.bytes);
        assert_eq!(manager.record().revision(), Revision(0));
        let signature = key
            .sign(
                &SystemRandom::new(),
                &BASE64.decode(resolved.bytes).unwrap(),
            )
            .unwrap();
        let verified = manager
            .approve(&review.id, 7, signature.as_ref(), 1_008.into())
            .unwrap();
        let admitted = manager.admit(verified, 1_009.into()).unwrap();
        let config = admitted
            .record()
            .settings()
            .unwrap()
            .github
            .as_ref()
            .unwrap();
        assert_eq!(config.repository("example", "one").unwrap().id().get(), 123);
        assert_eq!(config.repository("example", "new").unwrap().id().get(), 456);
    }

    #[test]
    fn a_signature_for_unresolved_names_cannot_publish_settings() {
        let (key, mut manager, review) = setup();
        let challenge = manager
            .authenticate(&review.id, 7, 1_001.into(), 1_002.into())
            .unwrap();
        let signature = key
            .sign(
                &SystemRandom::new(),
                &BASE64.decode(challenge.bytes).unwrap(),
            )
            .unwrap();
        assert_eq!(
            manager
                .approve(&review.id, 7, signature.as_ref(), 1_003.into())
                .err(),
            Some(Error::Stale)
        );
        assert!(manager.idle());
        assert_eq!(manager.record().revision(), Revision(0));
    }

    #[test]
    fn metadata_resolution_rejects_wrong_names_ambiguous_ids_cancellation_and_expiry() {
        for value in [
            br#"{"id":456,"full_name":"other/repo"}"#.as_slice(),
            br#"{"id":0,"full_name":"example/new"}"#,
            br#"{"id":456,"id":789,"full_name":"example/new"}"#,
        ] {
            let (_, mut manager, review) = setup();
            manager
                .authenticate(&review.id, 7, 1_001.into(), 1_002.into())
                .unwrap();
            let snapshot = crate::owner::test_support::vault::snapshot("github-write");
            let request = manager
                .prepare_lookup(&review.id, 7, &snapshot, 1_003.into())
                .unwrap();
            assert!(LookupResult::parse(request, value).is_err());
            assert!(
                manager
                    .resolved_challenge(&review.id, 7, 1_004.into())
                    .is_err()
            );
        }
        let (_, mut manager, review) = setup();
        let authenticated = MonotonicTimestamp::from(1_001);
        manager
            .authenticate(&review.id, 7, authenticated, authenticated)
            .unwrap();
        let snapshot = crate::owner::test_support::vault::snapshot("github-write");
        let request = manager
            .prepare_lookup(&review.id, 7, &snapshot, authenticated)
            .unwrap();
        let deadline = authenticated.checked_add(Duration::from_secs(30)).unwrap();
        assert_eq!(
            manager.admit_lookup(&request, deadline).err(),
            Some(Error::Expired)
        );
        manager.cancel(&review.id, 7).unwrap();
        assert!(
            manager
                .prepare_lookup(&review.id, 7, &snapshot, authenticated)
                .is_err()
        );
    }

    #[test]
    fn names_are_bounded_validated_and_cannot_duplicate_existing_or_pending_repositories() {
        for names in [
            vec![name("example/one")],
            vec![name("example/../new")],
            vec![name("example/new?x")],
            vec![name("example/new"), name("EXAMPLE/NEW")],
            (0..64)
                .map(|index| name(&format!("example/r{index}")))
                .collect(),
        ] {
            let (_, mut manager) = fixture();
            let review = manager
                .prepare(
                    7,
                    [1; 16],
                    Proposal {
                        revision: Revision(0),
                        settings: rules(),
                        provider: Some(pin()),
                    },
                    1_000.into(),
                    (),
                )
                .unwrap();
            assert!(manager.add_repositories(&review.id, 7, names).is_err());
        }
    }
}
