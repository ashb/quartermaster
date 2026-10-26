use super::{BASE64, Engine, Error, Migration, MigrationSource, Proposal, Record, Revision};
use qm_types::MonotonicTimestamp;
use ring::{
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
    signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DOMAIN: &[u8] = b"quartermaster.settings-approval.v1\0";

mod repositories;
pub(in crate::owner) use repositories::{
    LookupAdmission, LookupResult, PreparedLookup, RepositoryName,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::owner) struct Review {
    pub(in crate::owner) id: String,
    created: MonotonicTimestamp,
    session: String,
    nonce: String,
    revision: Revision,
    document: String,
    digest: String,
    approval_key: String,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[serde(rename_all = "camelCase")]
pub(in crate::owner) struct Challenge {
    review: Review,
    authenticated: MonotonicTimestamp,
    expires: MonotonicTimestamp,
    pub(in crate::owner) bytes: String,
}

struct Pending<C> {
    connection: u64,
    review: Review,
    proposed: Record,
    authentication: Option<(MonotonicTimestamp, MonotonicTimestamp, Vec<u8>)>,
    context: C,
    additions: Vec<RepositoryName>,
    lookup_next: usize,
    lookup_complete: usize,
}

enum Phase<C> {
    Idle,
    Reviewing(Box<Pending<C>>),
    Ready { id: String, connection: u64 },
    Committing { id: String, connection: u64 },
    Unavailable,
}

pub(in crate::owner) struct Manager<C = ()> {
    record: Record,
    migration: Option<Migration>,
    phase: Phase<C>,
}

pub(in crate::owner) struct VerifiedChange<C> {
    id: String,
    proposed: Record,
    authenticated: MonotonicTimestamp,
    expires: MonotonicTimestamp,
    connection: u64,
    context: C,
    signed: SignedChange,
}

pub(in crate::owner) struct Admission<C> {
    id: String,
    record: Record,
    connection: u64,
    context: C,
    pub(super) signed: SignedChange,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedChange {
    review: Review,
    authenticated: MonotonicTimestamp,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: String,
    previous: Record,
    proposed: Record,
    #[serde(default)]
    migration: Option<MigrationSource>,
}

impl SignedChange {
    pub(super) fn encoded(&self) -> Result<Vec<u8>, Error> {
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Invalid)?;
        if bytes.len() > qm_types::PROTECTED_RECORD_BYTES {
            return Err(Error::Invalid);
        }
        Ok(bytes)
    }

    pub(super) fn record(&self, key: &[u8]) -> Result<Record, Error> {
        let review = &self.review;
        let document = BASE64
            .decode(&review.document)
            .map_err(|_| Error::Invalid)?;
        if document.len() > 2 * super::RECORD_LIMIT
            || BASE64.decode(&review.digest).map_err(|_| Error::Invalid)?
                != digest(&SHA256, &document).as_ref()
            || BASE64
                .decode(&review.approval_key)
                .map_err(|_| Error::Invalid)?
                != key
            || BASE64.decode(&review.id).map_err(|_| Error::Invalid)?.len() != 16
            || BASE64
                .decode(&review.session)
                .map_err(|_| Error::Invalid)?
                .len()
                != 16
            || BASE64
                .decode(&review.nonce)
                .map_err(|_| Error::Invalid)?
                .len()
                != 32
            || u64::from(review.created) == 0
            || self
                .authenticated
                .checked_duration_since(review.created)
                .is_none_or(|age| age >= Duration::from_secs(120))
        {
            return Err(Error::Invalid);
        }
        let document: Document = serde_json::from_slice(&document).map_err(|_| Error::Invalid)?;
        if let Some(source) = &document.migration {
            source.validate()?;
            if document.previous.settings().is_some() || document.previous.provider().is_some() {
                return Err(Error::Invalid);
            }
        }
        for record in [&document.previous, &document.proposed] {
            Record::decode(&serde_json::to_vec(record).map_err(|_| Error::Invalid)?)?;
            if record.public_key() != key {
                return Err(Error::Invalid);
            }
        }
        if document.version != "quartermaster.settings-review.v1"
            || document.previous.revision() != review.revision
            || document.proposed.revision() != review.revision.next()?
            || document.proposed.settings().is_none()
        {
            return Err(Error::Invalid);
        }
        let signature = BASE64.decode(&self.signature).map_err(|_| Error::Invalid)?;
        if signature.is_empty() || signature.len() > 72 {
            return Err(Error::Invalid);
        }
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
            .verify(&signing_bytes(review, self.authenticated)?, &signature)
            .map_err(|_| Error::Invalid)?;
        Ok(document.proposed)
    }

    pub(super) fn migration_source(&self) -> Result<Option<MigrationSource>, Error> {
        let bytes = BASE64
            .decode(&self.review.document)
            .map_err(|_| Error::Invalid)?;
        let document: Document = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        Ok(document.migration)
    }
}

impl<C> Admission<C> {
    pub(in crate::owner) fn record(&self) -> &Record {
        &self.record
    }
}

impl<C> VerifiedChange<C> {
    pub(in crate::owner) fn context(&self) -> &C {
        &self.context
    }
    pub(in crate::owner) fn context_mut(&mut self) -> &mut C {
        &mut self.context
    }
}

fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Invalid)?;
    Ok(bytes)
}

impl<C> Manager<C> {
    pub(super) fn new(record: Record) -> Self {
        Self {
            record,
            migration: None,
            phase: Phase::Idle,
        }
    }
    pub(super) fn from_legacy(record: Record, bytes: &[u8]) -> Result<Self, Error> {
        let migration = Migration::from_legacy(&record, bytes)?;
        let mut inactive = record;
        inactive.settings = None;
        inactive.provider = None;
        Ok(Self {
            record: inactive,
            migration,
            phase: Phase::Idle,
        })
    }
    pub(in crate::owner) fn migration(&self) -> Option<&Migration> {
        self.migration.as_ref()
    }
    pub(in crate::owner) fn record(&self) -> &Record {
        &self.record
    }
    pub(in crate::owner) fn stable(&self) -> bool {
        !matches!(self.phase, Phase::Committing { .. } | Phase::Unavailable)
    }
    pub(in crate::owner) fn committing(&self) -> bool {
        matches!(self.phase, Phase::Committing { .. })
    }
    pub(in crate::owner) fn failed(&self) -> bool {
        matches!(self.phase, Phase::Unavailable)
    }
    pub(in crate::owner) fn idle(&self) -> bool {
        matches!(self.phase, Phase::Idle)
    }
    pub(in crate::owner) fn pending(&self, id: &str, connection: u64) -> bool {
        matches!(&self.phase, Phase::Reviewing(p) if p.review.id == id && p.connection == connection)
    }
    pub(in crate::owner) fn cancel(&mut self, id: &str, connection: u64) -> Result<bool, Error> {
        if matches!(&self.phase, Phase::Committing { id: current, connection: peer } if current == id && *peer == connection)
        {
            return Err(Error::Busy);
        }
        if self.pending(id, connection)
            || matches!(&self.phase, Phase::Ready { id: current, connection: peer } if current == id && *peer == connection)
        {
            self.phase = Phase::Idle;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    pub(in crate::owner) fn policy(&self) -> Result<super::Policy, super::AuthorizationError> {
        if matches!(self.phase, Phase::Committing { .. } | Phase::Unavailable) {
            return Err(super::AuthorizationError::InvalidPolicy);
        }
        if self.record.provider.is_none() {
            return Err(super::AuthorizationError::Denied);
        }
        self.record
            .settings
            .as_ref()
            .ok_or(super::AuthorizationError::Denied)?
            .policy()
    }

    pub(in crate::owner) fn prepare(
        &mut self,
        connection: u64,
        session: [u8; 16],
        proposal: Proposal,
        now: MonotonicTimestamp,
        context: C,
    ) -> Result<Review, Error> {
        if self.migration.is_some() {
            return Err(Error::Stale);
        }
        self.prepare_change(connection, session, proposal, now, context, None)
    }

    pub(in crate::owner) fn prepare_import(
        &mut self,
        id: &str,
        connection: u64,
        session: [u8; 16],
        now: MonotonicTimestamp,
        context: C,
    ) -> Result<Review, Error> {
        let migration = self
            .migration
            .as_ref()
            .filter(|migration| migration.source.id == id)
            .ok_or(Error::Stale)?
            .clone();
        self.prepare_change(
            connection,
            session,
            Proposal {
                revision: self.record.revision(),
                settings: migration.settings,
                provider: migration.provider,
            },
            now,
            context,
            Some(migration.source),
        )
    }

    fn prepare_change(
        &mut self,
        connection: u64,
        session: [u8; 16],
        proposal: Proposal,
        now: MonotonicTimestamp,
        context: C,
        migration: Option<MigrationSource>,
    ) -> Result<Review, Error> {
        let Proposal {
            revision,
            settings,
            provider,
        } = proposal;
        if !matches!(self.phase, Phase::Idle) {
            return Err(Error::Busy);
        }
        if revision != self.record.revision || u64::from(now) == 0 {
            return Err(Error::Stale);
        }
        if let Some(provider) = &provider {
            provider.validate()?;
        }
        let proposed = Record {
            revision: revision.next()?,
            settings: Some(settings),
            provider,
            ..self.record.clone()
        };
        let encoded = serde_json::to_vec(&proposed).map_err(|_| Error::Invalid)?;
        Record::decode(&encoded)?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Document<'a> {
            version: &'static str,
            previous: &'a Record,
            proposed: &'a Record,
            #[serde(skip_serializing_if = "Option::is_none")]
            migration: Option<MigrationSource>,
        }
        let bytes = serde_json::to_vec(&Document {
            version: "quartermaster.settings-review.v1",
            previous: &self.record,
            proposed: &proposed,
            migration,
        })
        .map_err(|_| Error::Invalid)?;
        if bytes.len() > 2 * super::RECORD_LIMIT {
            return Err(Error::Invalid);
        }
        let review = Review {
            id: BASE64.encode(random::<16>()?),
            created: now,
            session: BASE64.encode(session),
            nonce: BASE64.encode(random::<32>()?),
            revision,
            document: BASE64.encode(&bytes),
            digest: BASE64.encode(digest(&SHA256, &bytes)),
            approval_key: BASE64.encode(self.record.public_key()),
        };
        self.phase = Phase::Reviewing(Box::new(Pending {
            connection,
            review: review.clone(),
            proposed,
            authentication: None,
            context,
            additions: Vec::new(),
            lookup_next: 0,
            lookup_complete: 0,
        }));
        Ok(review)
    }

    pub(in crate::owner) fn authenticate(
        &mut self,
        id: &str,
        connection: u64,
        authenticated: MonotonicTimestamp,
        now: MonotonicTimestamp,
    ) -> Result<Challenge, Error> {
        let Phase::Reviewing(pending) = &mut self.phase else {
            return Err(Error::Stale);
        };
        if pending.connection != connection
            || pending.review.id != id
            || pending.authentication.is_some()
        {
            return Err(Error::Stale);
        }
        if authenticated
            .checked_duration_since(pending.review.created)
            .is_none_or(|age| age >= Duration::from_secs(120))
            || now
                .checked_duration_since(authenticated)
                .is_none_or(|age| age >= Duration::from_secs(30))
        {
            return Err(Error::Expired);
        }
        let expires = authenticated
            .checked_add(Duration::from_secs(30))
            .ok_or(Error::Expired)?;
        let bytes = signing_bytes(&pending.review, authenticated)?;
        let challenge = Challenge {
            review: pending.review.clone(),
            authenticated,
            expires,
            bytes: BASE64.encode(&bytes),
        };
        pending.authentication = Some((authenticated, expires, bytes));
        Ok(challenge)
    }

    pub(in crate::owner) fn approve(
        &mut self,
        id: &str,
        connection: u64,
        signature: &[u8],
        now: MonotonicTimestamp,
    ) -> Result<VerifiedChange<C>, Error> {
        if !matches!(&self.phase, Phase::Reviewing(pending) if pending.connection == connection && pending.review.id == id)
        {
            return Err(Error::Stale);
        }
        let Phase::Reviewing(pending) = std::mem::replace(&mut self.phase, Phase::Idle) else {
            unreachable!()
        };
        if !pending.additions.is_empty() {
            return Err(Error::Stale);
        }
        let (authenticated, expires, bytes) = pending.authentication.ok_or(Error::Invalid)?;
        if now < authenticated || now >= expires {
            return Err(Error::Expired);
        }
        if signature.is_empty() || signature.len() > 72 {
            return Err(Error::Invalid);
        }
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, self.record.public_key())
            .verify(&bytes, signature)
            .map_err(|_| Error::Invalid)?;
        let signed = SignedChange {
            review: pending.review,
            authenticated,
            signature: BASE64.encode(signature),
        };
        signed.encoded()?;
        self.phase = Phase::Ready {
            id: id.to_owned(),
            connection,
        };
        Ok(VerifiedChange {
            id: id.to_owned(),
            proposed: pending.proposed,
            authenticated,
            expires,
            connection,
            context: pending.context,
            signed,
        })
    }

    pub(in crate::owner) fn admit(
        &mut self,
        verified: VerifiedChange<C>,
        now: MonotonicTimestamp,
    ) -> Result<Admission<C>, Error> {
        if !matches!(&self.phase, Phase::Ready { id, connection } if *id == verified.id && *connection == verified.connection)
        {
            return Err(Error::Stale);
        }
        self.phase = Phase::Idle;
        if verified.proposed.revision != self.record.revision.next()? {
            return Err(Error::Stale);
        }
        if now < verified.authenticated || now >= verified.expires {
            return Err(Error::Expired);
        }
        self.phase = Phase::Committing {
            id: verified.id.clone(),
            connection: verified.connection,
        };
        Ok(Admission {
            id: verified.id,
            record: verified.proposed,
            connection: verified.connection,
            context: verified.context,
            signed: verified.signed,
        })
    }

    pub(in crate::owner) fn finish(
        &mut self,
        publication: super::store::Publication<C>,
    ) -> Result<C, Error> {
        let super::store::Publication { admission, result } = publication;
        if !matches!(&self.phase, Phase::Committing { id, connection } if *id == admission.id && *connection == admission.connection)
        {
            return Err(Error::Stale);
        }
        match result {
            Ok(()) => {
                self.record = admission.record;
                self.migration = None;
                self.phase = Phase::Idle;
                Ok(admission.context)
            }
            Err(error) => {
                self.phase = Phase::Unavailable;
                Err(error)
            }
        }
    }

    pub(in crate::owner) fn context(&self, id: &str, connection: u64) -> Result<&C, Error> {
        match &self.phase {
            Phase::Reviewing(pending)
                if pending.review.id == id && pending.connection == connection =>
            {
                Ok(&pending.context)
            }
            _ => Err(Error::Stale),
        }
    }

    pub(in crate::owner) fn with_context<T>(
        &mut self,
        id: &str,
        connection: u64,
        work: impl FnOnce(&mut C) -> T,
    ) -> Result<T, Error> {
        match &mut self.phase {
            Phase::Reviewing(pending)
                if pending.review.id == id && pending.connection == connection =>
            {
                Ok(work(&mut pending.context))
            }
            _ => Err(Error::Stale),
        }
    }

    pub(in crate::owner) fn abort(&mut self, verified: VerifiedChange<C>) {
        if matches!(&self.phase, Phase::Ready { id, connection } if *id == verified.id && *connection == verified.connection)
        {
            self.phase = Phase::Unavailable;
        }
    }

    pub(in crate::owner) fn cancel_connection(&mut self, connection: u64) {
        if matches!(&self.phase, Phase::Reviewing(pending) if pending.connection == connection)
            || matches!(&self.phase, Phase::Ready { connection: current, .. } if *current == connection)
        {
            self.phase = Phase::Idle;
        }
    }

    pub(in crate::owner) fn expire(&mut self, now: MonotonicTimestamp) {
        if let Phase::Reviewing(pending) = &self.phase {
            let expired = match &pending.authentication {
                Some((_, expires, _)) => now >= *expires,
                None => now
                    .checked_duration_since(pending.review.created)
                    .is_none_or(|age| age >= Duration::from_secs(120)),
            };
            if expired {
                self.phase = Phase::Idle;
            }
        }
    }
}

fn signing_bytes(review: &Review, authenticated: MonotonicTimestamp) -> Result<Vec<u8>, Error> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(BASE64.decode(&review.session).map_err(|_| Error::Invalid)?);
    bytes.extend(BASE64.decode(&review.nonce).map_err(|_| Error::Invalid)?);
    bytes.extend(review.revision.0.to_be_bytes());
    bytes.extend(BASE64.decode(&review.digest).map_err(|_| Error::Invalid)?);
    bytes.extend(u64::from(authenticated).to_be_bytes());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_signing_bytes_match_the_shared_swift_fixture() {
        let fixture: Challenge = serde_json::from_str(include_str!("../../../../../macos/Security/Tests/QuartermasterSecurityTests/Fixtures/settings-review.json")).unwrap();
        let document = BASE64.decode(&fixture.review.document).unwrap();
        assert_eq!(
            BASE64.decode(&fixture.review.digest).unwrap(),
            digest(&SHA256, &document).as_ref()
        );
        assert_eq!(
            signing_bytes(&fixture.review, fixture.authenticated).unwrap(),
            BASE64.decode(&fixture.bytes).unwrap()
        );
    }
}
