use super::{BASE64, Engine, Error, ProviderPin, Record, Revision, Settings};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(in crate::owner) enum Format {
    UnsignedV1,
    SignedV1,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::owner) struct MigrationSource {
    pub(in crate::owner) id: String,
    from_format: Format,
    to_format: Format,
}

impl MigrationSource {
    pub(super) fn validate(&self) -> Result<(), Error> {
        if self.from_format != Format::UnsignedV1
            || self.to_format != Format::SignedV1
            || BASE64.decode(&self.id).map_err(|_| Error::Invalid)?.len() != 32
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    pub(super) fn check_current(&self, bytes: &[u8]) -> Result<(), Error> {
        self.validate()?;
        if self.id != BASE64.encode(digest(&SHA256, bytes)) {
            return Err(Error::Stale);
        }
        Ok(())
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::owner) struct Migration {
    pub(in crate::owner) source: MigrationSource,
    pub(in crate::owner) revision: Revision,
    pub(in crate::owner) settings: Settings,
    pub(in crate::owner) provider: Option<ProviderPin>,
}

impl Migration {
    pub(super) fn from_legacy(record: &Record, bytes: &[u8]) -> Result<Option<Self>, Error> {
        let Some(settings) = record.settings() else {
            return if record.provider().is_none() {
                Ok(None)
            } else {
                Err(Error::Invalid)
            };
        };
        Ok(Some(Self {
            source: MigrationSource {
                id: BASE64.encode(digest(&SHA256, bytes)),
                from_format: Format::UnsignedV1,
                to_format: Format::SignedV1,
            },
            revision: record.revision(),
            settings: settings.clone(),
            provider: record.provider().cloned(),
        }))
    }
}
