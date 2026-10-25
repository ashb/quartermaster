use super::{grant::ReadGrantClaims, request::FrozenOperation};
use serde::Serialize;

pub(super) trait CredentialContext {
    fn credential_role(&self) -> &str;
}

pub(super) struct ReviewDocument<C> {
    operation: FrozenOperation,
    authorization: Option<ReadGrantClaims>,
    context: C,
    bytes: Vec<u8>,
}

impl<C> ReviewDocument<C> {
    pub(super) fn new(
        operation: FrozenOperation,
        authorization: Option<ReadGrantClaims>,
        context: C,
    ) -> Result<Self, serde_json::Error>
    where
        C: Serialize + CredentialContext,
    {
        #[derive(Serialize)]
        struct Envelope<'a, C> {
            #[serde(flatten)]
            operation: &'a FrozenOperation,
            #[serde(skip_serializing_if = "Option::is_none")]
            authorization: &'a Option<ReadGrantClaims>,
            #[serde(flatten)]
            context: &'a C,
        }
        let bytes = serde_json::to_vec(&Envelope {
            operation: &operation,
            authorization: &authorization,
            context: &context,
        })?;
        Ok(Self {
            operation,
            authorization,
            context,
            bytes,
        })
    }

    pub(super) fn matches(
        &self,
        operation: &FrozenOperation,
        authorization: Option<ReadGrantClaims>,
    ) -> bool {
        &self.operation == operation && self.authorization == authorization
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn context(&self) -> &C {
        &self.context
    }
}

impl<C: CredentialContext> ReviewDocument<C> {
    pub(super) fn credential_role(&self) -> &str {
        self.context.credential_role()
    }
}
