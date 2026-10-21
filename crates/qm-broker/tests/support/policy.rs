use super::*;
use crate::owner::grant::GrantRule;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixturePolicy {
    version: u8,
    writes: PolicyDecision,
    grants: Vec<GrantRule>,
    #[serde(skip)]
    github: Option<GitHubConfig>,
}

impl Default for FixturePolicy {
    fn default() -> Self {
        Self {
            version: 1,
            writes: PolicyDecision::RequireApproval,
            grants: Vec::new(),
            github: None,
        }
    }
}

impl FixturePolicy {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, AuthorizationError> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| AuthorizationError::InvalidPolicy)?;
        if value.version != 1 {
            return Err(AuthorizationError::InvalidPolicy);
        }
        for grant in &value.grants {
            grant.validate()?;
        }
        Ok(value)
    }

    pub(crate) fn with_github(mut self, github: GitHubConfig) -> Self {
        self.github = Some(github);
        self
    }
}

impl Authorizer {
    pub(crate) fn install(
        &mut self,
        fixture: Result<FixturePolicy, AuthorizationError>,
        wall_now: OffsetDateTime,
        now: Instant,
    ) -> Result<bool, AuthorizationError> {
        let anchor = continuous_now().map_err(|_| AuthorizationError::InvalidPolicy)?;
        match fixture {
            Ok(fixture) => {
                let changed = self.install_anchored(
                    Ok(Policy {
                        version: fixture.version,
                        writes: fixture.writes,
                        github: fixture.github,
                    }),
                    wall_now,
                    now,
                    anchor,
                )?;
                if changed {
                    self.grants = GrantTable::new(&fixture.grants, wall_now, now, anchor)?;
                }
                Ok(changed)
            }
            Err(error) => self.install_anchored(Err(error), wall_now, now, anchor),
        }
    }

    pub(crate) fn seed_fixture_grants(&mut self, bytes: &[u8]) {
        let fixture = FixturePolicy::decode(bytes).unwrap();
        self.grants = GrantTable::new(
            &fixture.grants,
            OffsetDateTime::now_utc(),
            Instant::now(),
            continuous_now().unwrap(),
        )
        .unwrap();
    }
}
