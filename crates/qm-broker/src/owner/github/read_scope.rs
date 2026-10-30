use qm_api_github::EffectKind;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(in crate::owner) enum ReadCategory {
    Repository,
    Issues,
    Actions,
    Output,
}

impl ReadCategory {
    pub(in crate::owner) const ALL: [Self; 4] =
        [Self::Repository, Self::Issues, Self::Actions, Self::Output];

    fn effects(self) -> &'static [EffectKind] {
        match self {
            Self::Repository => &[
                EffectKind::ReadRepository,
                EffectKind::ReadReadme,
                EffectKind::ReadRelatedSummaries,
            ],
            Self::Issues => &[
                EffectKind::ListIssues,
                EffectKind::ReadIssue,
                EffectKind::ListPullRequests,
                EffectKind::ReadPullRequest,
                EffectKind::ReadRelatedSummaries,
                EffectKind::ReadLinkedIssueSummaries,
                EffectKind::ReadProjectSummaries,
            ],
            Self::Actions => &[
                EffectKind::ListWorkflows,
                EffectKind::ReadWorkflow,
                EffectKind::ListWorkflowRuns,
                EffectKind::ReadWorkflowRun,
                EffectKind::ListWorkflowJobs,
                EffectKind::ReadWorkflowJob,
                EffectKind::ListRunArtifacts,
                EffectKind::ReadRelatedSummaries,
                EffectKind::ReadCheckSummaries,
            ],
            Self::Output => &[
                EffectKind::ReadRunLogs,
                EffectKind::ReadJobLogs,
                EffectKind::ReadCheckAnnotations,
            ],
        }
    }

    pub(in crate::owner) fn covers(self, effect: EffectKind) -> bool {
        self.effects().contains(&effect)
    }

    pub(in crate::owner) fn for_effects(
        effects: impl IntoIterator<Item = EffectKind>,
    ) -> Option<Vec<Self>> {
        let effects: Vec<_> = effects.into_iter().collect();
        let categories: Vec<_> = Self::ALL
            .into_iter()
            .filter(|category| {
                effects.iter().any(|effect| {
                    *effect != EffectKind::ReadRelatedSummaries && category.covers(*effect)
                })
            })
            .collect();
        if effects.is_empty()
            || !effects
                .iter()
                .all(|effect| categories.iter().any(|category| category.covers(*effect)))
        {
            None
        } else {
            Some(categories)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_reads_select_only_their_categories() {
        let categories = ReadCategory::for_effects([
            EffectKind::ReadRepository,
            EffectKind::ReadPullRequest,
            EffectKind::ReadRelatedSummaries,
        ])
        .unwrap();
        assert_eq!(categories, [ReadCategory::Repository, ReadCategory::Issues]);
    }

    #[test]
    fn empty_write_and_unscoped_summary_effects_cannot_create_a_read_grant() {
        for effects in [
            vec![],
            vec![EffectKind::CloseIssue],
            vec![EffectKind::ReadIssue, EffectKind::CloseIssue],
            vec![EffectKind::ReadRelatedSummaries],
        ] {
            assert!(ReadCategory::for_effects(effects).is_none());
        }
    }
}
