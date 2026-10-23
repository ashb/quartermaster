use super::GraphqlSyntax;
use crate::{Effect, EffectKind, GraphqlOperation, Location, Repository, Resource};
use hegel::{TestCase, generators as gs};
use serde_json::{Value, json};
use std::num::NonZeroU64;

#[derive(Clone, Copy, Debug)]
enum Binding {
    Default(bool),
    Supplied { default: bool, value: bool },
    Ambiguous,
}

impl Binding {
    fn value(self) -> Option<bool> {
        match self {
            Self::Default(value) | Self::Supplied { value, .. } => Some(value),
            Self::Ambiguous => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Gate {
    Always,
    Include(bool),
    Skip(bool),
    IncludeVariable,
    SkipVariable,
    Unknown,
}

impl Gate {
    fn draw(tc: &TestCase, allow_unknown: bool) -> Self {
        if allow_unknown && tc.draw(gs::booleans()) {
            return Self::Unknown;
        }
        tc.draw(gs::sampled_from(&[
            Self::Always,
            Self::Include(true),
            Self::Include(false),
            Self::Skip(true),
            Self::Skip(false),
            Self::IncludeVariable,
            Self::SkipVariable,
        ]))
    }

    fn value(self, binding: Binding) -> Option<bool> {
        match self {
            Self::Always => Some(true),
            Self::Include(value) => Some(value),
            Self::Skip(value) => Some(!value),
            Self::IncludeVariable => binding.value(),
            Self::SkipVariable => binding.value().map(|value| !value),
            Self::Unknown => None,
        }
    }

    fn active(self, binding: Binding, complete: &mut bool) -> bool {
        self.value(binding).unwrap_or_else(|| {
            *complete = false;
            true
        })
    }

    fn render(self) -> String {
        match self {
            Self::Always => String::new(),
            Self::Include(value) => format!("@include(if:{value})"),
            Self::Skip(value) => format!("@skip(if:{value})"),
            Self::IncludeVariable => "@include(if:$gate)".into(),
            Self::SkipVariable => "@skip(if:$gate)".into(),
            Self::Unknown => "@include(if:false) @future".into(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ReadKind {
    Issue,
    Issues { edges: bool },
}

#[derive(Clone, Copy, Debug)]
enum Placement {
    Inline,
    Named,
}

#[derive(Debug)]
struct ReadBranch {
    number: u64,
    kind: ReadKind,
    field_gate: Gate,
    spread_gate: Gate,
    placement: Placement,
    related: Vec<ReadBranch>,
}

impl ReadBranch {
    fn draw(
        tc: &TestCase,
        depth: u8,
        remaining: &mut u8,
        next: &mut u64,
        allow_unknown: bool,
    ) -> Self {
        *remaining -= 1;
        *next += 1;
        let number = *next;
        let kind = if tc.draw(gs::booleans()) {
            ReadKind::Issue
        } else {
            ReadKind::Issues {
                edges: tc.draw(gs::booleans()),
            }
        };
        let field_gate = Gate::draw(tc, allow_unknown);
        let spread_gate = Gate::draw(tc, allow_unknown);
        let placement = tc.draw(gs::sampled_from(&[Placement::Inline, Placement::Named]));
        let children = if depth == 0 {
            0
        } else {
            tc.draw(gs::integers::<u8>().max_value(2))
        };
        let mut related = Vec::new();
        for _ in 0..children {
            if *remaining == 0 {
                break;
            }
            related.push(Self::draw(tc, depth - 1, remaining, next, allow_unknown));
        }
        Self {
            number,
            kind,
            field_gate,
            spread_gate,
            placement,
            related,
        }
    }

    fn spine(depth: u8, next: &mut u64) -> Self {
        *next += 1;
        let number = *next;
        let related = if depth == 0 {
            Vec::new()
        } else {
            vec![Self::spine(depth - 1, next), Self::spine(0, next)]
        };
        Self {
            number,
            kind: if depth == 0 {
                ReadKind::Issue
            } else {
                ReadKind::Issues { edges: true }
            },
            field_gate: Gate::Always,
            spread_gate: Gate::Always,
            placement: Placement::Named,
            related,
        }
    }

    fn observe(&self, binding: Binding, parent: &[String], facts: &mut QueryFacts) {
        if !self.spread_gate.active(binding, &mut facts.complete)
            || !self.field_gate.active(binding, &mut facts.complete)
        {
            return;
        }
        let (field, effect) = match self.kind {
            ReadKind::Issue => ("issue", EffectKind::ReadIssue),
            ReadKind::Issues { .. } => ("issues", EffectKind::ListIssues),
        };
        let mut path = parent.to_vec();
        path.push(field.into());
        facts.effects.push(Effect {
            kind: effect,
            location: Location::Graphql(path.clone()),
        });
        if matches!(self.kind, ReadKind::Issue) {
            facts
                .resources
                .push(Resource::IssueNumber(NonZeroU64::new(self.number).unwrap()));
        }
        let issue_paths = match self.kind {
            ReadKind::Issue => vec![path],
            ReadKind::Issues { edges } => {
                let mut nodes = path.clone();
                nodes.push("nodes".into());
                let mut paths = vec![nodes];
                if edges {
                    path.extend(["edges".into(), "node".into()]);
                    paths.push(path);
                }
                paths
            }
        };
        for mut path in issue_paths {
            path.push("repository".into());
            for child in &self.related {
                child.observe(binding, &path, facts);
            }
        }
    }

    fn render(&self, syntax: &GraphqlSyntax, scalars: usize, fragments: &mut String) -> String {
        let id = self.number;
        let separator = syntax.separator;
        let mut issue = ["title", "body", "state", "url", "number", "createdAt"]
            .into_iter()
            .take(scalars)
            .enumerate()
            .map(|(index, field)| syntax.field(field, index))
            .collect::<Vec<_>>()
            .join(separator);
        if !self.related.is_empty() {
            let children = self
                .related
                .iter()
                .map(|child| child.render(syntax, scalars, fragments))
                .collect::<Vec<_>>()
                .join(separator);
            issue.push_str(&format!("{separator}repository{{name {children}}}"));
        }
        fragments.push_str(&format!(" fragment Issue{id} on Issue {{{issue}}}"));
        let field = match self.kind {
            ReadKind::Issue => format!(
                "branch{id}{separator}:{separator}issue(number:{id}) {} {{...{separator}Issue{id}}}",
                self.field_gate.render(),
            ),
            ReadKind::Issues { edges } => format!(
                "branch{id}{separator}:{separator}issues(first:2,states:[OPEN,CLOSED]) {} {{nodes{{...{separator}Issue{id}}} {} totalCount pageInfo{{hasNextPage hasPreviousPage startCursor endCursor}}}}",
                self.field_gate.render(),
                if edges {
                    format!("edges{{cursor node{{...{separator}Issue{id}}}}}")
                } else {
                    String::new()
                },
            ),
        };
        match self.placement {
            Placement::Inline => format!(
                "...{separator}on Repository {} {{{field}}}",
                self.spread_gate.render()
            ),
            Placement::Named => {
                fragments.push_str(&format!(" fragment Read{id} on Repository {{{field}}}"));
                format!("...{separator}Read{id} {}", self.spread_gate.render())
            }
        }
    }

    fn expanded_selections(&self, scalars: usize) -> usize {
        let issue = scalars
            + if self.related.is_empty() {
                0
            } else {
                2 + self
                    .related
                    .iter()
                    .map(|child| child.expanded_selections(scalars))
                    .sum::<usize>()
            };
        2 + match self.kind {
            ReadKind::Issue => 1 + issue,
            ReadKind::Issues { edges: false } => 8 + issue,
            ReadKind::Issues { edges: true } => 12 + 2 * issue,
        }
    }
}

#[derive(Debug)]
struct RepositoryRead {
    repository: Repository,
    gate: Gate,
    branches: Vec<ReadBranch>,
}

#[derive(Debug)]
pub(crate) struct QueryPlan {
    roots: Vec<RepositoryRead>,
    binding: Binding,
    scalars: usize,
    opaque: bool,
    unknown: bool,
}

#[derive(Debug)]
pub(crate) struct QueryFacts {
    pub effects: Vec<Effect>,
    pub resources: Vec<Resource>,
    pub roots: Vec<&'static str>,
    pub complete: bool,
}

impl QueryPlan {
    pub(crate) fn scope() -> Repository {
        Repository {
            owner: "scope".into(),
            name: "repository".into(),
        }
    }

    pub(crate) fn draw(tc: &TestCase) -> Self {
        let allow_unknown = tc.draw(gs::booleans());
        let count = tc.draw(gs::integers::<u8>().min_value(2).max_value(4));
        let depth = tc.draw(gs::integers::<u8>().min_value(1).max_value(3));
        let binding = if allow_unknown && tc.draw(gs::booleans()) {
            Binding::Ambiguous
        } else {
            tc.draw(gs::sampled_from(&[
                Binding::Default(false),
                Binding::Default(true),
                Binding::Supplied {
                    default: false,
                    value: true,
                },
                Binding::Supplied {
                    default: true,
                    value: false,
                },
            ]))
        };
        let mut next = 0;
        let mut roots = Vec::new();
        for index in 0..count {
            let repository = if index == 0 || tc.draw(gs::booleans()) {
                Self::scope()
            } else {
                Repository {
                    owner: format!("foreign{index}"),
                    name: "repository".into(),
                }
            };
            let gate = if index == 0 {
                Gate::Always
            } else {
                Gate::draw(tc, allow_unknown)
            };
            let mut remaining = tc.draw(gs::integers::<u8>().min_value(1).max_value(6));
            let mut branches = if index == 0 {
                vec![ReadBranch::spine(2, &mut next)]
            } else {
                Vec::new()
            };
            while remaining > 0 {
                branches.push(ReadBranch::draw(
                    tc,
                    depth,
                    &mut remaining,
                    &mut next,
                    allow_unknown,
                ));
            }
            roots.push(RepositoryRead {
                repository,
                gate,
                branches,
            });
        }
        Self {
            roots,
            binding,
            scalars: tc.draw(gs::integers::<usize>().min_value(1).max_value(6)),
            opaque: allow_unknown && tc.draw(gs::booleans()),
            unknown: allow_unknown && tc.draw(gs::booleans()),
        }
    }

    pub(crate) fn dense(depth: u8, roots: usize) -> Self {
        let mut next = 0;
        Self {
            roots: (0..roots)
                .map(|_| RepositoryRead {
                    repository: Self::scope(),
                    gate: Gate::Always,
                    branches: vec![ReadBranch::spine(depth, &mut next)],
                })
                .collect(),
            binding: Binding::Supplied {
                default: false,
                value: true,
            },
            scalars: 6,
            opaque: false,
            unknown: false,
        }
    }

    pub(crate) fn facts(&self) -> QueryFacts {
        let mut facts = QueryFacts {
            effects: Vec::new(),
            resources: Vec::new(),
            roots: if self.binding.value() == Some(false) {
                Vec::new()
            } else {
                vec!["__typename"]
            },
            complete: self.binding.value().is_some() && !self.opaque && !self.unknown,
        };
        for root in &self.roots {
            if !root.gate.active(self.binding, &mut facts.complete) {
                continue;
            }
            facts
                .resources
                .push(Resource::Repository(root.repository.clone()));
            facts.roots.push("repository");
            facts.effects.push(Effect {
                kind: EffectKind::ReadRepository,
                location: Location::Graphql(vec!["repository".into()]),
            });
            for branch in &root.branches {
                branch.observe(self.binding, &["repository".into()], &mut facts);
            }
        }
        if self.opaque {
            facts.roots.push("node");
            facts
                .resources
                .push(Resource::NodeId("unresolved-node".into()));
        }
        if self.unknown {
            facts.roots.push("future");
        }
        facts
    }

    pub(crate) fn render(&self, syntax: &GraphqlSyntax) -> (String, Value) {
        let mut fragments = String::new();
        let mut selections = String::from("__typename @include(if:$gate)");
        for (index, root) in self.roots.iter().enumerate() {
            let branches = root
                .branches
                .iter()
                .map(|branch| branch.render(syntax, self.scalars, &mut fragments))
                .collect::<Vec<_>>()
                .join(syntax.separator);
            selections.push_str(&format!(
                " ... on Query {} {{root{index}:repository(owner:{} name:{}){{name {branches}}}}}",
                root.gate.render(),
                syntax.string(&root.repository.owner),
                syntax.string(&root.repository.name),
            ));
        }
        if self.opaque {
            selections.push_str(" node(id:\"unresolved-node\"){... on Issue{repository{name}}}");
        }
        if self.unknown {
            selections.push_str(" future {repository{name}}");
        }
        let (default, variables) = match self.binding {
            Binding::Default(default) => (default, json!({})),
            Binding::Supplied { default, value } => (default, json!({"gate": value})),
            Binding::Ambiguous => (false, json!("{\"gate\":true}")),
        };
        (
            format!(
                "{} {fragments} query Other {{repository(owner:\"unselected\",name:\"outside\"){{name}}}} mutation Forbidden {{deleteIssue(input:{{issueId:\"secret\"}}){{clientMutationId}}}}",
                syntax.operation("query", &format!("($gate:Boolean={default})"), &selections)
            ),
            variables,
        )
    }

    pub(crate) fn expanded_selections(&self, syntax: &GraphqlSyntax) -> usize {
        1 + usize::from(syntax.fragment_depth)
            + if self.opaque { 4 } else { 0 }
            + if self.unknown { 3 } else { 0 }
            + self
                .roots
                .iter()
                .map(|root| {
                    3 + root
                        .branches
                        .iter()
                        .map(|branch| branch.expanded_selections(self.scalars))
                        .sum::<usize>()
                })
                .sum::<usize>()
    }
}

#[derive(Debug)]
struct Write {
    number: u64,
    kind: EffectKind,
    gate: Gate,
    nested_read: bool,
    unknown_argument: bool,
}

#[derive(Debug)]
struct Spread {
    target: usize,
    gate: Gate,
    inline: bool,
}

#[derive(Debug)]
struct MutationFragment {
    writes: Vec<Write>,
    spreads: Vec<Spread>,
}

#[derive(Debug)]
pub(crate) struct MutationPlan {
    fragments: Vec<MutationFragment>,
    entries: Vec<Spread>,
    binding: Binding,
    selected: bool,
    unknown_sibling: bool,
    reverse_definitions: bool,
}

#[derive(Debug)]
pub(crate) struct MutationFacts {
    pub effects: Vec<EffectKind>,
    pub resources: Vec<Resource>,
    pub operation: GraphqlOperation,
    pub roots: Vec<&'static str>,
}

impl MutationPlan {
    pub(crate) fn draw(tc: &TestCase) -> Self {
        let count = tc.draw(gs::integers::<usize>().min_value(3).max_value(6));
        let allow_unknown = tc.draw(gs::booleans());
        let binding = if allow_unknown && tc.draw(gs::booleans()) {
            Binding::Ambiguous
        } else {
            let value = tc.draw(gs::booleans());
            if tc.draw(gs::booleans()) {
                Binding::Default(value)
            } else {
                Binding::Supplied {
                    default: !value,
                    value,
                }
            }
        };
        let mut number = 0;
        let mut fragments = Vec::new();
        for index in 0..count {
            let writes = (0..tc.draw(gs::integers::<usize>().min_value(2).max_value(4)))
                .map(|write| {
                    number += 1;
                    Write {
                        number,
                        kind: if write % 2 == 0 {
                            EffectKind::CloseIssue
                        } else {
                            EffectKind::DeleteIssue
                        },
                        gate: Gate::draw(tc, allow_unknown),
                        nested_read: write % 2 == 0 && tc.draw(gs::booleans()),
                        unknown_argument: allow_unknown && tc.draw(gs::booleans()),
                    }
                })
                .collect();
            let spreads = if index == 0 {
                Vec::new()
            } else {
                [
                    index - 1,
                    tc.draw(gs::integers::<usize>().max_value(index - 1)),
                ]
                .into_iter()
                .map(|target| Spread {
                    target,
                    gate: Gate::draw(tc, allow_unknown),
                    inline: tc.draw(gs::booleans()),
                })
                .collect()
            };
            fragments.push(MutationFragment { writes, spreads });
        }
        Self {
            fragments,
            entries: [
                count - 1,
                tc.draw(gs::integers::<usize>().max_value(count - 1)),
            ]
            .into_iter()
            .map(|target| Spread {
                target,
                gate: Gate::draw(tc, allow_unknown),
                inline: tc.draw(gs::booleans()),
            })
            .collect(),
            binding,
            selected: tc.draw(gs::booleans()),
            unknown_sibling: allow_unknown && tc.draw(gs::booleans()),
            reverse_definitions: tc.draw(gs::booleans()),
        }
    }

    pub(crate) fn dense() -> Self {
        let fragments = (0..6)
            .map(|index| MutationFragment {
                writes: (0..4)
                    .map(|write| Write {
                        number: (index * 4 + write + 1) as u64,
                        kind: if write % 2 == 0 {
                            EffectKind::CloseIssue
                        } else {
                            EffectKind::DeleteIssue
                        },
                        gate: Gate::Always,
                        nested_read: write % 2 == 0,
                        unknown_argument: false,
                    })
                    .collect(),
                spreads: if index == 0 {
                    Vec::new()
                } else {
                    (0..2)
                        .map(|_| Spread {
                            target: index - 1,
                            gate: Gate::Always,
                            inline: true,
                        })
                        .collect()
                },
            })
            .collect();
        Self {
            fragments,
            entries: (0..2)
                .map(|_| Spread {
                    target: 5,
                    gate: Gate::Always,
                    inline: true,
                })
                .collect(),
            binding: Binding::Supplied {
                default: false,
                value: true,
            },
            selected: true,
            unknown_sibling: false,
            reverse_definitions: true,
        }
    }

    fn observe(&self, spread: &Spread, facts: &mut MutationFacts) {
        if !spread.gate.value(self.binding).unwrap_or(true) {
            return;
        }
        let fragment = &self.fragments[spread.target];
        for write in &fragment.writes {
            if !write.gate.value(self.binding).unwrap_or(true) {
                continue;
            }
            facts.effects.push(write.kind);
            facts.roots.push(if write.kind == EffectKind::CloseIssue {
                "closeIssue"
            } else {
                "deleteIssue"
            });
            facts
                .resources
                .push(Resource::NodeId(format!("write-{}", write.number)));
            if write.nested_read {
                facts.effects.push(EffectKind::ReadIssue);
                facts.resources.push(Resource::IssueNumber(
                    NonZeroU64::new(write.number).unwrap(),
                ));
            }
        }
        for spread in &fragment.spreads {
            self.observe(spread, facts);
        }
    }

    pub(crate) fn facts(&self) -> MutationFacts {
        let mut facts = MutationFacts {
            effects: Vec::new(),
            resources: Vec::new(),
            operation: if self.selected {
                GraphqlOperation::Mutation
            } else {
                GraphqlOperation::Query
            },
            roots: if !self.selected || self.binding.value() != Some(false) {
                vec!["__typename"]
            } else {
                Vec::new()
            },
        };
        if self.selected {
            for spread in &self.entries {
                self.observe(spread, &mut facts);
            }
            if self.unknown_sibling {
                facts.roots.push("future");
            }
        }
        facts
    }

    fn render_spread(spread: &Spread, syntax: &GraphqlSyntax) -> String {
        let target = spread.target;
        let separator = syntax.separator;
        let gate = spread.gate.render();
        if spread.inline {
            format!("...{separator}on Mutation {gate} {{...{separator}Part{target}}}")
        } else {
            format!("...{separator}Part{target} {gate}")
        }
    }

    pub(crate) fn render(&self, syntax: &GraphqlSyntax) -> (String, Value, &'static str) {
        let separator = syntax.separator;
        let mut fragments = Vec::new();
        for (index, fragment) in self.fragments.iter().enumerate() {
            let mut fields = Vec::new();
            for write in &fragment.writes {
                let field = if write.kind == EffectKind::CloseIssue {
                    "closeIssue"
                } else {
                    "deleteIssue"
                };
                fields.push(format!(
                    "write{}{separator}:{separator}{field}(input:{{issueId:{}{}}}) {} {{clientMutationId {}}}",
                    write.number,
                    syntax.string(&format!("write-{}", write.number)),
                    if write.unknown_argument { ",future:true" } else { "" },
                    write.gate.render(),
                    if write.nested_read { format!("issue{{repository{{issue(number:{}){{title}}}}}}", write.number) } else { String::new() },
                ));
            }
            fields.extend(
                fragment
                    .spreads
                    .iter()
                    .map(|spread| Self::render_spread(spread, syntax)),
            );
            fragments.push(format!(
                "fragment Part{index} on Mutation {{{}}}",
                fields.join(separator)
            ));
        }
        if self.reverse_definitions {
            fragments.reverse();
        }
        let mut selection = String::from("__typename @include(if:$gate)");
        for spread in &self.entries {
            selection.push_str(&format!(
                "{separator}{}",
                Self::render_spread(spread, syntax)
            ));
        }
        if self.unknown_sibling {
            selection.push_str(" future {__typename}");
        }
        let (default, variables) = match self.binding {
            Binding::Default(default) => (default, json!({})),
            Binding::Supplied { default, value } => (default, json!({"gate": value})),
            Binding::Ambiguous => (false, json!("{\"gate\":true}")),
        };
        (
            format!(
                "{} {} query Other {{__typename}} mutation Unselected {{deleteIssue(input:{{issueId:\"unselected\"}}){{clientMutationId}}}}",
                syntax.operation(
                    "mutation",
                    &format!("($gate:Boolean={default})"),
                    &selection
                ),
                fragments.join(separator)
            ),
            variables,
            if self.selected { "Selected" } else { "Other" },
        )
    }

    pub(crate) fn expanded_selections(&self, syntax: &GraphqlSyntax) -> usize {
        let mut sizes = Vec::new();
        for fragment in &self.fragments {
            sizes.push(
                fragment
                    .writes
                    .iter()
                    .map(|write| if write.nested_read { 6 } else { 2 })
                    .sum::<usize>()
                    + fragment
                        .spreads
                        .iter()
                        .map(|spread| 1 + usize::from(spread.inline) + sizes[spread.target])
                        .sum::<usize>(),
            );
        }
        1 + usize::from(syntax.fragment_depth)
            + if self.unknown_sibling { 2 } else { 0 }
            + self
                .entries
                .iter()
                .map(|spread| 1 + usize::from(spread.inline) + sizes[spread.target])
                .sum::<usize>()
    }
}
