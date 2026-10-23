mod schema;
use schema::Context;

use crate::{
    CapturedRequest,
    analysis::{
        Analysis, AnalysisError, AnalysisLimits, GraphqlOperation, Location, UncoveredReason,
    },
    json::Json,
};
use apollo_parser::{Parser, cst, cst::CstNode};
use std::collections::{BTreeMap, BTreeSet};

struct Envelope<'a> {
    selected: Option<&'a str>,
    variables: &'a Json,
    ambiguous_variables: bool,
}

struct Budget {
    selections: usize,
    values: usize,
    paths: usize,
}

pub(crate) fn inspect(
    request: &CapturedRequest,
    analysis: &mut Analysis,
    limits: AnalysisLimits,
) -> Result<(), AnalysisError> {
    if request.method() != "POST" || request.path_and_query() != "/graphql" {
        analysis.unknown(Location::Target, UncoveredReason::Endpoint);
    }
    crate::json::check_depth(request.body(), limits.json_depth)?;
    let Ok(body) = serde_json::from_slice::<Json>(request.body()) else {
        if request.has_json_grammar() {
            return Err(AnalysisError::InvalidJson);
        }
        analysis.unknown(Location::Body, UncoveredReason::ApplicationData);
        return Ok(());
    };
    let Some(fields) = body.object() else {
        analysis.unknown(Location::Body, UncoveredReason::ApplicationData);
        return Ok(());
    };
    if body.duplicate_members() {
        analysis.unknown(Location::Body, UncoveredReason::RepeatedInput);
    }
    if fields
        .iter()
        .any(|(name, _)| !matches!(name.as_str(), "query" | "variables" | "operationName"))
    {
        analysis.unknown(Location::Body, UncoveredReason::BodyMember);
    }
    let operation_name = match body.unique("operationName") {
        None | Some(Json::Null) => None,
        Some(Json::String(name)) => Some(name.as_str()),
        _ => {
            analysis.unknown(Location::Body, UncoveredReason::ApplicationData);
            None
        }
    };
    let empty = Json::Object(Vec::new());
    let variables = match body.unique("variables") {
        None | Some(Json::Null) => &empty,
        Some(value @ Json::Object(_)) => value,
        _ => {
            analysis.unknown(Location::Body, UncoveredReason::Variable);
            &empty
        }
    };
    let ambiguous_variables = fields
        .iter()
        .filter(|(name, _)| name == "variables")
        .count()
        > 1
        || !matches!(
            body.unique("variables"),
            None | Some(Json::Null) | Some(Json::Object(_))
        );
    let envelope = Envelope {
        selected: operation_name,
        variables,
        ambiguous_variables,
    };
    let mut budget = Budget {
        selections: limits.expanded_selections,
        values: limits.expanded_value_bytes,
        paths: limits.output_bytes,
    };
    let mut found = false;
    for (_, query) in fields.iter().filter(|(name, _)| name == "query") {
        found = true;
        if let Some(query) = query.string() {
            document(query, &envelope, analysis, limits, &mut budget)?;
        } else {
            analysis.unknown(Location::Body, UncoveredReason::ApplicationData);
        }
    }
    if !found {
        analysis.unknown(Location::Body, UncoveredReason::ApplicationData);
    }
    Ok(())
}

fn document(
    query: &str,
    envelope: &Envelope<'_>,
    analysis: &mut Analysis,
    limits: AnalysisLimits,
    budget: &mut Budget,
) -> Result<(), AnalysisError> {
    if limits.graphql_depth == 0 || limits.graphql_depth > 128 {
        return Err(AnalysisError::Limit);
    }
    let tree = Parser::new(query)
        .recursion_limit(limits.graphql_depth)
        .token_limit(limits.graphql_tokens)
        .parse();
    if tree.recursion_limit().high > limits.graphql_depth
        || tree.token_limit().high > limits.graphql_tokens
    {
        return Err(AnalysisError::Limit);
    }
    if tree.errors().len() != 0 {
        return Err(AnalysisError::InvalidGraphql);
    }
    let mut operations = Vec::new();
    let mut fragments = BTreeMap::new();
    let mut names = BTreeSet::new();
    for definition in tree.document().definitions() {
        match definition {
            cst::Definition::OperationDefinition(operation) => {
                let name = operation.name().map(|name| name.text().to_string());
                if !names.insert(name) {
                    return Err(AnalysisError::OperationSelection);
                }
                operations.push(operation);
            }
            cst::Definition::FragmentDefinition(fragment) => {
                let name = fragment
                    .fragment_name()
                    .ok_or(AnalysisError::InvalidGraphql)?
                    .name()
                    .ok_or(AnalysisError::InvalidGraphql)?
                    .text()
                    .to_string();
                if fragments.insert(name, fragment).is_some() {
                    return Err(AnalysisError::Fragment);
                }
            }
            _ => analysis.unknown(Location::Body, UncoveredReason::Schema),
        }
    }
    let operation = match envelope.selected {
        Some(selected) => operations
            .iter()
            .find(|operation| operation.name().is_some_and(|name| name.text() == selected)),
        None if operations.len() == 1 => operations.first(),
        None => None,
    }
    .ok_or(AnalysisError::OperationSelection)?;
    let kind = match operation.operation_type() {
        Some(kind) if kind.mutation_token().is_some() => GraphqlOperation::Mutation,
        Some(kind) if kind.subscription_token().is_some() => GraphqlOperation::Subscription,
        _ => GraphqlOperation::Query,
    };
    let selection = operation
        .selection_set()
        .ok_or(AnalysisError::InvalidGraphql)?;
    let used_variables = referenced_variables(&selection, &fragments);
    let mut walker = Walker {
        analysis,
        variables: BTreeMap::new(),
        used_variables,
        fragments,
        kind,
        budget,
        exhausted: false,
        max_depth: limits.graphql_depth,
    };
    if let Some(definitions) = operation.variable_definitions() {
        for definition in definitions.variable_definitions() {
            let name = definition
                .variable()
                .ok_or(AnalysisError::InvalidGraphql)?
                .text()
                .to_string();
            if walker.variables.contains_key(&name) {
                return Err(AnalysisError::InvalidGraphql);
            }
            if definition.directives().is_some() {
                walker.unknown(&[], UncoveredReason::Directive);
            }
            let mut supplied = envelope
                .variables
                .object()
                .unwrap_or(&[])
                .iter()
                .filter(|(key, _)| key == &name);
            let mut value = match (supplied.next(), supplied.next()) {
                _ if envelope.ambiguous_variables => {
                    walker.unknown(&[], UncoveredReason::Variable);
                    Json::Null
                }
                (Some((_, value)), None) => value.clone(),
                (None, None) => definition
                    .default_value()
                    .and_then(|default| default.value())
                    .map(|value| walker.value(value, &[]))
                    .unwrap_or(Json::Null),
                _ => {
                    walker.unknown(&[], UncoveredReason::Variable);
                    Json::Null
                }
            };
            if definition.ty().is_none_or(|ty| !type_matches(ty, &value)) {
                walker.unknown(&[], UncoveredReason::Variable);
                value = Json::Null;
            }
            walker.variables.insert(name, value);
        }
    }
    for (name, _) in envelope.variables.object().unwrap_or(&[]) {
        if !walker.variables.contains_key(name) {
            walker.unknown(&[], UncoveredReason::Variable);
        }
    }
    if operation.directives().is_some() {
        walker.unknown(&[], UncoveredReason::Directive);
    }
    let context = match kind {
        GraphqlOperation::Query => Context::Query,
        GraphqlOperation::Mutation => Context::Mutation,
        GraphqlOperation::Subscription => Context::Subscription,
    };
    walker.walk(selection, context, &[], true, 0, &mut BTreeSet::new())?;
    if walker.exhausted {
        return Err(AnalysisError::Limit);
    }
    if walker
        .variables
        .keys()
        .any(|name| !walker.used_variables.contains(name))
    {
        walker.unknown(&[], UncoveredReason::Variable);
    }
    Ok(())
}

fn referenced_variables(
    selection: &cst::SelectionSet,
    fragments: &BTreeMap<String, cst::FragmentDefinition>,
) -> BTreeSet<String> {
    let mut variables = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut pending = vec![selection.syntax().clone()];
    while let Some(selection) = pending.pop() {
        for node in selection.descendants() {
            if let Some(variable) = cst::Variable::cast(node.clone()) {
                variables.insert(variable.text().to_string());
            }
            if let Some(name) = cst::FragmentSpread::cast(node)
                .and_then(|spread| spread.fragment_name())
                .and_then(|fragment| fragment.name())
                .map(|name| name.text().to_string())
                && visited.insert(name.clone())
                && let Some(fragment) = fragments.get(&name)
            {
                pending.push(fragment.syntax().clone());
            }
        }
    }
    variables
}

struct Walker<'a> {
    analysis: &'a mut Analysis,
    variables: BTreeMap<String, Json>,
    used_variables: BTreeSet<String>,
    fragments: BTreeMap<String, cst::FragmentDefinition>,
    kind: GraphqlOperation,
    budget: &'a mut Budget,
    exhausted: bool,
    max_depth: usize,
}

impl Walker<'_> {
    fn unknown(&mut self, path: &[String], reason: UncoveredReason) {
        self.analysis.unknown_graphql(path, reason);
    }

    fn value(&mut self, value: cst::Value, path: &[String]) -> Json {
        let value = match value {
            cst::Value::StringValue(value) => Json::String(value.into()),
            cst::Value::EnumValue(value) => Json::String(value.text().to_string()),
            cst::Value::BooleanValue(value) => Json::Bool(value.true_token().is_some()),
            cst::Value::NullValue(_) => Json::Null,
            cst::Value::IntValue(value) => value
                .int_token()
                .and_then(|token| token.text().parse::<i64>().ok())
                .map(|value| Json::Number(value.into()))
                .unwrap_or_else(|| {
                    self.unknown(path, UncoveredReason::Argument);
                    Json::Null
                }),
            cst::Value::FloatValue(_) => {
                self.unknown(path, UncoveredReason::Argument);
                Json::Null
            }
            cst::Value::Variable(variable) => {
                let name = variable.text().to_string();
                return match self.variables.get(&name) {
                    Some(value) if value.charge(&mut self.budget.values) => value.clone(),
                    Some(_) => {
                        self.exhausted = true;
                        Json::Null
                    }
                    None => {
                        self.unknown(path, UncoveredReason::Variable);
                        Json::Null
                    }
                };
            }
            cst::Value::ListValue(list) => {
                Json::Array(list.values().map(|value| self.value(value, path)).collect())
            }
            cst::Value::ObjectValue(object) => Json::Object(
                object
                    .object_fields()
                    .filter_map(|field| {
                        Some((
                            field.name()?.text().to_string(),
                            self.value(field.value()?, path),
                        ))
                    })
                    .collect(),
            ),
        };
        if value.charge(&mut self.budget.values) {
            value
        } else {
            self.exhausted = true;
            Json::Null
        }
    }

    fn arguments(&mut self, arguments: Option<cst::Arguments>, path: &[String]) -> Json {
        let fields = arguments
            .into_iter()
            .flat_map(|arguments| arguments.arguments())
            .filter_map(|argument| {
                Some((
                    argument.name()?.text().to_string(),
                    self.value(argument.value()?, path),
                ))
            })
            .collect();
        let value = Json::Object(fields);
        if value.duplicate_members() {
            self.unknown(path, UncoveredReason::RepeatedInput);
        }
        value
    }

    fn included(&mut self, directives: Option<cst::Directives>, path: &[String]) -> bool {
        let mut included = true;
        let mut uncertain = false;
        let mut seen = BTreeSet::new();
        for directive in directives
            .into_iter()
            .flat_map(|directives| directives.directives())
        {
            let Some(name) = directive.name().map(|name| name.text().to_string()) else {
                continue;
            };
            let args = self.arguments(directive.arguments(), path);
            if !seen.insert(name.clone()) || args.object().is_none_or(|fields| fields.len() != 1) {
                self.unknown(path, UncoveredReason::Directive);
                uncertain = true;
                continue;
            }
            match (name.as_str(), args.unique("if")) {
                ("skip", Some(Json::Bool(skip))) => included &= !skip,
                ("include", Some(Json::Bool(include))) => included &= *include,
                _ => {
                    self.unknown(path, UncoveredReason::Directive);
                    uncertain = true;
                }
            }
        }
        included || uncertain
    }

    fn walk(
        &mut self,
        selection: cst::SelectionSet,
        context: Context,
        path: &[String],
        root: bool,
        depth: usize,
        active: &mut BTreeSet<String>,
    ) -> Result<(), AnalysisError> {
        if depth > self.max_depth {
            return Err(AnalysisError::Limit);
        }
        for selection in selection.selections() {
            if self.analysis.exhausted {
                return Err(AnalysisError::Limit);
            }
            self.budget.selections = self
                .budget
                .selections
                .checked_sub(1)
                .ok_or(AnalysisError::Limit)?;
            match selection {
                cst::Selection::Field(field) => {
                    let name = field
                        .name()
                        .ok_or(AnalysisError::InvalidGraphql)?
                        .text()
                        .to_string();
                    let bytes = crate::analysis::path_bytes(path)
                        .saturating_add(std::mem::size_of::<String>())
                        .saturating_add(name.len());
                    self.budget.paths = self
                        .budget
                        .paths
                        .checked_sub(bytes)
                        .ok_or(AnalysisError::Limit)?;
                    let mut location = path.to_vec();
                    location.push(name.clone());
                    if !self.included(field.directives(), &location) {
                        continue;
                    }
                    if root {
                        self.analysis.root(self.kind, &name);
                    }
                    let args = self.arguments(field.arguments(), &location);
                    if self.exhausted {
                        return Err(AnalysisError::Limit);
                    }
                    let child = schema::inspect(self.analysis, context, &name, &args, &location);
                    if self.analysis.exhausted {
                        return Err(AnalysisError::Limit);
                    }
                    match (child, field.selection_set()) {
                        (Some(child), Some(selection)) => {
                            self.walk(selection, child, &location, false, depth + 1, active)?
                        }
                        (None, None) => {}
                        (Some(_), None) | (None, Some(_)) => {
                            self.unknown(&location, UncoveredReason::Schema)
                        }
                    }
                }
                cst::Selection::FragmentSpread(spread) => {
                    if !self.included(spread.directives(), path) {
                        continue;
                    }
                    let name = spread
                        .fragment_name()
                        .and_then(|name| name.name())
                        .ok_or(AnalysisError::Fragment)?
                        .text()
                        .to_string();
                    if !active.insert(name.clone()) {
                        return Err(AnalysisError::Fragment);
                    }
                    let fragment = self
                        .fragments
                        .get(&name)
                        .ok_or(AnalysisError::Fragment)?
                        .clone();
                    if fragment.directives().is_some() {
                        self.unknown(path, UncoveredReason::Directive);
                    }
                    self.check_type(fragment.type_condition(), context, path);
                    self.walk(
                        fragment.selection_set().ok_or(AnalysisError::Fragment)?,
                        context,
                        path,
                        root,
                        depth + 1,
                        active,
                    )?;
                    active.remove(&name);
                }
                cst::Selection::InlineFragment(fragment) => {
                    if !self.included(fragment.directives(), path) {
                        continue;
                    }
                    self.check_type(fragment.type_condition(), context, path);
                    self.walk(
                        fragment.selection_set().ok_or(AnalysisError::Fragment)?,
                        context,
                        path,
                        root,
                        depth + 1,
                        active,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn check_type(
        &mut self,
        condition: Option<cst::TypeCondition>,
        context: Context,
        path: &[String],
    ) {
        if condition.is_some_and(|condition| {
            condition
                .named_type()
                .and_then(|ty| ty.name())
                .is_none_or(|name| name.text() != context.name())
        }) {
            self.unknown(path, UncoveredReason::Schema);
        }
    }
}

fn type_matches(ty: cst::Type, value: &Json) -> bool {
    if !known_type(&ty) {
        return false;
    }
    match ty {
        cst::Type::NamedType(ty) => matches!(value, Json::Null) || named_type_matches(ty, value),
        cst::Type::ListType(ty) => matches!(value, Json::Null) || list_type_matches(ty, value),
        cst::Type::NonNullType(ty) => {
            !matches!(value, Json::Null)
                && (ty
                    .named_type()
                    .is_some_and(|ty| named_type_matches(ty, value))
                    || ty
                        .list_type()
                        .is_some_and(|ty| list_type_matches(ty, value)))
        }
    }
}

fn known_type(ty: &cst::Type) -> bool {
    let named = |ty: cst::NamedType| {
        ty.name()
            .is_some_and(|name| matches!(name.text().as_ref(), "String" | "ID" | "Int" | "Boolean"))
    };
    match ty {
        cst::Type::NamedType(ty) => named(ty.clone()),
        cst::Type::ListType(ty) => ty.ty().is_some_and(|ty| known_type(&ty)),
        cst::Type::NonNullType(ty) => {
            ty.named_type().is_some_and(named)
                || ty
                    .list_type()
                    .and_then(|ty| ty.ty())
                    .is_some_and(|ty| known_type(&ty))
        }
    }
}

fn named_type_matches(ty: cst::NamedType, value: &Json) -> bool {
    let Some(name) = ty.name() else {
        return false;
    };
    match (name.text().as_ref(), value) {
        ("String" | "ID", Json::String(_)) | ("Boolean", Json::Bool(_)) => true,
        ("Int", Json::Number(value)) => value
            .as_i64()
            .is_some_and(|value| i32::try_from(value).is_ok()),
        _ => false,
    }
}

fn list_type_matches(ty: cst::ListType, value: &Json) -> bool {
    let (Some(ty), Json::Array(values)) = (ty.ty(), value) else {
        return false;
    };
    values.iter().all(|value| type_matches(ty.clone(), value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EffectKind, Repository, Resource};
    use crate::{
        PatternSet, analyze, analyze_with_limits,
        test_support::{
            GraphqlSyntax, graphql,
            query_model::{MutationFacts, MutationPlan, QueryFacts, QueryPlan},
            raw_request, request,
        },
    };
    use hegel::{TestCase, generators as gs};
    use serde_json::json;

    #[test]
    fn insignificant_commas_do_not_change_alias_or_fragment_parsing() {
        for document in [
            "{ ..., on Query { __typename } }",
            "{ alias, : __typename }",
            "{ ..., Fields } fragment Fields on Query { __typename }",
        ] {
            let captured = graphql(document, json!({}), None);
            assert!(
                analyze(&captured, &PatternSet::default())
                    .unwrap()
                    .complete()
            );
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Guard {
        Literal(bool),
        Default(bool),
        Supplied(bool),
        DuplicateValues,
        DuplicateEnvelopes,
        UnsupportedEnvelope,
        UnknownDirective,
        DuplicateDirective,
    }

    impl Guard {
        fn can_execute(self) -> bool {
            match self {
                Self::Literal(active) | Self::Default(active) | Self::Supplied(active) => active,
                _ => true,
            }
        }

        fn render(self, skip: bool) -> (String, String, String) {
            let directive = if skip { "skip" } else { "include" };
            match self {
                Self::Literal(active) => (
                    String::new(),
                    format!("@{directive}(if:{})", active != skip),
                    String::new(),
                ),
                Self::Default(active) => (
                    format!("($go:Boolean={})", active != skip),
                    format!("@{directive}(if:$go)"),
                    String::new(),
                ),
                Self::Supplied(active) => (
                    format!("($go:Boolean={})", active == skip),
                    format!("@{directive}(if:$go)"),
                    format!(",\"variables\":{{\"go\":{}}}", active != skip),
                ),
                Self::DuplicateValues | Self::DuplicateEnvelopes | Self::UnsupportedEnvelope => (
                    format!("($go:Boolean={skip})"),
                    format!("@{directive}(if:$go)"),
                    match self {
                        Self::DuplicateValues => {
                            r#", "variables":{"go":false,"g\u006f":true}"#.into()
                        }
                        Self::DuplicateEnvelopes => {
                            r#", "variables":{"go":false},"variables":{"go":true}"#.into()
                        }
                        _ => r#", "variables":"{\"go\":true}""#.into(),
                    },
                ),
                Self::UnknownDirective | Self::DuplicateDirective => (
                    String::new(),
                    format!(
                        "@{directive}(if:{skip}) {}",
                        if matches!(self, Self::UnknownDirective) {
                            "@future".into()
                        } else {
                            format!("@{directive}(if:{})", !skip)
                        }
                    ),
                    String::new(),
                ),
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Relationship {
        SameRepository,
        ForeignRepository,
        OpaqueNode,
        UnknownNested,
        UnknownRoot,
        UnknownArgument,
    }

    fn assert_query_facts(
        document: &str,
        variables: serde_json::Value,
        facts: &QueryFacts,
        omitted: Option<EffectKind>,
    ) {
        let body = json!({"query": document, "variables": variables, "operationName": "Selected"})
            .to_string();
        let raw = raw_request(
            "POST",
            "/graphql",
            "Content-Type: application/json\r\n",
            &body,
        );
        let captured =
            CapturedRequest::parse(raw.as_bytes(), crate::RequestLimits::default()).unwrap();
        let allowed: Vec<_> = [
            EffectKind::ReadRepository,
            EffectKind::ReadIssue,
            EffectKind::ListIssues,
        ]
        .into_iter()
        .filter(|kind| Some(*kind) != omitted)
        .collect();
        let covered = facts
            .effects
            .iter()
            .all(|effect| allowed.contains(&effect.kind));
        let scoped = facts.resources.iter().all(|resource| match resource {
            Resource::Repository(repository) => repository == &QueryPlan::scope(),
            Resource::IssueNumber(_) => true,
            _ => false,
        });
        let mut patterns = vec![
            crate::Pattern {
                id: "effects".into(),
                predicates: vec![crate::Predicate::OnlyEffects(allowed.clone())],
            },
            crate::Pattern {
                id: "scope".into(),
                predicates: vec![
                    crate::Predicate::OnlyEffects(allowed),
                    crate::Predicate::AllResourcesInRepository(QueryPlan::scope()),
                ],
            },
        ];
        for kind in [
            EffectKind::ReadRepository,
            EffectKind::ReadIssue,
            EffectKind::ListIssues,
            EffectKind::CloseIssue,
            EffectKind::DeleteIssue,
        ] {
            patterns.push(crate::Pattern {
                id: format!("restrict-{kind:?}"),
                predicates: vec![crate::Predicate::Effect(kind)],
            });
        }
        for field in ["__typename", "repository", "node", "future", "deleteIssue"] {
            patterns.push(crate::Pattern {
                id: format!("root-{field}"),
                predicates: vec![crate::Predicate::GraphqlRoot {
                    operation: GraphqlOperation::Query,
                    field: field.into(),
                }],
            });
        }
        let analysis = analyze(&captured, &PatternSet::new(patterns).unwrap())
            .unwrap_or_else(|error| panic!("{error:?}\n{document}"));
        assert_eq!(analysis.complete(), facts.complete);
        for expected in &facts.effects {
            assert!(
                analysis.effects.contains(expected),
                "missing effect {expected:?}"
            );
        }
        for observed in &analysis.effects {
            assert!(
                facts.effects.contains(observed),
                "unexpected effect {observed:?}"
            );
        }
        for expected in &facts.resources {
            assert!(
                analysis.resources.contains(expected),
                "missing resource {expected:?}"
            );
        }
        for observed in &analysis.resources {
            assert!(
                facts.resources.contains(observed),
                "unexpected resource {observed:?}"
            );
        }
        for kind in [
            EffectKind::ReadRepository,
            EffectKind::ReadIssue,
            EffectKind::ListIssues,
            EffectKind::CloseIssue,
            EffectKind::DeleteIssue,
        ] {
            assert_eq!(
                analysis
                    .matches
                    .iter()
                    .any(|matched| matched.id == format!("restrict-{kind:?}")),
                facts.effects.iter().any(|effect| effect.kind == kind)
            );
        }
        for expected in &facts.roots {
            assert!(
                analysis
                    .graphql_roots
                    .contains(&(GraphqlOperation::Query, (*expected).into())),
                "missing root {expected}"
            );
        }
        for (kind, field) in &analysis.graphql_roots {
            assert_eq!(*kind, GraphqlOperation::Query);
            assert!(
                facts.roots.contains(&field.as_str()),
                "unexpected root {field}"
            );
        }
        for field in ["__typename", "repository", "node", "future", "deleteIssue"] {
            assert_eq!(
                analysis
                    .matches
                    .iter()
                    .any(|matched| matched.id == format!("root-{field}")),
                facts.roots.contains(&field),
                "root predicate {field}"
            );
        }
        for (id, expected) in [
            ("effects", covered && facts.complete),
            ("scope", covered && facts.complete && scoped),
        ] {
            assert_eq!(
                analysis
                    .matches
                    .iter()
                    .any(|matched| matched.id == id && matched.complete),
                expected,
                "{id}"
            );
        }
        assert_eq!(captured.original(), raw.as_bytes());
        assert_eq!(captured.body(), body.as_bytes());
    }

    #[hegel::test(test_cases = 500, database = None, derandomize = false)]
    fn branching_queries_preserve_every_modeled_effect_and_resource(tc: TestCase) {
        let syntax = GraphqlSyntax::draw(&tc);
        let plan = QueryPlan::draw(&tc);
        let omitted = tc.draw(gs::sampled_from(&[
            None,
            Some(EffectKind::ReadRepository),
            Some(EffectKind::ReadIssue),
            Some(EffectKind::ListIssues),
        ]));
        let (document, variables) = plan.render(&syntax);
        let facts = plan.facts();
        tc.note(&format!("syntax={syntax:?}, plan={plan:?}, omitted={omitted:?}\n{document}\nvariables={variables}"));
        tc.event(if facts.complete {
            "complete model"
        } else {
            "uncertain model"
        });
        tc.event(if facts.resources.iter().any(|resource| matches!(resource, Resource::Repository(repository) if repository != &QueryPlan::scope())) {
            "foreign repository observed"
        } else {
            "no foreign repository observed"
        });
        tc.event_value(
            "unguarded expanded selections",
            plan.expanded_selections(&syntax) as f64,
        );
        tc.target_labelled(
            plan.expanded_selections(&syntax) as f64,
            "expanded selections",
        );
        assert_query_facts(&document, variables, &facts, omitted);
    }

    #[test]
    fn dense_shared_fragment_queries_preserve_their_complete_model() {
        let syntax = GraphqlSyntax::dense();
        for (depth, roots) in [(2, 20), (3, 4), (4, 1)] {
            let plan = QueryPlan::dense(depth, roots);
            let (document, variables) = plan.render(&syntax);
            println!(
                "depth={depth}, roots={roots}, selections={}, document_bytes={}",
                plan.expanded_selections(&syntax),
                document.len()
            );
            for omitted in [
                None,
                Some(EffectKind::ReadIssue),
                Some(EffectKind::ListIssues),
            ] {
                assert_query_facts(&document, variables.clone(), &plan.facts(), omitted);
            }
        }
    }

    fn assert_mutation_facts(
        document: &str,
        variables: serde_json::Value,
        selected: &str,
        facts: &MutationFacts,
    ) {
        let body = json!({"query": document, "variables": variables, "operationName": selected})
            .to_string();
        let raw = raw_request(
            "POST",
            "/graphql",
            "Content-Type: application/json\r\n",
            &body,
        );
        let captured =
            CapturedRequest::parse(raw.as_bytes(), crate::RequestLimits::default()).unwrap();
        let kinds = [
            EffectKind::CloseIssue,
            EffectKind::DeleteIssue,
            EffectKind::ReadIssue,
            EffectKind::ReadRepository,
        ];
        let roots = [
            (GraphqlOperation::Mutation, "closeIssue"),
            (GraphqlOperation::Mutation, "deleteIssue"),
            (GraphqlOperation::Mutation, "future"),
            (GraphqlOperation::Mutation, "__typename"),
            (GraphqlOperation::Query, "__typename"),
        ];
        let mut patterns: Vec<_> = kinds
            .iter()
            .map(|kind| crate::Pattern {
                id: format!("effect-{kind:?}"),
                predicates: vec![crate::Predicate::Effect(*kind)],
            })
            .collect();
        patterns.extend(roots.iter().map(|(operation, field)| crate::Pattern {
            id: format!("root-{operation:?}-{field}"),
            predicates: vec![crate::Predicate::GraphqlRoot {
                operation: *operation,
                field: (*field).into(),
            }],
        }));
        let analysis = analyze(&captured, &PatternSet::new(patterns).unwrap())
            .unwrap_or_else(|error| panic!("{error:?}\n{document}"));
        for kind in kinds {
            let expected = facts.effects.contains(&kind);
            assert_eq!(
                analysis.effects.iter().any(|effect| effect.kind == kind),
                expected,
                "effect {kind:?}"
            );
            assert_eq!(
                analysis
                    .matches
                    .iter()
                    .any(|matched| matched.id == format!("effect-{kind:?}")),
                expected,
                "effect predicate {kind:?}"
            );
        }
        assert!(
            analysis
                .effects
                .iter()
                .all(|effect| facts.effects.contains(&effect.kind))
        );
        for expected in &facts.resources {
            assert!(
                analysis.resources.contains(expected),
                "missing resource {expected:?}"
            );
        }
        for observed in &analysis.resources {
            assert!(
                facts.resources.contains(observed),
                "unexpected resource {observed:?}"
            );
        }
        for (operation, field) in roots {
            let expected = operation == facts.operation && facts.roots.contains(&field);
            assert_eq!(
                analysis.graphql_roots.contains(&(operation, field.into())),
                expected,
                "root {operation:?}-{field}"
            );
            assert_eq!(
                analysis
                    .matches
                    .iter()
                    .any(|matched| matched.id == format!("root-{operation:?}-{field}")),
                expected,
                "root predicate {operation:?}-{field}"
            );
        }
        assert!(
            analysis
                .graphql_roots
                .iter()
                .all(|(operation, field)| *operation == facts.operation
                    && facts.roots.contains(&field.as_str()))
        );
        if facts
            .effects
            .iter()
            .any(|kind| matches!(kind, EffectKind::CloseIssue | EffectKind::DeleteIssue))
        {
            assert!(!analysis.complete());
        }
        assert_eq!(captured.original(), raw.as_bytes());
        assert_eq!(captured.body(), body.as_bytes());
    }

    #[hegel::test(test_cases = 500, database = None, derandomize = false)]
    fn shared_mutation_fragments_preserve_every_possible_write(tc: TestCase) {
        let syntax = GraphqlSyntax::draw(&tc);
        let plan = MutationPlan::draw(&tc);
        let (document, variables, selected) = plan.render(&syntax);
        let facts = plan.facts();
        tc.note(&format!("syntax={syntax:?}, plan={plan:?}\n{document}\nvariables={variables}, selected={selected}"));
        tc.event(if facts.operation == GraphqlOperation::Mutation {
            "selected mutation"
        } else {
            "unselected mutation"
        });
        tc.event(if facts.effects.is_empty() {
            "no active write"
        } else {
            "active or uncertain write"
        });
        tc.event_value(
            "unguarded expanded selections",
            plan.expanded_selections(&syntax) as f64,
        );
        tc.target_labelled(
            plan.expanded_selections(&syntax) as f64,
            "expanded selections",
        );
        assert_mutation_facts(&document, variables, selected, &facts);
    }

    #[hegel::test(test_cases = 500, database = None, derandomize = false)]
    fn equivalent_query_and_mutation_renderings_preserve_classification(tc: TestCase) {
        let syntax = GraphqlSyntax::draw(&tc);
        let plain = GraphqlSyntax::plain();
        let patterns = PatternSet::new(vec![
            crate::Pattern {
                id: "reads".into(),
                predicates: vec![crate::Predicate::OnlyEffects(vec![
                    EffectKind::ReadRepository,
                    EffectKind::ReadIssue,
                    EffectKind::ListIssues,
                ])],
            },
            crate::Pattern {
                id: "scope".into(),
                predicates: vec![crate::Predicate::AllResourcesInRepository(
                    QueryPlan::scope(),
                )],
            },
            crate::Pattern {
                id: "close".into(),
                predicates: vec![crate::Predicate::Effect(EffectKind::CloseIssue)],
            },
            crate::Pattern {
                id: "delete".into(),
                predicates: vec![crate::Predicate::GraphqlRoot {
                    operation: GraphqlOperation::Mutation,
                    field: "deleteIssue".into(),
                }],
            },
        ])
        .unwrap();
        let query = QueryPlan::draw(&tc);
        let mutation = MutationPlan::draw(&tc);
        let (query_a, variables_a) = query.render(&plain);
        let (query_b, variables_b) = query.render(&syntax);
        let mutation_a = mutation.render(&plain);
        let mutation_b = mutation.render(&syntax);
        for ((document_a, variables_a, selected_a), (document_b, variables_b, selected_b)) in [
            (
                (query_a, variables_a, "Selected"),
                (query_b, variables_b, "Selected"),
            ),
            (mutation_a, mutation_b),
        ] {
            tc.note(&format!(
                "syntax={syntax:?}\nplain={document_a}\nvariant={document_b}"
            ));
            assert_eq!(variables_a, variables_b);
            assert_eq!(selected_a, selected_b);
            let request_a = graphql(&document_a, variables_a, Some(selected_a));
            let request_b = graphql(&document_b, variables_b, Some(selected_b));
            let original_a = request_a.original().to_vec();
            let original_b = request_b.original().to_vec();
            let a = analyze(&request_a, &patterns).unwrap();
            let b = analyze(&request_b, &patterns).unwrap();
            assert_eq!(a.complete(), b.complete());
            assert_eq!(a.effects, b.effects);
            assert_eq!(a.resources, b.resources);
            assert_eq!(a.graphql_roots, b.graphql_roots);
            assert_eq!(a.uncovered, b.uncovered);
            assert_eq!(a.matches, b.matches);
            assert_eq!(request_a.original(), original_a);
            assert_eq!(request_b.original(), original_b);
        }
    }

    #[test]
    fn dense_mutation_fragments_preserve_all_writes_and_payload_reads() {
        let syntax = GraphqlSyntax::dense();
        let plan = MutationPlan::dense();
        let (document, variables, selected) = plan.render(&syntax);
        println!(
            "mutation selections={}, document_bytes={}",
            plan.expanded_selections(&syntax),
            document.len()
        );
        assert_mutation_facts(&document, variables, selected, &plan.facts());
    }

    #[hegel::test(test_cases = 500, database = None, derandomize = false)]
    fn literal_default_and_supplied_variables_preserve_classification(tc: TestCase) {
        let active = tc.draw(gs::booleans());
        let number = tc.draw(gs::integers::<u16>().min_value(1).max_value(1000));
        let skip = tc.draw(gs::booleans());
        let directive = if skip { "skip" } else { "include" };
        let guard = if skip { !active } else { active };
        let literal = format!(
            "query Selected{{repository(owner:\"scope\",name:\"repository\"){{...Data @{directive}(if:{guard})}}}} fragment Data on Repository{{issue(number:{number}){{title}}}}"
        );
        let variable = format!(
            "query Selected($go:Boolean!={guard},$number:Int!={number}){{repository(owner:\"scope\",name:\"repository\"){{...Data @{directive}(if:$go)}}}} fragment Data on Repository{{issue(number:$number){{title}}}}"
        );
        let captured = graphql(&literal, json!({}), Some("Selected"));
        let expected = analyze(&captured, &PatternSet::default()).unwrap();
        for variables in [json!({}), json!({"go":guard,"number":number})] {
            let variant = graphql(&variable, variables, Some("Selected"));
            let observed = analyze(&variant, &PatternSet::default()).unwrap();
            tc.note(&format!(
                "literal={literal}\nvariable={variable}, active={active}"
            ));
            assert_eq!(observed.complete(), expected.complete());
            assert_eq!(observed.effects, expected.effects);
            assert_eq!(observed.resources, expected.resources);
            assert_eq!(observed.graphql_roots, expected.graphql_roots);
        }
    }

    #[test]
    fn unselected_operations_and_unreferenced_fragments_cannot_use_selected_variables() {
        for companion in [
            "query Other($unused:Int=1){repository(owner:\"scope\",name:\"repository\"){issue(number:$unused){title}}}",
            "fragment Unused on Repository{issue(number:$unused){title}}",
        ] {
            let document = format!(
                "query Selected($unused:Int=1){{repository(owner:\"scope\",name:\"repository\"){{name}}}} {companion}"
            );
            let captured = graphql(&document, json!({}), Some("Selected"));
            let analysis = analyze(&captured, &PatternSet::default()).unwrap();
            assert!(!analysis.complete());
            assert!(
                analysis
                    .uncovered
                    .iter()
                    .any(|input| input.reason == UncoveredReason::Variable)
            );
            assert!(
                analysis
                    .effects
                    .iter()
                    .all(|effect| effect.kind == EffectKind::ReadRepository)
            );
        }
    }

    #[test]
    fn unfamiliar_directives_and_metadata_prevent_complete_read_matches() {
        let repository = "repository(owner:\"scope\",name:\"repository\")";
        let cases = [
            (
                format!("query Selected @future {{{repository}{{name}}}}"),
                UncoveredReason::Directive,
            ),
            (
                format!("query Selected{{{repository} @future {{name}}}}"),
                UncoveredReason::Directive,
            ),
            (
                format!(
                    "query Selected{{...Fields @future}} fragment Fields on Query{{{repository}{{name}}}}"
                ),
                UncoveredReason::Directive,
            ),
            (
                format!("query Selected{{... on Query @future {{{repository}{{name}}}}}}"),
                UncoveredReason::Directive,
            ),
            (
                format!(
                    "query Selected{{...Fields}} fragment Fields on Query @future {{{repository}{{name}}}}"
                ),
                UncoveredReason::Directive,
            ),
            (
                format!(
                    "query Selected($number:Int=1 @future){{{repository}{{issue(number:$number){{title}}}}}}"
                ),
                UncoveredReason::Directive,
            ),
            (
                format!("query Selected{{{repository}{{name}}}} scalar Future"),
                UncoveredReason::Schema,
            ),
            (
                format!("query Selected{{... on Mutation{{{repository}{{name}}}}}}"),
                UncoveredReason::Schema,
            ),
            (
                format!(
                    "query Selected{{...Fields}} fragment Fields on Mutation{{{repository}{{name}}}}"
                ),
                UncoveredReason::Schema,
            ),
            (
                format!("query Selected{{{repository}{{... on Issue{{name}}}}}}"),
                UncoveredReason::Schema,
            ),
            (
                format!(
                    "query Selected{{{repository}{{...Fields}}}} fragment Fields on Issue{{name}}"
                ),
                UncoveredReason::Schema,
            ),
        ];
        let patterns = PatternSet::new(vec![
            crate::Pattern {
                id: "repository".into(),
                predicates: vec![
                    crate::Predicate::Effect(EffectKind::ReadRepository),
                    crate::Predicate::GraphqlRoot {
                        operation: GraphqlOperation::Query,
                        field: "repository".into(),
                    },
                ],
            },
            crate::Pattern {
                id: "reads".into(),
                predicates: vec![crate::Predicate::OnlyEffects(vec![
                    EffectKind::ReadRepository,
                    EffectKind::ReadIssue,
                ])],
            },
        ])
        .unwrap();
        for (document, reason) in cases {
            let captured = graphql(&document, json!({}), Some("Selected"));
            let analysis = analyze(&captured, &patterns).unwrap();
            assert!(!analysis.complete(), "{document}");
            assert!(
                analysis
                    .uncovered
                    .iter()
                    .any(|input| input.reason == reason),
                "{document}"
            );
            assert_eq!(
                analysis.matches,
                vec![crate::PatternMatch {
                    id: "repository".into(),
                    complete: false
                }],
                "{document}"
            );
        }
    }

    fn close_restriction() -> PatternSet {
        PatternSet::new(vec![crate::Pattern {
            id: "close".into(),
            predicates: vec![
                crate::Predicate::Effect(EffectKind::CloseIssue),
                crate::Predicate::GraphqlRoot {
                    operation: GraphqlOperation::Mutation,
                    field: "closeIssue".into(),
                },
            ],
        }])
        .unwrap()
    }

    #[test]
    fn uncertain_variable_types_cannot_exclude_a_known_write() {
        for (ty, value, reason, present) in [
            ("Boolean!", json!(false), None, false),
            ("Boolean!", json!(true), None, true),
            (
                "Boolean!",
                json!(null),
                Some(UncoveredReason::Variable),
                true,
            ),
            (
                "Boolean",
                json!("false"),
                Some(UncoveredReason::Variable),
                true,
            ),
            (
                "[Boolean!]!",
                json!([false]),
                Some(UncoveredReason::Directive),
                true,
            ),
            (
                "[[Boolean!]!]!",
                json!([[false]]),
                Some(UncoveredReason::Directive),
                true,
            ),
            (
                "[Boolean!]!",
                json!([null]),
                Some(UncoveredReason::Variable),
                true,
            ),
            (
                "[Boolean]",
                json!([null, false]),
                Some(UncoveredReason::Directive),
                true,
            ),
            (
                "[Boolean!]!",
                json!(false),
                Some(UncoveredReason::Variable),
                true,
            ),
            (
                "Int!",
                json!(2147483648_u64),
                Some(UncoveredReason::Variable),
                true,
            ),
            ("Float!", json!(0.0), Some(UncoveredReason::Variable), true),
        ] {
            let document = format!(
                "mutation($go:{ty}){{closeIssue(input:{{issueId:\"one\"}}) @include(if:$go){{clientMutationId}}}}"
            );
            let captured = graphql(&document, json!({"go":value}), None);
            let analysis = analyze(&captured, &close_restriction()).unwrap();
            assert_eq!(
                analysis
                    .effects
                    .iter()
                    .any(|effect| effect.kind == EffectKind::CloseIssue),
                present,
                "{ty}: {value}"
            );
            assert_eq!(
                analysis.matches.iter().any(|matched| matched.id == "close"),
                present,
                "{ty}: {value}"
            );
            if let Some(reason) = reason {
                assert!(
                    analysis
                        .uncovered
                        .iter()
                        .any(|input| input.reason == reason),
                    "{ty}: {value}"
                );
            }
            assert_eq!(analysis.complete(), !present);
        }
    }

    #[test]
    fn invalid_or_duplicate_arguments_preserve_known_write_restrictions() {
        for arguments in [
            "input:{issueId:\"one\",issueId:\"two\"}",
            "input:{issueId:\"one\",future:{gate:false}}",
            "input:{issueId:1.5}",
            "input:{issueId:9223372036854775808}",
            "input:null",
            "future:true",
            "",
            "input:{issueId:\"one\"},input:{issueId:\"two\"}",
        ] {
            let arguments = if arguments.is_empty() {
                String::new()
            } else {
                format!("({arguments})")
            };
            let document = format!("mutation{{closeIssue{arguments}{{clientMutationId}}}}");
            let captured = graphql(&document, json!({}), None);
            let analysis = analyze(&captured, &close_restriction()).unwrap();
            assert!(!analysis.complete(), "{document}");
            assert!(
                analysis
                    .uncovered
                    .iter()
                    .any(|input| input.reason == UncoveredReason::Argument),
                "{document}"
            );
            assert_eq!(
                analysis.matches,
                vec![crate::PatternMatch {
                    id: "close".into(),
                    complete: false
                }],
                "{document}"
            );
        }
    }

    #[hegel::test(test_cases = 500, database = None, derandomize = false)]
    fn mutation_restrictions_survive_obfuscation_and_uncertain_guards(tc: TestCase) {
        let syntax = GraphqlSyntax::draw(&tc);
        let active = tc.draw(gs::booleans());
        let guard = tc.draw(gs::sampled_from(&[
            Guard::Literal(active),
            Guard::Default(active),
            Guard::Supplied(active),
            Guard::DuplicateValues,
            Guard::DuplicateEnvelopes,
            Guard::UnsupportedEnvelope,
            Guard::UnknownDirective,
            Guard::DuplicateDirective,
        ]));
        let selected = tc.draw(gs::booleans());
        let skip = tc.draw(gs::booleans());
        let delete = tc.draw(gs::booleans());
        let unknown_sibling = tc.draw(gs::booleans());
        let unknown_argument = tc.draw(gs::booleans());
        let duplicate_query = tc.draw(gs::booleans());
        let harmless_first = duplicate_query && tc.draw(gs::booleans());
        let escaped_key = duplicate_query && tc.draw(gs::booleans());
        let (field, effect) = if delete {
            ("deleteIssue", EffectKind::DeleteIssue)
        } else {
            ("closeIssue", EffectKind::CloseIssue)
        };
        let (variables, directive, envelope) = guard.render(skip);
        let argument = if unknown_argument { ",future:true" } else { "" };
        let selection = format!(
            "{}(input:{{issueId:{}{argument}}}) {directive} {{clientMutationId}} {}",
            syntax.field(field, 0),
            syntax.string("opaque-issue"),
            if unknown_sibling {
                "future {__typename}"
            } else {
                ""
            },
        );
        let document = format!(
            "{} query Other {{__typename}}",
            syntax.operation("mutation", &variables, &selection)
        );
        let query = serde_json::to_string(&document).unwrap();
        let query_members = if duplicate_query {
            let harmless = serde_json::to_string(if selected {
                "mutation Selected{__typename}"
            } else {
                "query Other{__typename}"
            })
            .unwrap();
            let (first, second) = if harmless_first {
                (&harmless, &query)
            } else {
                (&query, &harmless)
            };
            let second_key = if escaped_key { r"qu\u0065ry" } else { "query" };
            format!("\"query\":{first},\"{second_key}\":{second}")
        } else {
            format!("\"query\":{query}")
        };
        let body = format!(
            "{{{query_members},\"operationName\":\"{}\"{envelope}}}",
            if selected { "Selected" } else { "Other" },
        );
        tc.note(&format!("syntax={syntax:?}, guard={guard:?}, selected={selected}, skip={skip}, effect={effect:?}\n{body}"));
        let raw = raw_request(
            "POST",
            "/graphql",
            "Content-Type: application/json\r\n",
            &body,
        );
        let captured =
            CapturedRequest::parse(raw.as_bytes(), crate::RequestLimits::default()).unwrap();
        let patterns = PatternSet::new(vec![
            crate::Pattern {
                id: "effect".into(),
                predicates: vec![crate::Predicate::Effect(effect)],
            },
            crate::Pattern {
                id: "root".into(),
                predicates: vec![crate::Predicate::GraphqlRoot {
                    operation: GraphqlOperation::Mutation,
                    field: field.into(),
                }],
            },
        ])
        .unwrap();
        let analysis = analyze(&captured, &patterns).unwrap();
        let expected = selected && guard.can_execute();
        if duplicate_query {
            tc.event(format!("conflicting queries: harmless_first={harmless_first}, escaped_key={escaped_key}, expected_write={expected}"));
            assert!(!analysis.complete());
            assert!(
                analysis
                    .uncovered
                    .iter()
                    .any(|input| input.reason == UncoveredReason::RepeatedInput)
            );
        } else {
            tc.event("single query");
        }
        assert_eq!(
            analysis
                .effects
                .iter()
                .any(|observed| observed.kind == effect),
            expected
        );
        assert_eq!(
            analysis
                .graphql_roots
                .contains(&(GraphqlOperation::Mutation, field.into())),
            expected
        );
        for id in ["effect", "root"] {
            assert_eq!(
                analysis.matches.iter().any(|matched| matched.id == id),
                expected
            );
        }
        assert_eq!(captured.original(), raw.as_bytes());
        assert_eq!(captured.body(), body.as_bytes());
    }

    #[hegel::test(test_cases = 500, database = None, derandomize = false)]
    fn complete_query_matches_cover_all_effects_and_resource_relationships(tc: TestCase) {
        let syntax = GraphqlSyntax::draw(&tc);
        let issue = tc.draw(gs::booleans());
        let list = tc.draw(gs::booleans());
        let relationship = tc.draw(gs::sampled_from(&[
            Relationship::SameRepository,
            Relationship::ForeignRepository,
            Relationship::OpaqueNode,
            Relationship::UnknownNested,
            Relationship::UnknownRoot,
            Relationship::UnknownArgument,
        ]));
        let omitted = tc.draw(gs::sampled_from(&[
            None,
            Some(EffectKind::ReadRepository),
            Some(EffectKind::ReadIssue),
            Some(EffectKind::ListIssues),
        ]));
        let owner = format!("owner{}", tc.draw(gs::integers::<u8>().max_value(3)));
        let name = format!("repo{}", tc.draw(gs::integers::<u8>().max_value(3)));
        let mut expected_effects = vec![EffectKind::ReadRepository];
        let mut fields = String::from("name");
        if issue {
            fields.push_str(" issue(number:1) {title repository {name}}");
            expected_effects.push(EffectKind::ReadIssue);
        }
        if list {
            fields.push_str(" issues(first:2) {nodes {number} pageInfo {hasNextPage}}");
            expected_effects.push(EffectKind::ListIssues);
        }
        if relationship == Relationship::UnknownNested {
            fields.push_str(" additional:issue(number:2) {future {repository {name}}}");
            expected_effects.push(EffectKind::ReadIssue);
        }
        let argument = if relationship == Relationship::UnknownArgument {
            ",future:true"
        } else {
            ""
        };
        let mut selection = format!(
            "{}(owner:{}{}name:{}{argument}) {{{fields}}}",
            syntax.field("repository", 0),
            syntax.string(&owner),
            syntax.separator,
            syntax.string(&name),
        );
        match relationship {
            Relationship::ForeignRepository => selection.push_str(&format!(
                " other:repository(owner:\"outside\",name:{}) {{name}}",
                syntax.string(&name)
            )),
            Relationship::OpaqueNode => {
                selection.push_str(" node(id:\"opaque\") {... on Issue {repository {name}}}")
            }
            Relationship::UnknownRoot => selection.push_str(" future {__typename}"),
            _ => {}
        }
        let document = format!(
            "{} mutation Unselected {{deleteIssue(input:{{issueId:\"x\"}}){{clientMutationId}}}}",
            syntax.operation("query", "", &selection)
        );
        let captured = graphql(&document, json!({}), Some("Selected"));
        let original = captured.original().to_vec();
        let allowed: Vec<_> = [
            EffectKind::ReadRepository,
            EffectKind::ReadIssue,
            EffectKind::ListIssues,
        ]
        .into_iter()
        .filter(|effect| Some(*effect) != omitted)
        .collect();
        let covered = expected_effects
            .iter()
            .all(|effect| allowed.contains(effect));
        let patterns = PatternSet::new(vec![
            crate::Pattern {
                id: "effects".into(),
                predicates: vec![crate::Predicate::OnlyEffects(allowed.clone())],
            },
            crate::Pattern {
                id: "repository".into(),
                predicates: vec![
                    crate::Predicate::OnlyEffects(allowed),
                    crate::Predicate::AllResourcesInRepository(Repository { owner, name }),
                ],
            },
        ])
        .unwrap();
        tc.note(&format!("syntax={syntax:?}, relationship={relationship:?}, omitted={omitted:?}, expected_effects={expected_effects:?}\n{document}"));
        let analysis = analyze(&captured, &patterns).unwrap();
        for expected in &expected_effects {
            assert!(
                analysis
                    .effects
                    .iter()
                    .any(|effect| effect.kind == *expected)
            );
        }
        assert!(
            analysis
                .effects
                .iter()
                .all(|effect| expected_effects.contains(&effect.kind))
        );
        let understood = matches!(
            relationship,
            Relationship::SameRepository | Relationship::ForeignRepository
        );
        assert_eq!(analysis.complete(), understood);
        assert_eq!(
            analysis
                .matches
                .iter()
                .any(|matched| matched.id == "effects" && matched.complete),
            covered && understood
        );
        assert_eq!(
            analysis
                .matches
                .iter()
                .any(|matched| matched.id == "repository" && matched.complete),
            covered && relationship == Relationship::SameRepository
        );
        assert_eq!(captured.original(), original);
    }

    #[test]
    fn selected_operation_defaults_aliases_and_fragments_are_resolved_together() {
        let captured = graphql(
            r#"
            query Read($owner:String!="ashb", $show:Boolean! = true) {
                alias:repository(owner:$owner, name:"reviewq") {
                    ...Fields @include(if:$show)
                    ... on Repository { nameWithOwner }
                }
            }
            mutation Unselected { deleteIssue(input:{issueId:"unused"}) { clientMutationId } }
            fragment Fields on Repository { issues(first:10,states:[OPEN]) { nodes { title number } pageInfo { hasNextPage endCursor } } }
        "#,
            json!({}),
            Some("Read"),
        );
        let analysis = analyze(&captured, &PatternSet::default()).unwrap();
        assert!(analysis.complete(), "{:?}", analysis.uncovered);
        assert!(
            analysis
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::ListIssues)
        );
        assert!(
            !analysis
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::DeleteIssue)
        );
        assert_eq!(
            analysis.resources,
            vec![Resource::Repository(Repository {
                owner: "ashb".into(),
                name: "reviewq".into()
            })]
        );
    }

    #[test]
    fn issue_state_list_coercion_preserves_complete_read_matches() {
        let patterns = PatternSet::new(vec![crate::Pattern {
            id: "issues".into(),
            predicates: vec![
                crate::Predicate::OnlyEffects(vec![
                    EffectKind::ReadRepository,
                    EffectKind::ListIssues,
                ]),
                crate::Predicate::AllResourcesInRepository(Repository {
                    owner: "scope".into(),
                    name: "repository".into(),
                }),
            ],
        }])
        .unwrap();
        for (states, complete) in [
            ("OPEN", true),
            ("CLOSED", true),
            ("null", true),
            ("[]", true),
            ("[OPEN,CLOSED]", true),
            ("FUTURE", false),
            ("[OPEN,FUTURE]", false),
            ("[null]", false),
            ("42", false),
            ("{state:OPEN}", false),
        ] {
            let document = format!(
                "{{repository(owner:\"scope\",name:\"repository\"){{issues(first:1,states:{states}){{nodes{{title}}}}}}}}"
            );
            let request = graphql(&document, json!({}), None);
            let original = request.original().to_vec();
            let analysis = analyze(&request, &patterns).unwrap();
            assert_eq!(analysis.complete(), complete, "{states}");
            assert_eq!(
                analysis
                    .matches
                    .iter()
                    .any(|matched| matched.id == "issues" && matched.complete),
                complete,
                "{states}"
            );
            assert!(
                analysis
                    .effects
                    .iter()
                    .any(|effect| effect.kind == EffectKind::ListIssues),
                "{states}"
            );
            if !complete {
                assert!(
                    analysis
                        .uncovered
                        .iter()
                        .any(|input| input.reason == UncoveredReason::Argument),
                    "{states}"
                );
            }
            assert_eq!(request.original(), original);
        }
    }

    #[test]
    fn query_label_and_repository_root_cannot_hide_unknown_resource_relationships() {
        for query in [
            r#"query { futureApi { id } }"#,
            r#"{ node(id:"opaque") { ... on Issue { title } } }"#,
            r#"{ repository(owner:"ashb",name:"reviewq") { issue(number:1) { timelineItems(first:1) { nodes { ... on CrossReferencedEvent { source { ... on Issue { repository { name } } } } } } } } }"#,
        ] {
            let analysis =
                analyze(&graphql(query, json!({}), None), &PatternSet::default()).unwrap();
            assert!(!analysis.complete());
        }
    }

    #[test]
    fn all_resource_predicate_checks_multiple_roots_and_opaque_ids() {
        let patterns = crate::PatternSet::new(vec![crate::Pattern {
            id: "repo".into(),
            predicates: vec![crate::Predicate::AllResourcesInRepository(Repository {
                owner: "ashb".into(),
                name: "reviewq".into(),
            })],
        }])
        .unwrap();
        let captured = graphql(
            r#"{ a:repository(owner:"ashb",name:"reviewq"){name} b:repository(owner:"other",name:"repo"){name} }"#,
            json!({}),
            None,
        );
        let analysis = analyze(&captured, &patterns).unwrap();
        assert!(analysis.complete());
        assert!(analysis.matches.is_empty());
        let captured = graphql(
            r#"{ repository(owner:"ashb",name:"reviewq"){name} node(id:"x"){__typename} }"#,
            json!({}),
            None,
        );
        assert!(analyze(&captured, &patterns).unwrap().matches.is_empty());
    }

    #[test]
    fn ambiguous_variables_or_directives_cannot_suppress_known_mutation_observations() {
        for body in [
            r#"{"query":"mutation($go:Boolean=false){ deleteIssue(input:{issueId:\"x\"}) @include(if:$go) {clientMutationId} }","variables":{"go":false,"go":true}}"#,
            r#"{"query":"mutation($go:Boolean=false){ deleteIssue(input:{issueId:\"x\"}) @include(if:$go) {clientMutationId} }","variables":{"go":false},"variables":{"go":true}}"#,
            r#"{"query":"mutation{ deleteIssue(input:{issueId:\"x\"}) @include(if:false) @include(if:true) {clientMutationId} }"}"#,
        ] {
            let captured = request(
                "POST",
                "/graphql",
                "Content-Type: application/json\r\n",
                body,
            );
            let analysis = analyze(&captured, &PatternSet::default()).unwrap();
            assert!(!analysis.complete());
            assert!(
                analysis
                    .effects
                    .iter()
                    .any(|effect| effect.kind == EffectKind::DeleteIssue),
                "{body}"
            );
        }
    }

    #[test]
    fn unsupported_variable_envelopes_cannot_use_defaults_to_hide_a_mutation() {
        let patterns = crate::PatternSet::new(vec![crate::Pattern {
            id: "deletion".into(),
            predicates: vec![
                crate::Predicate::Effect(EffectKind::DeleteIssue),
                crate::Predicate::GraphqlRoot {
                    operation: GraphqlOperation::Mutation,
                    field: "deleteIssue".into(),
                },
            ],
        }])
        .unwrap();
        for (default, directive) in [("false", "include"), ("true", "skip")] {
            let query = format!(
                "mutation($go:Boolean={default}) {{ deleteIssue(input:{{issueId:\"x\"}}) @{directive}(if:$go) {{clientMutationId}} }}"
            );
            for variables in [
                json!(r#"{"go":true}"#),
                json!([{"go": true}]),
                json!(true),
                json!(1),
            ] {
                let captured = graphql(&query, variables, None);
                let analysis = analyze(&captured, &patterns).unwrap();
                assert_eq!(
                    analysis.matches,
                    vec![crate::PatternMatch {
                        id: "deletion".into(),
                        complete: false,
                    }]
                );
                assert!(
                    analysis
                        .uncovered
                        .iter()
                        .any(|input| input.reason == UncoveredReason::Variable)
                );
            }
        }
    }

    #[test]
    fn absent_or_null_variables_can_use_defaults_to_exclude_a_mutation() {
        for variables in [None, Some(json!(null)), Some(json!({}))] {
            let mut body = json!({
                "query": r#"mutation($go:Boolean=false){deleteIssue(input:{issueId:"x"}) @include(if:$go){clientMutationId}}"#,
            });
            if let Some(variables) = variables {
                body["variables"] = variables;
            }
            let captured = request(
                "POST",
                "/graphql",
                "Content-Type: application/json\r\n",
                &body.to_string(),
            );
            let analysis = analyze(&captured, &PatternSet::default()).unwrap();
            assert!(analysis.complete());
            assert!(analysis.effects.is_empty());
            assert!(analysis.graphql_roots.is_empty());
        }
    }

    #[test]
    fn a_known_false_directive_excludes_its_mutation_but_unknown_guards_do_not() {
        for (guard, present) in [("false", false), ("$missing", true)] {
            let query = format!(
                "mutation {{ deleteIssue(input:{{issueId:\"x\"}}) @include(if:{guard}) {{clientMutationId}} }}"
            );
            let analysis =
                analyze(&graphql(&query, json!({}), None), &PatternSet::default()).unwrap();
            assert_eq!(
                analysis
                    .effects
                    .iter()
                    .any(|effect| effect.kind == EffectKind::DeleteIssue),
                present
            );
        }
    }

    #[test]
    fn parser_and_expansion_limits_are_errors_instead_of_unknown_coverage() {
        let captured = graphql(
            "{ repository(owner:\"a\",name:\"b\"){ name } }",
            json!({}),
            None,
        );
        for limits in [
            AnalysisLimits {
                graphql_tokens: 2,
                ..AnalysisLimits::default()
            },
            AnalysisLimits {
                graphql_depth: 1,
                ..AnalysisLimits::default()
            },
            AnalysisLimits {
                expanded_selections: 1,
                ..AnalysisLimits::default()
            },
        ] {
            assert_eq!(
                analyze_with_limits(&captured, &PatternSet::default(), limits).unwrap_err(),
                AnalysisError::Limit
            );
        }
        let captured = graphql("{...A} fragment A on Query {...A}", json!({}), None);
        assert_eq!(
            analyze(&captured, &PatternSet::default()).unwrap_err(),
            AnalysisError::Fragment
        );
    }

    #[test]
    fn repeated_fragment_values_and_deep_json_cannot_amplify_analysis_memory() {
        let query = format!(
            "mutation {{ ...F ...F ...F }} fragment F on Mutation {{ deleteIssue(input:{{issueId:\"{}\"}}) {{clientMutationId}} }}",
            "x".repeat(1024)
        );
        let captured = graphql(&query, json!({}), None);
        assert_eq!(
            analyze_with_limits(
                &captured,
                &PatternSet::default(),
                AnalysisLimits {
                    expanded_value_bytes: 2048,
                    ..AnalysisLimits::default()
                }
            )
            .unwrap_err(),
            AnalysisError::Limit
        );
        let deep = format!("{}0{}", "[".repeat(80), "]".repeat(80));
        let captured = request(
            "PATCH",
            "/repos/ashb/reviewq/issues/1",
            "Content-Type: application/json\r\n",
            &deep,
        );
        assert_eq!(
            analyze(&captured, &PatternSet::default()).unwrap_err(),
            AnalysisError::Limit
        );
    }

    #[test]
    fn long_ancestor_paths_count_toward_the_analysis_output_budget() {
        let query = format!("{{ {} {{ {} }} }}", "a".repeat(100_000), "x ".repeat(40));
        assert_eq!(
            analyze(&graphql(&query, json!({}), None), &PatternSet::default()).unwrap_err(),
            AnalysisError::Limit
        );
    }

    #[test]
    fn malformed_or_ambiguous_operations_do_not_become_automatic_matches() {
        for (query, expected) in [
            ("{ repository(", AnalysisError::InvalidGraphql),
            (
                "query A{__typename} query B{__typename}",
                AnalysisError::OperationSelection,
            ),
            (
                "query A{__typename} query A{__typename}",
                AnalysisError::OperationSelection,
            ),
        ] {
            assert_eq!(
                analyze(&graphql(query, json!({}), None), &PatternSet::default()).unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn known_json_grammar_failures_are_distinct_from_unfamiliar_media_or_members() {
        for body in [
            r#"{"query":"mutation { deleteIssue(input:{issueId:\"x\"}) {clientMutationId} }","future":"\uD800"}"#,
            r#"{"query":"mutation { deleteIssue(input:{issueId:\"x\"}) {clientMutationId} }","future":[}"#,
        ] {
            let captured = request(
                "POST",
                "/graphql",
                "Content-Type: application/json\r\n",
                body,
            );
            assert_eq!(
                analyze(&captured, &PatternSet::default()).unwrap_err(),
                AnalysisError::InvalidJson
            );
        }
        let captured = request(
            "POST",
            "/graphql",
            "Content-Type: application/future\r\n",
            "unfamiliar body",
        );
        assert!(
            !analyze(&captured, &PatternSet::default())
                .unwrap()
                .complete()
        );
    }
}
