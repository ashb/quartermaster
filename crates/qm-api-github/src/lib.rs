#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod analysis;
#[cfg(test)]
mod api_review;
mod graphql;
mod json;
mod lookup;
mod request;
mod rest;
#[cfg(test)]
mod test_support;

pub use analysis::{
    Analysis, AnalysisError, AnalysisLimits, Effect, EffectKind, GraphqlOperation, Location,
    Pattern, PatternError, PatternMatch, PatternSet, Predicate, Repository, Resource,
    SEMANTICS_VERSION, Uncovered, UncoveredReason, analyze, analyze_with_limits,
};
pub use lookup::{ResourceContext, ResourceKind};
pub use request::{CapturedRequest, Header, RequestError, RequestLimits};
