#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod analysis;
mod graphql;
mod json;
mod request;
mod rest;
#[cfg(test)]
mod test_support;

pub use analysis::{
    Analysis, AnalysisError, AnalysisLimits, Effect, EffectKind, GraphqlOperation, Location,
    Pattern, PatternError, PatternMatch, PatternSet, Predicate, Repository, Resource, Uncovered,
    UncoveredReason, analyze, analyze_with_limits,
};
pub use request::{CapturedRequest, Header, RequestError, RequestLimits};
