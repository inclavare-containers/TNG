use std::borrow::Cow;

use crate::error::TngError;
use async_trait::async_trait;

/// Result of a status query at a tree node.
pub enum StatusQueryResult {
    /// Reached an intermediate node — return child segment names.
    Subtree(Vec<Cow<'static, str>>),
    /// Reached a leaf node — return serialised value.
    Value(serde_json::Value),
}

/// Trait for nodes in the status tree. Each node can either delegate
/// to a child (matching a path segment) or return a leaf value.
#[async_trait]
pub trait StatusProvider: Send + Sync {
    /// Walk the remaining path segments.
    ///
    /// - Empty iterator → list child segments (`Subtree`)
    /// - Matching segment → delegate to child or return leaf (`Value`)
    /// - No match → `StatusPathNotFound`
    async fn query_status(&self, path: &[&str]) -> Result<StatusQueryResult, TngError>;
}
