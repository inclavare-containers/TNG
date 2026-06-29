use std::borrow::Cow;
use std::sync::Weak;

use crate::error::TngError;
use crate::service::RegistedService;
use crate::status::{StatusProvider, StatusQueryResult};
use async_trait::async_trait;

/// Lightweight handle for querying an egress's status tree.
pub struct EgressStatusHandle {
    pub flow: Weak<dyn RegistedService>,
}

#[async_trait]
impl StatusProvider for EgressStatusHandle {
    async fn query_status(&self, path: &[&str]) -> Result<StatusQueryResult, TngError> {
        if let Some(flow) = self.flow.upgrade() {
            flow.query_status(path).await
        } else {
            Err(TngError::StatusPathNotFound)
        }
    }
}

/// Lightweight handle for querying an ingress's status tree.
pub struct IngressStatusHandle {
    pub flow: Weak<dyn RegistedService>,
}

#[async_trait]
impl StatusProvider for IngressStatusHandle {
    async fn query_status(&self, path: &[&str]) -> Result<StatusQueryResult, TngError> {
        if let Some(flow) = self.flow.upgrade() {
            flow.query_status(path).await
        } else {
            Err(TngError::StatusPathNotFound)
        }
    }
}

pub struct TngState {
    pub ready: (
        tokio::sync::watch::Sender<bool>,
        tokio::sync::watch::Receiver<bool>,
    ),
    pub egresses: Vec<EgressStatusHandle>,
    pub ingresses: Vec<IngressStatusHandle>,
}

impl Default for TngState {
    fn default() -> Self {
        Self::new()
    }
}

impl TngState {
    pub fn new() -> Self {
        TngState {
            ready: tokio::sync::watch::channel(false),
            egresses: Vec::new(),
            ingresses: Vec::new(),
        }
    }

    pub fn add_egress(&mut self, handle: EgressStatusHandle) {
        self.egresses.push(handle);
    }

    pub fn add_ingress(&mut self, handle: IngressStatusHandle) {
        self.ingresses.push(handle);
    }
}

#[async_trait]
impl StatusProvider for TngState {
    async fn query_status(&self, path: &[&str]) -> Result<StatusQueryResult, TngError> {
        match path {
            [] => {
                let mut children = Vec::new();
                if !self.egresses.is_empty() {
                    children.push(Cow::Borrowed("egress"));
                }
                if !self.ingresses.is_empty() {
                    children.push(Cow::Borrowed("ingress"));
                }
                Ok(StatusQueryResult::Subtree(children))
            }
            ["egress"] => Ok(StatusQueryResult::Subtree(
                (0..self.egresses.len())
                    .map(|i| Cow::Owned(i.to_string()))
                    .collect(),
            )),
            ["egress", id, rest @ ..] => {
                if let Ok(id) = id.parse::<usize>() {
                    if let Some(handle) = self.egresses.get(id) {
                        handle.query_status(rest).await
                    } else {
                        Err(TngError::StatusPathNotFound)
                    }
                } else {
                    Err(TngError::StatusPathNotFound)
                }
            }
            ["ingress"] => Ok(StatusQueryResult::Subtree(
                (0..self.ingresses.len())
                    .map(|i| Cow::Owned(i.to_string()))
                    .collect(),
            )),
            ["ingress", id, rest @ ..] => {
                if let Ok(id) = id.parse::<usize>() {
                    if let Some(handle) = self.ingresses.get(id) {
                        handle.query_status(rest).await
                    } else {
                        Err(TngError::StatusPathNotFound)
                    }
                } else {
                    Err(TngError::StatusPathNotFound)
                }
            }
            _ => Err(TngError::StatusPathNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_query_status_empty() {
        let state = TngState::new();
        let result = state.query_status(&[]).await;
        assert!(matches!(result, Ok(StatusQueryResult::Subtree(ref v)) if v.is_empty()));
    }
}
