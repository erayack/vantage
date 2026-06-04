use std::{fmt::Write as _, future::Future};

use serde::Serialize;
use thiserror::Error;

use crate::http_client::{HttpClient, HttpClientError, HttpResponse};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyTarget {
    pub(crate) cgroup_id: u64,
    pub(crate) proto: &'static str,
    pub(crate) dst_port: u16,
    pub(crate) http_method: &'static str,
    pub(crate) http_path: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub(crate) struct PolicyRequest {
    pub(crate) rate_tokens_per_sec: u64,
    pub(crate) burst_tokens: u64,
    pub(crate) enabled: bool,
    pub(crate) proto: &'static str,
    pub(crate) dst_port: u16,
    pub(crate) http_method: &'static str,
}

#[derive(Debug, Clone)]
pub(crate) struct VantageClient {
    http: HttpClient,
}

#[derive(Debug, Error)]
pub(crate) enum ClientError {
    #[error("failed to serialize request body: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("vantage returned HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error(transparent)]
    Http(#[from] HttpClientError),
}

impl PolicyRequest {
    pub(crate) const fn with_target(policy: PolicyShape, target: &PolicyTarget) -> Self {
        Self {
            rate_tokens_per_sec: policy.rate_tokens_per_sec,
            burst_tokens: policy.burst_tokens,
            enabled: policy.enabled,
            proto: target.proto,
            dst_port: target.dst_port,
            http_method: target.http_method,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PolicyShape {
    pub(crate) rate_tokens_per_sec: u64,
    pub(crate) burst_tokens: u64,
    pub(crate) enabled: bool,
}

pub(crate) trait AdmissionClient {
    fn put_base_policy(
        &self,
        target: &PolicyTarget,
        policy: PolicyShape,
    ) -> impl Future<Output = Result<(), ClientError>> + Send;
    fn put_runtime_policy(
        &self,
        target: &PolicyTarget,
        policy: PolicyShape,
    ) -> impl Future<Output = Result<(), ClientError>> + Send;
    fn delete_runtime_policy(
        &self,
        target: &PolicyTarget,
        force: bool,
    ) -> impl Future<Output = Result<(), ClientError>> + Send;
}

impl VantageClient {
    pub(crate) fn new(base_url: &str) -> Result<Self, ClientError> {
        Ok(Self {
            http: HttpClient::new(base_url)?,
        })
    }
}

impl AdmissionClient for VantageClient {
    async fn put_base_policy(
        &self,
        target: &PolicyTarget,
        policy: PolicyShape,
    ) -> Result<(), ClientError> {
        let mut body = serde_json::to_value(PolicyRequest::with_target(policy, target))?;
        body["http_path"] = serde_json::Value::String(target.http_path.clone());
        let bytes = serde_json::to_vec(&body)?;
        let response = self.http.put_json(&policy_path(target), &bytes).await?;
        require_success(response)
    }

    async fn put_runtime_policy(
        &self,
        target: &PolicyTarget,
        policy: PolicyShape,
    ) -> Result<(), ClientError> {
        let mut body = serde_json::to_value(PolicyRequest::with_target(policy, target))?;
        body["http_path"] = serde_json::Value::String(target.http_path.clone());
        let bytes = serde_json::to_vec(&body)?;
        let response = self
            .http
            .put_json(&runtime_policy_path(target), &bytes)
            .await?;
        require_success(response)
    }

    async fn delete_runtime_policy(
        &self,
        target: &PolicyTarget,
        force: bool,
    ) -> Result<(), ClientError> {
        let response = self
            .http
            .delete(&runtime_policy_delete_path(target, force))
            .await?;
        require_success(response)
    }
}

fn require_success(response: HttpResponse) -> Result<(), ClientError> {
    if response.status_is_success() {
        return Ok(());
    }
    Err(ClientError::HttpStatus {
        status: response.status,
        body: response.body,
    })
}

fn policy_path(target: &PolicyTarget) -> String {
    format!("/policy/cg:{}", target.cgroup_id)
}

fn runtime_policy_path(target: &PolicyTarget) -> String {
    format!("/runtime-policy/cg:{}", target.cgroup_id)
}

fn runtime_policy_delete_path(target: &PolicyTarget, force: bool) -> String {
    format!(
        "{}?proto={}&dst_port={}&http_method={}&http_path={}&force={}",
        runtime_policy_path(target),
        target.proto,
        target.dst_port,
        target.http_method,
        percent_encode(&target.http_path),
        force
    )
}

fn percent_encode(raw: &str) -> String {
    let mut encoded = String::new();
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{PolicyTarget, percent_encode, runtime_policy_delete_path};

    fn target() -> PolicyTarget {
        PolicyTarget {
            cgroup_id: 42,
            proto: "tcp",
            dst_port: 8000,
            http_method: "post",
            http_path: "/v1/chat completions".to_owned(),
        }
    }

    #[test]
    fn encodes_delete_runtime_policy_query() {
        let path = runtime_policy_delete_path(&target(), false);
        assert_eq!(
            path,
            "/runtime-policy/cg:42?proto=tcp&dst_port=8000&http_method=post&http_path=%2Fv1%2Fchat%20completions&force=false"
        );
    }

    #[test]
    fn percent_encoding_keeps_unreserved_bytes() {
        assert_eq!(percent_encode("/a-b_c.~"), "%2Fa-b_c.~");
    }
}
