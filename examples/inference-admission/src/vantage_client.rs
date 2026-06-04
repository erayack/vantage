use std::{fmt::Write as _, future::Future, str::FromStr, time::Duration};

use serde::Serialize;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time::timeout,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 1 << 20;

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
    endpoint: HttpEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpEndpoint {
    host: String,
    port: u16,
}

#[derive(Debug, Error)]
pub(crate) enum ClientError {
    #[error("{0}")]
    InvalidBaseUrl(String),
    #[error("failed to serialize request body: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("HTTP transport failed: {0}")]
    Transport(#[from] std::io::Error),
    #[error("vantage returned HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("invalid HTTP response from vantage: {0}")]
    InvalidResponse(String),
    #[error("HTTP operation timed out after {seconds}s")]
    Timeout { seconds: u64 },
    #[error("HTTP response exceeded {limit} bytes")]
    ResponseTooLarge { limit: usize },
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

#[derive(Debug, Clone, Copy)]
enum Method {
    Put,
    Delete,
}

impl Method {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
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
            endpoint: HttpEndpoint::from_str(base_url)?,
        })
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, ClientError> {
        let mut stream = with_timeout(TcpStream::connect((
            self.endpoint.host.as_str(),
            self.endpoint.port,
        )))
        .await??;
        let body_len = body.map_or(0, <[u8]>::len);
        let mut request = String::new();
        let _ = write!(
            request,
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            method.as_str(),
            path,
            self.endpoint.host,
            body_len
        );
        if body.is_some() {
            request.push_str("Content-Type: application/json\r\n");
        }
        request.push_str("\r\n");
        with_timeout(stream.write_all(request.as_bytes())).await??;
        if let Some(body) = body {
            with_timeout(stream.write_all(body)).await??;
        }
        with_timeout(stream.shutdown()).await??;

        let response_bytes = read_response_bounded(&mut stream).await?;
        parse_response(&response_bytes)
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
        let response = self
            .request(Method::Put, &policy_path(target), Some(&bytes))
            .await?;
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
            .request(Method::Put, &runtime_policy_path(target), Some(&bytes))
            .await?;
        require_success(response)
    }

    async fn delete_runtime_policy(
        &self,
        target: &PolicyTarget,
        force: bool,
    ) -> Result<(), ClientError> {
        let response = self
            .request(
                Method::Delete,
                &runtime_policy_delete_path(target, force),
                None,
            )
            .await?;
        require_success(response)
    }
}

impl FromStr for HttpEndpoint {
    type Err = ClientError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let Some(rest) = raw.strip_prefix("http://") else {
            return Err(ClientError::InvalidBaseUrl(
                "only http:// vantage URLs are supported in this example".to_owned(),
            ));
        };
        if rest.contains(['/', '?', '#']) {
            return Err(ClientError::InvalidBaseUrl(
                "base URL must not include a path, query, or fragment".to_owned(),
            ));
        }
        let authority = rest;
        if authority.is_empty() {
            return Err(ClientError::InvalidBaseUrl(
                "base URL must include a host".to_owned(),
            ));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, raw_port)) if !host.is_empty() => {
                let port = raw_port.parse::<u16>().map_err(|error| {
                    ClientError::InvalidBaseUrl(format!("invalid port '{raw_port}': {error}"))
                })?;
                (host.to_owned(), port)
            }
            Some(_) => {
                return Err(ClientError::InvalidBaseUrl(
                    "base URL host must not be empty".to_owned(),
                ));
            }
            None => (authority.to_owned(), 80),
        };
        Ok(Self { host, port })
    }
}

async fn with_timeout<T>(future: impl Future<Output = T>) -> Result<T, ClientError> {
    timeout(REQUEST_TIMEOUT, future)
        .await
        .map_err(|_| ClientError::Timeout {
            seconds: REQUEST_TIMEOUT.as_secs(),
        })
}

async fn read_response_bounded(stream: &mut TcpStream) -> Result<Vec<u8>, ClientError> {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = with_timeout(stream.read(&mut chunk)).await??;
        if read == 0 {
            return Ok(response);
        }
        if response.len().saturating_add(read) > MAX_RESPONSE_BYTES {
            return Err(ClientError::ResponseTooLarge {
                limit: MAX_RESPONSE_BYTES,
            });
        }
        response.extend_from_slice(&chunk[..read]);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpResponse {
    status: u16,
    body: String,
}

impl HttpResponse {
    const fn status_is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
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

fn parse_response(response: &[u8]) -> Result<HttpResponse, ClientError> {
    let text = String::from_utf8_lossy(response);
    let Some((headers, body)) = text.split_once("\r\n\r\n") else {
        return Err(ClientError::InvalidResponse(
            "missing HTTP header terminator".to_owned(),
        ));
    };
    let Some(status_line) = headers.lines().next() else {
        return Err(ClientError::InvalidResponse(
            "missing HTTP status line".to_owned(),
        ));
    };
    let mut parts = status_line.split_whitespace();
    let Some(version) = parts.next() else {
        return Err(ClientError::InvalidResponse(
            "missing HTTP version".to_owned(),
        ));
    };
    if !version.starts_with("HTTP/") {
        return Err(ClientError::InvalidResponse(format!(
            "invalid HTTP version '{version}'"
        )));
    }
    let Some(raw_status) = parts.next() else {
        return Err(ClientError::InvalidResponse(
            "missing HTTP status code".to_owned(),
        ));
    };
    let status = raw_status.parse::<u16>().map_err(|error| {
        ClientError::InvalidResponse(format!("invalid HTTP status code '{raw_status}': {error}"))
    })?;
    Ok(HttpResponse {
        status,
        body: body.to_owned(),
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
    use std::str::FromStr as _;

    use super::{HttpEndpoint, PolicyTarget, percent_encode, runtime_policy_delete_path};

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
    fn parses_http_base_url() {
        let endpoint = HttpEndpoint::from_str("http://127.0.0.1:3000");
        let Ok(endpoint) = endpoint else {
            panic!("endpoint should parse");
        };
        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, 3000);
    }

    #[test]
    fn rejects_base_url_path() {
        let endpoint = HttpEndpoint::from_str("http://127.0.0.1:3000/api");
        assert!(endpoint.is_err(), "base URL path should be rejected");
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
