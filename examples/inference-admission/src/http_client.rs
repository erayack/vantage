use std::{fmt::Write as _, future::Future, str::FromStr, time::Duration};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time::timeout,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 1 << 20;

#[derive(Debug, Clone)]
pub(crate) struct HttpClient {
    endpoint: HttpEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpEndpoint {
    host: String,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) body: String,
}

impl HttpResponse {
    pub(crate) const fn status_is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

#[derive(Debug, Clone, Copy)]
enum Method {
    Get,
    Put,
    Delete,
}

impl Method {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum HttpClientError {
    #[error("{0}")]
    InvalidBaseUrl(String),
    #[error("HTTP transport failed: {0}")]
    Transport(#[from] std::io::Error),
    #[error("invalid HTTP response: {0}")]
    InvalidResponse(String),
    #[error("HTTP operation timed out after {seconds}s")]
    Timeout { seconds: u64 },
    #[error("HTTP response exceeded {limit} bytes")]
    ResponseTooLarge { limit: usize },
}

impl HttpClient {
    pub(crate) fn new(base_url: &str) -> Result<Self, HttpClientError> {
        Ok(Self {
            endpoint: HttpEndpoint::from_str(base_url)?,
        })
    }

    pub(crate) async fn get(&self, path: &str) -> Result<HttpResponse, HttpClientError> {
        self.request(Method::Get, path, None).await
    }

    pub(crate) async fn put_json(
        &self,
        path: &str,
        body: &[u8],
    ) -> Result<HttpResponse, HttpClientError> {
        self.request(Method::Put, path, Some(body)).await
    }

    pub(crate) async fn delete(&self, path: &str) -> Result<HttpResponse, HttpClientError> {
        self.request(Method::Delete, path, None).await
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, HttpClientError> {
        let mut stream = with_timeout(TcpStream::connect((
            self.endpoint.host.as_str(),
            self.endpoint.port,
        )))
        .await??;
        stream.set_nodelay(true)?;
        let mut request = String::new();
        let _ = write!(
            request,
            "{} {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n",
            method.as_str(),
            path,
            self.endpoint.host
        );
        if let Some(body) = body {
            let _ = write!(request, "Content-Length: {}\r\n", body.len());
            request.push_str("Content-Type: application/json\r\n");
        }
        request.push_str("\r\n");
        with_timeout(stream.write_all(request.as_bytes())).await??;
        if let Some(body) = body {
            with_timeout(stream.write_all(body)).await??;
        }
        with_timeout(stream.flush()).await??;

        let response_bytes = read_response_bounded(&mut stream).await?;
        parse_response(&response_bytes)
    }
}

impl FromStr for HttpEndpoint {
    type Err = HttpClientError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let Some(rest) = raw.strip_prefix("http://") else {
            return Err(HttpClientError::InvalidBaseUrl(
                "only http:// URLs are supported in this example".to_owned(),
            ));
        };
        if rest.contains(['/', '?', '#']) {
            return Err(HttpClientError::InvalidBaseUrl(
                "base URL must not include a path, query, or fragment".to_owned(),
            ));
        }
        if rest.is_empty() {
            return Err(HttpClientError::InvalidBaseUrl(
                "base URL must include a host".to_owned(),
            ));
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, raw_port)) if !host.is_empty() => {
                let port = raw_port.parse::<u16>().map_err(|error| {
                    HttpClientError::InvalidBaseUrl(format!("invalid port '{raw_port}': {error}"))
                })?;
                (host.to_owned(), port)
            }
            Some(_) => {
                return Err(HttpClientError::InvalidBaseUrl(
                    "base URL host must not be empty".to_owned(),
                ));
            }
            None => (rest.to_owned(), 80),
        };
        Ok(Self { host, port })
    }
}

async fn with_timeout<T>(future: impl Future<Output = T>) -> Result<T, HttpClientError> {
    timeout(REQUEST_TIMEOUT, future)
        .await
        .map_err(|_| HttpClientError::Timeout {
            seconds: REQUEST_TIMEOUT.as_secs(),
        })
}

async fn read_response_bounded(stream: &mut TcpStream) -> Result<Vec<u8>, HttpClientError> {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 8192];
    let mut expected_len: Option<usize> = None;
    let mut body_start: Option<usize> = None;
    let mut header_complete_without_body = false;
    loop {
        let read = with_timeout(stream.read(&mut chunk)).await??;
        if read == 0 {
            return Ok(response);
        }
        if response.len().saturating_add(read) > MAX_RESPONSE_BYTES {
            return Err(HttpClientError::ResponseTooLarge {
                limit: MAX_RESPONSE_BYTES,
            });
        }
        response.extend_from_slice(&chunk[..read]);
        if body_start.is_none()
            && let Some(header_end) = find_header_end(&response)
        {
            let headers = String::from_utf8_lossy(&response[..header_end]);
            expected_len = parse_content_length(&headers)?;
            let status = parse_status_code(&headers)?;
            header_complete_without_body = expected_len.is_none() && status_has_no_body(status);
            body_start = Some(header_end.saturating_add(4));
        }
        if header_complete_without_body {
            return Ok(response);
        }
        if let (Some(start), Some(expected)) = (body_start, expected_len)
            && response.len().saturating_sub(start) >= expected
        {
            return Ok(response);
        }
    }
}

fn parse_status_code(headers: &str) -> Result<u16, HttpClientError> {
    let Some(status_line) = headers.lines().next() else {
        return Err(HttpClientError::InvalidResponse(
            "missing HTTP status line".to_owned(),
        ));
    };
    let Some(raw_status) = status_line.split_whitespace().nth(1) else {
        return Err(HttpClientError::InvalidResponse(
            "missing HTTP status code".to_owned(),
        ));
    };
    raw_status.parse::<u16>().map_err(|error| {
        HttpClientError::InvalidResponse(format!(
            "invalid HTTP status code '{raw_status}': {error}"
        ))
    })
}

const fn status_has_no_body(status: u16) -> bool {
    (status >= 100 && status < 200) || status == 204 || status == 304
}

fn find_header_end(response: &[u8]) -> Option<usize> {
    response.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> Result<Option<usize>, HttpClientError> {
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        let trimmed = value.trim();
        let parsed = trimmed.parse::<usize>().map_err(|error| {
            HttpClientError::InvalidResponse(format!("invalid Content-Length '{trimmed}': {error}"))
        })?;
        return Ok(Some(parsed));
    }
    Ok(None)
}

fn parse_response(response: &[u8]) -> Result<HttpResponse, HttpClientError> {
    let text = String::from_utf8_lossy(response);
    let Some((headers, body)) = text.split_once("\r\n\r\n") else {
        return Err(HttpClientError::InvalidResponse(
            "missing HTTP header terminator".to_owned(),
        ));
    };
    let Some(status_line) = headers.lines().next() else {
        return Err(HttpClientError::InvalidResponse(
            "missing HTTP status line".to_owned(),
        ));
    };
    let mut parts = status_line.split_whitespace();
    let Some(version) = parts.next() else {
        return Err(HttpClientError::InvalidResponse(
            "missing HTTP version".to_owned(),
        ));
    };
    if !version.starts_with("HTTP/") {
        return Err(HttpClientError::InvalidResponse(format!(
            "invalid HTTP version '{version}'"
        )));
    }
    let Some(raw_status) = parts.next() else {
        return Err(HttpClientError::InvalidResponse(
            "missing HTTP status code".to_owned(),
        ));
    };
    let status = raw_status.parse::<u16>().map_err(|error| {
        HttpClientError::InvalidResponse(format!(
            "invalid HTTP status code '{raw_status}': {error}"
        ))
    })?;
    Ok(HttpResponse {
        status,
        body: body.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::HttpEndpoint;

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
}
