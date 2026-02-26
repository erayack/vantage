use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use thiserror::Error;
use vantage_common::Policy;

use crate::{
    AppState,
    map_client::MapError,
    metrics::{MetricsError, render_metrics_payload},
    tenant::{TenantParseError, TenantRef},
};

#[derive(Debug, Deserialize)]
pub(crate) struct PutPolicyRequest {
    pub rate_tokens_per_sec: u64,
    pub burst_tokens: u64,
    pub enabled: bool,
}

#[derive(Debug, Error)]
pub(crate) enum ApiError {
    #[error("map operation failed: {0}")]
    Map(#[from] MapError),
    #[error(transparent)]
    Tenant(#[from] TenantParseError),
    #[error(transparent)]
    Metrics(#[from] MetricsError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Tenant(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
            Self::Map(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("map operation failed: {error}"),
            )
                .into_response(),
            Self::Metrics(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("metrics operation failed: {error}"),
            )
                .into_response(),
        }
    }
}

/// Upserts a tenant policy into `POLICY_MAP`.
///
/// # Errors
///
/// Returns `ApiError` when map lookup/update fails.
pub(crate) async fn put_policy(
    Path(tenant): Path<String>,
    State(app): State<AppState>,
    Json(req): Json<PutPolicyRequest>,
) -> Result<StatusCode, ApiError> {
    let tenant = TenantRef::parse(&tenant)?.to_tenant_key();
    let maps = app.maps;
    let policy = Policy {
        rate_tokens_per_sec: req.rate_tokens_per_sec,
        burst_tokens: req.burst_tokens,
        enabled: u8::from(req.enabled),
        _pad: [0; 7],
    };
    maps.upsert_policy(tenant, policy)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Deletes a tenant policy from `POLICY_MAP`.
///
/// # Errors
///
/// Returns `ApiError` when map lookup/delete fails.
pub(crate) async fn delete_policy(
    Path(tenant): Path<String>,
    State(app): State<AppState>,
) -> Result<StatusCode, ApiError> {
    let tenant = TenantRef::parse(&tenant)?.to_tenant_key();
    let maps = app.maps;
    maps.delete_policy(tenant)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Renders daemon and per-tenant counter metrics in Prometheus text format.
///
/// # Errors
///
/// Returns `ApiError` when metric encoding or map iteration fails.
pub(crate) async fn metrics(State(state): State<AppState>) -> Result<Response, ApiError> {
    let payload = render_metrics_payload(&state.metrics, &state.maps)?;

    let mut response = payload.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );

    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::put,
    };
    use prometheus::{IntGauge, Registry};
    use tower::util::ServiceExt as _;
    use vantage_common::{Counters, KERNEL_DROP_EVENT_SAMPLE_EVERY, Policy, TenantKey};

    use super::{delete_policy, put_policy};
    use crate::{
        AppState, DropEventRuntime, MetricsState,
        config::Config,
        map_client::{MapClient, MapError, MapOps},
    };

    struct InMemoryMapOps {
        policies: Mutex<BTreeMap<TenantKey, Policy>>,
    }

    impl InMemoryMapOps {
        const fn new() -> Self {
            Self {
                policies: Mutex::new(BTreeMap::new()),
            }
        }
    }

    impl MapOps for InMemoryMapOps {
        fn upsert_policy(&self, tenant: TenantKey, policy: Policy) -> Result<(), MapError> {
            self.policies
                .lock()
                .map_err(|_| MapError::LockPoisoned)?
                .insert(tenant, policy);
            Ok(())
        }

        fn delete_policy(&self, tenant: TenantKey) -> Result<(), MapError> {
            self.policies
                .lock()
                .map_err(|_| MapError::LockPoisoned)?
                .remove(&tenant);
            Ok(())
        }

        fn collect_counters(&self) -> Result<Vec<(TenantKey, Counters)>, MapError> {
            Ok(Vec::new())
        }
    }

    fn test_state(maps: MapClient) -> AppState {
        let registry = Registry::new();
        let metric = IntGauge::new("vantage_daemon_up", "Daemon running state");
        let Ok(daemon_up) = metric else {
            panic!("metric should initialize");
        };
        daemon_up.set(1);
        let register = registry.register(Box::new(daemon_up.clone()));
        assert!(register.is_ok(), "metric registration should succeed");

        AppState {
            config: Config {
                iface: "lo".to_owned(),
                bind_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 3000)),
                attach_ingress: true,
                attach_egress: false,
                drop_event_log_sample_n: 1,
                drop_event_log_enabled: false,
            },
            drop_events: DropEventRuntime {
                kernel_sample_every: KERNEL_DROP_EVENT_SAMPLE_EVERY,
                log_sample_n: 1,
                log_enabled: false,
            },
            maps,
            metrics: MetricsState {
                registry,
                daemon_up,
            },
        }
    }

    #[tokio::test]
    async fn put_policy_returns_no_content() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/42")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true}"#,
            ));
        let Ok(request) = req else {
            panic!("request should build");
        };

        let resp = match app.oneshot(request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn put_policy_accepts_canonical_ip_tenant() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/ip:10.1.2.3")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true}"#,
            ));
        let Ok(request) = req else {
            panic!("request should build");
        };

        let resp = match app.oneshot(request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn put_policy_accepts_bare_ipv4_tenant() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/10.1.2.3")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true}"#,
            ));
        let Ok(request) = req else {
            panic!("request should build");
        };

        let resp = match app.oneshot(request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn put_policy_accepts_legacy_u32_tenant() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/167838211")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true}"#,
            ));
        let Ok(request) = req else {
            panic!("request should build");
        };

        let resp = match app.oneshot(request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn put_policy_rejects_invalid_tenant() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/not-a-tenant")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true}"#,
            ));
        let Ok(request) = req else {
            panic!("request should build");
        };

        let resp = match app.oneshot(request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn delete_policy_is_idempotent() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let first = Request::builder()
            .method("DELETE")
            .uri("/policy/7")
            .body(Body::empty());
        let Ok(first_request) = first else {
            panic!("request should build");
        };
        let first_resp = match app.clone().oneshot(first_request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(first_resp.status(), StatusCode::NO_CONTENT);

        let second = Request::builder()
            .method("DELETE")
            .uri("/policy/7")
            .body(Body::empty());
        let Ok(second_request) = second else {
            panic!("request should build");
        };
        let second_resp = match app.oneshot(second_request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(second_resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_policy_rejects_invalid_tenant() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("DELETE")
            .uri("/policy/not-a-tenant")
            .body(Body::empty());
        let Ok(request) = req else {
            panic!("request should build");
        };

        let resp = match app.oneshot(request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
