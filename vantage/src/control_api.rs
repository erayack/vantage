use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vantage_common::{Counters, GlobalStats, Policy, PolicyMatchLevel, ReasonBuckets, TenantKey};

use crate::{
    AppState,
    map_client::{MapError, ResolvedPolicy},
    metrics::{CpuWindowSample, MetricsError, render_metrics_payload, sample_cpu_window_async},
    tenant::{FlowProto, TenantParseError, TenantRef, compute_http_path_hash, normalized_flow_key},
};

const DEBUG_SNAPSHOT_SCHEMA_VERSION: u16 = 2;

#[derive(Debug, Deserialize)]
pub(crate) struct PutPolicyRequest {
    pub rate_tokens_per_sec: u64,
    pub burst_tokens: u64,
    pub enabled: bool,
    pub proto: Option<String>,
    pub dst_port: Option<u16>,
    pub http_path: Option<String>,
    pub http_path_hash: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PutEnabledRequest {
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct DeletePolicyQuery {
    pub proto: Option<String>,
    pub dst_port: Option<u16>,
    pub http_path: Option<String>,
    pub http_path_hash: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct ResolvePolicyQuery {
    pub proto: Option<String>,
    pub dst_port: Option<u16>,
    pub http_path: Option<String>,
    pub http_path_hash: Option<u32>,
}

#[derive(Debug, Serialize)]
pub(crate) struct GlobalEnabledResponse {
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct PolicyView {
    pub rate_tokens_per_sec: u64,
    pub burst_tokens: u64,
    pub enabled: bool,
}

impl From<Policy> for PolicyView {
    fn from(policy: Policy) -> Self {
        Self {
            rate_tokens_per_sec: policy.rate_tokens_per_sec,
            burst_tokens: policy.burst_tokens,
            enabled: policy.enabled != 0,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ResolvedPolicyView {
    pub requested: TenantKey,
    pub matched: TenantKey,
    pub match_level: PolicyMatchLevel,
    pub requested_flow: String,
    pub matched_flow: String,
    pub policy: PolicyView,
}

impl From<ResolvedPolicy> for ResolvedPolicyView {
    fn from(resolved: ResolvedPolicy) -> Self {
        Self {
            requested: resolved.requested,
            matched: resolved.matched,
            match_level: resolved.match_level,
            requested_flow: normalized_flow_key(resolved.requested),
            matched_flow: normalized_flow_key(resolved.matched),
            policy: resolved.policy.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct PolicyUpsertResponse {
    pub stored: TenantKey,
    pub scope: PolicyMatchLevel,
    pub stored_flow: String,
    pub precedence: &'static str,
    pub effective_for_stored: ResolvedPolicyView,
}

#[derive(Debug, Serialize)]
pub(crate) struct PolicyDeleteResponse {
    pub deleted: bool,
    pub deleted_key: TenantKey,
    pub deleted_flow: String,
    pub precedence: &'static str,
    pub effective_after_delete: Option<ResolvedPolicyView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ResolvePolicyResponse {
    pub requested: TenantKey,
    pub requested_flow: String,
    pub precedence: &'static str,
    pub effective: Option<ResolvedPolicyView>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct BenchmarkSnapshot {
    pub version: u16,
    pub ts_unix_ms: u64,
    pub cpu: CpuWindowSample,
    pub global: GlobalStatsView,
    pub top_tenants: Vec<TenantCounterView>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct GlobalStatsView {
    pub pass_pkts: u64,
    pub drop_pkts: u64,
    pub pass_bytes: u64,
    pub drop_bytes: u64,
    pub reasons: ReasonBucketsView,
}

impl From<GlobalStats> for GlobalStatsView {
    fn from(stats: GlobalStats) -> Self {
        Self {
            pass_pkts: stats.pass_pkts,
            drop_pkts: stats.drop_pkts,
            pass_bytes: stats.pass_bytes,
            drop_bytes: stats.drop_bytes,
            reasons: stats.reasons.into(),
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct ReasonBucketsView {
    pub no_tokens: u64,
    pub no_policy: u64,
    pub parse_fail: u64,
}

impl From<ReasonBuckets> for ReasonBucketsView {
    fn from(reasons: ReasonBuckets) -> Self {
        Self {
            no_tokens: reasons.no_tokens,
            no_policy: reasons.no_policy,
            parse_fail: reasons.parse_fail,
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct TenantCounterView {
    pub tenant: TenantKey,
    pub flow: String,
    pub pass_pkts: u64,
    pub drop_pkts: u64,
    pub pass_bytes: u64,
    pub drop_bytes: u64,
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
) -> Result<Json<PolicyUpsertResponse>, ApiError> {
    let proto = parse_proto(req.proto.as_deref())?;
    let http_path_hash = parse_http_path_hash(req.http_path.as_deref(), req.http_path_hash)?;
    let tenant = TenantRef::parse(&tenant)?
        .with_flow(proto, req.dst_port)?
        .with_http_path_hash(http_path_hash)
        .to_tenant_key();
    let maps = app.maps;
    let policy = Policy {
        rate_tokens_per_sec: req.rate_tokens_per_sec,
        burst_tokens: req.burst_tokens,
        enabled: u8::from(req.enabled),
        _pad: [0; 7],
    };
    maps.upsert_policy(tenant, policy)?;
    let effective_for_stored = ResolvedPolicyView {
        requested: tenant,
        matched: tenant,
        match_level: PolicyMatchLevel::Exact,
        requested_flow: normalized_flow_key(tenant),
        matched_flow: normalized_flow_key(tenant),
        policy: policy.into(),
    };

    Ok(Json(PolicyUpsertResponse {
        stored: tenant,
        scope: policy_scope_from_key(tenant),
        stored_flow: normalized_flow_key(tenant),
        precedence: policy_precedence_contract(),
        effective_for_stored,
    }))
}

/// Sets global data-path enabled state in `GLOBAL_CONFIG_MAP[0]`.
///
/// # Errors
///
/// Returns `ApiError` when map write fails.
pub(crate) async fn put_admin_enabled(
    State(app): State<AppState>,
    Json(req): Json<PutEnabledRequest>,
) -> Result<StatusCode, ApiError> {
    app.maps.set_global_enabled(req.enabled)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Reads global data-path enabled state from `GLOBAL_CONFIG_MAP[0]`.
///
/// # Errors
///
/// Returns `ApiError` when map read fails.
pub(crate) async fn get_admin_enabled(
    State(app): State<AppState>,
) -> Result<Json<GlobalEnabledResponse>, ApiError> {
    let enabled = app.maps.get_global_enabled()?;
    Ok(Json(GlobalEnabledResponse { enabled }))
}

/// Deletes a tenant policy from `POLICY_MAP`.
///
/// # Errors
///
/// Returns `ApiError` when map lookup/delete fails.
pub(crate) async fn delete_policy(
    Path(tenant): Path<String>,
    Query(query): Query<DeletePolicyQuery>,
    State(app): State<AppState>,
) -> Result<Json<PolicyDeleteResponse>, ApiError> {
    let proto = parse_proto(query.proto.as_deref())?;
    let http_path_hash = parse_http_path_hash(query.http_path.as_deref(), query.http_path_hash)?;
    let tenant = TenantRef::parse(&tenant)?
        .with_flow(proto, query.dst_port)?
        .with_http_path_hash(http_path_hash)
        .to_tenant_key();
    let maps = app.maps;
    let deleted = maps.get_policy(tenant)?.is_some();
    maps.delete_policy(tenant)?;
    let effective_after_delete = maps.resolve_policy(tenant)?;

    Ok(Json(PolicyDeleteResponse {
        deleted,
        deleted_key: tenant,
        deleted_flow: normalized_flow_key(tenant),
        precedence: policy_precedence_contract(),
        effective_after_delete: effective_after_delete.map(Into::into),
    }))
}

/// Resolves the effective policy for a tenant and returns the matched precedence level.
///
/// # Errors
///
/// Returns `ApiError` when tenant parsing or map reads fail.
pub(crate) async fn resolve_policy(
    Path(tenant): Path<String>,
    Query(query): Query<ResolvePolicyQuery>,
    State(app): State<AppState>,
) -> Result<Json<ResolvePolicyResponse>, ApiError> {
    let proto = parse_proto(query.proto.as_deref())?;
    let http_path_hash = parse_http_path_hash(query.http_path.as_deref(), query.http_path_hash)?;
    let requested = TenantRef::parse(&tenant)?
        .with_flow(proto, query.dst_port)?
        .with_http_path_hash(http_path_hash)
        .to_tenant_key();
    let effective = app.maps.resolve_policy(requested)?;

    Ok(Json(ResolvePolicyResponse {
        requested,
        requested_flow: normalized_flow_key(requested),
        precedence: policy_precedence_contract(),
        effective: effective.map(Into::into),
    }))
}

/// Renders daemon and per-tenant counter metrics in Prometheus text format.
///
/// # Errors
///
/// Returns `ApiError` when metric encoding or map iteration fails.
pub(crate) async fn metrics(State(state): State<AppState>) -> Result<Response, ApiError> {
    let payload = render_metrics_payload(
        &state.metrics,
        &state.maps,
        state.config.metrics_dimensions.enabled(),
    )?;

    let mut response = payload.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );

    Ok(response)
}

/// Samples daemon and host CPU over the configured window and returns averaged utilization.
///
/// # Errors
///
/// Returns `ApiError` when CPU sampling fails.
pub(crate) async fn debug_cpu_window(
    State(state): State<AppState>,
) -> Result<Json<CpuWindowSample>, ApiError> {
    let sample_window = std::time::Duration::from_millis(state.config.cpu_window_ms);
    let sample = sample_cpu_window_async(sample_window).await?;

    Ok(Json(sample))
}

/// Builds a benchmark-friendly snapshot with timestamp, CPU window, and global counters.
///
/// # Errors
///
/// Returns `ApiError` when CPU sampling or map reads fail.
pub(crate) async fn debug_snapshot(
    State(app): State<AppState>,
) -> Result<Json<BenchmarkSnapshot>, ApiError> {
    let sample_window = std::time::Duration::from_millis(app.config.cpu_window_ms);
    let cpu = sample_cpu_window_async(sample_window).await?;
    let global = app.maps.read_global_stats()?;
    let top_tenants = build_top_tenants(app.maps.collect_counters()?, app.config.debug_top_tenants);
    let ts_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        });

    Ok(Json(BenchmarkSnapshot {
        version: DEBUG_SNAPSHOT_SCHEMA_VERSION,
        ts_unix_ms,
        cpu,
        global: global.into(),
        top_tenants,
    }))
}

fn parse_proto(proto: Option<&str>) -> Result<Option<FlowProto>, TenantParseError> {
    match proto {
        Some(raw) => Ok(Some(FlowProto::parse(raw)?)),
        None => Ok(None),
    }
}

fn parse_http_path_hash(
    http_path: Option<&str>,
    explicit_hash: Option<u32>,
) -> Result<Option<u32>, TenantParseError> {
    let computed_hash = http_path.map(compute_http_path_hash);
    match (computed_hash, explicit_hash) {
        (Some(computed), Some(explicit)) if computed != explicit => {
            Err(TenantParseError::PathHashMismatch)
        }
        (Some(computed), _) => Ok(Some(computed)),
        (None, Some(explicit)) => Ok(Some(explicit)),
        (None, None) => Ok(None),
    }
}

const fn policy_precedence_contract() -> &'static str {
    "exact(src_ip,proto,dst_port) > proto_wildcard(src_ip,proto,0) > full_wildcard(src_ip,0,0)"
}

const fn policy_scope_from_key(key: TenantKey) -> PolicyMatchLevel {
    if key.proto == 0 {
        return PolicyMatchLevel::FullWildcard;
    }

    if key.dst_port == 0 {
        return PolicyMatchLevel::ProtoWildcard;
    }

    PolicyMatchLevel::Exact
}

fn build_top_tenants(counters: Vec<(TenantKey, Counters)>, limit: usize) -> Vec<TenantCounterView> {
    let mut counters = counters;
    counters.sort_unstable_by(|left, right| {
        right
            .1
            .drop_pkts
            .cmp(&left.1.drop_pkts)
            .then_with(|| right.1.drop_bytes.cmp(&left.1.drop_bytes))
            .then_with(|| left.0.cmp(&right.0))
    });

    counters
        .into_iter()
        .take(limit)
        .map(|(tenant, counters)| TenantCounterView {
            tenant,
            flow: normalized_flow_key(tenant),
            pass_pkts: counters.pass_pkts,
            drop_pkts: counters.drop_pkts,
            pass_bytes: counters.pass_bytes,
            drop_bytes: counters.drop_bytes,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode},
        routing::{get, put},
    };
    use prometheus::{IntGauge, Registry};
    use tower::util::ServiceExt as _;
    use vantage_common::{
        Counters, GlobalConfig, GlobalStats, KERNEL_DROP_EVENT_SAMPLE_EVERY, Policy, ReasonBuckets,
        TenantKey,
    };

    use super::{
        build_top_tenants, debug_cpu_window, debug_snapshot, delete_policy, get_admin_enabled,
        metrics, put_admin_enabled, put_policy, resolve_policy,
    };
    use crate::{
        AppState, DropEventRuntime, MetricsState,
        config::Config,
        map_client::{MapClient, MapError, MapOps},
        tenant::compute_http_path_hash,
    };

    struct InMemoryMapOps {
        policies: Mutex<BTreeMap<TenantKey, Policy>>,
        counters: Vec<(TenantKey, Counters)>,
        global_stats: GlobalStats,
        global_enabled: Mutex<bool>,
        flow_keys_live: Mutex<bool>,
    }

    impl InMemoryMapOps {
        fn new() -> Self {
            Self {
                policies: Mutex::new(BTreeMap::new()),
                counters: Vec::new(),
                global_stats: Self::default_global_stats(),
                global_enabled: Mutex::new(true),
                flow_keys_live: Mutex::new(true),
            }
        }

        const fn default_global_stats() -> GlobalStats {
            GlobalStats {
                pass_pkts: 0,
                drop_pkts: 0,
                pass_bytes: 0,
                drop_bytes: 0,
                reasons: ReasonBuckets {
                    no_tokens: 0,
                    no_policy: 0,
                    parse_fail: 0,
                },
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

        fn get_policy(&self, tenant: TenantKey) -> Result<Option<Policy>, MapError> {
            let policy = self
                .policies
                .lock()
                .map_err(|_| MapError::LockPoisoned)?
                .get(&tenant)
                .copied();
            Ok(policy)
        }

        fn collect_counters(&self) -> Result<Vec<(TenantKey, Counters)>, MapError> {
            Ok(self.counters.clone())
        }

        fn read_global_stats(&self) -> Result<GlobalStats, MapError> {
            Ok(self.global_stats)
        }

        fn seed_global_config(&self, config: GlobalConfig) -> Result<(), MapError> {
            {
                let mut enabled = self
                    .global_enabled
                    .lock()
                    .map_err(|_| MapError::LockPoisoned)?;
                *enabled = config.enabled != 0;
            }
            {
                let mut flow_keys_live = self
                    .flow_keys_live
                    .lock()
                    .map_err(|_| MapError::LockPoisoned)?;
                *flow_keys_live = config.flow_keys_live != 0;
            }
            Ok(())
        }

        fn set_global_enabled(&self, enabled: bool) -> Result<(), MapError> {
            {
                let mut current = self
                    .global_enabled
                    .lock()
                    .map_err(|_| MapError::LockPoisoned)?;
                *current = enabled;
            }
            Ok(())
        }

        fn get_global_enabled(&self) -> Result<bool, MapError> {
            let current = self
                .global_enabled
                .lock()
                .map_err(|_| MapError::LockPoisoned)?;
            Ok(*current)
        }

        fn set_flow_keys_live(&self, flow_keys_live: bool) -> Result<(), MapError> {
            {
                let mut current = self
                    .flow_keys_live
                    .lock()
                    .map_err(|_| MapError::LockPoisoned)?;
                *current = flow_keys_live;
            }
            Ok(())
        }

        fn get_flow_keys_live(&self) -> Result<bool, MapError> {
            let current = self
                .flow_keys_live
                .lock()
                .map_err(|_| MapError::LockPoisoned)?;
            Ok(*current)
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
                cpu_window_ms: 5_000,
                metrics_dimensions: crate::config::MetricsDimensions::Aggregate,
                flow_keys_mode: crate::config::FlowKeysMode::Live,
                debug_top_tenants: 10,
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

    fn fixture_snapshot_maps() -> MapClient {
        let fixture_stats = GlobalStats {
            pass_pkts: 11,
            drop_pkts: 3,
            pass_bytes: 1_500,
            drop_bytes: 300,
            reasons: ReasonBuckets {
                no_tokens: 2,
                no_policy: 1,
                parse_fail: 4,
            },
        };
        MapClient::from_ops(Arc::new(InMemoryMapOps {
            policies: Mutex::new(BTreeMap::new()),
            counters: vec![
                (
                    TenantKey {
                        src_ip: 167_838_211,
                        http_path_hash: 0,
                        dst_port: 443,
                        proto: 6,
                        _pad: 0,
                    },
                    Counters {
                        pass_pkts: 10,
                        drop_pkts: 9,
                        pass_bytes: 100,
                        drop_bytes: 90,
                    },
                ),
                (
                    TenantKey {
                        src_ip: 167_838_212,
                        http_path_hash: 0,
                        dst_port: 53,
                        proto: 17,
                        _pad: 0,
                    },
                    Counters {
                        pass_pkts: 5,
                        drop_pkts: 3,
                        pass_bytes: 50,
                        drop_bytes: 30,
                    },
                ),
            ],
            global_stats: fixture_stats,
            global_enabled: Mutex::new(true),
            flow_keys_live: Mutex::new(true),
        }))
    }

    fn assert_snapshot_basics(payload: &serde_json::Value) {
        assert_eq!(payload["version"], serde_json::json!(2));
        assert!(payload["ts_unix_ms"].as_u64().is_some());
        assert!(payload["cpu"]["window_ms"].as_u64().is_some());
        assert!(payload["cpu"]["system_cpu_percent"].as_f64().is_some());
        assert!(payload["cpu"]["daemon_cpu_percent"].as_f64().is_some());
        assert_eq!(payload["global"]["pass_pkts"], serde_json::json!(11));
        assert_eq!(payload["global"]["drop_pkts"], serde_json::json!(3));
        assert_eq!(payload["global"]["pass_bytes"], serde_json::json!(1_500));
        assert_eq!(payload["global"]["drop_bytes"], serde_json::json!(300));
        assert_eq!(
            payload["global"]["reasons"]["no_tokens"],
            serde_json::json!(2)
        );
        assert_eq!(
            payload["global"]["reasons"]["no_policy"],
            serde_json::json!(1)
        );
        assert_eq!(
            payload["global"]["reasons"]["parse_fail"],
            serde_json::json!(4)
        );
    }

    fn metrics_fixture_maps() -> MapClient {
        MapClient::from_ops(Arc::new(InMemoryMapOps {
            policies: Mutex::new(BTreeMap::new()),
            counters: vec![(
                TenantKey {
                    src_ip: 167_838_211,
                    http_path_hash: 0,
                    dst_port: 443,
                    proto: 6,
                    _pad: 0,
                },
                Counters {
                    pass_pkts: 10,
                    drop_pkts: 9,
                    pass_bytes: 100,
                    drop_bytes: 90,
                },
            )],
            global_stats: InMemoryMapOps::default_global_stats(),
            global_enabled: Mutex::new(true),
            flow_keys_live: Mutex::new(true),
        }))
    }

    #[tokio::test]
    async fn put_policy_returns_ok_with_resolution_payload() {
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
        assert_eq!(resp.status(), StatusCode::OK);

        let read = to_bytes(resp.into_body(), usize::MAX).await;
        let Ok(bytes) = read else {
            panic!("response body should be readable");
        };
        let parsed = serde_json::from_slice::<serde_json::Value>(&bytes);
        let Ok(payload) = parsed else {
            panic!("response should be valid JSON");
        };
        assert_eq!(
            payload["precedence"],
            serde_json::json!(
                "exact(src_ip,proto,dst_port) > proto_wildcard(src_ip,proto,0) > full_wildcard(src_ip,0,0)"
            )
        );
        assert_eq!(payload["scope"], serde_json::json!("full_wildcard"));
        assert_eq!(
            payload["effective_for_stored"]["match_level"],
            serde_json::json!("exact")
        );
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
        assert_eq!(resp.status(), StatusCode::OK);
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
        assert_eq!(resp.status(), StatusCode::OK);
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
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn put_policy_accepts_flow_fields() {
        let fixture = Arc::new(InMemoryMapOps::new());
        let maps = MapClient::from_ops(Arc::clone(&fixture) as Arc<dyn MapOps>);
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/ip:10.1.2.3")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true,"proto":"tcp","dst_port":443}"#,
            ));
        let Ok(request) = req else {
            panic!("request should build");
        };

        let resp = match app.oneshot(request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(resp.status(), StatusCode::OK);

        match fixture.policies.lock() {
            Ok(policies) => {
                let tenant = TenantKey {
                    src_ip: 167_838_211,
                    http_path_hash: 0,
                    dst_port: 443,
                    proto: 6,
                    _pad: 0,
                };
                assert!(
                    policies.contains_key(&tenant),
                    "flow-specific key should be written"
                );
            }
            Err(error) => {
                panic!("fixture lock should not be poisoned: {error}");
            }
        }
    }

    #[tokio::test]
    async fn put_policy_accepts_http_path_and_stores_hash_only() {
        let fixture = Arc::new(InMemoryMapOps::new());
        let maps = MapClient::from_ops(Arc::clone(&fixture) as Arc<dyn MapOps>);
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/ip:10.1.2.3")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true,"proto":"tcp","dst_port":443,"http_path":"/predict"}"#,
            ));
        let Ok(request) = req else {
            panic!("request should build");
        };

        let resp = match app.oneshot(request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(resp.status(), StatusCode::OK);

        match fixture.policies.lock() {
            Ok(policies) => {
                let tenant = TenantKey {
                    src_ip: 167_838_211,
                    http_path_hash: compute_http_path_hash("/predict"),
                    dst_port: 443,
                    proto: 6,
                    _pad: 0,
                };
                assert!(
                    policies.contains_key(&tenant),
                    "policy key should store only numeric hash selector"
                );
            }
            Err(error) => {
                panic!("fixture lock should not be poisoned: {error}");
            }
        }
    }

    #[tokio::test]
    async fn put_policy_rejects_mismatched_http_path_and_hash() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/ip:10.1.2.3")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true,"proto":"tcp","dst_port":443,"http_path":"/predict","http_path_hash":1}"#,
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
    async fn put_policy_rejects_proto_without_dst_port() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/ip:10.1.2.3")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true,"proto":"udp"}"#,
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
    async fn put_policy_rejects_dst_port_without_proto() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/ip:10.1.2.3")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true,"dst_port":53}"#,
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
    async fn put_policy_rejects_invalid_proto() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/ip:10.1.2.3")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true,"proto":"icmp","dst_port":53}"#,
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
        assert_eq!(first_resp.status(), StatusCode::OK);

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
        assert_eq!(second_resp.status(), StatusCode::OK);
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

    #[tokio::test]
    async fn delete_policy_accepts_flow_query_fields() {
        let fixture = Arc::new(InMemoryMapOps::new());
        let maps = MapClient::from_ops(Arc::clone(&fixture) as Arc<dyn MapOps>);
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let put_req = Request::builder()
            .method("PUT")
            .uri("/policy/ip:10.1.2.3")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true,"proto":"tcp","dst_port":443}"#,
            ));
        let Ok(put_request) = put_req else {
            panic!("request should build");
        };
        let put_response = match app.clone().oneshot(put_request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(put_response.status(), StatusCode::OK);

        let delete_req = Request::builder()
            .method("DELETE")
            .uri("/policy/ip:10.1.2.3?proto=tcp&dst_port=443")
            .body(Body::empty());
        let Ok(delete_request) = delete_req else {
            panic!("request should build");
        };
        let delete_response = match app.oneshot(delete_request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(delete_response.status(), StatusCode::OK);

        match fixture.policies.lock() {
            Ok(policies) => assert!(policies.is_empty(), "flow-specific key should be deleted"),
            Err(error) => panic!("fixture lock should not be poisoned: {error}"),
        }
    }

    #[tokio::test]
    async fn delete_policy_rejects_proto_without_dst_port() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("DELETE")
            .uri("/policy/ip:10.1.2.3?proto=udp")
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

    #[tokio::test]
    async fn resolve_policy_returns_effective_match_using_precedence() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .route("/policy/:tenant/resolve", get(resolve_policy))
            .with_state(test_state(maps));

        let broad_put = Request::builder()
            .method("PUT")
            .uri("/policy/ip:10.1.2.3")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true,"proto":"tcp","dst_port":0}"#,
            ));
        let Ok(broad_request) = broad_put else {
            panic!("request should build");
        };
        let broad_response = match app.clone().oneshot(broad_request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(broad_response.status(), StatusCode::OK);

        let resolve_req = Request::builder()
            .method("GET")
            .uri("/policy/ip:10.1.2.3/resolve?proto=tcp&dst_port=443")
            .body(Body::empty());
        let Ok(resolve_request) = resolve_req else {
            panic!("request should build");
        };
        let resolve_response = match app.oneshot(resolve_request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(resolve_response.status(), StatusCode::OK);

        let read = to_bytes(resolve_response.into_body(), usize::MAX).await;
        let Ok(bytes) = read else {
            panic!("response body should be readable");
        };
        let parsed = serde_json::from_slice::<serde_json::Value>(&bytes);
        let Ok(payload) = parsed else {
            panic!("response should be valid JSON");
        };
        assert_eq!(
            payload["effective"]["match_level"],
            serde_json::json!("proto_wildcard")
        );
        assert_eq!(
            payload["effective"]["matched"]["dst_port"],
            serde_json::json!(0)
        );
    }

    #[tokio::test]
    async fn put_admin_enabled_sets_global_flag() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route(
                "/admin/enabled",
                put(put_admin_enabled).get(get_admin_enabled),
            )
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/admin/enabled")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"enabled":false}"#));
        let Ok(request) = req else {
            panic!("request should build");
        };

        let response = match app.clone().oneshot(request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let get_req = Request::builder()
            .method("GET")
            .uri("/admin/enabled")
            .body(Body::empty());
        let Ok(get_request) = get_req else {
            panic!("request should build");
        };
        let get_response = match app.oneshot(get_request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(get_response.status(), StatusCode::OK);

        let read = to_bytes(get_response.into_body(), usize::MAX).await;
        let Ok(bytes) = read else {
            panic!("response body should be readable");
        };
        let parsed = serde_json::from_slice::<serde_json::Value>(&bytes);
        let Ok(payload) = parsed else {
            panic!("response should be valid JSON");
        };
        assert_eq!(payload, serde_json::json!({"enabled": false}));
    }

    #[tokio::test]
    async fn debug_cpu_window_returns_json_sample_from_fixture_state() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let mut state = test_state(maps);
        state.config.cpu_window_ms = 1;
        let app = Router::new()
            .route("/debug/cpu-window", get(debug_cpu_window))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/debug/cpu-window")
            .body(Body::empty());
        let Ok(request) = req else {
            panic!("request should build");
        };

        let response = match app.oneshot(request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(response.status(), StatusCode::OK);

        let read = to_bytes(response.into_body(), usize::MAX).await;
        let Ok(bytes) = read else {
            panic!("response body should be readable");
        };
        let parsed = serde_json::from_slice::<serde_json::Value>(&bytes);
        let Ok(payload) = parsed else {
            panic!("response should be valid JSON");
        };

        let window_ms = payload["window_ms"].as_u64();
        assert!(window_ms.is_some_and(|value| value >= 1));
        let system = payload["system_cpu_percent"].as_f64();
        let daemon = payload["daemon_cpu_percent"].as_f64();
        assert!(system.is_some(), "system cpu percent should be present");
        assert!(daemon.is_some(), "daemon cpu percent should be present");
    }

    #[tokio::test]
    async fn debug_snapshot_returns_contract_shape_with_bounded_top_tenants() {
        let maps = fixture_snapshot_maps();
        let mut state = test_state(maps);
        state.config.cpu_window_ms = 1;
        state.config.debug_top_tenants = 1;
        let app = Router::new()
            .route("/debug/snapshot", get(debug_snapshot))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/debug/snapshot")
            .body(Body::empty());
        let Ok(request) = req else {
            panic!("request should build");
        };

        let response = match app.oneshot(request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(response.status(), StatusCode::OK);

        let read = to_bytes(response.into_body(), usize::MAX).await;
        let Ok(bytes) = read else {
            panic!("response body should be readable");
        };
        let parsed = serde_json::from_slice::<serde_json::Value>(&bytes);
        let Ok(payload) = parsed else {
            panic!("response should be valid JSON");
        };

        assert_snapshot_basics(&payload);
        let top = payload["top_tenants"].as_array();
        let Some(top) = top else {
            panic!("top_tenants should be an array");
        };
        assert_eq!(top.len(), 1);
        assert_eq!(
            top[0]["flow"],
            serde_json::json!("src=10.1.2.3|proto=tcp|dport=443|path_hash=*")
        );
    }

    #[test]
    fn build_top_tenants_applies_ordering_and_limit() {
        let counters = vec![
            (
                TenantKey {
                    src_ip: 2,
                    http_path_hash: 0,
                    dst_port: 80,
                    proto: 6,
                    _pad: 0,
                },
                Counters {
                    pass_pkts: 1,
                    drop_pkts: 5,
                    pass_bytes: 10,
                    drop_bytes: 200,
                },
            ),
            (
                TenantKey {
                    src_ip: 1,
                    http_path_hash: 0,
                    dst_port: 80,
                    proto: 6,
                    _pad: 0,
                },
                Counters {
                    pass_pkts: 1,
                    drop_pkts: 5,
                    pass_bytes: 10,
                    drop_bytes: 200,
                },
            ),
            (
                TenantKey {
                    src_ip: 3,
                    http_path_hash: 0,
                    dst_port: 80,
                    proto: 6,
                    _pad: 0,
                },
                Counters {
                    pass_pkts: 1,
                    drop_pkts: 5,
                    pass_bytes: 10,
                    drop_bytes: 150,
                },
            ),
        ];

        let top = build_top_tenants(counters, 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].tenant.src_ip, 1);
        assert_eq!(top[1].tenant.src_ip, 2);
    }

    #[tokio::test]
    async fn metrics_endpoint_omits_flow_labels_when_aggregate_mode() {
        let maps = metrics_fixture_maps();
        let mut state = test_state(maps);
        state.config.metrics_dimensions = crate::config::MetricsDimensions::Aggregate;
        let app = Router::new()
            .route("/metrics", get(metrics))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/metrics")
            .body(Body::empty());
        let Ok(request) = req else {
            panic!("request should build");
        };

        let response = match app.oneshot(request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(response.status(), StatusCode::OK);

        let read = to_bytes(response.into_body(), usize::MAX).await;
        let Ok(bytes) = read else {
            panic!("response body should be readable");
        };
        let text = String::from_utf8(bytes.to_vec());
        let Ok(text) = text else {
            panic!("metrics response should be utf-8");
        };
        assert!(text.contains("vantage_tenant_pass_packets 10"));
        assert!(!text.contains("flow=\""));
    }

    #[tokio::test]
    async fn metrics_endpoint_includes_flow_labels_when_dimensional_mode() {
        let maps = metrics_fixture_maps();
        let mut state = test_state(maps);
        state.config.metrics_dimensions = crate::config::MetricsDimensions::PerFlow;
        let app = Router::new()
            .route("/metrics", get(metrics))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/metrics")
            .body(Body::empty());
        let Ok(request) = req else {
            panic!("request should build");
        };

        let response = match app.oneshot(request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(response.status(), StatusCode::OK);

        let read = to_bytes(response.into_body(), usize::MAX).await;
        let Ok(bytes) = read else {
            panic!("response body should be readable");
        };
        let text = String::from_utf8(bytes.to_vec());
        let Ok(text) = text else {
            panic!("metrics response should be utf-8");
        };
        assert!(text.contains("flow=\"src=10.1.2.3|proto=tcp|dport=443|path_hash=*\""));
        assert!(text.contains("src_ip=\"10.1.2.3\""));
    }
}
