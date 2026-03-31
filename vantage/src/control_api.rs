use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;
use vantage_common::{Counters, GlobalStats, Policy, PolicyMatchLevel, ReasonBuckets, TenantKey};

use crate::{
    AppState,
    adaptive::AdaptiveState,
    map_client::{MapError, PolicySource, ResolvedPolicy},
    metrics::{
        CpuWindowSample, MetricsError, render_metrics_payload, sample_cpu_window_async,
        sample_memory_percent_async,
    },
    state_store::StateStoreError,
    tenancy::TenancyError,
    tenant::{
        FlowProto, TenantParseError, TenantRef, http_method_label, normalized_flow_key, proto_label,
    },
};

const DEBUG_SNAPSHOT_SCHEMA_VERSION: u16 = 3;

#[derive(Debug, Deserialize)]
pub(crate) struct PutPolicyRequest {
    pub rate_tokens_per_sec: u64,
    pub burst_tokens: u64,
    pub enabled: bool,
    pub proto: Option<String>,
    pub dst_port: Option<u16>,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub http_path_hash: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PutEnabledRequest {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PutEssentialRequest {
    pub essential: bool,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct DeletePolicyQuery {
    pub proto: Option<String>,
    pub dst_port: Option<u16>,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub http_path_hash: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct ResolvePolicyQuery {
    pub proto: Option<String>,
    pub dst_port: Option<u16>,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub http_path_hash: Option<u32>,
}

#[derive(Debug, Serialize)]
pub(crate) struct GlobalEnabledResponse {
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct EssentialTenantResponse {
    pub tenant: u64,
    pub essential: bool,
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
    pub requested_selector: SelectorView,
    pub matched_selector: SelectorView,
    pub match_level: PolicyMatchLevel,
    pub source: PolicySource,
    pub requested_flow: String,
    pub matched_flow: String,
    pub policy: PolicyView,
}

impl From<ResolvedPolicy> for ResolvedPolicyView {
    fn from(resolved: ResolvedPolicy) -> Self {
        Self {
            requested: resolved.requested,
            matched: resolved.matched,
            requested_selector: SelectorView::from_tenant(resolved.requested),
            matched_selector: SelectorView::from_tenant(resolved.matched),
            match_level: resolved.match_level,
            source: resolved.source,
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
    pub stored_selector: SelectorView,
    pub stored_flow: String,
    pub precedence: &'static str,
    pub effective_for_stored: ResolvedPolicyView,
    pub warnings: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PolicyDeleteResponse {
    pub deleted: bool,
    pub deleted_key: TenantKey,
    pub deleted_selector: SelectorView,
    pub deleted_flow: String,
    pub precedence: &'static str,
    pub effective_after_delete: Option<ResolvedPolicyView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ResolvePolicyResponse {
    pub requested: TenantKey,
    pub requested_selector: SelectorView,
    pub requested_flow: String,
    pub precedence: &'static str,
    pub effective: Option<ResolvedPolicyView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SelectorView {
    pub proto: &'static str,
    pub dst_port: Option<u16>,
    pub http_method: &'static str,
    pub http_path_hash: Option<u32>,
    pub http_path_hash_hex: Option<String>,
    pub normalized: String,
}

impl SelectorView {
    fn from_tenant(tenant: TenantKey) -> Self {
        let http_path_hash = (tenant.http_path_hash != 0).then_some(tenant.http_path_hash);
        Self {
            proto: proto_label(tenant.proto),
            dst_port: (tenant.dst_port != 0).then_some(tenant.dst_port),
            http_method: http_method_label(tenant.http_method),
            http_path_hash,
            http_path_hash_hex: http_path_hash.map(|hash| format!("{hash:#010x}")),
            normalized: normalized_flow_key(tenant),
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct BenchmarkSnapshot {
    pub version: u16,
    pub ts_unix_ms: u64,
    pub cpu: CpuWindowSample,
    pub system_memory_percent: f64,
    pub adaptive_state: AdaptiveState,
    pub adaptive_high_watermark_percent: u8,
    pub adaptive_low_watermark_percent: u8,
    pub adaptive_managed_override_count: u64,
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
    #[error(transparent)]
    Tenancy(#[from] TenancyError),
    #[error(transparent)]
    StateStore(#[from] StateStoreError),
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
            Self::Tenancy(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("tenancy operation failed: {error}"),
            )
                .into_response(),
            Self::StateStore(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("state store operation failed: {error}"),
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
    let tenant = TenantRef::parse(&tenant)?
        .with_flow(proto, req.dst_port)?
        .with_http_selectors(
            req.http_method.as_deref(),
            req.http_path.as_deref(),
            req.http_path_hash,
        )?
        .to_tenant_key();
    let mut warnings = Vec::new();
    if partial_l7_policy_key(tenant) {
        app.metrics.partial_l7_policy_keys_total.inc();
        if app.config.policy_validation_mode.strict() {
            return Err(ApiError::Tenant(
                TenantParseError::PartialL7SelectorsRequireFlow,
            ));
        }

        warnings.push(PARTIAL_L7_POLICY_WARNING);
        warn!(
            tenant = ?tenant,
            policy_validation_mode = ?app.config.policy_validation_mode,
            "accepted partial-l7 policy key with wildcard l4 selectors"
        );
    }
    let maps = app.maps;
    let policy = Policy {
        rate_tokens_per_sec: req.rate_tokens_per_sec,
        burst_tokens: req.burst_tokens,
        enabled: u8::from(req.enabled),
        _pad: [0; 7],
    };
    let previous = app.state_store.upsert_base_policy(tenant, policy)?;
    if let Err(error) = maps.upsert_policy(tenant, policy) {
        let rollback = if let Some(previous_policy) = previous {
            app.state_store
                .upsert_base_policy(tenant, previous_policy)
                .map(|_| ())
        } else {
            app.state_store.delete_base_policy(tenant).map(|_| ())
        };
        if let Err(rollback_error) = rollback {
            warn!(
                tenant = ?tenant,
                error = %rollback_error,
                "failed to rollback persisted base policy after map apply failure"
            );
            return Err(ApiError::StateStore(rollback_error));
        }
        return Err(ApiError::Map(error));
    }
    let effective_for_stored = maps.resolve_policy(tenant)?.map_or_else(
        || ResolvedPolicyView {
            requested: tenant,
            matched: tenant,
            requested_selector: SelectorView::from_tenant(tenant),
            matched_selector: SelectorView::from_tenant(tenant),
            match_level: PolicyMatchLevel::Exact,
            source: PolicySource::Base,
            requested_flow: normalized_flow_key(tenant),
            matched_flow: normalized_flow_key(tenant),
            policy: policy.into(),
        },
        Into::into,
    );

    Ok(Json(PolicyUpsertResponse {
        stored: tenant,
        scope: policy_scope_from_key(tenant),
        stored_selector: SelectorView::from_tenant(tenant),
        stored_flow: normalized_flow_key(tenant),
        precedence: policy_precedence_contract(),
        effective_for_stored,
        warnings,
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
    let previous = app.state_store.snapshot()?.global_enabled;
    app.state_store.set_global_enabled(req.enabled)?;
    if let Err(error) = app.maps.set_global_enabled(req.enabled) {
        if let Err(rollback_error) = app.state_store.set_global_enabled(previous) {
            warn!(
                error = %rollback_error,
                "failed to rollback persisted global enabled after map apply failure"
            );
            return Err(ApiError::StateStore(rollback_error));
        }
        return Err(ApiError::Map(error));
    }
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

/// Marks or unmarks a tenant as essential for adaptive auto-throttling exclusion.
///
/// # Errors
///
/// Returns `ApiError` when tenant parsing or tenancy updates fail.
pub(crate) async fn put_tenant_essential(
    Path(tenant): Path<String>,
    State(app): State<AppState>,
    Json(req): Json<PutEssentialRequest>,
) -> Result<Json<EssentialTenantResponse>, ApiError> {
    let cgroup_id = parse_tenant_cgroup_id(&tenant)?;
    let previous = app
        .state_store
        .snapshot()?
        .essential_tenants
        .contains(&cgroup_id);
    let _ = app
        .state_store
        .set_essential_tenant(cgroup_id, req.essential)?;
    if let Err(error) = app.tenancy.set_essential(cgroup_id, req.essential) {
        if let Err(rollback_error) = app.state_store.set_essential_tenant(cgroup_id, previous) {
            warn!(
                tenant = cgroup_id,
                error = %rollback_error,
                "failed to rollback persisted essential flag after tenancy apply failure"
            );
            return Err(ApiError::StateStore(rollback_error));
        }
        return Err(ApiError::Tenancy(error));
    }

    Ok(Json(EssentialTenantResponse {
        tenant: cgroup_id,
        essential: req.essential,
    }))
}

/// Returns whether a tenant is currently marked essential.
///
/// # Errors
///
/// Returns `ApiError` when tenant parsing or tenancy lookups fail.
pub(crate) async fn tenant_essential(
    Path(tenant): Path<String>,
    State(app): State<AppState>,
) -> Result<Json<EssentialTenantResponse>, ApiError> {
    let cgroup_id = parse_tenant_cgroup_id(&tenant)?;
    let essential = app.tenancy.is_essential(cgroup_id)?;
    Ok(Json(EssentialTenantResponse {
        tenant: cgroup_id,
        essential,
    }))
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
    let tenant = TenantRef::parse(&tenant)?
        .with_flow(proto, query.dst_port)?
        .with_http_selectors(
            query.http_method.as_deref(),
            query.http_path.as_deref(),
            query.http_path_hash,
        )?
        .to_tenant_key();
    let maps = app.maps;
    let deleted = maps.get_policy(tenant)?.is_some();
    let previous = app.state_store.delete_base_policy(tenant)?;
    if let Err(error) = maps.delete_policy(tenant) {
        if let Some(previous_policy) = previous
            && let Err(rollback_error) = app.state_store.upsert_base_policy(tenant, previous_policy)
        {
            warn!(
                tenant = ?tenant,
                error = %rollback_error,
                "failed to rollback persisted base policy after map delete failure"
            );
            return Err(ApiError::StateStore(rollback_error));
        }
        return Err(ApiError::Map(error));
    }
    let effective_after_delete = maps.resolve_policy(tenant)?;

    Ok(Json(PolicyDeleteResponse {
        deleted,
        deleted_key: tenant,
        deleted_selector: SelectorView::from_tenant(tenant),
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
    let requested = TenantRef::parse(&tenant)?
        .with_flow(proto, query.dst_port)?
        .with_http_selectors(
            query.http_method.as_deref(),
            query.http_path.as_deref(),
            query.http_path_hash,
        )?
        .to_tenant_key();
    let effective = app.maps.resolve_policy(requested)?;

    Ok(Json(ResolvePolicyResponse {
        requested,
        requested_selector: SelectorView::from_tenant(requested),
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
    let system_memory_percent = sample_memory_percent_async().await?;
    let adaptive = app.adaptive_runtime.snapshot();
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
        system_memory_percent,
        adaptive_state: adaptive.state,
        adaptive_high_watermark_percent: app.config.adaptive.high_watermark_percent,
        adaptive_low_watermark_percent: app.config.adaptive.low_watermark_percent,
        adaptive_managed_override_count: adaptive.active_override_count,
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

fn parse_tenant_cgroup_id(raw: &str) -> Result<u64, TenantParseError> {
    let tenant = TenantRef::parse(raw)?;
    Ok(tenant.to_tenant_key().cgroup_id)
}

const fn policy_precedence_contract() -> &'static str {
    "runtime_override:[exact(cgroup_id,proto,dst_port,http_method,http_path_hash) > path_wildcard(cgroup_id,proto,dst_port,http_method,0) > method_path_wildcard(cgroup_id,proto,dst_port,0,0) > port_method_path_wildcard(cgroup_id,proto,0,0,0) > full_wildcard(cgroup_id,0,0,0,0)] > base:[exact(cgroup_id,proto,dst_port,http_method,http_path_hash) > path_wildcard(cgroup_id,proto,dst_port,http_method,0) > method_path_wildcard(cgroup_id,proto,dst_port,0,0) > port_method_path_wildcard(cgroup_id,proto,0,0,0) > full_wildcard(cgroup_id,0,0,0,0)]"
}

const PARTIAL_L7_POLICY_WARNING: &str = "partial L7 policy accepted with wildcard L4 selectors; set proto and dst_port for strict specificity";

const fn partial_l7_policy_key(key: TenantKey) -> bool {
    let has_l7_selector = key.http_method != 0 || key.http_path_hash != 0;
    has_l7_selector && (key.proto == 0 || key.dst_port == 0)
}

const fn policy_scope_from_key(key: TenantKey) -> PolicyMatchLevel {
    if key.proto == 0 {
        return PolicyMatchLevel::FullWildcard;
    }

    if key.dst_port == 0 {
        return PolicyMatchLevel::PortMethodPathWildcard;
    }

    if key.http_method == 0 {
        return PolicyMatchLevel::MethodPathWildcard;
    }

    if key.http_path_hash == 0 {
        return PolicyMatchLevel::PathWildcard;
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
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode},
        routing::{get, put},
    };
    use prometheus::{IntCounter, IntGauge, Registry};
    use tower::util::ServiceExt as _;
    use vantage_common::{
        Counters, GlobalConfig, GlobalStats, KERNEL_DROP_EVENT_SAMPLE_EVERY, Policy, ReasonBuckets,
        TenantKey,
    };

    use super::{
        PARTIAL_L7_POLICY_WARNING, build_top_tenants, debug_cpu_window, debug_snapshot,
        delete_policy, get_admin_enabled, metrics, put_admin_enabled, put_policy,
        put_tenant_essential, resolve_policy, tenant_essential,
    };
    use crate::{
        AppState, DropEventRuntime, MetricsState,
        adaptive::AdaptiveRuntimeState,
        config::{Config, PolicyValidationMode},
        map_client::{MapClient, MapError, MapOps},
        state_store::{StateStore, StateStoreDefaults},
        tenancy::TenancyState,
        tenant::compute_http_path_hash,
    };

    struct InMemoryMapOps {
        policies: Mutex<BTreeMap<TenantKey, Policy>>,
        runtime_policies: Mutex<BTreeMap<TenantKey, Policy>>,
        counters: Vec<(TenantKey, Counters)>,
        global_stats: GlobalStats,
        global_enabled: Mutex<bool>,
        flow_keys_live: Mutex<bool>,
    }

    impl InMemoryMapOps {
        fn new() -> Self {
            Self {
                policies: Mutex::new(BTreeMap::new()),
                runtime_policies: Mutex::new(BTreeMap::new()),
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

        fn upsert_runtime_policy(&self, tenant: TenantKey, policy: Policy) -> Result<(), MapError> {
            self.runtime_policies
                .lock()
                .map_err(|_| MapError::LockPoisoned)?
                .insert(tenant, policy);
            Ok(())
        }

        fn delete_runtime_policy(&self, tenant: TenantKey) -> Result<(), MapError> {
            self.runtime_policies
                .lock()
                .map_err(|_| MapError::LockPoisoned)?
                .remove(&tenant);
            Ok(())
        }

        fn get_runtime_policy(&self, tenant: TenantKey) -> Result<Option<Policy>, MapError> {
            let policy = self
                .runtime_policies
                .lock()
                .map_err(|_| MapError::LockPoisoned)?
                .get(&tenant)
                .copied();
            Ok(policy)
        }

        fn collect_policy_keys(&self) -> Result<Vec<TenantKey>, MapError> {
            let policies = self.policies.lock().map_err(|_| MapError::LockPoisoned)?;
            Ok(policies.keys().copied().collect())
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
        let partial_metric = IntCounter::new(
            "vantage_partial_l7_policy_keys_total",
            "Total number of policy upserts with L7 selectors and wildcard L4 selectors",
        );
        let Ok(partial_l7_policy_keys_total) = partial_metric else {
            panic!("metric should initialize");
        };
        let register_partial = registry.register(Box::new(partial_l7_policy_keys_total.clone()));
        assert!(
            register_partial.is_ok(),
            "partial-l7 metric registration should succeed"
        );
        let state_store = test_state_store("control_api_state");

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
                policy_validation_mode: PolicyValidationMode::Permissive,
                adaptive: crate::config::AdaptiveConfig {
                    enabled: false,
                    high_watermark_percent: 90,
                    low_watermark_percent: 80,
                    tick_ms: 1_000,
                    throttle_rate_tokens_per_sec: 100,
                    throttle_burst_tokens: 500,
                },
                essential_tenants: std::collections::BTreeSet::new(),
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
                partial_l7_policy_keys_total,
            },
            state_store,
            tenancy: TenancyState::default(),
            adaptive_runtime: AdaptiveRuntimeState::default(),
        }
    }

    fn test_state_store(name: &str) -> StateStore {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0_u128, |duration| duration.as_nanos());
        let path: PathBuf = std::env::temp_dir().join(format!(
            "vantage_{name}_{}_{}.json",
            std::process::id(),
            stamp
        ));
        let defaults = StateStoreDefaults::default();
        let loaded = StateStore::load_or_init(path, &defaults);
        let Ok(store) = loaded else {
            panic!("state store should initialize for tests");
        };
        store
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
            runtime_policies: Mutex::new(BTreeMap::new()),
            counters: vec![
                (
                    TenantKey {
                        cgroup_id: 167_838_211,
                        http_path_hash: 0,
                        dst_port: 443,
                        proto: 6,
                        http_method: 0,
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
                        cgroup_id: 167_838_212,
                        http_path_hash: 0,
                        dst_port: 53,
                        proto: 17,
                        http_method: 0,
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
        assert_eq!(payload["version"], serde_json::json!(3));
        assert!(payload["ts_unix_ms"].as_u64().is_some());
        assert!(payload["cpu"]["window_ms"].as_u64().is_some());
        assert!(payload["cpu"]["system_cpu_percent"].as_f64().is_some());
        assert!(payload["cpu"]["daemon_cpu_percent"].as_f64().is_some());
        assert!(payload["system_memory_percent"].as_f64().is_some());
        assert_eq!(payload["adaptive_state"], serde_json::json!("inactive"));
        assert_eq!(
            payload["adaptive_high_watermark_percent"],
            serde_json::json!(90)
        );
        assert_eq!(
            payload["adaptive_low_watermark_percent"],
            serde_json::json!(80)
        );
        assert_eq!(
            payload["adaptive_managed_override_count"],
            serde_json::json!(0)
        );
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
            runtime_policies: Mutex::new(BTreeMap::new()),
            counters: vec![(
                TenantKey {
                    cgroup_id: 167_838_211,
                    http_path_hash: 0,
                    dst_port: 443,
                    proto: 6,
                    http_method: 0,
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
            serde_json::json!(super::policy_precedence_contract())
        );
        assert_eq!(payload["scope"], serde_json::json!("full_wildcard"));
        assert_eq!(
            payload["effective_for_stored"]["match_level"],
            serde_json::json!("exact")
        );
        assert_eq!(
            payload["stored_selector"]["normalized"],
            serde_json::json!("cgroup=42|proto=*|dport=*|method=*|path_hash=*")
        );
        assert_eq!(
            payload["stored_selector"]["http_path_hash"],
            serde_json::json!(null)
        );
        assert_eq!(payload["warnings"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn put_policy_accepts_canonical_cgroup_tenant() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/cg:167838211")
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
    async fn put_policy_accepts_bare_cgroup_id_tenant() {
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
            .uri("/policy/cg:167838211")
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
                    cgroup_id: 167_838_211,
                    http_path_hash: 0,
                    dst_port: 443,
                    proto: 6,
                    http_method: 0,
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
            .uri("/policy/cg:167838211")
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
        let read = to_bytes(resp.into_body(), usize::MAX).await;
        let Ok(bytes) = read else {
            panic!("response body should be readable");
        };
        let parsed = serde_json::from_slice::<serde_json::Value>(&bytes);
        let Ok(payload) = parsed else {
            panic!("response should be valid JSON");
        };
        assert_eq!(
            payload["stored_selector"]["http_path_hash"],
            serde_json::json!(compute_http_path_hash("/predict"))
        );
        assert_eq!(
            payload["stored_selector"]["http_path_hash_hex"],
            serde_json::json!(format!("{:#010x}", compute_http_path_hash("/predict")))
        );
        assert_eq!(
            payload["stored_selector"]["http_method"],
            serde_json::json!("*")
        );

        match fixture.policies.lock() {
            Ok(policies) => {
                let tenant = TenantKey {
                    cgroup_id: 167_838_211,
                    http_path_hash: compute_http_path_hash("/predict"),
                    dst_port: 443,
                    proto: 6,
                    http_method: 0,
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
    async fn put_policy_accepts_http_method_and_path_selectors() {
        let fixture = Arc::new(InMemoryMapOps::new());
        let maps = MapClient::from_ops(Arc::clone(&fixture) as Arc<dyn MapOps>);
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/cg:167838211")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true,"proto":"tcp","dst_port":443,"http_method":"post","http_path":"/predict"}"#,
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
            payload["stored_selector"]["http_path_hash"],
            serde_json::json!(compute_http_path_hash("/predict"))
        );
        assert_eq!(
            payload["stored_selector"]["http_path_hash_hex"],
            serde_json::json!(format!("{:#010x}", compute_http_path_hash("/predict")))
        );
        assert_eq!(
            payload["stored_selector"]["http_method"],
            serde_json::json!("post")
        );

        match fixture.policies.lock() {
            Ok(policies) => {
                let tenant = TenantKey {
                    cgroup_id: 167_838_211,
                    http_path_hash: compute_http_path_hash("/predict"),
                    dst_port: 443,
                    proto: 6,
                    http_method: 2,
                };
                assert!(
                    policies.contains_key(&tenant),
                    "policy key should include normalized http method and path hash selectors"
                );
            }
            Err(error) => {
                panic!("fixture lock should not be poisoned: {error}");
            }
        }
    }

    #[tokio::test]
    async fn put_policy_response_reports_runtime_override_as_effective() {
        let fixture = Arc::new(InMemoryMapOps::new());
        let tenant = TenantKey {
            cgroup_id: 167_838_211,
            http_path_hash: 0,
            dst_port: 0,
            proto: 0,
            http_method: 0,
        };
        {
            let Ok(mut runtime_policies) = fixture.runtime_policies.lock() else {
                panic!("fixture lock should not be poisoned");
            };
            runtime_policies.insert(
                tenant,
                Policy {
                    rate_tokens_per_sec: 10,
                    burst_tokens: 5,
                    enabled: 1,
                    _pad: [0; 7],
                },
            );
        }

        let maps = MapClient::from_ops(Arc::clone(&fixture) as Arc<dyn MapOps>);
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/cg:167838211")
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
            payload["effective_for_stored"]["source"],
            serde_json::json!("runtime_override")
        );
        assert_eq!(
            payload["effective_for_stored"]["policy"]["rate_tokens_per_sec"],
            serde_json::json!(10)
        );
    }

    #[tokio::test]
    async fn put_policy_warns_on_partial_l7_in_permissive_mode() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/cg:167838211")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true,"http_path":"/predict"}"#,
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
            payload["warnings"],
            serde_json::json!([PARTIAL_L7_POLICY_WARNING])
        );
    }

    #[tokio::test]
    async fn put_policy_rejects_partial_l7_in_strict_mode() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let mut state = test_state(maps);
        state.config.policy_validation_mode = PolicyValidationMode::Strict;
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(state);

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/cg:167838211")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true,"http_path":"/predict"}"#,
            ));
        let Ok(request) = req else {
            panic!("request should build");
        };

        let resp = match app.oneshot(request).await {
            Ok(resp) => resp,
            Err(error) => match error {},
        };
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let read = to_bytes(resp.into_body(), usize::MAX).await;
        let Ok(bytes) = read else {
            panic!("response body should be readable");
        };
        let text = String::from_utf8(bytes.to_vec());
        let Ok(text) = text else {
            panic!("error payload should be utf-8");
        };
        assert!(text.contains("http selectors require both proto and dst_port"));
    }

    #[tokio::test]
    async fn put_policy_rejects_mismatched_http_path_and_hash() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/cg:167838211")
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
    async fn put_policy_rejects_invalid_http_method() {
        let maps = MapClient::from_ops(Arc::new(InMemoryMapOps::new()));
        let app = Router::new()
            .route("/policy/:tenant", put(put_policy).delete(delete_policy))
            .with_state(test_state(maps));

        let req = Request::builder()
            .method("PUT")
            .uri("/policy/cg:167838211")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"rate_tokens_per_sec":100,"burst_tokens":50,"enabled":true,"proto":"tcp","dst_port":443,"http_method":"trace"}"#,
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
            .uri("/policy/cg:167838211")
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
            .uri("/policy/cg:167838211")
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
            .uri("/policy/cg:167838211")
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
            .uri("/policy/cg:167838211")
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
            .uri("/policy/cg:167838211?proto=tcp&dst_port=443")
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
            .uri("/policy/cg:167838211?proto=udp")
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
            .uri("/policy/cg:167838211")
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
            .uri("/policy/cg:167838211/resolve?proto=tcp&dst_port=443")
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
            serde_json::json!("port_method_path_wildcard")
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
            serde_json::json!("cgroup=167838211|proto=tcp|dport=443|method=*|path_hash=*")
        );
    }

    #[test]
    fn build_top_tenants_applies_ordering_and_limit() {
        let counters = vec![
            (
                TenantKey {
                    cgroup_id: 2,
                    http_path_hash: 0,
                    dst_port: 80,
                    proto: 6,
                    http_method: 0,
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
                    cgroup_id: 1,
                    http_path_hash: 0,
                    dst_port: 80,
                    proto: 6,
                    http_method: 0,
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
                    cgroup_id: 3,
                    http_path_hash: 0,
                    dst_port: 80,
                    proto: 6,
                    http_method: 0,
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
        assert_eq!(top[0].tenant.cgroup_id, 1);
        assert_eq!(top[1].tenant.cgroup_id, 2);
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
        assert!(
            text.contains("flow=\"cgroup=167838211|proto=tcp|dport=443|method=*|path_hash=*\"")
        );
        assert!(text.contains("cgroup_id=\"167838211\""));
        assert!(text.contains("http_method=\"*\""));
        assert!(text.contains("http_path_hash=\"*\""));
    }

    #[tokio::test]
    async fn tenancy_endpoint_defaults_to_non_essential() {
        let state = test_state(MapClient::from_ops(Arc::new(InMemoryMapOps::new())));
        let app = Router::new()
            .route("/tenancy/:tenant/essential", get(tenant_essential))
            .with_state(state);

        let request = Request::builder()
            .method("GET")
            .uri("/tenancy/cg:42/essential")
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("request should build: {error}"));
        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|error| match error {});
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|error| panic!("response body should be readable: {error}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("response should be valid json: {error}"));
        assert_eq!(payload["tenant"], serde_json::json!(42));
        assert_eq!(payload["essential"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn tenancy_endpoint_can_mark_essential() {
        let state = test_state(MapClient::from_ops(Arc::new(InMemoryMapOps::new())));
        let app = Router::new()
            .route(
                "/tenancy/:tenant/essential",
                put(put_tenant_essential).get(tenant_essential),
            )
            .with_state(state);

        let request = Request::builder()
            .method("PUT")
            .uri("/tenancy/99/essential")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"essential":true}"#))
            .unwrap_or_else(|error| panic!("request should build: {error}"));
        let response = app
            .clone()
            .oneshot(request)
            .await
            .unwrap_or_else(|error| match error {});
        assert_eq!(response.status(), StatusCode::OK);

        let read_back = Request::builder()
            .method("GET")
            .uri("/tenancy/99/essential")
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("request should build: {error}"));
        let response = app
            .oneshot(read_back)
            .await
            .unwrap_or_else(|error| match error {});
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|error| panic!("response body should be readable: {error}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("response should be valid json: {error}"));
        assert_eq!(payload["tenant"], serde_json::json!(99));
        assert_eq!(payload["essential"], serde_json::json!(true));
    }
}
