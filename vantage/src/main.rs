pub mod adaptive;
pub mod config;
pub mod control_api;
pub mod events;
pub mod map_client;
pub mod metrics;
pub mod prereqs;
pub mod state_store;
pub mod tenancy;
pub mod tenant;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, put},
};
use aya::{
    Ebpf,
    programs::{SchedClassifier, TcAttachType, tc},
    util::KernelVersion,
};
use prometheus::{IntCounter, IntGauge, Registry};
use serde::Serialize;
use thiserror::Error;
use tokio::{
    signal,
    sync::watch,
    task::JoinHandle,
    time::{MissedTickBehavior, interval},
};
use tracing::{info, warn};
use vantage_common::{KERNEL_DROP_EVENT_SAMPLE_EVERY, Policy, TenantKey};

use crate::{
    adaptive::{AdaptiveRuntimeState, spawn_adaptive_controller},
    config::Config,
    control_api::{
        debug_cpu_window, debug_snapshot, delete_policy, delete_runtime_policy, get_admin_enabled,
        get_policy_list, get_runtime_policy_list, metrics, put_admin_enabled, put_policy,
        put_runtime_policy, put_tenant_essential, resolve_policy, tenant_essential,
    },
    events::{RingBufferHandle, spawn_drop_event_consumer, take_drop_event_ring},
    map_client::{MapClient, MapError},
    prereqs::ensure_cgroup_v2_mounted,
    tenancy::TenancyState,
};

#[derive(Clone)]
pub(crate) struct MetricsState {
    pub(crate) registry: Registry,
    pub(crate) daemon_up: IntGauge,
    pub(crate) partial_l7_policy_keys_total: IntCounter,
    pub(crate) reconcile_failures_total: IntCounter,
}

#[derive(Clone)]
pub struct AppState {
    pub(crate) config: Config,
    pub(crate) drop_events: DropEventRuntime,
    pub(crate) maps: MapClient,
    pub(crate) metrics: MetricsState,
    pub(crate) state_store: state_store::StateStore,
    pub(crate) tenancy: TenancyState,
    pub(crate) adaptive_runtime: AdaptiveRuntimeState,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct DropEventRuntime {
    pub(crate) kernel_sample_every: u64,
    pub(crate) log_sample_n: u32,
    pub(crate) log_enabled: bool,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    iface: String,
    direction: &'static str,
    cpu_window_ms: u64,
    metrics_dimensional_enabled: bool,
    flow_keys_live: bool,
    debug_top_tenants: usize,
    adaptive_enabled: bool,
    adaptive_high_watermark_percent: u8,
    adaptive_low_watermark_percent: u8,
    adaptive_tick_ms: u64,
    adaptive_throttle_rate_tokens_per_sec: u64,
    adaptive_throttle_burst_tokens: u64,
    drop_events: DropEventRuntime,
}

#[derive(Debug, Error)]
pub(crate) enum AppError {
    #[error(transparent)]
    Runtime(#[from] anyhow::Error),
    #[error(transparent)]
    StateStore(#[from] state_store::StateStoreError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = self.to_string();
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config = Config::from_args();
    run(config).await.map_err(anyhow::Error::new)?;
    Ok(())
}

pub(crate) async fn run(config: Config) -> Result<(), AppError> {
    setup_memlock_compatibility();
    ensure_cgroup_v2_mounted().context(
        "host prerequisite check failed: cgroup-v2 must be mounted before starting vantage",
    )?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/vantage"
    )))
    .context("failed to load embedded eBPF object")?;

    attach_tc(&mut ebpf, &config)?;

    let drop_event_ring: Option<RingBufferHandle> = if config.drop_event_log_enabled {
        Some(take_drop_event_ring(&mut ebpf).context("failed to acquire DROP_EVENTS map")?)
    } else {
        None
    };

    let state = build_app_state(&config, ebpf)?;
    let initial_reconciled_revision = reconcile_once(&state)
        .context("failed to complete startup reconcile before serving traffic")?;
    if let Some(ring_buf) = drop_event_ring {
        spawn_drop_event_consumer(
            ring_buf,
            shutdown_rx.clone(),
            config.drop_event_log_sample_n,
        );
    }
    let reconcile_task = spawn_reconcile_controller(
        state.clone(),
        shutdown_rx.clone(),
        initial_reconciled_revision,
        config.reconcile_tick_ms,
        config.reconcile_deep_check_every_n,
    );
    let app = build_router(state.clone());
    let flow_keys_live = state
        .maps
        .get_flow_keys_live()
        .context("failed to read flow-keys mode from GLOBAL_CONFIG_MAP startup state")?;
    let adaptive_task = if config.adaptive.enabled {
        Some(spawn_adaptive_controller(
            state.clone(),
            shutdown_rx.clone(),
        ))
    } else {
        None
    };

    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind HTTP server on {}", config.bind_addr))?;
    info!(
        bind_addr = %config.bind_addr,
        iface = %config.iface,
        direction = %direction_name(&config),
        cpu_window_ms = config.cpu_window_ms,
        drop_event_log_enabled = config.drop_event_log_enabled,
        drop_event_log_sample_n = config.drop_event_log_sample_n,
        metrics_dimensional_enabled = config.metrics_dimensions.enabled(),
        flow_keys_live,
        debug_top_tenants = config.debug_top_tenants,
        adaptive_enabled = config.adaptive.enabled,
        adaptive_high_watermark_percent = config.adaptive.high_watermark_percent,
        adaptive_low_watermark_percent = config.adaptive.low_watermark_percent,
        adaptive_tick_ms = config.adaptive.tick_ms,
        adaptive_throttle_rate_tokens_per_sec = config.adaptive.throttle_rate_tokens_per_sec,
        adaptive_throttle_burst_tokens = config.adaptive.throttle_burst_tokens,
        reconcile_tick_ms = config.reconcile_tick_ms,
        reconcile_deep_check_every_n = config.reconcile_deep_check_every_n,
        state_file_path = %config.state_file_path.display(),
        kernel_drop_event_sample_every = KERNEL_DROP_EVENT_SAMPLE_EVERY,
        "vantage daemon started"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown_tx))
        .await
        .context("HTTP server exited with error")?;

    if let Some(task) = adaptive_task {
        let joined = task.await;
        if let Err(error) = joined {
            warn!(%error, "adaptive controller task exited unexpectedly");
        }
    }
    let reconcile_joined = reconcile_task.await;
    if let Err(error) = reconcile_joined {
        warn!(%error, "reconcile controller task exited unexpectedly");
    }

    Ok(())
}

fn build_app_state(config: &Config, ebpf: Ebpf) -> Result<AppState, AppError> {
    let metrics_state = build_metrics_state()?;
    let drop_events = DropEventRuntime {
        kernel_sample_every: KERNEL_DROP_EVENT_SAMPLE_EVERY,
        log_sample_n: config.drop_event_log_sample_n,
        log_enabled: config.drop_event_log_enabled,
    };
    let global_seed = config.global_config_seed();
    let defaults = state_store::StateStoreDefaults {
        global_enabled: global_seed.enabled,
        flow_keys_live: global_seed.flow_keys_live,
        essential_tenants: config.essential_tenants.clone(),
    };
    let state_store = state_store::StateStore::load_or_init(&config.state_file_path, &defaults)?;
    let snapshot = state_store.snapshot()?;
    let maps = MapClient::new(Arc::new(std::sync::Mutex::new(ebpf)));
    maps.seed_global_config(
        config::GlobalConfigSeed {
            enabled: snapshot.global_enabled,
            flow_keys_live: snapshot.flow_keys_live,
        }
        .as_global_config(),
    )
    .context("failed to seed GLOBAL_CONFIG_MAP startup state")?;

    Ok(AppState {
        config: config.clone(),
        drop_events,
        maps,
        metrics: metrics_state,
        state_store,
        tenancy: TenancyState::new(snapshot.essential_tenants),
        adaptive_runtime: AdaptiveRuntimeState::default(),
    })
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/policy", get(get_policy_list))
        .route("/policy/:tenant", put(put_policy).delete(delete_policy))
        .route("/runtime-policy", get(get_runtime_policy_list))
        .route(
            "/runtime-policy/:tenant",
            put(put_runtime_policy).delete(delete_runtime_policy),
        )
        .route("/policy/:tenant/resolve", get(resolve_policy))
        .route(
            "/tenancy/:tenant/essential",
            put(put_tenant_essential).get(tenant_essential),
        )
        .route(
            "/admin/enabled",
            put(put_admin_enabled).get(get_admin_enabled),
        )
        .route("/metrics", get(metrics))
        .route("/debug/cpu-window", get(debug_cpu_window))
        .route("/debug/snapshot", get(debug_snapshot))
        .with_state(state)
}

fn reconcile_once(app: &AppState) -> anyhow::Result<u64> {
    let (snapshot, snapshot_revision) = app
        .state_store
        .snapshot_with_revision()
        .context("failed to capture persisted state snapshot for reconcile")?;

    let global_enabled = app
        .maps
        .get_global_enabled()
        .context("failed to read GLOBAL_CONFIG_MAP enabled state for reconcile")?;
    let flow_keys_live = app
        .maps
        .get_flow_keys_live()
        .context("failed to read GLOBAL_CONFIG_MAP flow-keys state for reconcile")?;
    if global_enabled != snapshot.global_enabled || flow_keys_live != snapshot.flow_keys_live {
        app.maps
            .seed_global_config(
                config::GlobalConfigSeed {
                    enabled: snapshot.global_enabled,
                    flow_keys_live: snapshot.flow_keys_live,
                }
                .as_global_config(),
            )
            .context("failed to reconcile GLOBAL_CONFIG_MAP from persisted state")?;
    }

    let desired_base = snapshot.base_policies;
    let mut desired_runtime = BTreeMap::new();
    for (&tenant, record) in &snapshot.runtime_overrides {
        desired_runtime.insert(tenant, record.policy);
    }

    let base_keys = app
        .maps
        .collect_policy_keys()
        .context("failed to collect base policy keys for reconcile")?;
    reconcile_policy_map(
        &desired_base,
        base_keys,
        |tenant| app.maps.get_policy(tenant),
        |entries| app.maps.upsert_policies_batch(entries),
        |tenants| app.maps.delete_policies_batch(tenants),
    )
    .context("failed to reconcile POLICY_MAP from persisted state")?;

    let runtime_keys = app
        .maps
        .collect_runtime_policy_keys()
        .context("failed to collect runtime policy keys for reconcile")?;
    reconcile_policy_map(
        &desired_runtime,
        runtime_keys,
        |tenant| app.maps.get_runtime_policy(tenant),
        |entries| app.maps.upsert_runtime_policies_batch(entries),
        |tenants| app.maps.delete_runtime_policies_batch(tenants),
    )
    .context("failed to reconcile RUNTIME_POLICY_MAP from persisted state")?;

    Ok(snapshot_revision)
}

fn reconcile_policy_map<FGet, FUpsert, FDelete>(
    desired: &BTreeMap<TenantKey, Policy>,
    current_keys: Vec<TenantKey>,
    mut get_policy: FGet,
    upsert_policies_batch: FUpsert,
    delete_policies_batch: FDelete,
) -> Result<(), MapError>
where
    FGet: FnMut(TenantKey) -> Result<Option<Policy>, MapError>,
    FUpsert: FnOnce(&[(TenantKey, Policy)]) -> Result<(), MapError>,
    FDelete: FnOnce(&[TenantKey]) -> Result<(), MapError>,
{
    let current_set: BTreeSet<_> = current_keys.into_iter().collect();
    let mut to_upsert = Vec::new();
    for (&tenant, &policy) in desired {
        let needs_upsert = if current_set.contains(&tenant) {
            get_policy(tenant)? != Some(policy)
        } else {
            true
        };
        if needs_upsert {
            to_upsert.push((tenant, policy));
        }
    }

    let mut to_delete = Vec::new();
    for tenant in current_set {
        if !desired.contains_key(&tenant) {
            to_delete.push(tenant);
        }
    }

    if !to_upsert.is_empty() {
        upsert_policies_batch(&to_upsert)?;
    }
    if !to_delete.is_empty() {
        delete_policies_batch(&to_delete)?;
    }

    Ok(())
}

fn spawn_reconcile_controller(
    app: AppState,
    mut shutdown_rx: watch::Receiver<bool>,
    initial_reconciled_revision: u64,
    reconcile_tick_ms: u64,
    reconcile_deep_check_every_n: u64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let tick = Duration::from_millis(reconcile_tick_ms.max(100));
        let deep_check_every = reconcile_deep_check_every_n.max(1);
        let mut ticker = interval(tick);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut tick_index = 0_u64;
        let mut last_reconciled_revision = initial_reconciled_revision;

        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    match changed {
                        Ok(()) if *shutdown_rx.borrow() => break,
                        Ok(()) => {}
                        Err(_) => break,
                    }
                }
                _ = ticker.tick() => {
                    tick_index = tick_index.saturating_add(1);
                    let current_revision = app.state_store.revision();
                    if !should_reconcile_tick(
                        current_revision,
                        last_reconciled_revision,
                        tick_index,
                        deep_check_every,
                    ) {
                        continue;
                    }
                    let deep_check_due = tick_index.is_multiple_of(deep_check_every);

                    match reconcile_once(&app) {
                        Ok(reconciled_revision) => {
                            last_reconciled_revision = reconciled_revision;
                        }
                        Err(error) => {
                            app.metrics.reconcile_failures_total.inc();
                            warn!(
                                error = %error,
                                tick_index,
                                deep_check_due,
                                "reconcile tick failed; retaining prior state and retrying next tick"
                            );
                        }
                    }
                }
            }
        }
    })
}

const fn should_reconcile_tick(
    current_revision: u64,
    last_reconciled_revision: u64,
    tick_index: u64,
    deep_check_every: u64,
) -> bool {
    current_revision != last_reconciled_revision || tick_index.is_multiple_of(deep_check_every)
}

fn setup_memlock_compatibility() {
    match KernelVersion::current() {
        Ok(current) if current < KernelVersion::new(5, 11, 0) => {
            info!(
                kernel_version = %current,
                "kernel may require RLIMIT_MEMLOCK adjustment; Aya will auto-retry with raised memlock on EPERM"
            );
        }
        Ok(_) => {}
        Err(error) => {
            warn!(
                error = %error,
                "failed to detect kernel version for memlock compatibility path"
            );
        }
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .compact()
        .init();
}

fn attach_tc(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<()> {
    if let Err(error) = tc::qdisc_add_clsact(&config.iface) {
        warn!(%error, iface = %config.iface, "unable to add clsact qdisc; continuing");
    }

    let program: &mut SchedClassifier = ebpf
        .program_mut("vantage_tc")
        .context("program 'vantage_tc' not found in eBPF object")?
        .try_into()
        .context("program 'vantage_tc' is not a tc classifier")?;

    program.load().context("failed to load tc classifier")?;

    if !config.attach_ingress && !config.attach_egress {
        anyhow::bail!("at least one tc attach direction must be enabled");
    }

    if config.attach_ingress {
        program
            .attach(&config.iface, TcAttachType::Ingress)
            .with_context(|| format!("failed to attach tc ingress on {}", config.iface))?;
    }

    if config.attach_egress {
        program
            .attach(&config.iface, TcAttachType::Egress)
            .with_context(|| format!("failed to attach tc egress on {}", config.iface))?;
    }

    Ok(())
}

fn build_metrics_state() -> anyhow::Result<MetricsState> {
    let registry = Registry::new();
    let daemon_up = IntGauge::new("vantage_daemon_up", "Daemon running state")?;
    daemon_up.set(1);
    registry.register(Box::new(daemon_up.clone()))?;
    let partial_l7_policy_keys_total = IntCounter::new(
        "vantage_partial_l7_policy_keys_total",
        "Total number of policy upserts with L7 selectors and wildcard L4 selectors",
    )?;
    registry.register(Box::new(partial_l7_policy_keys_total.clone()))?;
    let reconcile_failures_total = IntCounter::new(
        "vantage_reconcile_failures_total",
        "Total number of non-fatal reconcile tick failures",
    )?;
    registry.register(Box::new(reconcile_failures_total.clone()))?;

    Ok(MetricsState {
        registry,
        daemon_up,
        partial_l7_policy_keys_total,
        reconcile_failures_total,
    })
}

const fn direction_name(config: &Config) -> &'static str {
    match (config.attach_ingress, config.attach_egress) {
        (true, true) => "both",
        (true, false) => "ingress",
        (false, true) => "egress",
        (false, false) => "none",
    }
}

async fn healthz(State(state): State<AppState>) -> Json<HealthResponse> {
    let flow_keys_live = match state.maps.get_flow_keys_live() {
        Ok(flow_keys_live) => flow_keys_live,
        Err(error) => {
            warn!(
                error = %error,
                "failed to read live flow-keys mode for healthz; falling back to config value"
            );
            state.config.flow_keys_mode.live()
        }
    };
    Json(HealthResponse {
        status: "ok",
        iface: state.config.iface.clone(),
        direction: direction_name(&state.config),
        cpu_window_ms: state.config.cpu_window_ms,
        metrics_dimensional_enabled: state.config.metrics_dimensions.enabled(),
        flow_keys_live,
        debug_top_tenants: state.config.debug_top_tenants,
        adaptive_enabled: state.config.adaptive.enabled,
        adaptive_high_watermark_percent: state.config.adaptive.high_watermark_percent,
        adaptive_low_watermark_percent: state.config.adaptive.low_watermark_percent,
        adaptive_tick_ms: state.config.adaptive.tick_ms,
        adaptive_throttle_rate_tokens_per_sec: state.config.adaptive.throttle_rate_tokens_per_sec,
        adaptive_throttle_burst_tokens: state.config.adaptive.throttle_burst_tokens,
        drop_events: state.drop_events,
    })
}

async fn shutdown_signal(shutdown_tx: watch::Sender<bool>) {
    if let Err(error) = signal::ctrl_c().await {
        warn!(%error, "failed to listen for shutdown signal");
        return;
    }

    if let Err(error) = shutdown_tx.send(true) {
        warn!(%error, "failed to notify drop-event consumer shutdown");
    }
    info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap, path::PathBuf, sync::Arc};

    use axum::extract::State;
    use aya::{
        Ebpf,
        programs::{SchedClassifier, TcAttachType, tc},
    };
    use prometheus::{IntCounter, IntGauge, Registry};
    use vantage_common::{
        Counters, GlobalConfig, GlobalStats, KERNEL_DROP_EVENT_SAMPLE_EVERY, Policy, ReasonBuckets,
        TenantKey,
    };

    use super::{AppState, DropEventRuntime, MetricsState, direction_name, healthz};
    use crate::{
        adaptive::AdaptiveRuntimeState,
        config::Config,
        map_client::{MapClient, MapError, MapOps},
        state_store::{StateStore, StateStoreDefaults},
        tenancy::TenancyState,
    };

    struct NoopMapOps {
        flow_keys_live: bool,
    }

    impl MapOps for NoopMapOps {
        fn upsert_policy(&self, _tenant: TenantKey, _policy: Policy) -> Result<(), MapError> {
            Ok(())
        }

        fn delete_policy(&self, _tenant: TenantKey) -> Result<(), MapError> {
            Ok(())
        }

        fn get_policy(&self, _tenant: TenantKey) -> Result<Option<Policy>, MapError> {
            Ok(None)
        }

        fn upsert_runtime_policy(
            &self,
            _tenant: TenantKey,
            _policy: Policy,
        ) -> Result<(), MapError> {
            Ok(())
        }

        fn delete_runtime_policy(&self, _tenant: TenantKey) -> Result<(), MapError> {
            Ok(())
        }

        fn get_runtime_policy(&self, _tenant: TenantKey) -> Result<Option<Policy>, MapError> {
            Ok(None)
        }

        fn collect_policy_keys(&self) -> Result<Vec<TenantKey>, MapError> {
            Ok(Vec::new())
        }

        fn collect_runtime_policy_keys(&self) -> Result<Vec<TenantKey>, MapError> {
            Ok(Vec::new())
        }

        fn collect_counters(&self) -> Result<Vec<(TenantKey, Counters)>, MapError> {
            Ok(Vec::new())
        }

        fn read_global_stats(&self) -> Result<GlobalStats, MapError> {
            Ok(GlobalStats {
                pass_pkts: 0,
                drop_pkts: 0,
                pass_bytes: 0,
                drop_bytes: 0,
                reasons: ReasonBuckets {
                    no_tokens: 0,
                    no_policy: 0,
                    parse_fail: 0,
                },
            })
        }

        fn seed_global_config(&self, _config: GlobalConfig) -> Result<(), MapError> {
            Ok(())
        }

        fn set_global_enabled(&self, _enabled: bool) -> Result<(), MapError> {
            Ok(())
        }

        fn get_global_enabled(&self) -> Result<bool, MapError> {
            Ok(true)
        }

        fn set_flow_keys_live(&self, _flow_keys_live: bool) -> Result<(), MapError> {
            Ok(())
        }

        fn get_flow_keys_live(&self) -> Result<bool, MapError> {
            Ok(self.flow_keys_live)
        }
    }

    fn test_state(config: Config, drop_events: DropEventRuntime) -> AppState {
        let registry = Registry::new();
        let metric = IntGauge::new("vantage_daemon_up", "Daemon running state");
        let Ok(daemon_up) = metric else {
            panic!("metric should initialize");
        };
        daemon_up.set(1);
        let register = registry.register(Box::new(daemon_up.clone()));
        assert!(register.is_ok(), "metric registration should succeed");
        let state_store = test_state_store("main_state");

        let flow_keys_live = config.flow_keys_mode.live();

        AppState {
            config,
            drop_events,
            maps: MapClient::from_ops(Arc::new(NoopMapOps { flow_keys_live })),
            metrics: MetricsState {
                registry,
                daemon_up,
                partial_l7_policy_keys_total: IntCounter::new(
                    "vantage_partial_l7_policy_keys_total",
                    "Total number of policy upserts with L7 selectors and wildcard L4 selectors",
                )
                .unwrap_or_else(|error| panic!("metric should initialize: {error}")),
                reconcile_failures_total: IntCounter::new(
                    "vantage_reconcile_failures_total",
                    "Total number of non-fatal reconcile tick failures",
                )
                .unwrap_or_else(|error| panic!("metric should initialize: {error}")),
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

    #[test]
    fn reconcile_policy_map_updates_only_missing_stale_and_extra_entries() {
        let key_missing = TenantKey {
            cgroup_id: 1,
            http_path_hash: 0,
            dst_port: 0,
            proto: 0,
            http_method: 0,
        };
        let key_stale = TenantKey {
            cgroup_id: 2,
            http_path_hash: 0,
            dst_port: 0,
            proto: 0,
            http_method: 0,
        };
        let key_same = TenantKey {
            cgroup_id: 3,
            http_path_hash: 0,
            dst_port: 0,
            proto: 0,
            http_method: 0,
        };
        let key_extra = TenantKey {
            cgroup_id: 4,
            http_path_hash: 0,
            dst_port: 0,
            proto: 0,
            http_method: 0,
        };
        let desired_policy = Policy {
            rate_tokens_per_sec: 10,
            burst_tokens: 10,
            enabled: 1,
            _pad: [0; 7],
        };
        let stale_policy = Policy {
            rate_tokens_per_sec: 1,
            burst_tokens: 1,
            enabled: 1,
            _pad: [0; 7],
        };

        let mut desired = BTreeMap::new();
        desired.insert(key_missing, desired_policy);
        desired.insert(key_stale, desired_policy);
        desired.insert(key_same, desired_policy);

        let current = RefCell::new(BTreeMap::from([
            (key_stale, stale_policy),
            (key_same, desired_policy),
            (key_extra, desired_policy),
        ]));
        let upserts: RefCell<Vec<TenantKey>> = RefCell::new(Vec::new());
        let deletes: RefCell<Vec<TenantKey>> = RefCell::new(Vec::new());

        let reconciled = super::reconcile_policy_map(
            &desired,
            vec![key_stale, key_same, key_extra],
            |tenant| Ok(current.borrow().get(&tenant).copied()),
            |entries| {
                for (tenant, policy) in entries.iter().copied() {
                    current.borrow_mut().insert(tenant, policy);
                    upserts.borrow_mut().push(tenant);
                }
                Ok(())
            },
            |tenants| {
                for tenant in tenants.iter().copied() {
                    let _ = current.borrow_mut().remove(&tenant);
                    deletes.borrow_mut().push(tenant);
                }
                Ok(())
            },
        );
        assert!(
            reconciled.is_ok(),
            "reconcile should apply diff successfully"
        );

        let upserts = upserts.into_inner();
        assert_eq!(upserts.len(), 2);
        assert!(upserts.contains(&key_missing));
        assert!(upserts.contains(&key_stale));
        assert!(!upserts.contains(&key_same));

        let deletes = deletes.into_inner();
        assert_eq!(deletes, vec![key_extra]);
    }

    #[test]
    fn should_reconcile_tick_when_revision_changes() {
        assert!(super::should_reconcile_tick(5, 4, 1, 30));
    }

    #[test]
    fn should_reconcile_tick_on_deep_check_interval_without_revision_change() {
        assert!(super::should_reconcile_tick(7, 7, 30, 30));
    }

    #[test]
    fn should_skip_tick_when_revision_unchanged_and_not_deep_check() {
        assert!(!super::should_reconcile_tick(9, 9, 29, 30));
    }

    #[test]
    fn direction_name_reports_both() {
        let config = Config {
            iface: "lo".to_owned(),
            bind_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 3000)),
            state_file_path: PathBuf::from("./vantage-state.json"),
            attach_ingress: true,
            attach_egress: true,
            drop_event_log_sample_n: 5,
            drop_event_log_enabled: true,
            cpu_window_ms: 5_000,
            metrics_dimensions: crate::config::MetricsDimensions::Aggregate,
            flow_keys_mode: crate::config::FlowKeysMode::Live,
            debug_top_tenants: 10,
            policy_validation_mode: crate::config::PolicyValidationMode::Permissive,
            adaptive: crate::config::AdaptiveConfig {
                enabled: false,
                high_watermark_percent: 90,
                low_watermark_percent: 80,
                tick_ms: 1_000,
                throttle_rate_tokens_per_sec: 100,
                throttle_burst_tokens: 500,
            },
            reconcile_tick_ms: 1_000,
            reconcile_deep_check_every_n: 30,
            essential_tenants: std::collections::BTreeSet::new(),
        };
        assert_eq!(direction_name(&config), "both");
    }

    #[tokio::test]
    async fn healthz_reports_kernel_and_log_sampling() {
        let config = Config {
            iface: "lo".to_owned(),
            bind_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 3000)),
            state_file_path: PathBuf::from("./vantage-state.json"),
            attach_ingress: true,
            attach_egress: false,
            drop_event_log_sample_n: 5,
            drop_event_log_enabled: true,
            cpu_window_ms: 2_500,
            metrics_dimensions: crate::config::MetricsDimensions::PerFlow,
            flow_keys_mode: crate::config::FlowKeysMode::Legacy,
            debug_top_tenants: 25,
            policy_validation_mode: crate::config::PolicyValidationMode::Permissive,
            adaptive: crate::config::AdaptiveConfig {
                enabled: true,
                high_watermark_percent: 92,
                low_watermark_percent: 78,
                tick_ms: 750,
                throttle_rate_tokens_per_sec: 50,
                throttle_burst_tokens: 250,
            },
            reconcile_tick_ms: 1_000,
            reconcile_deep_check_every_n: 30,
            essential_tenants: std::collections::BTreeSet::new(),
        };
        let state = test_state(
            config,
            DropEventRuntime {
                kernel_sample_every: KERNEL_DROP_EVENT_SAMPLE_EVERY,
                log_sample_n: 5,
                log_enabled: true,
            },
        );

        let response = healthz(State(state)).await;
        let json = response.0;
        assert_eq!(json.direction, "ingress");
        assert_eq!(
            json.drop_events.kernel_sample_every,
            KERNEL_DROP_EVENT_SAMPLE_EVERY
        );
        assert_eq!(json.cpu_window_ms, 2_500);
        assert!(json.metrics_dimensional_enabled);
        assert!(!json.flow_keys_live);
        assert_eq!(json.debug_top_tenants, 25);
        assert!(json.adaptive_enabled);
        assert_eq!(json.adaptive_high_watermark_percent, 92);
        assert_eq!(json.adaptive_low_watermark_percent, 78);
        assert_eq!(json.adaptive_tick_ms, 750);
        assert_eq!(json.adaptive_throttle_rate_tokens_per_sec, 50);
        assert_eq!(json.adaptive_throttle_burst_tokens, 250);
        assert_eq!(json.drop_events.log_sample_n, 5);
        assert!(json.drop_events.log_enabled);
    }

    #[test]
    #[ignore = "requires root privileges and tc attach support on the host kernel"]
    fn tc_program_loads_and_attaches_on_loopback() {
        let object = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/vantage"));
        let ebpf = Ebpf::load(object);
        let Ok(mut ebpf) = ebpf else {
            panic!("embedded eBPF object should load");
        };

        let _ = tc::qdisc_add_clsact("lo");
        let program = ebpf.program_mut("vantage_tc");
        let Some(program) = program else {
            panic!("vantage_tc program should exist");
        };
        let classifier: Result<&mut SchedClassifier, _> = program.try_into();
        let Ok(classifier) = classifier else {
            panic!("vantage_tc should be a SchedClassifier");
        };
        assert!(
            classifier.load().is_ok(),
            "verifier should accept program including spinlock-backed map value"
        );
        assert!(
            classifier.attach("lo", TcAttachType::Ingress).is_ok(),
            "program should attach on loopback ingress"
        );
    }
}
