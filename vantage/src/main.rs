pub mod adaptive;
pub mod config;
pub mod control_api;
pub mod events;
pub mod map_client;
pub mod metrics;
pub mod prereqs;
pub mod tenancy;
pub mod tenant;

use std::sync::Arc;

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
use tokio::{signal, sync::watch};
use tracing::{info, warn};
use vantage_common::KERNEL_DROP_EVENT_SAMPLE_EVERY;

use crate::{
    adaptive::{AdaptiveRuntimeState, spawn_adaptive_controller},
    config::Config,
    control_api::{
        debug_cpu_window, debug_snapshot, delete_policy, get_admin_enabled, metrics,
        put_admin_enabled, put_policy, put_tenant_essential, resolve_policy, tenant_essential,
    },
    events::{spawn_drop_event_consumer, take_drop_event_ring},
    map_client::MapClient,
    prereqs::ensure_cgroup_v2_mounted,
    tenancy::TenancyState,
};

#[derive(Clone)]
pub(crate) struct MetricsState {
    pub(crate) registry: Registry,
    pub(crate) daemon_up: IntGauge,
    pub(crate) partial_l7_policy_keys_total: IntCounter,
}

#[derive(Clone)]
pub struct AppState {
    pub(crate) config: Config,
    pub(crate) drop_events: DropEventRuntime,
    pub(crate) maps: MapClient,
    pub(crate) metrics: MetricsState,
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
pub enum AppError {
    #[error(transparent)]
    Runtime(#[from] anyhow::Error),
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

    if config.drop_event_log_enabled {
        let ring_buf =
            take_drop_event_ring(&mut ebpf).context("failed to acquire DROP_EVENTS map")?;
        spawn_drop_event_consumer(
            ring_buf,
            shutdown_rx.clone(),
            config.drop_event_log_sample_n,
        );
    }

    let metrics_state = build_metrics_state()?;
    let drop_events = DropEventRuntime {
        kernel_sample_every: KERNEL_DROP_EVENT_SAMPLE_EVERY,
        log_sample_n: config.drop_event_log_sample_n,
        log_enabled: config.drop_event_log_enabled,
    };
    let maps = MapClient::new(Arc::new(std::sync::Mutex::new(ebpf)));
    maps.seed_global_config(config.global_config_seed().as_global_config())
        .context("failed to seed GLOBAL_CONFIG_MAP startup state")?;
    let state = AppState {
        config: config.clone(),
        drop_events,
        maps,
        metrics: metrics_state,
        tenancy: TenancyState::new(config.essential_tenants.clone()),
        adaptive_runtime: AdaptiveRuntimeState::default(),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/policy/:tenant", put(put_policy).delete(delete_policy))
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
        .with_state(state.clone());
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
        flow_keys_live = config.flow_keys_mode.live(),
        debug_top_tenants = config.debug_top_tenants,
        adaptive_enabled = config.adaptive.enabled,
        adaptive_high_watermark_percent = config.adaptive.high_watermark_percent,
        adaptive_low_watermark_percent = config.adaptive.low_watermark_percent,
        adaptive_tick_ms = config.adaptive.tick_ms,
        adaptive_throttle_rate_tokens_per_sec = config.adaptive.throttle_rate_tokens_per_sec,
        adaptive_throttle_burst_tokens = config.adaptive.throttle_burst_tokens,
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

    Ok(())
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

    Ok(MetricsState {
        registry,
        daemon_up,
        partial_l7_policy_keys_total,
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
    Json(HealthResponse {
        status: "ok",
        iface: state.config.iface.clone(),
        direction: direction_name(&state.config),
        cpu_window_ms: state.config.cpu_window_ms,
        metrics_dimensional_enabled: state.config.metrics_dimensions.enabled(),
        flow_keys_live: state.config.flow_keys_mode.live(),
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
    use std::sync::Arc;

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
        tenancy::TenancyState,
    };

    struct NoopMapOps;

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
            Ok(true)
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

        AppState {
            config,
            drop_events,
            maps: MapClient::from_ops(Arc::new(NoopMapOps)),
            metrics: MetricsState {
                registry,
                daemon_up,
                partial_l7_policy_keys_total: IntCounter::new(
                    "vantage_partial_l7_policy_keys_total",
                    "Total number of policy upserts with L7 selectors and wildcard L4 selectors",
                )
                .unwrap_or_else(|error| panic!("metric should initialize: {error}")),
            },
            tenancy: TenancyState::default(),
            adaptive_runtime: AdaptiveRuntimeState::default(),
        }
    }

    #[test]
    fn direction_name_reports_both() {
        let config = Config {
            iface: "lo".to_owned(),
            bind_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 3000)),
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
            essential_tenants: std::collections::BTreeSet::new(),
        };
        assert_eq!(direction_name(&config), "both");
    }

    #[tokio::test]
    async fn healthz_reports_kernel_and_log_sampling() {
        let config = Config {
            iface: "lo".to_owned(),
            bind_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 3000)),
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
