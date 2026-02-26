pub mod config;
pub mod control_api;
pub mod events;
pub mod map_client;
pub mod metrics;

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
use prometheus::{IntGauge, Registry};
use serde::Serialize;
use thiserror::Error;
use tokio::signal;
use tracing::{info, warn};

use crate::{
    config::Config,
    control_api::{delete_policy, metrics, put_policy},
    events::{spawn_drop_event_consumer, take_drop_event_ring},
    map_client::MapClient,
};

#[derive(Clone)]
pub(crate) struct MetricsState {
    pub(crate) registry: Registry,
    pub(crate) daemon_up: IntGauge,
}

#[derive(Clone)]
pub struct AppState {
    pub(crate) config: Config,
    pub(crate) drop_events: DropEventRuntime,
    pub(crate) maps: MapClient,
    pub(crate) metrics: MetricsState,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct DropEventRuntime {
    pub(crate) sample_n: u32,
    pub(crate) log_enabled: bool,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    iface: String,
    direction: &'static str,
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

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/vantage"
    )))
    .context("failed to load embedded eBPF object")?;

    attach_tc(&mut ebpf, &config)?;

    if config.drop_event_log_enabled {
        let ring_buf =
            take_drop_event_ring(&mut ebpf).context("failed to acquire DROP_EVENTS map")?;
        spawn_drop_event_consumer(ring_buf, config.drop_event_sample_n)
            .context("failed to start drop-event consumer task")?;
    }

    let metrics_state = build_metrics_state()?;
    let drop_events = DropEventRuntime {
        sample_n: config.drop_event_sample_n,
        log_enabled: config.drop_event_log_enabled,
    };
    let state = AppState {
        config: config.clone(),
        drop_events,
        maps: MapClient::new(Arc::new(std::sync::Mutex::new(ebpf))),
        metrics: metrics_state,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/policy/:tenant", put(put_policy).delete(delete_policy))
        .route("/metrics", get(metrics))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind HTTP server on {}", config.bind_addr))?;
    info!(
        bind_addr = %config.bind_addr,
        iface = %config.iface,
        direction = %direction_name(&config),
        drop_event_log_enabled = config.drop_event_log_enabled,
        drop_event_sample_n = config.drop_event_sample_n,
        "vantage daemon started"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server exited with error")?;

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

    Ok(MetricsState {
        registry,
        daemon_up,
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
        drop_events: state.drop_events,
    })
}

async fn shutdown_signal() {
    if let Err(error) = signal::ctrl_c().await {
        warn!(%error, "failed to listen for shutdown signal");
        return;
    }

    info!("shutdown signal received");
}
