use std::{net::SocketAddr, sync::Arc};

use anyhow::Context as _;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use aya::{
    Ebpf,
    programs::{SchedClassifier, TcAttachType, tc},
};
use clap::{Parser, ValueEnum};
use prometheus::{Encoder, IntGauge, Registry, TextEncoder};
use serde::Serialize;
use thiserror::Error;
use tokio::{signal, sync::Mutex};
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AttachDirection {
    Ingress,
    Egress,
    Both,
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
    #[clap(long, value_enum, default_value_t = AttachDirection::Ingress)]
    direction: AttachDirection,
    #[clap(long, default_value = "127.0.0.1:3000")]
    bind_addr: SocketAddr,
    #[clap(long)]
    enable_event_stream: bool,
}

#[derive(Debug, Clone)]
struct DaemonConfig {
    iface: String,
    direction: AttachDirection,
    bind_addr: SocketAddr,
    enable_event_stream: bool,
}

#[derive(Clone)]
struct MetricsState {
    registry: Registry,
    daemon_up: IntGauge,
}

#[derive(Clone)]
struct MapHandles {
    ebpf: Arc<Mutex<Ebpf>>,
}

#[derive(Clone)]
struct AppState {
    config: DaemonConfig,
    maps: MapHandles,
    metrics: MetricsState,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    iface: String,
    direction: &'static str,
}

#[derive(Debug, Error)]
enum AppError {
    #[error("failed to encode Prometheus metrics: {0}")]
    MetricsEncode(prometheus::Error),
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

    let opt = Opt::parse();
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/vantage"
    )))
    .context("failed to load embedded eBPF object")?;

    if opt.enable_event_stream {
        spawn_ebpf_log_task(&mut ebpf)?;
    }

    let config = DaemonConfig {
        iface: opt.iface,
        direction: opt.direction,
        bind_addr: opt.bind_addr,
        enable_event_stream: opt.enable_event_stream,
    };

    attach_tc(&mut ebpf, &config).context("failed to attach tc program")?;

    let metrics_state = build_metrics_state()?;
    let state = AppState {
        config: config.clone(),
        maps: MapHandles {
            ebpf: Arc::new(Mutex::new(ebpf)),
        },
        metrics: metrics_state,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind HTTP server on {}", config.bind_addr))?;
    info!(
        bind_addr = %config.bind_addr,
        iface = %config.iface,
        direction = %direction_name(config.direction),
        event_stream = config.enable_event_stream,
        "vantage daemon started"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server exited with error")?;

    Ok(())
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .compact()
        .init();
}

fn attach_tc(ebpf: &mut Ebpf, config: &DaemonConfig) -> anyhow::Result<()> {
    if let Err(error) = tc::qdisc_add_clsact(&config.iface) {
        warn!(%error, iface = %config.iface, "unable to add clsact qdisc; continuing");
    }

    let program: &mut SchedClassifier = ebpf
        .program_mut("vantage_tc")
        .context("program 'vantage_tc' not found in eBPF object")?
        .try_into()
        .context("program 'vantage_tc' is not a tc classifier")?;

    program.load().context("failed to load tc classifier")?;

    match config.direction {
        AttachDirection::Ingress => {
            program
                .attach(&config.iface, TcAttachType::Ingress)
                .with_context(|| format!("failed to attach tc ingress on {}", config.iface))?;
        }
        AttachDirection::Egress => {
            program
                .attach(&config.iface, TcAttachType::Egress)
                .with_context(|| format!("failed to attach tc egress on {}", config.iface))?;
        }
        AttachDirection::Both => {
            program
                .attach(&config.iface, TcAttachType::Ingress)
                .with_context(|| format!("failed to attach tc ingress on {}", config.iface))?;
            program
                .attach(&config.iface, TcAttachType::Egress)
                .with_context(|| format!("failed to attach tc egress on {}", config.iface))?;
        }
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

fn spawn_ebpf_log_task(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    match aya_log::EbpfLogger::init(ebpf) {
        Err(error) => {
            warn!(%error, "failed to initialize eBPF logger");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    if let Ok(mut guard) = logger.readable_mut().await {
                        guard.get_inner_mut().flush();
                        guard.clear_ready();
                    }
                }
            });
        }
    }

    Ok(())
}

const fn direction_name(direction: AttachDirection) -> &'static str {
    match direction {
        AttachDirection::Ingress => "ingress",
        AttachDirection::Egress => "egress",
        AttachDirection::Both => "both",
    }
}

async fn healthz(State(state): State<AppState>) -> Json<HealthResponse> {
    // Keep the eBPF object reachable from shared state to preserve map/program handles.
    let _ebpf_handle = Arc::clone(&state.maps.ebpf);

    Json(HealthResponse {
        status: "ok",
        iface: state.config.iface,
        direction: direction_name(state.config.direction),
    })
}

async fn metrics(State(state): State<AppState>) -> Result<Response, AppError> {
    state.metrics.daemon_up.set(1);
    let metric_families = state.metrics.registry.gather();

    let mut payload = Vec::new();
    TextEncoder::new()
        .encode(&metric_families, &mut payload)
        .map_err(AppError::MetricsEncode)?;

    let mut response = payload.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    Ok(response)
}

async fn shutdown_signal() {
    if let Err(error) = signal::ctrl_c().await {
        warn!(%error, "failed to listen for shutdown signal");
        return;
    }

    info!("shutdown signal received");
}
