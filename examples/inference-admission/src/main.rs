#![allow(clippy::redundant_pub_crate)]

pub(crate) mod config;
pub(crate) mod controller;
pub(crate) mod gpu;
pub(crate) mod inference;
pub(crate) mod state;
pub(crate) mod vantage_client;

use std::time::Duration;

use tokio::time::{MissedTickBehavior, interval};
use tracing::{info, warn};

use crate::{
    config::Config,
    controller::{AdmissionController, FileInferenceSource},
    gpu::FileGpuUtilSource,
    vantage_client::VantageClient,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .compact()
        .init();

    let config = Config::from_args();
    let client = VantageClient::new(&config.vantage_base_url)?;
    let gpu_source = FileGpuUtilSource::new(config.gpu_util_file_path.clone());
    let inference_source = FileInferenceSource::new(
        config.metrics_file_path.clone(),
        config.token_budget_per_minute,
    );
    let mut controller =
        AdmissionController::new(config.clone(), client, gpu_source, inference_source);

    info!(
        vantage_base_url = %config.vantage_base_url,
        tenant = config.tenant.cgroup_id,
        inference_port = config.inference_port,
        inference_http_path = %config.inference_http_path,
        tick_ms = config.tick_ms,
        "vantage inference admission controller started"
    );

    let mut ticker = interval(Duration::from_millis(config.tick_ms));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received");
                break;
            }
            _ = ticker.tick() => {
                if let Err(error) = controller.tick().await {
                    warn!(%error, "inference admission tick failed; retaining previous applied state");
                }
            }
        }
    }

    if let Err(error) = controller.clear_runtime_override().await {
        warn!(
            %error,
            "failed to clear inference runtime override during shutdown"
        );
    }

    Ok(())
}
