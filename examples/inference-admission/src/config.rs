use std::path::PathBuf;

use clap::Parser;
use thiserror::Error;

#[derive(Debug, Clone, Parser)]
#[command(name = "vantage-inference-admission")]
pub(crate) struct Cli {
    #[arg(
        long,
        default_value = "http://127.0.0.1:3000",
        env = "VANTAGE_INFERENCE_VANTAGE_BASE_URL"
    )]
    vantage_base_url: String,
    #[arg(long, env = "VANTAGE_INFERENCE_TENANT", value_parser = parse_tenant_selector)]
    tenant: TenantSelector,
    #[arg(long, default_value_t = 8000_u16, env = "VANTAGE_INFERENCE_PORT")]
    inference_port: u16,
    #[arg(
        long,
        default_value = "/v1/chat/completions",
        env = "VANTAGE_INFERENCE_HTTP_PATH"
    )]
    inference_http_path: String,
    #[arg(long, default_value_t = 1_000_u64, env = "VANTAGE_INFERENCE_TICK_MS")]
    tick_ms: u64,
    #[arg(
        long,
        default_value_t = 90.0_f64,
        env = "VANTAGE_INFERENCE_GPU_HIGH_WATERMARK_PERCENT"
    )]
    gpu_high_watermark_percent: f64,
    #[arg(
        long,
        default_value_t = 80.0_f64,
        env = "VANTAGE_INFERENCE_GPU_LOW_WATERMARK_PERCENT"
    )]
    gpu_low_watermark_percent: f64,
    #[arg(
        long,
        default_value_t = 90.0_f64,
        env = "VANTAGE_INFERENCE_KV_HIGH_WATERMARK_PERCENT"
    )]
    kv_high_watermark_percent: f64,
    #[arg(
        long,
        default_value_t = 80.0_f64,
        env = "VANTAGE_INFERENCE_KV_LOW_WATERMARK_PERCENT"
    )]
    kv_low_watermark_percent: f64,
    #[arg(
        long,
        default_value_t = 60_000_u64,
        env = "VANTAGE_INFERENCE_TOKEN_BUDGET_PER_MINUTE"
    )]
    token_budget_per_minute: u64,
    #[arg(
        long,
        default_value_t = 10_000_u64,
        env = "VANTAGE_INFERENCE_NORMAL_RATE_TOKENS_PER_SEC"
    )]
    normal_rate_tokens_per_sec: u64,
    #[arg(
        long,
        default_value_t = 50_000_u64,
        env = "VANTAGE_INFERENCE_NORMAL_BURST_TOKENS"
    )]
    normal_burst_tokens: u64,
    #[arg(
        long,
        default_value_t = 100_u64,
        env = "VANTAGE_INFERENCE_THROTTLE_RATE_TOKENS_PER_SEC"
    )]
    throttle_rate_tokens_per_sec: u64,
    #[arg(
        long,
        default_value_t = 500_u64,
        env = "VANTAGE_INFERENCE_THROTTLE_BURST_TOKENS"
    )]
    throttle_burst_tokens: u64,
    #[arg(long, env = "VANTAGE_INFERENCE_DISABLED_ON_EXHAUSTION")]
    disabled_on_exhaustion: bool,
    #[arg(long, env = "VANTAGE_INFERENCE_METRICS_FILE_PATH")]
    metrics_file_path: Option<PathBuf>,
    #[arg(long, env = "VANTAGE_INFERENCE_GPU_UTIL_FILE_PATH")]
    gpu_util_file_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TenantSelector {
    pub(crate) cgroup_id: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub(crate) vantage_base_url: String,
    pub(crate) tenant: TenantSelector,
    pub(crate) inference_port: u16,
    pub(crate) inference_http_path: String,
    pub(crate) tick_ms: u64,
    pub(crate) gpu_high_watermark_percent: f64,
    pub(crate) gpu_low_watermark_percent: f64,
    pub(crate) kv_high_watermark_percent: f64,
    pub(crate) kv_low_watermark_percent: f64,
    pub(crate) token_budget_per_minute: u64,
    pub(crate) normal_rate_tokens_per_sec: u64,
    pub(crate) normal_burst_tokens: u64,
    pub(crate) throttle_rate_tokens_per_sec: u64,
    pub(crate) throttle_burst_tokens: u64,
    pub(crate) disabled_on_exhaustion: bool,
    pub(crate) metrics_file_path: Option<PathBuf>,
    pub(crate) gpu_util_file_path: Option<PathBuf>,
}

#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    #[error("invalid tenant selector")]
    InvalidTenant,
}

impl Config {
    pub(crate) fn from_args() -> Self {
        Self::from_cli(Cli::parse())
    }

    #[cfg(test)]
    pub(crate) fn try_from_iter<I, T>(iter: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Cli::try_parse_from(iter).map(Self::from_cli)
    }

    fn from_cli(cli: Cli) -> Self {
        let gpu_high = clamp_percent(cli.gpu_high_watermark_percent);
        let kv_high = clamp_percent(cli.kv_high_watermark_percent);
        Self {
            vantage_base_url: cli.vantage_base_url.trim_end_matches('/').to_owned(),
            tenant: cli.tenant,
            inference_port: cli.inference_port,
            inference_http_path: normalize_http_path(&cli.inference_http_path),
            tick_ms: cli.tick_ms.max(100),
            gpu_high_watermark_percent: gpu_high,
            gpu_low_watermark_percent: clamp_low_watermark(cli.gpu_low_watermark_percent, gpu_high),
            kv_high_watermark_percent: kv_high,
            kv_low_watermark_percent: clamp_low_watermark(cli.kv_low_watermark_percent, kv_high),
            token_budget_per_minute: cli.token_budget_per_minute.max(1),
            normal_rate_tokens_per_sec: cli.normal_rate_tokens_per_sec.max(1),
            normal_burst_tokens: cli.normal_burst_tokens.max(1),
            throttle_rate_tokens_per_sec: cli.throttle_rate_tokens_per_sec.max(1),
            throttle_burst_tokens: cli.throttle_burst_tokens.max(1),
            disabled_on_exhaustion: cli.disabled_on_exhaustion,
            metrics_file_path: cli.metrics_file_path,
            gpu_util_file_path: cli.gpu_util_file_path,
        }
    }
}

fn parse_tenant_selector(raw: &str) -> Result<TenantSelector, ConfigError> {
    let trimmed = raw.trim();
    let value = trimmed.strip_prefix("cg:").unwrap_or(trimmed);
    value
        .parse::<u64>()
        .map(|cgroup_id| TenantSelector { cgroup_id })
        .map_err(|_| ConfigError::InvalidTenant)
}

fn normalize_http_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}

const fn clamp_percent(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 100.0)
    } else {
        100.0
    }
}

fn clamp_low_watermark(value: f64, high: f64) -> f64 {
    let low = clamp_percent(value);
    if low < high {
        low
    } else {
        (high - 1.0).max(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, TenantSelector, parse_tenant_selector};

    #[test]
    fn parses_tenant_prefix() {
        let parsed = parse_tenant_selector("cg:42");
        let Ok(parsed) = parsed else {
            panic!("tenant should parse");
        };
        assert_eq!(parsed, TenantSelector { cgroup_id: 42 });
    }

    #[test]
    fn normalizes_path_and_clamps_values() {
        let parsed = Config::try_from_iter([
            "vantage-inference-admission",
            "--tenant",
            "7",
            "--inference-http-path",
            "generate",
            "--tick-ms",
            "1",
            "--gpu-high-watermark-percent",
            "80",
            "--gpu-low-watermark-percent",
            "90",
            "--token-budget-per-minute",
            "0",
        ]);
        let Ok(config) = parsed else {
            panic!("config should parse");
        };
        assert_eq!(config.inference_http_path, "/generate");
        assert_eq!(config.tick_ms, 100);
        assert!((config.gpu_low_watermark_percent - 79.0).abs() < f64::EPSILON);
        assert_eq!(config.token_budget_per_minute, 1);
    }
}
