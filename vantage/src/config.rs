use std::{collections::BTreeSet, net::SocketAddr, num::ParseIntError, path::PathBuf};

use clap::{Parser, ValueEnum};
use vantage_common::GlobalConfig;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AttachDirection {
    Ingress,
    Egress,
    Both,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum FlowKeysMode {
    Live,
    Legacy,
}

impl FlowKeysMode {
    pub(crate) const fn live(self) -> bool {
        matches!(self, Self::Live)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetricsDimensions {
    Aggregate,
    PerFlow,
}

impl MetricsDimensions {
    pub(crate) const fn enabled(self) -> bool {
        matches!(self, Self::PerFlow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum PolicyValidationMode {
    Permissive,
    Strict,
}

impl PolicyValidationMode {
    pub(crate) const fn strict(self) -> bool {
        matches!(self, Self::Strict)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AdaptiveConfig {
    pub(crate) enabled: bool,
    pub(crate) high_watermark_percent: u8,
    pub(crate) low_watermark_percent: u8,
    pub(crate) tick_ms: u64,
    pub(crate) throttle_rate_tokens_per_sec: u64,
    pub(crate) throttle_burst_tokens: u64,
}

#[derive(Debug, Parser)]
#[command(name = "vantage")]
struct Cli {
    #[arg(short, long, default_value = "lo", env = "VANTAGE_IFACE")]
    iface: String,
    #[arg(
        long,
        value_enum,
        default_value_t = AttachDirection::Ingress,
        env = "VANTAGE_ATTACH_DIRECTION"
    )]
    direction: AttachDirection,
    #[arg(long, default_value = "127.0.0.1:3000", env = "VANTAGE_BIND_ADDR")]
    bind_addr: SocketAddr,
    #[arg(
        long = "state-file-path",
        default_value = "./vantage-state.json",
        env = "VANTAGE_STATE_FILE_PATH",
        value_parser = parse_state_file_path
    )]
    state_file_path: PathBuf,
    #[arg(
        long = "drop-event-sample-n",
        alias = "drop-event-log-sample-n",
        default_value_t = 1,
        env = "VANTAGE_DROP_EVENT_SAMPLE_N"
    )]
    drop_event_log_sample_n: u32,
    #[arg(
        long = "drop-event-log-enabled",
        alias = "enable-event-stream",
        env = "VANTAGE_DROP_EVENT_LOG_ENABLED"
    )]
    drop_event_log_enabled: bool,
    #[arg(long, default_value_t = 5_000_u64, env = "VANTAGE_CPU_WINDOW_MS")]
    cpu_window_ms: u64,
    #[arg(
        long = "metrics-dimensional-enabled",
        env = "VANTAGE_METRICS_DIMENSIONAL_ENABLED"
    )]
    metrics_dimensional_enabled: bool,
    #[arg(
        long = "flow-keys-mode",
        value_enum,
        default_value_t = FlowKeysMode::Live,
        env = "VANTAGE_FLOW_KEYS_MODE"
    )]
    flow_keys_mode: FlowKeysMode,
    #[arg(
        long = "debug-top-tenants",
        default_value_t = 10_usize,
        env = "VANTAGE_DEBUG_TOP_TENANTS"
    )]
    debug_top_tenants: usize,
    #[arg(
        long = "policy-validation-mode",
        value_enum,
        default_value_t = PolicyValidationMode::Permissive,
        env = "VANTAGE_POLICY_VALIDATION_MODE"
    )]
    policy_validation_mode: PolicyValidationMode,
    #[arg(long = "adaptive-enabled", env = "VANTAGE_ADAPTIVE_ENABLED")]
    adaptive_enabled: bool,
    #[arg(
        long = "adaptive-high-watermark-percent",
        default_value_t = 90_u8,
        env = "VANTAGE_ADAPTIVE_HIGH_WATERMARK_PERCENT"
    )]
    adaptive_high_watermark_percent: u8,
    #[arg(
        long = "adaptive-low-watermark-percent",
        default_value_t = 80_u8,
        env = "VANTAGE_ADAPTIVE_LOW_WATERMARK_PERCENT"
    )]
    adaptive_low_watermark_percent: u8,
    #[arg(
        long = "adaptive-tick-ms",
        default_value_t = 1_000_u64,
        env = "VANTAGE_ADAPTIVE_TICK_MS"
    )]
    adaptive_tick_ms: u64,
    #[arg(
        long = "adaptive-throttle-rate-tokens-per-sec",
        default_value_t = 100_u64,
        env = "VANTAGE_ADAPTIVE_THROTTLE_RATE_TOKENS_PER_SEC"
    )]
    adaptive_throttle_rate_tokens_per_sec: u64,
    #[arg(
        long = "adaptive-throttle-burst-tokens",
        default_value_t = 500_u64,
        env = "VANTAGE_ADAPTIVE_THROTTLE_BURST_TOKENS"
    )]
    adaptive_throttle_burst_tokens: u64,
    #[arg(
        long = "reconcile-tick-ms",
        default_value_t = 2_000_u64,
        env = "VANTAGE_RECONCILE_TICK_MS"
    )]
    reconcile_tick_ms: u64,
    #[arg(
        long = "reconcile-deep-check-every-n",
        default_value_t = 30_u64,
        env = "VANTAGE_RECONCILE_DEEP_CHECK_EVERY_N"
    )]
    reconcile_deep_check_every_n: u64,
    #[arg(
        long = "essential-tenant",
        env = "VANTAGE_ESSENTIAL_TENANTS",
        value_delimiter = ',',
        value_parser = parse_essential_tenant
    )]
    essential_tenants: Vec<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub(crate) iface: String,
    pub(crate) bind_addr: SocketAddr,
    pub(crate) state_file_path: PathBuf,
    pub(crate) attach_ingress: bool,
    pub(crate) attach_egress: bool,
    pub(crate) drop_event_log_sample_n: u32,
    pub(crate) drop_event_log_enabled: bool,
    pub(crate) cpu_window_ms: u64,
    pub(crate) metrics_dimensions: MetricsDimensions,
    pub(crate) flow_keys_mode: FlowKeysMode,
    pub(crate) debug_top_tenants: usize,
    pub(crate) policy_validation_mode: PolicyValidationMode,
    pub(crate) adaptive: AdaptiveConfig,
    pub(crate) reconcile_tick_ms: u64,
    pub(crate) reconcile_deep_check_every_n: u64,
    pub(crate) essential_tenants: BTreeSet<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GlobalConfigSeed {
    pub(crate) enabled: bool,
    pub(crate) flow_keys_live: bool,
}

impl GlobalConfigSeed {
    pub(crate) const fn as_global_config(self) -> GlobalConfig {
        GlobalConfig {
            enabled: if self.enabled { 1 } else { 0 },
            flow_keys_live: if self.flow_keys_live { 1 } else { 0 },
            _pad: [0; 6],
        }
    }
}

impl Config {
    pub(crate) fn from_args() -> Self {
        let cli = Cli::parse();
        Self::from_cli(cli)
    }

    #[cfg(test)]
    pub(crate) fn try_from_iter<I, T>(iter: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let cli = Cli::try_parse_from(iter)?;
        Ok(Self::from_cli(cli))
    }

    fn from_cli(cli: Cli) -> Self {
        let (attach_ingress, attach_egress) = match cli.direction {
            AttachDirection::Ingress => (true, false),
            AttachDirection::Egress => (false, true),
            AttachDirection::Both => (true, true),
        };
        let adaptive_high_watermark_percent = cli.adaptive_high_watermark_percent.clamp(2, 100);
        let adaptive_low_watermark_percent = cli
            .adaptive_low_watermark_percent
            .clamp(1, adaptive_high_watermark_percent.saturating_sub(1));

        Self {
            iface: cli.iface,
            bind_addr: cli.bind_addr,
            state_file_path: cli.state_file_path,
            attach_ingress,
            attach_egress,
            drop_event_log_sample_n: cli.drop_event_log_sample_n.max(1),
            drop_event_log_enabled: cli.drop_event_log_enabled,
            cpu_window_ms: cli.cpu_window_ms.max(1),
            metrics_dimensions: if cli.metrics_dimensional_enabled {
                MetricsDimensions::PerFlow
            } else {
                MetricsDimensions::Aggregate
            },
            flow_keys_mode: cli.flow_keys_mode,
            debug_top_tenants: cli.debug_top_tenants.clamp(1, 100),
            policy_validation_mode: cli.policy_validation_mode,
            adaptive: AdaptiveConfig {
                enabled: cli.adaptive_enabled,
                high_watermark_percent: adaptive_high_watermark_percent,
                low_watermark_percent: adaptive_low_watermark_percent,
                tick_ms: cli.adaptive_tick_ms.max(1),
                throttle_rate_tokens_per_sec: cli.adaptive_throttle_rate_tokens_per_sec.max(1),
                throttle_burst_tokens: cli.adaptive_throttle_burst_tokens.max(1),
            },
            reconcile_tick_ms: cli.reconcile_tick_ms.max(100),
            reconcile_deep_check_every_n: cli.reconcile_deep_check_every_n.max(1),
            essential_tenants: cli.essential_tenants.into_iter().collect(),
        }
    }

    pub(crate) const fn global_config_seed(&self) -> GlobalConfigSeed {
        GlobalConfigSeed {
            enabled: true,
            flow_keys_live: self.flow_keys_mode.live(),
        }
    }
}

fn parse_essential_tenant(raw: &str) -> Result<u64, String> {
    let trimmed = raw.trim();
    let value = trimmed.strip_prefix("cg:").unwrap_or(trimmed);
    value
        .parse::<u64>()
        .map_err(|error: ParseIntError| format!("invalid essential tenant '{raw}': {error}"))
}

fn parse_state_file_path(raw: &str) -> Result<PathBuf, String> {
    if raw.trim().is_empty() {
        return Err("state file path must not be empty".to_owned());
    }
    Ok(PathBuf::from(raw))
}

#[cfg(test)]
mod tests {
    use super::{Config, MetricsDimensions, PolicyValidationMode};

    fn parse_config<const N: usize>(args: [&str; N]) -> Result<Config, clap::Error> {
        temp_env::with_var("VANTAGE_STATE_FILE_PATH", None::<&str>, || {
            Config::try_from_iter(args)
        })
    }

    #[test]
    fn attach_direction_from_env_is_respected() {
        temp_env::with_var("VANTAGE_ATTACH_DIRECTION", Some("both"), || {
            let parsed = parse_config(["vantage"]);
            let Ok(config) = parsed else {
                panic!("config parsing should succeed");
            };
            assert!(config.attach_ingress);
            assert!(config.attach_egress);
        });
    }

    #[test]
    fn default_direction_is_ingress_only() {
        temp_env::with_var("VANTAGE_ATTACH_DIRECTION", None::<&str>, || {
            let parsed = parse_config(["vantage"]);
            let Ok(config) = parsed else {
                panic!("config parsing should succeed");
            };
            assert!(config.attach_ingress);
            assert!(!config.attach_egress);
        });
    }

    #[test]
    fn drop_event_sample_is_clamped_to_one() {
        let parsed = parse_config(["vantage", "--drop-event-sample-n", "0"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.drop_event_log_sample_n, 1);
    }

    #[test]
    fn cli_flag_overrides_env_value() {
        temp_env::with_var("VANTAGE_ATTACH_DIRECTION", Some("egress"), || {
            let parsed = parse_config(["vantage", "--direction", "ingress"]);
            let Ok(config) = parsed else {
                panic!("config parsing should succeed");
            };
            assert!(config.attach_ingress);
            assert!(!config.attach_egress);
        });
    }

    #[test]
    fn cpu_window_ms_uses_default() {
        let parsed = parse_config(["vantage"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.cpu_window_ms, 5_000);
    }

    #[test]
    fn cpu_window_ms_is_clamped_to_one() {
        let parsed = parse_config(["vantage", "--cpu-window-ms", "0"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.cpu_window_ms, 1);
    }

    #[test]
    fn state_file_path_uses_default() {
        let parsed = parse_config(["vantage"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(
            config.state_file_path,
            std::path::PathBuf::from("./vantage-state.json")
        );
    }

    #[test]
    fn state_file_path_can_be_overridden_by_flag() {
        let parsed = parse_config(["vantage", "--state-file-path", "./custom-state.json"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(
            config.state_file_path,
            std::path::PathBuf::from("./custom-state.json")
        );
    }

    #[test]
    fn state_file_path_can_be_overridden_by_env() {
        temp_env::with_var("VANTAGE_STATE_FILE_PATH", Some("./env-state.json"), || {
            let parsed = Config::try_from_iter(["vantage"]);
            let Ok(config) = parsed else {
                panic!("config parsing should succeed");
            };
            assert_eq!(
                config.state_file_path,
                std::path::PathBuf::from("./env-state.json")
            );
        });
    }

    #[test]
    fn empty_state_file_path_is_rejected() {
        let parsed = parse_config(["vantage", "--state-file-path", ""]);
        assert!(parsed.is_err(), "empty state file path should fail parsing");
    }

    #[test]
    fn empty_state_file_path_from_env_is_rejected() {
        temp_env::with_var("VANTAGE_STATE_FILE_PATH", Some(""), || {
            let parsed = Config::try_from_iter(["vantage"]);
            assert!(parsed.is_err(), "empty state file path should fail parsing");
        });
    }

    #[test]
    fn debug_top_tenants_uses_default() {
        let parsed = parse_config(["vantage"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.debug_top_tenants, 10);
    }

    #[test]
    fn debug_top_tenants_is_clamped_to_upper_bound() {
        let parsed = parse_config(["vantage", "--debug-top-tenants", "500"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.debug_top_tenants, 100);
    }

    #[test]
    fn debug_top_tenants_is_clamped_to_lower_bound() {
        let parsed = parse_config(["vantage", "--debug-top-tenants", "0"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.debug_top_tenants, 1);
    }

    #[test]
    fn metrics_dimensions_can_be_enabled() {
        let parsed = parse_config(["vantage", "--metrics-dimensional-enabled"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.metrics_dimensions, MetricsDimensions::PerFlow);
    }

    #[test]
    fn flow_keys_mode_defaults_to_live() {
        let parsed = parse_config(["vantage"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert!(config.flow_keys_mode.live());
    }

    #[test]
    fn flow_keys_mode_can_disable_flow_keys() {
        let parsed = parse_config(["vantage", "--flow-keys-mode", "legacy"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert!(!config.flow_keys_mode.live());
    }

    #[test]
    fn policy_validation_mode_defaults_to_permissive() {
        let parsed = parse_config(["vantage"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(
            config.policy_validation_mode,
            PolicyValidationMode::Permissive
        );
    }

    #[test]
    fn policy_validation_mode_can_be_set_to_strict() {
        let parsed = parse_config(["vantage", "--policy-validation-mode", "strict"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.policy_validation_mode, PolicyValidationMode::Strict);
        assert!(config.policy_validation_mode.strict());
    }

    #[test]
    fn adaptive_config_defaults_are_set() {
        let parsed = parse_config(["vantage"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert!(!config.adaptive.enabled);
        assert_eq!(config.adaptive.high_watermark_percent, 90);
        assert_eq!(config.adaptive.low_watermark_percent, 80);
        assert_eq!(config.adaptive.tick_ms, 1_000);
        assert_eq!(config.adaptive.throttle_rate_tokens_per_sec, 100);
        assert_eq!(config.adaptive.throttle_burst_tokens, 500);
    }

    #[test]
    fn adaptive_tick_ms_is_clamped_to_one() {
        let parsed = parse_config(["vantage", "--adaptive-tick-ms", "0"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.adaptive.tick_ms, 1);
    }

    #[test]
    fn adaptive_throttle_values_are_clamped_to_one() {
        let parsed = parse_config([
            "vantage",
            "--adaptive-throttle-rate-tokens-per-sec",
            "0",
            "--adaptive-throttle-burst-tokens",
            "0",
        ]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.adaptive.throttle_rate_tokens_per_sec, 1);
        assert_eq!(config.adaptive.throttle_burst_tokens, 1);
    }

    #[test]
    fn reconcile_defaults_are_set() {
        let parsed = parse_config(["vantage"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.reconcile_tick_ms, 2_000);
        assert_eq!(config.reconcile_deep_check_every_n, 30);
    }

    #[test]
    fn reconcile_values_are_clamped_to_minimums() {
        let parsed = parse_config([
            "vantage",
            "--reconcile-tick-ms",
            "0",
            "--reconcile-deep-check-every-n",
            "0",
        ]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.reconcile_tick_ms, 100);
        assert_eq!(config.reconcile_deep_check_every_n, 1);
    }

    #[test]
    fn reconcile_values_can_be_overridden_by_env() {
        temp_env::with_var("VANTAGE_RECONCILE_TICK_MS", Some("2500"), || {
            temp_env::with_var("VANTAGE_RECONCILE_DEEP_CHECK_EVERY_N", Some("45"), || {
                let parsed = parse_config(["vantage"]);
                let Ok(config) = parsed else {
                    panic!("config parsing should succeed");
                };
                assert_eq!(config.reconcile_tick_ms, 2_500);
                assert_eq!(config.reconcile_deep_check_every_n, 45);
            });
        });
    }

    #[test]
    fn reconcile_values_from_env_are_clamped_to_minimums() {
        temp_env::with_var("VANTAGE_RECONCILE_TICK_MS", Some("0"), || {
            temp_env::with_var("VANTAGE_RECONCILE_DEEP_CHECK_EVERY_N", Some("0"), || {
                let parsed = parse_config(["vantage"]);
                let Ok(config) = parsed else {
                    panic!("config parsing should succeed");
                };
                assert_eq!(config.reconcile_tick_ms, 100);
                assert_eq!(config.reconcile_deep_check_every_n, 1);
            });
        });
    }

    #[test]
    fn adaptive_high_watermark_is_clamped_to_hundred() {
        let parsed = parse_config(["vantage", "--adaptive-high-watermark-percent", "255"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.adaptive.high_watermark_percent, 100);
    }

    #[test]
    fn adaptive_high_watermark_is_clamped_to_minimum_two() {
        let parsed = parse_config(["vantage", "--adaptive-high-watermark-percent", "1"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.adaptive.high_watermark_percent, 2);
    }

    #[test]
    fn adaptive_low_watermark_is_clamped_below_high() {
        let parsed = parse_config([
            "vantage",
            "--adaptive-high-watermark-percent",
            "80",
            "--adaptive-low-watermark-percent",
            "99",
        ]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.adaptive.high_watermark_percent, 80);
        assert_eq!(config.adaptive.low_watermark_percent, 79);
    }

    #[test]
    fn adaptive_low_watermark_remains_recoverable_when_high_is_minimum() {
        let parsed = parse_config([
            "vantage",
            "--adaptive-high-watermark-percent",
            "1",
            "--adaptive-low-watermark-percent",
            "0",
        ]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.adaptive.high_watermark_percent, 2);
        assert_eq!(config.adaptive.low_watermark_percent, 1);
    }

    #[test]
    fn global_config_seed_enables_filtering_by_default() {
        let parsed = parse_config(["vantage"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };

        let seed = config.global_config_seed().as_global_config();
        assert_eq!(seed.enabled, 1);
        assert_eq!(seed.flow_keys_live, 1);
    }

    #[test]
    fn global_config_seed_respects_flow_key_mode() {
        let parsed = parse_config(["vantage", "--flow-keys-mode", "legacy"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };

        let seed = config.global_config_seed().as_global_config();
        assert_eq!(seed.enabled, 1);
        assert_eq!(seed.flow_keys_live, 0);
    }

    #[test]
    fn essential_tenants_parse_mixed_formats() {
        let parsed = parse_config([
            "vantage",
            "--essential-tenant",
            "cg:42",
            "--essential-tenant",
            "7",
        ]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };

        assert!(config.essential_tenants.contains(&42));
        assert!(config.essential_tenants.contains(&7));
        assert_eq!(config.essential_tenants.len(), 2);
    }

    #[test]
    fn essential_tenants_can_be_parsed_from_env_csv() {
        temp_env::with_var("VANTAGE_ESSENTIAL_TENANTS", Some("cg:11,12"), || {
            let parsed = parse_config(["vantage"]);
            let Ok(config) = parsed else {
                panic!("config parsing should succeed");
            };
            assert!(config.essential_tenants.contains(&11));
            assert!(config.essential_tenants.contains(&12));
        });
    }
}
