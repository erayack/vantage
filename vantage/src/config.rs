use std::net::SocketAddr;

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
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub(crate) iface: String,
    pub(crate) bind_addr: SocketAddr,
    pub(crate) attach_ingress: bool,
    pub(crate) attach_egress: bool,
    pub(crate) drop_event_log_sample_n: u32,
    pub(crate) drop_event_log_enabled: bool,
    pub(crate) cpu_window_ms: u64,
    pub(crate) metrics_dimensions: MetricsDimensions,
    pub(crate) flow_keys_mode: FlowKeysMode,
    pub(crate) debug_top_tenants: usize,
    pub(crate) policy_validation_mode: PolicyValidationMode,
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

        Self {
            iface: cli.iface,
            bind_addr: cli.bind_addr,
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
        }
    }

    pub(crate) const fn global_config_seed(&self) -> GlobalConfigSeed {
        GlobalConfigSeed {
            enabled: true,
            flow_keys_live: self.flow_keys_mode.live(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, MetricsDimensions, PolicyValidationMode};

    #[test]
    fn attach_direction_from_env_is_respected() {
        temp_env::with_var("VANTAGE_ATTACH_DIRECTION", Some("both"), || {
            let parsed = Config::try_from_iter(["vantage"]);
            let Ok(config) = parsed else {
                panic!("config parsing should succeed");
            };
            assert!(config.attach_ingress);
            assert!(config.attach_egress);
        });
    }

    #[test]
    fn default_direction_is_ingress_only() {
        let parsed = Config::try_from_iter(["vantage"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert!(config.attach_ingress);
        assert!(!config.attach_egress);
    }

    #[test]
    fn drop_event_sample_is_clamped_to_one() {
        let parsed = Config::try_from_iter(["vantage", "--drop-event-sample-n", "0"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.drop_event_log_sample_n, 1);
    }

    #[test]
    fn cli_flag_overrides_env_value() {
        temp_env::with_var("VANTAGE_ATTACH_DIRECTION", Some("egress"), || {
            let parsed = Config::try_from_iter(["vantage", "--direction", "ingress"]);
            let Ok(config) = parsed else {
                panic!("config parsing should succeed");
            };
            assert!(config.attach_ingress);
            assert!(!config.attach_egress);
        });
    }

    #[test]
    fn cpu_window_ms_uses_default() {
        let parsed = Config::try_from_iter(["vantage"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.cpu_window_ms, 5_000);
    }

    #[test]
    fn cpu_window_ms_is_clamped_to_one() {
        let parsed = Config::try_from_iter(["vantage", "--cpu-window-ms", "0"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.cpu_window_ms, 1);
    }

    #[test]
    fn debug_top_tenants_uses_default() {
        let parsed = Config::try_from_iter(["vantage"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.debug_top_tenants, 10);
    }

    #[test]
    fn debug_top_tenants_is_clamped_to_upper_bound() {
        let parsed = Config::try_from_iter(["vantage", "--debug-top-tenants", "500"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.debug_top_tenants, 100);
    }

    #[test]
    fn debug_top_tenants_is_clamped_to_lower_bound() {
        let parsed = Config::try_from_iter(["vantage", "--debug-top-tenants", "0"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.debug_top_tenants, 1);
    }

    #[test]
    fn metrics_dimensions_can_be_enabled() {
        let parsed = Config::try_from_iter(["vantage", "--metrics-dimensional-enabled"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.metrics_dimensions, MetricsDimensions::PerFlow);
    }

    #[test]
    fn flow_keys_mode_defaults_to_live() {
        let parsed = Config::try_from_iter(["vantage"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert!(config.flow_keys_mode.live());
    }

    #[test]
    fn flow_keys_mode_can_disable_flow_keys() {
        let parsed = Config::try_from_iter(["vantage", "--flow-keys-mode", "legacy"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert!(!config.flow_keys_mode.live());
    }

    #[test]
    fn policy_validation_mode_defaults_to_permissive() {
        let parsed = Config::try_from_iter(["vantage"]);
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
        let parsed = Config::try_from_iter(["vantage", "--policy-validation-mode", "strict"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };
        assert_eq!(config.policy_validation_mode, PolicyValidationMode::Strict);
        assert!(config.policy_validation_mode.strict());
    }

    #[test]
    fn global_config_seed_enables_filtering_by_default() {
        let parsed = Config::try_from_iter(["vantage"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };

        let seed = config.global_config_seed().as_global_config();
        assert_eq!(seed.enabled, 1);
        assert_eq!(seed.flow_keys_live, 1);
    }

    #[test]
    fn global_config_seed_respects_flow_key_mode() {
        let parsed = Config::try_from_iter(["vantage", "--flow-keys-mode", "legacy"]);
        let Ok(config) = parsed else {
            panic!("config parsing should succeed");
        };

        let seed = config.global_config_seed().as_global_config();
        assert_eq!(seed.enabled, 1);
        assert_eq!(seed.flow_keys_live, 0);
    }
}
