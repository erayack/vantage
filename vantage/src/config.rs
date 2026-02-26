use std::net::SocketAddr;

use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AttachDirection {
    Ingress,
    Egress,
    Both,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

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
}
