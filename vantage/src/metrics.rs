use std::{
    fmt::Write as _,
    fs, thread,
    time::{Duration, Instant},
};

use prometheus::{Encoder, TextEncoder};
use thiserror::Error;
use vantage_common::{Counters, TenantKey};

use crate::{
    MetricsState,
    map_client::{MapClient, MapError},
    tenant::{normalized_flow_key, proto_label, src_ip_label},
};

#[derive(Debug, Error)]
pub(crate) enum MetricsError {
    #[error("map operation failed: {0}")]
    Map(#[from] MapError),
    #[error("failed to encode Prometheus metrics: {0}")]
    Encode(#[from] prometheus::Error),
    #[error("CPU sampling task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("failed to read {path}: {source}")]
    ReadProc {
        path: &'static str,
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {reason}")]
    ParseProc { path: &'static str, reason: String },
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub(crate) struct CpuWindowSample {
    pub window_ms: u64,
    pub system_cpu_percent: f64,
    pub daemon_cpu_percent: f64,
}

/// Builds Prometheus text output from tenant counters in `COUNTERS_MAP`.
///
/// # Errors
///
/// Returns `MetricsError` when map reads fail.
pub(crate) fn render_metrics(maps: &MapClient, dimensional: bool) -> Result<String, MetricsError> {
    let counters = maps.collect_counters()?;
    Ok(append_counter_metrics(&counters, dimensional))
}

/// Builds Prometheus text output from daemon and tenant counters.
///
/// # Errors
///
/// Returns `MetricsError` when map reads or metric encoding fail.
pub(crate) fn render_metrics_payload(
    metrics: &MetricsState,
    maps: &MapClient,
    dimensional: bool,
) -> Result<Vec<u8>, MetricsError> {
    metrics.daemon_up.set(1);

    let metric_families = metrics.registry.gather();
    let mut payload = Vec::new();
    TextEncoder::new().encode(&metric_families, &mut payload)?;

    let counters = render_metrics(maps, dimensional)?;
    payload.extend_from_slice(counters.as_bytes());

    Ok(payload)
}

/// Samples CPU utilization over a fixed window using procfs cumulative jiffies.
///
/// # Errors
///
/// Returns `MetricsError` if procfs reads/parsing fail.
pub(crate) fn sample_cpu_window(window: Duration) -> Result<CpuWindowSample, MetricsError> {
    let start = ProcSnapshot::read()?;
    let started = Instant::now();
    thread::sleep(window);
    let end = ProcSnapshot::read()?;
    let elapsed = started.elapsed();

    compute_cpu_window_sample(start, end, elapsed)
}

/// Samples CPU utilization over a fixed window on a blocking thread.
///
/// # Errors
///
/// Returns `MetricsError` if task scheduling, procfs reads, or parsing fail.
pub(crate) async fn sample_cpu_window_async(
    window: Duration,
) -> Result<CpuWindowSample, MetricsError> {
    tokio::task::spawn_blocking(move || sample_cpu_window(window))
        .await
        .map_err(MetricsError::from)?
}

fn compute_cpu_window_sample(
    start: ProcSnapshot,
    end: ProcSnapshot,
    elapsed: Duration,
) -> Result<CpuWindowSample, MetricsError> {
    let total_delta = end.system_total.saturating_sub(start.system_total);
    let busy_delta = end.system_busy.saturating_sub(start.system_busy);
    let daemon_delta = end
        .daemon_user_system
        .saturating_sub(start.daemon_user_system);

    let system_cpu_percent = ratio_percent(busy_delta, total_delta)?;
    let daemon_cpu_percent = ratio_percent(daemon_delta, total_delta)?;

    Ok(CpuWindowSample {
        window_ms: elapsed.as_millis().try_into().unwrap_or(u64::MAX),
        system_cpu_percent,
        daemon_cpu_percent,
    })
}

fn ratio_percent(numerator: u64, denominator: u64) -> Result<f64, MetricsError> {
    if denominator == 0 {
        return Ok(0.0);
    }

    let scaled_basis_points = u128::from(numerator)
        .saturating_mul(10_000)
        .checked_div(u128::from(denominator))
        .unwrap_or(0);
    let scaled_u32 =
        u32::try_from(scaled_basis_points).map_err(|error| MetricsError::ParseProc {
            path: "cpu_window",
            reason: format!("scaled percent does not fit in u32: {error}"),
        })?;

    Ok(f64::from(scaled_u32) / 100.0)
}

#[derive(Debug, Clone, Copy)]
struct ProcSnapshot {
    system_total: u64,
    system_busy: u64,
    daemon_user_system: u64,
}

impl ProcSnapshot {
    fn read() -> Result<Self, MetricsError> {
        let (system_total, system_idle) = read_system_jiffies()?;
        let daemon_user_system = read_daemon_jiffies()?;
        Ok(Self {
            system_total,
            system_busy: system_total.saturating_sub(system_idle),
            daemon_user_system,
        })
    }
}

fn read_system_jiffies() -> Result<(u64, u64), MetricsError> {
    const PATH: &str = "/proc/stat";
    let text =
        fs::read_to_string(PATH).map_err(|source| MetricsError::ReadProc { path: PATH, source })?;
    parse_system_jiffies(&text)
}

fn parse_system_jiffies(text: &str) -> Result<(u64, u64), MetricsError> {
    const PATH: &str = "/proc/stat";
    let line = text
        .lines()
        .find(|line| line.starts_with("cpu "))
        .ok_or_else(|| MetricsError::ParseProc {
            path: PATH,
            reason: "missing aggregate cpu line".to_owned(),
        })?;

    let mut fields = line.split_whitespace();
    let _ = fields.next();
    let mut values = Vec::new();
    for token in fields {
        let parsed = token
            .parse::<u64>()
            .map_err(|error| MetricsError::ParseProc {
                path: PATH,
                reason: format!("invalid jiffy field '{token}': {error}"),
            })?;
        values.push(parsed);
    }

    if values.len() < 5 {
        return Err(MetricsError::ParseProc {
            path: PATH,
            reason: format!("expected at least 5 cpu fields, found {}", values.len()),
        });
    }

    let total = values.iter().copied().sum::<u64>();
    let idle = values[3].saturating_add(values[4]);
    Ok((total, idle))
}

fn read_daemon_jiffies() -> Result<u64, MetricsError> {
    const PATH: &str = "/proc/self/stat";
    let text =
        fs::read_to_string(PATH).map_err(|source| MetricsError::ReadProc { path: PATH, source })?;
    parse_daemon_jiffies(&text)
}

fn parse_daemon_jiffies(text: &str) -> Result<u64, MetricsError> {
    const PATH: &str = "/proc/self/stat";
    let close_paren = text.rfind(')').ok_or_else(|| MetricsError::ParseProc {
        path: PATH,
        reason: "missing command terminator ')'".to_owned(),
    })?;
    let rest = text
        .get(close_paren + 1..)
        .ok_or_else(|| MetricsError::ParseProc {
            path: PATH,
            reason: "missing stat fields after command".to_owned(),
        })?;
    let fields = rest.split_whitespace().collect::<Vec<_>>();
    if fields.len() <= 12 {
        return Err(MetricsError::ParseProc {
            path: PATH,
            reason: format!(
                "expected at least 13 fields after command, found {}",
                fields.len()
            ),
        });
    }

    let utime = fields[11]
        .parse::<u64>()
        .map_err(|error| MetricsError::ParseProc {
            path: PATH,
            reason: format!("invalid utime field: {error}"),
        })?;
    let stime = fields[12]
        .parse::<u64>()
        .map_err(|error| MetricsError::ParseProc {
            path: PATH,
            reason: format!("invalid stime field: {error}"),
        })?;
    Ok(utime.saturating_add(stime))
}

fn append_counter_metrics(counters: &[(TenantKey, Counters)], dimensional: bool) -> String {
    let mut payload = String::new();
    payload.push_str("# HELP vantage_tenant_pass_packets Total packets allowed by policy.\n");
    payload.push_str("# TYPE vantage_tenant_pass_packets counter\n");
    payload.push_str("# HELP vantage_tenant_drop_packets Total packets dropped by policy.\n");
    payload.push_str("# TYPE vantage_tenant_drop_packets counter\n");
    payload.push_str("# HELP vantage_tenant_pass_bytes Total bytes allowed by policy.\n");
    payload.push_str("# TYPE vantage_tenant_pass_bytes counter\n");
    payload.push_str("# HELP vantage_tenant_drop_bytes Total bytes dropped by policy.\n");
    payload.push_str("# TYPE vantage_tenant_drop_bytes counter\n");

    if dimensional {
        for (tenant, counters) in counters {
            let flow_key = normalized_flow_key(*tenant);
            let dst_port = if tenant.dst_port == 0 {
                "*".to_owned()
            } else {
                tenant.dst_port.to_string()
            };
            let _ = writeln!(
                payload,
                "vantage_tenant_pass_packets{{src_ip=\"{}\",dst_port=\"{}\",proto=\"{}\",flow=\"{}\"}} {}",
                src_ip_label(tenant.src_ip),
                dst_port,
                proto_label(tenant.proto),
                flow_key,
                counters.pass_pkts
            );
            let _ = writeln!(
                payload,
                "vantage_tenant_drop_packets{{src_ip=\"{}\",dst_port=\"{}\",proto=\"{}\",flow=\"{}\"}} {}",
                src_ip_label(tenant.src_ip),
                dst_port,
                proto_label(tenant.proto),
                flow_key,
                counters.drop_pkts
            );
            let _ = writeln!(
                payload,
                "vantage_tenant_pass_bytes{{src_ip=\"{}\",dst_port=\"{}\",proto=\"{}\",flow=\"{}\"}} {}",
                src_ip_label(tenant.src_ip),
                dst_port,
                proto_label(tenant.proto),
                flow_key,
                counters.pass_bytes
            );
            let _ = writeln!(
                payload,
                "vantage_tenant_drop_bytes{{src_ip=\"{}\",dst_port=\"{}\",proto=\"{}\",flow=\"{}\"}} {}",
                src_ip_label(tenant.src_ip),
                dst_port,
                proto_label(tenant.proto),
                flow_key,
                counters.drop_bytes
            );
        }
        return payload;
    }

    let totals = counters.iter().fold(
        Counters {
            pass_pkts: 0,
            drop_pkts: 0,
            pass_bytes: 0,
            drop_bytes: 0,
        },
        |mut acc, (_, current)| {
            acc.pass_pkts = acc.pass_pkts.saturating_add(current.pass_pkts);
            acc.drop_pkts = acc.drop_pkts.saturating_add(current.drop_pkts);
            acc.pass_bytes = acc.pass_bytes.saturating_add(current.pass_bytes);
            acc.drop_bytes = acc.drop_bytes.saturating_add(current.drop_bytes);
            acc
        },
    );
    let _ = writeln!(payload, "vantage_tenant_pass_packets {}", totals.pass_pkts);
    let _ = writeln!(payload, "vantage_tenant_drop_packets {}", totals.drop_pkts);
    let _ = writeln!(payload, "vantage_tenant_pass_bytes {}", totals.pass_bytes);
    let _ = writeln!(payload, "vantage_tenant_drop_bytes {}", totals.drop_bytes);

    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn fixture_snapshot(
        system_total: u64,
        system_busy: u64,
        daemon_user_system: u64,
    ) -> ProcSnapshot {
        ProcSnapshot {
            system_total,
            system_busy,
            daemon_user_system,
        }
    }

    #[test]
    fn dimensional_tenant_metrics_emit_flow_labels() {
        let payload = append_counter_metrics(
            &[(
                TenantKey {
                    src_ip: 167_838_211,
                    dst_port: 0,
                    proto: 0,
                    _pad: 0,
                },
                Counters {
                    pass_pkts: 1,
                    drop_pkts: 2,
                    pass_bytes: 3,
                    drop_bytes: 4,
                },
            )],
            true,
        );

        let text = payload;
        assert!(
            text.contains(
                "vantage_tenant_pass_packets{src_ip=\"10.1.2.3\",dst_port=\"*\",proto=\"*\",flow=\"src=10.1.2.3|proto=*|dport=*\"} 1\n"
            )
        );
        assert!(
            text.contains(
                "vantage_tenant_drop_packets{src_ip=\"10.1.2.3\",dst_port=\"*\",proto=\"*\",flow=\"src=10.1.2.3|proto=*|dport=*\"} 2\n"
            )
        );
        assert!(!text.contains("\\n"));
    }

    #[test]
    fn aggregated_metrics_disable_flow_dimensions() {
        let payload = append_counter_metrics(
            &[(
                TenantKey {
                    src_ip: 42,
                    dst_port: 53,
                    proto: 17,
                    _pad: 0,
                },
                Counters {
                    pass_pkts: 1,
                    drop_pkts: 2,
                    pass_bytes: 3,
                    drop_bytes: 4,
                },
            )],
            false,
        );

        let text = payload;
        assert!(text.contains("vantage_tenant_pass_packets 1\n"));
        assert!(text.contains("vantage_tenant_drop_packets 2\n"));
        assert!(text.contains("vantage_tenant_pass_bytes 3\n"));
        assert!(text.contains("vantage_tenant_drop_bytes 4\n"));
        assert!(!text.contains("{src_ip="));

        let mut parsed_samples = 0_u32;
        for line in text.lines() {
            if line.starts_with("vantage_tenant_") {
                let mut parts = line.split_whitespace();
                let name = parts.next();
                let value = parts.next();
                assert!(
                    parts.next().is_none(),
                    "sample line should contain two fields"
                );

                assert!(name.is_some(), "sample name should be present");
                let Some(raw_value) = value else {
                    panic!("sample value should be present");
                };
                let parsed = raw_value.parse::<u64>();
                assert!(parsed.is_ok(), "sample value should parse as u64");
                parsed_samples = parsed_samples.saturating_add(1);
            }
        }
        assert_eq!(parsed_samples, 4);
    }

    #[test]
    fn aggregated_metrics_sum_multiple_tenants() {
        let payload = append_counter_metrics(
            &[
                (
                    TenantKey {
                        src_ip: 1,
                        dst_port: 80,
                        proto: 6,
                        _pad: 0,
                    },
                    Counters {
                        pass_pkts: 10,
                        drop_pkts: 2,
                        pass_bytes: 1_000,
                        drop_bytes: 200,
                    },
                ),
                (
                    TenantKey {
                        src_ip: 2,
                        dst_port: 53,
                        proto: 17,
                        _pad: 0,
                    },
                    Counters {
                        pass_pkts: 3,
                        drop_pkts: 4,
                        pass_bytes: 300,
                        drop_bytes: 400,
                    },
                ),
            ],
            false,
        );

        assert!(payload.contains("vantage_tenant_pass_packets 13\n"));
        assert!(payload.contains("vantage_tenant_drop_packets 6\n"));
        assert!(payload.contains("vantage_tenant_pass_bytes 1300\n"));
        assert!(payload.contains("vantage_tenant_drop_bytes 600\n"));
    }

    #[test]
    fn parse_system_jiffies_reads_total_and_idle() {
        let parsed = parse_system_jiffies("cpu  10 20 30 40 50 60 70 80 90 100\n");
        let Ok((total, idle)) = parsed else {
            panic!("cpu stat line should parse");
        };
        assert_eq!(total, 550);
        assert_eq!(idle, 90);
    }

    #[test]
    fn parse_daemon_jiffies_reads_utime_stime_with_spaces_in_comm() {
        let parsed = parse_daemon_jiffies("1234 (vantage worker) R 1 2 3 4 5 6 7 8 9 10 11 12 13");
        let Ok(total) = parsed else {
            panic!("self stat line should parse");
        };
        assert_eq!(total, 23);
    }

    #[test]
    fn cpu_window_sample_uses_fixture_deltas() {
        let start = fixture_snapshot(1_000, 700, 15);
        let end = fixture_snapshot(1_100, 750, 20);

        let sample = compute_cpu_window_sample(start, end, Duration::from_millis(500));
        let Ok(sample) = sample else {
            panic!("fixture snapshot should compute");
        };

        assert_eq!(sample.window_ms, 500);
        assert!((sample.system_cpu_percent - 50.0).abs() < f64::EPSILON);
        assert!((sample.daemon_cpu_percent - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn cpu_window_sample_handles_zero_total_delta() {
        let snapshot = fixture_snapshot(10_000, 6_000, 100);
        let sample = compute_cpu_window_sample(snapshot, snapshot, Duration::from_millis(250));
        let Ok(sample) = sample else {
            panic!("zero delta should compute");
        };

        assert_eq!(sample.window_ms, 250);
        assert!((sample.system_cpu_percent - 0.0).abs() < f64::EPSILON);
        assert!((sample.daemon_cpu_percent - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn cpu_window_sample_handles_large_deltas_without_overflow_errors() {
        let start = fixture_snapshot(10, 5, 2);
        let end = fixture_snapshot(u64::from(u32::MAX) + 100, 10, 2);

        let sample = compute_cpu_window_sample(start, end, Duration::from_millis(500));
        let Ok(sample) = sample else {
            panic!("large deltas should compute");
        };

        assert!(sample.system_cpu_percent >= 0.0);
    }
}
