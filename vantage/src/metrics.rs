use prometheus::{Encoder, TextEncoder};
use thiserror::Error;
use vantage_common::{Counters, TenantKey};

use crate::{
    MetricsState,
    map_client::{MapClient, MapError},
};

#[derive(Debug, Error)]
pub(crate) enum MetricsError {
    #[error("map operation failed: {0}")]
    Map(#[from] MapError),
    #[error("failed to encode Prometheus metrics: {0}")]
    Encode(#[from] prometheus::Error),
}

/// Builds Prometheus text output from daemon and tenant counters.
///
/// # Errors
///
/// Returns `MetricsError` when map reads or metric encoding fail.
pub(crate) fn render_metrics(
    metrics: &MetricsState,
    maps: &MapClient,
) -> Result<Vec<u8>, MetricsError> {
    metrics.daemon_up.set(1);

    let metric_families = metrics.registry.gather();
    let mut payload = Vec::new();
    TextEncoder::new().encode(&metric_families, &mut payload)?;

    let counters = maps.collect_counters()?;
    append_counter_metrics(&mut payload, &counters);

    Ok(payload)
}

fn append_counter_metrics(payload: &mut Vec<u8>, counters: &[(TenantKey, Counters)]) {
    payload.extend_from_slice(
        b"# HELP vantage_tenant_pass_packets Total packets allowed for tenant.\n",
    );
    payload.extend_from_slice(b"# TYPE vantage_tenant_pass_packets counter\n");
    payload.extend_from_slice(
        b"# HELP vantage_tenant_drop_packets Total packets dropped for tenant.\n",
    );
    payload.extend_from_slice(b"# TYPE vantage_tenant_drop_packets counter\n");
    payload
        .extend_from_slice(b"# HELP vantage_tenant_pass_bytes Total bytes allowed for tenant.\n");
    payload.extend_from_slice(b"# TYPE vantage_tenant_pass_bytes counter\n");
    payload
        .extend_from_slice(b"# HELP vantage_tenant_drop_bytes Total bytes dropped for tenant.\n");
    payload.extend_from_slice(b"# TYPE vantage_tenant_drop_bytes counter\n");

    for (tenant, counters) in counters {
        payload.extend_from_slice(
            format!(
                "vantage_tenant_pass_packets{{tenant=\"{tenant}\"}} {}\n",
                counters.pass_pkts
            )
            .as_bytes(),
        );
        payload.extend_from_slice(
            format!(
                "vantage_tenant_drop_packets{{tenant=\"{tenant}\"}} {}\n",
                counters.drop_pkts
            )
            .as_bytes(),
        );
        payload.extend_from_slice(
            format!(
                "vantage_tenant_pass_bytes{{tenant=\"{tenant}\"}} {}\n",
                counters.pass_bytes
            )
            .as_bytes(),
        );
        payload.extend_from_slice(
            format!(
                "vantage_tenant_drop_bytes{{tenant=\"{tenant}\"}} {}\n",
                counters.drop_bytes
            )
            .as_bytes(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_metrics_use_real_newlines() {
        let mut payload = Vec::new();
        append_counter_metrics(
            &mut payload,
            &[(
                42,
                Counters {
                    pass_pkts: 1,
                    drop_pkts: 2,
                    pass_bytes: 3,
                    drop_bytes: 4,
                },
            )],
        );

        let text = String::from_utf8_lossy(&payload);
        assert!(text.contains("vantage_tenant_pass_packets{tenant=\"42\"} 1\n"));
        assert!(text.contains("vantage_tenant_drop_packets{tenant=\"42\"} 2\n"));
        assert!(text.contains("vantage_tenant_pass_bytes{tenant=\"42\"} 3\n"));
        assert!(text.contains("vantage_tenant_drop_bytes{tenant=\"42\"} 4\n"));
        assert!(!text.contains("\\n"));

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
}
