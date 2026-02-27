use std::mem::size_of;

use aya::{
    Ebpf,
    maps::{MapData, RingBuf},
};
use thiserror::Error;
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::watch,
};
use tracing::{info, warn};
use vantage_common::{
    DROP_EVENT_REASON_OFFSET, DROP_EVENT_TENANT_KEY_OFFSET, DROP_EVENT_TS_NS_OFFSET, DropEvent,
    DropReason, TenantKey,
};

use crate::tenant::{normalized_flow_key, proto_label, src_ip_label};

const DROP_EVENTS_MAP: &str = "DROP_EVENTS";
const MAX_EVENTS_PER_WAKE: usize = 1024;

pub(crate) type RingBufferHandle = RingBuf<MapData>;

#[derive(Debug, Error)]
pub(crate) enum EventError {
    #[error("required map '{0}' is missing")]
    MissingMap(&'static str),
    #[error("eBPF map operation failed: {0}")]
    Map(#[from] aya::maps::MapError),
    #[error("failed to create async fd for ring buffer: {0}")]
    AsyncFd(#[from] std::io::Error),
}

/// Takes ownership of the `DROP_EVENTS` ring buffer map from the loaded eBPF object.
///
/// # Errors
///
/// Returns `EventError` when the map is missing or cannot be converted to a typed ring buffer.
pub(crate) fn take_drop_event_ring(ebpf: &mut Ebpf) -> Result<RingBufferHandle, EventError> {
    let map = ebpf
        .take_map(DROP_EVENTS_MAP)
        .ok_or(EventError::MissingMap(DROP_EVENTS_MAP))?;
    let ring_buf = RingBuf::try_from(map)?;
    Ok(ring_buf)
}

/// Runs a ring buffer consumer until shutdown is requested.
///
/// # Errors
///
/// Returns `EventError` when preparing async readiness polling fails.
pub(crate) async fn run_drop_event_consumer(
    ring: RingBufferHandle,
    mut shutdown: watch::Receiver<bool>,
    log_sample_n: u32,
) -> Result<(), EventError> {
    let log_sample_n = log_sample_n.max(1);
    let mut async_fd = AsyncFd::with_interest(ring, Interest::READABLE)?;
    let mut seen_events = 0_u64;

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if should_stop_after_shutdown_change(changed.is_err(), *shutdown.borrow()) {
                    break;
                }
            }
            readiness = async_fd.readable_mut() => {
                let mut guard = match readiness {
                    Ok(guard) => guard,
                    Err(error) => {
                        warn!(%error, "failed while waiting on drop-event ring buffer readiness");
                        break;
                    }
                };

                let ring_buf = guard.get_inner_mut();
                let mut processed = 0_usize;
                let mut skipped = 0_usize;
                while let Some(item) = ring_buf.next() {
                    if processed < MAX_EVENTS_PER_WAKE {
                        if let Some(event) = decode_drop_event(&item) {
                            seen_events = seen_events.saturating_add(1);
                            if seen_events.is_multiple_of(u64::from(log_sample_n)) {
                                let flow_key = normalized_flow_key(event.tenant);
                                info!(
                                    tenant = ?event.tenant,
                                    flow_key = %flow_key,
                                    src_ip = %src_ip_label(event.tenant.src_ip),
                                    proto = proto_label(event.tenant.proto),
                                    dst_port = event.tenant.dst_port,
                                    reason = event.reason,
                                    ts_ns = event.ts_ns,
                                    log_sample_n,
                                    "drop event"
                                );
                            }
                        } else {
                            warn!(len = item.len(), "received malformed drop event payload");
                        }
                    } else {
                        skipped = skipped.saturating_add(1);
                    }

                    processed = processed.saturating_add(1);
                }

                if skipped > 0 {
                    warn!(skipped, "drop-event consumer skipped buffered events due to backpressure");
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}

/// Spawns a background task that consumes and logs sampled drop events.
pub(crate) fn spawn_drop_event_consumer(
    ring_buf: RingBufferHandle,
    shutdown: watch::Receiver<bool>,
    log_sample_n: u32,
) {
    tokio::task::spawn(async move {
        if let Err(error) = run_drop_event_consumer(ring_buf, shutdown, log_sample_n).await {
            warn!(%error, "drop-event consumer stopped with error");
        }
    });
}

const fn should_stop_after_shutdown_change(channel_closed: bool, shutdown_requested: bool) -> bool {
    channel_closed || shutdown_requested
}

struct DecodedDropEvent {
    tenant: TenantKey,
    ts_ns: u64,
    reason: &'static str,
}

fn decode_drop_event(payload: &[u8]) -> Option<DecodedDropEvent> {
    if payload.len() != size_of::<DropEvent>() {
        return None;
    }

    let src_ip = u32::from_ne_bytes(
        payload[DROP_EVENT_TENANT_KEY_OFFSET..DROP_EVENT_TENANT_KEY_OFFSET + 4]
            .try_into()
            .ok()?,
    );
    let http_path_hash = u32::from_ne_bytes(
        payload[DROP_EVENT_TENANT_KEY_OFFSET + 4..DROP_EVENT_TENANT_KEY_OFFSET + 8]
            .try_into()
            .ok()?,
    );
    let dst_port = u16::from_ne_bytes(
        payload[DROP_EVENT_TENANT_KEY_OFFSET + 8..DROP_EVENT_TENANT_KEY_OFFSET + 10]
            .try_into()
            .ok()?,
    );
    let proto = *payload.get(DROP_EVENT_TENANT_KEY_OFFSET + 10)?;
    let ts_ns = u64::from_ne_bytes(
        payload[DROP_EVENT_TS_NS_OFFSET..DROP_EVENT_TS_NS_OFFSET + 8]
            .try_into()
            .ok()?,
    );
    let reason_code = *payload.get(DROP_EVENT_REASON_OFFSET)?;

    Some(DecodedDropEvent {
        tenant: TenantKey {
            src_ip,
            http_path_hash,
            dst_port,
            proto,
            _pad: 0,
        },
        ts_ns,
        reason: reason_name(reason_code),
    })
}

const fn reason_name(reason: u8) -> &'static str {
    if reason == DropReason::NoTokens.as_u8() {
        "no_tokens"
    } else if reason == DropReason::NoPolicy.as_u8() {
        "no_policy"
    } else if reason == DropReason::ParseFail.as_u8() {
        "parse_fail"
    } else if reason == DropReason::StateStoreFail.as_u8() {
        "state_store_fail"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use std::{mem::size_of, time::Duration};

    use tokio::sync::watch;
    use vantage_common::{
        DROP_EVENT_REASON_OFFSET, DROP_EVENT_TENANT_KEY_OFFSET, DROP_EVENT_TS_NS_OFFSET, DropEvent,
        DropReason, TenantKey,
    };

    use super::{decode_drop_event, should_stop_after_shutdown_change};

    #[tokio::test]
    async fn shutdown_channel_stays_open_while_sender_is_retained() {
        let (tx, mut rx) = watch::channel(false);

        let timed = tokio::time::timeout(Duration::from_millis(10), rx.changed()).await;
        assert!(
            timed.is_err(),
            "receiver should remain pending while sender is retained without updates"
        );

        drop(tx);
    }

    #[tokio::test]
    async fn shutdown_channel_reports_closed_when_sender_is_dropped() {
        let (tx, mut rx) = watch::channel(false);
        drop(tx);

        let changed = rx.changed().await;
        assert!(
            should_stop_after_shutdown_change(changed.is_err(), *rx.borrow()),
            "closed shutdown channel should stop the consumer loop"
        );
    }

    #[test]
    fn drop_event_decode_round_trips_contract_layout() {
        let event = DropEvent {
            ts_ns: 1234,
            tenant_key: TenantKey {
                src_ip: 0x0a00_0001,
                http_path_hash: 0x1234_abcd,
                dst_port: 443,
                proto: 6,
                _pad: 0,
            },
            reason: DropReason::NoTokens.as_u8(),
            _pad: [0; 7],
        };
        let mut payload = [0_u8; size_of::<DropEvent>()];
        payload[DROP_EVENT_TS_NS_OFFSET..DROP_EVENT_TS_NS_OFFSET + 8]
            .copy_from_slice(&event.ts_ns.to_ne_bytes());
        payload[DROP_EVENT_TENANT_KEY_OFFSET..DROP_EVENT_TENANT_KEY_OFFSET + 4]
            .copy_from_slice(&event.tenant_key.src_ip.to_ne_bytes());
        payload[DROP_EVENT_TENANT_KEY_OFFSET + 4..DROP_EVENT_TENANT_KEY_OFFSET + 8]
            .copy_from_slice(&event.tenant_key.http_path_hash.to_ne_bytes());
        payload[DROP_EVENT_TENANT_KEY_OFFSET + 8..DROP_EVENT_TENANT_KEY_OFFSET + 10]
            .copy_from_slice(&event.tenant_key.dst_port.to_ne_bytes());
        payload[DROP_EVENT_TENANT_KEY_OFFSET + 10] = event.tenant_key.proto;
        payload[DROP_EVENT_REASON_OFFSET] = event.reason;

        let decoded = decode_drop_event(&payload);
        let Some(decoded) = decoded else {
            panic!("drop event payload should decode");
        };

        assert_eq!(decoded.tenant, event.tenant_key);
        assert_eq!(decoded.ts_ns, event.ts_ns);
        assert_eq!(decoded.reason, "no_tokens");
    }

    #[test]
    fn drop_event_offsets_match_shared_contract() {
        assert_eq!(size_of::<DropEvent>(), 32);
        assert_eq!(DROP_EVENT_TS_NS_OFFSET, 0);
        assert_eq!(DROP_EVENT_TENANT_KEY_OFFSET, 8);
        assert_eq!(
            DROP_EVENT_REASON_OFFSET,
            DROP_EVENT_TENANT_KEY_OFFSET + size_of::<TenantKey>()
        );
    }
}
