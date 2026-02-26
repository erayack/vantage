use std::mem::size_of;

use aya::{
    Ebpf,
    maps::{MapData, RingBuf},
};
use thiserror::Error;
use tokio::io::{Interest, unix::AsyncFd};
use tracing::{info, warn};
use vantage_common::{DropEvent, DropReason, TenantKey};

const DROP_EVENTS_MAP: &str = "DROP_EVENTS";
const TENANT_KEY_OFFSET: usize = 0;
const TS_NS_OFFSET: usize = 8;
const REASON_OFFSET: usize = 16;

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
pub(crate) fn take_drop_event_ring(ebpf: &mut Ebpf) -> Result<RingBuf<MapData>, EventError> {
    let map = ebpf
        .take_map(DROP_EVENTS_MAP)
        .ok_or(EventError::MissingMap(DROP_EVENTS_MAP))?;
    let ring_buf = RingBuf::try_from(map)?;
    Ok(ring_buf)
}

/// Spawns a background task that consumes and logs sampled drop events.
///
/// # Errors
///
/// Returns `EventError` when preparing async readiness polling fails.
pub(crate) fn spawn_drop_event_consumer(
    ring_buf: RingBuf<MapData>,
    sample_n: u32,
) -> Result<(), EventError> {
    let sample_n = sample_n.max(1);
    let mut async_fd = AsyncFd::with_interest(ring_buf, Interest::READABLE)?;

    tokio::task::spawn(async move {
        let mut seen_events = 0_u64;
        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(guard) => guard,
                Err(error) => {
                    warn!(%error, "failed while waiting on drop-event ring buffer readiness");
                    break;
                }
            };

            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                if let Some(event) = decode_drop_event(&item) {
                    seen_events = seen_events.saturating_add(1);
                    if seen_events.is_multiple_of(u64::from(sample_n)) {
                        info!(
                            tenant = event.tenant,
                            reason = event.reason,
                            ts_ns = event.ts_ns,
                            "drop event"
                        );
                    }
                } else {
                    warn!(len = item.len(), "received malformed drop event payload");
                }
            }
            guard.clear_ready();
        }
    });

    Ok(())
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

    let tenant = u32::from_ne_bytes(
        payload[TENANT_KEY_OFFSET..TENANT_KEY_OFFSET + 4]
            .try_into()
            .ok()?,
    );
    let ts_ns = u64::from_ne_bytes(payload[TS_NS_OFFSET..TS_NS_OFFSET + 8].try_into().ok()?);
    let reason_code = *payload.get(REASON_OFFSET)?;

    Some(DecodedDropEvent {
        tenant,
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
