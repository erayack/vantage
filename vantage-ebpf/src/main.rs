#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_F_NO_PREALLOC, TC_ACT_OK, TC_ACT_SHOT, bpf_spin_lock as BpfSpinLock},
    helpers::{bpf_ktime_get_ns, generated},
    macros::{classifier, map},
    maps::{HashMap, RingBuf},
    programs::TcContext,
};
use vantage_common::{Counters, DropEvent, DropReason, Policy, TenantKey, TokenState};

const HASH_MAP_MAX_ENTRIES: u32 = 4096;
const DROP_EVENTS_BYTES: u32 = 1 << 17;
const ETHERNET_HEADER_LEN: usize = 14;
const ETHER_TYPE_OFFSET: usize = 12;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_VERSION: u8 = 4;
const IPV4_VERSION_IHL_OFFSET: usize = ETHERNET_HEADER_LEN;
const IPV4_SRC_ADDR_OFFSET: usize = ETHERNET_HEADER_LEN + 12;
const NANOS_PER_SEC: u64 = 1_000_000_000;
const DROP_EVENT_SAMPLE_EVERY: u64 = 64;
const NO_PREALLOC_MAP_FLAGS: u32 = BPF_F_NO_PREALLOC;

#[repr(C)]
struct LockedTokenState {
    lock: BpfSpinLock,
    state: TokenState,
}

#[repr(C)]
struct LockedCounters {
    lock: BpfSpinLock,
    counters: Counters,
}

#[map]
static POLICY_MAP: HashMap<TenantKey, Policy> =
    HashMap::<TenantKey, Policy>::with_max_entries(HASH_MAP_MAX_ENTRIES, NO_PREALLOC_MAP_FLAGS);

#[map]
#[allow(dead_code)]
static STATE_MAP: HashMap<TenantKey, LockedTokenState> =
    HashMap::<TenantKey, LockedTokenState>::with_max_entries(
        HASH_MAP_MAX_ENTRIES,
        NO_PREALLOC_MAP_FLAGS,
    );

#[map]
#[allow(dead_code)]
static COUNTERS_MAP: HashMap<TenantKey, LockedCounters> =
    HashMap::<TenantKey, LockedCounters>::with_max_entries(
        HASH_MAP_MAX_ENTRIES,
        NO_PREALLOC_MAP_FLAGS,
    );

#[map]
#[allow(dead_code)]
static DROP_EVENTS: RingBuf = RingBuf::with_byte_size(DROP_EVENTS_BYTES, 0);

#[classifier]
pub fn vantage_tc(ctx: TcContext) -> i32 {
    match try_vantage_tc(&ctx) {
        Ok(verdict) => verdict,
        Err(()) => TC_ACT_OK,
    }
}

fn try_vantage_tc(ctx: &TcContext) -> Result<i32, ()> {
    let now_ns = monotonic_now_ns();
    let pkt_len = u64::from(ctx.len());

    let Some(tenant_key) = tenant_key_from_packet(ctx) else {
        // Fail-open on parse failure.
        return Ok(TC_ACT_OK);
    };

    let Some(policy) = read_policy(tenant_key) else {
        update_counters(tenant_key, pkt_len, true);
        return Ok(TC_ACT_OK);
    };

    if policy.enabled == 0 {
        update_counters(tenant_key, pkt_len, true);
        return Ok(TC_ACT_OK);
    }

    let passed = match decide_and_store_state(tenant_key, now_ns, &policy) {
        Ok(passed) => passed,
        Err(()) => {
            let drop_pkts = update_counters(tenant_key, pkt_len, false);
            maybe_emit_drop_event(tenant_key, now_ns, DropReason::StateStoreFail, drop_pkts);
            return Ok(TC_ACT_SHOT);
        }
    };
    let drop_pkts = update_counters(tenant_key, pkt_len, passed);
    if passed {
        Ok(TC_ACT_OK)
    } else {
        maybe_emit_drop_event(tenant_key, now_ns, DropReason::NoTokens, drop_pkts);
        Ok(TC_ACT_SHOT)
    }
}

fn tenant_key_from_packet(ctx: &TcContext) -> Option<TenantKey> {
    let packet_len = usize::try_from(ctx.len()).ok()?;
    if packet_len < ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN {
        return None;
    }

    let ether_type_hi = ctx.load::<u8>(ETHER_TYPE_OFFSET).ok()?;
    let ether_type_lo = ctx.load::<u8>(ETHER_TYPE_OFFSET + 1).ok()?;
    if ether_type_hi != 0x08 || ether_type_lo != 0x00 {
        return None;
    }

    let version_ihl = ctx.load::<u8>(IPV4_VERSION_IHL_OFFSET).ok()?;
    if version_ihl >> 4 != IPV4_VERSION {
        return None;
    }

    let ihl_words = version_ihl & 0x0f;
    if ihl_words < 5 {
        return None;
    }

    let ip_header_len = usize::from(ihl_words) * 4;
    if packet_len < ETHERNET_HEADER_LEN + ip_header_len {
        return None;
    }

    let src_ip = ctx.load::<u32>(IPV4_SRC_ADDR_OFFSET).ok()?;
    Some(u32::from_be(src_ip))
}

fn apply_token_bucket(now_ns: u64, policy: &Policy, state: &mut TokenState) -> bool {
    if policy.enabled == 0 {
        state.last_refill_ns = now_ns;
        return true;
    }

    if policy.burst_tokens == 0 {
        state.last_refill_ns = now_ns;
        state.tokens = 0;
        return false;
    }

    state.tokens = state.tokens.min(policy.burst_tokens);
    refill_tokens(now_ns, policy, state);

    if state.tokens == 0 {
        return false;
    }

    state.tokens = state.tokens.saturating_sub(1);
    true
}

#[allow(unsafe_code)]
fn read_policy(key: TenantKey) -> Option<Policy> {
    // SAFETY: The map value is copied out immediately and never held across
    // helper calls, avoiding aliasing/lifetime pitfalls of raw map pointers.
    unsafe { POLICY_MAP.get(&key).copied() }
}

fn initial_state(policy: &Policy, now_ns: u64) -> TokenState {
    TokenState {
        tokens: policy.burst_tokens,
        last_refill_ns: now_ns,
    }
}

#[allow(unsafe_code)]
fn decide_and_store_state(key: TenantKey, now_ns: u64, policy: &Policy) -> Result<bool, ()> {
    if let Some(state_ptr) = STATE_MAP.get_ptr_mut(&key) {
        // SAFETY: Pointer originates from BPF map lookup for `key` and is used
        // only within this function invocation.
        let state = unsafe { &mut *state_ptr };
        // SAFETY: The lock lives in a BPF map value and guards only its owning
        // value's critical section.
        unsafe { generated::bpf_spin_lock(&mut state.lock) };
        let passed = apply_token_bucket(now_ns, policy, &mut state.state);
        // SAFETY: Matches lock acquisition above in the same critical section.
        unsafe { generated::bpf_spin_unlock(&mut state.lock) };
        return Ok(passed);
    }

    let mut state = initial_state(policy, now_ns);
    let passed = apply_token_bucket(now_ns, policy, &mut state);
    let state = LockedTokenState {
        lock: BpfSpinLock { val: 0 },
        state,
    };
    STATE_MAP.insert(&key, &state, 0).map_err(|_| ())?;
    Ok(passed)
}

fn refill_tokens(now_ns: u64, policy: &Policy, state: &mut TokenState) {
    if policy.rate_tokens_per_sec == 0 {
        state.last_refill_ns = now_ns;
        return;
    }

    // Keep arithmetic linker-friendly for eBPF: avoid wide multiply paths that
    // may lower to unsupported compiler builtins.
    let effective_rate = policy.rate_tokens_per_sec.min(NANOS_PER_SEC);
    let nanos_per_token = NANOS_PER_SEC / effective_rate;
    if nanos_per_token == 0 {
        state.tokens = policy.burst_tokens;
        state.last_refill_ns = now_ns;
        return;
    }

    let elapsed_ns = now_ns.saturating_sub(state.last_refill_ns);
    let refill_tokens = elapsed_ns / nanos_per_token;
    if refill_tokens == 0 {
        return;
    }

    state.tokens = state
        .tokens
        .saturating_add(refill_tokens)
        .min(policy.burst_tokens);
    state.last_refill_ns = now_ns;
}

#[allow(unsafe_code)]
fn update_counters(key: TenantKey, pkt_len: u64, passed: bool) -> u64 {
    if let Some(counters_ptr) = COUNTERS_MAP.get_ptr_mut(&key) {
        // SAFETY: Pointer originates from BPF map lookup for `key` and is used
        // only within this function invocation.
        let counters = unsafe { &mut *counters_ptr };
        // SAFETY: The lock lives in a BPF map value and guards only its owning
        // value's critical section.
        unsafe { generated::bpf_spin_lock(&mut counters.lock) };
        if passed {
            counters.counters.pass_pkts = counters.counters.pass_pkts.saturating_add(1);
            counters.counters.pass_bytes = counters.counters.pass_bytes.saturating_add(pkt_len);
        } else {
            counters.counters.drop_pkts = counters.counters.drop_pkts.saturating_add(1);
            counters.counters.drop_bytes = counters.counters.drop_bytes.saturating_add(pkt_len);
        }
        let drop_pkts = counters.counters.drop_pkts;
        // SAFETY: Matches lock acquisition above in the same critical section.
        unsafe { generated::bpf_spin_unlock(&mut counters.lock) };
        return drop_pkts;
    }

    let mut counters = Counters {
        pass_pkts: 0,
        drop_pkts: 0,
        pass_bytes: 0,
        drop_bytes: 0,
    };
    if passed {
        counters.pass_pkts = 1;
        counters.pass_bytes = pkt_len;
    } else {
        counters.drop_pkts = 1;
        counters.drop_bytes = pkt_len;
    }
    let counters = LockedCounters {
        lock: BpfSpinLock { val: 0 },
        counters,
    };
    let _ = COUNTERS_MAP.insert(&key, &counters, 0);
    counters.counters.drop_pkts
}

fn maybe_emit_drop_event(key: TenantKey, now_ns: u64, reason: DropReason, drop_pkts: u64) {
    if drop_pkts == 0 || (drop_pkts & (DROP_EVENT_SAMPLE_EVERY - 1)) != 0 {
        return;
    }

    let event = DropEvent {
        tenant_key: key,
        ts_ns: now_ns,
        reason: reason.as_u8(),
        _pad: [0; 7],
    };

    let _ = DROP_EVENTS.output::<DropEvent>(event, 0);
}

#[allow(unsafe_code)]
fn monotonic_now_ns() -> u64 {
    // SAFETY: `bpf_ktime_get_ns` is a pure BPF helper that returns monotonic
    // nanoseconds and does not require additional pointer validity guarantees.
    unsafe { bpf_ktime_get_ns() }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(rate_tokens_per_sec: u64, burst_tokens: u64) -> Policy {
        Policy {
            rate_tokens_per_sec,
            burst_tokens,
            enabled: 1,
            _pad: [0; 7],
        }
    }

    #[test]
    fn no_rate_never_refills() {
        let policy = policy(0, 8);
        let mut state = TokenState {
            tokens: 0,
            last_refill_ns: 1,
        };

        refill_tokens(1 + (5 * NANOS_PER_SEC), &policy, &mut state);

        assert_eq!(state.tokens, 0);
    }

    #[test]
    fn refill_respects_rate_and_burst_cap() {
        let policy = policy(10, 5);
        let mut state = TokenState {
            tokens: 1,
            last_refill_ns: 0,
        };

        refill_tokens(NANOS_PER_SEC, &policy, &mut state);

        assert_eq!(state.tokens, 5);
    }

    #[test]
    fn token_bucket_drops_when_empty() {
        let policy = policy(1, 1);
        let mut state = TokenState {
            tokens: 0,
            last_refill_ns: NANOS_PER_SEC,
        };

        let passed = apply_token_bucket(NANOS_PER_SEC, &policy, &mut state);

        assert!(!passed);
    }
}
