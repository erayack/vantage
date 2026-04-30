#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{
        BPF_F_NO_PREALLOC, BPF_NOEXIST, TC_ACT_OK, TC_ACT_SHOT, bpf_spin_lock as AyaBpfSpinLock,
    },
    helpers::{
        bpf_ktime_get_ns, bpf_skb_cgroup_id, bpf_spin_lock as bpf_helper_spin_lock, bpf_spin_unlock,
    },
    macros::{classifier, map},
    maps::{Array, HashMap, LruHashMap, RingBuf},
    programs::TcContext,
};
use vantage_common::{
    Counters, DropEvent, DropReason, GlobalConfig, GlobalStats, HTTP_METHOD_ANY, HTTP_METHOD_GET,
    HTTP_METHOD_POST, KERNEL_DROP_EVENT_SAMPLE_EVERY, LockedTokenState, Policy, TenantKey,
    TokenState, fallback_policy_keys,
};

const HASH_MAP_MAX_ENTRIES: u32 = 4096;
const STATE_MAP_MAX_ENTRIES: u32 = 4096;
const GLOBAL_STATS_MAX_ENTRIES: u32 = 1;
const GLOBAL_STATS_INDEX: u32 = 0;
const GLOBAL_CONFIG_MAX_ENTRIES: u32 = 1;
const GLOBAL_CONFIG_INDEX: u32 = 0;
const DROP_EVENTS_BYTES: u32 = 1 << 17;
const ETHERNET_HEADER_LEN: usize = 14;
const ETHER_TYPE_OFFSET: usize = 12;
const ETHER_TYPE_IPV4: u16 = 0x0800;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_VERSION: u8 = 4;
const IPV4_VERSION_IHL_REL_OFFSET: usize = 0;
const IPV4_PROTOCOL_REL_OFFSET: usize = 9;
const L4_DST_PORT_REL_OFFSET: usize = 2;
const TCP_DATA_OFFSET_REL_OFFSET: usize = 12;
const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const HTTP_PREFIX_MAX_BYTES: usize = 128;
const HTTP_PATH_HASH_MAX_BYTES: usize = 64;
const FNV1A_OFFSET_BASIS: u32 = 0x811c_9dc5;
const FNV1A_PRIME: u32 = 0x0100_0193;
const NANOS_PER_SEC: u64 = 1_000_000_000;
const HASH_MAP_FLAGS: u32 = BPF_F_NO_PREALLOC;
const STATE_MAP_FLAGS: u32 = BPF_F_NO_PREALLOC;

#[map]
static POLICY_MAP: HashMap<TenantKey, Policy> =
    HashMap::<TenantKey, Policy>::with_max_entries(HASH_MAP_MAX_ENTRIES, HASH_MAP_FLAGS);

#[map]
static RUNTIME_POLICY_MAP: HashMap<TenantKey, Policy> =
    HashMap::<TenantKey, Policy>::with_max_entries(HASH_MAP_MAX_ENTRIES, HASH_MAP_FLAGS);

#[map]
#[allow(dead_code)]
// v0.3.0 contract: this map must remain LRU to bound token-state memory
// as flow-key cardinality grows. Under pressure, cold entries are evicted.
static STATE_MAP: LruHashMap<TenantKey, LockedTokenState> =
    LruHashMap::<TenantKey, LockedTokenState>::with_max_entries(
        STATE_MAP_MAX_ENTRIES,
        STATE_MAP_FLAGS,
    );

#[map]
#[allow(dead_code)]
static COUNTERS_MAP: HashMap<TenantKey, Counters> =
    HashMap::<TenantKey, Counters>::with_max_entries(HASH_MAP_MAX_ENTRIES, HASH_MAP_FLAGS);

#[map]
#[allow(dead_code)]
static GLOBAL_STATS_MAP: Array<GlobalStats> =
    Array::<GlobalStats>::with_max_entries(GLOBAL_STATS_MAX_ENTRIES, 0);

#[map]
#[allow(dead_code)]
static GLOBAL_CONFIG_MAP: Array<GlobalConfig> =
    Array::<GlobalConfig>::with_max_entries(GLOBAL_CONFIG_MAX_ENTRIES, 0);

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
    if !is_filter_enabled() {
        return Ok(TC_ACT_OK);
    }

    let now_ns = monotonic_now_ns();
    let pkt_len = u64::from(ctx.len());

    let Some(tenant_key) = flow_key_from_packet(ctx, is_flow_keys_live()) else {
        // Fail-open on parse failure.
        update_global_stats(pkt_len, true, Some(DropReason::ParseFail));
        return Ok(TC_ACT_OK);
    };

    let Some(policy) = read_policy_with_dual_fallback(tenant_key) else {
        update_counters(tenant_key, pkt_len, true);
        update_global_stats(pkt_len, true, Some(DropReason::NoPolicy));
        return Ok(TC_ACT_OK);
    };

    if policy.enabled == 0 {
        update_counters(tenant_key, pkt_len, true);
        update_global_stats(pkt_len, true, None);
        return Ok(TC_ACT_OK);
    }

    let passed = match decide_and_store_state(tenant_key, now_ns, &policy) {
        Ok(passed) => passed,
        Err(()) => {
            let drop_pkts = update_counters(tenant_key, pkt_len, false);
            update_global_stats(pkt_len, false, None);
            maybe_emit_drop_event(tenant_key, now_ns, DropReason::StateStoreFail, drop_pkts);
            return Ok(TC_ACT_SHOT);
        }
    };
    let drop_pkts = update_counters(tenant_key, pkt_len, passed);
    update_global_stats(
        pkt_len,
        passed,
        if passed {
            None
        } else {
            Some(DropReason::NoTokens)
        },
    );
    if passed {
        Ok(TC_ACT_OK)
    } else {
        maybe_emit_drop_event(tenant_key, now_ns, DropReason::NoTokens, drop_pkts);
        Ok(TC_ACT_SHOT)
    }
}

fn flow_key_from_packet(ctx: &TcContext, flow_keys_live: bool) -> Option<TenantKey> {
    let cgroup_id = extract_cgroup_id(ctx)?;
    let packet_len = usize::try_from(ctx.len()).ok()?;
    // Parser contract: all kernel packet reads are bounded.
    // L7 reads only inspect a small fixed payload prefix.
    let l3_offset = parse_l2_ipv4(ctx, packet_len)?;
    let (proto, l4_offset) = parse_l3_ipv4(ctx, packet_len, l3_offset)?;
    if !flow_keys_live {
        return Some(TenantKey {
            cgroup_id,
            http_path_hash: 0,
            dst_port: 0,
            proto: 0,
            http_method: 0,
        });
    }

    let dst_port = parse_l4_dst_port(ctx, packet_len, proto, l4_offset)?;
    let (http_method, http_path_hash) = parse_l7_http_selector(ctx, packet_len, proto, l4_offset);

    Some(TenantKey {
        cgroup_id,
        http_path_hash,
        dst_port,
        proto,
        http_method,
    })
}

#[allow(unsafe_code)]
fn extract_cgroup_id(ctx: &TcContext) -> Option<u64> {
    // SAFETY: Helper reads cgroup id from skb context; pointer comes directly
    // from kernel-provided `TcContext`.
    let cgroup_id = unsafe { bpf_skb_cgroup_id(ctx.skb.skb) };
    if cgroup_id == 0 {
        None
    } else {
        Some(cgroup_id)
    }
}

fn parse_l2_ipv4(ctx: &TcContext, packet_len: usize) -> Option<usize> {
    if packet_len < ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN {
        return None;
    }

    let ether_type_hi = ctx.load::<u8>(ETHER_TYPE_OFFSET).ok()?;
    let ether_type_lo = ctx.load::<u8>(ETHER_TYPE_OFFSET + 1).ok()?;
    let ether_type = u16::from_be_bytes([ether_type_hi, ether_type_lo]);
    if ether_type != ETHER_TYPE_IPV4 {
        return None;
    }

    Some(ETHERNET_HEADER_LEN)
}

fn parse_l3_ipv4(ctx: &TcContext, packet_len: usize, l3_offset: usize) -> Option<(u8, usize)> {
    if packet_len < l3_offset + IPV4_MIN_HEADER_LEN {
        return None;
    }

    let version_ihl = ctx
        .load::<u8>(l3_offset + IPV4_VERSION_IHL_REL_OFFSET)
        .ok()?;
    if version_ihl >> 4 != IPV4_VERSION {
        return None;
    }

    let ihl_words = version_ihl & 0x0f;
    if ihl_words < 5 {
        return None;
    }

    let ip_header_len = usize::from(ihl_words) * 4;
    if packet_len < l3_offset + ip_header_len {
        return None;
    }

    let proto = ctx.load::<u8>(l3_offset + IPV4_PROTOCOL_REL_OFFSET).ok()?;
    let l4_offset = l3_offset + ip_header_len;
    Some((proto, l4_offset))
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
fn read_base_policy(key: TenantKey) -> Option<Policy> {
    // SAFETY: The map value is copied out immediately and never held across
    // helper calls, avoiding aliasing/lifetime pitfalls of raw map pointers.
    unsafe { POLICY_MAP.get(&key).copied() }
}

#[allow(unsafe_code)]
fn read_runtime_policy(key: TenantKey) -> Option<Policy> {
    // SAFETY: The map value is copied out immediately and never held across
    // helper calls, avoiding aliasing/lifetime pitfalls of raw map pointers.
    unsafe { RUNTIME_POLICY_MAP.get(&key).copied() }
}

fn read_runtime_policy_with_fallback(key: TenantKey) -> Option<Policy> {
    let (candidates, _, candidate_count) = fallback_policy_keys(key);
    for candidate in candidates[..candidate_count].iter().copied() {
        if let Some(policy) = read_runtime_policy(candidate) {
            return Some(policy);
        }
    }

    None
}

fn read_base_policy_with_fallback(key: TenantKey) -> Option<Policy> {
    let (candidates, _, candidate_count) = fallback_policy_keys(key);
    for candidate in candidates[..candidate_count].iter().copied() {
        if let Some(policy) = read_base_policy(candidate) {
            return Some(policy);
        }
    }

    None
}

fn read_policy_with_dual_fallback(key: TenantKey) -> Option<Policy> {
    read_runtime_policy_with_fallback(key).or_else(|| read_base_policy_with_fallback(key))
}

#[allow(unsafe_code)]
fn is_filter_enabled() -> bool {
    read_global_config().is_none_or(|config| config.enabled != 0)
}

#[allow(unsafe_code)]
fn is_flow_keys_live() -> bool {
    read_global_config().is_none_or(|config| config.flow_keys_live != 0)
}

#[allow(unsafe_code)]
fn read_global_config() -> Option<GlobalConfig> {
    let config_ptr = GLOBAL_CONFIG_MAP.get_ptr(GLOBAL_CONFIG_INDEX)?;
    // SAFETY: Pointer originates from a BPF array lookup at a fixed index
    // and is copied out immediately in this invocation.
    let config = unsafe { *config_ptr };
    Some(config)
}

fn initial_state(policy: &Policy, now_ns: u64) -> TokenState {
    TokenState {
        tokens: policy.burst_tokens,
        last_refill_ns: now_ns,
    }
}

fn initial_locked_state(policy: &Policy, now_ns: u64) -> LockedTokenState {
    LockedTokenState::from_state(initial_state(policy, now_ns))
}

#[allow(unsafe_code)]
fn apply_token_bucket_with_lock(
    now_ns: u64,
    policy: &Policy,
    locked_state: &mut LockedTokenState,
) -> bool {
    // SAFETY: `locked_state` points to a map value and `lock` is the lock field
    // within that map value. The lock is always paired with an unlock in this
    // function before returning.
    unsafe {
        bpf_helper_spin_lock(core::ptr::from_mut(&mut locked_state.lock).cast::<AyaBpfSpinLock>())
    };
    let passed = apply_token_bucket(now_ns, policy, &mut locked_state.state);
    // SAFETY: This unlock matches the lock call above and uses the same map
    // value lock pointer.
    unsafe {
        bpf_spin_unlock(core::ptr::from_mut(&mut locked_state.lock).cast::<AyaBpfSpinLock>())
    };
    passed
}

#[allow(unsafe_code)]
fn decide_and_store_state(key: TenantKey, now_ns: u64, policy: &Policy) -> Result<bool, ()> {
    if let Some(locked_state_ptr) = STATE_MAP.get_ptr_mut(&key) {
        // SAFETY: Pointer originates from BPF map lookup for `key` and is used
        // only within this function invocation.
        let locked_state = unsafe { &mut *locked_state_ptr };
        let passed = apply_token_bucket_with_lock(now_ns, policy, locked_state);
        return Ok(passed);
    }

    let locked_state = initial_locked_state(policy, now_ns);
    let _ = STATE_MAP.insert(&key, &locked_state, u64::from(BPF_NOEXIST));

    if let Some(locked_state_ptr) = STATE_MAP.get_ptr_mut(&key) {
        // SAFETY: Pointer originates from BPF map lookup for `key` and is used
        // only within this function invocation.
        let locked_state = unsafe { &mut *locked_state_ptr };
        return Ok(apply_token_bucket_with_lock(now_ns, policy, locked_state));
    }

    Err(())
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
        if passed {
            counters.pass_pkts = counters.pass_pkts.saturating_add(1);
            counters.pass_bytes = counters.pass_bytes.saturating_add(pkt_len);
        } else {
            counters.drop_pkts = counters.drop_pkts.saturating_add(1);
            counters.drop_bytes = counters.drop_bytes.saturating_add(pkt_len);
        }
        let drop_pkts = counters.drop_pkts;
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
    let _ = COUNTERS_MAP.insert(&key, &counters, 0);
    counters.drop_pkts
}

fn maybe_emit_drop_event(key: TenantKey, now_ns: u64, reason: DropReason, drop_pkts: u64) {
    if drop_pkts == 0 || (drop_pkts & (KERNEL_DROP_EVENT_SAMPLE_EVERY - 1)) != 0 {
        return;
    }

    let event = DropEvent {
        ts_ns: now_ns,
        tenant_key: key,
        reason: reason.as_u8(),
        _pad: [0; 7],
    };

    let _ = DROP_EVENTS.output::<DropEvent>(event, 0);
}

#[allow(unsafe_code)]
fn update_global_stats(pkt_len: u64, passed: bool, reason: Option<DropReason>) {
    if let Some(stats_ptr) = GLOBAL_STATS_MAP.get_ptr_mut(GLOBAL_STATS_INDEX) {
        // SAFETY: Pointer originates from BPF array lookup and is used only
        // within this function invocation.
        let stats = unsafe { &mut *stats_ptr };
        if passed {
            stats.pass_pkts = stats.pass_pkts.saturating_add(1);
            stats.pass_bytes = stats.pass_bytes.saturating_add(pkt_len);
        } else {
            stats.drop_pkts = stats.drop_pkts.saturating_add(1);
            stats.drop_bytes = stats.drop_bytes.saturating_add(pkt_len);
        }
        if let Some(reason) = reason {
            match reason {
                DropReason::NoTokens => {
                    stats.reasons.no_tokens = stats.reasons.no_tokens.saturating_add(1);
                }
                DropReason::NoPolicy => {
                    stats.reasons.no_policy = stats.reasons.no_policy.saturating_add(1);
                }
                DropReason::ParseFail => {
                    stats.reasons.parse_fail = stats.reasons.parse_fail.saturating_add(1);
                }
                DropReason::StateStoreFail => {}
            }
        }
    }
}

#[allow(unsafe_code)]
fn monotonic_now_ns() -> u64 {
    // SAFETY: `bpf_ktime_get_ns` is a pure BPF helper that returns monotonic
    // nanoseconds and does not require additional pointer validity guarantees.
    unsafe { bpf_ktime_get_ns() }
}

const fn proto_has_dst_port(proto: u8) -> bool {
    proto == IPPROTO_TCP || proto == IPPROTO_UDP
}

fn parse_l4_dst_port(
    ctx: &TcContext,
    packet_len: usize,
    proto: u8,
    l4_offset: usize,
) -> Option<u16> {
    let dst_port_be = if proto_has_dst_port(proto) {
        Some(ctx.load::<u16>(l4_offset + L4_DST_PORT_REL_OFFSET).ok()?)
    } else {
        None
    };
    parse_l4_dst_port_value(proto, packet_len, l4_offset, dst_port_be)
}

fn parse_l4_dst_port_value(
    proto: u8,
    packet_len: usize,
    l4_offset: usize,
    dst_port_be: Option<u16>,
) -> Option<u16> {
    if !proto_has_dst_port(proto) {
        return Some(0);
    }
    if packet_len < l4_offset + L4_DST_PORT_REL_OFFSET + 2 {
        return None;
    }
    Some(u16::from_be(dst_port_be?))
}

fn parse_l7_http_selector(
    ctx: &TcContext,
    packet_len: usize,
    proto: u8,
    l4_offset: usize,
) -> (u8, u32) {
    let Some(payload_offset) = parse_l7_payload_offset(ctx, packet_len, proto, l4_offset) else {
        return (HTTP_METHOD_ANY, 0);
    };

    let mut prefix = [0_u8; HTTP_PREFIX_MAX_BYTES];
    let Ok(read_len) = ctx.load_bytes(payload_offset, &mut prefix) else {
        return (HTTP_METHOD_ANY, 0);
    };
    if read_len == 0 {
        return (HTTP_METHOD_ANY, 0);
    }

    parse_http_method_and_path_hash(&prefix, read_len).unwrap_or((HTTP_METHOD_ANY, 0))
}

fn parse_l7_payload_offset(
    ctx: &TcContext,
    packet_len: usize,
    proto: u8,
    l4_offset: usize,
) -> Option<usize> {
    if proto == IPPROTO_TCP {
        return parse_tcp_payload_offset(ctx, packet_len, l4_offset);
    }

    if proto == IPPROTO_UDP {
        let payload_offset = l4_offset.checked_add(UDP_HEADER_LEN)?;
        if packet_len < payload_offset {
            return None;
        }
        return Some(payload_offset);
    }

    None
}

fn parse_tcp_payload_offset(ctx: &TcContext, packet_len: usize, l4_offset: usize) -> Option<usize> {
    if packet_len < l4_offset + TCP_MIN_HEADER_LEN {
        return None;
    }
    let data_offset_byte = ctx
        .load::<u8>(l4_offset + TCP_DATA_OFFSET_REL_OFFSET)
        .ok()?;
    let data_offset_words = data_offset_byte >> 4;
    if data_offset_words < 5 {
        return None;
    }
    let tcp_header_len = usize::from(data_offset_words) * 4;
    let payload_offset = l4_offset.checked_add(tcp_header_len)?;
    if packet_len < payload_offset {
        return None;
    }
    Some(payload_offset)
}

fn parse_http_method_and_path_hash(
    prefix: &[u8; HTTP_PREFIX_MAX_BYTES],
    read_len: usize,
) -> Option<(u8, u32)> {
    if read_len < 5 {
        return None;
    }

    let (http_method, path_start) = if prefix.starts_with(b"GET ") {
        (HTTP_METHOD_GET, 4_usize)
    } else if read_len >= 6 && prefix.starts_with(b"POST ") {
        (HTTP_METHOD_POST, 5_usize)
    } else {
        return None;
    };

    parse_http_path_hash(prefix, read_len, path_start).map(|hash| (http_method, hash))
}

fn parse_http_path_hash(
    prefix: &[u8; HTTP_PREFIX_MAX_BYTES],
    read_len: usize,
    path_start: usize,
) -> Option<u32> {
    if path_start >= read_len {
        return None;
    }
    if prefix[path_start] != b'/' {
        return None;
    }

    let mut hash = FNV1A_OFFSET_BASIS;
    let mut seen_any = false;
    let mut idx = 0_usize;
    while idx < HTTP_PATH_HASH_MAX_BYTES {
        let pos = path_start.checked_add(idx)?;
        if pos >= read_len {
            return None;
        }
        let byte = prefix[pos];
        if byte == b' ' {
            return seen_any.then_some(hash);
        }
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(FNV1A_PRIME);
        seen_any = true;
        idx += 1;
    }
    None
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier, Mutex};

    use vantage_common::KERNEL_DROP_EVENT_SAMPLE_EVERY;

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

    #[test]
    fn kernel_drop_event_sampling_constant_is_fixed() {
        assert_eq!(KERNEL_DROP_EVENT_SAMPLE_EVERY, 64);
        assert!(KERNEL_DROP_EVENT_SAMPLE_EVERY.is_power_of_two());
    }

    #[test]
    fn fallback_policy_keys_use_exact_then_path_then_port_method_path_then_full_wildcard() {
        let key = TenantKey {
            cgroup_id: 0x0a00_0001,
            http_path_hash: 0x1234,
            dst_port: 443,
            proto: IPPROTO_TCP,
            http_method: 0,
        };

        let (exact, path_wildcard, method_path_wildcard, port_method_path_wildcard, full_wildcard) =
            fallback_policy_keys(key);

        assert_eq!(exact, key);
        assert_eq!(method_path_wildcard, None);
        assert_eq!(
            path_wildcard,
            Some(TenantKey {
                cgroup_id: key.cgroup_id,
                http_path_hash: 0,
                dst_port: key.dst_port,
                proto: IPPROTO_TCP,
                http_method: 0,
            })
        );
        assert_eq!(
            port_method_path_wildcard,
            Some(TenantKey {
                cgroup_id: key.cgroup_id,
                http_path_hash: 0,
                dst_port: 0,
                proto: IPPROTO_TCP,
                http_method: 0,
            })
        );
        assert_eq!(
            full_wildcard,
            Some(TenantKey {
                cgroup_id: key.cgroup_id,
                http_path_hash: 0,
                dst_port: 0,
                proto: 0,
                http_method: 0,
            })
        );
    }

    #[test]
    fn fallback_policy_keys_skip_wildcards_when_key_is_already_wildcard() {
        let key = TenantKey {
            cgroup_id: 0x0a00_0001,
            http_path_hash: 0,
            dst_port: 0,
            proto: 0,
            http_method: 0,
        };

        let (_exact, path_wildcard, method_path_wildcard, port_method_path_wildcard, full_wildcard) =
            fallback_policy_keys(key);

        assert_eq!(path_wildcard, None);
        assert_eq!(method_path_wildcard, None);
        assert_eq!(port_method_path_wildcard, None);
        assert_eq!(full_wildcard, None);
    }

    #[test]
    fn parse_l4_dst_port_requires_complete_transport_header() {
        let l4_offset = ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let packet_len = l4_offset + L4_DST_PORT_REL_OFFSET + 1;
        let parsed =
            parse_l4_dst_port_value(IPPROTO_TCP, packet_len, l4_offset, Some(8080_u16.to_be()));
        assert_eq!(parsed, None);
    }

    #[test]
    fn parse_l4_dst_port_extracts_port_for_tcp_udp() {
        let l4_offset = ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let packet_len = l4_offset + L4_DST_PORT_REL_OFFSET + 2;
        let tcp =
            parse_l4_dst_port_value(IPPROTO_TCP, packet_len, l4_offset, Some(443_u16.to_be()));
        let udp = parse_l4_dst_port_value(IPPROTO_UDP, packet_len, l4_offset, Some(53_u16.to_be()));
        assert_eq!(tcp, Some(443));
        assert_eq!(udp, Some(53));
    }

    #[test]
    fn parse_l4_dst_port_uses_wildcard_for_non_tcp_udp() {
        let l4_offset = ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let packet_len = l4_offset;
        let parsed = parse_l4_dst_port_value(1, packet_len, l4_offset, None);
        assert_eq!(parsed, Some(0));
    }

    #[test]
    fn parses_http_get_path_hash() {
        let mut prefix = [0_u8; HTTP_PREFIX_MAX_BYTES];
        let req = b"GET /predict HTTP/1.1";
        prefix[..req.len()].copy_from_slice(req);
        let parsed = parse_http_method_and_path_hash(&prefix, req.len());
        assert_eq!(parsed, Some((HTTP_METHOD_GET, 0xefb2_d4b7)));
    }

    #[test]
    fn parses_http_post_path_hash() {
        let mut prefix = [0_u8; HTTP_PREFIX_MAX_BYTES];
        let req = b"POST /score HTTP/1.1";
        prefix[..req.len()].copy_from_slice(req);
        let parsed = parse_http_method_and_path_hash(&prefix, req.len());
        assert_eq!(parsed, Some((HTTP_METHOD_POST, 0xf7bd_07cc)));
    }

    #[test]
    fn rejects_non_http_prefix_and_missing_space() {
        let mut prefix = [0_u8; HTTP_PREFIX_MAX_BYTES];
        let req = b"PRI * HTTP/2.0";
        prefix[..req.len()].copy_from_slice(req);
        assert_eq!(parse_http_method_and_path_hash(&prefix, req.len()), None);

        let mut prefix2 = [0_u8; HTTP_PREFIX_MAX_BYTES];
        let req2 = b"GET /predict";
        prefix2[..req2.len()].copy_from_slice(req2);
        assert_eq!(parse_http_method_and_path_hash(&prefix2, req2.len()), None);
    }

    #[derive(Default)]
    struct FirstTouchState {
        value: Mutex<Option<TokenState>>,
    }

    fn old_first_touch_update(
        state: &FirstTouchState,
        now_ns: u64,
        policy: &Policy,
        read_barrier: &Barrier,
        insert_barrier: &Barrier,
    ) -> bool {
        if let Ok(mut guard) = state.value.lock() {
            if let Some(existing) = guard.as_mut() {
                return apply_token_bucket(now_ns, policy, existing);
            }
        }

        read_barrier.wait();
        let mut local = initial_state(policy, now_ns);
        let passed = apply_token_bucket(now_ns, policy, &mut local);
        insert_barrier.wait();

        if let Ok(mut guard) = state.value.lock() {
            *guard = Some(local);
        }
        passed
    }

    fn noexist_first_touch_update(
        state: &FirstTouchState,
        now_ns: u64,
        policy: &Policy,
        read_barrier: &Barrier,
        insert_barrier: &Barrier,
    ) -> bool {
        if let Ok(mut guard) = state.value.lock() {
            if let Some(existing) = guard.as_mut() {
                return apply_token_bucket(now_ns, policy, existing);
            }
        }

        read_barrier.wait();
        let local = initial_state(policy, now_ns);
        insert_barrier.wait();

        if let Ok(mut guard) = state.value.lock() {
            if guard.is_none() {
                *guard = Some(local);
            }
        }

        if let Ok(mut guard) = state.value.lock()
            && let Some(existing) = guard.as_mut()
        {
            return apply_token_bucket(now_ns, policy, existing);
        }

        false
    }

    #[test]
    fn first_touch_parallel_updates_require_noexist_insert_semantics() {
        let policy = policy(0, 1);
        let now_ns = 123_u64;
        let old_state = Arc::new(FirstTouchState::default());
        let new_state = Arc::new(FirstTouchState::default());

        let old_read = Arc::new(Barrier::new(2));
        let old_insert = Arc::new(Barrier::new(2));
        let old_a = {
            let state = Arc::clone(&old_state);
            let read = Arc::clone(&old_read);
            let insert = Arc::clone(&old_insert);
            std::thread::spawn(move || {
                old_first_touch_update(&state, now_ns, &policy, &read, &insert)
            })
        };
        let old_b = {
            let state = Arc::clone(&old_state);
            let read = Arc::clone(&old_read);
            let insert = Arc::clone(&old_insert);
            std::thread::spawn(move || {
                old_first_touch_update(&state, now_ns, &policy, &read, &insert)
            })
        };
        let old_passes =
            usize::from(old_a.join().unwrap_or(false)) + usize::from(old_b.join().unwrap_or(false));
        assert_eq!(
            old_passes, 2,
            "legacy overwrite path can over-admit on first touch"
        );

        let new_read = Arc::new(Barrier::new(2));
        let new_insert = Arc::new(Barrier::new(2));
        let new_a = {
            let state = Arc::clone(&new_state);
            let read = Arc::clone(&new_read);
            let insert = Arc::clone(&new_insert);
            std::thread::spawn(move || {
                noexist_first_touch_update(&state, now_ns, &policy, &read, &insert)
            })
        };
        let new_b = {
            let state = Arc::clone(&new_state);
            let read = Arc::clone(&new_read);
            let insert = Arc::clone(&new_insert);
            std::thread::spawn(move || {
                noexist_first_touch_update(&state, now_ns, &policy, &read, &insert)
            })
        };
        let new_passes =
            usize::from(new_a.join().unwrap_or(false)) + usize::from(new_b.join().unwrap_or(false));
        assert_eq!(
            new_passes, 1,
            "BPF_NOEXIST-style insert prevents first-touch leakage"
        );
    }
}
