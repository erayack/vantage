#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

/// Flow-aware identity key derived from L2/L3/L4 metadata plus optional
/// userspace-provided HTTP path hash selector.
///
/// No application payload fields are part of kernel-side key extraction.
/// `dst_port`, `proto`, and `http_path_hash` support wildcard semantics for
/// fallback matching (`0` => wildcard).
#[repr(C)]
#[allow(clippy::pub_underscore_fields)]
#[cfg_attr(feature = "user", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantKey {
    pub src_ip: u32,
    pub http_path_hash: u32, // 0 => wildcard
    pub dst_port: u16,       // 0 => wildcard
    pub proto: u8,           // 0 => wildcard, 6 => TCP, 17 => UDP
    pub _pad: u8,
}

/// Computes 32-bit FNV-1a hash for HTTP path selector keying.
#[must_use]
pub const fn fnv1a_32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    let mut idx = 0_usize;
    while idx < bytes.len() {
        hash ^= bytes[idx] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        idx += 1;
    }
    hash
}

#[repr(u8)]
#[cfg_attr(feature = "user", derive(serde::Serialize))]
#[cfg_attr(feature = "user", serde(rename_all = "snake_case"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyMatchLevel {
    Exact = 0,
    ProtoWildcard = 1,
    FullWildcard = 2,
}

#[must_use]
pub const fn fallback_policy_keys(
    key: TenantKey,
) -> (TenantKey, Option<TenantKey>, Option<TenantKey>) {
    let exact_key = key;
    let proto_wildcard_key = if key.dst_port != 0 {
        Some(TenantKey {
            src_ip: key.src_ip,
            http_path_hash: key.http_path_hash,
            dst_port: 0,
            proto: key.proto,
            _pad: 0,
        })
    } else {
        None
    };
    let full_wildcard_key = if key.proto != 0 || key.dst_port != 0 {
        Some(TenantKey {
            src_ip: key.src_ip,
            http_path_hash: key.http_path_hash,
            dst_port: 0,
            proto: 0,
            _pad: 0,
        })
    } else {
        None
    };

    (exact_key, proto_wildcard_key, full_wildcard_key)
}

#[must_use]
pub fn policy_match_level(requested: TenantKey, matched: TenantKey) -> Option<PolicyMatchLevel> {
    let (exact_key, proto_wildcard_key, full_wildcard_key) = fallback_policy_keys(requested);
    if matched == exact_key {
        return Some(PolicyMatchLevel::Exact);
    }

    if let Some(proto_wildcard) = proto_wildcard_key
        && matched == proto_wildcard
    {
        return Some(PolicyMatchLevel::ProtoWildcard);
    }

    if let Some(full_wildcard) = full_wildcard_key
        && matched == full_wildcard
    {
        return Some(PolicyMatchLevel::FullWildcard);
    }

    None
}

/// Kernel drop-event emission sampling ratio (`1/N`) used in eBPF.
pub const KERNEL_DROP_EVENT_SAMPLE_EVERY: u64 = 64;

#[repr(C)]
#[allow(clippy::pub_underscore_fields)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub rate_tokens_per_sec: u64,
    pub burst_tokens: u64,
    pub enabled: u8,
    pub _pad: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenState {
    pub tokens: u64,
    pub last_refill_ns: u64,
}

#[repr(C)]
#[allow(clippy::pub_underscore_fields)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct bpf_spin_lock {
    pub val: u32,
}

#[repr(C)]
#[allow(clippy::pub_underscore_fields)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockedTokenState {
    pub lock: bpf_spin_lock,
    pub _pad: u32,
    pub state: TokenState,
}

impl LockedTokenState {
    #[must_use]
    pub const fn from_state(state: TokenState) -> Self {
        Self {
            lock: bpf_spin_lock { val: 0 },
            _pad: 0,
            state,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counters {
    pub pass_pkts: u64,
    pub drop_pkts: u64,
    pub pass_bytes: u64,
    pub drop_bytes: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReasonBuckets {
    pub no_tokens: u64,
    pub no_policy: u64,
    pub parse_fail: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobalStats {
    pub pass_pkts: u64,
    pub drop_pkts: u64,
    pub pass_bytes: u64,
    pub drop_bytes: u64,
    pub reasons: ReasonBuckets,
}

#[repr(C)]
#[allow(clippy::pub_underscore_fields)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockedCounters {
    pub lock: u32,
    pub _pad: u32,
    pub counters: Counters,
}

#[repr(C)]
#[allow(clippy::pub_underscore_fields)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockedGlobalStats {
    pub lock: u32,
    pub _pad: u32,
    pub stats: GlobalStats,
}

#[repr(C)]
#[allow(clippy::pub_underscore_fields)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobalConfig {
    pub enabled: u8,        // 0 => bypass data path logic (fail-open)
    pub flow_keys_live: u8, // 0 => legacy src-ip-only matching, 1 => flow-aware key matching
    pub _pad: [u8; 6],
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    NoTokens = 1,
    NoPolicy = 2,
    ParseFail = 3,
    StateStoreFail = 4,
}

impl DropReason {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[repr(C)]
#[allow(clippy::pub_underscore_fields)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DropEvent {
    pub ts_ns: u64,
    pub tenant_key: TenantKey,
    pub reason: u8,
    pub _pad: [u8; 7],
}

/// Byte offset of `DropEvent::ts_ns` within `DropEvent`.
pub const DROP_EVENT_TS_NS_OFFSET: usize = core::mem::offset_of!(DropEvent, ts_ns);
/// Byte offset of `DropEvent::tenant_key` within `DropEvent`.
pub const DROP_EVENT_TENANT_KEY_OFFSET: usize = core::mem::offset_of!(DropEvent, tenant_key);
/// Byte offset of `DropEvent::reason` within `DropEvent`.
pub const DROP_EVENT_REASON_OFFSET: usize = core::mem::offset_of!(DropEvent, reason);

#[cfg(feature = "user")]
// SAFETY: `TenantKey` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for TenantKey {}

#[cfg(feature = "user")]
// SAFETY: `Policy` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for Policy {}

#[cfg(feature = "user")]
// SAFETY: `TokenState` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for TokenState {}

#[cfg(feature = "user")]
// SAFETY: `bpf_spin_lock` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for bpf_spin_lock {}

#[cfg(feature = "user")]
// SAFETY: `LockedTokenState` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for LockedTokenState {}

#[cfg(feature = "user")]
// SAFETY: `Counters` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for Counters {}

#[cfg(feature = "user")]
// SAFETY: `ReasonBuckets` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for ReasonBuckets {}

#[cfg(feature = "user")]
// SAFETY: `GlobalStats` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for GlobalStats {}

#[cfg(feature = "user")]
// SAFETY: `LockedCounters` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for LockedCounters {}

#[cfg(feature = "user")]
// SAFETY: `LockedGlobalStats` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for LockedGlobalStats {}

#[cfg(feature = "user")]
// SAFETY: `GlobalConfig` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for GlobalConfig {}

#[cfg(feature = "user")]
// SAFETY: `DropEvent` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for DropEvent {}
