#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

/// Flow-aware identity key derived from cgroup identity plus optional
/// userspace-provided HTTP path hash selector.
///
/// No application payload fields are part of kernel-side key extraction.
/// `dst_port`, `proto`, `http_method`, and `http_path_hash` support wildcard
/// semantics for fallback matching (`0` => wildcard).
#[repr(C)]
#[allow(clippy::pub_underscore_fields)]
#[cfg_attr(feature = "user", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantKey {
    pub cgroup_id: u64,
    pub http_path_hash: u32, // 0 => wildcard
    pub dst_port: u16,       // 0 => wildcard
    pub proto: u8,           // 0 => wildcard, 6 => TCP, 17 => UDP
    pub http_method: u8,     // 0 => wildcard
}

pub const HTTP_METHOD_ANY: u8 = 0;
pub const HTTP_METHOD_GET: u8 = 1;
pub const HTTP_METHOD_POST: u8 = 2;
pub const HTTP_METHOD_PUT: u8 = 3;
pub const HTTP_METHOD_DELETE: u8 = 4;
pub const HTTP_METHOD_PATCH: u8 = 5;
pub const HTTP_METHOD_HEAD: u8 = 6;
pub const HTTP_METHOD_OPTIONS: u8 = 7;

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
    PathWildcard = 1,
    MethodPathWildcard = 2,
    PortMethodPathWildcard = 3,
    FullWildcard = 4,
}

#[must_use]
/// Builds deterministic policy fallback candidates in precedence order:
/// 1. exact `(cgroup_id, proto, dst_port, http_method, http_path_hash)`
/// 2. path wildcard `(cgroup_id, proto, dst_port, http_method, 0)`
/// 3. method+path wildcard `(cgroup_id, proto, dst_port, 0, 0)`
/// 4. L4/L7 wildcard `(cgroup_id, proto, 0, 0, 0)`
/// 5. full wildcard `(cgroup_id, 0, 0, 0, 0)`
pub const fn fallback_policy_keys(
    key: TenantKey,
) -> ([TenantKey; 5], [PolicyMatchLevel; 5], usize) {
    let path_wildcard = TenantKey {
        cgroup_id: key.cgroup_id,
        http_path_hash: 0,
        dst_port: key.dst_port,
        proto: key.proto,
        http_method: key.http_method,
    };
    let method_path_wildcard = TenantKey {
        cgroup_id: key.cgroup_id,
        http_path_hash: 0,
        dst_port: key.dst_port,
        proto: key.proto,
        http_method: 0,
    };
    let port_method_path_wildcard = TenantKey {
        cgroup_id: key.cgroup_id,
        http_path_hash: 0,
        dst_port: 0,
        proto: key.proto,
        http_method: 0,
    };
    let full_wildcard = TenantKey {
        cgroup_id: key.cgroup_id,
        http_path_hash: 0,
        dst_port: 0,
        proto: 0,
        http_method: 0,
    };

    let mut candidates = [key; 5];
    let mut levels = [PolicyMatchLevel::Exact; 5];
    let mut len = 1;

    if key.http_path_hash != 0 {
        candidates[len] = path_wildcard;
        levels[len] = PolicyMatchLevel::PathWildcard;
        len += 1;
    }
    if key.http_method != 0 {
        candidates[len] = method_path_wildcard;
        levels[len] = PolicyMatchLevel::MethodPathWildcard;
        len += 1;
    }
    if key.dst_port != 0 {
        candidates[len] = port_method_path_wildcard;
        levels[len] = PolicyMatchLevel::PortMethodPathWildcard;
        len += 1;
    }
    if key.proto != 0 {
        candidates[len] = full_wildcard;
        levels[len] = PolicyMatchLevel::FullWildcard;
        len += 1;
    }

    (candidates, levels, len)
}

#[must_use]
pub fn policy_match_level(requested: TenantKey, matched: TenantKey) -> Option<PolicyMatchLevel> {
    let (candidates, levels, candidate_count) = fallback_policy_keys(requested);
    for (index, candidate) in candidates[..candidate_count].iter().enumerate() {
        if matched == *candidate {
            return Some(levels[index]);
        }
    }

    None
}

/// Kernel drop-event emission sampling ratio (`1/N`) used in eBPF.
pub const KERNEL_DROP_EVENT_SAMPLE_EVERY: u64 = 64;

#[repr(C)]
#[allow(clippy::pub_underscore_fields)]
#[cfg_attr(feature = "user", derive(serde::Deserialize, serde::Serialize))]
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
    pub flow_keys_live: u8, // 0 => cgroup-only matching, 1 => flow-aware key matching
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

#[cfg(test)]
mod tests {
    use super::{
        HTTP_METHOD_POST, PolicyMatchLevel, TenantKey, fallback_policy_keys, fnv1a_32,
        policy_match_level,
    };

    #[test]
    fn fallback_policy_keys_follow_deterministic_precedence() {
        let key = TenantKey {
            cgroup_id: 0x0a00_0001,
            http_path_hash: 0x1234_abcd,
            dst_port: 443,
            proto: 6,
            http_method: HTTP_METHOD_POST,
        };

        let (candidates, _, candidate_count) = fallback_policy_keys(key);
        assert_eq!(candidate_count, 5);

        let exact = candidates[0];
        let path = candidates[1];
        let method_path = candidates[2];
        let port_method_path = candidates[3];
        let full = candidates[4];

        assert_eq!(exact, key);
        assert_eq!(
            path,
            TenantKey {
                cgroup_id: key.cgroup_id,
                http_path_hash: 0,
                dst_port: key.dst_port,
                proto: key.proto,
                http_method: key.http_method,
            }
        );
        assert_eq!(
            method_path,
            TenantKey {
                cgroup_id: key.cgroup_id,
                http_path_hash: 0,
                dst_port: key.dst_port,
                proto: key.proto,
                http_method: 0,
            }
        );
        assert_eq!(
            port_method_path,
            TenantKey {
                cgroup_id: key.cgroup_id,
                http_path_hash: 0,
                dst_port: 0,
                proto: key.proto,
                http_method: 0,
            }
        );
        assert_eq!(
            full,
            TenantKey {
                cgroup_id: key.cgroup_id,
                http_path_hash: 0,
                dst_port: 0,
                proto: 0,
                http_method: 0,
            }
        );
        assert_eq!(
            policy_match_level(key, exact),
            Some(PolicyMatchLevel::Exact)
        );
        assert_eq!(
            policy_match_level(key, path),
            Some(PolicyMatchLevel::PathWildcard)
        );
        assert_eq!(
            policy_match_level(key, method_path),
            Some(PolicyMatchLevel::MethodPathWildcard)
        );
        assert_eq!(
            policy_match_level(key, port_method_path),
            Some(PolicyMatchLevel::PortMethodPathWildcard)
        );
        assert_eq!(
            policy_match_level(key, full),
            Some(PolicyMatchLevel::FullWildcard)
        );
    }

    #[test]
    fn fallback_policy_keys_shorten_chain_for_existing_wildcards() {
        let key = TenantKey {
            cgroup_id: 0x0a00_0001,
            http_path_hash: 0,
            dst_port: 0,
            proto: 6,
            http_method: 0,
        };

        let (candidates, _, candidate_count) = fallback_policy_keys(key);
        assert_eq!(candidate_count, 2);
        assert_eq!(candidates[0], key);
        assert_eq!(
            candidates[1],
            TenantKey {
                cgroup_id: key.cgroup_id,
                http_path_hash: 0,
                dst_port: 0,
                proto: 0,
                http_method: 0,
            }
        );
    }

    #[test]
    fn fallback_policy_keys_do_not_emit_duplicate_method_only_states() {
        let key = TenantKey {
            cgroup_id: 0x0a00_0001,
            http_path_hash: 0,
            dst_port: 0,
            proto: 0,
            http_method: HTTP_METHOD_POST,
        };

        let (candidates, _, candidate_count) = fallback_policy_keys(key);
        assert_eq!(candidate_count, 2);
        assert_eq!(candidates[0], key);
        assert_eq!(
            candidates[1],
            TenantKey {
                cgroup_id: key.cgroup_id,
                http_path_hash: 0,
                dst_port: 0,
                proto: 0,
                http_method: 0,
            }
        );
    }

    #[test]
    fn fnv1a_hash_matches_known_vector() {
        assert_eq!(fnv1a_32(b"/predict"), 0xefb2_d4b7);
    }
}
