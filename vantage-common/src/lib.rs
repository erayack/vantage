#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

/// `PoC` identity key currently derived from packet `src_ip` (`u32`).
/// Keep userspace conversion seams in place so this can be migrated to
/// `cgroup_id` (`u64`) later with minimal API breakage.
pub type TenantKey = u32;

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
    pub _pad: [u8; 3],
}

#[cfg(feature = "user")]
// SAFETY: `Policy` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for Policy {}

#[cfg(feature = "user")]
// SAFETY: `TokenState` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for TokenState {}

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
// SAFETY: `DropEvent` is `repr(C)` and contains only plain integer fields.
unsafe impl Pod for DropEvent {}
