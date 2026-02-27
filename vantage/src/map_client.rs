use std::sync::{Arc, Mutex};

use aya::{
    Ebpf,
    maps::{Array, HashMap},
};
use thiserror::Error;
use vantage_common::{
    Counters, GlobalConfig, GlobalStats, Policy, PolicyMatchLevel, TenantKey, fallback_policy_keys,
    policy_match_level,
};

const GLOBAL_STATS_INDEX: u32 = 0;
const GLOBAL_CONFIG_INDEX: u32 = 0;

#[derive(Debug, Error)]
pub enum MapError {
    #[error("failed to lock eBPF object")]
    LockPoisoned,
    #[error("required map '{0}' is missing")]
    MissingMap(&'static str),
    #[error("eBPF map operation failed: {0}")]
    Map(#[from] aya::maps::MapError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub requested: TenantKey,
    pub matched: TenantKey,
    pub match_level: PolicyMatchLevel,
    pub policy: Policy,
}

pub(crate) trait MapOps: Send + Sync {
    fn upsert_policy(&self, tenant: TenantKey, policy: Policy) -> Result<(), MapError>;
    fn delete_policy(&self, tenant: TenantKey) -> Result<(), MapError>;
    fn get_policy(&self, tenant: TenantKey) -> Result<Option<Policy>, MapError>;
    fn collect_counters(&self) -> Result<Vec<(TenantKey, Counters)>, MapError>;
    fn read_global_stats(&self) -> Result<GlobalStats, MapError>;
    fn seed_global_config(&self, config: GlobalConfig) -> Result<(), MapError>;
    fn set_global_enabled(&self, enabled: bool) -> Result<(), MapError>;
    fn get_global_enabled(&self) -> Result<bool, MapError>;
    fn set_flow_keys_live(&self, flow_keys_live: bool) -> Result<(), MapError>;
    fn get_flow_keys_live(&self) -> Result<bool, MapError>;
}

struct EbpfMapOps {
    ebpf: Arc<Mutex<Ebpf>>,
}

#[derive(Clone)]
pub struct MapClient {
    inner: Arc<dyn MapOps>,
}

impl MapClient {
    pub fn new(ebpf: Arc<Mutex<Ebpf>>) -> Self {
        Self {
            inner: Arc::new(EbpfMapOps { ebpf }),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_ops(ops: Arc<dyn MapOps>) -> Self {
        Self { inner: ops }
    }

    /// Inserts or updates a policy entry for a tenant.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map write fails.
    pub fn upsert_policy(&self, tenant: TenantKey, policy: Policy) -> Result<(), MapError> {
        self.inner.upsert_policy(tenant, policy)
    }

    /// Removes a policy entry for a tenant.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map delete fails.
    pub fn delete_policy(&self, tenant: TenantKey) -> Result<(), MapError> {
        self.inner.delete_policy(tenant)
    }

    /// Reads an exact policy entry for a tenant key.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map read fails.
    pub fn get_policy(&self, tenant: TenantKey) -> Result<Option<Policy>, MapError> {
        self.inner.get_policy(tenant)
    }

    /// Resolves the effective policy for a tenant using precedence rules.
    ///
    /// Precedence order:
    /// 1. exact `(src_ip, proto, dst_port)`
    /// 2. proto wildcard `(src_ip, proto, 0)`
    /// 3. full wildcard `(src_ip, 0, 0)`
    ///
    /// # Errors
    ///
    /// Returns `MapError` when map access fails.
    pub fn resolve_policy(&self, requested: TenantKey) -> Result<Option<ResolvedPolicy>, MapError> {
        let (exact, proto_wildcard, full_wildcard) = fallback_policy_keys(requested);
        let candidates = [Some(exact), proto_wildcard, full_wildcard];
        let mut prior: Option<TenantKey> = None;

        for candidate in candidates.into_iter().flatten() {
            if prior == Some(candidate) {
                continue;
            }
            prior = Some(candidate);

            if let Some(policy) = self.get_policy(candidate)? {
                let level =
                    policy_match_level(requested, candidate).unwrap_or(PolicyMatchLevel::Exact);
                return Ok(Some(ResolvedPolicy {
                    requested,
                    matched: candidate,
                    match_level: level,
                    policy,
                }));
            }
        }

        Ok(None)
    }

    /// Reads all tenant counters from `COUNTERS_MAP`.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map iteration fails.
    pub fn collect_counters(&self) -> Result<Vec<(TenantKey, Counters)>, MapError> {
        self.inner.collect_counters()
    }

    /// Reads aggregate counters from `GLOBAL_STATS_MAP` index `0`.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map read fails.
    pub fn read_global_stats(&self) -> Result<GlobalStats, MapError> {
        self.inner.read_global_stats()
    }

    /// Seeds `GLOBAL_CONFIG_MAP[0]` during daemon startup.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map write fails.
    pub fn seed_global_config(&self, config: GlobalConfig) -> Result<(), MapError> {
        self.inner.seed_global_config(config)
    }

    /// Sets `GLOBAL_CONFIG_MAP[0].enabled` to toggle data-path filtering.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map write fails.
    pub fn set_global_enabled(&self, enabled: bool) -> Result<(), MapError> {
        self.inner.set_global_enabled(enabled)
    }

    /// Reads `GLOBAL_CONFIG_MAP[0].enabled`.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map read fails.
    pub fn get_global_enabled(&self) -> Result<bool, MapError> {
        self.inner.get_global_enabled()
    }

    /// Sets `GLOBAL_CONFIG_MAP[0].flow_keys_live` to toggle flow-aware keying.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map write fails.
    pub fn set_flow_keys_live(&self, flow_keys_live: bool) -> Result<(), MapError> {
        self.inner.set_flow_keys_live(flow_keys_live)
    }

    /// Reads `GLOBAL_CONFIG_MAP[0].flow_keys_live`.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map read fails.
    pub fn get_flow_keys_live(&self) -> Result<bool, MapError> {
        self.inner.get_flow_keys_live()
    }
}

impl MapOps for EbpfMapOps {
    fn set_flow_keys_live(&self, flow_keys_live: bool) -> Result<(), MapError> {
        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        {
            let map = ebpf
                .map_mut("GLOBAL_CONFIG_MAP")
                .ok_or(MapError::MissingMap("GLOBAL_CONFIG_MAP"))?;
            let mut global_config_map = Array::<_, GlobalConfig>::try_from(map)?;
            let mut config = read_global_config_or_default(&global_config_map)?;
            config.flow_keys_live = u8::from(flow_keys_live);
            global_config_map.set(GLOBAL_CONFIG_INDEX, config, 0)?;
        }
        drop(ebpf);

        Ok(())
    }

    fn get_flow_keys_live(&self) -> Result<bool, MapError> {
        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        let flow_keys_live = {
            let map = ebpf
                .map_mut("GLOBAL_CONFIG_MAP")
                .ok_or(MapError::MissingMap("GLOBAL_CONFIG_MAP"))?;
            let global_config_map = Array::<_, GlobalConfig>::try_from(map)?;
            let config = read_global_config_or_default(&global_config_map)?;
            config.flow_keys_live != 0
        };
        drop(ebpf);

        Ok(flow_keys_live)
    }

    fn upsert_policy(&self, tenant: TenantKey, policy: Policy) -> Result<(), MapError> {
        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        {
            let map = ebpf
                .map_mut("POLICY_MAP")
                .ok_or(MapError::MissingMap("POLICY_MAP"))?;
            let mut policy_map = HashMap::<_, TenantKey, Policy>::try_from(map)?;
            policy_map.insert(tenant, policy, 0)?;
        }
        drop(ebpf);

        Ok(())
    }

    fn delete_policy(&self, tenant: TenantKey) -> Result<(), MapError> {
        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        let remove_result = {
            let map = ebpf
                .map_mut("POLICY_MAP")
                .ok_or(MapError::MissingMap("POLICY_MAP"))?;
            let mut policy_map = HashMap::<_, TenantKey, Policy>::try_from(map)?;
            match policy_map.remove(&tenant) {
                Ok(()) | Err(aya::maps::MapError::KeyNotFound) => Ok(()),
                Err(error) => Err(MapError::Map(error)),
            }
        };
        drop(ebpf);
        remove_result?;

        Ok(())
    }

    fn get_policy(&self, tenant: TenantKey) -> Result<Option<Policy>, MapError> {
        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        let read_result = {
            let map = ebpf
                .map_mut("POLICY_MAP")
                .ok_or(MapError::MissingMap("POLICY_MAP"))?;
            let policy_map = HashMap::<_, TenantKey, Policy>::try_from(map)?;
            match policy_map.get(&tenant, 0) {
                Ok(policy) => Ok(Some(policy)),
                Err(aya::maps::MapError::KeyNotFound) => Ok(None),
                Err(error) => Err(MapError::Map(error)),
            }
        };
        drop(ebpf);
        read_result
    }

    fn collect_counters(&self) -> Result<Vec<(TenantKey, Counters)>, MapError> {
        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        let mut counters = {
            let map = ebpf
                .map_mut("COUNTERS_MAP")
                .ok_or(MapError::MissingMap("COUNTERS_MAP"))?;
            let counters_map = HashMap::<_, TenantKey, Counters>::try_from(map)?;

            let mut counters = Vec::new();
            for pair in &counters_map {
                let (tenant, value) = pair?;
                counters.push((tenant, value));
            }
            counters
        };
        drop(ebpf);

        if counters.len() > 1 {
            counters.sort_unstable_by_key(|(tenant, _)| *tenant);
        }

        Ok(counters)
    }

    fn read_global_stats(&self) -> Result<GlobalStats, MapError> {
        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        let stats = {
            let map = ebpf
                .map_mut("GLOBAL_STATS_MAP")
                .ok_or(MapError::MissingMap("GLOBAL_STATS_MAP"))?;
            let global_stats_map = Array::<_, GlobalStats>::try_from(map)?;
            global_stats_map.get(&GLOBAL_STATS_INDEX, 0)?
        };
        drop(ebpf);

        Ok(stats)
    }

    fn seed_global_config(&self, config: GlobalConfig) -> Result<(), MapError> {
        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        {
            let map = ebpf
                .map_mut("GLOBAL_CONFIG_MAP")
                .ok_or(MapError::MissingMap("GLOBAL_CONFIG_MAP"))?;
            let mut global_config_map = Array::<_, GlobalConfig>::try_from(map)?;
            global_config_map.set(GLOBAL_CONFIG_INDEX, config, 0)?;
        }
        drop(ebpf);

        Ok(())
    }

    fn set_global_enabled(&self, enabled: bool) -> Result<(), MapError> {
        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        {
            let map = ebpf
                .map_mut("GLOBAL_CONFIG_MAP")
                .ok_or(MapError::MissingMap("GLOBAL_CONFIG_MAP"))?;
            let mut global_config_map = Array::<_, GlobalConfig>::try_from(map)?;
            let mut config = read_global_config_or_default(&global_config_map)?;
            config.enabled = u8::from(enabled);
            global_config_map.set(GLOBAL_CONFIG_INDEX, config, 0)?;
        }
        drop(ebpf);

        Ok(())
    }

    fn get_global_enabled(&self) -> Result<bool, MapError> {
        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        let enabled = {
            let map = ebpf
                .map_mut("GLOBAL_CONFIG_MAP")
                .ok_or(MapError::MissingMap("GLOBAL_CONFIG_MAP"))?;
            let global_config_map = Array::<_, GlobalConfig>::try_from(map)?;
            let config = read_global_config_or_default(&global_config_map)?;
            config.enabled != 0
        };
        drop(ebpf);

        Ok(enabled)
    }
}

fn read_global_config_or_default(
    global_config_map: &Array<&mut aya::maps::MapData, GlobalConfig>,
) -> Result<GlobalConfig, MapError> {
    match global_config_map.get(&GLOBAL_CONFIG_INDEX, 0) {
        Ok(config) => Ok(config),
        Err(aya::maps::MapError::KeyNotFound) => Ok(GlobalConfig {
            enabled: 1,
            flow_keys_live: 1,
            _pad: [0; 6],
        }),
        Err(error) => Err(MapError::Map(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    use vantage_common::{PolicyMatchLevel, ReasonBuckets};

    use super::*;

    struct FixtureMapOps {
        policies: Mutex<BTreeMap<TenantKey, Policy>>,
        counters: Vec<(TenantKey, Counters)>,
        global_stats: GlobalStats,
        global_config: Mutex<GlobalConfig>,
    }

    impl FixtureMapOps {
        fn with_data(counters: Vec<(TenantKey, Counters)>, global_stats: GlobalStats) -> Arc<Self> {
            Arc::new(Self {
                policies: Mutex::new(BTreeMap::new()),
                counters,
                global_stats,
                global_config: Mutex::new(GlobalConfig {
                    enabled: 0,
                    flow_keys_live: 1,
                    _pad: [0; 6],
                }),
            })
        }
    }

    impl MapOps for FixtureMapOps {
        fn upsert_policy(&self, tenant: TenantKey, policy: Policy) -> Result<(), MapError> {
            self.policies
                .lock()
                .map_err(|_| MapError::LockPoisoned)?
                .insert(tenant, policy);
            Ok(())
        }

        fn delete_policy(&self, tenant: TenantKey) -> Result<(), MapError> {
            self.policies
                .lock()
                .map_err(|_| MapError::LockPoisoned)?
                .remove(&tenant);
            Ok(())
        }

        fn get_policy(&self, tenant: TenantKey) -> Result<Option<Policy>, MapError> {
            let policy = self
                .policies
                .lock()
                .map_err(|_| MapError::LockPoisoned)?
                .get(&tenant)
                .copied();
            Ok(policy)
        }

        fn collect_counters(&self) -> Result<Vec<(TenantKey, Counters)>, MapError> {
            Ok(self.counters.clone())
        }

        fn read_global_stats(&self) -> Result<GlobalStats, MapError> {
            Ok(self.global_stats)
        }

        fn seed_global_config(&self, config: GlobalConfig) -> Result<(), MapError> {
            {
                let mut current = self
                    .global_config
                    .lock()
                    .map_err(|_| MapError::LockPoisoned)?;
                *current = config;
            }
            Ok(())
        }

        fn set_global_enabled(&self, enabled: bool) -> Result<(), MapError> {
            {
                let mut current = self
                    .global_config
                    .lock()
                    .map_err(|_| MapError::LockPoisoned)?;
                current.enabled = u8::from(enabled);
            }
            Ok(())
        }

        fn get_global_enabled(&self) -> Result<bool, MapError> {
            let current = self
                .global_config
                .lock()
                .map_err(|_| MapError::LockPoisoned)?;
            Ok(current.enabled != 0)
        }

        fn set_flow_keys_live(&self, flow_keys_live: bool) -> Result<(), MapError> {
            {
                let mut current = self
                    .global_config
                    .lock()
                    .map_err(|_| MapError::LockPoisoned)?;
                current.flow_keys_live = u8::from(flow_keys_live);
            }
            Ok(())
        }

        fn get_flow_keys_live(&self) -> Result<bool, MapError> {
            let current = self
                .global_config
                .lock()
                .map_err(|_| MapError::LockPoisoned)?;
            Ok(current.flow_keys_live != 0)
        }
    }

    fn sample_global_stats() -> GlobalStats {
        GlobalStats {
            pass_pkts: 11,
            drop_pkts: 3,
            pass_bytes: 1500,
            drop_bytes: 300,
            reasons: ReasonBuckets {
                no_tokens: 2,
                no_policy: 1,
                parse_fail: 0,
            },
        }
    }

    #[test]
    fn read_global_stats_returns_fixture_data() {
        let maps = MapClient::from_ops(FixtureMapOps::with_data(Vec::new(), sample_global_stats()));

        let stats = maps.read_global_stats();
        let Ok(stats) = stats else {
            panic!("global stats should be readable");
        };

        assert_eq!(stats.pass_pkts, 11);
        assert_eq!(stats.drop_pkts, 3);
        assert_eq!(stats.pass_bytes, 1500);
        assert_eq!(stats.drop_bytes, 300);
        assert_eq!(stats.reasons.no_tokens, 2);
        assert_eq!(stats.reasons.no_policy, 1);
        assert_eq!(stats.reasons.parse_fail, 0);
    }

    #[test]
    fn collect_counters_preserves_fixture_values() {
        let counters = vec![(
            TenantKey {
                src_ip: 42,
                dst_port: 0,
                proto: 0,
                _pad: 0,
            },
            Counters {
                pass_pkts: 5,
                drop_pkts: 1,
                pass_bytes: 500,
                drop_bytes: 100,
            },
        )];
        let maps = MapClient::from_ops(FixtureMapOps::with_data(counters, sample_global_stats()));

        let collected = maps.collect_counters();
        let Ok(collected) = collected else {
            panic!("counters should be readable");
        };

        assert_eq!(collected.len(), 1);
        assert_eq!(
            collected[0].0,
            TenantKey {
                src_ip: 42,
                dst_port: 0,
                proto: 0,
                _pad: 0
            }
        );
        assert_eq!(collected[0].1.pass_pkts, 5);
        assert_eq!(collected[0].1.drop_pkts, 1);
        assert_eq!(collected[0].1.pass_bytes, 500);
        assert_eq!(collected[0].1.drop_bytes, 100);
    }

    #[test]
    fn policy_upsert_and_delete_work_with_fixture_storage() {
        let fixture = FixtureMapOps::with_data(Vec::new(), sample_global_stats());
        let maps = MapClient::from_ops(Arc::clone(&fixture) as Arc<dyn MapOps>);
        let policy = Policy {
            rate_tokens_per_sec: 100,
            burst_tokens: 50,
            enabled: 1,
            _pad: [0; 7],
        };

        let key = TenantKey {
            src_ip: 10,
            dst_port: 0,
            proto: 0,
            _pad: 0,
        };

        let inserted = maps.upsert_policy(key, policy);
        assert!(inserted.is_ok(), "policy insert should succeed");
        let deleted = maps.delete_policy(key);
        assert!(deleted.is_ok(), "policy delete should succeed");

        match fixture.policies.lock() {
            Ok(policies) => {
                assert!(policies.is_empty(), "policy should be removed from storage");
            }
            Err(error) => {
                panic!("fixture storage lock should not be poisoned: {error}");
            }
        }
    }

    #[test]
    fn global_enabled_round_trip_uses_fixture_storage() {
        let maps = MapClient::from_ops(FixtureMapOps::with_data(Vec::new(), sample_global_stats()));

        let initially_enabled = maps.get_global_enabled();
        let Ok(initially_enabled) = initially_enabled else {
            panic!("global enabled should be readable");
        };
        assert!(!initially_enabled);

        let set = maps.set_global_enabled(true);
        assert!(set.is_ok(), "global enabled should be writable");

        let enabled = maps.get_global_enabled();
        let Ok(enabled) = enabled else {
            panic!("global enabled should be readable after write");
        };
        assert!(enabled);
    }

    #[test]
    fn flow_keys_live_round_trip_uses_fixture_storage() {
        let maps = MapClient::from_ops(FixtureMapOps::with_data(Vec::new(), sample_global_stats()));

        let initially_live = maps.get_flow_keys_live();
        let Ok(initially_live) = initially_live else {
            panic!("flow-keys mode should be readable");
        };
        assert!(initially_live);

        let set = maps.set_flow_keys_live(false);
        assert!(set.is_ok(), "flow-keys mode should be writable");

        let live = maps.get_flow_keys_live();
        let Ok(live) = live else {
            panic!("flow-keys mode should be readable after write");
        };
        assert!(!live);
    }

    #[test]
    fn seed_global_config_overwrites_fixture_storage() {
        let maps = MapClient::from_ops(FixtureMapOps::with_data(Vec::new(), sample_global_stats()));
        let set = maps.seed_global_config(GlobalConfig {
            enabled: 1,
            flow_keys_live: 0,
            _pad: [0; 6],
        });
        assert!(set.is_ok(), "global config seed should be writable");

        let enabled = maps.get_global_enabled();
        let Ok(enabled) = enabled else {
            panic!("global enabled should be readable");
        };
        assert!(enabled);

        let flow_keys_live = maps.get_flow_keys_live();
        let Ok(flow_keys_live) = flow_keys_live else {
            panic!("flow-keys mode should be readable");
        };
        assert!(!flow_keys_live);
    }

    #[test]
    fn resolve_policy_uses_exact_then_proto_then_full_wildcard() {
        let fixture = FixtureMapOps::with_data(Vec::new(), sample_global_stats());
        let maps = MapClient::from_ops(Arc::clone(&fixture) as Arc<dyn MapOps>);
        let exact_key = TenantKey {
            src_ip: 0x0a01_0203,
            proto: 6,
            dst_port: 443,
            _pad: 0,
        };
        let proto_wildcard_key = TenantKey {
            src_ip: exact_key.src_ip,
            proto: exact_key.proto,
            dst_port: 0,
            _pad: 0,
        };
        let full_wildcard_key = TenantKey {
            src_ip: exact_key.src_ip,
            proto: 0,
            dst_port: 0,
            _pad: 0,
        };

        let upsert_full = maps.upsert_policy(
            full_wildcard_key,
            Policy {
                rate_tokens_per_sec: 100,
                burst_tokens: 10,
                enabled: 1,
                _pad: [0; 7],
            },
        );
        assert!(upsert_full.is_ok(), "full wildcard insert should succeed");

        let resolved_full = maps.resolve_policy(exact_key);
        let Ok(resolved_full) = resolved_full else {
            panic!("policy resolution should succeed");
        };
        let Some(resolved_full) = resolved_full else {
            panic!("full wildcard fallback should resolve");
        };
        assert_eq!(resolved_full.matched, full_wildcard_key);
        assert_eq!(resolved_full.match_level, PolicyMatchLevel::FullWildcard);

        let upsert_proto = maps.upsert_policy(
            proto_wildcard_key,
            Policy {
                rate_tokens_per_sec: 200,
                burst_tokens: 20,
                enabled: 1,
                _pad: [0; 7],
            },
        );
        assert!(upsert_proto.is_ok(), "proto wildcard insert should succeed");

        let resolved_proto = maps.resolve_policy(exact_key);
        let Ok(resolved_proto) = resolved_proto else {
            panic!("policy resolution should succeed");
        };
        let Some(resolved_proto) = resolved_proto else {
            panic!("proto wildcard fallback should resolve");
        };
        assert_eq!(resolved_proto.matched, proto_wildcard_key);
        assert_eq!(resolved_proto.match_level, PolicyMatchLevel::ProtoWildcard);

        let upsert_exact = maps.upsert_policy(
            exact_key,
            Policy {
                rate_tokens_per_sec: 300,
                burst_tokens: 30,
                enabled: 1,
                _pad: [0; 7],
            },
        );
        assert!(upsert_exact.is_ok(), "exact insert should succeed");

        let resolved_exact = maps.resolve_policy(exact_key);
        let Ok(resolved_exact) = resolved_exact else {
            panic!("policy resolution should succeed");
        };
        let Some(resolved_exact) = resolved_exact else {
            panic!("exact match should resolve");
        };
        assert_eq!(resolved_exact.matched, exact_key);
        assert_eq!(resolved_exact.match_level, PolicyMatchLevel::Exact);
    }
}
