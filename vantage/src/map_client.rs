use std::sync::{Arc, Mutex};

use aya::{
    Ebpf,
    maps::{Array, HashMap},
};
use thiserror::Error;
use vantage_common::{Counters, GlobalStats, Policy, TenantKey};

const GLOBAL_STATS_INDEX: u32 = 0;

#[derive(Debug, Error)]
pub enum MapError {
    #[error("failed to lock eBPF object")]
    LockPoisoned,
    #[error("required map '{0}' is missing")]
    MissingMap(&'static str),
    #[error("eBPF map operation failed: {0}")]
    Map(#[from] aya::maps::MapError),
}

pub(crate) trait MapOps: Send + Sync {
    fn upsert_policy(&self, tenant: TenantKey, policy: Policy) -> Result<(), MapError>;
    fn delete_policy(&self, tenant: TenantKey) -> Result<(), MapError>;
    fn collect_counters(&self) -> Result<Vec<(TenantKey, Counters)>, MapError>;
    fn read_global_stats(&self) -> Result<GlobalStats, MapError>;
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
}

impl MapOps for EbpfMapOps {
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
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    use vantage_common::ReasonBuckets;

    use super::*;

    struct FixtureMapOps {
        policies: Mutex<BTreeMap<TenantKey, Policy>>,
        counters: Vec<(TenantKey, Counters)>,
        global_stats: GlobalStats,
    }

    impl FixtureMapOps {
        fn with_data(counters: Vec<(TenantKey, Counters)>, global_stats: GlobalStats) -> Arc<Self> {
            Arc::new(Self {
                policies: Mutex::new(BTreeMap::new()),
                counters,
                global_stats,
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

        fn collect_counters(&self) -> Result<Vec<(TenantKey, Counters)>, MapError> {
            Ok(self.counters.clone())
        }

        fn read_global_stats(&self) -> Result<GlobalStats, MapError> {
            Ok(self.global_stats)
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
            42,
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
        assert_eq!(collected[0].0, 42);
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

        let inserted = maps.upsert_policy(10, policy);
        assert!(inserted.is_ok(), "policy insert should succeed");
        let deleted = maps.delete_policy(10);
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
}
