use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

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
const POLICY_MAP_NAME: &str = "POLICY_MAP";
const RUNTIME_POLICY_MAP_NAME: &str = "RUNTIME_POLICY_MAP";

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
    pub source: PolicySource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySource {
    RuntimeOverride,
    Base,
}

pub(crate) trait MapOps: Send + Sync {
    fn upsert_policy(&self, tenant: TenantKey, policy: Policy) -> Result<(), MapError>;
    fn upsert_policies_batch(&self, entries: &[(TenantKey, Policy)]) -> Result<(), MapError> {
        for (tenant, policy) in entries.iter().copied() {
            self.upsert_policy(tenant, policy)?;
        }
        Ok(())
    }
    fn delete_policy(&self, tenant: TenantKey) -> Result<(), MapError>;
    fn delete_policies_batch(&self, tenants: &[TenantKey]) -> Result<(), MapError> {
        for tenant in tenants.iter().copied() {
            self.delete_policy(tenant)?;
        }
        Ok(())
    }
    fn get_policy(&self, tenant: TenantKey) -> Result<Option<Policy>, MapError>;
    fn upsert_runtime_policy(&self, tenant: TenantKey, policy: Policy) -> Result<(), MapError>;
    fn upsert_runtime_policies_batch(
        &self,
        entries: &[(TenantKey, Policy)],
    ) -> Result<(), MapError> {
        for (tenant, policy) in entries.iter().copied() {
            self.upsert_runtime_policy(tenant, policy)?;
        }
        Ok(())
    }
    fn delete_runtime_policy(&self, tenant: TenantKey) -> Result<(), MapError>;
    fn delete_runtime_policies_batch(&self, tenants: &[TenantKey]) -> Result<(), MapError> {
        for tenant in tenants.iter().copied() {
            self.delete_runtime_policy(tenant)?;
        }
        Ok(())
    }
    fn get_runtime_policy(&self, tenant: TenantKey) -> Result<Option<Policy>, MapError>;
    fn collect_policy_keys(&self) -> Result<Vec<TenantKey>, MapError>;
    fn collect_runtime_policy_keys(&self) -> Result<Vec<TenantKey>, MapError>;
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

    /// Inserts or updates a runtime override policy entry for a tenant.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map write fails.
    pub fn upsert_runtime_policy(&self, tenant: TenantKey, policy: Policy) -> Result<(), MapError> {
        self.inner.upsert_runtime_policy(tenant, policy)
    }

    /// Removes a runtime override policy entry for a tenant.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map delete fails.
    pub fn delete_runtime_policy(&self, tenant: TenantKey) -> Result<(), MapError> {
        self.inner.delete_runtime_policy(tenant)
    }

    /// Reads an exact runtime override policy entry for a tenant key.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map read fails.
    pub fn get_runtime_policy(&self, tenant: TenantKey) -> Result<Option<Policy>, MapError> {
        self.inner.get_runtime_policy(tenant)
    }

    /// Inserts or updates a batch of policy entries in `POLICY_MAP`.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map writes fail.
    pub fn upsert_policies_batch(&self, entries: &[(TenantKey, Policy)]) -> Result<(), MapError> {
        self.inner.upsert_policies_batch(entries)
    }

    /// Removes a batch of policy entries from `POLICY_MAP`.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map deletes fail.
    pub fn delete_policies_batch(&self, tenants: &[TenantKey]) -> Result<(), MapError> {
        self.inner.delete_policies_batch(tenants)
    }

    /// Inserts or updates a batch of runtime override policy entries in `RUNTIME_POLICY_MAP`.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map writes fail.
    pub fn upsert_runtime_policies_batch(
        &self,
        entries: &[(TenantKey, Policy)],
    ) -> Result<(), MapError> {
        self.inner.upsert_runtime_policies_batch(entries)
    }

    /// Removes a batch of runtime override policy entries from `RUNTIME_POLICY_MAP`.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map deletes fail.
    pub fn delete_runtime_policies_batch(&self, tenants: &[TenantKey]) -> Result<(), MapError> {
        self.inner.delete_runtime_policies_batch(tenants)
    }

    /// Resolves the effective policy for a tenant using precedence rules.
    ///
    /// Precedence order:
    /// 1. runtime policy fallback chain
    /// 2. base policy fallback chain
    ///
    /// # Errors
    ///
    /// Returns `MapError` when map access fails.
    pub fn resolve_policy(&self, requested: TenantKey) -> Result<Option<ResolvedPolicy>, MapError> {
        if let Some(resolved) =
            Self::resolve_policy_from_chain(requested, PolicySource::RuntimeOverride, |tenant| {
                self.get_runtime_policy(tenant)
            })?
        {
            return Ok(Some(resolved));
        }

        Self::resolve_policy_from_chain(requested, PolicySource::Base, |tenant| {
            self.get_policy(tenant)
        })
    }

    fn resolve_policy_from_chain<F>(
        requested: TenantKey,
        source: PolicySource,
        mut getter: F,
    ) -> Result<Option<ResolvedPolicy>, MapError>
    where
        F: FnMut(TenantKey) -> Result<Option<Policy>, MapError>,
    {
        let (exact, path_wildcard, method_path_wildcard, port_method_path_wildcard, full_wildcard) =
            fallback_policy_keys(requested);
        let candidates = [
            Some(exact),
            path_wildcard,
            method_path_wildcard,
            port_method_path_wildcard,
            full_wildcard,
        ];
        let mut prior: Option<TenantKey> = None;

        for candidate in candidates.into_iter().flatten() {
            if prior == Some(candidate) {
                continue;
            }
            prior = Some(candidate);

            if let Some(policy) = getter(candidate)? {
                let level =
                    policy_match_level(requested, candidate).unwrap_or(PolicyMatchLevel::Exact);
                return Ok(Some(ResolvedPolicy {
                    requested,
                    matched: candidate,
                    match_level: level,
                    policy,
                    source,
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

    /// Reads all policy keys from `POLICY_MAP`.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map iteration fails.
    pub fn collect_policy_keys(&self) -> Result<Vec<TenantKey>, MapError> {
        self.inner.collect_policy_keys()
    }

    /// Reads all policy keys from `RUNTIME_POLICY_MAP`.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when lock acquisition, map lookup, or map iteration fails.
    pub fn collect_runtime_policy_keys(&self) -> Result<Vec<TenantKey>, MapError> {
        self.inner.collect_runtime_policy_keys()
    }

    /// Reads all cgroup IDs with at least one base policy selector in `POLICY_MAP`.
    ///
    /// # Errors
    ///
    /// Returns `MapError` when policy key iteration fails.
    pub fn collect_base_policy_tenants(&self) -> Result<BTreeSet<u64>, MapError> {
        let keys = self.collect_policy_keys()?;
        let mut tenants = BTreeSet::new();
        for key in keys {
            tenants.insert(key.cgroup_id);
        }
        Ok(tenants)
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
        self.upsert_policy_to_map(POLICY_MAP_NAME, tenant, policy)
    }

    fn delete_policy(&self, tenant: TenantKey) -> Result<(), MapError> {
        self.delete_policy_from_map(POLICY_MAP_NAME, tenant)
    }

    fn upsert_policies_batch(&self, entries: &[(TenantKey, Policy)]) -> Result<(), MapError> {
        self.upsert_policies_to_map_batch(POLICY_MAP_NAME, entries)
    }

    fn delete_policies_batch(&self, tenants: &[TenantKey]) -> Result<(), MapError> {
        self.delete_policies_from_map_batch(POLICY_MAP_NAME, tenants, false)
    }

    fn get_policy(&self, tenant: TenantKey) -> Result<Option<Policy>, MapError> {
        self.get_policy_from_map(POLICY_MAP_NAME, tenant)
    }

    fn upsert_runtime_policy(&self, tenant: TenantKey, policy: Policy) -> Result<(), MapError> {
        self.upsert_policy_to_map(RUNTIME_POLICY_MAP_NAME, tenant, policy)
    }

    fn upsert_runtime_policies_batch(
        &self,
        entries: &[(TenantKey, Policy)],
    ) -> Result<(), MapError> {
        self.upsert_policies_to_map_batch(RUNTIME_POLICY_MAP_NAME, entries)
    }

    fn delete_runtime_policy(&self, tenant: TenantKey) -> Result<(), MapError> {
        match self.delete_policy_from_map(RUNTIME_POLICY_MAP_NAME, tenant) {
            Err(MapError::MissingMap(RUNTIME_POLICY_MAP_NAME)) => Ok(()),
            other => other,
        }
    }

    fn delete_runtime_policies_batch(&self, tenants: &[TenantKey]) -> Result<(), MapError> {
        self.delete_policies_from_map_batch(RUNTIME_POLICY_MAP_NAME, tenants, true)
    }

    fn get_runtime_policy(&self, tenant: TenantKey) -> Result<Option<Policy>, MapError> {
        match self.get_policy_from_map(RUNTIME_POLICY_MAP_NAME, tenant) {
            Err(MapError::MissingMap(RUNTIME_POLICY_MAP_NAME)) => Ok(None),
            other => other,
        }
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

    fn collect_policy_keys(&self) -> Result<Vec<TenantKey>, MapError> {
        self.collect_policy_keys_from_map(POLICY_MAP_NAME, false)
    }

    fn collect_runtime_policy_keys(&self) -> Result<Vec<TenantKey>, MapError> {
        self.collect_policy_keys_from_map(RUNTIME_POLICY_MAP_NAME, true)
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

impl EbpfMapOps {
    fn upsert_policies_to_map_batch(
        &self,
        map_name: &'static str,
        entries: &[(TenantKey, Policy)],
    ) -> Result<(), MapError> {
        if entries.is_empty() {
            return Ok(());
        }

        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        {
            let map = ebpf
                .map_mut(map_name)
                .ok_or(MapError::MissingMap(map_name))?;
            let mut policy_map = HashMap::<_, TenantKey, Policy>::try_from(map)?;
            for &(tenant, policy) in entries {
                policy_map.insert(tenant, policy, 0)?;
            }
        }
        drop(ebpf);

        Ok(())
    }

    fn delete_policies_from_map_batch(
        &self,
        map_name: &'static str,
        tenants: &[TenantKey],
        missing_map_is_empty: bool,
    ) -> Result<(), MapError> {
        if tenants.is_empty() {
            return Ok(());
        }

        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        let remove_result: Result<(), MapError> = {
            let map = match ebpf.map_mut(map_name) {
                Some(map) => map,
                None if missing_map_is_empty => return Ok(()),
                None => return Err(MapError::MissingMap(map_name)),
            };
            let mut policy_map = HashMap::<_, TenantKey, Policy>::try_from(map)?;
            for tenant in tenants {
                match policy_map.remove(tenant) {
                    Ok(()) | Err(aya::maps::MapError::KeyNotFound) => {}
                    Err(error) => return Err(MapError::Map(error)),
                }
            }
            Ok(())
        };
        drop(ebpf);
        remove_result?;

        Ok(())
    }

    fn collect_policy_keys_from_map(
        &self,
        map_name: &'static str,
        missing_map_is_empty: bool,
    ) -> Result<Vec<TenantKey>, MapError> {
        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        let mut keys = {
            let map = match ebpf.map_mut(map_name) {
                Some(map) => map,
                None if missing_map_is_empty => return Ok(Vec::new()),
                None => return Err(MapError::MissingMap(map_name)),
            };
            let policy_map = HashMap::<_, TenantKey, Policy>::try_from(map)?;

            let mut keys = Vec::new();
            for pair in &policy_map {
                let (tenant, _) = pair?;
                keys.push(tenant);
            }
            keys
        };
        drop(ebpf);

        if keys.len() > 1 {
            keys.sort_unstable();
            keys.dedup();
        }

        Ok(keys)
    }
    fn upsert_policy_to_map(
        &self,
        map_name: &'static str,
        tenant: TenantKey,
        policy: Policy,
    ) -> Result<(), MapError> {
        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        {
            let map = ebpf
                .map_mut(map_name)
                .ok_or(MapError::MissingMap(map_name))?;
            let mut policy_map = HashMap::<_, TenantKey, Policy>::try_from(map)?;
            policy_map.insert(tenant, policy, 0)?;
        }
        drop(ebpf);

        Ok(())
    }

    fn delete_policy_from_map(
        &self,
        map_name: &'static str,
        tenant: TenantKey,
    ) -> Result<(), MapError> {
        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        let remove_result = {
            let map = ebpf
                .map_mut(map_name)
                .ok_or(MapError::MissingMap(map_name))?;
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

    fn get_policy_from_map(
        &self,
        map_name: &'static str,
        tenant: TenantKey,
    ) -> Result<Option<Policy>, MapError> {
        let mut ebpf = self.ebpf.lock().map_err(|_| MapError::LockPoisoned)?;
        let read_result = {
            let map = ebpf
                .map_mut(map_name)
                .ok_or(MapError::MissingMap(map_name))?;
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
        runtime_policies: Mutex<BTreeMap<TenantKey, Policy>>,
        counters: Vec<(TenantKey, Counters)>,
        global_stats: GlobalStats,
        global_config: Mutex<GlobalConfig>,
    }

    impl FixtureMapOps {
        fn with_data(counters: Vec<(TenantKey, Counters)>, global_stats: GlobalStats) -> Arc<Self> {
            Arc::new(Self {
                policies: Mutex::new(BTreeMap::new()),
                runtime_policies: Mutex::new(BTreeMap::new()),
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

        fn upsert_runtime_policy(&self, tenant: TenantKey, policy: Policy) -> Result<(), MapError> {
            self.runtime_policies
                .lock()
                .map_err(|_| MapError::LockPoisoned)?
                .insert(tenant, policy);
            Ok(())
        }

        fn delete_runtime_policy(&self, tenant: TenantKey) -> Result<(), MapError> {
            self.runtime_policies
                .lock()
                .map_err(|_| MapError::LockPoisoned)?
                .remove(&tenant);
            Ok(())
        }

        fn get_runtime_policy(&self, tenant: TenantKey) -> Result<Option<Policy>, MapError> {
            let policy = self
                .runtime_policies
                .lock()
                .map_err(|_| MapError::LockPoisoned)?
                .get(&tenant)
                .copied();
            Ok(policy)
        }

        fn collect_policy_keys(&self) -> Result<Vec<TenantKey>, MapError> {
            let policies = self.policies.lock().map_err(|_| MapError::LockPoisoned)?;
            Ok(policies.keys().copied().collect())
        }

        fn collect_runtime_policy_keys(&self) -> Result<Vec<TenantKey>, MapError> {
            let policies = self
                .runtime_policies
                .lock()
                .map_err(|_| MapError::LockPoisoned)?;
            Ok(policies.keys().copied().collect())
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

    struct FailingBatchOps {
        policies: Mutex<BTreeMap<TenantKey, Policy>>,
        fail_upsert_policy: TenantKey,
    }

    impl FailingBatchOps {
        fn with_fail_upsert_policy(fail_upsert_policy: TenantKey) -> Arc<Self> {
            Arc::new(Self {
                policies: Mutex::new(BTreeMap::new()),
                fail_upsert_policy,
            })
        }
    }

    impl MapOps for FailingBatchOps {
        fn upsert_policy(&self, tenant: TenantKey, policy: Policy) -> Result<(), MapError> {
            if tenant == self.fail_upsert_policy {
                return Err(MapError::MissingMap(POLICY_MAP_NAME));
            }
            self.policies
                .lock()
                .map_err(|_| MapError::LockPoisoned)?
                .insert(tenant, policy);
            Ok(())
        }

        fn delete_policy(&self, _tenant: TenantKey) -> Result<(), MapError> {
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

        fn upsert_runtime_policy(
            &self,
            _tenant: TenantKey,
            _policy: Policy,
        ) -> Result<(), MapError> {
            Ok(())
        }

        fn delete_runtime_policy(&self, _tenant: TenantKey) -> Result<(), MapError> {
            Ok(())
        }

        fn get_runtime_policy(&self, _tenant: TenantKey) -> Result<Option<Policy>, MapError> {
            Ok(None)
        }

        fn collect_policy_keys(&self) -> Result<Vec<TenantKey>, MapError> {
            let policies = self.policies.lock().map_err(|_| MapError::LockPoisoned)?;
            Ok(policies.keys().copied().collect())
        }

        fn collect_runtime_policy_keys(&self) -> Result<Vec<TenantKey>, MapError> {
            Ok(Vec::new())
        }

        fn collect_counters(&self) -> Result<Vec<(TenantKey, Counters)>, MapError> {
            Ok(Vec::new())
        }

        fn read_global_stats(&self) -> Result<GlobalStats, MapError> {
            Ok(sample_global_stats())
        }

        fn seed_global_config(&self, _config: GlobalConfig) -> Result<(), MapError> {
            Ok(())
        }

        fn set_global_enabled(&self, _enabled: bool) -> Result<(), MapError> {
            Ok(())
        }

        fn get_global_enabled(&self) -> Result<bool, MapError> {
            Ok(true)
        }

        fn set_flow_keys_live(&self, _flow_keys_live: bool) -> Result<(), MapError> {
            Ok(())
        }

        fn get_flow_keys_live(&self) -> Result<bool, MapError> {
            Ok(true)
        }
    }

    struct MissingRuntimeMapBatchDeleteOps;

    impl MapOps for MissingRuntimeMapBatchDeleteOps {
        fn upsert_policy(&self, _tenant: TenantKey, _policy: Policy) -> Result<(), MapError> {
            Ok(())
        }

        fn delete_policy(&self, _tenant: TenantKey) -> Result<(), MapError> {
            Ok(())
        }

        fn get_policy(&self, _tenant: TenantKey) -> Result<Option<Policy>, MapError> {
            Ok(None)
        }

        fn upsert_runtime_policy(
            &self,
            _tenant: TenantKey,
            _policy: Policy,
        ) -> Result<(), MapError> {
            Err(MapError::MissingMap(RUNTIME_POLICY_MAP_NAME))
        }

        fn delete_runtime_policy(&self, _tenant: TenantKey) -> Result<(), MapError> {
            Err(MapError::MissingMap(RUNTIME_POLICY_MAP_NAME))
        }

        fn delete_runtime_policies_batch(&self, _tenants: &[TenantKey]) -> Result<(), MapError> {
            Ok(())
        }

        fn get_runtime_policy(&self, _tenant: TenantKey) -> Result<Option<Policy>, MapError> {
            Ok(None)
        }

        fn collect_policy_keys(&self) -> Result<Vec<TenantKey>, MapError> {
            Ok(Vec::new())
        }

        fn collect_runtime_policy_keys(&self) -> Result<Vec<TenantKey>, MapError> {
            Ok(Vec::new())
        }

        fn collect_counters(&self) -> Result<Vec<(TenantKey, Counters)>, MapError> {
            Ok(Vec::new())
        }

        fn read_global_stats(&self) -> Result<GlobalStats, MapError> {
            Ok(sample_global_stats())
        }

        fn seed_global_config(&self, _config: GlobalConfig) -> Result<(), MapError> {
            Ok(())
        }

        fn set_global_enabled(&self, _enabled: bool) -> Result<(), MapError> {
            Ok(())
        }

        fn get_global_enabled(&self) -> Result<bool, MapError> {
            Ok(true)
        }

        fn set_flow_keys_live(&self, _flow_keys_live: bool) -> Result<(), MapError> {
            Ok(())
        }

        fn get_flow_keys_live(&self) -> Result<bool, MapError> {
            Ok(true)
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
                cgroup_id: 42,
                http_path_hash: 0,
                dst_port: 0,
                proto: 0,
                http_method: 0,
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
                cgroup_id: 42,
                http_path_hash: 0,
                dst_port: 0,
                proto: 0,
                http_method: 0
            }
        );
        assert_eq!(collected[0].1.pass_pkts, 5);
        assert_eq!(collected[0].1.drop_pkts, 1);
        assert_eq!(collected[0].1.pass_bytes, 500);
        assert_eq!(collected[0].1.drop_bytes, 100);
    }

    #[test]
    fn collect_base_policy_tenants_deduplicates_cgroup_ids() {
        let fixture = FixtureMapOps::with_data(Vec::new(), sample_global_stats());
        let maps = MapClient::from_ops(Arc::clone(&fixture) as Arc<dyn MapOps>);
        let key_a = TenantKey {
            cgroup_id: 10,
            http_path_hash: 0,
            dst_port: 80,
            proto: 6,
            http_method: 0,
        };
        let key_b = TenantKey {
            cgroup_id: 10,
            http_path_hash: 123,
            dst_port: 80,
            proto: 6,
            http_method: 1,
        };
        let key_c = TenantKey {
            cgroup_id: 20,
            http_path_hash: 0,
            dst_port: 0,
            proto: 0,
            http_method: 0,
        };
        let policy = Policy {
            rate_tokens_per_sec: 100,
            burst_tokens: 100,
            enabled: 1,
            _pad: [0; 7],
        };

        assert!(maps.upsert_policy(key_a, policy).is_ok());
        assert!(maps.upsert_policy(key_b, policy).is_ok());
        assert!(maps.upsert_policy(key_c, policy).is_ok());

        let tenants = maps.collect_base_policy_tenants();
        let Ok(tenants) = tenants else {
            panic!("base policy tenant collection should succeed");
        };
        assert_eq!(tenants.len(), 2);
        assert!(tenants.contains(&10));
        assert!(tenants.contains(&20));
    }

    #[test]
    fn collect_runtime_policy_keys_reads_runtime_entries() {
        let fixture = FixtureMapOps::with_data(Vec::new(), sample_global_stats());
        let maps = MapClient::from_ops(Arc::clone(&fixture) as Arc<dyn MapOps>);
        let key_a = TenantKey {
            cgroup_id: 10,
            http_path_hash: 0,
            dst_port: 80,
            proto: 6,
            http_method: 0,
        };
        let key_b = TenantKey {
            cgroup_id: 10,
            http_path_hash: 1,
            dst_port: 8080,
            proto: 6,
            http_method: 1,
        };
        let policy = Policy {
            rate_tokens_per_sec: 100,
            burst_tokens: 100,
            enabled: 1,
            _pad: [0; 7],
        };

        assert!(maps.upsert_runtime_policy(key_b, policy).is_ok());
        assert!(maps.upsert_runtime_policy(key_a, policy).is_ok());

        let collected = maps.collect_runtime_policy_keys();
        let Ok(mut collected) = collected else {
            panic!("runtime policy key collection should succeed");
        };
        collected.sort_unstable();
        assert_eq!(collected, vec![key_a, key_b]);
    }

    #[test]
    fn policy_batch_upsert_and_delete_work_with_fixture_storage() {
        let fixture = FixtureMapOps::with_data(Vec::new(), sample_global_stats());
        let maps = MapClient::from_ops(Arc::clone(&fixture) as Arc<dyn MapOps>);
        let key_a = TenantKey {
            cgroup_id: 100,
            http_path_hash: 0,
            dst_port: 80,
            proto: 6,
            http_method: 0,
        };
        let key_b = TenantKey {
            cgroup_id: 101,
            http_path_hash: 1,
            dst_port: 443,
            proto: 6,
            http_method: 1,
        };
        let policy = Policy {
            rate_tokens_per_sec: 300,
            burst_tokens: 30,
            enabled: 1,
            _pad: [0; 7],
        };

        let inserted = maps.upsert_policies_batch(&[(key_a, policy), (key_b, policy)]);
        assert!(inserted.is_ok(), "policy batch insert should succeed");

        let keys = maps.collect_policy_keys();
        let Ok(mut keys) = keys else {
            panic!("policy keys should be readable");
        };
        keys.sort_unstable();
        assert_eq!(keys, vec![key_a, key_b]);

        let deleted = maps.delete_policies_batch(&[key_a]);
        assert!(deleted.is_ok(), "policy batch delete should succeed");

        let remaining = maps.collect_policy_keys();
        let Ok(remaining) = remaining else {
            panic!("policy keys should be readable after batch delete");
        };
        assert_eq!(remaining, vec![key_b]);
    }

    #[test]
    fn runtime_policy_batch_upsert_and_delete_work_with_fixture_storage() {
        let fixture = FixtureMapOps::with_data(Vec::new(), sample_global_stats());
        let maps = MapClient::from_ops(Arc::clone(&fixture) as Arc<dyn MapOps>);
        let key_a = TenantKey {
            cgroup_id: 110,
            http_path_hash: 0,
            dst_port: 8080,
            proto: 6,
            http_method: 0,
        };
        let key_b = TenantKey {
            cgroup_id: 111,
            http_path_hash: 1,
            dst_port: 8443,
            proto: 6,
            http_method: 1,
        };
        let policy = Policy {
            rate_tokens_per_sec: 400,
            burst_tokens: 40,
            enabled: 1,
            _pad: [0; 7],
        };

        let inserted = maps.upsert_runtime_policies_batch(&[(key_a, policy), (key_b, policy)]);
        assert!(
            inserted.is_ok(),
            "runtime policy batch insert should succeed"
        );

        let keys = maps.collect_runtime_policy_keys();
        let Ok(mut keys) = keys else {
            panic!("runtime policy keys should be readable");
        };
        keys.sort_unstable();
        assert_eq!(keys, vec![key_a, key_b]);

        let deleted = maps.delete_runtime_policies_batch(&[key_a]);
        assert!(
            deleted.is_ok(),
            "runtime policy batch delete should succeed"
        );

        let remaining = maps.collect_runtime_policy_keys();
        let Ok(remaining) = remaining else {
            panic!("runtime policy keys should be readable after batch delete");
        };
        assert_eq!(remaining, vec![key_b]);
    }

    #[test]
    fn policy_batch_upsert_propagates_errors_after_prior_entries() {
        let key_ok = TenantKey {
            cgroup_id: 500,
            http_path_hash: 0,
            dst_port: 80,
            proto: 6,
            http_method: 0,
        };
        let key_fail = TenantKey {
            cgroup_id: 501,
            http_path_hash: 0,
            dst_port: 80,
            proto: 6,
            http_method: 0,
        };
        let policy = Policy {
            rate_tokens_per_sec: 700,
            burst_tokens: 70,
            enabled: 1,
            _pad: [0; 7],
        };
        let fixture = FailingBatchOps::with_fail_upsert_policy(key_fail);
        let maps = MapClient::from_ops(Arc::clone(&fixture) as Arc<dyn MapOps>);

        let result = maps.upsert_policies_batch(&[(key_ok, policy), (key_fail, policy)]);
        assert!(
            result.is_err(),
            "batch upsert should fail on configured key"
        );

        let inserted_ok = maps.get_policy(key_ok);
        let Ok(inserted_ok) = inserted_ok else {
            panic!("first key should still be queryable");
        };
        assert_eq!(inserted_ok, Some(policy));

        let inserted_fail = maps.get_policy(key_fail);
        let Ok(inserted_fail) = inserted_fail else {
            panic!("failed key should still be queryable");
        };
        assert_eq!(inserted_fail, None);
    }

    #[test]
    fn runtime_policy_batch_delete_treats_missing_runtime_map_as_empty() {
        let key = TenantKey {
            cgroup_id: 600,
            http_path_hash: 0,
            dst_port: 0,
            proto: 0,
            http_method: 0,
        };
        let maps = MapClient::from_ops(Arc::new(MissingRuntimeMapBatchDeleteOps));

        let deleted = maps.delete_runtime_policies_batch(&[key]);
        assert!(
            deleted.is_ok(),
            "runtime batch delete should succeed when runtime map is missing"
        );
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
            cgroup_id: 10,
            http_path_hash: 0,
            dst_port: 0,
            proto: 0,
            http_method: 0,
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
    fn resolve_policy_uses_exact_then_port_method_path_then_full_wildcard() {
        let fixture = FixtureMapOps::with_data(Vec::new(), sample_global_stats());
        let maps = MapClient::from_ops(Arc::clone(&fixture) as Arc<dyn MapOps>);
        let exact_key = TenantKey {
            cgroup_id: 0x0a01_0203,
            http_path_hash: 0,
            proto: 6,
            dst_port: 443,
            http_method: 0,
        };
        let port_method_path_wildcard_key = TenantKey {
            cgroup_id: exact_key.cgroup_id,
            http_path_hash: exact_key.http_path_hash,
            proto: exact_key.proto,
            dst_port: 0,
            http_method: 0,
        };
        let full_wildcard_key = TenantKey {
            cgroup_id: exact_key.cgroup_id,
            http_path_hash: exact_key.http_path_hash,
            proto: 0,
            dst_port: 0,
            http_method: 0,
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
        assert_eq!(resolved_full.source, PolicySource::Base);

        let upsert_port_method_path = maps.upsert_policy(
            port_method_path_wildcard_key,
            Policy {
                rate_tokens_per_sec: 200,
                burst_tokens: 20,
                enabled: 1,
                _pad: [0; 7],
            },
        );
        assert!(
            upsert_port_method_path.is_ok(),
            "port/method/path wildcard insert should succeed"
        );

        let resolved_proto = maps.resolve_policy(exact_key);
        let Ok(resolved_proto) = resolved_proto else {
            panic!("policy resolution should succeed");
        };
        let Some(resolved_proto) = resolved_proto else {
            panic!("port/method/path wildcard fallback should resolve");
        };
        assert_eq!(resolved_proto.matched, port_method_path_wildcard_key);
        assert_eq!(
            resolved_proto.match_level,
            PolicyMatchLevel::PortMethodPathWildcard
        );
        assert_eq!(resolved_proto.source, PolicySource::Base);

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
        assert_eq!(resolved_exact.source, PolicySource::Base);
    }

    #[test]
    fn resolve_policy_prefers_runtime_chain_before_base_chain() {
        let fixture = FixtureMapOps::with_data(Vec::new(), sample_global_stats());
        let maps = MapClient::from_ops(Arc::clone(&fixture) as Arc<dyn MapOps>);
        let requested_key = TenantKey {
            cgroup_id: 0x0a01_0203,
            http_path_hash: 0x00ab_cdef,
            proto: 6,
            dst_port: 443,
            http_method: 1,
        };
        let runtime_full_wildcard_key = TenantKey {
            cgroup_id: requested_key.cgroup_id,
            http_path_hash: 0,
            proto: 0,
            dst_port: 0,
            http_method: 0,
        };
        let base_exact_key = requested_key;

        let upsert_runtime = maps.upsert_runtime_policy(
            runtime_full_wildcard_key,
            Policy {
                rate_tokens_per_sec: 100,
                burst_tokens: 10,
                enabled: 1,
                _pad: [0; 7],
            },
        );
        assert!(
            upsert_runtime.is_ok(),
            "runtime wildcard insert should succeed"
        );

        let upsert_base_exact = maps.upsert_policy(
            base_exact_key,
            Policy {
                rate_tokens_per_sec: 300,
                burst_tokens: 30,
                enabled: 1,
                _pad: [0; 7],
            },
        );
        assert!(
            upsert_base_exact.is_ok(),
            "base exact insert should succeed"
        );

        let resolved = maps.resolve_policy(requested_key);
        let Ok(resolved) = resolved else {
            panic!("policy resolution should succeed");
        };
        let Some(resolved) = resolved else {
            panic!("runtime wildcard fallback should resolve before base exact");
        };
        assert_eq!(resolved.matched, runtime_full_wildcard_key);
        assert_eq!(resolved.match_level, PolicyMatchLevel::FullWildcard);
        assert_eq!(resolved.source, PolicySource::RuntimeOverride);
    }
}
