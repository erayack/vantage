use std::sync::{Arc, Mutex};

use aya::{Ebpf, maps::HashMap};
use thiserror::Error;
use vantage_common::{Counters, LockedCounters, Policy, TenantKey};

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
            let counters_map = HashMap::<_, TenantKey, LockedCounters>::try_from(map)?;

            let mut counters = Vec::new();
            for pair in &counters_map {
                let (tenant, locked) = pair?;
                counters.push((tenant, locked.counters));
            }
            counters
        };
        drop(ebpf);

        if counters.len() > 1 {
            counters.sort_unstable_by_key(|(tenant, _)| *tenant);
        }

        Ok(counters)
    }
}
