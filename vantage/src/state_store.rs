use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use vantage_common::{Policy, TenantKey};

const STATE_VERSION_V1: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeOwner {
    Manual,
    Adaptive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdaptiveUpsertOutcome {
    Applied,
    SkippedManualOwner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeDeleteMode {
    ManualOnly,
    AnyOwner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RuntimeOverrideRecord {
    pub(crate) policy: Policy,
    pub(crate) owner: RuntimeOwner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PersistedStateV1 {
    pub(crate) version: u16,
    pub(crate) global_enabled: bool,
    pub(crate) flow_keys_live: bool,
    pub(crate) essential_tenants: BTreeSet<u64>,
    #[serde(with = "base_policies_serde")]
    pub(crate) base_policies: BTreeMap<TenantKey, Policy>,
    #[serde(with = "runtime_overrides_serde")]
    pub(crate) runtime_overrides: BTreeMap<TenantKey, RuntimeOverrideRecord>,
}

impl PersistedStateV1 {
    #[must_use]
    pub(crate) fn with_defaults(defaults: &StateStoreDefaults) -> Self {
        Self {
            version: STATE_VERSION_V1,
            global_enabled: defaults.global_enabled,
            flow_keys_live: defaults.flow_keys_live,
            essential_tenants: defaults.essential_tenants.clone(),
            base_policies: BTreeMap::new(),
            runtime_overrides: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct StateStoreDefaults {
    pub(crate) global_enabled: bool,
    pub(crate) flow_keys_live: bool,
    pub(crate) essential_tenants: BTreeSet<u64>,
}

#[derive(Debug, Error)]
pub(crate) enum StateStoreError {
    #[error("failed to lock persisted state")]
    LockPoisoned,
    #[error("failed to read state file '{path}': {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write state file '{path}': {source}")]
    WriteFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse state file '{path}': {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("state file '{path}' has unsupported version {version}")]
    UnsupportedVersion { path: String, version: u16 },
}

#[derive(Clone)]
pub(crate) struct StateStore {
    inner: Arc<StateStoreInner>,
}

struct StateStoreInner {
    path: PathBuf,
    state: Mutex<PersistedStateV1>,
    revision: AtomicU64,
}

impl StateStore {
    /// Loads persisted desired state from disk, or initializes and persists defaults.
    ///
    /// # Errors
    ///
    /// Returns `StateStoreError` when the state file cannot be read/parsed/written,
    /// or when the file version is unsupported.
    pub(crate) fn load_or_init(
        path: impl Into<PathBuf>,
        defaults: &StateStoreDefaults,
    ) -> Result<Self, StateStoreError> {
        let path = path.into();
        let state = if let Some(state) = read_state_file(&path)? {
            state
        } else {
            let initial = PersistedStateV1::with_defaults(defaults);
            persist_state_file(&path, &initial)?;
            initial
        };
        Ok(Self {
            inner: Arc::new(StateStoreInner {
                path,
                state: Mutex::new(state),
                revision: AtomicU64::new(0),
            }),
        })
    }

    /// Returns an immutable point-in-time desired-state snapshot.
    ///
    /// # Errors
    ///
    /// Returns `StateStoreError` when the in-process state lock is poisoned.
    pub(crate) fn snapshot(&self) -> Result<PersistedStateV1, StateStoreError> {
        self.snapshot_with_revision().map(|(state, _)| state)
    }

    /// Returns an immutable point-in-time desired-state snapshot with revision.
    ///
    /// # Errors
    ///
    /// Returns `StateStoreError` when the in-process state lock is poisoned.
    pub(crate) fn snapshot_with_revision(
        &self,
    ) -> Result<(PersistedStateV1, u64), StateStoreError> {
        let state = self
            .inner
            .state
            .lock()
            .map_err(|_| StateStoreError::LockPoisoned)?;
        let revision = self.inner.revision.load(Ordering::Relaxed);
        Ok((state.clone(), revision))
    }

    #[must_use]
    pub(crate) fn revision(&self) -> u64 {
        self.inner.revision.load(Ordering::Relaxed)
    }

    /// Sets the persisted global enabled flag.
    ///
    /// # Errors
    ///
    /// Returns `StateStoreError` when persistence fails.
    pub(crate) fn set_global_enabled(&self, enabled: bool) -> Result<(), StateStoreError> {
        self.apply_mutation(|state| {
            state.global_enabled = enabled;
        })
    }

    /// Sets the persisted flow-keys mode.
    ///
    /// # Errors
    ///
    /// Returns `StateStoreError` when persistence fails.
    #[allow(dead_code)]
    pub(crate) fn set_flow_keys_live(&self, flow_keys_live: bool) -> Result<(), StateStoreError> {
        self.apply_mutation(|state| {
            state.flow_keys_live = flow_keys_live;
        })
    }

    /// Marks or unmarks a tenant as essential.
    ///
    /// Returns `true` when the set changed.
    ///
    /// # Errors
    ///
    /// Returns `StateStoreError` when persistence fails.
    pub(crate) fn set_essential_tenant(
        &self,
        cgroup_id: u64,
        essential: bool,
    ) -> Result<bool, StateStoreError> {
        self.apply_mutation_with_result(|state| {
            if essential {
                state.essential_tenants.insert(cgroup_id)
            } else {
                state.essential_tenants.remove(&cgroup_id)
            }
        })
    }

    /// Upserts a base policy in persisted desired state.
    ///
    /// # Errors
    ///
    /// Returns `StateStoreError` when persistence fails.
    pub(crate) fn upsert_base_policy(
        &self,
        tenant: TenantKey,
        policy: Policy,
    ) -> Result<Option<Policy>, StateStoreError> {
        self.apply_mutation_with_result(|state| state.base_policies.insert(tenant, policy))
    }

    /// Deletes a base policy from persisted desired state.
    ///
    /// # Errors
    ///
    /// Returns `StateStoreError` when persistence fails.
    pub(crate) fn delete_base_policy(
        &self,
        tenant: TenantKey,
    ) -> Result<Option<Policy>, StateStoreError> {
        self.apply_mutation_with_result(|state| state.base_policies.remove(&tenant))
    }

    /// Upserts a manual runtime override.
    ///
    /// # Errors
    ///
    /// Returns `StateStoreError` when persistence fails.
    pub(crate) fn upsert_manual_runtime_override(
        &self,
        tenant: TenantKey,
        policy: Policy,
    ) -> Result<Option<RuntimeOverrideRecord>, StateStoreError> {
        self.apply_mutation_with_result(|state| {
            state.runtime_overrides.insert(
                tenant,
                RuntimeOverrideRecord {
                    policy,
                    owner: RuntimeOwner::Manual,
                },
            )
        })
    }

    /// Deletes a runtime override using manual-delete semantics.
    ///
    /// Returns the removed record when deletion happened.
    ///
    /// # Errors
    ///
    /// Returns `StateStoreError` when persistence fails.
    pub(crate) fn delete_runtime_override_with_mode(
        &self,
        tenant: TenantKey,
        mode: RuntimeDeleteMode,
    ) -> Result<Option<RuntimeOverrideRecord>, StateStoreError> {
        self.apply_mutation_with_result(|state| match mode {
            RuntimeDeleteMode::AnyOwner => state.runtime_overrides.remove(&tenant),
            RuntimeDeleteMode::ManualOnly => {
                if state
                    .runtime_overrides
                    .get(&tenant)
                    .is_some_and(|entry| entry.owner == RuntimeOwner::Manual)
                {
                    return state.runtime_overrides.remove(&tenant);
                }
                None
            }
        })
    }

    /// Deletes a runtime override only when the owner matches.
    ///
    /// Returns `true` when an entry was removed.
    ///
    /// # Errors
    ///
    /// Returns `StateStoreError` when persistence fails.
    pub(crate) fn delete_runtime_override_if_owner(
        &self,
        tenant: TenantKey,
        owner: RuntimeOwner,
    ) -> Result<bool, StateStoreError> {
        self.apply_mutation_with_result(|state| {
            if state
                .runtime_overrides
                .get(&tenant)
                .is_some_and(|entry| entry.owner == owner)
            {
                let _ = state.runtime_overrides.remove(&tenant);
                return true;
            }
            false
        })
    }

    /// Upserts adaptive runtime override unless manually owned.
    ///
    /// Returns whether the upsert was applied or skipped due to manual ownership.
    ///
    /// # Errors
    ///
    /// Returns `StateStoreError` when persistence fails.
    pub(crate) fn upsert_adaptive_runtime_override(
        &self,
        tenant: TenantKey,
        policy: Policy,
    ) -> Result<AdaptiveUpsertOutcome, StateStoreError> {
        self.apply_mutation_with_result(|state| {
            if state
                .runtime_overrides
                .get(&tenant)
                .is_some_and(|entry| entry.owner == RuntimeOwner::Manual)
            {
                return AdaptiveUpsertOutcome::SkippedManualOwner;
            }
            let _ = state.runtime_overrides.insert(
                tenant,
                RuntimeOverrideRecord {
                    policy,
                    owner: RuntimeOwner::Adaptive,
                },
            );
            AdaptiveUpsertOutcome::Applied
        })
    }

    fn apply_mutation<F>(&self, mutate: F) -> Result<(), StateStoreError>
    where
        F: FnOnce(&mut PersistedStateV1),
    {
        self.apply_mutation_with_result(|state| {
            mutate(state);
        })
    }

    fn apply_mutation_with_result<F, R>(&self, mutate: F) -> Result<R, StateStoreError>
    where
        F: FnOnce(&mut PersistedStateV1) -> R,
    {
        let mut guard = self
            .inner
            .state
            .lock()
            .map_err(|_| StateStoreError::LockPoisoned)?;
        let mut candidate = guard.clone();
        let result = mutate(&mut candidate);
        persist_state_file(&self.inner.path, &candidate)?;
        *guard = candidate;
        let _ = self.inner.revision.fetch_add(1, Ordering::Relaxed);
        drop(guard);
        Ok(result)
    }
}

#[derive(Debug, Deserialize)]
struct VersionOnlyState {
    version: u16,
}

fn read_state_file(path: &Path) -> Result<Option<PersistedStateV1>, StateStoreError> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StateStoreError::ReadFile {
                path: path.display().to_string(),
                source,
            });
        }
    };

    let version_probe: VersionOnlyState =
        serde_json::from_slice(&data).map_err(|source| StateStoreError::Parse {
            path: path.display().to_string(),
            source,
        })?;

    if version_probe.version != STATE_VERSION_V1 {
        return Err(StateStoreError::UnsupportedVersion {
            path: path.display().to_string(),
            version: version_probe.version,
        });
    }

    let state = serde_json::from_slice::<PersistedStateV1>(&data).map_err(|source| {
        StateStoreError::Parse {
            path: path.display().to_string(),
            source,
        }
    })?;

    Ok(Some(state))
}

fn persist_state_file(path: &Path, state: &PersistedStateV1) -> Result<(), StateStoreError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|source| StateStoreError::WriteFile {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let tmp_path = tmp_path_for(path);
    if tmp_path.exists() {
        fs::remove_file(&tmp_path).map_err(|source| StateStoreError::WriteFile {
            path: tmp_path.display().to_string(),
            source,
        })?;
    }

    let bytes = serde_json::to_vec_pretty(state).map_err(|source| StateStoreError::Parse {
        path: path.display().to_string(),
        source,
    })?;

    let mut tmp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|source| StateStoreError::WriteFile {
            path: tmp_path.display().to_string(),
            source,
        })?;
    tmp.write_all(&bytes)
        .and_then(|()| tmp.write_all(b"\n"))
        .and_then(|()| tmp.flush())
        .and_then(|()| tmp.sync_all())
        .map_err(|source| StateStoreError::WriteFile {
            path: tmp_path.display().to_string(),
            source,
        })?;
    drop(tmp);

    fs::rename(&tmp_path, path).map_err(|source| StateStoreError::WriteFile {
        path: path.display().to_string(),
        source,
    })?;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let dir = File::open(parent).map_err(|source| StateStoreError::WriteFile {
            path: parent.display().to_string(),
            source,
        })?;
        dir.sync_all()
            .map_err(|source| StateStoreError::WriteFile {
                path: parent.display().to_string(),
                source,
            })?;
    }

    Ok(())
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut tmp = path.to_path_buf();
    let extension = match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if !ext.is_empty() => format!("{ext}.tmp"),
        _ => "tmp".to_owned(),
    };
    tmp.set_extension(extension);
    tmp
}

mod base_policies_serde {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Serialize, de::Error as _, ser::SerializeSeq};
    use vantage_common::{Policy, TenantKey};

    #[derive(Serialize, Deserialize)]
    struct Entry {
        tenant: TenantKey,
        policy: Policy,
    }

    pub(super) fn serialize<S>(
        map: &BTreeMap<TenantKey, Policy>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(map.len()))?;
        for (&tenant, &policy) in map {
            seq.serialize_element(&Entry { tenant, policy })?;
        }
        seq.end()
    }

    pub(super) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<TenantKey, Policy>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let entries = Vec::<Entry>::deserialize(deserializer)?;
        let mut out = BTreeMap::new();
        for entry in entries {
            if out.insert(entry.tenant, entry.policy).is_some() {
                return Err(D::Error::custom("duplicate base policy tenant key"));
            }
        }
        Ok(out)
    }
}

mod runtime_overrides_serde {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Serialize, de::Error as _, ser::SerializeSeq};
    use vantage_common::{Policy, TenantKey};

    use crate::state_store::{RuntimeOverrideRecord, RuntimeOwner};

    #[derive(Serialize, Deserialize)]
    struct Entry {
        tenant: TenantKey,
        policy: Policy,
        owner: RuntimeOwner,
    }

    pub(super) fn serialize<S>(
        map: &BTreeMap<TenantKey, RuntimeOverrideRecord>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(map.len()))?;
        for (&tenant, record) in map {
            seq.serialize_element(&Entry {
                tenant,
                policy: record.policy,
                owner: record.owner,
            })?;
        }
        seq.end()
    }

    pub(super) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<TenantKey, RuntimeOverrideRecord>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let entries = Vec::<Entry>::deserialize(deserializer)?;
        let mut out = BTreeMap::new();
        for entry in entries {
            if out
                .insert(
                    entry.tenant,
                    RuntimeOverrideRecord {
                        policy: entry.policy,
                        owner: entry.owner,
                    },
                )
                .is_some()
            {
                return Err(D::Error::custom("duplicate runtime override tenant key"));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        path::{Path, PathBuf},
    };

    use vantage_common::{Policy, TenantKey};

    use super::{
        AdaptiveUpsertOutcome, RuntimeDeleteMode, RuntimeOwner, StateStore, StateStoreDefaults,
        StateStoreError,
    };

    fn test_policy(rate: u64, burst: u64, enabled: bool) -> Policy {
        Policy {
            rate_tokens_per_sec: rate,
            burst_tokens: burst,
            enabled: u8::from(enabled),
            _pad: [0; 7],
        }
    }

    fn tenant(cgroup_id: u64) -> TenantKey {
        TenantKey {
            cgroup_id,
            http_path_hash: 0,
            dst_port: 0,
            proto: 0,
            http_method: 0,
        }
    }

    fn unique_test_dir(name: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0_u128, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!(
            "vantage_state_store_{name}_{}_{}",
            std::process::id(),
            stamp
        ))
    }

    fn state_path(root: &Path) -> PathBuf {
        root.join("state.json")
    }

    #[test]
    fn initializes_missing_file_with_defaults() {
        let root = unique_test_dir("init_defaults");
        let create = fs::create_dir_all(&root);
        assert!(create.is_ok(), "test directory should be created");

        let mut essential = BTreeSet::new();
        let inserted = essential.insert(42);
        assert!(inserted, "fixture insert should change set");
        let defaults = StateStoreDefaults {
            global_enabled: true,
            flow_keys_live: false,
            essential_tenants: essential,
        };

        let store = StateStore::load_or_init(state_path(&root), &defaults);
        let Ok(store) = store else {
            panic!("store should initialize from defaults");
        };
        let snapshot = store.snapshot();
        let Ok(snapshot) = snapshot else {
            panic!("snapshot should succeed");
        };
        assert_eq!(snapshot.version, 1);
        assert!(snapshot.global_enabled);
        assert!(!snapshot.flow_keys_live);
        assert!(snapshot.essential_tenants.contains(&42));
        assert!(snapshot.base_policies.is_empty());
        assert!(snapshot.runtime_overrides.is_empty());
    }

    #[test]
    fn rejects_unsupported_version() {
        let root = unique_test_dir("unsupported_version");
        let create = fs::create_dir_all(&root);
        assert!(create.is_ok(), "test directory should be created");

        let write = fs::write(
            state_path(&root),
            r#"{"version":2,"global_enabled":true,"flow_keys_live":true,"essential_tenants":[],"base_policies":[],"runtime_overrides":[]}"#,
        );
        assert!(write.is_ok(), "fixture state should be written");

        let defaults = StateStoreDefaults::default();
        let loaded = StateStore::load_or_init(state_path(&root), &defaults);
        let Err(error) = loaded else {
            panic!("unsupported version should fail");
        };
        assert!(
            matches!(
                error,
                StateStoreError::UnsupportedVersion { version: 2, .. }
            ),
            "error should report unsupported version: {error}"
        );
    }

    #[test]
    fn mutation_persists_and_is_visible_after_reload() {
        let root = unique_test_dir("persist_reload");
        let create = fs::create_dir_all(&root);
        assert!(create.is_ok(), "test directory should be created");

        let path = state_path(&root);
        let defaults = StateStoreDefaults::default();
        let store = StateStore::load_or_init(path.clone(), &defaults);
        let Ok(store) = store else {
            panic!("store should initialize");
        };
        let set_enabled = store.set_global_enabled(true);
        assert!(set_enabled.is_ok(), "global enabled update should persist");
        let upsert_base = store.upsert_base_policy(tenant(7), test_policy(10, 20, true));
        assert!(upsert_base.is_ok(), "base policy upsert should persist");
        let upsert_runtime =
            store.upsert_manual_runtime_override(tenant(11), test_policy(1, 2, true));
        assert!(
            upsert_runtime.is_ok(),
            "runtime override upsert should persist"
        );

        let defaults = StateStoreDefaults::default();
        let reloaded = StateStore::load_or_init(path, &defaults);
        let Ok(reloaded) = reloaded else {
            panic!("store should reload persisted data");
        };
        let snapshot = reloaded.snapshot();
        let Ok(snapshot) = snapshot else {
            panic!("snapshot should succeed");
        };

        assert!(snapshot.global_enabled);
        assert_eq!(
            snapshot.base_policies.get(&tenant(7)),
            Some(&test_policy(10, 20, true))
        );
        assert_eq!(
            snapshot
                .runtime_overrides
                .get(&tenant(11))
                .map(|record| record.owner),
            Some(RuntimeOwner::Manual)
        );
    }

    #[test]
    fn adaptive_upsert_does_not_override_manual_owner() {
        let root = unique_test_dir("adaptive_owner_guard");
        let create = fs::create_dir_all(&root);
        assert!(create.is_ok(), "test directory should be created");

        let defaults = StateStoreDefaults::default();
        let store = StateStore::load_or_init(state_path(&root), &defaults);
        let Ok(store) = store else {
            panic!("store should initialize");
        };

        let manual = store.upsert_manual_runtime_override(tenant(9), test_policy(200, 300, true));
        assert!(manual.is_ok(), "manual override insert should persist");

        let adaptive = store.upsert_adaptive_runtime_override(tenant(9), test_policy(1, 1, true));
        let Ok(adaptive) = adaptive else {
            panic!("adaptive upsert should complete");
        };
        assert_eq!(
            adaptive,
            AdaptiveUpsertOutcome::SkippedManualOwner,
            "adaptive override must not replace manual owner"
        );

        let snapshot = store.snapshot();
        let Ok(snapshot) = snapshot else {
            panic!("snapshot should succeed");
        };
        assert_eq!(
            snapshot
                .runtime_overrides
                .get(&tenant(9))
                .map(|record| record.owner),
            Some(RuntimeOwner::Manual)
        );
        assert_eq!(
            snapshot
                .runtime_overrides
                .get(&tenant(9))
                .map(|record| record.policy),
            Some(test_policy(200, 300, true))
        );
    }

    #[test]
    fn exposes_full_mutation_surface() {
        let root = unique_test_dir("full_mutations");
        let create = fs::create_dir_all(&root);
        assert!(create.is_ok(), "test directory should be created");

        let defaults = StateStoreDefaults::default();
        let store = StateStore::load_or_init(state_path(&root), &defaults);
        let Ok(store) = store else {
            panic!("store should initialize");
        };

        let flow_set = store.set_flow_keys_live(true);
        assert!(flow_set.is_ok(), "flow-key mode should persist");

        let essential_added = store.set_essential_tenant(99, true);
        let Ok(essential_added) = essential_added else {
            panic!("essential set should succeed");
        };
        assert!(essential_added, "essential insert should report change");

        let base_insert = store.upsert_base_policy(tenant(99), test_policy(9, 9, true));
        assert!(base_insert.is_ok(), "base policy upsert should succeed");
        let base_deleted = store.delete_base_policy(tenant(99));
        let Ok(base_deleted) = base_deleted else {
            panic!("base policy delete should succeed");
        };
        assert!(
            base_deleted.is_some(),
            "base policy delete should return removed entry"
        );

        let runtime_insert =
            store.upsert_manual_runtime_override(tenant(99), test_policy(3, 3, true));
        assert!(
            runtime_insert.is_ok(),
            "runtime override upsert should succeed"
        );
        let owner_deleted =
            store.delete_runtime_override_if_owner(tenant(99), RuntimeOwner::Adaptive);
        let Ok(owner_deleted) = owner_deleted else {
            panic!("owner-specific delete should succeed");
        };
        assert!(
            !owner_deleted,
            "owner-specific delete should not remove manual-owned entries"
        );

        let runtime_insert_manual =
            store.upsert_manual_runtime_override(tenant(99), test_policy(4, 4, true));
        assert!(
            runtime_insert_manual.is_ok(),
            "manual runtime override upsert should succeed"
        );
        let runtime_deleted =
            store.delete_runtime_override_with_mode(tenant(99), RuntimeDeleteMode::AnyOwner);
        let Ok(runtime_deleted) = runtime_deleted else {
            panic!("runtime delete should succeed");
        };
        assert!(
            runtime_deleted.is_some(),
            "runtime delete should report change"
        );
    }

    #[test]
    fn manual_delete_mode_requires_manual_owner_unless_forced() {
        let root = unique_test_dir("manual_delete_modes");
        let create = fs::create_dir_all(&root);
        assert!(create.is_ok(), "test directory should be created");

        let defaults = StateStoreDefaults::default();
        let store = StateStore::load_or_init(state_path(&root), &defaults);
        let Ok(store) = store else {
            panic!("store should initialize");
        };

        let inserted = store.upsert_adaptive_runtime_override(tenant(123), test_policy(5, 5, true));
        let Ok(inserted) = inserted else {
            panic!("adaptive runtime override upsert should succeed");
        };
        assert_eq!(inserted, AdaptiveUpsertOutcome::Applied);

        let manual_only =
            store.delete_runtime_override_with_mode(tenant(123), RuntimeDeleteMode::ManualOnly);
        let Ok(manual_only) = manual_only else {
            panic!("manual-only delete should succeed");
        };
        assert!(
            manual_only.is_none(),
            "manual-only delete must not remove adaptive-owned entries"
        );

        let forced =
            store.delete_runtime_override_with_mode(tenant(123), RuntimeDeleteMode::AnyOwner);
        let Ok(forced) = forced else {
            panic!("forced delete should succeed");
        };
        assert!(
            forced.is_some(),
            "forced delete should remove the entry regardless of owner"
        );
    }

    #[test]
    fn revision_advances_on_successful_mutations() {
        let root = unique_test_dir("revisions");
        let create = fs::create_dir_all(&root);
        assert!(create.is_ok(), "test directory should be created");

        let defaults = StateStoreDefaults::default();
        let store = StateStore::load_or_init(state_path(&root), &defaults);
        let Ok(store) = store else {
            panic!("store should initialize");
        };

        assert_eq!(store.revision(), 0, "initial revision should start at zero");

        let set_enabled = store.set_global_enabled(true);
        assert!(set_enabled.is_ok(), "global enabled update should persist");
        assert_eq!(
            store.revision(),
            1,
            "revision should advance after mutation"
        );

        let set_flow = store.set_flow_keys_live(true);
        assert!(set_flow.is_ok(), "flow-keys update should persist");
        let (snapshot, snapshot_revision) = store
            .snapshot_with_revision()
            .unwrap_or_else(|error| panic!("snapshot with revision should succeed: {error}"));
        assert!(
            snapshot.flow_keys_live,
            "snapshot should include latest value"
        );
        assert_eq!(
            snapshot_revision, 2,
            "snapshot revision should match mutation count"
        );
    }
}
