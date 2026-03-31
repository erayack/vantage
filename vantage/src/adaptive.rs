use std::{
    collections::BTreeSet,
    sync::{Arc, RwLock},
    time::Duration,
};

use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{MissedTickBehavior, interval},
};
use tracing::{debug, warn};
use vantage_common::{Policy, TenantKey};

use crate::{
    AppState,
    map_client::MapError,
    metrics::{MetricsError, sample_host_load_window_async},
    state_store::StateStoreError,
    tenancy::TenancyError,
};

#[derive(Debug, thiserror::Error)]
enum AdaptiveError {
    #[error(transparent)]
    Map(#[from] MapError),
    #[error(transparent)]
    Metrics(#[from] MetricsError),
    #[error(transparent)]
    Tenancy(#[from] TenancyError),
    #[error(transparent)]
    StateStore(#[from] StateStoreError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AdaptiveState {
    #[default]
    Inactive,
    Throttling,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AdaptiveRuntimeSnapshot {
    pub(crate) state: AdaptiveState,
    pub(crate) active_override_count: u64,
}

#[derive(Clone, Default)]
pub(crate) struct AdaptiveRuntimeState {
    inner: Arc<RwLock<AdaptiveRuntimeSnapshot>>,
}

impl AdaptiveRuntimeState {
    pub(crate) fn update(&self, state: AdaptiveState, active_override_count: usize) {
        match self.inner.write() {
            Ok(mut snapshot) => {
                snapshot.state = state;
                snapshot.active_override_count =
                    u64::try_from(active_override_count).unwrap_or(u64::MAX);
            }
            Err(mut error) => {
                let snapshot = error.get_mut();
                snapshot.state = state;
                snapshot.active_override_count =
                    u64::try_from(active_override_count).unwrap_or(u64::MAX);
            }
        }
    }

    pub(crate) fn snapshot(&self) -> AdaptiveRuntimeSnapshot {
        match self.inner.read() {
            Ok(snapshot) => *snapshot,
            Err(error) => *error.into_inner(),
        }
    }
}

pub(crate) fn spawn_adaptive_controller(
    app: AppState,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let tick = Duration::from_millis(app.config.adaptive.tick_ms);
        let mut ticker = interval(tick);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut mode = AdaptiveState::Inactive;
        let mut managed_overrides = BTreeSet::new();
        app.adaptive_runtime.update(mode, managed_overrides.len());
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    match changed {
                        Ok(()) if *shutdown_rx.borrow() => break,
                        Ok(()) => {}
                        Err(_) => break,
                    }
                }
                _ = ticker.tick() => {
                    if let Err(error) = tick_controller(&app, &mut mode, &mut managed_overrides).await {
                        warn!(%error, "adaptive controller tick failed");
                    }
                }
            }
        }

        if let Err(error) = clear_managed_overrides(&app, &mut managed_overrides) {
            warn!(%error, "adaptive controller shutdown cleanup failed");
        }
        app.adaptive_runtime
            .update(AdaptiveState::Inactive, managed_overrides.len());
    })
}

async fn tick_controller(
    app: &AppState,
    mode: &mut AdaptiveState,
    managed_overrides: &mut BTreeSet<TenantKey>,
) -> Result<(), AdaptiveError> {
    let sample_window = Duration::from_millis(app.config.adaptive.tick_ms);
    let sample = sample_host_load_window_async(sample_window).await?;
    let high = f64::from(app.config.adaptive.high_watermark_percent);
    let low = f64::from(app.config.adaptive.low_watermark_percent);
    let high_reached = sample.system_cpu_percent >= high || sample.system_memory_percent >= high;
    let recovered = sample.system_cpu_percent <= low && sample.system_memory_percent <= low;

    match *mode {
        AdaptiveState::Inactive => {
            if high_reached {
                reconcile_managed_overrides(app, managed_overrides)?;
                *mode = AdaptiveState::Throttling;
                debug!(
                    cpu = sample.system_cpu_percent,
                    memory = sample.system_memory_percent,
                    overrides = managed_overrides.len(),
                    "adaptive controller entered throttling mode"
                );
            }
        }
        AdaptiveState::Throttling => {
            if recovered {
                clear_managed_overrides(app, managed_overrides)?;
                *mode = AdaptiveState::Inactive;
                debug!(
                    cpu = sample.system_cpu_percent,
                    memory = sample.system_memory_percent,
                    "adaptive controller exited throttling mode"
                );
            } else {
                reconcile_managed_overrides(app, managed_overrides)?;
            }
        }
    }
    app.adaptive_runtime.update(*mode, managed_overrides.len());

    Ok(())
}

fn reconcile_managed_overrides(
    app: &AppState,
    managed_overrides: &mut BTreeSet<TenantKey>,
) -> Result<(), AdaptiveError> {
    let target = target_override_keys(app)?;
    let mut to_remove = Vec::new();

    for key in managed_overrides.iter().copied() {
        if target.contains(&key) {
            continue;
        }
        let removed = app
            .state_store
            .delete_runtime_override_if_owner(key, crate::state_store::RuntimeOwner::Adaptive)?;
        if removed {
            app.maps.delete_runtime_policy(key)?;
        }
        to_remove.push(key);
    }

    for key in to_remove {
        managed_overrides.remove(&key);
    }

    let policy = throttle_policy(app);
    for key in target {
        if managed_overrides.contains(&key) {
            continue;
        }
        let stored = app
            .state_store
            .upsert_adaptive_runtime_override(key, policy)?;
        if stored {
            app.maps.upsert_runtime_policy(key, policy)?;
            managed_overrides.insert(key);
        }
    }

    Ok(())
}

fn clear_managed_overrides(
    app: &AppState,
    managed_overrides: &mut BTreeSet<TenantKey>,
) -> Result<(), AdaptiveError> {
    let to_remove: Vec<_> = managed_overrides.iter().copied().collect();
    for key in to_remove {
        let removed = app
            .state_store
            .delete_runtime_override_if_owner(key, crate::state_store::RuntimeOwner::Adaptive)?;
        if removed {
            app.maps.delete_runtime_policy(key)?;
        }
        let _ = managed_overrides.remove(&key);
    }
    Ok(())
}

fn target_override_keys(app: &AppState) -> Result<BTreeSet<TenantKey>, AdaptiveError> {
    let mut cgroups = app.maps.collect_base_policy_tenants()?;
    for (key, _) in app.maps.collect_counters()? {
        cgroups.insert(key.cgroup_id);
    }

    let mut keys = BTreeSet::new();
    for cgroup_id in cgroups {
        if app.tenancy.is_essential(cgroup_id)? {
            continue;
        }
        keys.insert(tenant_wildcard_key(cgroup_id));
    }
    Ok(keys)
}

const fn tenant_wildcard_key(cgroup_id: u64) -> TenantKey {
    TenantKey {
        cgroup_id,
        dst_port: 0,
        proto: 0,
        http_method: 0,
        http_path_hash: 0,
    }
}

const fn throttle_policy(app: &AppState) -> Policy {
    Policy {
        rate_tokens_per_sec: app.config.adaptive.throttle_rate_tokens_per_sec,
        burst_tokens: app.config.adaptive.throttle_burst_tokens,
        enabled: 1,
        _pad: [0; 7],
    }
}
