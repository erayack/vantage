use std::{
    collections::BTreeSet,
    sync::{Arc, RwLock},
};

use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum TenancyError {
    #[error("failed to lock tenancy state")]
    LockPoisoned,
}

#[derive(Clone, Default)]
pub(crate) struct TenancyState {
    essential: Arc<RwLock<BTreeSet<u64>>>,
}

impl TenancyState {
    pub(crate) fn new(essential: BTreeSet<u64>) -> Self {
        Self {
            essential: Arc::new(RwLock::new(essential)),
        }
    }

    pub(crate) fn is_essential(&self, cgroup_id: u64) -> Result<bool, TenancyError> {
        let essential = self
            .essential
            .read()
            .map_err(|_| TenancyError::LockPoisoned)?;
        Ok(essential.contains(&cgroup_id))
    }

    pub(crate) fn set_essential(
        &self,
        cgroup_id: u64,
        is_essential: bool,
    ) -> Result<bool, TenancyError> {
        let mut essential = self
            .essential
            .write()
            .map_err(|_| TenancyError::LockPoisoned)?;
        if is_essential {
            return Ok(essential.insert(cgroup_id));
        }

        Ok(essential.remove(&cgroup_id))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::TenancyState;

    #[test]
    fn defaults_to_non_essential() {
        let state = TenancyState::default();
        let checked = state.is_essential(42);
        let Ok(checked) = checked else {
            panic!("tenancy lookup should succeed");
        };
        assert!(!checked);
    }

    #[test]
    fn can_mark_and_unmark_essential() {
        let mut initial = BTreeSet::new();
        initial.insert(11);
        let state = TenancyState::new(initial);

        let is_essential = state.is_essential(11);
        let Ok(is_essential) = is_essential else {
            panic!("tenancy lookup should succeed");
        };
        assert!(is_essential);

        let changed = state.set_essential(22, true);
        let Ok(changed) = changed else {
            panic!("tenancy update should succeed");
        };
        assert!(changed);

        let removed = state.set_essential(11, false);
        let Ok(removed) = removed else {
            panic!("tenancy update should succeed");
        };
        assert!(removed);

        let still = state.is_essential(11);
        let Ok(still) = still else {
            panic!("tenancy lookup should succeed");
        };
        assert!(!still);
    }
}
