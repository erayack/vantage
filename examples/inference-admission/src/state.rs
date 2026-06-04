use crate::controller::DesiredAdmission;

#[derive(Debug, Clone, Default)]
pub(crate) struct LastAppliedState {
    desired: Option<DesiredAdmission>,
}

impl LastAppliedState {
    pub(crate) fn should_apply(&self, desired: &DesiredAdmission) -> bool {
        self.desired.as_ref() != Some(desired)
    }

    pub(crate) const fn mark_applied(&mut self, desired: DesiredAdmission) {
        self.desired = Some(desired);
    }
}
