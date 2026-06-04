use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub(crate) struct InferencePressureSample {
    pub(crate) ts_unix_ms: u64,
    pub(crate) tokens_used_current_minute: u64,
    pub(crate) token_budget_per_minute: u64,
    pub(crate) kv_cache_used_bytes: Option<u64>,
    pub(crate) kv_cache_capacity_bytes: Option<u64>,
    pub(crate) active_requests: Option<u64>,
    pub(crate) queued_requests: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct InferencePressure {
    pub(crate) token_budget_percent: f64,
    pub(crate) kv_cache_percent: Option<f64>,
    pub(crate) active_requests: Option<u64>,
    pub(crate) queued_requests: Option<u64>,
}

impl InferencePressureSample {
    pub(crate) const fn empty(token_budget_per_minute: u64) -> Self {
        Self {
            ts_unix_ms: 0,
            tokens_used_current_minute: 0,
            token_budget_per_minute,
            kv_cache_used_bytes: None,
            kv_cache_capacity_bytes: None,
            active_requests: None,
            queued_requests: None,
        }
    }

    pub(crate) fn pressure(self) -> InferencePressure {
        let token_budget = self.token_budget_per_minute.max(1);
        let token_budget_percent = ratio_percent(
            self.tokens_used_current_minute.min(token_budget),
            token_budget,
        );
        let kv_cache_percent = match (self.kv_cache_used_bytes, self.kv_cache_capacity_bytes) {
            (Some(used), Some(capacity)) if capacity > 0 => {
                Some(ratio_percent(used.min(capacity), capacity))
            }
            _ => None,
        };

        InferencePressure {
            token_budget_percent,
            kv_cache_percent,
            active_requests: self.active_requests,
            queued_requests: self.queued_requests,
        }
    }
}

fn ratio_percent(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    let basis_points = u128::from(numerator)
        .saturating_mul(10_000)
        .checked_div(u128::from(denominator))
        .unwrap_or(0);
    let scaled = u32::try_from(basis_points).unwrap_or(u32::MAX);
    f64::from(scaled) / 100.0
}

#[cfg(test)]
mod tests {
    use super::InferencePressureSample;

    #[test]
    fn computes_token_and_kv_percentages() {
        let sample = InferencePressureSample {
            ts_unix_ms: 1,
            tokens_used_current_minute: 45,
            token_budget_per_minute: 100,
            kv_cache_used_bytes: Some(750),
            kv_cache_capacity_bytes: Some(1_000),
            active_requests: Some(3),
            queued_requests: Some(4),
        };

        let pressure = sample.pressure();
        assert!((pressure.token_budget_percent - 45.0).abs() < f64::EPSILON);
        assert_eq!(pressure.kv_cache_percent, Some(75.0));
        assert_eq!(pressure.active_requests, Some(3));
        assert_eq!(pressure.queued_requests, Some(4));
    }

    #[test]
    fn missing_or_zero_kv_capacity_disables_kv_pressure() {
        let sample = InferencePressureSample {
            ts_unix_ms: 1,
            tokens_used_current_minute: 0,
            token_budget_per_minute: 100,
            kv_cache_used_bytes: Some(750),
            kv_cache_capacity_bytes: Some(0),
            active_requests: None,
            queued_requests: None,
        };

        assert_eq!(sample.pressure().kv_cache_percent, None);
    }

    #[test]
    fn token_percent_is_capped_at_full_budget() {
        let sample = InferencePressureSample {
            ts_unix_ms: 1,
            tokens_used_current_minute: 200,
            token_budget_per_minute: 100,
            kv_cache_used_bytes: None,
            kv_cache_capacity_bytes: None,
            active_requests: None,
            queued_requests: None,
        };

        assert!((sample.pressure().token_budget_percent - 100.0).abs() < f64::EPSILON);
    }
}
