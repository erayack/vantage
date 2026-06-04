use std::{fs, io::ErrorKind, path::PathBuf};

use thiserror::Error;
use tracing::info;

use crate::{
    config::Config,
    gpu::{GpuError, GpuUtilSample, GpuUtilSource},
    inference::{InferencePressure, InferencePressureSample},
    state::LastAppliedState,
    vantage_client::{AdmissionClient, ClientError, PolicyShape, PolicyTarget},
};

const TOKEN_THROTTLE_HIGH_PERCENT: f64 = 90.0;
const TOKEN_THROTTLE_LOW_PERCENT: f64 = 80.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionMode {
    Normal,
    Throttled { reason: ThrottleReason },
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThrottleReason {
    Gpu,
    KvCache,
    TokenBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DesiredAdmission {
    pub(crate) mode: AdmissionMode,
    pub(crate) base_policy: PolicyShape,
    pub(crate) runtime_policy: Option<PolicyShape>,
}

#[derive(Debug, Error)]
pub(crate) enum ControllerError {
    #[error(transparent)]
    Gpu(#[from] GpuError),
    #[error(transparent)]
    Inference(#[from] InferenceSourceError),
    #[error(transparent)]
    Client(#[from] ClientError),
}

pub(crate) struct AdmissionController<Client, Gpu, Inference> {
    config: Config,
    client: Client,
    gpu_source: Gpu,
    inference_source: Inference,
    mode: AdmissionMode,
    last_applied: LastAppliedState,
}

#[derive(Debug, Clone)]
pub(crate) struct FileInferenceSource {
    path: Option<PathBuf>,
    default_token_budget_per_minute: u64,
}

#[derive(Debug, Error)]
pub(crate) enum InferenceSourceError {
    #[error("failed to read inference metrics file '{path}': {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse inference metrics file '{path}': {source}")]
    ParseFile {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

pub(crate) trait InferenceSource {
    fn sample(&self) -> Result<InferencePressureSample, InferenceSourceError>;
}

impl FileInferenceSource {
    pub(crate) const fn new(path: Option<PathBuf>, default_token_budget_per_minute: u64) -> Self {
        Self {
            path,
            default_token_budget_per_minute,
        }
    }
}

impl InferenceSource for FileInferenceSource {
    fn sample(&self) -> Result<InferencePressureSample, InferenceSourceError> {
        let Some(path) = &self.path else {
            return Ok(InferencePressureSample::empty(
                self.default_token_budget_per_minute,
            ));
        };
        let data = match fs::read(path) {
            Ok(data) => data,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(InferencePressureSample::empty(
                    self.default_token_budget_per_minute,
                ));
            }
            Err(source) => {
                return Err(InferenceSourceError::ReadFile {
                    path: path.display().to_string(),
                    source,
                });
            }
        };
        serde_json::from_slice::<InferencePressureSample>(&data).map_err(|source| {
            InferenceSourceError::ParseFile {
                path: path.display().to_string(),
                source,
            }
        })
    }
}

impl<Client, Gpu, Inference> AdmissionController<Client, Gpu, Inference>
where
    Client: AdmissionClient,
    Gpu: GpuUtilSource,
    Inference: InferenceSource,
{
    pub(crate) fn new(
        config: Config,
        client: Client,
        gpu_source: Gpu,
        inference_source: Inference,
    ) -> Self {
        Self {
            config,
            client,
            gpu_source,
            inference_source,
            mode: AdmissionMode::Normal,
            last_applied: LastAppliedState::default(),
        }
    }

    pub(crate) async fn tick(&mut self) -> Result<(), ControllerError> {
        let gpu_sample = self.gpu_source.sample()?;
        let inference_sample = self.inference_source.sample()?;
        let desired = decide_admission(
            &self.config,
            self.mode,
            gpu_sample,
            inference_sample,
            inference_sample.pressure(),
        );
        self.apply_if_changed(desired).await?;
        self.mode = desired.mode;
        Ok(())
    }

    pub(crate) async fn clear_runtime_override(&mut self) -> Result<(), ControllerError> {
        self.client
            .delete_runtime_policy(&policy_target(&self.config), false)
            .await?;
        self.mode = AdmissionMode::Normal;
        Ok(())
    }

    async fn apply_if_changed(&mut self, desired: DesiredAdmission) -> Result<(), ControllerError> {
        if !self.last_applied.should_apply(&desired) {
            return Ok(());
        }

        let target = policy_target(&self.config);
        self.client
            .put_base_policy(&target, desired.base_policy)
            .await?;
        match desired.runtime_policy {
            Some(policy) => {
                self.client.put_runtime_policy(&target, policy).await?;
            }
            None => {
                self.client.delete_runtime_policy(&target, false).await?;
            }
        }
        info!(mode = ?desired.mode, "applied inference admission policy");
        self.last_applied.mark_applied(desired);
        Ok(())
    }
}

fn decide_admission(
    config: &Config,
    current_mode: AdmissionMode,
    gpu_sample: Option<GpuUtilSample>,
    inference_sample: InferencePressureSample,
    pressure: InferencePressure,
) -> DesiredAdmission {
    let gpu_high = gpu_sample
        .is_some_and(|sample| sample.utilization_percent >= config.gpu_high_watermark_percent);
    let gpu_recovered = gpu_sample
        .is_none_or(|sample| sample.utilization_percent <= config.gpu_low_watermark_percent);
    let kv_high = pressure
        .kv_cache_percent
        .is_some_and(|percent| percent >= config.kv_high_watermark_percent);
    let kv_recovered = pressure
        .kv_cache_percent
        .is_none_or(|percent| percent <= config.kv_low_watermark_percent);
    let token_high = pressure.token_budget_percent >= TOKEN_THROTTLE_HIGH_PERCENT;
    let token_recovered = pressure.token_budget_percent <= TOKEN_THROTTLE_LOW_PERCENT;
    let exhausted = inference_sample.tokens_used_current_minute
        >= inference_sample.token_budget_per_minute.max(1);

    let mode = if config.disabled_on_exhaustion && exhausted {
        AdmissionMode::Exhausted
    } else if gpu_high {
        AdmissionMode::Throttled {
            reason: ThrottleReason::Gpu,
        }
    } else if kv_high {
        AdmissionMode::Throttled {
            reason: ThrottleReason::KvCache,
        }
    } else if token_high {
        AdmissionMode::Throttled {
            reason: ThrottleReason::TokenBudget,
        }
    } else if matches!(
        current_mode,
        AdmissionMode::Throttled { .. } | AdmissionMode::Exhausted
    ) && !(gpu_recovered && kv_recovered && token_recovered)
    {
        current_mode
    } else {
        AdmissionMode::Normal
    };

    DesiredAdmission {
        mode,
        base_policy: normal_policy(config),
        runtime_policy: runtime_policy_for_mode(config, mode),
    }
}

const fn normal_policy(config: &Config) -> PolicyShape {
    PolicyShape {
        rate_tokens_per_sec: config.normal_rate_tokens_per_sec,
        burst_tokens: config.normal_burst_tokens,
        enabled: true,
    }
}

const fn runtime_policy_for_mode(config: &Config, mode: AdmissionMode) -> Option<PolicyShape> {
    match mode {
        AdmissionMode::Normal => None,
        AdmissionMode::Throttled { .. } => Some(PolicyShape {
            rate_tokens_per_sec: config.throttle_rate_tokens_per_sec,
            burst_tokens: config.throttle_burst_tokens,
            enabled: true,
        }),
        AdmissionMode::Exhausted => Some(PolicyShape {
            rate_tokens_per_sec: 1,
            burst_tokens: 1,
            enabled: false,
        }),
    }
}

fn policy_target(config: &Config) -> PolicyTarget {
    PolicyTarget {
        cgroup_id: config.tenant.cgroup_id,
        proto: "tcp",
        dst_port: config.inference_port,
        http_method: "post",
        http_path: config.inference_http_path.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{AdmissionMode, ThrottleReason, decide_admission, runtime_policy_for_mode};
    use crate::{
        config::Config,
        gpu::{GpuError, GpuUtilSample, GpuUtilSource},
        inference::InferencePressureSample,
        vantage_client::{ClientError, PolicyShape, PolicyTarget},
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum ClientCall {
        PutBase(PolicyTarget, PolicyShape),
        PutRuntime(PolicyTarget, PolicyShape),
        DeleteRuntime(PolicyTarget, bool),
    }

    #[derive(Debug, Clone, Default)]
    struct FakeClient {
        calls: Arc<Mutex<Vec<ClientCall>>>,
        fail_after_calls: Option<usize>,
    }

    impl FakeClient {
        fn with_failure_after(fail_after_calls: usize) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                fail_after_calls: Some(fail_after_calls),
            }
        }

        fn calls(&self) -> Vec<ClientCall> {
            match self.calls.lock() {
                Ok(calls) => calls.clone(),
                Err(error) => error.into_inner().clone(),
            }
        }

        fn record(&self, call: ClientCall) -> Result<(), ClientError> {
            {
                let mut calls = match self.calls.lock() {
                    Ok(calls) => calls,
                    Err(error) => error.into_inner(),
                };
                if self
                    .fail_after_calls
                    .is_some_and(|limit| calls.len() >= limit)
                {
                    return Err(ClientError::InvalidResponse("fixture failure".to_owned()));
                }
                calls.push(call);
            }
            Ok(())
        }
    }

    impl crate::vantage_client::AdmissionClient for FakeClient {
        async fn put_base_policy(
            &self,
            target: &PolicyTarget,
            policy: PolicyShape,
        ) -> Result<(), ClientError> {
            self.record(ClientCall::PutBase(target.clone(), policy))
        }

        async fn put_runtime_policy(
            &self,
            target: &PolicyTarget,
            policy: PolicyShape,
        ) -> Result<(), ClientError> {
            self.record(ClientCall::PutRuntime(target.clone(), policy))
        }

        async fn delete_runtime_policy(
            &self,
            target: &PolicyTarget,
            force: bool,
        ) -> Result<(), ClientError> {
            self.record(ClientCall::DeleteRuntime(target.clone(), force))
        }
    }

    #[derive(Debug, Clone)]
    struct FixedGpu(Option<GpuUtilSample>);

    impl GpuUtilSource for FixedGpu {
        fn sample(&self) -> Result<Option<GpuUtilSample>, GpuError> {
            Ok(self.0)
        }
    }

    #[derive(Debug, Clone)]
    struct FixedInference(InferencePressureSample);

    impl super::InferenceSource for FixedInference {
        fn sample(&self) -> Result<InferencePressureSample, super::InferenceSourceError> {
            Ok(self.0)
        }
    }

    fn config(disabled_on_exhaustion: bool) -> Config {
        let parsed = Config::try_from_iter([
            "vantage-inference-admission",
            "--tenant",
            "42",
            "--disabled-on-exhaustion",
        ]);
        let Ok(mut config) = parsed else {
            panic!("config should parse");
        };
        config.disabled_on_exhaustion = disabled_on_exhaustion;
        config
    }

    fn sample(tokens: u64, kv_used: Option<u64>) -> InferencePressureSample {
        InferencePressureSample {
            ts_unix_ms: 1,
            tokens_used_current_minute: tokens,
            token_budget_per_minute: 100,
            kv_cache_used_bytes: kv_used,
            kv_cache_capacity_bytes: Some(100),
            active_requests: None,
            queued_requests: None,
        }
    }

    fn target() -> PolicyTarget {
        PolicyTarget {
            cgroup_id: 42,
            proto: "tcp",
            dst_port: 8000,
            http_method: "post",
            http_path: "/v1/chat/completions".to_owned(),
        }
    }

    #[tokio::test]
    async fn normal_tick_applies_base_and_clears_runtime_override() {
        let config = config(false);
        let client = FakeClient::default();
        let mut controller = super::AdmissionController::new(
            config.clone(),
            client.clone(),
            FixedGpu(None),
            FixedInference(sample(0, None)),
        );

        let tick = controller.tick().await;
        assert!(tick.is_ok(), "tick should apply normal state");

        assert_eq!(
            client.calls(),
            vec![
                ClientCall::PutBase(target(), super::normal_policy(&config)),
                ClientCall::DeleteRuntime(target(), false),
            ]
        );
    }

    #[tokio::test]
    async fn throttled_tick_applies_runtime_override() {
        let config = config(false);
        let client = FakeClient::default();
        let mut controller = super::AdmissionController::new(
            config.clone(),
            client.clone(),
            FixedGpu(Some(GpuUtilSample {
                ts_unix_ms: 1,
                utilization_percent: 95.0,
            })),
            FixedInference(sample(0, None)),
        );

        let tick = controller.tick().await;
        assert!(tick.is_ok(), "tick should apply throttled state");

        assert_eq!(
            client.calls(),
            vec![
                ClientCall::PutBase(target(), super::normal_policy(&config)),
                ClientCall::PutRuntime(
                    target(),
                    runtime_policy_for_mode(
                        &config,
                        AdmissionMode::Throttled {
                            reason: ThrottleReason::Gpu,
                        }
                    )
                    .unwrap_or_else(|| panic!("throttled mode should have policy")),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn apply_failure_does_not_mark_state_applied() {
        let config = config(false);
        let expected_policy = super::normal_policy(&config);
        let client = FakeClient::with_failure_after(1);
        let mut controller = super::AdmissionController::new(
            config,
            client.clone(),
            FixedGpu(Some(GpuUtilSample {
                ts_unix_ms: 1,
                utilization_percent: 95.0,
            })),
            FixedInference(sample(0, None)),
        );

        let first = controller.tick().await;
        assert!(first.is_err(), "runtime apply should fail");
        let second = controller.tick().await;
        assert!(
            second.is_err(),
            "state should retry because it was not marked applied"
        );

        assert_eq!(
            client.calls(),
            vec![ClientCall::PutBase(target(), expected_policy)]
        );
    }

    #[test]
    fn gpu_high_enters_throttled() {
        let config = config(false);
        let inference = sample(0, None);
        let desired = decide_admission(
            &config,
            AdmissionMode::Normal,
            Some(GpuUtilSample {
                ts_unix_ms: 1,
                utilization_percent: 95.0,
            }),
            inference,
            inference.pressure(),
        );

        assert_eq!(
            desired.mode,
            AdmissionMode::Throttled {
                reason: ThrottleReason::Gpu
            }
        );
        assert!(desired.runtime_policy.is_some());
    }

    #[test]
    fn kv_high_enters_throttled() {
        let config = config(false);
        let inference = sample(0, Some(95));
        let desired = decide_admission(
            &config,
            AdmissionMode::Normal,
            None,
            inference,
            inference.pressure(),
        );

        assert_eq!(
            desired.mode,
            AdmissionMode::Throttled {
                reason: ThrottleReason::KvCache
            }
        );
    }

    #[test]
    fn token_budget_high_enters_throttled() {
        let config = config(false);
        let inference = sample(90, None);
        let desired = decide_admission(
            &config,
            AdmissionMode::Normal,
            None,
            inference,
            inference.pressure(),
        );

        assert_eq!(
            desired.mode,
            AdmissionMode::Throttled {
                reason: ThrottleReason::TokenBudget
            }
        );
    }

    #[test]
    fn exhaustion_can_disable_runtime_policy() {
        let config = config(true);
        let inference = sample(100, None);
        let desired = decide_admission(
            &config,
            AdmissionMode::Normal,
            None,
            inference,
            inference.pressure(),
        );

        assert_eq!(desired.mode, AdmissionMode::Exhausted);
        assert_eq!(
            runtime_policy_for_mode(&config, desired.mode),
            desired.runtime_policy
        );
        let Some(policy) = desired.runtime_policy else {
            panic!("exhausted mode should have runtime policy");
        };
        assert!(!policy.enabled);
    }

    #[test]
    fn hysteresis_holds_throttling_until_all_signals_recover() {
        let config = config(false);
        let inference = sample(85, None);
        let desired = decide_admission(
            &config,
            AdmissionMode::Throttled {
                reason: ThrottleReason::TokenBudget,
            },
            Some(GpuUtilSample {
                ts_unix_ms: 1,
                utilization_percent: 70.0,
            }),
            inference,
            inference.pressure(),
        );

        assert_eq!(
            desired.mode,
            AdmissionMode::Throttled {
                reason: ThrottleReason::TokenBudget
            }
        );
    }

    #[test]
    fn recovers_to_normal_when_all_signals_are_low() {
        let config = config(false);
        let inference = sample(50, Some(50));
        let desired = decide_admission(
            &config,
            AdmissionMode::Throttled {
                reason: ThrottleReason::Gpu,
            },
            Some(GpuUtilSample {
                ts_unix_ms: 1,
                utilization_percent: 50.0,
            }),
            inference,
            inference.pressure(),
        );

        assert_eq!(desired.mode, AdmissionMode::Normal);
        assert!(desired.runtime_policy.is_none());
    }
}
