use std::sync::{Arc, Mutex};

use thiserror::Error;

use crate::{
    controller::{InferenceSource, InferenceSourceError},
    http_client::{HttpClient, HttpClientError},
    inference::InferencePressureSample,
};

#[derive(Debug, Clone)]
pub(crate) struct VllmMetricsSource {
    http: HttpClient,
    metrics_path: String,
    token_budget_per_minute: u64,
    token_window: Arc<Mutex<TokenWindow>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct ParsedVllmMetrics {
    pub(crate) gpu_cache_usage_percent: Option<f64>,
    pub(crate) requests_waiting: Option<u64>,
    pub(crate) requests_running: Option<u64>,
    pub(crate) prompt_tokens_total: Option<u64>,
    pub(crate) generation_tokens_total: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TokenTotals {
    prompt: u64,
    generation: u64,
}

#[derive(Debug, Default)]
struct TokenWindow {
    last_totals: Option<TokenTotals>,
}

#[derive(Debug, Error)]
pub(crate) enum VllmMetricsError {
    #[error(transparent)]
    Http(#[from] HttpClientError),
    #[error("vLLM metrics endpoint returned HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("failed to parse vLLM metric line {line_number}: {reason}")]
    ParseLine { line_number: usize, reason: String },
    #[error("vLLM token counter state lock is poisoned")]
    StateLockPoisoned,
}

impl VllmMetricsSource {
    pub(crate) fn new(
        metrics_base_url: &str,
        metrics_path: String,
        token_budget_per_minute: u64,
    ) -> Result<Self, VllmMetricsError> {
        Ok(Self {
            http: HttpClient::new(metrics_base_url)?,
            metrics_path,
            token_budget_per_minute,
            token_window: Arc::new(Mutex::new(TokenWindow::default())),
        })
    }
}

impl InferenceSource for VllmMetricsSource {
    async fn sample(&self) -> Result<InferencePressureSample, InferenceSourceError> {
        let response = self
            .http
            .get(&self.metrics_path)
            .await
            .map_err(VllmMetricsError::from)?;
        if !response.status_is_success() {
            return Err(VllmMetricsError::HttpStatus {
                status: response.status,
                body: response.body,
            }
            .into());
        }
        let parsed = parse_vllm_metrics(&response.body)?;
        let tokens_used_current_minute = self
            .token_window
            .lock()
            .map_err(|_| VllmMetricsError::StateLockPoisoned)?
            .tokens_since_last_sample(parsed);
        Ok(metrics_to_pressure_sample_with_tokens(
            parsed,
            tokens_used_current_minute,
            self.token_budget_per_minute,
            unix_timestamp_ms(),
        ))
    }
}

pub(crate) fn parse_vllm_metrics(text: &str) -> Result<ParsedVllmMetrics, VllmMetricsError> {
    let mut parsed = ParsedVllmMetrics::default();
    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index.saturating_add(1);
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name = parse_metric_name(line, line_number)?;
        if !is_relevant_metric(name) {
            continue;
        }
        let value = parse_metric_value(line, line_number)?;
        match name {
            "vllm:gpu_cache_usage_perc" => {
                let percent = normalize_gpu_cache_percent(value);
                parsed.gpu_cache_usage_percent = Some(
                    parsed
                        .gpu_cache_usage_percent
                        .map_or(percent, |current| current.max(percent)),
                );
            }
            "vllm:num_requests_waiting" => {
                parsed.requests_waiting = Some(
                    parsed
                        .requests_waiting
                        .unwrap_or(0)
                        .saturating_add(count(value)),
                );
            }
            "vllm:num_requests_running" => {
                parsed.requests_running = Some(
                    parsed
                        .requests_running
                        .unwrap_or(0)
                        .saturating_add(count(value)),
                );
            }
            "vllm:prompt_tokens_total" | "vllm:request_prompt_tokens_total" => {
                parsed.prompt_tokens_total = Some(
                    parsed
                        .prompt_tokens_total
                        .unwrap_or(0)
                        .saturating_add(count(value)),
                );
            }
            "vllm:generation_tokens_total" | "vllm:request_generation_tokens_total" => {
                parsed.generation_tokens_total = Some(
                    parsed
                        .generation_tokens_total
                        .unwrap_or(0)
                        .saturating_add(count(value)),
                );
            }
            _ => {}
        }
    }
    Ok(parsed)
}

#[cfg(test)]
pub(crate) fn metrics_to_pressure_sample(
    metrics: ParsedVllmMetrics,
    token_budget_per_minute: u64,
    now_ms: u64,
) -> InferencePressureSample {
    let tokens = metrics
        .prompt_tokens_total
        .unwrap_or(0)
        .saturating_add(metrics.generation_tokens_total.unwrap_or(0));
    metrics_to_pressure_sample_with_tokens(metrics, tokens, token_budget_per_minute, now_ms)
}

fn metrics_to_pressure_sample_with_tokens(
    metrics: ParsedVllmMetrics,
    tokens_used_current_minute: u64,
    token_budget_per_minute: u64,
    now_ms: u64,
) -> InferencePressureSample {
    InferencePressureSample {
        ts_unix_ms: now_ms,
        tokens_used_current_minute,
        token_budget_per_minute: token_budget_per_minute.max(1),
        kv_cache_used_bytes: None,
        kv_cache_capacity_bytes: None,
        kv_cache_percent: metrics.gpu_cache_usage_percent,
        active_requests: metrics.requests_running,
        queued_requests: metrics.requests_waiting,
    }
}

impl TokenWindow {
    fn tokens_since_last_sample(&mut self, metrics: ParsedVllmMetrics) -> u64 {
        let current = TokenTotals {
            prompt: metrics.prompt_tokens_total.unwrap_or(0),
            generation: metrics.generation_tokens_total.unwrap_or(0),
        };
        let tokens = self.last_totals.map_or(0, |last| {
            current
                .prompt
                .saturating_sub(last.prompt)
                .saturating_add(current.generation.saturating_sub(last.generation))
        });
        self.last_totals = Some(current);
        tokens
    }
}

fn parse_metric_name(line: &str, line_number: usize) -> Result<&str, VllmMetricsError> {
    let mut fields = line.split_whitespace();
    let Some(raw_name) = fields.next() else {
        return Err(parse_error(line_number, "missing metric name"));
    };
    Ok(raw_name.split_once('{').map_or(raw_name, |(name, _)| name))
}

fn is_relevant_metric(name: &str) -> bool {
    matches!(
        name,
        "vllm:gpu_cache_usage_perc"
            | "vllm:num_requests_waiting"
            | "vllm:num_requests_running"
            | "vllm:prompt_tokens_total"
            | "vllm:request_prompt_tokens_total"
            | "vllm:generation_tokens_total"
            | "vllm:request_generation_tokens_total"
    )
}

fn parse_metric_value(line: &str, line_number: usize) -> Result<f64, VllmMetricsError> {
    let mut fields = line.split_whitespace();
    let _ = fields.next();
    let Some(raw_value) = fields.next() else {
        return Err(parse_error(line_number, "missing metric value"));
    };
    let value = raw_value.parse::<f64>().map_err(|error| {
        parse_error(
            line_number,
            &format!("invalid value '{raw_value}': {error}"),
        )
    })?;
    if !value.is_finite() {
        return Err(parse_error(line_number, "metric value must be finite"));
    }
    Ok(value)
}

fn parse_error(line_number: usize, reason: &str) -> VllmMetricsError {
    VllmMetricsError::ParseLine {
        line_number,
        reason: reason.to_owned(),
    }
}

fn normalize_gpu_cache_percent(value: f64) -> f64 {
    let percent = if value <= 1.0 { value * 100.0 } else { value };
    percent.clamp(0.0, 100.0)
}

fn count(value: f64) -> u64 {
    const U64_MAX_AS_F64: f64 = 18_446_744_073_709_551_615.0;
    if value <= 0.0 {
        0
    } else if value >= U64_MAX_AS_F64 {
        u64::MAX
    } else {
        let rounded = format!("{:.0}", value.floor());
        rounded.parse::<u64>().unwrap_or(u64::MAX)
    }
}

fn unix_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::{TokenWindow, metrics_to_pressure_sample, parse_vllm_metrics};

    const NORMAL: &str = include_str!("../fixtures/vllm_metrics_normal.prom");
    const THROTTLED: &str = include_str!("../fixtures/vllm_metrics_throttled.prom");
    const EXHAUSTED: &str = include_str!("../fixtures/vllm_metrics_exhausted.prom");

    #[test]
    fn parses_normal_fixture() {
        let parsed = parse_vllm_metrics(NORMAL);
        let Ok(parsed) = parsed else {
            panic!("fixture should parse");
        };
        assert_eq!(parsed.gpu_cache_usage_percent, Some(20.0));
        assert_eq!(parsed.requests_waiting, Some(0));
        assert_eq!(parsed.requests_running, Some(1));
        assert_eq!(parsed.prompt_tokens_total, Some(12));
        assert_eq!(parsed.generation_tokens_total, Some(8));
    }

    #[test]
    fn parses_throttled_fixture_with_ratio_gpu_cache() {
        let parsed = parse_vllm_metrics(THROTTLED);
        let Ok(parsed) = parsed else {
            panic!("fixture should parse");
        };
        assert_eq!(parsed.gpu_cache_usage_percent, Some(95.0));
        assert_eq!(parsed.requests_waiting, Some(8));
        assert_eq!(parsed.requests_running, Some(16));
    }

    #[test]
    fn converts_exhausted_fixture_to_pressure_sample() {
        let parsed = parse_vllm_metrics(EXHAUSTED);
        let Ok(parsed) = parsed else {
            panic!("fixture should parse");
        };
        let sample = metrics_to_pressure_sample(parsed, 100, 123);
        assert_eq!(sample.ts_unix_ms, 123);
        assert_eq!(sample.tokens_used_current_minute, 120);
        assert_eq!(sample.token_budget_per_minute, 100);
        assert_eq!(sample.kv_cache_percent, Some(98.0));
        assert_eq!(sample.active_requests, Some(20));
        assert_eq!(sample.queued_requests, Some(12));
    }

    #[test]
    fn sums_labeled_metrics() {
        let text = "\
vllm:num_requests_waiting{model=\"a\"} 2
vllm:num_requests_waiting{model=\"b\"} 3
vllm:prompt_tokens_total{model=\"a\"} 4
vllm:prompt_tokens_total{model=\"b\"} 5
";
        let parsed = parse_vllm_metrics(text);
        let Ok(parsed) = parsed else {
            panic!("metrics should parse");
        };
        assert_eq!(parsed.requests_waiting, Some(5));
        assert_eq!(parsed.prompt_tokens_total, Some(9));
    }

    #[test]
    fn ignores_unrelated_invalid_metrics() {
        let text = "\
unrelated_metric NaN
other_exporter_metric_without_value
vllm:num_requests_running 2
vllm:prompt_tokens_total 7
";
        let parsed = parse_vllm_metrics(text);
        let Ok(parsed) = parsed else {
            panic!("unrelated invalid metrics should be ignored");
        };
        assert_eq!(parsed.requests_running, Some(2));
        assert_eq!(parsed.prompt_tokens_total, Some(7));
    }

    #[test]
    fn token_window_uses_counter_deltas() {
        let mut window = TokenWindow::default();
        let first = parse_vllm_metrics(
            "\
vllm:prompt_tokens_total 1000
vllm:generation_tokens_total 2000
",
        )
        .expect("first sample should parse");
        assert_eq!(window.tokens_since_last_sample(first), 0);

        let second = parse_vllm_metrics(
            "\
vllm:prompt_tokens_total 1010
vllm:generation_tokens_total 2025
",
        )
        .expect("second sample should parse");
        assert_eq!(window.tokens_since_last_sample(second), 35);

        let quiet = parse_vllm_metrics(
            "\
vllm:prompt_tokens_total 1010
vllm:generation_tokens_total 2025
",
        )
        .expect("quiet sample should parse");
        assert_eq!(window.tokens_since_last_sample(quiet), 0);
    }
}
