use std::{fs, io::ErrorKind, path::PathBuf};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct GpuUtilSample {
    pub(crate) ts_unix_ms: u64,
    pub(crate) utilization_percent: f64,
}

pub(crate) trait GpuUtilSource {
    fn sample(&self) -> Result<Option<GpuUtilSample>, GpuError>;
}

#[derive(Debug, Clone)]
pub(crate) struct FileGpuUtilSource {
    path: Option<PathBuf>,
}

#[derive(Debug, Error)]
pub(crate) enum GpuError {
    #[error("failed to read GPU utilization file '{path}': {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse GPU utilization file '{path}': {source}")]
    ParseFile {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Deserialize)]
struct RawGpuUtilSample {
    ts_unix_ms: u64,
    utilization_percent: f64,
}

impl FileGpuUtilSource {
    pub(crate) const fn new(path: Option<PathBuf>) -> Self {
        Self { path }
    }
}

impl GpuUtilSource for FileGpuUtilSource {
    fn sample(&self) -> Result<Option<GpuUtilSample>, GpuError> {
        let Some(path) = &self.path else {
            return Ok(None);
        };
        let data = match fs::read(path) {
            Ok(data) => data,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(GpuError::ReadFile {
                    path: path.display().to_string(),
                    source,
                });
            }
        };
        let raw = serde_json::from_slice::<RawGpuUtilSample>(&data).map_err(|source| {
            GpuError::ParseFile {
                path: path.display().to_string(),
                source,
            }
        })?;
        Ok(Some(GpuUtilSample {
            ts_unix_ms: raw.ts_unix_ms,
            utilization_percent: clamp_percent(raw.utilization_percent),
        }))
    }
}

const fn clamp_percent(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 100.0)
    } else {
        100.0
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::{FileGpuUtilSource, GpuError, GpuUtilSource};

    fn unique_test_dir(name: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0_u128, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!(
            "vantage_inference_gpu_{name}_{}_{}",
            std::process::id(),
            stamp
        ))
    }

    #[test]
    fn missing_configured_source_returns_none() {
        let source = FileGpuUtilSource::new(None);
        let sample = source.sample();
        let Ok(sample) = sample else {
            panic!("unconfigured source should not fail");
        };
        assert!(sample.is_none());
    }

    #[test]
    fn reads_and_clamps_gpu_file() {
        let root = unique_test_dir("valid");
        let created = fs::create_dir_all(&root);
        assert!(created.is_ok(), "test dir should be created");
        let path = root.join("gpu.json");
        let written = fs::write(&path, r#"{"ts_unix_ms":123,"utilization_percent":130.0}"#);
        assert!(written.is_ok(), "fixture should be written");

        let source = FileGpuUtilSource::new(Some(path));
        let sample = source.sample();
        let Ok(Some(sample)) = sample else {
            panic!("sample should parse");
        };
        assert_eq!(sample.ts_unix_ms, 123);
        assert!((sample.utilization_percent - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn invalid_json_is_reported() {
        let root = unique_test_dir("invalid");
        let created = fs::create_dir_all(&root);
        assert!(created.is_ok(), "test dir should be created");
        let path = root.join("gpu.json");
        let written = fs::write(&path, "not json");
        assert!(written.is_ok(), "fixture should be written");

        let source = FileGpuUtilSource::new(Some(path));
        let sample = source.sample();
        assert!(
            matches!(sample, Err(GpuError::ParseFile { .. })),
            "parse error should be returned"
        );
    }
}
