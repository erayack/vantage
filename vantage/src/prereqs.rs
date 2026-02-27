use std::fs;

use thiserror::Error;

const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

#[derive(Debug, Error)]
pub(crate) enum PrereqError {
    #[error("failed to read {path}: {source}")]
    ReadMountInfo {
        path: &'static str,
        source: std::io::Error,
    },
    #[error(
        "missing cgroup2 mount; cgroup-v2 is required for kernel identity extraction. verify with: mount | grep cgroup2"
    )]
    MissingCgroupV2,
}

/// Verifies required host prerequisites for cgroup-v2-based identity extraction.
///
/// # Errors
///
/// Returns `PrereqError` when mount metadata cannot be read or when no `cgroup2`
/// filesystem mount is present.
pub(crate) fn ensure_cgroup_v2_mounted() -> Result<(), PrereqError> {
    let mountinfo =
        fs::read_to_string(MOUNTINFO_PATH).map_err(|source| PrereqError::ReadMountInfo {
            path: MOUNTINFO_PATH,
            source,
        })?;

    if has_cgroup2_mount(&mountinfo) {
        return Ok(());
    }

    Err(PrereqError::MissingCgroupV2)
}

fn has_cgroup2_mount(mountinfo: &str) -> bool {
    mountinfo
        .lines()
        .filter_map(parse_fstype_from_mountinfo_line)
        .any(|fstype| fstype == "cgroup2")
}

fn parse_fstype_from_mountinfo_line(line: &str) -> Option<&str> {
    let (_, after_sep) = line.split_once(" - ")?;
    after_sep.split_whitespace().next()
}

#[cfg(test)]
mod tests {
    use super::{has_cgroup2_mount, parse_fstype_from_mountinfo_line};

    #[test]
    fn detects_cgroup2_mount_presence() {
        let mountinfo = "\
36 35 0:31 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n\
37 35 0:24 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n";

        assert!(has_cgroup2_mount(mountinfo));
    }

    #[test]
    fn reports_absent_cgroup2_mount() {
        let mountinfo = "\
37 35 0:24 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n\
38 35 0:5 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw\n";

        assert!(!has_cgroup2_mount(mountinfo));
    }

    #[test]
    fn parses_filesystem_type_from_well_formed_mountinfo_line() {
        let line =
            "36 35 0:31 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw";

        assert_eq!(parse_fstype_from_mountinfo_line(line), Some("cgroup2"));
    }

    #[test]
    fn ignores_malformed_mountinfo_line() {
        assert_eq!(parse_fstype_from_mountinfo_line("invalid"), None);
    }
}
