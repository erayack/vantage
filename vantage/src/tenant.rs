use std::{net::Ipv4Addr, str::FromStr};

use thiserror::Error;
use vantage_common::{TenantKey, fnv1a_32};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowProto {
    Tcp,
    Udp,
}

impl FlowProto {
    pub(crate) const fn parse(raw: &str) -> Result<Self, TenantParseError> {
        if raw.eq_ignore_ascii_case("tcp") {
            return Ok(Self::Tcp);
        }

        if raw.eq_ignore_ascii_case("udp") {
            return Ok(Self::Udp);
        }

        Err(TenantParseError::InvalidProto)
    }

    const fn to_u8(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TenantRef {
    src_ip: u32,
    proto: Option<FlowProto>,
    dst_port: Option<u16>,
    http_path_hash: Option<u32>,
}

impl TenantRef {
    pub(crate) fn parse(raw: &str) -> Result<Self, TenantParseError> {
        if let Some(value) = raw.strip_prefix("ip:") {
            return parse_ipv4(value);
        }

        if raw.contains('.') {
            return parse_ipv4(raw);
        }

        let src_ip = raw.parse::<u32>().map_err(|_| TenantParseError::Invalid)?;
        Ok(Self {
            src_ip,
            proto: None,
            dst_port: None,
            http_path_hash: None,
        })
    }

    pub(crate) const fn with_flow(
        mut self,
        proto: Option<FlowProto>,
        dst_port: Option<u16>,
    ) -> Result<Self, TenantParseError> {
        if proto.is_some() && dst_port.is_none() {
            return Err(TenantParseError::MissingDstPort);
        }

        if proto.is_none() && dst_port.is_some() {
            return Err(TenantParseError::MissingProto);
        }

        self.proto = proto;
        self.dst_port = dst_port;
        Ok(self)
    }

    pub(crate) const fn with_http_path_hash(mut self, http_path_hash: Option<u32>) -> Self {
        self.http_path_hash = http_path_hash;
        self
    }

    pub(crate) const fn to_tenant_key(self) -> TenantKey {
        TenantKey {
            src_ip: self.src_ip,
            http_path_hash: match self.http_path_hash {
                Some(hash) => hash,
                None => 0,
            },
            dst_port: match self.dst_port {
                Some(port) => port,
                None => 0,
            },
            proto: match self.proto {
                Some(proto) => proto.to_u8(),
                None => 0,
            },
            http_method: 0,
        }
    }
}

pub(crate) fn src_ip_label(src_ip: u32) -> String {
    Ipv4Addr::from(src_ip).to_string()
}

pub(crate) const fn proto_label(proto: u8) -> &'static str {
    match proto {
        0 => "*",
        6 => "tcp",
        17 => "udp",
        _ => "other",
    }
}

pub(crate) fn normalized_flow_key(tenant: TenantKey) -> String {
    let port = if tenant.dst_port == 0 {
        "*".to_owned()
    } else {
        tenant.dst_port.to_string()
    };

    format!(
        "src={}|proto={}|dport={}|method={}|path_hash={}",
        src_ip_label(tenant.src_ip),
        proto_label(tenant.proto),
        port,
        http_method_label(tenant.http_method),
        path_hash_label(tenant.http_path_hash)
    )
}

pub(crate) const fn http_method_label(method: u8) -> &'static str {
    match method {
        0 => "*",
        1 => "get",
        2 => "post",
        3 => "put",
        4 => "delete",
        5 => "patch",
        6 => "head",
        7 => "options",
        _ => "other",
    }
}

pub(crate) fn path_hash_label(http_path_hash: u32) -> String {
    if http_path_hash == 0 {
        "*".to_owned()
    } else {
        format!("{http_path_hash:#010x}")
    }
}

pub(crate) const fn compute_http_path_hash(http_path: &str) -> u32 {
    fnv1a_32(http_path.as_bytes())
}

fn parse_ipv4(raw: &str) -> Result<TenantRef, TenantParseError> {
    let addr = Ipv4Addr::from_str(raw).map_err(|_| TenantParseError::Invalid)?;
    Ok(TenantRef {
        src_ip: u32::from(addr),
        proto: None,
        dst_port: None,
        http_path_hash: None,
    })
}

#[derive(Debug, Error)]
pub(crate) enum TenantParseError {
    #[error("invalid tenant key")]
    Invalid,
    #[error("invalid proto, expected tcp|udp")]
    InvalidProto,
    #[error("dst_port is required when proto is set")]
    MissingDstPort,
    #[error("proto is required when dst_port is set")]
    MissingProto,
    #[error("http_path and http_path_hash mismatch")]
    PathHashMismatch,
    #[error(
        "http selectors require both proto and dst_port when strict policy validation is enabled"
    )]
    PartialL7SelectorsRequireFlow,
}

#[cfg(test)]
mod tests {
    use vantage_common::TenantKey;

    use super::{
        FlowProto, TenantRef, compute_http_path_hash, http_method_label, normalized_flow_key,
        path_hash_label, proto_label, src_ip_label,
    };

    #[test]
    fn parses_canonical_ip_prefix() {
        let parsed = TenantRef::parse("ip:10.1.2.3");
        let Ok(tenant) = parsed else {
            panic!("tenant parsing should succeed");
        };
        assert_eq!(
            tenant,
            TenantRef {
                src_ip: 167_838_211,
                proto: None,
                dst_port: None,
                http_path_hash: None,
            }
        );
    }

    #[test]
    fn parses_bare_ipv4() {
        let parsed = TenantRef::parse("10.1.2.3");
        let Ok(tenant) = parsed else {
            panic!("tenant parsing should succeed");
        };
        assert_eq!(
            tenant,
            TenantRef {
                src_ip: 167_838_211,
                proto: None,
                dst_port: None,
                http_path_hash: None,
            }
        );
    }

    #[test]
    fn parses_legacy_u32() {
        let parsed = TenantRef::parse("167838211");
        let Ok(tenant) = parsed else {
            panic!("tenant parsing should succeed");
        };
        assert_eq!(
            tenant,
            TenantRef {
                src_ip: 167_838_211,
                proto: None,
                dst_port: None,
                http_path_hash: None,
            }
        );
    }

    #[test]
    fn rejects_invalid_tenant() {
        let parsed = TenantRef::parse("not-a-tenant");
        assert!(parsed.is_err(), "invalid tenant should fail to parse");
    }

    #[test]
    fn converts_tenant_ref_to_key() {
        let tenant = TenantRef {
            src_ip: 42,
            proto: None,
            dst_port: None,
            http_path_hash: None,
        };
        assert_eq!(
            tenant.to_tenant_key(),
            TenantKey {
                src_ip: 42,
                http_path_hash: 0,
                dst_port: 0,
                proto: 0,
                http_method: 0
            }
        );
    }

    #[test]
    fn converts_flow_aware_tenant_ref_to_key() {
        let base = TenantRef::parse("ip:10.1.2.3");
        let Ok(base) = base else {
            panic!("tenant parsing should succeed");
        };
        let tenant = base.with_flow(Some(FlowProto::Tcp), Some(443));
        let Ok(tenant) = tenant else {
            panic!("flow override should succeed");
        };

        assert_eq!(
            tenant.to_tenant_key(),
            TenantKey {
                src_ip: 167_838_211,
                http_path_hash: 0,
                dst_port: 443,
                proto: 6,
                http_method: 0
            }
        );
    }

    #[test]
    fn rejects_proto_without_dst_port() {
        let base = TenantRef::parse("42");
        let Ok(base) = base else {
            panic!("tenant parsing should succeed");
        };
        let err = base.with_flow(Some(FlowProto::Udp), None);

        assert!(err.is_err(), "proto-only flow should be rejected");
    }

    #[test]
    fn parses_proto_case_insensitively() {
        let parsed = FlowProto::parse("TCP");
        let Ok(proto) = parsed else {
            panic!("proto parsing should succeed");
        };
        assert_eq!(proto, FlowProto::Tcp);
    }

    #[test]
    fn labels_proto_and_ip_for_observability() {
        assert_eq!(src_ip_label(167_838_211), "10.1.2.3");
        assert_eq!(proto_label(0), "*");
        assert_eq!(proto_label(6), "tcp");
        assert_eq!(proto_label(17), "udp");
        assert_eq!(proto_label(99), "other");
    }

    #[test]
    fn builds_normalized_flow_key() {
        let tenant = TenantKey {
            src_ip: 167_838_211,
            http_path_hash: 0x1234_abcd,
            dst_port: 443,
            proto: 6,
            http_method: 0,
        };
        assert_eq!(
            normalized_flow_key(tenant),
            "src=10.1.2.3|proto=tcp|dport=443|method=*|path_hash=0x1234abcd"
        );
    }

    #[test]
    fn computes_fnv1a_http_path_hash() {
        assert_eq!(compute_http_path_hash("/predict"), 0xefb2_d4b7);
    }

    #[test]
    fn wildcard_hash_label_is_star() {
        assert_eq!(path_hash_label(0), "*");
    }

    #[test]
    fn labels_http_method_for_observability() {
        assert_eq!(http_method_label(0), "*");
        assert_eq!(http_method_label(1), "get");
        assert_eq!(http_method_label(2), "post");
        assert_eq!(http_method_label(255), "other");
    }
}
