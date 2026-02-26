use std::{net::Ipv4Addr, str::FromStr};

use thiserror::Error;
use vantage_common::TenantKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TenantRef {
    SrcIp(u32),
}

impl TenantRef {
    pub(crate) fn parse(raw: &str) -> Result<Self, TenantParseError> {
        if let Some(value) = raw.strip_prefix("ip:") {
            return parse_ipv4(value);
        }

        if raw.contains('.') {
            return parse_ipv4(raw);
        }

        let key = raw.parse::<u32>().map_err(|_| TenantParseError::Invalid)?;
        Ok(Self::SrcIp(key))
    }

    pub(crate) const fn to_tenant_key(self) -> TenantKey {
        match self {
            Self::SrcIp(key) => key,
        }
    }
}

fn parse_ipv4(raw: &str) -> Result<TenantRef, TenantParseError> {
    let addr = Ipv4Addr::from_str(raw).map_err(|_| TenantParseError::Invalid)?;
    Ok(TenantRef::SrcIp(u32::from(addr)))
}

#[derive(Debug, Error)]
pub(crate) enum TenantParseError {
    #[error("invalid tenant key")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::TenantRef;

    #[test]
    fn parses_canonical_ip_prefix() {
        let parsed = TenantRef::parse("ip:10.1.2.3");
        let Ok(tenant) = parsed else {
            panic!("tenant parsing should succeed");
        };
        assert_eq!(tenant, TenantRef::SrcIp(167_838_211));
    }

    #[test]
    fn parses_bare_ipv4() {
        let parsed = TenantRef::parse("10.1.2.3");
        let Ok(tenant) = parsed else {
            panic!("tenant parsing should succeed");
        };
        assert_eq!(tenant, TenantRef::SrcIp(167_838_211));
    }

    #[test]
    fn parses_legacy_u32() {
        let parsed = TenantRef::parse("167838211");
        let Ok(tenant) = parsed else {
            panic!("tenant parsing should succeed");
        };
        assert_eq!(tenant, TenantRef::SrcIp(167_838_211));
    }

    #[test]
    fn rejects_invalid_tenant() {
        let parsed = TenantRef::parse("not-a-tenant");
        assert!(parsed.is_err(), "invalid tenant should fail to parse");
    }

    #[test]
    fn converts_tenant_ref_to_key() {
        let tenant = TenantRef::SrcIp(42);
        assert_eq!(tenant.to_tenant_key(), 42);
    }
}
