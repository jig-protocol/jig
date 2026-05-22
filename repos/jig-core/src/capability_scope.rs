use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use crate::error::{JigError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Separator used when encoding capability usage strings (capability + scope).
pub const CAPABILITY_SCOPE_SEPARATOR: char = '|';

/// Parsed representation of a capability scope pattern (`scheme://authority/path/*`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CapabilityScopePattern {
    canonical: String,
    scheme: String,
    authority: String,
    path_segments: Vec<String>,
    wildcard: bool,
}

impl CapabilityScopePattern {
    pub fn parse(scope: &str) -> Result<Self> {
        ScopeParser::parse(scope)
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn path_segments(&self) -> &[String] {
        &self.path_segments
    }

    pub fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    pub fn covers(&self, requested: &Self) -> bool {
        if self.scheme != requested.scheme || self.authority != requested.authority {
            return false;
        }

        match (self.wildcard, requested.wildcard) {
            (false, false) => self.path_segments == requested.path_segments,
            (false, true) => false,
            (true, _) => {
                if self.path_segments.len() > requested.path_segments.len() {
                    return false;
                }
                self.path_segments
                    .iter()
                    .zip(requested.path_segments.iter())
                    .all(|(a, b)| a == b)
            }
        }
    }

    pub fn any() -> Self {
        ScopeParser::parse("any://*").expect("static any scope")
    }
}

impl fmt::Display for CapabilityScopePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

impl PartialOrd for CapabilityScopePattern {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CapabilityScopePattern {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical.cmp(&other.canonical)
    }
}

impl Serialize for CapabilityScopePattern {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.canonical)
    }
}

impl<'de> Deserialize<'de> for CapabilityScopePattern {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        CapabilityScopePattern::parse(&s).map_err(serde::de::Error::custom)
    }
}

struct ScopeParser;

impl ScopeParser {
    fn parse(scope: &str) -> Result<CapabilityScopePattern> {
        let (scheme_raw, rest) = scope.split_once("://").ok_or_else(|| {
            JigError::Validation(format!("invalid scope (missing scheme): {scope}"))
        })?;
        let scheme = Self::normalise_scheme(scheme_raw)?;
        let (authority, path) = Self::split_authority_and_path(rest)?;
        let (segments, wildcard) = Self::parse_path(path)?;
        let canonical = Self::build_canonical(&scheme, &authority, &segments, wildcard);
        Ok(CapabilityScopePattern {
            canonical,
            scheme,
            authority,
            path_segments: segments,
            wildcard,
        })
    }

    fn normalise_scheme(raw: &str) -> Result<String> {
        if raw.is_empty() {
            return Err(JigError::Validation("scope scheme cannot be empty".into()));
        }
        if !raw.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '+' || c == '.' || c == '-'
        }) {
            return Err(JigError::Validation(format!("invalid scope scheme: {raw}")));
        }
        Ok(raw.to_ascii_lowercase())
    }

    fn split_authority_and_path(rest: &str) -> Result<(String, &str)> {
        let mut parts = rest.splitn(2, '/');
        let authority = parts
            .next()
            .ok_or_else(|| JigError::Validation("scope missing authority".into()))?;
        if authority.is_empty() {
            return Err(JigError::Validation(
                "scope authority cannot be empty".into(),
            ));
        }
        let authority = authority.to_ascii_lowercase();
        let path = parts.next().unwrap_or("");
        Ok((authority, path))
    }

    fn parse_path(path: &str) -> Result<(Vec<String>, bool)> {
        if path.is_empty() {
            return Ok((Vec::new(), false));
        }

        let mut segments = Vec::new();
        let raw_segments: Vec<&str> = path.split('/').collect();

        for (idx, segment) in raw_segments.iter().enumerate() {
            if segment.is_empty() {
                return Err(JigError::Validation(
                    "scope path segments cannot be empty".into(),
                ));
            }
            if *segment == "*" {
                if idx != raw_segments.len() - 1 {
                    return Err(JigError::Validation(
                        "wildcard '*' only permitted as final path segment".into(),
                    ));
                }
                return Ok((segments, true));
            }
            if segment.contains('*') {
                return Err(JigError::Validation(
                    "wildcard '*' must occupy entire final segment".into(),
                ));
            }
            segments.push(segment.to_string());
        }

        Ok((segments, false))
    }

    fn build_canonical(
        scheme: &str,
        authority: &str,
        segments: &[String],
        wildcard: bool,
    ) -> String {
        let mut canonical = format!("{scheme}://{authority}");
        for segment in segments {
            canonical.push('/');
            canonical.push_str(segment);
        }
        if wildcard {
            canonical.push_str("/*");
        }
        canonical
    }
}

/// Canonical capability + optional scope usage identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CapabilityUsageKey {
    pub capability: String,
    pub scope: Option<CapabilityScopePattern>,
}

impl CapabilityUsageKey {
    pub fn with_scope(capability: impl Into<String>, scope: CapabilityScopePattern) -> Self {
        Self {
            capability: capability.into(),
            scope: Some(scope),
        }
    }

    pub fn without_scope(capability: impl Into<String>) -> Self {
        Self {
            capability: capability.into(),
            scope: None,
        }
    }

    pub fn parse(input: &str) -> Result<Self> {
        if let Some((capability, scope_str)) = input.split_once(CAPABILITY_SCOPE_SEPARATOR) {
            if capability.trim().is_empty() {
                return Err(JigError::Validation(
                    "capability usage missing capability name".into(),
                ));
            }
            let scope = CapabilityScopePattern::parse(scope_str.trim())?;
            Ok(Self {
                capability: capability.trim().to_string(),
                scope: Some(scope),
            })
        } else {
            if input.trim().is_empty() {
                return Err(JigError::Validation(
                    "capability usage missing capability name".into(),
                ));
            }
            Ok(Self {
                capability: input.trim().to_string(),
                scope: None,
            })
        }
    }

    pub fn to_canonical_string(&self) -> String {
        if let Some(scope) = &self.scope {
            format!("{}{}{}", self.capability, CAPABILITY_SCOPE_SEPARATOR, scope)
        } else {
            self.capability.clone()
        }
    }
}

impl FromStr for CapabilityUsageKey {
    type Err = JigError;

    fn from_str(s: &str) -> Result<Self> {
        CapabilityUsageKey::parse(s)
    }
}

impl fmt::Display for CapabilityUsageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_canonical_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scope() {
        let scope = CapabilityScopePattern::parse("https://api.example.com/foo/*").unwrap();
        assert_eq!(scope.scheme(), "https");
        assert_eq!(scope.authority(), "api.example.com");
        assert!(scope.is_wildcard());
        assert_eq!(scope.path_segments(), &["foo".to_string()]);
    }

    #[test]
    fn covers_prefix() {
        let grant = CapabilityScopePattern::parse("https://api.example.com/orders/*").unwrap();
        let usage = CapabilityScopePattern::parse("https://api.example.com/orders/123").unwrap();
        assert!(grant.covers(&usage));
    }

    #[test]
    fn usage_key_roundtrip() {
        let scope = CapabilityScopePattern::parse("https://api.example.com/foo/*").unwrap();
        let key = CapabilityUsageKey::with_scope("net:http:fetch", scope.clone());
        let canonical = key.to_canonical_string();
        let parsed = CapabilityUsageKey::parse(&canonical).unwrap();
        assert_eq!(parsed.capability, "net:http:fetch");
        assert_eq!(parsed.scope.unwrap().canonical(), scope.canonical());
    }

    #[test]
    fn usage_key_unscoped_roundtrip() {
        let key = CapabilityUsageKey::without_scope("core:compute");
        let canonical = key.to_canonical_string();
        assert_eq!(canonical, "core:compute");
        let parsed = CapabilityUsageKey::parse(&canonical).unwrap();
        assert_eq!(parsed.capability, "core:compute");
        assert!(parsed.scope.is_none());
    }

    #[test]
    fn parse_scope_rejects_empty_segment() {
        let result = CapabilityScopePattern::parse("https://api.example.com/foo//bar");
        assert!(result.is_err());
    }

    #[test]
    fn parse_scope_rejects_non_final_wildcard() {
        let result = CapabilityScopePattern::parse("https://api.example.com/*/bar");
        assert!(result.is_err());
    }

    #[test]
    fn parse_scope_rejects_partial_segment_wildcard() {
        let result = CapabilityScopePattern::parse("https://api.example.com/ord*ers");
        assert!(result.is_err());
    }
}
