//! Lightweight macros and helpers for declaring capabilities and scopes.
//!
//! These are intended for downstream consumers (e.g., `jig-cli`) that need a
//! concise way to author capability declarations without hand-rolling parsing
//! or validation logic. The macros panic on invalid input to keep call sites
//! ergonomic; use the functions if you prefer fallible construction.

use crate::Result;
use crate::capability_scope::CapabilityScopePattern;
use crate::manifest::{Attestation, Capability};

/// Parse a list of scope strings into validated patterns.
pub fn parse_scopes<'a, I>(scopes: I) -> Result<Vec<CapabilityScopePattern>>
where
    I: IntoIterator<Item = &'a str>,
{
    scopes
        .into_iter()
        .map(CapabilityScopePattern::parse)
        .collect()
}

/// Build a capability with optional scopes, fuel, and attestations.
pub fn build_capability(
    name: impl Into<String>,
    scopes: Vec<CapabilityScopePattern>,
    fuel: Option<u64>,
    attestations: Vec<Attestation>,
) -> Capability {
    Capability {
        name: name.into(),
        scope: scopes,
        fuel,
        attestations,
        metadata: Default::default(),
    }
}

/// Declare a single capability.
///
/// Usage:
/// ```
/// use jig_core::{capability, capabilities};
///
/// let cap = capability!("net:http:fetch", scopes: ["https://api.example.com/*"], fuel: 500_000);
/// let list = capabilities![
///     capability!("core:compute"),
///     capability!("net:http:fetch", scopes: ["https://api.example.com/*"])
/// ];
/// ```
#[macro_export]
macro_rules! capability {
    ($name:expr) => {{
        $crate::capability_dsl::build_capability($name, Vec::new(), None, Vec::new())
    }};
    ($name:expr, fuel: $fuel:expr) => {{
        $crate::capability_dsl::build_capability($name, Vec::new(), Some($fuel), Vec::new())
    }};
    ($name:expr, scopes: [$($scope:expr),+ $(,)?]) => {{
        let scopes = $crate::capability_dsl::parse_scopes([$($scope),+])
            .expect("invalid capability scope");
        $crate::capability_dsl::build_capability($name, scopes, None, Vec::new())
    }};
    ($name:expr, scopes: [$($scope:expr),+ $(,)?], fuel: $fuel:expr) => {{
        let scopes = $crate::capability_dsl::parse_scopes([$($scope),+])
            .expect("invalid capability scope");
        $crate::capability_dsl::build_capability($name, scopes, Some($fuel), Vec::new())
    }};
}

/// Declare a `Vec<Capability>` from multiple `capability!` entries.
#[macro_export]
macro_rules! capabilities {
    ($($cap:expr),+ $(,)?) => {{
        vec![$($cap),+]
    }};
}

#[cfg(test)]
mod tests {
    #[test]
    fn macro_builds_capability_with_scope() {
        let cap = capability!("net:http:fetch", scopes: ["https://api.example.com/*"], fuel: 10);
        assert_eq!(cap.name, "net:http:fetch");
        assert_eq!(cap.fuel, Some(10));
        assert_eq!(cap.scope.len(), 1);
    }

    #[test]
    fn capabilities_macro_builds_vec() {
        let caps = capabilities![capability!("core:compute"), capability!("log:emit")];
        assert_eq!(caps.len(), 2);
    }
}
