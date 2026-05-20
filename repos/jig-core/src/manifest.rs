use crate::capability_scope::CapabilityScopePattern;
use crate::did::Did;
use crate::error::{JigError, Result};
use crate::hlc::HlcTimestamp;
use crate::serde_helpers::{
    deserialize_cid, deserialize_cid_vec, deserialize_opt_cid, serialize_cid, serialize_cid_vec,
    serialize_opt_cid, to_canonical_json_bytes,
};
use cid::Cid;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use std::collections::BTreeMap;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub type CapabilityName = String;
pub type HashHex = String;

/// Default schema URI for Jig manifests.
pub const DEFAULT_SCHEMA: &str = "https://jig.dev/schema/block-manifest/v0.1";

/// Visibility modes for metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MetadataVisibility {
    #[default]
    Public,
    RecipientsOnly,
    Private,
}

/// Descriptor for block resources (e.g. attachments).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resource {
    pub name: String,
    #[serde(serialize_with = "serialize_cid", deserialize_with = "deserialize_cid")]
    pub cid: Cid,
    pub mime: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Constraints {
    pub fuel_max: u64,
    pub memory_max_mb: u32,
    pub execution_timeout_ms: u32,
    pub deterministic: bool,
}

impl Default for Constraints {
    fn default() -> Self {
        Self {
            fuel_max: 5_000_000,
            memory_max_mb: 32,
            execution_timeout_ms: 250,
            deterministic: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Capability {
    pub name: CapabilityName,
    #[serde(default)]
    pub scope: Vec<CapabilityScopePattern>,
    #[serde(default)]
    pub fuel: Option<u64>,
    #[serde(default)]
    pub attestations: Vec<Attestation>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenderDescriptor {
    pub entry: String,
    pub expected_hash: HashHex,
    pub output_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Author {
    pub did: Did,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Provenance {
    pub created_at: OffsetDateTime,
    #[serde(
        default,
        serialize_with = "serialize_cid_vec",
        deserialize_with = "deserialize_cid_vec"
    )]
    pub useful_work_refs: Vec<Cid>,
    #[serde(default)]
    pub reputation_tier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Attestation {
    pub issuer: String,
    pub claim: String,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Privacy {
    pub encryption: String,
    #[serde(default)]
    pub recipients: Vec<Did>,
    #[serde(default)]
    pub metadata_visibility: MetadataVisibility,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockManifest {
    #[serde(default = "default_schema")]
    pub schema: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_cid",
        deserialize_with = "deserialize_opt_cid"
    )]
    pub block_id: Option<Cid>,
    pub version: Version,
    #[serde(default)]
    pub authors: Vec<Author>,
    #[serde(
        default,
        serialize_with = "serialize_cid_vec",
        deserialize_with = "deserialize_cid_vec"
    )]
    pub parents: Vec<Cid>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub constraints: Constraints,
    #[serde(default)]
    pub resources: Vec<Resource>,
    #[serde(default)]
    pub render: Option<RenderDescriptor>,
    #[serde(default)]
    pub provenance: Option<Provenance>,
    #[serde(default)]
    pub attestations: Vec<Attestation>,
    #[serde(default)]
    pub privacy: Option<Privacy>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,

    // --- v0.0.2 fields ---
    /// HLC timestamp set by the ingest pipeline.  `None` in pre-ingest constructed
    /// manifests and legacy fixtures (backward-compat via `#[serde(default)]`).
    /// Populated to `Some` in Phase B ingest; used for causal ordering in v0.0.3+.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc_ts: Option<HlcTimestamp>,

    /// CIDs of `time-attestation` blocks that vouch for this manifest's timestamp.
    /// Empty in v0.0.2; populated in v0.0.3+ when time-authority emitters land.
    #[serde(
        default,
        serialize_with = "serialize_cid_vec",
        deserialize_with = "deserialize_cid_vec"
    )]
    pub attested_by: Vec<Cid>,

    /// Reserved for v0.0.3+ CRDT block kinds (e.g. `"lww-register"`, `"add-wins-set"`).
    /// `None` in v0.0.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crdt_kind: Option<String>,
}

fn default_schema() -> String {
    DEFAULT_SCHEMA.to_string()
}

impl BlockManifest {
    /// Returns a builder for ergonomic manifest construction.
    pub fn builder() -> BlockManifestBuilder {
        BlockManifestBuilder::default()
    }

    /// Serialise the manifest to canonical JSON bytes (stable field order).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        to_canonical_json_bytes(self)
    }

    /// Validate structural invariants.
    pub fn validate(&self) -> Result<()> {
        if self.authors.is_empty() {
            return Err(JigError::Validation(
                "manifest must contain at least one author".into(),
            ));
        }
        if let Some(provenance) = &self.provenance {
            validate_timestamp(provenance.created_at)?;
        }
        if let Some(render) = &self.render
            && render.expected_hash.is_empty()
        {
            return Err(JigError::Validation("render expected_hash missing".into()));
        }

        // Validate capabilities against registry
        validate_manifest_capabilities(self)?;

        Ok(())
    }

    /// Attach a computed block ID (CID) to the manifest.
    pub fn with_block_id(mut self, cid: Cid) -> Self {
        self.block_id = Some(cid);
        self
    }

    /// Set the HLC timestamp (typically by the ingest pipeline after block creation).
    pub fn with_hlc(mut self, ts: HlcTimestamp) -> Self {
        self.hlc_ts = Some(ts);
        self
    }

    /// Set the list of time-attestation block CIDs that vouch for this manifest.
    /// Pass an empty `Vec` to assert "no attestations yet" (the default).
    pub fn with_attested_by(mut self, cids: Vec<Cid>) -> Self {
        self.attested_by = cids;
        self
    }

    /// Set the CRDT block kind.  Reserved for v0.0.3+.
    /// Wraps the value in `Some` internally; to clear, assign `crdt_kind` directly.
    pub fn with_crdt_kind(mut self, kind: impl Into<String>) -> Self {
        self.crdt_kind = Some(kind.into());
        self
    }
}

fn validate_timestamp(ts: OffsetDateTime) -> Result<()> {
    // OffsetDateTime already validates; we just ensure it marshals.
    ts.format(&Rfc3339)
        .map(|_| ())
        .map_err(|e| JigError::Validation(format!("invalid timestamp: {e}")))
}

fn validate_manifest_capabilities(manifest: &BlockManifest) -> Result<()> {
    use crate::capability_registry::CapabilityRegistry;
    use crate::capability_validation::validate_all_capabilities;

    let registry = CapabilityRegistry::default();
    validate_all_capabilities(&manifest.capabilities, &registry)
}

#[derive(Default)]
pub struct BlockManifestBuilder {
    schema: Option<String>,
    block_id: Option<Cid>,
    version: Option<Version>,
    authors: Vec<Author>,
    parents: Vec<Cid>,
    capabilities: Vec<Capability>,
    constraints: Option<Constraints>,
    resources: Vec<Resource>,
    render: Option<RenderDescriptor>,
    provenance: Option<Provenance>,
    attestations: Vec<Attestation>,
    privacy: Option<Privacy>,
    metadata: BTreeMap<String, Value>,
}

impl BlockManifestBuilder {
    pub fn schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = Some(schema.into());
        self
    }

    pub fn block_id(mut self, cid: Cid) -> Self {
        self.block_id = Some(cid);
        self
    }

    pub fn version(mut self, version: Version) -> Self {
        self.version = Some(version);
        self
    }

    pub fn author(mut self, author: Author) -> Self {
        self.authors.push(author);
        self
    }

    pub fn authors(mut self, authors: Vec<Author>) -> Self {
        self.authors.extend(authors);
        self
    }

    pub fn parent(mut self, parent: Cid) -> Self {
        self.parents.push(parent);
        self
    }

    pub fn capability(mut self, capability: Capability) -> Self {
        self.capabilities.push(capability);
        self
    }

    pub fn constraints(mut self, constraints: Constraints) -> Self {
        self.constraints = Some(constraints);
        self
    }

    pub fn resource(mut self, resource: Resource) -> Self {
        self.resources.push(resource);
        self
    }

    pub fn render(mut self, render: RenderDescriptor) -> Self {
        self.render = Some(render);
        self
    }

    pub fn provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = Some(provenance);
        self
    }

    pub fn attestation(mut self, attestation: Attestation) -> Self {
        self.attestations.push(attestation);
        self
    }

    pub fn privacy(mut self, privacy: Privacy) -> Self {
        self.privacy = Some(privacy);
        self
    }

    pub fn metadata_entry(mut self, key: impl Into<String>, value: Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    pub fn build(self) -> Result<BlockManifest> {
        let version = self
            .version
            .ok_or_else(|| JigError::Validation("manifest version required".into()))?;
        let manifest = BlockManifest {
            schema: self.schema.unwrap_or_else(|| DEFAULT_SCHEMA.to_string()),
            block_id: self.block_id,
            version,
            authors: self.authors,
            parents: self.parents,
            capabilities: self.capabilities,
            constraints: self.constraints.unwrap_or_default(),
            resources: self.resources,
            render: self.render,
            provenance: self.provenance,
            attestations: self.attestations,
            privacy: self.privacy,
            metadata: self.metadata,
            hlc_ts: None,
            attested_by: vec![],
            crdt_kind: None,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::HlcTimestamp;

    fn test_author() -> Author {
        Author {
            did: "did:jig:alice".into(),
            public_key: None,
            roles: vec!["author".into()],
        }
    }

    fn minimal_manifest() -> BlockManifest {
        BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(test_author())
            .build()
            .unwrap()
    }

    #[test]
    fn manifest_carries_hlc_attested_by_and_crdt_kind() {
        let hlc = HlcTimestamp::now_wall(crate::Did::from_test_string("origin"));
        let m = minimal_manifest()
            .with_hlc(hlc.clone())
            .with_attested_by(vec![]);

        assert_eq!(m.hlc_ts, Some(hlc));
        assert!(m.attested_by.is_empty());
        // crdt_kind defaults to None when not set
        assert!(m.crdt_kind.is_none());
    }

    #[test]
    fn manifest_canonical_json_roundtrip_includes_new_fields() {
        let hlc = HlcTimestamp {
            wall_ms: 1234,
            logical: 5,
            server_did: crate::Did::from_test_string("o"),
        };
        let m = minimal_manifest().with_hlc(hlc);
        let bytes = m.to_canonical_bytes().unwrap();
        let parsed: BlockManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn manifest_canonical_json_handles_absent_optional_fields() {
        let m = minimal_manifest();
        let json = String::from_utf8(m.to_canonical_bytes().unwrap()).unwrap();
        // attested_by always serialized (Vec defaults to []); hlc_ts/crdt_kind
        // are absent when None due to skip_serializing_if = "Option::is_none"
        assert!(json.contains("\"attested_by\":[]"), "json={json}");
        assert!(!json.contains("\"hlc_ts\""), "json={json}");
        assert!(!json.contains("\"crdt_kind\""), "json={json}");
    }

    #[test]
    fn manifest_with_hlc_preserves_other_fields() {
        let m = minimal_manifest();
        let original_version = m.version.clone();
        let hlc = HlcTimestamp::now_wall(crate::Did::from_test_string("o"));
        let m2 = m.with_hlc(hlc);
        assert_eq!(m2.version, original_version);
    }

    #[test]
    fn manifest_with_crdt_kind_round_trips_value() {
        let m = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:alice".into(),
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap()
            .with_crdt_kind("lww-register");
        assert_eq!(m.crdt_kind.as_deref(), Some("lww-register"));

        // Round-trips through canonical JSON
        let bytes = m.to_canonical_bytes().unwrap();
        let parsed: BlockManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.crdt_kind.as_deref(), Some("lww-register"));
    }

    #[test]
    fn manifest_canonical_bytes_are_stable_under_serde_roundtrip() {
        // CID stability anchor: any manifest built by v0.0.2 callers must
        // produce canonical bytes that survive a serde round-trip unchanged.
        // Phase B's ingest pipeline blake3-hashes canonical bytes to derive the
        // block CID; if this property breaks, every block CID computed by the
        // recipient differs from the sender's CID, breaking federation.
        let hlc = HlcTimestamp {
            wall_ms: 1234,
            logical: 5,
            server_did: crate::Did::from_test_string("o"),
        };
        let m = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:alice".into(),
                public_key: None,
                roles: vec!["author".into()],
            })
            .metadata_entry("example", serde_json::json!({"foo": "bar"}))
            .build()
            .unwrap()
            .with_hlc(hlc)
            .with_attested_by(vec![])
            .with_crdt_kind("lww-register");

        let bytes_first = m.to_canonical_bytes().unwrap();
        let parsed: BlockManifest = serde_json::from_slice(&bytes_first).unwrap();
        let bytes_second = parsed.to_canonical_bytes().unwrap();
        assert_eq!(
            bytes_first, bytes_second,
            "manifest canonical bytes drifted across serde roundtrip — \
             this breaks CID stability between sender and recipient"
        );

        // Also verify all three new fields survive the roundtrip with values intact.
        assert_eq!(parsed.hlc_ts.as_ref().map(|h| h.wall_ms), Some(1234));
        assert_eq!(parsed.attested_by.len(), 0);
        assert_eq!(parsed.crdt_kind.as_deref(), Some("lww-register"));
    }

    #[test]
    fn legacy_fixture_round_trip_does_not_panic() {
        // Sanity check: deserializing the legacy manifest fixture (no hlc_ts,
        // no attested_by, no crdt_kind keys) succeeds and produces defaults.
        // Note: this test does NOT assert byte-stability across that round-trip,
        // because legacy fixtures lack the v0.0.2 keys and their re-serialized
        // form will (intentionally) differ. That divergence is acceptable;
        // legacy CIDs are author-time-frozen.
        let fixture = include_str!("../tests/fixtures/manifest_v0.1.json");
        let parsed: BlockManifest = serde_json::from_str(fixture).unwrap();
        assert!(
            parsed.hlc_ts.is_none(),
            "legacy fixture should default hlc_ts to None"
        );
        assert!(
            parsed.attested_by.is_empty(),
            "legacy fixture should default attested_by to []"
        );
        assert!(
            parsed.crdt_kind.is_none(),
            "legacy fixture should default crdt_kind to None"
        );
    }
}
