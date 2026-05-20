use crate::capability_scope::CapabilityScopePattern;
use crate::error::{JigError, Result};
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

pub type Did = String;
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
        };
        manifest.validate()?;
        Ok(manifest)
    }
}
