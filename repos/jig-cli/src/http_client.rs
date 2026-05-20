use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use cid::Cid;
use jig_core::{Author, BlockBundle, BlockManifest};
use reqwest::Url;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

#[derive(Clone)]
pub struct JigHttpClient {
    base_url: Url,
    client: reqwest::Client,
}

impl JigHttpClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let url = Url::parse(base_url).map_err(|e| anyhow!("invalid base url: {e}"))?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            base_url: url,
            client,
        })
    }

    pub async fn ingest_text(&self, author_did: &str, channel: &str, text: &str) -> Result<Cid> {
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: author_did.to_string(),
                public_key: None,
                roles: vec![],
            })
            .metadata_entry("kind", json!("text"))
            .metadata_entry("channel", json!(channel))
            .metadata_entry("content", json!(text))
            .build()?;

        let manifest_bytes = manifest.to_canonical_bytes()?;
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &[],
            resources: vec![],
        };
        let _expected_cid = bundle.block_cid()?;

        let payload = serde_json::json!({
            "manifest": manifest,
        });

        let url = self.base_url.join("blocks")?;
        let resp: IngestResponse = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let parsed: Cid = resp
            .block_id
            .parse()
            .map_err(|e| anyhow!("invalid CID returned: {e}"))?;
        Ok(parsed)
    }

    pub async fn list_blocks(&self, limit: usize) -> Result<Vec<BlockSummary>> {
        let mut url = self.base_url.join("blocks")?;
        url.set_query(Some(&format!("limit={}", limit)));

        let resp = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<BlockSummary>>()
            .await?;
        Ok(resp)
    }

    #[allow(dead_code)]
    pub async fn get_block(&self, cid: &Cid) -> Result<BlockDetail> {
        let url = self.base_url.join(&format!("blocks/{}", cid))?;
        let resp = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<BlockDetail>()
            .await?;
        Ok(resp)
    }
}

#[derive(Debug, Deserialize)]
struct IngestResponse {
    block_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockSummary {
    pub block_id: String,
    pub manifest: serde_json::Value,
    pub created_at: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct BlockDetail {
    pub block_id: String,
    pub manifest: serde_json::Value,
    pub code_b64: Option<String>,
    pub resources: Vec<BlockResource>,
    pub created_at: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct BlockResource {
    pub name: String,
    pub mime: String,
    pub data_b64: String,
}

impl BlockSummary {
    pub fn created_at(&self) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(&self.created_at)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    }
}
