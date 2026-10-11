use anyhow::{Result, anyhow};
use cid::Cid;
use reqwest::Url;
use serde::{Deserialize, Serialize};
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

