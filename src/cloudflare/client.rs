use std::collections::HashSet;
use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use thiserror::Error;

use super::model::{ApiEnvelope, DeleteResult, DnsRecord, DnsRecordKind, RecordRequest};
use super::{record_locks::RecordLocks, txt};

const BASE_URL: &str = "https://api.cloudflare.com/client/v4";

#[derive(Clone)]
pub struct CloudflareClient {
    http: Client,
    base_url: String,
    zone_id: String,
    api_token: String,
    locks: RecordLocks,
}

#[derive(Debug, Error)]
pub enum CloudflareError {
    #[error("HTTP client construction failed")]
    ClientBuild,

    #[error("HTTP request failed for {operation}")]
    Http { operation: &'static str },

    #[error("Cloudflare API error for {operation}: status={status}, codes={codes:?}")]
    Api {
        operation: &'static str,
        status: StatusCode,
        codes: Vec<i64>,
    },

    #[error("invalid Cloudflare response for {operation}")]
    Parse { operation: &'static str },

    #[error("unsupported TXT operation")]
    InvalidTxt,
}

impl CloudflareClient {
    pub fn new(zone_id: String, api_token: String) -> Result<Self, CloudflareError> {
        Self::with_endpoint(
            zone_id,
            api_token,
            BASE_URL.to_string(),
            Duration::from_secs(15),
        )
    }

    pub(crate) fn with_endpoint(
        zone_id: String,
        api_token: String,
        base_url: String,
        timeout: Duration,
    ) -> Result<Self, CloudflareError> {
        let http = Client::builder()
            .timeout(timeout)
            .user_agent(concat!(
                "cloudflare-ddns-rfc2136/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(|_| CloudflareError::ClientBuild)?;

        Ok(Self {
            http,
            base_url,
            zone_id,
            api_token,
            locks: RecordLocks::default(),
        })
    }

    pub async fn upsert_rrset(
        &self,
        name: &str,
        kind: DnsRecordKind,
        contents: &[String],
        ttl: u32,
    ) -> Result<(), CloudflareError> {
        if kind == DnsRecordKind::Txt {
            return Err(CloudflareError::InvalidTxt);
        }
        let _guard = self.locks.acquire(name, kind).await;
        let desired = dedupe(contents);
        let existing = self.list_records(kind, name).await?;
        let mut used_ids = HashSet::new();

        for content in &desired {
            if let Some(record) = existing
                .iter()
                .find(|record| record.content == *content && !used_ids.contains(&record.id))
            {
                used_ids.insert(record.id.clone());
                if record.ttl != ttl || record.proxied.unwrap_or(false) {
                    self.update_record(&record.id, name, kind, content, ttl)
                        .await?;
                }
                continue;
            }

            if let Some(record) = existing
                .iter()
                .find(|record| !used_ids.contains(&record.id))
            {
                used_ids.insert(record.id.clone());
                self.update_record(&record.id, name, kind, content, ttl)
                    .await?;
            } else {
                self.create_record(name, kind, content, ttl).await?;
            }
        }

        for record in existing {
            if !used_ids.contains(&record.id) {
                self.delete_record_by_id(&record.id).await?;
            }
        }

        Ok(())
    }

    pub async fn add_txt(
        &self,
        name: &str,
        content: &str,
        ttl: u32,
    ) -> Result<(), CloudflareError> {
        if !content.is_ascii() || content.len() > 255 {
            return Err(CloudflareError::InvalidTxt);
        }
        let _guard = self.locks.acquire(name, DnsRecordKind::Txt).await;
        let records = self.list_records(DnsRecordKind::Txt, name).await?;
        if records
            .iter()
            .any(|record| txt::decode(&record.content).as_deref() == Some(content))
        {
            return Ok(());
        }
        self.create_record(name, DnsRecordKind::Txt, &txt::encode(content), ttl)
            .await?;
        Ok(())
    }

    pub async fn delete_rrset(
        &self,
        name: &str,
        kind: DnsRecordKind,
    ) -> Result<(), CloudflareError> {
        if kind == DnsRecordKind::Txt {
            return Err(CloudflareError::InvalidTxt);
        }
        let _guard = self.locks.acquire(name, kind).await;
        for record in self.list_records(kind, name).await? {
            self.delete_record_by_id(&record.id).await?;
        }
        Ok(())
    }

    pub async fn delete_record(
        &self,
        name: &str,
        kind: DnsRecordKind,
        content: &str,
    ) -> Result<(), CloudflareError> {
        let _guard = self.locks.acquire(name, kind).await;
        for record in self.list_records(kind, name).await? {
            let matches = if kind == DnsRecordKind::Txt {
                txt::decode(&record.content).as_deref() == Some(content)
            } else {
                record.content == content
            };
            if matches {
                self.delete_record_by_id(&record.id).await?;
            }
        }
        Ok(())
    }

    async fn list_records(
        &self,
        kind: DnsRecordKind,
        name: &str,
    ) -> Result<Vec<DnsRecord>, CloudflareError> {
        let name = cloudflare_name(name);
        let mut page = 1_u32;
        let mut records = Vec::new();
        loop {
            let request = self
                .http
                .get(self.records_url())
                .bearer_auth(&self.api_token)
                .query(&[
                    ("type", kind.as_str()),
                    ("name", name.as_str()),
                    ("page", &page.to_string()),
                    ("per_page", "100"),
                ]);
            let envelope: ApiEnvelope<Vec<DnsRecord>> =
                self.send_envelope(request, "list_records").await?;
            let info = envelope.result_info.ok_or(CloudflareError::Parse {
                operation: "list_records pagination",
            })?;
            let result = envelope.result.ok_or(CloudflareError::Parse {
                operation: "list_records",
            })?;
            if info.page != page
                || (info.total_pages < page
                    && !(page == 1 && info.total_pages == 0 && result.is_empty()))
            {
                return Err(CloudflareError::Parse {
                    operation: "list_records pagination",
                });
            }
            records.extend(result.into_iter().filter(|record| {
                cloudflare_name(&record.name) == name && record.record_type == kind.as_str()
            }));
            if page >= info.total_pages {
                return Ok(records);
            }
            page += 1;
        }
    }

    async fn create_record(
        &self,
        name: &str,
        kind: DnsRecordKind,
        content: &str,
        ttl: u32,
    ) -> Result<DnsRecord, CloudflareError> {
        let body = RecordRequest {
            record_type: kind.as_str(),
            name: &cloudflare_name(name),
            content,
            ttl,
            proxied: (kind != DnsRecordKind::Txt).then_some(false),
        };
        let request = self
            .http
            .post(self.records_url())
            .bearer_auth(&self.api_token)
            .json(&body);

        self.send(request, "create_record").await
    }

    async fn update_record(
        &self,
        id: &str,
        name: &str,
        kind: DnsRecordKind,
        content: &str,
        ttl: u32,
    ) -> Result<DnsRecord, CloudflareError> {
        let body = RecordRequest {
            record_type: kind.as_str(),
            name: &cloudflare_name(name),
            content,
            ttl,
            proxied: (kind != DnsRecordKind::Txt).then_some(false),
        };
        let request = self
            .http
            .put(format!("{}/{}", self.records_url(), id))
            .bearer_auth(&self.api_token)
            .json(&body);

        self.send(request, "update_record").await
    }

    async fn delete_record_by_id(&self, id: &str) -> Result<(), CloudflareError> {
        let request = self
            .http
            .delete(format!("{}/{}", self.records_url(), id))
            .bearer_auth(&self.api_token);

        let result: DeleteResult = self.send(request, "delete_record").await?;
        let _ = result.id;
        Ok(())
    }

    async fn send<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        operation: &'static str,
    ) -> Result<T, CloudflareError> {
        self.send_envelope(request, operation)
            .await?
            .result
            .ok_or(CloudflareError::Parse { operation })
    }

    async fn send_envelope<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        operation: &'static str,
    ) -> Result<ApiEnvelope<T>, CloudflareError> {
        let response = request
            .send()
            .await
            .map_err(|_| CloudflareError::Http { operation })?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|_| CloudflareError::Http { operation })?;
        // Remote error text can contain credentials. Keep only status and numeric codes.
        if !status.is_success() {
            return Err(CloudflareError::Api {
                operation,
                status,
                codes: Vec::new(),
            });
        }
        let envelope: ApiEnvelope<T> =
            serde_json::from_slice(&body).map_err(|_| CloudflareError::Parse { operation })?;
        if !envelope.success {
            return Err(CloudflareError::Api {
                operation,
                status,
                codes: envelope.errors.iter().map(|error| error.code).collect(),
            });
        }
        Ok(envelope)
    }

    fn records_url(&self) -> String {
        format!("{}/zones/{}/dns_records", self.base_url, self.zone_id)
    }
}

fn cloudflare_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn dedupe(contents: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for content in contents {
        if seen.insert(content.clone()) {
            result.push(content.clone());
        }
    }
    result
}
