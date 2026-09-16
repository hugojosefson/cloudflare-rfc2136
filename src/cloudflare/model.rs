use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DnsRecordKind {
    A,
    Aaaa,
    Txt,
}

impl DnsRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Txt => "TXT",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    pub ttl: u32,
    pub proxied: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ApiEnvelope<T> {
    pub success: bool,
    pub errors: Vec<ApiError>,
    pub result: Option<T>,
    pub result_info: Option<PageInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    pub code: i64,
}

#[derive(Debug, Deserialize)]
pub struct PageInfo {
    pub page: u32,
    pub total_pages: u32,
}

#[derive(Debug, Deserialize)]
pub struct DeleteResult {
    pub id: String,
}

#[derive(Debug, Serialize)]
pub struct RecordRequest<'a> {
    #[serde(rename = "type")]
    pub record_type: &'a str,
    pub name: &'a str,
    pub content: &'a str,
    pub ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,
}
