use std::collections::BTreeMap;

use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};

use crate::cloudflare::model::DnsRecordKind;
use crate::config::AppConfig;

use super::DnsError;
use super::validation::normalize_owner_name;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DnsChange {
    AddTxt {
        name: String,
        content: String,
    },
    Upsert {
        name: String,
        kind: DnsRecordKind,
        contents: Vec<String>,
    },
    DeleteRrset {
        name: String,
        kind: DnsRecordKind,
    },
    DeleteRecord {
        name: String,
        kind: DnsRecordKind,
        content: String,
    },
}

pub fn extract_changes(message: &Message, config: &AppConfig) -> Result<Vec<DnsChange>, DnsError> {
    if message.metadata.message_type != MessageType::Query
        || message.metadata.op_code != OpCode::Update
    {
        return Err(DnsError::NotUpdate);
    }

    validate_zone(message, config)?;

    if !message.answers.is_empty() {
        return Err(DnsError::UnsupportedOperation(
            "prerequisite section is not supported".to_string(),
        ));
    }

    let mut changes = Vec::new();
    let mut pending_adds: BTreeMap<(String, DnsRecordKind), Vec<String>> = BTreeMap::new();

    for record in &message.authorities {
        let kind = DnsRecordKind::try_from(record.record_type())?;
        let name = normalize_owner_name(&record.name, kind, config)?.to_ascii();

        match classify_record(record, kind)? {
            RecordOperation::Add(content) if kind == DnsRecordKind::Txt => {
                flush_pending(&mut pending_adds, &mut changes);
                changes.push(DnsChange::AddTxt { name, content });
            }
            RecordOperation::Add(content) => {
                pending_adds.entry((name, kind)).or_default().push(content);
            }
            RecordOperation::DeleteRrset => {
                flush_pending(&mut pending_adds, &mut changes);
                changes.push(DnsChange::DeleteRrset { name, kind });
            }
            RecordOperation::DeleteRecord(content) => {
                flush_pending(&mut pending_adds, &mut changes);
                changes.push(DnsChange::DeleteRecord {
                    name,
                    kind,
                    content,
                });
            }
        }
    }

    flush_pending(&mut pending_adds, &mut changes);
    Ok(changes)
}

fn validate_zone(message: &Message, config: &AppConfig) -> Result<(), DnsError> {
    if message.queries.len() != 1 {
        return Err(DnsError::ZoneRejected(
            "RFC2136 update must contain exactly one zone".to_string(),
        ));
    }

    let zone = &message.queries[0];
    let mut zone_name = zone.name().to_lowercase();
    zone_name.set_fqdn(true);

    if zone_name != config.dns_zone {
        return Err(DnsError::ZoneRejected(format!(
            "requested zone {zone_name} does not match DNS_ZONE"
        )));
    }

    if zone.query_class() != DNSClass::IN {
        return Err(DnsError::ZoneRejected("zone class must be IN".to_string()));
    }

    if zone.query_type() != RecordType::SOA {
        return Err(DnsError::ZoneRejected(
            "zone type must be SOA for RFC2136 updates".to_string(),
        ));
    }

    Ok(())
}

fn classify_record(record: &Record, kind: DnsRecordKind) -> Result<RecordOperation, DnsError> {
    match record.dns_class {
        DNSClass::IN => {
            if kind == DnsRecordKind::Txt && record.ttl > i32::MAX as u32 {
                return Err(DnsError::UnsupportedOperation(
                    "TXT TTL exceeds 2147483647".to_string(),
                ));
            }
            let content = record_content(record, kind)?.ok_or_else(|| {
                DnsError::UnsupportedOperation("add operation must include record data".to_string())
            })?;
            Ok(RecordOperation::Add(content))
        }
        DNSClass::ANY => {
            if kind == DnsRecordKind::Txt {
                return Err(DnsError::UnsupportedOperation(
                    "TXT removal must specify a value with class NONE".to_string(),
                ));
            }
            if record.ttl != 0 {
                return Err(DnsError::UnsupportedOperation(
                    "delete-rrset operation must use TTL 0".to_string(),
                ));
            }

            match &record.data {
                RData::Update0(_) => Ok(RecordOperation::DeleteRrset),
                _ => Err(DnsError::UnsupportedOperation(
                    "delete-rrset operation must have empty RDATA".to_string(),
                )),
            }
        }
        DNSClass::NONE => {
            if record.ttl != 0 {
                return Err(DnsError::UnsupportedOperation(
                    "delete-record operation must use TTL 0".to_string(),
                ));
            }

            let content = record_content(record, kind)?.ok_or_else(|| {
                DnsError::UnsupportedOperation(
                    "delete-record operation must include record data".to_string(),
                )
            })?;
            Ok(RecordOperation::DeleteRecord(content))
        }
        other => Err(DnsError::UnsupportedOperation(format!(
            "record class {other} is not allowed"
        ))),
    }
}

fn record_content(record: &Record, kind: DnsRecordKind) -> Result<Option<String>, DnsError> {
    match (&record.data, kind) {
        (RData::A(A(addr)), DnsRecordKind::A) => Ok(Some(addr.to_string())),
        (RData::AAAA(AAAA(addr)), DnsRecordKind::Aaaa) => Ok(Some(addr.to_string())),
        (RData::TXT(txt), DnsRecordKind::Txt) => {
            let [content] = txt.txt_data.as_ref() else {
                return Err(DnsError::RecordRejected(
                    "TXT must contain one string".to_string(),
                ));
            };
            if !content.is_ascii() || content.len() > 255 {
                return Err(DnsError::RecordRejected(
                    "TXT must contain at most 255 ASCII bytes".to_string(),
                ));
            }
            Ok(Some(String::from_utf8(content.to_vec()).map_err(|_| {
                DnsError::RecordRejected("invalid TXT data".to_string())
            })?))
        }
        (RData::Update0(_), _) => Ok(None),
        _ => Err(DnsError::RecordRejected(format!(
            "record type {} is not allowed",
            record.record_type()
        ))),
    }
}

fn flush_pending(
    pending_adds: &mut BTreeMap<(String, DnsRecordKind), Vec<String>>,
    changes: &mut Vec<DnsChange>,
) {
    for ((name, kind), contents) in std::mem::take(pending_adds) {
        changes.push(DnsChange::Upsert {
            name,
            kind,
            contents,
        });
    }
}

enum RecordOperation {
    Add(String),
    DeleteRrset,
    DeleteRecord(String),
}

impl TryFrom<RecordType> for DnsRecordKind {
    type Error = DnsError;

    fn try_from(value: RecordType) -> Result<Self, Self::Error> {
        match value {
            RecordType::A => Ok(Self::A),
            RecordType::AAAA => Ok(Self::Aaaa),
            RecordType::TXT => Ok(Self::Txt),
            other => Err(DnsError::RecordRejected(format!(
                "record type {other} is not allowed"
            ))),
        }
    }
}
