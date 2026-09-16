use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, OpCode, ResponseCode, update_message};
use hickory_proto::rr::rdata::{A, AAAA, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use super::*;
use crate::test_support::api::{Fault, MockApi, record};
use crate::test_support::{check_response, config, sign, txt_record, update};

const NAME: &str = "_acme-challenge.example.com.";

#[test]
fn fallback_response_preserves_id_and_opcode() {
    let raw = [0x12, 0x34, 0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let response = fallback_response(&raw, ResponseCode::Refused);
    assert_eq!(&response[0..2], &[0x12, 0x34]);
    assert_eq!(response[2] & 0x78, 0x28);
    assert_eq!(response[3], 5);
}

#[tokio::test]
async fn invalid_permissions_and_records_cause_no_api_requests() {
    let api = MockApi::start(Vec::new()).await;
    let client = Arc::new(api.client());
    let cfg = config();
    let valid = txt_record(NAME, b"value", DNSClass::IN);
    let mut cases = Vec::new();
    let mut disabled = cfg.clone();
    disabled.enable_acme_txt = false;
    cases.push((update(vec![valid.clone()]), disabled));
    let mut restricted = cfg.clone();
    restricted.allowed_record_suffix = Name::from_ascii("allowed.example.com.").unwrap();
    cases.push((update(vec![valid.clone()]), restricted));
    for class in [DNSClass::IN, DNSClass::NONE] {
        for name in [
            "example.com.",
            "*.example.com.",
            "_acme-challenge.*.example.com.",
            "_other.example.com.",
            "_acme-challenge-extra.example.com.",
            "host.example.com.",
            "_acme-challenge._other.example.com.",
            "_acme-challenge.example.com.evil.example.",
        ] {
            cases.push((update(vec![txt_record(name, b"value", class)]), cfg.clone()));
        }
    }
    for data in [
        RData::TXT(TXT::from_bytes(vec![b"a", b"b"])),
        RData::TXT(TXT::from_bytes(vec![b"\xff"])),
        RData::TXT(TXT::from_bytes(Vec::new())),
        RData::Update0(RecordType::TXT),
        RData::Update0(RecordType::ANY),
        RData::A(A("192.0.2.1".parse().unwrap())),
        RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
        RData::Update0(RecordType::MX),
    ] {
        let record = Record::from_rdata(Name::from_ascii(NAME).unwrap(), 0, data);
        cases.push((update(vec![record]), cfg.clone()));
    }
    for class in [DNSClass::ANY, DNSClass::CH, DNSClass::HS] {
        cases.push((update(vec![txt_record(NAME, b"value", class)]), cfg.clone()));
    }
    let mut invalid_ttl = valid.clone();
    invalid_ttl.ttl = u32::MAX;
    cases.push((update(vec![invalid_ttl]), cfg.clone()));
    let mut nonzero_delete = txt_record(NAME, b"value", DNSClass::NONE);
    nonzero_delete.ttl = 1;
    cases.push((update(vec![nonzero_delete]), cfg.clone()));
    let mut empty_any = Record::from_rdata(
        Name::from_ascii(NAME).unwrap(),
        0,
        RData::Update0(RecordType::TXT),
    );
    empty_any.dns_class = DNSClass::ANY;
    cases.push((update(vec![empty_any]), cfg.clone()));
    let mut wrong_zone = update(vec![valid.clone()]);
    wrong_zone.queries[0].set_name(Name::from_ascii("other.example.").unwrap());
    cases.push((wrong_zone, cfg.clone()));
    let mut wrong_class = update(vec![valid.clone()]);
    wrong_class.queries[0].set_query_class(DNSClass::CH);
    cases.push((wrong_class, cfg.clone()));
    let mut wrong_type = update(vec![valid.clone()]);
    wrong_type.queries[0].set_query_type(RecordType::TXT);
    cases.push((wrong_type, cfg.clone()));
    let mut prerequisites = update(vec![valid.clone()]);
    prerequisites.answers.push(valid.clone());
    cases.push((prerequisites, cfg.clone()));
    let mut not_update = update(vec![valid.clone()]);
    not_update.metadata.op_code = OpCode::Query;
    let wire = sign(not_update, &cfg);
    let response = handle_wire(&wire, Arc::new(cfg.clone()), client.clone()).await;
    assert_eq!(
        Message::from_vec(&response).unwrap().response_code,
        ResponseCode::Refused
    );
    for (mut message, cfg) in cases {
        // A valid first record must not cause a write before later validation fails.
        message.authorities.insert(0, valid.clone());
        let wire = sign(message, &cfg);
        let response = handle_wire(&wire, Arc::new(cfg.clone()), client.clone()).await;
        check_response(&wire, &response, &cfg, ResponseCode::Refused);
    }
    assert!(api.state.lock().unwrap().requests.is_empty());
}

#[tokio::test]
async fn invalid_authentication_causes_no_api_requests() {
    let api = MockApi::start(Vec::new()).await;
    let cfg = config();
    let message = update(vec![txt_record(NAME, b"value", DNSClass::IN)]);
    let mut wrong_key = cfg.clone();
    wrong_key.tsig_secret = b"wrong-dummy-secret".to_vec();
    let mut wrong_name = cfg.clone();
    wrong_name.tsig_key_name = Name::from_ascii("wrong-key.").unwrap();
    let mut wrong_algorithm = cfg.clone();
    wrong_algorithm.tsig_algorithm = hickory_proto::rr::rdata::tsig::TsigAlgorithm::HmacSha512;
    for wire in [
        message.to_vec().unwrap(),
        sign(message.clone(), &wrong_key),
        sign(message.clone(), &wrong_name),
        sign(message, &wrong_algorithm),
    ] {
        let response = handle_wire(&wire, Arc::new(cfg.clone()), Arc::new(api.client())).await;
        assert_eq!(
            Message::from_vec(&response).unwrap().response_code,
            ResponseCode::Refused
        );
    }
    assert!(api.state.lock().unwrap().requests.is_empty());
}

#[tokio::test]
async fn txt_order_case_whitespace_and_ttl_survive_wire_processing() {
    let api = MockApi::start(Vec::new()).await;
    let cfg = Arc::new(config());
    let client = Arc::new(api.client());
    let add = txt_record(
        "_ACME-CHALLENGE.Host.Example.COM.",
        b" Mixed-Case \t",
        DNSClass::IN,
    );
    let delete = txt_record(
        "_acme-challenge.host.example.com.",
        b" Mixed-Case \t",
        DNSClass::NONE,
    );
    for (records, count) in [
        (vec![add.clone(), delete.clone()], 0),
        (vec![delete, add.clone()], 1),
        (vec![add], 1),
    ] {
        let wire = sign(update(records), &cfg);
        let response = handle_wire(&wire, cfg.clone(), client.clone()).await;
        check_response(&wire, &response, &cfg, ResponseCode::NoError);
        assert_eq!(api.values().len(), count);
    }
    let state = api.state.lock().unwrap();
    assert_eq!(state.records[0]["content"], "\" Mixed-Case \\009\"");
    assert_eq!(state.records[0]["name"], "_acme-challenge.host.example.com");
    assert_eq!(state.records[0]["ttl"], 300);
}

#[tokio::test]
async fn update_reports_partial_api_failure_and_retry_is_safe() {
    let api = MockApi::start(Vec::new()).await;
    api.state.lock().unwrap().faults.insert(
        4,
        Fault {
            status: 429,
            body: "dummy-api-token".into(),
            delay: Duration::ZERO,
        },
    );
    let cfg = Arc::new(config());
    let client = Arc::new(api.client());
    let wire = sign(
        update(vec![
            txt_record(NAME, b"a", DNSClass::IN),
            txt_record(NAME, b"b", DNSClass::IN),
        ]),
        &cfg,
    );
    let response = handle_wire(&wire, cfg.clone(), client.clone()).await;
    check_response(&wire, &response, &cfg, ResponseCode::ServFail);
    assert_eq!(api.values(), ["\"a\""]);
    let response = handle_wire(&wire, cfg.clone(), client).await;
    check_response(&wire, &response, &cfg, ResponseCode::NoError);
    assert_eq!(api.values(), ["\"a\"", "\"b\""]);
}

#[tokio::test]
async fn timeout_and_api_errors_produce_signed_servfail() {
    for (status, delay) in [
        (403, Duration::ZERO),
        (429, Duration::ZERO),
        (200, Duration::ZERO),
        (200, Duration::from_millis(200)),
    ] {
        let api = MockApi::start(Vec::new()).await;
        api.state.lock().unwrap().faults.insert(
            1,
            Fault {
                status,
                body: "dummy-api-token".into(),
                delay,
            },
        );
        let cfg = Arc::new(config());
        let wire = sign(update(vec![txt_record(NAME, b"a", DNSClass::IN)]), &cfg);
        let client = Arc::new(api.client_with_timeout(Duration::from_millis(50)));
        let response = handle_wire(&wire, cfg.clone(), client).await;
        check_response(&wire, &response, &cfg, ResponseCode::ServFail);
        assert!(!String::from_utf8_lossy(&response).contains("dummy-api-token"));
    }
}

#[tokio::test]
async fn hickory_builders_encode_value_cleanup_and_full_set_refusal() {
    let api = MockApi::start(vec![record(
        "b",
        "_acme-challenge.example.com",
        "TXT",
        "\"b\"",
    )])
    .await;
    let cfg = Arc::new(config());
    let client = Arc::new(api.client());
    let record = txt_record(NAME, b"a", DNSClass::IN);
    let mut rrset = RecordSet::new(record.name.clone(), RecordType::TXT, 60);
    rrset.insert(record.clone(), 0);
    let add = update_message::append(rrset.clone(), cfg.dns_zone.clone(), false, true);
    let delete = update_message::delete_by_rdata(rrset, cfg.dns_zone.clone(), true);
    let old_delete = update_message::delete_rrset(record, cfg.dns_zone.clone(), true);
    for (message, expected) in [
        (add, ResponseCode::NoError),
        (delete, ResponseCode::NoError),
        (old_delete, ResponseCode::Refused),
    ] {
        let wire = sign(message, &cfg);
        let response = handle_wire(&wire, cfg.clone(), client.clone()).await;
        check_response(&wire, &response, &cfg, expected);
    }
    assert_eq!(api.values(), ["\"b\""]);
}

#[tokio::test]
async fn signed_udp_and_tcp_updates_use_shared_state() {
    let api = MockApi::start(Vec::new()).await;
    let cfg = Arc::new(config());
    let client = Arc::new(api.client());
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let udp_task = tokio::spawn(serve_udp(udp, cfg.clone(), client.clone()));
    let tcp_task = tokio::spawn(serve_tcp(tcp, cfg.clone(), client));
    tokio::time::timeout(Duration::from_secs(5), async {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(udp_addr).await.unwrap();
        let mut stream = TcpStream::connect(tcp_addr).await.unwrap();
        for class in [DNSClass::IN, DNSClass::NONE, DNSClass::NONE] {
            let wire = sign(update(vec![txt_record(NAME, b"shared", class)]), &cfg);
            let udp_response = async {
                socket.send(&wire).await.unwrap();
                let mut buf = vec![0; 4096];
                let len = socket.recv(&mut buf).await.unwrap();
                buf.truncate(len);
                buf
            };
            let tcp_response = async {
                stream.write_u16(wire.len() as u16).await.unwrap();
                stream.write_all(&wire).await.unwrap();
                let len = stream.read_u16().await.unwrap();
                let mut buf = vec![0; usize::from(len)];
                stream.read_exact(&mut buf).await.unwrap();
                buf
            };
            let (udp, tcp) = tokio::join!(udp_response, tcp_response);
            check_response(&wire, &udp, &cfg, ResponseCode::NoError);
            check_response(&wire, &tcp, &cfg, ResponseCode::NoError);
            assert_eq!(
                api.values().len(),
                if class == DNSClass::IN { 1 } else { 0 }
            );
        }
    })
    .await
    .unwrap();
    udp_task.abort();
    tcp_task.abort();
}

#[tokio::test]
async fn malformed_packets_do_not_panic_or_call_the_api() {
    let api = MockApi::start(Vec::new()).await;
    let cfg = Arc::new(config());
    let client = Arc::new(api.client());
    let wire = sign(update(vec![txt_record(NAME, b"value", DNSClass::IN)]), &cfg);
    for len in 0..wire.len() {
        let response = handle_wire(&wire[..len], cfg.clone(), client.clone()).await;
        let response = Message::from_vec(&response).unwrap();
        assert_ne!(response.response_code, ResponseCode::NoError);
    }
    assert!(api.state.lock().unwrap().requests.is_empty());
}

#[test]
fn address_parsing_and_restrictions_remain() {
    let cfg = config();
    for data in [
        RData::A(A("192.0.2.1".parse().unwrap())),
        RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
    ] {
        let record = Record::from_rdata(
            Name::from_ascii("HOST.example.com.").unwrap(),
            60,
            data.clone(),
        );
        let changes = rfc2136::extract_changes(&update(vec![record]), &cfg).unwrap();
        assert!(
            matches!(&changes[0], rfc2136::DnsChange::Upsert { name, .. } if name == "host.example.com.")
        );
        for name in [
            NAME,
            "_other.example.com.",
            "example.com.",
            "*.example.com.",
            "host.example.com.evil.example.",
        ] {
            let record = Record::from_rdata(Name::from_ascii(name).unwrap(), 60, data.clone());
            assert!(rfc2136::extract_changes(&update(vec![record]), &cfg).is_err());
        }
    }
}

#[tokio::test]
async fn ascii_wire_round_trip_and_all_tsig_algorithms() {
    use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
    for algorithm in [
        TsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha512,
    ] {
        let api = MockApi::start(Vec::new()).await;
        let mut cfg = config();
        cfg.tsig_algorithm = algorithm;
        let cfg = Arc::new(cfg);
        let client = Arc::new(api.client());
        let value: Vec<_> = (0..=127).chain(0..127).collect();
        for bytes in [value.as_slice(), b""] {
            for class in [DNSClass::IN, DNSClass::NONE] {
                let wire = sign(update(vec![txt_record(NAME, bytes, class)]), &cfg);
                let response = handle_wire(&wire, cfg.clone(), client.clone()).await;
                check_response(&wire, &response, &cfg, ResponseCode::NoError);
            }
        }
        assert!(api.values().is_empty());
    }
}
