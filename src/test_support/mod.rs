pub mod api;

use std::time::{SystemTime, UNIX_EPOCH};

use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::rdata::tsig::{TsigAlgorithm, signed_bitmessage_to_buf};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, TSigner};

use crate::config::AppConfig;

pub fn config() -> AppConfig {
    AppConfig {
        listen_udp: "127.0.0.1:0".parse().unwrap(),
        listen_tcp: "127.0.0.1:0".parse().unwrap(),
        dns_zone: Name::from_ascii("example.com.").unwrap(),
        allowed_record_suffix: Name::from_ascii("example.com.").unwrap(),
        cloudflare_zone_id: "test-zone".into(),
        cloudflare_api_token: "dummy-api-token".into(),
        default_ttl: 300,
        enable_acme_txt: true,
        tsig_key_name: Name::from_ascii("test-key.").unwrap(),
        tsig_secret: b"dummy-tsig-key-for-tests-only".to_vec(),
        tsig_algorithm: TsigAlgorithm::HmacSha256,
        log_level: "info".into(),
    }
}

pub fn txt_record(name: &str, value: &[u8], class: DNSClass) -> Record {
    let ttl = if class == DNSClass::IN { 60 } else { 0 };
    let mut record = Record::from_rdata(
        Name::from_ascii(name).unwrap(),
        ttl,
        RData::TXT(TXT::from_bytes(vec![value])),
    );
    record.dns_class = class;
    record
}

pub fn update(records: Vec<Record>) -> Message {
    let mut message = Message::query();
    message.metadata.id = 0x1234;
    message.metadata.op_code = OpCode::Update;
    message.add_query(Query::query(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::SOA,
    ));
    message.authorities = records;
    message
}

pub fn sign(mut message: Message, config: &AppConfig) -> Vec<u8> {
    let signer = TSigner::new(
        config.tsig_secret.clone(),
        config.tsig_algorithm.clone(),
        config.tsig_key_name.clone(),
        300,
    )
    .unwrap();
    message
        .finalize(
            &signer,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
    message.to_vec().unwrap()
}

pub fn check_response(request: &[u8], response: &[u8], config: &AppConfig, expected: ResponseCode) {
    let request_message = Message::from_vec(request).unwrap();
    let response_message = Message::from_vec(response).unwrap();
    assert_eq!(request_message.id, response_message.id);
    assert_eq!(response_message.op_code, OpCode::Update);
    assert_eq!(response_message.response_code, expected);
    let (_, request_tsig) = signed_bitmessage_to_buf(request, None, true).unwrap();
    let (data, response_tsig) =
        signed_bitmessage_to_buf(response, Some(&request_tsig.data.mac), true).unwrap();
    assert_eq!(response_tsig.name, config.tsig_key_name);
    assert_eq!(response_tsig.data.algorithm, config.tsig_algorithm);
    config
        .tsig_algorithm
        .verify_mac(&config.tsig_secret, &data, &response_tsig.data.mac)
        .unwrap();
}
