use std::time::Duration;

use serde_json::json;

use super::model::DnsRecordKind;
use crate::test_support::api::{Fault, MockApi, record};

const NAME: &str = "_acme-challenge.example.com";

#[tokio::test]
async fn adds_and_cleanup_keep_other_values_and_support_retries() {
    let api = MockApi::start(vec![record("a", NAME, "TXT", "\"value-a\"")]).await;
    let client = api.client();
    client.add_txt(NAME, "value-b", 300).await.unwrap();
    client.add_txt(NAME, "value-b", 300).await.unwrap();
    assert_eq!(api.values(), ["\"value-a\"", "\"value-b\""]);
    client
        .delete_record(NAME, DnsRecordKind::Txt, "value-a")
        .await
        .unwrap();
    client
        .delete_record(NAME, DnsRecordKind::Txt, "value-a")
        .await
        .unwrap();
    assert_eq!(api.values(), ["\"value-b\""]);
    let state = api.state.lock().unwrap();
    let writes: Vec<_> = state
        .requests
        .iter()
        .filter(|r| r.method == "POST")
        .collect();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].body["content"], "\"value-b\"");
    assert_eq!(writes[0].body["ttl"], 300);
    assert!(writes[0].body.get("proxied").is_none());
    assert!(!state.requests.iter().any(|r| r.method == "PUT"));
}

#[tokio::test]
async fn pagination_finds_existing_values_and_collects_ids_before_removal() {
    let api = MockApi::start(vec![
        record("b", NAME, "TXT", "\"value-b\""),
        record("a1", NAME, "TXT", "\"value-a\""),
        record("a2", NAME, "TXT", "value-a"),
        record("other", NAME, "TXT", "\"value-\" \"a\""),
    ])
    .await;
    api.state.lock().unwrap().page_size = 1;
    let client = api.client();
    client.add_txt(NAME, "value-a", 300).await.unwrap();
    assert_eq!(api.state.lock().unwrap().requests.len(), 4);
    client
        .delete_record(NAME, DnsRecordKind::Txt, "value-a")
        .await
        .unwrap();
    assert_eq!(api.values(), ["\"value-b\"", "\"value-\" \"a\""]);
    let state = api.state.lock().unwrap();
    let methods: Vec<_> = state.requests.iter().map(|r| r.method.as_str()).collect();
    assert_eq!(
        methods,
        [
            "GET", "GET", "GET", "GET", "GET", "GET", "GET", "GET", "DELETE", "DELETE"
        ]
    );
}

#[tokio::test]
async fn exact_owner_and_type_filters_protect_unrelated_records() {
    let api = MockApi::start(vec![
        record("1", "other.example.com", "TXT", "\"value\""),
        record("2", NAME, "A", "value"),
        record("3", NAME, "TXT", "\"value\""),
    ])
    .await;
    api.state.lock().unwrap().include_unmatched = true;
    api.client()
        .delete_record(NAME, DnsRecordKind::Txt, "value")
        .await
        .unwrap();
    assert_eq!(api.state.lock().unwrap().records.len(), 2);
}

#[tokio::test]
async fn concurrent_additions_share_locks_across_clones_and_name_case() {
    let api = MockApi::start(Vec::new()).await;
    let client = api.client();
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..20 {
        let client = client.clone();
        tasks.spawn(async move {
            let name = if index % 2 == 0 {
                "_ACME-CHALLENGE.EXAMPLE.COM."
            } else {
                NAME
            };
            client
                .add_txt(name, &format!("value-{}", index % 4), 300)
                .await
                .unwrap();
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    let mut values = api.values();
    values.sort();
    assert_eq!(
        values,
        ["\"value-0\"", "\"value-1\"", "\"value-2\"", "\"value-3\""]
    );
    let (add, remove) = tokio::join!(
        client.add_txt(NAME, "new", 300),
        client.delete_record(NAME, DnsRecordKind::Txt, "value-0"),
    );
    add.unwrap();
    remove.unwrap();
    assert_eq!(api.values().len(), 4);
    assert!(!api.values().contains(&"\"value-0\"".into()));
}

#[tokio::test]
async fn ascii_content_survives_cloudflare_encoding() {
    let api = MockApi::start(Vec::new()).await;
    let client = api.client();
    let value = " Case \"quoted\" \\backslash\t\0\x7f ";
    client.add_txt(NAME, value, 300).await.unwrap();
    client.add_txt(NAME, value, 300).await.unwrap();
    assert_eq!(api.values().len(), 1);
    assert_eq!(
        api.values()[0],
        "\" Case \\\"quoted\\\" \\\\backslash\\009\\000\\127 \""
    );
    client
        .delete_record(NAME, DnsRecordKind::Txt, value)
        .await
        .unwrap();
    assert!(api.values().is_empty());
}

#[tokio::test]
async fn txt_cannot_use_replacement_or_full_set_removal() {
    let api = MockApi::start(Vec::new()).await;
    let client = api.client();
    assert!(
        client
            .upsert_rrset(NAME, DnsRecordKind::Txt, &["value".into()], 300)
            .await
            .is_err()
    );
    assert!(client.delete_rrset(NAME, DnsRecordKind::Txt).await.is_err());
    assert!(api.state.lock().unwrap().requests.is_empty());
}

#[tokio::test]
async fn a_and_aaaa_keep_replacement_serialization() {
    for (kind, old, new) in [
        (DnsRecordKind::A, "192.0.2.1", "192.0.2.2"),
        (DnsRecordKind::Aaaa, "2001:db8::1", "2001:db8::2"),
    ] {
        let api = MockApi::start(vec![
            record("old", "host.example.com", kind.as_str(), old),
            record("extra", "host.example.com", kind.as_str(), old),
        ])
        .await;
        api.client()
            .upsert_rrset("host.example.com", kind, &[new.into()], 600)
            .await
            .unwrap();
        assert_eq!(api.values(), [new]);
        let state = api.state.lock().unwrap();
        let put = state.requests.iter().find(|r| r.method == "PUT").unwrap();
        assert_eq!(
            put.body,
            json!({"type": kind.as_str(), "name": "host.example.com", "content": new, "ttl": 600, "proxied": false})
        );
    }
}

#[tokio::test]
async fn api_failures_and_timeouts_do_not_expose_response_content() {
    for (status, body, delay) in [
        (403, "dummy-api-token Authorization dummy-tsig-key-for-tests-only".into(), Duration::ZERO),
        (429, "rate limit dummy-api-token".into(), Duration::ZERO),
        (200, json!({"success": false, "errors": [{"code": 1000, "message": "dummy-api-token"}], "result": null}).to_string(), Duration::ZERO),
        (200, "{\"success\":\"dummy-api-token\"}".into(), Duration::ZERO),
        (200, "{}".into(), Duration::from_millis(200)),
    ] {
        let api = MockApi::start(Vec::new()).await;
        api.state.lock().unwrap().faults.insert(1, Fault {status, body, delay});
        let error = api.client_with_timeout(Duration::from_millis(50)).add_txt(NAME, "value", 300).await.unwrap_err();
        let text = format!("{error} {error:?}");
        assert!(!text.contains("dummy-api-token"));
        assert!(!text.contains("dummy-tsig"));
        assert!(!text.contains("Authorization"));
        assert!(api.values().is_empty());
    }
}

#[tokio::test]
async fn invalid_or_failed_later_pages_cause_no_writes() {
    for body in [
        json!({"success": true, "errors": [], "result": []}),
        json!({"success": true, "errors": [], "result": [], "result_info": {"page": 1, "total_pages": 2}}),
    ] {
        let api = MockApi::start(vec![
            record("1", NAME, "TXT", "\"value\""),
            record("2", NAME, "TXT", "\"value\""),
        ])
        .await;
        {
            let mut state = api.state.lock().unwrap();
            state.page_size = 1;
            state.faults.insert(
                2,
                Fault {
                    status: 200,
                    body: body.to_string(),
                    delay: Duration::ZERO,
                },
            );
        }
        assert!(
            api.client()
                .delete_record(NAME, DnsRecordKind::Txt, "value")
                .await
                .is_err()
        );
        assert_eq!(api.values().len(), 2);
        assert!(
            api.state
                .lock()
                .unwrap()
                .requests
                .iter()
                .all(|r| r.method == "GET")
        );
    }
}

#[tokio::test]
async fn cleanup_retry_after_partial_failure_keeps_other_values() {
    let api = MockApi::start(vec![
        record("a1", NAME, "TXT", "\"a\""),
        record("a2", NAME, "TXT", "\"a\""),
        record("b", NAME, "TXT", "\"b\""),
    ])
    .await;
    api.state.lock().unwrap().faults.insert(
        3,
        Fault {
            status: 503,
            body: "unavailable".into(),
            delay: Duration::ZERO,
        },
    );
    let client = api.client();
    assert!(
        client
            .delete_record(NAME, DnsRecordKind::Txt, "a")
            .await
            .is_err()
    );
    assert_eq!(api.values(), ["\"a\"", "\"b\""]);
    client
        .delete_record(NAME, DnsRecordKind::Txt, "a")
        .await
        .unwrap();
    assert_eq!(api.values(), ["\"b\""]);
}
