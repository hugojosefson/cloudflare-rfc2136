use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

use crate::cloudflare::CloudflareClient;

#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub body: Value,
}

pub struct Fault {
    pub status: u16,
    pub body: String,
    pub delay: Duration,
}

pub struct State {
    pub records: Vec<Value>,
    pub requests: Vec<Request>,
    pub faults: BTreeMap<usize, Fault>,
    pub page_size: usize,
    pub include_unmatched: bool,
    next_id: usize,
}

pub struct MockApi {
    pub state: Arc<Mutex<State>>,
    pub url: String,
    task: JoinHandle<()>,
}

impl MockApi {
    pub async fn start(records: Vec<Value>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State {
            records,
            requests: Vec::new(),
            faults: BTreeMap::new(),
            page_size: 100,
            include_unmatched: false,
            next_id: 1000,
        }));
        let shared = state.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    connection = listener.accept() => {
                        let (stream, _) = connection.unwrap();
                        connections.spawn(serve(stream, shared.clone()));
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        result.unwrap().unwrap();
                    }
                }
            }
        });
        Self { state, url, task }
    }

    pub fn client(&self) -> CloudflareClient {
        self.client_with_timeout(Duration::from_secs(2))
    }

    pub fn client_with_timeout(&self, timeout: Duration) -> CloudflareClient {
        CloudflareClient::with_endpoint(
            "test-zone".into(),
            "dummy-api-token".into(),
            self.url.clone(),
            timeout,
        )
        .unwrap()
    }

    pub fn values(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .records
            .iter()
            .map(|r| r["content"].as_str().unwrap().to_string())
            .collect()
    }
}

impl Drop for MockApi {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn record(id: &str, name: &str, kind: &str, content: &str) -> Value {
    json!({"id": id, "name": name, "type": kind, "content": content, "ttl": 300, "proxied": false})
}

async fn serve(mut stream: TcpStream, state: Arc<Mutex<State>>) {
    let mut bytes = Vec::new();
    let end = loop {
        let mut buffer = [0; 4096];
        let read = stream.read(&mut buffer).await.unwrap();
        if read == 0 {
            return;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break end + 4;
        }
        assert!(bytes.len() < 65_536);
    };
    let header = String::from_utf8(bytes[..end].to_vec()).unwrap();
    let mut first_line = header.lines().next().unwrap().split_whitespace();
    let method = first_line.next().unwrap().to_string();
    let target = first_line.next().unwrap().to_string();
    let length = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        .unwrap_or(0);
    while bytes.len() < end + length {
        let mut buffer = [0; 4096];
        let read = stream.read(&mut buffer).await.unwrap();
        if read == 0 {
            return;
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    let body = if length == 0 {
        Value::Null
    } else {
        serde_json::from_slice(&bytes[end..end + length]).unwrap()
    };
    let (status, body, delay) = respond(
        &mut state.lock().unwrap(),
        Request {
            method,
            target,
            body,
        },
    );
    tokio::time::sleep(delay).await;
    let response = format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

fn respond(state: &mut State, request: Request) -> (u16, String, Duration) {
    state.requests.push(request.clone());
    if let Some(fault) = state.faults.remove(&state.requests.len()) {
        return (fault.status, fault.body, fault.delay);
    }
    let url = reqwest::Url::parse(&format!("http://localhost{}", request.target)).unwrap();
    let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    let mut envelope = json!({"success": true, "errors": [], "result": null});
    match request.method.as_str() {
        "GET" => {
            let page = query["page"].parse::<usize>().unwrap();
            let records: Vec<_> = state
                .records
                .iter()
                .filter(|record| {
                    state.include_unmatched
                        || (record["name"]
                            .as_str()
                            .unwrap()
                            .eq_ignore_ascii_case(&query["name"])
                            && record["type"] == query["type"])
                })
                .cloned()
                .collect();
            envelope["result"] = json!(
                records
                    .iter()
                    .skip((page - 1) * state.page_size)
                    .take(state.page_size)
                    .collect::<Vec<_>>()
            );
            envelope["result_info"] = json!({"page": page, "total_pages": records.len().div_ceil(state.page_size).max(1)});
        }
        "POST" => {
            state.next_id += 1;
            let mut record = request.body;
            record["id"] = json!(state.next_id.to_string());
            state.records.push(record.clone());
            envelope["result"] = record;
        }
        "PUT" => {
            let id = url.path_segments().unwrap().next_back().unwrap();
            let record = state
                .records
                .iter_mut()
                .find(|record| record["id"] == id)
                .unwrap();
            *record = request.body;
            record["id"] = json!(id);
            envelope["result"] = record.clone();
        }
        "DELETE" => {
            let id = url.path_segments().unwrap().next_back().unwrap();
            state.records.retain(|record| record["id"] != id);
            envelope["result"] = json!({"id": id});
        }
        _ => panic!("unsupported method"),
    }
    (200, envelope.to_string(), Duration::from_millis(5))
}
