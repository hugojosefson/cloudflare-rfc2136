use std::io::Write;
use std::process::{Command, Stdio};

use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::*;
use crate::test_support::{api::MockApi, config};

#[tokio::test]
#[ignore = "requires BIND nsupdate"]
async fn bind_nsupdate_preserves_txt_values_over_udp_and_tcp() {
    for tcp in [false, true] {
        let api = MockApi::start(Vec::new()).await;
        let cfg = Arc::new(config());
        let client = Arc::new(api.client());
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = udp.local_addr().unwrap();
        let listener = TcpListener::bind(address).await.unwrap();
        let udp_task = tokio::spawn(serve_udp(udp, cfg.clone(), client.clone()));
        let tcp_task = tokio::spawn(serve_tcp(listener, cfg.clone(), client));

        for (operation, expected_values, success) in [
            (
                "add _acme-challenge.example.com. 60 TXT \"a\"",
                vec!["\"a\""],
                true,
            ),
            (
                "add _acme-challenge.example.com. 60 TXT \"b\"",
                vec!["\"a\"", "\"b\""],
                true,
            ),
            (
                "add _acme-challenge.example.com. 60 TXT \"a\"",
                vec!["\"a\"", "\"b\""],
                true,
            ),
            (
                "delete _acme-challenge.example.com. TXT \"a\"",
                vec!["\"b\""],
                true,
            ),
            (
                "delete _acme-challenge.example.com. TXT \"a\"",
                vec!["\"b\""],
                true,
            ),
            (
                "delete _acme-challenge.example.com. TXT",
                vec!["\"b\""],
                false,
            ),
        ] {
            let input = format!(
                "server 127.0.0.1 {}\nzone example.com.\nkey hmac-sha256:test-key. {}\nupdate {operation}\nsend\n",
                address.port(),
                STANDARD.encode(&cfg.tsig_secret),
            );
            let output = tokio::task::spawn_blocking(move || {
                let mut command = Command::new("nsupdate");
                command.args(["-t", "3"]);
                if tcp {
                    command.arg("-v");
                }
                let mut child = command
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("BIND nsupdate must be installed");
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(input.as_bytes())
                    .unwrap();
                child.wait_with_output().unwrap()
            })
            .await
            .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.success(), success, "{operation}: {stderr}");
            if success {
                assert!(stderr.is_empty(), "{stderr}");
            } else {
                assert!(stderr.contains("REFUSED"), "{stderr}");
            }
            assert_eq!(api.values(), expected_values);
        }
        udp_task.abort();
        tcp_task.abort();
    }
}
