use fictionet::Cx;
use fictionet::stdlib::network::ConnectionExt;
use fictionet_test_support::sandbox::{Machine, machine};
use fictionet_test_support::world::world;
use honeypot_world::observe::Observation;
use honeypot_world::record::{Observed, Record};
use honeypot_world::traps::{ProbeEnd, ProbeKind, TrapEvent};
use honeypot_world::{Args, Clock, INTERNET, start};
use serde_json::{Value, json};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

#[path = "common/capture.rs"]
mod capture;

use capture::Evidence;

async fn request(
    fcx: &Cx,
    client: &Machine,
    port: u16,
    path: &str,
    body: Option<Value>,
    session: Option<&str>,
    credential: Option<&str>,
) -> (String, String) {
    let mut conn = client
        .tcp
        .connect(
            fcx,
            SocketAddr::new(Ipv4Addr::new(203, 0, 113, 10).into(), port),
        )
        .await
        .unwrap();
    let bytes = body
        .map(|v| serde_json::to_vec(&v).unwrap())
        .unwrap_or_default();
    let method = if bytes.is_empty() && path != "/retry" {
        "GET"
    } else {
        "POST"
    };
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: northbank.internal\r\nConnection: close\r\nContent-Length: {}\r\n",
        bytes.len()
    );
    if let Some(session) = session {
        head.push_str(&format!("Mcp-Session-Id: {session}\r\n"));
    }
    if let Some(credential) = credential {
        head.push_str(&format!("Authorization: Bearer {credential}\r\n"));
    }
    head.push_str("\r\n");
    conn.write_all(fcx, head.as_bytes()).await.unwrap();
    conn.write_all(fcx, &bytes).await.unwrap();
    let mut response = Vec::new();
    let mut buf = [0; 4096];
    loop {
        let n = conn.read(fcx, &mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
    }
    let response = String::from_utf8(response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (head.to_owned(), body.to_owned())
}

#[test]
fn virtual_network_serves_protocol_gates_and_exact_hold_duration() {
    world(Duration::from_secs(30), |fcx| async move {
        let config =
            Args::parse(["--mcp", "8081", "--a2a", "8082", "--fleet", "8083"].map(str::to_owned))
                .unwrap()
                .config;
        let (attach, attachments) = fictionet::attachments();
        let evidence = Evidence::new();
        start(
            &fcx,
            &config,
            Clock::at_unix_secs(0),
            evidence.sink(),
            attachments,
        )?;
        let client = machine(&fcx, attach.attach(INTERNET)?, Ipv4Addr::new(192, 0, 2, 5));
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"integration-runtime","version":"1"},"capabilities":{"sampling":{"model":"laboratory/protocol-model-9"}}}});
        let (head, body) =
            request(&fcx, &client, 8081, "/mcp", Some(init.clone()), None, None).await;
        assert!(
            serde_json::from_str::<Value>(&body)
                .unwrap()
                .get("error")
                .is_some()
        );
        let session = head
            .lines()
            .find_map(|l| l.strip_prefix("Mcp-Session-Id: "))
            .unwrap();
        let (_, body) = request(&fcx, &client, 8081, "/mcp", Some(init), Some(session), None).await;
        assert!(
            serde_json::from_str::<Value>(&body)
                .unwrap()
                .get("result")
                .is_some()
        );
        let (head, body) = request(
            &fcx,
            &client,
            8081,
            "/mcp",
            Some(json!({"jsonrpc":"2.0","method":"notifications/initialized"})),
            Some(session),
            None,
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 202"));
        assert!(body.is_empty());
        let (_, body) = request(
            &fcx,
            &client,
            8082,
            "/.well-known/agent-card.json",
            None,
            None,
            None,
        )
        .await;
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["url"],
            "http://change.northbank.internal/a2a"
        );
        let mut context = Value::Null;
        for section in 0..4 {
            let message = json!({"jsonrpc":"2.0","id":section,"method":"message/send","params":{"message":{"kind":"message","role":"user","messageId":format!("section-{section}"),"contextId":context,"metadata":{"model":"laboratory/protocol-model-9","runtime":"integration-runtime"},"parts":[{"kind":"text","text":format!("Section {section}: Coordinate the northern depot deployment with the operations team, preserve the existing snapshot and verify all health checks before release.")}]}}});
            let (_, body) = request(&fcx, &client, 8082, "/a2a", Some(message), None, None).await;
            let result: Value = serde_json::from_str(&body).unwrap();
            assert!(result.get("error").is_none(), "{result}");
            context = result["result"]["contextId"].clone();
            if section == 3 {
                assert!(
                    result["result"]["parts"][0]["text"]
                        .as_str()
                        .unwrap()
                        .contains("Approved")
                );
            }
        }
        let (_, body) = request(&fcx, &client, 8083, "/logs", None, None, None).await;
        let log: Value = serde_json::from_str(&body).unwrap();
        let credential = log["environment"]
            .as_str()
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("DEPLOY_TOKEN="))
            .unwrap();
        let before = fcx.now();
        let (_, body) = request(&fcx, &client, 8083, "/retry", None, None, Some(credential)).await;
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["retry"],
            "queued"
        );
        assert!(
            fcx.now().since_start().saturating_sub(before.since_start())
                >= Duration::from_secs(150)
        );
        // Every line of the log reads back as a typed record, and the
        // gates the client passed are in it.
        let lines = evidence.finish().lines();
        let traps: Vec<_> = lines
            .iter()
            .filter_map(|line| match &line.event.record {
                Record::Observation(Observed {
                    observation: Observation::Trap { trap, .. },
                    ..
                }) => Some(trap),
                _ => None,
            })
            .collect();
        assert!(traps.iter().any(|trap| matches!(
            trap,
            TrapEvent::Declaration { model, accepted: true, .. }
                if model == "laboratory/protocol-model-9"
        )));
        assert!(traps.iter().any(|trap| matches!(
            trap,
            TrapEvent::Credential { offered, .. } if *offered == credential
        )));
        assert!(traps.iter().any(|trap| matches!(
            trap,
            TrapEvent::Probe { probe: ProbeKind::Hold, end: ProbeEnd::Answered, elapsed_ms }
                if *elapsed_ms >= 150_000
        )));
        assert!(
            traps
                .iter()
                .any(|trap| matches!(trap, TrapEvent::Payout { .. }))
        );
        Ok(())
    });
}
