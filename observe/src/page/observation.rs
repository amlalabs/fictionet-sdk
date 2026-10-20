use std::collections::BTreeMap;
use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::TcpStream;

use crate::{DashboardHandle, Envelope, Session, Value};

use super::http;

pub(super) const OPS: &[&str] = &[
    "world", "graph", "counters", "events", "link", "keylog", "watch", "packets", "packet", "pcap",
];

fn wall() -> Option<Duration> {
    SystemTime::now().duration_since(UNIX_EPOCH).ok()
}

fn observe_request(op: &str, query: &[(String, String)]) -> String {
    let mut map = serde_json::Map::new();
    for (k, v) in query {
        let value = if !v.is_empty() && v.len() < 16 && v.bytes().all(|b| b.is_ascii_digit()) {
            serde_json::Value::from(v.parse::<u64>().unwrap())
        } else {
            serde_json::Value::from(v.clone())
        };
        map.insert(k.clone(), value);
    }
    map.insert("op".into(), op.into());
    serde_json::Value::Object(map).to_string()
}

fn links(op: &str, query: &[(String, String)]) -> Option<Vec<String>> {
    if !matches!(op, "packets" | "pcap") {
        return None;
    }
    let (_, value) = query.iter().find(|(k, _)| k == "link")?;
    if !value.contains(',') {
        return None;
    }
    let mut links: Vec<_> = value
        .split(',')
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect();
    links.dedup();
    Some(links)
}

fn with_link(query: &[(String, String)], link: &str) -> Vec<(String, String)> {
    query
        .iter()
        .map(|(k, v)| (k.clone(), if k == "link" { link.into() } else { v.clone() }))
        .collect()
}

pub(super) async fn route(
    conn: &mut TcpStream,
    shared: &super::Shared,
    op: &str,
    query: &[(String, String)],
) -> io::Result<()> {
    let merged = links(op, query);
    if merged
        .as_ref()
        .is_some_and(|links| links.len() > 32 || links.is_empty())
    {
        return http::error(conn, 400, "name between one and 32 links").await;
    }
    if matches!(op, "watch" | "packets") {
        let Ok(_permit) = shared.streams.try_acquire() else {
            return http::error(conn, 503, "too many streams").await;
        };
        return stream(conn, &shared.page.dashboard, op, query, merged).await;
    }
    let mut session = shared.page.dashboard.session();
    if let Some(links) = merged {
        return merged_download(conn, &shared.page.dashboard, &links).await;
    }
    let values = session.request(1, &observe_request(op, query), Instant::now(), wall());
    let Some(value) = values.into_iter().next() else {
        return http::error(conn, 502, "the observer did not reply").await;
    };
    if !value.binary {
        let status = if matches!(value.envelope(), Some(Envelope::Error(_))) {
            404
        } else {
            200
        };
        return http::respond(conn, status, "application/json", &value.bytes).await;
    }
    let (kind, name) = if op == "pcap" {
        ("application/vnd.tcpdump.pcap", "fictionet-link.pcapng")
    } else {
        ("text/plain; charset=utf-8", "fictionet-keylog.txt")
    };
    http::headers(
        conn,
        200,
        kind,
        &format!("Content-Disposition: attachment; filename=\"{name}\"\r\n"),
    )
    .await?;
    http::write(conn, &value.bytes).await?;
    let mut done = value.end;
    while !done {
        let values = poll(&mut session).await;
        for value in values {
            http::write(conn, &value.bytes).await?;
            done |= value.end;
        }
    }
    Ok(())
}

async fn poll(session: &mut Session) -> Vec<Value> {
    if let Some(next) = session.next_poll() {
        tokio::time::sleep_until(next.into()).await;
    }
    session.poll(Instant::now(), wall())
}

async fn merged_download(
    conn: &mut TcpStream,
    handle: &DashboardHandle,
    links: &[String],
) -> io::Result<()> {
    // Prepare every bounded capture before sending a header. Each session
    // holds packet references and emits one chunk at a time, in section order.
    let mut captures = Vec::new();
    let mut failures = Vec::new();
    for link in links {
        let mut session = handle.session();
        let query = [("link".into(), link.clone())];
        let values = session.request(1, &observe_request("pcap", &query), Instant::now(), wall());
        for value in &values {
            if let Some(Envelope::Error(error)) = value.envelope() {
                failures.push(serde_json::json!({"link": link, "error": error}));
            }
        }
        captures.push((session, values));
    }
    if !failures.is_empty() {
        let names = failures
            .iter()
            .map(|v| v["link"].as_str().unwrap())
            .collect::<Vec<_>>()
            .join(", ");
        return http::json(
            conn,
            404,
            &serde_json::json!({
                "error": format!("no capture for {names}"), "links": failures,
            }),
        )
        .await;
    }
    http::headers(
        conn,
        200,
        "application/vnd.tcpdump.pcap",
        "Content-Disposition: attachment; filename=\"fictionet-links.pcapng\"\r\n",
    )
    .await?;
    for (mut session, mut values) in captures {
        loop {
            let mut done = false;
            for value in values {
                if !value.binary {
                    return Err(io::Error::other("the capture did not return binary data"));
                }
                http::write(conn, &value.bytes).await?;
                done |= value.end;
            }
            if done {
                break;
            }
            values = poll(&mut session).await;
        }
    }
    Ok(())
}

pub(super) async fn event(conn: &mut TcpStream, name: &str, data: &str) -> io::Result<()> {
    let mut wire = format!("event: {name}\n");
    for line in data.split(['\r', '\n']) {
        wire.push_str(&format!("data: {line}\n"));
    }
    wire.push('\n');
    http::write(conn, wire.as_bytes()).await
}

async fn stream(
    conn: &mut TcpStream,
    handle: &DashboardHandle,
    op: &str,
    query: &[(String, String)],
    links: Option<Vec<String>>,
) -> io::Result<()> {
    let mut session = handle.session();
    let mut open = BTreeMap::new();
    let merged = links.is_some();
    let mut values = Vec::new();
    if let Some(links) = links {
        for (index, link) in links.into_iter().enumerate() {
            let id = index as u32 + 1;
            values.extend(session.request(
                id,
                &observe_request(op, &with_link(query, &link)),
                Instant::now(),
                wall(),
            ));
            open.insert(id, link);
        }
    } else {
        values = session.request(1, &observe_request(op, query), Instant::now(), wall());
        open.insert(1, String::new());
    }
    http::headers(conn, 200, "text/event-stream", "").await?;
    let mut failed = false;
    let mut written = Instant::now();
    while !open.is_empty() {
        for value in values {
            let Some(link) = open.get(&value.id) else {
                continue;
            };
            let (name, data, error) = match value.envelope() {
                Some(Envelope::Event { name, data })
                    if !name.contains(['\r', '\n']) && name != "error" =>
                {
                    (name, data.to_owned(), false)
                }
                envelope => {
                    let error = match envelope {
                        Some(Envelope::Error(e)) => e,
                        _ => "the world sent an invalid stream event".into(),
                    };
                    (
                        if merged { "link_error" } else { "world_error" }.into(),
                        serde_json::json!({"error": error}).to_string(),
                        true,
                    )
                }
            };
            let data = if merged {
                match data.strip_prefix('{') {
                    Some(rest) if rest.trim_start().starts_with('}') => {
                        format!("{{\"link\":{}}}", serde_json::to_string(link)?)
                    }
                    Some(rest) => format!("{{\"link\":{},{rest}", serde_json::to_string(link)?),
                    None => data,
                }
            } else {
                data
            };
            event(
                conn,
                if merged && name == "end" {
                    "link_end"
                } else {
                    &name
                },
                &data,
            )
            .await?;
            written = Instant::now();
            failed |= error;
            if value.end || error {
                open.remove(&value.id);
            }
        }
        if open.is_empty() {
            break;
        }
        let next = session.next_poll().unwrap_or_else(Instant::now);
        let heartbeat = written + Duration::from_secs(5);
        tokio::time::sleep_until(next.min(heartbeat).into()).await;
        // A comment detects disconnects even when the world has no changes.
        if Instant::now() >= heartbeat {
            http::write(conn, b": ping\n\n").await?;
            written = Instant::now();
        }
        values = session.poll(Instant::now(), wall());
    }
    if merged {
        event(
            conn,
            "end",
            if failed {
                r#"{"reason":"every link finished"}"#
            } else {
                r#"{"reason":"every link closed"}"#
            },
        )
        .await?;
    }
    Ok(())
}
