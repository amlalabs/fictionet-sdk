use std::io;

use serde_json::{Value, json};
use tokio::net::TcpStream;

use super::{Label, LabelTarget, Shared, http, observation};

pub(super) async fn route(
    conn: &mut TcpStream,
    shared: &Shared,
    req: &http::Request,
) -> io::Result<()> {
    if req.query.len() > 1 || req.query.iter().any(|(name, _)| name != "host") {
        return http::error(conn, 400, "export accepts only an optional host").await;
    }
    let host = match req.query.first() {
        None => None,
        Some((_, name)) => match shared.page.hosts.iter().find(|host| &host.name == name) {
            Some(host) => Some(host),
            None => return http::error(conn, 404, "no such host").await,
        },
    };
    if req.path.ends_with("/packets") {
        let links: Vec<_> = shared
            .page
            .dashboard
            .0
            .collector
            .sandbox_links(host.map(|host| host.sandbox.as_str()))
            .into_iter()
            .map(|id| id.to_string())
            .collect();
        if links.is_empty() {
            return http::error(conn, 404, "this scope has no captured links").await;
        }
        return observation::route(conn, shared, "pcap", &[("link".into(), links.join(","))]).await;
    }
    let labels = shared
        .page
        .labels
        .as_ref()
        .map_or_else(Vec::new, |labels| labels.snapshot());
    let end = shared.page.dashboard.0.collector.events().last();
    http::headers(
        conn,
        200,
        "application/x-ndjson",
        "Content-Disposition: attachment; filename=\"fictionet-events.jsonl\"\r\n",
    )
    .await?;
    line(conn, &json!({"type":"export", "through":end, "host":host.map(|host| &host.name), "labels": labels})).await?;
    let mut after = 0;
    let mut lost = 0;
    loop {
        let batch: Value =
            serde_json::from_str(&crate::view::events(&shared.page.dashboard, after, 128))
                .map_err(io::Error::other)?;
        let dropped = batch["dropped"].as_u64().unwrap_or(0);
        if dropped > lost {
            line(conn, &json!({"type":"loss", "stream":"events", "count":dropped - lost, "scope":"run", "through":end})).await?;
            lost = dropped;
        }
        let events = batch["events"]
            .as_array()
            .ok_or_else(|| io::Error::other("invalid event batch"))?;
        if events.is_empty() {
            break;
        }
        for event in events {
            let seq = event["seq"]
                .as_u64()
                .ok_or_else(|| io::Error::other("event has no sequence"))?;
            if seq > end {
                return Ok(());
            }
            after = seq;
            if host.is_some_and(|host| {
                event["sandbox"]["name"].as_str() != Some(host.sandbox.as_str())
            }) {
                continue;
            }
            line(conn, &labeled(event.clone(), &labels)).await?;
        }
        if after >= end {
            break;
        }
    }
    Ok(())
}

pub(super) fn labeled(mut event: Value, labels: &[Label]) -> Value {
    let attached: Vec<_> = labels
        .iter()
        .filter(|label| match &label.target {
            LabelTarget::Event { seq } => event["seq"].as_u64() == Some(*seq),
            LabelTarget::Connection { id, local, peer } => {
                event["conn"].as_u64() == Some(*id)
                    && event["local"].as_str() == Some(local)
                    && event["peer"].as_str() == Some(peer)
            }
            LabelTarget::Flow { .. } => false,
        })
        .collect();
    event["labels"] = serde_json::to_value(attached).expect("labels are JSON");
    event
}

async fn line(conn: &mut TcpStream, value: &Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    http::write(conn, &bytes).await
}
