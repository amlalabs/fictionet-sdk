use std::io;

use serde_json::json;
use tokio::net::TcpStream;

use super::{Shared, http};

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
    let collector = &shared.page.dashboard.0.collector;
    let packets = req.path.ends_with("/packets");
    let sandbox = host.map(|host| host.sandbox.clone());
    let streams = if packets {
        let mut streams: Vec<_> = collector
            .sandbox_links(sandbox.as_deref())
            .into_iter()
            .map(fictionet::events::Stream::Packets)
            .collect();
        if streams.is_empty() {
            return http::error(conn, 404, "this scope has no captured links").await;
        }
        streams.push(fictionet::events::Stream::Keys);
        streams
    } else {
        vec![fictionet::events::Stream::Events]
    };
    let labels = shared
        .page
        .labels
        .as_ref()
        .map_or_else(Vec::new, |labels| labels.snapshot());
    let mut export = collector.export(&crate::export::Selection {
        streams,
        sandbox,
        labels: labels.clone(),
        wall: shared.page.dashboard.0.wall(),
        ..Default::default()
    });
    http::headers(
        conn,
        200,
        if packets {
            "application/vnd.tcpdump.pcap"
        } else {
            "application/x-ndjson"
        },
        if packets {
            "Content-Disposition: attachment; filename=\"fictionet-links.pcapng\"\r\n"
        } else {
            "Content-Disposition: attachment; filename=\"fictionet-events.jsonl\"\r\n"
        },
    )
    .await?;
    if packets {
        loop {
            let (bytes, last) = export.next_chunk();
            http::write(conn, &bytes).await?;
            if last {
                break;
            }
        }
    } else {
        let mut header = serde_json::to_vec(&json!({"type":"export", "through":export.through(), "host":host.map(|host| &host.name), "labels":labels})).map_err(io::Error::other)?;
        header.push(b'\n');
        http::write(conn, &header).await?;
        for line in export.jsonl() {
            http::write(conn, line.map_err(io::Error::other)?.as_bytes()).await?;
        }
    }
    Ok(())
}
