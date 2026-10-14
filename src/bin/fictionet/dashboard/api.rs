use std::io;
use std::net::TcpStream;
use std::time::Duration;

use fictionet::relay::observer::Client;

use super::respond;
use super::sse::{stream, stream_merged};

/// Ops whose replies are streams of `{"event":...,"data":...}` values.
const STREAMS: [&str; 2] = ["watch", "packets"];
/// Links one merged `packets` or `pcap` call may name.
const MAX_MERGED: usize = 32;

/// The observe request for `GET /api/<op>?...`: query values that are
/// whole numbers are sent as numbers, the rest as strings.
pub(crate) fn observe_request(op: &str, query: &[(String, String)]) -> String {
    let mut out = format!("{{\"op\":{}", quote(op));
    for (k, v) in query {
        let value = if !v.is_empty() && v.len() < 16 && v.bytes().all(|b| b.is_ascii_digit()) {
            v.clone()
        } else {
            quote(v)
        };
        out.push_str(&format!(",{}:{value}", quote(k)));
    }
    out.push('}');
    out
}

pub(super) fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Carries one API call to the world and its reply back.
pub(super) fn api(
    world: &str,
    mut conn: TcpStream,
    op: &str,
    query: &[(String, String)],
) -> io::Result<()> {
    let mut client = match Client::connect(world, "fictionet dashboard") {
        Ok(c) => c,
        Err(msg) => {
            let body = format!("{{\"error\":{}}}", quote(&msg));
            return respond(
                &mut conn,
                "502 Bad Gateway",
                "application/json",
                body.as_bytes(),
                "",
            );
        }
    };
    if let Some(links) = merged_links(op, query) {
        if links.len() > MAX_MERGED {
            return respond(
                &mut conn,
                "400 Bad Request",
                "application/json",
                br#"{"error":"too many links"}"#,
                "",
            );
        }
        return if op == "packets" {
            stream_merged(client, conn, query, &links)
        } else {
            pcap_merged(client, conn, &links)
        };
    }
    let request = observe_request(op, query);
    client.request(&request)?;
    if STREAMS.contains(&op) {
        return stream(client, conn);
    }
    client.set_timeout(Some(Duration::from_secs(30)))?;
    let Some(value) = client.next_value().or_else(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            Ok(None)
        } else {
            Err(e)
        }
    })?
    else {
        return respond(
            &mut conn,
            "502 Bad Gateway",
            "application/json",
            br#"{"error":"the world closed"}"#,
            "",
        );
    };
    if value.binary {
        let (kind, name) = match op {
            "pcap" => (
                "application/vnd.tcpdump.pcap",
                format!(
                    "fictionet-{}.pcapng",
                    query
                        .iter()
                        .find(|(k, _)| k == "link")
                        .map_or("link", |(_, v)| v)
                ),
            ),
            _ => ("text/plain; charset=utf-8", format!("fictionet-{op}.txt")),
        };
        let name: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
            .collect();
        let disposition = format!("Content-Disposition: attachment; filename=\"{name}\"\r\n");
        return respond(&mut conn, "200 OK", kind, &value.bytes, &disposition);
    }
    let status = if value.bytes.starts_with(br#"{"error":"#) {
        "404 Not Found"
    } else {
        "200 OK"
    };
    respond(&mut conn, status, "application/json", &value.bytes, "")
}

/// The links of a `packets` or `pcap` call that names more than one.
pub(super) fn merged_links(op: &str, query: &[(String, String)]) -> Option<Vec<String>> {
    if op != "packets" && op != "pcap" {
        return None;
    }
    let (_, value) = query.iter().find(|(k, _)| k == "link")?;
    if !value.contains(',') {
        return None;
    }
    let mut links: Vec<String> = value
        .split(',')
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    links.dedup();
    Some(links)
}

/// The query with `link` set to one link.
pub(super) fn with_link(query: &[(String, String)], link: &str) -> Vec<(String, String)> {
    query
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                if k == "link" {
                    link.to_owned()
                } else {
                    v.clone()
                },
            )
        })
        .collect()
}

/// The captures of several links, one pcapng section after another.
fn pcap_merged(mut client: Client, mut conn: TcpStream, links: &[String]) -> io::Result<()> {
    client.set_timeout(Some(Duration::from_secs(30)))?;
    let mut file = Vec::new();
    for link in links {
        let value = client.call(&observe_request(
            "pcap",
            &[("link".to_owned(), link.clone())],
        ))?;
        if value.binary {
            file.extend_from_slice(&value.bytes);
        }
    }
    if file.is_empty() {
        return respond(
            &mut conn,
            "404 Not Found",
            "application/json",
            br#"{"error":"nothing is watching those links"}"#,
            "",
        );
    }
    let disposition = "Content-Disposition: attachment; filename=\"fictionet-links.pcapng\"\r\n";
    respond(
        &mut conn,
        "200 OK",
        "application/vnd.tcpdump.pcap",
        &file,
        disposition,
    )
}
