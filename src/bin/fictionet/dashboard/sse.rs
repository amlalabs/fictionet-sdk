use std::io::{self, BufWriter, Write};
use std::net::TcpStream;
use std::time::Duration;

use fictionet::relay::observer::{Client, Envelope, Value};

use super::api::{observe_request, quote, with_link};

/// `data` (a JSON object) with `"link":"<link>"` added first.
pub(crate) fn add_link(data: &str, link: &str) -> String {
    match data.strip_prefix('{') {
        Some(rest) if rest.trim_start().starts_with('}') => format!("{{\"link\":{}}}", quote(link)),
        Some(rest) => format!("{{\"link\":{},{rest}", quote(link)),
        None => data.to_owned(),
    }
}

/// Relays the `packets` streams of several links as one stream of
/// server-sent events. Each event's data gets the link it is from. A link
/// whose stream ends sends `link_end`; the stream ends when all have.
pub(super) fn stream_merged(
    mut client: Client,
    conn: TcpStream,
    query: &[(String, String)],
    links: &[String],
) -> io::Result<()> {
    let mut open = std::collections::HashMap::new();
    for link in links {
        let id = client.request(&observe_request("packets", &with_link(query, link)))?;
        open.insert(id, link.clone());
    }
    let mut out = BufWriter::new(conn.try_clone()?);
    out.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\n\
          X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
    )?;
    out.flush()?;
    client.set_timeout(Some(Duration::from_secs(5)))?;
    while !open.is_empty() {
        match client.next_value() {
            Ok(Some(value)) => {
                let Some(link) = open.get(&value.id).cloned() else {
                    continue;
                };
                match event(&value) {
                    Some((name, data)) if name == "end" => {
                        write_event(&mut out, "link_end", &add_link(data, &link))?
                    }
                    Some((name, data)) => write_event(&mut out, &name, &add_link(data, &link))?,
                    None => {
                        let data = format!(
                            "{{\"error\":{}}}",
                            quote(&String::from_utf8_lossy(&value.bytes))
                        );
                        write_event(&mut out, "link_end", &add_link(&data, &link))?
                    }
                }
                out.flush()?;
                if value.end {
                    open.remove(&value.id);
                }
            }
            Ok(None) => break,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                out.write_all(b": ping\n\n")?;
                out.flush()?;
            }
            Err(e) => return Err(e),
        }
    }
    write_event(&mut out, "end", r#"{"reason":"every link closed"}"#)?;
    out.flush()
}

/// An event's name and original JSON data, ready for server-sent events.
pub(crate) fn event(value: &Value) -> Option<(String, &str)> {
    let Envelope::Event { name, data } = value.envelope()? else {
        return None;
    };
    if name.contains(['\r', '\n']) {
        return None;
    }
    Some((name, data))
}

fn write_event(out: &mut impl Write, name: &str, data: &str) -> io::Result<()> {
    writeln!(out, "event: {name}")?;
    for line in data.split(['\r', '\n']) {
        writeln!(out, "data: {line}")?;
    }
    writeln!(out)
}

/// Relays a stream as server-sent events until either side closes.
pub(super) fn stream(mut client: Client, conn: TcpStream) -> io::Result<()> {
    let mut out = BufWriter::new(conn.try_clone()?);
    out.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\n\
          X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
    )?;
    out.flush()?;
    // Wake now and then to send a comment, so a closed browser is noticed
    // even when the world has nothing to say.
    client.set_timeout(Some(Duration::from_secs(5)))?;
    loop {
        match client.next_value().or_else(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                Ok(None)
            } else {
                Err(e)
            }
        }) {
            Ok(Some(value)) => {
                match event(&value) {
                    Some((name, data)) => write_event(&mut out, &name, data)?,
                    None => write_event(&mut out, "error", &String::from_utf8_lossy(&value.bytes))?,
                }
                out.flush()?;
                if value.end {
                    return Ok(());
                }
            }
            Ok(None) => {
                write_event(&mut out, "end", r#"{"reason":"the world closed"}"#)?;
                return out.flush();
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                out.write_all(b": ping\n\n")?;
                out.flush()?;
            }
            Err(e) => return Err(e),
        }
    }
}
