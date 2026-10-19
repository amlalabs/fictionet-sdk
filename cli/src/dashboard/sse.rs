//! Observer streams as SSE. `end` closes a stream normally; `link_end`
//! closes one merged link. A refusal sends `world_error` with an `error`
//! string, or `link_error` with `link` and `error` for a merged subscription.
//! Other merged links keep streaming. Receive failures send `world_error`
//! before returning the error. The browser treats `world_error` as terminal;
//! its local `error` event is reserved for transient connection drops.

use std::io::{self, BufWriter, Write};
use std::net::TcpStream;
use std::time::Duration;

use fictionet_observe::{Client, Envelope, Value};

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
/// whose stream ends sends `link_end`; a refusal sends `link_error`.
/// The stream ends when every subscription has ended or failed.
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
    let mut transport = Transport::new(client, conn)?;
    let mut failed = false;
    while !open.is_empty() {
        let Some(value) = transport.next_value()? else {
            return Ok(());
        };
        let Some(link) = open.get(&value.id) else {
            continue;
        };
        match event(&value) {
            Some((name, data)) if name == "end" => {
                transport.event("link_end", &add_link(data, link))?
            }
            Some((name, data)) => transport.event(&name, &add_link(data, link))?,
            None => {
                transport.event("link_error", &add_link(&error_data(&value), link))?;
                failed = true;
                open.remove(&value.id);
                continue;
            }
        }
        if value.end {
            open.remove(&value.id);
        }
    }
    transport.event(
        "end",
        if failed {
            r#"{"reason":"every link finished"}"#
        } else {
            r#"{"reason":"every link closed"}"#
        },
    )
}

/// A decoded refusal, or a diagnosis for a value that is not a stream event.
fn error_data(value: &Value) -> String {
    let error = match value.envelope() {
        Some(Envelope::Error(error)) => error,
        _ => "the world sent an invalid stream event".to_owned(),
    };
    format!("{{\"error\":{}}}", quote(&error))
}

/// An event's name and original JSON data, ready for server-sent events.
pub(crate) fn event(value: &Value) -> Option<(String, &str)> {
    let Envelope::Event { name, data } = value.envelope()? else {
        return None;
    };
    if name.contains(['\r', '\n']) || name == "error" {
        return None;
    }
    Some((name, data))
}

/// Shared SSE writing, terminal outcomes, receive timeouts, and idle heartbeats.
struct Transport {
    client: Client,
    out: BufWriter<TcpStream>,
}

impl Transport {
    /// Sends the response headers and sets the observer's receive timeout.
    fn new(client: Client, conn: TcpStream) -> io::Result<Self> {
        let mut out = BufWriter::new(conn.try_clone()?);
        out.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\n\
              X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        )?;
        out.flush()?;
        // Wake now and then to send a comment, so a closed browser is noticed
        // even when the world has nothing to say.
        client.set_timeout(Some(Duration::from_secs(5)))?;
        Ok(Self { client, out })
    }

    /// Receives a value, sending heartbeats while idle and terminal events on
    /// close or failure. Only a close between values is a normal end.
    fn next_value(&mut self) -> io::Result<Option<Value>> {
        loop {
            match self.client.next_value() {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    self.out.write_all(b": ping\n\n")?;
                    self.out.flush()?;
                }
                Ok(None) => {
                    self.event("end", r#"{"reason":"the world closed"}"#)?;
                    return Ok(None);
                }
                Err(e) => {
                    self.event(
                        "world_error",
                        &format!("{{\"error\":{}}}", quote(&e.to_string())),
                    )?;
                    return Err(e);
                }
                Ok(value) => return Ok(value),
            }
        }
    }

    /// Writes and flushes one SSE event.
    fn event(&mut self, name: &str, data: &str) -> io::Result<()> {
        writeln!(self.out, "event: {name}")?;
        for line in data.split(['\r', '\n']) {
            writeln!(self.out, "data: {line}")?;
        }
        writeln!(self.out)?;
        self.out.flush()
    }
}

/// Relays a stream as server-sent events until either side closes.
pub(super) fn stream(client: Client, conn: TcpStream) -> io::Result<()> {
    let mut transport = Transport::new(client, conn)?;
    while let Some(value) = transport.next_value()? {
        match event(&value) {
            Some((name, data)) => transport.event(&name, data)?,
            None => {
                transport.event("world_error", &error_data(&value))?;
                return Ok(());
            }
        }
        if value.end {
            return Ok(());
        }
    }
    Ok(())
}
