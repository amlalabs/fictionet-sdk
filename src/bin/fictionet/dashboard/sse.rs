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
    let mut transport = Transport::new(client, conn)?;
    while !open.is_empty() {
        let Some(value) = transport.next_value()? else {
            break;
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
                let data = format!(
                    "{{\"error\":{}}}",
                    quote(&String::from_utf8_lossy(&value.bytes))
                );
                transport.event("link_end", &add_link(&data, link))?
            }
        }
        if value.end {
            open.remove(&value.id);
        }
    }
    transport.event("end", r#"{"reason":"every link closed"}"#)
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

/// Shared SSE writing, receive timeouts, and idle heartbeats.
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

    /// Receives a value, sending heartbeats while the observer is idle.
    fn next_value(&mut self) -> io::Result<Option<Value>> {
        loop {
            match self.client.next_value() {
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    self.out.write_all(b": ping\n\n")?;
                    self.out.flush()?;
                }
                result => return result,
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
            None => transport.event("error", &String::from_utf8_lossy(&value.bytes))?,
        }
        if value.end {
            return Ok(());
        }
    }
    transport.event("end", r#"{"reason":"the world closed"}"#)
}
