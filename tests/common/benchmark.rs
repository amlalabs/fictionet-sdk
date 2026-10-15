use fictionet::relay::observer::{Client, Envelope, Value};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Whether all subscriptions were acknowledged, or the observer failed.
#[derive(Debug, PartialEq, Eq)]
pub enum ObserverStatus {
    /// At least one subscription still needs its first reply.
    Waiting,
    /// Every subscription has acknowledged its request id.
    Ready,
    /// The observer stopped with this reason.
    Failed(String),
}

impl ObserverStatus {
    /// Fails the world's readiness wait when the observer cannot continue.
    pub fn ready(&self) -> io::Result<bool> {
        match self {
            Self::Waiting => Ok(false),
            Self::Ready => Ok(true),
            Self::Failed(reason) => Err(io::Error::other(reason.clone())),
        }
    }
}

/// The observer operations used by the benchmark, also scriptable in tests.
pub trait Observer {
    /// Sends a request and returns the id used to match its replies.
    fn request(&mut self, json: &str) -> io::Result<u32>;
    /// Reads a whole reply, or EOF when the session closes.
    fn next_value(&mut self) -> io::Result<Option<Value>>;
}

impl Observer for Client {
    fn request(&mut self, json: &str) -> io::Result<u32> {
        self.request(json)
    }

    fn next_value(&mut self) -> io::Result<Option<Value>> {
        self.next_value()
    }
}

/// Watches the graph and optionally every sandbox's packets until `stop`.
/// Ready requires a snapshot for the watch id and a link for each packets id.
/// Returns packet rows received while `measuring` only if the observer outlived
/// the measurement. Set `stop` after measuring and before cancelling the world.
/// EOF, ended subscriptions and invalid replies before then fail the run.
/// Rows lag packets by up to one 100 ms tick, so the count is close, not exact.
pub fn watch_world(
    client: &mut impl Observer,
    packets: bool,
    sandboxes: usize,
    stop: &AtomicBool,
    status: &Mutex<ObserverStatus>,
    measuring: &AtomicBool,
) -> io::Result<u64> {
    let result = (|| {
        // Wait until every sandbox has a link in the graph.
        let links = loop {
            let id = client.request(r#"{"op":"graph"}"#)?;
            let graph = client.next_value()?.ok_or_else(|| {
                io::Error::new(ErrorKind::UnexpectedEof, "observer closed before graph")
            })?;
            if graph.id != id || graph.binary {
                return Err(reply_error(&graph, "invalid graph reply"));
            }
            if let Some(Envelope::Error(reason)) = graph.envelope() {
                return Err(reply_error(&graph, &reason));
            }
            let links = sandbox_links(&String::from_utf8_lossy(&graph.bytes));
            if links.len() >= sandboxes {
                break links;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let watch = client.request(r#"{"op":"watch"}"#)?;
        let mut subscriptions = vec![(watch, "snapshot", false)];
        if packets {
            for link in &links {
                let id =
                    client.request(&format!(r#"{{"op":"packets","link":"{link}","after":0}}"#))?;
                subscriptions.push((id, "link", false));
            }
        }
        let mut rows = 0;
        while !stop.load(Ordering::Acquire) {
            let value = client.next_value();
            // Cancellation may close a read that was already waiting.
            if stop.load(Ordering::Acquire) {
                break;
            }
            let v = match value {
                Ok(Some(v)) => v,
                Ok(None) => {
                    return Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "observer closed during measurement",
                    ));
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    continue;
                }
                Err(e) => return Err(e),
            };
            let name = match v.envelope() {
                Some(Envelope::Event { name, .. }) => name,
                Some(Envelope::Error(reason)) => return Err(reply_error(&v, &reason)),
                None => return Err(reply_error(&v, "invalid event envelope")),
            };
            let Some((_, first, acknowledged)) = subscriptions.iter_mut().find(|s| s.0 == v.id)
            else {
                return Err(reply_error(&v, "unknown subscription id"));
            };
            if v.end || matches!(name.as_str(), "end" | "ended") {
                return Err(reply_error(&v, "subscription ended during measurement"));
            }
            if !*acknowledged {
                if name != *first {
                    return Err(reply_error(&v, &format!("expected {first} as first reply")));
                }
                *acknowledged = true;
                if subscriptions.iter().all(|s| s.2) {
                    *status.lock().unwrap() = ObserverStatus::Ready;
                }
            }
            if v.id != watch && name == "packet" && measuring.load(Ordering::Acquire) {
                rows += 1;
            }
        }
        if !status.lock().unwrap().ready()? {
            return Err(io::Error::other("observer stopped before ready"));
        }
        Ok(rows)
    })();
    if let Err(error) = &result {
        *status.lock().unwrap() = ObserverStatus::Failed(error.to_string());
    }
    result
}

fn reply_error(value: &Value, reason: &str) -> io::Error {
    io::Error::new(
        ErrorKind::InvalidData,
        format!(
            "observer reply {}: {reason}: {}",
            value.id,
            String::from_utf8_lossy(&value.bytes)
        ),
    )
}

/// The ids of the links that end at a sandbox, read from a graph's JSON.
fn sandbox_links(graph: &str) -> Vec<String> {
    // Nodes look like {"id":"s7","kind":"sandbox",...}, edges like
    // {"id":"e7","a":"t11","b":"s7",...}.
    let field = |obj: &str, key: &str| -> Option<String> {
        let at = obj.find(&format!("\"{key}\":\""))? + key.len() + 4;
        Some(obj[at..].split('"').next()?.to_string())
    };
    let objects: Vec<&str> = graph.split('{').collect();
    let sandboxes: Vec<String> = objects
        .iter()
        .filter(|o| o.contains(r#""kind":"sandbox""#))
        .filter_map(|o| field(o, "id"))
        .collect();
    objects
        .iter()
        .filter(|o| o.starts_with(r#""id":"e"#))
        .filter(|o| {
            [field(o, "a"), field(o, "b")]
                .iter()
                .flatten()
                .any(|end| sandboxes.contains(end))
        })
        .filter_map(|o| field(o, "id"))
        .collect()
}

/// Fetches one proxy response, requiring EOF, the expected status and exact framing.
/// Returns the body. I/O errors and invalid responses panic before a timing is used.
pub fn fetch(addr: SocketAddr, host: &str, auth: &str, expected_status: u16) -> Vec<u8> {
    let mut s = TcpStream::connect(addr)
        .unwrap_or_else(|error| panic!("connect to proxy for {host}: {error}"));
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(s, "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: {auth}\r\nConnection: close\r\n\r\n")
        .unwrap_or_else(|error| panic!("write proxy request for {host}: {error}"));
    let mut out = Vec::new();
    s.read_to_end(&mut out)
        .unwrap_or_else(|error| panic!("read proxy response for {host}: {error}"));
    response_body(&out, expected_status).to_vec()
}

// These workloads use one Content-Length response. Reject other framing, including
// duplicate lengths, rather than guessing where a successful transfer ends.
fn response_body(bytes: &[u8], expected_status: u16) -> &[u8] {
    let end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("complete HTTP response head");
    let head = std::str::from_utf8(&bytes[..end]).expect("HTTP response head text");
    let body = &bytes[end + 4..];
    let mut lines = head.split("\r\n");
    let mut status = lines.next().unwrap().splitn(3, ' ');
    assert_eq!(status.next(), Some("HTTP/1.1"), "HTTP version");
    assert_eq!(
        status.next().expect("HTTP status code"),
        expected_status.to_string(),
        "HTTP status"
    );
    let reason = status.next().expect("HTTP status reason");
    assert!(
        reason.bytes().all(|b| b == b'\t' || (32..127).contains(&b)),
        "HTTP status reason"
    );
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').expect("HTTP header");
        assert!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)),
            "HTTP header name"
        );
        assert!(
            value.bytes().all(|b| b == b'\t' || (32..127).contains(&b)),
            "HTTP header value"
        );
        assert!(
            !name.eq_ignore_ascii_case("transfer-encoding"),
            "proxy benchmark requires Content-Length framing"
        );
        if name.eq_ignore_ascii_case("content-length") {
            assert!(length.is_none(), "duplicate Content-Length");
            let value = value.trim_matches([' ', '\t']);
            assert!(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                "invalid Content-Length"
            );
            length = Some(value.parse::<usize>().expect("Content-Length in range"));
        }
    }
    assert_eq!(
        body.len(),
        length.expect("missing Content-Length"),
        "HTTP body length"
    );
    body
}
