use fictionet::relay::observer::{Client, Envelope, Value};
use std::io::{self, ErrorKind};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

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

/// Watches the graph and optionally every sandbox's packets until `stop`.
/// Ready requires a snapshot for the watch id and a link for each packets id.
/// Returns packet rows received while `measuring` only if the observer outlived
/// the measurement. Set `stop` after measuring and before cancelling the world.
/// EOF, ended subscriptions and invalid replies before then fail the run.
/// Rows lag packets by up to one 100 ms tick, so the count is close, not exact.
pub fn watch_world(
    client: &mut Client,
    packets: bool,
    sandboxes: usize,
    stop: &AtomicBool,
    status: &Mutex<ObserverStatus>,
    measuring: &AtomicBool,
) -> io::Result<u64> {
    let result = (|| {
        let watch = client.request(r#"{"op":"watch"}"#)?;
        let mut graph_request = None;
        let mut graph_changed = false;
        let mut snapshot = false;
        let links = loop {
            let value = client.next_value()?.ok_or_else(|| {
                io::Error::new(ErrorKind::UnexpectedEof, "observer closed before graph")
            })?;
            if let Some(Envelope::Error(reason)) = value.envelope() {
                return Err(reply_error(&value, &reason));
            }
            let graph = if value.id == watch {
                match value.envelope() {
                    Some(Envelope::Event { name, data }) if name == "snapshot" => {
                        snapshot = true;
                        data
                    }
                    Some(Envelope::Event { name, .. }) if name == "node" || name == "edge" => {
                        if graph_request.is_none() {
                            graph_request = Some(client.request(r#"{"op":"graph"}"#)?);
                        } else {
                            graph_changed = true;
                        }
                        continue;
                    }
                    Some(Envelope::Event { name, .. }) if !value.end && name != "ended" => continue,
                    _ => return Err(reply_error(&value, "watch ended before graph")),
                }
            } else if Some(value.id) == graph_request && !value.binary && value.end {
                graph_request = None;
                std::str::from_utf8(&value.bytes)
                    .map_err(|_| reply_error(&value, "invalid graph text"))?
            } else {
                return Err(reply_error(&value, "invalid graph reply"));
            };
            let links = sandbox_links(graph);
            if snapshot && links.len() >= sandboxes {
                break links;
            }
            if graph_request.is_none() && graph_changed {
                graph_request = Some(client.request(r#"{"op":"graph"}"#)?);
                graph_changed = false;
            }
        };
        let mut subscriptions = vec![(watch, "snapshot", true)];
        if packets {
            for link in &links {
                let id =
                    client.request(&format!(r#"{{"op":"packets","link":"{link}","after":0}}"#))?;
                subscriptions.push((id, "link", false));
            }
        }
        if subscriptions.iter().all(|s| s.2) {
            *status.lock().unwrap() = ObserverStatus::Ready;
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
