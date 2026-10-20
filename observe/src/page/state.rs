use std::io;
use std::marker::PhantomData;
use std::sync::Arc;

use fictionet::sync::Mutex;
use fictionet::time::Instant;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::{Notify, watch};
use tokio::task::JoinSet;

use super::{http, observation};

/// The snapshot size bound.
#[derive(Clone, Copy, Debug)]
pub struct StateLimits {
    /// Maximum serialized snapshot bytes.
    pub max_bytes: usize,
}

impl Default for StateLimits {
    fn default() -> Self {
        Self {
            max_bytes: 256 << 10,
        }
    }
}

/// Persistent publication status, included with every snapshot.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateStatus {
    /// A publication exceeded its byte bound; the preceding value was kept.
    pub too_large: bool,
}

/// A full authoritative value. Time is run time in seconds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot<T> {
    /// Monotonically increasing revision; zero means no publication yet.
    pub revision: u64,
    /// Application time in the world, in seconds.
    pub at: f64,
    /// Latest snapshot, or null before the first publication.
    pub value: Option<T>,
    /// Persistent publication status.
    pub status: StateStatus,
}

/// A failed publication leaves the previous revision and value intact.
#[derive(Debug)]
pub enum PublishError {
    /// The snapshot exceeded the configured byte budget.
    TooLarge,
    /// Serialization failed.
    Serialize(serde_json::Error),
    /// The revision counter cannot advance.
    RevisionExhausted,
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("state publication exceeds StateLimits::max_bytes"),
            Self::Serialize(e) => e.fmt(f),
            Self::RevisionExhausted => f.write_str("state revision counter exhausted"),
        }
    }
}
impl std::error::Error for PublishError {}

/// Executor-neutral state publication. Clones share one bounded snapshot;
/// publishing never waits for subscribers or requires a runtime.
pub struct StateTopic<T> {
    pub(super) topic: Topic,
    marker: PhantomData<fn() -> T>,
}

impl<T> Clone for StateTopic<T> {
    fn clone(&self) -> Self {
        Self {
            topic: self.topic.clone(),
            marker: PhantomData,
        }
    }
}

#[derive(Clone)]
pub(super) struct Topic(Arc<Inner>);
struct Inner {
    limits: StateLimits,
    state: Mutex<State>,
    changed: watch::Sender<u64>,
}
struct State {
    revision: u64,
    at: f64,
    value: String,
    status: StateStatus,
}

impl<T> StateTopic<T> {
    /// Creates an initially unpublished topic. Zero bytes refuses publications.
    pub fn new(limits: StateLimits) -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            topic: Topic(Arc::new(Inner {
                limits,
                state: Mutex::new(State {
                    revision: 0,
                    at: 0.0,
                    value: "null".into(),
                    status: StateStatus::default(),
                }),
                changed,
            })),
            marker: PhantomData,
        }
    }

    /// Latest accepted revision. A rejected publication does not advance it.
    pub fn revision(&self) -> u64 {
        self.topic.0.state.lock().revision
    }
}

impl<T: Serialize> StateTopic<T> {
    /// Publishes a replacement snapshot.
    pub fn publish(&self, at: Instant, snapshot: &T) -> Result<u64, PublishError> {
        let value = serde_json::to_string(snapshot).map_err(PublishError::Serialize)?;
        let inner = &self.topic.0;
        let mut state = inner.state.lock();
        if value.len() > inner.limits.max_bytes {
            state.status.too_large = true;
            inner.changed.send_modify(|n| *n = n.wrapping_add(1));
            return Err(PublishError::TooLarge);
        }
        let revision = state
            .revision
            .checked_add(1)
            .ok_or(PublishError::RevisionExhausted)?;
        state.revision = revision;
        state.at = at.since_start().as_secs_f64();
        state.value = value;
        inner.changed.send_modify(|n| *n = n.wrapping_add(1));
        Ok(revision)
    }
}

impl State {
    fn snapshot(&self) -> String {
        format!(
            "{{\"revision\":{},\"at\":{},\"value\":{},\"status\":{{\"too_large\":{}}}}}",
            self.revision, self.at, self.value, self.status.too_large
        )
    }
}

impl Topic {
    pub fn snapshot(&self) -> String {
        self.0.state.lock().snapshot()
    }

    /// The snapshot a reader at revision `after` needs, or `None` when it
    /// holds the current revision.
    fn since(&self, after: Option<u64>) -> (u64, Option<String>) {
        let state = self.0.state.lock();
        let current = after == Some(state.revision);
        (state.revision, (!current).then(|| state.snapshot()))
    }
}

/// Most topics one stream may carry.
pub(super) const MAX_STREAM_TOPICS: usize = 64;

/// Streams several topics on one connection, so a page needs one connection
/// for all of its state. Each topic first gets its snapshot, unless its
/// cursor is current, then the snapshot after every change. Every event names
/// its topic.
pub(super) async fn stream(
    conn: &mut TcpStream,
    topics: &[(&str, &Topic, Option<u64>)],
    mut stopping: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    // Subscribe before the first read, so no change in between is lost. A
    // notification that arrives while events are written is kept as a permit.
    let changed = Arc::new(Notify::new());
    let mut watchers = JoinSet::new();
    for (_, topic, _) in topics {
        let mut receiver = topic.0.changed.subscribe();
        let changed = changed.clone();
        watchers.spawn(async move {
            while receiver.changed().await.is_ok() {
                changed.notify_one();
            }
        });
    }
    let mut closing = false;
    let mut cursors: Vec<Option<u64>> = topics.iter().map(|(_, _, after)| *after).collect();
    let mut too_large_shown = vec![false; topics.len()];
    http::headers(conn, 200, "text/event-stream", "").await?;
    loop {
        for (i, (id, topic, _)) in topics.iter().enumerate() {
            if !too_large_shown[i] && topic.0.state.lock().status.too_large {
                cursors[i] = None;
                too_large_shown[i] = true;
            }
            let (revision, snapshot) = topic.since(cursors[i]);
            cursors[i] = Some(revision);
            if let Some(data) = snapshot {
                let id = serde_json::to_string(id).map_err(io::Error::other)?;
                observation::event(
                    conn,
                    "snapshot",
                    &format!("{{\"topic\":{id},{}", &data[1..]),
                )
                .await?;
            }
        }
        if closing {
            return observation::end(conn).await;
        }
        let ping = tokio::select! {
            biased;
            () = async { let _ = stopping.wait_for(|stopped| *stopped).await; } => {
                closing = true;
                false
            }
            () = http::hangup(conn) => return Ok(()),
            () = changed.notified() => false,
            () = tokio::time::sleep(std::time::Duration::from_secs(5)) => true,
        };
        if ping {
            http::write(conn, b": ping\n\n").await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn at() -> Instant {
        Instant::from_since_start(std::time::Duration::from_secs(3))
    }

    #[test]
    fn readers_get_the_snapshot_unless_current_and_rejections_keep_the_value() {
        let topic = StateTopic::<u64>::new(StateLimits { max_bytes: 16 });
        assert_eq!(topic.topic.since(None).0, 0);
        assert!(topic.topic.since(Some(0)).1.is_none());
        topic.publish(at(), &1).unwrap();
        topic.publish(at(), &2).unwrap();
        for after in [None, Some(0), Some(1), Some(7)] {
            let (revision, snapshot) = topic.topic.since(after);
            assert_eq!(revision, 2);
            let value: Snapshot<u64> = serde_json::from_str(&snapshot.unwrap()).unwrap();
            assert_eq!(value.value, Some(2));
        }
        assert!(topic.topic.since(Some(2)).1.is_none());
        assert!(matches!(
            topic.publish(at(), &u64::MAX),
            Err(PublishError::TooLarge)
        ));
        let value: Snapshot<u64> = serde_json::from_str(&topic.topic.snapshot()).unwrap();
        assert_eq!(value.revision, 2);
        assert_eq!(value.value, Some(2));
        assert!(value.status.too_large);
        assert_eq!(value.at, 3.0);
        topic.publish(at(), &6).unwrap();
        assert!(topic.topic.0.state.lock().status.too_large);
        assert_eq!(topic.revision(), 3);
    }

    #[test]
    fn publishers_do_not_wait_for_subscribers_or_need_a_runtime() {
        let topic = StateTopic::new(StateLimits { max_bytes: 16 });
        let _stalled = topic.topic.0.changed.subscribe();
        for n in 0..10_000 {
            topic.publish(at(), &n).unwrap();
        }
        assert_eq!(topic.revision(), 10_000);
        assert_eq!(topic.topic.0.state.lock().value, "9999");
    }
}
