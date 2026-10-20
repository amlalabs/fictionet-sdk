use std::collections::VecDeque;
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

/// Snapshot and delta retention bounds.
#[derive(Clone, Copy, Debug)]
pub struct StateLimits {
    /// Maximum serialized snapshot bytes and total retained delta bytes.
    pub max_bytes: usize,
    /// Maximum retained delta count. Zero keeps snapshots only.
    pub deltas: usize,
}

impl Default for StateLimits {
    fn default() -> Self {
        Self {
            max_bytes: 256 << 10,
            deltas: 64,
        }
    }
}

/// Persistent publication status, included with every snapshot and delta.
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
    /// The snapshot or delta exceeded the configured byte budget.
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

/// Executor-neutral state publication. Clones share one bounded snapshot and
/// delta ring; publishing never waits for subscribers or requires a runtime.
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
    deltas: VecDeque<Delta>,
    bytes: usize,
    status: StateStatus,
}
struct Delta {
    revision: u64,
    at: f64,
    value: String,
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
                    deltas: VecDeque::new(),
                    bytes: 0,
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
    /// Publishes a replacement snapshot, invalidating delta continuity.
    pub fn publish(&self, at: Instant, snapshot: &T) -> Result<u64, PublishError> {
        self.publish_bytes(at, snapshot, None)
    }

    /// Publishes one snapshot and its delta from the preceding revision.
    /// The delta's application semantics belong to the custom panel.
    pub fn publish_with_delta<D: Serialize>(
        &self,
        at: Instant,
        snapshot: &T,
        delta: &D,
    ) -> Result<u64, PublishError> {
        let delta = serde_json::to_string(delta).map_err(PublishError::Serialize)?;
        self.publish_bytes(at, snapshot, Some(delta))
    }

    fn publish_bytes(
        &self,
        at: Instant,
        snapshot: &T,
        delta: Option<String>,
    ) -> Result<u64, PublishError> {
        let value = serde_json::to_string(snapshot).map_err(PublishError::Serialize)?;
        let inner = &self.topic.0;
        let mut state = inner.state.lock();
        if value.len() > inner.limits.max_bytes
            || delta
                .as_ref()
                .is_some_and(|d| d.len() > inner.limits.max_bytes)
        {
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
        if let Some(value) = delta.filter(|_| inner.limits.deltas > 0) {
            state.bytes += value.len();
            let at = state.at;
            state.deltas.push_back(Delta {
                revision,
                at,
                value,
            });
            while state.deltas.len() > inner.limits.deltas || state.bytes > inner.limits.max_bytes {
                state.bytes -= state.deltas.pop_front().unwrap().value.len();
            }
        } else {
            state.deltas.clear();
            state.bytes = 0;
        }
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

    fn since(&self, after: Option<u64>) -> (u64, Vec<(&'static str, String)>) {
        let state = self.0.state.lock();
        let snapshot = || (state.revision, vec![("snapshot", state.snapshot())]);
        let Some(after) = after else {
            return snapshot();
        };
        if after > state.revision {
            return snapshot();
        }
        if after == state.revision {
            return (state.revision, vec![]);
        }
        if !state
            .deltas
            .front()
            .is_some_and(|d| d.revision <= after.saturating_add(1))
        {
            return snapshot();
        }
        let too_large = state.status.too_large;
        let values = state
            .deltas
            .iter()
            .filter(|d| d.revision > after)
            .map(|d| {
                let data = format!(
                    "{{\"revision\":{},\"at\":{},\"delta\":{},\"status\":{{\"too_large\":{}}}}}",
                    d.revision, d.at, d.value, too_large
                );
                ("delta", data)
            })
            .collect();
        (state.revision, values)
    }
}

/// Most topics one stream may carry.
pub(super) const MAX_STREAM_TOPICS: usize = 64;

/// Streams several topics on one connection, so a page needs one connection
/// for all of its state. Each topic first gets its snapshot, or the deltas
/// after its cursor, then every change. Every event names its topic.
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
            let (revision, values) = topic.since(cursors[i]);
            cursors[i] = Some(revision);
            for (name, data) in values {
                let id = serde_json::to_string(id).map_err(io::Error::other)?;
                observation::event(conn, name, &format!("{{\"topic\":{id},{}", &data[1..])).await?;
            }
        }
        if closing {
            return observation::end(conn).await;
        }
        tokio::select! {
            biased;
            () = async { let _ = stopping.wait_for(|stopped| *stopped).await; } => closing = true,
            () = changed.notified() => {}
            () = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                http::write(conn, b": ping\n\n").await?;
            }
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
    fn snapshots_replace_missing_history_and_keep_rejected_values() {
        let topic = StateTopic::new(StateLimits {
            max_bytes: 16,
            deltas: 2,
        });
        topic.publish(at(), &1).unwrap();
        topic.publish_with_delta(at(), &2, &1).unwrap();
        topic.publish_with_delta(at(), &3, &1).unwrap();
        let (_, values) = topic.topic.since(Some(1));
        assert_eq!(values.len(), 2);
        assert!(values.iter().all(|(name, _)| *name == "delta"));
        topic.publish_with_delta(at(), &4, &1).unwrap();
        assert_eq!(topic.topic.since(Some(1)).1[0].0, "snapshot");
        assert!(topic.topic.since(Some(4)).1.is_empty());
        assert!(matches!(
            topic.publish_with_delta(at(), &5, &"x".repeat(17)),
            Err(PublishError::TooLarge)
        ));
        let value: Snapshot<u32> = serde_json::from_str(&topic.topic.snapshot()).unwrap();
        assert_eq!(value.revision, 4);
        assert_eq!(value.value, Some(4));
        assert!(value.status.too_large);
        topic.publish(at(), &6).unwrap();
        assert!(topic.topic.0.state.lock().status.too_large);
        assert_eq!(topic.topic.since(Some(4)).1[0].0, "snapshot");
        topic.publish_with_delta(at(), &7, &1).unwrap();
        assert_eq!(topic.topic.since(Some(5)).1[0].0, "delta");
    }

    #[test]
    fn publishers_do_not_wait_for_subscribers_or_need_a_runtime() {
        let topic = StateTopic::new(StateLimits {
            max_bytes: 16,
            deltas: 100,
        });
        let _stalled = topic.topic.0.changed.subscribe();
        for n in 0..10_000 {
            topic.publish_with_delta(at(), &n, &"12345678").unwrap();
        }
        assert_eq!(topic.revision(), 10_000);
        let state = topic.topic.0.state.lock();
        assert!(state.bytes <= 16);
        assert_eq!(state.deltas.len(), 1);
    }
}
