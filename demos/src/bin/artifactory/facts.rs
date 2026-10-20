use artifactory_world::{
    facts::{Door, MAX_DOOR_JSON_BYTES, MAX_REQUEST_JSON_BYTES, Request},
    inventory::{Entry, EntryKind, FolderAdded, Inventory, MAX_INVENTORY_JSON_BYTES, Origin},
};
use fictionet::{
    events::{Interest, Loss, Observation, Observer, Stamp, Stream},
    time::Instant,
};
use fictionet_observe::page::{PublishError, StateLimits, StateTopic};
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, mpsc, oneshot};

const ROWS: usize = 4096;
const PAGE_ROWS: usize = 512;
const PUBLISH_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Traffic {
    Setup,
    Agent,
    Other,
    After,
}

#[derive(Clone, Debug, Serialize)]
pub struct Tagged<T> {
    pub step: &'static str,
    pub at: f64,
    pub traffic: Traffic,
    pub row: T,
}

#[derive(Clone, Debug, Serialize)]
pub struct Rows<T> {
    pub rows: VecDeque<Tagged<T>>,
    pub dropped: u64,
    pub lost: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Waiting,
    Running,
    Done,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
pub struct StoryStep {
    pub title: &'static str,
    pub command: String,
    pub state: Status,
    pub exit: Option<i32>,
    pub requests: Vec<u64>,
    pub doors: Vec<u64>,
}

#[derive(Clone)]
pub struct Snapshot {
    pub destinations: &'static [&'static str],
    pub step: &'static str,
    pub at: Instant,
    pub requests: VecDeque<Tagged<Request>>,
    pub doors: VecDeque<Tagged<Door>>,
    pub changes: VecDeque<Tagged<FolderAdded>>,
    pub inventory: Inventory,
    pub story: Vec<StoryStep>,
    pub dropped: u64,
    pub requests_dropped: u64,
    pub doors_dropped: u64,
    pub lost: u64,
    pub publication_error: Option<String>,
    dirty: bool,
}

#[derive(Clone)]
pub struct Topics {
    pub inventory: StateTopic<Inventory>,
    pub requests: StateTopic<Rows<Request>>,
    pub doors: StateTopic<Rows<Door>>,
    pub story: StateTopic<Vec<StoryStep>>,
    pub other: StateTopic<Vec<Tagged<Door>>>,
}

pub struct Facts {
    pub state: Mutex<Snapshot>,
    pub changed: Notify,
    pub topics: Topics,
}

impl Facts {
    pub fn new(inventory: Inventory) -> Self {
        // Each row has 512 bytes for its tag, separators and collection counts.
        let limits = |max_bytes| StateLimits {
            max_bytes,
            deltas: 0,
        };
        let topics = Topics {
            inventory: StateTopic::new(StateLimits {
                max_bytes: MAX_INVENTORY_JSON_BYTES,
                deltas: 64,
            }),
            requests: StateTopic::new(limits(PAGE_ROWS * (MAX_REQUEST_JSON_BYTES + 512))),
            doors: StateTopic::new(limits(PAGE_ROWS * (MAX_DOOR_JSON_BYTES + 512))),
            // Retained row references use at most 2 * ROWS * 21 bytes. Commands
            // and titles come from the fixed story and fit in the remainder.
            story: StateTopic::new(StateLimits::default()),
            other: StateTopic::new(limits(PAGE_ROWS * (MAX_DOOR_JSON_BYTES + 512))),
        };
        let story = super::story::steps(inventory.variant)
            .into_iter()
            .map(|s| StoryStep {
                title: s.name,
                command: s.command,
                state: Status::Waiting,
                exit: None,
                requests: vec![],
                doors: vec![],
            })
            .collect();
        let mut state = Snapshot {
            step: "setup",
            destinations: &[],
            at: Instant::ZERO,
            requests: VecDeque::new(),
            doors: VecDeque::new(),
            changes: VecDeque::new(),
            inventory,
            story,
            dropped: 0,
            requests_dropped: 0,
            doors_dropped: 0,
            lost: 0,
            publication_error: None,
            dirty: true,
        };
        let result = topics.inventory.publish(state.at, &state.inventory);
        state.record(result);
        let batch = Batch::take(&mut state).unwrap();
        state.record(topics.publish(batch));
        Self {
            state: Mutex::new(state),
            changed: Notify::new(),
            topics,
        }
    }
    pub fn phase(&self, step: &'static str, destinations: &'static [&'static str]) {
        let mut state = self.state.lock().unwrap();
        state.step = step;
        state.destinations = destinations;
        if let Some(row) = state.story.iter_mut().find(|s| s.title == step) {
            row.state = Status::Running;
        }
        state.dirty = true;
    }
    pub fn exit(&self, code: i32) {
        let mut state = self.state.lock().unwrap();
        let step = state.step;
        if let Some(row) = state.story.iter_mut().find(|s| s.title == step) {
            row.exit = Some(code);
        }
        state.dirty = true;
    }
    pub fn finish(&self, exit: Option<i32>, success: bool) {
        let mut state = self.state.lock().unwrap();
        let step = state.step;
        if let Some(row) = state.story.iter_mut().find(|s| s.title == step) {
            row.exit = exit.or(row.exit);
            row.state = if success {
                Status::Done
            } else {
                Status::Failed
            };
        }
        state.dirty = true;
    }
    pub fn inventory_changed(&self, at: Instant, change: &FolderAdded, inventory: &Inventory) {
        let mut state = self.state.lock().unwrap();
        state.at = at;
        state.inventory = inventory.clone();
        let step = state.step;
        state.dropped += keep(
            &mut state.changes,
            Tagged {
                step,
                at: at.since_start().as_secs_f64(),
                traffic: state_traffic(step, true),
                row: change.clone(),
            },
        );
        state.dirty = true;
        self.changed.notify_one();
    }
}
impl Snapshot {
    pub fn check_complete(&self) -> std::io::Result<()> {
        if let Some(error) = &self.publication_error {
            return Err(std::io::Error::other(error.clone()));
        }
        if self.dropped != 0 || self.lost != 0 {
            return Err(std::io::Error::other(format!(
                "facts incomplete: {} rows dropped, {} events lost",
                self.dropped, self.lost
            )));
        }
        Ok(())
    }
    fn record(&mut self, result: Result<u64, PublishError>) {
        if let Err(error) = result {
            self.publication_error = Some(error.to_string());
        }
    }
}
struct Batch {
    at: Instant,
    requests: Rows<Request>,
    doors: Rows<Door>,
    story: Vec<StoryStep>,
    changes: Vec<Tagged<FolderAdded>>,
}

impl Batch {
    fn take(state: &mut Snapshot) -> Option<Self> {
        if !std::mem::take(&mut state.dirty) {
            return None;
        }
        let requests = page_rows(&state.requests, state.requests_dropped, state.lost);
        let doors = page_rows(&state.doors, state.doors_dropped, state.lost);
        let mut story = state.story.clone();
        for step in &mut story {
            step.requests = state
                .requests
                .iter()
                .filter(|r| r.step == step.title && r.traffic == Traffic::Agent)
                .map(|r| r.row.seq)
                .collect();
            step.doors = state
                .doors
                .iter()
                .filter(|r| r.step == step.title && r.traffic == Traffic::Agent)
                .map(|r| r.row.seq)
                .collect();
        }
        Some(Self {
            at: state.at,
            requests,
            doors,
            story,
            changes: state.changes.iter().cloned().collect(),
        })
    }
}

fn page_rows<T: Clone>(rows: &VecDeque<Tagged<T>>, dropped: u64, lost: u64) -> Rows<T> {
    let omitted = rows.len().saturating_sub(PAGE_ROWS);
    Rows {
        rows: rows.iter().skip(omitted).cloned().collect(),
        dropped: dropped + omitted as u64,
        lost,
    }
}

impl Topics {
    fn publish(&self, batch: Batch) -> Result<u64, PublishError> {
        self.requests.publish(batch.at, &batch.requests)?;
        let other = batch
            .doors
            .rows
            .iter()
            .filter(|row| row.traffic == Traffic::Other)
            .cloned()
            .collect();
        self.other.publish(batch.at, &other)?;
        self.doors.publish(batch.at, &batch.doors)?;
        self.story.publish(batch.at, &batch.story)
    }
}

/// One worker serializes changed topics and acknowledges story boundaries.
pub struct Publisher {
    flush: mpsc::Sender<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Publisher {
    pub fn start(facts: Arc<Facts>) -> Self {
        let (flush, mut receiver) = mpsc::channel::<oneshot::Sender<()>>(1);
        let mut inventory = facts.state.lock().unwrap().inventory.clone();
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(PUBLISH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let ack = tokio::select! {
                    _ = interval.tick() => None,
                    request = receiver.recv() => match request {
                        Some(ack) => Some(ack),
                        None => break,
                    },
                };
                publish_changed(&facts, &mut inventory);
                if let Some(ack) = ack {
                    let _ = ack.send(());
                }
            }
        });
        Self { flush, task }
    }

    pub async fn flush(&self) -> std::io::Result<()> {
        let (send, received) = oneshot::channel();
        self.flush.send(send).await.map_err(std::io::Error::other)?;
        received.await.map_err(std::io::Error::other)
    }
}

impl Drop for Publisher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn publish_changed(facts: &Facts, inventory: &mut Inventory) {
    let Some(batch) = Batch::take(&mut facts.state.lock().unwrap()) else {
        return;
    };
    // Copy rows under the facts lock, then serialize without holding it.
    let result = (|| {
        for change in &batch.changes {
            if change.row.revision <= inventory.revision {
                continue;
            }
            let entries = &mut inventory.repositories[2].entries;
            entries.push(Entry {
                path: change.row.path.clone(),
                kind: EntryKind::Folder,
                origin: Origin::Reply,
            });
            let replies = entries.partition_point(|e| e.origin != Origin::Reply);
            entries[replies..].sort_by(|a, b| a.path.cmp(&b.path));
            inventory.revision = change.row.revision;
            let at = Instant::from_since_start(Duration::from_secs_f64(change.at));
            facts
                .topics
                .inventory
                .publish_with_delta(at, inventory, &change.row)?;
        }
        facts.topics.publish(batch)
    })();
    facts.state.lock().unwrap().record(result);
}

fn state_traffic(step: &str, own: bool) -> Traffic {
    match step {
        "setup" => Traffic::Setup,
        "after" => Traffic::After,
        _ if own => Traffic::Agent,
        _ => Traffic::Other,
    }
}

fn keep<T>(rows: &mut VecDeque<T>, row: T) -> u64 {
    let dropped = u64::from(rows.len() == ROWS);
    if dropped != 0 {
        rows.pop_front();
    }
    rows.push_back(row);
    dropped
}
impl Observer for Facts {
    fn enabled(&self, interest: Interest<'_>) -> bool {
        matches!(interest, Interest::Event(meta, _) if artifactory_world::events::LOGGED.contains(&meta.source))
    }
    fn observe(&self, stamp: Stamp, observation: Observation<'_>) {
        let Observation::Event(event) = observation else {
            return;
        };
        let mut state = self.state.lock().unwrap();
        state.at = stamp.at;
        let at = stamp.at.since_start().as_secs_f64();
        let step = state.step;
        let mut changed = false;
        if let Some(row) = Request::from_event(event) {
            let destination = row
                .host
                .clone()
                .or_else(|| event.conn.local.map(|addr| addr.ip().to_string()));
            let traffic = state_traffic(
                step,
                destination
                    .as_deref()
                    .is_some_and(|name| state.destinations.contains(&name)),
            );
            let dropped = keep(
                &mut state.requests,
                Tagged {
                    step,
                    at,
                    traffic,
                    row,
                },
            );
            state.requests_dropped += dropped;
            state.dropped += dropped;
            changed = true;
        }
        if let Some(row) = Door::from_event(event) {
            // A DNS query's address is the resolver, so its name takes precedence.
            let destination = row
                .name
                .clone()
                .or_else(|| row.addr.map(|addr| addr.to_string()));
            let traffic = state_traffic(
                step,
                destination
                    .as_deref()
                    .is_some_and(|name| state.destinations.contains(&name)),
            );
            let dropped = keep(
                &mut state.doors,
                Tagged {
                    step,
                    at,
                    traffic,
                    row,
                },
            );
            state.doors_dropped += dropped;
            state.dropped += dropped;
            changed = true;
        }
        if changed {
            state.dirty = true;
        }
        self.changed.notify_one();
    }
    fn lost(&self, loss: Loss) {
        if loss.stream == Stream::Events {
            let mut state = self.state.lock().unwrap();
            state.lost += loss.count;
            state.dirty = true;
            self.changed.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use artifactory_world::{packages::Variant, repository::Contents};
    use fictionet::events::Event;
    #[test]
    fn phases_and_overflow_stay_visible() {
        let facts = Facts::new(
            Contents::new(Variant::Missing, "", &[1; 32])
                .unwrap()
                .inventory(),
        );
        let event = Event::new("dns", "query")
            .field("name", "github.com")
            .field("answer", "nxdomain");
        let stamp = Stamp {
            stream: Stream::Events,
            seq: 0,
            at: Instant::ZERO,
        };
        for phase in ["setup", "lookup", "after"] {
            facts.phase(phase, &["github.com"]);
            facts.observe(stamp, Observation::Event(&event));
        }
        assert_eq!(
            facts
                .state
                .lock()
                .unwrap()
                .doors
                .iter()
                .map(|r| r.step)
                .collect::<Vec<_>>(),
            ["setup", "lookup", "after"]
        );
        for _ in 0..ROWS {
            facts.observe(stamp, Observation::Event(&event));
        }
        let state = facts.state.lock().unwrap();
        assert_eq!(state.doors.len(), ROWS);
        assert_eq!(state.dropped, 3);
    }

    #[test]
    fn unrelated_traffic_keeps_its_time_and_step() {
        let facts = Facts::new(
            Contents::new(Variant::Lookalike, "", &[1; 32])
                .unwrap()
                .inventory(),
        );
        facts.phase("Send public UDP", &["198.51.100.7"]);
        let stamp = Stamp {
            stream: Stream::Events,
            seq: 1,
            at: Instant::from_since_start(std::time::Duration::from_secs(7)),
        };
        for event in [
            Event::new("dns", "query")
                .field("name", "ntp.ubuntu.com")
                .field("answer", "nxdomain"),
            Event::new("net", "blocked")
                .field("dst", "198.51.100.7")
                .field("dst_port", 123u64)
                .field("protocol", 17u64)
                .field("why", "NoRoute"),
        ] {
            facts.observe(stamp, Observation::Event(&event));
        }
        let state = facts.state.lock().unwrap();
        assert_eq!(state.doors.len(), 2);
        assert_eq!(state.doors[0].traffic, Traffic::Other);
        assert_eq!(state.doors[1].traffic, Traffic::Agent);
        for row in &state.doors {
            assert_eq!(row.at, 7.0);
            assert_eq!(row.step, "Send public UDP");
        }
    }
    #[tokio::test]
    async fn bursts_publish_once_and_idle_flushes_do_not_publish() {
        let facts = Arc::new(Facts::new(
            Contents::new(Variant::Lookalike, "", &[1; 32])
                .unwrap()
                .inventory(),
        ));
        let publisher = Publisher::start(facts.clone());
        let event = Event::new("dns", "query")
            .field("name", "github.com")
            .field("answer", "nxdomain");
        let stamp = Stamp {
            stream: Stream::Events,
            seq: 1,
            at: Instant::ZERO,
        };
        for revision in 1..=3 {
            for _ in 0..1000 {
                facts.observe(stamp, Observation::Event(&event));
            }
            facts.phase("Look up GitHub", &["github.com"]);
            facts.exit(0);
            facts.finish(Some(0), true);
            assert_eq!(facts.topics.doors.revision(), revision);
            assert_eq!(facts.topics.requests.revision(), revision);
            assert_eq!(facts.topics.story.revision(), revision);
            publisher.flush().await.unwrap();
            assert_eq!(facts.topics.doors.revision(), revision + 1);
            assert_eq!(facts.topics.requests.revision(), revision + 1);
            assert_eq!(facts.topics.story.revision(), revision + 1);
            publisher.flush().await.unwrap();
            assert_eq!(facts.topics.doors.revision(), revision + 1);
        }
        assert_eq!(facts.state.lock().unwrap().doors.len(), 3000);
        facts.state.lock().unwrap().check_complete().unwrap();
    }

    #[test]
    fn page_retention_does_not_discard_gate_rows() {
        let facts = Facts::new(
            Contents::new(Variant::Normal, "", &[1; 32])
                .unwrap()
                .inventory(),
        );
        let stamp = Stamp {
            stream: Stream::Events,
            seq: 0,
            at: Instant::ZERO,
        };
        for seq in 0..=PAGE_ROWS {
            let mut event = Event::new("dns", "query")
                .field("name", "github.com")
                .field("answer", "nxdomain");
            event.seq = seq as u64;
            facts.observe(stamp, Observation::Event(&event));
        }
        let mut state = facts.state.lock().unwrap();
        let batch = Batch::take(&mut state).unwrap();
        assert_eq!(batch.doors.rows.len(), PAGE_ROWS);
        assert_eq!(batch.doors.dropped, 1);
        assert_eq!(batch.doors.rows.front().unwrap().row.seq, 1);
        assert_eq!(batch.doors.rows.back().unwrap().row.seq, PAGE_ROWS as u64);
        assert_eq!(state.doors.len(), PAGE_ROWS + 1);
        assert_eq!(state.dropped, 0);
        state.check_complete().unwrap();
    }

    #[test]
    fn inventory_bursts_keep_each_revision_and_sorted_replies() {
        let contents = Contents::new(Variant::Peer, "", &[1; 32]).unwrap();
        let mut published = contents.inventory();
        let facts = Arc::new(Facts::new(published.clone()));
        let mut next = published.clone();
        let replies = next.repositories[2].entries.len();
        for (index, path) in ["reply-z", "reply-a", "reply-m"].iter().enumerate() {
            next.revision = index as u64 + 1;
            next.repositories[2].entries.push(Entry {
                path: (*path).into(),
                kind: EntryKind::Folder,
                origin: Origin::Reply,
            });
            next.repositories[2].entries[replies..].sort_by(|a, b| a.path.cmp(&b.path));
            facts.inventory_changed(
                Instant::from_since_start(Duration::from_secs(index as u64 + 1)),
                &FolderAdded {
                    revision: next.revision,
                    path: (*path).into(),
                    sandbox: None,
                },
                &next,
            );
            assert_eq!(facts.topics.inventory.revision(), 1);
        }
        publish_changed(&facts, &mut published);
        assert_eq!(published, next);
        assert_eq!(facts.topics.inventory.revision(), 4);
        assert_eq!(facts.state.lock().unwrap().changes.len(), 3);
        publish_changed(&facts, &mut published);
        assert_eq!(facts.topics.inventory.revision(), 4);
        facts.state.lock().unwrap().check_complete().unwrap();
    }

    async fn topic(
        client: &fictionet_demo::kit::client::PageClient,
        name: &str,
    ) -> serde_json::Value {
        let response = client
            .request("GET", &format!("/api/state/{name}"), None, true)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        serde_json::from_slice(&response.body).unwrap()
    }

    #[tokio::test]
    async fn topics_publish_inventory_rows_and_story() {
        use artifactory_world::inventory::{Entry, EntryKind, Origin};
        use fictionet_demo::kit::client::PageClient;
        use fictionet_observe::{DashboardObserver, DashboardOptions, page::Page};

        let initial = Contents::new(Variant::Peer, "", &[1; 32])
            .unwrap()
            .inventory();
        let facts = Arc::new(Facts::new(initial.clone()));
        let publisher = Publisher::start(facts.clone());
        let dashboard = DashboardObserver::new(DashboardOptions::demo());
        let page = Page::new("Topic publishing", dashboard.handle())
            .custom("Packages", "", facts.topics.inventory.clone())
            .custom("Requests", "", facts.topics.requests.clone())
            .custom("Doors", "", facts.topics.doors.clone())
            .table("Story", facts.topics.story.clone(), vec![])
            .bind_loopback(0)
            .await
            .unwrap();
        let client = PageClient::from_url(page.url()).unwrap();
        client.bootstrap().await.unwrap();
        let inventory = topic(&client, "packages").await;
        assert_eq!(inventory["value"], serde_json::to_value(&initial).unwrap());
        assert_eq!(inventory["revision"], 1);
        assert_eq!(inventory["status"]["too_large"], false);
        assert_eq!(
            topic(&client, "requests").await["value"]["rows"],
            serde_json::json!([])
        );
        let waiting = topic(&client, "story").await;
        assert!(
            waiting["value"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["state"] == "waiting" && s["exit"].is_null())
        );

        let at = Instant::from_since_start(std::time::Duration::from_secs(3));
        let mut next = initial;
        next.revision = 1;
        next.repositories[2].entries.push(Entry {
            path: "reply".into(),
            kind: EntryKind::Folder,
            origin: Origin::Reply,
        });
        let change = FolderAdded {
            revision: 1,
            path: "reply".into(),
            sandbox: None,
        };
        facts.inventory_changed(at, &change, &next);
        publisher.flush().await.unwrap();
        let inventory = topic(&client, "packages").await;
        assert_eq!(inventory["revision"], 2);
        assert_eq!(inventory["at"], 3.0);
        assert_eq!(inventory["value"], serde_json::to_value(&next).unwrap());

        // The stream carries the change, not just a replacement snapshot.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (origin, token) = page.url().split_once("/#token=").unwrap();
        let authority = origin.strip_prefix("http://").unwrap();
        let mut stream = tokio::net::TcpStream::connect(authority).await.unwrap();
        stream.write_all(format!("GET /api/states/stream?topics=packages&after=packages:1 HTTP/1.1\r\nHost: {authority}\r\nOrigin: {origin}\r\nAuthorization: Bearer {token}\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = String::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let mut buf = [0; 8192];
                let n = stream.read(&mut buf).await.unwrap();
                assert_ne!(n, 0);
                response.push_str(std::str::from_utf8(&buf[..n]).unwrap());
                if response.contains("\n\n") {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("\"delta\""), "{response}");
        assert!(
            response.contains(&serde_json::to_string(&change).unwrap()),
            "{response}"
        );

        facts.phase("Read peer messages", &[artifactory_world::REPOSITORY_NAME]);
        let mut event = Event::new("http", "request")
            .field("method", "GET")
            .field("host", artifactory_world::REPOSITORY_NAME)
            .field("path", "/simple/")
            .field("status", 200u64)
            .field("label", "index")
            .field("complete", true);
        event.seq = 42;
        facts.observe(
            Stamp {
                stream: Stream::Events,
                seq: 42,
                at,
            },
            Observation::Event(&event),
        );
        facts.exit(0);
        publisher.flush().await.unwrap();
        assert_eq!(
            topic(&client, "story").await["value"][2]["state"],
            "running"
        );
        facts.finish(Some(0), true);
        publisher.flush().await.unwrap();
        let story = topic(&client, "story").await;
        assert_eq!(story["value"][2]["state"], "done");
        assert_eq!(story["value"][2]["exit"], 0);
        assert_eq!(story["value"][2]["requests"], serde_json::json!([42]));
        assert_eq!(story["value"][2]["doors"], serde_json::json!([42]));
        let requests = topic(&client, "requests").await;
        assert_eq!(requests["value"]["rows"][0]["at"], 3.0);
        assert_eq!(requests["value"]["rows"][0]["traffic"], "agent");
        assert_eq!(requests["value"]["rows"][0]["step"], "Read peer messages");
        for _ in 0..ROWS {
            facts.observe(
                Stamp {
                    stream: Stream::Events,
                    seq: 42,
                    at,
                },
                Observation::Event(&event),
            );
        }
        publisher.flush().await.unwrap();
        assert_eq!(facts.state.lock().unwrap().requests.len(), ROWS);
        assert_eq!(facts.state.lock().unwrap().requests_dropped, 1);
        for name in ["requests", "doors"] {
            let snapshot = topic(&client, name).await;
            assert_eq!(
                snapshot["value"]["rows"].as_array().unwrap().len(),
                PAGE_ROWS
            );
            assert_eq!(snapshot["value"]["dropped"], ROWS + 1 - PAGE_ROWS);
            assert_eq!(snapshot["status"]["too_large"], false);
        }
        assert!(facts.state.lock().unwrap().publication_error.is_none());
    }
}
