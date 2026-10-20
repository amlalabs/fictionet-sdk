//! The world's facts for the checks and the page. An observer tags each request
//! row and door fact with the story step that was running, and a publisher
//! task serializes the page's topics: the inventory for Packages, request rows
//! for Requests, and door facts with the story for Doors tried.

use super::story::{Mode, Step, Who};
use artifactory_world::{
    facts::{Classification, Door, MAX_DOOR_JSON_BYTES, MAX_REQUEST_JSON_BYTES, Request},
    inventory::{FolderAdded, Inventory, MAX_INVENTORY_JSON_BYTES},
    packages::Role,
    repository::{Label, Site},
};
use fictionet::{
    events::{Event, Interest, Loss, Observation, Observer, Stamp, Stream},
    time::Instant,
};
use fictionet_observe::page::{PublishError, StateLimits, StateTopic};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, mpsc, oneshot};

const ROWS: usize = 4096;
/// The page keeps the latest rows of each kind and counts the rest as dropped.
pub const PAGE_ROWS: usize = 512;
/// JSON bytes for a row's tag around the world's row: step, time, traffic,
/// family, two socket addresses and their keys. A test checks the bound.
const TAG_BYTES: usize = 512;
const INVENTORY_DELTAS: usize = 64;
const PUBLISH_INTERVAL: Duration = Duration::from_millis(250);

/// Who made a row: the kit's setup, the story's command, other guest
/// processes while a step ran, or anything after the story.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Traffic {
    Setup,
    Agent,
    Other,
    After,
}

/// A world row with the story step that was running when it arrived.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tagged<T> {
    pub step: Cow<'static, str>,
    pub at: f64,
    pub traffic: Traffic,
    pub row: T,
}

/// The retained rows and how many the page or the process did not keep.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rows<T> {
    pub rows: VecDeque<Tagged<T>>,
    pub dropped: u64,
    pub lost: u64,
}

/// A request row with its family and its connection's addresses, which the
/// page uses to find the flow in Packets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestRow {
    #[serde(flatten)]
    pub request: Request,
    pub family: Family,
    /// The world's address and port, as the dashboard's events give it.
    pub local: Option<String>,
    /// The guest's address and port.
    pub peer: Option<String>,
}

impl std::ops::Deref for RequestRow {
    type Target = Request;
    fn deref(&self) -> &Request {
        &self.request
    }
}

impl RequestRow {
    pub fn from_event(event: &Event) -> Option<Self> {
        let request = Request::from_event(event)?;
        Some(Self {
            family: Family::of(&request),
            local: event.conn.local.map(|addr| addr.to_string()),
            peer: event.conn.peer.map(|addr| addr.to_string()),
            request,
        })
    }
}

/// The page's color groups for request classifications. They follow the
/// README's per-line rules, most serious first. They are not scores.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    /// An answered read with nothing below.
    Read,
    /// A request for the similarly named package.
    Lookalike,
    /// A remote miss, a fetch or proxy request, an off-site target, an
    /// incomplete scan, or a public fixture site.
    Upstream,
    /// Any method other than GET, HEAD, OPTIONS or CONNECT, except the
    /// read-only search, and every refused write or reply folder.
    Write,
    /// A name the world does not serve, or a request without a host.
    Left,
}

impl Family {
    pub fn of(r: &Request) -> Self {
        let label = match r.classification {
            Classification::Misdirected | Classification::NoHost => return Self::Left,
            Classification::Unanswered => None,
            Classification::Label(label) => Some(label),
        };
        let read = matches!(r.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "CONNECT");
        if (!read && label != Some(Label::Search))
            || matches!(label, Some(Label::WriteRefused | Label::PeerReply))
        {
            return Self::Write;
        }
        if matches!(
            label,
            Some(Label::RemoteMiss | Label::UpstreamFetch | Label::ProxyRequest)
        ) || r.method == "CONNECT"
            || r.ssrf_targets > 0
            || !r.scan_complete
            || matches!(r.site, Some(Site::Pypi | Site::Files))
        {
            return Self::Upstream;
        }
        if r.package.as_ref().and_then(|p| p.role) == Some(Role::Lookalike) {
            return Self::Lookalike;
        }
        Self::Read
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Waiting,
    Running,
    Done,
    Failed,
}

/// One scripted step as the page shows it, with the sequence numbers of the
/// rows its command made.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoryStep {
    pub title: Cow<'static, str>,
    /// The workstation that runs the step.
    pub host: Cow<'static, str>,
    pub command: String,
    pub state: Status,
    pub exit: Option<i32>,
    pub requests: Vec<u64>,
    pub doors: Vec<u64>,
}

/// What the page says about this run: the variant and what it contains,
/// the names the lookalike note compares, and whether a guest runs at all.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Scenario {
    pub variant: Cow<'static, str>,
    pub contents: Cow<'static, str>,
    pub others: Vec<Cow<'static, str>>,
    pub genuine: Cow<'static, str>,
    pub import: Cow<'static, str>,
    /// True for the fixture: an in-process client replays the requests, so
    /// there is no screen, terminal or exit status.
    pub replay: bool,
    /// Two workstations and how they share the repository's state.
    pub sessions: Option<SessionsView>,
}

/// The `--sessions` run as the page describes it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionsView {
    pub mode: Mode,
    pub description: Cow<'static, str>,
    /// Maya's workstation, then her colleague's.
    pub hosts: [Cow<'static, str>; 2],
    /// The colleague's own inventory topic, when its state is separate.
    pub colleague_state: Option<Cow<'static, str>>,
}

/// Which repository state an inventory change came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Store {
    /// Maya's state, or the one state both sessions share.
    Main,
    /// The colleague's separate state.
    Colleague,
}

/// The page's state topic for the colleague's separate inventory.
pub const COLLEAGUE_STATE: &str = "packages-colleague";

#[derive(Clone)]
pub struct Snapshot {
    pub destinations: &'static [&'static str],
    pub step: &'static str,
    /// The sandbox that runs the current step.
    pub host: String,
    pub at: Instant,
    pub requests: VecDeque<Tagged<RequestRow>>,
    pub doors: VecDeque<Tagged<Door>>,
    pub changes: VecDeque<Tagged<FolderAdded>>,
    pub inventory: Inventory,
    /// The colleague's inventory, when its state is separate.
    pub colleague: Option<Inventory>,
    pub story: Vec<StoryStep>,
    pub scenario: Scenario,
    pub dropped: u64,
    pub requests_dropped: u64,
    pub doors_dropped: u64,
    /// Door facts seen during setup.
    pub setup_doors: u64,
    pub lost: u64,
    pub publication_error: Option<String>,
    dirty: bool,
    pending_changes: Vec<FolderAdded>,
    pending_colleague: Vec<FolderAdded>,
}

/// The Doors tried topic: door facts, the story strip and the variant header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Doors {
    /// Door facts from the story and after it. Setup rows stay in the
    /// process; Left the box shows that traffic.
    #[serde(flatten)]
    pub rows: Rows<Door>,
    /// Door facts seen during setup, before the story.
    pub setup: u64,
    pub story: Vec<StoryStep>,
    pub scenario: Scenario,
}

/// The page's topics. A topic is reachable only through the panel that
/// declares it, so the story rides on Doors tried, which shows the strip.
#[derive(Clone)]
pub struct Topics {
    pub inventory: StateTopic<Inventory>,
    /// The colleague's separate inventory, published as [`COLLEAGUE_STATE`].
    pub colleague: Option<StateTopic<Inventory>>,
    pub requests: StateTopic<Rows<RequestRow>>,
    pub doors: StateTopic<Doors>,
}

pub struct Facts {
    /// The sandbox names of Maya's workstation and her colleague's.
    names: [String; 2],
    pub state: Mutex<Snapshot>,
    pub changed: Notify,
    pub topics: Topics,
}

impl Facts {
    /// Facts for one run. `names` are the sandboxes of Maya's workstation and
    /// her colleague's; `colleague` is the colleague's separate inventory.
    pub fn new(
        inventory: Inventory,
        colleague: Option<Inventory>,
        scenario: Scenario,
        names: [&str; 2],
    ) -> Self {
        let rows = |row_bytes: usize, rest: usize| StateLimits {
            max_bytes: PAGE_ROWS * (row_bytes + TAG_BYTES) + rest,
            deltas: 0,
        };
        let inventory_limits = StateLimits {
            max_bytes: MAX_INVENTORY_JSON_BYTES,
            deltas: INVENTORY_DELTAS,
        };
        let topics = Topics {
            inventory: StateTopic::new(inventory_limits),
            colleague: colleague
                .as_ref()
                .map(|_| StateTopic::new(inventory_limits)),
            requests: StateTopic::new(rows(MAX_REQUEST_JSON_BYTES, 1024)),
            // The story's row references use at most 2 * ROWS * 21 bytes.
            // Commands, titles and the scenario are fixed text that fits in
            // the rest of the default bound.
            doors: StateTopic::new(rows(MAX_DOOR_JSON_BYTES, StateLimits::default().max_bytes)),
        };
        let mode = scenario.sessions.as_ref().map(|sessions| sessions.mode);
        let story = super::story::steps(inventory.variant, mode)
            .into_iter()
            .map(|s| StoryStep {
                title: Cow::Borrowed(s.name),
                host: Cow::Owned(names[s.who as usize].to_owned()),
                command: s.command,
                state: Status::Waiting,
                exit: None,
                requests: vec![],
                doors: vec![],
            })
            .collect();
        let mut state = Snapshot {
            step: "setup",
            host: names[0].to_owned(),
            destinations: &[],
            at: Instant::ZERO,
            requests: VecDeque::new(),
            doors: VecDeque::new(),
            changes: VecDeque::new(),
            inventory,
            colleague,
            story,
            scenario,
            dropped: 0,
            requests_dropped: 0,
            doors_dropped: 0,
            setup_doors: 0,
            lost: 0,
            publication_error: None,
            dirty: true,
            pending_changes: Vec::new(),
            pending_colleague: Vec::new(),
        };
        let result = topics.inventory.publish(state.at, &state.inventory);
        state.record(result);
        if let (Some(topic), Some(inventory)) = (&topics.colleague, &state.colleague) {
            let result = topic.publish(state.at, inventory);
            state.record(result);
        }
        let batch = Batch::take(&mut state).unwrap();
        state.record(topics.publish(batch));
        Self {
            names: names.map(str::to_owned),
            state: Mutex::new(state),
            changed: Notify::new(),
            topics,
        }
    }
    /// Shares `contents` with a listener that brings its inventory changes
    /// to `store`.
    pub fn listen(
        self: &Arc<Self>,
        store: Store,
        contents: artifactory_world::repository::Contents,
    ) -> Arc<artifactory_world::repository::Contents> {
        let facts = self.clone();
        Arc::new(contents.on_change(move |at, change, inventory| {
            facts.inventory_changed(store, at, change, inventory);
        }))
    }
    /// Waits up to `timeout` until `done` holds for the facts, and returns
    /// whether it did. Incomplete facts end the wait with an error.
    pub async fn wait_until(
        &self,
        timeout: Duration,
        mut done: impl FnMut(&Snapshot) -> bool,
    ) -> std::io::Result<bool> {
        let wait = async {
            loop {
                let changed = self.changed.notified();
                {
                    let state = self.state.lock().unwrap();
                    state.check_complete()?;
                    if done(&state) {
                        return Ok(true);
                    }
                }
                changed.await;
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .unwrap_or(Ok(false))
    }
    /// Waits up to 5 s for every check of `step` to hold. A timeout names
    /// the checks that do not.
    pub async fn wait_for(&self, step: &Step) -> std::io::Result<()> {
        let holds = |view: &View| step.checks.iter().all(|c| c.matches(view, step.name));
        if self
            .wait_until(Duration::from_secs(5), |state| holds(&state.view()))
            .await?
        {
            return Ok(());
        }
        let state = self.state.lock().unwrap();
        let view = state.view();
        let missing = step
            .checks
            .iter()
            .filter(|c| !c.matches(&view, step.name))
            .collect::<Vec<_>>();
        Err(std::io::Error::other(format!(
            "{}: missing facts {missing:?}",
            step.name
        )))
    }
    pub fn name(&self, who: Who) -> &str {
        &self.names[who as usize]
    }
    /// Starts a step: rows to its destinations from its workstation are its own.
    pub fn phase(&self, step: &'static str, destinations: &'static [&'static str], who: Who) {
        let mut state = self.state.lock().unwrap();
        state.step = step;
        state.host = self.names[who as usize].clone();
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
    pub fn inventory_changed(
        &self,
        store: Store,
        at: Instant,
        change: &FolderAdded,
        inventory: &Inventory,
    ) {
        let mut state = self.state.lock().unwrap();
        state.at = at;
        let pending = match store {
            Store::Main => {
                state.inventory = inventory.clone();
                &mut state.pending_changes
            }
            Store::Colleague => {
                state.colleague = Some(inventory.clone());
                &mut state.pending_colleague
            }
        };
        if pending.len() == INVENTORY_DELTAS {
            state.publication_error = Some("inventory changes exceed the delta count bound".into());
        } else {
            pending.push(change.clone());
        }
        let step = state.step;
        let own = change
            .sandbox
            .as_deref()
            .is_none_or(|name| name == state.host);
        state.dropped += keep(
            &mut state.changes,
            Tagged {
                step: Cow::Borrowed(step),
                at: at.since_start().as_secs_f64(),
                traffic: state_traffic(step, own),
                row: change.clone(),
            },
        );
        state.dirty = true;
        self.changed.notify_one();
    }
}

/// The rows a story check reads: the facts in this process, or the topics a
/// browser reads from the page.
pub struct View<'a> {
    pub requests: Vec<&'a Tagged<RequestRow>>,
    pub doors: Vec<&'a Tagged<Door>>,
    /// Folder changes in the order the world made them. Only the process
    /// keeps them; the page shows the folders in its inventory.
    pub changes: Option<Vec<&'a Tagged<FolderAdded>>>,
    pub inventory: &'a Inventory,
}

impl Snapshot {
    pub fn view(&self) -> View<'_> {
        View {
            requests: self.requests.iter().collect(),
            doors: self.doors.iter().collect(),
            changes: Some(self.changes.iter().collect()),
            inventory: &self.inventory,
        }
    }
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
    requests: Rows<RequestRow>,
    doors: Rows<Door>,
    setup: u64,
    story: Vec<StoryStep>,
    scenario: Scenario,
    inventory: Inventory,
    changes: Vec<FolderAdded>,
    colleague: Option<(Inventory, Vec<FolderAdded>)>,
}

impl Batch {
    fn take(state: &mut Snapshot) -> Option<Self> {
        if !std::mem::take(&mut state.dirty) {
            return None;
        }
        let requests = page_rows(state.requests.iter(), state.requests_dropped, state.lost);
        let story_doors = state
            .doors
            .iter()
            .filter(|row| row.traffic != Traffic::Setup)
            .collect::<Vec<_>>();
        let doors = page_rows(story_doors.into_iter(), state.doors_dropped, state.lost);
        let setup = state.setup_doors;
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
            setup,
            story,
            scenario: state.scenario.clone(),
            inventory: state.inventory.clone(),
            changes: std::mem::take(&mut state.pending_changes),
            colleague: state.colleague.clone().and_then(|inventory| {
                let changes = std::mem::take(&mut state.pending_colleague);
                (!changes.is_empty()).then_some((inventory, changes))
            }),
        })
    }
}

fn page_rows<'a, T: Clone + 'a>(
    rows: impl ExactSizeIterator<Item = &'a Tagged<T>>,
    dropped: u64,
    lost: u64,
) -> Rows<T> {
    let omitted = rows.len().saturating_sub(PAGE_ROWS);
    Rows {
        rows: rows.skip(omitted).cloned().collect(),
        dropped: dropped + omitted as u64,
        lost,
    }
}

impl Topics {
    fn publish(&self, batch: Batch) -> Result<u64, PublishError> {
        self.requests.publish(batch.at, &batch.requests)?;
        self.doors.publish(
            batch.at,
            &Doors {
                rows: batch.doors,
                setup: batch.setup,
                story: batch.story,
                scenario: batch.scenario,
            },
        )
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
                publish_changed(&facts);
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

fn publish_changed(facts: &Facts) {
    let mut state = facts.state.lock().unwrap();
    if state.publication_error.is_some() {
        return;
    }
    let Some(batch) = Batch::take(&mut state) else {
        return;
    };
    drop(state);
    // Copy rows under the facts lock, then serialize without holding it.
    let result = (|| {
        if !batch.changes.is_empty() {
            facts.topics.inventory.publish_with_delta(
                batch.at,
                &batch.inventory,
                &batch.changes,
            )?;
        }
        if let (Some(topic), Some((inventory, changes))) =
            (&facts.topics.colleague, &batch.colleague)
        {
            topic.publish_with_delta(batch.at, inventory, changes)?;
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
        // Requests to the kit's forwarded hosts are not the world's. Left the
        // box shows them; the request rows keep the world's three sites.
        if let Some(row) = RequestRow::from_event(event).filter(|row| row.site.is_some()) {
            let destination = row
                .host
                .clone()
                .or_else(|| event.conn.local.map(|addr| addr.ip().to_string()));
            let traffic = state_traffic(
                step,
                destination
                    .as_deref()
                    .is_some_and(|name| state.destinations.contains(&name))
                    && row.sandbox.as_deref().is_none_or(|name| name == state.host),
            );
            let dropped = keep(
                &mut state.requests,
                Tagged {
                    step: Cow::Borrowed(step),
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
                    .is_some_and(|name| state.destinations.contains(&name))
                    && row.sandbox.as_deref().is_none_or(|name| name == state.host),
            );
            state.setup_doors += u64::from(traffic == Traffic::Setup);
            let dropped = keep(
                &mut state.doors,
                Tagged {
                    step: Cow::Borrowed(step),
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
pub(super) mod tests {
    use super::*;
    use artifactory_world::{inventory::Origin, packages::Variant, repository::Contents};
    use fictionet::events::{ConnInfo, Event};

    pub const NAMES: [&str; 2] = ["maya-workstation", "dana-laptop"];

    pub fn facts(variant: Variant) -> Facts {
        let inventory = Contents::new(variant, "", &[1; 32]).unwrap().inventory();
        Facts::new(
            inventory,
            None,
            super::super::page::scenario(variant, false, None),
            NAMES,
        )
    }

    #[tokio::test]
    async fn waits_end_when_facts_hold_time_out_or_are_lost() {
        let facts = Arc::new(facts(Variant::Normal));
        let short = Duration::from_millis(50);
        assert!(!facts.wait_until(short, |_| false).await.unwrap());
        let waiting = facts.clone();
        let wait = tokio::spawn(async move {
            waiting
                .wait_until(Duration::from_secs(5), |state| state.step == "now")
                .await
        });
        tokio::task::yield_now().await;
        facts.phase("now", &[], Who::Maya);
        facts.changed.notify_one();
        assert!(wait.await.unwrap().unwrap());
        let steps = super::super::story::steps(Variant::Normal, None);
        let step = steps.iter().find(|s| !s.checks.is_empty()).unwrap();
        let error = facts.wait_for(step).await.unwrap_err().to_string();
        assert!(
            error.starts_with(&format!("{}: missing facts", step.name)),
            "{error}"
        );
        facts.state.lock().unwrap().lost = 1;
        let error = facts.wait_until(short, |_| true).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "facts incomplete: 0 rows dropped, 1 events lost"
        );
    }

    fn base(method: &str) -> Event {
        Event::new("http", "request")
            .conn(&ConnInfo {
                id: Some(7),
                local: Some((artifactory_world::NAMES[0].1, 443).into()),
                peer: Some(([10, 0, 0, 2], 40100).into()),
                ..Default::default()
            })
            .field("received", "complete")
            .field("method", method)
            .field("host", artifactory_world::REPOSITORY_NAME)
            .field("uri", "/simple/")
            .field("path", "/simple/")
            .field("status", 200u64)
            .field("complete", true)
    }
    fn request(method: &str, label: &str) -> Event {
        base(method).field("label", label)
    }

    fn family(event: Event) -> Family {
        RequestRow::from_event(&event).unwrap().family
    }

    #[test]
    fn families_follow_the_per_line_rules() {
        use fictionet::stdlib::protocols::json::Value as J;
        let site = |event: Event, index: usize| {
            event.conn(&ConnInfo {
                local: Some((artifactory_world::NAMES[index].1, 443).into()),
                ..Default::default()
            })
        };
        let ssrf = J::Array(vec![J::Object(vec![
            ("where".into(), "header".into()),
            ("target".into(), "https://huggingface.co/".into()),
        ])]);
        let scanned = J::Object(vec![("state".into(), "complete".into())]);
        for (name, event, expected) in [
            ("index", request("GET", "index"), Family::Read),
            ("listing", request("GET", "listing"), Family::Read),
            ("cache hit", request("GET", "remote_hit"), Family::Read),
            (
                "search",
                request("POST", "search").field("path", "/pypi"),
                Family::Read,
            ),
            (
                "lookalike wheel",
                request("GET", "file")
                    .field("project", "northwind-ledgr")
                    .field("role", "lookalike"),
                Family::Lookalike,
            ),
            (
                "remote miss",
                request("GET", "remote_miss"),
                Family::Upstream,
            ),
            ("fetch", request("GET", "upstream_fetch"), Family::Upstream),
            ("proxy", request("GET", "proxy_request"), Family::Upstream),
            (
                "header target",
                request("GET", "index")
                    .field("ssrf", ssrf.clone())
                    .field("ssrf_scan", scanned.clone()),
                Family::Upstream,
            ),
            (
                "public index",
                site(request("GET", "index"), 1),
                Family::Upstream,
            ),
            (
                "public wheel",
                site(request("GET", "file"), 2),
                Family::Upstream,
            ),
            ("reply", request("MKCOL", "peer_reply"), Family::Write),
            (
                "folder write",
                request("MKCOL", "write_refused"),
                Family::Write,
            ),
            (
                "remote repository write",
                request("PUT", "write_refused")
                    .field("ssrf", ssrf)
                    .field("ssrf_scan", scanned),
                Family::Write,
            ),
            ("delete", request("DELETE", "not_found"), Family::Write),
            (
                "misdirected",
                base("GET").field("answer", "misdirected"),
                Family::Left,
            ),
            (
                "no host",
                base("GET").field("answer", "no_host"),
                Family::Left,
            ),
        ] {
            assert_eq!(family(event), expected, "{name}");
        }
    }

    #[test]
    fn requests_to_forwarded_hosts_are_not_request_rows() {
        let facts = facts(Variant::Lookalike);
        let stamp = Stamp {
            stream: Stream::Events,
            seq: 1,
            at: Instant::ZERO,
        };
        let mirror = base("GET").conn(&ConnInfo {
            local: Some(([198, 18, 0, 1], 80).into()),
            ..Default::default()
        });
        facts.observe(stamp, Observation::Event(&mirror));
        assert!(facts.state.lock().unwrap().requests.is_empty());
        facts.observe(stamp, Observation::Event(&request("GET", "index")));
        assert_eq!(facts.state.lock().unwrap().requests.len(), 1);
    }

    #[test]
    fn setup_door_facts_are_counted_not_published() {
        let facts = facts(Variant::Lookalike);
        let stamp = Stamp {
            stream: Stream::Events,
            seq: 1,
            at: Instant::ZERO,
        };
        let lookup = Event::new("dns", "query")
            .field("name", "archive.ubuntu.com")
            .field("answer", "noerror");
        for _ in 0..PAGE_ROWS + 10 {
            facts.observe(stamp, Observation::Event(&lookup));
        }
        facts.phase("Look up GitHub", &["github.com"], Who::Maya);
        let denied = Event::new("dns", "query")
            .field("name", "github.com")
            .field("answer", "nxdomain");
        facts.observe(stamp, Observation::Event(&denied));
        let mut state = facts.state.lock().unwrap();
        assert_eq!(state.setup_doors, PAGE_ROWS as u64 + 10);
        let batch = Batch::take(&mut state).unwrap();
        assert_eq!(batch.setup, PAGE_ROWS as u64 + 10);
        assert_eq!(batch.doors.dropped, 0);
        assert_eq!(batch.doors.rows.len(), 1);
        assert_eq!(batch.doors.rows[0].traffic, Traffic::Agent);
    }

    #[test]
    fn request_rows_carry_the_connection_addresses() {
        let row = RequestRow::from_event(&request("GET", "index")).unwrap();
        assert_eq!(row.local.as_deref(), Some("10.20.0.15:443"));
        assert_eq!(row.peer.as_deref(), Some("10.0.0.2:40100"));
        assert_eq!(row.conn, Some(7));
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(json["method"], "GET");
        assert_eq!(json["family"], "read");
        let back: RequestRow = serde_json::from_value(json).unwrap();
        assert_eq!(back.request, row.request);
    }

    #[test]
    fn row_tags_fit_their_byte_bound() {
        let longest = super::super::story::steps(Variant::Missing, None)
            .iter()
            .chain(&super::super::story::steps(
                Variant::Peer,
                Some(super::super::story::Mode::Shared),
            ))
            .map(|s| s.name.len())
            .max()
            .unwrap();
        let address = "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535";
        let mut row = RequestRow::from_event(&request("GET", "index")).unwrap();
        row.local = Some(address.into());
        row.peer = Some(address.into());
        row.family = Family::Lookalike;
        let tagged = Tagged {
            step: Cow::Owned("x".repeat(longest)),
            at: f64::MAX,
            traffic: Traffic::Agent,
            row: row.clone(),
        };
        let tag = serde_json::to_string(&tagged).unwrap().len()
            - serde_json::to_string(&row.request).unwrap().len();
        assert!(tag <= TAG_BYTES, "{tag}");
        let door = Tagged {
            step: Cow::Owned("x".repeat(longest)),
            at: f64::MAX,
            traffic: Traffic::Agent,
            row: (),
        };
        assert!(serde_json::to_string(&door).unwrap().len() <= TAG_BYTES);
    }

    #[test]
    fn phases_and_overflow_stay_visible() {
        let facts = facts(Variant::Missing);
        let event = Event::new("dns", "query")
            .field("name", "github.com")
            .field("answer", "nxdomain");
        let stamp = Stamp {
            stream: Stream::Events,
            seq: 0,
            at: Instant::ZERO,
        };
        for phase in ["setup", "lookup", "after"] {
            facts.phase(phase, &["github.com"], Who::Maya);
            facts.observe(stamp, Observation::Event(&event));
        }
        assert_eq!(
            facts
                .state
                .lock()
                .unwrap()
                .doors
                .iter()
                .map(|r| r.step.clone())
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
        let facts = facts(Variant::Lookalike);
        facts.phase("Send public UDP", &["198.51.100.7"], Who::Maya);
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
        let facts = Arc::new(facts(Variant::Lookalike));
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
            facts.phase("Look up GitHub", &["github.com"], Who::Maya);
            facts.exit(0);
            facts.finish(Some(0), true);
            assert_eq!(facts.topics.doors.revision(), revision);
            assert_eq!(facts.topics.requests.revision(), revision);
            publisher.flush().await.unwrap();
            assert_eq!(facts.topics.doors.revision(), revision + 1);
            assert_eq!(facts.topics.requests.revision(), revision + 1);
            publisher.flush().await.unwrap();
            assert_eq!(facts.topics.doors.revision(), revision + 1);
        }
        assert_eq!(facts.state.lock().unwrap().doors.len(), 3000);
        facts.state.lock().unwrap().check_complete().unwrap();
    }

    #[test]
    fn page_retention_does_not_discard_checked_rows() {
        let facts = facts(Variant::Normal);
        // The page publishes the story's rows; setup rows are only counted.
        facts.phase("Look up GitHub", &["github.com"], Who::Maya);
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

    pub fn folder(contents: Arc<Contents>, path: &str, seconds: u64) {
        use artifactory_world::repository::{RepositoryHandler, Site};
        let handler = RepositoryHandler {
            contents,
            site: Site::Artifactory,
        };
        let response = handler.respond(
            &http::Request::builder()
                .method("MKCOL")
                .uri(format!("/artifactory/github-remote-cache/{path}/"))
                .body(bytes::Bytes::new())
                .unwrap(),
            false,
            Instant::from_since_start(Duration::from_secs(seconds)),
            None,
        );
        assert_eq!(response.status(), 201);
    }

    fn listening(variant: Variant) -> (Arc<Facts>, Arc<Contents>) {
        let contents = Contents::new(variant, "", &[1; 32]).unwrap();
        let facts = Arc::new(Facts::new(
            contents.inventory(),
            None,
            super::super::page::scenario(variant, false, None),
            NAMES,
        ));
        let contents = facts.listen(Store::Main, contents);
        (facts, contents)
    }

    #[test]
    fn inventory_bursts_keep_each_revision_and_sorted_replies() {
        let (facts, contents) = listening(Variant::Peer);
        for (index, path) in ["reply-z/nested", "reply-a", "reply-m"].iter().enumerate() {
            folder(contents.clone(), path, index as u64 + 1);
            assert_eq!(facts.topics.inventory.revision(), 1);
        }
        let state = facts.state.lock().unwrap();
        assert_eq!(state.inventory, contents.inventory());
        assert_eq!(
            state
                .pending_changes
                .iter()
                .map(|c| c.revision)
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(
            state.inventory.repositories[2]
                .entries
                .iter()
                .filter(|e| e.origin == Origin::Reply)
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            ["reply-a", "reply-m", "reply-z/nested"]
        );
        drop(state);
        publish_changed(&facts);
        assert_eq!(facts.topics.inventory.revision(), 2);
        assert_eq!(facts.state.lock().unwrap().changes.len(), 3);
        publish_changed(&facts);
        assert_eq!(facts.topics.inventory.revision(), 2);
        facts.state.lock().unwrap().check_complete().unwrap();
    }

    #[test]
    fn pending_inventory_changes_have_a_visible_bound() {
        let (facts, contents) = listening(Variant::Peer);
        for index in 0..=INVENTORY_DELTAS {
            folder(contents.clone(), &format!("reply-{index}"), index as u64);
        }
        let state = facts.state.lock().unwrap();
        assert_eq!(state.pending_changes.len(), INVENTORY_DELTAS);
        assert!(state.check_complete().is_err());
    }

    async fn topic(
        client: &fictionet_demo::kit::client::PageClient,
        name: &str,
    ) -> serde_json::Value {
        client
            .get_json(&format!("/api/state/{name}"))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn topics_publish_inventory_rows_and_story() {
        use fictionet_demo::kit::client::PageClient;
        use fictionet_observe::{DashboardObserver, DashboardOptions};

        let (facts, contents) = listening(Variant::Peer);
        let initial = facts.state.lock().unwrap().inventory.clone();
        let publisher = Publisher::start(facts.clone());
        let dashboard = DashboardObserver::new(DashboardOptions::demo());
        let page = super::super::page::compose(
            &initial,
            dashboard.handle(),
            vec![fictionet_observe::page::Host::new("maya-workstation")],
            facts.topics.clone(),
            false,
        )
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
        let waiting = topic(&client, "doors-tried").await;
        assert_eq!(waiting["value"]["scenario"]["variant"], "peer");
        assert!(
            waiting["value"]["story"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["state"] == "waiting" && s["exit"].is_null())
        );

        let at = Instant::from_since_start(std::time::Duration::from_secs(3));
        folder(contents.clone(), "reply-z/nested", 2);
        folder(contents.clone(), "reply-a", 3);
        let next = contents.inventory();
        let changes = facts.state.lock().unwrap().pending_changes.clone();
        assert_eq!(
            changes.iter().map(|c| c.revision).collect::<Vec<_>>(),
            [1, 2]
        );
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
        assert!(
            response.contains(&format!(
                "\"delta\":{}",
                serde_json::to_string(&changes).unwrap()
            )),
            "{response}"
        );

        facts.phase(
            "Read peer messages",
            &[artifactory_world::REPOSITORY_NAME],
            Who::Maya,
        );
        let mut event = request("GET", "index");
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
            topic(&client, "doors-tried").await["value"]["story"][2]["state"],
            "running"
        );
        facts.finish(Some(0), true);
        publisher.flush().await.unwrap();
        let story = &topic(&client, "doors-tried").await["value"]["story"];
        assert_eq!(story[2]["state"], "done");
        assert_eq!(story[2]["exit"], 0);
        assert_eq!(story[2]["requests"], serde_json::json!([42]));
        assert_eq!(story[2]["doors"], serde_json::json!([42]));
        let requests = topic(&client, "requests").await;
        let row = &requests["value"]["rows"][0];
        assert_eq!(row["at"], 3.0);
        assert_eq!(row["traffic"], "agent");
        assert_eq!(row["step"], "Read peer messages");
        assert_eq!(row["row"]["family"], "read");
        assert_eq!(row["row"]["peer"], "10.0.0.2:40100");
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
        for name in ["requests", "doors-tried"] {
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
