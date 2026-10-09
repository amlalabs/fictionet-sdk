//! What the core records about a running world, for the
//! [dashboard](crate::observe#the-dashboard).
//!
//! Every [`pair`](crate::pair) and every [`Attachment`](crate::Attachment)
//! carries a [`Meter`]: packet and byte counts for each direction, and a
//! packet tap that copies packets only while a viewer watches the link. The
//! counts cost two relaxed atomic additions per packet. The tap costs one
//! relaxed atomic load per packet while nothing watches.
//!
//! Every [`run`](crate::run) also has a [`Graph`]: its tasks, where each
//! was spawned, which task uses which end of each link, and the run's
//! [events](crate::events).

use fictionet::sync::{Mutex, MutexGuard};

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::HashMap;
#[cfg(any(feature = "observe", all(test, feature = "std")))]
use std::collections::VecDeque;
use std::panic::Location;
#[cfg(any(feature = "observe", all(test, feature = "std")))]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
#[cfg(any(feature = "observe", all(test, feature = "std")))]
use std::time::Duration;

use crate::Packet;
use crate::sys::SystemTime;
#[cfg(any(feature = "observe", all(test, feature = "std")))]
use crate::time::Instant;

thread_local! {
    /// The id of the task this thread is polling, or 0 outside any task.
    static CURRENT: Cell<u64> = const { Cell::new(0) };
}

/// The task this thread is polling right now, or 0.
#[inline]
pub(crate) fn current_task() -> u64 {
    CURRENT.with(Cell::get)
}

/// Sets the current task while a task is polled, and puts back the one
/// before it when dropped.
pub(crate) struct Polling(u64);

impl Polling {
    #[inline]
    pub(crate) fn enter(id: u64) -> Polling {
        Polling(CURRENT.with(|c| c.replace(id)))
    }
}

impl Drop for Polling {
    #[inline]
    fn drop(&mut self) {
        CURRENT.with(|c| c.set(self.0));
    }
}

/// Hashes task and link ids, which are small distinct numbers, with one
/// multiplication instead of SipHash.
pub(crate) type Ids = std::hash::BuildHasherDefault<IdHasher>;

#[derive(Default)]
pub(crate) struct IdHasher(u64);

impl std::hash::Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = (self.0 ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3);
        }
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = n.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

// ---------------------------------------------------------------------------
// Meters

/// Link ids, unique in the process. They only name links in the
/// dashboard's messages.
static NEXT_LINK: AtomicU64 = AtomicU64::new(1);

/// The counts and the tap of one link: a pair, or an attachment.
///
/// Side 0 and side 1 are the two ends. For an attachment, side 0 is the
/// world and side 1 the sandbox.
///
/// A pair counts its packets itself, as plain numbers under the lock it
/// takes for each packet anyway, and the meter reads them through
/// `counted`. An attachment counts in `counts`, with atomics.
pub(crate) struct Meter {
    pub(crate) id: u64,
    /// What end `s` sent, for an attachment.
    #[cfg(feature = "std")]
    counts: [Count; 2],
    /// What holds the counts of a pair.
    counted: OnceLock<Weak<dyn Counted>>,
    /// The task that made the link, or 0.
    #[cfg(feature = "observe")]
    creator: u64,
    /// For an attachment: the sandbox's name. Side 1 is the sandbox.
    sandbox: OnceLock<Arc<str>>,
    /// Set while a viewer watches: `send` then copies packets into `tap`.
    #[cfg(any(feature = "observe", all(test, feature = "std")))]
    tapped: AtomicBool,
    #[cfg(any(feature = "observe", all(test, feature = "std")))]
    tap: Mutex<Option<Arc<Tap>>>,
}

#[derive(Default)]
#[cfg(feature = "std")]
struct Count {
    packets: AtomicU64,
    bytes: AtomicU64,
}

impl Meter {
    pub(crate) fn new() -> Arc<Meter> {
        Arc::new(Meter {
            id: NEXT_LINK.fetch_add(1, Ordering::Relaxed),
            #[cfg(feature = "std")]
            counts: Default::default(),
            counted: OnceLock::new(),
            #[cfg(feature = "observe")]
            creator: current_task(),
            sandbox: OnceLock::new(),
            #[cfg(any(feature = "observe", all(test, feature = "std")))]
            tapped: AtomicBool::new(false),
            #[cfg(any(feature = "observe", all(test, feature = "std")))]
            tap: Mutex::new(None),
        })
    }

    /// Marks side 1 as the sandbox called `name`.
    pub(crate) fn set_sandbox(&self, name: &str) {
        let _ = self.sandbox.set(Arc::from(name));
    }

    /// Reads the counts from `counted` from now on.
    pub(crate) fn count_in(&self, counted: Weak<dyn Counted>) {
        let _ = self.counted.set(counted);
    }

    /// Counts a packet that end `side` sent, and copies it if watched.
    #[inline]
    #[cfg(feature = "std")]
    pub(crate) fn sent(&self, side: usize, packet: &Packet) {
        let c = &self.counts[side];
        c.packets.fetch_add(1, Ordering::Relaxed);
        c.bytes.fetch_add(packet.0.len() as u64, Ordering::Relaxed);
        self.copy(side, packet);
    }

    /// Copies a packet that end `side` sent, if a viewer watches.
    #[inline]
    pub(crate) fn copy(&self, side: usize, packet: &Packet) {
        #[cfg(not(any(feature = "observe", all(test, feature = "std"))))]
        let _ = (side, packet);
        #[cfg(any(feature = "observe", all(test, feature = "std")))]
        if self.tapped.load(Ordering::Relaxed) {
            self.capture(side, packet);
        }
    }

    #[cold]
    #[cfg(any(feature = "observe", all(test, feature = "std")))]
    fn capture(&self, side: usize, packet: &Packet) {
        let tap = self.tap.lock().clone();
        if let Some(tap) = tap {
            tap.push(side as u8, &packet.0);
        }
    }

    /// Packets and bytes each side has sent: `[packets 0, bytes 0, packets
    /// 1, bytes 1]`.
    #[cfg(any(feature = "observe", all(test, feature = "std")))]
    pub(crate) fn totals(&self) -> [u64; 4] {
        if let Some(counted) = self.counted.get() {
            return counted.upgrade().map_or([0; 4], |c| c.totals());
        }
        [
            self.counts[0].packets.load(Ordering::Relaxed),
            self.counts[0].bytes.load(Ordering::Relaxed),
            self.counts[1].packets.load(Ordering::Relaxed),
            self.counts[1].bytes.load(Ordering::Relaxed),
        ]
    }

    /// Starts copying packets, or joins the viewers already watching.
    #[cfg(any(feature = "observe", all(test, feature = "std")))]
    pub(crate) fn watch(
        self: &Arc<Self>,
        environment: &Arc<crate::entropy::RunEnvironment>,
    ) -> TapGuard {
        let mut slot = self.tap.lock();
        let tap = slot
            .get_or_insert_with(|| Arc::new(Tap::new(environment.clone())))
            .clone();
        tap.viewers.fetch_add(1, Ordering::Relaxed);
        self.tapped.store(true, Ordering::Relaxed);
        TapGuard {
            meter: Arc::downgrade(self),
            tap,
        }
    }
}

/// Whatever counts a link's packets itself.
pub(crate) trait Counted: Send + Sync {
    /// `[packets 0, bytes 0, packets 1, bytes 1]`, by the side that sent.
    #[cfg(any(feature = "observe", all(test, feature = "std")))]
    fn totals(&self) -> [u64; 4];
}

/// One viewer of a link's packets. Dropping the last one stops the copies.
#[cfg(any(feature = "observe", all(test, feature = "std")))]
pub(crate) struct TapGuard {
    /// Weak, so that a watched link still closes when its ends are gone.
    meter: Weak<Meter>,
    pub(crate) tap: Arc<Tap>,
}

#[cfg(any(feature = "observe", all(test, feature = "std")))]
impl Drop for TapGuard {
    fn drop(&mut self) {
        let Some(meter) = self.meter.upgrade() else {
            return;
        };
        let mut slot = meter.tap.lock();
        if self.tap.viewers.fetch_sub(1, Ordering::Relaxed) == 1 {
            meter.tapped.store(false, Ordering::Relaxed);
            *slot = None;
        }
    }
}

// ---------------------------------------------------------------------------
// The tap

/// Packets kept in full in each 100 ms window before sampling starts.
#[cfg(any(feature = "observe", all(test, feature = "std")))]
pub(crate) const FULL_PER_WINDOW: u64 = 64;
#[cfg(any(feature = "observe", all(test, feature = "std")))]
const WINDOW: Duration = Duration::from_millis(100);
/// How many bytes of copies a tap keeps. Older copies are dropped first.
#[cfg(any(feature = "observe", all(test, feature = "std")))]
const TAP_BYTES: usize = 8 << 20;
/// How many copies a tap keeps.
#[cfg(any(feature = "observe", all(test, feature = "std")))]
const TAP_PACKETS: usize = 4096;

/// A copied packet.
#[derive(Clone)]
#[cfg(any(feature = "observe", all(test, feature = "std")))]
pub(crate) struct Copy {
    /// Numbers every copy of a tap, from 1, with no gaps.
    pub(crate) seq: u64,
    pub(crate) at: Instant,
    /// Which end sent it.
    pub(crate) side: u8,
    pub(crate) data: Arc<[u8]>,
    /// Packets on this link that were not copied since the copy before.
    pub(crate) skipped: u64,
}

/// A bounded buffer of copied packets.
///
/// Within each 100 ms window, the first [`FULL_PER_WINDOW`] packets are
/// copied. Past that, one in every `n` is, where `n` doubles every
/// `FULL_PER_WINDOW` packets, so a flood costs at most about 130 copies a
/// window, not one per packet.
#[cfg(any(feature = "observe", all(test, feature = "std")))]
pub(crate) struct Tap {
    environment: Arc<crate::entropy::RunEnvironment>,
    viewers: AtomicUsize,
    state: Mutex<TapState>,
}

#[cfg(any(feature = "observe", all(test, feature = "std")))]
struct TapState {
    copies: VecDeque<Copy>,
    bytes: usize,
    next_seq: u64,
    window_start: Instant,
    in_window: u64,
    skipped: u64,
}

#[cfg(any(feature = "observe", all(test, feature = "std")))]
impl Tap {
    fn new(environment: Arc<crate::entropy::RunEnvironment>) -> Tap {
        Tap {
            environment,
            viewers: AtomicUsize::new(0),
            state: Mutex::new(TapState {
                copies: VecDeque::new(),
                bytes: 0,
                next_seq: 1,
                window_start: Instant::ZERO,
                in_window: 0,
                skipped: 0,
            }),
        }
    }

    fn push(&self, side: u8, data: &[u8]) {
        let now = self.environment.clock.now();
        let mut s = self.state.lock();
        if now
            .since_start()
            .saturating_sub(s.window_start.since_start())
            >= WINDOW
        {
            s.window_start = now;
            s.in_window = 0;
        }
        let k = s.in_window;
        s.in_window += 1;
        if !keep(k) {
            s.skipped += 1;
            return;
        }
        let seq = s.next_seq;
        s.next_seq += 1;
        let skipped = std::mem::take(&mut s.skipped);
        s.bytes += data.len();
        s.copies.push_back(Copy {
            seq,
            at: now,
            side,
            data: data.into(),
            skipped,
        });
        while s.copies.len() > TAP_PACKETS || s.bytes > TAP_BYTES {
            let Some(old) = s.copies.pop_front() else {
                break;
            };
            s.bytes -= old.data.len();
        }
    }

    /// Copies with a sequence number of `after + 1` or more, at most `max`.
    pub(crate) fn since(&self, after: u64, max: usize) -> Vec<Copy> {
        let s = self.state.lock();
        let first = s.copies.front().map_or(0, |c| c.seq);
        let skip = (after + 1).saturating_sub(first) as usize;
        s.copies.iter().skip(skip).take(max).cloned().collect()
    }
}

/// Whether the `k`th packet of a window (from 0) is copied.
#[cfg(any(feature = "observe", all(test, feature = "std")))]
pub(crate) fn keep(k: u64) -> bool {
    if k < FULL_PER_WINDOW {
        return true;
    }
    // 64..128 every 2nd, 128..192 every 4th, and so on.
    let step = 1u64 << ((k / FULL_PER_WINDOW).min(30));
    k.is_multiple_of(step)
}

// ---------------------------------------------------------------------------
// The graph

/// A named group of tasks, from [`Cx::group`](crate::Cx::group). Only
/// observers read it.
#[derive(Debug)]
pub(crate) struct Group {
    /// Unique in its run, from 1.
    #[cfg(feature = "observe")]
    pub(crate) id: u64,
    #[cfg(feature = "observe")]
    pub(crate) name: String,
    /// The group this one is inside.
    #[cfg(feature = "observe")]
    pub(crate) parent: Option<Arc<Group>>,
}

impl Group {
    pub(crate) fn new(id: u64, name: String, parent: Option<Arc<Group>>) -> Arc<Group> {
        #[cfg(not(feature = "observe"))]
        let _ = (id, name, parent);
        Arc::new(Group {
            #[cfg(feature = "observe")]
            id,
            #[cfg(feature = "observe")]
            name,
            #[cfg(feature = "observe")]
            parent,
        })
    }

    /// This group and the groups it is inside, innermost first.
    #[cfg(feature = "observe")]
    pub(crate) fn chain(self: &Arc<Self>) -> impl Iterator<Item = &Arc<Group>> {
        std::iter::successors(Some(self), |g| g.parent.as_ref())
    }
}

/// A task as observers see it.
#[derive(Clone, Debug)]
pub(crate) struct TaskInfo {
    pub(crate) parent: u64,
    /// The group the task belongs to, if any.
    #[cfg(feature = "observe")]
    pub(crate) group: Option<Arc<Group>>,
    /// The stdlib function's name, or the full type name of the task's
    /// future, shortened by [`short_name`] only when an observer asks.
    pub(crate) name: Cow<'static, str>,
    pub(crate) file: &'static str,
    pub(crate) line: u32,
    #[cfg(feature = "observe")]
    pub(crate) started: Duration,
}

/// A link the graph has seen used.
pub(crate) struct LinkInfo {
    pub(crate) meter: Weak<Meter>,
    /// The task using each end, or 0 if none has been seen.
    pub(crate) owners: [u64; 2],
    #[cfg(feature = "observe")]
    pub(crate) creator: u64,
    pub(crate) sandbox: Option<Arc<str>>,
    pub(crate) label: Option<Arc<str>>,
}

/// One line of an `SSLKEYLOGFILE`: a TLS secret and the client random it
/// belongs to.
#[derive(Clone, Debug)]
pub struct KeyLine {
    /// SSLKEYLOGFILE label, such as CLIENT_TRAFFIC_SECRET_0.
    pub label: String,
    /// ClientHello random identifying the session.
    pub client_random: Vec<u8>,
    /// Traffic secret bytes.
    pub secret: Vec<u8>,
}

/// How many TLS secrets a world keeps, about 4,000 sessions. Past that,
/// the oldest are forgotten.
#[cfg(feature = "observe")]
pub(crate) const MAX_KEYS: usize = 20_000;

/// What a run records about itself for observers.
///
/// Every run keeps one. Starting a task, and a task taking an end of a
/// link, each take its lock once. Packets never do.
pub(crate) struct Graph {
    pub(crate) environment: Arc<crate::entropy::RunEnvironment>,
    pub(crate) start_wall: SystemTime,
    /// Observer sessions connected to the world. While there are none,
    /// packet copies and TLS keys are not kept.
    pub(crate) viewers: AtomicUsize,
    /// The run's events, kept whether or not anyone observes.
    pub(crate) events: Arc<crate::events::Store>,
    /// The id of the next group.
    next_group: AtomicU64,
    state: Mutex<GraphState>,
    /// Application decoders for links watched from now on.
    pub(crate) protocols: Mutex<crate::observe::Registry>,
    /// Watched links, so observers of one link share one decoded copy.
    #[cfg(feature = "observe")]
    pub(crate) watches: Mutex<std::collections::HashMap<u64, Arc<crate::observe::LinkWatch>>>,
}

#[derive(Default)]
pub(crate) struct GraphState {
    pub(crate) tasks: HashMap<u64, TaskInfo, Ids>,
    pub(crate) links: HashMap<u64, LinkInfo, Ids>,
    /// The link count at which dead links are next swept out.
    sweep_at: usize,
    #[cfg(feature = "observe")]
    pub(crate) keys: VecDeque<KeyLine>,
    /// How many keys have ever been added, so watches can take new ones
    /// after old ones are forgotten.
    #[cfg(feature = "observe")]
    pub(crate) keys_added: u64,
    /// The run has ended.
    pub(crate) ended: bool,
}

impl Graph {
    pub(crate) fn new(seed: crate::Seed, mode: crate::RunMode) -> Arc<Graph> {
        Arc::new(Graph {
            environment: Arc::new(crate::entropy::RunEnvironment::new(seed, mode)),
            start_wall: if mode == crate::RunMode::Real {
                SystemTime::now()
            } else {
                crate::sys::UNIX_EPOCH
            },
            viewers: AtomicUsize::new(0),
            next_group: AtomicU64::new(1),
            state: Mutex::new(GraphState {
                sweep_at: 64,
                ..GraphState::default()
            }),
            events: crate::events::Store::new(mode),
            #[cfg(feature = "observe")]
            watches: Mutex::default(),
            protocols: Mutex::default(),
        })
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, GraphState> {
        self.state.lock()
    }

    /// Whether an observer is subscribed to this world's events.
    #[inline]
    pub(crate) fn observed(&self) -> bool {
        self.viewers.load(Ordering::Relaxed) > 0
    }

    #[cfg(any(feature = "observe", all(test, feature = "std")))]
    pub(crate) fn since_start(&self) -> Duration {
        self.environment.clock.now().since_start()
    }

    /// A new group id.
    pub(crate) fn next_group(&self) -> u64 {
        self.next_group.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn task_started(
        &self,
        id: u64,
        name: Cow<'static, str>,
        location: &'static Location<'static>,
        group: Option<Arc<Group>>,
    ) {
        #[cfg(not(feature = "observe"))]
        let _ = group;
        let info = TaskInfo {
            parent: current_task(),
            #[cfg(feature = "observe")]
            group,
            name,
            file: location.file(),
            line: location.line(),
            #[cfg(feature = "observe")]
            started: self.since_start(),
        };
        self.state().tasks.insert(id, info);
    }

    pub(crate) fn task_ended(&self, id: u64) {
        self.state().tasks.remove(&id);
    }

    pub(crate) fn run_ended(&self) {
        let mut s = self.state();
        s.ended = true;
        s.tasks.clear();
        drop(s);
        // Nothing more is recorded: let callbacks and file writers go.
        self.events.close();
        // Nothing more crosses the world's links: stop watching them.
        #[cfg(feature = "observe")]
        self.watches.lock().clear();
    }

    fn link<'a>(s: &'a mut GraphState, meter: &Arc<Meter>) -> &'a mut LinkInfo {
        if s.links.len() >= s.sweep_at {
            // Links are only ever added here, so sweeping when the count
            // doubles keeps the cost per link constant.
            s.links.retain(|_, l| l.meter.strong_count() > 0);
            s.sweep_at = (s.links.len() * 2).max(64);
        }
        s.links.entry(meter.id).or_insert_with(|| LinkInfo {
            meter: Arc::downgrade(meter),
            owners: [0, 0],
            #[cfg(feature = "observe")]
            creator: meter.creator,
            sandbox: meter.sandbox.get().cloned(),
            label: None,
        })
    }

    /// Records that `task` uses end `side` of `meter`.
    #[cold]
    pub(crate) fn owns(&self, meter: &Arc<Meter>, side: usize, task: u64) {
        let mut s = self.state();
        let link = Self::link(&mut s, meter);
        link.owners[side] = task;
        if link.sandbox.is_none() {
            link.sandbox = meter.sandbox.get().cloned();
        }
    }

    /// Gives a link a label, such as the prefix a router sends to it.
    pub(crate) fn label(&self, meter: &Arc<Meter>, label: String) {
        let mut s = self.state();
        Self::link(&mut s, meter).label = Some(Arc::from(label));
    }

    /// The task `task` as an event records it, if it is running.
    pub(crate) fn origin(&self, task: u64) -> Option<crate::events::Origin> {
        if task == 0 {
            return None;
        }
        let s = self.state();
        let t = s.tasks.get(&task)?;
        Some(crate::events::Origin {
            task,
            name: t.name.clone(),
            file: t.file,
            line: t.line,
            parent: t.parent,
        })
    }

    #[cfg(feature = "observe")]
    pub(crate) fn key(&self, line: KeyLine) {
        let mut s = self.state();
        if s.keys.len() >= MAX_KEYS {
            s.keys.pop_front();
        }
        s.keys.push_back(line);
        s.keys_added += 1;
    }
}

/// The name of a task's future type, for [`TaskInfo::name`].
pub(crate) fn task_name<T: ?Sized>() -> Cow<'static, str> {
    Cow::Borrowed(std::any::type_name::<T>())
}

/// A short name for a task, from the type of its future: the last two
/// path segments, without closures and generics.
/// `fictionet::stdlib::web::net::pings::{{closure}}` becomes `net::pings`.
/// A name with no path, such as `delay`, stays as it is.
pub(crate) fn short_name(full: &str) -> String {
    // Cut generic arguments, which can hold paths of their own.
    let mut depth = 0;
    let mut plain = String::with_capacity(full.len());
    for ch in full.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth -= 1,
            _ if depth == 0 => plain.push(ch),
            _ => {}
        }
    }
    let parts: Vec<&str> = plain
        .split("::")
        .filter(|p| !p.is_empty() && !p.starts_with('{'))
        .collect();
    let n = parts.len();
    parts[n.saturating_sub(2)..].join("::")
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn names_come_from_the_future_type() {
        async fn pings() {}
        fn name_of<F>(_: &F) -> String {
            short_name(&task_name::<F>())
        }
        assert_eq!(name_of(&pings()), "names_come_from_the_future_type::pings");
        let block = async {};
        assert_eq!(name_of(&block), "tests::names_come_from_the_future_type");
    }

    /// A watched run knows its tasks, where they were spawned, which task
    /// uses which end of a pair, and how much went each way.
    #[test]
    fn a_watched_run_records_tasks_owners_and_counts() {
        use crate::Interface;
        use crate::prelude::*;
        let graph = Graph::new(crate::Seed::random(), crate::RunMode::Real);
        let g = graph.clone();
        let (spawn_line, seen) = (Arc::new(AtomicU64::new(0)), Arc::new(Mutex::new(None)));
        let (line, s) = (spawn_line.clone(), seen.clone());
        let out = crate::block_on(crate::run::run_with(graph.clone(), move |fcx| async move {
            let (mut a, mut b) = crate::pair();
            line.store(u64::from(line!()) + 1, Ordering::SeqCst);
            let echo = fcx.spawn(move |fcx| async move {
                while let Ok(p) = b.recv(&fcx).await {
                    b.send(p);
                }
                Ok(())
            });
            for i in 0..10u8 {
                a.send(Packet(vec![i; 100]));
                a.recv(&fcx).await?;
            }
            *s.lock() = Some(snapshot(&g));
            drop(a);
            Ok(echo.join(&fcx).await?)
        }));
        out.unwrap();
        let (tasks, links) = seen.lock().take().unwrap();
        let world = &tasks
            .iter()
            .find(|(_, t)| t.name == "world")
            .expect("the world task")
            .0;
        let (echo, info) = tasks
            .iter()
            .find(|(_, t)| t.name != "world")
            .expect("the echo task");
        assert_eq!(info.line as u64, spawn_line.load(Ordering::SeqCst));
        assert!(info.file.ends_with("watch.rs"));
        assert_eq!(info.parent, *world);
        assert_eq!(links.len(), 1);
        let (owners, totals) = &links[0];
        assert_eq!(*owners, [*world, *echo]);
        assert_eq!(*totals, [10, 1000, 10, 1000]);
        // Once the run is over, its tasks are gone.
        assert!(graph.state().tasks.is_empty());
        assert!(graph.state().ended);
    }

    type Snapshot = (Vec<(u64, TaskInfo)>, Vec<([u64; 2], [u64; 4])>);

    fn snapshot(g: &Graph) -> Snapshot {
        let s = g.state();
        let tasks = s.tasks.iter().map(|(id, t)| (*id, t.clone())).collect();
        let links = s
            .links
            .values()
            .map(|l| (l.owners, l.meter.upgrade().unwrap().totals()))
            .collect();
        (tasks, links)
    }

    /// Pairs count their packets in every run.
    #[test]
    fn pairs_count_their_packets() {
        use crate::Interface;
        use crate::prelude::*;
        crate::block_on(crate::run(fictionet::Seed::random(), |fcx| async move {
            let (mut a, mut b) = crate::pair();
            a.send(Packet(vec![0; 40]));
            b.recv(&fcx).await?;
            assert_eq!(a.meter().totals(), [1, 40, 0, 0]);
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn graph_and_sampling_windows_use_lab_time() {
        crate::block_on(crate::lab(crate::Seed::from_u64(0), |fcx| async move {
            let meter = Meter::new();
            let guard = meter.watch(&fcx.graph().environment);
            for _ in 0..66 {
                meter.sent(0, &Packet(vec![1]));
            }
            let before = guard.tap.since(0, 100);
            assert_eq!(before.len(), 65);
            assert!(before.iter().all(|copy| copy.at == Instant::ZERO));
            fcx.sleep(WINDOW).await?;
            assert_eq!(fcx.graph().since_start(), WINDOW);
            meter.sent(0, &Packet(vec![2]));
            let after = guard.tap.since(65, 100);
            assert_eq!(after.len(), 1);
            assert_eq!(after[0].at.since_start(), WINDOW);
            assert_eq!(after[0].skipped, 1);
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn sampling_keeps_the_first_packets_then_thins_out() {
        let kept: Vec<u64> = (0..256).filter(|&k| keep(k)).collect();
        assert_eq!(kept.len(), 64 + 32 + 16 + 8);
        assert!(kept[..64].iter().copied().eq(0..64));
        assert_eq!(&kept[64..67], &[64, 66, 68]);
    }

    #[test]
    fn a_tap_copies_only_while_watched_and_is_bounded() {
        let meter = Meter::new();
        meter.sent(0, &Packet(vec![1; 10]));
        let guard = meter.watch(&Arc::new(crate::entropy::RunEnvironment::new(
            crate::Seed::from_u64(0),
            crate::RunMode::Real,
        )));
        meter.sent(1, &Packet(vec![2; 10]));
        meter.sent(0, &Packet(vec![3; 10]));
        let copies = guard.tap.since(0, 100);
        assert_eq!(copies.len(), 2);
        assert_eq!(
            (copies[0].seq, copies[0].side, copies[0].data[0]),
            (1, 1, 2)
        );
        assert_eq!(guard.tap.since(1, 100).len(), 1);
        assert_eq!(meter.totals(), [2, 20, 1, 10]);
        drop(guard);
        assert!(!meter.tapped.load(Ordering::Relaxed));
        assert!(meter.tap.lock().is_none());

        // A flood within one window is sampled, and the skipped count is
        // carried by the next copy.
        let guard = meter.watch(&Arc::new(crate::entropy::RunEnvironment::new(
            crate::Seed::from_u64(0),
            crate::RunMode::Real,
        )));
        for _ in 0..1000 {
            meter.sent(0, &Packet(vec![0; 4]));
        }
        let copies = guard.tap.since(0, 10_000);
        assert!(copies.len() < 200, "{} copies", copies.len());
        let skipped: u64 = copies.iter().map(|c| c.skipped).sum();
        assert!(
            skipped + copies.len() as u64 <= 1000 && skipped > 300,
            "{skipped} skipped"
        );
    }
}
