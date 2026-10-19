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
    registration: Mutex<Option<Registration>>,
    packets: OnceLock<Arc<PacketStream>>,
    /// What end `s` sent, for an attachment.
    #[cfg(feature = "std")]
    counts: [Count; 2],
    /// What holds the counts of a pair.
    counted: OnceLock<Weak<dyn Counted>>,
    /// The task that made the link, if any.
    creator: Option<crate::run::RunTask>,
    /// For an attachment: the sandbox's name. Side 1 is the sandbox.
    sandbox: OnceLock<Arc<str>>,
    /// Set while a viewer watches: `send` then copies packets into `tap`.
    #[cfg(any(feature = "observe", all(test, feature = "std")))]
    tapped: AtomicBool,
    #[cfg(any(feature = "observe", all(test, feature = "std")))]
    tap: Mutex<Option<Arc<Tap>>>,
}

pub(crate) struct PacketStream {
    observer: Arc<crate::events::Dispatch>,
    link: crate::events::LinkId,
    sequence: Mutex<u64>,
}

impl PacketStream {
    pub(crate) fn packet(&self, side: usize, packet: &Packet) -> Option<Publication<'_>> {
        let stream = self;
        let meta = crate::events::PacketMeta {
            link: stream.link,
            side: if side == 0 {
                crate::events::Side::A
            } else {
                crate::events::Side::B
            },
            len: packet.0.len(),
            link_type: crate::events::LinkType::Ip,
        };
        stream
            .observer
            .enabled(crate::events::Interest::Packet(meta))
            .then(|| Publication {
                stream,
                sequence: stream.sequence.lock(),
                meta,
            })
    }
}

pub(crate) struct Publication<'a> {
    stream: &'a PacketStream,
    sequence: MutexGuard<'a, u64>,
    meta: crate::events::PacketMeta,
}

impl Publication<'_> {
    pub(crate) fn publish(&mut self, packet: &Packet) {
        self.stream.observer.packet(
            &mut self.sequence,
            crate::events::PacketRef {
                link: self.meta.link,
                side: self.meta.side,
                len: self.meta.len,
                link_type: self.meta.link_type,
                bytes: &packet.0,
            },
        );
    }
}

struct Registration {
    observer: Arc<crate::events::Dispatch>,
    link: crate::events::LinkId,
    host: Option<crate::events::HostId>,
    owners: [Option<crate::events::TaskId>; 2],
    ended: bool,
}

impl Drop for Meter {
    fn drop(&mut self) {
        self.close(self.totals());
    }
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
            registration: Mutex::new(None),
            packets: OnceLock::new(),
            #[cfg(feature = "std")]
            counts: Default::default(),
            counted: OnceLock::new(),
            creator: crate::run::RunTask::current(),
            sandbox: OnceLock::new(),
            #[cfg(any(feature = "observe", all(test, feature = "std")))]
            tapped: AtomicBool::new(false),
            #[cfg(any(feature = "observe", all(test, feature = "std")))]
            tap: Mutex::new(None),
        })
    }

    pub(crate) fn packets(&self) -> Option<Arc<PacketStream>> {
        self.packets.get().cloned()
    }

    pub(crate) fn link_id(&self) -> Option<crate::events::LinkId> {
        self.registration
            .lock()
            .as_ref()
            .map(|registration| registration.link)
    }

    pub(crate) fn register_current(self: &Arc<Self>) {
        crate::run::with_dispatch(|observer| {
            if let Some(observer) = observer {
                self.register(observer);
            }
        });
    }

    #[cold]
    pub(crate) fn register(self: &Arc<Self>, observer: &Arc<crate::events::Dispatch>) {
        use crate::events::{LinkCounters, TaskId, TopologyRef};
        if !observer.installed() {
            return;
        }
        let mut registration = self.registration.lock();
        if registration.is_some() {
            return;
        }
        let link = observer.next_link();
        let packets = Arc::new(PacketStream {
            observer: observer.clone(),
            link,
            sequence: Mutex::new(0),
        });
        assert!(self.packets.set(packets.clone()).is_ok());
        if let Some(counted) = self.counted.get().and_then(Weak::upgrade) {
            counted.observe_packets(packets);
        }
        let sandbox = self.sandbox.get();
        let host = sandbox.map(|_| observer.next_host());
        *registration = Some(Registration {
            observer: observer.clone(),
            link,
            host,
            owners: [None; 2],
            ended: false,
        });
        if let (Some(name), Some(host)) = (sandbox, host) {
            observer.topology(TopologyRef::HostAdded {
                host,
                name,
                group: None,
                sandbox: Some(name),
            });
        }
        observer.topology(TopologyRef::LinkAdded {
            link,
            creator: self
                .creator
                .filter(|task| task.run == observer.run_id)
                .map(|task| TaskId(task.id)),
            sandbox: sandbox.map(AsRef::as_ref),
            host,
            counters: LinkCounters(Arc::downgrade(self)),
        });
    }

    #[cold]
    pub(crate) fn owner(self: &Arc<Self>, fcx: &crate::Cx, side: usize, task: u64) {
        use crate::events::{Side, TaskId, TopologyRef};
        let Some(observer) = fcx.run.observer.shared() else {
            return;
        };
        self.register(observer);
        let mut registration = self.registration.lock();
        if let Some(r) = registration.as_mut()
            && r.observer.run_id == fcx.run.observer.run_id
            && !r.ended
            && r.owners[side] != Some(TaskId(task))
        {
            r.owners[side] = Some(TaskId(task));
            r.observer.topology(TopologyRef::LinkOwner {
                link: r.link,
                side: if side == 0 { Side::A } else { Side::B },
                task: TaskId(task),
            });
        }
    }

    pub(crate) fn label(self: &Arc<Self>, fcx: &crate::Cx, label: &str) {
        let Some(observer) = fcx.run.observer.shared() else {
            return;
        };
        self.register(observer);
        if let Some(r) = self.registration.lock().as_ref()
            && r.observer.run_id == fcx.run.observer.run_id
            && !r.ended
        {
            r.observer.topology(crate::events::TopologyRef::LinkLabel {
                link: r.link,
                label,
            });
        }
    }

    pub(crate) fn close_attachment(&self) {
        if self.sandbox.get().is_some() {
            self.close(self.totals());
        }
    }

    pub(crate) fn close(&self, totals: [u64; 4]) {
        use crate::events::TopologyRef;
        if let Some(r) = self.registration.lock().as_mut()
            && !r.ended
        {
            r.ended = true;
            r.observer.topology(TopologyRef::LinkRemoved {
                link: r.link,
                totals: crate::events::streams::counts(totals),
            });
            if let Some(host) = r.host {
                r.observer.topology(TopologyRef::HostRemoved { host });
            }
        }
    }

    /// Marks side 1 as the sandbox called `name`.
    pub(crate) fn set_sandbox(&self, name: &str) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "callers set the sandbox once, on a meter just made by Meter::new or pair_with_guard"
        )]
        let _ = self.sandbox.set(Arc::from(name));
    }

    /// Reads the counts from `counted` from now on.
    pub(crate) fn count_in(&self, counted: Weak<dyn Counted>) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the only caller, cable::make, sets it once, right after Meter::new"
        )]
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
    pub(crate) fn totals(&self) -> [u64; 4] {
        if let Some(counted) = self.counted.get() {
            return counted.upgrade().map_or([0; 4], |c| c.totals());
        }
        #[cfg(not(feature = "std"))]
        {
            [0; 4]
        }
        #[cfg(feature = "std")]
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
        environment: &Arc<crate::environment::RunEnvironment>,
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
    fn totals(&self) -> [u64; 4];
    fn observe_packets(&self, packets: Arc<PacketStream>);
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
    environment: Arc<crate::environment::RunEnvironment>,
    viewers: AtomicUsize,
    state: Mutex<TapState>,
}

#[cfg(any(feature = "observe", all(test, feature = "std")))]
struct TapState {
    copies: VecDeque<Copy>,
    bytes: usize,
    max_packets: usize,
    max_bytes: usize,
    next_seq: u64,
    window_start: Instant,
    in_window: u64,
    skipped: u64,
}

#[cfg(any(feature = "observe", all(test, feature = "std")))]
impl Tap {
    fn new(environment: Arc<crate::environment::RunEnvironment>) -> Tap {
        Tap {
            environment,
            viewers: AtomicUsize::new(0),
            state: Mutex::new(TapState {
                copies: VecDeque::new(),
                bytes: 0,
                max_packets: TAP_PACKETS,
                max_bytes: TAP_BYTES,
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
        while s.copies.len() > s.max_packets || s.bytes > s.max_bytes {
            let Some(old) = s.copies.pop_front() else {
                break;
            };
            s.bytes -= old.data.len();
        }
    }

    /// Copies after `after`, at most `max`, and how many copies before
    /// them were evicted. An empty buffer can still report eviction.
    pub(crate) fn since(&self, after: u64, max: usize) -> (u64, Vec<Copy>) {
        let s = self.state.lock();
        let first = s.copies.front().map_or(s.next_seq, |c| c.seq);
        let missed = first.saturating_sub(after.saturating_add(1));
        let skip = s.copies.partition_point(|c| c.seq <= after);
        (
            missed,
            s.copies.iter().skip(skip).take(max).cloned().collect(),
        )
    }

    #[cfg(test)]
    pub(crate) fn set_limits(&self, packets: usize, bytes: usize) {
        let mut s = self.state.lock();
        s.max_packets = packets;
        s.max_bytes = bytes;
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
pub(crate) struct Group {
    pub(crate) id: u64,
    pub(crate) name: String,
    pub(crate) parent: Option<Arc<Group>>,
    observer: Option<Arc<crate::events::Dispatch>>,
    pub(crate) host: Option<crate::events::HostId>,
}

impl std::fmt::Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Group")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("parent", &self.parent)
            .finish_non_exhaustive()
    }
}

impl Group {
    pub(crate) fn new(
        id: u64,
        name: String,
        parent: Option<Arc<Group>>,
        observer: Option<Arc<crate::events::Dispatch>>,
        host: bool,
    ) -> Arc<Group> {
        use crate::events::{GroupId, TopologyRef};
        let host = observer.as_ref().filter(|_| host).map(|o| o.next_host());
        let group = Arc::new(Group {
            id,
            name,
            parent,
            observer,
            host,
        });
        if let Some(observer) = &group.observer {
            observer.topology(TopologyRef::GroupAdded {
                group: GroupId(id),
                name: &group.name,
                parent: group.parent.as_ref().map(|p| GroupId(p.id)),
            });
            if let Some(host) = group.host {
                observer.topology(TopologyRef::HostAdded {
                    host,
                    name: &group.name,
                    group: Some(GroupId(id)),
                    sandbox: None,
                });
            }
        }
        group
    }

    /// This group and the groups it is inside, innermost first.
    #[cfg(feature = "observe")]
    pub(crate) fn chain(self: &Arc<Self>) -> impl Iterator<Item = &Arc<Group>> {
        std::iter::successors(Some(self), |g| g.parent.as_ref())
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        use crate::events::{GroupId, TopologyRef};
        if let Some(observer) = &self.observer {
            if let Some(host) = self.host {
                observer.topology(TopologyRef::HostRemoved { host });
            }
            observer.topology(TopologyRef::GroupRemoved {
                group: GroupId(self.id),
            });
        }
    }
}

/// A task as observers see it.
#[derive(Clone, Debug)]
pub(crate) struct TaskInfo {
    pub(crate) parent: u64,
    /// The group the task belongs to, if any.
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

/// What a run records about itself for observers.
///
/// Every run keeps one. Starting a task, and a task taking an end of a
/// link, each take its lock once. Packets never do.
pub(crate) struct Graph {
    pub(crate) run_id: u64,
    #[cfg(feature = "std")]
    pub(crate) environment: Arc<crate::environment::RunEnvironment>,
    #[cfg(feature = "observe")]
    pub(crate) start_wall: SystemTime,
    /// Observer sessions connected to the world. While there are none,
    /// packet copies and TLS keys are not kept.
    pub(crate) viewers: AtomicUsize,
    /// Event history explicitly installed by the world socket's owner.
    #[cfg(feature = "observe")]
    pub(crate) events: Option<Arc<crate::events::Memory>>,
    /// TLS keys recorded by the run's protocol producers.
    #[cfg(feature = "observe")]
    pub(crate) keys: Arc<crate::telemetry::KeyRecorder>,
    state: Mutex<GraphState>,
    /// Application decoders for links watched from now on.
    pub(crate) protocols: Mutex<crate::observe::Registry>,
    /// Watched links, so observers of one link share one decoded copy.
    #[cfg(feature = "observe")]
    pub(crate) watches: crate::observe::WatchSet,
}

#[derive(Default)]
pub(crate) struct GraphState {
    pub(crate) revision: u64,
    pub(crate) tasks: HashMap<u64, TaskInfo, Ids>,
    pub(crate) links: HashMap<u64, LinkInfo, Ids>,
    /// The link count at which dead links are next swept out.
    sweep_at: usize,
    /// The run has ended.
    pub(crate) ended: bool,
}

impl Graph {
    pub(crate) fn new(
        run_id: u64,
        environment: Arc<crate::environment::RunEnvironment>,
        start_wall: SystemTime,
        events: Option<Arc<crate::events::Memory>>,
        #[cfg(feature = "observe")] keys: Arc<crate::telemetry::KeyRecorder>,
    ) -> Arc<Graph> {
        #[cfg(not(feature = "std"))]
        let _ = environment;
        #[cfg(not(feature = "observe"))]
        let _ = (start_wall, events);
        Arc::new(Graph {
            run_id,
            #[cfg(feature = "std")]
            environment,
            #[cfg(feature = "observe")]
            start_wall,
            viewers: AtomicUsize::new(0),
            state: Mutex::new(GraphState {
                sweep_at: 64,
                ..GraphState::default()
            }),
            #[cfg(feature = "observe")]
            events,
            #[cfg(feature = "observe")]
            keys,
            #[cfg(feature = "observe")]
            watches: crate::observe::WatchSet::default(),
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

    pub(crate) fn task_started(
        &self,
        id: u64,
        name: Cow<'static, str>,
        location: &'static Location<'static>,
        group: Option<Arc<Group>>,
    ) {
        let info = TaskInfo {
            parent: crate::run::current_task(self),
            group,
            name,
            file: location.file(),
            line: location.line(),
            #[cfg(feature = "observe")]
            started: self.since_start(),
        };
        let mut s = self.state();
        s.tasks.insert(id, info);
        s.revision += 1;
    }

    pub(crate) fn task_ended(&self, id: u64) {
        let mut s = self.state();
        let removed = s.tasks.remove(&id);
        if removed.is_some() {
            s.revision += 1;
        }
        drop(s);
        drop(removed);
    }

    pub(crate) fn run_ended(&self) {
        let mut s = self.state();
        s.ended = true;
        s.revision += 1;
        let tasks = std::mem::take(&mut s.tasks);
        drop(s);
        drop(tasks);
    }

    fn link<'a>(&self, s: &'a mut GraphState, meter: &Arc<Meter>) -> &'a mut LinkInfo {
        s.revision += 1;
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
            creator: meter.creator.map_or(0, |t| t.in_graph(self)),
            sandbox: meter.sandbox.get().cloned(),
            label: None,
        })
    }

    /// Records that `task` uses end `side` of `meter`.
    #[cold]
    pub(crate) fn owns(&self, meter: &Arc<Meter>, side: usize, task: u64) {
        let mut s = self.state();
        let link = self.link(&mut s, meter);
        link.owners[side] = task;
        if link.sandbox.is_none() {
            link.sandbox = meter.sandbox.get().cloned();
        }
    }

    /// Gives a link a label, such as the prefix a router sends to it.
    pub(crate) fn label(&self, meter: &Arc<Meter>, label: String) {
        let mut s = self.state();
        self.link(&mut s, meter).label = Some(Arc::from(label));
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
}

/// The name of a task's future type, for [`TaskInfo::name`].
pub(crate) fn task_name<T: ?Sized>() -> Cow<'static, str> {
    Cow::Borrowed(std::any::type_name::<T>())
}

/// A short name for a task, from the type of its future: the last two
/// path segments, without closures and generics.
/// `fictionet::stdlib::web::net::pings::{{closure}}` becomes `net::pings`.
/// A name with no path, such as `delay`, stays as it is.
pub fn short_name(full: &str) -> String {
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
    fn unobserved_links_do_not_register() {
        use crate::{Interface, InterfaceExt};
        crate::block_on(crate::lab(
            crate::RunOptions::new(crate::Seed::from_u64(1)),
            |cx| async move {
                let (mut a, mut b) = crate::pair();
                a.link().unwrap().label(&cx, "link".into());
                a.send(crate::Packet(vec![1]));
                b.recv(&cx).await?;
                assert!(a.meter().registration.lock().is_none());
                Ok(())
            },
        ))
        .unwrap();
    }

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
        let shared = crate::run::RunShared::new(crate::Seed::random(), crate::RunMode::Real);
        let graph = shared.graph.clone();
        let g = graph.clone();
        let (spawn_line, seen) = (Arc::new(AtomicU64::new(0)), Arc::new(Mutex::new(None)));
        let (line, s) = (spawn_line.clone(), seen.clone());
        let out = crate::block_on(crate::run::run_with(shared, move |fcx| async move {
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

    #[test]
    fn link_owners_and_creators_stay_in_their_run() {
        use crate::Interface;
        use crate::prelude::*;
        crate::block_on(crate::lab(
            fictionet::RunOptions::new(crate::Seed::from_u64(1)),
            |fcx| async move {
                let (mut a, mut b) = crate::pair();
                a.send(Packet(vec![1]));
                b.recv(&fcx).await?;
                assert_eq!(fcx.graph().state().links[&b.meter().id].owners, [0, 1]);
                #[cfg(feature = "observe")]
                assert_eq!(fcx.graph().state().links[&b.meter().id].creator, 1);

                let foreign = fcx;
                crate::lab(
                    fictionet::RunOptions::new(crate::Seed::from_u64(2)),
                    move |fcx| async move {
                        a.send(Packet(vec![2]));
                        b.recv(&fcx).await?;
                        // Both roots are task 1, but this end must be seen anew.
                        assert_eq!(fcx.graph().state().links[&b.meter().id].owners, [0, 1]);
                        #[cfg(feature = "observe")]
                        assert_eq!(fcx.graph().state().links[&b.meter().id].creator, 0);

                        let (mut c, mut d) = crate::pair();
                        c.send(Packet(vec![3]));
                        d.recv(&foreign).await?;
                        assert!(!foreign.graph().state().links.contains_key(&d.meter().id));
                        // Labeling also creates a graph entry, without ownership.
                        foreign.graph().label(d.meter(), "foreign".into());
                        let graph = foreign.graph().state();
                        let link = &graph.links[&d.meter().id];
                        assert_eq!(link.owners, [0, 0]);
                        #[cfg(feature = "observe")]
                        assert_eq!(link.creator, 0);
                        Ok(())
                    },
                )
                .await
            },
        ))
        .unwrap();
    }

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
        crate::block_on(crate::run(
            fictionet::RunOptions::new(fictionet::Seed::random()),
            |fcx| async move {
                let (mut a, mut b) = crate::pair();
                a.send(Packet(vec![0; 40]));
                b.recv(&fcx).await?;
                assert_eq!(a.meter().totals(), [1, 40, 0, 0]);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn graph_and_sampling_windows_use_lab_time() {
        crate::block_on(crate::lab(
            fictionet::RunOptions::new(crate::Seed::from_u64(0)),
            |fcx| async move {
                let meter = Meter::new();
                let guard = meter.watch(&fcx.graph().environment);
                for _ in 0..66 {
                    meter.sent(0, &Packet(vec![1]));
                }
                let (missed, before) = guard.tap.since(0, 100);
                assert_eq!(missed, 0);
                assert_eq!(before.len(), 65);
                assert!(before.iter().all(|copy| copy.at == Instant::ZERO));
                fcx.sleep(WINDOW).await?;
                assert_eq!(fcx.graph().since_start(), WINDOW);
                meter.sent(0, &Packet(vec![2]));
                let (missed, after) = guard.tap.since(65, 100);
                assert_eq!(missed, 0);
                assert_eq!(after.len(), 1);
                assert_eq!(after[0].at.since_start(), WINDOW);
                assert_eq!(after[0].skipped, 1);
                Ok(())
            },
        ))
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
    fn tap_reports_eviction_at_both_limits_and_at_cursor_boundaries() {
        for (packets, bytes) in [(2, TAP_BYTES), (TAP_PACKETS, 8)] {
            let tap = Tap::new(Arc::new(crate::environment::RunEnvironment::new(
                crate::Seed::from_u64(0),
                crate::RunMode::Lab,
            )));
            tap.set_limits(packets, bytes);
            for _ in 0..4 {
                tap.push(0, &[0; 4]);
            }
            let (missed, copies) = tap.since(0, 1);
            assert_eq!(missed, 2);
            assert_eq!(copies.len(), 1);
            assert_eq!(copies[0].seq, 3);
            assert_eq!(copies[0].skipped, 0);
            assert_eq!(tap.since(1, 10).0, 1);
            assert_eq!(tap.since(2, 10).0, 0);
            let (missed, copies) = tap.since(3, 10);
            assert_eq!(missed, 0);
            assert_eq!(copies[0].seq, 4);
            for after in [4, u64::MAX] {
                let (missed, copies) = tap.since(after, 10);
                assert_eq!(missed, 0);
                assert!(copies.is_empty());
            }
        }
    }

    #[test]
    fn tap_reports_eviction_even_when_no_copy_fits() {
        let tap = Tap::new(Arc::new(crate::environment::RunEnvironment::new(
            crate::Seed::from_u64(0),
            crate::RunMode::Lab,
        )));
        tap.set_limits(2, 4);
        assert_eq!(tap.since(0, 10).0, 0);
        tap.push(0, &[0; 5]);
        let (missed, copies) = tap.since(0, 10);
        assert_eq!(missed, 1);
        assert!(copies.is_empty());
        assert_eq!(tap.since(1, 10).0, 0);
        tap.push(0, &[0; 4]);
        let (missed, copies) = tap.since(1, 10);
        assert_eq!(missed, 0);
        assert_eq!(copies[0].seq, 2);
    }

    #[test]
    fn a_tap_copies_only_while_watched_and_is_bounded() {
        let meter = Meter::new();
        meter.sent(0, &Packet(vec![1; 10]));
        let guard = meter.watch(&Arc::new(crate::environment::RunEnvironment::new(
            crate::Seed::from_u64(0),
            crate::RunMode::Real,
        )));
        meter.sent(1, &Packet(vec![2; 10]));
        meter.sent(0, &Packet(vec![3; 10]));
        let (missed, copies) = guard.tap.since(0, 100);
        assert_eq!(missed, 0);
        assert_eq!(copies.len(), 2);
        assert_eq!(
            (copies[0].seq, copies[0].side, copies[0].data[0]),
            (1, 1, 2)
        );
        assert_eq!(guard.tap.since(1, 100).1.len(), 1);
        assert_eq!(meter.totals(), [2, 20, 1, 10]);
        drop(guard);
        assert!(!meter.tapped.load(Ordering::Relaxed));
        assert!(meter.tap.lock().is_none());

        // A flood within one window is sampled, and the skipped count is
        // carried by the next copy.
        let guard = meter.watch(&Arc::new(crate::environment::RunEnvironment::new(
            crate::Seed::from_u64(0),
            crate::RunMode::Real,
        )));
        for _ in 0..1000 {
            meter.sent(0, &Packet(vec![0; 4]));
        }
        let (missed, copies) = guard.tap.since(0, 10_000);
        assert_eq!(missed, 0);
        assert!(copies.len() < 200, "{} copies", copies.len());
        let skipped: u64 = copies.iter().map(|c| c.skipped).sum();
        assert!(
            skipped + copies.len() as u64 <= 1000 && skipped > 300,
            "{skipped} skipped"
        );
    }
}
