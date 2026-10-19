//! Link counters, stream registration, and task origins.

use fictionet::sync::{Mutex, MutexGuard};

use std::borrow::Cow;
use std::collections::HashMap;
use std::panic::Location;
#[cfg(feature = "std")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use crate::Packet;

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

/// The counts and packet stream of one link: a pair, or an attachment.
///
/// Side 0 and side 1 are the two ends. For an attachment, side 0 is the
/// world and side 1 the sandbox.
///
/// A pair counts its packets itself, as plain numbers under the lock it
/// takes for each packet anyway, and the meter reads them through
/// `counted`. An attachment counts in `counts`, with atomics.
pub(crate) struct Meter {
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
            registration: Mutex::new(None),
            packets: OnceLock::new(),
            #[cfg(feature = "std")]
            counts: Default::default(),
            counted: OnceLock::new(),
            creator: crate::run::RunTask::current(),
            sandbox: OnceLock::new(),
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

    /// Counts a packet that end `side` sent.
    #[inline]
    #[cfg(feature = "std")]
    pub(crate) fn sent(&self, side: usize, packet: &Packet) {
        let c = &self.counts[side];
        c.packets.fetch_add(1, Ordering::Relaxed);
        c.bytes.fetch_add(packet.0.len() as u64, Ordering::Relaxed);
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
}

/// Whatever counts a link's packets itself.
pub(crate) trait Counted: Send + Sync {
    /// `[packets 0, bytes 0, packets 1, bytes 1]`, by the side that sent.
    fn totals(&self) -> [u64; 4];
    fn observe_packets(&self, packets: Arc<PacketStream>);
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
}

/// Task origins retained while their tasks are running.
pub(crate) struct Graph {
    pub(crate) run_id: u64,
    #[cfg(feature = "std")]
    pub(crate) environment: Arc<crate::environment::RunEnvironment>,
    state: Mutex<GraphState>,
}

#[derive(Default)]
pub(crate) struct GraphState {
    pub(crate) tasks: HashMap<u64, TaskInfo, Ids>,
}

impl Graph {
    pub(crate) fn new(
        run_id: u64,
        environment: Arc<crate::environment::RunEnvironment>,
    ) -> Arc<Graph> {
        #[cfg(not(feature = "std"))]
        let _ = environment;
        Arc::new(Graph {
            run_id,
            #[cfg(feature = "std")]
            environment,
            state: Mutex::default(),
        })
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, GraphState> {
        self.state.lock()
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
        };
        let mut s = self.state();
        s.tasks.insert(id, info);
    }

    pub(crate) fn task_ended(&self, id: u64) {
        let mut s = self.state();
        let removed = s.tasks.remove(&id);
        drop(s);
        drop(removed);
    }

    pub(crate) fn run_ended(&self) {
        let mut s = self.state();
        let tasks = std::mem::take(&mut s.tasks);
        drop(s);
        drop(tasks);
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

    #[derive(Default)]
    struct Topology {
        links: Mutex<HashMap<crate::events::LinkId, Link>>,
        ended: std::sync::atomic::AtomicBool,
    }

    #[derive(Default)]
    struct Link {
        creator: u64,
        owners: [u64; 2],
        label: Option<String>,
    }

    impl crate::events::Observer for Topology {
        fn enabled(&self, interest: crate::events::Interest<'_>) -> bool {
            matches!(interest, crate::events::Interest::Topology(_))
        }
        fn observe(&self, _: crate::events::Stamp, item: crate::events::Observation<'_>) {
            use crate::events::{Observation, Side, TopologyRef};
            match item {
                Observation::Topology(TopologyRef::LinkAdded { link, creator, .. }) => {
                    self.links.lock().insert(
                        link,
                        Link {
                            creator: creator.map_or(0, crate::events::TaskId::get),
                            ..Link::default()
                        },
                    );
                }
                Observation::Topology(TopologyRef::LinkOwner { link, side, task }) => {
                    self.links.lock().get_mut(&link).unwrap().owners
                        [usize::from(side == Side::B)] = task.get();
                }
                Observation::Topology(TopologyRef::LinkLabel { link, label }) => {
                    self.links.lock().get_mut(&link).unwrap().label = Some(label.into());
                }
                _ => {}
            }
        }
        fn end(&self, _: crate::time::Instant) {
            self.ended.store(true, Ordering::Relaxed);
        }
    }

    /// A watched run knows its tasks, where they were spawned, which task
    /// uses which end of a pair, and how much went each way.
    #[test]
    fn a_watched_run_records_tasks_owners_and_counts() {
        use crate::Interface;
        use crate::prelude::*;
        let sink = Arc::new(Topology::default());
        let shared = crate::run::RunShared::with_options(
            crate::RunOptions::new(crate::Seed::random()).observer(sink.clone()),
            crate::RunMode::Real,
        );
        let observer = sink.clone();
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
            *s.lock() = Some((g.state().tasks.clone(), a.meter().totals()));
            drop(a);
            Ok(echo.join(&fcx).await?)
        }));
        out.unwrap();
        let (tasks, totals) = seen.lock().take().unwrap();
        let world = tasks
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
        let links = observer.links.lock();
        assert_eq!(links.len(), 1);
        let link = links.values().next().unwrap();
        assert_eq!(link.owners, [*world, *echo]);
        assert_eq!(link.creator, *world);
        assert_eq!(totals, [10, 1000, 10, 1000]);
        // Once the run is over, its tasks are gone.
        assert!(graph.state().tasks.is_empty());
        assert!(observer.ended.load(Ordering::Relaxed));
    }

    #[test]
    fn link_owners_and_creators_stay_in_their_run() {
        use crate::{Interface, InterfaceExt};
        let outer = Arc::new(Topology::default());
        let inner = Arc::new(Topology::default());
        let nested = inner.clone();
        crate::block_on(crate::lab(
            crate::RunOptions::new(crate::Seed::from_u64(1)).observer(outer.clone()),
            |fcx| async move {
                let (mut a, mut b) = crate::pair();
                a.send(Packet(vec![1]));
                b.recv(&fcx).await?;
                let foreign = fcx;
                crate::lab(
                    crate::RunOptions::new(crate::Seed::from_u64(2)).observer(nested),
                    move |fcx| async move {
                        a.send(Packet(vec![2]));
                        b.recv(&fcx).await?;
                        let (mut c, mut d) = crate::pair();
                        c.send(Packet(vec![3]));
                        d.recv(&foreign).await?;
                        d.link().unwrap().label(&foreign, "foreign".into());
                        Ok(())
                    },
                )
                .await
            },
        ))
        .unwrap();
        let links = outer.links.lock();
        assert_eq!(links.len(), 1);
        let link = links.values().next().unwrap();
        assert_eq!(link.owners, [0, 1]);
        assert_eq!(link.creator, 1);
        assert!(link.label.is_none());
        let links = inner.links.lock();
        assert_eq!(links.len(), 1);
        let link = links.values().next().unwrap();
        assert_eq!(link.owners, [0, 0]);
        assert_eq!(link.creator, 1);
        assert!(link.label.is_none());
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
    /// `filter` shows as `filter`, at the line that called it.
    #[test]
    fn filter_reports_its_caller() {
        crate::block_on(crate::run(
            fictionet::RunOptions::new(fictionet::Seed::random()),
            |fcx| async move {
                let (a, _b) = crate::pair();
                let line = line!() + 1;
                let _f = crate::stdlib::network::filter(&fcx, a, |_, _, _| true);
                let tasks: Vec<_> = fcx.graph().state().tasks.values().cloned().collect();
                assert!(
                    tasks
                        .iter()
                        .any(|t| t.name == "filter" && t.file == file!() && t.line == line),
                    "{tasks:?}"
                );
                Ok(())
            },
        ))
        .unwrap();
    }
}
