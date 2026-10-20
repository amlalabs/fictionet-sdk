//! Link identity, counters, run registration and borrowed packet streams.
//! Core publishes topology and counters to the observer; consumers build graphs.

use fictionet::sync::{Mutex, MutexGuard};
#[cfg(feature = "std")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use crate::Packet;

/// The counts and packet stream of one link: a pair, or an attachment.
///
/// Side 0 and side 1 are the two ends. For an attachment, side 0 is the
/// world and side 1 the sandbox.
///
/// A pair counts its packets itself, as plain numbers under the lock it
/// takes for each packet anyway, and the meter reads them through
/// `counted`. An attachment counts in `counts`, with atomics.
/// Registration assigns a run-scoped link id. A tap installs a packet stream.
/// Without an observer the link does not register. A handle shares this
/// lightweight state, without retaining a topology graph.
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
    tap: AtomicPtr<Arc<str>>,
    // Names stay at stable addresses until the stream is dropped.
    #[expect(clippy::vec_box, reason = "packet readers borrow names across renames")]
    names: Mutex<Vec<Box<Arc<str>>>>,
    sandbox: Option<Arc<str>>,
}

impl PacketStream {
    fn name(&self) -> &str {
        // SAFETY: The pointer names an immutable box owned by names. Renaming
        // only appends boxes, so this borrow stays valid for the stream's life.
        unsafe { &*self.tap.load(Ordering::Acquire) }
    }

    fn rename(&self, name: Arc<str>) {
        let mut name = Box::new(name);
        let pointer = &mut *name as *mut Arc<str>;
        self.names.lock().push(name);
        self.tap.store(pointer, Ordering::Release);
    }

    fn reference<'a>(
        &'a self,
        tap: &'a str,
        side: usize,
        packet: &'a Packet,
    ) -> crate::events::PacketRef<'a> {
        crate::events::PacketRef {
            link: self.link,
            tap,
            sandbox: self.sandbox.as_deref(),
            side: if side == 0 {
                crate::events::Side::A
            } else {
                crate::events::Side::B
            },
            len: packet.0.len(),
            link_type: crate::events::LinkType::Ip,
            bytes: &packet.0,
        }
    }

    pub(crate) fn packet(&self, side: usize, packet: &Packet) -> Option<Publication<'_>> {
        let tap = self.name();
        self.observer
            .enabled(crate::events::Interest::Packet(
                self.reference(tap, side, packet),
            ))
            .then(|| Publication {
                stream: self,
                sequence: self.sequence.lock(),
                side,
                tap,
            })
    }
}

pub(crate) struct Publication<'a> {
    stream: &'a PacketStream,
    sequence: MutexGuard<'a, u64>,
    side: usize,
    tap: &'a str,
}

impl Publication<'_> {
    pub(crate) fn publish(&mut self, packet: &Packet) {
        self.stream.observer.packet(
            &mut self.sequence,
            self.stream.reference(self.tap, self.side, packet),
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
                self.register_tapped(observer);
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

    pub(crate) fn register_tapped(self: &Arc<Self>, observer: &Arc<crate::events::Dispatch>) {
        self.register(observer);
        if let Some(r) = self.registration.lock().as_ref()
            && r.observer.run_id == observer.run_id
            && !r.ended
            && self.packets.get().is_none()
            && let Some(name) = self.sandbox.get()
        {
            self.install_packets(r, name);
            r.observer
                .topology(crate::events::TopologyRef::LinkTap { link: r.link, name });
        }
    }

    fn install_packets(&self, r: &Registration, name: &Arc<str>) {
        if let Some(packets) = self.packets.get() {
            packets.rename(name.clone());
            return;
        }
        let mut name = Box::new(name.clone());
        let packets = Arc::new(PacketStream {
            observer: r.observer.clone(),
            link: r.link,
            sequence: Mutex::new(0),
            tap: AtomicPtr::new(&mut *name),
            names: Mutex::new(vec![name]),
            sandbox: self.sandbox.get().cloned(),
        });
        assert!(self.packets.set(packets.clone()).is_ok());
        if let Some(counted) = self.counted.get().and_then(Weak::upgrade) {
            counted.observe_packets(packets);
        }
    }

    #[cold]
    pub(crate) fn owner(self: &Arc<Self>, fcx: &crate::Cx, side: usize, task: u64) {
        use crate::events::{Side, TaskId, TopologyRef};
        let Some(observer) = fcx.run.observer.shared() else {
            return;
        };
        self.register_tapped(observer);
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

    pub(crate) fn tap(self: &Arc<Self>, fcx: &crate::Cx, name: &str) {
        let Some(observer) = fcx.run.observer.shared() else {
            return;
        };
        self.register(observer);
        let registration = self.registration.lock();
        if let Some(r) = registration.as_ref()
            && (r.observer.run_id != fcx.run.observer.run_id || r.ended)
        {
            return;
        }
        let name: Arc<str> = name.into();
        if let Some(r) = registration.as_ref() {
            self.install_packets(r, &name);
            r.observer.topology(crate::events::TopologyRef::LinkTap {
                link: r.link,
                name: &name,
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
    pub(crate) fn set_sandbox(&self, name: Arc<str>) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "callers set the sandbox once, on a meter just made by Meter::new or pair_with_guard"
        )]
        let _ = self.sandbox.set(name);
    }

    /// Uses `counted` as the source of link counters.
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

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn unobserved_links_do_not_register() {
        use crate::{Interface, InterfaceExt};
        crate::block_on(crate::lab(
            crate::RunOptions::new(crate::Seed::from_u64(1)),
            |cx| async move {
                let (mut a, mut b) = crate::pair();
                a = cx.tap("link", a);
                a.send(crate::Packet(vec![1]));
                b.recv(&cx).await?;
                assert!(a.meter().registration.lock().is_none());
                assert!(a.meter().packets.get().is_none());
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn attachment_names_share_storage_with_default_taps() {
        use crate::Interface;
        for observed in [false, true] {
            let (attacher, mut attachments) = crate::attachments();
            let sandbox = attacher.attach("guest").unwrap();
            let mut options = crate::RunOptions::new(crate::Seed::from_u64(1));
            if observed {
                options = options.observer(Arc::new(Topology::default()));
            }
            crate::block_on(crate::lab(options, |cx| async move {
                let attachment = attachments.next(&cx).await?;
                let meter = sandbox.meter();
                let name = meter.sandbox.get().unwrap();
                assert_eq!(attachment.name().as_ptr(), name.as_ptr());
                assert_eq!(meter.registration.lock().is_some(), observed);
                assert_eq!(meter.packets.get().is_some(), observed);
                if let Some(packets) = meter.packets.get() {
                    assert_eq!(packets.name().as_ptr(), name.as_ptr());
                }
                assert_eq!(attachment.link().unwrap().0.sandbox.get(), Some(name));
                Ok(())
            }))
            .unwrap();
        }
    }

    #[test]
    fn borrowed_tap_names_survive_renames() {
        crate::block_on(crate::lab(
            crate::RunOptions::new(crate::Seed::from_u64(1))
                .observer(Arc::new(Topology::default())),
            |cx| async move {
                let (a, _b) = crate::pair();
                let mut a = cx.tap("first", a);
                let stream = a.meter().packets().unwrap();
                let first = stream.name();
                for i in 0..32 {
                    let name = format!("tap {i}");
                    a = cx.tap(&name, a);
                    assert_eq!(stream.name(), name);
                    assert_eq!(first, "first");
                }
                Ok(())
            },
        ))
        .unwrap();
    }

    #[derive(Default)]
    struct Topology {
        tasks: Mutex<HashMap<u64, crate::events::Origin>>,
        live: Mutex<HashSet<u64>>,
        links: Mutex<HashMap<crate::events::LinkId, Link>>,
        ended: std::sync::atomic::AtomicBool,
    }

    #[derive(Default)]
    struct Link {
        creator: u64,
        owners: [u64; 2],
        tap: Option<String>,
    }

    impl crate::events::Observer for Topology {
        fn enabled(&self, interest: crate::events::Interest<'_>) -> bool {
            matches!(interest, crate::events::Interest::Topology(_))
        }
        fn observe(&self, _: crate::events::Stamp, item: crate::events::Observation<'_>) {
            use crate::events::{Observation, Side, TopologyRef};
            match item {
                Observation::Topology(TopologyRef::TaskAdded {
                    task,
                    parent,
                    name,
                    file,
                    line,
                    ..
                }) => {
                    self.tasks.lock().insert(
                        task.get(),
                        crate::events::Origin {
                            task: task.get(),
                            parent: parent.map_or(0, crate::events::TaskId::get),
                            name: name.to_owned().into(),
                            file,
                            line,
                        },
                    );
                    self.live.lock().insert(task.get());
                }
                Observation::Topology(TopologyRef::TaskRemoved { task }) => {
                    assert!(self.live.lock().remove(&task.get()));
                }
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
                Observation::Topology(TopologyRef::LinkTap { link, name }) => {
                    self.links.lock().get_mut(&link).unwrap().tap = Some(name.into());
                }
                _ => {}
            }
        }
        fn end(&self, _: crate::time::Instant) {
            self.ended.store(true, Ordering::Relaxed);
        }
    }

    /// The observer receives tasks, spawn locations, link owners and counters.
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
            *s.lock() = Some(a.meter().totals());
            drop(a);
            Ok(echo.join(&fcx).await?)
        }));
        out.unwrap();
        let totals = seen.lock().take().unwrap();
        let tasks = observer.tasks.lock();
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
        assert!(info.file.ends_with("link.rs"));
        assert_eq!(info.parent, *world);
        let links = observer.links.lock();
        assert_eq!(links.len(), 1);
        let link = links.values().next().unwrap();
        assert_eq!(link.owners, [*world, *echo]);
        assert_eq!(link.creator, *world);
        assert_eq!(totals, [10, 1000, 10, 1000]);
        // Once the run is over, its tasks are gone.
        assert!(observer.live.lock().is_empty());
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
                        let _d = foreign.tap("foreign", d);
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
        assert!(link.tap.is_none());
        let links = inner.links.lock();
        assert_eq!(links.len(), 1);
        let link = links.values().next().unwrap();
        assert_eq!(link.owners, [0, 0]);
        assert_eq!(link.creator, 1);
        assert!(link.tap.is_none());
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
        let observer = Arc::new(Topology::default());
        let spawn_line = Arc::new(AtomicU64::new(0));
        let line = spawn_line.clone();
        crate::block_on(crate::run(
            fictionet::RunOptions::new(fictionet::Seed::random()).observer(observer.clone()),
            |fcx| async move {
                let (a, _b) = crate::pair();
                line.store(u64::from(line!()) + 1, Ordering::Relaxed);
                let _f = crate::stdlib::network::filter(&fcx, a, |_, _, _| true);
                Ok(())
            },
        ))
        .unwrap();
        let tasks = observer.tasks.lock();
        assert!(
            tasks.values().any(|t| t.name == "filter"
                && t.file == file!()
                && u64::from(t.line) == spawn_line.load(Ordering::Relaxed)),
            "{tasks:?}"
        );
    }
}
