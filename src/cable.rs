use fictionet::sync::Mutex;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};

use crate::cx::CancelWait;
use crate::link::{Counted, Meter};
use crate::packet_queue::PacketQueue;
use crate::{Cx, Interface, Packet, RecvError};

/// Makes two connected [`Interface`]s and returns them.
///
/// A packet sent into one end comes out of the other, in order. Think of
/// the pair as a network cable with a plug at each end, as the diagram
/// below shows. Inside, it is two
/// queues, one for each direction, each with one sender and one receiver.
/// The queues have no size limit. Dropping either end closes both
/// directions.
///
#[doc = include_str!("../docs/diagrams/pair.svg")]
///
/// Both ends are `Send`, so they can be used from different threads.
///
/// `pair` is the basic building block: everything in
/// [`stdlib`](crate::stdlib) is wired together with it. A world uses it to
/// connect two pieces by hand, for example a
/// [router](crate::stdlib::network::route::router) and the machine behind one of its
/// routes. Sandboxes do not come from `pair`: each one reaches the
/// world as an [`Attachment`](crate::Attachment).
pub fn pair() -> (End, End) {
    make(None, None, true)
}

/// Makes a cable that drops `guard` when the cable closes, from either end.
/// [`Attacher`](crate::Attacher) uses this to hold a name until then.
pub(crate) fn pair_with_guard(guard: Option<Box<dyn Send>>) -> (End, End) {
    make(guard, None, false)
}

/// What a queued packet costs against a limit beyond its bytes: its place
/// in the queue. So a flood of tiny packets is bounded too.
pub const PACKET_COST: usize = 64;

/// Makes a [`pair`] whose queues each hold at most `limit` bytes, counting
/// each packet's length plus 64 bytes. A packet sent past that is dropped,
/// as on a congested link. Use it for links on the agent's path, where an
/// unlimited queue would let the agent grow the world's memory without
/// end.
pub fn pair_with_limit(limit: usize) -> (End, End) {
    make(None, Some(limit), true)
}

fn make(guard: Option<Box<dyn Send>>, limit: Option<usize>, register: bool) -> (End, End) {
    let cable = Arc::new(Cable {
        dirs: [
            Mutex::new(Direction::default()),
            Mutex::new(Direction::default()),
        ],
        guard: Mutex::new(guard),
        meter: Meter::new(),
        limit,
    });
    let counted: Weak<dyn Counted> = Arc::downgrade(&cable) as Weak<Cable>;
    cable.meter.count_in(counted);
    if register {
        cable.meter.register_current();
    }
    (
        End {
            packets: cable.meter.packets(),
            cable: cable.clone(),
            side: 0,
            wait: CancelWait::default(),
            seen: None,
        },
        End {
            packets: cable.meter.packets(),
            cable,
            side: 1,
            wait: CancelWait::default(),
            seen: None,
        },
    )
}

/// The state both ends share.
struct Cable {
    /// `dirs[i]` carries the packets that end `i` receives.
    dirs: [Mutex<Direction>; 2],
    /// Dropped when the first end is dropped.
    guard: Mutex<Option<Box<dyn Send>>>,
    /// Counters published to the observer.
    meter: Arc<Meter>,
    /// The most bytes each queue may hold, if limited.
    limit: Option<usize>,
}

/// One direction of a cable: a queue with one sender and one receiver.
#[derive(Default)]
struct Direction {
    queue: PacketQueue,
    /// The receiver waiting for a packet, if any.
    waker: Option<Waker>,
    /// One end was dropped.
    closed: bool,
    /// Packets and bytes put into this queue, published to the observer.
    packets: u64,
    bytes: u64,
    /// The packet stream after the link is tapped.
    observation: Option<Arc<crate::link::PacketStream>>,
}

/// One of the two connected [`Interface`]s made by [`pair`].
///
/// Dropping it closes the link. Packets still queued for this end are
/// lost. The other end receives what was already sent to it, and then
/// [`RecvError::Closed`].
pub struct End {
    packets: Option<Arc<crate::link::PacketStream>>,
    cable: Arc<Cable>,
    /// Which end this is: 0 or 1. It receives from `dirs[side]` and sends
    /// into `dirs[1 - side]`.
    side: usize,
    /// Where a receiver outside the run waits for a cancel.
    wait: CancelWait,
    /// The last task polling this end, published as link ownership.
    seen: Option<crate::run::RunTask>,
}

impl Interface for End {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(RecvError::Cancelled));
        }
        let current = crate::run::RunTask::current_in(fcx.run.id);
        if current != self.seen
            && let Some(task) = current
        {
            self.seen = current;
            self.cable.meter.owner(fcx, self.side, task.id);
        }
        {
            let mut dir = self.cable.dirs[self.side].lock();
            if let Some(packet) = dir.queue.pop() {
                return Poll::Ready(Ok(packet));
            }
            if dir.closed {
                return Poll::Ready(Err(RecvError::Closed));
            }
            match &dir.waker {
                Some(w) if w.will_wake(cx.waker()) => {}
                _ => dir.waker = Some(cx.waker().clone()),
            }
        }
        if fcx.register_cancel(cx.waker(), &mut self.wait) {
            return Poll::Ready(Err(RecvError::Cancelled));
        }
        Poll::Pending
    }

    fn send(&mut self, packet: Packet) {
        if let Some(stream) = &self.packets
            && let Some(publication) = stream.packet(self.side, &packet)
        {
            return send_observed(&self.cable, self.side, publication, packet);
        }
        let waker = {
            let mut dir = self.cable.dirs[1 - self.side].lock();
            if self.packets.is_none() && dir.observation.is_some() {
                // The link was tapped after this end was made.
                self.packets = dir.observation.clone();
                drop(dir);
                return self.send(packet);
            }
            if dir.closed {
                return;
            }
            let bytes = packet.0.len() as u64;
            if dir.queue.try_push(packet, self.cable.limit).is_err() {
                return;
            }
            dir.packets += 1;
            dir.bytes += bytes;
            dir.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn link(&self) -> Option<crate::LinkHandle> {
        Some(crate::LinkHandle::new(self.cable.meter.clone()))
    }
}

/// Sends a packet the run's observer wants. The packet is counted and
/// published only if it fits and the far end is open, and the observer is
/// called with no direction lock held. The per-link publication lock stays
/// held until the packet is queued, so the two ends publish in the order
/// their packets enter the link. The receiver can only make room meanwhile;
/// if its end closes first, the packet is lost as queued packets are.
#[cold]
fn send_observed(
    cable: &Cable,
    side: usize,
    mut publication: crate::link::Publication<'_>,
    packet: Packet,
) {
    {
        let mut dir = cable.dirs[1 - side].lock();
        if dir.closed || !dir.queue.fits(packet.0.len(), cable.limit) {
            return;
        }
        dir.packets += 1;
        dir.bytes += packet.0.len() as u64;
    }
    publication.publish(&packet);
    let waker = {
        let mut dir = cable.dirs[1 - side].lock();
        if dir.closed || dir.queue.try_push(packet, cable.limit).is_err() {
            return;
        }
        dir.waker.take()
    };
    drop(publication);
    if let Some(w) = waker {
        w.wake();
    }
}

impl Drop for End {
    fn drop(&mut self) {
        // Packets still queued for this end are lost. The other end reads
        // what is queued for it, then `Closed`.
        let lost = {
            let mut dir = self.cable.dirs[self.side].lock();
            dir.closed = true;
            dir.waker = None;
            std::mem::take(&mut dir.queue)
        };
        drop(lost);
        let waker = {
            let mut dir = self.cable.dirs[1 - self.side].lock();
            dir.closed = true;
            dir.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
        let guard = self.cable.guard.lock().take();
        drop(guard);
        if self.side == 0 {
            self.cable.meter.close_attachment();
        }
    }
}

impl End {
    /// The bytes waiting for this end to read, counted as for a limit.
    #[cfg(test)]
    pub(crate) fn queued(&self) -> usize {
        self.cable.dirs[self.side].lock().queue.bytes()
    }

    /// Whether the other end is gone.
    pub(crate) fn peer_gone(&self) -> bool {
        self.cable.dirs[self.side].lock().closed
    }

    /// The counters and packet stream of this end's pair.
    pub(crate) fn meter(&self) -> &Arc<Meter> {
        &self.cable.meter
    }
}

impl Drop for Cable {
    fn drop(&mut self) {
        self.meter.close(self.totals());
    }
}

impl Counted for Cable {
    fn observe_packets(&self, packets: Arc<crate::link::PacketStream>) {
        for direction in &self.dirs {
            direction.lock().observation = Some(packets.clone());
        }
    }

    fn totals(&self) -> [u64; 4] {
        // End `s` sends into `dirs[1 - s]`.
        let (p1, b1) = {
            let d = self.dirs[0].lock();
            (d.packets, d.bytes)
        };
        let (p0, b0) = {
            let d = self.dirs[1].lock();
            (d.packets, d.bytes)
        };
        [p0, b0, p1, b1]
    }
}

impl std::fmt::Debug for End {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("End").field("side", &self.side).finish()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{InterfaceExt, block_on, run};

    use crate::events::{
        Counts, Interest, LinkCounters, LinkId, LinkType, Observation, Observer, Side, Stamp,
        Stream, TopologyKind, TopologyRef,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct Captured {
        pub(crate) stamp: Stamp,
        pub(crate) side: Side,
        pub(crate) tap: String,
        pub(crate) sandbox: Option<String>,
        pub(crate) bytes: Vec<u8>,
    }

    pub(crate) struct PacketSink {
        pub(crate) enabled: AtomicBool,
        topology: bool,
        pub(crate) packets: Mutex<Vec<Captured>>,
        events: Mutex<Vec<Stamp>>,
        links: Mutex<Vec<(LinkId, LinkCounters)>>,
        taps: Mutex<Vec<(LinkId, String)>>,
    }

    impl PacketSink {
        pub(crate) fn new(enabled: bool, topology: bool) -> Self {
            Self {
                enabled: AtomicBool::new(enabled),
                topology,
                packets: Mutex::new(Vec::new()),
                events: Mutex::new(Vec::new()),
                links: Mutex::new(Vec::new()),
                taps: Mutex::new(Vec::new()),
            }
        }
    }

    impl Observer for PacketSink {
        fn enabled(&self, interest: Interest<'_>) -> bool {
            match interest {
                Interest::Packet(_) => self.enabled.load(Ordering::Relaxed),
                Interest::Event(..) => true,
                Interest::Topology(TopologyKind::Link) => self.topology,
                Interest::Topology(_) | Interest::TlsKey(_) => false,
            }
        }

        fn observe(&self, stamp: Stamp, item: Observation<'_>) {
            match item {
                Observation::Packet(packet) => {
                    assert_eq!(stamp.stream, Stream::Packets(packet.link));
                    assert_eq!(packet.link_type, LinkType::Ip);
                    assert_eq!(packet.len, packet.bytes.len());
                    self.packets.lock().push(Captured {
                        stamp,
                        side: packet.side,
                        tap: packet.tap.into(),
                        sandbox: packet.sandbox.map(str::to_owned),
                        bytes: packet.bytes.to_vec(),
                    });
                }
                Observation::Event(_) => self.events.lock().push(stamp),
                Observation::Topology(TopologyRef::LinkAdded { link, counters, .. }) => {
                    self.links.lock().push((link, counters))
                }
                Observation::Topology(TopologyRef::LinkTap { link, name }) => {
                    self.taps.lock().push((link, name.into()));
                }
                Observation::Topology(_) => {}
                Observation::TlsKey(_) => panic!("unexpected TLS key"),
            }
        }
    }

    #[test]
    fn crossings_are_numbered_per_link_and_repeat_with_lab_time() {
        fn sample() -> (Vec<Captured>, Vec<Stamp>) {
            let sink = Arc::new(PacketSink::new(true, true));
            let observer = sink.clone();
            block_on(crate::lab(
                crate::RunOptions::new(crate::Seed::from_u64(7)).observer(observer.clone()),
                |cx| async move {
                    let (mut a, mut b) = pair_with_limit(PACKET_COST + 3);
                    let (mut c, d) = pair();
                    a = cx.tap("first", a);
                    c = cx.tap("second", c);
                    cx.emit("test", "before", |event| event);
                    a.send(Packet(vec![1, 2, 3]));
                    a.send(Packet(vec![9]));
                    assert_eq!(b.recv(&cx).await?, Packet(vec![1, 2, 3]));
                    cx.sleep(crate::time::ms(10)).await?;
                    b.send(Packet(vec![4]));
                    c.send(Packet(vec![5, 6]));
                    cx.emit("test", "after", |event| event);
                    let counts = LinkCounters(Arc::downgrade(a.meter())).totals();
                    assert_eq!(
                        counts,
                        [
                            Counts {
                                packets: 1,
                                bytes: 3
                            },
                            Counts {
                                packets: 1,
                                bytes: 1
                            }
                        ]
                    );
                    drop(b);
                    a.send(Packet(vec![8]));
                    drop(d);
                    c.send(Packet(vec![8]));
                    Ok(())
                },
            ))
            .unwrap();
            let packets = sink.packets.lock().clone();
            assert_eq!(packets.len(), 3);
            assert_eq!(
                packets.iter().map(|p| p.stamp.seq).collect::<Vec<_>>(),
                [1, 2, 1]
            );
            assert_eq!(
                packets.iter().map(|p| p.side).collect::<Vec<_>>(),
                [Side::A, Side::B, Side::A]
            );
            assert_eq!(
                packets.iter().map(|p| p.bytes.clone()).collect::<Vec<_>>(),
                [vec![1, 2, 3], vec![4], vec![5, 6]]
            );
            assert_eq!(packets[0].stamp.at, crate::time::Instant::ZERO);
            assert_eq!(packets[1].stamp.at.since_start(), crate::time::ms(10));
            assert_eq!(packets[2].stamp.at, packets[1].stamp.at);
            assert_ne!(packets[0].stamp.stream, packets[2].stamp.stream);
            assert_eq!(sink.links.lock().len(), 2);
            let events = sink.events.lock().clone();
            (packets, events)
        }
        assert_eq!(sample(), sample());
    }

    #[test]
    fn tapping_one_end_observes_crossings_from_the_other() {
        let (mut a, mut b) = pair();
        let sink = Arc::new(PacketSink::new(true, false));
        block_on(crate::lab(
            crate::RunOptions::new(crate::Seed::from_u64(1)).observer(sink.clone()),
            |cx| async move {
                b = cx.tap("pair", b);
                assert!(
                    b.poll_recv(&cx, &mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                a.send(Packet(vec![1]));
                assert_eq!(b.recv(&cx).await?, Packet(vec![1]));
                Ok(())
            },
        ))
        .unwrap();
        let packets = sink.packets.lock();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].stamp.seq, 1);
    }

    #[test]
    fn changing_packet_interest_only_numbers_accepted_crossings() {
        let sink = Arc::new(PacketSink::new(false, false));
        let observer = sink.clone();
        block_on(crate::lab(
            crate::RunOptions::new(crate::Seed::from_u64(1)).observer(observer.clone()),
            |cx| async move {
                let (mut a, _b) = pair();
                a = cx.tap("pair", a);
                for (i, enabled) in [false, true, false, true].into_iter().enumerate() {
                    observer.enabled.store(enabled, Ordering::Relaxed);
                    a.send(Packet(vec![u8::try_from(i).unwrap()]));
                    cx.emit("test", "crossing", |event| event);
                }
                Ok(())
            },
        ))
        .unwrap();
        let packets = sink.packets.lock();
        assert_eq!(
            packets
                .iter()
                .map(|p| (p.stamp.seq, p.bytes[0]))
                .collect::<Vec<_>>(),
            [(1, 1), (2, 3)]
        );
        let events = sink.events.lock();
        assert!(
            events
                .iter()
                .enumerate()
                .all(|(i, event)| event.seq == i as u64 + 1)
        );
    }

    #[test]
    fn a_declining_check_reads_no_clock_and_numbers_nothing() {
        #[derive(Default)]
        struct EvenPackets(Mutex<Vec<(u64, u8)>>);
        impl Observer for EvenPackets {
            fn enabled(&self, interest: Interest<'_>) -> bool {
                matches!(interest, Interest::Packet(packet) if packet.bytes[0] % 2 == 0)
            }
            fn observe(&self, stamp: Stamp, item: Observation<'_>) {
                if let Observation::Packet(packet) = item {
                    self.0.lock().push((stamp.seq, packet.bytes[0]));
                }
            }
        }
        let sink = Arc::new(EvenPackets::default());
        block_on(crate::lab(
            crate::RunOptions::new(crate::Seed::from_u64(1)).observer(sink.clone()),
            |cx| async move {
                let (mut a, mut b) = pair();
                a = cx.tap("pair", a);
                for byte in 1..=6 {
                    let reads = cx.run.environment.clock.reads.load(Ordering::Relaxed);
                    a.send(Packet(vec![byte]));
                    assert_eq!(
                        cx.run.environment.clock.reads.load(Ordering::Relaxed),
                        reads + usize::from(byte % 2 == 0)
                    );
                    assert_eq!(b.recv(&cx).await?, Packet(vec![byte]));
                }
                Ok(())
            },
        ))
        .unwrap();
        assert_eq!(*sink.0.lock(), [(1, 2), (2, 4), (3, 6)]);
    }

    #[test]
    fn packet_callbacks_release_direction_locks_before_delivery() {
        struct ClosePeer(Mutex<Option<End>>);
        impl Observer for ClosePeer {
            fn enabled(&self, interest: Interest<'_>) -> bool {
                matches!(interest, Interest::Packet(_))
            }
            fn observe(&self, _: Stamp, _: Observation<'_>) {
                let peer = self.0.lock().take().unwrap();
                let (tx, rx) = std::sync::mpsc::channel();
                let thread = std::thread::spawn(move || {
                    drop(peer);
                    tx.send(()).unwrap();
                });
                rx.recv_timeout(std::time::Duration::from_secs(5))
                    .expect("peer drop must finish outside the direction lock");
                thread.join().unwrap();
            }
        }
        let sink = Arc::new(ClosePeer(Mutex::new(None)));
        block_on(crate::lab(
            crate::RunOptions::new(crate::Seed::from_u64(1)).observer(sink.clone()),
            |cx| async move {
                let (mut a, b) = pair();
                a = cx.tap("pair", a);
                *sink.0.lock() = Some(b);
                a.send(Packet(vec![1]));
                assert_eq!(a.meter().totals(), [1, 1, 0, 0]);
                assert!(a.cable.dirs[1].lock().queue.pop().is_none());
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn concurrent_ends_share_one_ordered_packet_stream() {
        let sink = Arc::new(PacketSink::new(true, false));
        block_on(crate::lab(
            crate::RunOptions::new(crate::Seed::from_u64(1)).observer(sink.clone()),
            |cx| async move {
                let (mut a, mut b) = pair();
                a = cx.tap("pair", a);
                std::thread::scope(|scope| {
                    let a = scope.spawn(|| {
                        for i in 0..100 {
                            a.send(Packet(vec![i]));
                        }
                    });
                    let b = scope.spawn(|| {
                        for i in 0..100 {
                            b.send(Packet(vec![i]));
                        }
                    });
                    a.join().unwrap();
                    b.join().unwrap();
                });
                Ok(())
            },
        ))
        .unwrap();
        let packets = sink.packets.lock();
        assert_eq!(packets.len(), 200);
        assert!(
            packets
                .iter()
                .enumerate()
                .all(|(i, p)| p.stamp.seq == i as u64 + 1)
        );
        for side in [Side::A, Side::B] {
            assert_eq!(
                packets
                    .iter()
                    .filter(|p| p.side == side)
                    .map(|p| p.bytes[0])
                    .collect::<Vec<_>>(),
                (0..100).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn an_untapped_pair_never_calls_the_observer() {
        struct NoPackets;
        impl Observer for NoPackets {
            fn enabled(&self, interest: Interest<'_>) -> bool {
                assert!(!matches!(interest, Interest::Packet(_)));
                matches!(interest, Interest::Topology(_))
            }
            fn observe(&self, _: Stamp, item: Observation<'_>) {
                assert!(!matches!(item, Observation::Packet(_)));
            }
        }
        block_on(crate::lab(
            crate::RunOptions::new(crate::Seed::from_u64(1)).observer(Arc::new(NoPackets)),
            |cx| async move {
                let (mut a, mut b) = pair();
                assert!(a.meter().link_id().is_some());
                let reads = cx.run.environment.clock.reads.load(Ordering::Relaxed);
                a.send(Packet(vec![1]));
                b.send(Packet(vec![2]));
                assert_eq!(
                    cx.run.environment.clock.reads.load(Ordering::Relaxed),
                    reads
                );
                assert_eq!(a.recv(&cx).await?, Packet(vec![2]));
                assert_eq!(b.recv(&cx).await?, Packet(vec![1]));
                assert_eq!(a.meter().totals(), [1, 1, 1, 1]);
                let reads = cx.run.environment.clock.reads.load(Ordering::Relaxed);
                a.send(Packet(vec![3]));
                b.send(Packet(vec![4]));
                assert_eq!(
                    cx.run.environment.clock.reads.load(Ordering::Relaxed),
                    reads
                );
                assert_eq!(a.recv(&cx).await?, Packet(vec![4]));
                assert_eq!(b.recv(&cx).await?, Packet(vec![3]));
                assert_eq!(a.meter().totals(), [2, 2, 2, 2]);
                assert!(a.packets.is_none());
                assert!(b.packets.is_none());
                assert!(a.meter().packets().is_none());
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn a_tap_names_the_stream_and_renames_it() {
        let sink = Arc::new(PacketSink::new(true, true));
        block_on(crate::lab(
            crate::RunOptions::new(crate::Seed::from_u64(1)).observer(sink.clone()),
            |cx| async move {
                let (mut a, mut b) = pair();
                a.send(Packet(vec![0]));
                a = cx.tap("first", a);
                a.send(Packet(vec![1]));
                b = cx.tap("second", b);
                b.send(Packet(vec![2]));
                a.send(Packet(vec![3]));
                assert_eq!(a.meter().totals(), [3, 3, 1, 1]);
                Ok(())
            },
        ))
        .unwrap();
        let links = sink.links.lock();
        assert_eq!(links.len(), 1);
        let link = links[0].0;
        assert_eq!(
            *sink.taps.lock(),
            [(link, "first".into()), (link, "second".into())]
        );
        let packets = sink.packets.lock();
        assert_eq!(
            packets
                .iter()
                .map(|p| (p.stamp.seq, p.tap.as_str(), p.side, p.bytes[0]))
                .collect::<Vec<_>>(),
            [
                (1, "first", Side::A, 1),
                (2, "second", Side::B, 2),
                (3, "second", Side::A, 3)
            ]
        );
        assert!(
            packets
                .iter()
                .all(|p| p.stamp.stream == Stream::Packets(link) && p.sandbox.is_none())
        );
    }

    #[test]
    fn an_attachment_is_tapped_by_its_sandbox_name() {
        for attach_in_run in [false, true] {
            let sink = Arc::new(PacketSink::new(true, true));
            let (attacher, mut attachments) = crate::attachments();
            let sandbox = (!attach_in_run).then(|| attacher.attach("guest").unwrap());
            block_on(crate::lab(
                crate::RunOptions::new(crate::Seed::from_u64(1)).observer(sink.clone()),
                |cx| async move {
                    let mut sandbox = sandbox.unwrap_or_else(|| attacher.attach("guest").unwrap());
                    let mut attachment = attachments.next(&cx).await?;
                    sandbox.send(Packet(vec![1]));
                    assert_eq!(attachment.recv(&cx).await?, Packet(vec![1]));
                    attachment.send(Packet(vec![2]));
                    assert_eq!(sandbox.recv(&cx).await?, Packet(vec![2]));
                    attachment = cx.tap("uplink", attachment);
                    sandbox.send(Packet(vec![3]));
                    assert_eq!(attachment.recv(&cx).await?, Packet(vec![3]));
                    Ok(())
                },
            ))
            .unwrap();
            let packets = sink.packets.lock();
            assert_eq!(
                packets
                    .iter()
                    .map(|p| (p.stamp.seq, p.tap.as_str(), p.sandbox.as_deref(), p.side))
                    .collect::<Vec<_>>(),
                [
                    (1, "guest", Some("guest"), Side::B),
                    (2, "guest", Some("guest"), Side::A),
                    (3, "uplink", Some("guest"), Side::B)
                ]
            );
            let links = sink.links.lock();
            assert_eq!(links.len(), 1);
            assert_eq!(
                *sink.taps.lock(),
                [(links[0].0, "guest".into()), (links[0].0, "uplink".into())]
            );
        }
    }

    #[test]
    fn unobserved_crossings_do_not_read_the_clock() {
        block_on(crate::lab(
            crate::RunOptions::new(crate::Seed::from_u64(1)),
            |cx| async move {
                let (mut a, mut b) = pair();
                let reads = cx.run.environment.clock.reads.load(Ordering::Relaxed);
                a.send(Packet(vec![1]));
                b.send(Packet(vec![2]));
                assert_eq!(
                    cx.run.environment.clock.reads.load(Ordering::Relaxed),
                    reads
                );
                assert!(a.packets.is_none());
                assert!(a.meter().packets().is_none());
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn a_limited_cable_drops_what_does_not_fit_and_frees_what_is_read() {
        let result = block_on(run(
            fictionet::RunOptions::new(fictionet::Seed::random()),
            |fcx| async move {
                // Room for exactly ten 36-byte packets.
                let (mut a, mut b) = pair_with_limit(10 * (36 + PACKET_COST));
                for i in 0..20u8 {
                    a.send(Packet(vec![i; 36]));
                }
                for i in 0..10u8 {
                    assert_eq!(b.recv(&fcx).await?, Packet(vec![i; 36]));
                }
                // The ten past the limit were dropped; reading made room again.
                a.send(Packet(vec![99; 36]));
                assert_eq!(b.recv(&fcx).await?, Packet(vec![99; 36]));
                assert_eq!(b.cable.dirs[b.side].lock().queue.bytes(), 0);
                Err::<(), crate::Error>(crate::Error::msg("done"))
            },
        ));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }
}
