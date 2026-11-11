//! Packet delays, rate limits, and filters.
//!
//! These functions start tasks that forward packets through interfaces with
//! delays, rate limits, or caller-selected filtering. They do not parse or
//! write protocol messages, implement sessions or services, or encrypt traffic.

use fictionet::stdlib::layer::{Budget, Charge, ChargedDeque};
use std::task::Poll;

use fictionet::PACKET_COST;
use fictionet::stdlib::network::ports;
use fictionet::time::{Duration, Instant};
use fictionet::{Cx, End, Interface, Packet};

/// Delays every packet by `by`, in both directions, as a link with fixed
/// latency does.
///
/// Put it between a sandbox and the rest of the world to make every
/// destination feel far away. It starts a background task and returns
/// immediately with a new [`End`]. Use that end where you would have used
/// `inner`:
///
/// - Packets that come out of `inner` come out of the returned end `by`
///   later.
/// - Packets sent into the returned end reach `inner` `by` later.
///
/// So a round trip through `delay(&fcx, ms(50), ..)` takes 100 ms. Each
/// packet is delayed on its own: ten packets sent together all arrive `by`
/// later, together.
///
/// A delay also caps how fast one TCP connection can go, as it does on a real
/// long link: a connection carries at most one buffer of data per round trip.
/// With the stdlib's default 256 KiB buffers, a 100 ms round trip allows about
/// 2.6 MB/s. [`fictionet::stdlib::network::tcp::Options::buffer`] sets larger
/// ones.
///
/// The task stops when either interface closes, or when the caller's
/// [region](Cx#regions) is cancelled. Packets it still holds are lost.
///
/// A delay holds at most 32 MiB of packets in each direction, counting each
/// packet's buffer, its capacity rather than its length, plus
/// [`PACKET_COST`](fictionet::PACKET_COST), and the queue's places. A
/// packet that arrives while its direction is full is dropped, as a real
/// link drops what its buffer cannot hold. That is about 20,000 full-size
/// packets: with a 100 ms delay, a direction fills only above about
/// 300 MB/s. The returned end also holds at most 32 MiB each way while it
/// waits to be read, counting each packet the same way but for the places,
/// and drops what is sent past that. Without these limits, a sandbox that sends without pause, or a
/// world that never reads the returned end, would grow the world's memory
/// without end.
///
/// How it works: `delay` makes two connected interfaces with
/// [`pair`](fictionet::pair), returns one, and starts a task with
/// [`Cx::spawn`] that holds the other and `inner`. The task stamps each
/// packet with `fcx.now() + by` and puts it in a queue for its direction. Because the delay is fixed, each queue is
/// already in the order packets leave. The task waits for whichever comes
/// first: a packet from either side, or the time at the front of a queue.
#[track_caller]
pub fn delay(fcx: &Cx, by: Duration, inner: impl Interface) -> End {
    shape(
        fcx,
        inner,
        move |queue: &Queue, now: Instant, _len: usize| {
            // Each packet waits `by` from when it arrived. The queue stays in
            // release order because `by` is fixed.
            let _ = queue;
            Some(later(now, by))
        },
    )
}

/// Limits packets to `bits_per_second`, with a queue of at most `queue`
/// packets in each direction.
///
/// This models a slow link, and the way a real slow link loses packets.
/// Packets that arrive faster than the rate wait in the queue. When the
/// queue already holds `queue` packets, a new packet is dropped. This is
/// called tail drop.
///
/// A queue limit only matters where packets wait, and packets only wait
/// where something is slower than its input. That is why the limit comes
/// with a rate. Interfaces made by [`pair`](fictionet::pair) never fill up on
/// their own.
///
/// Whatever `queue` says, a direction also holds at most 32 MiB, counting
/// each packet as [`delay`] does. The returned end
/// holds at most 32 MiB each way while it waits to be read, and drops what
/// is sent past that, so packets that have left the queue cannot pile up
/// in an end that is not read.
///
/// Each direction has its own rate and queue, as on a real link. Like
/// [`delay`], it starts a background task and returns immediately with a
/// new [`End`] to use in place of `inner`. The task stops when either
/// interface closes, or when the caller's [region](Cx#regions) is
/// cancelled.
///
/// ```
/// # use fictionet::{Attachment, Cx, stdlib};
/// # fn wire(fcx: Cx, sandbox: Attachment) {
/// // A 10 Mbit/s link with room for 100 waiting packets each way.
/// let link = stdlib::network::bottleneck(&fcx, 10_000_000, 100, sandbox);
/// # drop(link);
/// # }
/// ```
///
/// The queue counts every packet that has not left yet, including the one
/// being sent. A packet leaves when its last bit has been sent: a 1,000-byte
/// packet on a 1 Mbit/s link leaves 8 ms after the link started sending it.
/// So with `queue` 10, a burst of 11 packets loses the 11th. A rate of 0
/// sends nothing: the queue fills and every later packet is dropped.
#[track_caller]
pub fn bottleneck(fcx: &Cx, bits_per_second: u64, queue: usize, inner: impl Interface) -> End {
    shape(
        fcx,
        inner,
        move |waiting: &Queue, now: Instant, len: usize| {
            if waiting.len() >= queue {
                return None;
            }
            // The link starts on this packet when the one before it has left.
            let start = match waiting.last() {
                Some(leaves) if leaves > now => leaves,
                _ => now,
            };
            Some(later(start, send_time(len, bits_per_second)))
        },
    )
}

/// Which way a packet is going through a [`filter`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Out of `inner`, toward the returned end. When `inner` is an
    /// [`Attachment`](fictionet::Attachment), these are the packets the
    /// sandbox sends.
    FromInner,
    /// Into `inner`, from the returned end. When `inner` is an
    /// `Attachment`, these are the packets the sandbox receives.
    ToInner,
}

/// Calls `keep` for every packet that passes, in both directions, and
/// passes on only the packets it returns `true` for.
///
/// Use it to watch packets, or to drop some of them. Like [`delay`], it
/// starts a background task and returns immediately with a new [`End`] to
/// use in place of `inner`. Packets that `keep` lets through pass
/// unchanged and without delay, in the order they came. As with
/// [`delay`], the returned end holds at most 32 MiB each way while it
/// waits to be read, and drops what is sent past that.
///
/// This one drops 2% of the packets in each direction at random, as a
/// lossy link does:
///
/// ```
/// # use fictionet::{Attachment, Cx, stdlib};
/// # fn wire(fcx: Cx, sandbox: Attachment) {
/// let lossy = stdlib::network::filter(&fcx, sandbox, |fcx, _direction, _packet| fcx.random_f64() >= 0.02);
/// # drop(lossy);
/// # }
/// ```
///
/// `keep` runs inside the task, once per packet, so it must return quickly
/// and must not block. Every task of a world shares one thread, so a slow
/// `keep` slows the whole world. To write packets to a file, hand them to
/// a channel that never waits, and write them on another thread.
///
/// The task stops when either interface closes, or when the caller's
/// [region](Cx#regions) is cancelled.
#[track_caller]
pub fn filter<F>(fcx: &Cx, inner: impl Interface, mut keep: F) -> End
where
    F: FnMut(&Cx, Direction, &Packet) -> bool + Send + 'static,
{
    let (outer, mine) = link_pair();
    fcx.spawn(move |fcx| async move {
        // Port 0 is `inner`, port 1 our end of the new pair.
        let mut ports =
            ports::Ports::new(vec![Box::new(inner) as Box<dyn Interface>, Box::new(mine)]);
        loop {
            match ports.next(&fcx, None, |_| Poll::Pending).await? {
                ports::Event::Packet(i, packet) => {
                    let direction = if i == 0 {
                        Direction::FromInner
                    } else {
                        Direction::ToInner
                    };
                    if keep(&fcx, direction, &packet) {
                        ports.send(1 - i, packet);
                    }
                }
                ports::Event::Timer => {}
                ports::Event::Closed(_) | ports::Event::Extra => return Ok(()),
            }
        }
    });
    outer
}

/// How long `len` bytes take at `bits_per_second`, rounded up to the next
/// nanosecond. `Duration::MAX` for a rate of 0.
fn send_time(len: usize, bits_per_second: u64) -> Duration {
    if bits_per_second == 0 {
        return Duration::MAX;
    }
    let nanos = (len as u128 * 8 * 1_000_000_000).div_ceil(bits_per_second as u128);
    match u64::try_from(nanos) {
        Ok(n) => Duration::from_nanos(n),
        Err(_) => Duration::MAX,
    }
}

/// `at + d`, or a time so far away it never comes if that overflows.
fn later(at: Instant, d: Duration) -> Instant {
    match at.since_start().checked_add(d) {
        Some(t) => Instant::from_since_start(t),
        None => Instant::from_since_start(Duration::MAX),
    }
}

/// The packets waiting in one direction of a [`shape`]d link, each with the
/// time it leaves. Always in leaving order. A budget of [`LINK_STORE`]
/// pays for them, each counted as a limited cable counts it, and for the
/// queue's places, charged as it grows.
struct Queue {
    packets: ChargedDeque<(Instant, Packet, Charge)>,
    budget: Budget,
}

impl Default for Queue {
    fn default() -> Self {
        let budget = Budget::new(LINK_STORE);
        Queue {
            packets: ChargedDeque::new(&budget, usize::MAX),
            budget,
        }
    }
}

impl Queue {
    /// The packets waiting.
    fn len(&self) -> usize {
        self.packets.len()
    }

    /// When the first packet leaves.
    fn first(&self) -> Option<Instant> {
        self.packets.front().map(|(leaves, _, _)| *leaves)
    }

    /// When the last packet leaves.
    fn last(&self) -> Option<Instant> {
        self.packets.iter().last().map(|(leaves, _, _)| *leaves)
    }

    /// Queues `packet` to leave at `leaves`, charging it and then a place
    /// first. False, with nothing charged, past the store.
    fn push(&mut self, leaves: Instant, packet: Packet) -> bool {
        let cost = packet.chunk().capacity().checked_add(PACKET_COST);
        let charge = cost.and_then(|cost| self.budget.charge(cost));
        let Some(charge) = charge else {
            return false;
        };
        let Some(place) = self.packets.place() else {
            return false;
        };
        place.push_back((leaves, packet, charge));
        true
    }

    /// Takes out the first packet. An emptied queue gives back its places.
    fn pop(&mut self) -> Option<Packet> {
        let (_, packet, _) = self.packets.pop_front()?;
        if self.packets.is_empty() {
            self.packets.shrink_to(0);
        }
        Some(packet)
    }
}

/// The most a [`delay`] or [`bottleneck`] holds in each direction: packets
/// waiting to leave, each counted as its buffer's capacity plus
/// [`PACKET_COST`](fictionet::PACKET_COST), and the queue's places. A
/// packet that would take a direction past this is dropped, as a full
/// queue on a real link drops it.
const LINK_STORE: usize = 32 << 20;

/// The most each direction of the interface returned by [`delay`],
/// [`bottleneck`] and [`filter`] holds while it waits to be read, each
/// packet counted as its buffer's capacity plus
/// [`PACKET_COST`](fictionet::PACKET_COST). Past that, packets sent into
/// it are dropped. TCP puts up to a window of packets into it at once, so
/// it is as large as the windows of a hundred connections with the default
/// buffers.
const LINK_OUTPUT: usize = 32 << 20;

/// The two ends that [`shape`] and [`filter`] make, with a size limit.
fn link_pair() -> (End, End) {
    fictionet::pair_with_limit(LINK_OUTPUT)
}

/// The loop behind [`delay`] and [`bottleneck`]. For each packet,
/// `admit(queue, now, len)` gives the time it leaves, or `None` to drop it.
/// Leaving times must not go down within a direction.
#[track_caller]
fn shape<F>(fcx: &Cx, inner: impl Interface, admit: F) -> End
where
    F: Fn(&Queue, Instant, usize) -> Option<Instant> + Send + 'static,
{
    let (outer, mine) = link_pair();
    fcx.spawn(move |fcx| async move {
        // Port 0 is `inner`, port 1 our end of the new pair. A packet from
        // port `i` waits in `queues[i]`, then goes out on port `1 - i`.
        let mut ports =
            ports::Ports::new(vec![Box::new(inner) as Box<dyn Interface>, Box::new(mine)]);
        let mut queues = [Queue::default(), Queue::default()];
        loop {
            let deadline = queues.iter().filter_map(Queue::first).min();
            match ports.next(&fcx, deadline, |_| Poll::Pending).await? {
                ports::Event::Packet(i, packet) => {
                    let now = fcx.now();
                    if let Some(leaves) = admit(&queues[i], now, packet.len()) {
                        // Past the store, the packet is dropped.
                        let _ = queues[i].push(leaves, packet);
                    }
                }
                ports::Event::Timer => {
                    let now = fcx.now();
                    let mut sent = 0;
                    for (i, queue) in queues.iter_mut().enumerate() {
                        while sent < ports::BUDGET {
                            match queue.first() {
                                Some(t) if t <= now => {}
                                _ => break,
                            }
                            let packet = queue.pop().expect("a first packet");
                            ports.send(1 - i, packet);
                            sent += 1;
                        }
                    }
                    ports.spend(sent);
                }
                ports::Event::Closed(_) | ports::Event::Extra => return Ok(()),
            }
        }
    });
    outer
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::{InterfaceExt, block_on, pair, run};
    use std::future::poll_fn;

    /// How many 1,500-byte packets fit in 32 MiB, at [`PACKET_COST`] more
    /// each.
    const FIT: usize = (32 << 20) / (1500 + PACKET_COST);

    /// A delay queue's place for one packet.
    const PLACE: usize = size_of::<(Instant, Packet, Charge)>();

    /// Sends `n` 1,500-byte packets into `inner`'s other end, giving the
    /// link's task turns as it goes.
    async fn flood(fcx: &Cx, into: &mut End, n: usize) -> fictionet::Result {
        for i in 0..n {
            into.send(Packet::new(vec![0x45; 1500]));
            if i % 32 == 31 {
                fcx.yield_now().await?;
            }
        }
        for _ in 0..1000 {
            fcx.yield_now().await?;
        }
        Ok(())
    }

    /// Takes every packet that is ready on `end` now.
    async fn drain(fcx: &Cx, end: &mut End) -> usize {
        let mut n = 0;
        while let Poll::Ready(Ok(_)) = poll_fn(|t| Poll::Ready(end.poll_recv(fcx, t))).await {
            n += 1;
        }
        n
    }

    #[test]
    fn a_delay_drops_what_does_not_fit() {
        block_on(fictionet::lab(
            fictionet::Seed::from_u64(0),
            |fcx| async move {
                let (mut sandbox, inner) = pair();
                let mut far = delay(&fcx, Duration::from_secs(1), inner);
                flood(&fcx, &mut sandbox, FIT + 500).await?;
                assert_eq!(
                    drain(&fcx, &mut far).await,
                    0,
                    "nothing leaves before the delay"
                );
                fcx.sleep(Duration::from_secs(1)).await?;
                // Turns for the link's task to send all that is due.
                for _ in 0..FIT {
                    fcx.yield_now().await?;
                }
                let kept = drain(&fcx, &mut far).await;
                // The store pays for the packets and the queue's places:
                // never more packets than fit alone, and no fewer than fit
                // with three places each (twice the places a doubling
                // leaves, and the old ones while they move).
                assert!(kept <= FIT, "{kept} packets kept, past 32 MiB");
                assert!(
                    kept >= (32 << 20) / (1500 + PACKET_COST + 3 * PLACE),
                    "{kept} packets kept, far less than 32 MiB"
                );
                assert_eq!(fcx.now().since_start(), Duration::from_secs(1));
                // Room again, once the queue has emptied.
                sandbox.send(Packet::new(vec![1; 100]));
                assert_eq!(far.recv(&fcx).await?, Packet::new(vec![1; 100]));
                assert_eq!(fcx.now().since_start(), Duration::from_secs(2));
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn a_ten_packet_queue_drops_the_eleventh_packet_of_a_burst() {
        block_on(fictionet::lab(
            fictionet::Seed::from_u64(0),
            |fcx| async move {
                let (mut sandbox, inner) = pair();
                let mut far = bottleneck(&fcx, 1_000_000, 10, inner);
                for byte in 0..11 {
                    sandbox.send(Packet::new(vec![byte; 1250]));
                }
                for byte in 0..10 {
                    assert_eq!(far.recv(&fcx).await?, Packet::new(vec![byte; 1250]));
                    assert_eq!(
                        fcx.now().since_start(),
                        Duration::from_millis(10 * (u64::from(byte) + 1))
                    );
                }
                assert_eq!(drain(&fcx, &mut far).await, 0);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn an_unread_bottleneck_output_stops_growing() {
        block_on(run(fictionet::Seed::random(), |fcx| async move {
            let (mut sandbox, inner) = pair();
            let mut far = bottleneck(&fcx, u64::MAX, 64, inner);
            flood(&fcx, &mut sandbox, FIT + 500).await?;
            assert_eq!(
                drain(&fcx, &mut far).await,
                FIT,
                "the output kept 32 MiB and dropped the rest"
            );
            Ok(())
        }))
        .unwrap();
    }
}

/// Copies packets in both directions to a bounded channel chosen by the world.
/// A full or closed channel drops the copy and leaves forwarding unaffected.
pub fn tap<I: Interface>(
    inner: I,
    packets: std::sync::mpsc::SyncSender<(Direction, Packet)>,
) -> impl Interface {
    Tap { inner, packets }
}

struct Tap<I> {
    inner: I,
    packets: std::sync::mpsc::SyncSender<(Direction, Packet)>,
}

impl<I: Interface> Interface for Tap<I> {
    fn poll_recv(
        &mut self,
        fcx: &Cx,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Packet, crate::RecvError>> {
        let result = self.inner.poll_recv(fcx, cx);
        if let Poll::Ready(Ok(packet)) = &result {
            let _ = self
                .packets
                .try_send((Direction::FromInner, packet.clone()));
        }
        result
    }

    fn send(&mut self, packet: Packet) {
        let _ = self.packets.try_send((Direction::ToInner, packet.clone()));
        self.inner.send(packet);
    }
}

#[cfg(test)]
mod tap_tests {
    use super::*;
    use fictionet::InterfaceExt;

    #[test]
    fn packet_copies_never_hold_up_forwarding() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |cx| async move {
                let (inner, mut peer) = fictionet::pair();
                let (send, receive) = std::sync::mpsc::sync_channel(1);
                let mut tapped = tap(inner, send);
                let outbound = Packet::new(vec![1, 2, 3]);
                peer.send(outbound.clone());
                assert_eq!(tapped.recv(&cx).await?, outbound);
                let inbound = Packet::new(vec![4, 5, 6]);
                tapped.send(inbound.clone());
                assert_eq!(peer.recv(&cx).await?, inbound);
                assert_eq!(
                    receive.try_recv().unwrap(),
                    (Direction::FromInner, outbound)
                );
                tapped.send(inbound.clone());
                assert_eq!(
                    receive.try_recv().unwrap(),
                    (Direction::ToInner, inbound.clone())
                );
                assert_eq!(peer.recv(&cx).await?, inbound);
                drop(receive);
                tapped.send(Packet::new(vec![7]));
                assert_eq!(peer.recv(&cx).await?, Packet::new(vec![7]));
                Ok(())
            },
        ))
        .unwrap();
    }
}
