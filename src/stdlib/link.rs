//! Packet delays, rate limits, and filters.
//!
//! These functions start tasks that forward packets through interfaces with
//! delays, rate limits, or caller-selected filtering. They do not parse or
//! write protocol messages, implement sessions or services, or encrypt traffic.

use std::collections::VecDeque;
use std::task::Poll;

use fictionet::PACKET_COST;
use fictionet::stdlib::ports;
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
/// A delay also caps how fast one TCP connection can go, as it does on a
/// real long link: a connection carries at most one buffer of data per
/// round trip. With the stdlib's default 256 KiB buffers, a 100 ms round
/// trip allows about 2.6 MB/s. [`fictionet::stdlib::tcp::Options::buffer`] sets larger ones.
///
/// The task stops when either interface closes, or when the caller's
/// [region](Cx#regions) is cancelled. Packets it still holds are lost.
///
/// A delay holds at most 32 MiB of packets in each direction, counting each
/// packet's length plus 64 bytes. A packet that arrives while its direction
/// is full is dropped, as a real link drops what its buffer cannot hold.
/// That is about 21,000 full-size packets: with a 100 ms delay, a direction
/// fills only above about 320 MB/s. The returned end also holds at most
/// 32 MiB each way, counted the same way, while it waits to be read, and
/// drops what is sent past that. Without these limits, a sandbox that sends without pause, or a
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
        "delay",
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
/// each packet's length plus 64 bytes, as [`delay`] does. The returned end
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
/// let link = stdlib::bottleneck(&fcx, 10_000_000, 100, sandbox);
/// # drop(link);
/// # }
/// ```
///
/// The queue counts every packet that has not left yet, including the one
/// being sent. A packet leaves when its last bit has been sent: a 1,000-byte
/// packet on a 1 Mbit/s link leaves 8 ms after the link started sending it.
/// So with `queue` 10, a burst of 11 packets loses the 11th. A rate of 0
/// sends nothing: the queue fills and every later packet is dropped. The
/// drops are recorded as `bottleneck.drop` [repeats](fictionet::events#repeats),
/// with how many packets were waiting (`waiting`).
#[track_caller]
pub fn bottleneck(fcx: &Cx, bits_per_second: u64, queue: usize, inner: impl Interface) -> End {
    shape(
        fcx,
        "bottleneck",
        inner,
        move |waiting: &Queue, now: Instant, len: usize| {
            if waiting.packets.len() >= queue {
                return None;
            }
            // The link starts on this packet when the one before it has left.
            let start = match waiting.packets.back() {
                Some((leaves, _)) if *leaves > now => *leaves,
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
/// let lossy = stdlib::filter(&fcx, sandbox, |fcx, _direction, _packet| fcx.random_f64() >= 0.02);
/// # drop(lossy);
/// # }
/// ```
///
/// `keep` runs inside the task, once per packet, so it must return quickly
/// and must not block. Every task of a world shares one thread, so a slow
/// `keep` slows the whole world. To write packets to a file, hand them to
/// a channel that never waits, and write them on another thread. The
/// [packet capture recipe](fictionet::recipes#packet-capture) does this.
///
/// The task stops when either interface closes, or when the caller's
/// [region](Cx#regions) is cancelled.
#[track_caller]
pub fn filter<F>(fcx: &Cx, inner: impl Interface, mut keep: F) -> End
where
    F: FnMut(&Cx, Direction, &Packet) -> bool + Send + 'static,
{
    let (outer, mine) = link_pair();
    fcx.spawn_as(
        || "filter".into(),
        move |fcx| async move {
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
        },
    );
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
/// time it leaves. Always in leaving order.
#[derive(Default)]
struct Queue {
    packets: VecDeque<(Instant, Packet)>,
    /// What `packets` holds, counted as for [`LINK_STORE`].
    bytes: usize,
}

/// The most a [`delay`] or [`bottleneck`] holds in each direction: packets
/// waiting to leave, each counted as its length plus 64 bytes. A packet
/// that would take a direction past this is dropped, as a full queue on a
/// real link drops it.
const LINK_STORE: usize = 32 << 20;

/// The most each direction of the interface returned by [`delay`],
/// [`bottleneck`] and [`filter`] holds while it waits to be read, counted
/// the same way. Past that, packets sent into it are dropped. TCP puts up
/// to a window of packets into it at once, so it is as large as the
/// windows of a hundred connections with the default buffers.
const LINK_OUTPUT: usize = 32 << 20;

/// The two ends that [`shape`] and [`filter`] make, with a size limit.
fn link_pair() -> (End, End) {
    fictionet::pair_with_limit(LINK_OUTPUT)
}

/// The loop behind [`delay`] and [`bottleneck`]. For each packet,
/// `admit(queue, now, len)` gives the time it leaves, or `None` to drop it.
/// Leaving times must not go down within a direction.
#[track_caller]
fn shape<F>(fcx: &Cx, name: &'static str, inner: impl Interface, admit: F) -> End
where
    F: Fn(&Queue, Instant, usize) -> Option<Instant> + Send + 'static,
{
    let (outer, mine) = link_pair();
    fcx.spawn_as(
        move || name.into(),
        move |fcx| async move {
            // Port 0 is `inner`, port 1 our end of the new pair. A packet from
            // port `i` waits in `queues[i]`, then goes out on port `1 - i`.
            let mut ports =
                ports::Ports::new(vec![Box::new(inner) as Box<dyn Interface>, Box::new(mine)]);
            let mut queues = [Queue::default(), Queue::default()];
            loop {
                let deadline = queues
                    .iter()
                    .filter_map(|q| q.packets.front().map(|(t, _)| *t))
                    .min();
                match ports.next(&fcx, deadline, |_| Poll::Pending).await? {
                    ports::Event::Packet(i, packet) => {
                        let now = fcx.now();
                        let cost = packet.0.len() + PACKET_COST;
                        let fits = queues[i].bytes + cost <= LINK_STORE;
                        if let Some(leaves) =
                            admit(&queues[i], now, packet.0.len()).filter(|_| fits)
                        {
                            queues[i].bytes += cost;
                            queues[i].packets.push_back((leaves, packet));
                        } else {
                            let waiting = queues[i].packets.len();
                            fictionet::events::record_drop(
                                &fcx,
                                name,
                                &packet,
                                "the queue was full",
                                fictionet::events::Fields::new().with("waiting", waiting as u64),
                                |event| event,
                            );
                        }
                    }
                    ports::Event::Timer => {
                        let now = fcx.now();
                        let mut sent = 0;
                        for (i, queue) in queues.iter_mut().enumerate() {
                            while sent < ports::BUDGET {
                                match queue.packets.front() {
                                    Some((t, _)) if *t <= now => {}
                                    _ => break,
                                }
                                let (_, packet) = queue.packets.pop_front().unwrap();
                                queue.bytes -= packet.0.len() + PACKET_COST;
                                ports.send(1 - i, packet);
                                sent += 1;
                            }
                        }
                        ports.spend(sent);
                    }
                    ports::Event::Closed(_) | ports::Event::Extra => return Ok(()),
                }
            }
        },
    );
    outer
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::{InterfaceExt, block_on, pair, run};
    use std::future::poll_fn;

    /// How many 1,500-byte packets fit in 32 MiB, at 64 bytes more each.
    const FIT: usize = (32 << 20) / (1500 + PACKET_COST);

    /// Sends `n` 1,500-byte packets into `inner`'s other end, giving the
    /// link's task turns as it goes.
    async fn flood(fcx: &Cx, into: &mut End, n: usize) -> fictionet::Result {
        for i in 0..n {
            into.send(Packet(vec![0x45; 1500]));
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
        block_on(run(|fcx| async move {
            let (mut sandbox, inner) = pair();
            let mut far = delay(&fcx, Duration::from_secs(1), inner);
            flood(&fcx, &mut sandbox, FIT + 500).await?;
            assert_eq!(
                drain(&fcx, &mut far).await,
                0,
                "nothing leaves before the delay"
            );
            fcx.sleep(Duration::from_millis(1200)).await?;
            assert_eq!(
                drain(&fcx, &mut far).await,
                FIT,
                "the delay kept 32 MiB and dropped the rest"
            );
            // Room again, once the queue has emptied.
            sandbox.send(Packet(vec![1; 100]));
            assert_eq!(far.recv(&fcx).await?, Packet(vec![1; 100]));
            Ok(())
        }))
        .unwrap();
    }

    /// A flooded bottleneck counts its drops: a few events, not one per
    /// packet, so the flood pushes nothing else out of the log.
    #[test]
    fn a_flooded_bottleneck_counts_its_drops() {
        block_on(run(|fcx| async move {
            let (mut sandbox, inner) = pair();
            let _far = bottleneck(&fcx, 0, 10, inner);
            fcx.record(fictionet::events::Event::new("http", "request"));
            let flood = fictionet::events::MAX_EVENTS + 10_000;
            for i in 0..flood {
                sandbox.send(Packet(vec![0x45; 20]));
                if i % 32 == 31 {
                    fcx.yield_now().await?;
                }
            }
            let deadline = fcx.now() + 3 * fictionet::events::REPEAT_WINDOW;
            let mut next = 1;
            loop {
                let drops = fcx
                    .events()
                    .wait(&fcx, next, Duration::from_millis(50), |e| {
                        e.source == "bottleneck" && e.kind == "drop"
                    })
                    .await?;
                let reported = drops.iter().map(|e| e.u64("count").unwrap()).sum::<u64>();
                if reported == flood as u64 - 10 {
                    break;
                }
                assert!(
                    fcx.now() < deadline,
                    "drop report counted {reported} of {} packets",
                    flood - 10
                );
                next = drops.len() + 1;
            }
            fcx.record(fictionet::events::Event::new("http", "request"));
            let events = fcx.events();
            assert_eq!(events.of("http", "request").len(), 2);
            let drops = events.of("bottleneck", "drop");
            assert!(drops.len() <= 4, "{drops:?}");
            assert_eq!(
                drops.iter().map(|e| e.u64("count").unwrap()).sum::<u64>(),
                flood as u64 - 10
            );
            assert_eq!(drops[0].str("why"), Some("the queue was full"));
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn an_unread_bottleneck_output_stops_growing() {
        block_on(run(|fcx| async move {
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
