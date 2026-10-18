mod common;

use common::World;
use divan::{
    Bencher,
    counter::{BytesCount, ItemsCount},
};
use fictionet::prelude::*;
use fictionet::stdlib::{
    self,
    network::{ip, tcp},
};
use fictionet::{Cx, End, Interface, Packet, RecvError, pair};
use std::future::poll_fn;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

#[divan::bench(args = [(1, 32 << 20), (10, 4 << 20), (100, 1 << 20)], sample_count = 3, sample_size = 1)]
fn tcp(bencher: Bencher, case: (usize, usize)) {
    bulk(bencher, Topology::Direct, case.0, 0, case.1, None);
}

#[divan::bench(args = [(1, 32 << 20), (10, 4 << 20), (100, 1 << 20)], sample_count = 3, sample_size = 1)]
fn path(bencher: Bencher, case: (usize, usize)) {
    bulk(bencher, Topology::Path, case.0, 0, case.1, None);
}

#[divan::bench(args = [0, 99], sample_count = 3, sample_size = 1)]
fn idle(bencher: Bencher, idle: usize) {
    bulk(bencher, Topology::Direct, 1, idle, 32 << 20, None);
}

#[divan::bench(args = [
    (10, 1, 16 << 20, None), (10, 1, 16 << 20, Some(1 << 20)),
    (50, 1, 8 << 20, None), (50, 1, 8 << 20, Some(1 << 20)),
    (10, 10, 4 << 20, None), (10, 10, 4 << 20, Some(1 << 20)),
], sample_count = 3, sample_size = 1)]
fn delay(bencher: Bencher, case: (u64, usize, usize, Option<usize>)) {
    bulk(bencher, Topology::Delay(case.0), case.1, 0, case.2, case.3);
}

fn bulk(
    bencher: Bencher,
    topology: Topology,
    flows: usize,
    idle: usize,
    per_flow: usize,
    buffer: Option<usize>,
) {
    let packets = Arc::new(Mutex::new(None));
    bencher
        .counter(BytesCount::new(flows * per_flow))
        .with_inputs(|| {
            tcp_bulk(
                topology,
                flows,
                idle,
                per_flow,
                TcpOpts { buffer },
                packets.clone(),
            )
        })
        .bench_local_values(World::measure);
    if let Some((sent, lost)) = *packets.lock().unwrap() {
        eprintln!("last transfer: packets sent={sent}, packets lost={lost}");
    }
}

mod sched {
    use super::*;

    #[divan::bench(sample_count = 3, sample_size = 1)]
    fn packet_round_trips(bencher: Bencher) {
        bencher
            .counter(ItemsCount::new(500_000_u64))
            .with_inputs(|| ping_pong(500_000))
            .bench_local_values(World::measure);
    }

    #[divan::bench(sample_count = 3, sample_size = 1)]
    fn tcp_round_trips(bencher: Bencher) {
        bencher
            .counter(ItemsCount::new(10_000_u64))
            .with_inputs(|| tcp_exchanges(10_000))
            .bench_local_values(World::measure);
    }
}

mod memory {
    use super::*;

    #[divan::bench(sample_count = 3, sample_size = 1)]
    fn delay(bencher: Bencher) {
        measure(bencher, true);
    }

    #[divan::bench(sample_count = 3, sample_size = 1)]
    fn bottleneck(bencher: Bencher) {
        measure(bencher, false);
    }

    fn measure(bencher: Bencher, delayed: bool) {
        let kept = Arc::new(Mutex::new(None));
        bencher
            .counter(BytesCount::new(40_000_u64 * 1500))
            .counter(ItemsCount::new(40_000_u64))
            .with_inputs(|| unread(delayed, 40_000, kept.clone()))
            .bench_local_values(World::measure);
        if let Some(kept) = *kept.lock().unwrap() {
            eprintln!(
                "last unread link: packets sent=40000, payload bytes=60000000, packets in unread end={kept}"
            );
        }
    }
}

/// Packets counted at one TCP endpoint's interface: what it sent into the
/// network, and what the network delivered to it.
#[derive(Default)]
struct Counts {
    sent: AtomicU64,
    delivered: AtomicU64,
}

struct Counted<I> {
    inner: I,
    counts: Arc<Counts>,
}

impl<I: Interface> Interface for Counted<I> {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        let r = self.inner.poll_recv(fcx, cx);
        if let Poll::Ready(Ok(_)) = r {
            self.counts.delivered.fetch_add(1, Ordering::Relaxed);
        }
        r
    }

    fn send(&mut self, packet: Packet) {
        self.counts.sent.fetch_add(1, Ordering::Relaxed);
        self.inner.send(packet)
    }

    fn observe_link(&self) -> Option<fictionet::observe::LinkHandle> {
        self.inner.observe_link()
    }
}

#[derive(Clone, Copy)]
enum Topology {
    /// The two endpoints share one pair.
    Direct,
    /// A protocol split at each endpoint, and a router between them, as
    /// `Sites` builds for each machine.
    Path,
    /// A `delay` of this many milliseconds each way, on one pair.
    Delay(u64),
}

/// TCP options for both endpoints of a run: the buffer size per
/// connection, or the default.
#[derive(Clone, Copy)]
struct TcpOpts {
    buffer: Option<usize>,
}

fn endpoint(fcx: &Cx, inner: impl Interface, addr: &str, opts: TcpOpts) -> tcp::Endpoint {
    let addr = addr.parse().unwrap();
    match opts.buffer {
        None => tcp::endpoint(fcx, inner, addr),
        Some(b) => tcp::endpoint_with(fcx, inner, addr, tcp::Options::default().buffer(b)),
    }
}

/// Moves `per_flow` bytes on each of `flows` connections at once, from the
/// endpoint at 10.0.0.2 to the one at 10.0.0.1, and checks every byte.
/// `idle` more connections stay open and quiet the whole time.
fn tcp_bulk(
    topology: Topology,
    flows: usize,
    idle: usize,
    per_flow: usize,
    opts: TcpOpts,
    result: Arc<Mutex<Option<(u64, u64)>>>,
) -> World {
    World::new(move |fcx, checkpoint| async move {
        let (a, b, _keep): (End, End, Vec<Box<dyn Send>>) = match topology {
            Topology::Direct => {
                let (a, b) = pair();
                (a, b, Vec::new())
            }
            Topology::Delay(ms) => {
                let (a, b) = pair();
                let b = stdlib::network::delay(&fcx, fictionet::time::ms(ms), b);
                (a, b, Vec::new())
            }
            Topology::Path => {
                let (a, ar) = pair();
                let (br, b) = pair();
                let router = stdlib::network::route::router(
                    &fcx,
                    vec![("10.0.0.1/32".parse()?, ar), ("10.0.0.2/32".parse()?, br)],
                );
                let (a, u1, i1, o1) = ip::split_protocols(&fcx, a);
                let (b, u2, i2, o2) = ip::split_protocols(&fcx, b);
                (
                    a,
                    b,
                    vec![
                        Box::new(router),
                        Box::new(u1),
                        Box::new(i1),
                        Box::new(o1),
                        Box::new(u2),
                        Box::new(i2),
                        Box::new(o2),
                    ],
                )
            }
        };
        let (ca, cb) = (Arc::new(Counts::default()), Arc::new(Counts::default()));
        let client = endpoint(
            &fcx,
            Counted {
                inner: a,
                counts: ca.clone(),
            },
            "10.0.0.1",
            opts,
        );
        let server = endpoint(
            &fcx,
            Counted {
                inner: b,
                counts: cb.clone(),
            },
            "10.0.0.2",
            opts,
        );
        let mut listener = server.listen(80)?;
        let mut conns = Vec::new();
        for _ in 0..flows + idle {
            let c = client.connect(&fcx, "10.0.0.2:80".parse()?).await?;
            let s = listener.accept(&fcx).await?;
            conns.push((c, s));
        }
        let quiet = conns.split_off(flows);
        let sent0 = ca.sent.load(Ordering::Relaxed) + cb.sent.load(Ordering::Relaxed);
        let got0 = ca.delivered.load(Ordering::Relaxed) + cb.delivered.load(Ordering::Relaxed);
        checkpoint.wait().await;
        let mut joins = Vec::new();
        for (mut c, mut s) in conns {
            joins.push(fcx.spawn(move |fcx| async move {
                let buf = vec![0x5a; 65536];
                let mut left = per_flow;
                while left > 0 {
                    let n = left.min(buf.len());
                    s.write_all(&fcx, &buf[..n]).await?;
                    left -= n;
                }
                // Wait for the reader's one-byte "done", so the writer's
                // side stays open until every byte has arrived.
                let mut done = [0];
                c_read_exact(&fcx, &mut s, &mut done).await?;
                Ok(())
            }));
            joins.push(fcx.spawn(move |fcx| async move {
                let mut buf = vec![0; 65536];
                let mut left = per_flow;
                while left > 0 {
                    let n = left.min(buf.len());
                    c_read_exact(&fcx, &mut c, &mut buf[..n]).await?;
                    assert!(
                        buf[..n].iter().all(|&v| v == 0x5a),
                        "TCP delivered the wrong bytes"
                    );
                    left -= n;
                }
                c.write_all(&fcx, &[1]).await?;
                Ok(())
            }));
        }
        for j in joins {
            j.join(&fcx).await?;
        }
        checkpoint.wait().await;
        // Let the last ACKs and FINs land before counting what was lost.
        fcx.sleep(fictionet::time::ms(200)).await?;
        let sent = ca.sent.load(Ordering::Relaxed) + cb.sent.load(Ordering::Relaxed) - sent0;
        let got =
            ca.delivered.load(Ordering::Relaxed) + cb.delivered.load(Ordering::Relaxed) - got0;
        *result.lock().unwrap() = Some((sent, sent.saturating_sub(got)));
        drop(quiet);
        fcx.cancel();
        Ok(())
    })
}

async fn c_read_exact(fcx: &Cx, c: &mut tcp::TcpConnection, buf: &mut [u8]) -> fictionet::Result {
    let mut at = 0;
    while at < buf.len() {
        let n = c.read(fcx, &mut buf[at..]).await?;
        assert!(n > 0, "the connection ended early");
        at += n;
    }
    Ok(())
}

/// Sends one packet back and forth `n` times between the world and an echo
/// task, reusing its buffer.
fn ping_pong(n: usize) -> World {
    World::new(move |fcx, checkpoint| async move {
        let (mut a, mut b) = pair();
        let echo = fcx.spawn(move |fcx| async move {
            for _ in 0..n {
                let p = b.recv(&fcx).await?;
                b.send(p);
            }
            Ok(())
        });
        let mut p = Packet(vec![0x45; 1500]);
        checkpoint.wait().await;
        for _ in 0..n {
            a.send(p);
            p = a.recv(&fcx).await?;
        }
        echo.join(&fcx).await?;
        checkpoint.wait().await;
        fcx.cancel();
        Ok(())
    })
}

/// `n` sequential 64-byte requests and replies on one TCP connection.
fn tcp_exchanges(n: usize) -> World {
    World::new(move |fcx, checkpoint| async move {
        let (a, b) = pair();
        let client = tcp::endpoint(&fcx, a, "10.0.0.1".parse()?);
        let server = tcp::endpoint(&fcx, b, "10.0.0.2".parse()?);
        let mut listener = server.listen(80)?;
        let mut c = client.connect(&fcx, "10.0.0.2:80".parse()?).await?;
        let mut s = listener.accept(&fcx).await?;
        let echo = fcx.spawn(move |fcx| async move {
            let mut buf = [0; 64];
            for _ in 0..n {
                c_read_exact(&fcx, &mut s, &mut buf).await?;
                s.write_all(&fcx, &buf).await?;
            }
            Ok(())
        });
        let mut buf = [0; 64];
        checkpoint.wait().await;
        for _ in 0..n {
            c.write_all(&fcx, &[0x5a; 64]).await?;
            c_read_exact(&fcx, &mut c, &mut buf).await?;
        }
        echo.join(&fcx).await?;
        checkpoint.wait().await;
        fcx.cancel();
        Ok(())
    })
}

fn unread(delayed: bool, n: usize, result: Arc<Mutex<Option<u64>>>) -> World {
    World::new(move |fcx, checkpoint| async move {
        let (mut a, b) = pair();
        let mut far = if delayed {
            stdlib::network::delay(&fcx, fictionet::time::ms(60_000), b)
        } else {
            stdlib::network::bottleneck(&fcx, 1_000_000_000_000, 64, b)
        };
        checkpoint.wait().await;
        for i in 0..n {
            a.send(Packet(vec![0x45; 1500]));
            if i % 32 == 31 {
                fcx.yield_now().await?;
            }
        }
        // Give the link's task turns to take every packet from its input.
        for _ in 0..1000 {
            fcx.yield_now().await?;
        }
        checkpoint.wait().await;
        // Count what the bottleneck released into its output. A delay
        // releases nothing within the run.
        let mut kept = 0;
        while let Poll::Ready(Ok(_)) = poll_fn(|t| Poll::Ready(far.poll_recv(&fcx, t))).await {
            kept += 1;
        }
        *result.lock().unwrap() = Some(kept);
        fcx.cancel();
        Ok(())
    })
}
