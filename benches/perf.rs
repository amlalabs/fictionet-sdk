//! Fictionet's performance suite.
//!
//! Most groups build a small world and push traffic through it. The decoders
//! group uses in-memory bytes. Each prints a table. The counts do not depend on how
//! busy the machine is: allocations, packets sent and lost, round trips.
//! Times and rates are medians of several runs, with the range beside them,
//! because a shared machine makes any single run noisy.
//!
//! ```text
//! cargo bench --bench perf                 # every group
//! cargo bench --bench perf -- tcp path     # some groups
//! cargo bench --bench perf -- --list       # the groups, and what each measures
//! cargo bench --bench perf -- sites --reps 5
//! ```
//!
//! This is not a pass/fail test, and CI does not run it. Compare two
//! commits by running the same groups on each, one after the other, and
//! look at the counts first.

use fictionet::stdlib::codec::Frames;
use std::alloc::{GlobalAlloc, Layout, System};
use std::convert::Infallible;
use std::future::{Future, poll_fn};
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use fictionet::prelude::*;
use fictionet::relay::{self, Hello, Message as RelayMessage, unix};
use fictionet::stdlib::dns::op::{Message, MessageType, Query, ResponseCode};
use fictionet::stdlib::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::{self, ConnError, Connection, ip, tcp, tls, udp, web};
use fictionet::{
    Attacher, Cx, End, Interface, Packet, RecvError, WorldSocket, block_on, listen, pair, run,
};
use http::{Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Empty, Full};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

// ---------------------------------------------------------------------------
// Counting allocations

/// The system allocator, counting calls. A relaxed atomic add per call
/// costs little next to the allocation itself.
struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
/// Bytes allocated and not yet freed.
static LIVE: AtomicI64 = AtomicI64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        LIVE.fetch_add(n as i64 - l.size() as i64, Ordering::Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as i64, Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocs() -> u64 {
    ALLOCS.load(Ordering::Relaxed)
}

/// CPU time this process has used, user and system, in microseconds.
fn cpu_us() -> u64 {
    let mut r = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage fills the struct it is given.
    let r = unsafe {
        libc::getrusage(libc::RUSAGE_SELF, r.as_mut_ptr());
        r.assume_init()
    };
    ((r.ru_utime.tv_sec + r.ru_stime.tv_sec) * 1_000_000 + r.ru_utime.tv_usec + r.ru_stime.tv_usec)
        as u64
}

/// Heap bytes allocated and not yet freed, by the whole process.
fn live() -> i64 {
    LIVE.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Running and printing

struct Options {
    reps: usize,
    quick: bool,
}

type Group = (&'static str, &'static str, fn(&Options));

const GROUPS: &[Group] = &[
    (
        "tcp",
        "bulk TCP between two endpoints on one pair: 1, 10 and 100 flows",
        tcp_direct,
    ),
    (
        "path",
        "bulk TCP through a protocol split at each end and a router: 1, 10 and 100 flows",
        tcp_path,
    ),
    (
        "idle",
        "one active TCP flow beside 0 and 99 idle connections on the same endpoints",
        tcp_idle,
    ),
    (
        "delay",
        "bulk TCP over a delayed link (10 ms and 50 ms each way)",
        tcp_delay,
    ),
    (
        "sched",
        "the scheduler: packet ping-pong through a pair, and small TCP exchanges",
        sched,
    ),
    (
        "memory",
        "memory held by a delay and a bottleneck whose output is never read",
        memory,
    ),
    (
        "relay",
        "the relay protocol: socketpair sends, and an echo through listen",
        relay_group,
    ),
    (
        "sites",
        "HTTP/1.1 and HTTP/2 over TLS to a Sites site, from 1 and 10 sandboxes",
        sites,
    ),
    (
        "observe",
        "the cost of an observer watching the graph and ten sandbox links",
        observe,
    ),
    (
        "graph",
        "HTTP/2 latency with 1,000 sites while an observer watches the graph",
        graph,
    ),
    (
        "proxy",
        "fictionet attach --type http_proxy: DNS queries for cold and missing names",
        proxy,
    ),
    (
        "decoders",
        "in-memory TPKT/COTP, HTTP/1 requests and ITCH in 16 KiB chunks",
        decoders,
    ),
];

fn main() {
    // `cargo bench` passes `--bench`; a filter after `--` names groups.
    let mut args = std::env::args()
        .skip(1)
        .filter(|a| a != "--bench")
        .peekable();
    let mut names = Vec::new();
    let mut opts = Options {
        reps: 3,
        quick: false,
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "--reps" => opts.reps = args.next().and_then(|n| n.parse().ok()).expect("--reps N"),
            "--quick" => opts.quick = true,
            "--list" => {
                for (name, about, _) in GROUPS {
                    println!("{name:8} {about}");
                }
                return;
            }
            _ => names.push(a),
        }
    }
    for (name, about, f) in GROUPS {
        if names.is_empty() || names.iter().any(|n| n == name) {
            println!("\n## {name}: {about}\n");
            f(&opts);
        }
    }
}

/// A table printed with aligned columns.
struct Table {
    head: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    fn new(head: &[&str]) -> Table {
        Table {
            head: head.iter().map(|s| s.to_string()).collect(),
            rows: Vec::new(),
        }
    }

    fn row(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }

    fn print(&self) {
        let mut w: Vec<usize> = self.head.iter().map(|h| h.len()).collect();
        for r in &self.rows {
            for (i, c) in r.iter().enumerate() {
                w[i] = w[i].max(c.len());
            }
        }
        let line = |cells: &[String]| {
            let s: Vec<String> = cells
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    if i == 0 {
                        format!("{c:<0$}", w[i])
                    } else {
                        format!("{c:>0$}", w[i])
                    }
                })
                .collect();
            println!("| {} |", s.join(" | "));
        };
        line(&self.head);
        println!(
            "|{}|",
            w.iter()
                .enumerate()
                .map(|(i, n)| if i == 0 {
                    format!(":{}", "-".repeat(n + 1))
                } else {
                    format!("{}:", "-".repeat(n + 1))
                })
                .collect::<Vec<_>>()
                .join("|")
        );
        for r in &self.rows {
            line(r);
        }
    }
}

/// The median of `v`, and its range, as "median [min–max]".
fn spread(v: &[f64], digits: usize) -> String {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    let med = s[s.len() / 2];
    if s.len() == 1 {
        return format!("{med:.digits$}");
    }
    format!(
        "{med:.digits$} [{:.digits$}–{:.digits$}]",
        s[0],
        s[s.len() - 1]
    )
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    s[s.len() / 2]
}

/// The median of whole-number counts.
fn median_u(v: &[u64]) -> u64 {
    let mut s = v.to_vec();
    s.sort_unstable();
    s[s.len() / 2]
}

fn percentile(sorted: &[u64], p: f64) -> f64 {
    sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)] as f64 / 1000.0
}

/// Ends the run once the world is done: `fcx.cancel()` stops the tasks it
/// left running, and the run ends with `Cancelled`, which is expected.
fn finish(result: fictionet::Result) {
    if let Err(e) = result
        && !e.is::<fictionet::Cancelled>()
    {
        panic!("the world failed: {e}");
    }
}

// ---------------------------------------------------------------------------
// Decoders

fn decoders(o: &Options) {
    use std::hint::black_box;
    use stdlib::codec::{Decode, Stream, Wire, finish, pump};
    use stdlib::{http1, itch, tpkt};

    // Keep construction here so a decoder rename changes just one line.
    fn packets() -> impl Decode<Item = tpkt::Packet, Error = tpkt::Error> {
        Frames::<tpkt::Packet>::new()
    }
    fn requests() -> impl Decode<Item = http1::Request, Error = http1::Error> {
        http1::Requests::new()
    }
    fn messages() -> impl Decode<Item = Result<itch::Message, itch::Error>, Error = itch::Error> {
        Frames::<itch::Message>::default()
    }

    fn measure<D: Decode>(
        o: &Options,
        name: &str,
        frame: &[u8],
        make: impl Fn() -> D,
        mut consume: impl FnMut(D::Item),
    ) -> Vec<String>
    where
        D::Error: Clone + std::fmt::Debug,
    {
        let count = (4 * 1024 * 1024_usize).div_ceil(frame.len());
        let input = frame.repeat(count);
        let mut rates = Vec::with_capacity(o.reps);
        let mut items = Vec::with_capacity(o.reps);
        let mut per = Vec::with_capacity(o.reps);
        for _ in 0..o.reps {
            let before = allocs();
            let start = Instant::now();
            let mut stream = Stream::new(make());
            let mut decoded = 0;
            let mut on = |item| {
                consume(item);
                decoded += 1;
            };
            for chunk in black_box(&input).chunks(16 * 1024) {
                assert_eq!(pump(&mut stream, chunk, &mut on).unwrap(), chunk.len());
            }
            finish(&mut stream, &mut on).unwrap();
            assert_eq!(decoded, count);
            assert_eq!(stream.buffered(), 0);
            drop(stream);
            let seconds = start.elapsed().as_secs_f64();
            let allocations = allocs() - before;
            rates.push(input.len() as f64 / 1e6 / seconds);
            items.push(decoded as f64 / seconds);
            per.push(allocations as f64 / decoded as f64);
        }
        vec![
            name.to_string(),
            input.len().to_string(),
            count.to_string(),
            spread(&rates, 1),
            spread(&items, 0),
            spread(&per, 4),
        ]
    }

    // A COTP data TPDU with its end-of-message bit set and 128 payload bytes.
    let mut payload = vec![2, 0xf0, 0x80];
    payload.extend_from_slice(&[0x42; 128]);
    let packet = tpkt::Packet::new(payload).to_bytes().unwrap();
    let request =
        b"POST /orders HTTP/1.1\r\nHost: bench.local\r\nContent-Length: 16\r\n\r\n0123456789abcdef";
    let order = itch::AddOrder {
        header: itch::Header {
            locate: 7,
            tracking: 0,
            timestamp: itch::Timestamp::new(34_200_000_000_000).unwrap(),
        },
        order_ref: 1,
        side: itch::Side::Buy,
        shares: 300,
        stock: itch::Alpha::right_padded("ZXZZT").unwrap(),
        price: itch::Price4(102_500),
    }
    .to_bytes()
    .unwrap();
    let mut message = (order.len() as u16).to_be_bytes().to_vec();
    message.extend_from_slice(&order);

    let mut t = Table::new(&[
        "decoder",
        "bytes/run",
        "items/run",
        "MB/s",
        "items/s",
        "allocs/item",
    ]);
    t.row(measure(o, "TPKT/COTP", &packet, packets, |item| {
        black_box(item);
    }));
    t.row(measure(o, "HTTP/1 requests", request, requests, |item| {
        black_box(item);
    }));
    t.row(measure(o, "ITCH add orders", &message, messages, |item| {
        black_box(item.unwrap());
    }));
    t.print();
}

// ---------------------------------------------------------------------------
// TCP

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

/// One bulk run: how long it took, packets sent and lost, allocations.
struct Bulk {
    secs: f64,
    sent: u64,
    lost: u64,
    allocs: u64,
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
fn tcp_bulk(topology: Topology, flows: usize, idle: usize, per_flow: usize, opts: TcpOpts) -> Bulk {
    let out = Arc::new(Mutex::new(None));
    let result = out.clone();
    finish(block_on(run(move |fcx| async move {
        let (a, b, _keep): (End, End, Vec<Box<dyn Send>>) = match topology {
            Topology::Direct => {
                let (a, b) = pair();
                (a, b, Vec::new())
            }
            Topology::Delay(ms) => {
                let (a, b) = pair();
                let b = stdlib::delay(&fcx, fictionet::time::ms(ms), b);
                (a, b, Vec::new())
            }
            Topology::Path => {
                let (a, ar) = pair();
                let (br, b) = pair();
                let router = stdlib::route::router(
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
        let a0 = allocs();
        let start = Instant::now();
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
        let secs = start.elapsed().as_secs_f64();
        let allocs = allocs() - a0;
        // Let the last ACKs and FINs land before counting what was lost.
        fcx.sleep(fictionet::time::ms(200)).await?;
        let sent = ca.sent.load(Ordering::Relaxed) + cb.sent.load(Ordering::Relaxed) - sent0;
        let got =
            ca.delivered.load(Ordering::Relaxed) + cb.delivered.load(Ordering::Relaxed) - got0;
        *result.lock().unwrap() = Some(Bulk {
            secs,
            sent,
            lost: sent.saturating_sub(got),
            allocs,
        });
        drop(quiet);
        fcx.cancel();
        Ok(())
    })));
    out.lock().unwrap().take().expect("the run reported")
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

/// Runs `tcp_bulk` `reps` times and adds a row.
fn bulk_row(t: &mut Table, label: String, reps: usize, f: impl Fn() -> (Bulk, usize)) {
    let mut rates = Vec::new();
    let mut sent = Vec::new();
    let mut lost = Vec::new();
    let mut per_mb = Vec::new();
    for _ in 0..reps {
        let (b, bytes) = f();
        rates.push(bytes as f64 / b.secs / 1e6);
        sent.push(b.sent);
        lost.push(b.lost);
        per_mb.push(b.allocs as f64 / (bytes as f64 / 1e6));
    }
    lost.sort_unstable();
    t.row(vec![
        label,
        spread(&rates, 1),
        median_u(&sent).to_string(),
        format!("{} [{}–{}]", median_u(&lost), lost[0], lost[lost.len() - 1]),
        format!("{:.0}", median(&per_mb)),
    ]);
}

fn flows_table(o: &Options, topology: Topology) {
    let mut t = Table::new(&[
        "flows × bytes each",
        "MB/s",
        "packets sent",
        "packets lost",
        "allocs/MB",
    ]);
    let cases: &[(usize, usize)] = if o.quick {
        &[(1, 8 << 20), (10, 1 << 20), (100, 256 << 10)]
    } else {
        &[(1, 32 << 20), (10, 4 << 20), (100, 1 << 20)]
    };
    for &(flows, per_flow) in cases {
        bulk_row(
            &mut t,
            format!("{flows} × {} KiB", per_flow >> 10),
            o.reps,
            || {
                (
                    tcp_bulk(topology, flows, 0, per_flow, TcpOpts { buffer: None }),
                    flows * per_flow,
                )
            },
        );
    }
    t.print();
}

fn tcp_direct(o: &Options) {
    flows_table(o, Topology::Direct);
}

fn tcp_path(o: &Options) {
    flows_table(o, Topology::Path);
}

fn tcp_idle(o: &Options) {
    let mut t = Table::new(&[
        "active + idle connections",
        "MB/s",
        "packets sent",
        "packets lost",
        "allocs/MB",
    ]);
    let size = if o.quick { 8 << 20 } else { 32 << 20 };
    for idle in [0, 99] {
        bulk_row(&mut t, format!("1 + {idle}"), o.reps, || {
            (
                tcp_bulk(Topology::Direct, 1, idle, size, TcpOpts { buffer: None }),
                size,
            )
        });
    }
    t.print();
}

fn tcp_delay(o: &Options) {
    let mut t = Table::new(&[
        "delay each way, flows × bytes, buffer",
        "MB/s",
        "packets sent",
        "packets lost",
        "allocs/MB",
    ]);
    let cases: &[(u64, usize, usize)] = if o.quick {
        &[(10, 1, 4 << 20), (10, 10, 1 << 20)]
    } else {
        &[(10, 1, 16 << 20), (50, 1, 8 << 20), (10, 10, 4 << 20)]
    };
    for &(ms, flows, per_flow) in cases {
        for buffer in buffer_sizes() {
            let label = format!(
                "{ms} ms, {flows} × {} MiB, {}",
                per_flow >> 20,
                buffer.map_or("default".to_string(), |b| format!("{} KiB", b >> 10))
            );
            bulk_row(&mut t, label, o.reps, || {
                (
                    tcp_bulk(Topology::Delay(ms), flows, 0, per_flow, TcpOpts { buffer }),
                    flows * per_flow,
                )
            });
        }
    }
    t.print();
}

/// The buffer sizes the delay group compares.
fn buffer_sizes() -> Vec<Option<usize>> {
    vec![None, Some(1 << 20)]
}

// ---------------------------------------------------------------------------
// The scheduler

fn sched(o: &Options) {
    let mut t = Table::new(&[
        "workload",
        "time, ms",
        "allocations",
        "allocs per round trip",
    ]);
    let n = if o.quick { 100_000 } else { 500_000 };
    let mut times = Vec::new();
    let mut counts = Vec::new();
    for _ in 0..o.reps {
        let (secs, a) = ping_pong(n);
        times.push(secs * 1e3);
        counts.push(a);
    }
    let a = median_u(&counts);
    t.row(vec![
        format!("{n} packet round trips through a pair"),
        spread(&times, 1),
        a.to_string(),
        format!("{:.2}", a as f64 / n as f64),
    ]);
    let n = if o.quick { 2_000 } else { 10_000 };
    let mut times = Vec::new();
    let mut counts = Vec::new();
    for _ in 0..o.reps {
        let (secs, a) = tcp_exchanges(n);
        times.push(secs * 1e3);
        counts.push(a);
    }
    let a = median_u(&counts);
    t.row(vec![
        format!("{n} TCP 64-byte request/reply exchanges"),
        spread(&times, 1),
        a.to_string(),
        format!("{:.2}", a as f64 / n as f64),
    ]);
    t.print();
}

/// Sends one packet back and forth `n` times between the world and an echo
/// task, reusing its buffer. Returns the time and the allocations.
fn ping_pong(n: usize) -> (f64, u64) {
    let out = Arc::new(Mutex::new((0.0, 0)));
    let result = out.clone();
    finish(block_on(run(move |fcx| async move {
        let (mut a, mut b) = pair();
        let echo = fcx.spawn(move |fcx| async move {
            for _ in 0..n {
                let p = b.recv(&fcx).await?;
                b.send(p);
            }
            Ok(())
        });
        let mut p = Packet(vec![0x45; 1500]);
        let a0 = allocs();
        let start = Instant::now();
        for _ in 0..n {
            a.send(p);
            p = a.recv(&fcx).await?;
        }
        echo.join(&fcx).await?;
        *result.lock().unwrap() = (start.elapsed().as_secs_f64(), allocs() - a0);
        fcx.cancel();
        Ok(())
    })));
    *out.lock().unwrap()
}

/// `n` sequential 64-byte requests and replies on one TCP connection.
fn tcp_exchanges(n: usize) -> (f64, u64) {
    let out = Arc::new(Mutex::new((0.0, 0)));
    let result = out.clone();
    finish(block_on(run(move |fcx| async move {
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
        let a0 = allocs();
        let start = Instant::now();
        for _ in 0..n {
            c.write_all(&fcx, &[0x5a; 64]).await?;
            c_read_exact(&fcx, &mut c, &mut buf).await?;
        }
        echo.join(&fcx).await?;
        *result.lock().unwrap() = (start.elapsed().as_secs_f64(), allocs() - a0);
        fcx.cancel();
        Ok(())
    })));
    *out.lock().unwrap()
}

// ---------------------------------------------------------------------------
// Memory

fn memory(o: &Options) {
    let mut t = Table::new(&[
        "unread link",
        "packets sent",
        "payload, MB",
        "heap growth, MB",
        "packets in the unread end",
    ]);
    let n = if o.quick { 10_000 } else { 40_000 };
    for kind in ["delay 60 s", "bottleneck, 64-packet queue"] {
        let runs: Vec<(i64, u64)> = (0..o.reps).map(|_| unread(kind, n)).collect();
        let grew: Vec<f64> = runs.iter().map(|r| r.0 as f64 / 1e6).collect();
        let kept = median_u(&runs.iter().map(|r| r.1).collect::<Vec<_>>());
        t.row(vec![
            kind.to_string(),
            n.to_string(),
            format!("{:.1}", n as f64 * 1500.0 / 1e6),
            spread(&grew, 1),
            kept.to_string(),
        ]);
    }
    t.print();
}

/// Sends `n` 1,500-byte packets into a link whose other side is never read,
/// then reports how much the heap grew, and how many packets the link
/// released into its unread end (read out at the end). A delay releases
/// none within the run: what it holds is still waiting inside it.
fn unread(kind: &'static str, n: usize) -> (i64, u64) {
    let out = Arc::new(Mutex::new((0, 0)));
    let result = out.clone();
    finish(block_on(run(move |fcx| async move {
        let (mut a, b) = pair();
        let mut far = if kind.starts_with("delay") {
            stdlib::delay(&fcx, fictionet::time::ms(60_000), b)
        } else {
            stdlib::bottleneck(&fcx, 1_000_000_000_000, 64, b)
        };
        let before = live();
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
        let grew = live() - before;
        // Count what the bottleneck released into its output. A delay
        // releases nothing within the run.
        let mut kept = 0;
        while let Poll::Ready(Ok(_)) = poll_fn(|t| Poll::Ready(far.poll_recv(&fcx, t))).await {
            kept += 1;
        }
        *result.lock().unwrap() = (grew, kept);
        fcx.cancel();
        Ok(())
    })));
    *out.lock().unwrap()
}

// ---------------------------------------------------------------------------
// The relay protocol

fn relay_group(o: &Options) {
    let mut t = Table::new(&["workload", "rate", "allocations per packet"]);
    let n = if o.quick { 50_000 } else { 200_000 };
    let mut rates = Vec::new();
    let mut per = Vec::new();
    for _ in 0..o.reps {
        let (secs, a) = socketpair_sends(n, 1500);
        rates.push(n as f64 / secs / 1e6);
        per.push(a as f64 / n as f64);
    }
    t.row(vec![
        format!("{n} sends of 1,500 bytes on a socketpair"),
        format!("{} M/s", spread(&rates, 2)),
        format!("{:.2}", median(&per)),
    ]);
    for outstanding in [1, 64] {
        let n = if o.quick { 20_000 } else { 100_000 };
        let mut rates = Vec::new();
        let mut per = Vec::new();
        for _ in 0..o.reps {
            let (secs, a) = listen_echo(n, outstanding);
            rates.push(n as f64 / secs / 1e3);
            per.push(a as f64 / n as f64);
        }
        t.row(vec![
            format!("{n} echoes through listen, {outstanding} outstanding"),
            format!("{} k/s", spread(&rates, 0)),
            format!("{:.2}", median(&per)),
        ]);
    }
    t.print();
}

/// Sends `n` packet messages over a socketpair with the relay's own send,
/// and receives them on another thread. Returns the time, and the
/// allocations of the sending thread's calls.
fn socketpair_sends(n: usize, size: usize) -> (f64, u64) {
    let mut fds = [0; 2];
    // SAFETY: socketpair fills two fds, owned from here.
    let r = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    assert_eq!(r, 0, "socketpair");
    let (a, b) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let reader = std::thread::spawn(move || {
        let mut buf = vec![0u8; relay::MAX_MESSAGE];
        for _ in 0..n {
            let got = unix::recv(b.as_raw_fd(), &mut buf, false).unwrap();
            assert_eq!(got, size + 1);
        }
    });
    let payload = vec![0x45u8; size];
    let kind = [relay::PACKET];
    let a0 = allocs();
    let start = Instant::now();
    for _ in 0..n {
        unix::send_parts(a.as_raw_fd(), &[&kind, &payload], false).unwrap();
    }
    let a1 = allocs() - a0;
    reader.join().unwrap();
    (start.elapsed().as_secs_f64(), a1)
}

static SOCKETS: AtomicU64 = AtomicU64::new(0);

/// A path for a world socket, in the build's target directory.
fn socket_path(tag: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("bench-sockets");
    std::fs::create_dir_all(&dir).unwrap();
    let n = SOCKETS.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("{tag}-{}-{n}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

/// A world that echoes every packet of the sandbox `agent`, reached through
/// `listen`, and a client that speaks the relay protocol to it with
/// `outstanding` packets in flight. Returns the time for `n` echoes, and
/// the allocations of the whole process during them.
fn listen_echo(n: usize, outstanding: usize) -> (f64, u64) {
    let path = socket_path("echo");
    let (attacher, mut attachments) = fictionet::attachments();
    let listening = listen(WorldSocket::UnixSocket(path.clone()), attacher).unwrap();
    let world = std::thread::spawn(move || {
        finish(block_on(run(move |fcx| async move {
            let mut agent = attachments.get(&fcx, "agent").await?;
            loop {
                match agent.recv(&fcx).await {
                    Ok(p) => agent.send(p),
                    Err(_) => return Ok(()),
                }
            }
        })));
    });
    let fd = unix::connect(&path).unwrap();
    let hello = Hello {
        version: relay::VERSION,
        mtu: 1500,
        kind: "tun".into(),
        name: "agent".into(),
    };
    unix::send(fd.as_raw_fd(), &RelayMessage::Hello(hello).encode(), false).unwrap();
    let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
    let got = unix::recv(fd.as_raw_fd(), &mut buf, false).unwrap();
    assert_eq!(&buf[..got], &[relay::ACCEPT]);
    let payload = vec![0x45u8; 1500];
    let kind = [relay::PACKET];
    let a0 = allocs();
    let start = Instant::now();
    let mut sent = 0;
    let mut back = 0;
    while back < n {
        while sent < n && sent - back < outstanding {
            unix::send_parts(fd.as_raw_fd(), &[&kind, &payload], false).unwrap();
            sent += 1;
        }
        let got = unix::recv(fd.as_raw_fd(), &mut buf, false).unwrap();
        assert_eq!(got, 1501, "the echo came back whole");
        back += 1;
    }
    let secs = start.elapsed().as_secs_f64();
    let a1 = allocs() - a0;
    drop(fd);
    world.join().unwrap();
    drop(listening);
    let _ = std::fs::remove_file(&path);
    (secs, a1)
}

// ---------------------------------------------------------------------------
// Sites

/// What a Sites run watches, through a real observer session.
#[derive(Clone, Copy, PartialEq)]
enum Watch {
    None,
    /// A `watch` request: the graph and its changes.
    Graph,
    /// The graph, and a `packets` stream on every sandbox link.
    Packets,
}

struct HttpRun {
    rps: f64,
    p50: f64,
    p99: f64,
    max: f64,
    cpu_per_request: f64,
    allocs_per_request: f64,
    rows: u64,
}

#[derive(Clone, Copy)]
struct HttpCase {
    sandboxes: usize,
    h2: bool,
    requests: usize,
    body: usize,
    sites: usize,
    watch: Watch,
    /// Whether the world subscribes a callback (one that does nothing) to
    /// its events.
    hooks: bool,
}

#[derive(Clone)]
struct Page(Bytes);

impl tower_service::Service<Request<fictionet::stdlib::web::Body>> for Page {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Request<fictionet::stdlib::web::Body>) -> Self::Future {
        std::future::ready(Ok(Response::new(Full::new(self.0.clone()))))
    }
}

fn sites(o: &Options) {
    let requests = if o.quick { 5_000 } else { 30_000 };
    let mut t = http_table();
    for h2 in [false, true] {
        for sandboxes in [1, 10] {
            http_row(
                &mut t,
                o.reps,
                HttpCase {
                    sandboxes,
                    h2,
                    requests,
                    body: 1024,
                    sites: 1,
                    watch: Watch::None,
                    hooks: false,
                },
            );
        }
    }
    http_row(
        &mut t,
        o.reps,
        HttpCase {
            sandboxes: 10,
            h2: false,
            requests,
            body: 1024,
            sites: 1,
            watch: Watch::None,
            hooks: true,
        },
    );
    t.print();
}

fn observe(o: &Options) {
    // Long enough for many packet ticks (every 100 ms) and graph ticks
    // (every 250 ms).
    let requests = if o.quick { 40_000 } else { 200_000 };
    let mut t = http_table();
    for watch in [Watch::None, Watch::Graph, Watch::Packets] {
        http_row(
            &mut t,
            o.reps,
            HttpCase {
                sandboxes: 10,
                h2: false,
                requests,
                body: 1024,
                sites: 1,
                watch,
                hooks: false,
            },
        );
    }
    t.print();
}

fn graph(o: &Options) {
    let requests = if o.quick { 40_000 } else { 150_000 };
    let mut t = http_table();
    for watch in [Watch::None, Watch::Graph] {
        http_row(
            &mut t,
            o.reps,
            HttpCase {
                sandboxes: 1,
                h2: true,
                requests,
                body: 1024,
                sites: 1000,
                watch,
                hooks: false,
            },
        );
    }
    t.print();
}

fn http_table() -> Table {
    Table::new(&[
        "case",
        "requests/s",
        "p50 µs",
        "p99 µs",
        "max µs",
        "CPU µs/req",
        "allocs/req",
        "observer rows",
    ])
}

fn http_row(t: &mut Table, reps: usize, case: HttpCase) {
    let runs: Vec<HttpRun> = (0..reps).map(|_| http_run(case)).collect();
    let pick = |f: fn(&HttpRun) -> f64| runs.iter().map(f).collect::<Vec<f64>>();
    let label = format!(
        "{} × {}{}{}{}",
        if case.h2 { "HTTP/2" } else { "HTTP/1.1" },
        case.sandboxes,
        if case.sites > 1 {
            format!(", {} sites", case.sites)
        } else {
            String::new()
        },
        if case.hooks {
            ", events subscribed"
        } else {
            ""
        },
        match case.watch {
            Watch::None => "",
            Watch::Graph => ", graph watched",
            Watch::Packets => ", graph + 10 links watched",
        }
    );
    t.row(vec![
        label,
        spread(&pick(|r| r.rps), 0),
        format!("{:.1}", median(&pick(|r| r.p50))),
        format!("{:.1}", median(&pick(|r| r.p99))),
        spread(&pick(|r| r.max), 0),
        format!("{:.2}", median(&pick(|r| r.cpu_per_request))),
        format!("{:.1}", median(&pick(|r| r.allocs_per_request))),
        median_u(&runs.iter().map(|r| r.rows).collect::<Vec<_>>()).to_string(),
    ]);
}

const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

struct Machine {
    tcp: tcp::Endpoint,
    udp: udp::Endpoint,
    _icmp: End,
}

fn machine(fcx: &Cx, attacher: &Attacher, name: &str, addr: Ipv4Addr) -> Machine {
    let end = attacher.attach(name).unwrap();
    let (tcp, udp, icmp, _other) = ip::split_protocols(fcx, end);
    Machine {
        tcp: tcp::endpoint(fcx, tcp, addr.into()),
        udp: udp::endpoint(fcx, udp, addr.into()),
        _icmp: icmp,
    }
}

async fn lookup(fcx: &Cx, m: &Machine, name: &str) -> Ipv4Addr {
    let mut socket = m
        .udp
        .bind(40000 + (fcx.random_u64() % 20000) as u16)
        .unwrap();
    let mut q = Message::query();
    q.metadata.id = fcx.random_u64() as u16;
    q.metadata.recursion_desired = true;
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    socket.send_to(&q.to_vec().unwrap(), SocketAddr::new(GATEWAY.into(), 53));
    let (bytes, _) = socket.recv(fcx).await.unwrap();
    let r = Message::from_vec(&bytes).unwrap();
    assert_eq!(r.metadata.message_type, MessageType::Response);
    assert_eq!(r.metadata.response_code, ResponseCode::NoError, "{name}");
    r.answers
        .iter()
        .find_map(|rec| match &rec.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .expect("an A record")
}

fn certs() -> (
    RootCertStore,
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
) {
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca.self_signed(&ca_key).unwrap();
    let mut leaf = CertificateParams::new(vec!["bench.test".to_string()]).unwrap();
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    (
        roots,
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
}

/// One Sites world with `case.sandboxes` sandboxes, each holding one TLS
/// connection to `bench.test` and sending `case.requests / sandboxes`
/// requests on it, one at a time.
fn http_run(case: HttpCase) -> HttpRun {
    let (attacher, attachments) = fictionet::attachments();
    // The observer reaches the world through a real world socket, as the
    // dashboard does.
    let path = socket_path("sites");
    let listening = listen(WorldSocket::UnixSocket(path.clone()), attacher.clone()).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(false));
    let measuring = Arc::new(AtomicBool::new(false));
    let observer = (case.watch != Watch::None).then(|| {
        let (stop, ready, measuring, path) =
            (stop.clone(), ready.clone(), measuring.clone(), path.clone());
        std::thread::spawn(move || {
            watch_world(&path, case.watch, case.sandboxes, &stop, &ready, &measuring)
        })
    });
    let timing = measuring.clone();
    let out = Arc::new(Mutex::new(None));
    let result = out.clone();
    let wait_for = ready.clone();
    finish(block_on(run(move |fcx| async move {
        let (roots, chain, key) = certs();
        let roots = Arc::new(roots);
        let config = Arc::new(
            tls::config_builder(
                &fcx,
                SystemTime::now(),
                rustls::crypto::ring::default_provider(),
            )
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?,
        );
        let page = Page(Bytes::from(vec![b'x'; case.body]));
        let sites = web::Sites::new(move |_| {
            let config = config.clone();
            Some(web::Site::new(page.clone()).tls(move |_| config.clone()))
        });
        if case.hooks {
            fcx.events().subscribe(|_| {});
        }
        sites.serve(&fcx, attachments)?;
        let machines: Vec<Machine> = (0..case.sandboxes)
            .map(|i| {
                machine(
                    &fcx,
                    &attacher,
                    &format!("sandbox{i}"),
                    Ipv4Addr::new(10, 0, 0, 2 + i as u8),
                )
            })
            .collect();
        let addr = lookup(&fcx, &machines[0], "bench.test").await;
        for i in 1..case.sites {
            lookup(&fcx, &machines[0], &format!("site{i}.test")).await;
        }
        let mut clients = Vec::new();
        for m in &machines {
            let conn = m
                .tcp
                .connect(&fcx, SocketAddr::new(addr.into(), 443))
                .await?;
            let alpn: &[u8] = if case.h2 { b"h2" } else { b"http/1.1" };
            let mut t = TlsClient::new(conn, &roots, "bench.test", alpn);
            t.handshake(&fcx)
                .await
                .map_err(|e| fictionet::Error::msg(format!("{e:?}")))?;
            let mut c = Client::new(&fcx, t, case.h2).await;
            for _ in 0..100 {
                c.get().await;
            }
            clients.push(c);
        }
        // Wait until the observer is watching, while the world runs.
        if case.watch != Watch::None {
            while !wait_for.load(Ordering::Acquire) {
                fcx.sleep(fictionet::time::ms(5)).await?;
            }
        }
        let each = case.requests / case.sandboxes;
        let lat = Arc::new(Mutex::new(Vec::with_capacity(case.requests)));
        let (a0, cpu0) = (allocs(), cpu_us());
        let start = Instant::now();
        timing.store(true, Ordering::Release);
        let mut tasks = Vec::new();
        for mut c in clients {
            let lat = lat.clone();
            tasks.push(fcx.spawn(move |_| async move {
                let mut samples = Vec::with_capacity(each);
                for _ in 0..each {
                    let t = Instant::now();
                    let (status, version, len) = c.get().await;
                    assert_eq!(status, StatusCode::OK);
                    assert_eq!(len, case.body);
                    assert_eq!(
                        version,
                        if case.h2 {
                            Version::HTTP_2
                        } else {
                            Version::HTTP_11
                        }
                    );
                    samples.push(t.elapsed().as_nanos() as u64);
                }
                lat.lock().unwrap().extend(samples);
                Ok(())
            }));
        }
        for t in tasks {
            t.join(&fcx).await?;
        }
        let secs = start.elapsed().as_secs_f64();
        let (a1, cpu1) = (allocs() - a0, cpu_us() - cpu0);
        // Rows still on their way belong to the timed requests.
        fcx.sleep(fictionet::time::ms(150)).await?;
        timing.store(false, Ordering::Release);
        let mut l = lat.lock().unwrap();
        l.sort_unstable();
        let total = l.len();
        *result.lock().unwrap() = Some(HttpRun {
            rps: total as f64 / secs,
            p50: percentile(&l, 0.5),
            p99: percentile(&l, 0.99),
            max: percentile(&l, 1.0),
            cpu_per_request: cpu1 as f64 / total as f64,
            allocs_per_request: a1 as f64 / total as f64,
            rows: 0,
        });
        fcx.cancel();
        Ok(())
    })));
    stop.store(true, Ordering::Release);
    let rows = observer.map_or(0, |o| o.join().unwrap());
    drop(listening);
    let _ = std::fs::remove_file(&path);
    let mut r = out.lock().unwrap().take().expect("the run reported");
    r.rows = rows;
    r
}

/// An observer session: watches the graph and, for `Watch::Packets`, the
/// packets of every sandbox link, reading every value until `stop`.
/// Returns how many packet rows arrived while `measuring` was set. Rows
/// lag the packets by up to one 100 ms tick, so the count is close, not
/// exact.
fn watch_world(
    path: &std::path::Path,
    watch: Watch,
    sandboxes: usize,
    stop: &AtomicBool,
    ready: &AtomicBool,
    measuring: &AtomicBool,
) -> u64 {
    let path = path.to_str().unwrap();
    let mut client = relay::observer::Client::connect(path, "bench").expect("an observer session");
    client
        .set_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    // Wait until every sandbox has a link in the graph.
    let links = loop {
        let graph = client.call(r#"{"op":"graph"}"#).expect("a graph");
        let links = sandbox_links(&String::from_utf8_lossy(&graph.bytes));
        if links.len() >= sandboxes {
            break links;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // Ready once the world has answered every subscription: the graph's
    // snapshot, and the `link` event that starts each packet stream.
    let mut waiting = 1;
    client.request(r#"{"op":"watch"}"#).unwrap();
    if watch == Watch::Packets {
        for link in &links {
            client
                .request(&format!(r#"{{"op":"packets","link":"{link}","after":0}}"#))
                .unwrap();
        }
        waiting += links.len();
    }
    let mut rows = 0;
    while !stop.load(Ordering::Acquire) {
        match client.next_value() {
            Ok(Some(v)) => {
                if v.bytes.starts_with(br#"{"event":"snapshot""#)
                    || v.bytes.starts_with(br#"{"event":"link""#)
                {
                    waiting -= 1;
                    if waiting == 0 {
                        ready.store(true, Ordering::Release);
                    }
                }
                // Rows of packets sent while the requests were timed.
                if v.bytes.starts_with(br#"{"event":"packet""#) && measuring.load(Ordering::Acquire)
                {
                    rows += 1;
                }
            }
            Ok(None) => break,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => panic!("observer: {e}"),
        }
    }
    rows
}

/// The ids of the links that end at a sandbox, read from a graph's JSON.
fn sandbox_links(graph: &str) -> Vec<String> {
    // Nodes look like {"id":"s7","kind":"sandbox",...}, edges like
    // {"id":"e7","a":"t11","b":"s7",...}.
    let field = |obj: &str, key: &str| -> Option<String> {
        let at = obj.find(&format!("\"{key}\":\""))? + key.len() + 4;
        Some(obj[at..].split('"').next()?.to_string())
    };
    let objects: Vec<&str> = graph.split('{').collect();
    let sandboxes: Vec<String> = objects
        .iter()
        .filter(|o| o.contains(r#""kind":"sandbox""#))
        .filter_map(|o| field(o, "id"))
        .collect();
    objects
        .iter()
        .filter(|o| o.starts_with(r#""id":"e"#))
        .filter(|o| {
            [field(o, "a"), field(o, "b")]
                .iter()
                .flatten()
                .any(|end| sandboxes.contains(end))
        })
        .filter_map(|o| field(o, "id"))
        .collect()
}

// A rustls client as a `Connection`.

struct TlsClient<C> {
    conn: C,
    tls: ClientConnection,
    out: Vec<u8>,
    inbuf: Box<[u8]>,
    pending: Vec<u8>,
}

impl<C: Connection + Unpin> TlsClient<C> {
    fn new(conn: C, roots: &Arc<RootCertStore>, name: &str, alpn: &[u8]) -> Self {
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots.clone())
                .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        let tls = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from(name.to_owned()).unwrap(),
        )
        .unwrap();
        TlsClient {
            conn,
            tls,
            out: Vec::new(),
            inbuf: vec![0; 16384].into_boxed_slice(),
            pending: Vec::new(),
        }
    }

    fn poll_flush(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        loop {
            if self.out.is_empty() {
                if !self.tls.wants_write() {
                    return Poll::Ready(Ok(()));
                }
                self.tls.write_tls(&mut self.out).unwrap();
            }
            match self.conn.poll_write(fcx, cx, &self.out) {
                Poll::Ready(Ok(n)) => {
                    self.out.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// Reads from the connection into rustls once. `Ok(false)` at the end
    /// of the stream.
    fn poll_fill(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<bool, ConnError>> {
        let fresh;
        let mut data: &[u8] = if !self.pending.is_empty() {
            fresh = std::mem::take(&mut self.pending);
            &fresh
        } else {
            let n = match self.conn.poll_read(fcx, cx, &mut self.inbuf) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                let _ = self.tls.read_tls(&mut &[][..]);
            }
            &self.inbuf[..n]
        };
        let n = data.len();
        loop {
            if !data.is_empty() && self.tls.read_tls(&mut data).is_err() {
                self.pending = data.to_vec();
                return Poll::Ready(Ok(true));
            }
            if self.tls.process_new_packets().is_err() {
                return Poll::Ready(Err(ConnError::Broken));
            }
            if data.is_empty() {
                return Poll::Ready(Ok(n > 0));
            }
        }
    }

    async fn handshake(&mut self, fcx: &Cx) -> Result<(), ConnError> {
        poll_fn(|cx| {
            loop {
                match self.poll_flush(fcx, cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
                if !self.tls.is_handshaking() {
                    return Poll::Ready(Ok(()));
                }
                match self.poll_fill(fcx, cx) {
                    Poll::Ready(Ok(true)) => {}
                    Poll::Ready(Ok(false)) => return Poll::Ready(Err(ConnError::Closed)),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await
    }
}

impl<C: Connection + Unpin> Connection for TlsClient<C> {
    fn poll_read(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        loop {
            match self.tls.reader().read(buf) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Poll::Ready(Ok(0)),
                Err(_) => return Poll::Ready(Err(ConnError::Broken)),
            }
            if let Poll::Ready(Err(e)) = self.poll_flush(fcx, cx) {
                return Poll::Ready(Err(e));
            }
            match self.poll_fill(fcx, cx) {
                Poll::Ready(Ok(true)) => {}
                Poll::Ready(Ok(false)) => {
                    return Poll::Ready(Ok(self.tls.reader().read(buf).unwrap_or(0)));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_write(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        if let Poll::Ready(Err(e)) = self.poll_flush(fcx, cx) {
            return Poll::Ready(Err(e));
        }
        let n = self.tls.writer().write(data).unwrap();
        let _ = self.poll_flush(fcx, cx);
        Poll::Ready(Ok(n))
    }

    fn poll_shutdown(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        self.tls.send_close_notify();
        match self.poll_flush(fcx, cx) {
            Poll::Ready(Ok(())) => self.conn.poll_shutdown(fcx, cx),
            other => other,
        }
    }
}

// A hyper client over a `Connection`.

struct Io<C> {
    fcx: Cx,
    conn: C,
}

impl<C: Connection + Unpin> hyper::rt::Read for Io<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut tmp = [0u8; 16 * 1024];
        let tmp = &mut tmp[..buf.remaining().min(16 * 1024)];
        match this.conn.poll_read(&this.fcx, cx, tmp) {
            Poll::Ready(Ok(n)) => {
                buf.put_slice(&tmp[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<C: Connection + Unpin> hyper::rt::Write for Io<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.conn
            .poll_write(&this.fcx, cx, data)
            .map_err(std::io::Error::other)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.conn
            .poll_shutdown(&this.fcx, cx)
            .map_err(std::io::Error::other)
    }
}

#[derive(Clone)]
struct Exec(Cx);

impl<F: Future<Output = ()> + Send + 'static> hyper::rt::Executor<F> for Exec {
    fn execute(&self, fut: F) {
        self.0.spawn(move |_| async move {
            fut.await;
            Ok(())
        });
    }
}

enum Client {
    H1(hyper::client::conn::http1::SendRequest<Empty<Bytes>>),
    H2(hyper::client::conn::http2::SendRequest<Empty<Bytes>>),
}

impl Client {
    async fn new<C: Connection + Unpin>(fcx: &Cx, conn: C, h2: bool) -> Client {
        let io = Io {
            fcx: fcx.clone(),
            conn,
        };
        if h2 {
            let (send, conn) = hyper::client::conn::http2::handshake(Exec(fcx.clone()), io)
                .await
                .unwrap();
            fcx.spawn(move |_| async move {
                let _ = conn.await;
                Ok(())
            });
            Client::H2(send)
        } else {
            let (send, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
            fcx.spawn(move |_| async move {
                let _ = conn.await;
                Ok(())
            });
            Client::H1(send)
        }
    }

    /// GETs `https://bench.test/`: the status, the version and the body's
    /// length.
    async fn get(&mut self) -> (StatusCode, Version, usize) {
        let response = match self {
            Client::H1(s) => {
                s.ready().await.unwrap();
                let r = Request::builder()
                    .uri("/")
                    .header("host", "bench.test")
                    .body(Empty::new())
                    .unwrap();
                s.send_request(r).await.unwrap()
            }
            Client::H2(s) => {
                s.ready().await.unwrap();
                let r = Request::builder()
                    .uri("https://bench.test/")
                    .body(Empty::new())
                    .unwrap();
                s.send_request(r).await.unwrap()
            }
        };
        let (status, version) = (response.status(), response.version());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, version, body.len())
    }
}

// ---------------------------------------------------------------------------
// The proxy

/// The `fictionet` binary that the proxy group runs: `FICTIONET_BIN`, or
/// the one built with this suite.
fn fictionet_bin() -> String {
    std::env::var("FICTIONET_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_fictionet").to_string())
}

/// "relay:<token>" in base64, for the token the proxy group uses.
const PROXY_TOKEN: &str = "bench-token";
const PROXY_AUTH: &str = "Basic cmVsYXk6YmVuY2gtdG9rZW4=";

fn proxy(o: &Options) {
    let mut t = Table::new(&["workload", "DNS queries for the name", "time, ms"]);
    let burst = 32;
    let sequential = if o.quick { 20 } else { 50 };
    let mut rows: Vec<(String, Vec<u64>, Vec<f64>)> = vec![
        (
            format!("{burst} requests at once to one cold name"),
            Vec::new(),
            Vec::new(),
        ),
        (
            format!("{sequential} requests in a row to a missing name"),
            Vec::new(),
            Vec::new(),
        ),
    ];
    for _ in 0..o.reps {
        let (cold, missing) = proxy_run(burst, sequential);
        rows[0].1.push(cold.0);
        rows[0].2.push(cold.1);
        rows[1].1.push(missing.0);
        rows[1].2.push(missing.1);
    }
    for (label, queries, times) in rows {
        t.row(vec![
            label,
            median_u(&queries).to_string(),
            spread(&times, 1),
        ]);
    }
    t.print();
}

/// A Sites world with `plain.test`, and an HTTP proxy attached to it.
/// Returns the DNS queries and time for `burst` simultaneous requests to
/// `plain.test` (the proxy's cache is cold), and for `sequential` requests
/// in a row to `missing.test`, which does not exist.
fn proxy_run(burst: usize, sequential: usize) -> ((u64, f64), (u64, f64)) {
    use std::io::BufRead;
    let path = socket_path("proxy");
    let dir = path.parent().unwrap().to_path_buf();
    let token = dir.join(format!("token-{}", std::process::id()));
    std::fs::write(&token, PROXY_TOKEN).unwrap();
    let queries: Arc<Mutex<std::collections::HashMap<String, u64>>> = Arc::default();
    let stop = Arc::new(AtomicBool::new(false));
    let (attacher, attachments) = fictionet::attachments();
    let listening = listen(WorldSocket::UnixSocket(path.clone()), attacher).unwrap();
    let world = {
        let (queries, stop) = (queries.clone(), stop.clone());
        std::thread::spawn(move || {
            finish(block_on(run(move |fcx| async move {
                let page = Page(Bytes::from_static(b"plain site\n"));
                fcx.events().subscribe(move |e| {
                    if e.is("dns", "query")
                        && let Some(name) = e.str("name")
                        && e.u64("qtype") == Some(1)
                    {
                        *queries.lock().unwrap().entry(name.to_owned()).or_default() += 1;
                    }
                });
                web::Sites::new(move |host: &str| {
                    (host == "plain.test").then(|| web::Site::new(page.clone()).plain_http())
                })
                .serve(&fcx, attachments)?;
                while !stop.load(Ordering::Acquire) {
                    fcx.sleep(fictionet::time::ms(10)).await?;
                }
                fcx.cancel();
                Ok(())
            })));
        })
    };
    let mut child = std::process::Command::new(fictionet_bin())
        .args([
            "attach",
            "--world",
            &format!("unix:{}", path.display()),
            "--name",
            "agent",
            "--type",
            "http_proxy",
        ])
        .args([
            "--listen",
            "127.0.0.1:0",
            "--token-file",
            token.to_str().unwrap(),
            "--ip-addr",
            "10.0.0.2",
            "--dns",
            "10.0.0.1",
        ])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("fictionet attach");
    let mut lines = std::io::BufReader::new(child.stderr.take().unwrap()).lines();
    let first = lines.next().unwrap().unwrap();
    let addr: SocketAddr = first
        .split(" on ")
        .nth(1)
        .and_then(|r| r.split(',').next())
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("attach said: {first}"));
    std::thread::spawn(move || for _ in lines.map_while(Result::ok) {});
    let get = move |host: &str| -> String {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        write!(s, "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: {PROXY_AUTH}\r\nConnection: close\r\n\r\n").unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    };
    let count = |name: &str| queries.lock().unwrap().get(name).copied().unwrap_or(0);

    let start = Instant::now();
    let gate = Arc::new(std::sync::Barrier::new(burst));
    let threads: Vec<_> = (0..burst)
        .map(|_| {
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                get("plain.test")
            })
        })
        .collect();
    for th in threads {
        let answer = th.join().unwrap();
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    }
    let cold = (count("plain.test"), start.elapsed().as_secs_f64() * 1e3);

    let start = Instant::now();
    for _ in 0..sequential {
        let answer = get("missing.test");
        assert!(answer.starts_with("HTTP/1.1 502"), "{answer}");
    }
    let missing = (count("missing.test"), start.elapsed().as_secs_f64() * 1e3);

    let _ = child.kill();
    let _ = child.wait();
    stop.store(true, Ordering::Release);
    world.join().unwrap();
    drop(listening);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&token);
    (cold, missing)
}
