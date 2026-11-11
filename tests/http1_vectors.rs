//! Differential checks of the HTTP/1 decoders against the executable Lean
//! model in `verification/http/lean/Http/Wire.lean`. Run through
//! `cargo xtask http-verify diff`, which writes the vectors and names their
//! directory in `HTTP1_VECTORS`.
//!
//! Each vector is replayed twice: with the whole input pushed at once, and
//! in random pieces. Both must give the model's events and stop.
//!
//! Each request vector is also served by the HTTP/1 server (`Http1`) in
//! the same random pieces, as one costed step (verification/resources/
//! cost.rs): the server holds no more than its budget and what it keeps
//! uncharged, and asks the allocator for at most a linear bound of the
//! bytes it took, stated in [`served`]. Two fixed sessions do the same for
//! a head at the server's 64 KiB limit sent a byte a delivery.

#[path = "../verification/resources/alloc.rs"]
mod alloc;
#[path = "../verification/resources/cost.rs"]
mod cost;

use std::sync::Arc;

use cost::{Charged, Costs, Linear};
use fictionet::stdlib::codec::{Decode, Fail, Stream};
use fictionet::stdlib::layer::{Admit, Budget, Chunk, Driver, StreamCommand, StreamEvent};
use fictionet::stdlib::protocols::http1::{
    Event, Limits, RequestEvents, ResponseEvents, ResponseHead, Version,
};
use fictionet::stdlib::web::httpd::{self, Body, Exchange, Handler, Http1, Reply};
use fictionet::stdlib::web::{Head, Request, Response};
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};
use serde_json::{Value, json};

fn cases(kind: &str, mut check: impl FnMut(usize, &Value) -> Option<String>) {
    let dir = std::env::var_os("HTTP1_VECTORS").expect("run cargo xtask http-verify diff");
    let path = std::path::Path::new(&dir).join(format!("{kind}.json"));
    let data: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let cases = data.as_array().unwrap();
    assert!(!cases.is_empty(), "empty {kind} vectors");
    let mut disagree = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        if let Some(why) = check(i, case) {
            disagree.push(why);
        }
    }
    println!("{kind}: {} cases, {} disagree", cases.len(), disagree.len());
    for why in disagree.iter().take(5) {
        println!("{why}");
    }
    assert!(
        disagree.is_empty(),
        "{kind}: the Rust decoder and the model disagree"
    );
}

fn bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| u8::try_from(v.as_u64().unwrap()).unwrap())
        .collect()
}

fn n(value: &Value, key: &str) -> usize {
    usize::try_from(value[key].as_u64().unwrap()).unwrap()
}

fn limits(v: &Value) -> Limits {
    Limits {
        start_line: n(v, "start_line"),
        header_line: n(v, "header_line"),
        headers: n(v, "headers"),
        head: n(v, "head"),
        body_chunk: n(v, "body_chunk"),
        ..Limits::default()
    }
}

/// splitmix64, for the piece sizes.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        usize::try_from(z % u64::try_from(n.max(1)).unwrap()).unwrap()
    }
}

fn version(v: Version) -> &'static str {
    v.as_str()
}

/// Feeds `input` to a `Stream` over `decoder`, whole or in random pieces,
/// with the end of input after it when `eof`, and describes what comes out
/// as the model does.
fn replay<H, D>(
    decoder: D,
    input: &[u8],
    eof: bool,
    mut pieces: Option<&mut Rng>,
    head: impl Fn(&H, u64) -> Value,
    failed: impl Fn(&D::Error) -> Value,
) -> (Vec<Value>, Value)
where
    D: Decode<Item = Event<H>>,
    D::Error: Clone,
{
    let mut stream = Stream::new(decoder);
    let mut events = Vec::new();
    let mut fed = 0;
    let drain = |stream: &mut Stream<D>, events: &mut Vec<Value>| -> Option<Value> {
        while let Some(result) = stream.next_span() {
            match result {
                Ok((Event::Head(h), range)) => events.push(json!({ "head": head(&h, range.end) })),
                Ok((Event::Body(b), _)) => events.push(json!({ "body": b })),
                Ok((Event::Done, range)) => events.push(json!({ "done": range.end })),
                Err(Fail::Protocol(e)) => return Some(json!({ "failed": failed(&e) })),
                Err(Fail::Truncated { .. }) => return Some(json!({ "truncated": true })),
                Err(other) => return Some(json!({ "other": format!("{other:?}") })),
            }
        }
        None
    };
    loop {
        let end = match pieces.as_deref_mut() {
            Some(rng) if fed < input.len() => fed + 1 + rng.below(input.len() - fed),
            _ => input.len(),
        };
        let taken = stream.push(&input[fed..end]);
        fed += taken;
        if let Some(stop) = drain(&mut stream, &mut events) {
            return (events, stop);
        }
        if fed == input.len() || stream.is_done() {
            break;
        }
        if taken == 0 && stream.buffered() >= stream.limit() {
            return (
                events,
                json!({ "other": "the buffer filled while the decoder waited" }),
            );
        }
    }
    if eof {
        stream.end();
        if let Some(stop) = drain(&mut stream, &mut events) {
            return (events, stop);
        }
    }
    let offset = stream.offset();
    let stop = if stream.is_done() {
        json!({ "ended": offset })
    } else {
        json!({ "waiting": offset })
    };
    (events, stop)
}

/// Replays one case whole and in pieces; the disagreement, if any.
fn compare(
    i: usize,
    case: &Value,
    run: impl Fn(Option<&mut Rng>) -> (Vec<Value>, Value),
) -> Option<String> {
    let expected = (
        case["events"].as_array().unwrap().clone(),
        case["stop"].clone(),
    );
    let whole = run(None);
    if whole != expected {
        return Some(format!(
            "case {i} whole: input {:?} eof {}\n  rust:  {:?}\n  model: {:?}",
            String::from_utf8_lossy(&bytes(&case["input"])),
            case["eof"],
            whole,
            expected
        ));
    }
    let mut rng = Rng(u64::try_from(i).unwrap());
    let pieces = run(Some(&mut rng));
    if pieces != expected {
        return Some(format!(
            "case {i} in pieces: input {:?}\n  rust:  {:?}\n  model: {:?}",
            String::from_utf8_lossy(&bytes(&case["input"])),
            pieces,
            expected
        ));
    }
    None
}

/// Answers every request with an empty 200, allocating nothing.
struct Empty;

impl Handler for Empty {
    fn call(&self, _: Request, _: &mut Exchange<'_>) -> Reply {
        Reply::Now(Response::new(Body::empty()))
    }
}

/// The HTTP/1 server with the decoder limits `head`, charging `budget`.
fn server(head: Limits, budget: &Budget) -> Driver<Http1> {
    let limits = httpd::Limits {
        head,
        ..httpd::Limits::default()
    };
    Driver::new(
        Http1::with(Arc::new(Empty), limits),
        Arc::new(SeededEntropy::new(Seed::from_u64(1))),
        budget.clone(),
        Instant::ZERO,
    )
}

/// Runs the server until it is still, taking every write as a transport
/// would and reporting it written.
fn settle(driver: &mut Driver<Http1>) {
    for _ in 0..1 << 16 {
        let mut moved = driver.run().unwrap();
        while let Some(command) = driver.take_command() {
            moved = true;
            if let StreamCommand::Write(chunk) = command {
                let written = chunk.len() as u64;
                drop(chunk);
                driver.deliver(StreamEvent::Written(written)).unwrap();
            }
        }
        if !moved {
            return;
        }
    }
    panic!("the server kept moving with nothing new");
}

/// Delivers `pieces` to the server, then the end of input when `eof`,
/// while it takes them: the bytes it took. It stops at a piece the server
/// does not take even once it has answered what it read: one that waits
/// for memory, or that comes after the end of what it reads.
fn deliver(driver: &mut Driver<Http1>, pieces: impl Iterator<Item = Chunk>, eof: bool) -> usize {
    let mut taken = 0;
    for mut piece in pieces {
        let mut refused = false;
        while !piece.is_empty() {
            let len = piece.len();
            let rest = match driver.deliver(StreamEvent::Data(piece)).unwrap() {
                Admit::Taken => Chunk::default(),
                Admit::Partial(StreamEvent::Data(rest))
                | Admit::Blocked(StreamEvent::Data(rest)) => rest,
                _ => return taken,
            };
            settle(driver);
            if rest.len() == len {
                if refused {
                    return taken;
                }
                refused = true;
            } else {
                refused = false;
            }
            taken += len - rest.len();
            piece = rest;
        }
    }
    if eof {
        driver.deliver(StreamEvent::Ended).unwrap();
        settle(driver);
    }
    taken
}

/// The ends of the pieces `rng` cuts `len` bytes into, as [`replay`] cuts
/// them.
fn cuts(len: usize, rng: &mut Rng) -> Vec<usize> {
    let mut ends = Vec::new();
    let mut fed = 0;
    while fed < len {
        fed += 1 + rng.below(len - fed);
        ends.push(fed);
    }
    ends
}

/// `input` as unpaid chunks, a transport's deliveries, cut at `ends`,
/// each made as it is delivered.
fn chunks<'a>(input: &'a [u8], ends: &'a [usize]) -> impl Iterator<Item = Chunk> + 'a {
    let mut start = 0;
    ends.iter().map(move |&end| {
        let piece = Chunk::unpaid(input[start..end].to_vec());
        start = end;
        piece
    })
}

/// The budget a request vector of `input` bytes is served with: the
/// connection's pools' slots (2 KiB and 16 KiB, with 64 bytes of headroom
/// each, `Http1::open`), an answer's head in a small slot, and room for
/// the input held twice while it moves, and twice again for the block it
/// moves to.
fn served_budget(input: usize) -> usize {
    2 * (2048 + 64) + 16_384 + 64 + 4 * input
}

/// A chunk's shared backing, at most: two reference counts, its vector,
/// its reservation (a budget handle and a count), what it holds and its
/// pool's handle.
const BACKING: usize = 128;

/// What the server's own state takes, made with it: the layer's queues
/// and timers, the driver's, and the handler.
const LAYER: usize = 1024;

/// What the connection allocates when it opens, besides its layer: the
/// pools' shared state, the rejected-request record and the dates
/// (`Http1::open`), and the small pool's first slot.
const OPENING: usize = 512 + 2048;

/// The head pools' slots: a head may be joined in a small slot (2 KiB)
/// and a large one (16 KiB and 64 bytes of headroom) however few bytes it
/// has, before it needs a block of its own.
const POOL_SLOTS: usize = 2048 + 16_384 + 64;

/// What each message asks for besides its bytes, at most: a field block
/// for its head, a copy of a head refused for its `Host` (`Http1::fail`),
/// and its answer's head, each a small pool slot when the pool's are out;
/// and the answer's body, fields and the refusal's record, within 1 KiB.
const PER_MESSAGE: usize = 3 * (2048 + 64) + 1024;

/// Chunks live at once: a delivery, the block it joins, the block that
/// block moves to, a head's field block, a body, the answer, and the
/// pools' free slots.
const LIVE_CHUNKS: usize = 8;

/// The blocks a unit is joined in come to less than this many times its
/// bytes: a block is replaced only when full, by one at least twice what
/// it held and at most twice what it must hold, so the blocks form a
/// doubling series whose sum is under twice its last, and the last is
/// under twice the unit. A block the budget had no room to double is
/// replaced at most once more, by the largest block that fits, which is
/// at most twice the unit too, and that block is never replaced.
const JOIN_PER: usize = 4;

/// Serves `input` cut at `ends`, as a transport delivers it, with the
/// decoder limits `head` over `budget`, as one costed step of `costs`
/// that holds `messages` requests at most. The deliveries are made in the
/// step, as the transport makes them for the server. The bounds:
///
/// - **Within the charge**: the most bytes live at once is at most the
///   budget's limit, plus what is uncharged by design: the layer's state,
///   the pools' state, a backing for each chunk live at once, and the
///   delivery in hand, which the server pays for only once it keeps it.
/// - **Linear copying**: the bytes asked for are at most `JOIN_PER` times
///   the input, plus the deliveries themselves (their bytes, and a
///   backing each), plus the layer and its opening, plus a field block and
///   an answer for each message.
fn served(
    costs: &mut Costs,
    head: Limits,
    budget: &Budget,
    input: &[u8],
    ends: &[usize],
    eof: bool,
    messages: usize,
) -> usize {
    let most_piece = ends
        .iter()
        .scan(0, |start, &end| Some(end - std::mem::replace(start, end)))
        .max()
        .unwrap_or(0);
    let charge = budget.limit() + LAYER + OPENING + LIVE_CHUNKS * BACKING + most_piece;
    let linear = Linear {
        num: JOIN_PER + 1,
        den: 1,
        fixed: BACKING * ends.len() + LAYER + OPENING + POOL_SLOTS + PER_MESSAGE * messages,
    };
    costs.step(input.len(), charge, linear, || {
        let mut driver = server(head, budget);
        let taken = deliver(&mut driver, chunks(input, ends), eof);
        drop(driver);
        Charged {
            value: taken,
            charged: 0,
            moved: 0,
        }
    })
}

/// A request head of `fields` fields of `value` bytes each.
fn padded_head(fields: usize, value: usize) -> Vec<u8> {
    let mut wire = b"GET / HTTP/1.1\r\nHost: a.test\r\n".to_vec();
    for field in 0..fields {
        wire.extend_from_slice(format!("x-pad-{field:02}: ").as_bytes());
        wire.extend(std::iter::repeat_n(b'a', value));
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"\r\n");
    wire
}

/// A head of nearly the server's 64 KiB limit, sent a byte a delivery,
/// served as one costed step: within a roomy budget, it is joined in
/// doubling blocks (before 3271cfe52, a block of exactly what it needed on
/// every delivery); within one that leaves it no room to double past 32
/// KiB, it takes the largest block that fits (at 3271cfe52, a block of
/// exactly what it needed on every later delivery).
#[test]
fn heads_a_byte_a_delivery() {
    let wire = padded_head(97, 640);
    let ends: Vec<usize> = (1..=wire.len()).collect();
    let mut total = Costs::new("heads");
    for (session, room) in [("roomy", 1 << 20), ("tight", 2048 + 16_448 + 80_000)] {
        let budget = Budget::new(room);
        let mut costs = Costs::new(format!("heads, {session} budget"));
        let taken = served(
            &mut costs,
            Limits::default(),
            &budget,
            &wire,
            &ends,
            false,
            1,
        );
        if session == "roomy" {
            assert_eq!(taken, wire.len(), "a roomy budget takes the head");
        }
        total.absorb(&costs);
    }
    println!("heads cost: {}", total.summary());
}

#[test]
fn requests() {
    let mut served_costs = Costs::new("served requests");
    cases("requests", |i, case| {
        let input = bytes(&case["input"]);
        let eof = case["eof"].as_bool().unwrap();
        let messages = case["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e.get("head").is_some())
            .count();
        let mut costs = Costs::new(format!("requests case {i}"));
        let ends = cuts(input.len(), &mut Rng(u64::try_from(i).unwrap()));
        served(
            &mut costs,
            limits(&case["limits"]),
            &Budget::new(served_budget(input.len())),
            &input,
            &ends,
            eof,
            // An answer for each head, and one for a refusal.
            messages + 1,
        );
        served_costs.absorb(&costs);
        compare(i, case, |pieces| {
            replay(
                RequestEvents::with_limits(limits(&case["limits"])),
                &input,
                eof,
                pieces,
                |h: &Head, end| {
                    json!({
                        "method": h.method().as_bytes(),
                        "target": h.target().as_bytes(),
                        "version": version(h.version()),
                        "status": 0,
                        "end": end,
                    })
                },
                |e| json!(format!("{:?}", e.reason())),
            )
        })
    });
    println!("requests cost: {}", served_costs.summary());
}

#[test]
fn responses() {
    cases("responses", |i, case| {
        let input = bytes(&case["input"]);
        let eof = case["eof"].as_bool().unwrap();
        compare(i, case, |pieces| {
            let mut decoder = ResponseEvents::with_limits(limits(&case["limits"]));
            for method in case["methods"].as_array().unwrap() {
                decoder.expect_method(method.as_str().unwrap()).unwrap();
            }
            replay(
                decoder,
                &input,
                eof,
                pieces,
                |h: &ResponseHead, end| {
                    json!({
                        "method": [],
                        "target": [],
                        "version": version(h.version),
                        "status": h.status,
                        "end": end,
                    })
                },
                |e| json!(format!("{e:?}")),
            )
        })
    });
}

/// `framing.json`: heads written from the abstract framing fields of
/// `Request.lean`, with what its `requestFraming` says of them. The decoder
/// must refuse with the same reason, or read the one message with the body
/// the framing gives.
#[test]
fn framing() {
    cases("framing", |i, case| {
        let input = bytes(&case["input"]);
        let (events, stop) = replay(
            RequestEvents::new(),
            &input,
            true,
            None,
            |h: &Head, _| json!(h.method()),
            |e| json!(format!("{:?}", e.reason())),
        );
        let expect = &case["expect"];
        let got = if let Some(reason) = stop.get("failed") {
            json!({ "error": reason })
        } else {
            let body: Vec<u8> = events
                .iter()
                .filter_map(|e| e.get("body"))
                .flat_map(bytes)
                .collect();
            let heads = events.iter().filter(|e| e.get("head").is_some()).count();
            let dones = events.iter().filter(|e| e.get("done").is_some()).count();
            if heads != 1 || dones != 1 || stop.get("ended").is_none() {
                json!({ "messages": heads, "done": dones, "stop": stop })
            } else {
                json!({ "body": body })
            }
        };
        (got != *expect).then(|| {
            format!(
                "case {i}: input {:?}\n  rust:  {got}\n  Request.lean: {expect}",
                String::from_utf8_lossy(&input)
            )
        })
    });
}
