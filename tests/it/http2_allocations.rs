//! Heap allocations per request on an HTTP/2 connection's own path: the
//! frames read, the request's head decoded, its body handed up, and the
//! response framed and written, with the test standing in for the stream's
//! child and the transport, so that what is counted is the connection's
//! alone. Inputs and responses are made before the count starts.

use std::sync::Arc;

use fictionet::stdlib::layer::{
    Admit, Budget, Child, Chunk, Driver, MuxCommand, MuxEvent, StreamCommand, StreamEvent, Top,
};
use fictionet::stdlib::protocols::{hpack, http2};
use fictionet::stdlib::web::httpd::{
    ExchangeCommand, ExchangeEvent, Http2, HttpExchange, Limits, ResponseHead,
};
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};

use crate::common::alloc::measuring;

/// Requests before the count starts: the connection's pools, lists and
/// HPACK tables reach the sizes a steady exchange keeps. The connection's
/// receive window comes back in one WINDOW_UPDATE about every half window
/// of bodies, the busiest batch there is, so the warm-up sees it twice.
const WARMUP: usize = 2 * 65_536 / BODY;
/// Requests counted.
const REQUESTS: usize = 2000;
/// Heap allocations the connection may make per request, at most.
const CEILING: usize = 0;
/// Heap allocations the counted run may make besides, at most.
const FIXED: usize = 0;
/// The request body each request carries.
const BODY: usize = 64;

/// What one request needs, made before the count starts: the client's
/// frames, paid for by the connection's budget as a transport's delivery
/// is, and the response the child answers with.
struct Exchange {
    input: Chunk,
    head: ExchangeCommand,
    body: ExchangeCommand,
}

fn exchanges(budget: &Budget, count: usize) -> Vec<Exchange> {
    let mut encoder = hpack::Encoder::new(4096);
    (0..count)
        .map(|i| {
            let stream = 1 + 2 * i as u32;
            let fields = [
                hpack::Field::new(":method", "POST"),
                hpack::Field::new(":scheme", "https"),
                hpack::Field::new(":authority", "a.test"),
                hpack::Field::new(":path", "/items"),
                hpack::Field::new("content-type", "application/json"),
                hpack::Field::new("content-length", BODY.to_string()),
            ];
            let mut fragment = Vec::new();
            encoder.encode_block(&fields, &mut fragment).unwrap();
            let mut bytes = Vec::new();
            http2::Frame::Headers(http2::Headers {
                stream,
                flags: 4,
                fragment,
                priority: None,
                padding: None,
            })
            .write_to(&mut bytes);
            http2::Frame::Data(http2::Data {
                stream,
                flags: 1,
                data: vec![b'b'; BODY],
                padding: None,
            })
            .write_to(&mut bytes);
            Exchange {
                input: Chunk::copy_of(budget, &bytes).unwrap(),
                head: ExchangeCommand::Head(Box::new(ResponseHead {
                    status: http::StatusCode::OK,
                    headers: http::HeaderMap::new(),
                    end: false,
                })),
                body: ExchangeCommand::Data(Chunk::copy_of(budget, b"{\"ok\":true}").unwrap()),
            }
        })
        .collect()
}

trait WriteTo {
    fn write_to(&self, out: &mut Vec<u8>);
}

impl WriteTo for http2::Frame {
    fn write_to(&self, out: &mut Vec<u8>) {
        use fictionet::stdlib::codec::Wire;
        self.write(out).unwrap();
    }
}

type Events = Vec<MuxEvent<HttpExchange, Top, fictionet::stdlib::web::httpd::Opening>>;

/// Runs one exchange through the connection: the client's frames in, the
/// stream's events up to the child, the child's answer down, and the
/// transport taking every write. Returns how many responses ended.
fn exchange(driver: &mut Driver<Http2>, events: &mut Events, exchange: Exchange) -> usize {
    let Exchange { input, head, body } = exchange;
    let mut child: Option<Child> = None;
    let mut answer = [Some(head), Some(body), Some(ExchangeCommand::End)];
    let mut ended = 0;
    assert!(matches!(
        driver.deliver(StreamEvent::Data(input)).unwrap(),
        Admit::Taken
    ));
    for _ in 0..64 {
        let mut moved = driver.run().unwrap();
        moved |= driver.send_above(|event| {
            events.push(event);
            Admit::Taken
        });
        for event in events.drain(..) {
            match event {
                MuxEvent::Opened(handle, opening, _) => {
                    drop(opening);
                    let grant = handle.grant::<HttpExchange, Top>(Http2::WINDOW);
                    assert!(matches!(driver.command(grant).unwrap(), Admit::Taken));
                    child = Some(handle);
                }
                MuxEvent::Child(_, ExchangeEvent::End) => {
                    let handle = child.as_ref().expect("an open stream");
                    for command in answer.iter_mut().filter_map(Option::take) {
                        let command: MuxCommand<HttpExchange, Top> = handle.send(command);
                        assert!(matches!(driver.command(command).unwrap(), Admit::Taken));
                    }
                }
                MuxEvent::Child(_, ExchangeEvent::Closed { .. }) => {
                    child = None;
                    ended += 1;
                }
                // Body pieces are dropped as a child that read them would.
                _ => {}
            }
            moved = true;
        }
        let mut written = 0;
        while let Some(command) = driver.take_command() {
            if let StreamCommand::Write(chunk) = command {
                written += chunk.len() as u64;
            }
            moved = true;
        }
        if written > 0 {
            let taken = driver.deliver(StreamEvent::Written(written)).unwrap();
            assert!(matches!(taken, Admit::Taken));
        }
        if !moved {
            break;
        }
    }
    ended
}

/// A connection that has served `WARMUP` requests serves `REQUESTS` more
/// with at most `CEILING` heap allocations each, and `FIXED` besides:
/// frames are read from the deliveries they came in, heads decoded into
/// blocks the connection keeps, streams kept in slots it keeps, and
/// frames written into blocks it keeps. An inequality: a connection that
/// allocates less passes.
#[test]
fn an_http2_request_allocates_nothing_on_the_connection() {
    let budget = Budget::new(1 << 24);
    let mut driver = Driver::new(
        Http2::new(Limits::default()),
        Arc::new(SeededEntropy::new(Seed::from_u64(4))),
        budget.clone(),
        Instant::ZERO,
    );
    let mut preface = http2::PREFACE.to_vec();
    http2::Frame::Settings(http2::Settings {
        flags: 0,
        entries: Vec::new(),
    })
    .write_to(&mut preface);
    http2::Frame::Settings(http2::Settings {
        flags: 1,
        entries: Vec::new(),
    })
    .write_to(&mut preface);
    let mut events: Events = Vec::with_capacity(64);
    let mut all = exchanges(&budget, WARMUP + REQUESTS).into_iter();
    let opened = Exchange {
        input: Chunk::copy_of(&budget, &preface).unwrap(),
        head: ExchangeCommand::End,
        body: ExchangeCommand::End,
    };
    exchange(&mut driver, &mut events, opened);
    let warm: usize = all
        .by_ref()
        .take(WARMUP)
        .map(|one| exchange(&mut driver, &mut events, one))
        .sum();
    assert_eq!(warm, WARMUP, "every warm-up request was answered");
    let counted: Vec<Exchange> = all.collect();
    let (served, stats) = measuring(|| {
        counted
            .into_iter()
            .map(|one| exchange(&mut driver, &mut events, one))
            .sum::<usize>()
    });
    assert_eq!(served, REQUESTS, "every counted request was answered");
    let allowed = REQUESTS * CEILING + FIXED;
    assert!(
        stats.allocations <= allowed,
        "{} allocations for {REQUESTS} requests, past {allowed}",
        stats.allocations
    );
    assert_eq!(driver.layer().streams(), 0);
}
