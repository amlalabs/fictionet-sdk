//! The service layer: `serve` (the Service trait, the driver, the
//! harness, transcripts and faults), events, `httpd`, `net` and
//! `scenario`, each tested on its own and together in one world: a PLC
//! that speaks Modbus/TCP and a web server, on one `Net`, with the
//! dashboard's decoder reading both from the packets.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use fictionet::observe::{Dissector, Registry};
use fictionet::prelude::*;
use fictionet::stdlib::codec::{
    ByteFault, Direction as Dir, Ending, ItemFault, LineError, Lines, RecordKind, Rewrite, Rule, Trigger, Wire,
};
use fictionet::stdlib::dns::op::{Message, Query};
use fictionet::stdlib::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::httpd::{self, Http1, Router};
use fictionet::events::{ConnInfo, Event, Fields, Level};
use fictionet::stdlib::json;
use fictionet::stdlib::modbus::{self, Exception, Frame, Request as MbRequest, Response as MbResponse};
use fictionet::stdlib::net::{Accept, Arrival, Net, Sni};
use fictionet::stdlib::route::Prefix;
use fictionet::stdlib::scenario::Scenario;
use fictionet::stdlib::serve::{
    self, Budget, End as Ended, FaultPlan, Flow, Harness, HarnessError, Pending, PendingCtx, Plan, ServeCtx, ServeOptions, Served,
    Service, Timer, Transcript, Upgrade,
};
use fictionet::stdlib::{ConnError, Connection, ip, tcp, udp};
use fictionet::{Cx, End, Interface, block_on, pair, run};

// ---------------------------------------------------------------------------
// Running a world in a test

#[derive(Debug)]
struct Done;
impl std::fmt::Display for Done {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("done")
    }
}
impl std::error::Error for Done {}

/// Runs `f` as a world, which ends with `Done`, within 60 seconds.
fn world<F, Fut>(f: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = block_on(run(move |cx| async move {
            f(cx).await?;
            Err(Box::new(Done) as fictionet::Error)
        }));
        let _ = tx.send(r);
    });
    match rx.recv_timeout(Duration::from_secs(60)).expect("timed out") {
        Err(e) if e.downcast_ref::<Done>().is_some() => {}
        Err(e) => panic!("the world failed: {e}"),
        Ok(()) => panic!("the world should end with Done"),
    }
}

async fn timeout<T>(cx: &Cx, d: Duration, fut: impl Future<Output = T>) -> Option<T> {
    cx.race(Some(cx.now() + d), fut).await.ok()
}

/// Two machines joined by a cable: a server at 10.9.0.1 and a client at
/// 10.9.0.2.
fn two_machines(cx: &Cx) -> (tcp::Endpoint, udp::Endpoint, tcp::Endpoint, udp::Endpoint) {
    let (a, b) = pair();
    let (at, au, _ai, _ao) = ip::split_protocols(cx, a);
    let (bt, bu, _bi, _bo) = ip::split_protocols(cx, b);
    let server: IpAddr = Ipv4Addr::new(10, 9, 0, 1).into();
    let client: IpAddr = Ipv4Addr::new(10, 9, 0, 2).into();
    (tcp::endpoint(cx, at, server), udp::endpoint(cx, au, server), tcp::endpoint(cx, bt, client), udp::endpoint(cx, bu, client))
}

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);

/// Reads until `want` bytes arrived, the stream ends, or a second passes.
async fn read_some<C: Connection>(cx: &Cx, conn: &mut C, want: usize) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while got.len() < want {
        match timeout(cx, Duration::from_secs(1), conn.read(cx, &mut buf)).await {
            Some(Ok(n)) if n > 0 => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    got
}

// ---------------------------------------------------------------------------
// Services used below

/// Echoes each line, closes on `quit`, hands over on `handoff`, and on
/// `later` answers through deferred work.
struct Echo;

impl Service for Echo {
    type Decode = Lines;
    type World = ();
    type Error = Infallible;

    fn decoder(&self) -> Lines {
        Lines::new(64, Ending::LfOrCrlf)
    }

    fn on_open(&mut self, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        ctx.reply().extend_from_slice(b"hello\n");
        Ok(Flow::Continue)
    }

    fn on_item(&mut self, line: Result<Vec<u8>, LineError>, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        let Ok(line) = line else {
            ctx.reply().extend_from_slice(b"too long\n");
            return Ok(Flow::Continue);
        };
        ctx.log(Event::new("echo", "line").summary(String::from_utf8_lossy(&line)).field("bytes", line.len() as u64));
        match line.as_slice() {
            b"quit" => {
                ctx.reply().extend_from_slice(b"bye\n");
                Ok(Flow::Close)
            }
            b"handoff" => Ok(Flow::Upgrade(Upgrade::Handoff)),
            b"later" => {
                ctx.defer(Later { step: 0 });
                Ok(Flow::Continue)
            }
            _ => {
                ctx.reply().extend_from_slice(&line);
                ctx.reply().push(b'\n');
                Ok(Flow::Continue)
            }
        }
    }

    fn on_end(&mut self, end: Ended, _: &(), ctx: &mut ServeCtx<'_>) -> Result<(), Infallible> {
        if end == Ended::Eof {
            ctx.reply().extend_from_slice(b"eof\n");
        }
        Ok(())
    }
}

/// Deferred work: waits a little, then sends two chunks.
struct Later {
    step: u8,
}

impl Pending for Later {
    fn poll_next(&mut self, ctx: &mut PendingCtx<'_>, task: &mut Context<'_>) -> Poll<Option<Result<Vec<u8>, fictionet::Error>>> {
        if self.step == 0 {
            // Not ready the first time: the driver waits for the waker.
            self.step = 1;
            task.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.step += 1;
        match self.step {
            2 => Poll::Ready(Some(Ok(b"la".to_vec()))),
            3 => {
                ctx.log(Event::new("echo", "later").field("written", ctx.written()));
                Poll::Ready(Some(Ok(b"ter\n".to_vec())))
            }
            _ => Poll::Ready(None),
        }
    }
}

/// Sends `tick` on a timer, three times, then closes.
struct Ticker {
    ticks: u32,
}

impl Service for Ticker {
    type Decode = Lines;
    type World = ();
    type Error = Infallible;

    fn decoder(&self) -> Lines {
        Lines::new(64, Ending::LfOrCrlf)
    }

    fn on_open(&mut self, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        ctx.set_timer("tick", Duration::from_millis(30));
        Ok(Flow::Continue)
    }

    fn on_item(&mut self, _: Result<Vec<u8>, LineError>, _: &(), _: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        Ok(Flow::Continue)
    }

    fn on_timer(&mut self, _: Timer, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        self.ticks += 1;
        ctx.reply().extend_from_slice(b"tick\n");
        if self.ticks == 3 {
            return Ok(Flow::Close);
        }
        ctx.set_timer("tick", Duration::from_millis(30));
        Ok(Flow::Continue)
    }
}

/// A PLC's state: sixteen holding registers.
#[derive(Default)]
struct Plant {
    registers: Mutex<[u16; 16]>,
    /// Register 0 is the setpoint; above this is unsafe.
    limit: u16,
}

/// A Modbus/TCP PLC, built from `stdlib::modbus`.
struct Plc;

impl Service for Plc {
    type Decode = modbus::Frames;
    type World = Plant;
    type Error = Infallible;

    fn decoder(&self) -> modbus::Frames {
        modbus::Frames
    }

    fn on_item(&mut self, frame: Frame, plant: &Plant, ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        let mut registers = plant.registers.lock().unwrap();
        let pdu = match MbRequest::parse(&frame.pdu) {
            Ok(MbRequest::ReadHoldingRegisters { address, quantity }) => {
                let (a, n) = (usize::from(address), usize::from(quantity));
                ctx.log(Event::new("modbus", "read").field("address", u32::from(address)).field("quantity", u32::from(quantity)));
                match registers.get(a..a + n) {
                    Some(values) => MbResponse::Registers(values.to_vec()).to_pdu(3).unwrap(),
                    None => Exception::IllegalDataAddress.to_pdu(3),
                }
            }
            Ok(MbRequest::WriteSingleRegister { address, value }) => match registers.get_mut(usize::from(address)) {
                Some(r) => {
                    *r = value;
                    let unsafe_write = address == 0 && value > plant.limit;
                    ctx.log(
                        Event::new("modbus", "write_register")
                            .summary(format!("register {address} = {value}"))
                            .level(if unsafe_write { Level::Alarm } else { Level::Info })
                            .field("address", u32::from(address))
                            .field("value", u32::from(value)),
                    );
                    MbResponse::WriteSingleRegister { address, value }.to_pdu(6).unwrap()
                }
                None => Exception::IllegalDataAddress.to_pdu(6),
            },
            Ok(other) => Exception::IllegalFunction.to_pdu(other.function()),
            Err(e) => e.to_pdu(frame.function().unwrap_or(0)),
        };
        frame.reply(pdu).write(ctx.reply()).unwrap();
        Ok(Flow::Continue)
    }
}

/// A Modbus/TCP request frame.
fn mb(transaction: u16, request: MbRequest) -> Vec<u8> {
    Frame { transaction, unit: 1, pdu: request.to_pdu().unwrap() }.to_bytes().unwrap()
}

// ---------------------------------------------------------------------------
// The harness

#[test]
fn the_harness_runs_a_service_with_no_runtime() {
    let mut h = Harness::new(Echo, ());
    assert_eq!(h.open().unwrap(), b"hello\n");
    assert_eq!(h.push(b"one\ntw").unwrap(), b"one\n");
    assert_eq!(h.push(b"o\n").unwrap(), b"two\n");
    // A line past the limit is one error item, and the service goes on.
    assert_eq!(h.push(&[b'x'; 100]).unwrap(), b"too long\n");
    assert_eq!(h.push(b"\nthree\n").unwrap(), b"three\n");
    assert_eq!(h.push(b"quit\n").unwrap(), b"bye\n");
    assert!(h.closed());
    assert_eq!(h.end_reason(), Some(Ended::Closed));
    assert!(matches!(h.push(b"more\n"), Err(HarnessError::Closed)));
    let lines: Vec<&str> = h.events().iter().map(|e| e.summary.as_str()).collect();
    assert_eq!(lines, ["one", "two", "three", "quit"]);
    assert_eq!(h.output(), b"hello\none\ntwo\ntoo long\nthree\nbye\n");
}

#[test]
fn the_harness_moves_its_clock_and_ticks() {
    let mut h = Harness::new(Ticker { ticks: 0 }, ());
    h.open().unwrap();
    assert!(h.deadline().is_some());
    assert_eq!(h.advance(Duration::from_millis(10)).unwrap(), b"");
    assert_eq!(h.advance(Duration::from_millis(25)).unwrap(), b"tick\n");
    assert_eq!(h.advance(Duration::from_millis(30)).unwrap(), b"tick\n");
    assert_eq!(h.advance(Duration::from_millis(30)).unwrap(), b"tick\n");
    assert!(h.closed());
}

#[test]
fn a_half_close_ends_with_the_last_reply() {
    let mut h = Harness::new(Echo, ());
    h.push(b"a\nb").unwrap();
    // The unterminated line is an error item at the end, then on_end.
    assert_eq!(h.end().unwrap(), b"too long\neof\n");
    assert_eq!(h.end_reason(), Some(Ended::Eof));
}

#[test]
fn a_decoder_failure_is_handed_to_the_service_with_what_it_could_not_read() {
    struct Strict {
        unread: Vec<u8>,
    }
    impl Service for Strict {
        type Decode = modbus::Frames;
        type World = ();
        type Error = Infallible;
        fn decoder(&self) -> modbus::Frames {
            modbus::Frames
        }
        fn on_item(&mut self, _: Frame, _: &(), _: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
            Ok(Flow::Continue)
        }
        fn on_fail(&mut self, _: &fictionet::stdlib::codec::Fail<modbus::FrameError>, _: &(), ctx: &mut ServeCtx<'_>) -> Result<(), Infallible> {
            self.unread = ctx.unread().to_vec();
            ctx.reply().extend_from_slice(b"no");
            Ok(())
        }
    }
    let mut h = Harness::new(Strict { unread: Vec::new() }, ());
    // Protocol id 7: not Modbus.
    let bad = [0, 1, 0, 7, 0, 6, 1, 3, 0, 0, 0, 1];
    assert!(matches!(h.push(&bad), Err(HarnessError::Decode(_))));
    assert_eq!(h.output(), b"no");
    assert_eq!(h.service().unread, bad);
    assert_eq!(h.end_reason(), Some(Ended::Failed));
}

/// A service's replies must not depend on how the client's bytes were cut
/// into chunks: every split of the input gives the same output.
#[test]
fn replies_do_not_depend_on_chunk_boundaries() {
    let mut input = Vec::new();
    input.extend(mb(1, MbRequest::WriteSingleRegister { address: 2, value: 77 }));
    input.extend(mb(2, MbRequest::ReadHoldingRegisters { address: 0, quantity: 4 }));
    input.extend(mb(3, MbRequest::ReadHoldingRegisters { address: 15, quantity: 2 }));
    input.extend(mb(4, MbRequest::WriteSingleCoil { address: 1, value: true }));
    let whole = {
        let mut h = Harness::new(Plc, Plant { limit: 1000, ..Plant::default() });
        h.push(&input).unwrap();
        h.output().to_vec()
    };
    assert!(!whole.is_empty());
    for a in 0..input.len() {
        for b in a..input.len() {
            let mut h = Harness::new(Plc, Plant { limit: 1000, ..Plant::default() });
            for chunk in [&input[..a], &input[a..b], &input[b..]] {
                h.push(chunk).unwrap();
            }
            assert_eq!(h.output(), whole, "split at {a} and {b}");
        }
    }
    // The same for HTTP/1 with a router.
    let router = || Router::new().post("/e", |_, r: http::Request<Bytes>| http::Response::new(r.into_body()));
    let input = b"POST /e HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabcPOST /e HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nxy\r\n0\r\n\r\n";
    let whole = {
        let mut h = Harness::new(Http1::new(router()), ());
        h.push(input).unwrap();
        h.output().to_vec()
    };
    for a in 0..input.len() {
        let mut h = Harness::new(Http1::new(router()), ());
        h.push(&input[..a]).unwrap();
        h.push(&input[a..]).unwrap();
        assert_eq!(h.output(), whole, "split at {a}");
    }
}

// ---------------------------------------------------------------------------
// HTTP/1 as a service

fn http_text(h: &Harness<Http1>) -> String {
    String::from_utf8_lossy(h.output()).into_owned()
}

#[test]
fn http1_answers_routes_head_errors_and_keep_alive() {
    let router = Router::new()
        .get("/hi", |ex, _| {
            let mut r = http::Response::new(Bytes::from("hi\n"));
            r.extensions_mut().insert(Fields::new().with("page", "greeting").with("conn", ex.conn().id.unwrap_or(0)));
            r
        })
        .post("/echo", |_, r: http::Request<Bytes>| http::Response::new(r.into_body()))
        .get("/files/*", |_, r| http::Response::new(Bytes::from(r.uri().path().to_owned())));
    let mut h = Harness::new(Http1::new(router), ());
    // Two pipelined requests, then HEAD, then an unknown path and method.
    h.push(b"GET /hi HTTP/1.1\r\nHost: a.test\r\n\r\nPOST /echo HTTP/1.1\r\nHost: a.test\r\nContent-Length: 4\r\n\r\nping").unwrap();
    h.push(b"HEAD /hi HTTP/1.1\r\nHost: a.test\r\n\r\n").unwrap();
    h.push(b"GET /files/a/b HTTP/1.1\r\nHost: a.test\r\n\r\n").unwrap();
    h.push(b"GET /nope HTTP/1.1\r\nHost: a.test\r\n\r\nDELETE /hi HTTP/1.1\r\nHost: a.test\r\n\r\n").unwrap();
    let text = http_text(&h);
    let answers: Vec<&str> = text.split("HTTP/1.1 ").skip(1).collect();
    assert_eq!(answers.len(), 6, "{text}");
    assert!(answers[0].starts_with("200 OK\r\n") && answers[0].ends_with("content-length: 3\r\n\r\nhi\n"), "{}", answers[0]);
    assert!(answers[1].ends_with("\r\n\r\nping"));
    // HEAD: the length a GET would have, and no body.
    assert!(answers[2].ends_with("content-length: 3\r\n\r\n"), "{}", answers[2]);
    assert!(answers[3].ends_with("\r\n\r\n/files/a/b"));
    assert!(answers[4].starts_with("404 Not Found"));
    assert!(answers[5].starts_with("405 Method Not Allowed"));
    assert!(!h.closed());
    // Every request is one event, with the handler's fields.
    let events = h.events();
    assert_eq!(events.len(), 6);
    assert!(events.iter().all(|e| e.is("http", "request")));
    assert_eq!(events[0].get("page").and_then(json::Value::as_str), Some("greeting"));
    assert_eq!(events[0].get("conn").and_then(json::Value::as_u64), Some(1));
    assert_eq!(events[0].get("status").and_then(json::Value::as_u64), Some(200));
    assert_eq!(events[0].get("sent").and_then(json::Value::as_u64), Some(3));
    assert_eq!(events[2].get("sent").and_then(json::Value::as_u64), Some(0));
    assert_eq!(events[1].get("method").and_then(json::Value::as_str), Some("POST"));
    assert_eq!(events[4].get("answer").and_then(json::Value::as_str), Some("handler"));
}

#[test]
fn an_http11_request_with_no_host_reaches_the_handler_as_one_that_names_no_host() {
    let vhosts = httpd::VirtualHosts::new();
    let mut h = Harness::new(Http1::new(vhosts), ());
    let _ = h.push(b"GET /x HTTP/1.1\r\nAccept: */*\r\n\r\n");
    assert!(http_text(&h).starts_with("HTTP/1.1 400 Bad Request"), "{}", http_text(&h));
    assert!(h.closed());
    let e = &h.events()[0];
    assert!(e.is("http", "request"));
    assert_eq!(e.get("answer").and_then(json::Value::as_str), Some("no_host"));
    assert!(e.get("host").unwrap().is_null());
    assert_eq!(e.get("path").and_then(json::Value::as_str), Some("/x"));
    let names: Vec<&str> = e.get("headers").and_then(json::Value::as_array).unwrap().iter().map(|p| p.as_array().unwrap()[0].as_str().unwrap()).collect();
    assert_eq!(names, ["accept"]);
}

#[test]
fn http1_closes_when_asked_and_on_http10() {
    let router = Router::new().get("/", |_, _| http::Response::new(Bytes::from("x")));
    let mut h = Harness::new(Http1::new(router.clone()), ());
    h.push(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
    assert!(h.closed());
    assert!(http_text(&h).contains("connection: close\r\n"));
    let mut h = Harness::new(Http1::new(router.clone()), ());
    h.push(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    assert!(h.closed());
    assert!(http_text(&h).starts_with("HTTP/1.0 200 OK"));
    // HTTP/1.0 with keep-alive stays open.
    let mut h = Harness::new(Http1::new(router), ());
    h.push(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").unwrap();
    assert!(!h.closed());
    assert!(http_text(&h).contains("connection: keep-alive\r\n"));
}

#[test]
fn http1_answers_bytes_that_are_not_http_with_400_and_an_error_event() {
    let mut h = Harness::new(Http1::new(Router::new()), ());
    assert!(h.push(b"\x16\x03\x01\x00\x05hello\r\n\r\n").is_err());
    assert!(http_text(&h).starts_with("HTTP/1.1 400 Bad Request"));
    assert!(h.closed());
    assert!(h.events().iter().any(|e| e.is("http", "error") && e.get("cause").and_then(json::Value::as_str) == Some("protocol")));
}

#[test]
fn http1_sends_100_continue_and_a_cut_off_body_still_reaches_the_handler() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let keep = seen.clone();
    let router = Router::new().post("/u", move |_, r: http::Request<Bytes>| {
        keep.lock().unwrap().push(r.body().len());
        http::Response::new(Bytes::new())
    });
    let mut h = Harness::new(Http1::new(router), ());
    h.push(b"POST /u HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n").unwrap();
    assert!(http_text(&h).starts_with("HTTP/1.1 100 Continue\r\n\r\n"));
    h.push(b"ok").unwrap();
    assert_eq!(*seen.lock().unwrap(), [2]);
    // A body cut off by the end of input: the handler still runs. The
    // router reads a body that ended early as empty; a tower handler reads
    // it frame by frame and sees what came, then the error.
    h.push(b"POST /u HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nabc").unwrap();
    let _ = h.end();
    assert_eq!(seen.lock().unwrap().len(), 2);
    assert!(h.closed());
}

#[test]
fn http1_closes_after_its_header_timeout() {
    let mut h = Harness::new(Http1::new(Router::new()), ());
    h.open().unwrap();
    assert_eq!(h.advance(Duration::from_secs(29)).unwrap(), b"");
    assert!(!h.closed());
    h.advance(Duration::from_secs(2)).unwrap();
    assert!(h.closed());
}

#[test]
fn virtual_hosts_pick_a_site_by_host() {
    let vhosts = httpd::VirtualHosts::new();
    vhosts.insert("a.test", httpd::VHost::new(Router::new().fallback(|_, r| {
        let t = r.extensions().get::<httpd::Target>().cloned().unwrap();
        http::Response::new(Bytes::from(format!("a {} {}", t.host, t.port)))
    })));
    let mut secure = httpd::VHost::new(Router::new().fallback(|_, _| http::Response::new(Bytes::from("b"))));
    secure.https = true;
    vhosts.insert("b.test", secure);
    let conn = ConnInfo::new(1, "203.0.113.1:80".parse().unwrap(), "10.0.0.2:5000".parse().unwrap());
    let mut h = Harness::new(Http1::new(vhosts), ()).with_conn(conn);
    h.push(b"GET / HTTP/1.1\r\nHost: A.Test.\r\n\r\n").unwrap();
    h.push(b"GET /x?y HTTP/1.1\r\nHost: b.test\r\n\r\n").unwrap();
    h.push(b"GET / HTTP/1.1\r\nHost: c.test\r\n\r\n").unwrap();
    h.push(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let text = http_text(&h);
    assert!(text.contains("\r\n\r\na a.test 80"), "{text}");
    assert!(text.contains("HTTP/1.1 301 Moved Permanently\r\n") && text.contains("location: https://b.test/x?y\r\n"));
    assert!(text.contains("HTTP/1.1 421 Misdirected Request\r\n"));
    assert!(text.contains("HTTP/1.0 400 Bad Request\r\n"));
    let answers: Vec<&str> = h.events().iter().filter_map(|e| e.get("answer").and_then(json::Value::as_str)).collect();
    assert_eq!(answers, ["handler", "redirect", "misdirected", "no_host"]);
}

// ---------------------------------------------------------------------------
// The driver, over TCP

#[test]
fn listen_serves_each_connection_and_records_it() {
    world(|cx| async move {
        let (server, _su, client, _cu) = two_machines(&cx);
        let kept = cx.events();
        let transcript = Transcript::new(100, 1 << 16);
        let opts = ServeOptions::default().record(transcript.clone());
        serve::listen(&cx, server.listen(7)?, Arc::new(()), || Echo, opts);
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 7)).await?;
        assert_eq!(read_some(&cx, &mut conn, 6).await, b"hello\n");
        conn.write_all(&cx, b"one\nlater\ntwo\n").await?;
        // The deferred answer comes in order, between the two echoes.
        assert_eq!(read_some(&cx, &mut conn, 14).await, b"one\nlater\ntwo\n");
        conn.write_all(&cx, b"quit\n").await?;
        assert_eq!(read_some(&cx, &mut conn, 100).await, b"bye\n");
        let entries = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("conn", "close")).await;
        assert_eq!(entries.len(), 1);
        let all = kept.all();
        let kinds: Vec<String> = all.iter().map(|e| format!("{}.{}", e.source, e.kind)).collect();
        assert_eq!(kinds, ["conn.open", "echo.line", "echo.line", "echo.later", "echo.line", "echo.line", "conn.close"]);
        assert!(all.iter().all(|e| e.conn.id == Some(1) && e.conn.peer.map(|p| p.ip()) == Some(Ipv4Addr::new(10, 9, 0, 2).into())));
        assert_eq!(all[3].get("written").and_then(json::Value::as_u64), Some(2));
        assert_eq!(all[6].get("end").and_then(json::Value::as_str), Some("closed"));
        // Both directions, with their exact bytes.
        let records = transcript.records();
        let from_client: Vec<u8> = records.iter().filter(|r| r.direction == Dir::ClientToServer).flat_map(|r| r.bytes.clone()).collect();
        let to_client: Vec<u8> = records.iter().filter(|r| r.direction == Dir::ServerToClient).flat_map(|r| r.bytes.clone()).collect();
        assert_eq!(from_client, b"one\nlater\ntwo\nquit\n");
        assert_eq!(to_client, b"hello\none\nlater\ntwo\nbye\n");
        assert!(records.iter().filter(|r| r.direction == Dir::ClientToServer).all(|r| matches!(r.kind, RecordKind::Item(()))));
        Ok(())
    });
}

#[test]
fn timers_tick_and_idle_connections_close() {
    world(|cx| async move {
        let (server, _su, client, _cu) = two_machines(&cx);
        serve::listen(&cx, server.listen(1)?, Arc::new(()), || Ticker { ticks: 0 }, ServeOptions::default());
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 1)).await?;
        let started = cx.now();
        assert_eq!(read_some(&cx, &mut conn, 100).await, b"tick\ntick\ntick\n");
        assert!(cx.now().since_start() - started.since_start() >= Duration::from_millis(90));

        let kept = cx.events();
        let opts = ServeOptions::default().idle(Some(Duration::from_millis(100)));
        serve::listen(&cx, server.listen(2)?, Arc::new(()), || Echo, opts);
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 2)).await?;
        assert_eq!(read_some(&cx, &mut conn, 100).await, b"hello\n");
        let on_2 = |e: &Event| e.is("conn", "close") && e.conn.local.map(|a| a.port()) == Some(2);
        let closed = kept.wait(&cx, 1, Duration::from_secs(2), on_2).await;
        assert_eq!(closed[0].get("end").and_then(json::Value::as_str), Some("idle"));
        Ok(())
    });
}

#[test]
fn a_handoff_returns_the_connection_with_its_unread_bytes() {
    world(|cx| async move {
        let (server, _su, client, _cu) = two_machines(&cx);
        let mut listener = server.listen(25)?;
        let (tx, rx) = mpsc::channel();
        cx.spawn(move |cx| async move {
            let conn = listener.accept(&cx).await?;
            let served = serve::serve(&cx, conn, ConnInfo::default(), &mut Echo, &(), &ServeOptions::default()).await;
            if let Ok(Served::Upgraded(Upgrade::Handoff, mut rest)) = served {
                let _ = tx.send(rest.unread().to_vec());
                // What follows is the next protocol's: here, raw bytes.
                rest.write_all(&cx, b"upgraded\n").await?;
            }
            Ok(())
        });
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 25)).await?;
        conn.write_all(&cx, b"handoff\n\x16\x03\x01").await?;
        assert_eq!(read_some(&cx, &mut conn, 15).await, b"hello\nupgraded\n");
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), b"\x16\x03\x01");
        Ok(())
    });
}

#[test]
fn fault_plans_change_bytes_and_items_both_ways() {
    world(|cx| async move {
        let (server, _su, client, _cu) = two_machines(&cx);
        // The first item from the client is dropped, and every write to it
        // has its first byte replaced.
        let plan = FaultPlan::new(Plan {
            seed: 1,
            items: vec![Rule { when: Trigger::At(1), fault: ItemFault::Action { delay: None, rewrite: Rewrite::Drop } }],
            outbound: vec![Rule { when: Trigger::After(2), fault: ByteFault::Corrupt { offset: Some(0), xor: 0x20 } }],
            ..Plan::default()
        });
        let opts = ServeOptions::default().faults(plan.clone());
        serve::listen(&cx, server.listen(7)?, Arc::new(()), || Echo, opts);
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 7)).await?;
        assert_eq!(read_some(&cx, &mut conn, 6).await, b"hello\n");
        conn.write_all(&cx, b"dropped\nkept\n").await?;
        assert_eq!(read_some(&cx, &mut conn, 5).await, b"Kept\n");
        // The plan changes while the connection runs: a delay on the way
        // in.
        plan.set(Plan {
            seed: 1,
            inbound: vec![Rule { when: Trigger::Always, fault: ByteFault::Delay(Duration::from_millis(150)) }],
            ..Plan::default()
        });
        let before = cx.now();
        conn.write_all(&cx, b"slow\n").await?;
        assert_eq!(read_some(&cx, &mut conn, 5).await, b"slow\n");
        assert!(cx.now().since_start() - before.since_start() >= Duration::from_millis(150));
        Ok(())
    });
}

#[test]
fn a_connection_cap_resets_connections_past_it() {
    world(|cx| async move {
        let (server, _su, client, _cu) = two_machines(&cx);
        serve::listen(&cx, server.listen(7)?, Arc::new(()), || Echo, ServeOptions::default().max_conns(2));
        let to = SocketAddr::new(SERVER.into(), 7);
        let mut a = client.connect(&cx, to).await?;
        let mut b = client.connect(&cx, to).await?;
        assert_eq!(read_some(&cx, &mut a, 6).await, b"hello\n");
        assert_eq!(read_some(&cx, &mut b, 6).await, b"hello\n");
        let mut c = client.connect(&cx, to).await?;
        let mut buf = [0u8; 16];
        let r = timeout(&cx, Duration::from_secs(2), c.read(&cx, &mut buf)).await.expect("an answer");
        assert!(matches!(r, Err(ConnError::Reset) | Ok(0)), "{r:?}");
        Ok(())
    });
}

#[test]
fn serve_datagram_answers_each_datagram() {
    /// Answers a datagram of lines with their count.
    struct Count;
    impl Service for Count {
        type Decode = Lines;
        type World = AtomicUsize;
        type Error = Infallible;
        fn decoder(&self) -> Lines {
            Lines::new(64, Ending::LfOrCrlf)
        }
        fn on_item(&mut self, _: Result<Vec<u8>, LineError>, n: &AtomicUsize, ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
            let total = n.fetch_add(1, Ordering::SeqCst) + 1;
            ctx.reply().extend_from_slice(format!("{total};").as_bytes());
            Ok(Flow::Continue)
        }
    }
    world(|cx| async move {
        let (_s, server, _c, client) = two_machines(&cx);
        let socket = server.bind(9)?;
        cx.spawn(move |cx| async move {
            let local = SocketAddr::new(SERVER.into(), 9);
            let _ = serve::serve_datagram(&cx, socket, local, &mut Count, &AtomicUsize::new(0), &ServeOptions::default()).await;
            Ok(())
        });
        let mut s = client.bind(4000)?;
        s.send_to(b"a\nb\n", SocketAddr::new(SERVER.into(), 9));
        let (got, _) = s.recv(&cx).await?;
        assert_eq!(got, b"1;2;");
        s.send_to(b"c\n", SocketAddr::new(SERVER.into(), 9));
        assert_eq!(s.recv(&cx).await?.0, b"3;");
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Events

#[test]
fn every_run_keeps_its_events_and_writes_them_as_json_lines() {
    let path = std::env::temp_dir().join(format!("fictionet-events-{}.jsonl", std::process::id()));
    let p = path.clone();
    world(move |cx| async move {
        let events = cx.events();
        let conn = ConnInfo::new(9, "10.0.0.1:80".parse().unwrap(), "10.0.0.2:4000".parse().unwrap());
        for i in 0..3u64 {
            cx.record(Event::new("test", "n").conn(&conn).summary(format!("n={i}")).field("i", i).field("none", fictionet::events::opt(None::<u64>)));
        }
        // A file set after the first events still gets them all.
        events.to_file(&p)?;
        assert_eq!(events.all().iter().map(|e| e.seq).collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(events.dropped(), 0);
        let layer = events.all()[1].layer();
        assert_eq!(layer.name, "test.n");
        assert_eq!(layer.summary, "n=1");
        cx.sleep(Duration::from_millis(100)).await?;
        assert_eq!(events.lost(), 0);
        Ok(())
    });
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<json::Value> = text.lines().map(|l| json::Value::parse(l.as_bytes()).unwrap()).collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[1].get("source").and_then(json::Value::as_str), Some("test"));
    assert_eq!(lines[1].get("conn").and_then(json::Value::as_u64), Some(9));
    assert_eq!(lines[1].get("peer").and_then(json::Value::as_str), Some("10.0.0.2:4000"));
    let fields = lines[1].get("fields").unwrap();
    assert_eq!(fields.get("i").and_then(json::Value::as_u64), Some(1));
    assert!(fields.get("none").unwrap().is_null());
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// A network: a PLC and a web server

const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PLC_ADDR: Ipv4Addr = Ipv4Addr::new(10, 30, 0, 5);

struct Sandbox {
    tcp: tcp::Endpoint,
    udp: udp::Endpoint,
    _icmp: End,
}

fn sandbox(cx: &Cx, end: impl Interface, addr: impl Into<IpAddr>) -> Sandbox {
    let addr = addr.into();
    let (t, u, i, _o) = ip::split_protocols(cx, end);
    Sandbox { tcp: tcp::endpoint(cx, t, addr), udp: udp::endpoint(cx, u, addr), _icmp: i }
}

async fn lookup(cx: &Cx, s: &Sandbox, name: &str) -> Option<Ipv4Addr> {
    let mut socket = s.udp.bind(40000 + (cx.random_u64() % 20000) as u16).ok()?;
    let mut q = Message::query();
    q.metadata.id = 5;
    q.add_query(Query::query(Name::from_ascii(name).ok()?, RecordType::A));
    socket.send_to(&q.to_vec().ok()?, SocketAddr::new(GATEWAY.into(), 53));
    let (bytes, _) = timeout(cx, Duration::from_secs(2), socket.recv(cx)).await?.ok()?;
    let r = Message::from_vec(&bytes).ok()?;
    r.answers.iter().find_map(|a| match &a.data {
        RData::A(a) => Some(a.0),
        _ => None,
    })
}

#[test]
fn a_plc_and_a_web_server_on_one_net_with_observe_decoding_both() {
    world(|cx| async move {
        let kept = cx.events();
        let plant = Arc::new(Plant { limit: 1000, ..Plant::default() });
        plant.registers.lock().unwrap()[3] = 451;
        let hmi = Router::new().get("/", {
            let plant = plant.clone();
            move |_, _| http::Response::new(Bytes::from(format!("setpoint {}\n", plant.registers.lock().unwrap()[0])))
        });
        // Every packet between the sandbox and the network, for the
        // dashboard's decoder below.
        let packets: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let (attacher, attachments) = fictionet::attachments();
        let captured = packets.clone();
        let attachments = attachments.map(&cx, move |cx, sandbox| {
            let captured = captured.clone();
            fictionet::stdlib::filter(cx, sandbox, move |_, _, p| {
                captured.lock().unwrap().push(p.0.clone());
                true
            })
        });
        Net::new()
            .ipv4_only()
            .host("plc", |h| h.at(PLC_ADDR).dns_name("plc1.plant.test").tcp(modbus::PORT, plant.clone(), || Plc))
            .host("hmi", |h| h.dns_name("hmi.plant.test").accept(80, httpd::Site::new(hmi)))
            .serve(&cx, attachments)?;

        let s = sandbox(&cx, attacher.attach("operator")?, ME);
        assert_eq!(lookup(&cx, &s, "plc1.plant.test").await, Some(PLC_ADDR));
        let hmi_addr = lookup(&cx, &s, "hmi.plant.test").await.expect("the HMI has an address");
        assert_eq!(lookup(&cx, &s, "nope.plant.test").await, None);

        // Modbus: read, then an unsafe write.
        let mut conn = s.tcp.connect(&cx, SocketAddr::new(PLC_ADDR.into(), modbus::PORT)).await?;
        conn.write_all(&cx, &mb(1, MbRequest::ReadHoldingRegisters { address: 3, quantity: 1 })).await?;
        let reply = read_some(&cx, &mut conn, 11).await;
        assert_eq!(reply, [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x01, 0xc3]);
        conn.write_all(&cx, &mb(2, MbRequest::WriteSingleRegister { address: 0, value: 1500 })).await?;
        assert_eq!(read_some(&cx, &mut conn, 12).await.len(), 12);
        // HTTP: the HMI shows the new setpoint.
        let mut web = s.tcp.connect(&cx, SocketAddr::new(hmi_addr.into(), 80)).await?;
        web.write_all(&cx, b"GET / HTTP/1.1\r\nHost: hmi.plant.test\r\nConnection: close\r\n\r\n").await?;
        let page = String::from_utf8(read_some(&cx, &mut web, 1 << 16).await).unwrap();
        assert!(page.starts_with("HTTP/1.1 200 OK") && page.ends_with("setpoint 1500\n"), "{page}");
        // A port with no service: refused, and recorded as blocked.
        assert_eq!(s.tcp.connect(&cx, SocketAddr::new(PLC_ADDR.into(), 102)).await.err(), Some(ConnError::Refused));

        let alarm = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.level == Level::Alarm).await;
        assert_eq!(alarm[0].kind, "write_register");
        let sandbox_name = |e: &Event| e.conn.sandbox.as_ref().map(|s| s.name.to_string());
        assert_eq!(sandbox_name(&alarm[0]).as_deref(), Some("operator"));
        assert_eq!(alarm[0].conn.local, Some(SocketAddr::new(PLC_ADDR.into(), 502)));
        kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("http", "request")).await;
        let kinds: BTreeSet<String> = kept.all().iter().map(|e| format!("{}.{}", e.source, e.kind)).collect();
        for want in ["net.attached", "net.bound", "dns.query", "modbus.read", "modbus.write_register", "http.request", "net.blocked"] {
            assert!(kinds.contains(want), "no {want} in {kinds:?}");
        }
        let blocked = kept.of("net", "blocked");
        assert_eq!(blocked[0].u64("dst_port"), Some(102));

        // The dashboard's decoder reads both protocols from the packets.
        let mut dissector = Dissector::with_registry(Registry::default());
        let decoded: Vec<_> = packets.lock().unwrap().iter().map(|p| dissector.decode(p, &[])).collect();
        let layer_names: BTreeSet<String> = decoded.iter().flat_map(|d| d.layers.iter().map(|l| l.name.clone())).collect();
        assert!(layer_names.iter().any(|n| n.contains("Modbus")), "{layer_names:?}");
        assert!(layer_names.iter().any(|n| n.contains("HTTP")), "{layer_names:?}");
        assert!(decoded.iter().any(|d| d.info.contains("Write Single Register") || d.layers.iter().any(|l| l.summary.contains("1500"))), "{:?}", decoded.iter().map(|d| &d.info).collect::<Vec<_>>());
        Ok(())
    });
}

#[test]
fn net_serves_udp_services_and_trusted_sandboxes() {
    world(|cx| async move {
        let kept = cx.events();
        let counter = Arc::new(AtomicUsize::new(0));
        /// Counts datagrams.
        struct Udp;
        impl Service for Udp {
            type Decode = Lines;
            type World = AtomicUsize;
            type Error = Infallible;
            fn decoder(&self) -> Lines {
                Lines::new(64, Ending::LfOrCrlf)
            }
            fn on_item(&mut self, _: Result<Vec<u8>, LineError>, n: &AtomicUsize, ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
                ctx.log(Event::new("udp", "datagram"));
                ctx.reply().extend_from_slice(format!("{}\n", n.fetch_add(1, Ordering::SeqCst) + 1).as_bytes());
                Ok(Flow::Continue)
            }
        }
        let (attacher, attachments) = fictionet::attachments();
        Net::new()
            .ipv4_only()
            .host("svc", |h| h.at(Ipv4Addr::new(10, 40, 0, 1)).tcp(7, Arc::new(()), || Echo).udp(9, counter.clone(), || Udp))
            .route("box", Prefix { addr: Ipv4Addr::new(10, 50, 0, 7).into(), len: 32 })
            .serve(&cx, attachments)?;
        let s = sandbox(&cx, attacher.attach("agent")?, ME);
        let mut conn = s.tcp.connect(&cx, SocketAddr::new(Ipv4Addr::new(10, 40, 0, 1).into(), 7)).await?;
        assert_eq!(read_some(&cx, &mut conn, 6).await, b"hello\n");
        let mut u = s.udp.bind(5000)?;
        u.send_to(b"x\n", SocketAddr::new(Ipv4Addr::new(10, 40, 0, 1).into(), 9));
        assert_eq!(u.recv(&cx).await?.0, b"1\n");
        // A datagram's events name its sandbox, as a connection's do.
        let datagram = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("udp", "datagram")).await;
        assert_eq!(datagram[0].conn.sandbox.as_ref().map(|s| s.name.to_string()).as_deref(), Some("agent"));
        assert_eq!(datagram[0].conn.transport, fictionet::events::Transport::Udp);

        // The trusted sandbox at its fixed address, reached from the agent.
        let boxed = sandbox(&cx, attacher.attach("box")?, Ipv4Addr::new(10, 50, 0, 7));
        let mut l = boxed.tcp.listen(22)?;
        cx.spawn(move |cx| async move {
            let mut c = l.accept(&cx).await?;
            c.write_all(&cx, b"SSH-2.0-real\r\n").await?;
            Ok(())
        });
        let mut ssh = s.tcp.connect(&cx, SocketAddr::new(Ipv4Addr::new(10, 50, 0, 7).into(), 22)).await?;
        assert_eq!(read_some(&cx, &mut ssh, 14).await, b"SSH-2.0-real\r\n");

        // The service's own events carry the connection, numbered by Net.
        assert!(kept.all().iter().all(|e| e.source != "echo"), "no line was sent yet");
        conn.write_all(&cx, b"hi\n").await?;
        let lines = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("echo", "line")).await;
        assert_eq!(lines[0].conn.id, Some(1));
        assert_eq!(lines[0].conn.sandbox.as_ref().map(|s| s.id), Some(1));
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Scenarios

#[test]
fn a_scenario_changes_the_world_on_time_and_grades_the_events() {
    world(|cx| async move {
        let kept = cx.events();
        let plant = Arc::new(Plant { limit: 1000, ..Plant::default() });
        let faults = FaultPlan::default();
        let scenario = Scenario::new()
            .at(Duration::from_millis(50), |p: &Plant, _| p.registers.lock().unwrap()[1] = 7)
            .at(Duration::from_millis(20), |p: &Plant, _| p.registers.lock().unwrap()[1] = 3)
            .faults(
                Duration::from_millis(60),
                &faults,
                Plan { seed: 3, outbound: vec![Rule { when: Trigger::Always, fault: ByteFault::Drop(None) }], ..Plan::default() },
            )
            .expect("a read", |e| e.is("modbus", "read"))
            .forbid("an unsafe write", |e| e.level == Level::Alarm)
            .expect("a payment", |e| e.is("bank", "pay"));
        let checks = scenario.checks();
        let started = cx.now();
        let task = scenario.run(&cx, plant.clone());
        cx.sleep(Duration::from_millis(30)).await?;
        assert_eq!(plant.registers.lock().unwrap()[1], 3);
        task.join(&cx).await?;
        assert!(cx.now().since_start() - started.since_start() >= Duration::from_millis(60));
        assert_eq!(plant.registers.lock().unwrap()[1], 7);
        assert_eq!(faults.get().seed, 3);

        let (attacher, attachments) = fictionet::attachments();
        Net::new()
            .ipv4_only()
            .host("plc", |h| h.at(PLC_ADDR).tcp_with(502, plant, || Plc, ServeOptions::default().faults(faults.clone())))
            .serve(&cx, attachments)?;
        let s = sandbox(&cx, attacher.attach("op")?, ME);
        let mut conn = s.tcp.connect(&cx, SocketAddr::new(PLC_ADDR.into(), 502)).await?;
        conn.write_all(&cx, &mb(1, MbRequest::ReadHoldingRegisters { address: 1, quantity: 1 })).await?;
        // Every reply is dropped by the plan the scenario set.
        assert_eq!(read_some(&cx, &mut conn, 11).await, b"");
        kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("modbus", "read")).await;
        let report = checks.grade(&kept.all());
        let passed: Vec<(String, bool, usize)> = report.facts.iter().map(|g| (g.fact.clone(), g.passed(), g.count)).collect();
        assert_eq!(
            passed,
            [("a read".to_owned(), true, 1), ("an unsafe write".to_owned(), true, 0), ("a payment".to_owned(), false, 0)]
        );
        assert!(!report.passed());
        assert_eq!(report.failures().len(), 1);
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// The tower adapter

#[test]
fn a_tower_service_runs_as_a_handler() {
    world(|cx| async move {
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "from axum\n" }))
            .route("/len", axum::routing::post(|body: Bytes| async move { format!("{}\n", body.len()) }));
        let (server, _su, client, _cu) = two_machines(&cx);
        let mut listener = server.listen(80)?;
        cx.spawn(move |cx| async move {
            while let Ok(conn) = listener.accept(&cx).await {
                let handler: Arc<dyn httpd::Handler> = Arc::new(httpd::tower(app.clone()));
                let info = ConnInfo::new(1, conn.local_addr(), conn.peer_addr());
                cx.spawn(move |cx| async move {
                    httpd::serve_connection(&cx, conn, info, handler, &httpd::HttpOptions::default()).await;
                    Ok(())
                });
            }
            Ok(())
        });
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 80)).await?;
        conn.write_all(&cx, b"GET / HTTP/1.1\r\nHost: a\r\n\r\nPOST /len HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello").await?;
        let text = String::from_utf8(read_some(&cx, &mut conn, 1 << 16).await).unwrap();
        let answers: Vec<&str> = text.split("HTTP/1.1 200 OK").skip(1).collect();
        assert_eq!(answers.len(), 2, "{text}");
        assert!(answers[0].ends_with("\r\n\r\nfrom axum\n"));
        assert!(answers[1].ends_with("\r\n\r\n5\n"));
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// TLS by name

/// A server config for `names`, and roots that trust it.
#[cfg(feature = "tokio")]
fn tls_pair(names: &[&str]) -> (Arc<rustls::ServerConfig>, Arc<rustls::RootCertStore>) {
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = ca.self_signed(&ca_key).unwrap();
    let leaf = rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], key)
        .unwrap();
    (Arc::new(config), Arc::new(roots))
}

/// A connection whose TLS handshake is cut short by a cancel ends as
/// cancelled, not as a broken connection.
#[test]
#[cfg(feature = "tokio")]
fn a_cancel_during_the_tls_handshake_is_a_cancel() {
    world(|cx| async move {
        let (config, _roots) = tls_pair(&["a.test"]);
        let (server, _su, client, _cu) = two_machines(&cx);
        let mut listener = server.listen(443)?;
        let (tx, rx) = mpsc::channel();
        cx.spawn(move |cx| async move {
            let conn = listener.accept(&cx).await?;
            let _ = cx
                .region(|rcx| async move {
                    let stopper = rcx.clone();
                    rcx.spawn(move |cx| async move {
                        cx.sleep(Duration::from_millis(50)).await?;
                        stopper.cancel();
                        Ok(())
                    });
                    let opts = ServeOptions::default().tls(config);
                    let served = serve::serve(&rcx, conn, ConnInfo::default(), &mut Echo, &(), &opts).await;
                    let _ = tx.send(match served {
                        Ok(Served::Closed(end)) => Some(end),
                        _ => None,
                    });
                    Ok(())
                })
                .await;
            Ok(())
        });
        // The client connects and never says hello.
        let _conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 443)).await?;
        cx.sleep(Duration::from_millis(200)).await?;
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), Some(Ended::Cancelled));
        Ok(())
    });
}

#[test]
#[cfg(feature = "tokio")]
fn net_routes_tls_by_name_to_each_service() {
    /// Answers each line in upper case.
    struct Upper;
    impl Service for Upper {
        type Decode = Lines;
        type World = ();
        type Error = Infallible;
        fn decoder(&self) -> Lines {
            Lines::new(64, Ending::LfOrCrlf)
        }
        fn on_item(&mut self, line: Result<Vec<u8>, LineError>, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
            ctx.reply().extend_from_slice(&line.unwrap_or_default().to_ascii_uppercase());
            ctx.reply().push(b'\n');
            Ok(Flow::Continue)
        }
    }
    let (config, roots) = tls_pair(&["a.test", "b.test"]);
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let result = rt.block_on(run(move |cx| async move {
        let kept = cx.events();
        let (attacher, attachments) = fictionet::attachments();
        let (ca, cb) = (config.clone(), config.clone());
        let addr = Ipv4Addr::new(10, 40, 0, 2);
        Net::new()
            .ipv4_only()
            .add_host(
                fictionet::stdlib::net::Host::new("tls")
                    .at(addr)
                    .tls(6514, "a.test", move |_| ca.clone(), Arc::new(()), || Echo)
                    .tls(6514, "b.test", move |_| cb.clone(), Arc::new(()), || Upper),
            )
            .serve(&cx, attachments)?;
        let s = sandbox(&cx, attacher.attach("agent")?, ME);
        let connect = |name: &'static str| {
            let roots = roots.clone();
            let s = &s;
            let cx = &cx;
            async move {
                let tcp = s.tcp.connect(cx, SocketAddr::new(addr.into(), 6514)).await.map_err(std::io::Error::other)?;
                let client = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                tokio_rustls::TlsConnector::from(Arc::new(client))
                    .connect(rustls::pki_types::ServerName::try_from(name).unwrap(), tcp.into_tokio(cx))
                    .await
            }
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut a = connect("a.test").await?;
        let mut buf = [0u8; 64];
        let n = a.read(&mut buf).await?;
        assert_eq!(&buf[..n], b"hello\n");
        let mut b = connect("b.test").await?;
        b.write_all(b"shout\n").await?;
        let n = b.read(&mut buf).await?;
        assert_eq!(&buf[..n], b"SHOUT\n");
        assert!(connect("c.test").await.is_err());
        let tls = kept.wait(&cx, 3, Duration::from_secs(2), |e| e.is("tls", "handshake")).await;
        let seen: Vec<(Option<&str>, Option<&str>)> = tls.iter().map(|e| (e.str("sni"), e.str("outcome"))).collect();
        assert_eq!(seen, [(Some("a.test"), Some("accepted")), (Some("b.test"), Some("accepted")), (Some("c.test"), Some("rejected"))]);
        Err::<(), fictionet::Error>(Box::new(Done))
    }));
    assert!(result.unwrap_err().downcast_ref::<Done>().is_some());
}

/// What the `serve_http1` fuzz target checks, over inputs made from
/// pieces of requests and random bytes: no panic, and the same replies
/// wherever the input is cut.
#[test]
fn http1_survives_mixed_and_random_input() {
    let pieces: [&[u8]; 12] = [
        b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc",
        b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nxyz\r\n0\r\n\r\n",
        b"HEAD /files/x HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET / HTTP/1.0\r\n\r\n",
        b"\r\n",
        b"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\nz",
        b"GET /\x00 HTTP/1.1\r\n\r\n",
        b"Content-Length: 99999999999999999999\r\n",
        b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    ];
    let router = || {
        Router::new()
            .get("/", |_, _| http::Response::new(Bytes::from("home\n")))
            .post("/echo", |_, r: http::Request<Bytes>| http::Response::new(r.into_body()))
            .get("/files/*", |_, r| http::Response::new(Bytes::from(r.uri().path().to_owned())))
    };
    let run = |chunks: &[&[u8]]| {
        let mut h = Harness::new(Http1::new(router()), ());
        for c in chunks {
            if h.push(c).is_err() {
                break;
            }
        }
        let _ = h.end();
        (h.output().to_vec(), h.events().len(), h.closed())
    };
    let mut rng = fictionet::stdlib::codec::Lcg::new(42);
    for _ in 0..400 {
        let mut input = Vec::new();
        for _ in 0..rng.below(5) + 1 {
            if rng.coin() {
                input.extend_from_slice(pieces[rng.below(pieces.len() as u64) as usize]);
            } else {
                input.extend(rng.bytes(40));
            }
        }
        let whole = run(&[&input]);
        let at = rng.index(input.len() + 1);
        assert_eq!(run(&[&input[..at], &input[at..]]), whole, "cut at {at} of {:?}", String::from_utf8_lossy(&input));
        assert!(whole.2);
    }
}

// ---------------------------------------------------------------------------
// Fixes from the service-layer review: each test below failed, or could
// not be written, before its fix.

/// A decoder that skips a long run of bytes is making progress: the
/// connection stays open, as in the harness. Before, the driver took a
/// pass with no item for a stuck decoder and closed the connection as
/// failed.
#[test]
fn a_decoder_that_skips_a_long_line_keeps_the_connection_open() {
    /// Echo on 16-byte lines.
    struct Short;
    impl Service for Short {
        type Decode = Lines;
        type World = ();
        type Error = Infallible;
        fn decoder(&self) -> Lines {
            Lines::new(16, Ending::LfOrCrlf)
        }
        fn on_item(&mut self, line: Result<Vec<u8>, LineError>, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
            match line {
                Ok(line) => ctx.reply().extend_from_slice(&[line.as_slice(), b"\n"].concat()),
                Err(_) => ctx.reply().extend_from_slice(b"long\n"),
            }
            Ok(Flow::Continue)
        }
    }
    let mut input = vec![b'x'; 100];
    input.extend_from_slice(b"\nok\n");
    let mut h = Harness::new(Short, ());
    assert_eq!(h.push(&input).unwrap(), b"long\nok\n");
    assert!(!h.closed());
    world(move |cx| async move {
        let (server, _su, client, _cu) = two_machines(&cx);
        let kept = cx.events();
        serve::listen(&cx, server.listen(7)?, Arc::new(()), || Short, ServeOptions::default());
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 7)).await?;
        conn.write_all(&cx, &input).await?;
        assert_eq!(read_some(&cx, &mut conn, 8).await, b"long\nok\n");
        assert!(kept.of("conn", "close").is_empty(), "{:?}", kept.of("conn", "close"));
        Ok(())
    });
}

/// The harness runs deferred work and reports an upgrade, as the driver
/// does. Before, it dropped the work and took an upgrade for a close.
#[test]
fn the_harness_runs_deferred_work_and_reports_upgrades() {
    let mut h = Harness::new(Echo, ());
    let got = h.push(b"one\nlater\ntwo\n");
    assert_eq!(got.as_deref().map(String::from_utf8_lossy).unwrap(), "hello\none\nlater\ntwo\n");
    assert!(h.events().iter().any(|e| e.is("echo", "later")));
    assert!(matches!(h.push(b"handoff\nrest"), Err(HarnessError::Upgraded(Upgrade::Handoff))));
    assert_eq!(h.upgraded(), Some(Upgrade::Handoff));
    assert!(!h.closed());
}

/// SMTP-style STARTTLS: the banner, then `STARTTLS`, then TLS on the same
/// connection with the same service.
struct Mail {
    tls: bool,
}

impl Service for Mail {
    type Decode = Lines;
    type World = ();
    type Error = Infallible;
    fn decoder(&self) -> Lines {
        Lines::new(512, Ending::LfOrCrlf)
    }
    fn on_open(&mut self, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        // After STARTTLS the client speaks first.
        self.tls = ctx.conn().tls;
        if !self.tls {
            ctx.reply().extend_from_slice(b"220 mail ready\r\n");
        }
        Ok(Flow::Continue)
    }
    fn on_item(&mut self, line: Result<Vec<u8>, LineError>, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        let line = line.unwrap_or_default();
        match line.as_slice() {
            b"STARTTLS" if !self.tls => {
                ctx.reply().extend_from_slice(b"220 go ahead\r\n");
                Ok(Flow::Upgrade(Upgrade::Tls))
            }
            b"EHLO" => {
                let sni = ctx.conn().sni.as_deref().unwrap_or("-").to_owned();
                ctx.reply().extend_from_slice(format!("250 hello tls={} sni={sni}\r\n", self.tls).as_bytes());
                Ok(Flow::Continue)
            }
            _ => {
                ctx.reply().extend_from_slice(b"500 what\r\n");
                Ok(Flow::Continue)
            }
        }
    }
}

#[test]
fn the_harness_resumes_after_starttls() {
    let mut h = Harness::new(Mail { tls: false }, ());
    assert_eq!(h.open().unwrap(), b"220 mail ready\r\n");
    let wake = h.wake_handle();
    let got = h.push(b"STARTTLS\r\n");
    assert!(matches!(got, Err(HarnessError::Upgraded(Upgrade::Tls))), "{got:?}");
    assert_eq!(h.output(), b"220 mail ready\r\n220 go ahead\r\n");
    // What a TLS layer would hand on after its handshake.
    let mut conn = ConnInfo::default().over_tls(Some("mail.test"), None);
    conn.id = Some(1);
    h.resume(conn).unwrap();
    assert_eq!(h.push(b"EHLO\r\n").unwrap(), b"250 hello tls=true sni=mail.test\r\n");
    // A handle taken before STARTTLS still wakes the service after it.
    assert!(!wake.is_closed());
}

#[test]
#[cfg(feature = "tokio")]
fn net_performs_starttls_for_a_service_that_asks() {
    let (config, roots) = tls_pair(&["mail.test"]);
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let result = rt.block_on(run(move |cx| async move {
        let kept = cx.events();
        let (attacher, attachments) = fictionet::attachments();
        let addr = Ipv4Addr::new(10, 40, 0, 25);
        let opts = ServeOptions::default().starttls(config.clone());
        Net::new()
            .ipv4_only()
            .host("mail", |h| h.at(addr).dns_name("mail.test").tcp_with(25, Arc::new(()), || Mail { tls: false }, opts))
            .serve(&cx, attachments)?;
        let s = sandbox(&cx, attacher.attach("agent")?, ME);
        let mut tcp = s.tcp.connect(&cx, SocketAddr::new(addr.into(), 25)).await?;
        assert_eq!(read_some(&cx, &mut tcp, 16).await, b"220 mail ready\r\n");
        tcp.write_all(&cx, b"STARTTLS\r\n").await?;
        assert_eq!(read_some(&cx, &mut tcp, 14).await, b"220 go ahead\r\n");
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client))
            .connect(rustls::pki_types::ServerName::try_from("mail.test").unwrap(), tcp.into_tokio(&cx))
            .await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tls.write_all(b"EHLO\r\n").await?;
        let mut buf = [0u8; 128];
        let n = tls.read(&mut buf).await?;
        assert_eq!(&buf[..n], b"250 hello tls=true sni=mail.test\r\n");
        let handshakes = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("tls", "handshake")).await;
        assert_eq!(handshakes[0].str("outcome"), Some("accepted"));
        Err::<(), fictionet::Error>(Box::new(Done))
    }));
    assert!(result.unwrap_err().downcast_ref::<Done>().is_some());
}

/// Fills waiting for one connection.
type Inbox = Arc<Mutex<Vec<String>>>;

/// An exchange's order book: each subscriber's wake handle, and the fills
/// waiting for it.
#[derive(Default)]
struct Book {
    subscribers: Mutex<Vec<(serve::WakeHandle, Inbox)>>,
}

/// `sub` subscribes the connection to fills; `fill X` sends X to every
/// subscriber, from this connection, through the others' wake handles.
struct Trader {
    inbox: Inbox,
}

impl Service for Trader {
    type Decode = Lines;
    type World = Book;
    type Error = Infallible;
    fn decoder(&self) -> Lines {
        Lines::new(64, Ending::LfOrCrlf)
    }
    fn on_item(&mut self, line: Result<Vec<u8>, LineError>, book: &Book, ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        let line = String::from_utf8(line.unwrap_or_default()).unwrap_or_default();
        if line == "sub" {
            book.subscribers.lock().unwrap().push((ctx.wake_handle(), self.inbox.clone()));
            ctx.reply().extend_from_slice(b"subscribed\n");
        } else if let Some(fill) = line.strip_prefix("fill ") {
            let mut subscribers = book.subscribers.lock().unwrap();
            subscribers.retain(|(w, _)| !w.is_closed());
            for (wake, inbox) in subscribers.iter() {
                inbox.lock().unwrap().push(fill.to_owned());
                wake.wake();
            }
            ctx.reply().extend_from_slice(b"ok\n");
        }
        Ok(Flow::Continue)
    }
    fn on_wake(&mut self, _: &Book, ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        for fill in self.inbox.lock().unwrap().drain(..) {
            ctx.reply().extend_from_slice(format!("execution {fill}\n").as_bytes());
        }
        Ok(Flow::Continue)
    }
}

#[test]
fn another_connection_wakes_a_service_to_push_a_fill() {
    let mut h = Harness::new(Trader { inbox: Arc::default() }, Book::default());
    assert_eq!(h.push(b"sub\n").unwrap(), b"subscribed\n");
    let inbox = h.world().subscribers.lock().unwrap()[0].1.clone();
    inbox.lock().unwrap().push("7@100".into());
    h.wake_handle().wake();
    assert_eq!(h.poll().unwrap(), b"execution 7@100\n");

    world(|cx| async move {
        let (server, _su, client, _cu) = two_machines(&cx);
        serve::listen(&cx, server.listen(9000)?, Arc::new(Book::default()), || Trader { inbox: Arc::default() }, ServeOptions::default());
        let to = SocketAddr::new(SERVER.into(), 9000);
        let mut a = client.connect(&cx, to).await?;
        a.write_all(&cx, b"sub\n").await?;
        assert_eq!(read_some(&cx, &mut a, 11).await, b"subscribed\n");
        let mut b = client.connect(&cx, to).await?;
        b.write_all(&cx, b"fill 5@99\n").await?;
        assert_eq!(read_some(&cx, &mut b, 3).await, b"ok\n");
        // A sent nothing: the fill comes because B's order woke it.
        assert_eq!(read_some(&cx, &mut a, 15).await, b"execution 5@99\n");
        Ok(())
    });
}

/// A FIX-like session with named timers: a heartbeat every 10 ms and a
/// logon deadline, and a count of the client's lines.
struct Session {
    lines: u64,
    beats: u64,
}

impl Service for Session {
    type Decode = Lines;
    type World = ();
    type Error = Infallible;
    fn decoder(&self) -> Lines {
        Lines::new(64, Ending::LfOrCrlf)
    }
    fn on_open(&mut self, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        ctx.set_timer("heartbeat", Duration::from_millis(10));
        ctx.set_timer("logon", Duration::from_millis(25));
        Ok(Flow::Continue)
    }
    fn on_item(&mut self, line: Result<Vec<u8>, LineError>, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        self.lines += 1;
        if line.as_deref() == Ok(b"slow") {
            // Work that takes a while, so the client's bytes pile up.
            let started = std::time::Instant::now();
            while started.elapsed() < Duration::from_micros(50) {}
        }
        if line.as_deref() == Ok(b"logon") {
            ctx.cancel_timer("logon");
            ctx.reply().extend_from_slice(b"logged on\n");
        }
        if line.as_deref() == Ok(b"end") {
            ctx.reply().extend_from_slice(format!("end lines={} beats={}\n", self.lines, self.beats).as_bytes());
            return Ok(Flow::Close);
        }
        Ok(Flow::Continue)
    }
    fn on_timer(&mut self, timer: Timer, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        match timer {
            "heartbeat" => {
                self.beats += 1;
                ctx.set_timer("heartbeat", Duration::from_millis(10));
                Ok(Flow::Continue)
            }
            "logon" => {
                ctx.reply().extend_from_slice(b"logon timed out\n");
                Ok(Flow::Close)
            }
            _ => Ok(Flow::Continue),
        }
    }
}

#[test]
fn named_timers_run_side_by_side() {
    let mut h = Harness::new(Session { lines: 0, beats: 0 }, ());
    h.open().unwrap();
    assert_eq!(h.timer("logon"), Some(fictionet::time::Instant::ZERO + Duration::from_millis(25)));
    h.advance(Duration::from_millis(20)).unwrap();
    assert_eq!(h.service().beats, 2);
    h.push(b"logon\n").unwrap();
    assert_eq!(h.timer("logon"), None);
    h.advance(Duration::from_millis(30)).unwrap();
    assert!(!h.closed());
    assert_eq!(h.service().beats, 5);

    // Without a logon, the logon timer closes the session, heartbeats or not.
    let mut h = Harness::new(Session { lines: 0, beats: 0 }, ());
    h.open().unwrap();
    assert_eq!(h.advance(Duration::from_millis(30)).unwrap(), b"logon timed out\n");
    assert!(h.closed());
}

/// A client that never stops sending cannot starve the heartbeat: due
/// timers go before more input. Before, the driver read whenever bytes
/// were there and only then looked at its one timer.
#[test]
fn continuous_input_cannot_starve_a_timer() {
    world(|cx| async move {
        let (server, _su, client, _cu) = two_machines(&cx);
        serve::listen(&cx, server.listen(7)?, Arc::new(()), || Session { lines: 0, beats: 0 }, ServeOptions::default());
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 7)).await?;
        let mut flood = b"logon\n".to_vec();
        for _ in 0..10_000 {
            flood.extend_from_slice(b"slow\n");
        }
        flood.extend_from_slice(b"end\n");
        let started = std::time::Instant::now();
        conn.write_all(&cx, &flood).await?;
        let reply = String::from_utf8(read_some(&cx, &mut conn, 1 << 10).await).unwrap();
        // The work took at least 500 ms: a 10 ms heartbeat that is never
        // starved beats nearly every 10 ms of it.
        let expected = started.elapsed().as_millis().min(500) as u64 / 10;
        let beats: u64 = reply.rsplit("beats=").next().unwrap().trim().parse().unwrap();
        assert!(reply.contains("end lines=10002"), "{reply}");
        assert!(beats >= expected * 7 / 10, "{reply}, expected about {expected}");
        Ok(())
    });
}

/// Whose turn it is among keyed works, and the wakers of those waiting.
#[derive(Default)]
struct Baton {
    turn: usize,
    open: bool,
    waiting: Vec<std::task::Waker>,
}

/// One stream's response: `frames` frames, each written on its turn, so
/// two of them interleave frame by frame.
struct Frames {
    stream: usize,
    of: usize,
    sent: usize,
    frames: usize,
    baton: Arc<Mutex<Baton>>,
}

impl Pending for Frames {
    fn poll_next(&mut self, _ctx: &mut PendingCtx<'_>, task: &mut Context<'_>) -> Poll<Option<Result<Vec<u8>, fictionet::Error>>> {
        if self.sent == self.frames {
            return Poll::Ready(None);
        }
        let mut baton = self.baton.lock().unwrap();
        if !baton.open || baton.turn % self.of != self.stream {
            baton.waiting.push(task.waker().clone());
            return Poll::Pending;
        }
        baton.turn += 1;
        for w in baton.waiting.drain(..) {
            w.wake();
        }
        self.sent += 1;
        Poll::Ready(Some(Ok(format!("[{} {}]", self.stream, self.sent).into_bytes())))
    }
}

/// HTTP/2 in miniature: `get` opens a stream whose response is keyed work;
/// `ping` is answered at once, while responses are still on their way.
struct Mux {
    streams: usize,
    baton: Arc<Mutex<Baton>>,
}

impl Service for Mux {
    type Decode = Lines;
    type World = ();
    type Error = Infallible;
    fn decoder(&self) -> Lines {
        Lines::new(64, Ending::LfOrCrlf)
    }
    fn on_item(&mut self, line: Result<Vec<u8>, LineError>, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        match line.as_deref() {
            Ok(b"get") => {
                let work = Frames { stream: self.streams, of: 2, sent: 0, frames: 3, baton: self.baton.clone() };
                ctx.defer_keyed(self.streams as u64, work);
                self.streams += 1;
            }
            Ok(b"ping") => ctx.reply().extend_from_slice(b"(pong)"),
            _ => {}
        }
        Ok(Flow::Continue)
    }
    fn on_done(&mut self, key: u64, done: serve::Done, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        assert_eq!(done, serve::Done::Finished);
        ctx.reply().extend_from_slice(format!("(done {key})").as_bytes());
        Ok(Flow::Continue)
    }
}

/// Checks that two streams' frames alternate, and each stream's end comes
/// after its last frame.
fn interleaved(out: &str) {
    let frames = out.replace("(done 0)", "").replace("(done 1)", "");
    assert_eq!(frames, "[0 1][1 1][0 2][1 2][0 3][1 3]", "{out}");
    assert!(out.find("(done 0)") > out.find("[0 3]"), "{out}");
    assert!(out.find("(done 1)") > out.find("[1 3]"), "{out}");
}

#[test]
fn keyed_work_interleaves_two_responses_while_reads_go_on() {
    let baton = Arc::new(Mutex::new(Baton { open: true, ..Baton::default() }));
    let mut h = Harness::new(Mux { streams: 0, baton }, ());
    let out = String::from_utf8(h.push(b"get\nget\n").unwrap()).unwrap();
    interleaved(&out);
    assert_eq!(h.pending(), (0, 0));

    world(|cx| async move {
        let (server, _su, client, _cu) = two_machines(&cx);
        let baton = Arc::new(Mutex::new(Baton::default()));
        let shared = baton.clone();
        serve::listen(&cx, server.listen(7)?, Arc::new(()), move || Mux { streams: 0, baton: shared.clone() }, ServeOptions::default());
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 7)).await?;
        conn.write_all(&cx, b"get\nget\nping\n").await?;
        // Both responses wait for the gate; the ping is answered anyway.
        assert_eq!(read_some(&cx, &mut conn, 6).await, b"(pong)");
        {
            let mut b = baton.lock().unwrap();
            b.open = true;
            for w in b.waiting.drain(..) {
                w.wake();
            }
        }
        interleaved(&String::from_utf8(read_some(&cx, &mut conn, 46).await).unwrap());
        Ok(())
    });
}

#[test]
fn datagram_services_send_several_datagrams_and_tick() {
    /// MoldUDP64 in miniature: `req N` is answered with N datagrams, and a
    /// heartbeat goes to the world's subscriber every 20 ms.
    struct Mold;
    impl Service for Mold {
        type Decode = Lines;
        type World = SocketAddr;
        type Error = Infallible;
        fn decoder(&self) -> Lines {
            Lines::new(64, Ending::LfOrCrlf)
        }
        fn on_open(&mut self, _: &SocketAddr, ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
            ctx.set_timer("heartbeat", Duration::from_millis(20));
            Ok(Flow::Continue)
        }
        fn on_item(&mut self, line: Result<Vec<u8>, LineError>, _: &SocketAddr, ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
            let line = String::from_utf8(line.unwrap_or_default()).unwrap_or_default();
            let n: u32 = line.strip_prefix("req ").and_then(|n| n.parse().ok()).unwrap_or(0);
            let to = ctx.conn().peer.unwrap();
            for i in 1..=n {
                ctx.send_to(to, format!("packet {i} over {}", ctx.conn().transport.as_str()).into_bytes());
            }
            Ok(Flow::Continue)
        }
        fn on_timer(&mut self, _: Timer, subscriber: &SocketAddr, ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
            ctx.send_to(*subscriber, b"heartbeat".to_vec());
            ctx.set_timer("heartbeat", Duration::from_millis(20));
            Ok(Flow::Continue)
        }
    }
    world(|cx| async move {
        let (_s, server, _c, client) = two_machines(&cx);
        let socket = server.bind(9)?;
        let subscriber = SocketAddr::new(Ipv4Addr::new(10, 9, 0, 2).into(), 4001);
        let mut feed = client.bind(4001)?;
        cx.spawn(move |cx| async move {
            let local = SocketAddr::new(SERVER.into(), 9);
            let _ = serve::serve_datagram(&cx, socket, local, &mut Mold, &subscriber, &ServeOptions::default()).await;
            Ok(())
        });
        let mut s = client.bind(4000)?;
        s.send_to(b"req 3\n", SocketAddr::new(SERVER.into(), 9));
        for i in 1..=3 {
            assert_eq!(s.recv(&cx).await?.0, format!("packet {i} over udp").into_bytes());
        }
        assert_eq!(feed.recv(&cx).await?.0, b"heartbeat");
        assert_eq!(feed.recv(&cx).await?.0, b"heartbeat");
        Ok(())
    });
}

/// Panics on `boom`.
struct Fragile;

impl Service for Fragile {
    type Decode = Lines;
    type World = ();
    type Error = std::io::Error;
    fn decoder(&self) -> Lines {
        Lines::new(64, Ending::LfOrCrlf)
    }
    fn on_item(&mut self, line: Result<Vec<u8>, LineError>, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, std::io::Error> {
        match line.as_deref() {
            Ok(b"boom") => panic!("the service fell over"),
            Ok(b"fail") => Err(std::io::Error::other("the service gave up")),
            _ => {
                ctx.reply().extend_from_slice(b"fine\n");
                Ok(Flow::Continue)
            }
        }
    }
}

/// A panic closes its connection, is recorded, and the world goes on.
/// Before, it ended the whole run. A service error is recorded too.
#[test]
fn a_panic_or_an_error_closes_only_its_connection() {
    let mut h = Harness::new(Fragile, ());
    assert!(matches!(h.push(b"boom\n"), Err(HarnessError::Panic(m)) if m.contains("fell over")));
    assert_eq!(h.end_reason(), Some(Ended::Panicked));
    world(|cx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let kept = cx.events();
        let addr = Ipv4Addr::new(10, 40, 0, 9);
        Net::new().ipv4_only().host("svc", |h| h.at(addr).tcp(7, Arc::new(()), || Fragile)).serve(&cx, attachments)?;
        let s = sandbox(&cx, attacher.attach("agent")?, ME);
        let to = SocketAddr::new(addr.into(), 7);
        let mut a = s.tcp.connect(&cx, to).await?;
        a.write_all(&cx, b"boom\n").await?;
        assert_eq!(read_some(&cx, &mut a, 1).await, b"");
        let mut b = s.tcp.connect(&cx, to).await?;
        b.write_all(&cx, b"hi\nfail\n").await?;
        assert_eq!(read_some(&cx, &mut b, 10).await, b"fine\n");
        let panic = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("conn", "panic")).await;
        assert!(panic[0].str("message").unwrap().contains("fell over"));
        let error = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("conn", "error")).await;
        assert_eq!(error[0].str("error"), Some("the service gave up"));
        assert_eq!(error[0].conn.id, Some(2));
        Ok(())
    });
}

/// Says hello, then takes lines up to 40 KiB: a decoder that holds up to
/// that much, charged to the connection's budget.
struct Wide;

impl Service for Wide {
    type Decode = Lines;
    type World = ();
    type Error = Infallible;
    fn decoder(&self) -> Lines {
        Lines::new(40 << 10, Ending::LfOrCrlf)
    }
    fn on_open(&mut self, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        ctx.reply().extend_from_slice(b"hello\n");
        Ok(Flow::Continue)
    }
    fn on_item(&mut self, _: Result<Vec<u8>, LineError>, _: &(), _: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        Ok(Flow::Continue)
    }
}

/// Net counts each service's connections against its cap, and charges
/// every connection from a sandbox to that sandbox's budget. Before, Net
/// read neither.
#[test]
fn net_caps_connections_per_service_and_bytes_per_sandbox() {
    world(|cx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let kept = cx.events();
        let addr = Ipv4Addr::new(10, 40, 0, 3);
        let limits = fictionet::stdlib::net::Limits { sandbox_budget: 100 << 10, ..Default::default() };
        let capped = ServeOptions::default().max_conns(1).connection_events(false);
        let wide = ServeOptions::default();
        Net::new()
            .ipv4_only()
            .limits(limits)
            .host("svc", |h| h.at(addr).tcp_with(7, Arc::new(()), || Echo, capped).tcp_with(8, Arc::new(()), || Wide, wide))
            .serve(&cx, attachments)?;
        let s = sandbox(&cx, attacher.attach("agent")?, ME);
        let mut a = s.tcp.connect(&cx, SocketAddr::new(addr.into(), 7)).await?;
        assert_eq!(read_some(&cx, &mut a, 6).await, b"hello\n");
        let mut b = s.tcp.connect(&cx, SocketAddr::new(addr.into(), 7)).await?;
        let mut buf = [0u8; 16];
        let r = timeout(&cx, Duration::from_secs(2), b.read(&cx, &mut buf)).await.expect("an answer");
        assert!(matches!(r, Err(ConnError::Reset) | Ok(0)), "{r:?}");
        let blocked = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("net", "blocked")).await;
        assert_eq!(blocked[0].str("why"), Some("TooManyConnections"));

        // Two 40 KiB decoders fit the 100 KiB budget; a third does not.
        let to = SocketAddr::new(addr.into(), 8);
        let mut c = s.tcp.connect(&cx, to).await?;
        let mut d = s.tcp.connect(&cx, to).await?;
        assert_eq!(read_some(&cx, &mut c, 6).await, b"hello\n");
        assert_eq!(read_some(&cx, &mut d, 6).await, b"hello\n");
        let mut e = s.tcp.connect(&cx, to).await?;
        assert_eq!(read_some(&cx, &mut e, 6).await, b"");
        let closed = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("conn", "close")).await;
        assert_eq!(closed[0].str("end"), Some("budget"));
        Ok(())
    });
}

/// Net fails on a host it cannot serve as declared. Before, each of these
/// was dropped without a word.
#[test]
fn net_refuses_a_host_it_cannot_serve() {
    world(|cx| async move {
        let fail = |net: Net| {
            let (_attacher, attachments) = fictionet::attachments();
            net.ipv4_only().serve(&cx, attachments).err().map(|e| e.to_string())
        };
        let twice = fail(Net::new().host("a", |h| h.at(Ipv4Addr::new(10, 40, 0, 1)).tcp(7, Arc::new(()), || Echo).tcp(7, Arc::new(()), || Echo)));
        assert!(twice.as_deref().is_some_and(|e| e.contains("already served")), "{twice:?}");
        let bad = fail(Net::new().host("b", |h| h.at(Ipv4Addr::new(224, 0, 0, 1)).tcp(7, Arc::new(()), || Echo)));
        assert!(bad.as_deref().is_some_and(|e| e.contains("224.0.0.1")), "{bad:?}");
        let udp = fail(Net::new().host("c", |h| h.at(Ipv4Addr::new(10, 40, 0, 2)).udp(9, Arc::new(()), || Echo).udp(9, Arc::new(()), || Echo)));
        assert!(udp.is_some(), "{udp:?}");
        // TLS and plain on one port, in either order. Before, the port
        // served only TLS.
        let config = |_: &Cx| -> Arc<fictionet::stdlib::tls::ServerConfig> { unreachable!("no handshake happens") };
        let at = Ipv4Addr::new(10, 40, 0, 3);
        let tls_first = fail(Net::new().host("d", |h| h.at(at).tls_accept(443, Sni::Any, config, Spy::default()).tcp(443, Arc::new(()), || Echo)));
        assert!(tls_first.as_deref().is_some_and(|e| e.contains("serves TLS")), "{tls_first:?}");
        let plain_first = fail(Net::new().host("e", |h| h.at(at).tcp(443, Arc::new(()), || Echo).tls_accept(443, Sni::Any, config, Spy::default())));
        assert!(plain_first.as_deref().is_some_and(|e| e.contains("serves without TLS")), "{plain_first:?}");
        Ok(())
    });
}

/// A reader set after a connection opened still sees that connection's
/// earlier events, and its later ones.
#[test]
fn a_reader_added_mid_connection_sees_its_events() {
    world(|cx| async move {
        let (server, _su, client, _cu) = two_machines(&cx);
        serve::listen(&cx, server.listen(7)?, Arc::new(()), || Echo, ServeOptions::default());
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 7)).await?;
        conn.write_all(&cx, b"before\n").await?;
        assert_eq!(read_some(&cx, &mut conn, 13).await, b"hello\nbefore\n");
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s = seen.clone();
        cx.events().subscribe(move |e| {
            if e.is("echo", "line") {
                s.lock().unwrap().push(e.summary.clone());
            }
        });
        conn.write_all(&cx, b"after\n").await?;
        assert_eq!(read_some(&cx, &mut conn, 6).await, b"after\n");
        cx.events().wait(&cx, 2, Duration::from_secs(2), |e| e.is("echo", "line")).await;
        assert_eq!(*seen.lock().unwrap(), ["before", "after"]);
        Ok(())
    });
}

/// Draws one number per connection.
struct Dice;

impl Service for Dice {
    type Decode = Lines;
    type World = ();
    type Error = Infallible;
    fn decoder(&self) -> Lines {
        Lines::new(64, Ending::LfOrCrlf)
    }
    fn on_open(&mut self, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        let n = ctx.random_u64();
        ctx.reply().extend_from_slice(format!("{n}\n").as_bytes());
        Ok(Flow::Close)
    }
    fn on_item(&mut self, _: Result<Vec<u8>, LineError>, _: &(), _: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        Ok(Flow::Continue)
    }
}

/// Two runs with the same seed and the same connections draw the same
/// numbers; connections differ from each other. Before, each connection
/// was seeded from the operating system.
#[test]
fn a_seeded_run_repeats_its_randomness() {
    let draws = |seed: u64| {
        let (tx, rx) = mpsc::channel();
        world(move |cx| async move {
            let (server, _su, client, _cu) = two_machines(&cx);
            serve::listen(&cx, server.listen(7)?, Arc::new(()), || Dice, ServeOptions::default().seed(seed));
            let mut got = Vec::new();
            for _ in 0..2 {
                let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 7)).await?;
                got.push(String::from_utf8(read_some(&cx, &mut conn, 64).await).unwrap());
            }
            tx.send(got).unwrap();
            Ok(())
        });
        rx.recv().unwrap()
    };
    let first = draws(7);
    assert_eq!(first, draws(7));
    assert_ne!(first[0], first[1]);
    assert_ne!(first, draws(8));
}

/// A network's events start with one that puts the run's clock on a
/// calendar.
#[test]
fn a_net_starts_its_events_with_a_wall_clock_anchor() {
    world(|cx| async move {
        let kept = cx.events();
        let (_attacher, attachments) = fictionet::attachments();
        let date = Fields::new().with("world_date", "2026-10-06");
        Net::new().start_fields(date).serve(&cx, attachments)?;
        let first = &kept.all()[0];
        assert!(first.is("run", "start"));
        assert_eq!(first.at, fictionet::time::Instant::ZERO);
        assert_eq!(first.str("world_date"), Some("2026-10-06"));
        assert!(first.get("wall").and_then(json::Value::as_f64).is_some_and(|w| w > 1.7e9));
        Ok(())
    });
}

/// A body that trickles in is cut off by its own timer. Before, the head
/// timer was cancelled on the head and nothing replaced it.
#[test]
fn http1_closes_a_request_whose_body_never_finishes() {
    let mut h = Harness::new(Http1::new(Router::new()), ());
    h.push(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nabc").unwrap();
    assert_eq!(h.advance(Duration::from_secs(29)).unwrap(), b"");
    assert!(!h.closed());
    h.advance(Duration::from_secs(2)).unwrap();
    assert!(h.closed());
}

/// A closed connection counts against the cap until its socket is gone, so
/// a client that never finishes closing cannot open more. Before, the
/// count dropped when the service ended.
#[test]
fn a_connection_counts_until_its_socket_is_gone() {
    world(|cx| async move {
        let (server, _su, client, _cu) = two_machines(&cx);
        serve::listen(&cx, server.listen(7)?, Arc::new(()), || Echo, ServeOptions::default().max_conns(1));
        let to = SocketAddr::new(SERVER.into(), 7);
        let mut a = client.connect(&cx, to).await?;
        a.write_all(&cx, b"quit\n").await?;
        assert_eq!(read_some(&cx, &mut a, 10).await, b"hello\nbye\n");
        // The server closed its side; `a` keeps its own open.
        let mut b = client.connect(&cx, to).await?;
        let mut buf = [0u8; 16];
        let r = timeout(&cx, Duration::from_secs(2), b.read(&cx, &mut buf)).await.expect("an answer");
        assert!(matches!(r, Err(ConnError::Reset) | Ok(0)), "{r:?}");
        drop(a);
        Ok(())
    });
}

/// A LAN joins Net: a host placed on it, a VM attached to it as a member,
/// DNS at the LAN's first address, the agent reaching the LAN through the
/// router, multicast from a host to a member, and LAN drops recorded.
#[test]
fn hosts_and_members_share_a_lan_on_the_net() {
    /// Sends `tick` to a multicast group every 20 ms.
    struct Feed;
    impl Service for Feed {
        type Decode = Lines;
        type World = SocketAddr;
        type Error = Infallible;
        fn decoder(&self) -> Lines {
            Lines::new(64, Ending::LfOrCrlf)
        }
        fn on_open(&mut self, _: &SocketAddr, ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
            ctx.set_timer("tick", Duration::from_millis(20));
            Ok(Flow::Continue)
        }
        fn on_item(&mut self, _: Result<Vec<u8>, LineError>, _: &SocketAddr, _: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
            Ok(Flow::Continue)
        }
        fn on_timer(&mut self, _: Timer, group: &SocketAddr, ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
            ctx.send_to(*group, b"tick".to_vec());
            ctx.set_timer("tick", Duration::from_millis(20));
            Ok(Flow::Continue)
        }
    }
    world(|cx| async move {
        let kept = cx.events();
        let (attacher, attachments) = fictionet::attachments();
        let lan: Prefix = "192.168.56.0/24".parse()?;
        let dc: Ipv4Addr = "192.168.56.10".parse()?;
        let ws: Ipv4Addr = "192.168.56.31".parse()?;
        let group = SocketAddr::new(Ipv4Addr::new(239, 1, 1, 1).into(), 30001);
        Net::new()
            .ipv4_only()
            .lan("corp", lan)
            .host("dc01", |h| h.on("corp").at(dc).dns_name("dc01.corp.test").tcp(389, Arc::new(()), || Echo))
            .host("feed", |h| h.on("corp").dns_name("feed.corp.test").udp(30000, Arc::new(group), || Feed))
            .member("ws01", "corp", ws.into())
            .serve(&cx, attachments)?;

        // The VM: its own stack at its LAN address, no DHCP.
        let vm = sandbox(&cx, attacher.attach("ws01")?, ws);
        // DNS at the LAN's first address.
        let mut socket = vm.udp.bind(40001)?;
        let mut q = Message::query();
        q.metadata.id = 9;
        q.add_query(Query::query(Name::from_ascii("dc01.corp.test").unwrap(), RecordType::A));
        socket.send_to(&q.to_vec().unwrap(), SocketAddr::new(Ipv4Addr::new(192, 168, 56, 1).into(), 53));
        let (bytes, _) = timeout(&cx, Duration::from_secs(2), socket.recv(&cx)).await.expect("a DNS answer")?;
        let answer = Message::from_vec(&bytes).unwrap();
        assert!(answer.answers.iter().any(|a| matches!(&a.data, RData::A(a) if a.0 == dc)));
        // The VM reaches the host across the LAN.
        let mut conn = vm.tcp.connect(&cx, SocketAddr::new(dc.into(), 389)).await?;
        assert_eq!(read_some(&cx, &mut conn, 6).await, b"hello\n");
        // Multicast from a host on the LAN reaches the member that joined.
        vm.udp.join(group.ip())?;
        let mut feed = vm.udp.bind(group.port())?;
        assert_eq!(timeout(&cx, Duration::from_secs(2), feed.recv(&cx)).await.expect("a tick")?.0, b"tick");

        // The agent, on the sandboxes' subnet, reaches the LAN through the
        // router.
        let agent = sandbox(&cx, attacher.attach("agent")?, ME);
        let mut conn = agent.tcp.connect(&cx, SocketAddr::new(dc.into(), 389)).await?;
        assert_eq!(read_some(&cx, &mut conn, 6).await, b"hello\n");
        conn.write_all(&cx, b"hi\n").await?;
        assert_eq!(read_some(&cx, &mut conn, 3).await, b"hi\n");
        // An address on the LAN with no member: the LAN drops it, and the
        // events say so.
        let mut u = agent.udp.bind(5000)?;
        u.send_to(b"anyone?", SocketAddr::new(Ipv4Addr::new(192, 168, 56, 99).into(), 7));
        let drops = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("net", "blocked") && e.str("why") == Some("Lan")).await;
        assert_eq!(drops[0].str("detail"), Some("no member at that address"));
        assert_eq!(drops[0].conn.sandbox.as_ref().map(|s| s.name.to_string()).as_deref(), Some("agent"));
        // The VM is named in events like any sandbox.
        let joined = kept.of("net", "attached");
        assert!(joined.iter().any(|e| e.conn.sandbox.as_ref().is_some_and(|s| &*s.name == "ws01")));
        let vm_lines: Vec<Event> = kept.all().into_iter().filter(|e| e.conn.sandbox.as_ref().is_some_and(|s| &*s.name == "ws01") && e.is("dns", "query")).collect();
        assert!(!vm_lines.is_empty());
        Ok(())
    });
}

#[test]
fn net_refuses_lans_that_overlap() {
    world(|cx| async move {
        let fail = |net: Net| {
            let (_attacher, attachments) = fictionet::attachments();
            net.ipv4_only().serve(&cx, attachments).err().map(|e| e.to_string())
        };
        let p = |s: &str| s.parse::<Prefix>().unwrap();
        assert!(fail(Net::new().lan("a", p("10.0.0.0/16"))).is_some_and(|e| e.contains("sandboxes")));
        assert!(fail(Net::new().lan("a", p("192.168.0.0/16")).lan("b", p("192.168.56.0/24"))).is_some_and(|e| e.contains("overlaps LAN a")));
        assert!(fail(Net::new().lan("a", p("192.168.56.0/24")).member("vm", "a", "192.168.56.1".parse().unwrap())).is_some());
        assert!(fail(Net::new().lan("a", p("192.168.56.0/24")).host("x", |h| h.at(Ipv4Addr::new(192, 168, 56, 5)))).is_some_and(|e| e.contains("Host::on")));
        Ok(())
    });
}

/// Keeps the budget each connection arrives with, and closes it.
#[derive(Default)]
struct Spy(Arc<Mutex<Vec<Option<Budget>>>>);

impl Accept for Spy {
    fn serve(&self, _: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        self.0.lock().unwrap().push(arrival.budget);
        Box::pin(async {})
    }
}

/// What `spy` has kept, once it has kept `n`.
async fn spied(cx: &Cx, spy: &Mutex<Vec<Option<Budget>>>, n: usize) -> Vec<Option<Budget>> {
    for _ in 0..200 {
        let kept = spy.lock().unwrap().clone();
        if kept.len() >= n {
            return kept;
        }
        let _ = cx.sleep(Duration::from_millis(10)).await;
    }
    panic!("the spy kept fewer than {n} budgets");
}

/// A sandbox has one budget for its IPv4 and IPv6 addresses, and a new
/// attachment at the same address gets a new one. Before, budgets were
/// kept by address: each family had its own, and an address kept its
/// budget after its sandbox detached.
#[test]
fn net_keeps_one_budget_per_attachment() {
    world(|cx| async move {
        let kept = cx.events();
        let (attacher, attachments) = fictionet::attachments();
        let (addr, addr6) = (Ipv4Addr::new(10, 40, 0, 3), "2001:2::3".parse::<Ipv6Addr>()?);
        let me6: Ipv6Addr = "2001:db8::2".parse()?;
        let spy = Spy::default();
        let budgets = spy.0.clone();
        Net::new()
            .host("svc", |h| h.at(addr).at(addr6).tcp(8, Arc::new(()), || Wide).accept(9, spy))
            .serve(&cx, attachments)?;

        // One sandbox on both families: a connection over IPv4 is charged
        // to the budget a connection over IPv6 gets.
        let first = budgets.clone();
        let first_attacher = &attacher;
        let _ = cx
            .region(|cx| async move {
                let (v4, v6, _other) = ip::split_versions(&cx, first_attacher.attach("a")?);
                let (a4, a6) = (sandbox(&cx, v4, ME), sandbox(&cx, v6, me6));
                let mut wide = a4.tcp.connect(&cx, SocketAddr::new(addr.into(), 8)).await?;
                assert_eq!(read_some(&cx, &mut wide, 6).await, b"hello\n");
                let _spied4 = a4.tcp.connect(&cx, SocketAddr::new(addr.into(), 9)).await?;
                let _spied6 = a6.tcp.connect(&cx, SocketAddr::new(addr6.into(), 9)).await?;
                let got = spied(&cx, &first, 2).await;
                let (b4, b6) = (got[0].clone().expect("a budget"), got[1].clone().expect("a budget"));
                assert!(b4.used() >= 40 << 10, "{b4:?}");
                assert_eq!(b6.used(), b4.used(), "IPv6 has its own budget");
                // Leaving the region detaches the sandbox.
                Err(Box::new(Done) as fictionet::Error)
            })
            .await;
        kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("net", "detached")).await;
        let a = budgets.lock().unwrap()[0].clone().expect("a budget");

        // Another sandbox at the same address: its own budget.
        let b = sandbox(&cx, attacher.attach("b")?, ME);
        let mut wide = b.tcp.connect(&cx, SocketAddr::new(addr.into(), 8)).await?;
        assert_eq!(read_some(&cx, &mut wide, 6).await, b"hello\n");
        let _spied = b.tcp.connect(&cx, SocketAddr::new(addr.into(), 9)).await?;
        let got = spied(&cx, &budgets, 3).await;
        let b_budget = got[2].clone().expect("a budget");
        assert!(b_budget.used() >= 40 << 10, "{b_budget:?}");
        for _ in 0..200 {
            if a.used() == 0 {
                break;
            }
            cx.sleep(Duration::from_millis(10)).await?;
        }
        assert_eq!(a.used(), 0, "the sandbox that detached still has charges: {a:?}");
        Ok(())
    });
}

/// A LAN member detaches as any sandbox does: its connections are reset
/// and `net.detached` is recorded, and it can attach again. Before, a
/// member was never detached.
#[test]
fn a_lan_member_detaches_like_any_sandbox() {
    world(|cx| async move {
        let kept = cx.events();
        let (attacher, attachments) = fictionet::attachments();
        let dc: Ipv4Addr = "192.168.56.10".parse()?;
        let ws: Ipv4Addr = "192.168.56.31".parse()?;
        Net::new()
            .ipv4_only()
            .lan("corp", "192.168.56.0/24".parse()?)
            .host("dc01", |h| h.on("corp").at(dc).tcp(389, Arc::new(()), || Echo))
            .member("ws01", "corp", ws.into())
            .serve(&cx, attachments)?;

        let to = SocketAddr::new(dc.into(), 389);
        let first_attacher = &attacher;
        let _ = cx
            .region(|cx| async move {
                let vm = sandbox(&cx, first_attacher.attach("ws01")?, ws);
                let mut conn = vm.tcp.connect(&cx, to).await?;
                assert_eq!(read_some(&cx, &mut conn, 6).await, b"hello\n");
                // Leaving the region takes the VM away without a word to
                // the server.
                Err(Box::new(Done) as fictionet::Error)
            })
            .await;
        let detached = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("net", "detached")).await;
        let first = detached[0].conn.sandbox.clone().expect("a sandbox");
        assert_eq!((&*first.name, first.addr), ("ws01", Some(ws)));
        // The server's side of the connection was reset.
        let closed = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("conn", "close")).await;
        assert_eq!(closed[0].conn.sandbox.as_ref().map(|s| s.id), Some(first.id));

        // The member attaches again, as a new sandbox.
        let vm = sandbox(&cx, attacher.attach("ws01")?, ws);
        let mut conn = vm.tcp.connect(&cx, to).await?;
        assert_eq!(read_some(&cx, &mut conn, 6).await, b"hello\n");
        let attached = kept.of("net", "attached");
        assert_eq!(attached.len(), 2, "{attached:?}");
        assert_ne!(attached[1].conn.sandbox.as_ref().map(|s| s.id), Some(first.id));
        Ok(())
    });
}

/// `Host::tcp` records each connection's opening and closing, as
/// `Host::tcp_with` does by default. Before, `tcp` turned them off.
#[test]
fn net_records_connections_on_a_tcp_port() {
    world(|cx| async move {
        let kept = cx.events();
        let (attacher, attachments) = fictionet::attachments();
        let addr = Ipv4Addr::new(10, 40, 0, 1);
        Net::new().ipv4_only().host("svc", |h| h.at(addr).tcp(7, Arc::new(()), || Echo)).serve(&cx, attachments)?;
        let s = sandbox(&cx, attacher.attach("agent")?, ME);
        let mut conn = s.tcp.connect(&cx, SocketAddr::new(addr.into(), 7)).await?;
        conn.write_all(&cx, b"quit\n").await?;
        assert_eq!(read_some(&cx, &mut conn, 10).await, b"hello\nbye\n");
        let closed = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("conn", "close")).await;
        let opened = kept.of("conn", "open");
        assert_eq!(opened.len(), 1, "{opened:?}");
        assert_eq!((opened[0].conn.id, closed[0].conn.id), (Some(1), Some(1)));
        Ok(())
    });
}

/// A STARTTLS handshake has the network's handshake limit. Before, it had
/// the service's default of 10 seconds.
#[test]
#[cfg(feature = "tokio")]
fn net_limits_a_starttls_handshake() {
    let (config, _roots) = tls_pair(&["mail.test"]);
    world(move |cx| async move {
        let kept = cx.events();
        let (attacher, attachments) = fictionet::attachments();
        let addr = Ipv4Addr::new(10, 40, 0, 25);
        let limits = fictionet::stdlib::net::Limits { handshake: Duration::from_millis(200), ..Default::default() };
        let opts = ServeOptions::default().starttls(config);
        Net::new()
            .ipv4_only()
            .limits(limits)
            .host("mail", |h| h.at(addr).tcp_with(25, Arc::new(()), || Mail { tls: false }, opts))
            .serve(&cx, attachments)?;
        let s = sandbox(&cx, attacher.attach("agent")?, ME);
        let mut conn = s.tcp.connect(&cx, SocketAddr::new(addr.into(), 25)).await?;
        assert_eq!(read_some(&cx, &mut conn, 16).await, b"220 mail ready\r\n");
        conn.write_all(&cx, b"STARTTLS\r\n").await?;
        assert_eq!(read_some(&cx, &mut conn, 14).await, b"220 go ahead\r\n");
        // The client never starts its handshake.
        let handshake = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("tls", "handshake")).await;
        assert_ne!(handshake[0].str("outcome"), Some("accepted"));
        Ok(())
    });
}
