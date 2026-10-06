//! The service layer: `serve` (the Service trait, the driver, the
//! harness, transcripts and faults), `journal`, `httpd`, `net` and
//! `scenario`, each tested on its own and together in one world: a PLC
//! that speaks Modbus/TCP and a web server, on one `Net`, with the
//! dashboard's decoder reading both from the packets.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
use fictionet::stdlib::journal::{ConnInfo, Entry, Event, Fields, Journal, Level};
use fictionet::stdlib::json;
use fictionet::stdlib::modbus::{self, Exception, Frame, Request as MbRequest, Response as MbResponse};
use fictionet::stdlib::net::Net;
use fictionet::stdlib::route::Prefix;
use fictionet::stdlib::scenario::Scenario;
use fictionet::stdlib::serve::{
    self, End as Ended, FaultPlan, Flow, Harness, HarnessError, Pending, PendingCtx, Plan, ServeCtx, ServeOptions, Served,
    Service, Transcript,
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
    let mut fut = pin!(fut);
    let mut sleep = pin!(cx.sleep(d));
    poll_fn(|task| {
        if let Poll::Ready(v) = fut.as_mut().poll(task) {
            return Poll::Ready(Some(v));
        }
        if sleep.as_mut().poll(task).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
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

/// Echoes each line, closes on `quit`, hands over on `starttls`, and on
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
            b"starttls" => Ok(Flow::Upgrade),
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
        ctx.wake_in(Duration::from_millis(30));
        Ok(Flow::Continue)
    }

    fn on_item(&mut self, _: Result<Vec<u8>, LineError>, _: &(), _: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        Ok(Flow::Continue)
    }

    fn on_tick(&mut self, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        self.ticks += 1;
        ctx.reply().extend_from_slice(b"tick\n");
        if self.ticks == 3 {
            return Ok(Flow::Close);
        }
        ctx.wake_in(Duration::from_millis(30));
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
        let journal = Journal::new();
        let kept = journal.keep(100);
        let transcript = Transcript::new(100, 1 << 16);
        let opts = ServeOptions::default().journal(journal).record(transcript.clone());
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
        let all = kept.entries();
        let kinds: Vec<String> = all.iter().map(|e| format!("{}.{}", e.event.service, e.event.kind)).collect();
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

        let journal = Journal::new();
        let kept = journal.keep(100);
        let opts = ServeOptions::default().journal(journal).idle(Some(Duration::from_millis(100)));
        serve::listen(&cx, server.listen(2)?, Arc::new(()), || Echo, opts);
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 2)).await?;
        assert_eq!(read_some(&cx, &mut conn, 100).await, b"hello\n");
        let closed = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("conn", "close")).await;
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
            let served = serve::serve(&cx, conn, ConnInfo::default(), None, &mut Echo, &(), &ServeOptions::default()).await;
            if let Ok(Served::Upgraded(mut rest)) = served {
                let _ = tx.send(rest.unread().to_vec());
                // What follows is the next protocol's: here, raw bytes.
                rest.write_all(&cx, b"upgraded\n").await?;
            }
            Ok(())
        });
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 25)).await?;
        conn.write_all(&cx, b"starttls\n\x16\x03\x01").await?;
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
// The journal

#[test]
fn the_journal_writes_json_lines_and_keeps_what_it_is_asked_to() {
    let path = std::env::temp_dir().join(format!("fictionet-journal-{}.jsonl", std::process::id()));
    let p = path.clone();
    world(move |cx| async move {
        let journal = Journal::new().to_file(&p)?;
        let kept = journal.keep(2);
        let conn = ConnInfo::new(9, "10.0.0.1:80".parse().unwrap(), "10.0.0.2:4000".parse().unwrap());
        for i in 0..3u64 {
            journal.record(&cx, &conn, Event::new("test", "n").summary(format!("n={i}")).field("i", i).field("none", fictionet::stdlib::journal::opt(None::<u64>)));
        }
        assert_eq!(kept.entries().iter().map(|e| e.seq).collect::<Vec<_>>(), [2, 3]);
        assert_eq!(kept.dropped(), 1);
        assert_eq!(journal.lost(), 0);
        let layer = kept.entries()[0].layer();
        assert_eq!(layer.name, "test.n");
        assert_eq!(layer.summary, "n=1");
        cx.sleep(Duration::from_millis(100)).await?;
        Ok(())
    });
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<json::Value> = text.lines().map(|l| json::Value::parse(l.as_bytes()).unwrap()).collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[1].get("service").and_then(json::Value::as_str), Some("test"));
    assert_eq!(lines[1].get("conn").and_then(json::Value::as_u64), Some(9));
    assert_eq!(lines[1].get("peer").and_then(json::Value::as_str), Some("10.0.0.2:4000"));
    let fields = lines[1].get("fields").unwrap();
    assert_eq!(fields.get("i").and_then(json::Value::as_u64), Some(1));
    assert!(fields.get("none").unwrap().is_null());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_journal_with_no_sink_records_nothing() {
    world(|cx| async move {
        let journal = Journal::new().dashboard(false);
        assert!(!journal.wants(&cx));
        let counted = Arc::new(AtomicU64::new(0));
        let c = counted.clone();
        journal.subscribe(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        });
        assert!(journal.wants(&cx));
        journal.record(&cx, &ConnInfo::default(), Event::new("x", "y"));
        assert_eq!(counted.load(Ordering::SeqCst), 1);
        Ok(())
    });
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

fn sandbox(cx: &Cx, end: impl Interface, addr: Ipv4Addr) -> Sandbox {
    let (t, u, i, _o) = ip::split_protocols(cx, end);
    Sandbox { tcp: tcp::endpoint(cx, t, addr.into()), udp: udp::endpoint(cx, u, addr.into()), _icmp: i }
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
        let journal = Journal::new();
        let kept = journal.keep(1000);
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
            .journal(journal.clone())
            .ipv4_only()
            .host("plc")
            .at(PLC_ADDR)
            .dns_name("plc1.plant.test")
            .tcp(modbus::PORT, plant.clone(), || Plc)
            .done()
            .host("hmi")
            .dns_name("hmi.plant.test")
            .http(80, hmi)
            .done()
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
        // A port with no service: refused, and journaled as blocked.
        assert_eq!(s.tcp.connect(&cx, SocketAddr::new(PLC_ADDR.into(), 102)).await.err(), Some(ConnError::Refused));

        let alarm = kept.wait(&cx, 1, Duration::from_secs(2), |e| e.event.level == Level::Alarm).await;
        assert_eq!(alarm[0].event.kind, "write_register");
        let sandbox_name = |e: &Entry| e.conn.sandbox.as_ref().map(|s| s.name.to_string());
        assert_eq!(sandbox_name(&alarm[0]).as_deref(), Some("operator"));
        assert_eq!(alarm[0].conn.local, Some(SocketAddr::new(PLC_ADDR.into(), 502)));
        kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("http", "request")).await;
        let kinds: BTreeSet<String> = kept.entries().iter().map(|e| format!("{}.{}", e.event.service, e.event.kind)).collect();
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
        let journal = Journal::new();
        let kept = journal.keep(1000);
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
                ctx.reply().extend_from_slice(format!("{}\n", n.fetch_add(1, Ordering::SeqCst) + 1).as_bytes());
                Ok(Flow::Continue)
            }
        }
        let (attacher, attachments) = fictionet::attachments();
        Net::new()
            .journal(journal)
            .ipv4_only()
            .host("svc")
            .at(Ipv4Addr::new(10, 40, 0, 1))
            .tcp(7, Arc::new(()), || Echo)
            .udp(9, counter.clone(), || Udp)
            .done()
            .route("box", Prefix { addr: Ipv4Addr::new(10, 50, 0, 7).into(), len: 32 })
            .serve(&cx, attachments)?;
        let s = sandbox(&cx, attacher.attach("agent")?, ME);
        let mut conn = s.tcp.connect(&cx, SocketAddr::new(Ipv4Addr::new(10, 40, 0, 1).into(), 7)).await?;
        assert_eq!(read_some(&cx, &mut conn, 6).await, b"hello\n");
        let mut u = s.udp.bind(5000)?;
        u.send_to(b"x\n", SocketAddr::new(Ipv4Addr::new(10, 40, 0, 1).into(), 9));
        assert_eq!(u.recv(&cx).await?.0, b"1\n");

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
        assert!(kept.entries().iter().all(|e| e.event.service != "echo"), "no line was sent yet");
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
fn a_scenario_changes_the_world_on_time_and_grades_the_journal() {
    world(|cx| async move {
        let journal = Journal::new();
        let kept = journal.keep(100);
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
            .forbid("an unsafe write", |e| e.event.level == Level::Alarm)
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
        Net::new().journal(journal).ipv4_only().host("plc").at(PLC_ADDR).tcp_with(502, plant, || Plc, ServeOptions::default().faults(faults.clone())).done().serve(&cx, attachments)?;
        let s = sandbox(&cx, attacher.attach("op")?, ME);
        let mut conn = s.tcp.connect(&cx, SocketAddr::new(PLC_ADDR.into(), 502)).await?;
        conn.write_all(&cx, &mb(1, MbRequest::ReadHoldingRegisters { address: 1, quantity: 1 })).await?;
        // Every reply is dropped by the plan the scenario set.
        assert_eq!(read_some(&cx, &mut conn, 11).await, b"");
        kept.wait(&cx, 1, Duration::from_secs(2), |e| e.is("modbus", "read")).await;
        let report = checks.grade(&kept.entries());
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
                    httpd::serve_connection(&cx, conn, info, None, handler, &httpd::HttpOptions::default()).await;
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
        let journal = Journal::new();
        let kept = journal.keep(1000);
        let (attacher, attachments) = fictionet::attachments();
        let (ca, cb) = (config.clone(), config.clone());
        let addr = Ipv4Addr::new(10, 40, 0, 2);
        Net::new()
            .journal(journal)
            .ipv4_only()
            .add_host(
                fictionet::stdlib::net::Host::new("tls")
                    .at(addr)
                    .tls(6514, Some("a.test"), move |_| ca.clone(), Arc::new(()), || Echo)
                    .tls(6514, Some("b.test"), move |_| cb.clone(), Arc::new(()), || Upper),
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
