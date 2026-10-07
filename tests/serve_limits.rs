//! What a connection may hold and how long it may stall: the write side of
//! `serve` charged to the budget and given a deadline, HTTP/2 held to the
//! same limits, budget and seed as HTTP/1, and request events that say
//! what the connection took.

use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use fictionet::events::{ConnInfo, Event};
use fictionet::stdlib::codec::{Ending, ItemFault, Lcg, LineError, Lines, Rewrite, Rule, Trigger};
use fictionet::stdlib::httpd::{self, Body, Exchange, Handler, Http1, HttpOptions, Limits, Reply, Router};
use fictionet::stdlib::json;
use fictionet::stdlib::serve::{self, Budget, Ended, FaultPlan, Flow, Harness, Plan, ServeCtx, ServeOptions, Service};
use fictionet::stdlib::{Connection, ConnectionExt, ip, tcp};
use fictionet::{Cx, block_on, pair, run};
use http_body::Frame;
use http_body_util::{BodyExt, Full};

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

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);

/// Two machines joined by a cable: a server at 10.9.0.1 and a client at
/// 10.9.0.2.
fn two_machines(cx: &Cx) -> (tcp::Endpoint, tcp::Endpoint) {
    let (a, b) = pair();
    let (at, _au, _ai, _ao) = ip::split_protocols(cx, a);
    let (bt, _bu, _bi, _bo) = ip::split_protocols(cx, b);
    let client: IpAddr = Ipv4Addr::new(10, 9, 0, 2).into();
    (tcp::endpoint(cx, at, SERVER.into()), tcp::endpoint(cx, bt, client))
}

/// Serves HTTP on `port` of `server` with `handler` and `opts`, numbering
/// connections from 1.
fn serve_http(cx: &Cx, server: &tcp::Endpoint, port: u16, handler: Arc<dyn Handler>, opts: HttpOptions) -> fictionet::Result {
    let mut listener = server.listen(port)?;
    cx.spawn(move |cx| async move {
        let mut id = 0;
        loop {
            let conn = listener.accept(&cx).await?;
            id += 1;
            let info = ConnInfo::new(id, conn.local_addr(), conn.peer_addr());
            let (handler, opts) = (handler.clone(), opts.clone());
            cx.spawn(move |cx| async move {
                httpd::serve_connection(&cx, conn, info, handler, &opts).await;
                Ok(())
            });
        }
    });
    Ok(())
}

/// Reads until `want` bytes arrived, the stream ends, or a second passes.
async fn read_some<C: Connection>(cx: &Cx, conn: &mut C, want: usize) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while got.len() < want {
        match cx.race(Some(cx.now() + Duration::from_secs(1)), conn.read(cx, &mut buf)).await {
            Ok(Ok(n)) if n > 0 => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    got
}

fn field_u64(e: &Event, name: &str) -> Option<u64> {
    e.get(name).and_then(json::Value::as_u64)
}

fn field_bool(e: &Event, name: &str) -> Option<bool> {
    e.get(name).and_then(json::Value::as_bool)
}

/// Says `size` bytes on each line it gets, all at once.
struct Loud {
    size: usize,
}

impl Service for Loud {
    type Decoder = Lines;
    type State = ();
    type Error = Infallible;
    fn decoder(&self) -> Lines {
        Lines::new(64, Ending::LfOrCrlf)
    }
    fn on_item(&mut self, _: Result<Vec<u8>, LineError>, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        ctx.reply().resize(self.size, b'x');
        Ok(Flow::Continue)
    }
}

fn page(size: usize) -> Router {
    Router::new().get("/", move |_, _| http::Response::new(Bytes::from(vec![b'x'; size])))
}

// ---------------------------------------------------------------------------
// The write side of serve

/// A reply not yet written counts against the budget. Before, only what
/// was read did, so a client that asked for big replies and never read
/// them held them outside the budget.
#[test]
fn reply_bytes_count_against_the_budget() {
    let opts = ServeOptions::default().idle(None).budget(Budget::new(256 << 10));
    let mut h = Harness::with_options(Loud { size: 1 << 20 }, (), opts);
    assert_eq!(h.push(b"go\n").unwrap(), b"");
    assert_eq!(h.end_reason(), Some(Ended::Budget));

    // A reply that fits goes out.
    let opts = ServeOptions::default().idle(None).budget(Budget::new(256 << 10));
    let mut h = Harness::with_options(Loud { size: 64 << 10 }, (), opts);
    assert_eq!(h.push(b"go\n").unwrap().len(), 64 << 10);
    assert_eq!(h.end_reason(), None);
}

/// What deferred work holds counts too: an HTTP/1 response body waiting
/// to be written. Before, it did not.
#[test]
fn a_response_body_waiting_to_be_written_counts_against_the_budget() {
    let opts = ServeOptions::default().idle(None).budget(Budget::new(512 << 10));
    let mut h = Harness::with_options(Http1::new(page(1 << 20)), (), opts);
    assert_eq!(h.push(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").unwrap(), b"");
    assert_eq!(h.end_reason(), Some(Ended::Budget));
    let request = h.events().iter().find(|e| e.is("http", "request")).expect("an http.request event");
    assert_eq!(request.str("answer"), Some("cancelled"));
    assert_eq!(field_u64(request, "sent"), Some(0));
}

/// A write that takes no bytes for the write timeout ends the connection.
/// Before, the driver waited for ever on a client that stopped reading.
#[test]
fn a_client_that_stops_reading_times_out() {
    world(|cx| async move {
        let (server, client) = two_machines(&cx);
        let kept = cx.events();
        let opts = ServeOptions::default().idle(None).write_timeout(Some(Duration::from_millis(300)));
        serve::listen(&cx, server.listen(7)?, Arc::new(()), || Loud { size: 16 << 20 }, opts);
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 7)).await?;
        conn.write_all(&cx, b"go\n").await?;
        let closed = kept.wait(&cx, 1, Duration::from_secs(10), |e| e.is("conn", "close")).await;
        assert_eq!(closed.first().and_then(|e| e.str("end")), Some("timed_out"));
        drop(conn);
        Ok(())
    });
}

/// Item faults that stop, because the client's bytes did not decode, say
/// so. Before, they stopped without a word.
#[test]
fn item_faults_that_stop_record_why() {
    let plan = FaultPlan::new(Plan {
        seed: 1,
        items: vec![Rule { when: Trigger::At(1000), fault: ItemFault::Action { delay: None, rewrite: Rewrite::Drop } }],
        ..Plan::default()
    });
    let opts = ServeOptions::default().idle(None).faults(plan);
    let mut h = Harness::with_options(Http1::new(page(2)), (), opts);
    let _ = h.push(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n\x00\x01 not http\r\n\r\n");
    let stopped = h.events().iter().find(|e| e.is("conn", "faults")).expect("a conn.faults event");
    assert_eq!(stopped.str("stopped"), Some("failed"));
}

// ---------------------------------------------------------------------------
// HTTP/1 events and closes

/// A body of unknown length, in one frame.
struct Unsized(Option<Bytes>);

impl http_body::Body for Unsized {
    type Data = Bytes;
    type Error = fictionet::Error;
    fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, fictionet::Error>>> {
        Poll::Ready(self.get_mut().0.take().map(|b| Ok(Frame::data(b))))
    }
}

struct Streams;

impl Handler for Streams {
    fn call(&self, _: http::Request<Body>, _: &mut Exchange<'_>) -> Reply {
        Reply::Now(http::Response::new(Body::new(Unsized(Some(Bytes::from_static(b"streamed\n"))))))
    }
}

/// An HTTP/1.0 response of unknown length ends with the connection, even
/// when the client asked to keep it alive. Before, the connection stayed
/// open and the client waited for the end of the body until a timer
/// fired.
#[test]
fn an_http10_body_of_unknown_length_closes_the_connection() {
    let mut h = Harness::new(Http1::new(Streams), ());
    let reply = h.push(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").unwrap();
    let text = String::from_utf8(reply).unwrap();
    assert!(text.starts_with("HTTP/1.0 200 OK\r\n"), "{text}");
    assert!(!text.contains("content-length") && !text.contains("keep-alive"), "{text}");
    assert!(text.ends_with("\r\n\r\nstreamed\n"), "{text}");
    assert_eq!(h.end_reason(), Some(Ended::Closed));

    // With a known length, the connection stays open.
    let mut h = Harness::new(Http1::new(page(3)), ());
    let reply = h.push(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").unwrap();
    assert!(String::from_utf8(reply).unwrap().contains("connection: keep-alive"));
    assert_eq!(h.end_reason(), None);
}

/// A request's event is made once its bytes are written, and says what
/// the connection took. Before, a buffered response was logged complete
/// as soon as it was made, even when the client reset the connection
/// before reading it.
#[test]
fn a_response_cut_off_by_a_reset_is_logged_incomplete() {
    world(|cx| async move {
        let (server, client) = two_machines(&cx);
        let kept = cx.events();
        let size = 8 << 20;
        serve_http(&cx, &server, 80, Arc::new(page(size)), HttpOptions::default())?;
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 80)).await?;
        conn.write_all(&cx, b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").await?;
        let head = read_some(&cx, &mut conn, 64).await;
        assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n"));
        conn.reset();
        let request = kept.wait(&cx, 1, Duration::from_secs(10), |e| e.is("http", "request")).await;
        let request = request.first().expect("an http.request event");
        assert_eq!(field_bool(request, "complete"), Some(false));
        assert!(field_u64(request, "sent").unwrap() < size as u64);

        // A response read to the end is complete.
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 80)).await?;
        conn.write_all(&cx, b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n").await?;
        let mut all = Vec::new();
        let mut buf = vec![0u8; 64 << 10];
        loop {
            match conn.read(&cx, &mut buf).await? {
                0 => break,
                n => all.extend_from_slice(&buf[..n]),
            }
        }
        assert!(all.len() > size);
        let done = kept.wait(&cx, 2, Duration::from_secs(10), |e| e.is("http", "request")).await;
        assert_eq!(field_bool(&done[1], "complete"), Some(true));
        assert_eq!(field_u64(&done[1], "sent"), Some(size as u64));
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// HTTP/2

/// The server's settings say how many streams a connection may open at
/// once: 100, not hyper's 200.
#[test]
fn http2_caps_the_streams_a_connection_opens() {
    world(|cx| async move {
        let (server, client) = two_machines(&cx);
        serve_http(&cx, &server, 80, Arc::new(page(2)), HttpOptions::default())?;
        let mut conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 80)).await?;
        conn.write_all(&cx, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00").await?;
        let mut got = read_some(&cx, &mut conn, 9).await;
        assert_eq!(got[3], 4, "the first frame is SETTINGS");
        let len = usize::from(got[0]) << 16 | usize::from(got[1]) << 8 | usize::from(got[2]);
        if got.len() < 9 + len {
            let more = read_some(&cx, &mut conn, 9 + len - got.len()).await;
            got.extend_from_slice(&more);
        }
        let settings: Vec<(u16, u32)> = got[9..9 + len]
            .chunks(6)
            .map(|s| (u16::from_be_bytes([s[0], s[1]]), u32::from_be_bytes([s[2], s[3], s[4], s[5]])))
            .collect();
        assert!(settings.contains(&(3, 100)), "{settings:?}");
        Ok(())
    });
}

/// HTTP/2 applies the body limit, charges bodies to the budget, and draws
/// a handler's randomness from the connection's seed, as HTTP/1 does.
/// Before, it took any body up to 64 MiB, charged nothing, and drew from
/// the run's own randomness.
#[test]
fn http2_has_the_limits_budget_and_seed_of_http1() {
    world(|cx| async move {
        let (server, client) = two_machines(&cx);
        let kept = cx.events();
        let router = Router::new()
            .get("/dice", |ex, _| http::Response::new(Bytes::from(ex.random_u64().to_string())))
            .post("/echo", |_, request: http::Request<Bytes>| http::Response::new(request.into_body()));
        let opts = HttpOptions {
            limits: Limits { body: 3000, ..Limits::default() },
            budget: Some(Budget::new(2000)),
            seed: 7,
            ..HttpOptions::default()
        };
        serve_http(&cx, &server, 80, Arc::new(router), opts)?;
        let conn = client.connect(&cx, SocketAddr::new(SERVER.into(), 80)).await?;
        let (mut send, driving) = hyper::client::conn::http2::handshake(Exec(cx.clone()), Io { cx: cx.clone(), conn }).await?;
        cx.spawn(move |_| async move {
            let _ = driving.await;
            Ok(())
        });
        let mut ask = async |method: http::Method, path: &str, body: Vec<u8>| -> fictionet::Result<(u16, Bytes)> {
            send.ready().await?;
            let request = http::Request::builder().method(method).uri(format!("http://a.test{path}")).body(Full::new(Bytes::from(body)))?;
            let response = send.send_request(request).await?;
            let status = response.status().as_u16();
            Ok((status, response.into_body().collect().await?.to_bytes()))
        };

        let (status, body) = ask(http::Method::GET, "/dice", vec![]).await?;
        assert_eq!(status, 200);
        let expected = Lcg::new(serve::conn_seed(7, 1)).next();
        assert_eq!(body, expected.to_string());

        // Within the budget and the limit.
        let (status, body) = ask(http::Method::POST, "/echo", vec![b'a'; 1500]).await?;
        assert_eq!((status, body.len()), (200, 1500));
        // Within the limit, past the budget.
        let (status, _) = ask(http::Method::POST, "/echo", vec![b'b'; 2500]).await?;
        assert_eq!(status, 503);
        // Past the limit.
        let (status, _) = ask(http::Method::POST, "/echo", vec![b'c'; 3500]).await?;
        assert_eq!(status, 413);

        let events = kept.wait(&cx, 4, Duration::from_secs(5), |e| e.is("http", "request")).await;
        let answers: Vec<_> = events.iter().map(|e| e.str("answer").unwrap_or("").to_owned()).collect();
        assert_eq!(answers, ["handler", "handler", "budget", "too_large"]);
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// A hyper client over a Connection

struct Io<C> {
    cx: Cx,
    conn: C,
}

impl<C: Connection + Unpin> hyper::rt::Read for Io<C> {
    fn poll_read(self: Pin<&mut Self>, task: &mut Context<'_>, mut buf: hyper::rt::ReadBufCursor<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut tmp = vec![0u8; buf.remaining().min(16 * 1024)];
        match this.conn.poll_read(&this.cx, task, &mut tmp) {
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
    fn poll_write(self: Pin<&mut Self>, task: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.conn.poll_write(&this.cx, task, data).map_err(std::io::Error::other)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.conn.poll_shutdown(&this.cx, task).map_err(std::io::Error::other)
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
