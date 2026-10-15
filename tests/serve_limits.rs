//! What a connection may hold and how long it may stall: the write side of
//! `serve` charged to the budget and given a deadline, HTTP/2 held to the
//! same limits, budget and seed as HTTP/1, and request events that say
//! what the connection took.

#[macro_use]
#[path = "common/service_fixture.rs"]
mod service_fixture;

mod common;
#[path = "common/done.rs"]
mod done;
#[path = "common/wait.rs"]
mod wait;
#[path = "common/world.rs"]
mod world;

#[path = "../examples/common/hyper.rs"]
mod hyper_io;
use hyper_io::{Exec, Io};

use world::world;

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use fictionet::events::{ConnInfo, Event};
use fictionet::stdlib::codec::{Ending, ItemFault, LineError, Lines, Rewrite, Rule, Trigger};
use fictionet::stdlib::httpd::{
    self, Body, Exchange, Handler, Http1, HttpOptions, Limits, Reply, Router,
};
use fictionet::stdlib::json;
use fictionet::stdlib::serve::{self, Budget, Ended, FaultPlan, Flow, Harness, Plan, ServeOptions};
use fictionet::stdlib::{Connection, ConnectionExt, ip, tcp};
use fictionet::{Cx, pair};
use http_body::Frame;
use http_body_util::{BodyExt, Full};

// ---------------------------------------------------------------------------
// Running a world in a test

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);

/// Two machines joined by a cable: a server at 10.9.0.1 and a client at
/// 10.9.0.2.
fn two_machines(fcx: &Cx) -> (tcp::Endpoint, tcp::Endpoint) {
    let (a, b) = pair();
    let (at, _au, _ai, _ao) = ip::split_protocols(fcx, a);
    let (bt, _bu, _bi, _bo) = ip::split_protocols(fcx, b);
    let client: IpAddr = Ipv4Addr::new(10, 9, 0, 2).into();
    (
        tcp::endpoint(fcx, at, SERVER.into()),
        tcp::endpoint(fcx, bt, client),
    )
}

/// Serves HTTP on `port` of `server` with `handler` and `opts`, numbering
/// connections from 1.
fn serve_http(
    fcx: &Cx,
    server: &tcp::Endpoint,
    port: u16,
    handler: Arc<dyn Handler>,
    opts: HttpOptions,
) -> fictionet::Result {
    let mut listener = server.listen(port)?;
    fcx.spawn(move |fcx| async move {
        let mut id = 0;
        loop {
            let conn = listener.accept(&fcx).await?;
            id += 1;
            let info = ConnInfo::new(id, conn.local_addr(), conn.peer_addr());
            let (handler, opts) = (handler.clone(), opts.clone());
            fcx.spawn(move |fcx| async move {
                Ok(httpd::serve_connection(&fcx, conn, info, handler, &opts).await?)
            });
        }
    });
    Ok(())
}

/// Reads until `want` bytes arrived, the stream ends, or a second passes.
async fn read_some<C: Connection>(fcx: &Cx, conn: &mut C, want: usize) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while got.len() < want {
        match fcx
            .race(
                Some(fcx.now() + Duration::from_secs(1)),
                conn.read(fcx, &mut buf),
            )
            .await
        {
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

service_fixture! {
    Loud => (Lines, (), Infallible);
    decoder(self) {
        Lines::new(64, Ending::LfOrCrlf)
    }
    on_item(self, _: Result<Vec<u8>, LineError>; _, driver) -> Flow {
        driver.reply().resize(self.size, b'x');
        Ok(Flow::Continue)
    }
}

fn page(size: usize) -> Router {
    Router::new().get("/", move |_, _| {
        http::Response::new(Bytes::from(vec![b'x'; size]))
    })
}

// ---------------------------------------------------------------------------
// The write side of serve

/// A reply not yet written counts against the budget. Before, only what
/// was read did, so a client that asked for big replies and never read
/// them held them outside the budget.
#[test]
fn reply_bytes_count_against_the_budget() {
    let opts = ServeOptions::default()
        .idle(None)
        .budget(Budget::new(256 << 10));
    let mut h = Harness::with_options(
        fictionet::Seed::from_u64(0),
        Loud { size: 1 << 20 },
        (),
        opts,
    );
    assert_eq!(h.push(b"go\n").unwrap(), b"");
    assert_eq!(h.end_reason(), Some(Ended::Budget));

    // A reply that fits goes out.
    let opts = ServeOptions::default()
        .idle(None)
        .budget(Budget::new(256 << 10));
    let mut h = Harness::with_options(
        fictionet::Seed::from_u64(0),
        Loud { size: 64 << 10 },
        (),
        opts,
    );
    assert_eq!(h.push(b"go\n").unwrap().len(), 64 << 10);
    assert_eq!(h.end_reason(), None);
}

/// What deferred work holds counts too: an HTTP/1 response body waiting
/// to be written. Before, it did not.
#[test]
fn a_response_body_waiting_to_be_written_counts_against_the_budget() {
    let opts = ServeOptions::default()
        .idle(None)
        .budget(Budget::new(512 << 10));
    let mut h = Harness::with_options(
        fictionet::Seed::from_u64(0),
        Http1::new(page(1 << 20)),
        (),
        opts,
    );
    assert_eq!(
        h.push(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").unwrap(),
        b""
    );
    assert_eq!(h.end_reason(), Some(Ended::Budget));
    let request = h
        .events()
        .iter()
        .find(|e| e.is("http", "request"))
        .expect("an http.request event");
    assert_eq!(request.str("answer"), Some("cancelled"));
    assert_eq!(field_u64(request, "sent"), Some(0));
}

/// A write that takes no bytes for the write timeout ends the connection.
/// Before, the driver waited for ever on a client that stopped reading.
#[test]
fn a_client_that_stops_reading_times_out() {
    world(Duration::from_secs(60), |fcx| async move {
        let (server, client) = two_machines(&fcx);
        let kept = fcx.events();
        let opts = ServeOptions::default()
            .idle(None)
            .write_timeout(Some(Duration::from_millis(300)));
        serve::listen(
            &fcx,
            server.listen(7)?,
            Arc::new(()),
            || Loud { size: 16 << 20 },
            opts,
        );
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 7))
            .await?;
        conn.write_all(&fcx, b"go\n").await?;
        let closed = kept
            .wait(&fcx, 1, Duration::from_secs(10), |e| e.is("conn", "close"))
            .await?;
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
        items: vec![Rule {
            when: Trigger::At(1000),
            fault: ItemFault::Action {
                delay: None,
                rewrite: Rewrite::Drop,
            },
        }],
        ..Plan::default()
    });
    let opts = ServeOptions::default().idle(None).faults(plan);
    let mut h = Harness::with_options(fictionet::Seed::from_u64(0), Http1::new(page(2)), (), opts);
    let _ = h.push(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n\x00\x01 not http\r\n\r\n");
    let stopped = h
        .events()
        .iter()
        .find(|e| e.is("conn", "faults"))
        .expect("a conn.faults event");
    assert_eq!(stopped.str("stopped"), Some("failed"));
}

// ---------------------------------------------------------------------------
// HTTP/1 events and closes

/// A body of unknown length, in one frame.
struct Unsized(Option<Bytes>);

impl http_body::Body for Unsized {
    type Data = Bytes;
    type Error = fictionet::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, fictionet::Error>>> {
        Poll::Ready(self.get_mut().0.take().map(|b| Ok(Frame::data(b))))
    }
}

struct Streams;

impl Handler for Streams {
    fn call(&self, _: http::Request<Body>, _: &mut Exchange<'_>) -> Reply {
        Reply::Now(http::Response::new(Body::new(Unsized(Some(
            Bytes::from_static(b"streamed\n"),
        )))))
    }
}

#[test]
fn response_policy_agrees_across_native_and_hyper() {
    struct Responses;

    impl Handler for Responses {
        fn call(&self, request: http::Request<Body>, _: &mut Exchange<'_>) -> Reply {
            let status: u16 = request.uri().path()[1..].parse().unwrap();
            let bytes = Bytes::from_static(b"body");
            let body = if request.headers().contains_key("x-unknown") {
                Body::new(Unsized(Some(bytes)))
            } else {
                Body::from(bytes)
            };
            let mut response = http::Response::builder().status(status);
            if let Some(len) = request.headers().get("x-length") {
                response = response.header("content-length", len);
            }
            if let Some(date) = request.headers().get("x-date") {
                response = response.header("date", date);
            }
            Reply::Now(response.body(body).unwrap())
        }
    }

    world(Duration::from_secs(30), |fcx| async move {
        let (server, client) = two_machines(&fcx);
        let start = std::time::SystemTime::UNIX_EPOCH;
        let own_date = "Mon, 01 Jan 2001 00:00:00 GMT";
        for (port, date) in [(80, None), (81, Some(start))] {
            serve_http(
                &fcx,
                &server,
                port,
                Arc::new(Responses),
                HttpOptions {
                    date,
                    ..HttpOptions::default()
                },
            )?;
            for backend in ["native", "upgrade", "h2"] {
                // Method, status, unknown size, supplied length, wire lengths
                // (native HTTP/1, hyper HTTP/1, HTTP/2), and received body.
                for (method, status, unknown, given, lengths, body) in [
                    ("GET", 200, false, None, [Some("4"); 3], "body"),
                    ("GET", 200, true, None, [None; 3], "body"),
                    (
                        "GET",
                        200,
                        false,
                        Some("004"),
                        [Some("4"), Some("004"), Some("004")],
                        "body",
                    ),
                    ("HEAD", 200, false, None, [Some("4"); 3], ""),
                    ("HEAD", 200, false, Some("7"), [Some("7"); 3], ""),
                    ("HEAD", 200, true, None, [None; 3], ""),
                    ("HEAD", 200, true, Some("7"), [Some("7"); 3], ""),
                    ("GET", 204, false, None, [None; 3], ""),
                    ("GET", 304, false, None, [None; 3], ""),
                    ("HEAD", 304, false, None, [None; 3], ""),
                    ("GET", 304, false, Some("7"), [None, None, Some("7")], ""),
                ] {
                    for supplied_date in [false, true] {
                        let mut request = http::Request::builder()
                            .method(method)
                            .uri(format!("http://a.test/{status}"))
                            .header("host", "a.test");
                        if unknown {
                            request = request.header("x-unknown", "yes");
                        }
                        if let Some(len) = given {
                            request = request.header("x-length", len);
                        }
                        if supplied_date {
                            request = request.header("x-date", own_date);
                        }
                        if backend == "upgrade" {
                            request = request
                                .header("connection", "upgrade")
                                .header("upgrade", "websocket");
                        }
                        let request = request.body(Full::new(Bytes::new()))?;
                        let conn = client
                            .connect(&fcx, SocketAddr::new(SERVER.into(), port))
                            .await?;
                        let io = Io {
                            fcx: fcx.clone(),
                            conn,
                        };
                        let before = fcx.now();
                        let response = if backend == "h2" {
                            let (mut send, driving) =
                                hyper::client::conn::http2::handshake(Exec(fcx.clone()), io)
                                    .await?;
                            fcx.spawn(move |_| async move {
                                let _ = driving.await;
                                Ok(())
                            });
                            send.send_request(request).await?
                        } else {
                            let (mut send, driving) =
                                hyper::client::conn::http1::handshake(io).await?;
                            fcx.spawn(move |_| async move {
                                let _ = driving.await;
                                Ok(())
                            });
                            send.send_request(request).await?
                        };
                        let case = format!(
                            "{backend} {method} {status} unknown={unknown} length={given:?} date={date:?} supplied_date={supplied_date}"
                        );
                        assert_eq!(response.status(), status, "{case}");
                        let index = match backend {
                            "native" => 0,
                            "upgrade" => 1,
                            _ => 2,
                        };
                        assert_eq!(
                            response
                                .headers()
                                .get("content-length")
                                .map(|v| v.to_str().unwrap()),
                            lengths[index],
                            "{case}"
                        );
                        assert_eq!(
                            response.headers().contains_key("transfer-encoding"),
                            unknown && method == "GET" && backend != "h2",
                            "{case}"
                        );
                        let dates: Vec<_> = response.headers().get_all("date").iter().collect();
                        if supplied_date {
                            assert_eq!(dates, [own_date], "{case}");
                        } else if date.is_some() {
                            assert_eq!(dates.len(), 1, "{case}");
                            let earliest = httpd::date_header(date, before).unwrap();
                            let latest = httpd::date_header(date, fcx.now()).unwrap();
                            assert!(dates[0] == earliest || dates[0] == latest, "{case}");
                        } else {
                            assert!(dates.is_empty(), "{case}");
                        }
                        assert_eq!(
                            response.into_body().collect().await?.to_bytes(),
                            body,
                            "{case}"
                        );
                    }
                }
            }
        }
        Ok(())
    });
}

/// An HTTP/1.0 response of unknown length ends with the connection, even
/// when the client asked to keep it alive. Before, the connection stayed
/// open and the client waited for the end of the body until a timer
/// fired.
#[test]
fn an_http10_body_of_unknown_length_closes_the_connection() {
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(Streams), ());
    let reply = h
        .push(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
        .unwrap();
    let text = String::from_utf8(reply).unwrap();
    assert!(text.starts_with("HTTP/1.0 200 OK\r\n"), "{text}");
    assert!(
        !text.contains("content-length") && !text.contains("keep-alive"),
        "{text}"
    );
    assert!(text.ends_with("\r\n\r\nstreamed\n"), "{text}");
    assert_eq!(h.end_reason(), Some(Ended::Closed));

    // With a known length, the connection stays open.
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(page(3)), ());
    let reply = h
        .push(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
        .unwrap();
    assert!(
        String::from_utf8(reply)
            .unwrap()
            .contains("connection: keep-alive")
    );
    assert_eq!(h.end_reason(), None);
}

/// A request's event is made once its bytes are written, and says what
/// the connection took. Before, a buffered response was logged complete
/// as soon as it was made, even when the client reset the connection
/// before reading it.
#[test]
fn a_response_cut_off_by_a_reset_is_logged_incomplete() {
    world(Duration::from_secs(60), |fcx| async move {
        let (server, client) = two_machines(&fcx);
        let kept = fcx.events();
        let size = 8 << 20;
        serve_http(
            &fcx,
            &server,
            80,
            Arc::new(page(size)),
            HttpOptions::default(),
        )?;
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        conn.write_all(&fcx, b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
            .await?;
        let head = read_some(&fcx, &mut conn, 64).await;
        assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n"));
        conn.reset();
        let request = kept
            .wait(&fcx, 1, Duration::from_secs(10), |e| {
                e.is("http", "request")
            })
            .await?;
        let request = request.first().expect("an http.request event");
        assert_eq!(field_bool(request, "complete"), Some(false));
        assert!(field_u64(request, "sent").unwrap() < size as u64);

        // A response read to the end is complete.
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        conn.write_all(
            &fcx,
            b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n",
        )
        .await?;
        let mut all = Vec::new();
        let mut buf = vec![0u8; 64 << 10];
        loop {
            match conn.read(&fcx, &mut buf).await? {
                0 => break,
                n => all.extend_from_slice(&buf[..n]),
            }
        }
        assert!(all.len() > size);
        let done = kept
            .wait(&fcx, 2, Duration::from_secs(10), |e| {
                e.is("http", "request")
            })
            .await?;
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
    world(Duration::from_secs(60), |fcx| async move {
        let (server, client) = two_machines(&fcx);
        serve_http(&fcx, &server, 80, Arc::new(page(2)), HttpOptions::default())?;
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        conn.write_all(
            &fcx,
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00",
        )
        .await?;
        let mut got = read_some(&fcx, &mut conn, 9).await;
        assert_eq!(got[3], 4, "the first frame is SETTINGS");
        let len = usize::from(got[0]) << 16 | usize::from(got[1]) << 8 | usize::from(got[2]);
        if got.len() < 9 + len {
            let more = read_some(&fcx, &mut conn, 9 + len - got.len()).await;
            got.extend_from_slice(&more);
        }
        let settings: Vec<(u16, u32)> = got[9..9 + len]
            .chunks(6)
            .map(|s| {
                (
                    u16::from_be_bytes([s[0], s[1]]),
                    u32::from_be_bytes([s[2], s[3], s[4], s[5]]),
                )
            })
            .collect();
        assert!(settings.contains(&(3, 100)), "{settings:?}");
        Ok(())
    });
}

/// HTTP/2 applies the body limit, charges bodies to the budget, and draws
/// a handler's randomness from the run's stream, as HTTP/1 does.
#[test]
fn http2_has_the_limits_budget_and_seed_of_http1() {
    world::seeded_world(
        fictionet::Seed::from_u64(7),
        Duration::from_secs(60),
        |fcx| async move {
            let (server, client) = two_machines(&fcx);
            let kept = fcx.events();
            let router = Router::new()
                .get("/dice", |ex, _| {
                    http::Response::new(Bytes::from(ex.random_u64().to_string()))
                })
                .post("/echo", |_, request: http::Request<Bytes>| {
                    http::Response::new(request.into_body())
                });
            let opts = HttpOptions {
                limits: Limits {
                    body: 9000,
                    ..Limits::default()
                },
                budget: Some(Budget::new(8000)),
                ..HttpOptions::default()
            };
            serve_http(&fcx, &server, 80, Arc::new(router), opts)?;
            let conn = client
                .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
                .await?;
            let (mut send, driving) = hyper::client::conn::http2::handshake(
                Exec(fcx.clone()),
                Io {
                    fcx: fcx.clone(),
                    conn,
                },
            )
            .await?;
            fcx.spawn(move |_| async move {
                let _ = driving.await;
                Ok(())
            });
            let mut ask = async |method: http::Method,
                                 path: &str,
                                 body: Vec<u8>|
                   -> fictionet::Result<(u16, Bytes)> {
                send.ready().await?;
                let request = http::Request::builder()
                    .method(method)
                    .uri(format!("http://a.test{path}"))
                    .body(Full::new(Bytes::from(body)))?;
                let response = send.send_request(request).await?;
                let status = response.status().as_u16();
                Ok((status, response.into_body().collect().await?.to_bytes()))
            };

            let (status, body) = ask(http::Method::GET, "/dice", vec![]).await?;
            assert_eq!(status, 200);
            use fictionet::Entropy;
            let source = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(7));
            // Each of the two TCP endpoints takes its interface seed and port start.
            source.fill_random(&mut [0; 32]);
            let expected = source.random_u64();
            assert_eq!(body, expected.to_string());

            // Within the budget and the limit.
            let (status, body) = ask(http::Method::POST, "/echo", vec![b'a'; 1500]).await?;
            assert_eq!((status, body.len()), (200, 1500));
            // Within the limit, past the budget.
            let (status, _) = ask(http::Method::POST, "/echo", vec![b'b'; 7500]).await?;
            assert_eq!(status, 503);
            // Past the limit.
            let (status, _) = ask(http::Method::POST, "/echo", vec![b'c'; 9500]).await?;
            assert_eq!(status, 413);

            let events = kept
                .wait(&fcx, 4, Duration::from_secs(5), |e| e.is("http", "request"))
                .await?;
            let answers: Vec<_> = events
                .iter()
                .map(|e| e.str("answer").unwrap_or("").to_owned())
                .collect();
            assert_eq!(answers, ["handler", "handler", "budget", "too_large"]);
            Ok(())
        },
    );
}

#[test]
fn pending_http1_requests_keep_their_body_charge() {
    world(Duration::from_secs(10), |fcx| async move {
        let budget = Budget::new(1 << 20);
        let router = Router::new().route_async(None, "/", |fcx, request| async move {
            fcx.sleep(Duration::from_secs(1)).await.unwrap();
            assert_eq!(request.body().len(), 8192);
            http::Response::new(Bytes::new())
        });
        let mut h = Harness::with_options(
            fictionet::Seed::from_u64(0),
            Http1::new(router),
            (),
            ServeOptions::default().budget(budget.clone()),
        )
        .with_fcx(fcx.clone());
        h.open().unwrap();
        let base = budget.used();
        h.push(b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 8192\r\n\r\n")
            .unwrap();
        h.push(&[b'x'; 8192]).unwrap();
        assert_eq!(h.pending(), (1, 0));
        assert!(budget.used() >= base + 8192);
        fcx.sleep(Duration::from_secs(1)).await?;
        assert!(!h.poll().unwrap().is_empty());
        assert_eq!(h.pending(), (0, 0));
        assert_eq!(budget.used(), base);
        drop(h);
        assert_eq!(budget.used(), 0);
        Ok(())
    });
}

#[test]
fn truncated_http1_requests_keep_their_body_charge() {
    struct Partial;
    impl Handler for Partial {
        fn call(&self, request: http::Request<Body>, _: &mut Exchange<'_>) -> Reply {
            Reply::Later(Box::new(move |fcx| {
                Box::pin(async move {
                    fcx.sleep(Duration::from_secs(1)).await?;
                    assert!(request.into_body().collect().await.is_err());
                    Ok(http::Response::new(Body::empty()))
                })
            }))
        }
    }
    world(Duration::from_secs(10), |fcx| async move {
        let budget = Budget::new(1 << 20);
        let mut h = Harness::with_options(
            fictionet::Seed::from_u64(0),
            Http1::new(Partial),
            (),
            ServeOptions::default().budget(budget.clone()),
        )
        .with_fcx(fcx.clone());
        h.open().unwrap();
        let base = budget.used();
        h.push(b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 16384\r\n\r\n")
            .unwrap();
        h.push(&[b'x'; 8192]).unwrap();
        let _ = h.end();
        assert_eq!(h.pending(), (1, 0));
        assert!(budget.used() >= base + 8192);
        drop(h);
        assert_eq!(budget.used(), 0);
        Ok(())
    });
}

#[test]
fn http1_charges_heads_while_reading_and_metadata_while_waiting() {
    world(Duration::from_secs(10), |fcx| async move {
        let budget = Budget::new(1 << 20);
        let router = Router::new().route_async(None, "/", |fcx, request| async move {
            fcx.sleep(Duration::from_secs(1)).await.unwrap();
            assert_eq!(request.headers()["x-large"].as_bytes().len(), 4096);
            http::Response::new(Bytes::new())
        });
        let mut h = Harness::with_options(
            fictionet::Seed::from_u64(0),
            Http1::new(router),
            (),
            ServeOptions::default().budget(budget.clone()),
        )
        .with_fcx(fcx.clone());
        h.open().unwrap();
        let base = budget.used();
        let head = format!(
            "POST / HTTP/1.1\r\nHost: a.test\r\nX-Large: {}\r\nContent-Length: 1\r\n\r\n",
            "x".repeat(4096)
        );
        h.push(head.as_bytes()).unwrap();
        assert!(budget.used() >= base + 4096, "the head waits for the body");
        h.push(b"x").unwrap();
        assert_eq!(h.pending(), (1, 0));
        assert!(
            budget.used() >= base + 8192,
            "the handler and event each hold headers"
        );
        fcx.sleep(Duration::from_secs(1)).await?;
        assert!(!h.poll().unwrap().is_empty());
        assert_eq!(budget.used(), base);

        // Leave room for one head, but not its copy in the pending event.
        let other = budget.charge(budget.limit() - base - 6000).unwrap();
        assert!(h.push(head.as_bytes()).unwrap().is_empty());
        assert!(h.push(b"x").unwrap().is_empty());
        assert_eq!(h.end_reason(), Some(Ended::Budget));
        assert_eq!(h.pending(), (0, 0));
        drop(h);
        drop(other);
        assert_eq!(budget.used(), 0);
        Ok(())
    });
}

fn metadata_request() -> http::Request<Full<Bytes>> {
    http::Request::get("http://a.test/")
        .header("x-large", "x".repeat(4096))
        .body(Full::new(Bytes::new()))
        .unwrap()
}

struct WaitingMetadata;

impl Handler for WaitingMetadata {
    fn call(&self, request: http::Request<Body>, _: &mut Exchange<'_>) -> Reply {
        Reply::Later(Box::new(move |fcx| {
            Box::pin(async move {
                fcx.record(Event::new("test", "waiting"));
                std::future::pending::<()>().await;
                assert_eq!(request.headers()["x-large"].as_bytes().len(), 4096);
                Ok(http::Response::new(Body::empty()))
            })
        }))
    }
}

#[test]
fn http2_rejects_metadata_before_calling_the_handler() {
    world(Duration::from_secs(10), |fcx| async move {
        let (server, client) = two_machines(&fcx);
        let budget = Budget::new(1024);
        let router = Router::new().get("/", |_, _| panic!("metadata was not admitted"));
        serve_http(
            &fcx,
            &server,
            80,
            Arc::new(router),
            HttpOptions {
                budget: Some(budget.clone()),
                ..HttpOptions::default()
            },
        )?;
        let conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        let (mut send, driving) = hyper::client::conn::http2::handshake(
            Exec(fcx.clone()),
            Io {
                fcx: fcx.clone(),
                conn,
            },
        )
        .await?;
        fcx.spawn(move |_| async move {
            let _ = driving.await;
            Ok(())
        });
        assert!(send.send_request(metadata_request()).await.is_err());
        let events = fcx.events().of("http", "request");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].str("answer"), Some("budget"));
        assert_eq!(budget.used(), 0);
        Ok(())
    });
}

#[test]
fn http2_pending_metadata_releases_on_reset_and_region_cancellation() {
    world(Duration::from_secs(10), |fcx| async move {
        let budget = Budget::new(64 << 10);
        let shared = budget.clone();
        fcx.region(move |fcx| async move {
            let budget = shared;
            let (server, client) = two_machines(&fcx);
            serve_http(
                &fcx,
                &server,
                80,
                Arc::new(WaitingMetadata),
                HttpOptions {
                    budget: Some(budget.clone()),
                    ..HttpOptions::default()
                },
            )?;
            let conn = client
                .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
                .await?;
            let (mut send, driving) = hyper::client::conn::http2::handshake(
                Exec(fcx.clone()),
                Io {
                    fcx: fcx.clone(),
                    conn,
                },
            )
            .await?;
            fcx.spawn(move |_| async move {
                let _ = driving.await;
                Ok(())
            });
            let first = send.send_request(metadata_request());
            fcx.events()
                .wait(&fcx, 1, Duration::from_secs(1), |e| e.is("test", "waiting"))
                .await?;
            let one = budget.used();
            assert!(one >= 8192, "request and event headers both count");
            // Event timestamps can differ in size between requests.
            let other = budget.charge(budget.limit() - 2 * one - 1024).unwrap();
            let second = send.send_request(metadata_request());
            wait::until(&fcx, Duration::from_secs(1), || {
                fcx.events().of("test", "waiting").len() == 2
            })
            .await;
            let two = budget.used();
            assert!(two >= other.bytes() + 2 * 8192);
            assert!(send.send_request(metadata_request()).await.is_err());
            assert_eq!(fcx.events().of("test", "waiting").len(), 2);
            assert_eq!(budget.used(), two);

            drop(first);
            wait::until(&fcx, Duration::from_secs(1), || budget.used() == two - one).await;
            let third = send.send_request(metadata_request());
            wait::until(&fcx, Duration::from_secs(1), || {
                fcx.events().of("test", "waiting").len() == 3
            })
            .await;
            assert!(budget.used() >= other.bytes() + 2 * 8192);
            drop(other);
            fcx.cancel();
            fcx.cancelled().await;
            // Keep both response futures alive until the server region stops.
            let _keep = (second, third);
            Ok(())
        })
        .await?;
        assert_eq!(budget.used(), 0);
        Ok(())
    });
}

#[test]
fn http1_pending_metadata_releases_on_reset() {
    world(Duration::from_secs(10), |fcx| async move {
        let (server, client) = two_machines(&fcx);
        let budget = Budget::new(1 << 20);
        serve_http(
            &fcx,
            &server,
            80,
            Arc::new(WaitingMetadata),
            HttpOptions {
                budget: Some(budget.clone()),
                ..HttpOptions::default()
            },
        )?;
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        let head = format!(
            "GET / HTTP/1.1\r\nHost: a.test\r\nX-Large: {}\r\n\r\n",
            "x".repeat(4096)
        );
        conn.write_all(&fcx, head.as_bytes()).await?;
        fcx.events()
            .wait(&fcx, 1, Duration::from_secs(1), |e| e.is("test", "waiting"))
            .await?;
        assert!(budget.used() >= 8192);
        conn.reset();
        wait::until(&fcx, Duration::from_secs(1), || budget.used() == 0).await;
        assert_eq!(
            fcx.events().of("http", "request")[0].str("answer"),
            Some("cancelled")
        );
        Ok(())
    });
}

struct WaitingBody;

impl http_body::Body for WaitingBody {
    type Data = Bytes;
    type Error = fictionet::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Pending
    }
}

struct StreamingMetadata;

impl Handler for StreamingMetadata {
    fn call(&self, _: http::Request<Body>, _: &mut Exchange<'_>) -> Reply {
        Reply::Now(http::Response::new(Body::new(WaitingBody)))
    }
}

#[test]
fn request_events_stay_charged_while_responses_stream() {
    world(Duration::from_secs(10), |fcx| async move {
        let budget = Budget::new(1 << 20);
        let mut h = Harness::with_options(
            fictionet::Seed::from_u64(0),
            Http1::new(StreamingMetadata),
            (),
            ServeOptions::default().budget(budget.clone()),
        );
        h.open().unwrap();
        let base = budget.used();
        let head = format!(
            "GET / HTTP/1.1\r\nHost: a.test\r\nX-Large: {}\r\n\r\n",
            "x".repeat(4096)
        );
        assert!(
            h.push(head.as_bytes())
                .unwrap()
                .starts_with(b"HTTP/1.1 200")
        );
        assert_eq!(h.pending(), (1, 0));
        assert!(budget.used() >= base + 4096);
        assert!(!h.events().iter().any(|e| e.is("http", "request")));
        drop(h);
        assert_eq!(budget.used(), 0);

        let (server, client) = two_machines(&fcx);
        serve_http(
            &fcx,
            &server,
            80,
            Arc::new(StreamingMetadata),
            HttpOptions {
                budget: Some(budget.clone()),
                ..HttpOptions::default()
            },
        )?;
        let conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        let (mut send, driving) = hyper::client::conn::http2::handshake(
            Exec(fcx.clone()),
            Io {
                fcx: fcx.clone(),
                conn,
            },
        )
        .await?;
        fcx.spawn(move |_| async move {
            let _ = driving.await;
            Ok(())
        });
        let response = send.send_request(metadata_request()).await?;
        assert_eq!(response.status(), 200);
        assert!(budget.used() >= 4096);
        assert!(fcx.events().of("http", "request").is_empty());
        drop(response);
        wait::until(&fcx, Duration::from_secs(1), || budget.used() == 0).await;
        Ok(())
    });
}

#[test]
fn default_first_bytes_uses_the_header_deadline() {
    world(Duration::from_secs(10), |fcx| async move {
        let (server, client) = two_machines(&fcx);
        let opts = HttpOptions {
            limits: Limits {
                header_timeout: Duration::from_millis(100),
                ..Limits::default()
            },
            ..HttpOptions::default()
        };
        serve_http(&fcx, &server, 80, Arc::new(page(0)), opts)?;
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        let start = fcx.now();
        let result = fcx
            .race(
                Some(start + Duration::from_secs(1)),
                conn.read(&fcx, &mut [0; 1]),
            )
            .await;
        assert!(matches!(result, Ok(Ok(0))));
        assert!(fcx.now().since_start() - start.since_start() < Duration::from_secs(1));
        Ok(())
    });
}

#[test]
fn upgrade_keep_alive_preserves_line_limits() {
    world(Duration::from_secs(10), |fcx| async move {
        let (server, client) = two_machines(&fcx);
        let opts = HttpOptions {
            limits: Limits {
                head: fictionet::stdlib::http1::Limits {
                    header_line: 32,
                    ..Default::default()
                },
                ..Limits::default()
            },
            ..HttpOptions::default()
        };
        serve_http(&fcx, &server, 80, Arc::new(page(0)), opts)?;
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        conn.write_all(
            &fcx,
            b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await?;
        let response = read_some(&fcx, &mut conn, 1).await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        conn.write_all(&fcx, b"GET / HTTP/1.1\r\nHost: a.test\r\nX-Long: abcdefghijklmnopqrstuvwxyz0123456789\r\n\r\n").await?;
        let response = read_some(&fcx, &mut conn, 1).await;
        assert!(!response.starts_with(b"HTTP/1.1 200"));
        Ok(())
    });
}

#[test]
fn upgrade_keep_alive_preserves_header_timeout() {
    world(Duration::from_secs(10), |fcx| async move {
        let (server, client) = two_machines(&fcx);
        let opts = HttpOptions {
            limits: Limits {
                header_timeout: Duration::from_millis(100),
                ..Limits::default()
            },
            ..HttpOptions::default()
        };
        serve_http(&fcx, &server, 80, Arc::new(page(0)), opts)?;
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        conn.write_all(
            &fcx,
            b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await?;
        assert!(
            read_some(&fcx, &mut conn, 1)
                .await
                .starts_with(b"HTTP/1.1 200")
        );
        conn.write_all(&fcx, b"GET /").await?;
        let result = fcx
            .race(
                Some(fcx.now() + Duration::from_secs(1)),
                conn.read(&fcx, &mut [0; 1]),
            )
            .await;
        assert!(matches!(result, Ok(Ok(0))));
        Ok(())
    });
}

#[test]
fn peer_admission_is_shared_by_machines_and_dns() {
    world(Duration::from_secs(10), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        fictionet::stdlib::net::Net::new()
            .ipv4_only()
            .limits(fictionet::stdlib::net::Limits {
                connections_per_peer: 1,
                ..Default::default()
            })
            .host("one", |h| {
                h.at(Ipv4Addr::new(198, 18, 0, 2))
                    .tcp(7, Arc::new(()), || Loud { size: 1 })
            })
            .host("two", |h| {
                h.at(Ipv4Addr::new(198, 18, 0, 3))
                    .tcp(7, Arc::new(()), || Loud { size: 1 })
            })
            .start(&fcx, attachments)?;
        let m = fictionet::stdlib::sandbox::machine(
            &fcx,
            attacher.attach("a")?,
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let mut first = m.tcp.connect(&fcx, "198.18.0.2:7".parse()?).await?;
        first.write_all(&fcx, b"hello\n").await?;
        assert_eq!(read_some(&fcx, &mut first, 1).await, b"x");
        let mut second = m.tcp.connect(&fcx, "198.18.0.3:7".parse()?).await?;
        let result = fcx
            .race(
                Some(fcx.now() + Duration::from_secs(1)),
                second.read(&fcx, &mut [0; 1]),
            )
            .await;
        assert!(matches!(
            result,
            Ok(Err(fictionet::stdlib::ConnError::Reset))
        ));
        let mut dns = m.tcp.connect(&fcx, "10.0.0.1:53".parse()?).await?;
        let result = fcx
            .race(
                Some(fcx.now() + Duration::from_secs(1)),
                dns.read(&fcx, &mut [0; 1]),
            )
            .await;
        assert!(matches!(
            result,
            Ok(Err(fictionet::stdlib::ConnError::Reset))
        ));
        Ok(())
    });
}

#[test]
fn dns_tcp_uses_the_sandbox_service_budget() {
    world(Duration::from_secs(10), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        fictionet::stdlib::net::Net::new()
            .ipv4_only()
            .limits(fictionet::stdlib::net::Limits {
                sandbox_budget: 1,
                ..Default::default()
            })
            .start(&fcx, attachments)?;
        let m = fictionet::stdlib::sandbox::machine(
            &fcx,
            attacher.attach("a")?,
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let mut conn = m.tcp.connect(&fcx, "10.0.0.1:53".parse()?).await?;
        let result = fcx
            .race(
                Some(fcx.now() + Duration::from_secs(1)),
                conn.read(&fcx, &mut [0; 1]),
            )
            .await;
        assert!(matches!(result, Ok(Ok(0))));
        Ok(())
    });
}

#[test]
fn protocol_detection_does_not_restart_the_first_head_deadline() {
    world(Duration::from_secs(10), |fcx| async move {
        let (server, client) = two_machines(&fcx);
        let opts = HttpOptions {
            limits: Limits {
                header_timeout: Duration::from_millis(100),
                ..Limits::default()
            },
            ..HttpOptions::default()
        };
        serve_http(&fcx, &server, 80, Arc::new(page(0)), opts)?;
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        let start = fcx.now();
        fcx.sleep(Duration::from_millis(70)).await?;
        conn.write_all(&fcx, b"GET /").await?;
        let result = fcx
            .race(
                Some(start + Duration::from_millis(120)),
                conn.read(&fcx, &mut [0; 1]),
            )
            .await;
        assert!(matches!(result, Ok(Ok(0))));
        Ok(())
    });
}
