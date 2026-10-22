//! What a connection may hold and how long it may stall: the write side of
//! `serve` charged to the budget and given a deadline, HTTP/2 held to the
//! same limits, budget and seed as HTTP/1, and request events that say
//! what the connection took.

use crate::common::http_observer;
use crate::common::io;
use crate::common::world;
use crate::http2_server::H2_INPUT;

use fictionet_extras::hyper_io;
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
use fictionet::stdlib::codec::{Ending, ItemFault, LineError, Lines, Rewrite, Rule, Trigger, Wire};
use fictionet::stdlib::protocols::json;
use fictionet::stdlib::services::serve::{
    self, Budget, Ended, FaultPlan, Flow, Harness, Plan, ServeOptions,
};
use fictionet::stdlib::web::httpd::{
    self, Body, Exchange, Handler, Http1, HttpOptions, Limits, Reply, Router,
};
use fictionet::stdlib::{
    network::{Connection, ConnectionExt, ip, tcp},
    protocols::{hpack, http1, http2},
};
use fictionet::{Cx, pair};
use http_body::Frame;
use http_body_util::{BodyExt, Full};
use http_observer::{Exposure, SECRET, assert_redacted};
use hyper_util::rt::TokioIo;

fn idle_http2_budget(budget: &Budget) {
    assert_eq!(budget.used(), H2_INPUT);
}

async fn hyper_exposure(
    fcx: Cx,
    log: Arc<fictionet_observe::Memory>,
    received: httpd::Received,
    expected_status: u16,
) -> fictionet::Result {
    let (server, client) = two_machines(&fcx);
    let observer = Arc::new(Exposure::default());
    let router = Router::new().post("/login", move |_, _| {
        assert_eq!(
            received,
            httpd::Received::Complete,
            "rejected body reached handler"
        );
        http::Response::new(Bytes::new())
    });
    let budget = Budget::new(H2_INPUT + 8000);
    let opts = HttpOptions {
        limits: Limits {
            body: if received == httpd::Received::TooLarge {
                10
            } else {
                16000
            },
            body_timeout: Duration::from_secs(1),
            ..Limits::default()
        },
        budget: Some(budget.clone()),
        observe: Some(observer.clone()),
        ..HttpOptions::default()
    };
    serve_http(&fcx, &server, 80, Arc::new(router), opts)?;
    let conn = client
        .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
        .await?;
    let (mut send, driving) = h2::client::handshake(TokioIo::new(Io {
        fcx: fcx.clone(),
        conn,
    }))
    .await?;
    fcx.spawn(move |_| async move {
        driving.await?;
        Ok(())
    });
    let request = http::Request::post("http://Original.Test:80/login")
        .header("host", "different.test")
        .body(())?;
    let (response, mut stream) = send.send_request(request, false)?;
    let body = if received == httpd::Received::Budget {
        Bytes::from(vec![b'!'; 7500])
    } else if received == httpd::Received::TooLarge {
        Bytes::from_static(b"0123456789012345678!")
    } else {
        Bytes::from_static(SECRET)
    };
    let bytes = body.len();
    stream.send_data(body, received != httpd::Received::Timeout)?;
    let response = response.await?;
    assert_eq!(response.status().as_u16(), expected_status);
    let mut response_body = response.into_body();
    while let Some(data) = response_body.data().await {
        let data = data?;
        response_body.flow_control().release_capacity(data.len())?;
    }
    let events = log
        .wait(&fcx, 0, 1, Duration::from_secs(1), |e| {
            e.is("http", "request")
        })
        .await?;
    assert_eq!(
        *observer.ends.lock().unwrap(),
        [("/login".into(), bytes, received)]
    );
    let heads = observer.heads.lock().unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(
        heads[0].0.uri.authority().unwrap().as_str(),
        "Original.Test:80"
    );
    assert_eq!(heads[0].0.headers["host"], "different.test");
    assert_eq!(heads[0].0.version, http::Version::HTTP_2);
    assert_eq!(heads[0].1.id, Some(1));
    let event = &events[0];
    let answer = match received {
        httpd::Received::Complete => "handler",
        httpd::Received::TooLarge => "too_large",
        httpd::Received::Timeout => "timeout",
        httpd::Received::Budget => "budget",
        httpd::Received::CutOff => "cut_off",
    };
    assert_eq!(event.str("answer"), Some(answer));
    assert_eq!(
        event.str("received"),
        Some(if received == httpd::Received::Complete {
            "complete"
        } else {
            answer
        })
    );
    assert_eq!(field_bool(event, "classified"), Some(true));
    assert_redacted(event);
    idle_http2_budget(&budget);
    Ok(())
}

#[test]
fn observer_sees_no_host_body() {
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| async move {
        let (server, client) = two_machines(&fcx);
        let observer = Arc::new(Exposure::default());
        let hosts = httpd::VirtualHosts::new();
        hosts.set_default(httpd::VHost::new(Router::new().post("/login", |_, _| {
            panic!("request without a host reached handler")
        })));
        serve_http(
            &fcx,
            &server,
            80,
            Arc::new(hosts),
            HttpOptions {
                observe: Some(observer.clone()),
                ..HttpOptions::default()
            },
        )?;
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        // The h2 client requires an authority, so send the frames directly.
        let mut request = http2::PREFACE.to_vec();
        http2::Settings {
            flags: 0,
            entries: Vec::new(),
        }
        .write(&mut request)?;
        let mut fragment = Vec::new();
        hpack::Encoder::new(4096).encode_block(
            &[
                hpack::Field::new(":method", "POST"),
                hpack::Field::new(":scheme", "http"),
                hpack::Field::new(":path", "/login"),
            ],
            &mut fragment,
        )?;
        http2::Headers {
            stream: 1,
            flags: 4, // END_HEADERS, leaving the body open.
            fragment,
            priority: None,
            padding: None,
        }
        .write(&mut request)?;
        http2::Data {
            stream: 1,
            flags: 1, // END_STREAM.
            data: SECRET.to_vec(),
            padding: None,
        }
        .write(&mut request)?;
        conn.write_all(&fcx, &request).await?;
        let events = log
            .wait(&fcx, 0, 1, Duration::from_secs(1), |e| {
                e.is("http", "request")
            })
            .await?;
        let heads = observer.heads.lock().unwrap();
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].0.method, http::Method::POST);
        assert_eq!(heads[0].0.uri, "/login");
        assert_eq!(heads[0].0.version, http::Version::HTTP_2);
        assert!(heads[0].0.uri.authority().is_none());
        assert!(!heads[0].0.headers.contains_key("host"));
        assert_eq!(heads[0].1.id, Some(1));
        assert_eq!(
            *observer.ends.lock().unwrap(),
            [("/login".into(), SECRET.len(), httpd::Received::Complete)]
        );
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.str("answer"), Some("no_host"));
        assert_eq!(event.str("received"), Some("complete"));
        assert_eq!(event.u64("status"), Some(400));
        assert_eq!(event.str("source"), Some("observer"));
        assert_eq!(event.u64("observed_bytes"), Some(SECRET.len() as u64));
        assert_eq!(field_bool(event, "classified"), Some(true));
        assert_redacted(event);
        Ok(())
    });
}

#[test]
fn body_limit_exposure() {
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| {
        hyper_exposure(fcx, log, httpd::Received::TooLarge, 413)
    });
}

#[test]
fn partial_timeout_exposure() {
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| {
        hyper_exposure(fcx, log, httpd::Received::Timeout, 408)
    });
}

#[test]
fn hook_redacts_before_log() {
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| {
        hyper_exposure(fcx, log, httpd::Received::Complete, 200)
    });
}

#[test]
fn body_budget_exposure() {
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| {
        hyper_exposure(fcx, log, httpd::Received::Budget, 503)
    });
}

#[test]
fn observer_sees_metadata_budget_rejection() {
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| async move {
        let (server, client) = two_machines(&fcx);
        let observer = Arc::new(Exposure::default());
        let router = Router::new().get("/", |_, _| panic!("metadata was not admitted"));
        serve_http(
            &fcx,
            &server,
            80,
            Arc::new(router),
            HttpOptions {
                budget: Some(Budget::new(H2_INPUT + 1024)),
                observe: Some(observer.clone()),
                ..HttpOptions::default()
            },
        )?;
        let conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        let (mut send, driving) = h2::client::handshake(TokioIo::new(Io {
            fcx: fcx.clone(),
            conn,
        }))
        .await?;
        fcx.spawn(move |_| async move {
            driving.await?;
            Ok(())
        });
        let request = metadata_request().map(|_| ());
        let (response, _) = send.send_request(request, true)?;
        assert!(response.await.is_err());
        let events = log.checked_of("http", "request").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].str("answer"), Some("budget"));
        assert_eq!(events[0].str("received"), Some("budget"));
        assert_eq!(events[0].str("source"), Some("observer"));
        assert_eq!(observer.heads.lock().unwrap().len(), 1);
        assert_eq!(
            *observer.ends.lock().unwrap(),
            [("/".into(), 0, httpd::Received::Budget)]
        );
        Ok(())
    });
}

#[test]
fn observer_keeps_concurrent_request_identity() {
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| async move {
        let (server, client) = two_machines(&fcx);
        let observer = Arc::new(Exposure::default());
        let router = Router::new().post("/clean", |_, _| http::Response::new(Bytes::new()));
        serve_http(
            &fcx,
            &server,
            80,
            Arc::new(router),
            HttpOptions {
                observe: Some(observer.clone()),
                ..HttpOptions::default()
            },
        )?;
        let conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        let (mut send, driving) = h2::client::handshake(TokioIo::new(Io {
            fcx: fcx.clone(),
            conn,
        }))
        .await?;
        fcx.spawn(move |_| async move {
            driving.await?;
            Ok(())
        });
        let (cut_off, mut partial) = send.send_request(
            http::Request::post("http://a.test/private").body(())?,
            false,
        )?;
        partial.send_data(Bytes::from_static(SECRET), false)?;
        let (clean, _) =
            send.send_request(http::Request::post("http://a.test/clean").body(())?, true)?;
        assert_eq!(clean.await?.status(), 200);
        partial.send_reset(h2::Reason::CANCEL);
        assert!(cut_off.await.is_err());
        let events = log
            .wait(&fcx, 0, 2, Duration::from_secs(1), |e| {
                e.is("http", "request")
            })
            .await?;
        let clean = events
            .iter()
            .find(|e| e.str("path") == Some("/clean"))
            .unwrap();
        assert_eq!(clean.str("received"), Some("complete"));
        assert_eq!(field_bool(clean, "classified"), Some(false));
        let cut_off = events
            .iter()
            .find(|e| e.str("path") == Some("/private"))
            .unwrap();
        assert_eq!(cut_off.str("received"), Some("cut_off"));
        assert_eq!(field_bool(cut_off, "classified"), Some(true));
        assert_eq!(
            *observer.ends.lock().unwrap(),
            [
                ("/clean".into(), 0, httpd::Received::Complete),
                ("/private".into(), SECRET.len(), httpd::Received::CutOff),
            ]
        );
        Ok(())
    });
}

#[test]
fn observer_sees_upgrade_path_body_limit() {
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| async move {
        let (server, client) = two_machines(&fcx);
        let observer = Arc::new(Exposure::default());
        let router = Router::new().post("/", |_, _| panic!("oversized body reached handler"));
        serve_http(
            &fcx,
            &server,
            80,
            Arc::new(router),
            HttpOptions {
                limits: Limits {
                    body: 10,
                    ..Limits::default()
                },
                observe: Some(observer.clone()),
                ..HttpOptions::default()
            },
        )?;
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        conn.write_all(&fcx, b"POST / HTTP/1.1\r\nHost: a.test\r\nConnection: upgrade\r\nUpgrade: websocket\r\nContent-Length: 20\r\n\r\n01234567890123456789").await?;
        assert!(
            io::read_some(&fcx, &mut conn, 200)
                .await
                .starts_with(b"HTTP/1.1 413")
        );
        let events = log.checked_of("http", "request").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].str("answer"), Some("too_large"));
        assert_eq!(events[0].str("received"), Some("too_large"));
        assert_eq!(observer.heads.lock().unwrap().len(), 1);
        assert_eq!(
            *observer.ends.lock().unwrap(),
            [("/".into(), 20, httpd::Received::TooLarge)]
        );
        Ok(())
    });
}

#[cfg(feature = "tokio")]
#[test]
fn observer_sees_a_handed_off_request_once() {
    struct Echo;
    impl Handler for Echo {
        fn call(&self, request: http::Request<Body>, _: &mut Exchange<'_>) -> Reply {
            if request
                .extensions()
                .get::<hyper::upgrade::OnUpgrade>()
                .is_none()
            {
                return Reply::Handoff(request);
            }
            Reply::Now(http::Response::new(request.into_body()))
        }
    }
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| async move {
        let (server, client) = two_machines(&fcx);
        let observer = Arc::new(Exposure::default());
        serve_http(
            &fcx,
            &server,
            80,
            Arc::new(Echo),
            HttpOptions {
                observe: Some(observer.clone()),
                ..HttpOptions::default()
            },
        )?;
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        let mut request = format!(
            "POST /login HTTP/1.1\r\nHost: a.test\r\nConnection: upgrade\r\nUpgrade: websocket\r\nContent-Length: {}\r\n\r\n",
            SECRET.len()
        )
        .into_bytes();
        request.extend_from_slice(SECRET);
        conn.write_all(&fcx, &request).await?;
        let response = keep_alive_response(&fcx, &mut conn).await;
        assert_eq!(response.head.status, 200);
        assert_eq!(response.body, SECRET);
        log.wait(&fcx, 0, 1, Duration::from_secs(1), |e| {
            e.is("http", "request")
        })
        .await?;
        assert_eq!(observer.heads.lock().unwrap().len(), 1);
        assert_eq!(
            *observer.ends.lock().unwrap(),
            [("/login".into(), SECRET.len(), httpd::Received::Complete)]
        );
        let events = log.checked_of("http", "request").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].str("received"), Some("complete"));
        assert_eq!(
            field_u64(&events[0], "observed_bytes"),
            Some(SECRET.len() as u64)
        );
        assert_eq!(field_bool(&events[0], "classified"), Some(true));
        assert_redacted(&events[0]);
        Ok(())
    });
}

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
    let log = std::sync::Arc::new(fictionet_observe::Memory::default());
    let mut h = Harness::with_options(
        fictionet::Seed::from_u64(0),
        Http1::new(page(1 << 20)),
        (),
        opts,
    )
    .observer(log.clone());
    assert_eq!(
        h.push(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").unwrap(),
        b""
    );
    assert_eq!(h.end_reason(), Some(Ended::Budget));
    let request = log
        .checked_all()
        .unwrap()
        .iter()
        .find(|e| e.is("http", "request"))
        .expect("an http.request event")
        .clone();
    assert_eq!(request.str("answer"), Some("cancelled"));
    assert_eq!(field_u64(&request, "sent"), Some(0));
}

/// A write that takes no bytes for the write timeout ends the connection.
/// Before, the driver waited for ever on a client that stopped reading.
#[test]
fn a_client_that_stops_reading_times_out() {
    crate::common::world::observed_world(Duration::from_secs(60), |fcx, kept| async move {
        let (server, client) = two_machines(&fcx);
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
            .wait(&fcx, 0, 1, Duration::from_secs(10), |e| {
                e.is("conn", "close")
            })
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
    let log = std::sync::Arc::new(fictionet_observe::Memory::default());
    let mut h = Harness::with_options(fictionet::Seed::from_u64(0), Http1::new(page(2)), (), opts)
        .observer(log.clone());
    let _ = h.push(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n\x00\x01 not http\r\n\r\n");
    let stopped = log
        .checked_all()
        .unwrap()
        .iter()
        .find(|e| e.is("conn", "faults"))
        .expect("a conn.faults event")
        .clone();
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
            if request.headers().contains_key("upgrade")
                && request
                    .extensions()
                    .get::<hyper::upgrade::OnUpgrade>()
                    .is_none()
            {
                return Reply::Handoff(request);
            }
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
            // Only the `tokio` feature hands upgrade requests to hyper.
            let backends: &[&str] = if cfg!(feature = "tokio") {
                &["native", "upgrade", "h2"]
            } else {
                &["native", "h2"]
            };
            for &backend in backends {
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
        !text.contains("Content-Length") && !text.contains("keep-alive"),
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
            .contains("Connection: keep-alive")
    );
    assert_eq!(h.end_reason(), None);
}

/// A request's event is made once its bytes are written, and says what
/// the connection took. Before, a buffered response was logged complete
/// as soon as it was made, even when the client reset the connection
/// before reading it.
#[test]
fn a_response_cut_off_by_a_reset_is_logged_incomplete() {
    crate::common::world::observed_world(Duration::from_secs(60), |fcx, kept| async move {
        let (server, client) = two_machines(&fcx);
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
        let head = io::read_some(&fcx, &mut conn, 64).await;
        assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n"));
        conn.reset();
        let request = kept
            .wait(&fcx, 0, 1, Duration::from_secs(10), |e| {
                e.is("http", "request")
            })
            .await?;
        let request = request.first().expect("an http.request event").clone();
        assert_eq!(field_bool(&request, "complete"), Some(false));
        assert!(field_u64(&request, "sent").unwrap() < size as u64);

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
            .wait(&fcx, 0, 2, Duration::from_secs(10), |e| {
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
        let mut got = io::read_some(&fcx, &mut conn, 9).await;
        assert_eq!(got[3], 4, "the first frame is SETTINGS");
        let len = usize::from(got[0]) << 16 | usize::from(got[1]) << 8 | usize::from(got[2]);
        if got.len() < 9 + len {
            let more = io::read_some(&fcx, &mut conn, 9 + len - got.len()).await;
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
    let log = Arc::new(fictionet_observe::Memory::default());
    world::seeded_world(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(log.clone()),
        Duration::from_secs(60),
        move |fcx| async move {
            let (server, client) = two_machines(&fcx);
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
                budget: Some(Budget::new(H2_INPUT + 8000)),
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

            let events = log
                .wait(&fcx, 0, 4, Duration::from_secs(5), |e| {
                    e.is("http", "request")
                })
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
                fcx.emit("test", "waiting", |event| event);
                std::future::pending::<()>().await;
                assert_eq!(request.headers()["x-large"].as_bytes().len(), 4096);
                Ok(http::Response::new(Body::empty()))
            })
        }))
    }
}

#[test]
fn http2_rejects_metadata_before_calling_the_handler() {
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| async move {
        let (server, client) = two_machines(&fcx);
        let budget = Budget::new(H2_INPUT + 1024);
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
        let events = log.checked_of("http", "request").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].str("answer"), Some("budget"));
        idle_http2_budget(&budget);
        Ok(())
    });
}

#[test]
fn http2_pending_metadata_releases_on_reset_and_region_cancellation() {
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| async move {
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
            log.wait(&fcx, 0, 1, Duration::from_secs(1), |e| {
                e.is("test", "waiting")
            })
            .await?;
            let one = budget.used();
            assert!(one >= 8192, "request and event headers both count");
            // Event timestamps can differ in size between requests.
            let other = budget
                .charge(budget.limit() - one - (one - H2_INPUT) - 1024)
                .unwrap();
            let second = send.send_request(metadata_request());
            assert_eq!(
                log.wait(&fcx, 0, 2, Duration::from_secs(1), |e| e
                    .is("test", "waiting"))
                    .await?
                    .len(),
                2
            );
            let two = budget.used();
            assert!(two >= other.bytes() + 2 * 8192);
            assert!(send.send_request(metadata_request()).await.is_err());
            assert_eq!(log.checked_of("test", "waiting").unwrap().len(), 2);
            let rejected = budget.used();
            assert_eq!(rejected, two);
            let request_charge = two - one - other.bytes();

            drop(first);
            fcx.idle().await?;
            assert_eq!(budget.used(), rejected - request_charge);
            let third = send.send_request(metadata_request());
            assert_eq!(
                log.wait(&fcx, 0, 3, Duration::from_secs(1), |e| e
                    .is("test", "waiting"))
                    .await?
                    .len(),
                3
            );
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
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| async move {
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
        log.wait(&fcx, 0, 1, Duration::from_secs(1), |e| {
            e.is("test", "waiting")
        })
        .await?;
        assert!(budget.used() >= 8192);
        conn.reset();
        fcx.idle().await?;
        assert_eq!(budget.used(), 0);
        assert_eq!(
            log.checked_of("http", "request").unwrap()[0].str("answer"),
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
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| async move {
        let budget = Budget::new(1 << 20);
        let harness_log = std::sync::Arc::new(fictionet_observe::Memory::default());
        let mut h = Harness::with_options(
            fictionet::Seed::from_u64(0),
            Http1::new(StreamingMetadata),
            (),
            ServeOptions::default().budget(budget.clone()),
        )
        .observer(harness_log.clone());
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
        assert!(
            !harness_log
                .checked_all()
                .unwrap()
                .iter()
                .any(|e| e.is("http", "request"))
        );
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
        assert!(log.checked_of("http", "request").unwrap().is_empty());
        drop(response);
        fcx.idle().await?;
        idle_http2_budget(&budget);
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

/// Reads one Content-Length response without consuming the next response.
async fn keep_alive_response(fcx: &Cx, conn: &mut impl Connection) -> http1::Response {
    let deadline = fcx.now() + Duration::from_secs(1);
    let mut bytes = io::read_until_async(fcx, conn, deadline, b"\r\n\r\n")
        .await
        .expect("complete response head");
    let (head, _) = http1::ResponseHead::parse_lenient(&bytes)
        .unwrap()
        .expect("response head");
    let length = head
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))
        .expect("keep-alive response declares its length");
    let length: usize = std::str::from_utf8(&length.value).unwrap().parse().unwrap();
    fcx.race(Some(deadline), async {
        let end = bytes.len() + length;
        let mut buf = [0; 4096];
        while bytes.len() < end {
            let want = buf.len().min(end - bytes.len());
            let n = conn.read(fcx, &mut buf[..want]).await.unwrap();
            assert_ne!(n, 0, "EOF before response body ends");
            bytes.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .expect("complete response body");
    fictionet_test_support::response(&bytes, "GET", false)
}

/// Requires a successful keep-alive request before rejecting an over-long
/// header, on hyper's upgrade path.
#[cfg(feature = "tokio")]
async fn upgrade_keep_alive_line_limit(
    fcx: &Cx,
    log: &fictionet_observe::Memory,
) -> fictionet::Result {
    let (server, client) = two_machines(fcx);
    let opts = HttpOptions {
        limits: Limits {
            head: fictionet::stdlib::protocols::http1::Limits {
                header_line: 32,
                ..Default::default()
            },
            ..Limits::default()
        },
        ..HttpOptions::default()
    };
    struct UpgradePage;
    impl Handler for UpgradePage {
        fn call(&self, request: http::Request<Body>, ex: &mut Exchange<'_>) -> Reply {
            if request.headers().contains_key("upgrade")
                && request
                    .extensions()
                    .get::<hyper::upgrade::OnUpgrade>()
                    .is_none()
            {
                return Reply::Handoff(request);
            }
            page(4).call(request, ex)
        }
    }
    serve_http(fcx, &server, 80, Arc::new(UpgradePage), opts)?;
    let mut conn = client
        .connect(fcx, SocketAddr::new(SERVER.into(), 80))
        .await?;
    conn.write_all(
        fcx,
        b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
    )
    .await?;
    let response = keep_alive_response(fcx, &mut conn).await;
    assert_eq!(response.head.status, 200);
    assert_eq!(response.body, b"xxxx");
    conn.write_all(
        fcx,
        b"GET / HTTP/1.1\r\nHost: a.test\r\nX-Long: short\r\n\r\n",
    )
    .await?;
    let response = keep_alive_response(fcx, &mut conn).await;
    assert_eq!(response.head.status, 200);
    assert_eq!(response.body, b"xxxx");
    conn.write_all(
        fcx,
        b"GET / HTTP/1.1\r\nHost: a.test\r\nX-Long: abcdefghijklmnopqrstuvwxyz0123456789\r\n\r\n",
    )
    .await?;
    let result = fcx
        .race(
            Some(fcx.now() + Duration::from_secs(1)),
            conn.read(fcx, &mut [0; 1]),
        )
        .await;
    // The upgrade path rejects the head by closing without a status response.
    assert_eq!(result, Ok(Ok(0)));
    assert_eq!(log.checked_of("http", "request").unwrap().len(), 2);
    Ok(())
}

#[cfg(feature = "tokio")]
#[test]
fn upgrade_keep_alive_preserves_line_limits() {
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| async move {
        upgrade_keep_alive_line_limit(&fcx, &log).await
    });
}

#[cfg(feature = "tokio")]
#[test]
fn upgrade_keep_alive_line_limit_rejection_records_protocol_error() {
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, log| async move {
        upgrade_keep_alive_line_limit(&fcx, &log).await?;
        let errors = log.checked_of("http", "error").unwrap();
        assert_eq!(errors.len(), 1, "missing limit rejection event");
        assert_eq!(errors[0].str("cause"), Some("protocol"));
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
        serve_http(&fcx, &server, 80, Arc::new(page(4)), opts)?;
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        conn.write_all(
            &fcx,
            b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await?;
        let response = keep_alive_response(&fcx, &mut conn).await;
        assert_eq!(response.head.status, 200);
        assert_eq!(response.body, b"xxxx");
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
fn silent_limit_failure() {
    world(Duration::from_secs(10), |fcx| async move {
        let (server, client) = two_machines(&fcx);
        let mut listener = server.listen(80)?;
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        let _peer = listener.accept(&fcx).await?;
        let result = fcx
            .race(
                Some(fcx.now() + Duration::from_secs(1)),
                conn.read(&fcx, &mut [0; 1]),
            )
            .await;
        // Silence is a deadline, not the EOF required for limit rejection.
        assert_eq!(result, Err(fictionet::RaceError::Deadline));
        Ok(())
    });
}

#[test]
fn partial_200_not_rejection() {
    world(Duration::from_secs(10), |fcx| async move {
        for bytes in [
            b"H".as_slice(),
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n\r\nx",
        ] {
            let (server, client) = two_machines(&fcx);
            let mut listener = server.listen(80)?;
            fcx.spawn(move |fcx| async move {
                let mut peer = listener.accept(&fcx).await?;
                peer.write_all(&fcx, bytes).await?;
                peer.shutdown(&fcx).await?;
                Ok(())
            });
            let mut conn = client
                .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
                .await?;
            let mut first = [0; 1];
            let result = fcx
                .race(
                    Some(fcx.now() + Duration::from_secs(1)),
                    conn.read(&fcx, &mut first),
                )
                .await;
            // A response byte, including a non-200 status, is not rejection EOF.
            assert_eq!(result, Ok(Ok(1)));
            assert_eq!(first, [b'H']);
            let mut got = first.to_vec();
            got.extend(
                io::read_to_end(&fcx, &mut conn, fcx.now() + Duration::from_secs(1)).await??,
            );
            assert_eq!(got, bytes);
            assert_eq!(
                http1::Response::parse_for(&got, "GET"),
                Err(http1::Error::Incomplete)
            );
        }
        Ok(())
    });
}

#[test]
fn peer_admission_is_shared_by_machines_and_dns() {
    world(Duration::from_secs(10), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        fictionet::stdlib::world::net::Net::new()
            .ipv4_only()
            .limits(fictionet::stdlib::world::net::Limits {
                connections_per_peer: 1,
                ..Default::default()
            })
            .host("one", |h| {
                h.at(Ipv4Addr::new(104, 18, 0, 2))
                    .tcp(7, Arc::new(()), || Loud { size: 1 })
            })
            .host("two", |h| {
                h.at(Ipv4Addr::new(104, 18, 0, 3))
                    .tcp(7, Arc::new(()), || Loud { size: 1 })
            })
            .start(&fcx, attachments)?;
        let m = fictionet::stdlib::world::sandbox::machine(
            &fcx,
            attacher.attach("a")?,
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let mut first = m.tcp.connect(&fcx, "104.18.0.2:7".parse()?).await?;
        first.write_all(&fcx, b"hello\n").await?;
        assert_eq!(io::read_some(&fcx, &mut first, 1).await, b"x");
        let mut second = m.tcp.connect(&fcx, "104.18.0.3:7".parse()?).await?;
        let result = fcx
            .race(
                Some(fcx.now() + Duration::from_secs(1)),
                second.read(&fcx, &mut [0; 1]),
            )
            .await;
        assert!(matches!(
            result,
            Ok(Err(fictionet::stdlib::network::ConnError::Reset))
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
            Ok(Err(fictionet::stdlib::network::ConnError::Reset))
        ));
        Ok(())
    });
}

#[test]
fn dns_tcp_uses_the_sandbox_service_budget() {
    world(Duration::from_secs(10), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        fictionet::stdlib::world::net::Net::new()
            .ipv4_only()
            .limits(fictionet::stdlib::world::net::Limits {
                sandbox_budget: 1,
                ..Default::default()
            })
            .start(&fcx, attachments)?;
        let m = fictionet::stdlib::world::sandbox::machine(
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
