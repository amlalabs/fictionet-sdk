use super::*;
use fictionet::Seed;
use fictionet::stdlib::layer::{Harness, Switch};
use fictionet::stdlib::services::stack::{StackError, Tunnel};
use fictionet::time::Instant;

// ---------------------------------------------------------------------------
// The harness

/// A stack's replies must not depend on how the client's bytes were cut
/// into chunks: every split of the input gives the same output.
#[test]
fn replies_do_not_depend_on_chunk_boundaries() {
    let mut input = Vec::new();
    input.extend(mb(
        1,
        MbRequest::WriteSingleRegister {
            address: 2,
            value: 77,
        },
    ));
    input.extend(mb(
        2,
        MbRequest::ReadHoldingRegisters {
            address: 0,
            quantity: 4,
        },
    ));
    input.extend(mb(
        3,
        MbRequest::ReadHoldingRegisters {
            address: 15,
            quantity: 2,
        },
    ));
    input.extend(mb(
        4,
        MbRequest::WriteSingleCoil {
            address: 1,
            value: true,
        },
    ));
    let plant = || {
        Arc::new(Plant {
            limit: 1000,
            ..Plant::default()
        })
    };
    let whole = {
        let mut h = Harness::new(Seed::from_u64(0), Plc::stack(plant()));
        h.push(&input).unwrap();
        h.output().to_vec()
    };
    assert!(!whole.is_empty());
    for a in 0..input.len() {
        for b in a..input.len() {
            let mut h = Harness::new(Seed::from_u64(0), Plc::stack(plant()));
            for chunk in [&input[..a], &input[a..b], &input[b..]] {
                h.push(chunk).unwrap();
            }
            assert_eq!(h.output(), whole, "split at {a} and {b}");
        }
    }
    // The same for HTTP/1 with a router.
    let router = || {
        fictionet_test_support::handler(
            |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>, r: http::Request<Bytes>| {
                http::Response::new(r.into_body())
            },
        )
    };
    let input = b"POST /e HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabcPOST /e HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nxy\r\n0\r\n\r\n";
    let whole = {
        let mut h = layer::Harness::new(Seed::from_u64(0), Http1::new(router()))
            .with_worker(Polling::new());
        h.push(input).unwrap();
        h.output().to_vec()
    };
    for a in 0..input.len() {
        let mut h = layer::Harness::new(Seed::from_u64(0), Http1::new(router()))
            .with_worker(Polling::new());
        h.push(&input[..a]).unwrap();
        h.push(&input[a..]).unwrap();
        assert_eq!(h.output(), whole, "split at {a}");
    }
}

// ---------------------------------------------------------------------------
// The runner, over TCP

#[test]
fn a_listener_serves_each_connection() {
    world(Duration::from_secs(60), |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        line_stack::listen(
            &fcx,
            server.listen(7)?,
            StreamLimits::default(),
            Echo::stack,
        );
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 7))
            .await?;
        assert_eq!(read_some(&fcx, &mut conn, 6).await, b"hello\n");
        conn.write_all(&fcx, b"one\nlater\ntwo\n").await?;
        // The answer from work comes in order, between the two echoes.
        assert_eq!(read_some(&fcx, &mut conn, 14).await, b"one\nlater\ntwo\n");
        conn.write_all(&fcx, b"quit\n").await?;
        assert_eq!(read_some(&fcx, &mut conn, 100).await, b"bye\n");
        Ok(())
    });
}

#[test]
fn timers_tick_and_idle_connections_close() {
    world(Duration::from_secs(60), |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        line_stack::listen(&fcx, server.listen(1)?, StreamLimits::default(), || {
            Lined::new(Ticker::default())
        });
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 1))
            .await?;
        let started = fcx.now();
        assert_eq!(read_some(&fcx, &mut conn, 100).await, b"tick\ntick\ntick\n");
        assert!(fcx.now().since_start() - started.since_start() >= Duration::from_millis(90));

        let limits = StreamLimits {
            idle: Some(Duration::from_millis(100)),
            ..StreamLimits::default()
        };
        line_stack::listen(&fcx, server.listen(2)?, limits, Echo::stack);
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 2))
            .await?;
        assert_eq!(read_some(&fcx, &mut conn, 6).await, b"hello\n");
        let started = fcx.now();
        // The stack hears an idle client as one that ended its direction,
        // answers that, and the connection closes.
        assert_eq!(read_some(&fcx, &mut conn, 4).await, b"eof\n");
        assert_eq!(
            fcx.now().since_start() - started.since_start(),
            Duration::from_millis(100)
        );
        assert_eq!(conn.read(&fcx, &mut [0; 1]).await?, 0);
        Ok(())
    });
}

/// The echo, switching to `then` on `handoff`.
type Switching = Switch<Lined<Echo>, Tunnel>;

fn switching(then: echo_stack::Then) -> Switching {
    Switch::new(Lined::new(Echo { then: Some(then) }))
}

#[test]
fn a_handover_gives_the_next_protocol_the_unread_bytes() {
    world(Duration::from_secs(60), |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        let (tx, rx) = mpsc::channel();
        let tx = Arc::new(Mutex::new(tx));
        let then: echo_stack::Then = Arc::new(move || {
            let tx = tx.clone();
            Tunnel::new(move |fcx, mut rest| async move {
                let mut unread = [0; 3];
                let mut got = 0;
                while got < unread.len() {
                    match rest.read(&fcx, &mut unread[got..]).await {
                        Ok(n) if n > 0 => got += n,
                        _ => return,
                    }
                }
                let _ = tx.lock().unwrap().send(unread.to_vec());
                // What follows is the next protocol's: here, raw bytes.
                let _ = rest.write_all(&fcx, b"upgraded\n").await;
            })
        });
        line_stack::listen(
            &fcx,
            server.listen(25)?,
            StreamLimits::default(),
            move || switching(then.clone()),
        );
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 25))
            .await?;
        conn.write_all(&fcx, b"handoff\n\x16\x03\x01").await?;
        assert_eq!(read_some(&fcx, &mut conn, 15).await, b"hello\nupgraded\n");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            b"\x16\x03\x01"
        );
        Ok(())
    });
}

#[test]
fn a_connection_cap_resets_connections_past_it() {
    let addr = Ipv4Addr::new(10, 40, 0, 9);
    world(Duration::from_secs(60), move |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("svc", |h| {
                h.at(addr)
                    .tcp_stack_with(7, StreamLimits::default(), 2, |_| Echo::stack())
            })
            .start(&fcx, attachments)?;
        let s = machine(&fcx, attacher.attach("agent")?, ME);
        let to = SocketAddr::new(addr.into(), 7);
        let mut a = s.tcp.connect(&fcx, to).await?;
        let mut b = s.tcp.connect(&fcx, to).await?;
        assert_eq!(read_some(&fcx, &mut a, 6).await, b"hello\n");
        assert_eq!(read_some(&fcx, &mut b, 6).await, b"hello\n");
        let mut c = s.tcp.connect(&fcx, to).await?;
        let mut buf = [0u8; 16];
        let r = timeout(&fcx, Duration::from_secs(2), c.read(&fcx, &mut buf))
            .await
            .expect("an answer");
        assert!(matches!(r, Err(ConnError::Reset) | Ok(0)), "{r:?}");
        Ok(())
    });
}

/// Answers a datagram of lines with their count so far, in one datagram.
struct Count {
    seen: usize,
    answer: Vec<u8>,
}

impl DatagramApp for Count {
    type Timer = ();

    fn line(&mut self, _: Result<Vec<u8>, LineError>, _: SocketAddr, _: &mut Sends<'_, ()>) {
        self.seen += 1;
        self.answer
            .extend_from_slice(format!("{};", self.seen).as_bytes());
    }

    fn finished(&mut self, from: SocketAddr, sends: &mut Sends<'_, ()>) {
        sends.send_to(from, std::mem::take(&mut self.answer));
    }
}

#[test]
fn the_datagram_runner_answers_each_datagram() {
    world(Duration::from_secs(60), |fcx| async move {
        let (_s, server, _c, client) = two_machines(&fcx);
        let socket = server.bind(9)?;
        fcx.spawn(move |fcx| async move {
            let local = SocketAddr::new(SERVER.into(), 9);
            let count = Count {
                seen: 0,
                answer: Vec::new(),
            };
            let stack = Datagrammed::new(count, Some(local));
            let budget = Budget::unlimited();
            let _ = stack::datagrams(&fcx, socket, local, stack, budget, |_| {}).await;
            Ok(())
        });
        let mut s = client.bind(4000)?;
        s.send_to(b"a\nb\n", SocketAddr::new(SERVER.into(), 9));
        let (got, _) = s.recv(&fcx).await?;
        assert_eq!(got, b"1;2;");
        s.send_to(b"c\n", SocketAddr::new(SERVER.into(), 9));
        assert_eq!(s.recv(&fcx).await?.0, b"3;");
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// The tower adapter

#[test]
fn a_tower_service_runs_as_a_handler() {
    world(Duration::from_secs(60), |fcx| async move {
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "from axum\n" }))
            .route(
                "/len",
                axum::routing::post(|body: Bytes| async move { format!("{}\n", body.len()) }),
            );
        let (server, _su, client, _cu) = two_machines(&fcx);
        let mut listener = server.listen(80)?;
        fcx.spawn(move |fcx| async move {
            while let Ok(conn) = listener.accept(&fcx).await {
                let handler: Arc<dyn httpd::Handler> = Arc::new(httpd::tower(app.clone()));
                let info = ConnInfo::new(1, conn.local_addr(), conn.peer_addr());
                fcx.spawn(move |fcx| async move {
                    Ok(httpd::serve_connection(
                        &fcx,
                        conn,
                        info,
                        handler,
                        &httpd::HttpOptions::default(),
                    )
                    .await?)
                });
            }
            Ok(())
        });
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        conn.write_all(&fcx, b"GET / HTTP/1.1\r\nHost: a\r\n\r\nPOST /len HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello").await?;
        let text = String::from_utf8(read_some(&fcx, &mut conn, 1 << 16).await).unwrap();
        let answers: Vec<&str> = text.split("HTTP/1.1 200 OK").skip(1).collect();
        assert_eq!(answers.len(), 2, "{text}");
        assert!(answers[0].ends_with("\r\n\r\nfrom axum\n"));
        assert!(answers[1].ends_with("\r\n\r\n5\n"));
        Ok(())
    });
}

/// Echo on 16-byte lines.
struct Short;

impl LineApp for Short {
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Next = Infallible;
    type Error = Infallible;

    fn max_line(&self) -> usize {
        16
    }

    fn line(
        &mut self,
        line: Result<Vec<u8>, LineError>,
        out: &mut LineOut<'_, Self>,
    ) -> Result<(), Infallible> {
        match line {
            Ok(line) => out.write(&[line.as_slice(), b"\n"].concat()),
            Err(_) => out.write(b"long\n"),
        }
        Ok(())
    }
}

/// A reader that skips a long run of bytes is making progress: the
/// connection stays open, in the harness and over TCP.
#[test]
fn a_reader_that_skips_a_long_line_keeps_the_connection_open() {
    let mut input = vec![b'x'; 100];
    input.extend_from_slice(b"\nok\n");
    let mut h = Harness::new(Seed::from_u64(0), Lined::new(Short));
    h.push(&input).unwrap();
    assert_eq!(h.output(), b"long\nok\n");
    assert!(!h.ended() && !h.input_closed());
    world(Duration::from_secs(60), move |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        line_stack::listen(&fcx, server.listen(7)?, StreamLimits::default(), || {
            Lined::new(Short)
        });
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 7))
            .await?;
        conn.write_all(&fcx, &input).await?;
        assert_eq!(read_some(&fcx, &mut conn, 8).await, b"long\nok\n");
        Ok(())
    });
}

/// The harness runs a stack's work, and a switch runs the protocol the
/// stack handed over to, with the bytes read past the handover.
#[test]
fn the_harness_runs_work_and_switches_protocols() {
    world(Duration::from_secs(60), |fcx| async move {
        let then: echo_stack::Then = Arc::new(|| {
            Tunnel::new(|fcx, rest| async move {
                // The next protocol keeps the connection.
                let _ = fcx.cancelled().await;
                drop(rest);
            })
        });
        let mut h = Harness::new(Seed::from_u64(0), switching(then))
            .with_worker(Polling::in_world(fcx.clone()));
        h.push(b"one\nlater\ntwo\n").unwrap();
        assert_eq!(
            String::from_utf8_lossy(&h.take_output()),
            "hello\none\nlater\ntwo\n"
        );
        h.push(b"handoff\nrest").unwrap();
        assert!(h.layer().then().is_some(), "the tunnel runs");
        assert!(h.layer().first().is_none(), "the echo is gone");
        assert_eq!(h.unread(), 0, "the tunnel took the rest");
        assert!(!h.ended(), "a handover is not a close");
        Ok(())
    });
}

/// Subscribers to fills, each with where to send its fills.
type Book = Arc<Mutex<Vec<tokio::sync::mpsc::UnboundedSender<String>>>>;

/// Waits for the next fill sent to one subscriber.
struct NextFill(tokio::sync::mpsc::UnboundedReceiver<String>);

impl Job for NextFill {
    type Done = (Option<String>, tokio::sync::mpsc::UnboundedReceiver<String>);

    fn poll(&mut self, _: Option<&Cx>, cx: &mut Context<'_>) -> Poll<Self::Done> {
        match self.0.poll_recv(cx) {
            Poll::Ready(fill) => {
                let (_, empty) = tokio::sync::mpsc::unbounded_channel();
                Poll::Ready((fill, std::mem::replace(&mut self.0, empty)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// `sub` subscribes the connection to fills; `fill X` sends X to every
/// subscriber, from this connection, and the others' work wakes for it.
struct Trader(Book);

impl LineApp for Trader {
    type Timer = ();
    type Work = NextFill;
    type Done = (Option<String>, tokio::sync::mpsc::UnboundedReceiver<String>);
    type Next = Infallible;
    type Error = Infallible;

    fn line(
        &mut self,
        line: Result<Vec<u8>, LineError>,
        out: &mut LineOut<'_, Self>,
    ) -> Result<(), Infallible> {
        let line = String::from_utf8(line.unwrap_or_default()).unwrap_or_default();
        if line == "sub" {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            self.0.lock().unwrap().push(tx);
            out.start(NextFill(rx));
            out.write(b"subscribed\n");
        } else if let Some(fill) = line.strip_prefix("fill ") {
            let mut subscribers = self.0.lock().unwrap();
            subscribers.retain(|tx| tx.send(fill.to_owned()).is_ok());
            out.write(b"ok\n");
        }
        Ok(())
    }

    fn done(&mut self, done: Self::Done, out: &mut LineOut<'_, Self>) -> Result<(), Infallible> {
        let (fill, rx) = done;
        if let Some(fill) = fill {
            out.write(format!("execution {fill}\n").as_bytes());
            out.start(NextFill(rx));
        }
        Ok(())
    }
}

#[test]
fn another_connection_wakes_a_stack_to_push_a_fill() {
    let book = Book::default();
    let mut h = Harness::new(Seed::from_u64(0), Lined::new(Trader(book.clone())))
        .with_worker(Polling::new());
    h.push(b"sub\n").unwrap();
    assert_eq!(h.take_output(), b"subscribed\n");
    book.lock().unwrap()[0].send("7@100".into()).unwrap();
    h.settle().unwrap();
    assert_eq!(h.take_output(), b"execution 7@100\n");

    world(Duration::from_secs(60), |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        let book = Book::default();
        line_stack::listen(
            &fcx,
            server.listen(9000)?,
            StreamLimits::default(),
            move || Lined::new(Trader(book.clone())),
        );
        let to = SocketAddr::new(SERVER.into(), 9000);
        let mut a = client.connect(&fcx, to).await?;
        a.write_all(&fcx, b"sub\n").await?;
        assert_eq!(read_some(&fcx, &mut a, 11).await, b"subscribed\n");
        let mut b = client.connect(&fcx, to).await?;
        b.write_all(&fcx, b"fill 5@99\n").await?;
        assert_eq!(read_some(&fcx, &mut b, 3).await, b"ok\n");
        // A sent nothing: the fill comes because B's order woke it.
        assert_eq!(read_some(&fcx, &mut a, 15).await, b"execution 5@99\n");
        Ok(())
    });
}

/// A FIX-like session with named timers: a heartbeat every 10 ms and a
/// logon deadline, and a count of the client's lines.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionTimer {
    Heartbeat,
    Logon,
}

struct Session {
    lines: u64,
    beats: u64,
}

impl Session {
    fn stack() -> Lined<Session> {
        Lined::new(Session { lines: 0, beats: 0 })
    }
}

impl LineApp for Session {
    type Timer = SessionTimer;
    type Work = Infallible;
    type Done = Infallible;
    type Next = Infallible;
    type Error = Infallible;

    fn open(&mut self, out: &mut LineOut<'_, Self>) -> Result<(), Infallible> {
        out.set_timer(SessionTimer::Heartbeat, Duration::from_millis(10));
        out.set_timer(SessionTimer::Logon, Duration::from_millis(25));
        Ok(())
    }

    fn line(
        &mut self,
        line: Result<Vec<u8>, LineError>,
        out: &mut LineOut<'_, Self>,
    ) -> Result<(), Infallible> {
        self.lines += 1;
        if line.as_deref() == Ok(b"step") {
            assert_eq!(
                self.beats,
                self.lines - 2,
                "due heartbeat before the next line"
            );
            out.set_timer(SessionTimer::Heartbeat, Duration::ZERO);
        }
        if line.as_deref() == Ok(b"logon") {
            out.cancel_timer(SessionTimer::Logon);
            out.write(b"logged on\n");
        }
        if line.as_deref() == Ok(b"end") {
            out.write(format!("end lines={} beats={}\n", self.lines, self.beats).as_bytes());
            out.close();
        }
        Ok(())
    }

    fn timer(
        &mut self,
        timer: SessionTimer,
        out: &mut LineOut<'_, Self>,
    ) -> Result<(), Infallible> {
        match timer {
            SessionTimer::Heartbeat => {
                self.beats += 1;
                out.set_timer(SessionTimer::Heartbeat, Duration::from_millis(10));
            }
            SessionTimer::Logon => {
                out.write(b"logon timed out\n");
                out.close();
            }
        }
        Ok(())
    }
}

#[test]
fn named_timers_run_side_by_side() {
    let mut h = Harness::new(Seed::from_u64(0), Session::stack());
    h.settle().unwrap();
    assert_eq!(
        h.layer().timer(&SessionTimer::Logon),
        Some(Instant::ZERO + Duration::from_millis(25))
    );
    h.advance(Duration::from_millis(20)).unwrap();
    assert_eq!(h.layer().app().beats, 2);
    h.push(b"logon\n").unwrap();
    assert_eq!(h.layer().timer(&SessionTimer::Logon), None);
    h.advance(Duration::from_millis(30)).unwrap();
    assert!(!h.ended());
    assert_eq!(h.layer().app().beats, 5);

    // Without a logon, the logon timer closes the session, heartbeats or not.
    let mut h = Harness::new(Seed::from_u64(0), Session::stack());
    h.settle().unwrap();
    h.advance(Duration::from_millis(30)).unwrap();
    assert_eq!(h.take_output(), b"logon timed out\n");
    assert!(h.ended());
}

/// A client that never stops sending cannot starve the heartbeat: due
/// timers go before more input.
#[test]
fn continuous_input_cannot_starve_a_timer() {
    world(Duration::from_secs(60), |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        line_stack::listen(
            &fcx,
            server.listen(7)?,
            StreamLimits::default(),
            Session::stack,
        );
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 7))
            .await?;
        let mut flood = b"logon\n".to_vec();
        for _ in 0..10_000 {
            flood.extend_from_slice(b"step\n");
        }
        flood.extend_from_slice(b"end\n");
        conn.write_all(&fcx, &flood).await?;
        let reply = String::from_utf8(
            timeout(&fcx, Duration::from_secs(30), async {
                let mut reply = Vec::new();
                let mut bytes = [0; 1024];
                loop {
                    let n = conn.read(&fcx, &mut bytes).await?;
                    if n == 0 {
                        break;
                    }
                    reply.extend_from_slice(&bytes[..n]);
                }
                Ok::<_, ConnError>(reply)
            })
            .await
            .expect("the stack did not finish")
            .unwrap(),
        )
        .unwrap();
        assert_eq!(reply, "logged on\nend lines=10002 beats=10000\n");
        Ok(())
    });
}

/// Whose turn it is among the streams' frames, and the wakers of those
/// waiting.
#[derive(Default)]
struct Baton {
    turn: usize,
    open: bool,
    waiting: Vec<std::task::Waker>,
}

/// One stream's next frame, written on its turn, so two streams' frames
/// interleave frame by frame.
struct NextFrame {
    stream: usize,
    of: usize,
    frame: usize,
    frames: usize,
    baton: Arc<Mutex<Baton>>,
}

impl Job for NextFrame {
    /// The frame, and the work for the stream's next frame, if any.
    type Done = (Vec<u8>, Option<NextFrame>, usize);

    fn poll(&mut self, _: Option<&Cx>, cx: &mut Context<'_>) -> Poll<Self::Done> {
        let mut baton = self.baton.lock().unwrap();
        if !baton.open || baton.turn % self.of != self.stream {
            baton.waiting.push(cx.waker().clone());
            return Poll::Pending;
        }
        baton.turn += 1;
        for w in baton.waiting.drain(..) {
            w.wake();
        }
        let frame = format!("[{} {}]", self.stream, self.frame).into_bytes();
        let next = (self.frame < self.frames).then(|| NextFrame {
            stream: self.stream,
            of: self.of,
            frame: self.frame + 1,
            frames: self.frames,
            baton: self.baton.clone(),
        });
        Poll::Ready((frame, next, self.stream))
    }
}

/// HTTP/2 in miniature: `get` opens a stream whose response comes a frame
/// at a time from work; `ping` is answered at once, while responses are
/// still on their way.
struct Mux {
    streams: usize,
    baton: Arc<Mutex<Baton>>,
}

impl LineApp for Mux {
    type Timer = ();
    type Work = NextFrame;
    type Done = (Vec<u8>, Option<NextFrame>, usize);
    type Next = Infallible;
    type Error = Infallible;

    fn line(
        &mut self,
        line: Result<Vec<u8>, LineError>,
        out: &mut LineOut<'_, Self>,
    ) -> Result<(), Infallible> {
        match line.as_deref() {
            Ok(b"get") => {
                out.start(NextFrame {
                    stream: self.streams,
                    of: 2,
                    frame: 1,
                    frames: 3,
                    baton: self.baton.clone(),
                });
                self.streams += 1;
            }
            Ok(b"ping") => out.write(b"(pong)"),
            _ => {}
        }
        Ok(())
    }

    fn done(&mut self, done: Self::Done, out: &mut LineOut<'_, Self>) -> Result<(), Infallible> {
        let (frame, next, stream) = done;
        out.write(&frame);
        match next {
            Some(next) => out.start(next),
            None => out.write(format!("(done {stream})").as_bytes()),
        }
        Ok(())
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
fn work_interleaves_two_responses_while_reads_go_on() {
    let baton = Arc::new(Mutex::new(Baton {
        open: true,
        ..Baton::default()
    }));
    let mut h = Harness::new(Seed::from_u64(0), Lined::new(Mux { streams: 0, baton }))
        .with_worker(Polling::new());
    h.push(b"get\nget\n").unwrap();
    interleaved(&String::from_utf8(h.take_output()).unwrap());
    assert_eq!(h.jobs(), 0);

    world(Duration::from_secs(60), |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        let baton = Arc::new(Mutex::new(Baton::default()));
        let shared = baton.clone();
        line_stack::listen(
            &fcx,
            server.listen(7)?,
            StreamLimits::default(),
            move || {
                Lined::new(Mux {
                    streams: 0,
                    baton: shared.clone(),
                })
            },
        );
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 7))
            .await?;
        conn.write_all(&fcx, b"get\nget\nping\n").await?;
        // Both responses wait for the gate; the ping is answered anyway.
        assert_eq!(read_some(&fcx, &mut conn, 6).await, b"(pong)");
        {
            let mut b = baton.lock().unwrap();
            b.open = true;
            for w in b.waiting.drain(..) {
                w.wake();
            }
        }
        interleaved(&String::from_utf8(read_some(&fcx, &mut conn, 46).await).unwrap());
        Ok(())
    });
}

/// MoldUDP64 in miniature: `req N` is answered with N datagrams, and a
/// heartbeat goes to the world's subscriber every 20 ms.
struct Mold {
    subscriber: SocketAddr,
    transport: &'static str,
}

impl DatagramApp for Mold {
    type Timer = ();

    fn open(&mut self, sends: &mut Sends<'_, ()>) {
        sends.set_timer((), Duration::from_millis(20));
    }

    fn line(
        &mut self,
        line: Result<Vec<u8>, LineError>,
        from: SocketAddr,
        sends: &mut Sends<'_, ()>,
    ) {
        let line = String::from_utf8(line.unwrap_or_default()).unwrap_or_default();
        let n: u32 = line
            .strip_prefix("req ")
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        for i in 1..=n {
            let packet = format!("packet {i} over {}", self.transport);
            sends.send_to(from, packet.into_bytes());
        }
    }

    fn timer(&mut self, _: (), sends: &mut Sends<'_, ()>) {
        sends.send_to(self.subscriber, b"heartbeat".to_vec());
        sends.set_timer((), Duration::from_millis(20));
    }
}

#[test]
fn a_datagram_stack_sends_several_datagrams_and_ticks() {
    let addr = Ipv4Addr::new(10, 40, 0, 9);
    world(Duration::from_secs(60), move |fcx| async move {
        let subscriber = SocketAddr::new(ME.into(), 4001);
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("mold", |h| {
                h.at(addr)
                    .udp_stack(9, Budget::unlimited(), move |info: &ConnInfo| {
                        let mold = Mold {
                            subscriber,
                            transport: info.transport.as_str(),
                        };
                        Datagrammed::new(mold, info.local)
                    })
            })
            .start(&fcx, attachments)?;
        let s = machine(&fcx, attacher.attach("agent")?, ME);
        let mut feed = s.udp.bind(4001)?;
        let mut u = s.udp.bind(4000)?;
        u.send_to(b"req 3\n", SocketAddr::new(addr.into(), 9));
        for i in 1..=3 {
            assert_eq!(
                u.recv(&fcx).await?.0,
                format!("packet {i} over udp").into_bytes()
            );
        }
        assert_eq!(feed.recv(&fcx).await?.0, b"heartbeat");
        assert_eq!(feed.recv(&fcx).await?.0, b"heartbeat");
        Ok(())
    });
}

/// Panics on `boom`, gives up on `fail`.
struct Fragile;

impl LineApp for Fragile {
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Next = Infallible;
    type Error = std::io::Error;

    fn line(
        &mut self,
        line: Result<Vec<u8>, LineError>,
        out: &mut LineOut<'_, Self>,
    ) -> Result<(), std::io::Error> {
        match line.as_deref() {
            Ok(b"boom") => panic!("the stack fell over"),
            Ok(b"fail") => Err(std::io::Error::other("the stack gave up")),
            _ => {
                out.write(b"fine\n");
                Ok(())
            }
        }
    }
}

/// A stack error closes only its connection. A panic is not caught: it
/// ends the run, as a panic anywhere in a world does.
#[test]
fn an_error_closes_only_its_connection_and_a_panic_ends_the_run() {
    let mut h = Harness::new(Seed::from_u64(0), Lined::new(Fragile));
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h.push(b"boom\n")));
    assert!(caught.is_err());

    let addr = Ipv4Addr::new(10, 40, 0, 9);
    let to = SocketAddr::new(addr.into(), 7);
    world(Duration::from_secs(60), move |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("svc", |h| h.at(addr).tcp_stack(7, |_| Lined::new(Fragile)))
            .start(&fcx, attachments)?;
        let s = machine(&fcx, attacher.attach("agent")?, ME);
        let mut b = s.tcp.connect(&fcx, to).await?;
        b.write_all(&fcx, b"hi\nfail\n").await?;
        assert_eq!(read_some(&fcx, &mut b, 10).await, b"fine\n");
        // The world goes on: another connection is served.
        let mut c = s.tcp.connect(&fcx, to).await?;
        c.write_all(&fcx, b"hi\n").await?;
        assert_eq!(read_some(&fcx, &mut c, 5).await, b"fine\n");
        Ok(())
    });

    let ran = std::thread::spawn(move || {
        block_on(lab(Seed::from_u64(1), move |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            Net::new(fictionet_extras::network::cdn_pools())
                .ipv4_only()
                .host("svc", |h| h.at(addr).tcp_stack(7, |_| Lined::new(Fragile)))
                .start(&fcx, attachments)?;
            let s = machine(&fcx, attacher.attach("agent")?, ME);
            let mut a = s.tcp.connect(&fcx, to).await?;
            a.write_all(&fcx, b"boom\n").await?;
            fcx.idle().await?;
            Ok(())
        }))
    })
    .join();
    let panic = ran.expect_err("the run should end with the panic");
    assert_eq!(panic.downcast_ref::<&str>(), Some(&"the stack fell over"));
}

/// Draws one number per connection.
struct Dice;

impl LineApp for Dice {
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Next = Infallible;
    type Error = Infallible;

    fn open(&mut self, out: &mut LineOut<'_, Self>) -> Result<(), Infallible> {
        let n = out.random_u64();
        out.write(format!("{n}\n").as_bytes());
        out.close();
        Ok(())
    }

    fn line(
        &mut self,
        _: Result<Vec<u8>, LineError>,
        _: &mut LineOut<'_, Self>,
    ) -> Result<(), Infallible> {
        Ok(())
    }
}

/// Two runs with the same seed and the same connections draw the same
/// numbers; successive connections consume different parts of the stream.
#[test]
fn a_seeded_run_repeats_its_randomness() {
    let draws = |seed: u64| {
        let (tx, rx) = mpsc::channel();
        block_on(lab(Seed::from_u64(seed), move |fcx| async move {
            let (server, _su, client, _cu) = two_machines(&fcx);
            line_stack::listen(&fcx, server.listen(7)?, StreamLimits::default(), || {
                Lined::new(Dice)
            });
            let mut got = Vec::new();
            for _ in 0..2 {
                let mut conn = client
                    .connect(&fcx, SocketAddr::new(SERVER.into(), 7))
                    .await?;
                got.push(String::from_utf8(read_some(&fcx, &mut conn, 64).await).unwrap());
            }
            tx.send(got).unwrap();
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
        rx.recv().unwrap()
    };
    let first = draws(7);
    assert_eq!(first, draws(7));
    assert_ne!(first[0], first[1]);
    assert_ne!(first, draws(8));
}

/// A closed connection counts against the cap until its socket is gone, so
/// a client that never finishes closing cannot open more.
#[test]
fn a_connection_counts_until_its_socket_is_gone() {
    let addr = Ipv4Addr::new(10, 40, 0, 9);
    world(Duration::from_secs(60), move |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("svc", |h| {
                h.at(addr)
                    .tcp_stack_with(7, StreamLimits::default(), 1, |_| Echo::stack())
            })
            .start(&fcx, attachments)?;
        let s = machine(&fcx, attacher.attach("agent")?, ME);
        let to = SocketAddr::new(addr.into(), 7);
        let mut a = s.tcp.connect(&fcx, to).await?;
        a.write_all(&fcx, b"quit\n").await?;
        assert_eq!(read_some(&fcx, &mut a, 10).await, b"hello\nbye\n");
        // The server closed its side; `a` keeps its own open.
        let mut b = s.tcp.connect(&fcx, to).await?;
        let mut buf = [0u8; 16];
        let r = timeout(&fcx, Duration::from_secs(2), b.read(&fcx, &mut buf))
            .await
            .expect("an answer");
        assert!(matches!(r, Err(ConnError::Reset) | Ok(0)), "{r:?}");
        drop(a);
        Ok(())
    });
}

/// Runs `work` in a region of its own, cancels that region 50 ms in, and
/// returns what `work` returned, as `{:?}`.
async fn after_a_cancel<F, Fut, T>(fcx: &Cx, work: F) -> String
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = T>,
    T: std::fmt::Debug,
{
    let out = Arc::new(Mutex::new(String::new()));
    let o = out.clone();
    let _ = fcx
        .region(|region_fcx| async move {
            let stopper = region_fcx.clone();
            region_fcx.spawn(move |fcx| async move {
                fcx.sleep(Duration::from_millis(50)).await?;
                stopper.cancel();
                Ok(())
            });
            *o.lock().unwrap() = format!("{:?}", work(region_fcx).await);
            Ok(())
        })
        .await;
    out.lock().unwrap().clone()
}

/// Answers nothing.
struct Quiet;

impl DatagramApp for Quiet {
    type Timer = ();

    fn line(&mut self, _: Result<Vec<u8>, LineError>, _: SocketAddr, _: &mut Sends<'_, ()>) {}
}

/// Every wait of the serving stack reports a cancel the one way: an
/// accept, the stream runner, `httpd::serve_connection`, the datagram
/// runner, and, with the `tokio` feature, a connection read through
/// tokio's traits.
#[test]
fn every_serving_wait_reports_a_cancel() {
    world(Duration::from_secs(60), |fcx| async move {
        let (server, server_udp, client, _cu) = two_machines(&fcx);
        let mut listener = server.listen(7)?;

        // Nothing connects: the accept is cancelled.
        let got = after_a_cancel(&fcx, |region_fcx| async move {
            listener.accept(&region_fcx).await.map(|_| ())
        })
        .await;
        assert_eq!(got, "Err(Cancelled)");

        // A client that connects and sends nothing, served by the stream
        // runner.
        let mut listener = server.listen(8)?;
        let _c1 = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 8))
            .await?;
        let conn = listener.accept(&fcx).await?;
        let info = ConnInfo::new(1, conn.local_addr(), conn.peer_addr());
        let got = after_a_cancel(&fcx, |region_fcx| async move {
            let limits = StreamLimits::default();
            let budget = Budget::unlimited();
            stack::stream(
                &region_fcx,
                conn,
                &info,
                Echo::stack(),
                budget,
                limits,
                |_| {},
            )
            .await
            .map(|_| ())
            .map_err(|e| matches!(e, StackError::Cancelled).then_some(fictionet::Cancelled))
        })
        .await;
        assert_eq!(got, "Err(Some(Cancelled))");

        // The same, by httpd.
        let mut listener = server.listen(80)?;
        let _c2 = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        let conn = listener.accept(&fcx).await?;
        let handler: Arc<dyn httpd::Handler> = Arc::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        }));
        let info = ConnInfo::new(1, conn.local_addr(), conn.peer_addr());
        let got = after_a_cancel(&fcx, |region_fcx| async move {
            httpd::serve_connection(
                &region_fcx,
                conn,
                info,
                handler,
                &httpd::HttpOptions::default(),
            )
            .await
        })
        .await;
        assert_eq!(got, "Err(Cancelled)");

        // A socket that receives no datagrams, served by the datagram
        // runner.
        let socket = server_udp.bind(9)?;
        let local = SocketAddr::new(SERVER.into(), 9);
        let got = after_a_cancel(&fcx, |region_fcx| async move {
            let stack = Datagrammed::new(Quiet, Some(local));
            stack::datagrams(
                &region_fcx,
                socket,
                local,
                stack,
                Budget::unlimited(),
                |_| {},
            )
            .await
            .map_err(|e| matches!(e, StackError::Cancelled).then_some(fictionet::Cancelled))
        })
        .await;
        assert_eq!(got, "Err(Some(Cancelled))");

        // A read through tokio's traits fails with an I/O error whose
        // source is the connection's cancel, of a kind std does not retry.
        #[cfg(feature = "tokio")]
        {
            let mut listener = server.listen(9)?;
            let _c3 = client
                .connect(&fcx, SocketAddr::new(SERVER.into(), 9))
                .await?;
            let conn = listener.accept(&fcx).await?;
            let got = after_a_cancel(&fcx, |region_fcx| async move {
                use tokio::io::AsyncReadExt;
                let mut io = conn.into_tokio(&region_fcx);
                let mut buf = [0; 8];
                match io.read(&mut buf).await {
                    Ok(n) => format!("read {n}"),
                    Err(e) => format!(
                        "{:?} {:?}",
                        e.kind(),
                        e.get_ref().and_then(|e| e.downcast_ref::<ConnError>())
                    ),
                }
            })
            .await;
            assert_eq!(got, "\"Other Some(Cancelled)\"");
        }
        Ok(())
    });
}

#[test]
fn a_harness_stack_and_http_share_the_world_s_entropy() {
    use fictionet::{Entropy, SeededEntropy};
    let seed = Seed::from_u64(42);
    world::seeded_world(seed, Duration::from_secs(10), move |fcx| async move {
        let oracle = SeededEntropy::new(seed);
        assert_eq!(fcx.random_u64(), oracle.random_u64());
        let mut dice = Harness::new(Seed::from_u64(999), Lined::new(Dice))
            .with_worker(Polling::in_world(fcx.clone()));
        dice.settle().unwrap();
        assert_eq!(
            dice.take_output(),
            format!("{}\n", oracle.random_u64()).as_bytes()
        );

        let stamp = Arc::new(Mutex::new(None));
        let seen = stamp.clone();
        let router = fictionet_test_support::handler(
            move |ex: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                  _: http::Request<bytes::Bytes>| {
                *seen.lock().unwrap() = Some(ex.now());
                http::Response::new(Bytes::from(ex.random_u64().to_le_bytes().to_vec()))
            },
        );
        let mut http = layer::Harness::new(Seed::from_u64(999), Http1::new(router))
            .with_worker(Polling::in_world(fcx.clone()));
        fcx.sleep(Duration::from_millis(1)).await?;
        let before = fcx.now();
        http.push(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n").unwrap();
        let reply = http.take_output();
        assert!(reply.ends_with(&oracle.random_u64().to_le_bytes()));
        let stamp = stamp.lock().unwrap().unwrap();
        assert!(stamp >= before && stamp <= fcx.now());
        assert_eq!(fcx.random_u64(), oracle.random_u64());
        Ok(())
    });
}
