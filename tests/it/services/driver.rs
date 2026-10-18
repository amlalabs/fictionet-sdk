use super::*;

// ---------------------------------------------------------------------------
// The harness

/// A service's replies must not depend on how the client's bytes were cut
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
    let whole = {
        let mut h = Harness::new(
            fictionet::Seed::from_u64(0),
            Plc,
            Plant {
                limit: 1000,
                ..Plant::default()
            },
        );
        h.push(&input).unwrap();
        h.output().to_vec()
    };
    assert!(!whole.is_empty());
    for a in 0..input.len() {
        for b in a..input.len() {
            let mut h = Harness::new(
                fictionet::Seed::from_u64(0),
                Plc,
                Plant {
                    limit: 1000,
                    ..Plant::default()
                },
            );
            for chunk in [&input[..a], &input[a..b], &input[b..]] {
                h.push(chunk).unwrap();
            }
            assert_eq!(h.output(), whole, "split at {a} and {b}");
        }
    }
    // The same for HTTP/1 with a router.
    let router = || {
        Router::new().post("/e", |_, r: http::Request<Bytes>| {
            http::Response::new(r.into_body())
        })
    };
    let input = b"POST /e HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabcPOST /e HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nxy\r\n0\r\n\r\n";
    let whole = {
        let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router()), ());
        h.push(input).unwrap();
        h.output().to_vec()
    };
    for a in 0..input.len() {
        let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router()), ());
        h.push(&input[..a]).unwrap();
        h.push(&input[a..]).unwrap();
        assert_eq!(h.output(), whole, "split at {a}");
    }
}

// ---------------------------------------------------------------------------
// The driver, over TCP

#[test]
fn listen_serves_each_connection_and_records_it() {
    world(Duration::from_secs(60), |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        let kept = fcx.events();
        let transcript = Transcript::new(100, 1 << 16);
        let opts = ServeOptions::default().record(transcript.clone());
        serve::listen(&fcx, server.listen(7)?, Arc::new(()), || Echo, opts);
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 7))
            .await?;
        assert_eq!(read_some(&fcx, &mut conn, 6).await, b"hello\n");
        conn.write_all(&fcx, b"one\nlater\ntwo\n").await?;
        // The deferred answer comes in order, between the two echoes.
        assert_eq!(read_some(&fcx, &mut conn, 14).await, b"one\nlater\ntwo\n");
        conn.write_all(&fcx, b"quit\n").await?;
        assert_eq!(read_some(&fcx, &mut conn, 100).await, b"bye\n");
        let entries = kept
            .wait(&fcx, 1, Duration::from_secs(2), |e| e.is("conn", "close"))
            .await?;
        assert_eq!(entries.len(), 1);
        let all = kept.all();
        let kinds: Vec<String> = all
            .iter()
            .map(|e| format!("{}.{}", e.source, e.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                "conn.open",
                "echo.line",
                "echo.line",
                "echo.later",
                "echo.line",
                "echo.line",
                "conn.close"
            ]
        );
        assert!(all.iter().all(|e| e.conn.id == Some(1)
            && e.conn.peer.map(|p| p.ip()) == Some(Ipv4Addr::new(10, 9, 0, 2).into())));
        assert_eq!(all[3].get("written").and_then(json::Value::as_u64), Some(2));
        assert_eq!(
            all[6].get("end").and_then(json::Value::as_str),
            Some("closed")
        );
        // Both directions, with their exact bytes.
        let records = transcript.records();
        let from_client: Vec<u8> = records
            .iter()
            .filter(|r| r.sender == Side::Client)
            .flat_map(|r| r.bytes.clone())
            .collect();
        let to_client: Vec<u8> = records
            .iter()
            .filter(|r| r.sender == Side::Server)
            .flat_map(|r| r.bytes.clone())
            .collect();
        assert_eq!(from_client, b"one\nlater\ntwo\nquit\n");
        assert_eq!(to_client, b"hello\none\nlater\ntwo\nbye\n");
        assert!(
            records
                .iter()
                .filter(|r| r.sender == Side::Client)
                .all(|r| matches!(r.kind, RecordKind::Item(())))
        );
        Ok(())
    });
}

#[test]
fn timers_tick_and_idle_connections_close() {
    world(Duration::from_secs(60), |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        serve::listen(
            &fcx,
            server.listen(1)?,
            Arc::new(()),
            || Ticker { ticks: 0 },
            ServeOptions::default(),
        );
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 1))
            .await?;
        let started = fcx.now();
        assert_eq!(read_some(&fcx, &mut conn, 100).await, b"tick\ntick\ntick\n");
        assert!(fcx.now().since_start() - started.since_start() >= Duration::from_millis(90));

        let kept = fcx.events();
        let opts = ServeOptions::default().idle(Some(Duration::from_millis(100)));
        serve::listen(&fcx, server.listen(2)?, Arc::new(()), || Echo, opts);
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 2))
            .await?;
        assert_eq!(read_some(&fcx, &mut conn, 100).await, b"hello\n");
        let on_2 = |e: &Event| e.is("conn", "close") && e.conn.local.map(|a| a.port()) == Some(2);
        let closed = kept.wait(&fcx, 1, Duration::from_secs(2), on_2).await?;
        assert_eq!(
            closed[0].get("end").and_then(json::Value::as_str),
            Some("idle")
        );
        Ok(())
    });
}

#[test]
fn a_handoff_returns_the_connection_with_its_unread_bytes() {
    world(Duration::from_secs(60), |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        let mut listener = server.listen(25)?;
        let (tx, rx) = mpsc::channel();
        fcx.spawn(move |fcx| async move {
            let conn = listener.accept(&fcx).await?;
            let served = serve::connection(
                &fcx,
                conn,
                ConnInfo::default(),
                &mut Echo,
                &(),
                &ServeOptions::default(),
            )
            .await;
            if let Ok(Served::Upgraded(Upgrade::Handoff, mut rest)) = served {
                let _ = tx.send(rest.unread().to_vec());
                // What follows is the next protocol's: here, raw bytes.
                rest.write_all(&fcx, b"upgraded\n").await?;
            }
            Ok(())
        });
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
fn fault_plans_change_bytes_and_items_both_ways() {
    world(Duration::from_secs(60), |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        // The first item from the client is dropped, and every write to it
        // has its first byte replaced.
        let plan = FaultPlan::new(Plan {
            items: vec![Rule {
                when: Trigger::At(1),
                fault: ItemFault::Action {
                    delay: None,
                    rewrite: Rewrite::Drop,
                },
            }],
            outbound: vec![Rule {
                when: Trigger::After(2),
                fault: ByteFault::Corrupt {
                    offset: Some(0),
                    xor: 0x20,
                },
            }],
            ..Plan::default()
        });
        let opts = ServeOptions::default().faults(plan.clone());
        serve::listen(&fcx, server.listen(7)?, Arc::new(()), || Echo, opts);
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 7))
            .await?;
        assert_eq!(read_some(&fcx, &mut conn, 6).await, b"hello\n");
        conn.write_all(&fcx, b"dropped\nkept\n").await?;
        assert_eq!(read_some(&fcx, &mut conn, 5).await, b"Kept\n");
        // The plan changes while the connection runs: a delay on the way
        // in.
        plan.set(Plan {
            inbound: vec![Rule {
                when: Trigger::Always,
                fault: ByteFault::Delay(Duration::from_millis(150)),
            }],
            ..Plan::default()
        });
        let before = fcx.now();
        conn.write_all(&fcx, b"slow\n").await?;
        assert_eq!(read_some(&fcx, &mut conn, 5).await, b"slow\n");
        assert!(fcx.now().since_start() - before.since_start() >= Duration::from_millis(150));
        Ok(())
    });
}

#[test]
fn a_connection_cap_resets_connections_past_it() {
    world(Duration::from_secs(60), |fcx| async move {
        let events = fcx.events();
        let (server, _su, client, _cu) = two_machines(&fcx);
        serve::listen(
            &fcx,
            server.listen(7)?,
            Arc::new(()),
            || Echo,
            ServeOptions::default().max_conns(2),
        );
        let to = SocketAddr::new(SERVER.into(), 7);
        let mut a = client.connect(&fcx, to).await?;
        let mut b = client.connect(&fcx, to).await?;
        assert_eq!(read_some(&fcx, &mut a, 6).await, b"hello\n");
        assert_eq!(read_some(&fcx, &mut b, 6).await, b"hello\n");
        let mut c = client.connect(&fcx, to).await?;
        let mut buf = [0u8; 16];
        let r = timeout(&fcx, Duration::from_secs(2), c.read(&fcx, &mut buf))
            .await
            .expect("an answer");
        assert!(matches!(r, Err(ConnError::Reset) | Ok(0)), "{r:?}");
        let blocked = events
            .wait(&fcx, 1, Duration::from_secs(2), |e| e.is("net", "blocked"))
            .await?;
        assert_eq!(blocked[0].str("why"), Some("TooManyConnections"));
        assert_eq!(blocked[0].str("dst"), Some("10.9.0.1"));
        Ok(())
    });
}

#[test]
fn datagram_answers_each_datagram() {
    /// Answers a datagram of lines with their count.
    struct Count;
    service_fixture! {
        Count => (Lines, AtomicUsize, Infallible);
        decoder(self) {
            Lines::new(64, Ending::LfOrCrlf)
        }
        on_item(self, _: Result<Vec<u8>, LineError>; n, driver) -> Flow {
            let total = n.fetch_add(1, Ordering::SeqCst) + 1;
            driver
                .reply()
                .extend_from_slice(format!("{total};").as_bytes());
            Ok(Flow::Continue)
        }
    }
    world(Duration::from_secs(60), |fcx| async move {
        let (_s, server, _c, client) = two_machines(&fcx);
        let socket = server.bind(9)?;
        fcx.spawn(move |fcx| async move {
            let local = SocketAddr::new(SERVER.into(), 9);
            let _ = serve::datagram(
                &fcx,
                socket,
                local,
                &mut Count,
                &AtomicUsize::new(0),
                &ServeOptions::default(),
            )
            .await;
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

/// A decoder that skips a long run of bytes is making progress: the
/// connection stays open, as in the harness. Before, the driver took a
/// pass with no item for a stuck decoder and closed the connection as
/// failed.
#[test]
fn a_decoder_that_skips_a_long_line_keeps_the_connection_open() {
    /// Echo on 16-byte lines.
    struct Short;
    service_fixture! {
        Short => (Lines, (), Infallible);
        decoder(self) {
            Lines::new(16, Ending::LfOrCrlf)
        }
        on_item(self, line: Result<Vec<u8>, LineError>; _, driver) -> Flow {
            match line {
                Ok(line) => driver
                    .reply()
                    .extend_from_slice(&[line.as_slice(), b"\n"].concat()),
                Err(_) => driver.reply().extend_from_slice(b"long\n"),
            }
            Ok(Flow::Continue)
        }
    }
    let mut input = vec![b'x'; 100];
    input.extend_from_slice(b"\nok\n");
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Short, ());
    assert_eq!(h.push(&input).unwrap(), b"long\nok\n");
    assert!(!h.closed());
    world(Duration::from_secs(60), move |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        let kept = fcx.events();
        serve::listen(
            &fcx,
            server.listen(7)?,
            Arc::new(()),
            || Short,
            ServeOptions::default(),
        );
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 7))
            .await?;
        conn.write_all(&fcx, &input).await?;
        assert_eq!(read_some(&fcx, &mut conn, 8).await, b"long\nok\n");
        assert!(
            kept.of("conn", "close").is_empty(),
            "{:?}",
            kept.of("conn", "close")
        );
        Ok(())
    });
}

/// The harness runs deferred work and reports an upgrade, as the driver
/// does. Before, it dropped the work and took an upgrade for a close.
#[test]
fn the_harness_runs_deferred_work_and_reports_upgrades() {
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Echo, ());
    let got = h.push(b"one\nlater\ntwo\n");
    assert_eq!(
        got.as_deref().map(String::from_utf8_lossy).unwrap(),
        "hello\none\nlater\ntwo\n"
    );
    assert!(h.events().iter().any(|e| e.is("echo", "later")));
    assert!(matches!(
        h.push(b"handoff\nrest"),
        Err(HarnessError::Upgraded(Upgrade::Handoff))
    ));
    assert_eq!(h.upgraded(), Some(Upgrade::Handoff));
    assert!(!h.closed());
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

service_fixture! {
    Trader => (Lines, Book, Infallible);
    decoder(self) {
        Lines::new(64, Ending::LfOrCrlf)
    }
    on_item(self, line: Result<Vec<u8>, LineError>; book, driver) -> Flow {
        let line = String::from_utf8(line.unwrap_or_default()).unwrap_or_default();
        if line == "sub" {
            book.subscribers
                .lock()
                .unwrap()
                .push((driver.wake_handle(), self.inbox.clone()));
            driver.reply().extend_from_slice(b"subscribed\n");
        } else if let Some(fill) = line.strip_prefix("fill ") {
            let mut subscribers = book.subscribers.lock().unwrap();
            subscribers.retain(|(w, _)| !w.is_closed());
            for (wake, inbox) in subscribers.iter() {
                inbox.lock().unwrap().push(fill.to_owned());
                wake.wake();
            }
            driver.reply().extend_from_slice(b"ok\n");
        }
        Ok(Flow::Continue)
    }
    on_wake(self; _, driver) -> Flow {
        for fill in self.inbox.lock().unwrap().drain(..) {
            driver
                .reply()
                .extend_from_slice(format!("execution {fill}\n").as_bytes());
        }
        Ok(Flow::Continue)
    }
}

#[test]
fn another_connection_wakes_a_service_to_push_a_fill() {
    let mut h = Harness::new(
        fictionet::Seed::from_u64(0),
        Trader {
            inbox: Arc::default(),
        },
        Book::default(),
    );
    assert_eq!(h.push(b"sub\n").unwrap(), b"subscribed\n");
    let inbox = h.state().subscribers.lock().unwrap()[0].1.clone();
    inbox.lock().unwrap().push("7@100".into());
    h.wake_handle().wake();
    assert_eq!(h.poll().unwrap(), b"execution 7@100\n");

    world(Duration::from_secs(60), |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        serve::listen(
            &fcx,
            server.listen(9000)?,
            Arc::new(Book::default()),
            || Trader {
                inbox: Arc::default(),
            },
            ServeOptions::default(),
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
struct Session {
    lines: u64,
    beats: u64,
}

service_fixture! {
    Session => (Lines, (), Infallible);
    decoder(self) {
        Lines::new(64, Ending::LfOrCrlf)
    }
    on_open(self; _, driver) -> Flow {
        driver.set_timer("heartbeat", Duration::from_millis(10));
        driver.set_timer("logon", Duration::from_millis(25));
        Ok(Flow::Continue)
    }
    on_item(self, line: Result<Vec<u8>, LineError>; _, driver) -> Flow {
        self.lines += 1;
        if line.as_deref() == Ok(b"slow") {
            // Work that takes a while, so the client's bytes pile up.
            let started = fictionet::stdlib::test_support::thread_cpu_time();
            while fictionet::stdlib::test_support::thread_cpu_time() - started
                < Duration::from_micros(50)
            {}
        }
        if line.as_deref() == Ok(b"logon") {
            driver.cancel_timer("logon");
            driver.reply().extend_from_slice(b"logged on\n");
        }
        if line.as_deref() == Ok(b"end") {
            driver.reply().extend_from_slice(
                format!("end lines={} beats={}\n", self.lines, self.beats).as_bytes(),
            );
            return Ok(Flow::Close);
        }
        Ok(Flow::Continue)
    }
    on_timer(self, timer: Timer; _, driver) -> Flow {
        match timer {
            "heartbeat" => {
                self.beats += 1;
                driver.set_timer("heartbeat", Duration::from_millis(10));
                Ok(Flow::Continue)
            }
            "logon" => {
                driver.reply().extend_from_slice(b"logon timed out\n");
                Ok(Flow::Close)
            }
            _ => Ok(Flow::Continue),
        }
    }
}

#[test]
fn named_timers_run_side_by_side() {
    let mut h = Harness::new(
        fictionet::Seed::from_u64(0),
        Session { lines: 0, beats: 0 },
        (),
    );
    h.open().unwrap();
    assert_eq!(
        h.timer("logon"),
        Some(fictionet::time::Instant::ZERO + Duration::from_millis(25))
    );
    h.advance(Duration::from_millis(20)).unwrap();
    assert_eq!(h.service().beats, 2);
    h.push(b"logon\n").unwrap();
    assert_eq!(h.timer("logon"), None);
    h.advance(Duration::from_millis(30)).unwrap();
    assert!(!h.closed());
    assert_eq!(h.service().beats, 5);

    // Without a logon, the logon timer closes the session, heartbeats or not.
    let mut h = Harness::new(
        fictionet::Seed::from_u64(0),
        Session { lines: 0, beats: 0 },
        (),
    );
    h.open().unwrap();
    assert_eq!(
        h.advance(Duration::from_millis(30)).unwrap(),
        b"logon timed out\n"
    );
    assert!(h.closed());
}

/// A client that never stops sending cannot starve the heartbeat: due
/// timers go before more input. Before, the driver read whenever bytes
/// were there and only then looked at its one timer.
#[test]
fn continuous_input_cannot_starve_a_timer() {
    world::real_world(Duration::from_secs(60), |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        serve::listen(
            &fcx,
            server.listen(7)?,
            Arc::new(()),
            || Session { lines: 0, beats: 0 },
            ServeOptions::default(),
        );
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 7))
            .await?;
        let mut flood = b"logon\n".to_vec();
        for _ in 0..10_000 {
            flood.extend_from_slice(b"slow\n");
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
            .expect("the service did not finish")
            .unwrap(),
        )
        .unwrap();
        // The work took at least 500 ms: a 10 ms heartbeat that is never
        // starved beats nearly every 10 ms of it.
        let expected = 50;
        let beats: u64 = reply
            .rsplit("beats=")
            .next()
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(reply.contains("end lines=10002"), "{reply}");
        assert!(
            beats >= expected * 7 / 10,
            "{reply}, expected about {expected}"
        );
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
    fn poll_next(
        &mut self,
        _ctx: &mut PendingDriver<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Vec<u8>, fictionet::Error>>> {
        if self.sent == self.frames {
            return Poll::Ready(None);
        }
        let mut baton = self.baton.lock().unwrap();
        if !baton.open || baton.turn % self.of != self.stream {
            baton.waiting.push(cx.waker().clone());
            return Poll::Pending;
        }
        baton.turn += 1;
        for w in baton.waiting.drain(..) {
            w.wake();
        }
        self.sent += 1;
        Poll::Ready(Some(Ok(
            format!("[{} {}]", self.stream, self.sent).into_bytes()
        )))
    }
}

/// HTTP/2 in miniature: `get` opens a stream whose response is keyed work;
/// `ping` is answered at once, while responses are still on their way.
struct Mux {
    streams: usize,
    baton: Arc<Mutex<Baton>>,
}

service_fixture! {
    Mux => (Lines, (), Infallible);
    decoder(self) {
        Lines::new(64, Ending::LfOrCrlf)
    }
    on_item(self, line: Result<Vec<u8>, LineError>; _, driver) -> Flow {
        match line.as_deref() {
            Ok(b"get") => {
                let work = Frames {
                    stream: self.streams,
                    of: 2,
                    sent: 0,
                    frames: 3,
                    baton: self.baton.clone(),
                };
                driver.defer_keyed(self.streams as u64, work);
                self.streams += 1;
            }
            Ok(b"ping") => driver.reply().extend_from_slice(b"(pong)"),
            _ => {}
        }
        Ok(Flow::Continue)
    }
    on_done(self, key: u64, done: serve::Done; _, driver) -> Flow {
        assert!(matches!(done, serve::Done::Finished), "{done:?}");
        driver
            .reply()
            .extend_from_slice(format!("(done {key})").as_bytes());
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
    let baton = Arc::new(Mutex::new(Baton {
        open: true,
        ..Baton::default()
    }));
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Mux { streams: 0, baton }, ());
    let out = String::from_utf8(h.push(b"get\nget\n").unwrap()).unwrap();
    interleaved(&out);
    assert_eq!(h.pending(), (0, 0));

    world(Duration::from_secs(60), |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        let baton = Arc::new(Mutex::new(Baton::default()));
        let shared = baton.clone();
        serve::listen(
            &fcx,
            server.listen(7)?,
            Arc::new(()),
            move || Mux {
                streams: 0,
                baton: shared.clone(),
            },
            ServeOptions::default(),
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

#[test]
fn datagram_services_send_several_datagrams_and_tick() {
    /// MoldUDP64 in miniature: `req N` is answered with N datagrams, and a
    /// heartbeat goes to the world's subscriber every 20 ms.
    struct Mold;
    service_fixture! {
        Mold => (Lines, SocketAddr, Infallible);
        decoder(self) {
            Lines::new(64, Ending::LfOrCrlf)
        }
        on_open(self; _, driver) -> Flow {
            driver.set_timer("heartbeat", Duration::from_millis(20));
            Ok(Flow::Continue)
        }
        on_item(self, line: Result<Vec<u8>, LineError>; _, driver) -> Flow {
            let line = String::from_utf8(line.unwrap_or_default()).unwrap_or_default();
            let n: u32 = line
                .strip_prefix("req ")
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            let to = driver.conn().peer.unwrap();
            for i in 1..=n {
                driver.send_to(
                    to,
                    format!("packet {i} over {}", driver.conn().transport.as_str()).into_bytes(),
                );
            }
            Ok(Flow::Continue)
        }
        on_timer(self, _: Timer; subscriber, driver) -> Flow {
            driver.send_to(*subscriber, b"heartbeat".to_vec());
            driver.set_timer("heartbeat", Duration::from_millis(20));
            Ok(Flow::Continue)
        }
    }
    world(Duration::from_secs(60), |fcx| async move {
        let (_s, server, _c, client) = two_machines(&fcx);
        let socket = server.bind(9)?;
        let subscriber = SocketAddr::new(Ipv4Addr::new(10, 9, 0, 2).into(), 4001);
        let mut feed = client.bind(4001)?;
        fcx.spawn(move |fcx| async move {
            let local = SocketAddr::new(SERVER.into(), 9);
            let _ = serve::datagram(
                &fcx,
                socket,
                local,
                &mut Mold,
                &subscriber,
                &ServeOptions::default(),
            )
            .await;
            Ok(())
        });
        let mut s = client.bind(4000)?;
        s.send_to(b"req 3\n", SocketAddr::new(SERVER.into(), 9));
        for i in 1..=3 {
            assert_eq!(
                s.recv(&fcx).await?.0,
                format!("packet {i} over udp").into_bytes()
            );
        }
        assert_eq!(feed.recv(&fcx).await?.0, b"heartbeat");
        assert_eq!(feed.recv(&fcx).await?.0, b"heartbeat");
        Ok(())
    });
}

/// Panics on `boom`.
struct Fragile;

service_fixture! {
    Fragile => (Lines, (), std::io::Error);
    decoder(self) {
        Lines::new(64, Ending::LfOrCrlf)
    }
    on_item(self, line: Result<Vec<u8>, LineError>; _, driver) -> Flow {
        match line.as_deref() {
            Ok(b"boom") => panic!("the service fell over"),
            Ok(b"fail") => Err(std::io::Error::other("the service gave up")),
            _ => {
                driver.reply().extend_from_slice(b"fine\n");
                Ok(Flow::Continue)
            }
        }
    }
}

/// A service error closes only its connection and is recorded. A panic
/// is not caught: it ends the run, as a panic anywhere in a world does.
/// Before, the driver caught it and the world went on.
#[test]
fn an_error_closes_only_its_connection_and_a_panic_ends_the_run() {
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Fragile, ());
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h.push(b"boom\n")));
    assert!(caught.is_err());

    let addr = Ipv4Addr::new(10, 40, 0, 9);
    let to = SocketAddr::new(addr.into(), 7);
    world(Duration::from_secs(60), move |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let kept = fcx.events();
        Net::new()
            .ipv4_only()
            .host("svc", |h| h.at(addr).tcp(7, Arc::new(()), || Fragile))
            .start(&fcx, attachments)?;
        let s = machine(&fcx, attacher.attach("agent")?, ME);
        let mut b = s.tcp.connect(&fcx, to).await?;
        b.write_all(&fcx, b"hi\nfail\n").await?;
        assert_eq!(read_some(&fcx, &mut b, 10).await, b"fine\n");
        let error = kept
            .wait(&fcx, 1, Duration::from_secs(2), |e| e.is("conn", "error"))
            .await?;
        assert_eq!(error[0].str("error"), Some("the service gave up"));
        assert_eq!(error[0].conn.id, Some(1));
        Ok(())
    });

    let ran = std::thread::spawn(move || {
        block_on(lab(fictionet::Seed::from_u64(1), move |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            Net::new()
                .ipv4_only()
                .host("svc", |h| h.at(addr).tcp(7, Arc::new(()), || Fragile))
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
    assert_eq!(panic.downcast_ref::<&str>(), Some(&"the service fell over"));
}

/// Draws one number per connection.
struct Dice;

service_fixture! {
    Dice => (Lines, (), Infallible);
    decoder(self) {
        Lines::new(64, Ending::LfOrCrlf)
    }
    on_open(self; _, driver) -> Flow {
        let n = driver.random_u64();
        driver
            .reply()
            .extend_from_slice(format!("{n}\n").as_bytes());
        Ok(Flow::Close)
    }
    on_item(self, _: Result<Vec<u8>, LineError>; _, _) -> Flow {
        Ok(Flow::Continue)
    }
}

/// Two runs with the same seed and the same connections draw the same
/// numbers; successive connections consume different parts of the stream.
#[test]
fn a_seeded_run_repeats_its_randomness() {
    let draws = |seed: u64| {
        let (tx, rx) = mpsc::channel();
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(seed),
            move |fcx| async move {
                let (server, _su, client, _cu) = two_machines(&fcx);
                serve::listen(
                    &fcx,
                    server.listen(7)?,
                    Arc::new(()),
                    || Dice,
                    ServeOptions::default(),
                );
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
            },
        ))
        .unwrap();
        rx.recv().unwrap()
    };
    let first = draws(7);
    assert_eq!(first, draws(7));
    assert_ne!(first[0], first[1]);
    assert_ne!(first, draws(8));
}

/// A closed connection counts against the cap until its socket is gone, so
/// a client that never finishes closing cannot open more. Before, the
/// count dropped when the service ended.
#[test]
fn a_connection_counts_until_its_socket_is_gone() {
    world(Duration::from_secs(60), |fcx| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        serve::listen(
            &fcx,
            server.listen(7)?,
            Arc::new(()),
            || Echo,
            ServeOptions::default().max_conns(1),
        );
        let to = SocketAddr::new(SERVER.into(), 7);
        let mut a = client.connect(&fcx, to).await?;
        a.write_all(&fcx, b"quit\n").await?;
        assert_eq!(read_some(&fcx, &mut a, 10).await, b"hello\nbye\n");
        // The server closed its side; `a` keeps its own open.
        let mut b = client.connect(&fcx, to).await?;
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

/// Every wait of the serving stack reports a cancel the one way: an
/// accept, `serve`, `datagram`, `httpd::serve_connection`, and, with the
/// `tokio` feature, a connection read through tokio's traits.
#[test]
fn every_serving_wait_reports_a_cancel() {
    world(Duration::from_secs(60), |fcx| async move {
        let (server, server_udp, client, _cu) = two_machines(&fcx);
        let mut listener = server.listen(7)?;

        // Nobody connects: the accept is cancelled.
        let got = after_a_cancel(&fcx, |region_fcx| async move {
            listener.accept(&region_fcx).await.map(|_| ())
        })
        .await;
        assert_eq!(got, "Err(Cancelled)");

        // A client that connects and sends nothing, served by `serve`.
        let mut listener = server.listen(8)?;
        let _c1 = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 8))
            .await?;
        let conn = listener.accept(&fcx).await?;
        let got = after_a_cancel(&fcx, |region_fcx| async move {
            serve::connection(
                &region_fcx,
                conn,
                ConnInfo::default(),
                &mut Echo,
                &(),
                &ServeOptions::default(),
            )
            .await
            .map(|_| ())
        })
        .await;
        assert_eq!(got, "Err(Cancelled)");

        // The same, by httpd.
        let mut listener = server.listen(80)?;
        let _c2 = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 80))
            .await?;
        let conn = listener.accept(&fcx).await?;
        let handler: Arc<dyn httpd::Handler> = Arc::new(Router::new());
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

        // A socket that receives no datagrams, served by `datagram`.
        let socket = server_udp.bind(9)?;
        let local = SocketAddr::new(SERVER.into(), 9);
        let got = after_a_cancel(&fcx, |region_fcx| async move {
            serve::datagram(
                &region_fcx,
                socket,
                local,
                &mut Echo,
                &(),
                &ServeOptions::default(),
            )
            .await
        })
        .await;
        assert_eq!(got, "Err(Cancelled)");

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
fn harness_service_http_and_faults_share_the_context_stream() {
    use fictionet::{Entropy, Seed, SeededEntropy};
    let seed = Seed::from_u64(42);
    world::seeded_world(seed, Duration::from_secs(10), move |fcx| async move {
        let oracle = SeededEntropy::new(seed);
        assert_eq!(fcx.random_u64(), oracle.random_u64());
        let mut dice = Harness::new(Seed::from_u64(999), Dice, ()).with_fcx(fcx.clone());
        assert_eq!(
            dice.open().unwrap(),
            format!("{}\n", oracle.random_u64()).as_bytes()
        );

        let mut faults = fictionet::stdlib::codec::Faults::new(64, 0);
        let plan = [Rule {
            when: Trigger::Chance { take: 1, out_of: 2 },
            fault: ByteFault::Corrupt {
                offset: None,
                xor: 1,
            },
        }];
        let mut bytes = Vec::new();
        faults.bytes(&fcx, &plan, b"abc", &mut bytes).unwrap();
        let mut expected = b"abc".to_vec();
        if oracle.random_below(2) == 0 {
            expected[oracle.random_below(3) as usize] ^= 1;
        }
        assert_eq!(bytes, expected);

        let stamp = Arc::new(Mutex::new(None));
        let seen = stamp.clone();
        let router = Router::new().get("/", move |ex, _| {
            *seen.lock().unwrap() = Some(ex.now());
            http::Response::new(Bytes::from(ex.random_u64().to_le_bytes().to_vec()))
        });
        let mut http =
            Harness::new(Seed::from_u64(999), Http1::new(router), ()).with_fcx(fcx.clone());
        fcx.sleep(Duration::from_millis(1)).await?;
        let before = fcx.now();
        let reply = http.push(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n").unwrap();
        assert!(reply.ends_with(&oracle.random_u64().to_le_bytes()));
        let stamp = stamp.lock().unwrap().unwrap();
        assert!(stamp >= before && stamp <= fcx.now());
        assert_eq!(fcx.random_u64(), oracle.random_u64());
        Ok(())
    });
}
