//! `fictionet observe` and `fictionet dashboard`, run as the binary against
//! a world in this process.

use crate::common::logged;

use logged::logged;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use fictionet::InterfaceExt;

const BIN: &str = env!("CARGO_BIN_EXE_fictionet");

fn temp_socket() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fn-obsbin-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("world.sock").to_str().unwrap().to_owned()
}

/// A world that takes attachments, and emits an event every 50 ms.
fn start_world(path: &str) -> fictionet::Listening {
    let (attacher, mut attachments) = fictionet::attachments();
    let listening =
        fictionet::listen(fictionet::WorldSocket::UnixSocket(path.into()), attacher).unwrap();
    std::thread::spawn(move || {
        let _ = fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            move |fcx| async move {
                fcx.spawn(move |fcx| async move {
                    while let Ok(a) = attachments.next(&fcx).await {
                        drop(a);
                    }
                    Ok(())
                });
                let mut n = 0i64;
                loop {
                    fcx.record(fictionet::events::Event::new("test", "tick").field("n", n));
                    n += 1;
                    fcx.sleep(fictionet::time::ms(50)).await?;
                }
            },
        ));
    });
    listening
}

fn get(port: u16, path: &str) -> (String, String) {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        conn,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer dashboard-test-token\r\n\r\n"
    )
    .unwrap();
    let mut all = String::new();
    conn.read_to_string(&mut all).unwrap();
    let (head, body) = all.split_once("\r\n\r\n").unwrap();
    (head.lines().next().unwrap().to_owned(), body.to_owned())
}

#[test]
fn observe_prints_json_lines() {
    let path = temp_socket();
    let _listening = start_world(&path);
    let world = format!("unix:{path}");
    let out = Command::new(BIN)
        .args(["observe", "--world", &world, "world"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.starts_with(r#"{"observe":1,"#) && text.ends_with("}\n"),
        "{text}"
    );

    assert!(
        text.contains(&format!("\"fictionet\":\"{}\"", env!("CARGO_PKG_VERSION"))),
        "{text}"
    );

    // A stream: the snapshot, then the world's own events, one per line.
    let mut child = Command::new(BIN)
        .args(["observe", "--world", &world, "watch"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    assert!(
        lines
            .next()
            .unwrap()
            .unwrap()
            .starts_with(r#"{"event":"snapshot""#)
    );
    let tick = lines
        .map(Result::unwrap)
        .find(|l| l.contains(r#""source":"test","kind":"tick""#));
    assert!(tick.is_some());
    child.kill().unwrap();
    child.wait().unwrap();

    // A request the world cannot answer exits 1; one that makes no sense, 2.
    let out = Command::new(BIN)
        .args(["observe", "--world", &world, "packet", "e999", "1"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains(r#""error""#));
    let out = Command::new(BIN)
        .args(["observe", "--world", &world, "fly"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(BIN)
        .args(["observe", "--world", "unix:/nonexistent/world.sock"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));

    // A full disk is a failure, not a quiet stop as a closed pipe is.
    if let Ok(full) = std::fs::File::create("/dev/full") {
        let out = Command::new(BIN)
            .args(["observe", "--world", &world, "world"])
            .stdout(full)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{out:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("writing to stdout"),
            "{out:?}"
        );
    }
}

/// A scripted observer peer, with the same replies for each request.
fn with_observer(replies: &[(u8, &[u8])], requests: usize, run: impl FnOnce(&str)) {
    use fictionet::relay::{Message, unix};

    with_observer_action(
        requests,
        |peer, id| {
            for &(flags, body) in replies {
                unix::send(peer, &Message::Reply { id, flags, body }.encode(), false).unwrap();
            }
        },
        run,
    );
}

/// A scripted observer peer that runs an action for each request.
fn with_observer_action(
    requests: usize,
    mut reply: impl FnMut(std::os::fd::RawFd, u32) + Send,
    run: impl FnOnce(&str),
) {
    use fictionet::relay::{self, Message, unix};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let path = temp_socket();
    let (addr, len) = unix::address(std::path::Path::new(&path)).unwrap();
    // SAFETY: the socket is owned here; addr is valid for len bytes.
    let listener = unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0);
        assert!(fd >= 0);
        let listener = OwnedFd::from_raw_fd(fd);
        assert_eq!(libc::bind(fd, (&raw const addr).cast(), len), 0);
        assert_eq!(libc::listen(fd, 1), 0);
        listener
    };
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut remaining = requests;
            while remaining != 0 {
                // Close-on-exec, so a child process that another test starts does not
                // keep the connection open.
                // SAFETY: accept needs no address output; the returned fd is owned here.
                let peer = unsafe {
                    let fd = libc::accept4(
                        listener.as_raw_fd(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        libc::SOCK_CLOEXEC,
                    );
                    assert!(fd >= 0);
                    OwnedFd::from_raw_fd(fd)
                };
                unix::set_timeout(
                    peer.as_raw_fd(),
                    libc::SO_RCVTIMEO,
                    Some(Duration::from_secs(5)),
                )
                .unwrap();
                let mut buf = vec![0; relay::MAX_MESSAGE];
                let n = unix::recv(peer.as_raw_fd(), &mut buf, false).unwrap();
                assert!(matches!(relay::decode(&buf[..n]), Ok(Message::Hello(_))));
                unix::send(peer.as_raw_fd(), &Message::Accept.encode(), false).unwrap();
                while remaining != 0 {
                    let n = unix::recv(peer.as_raw_fd(), &mut buf, false).unwrap();
                    if n == 0 {
                        break;
                    }
                    remaining -= 1;
                    let Message::Request { id, .. } = relay::decode(&buf[..n]).unwrap() else {
                        panic!("expected an observer request");
                    };
                    reply(peer.as_raw_fd(), id);
                }
            }
        });
        run(&path);
        server.join().unwrap();
    });
    drop(listener);
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(std::path::Path::new(&path).parent().unwrap()).unwrap();
}

#[test]
fn observe_inspects_envelopes_and_preserves_bytes() {
    use fictionet::relay::{BINARY, END};

    for (flags, bytes, status) in [
        (END, br#"{"error":"missing"}"#.as_slice(), 1),
        (END, b" \n{ \"extra\": 1, \"error\": \"missing\" }\n", 1),
        (END, br#"{"error":false}"#, 0),
        (END, br#"{"error":"truncated""#, 0),
        (END | BINARY, br#"{"error":"binary"}"#, 0),
        (0, br#"{"event":"ended","data":{}}"#, 0),
        (0, b" { \"data\": {}, \"event\": \"end\\u0065d\" } \n", 0),
        (0, br#"{"event":"ended","data":}"#, 1),
        (0, br#"{"event":"ended","data":{}} trailing"#, 1),
        (BINARY, br#"{"event":"ended","data":{}}"#, 1),
    ] {
        with_observer(&[(flags, bytes)], 1, |path| {
            let out = Command::new(BIN)
                .args(["observe", "--world", &format!("unix:{path}"), "watch"])
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(status), "{out:?}");
            let expected = if flags & BINARY != 0 {
                bytes.to_vec()
            } else {
                [bytes, b"\n"].concat()
            };
            assert_eq!(out.stdout, expected);
        });
    }
}

#[test]
fn dashboard_inspects_envelopes_for_json_and_streams() {
    use fictionet::relay::END;

    for (route, requests, bytes, status, expected) in [
        (
            "/api/packet",
            1,
            " { \"extra\": 1, \"error\": \"missing\" } ",
            "404 Not Found",
            " { \"extra\": 1, \"error\": \"missing\" } ",
        ),
        (
            "/api/packet",
            1,
            "{\"error\":false}",
            "200 OK",
            "{\"error\":false}",
        ),
        (
            "/api/watch",
            1,
            " {\n\"data\": { \"id\": \"t1\" }, \"event\": \"no\\u0064e\"\n} ",
            "200 OK",
            "event: node\ndata: { \"id\": \"t1\" }\n\n",
        ),
        (
            "/api/watch",
            1,
            "{\"event\":\"node\",\"data\":{\n\"id\": \"t1\"\n}}",
            "200 OK",
            "event: node\ndata: {\ndata: \"id\": \"t1\"\ndata: }\n\n",
        ),
        (
            "/api/watch",
            1,
            "{\"event\":\"node\",\"data\":}",
            "200 OK",
            "event: world_error\ndata: {\"error\":\"the world sent an invalid stream event\"}\n\n",
        ),
        (
            "/api/watch",
            1,
            "{\n\"error\": \"missing\"\n}",
            "200 OK",
            "event: world_error\ndata: {\"error\":\"missing\"}\n\n",
        ),
        (
            "/api/watch",
            1,
            "{\"event\":\"error\",\"data\":{}}",
            "200 OK",
            "event: world_error\ndata: {\"error\":\"the world sent an invalid stream event\"}\n\n",
        ),
        (
            "/api/packets?link=e3,e7",
            2,
            " { \"data\": {\n\"reason\": \"closed\" }, \"event\": \"end\" } ",
            "200 OK",
            "event: link_end\ndata: {\"link\":\"e3\",\ndata: \"reason\": \"closed\" }\n\nevent: link_end\ndata: {\"link\":\"e7\",\ndata: \"reason\": \"closed\" }\n\nevent: end\ndata: {\"reason\":\"every link closed\"}\n\n",
        ),
        (
            "/api/packets?link=e3,e7",
            2,
            "{\"event\":\"end\",\"data\":{ }}",
            "200 OK",
            "event: link_end\ndata: {\"link\":\"e3\"}\n\nevent: link_end\ndata: {\"link\":\"e7\"}\n\nevent: end\ndata: {\"reason\":\"every link closed\"}\n\n",
        ),
    ] {
        with_observer(&[(END, bytes.as_bytes())], requests, |path| {
            with_dashboard(path, |port| {
                let (head, body) = get(port, route);
                assert_eq!(head, format!("HTTP/1.1 {status}"));
                assert_eq!(body, expected);
            });
        });
    }
}

/// Runs a dashboard and cleans up its child and token file even on panic.
fn with_dashboard(path: &str, run: impl FnOnce(u16)) {
    let token_file = format!("{path}.token");
    std::fs::write(&token_file, "dashboard-test-token\n").unwrap();
    let mut child = Command::new(BIN)
        .args([
            "dashboard",
            "--world",
            &format!("unix:{path}"),
            "--listen",
            "127.0.0.1:0",
            "--token-file",
            &token_file,
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port = line
            .trim_end()
            .rsplit(':')
            .next()
            .unwrap()
            .trim_end_matches('/')
            .parse()
            .unwrap();
        run(port);
    }));
    let cleanup = [
        child.kill(),
        child.wait().map(|_| ()),
        std::fs::remove_file(token_file),
    ];
    if let Err(panic) = outcome {
        for result in cleanup {
            if let Err(error) = result {
                eprintln!("dashboard cleanup failed during panic: {error}");
            }
        }
        std::panic::resume_unwind(panic);
    }
    for result in cleanup {
        result.unwrap();
    }
}

#[test]
fn dashboard_cleanup_preserves_callback_panic() {
    let path = temp_socket();
    let listening = start_world(&path);
    let token_file = format!("{path}.token");
    let outcome = std::panic::catch_unwind(|| {
        with_dashboard(&path, |_| {
            assert!(std::path::Path::new(&token_file).exists());
            panic!("dashboard callback failed");
        });
    });
    let panic = outcome.expect_err("the callback panic must propagate");
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"dashboard callback failed")
    );
    assert!(!std::path::Path::new(&token_file).exists());
    drop(listening);
    std::fs::remove_dir(std::path::Path::new(&path).parent().unwrap()).unwrap();
}

/// Opens an SSE connection and checks its response headers.
fn sse_connection(port: u16, route: &str) -> BufReader<TcpStream> {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    write!(
        conn,
        "GET {route} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer dashboard-test-token\r\n\r\n"
    )
    .unwrap();
    let mut reader = BufReader::new(conn);
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        headers.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    assert_eq!(
        headers,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n"
    );
    reader
}

/// Reads one complete SSE frame, including its terminating blank line.
fn sse_frame(reader: &mut impl BufRead) -> String {
    let mut frame = String::new();
    loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        frame.push_str(&line);
        if line == "\n" {
            return frame;
        }
    }
}

#[test]
fn dashboard_sse_keeps_partial_replies_across_heartbeats() {
    use fictionet::relay::{END, MORE, Message, unix};

    for (route, links) in [
        ("/api/watch", vec![None]),
        ("/api/packets?link=e3,e7", vec![Some("e3"), Some("e7")]),
    ] {
        let (resume, heartbeat) = std::sync::mpsc::channel();
        with_observer_action(
            links.len(),
            move |peer, id| {
                unix::send(
                    peer,
                    &Message::Reply {
                        id,
                        flags: MORE,
                        body: br#"{"event":"packet","data":"#,
                    }
                    .encode(),
                    false,
                )
                .unwrap();
                heartbeat.recv_timeout(Duration::from_secs(15)).unwrap();
                for (flags, body) in [
                    (0, br#"{"seq":1}}"#.as_slice()),
                    (END, br#"{"event":"end","data":{"reason":"closed"}}"#),
                ] {
                    unix::send(peer, &Message::Reply { id, flags, body }.encode(), false).unwrap();
                }
            },
            |path| {
                with_dashboard(path, |port| {
                    let mut reader = sse_connection(port, route);
                    for link in &links {
                        assert_eq!(sse_frame(&mut reader), ": ping\n\n");
                        resume.send(()).unwrap();
                        let (data, end_name, end_data) = match link {
                            Some(link) => (
                                format!(r#"{{"link":"{link}","seq":1}}"#),
                                "link_end",
                                format!(r#"{{"link":"{link}","reason":"closed"}}"#),
                            ),
                            None => (
                                r#"{"seq":1}"#.into(),
                                "end",
                                r#"{"reason":"closed"}"#.into(),
                            ),
                        };
                        assert_eq!(
                            sse_frame(&mut reader),
                            format!("event: packet\ndata: {data}\n\n")
                        );
                        assert_eq!(
                            sse_frame(&mut reader),
                            format!("event: {end_name}\ndata: {end_data}\n\n")
                        );
                    }
                    let mut rest = String::new();
                    reader.read_to_string(&mut rest).unwrap();
                    assert_eq!(
                        rest,
                        if links.len() == 1 {
                            ""
                        } else {
                            "event: end\ndata: {\"reason\":\"every link closed\"}\n\n"
                        }
                    );
                });
            },
        );
    }
}

#[test]
fn dashboard_sse_distinguishes_boundary_close_from_truncation() {
    use fictionet::relay::{MORE, Message, unix};

    for (route, requests) in [("/api/watch", 1), ("/api/packets?link=e3,e7", 2)] {
        for partial in [false, true] {
            let mut remaining = requests;
            with_observer_action(
                requests,
                |peer, id| {
                    remaining -= 1;
                    if partial && remaining == 0 {
                        unix::send(
                            peer,
                            &Message::Reply {
                                id,
                                flags: MORE,
                                body: br#"{"event":"packet","data":"#,
                            }
                            .encode(),
                            false,
                        )
                        .unwrap();
                    }
                },
                |path| {
                    with_dashboard(path, |port| {
                        let mut reader = sse_connection(port, route);
                        let mut body = String::new();
                        reader.read_to_string(&mut body).unwrap();
                        assert_eq!(
                            body,
                            if partial {
                                "event: world_error\ndata: {\"error\":\"the world closed during a reply value\"}\n\n"
                            } else {
                                "event: end\ndata: {\"reason\":\"the world closed\"}\n\n"
                            }
                        );
                    });
                },
            );
        }
    }
}

#[test]
fn dashboard_partial_frame_after_ended() {
    use fictionet::relay::{END, MORE, Message, unix};

    for (route, requests, prefix) in [
        ("/api/watch", 1, "event: ended\ndata: {}\n\n"),
        (
            "/api/packets?link=e3,e7",
            2,
            "event: ended\ndata: {\"link\":\"e7\"}\n\n",
        ),
    ] {
        for (flags, reason) in [
            (MORE, "the world closed during a reply value"),
            (MORE | END, "invalid reply flags or continuation"),
        ] {
            let mut remaining = requests;
            with_observer_action(
                requests,
                |peer, id| {
                    remaining -= 1;
                    if remaining == 0 {
                        for (flags, body) in [
                            (0, br#"{"event":"ended","data":{}}"#.as_slice()),
                            (flags, br#"{"event":"end","data":"#),
                        ] {
                            unix::send(peer, &Message::Reply { id, flags, body }.encode(), false)
                                .unwrap();
                        }
                    }
                },
                |path| {
                    with_dashboard(path, |port| {
                        let (status, body) = get(port, route);
                        assert_eq!(status, "HTTP/1.1 200 OK");
                        assert_eq!(
                            body,
                            format!(
                                "{prefix}event: world_error\ndata: {{\"error\":\"{reason}\"}}\n\n"
                            )
                        );
                    });
                },
            );
        }
    }
}

#[test]
fn dashboard_refused_subscription_reason() {
    use fictionet::relay::END;

    for (route, requests, expected) in [
        (
            "/api/packets?link=e3",
            1,
            "event: world_error\ndata: {\"error\":\"no such link\"}\n\n",
        ),
        (
            "/api/packets?link=e3,e7",
            2,
            "event: link_error\ndata: {\"link\":\"e3\",\"error\":\"no such link\"}\n\nevent: link_error\ndata: {\"link\":\"e7\",\"error\":\"no such link\"}\n\nevent: end\ndata: {\"reason\":\"every link finished\"}\n\n",
        ),
    ] {
        with_observer(
            &[(END, br#"{ "error": "no such link" }"#)],
            requests,
            |path| {
                with_dashboard(path, |port| {
                    let (status, body) = get(port, route);
                    assert_eq!(status, "HTTP/1.1 200 OK");
                    assert_eq!(body, expected);
                });
            },
        );
    }
}

#[test]
fn dashboard_json_truncation_preserves_the_reason() {
    use fictionet::relay::MORE;

    with_observer(&[(MORE, br#"{"nodes":"#)], 1, |path| {
        with_dashboard(path, |port| {
            let (status, body) = get(port, "/api/graph");
            assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
            assert_eq!(body, r#"{"error":"the world closed during a reply value"}"#);
        });
    });
}

#[test]
fn dashboard_merged_refusal_keeps_other_links_streaming() {
    use fictionet::relay::{END, Message, unix};

    let mut first = true;
    with_observer_action(
        2,
        |peer, id| {
            let replies: &[(u8, &[u8])] = if first {
                &[(END, br#"{"error":"no such link"}"#)]
            } else {
                &[
                    (0, br#"{"event":"packet","data":{"seq":1}}"#),
                    (END, br#"{"event":"end","data":{"reason":"closed"}}"#),
                ]
            };
            first = false;
            for &(flags, body) in replies {
                unix::send(peer, &Message::Reply { id, flags, body }.encode(), false).unwrap();
            }
        },
        |path| {
            with_dashboard(path, |port| {
                let (status, body) = get(port, "/api/packets?link=e3,e7");
                assert_eq!(status, "HTTP/1.1 200 OK");
                assert_eq!(
                    body,
                    concat!(
                        "event: link_error\ndata: {\"link\":\"e3\",\"error\":\"no such link\"}\n\n",
                        "event: packet\ndata: {\"link\":\"e7\",\"seq\":1}\n\n",
                        "event: link_end\ndata: {\"link\":\"e7\",\"reason\":\"closed\"}\n\n",
                        "event: end\ndata: {\"reason\":\"every link finished\"}\n\n",
                    )
                );
            });
        },
    );
}

#[test]
fn dashboard_sse_heartbeat_releases_an_idle_observer_after_browser_disconnect() {
    use fictionet::relay::unix;
    use std::os::fd::AsRawFd;

    for (route, requests) in [("/api/watch", 1), ("/api/packets?link=e3,e7", 2)] {
        let (closed, done) = std::sync::mpsc::channel();
        let mut remaining = requests;
        with_observer_action(
            requests,
            |peer, _| {
                remaining -= 1;
                if remaining == 0 {
                    unix::set_timeout(peer, libc::SO_RCVTIMEO, Some(Duration::from_secs(15)))
                        .unwrap();
                    let mut buf = [0; 1];
                    assert_eq!(unix::recv(peer, &mut buf, false).unwrap(), 0);
                    closed.send(()).unwrap();
                }
            },
            |path| {
                with_dashboard(path, |port| {
                    let mut reader = sse_connection(port, route);
                    assert_eq!(sse_frame(&mut reader), ": ping\n\n");
                    // Reset the browser connection so the next heartbeat fails to write.
                    let linger = libc::linger {
                        l_onoff: 1,
                        l_linger: 0,
                    };
                    // SAFETY: the socket and linger value are valid for this call.
                    assert_eq!(
                        unsafe {
                            libc::setsockopt(
                                reader.get_ref().as_raw_fd(),
                                libc::SOL_SOCKET,
                                libc::SO_LINGER,
                                (&raw const linger).cast(),
                                std::mem::size_of_val(&linger) as libc::socklen_t,
                            )
                        },
                        0
                    );
                    drop(reader);
                    done.recv_timeout(Duration::from_secs(15)).unwrap();
                });
            },
        );
    }
}

#[test]
fn the_dashboard_serves_the_app_and_carries_its_api_calls() {
    let path = temp_socket();
    let _listening = start_world(&path);
    let world = format!("unix:{path}");
    let token_file = format!("{path}.token");
    std::fs::write(&token_file, "dashboard-test-token\n").unwrap();
    let mut child = Command::new(BIN)
        .args([
            "dashboard",
            "--world",
            &world,
            "--listen",
            "127.0.0.1:0",
            "--token-file",
            &token_file,
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    let port: u16 = line
        .trim_end()
        .rsplit(':')
        .next()
        .unwrap()
        .trim_end_matches('/')
        .parse()
        .unwrap();

    std::fs::remove_file(&token_file).unwrap();
    for route in [
        "/api/keylog",
        "/api/graph",
        "/api/watch",
        "/api/packets?link=e1",
        "/api/packet?link=e1&seq=1",
        "/api/pcap",
        "/api/bootstrap",
    ] {
        assert!(raw_get(port, route, "").starts_with("HTTP/1.1 401"));
        assert!(
            raw_get(
                port,
                route,
                "Cookie: fictionet_token=dashboard-test-token\r\n"
            )
            .starts_with("HTTP/1.1 401")
        );
        assert!(
            raw_get(port, route, "Authorization: Bearer wrong\r\n").starts_with("HTTP/1.1 401")
        );
    }
    // A coalesced request or body suffix cannot supply the first request's headers.
    for suffix in [
        "Authorization: Bearer dashboard-test-token\r\nCookie: fictionet_token=dashboard-test-token\r\nHost: localhost\r\nOrigin: http://localhost\r\nSec-Fetch-Site: same-origin\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer dashboard-test-token\r\nCookie: fictionet_token=dashboard-test-token\r\nOrigin: http://localhost\r\nSec-Fetch-Site: same-origin\r\n\r\n",
    ] {
        for (headers, status) in [
            ("Host: localhost\r\n", "401"),
            (
                "Host: evil.example\r\nAuthorization: Bearer dashboard-test-token\r\n",
                "403",
            ),
            (
                "Host: localhost\r\nAuthorization: Bearer dashboard-test-token\r\nOrigin: http://evil.example\r\nSec-Fetch-Site: cross-site\r\n",
                "403",
            ),
        ] {
            let response = raw_request(
                port,
                &format!("GET /api/keylog HTTP/1.1\r\n{headers}\r\n{suffix}"),
            );
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}")),
                "{response}"
            );
            assert_eq!(response.matches("HTTP/1.1 ").count(), 1);
        }
    }
    for route in ["/", "/index.html", "/app.mjs", "/transport.mjs", "/app.css"] {
        let shell = raw_get(port, route, "");
        assert!(shell.starts_with("HTTP/1.1 200"), "{shell}");
        if matches!(route, "/" | "/index.html") {
            assert!(shell.contains("Set-Cookie: fictionet_token=; Path=/; Max-Age=0;"));
        } else {
            assert!(!shell.contains("Set-Cookie:"));
        }
        assert!(!shell.contains("dashboard-test-token"));
    }
    assert!(
        raw_get(port, "/api/bootstrap?token=dashboard-test-token", "").starts_with("HTTP/1.1 401")
    );
    let bootstrap = raw_get(
        port,
        "/api/bootstrap",
        "Authorization: Bearer dashboard-test-token\r\n",
    );
    assert!(bootstrap.starts_with("HTTP/1.1 204"), "{bootstrap}");
    assert!(!bootstrap.contains("Set-Cookie:"));
    assert!(!bootstrap.contains("dashboard-test-token"));
    assert!(
        raw_get(
            port,
            "/api/bootstrap",
            "Authorization: Bearer dashboard-test-token\r\n"
        )
        .starts_with("HTTP/1.1 401")
    );
    assert!(raw_get(port, "/login?token=dashboard-test-token", "").starts_with("HTTP/1.1 401"));
    // Another port on the same host is a different browser origin.
    assert!(
        raw_request(
            port,
            &format!(
                "GET /api/keylog HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer dashboard-test-token\r\nOrigin: http://127.0.0.1:{}\r\n\r\n",
                if port == 9000 { 9001 } else { 9000 }
            )
        )
        .starts_with("HTTP/1.1 403")
    );
    assert!(
        raw_get(
            port,
            "/api/keylog",
            "Authorization: Bearer dashboard-test-token\r\nOrigin: http://other.example\r\n"
        )
        .starts_with("HTTP/1.1 403")
    );
    let (status, body) = get(port, "/");
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert!(body.contains("app.mjs"));
    assert_eq!(get(port, "/app.mjs").0, "HTTP/1.1 200 OK");

    // An API call becomes an observe request.
    let (status, body) = get(port, "/api/graph");
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert!(body.contains(r#""kind":"world""#), "{body}");
    let (status, body) = get(port, "/api/packet?link=e999&seq=1");
    assert_eq!(status, "HTTP/1.1 404 Not Found");
    assert!(body.starts_with(r#"{"error":"#));

    // A stream comes back as server-sent events.
    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(conn, "GET /api/watch HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer dashboard-test-token\r\n\r\n").unwrap();
    let mut events = BufReader::new(conn);
    let mut seen = Vec::new();
    while seen.len() < 4 {
        let mut l = String::new();
        if events.read_line(&mut l).unwrap() == 0 {
            break;
        }
        if let Some(name) = l.strip_prefix("event: ") {
            seen.push(name.trim().to_owned());
        }
    }
    assert_eq!(seen[0], "snapshot");
    assert!(seen.iter().any(|e| e == "event"), "{seen:?}");

    // A page on another site cannot read it through a name of its own.
    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        conn,
        "GET /api/graph HTTP/1.1\r\nHost: attacker.example:{port}\r\n\r\n"
    )
    .unwrap();
    let mut all = String::new();
    conn.read_to_string(&mut all).unwrap();
    assert!(all.starts_with("HTTP/1.1 403"));

    child.kill().unwrap();
    child.wait().unwrap();
}

/// A world with two links that each carry a packet every 20 ms.
fn start_two_links(path: &str) -> fictionet::Listening {
    use fictionet::Interface;
    use fictionet::prelude::*;
    let (attacher, mut attachments) = fictionet::attachments();
    let listening =
        fictionet::listen(fictionet::WorldSocket::UnixSocket(path.into()), attacher).unwrap();
    let (ready, started) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            move |fcx| async move {
                // Observers find a world once it takes attachments.
                fcx.spawn(move |fcx| async move {
                    while let Ok(a) = attachments.next(&fcx).await {
                        drop(a);
                    }
                    Ok(())
                });
                let lan = fcx.group("lan");
                for _ in 0..2 {
                    let (mut a, mut b) = fictionet::pair();
                    lan.spawn(move |fcx| async move {
                        while let Ok(p) = b.recv(&fcx).await {
                            b.send(p);
                        }
                        Ok(())
                    });
                    fcx.spawn(move |fcx| async move {
                        loop {
                            // An IPv4 header with nothing after it.
                            let p = vec![
                                0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
                            ];
                            a.send(fictionet::Packet(p));
                            a.recv(&fcx).await?;
                            fcx.sleep(fictionet::time::ms(20)).await?;
                        }
                    });
                }
                fcx.idle().await?;
                ready.send(()).unwrap();
                Ok(())
            },
        ));
    });
    started.recv_timeout(Duration::from_secs(10)).unwrap();
    listening
}

/// `packets` and `pcap` for several links: one stream of all their
/// packets, each with its link, and one file with a section for each.
#[test]
fn the_dashboard_merges_the_packets_of_several_links() {
    let path = temp_socket();
    let token_file = format!("{path}.token");
    std::fs::write(&token_file, "dashboard-test-token\n").unwrap();
    let _listening = start_two_links(&path);
    let world = format!("unix:{path}");
    /// Stops the dashboard however the test ends.
    struct Stop(std::process::Child);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Stop(
        Command::new(BIN)
            .args([
                "dashboard",
                "--world",
                &world,
                "--listen",
                "127.0.0.1:0",
                "--token-file",
                &token_file,
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut out = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    let port: u16 = line
        .trim_end()
        .rsplit(':')
        .next()
        .unwrap()
        .trim_end_matches('/')
        .parse()
        .unwrap();
    std::fs::remove_file(&token_file).unwrap();
    assert_eq!(get(port, "/groups.mjs").0, "HTTP/1.1 200 OK");

    // The two links, and the group their echo tasks are in.
    let graph = get(port, "/api/graph").1;
    assert!(graph.contains(r#""name":"lan","parent":null"#), "{graph}");
    let links: Vec<String> = graph
        .split(r#"{"id":"e"#)
        .skip(1)
        .map(|r| format!("e{}", r.split('"').next().unwrap()))
        .collect();
    assert_eq!(links.len(), 2, "{graph}");
    let both = links.join(",");

    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        conn,
        "GET /api/packets?link={both} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer dashboard-test-token\r\n\r\n"
    )
    .unwrap();
    let mut events = BufReader::new(conn);
    let mut from = std::collections::HashSet::new();
    let mut packets = 0;
    while from.len() < 2 || packets < 6 {
        let mut l = String::new();
        if events.read_line(&mut l).unwrap() == 0 {
            break;
        }
        if let Some(data) = l.strip_prefix("data: ")
            && data.contains(r#""seq":"#)
        {
            packets += 1;
            assert!(data.contains(r#""evicted":0"#), "{data}");
            let link = data
                .split(r#""link":""#)
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
                .to_owned();
            assert!(links.contains(&link), "{data}");
            from.insert(link);
        }
    }
    assert_eq!(from.len(), 2, "packets came from both links");

    // While the stream above still watches both links, the capture of both
    // holds two pcapng sections.
    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        conn,
        "GET /api/pcap?link={both} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer dashboard-test-token\r\n\r\n"
    )
    .unwrap();
    let mut all = Vec::new();
    conn.read_to_end(&mut all).unwrap();
    let head_end = all.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert!(
        all.starts_with(b"HTTP/1.1 200 OK"),
        "{}",
        String::from_utf8_lossy(&all[..head_end])
    );
    let body = &all[head_end..];
    let sections = body
        .windows(4)
        .filter(|w| *w == [0x0a, 0x0d, 0x0d, 0x0a])
        .count();
    assert!(body.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]));
    assert!(sections >= 2, "{sections} section headers");
    drop(child);
}

fn two_dashboard_links(port: u16) -> Vec<String> {
    let graph = get(port, "/api/graph").1;
    let links: Vec<String> = graph
        .split(r#"{"id":"e"#)
        .skip(1)
        .map(|r| format!("e{}", r.split('"').next().unwrap()))
        .collect();
    assert_eq!(links.len(), 2, "{graph}");
    links
}

/// Checks that a failed download carries JSON, with no partial capture.
fn capture_failure(port: u16, links: &str) -> String {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        conn,
        "GET /api/pcap?link={links} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer dashboard-test-token\r\n\r\n"
    )
    .unwrap();
    let mut all = Vec::new();
    conn.read_to_end(&mut all).unwrap();
    let head_end = all.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let head = std::str::from_utf8(&all[..head_end]).unwrap();
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");
    assert!(head.lines().any(|l| l == "Content-Type: application/json"));
    let body = &all[head_end..];
    assert!(!body.windows(4).any(|w| w == [0x0a, 0x0d, 0x0d, 0x0a]));
    String::from_utf8(body.to_vec()).unwrap()
}

#[test]
fn the_dashboard_fails_a_capture_when_the_second_link_is_not_watched() {
    let path = temp_socket();
    let _listening = start_two_links(&path);
    with_dashboard(&path, |port| {
        let links = two_dashboard_links(port);
        let mut events = sse_connection(port, &format!("/api/packets?link={}", links[0]));
        while !sse_frame(&mut events).starts_with("event: packet\n") {}

        let body = capture_failure(port, &links.join(","));
        assert_eq!(
            body,
            format!(
                r#"{{"error":"no capture for {0}","links":[{{"link":"{0}","error":"nothing is watching that link"}}]}}"#,
                links[1]
            )
        );
        drop(events);
    });
}

#[test]
fn the_dashboard_fails_a_capture_when_a_requested_link_does_not_exist() {
    let path = temp_socket();
    let _listening = start_two_links(&path);
    with_dashboard(&path, |port| {
        let links = two_dashboard_links(port);
        let streams: Vec<_> = links
            .iter()
            .map(|link| {
                let mut events = sse_connection(port, &format!("/api/packets?link={link}"));
                while !sse_frame(&mut events).starts_with("event: packet\n") {}
                events
            })
            .collect();

        let body = capture_failure(port, &format!("{},e999", links.join(",")));
        assert_eq!(
            body,
            r#"{"error":"no capture for e999","links":[{"link":"e999","error":"nothing is watching that link"}]}"#
        );
        drop(streams);
    });
}

#[test]
fn the_dashboard_names_every_failed_capture_and_preserves_unexpected_replies() {
    use fictionet::relay::END;

    for (reply, error) in [
        (
            r#" { "error": "missing \"capture\"\n" } "#,
            r#""missing \"capture\"\u000a""#,
        ),
        (r#"{"error":false}"#, r#""{\"error\":false}""#),
        (r#"{"error":"truncated""#, r#""{\"error\":\"truncated\"""#),
    ] {
        with_observer(&[(END, reply.as_bytes())], 2, |path| {
            with_dashboard(path, |port| {
                let body = capture_failure(port, "e3,e7");
                assert_eq!(
                    body,
                    format!(
                        r#"{{"error":"no capture for e3, e7","links":[{{"link":"e3","error":{error}}},{{"link":"e7","error":{error}}}]}}"#
                    )
                );
            });
        });
    }
}

/// A watch on a world that ends normally exits 0, after printing `ended`
/// and the stream's end.
#[test]
fn a_watch_exits_0_when_the_world_ends() {
    let path = temp_socket();
    let world = format!("unix:{path}");
    let (attacher, mut attachments) = fictionet::attachments();
    let listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(path.clone().into()),
        attacher,
    )
    .unwrap();
    let mut child = Command::new(BIN)
        .args(["observe", "--world", &world, "watch"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    // The world returns once the observer has its snapshot.
    let (stop, mut stopped) = fictionet::pair();
    let world_thread = std::thread::spawn(move || {
        let _ = fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            move |fcx| async move {
                fcx.spawn(move |fcx| async move {
                    while let Ok(a) = attachments.next(&fcx).await {
                        drop(a);
                    }
                    Ok(())
                });
                assert_eq!(stopped.recv(&fcx).await, Err(fictionet::RecvError::Closed));
                // Ends the run, with the task above.
                fcx.cancel();
                Ok(())
            },
        ));
        drop(listening);
    });
    let log = logged(child.stdout.take().unwrap(), r#""event":"snapshot""#);
    drop(stop);
    let status = crate::common::within(Duration::from_secs(20), move || child.wait().unwrap());
    world_thread.join().unwrap();
    let out = log.join().unwrap();
    assert_eq!(status.code(), Some(0), "{out}");
    assert!(out.contains(r#"{"event":"ended","#), "{out}");
    assert!(
        out.trim_end()
            .ends_with(r#"{"event":"end","data":{"reason":"the world ended"}}"#),
        "{out}"
    );
}

#[test]
fn observe_partial_frame_after_ended_is_an_error() {
    use fictionet::relay::MORE;

    let ended_value = br#"{"event":"ended","data":{}}"#;
    for (ended, partial) in [(true, false), (true, true), (false, true)] {
        let mut replies = Vec::new();
        if ended {
            replies.push((0, ended_value.as_slice()));
        }
        if partial {
            replies.push((MORE, br#"{"event":"end","data":"#.as_slice()));
        }
        with_observer(&replies, 1, |path| {
            let out = Command::new(BIN)
                .args(["observe", "--world", &format!("unix:{path}"), "watch"])
                .output()
                .unwrap();
            assert_eq!(
                out.status.code(),
                Some(if partial { 1 } else { 0 }),
                "{out:?}"
            );
            if partial {
                assert!(
                    String::from_utf8_lossy(&out.stderr).contains("during a reply value"),
                    "{out:?}"
                );
            } else {
                assert!(out.stderr.is_empty(), "{out:?}");
            }
            let expected = if ended {
                [ended_value.as_slice(), b"\n"].concat()
            } else {
                Vec::new()
            };
            assert_eq!(out.stdout, expected, "only whole values reach stdout");
        });
    }
}

fn raw_get(port: u16, path: &str, headers: &str) -> String {
    raw_request(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n"),
    )
}

fn raw_request(port: u16, request: &str) -> String {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    conn.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    conn.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn version_reports_the_package_version() {
    let out = Command::new(BIN).arg("--version").output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("fictionet {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn dashboard_requires_a_readable_valid_token_file() {
    let path = format!("{}.token", temp_socket());
    for invalid in [b"\n".as_slice(), b"two words", &[b'x'; 256]] {
        std::fs::write(&path, invalid).unwrap();
        let out = Command::new(BIN)
            .args([
                "dashboard",
                "--world",
                "unix:/nonexistent-world",
                "--token-file",
                &path,
            ])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("the token file"));
    }
    std::fs::remove_file(path).unwrap();
    for extra in [vec![], vec!["--token-file", "/nonexistent-fictionet-token"]] {
        let out = Command::new(BIN)
            .args(["dashboard", "--world", "unix:/nonexistent-world"])
            .args(extra)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("token"));
    }
}
