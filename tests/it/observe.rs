//! The observe API, spoken over a real world socket with no UI: a world
//! with one sandbox, and an observer asking for the graph, following its
//! changes and custom events, and watching a link's packets.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use crate::common::temp;

use fictionet::Interface;
use fictionet::prelude::*;
use fictionet::relay::observer::{Client, Value};
use fictionet::relay::{self, Hello, Message, unix};

fn observer_connection<T: Send + 'static>(
    path: &str,
    connect: impl FnOnce() -> T + Send + 'static,
) -> (std::thread::JoinHandle<T>, OwnedFd) {
    let (addr, len) = unix::address(std::path::Path::new(path)).unwrap();
    // SAFETY: the socket is owned from here; addr is valid for len bytes.
    let listener = unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0);
        assert!(fd >= 0);
        let listener = OwnedFd::from_raw_fd(fd);
        assert_eq!(libc::bind(fd, (&raw const addr).cast(), len), 0);
        assert_eq!(libc::listen(fd, 1), 0);
        listener
    };
    let thread = std::thread::spawn(connect);
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
    (thread, peer)
}

fn observer_peer(greeting: &[u8]) -> (Result<Client, String>, OwnedFd) {
    let path = temp::socket();
    let client_path = path.clone();
    let (thread, peer) =
        observer_connection(&path, move || Client::connect(&client_path, "frame-limit"));
    for option in [libc::SO_SNDTIMEO, libc::SO_RCVTIMEO] {
        unix::set_timeout(peer.as_raw_fd(), option, Some(Duration::from_secs(5))).unwrap();
    }
    let mut buf = vec![0; relay::MAX_MESSAGE + 1];
    let n = unix::recv(peer.as_raw_fd(), &mut buf, false).unwrap();
    assert!(matches!(relay::decode(&buf[..n]), Ok(Message::Hello(_))));
    unix::send(peer.as_raw_fd(), greeting, false).unwrap();
    let client = thread.join().unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(std::path::Path::new(&path).parent().unwrap()).unwrap();
    (client, peer)
}

#[test]
fn observer_accepts_a_reply_at_the_message_limit() {
    let (client, peer) = observer_peer(&Message::Accept.encode());
    let mut client = client.unwrap();
    client.set_timeout(Some(Duration::from_secs(5))).unwrap();
    let body = vec![42; relay::MAX_REPLY_CHUNK];
    let frame = Message::Reply {
        id: 7,
        flags: relay::BINARY | relay::END,
        body: &body,
    }
    .encode();
    assert_eq!(frame.len(), relay::MAX_MESSAGE);
    unix::send(peer.as_raw_fd(), &frame, false).unwrap();
    let value = client.next_value().unwrap().unwrap();
    assert_eq!(value.id, 7);
    assert_eq!(value.bytes, body);
    assert!(value.binary && value.end);
}

#[test]
fn observer_resumes_partial_values_after_receive_timeouts() {
    for binary in [0, relay::BINARY] {
        for end in [0, relay::END] {
            let (client, peer) = observer_peer(&Message::Accept.encode());
            let mut client = client.unwrap();
            client.set_timeout(Some(Duration::from_millis(20))).unwrap();
            for body in [b"first".as_slice(), b" middle"] {
                let frame = Message::Reply {
                    id: 7,
                    flags: binary | relay::MORE,
                    body,
                }
                .encode();
                unix::send(peer.as_raw_fd(), &frame, false).unwrap();
                for _ in 0..2 {
                    assert!(matches!(
                        client.next_value().unwrap_err().kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ));
                }
            }
            let frame = Message::Reply {
                id: 7,
                flags: binary | end,
                body: b" last",
            }
            .encode();
            unix::send(peer.as_raw_fd(), &frame, false).unwrap();
            let value = client.next_value().unwrap().unwrap();
            assert_eq!(value.id, 7);
            assert_eq!(value.bytes, b"first middle last");
            assert_eq!(value.binary, binary != 0);
            assert_eq!(value.end, end != 0);

            let frame = Message::Reply {
                id: 8,
                flags: relay::END,
                body: b"{}",
            }
            .encode();
            unix::send(peer.as_raw_fd(), &frame, false).unwrap();
            let value = client.next_value().unwrap().unwrap();
            assert_eq!(value.id, 8);
            assert_eq!(value.bytes, b"{}");
            assert!(!value.binary && value.end);
            drop(peer);
            assert!(client.next_value().unwrap().is_none());
        }
    }
}

#[test]
fn observer_rejects_invalid_reply_flags_and_continuations() {
    for first in [None, Some(0), Some(relay::BINARY)] {
        let mut invalid = vec![(7, relay::MORE | relay::END), (7, 8)];
        if let Some(binary) = first {
            invalid.extend([
                (8, binary | relay::END),
                (7, (binary ^ relay::BINARY) | relay::END),
            ]);
        }
        for (id, flags) in invalid {
            let (client, peer) = observer_peer(&Message::Accept.encode());
            let mut client = client.unwrap();
            client.set_timeout(Some(Duration::from_millis(20))).unwrap();
            if let Some(binary) = first {
                let frame = Message::Reply {
                    id: 7,
                    flags: binary | relay::MORE,
                    body: b"first",
                }
                .encode();
                unix::send(peer.as_raw_fd(), &frame, false).unwrap();
                assert!(matches!(
                    client.next_value().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ));
            }
            let frame = Message::Reply {
                id,
                flags,
                body: b"last",
            }
            .encode();
            unix::send(peer.as_raw_fd(), &frame, false).unwrap();
            assert_eq!(
                client.next_value().unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
            assert_eq!(unix::recv(peer.as_raw_fd(), &mut [0; 1], false).unwrap(), 0);
            assert!(client.next_value().unwrap().is_none());
        }
    }
}

#[test]
fn observer_reports_eof_during_a_value() {
    for timeout in [false, true] {
        let (client, peer) = observer_peer(&Message::Accept.encode());
        let mut client = client.unwrap();
        client.set_timeout(Some(Duration::from_millis(20))).unwrap();
        let frame = Message::Reply {
            id: 7,
            flags: relay::MORE,
            body: b"first",
        }
        .encode();
        unix::send(peer.as_raw_fd(), &frame, false).unwrap();
        if timeout {
            assert!(matches!(
                client.next_value().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ));
        }
        drop(peer);
        assert_eq!(
            client.next_value().unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert!(client.next_value().unwrap().is_none());
    }
}

#[test]
fn observer_closes_on_oversized_or_truncated_replies() {
    for extra in [1, 2] {
        let (client, peer) = observer_peer(&Message::Accept.encode());
        let mut client = client.unwrap();
        client.set_timeout(Some(Duration::from_secs(5))).unwrap();
        let frame = Message::Reply {
            id: 7,
            flags: relay::BINARY | relay::END,
            body: &vec![42; relay::MAX_REPLY_CHUNK + extra],
        }
        .encode();
        unix::send(peer.as_raw_fd(), &frame, false).unwrap();
        let error = client.next_value().unwrap_err();
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidData,
            "{extra} bytes over the limit"
        );
        assert_eq!(
            error.to_string(),
            "the world sent a message longer than 65,536 bytes"
        );
        assert_eq!(unix::recv(peer.as_raw_fd(), &mut [0; 1], false).unwrap(), 0);
    }
}

#[test]
fn observer_closes_on_malformed_replies() {
    let (client, peer) = observer_peer(&Message::Accept.encode());
    let mut client = client.unwrap();
    client.set_timeout(Some(Duration::from_secs(5))).unwrap();
    unix::send(peer.as_raw_fd(), &[relay::REPLY], false).unwrap();
    assert_eq!(
        client.next_value().unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(unix::recv(peer.as_raw_fd(), &mut [0; 1], false).unwrap(), 0);
}

#[test]
fn observer_rejects_oversized_or_truncated_greetings() {
    for extra in [1, 2] {
        let greeting = Message::Refuse("x".repeat(relay::MAX_MESSAGE - 1 + extra)).encode();
        let (client, peer) = observer_peer(&greeting);
        let error = client.err().unwrap();
        assert_eq!(error, "the world sent a message longer than 65,536 bytes");
        assert_eq!(unix::recv(peer.as_raw_fd(), &mut [0; 1], false).unwrap(), 0);
    }
}

#[test]
fn an_observer_times_out_when_an_accepted_connection_never_answers_hello() {
    let path = temp::socket();
    let (tx, rx) = std::sync::mpsc::channel();
    let client_path = path.clone();
    let (thread, peer) = observer_connection(&path, move || {
        tx.send(Client::connect(&client_path, "silent-peer").err())
            .unwrap();
    });
    unix::set_timeout(
        peer.as_raw_fd(),
        libc::SO_RCVTIMEO,
        Some(Duration::from_secs(5)),
    )
    .unwrap();
    let mut buf = vec![0; relay::MAX_MESSAGE];
    let n = unix::recv(peer.as_raw_fd(), &mut buf, false).unwrap();
    assert!(matches!(relay::decode(&buf[..n]), Ok(Message::Hello(_))));
    let result = rx.recv_timeout(relay::HANDSHAKE_TIMEOUT + Duration::from_secs(10));
    drop(peer);
    thread.join().unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(std::path::Path::new(&path).parent().unwrap()).unwrap();
    assert_eq!(
        result.unwrap().as_deref(),
        Some("the observer hello handshake timed out")
    );
}

/// Starts a world on `path` that echoes every sandbox's packets through a
/// task of its own, and emits an `echo` event for each.
fn start_world(path: &str) -> fictionet::Listening {
    let (attacher, mut attachments) = fictionet::attachments();
    let listening =
        fictionet::listen(fictionet::WorldSocket::UnixSocket(path.into()), attacher).unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            move |fcx| async move {
                fcx.spawn(move |fcx| async move {
                    while let Ok(mut sandbox) = attachments.next(&fcx).await {
                        fcx.spawn(move |fcx| async move {
                            let (mut mine, mut theirs) = fictionet::pair();
                            fcx.spawn(move |fcx| async move {
                                while let Ok(p) = theirs.recv(&fcx).await {
                                    fcx.record(
                                        fictionet::events::Event::new("test", "echo")
                                            .field("len", p.0.len() as u64),
                                    );
                                    theirs.send(p);
                                }
                                Ok(())
                            });
                            while let Ok(p) = sandbox.recv(&fcx).await {
                                mine.send(p);
                                let back = mine.recv(&fcx).await?;
                                sandbox.send(back);
                            }
                            Ok(())
                        });
                    }
                    Ok(())
                });
                fcx.idle().await?;
                ready_tx.send(()).unwrap();
                Ok(())
            },
        ));
    });
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    listening
}

/// Attaches a sandbox called `name` by speaking the relay protocol, and
/// sends one ping per command. Dropping the sender detaches it.
fn start_sandbox(
    path: &str,
    name: &str,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let fd = unix::connect(path).unwrap();
    let hello = Hello {
        version: relay::VERSION,
        mtu: 1500,
        kind: "tun".into(),
        name: name.into(),
    };
    unix::send(fd.as_raw_fd(), &Message::Hello(hello).encode(), false).unwrap();
    let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
    let n = unix::recv(fd.as_raw_fd(), &mut buf, false).unwrap();
    assert_eq!(relay::decode(&buf[..n]), Ok(Message::Accept));
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let fd: OwnedFd = fd;
        let mut seq = 0u16;
        while receive.recv().is_ok() {
            let mut ping = vec![
                0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1, 8, 0, 0, 0,
                0x12, 0x34,
            ];
            ping.extend_from_slice(&seq.to_be_bytes());
            unix::send(fd.as_raw_fd(), &Message::Packet(&ping).encode(), false).unwrap();
            assert!(unix::recv(fd.as_raw_fd(), &mut buf, false).unwrap() > 0);
            seq = seq.wrapping_add(1);
        }
    });
    (send, thread)
}

fn text(v: &Value) -> String {
    String::from_utf8(v.bytes.clone()).unwrap()
}

/// Reads values until `want` matches one, for at most ten seconds.
#[track_caller]
fn until(client: &mut Client, mut want: impl FnMut(&Value) -> bool) -> Vec<Value> {
    let start = Instant::now();
    let mut seen = Vec::new();
    while start.elapsed() < Duration::from_secs(10) {
        let Ok(Some(v)) = client.next_value() else {
            break;
        };
        let done = want(&v);
        seen.push(v);
        if done {
            return seen;
        }
    }
    panic!(
        "never got the value; saw {:?}",
        seen.iter().map(text).collect::<Vec<_>>()
    );
}

/// The number of the first edge in `json` that ends at a sandbox: an
/// object `{"id":"e<n>",...,"b":"s<m>",...}`.
fn sandbox_edge_in(json: &str) -> Option<u64> {
    json.match_indices(r#"{"id":"e"#).find_map(|(at, _)| {
        let edge = &json[at..at + json[at..].find('}')?];
        edge.contains(r#""b":"s"#).then(|| {
            edge[8..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .ok()
        })?
    })
}

/// The number after `"key":` in `json`.
fn number_after(json: &str, key: &str) -> u64 {
    let at = json
        .find(&format!("\"{key}\":"))
        .unwrap_or_else(|| panic!("no {key} in {json}"))
        + key.len()
        + 3;
    json[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap()
}

#[test]
fn an_observer_sees_the_graph_its_changes_events_and_packets() {
    let path = temp::socket();
    let _listening = start_world(&path);
    let mut client = Client::connect(&path, "test").unwrap();
    client.set_timeout(Some(Duration::from_secs(10))).unwrap();

    // The world says which API it speaks.
    let world = client.call(r#"{"op":"world"}"#).unwrap();
    assert!(world.end && !world.binary);
    assert!(
        text(&world).starts_with(r#"{"observe":1,"#),
        "{}",
        text(&world)
    );
    assert!(text(&client.call(r#"{"op":"world"}"#).unwrap()).contains(r#""running":true"#));

    // Follow the graph, then attach a sandbox: it shows up as a node with
    // an edge, its counters rise, and the echo task's events arrive.
    let watch = client.request(r#"{"op":"watch"}"#).unwrap();
    let (ping, sandbox) = start_sandbox(&path, "agent");
    let mut sandbox_edge = None;
    let (mut counters, mut echoes) = (0, 0);
    let seen = until(&mut client, |v| {
        let t = text(v);
        assert_eq!(v.id, watch);
        assert!(!v.end);
        // The sandbox may attach before the snapshot is taken, so its edge
        // arrives either in the snapshot or as an edge event.
        if t.starts_with(r#"{"event":"edge""#) || t.starts_with(r#"{"event":"snapshot""#) {
            sandbox_edge = sandbox_edge.or_else(|| sandbox_edge_in(&t));
        }
        if t.starts_with(r#"{"event":"snapshot""#) {
            ping.send(()).unwrap();
        } else if t.starts_with(r#"{"event":"counters""#) {
            counters += 1;
            if counters < 2 {
                ping.send(()).unwrap();
            }
        }
        if t.starts_with(r#"{"event":"event""#)
            && t.contains(r#""source":"test","kind":"echo","#)
            && t.contains(r#""fields":{"len":28}"#)
        {
            echoes += 1;
        }
        sandbox_edge.is_some() && counters >= 2 && echoes >= 1
    });
    assert!(text(&seen[0]).starts_with(r#"{"event":"snapshot""#));
    assert!(
        seen.iter()
            .any(|v| text(v).contains(r#""kind":"sandbox","name":"agent""#))
    );
    let edge = sandbox_edge.unwrap();

    // One-off requests answer at once, alongside the subscription.
    let graph = client.call(r#"{"op":"graph"}"#);
    // A reply to the watch may come first; skip those.
    let graph = match graph {
        Ok(v) if v.id == watch => until(&mut client, |v| v.id != watch).pop().unwrap(),
        other => other.unwrap(),
    };
    assert!(
        text(&graph).contains(r#""file":"tests/it/observe.rs""#),
        "{}",
        text(&graph)
    );
    assert!(graph.end);

    // Stop following the graph. Its last reply says why, and ends it.
    let cancel = client
        .request(&format!(r#"{{"op":"cancel","id":{watch}}}"#))
        .unwrap();
    let mut ended = false;
    until(&mut client, |v| {
        if v.id == watch && v.end {
            assert_eq!(text(v), r#"{"event":"end","data":{"reason":"cancelled"}}"#);
            ended = true;
        }
        v.id == cancel
    });
    assert!(ended);

    // The world kept its events with no one watching. A late observer
    // reads them in one call, or replays the log from its start with
    // `watch`, then follows it.
    let events = text(&client.call(r#"{"op":"events","after":0,"max":2}"#).unwrap());
    assert!(
        events.starts_with(r#"{"events":[{"seq":1,"#)
            && events.contains(r#""seq":2,"#)
            && !events.contains(r#""seq":3,"#),
        "{events}"
    );
    let replay = client.request(r#"{"op":"watch","after":0}"#).unwrap();
    let seen = until(&mut client, |v| {
        v.id == replay && text(v).starts_with(r#"{"event":"event""#)
    });
    assert!(
        text(&seen[0]).contains(r#""events":[]"#),
        "{}",
        text(&seen[0])
    );
    assert!(
        text(seen.last().unwrap()).starts_with(r#"{"event":"event","data":{"seq":1,"#),
        "{}",
        text(seen.last().unwrap())
    );
    let cancel = client
        .request(&format!(r#"{{"op":"cancel","id":{replay}}}"#))
        .unwrap();
    until(&mut client, |v| v.id == cancel);

    // Watch the sandbox's link: its packets come decoded.
    let packets = client
        .request(&format!(r#"{{"op":"packets","link":"e{edge}"}}"#))
        .unwrap();
    let seen = until(&mut client, |v| {
        if v.id == packets && text(v).starts_with(r#"{"event":"link""#) {
            ping.send(()).unwrap();
        }
        v.id == packets && text(v).starts_with(r#"{"event":"packet""#)
    });
    let link = seen.iter().find(|v| v.id == packets).unwrap();
    assert!(
        text(link).starts_with(r#"{"event":"link""#),
        "{}",
        text(link)
    );
    let packet = text(seen.last().unwrap());
    assert!(
        packet.contains(r#""proto":"ICMP""#) && packet.contains("Echo (ping) request id=0x1234"),
        "{packet}"
    );
    let seq = number_after(&packet, "seq");
    assert_eq!(number_after(&packet, "evicted"), 0);

    // Its layers and bytes.
    client
        .request(&format!(
            r#"{{"op":"packet","link":"e{edge}","seq":{seq}}}"#
        ))
        .unwrap();
    let detail = until(&mut client, |v| v.id != packets).pop().unwrap();
    let detail = text(&detail);
    assert!(
        detail.contains("Internet Control Message Protocol"),
        "{detail}"
    );
    assert!(detail.contains(r#""hex":"4500001c"#), "{detail}");

    // The capture, as pcapng bytes.
    client
        .request(&format!(r#"{{"op":"pcap","link":"e{edge}"}}"#))
        .unwrap();
    let pcap = until(&mut client, |v| v.id != packets).pop().unwrap();
    assert!(pcap.binary && pcap.end);
    assert_eq!(&pcap.bytes[..4], &[0x0a, 0x0d, 0x0d, 0x0a]);

    // Mistakes get an error, and the session goes on.
    client.request(r#"{"op":"fly"}"#).unwrap();
    let err = until(&mut client, |v| v.id != packets).pop().unwrap();
    assert_eq!(text(&err), r#"{"error":"unknown op fly"}"#);

    // When the sandbox leaves, its link closes and the packet stream ends.
    drop(ping);
    sandbox.join().unwrap();
    let last = until(&mut client, |v| v.id == packets && v.end)
        .pop()
        .unwrap();
    assert_eq!(
        text(&last),
        r#"{"event":"end","data":{"reason":"the link closed"}}"#
    );
}

#[test]
fn observer_session_capacity_counts_idle_clients_and_reuses_slots() {
    let path = temp::socket();
    let (attacher, _attachments) = fictionet::attachments();
    let listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(path.clone().into()),
        attacher,
    )
    .unwrap();
    listening.set_observer_limit(2);
    let mut first = Client::connect(&path, "first").unwrap();
    first.set_timeout(Some(Duration::from_secs(5))).unwrap();
    let second = Client::connect(&path, "second").unwrap();
    let refusal = "the world refused: this listener has too many observer sessions";
    for _ in 0..3 {
        assert_eq!(
            Client::connect(&path, "excess").err().as_deref(),
            Some(refusal)
        );
    }
    drop(start_sandbox(&path, "agent"));
    assert!(text(&first.call(r#"{"op":"world"}"#).unwrap()).contains(r#""running":false"#));
    drop(second);
    let mut reused = None;
    crate::common::poll::until(
        Duration::from_secs(5),
        "disconnected observer slot to be released",
        || match Client::connect(&path, "reused") {
            Ok(client) => {
                reused = Some(client);
                true
            }
            Err(reason) => {
                assert_eq!(reason, refusal);
                false
            }
        },
    );
    let mut reused = reused.unwrap();
    reused.set_timeout(Some(Duration::from_secs(5))).unwrap();
    listening.set_observer_limit(0);
    assert_eq!(
        Client::connect(&path, "disabled").err().as_deref(),
        Some(refusal)
    );
    assert!(reused.call(r#"{"op":"world"}"#).unwrap().end);
    assert!(first.call(r#"{"op":"world"}"#).unwrap().end);
}

#[test]
fn watch_capacity_errors_preserve_shared_streams_and_cancel_frees_admission() {
    let path = temp::socket();
    let (attacher, mut attachments) = fictionet::attachments();
    let _listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(path.clone().into()),
        attacher,
    )
    .unwrap();
    let mut world = std::pin::pin!(fictionet::run(
        fictionet::Seed::from_u64(1),
        move |fcx| async move {
            fcx.set_observe_watch_limit(1);
            let mut links = Vec::new();
            for (end, mut other) in [fictionet::pair(), fictionet::pair()] {
                end.observe_link().unwrap().label(&fcx, "test".into());
                fcx.spawn(move |fcx| async move {
                    other.recv(&fcx).await?;
                    Ok(())
                });
                links.push(end);
            }
            attachments.next(&fcx).await?;
            drop(links);
            Ok(())
        }
    ));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    // Start the world, then its endpoint tasks so both links are visible.
    for _ in 0..2 {
        assert!(std::future::Future::poll(world.as_mut(), &mut cx).is_pending());
    }
    let mut first = Client::connect(&path, "first").unwrap();
    let mut second = Client::connect(&path, "second").unwrap();
    first.set_timeout(Some(Duration::from_secs(5))).unwrap();
    second.set_timeout(Some(Duration::from_secs(5))).unwrap();
    let graph = text(&first.call(r#"{"op":"graph"}"#).unwrap());
    let edges: Vec<String> = graph
        .match_indices(r#"{"id":"e"#)
        .map(|(at, _)| {
            graph[at + 8..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect()
        })
        .collect();
    assert_eq!(edges.len(), 2, "{graph}");
    let packets = |edge: &str| format!(r#"{{"op":"packets","link":"e{edge}"}}"#);
    let a = first.call(&packets(&edges[0])).unwrap();
    let b = second.call(&packets(&edges[0])).unwrap();
    assert!(!a.end && !b.end);
    assert_eq!(text(&a), text(&b));
    let refusal = r#"{"error":"this world has too many watched links"}"#;
    for _ in 0..3 {
        let refused = second.call(&packets(&edges[1])).unwrap();
        assert!(refused.end);
        assert_eq!(text(&refused), refusal);
    }
    let cancel = first
        .request(&format!(r#"{{"op":"cancel","id":{}}}"#, a.id))
        .unwrap();
    let seen = until(&mut first, |v| v.id == cancel);
    assert!(seen.iter().any(|v| v.id == a.id && v.end));
    assert_eq!(text(&first.call(&packets(&edges[1])).unwrap()), refusal);
    let cancel = second
        .request(&format!(r#"{{"op":"cancel","id":{}}}"#, b.id))
        .unwrap();
    until(&mut second, |v| v.id == cancel);
    let admitted = first.call(&packets(&edges[1])).unwrap();
    assert!(!admitted.end);
    assert!(text(&admitted).starts_with(r#"{"event":"link""#));
    let forgotten = second
        .call(&format!(r#"{{"op":"pcap","link":"e{}"}}"#, edges[0]))
        .unwrap();
    assert_eq!(
        text(&forgotten),
        r#"{"error":"nothing is watching that link"}"#
    );
}

#[test]
fn an_observer_takes_no_name() {
    let path = temp::socket();
    let _listening = start_world(&path);
    // An observer called "agent" does not stop a sandbox called "agent".
    let _a = Client::connect(&path, "agent").unwrap();
    let _b = Client::connect(&path, "agent").unwrap();
    drop(start_sandbox(&path, "agent"));
}

#[test]
fn an_observer_of_a_world_that_has_not_started_waits() {
    let path = temp::socket();
    // A socket whose world never asks for an attachment: there is no run
    // to observe yet.
    let (attacher, _attachments) = fictionet::attachments();
    let _listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(path.clone().into()),
        attacher,
    )
    .unwrap();
    let mut client = Client::connect(&path, "test").unwrap();
    client.set_timeout(Some(Duration::from_secs(10))).unwrap();
    assert!(text(&client.call(r#"{"op":"world"}"#).unwrap()).contains(r#""running":false"#));
    assert_eq!(
        text(&client.call(r#"{"op":"graph"}"#).unwrap()),
        r#"{"error":"no world is running yet"}"#
    );
    let watch = client.call(r#"{"op":"watch"}"#).unwrap();
    assert_eq!(text(&watch), r#"{"event":"waiting","data":{}}"#);
    assert!(!watch.end);
}

/// A `hello` type kept for later versions of the observe API is refused,
/// with its reason, and does not attach a sandbox.
#[test]
fn a_later_observer_type_is_refused() {
    let path = temp::socket();
    let _listening = start_world(&path);
    let fd = unix::connect(&path).unwrap();
    let hello = Hello {
        version: relay::VERSION,
        mtu: 0,
        kind: "observe2".into(),
        name: "agent".into(),
    };
    unix::send(fd.as_raw_fd(), &Message::Hello(hello).encode(), false).unwrap();
    let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
    let n = unix::recv(fd.as_raw_fd(), &mut buf, false).unwrap();
    match relay::decode(&buf[..n]) {
        Ok(Message::Refuse(reason)) => assert_eq!(reason, "unsupported observer type observe2"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    // The name was not taken.
    drop(start_sandbox(&path, "agent"));
}
