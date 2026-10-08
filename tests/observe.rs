//! The observe API, spoken over a real world socket with no UI: a world
//! with one sandbox, and an observer asking for the graph, following its
//! changes and custom events, and watching a link's packets.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use fictionet::Interface;
use fictionet::prelude::*;
use fictionet::relay::observer::{Client, Value};
use fictionet::relay::{self, Hello, Message, unix};

fn temp_socket() -> String {
    // Unix socket paths must be short, so not under a long target dir.
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fn-obs-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("world.sock").to_str().unwrap().to_owned()
}

/// Starts a world on `path` that echoes every sandbox's packets through a
/// task of its own, and emits an `echo` event for each.
fn start_world(path: &str) -> fictionet::Listening {
    let (attacher, mut attachments) = fictionet::attachments();
    let listening =
        fictionet::listen(fictionet::WorldSocket::UnixSocket(path.into()), attacher).unwrap();
    std::thread::spawn(move || {
        let _ = fictionet::block_on(fictionet::run(move |fcx| async move {
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
        }));
    });
    listening
}

/// Attaches a sandbox called `name` by speaking the relay protocol, and
/// sends it a ping every 20 ms until `stop` is set.
fn start_sandbox(path: &str, name: &str, stop: Arc<AtomicBool>) {
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
    std::thread::spawn(move || {
        let fd: OwnedFd = fd;
        let mut seq = 0u16;
        while !stop.load(Ordering::SeqCst) {
            let mut ping = vec![
                0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1, 8, 0, 0, 0,
                0x12, 0x34,
            ];
            ping.extend_from_slice(&seq.to_be_bytes());
            if unix::send(fd.as_raw_fd(), &Message::Packet(&ping).encode(), false).is_err() {
                return;
            }
            let _ = unix::recv(fd.as_raw_fd(), &mut buf, false);
            seq = seq.wrapping_add(1);
            std::thread::sleep(Duration::from_millis(20));
        }
    });
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
    let path = temp_socket();
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
    // The observer finds the run once the world first asks for a sandbox;
    // before that, a watch starts with "waiting". Wait for it, so the watch
    // below starts with the snapshot even on a busy machine.
    let start = Instant::now();
    while !text(&client.call(r#"{"op":"world"}"#).unwrap()).contains(r#""running":true"#) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the world never started running"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    // Follow the graph, then attach a sandbox: it shows up as a node with
    // an edge, its counters rise, and the echo task's events arrive.
    let watch = client.request(r#"{"op":"watch"}"#).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    start_sandbox(&path, "agent", stop.clone());
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
        counters += t.starts_with(r#"{"event":"counters""#) as u32;
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
        text(&graph).contains(r#""file":"tests/observe.rs""#),
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
    stop.store(true, Ordering::SeqCst);
    let last = until(&mut client, |v| v.id == packets && v.end)
        .pop()
        .unwrap();
    assert_eq!(
        text(&last),
        r#"{"event":"end","data":{"reason":"the link closed"}}"#
    );
}

#[test]
fn an_observer_takes_no_name() {
    let path = temp_socket();
    let _listening = start_world(&path);
    // An observer called "agent" does not stop a sandbox called "agent".
    let _a = Client::connect(&path, "agent").unwrap();
    let _b = Client::connect(&path, "agent").unwrap();
    start_sandbox(&path, "agent", Arc::new(AtomicBool::new(true)));
}

#[test]
fn an_observer_of_a_world_that_has_not_started_waits() {
    let path = temp_socket();
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
    let path = temp_socket();
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
    start_sandbox(&path, "agent", Arc::new(AtomicBool::new(true)));
}
