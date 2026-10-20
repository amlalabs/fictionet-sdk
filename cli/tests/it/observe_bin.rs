//! `fictionet observe`, run as the binary against a world in this process.

use fictionet_test_support::{logged, temp};

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use fictionet::InterfaceExt;

const BIN: &str = env!("CARGO_BIN_EXE_fictionet");

/// A world that emits an event every 50 ms.
fn start_world(path: &str) -> fictionet_observe::Endpoint {
    let dashboard = fictionet_observe::DashboardObserver::new(Default::default());
    let listening = fictionet_observe::serve(dashboard.handle(), path).unwrap();
    std::thread::spawn(move || {
        let _ = fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::random()).observer(std::sync::Arc::new(
                fictionet_observe::Aggregate::new(dashboard.observer()),
            )),
            move |fcx| async move {
                let mut n = 0i64;
                loop {
                    fcx.emit("test", "tick", |event| event.field("n", n));
                    n += 1;
                    fcx.sleep(fictionet::time::ms(50)).await?;
                }
            },
        ));
    });
    listening
}

#[test]
fn observe_prints_json_lines() {
    let path = temp::socket();
    let _listening = start_world(&path);
    let world = format!("unix:{path}");
    let out = Command::new(BIN)
        .args(["observe", "--observation", &world, "world"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.starts_with(r#"{"observe":2,"#) && text.ends_with("}\n"),
        "{text}"
    );

    assert!(
        text.contains(&format!("\"fictionet\":\"{}\"", env!("CARGO_PKG_VERSION"))),
        "{text}"
    );

    // A stream: the snapshot, then the world's own events, one per line.
    let mut child = Command::new(BIN)
        .args(["observe", "--observation", &world, "watch"])
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
        .args(["observe", "--observation", &world, "packet", "e999", "1"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains(r#""error""#));
    let out = Command::new(BIN)
        .args(["observe", "--observation", &world, "fly"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(BIN)
        .args(["observe", "--observation", "unix:/nonexistent/world.sock"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));

    // A full disk is a failure, not a quiet stop as a closed pipe is.
    if let Ok(full) = std::fs::File::create("/dev/full") {
        let out = Command::new(BIN)
            .args(["observe", "--observation", &world, "world"])
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

const MORE: u8 = 1;
const END: u8 = 2;
const BINARY: u8 = 4;

fn send_frame(mut peer: &std::os::unix::net::UnixStream, body: &[u8]) {
    peer.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    peer.write_all(body).unwrap();
}

fn send_reply(peer: &std::os::unix::net::UnixStream, id: u32, flags: u8, body: &[u8]) {
    let mut frame = vec![5];
    frame.extend_from_slice(&id.to_be_bytes());
    frame.push(flags);
    frame.extend_from_slice(body);
    send_frame(peer, &frame);
}

fn read_frame(mut peer: &std::os::unix::net::UnixStream) -> Option<Vec<u8>> {
    let mut header = [0; 4];
    if peer.read(&mut header[..1]).unwrap() == 0 {
        return None;
    }
    peer.read_exact(&mut header[1..]).unwrap();
    let mut body = vec![0; u32::from_be_bytes(header) as usize];
    peer.read_exact(&mut body).unwrap();
    Some(body)
}

/// A scripted observer peer that answers one request with `replies`.
fn with_observer(replies: &[(u8, &[u8])], run: impl FnOnce(&str)) {
    let path = temp::socket();
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            assert_eq!(
                read_frame(&peer).unwrap(),
                [b"\x01\x00\x00\x00\x02".as_slice(), b"fictionet-observe"].concat()
            );
            send_frame(&peer, &[2]);
            let frame = read_frame(&peer).expect("an observation request");
            assert_eq!(frame[0], 4, "expected an observation request");
            let id = u32::from_be_bytes(frame[1..5].try_into().unwrap());
            for &(flags, body) in replies {
                send_reply(&peer, id, flags, body);
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
        with_observer(&[(flags, bytes)], |path| {
            let out = Command::new(BIN)
                .args(["observe", "--observation", &format!("unix:{path}"), "watch"])
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

/// A watch on a world that ends normally exits 0, after printing `ended`
/// and the stream's end.
#[test]
fn a_watch_exits_0_when_the_world_ends() {
    let path = temp::socket();
    let world = format!("unix:{path}");
    let dashboard = fictionet_observe::DashboardObserver::new(Default::default());
    let listening = fictionet_observe::serve(dashboard.handle(), &path).unwrap();
    let mut child = Command::new(BIN)
        .args(["observe", "--observation", &world, "watch"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    // The world returns once the observer has its snapshot.
    let (stop, mut stopped) = fictionet::pair();
    let world_thread = std::thread::spawn(move || {
        let _ = fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::random()).observer(std::sync::Arc::new(
                fictionet_observe::Aggregate::new(dashboard.observer()),
            )),
            move |fcx| async move {
                assert_eq!(stopped.recv(&fcx).await, Err(fictionet::RecvError::Closed));
                fcx.cancel();
                Ok(())
            },
        ));
    });
    let log = logged(child.stdout.take().unwrap(), r#""event":"snapshot""#);
    drop(stop);
    let status =
        fictionet_test_support::within(Duration::from_secs(20), move || child.wait().unwrap());
    world_thread.join().unwrap();
    drop(listening);
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
    let ended_value = br#"{"event":"ended","data":{}}"#;
    for (ended, partial) in [(true, false), (true, true), (false, true)] {
        let mut replies = Vec::new();
        if ended {
            replies.push((0, ended_value.as_slice()));
        }
        if partial {
            replies.push((MORE, br#"{"event":"end","data":"#.as_slice()));
        }
        with_observer(&replies, |path| {
            let out = Command::new(BIN)
                .args(["observe", "--observation", &format!("unix:{path}"), "watch"])
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

#[test]
fn version_reports_the_package_version() {
    let out = Command::new(BIN).arg("--version").output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("fictionet {}\n", env!("CARGO_PKG_VERSION"))
    );
}
