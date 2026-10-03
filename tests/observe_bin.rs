//! `fictionet observe` and `fictionet dashboard`, run as the binary against
//! a world in this process.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_fictionet");

fn temp_socket() -> String {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("fn-obsbin-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("world.sock").to_str().unwrap().to_owned()
}

/// A world that takes attachments, and emits an event every 50 ms.
fn start_world(path: &str) -> fictionet::Listening {
    let (attacher, mut attachments) = fictionet::attachments();
    let listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(path.into()), attacher).unwrap();
    std::thread::spawn(move || {
        let _ = fictionet::block_on(fictionet::run(move |cx| async move {
            cx.spawn(move |cx| async move {
                while let Some(a) = attachments.next(&cx).await {
                    drop(a);
                }
                Ok(())
            });
            let mut n = 0i64;
            loop {
                cx.event("tick").int("n", n).emit();
                n += 1;
                cx.sleep(fictionet::time::ms(50)).await?;
            }
        }));
    });
    listening
}

fn get(port: u16, path: &str) -> (String, String) {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(conn, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").unwrap();
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
    let out = Command::new(BIN).args(["observe", "--world", &world, "world"]).output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with(r#"{"observe":1,"#) && text.ends_with("}\n"), "{text}");

    // A stream: the snapshot, then the world's own events, one per line.
    let mut child = Command::new(BIN).args(["observe", "--world", &world, "watch"]).stdout(Stdio::piped()).spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    assert!(lines.next().unwrap().unwrap().starts_with(r#"{"event":"snapshot""#));
    let tick = lines.map(Result::unwrap).find(|l| l.contains(r#""name":"tick""#));
    assert!(tick.is_some());
    child.kill().unwrap();
    child.wait().unwrap();

    // A request the world cannot answer exits 1; one that makes no sense, 2.
    let out = Command::new(BIN).args(["observe", "--world", &world, "packet", "e999", "1"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains(r#""error""#));
    let out = Command::new(BIN).args(["observe", "--world", &world, "fly"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(BIN).args(["observe", "--world", "unix:/nonexistent/world.sock"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn the_dashboard_serves_the_app_and_carries_its_api_calls() {
    let path = temp_socket();
    let _listening = start_world(&path);
    let world = format!("unix:{path}");
    let mut child = Command::new(BIN)
        .args(["dashboard", "--world", &world, "--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    let port: u16 = line.trim_end().rsplit(':').next().unwrap().trim_end_matches('/').parse().unwrap();

    let (status, body) = get(port, "/");
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert!(body.contains("app.js"));
    assert_eq!(get(port, "/app.js").0, "HTTP/1.1 200 OK");

    // An API call becomes an observe request.
    let (status, body) = get(port, "/api/graph");
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert!(body.contains(r#""kind":"world""#), "{body}");
    let (status, body) = get(port, "/api/packet?link=e999&seq=1");
    assert_eq!(status, "HTTP/1.1 404 Not Found");
    assert!(body.starts_with(r#"{"error":"#));

    // A stream comes back as server-sent events.
    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(conn, "GET /api/watch HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
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
    assert!(seen.iter().any(|e| e == "note"), "{seen:?}");

    // A page on another site cannot read it through a name of its own.
    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(conn, "GET /api/graph HTTP/1.1\r\nHost: attacker.example:{port}\r\n\r\n").unwrap();
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
    let listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(path.into()), attacher).unwrap();
    std::thread::spawn(move || {
        let _ = fictionet::block_on(fictionet::run(move |cx| async move {
            // Observers find a world once it takes attachments.
            cx.spawn(move |cx| async move {
                while let Some(a) = attachments.next(&cx).await {
                    drop(a);
                }
                Ok(())
            });
            let lan = cx.group("lan");
            for _ in 0..2 {
                let (mut a, mut b) = fictionet::pair();
                lan.spawn(move |cx| async move {
                    while let Ok(p) = b.recv(&cx).await {
                        b.send(p);
                    }
                    Ok(())
                });
                cx.spawn(move |cx| async move {
                    loop {
                        // An IPv4 header with nothing after it.
                        let p = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
                        a.send(fictionet::Packet(p));
                        a.recv(&cx).await?;
                        cx.sleep(fictionet::time::ms(20)).await?;
                    }
                });
            }
            Ok(())
        }));
    });
    listening
}

/// `packets` and `pcap` for several links: one stream of all their
/// packets, each with its link, and one file with a section for each.
#[test]
fn the_dashboard_merges_the_packets_of_several_links() {
    let path = temp_socket();
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
        Command::new(BIN).args(["dashboard", "--world", &world, "--listen", "127.0.0.1:0"]).stdout(Stdio::piped()).spawn().unwrap(),
    );
    let mut out = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    let port: u16 = line.trim_end().rsplit(':').next().unwrap().trim_end_matches('/').parse().unwrap();
    assert_eq!(get(port, "/groups.js").0, "HTTP/1.1 200 OK");

    // The two links, and the group their echo tasks are in.
    std::thread::sleep(Duration::from_millis(200));
    let (_, graph) = get(port, "/api/graph");
    assert!(graph.contains(r#""name":"lan","parent":null"#), "{graph}");
    let links: Vec<String> =
        graph.split(r#"{"id":"e"#).skip(1).map(|r| format!("e{}", r.split('"').next().unwrap())).collect();
    assert_eq!(links.len(), 2, "{graph}");
    let both = links.join(",");

    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(conn, "GET /api/packets?link={both} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
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
            let link = data.split(r#""link":""#).nth(1).unwrap().split('"').next().unwrap().to_owned();
            assert!(links.contains(&link), "{data}");
            from.insert(link);
        }
    }
    assert_eq!(from.len(), 2, "packets came from both links");

    // While the stream above still watches both links, the capture of both
    // holds two pcapng sections.
    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(conn, "GET /api/pcap?link={both} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
    let mut all = Vec::new();
    conn.read_to_end(&mut all).unwrap();
    let head_end = all.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert!(all.starts_with(b"HTTP/1.1 200 OK"), "{}", String::from_utf8_lossy(&all[..head_end]));
    let body = &all[head_end..];
    let sections = body.windows(4).filter(|w| *w == [0x0a, 0x0d, 0x0d, 0x0a]).count();
    assert!(body.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]));
    assert!(sections >= 2, "{sections} section headers");
    drop(child);
}
