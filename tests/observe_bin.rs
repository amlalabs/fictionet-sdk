//! `fictionet observe` and `fictionet dashboard`, run as the binary against
//! a world in this process.

#[path = "common/logged.rs"]
mod logged;
#[path = "common/poll.rs"]
mod poll;

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
    for route in ["/", "/api/keylog", "/api/graph", "/api/watch", "/api/pcap"] {
        assert!(raw_get(port, route, "").starts_with("HTTP/1.1 401"));
        assert!(
            raw_get(port, route, "Authorization: Bearer wrong\r\n").starts_with("HTTP/1.1 401")
        );
    }
    assert!(raw_get(port, "/login?token=wrong", "").starts_with("HTTP/1.1 401"));
    let login = raw_get(port, "/login?token=dashboard-test-token", "");
    assert!(login.starts_with("HTTP/1.1 303"), "{login}");
    assert!(login.contains("HttpOnly; SameSite=Strict"));
    assert!(login.contains("Location: /\r\n"));
    let cookie = login
        .lines()
        .find_map(|line| line.strip_prefix("Set-Cookie: "))
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    assert!(
        raw_get(port, "/api/keylog", &format!("Cookie: {cookie}\r\n")).starts_with("HTTP/1.1 200")
    );
    assert!(raw_get(port, "/login?token=dashboard-test-token", "").starts_with("HTTP/1.1 401"));
    assert!(
        raw_get(port, "/api/keylog", "Cookie: fictionet_token=wrong\r\n")
            .starts_with("HTTP/1.1 401")
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
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(conn, "GET /api/watch HTTP/1.1\r\nHost: localhost\r\nCookie: fictionet_token=dashboard-test-token\r\n\r\n").unwrap();
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
                Ok(())
            },
        ));
    });
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
    assert_eq!(get(port, "/groups.js").0, "HTTP/1.1 200 OK");

    // The two links, and the group their echo tasks are in.
    let mut graph = String::new();
    poll::until(Duration::from_secs(10), || {
        graph = get(port, "/api/graph").1;
        graph.contains(r#""name":"lan","parent":null"#) && graph.matches(r#"{"id":"e"#).count() == 2
    });
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
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    world_thread.join().unwrap();
    let out = log.join().unwrap();
    let status = status.expect("the watch should exit when the world ends");
    assert_eq!(status.code(), Some(0), "{out}");
    assert!(out.contains(r#"{"event":"ended","#), "{out}");
    assert!(
        out.trim_end()
            .ends_with(r#"{"event":"end","data":{"reason":"the world ended"}}"#),
        "{out}"
    );
}

fn raw_get(port: u16, path: &str, headers: &str) -> String {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        conn,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n"
    )
    .unwrap();
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
