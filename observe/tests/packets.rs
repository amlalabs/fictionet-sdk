//! Packet watches over the observation endpoint: a world runs on its own
//! thread, and clients follow its graph, watch a link's packets, read one
//! packet's layers and download the capture.
#![cfg(all(feature = "native", unix))]

use std::io::{ErrorKind, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use fictionet::stdlib::network::{Connection, ConnectionExt, tcp};
use fictionet::stdlib::protocols::x509::{Time, Validity};
use fictionet::stdlib::services::ca::Ca;
use fictionet::stdlib::services::tls::{self, ServerConfig};
use fictionet::{Cx, Interface, InterfaceExt, Packet, Result, RunOptions, Seed};
use fictionet_observe::{Client, DashboardObserver, DashboardOptions, Value, serve};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

/// A private directory for one endpoint socket, removed afterward.
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "observe-packets-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn socket(&self) -> PathBuf {
        self.0.join("observe.sock")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn text(v: &Value) -> String {
    String::from_utf8_lossy(&v.bytes).into_owned()
}

/// Reads values until `want` matches one, for at most twenty seconds.
#[track_caller]
fn until(client: &mut Client, mut want: impl FnMut(&Value) -> bool) -> Vec<Value> {
    let start = Instant::now();
    let mut seen = Vec::new();
    while start.elapsed() < Duration::from_secs(20) {
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

/// The whole binary reply to request `id`: its values joined.
fn joined(client: &mut Client, id: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    until(client, |v| {
        if v.id == id {
            assert!(v.binary, "{}", text(v));
            bytes.extend_from_slice(&v.bytes);
        }
        v.id == id && v.end
    });
    bytes
}

/// The number of the first edge in `json` that ends at a sandbox.
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

fn ping(seq: u16) -> Packet {
    let mut ping = vec![
        0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1, 8, 0, 0, 0, 0x12, 0x34,
    ];
    ping.extend_from_slice(&seq.to_be_bytes());
    Packet(ping)
}

#[test]
fn an_observer_sees_the_graph_its_changes_events_and_packets() {
    let directory = Directory::new();
    let dashboard = DashboardObserver::new(DashboardOptions::default());
    let _endpoint = serve(dashboard.handle(), directory.socket()).unwrap();
    let (attacher, mut attachments) = fictionet::attachments();
    let observer = dashboard.observer();
    let world = std::thread::spawn(move || {
        fictionet::block_on(fictionet::run(
            RunOptions::new(Seed::random()).observer(observer),
            move |fcx| async move {
                let mut sandbox = attachments.next(&fcx).await?;
                let (mut mine, mut theirs) = fictionet::pair();
                mine = fcx.tap("echo", mine);
                fcx.spawn(move |fcx| async move {
                    while let Ok(p) = theirs.recv(&fcx).await {
                        fcx.emit("test", "echo", |event| event.field("len", p.0.len() as u64));
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
            },
        ))
    });
    let mut client = Client::connect(directory.socket()).unwrap();
    client.set_timeout(Some(Duration::from_secs(10))).unwrap();
    let watch = client.request(r#"{"op":"watch"}"#).unwrap();
    let mut sandbox = attacher.attach("agent").unwrap();
    let mut edge = None;
    until(&mut client, |v| {
        assert_eq!(v.id, watch);
        let t = text(v);
        if t.starts_with(r#"{"event":"edge""#) || t.starts_with(r#"{"event":"snapshot""#) {
            edge = edge.or_else(|| sandbox_edge_in(&t));
        }
        edge.is_some()
    });
    let edge = edge.unwrap();
    sandbox.send(ping(0));
    let (mut counters, mut echoes) = (0, 0);
    until(&mut client, |v| {
        assert_eq!(v.id, watch);
        assert!(!v.end);
        let t = text(v);
        if t.starts_with(r#"{"event":"counters""#) {
            counters += 1;
            if counters < 2 {
                sandbox.send(ping(1));
            }
        }
        if t.starts_with(r#"{"event":"event""#)
            && t.contains(r#""source":"test","kind":"echo","#)
            && t.contains(r#""fields":{"len":28}"#)
        {
            echoes += 1;
        }
        counters >= 2 && echoes >= 1
    });
    for request in [r#"{"op":"world"}"#, r#"{"op":"graph"}"#] {
        let id = client.request(request).unwrap();
        let value = until(&mut client, |v| v.id == id).pop().unwrap();
        assert!(value.end && !value.binary);
        if request.contains("world") {
            assert!(text(&value).starts_with(r#"{"observe":2,"#));
            assert!(text(&value).contains(r#""running":true"#));
        } else {
            assert!(text(&value).contains(r#""kind":"sandbox","name":"agent""#));
            assert!(text(&value).contains(r#""file":"observe/tests/packets.rs""#));
        }
    }
    let cancel = client
        .request(&format!(r#"{{"op":"cancel","id":{watch}}}"#))
        .unwrap();
    let seen = until(&mut client, |v| v.id == cancel);
    let ended = seen.iter().find(|v| v.id == watch && v.end).unwrap();
    assert_eq!(
        text(ended),
        r#"{"event":"end","data":{"reason":"cancelled"}}"#
    );
    let events = text(&client.call(r#"{"op":"events","after":0,"max":2}"#).unwrap());
    assert!(events.starts_with(r#"{"events":[{"seq":1,"#));
    assert!(events.contains(r#""seq":2,"#));
    assert!(!events.contains(r#""seq":3,"#));
    let replay = client.request(r#"{"op":"watch","after":0}"#).unwrap();
    let seen = until(&mut client, |v| {
        v.id == replay && text(v).starts_with(r#"{"event":"event""#)
    });
    assert!(text(&seen[0]).contains(r#""events":[]"#));
    assert!(text(seen.last().unwrap()).starts_with(r#"{"event":"event","data":{"seq":1,"#));
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
            sandbox.send(ping(0));
        }
        v.id == packets && text(v).starts_with(r#"{"event":"packet""#)
    });
    let link = seen.iter().find(|v| v.id == packets).unwrap();
    assert!(text(link).contains(&format!(r#""id":"e{edge}""#)));
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
    let detail = text(&until(&mut client, |v| v.id != packets).pop().unwrap());
    assert!(
        detail.contains("Internet Control Message Protocol"),
        "{detail}"
    );
    assert!(detail.contains(r#""hex":"4500001c"#), "{detail}");

    // The capture, as pcapng bytes.
    let pcap = client
        .request(&format!(r#"{{"op":"pcap","link":"e{edge}"}}"#))
        .unwrap();
    let file = joined(&mut client, pcap);
    assert_eq!(&file[..4], &[0x0a, 0x0d, 0x0d, 0x0a]);

    // Mistakes get an error, and the session goes on.
    let fly = client.request(r#"{"op":"fly"}"#).unwrap();
    let error = until(&mut client, |v| v.id == fly).pop().unwrap();
    assert_eq!(text(&error), r#"{"error":"unknown op fly"}"#);

    // When the sandbox leaves, its link closes and the packet stream ends.
    drop(sandbox);
    let last = until(&mut client, |v| v.id == packets && v.end)
        .pop()
        .unwrap();
    assert_eq!(
        text(&last),
        r#"{"event":"end","data":{"reason":"the link closed"}}"#
    );
    world.join().unwrap().unwrap();
}

#[test]
fn watch_capacity_errors_preserve_shared_streams_and_cancel_frees_admission() {
    let directory = Directory::new();
    let dashboard = DashboardObserver::new(DashboardOptions {
        watches: 1,
        ..DashboardOptions::default()
    });
    let _endpoint = serve(dashboard.handle(), directory.socket()).unwrap();
    let (attacher, mut attachments) = fictionet::attachments();
    let observer = dashboard.observer();
    let world = std::thread::spawn(move || {
        fictionet::block_on(fictionet::run(
            RunOptions::new(Seed::from_u64(1)).observer(observer),
            move |fcx| async move {
                let mut links = Vec::new();
                for (mut end, mut other) in [fictionet::pair(), fictionet::pair()] {
                    end = fcx.tap("test", end);
                    fcx.spawn(move |fcx| async move {
                        let _ = other.recv(&fcx).await;
                        Ok(())
                    });
                    links.push(end);
                }
                attachments.next(&fcx).await?;
                drop(links);
                Ok(())
            },
        ))
    });
    let mut first = Client::connect(directory.socket()).unwrap();
    let mut second = Client::connect(directory.socket()).unwrap();
    first.set_timeout(Some(Duration::from_secs(5))).unwrap();
    second.set_timeout(Some(Duration::from_secs(5))).unwrap();
    let start = Instant::now();
    let edges: Vec<String> = loop {
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
        if edges.len() == 2 {
            break edges;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "{graph}");
        std::thread::sleep(Duration::from_millis(20));
    };
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
    assert!(forgotten.binary && forgotten.end);
    assert_eq!(&forgotten.bytes[..4], &[0x0a, 0x0d, 0x0d, 0x0a]);
    assert_eq!(
        fictionet::stdlib::codec::le32(&forgotten.bytes, 28).unwrap(),
        1
    );
    let done = attacher.attach("done").unwrap();
    world.join().unwrap().unwrap();
    drop(done);
}

#[test]
fn the_handle_and_the_endpoint_give_the_same_packet_bytes() {
    let dashboard = DashboardObserver::new(DashboardOptions {
        collector: fictionet_observe::Options::default(),
        ..Default::default()
    });
    fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(5)).observer(dashboard.observer()),
        |cx| async move {
            let (attacher, mut attachments) = fictionet::attachments();
            let mut sandbox = attacher.attach("guest").unwrap();
            let mut attachment = attachments.next(&cx).await?;
            for seq in 0..5 {
                sandbox.send(ping(seq));
                let echo = attachment.recv(&cx).await?;
                attachment.send(echo);
            }
            Ok(())
        },
    ))
    .unwrap();
    let directory = Directory::new();
    let _endpoint = serve(dashboard.handle(), directory.socket()).unwrap();
    let mut client = Client::connect(directory.socket()).unwrap();
    client.set_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut direct = dashboard.handle().session();
    let now = Instant::now();
    let same = |a: &Value, b: &Value| {
        assert_eq!(
            (a.id, &a.bytes, a.binary, a.end),
            (b.id, &b.bytes, b.binary, b.end),
            "{} / {}",
            text(a),
            text(b)
        );
    };

    let request = r#"{"op":"packets","link":"e1"}"#;
    let id = client.request(request).unwrap();
    let mut expected = direct.request(id, request, now, None);
    while !expected.last().unwrap().end {
        expected.extend(direct.poll(now, None));
    }
    assert_eq!(expected.len(), 1 + 10 + 1);
    for value in &expected {
        same(value, &client.next_value().unwrap().unwrap());
    }

    let request = r#"{"op":"packet","link":"e1","seq":4}"#;
    let id = client.request(request).unwrap();
    let expected = direct.request(id, request, now, None);
    assert!(text(&expected[0]).starts_with(r#"{"seq":4,"#));
    same(&expected[0], &client.next_value().unwrap().unwrap());

    let request = r#"{"op":"pcap","link":"e1"}"#;
    let id = client.request(request).unwrap();
    let mut expected = direct.request(id, request, now, None);
    while !expected.last().unwrap().end {
        expected.extend(direct.poll(now, None));
    }
    for value in &expected {
        same(value, &client.next_value().unwrap().unwrap());
    }
}

/// A CA, and a server and client config for `secret.test`.
fn configs(fcx: &Cx) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let ca = Ca::new(fcx, "Test CA").unwrap();
    let leaf = ca
        .issue(
            fcx,
            &["secret.test"],
            Validity {
                not_before: Time::from_unix(946684800).unwrap(),
                not_after: Time::from_unix(4102444800).unwrap(),
            },
        )
        .unwrap();
    let provider = rustls::crypto::ring::default_provider();
    let server = tls::config_builder(fcx, SystemTime::now())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(leaf.chain, leaf.key)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der()).unwrap();
    let client = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

/// Speaks TLS as a client over `conn`: finishes the handshake, changes
/// its keys with a KeyUpdate (which asks the server to change its own),
/// sends one request and returns the response.
async fn fetch<C: Connection>(
    fcx: &Cx,
    mut conn: C,
    config: Arc<ClientConfig>,
    request: &[u8],
) -> Result<Vec<u8>> {
    let mut tls = ClientConnection::new(config, ServerName::try_from("secret.test").unwrap())?;
    let mut sent = false;
    let mut response = Vec::new();
    let mut buf = vec![0u8; 16 << 10];
    loop {
        if !sent && !tls.is_handshaking() {
            tls.refresh_traffic_keys()?;
            tls.writer().write_all(request)?;
            sent = true;
        }
        while tls.wants_write() {
            let mut out = Vec::new();
            tls.write_tls(&mut out)?;
            conn.write_all(fcx, &out).await?;
        }
        match tls.reader().read_to_end(&mut response) {
            Ok(_) => return Ok(response),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(response),
            Err(e) => return Err(e.into()),
        }
        if response.ends_with(b"hello") {
            return Ok(response);
        }
        let n = conn.read(fcx, &mut buf).await?;
        if n == 0 {
            return Ok(response);
        }
        tls.read_tls(&mut &buf[..n])?;
        tls.process_new_packets()?;
    }
}

#[test]
fn https_on_a_watched_link_shows_decrypted_http() {
    let directory = Directory::new();
    let dashboard = DashboardObserver::new(DashboardOptions::default());
    let _endpoint = serve(dashboard.handle(), directory.socket()).unwrap();
    let (mut go, mut started) = fictionet::pair();
    let (response_tx, fetched) = std::sync::mpsc::channel();
    let observer = dashboard.observer();
    let world = std::thread::spawn(move || {
        fictionet::block_on(fictionet::run(
            RunOptions::new(Seed::random()).observer(observer),
            move |fcx| async move {
                let (server_cfg, client_cfg) = configs(&fcx);
                let (a, b) = fictionet::pair();
                let a = fcx.tap("tls", a);
                let client = tcp::endpoint(&fcx, a, "10.0.0.2".parse()?);
                let server = tcp::endpoint(&fcx, b, "10.0.0.1".parse()?);
                let mut listener = server.listen(443)?;
                fcx.spawn(move |fcx| async move {
                    let conn = listener.accept(&fcx).await?;
                    let mut conn = tls::server(&fcx, conn)
                        .await?
                        .finish(&fcx, server_cfg)
                        .await?;
                    let mut request = Vec::new();
                    let mut buf = [0u8; 4096];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        let n = conn.read(&fcx, &mut buf).await?;
                        request.extend_from_slice(&buf[..n]);
                    }
                    conn.write_all(&fcx, b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")
                        .await?;
                    conn.shutdown(&fcx).await?;
                    Ok(())
                });
                started.recv(&fcx).await?;
                let conn = client.connect(&fcx, "10.0.0.1:443".parse()?).await?;
                let response = fetch(
                    &fcx,
                    conn,
                    client_cfg,
                    b"GET /secret HTTP/1.1\r\nhost: secret.test\r\n\r\n",
                )
                .await?;
                response_tx.send(response).unwrap();
                started.recv(&fcx).await?;
                fcx.cancel();
                Ok(())
            },
        ))
    });

    let mut observer = Client::connect(directory.socket()).unwrap();
    observer.set_timeout(Some(Duration::from_secs(10))).unwrap();
    // Follow the graph until the pair between the two endpoints shows.
    observer.request(r#"{"op":"watch"}"#).unwrap();
    let start = Instant::now();
    let mut edge = None;
    while edge.is_none() && start.elapsed() < Duration::from_secs(10) {
        let v = text(&observer.next_value().unwrap().unwrap());
        // The pair is the only edge; both of its ends are tcp::endpoint.
        if let Some(at) = v.find(r#"{"id":"e"#) {
            let digits: String = v[at + 8..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            edge = Some(digits);
        }
    }
    let edge = edge.expect("the pair between the endpoints");
    let packets = observer
        .request(&format!(r#"{{"op":"packets","link":"e{edge}"}}"#))
        .unwrap();

    let (mut request, mut response) = (false, false);
    while !(request && response) && start.elapsed() < Duration::from_secs(20) {
        let v = observer.next_value().unwrap().unwrap();
        if v.id != packets {
            continue;
        }
        let t = text(&v);
        if t.starts_with(r#"{"event":"link""#) {
            go.send(Packet(Vec::new()));
        }
        // The packet is shown as what TLS carries.
        request |= t.contains(r#""proto":"HTTP","info":"GET /secret HTTP/1.1""#)
            && t.contains("decrypted");
        response |=
            t.contains(r#""proto":"HTTP","info":"HTTP/1.1 200 OK""#) && t.contains("decrypted");
    }
    assert!(request && response, "the HTTP inside the TLS was not shown");
    assert!(
        fetched
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .ends_with(b"hello")
    );

    // The keys, and the capture with the keys in it.
    let keylog = observer.request(r#"{"op":"keylog"}"#).unwrap();
    let keylog = until(&mut observer, |v| v.id == keylog).pop().unwrap();
    assert!(
        keylog.binary && text(&keylog).contains("CLIENT_TRAFFIC_SECRET_0 "),
        "{}",
        text(&keylog)
    );
    let pcap = observer
        .request(&format!(r#"{{"op":"pcap","link":"e{edge}"}}"#))
        .unwrap();
    let b = joined(&mut observer, pcap);
    // The third block is the Decryption Secrets Block.
    let first = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
    let second = u32::from_le_bytes(b[first + 4..first + 8].try_into().unwrap()) as usize;
    assert_eq!(
        u32::from_le_bytes(b[first + second..first + second + 4].try_into().unwrap()),
        0x0a
    );
    go.send(Packet(Vec::new()));
    world.join().unwrap().unwrap();
}
