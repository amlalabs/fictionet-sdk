use super::admission::{ACK, RST, SYN, open_idle, tcp_seg};
use super::dns_dhcp::{dhcp_ask, dhcp_msg, read_exact};
use super::http_serving::read_all;
use super::sites::raw_dns;
use super::*;
use fictionet::RunOptions;

// ---------------------------------------------------------------------------
// Tests: events

/// A test world's retained events, read from a mark the test moves past the
/// events it has checked.
#[derive(Clone)]
pub(super) struct Log {
    pub(super) events: Arc<Memory>,
    from: Arc<AtomicU64>,
}

impl Log {
    pub(super) fn new(events: Arc<Memory>) -> Log {
        Log {
            events,
            from: Arc::default(),
        }
    }

    /// Moves the mark past every event so far.
    pub(super) fn clear(&self) {
        self.from.store(self.events.last(), Ordering::SeqCst);
    }
}

/// [`world`], with explicit event retention.
pub(super) fn world_events<F, Fut>(f: F)
where
    F: FnOnce(Cx, Attacher, Env, Log) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    world_events_with_memory(
        |memory| RunOptions::new(Seed::from_u64(1)).observer(memory),
        Arc::new(Memory::default()),
        f,
    )
}

fn world_events_with_memory<F, Fut>(
    options: impl FnOnce(Arc<Memory>) -> RunOptions,
    evidence: Arc<Memory>,
    f: F,
) where
    F: FnOnce(Cx, Attacher, Env, Log) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    run_world::seeded_world(
        options(evidence.clone()),
        Duration::from_secs(60),
        move |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let t = sites(&fcx);
            let env = t.serve_with(&fcx, attachments)?;
            let log = Log::new(evidence);
            f(fcx, attacher, env, log).await?;
            Ok(())
        },
    );
}

/// The events after the log's mark that `pick` keeps.
pub(super) fn picked<T>(log: &Log, pick: impl FnMut(&Event) -> Option<T>) -> Vec<T> {
    log.events
        .checked_all()
        .unwrap()
        .iter()
        .filter(|event| event.seq > log.from.load(Ordering::SeqCst))
        .filter_map(pick)
        .collect()
}

/// Waits up to 5 s until `pick` keeps `n` events after the log's mark,
/// and returns them.
pub(super) async fn wait_for<T>(
    fcx: &Cx,
    log: &Log,
    n: usize,
    pick: impl Fn(&Event) -> Option<T>,
) -> Vec<T> {
    let from = log.from.load(Ordering::SeqCst);
    let got = log
        .events
        .wait(fcx, from, n, Duration::from_secs(5), |e| pick(e).is_some())
        .await
        .expect("the world stopped");
    if got.len() < n {
        panic!(
            "fewer than {n} such events: {:#?}",
            log.events.checked_all().unwrap()
        );
    }
    got.iter().filter_map(pick).collect()
}

fn is(s: &Sandbox, name: &str, addr: Option<Ipv4Addr>) -> bool {
    &*s.name == name && s.addr == addr
}

/// The sandbox an event names.
pub(super) fn sandbox_of(e: &Event) -> Option<&Sandbox> {
    e.conn.sandbox.as_ref()
}

/// Picks the events of `source`'s `kind`.
pub(super) fn seen(source: &'static str, kind: &'static str) -> impl Fn(&Event) -> Option<Event> {
    move |e| e.is(source, kind).then(|| e.clone())
}

pub(super) fn dns_seen(e: &Event) -> Option<Event> {
    seen("dns", "query")(e)
}

pub(super) fn tls_seen(e: &Event) -> Option<Event> {
    seen("tls", "handshake")(e)
}

pub(super) fn http_seen(e: &Event) -> Option<Event> {
    seen("http", "request")(e)
}

fn error_seen(e: &Event) -> Option<Event> {
    seen("http", "error")(e)
}

pub(super) fn blocked_seen(e: &Event) -> Option<Event> {
    seen("net", "blocked")(e)
}

/// The field `name` as an address.
pub(super) fn addr(e: &Event, name: &str) -> Option<IpAddr> {
    e.str(name)?.parse().ok()
}

/// Whether the field `name` is true.
pub(super) fn flag(e: &Event, name: &str) -> bool {
    e.get(name).and_then(|v| v.as_bool()) == Some(true)
}

/// The address and port an event's connection arrived on.
pub(super) fn local(e: &Event) -> SocketAddr {
    e.conn
        .local
        .expect("a connection's event names its address")
}

/// A DNS event's answer, as `addr 192.0.2.1`, `nodata`, `nxdomain`,
/// `error 1` or `none`.
pub(super) fn answer(e: &Event) -> String {
    match e.str("answer") {
        Some("addr") => format!("addr {}", e.str("addr").unwrap_or_default()),
        Some("error") => format!("error {}", e.u64("rcode").unwrap_or_default()),
        Some(other) => other.to_owned(),
        None => "none".to_owned(),
    }
}

/// A TLS event's outcome, with its `alpn`, `alert_code` or nothing after a
/// space: `accepted h2`, `alert 48`, `rejected`.
pub(super) fn outcome(e: &Event) -> String {
    match e.str("outcome") {
        Some("accepted") => format!("accepted {}", e.str("alpn").unwrap_or("-")),
        Some("alert") => format!("alert {}", e.u64("alert_code").unwrap_or_default()),
        Some(other) => other.to_owned(),
        None => "none".to_owned(),
    }
}

/// How many fields a handler added to an HTTP event.
fn extra(e: &Event) -> usize {
    let standard = [
        "scheme",
        "sni",
        "host",
        "method",
        "uri",
        "path",
        "query",
        "version",
        "headers",
        "started",
        "answer",
        "received",
        "status",
        "sent",
        "complete",
        "world_site",
    ];
    e.fields
        .iter()
        .filter(|(n, _)| !standard.contains(n))
        .count()
}

/// A `net.blocked` event's `why`, sandbox address, protocol, source,
/// destination and destination port.
type BlockedRow<'a> = (
    &'a str,
    Option<Ipv4Addr>,
    Option<u64>,
    Option<IpAddr>,
    Option<IpAddr>,
    Option<u64>,
);

fn blocked_row(e: &Event) -> BlockedRow<'_> {
    (
        e.str("why").unwrap_or_default(),
        sandbox_of(e).and_then(|s| s.addr),
        e.u64("protocol"),
        addr(e, "src"),
        addr(e, "dst"),
        e.u64("dst_port"),
    )
}

#[test]
fn events_attach_bind_and_detach() {
    world_events(|fcx, attacher, _env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut a = attacher.attach("a").unwrap();
        a.send(ping(me, GATEWAY, 1));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .is_some()
        );

        // A sandbox that gets its address from DHCP.
        let (any, bc) = (Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST);
        let mut d = attacher.attach("d").unwrap();
        let (_, offer) = dhcp_ask(&fcx, &mut d, any, bc, &dhcp_msg(dhcp::DISCOVER, 1, 1))
            .await
            .expect("an offer");
        let got = offer.yiaddr;
        let mut request = dhcp_msg(dhcp::REQUEST, 1, 1);
        request.push(dhcp::opt::REQUESTED_IP, got.octets());
        request.push(dhcp::opt::SERVER_ID, GATEWAY.octets());
        let (_, ack) = dhcp_ask(&fcx, &mut d, any, bc, &request)
            .await
            .expect("an ack");
        assert_eq!(ack.message_type(), Some(dhcp::ACK));
        // A renewal binds nothing new.
        let mut renew = dhcp_msg(dhcp::REQUEST, 2, 1);
        renew.ciaddr = got;
        let (_, ack) = dhcp_ask(&fcx, &mut d, got, GATEWAY, &renew)
            .await
            .expect("an ack");
        assert_eq!(ack.message_type(), Some(dhcp::ACK));

        drop(a);
        wait_for(&fcx, &log, 1, seen("net", "detached")).await;

        let of = |name: &str| {
            picked(&log, |e| {
                (e.source == "net" && &*sandbox_of(e)?.name == name).then(|| e.clone())
            })
        };
        let a_events = of("a");
        let kinds: Vec<_> = a_events.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, ["attached", "bound", "detached"], "{a_events:#?}");
        let sandbox = |e: &Event| sandbox_of(e).unwrap().clone();
        assert!(is(&sandbox(&a_events[0]), "a", None) && sandbox(&a_events[0]).id == 1);
        assert!(is(&sandbox(&a_events[1]), "a", Some(me)) && !flag(&a_events[1], "by_dhcp"));
        assert!(is(&sandbox(&a_events[2]), "a", Some(me)) && sandbox(&a_events[2]).id == 1);

        let d_events = of("d");
        assert!(
            d_events[0].is("net", "attached")
                && is(&sandbox(&d_events[0]), "d", None)
                && sandbox(&d_events[0]).id == 2
        );
        let bound: Vec<_> = d_events.iter().filter(|e| e.kind == "bound").collect();
        assert_eq!(bound.len(), 1, "{d_events:#?}");
        assert!(is(&sandbox(bound[0]), "d", Some(got)) && flag(bound[0], "by_dhcp"));
        Ok(())
    });
}

/// Opens a TCP connection by hand from a raw sandbox to `to`, and sends
/// `data` on it. Returns our port and the next sequence numbers (ours,
/// theirs).
async fn raw_connect(
    fcx: &Cx,
    raw: &mut End,
    me: Ipv4Addr,
    to: SocketAddr,
    port: u16,
    data: &[u8],
) -> (u32, u32) {
    let IpAddr::V4(dst) = to.ip() else {
        unreachable!()
    };
    raw.send(tcp_seg(me, port, dst, to.port(), 1000, 0, SYN, &[]));
    loop {
        let p = recv_within(fcx, raw, Duration::from_secs(2))
            .await
            .expect("a SYN-ACK");
        let (_, _, proto, t) = parse(&p);
        if proto == 6 && t[13] & (SYN | ACK) == SYN | ACK {
            let theirs = u32::from_be_bytes([t[4], t[5], t[6], t[7]]).wrapping_add(1);
            raw.send(tcp_seg(me, port, dst, to.port(), 1001, theirs, ACK, &[]));
            if !data.is_empty() {
                raw.send(tcp_seg(me, port, dst, to.port(), 1001, theirs, ACK, data));
            }
            return (1001 + data.len() as u32, theirs);
        }
    }
}

#[test]
fn events_name_each_attachment_by_id() {
    world_events(|fcx, attacher, env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut a = attacher.attach("a").unwrap();
        let (_, addrs) = raw_dns(&fcx, &mut a, me, GATEWAY, "slow.test", 1)
            .await
            .unwrap();
        let slow = addrs[0];
        let _ = raw_dns(&fcx, &mut a, me, GATEWAY, "secure.test", 2)
            .await
            .unwrap();
        // A request whose handler never answers, and a TLS handshake that
        // never starts, both still open when the sandbox detaches.
        raw_connect(
            &fcx,
            &mut a,
            me,
            SocketAddr::new(SECURE_ADDR.into(), 443),
            30_001,
            &[],
        )
        .await;
        raw_connect(
            &fcx,
            &mut a,
            me,
            SocketAddr::new(slow.into(), 80),
            30_000,
            b"GET /wait HTTP/1.1\r\nHost: slow.test\r\n\r\n",
        )
        .await;
        fcx.idle().await?;
        assert!(env.waiting.load(Ordering::SeqCst) == 1);
        drop(a);
        wait_for(&fcx, &log, 1, seen("net", "detached")).await;

        // The same name and address again: a new id.
        let mut a = attacher.attach("a").unwrap();
        let _ = raw_dns(&fcx, &mut a, me, GATEWAY, "secure.test", 3)
            .await
            .unwrap();

        let http = wait_for(&fcx, &log, 1, http_seen).await;
        assert_eq!(
            (
                http[0].str("answer"),
                http[0].u64("status"),
                flag(&http[0], "complete")
            ),
            (Some("cancelled"), None, false)
        );
        assert_eq!(
            (
                sandbox_of(&http[0]).unwrap().id,
                http[0].str("host"),
                http[0].str("path")
            ),
            (1, Some("slow.test"), Some("/wait"))
        );
        assert_eq!(local(&http[0]), SocketAddr::from((slow, 80)));
        let tls = wait_for(&fcx, &log, 1, tls_seen).await;
        assert_eq!(
            (sandbox_of(&tls[0]).unwrap().id, outcome(&tls[0])),
            (1, "detached".to_owned())
        );
        let dns = wait_for(&fcx, &log, 3, dns_seen).await;
        let ids: Vec<u64> = dns.iter().map(|d| sandbox_of(d).unwrap().id).collect();
        assert_eq!(ids, vec![1, 1, 2]);
        assert!(
            dns.iter()
                .all(|d| is(sandbox_of(d).unwrap(), "a", Some(me)))
        );
        let attached = picked(&log, |e| {
            e.is("net", "attached").then(|| sandbox_of(e).unwrap().id)
        });
        assert_eq!(attached, vec![1, 2]);
        Ok(())
    });
}

#[test]
fn events_for_dns_queries() {
    world_events(|fcx, attacher, env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let m = machine(&fcx, attacher.attach("a").unwrap(), me);
        assert_eq!(lookup(&fcx, &m, "secure.test").await, SECURE_ADDR);
        assert_eq!(lookup(&fcx, &m, "Secure.Test.").await, SECURE_ADDR);
        assert_eq!(
            dns(&fcx, &m, "secure.test", RecordType::AAAA).await,
            (ResponseCode::NoError, vec![])
        );
        assert_eq!(
            dns(&fcx, &m, "nope.test", RecordType::A).await.0,
            ResponseCode::NXDomain
        );

        // Over TCP.
        let mut conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(GATEWAY.into(), 53))
            .await
            .unwrap();
        let mut q = Message::new(7, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("nope.test").unwrap(),
            RecordType::A,
        ));
        let bytes = q.to_vec().unwrap();
        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        conn.write_all(&fcx, &framed).await.unwrap();
        let mut len = [0u8; 2];
        read_exact(&fcx, &mut conn, &mut len).await;

        let mut socket = m.udp.bind(4444).unwrap();
        let gw = SocketAddr::new(GATEWAY.into(), 53);
        // A message with a header but nothing readable after it: FORMERR.
        socket.send_to(&[0, 9, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xff], gw);
        let (reply, _) = timeout(&fcx, Duration::from_secs(2), socket.recv(&fcx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply[3] & 0x0f, 1, "FORMERR");
        // Two questions in one message: FORMERR, and no name.
        let mut q = Message::new(10, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("secure.test").unwrap(),
            RecordType::A,
        ));
        q.add_query(Query::query(
            Name::from_ascii("nope.test").unwrap(),
            RecordType::A,
        ));
        socket.send_to(&q.to_vec().unwrap(), gw);
        let (reply, _) = timeout(&fcx, Duration::from_secs(2), socket.recv(&fcx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply[3] & 0x0f, 1, "FORMERR");
        // Too short to answer at all.
        socket.send_to(b"xx", gw);

        let got = wait_for(&fcx, &log, 8, dns_seen).await;
        assert!(
            got.iter()
                .all(|d| is(sandbox_of(d).unwrap(), "a", Some(me))),
            "{got:#?}"
        );
        let summary: Vec<_> = got
            .iter()
            .map(|d| (flag(d, "tcp"), d.str("name"), d.u64("qtype"), answer(d)))
            .collect();
        let a = |s: &str| s.to_owned();
        assert_eq!(
            summary,
            vec![
                (
                    false,
                    Some("secure.test"),
                    Some(1),
                    format!("addr {SECURE_ADDR}")
                ),
                // Seen before: the callback does not run, the query is still an event.
                (
                    false,
                    Some("secure.test"),
                    Some(1),
                    format!("addr {SECURE_ADDR}")
                ),
                (false, Some("secure.test"), Some(28), a("addr 2001:2::1")),
                (false, Some("nope.test"), Some(1), a("nxdomain")),
                (true, Some("nope.test"), Some(1), a("nxdomain")),
                (false, None, None, a("error 1")),
                (false, None, None, a("error 1")),
                (false, None, None, a("none")),
            ]
        );
        assert_eq!(env.calls.load(Ordering::SeqCst), 2);
        Ok(())
    });
}

#[test]
fn events_for_tls_handshakes() {
    world_events(|fcx, attacher, env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let m = machine(&fcx, attacher.attach("a").unwrap(), me);
        assert_eq!(lookup(&fcx, &m, "secure.test").await, SECURE_ADDR);
        assert_eq!(lookup(&fcx, &m, "shared.test").await, SECURE_ADDR);
        assert_eq!(lookup(&fcx, &m, "events.test").await, EVENTS_ADDR);
        let to = |addr: Ipv4Addr| SocketAddr::new(addr.into(), 443);

        // 1. Accepted, with h2.
        let conn = tls_connect(
            &fcx,
            &m,
            &env,
            SECURE_ADDR,
            "secure.test",
            &[b"h2", b"http/1.1"],
        )
        .await
        .unwrap();
        drop(conn);
        // 2. No SNI (a client that connected to a bare address).
        assert!(
            tls_connect(&fcx, &m, &env, SECURE_ADDR, "203.0.113.10", &[])
                .await
                .is_err()
        );
        // 3. A name with no TLS site at this address.
        assert!(
            tls_connect(&fcx, &m, &env, SECURE_ADDR, "shared.test", &[])
                .await
                .is_err()
        );
        // 4. A client that does not trust the world's CA: it sends unknown_ca.
        let other_ca = fictionet::stdlib::services::ca::Ca::new(&fcx, "Another CA").unwrap();
        let mut other = RootCertStore::empty();
        other.add(other_ca.cert_der()).unwrap();
        let other = Arc::new(other);
        let tcp = m.tcp.connect(&fcx, to(SECURE_ADDR)).await.unwrap();
        let mut client = TlsClient::new(
            &fcx,
            tcp,
            &other,
            "secure.test",
            &[],
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000),
        )
        .unwrap();
        assert!(client.handshake(&fcx).await.is_err());
        // 5. A hello split over several segments.
        let mut tcp = m.tcp.connect(&fcx, to(EVENTS_ADDR)).await.unwrap();
        let mut tls = tls::with_context(&fcx, || {
            ClientConnection::new(
                fictionet::stdlib::world::sandbox::client_config(
                    &fcx,
                    std::time::UNIX_EPOCH + Duration::from_secs(1_893_456_000),
                    Some(&env.roots),
                    &[b"http/1.1"],
                )
                .unwrap(),
                ServerName::try_from("events.test".to_owned()).unwrap(),
            )
        })
        .unwrap();
        let mut hello = Vec::new();
        while tls.wants_write() {
            tls.write_tls(&mut hello).unwrap();
        }
        assert!(hello.len() > 100);
        for chunk in hello.chunks(hello.len() / 3 + 1) {
            tcp.write_all(&fcx, chunk).await.unwrap();
            let _ = fcx.sleep(Duration::from_millis(30)).await;
        }
        let mut client = TlsClient::with(tcp, tls);
        client.handshake(&fcx).await.unwrap();
        drop(client);
        // 6. Closed before a hello.
        let mut tcp = m.tcp.connect(&fcx, to(SECURE_ADDR)).await.unwrap();
        tcp.shutdown(&fcx).await.unwrap();
        // 7. Not TLS at all.
        let mut tcp = m.tcp.connect(&fcx, to(SECURE_ADDR)).await.unwrap();
        tcp.write_all(&fcx, b"GET / HTTP/1.1\r\nHost: secure.test\r\n\r\n")
            .await
            .unwrap();

        let got = wait_for(&fcx, &log, 7, tls_seen).await;
        assert!(
            got.iter()
                .all(|t| is(sandbox_of(t).unwrap(), "a", Some(me))),
            "{got:#?}"
        );
        let summary: Vec<_> = got
            .iter()
            .map(|t| (addr(t, "addr"), t.str("sni"), outcome(t)))
            .collect();
        let (secure, events) = (Some(IpAddr::V4(SECURE_ADDR)), Some(IpAddr::V4(EVENTS_ADDR)));
        assert_eq!(
            summary[0],
            (secure, Some("secure.test"), "accepted h2".to_owned())
        );
        assert_eq!(summary[1], (secure, None, "rejected".to_owned()));
        assert_eq!(
            summary[2],
            (secure, Some("shared.test"), "rejected".to_owned())
        );
        assert_eq!(
            summary[3],
            (secure, Some("secure.test"), "alert 48".to_owned())
        );
        assert_eq!(got[3].str("alert"), Some("unknown_ca"));
        assert_eq!(got[3].u64("alert_code"), Some(48));
        assert_eq!(
            summary[4],
            (events, Some("events.test"), "accepted http/1.1".to_owned())
        );
        assert_eq!(summary[5], (secure, None, "closed".to_owned()));
        assert_eq!(
            (summary[6].1, summary[6].2.as_str()),
            (None, "failed"),
            "{:?}",
            summary[6]
        );
        assert!(!got[6].str("detail").unwrap_or_default().is_empty());
        // Connections are numbered in order, from 1.
        let conns: Vec<u64> = got.iter().map(|t| t.conn.id.unwrap()).collect();
        assert_eq!(conns, (1..=7).collect::<Vec<u64>>());
        Ok(())
    });
}

/// Sends `request` on a new connection to `addr:80` and reads until the
/// server closes it.
pub(super) async fn raw_http(
    fcx: &Cx,
    m: &Machine,
    addr: Ipv4Addr,
    request: &[u8],
) -> Result<Vec<u8>, ConnError> {
    let mut conn = m
        .tcp
        .connect(fcx, SocketAddr::new(addr.into(), 80))
        .await
        .unwrap();
    conn.write_all(fcx, request).await.unwrap();
    read_all(fcx, &mut conn).await
}

#[test]
fn events_for_http_requests() {
    world_events(|fcx, attacher, env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let m = machine(&fcx, attacher.attach("a").unwrap(), me);
        assert_eq!(lookup(&fcx, &m, "events.test").await, EVENTS_ADDR);
        assert_eq!(lookup(&fcx, &m, "secure.test").await, SECURE_ADDR);
        let broken = lookup(&fcx, &m, "broken.test").await;

        // Three HTTP/2 requests on one connection, from a handler that puts
        // a Page in its response's extensions.
        let before = fcx.now();
        let conn = tls_connect(&fcx, &m, &env, EVENTS_ADDR, "events.test", &[b"h2"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, true).await;
        for path in ["/page", "/page?x=1", "/page"] {
            let got = client.get("https", "events.test", path).await;
            assert_eq!(got.status, StatusCode::OK);
            assert_eq!(got.body, "page sni=Some(\"events.test\")");
        }
        let tls = wait_for(&fcx, &log, 1, tls_seen).await.remove(0);
        let pages = wait_for(&fcx, &log, 3, http_seen).await;
        let mut last = before.since_start().as_secs_f64();
        for (h, path) in pages.iter().zip(["/page", "/page?x=1", "/page"]) {
            assert!(is(sandbox_of(h).unwrap(), "a", Some(me)));
            assert_eq!(h.conn.id, tls.conn.id, "one connection");
            assert_eq!(
                (h.str("answer"), h.u64("status"), h.str("version")),
                (Some("handler"), Some(200), Some("HTTP/2.0"))
            );
            let uri: http::Uri = h.str("uri").unwrap().parse().unwrap();
            assert_eq!(
                (h.str("method"), uri.path_and_query().unwrap().as_str()),
                (Some("GET"), path)
            );
            assert_eq!(h.str("world_site"), Some("events.test"));
            assert_eq!(h.str("page"), Some("article"));
            assert_eq!(h.str("received"), Some("complete"));
            assert_eq!(extra(h), 1);
            assert_eq!(
                (h.u64("sent"), flag(h, "complete")),
                (Some("page sni=Some(\"events.test\")".len() as u64), true)
            );
            assert_eq!(
                (h.str("scheme"), h.str("host"), h.str("sni")),
                (Some("https"), Some("events.test"), Some("events.test"))
            );
            assert_eq!(local(h), SocketAddr::from((EVENTS_ADDR, 443)));
            let started = h.get("started").and_then(|v| v.as_f64()).unwrap();
            assert!(started >= last, "requests started in order");
            last = started;
        }
        // The connection's TLS event came first.
        let order = picked(&log, |e| match (e.source, e.kind) {
            ("tls", "handshake") => Some("tls"),
            ("http", "request") => Some("http"),
            _ => None,
        });
        assert_eq!(order, vec!["tls", "http", "http", "http"]);
        log.clear();

        // Answers from Sites itself, on port 80.
        let tcp = m
            .tcp
            .connect(&fcx, SocketAddr::new(SECURE_ADDR.into(), 80))
            .await
            .unwrap();
        let mut client = Client::new(&fcx, tcp, false).await;
        assert_eq!(
            client.get("http", "secure.test", "/x?y=1").await.status,
            StatusCode::MOVED_PERMANENTLY
        );
        assert_eq!(
            client.get("http", "unknown.test", "/").await.status,
            StatusCode::MISDIRECTED_REQUEST
        );
        let tcp = m
            .tcp
            .connect(&fcx, SocketAddr::new(broken.into(), 80))
            .await
            .unwrap();
        let mut client = Client::new(&fcx, tcp, false).await;
        assert_eq!(
            client.get("http", "broken.test", "/").await.status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let reply = raw_http(&fcx, &m, SECURE_ADDR, b"GET / HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        assert!(
            reply.starts_with(b"HTTP/1.0 400"),
            "{}",
            String::from_utf8_lossy(&reply)
        );
        let got = wait_for(&fcx, &log, 4, http_seen).await;
        assert!(got.iter().all(|h| h.str("received") == Some("complete")));
        let summary: Vec<_> = got
            .iter()
            .map(|h| {
                (
                    h.str("answer"),
                    h.u64("status"),
                    h.str("host"),
                    local(h).port(),
                    h.str("sni"),
                    extra(h),
                    flag(h, "complete"),
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                (
                    Some("redirect"),
                    Some(301),
                    Some("secure.test"),
                    80,
                    None,
                    0,
                    true
                ),
                (
                    Some("misdirected"),
                    Some(421),
                    Some("unknown.test"),
                    80,
                    None,
                    0,
                    true
                ),
                (
                    Some("error"),
                    Some(500),
                    Some("broken.test"),
                    80,
                    None,
                    0,
                    true
                ),
                (Some("no_host"), Some(400), None, 80, None, 0, true),
            ]
        );
        assert_eq!(got[0].str("world_site"), Some("secure.test"));
        assert_eq!(got[0].str("uri"), Some("/x?y=1"));
        let headers = got[0].get("headers").and_then(|v| v.as_array()).unwrap();
        let host = headers
            .iter()
            .filter_map(|p| p.as_array())
            .find(|p| p[0].as_str() == Some("host"))
            .unwrap();
        assert_eq!(host[1].as_str(), Some("secure.test"));
        assert_eq!(got[0].conn.id, got[1].conn.id);
        assert_ne!(got[1].conn.id, got[2].conn.id);
        log.clear();

        // HEAD: no body, complete once sent.
        let conn = tls_connect(&fcx, &m, &env, EVENTS_ADDR, "events.test", &[b"http/1.1"])
            .await
            .unwrap();
        let Client::H1(mut send) = Client::new(&fcx, conn, false).await else {
            unreachable!()
        };
        send.ready().await.unwrap();
        let r = send
            .send_request(
                Request::head("/page")
                    .header("host", "events.test")
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        drop(r);
        let got = wait_for(&fcx, &log, 1, http_seen).await;
        assert_eq!(
            (
                got[0].str("method"),
                got[0].u64("sent"),
                flag(&got[0], "complete")
            ),
            (Some("HEAD"), Some(0), true)
        );
        log.clear();

        // A whole download, then one the client cuts short.
        let conn = tls_connect(&fcx, &m, &env, EVENTS_ADDR, "events.test", &[b"h2"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, true).await;
        assert_eq!(
            client.get("https", "events.test", "/big").await.body.len(),
            BIG
        );
        let Client::H2(send) = &mut client else {
            unreachable!()
        };
        send.ready().await.unwrap();
        let response = send
            .send_request(
                Request::get("https://events.test/big")
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut body = response.into_body();
        let first = body.frame().await.unwrap().unwrap();
        assert!(first.is_data());
        // Dropping the body resets the stream.
        drop(body);
        let got = wait_for(&fcx, &log, 2, http_seen).await;
        assert_eq!(
            (got[0].u64("sent"), flag(&got[0], "complete")),
            (Some(BIG as u64), true)
        );
        assert!(!flag(&got[1], "complete"), "{:?}", got[1]);
        let sent = got[1].u64("sent").unwrap();
        assert!(sent < BIG as u64, "{sent}");
        assert_eq!(got[1].u64("status"), Some(200));
        eprintln!("cut short after {sent} of {BIG} bytes");
        log.clear();

        // A request the client cancels while the handler waits: the stream
        // is reset, and the connection goes on.
        send.ready().await.unwrap();
        let waiting = send.send_request(
            Request::get("https://events.test/wait")
                .body(Empty::new())
                .unwrap(),
        );
        assert!(
            timeout(&fcx, Duration::from_millis(200), waiting)
                .await
                .is_none(),
            "no answer to /wait"
        );
        let got = wait_for(&fcx, &log, 1, http_seen).await;
        let g = &got[0];
        assert_eq!(
            (
                g.str("answer"),
                g.u64("status"),
                g.u64("sent"),
                flag(g, "complete")
            ),
            (Some("cancelled"), None, Some(0), false)
        );
        assert_eq!(g.str("path"), Some("/wait"));
        assert_eq!(g.str("world_site"), Some("events.test"));
        assert_eq!(
            client.get("https", "events.test", "/page").await.status,
            StatusCode::OK
        );
        assert_eq!(wait_for(&fcx, &log, 2, http_seen).await.len(), 2);
        Ok(())
    });
}

#[test]
fn events_for_a_client_that_resets_mid_request() {
    world_events(|fcx, attacher, env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let (_, addrs) = raw_dns(&fcx, &mut raw, me, GATEWAY, "slow.test", 1)
            .await
            .unwrap();
        let slow = addrs[0];
        let to = SocketAddr::new(slow.into(), 80);
        // HTTP/1.1, the handler never answers, the client resets.
        let (seq, ack) = raw_connect(
            &fcx,
            &mut raw,
            me,
            to,
            30_000,
            b"GET /wait HTTP/1.1\r\nHost: slow.test\r\n\r\n",
        )
        .await;
        fcx.idle().await?;
        assert!(env.waiting.load(Ordering::SeqCst) == 1);
        assert!(picked(&log, http_seen).is_empty());
        raw.send(tcp_seg(me, 30_000, slow, 80, seq, ack, RST, &[]));
        let got = wait_for(&fcx, &log, 1, http_seen).await;
        assert_eq!(
            (
                got[0].str("answer"),
                got[0].u64("status"),
                flag(&got[0], "complete")
            ),
            (Some("cancelled"), None, false)
        );
        assert_eq!(
            (got[0].str("version"), got[0].str("host")),
            (Some("HTTP/1.1"), Some("slow.test"))
        );
        assert_eq!(got[0].str("world_site"), Some("slow.test"));
        // A reset is the client going away, not an HTTP error.
        fcx.idle().await?;
        assert!(picked(&log, error_seen).is_empty());
        assert_eq!(picked(&log, http_seen).len(), 1, "exactly one event");
        Ok(())
    });
}

/// Sets its flag when dropped.
struct SetOnDrop(Arc<std::sync::atomic::AtomicBool>);

impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A world without an event callback: an HTTP/1.1 client that resets while
/// the handler works ends the handler at once, instead of leaving it
/// running for a client that is gone.
#[test]
fn a_reset_mid_request_drops_the_handler_without_events() {
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = dropped.clone();
    let result = within(Duration::from_secs(30), move || {
        block_on(lab(
            RunOptions::new(Seed::from_u64(1)),
            move |fcx| async move {
                let (attacher, attachments) = fictionet::attachments();
                let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let (seen, set) = (started.clone(), flag.clone());
                let app = axum::Router::new().route(
                    "/hang",
                    axum::routing::get(move || {
                        let (seen, set) = (seen.clone(), set.clone());
                        async move {
                            let _guard = SetOnDrop(set);
                            seen.store(true, Ordering::SeqCst);
                            std::future::pending::<()>().await;
                            "never"
                        }
                    }),
                );
                web::Sites::new(move |host| {
                    (host == "hang.test").then(|| web::Site::new(app.clone()))
                })
                .start(&fcx, attachments)?;

                let me = Ipv4Addr::new(10, 0, 0, 2);
                let mut raw = attacher.attach("a").unwrap();
                let (_, addrs) = raw_dns(&fcx, &mut raw, me, GATEWAY, "hang.test", 1)
                    .await
                    .unwrap();
                let to = SocketAddr::new(addrs[0].into(), 80);
                let (seq, ack) = raw_connect(
                    &fcx,
                    &mut raw,
                    me,
                    to,
                    30_000,
                    b"GET /hang HTTP/1.1\r\nHost: hang.test\r\n\r\n",
                )
                .await;
                fcx.idle().await?;
                assert!(started.load(Ordering::SeqCst), "the handler started");
                assert!(!flag.load(Ordering::SeqCst));
                raw.send(tcp_seg(me, 30_000, addrs[0], 80, seq, ack, RST, &[]));
                fcx.idle().await?;
                // Checked here: stopping the world would drop the handler too.
                assert!(
                    flag.load(Ordering::SeqCst),
                    "the handler was dropped after the reset"
                );
                Err(fictionet::Error::from(Done))
            },
        ))
    });
    assert!(
        matches!(&result, Err(e) if e.downcast_ref::<Done>().is_some()),
        "{:?}",
        result.err().map(|e| e.to_string())
    );
    assert!(dropped.load(Ordering::SeqCst));
}

/// A world stops while HTTP/1.1 and HTTP/2 handlers wait on something
/// outside the world, with their connections still open.
#[test]
fn the_world_stops_while_handlers_wait() {
    world_events(|fcx, attacher, env, log| async move {
        let m = default_machine(&fcx, &attacher);
        let slow = lookup(&fcx, &m, "slow.test").await;
        let to = SocketAddr::new(slow.into(), 80);
        let mut h1 = m.tcp.connect(&fcx, to).await.unwrap();
        h1.write_all(&fcx, b"GET /wait HTTP/1.1\r\nHost: slow.test\r\n\r\n")
            .await
            .unwrap();
        // HTTP/2 with prior knowledge: the preface, empty SETTINGS, and one
        // GET /wait on stream 1 (HPACK: :method GET, :scheme http, then
        // :path and :authority as literals).
        let mut h2 = m.tcp.connect(&fcx, to).await.unwrap();
        let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        bytes.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        let mut block = vec![0x82, 0x86, 0x04, 5];
        block.extend_from_slice(b"/wait");
        block.extend_from_slice(&[0x01, 9]);
        block.extend_from_slice(b"slow.test");
        bytes.extend_from_slice(&[0, 0, block.len() as u8, 1, 0x05, 0, 0, 0, 1]);
        bytes.extend_from_slice(&block);
        h2.write_all(&fcx, &bytes).await.unwrap();
        fcx.idle().await?;
        assert!(env.waiting.load(Ordering::SeqCst) == 2);
        assert!(
            picked(&log, http_seen).is_empty(),
            "both handlers still wait"
        );
        // Keep both connections open while the world stops.
        let _keep = (h1, h2);
        Err(fictionet::Error::from(Done))
    });
}

#[test]
fn partial_preface_eof() {
    world_events(|fcx, attacher, _env, log| async move {
        let m = default_machine(&fcx, &attacher);
        let plain = lookup(&fcx, &m, "plain.test").await;
        let mut conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(plain.into(), 80))
            .await?;
        conn.write_all(&fcx, b"PRI * HTTP/2.0\r\n").await?;
        conn.shutdown(&fcx).await?;
        let reply = read_all(&fcx, &mut conn).await?;
        let errors = picked(&log, error_seen);
        assert_eq!(errors.len(), 1, "a truncated preface must be reported once");
        assert_eq!(errors[0].str("cause"), Some("protocol"));
        assert_eq!(local(&errors[0]), SocketAddr::from((plain, 80)));
        assert_eq!(
            fictionet_test_support::response(&reply, "PRI", false)
                .head
                .status,
            400
        );
        Ok(())
    });
}

#[test]
fn events_for_bytes_that_are_not_http() {
    world_events(|fcx, attacher, env, log| async move {
        let m = default_machine(&fcx, &attacher);
        let plain = lookup(&fcx, &m, "plain.test").await;
        assert_eq!(lookup(&fcx, &m, "events.test").await, EVENTS_ADDR);

        // Garbage on port 80 gets a complete 400 followed by clean EOF.
        let bad_head = raw_http(&fcx, &m, plain, b"\x16\x03\x01\x00\x05hello\r\n\r\n")
            .await
            .unwrap();
        let response = fictionet_test_support::response(&bad_head, "GET", false);
        assert_eq!(response.head.status, 400);
        assert!(response.body.is_empty());
        // HTTP/2 with prior knowledge, then a SETTINGS frame of a size no
        // SETTINGS frame can have.
        let mut bad = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        bad.extend_from_slice(&[0, 0, 5, 4, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5]);
        // The invalid frame gets SETTINGS and a protocol-error GOAWAY, then clean EOF.
        use fictionet::stdlib::protocols::http2;
        let reply = raw_http(&fcx, &m, plain, &bad).await.unwrap();
        let head = http2::FrameHeader::parse(&reply[..http2::HEADER_LEN]).unwrap();
        let (settings, goaway) = reply.split_at(http2::HEADER_LEN + head.length);
        assert!(matches!(
            http2::Frame::parse(settings).unwrap(),
            http2::Frame::Settings(_)
        ));
        assert_eq!(
            http2::Frame::parse(goaway).unwrap(),
            http2::Frame::GoAway(http2::GoAway {
                flags: 0,
                last_stream: 0,
                // SETTINGS payloads must consist of complete six-byte entries.
                code: http2::ErrorCode::FrameSizeError as u32,
                debug: Vec::new(),
            })
        );
        // Clean closes make no event: a whole request, and nothing at all.
        let ok = raw_http(
            &fcx,
            &m,
            plain,
            b"GET / HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        assert!(ok.starts_with(b"HTTP/1.1 200"));
        let mut conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(plain.into(), 80))
            .await
            .unwrap();
        conn.shutdown(&fcx).await.unwrap();
        // An empty half-close is answered by a clean EOF with no bytes.
        assert_eq!(read_all(&fcx, &mut conn).await, Ok(Vec::new()));
        // After a TLS handshake, a record that does not decrypt.
        let mut client = tls_connect(&fcx, &m, &env, EVENTS_ADDR, "events.test", &[b"http/1.1"])
            .await
            .unwrap();
        // First a request, so the server has finished its handshake.
        client
            .write_all(&fcx, b"GET /page HTTP/1.1\r\nHost: events.test\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        read_exact(&fcx, &mut client, &mut buf).await;
        let mut record = vec![23, 3, 3, 0, 40];
        record.extend_from_slice(&[0x55; 40]);
        client.conn.write_all(&fcx, &record).await.unwrap();

        let got = wait_for(&fcx, &log, 3, error_seen).await;
        fcx.idle().await?;
        assert_eq!(
            picked(&log, error_seen).len(),
            3,
            "{:#?}",
            picked(&log, error_seen)
        );
        let summary: Vec<_> = got.iter().map(|b| (local(b), b.str("cause"))).collect();
        assert_eq!(
            summary,
            vec![
                (SocketAddr::from((plain, 80)), Some("protocol")),
                (SocketAddr::from((plain, 80)), Some("protocol")),
                (SocketAddr::from((EVENTS_ADDR, 443)), Some("transport")),
            ]
        );
        let me = Some(Ipv4Addr::new(10, 0, 0, 2));
        assert!(got.iter().all(|b| is(sandbox_of(b).unwrap(), "a", me)
            && !b.str("detail").unwrap_or_default().is_empty()));
        assert_ne!(got[0].conn.id, got[1].conn.id);
        Ok(())
    });
}

/// A client that connects and sends nothing reaches the configured timeout.
#[test]
fn events_for_clients_that_send_nothing() {
    run_world::observed_world(Duration::from_secs(60), |fcx, evidence| async move {
        let (attacher, attachments) = fictionet::attachments();
        sites(&fcx)
            .sites
            .into_net()
            .limits(fictionet::stdlib::world::net::Limits {
                handshake: Duration::from_secs(1),
                dns_tcp_idle: Duration::from_secs(1),
                ..Default::default()
            })
            .start(&fcx, attachments)?;
        let log = Log::new(evidence);
        let m = default_machine(&fcx, &attacher);
        assert_eq!(lookup(&fcx, &m, "secure.test").await, SECURE_ADDR);
        let started = fcx.now();
        let _quiet_80 = m
            .tcp
            .connect(&fcx, SocketAddr::new(SECURE_ADDR.into(), 80))
            .await
            .unwrap();
        let _quiet_443 = m
            .tcp
            .connect(&fcx, SocketAddr::new(SECURE_ADDR.into(), 443))
            .await
            .unwrap();
        let tls = wait_for_long(&fcx, &log, tls_seen).await;
        let took = fcx.now().since_start() - started.since_start();
        assert_eq!(took, Duration::from_secs(1));
        assert_eq!(
            (tls.str("sni"), outcome(&tls)),
            (None, "timed_out".to_owned())
        );
        let bad = wait_for(&fcx, &log, 1, error_seen).await;
        assert_eq!(
            (local(&bad[0]).port(), bad[0].str("cause")),
            (80, Some("timeout"))
        );
        Ok(())
    });
}

/// Waits up to 10 s for the first event `pick` keeps.
async fn wait_for_long<T>(fcx: &Cx, log: &Log, pick: impl Fn(&Event) -> Option<T>) -> T {
    let from = log.from.load(Ordering::SeqCst);
    let got = log
        .events
        .wait(fcx, 0, 1, Duration::from_secs(10), |e| {
            e.seq > from && pick(e).is_some()
        })
        .await
        .expect("the world stopped");
    got.iter().find_map(pick).expect("no such event")
}

#[test]
fn closed_udp_events_match_delivery_for_declared_lengths() {
    world_events(|fcx, attacher, _env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        raw.send(ping(me, GATEWAY, 1));
        recv_within(&fcx, &mut raw, SHORT).await.unwrap();
        log.clear();
        for len in [0u16, 7, 11, u16::MAX] {
            let mut bad = udp(me, 1000, GATEWAY, 5000, b"hi");
            bad.0[24..26].copy_from_slice(&len.to_be_bytes());
            bad.0[26..28].fill(0);
            raw.send(bad);
        }
        assert!(recv_within(&fcx, &mut raw, SHORT).await.is_none());
        assert!(picked(&log, blocked_seen).is_empty());

        let good = udp(me, 1000, GATEWAY, 5000, b"hi");
        let mut bytes = good.0[20..].to_vec();
        bytes.extend_from_slice(b"outside UDP");
        raw.send(ip::packet(me.into(), GATEWAY.into(), 17, &bytes));
        let (_, _, proto, icmp) = parse(&recv_within(&fcx, &mut raw, SHORT).await.unwrap());
        assert_eq!((proto, icmp[0], icmp[1]), (1, 3, 3));
        let events = wait_for(&fcx, &log, 1, blocked_seen).await;
        assert_eq!(events.len(), 1);
        assert_eq!(
            blocked_row(&events[0]),
            (
                "ClosedPort",
                Some(me),
                Some(17),
                Some(me.into()),
                Some(GATEWAY.into()),
                Some(5000)
            )
        );
        Ok(())
    });
}

#[test]
fn events_for_blocked_packets() {
    world_events(|fcx, attacher, _env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();

        // Before binding: not IP, and IPv6 to the unspecified address.
        raw.send(Packet(vec![1, 2, 3]));
        let mut v6 = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
        v6.extend_from_slice(&[0; 32]);
        v6.extend_from_slice(&[0, 1, 0, 53, 0, 8, 0, 0]);
        raw.send(Packet(v6));
        // A source that cannot be bound.
        raw.send(ping(Ipv4Addr::new(192, 168, 1, 5), GATEWAY, 1));
        // DHCP that cannot be read: dropped, not reported.
        raw.send(udp(
            Ipv4Addr::UNSPECIFIED,
            68,
            Ipv4Addr::BROADCAST,
            67,
            b"not dhcp",
        ));
        // Bind, then break the rules.
        raw.send(ping(me, GATEWAY, 2));
        assert!(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .is_some()
        );
        raw.send(ping(Ipv4Addr::new(10, 0, 0, 9), GATEWAY, 3));
        raw.send(ping(me, Ipv4Addr::new(10, 0, 0, 3), 4));
        raw.send(udp(me, 1000, Ipv4Addr::BROADCAST, 2000, b"hi"));
        // No machine there: host unreachable.
        raw.send(ping(me, Ipv4Addr::new(192, 0, 2, 1), 5));
        let (_, _, _, icmp) = parse(
            &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((icmp[0], icmp[1]), (3, 1));
        // Closed ports at a machine and at the gateway.
        let (_, addrs) = raw_dns(&fcx, &mut raw, me, GATEWAY, "plain.test", 5)
            .await
            .unwrap();
        let plain = addrs[0];
        for (dst, port) in [(plain, 22), (plain, 443), (GATEWAY, 80)] {
            raw.send(tcp_seg(me, 30_000, dst, port, 1, 0, SYN, &[]));
            let (_, _, proto, t) = parse(
                &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                    .await
                    .unwrap(),
            );
            assert_eq!((proto, t[13] & RST), (6, RST), "a RST from {dst}:{port}");
        }
        for (dst, port) in [(plain, 9999), (GATEWAY, 5000)] {
            raw.send(udp(me, 1000, dst, port, b"hi"));
            let (_, _, proto, icmp) = parse(
                &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                    .await
                    .unwrap(),
            );
            assert_eq!(
                (proto, icmp[0], icmp[1]),
                (1, 3, 3),
                "port unreachable from {dst}:{port}"
            );
        }
        // UDP with a bad checksum is dropped below Sites, unreported.
        let mut bad = udp(me, 1000, plain, 9999, b"hi");
        let n = bad.0.len();
        bad.0[n - 1] ^= 0xff;
        raw.send(bad);
        assert!(recv_within(&fcx, &mut raw, SHORT).await.is_none());
        // Open ports make no event.
        raw.send(tcp_seg(me, 30_001, plain, 80, 1, 0, SYN, &[]));
        assert!(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .is_some()
        );

        // Each blocked packet is retained as a raw fact.
        let got = wait_for(&fcx, &log, 12, blocked_seen).await;
        let summary: Vec<_> = got.iter().map(blocked_row).collect();
        let v4 = |a: Ipv4Addr| Some(IpAddr::V4(a));
        assert_eq!(
            summary,
            vec![
                ("Malformed", None, None, None, None, None),
                (
                    "Broadcast",
                    None,
                    Some(17),
                    Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
                    Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
                    Some(53)
                ),
                (
                    "NotItsAddress",
                    None,
                    Some(1),
                    v4(Ipv4Addr::new(192, 168, 1, 5)),
                    v4(GATEWAY),
                    None
                ),
                (
                    "NotItsAddress",
                    Some(me),
                    Some(1),
                    v4(Ipv4Addr::new(10, 0, 0, 9)),
                    v4(GATEWAY),
                    None
                ),
                (
                    "OtherSandbox",
                    Some(me),
                    Some(1),
                    v4(me),
                    v4(Ipv4Addr::new(10, 0, 0, 3)),
                    None
                ),
                (
                    "Broadcast",
                    Some(me),
                    Some(17),
                    v4(me),
                    v4(Ipv4Addr::BROADCAST),
                    Some(2000)
                ),
                (
                    "NoRoute",
                    Some(me),
                    Some(1),
                    v4(me),
                    v4(Ipv4Addr::new(192, 0, 2, 1)),
                    None
                ),
                ("ClosedPort", Some(me), Some(6), v4(me), v4(plain), Some(22)),
                (
                    "ClosedPort",
                    Some(me),
                    Some(6),
                    v4(me),
                    v4(plain),
                    Some(443)
                ),
                (
                    "ClosedPort",
                    Some(me),
                    Some(6),
                    v4(me),
                    v4(GATEWAY),
                    Some(80)
                ),
                (
                    "ClosedPort",
                    Some(me),
                    Some(17),
                    v4(me),
                    v4(plain),
                    Some(9999)
                ),
                (
                    "ClosedPort",
                    Some(me),
                    Some(17),
                    v4(me),
                    v4(GATEWAY),
                    Some(5000)
                ),
            ]
        );
        assert!(got.iter().all(|event| event.get("count").is_none()));
        assert!(
            got.iter()
                .all(|b| sandbox_of(b).is_some_and(|s| &*s.name == "a" && s.id == 1))
        );
        log.clear();

        // Past the connection limit, every refusal is recorded.
        let (_, addrs) = raw_dns(&fcx, &mut raw, me, GATEWAY, "secure.test", 6)
            .await
            .unwrap();
        assert_eq!(addrs, vec![SECURE_ADDR]);
        let (open, _) = open_idle(
            &fcx,
            &mut raw,
            me,
            SocketAddr::new(SECURE_ADDR.into(), 443),
            300,
        )
        .await;
        assert_eq!(open, 300);
        let got = wait_for(&fcx, &log, 44, blocked_seen).await;
        assert_eq!(got[0].u64("dst_port"), Some(443));
        assert_eq!(got.len(), 44);
        assert!(got.iter().all(|event| event.get("count").is_none()));
        assert!(got.iter().all(
            |b| b.str("why") == Some("TooManyConnections") && addr(b, "dst") == v4(SECURE_ADDR)
        ));
        assert!(
            got.iter()
                .all(|b| is(sandbox_of(b).unwrap(), "a", Some(me)))
        );
        Ok(())
    });
}

/// A scan cannot evict grading evidence under the production observer limits.
#[test]
fn a_port_scan_cannot_push_out_the_events_a_grader_reads() {
    const SCAN: u16 = 55_000;
    let path = std::env::temp_dir().join(format!("fictionet-scan-{}.jsonl", std::process::id()));
    let jsonl = Arc::new(fictionet_observe::Jsonl::open(&path, Default::default()).unwrap());
    let kept: Arc<std::sync::Mutex<Option<Arc<Memory>>>> = Arc::default();
    let keep = kept.clone();
    world_events_with_memory(
        |memory| {
            RunOptions::new(Seed::from_u64(1)).observer(Arc::new(
                fictionet_observe::Aggregate::new(Arc::new(fictionet::events::Fanout::new(vec![
                    memory,
                    jsonl.clone(),
                ]))),
            ))
        },
        Arc::new(Memory::default()),
        move |fcx, attacher, env, log| async move {
            // What a grader reads: a lookup, a TLS handshake and a request.
            let m = default_machine(&fcx, &attacher);
            assert_eq!(lookup(&fcx, &m, "secure.test").await, SECURE_ADDR);
            let conn = tls_connect(&fcx, &m, &env, SECURE_ADDR, "secure.test", &[b"http/1.1"])
                .await
                .unwrap();
            let mut client = Client::new(&fcx, conn, false).await;
            assert_eq!(
                client.get("https", "secure.test", "/").await.status,
                StatusCode::OK
            );

            // The scan, from another sandbox: every port but the open ones.
            let me = Ipv4Addr::new(10, 0, 0, 3);
            let mut raw = attacher.attach("b").unwrap();
            raw.send(ping(me, GATEWAY, 1));
            assert!(
                recv_within(&fcx, &mut raw, Duration::from_secs(2))
                    .await
                    .is_some()
            );
            let (_, addrs) = raw_dns(&fcx, &mut raw, me, GATEWAY, "plain.test", 2)
                .await
                .unwrap();
            let plain = addrs[0];
            let ports: Vec<u16> = (1..)
                .filter(|p| ![80, 443].contains(p))
                .take(usize::from(SCAN))
                .collect();
            for batch in ports.chunks(500) {
                for &port in batch {
                    raw.send(tcp_seg(me, 40_000, plain, port, 1, 0, SYN, &[]));
                }
                for _ in batch {
                    let (_, _, _, t) = parse(
                        &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                            .await
                            .expect("a RST"),
                    );
                    assert_eq!(t[13] & RST, RST);
                }
            }
            *keep.lock().unwrap() = Some(log.events.clone());
            Ok(())
        },
    );
    jsonl.finish().unwrap();
    let events = kept.lock().unwrap().take().unwrap();
    fn from(e: &Event, name: &str) -> bool {
        sandbox_of(e).is_some_and(|s| &*s.name == name)
    }
    let all = events.checked_all().unwrap();
    let graders: Vec<_> = all
        .iter()
        .filter(|e| from(e, "a") && e.source != "net")
        .map(|e| format!("{}.{}", e.source, e.kind))
        .collect();
    for want in ["dns.query", "tls.handshake", "http.request"] {
        assert!(
            graders.iter().any(|g| g == want),
            "{want} is gone: {graders:?}"
        );
    }
    assert_eq!(events.dropped(), 0);
    let blocked: Vec<_> = all
        .iter()
        .filter(|e| e.is("net", "blocked") && from(e, "b"))
        .collect();
    assert!(blocked.len() < 100, "{} events for the scan", blocked.len());
    assert_eq!(
        blocked
            .iter()
            .map(|event| event.u64("count").unwrap_or(1))
            .sum::<u64>(),
        u64::from(SCAN)
    );
    assert_eq!(jsonl.lost(), 0);
    let text = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(text.lines().count(), all.len());
    assert_eq!(text.as_bytes(), crate::common::evidence_bytes(&events));
    assert!(
        text.lines()
            .any(|l| l.contains(r#""source":"http","kind":"request""#))
    );
}

#[test]
fn default_site_events_do_not_claim_the_requested_name_was_registered() {
    let saved = Arc::new(std::sync::Mutex::new(None));
    let retained = saved.clone();
    world_events(move |fcx, attacher, _env, log| async move {
        *retained.lock().unwrap() = Some(log.events.clone());
        let m = default_machine(&fcx, &attacher);
        assert_eq!(lookup(&fcx, &m, "default.test").await, DEFAULT_ADDR);
        for host in ["default.test", "unregistered.test"] {
            let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            let response = raw_http(&fcx, &m, DEFAULT_ADDR, request.as_bytes())
                .await
                .unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200"));
        }
        Ok(())
    });
    let log = saved.lock().unwrap().take().unwrap();
    let events = log.checked_of("http", "request").unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].str("world_site"), Some("default.test"));
    assert_eq!(events[1].str("world_site"), Some("the default site"));
    assert_eq!(events[1].str("host"), Some("unregistered.test"));
}
