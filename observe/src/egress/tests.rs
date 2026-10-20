use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use fictionet::events::{
    ConnInfo, Event, LossReason, Observation, Observer, Sandbox, Stamp, Stream, Transport,
};
use fictionet::time::Instant;

use super::*;

const GUEST: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

fn sandbox(name: &str) -> Sandbox {
    Sandbox {
        id: 1,
        name: Arc::from(name),
        addr: Some(GUEST),
        addr_v6: None,
    }
}

/// A connection from the guest `workstation` to `local`, numbered `id`.
fn conn(id: u64, local: &str) -> ConnInfo {
    let local: SocketAddr = local.parse().unwrap();
    ConnInfo::new(id, local, SocketAddr::new(GUEST.into(), 40_000 + id as u16))
        .from_sandbox(Some(sandbox("workstation")))
}

fn feed(egress: &Egress, at: u64, event: Event) {
    let interest = fictionet::events::Interest::Event(
        fictionet::events::Metadata {
            source: event.source,
            kind: event.kind,
        },
        &event.conn,
    );
    if !egress.enabled(interest) {
        return;
    }
    egress.observe(
        Stamp {
            stream: Stream::Events,
            seq: at,
            at: Instant::from_since_start(Duration::from_secs(at)),
        },
        Observation::Event(&event),
    );
}

fn request(conn: &ConnInfo, host: &str) -> Event {
    Event::new("http", "request")
        .conn(conn)
        .field("host", host)
        .field("world_site", host)
        .field("answer", "handler")
        .field("status", 200u32)
}

fn blocked(why: &str, protocol: u32, dst: &str, port: Option<u32>) -> Event {
    let event = Event::new("net", "blocked")
        .conn(&ConnInfo::default().from_sandbox(Some(sandbox("workstation"))))
        .field("why", why)
        .field("protocol", protocol)
        .field("src", GUEST.to_string())
        .field("dst", dst);
    match port {
        Some(port) => event.field("dst_port", port),
        None => event,
    }
}

fn row<'a>(snapshot: &'a EgressSnapshot, address: &str, outcome: Outcome) -> &'a Destination {
    snapshot
        .destinations
        .iter()
        .find(|d| d.address == address && d.outcome == outcome)
        .unwrap_or_else(|| panic!("no {outcome:?} row for {address}: {snapshot:#?}"))
}

#[test]
fn a_dns_query_without_an_answer_is_refused_and_unanswered() {
    let egress = Egress::default();
    let query = conn(1, "8.8.8.8:53");
    feed(
        &egress,
        1,
        Event::new("dns", "query")
            .conn(&query)
            .field("name", "example.com")
            .field("answer", "none"),
    );
    let snapshot = egress.snapshot();
    let destination = row(&snapshot, "8.8.8.8:53", Outcome::Refused);
    assert_eq!(destination.requests, 1);
    assert_eq!(destination.unanswered, 1);
    assert_eq!(snapshot.lost, 0);
}

#[test]
fn a_world_site_serves_requests_and_counts_each_connection_once() {
    let egress = Egress::default();
    let tls = conn(1, "203.0.113.10:443");
    feed(&egress, 1, Event::new("conn", "open").conn(&tls));
    feed(
        &egress,
        2,
        Event::new("tls", "handshake")
            .conn(&tls)
            .field("sni", "example.test")
            .field("outcome", "accepted"),
    );
    feed(&egress, 3, request(&tls, "example.test"));
    feed(&egress, 4, request(&tls, "example.test"));
    feed(&egress, 5, Event::new("conn", "close").conn(&tls));
    let snapshot = egress.snapshot();
    assert_eq!(snapshot.destinations.len(), 1, "{snapshot:#?}");
    let site = row(&snapshot, "203.0.113.10:443", Outcome::Served);
    assert_eq!(site.sandbox, "workstation");
    assert_eq!(site.transport, "tcp");
    assert_eq!(site.name.as_deref(), Some("example.test"));
    assert_eq!(site.by, "example.test");
    assert_eq!((site.connections, site.requests, site.packets), (1, 2, 0));
    assert_eq!((site.first, site.last), (3.0, 4.0));
    assert!(snapshot.complete());
    assert_eq!(snapshot.at, 4.0);
}

#[test]
fn forwarded_requests_name_the_real_origin_beside_requests_the_world_served() {
    let egress = Egress::default();
    let mirror = conn(1, "198.51.100.7:80");
    feed(&egress, 1, Event::new("conn", "open").conn(&mirror));
    feed(
        &egress,
        2,
        request(&mirror, "archive.ubuntu.com").field("forwarded", "http://archive.ubuntu.com"),
    );
    // The host's cache answered this one: it never left.
    feed(
        &egress,
        3,
        request(&mirror, "archive.ubuntu.com").field("served_by", "host package cache"),
    );
    let claude = conn(2, "198.51.100.9:443");
    feed(
        &egress,
        4,
        request(&claude, "downloads.claude.ai").field("forwarded", "https://downloads.claude.ai"),
    );
    let snapshot = egress.snapshot();
    let forwarded = row(&snapshot, "198.51.100.7:80", Outcome::Forwarded);
    assert_eq!(forwarded.by, "http://archive.ubuntu.com");
    assert_eq!(forwarded.name.as_deref(), Some("archive.ubuntu.com"));
    assert_eq!((forwarded.connections, forwarded.requests), (1, 1));
    let cached = row(&snapshot, "198.51.100.7:80", Outcome::Served);
    assert_eq!(cached.by, "host package cache");
    assert_eq!((cached.connections, cached.requests), (0, 1));
    let download = row(&snapshot, "198.51.100.9:443", Outcome::Forwarded);
    assert_eq!(download.by, "https://downloads.claude.ai");
    let mut origins: Vec<_> = snapshot
        .destinations
        .iter()
        .filter(|d| d.outcome == Outcome::Forwarded)
        .map(|d| d.by.as_str())
        .collect();
    origins.sort_unstable();
    assert_eq!(
        origins,
        ["http://archive.ubuntu.com", "https://downloads.claude.ai"]
    );
}

#[test]
fn closed_ports_rejected_names_and_misdirected_requests_are_refused() {
    let egress = Egress::default();
    feed(
        &egress,
        1,
        blocked("ClosedPort", 6, "203.0.113.10", Some(22)),
    );
    feed(
        &egress,
        2,
        blocked("ClosedPort", 6, "203.0.113.10", Some(22)).field("count", 4u32),
    );
    let tls = conn(7, "203.0.113.10:443");
    feed(&egress, 3, Event::new("conn", "open").conn(&tls));
    feed(
        &egress,
        4,
        Event::new("tls", "handshake")
            .conn(&tls)
            .field("sni", "bank.test")
            .field("outcome", "rejected"),
    );
    feed(&egress, 5, Event::new("conn", "close").conn(&tls));
    let plain = conn(8, "203.0.113.10:80");
    feed(
        &egress,
        6,
        Event::new("http", "request")
            .conn(&plain)
            .field("host", "other.test")
            .field("answer", "misdirected"),
    );
    let snapshot = egress.snapshot();
    let port = row(&snapshot, "203.0.113.10:22", Outcome::Refused);
    assert_eq!((port.by.as_str(), port.packets), ("port closed", 5));
    let name = row(&snapshot, "203.0.113.10:443", Outcome::Refused);
    assert_eq!(name.by, "no site for that name");
    assert_eq!(name.name.as_deref(), Some("bank.test"));
    assert_eq!(name.connections, 1, "the close does not count it twice");
    let request = row(&snapshot, "203.0.113.10:80", Outcome::Refused);
    assert_eq!(
        (request.by.as_str(), request.requests),
        ("no site for that name", 1)
    );
    assert!(
        !snapshot
            .destinations
            .iter()
            .any(|d| d.outcome == Outcome::Served)
    );
}

#[test]
fn public_resolvers_raw_addresses_and_ipv6_have_no_route() {
    let egress = Egress::default();
    // The world's DNS answered the name; nothing answered 8.8.8.8 or 1.1.1.1.
    let dns = ConnInfo {
        transport: Transport::Udp,
        ..conn(1, "10.0.2.2:53")
    };
    feed(
        &egress,
        1,
        Event::new("dns", "query")
            .conn(&dns)
            .field("name", "www.google.com")
            .field("qtype", 1u32)
            .field("answer", "nxdomain"),
    );
    feed(
        &egress,
        2,
        Event::new("dns", "query")
            .conn(&dns)
            .field("name", "example.test")
            .field("qtype", 1u32)
            .field("answer", "addr")
            .field("addr", "203.0.113.10"),
    );
    feed(&egress, 3, blocked("NoRoute", 17, "8.8.8.8", Some(53)));
    feed(&egress, 4, blocked("NoRoute", 6, "1.1.1.1", Some(443)));
    feed(
        &egress,
        5,
        blocked("Ipv6", 58, "2606:4700:4700::1111", None),
    );
    feed(
        &egress,
        6,
        blocked("ClosedPort", 6, "203.0.113.10", Some(8443)),
    );
    let snapshot = egress.snapshot();
    let resolver = row(&snapshot, "10.0.2.2:53", Outcome::Served);
    assert_eq!(
        (
            resolver.by.as_str(),
            resolver.transport.as_str(),
            resolver.requests
        ),
        ("the world's DNS", "udp", 2)
    );
    let google = snapshot
        .lookups
        .iter()
        .find(|l| l.name == "www.google.com")
        .unwrap();
    assert_eq!(google.answer, "no such name");
    let dns8 = row(&snapshot, "8.8.8.8:53", Outcome::NoRoute);
    assert_eq!(
        (dns8.transport.as_str(), dns8.by.as_str()),
        ("udp", "no machine at that address")
    );
    let raw = row(&snapshot, "1.1.1.1:443", Outcome::NoRoute);
    assert_eq!(raw.transport, "tcp");
    let v6 = row(&snapshot, "2606:4700:4700::1111", Outcome::NoRoute);
    assert_eq!(
        (v6.transport.as_str(), v6.by.as_str()),
        ("icmpv6", "IPv6 is off")
    );
    // The guest's own lookup names the address it then tried.
    let named = row(&snapshot, "203.0.113.10:8443", Outcome::Refused);
    assert_eq!(named.name.as_deref(), Some("example.test"));
}

#[test]
fn a_full_table_counts_what_it_drops_and_run_losses_mark_it_incomplete() {
    let egress = Egress::new(EgressLimits {
        rows: 2,
        lookups: 1,
        names: 1,
        connections: 1,
    });
    for (at, address) in ["192.0.2.1", "192.0.2.2", "192.0.2.3"].iter().enumerate() {
        feed(
            &egress,
            at as u64,
            blocked("NoRoute", 6, address, Some(443)).field("count", 3u32),
        );
    }
    // An existing row still counts.
    feed(&egress, 4, blocked("NoRoute", 6, "192.0.2.1", Some(443)));
    let snapshot = egress.snapshot();
    assert_eq!(snapshot.destinations.len(), 2);
    assert_eq!(snapshot.dropped, 3, "the third destination's three packets");
    assert_eq!(row(&snapshot, "192.0.2.1:443", Outcome::NoRoute).packets, 4);
    assert!(!snapshot.complete());
    let revision = snapshot.revision;
    // Connections past the bound count as dropped too.
    feed(
        &egress,
        5,
        Event::new("conn", "open").conn(&conn(1, "203.0.113.1:22")),
    );
    feed(
        &egress,
        6,
        Event::new("conn", "open").conn(&conn(2, "203.0.113.1:22")),
    );
    assert_eq!(egress.snapshot().dropped, 4);
    egress.lost(fictionet::events::Loss {
        stream: Stream::Events,
        reason: LossReason::Overflow,
        count: 7,
        bytes: None,
        seqs: None,
    });
    egress.lost(fictionet::events::Loss {
        stream: Stream::Keys,
        reason: LossReason::Overflow,
        count: 9,
        bytes: None,
        seqs: None,
    });
    let snapshot = egress.snapshot();
    assert_eq!(snapshot.lost, 7, "only lost events count");
    assert!(snapshot.revision > revision);
}

#[test]
fn a_service_connection_without_requests_counts_when_it_closes() {
    let egress = Egress::default();
    let ssh = conn(3, "203.0.113.20:22");
    feed(&egress, 1, Event::new("conn", "open").conn(&ssh));
    assert!(egress.snapshot().destinations.is_empty());
    feed(&egress, 9, Event::new("conn", "close").conn(&ssh));
    let snapshot = egress.snapshot();
    let service = row(&snapshot, "203.0.113.20:22", Outcome::Served);
    assert_eq!(
        (service.by.as_str(), service.connections),
        ("a world service", 1)
    );
}

#[test]
fn events_without_a_sandbox_are_not_attempts_from_a_guest() {
    let egress = Egress::default();
    let world = ConnInfo::new(
        1,
        "203.0.113.10:443".parse().unwrap(),
        "203.0.113.11:5000".parse().unwrap(),
    );
    feed(&egress, 1, request(&world, "example.test"));
    feed(&egress, 2, Event::new("shop", "order"));
    let snapshot = egress.snapshot();
    assert!(snapshot.destinations.is_empty());
    assert_eq!(snapshot.revision, 0);
}

#[test]
fn a_world_names_the_sandbox_of_a_packet_it_refused_itself() {
    let egress = Egress::default();
    let refused = |sandbox: Option<&str>| {
        let event = Event::new("net", "blocked")
            .field("why", "NoRoute")
            .field("protocol", 17u32)
            .field("dst", "1.1.1.1")
            .field("dst_port", 53u32);
        match sandbox {
            Some(name) => event.field("sandbox", name),
            None => event,
        }
    };
    feed(&egress, 1, refused(None));
    feed(
        &egress,
        2,
        Event::new("path", "unreachable").field("sandbox", "agent"),
    );
    assert_eq!(
        egress.snapshot().revision,
        0,
        "no sandbox, or not net.blocked"
    );
    feed(&egress, 3, refused(Some("agent")));
    let snapshot = egress.snapshot();
    let row = row(&snapshot, "1.1.1.1:53", Outcome::NoRoute);
    assert_eq!(
        (row.sandbox.as_str(), row.transport.as_str(), row.packets),
        ("agent", "udp", 1)
    );
    assert_eq!(row.by, "no machine at that address");
}

#[test]
fn cached_answers_name_the_host_cache() {
    let egress = Egress::default();
    feed(
        &egress,
        1,
        request(&conn(1, "198.51.100.7:80"), "archive.ubuntu.com")
            .field("served_by", "host package cache"),
    );
    let snapshot = egress.snapshot();
    let cached = row(&snapshot, "198.51.100.7:80", Outcome::Served);
    assert_eq!(cached.by, "host package cache");
    assert_eq!(cached.requests, 1);
    assert!(snapshot.complete());
}

#[test]
fn failed_handshakes_before_service_open_are_attempts() {
    for outcome in [
        "rejected",
        "alert",
        "failed",
        "closed",
        "timed_out",
        "detached",
        "cancelled",
    ] {
        let egress = Egress::default();
        feed(
            &egress,
            1,
            Event::new("tls", "handshake")
                .conn(&conn(1, "203.0.113.10:443"))
                .field("sni", "example.test")
                .field("outcome", outcome),
        );
        let snapshot = egress.snapshot();
        assert_eq!(snapshot.destinations.len(), 1);
        assert_eq!(snapshot.destinations[0].connections, 1);
        assert_eq!(snapshot.destinations[0].outcome, Outcome::Refused);
    }
}

#[test]
fn topology_names_live_connections_and_closing_counts_them_once() {
    use fictionet::events::TopologyRef;
    struct HostIdentity(std::sync::Mutex<Option<fictionet::events::HostId>>);
    impl Observer for HostIdentity {
        fn enabled(&self, interest: Interest<'_>) -> bool {
            matches!(interest, Interest::Topology(TopologyKind::Host))
        }
        fn observe(&self, _: Stamp, item: Observation<'_>) {
            if let Observation::Topology(TopologyRef::HostAdded { host, .. }) = item {
                *self.0.lock().unwrap() = Some(host);
            }
        }
    }
    let identity = Arc::new(HostIdentity(std::sync::Mutex::new(None)));
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(1)).observer(identity.clone()),
        |cx| async move {
            let _host = cx.host("jump server");
            Ok(())
        },
    ))
    .unwrap();
    let host = identity.0.lock().unwrap().unwrap();
    let egress = Egress::default();
    let info = conn(1, "203.0.113.10:22");
    let stamp = Stamp {
        stream: Stream::Topology,
        seq: 1,
        at: Instant::ZERO,
    };
    egress.observe(
        stamp,
        Observation::Topology(TopologyRef::HostAdded {
            host,
            name: "jump server",
            group: None,
            sandbox: None,
        }),
    );
    egress.observe(
        stamp,
        Observation::Topology(TopologyRef::ConnectionOpened {
            conn: &info,
            task: None,
            host: Some(host),
        }),
    );
    feed(&egress, 1, Event::new("conn", "open").conn(&info));
    let snapshot = egress.snapshot();
    assert_eq!(snapshot.pending.len(), 1);
    assert_eq!(snapshot.pending[0].service.as_deref(), Some("jump server"));
    egress.observe(
        stamp,
        Observation::Topology(TopologyRef::ConnectionClosed { conn: &info }),
    );
    feed(&egress, 2, Event::new("conn", "close").conn(&info));
    let snapshot = egress.snapshot();
    assert!(snapshot.pending.is_empty());
    assert_eq!(snapshot.destinations.len(), 1);
    assert_eq!(snapshot.destinations[0].by, "jump server");
    assert_eq!(snapshot.destinations[0].connections, 1);
}

#[test]
fn a_name_from_one_sandbox_does_not_name_another_sandbox_destination() {
    let egress = Egress::default();
    feed(
        &egress,
        1,
        Event::new("dns", "query")
            .conn(&conn(1, "10.0.2.2:53"))
            .field("name", "example.test")
            .field("answer", "addr")
            .field("addr", "203.0.113.10"),
    );
    let mut other = blocked("ClosedPort", 6, "203.0.113.10", Some(22));
    other.conn.sandbox = Some(sandbox("another guest"));
    feed(&egress, 2, other);
    let snapshot = egress.snapshot();
    assert!(
        row(&snapshot, "203.0.113.10:22", Outcome::Refused)
            .name
            .is_none()
    );
}

#[test]
fn the_matched_site_takes_precedence_over_the_requested_name() {
    let egress = Egress::default();
    feed(
        &egress,
        1,
        request(&conn(1, "203.0.113.10:80"), "unregistered.test")
            .field("world_site", "the default site"),
    );
    let snapshot = egress.snapshot();
    assert_eq!(snapshot.destinations[0].by, "the default site");
    assert_eq!(
        snapshot.destinations[0].name.as_deref(),
        Some("unregistered.test")
    );
}

#[test]
fn requests_without_an_answer_keep_their_destination_facts() {
    for answer in ["cancelled", "error"] {
        let egress = Egress::default();
        feed(
            &egress,
            1,
            request(&conn(1, "203.0.113.10:80"), "example.test").field("answer", answer),
        );
        let snapshot = egress.snapshot();
        assert_eq!(snapshot.lost, 0);
        assert!(snapshot.complete());
        assert_eq!(snapshot.destinations.len(), 1);
        let site = &snapshot.destinations[0];
        assert_eq!(site.outcome, Outcome::Served);
        assert_eq!(site.by, "example.test");
        assert_eq!((site.requests, site.unanswered), (1, 1));
        feed(
            &egress,
            2,
            request(&conn(2, "203.0.113.10:80"), "example.test")
                .field("answer", answer)
                .field("forwarded", "https://example.test"),
        );
        let snapshot = egress.snapshot();
        let forwarded = row(&snapshot, "203.0.113.10:80", Outcome::Forwarded);
        assert_eq!(forwarded.by, "https://example.test");
        assert_eq!((forwarded.requests, forwarded.unanswered), (1, 1));
        assert!(snapshot.complete());
    }
}

#[test]
fn service_open_keeps_the_name_negotiated_before_it() {
    let egress = Egress::default();
    let conn = conn(1, "203.0.113.10:443").over_tls(Some("example.test"), None);
    feed(&egress, 1, Event::new("conn", "open").conn(&conn));
    feed(&egress, 2, Event::new("conn", "close").conn(&conn));
    let snapshot = egress.snapshot();
    assert_eq!(
        snapshot.destinations[0].name.as_deref(),
        Some("example.test")
    );
    assert_eq!(snapshot.destinations[0].by, "example.test");
}
