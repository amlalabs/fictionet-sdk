use fictionet::stdlib::web::httpd::Body;
use fictionet::{Budget, Pool};

use super::common::alloc::measuring;

#[test]
fn virtual_hosts_route_borrowed_names_and_deliver_typed_sites_without_allocating() {
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::network::ConnInfo;
    use fictionet::stdlib::web::{
        Head, Request, Site,
        httpd::{Exchange, Handler, Reply, Routing, VHost, VirtualHosts},
    };
    use fictionet::{Seed, SeededEntropy};

    struct Inspect(Site);
    impl Handler for Inspect {
        fn call(&self, request: Request, exchange: &mut Exchange<'_>) -> Reply {
            assert_eq!(request.site, self.0);
            assert_eq!(request.site.sni, exchange.conn().sni);
            assert!(
                request
                    .head
                    .host()
                    .unwrap()
                    .eq_ignore_ascii_case(self.0.name.as_bytes())
            );
            Reply::Now(http::Response::new(Body::empty()))
        }
    }
    let conn = ConnInfo {
        local: Some("127.0.0.1:8080".parse().unwrap()),
        tls: true,
        sni: Some("tls-name.test".into()),
        ..ConnInfo::default()
    };
    let initial = Site::connection(&conn);
    let expected = Site {
        name: "example.test".into(),
        routing: Routing::Exact,
        ..initial.clone()
    };
    let hosts = VirtualHosts::new();
    let mut vhost = VHost::new(Inspect(expected));
    vhost.https = true;
    hosts.insert("example.test", vhost);
    let entropy = SeededEntropy::new(Seed::from_u64(7));
    let mut exchange = Exchange::new(fictionet::time::Instant::ZERO, &entropy, &conn);
    let heads: Vec<_> = [
        "example.test",
        "EXAMPLE.Test:8080",
        "Example.TEST.",
        "EXAMPLE.test.:443",
    ]
    .into_iter()
    .map(|host| Head::parse(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes()).unwrap())
    .collect();
    let mut route = |head: &Head| {
        let reply = hosts.call(
            Request {
                head: head.clone(),
                body: Body::empty(),
                site: initial.clone(),
            },
            &mut exchange,
        );
        let Reply::Now(response) = reply else {
            panic!("synchronous handler");
        };
        response.status()
    };
    for i in 0..200 {
        assert!(route(&heads[i % heads.len()]).is_success());
    }
    let count: usize = 2000;
    let (_, stats) = measuring(|| {
        for i in 0..count {
            assert!(route(&heads[i % heads.len()]).is_success());
        }
    });
    const CEILING: usize = 0;
    eprintln!(
        "virtual host routing: {} allocations for {count} requests",
        stats.allocations
    );
    assert!(stats.allocations <= count.saturating_mul(CEILING));
    let unknown = Head::parse(b"GET / HTTP/1.1\r\nHost: unknown.test\r\n\r\n").unwrap();
    assert_eq!(route(&unknown), http::StatusCode::MISDIRECTED_REQUEST);
}

#[test]
fn request_head_clones_share_storage() {
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::web::Head;

    let head = Head::parse(b"GET / HTTP/1.1\r\nHost: example.test\r\nX-A: one\r\nx-a: two\r\n\r\n")
        .unwrap();
    let count: usize = 2000;
    let (_, stats) = measuring(|| {
        for _ in 0..count {
            let copy = std::hint::black_box(head.clone());
            assert_eq!(copy, head);
        }
    });
    const CEILING: usize = 0;
    eprintln!(
        "head clones: {} allocations for {count} clones",
        stats.allocations
    );
    assert!(stats.allocations <= count.saturating_mul(CEILING));
}

#[test]
fn pooled_request_heads_reuse_storage() {
    use fictionet::stdlib::codec::{Decode, Step};
    use fictionet::stdlib::protocols::http1::{Event, RequestEvents};

    const CEILING: usize = 0;
    let budget = Budget::new(1 << 20);
    let small = Pool::new(&budget, 2048, 4);
    let large = Pool::new(&budget, 16384 + 64, 2);
    let mut decoder = RequestEvents::new();
    decoder.storage(budget.clone(), small.clone(), large.clone());
    let mut exchange = || {
        let wire = b"GET / HTTP/1.1\r\nHost: example.test\r\nX-A: one\r\nx-a: two\r\n\r\n";
        let Step::Item(Event::Head(head), used) = decoder.decode(wire, false).unwrap() else {
            panic!("request head");
        };
        assert_eq!(used, wire.len());
        assert_eq!(head.field(b"X-a"), Some(b"one".as_slice()));
        assert_eq!(
            head.fields()
                .filter(|(name, _)| name.eq_ignore_ascii_case(b"x-a"))
                .count(),
            2
        );
        drop(head);
        assert!(matches!(
            decoder.decode(&[], false).unwrap(),
            Step::Item(Event::Done, 0)
        ));
    };
    for _ in 0..200 {
        exchange();
    }
    let count: usize = 2000;
    let (_, stats) = measuring(|| {
        for _ in 0..count {
            exchange();
        }
    });
    eprintln!(
        "pooled request heads: {} allocations for {count} requests",
        stats.allocations
    );
    assert!(stats.allocations <= count.saturating_mul(CEILING));
    assert_eq!(budget.used(), small.charged() + large.charged());
}

#[test]
fn pooled_full_bodies_reuse_storage() {
    const CEILING_PER_BODY: usize = 0;
    let budget = Budget::new(1 << 20);
    let pool = Pool::new(&budget, 2048, 4);
    let exchange = || {
        let mut block = pool.take(&budget, 64).unwrap();
        block.extend_within(b"a full response body").unwrap();
        let body = Body::Full(block);
        let bytes = body.bytes().unwrap();
        assert_eq!(&bytes[..], b"a full response body");
        drop(body);
        assert!(!bytes.is_empty());
        drop(bytes);
        assert!(Body::empty().bytes().unwrap().is_empty());
    };
    for _ in 0..200 {
        exchange();
    }
    let count: usize = 2000;
    let (_, stats) = measuring(|| {
        for _ in 0..count {
            exchange();
        }
    });
    eprintln!(
        "full bodies: {} allocations for {count} exchanges",
        stats.allocations
    );
    assert!(stats.allocations <= count.saturating_mul(CEILING_PER_BODY));
    assert!(budget.used() == pool.charged());
}
