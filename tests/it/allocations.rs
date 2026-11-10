use fictionet::stdlib::web::httpd::Body;
use fictionet::{Budget, Pool};

use super::common::alloc::measuring;

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
