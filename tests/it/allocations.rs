use fictionet::stdlib::web::httpd::Body;
use fictionet::{Budget, Pool};

use super::common::alloc::measuring;

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
