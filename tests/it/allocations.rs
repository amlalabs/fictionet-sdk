use super::common::alloc::measuring;
use fictionet_test_support::bench::{World, http};
use std::sync::{Arc, Mutex};

const REQUESTS: usize = 2000;
// Round the measured server totals per request up, including checkpoint
// overhead. A whole additional allocation per request exceeds these bounds.
const HTTP1_CEILING: usize = 39;
const HTTP2_CEILING: usize = 64;

fn split(h2: bool) {
    let server_thread = std::thread::current().id();
    let client_stats = Arc::new(Mutex::new(None));
    let measured = client_stats.clone();
    let world = http::world(
        http::HttpCase {
            sandboxes: 1,
            h2,
            requests: REQUESTS,
            body: 1024,
            sites: 1,
        },
        Arc::new(Mutex::new(None)),
        move |world| {
            assert_ne!(std::thread::current().id(), server_thread);
            let (world, stats) = measuring(|| World::measure(world));
            *measured.lock().unwrap() = Some(stats);
            world
        },
    );
    let (world, server) = measuring(|| world.measure());
    let ceiling = if h2 { HTTP2_CEILING } else { HTTP1_CEILING };
    assert!(
        server.allocations <= REQUESTS * ceiling,
        "{} server allocations exceed {ceiling} per request over {REQUESTS} requests",
        server.allocations
    );
    let client = client_stats.lock().unwrap().unwrap();
    assert!(client.allocations > 0);
    assert!(server.allocations > 0);
    eprintln!("h2={h2}: server={server:?}, client={client:?}");
    drop(world);
}

#[test]
fn http1_server_allocations() {
    split(false);
}

#[test]
fn http2_server_allocations() {
    split(true);
}
