use divan::{Bencher, counter::ItemsCount};
use fictionet_test_support::bench::{World, http};
use http::{HttpCase, Watch};
use std::task::Context;
use std::time::Duration;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

#[divan::bench(sample_count = 3, sample_size = 1)]
fn timers(bencher: Bencher) {
    bencher
        .counter(ItemsCount::new(500_000_u64))
        .with_inputs(|| {
            World::new(|fcx, checkpoint| async move {
                let mut first = fictionet::Timer::new(&fcx);
                let at = fcx.now() + Duration::from_secs(3600);
                assert!(
                    first
                        .poll_until(&mut Context::from_waker(std::task::Waker::noop()), at)
                        .is_pending()
                );
                let mut later = fictionet::Timer::new(&fcx);
                checkpoint.wait().await;
                {
                    let mut cx = Context::from_waker(std::task::Waker::noop());
                    for i in 0..500_000 {
                        assert!(
                            later
                                .poll_until(&mut cx, at + Duration::from_secs(1 + i % 2))
                                .is_pending()
                        );
                    }
                }
                checkpoint.wait().await;
                Ok(())
            })
        })
        .bench_local_values(World::measure);
}

#[divan::bench(args = [false, true], sample_count = 3, sample_size = 1)]
fn logging(bencher: Bencher, writer: bool) {
    http::bench(
        bencher,
        HttpCase {
            sandboxes: 10,
            h2: false,
            requests: 100_000,
            body: 1024,
            sites: 1,
            watch: Watch::None,
            hooks: false,
            writer,
        },
    );
}

mod observe {
    use super::*;

    #[divan::bench(args = [Watch::None, Watch::Graph, Watch::Packets], sample_count = 3, sample_size = 1)]
    fn links(bencher: Bencher, watch: Watch) {
        http::bench(
            bencher,
            HttpCase {
                sandboxes: 10,
                h2: false,
                requests: 200_000,
                body: 1024,
                sites: 1,
                watch,
                hooks: false,
                writer: false,
            },
        );
    }

    #[divan::bench(args = [Watch::None, Watch::Graph], sample_count = 3, sample_size = 1)]
    fn graph(bencher: Bencher, watch: Watch) {
        http::bench(
            bencher,
            HttpCase {
                sandboxes: 1,
                h2: true,
                requests: 150_000,
                body: 1024,
                sites: 1000,
                watch,
                hooks: false,
                writer: false,
            },
        );
    }
}
