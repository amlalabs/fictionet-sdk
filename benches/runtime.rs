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

mod logging {
    use super::*;

    #[divan::bench(args = [false, true], sample_count = 3, sample_size = 1)]
    fn http(bencher: Bencher, writer: bool) {
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

    struct Half(bool);
    impl fictionet_observe::Policy for Half {
        fn classes(&self) -> &[fictionet_observe::Class] {
            const CLASSES: &[fictionet_observe::Class] = &[fictionet_observe::Class::new("events")
                .count(50_000)
                .bytes(16 << 20)];
            CLASSES
        }
        fn admit(&self, interest: fictionet::events::Interest<'_>) -> fictionet_observe::Admit {
            use fictionet::events::Interest;
            use fictionet_observe::Admit;
            match interest {
                Interest::Event(meta, _) if self.0 && meta.kind == "response" => Admit::Skip,
                Interest::Event(..) => Admit::Class(0),
                _ => Admit::Skip,
            }
        }
        fn sort(&self, _: &fictionet::events::Observation<'_>) -> Option<usize> {
            None
        }
        fn topology(&self, _: fictionet::events::TopologyKind) -> bool {
            false
        }
    }

    #[divan::bench(args = [false, true], sample_count = 3, sample_size = 1)]
    fn policy(bencher: Bencher, skip_half: bool) {
        use std::sync::Arc;
        bencher
            .counter(ItemsCount::new(100_000u64))
            .with_inputs(|| {
                let observer =
                    Arc::new(fictionet_observe::Collector::new(Arc::new(Half(skip_half))));
                let options =
                    fictionet::RunOptions::new(fictionet::Seed::from_u64(1)).observer(observer);
                World::with_options(options, |cx, checkpoint| async move {
                    checkpoint.wait().await;
                    for index in 0..100_000u64 {
                        let kind = if index % 2 == 0 {
                            "request"
                        } else {
                            "response"
                        };
                        cx.emit("bench", kind, |event| event.field("index", index));
                    }
                    checkpoint.wait().await;
                    Ok(())
                })
            })
            .bench_local_values(World::measure);
    }
}

mod observe {
    use super::*;

    #[divan::bench(args = [Watch::None, Watch::Graph, Watch::Packets, Watch::Policy], sample_count = 3, sample_size = 1)]
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
