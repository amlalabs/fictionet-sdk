//! Bulk TCP over one pair, alternating the SDK and a copied module.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use fictionet::stdlib::{Connection, ConnectionExt};
use fictionet::{Cx, block_on, pair, run};

// Allow 15% less throughput and 5% more allocations per MB for the copy.
const MAX_SLOWDOWN: f64 = 0.15;
const MAX_EXTRA_ALLOCS: f64 = 0.05;
const ROUNDS: usize = 7;
const BYTES: usize = 256 * 1024 * 1024;

struct Counting;
static ALLOCS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

struct Sample {
    seconds: f64,
    allocations: u64,
}

async fn read_exact<C: Connection>(fcx: &Cx, conn: &mut C, buf: &mut [u8]) -> fictionet::Result {
    let mut at = 0;
    while at < buf.len() {
        let n = conn.read(fcx, &mut buf[at..]).await?;
        assert!(n > 0, "TCP ended before all bytes arrived");
        at += n;
    }
    Ok(())
}

async fn transfer<C: Connection>(
    fcx: &Cx,
    mut client: C,
    mut server: C,
    bytes: usize,
) -> fictionet::Result {
    let writer = fcx.spawn(move |fcx| async move {
        let buf = vec![0x5a; 65536];
        let mut left = bytes;
        while left > 0 {
            let n = left.min(buf.len());
            server.write_all(&fcx, &buf[..n]).await?;
            left -= n;
        }
        // Keep the writer open until the reader acknowledges every byte.
        let mut done = [0];
        read_exact(&fcx, &mut server, &mut done).await?;
        assert_eq!(done, [1]);
        Ok(())
    });
    let mut buf = vec![0; 65536];
    let mut left = bytes;
    while left > 0 {
        let n = left.min(buf.len());
        read_exact(fcx, &mut client, &mut buf[..n]).await?;
        // Spot checks keep the reader's own work small next to TCP's.
        assert!(
            buf[0] == 0x5a && buf[n / 2] == 0x5a && buf[n - 1] == 0x5a,
            "TCP delivered wrong bytes"
        );
        left -= n;
    }
    client.write_all(fcx, &[1]).await?;
    writer.join(fcx).await?;
    Ok(())
}

// Both cases use the same setup and transfer, with concrete endpoint types.
macro_rules! case {
    ($name:ident, $module:path) => {
        fn $name(bytes: usize) -> Sample {
            use $module as tcp;
            let out = Arc::new(Mutex::new(None));
            let result = out.clone();
            let run_result = block_on(run(move |fcx| async move {
                let (a, b) = pair();
                let client = tcp::endpoint(&fcx, a, "10.0.0.1".parse()?);
                let server = tcp::endpoint(&fcx, b, "10.0.0.2".parse()?);
                let mut listener = server.listen(80)?;
                let c = client.connect(&fcx, "10.0.0.2:80".parse()?).await?;
                let s = listener.accept(&fcx).await?;
                let allocations = ALLOCS.load(Ordering::Relaxed);
                let start = Instant::now();
                transfer(&fcx, c, s, bytes).await?;
                let seconds = start.elapsed().as_secs_f64();
                let allocations = ALLOCS.load(Ordering::Relaxed) - allocations;
                *result.lock().unwrap() = Some(Sample {
                    seconds,
                    allocations,
                });
                fcx.cancel();
                Ok(())
            }));
            if let Err(error) = run_result
                && !error.is::<fictionet::Cancelled>()
            {
                panic!("TCP benchmark failed: {error}");
            }
            out.lock().unwrap().take().expect("TCP transfer completed")
        }
    };
}

case!(builtin, fictionet::stdlib::tcp);
case!(copied, fictionet_copy_modules::tcp);

fn row(name: &str, samples: &[Sample]) -> (f64, f64) {
    let mb = BYTES as f64 / 1_000_000.0;
    let mut rates: Vec<_> = samples.iter().map(|s| mb / s.seconds).collect();
    let mut allocations: Vec<_> = samples.iter().map(|s| s.allocations as f64 / mb).collect();
    rates.sort_by(f64::total_cmp);
    allocations.sort_by(f64::total_cmp);
    let middle = samples.len() / 2;
    let best = rates[samples.len() - 1];
    println!(
        "{name:<10} {:>10.1} {:>10.1} [{:>7.1}, {:>7.1}] {:>12.1}",
        best, rates[middle], rates[0], best, allocations[middle]
    );
    // Other work on the machine only slows a round, so the fastest round
    // is the steadiest measure of what the code can do.
    (best, allocations[middle])
}

fn main() {
    // Warm both code paths before measuring; setup is outside the timed span.
    builtin(1024 * 1024);
    copied(1024 * 1024);
    let mut built = Vec::with_capacity(ROUNDS);
    let mut copy = Vec::with_capacity(ROUNDS);
    // Each side goes first in alternate rounds, so neither always runs on
    // the state the other left behind.
    for round in 0..ROUNDS {
        if round % 2 == 0 {
            built.push(builtin(BYTES));
            copy.push(copied(BYTES));
        } else {
            copy.push(copied(BYTES));
            built.push(builtin(BYTES));
        }
    }
    println!("{ROUNDS} rounds per side, {BYTES} bytes per round; MB = 1,000,000 bytes");
    println!("             best MB/s median MB/s       range MB/s     allocs/MB");
    let (built_rate, built_allocs) = row("built-in", &built);
    let (copy_rate, copy_allocs) = row("copy", &copy);
    assert!(
        copy_rate >= built_rate * (1.0 - MAX_SLOWDOWN),
        "the copy's best throughput fell more than 15% below the built-in's"
    );
    assert!(
        copy_allocs <= built_allocs * (1.0 + MAX_EXTRA_ALLOCS),
        "copy allocations rose more than 5%"
    );
}
