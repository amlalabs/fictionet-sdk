// A sandbox on a slow link: `stdlib::bottleneck` in front of `web::Sites`,
// with a count of the packets its queues drop.
//
//     cargo run --example bottleneck_sites -- /run/fictionet/world.sock

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use fictionet::stdlib::{self, Direction, web};
use fictionet::time::ms;

/// 8 Mbit/s: one megabyte a second, each way.
const RATE: u64 = 8_000_000;
/// Room for 100 waiting packets in each direction.
const QUEUE: usize = 100;

/// Packets counted on one side of the bottleneck: `[toward the sandbox,
/// from the sandbox]`.
type Counts = Arc<[AtomicU64; 2]>;

/// A filter that counts packets by direction and passes them all.
fn count(fcx: &fictionet::Cx, inner: impl fictionet::Interface, counts: Counts) -> fictionet::End {
    stdlib::filter(fcx, inner, move |_, direction, _| {
        let i = if direction == Direction::ToInner {
            0
        } else {
            1
        };
        counts[i].fetch_add(1, Ordering::Relaxed);
        true
    })
}

fn main() -> fictionet::Result {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let (attacher, attachments) = fictionet::attachments();
    let _listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(path.clone().into()),
        attacher,
    )?;
    println!("listening on {path}");

    fictionet::block_on(fictionet::run(
        fictionet::Seed::random(),
        |fcx| async move {
            let app =
                axum::Router::new()
                    .route("/4mb", get(|| async { vec![b'x'; 4 << 20] }))
                    .route(
                        "/upload",
                        post(|body: axum::body::Bytes| async move {
                            format!("got {} bytes\n", body.len())
                        }),
                    )
                    // The agent sends this body, so keep a limit on it.
                    .layer(DefaultBodyLimit::max(8 << 20));

            let slow = attachments.map(&fcx, |fcx, sandbox| {
            // Count packets on both sides of the bottleneck. A packet
            // that went in on one side and never came out of the other
            // was dropped by the queue.
            let name = sandbox.name().to_owned();
            let near: Counts = Arc::default();
            let far: Counts = Arc::default();
            let link = count(fcx, sandbox, near.clone());
            let link = stdlib::bottleneck(fcx, RATE, QUEUE, link);
            let link = count(fcx, link, far.clone());

            // Each time the packets stop for a second, report. The queues
            // are empty by then, so the counts are exact. When the sandbox
            // detaches, the filters stop and drop their counts, and so
            // this task stops too.
            fcx.spawn(move |fcx| async move {
                let total = |c: &Counts| c[0].load(Ordering::Relaxed) + c[1].load(Ordering::Relaxed);
                let (mut last, mut reported) = (0, 0);
                while Arc::strong_count(&near) > 1 {
                    fcx.sleep(ms(1000)).await?;
                    let now = total(&far);
                    if now == last && now != reported {
                        reported = now;
                        let n = |c: &Counts, i: usize| c[i].load(Ordering::Relaxed);
                        // Toward the sandbox, packets enter at `far` and
                        // leave at `near`. From it, the other way round.
                        println!(
                            "{name}: toward it {} packets, {} dropped; from it {} packets, {} dropped",
                            n(&far, 0),
                            n(&far, 0) - n(&near, 0),
                            n(&near, 1),
                            n(&near, 1) - n(&far, 1),
                        );
                    }
                    last = now;
                }
                Ok(())
            });
            link
        });

            web::Sites::new(move |host: &str| match host {
                "example.test" => Some(web::Site::new(app.clone())),
                _ => None,
            })
            .start(&fcx, slow)?;
            Ok(())
        },
    ))
}
