//! A lossy link: `stdlib::network::filter` in front of `web::Sites` drops 5% of the
//! packets in each direction, at random.
//!
//! ```text
//! cargo run --example lossy_sites -- /run/fictionet/world.sock /run/fictionet/observation.sock
//! ```
//!
//! The optional second argument opens a Unix observation socket. Watch it
//! from another terminal:
//!
//! ```sh
//! fictionet observe --observation unix:/run/fictionet/observation.sock watch
//! ```
//!
//! For the shell commands and capture limits, see `fictionet_observe`.

use fictionet::stdlib::{self, web};

/// The share of packets dropped in each direction.
const LOSS: f64 = 0.05;

fn main() -> fictionet::Result {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let (options, _observation) = fictionet_observe::serve_observation(
        fictionet::RunOptions::new(fictionet::Seed::random()),
        args.next().map(Into::into),
        None,
    )?;
    let (_listening, attachments) =
        fictionet::Listening::bind(fictionet::WorldSocket::UnixSocket(path.clone().into()))?;
    println!("listening on {path}");

    fictionet::block_on(fictionet::run(options, |fcx| async move {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async { "hello over a lossy link\n" }),
        );

        // `fcx.random_f64()` is below 0.05 one time in twenty: drop those.
        let lossy = attachments.map(&fcx, |fcx, sandbox| {
            let link = stdlib::network::filter(fcx, sandbox, |fcx, _direction, _packet| {
                fcx.random_f64() >= LOSS
            });
            fcx.tap("lossy", link)
        });

        web::Sites::new(move |host: &str| match host {
            "example.test" => Some(web::Site::new(app.clone())),
            _ => None,
        })
        .start(&fcx, lossy)?;
        Ok(())
    }))
}
