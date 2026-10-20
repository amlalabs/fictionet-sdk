//! Runs the world on a world socket for `fictionet attach` in the Compose demo.
//! The first argument is the socket path, defaulting to `/run/fictionet/world.sock`.
//! The optional second argument opens a Unix observation socket for the
//! dashboard. Prints `attached <name>` for each sandbox.
//!
//! ```sh
//! fictionet observe --observation unix:/run/fictionet/observation.sock watch
//! ```

use fictionet::Result;

fn main() -> Result {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let (options, _observation) = fictionet_observe::serve_observation(
        fictionet::RunOptions::new(fictionet::Seed::random()),
        args.next(),
        None,
    )?;
    let (_listening, attachments) =
        fictionet::Listening::bind(fictionet::WorldSocket::UnixSocket(path.clone().into()))?;
    println!("listening on {path}");
    fictionet::block_on(fictionet::run(options, move |fcx| {
        let attachments = attachments.map(&fcx, |_, sandbox| {
            println!("attached {}", sandbox.name());
            sandbox
        });
        scan_world::world(fcx, attachments)
    }))
}
