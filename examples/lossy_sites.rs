// A lossy link: `stdlib::filter` in front of `web::Sites` drops 5% of the
// packets in each direction, at random.
//
//     cargo run --example lossy_sites -- /run/fictionet/world.sock

use fictionet::stdlib::{self, web};

/// The share of packets dropped in each direction.
const LOSS: f64 = 0.05;

fn main() -> fictionet::Result {
    let path = std::env::args().nth(1).unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let (attacher, attachments) = fictionet::attachments();
    let _listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(path.clone().into()), attacher)?;
    println!("listening on {path}");

    fictionet::block_on(fictionet::run(|cx| async move {
        let app = axum::Router::new().route("/", axum::routing::get(|| async { "hello over a lossy link\n" }));

        // `cx.random_f64()` is below 0.05 one time in twenty: drop those.
        let lossy = attachments.map(&cx, |cx, sandbox| {
            stdlib::filter(cx, sandbox, |cx, _direction, _packet| cx.random_f64() >= LOSS)
        });

        web::Sites::new(move |host: &str| match host {
            "example.test" => Some(web::Site::new(app.clone())),
            _ => None,
        })
        .serve(&cx, lossy)?;
        Ok(())
    }))
}
