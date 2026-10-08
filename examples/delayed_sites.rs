// A website 200 ms away from every sandbox: `stdlib::delay` in front of
// `web::Sites`, with `Attachments::map`.
//
//     cargo run --example delayed_sites -- /run/fictionet/world.sock

use fictionet::stdlib::{self, web};
use fictionet::time::ms;

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

    fictionet::block_on(fictionet::run(|fcx| async move {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async { "hello from far away\n" }),
        );

        // Every sandbox, as it attaches, gets a 200 ms delay each way.
        let far = attachments.map(&fcx, |fcx, sandbox| stdlib::delay(fcx, ms(200), sandbox));

        web::Sites::new(move |host: &str| match host {
            "example.test" => Some(web::Site::new(app.clone())),
            _ => None,
        })
        .serve(&fcx, far)?;
        Ok(())
    }))
}
