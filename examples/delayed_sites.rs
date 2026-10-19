// A website 200 ms away from every sandbox: `stdlib::network::delay` in front of
// `web::Sites`, with `Attachments::map`.
//
//     cargo run --example delayed_sites -- /run/fictionet/world.sock [observation.sock]

use fictionet::stdlib::{self, web};
use fictionet::time::ms;

fn main() -> fictionet::Result {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let mut options = fictionet::RunOptions::new(fictionet::Seed::random());
    let _observation = if let Some(path) = args.next() {
        let dashboard = fictionet_observe::DashboardObserver::new(Default::default());
        options = options.observer(std::sync::Arc::new(fictionet_observe::Aggregate::new(
            dashboard.observer(),
        )));
        Some(fictionet_observe::serve(dashboard.handle(), path)?)
    } else {
        None
    };
    let (_listening, attachments) =
        fictionet::Listening::bind(fictionet::WorldSocket::UnixSocket(path.clone().into()))?;
    println!("listening on {path}");

    fictionet::block_on(fictionet::run(options, |fcx| async move {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async { "hello from far away\n" }),
        );

        // Every sandbox, as it attaches, gets a 200 ms delay each way.
        let far = attachments.map(&fcx, |fcx, sandbox| {
            stdlib::network::delay(fcx, ms(200), sandbox)
        });

        web::Sites::new(move |host: &str| match host {
            "example.test" => Some(web::Site::new(app.clone())),
            _ => None,
        })
        .start(&fcx, far)?;
        Ok(())
    }))
}
