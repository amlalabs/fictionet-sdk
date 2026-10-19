use fictionet::Result;

fn main() -> Result {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let (_listening, attachments) =
        fictionet::Listening::bind(fictionet::WorldSocket::UnixSocket(path.clone().into()))?;
    println!("listening on {path}");
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::random())
            .aggregate_events()
            .event_history(std::sync::Arc::new(fictionet::events::Memory::default())),
        move |fcx| {
            let attachments = attachments.map(&fcx, |_, sandbox| {
                println!("attached {}", sandbox.name());
                sandbox
            });
            scan_world::world(fcx, attachments)
        },
    ))
}
