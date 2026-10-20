//! The real article page and world, with a placeholder screen and a scripted client.

mod page;
mod world;

use std::net::Ipv4Addr;
use std::time::SystemTime;

use fakewiki_world::{
    content::Content,
    pages,
    tamper::{Scope, Tampering},
};
use fictionet::stdlib::{codec::Wire, protocols::http1, web, world::sandbox};
use fictionet::{RunOptions, Seed};
use fictionet_demo::kit;
use fictionet_observe::{
    DashboardObserver, DashboardOptions,
    page::{Host, HostState, HostStatus, Page, StateLimits, StateTopic},
};

const HOST: &str = "workstation";
const WIKI: &str = "en.wikipedia.org";
const ARTICLE: &str = "/wiki/Stream_ripping";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let controls = page::Controls::new("in-world client (scripted)");
    let dashboard = DashboardObserver::new(DashboardOptions::demo());
    let status = StateTopic::<HostStatus>::new(StateLimits::default());
    let server = controls
        .page(
            Page::new("FakeWiki · no VM · placeholder screen", dashboard.handle()).host(
                Host::new(HOST)
                    .console(kit::preview::Console)
                    .status(status.clone()),
            ),
        )
        .bind_loopback(0)
        .await?;
    println!("{}", server.url());
    eprintln!(
        "No VM or Firefox is running. Press Enter for each scripted article read; EOF stops the example."
    );
    let (sender, mut lines) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || {
        for line in std::io::stdin().lines() {
            if line.is_err() || sender.blocking_send(()).is_err() {
                break;
            }
        }
    });
    let result = fictionet::run(
        RunOptions::new(Seed::from_u64(1)).observer(dashboard.observer()),
        |cx| async move {
            status.publish(
                cx.now(),
                &HostStatus {
                    state: HostState::DesktopUp,
                    addresses: vec![],
                    screen: true,
                    terminal: false,
                },
            )?;
            let tampering = Tampering::new(false, Scope::Wikipedia);
            let (_, leaves) = world::certificates(&cx)?;
            let content = Content::in_process(tampering.clone());
            let (attacher, attachments) = fictionet::attachments();
            world::network(&cx, leaves, tampering.clone(), || {
                web::Site::handler(content.clone())
            })?
            .start(&cx, attachments)?;
            controls.start(&cx, tampering.clone())?;
            let machine = sandbox::machine(&cx, attacher.attach(HOST)?, Ipv4Addr::new(10, 0, 0, 2));
            while cx.race(None, lines.recv()).await?.is_some() {
                let mut tls = machine
                    .tls(
                        &cx,
                        (pages::host_ips()[WIKI], 443).into(),
                        WIKI,
                        None,
                        SystemTime::now(),
                    )
                    .await?;
                let request = http1::Request::parse(
                    format!("GET {ARTICLE} HTTP/1.1\r\nHost: {WIKI}\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )?;
                let response = sandbox::request(&cx, &mut tls, &request).await?;
                eprintln!(
                    "Scripted client received HTTP {} ({} bytes)",
                    response.head.status,
                    response.body.len()
                );
            }
            cx.cancel();
            Ok(())
        },
    )
    .await;
    if let Err(error) = result
        && !error.is::<fictionet::Cancelled>()
    {
        return Err(error.into());
    }
    Ok(())
}
