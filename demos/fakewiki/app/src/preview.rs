//! The article page and world without a VM: a placeholder screen and an
//! in-world scripted client that reads the article.

use std::net::Ipv4Addr;

use fakewiki_world::{
    content::Content,
    tamper::{Scope, Tampering},
};
use fictionet::stdlib::{web, world::sandbox};
use fictionet::{RunOptions, Seed};
use fictionet_demo::kit::preview::{Console, Input, Story};
use fictionet_observe::{
    DashboardObserver, DashboardOptions,
    page::{Containment, Host, HostState, HostStatus, Labels, Page, StateLimits, StateTopic},
};

use super::{HOST, page, world};

pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let controls = page::Controls::new("in-world client (scripted)");
    let dashboard = DashboardObserver::new(DashboardOptions {
        collector: fictionet_observe::Options::default(),
        ..Default::default()
    });
    let status = StateTopic::<HostStatus>::new(StateLimits::default());
    let screen = Console::new();
    let labels = Labels::default();
    let server = controls
        .page(
            Page::new("FakeWiki · no VM · placeholder screen", dashboard.handle())
                .containment(StateTopic::<Containment>::new(StateLimits::default()))
                .labels(labels.clone())
                .host(
                    Host::new(HOST)
                        .console(screen.clone())
                        .status(status.clone()),
                ),
        )
        .bind_loopback(fictionet_demo::kit::PAGE_PORT)
        .await?;
    let _access = fictionet_demo::kit::PageAccess::new(server.url())?;
    eprintln!(
        "No VM or Firefox is running. The in-world client's story reads the article. Use the page's tamper switch between runs."
    );
    let mut input = Input::stdin(Story::OnEnter, Some(screen))?;
    let audit = std::sync::Arc::new(fictionet_extras::guest_content::Audit::default());
    let result = fictionet::run(
        RunOptions::new(Seed::from_u64(1)).observer(std::sync::Arc::new(
            fictionet::events::Fanout::new(vec![audit.clone(), dashboard.observer()]),
        )),
        |cx| async move {
            cx.spawn(move |cx| async move { Ok(labels.run(&cx).await?) });
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
            let content = Content::new(tampering.clone());
            let (attacher, attachments) = fictionet::attachments();
            world::network(&cx, leaves, tampering.clone(), || {
                web::Site::handler(content.clone())
            })?
            .start(&cx, attachments)?;
            controls.start(&cx, tampering.clone())?;
            let machine = sandbox::machine(&cx, attacher.attach(HOST)?, Ipv4Addr::new(10, 0, 0, 2));
            while cx.race(None, input.run()).await? {
                let response = world::read_article(&cx, &machine).await?;
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
    audit.check()?;
    Ok(())
}
