//! The bank, the package mirrors, Claude Code's model site, and the admin
//! attachment.

use super::control::Control;
use border_world::{Extra, certs, log::Log, scenario::Scenario};
use fictionet::{
    Cx,
    stdlib::{services::ca::Ca, web},
};
use fictionet_demo::kit;
use fictionet_extras::models;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::SystemTime;

/// Starts the world. With `model`, Claude Code in the guest is signed in
/// and its calls go out through the model site at `api.anthropic.com`.
pub async fn start(
    cx: Cx,
    mut world: kit::World,
    scenario: Arc<Scenario>,
    control: Control,
    log: Log,
    model: Option<models::Model>,
) -> fictionet::Result {
    log.attach(&cx);
    let ca = Ca::new(&cx, certs::LAB_CA_NAME)?;
    world.trust("internet-security", &ca.cert_pem())?;
    let ids = border_world::identities(&cx, &ca)?;
    let mirror = world.mirror(&cx)?;
    let mut extra = Extra::default().route(kit::JUMP, kit::jump_prefix());
    let address = |index: u8| Ipv4Addr::new(104, 18, 0, index + 10);
    for (index, name) in ["archive.ubuntu.com", "security.ubuntu.com"]
        .into_iter()
        .chain(kit::desktop::HOSTS.iter().copied())
        .chain([kit::desktop::CLAUDE_HOST])
        .enumerate()
    {
        let address = address(index as u8);
        let mut site = web::Site::new(mirror.clone());
        if name != "archive.ubuntu.com" && name != "security.ubuntu.com" {
            site = site.tls(
                certs::leaf(&cx, &ca, &[name], address)?.server_config(&cx, SystemTime::now())?,
            );
        }
        extra = extra.host(address, site.into_host(name));
    }
    if let Some(model) = model {
        kit::desktop::sign_in_claude(&mut world, &model, super::guest::USER)?;
        let host = models::Provider::Anthropic.host();
        let address = address(9);
        let tls = certs::leaf(&cx, &ca, &[host], address)?.server_config(&cx, SystemTime::now())?;
        extra = extra.host(address, web::Site::handler(model).tls(tls).into_host(host));
    }
    let routing = border_world::start_with(&cx, scenario, ids, world.into_attachments(), extra)?;
    cx.spawn(move |cx| control.serve(cx, routing));
    Ok(())
}
