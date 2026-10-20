//! The bank, the package mirrors, and the admin attachment.

use super::control::Control;
use border_world::{Extra, certs, log::Log, scenario::Scenario};
use fictionet::{
    Cx,
    stdlib::{services::ca::Ca, web},
};
use fictionet_demo::kit;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::SystemTime;

pub async fn start(
    cx: Cx,
    mut world: kit::World,
    scenario: Arc<Scenario>,
    control: Control,
    log: Log,
) -> fictionet::Result {
    log.attach(&cx);
    let ca = Ca::new(&cx, certs::LAB_CA_NAME)?;
    world.trust("internet-security", &ca.cert_pem())?;
    let ids = border_world::identities(&cx, &ca)?;
    control
        .view
        .certificates(cx.now(), super::certificates::Certificates::new(&ids)?);
    let mirror = world.mirror(&cx)?;
    let mut extra = Extra::default().route(kit::JUMP, kit::jump_prefix());
    for (index, name) in ["archive.ubuntu.com", "security.ubuntu.com"]
        .into_iter()
        .chain(kit::desktop::HOSTS.iter().copied())
        .enumerate()
    {
        let address = Ipv4Addr::new(198, 18, 0, index as u8 + 10);
        let mut site = web::Site::new(mirror.clone());
        if kit::desktop::HOSTS.contains(&name) {
            site = site.tls(
                certs::leaf(&cx, &ca, &[name], address)?.server_config(&cx, SystemTime::now())?,
            );
        }
        extra = extra.host(address, site.into_host(name));
    }
    let routing = border_world::start_with(&cx, scenario, ids, world.into_attachments(), extra)?;
    cx.spawn(move |cx| control.serve(cx, routing));
    Ok(())
}
