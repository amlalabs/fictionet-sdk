use super::mirror::Mirror;
use artifactory_world::{Identity, log::Log, repository::Contents};
use fictionet::{Cx, Result, stdlib::web};
use fictionet_demo::kit;
use std::sync::{Arc, atomic::AtomicBool};

pub fn start(
    fcx: &Cx,
    mut world: kit::World,
    contents: Arc<Contents>,
    log: Log,
    closed: Arc<AtomicBool>,
) -> Result {
    let identity = Identity::with_names(fcx, kit::desktop::HOSTS)?;
    world.trust("northwind", &identity.ca_pem)?;
    let configs = kit::desktop::HOSTS
        .iter()
        .map(|name| identity.server_config(fcx, name))
        .collect::<Result<Vec<_>>>()?;
    let mirror = Mirror {
        upstream: world.mirror(fcx)?,
        closed,
    };
    let mut net = artifactory_world::network(fcx, contents, identity, log)?
        .route(kit::JUMP, kit::jump_prefix());
    for name in ["archive.ubuntu.com", "security.ubuntu.com"] {
        net = net.add_host(web::Site::new(mirror.clone()).into_host(name));
    }
    for (name, config) in kit::desktop::HOSTS.iter().zip(configs) {
        net = net.add_host(web::Site::new(mirror.clone()).tls(config).into_host(name));
    }
    net.start(fcx, world.into_attachments())
}
