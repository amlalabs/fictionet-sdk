//! The network the guest sees: the Artifactory world's sites, the jump route
//! for the page's consoles, and the kit's package mirror, which forwards
//! during setup and then answers 403.

use artifactory_world::{
    Identity,
    log::Log,
    repository::{Contents, Sessions},
};
use fictionet::{Cx, Result, stdlib::web};
use fictionet_demo::kit;
use std::collections::BTreeMap;
use std::sync::{Arc, atomic::AtomicBool};

/// One shared repository state, or Maya's and her colleague's by sandbox.
pub fn sessions(
    main: Arc<Contents>,
    colleague: Option<Arc<Contents>>,
    names: [&str; 2],
) -> Sessions {
    match colleague {
        None => Sessions::Shared(main),
        Some(colleague) => Sessions::Separate(BTreeMap::from([
            (names[0].to_owned(), main),
            (names[1].to_owned(), colleague),
        ])),
    }
}

pub fn start(
    fcx: &Cx,
    mut world: kit::World,
    sessions: Sessions,
    log: Log,
    closed: Arc<AtomicBool>,
) -> Result {
    let identity = Identity::with_names(fcx, kit::desktop::HOSTS)?;
    world.trust("northwind", &identity.ca_pem)?;
    let configs = kit::desktop::HOSTS
        .iter()
        .map(|name| identity.server_config(fcx, name))
        .collect::<Result<Vec<_>>>()?;
    let mirror = kit::mirror::Closable::new(world.mirror(fcx)?, closed);
    let mut net = artifactory_world::network(fcx, sessions, identity, log)?
        .route(kit::JUMP, kit::jump_prefix());
    for name in ["archive.ubuntu.com", "security.ubuntu.com"] {
        net = net.add_host(web::Site::new(mirror.clone()).into_host(name));
    }
    for (name, config) in kit::desktop::HOSTS.iter().zip(configs) {
        net = net.add_host(web::Site::new(mirror.clone()).tls(config).into_host(name));
    }
    net.start(fcx, world.into_attachments())
}
