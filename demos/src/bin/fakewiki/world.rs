use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::SystemTime;

use fakewiki_world::{content::Content, issue_leaves, pages, sites, tamper::Tampering};
use fictionet::Cx;
use fictionet::stdlib::{services::ca::Leaf, web, world::net::Net};
use fictionet_demo::kit::{self, World};

use super::page::Controls;

pub const APT: &[&str] = &["archive.ubuntu.com", "security.ubuntu.com"];

pub fn certificates(cx: &Cx) -> fictionet::Result<(String, HashMap<String, Leaf>)> {
    let names: Vec<_> = pages::host_ips()
        .into_keys()
        .chain(kit::desktop::HOSTS.iter().map(|s| s.to_string()))
        .collect();
    issue_leaves(cx, names.iter())
}

pub fn network(
    cx: &Cx,
    mut leaves: HashMap<String, Leaf>,
    tampering: Tampering,
    mirror: impl Fn() -> web::Site,
) -> fictionet::Result<Net> {
    let mut mirrors = Vec::new();
    for host in APT {
        mirrors.push(mirror().into_host(host));
    }
    for host in kit::desktop::HOSTS {
        let leaf = leaves.remove(*host).expect("mirror certificate");
        mirrors.push(
            mirror()
                .tls(leaf.server_config(cx, SystemTime::now())?)
                .into_host(host),
        );
    }
    let hosts: HashMap<String, Ipv4Addr> = pages::host_ips();
    let mut net = sites(cx, &hosts, leaves, Content::in_process(tampering))?;
    for host in mirrors {
        net = net.add_host(host);
    }
    Ok(net.route(kit::JUMP, kit::jump_prefix()))
}

pub async fn start(cx: Cx, mut world: World, controls: Controls) -> fictionet::Result {
    let tampering = Tampering::new(false, fakewiki_world::tamper::Scope::Wikipedia);
    let (root, leaves) = certificates(&cx)?;
    world.trust("internet", &root)?;
    let mirror = world.mirror(&cx)?;
    let net = network(&cx, leaves, tampering.clone(), || {
        web::Site::new(mirror.clone())
    })?;
    controls.start(&cx, tampering)?;
    net.start(&cx, world.into_attachments())
}
