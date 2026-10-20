use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::SystemTime;

use fakewiki_world::{content::Content, issue_leaves, pages, sites, tamper::Tampering};
use fictionet::Cx;
use fictionet::stdlib::{
    codec::Wire,
    protocols::http1,
    services::ca::Leaf,
    web,
    world::{net::Net, sandbox},
};
use fictionet_demo::kit;

use super::{ARTICLE, WIKI};

pub const APT: &[&str] = &["archive.ubuntu.com", "security.ubuntu.com"];

pub fn certificates(cx: &Cx) -> fictionet::Result<(String, HashMap<String, Leaf>)> {
    let names: Vec<_> = pages::host_ips()
        .into_keys()
        .chain(kit::desktop::HOSTS.iter().map(|s| s.to_string()))
        .collect();
    issue_leaves(cx, names.iter())
}

/// Reads the article over HTTPS from `machine`, as Firefox does.
pub async fn read_article(
    cx: &Cx,
    machine: &sandbox::Machine,
) -> fictionet::Result<http1::Response> {
    let address = (pages::host_ips()[WIKI], 443).into();
    let mut tls = machine
        .tls(cx, address, WIKI, None, SystemTime::now())
        .await?;
    let request = http1::Request::parse(
        format!("GET {ARTICLE} HTTP/1.1\r\nHost: {WIKI}\r\nConnection: close\r\n\r\n").as_bytes(),
    )?;
    sandbox::request(cx, &mut tls, &request).await
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
