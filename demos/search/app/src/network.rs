//! Join model gateways, provider sign-in and the package mirror to the web.

use fictionet::Cx;
use std::sync::Arc;

/// The names the world forwards to the real internet, and why: the guest's
/// packages and coding agents, installed at boot.
pub const FORWARDED: &[(&str, &str)] = &[
    ("archive.ubuntu.com", "Ubuntu packages installed at boot"),
    (
        "security.ubuntu.com",
        "Ubuntu security packages installed at boot",
    ),
    ("packages.mozilla.org", "Firefox installed at boot"),
    (
        fictionet_demo::kit::desktop::CLAUDE_HOST,
        "Claude Code installed at boot",
    ),
    ("releases.openai.com", "Codex installed at boot"),
];

/// The world's network for the guest run and the preview: the web,
/// with package downloads mirrored, sign-in relayed over raw TLS, and model
/// search and fetch answered by the world using the guest’s own credentials.
pub fn build(
    world: &web_world::World,
    cx: &Cx,
    log: Arc<fictionet_extras::log::Log>,
    mirror: fictionet_demo::kit::mirror::Cache<fictionet::stdlib::web::Proxy>,
) -> fictionet::Result<fictionet::stdlib::world::net::Net> {
    use fictionet::stdlib::web::Site;
    let mozilla = world
        .ca
        .config(cx, fictionet_demo::kit::desktop::HOSTS[0])?
        .0;
    let claude = world
        .ca
        .config(cx, fictionet_demo::kit::desktop::CLAUDE_HOST)?
        .0;
    let openai = world.ca.config(cx, "releases.openai.com")?.0;
    use fictionet_extras::models::{Model, Provider};
    let models = [Provider::Anthropic, Provider::OpenAi, Provider::ChatGpt]
        .into_iter()
        .map(|provider| {
            Ok((
                provider.host(),
                (
                    Model::guest(cx, provider)?.search(world.pages.clone()),
                    world.ca.config(cx, provider.host())?.0,
                ),
            ))
        })
        .collect::<fictionet::Result<Vec<_>>>()?;
    Ok(world.net(cx, log, move |host| {
        if let Some((_, (model, tls))) = models.iter().find(|(name, _)| *name == host) {
            return Some(
                Site::handler(model.clone())
                    .tls(tls.clone())
                    .into_host(host),
            );
        }
        if fictionet_extras::models::signin::HOSTS.contains(&host) {
            return Some(
                fictionet::stdlib::world::net::Host::new(host)
                    .dns_name(host)
                    .port_server(
                        443,
                        fictionet_extras::models::signin::Relay(format!("{host}:443")),
                    ),
            );
        }
        FORWARDED.iter().any(|(name, _)| *name == host).then(|| {
            let site = Site::new(mirror.clone());
            if fictionet_demo::kit::desktop::HOSTS.contains(&host) {
                site.tls(mozilla.clone())
            } else if host == fictionet_demo::kit::desktop::CLAUDE_HOST {
                site.tls(claude.clone())
            } else if host == "releases.openai.com" {
                site.tls(openai.clone())
            } else {
                site
            }
            .into_host(host)
        })
    }))
}
