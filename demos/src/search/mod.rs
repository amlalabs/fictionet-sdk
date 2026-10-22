//! Search page, authoritative topics, and the in-process network.

use std::sync::Arc;
use std::time::Duration;

use web_world::{
    pages::{Applied, Command, Pages},
    search::{self, Searches},
};
use fictionet::Cx;
use fictionet_observe::page::Host;
use fictionet_observe::{
    DashboardHandle,
    page::{CommandLimits, CommandPort, Page, Rejected, StateLimits, StateTopic},
};

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
        crate::kit::desktop::CLAUDE_HOST,
        "Claude Code installed at boot",
    ),
    ("releases.openai.com", "Codex installed at boot"),
];

/// Sign-in connections retain the providers' end-to-end TLS.
pub const PASSED: &[&str] = &[
    "claude.ai",
    "console.anthropic.com",
    "platform.claude.com",
    "auth.openai.com",
    "challenges.cloudflare.com",
];

#[derive(Clone)]
pub struct Topics {
    pub searches: StateTopic<search::Snapshot>,
    pub commands: CommandPort<Command, Applied>,
}

impl Topics {
    pub fn new() -> Self {
        Self {
            searches: StateTopic::new(StateLimits {
                max_bytes: search::MAX_SNAPSHOT_BYTES,
            }),
            commands: CommandPort::new(CommandLimits::default()),
        }
    }

    pub fn page(&self, dashboard: DashboardHandle, host: Host) -> Page {
        Page::new("Search", dashboard)
            .host(host)
            .standard_panels()
            .architecture(crate::kit::architecture("adaptive"))
            .command("generation", self.commands.clone())
            .custom(
                "Web",
                format!(
                    "{}\nconst forwardedHosts = {};",
                    include_str!("search.mjs"),
                    serde_json::to_string(
                        &FORWARDED.iter().map(|(host, _)| host).collect::<Vec<_>>()
                    )
                    .expect("host names serialize")
                ),
                self.searches.clone(),
            )
            .asset(
                "search/model.mjs",
                "text/javascript",
                include_bytes!("model.mjs").to_vec(),
            )
            .asset(
                "search/motion.mjs",
                "text/javascript",
                include_bytes!("motion.mjs").to_vec(),
            )
            .asset(
                "search/web.mjs",
                "text/javascript",
                include_bytes!("web.mjs").to_vec(),
            )
            .asset(
                "search/view.mjs",
                "text/javascript",
                include_bytes!("view.mjs").to_vec(),
            )
            .asset(
                "search/style.css",
                "text/css",
                include_bytes!("style.css").to_vec(),
            )
            .workspace("Web")
            .app()
    }

    pub fn start(&self, cx: &Cx, searches: Arc<Searches>, pages: Arc<Pages>) -> fictionet::Result {
        let port = self.commands.clone();
        cx.spawn(move |cx| async move {
            crate::kit::serve_commands(&cx, &port, |command| {
                Ok(pages
                    .apply(&cx, command.clone())
                    .map_err(|rejected| match rejected {
                        web_world::pages::Rejected::Stale { current } => {
                            Rejected::StaleRevision { current }
                        }
                        web_world::pages::Rejected::Invalid { message } => {
                            Rejected::Invalid { message }
                        }
                    }))
            })
            .await
        });
        let topic = self.searches.clone();
        cx.spawn(move |cx| async move {
            let mut revision = None;
            loop {
                publish_changed(&cx, &searches, &topic, &mut revision)?;
                cx.sleep(Duration::from_millis(50)).await?;
            }
        });
        Ok(())
    }
}

fn publish_changed(
    cx: &Cx,
    searches: &Searches,
    topic: &StateTopic<search::Snapshot>,
    last: &mut Option<u64>,
) -> fictionet::Result<bool> {
    if *last == Some(searches.revision()) {
        return Ok(false);
    }
    let snapshot = searches.snapshot();
    topic
        .publish(cx.now(), &snapshot)
        .map_err(fictionet::Error::msg)?;
    *last = Some(snapshot.revision);
    Ok(true)
}

impl Default for Topics {
    fn default() -> Self {
        Self::new()
    }
}

/// The world's network for the guest run and the preview: the adaptive web,
/// with package downloads mirrored, sign-in relayed over raw TLS, and model
/// search and fetch answered by the world using the guest’s own credentials.
pub fn network(
    world: &web_world::World,
    cx: &Cx,
    log: Arc<example_common::log::Log>,
    mirror: crate::kit::mirror::Cache<fictionet::stdlib::web::Proxy>,
) -> fictionet::Result<fictionet::stdlib::world::net::Net> {
    use fictionet::stdlib::web::Site;
    let mozilla = world.ca.config(cx, crate::kit::desktop::HOSTS[0])?.0;
    let claude = world.ca.config(cx, crate::kit::desktop::CLAUDE_HOST)?.0;
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
        if PASSED.contains(&host) {
            return Some(
                fictionet::stdlib::world::net::Host::new(host)
                    .dns_name(host)
                    .port_server(443, Relay(format!("{host}:443"))),
            );
        }
        FORWARDED.iter().any(|(name, _)| *name == host).then(|| {
            let site = Site::new(mirror.clone());
            if crate::kit::desktop::HOSTS.contains(&host) {
                site.tls(mozilla.clone())
            } else if host == crate::kit::desktop::CLAUDE_HOST {
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

#[cfg(test)]
mod tests;

/// One vendor connection, carrying only the guest's encrypted bytes.
pub struct Relay(pub String);

impl fictionet::stdlib::world::net::PortServer for Relay {
    fn serve(
        &self,
        cx: Cx,
        arrival: fictionet::stdlib::world::net::Arrival,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        use fictionet::tokio::ConnectionTokioExt;
        let host = self.0.clone();
        Box::pin(async move {
            let work = async {
                let mut upstream = tokio::net::TcpStream::connect(host.as_str()).await?;
                cx.emitter(&arrival.info)
                    .emit("signin", "connection", |event| {
                        event.field("host", host.trim_end_matches(":443"))
                    });
                let mut guest = arrival.conn.into_tokio(&cx);
                tokio::io::copy_bidirectional(&mut guest, &mut upstream).await?;
                Ok::<_, std::io::Error>(())
            };
            tokio::select! {
                _ = cx.cancelled() => {},
                result = work => {
                    if let Err(error) = result {
                        cx.emit("search", "relay_error", |event| event.field("host", host.as_str()).field("error", error.to_string()));
                    }
                }
            }
        })
    }
}
