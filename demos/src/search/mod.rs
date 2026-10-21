//! Search page, authoritative topics, and the in-process network.

use std::sync::Arc;
use std::time::Duration;

use adaptive_web_world::{
    pages::{Applied, Command, Pages},
    search::{self, Searches},
};
use fictionet::Cx;
use fictionet_extras::models;
use fictionet_observe::page::Host;
use fictionet_observe::{
    DashboardHandle,
    page::{CommandLimits, CommandPort, Page, Rejected, StateLimits, StateTopic},
};

/// The names the world forwards to the real internet, and why: the guest's
/// packages and Claude Code, installed at boot. Claude Code's model calls
/// go out through the model site, when there is one.
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

/// Model and sign-in services, passed straight through to the real ones:
/// Claude Code and Codex sign in and call their models as they normally do.
pub const PASSED: &[&str] = &[
    "api.anthropic.com",
    "claude.ai",
    "console.anthropic.com",
    "platform.claude.com",
    "api.openai.com",
    "auth.openai.com",
    "chatgpt.com",
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
                        adaptive_web_world::pages::Rejected::Stale { current } => {
                            Rejected::StaleRevision { current }
                        }
                        adaptive_web_world::pages::Rejected::Invalid { message } => {
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
/// with the names in [`FORWARDED`] served from the kit's package mirror and,
/// given one, Claude Code's model site at `api.anthropic.com`. Every HTTPS
/// name has a certificate from the world's CA.
pub fn network(
    world: &adaptive_web_world::World,
    cx: &Cx,
    log: Arc<example_common::log::Log>,
    mirror: crate::kit::mirror::Cache<fictionet::stdlib::web::Proxy>,
    model: Option<models::Model>,
) -> fictionet::Result<fictionet::stdlib::world::net::Net> {
    use fictionet::stdlib::web::Site;
    let mozilla = world.ca.config(cx, crate::kit::desktop::HOSTS[0])?.0;
    let claude = world.ca.config(cx, crate::kit::desktop::CLAUDE_HOST)?.0;
    let api = world.ca.config(cx, models::Provider::Anthropic.host())?.0;
    let passed: std::collections::HashMap<&'static str, _> = PASSED
        .iter()
        .map(|host| Ok((*host, world.ca.config(cx, host)?.0)))
        .collect::<fictionet::Result<_>>()?;
    let openai = world.ca.config(cx, "releases.openai.com")?.0;
    Ok(world.net(cx, log, move |host| {
        if host == models::Provider::Anthropic.host()
            && let Some(model) = model.clone()
        {
            return Some(Site::handler(model).tls(api.clone()));
        }
        if let Some(config) = passed.get(host) {
            return Some(Site::new(mirror.clone()).tls(config.clone()));
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
        })
    }))
}

#[cfg(test)]
mod tests;
