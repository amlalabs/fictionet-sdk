//! Search page, authoritative topics, and the in-process network.

use std::sync::Arc;
use std::time::Duration;

use adaptive_web_world::{
    pages::{Applied, Command, Pages},
    search::{self, Searches},
};
use fictionet::Cx;
use fictionet_observe::page::Host;
use fictionet_observe::{
    DashboardHandle,
    page::{CommandLimits, CommandPort, Page, Rejected, StateLimits, StateTopic},
};
use serde::Serialize;

pub const FORWARDED: &[(&str, &str)] = &[
    ("archive.ubuntu.com", "Ubuntu packages installed at boot"),
    (
        "security.ubuntu.com",
        "Ubuntu security packages installed at boot",
    ),
    ("packages.mozilla.org", "Firefox installed at boot"),
];

#[derive(Serialize)]
pub struct Policy {
    searcher: &'static str,
    forwarded: Vec<Forwarded>,
    made_up: &'static str,
    refused: &'static str,
}

#[derive(Serialize)]
struct Forwarded {
    host: &'static str,
    why: &'static str,
}

#[derive(Clone)]
pub struct Topics {
    pub searches: StateTopic<search::Snapshot>,
    pub policy: StateTopic<Policy>,
    pub commands: CommandPort<Command, Applied>,
}

impl Topics {
    pub fn new() -> Self {
        Self {
            searches: StateTopic::new(StateLimits {
                max_bytes: search::MAX_SNAPSHOT_BYTES,
            }),
            policy: StateTopic::new(StateLimits::default()),
            commands: CommandPort::new(CommandLimits::default()),
        }
    }

    pub fn page(&self, dashboard: DashboardHandle, host: Host) -> Page {
        Page::new("Mediated search", dashboard)
            .host(host)
            .standard_panels()
            .state("policy", self.policy.clone())
            .command("generation", self.commands.clone())
            .custom("Search", include_str!("search.mjs"), self.searches.clone())
            .asset(
                "search/model.mjs",
                "text/javascript",
                include_bytes!("model.mjs").to_vec(),
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
            .workspace("Search")
            .workspace_consoles()
    }

    pub fn start(
        &self,
        cx: &Cx,
        searches: Arc<Searches>,
        pages: Arc<Pages>,
        searcher: &'static str,
    ) -> fictionet::Result {
        self.policy
            .publish(cx.now(), &policy(searcher))
            .map_err(fictionet::Error::msg)?;
        let port = self.commands.clone();
        cx.spawn(move |cx| async move {
            crate::kit::serve_commands(&cx, &port, |command| {
                Ok(pages.apply(&cx, *command).map_err(
                    |adaptive_web_world::pages::Rejected::Stale { current }| {
                        Rejected::StaleRevision { current }
                    },
                ))
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

pub fn policy(searcher: &'static str) -> Policy {
    Policy {
        searcher,
        forwarded: FORWARDED
            .iter()
            .map(|&(host, why)| Forwarded { host, why })
            .collect(),
        made_up: "Every other name that could be on the internet gets a site made up by the world, at an address it picks.",
        refused: "Single-label names and reserved or private top-level domains get no address.",
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
/// with the names in [`FORWARDED`] served from the kit's package mirror.
pub fn network(
    world: &adaptive_web_world::World,
    cx: &Cx,
    log: Arc<example_common::log::Log>,
    mirror: crate::kit::mirror::Cache<fictionet::stdlib::web::Proxy>,
) -> fictionet::Result<fictionet::stdlib::world::net::Net> {
    let tls = world.ca.config(cx, crate::kit::desktop::HOSTS[0])?.0;
    Ok(world.net(cx, log, move |host| {
        FORWARDED.iter().any(|(name, _)| *name == host).then(|| {
            let site = fictionet::stdlib::web::Site::new(mirror.clone());
            if crate::kit::desktop::HOSTS.contains(&host) {
                site.tls(tls.clone())
            } else {
                site
            }
        })
    }))
}

#[cfg(test)]
mod tests;
