//! Search page, authoritative topics, and the in-process network.

use std::sync::Arc;
use std::time::Duration;

use fictionet::Cx;
use fictionet_observe::page::Host;
use fictionet_observe::{
    DashboardHandle,
    page::{CommandLimits, CommandPort, Page, Rejected, StateLimits, StateTopic},
};
use web_world::{
    pages::{Applied, Command, Pages},
    search::{self, Searches},
};

use crate::network::FORWARDED;

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
            .architecture(fictionet_demo::kit::architecture("web"))
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
            fictionet_demo::kit::serve_commands(&cx, &port, |command| {
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

#[cfg(test)]
mod tests;
