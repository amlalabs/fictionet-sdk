use std::sync::Arc;
use std::time::Duration;

use adaptive_web_world::{
    search::{self, Searches},
    stub::{Applied, Command, Stub},
};
use fictionet::Cx;
use fictionet_demo::kit::Hosts;
use fictionet_observe::{
    DashboardHandle,
    page::{
        Action, Column, CommandLimits, CommandPort, EventFilter, Page, Rejected, StateLimits,
        StateTopic,
    },
};
use serde::Serialize;
use serde_json::json;

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
    forwarded: Vec<Forwarded>,
    made_up: &'static str,
    refused: &'static str,
}

#[derive(Serialize)]
struct Forwarded {
    host: &'static str,
    why: &'static str,
}

#[derive(Serialize)]
pub struct Generation {
    generate: bool,
    revision: u64,
    generator: &'static str,
}

#[derive(Clone)]
pub struct Topics {
    pub searches: StateTopic<search::Snapshot>,
    pub policy: StateTopic<Policy>,
    pub generation: StateTopic<Generation>,
    pub commands: CommandPort<Command, Applied>,
}

impl Topics {
    pub fn new() -> Self {
        Self {
            searches: StateTopic::new(StateLimits {
                max_bytes: search::MAX_SNAPSHOT_BYTES,
                deltas: 0,
            }),
            policy: StateTopic::new(StateLimits::default()),
            generation: StateTopic::new(StateLimits::default()),
            commands: CommandPort::new(CommandLimits::default()),
        }
    }

    pub fn page(&self, dashboard: DashboardHandle, hosts: &mut Hosts) -> Page {
        Page::new("Search", dashboard)
            .host(hosts.take(super::guest::HOST))
            .standard_panels()
            .state("search-state", self.searches.clone())
            .state("policy", self.policy.clone())
            .control(
                "Generation",
                self.commands.clone(),
                vec![
                    Action {
                        label: "Turn generation on".into(),
                        command: json!({"command":"set_generation","generate":true}),
                    },
                    Action {
                        label: "Turn generation off".into(),
                        command: json!({"command":"set_generation","generate":false}),
                    },
                ],
            )
            .control_state(self.generation.clone())
            .control_revision("/value/revision")
            .event_table(
                "Searches",
                EventFilter {
                    source: Some("adaptive".into()),
                    kinds: vec!["query".into(), "query_failed".into()],
                    ..EventFilter::default()
                },
                columns(),
            )
    }

    pub fn start(&self, cx: &Cx, searches: Arc<Searches>, stub: Arc<Stub>) -> fictionet::Result {
        self.policy
            .publish(cx.now(), &policy())
            .map_err(fictionet::Error::msg)?;
        let port = self.commands.clone();
        let generator = stub.clone();
        cx.spawn(move |cx| async move {
            loop {
                let command = cx.race(None, port.recv()).await?;
                let Some(command) = command else {
                    return Ok(());
                };
                match stub.apply(&cx, command.command) {
                    Ok(applied) => command.reply(&cx, applied),
                    Err(adaptive_web_world::stub::Rejected::Stale { current }) => {
                        command.reject(&cx, Rejected::StaleRevision { current })
                    }
                }
            }
        });
        let topic = self.searches.clone();
        let generation = self.generation.clone();
        cx.spawn(move |cx| async move {
            let mut revision = None;
            let mut generation_revision = None;
            loop {
                if publish_changed(&cx, &searches, &topic, &mut revision)? {
                    let settings = generator.generation();
                    if generation_revision != Some(settings.revision) {
                        generation
                            .publish(
                                cx.now(),
                                &Generation {
                                    generate: settings.generate,
                                    revision: settings.revision,
                                    generator: "stub generator (no model)",
                                },
                            )
                            .map_err(fictionet::Error::msg)?;
                        generation_revision = Some(settings.revision);
                    }
                }
                cx.sleep(Duration::from_millis(50)).await?;
            }
        });
        Ok(())
    }
}

fn columns() -> Vec<Column> {
    [
        ("Time", "/at"),
        ("Host", "/sandbox/name"),
        ("Engine", "/fields/engine"),
        ("Search", "/fields/search"),
        ("Event", "/kind"),
        ("Reason", "/fields/why"),
    ]
    .into_iter()
    .map(|(name, path)| Column::new(name, path))
    .collect()
}

pub fn policy() -> Policy {
    Policy {
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
