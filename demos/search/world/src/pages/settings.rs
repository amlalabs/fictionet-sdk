//! Page sources and world controls.

use super::*;
use fictionet::stdlib::services::dns::WallClock;
use fictionet::stdlib::world::net::dns::Namespace;

/// A change to the world. Each carries the settings revision it expects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    /// Edit pages for `scenario` from now on; an empty one leaves pages as
    /// they are.
    SetScenario {
        scenario: String,
        expected_revision: u64,
    },
}

impl Command {
    fn expected_revision(&self) -> u64 {
        match self {
            Self::SetScenario {
                expected_revision, ..
            } => *expected_revision,
        }
    }
}

/// The settings revision after an accepted command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    pub revision: u64,
    /// Run time when the command was applied, in milliseconds.
    pub at_ms: u64,
}

/// A command that did not change the settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Rejected {
    /// The caller's revision differs from the current settings revision.
    Stale { current: u64 },
    /// The command cannot apply, and why.
    Invalid { message: String },
}

impl Pages {
    pub(super) fn with_source(seed: Seed, source: Source) -> Self {
        Self {
            observation: Default::default(),
            seed,
            settings: Mutex::new(Settings {
                source,
                revision: 0,
                lag: None,
            }),
            copied: None,
            live: None,
            depth: None,
            editor: None,
            fetcher: Default::default(),
            // Every session advances it with its own clock before the
            // world's DNS answers, so this first clock is never read.
            namespace: Namespace::new(WallClock {
                start: std::time::UNIX_EPOCH,
            }),
            live_dns: Default::default(),
            served: Default::default(),
        }
    }

    /// Runs `served` each time the session comes to serve hosts it did not
    /// serve before: when Live-Depth allows an address on a new host, and
    /// when a session starts. It replaces what an earlier network set.
    pub(crate) fn on_hosts_served(&self, served: impl Fn() + Send + Sync + 'static) {
        *self.served.0.lock().unwrap() = Some(Arc::new(served));
    }

    /// The session the world's DNS answers for.
    pub(crate) fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// The internet's DNS servers, asked from the host: the upstream of
    /// the world's learned zones in Live, Live-Depth, and Edited, and
    /// what a Copied session asks for the names it needs in every session.
    pub(crate) fn live_dns(&self) -> Arc<fictionet_host::dns::Internet> {
        self.live_dns
            .get_or_init(|| Arc::new(fictionet_host::dns::Internet::new()))
            .clone()
    }

    /// Edits pages with `model` in Edited mode.
    pub fn with_editor(mut self, model: model::Model) -> Self {
        self.editor = Some(Arc::new(edit::Editor::new(model, self.seed.date.clone())));
        self
    }

    /// The seed used by this world.
    pub fn seed(&self) -> &Seed {
        &self.seed
    }

    /// What answers requests.
    pub fn source(&self) -> Source {
        self.settings.lock().unwrap().source
    }

    /// The settings revision commands must name.
    pub fn revision(&self) -> u64 {
        self.settings.lock().unwrap().revision
    }

    /// Whether the host has a search key for Live and Live-Depth.
    pub fn live_available(&self) -> bool {
        self.live.is_some()
    }

    /// Whether the host has what Edited needs: Live and a model.
    pub fn edited_available(&self) -> bool {
        self.live.is_some() && self.editor.is_some()
    }

    /// The scenario Edited follows, if any, and whether it is ready.
    pub fn scenario(&self) -> Option<Scenario> {
        self.editor.as_ref()?.scenario()
    }

    /// The scenario and its readiness, as they change; `None` without an
    /// editor.
    pub fn scenario_changes(&self) -> Option<tokio::sync::watch::Receiver<Option<Scenario>>> {
        Some(self.editor.as_ref()?.changes())
    }

    /// Why this world cannot answer from `source`, if it cannot.
    pub fn unavailable(&self, source: Source) -> Option<&'static str> {
        match source {
            Source::Copied if self.copied.is_none() => Some("This world has no copied pages"),
            Source::Copied if !self.has_copied_dns() => Some(
                "The copied pages have no DNS: run cargo xtask search-capture <downloads> --dns",
            ),
            Source::Live | Source::LiveDepth | Source::Edited if self.live.is_none() => {
                Some("Live pages need EXA_API_KEY on the host")
            }
            Source::Edited if self.editor.is_none() => {
                Some("Edited pages need a model key on the host")
            }
            _ => None,
        }
    }

    /// Starts a session that answers from `source`, in the world `fcx`:
    /// nothing a previous session copied, allowed, fetched, edited or
    /// resolved carries over. A scenario stays, with the account already
    /// written for it. `copied_lag` is measured once before boot so the
    /// workstation, the copied pages, and the world's DNS use the same
    /// clock: the world's resolvers check signatures against it, so the
    /// captured signatures of a Copied session are inside their windows.
    /// A corpus with no DNS captured cannot start a Copied session, since
    /// its names would not resolve.
    pub fn start_session(
        &self,
        fcx: &Cx,
        source: Source,
        copied_lag: Option<std::time::Duration>,
    ) -> Result<(), Rejected> {
        if let Some(message) = self.unavailable(source) {
            return Err(Rejected::Invalid {
                message: message.into(),
            });
        }
        let mut settings = self.settings.lock().unwrap();
        for live in self.live.iter().chain(&self.depth) {
            live.restart();
        }
        if let Some(editor) = &self.editor {
            editor.new_session(fcx);
        }
        self.forget_packages();
        settings.lag = Some(copied_lag);
        settings.source = source;
        settings.revision += 1;
        // The DNS session starts after the mode is set, so the world's DNS
        // sources choose for the new mode when they see it.
        let lag = copied_lag
            .filter(|_| source == Source::Copied)
            .unwrap_or_default();
        let start = std::time::SystemTime::now() - fcx.now().since_start() - lag;
        self.namespace.advance(WallClock { start });
        drop(settings);
        self.served.run();
        Ok(())
    }

    /// Applies a command against the current revision; every accepted
    /// command advances it.
    pub fn apply(&self, fcx: &Cx, command: Command) -> Result<Applied, Rejected> {
        let mut settings = self.settings.lock().unwrap();
        if command.expected_revision() != settings.revision {
            return Err(Rejected::Stale {
                current: settings.revision,
            });
        }
        match command {
            Command::SetScenario { scenario, .. } => {
                let Some(editor) = &self.editor else {
                    return Err(Rejected::Invalid {
                        message: "Edited pages need a model key on the host".into(),
                    });
                };
                let scenario = text::normalize_space(&scenario);
                editor.set_scenario(fcx, (!scenario.is_empty()).then_some(scenario));
            }
        }
        settings.revision += 1;
        Ok(Applied {
            revision: settings.revision,
            at_ms: fcx.now().since_start().as_millis() as u64,
        })
    }
}
