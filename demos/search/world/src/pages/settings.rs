//! Page sources and world controls.

use super::*;

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
            }),
            copied: None,
            live: None,
            depth: None,
            editor: None,
            fetcher: Default::default(),
            written: None,
        }
    }

    /// Pages that the written web answers: the standalone world's.
    pub fn from_written(written: written::Written) -> Self {
        let mut pages = Self::with_source(written.seed().clone(), Source::Copied);
        pages.written = Some(Arc::new(written));
        pages
    }

    /// The written web, for the standalone world.
    pub fn written(&self) -> Option<&Arc<written::Written>> {
        self.written.as_ref()
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
    /// nothing a previous session copied, crawled, fetched or edited
    /// carries over. A scenario stays, with the account already written
    /// for it.
    pub fn start_session(&self, fcx: &Cx, source: Source) -> Result<(), Rejected> {
        if let Some(message) = self.unavailable(source) {
            return Err(Rejected::Invalid {
                message: message.into(),
            });
        }
        let mut settings = self.settings.lock().unwrap();
        for live in self.live.iter().chain(&self.depth) {
            live.restart(fcx);
        }
        if let Some(editor) = &self.editor {
            editor.new_session(fcx);
        }
        self.forget_packages();
        settings.source = source;
        settings.revision += 1;
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
