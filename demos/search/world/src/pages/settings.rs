//! Page sources and world controls.

use super::*;

/// A change to the world. Each carries the settings revision it expects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    /// Answer new requests from `source`.
    SetSource {
        source: Source,
        expected_revision: u64,
    },
    /// Edit pages for `scenario` from now on; an empty one leaves pages as
    /// they are.
    SetScenario {
        scenario: String,
        expected_revision: u64,
    },
    /// Forget the pages copied and the edits made.
    Restart { expected_revision: u64 },
}

impl Command {
    fn expected_revision(&self) -> u64 {
        match self {
            Self::SetSource {
                expected_revision, ..
            }
            | Self::SetScenario {
                expected_revision, ..
            }
            | Self::Restart { expected_revision } => *expected_revision,
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
            editor: None,
            fetcher: Default::default(),
        }
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

    /// What answers new requests.
    pub fn source(&self) -> Source {
        self.settings.lock().unwrap().source
    }

    /// The settings revision commands must name.
    pub fn revision(&self) -> u64 {
        self.settings.lock().unwrap().revision
    }

    /// Whether the host has a search key for Live.
    pub fn live_available(&self) -> bool {
        self.live.is_some()
    }

    /// Whether the host has what Edited needs: Live and a model.
    pub fn edited_available(&self) -> bool {
        self.live.is_some() && self.editor.is_some()
    }

    /// The scenario Edited follows, if any.
    pub fn scenario(&self) -> Option<String> {
        self.editor.as_ref()?.scenario()
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
        let invalid = |message: &str| Rejected::Invalid {
            message: message.into(),
        };
        match command {
            Command::SetSource { source, .. } => {
                match source {
                    Source::Copied if self.copied.is_none() => {
                        return Err(invalid("This world has no copied pages"));
                    }
                    Source::Live | Source::Edited if self.live.is_none() => {
                        return Err(invalid("Live pages need EXA_API_KEY on the host"));
                    }
                    Source::Edited if self.editor.is_none() => {
                        return Err(invalid("Edited pages need a model key on the host"));
                    }
                    _ => {}
                }
                if let Some(live) = &self.live
                    && source.is_live() != settings.source.is_live()
                {
                    live.revoke(source.is_live());
                }
                settings.source = source;
            }
            Command::SetScenario { scenario, .. } => {
                let Some(editor) = &self.editor else {
                    return Err(invalid("Edited pages need a model key on the host"));
                };
                let scenario = text::normalize_space(&scenario);
                editor.set_scenario(fcx, (!scenario.is_empty()).then_some(scenario));
            }
            Command::Restart { .. } => {
                if let Some(live) = &self.live {
                    live.restart();
                }
                if let Some(editor) = &self.editor {
                    editor.restart(fcx);
                }
            }
        }
        settings.revision += 1;
        Ok(Applied {
            revision: settings.revision,
            at_ms: fcx.now().since_start().as_millis() as u64,
        })
    }
}
