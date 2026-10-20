//! Revisioned tampering state and commands applied by a world task.

use std::sync::Arc;
use std::time::Duration;

use fictionet::{Cx, sync::Mutex};
use serde::{Deserialize, Serialize};

use crate::pages::Variant;

/// Maximum compact JSON size of any tampering state, in bytes.
pub const MAX_TAMPER_STATE_BYTES: usize = 160;
/// Maximum compact JSON size of any command, in bytes.
pub const MAX_COMMAND_BYTES: usize = 96;
/// Maximum compact JSON size of any reply, in bytes.
pub const MAX_REPLY_BYTES: usize = 160;

/// Sources that carry the false claim when tampering is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Only Wikipedia changes.
    Wikipedia,
    /// Every source changes.
    AllSources,
}

impl Scope {
    /// The scope name used in events and JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wikipedia => "wikipedia",
            Self::AllSources => "all_sources",
        }
    }
}

/// A snapshot of the world's selected content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TamperState {
    /// Number of applied changes.
    pub revision: u64,
    /// Run time of the last change, or zero for the initial state.
    pub since_start: Duration,
    /// Whether the selected sources carry false claims.
    pub on: bool,
    /// Which sources change when tampering is on.
    pub scope: Scope,
}

impl TamperState {
    /// The renderer variant selected by this snapshot.
    pub fn variant(self) -> Variant {
        match (self.on, self.scope) {
            (false, _) => Variant::Control,
            (true, Scope::Wikipedia) => Variant::AlteredOne,
            (true, Scope::AllSources) => Variant::AlteredAll,
        }
    }
}

/// A page command, such as `{"type":"set_tampering","on":true,"expected_revision":0}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    /// Sets tampering only if the caller has the current revision.
    SetTampering {
        /// The requested switch position.
        on: bool,
        /// The revision the caller read.
        expected_revision: u64,
    },
}

/// The result of applying a command at a world scheduling point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    /// The command was accepted, including a command with no change.
    Applied {
        /// The resulting revision.
        revision: u64,
        /// Run time of the last change.
        since_start: Duration,
        /// Whether the command changed the switch.
        changed: bool,
    },
    /// The state was left unchanged.
    Rejected(Rejection),
}

/// Why a command could not be applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Rejection {
    /// The caller's revision does not match the world.
    StaleRevision {
        /// The revision supplied by the caller.
        expected: u64,
        /// The world's current revision.
        current: u64,
    },
}

/// Shared tampering state, read once by each request.
#[derive(Clone)]
pub struct Tampering(Arc<Mutex<TamperState>>);

impl Tampering {
    /// Creates an initial state at revision zero and run time zero.
    pub fn new(on: bool, scope: Scope) -> Self {
        Self(Arc::new(Mutex::new(TamperState {
            revision: 0,
            since_start: Duration::ZERO,
            on,
            scope,
        })))
    }

    /// Returns one consistent snapshot.
    pub fn state(&self) -> TamperState {
        *self.0.lock()
    }

    /// Validates and applies a command at the calling world task's scheduling point.
    /// Events are built only when an observer is interested.
    pub fn apply(&self, fcx: &Cx, command: Command) -> Reply {
        let Command::SetTampering {
            on,
            expected_revision,
        } = command;
        let mut state = self.0.lock();
        if expected_revision != state.revision {
            let current = state.revision;
            drop(state);
            fcx.emit("fakewiki", "tampering_rejected", |event| {
                event
                    .field("expected", expected_revision)
                    .field("current", current)
            });
            return Reply::Rejected(Rejection::StaleRevision {
                expected: expected_revision,
                current,
            });
        }
        let changed = state.on != on;
        if changed {
            state.revision = state
                .revision
                .checked_add(1)
                .expect("tampering revision exhausted");
            state.on = on;
            state.since_start = fcx.now().since_start();
        }
        let snapshot = *state;
        drop(state);
        fcx.emit("fakewiki", "tampering", |event| {
            event
                .field("on", snapshot.on)
                .field("scope", snapshot.scope.as_str())
                .field("variant", snapshot.variant().as_str())
                .field("revision", snapshot.revision)
                .field("changed", changed)
        });
        Reply::Applied {
            revision: snapshot.revision,
            since_start: snapshot.since_start,
            changed,
        }
    }
}

impl From<Variant> for Tampering {
    fn from(variant: Variant) -> Self {
        match variant {
            Variant::Control => Self::new(false, Scope::Wikipedia),
            Variant::AlteredOne => Self::new(true, Scope::Wikipedia),
            Variant::AlteredAll => Self::new(true, Scope::AllSources),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_events_describe_each_outcome() {
        let memory = Arc::new(fictionet_observe::Memory::default());
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)).observer(memory.clone()),
            |fcx| async move {
                for scope in [Scope::Wikipedia, Scope::AllSources] {
                    let tampering = Tampering::new(false, scope);
                    for (on, expected_revision) in [(true, 0), (true, 1), (false, 0), (false, 1)] {
                        tampering.apply(
                            &fcx,
                            Command::SetTampering {
                                on,
                                expected_revision,
                            },
                        );
                    }
                }
                Ok(())
            },
        ))
        .unwrap();
        let events = memory.checked_all().unwrap();
        let events: Vec<_> = events.iter().filter(|e| e.source == "fakewiki").collect();
        assert_eq!(events.len(), 8);
        for (group, scope) in events
            .as_chunks::<4>()
            .0
            .iter()
            .zip([Scope::Wikipedia, Scope::AllSources])
        {
            for (event, on, revision, changed) in [
                (group[0], true, 1, true),
                (group[1], true, 1, false),
                (group[3], false, 2, true),
            ] {
                assert_eq!(event.kind, "tampering");
                assert_eq!(event.get("on").and_then(|v| v.as_bool()), Some(on));
                assert_eq!(event.str("scope"), Some(scope.as_str()));
                assert_eq!(
                    event.str("variant"),
                    Some(Tampering::new(on, scope).state().variant().as_str())
                );
                assert_eq!(event.u64("revision"), Some(revision));
                assert_eq!(
                    event.get("changed").and_then(|v| v.as_bool()),
                    Some(changed)
                );
            }
            assert_eq!(group[2].kind, "tampering_rejected");
            assert_eq!(group[2].u64("expected"), Some(0));
            assert_eq!(group[2].u64("current"), Some(1));
        }
    }

    #[test]
    fn commands_validate_revision_and_preserve_noop_time() {
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            |fcx| async move {
                for variant in [Variant::Control, Variant::AlteredOne, Variant::AlteredAll] {
                    assert_eq!(Tampering::from(variant).state().variant(), variant);
                }
                let tampering = Tampering::from(Variant::Control);
                let clone = tampering.clone();
                for (on, expected_revision, changed) in [
                    (false, 0, false),
                    (true, 0, true),
                    (true, 1, false),
                    (false, 1, true),
                ] {
                    let before = tampering.state();
                    fcx.sleep(Duration::from_millis(1)).await?;
                    let revision = before.revision + u64::from(changed);
                    let since_start = if changed {
                        fcx.now().since_start()
                    } else {
                        before.since_start
                    };
                    assert_eq!(
                        tampering.apply(
                            &fcx,
                            Command::SetTampering {
                                on,
                                expected_revision
                            }
                        ),
                        Reply::Applied {
                            revision,
                            since_start,
                            changed
                        }
                    );
                    assert_eq!(
                        clone.state(),
                        TamperState {
                            revision,
                            since_start,
                            on,
                            scope: Scope::Wikipedia
                        }
                    );
                }
                let before = tampering.state();
                assert_eq!(
                    tampering.apply(
                        &fcx,
                        Command::SetTampering {
                            on: true,
                            expected_revision: 0
                        }
                    ),
                    Reply::Rejected(Rejection::StaleRevision {
                        expected: 0,
                        current: 2
                    })
                );
                assert_eq!(tampering.state(), before);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn command_json_is_strict() {
        assert_eq!(
            serde_json::from_str::<Command>(
                r#"{"type":"set_tampering","on":true,"expected_revision":0}"#
            )
            .unwrap(),
            Command::SetTampering {
                on: true,
                expected_revision: 0
            }
        );
        for input in [
            r#"{"type":"set_tampering","on":true,"expected_revision":0,"extra":1}"#,
            r#"{"type":"unknown","on":true,"expected_revision":0}"#,
            r#"{"type":"set_tampering","on":"true","expected_revision":0}"#,
            r#"{"type":"set_tampering","on":true,"expected_revision":-1}"#,
            r#"{"type":"set_tampering","on":true}"#,
        ] {
            assert!(serde_json::from_str::<Command>(input).is_err(), "{input}");
        }
    }

    fn bounded<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(
        value: T,
        bound: usize,
    ) {
        let json = serde_json::to_vec(&value).unwrap();
        eprintln!(
            "{}: {} bytes (bound {bound})",
            std::any::type_name::<T>(),
            json.len()
        );
        assert!(json.len() <= bound);
        assert_eq!(serde_json::from_slice::<T>(&json).unwrap(), value);
    }

    #[test]
    fn compact_json_bounds_cover_largest_fields() {
        for scope in [Scope::Wikipedia, Scope::AllSources] {
            for on in [false, true] {
                bounded(
                    TamperState {
                        revision: u64::MAX,
                        since_start: Duration::MAX,
                        on,
                        scope,
                    },
                    MAX_TAMPER_STATE_BYTES,
                );
                bounded(
                    Command::SetTampering {
                        on,
                        expected_revision: u64::MAX,
                    },
                    MAX_COMMAND_BYTES,
                );
                bounded(
                    Reply::Applied {
                        revision: u64::MAX,
                        since_start: Duration::MAX,
                        changed: on,
                    },
                    MAX_REPLY_BYTES,
                );
            }
        }
        bounded(
            Reply::Rejected(Rejection::StaleRevision {
                expected: u64::MAX,
                current: u64::MAX,
            }),
            MAX_REPLY_BYTES,
        );
    }
}
