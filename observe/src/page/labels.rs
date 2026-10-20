use std::sync::Arc;

use fictionet::sync::Mutex;
use serde::{Deserialize, Serialize};

use super::{Command, CommandLimits, CommandPort, Page, Rejected, StateLimits, StateTopic};

/// A run identity a viewer can label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LabelTarget {
    /// An event's sequence number.
    Event {
        /// Event sequence.
        seq: u64,
    },
    /// A connection, including its endpoints to distinguish service counters.
    Connection {
        /// Connection number.
        id: u64,
        /// Local endpoint.
        local: String,
        /// Peer endpoint.
        peer: String,
    },
    /// A packet flow on one captured link. Endpoint order is immaterial.
    Flow {
        /// Link identifier.
        link: String,
        /// First packet address.
        a: String,
        /// Second packet address.
        b: String,
    },
}

impl LabelTarget {
    fn valid(&self) -> bool {
        let address = |s: &str| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control);
        match self {
            Self::Event { seq } => *seq > 0,
            Self::Connection { id, local, peer } => {
                *id > 0
                    && local.parse::<std::net::SocketAddr>().is_ok()
                    && peer.parse::<std::net::SocketAddr>().is_ok()
            }
            Self::Flow { link, a, b } => {
                link.strip_prefix('e')
                    .is_some_and(|id| id.parse::<u64>().is_ok_and(|id| id > 0))
                    && address(a)
                    && address(b)
            }
        }
    }
}

/// A bounded text label applied at a world scheduling point.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Label {
    /// Run-local label identity, never reused.
    pub id: u64,
    /// Labeled identity.
    pub target: LabelTarget,
    /// At most 80 UTF-8 bytes, without control characters.
    pub text: String,
    /// Application time in run seconds.
    pub at: f64,
}

/// Inputs to the world's label task.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum LabelCommand {
    /// Adds one label, within the text and count bounds.
    Add {
        /// Typed identity.
        target: LabelTarget,
        /// Short text.
        text: String,
    },
    /// Removes a label by its run-local identity.
    Remove {
        /// Label identity.
        id: u64,
    },
}

#[derive(Clone, Default)]
struct Store {
    next: u64,
    labels: Vec<Label>,
}

/// A label mailbox and state topic. At most 256 labels are retained.
/// Pass a clone to [`Page::labels`], and apply its commands in a world task.
/// Every accepted change emits `page.label` before replying to the browser.
#[derive(Clone)]
pub struct Labels {
    /// World input mailbox. Replies name the applied state revision.
    pub commands: CommandPort<LabelCommand, u64>,
    /// Authoritative labels, published at the world's application time.
    pub topic: StateTopic<Vec<Label>>,
    store: Arc<Mutex<Store>>,
}

impl Default for Labels {
    fn default() -> Self {
        Self {
            commands: CommandPort::new(CommandLimits::default()),
            topic: StateTopic::new(StateLimits::default()),
            store: Arc::new(Mutex::new(Store::default())),
        }
    }
}

impl Labels {
    /// Applies a command, validating its target, text and count first.
    pub fn apply(&self, cx: &fictionet::Cx, input: Command<LabelCommand, u64>) {
        match self.apply_change(cx, &input.command) {
            Ok(revision) => input.reply(cx, revision),
            Err(message) => input.reject(cx, Rejected::Invalid { message }),
        }
    }

    /// Runs the mailbox at world scheduling points until the region closes.
    pub async fn run(&self, cx: &fictionet::Cx) -> Result<(), fictionet::Cancelled> {
        loop {
            let command = cx
                .race(None, self.commands.recv())
                .await
                .map_err(|_| fictionet::Cancelled)?;
            let Some(command) = command else {
                return Ok(());
            };
            self.apply(cx, command);
        }
    }

    /// Applies a world-authored label input and records its change. Browser
    /// inputs use [`Self::apply`] so the mailbox also receives its reply.
    pub fn apply_change(&self, cx: &fictionet::Cx, command: &LabelCommand) -> Result<u64, String> {
        let mut store = self.store.lock();
        let mut next = store.clone();
        match command {
            LabelCommand::Add { target, text } => {
                if !target.valid()
                    || text.trim().is_empty()
                    || text.len() > 80
                    || text.chars().any(char::is_control)
                {
                    return Err("Use a valid target and one to 80 bytes of label text without control characters".into());
                }
                if next.labels.len() >= 256 {
                    return Err("The run already has 256 labels; remove one first".into());
                }
                next.next = next
                    .next
                    .checked_add(1)
                    .ok_or("Label identities exhausted")?;
                let mut target = target.clone();
                if let LabelTarget::Flow { a, b, .. } = &mut target
                    && a > b
                {
                    std::mem::swap(a, b);
                }
                next.labels.push(Label {
                    id: next.next,
                    target,
                    text: text.clone(),
                    at: cx.now().since_start().as_secs_f64(),
                });
            }
            LabelCommand::Remove { id } => {
                let index = next
                    .labels
                    .iter()
                    .position(|label| label.id == *id)
                    .ok_or("That label is no longer present")?;
                next.labels.remove(index);
            }
        }
        let revision = self
            .topic
            .publish(cx.now(), &next.labels)
            .map_err(|error| error.to_string())?;
        let id = match command {
            LabelCommand::Add { .. } => next.next,
            LabelCommand::Remove { id } => *id,
        };
        *store = next;
        cx.emit("page", "label", |event| {
            event
                .field(
                    "change",
                    super::command::event_value(
                        &serde_json::to_value(command).expect("label command is JSON"),
                    ),
                )
                .field("revision", revision)
                .field("id", id)
        });
        Ok(revision)
    }

    pub(super) fn snapshot(&self) -> Vec<Label> {
        self.store.lock().labels.clone()
    }
}

impl Page {
    /// Enables labeling through a world-owned mailbox and authoritative topic.
    pub fn labels(mut self, labels: Labels) -> Self {
        if self.labels.is_some() {
            self.errors.push("labels called twice".into());
        }
        self.topics
            .push(("labels".into(), labels.topic.topic.clone()));
        self.commands
            .push(("labels".into(), Box::new(labels.commands.clone())));
        self.labels = Some(labels);
        self.panels.push(super::builder::labels_panel(true));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::{RunOptions, Seed};

    #[test]
    fn label_inputs_are_bounded_recorded_and_joined_to_exports() {
        let events = Arc::new(crate::Memory::default());
        let saved = events.clone();
        fictionet::block_on(fictionet::lab(
            RunOptions::new(Seed::from_u64(1)).observer(events),
            move |cx| async move {
                let labels = Labels::default();
                let command = LabelCommand::Add {
                    target: LabelTarget::Event { seq: 7 },
                    text: "download".into(),
                };
                assert_eq!(labels.apply_change(&cx, &command).unwrap(), 1);
                let mut event = fictionet::events::Event::new("test", "item");
                event.seq = 7;
                assert_eq!(
                    crate::export::event_labels(&event, &labels.snapshot())[0].text,
                    "download"
                );
                event.seq = 8;
                assert!(crate::export::event_labels(&event, &labels.snapshot()).is_empty());
                let connection = LabelTarget::Connection {
                    id: 3,
                    local: "192.0.2.1:80".into(),
                    peer: "10.0.2.15:40000".into(),
                };
                labels
                    .apply_change(
                        &cx,
                        &LabelCommand::Add {
                            target: connection,
                            text: "request".into(),
                        },
                    )
                    .unwrap();
                event.conn = fictionet::events::ConnInfo::new(
                    3,
                    "192.0.2.1:80".parse().unwrap(),
                    "10.0.2.15:40000".parse().unwrap(),
                );
                assert_eq!(
                    crate::export::event_labels(&event, &labels.snapshot())[0].text,
                    "request"
                );
                let flow = LabelTarget::Flow {
                    link: "e1".into(),
                    a: "b".into(),
                    b: "a".into(),
                };
                labels
                    .apply_change(
                        &cx,
                        &LabelCommand::Add {
                            target: flow,
                            text: "flow".into(),
                        },
                    )
                    .unwrap();
                assert_eq!(
                    labels.snapshot()[2].target,
                    LabelTarget::Flow {
                        link: "e1".into(),
                        a: "a".into(),
                        b: "b".into()
                    }
                );
                for text in ["", "\n", &"x".repeat(81)] {
                    assert!(
                        labels
                            .apply_change(
                                &cx,
                                &LabelCommand::Add {
                                    target: LabelTarget::Event { seq: 7 },
                                    text: text.into()
                                }
                            )
                            .is_err()
                    );
                }
                assert!(
                    labels
                        .apply_change(
                            &cx,
                            &LabelCommand::Add {
                                target: LabelTarget::Event { seq: 0 },
                                text: "invalid".into()
                            }
                        )
                        .is_err()
                );
                for _ in 3..256 {
                    labels.apply_change(&cx, &command).unwrap();
                }
                assert_eq!(labels.snapshot().len(), 256);
                assert!(labels.apply_change(&cx, &command).is_err());
                labels
                    .apply_change(&cx, &LabelCommand::Remove { id: 1 })
                    .unwrap();
                assert!(
                    labels
                        .apply_change(&cx, &LabelCommand::Remove { id: 1 })
                        .is_err()
                );
                assert_eq!(labels.snapshot().len(), 255);
                labels.apply_change(&cx, &command).unwrap();
                assert_eq!(labels.snapshot().last().unwrap().id, 257);
                let changes = saved.checked_of("page", "label").unwrap();
                assert_eq!(changes.len(), 258);
                assert_eq!(changes[0].u64("id"), Some(1));
                assert_eq!(changes.last().unwrap().u64("revision"), Some(258));
                Ok(())
            },
        ))
        .unwrap();
    }
}
