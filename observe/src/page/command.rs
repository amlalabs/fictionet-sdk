use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use fictionet::sync::Mutex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{mpsc, watch};

/// Command mailbox, deduplication and HTTP wait bounds.
#[derive(Clone, Copy, Debug)]
pub struct CommandLimits {
    /// Commands waiting for the world to receive them.
    pub queued: usize,
    /// Retained request IDs, including queued and pending commands.
    pub requests: usize,
    /// HTTP reply deadline. Expiry never cancels an enqueued command.
    pub timeout: Duration,
}

impl Default for CommandLimits {
    fn default() -> Self {
        Self {
            queued: 32,
            requests: 128,
            timeout: Duration::from_secs(10),
        }
    }
}

/// A declared control action. The browser sends this JSON as `command`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Action {
    /// Visible button label.
    pub label: String,
    /// Concrete command decoded by the port's command type.
    pub command: Value,
}

/// POST body for a command port.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRequest {
    /// Nonempty caller-chosen ID, at most 128 UTF-8 bytes.
    pub request_id: String,
    /// Concrete command value.
    pub command: Value,
}

/// World-side rejection of a command.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Rejected {
    /// State changed since the browser read it.
    StaleRevision {
        /// Current world revision.
        current: u64,
    },
    /// The world declined the operation.
    Invalid {
        /// Human-readable reason.
        message: String,
    },
    /// The world dropped the command without replying.
    Unavailable,
}

/// Command result. Successful values retain the author's JSON shape.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CommandReply {
    /// World accepted and applied the command.
    Applied {
        /// Caller-chosen request ID.
        request_id: String,
        /// Serialized world reply.
        reply: Value,
    },
    /// World declined the command.
    Rejected {
        /// Caller-chosen request ID.
        request_id: String,
        /// Typed reason.
        rejection: Rejected,
    },
    /// A duplicate arrived while the first command is pending.
    Pending {
        /// Caller-chosen request ID.
        request_id: String,
    },
    /// HTTP wait expired. The command remains queued or in progress.
    Timeout {
        /// Caller-chosen request ID.
        request_id: String,
        /// Read state before deciding whether to retry.
        error: String,
    },
}

impl CommandReply {
    fn status(&self) -> u16 {
        match self {
            Self::Applied { .. } => 200,
            Self::Rejected { .. } => 409,
            Self::Pending { .. } => 202,
            Self::Timeout { .. } => 504,
        }
    }
}

/// A typed, bounded, executor-neutral world mailbox. Receiving and replying
/// work on any executor; only the HTTP deadline uses the page's Tokio runtime.
pub struct CommandPort<C, R> {
    inner: Arc<Inner<C, R>>,
}

impl<C, R> Clone for CommandPort<C, R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

struct Inner<C, R> {
    limits: CommandLimits,
    sender: mpsc::Sender<Command<C, R>>,
    receiver: tokio::sync::Mutex<mpsc::Receiver<Command<C, R>>>,
    cache: Mutex<Cache>,
}
#[derive(Default)]
struct Cache {
    order: VecDeque<String>,
    entries: BTreeMap<String, watch::Sender<Option<CommandReply>>>,
}

impl<C, R> CommandPort<C, R> {
    /// Creates a port. Zero queue or cache capacity is rejected at bind time.
    pub fn new(limits: CommandLimits) -> Self {
        let (sender, receiver) = mpsc::channel(limits.queued.max(1));
        Self {
            inner: Arc::new(Inner {
                limits,
                sender,
                receiver: tokio::sync::Mutex::new(receiver),
                cache: Mutex::new(Cache::default()),
            }),
        }
    }

    /// Waits for the next command, without requiring a Tokio runtime.
    pub async fn recv(&self) -> Option<Command<C, R>> {
        self.inner.receiver.lock().await.recv().await
    }

    /// Takes a command at an explicit world scheduling point.
    pub fn try_recv(&self) -> Option<Command<C, R>> {
        self.inner.receiver.try_lock().ok()?.try_recv().ok()
    }
}

/// One command delivered to the world. Finish it with [`Command::reply`]
/// or [`Command::reject`]; both record the outcome using the world's `Cx`.
pub struct Command<C, R> {
    /// Decoded world-owned input.
    pub command: C,
    /// Caller-chosen request ID.
    pub request_id: String,
    panel: String,
    json: Value,
    result: watch::Sender<Option<CommandReply>>,
    marker: PhantomData<fn() -> R>,
}

impl<C, R> Command<C, R> {
    fn finish(&self, cx: &fictionet::Cx, reply: CommandReply) {
        cx.emit("page", "command", |event| {
            // Core's JSON value preserves the input object without adding a
            // serde dependency to the sans-I/O SDK.
            let command = event_value(&self.json);
            let outcome =
                event_value(&serde_json::to_value(&reply).expect("command reply is JSON"));
            event
                .field("panel", self.panel.as_str())
                .field("request_id", self.request_id.as_str())
                .field("command", command)
                .field("outcome", outcome)
        });
        self.result.send_replace(Some(reply));
    }

    /// Rejects the input and records the reason at the world's current time.
    pub fn reject(self, cx: &fictionet::Cx, rejection: Rejected) {
        self.finish(
            cx,
            CommandReply::Rejected {
                request_id: self.request_id.clone(),
                rejection,
            },
        );
    }
}

pub(super) fn event_value(value: &Value) -> fictionet::stdlib::protocols::json::Value {
    use fictionet::stdlib::protocols::json::{Number, Value as EventValue};
    match value {
        Value::Null => EventValue::Null,
        Value::Bool(value) => EventValue::Bool(*value),
        Value::Number(value) => {
            EventValue::Number(Number::from_text(&value.to_string()).expect("valid JSON number"))
        }
        Value::String(value) => EventValue::String(value.clone()),
        Value::Array(values) => EventValue::Array(values.iter().map(event_value).collect()),
        Value::Object(values) => EventValue::Object(
            values
                .iter()
                .map(|(k, v)| (k.clone(), event_value(v)))
                .collect(),
        ),
    }
}

impl<C, R: Serialize> Command<C, R> {
    /// Records an accepted command and replies. Replies are limited to 64 KiB;
    /// serialization or size errors become typed invalid rejections.
    pub fn reply(self, cx: &fictionet::Cx, reply: R) {
        let value = serde_json::to_vec(&reply)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                if bytes.len() > super::http::MAX_BODY {
                    return Err("command reply exceeds 64 KiB".into());
                }
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())
            });
        let reply = match value {
            Ok(reply) => CommandReply::Applied {
                request_id: self.request_id.clone(),
                reply,
            },
            Err(message) => CommandReply::Rejected {
                request_id: self.request_id.clone(),
                rejection: Rejected::Invalid { message },
            },
        };
        self.finish(cx, reply);
    }
}

impl<C, R> Drop for Command<C, R> {
    fn drop(&mut self) {
        if self.result.borrow().is_none() {
            self.result.send_replace(Some(CommandReply::Rejected {
                request_id: self.request_id.clone(),
                rejection: Rejected::Unavailable,
            }));
        }
    }
}

type ReplyFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(u16, CommandReply), (u16, String)>> + Send + 'a>>;

pub(super) trait Dispatch: Send + Sync {
    fn validate(&self, actions: &[Action], linked: bool) -> Result<(), String>;
    fn submit<'a>(&'a self, panel: &'a str, request: CommandRequest) -> ReplyFuture<'a>;
}

fn decode<C: DeserializeOwned>(value: Value) -> Result<C, String> {
    serde_path_to_error::deserialize(value)
        .map_err(|e| format!("command.{}: {}", e.path(), e.inner()))
}

impl<C: DeserializeOwned + Send + 'static, R: Serialize + 'static> Dispatch for CommandPort<C, R> {
    fn validate(&self, actions: &[Action], linked: bool) -> Result<(), String> {
        if self.inner.limits.queued == 0 || self.inner.limits.requests == 0 {
            return Err("CommandPort::new requires positive queued and requests bounds".into());
        }
        for action in actions {
            if action.label.trim().is_empty() {
                return Err("Action label is empty; provide a visible label".into());
            }
            let mut value = action.command.clone();
            if linked {
                let object = value.as_object_mut().ok_or_else(|| {
                    format!(
                        "Action {:?} must be an object for control_state; declare command fields",
                        action.label
                    )
                })?;
                object.insert("expected_revision".into(), 0.into());
            }
            decode::<C>(value).map_err(|e| format!("Action {:?}: {e}", action.label))?;
        }
        Ok(())
    }

    fn submit<'a>(&'a self, panel: &'a str, request: CommandRequest) -> ReplyFuture<'a> {
        Box::pin(async move {
            if request.request_id.is_empty() || request.request_id.len() > 128 {
                return Err((
                    400,
                    "request_id must contain between one and 128 UTF-8 bytes".into(),
                ));
            }
            let mut result = {
                let mut cache = self.inner.cache.lock();
                let key = format!("{panel}\0{}", request.request_id);
                if let Some(existing) = cache.entries.get(&key) {
                    let reply =
                        existing
                            .borrow()
                            .clone()
                            .unwrap_or_else(|| CommandReply::Pending {
                                request_id: request.request_id.clone(),
                            });
                    return Ok((reply.status(), reply));
                }
                let command = decode::<C>(request.command.clone()).map_err(|e| (400, e))?;
                let permit = self
                    .inner
                    .sender
                    .try_reserve()
                    .map_err(|_| (503, "command queue is full".into()))?;
                if cache.entries.len() >= self.inner.limits.requests {
                    let Some(index) = cache
                        .order
                        .iter()
                        .position(|id| cache.entries[id].borrow().is_some())
                    else {
                        return Err((503, "request cache is full of pending commands".into()));
                    };
                    let id = cache.order.remove(index).unwrap();
                    cache.entries.remove(&id);
                }
                let (result, receiver) = watch::channel(None);
                cache.order.push_back(key.clone());
                cache.entries.insert(key, result.clone());
                permit.send(Command {
                    command,
                    request_id: request.request_id.clone(),
                    panel: panel.into(),
                    json: request.command,
                    result,
                    marker: PhantomData,
                });
                receiver
            };
            let reply = tokio::time::timeout(self.inner.limits.timeout, async {
                loop {
                    if let Some(reply) = result.borrow_and_update().clone() {
                        return reply;
                    }
                    if result.changed().await.is_err() {
                        return CommandReply::Rejected {
                            request_id: request.request_id.clone(),
                            rejection: Rejected::Unavailable,
                        };
                    }
                }
            })
            .await
            .unwrap_or_else(|_| CommandReply::Timeout {
                request_id: request.request_id,
                error: "the command may still apply; read the state before retrying".into(),
            });
            Ok((reply.status(), reply))
        })
    }
}
