//! The run's routing revision and typed command boundary.
//!
//! Call [`Routing::apply`] from a world task. A successful change publishes the
//! mode for the next packet, emits a fact, and wakes established BGP sessions.
//! The packet path reads one atomic mode. Commands and state projections share
//! a lock so revision, mode and effective time stay together.

use std::net::Ipv4Addr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use fictionet::Cx;
use fictionet::events::Fields;
use fictionet::stdlib::protocols::json::Value;
use fictionet::stdlib::services::serve::WakeHandle;
use fictionet::sync::Mutex;
use serde::{Deserialize, Serialize};

use crate::scenario::{Announcement, BANK_ADDR, Identity, Scenario, Variant};

/// Change the route only if the caller has the current revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetRoute {
    pub mode: Variant,
    pub expected_revision: u64,
}

impl SetRoute {
    pub const MAX_JSON_BYTES: usize = 80;
}

/// The revision and run time of an applied change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    pub revision: u64,
    pub at_ms: u64,
}

impl Applied {
    pub const MAX_JSON_BYTES: usize = 80;
}

/// Why a command left the route unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rejection {
    StaleRevision,
    AlreadyInMode,
}

impl Rejection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleRevision => "stale_revision",
            Self::AlreadyInMode => "already_in_mode",
        }
    }
}

/// A rejected command, with the state the caller should use next.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rejected {
    pub reason: Rejection,
    pub revision: u64,
    pub mode: Variant,
}

impl Rejected {
    pub const MAX_JSON_BYTES: usize = 100;
}

/// One announced route. `hijack` means a foreign origin claims home space.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub prefix: String,
    pub as_path: Vec<u16>,
    pub origin_as: u16,
    pub hijack: bool,
}

impl Route {
    pub(crate) fn new(scenario: &Scenario, route: &Announcement) -> Self {
        Self {
            prefix: format!("{}/{}", route.prefix.addr, route.prefix.len),
            as_path: route.as_path.clone(),
            origin_as: route.origin_as(),
            hijack: scenario.conflicts_with_home(route),
        }
    }

    pub(crate) fn fact(&self) -> Value {
        Fields::new()
            .with("prefix", self.prefix.clone())
            .with(
                "as_path",
                Value::Array(self.as_path.iter().map(|&n| u64::from(n).into()).collect()),
            )
            .with("origin_as", u64::from(self.origin_as))
            .with("hijack", self.hijack)
            .to_json()
    }
}

/// The current routes and the bank path as seen from the sandbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteState {
    pub revision: u64,
    pub mode: Variant,
    pub since_ms: u64,
    pub routes: Vec<Route>,
    pub bank_route: Route,
    pub bank_hops: Vec<Ipv4Addr>,
    pub bank_identity: Identity,
}

impl RouteState {
    /// The maximum for a projection produced by this world, in either mode.
    pub const MAX_JSON_BYTES: usize = 1024;

    /// Projects a scenario at the supplied routing revision and run time.
    pub fn new(scenario: &Scenario, revision: u64, since_ms: u64) -> Self {
        Self {
            revision,
            mode: scenario.variant,
            since_ms,
            routes: scenario
                .announcements()
                .iter()
                .map(|r| Route::new(scenario, r))
                .collect(),
            bank_route: Route::new(scenario, &scenario.bank_route()),
            bank_hops: scenario.hops(BANK_ADDR),
            bank_identity: scenario.bank_identity(),
        }
    }
}

/// A cheap handle to the run's routing table.
#[derive(Clone)]
pub struct Routing(Arc<Inner>);

struct Inner {
    scenario: Arc<Scenario>,
    hijacked: AtomicBool,
    revision: Mutex<Revision>,
}

struct Revision {
    number: u64,
    since_ms: u64,
    peers: Vec<WakeHandle>,
}

impl Routing {
    pub(crate) fn new(scenario: Arc<Scenario>) -> Self {
        Self(Arc::new(Inner {
            hijacked: AtomicBool::new(scenario.hijacked()),
            scenario,
            revision: Mutex::new(Revision {
                number: 0,
                since_ms: 0,
                peers: Vec::new(),
            }),
        }))
    }

    /// The route to assign to a packet entering the path now.
    pub fn mode(&self) -> Variant {
        if self.0.hijacked.load(Ordering::Acquire) {
            Variant::Hijack
        } else {
            Variant::Legitimate
        }
    }

    pub fn state(&self) -> RouteState {
        let revision = self.0.revision.lock();
        RouteState::new(
            &self.0.scenario.routed(self.mode()),
            revision.number,
            revision.since_ms,
        )
    }

    pub(crate) fn register(&self, peer: WakeHandle) {
        let mut revision = self.0.revision.lock();
        revision.peers.retain(|p| !p.is_closed());
        revision.peers.push(peer);
    }

    /// Applies one command from a world task. Rejections never move the revision.
    pub fn apply(&self, fcx: &Cx, command: SetRoute) -> Result<Applied, Rejected> {
        let mut revision = self.0.revision.lock();
        let previous = self.mode();
        let reason = if command.expected_revision != revision.number {
            Some(Rejection::StaleRevision)
        } else if command.mode == previous {
            Some(Rejection::AlreadyInMode)
        } else {
            None
        };
        if let Some(reason) = reason {
            fcx.emit("border", "route_rejected", |e| {
                e.field("reason", reason.as_str())
                    .field("expected_revision", command.expected_revision)
                    .field("revision", revision.number)
                    .field("mode", previous.as_str())
            });
            return Err(Rejected {
                reason,
                revision: revision.number,
                mode: previous,
            });
        }
        revision.number += 1;
        revision.since_ms = fcx.now().since_start().as_millis() as u64;
        self.0
            .hijacked
            .store(command.mode == Variant::Hijack, Ordering::Release);
        fcx.emit("border", "route", |e| {
            let scenario = self.0.scenario.routed(command.mode);
            e.field("revision", revision.number)
                .field("mode", command.mode.as_str())
                .field("previous_mode", previous.as_str())
                .field(
                    "bank_route",
                    Route::new(&scenario, &scenario.bank_route()).fact(),
                )
                .field(
                    "bank_hops",
                    Value::Array(
                        scenario
                            .hops(BANK_ADDR)
                            .iter()
                            .map(|a| a.to_string().into())
                            .collect(),
                    ),
                )
                .field("at_ms", revision.since_ms)
        });
        revision.peers.retain(|p| !p.is_closed());
        for peer in &revision.peers {
            peer.wake();
        }
        Ok(Applied {
            revision: revision.number,
            at_ms: revision.since_ms,
        })
    }
}
