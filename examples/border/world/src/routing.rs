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

use example_common::events::field;
use example_common::names::name;
use fictionet::Cx;
use fictionet::stdlib::services::serve::WakeHandle;
use fictionet::sync::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::json;

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

/// Let the impostor answer at the bank's address in the hijack, or not,
/// only if the caller has the current revision. With the impostor off, the
/// hijacked bank address has no host, and Transpeak's router answers "host
/// unreachable".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetImpostor {
    pub on: bool,
    pub expected_revision: u64,
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
    /// The command asks for the route or impostor the world already has.
    AlreadyInMode,
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
    /// Whether the impostor answers at the bank's address in the hijack.
    pub impostor: bool,
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
            impostor: true,
        }
    }
}

/// A cheap handle to the run's routing table.
#[derive(Clone)]
pub struct Routing(Arc<Inner>);

struct Inner {
    scenario: Arc<Scenario>,
    hijacked: AtomicBool,
    impostor: AtomicBool,
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
            impostor: AtomicBool::new(true),
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

    /// Whether the impostor answers at the bank's address in the hijack.
    pub fn impostor(&self) -> bool {
        self.0.impostor.load(Ordering::Acquire)
    }

    pub fn state(&self) -> RouteState {
        let revision = self.0.revision.lock();
        RouteState {
            impostor: self.impostor(),
            ..RouteState::new(
                &self.0.scenario.routed(self.mode()),
                revision.number,
                revision.since_ms,
            )
        }
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
        self.check(
            fcx,
            &revision,
            command.expected_revision,
            command.mode == previous,
        )?;
        Ok(self.change(fcx, &mut revision, command.mode, self.impostor()))
    }

    /// Turns the impostor on or off from a world task. Rejections never move
    /// the revision.
    pub fn set_impostor(&self, fcx: &Cx, command: SetImpostor) -> Result<Applied, Rejected> {
        let mut revision = self.0.revision.lock();
        self.check(
            fcx,
            &revision,
            command.expected_revision,
            command.on == self.impostor(),
        )?;
        Ok(self.change(fcx, &mut revision, self.mode(), command.on))
    }

    /// Puts the route back to normal with the impostor on, whatever they are
    /// now, as at the start of the run. Only a stale revision is rejected.
    pub fn restart(&self, fcx: &Cx, expected_revision: u64) -> Result<Applied, Rejected> {
        let mut revision = self.0.revision.lock();
        self.check(fcx, &revision, expected_revision, false)?;
        let applied = self.change(fcx, &mut revision, Variant::Legitimate, true);
        fcx.emit("border", "restarted", |e| {
            e.field("revision", applied.revision)
                .field("at_ms", applied.at_ms)
        });
        Ok(applied)
    }

    /// Rejects a stale revision, or a command that changes nothing.
    fn check(
        &self,
        fcx: &Cx,
        revision: &Revision,
        expected: u64,
        unchanged: bool,
    ) -> Result<(), Rejected> {
        let reason = if expected != revision.number {
            Rejection::StaleRevision
        } else if unchanged {
            Rejection::AlreadyInMode
        } else {
            return Ok(());
        };
        let mode = self.mode();
        fcx.emit("border", "route_rejected", |e| {
            e.field("reason", name(&reason))
                .field("expected_revision", expected)
                .field("revision", revision.number)
                .field("mode", name(&mode))
        });
        Err(Rejected {
            reason,
            revision: revision.number,
            mode,
        })
    }

    /// Moves to the next revision with `mode` and `impostor`, emits what
    /// changed, and wakes the BGP sessions when the route did.
    fn change(&self, fcx: &Cx, revision: &mut Revision, mode: Variant, impostor: bool) -> Applied {
        let previous = self.mode();
        let was = self.impostor();
        revision.number += 1;
        revision.since_ms = fcx.now().since_start().as_millis() as u64;
        self.0
            .hijacked
            .store(mode == Variant::Hijack, Ordering::Release);
        self.0.impostor.store(impostor, Ordering::Release);
        if mode != previous {
            fcx.emit("border", "route", |e| {
                let scenario = self.0.scenario.routed(mode);
                e.field("revision", revision.number)
                    .field("mode", name(&mode))
                    .field("previous_mode", name(&previous))
                    .field(
                        "bank_route",
                        field(&json!(Route::new(&scenario, &scenario.bank_route()))),
                    )
                    .field("bank_hops", field(&json!(scenario.hops(BANK_ADDR))))
                    .field("at_ms", revision.since_ms)
            });
            revision.peers.retain(|p| !p.is_closed());
            for peer in &revision.peers {
                peer.wake();
            }
        }
        if impostor != was {
            fcx.emit("border", "impostor", |e| {
                e.field("revision", revision.number)
                    .field("on", impostor)
                    .field("at_ms", revision.since_ms)
            });
        }
        Applied {
            revision: revision.number,
            at_ms: revision.since_ms,
        }
    }
}
