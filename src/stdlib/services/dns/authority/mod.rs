//! Authoritative servers: what a server at an address answers, and the
//! engine that runs one.
//!
//! An [`Authority`] is world code that decides a server's reply to one
//! request. It may need to see what another server answers first, such
//! as a relay that passes on a real server's reply: it returns
//! [`Step::Need`] with the question, and the [`AuthorityEngine`] carries
//! it, records what came back, and asks again with that observation
//! [known](Known). The engine puts every reply through the server front
//! of [`ServerConfig`], which gives it the header and EDNS details real
//! servers send.
//!
//! | Authority | What it answers |
//! | --- | --- |
//! | [`Zones`] | From zone data, with the answer of RFC 1034 §4.3.2. |
//! | [`Relay`] | What the real server at its own address answers. |
//! | [`Overlay`] | What its base answers, except for invented zones below it. |
//! | [`Observe`] | What the authority it wraps answers, shown to a callback first. |
//!
//! A world writes its own for anything else, such as a server that
//! answers one sandbox differently from the others.

use std::net::SocketAddr;
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::op::ResponseCode;
use fictionet::stdlib::protocols::dns::rr::{LowerName, RecordType};
use fictionet::stdlib::protocols::dns::{EdeCode, Request, Response};
use fictionet::stdlib::services::serve::Transport;

use super::exchange::Client;
use super::zone::{Answered, ZoneData, answer};

mod engine;
mod observe;
mod overlay;
mod relay;
mod server;

pub use engine::AuthorityEngine;
pub use observe::Observe;
pub use overlay::Overlay;
pub use relay::Relay;
pub use server::{ChaosAnswer, Identity, ServerConfig, bare_reply, chaos};

/// A question, as bytes, that a server sends to another server.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ask {
    /// The server asked.
    pub server: SocketAddr,
    /// How it is asked.
    pub transport: Transport,
    /// One DNS query.
    pub query: Vec<u8>,
}

/// What a client of that server saw.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Observed {
    /// The server's reply, as it arrived.
    Reply(Vec<u8>),
    /// The server could not be reached, or refused the connection.
    Unreachable,
    /// No reply came in time.
    Timeout,
}

/// The observations made so far for one request.
pub trait Known {
    /// What `ask` gave, if it was asked.
    fn get(&self, ask: &Ask) -> Option<&Observed>;
}

/// What an authority does with one request, given what it knows so far.
#[derive(Clone, Debug, PartialEq)]
pub enum Step {
    /// Reply with this, after the server front gives it the header and
    /// EDNS details of [`ServerConfig`] and it is fitted to the client's
    /// size.
    Reply(Response),
    /// Reply with these octets exactly as they are, such as a real
    /// server's reply that a relay passes on. Only a reply larger than the
    /// client can take is written again, truncated as RFC 2181 §9 says.
    Verbatim(Vec<u8>),
    /// Ask another server first, then ask the authority again.
    Need(Ask),
    /// Send nothing, as a server that never replies.
    Silent,
}

/// What the server at `local` answers. World code: trusted, called
/// synchronously by the engine, so it must return quickly.
///
/// `respond` is a function of its arguments. Within one request the
/// observations only grow, and an authority never asks for something it
/// already knows, so each request ends within as many steps as it has
/// distinct asks.
pub trait Authority: Send + Sync + 'static {
    /// The step for `req`, which `client` sent to the server at `local`,
    /// whose front is `server`.
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        client: &Client,
        known: &dyn Known,
    ) -> Step;
}

impl<A: Authority + ?Sized> Authority for Arc<A> {
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        client: &Client,
        known: &dyn Known,
    ) -> Step {
        (**self).respond(req, local, server, client, known)
    }
}

/// Answers from zones, as an authoritative server that hosts them.
///
/// The deepest zone whose apex is at or above QNAME answers, except that
/// a DS question at a zone's apex goes to the zone above it when that zone
/// is hosted too, since the parent holds DS (RFC 4035 §3.1.4.1). A view
/// that does not know a fact the reply needs gives SERVFAIL, never a
/// negative. A QNAME no hosted zone contains gets REFUSED, with Extended
/// DNS Error 20, Not Authoritative, when the front sends them (RFC 8914
/// §4.21). Zone transfers are refused: zone data makes views for
/// questions, not listings of a whole zone. Zones never ask another
/// server.
pub struct Zones {
    zones: Vec<Arc<dyn ZoneData>>,
}

impl Zones {
    /// A server for `zones`. At equal depth, the zone given last answers.
    pub fn new(zones: Vec<Arc<dyn ZoneData>>) -> Zones {
        Zones { zones }
    }

    /// The zone that answers a question for `qname` of type `qtype`.
    fn find(&self, qname: &LowerName, qtype: RecordType) -> Option<&dyn ZoneData> {
        // `max_by_key` keeps the last of equal keys: the zone given last.
        let deepest = |strictly_above: bool| {
            self.zones
                .iter()
                .filter(|zone| zone.apex().zone_of(qname))
                .filter(|zone| !strictly_above || zone.apex() != qname)
                .max_by_key(|zone| zone.apex().num_labels())
        };
        let zone = match qtype {
            RecordType::DS => deepest(true).or_else(|| deepest(false)),
            _ => deepest(false),
        };
        zone.map(|zone| &**zone)
    }
}

impl Authority for Zones {
    fn respond(
        &self,
        req: &Request,
        _local: SocketAddr,
        server: &ServerConfig,
        _client: &Client,
        _known: &dyn Known,
    ) -> Step {
        let qname = LowerName::new(req.question.name());
        let qtype = req.question.query_type();
        if matches!(qtype, RecordType::AXFR | RecordType::IXFR) {
            return Step::Reply(bare_reply(req, ResponseCode::Refused, None));
        }
        let Some(zone) = self.find(&qname, qtype) else {
            let ede = server.ede.then_some(EdeCode::NOT_AUTHORITATIVE);
            return Step::Reply(bare_reply(req, ResponseCode::Refused, ede));
        };
        match answer(&*zone.view(&req.question), req, server.any) {
            Answered::Response(response) => Step::Reply(response),
            Answered::Unknown { .. } => Step::Reply(bare_reply(req, ResponseCode::ServFail, None)),
        }
    }
}
