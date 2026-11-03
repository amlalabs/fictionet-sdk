//! Authoritative servers: what a server at an address answers, and the
//! engine that runs one.
//!
//! An [`Authority`] is world code that decides a server's reply to one
//! request. A server whose zone is [learned](super::zone::Learned) may
//! need a fact it does not hold yet: it returns [`Step::Need`] with a
//! [`Lookup`] of one real server of the zone, and the [`AuthorityEngine`]
//! has its driver put the lookup to the upstream, [files](Authority::file)
//! what came back, and asks the authority again. The engine puts every
//! reply through the server front of [`ServerConfig`], which gives it the
//! header and EDNS details real servers send. Every reply is built from
//! records; no message from a real server is passed on.
//!
//! | Authority | What it answers |
//! | --- | --- |
//! | [`Zones`] | From zone data, with the answer of RFC 1034 §4.3.2. |
//! | [`Copies`] | As [`Zones`], over learned copies of the zones each address serves, looking up what a copy lacks and noting the child zones real servers turn out to serve. |
//! | [`Overlay`] | What its base answers, except for invented zones below it. |
//! | [`Observe`] | What the authority it wraps answers, shown to a callback first. |
//!
//! A world writes its own for anything else, such as a server that
//! answers one sandbox differently from the others.

use std::net::SocketAddr;
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::op::ResponseCode;
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, RecordType};
use fictionet::stdlib::protocols::dns::{EdeCode, Request, Response, label_count};

use super::exchange::{Client, Generation};
use super::lookup::{Looked, Lookup};
use super::zone::{Answered, ZoneData, answer};

mod copies;
mod engine;
mod observe;
mod overlay;
mod server;

pub use copies::Copies;
pub use engine::AuthorityEngine;
pub use observe::Observe;
pub use overlay::Overlay;
pub use server::{ChaosAnswer, ChaosReply, ChaosZone, Identity, ServerConfig, bare_reply, chaos};

/// What an authority does with one request, given what its zones hold
/// now.
#[derive(Clone, Debug, PartialEq)]
pub enum Step {
    /// Reply with this, after the server front gives it the header and
    /// EDNS details of [`ServerConfig`] and it is fitted to the client's
    /// size.
    Reply(Response),
    /// Look this up first, file what it gives, then ask the authority
    /// again.
    Need(Lookup),
    /// Send nothing, as a server that never replies.
    Silent,
}

/// What the server at `local` answers. World code: trusted, called
/// synchronously by the engine, so it must return quickly.
///
/// `respond` depends on its arguments and on what the authority's zones
/// hold. A request that needs a lookup it already made gets no reply from
/// the engine, since what that lookup gave did not settle the fact, so
/// each request ends within as many steps as it has distinct lookups.
pub trait Authority: Send + Sync + 'static {
    /// The step for `req`, which `client` sent to the server at `local`,
    /// whose front is `server`.
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        client: &Client,
    ) -> Step;

    /// Files what `lookup`, made in session `generation`, gave into the
    /// zone it names. An authority without learned zones files nothing.
    fn file(&self, lookup: &Lookup, looked: &Looked, generation: Generation) {
        let _ = (lookup, looked, generation);
    }

    /// Starts session `generation`, if it is newer than the one the
    /// authority's learned zones hold: what they learned before is
    /// dropped.
    fn advance(&self, generation: Generation) {
        let _ = generation;
    }
}

impl<A: Authority + ?Sized> Authority for Arc<A> {
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        client: &Client,
    ) -> Step {
        (**self).respond(req, local, server, client)
    }

    fn file(&self, lookup: &Lookup, looked: &Looked, generation: Generation) {
        (**self).file(lookup, looked, generation);
    }

    fn advance(&self, generation: Generation) {
        (**self).advance(generation);
    }
}

/// Answers from zones, as an authoritative server that hosts them.
///
/// The deepest zone whose apex is at or above QNAME answers, except that
/// a DS question at a zone's apex goes to the zone above it when that zone
/// is hosted too and holds the cut, since the parent holds DS (RFC 4035
/// §3.1.4.1). When that zone refers the question to a zone between them,
/// the zone at the apex answers NODATA. A view that does not know a fact
/// the reply needs never gives a negative: the server answers SERVFAIL.
/// A QNAME no hosted zone contains gets REFUSED, with Extended DNS Error
/// 20, Not Authoritative, when the front sends them (RFC 8914 §4.21).
/// Zone transfers are refused: zone data makes views for questions, not
/// listings of a whole zone. Zones hold class IN only: QCLASS * gets
/// FORMERR, as from BIND, and any other class REFUSED.
///
/// [`Copies`] answers the same way from learned zones, and looks up what
/// they do not know.
pub struct Zones {
    zones: Vec<Arc<dyn ZoneData>>,
}

impl Zones {
    /// A server for `zones`. At equal depth, the zone given last answers.
    pub fn new(zones: Vec<Arc<dyn ZoneData>>) -> Zones {
        Zones { zones }
    }
}

/// The deepest of `zones` that contains `qname`, or with
/// `strictly_above`, the deepest whose apex is not `qname`. At equal
/// depth, the zone given last.
fn deepest<'z>(
    zones: &'z [Arc<dyn ZoneData>],
    qname: &LowerName,
    strictly_above: bool,
) -> Option<&'z dyn ZoneData> {
    // `max_by_key` keeps the last of equal keys: the zone given last.
    zones
        .iter()
        .filter(|zone| zone.apex().zone_of(qname))
        .filter(|zone| !strictly_above || zone.apex() != qname)
        .max_by_key(|zone| label_count(zone.apex()))
        .map(|zone| &**zone)
}

/// What a server hosting `zones` does with `req`, with `server` as its
/// front, as [`Zones`] describes. `unknown` gives the step when a zone's
/// view does not know a fact the reply needs: it gets the zone and the
/// name the answer had reached, QNAME or the target of the last CNAME or
/// DNAME it followed (RFC 1034 §4.3.2 step 3a, RFC 6672 §3.2).
fn respond_from(
    zones: &[Arc<dyn ZoneData>],
    req: &Request,
    server: &ServerConfig,
    unknown: &dyn Fn(&dyn ZoneData, LowerName) -> Step,
) -> Step {
    let qname = LowerName::new(req.question.name());
    let qtype = req.question.query_type();
    if matches!(qtype, RecordType::AXFR | RecordType::IXFR) {
        return Step::Reply(bare_reply(req, ResponseCode::Refused, None));
    }
    match req.question.query_class() {
        DNSClass::IN => {}
        // A zone answers from its data with AA, and an answer to QCLASS
        // * can never be authoritative (RFC 1034 §3.7.1). BIND 9.20
        // answers FORMERR, as here.
        DNSClass::ANY => return Step::Reply(bare_reply(req, ResponseCode::FormErr, None)),
        // Zones hold class IN data only.
        _ => {
            let ede = server.ede.then_some(EdeCode::NOT_AUTHORITATIVE);
            return Step::Reply(bare_reply(req, ResponseCode::Refused, ede));
        }
    }
    let Some(zone) = deepest(zones, &qname, false) else {
        let ede = server.ede.then_some(EdeCode::NOT_AUTHORITATIVE);
        return Step::Reply(bare_reply(req, ResponseCode::Refused, ede));
    };
    let answer_from = |zone: &dyn ZoneData| match answer(&*zone.view(&req.question), req, server.any)
    {
        Answered::Response(response) => Step::Reply(response),
        Answered::Unknown { reached, .. } => unknown(zone, reached),
    };
    if qtype == RecordType::DS
        && zone.apex() == &qname
        && let Some(above) = deepest(zones, &qname, true)
    {
        // A zone above that refers the question on is not the parent,
        // so the zone itself answers NODATA from its apex (RFC 4035
        // §3.1.4.1), as BIND does.
        match answer_from(above) {
            Step::Reply(response) if is_referral(&response) => {}
            step => return step,
        }
    }
    answer_from(zone)
}

/// Whether `response` is a referral: NOERROR with AA clear, which a zone
/// gives only at a zone cut.
fn is_referral(response: &Response) -> bool {
    let metadata = &response.message.metadata;
    !metadata.authoritative && metadata.response_code == ResponseCode::NoError
}

impl Authority for Zones {
    fn respond(
        &self,
        req: &Request,
        _local: SocketAddr,
        server: &ServerConfig,
        _client: &Client,
    ) -> Step {
        respond_from(&self.zones, req, server, &|_, _| {
            Step::Reply(bare_reply(req, ResponseCode::ServFail, None))
        })
    }
}
