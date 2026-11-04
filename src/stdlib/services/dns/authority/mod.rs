//! Authoritative servers: what a server at an address answers, and the
//! engine that runs one.
//!
//! An [`Authority`] is world code that decides a server's reply to one
//! request. An authority whose zone data comes from real servers may
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
//! | [`Overlay`] | What its base answers, except for invented zones below it. |
//! | [`Observe`] | What the authority it wraps answers, shown to a callback first. |
//!
//! A world writes its own for anything else, such as a server that
//! answers one sandbox differently from the others. [`respond_from_zones`]
//! gives such an authority the answer of [`Zones`] over its own zone
//! data, with the step it takes for a fact the data does not know, and
//! [`refuse_transfer`] the refusal of zone transfers. The copies of real
//! servers in `fictionet-extras` (`fictionet_extras::dns::copies`) are
//! built that way.

use std::net::SocketAddr;
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::op::{Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, Name, RecordType};
use fictionet::stdlib::protocols::dns::{EdeCode, Request, Response, label_count};

use super::exchange::{Client, Generation};
use super::lookup::{Looked, Lookup};
use super::zone::{Answered, ZoneData, answer_onward};

mod engine;
mod observe;
mod overlay;
mod server;

pub use engine::AuthorityEngine;
pub use observe::Observe;
pub use overlay::Overlay;
pub use server::{ChaosZone, Identity, ServerConfig, bare_reply};

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
/// the zone at the apex answers NODATA. A CNAME or DNAME chain that
/// leaves its zone, reaches a cut, or reaches a name a hosted zone below
/// its zone holds goes on in the deepest hosted zone that holds the name,
/// and the reply carries the whole chain and
/// the data it leads to, as step 1 searches every zone the server has
/// (RFC 1034 §4.3.2 step 3a). A view that does not know a fact
/// the reply needs never gives a negative: the server answers SERVFAIL.
/// A QNAME no hosted zone contains gets REFUSED, with Extended DNS Error
/// 20, Not Authoritative, when the front sends them (RFC 8914 §4.21).
/// Zone transfers are refused: zone data makes views for questions, not
/// listings of a whole zone. Zones hold class IN only: QCLASS * gets
/// FORMERR, as from BIND, and any other class REFUSED.
///
/// [`respond_from_zones`] answers the same way for an authority that
/// takes its own step when a view does not know a fact.
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

/// REFUSED when `req` asks for a zone transfer, before an authority looks
/// at anything else; `None` for any other question. A transfer lists a
/// zone, and the authorities here list none; a referral, a lookup, or a
/// parent's answer in place of one is no listing (RFC 5936 §2.2).
pub fn refuse_transfer(req: &Request) -> Option<Step> {
    matches!(
        req.question.query_type(),
        RecordType::AXFR | RecordType::IXFR
    )
    .then(|| Step::Reply(bare_reply(req, ResponseCode::Refused, None)))
}

/// The step [`respond_from_zones`] takes when a zone's view does not know
/// a fact the reply needs. It is called with the zone, the question asked
/// in that zone, and the name the answer had reached: that question's
/// name, or the target of the last CNAME or DNAME it followed (RFC 1034
/// §4.3.2 step 3a, RFC 6672 §3.2).
pub type OnUnknown<'a> = &'a dyn Fn(&dyn ZoneData, &Query, LowerName) -> Step;

/// What a server hosting `zones` does with `req`, with `server` as its
/// front, as [`Zones`] describes: the authoritative answer of RFC 1034
/// §4.3.2 over every zone it hosts, with CNAME and DNAME chains that go
/// on in the other hosted zones, and DS at a zone's apex asked of the
/// zone above it first (RFC 4035 §3.1.4.1). Where a zone's view does not
/// know a fact the reply needs, the step is what `unknown` gives: [`Zones`]
/// answers SERVFAIL there, and an authority that learns its data may
/// return [`Step::Need`].
pub fn respond_from_zones(
    zones: &[Arc<dyn ZoneData>],
    req: &Request,
    server: &ServerConfig,
    unknown: OnUnknown<'_>,
) -> Step {
    if let Some(refused) = refuse_transfer(req) {
        return refused;
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
    let qname = LowerName::new(req.question.name());
    let Some(zone) = deepest(zones, &qname, false) else {
        let ede = server.ede.then_some(EdeCode::NOT_AUTHORITATIVE);
        return Step::Reply(bare_reply(req, ResponseCode::Refused, ede));
    };
    respond_hosted(zones, zone, req, server, unknown, &mut vec![qname])
}

/// The reply to `req` from `zone`, the deepest of `zones` that holds its
/// QNAME. Where a CNAME or DNAME chain goes past that zone, to a name
/// another hosted zone holds, the answer goes on in that zone, as step 1
/// searches every zone the server has (RFC 1034 §4.3.2 step 3a). `seen`
/// holds the names the chain went on at: one it reaches again is a loop,
/// answered SERVFAIL with the chain (RFC 1034 §3.6.2).
fn respond_hosted(
    zones: &[Arc<dyn ZoneData>],
    zone: &dyn ZoneData,
    req: &Request,
    server: &ServerConfig,
    unknown: OnUnknown<'_>,
    seen: &mut Vec<LowerName>,
) -> Step {
    let qname = LowerName::new(req.question.name());
    let qtype = req.question.query_type();
    let hosted: Vec<LowerName> = zones.iter().map(|zone| zone.apex().clone()).collect();
    let answer_from = |zone: &dyn ZoneData, seen: &mut Vec<LowerName>| match answer_onward(
        &*zone.view(&req.question),
        req,
        server.any,
        &hosted,
    ) {
        (Answered::Response(response), Some(onward)) => {
            let hosted =
                deepest(zones, &onward.target, false).filter(|next| next.apex() != zone.apex());
            let Some(next_zone) = hosted else {
                return Step::Reply(response);
            };
            if seen.contains(&onward.target) {
                // The chain came back to a name it passed: a loop, which
                // is an error (RFC 1034 §3.6.2). The chain goes with the
                // proofs of its wildcard expansions (RFC 4035 §3.1.3.3).
                let mut looped = onward.chain;
                looped.message.metadata.response_code = ResponseCode::ServFail;
                return Step::Reply(looped);
            }
            seen.push(onward.target.clone());
            let mut next = req.clone();
            next.question.set_name(Name::from(&onward.target));
            match respond_hosted(zones, next_zone, &next, server, unknown, seen) {
                Step::Reply(rest) => Step::Reply(joined(onward.chain, rest)),
                step => step,
            }
        }
        (Answered::Response(response), None) => Step::Reply(response),
        (Answered::Unknown { reached, .. }, _) => unknown(zone, &req.question, reached),
    };
    if qtype == RecordType::DS
        && zone.apex() == &qname
        && let Some(above) = deepest(zones, &qname, true)
    {
        // A zone above that refers the question on is not the parent,
        // so the zone itself answers NODATA from its apex (RFC 4035
        // §3.1.4.1), as BIND does.
        match answer_from(above, seen) {
            Step::Reply(response) if is_referral(&response) => {}
            step => return step,
        }
    }
    answer_from(zone, seen)
}

/// `chain`, the reply that holds a CNAME and DNAME chain up to the name
/// it went past its zone at, followed by `rest`, the reply for that name
/// from the zone that holds it: the chain's answers, then the rest's, the
/// chain's denial records beside the rest's authority section, and the
/// rest's additional section and RCODE (RFC 6604 §2). The header and the
/// question are the chain's, which is the client's, and AA stays set,
/// since the first answer is authoritative (RFC 1035 §4.1.1).
fn joined(chain: Response, rest: Response) -> Response {
    let mut message = chain.message;
    let rest_message = rest.message;
    message.metadata.response_code = rest_message.metadata.response_code;
    for record in rest_message.answers {
        if !message.answers.contains(&record) {
            message.answers.push(record);
        }
    }
    let proofs = std::mem::replace(&mut message.authorities, rest_message.authorities);
    for record in proofs {
        if !message.authorities.contains(&record) {
            message.authorities.push(record);
        }
    }
    message.additionals = rest_message.additionals;
    Response {
        message,
        required_additional: rest.required_additional,
    }
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
        respond_from_zones(&self.zones, req, server, &|_, _, _| {
            Step::Reply(bare_reply(req, ResponseCode::ServFail, None))
        })
    }
}
