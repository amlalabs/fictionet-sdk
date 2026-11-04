//! Invented zones on top of another authority, delegated to as a parent
//! would.

use std::net::SocketAddr;

use fictionet::stdlib::protocols::dns::dnssec::proof::delegation_proof;
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::label_count;
use fictionet::stdlib::protocols::dns::op::{
    Edns, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, Name, RData, Record, RecordType};
use fictionet::stdlib::protocols::dns::{Parsed, Request, Response};

use super::super::exchange::{Client, Generation};
use super::super::lookup::{Looked, Lookup};
use super::super::records::rrsets;
use super::server::glue_first;
use super::{Authority, ServerConfig, Step, bare_reply, refuse_transfer};

/// Answers as its base does, except for zones invented below it.
///
/// An overlay sits on the servers of a zone's parent, such as the `com`
/// servers of a world that learns `com` from the real ones
/// ([`Learned`](super::super::zone::Learned)), with each invented zone, a
/// child of that parent,
/// added by [`below`](Overlay::below). A zone transfer gets REFUSED, and a
/// question in a class other than IN gets what the base gives it. For a
/// question at or below an invented zone's apex:
///
/// - At one of the invented zone's own name servers (an address its apex
///   NS targets have in its glue), the zone's authority answers.
/// - At a server that does not serve the parent, the overlay answers as
///   its base does, since only the parent's servers refer to a child
///   (RFC 1034 §4.2.1). The base serves the parent where its reply to
///   `<apex> DS` has AA set and carries the parent's SOA or the DS
///   RRset. So an overlay may wrap every server a mirror places, and
///   the root still refers only to the parent. When the base needs a
///   lookup for that question, the overlay needs it too; when the base
///   stays silent, so does the overlay.
/// - Elsewhere the overlay answers as the parent: a referral composed from
///   the invented zone's apex NS RRset and glue, with AA clear. When the
///   invented zone gives no address for a name server at or below its
///   apex, the referral could not be followed (RFC 9471 §3.1), so the
///   overlay answers SERVFAIL in its place. A DS
///   question at the apex goes to the base, since the parent's side
///   answers DS (RFC 4035 §3.1.4.1). Where the base says the apex does
///   not exist, the overlay answers NODATA with the same records instead,
///   as a parent answers for an unsigned delegation, so the parent never
///   both refers to the zone and denies it.
///
/// With DO, the referral needs the parent's word on the DS RRset
/// (RFC 4035 §3.1.4), the same word the base gives `<apex> DS`. When the
/// base's reply to `<apex> DS` has the DS RRset, as the real parent of a
/// signed domain that an invented zone stands in for does, the referral
/// carries it with its RRSIGs. Otherwise the overlay puts the NSEC and
/// NSEC3 records of that reply that speak to a delegation at the apex,
/// with their RRSIGs, into the referral's authority section, leaving out
/// a record that shows only that no wildcard matched, which a parent
/// never sends with a delegation (RFC 5155 §7.2.7). The base's reply
/// carries the denial its zone holds for the apex
/// ([`View::denial`](super::super::zone::View::denial)), such as the
/// NSEC3 records a learned zone copied from the real parent with their
/// RRSIGs. The overlay does not judge them: a validator checks them for
/// this name. Under an opt-out NSEC3 parent, as `com`, `net`, and `org`
/// are, they prove the delegation insecure (RFC 5155 §8.9), so the
/// invented zone resolves as an unsigned zone. Under an NSEC parent, as
/// the root is, no record proves it, and validators call the delegation
/// bogus. Where the parent has a DS RRset, validators call it bogus too,
/// since the invented zone has no key the DS names. The invented zone is
/// never passed off as a signed one.
pub struct Overlay<B: Authority> {
    base: B,
    /// The zone the base serves, whose children the overlay invents.
    zone: LowerName,
    zones: Vec<(LowerName, Box<dyn Authority>)>,
}

impl<B: Authority> Overlay<B> {
    /// `base`, the servers of `zone`, with no zones invented below it yet.
    pub fn new(base: B, zone: Name) -> Overlay<B> {
        Overlay {
            base,
            zone: LowerName::new(&zone),
            zones: Vec::new(),
        }
    }

    /// This overlay with the zone at `apex` answered by `inner`, whose
    /// replies to `<apex> NS` give the zone's name servers and their glue.
    ///
    /// # Panics
    ///
    /// If `apex` is not a child of the overlay's zone. The names between
    /// the zone and a deeper apex are the base's, which may deny them or
    /// refer them elsewhere while the overlay refers names below them.
    /// The parent would then deny a name and answer for names under it,
    /// which RFC 8020 §2 rules out, and a resolver that minimises its
    /// questions would never reach the invented zone.
    pub fn below(mut self, apex: Name, inner: impl Authority) -> Overlay<B> {
        let apex = LowerName::new(&apex);
        assert!(
            !apex.is_root() && apex.base_name() == self.zone,
            "an invented zone at {apex} is not a child of {}",
            self.zone
        );
        self.zones.push((apex, Box::new(inner)));
        self
    }
}

impl<B: Authority> Authority for Overlay<B> {
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        client: &Client,
    ) -> Step {
        if let Some(refused) = refuse_transfer(req) {
            return refused;
        }
        // Invented zones hold class IN data only, and an answer to QCLASS
        // * can never be authoritative (RFC 1034 §3.7.1), so the server
        // answers any other class for every name as its base does.
        if req.question.query_class() != DNSClass::IN {
            return self.base.respond(req, local, server, client);
        }
        let qname = LowerName::new(req.question.name());
        let invented = self
            .zones
            .iter()
            .filter(|(apex, _)| apex.zone_of(&qname))
            .max_by_key(|(apex, _)| label_count(apex));
        let Some((apex, inner)) = invented else {
            return self.base.respond(req, local, server, client);
        };
        let apex = Name::from(apex);

        let ns_question = question(req, &apex, RecordType::NS, false);
        let delegation = match decoded(inner.respond(&ns_question, local, server, client)) {
            Decoded::Message(message) => message,
            Decoded::Step(step) => return step,
        };
        let ns: Vec<Record> = delegation
            .answers
            .iter()
            .filter(|record| record.name == apex && record.record_type() == RecordType::NS)
            .cloned()
            .collect();
        if ns.is_empty() {
            return Step::Reply(bare_reply(req, ResponseCode::ServFail, None));
        }
        let targets: Vec<&Name> = ns
            .iter()
            .filter_map(|record| match &record.data {
                RData::NS(target) => Some(&target.0),
                _ => None,
            })
            .collect();
        let glue: Vec<Record> = delegation
            .additionals
            .iter()
            .filter(|record| record.data.ip_addr().is_some() && targets.contains(&&record.name))
            .cloned()
            .collect();
        if glue
            .iter()
            .any(|record| record.data.ip_addr() == Some(local.ip()))
        {
            return inner.respond(req, local, server, client);
        }
        let zone = Name::from(&self.zone);
        if *req.question.name() == apex && req.question.query_type() == RecordType::DS {
            let step = self.base.respond(req, local, server, client);
            return unsigned_delegation(req, &apex, &zone, step);
        }
        // Only the parent's servers refer to a child (RFC 1034 §4.2.1).
        // Anywhere else, such as at a root server or a server of another
        // zone, the overlay answers as its base does.
        let ds_question = question(req, &apex, RecordType::DS, true);
        let parent = match decoded(self.base.respond(&ds_question, local, server, client)) {
            Decoded::Message(reply) => reply,
            Decoded::Step(step) => return step,
        };
        if !serves(&parent, &apex, &zone) {
            return self.base.respond(req, local, server, client);
        }

        // A referral without the glue for a name server at or below the
        // apex cannot be followed (RFC 9471 §3.1). The inner zone leaves
        // out the addresses of a target it does not know.
        let unglued = targets.iter().any(|target| {
            apex.zone_of(target) && !glue.iter().any(|record| record.name == **target)
        });
        if unglued {
            return Step::Reply(bare_reply(req, ResponseCode::ServFail, None));
        }

        let mut authority = ns;
        if req.edns.is_some_and(|edns| edns.dnssec_ok) {
            let ds: Vec<Record> = parent
                .answers
                .iter()
                .filter(|record| record.name == apex && covered(record) == RecordType::DS)
                .cloned()
                .collect();
            if ds.is_empty() {
                authority.extend(denial(&apex, &zone, &parent.authorities));
            } else {
                authority.extend(ds);
            }
        }
        Step::Reply(referral(req, authority, glue))
    }

    fn file(&self, lookup: &Lookup, looked: &Looked, generation: Generation) {
        self.base.file(lookup, looked, generation);
        for (_, inner) in &self.zones {
            inner.file(lookup, looked, generation);
        }
    }

    fn advance(&self, generation: Generation) {
        self.base.advance(generation);
        for (_, inner) in &self.zones {
            inner.advance(generation);
        }
    }
}

/// A step's reply as a message, or the step to return as it is.
enum Decoded {
    Message(Message),
    Step(Step),
}

/// The message in `step`'s reply. A step without one is what the overlay
/// returns in its place.
fn decoded(step: Step) -> Decoded {
    match step {
        Step::Reply(response) => Decoded::Message(response.message),
        step @ (Step::Need(_) | Step::Silent) => Decoded::Step(step),
    }
}

/// The question `<name> <rtype>` as a request with `req`'s ID and
/// transport, recursion not desired, and with EDNS and DO when
/// `dnssec_ok`.
fn question(req: &Request, name: &Name, rtype: RecordType, dnssec_ok: bool) -> Request {
    let mut message = Message::new(req.message.metadata.id, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(name.clone(), rtype));
    if dnssec_ok {
        let mut edns = Edns::new();
        edns.set_max_payload(1232).set_dnssec_ok(true);
        message.set_edns(edns);
    }
    let bytes = message
        .to_vec()
        .expect("a query with one question and an OPT record writes");
    match Request::parse(&bytes, req.transport) {
        Parsed::Request(request) => request,
        _ => unreachable!("a QUERY for NS or DS with one question passes every check"),
    }
}

/// The answer to `<apex> DS`, `req`, given the base's `step`, where the
/// base may serve `zone`, the parent.
///
/// The base knows nothing of the invented zone, so it may deny that the
/// apex exists at all. A parent that delegates a name never says that:
/// for an unsigned delegation it answers NODATA, with its SOA and the
/// records that prove there is no DS (RFC 4035 §3.1.4.1, RFC 5155
/// §7.2.4). An NXDOMAIN from a server of the parent, with AA and the
/// parent's SOA, therefore goes out as NOERROR with
/// its SOA and the part of its denial that such a proof needs: under an
/// opt-out NSEC3 parent, the closest encloser's NSEC3 and the opt-out
/// span over the apex, as real `com` sends for an unsigned delegation,
/// without the NXDOMAIN's proof that no wildcard matched. Any other reply
/// goes out as the base gave it.
fn unsigned_delegation(req: &Request, apex: &Name, zone: &Name, step: Step) -> Step {
    let reply = match &step {
        Step::Reply(response) => Some(response.message.clone()),
        Step::Need(_) | Step::Silent => None,
    };
    match reply {
        Some(reply)
            if reply.metadata.response_code == ResponseCode::NXDomain
                && serves(&reply, apex, zone) =>
        {
            let mut response = bare_reply(req, ResponseCode::NoError, None);
            response.message.metadata.authoritative = reply.metadata.authoritative;
            let soa = reply
                .authorities
                .iter()
                .filter(|record| covered(record) == RecordType::SOA)
                .cloned();
            let proof = denial(apex, zone, &reply.authorities);
            response.message.authorities = soa.chain(proof).collect();
            Step::Reply(response)
        }
        _ => step,
    }
}

/// Whether `reply`, the base's reply to `<apex> DS`, comes from a server
/// of `zone`, the parent: it has AA set, and gives the DS RRset or the
/// zone's SOA.
fn serves(reply: &Message, apex: &Name, zone: &Name) -> bool {
    let ds = reply
        .answers
        .iter()
        .any(|record| record.name == *apex && record.record_type() == RecordType::DS);
    let soa = reply
        .authorities
        .iter()
        .any(|record| record.name == *zone && record.record_type() == RecordType::SOA);
    reply.metadata.authoritative && (ds || soa)
}

/// The records of `authority`, the base's reply to `<apex> DS`, that a
/// parent serving `zone` sends to show a delegation at `apex` has no DS
/// ([`delegation_proof`]), with the RRSIGs that cover them.
fn denial(apex: &Name, zone: &Name, authority: &[Record]) -> Vec<Record> {
    let sets = rrsets(authority);
    let kept = delegation_proof(apex, zone, &sets);
    authority
        .iter()
        .filter(|record| {
            kept.iter()
                .any(|set| set.name() == &record.name && set.record_type() == covered(record))
        })
        .cloned()
        .collect()
}

/// The type `record` belongs to: the type it covers for an RRSIG, its own
/// otherwise.
fn covered(record: &Record) -> RecordType {
    match &record.data {
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => rrsig.input().type_covered,
        _ => record.record_type(),
    }
}

/// A referral to the zone at `apex`: `authority` and the glue, the glue at
/// or below the apex required (RFC 9471 §3.1), with AA clear.
fn referral(req: &Request, authority: Vec<Record>, glue: Vec<Record>) -> Response {
    let mut message = bare_reply(req, ResponseCode::NoError, None).message;
    message.authorities = authority;
    message.additionals = glue;
    let required_additional = glue_first(&mut message);
    Response {
        message,
        required_additional,
    }
}
