//! Invented zones on top of another authority, delegated to as a parent
//! would.

use std::net::{IpAddr, SocketAddr};

use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::op::{
    Edns, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData, Record, RecordType};
use fictionet::stdlib::protocols::dns::{Parsed, Request, Response};

use super::super::exchange::Client;
use super::server::glue_first;
use super::{Authority, Known, ServerConfig, Step, bare_reply};

/// Answers as its base does, except for zones invented below it.
///
/// An overlay sits on the servers of a zone's parent, such as a relay of
/// the `com` servers, with each invented zone, a child of that parent,
/// added by [`below`](Overlay::below). For a question at or below an invented
/// zone's apex:
///
/// - At one of the invented zone's own name servers (an address its apex
///   NS targets have in its glue), the zone's authority answers.
/// - Elsewhere the overlay answers as the parent: a referral composed from
///   the invented zone's apex NS RRset and glue, with AA clear. A DS
///   question at the apex goes to the base, since the parent's side
///   answers DS (RFC 4035 §3.1.4.1). Where the base says the apex does
///   not exist, the overlay answers NODATA with the same records instead,
///   as a parent answers for an unsigned delegation, so the parent never
///   both refers to the zone and denies it.
///
/// With DO, the referral needs the parent's word on the DS RRset
/// (RFC 4035 §3.1.4). The overlay asks its base the question
/// `<apex> DS` and puts the NSEC and NSEC3 records of that reply, with
/// their RRSIGs, into the referral's authority section. The records are
/// decoded from the base's reply and encoded again, never copied as
/// octets. The overlay does not judge them: a validator checks them for
/// this name. Under an opt-out NSEC3 parent, as `com`, `net`, and `org`
/// are, they prove the delegation insecure (RFC 5155 §8.9), so the
/// invented zone resolves as an unsigned zone. Under an NSEC parent, as
/// the root is, no record proves it, and validators call the delegation
/// bogus. The invented zone is never passed off as a signed one. When the
/// base stays silent for the DS question, so does the overlay.
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
        known: &dyn Known,
    ) -> Step {
        let qname = LowerName::new(req.question.name());
        let invented = self
            .zones
            .iter()
            .filter(|(apex, _)| apex.zone_of(&qname))
            .max_by_key(|(apex, _)| apex.num_labels());
        let Some((apex, inner)) = invented else {
            return self.base.respond(req, local, server, client, known);
        };
        let apex = Name::from(apex);

        let ns_question = question(req, &apex, RecordType::NS, false);
        let delegation = match decoded(inner.respond(&ns_question, local, server, client, known)) {
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
            .filter(|record| address(record).is_some() && targets.contains(&&record.name))
            .cloned()
            .collect();

        if glue
            .iter()
            .any(|record| address(record) == Some(local.ip()))
        {
            return inner.respond(req, local, server, client, known);
        }
        if *req.question.name() == apex && req.question.query_type() == RecordType::DS {
            let step = self.base.respond(req, local, server, client, known);
            return unsigned_delegation(req, step);
        }

        let mut authority = ns;
        if req.edns.is_some_and(|edns| edns.dnssec_ok) {
            let ds_question = question(req, &apex, RecordType::DS, true);
            match decoded(
                self.base
                    .respond(&ds_question, local, server, client, known),
            ) {
                Decoded::Message(reply) => authority.extend(denial(reply.authorities)),
                Decoded::Step(step) => return step,
            }
        }
        Step::Reply(referral(req, authority, glue))
    }
}

/// A step's reply as a message, or the step to return as it is.
enum Decoded {
    Message(Message),
    Step(Step),
}

/// The message in `step`'s reply. A step without one, or with octets that
/// do not decode, is what the overlay returns in its place.
fn decoded(step: Step) -> Decoded {
    match step {
        Step::Reply(response) => Decoded::Message(response.message),
        Step::Verbatim(bytes) => match Message::from_vec(&bytes) {
            Ok(message) => Decoded::Message(message),
            Err(_) => Decoded::Step(Step::Silent),
        },
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

/// The parent's answer to `<apex> DS`, `req`, given the base's `step`.
///
/// The base knows nothing of the invented zone, so it may deny that the
/// apex exists at all. A parent that delegates a name never says that:
/// for an unsigned delegation it answers NODATA, with its SOA and the
/// records that prove there is no DS (RFC 4035 §3.1.4.1, RFC 5155
/// §7.2.4). An NXDOMAIN from the base therefore goes out as NOERROR with
/// the same authority section, whose closest encloser proof and opt-out
/// span are what real `com` sends for an unsigned delegation. Any other
/// reply goes out as the base gave it.
fn unsigned_delegation(req: &Request, step: Step) -> Step {
    let reply = match &step {
        Step::Reply(response) => Some(response.message.clone()),
        Step::Verbatim(bytes) => Message::from_vec(bytes).ok(),
        Step::Need(_) | Step::Silent => None,
    };
    match reply {
        Some(reply) if reply.metadata.response_code == ResponseCode::NXDomain => {
            let mut response = bare_reply(req, ResponseCode::NoError, None);
            response.message.metadata.authoritative = reply.metadata.authoritative;
            response.message.authorities = reply.authorities;
            Step::Reply(response)
        }
        _ => step,
    }
}

/// The NSEC and NSEC3 records in `records`, with the RRSIGs that cover
/// them.
fn denial(records: Vec<Record>) -> impl Iterator<Item = Record> {
    records.into_iter().filter(|record| {
        let rtype = match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => rrsig.input().type_covered,
            _ => record.record_type(),
        };
        matches!(rtype, RecordType::NSEC | RecordType::NSEC3)
    })
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

/// The address in an A or AAAA record.
fn address(record: &Record) -> Option<IpAddr> {
    match &record.data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
        _ => None,
    }
}
