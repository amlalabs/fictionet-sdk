//! Rendering an answer for one client: its ID, flags, EDNS, question
//! case, AD and CD, Extended DNS Errors, and TTLs counted down.
//!
//! Nothing cached is replayed as a whole packet. Every answer is built
//! for the client that asked, from the pieces its resolution found.

use std::net::SocketAddr;
use std::time::Duration;

use fictionet::stdlib::protocols::dns::dnssec::Validation;
use fictionet::stdlib::protocols::dns::op::{Header, Message, ResponseCode};
use fictionet::stdlib::protocols::dns::read_message;
use fictionet::stdlib::protocols::dns::rr::{
    DNSClass, LowerName, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::serialize::binary::{BinDecodable, BinDecoder};
use fictionet::stdlib::protocols::dns::{Ede, EdeCode, Request, Response};
use fictionet::time::Instant;

use super::super::authority::bare_reply;
use super::super::event::{Event, ReplyFlags};
use super::super::exchange::Client;
use super::super::records::rrsets;
use super::cache::{Entry, Negative, ttl_left};
use super::resolution::{Outcome, is_dname, with_ttl};
use super::{Asker, Delegation, Piece, Resolver, worse};
use fictionet::stdlib::protocols::dns::dnssec::Verify;

impl<V: Verify> Resolver<V> {
    /// The octets of `response` for `request`, through the front:
    ///
    /// - The ID, opcode, RD, and CD are the query's (RFC 1035 §4.1.1,
    ///   RFC 4035 §3.2.2). RA is set, AA is clear, and Z is zero. TC is
    ///   set only when [`fit`](fictionet::stdlib::protocols::dns::fit) must.
    /// - The question is the query's, in its case, and so is every owner in
    ///   the answer equal to QNAME (RFC 4343 §4.1).
    /// - A query without OPT gets a reply without one (RFC 6891 §7). With
    ///   one, the reply's OPT has version 0, the resolver's payload, the
    ///   query's DO bit (RFC 3225 §3), and every other flag clear
    ///   (RFC 6891 §6.1.4). Options in the query are not echoed; NSID
    ///   goes only to a query that asks (RFC 5001 §2.1), and Extended DNS
    ///   Errors only when [`ede`](super::Config::ede) is on.
    pub(super) fn render_response(&self, request: &Request, response: Response) -> Vec<u8> {
        self.render_with(request, response, false, false)
    }

    /// [`render_response`](Resolver::render_response) with AD set when
    /// `authentic`, and AA kept as the response has it when `keep_aa`.
    fn render_with(
        &self,
        request: &Request,
        mut response: Response,
        authentic: bool,
        keep_aa: bool,
    ) -> Vec<u8> {
        let metadata = &mut response.message.metadata;
        metadata.authoritative &= keep_aa;
        metadata.authentic_data = authentic;
        self.server.render(request, response)
    }

    /// The octets of a local zone's `response`, which keeps its AA bit only
    /// when `keep_aa`, as the configuration says for that zone. Local data
    /// is never validated, so AD stays clear.
    pub(super) fn render_local(
        &self,
        request: &Request,
        response: Response,
        keep_aa: bool,
    ) -> Vec<u8> {
        self.render_with(request, response, false, keep_aa)
    }

    /// The answer of `asker` from its pieces, the validation of the whole,
    /// and whether it all came from the cache:
    ///
    /// - A failure gives SERVFAIL with its Extended DNS Error, and EDE 13,
    ///   Cached Error, when it came from the cache (RFC 9520 §3.2,
    ///   RFC 8914 §4.14). A failure never answers as a negative.
    /// - When the client did not set CD, Bogus gives SERVFAIL with the
    ///   validator's error, and Indeterminate SERVFAIL with EDE 5
    ///   (RFC 4035 §5.5). With CD set, the data goes out with AD clear
    ///   (RFC 4035 §3.2.2).
    /// - AD is set only for Secure answers to queries with DO or AD
    ///   (RFC 6840 §5.7, §5.8), never for answers not validated, and never
    ///   because a server said so.
    /// - The answer section holds each alias, after the DNAME it was
    ///   synthesized from, then the data, after the DNAME a CNAME asked
    ///   for was synthesized from. A negative's SOA goes in the
    ///   authority section with its TTL counted down (RFC 2308 §6); with
    ///   DO, so do the denial records, and the NSEC or NSEC3 records that
    ///   show a wildcard answer had no closer match (RFC 4035 §3.1.3.3).
    /// - A DNAME whose substitution would pass 255 octets gives YXDOMAIN
    ///   with the DNAME (RFC 6672 §2.2).
    /// - Without DO, RRSIG, NSEC, and NSEC3 records are left out unless
    ///   the question asks for their type (RFC 4035 §3.2.1).
    /// - Stale data carries the TTL of [`Stale::reply_ttl`](super::Stale::reply_ttl)
    ///   and EDE 3, or 19 for NXDOMAIN (RFC 8767 §4, RFC 8914 §4.4, §4.20).
    pub(super) fn render_pieces(&self, asker: &Asker) -> (Vec<u8>, Validation, bool) {
        let request = &asker.request;
        let pieces = &asker.pieces;
        let cached = !pieces.is_empty() && pieces.iter().all(|piece| piece.cached);
        let validation = pieces
            .iter()
            .map(Piece::validation)
            .fold(Validation::Secure, worse);
        let validation = if pieces.iter().any(|piece| !piece.checks.is_empty()) {
            validation
        } else {
            Validation::NotPerformed
        };

        if let Some(Piece {
            outcome: Outcome::Failure(why),
            cached,
            ..
        }) = pieces.last()
        {
            let mut edes = vec![why.ede()];
            if *cached {
                edes.push(EdeCode::CACHED_ERROR);
            }
            let reply = self.servfail(request, &edes);
            return (reply, Validation::NotPerformed, *cached);
        }
        if asker.validate && matches!(validation, Validation::Bogus(_) | Validation::Indeterminate)
        {
            let ede = validation.ede().into_iter().collect::<Vec<_>>();
            return (self.servfail(request, &ede), validation, cached);
        }

        let dnssec_ok = request.edns.is_some_and(|edns| edns.dnssec_ok);
        let qtype = request.question.query_type();
        let keep = |set: &RecordSet| {
            dnssec_ok
                || !matches!(
                    set.record_type(),
                    RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
                )
                || set.record_type() == qtype
        };
        let stale_ttl = self.config.serve_stale.map_or(0, |stale| {
            u32::try_from(stale.reply_ttl.as_secs()).unwrap_or(u32::MAX)
        });
        let max_ttl = u32::try_from(self.config.max_ttl.as_secs()).unwrap_or(u32::MAX);
        let query = &request.message.metadata;
        let mut message = Message::response(query.id, query.op_code);
        message.add_query(request.question.clone());
        let mut edes = Vec::new();
        for piece in pieces {
            // Fresh data has its TTL as the server sent it; the client sees
            // it within the cache's limit, counted down from when it
            // arrived, and, when it is Secure, no longer than the RRSIG
            // that verified it allows (RFC 4035 §5.3.3), as it would from
            // the cache.
            let secure = !piece.checks.is_empty() && piece.validation() == Validation::Secure;
            let ttl = |set: &RecordSet| {
                let ttl = if piece.stale {
                    stale_ttl
                } else {
                    let ttl = Duration::from_secs(u64::from(set.ttl().min(max_ttl)));
                    let mut expires = piece.at + ttl;
                    if secure && let Some(until) = self.secure_until(set, piece.at, &piece.verified)
                    {
                        expires = expires.min(until);
                    }
                    ttl_left(expires, self.now)
                };
                with_ttl(set, ttl)
            };
            // With DO, a wildcard answer carries the NSEC or NSEC3 records
            // that show no closer name matched (RFC 4035 §3.1.3.3), so a
            // validator downstream can check it too.
            let prove = |proof: &[RecordSet], message: &mut Message| {
                if dnssec_ok {
                    for set in proof.iter().filter(|set| !is_dname(set)) {
                        push_once(&mut message.authorities, &ttl(set), dnssec_ok);
                    }
                }
            };
            // A chain that passes one DNAME twice sends it once
            // (RFC 2181 §5).
            let dnames = |proof: &[RecordSet], message: &mut Message| {
                for set in proof.iter().filter(|set| is_dname(set)) {
                    push_once(&mut message.answers, &ttl(set), dnssec_ok);
                }
            };
            match &piece.outcome {
                Outcome::Alias { cname, proof, .. } => {
                    dnames(proof, &mut message);
                    push(&mut message.answers, &ttl(cname), dnssec_ok);
                    prove(proof, &mut message);
                }
                Outcome::Data { sets, proof, .. } => {
                    dnames(proof, &mut message);
                    for set in sets.iter().filter(|set| keep(set)) {
                        push(&mut message.answers, &ttl(set), dnssec_ok);
                    }
                    prove(proof, &mut message);
                }
                Outcome::TooLong { dname, .. } => {
                    message.metadata.response_code = ResponseCode::YXDomain;
                    push(&mut message.answers, &ttl(dname), dnssec_ok);
                }
                Outcome::Negative {
                    kind, soa, denial, ..
                } => {
                    if *kind == Negative::NxDomain {
                        message.metadata.response_code = ResponseCode::NXDomain;
                    }
                    for set in soa.iter() {
                        push(&mut message.authorities, &ttl(set), dnssec_ok);
                    }
                    // A wildcard alias before it may have carried some of
                    // the same records.
                    if dnssec_ok {
                        for set in denial {
                            push_once(&mut message.authorities, &ttl(set), dnssec_ok);
                        }
                    }
                }
                Outcome::Failure(_) => {}
            }
            if piece.stale {
                let ede = match piece.outcome {
                    Outcome::Negative {
                        kind: Negative::NxDomain,
                        ..
                    } => EdeCode::STALE_NXDOMAIN_ANSWER,
                    _ => EdeCode::STALE_ANSWER,
                };
                // An alias and its target served stale are one stale
                // answer.
                if !edes.contains(&ede) {
                    edes.push(ede);
                }
            }
        }
        edes.extend(validation.ede());
        set_edes(&mut message, &edes);
        let authentic = validation == Validation::Secure && (dnssec_ok || request.ad);
        let response = Response {
            message,
            required_additional: 0,
        };
        (
            self.render_with(request, response, authentic, false),
            validation,
            cached,
        )
    }

    /// A referral for `request`, whose RD was clear, through the aliases
    /// in `pieces`: those aliases in the answer section (RFC 1034 §4.3.2
    /// step 3a), then `delegation`. A local zone's referral goes out with
    /// its authority and additional sections as the zone gave them
    /// (step 3b). A referral from the cache for a name it could follow
    /// no further holds the deepest NS RRset the cache holds at or above
    /// the name, and the cached addresses of its targets (step 4); with
    /// no NS RRset, SERVFAIL.
    pub(super) fn render_referral(
        &self,
        request: &Request,
        pieces: &[Piece],
        delegation: Delegation,
    ) -> Vec<u8> {
        let query = &request.message.metadata;
        let mut message = Message::response(query.id, query.op_code);
        message.add_query(request.question.clone());
        let dnssec_ok = request.edns.is_some_and(|edns| edns.dnssec_ok);
        let max_ttl = u32::try_from(self.config.max_ttl.as_secs()).unwrap_or(u32::MAX);
        for piece in pieces {
            let Outcome::Alias { cname, proof, .. } = &piece.outcome else {
                continue;
            };
            let ttl = |set: &RecordSet| {
                let ttl = Duration::from_secs(u64::from(set.ttl().min(max_ttl)));
                with_ttl(set, ttl_left(piece.at + ttl, self.now))
            };
            for dname in proof.iter().filter(|set| is_dname(set)) {
                push_once(&mut message.answers, &ttl(dname), dnssec_ok);
            }
            push(&mut message.answers, &ttl(cname), dnssec_ok);
        }
        let name = match delegation {
            Delegation::Local(referral) => {
                message.authorities.extend(referral.message.authorities);
                message.additionals.extend(referral.message.additionals);
                let response = Response {
                    message,
                    required_additional: referral.required_additional,
                };
                return self.render_with(request, response, false, false);
            }
            Delegation::Cached(name) => name,
        };
        let mut at = name;
        let ns = loop {
            let key = super::Key::new(at.clone(), RecordType::NS, DNSClass::IN);
            if let Some(Entry::Positive { set, expires, .. }) = self.cache.data(&key, self.now) {
                break Some((set.clone(), *expires));
            }
            if at.is_root() {
                break None;
            }
            at = at.base_name();
        };
        let Some((ns, expires)) = ns else {
            return self.servfail(request, &[]);
        };
        push(
            &mut message.authorities,
            &with_ttl(&ns, ttl_left(expires, self.now)),
            dnssec_ok,
        );
        let mut required = 0;
        for record in ns.records_without_rrsigs() {
            let RData::NS(target) = &record.data else {
                continue;
            };
            for rtype in [RecordType::A, RecordType::AAAA] {
                let key = super::Key::new(LowerName::new(&target.0), rtype, DNSClass::IN);
                if let Some(Entry::Positive { set, expires, .. }) = self.cache.data(&key, self.now)
                {
                    push(
                        &mut message.additionals,
                        &with_ttl(set, ttl_left(*expires, self.now)),
                        false,
                    );
                    required += 1;
                }
            }
        }
        let response = Response {
            message,
            required_additional: required,
        };
        self.render_with(request, response, false, false)
    }

    /// SERVFAIL for `request`, with `edes`.
    fn servfail(&self, request: &Request, edes: &[EdeCode]) -> Vec<u8> {
        let mut reply = bare_reply(request, ResponseCode::ServFail, None);
        set_edes(&mut reply.message, edes);
        self.render_response(request, reply)
    }
}

/// Appends `set`'s records to `section`, with its RRSIGs when `dnssec_ok`.
fn push(section: &mut Vec<Record>, set: &RecordSet, dnssec_ok: bool) {
    section.extend(set.records_without_rrsigs().cloned());
    if dnssec_ok {
        section.extend(set.rrsigs().iter().cloned());
    }
}

/// [`push`], unless `section` already holds records of `set`'s owner and
/// type, as when two aliases of one chain carry the same proof.
fn push_once(section: &mut Vec<Record>, set: &RecordSet, dnssec_ok: bool) {
    let held = section
        .iter()
        .any(|record| record.name == *set.name() && record.record_type() == set.record_type());
    if !held {
        push(section, set, dnssec_ok);
    }
}

/// Puts `edes` in `message`'s OPT record, one option each. The front
/// keeps them only for clients that sent OPT, and only when the resolver
/// sends Extended DNS Errors.
fn set_edes(message: &mut Message, edes: &[EdeCode]) {
    if edes.is_empty() {
        return;
    }
    let mut edns = message.edns.take().unwrap_or_default();
    for code in edes {
        edns.options_mut().insert(Ede::new(*code).to_option());
    }
    message.set_edns(edns);
}

/// The event for a reply of `bytes` sent to `client`.
pub(super) fn reply_event(
    at: Instant,
    client: Client,
    bytes: &[u8],
    validation: Validation,
    cached: bool,
) -> Event {
    let server: SocketAddr = client.local;
    let size = u16::try_from(bytes.len()).expect("a reply fits a DNS message's 65535 octets");
    let (question, rcode, flags, answers, ede) = match read_message(bytes) {
        Ok(message) => {
            let ede = message.edns.as_ref().and_then(|edns| {
                edns.options()
                    .as_ref()
                    .iter()
                    .find_map(|(_, option)| Ede::from_option(option))
                    .map(|ede| ede.code)
            });
            (
                message.queries.first().cloned(),
                message.metadata.response_code,
                ReplyFlags::of(&message.metadata),
                rrsets(&message.answers),
                ede,
            )
        }
        Err(_) => {
            let header = Header::read(&mut BinDecoder::new(bytes))
                .expect("every reply the engine sends has a header");
            (
                None,
                header.metadata.response_code,
                ReplyFlags::of(&header.metadata),
                Vec::new(),
                None,
            )
        }
    };
    Event::Reply {
        at,
        server,
        client,
        question,
        rcode,
        flags,
        answers,
        validation,
        ede,
        cached,
        size,
    }
}
