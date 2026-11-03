//! The server front: the header and EDNS details an authoritative server
//! puts on every reply, its answers to CHAOS-class questions, and its
//! payload size.

use std::collections::BTreeMap;
use std::time::Duration;

use fictionet::stdlib::protocols::dns::op::{Edns, Message, MessageType, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::rdata::{NS, SOA, TXT};
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, Name, RData, Record, RecordType};
use fictionet::stdlib::protocols::dns::{
    Ede, EdeCode, Fitted, Limit, Nsid, Request, Response, fit,
};
use fictionet::stdlib::services::serve::Transport;

use super::super::zone::AnyResponse;

/// How an authoritative server presents its replies.
///
/// The server has no DNS cookies (RFC 7873): a COOKIE option in a query
/// is ignored like any option the server does not know (RFC 6891
/// §6.1.2), as the root servers and the large public resolvers do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    /// What the server says about itself: its CHAOS answers and its NSID,
    /// which come from this one source so that they describe the same
    /// instance.
    pub identity: Identity,
    /// The largest UDP reply the server sends and advertises
    /// (RFC 6891 §6.2.5).
    pub payload: u16,
    /// Whether replies carry Extended DNS Errors (RFC 8914).
    pub ede: bool,
    /// What the server sends for QTYPE ANY (RFC 8482 §4).
    pub any: AnyResponse,
    /// How long the server waits for a lookup before it counts the
    /// lookup as unanswered.
    pub ask_timeout: Duration,
    /// Whether the server offers recursion. Its replies then set RA
    /// (RFC 1035 §4.1.1) and keep the AD bit the engine behind it gave, as
    /// a validating resolver's do (RFC 4035 §3.2.3). An authoritative
    /// server's replies clear both.
    pub recursion_available: bool,
}

impl ServerConfig {
    /// An ordinary authoritative server: a 1232-octet payload, the size
    /// the DNS Flag Day 2020 settled on; Extended DNS Errors; the
    /// synthesized HINFO answer to ANY of RFC 8482 §4.2; and an identity
    /// with no names and no NSID. A world that plays a particular server
    /// writes its values over this one.
    pub fn generic() -> ServerConfig {
        ServerConfig {
            identity: Identity::none(),
            payload: 1232,
            ede: true,
            any: AnyResponse::Hinfo,
            ask_timeout: ASK_TIMEOUT,
            recursion_available: false,
        }
    }

    /// `response` with the header and EDNS details of this server, for
    /// `req`:
    ///
    /// - The ID, opcode, RD, and CD are the query's. RA and AD follow
    ///   [`recursion_available`](ServerConfig::recursion_available). TC is
    ///   clear, and [`fit`] sets TC when it must. AA is the authority's.
    /// - The question is the query's, in the query's case, and every owner
    ///   in the answer section equal to QNAME takes that case
    ///   (RFC 4343 §4.1).
    /// - A query without an OPT record gets a reply without one
    ///   (RFC 6891 §7). Otherwise the reply's OPT has version 0, this
    ///   server's payload, the query's DO bit (RFC 3225 §3), and every
    ///   other flag clear, whatever unknown flags the query set
    ///   (RFC 6891 §6.1.4).
    /// - Options from the query are never echoed (RFC 6891 §6.1.2). The
    ///   reply carries the server's NSID only when the query asked for it
    ///   (RFC 5001 §2.1), and the authority's own options but an NSID,
    ///   Extended DNS Errors only when [`ede`](ServerConfig::ede) is on.
    ///   The NSID is the [`identity`](ServerConfig::identity)'s.
    pub fn front(&self, req: &Request, response: Response) -> Response {
        let Response {
            mut message,
            required_additional,
        } = response;
        let query = &req.message.metadata;
        let metadata = &mut message.metadata;
        metadata.id = query.id;
        metadata.message_type = MessageType::Response;
        metadata.op_code = query.op_code;
        metadata.recursion_desired = req.rd;
        metadata.checking_disabled = req.cd;
        metadata.recursion_available = self.recursion_available;
        metadata.authentic_data &= self.recursion_available;
        metadata.truncation = false;

        let qname = req.question.name();
        message.queries = vec![req.question.clone()];
        for record in &mut message.answers {
            if record.name == *qname {
                record.name = qname.clone();
            }
        }

        let authority = message.edns.take();
        message.edns = req.edns.map(|asked| {
            let mut edns = Edns::new();
            edns.set_max_payload(self.payload.max(512))
                .set_dnssec_ok(asked.dnssec_ok);
            let own = authority.iter().flat_map(|edns| edns.options().as_ref());
            for (_, option) in own {
                let ede = Ede::from_option(option).is_some();
                let nsid = Nsid::from_option(option).is_some();
                if !nsid && (self.ede || !ede) {
                    edns.options_mut().insert(option.clone());
                }
            }
            if let (true, Some(nsid)) = (asked.nsid, &self.identity.nsid) {
                edns.options_mut().insert(Nsid(nsid.clone()).to_option());
            }
            edns
        });
        Response {
            message,
            required_additional,
        }
    }

    /// The octets of the reply to a CHAOS-class question, from
    /// [`identity`](ServerConfig::identity) alone ([`Identity::reply`]),
    /// through the front and fitted to the client's size, with the
    /// identity's payload and OPT record.
    pub(in super::super) fn render_chaos(&self, req: &Request) -> Vec<u8> {
        let identity = &self.identity;
        let (response, edns) = identity.reply(req);
        let mut response = self.front(req, response);
        if !edns {
            response.message.edns = None;
        }
        let payload = identity.payload.unwrap_or(self.payload);
        if let Some(edns) = &mut response.message.edns {
            edns.set_max_payload(payload.max(512));
        }
        self.write(req, response, Limit::for_request(req, payload))
    }

    /// The octets of `response` for `req`, through the front and fitted to
    /// the client's size. A reply hickory cannot write becomes SERVFAIL.
    pub(in super::super) fn render(&self, req: &Request, response: Response) -> Vec<u8> {
        let response = self.front(req, response);
        self.write(req, response, Limit::for_request(req, self.payload))
    }

    /// The octets of `response`, which has been through the front, fitted
    /// to `limit`, or of SERVFAIL when hickory cannot write it.
    fn write(&self, req: &Request, response: Response, limit: Limit) -> Vec<u8> {
        match fit(&response, limit) {
            Ok(Fitted { bytes, .. }) => bytes,
            Err(_) => {
                let failed = self.front(req, bare_reply(req, ResponseCode::ServFail, None));
                fit(&failed, limit)
                    .expect("a reply with only a question and an OPT record writes")
                    .bytes
            }
        }
    }

    /// The octets of a reply [`Request::parse`] rejected the query with,
    /// carrying this server's payload in its OPT record.
    pub(in super::super) fn render_reject(
        &self,
        mut reject: Message,
        transport: Transport,
    ) -> Vec<u8> {
        if let Some(edns) = &mut reject.edns {
            edns.set_max_payload(self.payload.max(512));
        }
        reject.metadata.recursion_available = self.recursion_available;
        let limit = match transport {
            Transport::Tcp => Limit::Stream,
            Transport::Udp => Limit::Udp512,
        };
        let response = Response {
            message: reject,
            required_additional: 0,
        };
        fit(&response, limit)
            .expect("a rejection holds only a question, an OPT record, and a TSIG record")
            .bytes
    }
}

/// What a stub such as `dig` waits for one try before it gives up.
const ASK_TIMEOUT: Duration = Duration::from_secs(5);

/// Moves the glue a referral in `message` needs to the front of its
/// additional section: the addresses of NS targets at or below the cut
/// (RFC 9471 §3.1). Returns how many RRsets that glue makes.
pub(super) fn glue_first(message: &mut Message) -> usize {
    if !message.answers.is_empty() {
        return 0;
    }
    let cuts: Vec<(Name, Name)> = message
        .authorities
        .iter()
        .filter_map(|record| match &record.data {
            RData::NS(ns) => Some((record.name.clone(), ns.0.clone())),
            _ => None,
        })
        .collect();
    let needed = |record: &Record| {
        matches!(record.record_type(), RecordType::A | RecordType::AAAA)
            && cuts
                .iter()
                .any(|(cut, target)| record.name == *target && cut.zone_of(&record.name))
    };
    let (mut glue, rest): (Vec<Record>, Vec<Record>) =
        message.additionals.drain(..).partition(needed);
    let mut sets: Vec<(Name, RecordType)> = Vec::new();
    for record in &glue {
        let set = (record.name.clone(), record.record_type());
        if !sets.contains(&set) {
            sets.push(set);
        }
    }
    glue.extend(rest);
    message.additionals = glue;
    sets.len()
}

/// A reply to `req` with `rcode`, the question, and nothing else, and
/// with Extended DNS Error `ede` when given. The server front adds the
/// rest.
pub fn bare_reply(req: &Request, rcode: ResponseCode, ede: Option<EdeCode>) -> Response {
    bare_reply_with(req, rcode, ede.map(Ede::new))
}

/// [`bare_reply`] with an Extended DNS Error that may carry text.
fn bare_reply_with(req: &Request, rcode: ResponseCode, ede: Option<Ede>) -> Response {
    let query = &req.message.metadata;
    let mut message = Message::error_msg(query.id, query.op_code, rcode);
    message.add_query(req.question.clone());
    if let Some(ede) = ede {
        let mut edns = Edns::new();
        edns.options_mut().insert(ede.to_option());
        message.set_edns(edns);
    }
    Response {
        message,
        required_additional: 0,
    }
}

/// What a server says about itself: its answers to CHAOS-class questions
/// by name, how those replies look, and its NSID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Answers by name. Real servers answer the names of [`chaos`] and
    /// more of their own.
    pub chaos: BTreeMap<LowerName, ChaosAnswer>,
    /// The reply for a CHAOS-class name not in [`chaos`](Identity::chaos)
    /// and not below one of its [zones](ChaosAnswer::Zone).
    pub unlisted: ChaosReply,
    /// The reply to a question of a type other than TXT or ANY, for every
    /// name that is not a [zone](ChaosAnswer::Zone) or below one.
    pub other_types: ChaosReply,
    /// Whether its [`Txt`](ChaosAnswer::Txt) answers set AA.
    pub aa: bool,
    /// The name server identifier sent to a query that asks for one
    /// (RFC 5001).
    pub nsid: Option<Vec<u8>>,
    /// The TTL of its TXT answers.
    pub ttl: u32,
    /// The EDNS payload size its CHAOS replies advertise, when it is not
    /// the server's own.
    pub payload: Option<u16>,
}

impl Identity {
    /// No names and no NSID: every CHAOS-class question gets REFUSED, and
    /// TXT answers, once names are added, have TTL 0 and AA clear.
    pub fn none() -> Identity {
        Identity {
            chaos: BTreeMap::new(),
            unlisted: ChaosReply::rcode(ResponseCode::Refused),
            other_types: ChaosReply::rcode(ResponseCode::Refused),
            aa: false,
            nsid: None,
            ttl: 0,
            payload: None,
        }
    }

    /// This identity with `answer` for `name`.
    pub fn answer(mut self, name: LowerName, answer: ChaosAnswer) -> Identity {
        self.chaos.insert(name, answer);
        self
    }

    /// This identity giving its TXT answers TTL `ttl`.
    pub fn ttl(mut self, ttl: u32) -> Identity {
        self.ttl = ttl;
        self
    }

    /// The reply to the CHAOS-class question `req`, before a server front
    /// adds its header details and EDNS, and whether it has an OPT record
    /// when the query had one:
    ///
    /// - A zone transfer gets REFUSED: these names are no zones to list
    ///   (RFC 5936 §2.2).
    /// - A name at or below a [zone](ChaosAnswer::Zone) gets the zone's
    ///   answer ([`ChaosZone`]).
    /// - Any other name asked for a type other than TXT or ANY gets
    ///   [`other_types`](Identity::other_types).
    /// - A [`Txt`](ChaosAnswer::Txt) name, asked for TXT or ANY, gets its
    ///   text as one TXT record with the identity's TTL, and AA as
    ///   [`aa`](Identity::aa) says.
    /// - A name with a reply of its own gets it, and an unlisted name gets
    ///   [`unlisted`](Identity::unlisted).
    pub fn reply(&self, req: &Request) -> (Response, bool) {
        if matches!(
            req.question.query_type(),
            RecordType::AXFR | RecordType::IXFR
        ) {
            return (bare_reply(req, ResponseCode::Refused, None), true);
        }
        let qname = LowerName::new(req.question.name());
        let zone = self.chaos.iter().find_map(|(name, answer)| match answer {
            ChaosAnswer::Zone(zone) if name.zone_of(&qname) => Some((name, zone)),
            _ => None,
        });
        if let Some((apex, zone)) = zone {
            return (self.zone_reply(req, &Name::from(apex), zone), true);
        }
        let other = !matches!(req.question.query_type(), RecordType::TXT | RecordType::ANY);
        let empty = |reply: &ChaosReply| {
            (
                bare_reply_with(req, reply.rcode, reply.ede.clone()),
                reply.edns,
            )
        };
        match self.chaos.get(&qname) {
            _ if other => empty(&self.other_types),
            Some(ChaosAnswer::Txt(text)) => {
                let mut response = bare_reply(req, ResponseCode::NoError, None);
                response.message.metadata.authoritative = self.aa;
                response
                    .message
                    .answers
                    .push(self.txt(req.question.name(), text));
                (response, true)
            }
            Some(ChaosAnswer::Reply(reply)) => empty(reply),
            Some(ChaosAnswer::Zone(_)) | None => empty(&self.unlisted),
        }
    }

    /// The reply to `req` from `zone`, the CHAOS zone at `apex`, with AA
    /// set: at the apex, the zone's records of the type asked, or NODATA
    /// with the SOA; below it, NXDOMAIN with the SOA (RFC 2308 §2.1,
    /// §2.2).
    fn zone_reply(&self, req: &Request, apex: &Name, zone: &ChaosZone) -> Response {
        let qtype = req.question.query_type();
        let mut response = bare_reply(req, ResponseCode::NoError, None);
        response.message.metadata.authoritative = true;
        let soa = chaos_record(apex, zone.soa_ttl, RData::SOA(zone.soa.clone()));
        if req.question.name() != apex {
            response.message.metadata.response_code = ResponseCode::NXDomain;
            response.message.authorities.push(soa);
            return response;
        }
        let ns = chaos_record(apex, zone.ns_ttl, RData::NS(NS(zone.ns.clone())));
        let txt = zone.txt.as_deref().map(|text| self.txt(apex, text));
        let answers: Vec<Record> = match qtype {
            RecordType::TXT => txt.into_iter().collect(),
            RecordType::SOA => vec![soa.clone()],
            RecordType::NS => vec![ns],
            RecordType::ANY => txt.into_iter().chain([soa.clone(), ns]).collect(),
            _ => Vec::new(),
        };
        if answers.is_empty() {
            response.message.authorities.push(soa);
        }
        response.message.answers = answers;
        response
    }

    /// `text` at `name` as one CHAOS-class TXT record with the identity's
    /// TTL.
    fn txt(&self, name: &Name, text: &str) -> Record {
        let txt = RData::TXT(TXT::new(vec![text.to_string()]));
        chaos_record(name, self.ttl, txt)
    }
}

/// `rdata` at `name` as a CHAOS-class record with `ttl`.
fn chaos_record(name: &Name, ttl: u32, rdata: RData) -> Record {
    let mut record = Record::from_rdata(name.clone(), ttl, rdata);
    record.dns_class = DNSClass::CH;
    record
}

/// A server's answer to a CHAOS-class question for one name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChaosAnswer {
    /// One TXT string, at most 255 octets (RFC 1035 §3.3), served without
    /// a zone.
    Txt(String),
    /// A zone of its own at the name.
    Zone(ChaosZone),
    /// No data, with this reply, as servers that refuse to say.
    Reply(ChaosReply),
}

/// A CHAOS-class zone at one name, as some servers serve each name they
/// answer about themselves: its apex records, and the TXT string at the
/// apex if any. The zone holds no other names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChaosZone {
    /// The zone's SOA, whose owner is the zone's name.
    pub soa: SOA,
    /// The TTL of the SOA record.
    pub soa_ttl: u32,
    /// The target of the zone's one NS record.
    pub ns: Name,
    /// The TTL of the NS record.
    pub ns_ttl: u32,
    /// The TXT string at the apex, with the identity's TTL.
    pub txt: Option<String>,
}

/// A CHAOS-class reply without data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChaosReply {
    /// Its RCODE.
    pub rcode: ResponseCode,
    /// The Extended DNS Error it carries (RFC 8914), if any.
    pub ede: Option<Ede>,
    /// Whether it has an OPT record when the query had one, as some
    /// servers leave it out.
    pub edns: bool,
}

impl ChaosReply {
    /// A reply with `rcode`, no Extended DNS Error, and an OPT record when
    /// the query had one.
    pub fn rcode(rcode: ResponseCode) -> ChaosReply {
        ChaosReply {
            rcode,
            ede: None,
            edns: true,
        }
    }
}

/// The CHAOS-class names servers answer about themselves.
pub mod chaos {
    use fictionet::stdlib::protocols::dns::rr::{LowerName, Name};

    fn name(text: &str) -> LowerName {
        LowerName::new(&Name::from_ascii(text).expect("a valid name"))
    }

    /// `id.server.`: which server instance answered (RFC 4892 §2).
    pub fn id_server() -> LowerName {
        name("id.server.")
    }

    /// `version.server.`: the server's software version, as some
    /// operators publish it.
    pub fn version_server() -> LowerName {
        name("version.server.")
    }

    /// `hostname.bind.`: BIND's name for the instance (RFC 4892 §2).
    pub fn hostname_bind() -> LowerName {
        name("hostname.bind.")
    }

    /// `version.bind.`: BIND's name for the software version.
    pub fn version_bind() -> LowerName {
        name("version.bind.")
    }

    /// `authors.bind.`: BIND's list of its authors.
    pub fn authors_bind() -> LowerName {
        name("authors.bind.")
    }
}
