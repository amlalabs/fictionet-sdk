//! The server front: the header and EDNS details an authoritative server
//! puts on every reply, its answers to CHAOS-class questions, and its
//! payload size.

use std::collections::BTreeMap;
use std::time::Duration;

use fictionet::stdlib::protocols::dns::op::{Edns, Message, MessageType, ResponseCode};
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
    /// What the server says about itself: its CHAOS data and its NSID,
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
    /// synthesized HINFO answer to ANY of RFC 8482 §4.2, with a TTL of an
    /// hour; and an identity
    /// with no CHAOS data and no NSID. A world that plays a particular server
    /// writes its values over this one.
    pub fn generic() -> ServerConfig {
        ServerConfig {
            identity: Identity::none(),
            payload: 1232,
            ede: true,
            any: AnyResponse::Hinfo { ttl: 3600 },
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
    /// [`identity`](ServerConfig::identity) alone
    /// ([`Identity::respond`]), through the front and fitted to the
    /// client's size.
    pub(in super::super) fn render_chaos(&self, req: &Request) -> Vec<u8> {
        self.render(req, self.identity.respond(req))
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
    let query = &req.message.metadata;
    let mut message = Message::error_msg(query.id, query.op_code, rcode);
    message.add_query(req.question.clone());
    if let Some(code) = ede {
        let mut edns = Edns::new();
        edns.options_mut().insert(Ede::new(code).to_option());
        message.set_edns(edns);
    }
    Response {
        message,
        required_additional: 0,
    }
}

/// What a server says about itself: the CHAOS-class data it answers
/// questions from, and its NSID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Its CHAOS-class zones. Each holds its own apex, and at equal apex
    /// the zone given last answers.
    pub zones: Vec<ChaosZone>,
    /// Names it answers with an RCODE and no records, whatever the type
    /// asked.
    pub rcodes: BTreeMap<LowerName, ResponseCode>,
    /// The RCODE for a name in none of its zones and with no RCODE of its
    /// own.
    pub unlisted: ResponseCode,
    /// The name server identifier sent to a query that asks for one
    /// (RFC 5001).
    pub nsid: Option<Vec<u8>>,
}

impl Identity {
    /// No zones and no NSID: every CHAOS-class question gets REFUSED
    /// (RFC 1035 §4.1.1).
    pub fn none() -> Identity {
        Identity {
            zones: Vec::new(),
            rcodes: BTreeMap::new(),
            unlisted: ResponseCode::Refused,
            nsid: None,
        }
    }

    /// This identity serving `zone`, in place of any zone it served at
    /// the same apex.
    pub fn zone(mut self, zone: ChaosZone) -> Identity {
        let apex = LowerName::new(&zone.apex);
        self.zones.retain(|held| LowerName::new(&held.apex) != apex);
        self.zones.push(zone);
        self
    }

    /// This identity answering `name` with `rcode` and no records.
    pub fn rcode(mut self, name: LowerName, rcode: ResponseCode) -> Identity {
        self.rcodes.insert(name, rcode);
        self
    }

    /// The reply to the CHAOS-class question `req`, before a server front
    /// adds its header details and EDNS:
    ///
    /// - A zone transfer gets REFUSED: these zones answer questions, and
    ///   cannot be listed (RFC 5936 §2.2).
    /// - A name in [`rcodes`](Identity::rcodes) gets its RCODE.
    /// - A name at or below the apex of one of its zones is answered from
    ///   the deepest such zone ([`ChaosZone`]).
    /// - Any other name gets [`unlisted`](Identity::unlisted).
    pub fn respond(&self, req: &Request) -> Response {
        if matches!(
            req.question.query_type(),
            RecordType::AXFR | RecordType::IXFR
        ) {
            return bare_reply(req, ResponseCode::Refused, None);
        }
        let qname = LowerName::new(req.question.name());
        if let Some(rcode) = self.rcodes.get(&qname) {
            return bare_reply(req, *rcode, None);
        }
        // `max_by_key` keeps the last of equal keys: the zone given last.
        let zone = self
            .zones
            .iter()
            .filter(|zone| LowerName::new(&zone.apex).zone_of(&qname))
            .max_by_key(|zone| zone.apex.num_labels());
        match zone {
            Some(zone) => zone.respond(req),
            None => bare_reply(req, self.unlisted, None),
        }
    }
}

/// A CHAOS-class zone whose records are all at its apex, answered as any
/// zone is (RFC 1034 §4.3.2), with AA set: at the apex, its records of
/// the type asked, or NODATA; below the apex, NXDOMAIN. A negative reply
/// carries the zone's SOA when it has one, with the smaller of the SOA's
/// TTL and its MINIMUM field (RFC 2308 §2.1, §2.2, §3).
///
/// The zone holds no aliases. A CNAME at an apex could not stand beside
/// other data (RFC 1034 §3.6.2), and a DNAME would redirect the names
/// below the apex, which this zone answers NXDOMAIN (RFC 6672 §2.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChaosZone {
    apex: Name,
    records: Vec<Record>,
}

impl ChaosZone {
    /// An empty zone at `apex`.
    pub fn new(apex: Name) -> ChaosZone {
        ChaosZone {
            apex,
            records: Vec::new(),
        }
    }

    /// This zone with `rdata` at its apex, as a CHAOS-class record with
    /// `ttl`. Panics if `rdata` is a CNAME or a DNAME.
    pub fn record(mut self, ttl: u32, rdata: RData) -> ChaosZone {
        assert!(
            !matches!(rdata.record_type(), RecordType::CNAME | RecordType::DNAME),
            "a CHAOS zone holds no aliases"
        );
        let mut record = Record::from_rdata(self.apex.clone(), ttl, rdata);
        record.dns_class = DNSClass::CH;
        self.records.push(record);
        self
    }

    /// The zone's apex.
    pub fn apex(&self) -> &Name {
        &self.apex
    }

    /// The zone's records, in the order they were added, which is the
    /// order an answer to ANY gives them in.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// The reply to `req`, whose QNAME is at or below the apex.
    fn respond(&self, req: &Request) -> Response {
        let qtype = req.question.query_type();
        let mut response = bare_reply(req, ResponseCode::NoError, None);
        response.message.metadata.authoritative = true;
        let negative_soa = self.records.iter().find_map(|record| match &record.data {
            RData::SOA(soa) => {
                let mut negative = record.clone();
                negative.ttl = record.ttl.min(soa.minimum);
                Some(negative)
            }
            _ => None,
        });
        if *req.question.name() != self.apex {
            response.message.metadata.response_code = ResponseCode::NXDomain;
            response.message.authorities.extend(negative_soa);
            return response;
        }
        let answers: Vec<Record> = self
            .records
            .iter()
            .filter(|record| qtype == RecordType::ANY || record.record_type() == qtype)
            .cloned()
            .collect();
        if answers.is_empty() {
            response.message.authorities.extend(negative_soa);
        }
        response.message.answers = answers;
        response
    }
}
