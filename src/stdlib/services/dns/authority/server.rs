//! The server front: the header and EDNS details an authoritative server
//! puts on every reply, its answers to CHAOS-class questions, and its
//! payload size.

use std::collections::BTreeMap;
use std::time::Duration;

use fictionet::stdlib::protocols::dns::op::{Edns, Header, Message, MessageType, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::rdata::TXT;
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, Name, RData, Record, RecordType};
use fictionet::stdlib::protocols::dns::serialize::binary::{BinDecodable, BinDecoder};
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
    /// What the server says about itself.
    pub identity: Identity,
    /// The largest UDP reply the server sends and advertises
    /// (RFC 6891 §6.2.5).
    pub payload: u16,
    /// Whether replies carry Extended DNS Errors (RFC 8914).
    pub ede: bool,
    /// What the server sends for QTYPE ANY (RFC 8482 §4).
    pub any: AnyResponse,
    /// Whether zone transfers reach the authority. Without it, AXFR and
    /// IXFR over TCP get REFUSED.
    pub transfer: bool,
    /// How long the server waits for another server it asks before it
    /// counts the question as unanswered.
    pub ask_timeout: Duration,
}

impl ServerConfig {
    /// An ordinary authoritative server: a 1232-octet payload, the size
    /// the DNS Flag Day 2020 settled on; Extended DNS Errors; the RFC 8482
    /// HINFO answer to ANY, as Cloudflare's servers send; no transfers; and
    /// no identity.
    pub fn generic() -> ServerConfig {
        ServerConfig {
            identity: Identity::none(),
            payload: 1232,
            ede: true,
            any: AnyResponse::Hinfo,
            transfer: false,
            ask_timeout: ASK_TIMEOUT,
        }
    }

    /// A root server with `identity`, which carries its letter's and
    /// site's CHAOS names and NSID. As observed at the root letters: a
    /// 4096-octet payload, and every RRset of the name for ANY.
    pub fn root(identity: Identity) -> ServerConfig {
        ServerConfig {
            identity,
            payload: 4096,
            any: AnyResponse::All,
            ..ServerConfig::generic()
        }
    }

    /// A `gtld-servers.net` server with `identity`: a 4096-octet payload
    /// and every RRset of the name for ANY, as the root servers.
    pub fn gtld(identity: Identity) -> ServerConfig {
        ServerConfig::root(identity)
    }

    /// `response` with the header and EDNS details of this server, for
    /// `req`:
    ///
    /// - The ID, opcode, RD, and CD are the query's; RA, AD, and TC are
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
    ///   (RFC 5001 §2.1), and the authority's own options, Extended DNS
    ///   Errors only when [`ede`](ServerConfig::ede) is on.
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
        metadata.recursion_available = false;
        metadata.authentic_data = false;
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
                if Nsid::from_option(option).is_none() && (self.ede || !ede) {
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

    /// The reply to a CHAOS-class question, from [`identity`](ServerConfig::identity)
    /// alone. A name with text gets it as one TXT record with TTL 0 and
    /// AA set, for QTYPE TXT or ANY, and an empty NOERROR for other types.
    pub(super) fn chaos(&self, req: &Request) -> Response {
        let qname = LowerName::new(req.question.name());
        let text = match self.identity.chaos.get(&qname) {
            None => return bare_reply(req, self.identity.unlisted, None),
            Some(ChaosAnswer::Rcode(code)) => return bare_reply(req, *code, None),
            Some(ChaosAnswer::Txt(text)) => text,
        };
        let mut response = bare_reply(req, ResponseCode::NoError, None);
        response.message.metadata.authoritative = true;
        if matches!(req.question.query_type(), RecordType::TXT | RecordType::ANY) {
            let txt = RData::TXT(TXT::new(vec![text.clone()]));
            let mut record = Record::from_rdata(req.question.name().clone(), 0, txt);
            record.dns_class = DNSClass::CH;
            response.message.answers.push(record);
        }
        response
    }

    /// The octets of `response` for `req`, through the front and fitted to
    /// the client's size. A reply hickory cannot write becomes SERVFAIL.
    pub(super) fn render(&self, req: &Request, response: Response) -> Vec<u8> {
        let limit = Limit::for_request(req, self.payload);
        match fit(&self.front(req, response), limit) {
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
    pub(super) fn render_reject(&self, mut reject: Message, transport: Transport) -> Vec<u8> {
        if let Some(edns) = &mut reject.edns {
            edns.set_max_payload(self.payload.max(512));
        }
        let limit = match transport {
            Transport::Tcp => Limit::Stream,
            Transport::Udp => Limit::Udp512,
        };
        let response = Response {
            message: reject,
            required_additional: 0,
        };
        fit(&response, limit)
            .expect("a rejection holds only a question and an OPT record")
            .bytes
    }

    /// `bytes`, a whole reply for `req`, as they are when they fit the
    /// client's size. A larger reply, such as one a source fetched over
    /// TCP for a client that asked over UDP, is decoded and written again
    /// with [`fit`], which keeps whole RRsets, the glue a referral needs,
    /// and sets TC (RFC 2181 §9, RFC 9471 §3.1). `None` for octets that
    /// are not a response, and for a reply too large that does not decode.
    pub(super) fn verbatim(&self, req: &Request, bytes: Vec<u8>) -> Option<Vec<u8>> {
        let header = Header::read(&mut BinDecoder::new(&bytes)).ok()?;
        if header.metadata.message_type != MessageType::Response {
            return None;
        }
        let limit = Limit::for_request(req, self.payload);
        if bytes.len() <= limit.octets() {
            return Some(bytes);
        }
        let mut message = Message::from_vec(&bytes).ok()?;
        let required_additional = glue_first(&mut message);
        let response = Response {
            message,
            required_additional,
        };
        fit(&response, limit).ok().map(|fitted| fitted.bytes)
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

/// What a server says about itself: its answers to CHAOS-class TXT
/// questions by name, and its NSID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Answers by name. Real servers answer the names of [`chaos`] and
    /// more of their own.
    pub chaos: BTreeMap<LowerName, ChaosAnswer>,
    /// The RCODE for a CHAOS-class name not in [`chaos`](Identity::chaos).
    pub unlisted: ResponseCode,
    /// The name server identifier sent to a query that asks for one
    /// (RFC 5001).
    pub nsid: Option<Vec<u8>>,
}

impl Identity {
    /// No names and no NSID: every CHAOS-class question gets REFUSED, as
    /// at Cloudflare's resolver for names it does not answer.
    pub fn none() -> Identity {
        Identity {
            chaos: BTreeMap::new(),
            unlisted: ResponseCode::Refused,
            nsid: None,
        }
    }

    /// This identity with `answer` for `name`.
    pub fn answer(mut self, name: LowerName, answer: ChaosAnswer) -> Identity {
        self.chaos.insert(name, answer);
        self
    }
}

/// A server's answer to a CHAOS-class question for one name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChaosAnswer {
    /// One TXT string, at most 255 octets (RFC 1035 §3.3).
    Txt(String),
    /// No data, with this RCODE, as servers that refuse to say.
    Rcode(ResponseCode),
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
