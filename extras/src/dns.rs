//! DNS lookups kept in WARC archives beside captured pages, and played
//! back as an [`Upstream`].
//!
//! [`Capture`] records what another upstream, such as the internet asked
//! from the host, gives for each lookup, and writes it as two WARC records: a
//! `request` holding the query the lookup stands for and a `response`
//! holding the server's response, both as `application/dns-message`
//! (RFC 8484 §6), with the server and the question in a `dns:` target URI
//! (RFC 4501), for example `dns://192.5.6.30/example.com.?type=NS`.
//! [`Replay`] reads those records back and gives the same responses to
//! the same lookups, so a world resolves names as it did when the pages
//! were captured.
//!
//! A lookup the capture does not hold gets no reply: the world's server
//! that needed it stays silent, and a resolver caches a failure for the
//! name, not a negative answer.
//!
//! The real internet's DNS as a world plays it lives here too, beside the
//! SDK's primitives: [`mirror`] copies the real hierarchy onto servers at
//! the real servers' addresses, which answer from [`copies`] of the zones
//! they serve, each address's copy of a zone [`learned`] from what its own
//! real server answered. [`public`] has the large public resolvers, [`doh`]
//! what their DNS over HTTPS servers answer past RFC 8484, [`place`]
//! how the root, `gtld-servers.net`, and public resolver servers look
//! from one place, and [`roots`] the `gtld-servers.net` servers' addresses,
//! what the root and `gtld-servers.net` servers' software does
//! everywhere, and the zones a mirror serves at their addresses. [`unbound`] plays Unbound's configuration, [`chaos`]
//! the CHAOS-class names servers answer about themselves and the plain
//! and refusing looks of those answers, and [`bind`] BIND's CHAOS-class
//! zones.

pub mod bind;
pub mod chaos;
pub mod copies;
pub mod doh;
pub mod learned;
pub mod mirror;
pub mod place;
pub mod public;
pub mod roots;
pub mod unbound;

use std::collections::{HashMap, HashSet};
use std::future::{Future, ready};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;

use fictionet::Cx;
use fictionet::stdlib::protocols::dns::op::{Message, Query};
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, Name, RData, RecordType};
use fictionet::stdlib::protocols::dns::{Parsed, Request, label_count, read_message};
use fictionet::stdlib::services::dns::{Looked, Lookup};
use fictionet::stdlib::services::serve::Transport;
use fictionet::stdlib::world::net::dns::Upstream;
use fictionet::sync::Mutex;

use crate::warc;

/// Public names advertised by the ECH configurations in an HTTPS or SVCB
/// record. Invalid lists and unknown configuration versions give no names.
pub fn ech_public_names(data: &RData) -> Vec<LowerName> {
    use fictionet::stdlib::protocols::dns::rr::rdata::svcb::SvcParamValue;
    use rustls::internal::msgs::{codec::Codec, handshake::EchConfigPayload};

    let params = match data {
        RData::HTTPS(record) => &record.svc_params,
        RData::SVCB(record) => &record.svc_params,
        _ => return Vec::new(),
    };
    params
        .iter()
        .filter_map(|(_, value)| match value {
            SvcParamValue::EchConfigList(list) => Vec::<EchConfigPayload>::read_bytes(&list.0).ok(),
            _ => None,
        })
        .flatten()
        .filter_map(|config| match config {
            EchConfigPayload::V18(config) => Name::from_ascii(config.public_name.as_ref())
                .ok()
                .map(|mut name| {
                    name.set_fqdn(true);
                    LowerName::new(&name)
                }),
            _ => None,
        })
        .collect()
}

/// The media type of a DNS message in wire format (RFC 8484 §6).
const DNS_MESSAGE: &str = "application/dns-message";

/// The port a `dns:` URI means when it names none (RFC 4501 §2).
const DNS_PORT: u16 = 53;

/// Whether `uri` is a `dns:` URI (RFC 4501), whose scheme name is
/// case-insensitive (RFC 3986 §3.1).
pub(crate) fn is_dns_uri(uri: &str) -> bool {
    uri.get(..4)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("dns:"))
}

/// An upstream that keeps every response another upstream gives, to
/// write them to a WARC archive with [`Capture::write`].
///
/// It gives exactly what the upstream it wraps gives. Only responses are
/// kept: a server that was unreachable or silent leaves nothing, and
/// [`Replay`] gives such a lookup no reply, as it does any lookup the
/// capture lacks.
pub struct Capture<U> {
    upstream: U,
    exchanges: Mutex<Vec<Exchange>>,
}

/// One lookup and the response it got.
struct Exchange {
    lookup: Lookup,
    response: Message,
    at: time::OffsetDateTime,
}

impl<U: Upstream> Capture<U> {
    /// `upstream`, with its responses kept.
    pub fn new(upstream: U) -> Capture<U> {
        Capture {
            upstream,
            exchanges: Mutex::new(Vec::new()),
        }
    }

    /// Appends the responses kept since the last write to the archive at
    /// `path`, and forgets them. Each becomes a `request` record with the
    /// query the lookup stands for (its question, without recursion and
    /// with DO set, as every lookup asks), then a `response` record with the response,
    /// which names the request in `WARC-Concurrent-To`. A lookup whose
    /// query or response does not write is left out.
    pub fn write(&self, path: &Path) -> io::Result<()> {
        let exchanges = std::mem::take(&mut *self.exchanges.lock());
        for exchange in exchanges {
            let (Ok(query), Ok(response)) = (
                exchange.lookup.query(0).to_vec(),
                exchange.response.to_vec(),
            ) else {
                continue;
            };
            let target = target_uri(&exchange.lookup);
            let date = warc::date(exchange.at);
            let address = exchange.lookup.server.ip().to_string();
            let request = warc::append_record(
                path,
                &[
                    ("WARC-Type", "request"),
                    ("WARC-Target-URI", &target),
                    ("WARC-Date", &date),
                    ("WARC-IP-Address", &address),
                    ("Content-Type", DNS_MESSAGE),
                ],
                &query,
            )?;
            warc::append_record(
                path,
                &[
                    ("WARC-Type", "response"),
                    ("WARC-Target-URI", &target),
                    ("WARC-Date", &date),
                    ("WARC-IP-Address", &address),
                    ("WARC-Concurrent-To", &request.id),
                    ("Content-Type", DNS_MESSAGE),
                ],
                &response,
            )?;
        }
        Ok(())
    }
}

impl<U: Upstream> Upstream for Capture<U> {
    fn lookup<'a>(
        &'a self,
        fcx: &'a Cx,
        lookup: Lookup,
    ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
        Box::pin(async move {
            let looked = self.upstream.lookup(fcx, lookup.clone()).await;
            if let Looked::Response(response) = &looked {
                self.exchanges.lock().push(Exchange {
                    lookup,
                    response: response.clone(),
                    at: time::OffsetDateTime::now_utc(),
                });
            }
            looked
        })
    }
}

/// The `dns:` URI of `lookup` (RFC 4501 §2): the server as the authority,
/// the question's name, and its type, with its class when that is not IN.
fn target_uri(lookup: &Lookup) -> String {
    let server = if lookup.server.port() == DNS_PORT {
        match lookup.server.ip() {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        }
    } else {
        lookup.server.to_string()
    };
    let question = &lookup.question;
    let mut uri = format!(
        "dns://{server}/{}?type={}",
        uri_name(question.name()),
        mnemonic(question.query_type())
    );
    if question.query_class() != DNSClass::IN {
        uri.push_str(";class=");
        uri.push_str(&question.query_class().to_string());
    }
    uri
}

/// `name` as the `dnsname` of a `dns:` URI (RFC 4501 §2): labels joined
/// by periods, with every octet but letters, digits, hyphens, and
/// underscores percent-encoded, and a period inside a label written as
/// an escaped `\.`. The root is `.`.
fn uri_name(name: &Name) -> String {
    if name.is_root() {
        return ".".to_string();
    }
    let mut out = String::new();
    for label in name.iter() {
        for &octet in label {
            match octet {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' => out.push(octet as char),
                b'.' => out.push_str("%5C."),
                _ => out.push_str(&format!("%{octet:02X}")),
            }
        }
        out.push('.');
    }
    out
}

/// A record type as a `dnstypeval` (RFC 4501 §2): its mnemonic, or its
/// number when it has none.
fn mnemonic(kind: RecordType) -> String {
    match kind {
        RecordType::Unknown(number) => number.to_string(),
        known => known.to_string(),
    }
}

/// The server a `dns:` URI names, from its authority, with port 53 when
/// it gives none.
fn uri_server(uri: &str) -> Option<SocketAddr> {
    if !is_dns_uri(uri) {
        return None;
    }
    let authority = uri[4..].strip_prefix("//")?.split('/').next()?;
    authority.parse().ok().or_else(|| {
        let host = authority.trim_start_matches('[').trim_end_matches(']');
        Some(SocketAddr::new(host.parse().ok()?, DNS_PORT))
    })
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// How the name of a DNS capture's archive in a corpus directory starts
/// ([`Replay::capture_file`]).
const CAPTURE_PREFIX: &str = "zz-dns-";

/// How the name of a DNS capture's archive ends.
const CAPTURE_SUFFIX: &str = ".warc.gz";

/// What makes two lookups one question for [`Replay`]: the name, in
/// lowercase, the type, and the class.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Question {
    name: LowerName,
    qtype: RecordType,
    qclass: DNSClass,
}

impl Question {
    fn of(query: &Query) -> Question {
        Question {
            name: LowerName::new(query.name()),
            qtype: query.query_type(),
            qclass: query.query_class(),
        }
    }
}

/// An upstream that gives the responses [`Capture`] recorded.
///
/// A lookup gets the response recorded for the same question (its name,
/// ignoring case, its type, and its class) sent to the same server.
/// Every lookup asks with DO, so only exchanges whose recorded query set
/// DO are kept: a response to a query without it lacks the DNSSEC records
/// a lookup's response carries.
///
/// The servers named in one NS RRset serve the same zone, so for a
/// question at or below that zone a response recorded from one of them
/// answers for the others too: a resolver that picks another root letter
/// than the capture did, or another of a domain's name servers, gets the
/// recorded response. The capture's own NS records and addresses say
/// which servers those are. Each server answers from the deepest zone it
/// serves that holds the name, and DS from the zone above, so a response
/// stands in only for a server that answers the question from the same
/// zone: a.root's authoritative answer from `arpa`, which j.root does not
/// serve, never answers for j.root.
///
/// A corpus holds several captures, and a world's clock stands at the
/// newest one, so the response comes from the newest capture that holds
/// one for the server or a server of its zone: an older capture's RRSIGs
/// may have expired by that clock. Within one capture, the server's own
/// response comes first.
///
/// Any other lookup gets [`Looked::NoReply`], as from a server that never
/// replies.
#[derive(Debug, Default)]
pub struct Replay {
    /// The responses to each question: the server that sent each, the
    /// response, and the capture it came from, counted in the order the
    /// archives were read.
    replies: HashMap<Question, Vec<(SocketAddr, Message, usize)>>,
    /// The zones each server address serves, by the capture's NS records.
    zones: HashMap<IpAddr, Vec<LowerName>>,
    /// When the newest recorded response was captured.
    newest: Option<time::OffsetDateTime>,
}

impl Replay {
    /// The DNS lookups in the archives `files`, in order: a later response
    /// to the same question from the same server replaces an earlier one.
    /// Records that are not DNS exchanges, such as captured pages, are
    /// skipped.
    pub fn open(files: impl IntoIterator<Item = PathBuf>) -> io::Result<Replay> {
        let mut replay = Replay::default();
        let mut ns = HashSet::new();
        let mut addresses: HashMap<LowerName, Vec<IpAddr>> = HashMap::new();
        for (capture, file) in files.into_iter().enumerate() {
            let mut queries: HashMap<String, Vec<u8>> = HashMap::new();
            let mut responses = Vec::new();
            warc::each_record(
                &file,
                |fields| {
                    fields
                        .get("warc-target-uri")
                        .is_some_and(|uri| is_dns_uri(uri))
                        && fields.get("content-type").map(String::as_str) == Some(DNS_MESSAGE)
                },
                |stored| {
                    let Some(block) = stored.block else {
                        return Ok(());
                    };
                    let fields = stored.fields;
                    match fields.get("warc-type").map(String::as_str) {
                        Some("request") => {
                            if let Some(id) = fields.get("warc-record-id") {
                                queries.insert(id.clone(), block);
                            }
                        }
                        Some("response") => responses.push((fields, block)),
                        _ => {}
                    }
                    Ok(())
                },
            )?;
            for (fields, reply) in responses {
                let server = fields
                    .get("warc-target-uri")
                    .and_then(|uri| uri_server(uri))
                    .ok_or_else(|| invalid("a DNS response whose URI names no server"))?;
                let query = fields
                    .get("warc-concurrent-to")
                    .and_then(|id| queries.get(id))
                    .ok_or_else(|| invalid("a DNS response without its request"))?;
                let Parsed::Request(request) = Request::parse(query, Transport::Tcp) else {
                    return Err(invalid("a recorded DNS query that does not parse"));
                };
                let Ok(message) = read_message(&reply) else {
                    continue;
                };
                learn(&message, &mut ns, &mut addresses);
                if let Some(text) = fields.get("warc-date") {
                    let date = warc::parse_date(text)
                        .ok_or_else(|| invalid("a DNS response whose WARC-Date is no date"))?;
                    replay.newest = replay.newest.max(Some(date));
                }
                if !request.edns.is_some_and(|edns| edns.dnssec_ok) {
                    continue;
                }
                let replies = replay
                    .replies
                    .entry(Question::of(&request.question))
                    .or_default();
                replies.retain(|(recorded, _, _)| *recorded != server);
                replies.push((server, message, capture));
            }
        }
        for (zone, target) in ns {
            for &address in addresses.get(&target).into_iter().flatten() {
                let zones = replay.zones.entry(address).or_default();
                if !zones.contains(&zone) {
                    zones.push(zone.clone());
                }
            }
        }
        Ok(replay)
    }

    /// The DNS captured into the corpus directory `root`: its
    /// [`capture_file`](Replay::capture_file) archives, oldest first, so a
    /// later capture's response replaces an earlier one. The pages'
    /// archives hold no DNS and are not read.
    pub fn directory(root: &Path) -> io::Result<Replay> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(CAPTURE_PREFIX) && name.ends_with(CAPTURE_SUFFIX) {
                files.push(entry.path());
            }
        }
        files.sort_by_key(|path| path.file_name().map(std::ffi::OsStr::to_os_string));
        Replay::open(files)
    }

    /// Where a DNS capture made at `stamp`, in nanoseconds since the Unix
    /// epoch, goes in the corpus directory `root`:
    /// `zz-dns-<stamp>.warc.gz`, which sorts after the pages' archives.
    pub fn capture_file(root: &Path, stamp: u128) -> PathBuf {
        root.join(format!("{CAPTURE_PREFIX}{stamp}{CAPTURE_SUFFIX}"))
    }

    /// When the newest recorded response was captured, by its
    /// `WARC-Date`, or `None` when the capture holds no response.
    pub fn newest_capture(&self) -> Option<time::OffsetDateTime> {
        self.newest
    }

    /// The recorded response to `question` sent to `server`, from the
    /// newest capture that holds one from that server or from a server
    /// that answers it from the same zone: in that capture, the server's
    /// own, or else another's.
    fn reply(&self, server: SocketAddr, question: &Question) -> Option<&Message> {
        let name = &question.name;
        // An authoritative server answers from the deepest zone it serves
        // that holds the name (RFC 1034 §4.3.2 step 2), and DS from the
        // zone above the name's own when it serves one, or else from the
        // name's own (RFC 4035 §3.1.4.1).
        let parents = question.qtype == RecordType::DS && !name.is_root();
        let answering = |address: IpAddr| {
            let holding = || {
                self.zones
                    .get(&address)
                    .into_iter()
                    .flatten()
                    .filter(|zone| zone.zone_of(name))
            };
            holding()
                .filter(|zone| !(parents && *zone == name))
                .max_by_key(|zone| label_count(zone))
                .or_else(|| holding().max_by_key(|zone| label_count(zone)))
        };
        // Within a capture the server's own response ranks above any
        // other.
        let rank = |from: &SocketAddr| {
            if *from == server {
                return Some(true);
            }
            let zone = answering(server.ip())?;
            (from.port() == server.port() && answering(from.ip()) == Some(zone)).then_some(false)
        };
        self.replies
            .get(question)?
            .iter()
            .filter_map(|(from, reply, capture)| Some(((*capture, rank(from)?), reply)))
            .max_by_key(|(key, _)| *key)
            .map(|(_, reply)| reply)
    }
}

/// Notes the NS records and the addresses in `message`.
fn learn(
    message: &Message,
    ns: &mut HashSet<(LowerName, LowerName)>,
    addresses: &mut HashMap<LowerName, Vec<IpAddr>>,
) {
    let records = message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals);
    for record in records {
        let owner = LowerName::new(&record.name);
        match &record.data {
            RData::NS(target) => {
                ns.insert((owner, LowerName::new(&target.0)));
            }
            RData::A(address) => note(addresses, owner, IpAddr::V4(address.0)),
            RData::AAAA(address) => note(addresses, owner, IpAddr::V6(address.0)),
            _ => {}
        }
    }
}

fn note(addresses: &mut HashMap<LowerName, Vec<IpAddr>>, owner: LowerName, address: IpAddr) {
    let known = addresses.entry(owner).or_default();
    if !known.contains(&address) {
        known.push(address);
    }
}

impl Upstream for Replay {
    fn lookup<'a>(
        &'a self,
        _fcx: &'a Cx,
        lookup: Lookup,
    ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
        let looked = self
            .reply(lookup.server, &Question::of(&lookup.question))
            .map_or(Looked::NoReply, |reply| Looked::Response(reply.clone()));
        Box::pin(ready(looked))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ech_names_require_a_complete_recognized_configuration() {
        use fictionet::stdlib::protocols::dns::rr::rdata::svcb::{
            EchConfigList, SvcParamKey, SvcParamValue,
        };
        use fictionet::stdlib::protocols::dns::rr::rdata::{HTTPS, SVCB};
        let public = b"public.example";
        let mut config = vec![0, 0, 32, 0, 1, 1, 0, 4, 0, 1, 0, 1, 0, public.len() as u8];
        config.extend_from_slice(public);
        config.extend_from_slice(&[0, 0]);
        let mut list = ((config.len() + 4) as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&[0xfe, 0x0d]);
        list.extend_from_slice(&(config.len() as u16).to_be_bytes());
        list.extend_from_slice(&config);
        let record = |bytes: Vec<u8>| {
            RData::HTTPS(HTTPS(SVCB::new(
                1,
                Name::root(),
                vec![(
                    SvcParamKey::EchConfigList,
                    SvcParamValue::EchConfigList(EchConfigList(bytes)),
                )],
            )))
        };
        assert_eq!(
            ech_public_names(&record(list.clone())),
            vec![LowerName::new(
                &Name::from_ascii("public.example.").unwrap()
            )]
        );
        for length in 0..list.len() {
            assert!(ech_public_names(&record(list[..length].to_vec())).is_empty());
        }
        let mut trailing = list.clone();
        trailing.push(0);
        assert!(ech_public_names(&record(trailing)).is_empty());
        list[2] = 0xff;
        assert!(ech_public_names(&record(list)).is_empty());
    }
}
