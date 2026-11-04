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
        // zone above the name's own (RFC 4035 §3.1.4.1).
        let parents = question.qtype == RecordType::DS && !name.is_root();
        let answering = |address: IpAddr| {
            self.zones
                .get(&address)
                .into_iter()
                .flatten()
                .filter(|zone| zone.zone_of(name) && !(parents && *zone == name))
                .max_by_key(|zone| label_count(zone))
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
    use fictionet::Seed;
    use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
    use fictionet::stdlib::protocols::dns::dnssec::{
        self, Algorithm, DigestType, KeyFlags, Sign, ZoneKey,
    };
    use fictionet::stdlib::protocols::dns::op::{Edns, OpCode};
    use fictionet::stdlib::protocols::dns::rr::Record;
    use fictionet::stdlib::protocols::dns::rr::rdata::{A, NS};
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const A_ROOT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), 53);
    const B_ROOT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)), 53);
    const COM: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 5, 6, 30)), 53);

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    /// A lookup of `qname` and `kind` at `server`.
    fn lookup(server: SocketAddr, qname: &str, kind: RecordType) -> Lookup {
        Lookup::new(
            server,
            LowerName::from(Name::root()),
            &Query::query(name(qname), kind),
        )
    }

    /// A response to `lookup`, with its question, an OPT record with DO,
    /// and nothing else yet.
    fn response_to(lookup: &Lookup) -> Message {
        let mut reply = Message::response(0, OpCode::Query);
        reply.add_query(lookup.question.clone());
        let mut edns = Edns::new();
        edns.set_max_payload(1232).set_dnssec_ok(true);
        reply.set_edns(edns);
        reply
    }

    /// A small hierarchy as an upstream: the root servers refer `com` to
    /// one server, which answers `www.example.com A`. It counts the
    /// lookups it is given.
    #[derive(Default)]
    struct Hierarchy {
        asked: AtomicUsize,
    }

    impl Hierarchy {
        fn answer(&self, lookup: &Lookup) -> Looked {
            let mut reply = response_to(lookup);
            let qname = lookup.question.name().clone();
            if lookup.server == A_ROOT || lookup.server == B_ROOT {
                if qname.is_root() {
                    reply.metadata.authoritative = true;
                    for (letter, address) in [("a", A_ROOT), ("b", B_ROOT)] {
                        let server = name(&format!("{letter}.root-servers.net."));
                        reply.add_answer(Record::from_rdata(
                            Name::root(),
                            518400,
                            RData::NS(NS(server.clone())),
                        ));
                        let IpAddr::V4(ip) = address.ip() else {
                            unreachable!()
                        };
                        reply.add_additional(Record::from_rdata(server, 518400, RData::A(A(ip))));
                    }
                } else {
                    let server = name("a.gtld-servers.net.");
                    reply.add_authority(Record::from_rdata(
                        name("com."),
                        172800,
                        RData::NS(NS(server.clone())),
                    ));
                    reply.add_additional(Record::from_rdata(
                        server,
                        172800,
                        RData::A(A::new(192, 5, 6, 30)),
                    ));
                }
            } else if lookup.server == COM {
                reply.metadata.authoritative = true;
                reply.add_answer(Record::from_rdata(
                    qname,
                    300,
                    RData::A(A::new(192, 0, 2, 80)),
                ));
            } else {
                return Looked::Unreachable;
            }
            Looked::Response(reply)
        }
    }

    impl Upstream for Hierarchy {
        fn lookup<'a>(
            &'a self,
            _fcx: &'a Cx,
            lookup: Lookup,
        ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
            self.asked.fetch_add(1, Ordering::Relaxed);
            Box::pin(ready(self.answer(&lookup)))
        }
    }

    /// A fresh archive path for one test.
    fn archive(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fictionet-dns-{test}-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("dns.warc.gz")
    }

    fn run<F: Future<Output = ()> + Send + 'static>(test: impl FnOnce(Cx) -> F + Send) {
        fictionet::block_on(fictionet::run(Seed::from_u64(1), |fcx| {
            let test = test(fcx);
            async move {
                test.await;
                Ok(())
            }
        }))
        .unwrap();
    }

    /// Captures `lookups` through a [`Hierarchy`] into `path`.
    async fn capture(fcx: &Cx, path: &Path, lookups: Vec<Lookup>) -> Vec<Looked> {
        let capture = Capture::new(Hierarchy::default());
        let mut looked = Vec::new();
        for lookup in lookups {
            looked.push(capture.lookup(fcx, lookup).await);
        }
        capture.write(path).unwrap();
        looked
    }

    fn reply(looked: Looked) -> Message {
        match looked {
            Looked::Response(response) => response,
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn replay_gives_captured_responses_and_no_reply_to_other_lookups() {
        let path = archive("replay");
        run(async move |fcx| {
            let www = lookup(COM, "www.example.com.", RecordType::A);
            capture(&fcx, &path, vec![www]).await;
            let replay = Replay::open([path.clone()]).unwrap();

            let asked = lookup(COM, "WwW.ExAmPlE.CoM.", RecordType::A);
            let answer = reply(replay.lookup(&fcx, asked).await);
            assert_eq!(
                answer.answers[0].data,
                RData::A(A::new(192, 0, 2, 80)),
                "the recorded server's records"
            );

            for other in [
                lookup(COM, "mail.example.com.", RecordType::A),
                lookup(COM, "www.example.com.", RecordType::AAAA),
                lookup(A_ROOT, "www.example.com.", RecordType::A),
            ] {
                assert_eq!(replay.lookup(&fcx, other).await, Looked::NoReply);
            }
        });
    }

    #[test]
    fn capture_then_replay_gives_the_same_responses() {
        let path = archive("round-trip");
        run(async move |fcx| {
            let lookups = vec![
                lookup(A_ROOT, ".", RecordType::NS),
                lookup(A_ROOT, "com.", RecordType::NS),
                lookup(COM, "www.example.com.", RecordType::A),
            ];
            // WARC-Date has whole seconds.
            let before = time::OffsetDateTime::now_utc()
                .replace_nanosecond(0)
                .unwrap();
            let looked = capture(&fcx, &path, lookups.clone()).await;
            let replay = Replay::open([path.clone()]).unwrap();
            let newest = replay.newest_capture().expect("a capture time");
            assert!(before <= newest && newest <= time::OffsetDateTime::now_utc());
            for (lookup, looked) in lookups.into_iter().zip(looked) {
                assert_eq!(replay.lookup(&fcx, lookup).await, looked);
            }

            // Pages and DNS share capture files: each reader skips the
            // other's records.
            let page = warc::Response {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: bytes::Bytes::from_static(b"hello"),
            };
            let mut pages = warc::Archive::default();
            pages
                .append(&path, "https://www.example.com/", &page)
                .unwrap();
            let pages = warc::Archive::open([path.clone()]).unwrap();
            assert_eq!(
                pages.urls().collect::<Vec<_>>(),
                ["https://www.example.com/"]
            );
            let replay = Replay::open([path.clone()]).unwrap();
            assert_eq!(replay.newest_capture(), Some(newest));
        });
    }

    /// Every form of WARC-Date that WARC 1.1 allows names its instant, and
    /// anything else names none.
    #[test]
    fn warc_dates_read_in_every_w3c_form() {
        let at = |text: &str| warc::parse_date(text).map(|at| at.unix_timestamp());
        assert_eq!(at("2026-11-02T16:06:07Z"), Some(1_793_635_567));
        assert_eq!(at("2026-11-02T16:06:07.25Z"), Some(1_793_635_567));
        assert_eq!(at("2026-11-02T17:06:07+01:00"), Some(1_793_635_567));
        assert_eq!(at("2026-11-02T16:06Z"), Some(1_793_635_560));
        assert_eq!(at("2026-11-02"), Some(1_793_577_600));
        assert_eq!(at("2026-11"), Some(1_793_491_200));
        assert_eq!(at("2026"), Some(1_767_225_600));
        for wrong in [
            "",
            "yesterday",
            "2026-13-01",
            "2026-11-02T16:06:07",
            "26-11-02",
        ] {
            assert_eq!(at(wrong), None, "{wrong}");
        }
    }

    #[test]
    fn a_recorded_reply_answers_for_the_other_servers_of_its_zone() {
        let path = archive("siblings");
        run(async move |fcx| {
            let upstream = Arc::new(Hierarchy::default());
            let capture = Capture::new(upstream.clone());
            for lookup in [
                lookup(A_ROOT, ".", RecordType::NS),
                lookup(A_ROOT, "com.", RecordType::NS),
            ] {
                capture.lookup(&fcx, lookup).await;
            }
            capture.write(&path).unwrap();
            let replay = Replay::open([path.clone()]).unwrap();

            // The priming reply names b.root-servers.net at B_ROOT, so B_ROOT
            // serves the root zone and gets A_ROOT's referral for com.
            let referral = reply(
                replay
                    .lookup(&fcx, lookup(B_ROOT, "com.", RecordType::NS))
                    .await,
            );
            assert_eq!(
                referral.authorities[0].data,
                RData::NS(NS(name("a.gtld-servers.net.")))
            );
            // The com server is in no NS RRset of the root zone's, and the
            // capture never asked it this.
            assert_eq!(
                replay
                    .lookup(&fcx, lookup(COM, "com.", RecordType::NS))
                    .await,
                Looked::NoReply
            );
            assert_eq!(upstream.asked.load(Ordering::Relaxed), 2);
        });
    }

    /// Two root servers of which only a.root also serves `arpa`, as
    /// a.ns.arpa: it answers `arpa NS` from that zone, and `arpa DS`, the
    /// root zone's data, from the root zone.
    struct ArpaAtA;

    impl Upstream for ArpaAtA {
        fn lookup<'a>(
            &'a self,
            _fcx: &'a Cx,
            lookup: Lookup,
        ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
            let mut reply = response_to(&lookup);
            reply.metadata.authoritative = true;
            let qname = lookup.question.name().clone();
            let glue = |reply: &mut Message, server: &str, address: SocketAddr| {
                let IpAddr::V4(ip) = address.ip() else {
                    unreachable!("the servers here have IPv4 addresses")
                };
                reply.add_additional(Record::from_rdata(name(server), 518400, RData::A(A(ip))));
            };
            if qname.is_root() {
                for (letter, address) in [("a", A_ROOT), ("b", B_ROOT)] {
                    let server = format!("{letter}.root-servers.net.");
                    reply.add_answer(Record::from_rdata(
                        Name::root(),
                        518400,
                        RData::NS(NS(name(&server))),
                    ));
                    glue(&mut reply, &server, address);
                }
            } else if lookup.question.query_type() == RecordType::NS {
                reply.add_answer(Record::from_rdata(
                    qname,
                    518400,
                    RData::NS(NS(name("a.ns.arpa."))),
                ));
                glue(&mut reply, "a.ns.arpa.", A_ROOT);
            }
            Box::pin(ready(Looked::Response(reply)))
        }
    }

    #[test]
    fn a_recorded_reply_answers_only_for_servers_answering_from_its_zone() {
        let path = archive("arpa");
        run(async move |fcx| {
            let capture = Capture::new(ArpaAtA);
            for lookup in [
                lookup(A_ROOT, ".", RecordType::NS),
                lookup(A_ROOT, "arpa.", RecordType::NS),
                lookup(A_ROOT, "arpa.", RecordType::DS),
            ] {
                capture.lookup(&fcx, lookup).await;
            }
            capture.write(&path).unwrap();
            let replay = Replay::open([path.clone()]).unwrap();

            let own = reply(
                replay
                    .lookup(&fcx, lookup(A_ROOT, "arpa.", RecordType::NS))
                    .await,
            );
            assert_eq!(own.answers[0].data, RData::NS(NS(name("a.ns.arpa."))));
            // b.root serves the root zone alone, and answers `arpa NS`
            // from it, not from `arpa` as a.root did.
            assert_eq!(
                replay
                    .lookup(&fcx, lookup(B_ROOT, "arpa.", RecordType::NS))
                    .await,
                Looked::NoReply
            );
            // Both answer `arpa DS` from the root zone.
            let ds = reply(
                replay
                    .lookup(&fcx, lookup(B_ROOT, "arpa.", RecordType::DS))
                    .await,
            );
            assert_eq!(ds.queries[0].query_type(), RecordType::DS);
        });
    }

    #[test]
    fn target_uris_follow_rfc_4501() {
        let uri = |server, qname, kind| target_uri(&lookup(server, qname, kind));
        assert_eq!(
            uri(A_ROOT, ".", RecordType::NS),
            "dns://198.41.0.4/.?type=NS"
        );
        assert_eq!(
            uri(COM, "_25._tcp.mail.example.com.", RecordType::TLSA),
            "dns://192.5.6.30/_25._tcp.mail.example.com.?type=TLSA"
        );
        let v6 = SocketAddr::new("2001:503:ba3e::2:30".parse().unwrap(), 5353);
        assert_eq!(
            uri(v6, "a.example.", RecordType::Unknown(65280)),
            "dns://[2001:503:ba3e::2:30]:5353/a.example.?type=65280"
        );
        assert_eq!(
            uri_server("dns://[2001:503:ba3e::2:30]:5353/a.example.?type=A"),
            Some(v6)
        );
        assert_eq!(uri_server("DNS://198.41.0.4/.?type=NS"), Some(A_ROOT));
        assert_eq!(uri_server("dns:www.example.com?type=A"), None);
    }

    const C_ROOT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 33, 4, 12)), 53);

    /// Three root servers that answer every name but the root with
    /// `address`, and refer `com` with a DS RRset.
    struct Roots(Ipv4Addr);

    impl Upstream for Roots {
        fn lookup<'a>(
            &'a self,
            _fcx: &'a Cx,
            lookup: Lookup,
        ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
            let mut reply = response_to(&lookup);
            let qname = lookup.question.name().clone();
            if qname.is_root() {
                reply.metadata.authoritative = true;
                for (letter, address) in [("a", A_ROOT), ("b", B_ROOT), ("c", C_ROOT)] {
                    let server = name(&format!("{letter}.root-servers.net."));
                    reply.add_answer(Record::from_rdata(
                        Name::root(),
                        518400,
                        RData::NS(NS(server.clone())),
                    ));
                    let IpAddr::V4(ip) = address.ip() else {
                        unreachable!("the root servers here have IPv4 addresses")
                    };
                    reply.add_additional(Record::from_rdata(server, 518400, RData::A(A(ip))));
                }
            } else if qname == name("example.com.") {
                let com = name("com.");
                let server = name("a.gtld-servers.net.");
                reply.add_authority(Record::from_rdata(
                    com.clone(),
                    172800,
                    RData::NS(NS(server.clone())),
                ));
                let entropy = fictionet::SeededEntropy::new(Seed::from_u64(3));
                let key = ZoneKey::generate(&entropy, Algorithm::Ed25519, KeyFlags::KSK);
                let ds = dnssec::ds(&com, &key.dnskey(), DigestType::Sha256);
                reply.add_authority(Record::from_rdata(
                    com,
                    86400,
                    RData::DNSSEC(DNSSECRData::DS(ds)),
                ));
                reply.add_additional(Record::from_rdata(
                    server,
                    172800,
                    RData::A(A::new(192, 5, 6, 30)),
                ));
            } else {
                reply.metadata.authoritative = true;
                reply.add_answer(Record::from_rdata(qname, 300, RData::A(A(self.0))));
            }
            Box::pin(ready(Looked::Response(reply)))
        }
    }

    /// Captures `lookups` through `Roots(address)` into `path`.
    async fn capture_roots(fcx: &Cx, path: &Path, address: Ipv4Addr, lookups: Vec<Lookup>) {
        let capture = Capture::new(Roots(address));
        for lookup in lookups {
            capture.lookup(fcx, lookup).await;
        }
        capture.write(path).unwrap();
    }

    #[test]
    fn the_newest_capture_answers_for_every_server_of_a_zone() {
        let old = archive("older");
        let new = archive("newer");
        let (older, newer) = (old.clone(), new.clone());
        run(async move |fcx| {
            let lookups = |server| {
                vec![
                    lookup(server, ".", RecordType::NS),
                    lookup(server, "probe.test.", RecordType::A),
                ]
            };
            capture_roots(&fcx, &older, Ipv4Addr::new(192, 0, 2, 1), lookups(B_ROOT)).await;
            capture_roots(&fcx, &newer, Ipv4Addr::new(192, 0, 2, 2), lookups(A_ROOT)).await;
            let replay = Replay::open([older, newer]).unwrap();
            // b.root was asked only by the older capture, but a.root, of
            // the same zone, by the newer one, whose RRSIGs the world's
            // clock still finds valid.
            for server in [A_ROOT, B_ROOT, C_ROOT] {
                let probe = lookup(server, "probe.test.", RecordType::A);
                let answer = reply(replay.lookup(&fcx, probe).await);
                assert_eq!(
                    answer.answers[0].data,
                    RData::A(A::new(192, 0, 2, 2)),
                    "{server}"
                );
            }
        });
    }

    #[test]
    fn a_referral_keeps_its_ds_rrset() {
        let path = archive("ds");
        run(async move |fcx| {
            let referral = lookup(A_ROOT, "example.com.", RecordType::A);
            capture_roots(
                &fcx,
                &path,
                Ipv4Addr::new(192, 0, 2, 1),
                vec![referral.clone()],
            )
            .await;
            let replay = Replay::open([path.clone()]).unwrap();
            let referral = reply(replay.lookup(&fcx, referral).await);
            assert!(
                referral
                    .authorities
                    .iter()
                    .any(|record| record.record_type() == RecordType::DS)
            );
        });
    }
}
