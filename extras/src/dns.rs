//! DNS exchanges kept in WARC archives beside captured pages, and played
//! back as a [`Source`].
//!
//! [`Capture`] records what another source, such as the host's live
//! source, answers, and writes each exchange as two WARC records: a
//! `request` holding the query and a `response` holding the reply, both as
//! `application/dns-message` (RFC 8484 §6), with the server and the
//! question in a `dns:` target URI (RFC 4501), for example
//! `dns://192.5.6.30/example.com.?type=NS`. [`Replay`] reads those records
//! back and answers the same questions to the same servers, so a world
//! resolves names as it did when the pages were captured.
//!
//! A question the capture does not hold gets no reply: the simulated
//! server stays silent, and a resolver caches a failure for the name, not
//! a negative answer.

use std::collections::{HashMap, HashSet};
use std::future::{Future, ready};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;

use fictionet::Cx;
use fictionet::stdlib::protocols::dns::op::Message;
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, Name, RData, RecordType};
use fictionet::stdlib::protocols::dns::{Parsed, Request, read_message, restore};
use fictionet::stdlib::services::dns::authority::{Ask, Observed};
use fictionet::stdlib::services::serve::Transport;
use fictionet::stdlib::world::net::dns::{Question, Source};
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

/// A source that keeps every reply another source gives, to write them to
/// a WARC archive with [`Capture::write`].
///
/// It answers exactly as the source it wraps. Only replies are kept: a
/// server that was unreachable or silent leaves nothing, and [`Replay`]
/// answers such a question with silence, as it does any question the
/// capture lacks.
pub struct Capture<S> {
    source: S,
    exchanges: Mutex<Vec<Exchange>>,
}

/// One question and the reply it got.
struct Exchange {
    ask: Ask,
    reply: Vec<u8>,
    at: time::OffsetDateTime,
}

impl<S: Source> Capture<S> {
    /// `source`, with its replies kept.
    pub fn new(source: S) -> Capture<S> {
        Capture {
            source,
            exchanges: Mutex::new(Vec::new()),
        }
    }

    /// Appends the replies kept since the last write to the archive at
    /// `path`, and forgets them. Each becomes a `request` record with the
    /// query as it was sent, then a `response` record with the reply as it
    /// arrived, which names the request in `WARC-Concurrent-To`. A query
    /// that does not parse as a question names nothing [`Replay`] could
    /// match, so its exchange is left out.
    pub fn write(&self, path: &Path) -> io::Result<()> {
        let exchanges = std::mem::take(&mut *self.exchanges.lock());
        for exchange in exchanges {
            let Some(target) = target_uri(&exchange.ask) else {
                continue;
            };
            let date = warc::date(exchange.at);
            let address = exchange.ask.server.ip().to_string();
            let request = warc::append_record(
                path,
                &[
                    ("WARC-Type", "request"),
                    ("WARC-Target-URI", &target),
                    ("WARC-Date", &date),
                    ("WARC-IP-Address", &address),
                    ("Content-Type", DNS_MESSAGE),
                ],
                &exchange.ask.query,
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
                &exchange.reply,
            )?;
        }
        Ok(())
    }
}

impl<S: Source> Source for Capture<S> {
    fn ask<'a>(
        &'a self,
        fcx: &'a Cx,
        ask: Ask,
    ) -> Pin<Box<dyn Future<Output = Observed> + Send + 'a>> {
        Box::pin(async move {
            let observed = self.source.ask(fcx, ask.clone()).await;
            if let Observed::Reply(reply) = &observed {
                self.exchanges.lock().push(Exchange {
                    ask,
                    reply: reply.clone(),
                    at: time::OffsetDateTime::now_utc(),
                });
            }
            observed
        })
    }
}

/// The `dns:` URI of `ask` (RFC 4501 §2): the server as the authority,
/// the question's name, and its type, with its class when that is not IN.
fn target_uri(ask: &Ask) -> Option<String> {
    let Parsed::Request(request) = Request::parse(&ask.query, ask.transport) else {
        return None;
    };
    let server = if ask.server.port() == DNS_PORT {
        match ask.server.ip() {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        }
    } else {
        ask.server.to_string()
    };
    let question = &request.question;
    let mut uri = format!(
        "dns://{server}/{}?type={}",
        uri_name(question.name()),
        mnemonic(question.query_type())
    );
    if question.query_class() != DNSClass::IN {
        uri.push_str(";class=");
        uri.push_str(&question.query_class().to_string());
    }
    Some(uri)
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

/// A source that answers from DNS exchanges recorded by [`Capture`].
///
/// A question gets the reply recorded for the same question (its name,
/// ignoring case, its type and class, and whether it carried EDNS and the
/// DO bit) sent to the same server, with the asker's ID and question case
/// put back ([`restore`]) and its RD and CD bits copied in, as the
/// authority would have copied them (RFC 1035 §4.1.1, RFC 4035 §3.1.6).
/// Every other byte is the recorded server's. A question without DO, as
/// `dig` asks by default, that the capture holds only with DO gets the
/// recorded reply without its DNSSEC records, and without its OPT record
/// when the query had none, as the server would have sent it.
///
/// The servers named in one NS RRset serve the same zone, so for a
/// question at or below that zone a reply recorded from one of them
/// answers for the others too: a resolver that picks another root letter
/// than the capture did, or another of a domain's name servers, gets the
/// recorded reply. The capture's own NS records and addresses say which
/// servers those are.
///
/// A corpus holds several captures, and a world's clock stands at the
/// newest one, so the reply comes from the newest capture that holds one
/// for the server or a server of its zone: an older capture's RRSIGs may
/// have expired by that clock. Within one capture, the server's own reply
/// comes first, then the reply of the server sharing the deepest zone.
///
/// Anything else gets [`Observed::Timeout`], as from a server that never
/// replies.
#[derive(Debug, Default)]
pub struct Replay {
    /// The replies to each question: the server that sent each, the
    /// reply, and the capture it came from, counted in the order the
    /// archives were read.
    replies: HashMap<Question, Vec<(SocketAddr, Vec<u8>, usize)>>,
    /// The zones each server address serves, by the capture's NS records.
    zones: HashMap<IpAddr, Vec<LowerName>>,
    /// The owners of the A records in the answers to recorded A questions.
    addressed: HashSet<LowerName>,
    /// The target of each CNAME record in a recorded answer, by owner.
    aliases: HashMap<LowerName, LowerName>,
    /// When the newest recorded reply was captured.
    newest: Option<time::OffsetDateTime>,
}

impl Replay {
    /// The DNS exchanges in the archives `files`, in order: a later reply
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
                if let Ok(message) = read_message(&reply) {
                    learn(&message, &mut ns, &mut addresses);
                    let asks_address = request.question.query_type() == RecordType::A;
                    for record in &message.answers {
                        let owner = LowerName::new(&record.name);
                        match &record.data {
                            RData::A(_) if asks_address => {
                                replay.addressed.insert(owner);
                            }
                            RData::CNAME(target) => {
                                replay.aliases.insert(owner, LowerName::new(&target.0));
                            }
                            _ => {}
                        }
                    }
                }
                if let Some(text) = fields.get("warc-date") {
                    let date = warc::parse_date(text)
                        .ok_or_else(|| invalid("a DNS response whose WARC-Date is no date"))?;
                    replay.newest = replay.newest.max(Some(date));
                }
                let replies = replay.replies.entry(Question::of(&request)).or_default();
                replies.retain(|(recorded, _, _)| *recorded != server);
                replies.push((server, reply, capture));
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
    /// later capture's reply replaces an earlier one. The pages' archives
    /// hold no DNS and are not read.
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

    /// Whether the recorded replies give `name` an IPv4 address: an A
    /// record of its own in the answer to an A question, or one at the end
    /// of its CNAME chain. A chain that crosses zones is recorded as
    /// several replies, each alias from its own zone's servers and the
    /// address from the last one's, and is followed across them.
    pub fn resolves(&self, name: &LowerName) -> bool {
        let mut seen = HashSet::new();
        let mut name = name;
        loop {
            if self.addressed.contains(name) {
                return true;
            }
            // A chain that comes back to a name it passed has no end.
            if !seen.insert(name) {
                return false;
            }
            match self.aliases.get(name) {
                Some(target) => name = target,
                None => return false,
            }
        }
    }

    /// When the newest recorded reply was captured, by its `WARC-Date`, or
    /// `None` when the capture holds no reply.
    pub fn newest_capture(&self) -> Option<time::OffsetDateTime> {
        self.newest
    }

    /// The reply for `request` sent to `server`: the recorded reply to the
    /// same question, or for a query without DO the reply recorded for
    /// the same question with DO, with what DO brought taken out. The
    /// capture asks every question with DO, as the world's resolvers do,
    /// and a real server answers a query without it with the same records
    /// less the DNSSEC ones (RFC 4035 §3.2.1), a referral's DS RRset among
    /// them (RFC 4035 §3.1.4.1), and, for a query with no OPT record, no
    /// OPT record either (RFC 6891 §7).
    fn reply_to(&self, server: SocketAddr, request: &Request) -> Option<Vec<u8>> {
        let question = Question::of(request);
        if let Some(reply) = self.reply(server, &question) {
            return Some(reply.to_vec());
        }
        if question.dnssec_ok {
            return None;
        }
        let signed = Question {
            edns: true,
            dnssec_ok: true,
            ..question
        };
        let mut message = read_message(self.reply(server, &signed)?).ok()?;
        let asked = request.question.query_type();
        // A referral carries the child's DS RRset only for DO
        // (RFC 4035 §3.1.4.1).
        let keep = |record: &fictionet::stdlib::protocols::dns::rr::Record| {
            let rtype = record.record_type();
            rtype == asked
                || !matches!(
                    rtype,
                    RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3 | RecordType::DS
                )
        };
        message.answers.retain(keep);
        message.authorities.retain(keep);
        message.additionals.retain(keep);
        match (&request.edns, &mut message.edns) {
            (None, edns) => *edns = None,
            (Some(_), Some(edns)) => {
                edns.set_dnssec_ok(false);
            }
            (Some(_), None) => {}
        }
        message.to_vec().ok()
    }

    /// The recorded reply to `question` sent to `server`, from the newest
    /// capture that holds one from that server or from a server sharing a
    /// zone with it that holds the question's name: in that capture, the
    /// server's own, or else the one from the server sharing the deepest
    /// such zone.
    fn reply(&self, server: SocketAddr, question: &Question) -> Option<&[u8]> {
        let name = &question.name;
        let serving = |address: IpAddr| {
            self.zones
                .get(&address)
                .into_iter()
                .flatten()
                .filter(|zone| zone.zone_of(name))
        };
        // Within a capture the server's own reply ranks above any other.
        let rank = |from: &SocketAddr| {
            if *from == server {
                return Some(u8::MAX);
            }
            if from.port() != server.port() {
                return None;
            }
            serving(server.ip())
                .filter(|zone| serving(from.ip()).any(|other| other == *zone))
                .map(|zone| zone.num_labels())
                .max()
        };
        self.replies
            .get(question)?
            .iter()
            .filter_map(|(from, reply, capture)| Some(((*capture, rank(from)?), reply)))
            .max_by_key(|(key, _)| *key)
            .map(|(_, reply)| reply.as_slice())
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

impl Source for Replay {
    fn ask<'a>(
        &'a self,
        _fcx: &'a Cx,
        ask: Ask,
    ) -> Pin<Box<dyn Future<Output = Observed> + Send + 'a>> {
        let Parsed::Request(request) = Request::parse(&ask.query, ask.transport) else {
            return Box::pin(ready(Observed::Timeout));
        };
        let observed = self
            .reply_to(ask.server, &request)
            .and_then(|reply| restore(&reply, &request).ok())
            .map_or(Observed::Timeout, |mut bytes| {
                // RD is the low bit of the third header octet, CD bit 4 of
                // the fourth (RFC 1035 §4.1.1, RFC 4035 §3.1.6). `restore`
                // accepts only replies with a whole header.
                bytes[2] = (bytes[2] & !0x01) | u8::from(request.rd);
                bytes[3] = (bytes[3] & !0x10) | (u8::from(request.cd) << 4);
                Observed::Reply(bytes)
            });
        Box::pin(ready(observed))
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
    use fictionet::stdlib::protocols::dns::op::{Edns, MessageType, OpCode, Query};
    use fictionet::stdlib::protocols::dns::rr::Record;
    use fictionet::stdlib::protocols::dns::rr::rdata::{A, CNAME, NS};
    use fictionet::stdlib::services::serve::Transport;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const A_ROOT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), 53);
    const B_ROOT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)), 53);
    const COM: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 5, 6, 30)), 53);

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    /// A query for `qname` and `kind` with `id`, RD clear, and EDNS with
    /// DO set when `dnssec`.
    fn query(id: u16, qname: &str, kind: RecordType, dnssec: Option<bool>) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(name(qname), kind));
        if let Some(dnssec_ok) = dnssec {
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            edns.set_dnssec_ok(dnssec_ok);
            message.set_edns(edns);
        }
        message.to_vec().unwrap()
    }

    fn ask(server: SocketAddr, query: Vec<u8>) -> Ask {
        Ask {
            server,
            transport: Transport::Udp,
            query,
        }
    }

    /// A small hierarchy as a source: the root servers refer `com` to one
    /// server, which answers `www.example.com A`. It counts the questions
    /// it is asked.
    #[derive(Default)]
    struct Hierarchy {
        asked: AtomicUsize,
    }

    impl Hierarchy {
        fn answer(&self, ask: &Ask) -> Observed {
            let Parsed::Request(request) = Request::parse(&ask.query, ask.transport) else {
                return Observed::Timeout;
            };
            let mut reply = Message::response(request.message.metadata.id, OpCode::Query);
            reply.metadata.recursion_desired = request.rd;
            reply.add_query(request.question.clone());
            let qname = request.question.name().clone();
            if ask.server == A_ROOT || ask.server == B_ROOT {
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
            } else if ask.server == COM {
                reply.metadata.authoritative = true;
                reply.add_answer(Record::from_rdata(
                    qname,
                    300,
                    RData::A(A::new(192, 0, 2, 80)),
                ));
            } else {
                return Observed::Unreachable;
            }
            if let Some(edns) = &request.edns {
                let mut out = Edns::new();
                out.set_max_payload(1232);
                out.set_dnssec_ok(edns.dnssec_ok);
                reply.set_edns(out);
            }
            Observed::Reply(reply.to_vec().unwrap())
        }
    }

    impl Source for Hierarchy {
        fn ask<'a>(
            &'a self,
            _fcx: &'a Cx,
            ask: Ask,
        ) -> Pin<Box<dyn Future<Output = Observed> + Send + 'a>> {
            self.asked.fetch_add(1, Ordering::Relaxed);
            Box::pin(ready(self.answer(&ask)))
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

    /// Captures `asks` through a [`Hierarchy`] into `path`.
    async fn capture(fcx: &Cx, path: &Path, asks: Vec<Ask>) -> Vec<Observed> {
        let capture = Capture::new(Hierarchy::default());
        let mut observed = Vec::new();
        for ask in asks {
            observed.push(capture.ask(fcx, ask).await);
        }
        capture.write(path).unwrap();
        observed
    }

    fn reply(observed: Observed) -> Message {
        match observed {
            Observed::Reply(bytes) => Message::from_vec(&bytes).unwrap(),
            other => panic!("expected a reply, got {other:?}"),
        }
    }

    #[test]
    fn replay_answers_captured_asks_with_the_asker_id_and_times_out_on_others() {
        let path = archive("replay");
        run(async move |fcx| {
            let www = query(7, "www.example.com.", RecordType::A, Some(true));
            capture(&fcx, &path, vec![ask(COM, www)]).await;
            let replay = Replay::open([path.clone()]).unwrap();
            assert!(replay.resolves(&LowerName::new(&name("www.example.com."))));
            assert!(!replay.resolves(&LowerName::new(&name("mail.example.com."))));

            let mut asked = query(0x4242, "WwW.ExAmPlE.CoM.", RecordType::A, Some(true));
            asked[2] |= 0x01; // RD
            let answer = reply(replay.ask(&fcx, ask(COM, asked)).await);
            assert_eq!(answer.metadata.id, 0x4242);
            assert!(answer.metadata.recursion_desired);
            assert_eq!(answer.queries[0].name().to_ascii(), "WwW.ExAmPlE.CoM.");
            assert_eq!(
                answer.answers[0].data,
                RData::A(A::new(192, 0, 2, 80)),
                "the recorded server's records"
            );

            for other in [
                ask(
                    COM,
                    query(1, "mail.example.com.", RecordType::A, Some(true)),
                ),
                ask(
                    COM,
                    query(1, "www.example.com.", RecordType::AAAA, Some(true)),
                ),
                ask(
                    A_ROOT,
                    query(1, "www.example.com.", RecordType::A, Some(true)),
                ),
            ] {
                assert_eq!(replay.ask(&fcx, other).await, Observed::Timeout);
            }

            // The same question without DO, as `dig` asks, gets the reply
            // the server sends without DO: DO clear in its OPT record, and
            // no OPT record for a query that had none.
            let plain = reply(
                replay
                    .ask(
                        &fcx,
                        ask(
                            COM,
                            query(2, "www.example.com.", RecordType::A, Some(false)),
                        ),
                    )
                    .await,
            );
            assert_eq!(plain.metadata.id, 2);
            assert_eq!(plain.answers[0].data, RData::A(A::new(192, 0, 2, 80)));
            assert!(!plain.edns.unwrap().flags().dnssec_ok);
            let bare = reply(
                replay
                    .ask(
                        &fcx,
                        ask(COM, query(3, "www.example.com.", RecordType::A, None)),
                    )
                    .await,
            );
            assert_eq!(bare.answers[0].data, RData::A(A::new(192, 0, 2, 80)));
            assert!(bare.edns.is_none());
        });
    }

    #[test]
    fn capture_then_replay_gives_the_same_replies() {
        let path = archive("round-trip");
        run(async move |fcx| {
            let asks = vec![
                ask(A_ROOT, query(1, ".", RecordType::NS, Some(true))),
                ask(A_ROOT, query(2, "com.", RecordType::NS, Some(false))),
                ask(COM, query(3, "www.example.com.", RecordType::A, None)),
            ];
            // WARC-Date has whole seconds.
            let before = time::OffsetDateTime::now_utc()
                .replace_nanosecond(0)
                .unwrap();
            let observed = capture(&fcx, &path, asks.clone()).await;
            let replay = Replay::open([path.clone()]).unwrap();
            let newest = replay.newest_capture().expect("a capture time");
            assert!(before <= newest && newest <= time::OffsetDateTime::now_utc());
            for (ask, observed) in asks.into_iter().zip(observed) {
                assert_eq!(replay.ask(&fcx, ask).await, observed);
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

    /// Recorded answers to A questions, where a name's alias leads into
    /// another zone and the address comes from that zone's servers in a
    /// reply of its own.
    struct Aliased;

    impl Source for Aliased {
        fn ask<'a>(
            &'a self,
            _fcx: &'a Cx,
            ask: Ask,
        ) -> Pin<Box<dyn Future<Output = Observed> + Send + 'a>> {
            let Parsed::Request(request) = Request::parse(&ask.query, ask.transport) else {
                return Box::pin(ready(Observed::Timeout));
            };
            let qname = request.question.name().clone();
            let mut reply = Message::response(request.message.metadata.id, OpCode::Query);
            reply.metadata.authoritative = true;
            reply.add_query(request.question.clone());
            let data = match qname.to_ascii().as_str() {
                "www.example.com." => RData::CNAME(CNAME(name("edge.cdn.net."))),
                "loop.example.com." => RData::CNAME(CNAME(name("back.example.com."))),
                "back.example.com." => RData::CNAME(CNAME(name("loop.example.com."))),
                _ => RData::A(A::new(192, 0, 2, 80)),
            };
            reply.add_answer(Record::from_rdata(qname, 300, data));
            Box::pin(ready(Observed::Reply(reply.to_vec().unwrap())))
        }
    }

    #[test]
    fn a_name_resolves_through_an_alias_into_another_zone() {
        let path = archive("cross-zone");
        run(async move |fcx| {
            let cdn = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 53);
            let capture = Capture::new(Aliased);
            for (server, qname) in [
                (COM, "www.example.com."),
                (cdn, "edge.cdn.net."),
                (COM, "loop.example.com."),
                (COM, "back.example.com."),
            ] {
                let asked = ask(server, query(1, qname, RecordType::A, Some(true)));
                capture.ask(&fcx, asked).await;
            }
            capture.write(&path).unwrap();
            let replay = Replay::open([path.clone()]).unwrap();
            let resolves = |text: &str| replay.resolves(&LowerName::new(&name(text)));
            assert!(resolves("www.example.com."));
            assert!(resolves("edge.cdn.net."));
            assert!(!resolves("loop.example.com."));
            assert!(!resolves("mail.example.com."));
        });
    }

    #[test]
    fn a_recorded_reply_answers_for_the_other_servers_of_its_zone() {
        let path = archive("siblings");
        run(async move |fcx| {
            let source = Arc::new(Hierarchy::default());
            let capture = Capture::new(source.clone());
            for ask in [
                ask(A_ROOT, query(1, ".", RecordType::NS, Some(true))),
                ask(A_ROOT, query(2, "com.", RecordType::NS, Some(true))),
            ] {
                capture.ask(&fcx, ask).await;
            }
            capture.write(&path).unwrap();
            let replay = Replay::open([path.clone()]).unwrap();

            // The priming reply names b.root-servers.net at B_ROOT, so B_ROOT
            // serves the root zone and gets A_ROOT's referral for com.
            let referral = reply(
                replay
                    .ask(
                        &fcx,
                        ask(B_ROOT, query(9, "com.", RecordType::NS, Some(true))),
                    )
                    .await,
            );
            assert_eq!(referral.metadata.id, 9);
            assert_eq!(
                referral.authorities[0].data,
                RData::NS(NS(name("a.gtld-servers.net.")))
            );
            // The com server is in no NS RRset of the root zone's, and the
            // capture never asked it this.
            assert_eq!(
                replay
                    .ask(&fcx, ask(COM, query(9, "com.", RecordType::NS, Some(true))))
                    .await,
                Observed::Timeout
            );
            assert_eq!(source.asked.load(Ordering::Relaxed), 2);
        });
    }

    #[test]
    fn target_uris_follow_rfc_4501() {
        let uri =
            |server, qname, kind| target_uri(&ask(server, query(1, qname, kind, None))).unwrap();
        assert_eq!(
            uri(A_ROOT, ".", RecordType::NS),
            "dns://198.41.0.4/.?type=NS"
        );
        assert_eq!(
            uri(COM, "_25._tcp.Mail.example.com.", RecordType::TLSA),
            "dns://192.5.6.30/_25._tcp.Mail.example.com.?type=TLSA"
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
    /// `address`, and with DO refer `com` with a DS RRset.
    struct Roots(Ipv4Addr);

    impl Source for Roots {
        fn ask<'a>(
            &'a self,
            _fcx: &'a Cx,
            ask: Ask,
        ) -> Pin<Box<dyn Future<Output = Observed> + Send + 'a>> {
            let Parsed::Request(request) = Request::parse(&ask.query, ask.transport) else {
                return Box::pin(ready(Observed::Timeout));
            };
            let dnssec_ok = request.edns.is_some_and(|edns| edns.dnssec_ok);
            let mut reply = Message::response(request.message.metadata.id, OpCode::Query);
            reply.add_query(request.question.clone());
            let qname = request.question.name().clone();
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
                if dnssec_ok {
                    let entropy = fictionet::SeededEntropy::new(Seed::from_u64(3));
                    let key = ZoneKey::generate(&entropy, Algorithm::Ed25519, KeyFlags::KSK);
                    let ds = dnssec::ds(&com, &key.dnskey(), DigestType::Sha256);
                    reply.add_authority(Record::from_rdata(
                        com,
                        86400,
                        RData::DNSSEC(DNSSECRData::DS(ds)),
                    ));
                }
                reply.add_additional(Record::from_rdata(
                    server,
                    172800,
                    RData::A(A::new(192, 5, 6, 30)),
                ));
            } else {
                reply.metadata.authoritative = true;
                reply.add_answer(Record::from_rdata(qname, 300, RData::A(A(self.0))));
            }
            if let Some(edns) = &request.edns {
                let mut out = Edns::new();
                out.set_max_payload(1232);
                out.set_dnssec_ok(edns.dnssec_ok);
                reply.set_edns(out);
            }
            Box::pin(ready(Observed::Reply(reply.to_vec().unwrap())))
        }
    }

    /// Captures `asks` through `Roots(address)` into `path`.
    async fn capture_roots(fcx: &Cx, path: &Path, address: Ipv4Addr, asks: Vec<Ask>) {
        let capture = Capture::new(Roots(address));
        for ask in asks {
            capture.ask(fcx, ask).await;
        }
        capture.write(path).unwrap();
    }

    #[test]
    fn the_newest_capture_answers_for_every_server_of_a_zone() {
        let old = archive("older");
        let new = archive("newer");
        let (older, newer) = (old.clone(), new.clone());
        run(async move |fcx| {
            let asks = |server| {
                vec![
                    ask(server, query(1, ".", RecordType::NS, Some(true))),
                    ask(server, query(2, "probe.test.", RecordType::A, Some(true))),
                ]
            };
            capture_roots(&fcx, &older, Ipv4Addr::new(192, 0, 2, 1), asks(B_ROOT)).await;
            capture_roots(&fcx, &newer, Ipv4Addr::new(192, 0, 2, 2), asks(A_ROOT)).await;
            let replay = Replay::open([older, newer]).unwrap();
            // b.root was asked only by the older capture, but a.root, of
            // the same zone, by the newer one, whose RRSIGs the world's
            // clock still finds valid.
            for server in [A_ROOT, B_ROOT, C_ROOT] {
                let probe = ask(server, query(9, "probe.test.", RecordType::A, Some(true)));
                let answer = reply(replay.ask(&fcx, probe).await);
                assert_eq!(
                    answer.answers[0].data,
                    RData::A(A::new(192, 0, 2, 2)),
                    "{server}"
                );
            }
        });
    }

    #[test]
    fn a_referral_without_do_leaves_out_the_ds_rrset() {
        let path = archive("ds");
        run(async move |fcx| {
            let referral = ask(A_ROOT, query(1, "example.com.", RecordType::A, Some(true)));
            capture_roots(&fcx, &path, Ipv4Addr::new(192, 0, 2, 1), vec![referral]).await;
            let replay = Replay::open([path.clone()]).unwrap();
            let plain = ask(A_ROOT, query(2, "example.com.", RecordType::A, Some(false)));
            let referral = reply(replay.ask(&fcx, plain).await);
            let types: Vec<RecordType> = referral
                .authorities
                .iter()
                .map(Record::record_type)
                .collect();
            assert_eq!(types, [RecordType::NS]);
            // Asked for with DO, it keeps it.
            let signed = ask(A_ROOT, query(3, "example.com.", RecordType::A, Some(true)));
            let referral = reply(replay.ask(&fcx, signed).await);
            assert!(
                referral
                    .authorities
                    .iter()
                    .any(|record| record.record_type() == RecordType::DS)
            );
        });
    }
}
