//! A DNS query as a server receives it, checked in one fixed order.
//!
//! [`Request::parse`] turns the bytes of one query into exactly one of
//! three outcomes: a [`Request`] to answer, a [`Reject`](Parsed::Reject)
//! reply to send as it is, or [`Silent`](Parsed::Silent) for bytes that
//! get no reply at all. A server that wants to bend one rule, such as
//! answering EDNS versions above 0 instead of sending BADVERS
//! (RFC 6891 §6.1.3), wraps `parse` and changes the outcome.

use super::op::{
    DEFAULT_MAX_PAYLOAD_LEN, Edns, Header, Message, MessageType, Metadata, OpCode, Query,
    ResponseCode,
};
use super::rr::rdata::opt::EdnsCode;
use super::rr::rdata::tsig::TsigError;
use super::rr::rdata::{NULL, TSIG};
use super::rr::{DNSClass, Name, RData, Record, RecordType};
use super::serialize::binary::{BinDecodable, BinDecoder, DecodeError};
use fictionet::stdlib::services::serve::Transport;

/// A query that passed every check of [`Request::parse`]: a QUERY with
/// one question a server can answer.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    /// The whole message as parsed.
    pub message: Message,
    /// The one question.
    pub question: Query,
    /// The question's octets as received, which a reply echoes byte for
    /// byte so the name keeps the sender's case (RFC 4343 §4.1).
    pub question_bytes: Vec<u8>,
    /// How the query arrived.
    pub transport: Transport,
    /// The query's EDNS, if it had an OPT record.
    pub edns: Option<EdnsIn>,
    /// Recursion desired (RFC 1035 §4.1.1).
    pub rd: bool,
    /// Checking disabled (RFC 4035 §3.2.2).
    pub cd: bool,
    /// Authentic data, which in a query asks for the AD bit in the reply
    /// (RFC 6840 §5.7).
    pub ad: bool,
}

/// What a query's OPT record asked for (RFC 6891 §6.1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdnsIn {
    /// The largest UDP reply the requestor can take, at least 512.
    pub payload: u16,
    /// The EDNS version, always 0 in a request, since `parse` rejects any
    /// other.
    pub version: u8,
    /// DNSSEC OK: the requestor wants DNSSEC records (RFC 3225).
    pub dnssec_ok: bool,
    /// The query carried an NSID option, which asks for the server's
    /// identifier (RFC 5001 §2.1).
    pub nsid: bool,
}

/// The outcome of [`Request::parse`].
#[derive(Clone, Debug, PartialEq)]
pub enum Parsed {
    /// A query to answer.
    Request(Request),
    /// A query refused with this reply.
    Reject(Message),
    /// Bytes that get no reply: too short for a header, or a response.
    Silent,
}

/// The length of a DNS header (RFC 1035 §4.1.1).
const HEADER: usize = 12;

impl Request {
    /// Checks one query in this order, and stops at the first that fails:
    ///
    /// 1. Fewer than 12 octets, or QR set: [`Silent`](Parsed::Silent).
    /// 2. A message that does not parse: FORMERR, with an OPT record when
    ///    the fault is in the query's OPT record (RFC 6891 §7). A record
    ///    of a type whose RDATA hickory reads by stricter rules, or with
    ///    empty RDATA, is carried as octets (RFC 3597 §4), so only a
    ///    message whose records do not read even as octets fails here, and
    ///    so does a TSIG record that is not the last record of the message,
    ///    or is one of several (RFC 8945 §5.2).
    /// 3. More than one OPT record: FORMERR with an OPT (RFC 6891 §6.1.1).
    /// 4. An EDNS version above 0: BADVERS with an OPT of version 0
    ///    (RFC 6891 §6.1.3).
    /// 5. A TSIG record: NOTAUTH with a TSIG record of error BADKEY, since
    ///    a server here holds no keys (RFC 8945 §5.2.1).
    /// 6. An opcode other than QUERY: NOTIMP.
    /// 7. A question count other than 1: FORMERR (RFC 9619).
    /// 8. QTYPE OPT, TSIG, or TKEY, meta-types that only appear as records
    ///    of the one message they travel in, never as data to ask for:
    ///    FORMERR (RFC 6891 §6.1.1, RFC 6895 §3.1).
    /// 9. AXFR over UDP, which it is not defined for: FORMERR
    ///    (RFC 5936 §4.2). IXFR is defined over UDP as well as TCP
    ///    (RFC 1995 §2), so the server's transfer policy answers it.
    /// 10. QTYPE MAILA or MAILB: NOTIMP (RFC 1035 §3.2.3).
    ///
    /// A rejection copies the query's ID, opcode, RD, and CD. It echoes
    /// the question when the query is a QUERY with one question, and it
    /// carries an OPT record of version 0 when the query had a readable
    /// one, with the query's DO bit (RFC 3225 §3). A server may change its
    /// OPT before sending, such as to set its own payload size.
    pub fn parse(bytes: &[u8], transport: Transport) -> Parsed {
        if bytes.len() < HEADER || bytes[2] & 0x80 != 0 {
            return Parsed::Silent;
        }
        let message = match Message::from_vec(bytes).map_err(|_| opaque(bytes)) {
            Ok(message) | Err(Ok(message)) => message,
            Err(Err(Fault { in_opt })) => return Parsed::Reject(unparsed(bytes, in_opt)),
        };
        let metadata = message.metadata;
        let one_question = metadata.op_code == OpCode::Query && message.queries.len() == 1;
        let reply = |code| {
            let edns = message.edns.as_ref().map(|edns| edns.flags().dnssec_ok);
            let question = one_question.then(|| message.queries[0].clone());
            rejection(&metadata, code, question, edns)
        };
        let reject = |code| Parsed::Reject(reply(code));

        if message.edns.as_ref().is_some_and(|edns| edns.version() > 0) {
            return reject(ResponseCode::BADVERS);
        }
        if let Some(tsig) = message.signature() {
            return Parsed::Reject(bad_key(reply(ResponseCode::NotAuth), tsig));
        }
        if metadata.op_code != OpCode::Query {
            return reject(ResponseCode::NotImp);
        }
        if message.queries.len() != 1 {
            return reject(ResponseCode::FormErr);
        }
        let question = message.queries[0].clone();
        match question.query_type() {
            kind if matches!(kind, RecordType::OPT | RecordType::TSIG)
                || u16::from(kind) == TKEY =>
            {
                return reject(ResponseCode::FormErr);
            }
            RecordType::AXFR if transport == Transport::Udp => {
                return reject(ResponseCode::FormErr);
            }
            kind if matches!(u16::from(kind), MAILB | MAILA) => {
                return reject(ResponseCode::NotImp);
            }
            _ => {}
        }

        let edns = message.edns.as_ref().map(|edns| EdnsIn {
            payload: edns.max_payload(),
            version: edns.version(),
            dnssec_ok: edns.flags().dnssec_ok,
            nsid: edns.option(EdnsCode::NSID).is_some(),
        });
        Parsed::Request(Request {
            question_bytes: question_bytes(bytes).expect("a parsed message's question reads again"),
            question,
            transport,
            edns,
            rd: metadata.recursion_desired,
            cd: metadata.checking_disabled,
            ad: metadata.authentic_data,
            message,
        })
    }
}

/// Reads a whole message as [`Message::from_vec`] does, and also when it
/// holds records whose RDATA is empty. RFC 3597 §4 lets a record of any
/// type have empty RDATA (`\# 0` in a master file), but hickory takes such
/// a record only in an UPDATE message (RFC 2136 §2.5), where it reads as
/// [`RData::Update0`](super::rr::RData::Update0), and refuses any other
/// message that holds one. A resolver reads its replies with this, so a
/// zone that holds such a record can still be resolved.
///
/// Records whose RDATA a validator ignores while the rest of the message
/// stands are read with their RDATA as octets (RFC 3597 §5), where
/// hickory refuses the whole message or reads them as records to use:
/// NSEC3 records with a Hash Algorithm other than SHA-1 or a Flags bit
/// other than Opt-Out (RFC 5155 §8.1, §8.2), NSEC3PARAM records with a
/// Hash Algorithm other than SHA-1 or any Flags bit set (RFC 5155 §4.1.2,
/// §4.2), and DNSKEY records whose Protocol is not 3 (RFC 4034 §2.1.2).
/// Each keeps its place in its RRset, whose RRSIG covers it.
pub fn read_message(bytes: &[u8]) -> Result<Message, DecodeError> {
    let mut decoder = BinDecoder::new(bytes);
    let Header {
        mut metadata,
        counts,
    } = Header::read(&mut decoder)?;
    let queries = (0..counts.queries)
        .map(|_| Query::read(&mut decoder))
        .collect::<Result<Vec<_>, _>>()?;
    let answers = read_section(bytes, &mut decoder, counts.answers, false)?.records;
    let authorities = read_section(bytes, &mut decoder, counts.authorities, false)?.records;
    let Section {
        records: additionals,
        edns,
    } = read_section(bytes, &mut decoder, counts.additionals, true)?;
    if let Some(edns) = &edns {
        metadata.merge_response_code(edns.rcode_high());
    }
    let mut message = Message::new(metadata.id, metadata.message_type, metadata.op_code);
    message.metadata = metadata;
    message.queries = queries;
    message.answers = answers;
    message.authorities = authorities;
    message.additionals = additionals;
    message.edns = edns;
    Ok(message)
}

/// The records of one section of a message, and the EDNS of its OPT
/// record.
struct Section {
    records: Vec<Record>,
    edns: Option<Edns>,
}

/// Reads the `count` records of one section from `decoder`, a decoder of
/// `bytes`, as [`Message::read_records`] does under UPDATE, the one
/// opcode under which hickory reads empty RDATA. A record a validator
/// ignores is read with its RDATA as octets ([`ignored_by_validators`]).
fn read_section<'a>(
    bytes: &'a [u8],
    decoder: &mut BinDecoder<'a>,
    count: u16,
    additional: bool,
) -> Result<Section, DecodeError> {
    let mut section = Section {
        records: Vec::new(),
        edns: None,
    };
    let mut signed = false;
    for _ in 0..count {
        if signed {
            // A TSIG record is the last in the message (RFC 8945 §5.1).
            return Err(DecodeError::RecordAfterSig);
        }
        if let Some((record, past)) = ignored_by_validators(bytes, decoder) {
            *decoder = past;
            section.records.push(record);
            continue;
        }
        let (records, edns, sig) = Message::read_records(decoder, 1, additional, OpCode::Update)?;
        if edns.is_some() && section.edns.is_some() {
            return Err(DecodeError::DuplicateEdns);
        }
        section.records.extend(records);
        section.edns = section.edns.or(edns);
        signed = sig.is_some();
    }
    Ok(section)
}

/// The record `decoder`, a decoder of `bytes`, is at, with its RDATA as
/// octets (RFC 3597 §5), and a decoder past it, when the RFCs have the
/// record ignored as the rest of the message stands, which hickory would
/// refuse, with the whole message, or read as a record to use:
///
/// - an NSEC3 record with a Hash Algorithm other than SHA-1, the one
///   hickory reads, or a Flags bit set other than Opt-Out (RFC 5155 §8.1,
///   §8.2);
/// - an NSEC3PARAM record with a Hash Algorithm other than SHA-1, or any
///   Flags bit set (RFC 5155 §4.1.2, §4.2);
/// - a DNSKEY record whose Protocol field is not 3, which is no key
///   (RFC 4034 §2.1.2).
///
/// The record keeps its place in its RRset, whose RRSIG covers it
/// (RFC 4034 §3.1.8.1), and no code that reads the type's RDATA takes it.
/// The record is read as RFC 1035 §4.1.3 lays it out: its owner, TYPE,
/// CLASS, TTL, and RDLENGTH, then RDATA, which starts with the Hash
/// Algorithm and Flags (RFC 5155 §3.2, §4.2) or the Flags and Protocol
/// (RFC 4034 §2.1). `None` for any other record, or one that does not
/// fit, which hickory then reads or refuses.
fn ignored_by_validators<'a>(
    bytes: &'a [u8],
    decoder: &BinDecoder<'a>,
) -> Option<(Record, BinDecoder<'a>)> {
    let mut ahead = BinDecoder::new(bytes);
    ahead.read_slice(decoder.index()).ok()?;
    let owner = Name::read(&mut ahead).ok()?;
    let rtype = RecordType::from(ahead.read_u16().ok()?.unverified());
    let class = DNSClass::from(ahead.read_u16().ok()?.unverified());
    let ttl = ahead.read_u32().ok()?.unverified();
    let length = ahead.read_u16().ok()?.unverified();
    let rdata = ahead.read_slice(usize::from(length)).ok()?.unverified();
    let ignored = match rtype {
        RecordType::NSEC3 => match rdata {
            [algorithm, flags, ..] => *algorithm != SHA1 || flags & !OPT_OUT != 0,
            _ => false,
        },
        RecordType::NSEC3PARAM => match rdata {
            [algorithm, flags, ..] => *algorithm != SHA1 || *flags != 0,
            _ => false,
        },
        RecordType::DNSKEY => rdata.get(2).is_some_and(|protocol| *protocol != 3),
        _ => false,
    };
    if !ignored {
        return None;
    }
    let data = RData::Unknown {
        code: rtype,
        rdata: NULL::with(rdata.to_vec()),
    };
    let mut record = Record::from_rdata(owner, ttl, data);
    record.dns_class = class;
    Some((record, ahead))
}

/// NSEC3 Hash Algorithm SHA-1 (RFC 5155 §11).
const SHA1: u8 = 1;
/// The NSEC3 Opt-Out flag, the one Flags bit RFC 5155 §3.1.2 defines.
const OPT_OUT: u8 = 0b0000_0001;

/// QTYPE TKEY, a meta-type for key agreement (RFC 2930 §2).
const TKEY: u16 = 249;
/// QTYPE MAILB, mailbox records (RFC 1035 §3.2.3).
const MAILB: u16 = 253;
/// QTYPE MAILA, mail agent records, obsolete (RFC 1035 §3.2.3).
const MAILA: u16 = 254;

/// The octets of the first question of a message that parsed.
fn question_bytes(bytes: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let mut decoder = BinDecoder::new(bytes);
    Header::read(&mut decoder)?;
    Query::read(&mut decoder)?;
    Ok(bytes[HEADER..decoder.index()].to_vec())
}

/// Why a query does not read even with its RDATA as octets.
struct Fault {
    /// Whether the fault is in an OPT record: one that does not read, one
    /// outside the additional section, one whose options do not decode,
    /// or one of several. The FORMERR then carries an OPT (RFC 6891 §7).
    in_opt: bool,
}

/// A query hickory does not read, read as RFC 3597 §4 asks: each record's
/// RDATA as octets, except the names inside the RDATA of the RFC 1035
/// types that may hold compressed names, which must read inside it. The
/// message has the query's header, its questions, the OPT record of its
/// additional section, and its TSIG record, and none of its other records,
/// which a server does not use. A TSIG record that is not the last record
/// of the message, or does not read, is a fault (RFC 8945 §5.2).
fn opaque(bytes: &[u8]) -> Result<Message, Fault> {
    let mut decoder = BinDecoder::new(bytes);
    let header = Header::read(&mut decoder).map_err(|_| Fault { in_opt: false })?;
    for _ in 0..header.counts.queries {
        Query::read(&mut decoder).map_err(|_| Fault { in_opt: false })?;
    }
    let questions = decoder.index();
    let outside = u32::from(header.counts.answers) + u32::from(header.counts.authorities);
    let records = outside + u32::from(header.counts.additionals);
    let (mut at, mut opts, mut tsig) = (questions, Vec::new(), None);
    for index in 0..records {
        let (rtype, end) = record(bytes, at).map_err(|rtype| Fault {
            in_opt: rtype == Some(OPT),
        })?;
        if rtype == OPT {
            if index < outside {
                return Err(Fault { in_opt: true });
            }
            opts.push(at..end);
        }
        if rtype == u16::from(RecordType::TSIG) {
            if index + 1 != records {
                return Err(Fault { in_opt: false });
            }
            tsig = Some(at);
        }
        at = end;
    }
    let mut reduced = bytes[..questions].to_vec();
    reduced[6..10].fill(0);
    let count = u16::try_from(opts.len()).map_err(|_| Fault { in_opt: true })?;
    reduced[10..12].copy_from_slice(&count.to_be_bytes());
    for opt in opts {
        reduced.extend_from_slice(&bytes[opt]);
    }
    let mut message = Message::from_vec(&reduced).map_err(|_| Fault { in_opt: true })?;
    if let Some(start) = tsig {
        // Read where it lies, so a name compressed against an earlier
        // record still reads.
        let fault = |_| Fault { in_opt: false };
        let mut decoder = BinDecoder::new(bytes);
        decoder.read_slice(start).map_err(fault)?;
        let signature = Record::read(&mut decoder)
            .map_err(fault)?
            .map(|data| match data {
                RData::TSIG(tsig) => Some(tsig),
                _ => None,
            })
            .ok_or(Fault { in_opt: false })?;
        message.signature = Some(Box::new(signature));
    }
    Ok(message)
}

/// The NOTAUTH reply to a query signed with `tsig`, from a server that
/// holds no TSIG keys: the key is unknown to it, so the reply carries a
/// TSIG record with error BADKEY and no MAC, and is itself unsigned
/// (RFC 8945 §5.2.1, §5.3.2). The record names the query's key and
/// algorithm and keeps its time signed, fudge, and original ID.
fn bad_key(mut reply: Message, tsig: &Record<TSIG>) -> Message {
    let query = &tsig.data;
    let data = TSIG::new(
        query.algorithm.clone(),
        query.time,
        query.fudge,
        Vec::new(),
        query.oid,
        Some(TsigError::BadKey),
        Vec::new(),
    );
    let mut record = Record::from_rdata(tsig.name.clone(), 0, data);
    record.dns_class = DNSClass::ANY;
    reply.signature = Some(Box::new(record));
    reply
}

/// The record type OPT (RFC 6891 §6.1.1).
const OPT: u16 = 41;

/// The type of the record at `start` and where it ends, read with its
/// RDATA as octets, as [`opaque`] reads it. A record that does not read
/// gives its type, when that much reads.
fn record(bytes: &[u8], start: usize) -> Result<(u16, usize), Option<u16>> {
    let fixed = name_end(bytes, start, bytes.len()).ok_or(None)?;
    let field = |offset: usize| {
        let octets = bytes.get(fixed + offset..fixed + offset + 2)?;
        Some(u16::from_be_bytes([octets[0], octets[1]]))
    };
    let rtype = field(0).ok_or(None)?;
    let length = field(8).ok_or(Some(rtype))?;
    let rdata = fixed + 10;
    let end = rdata + usize::from(length);
    if end > bytes.len() {
        return Err(Some(rtype));
    }
    if let Some((before, names, after)) = compressible(rtype) {
        let mut name = rdata + before;
        if name > end {
            return Err(Some(rtype));
        }
        for _ in 0..names {
            name = name_end(bytes, name, end).ok_or(Some(rtype))?;
        }
        if name + after != end {
            return Err(Some(rtype));
        }
    }
    Ok((rtype, end))
}

/// The layout of the RDATA of an RFC 1035 type whose names may be
/// compressed (RFC 3597 §4): the octets before its names, how many names,
/// and the octets after them. NS, MD, MF, CNAME, MB, MG, MR, and PTR hold
/// one name; SOA two names and 20 octets; MINFO two names; MX a
/// preference and one name.
fn compressible(rtype: u16) -> Option<(usize, usize, usize)> {
    match rtype {
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 => Some((0, 1, 0)),
        6 => Some((0, 2, 20)),
        14 => Some((0, 2, 0)),
        15 => Some((2, 1, 0)),
        _ => None,
    }
}

/// Where the name at `start` ends, reading no octet at or past `limit`.
/// Each compression pointer must point before itself, and the name it
/// points to is read with the pointer's position as the new limit
/// (RFC 1035 §4.1.4). `None` for a name that does not read, or one longer
/// than 255 octets (RFC 1035 §2.3.4).
fn name_end(bytes: &[u8], start: usize, limit: usize) -> Option<usize> {
    let (mut at, mut limit) = (start, limit);
    let mut end = None;
    let mut length = 1;
    loop {
        if at >= limit {
            return None;
        }
        let octet = *bytes.get(at)?;
        match octet {
            0 => return (length <= 255).then_some(end.unwrap_or(at + 1)),
            1..=63 => {
                let label = usize::from(octet);
                if at + 1 + label > limit {
                    return None;
                }
                length += 1 + label;
                at += 1 + label;
            }
            0xc0..=0xff => {
                if at + 1 >= limit {
                    return None;
                }
                let target = usize::from(octet & 0x3f) << 8 | usize::from(bytes[at + 1]);
                if target >= at {
                    return None;
                }
                end.get_or_insert(at + 2);
                limit = at;
                at = target;
            }
            _ => return None,
        }
    }
}

/// The FORMERR reply to a query that does not parse, built from its header
/// octets alone.
fn unparsed(bytes: &[u8], opt: bool) -> Message {
    let mut metadata = Metadata::new(
        u16::from_be_bytes([bytes[0], bytes[1]]),
        MessageType::Query,
        OpCode::from_u8((bytes[2] >> 3) & 0x0f),
    );
    metadata.recursion_desired = bytes[2] & 0x01 != 0;
    metadata.checking_disabled = bytes[3] & 0x10 != 0;
    rejection(&metadata, ResponseCode::FormErr, None, opt.then_some(false))
}

/// A reply refusing a query with `code`. `dnssec_ok` is `Some` when the
/// reply carries an OPT record, with the DO bit to set in it.
fn rejection(
    query: &Metadata,
    code: ResponseCode,
    question: Option<Query>,
    dnssec_ok: Option<bool>,
) -> Message {
    let mut reply = Message::error_msg(query.id, query.op_code, code);
    reply.metadata.recursion_desired = query.recursion_desired;
    reply.metadata.checking_disabled = query.checking_disabled;
    reply.queries.extend(question);
    if let Some(dnssec_ok) = dnssec_ok {
        let mut edns = Edns::new();
        edns.set_max_payload(DEFAULT_MAX_PAYLOAD_LEN)
            .set_dnssec_ok(dnssec_ok);
        reply.set_edns(edns);
    }
    reply
}

#[cfg(test)]
mod tests {
    use super::super::options::Nsid;
    use super::super::rr::{Name, Record};
    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    /// A query for `www.Example.test.` A with ID 77, changed by `change`.
    fn query(change: impl FnOnce(&mut Message)) -> Vec<u8> {
        let mut message = Message::new(77, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(name("www.Example.test."), RecordType::A));
        change(&mut message);
        message.to_vec().unwrap()
    }

    fn edns(version: u8, dnssec_ok: bool) -> Edns {
        let mut edns = Edns::new();
        edns.set_max_payload(4096)
            .set_version(version)
            .set_dnssec_ok(dnssec_ok);
        edns
    }

    fn rejected(bytes: &[u8], transport: Transport) -> Message {
        match Request::parse(bytes, transport) {
            Parsed::Reject(reply) => {
                // The rejection is what goes on the wire, and reads back.
                Message::from_vec(&reply.to_vec().unwrap()).unwrap()
            }
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    fn accepted(bytes: &[u8], transport: Transport) -> Request {
        match Request::parse(bytes, transport) {
            Parsed::Request(request) => request,
            other => panic!("expected a request, got {other:?}"),
        }
    }

    #[test]
    fn short_messages_and_responses_get_silence() {
        let good = query(|_| {});
        assert_eq!(Request::parse(&good[..11], Transport::Udp), Parsed::Silent);
        assert_eq!(Request::parse(&[], Transport::Tcp), Parsed::Silent);
        let mut response = good.clone();
        response[2] |= 0x80;
        assert_eq!(Request::parse(&response, Transport::Udp), Parsed::Silent);
        // A response that does not even parse is still silent.
        assert_eq!(
            Request::parse(&response[..15], Transport::Udp),
            Parsed::Silent
        );
    }

    #[test]
    fn an_unparseable_query_gets_formerr_without_opt() {
        let mut bytes = query(|m| {
            m.metadata.recursion_desired = true;
            m.metadata.checking_disabled = true;
        });
        bytes.truncate(bytes.len() - 2);
        let reply = rejected(&bytes, Transport::Udp);
        assert_eq!(reply.metadata.id, 77);
        assert_eq!(reply.metadata.message_type, MessageType::Response);
        assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
        assert!(reply.metadata.recursion_desired);
        assert!(reply.metadata.checking_disabled);
        assert!(reply.queries.is_empty());
        assert!(reply.edns.is_none());
    }

    #[test]
    fn a_fault_in_the_opt_record_gets_formerr_with_opt() {
        // An OPT whose RDATA length runs past the end of the message.
        let mut bytes = query(|m| {
            m.set_edns(edns(0, true));
        });
        let rdlength = bytes.len() - 2;
        bytes[rdlength..].copy_from_slice(&[0, 16]);
        bytes.extend_from_slice(&[0, 8, 0, 4]);
        let reply = rejected(&bytes, Transport::Udp);
        assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
        let opt = reply.edns.unwrap();
        assert_eq!(opt.version(), 0);
        assert!(!opt.flags().dnssec_ok);

        // An OPT in the answer section.
        let bytes = query(|m| {
            m.add_answer(Record::from(&edns(0, false)));
        });
        let reply = rejected(&bytes, Transport::Udp);
        assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
        assert!(reply.edns.is_some());
    }

    #[test]
    fn two_opt_records_get_formerr_with_opt() {
        let bytes = query(|m| {
            m.add_additional(Record::from(&edns(0, false)));
            m.set_edns(edns(0, false));
        });
        let reply = rejected(&bytes, Transport::Udp);
        assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
        assert!(reply.edns.is_some());
        assert!(reply.queries.is_empty());
    }

    #[test]
    fn an_edns_version_above_0_gets_badvers_with_version_0() {
        let bytes = query(|m| {
            m.set_edns(edns(1, true));
        });
        let reply = rejected(&bytes, Transport::Udp);
        // BADVERS shares 16 with BADSIG (RFC 6891 §9), which hickory reads.
        assert_eq!(u16::from(reply.metadata.response_code), 16);
        let opt = reply.edns.unwrap();
        assert_eq!(opt.version(), 0);
        assert!(opt.flags().dnssec_ok);
        assert_eq!(reply.queries[0].name().to_ascii(), "www.Example.test.");

        // The version is checked before the opcode.
        let bytes = query(|m| {
            m.metadata.op_code = OpCode::Notify;
            m.set_edns(edns(1, false));
        });
        assert_eq!(
            u16::from(rejected(&bytes, Transport::Udp).metadata.response_code),
            16
        );
    }

    #[test]
    fn other_opcodes_get_notimp() {
        for op_code in [
            OpCode::Status,
            OpCode::Notify,
            OpCode::Update,
            OpCode::Unknown(3),
        ] {
            let bytes = query(|m| m.metadata.op_code = op_code);
            let reply = rejected(&bytes, Transport::Udp);
            assert_eq!(reply.metadata.response_code, ResponseCode::NotImp);
            assert_eq!(reply.metadata.op_code, op_code);
            assert!(reply.queries.is_empty());
            assert!(reply.edns.is_none());
        }
    }

    #[test]
    fn a_question_count_other_than_1_gets_formerr() {
        let none = query(|m| m.queries.clear());
        assert_eq!(
            rejected(&none, Transport::Udp).metadata.response_code,
            ResponseCode::FormErr
        );
        let two = query(|m| {
            m.add_query(Query::query(name("b.test."), RecordType::A));
            m.set_edns(edns(0, true));
        });
        let reply = rejected(&two, Transport::Udp);
        assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
        assert!(reply.queries.is_empty());
        assert!(reply.edns.unwrap().flags().dnssec_ok);
    }

    #[test]
    fn meta_qtypes_get_formerr() {
        for kind in [RecordType::OPT, RecordType::TSIG, RecordType::from(TKEY)] {
            let bytes = query(|m| {
                m.queries[0].set_query_type(kind);
            });
            let reply = rejected(&bytes, Transport::Tcp);
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::FormErr,
                "{kind}"
            );
            assert_eq!(reply.queries[0].query_type(), kind);
        }
    }

    #[test]
    fn axfr_over_udp_gets_formerr_and_ixfr_does_not() {
        let axfr = query(|m| {
            m.queries[0].set_query_type(RecordType::AXFR);
        });
        assert_eq!(
            rejected(&axfr, Transport::Udp).metadata.response_code,
            ResponseCode::FormErr
        );
        assert_eq!(
            accepted(&axfr, Transport::Tcp).question.query_type(),
            RecordType::AXFR
        );
        // IXFR is defined over UDP too (RFC 1995 §2).
        let ixfr = query(|m| {
            m.queries[0].set_query_type(RecordType::IXFR);
        });
        for transport in [Transport::Udp, Transport::Tcp] {
            assert_eq!(
                accepted(&ixfr, transport).question.query_type(),
                RecordType::IXFR
            );
        }
    }

    #[test]
    fn maila_and_mailb_get_notimp() {
        for kind in [253, 254] {
            let bytes = query(|m| {
                m.queries[0].set_query_type(RecordType::from(kind));
            });
            let reply = rejected(&bytes, Transport::Udp);
            assert_eq!(reply.metadata.response_code, ResponseCode::NotImp);
            assert_eq!(u16::from(reply.queries[0].query_type()), kind);
        }
    }

    #[test]
    fn a_good_query_is_a_request() {
        let bytes = query(|m| {
            m.metadata.recursion_desired = true;
            m.metadata.authentic_data = true;
            let mut edns = edns(0, true);
            edns.options_mut().insert(Nsid(Vec::new()).to_option());
            m.set_edns(edns);
        });
        let request = accepted(&bytes, Transport::Udp);
        assert_eq!(request.message.metadata.id, 77);
        assert_eq!(request.question.name().to_ascii(), "www.Example.test.");
        assert_eq!(request.question.query_type(), RecordType::A);
        assert_eq!(request.question_bytes, bytes[12..12 + 22]);
        assert_eq!(&request.question_bytes[..4], b"\x03www");
        assert_eq!(&request.question_bytes[4..12], b"\x07Example");
        assert_eq!(request.transport, Transport::Udp);
        assert!(request.rd && request.ad && !request.cd);
        assert_eq!(
            request.edns,
            Some(EdnsIn {
                payload: 4096,
                version: 0,
                dnssec_ok: true,
                nsid: true,
            })
        );

        let plain = accepted(&query(|_| {}), Transport::Tcp);
        assert_eq!(plain.edns, None);
        assert!(!plain.rd && !plain.ad && !plain.cd);
        assert_eq!(plain.transport, Transport::Tcp);
    }
}
