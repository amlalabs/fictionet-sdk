//! Writing a reply within the size a requestor can take, as real servers
//! truncate: whole RRsets, the data a reply needs first, and TC only when
//! that data does not fit.
//!
//! hickory's own [`Message::truncate`] keeps only the question and the OPT
//! record. That is legal, but it is not what real servers send, and an
//! agent that compares the two can tell.

use super::op::{Edns, Header, HeaderCounts, Message};
use super::request::Request;
use super::rr::{DNSClass, Name, RData, Record, RecordType};
use super::serialize::binary::{BinEncodable, BinEncoder};
use super::{ProtoError, dnssec::rdata::DNSSECRData};
use fictionet::stdlib::services::serve::Transport;

/// A reply to write with [`fit`].
#[derive(Clone, Debug, PartialEq)]
pub struct Response {
    /// The reply.
    pub message: Message,
    /// How many RRsets at the start of the additional section the reply
    /// needs, such as the glue a referral cannot be followed without
    /// (RFC 9471 §3.1). The rest of the additional section is optional.
    pub required_additional: usize,
}

/// The most octets a reply may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Limit {
    /// UDP to a requestor without EDNS: 512 octets (RFC 1035 §4.2.1).
    Udp512,
    /// UDP to a requestor with EDNS: this many octets, and never fewer
    /// than 512 (RFC 6891 §6.2.5).
    UdpEdns(u16),
    /// A stream: 65535 octets, the most its length prefix can say
    /// (RFC 1035 §4.2.2).
    Stream,
}

impl Limit {
    /// The limit for a reply to `request` from a server whose own UDP
    /// payload size is `server_payload`: the smaller of the two sizes, and
    /// at least 512 (RFC 6891 §6.2.5).
    pub fn for_request(request: &Request, server_payload: u16) -> Limit {
        match (request.transport, request.edns) {
            (Transport::Tcp, _) => Limit::Stream,
            (Transport::Udp, None) => Limit::Udp512,
            (Transport::Udp, Some(edns)) => {
                Limit::UdpEdns(edns.payload.max(512).min(server_payload))
            }
        }
    }

    /// The limit in octets.
    pub fn octets(self) -> usize {
        match self {
            Limit::Udp512 => 512,
            Limit::UdpEdns(payload) => usize::from(payload.max(512)),
            Limit::Stream => usize::from(u16::MAX),
        }
    }
}

/// A reply written by [`fit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fitted {
    /// The message, at most [`Limit::octets`] long.
    pub bytes: Vec<u8>,
    /// Whether data the reply needs was left out, so TC is set.
    pub truncated: bool,
}

/// Writes `response` within `limit`, in this order:
///
/// 1. The header, the questions, and room for the OPT record, which is
///    always kept (RFC 6891 §7). If the OPT's options leave no room for
///    the questions, they are dropped and the reply is truncated.
/// 2. The answer and authority sections, one whole RRset at a time, each
///    with the RRSIGs that cover it, then the first
///    [`required_additional`](Response::required_additional) RRsets of the
///    additional section. At the first of these that does not fit, the
///    reply stops and TC is set (RFC 2181 §9).
/// 3. The rest of the additional section, each RRset that fits. One that
///    does not is left out without TC (RFC 2181 §9).
///
/// The records of an RRset are written together where the RRset first
/// appears in its section, so an RRset whose records are spread through a
/// section comes out in one piece. TC is also set when the message already
/// has it. Fails only when hickory cannot write a record at all, whatever
/// the room.
pub fn fit(response: &Response, limit: Limit) -> Result<Fitted, ProtoError> {
    let message = &response.message;
    let octets = limit.octets();
    let full_opt = message
        .edns
        .as_ref()
        .map(|edns| opt_record(message, edns, true));
    let bare_opt = message
        .edns
        .as_ref()
        .map(|edns| opt_record(message, edns, false));
    let full_room = full_opt.as_ref().map_or(Ok(0), encoded_len)?;
    let bare_room = bare_opt.as_ref().map_or(Ok(0), encoded_len)?;

    let mut bytes = Vec::new();
    let mut encoder = BinEncoder::new(&mut bytes);
    let mut truncated = false;
    let mut counts = HeaderCounts::default();

    // Every limit is at least 512 octets, which holds a header and an
    // empty OPT, so these subtractions never wrap.
    encoder.set_max_size(max_size(octets - bare_room));
    let place = encoder.place::<Header>()?;
    for query in &message.queries {
        if !write(&mut encoder, &[query])? {
            truncated = true;
            break;
        }
        counts.queries += 1;
    }
    let opt = if truncated || encoder.offset() + full_room > octets {
        truncated = true;
        bare_opt
    } else {
        encoder.set_max_size(max_size(octets - full_room));
        full_opt
    };

    let additional = rrsets(&message.additionals);
    let required = additional.len().min(response.required_additional);
    let sections = [
        (rrsets(&message.answers), &mut counts.answers),
        (rrsets(&message.authorities), &mut counts.authorities),
        (additional[..required].to_vec(), &mut counts.additionals),
    ];
    'required: for (sets, count) in sections {
        for set in sets {
            if truncated || !write(&mut encoder, &set)? {
                truncated = true;
                break 'required;
            }
            *count += records(set.len());
        }
    }
    if !truncated {
        for set in &additional[required..] {
            if write(&mut encoder, set)? {
                counts.additionals += records(set.len());
            }
        }
    }

    if let Some(opt) = &opt {
        encoder.set_max_size(max_size(octets));
        opt.emit(&mut encoder)?;
        counts.additionals += 1;
    }
    let mut metadata = message.metadata;
    metadata.truncation |= truncated;
    place.replace(&mut encoder, Header { metadata, counts })?;
    Ok(Fitted { bytes, truncated })
}

/// The OPT record for `edns`, carrying the high bits of the message's
/// RCODE (RFC 6891 §6.1.3), with its options or without them.
fn opt_record(message: &Message, edns: &Edns, options: bool) -> Record {
    let mut edns = edns.clone();
    edns.set_rcode_high(message.metadata.response_code.high());
    if !options {
        edns.options_mut().as_mut().clear();
    }
    Record::from(&edns)
}

/// The length of `record` written on its own. An OPT record's owner is the
/// root, which is never compressed, so its length is the same anywhere.
fn encoded_len(record: &Record) -> Result<usize, ProtoError> {
    let mut bytes = Vec::new();
    record.emit(&mut BinEncoder::new(&mut bytes))?;
    Ok(bytes.len())
}

/// `octets` as hickory's encoder limit. Every limit is at most 65535.
fn max_size(octets: usize) -> u16 {
    u16::try_from(octets).expect("a DNS message limit fits in 16 bits")
}

/// A record count for the header. A message holds at most 65535 octets
/// and every record takes at least 11, so the count fits.
fn records(count: usize) -> u16 {
    u16::try_from(count).expect("a written section fits in a header count")
}

/// Writes `items` whole, or nothing if they do not all fit within the
/// encoder's limit. Returns whether they were written.
fn write<T: BinEncodable>(encoder: &mut BinEncoder<'_>, items: &[&T]) -> Result<bool, ProtoError> {
    let mark = encoder.offset();
    for item in items {
        match item.emit(encoder) {
            Ok(()) => {}
            Err(ProtoError::MaxBufferSizeExceeded(_)) => {
                encoder.set_offset(mark);
                encoder.trim();
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

/// The records of one section grouped into RRsets in order of first
/// appearance: records with the same owner, class, and type, and the
/// RRSIGs with that owner and class that cover the type (RFC 4034 §3).
fn rrsets(records: &[Record]) -> Vec<Vec<&Record>> {
    /// What makes records one RRset: owner, class, and type (RFC 2181 §5).
    type Key<'a> = (&'a Name, DNSClass, RecordType);
    let mut sets: Vec<(Key<'_>, Vec<&Record>)> = Vec::new();
    for record in records {
        let kind = match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => rrsig.input().type_covered,
            _ => record.record_type(),
        };
        let key = (&record.name, record.dns_class, kind);
        match sets.iter_mut().find(|(other, _)| *other == key) {
            Some((_, set)) => set.push(record),
            None => sets.push((key, vec![record])),
        }
    }
    sets.into_iter().map(|(_, set)| set).collect()
}

#[cfg(test)]
mod tests {
    use super::super::op::{Edns, MessageType, OpCode, Query, ResponseCode};
    use super::super::request::Parsed;
    use super::super::rr::rdata::{A, NS, TXT};
    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    fn a(owner: &str, last: u8) -> Record {
        Record::from_rdata(name(owner), 300, RData::A(A::new(192, 0, 2, last)))
    }

    fn txt(owner: &str, len: usize) -> Record {
        Record::from_rdata(
            name(owner),
            300,
            RData::TXT(TXT::new(vec!["x".repeat(len)])),
        )
    }

    fn reply(answers: Vec<Record>) -> Message {
        let mut message = Message::response(9, OpCode::Query);
        message.add_query(Query::query(name("example.test."), RecordType::A));
        message.answers = answers;
        message
    }

    fn parse(fitted: &Fitted) -> Message {
        Message::from_vec(&fitted.bytes).unwrap()
    }

    #[test]
    fn a_reply_that_fits_is_written_whole() {
        let mut message = reply(vec![a("example.test.", 1), a("example.test.", 2)]);
        message.add_additional(a("ns.example.test.", 3));
        let fitted = fit(
            &Response {
                message: message.clone(),
                required_additional: 0,
            },
            Limit::Udp512,
        )
        .unwrap();
        assert!(!fitted.truncated);
        assert_eq!(fitted.bytes, message.to_vec().unwrap());
    }

    #[test]
    fn answers_are_cut_between_rrsets_and_set_tc() {
        // Two RRsets of about 200 octets each, then one that does not fit.
        let message = reply(vec![
            txt("a.example.test.", 90),
            txt("b.example.test.", 180),
            txt("a.example.test.", 90),
            txt("c.example.test.", 200),
        ]);
        let response = Response {
            message,
            required_additional: 0,
        };
        let fitted = fit(&response, Limit::Udp512).unwrap();
        assert!(fitted.truncated);
        assert!(fitted.bytes.len() <= 512);
        let back = parse(&fitted);
        assert!(back.metadata.truncation);
        let owners: Vec<String> = back.answers.iter().map(|r| r.name.to_string()).collect();
        assert_eq!(
            owners,
            ["a.example.test.", "a.example.test.", "b.example.test."]
        );

        let whole = fit(&response, Limit::UdpEdns(1232)).unwrap();
        assert!(!whole.truncated);
        assert_eq!(parse(&whole).answers.len(), 4);
    }

    #[test]
    fn an_rrset_spread_through_a_section_comes_out_together() {
        let message = reply(vec![
            a("a.example.test.", 1),
            a("b.example.test.", 2),
            a("A.example.test.", 3),
        ]);
        let fitted = fit(
            &Response {
                message,
                required_additional: 0,
            },
            Limit::Udp512,
        )
        .unwrap();
        assert!(!fitted.truncated);
        let owners: Vec<String> = parse(&fitted)
            .answers
            .iter()
            .map(|r| r.name.to_string())
            .collect();
        assert_eq!(
            owners,
            ["a.example.test.", "A.example.test.", "b.example.test."]
        );
    }

    #[test]
    fn an_rrset_is_never_split() {
        let message = reply((0..40).map(|i| a("example.test.", i)).collect());
        let fitted = fit(
            &Response {
                message,
                required_additional: 0,
            },
            Limit::Udp512,
        )
        .unwrap();
        assert!(fitted.truncated);
        assert!(parse(&fitted).answers.is_empty());
    }

    #[test]
    fn required_glue_sets_tc_and_optional_data_does_not() {
        let mut message = Message::response(3, OpCode::Query);
        message.add_query(Query::query(name("www.example.test."), RecordType::A));
        message.add_authority(Record::from_rdata(
            name("example.test."),
            86400,
            RData::NS(NS(name("ns1.example.test."))),
        ));
        message.add_additional(txt("ns1.example.test.", 200));
        message.add_additional(txt("other.test.", 250));
        message.add_additional(a("third.test.", 1));

        let optional = Response {
            message: message.clone(),
            required_additional: 1,
        };
        let fitted = fit(&optional, Limit::Udp512).unwrap();
        assert!(!fitted.truncated);
        let back = parse(&fitted);
        assert!(!back.metadata.truncation);
        let owners: Vec<String> = back
            .additionals
            .iter()
            .map(|r| r.name.to_string())
            .collect();
        assert_eq!(owners, ["ns1.example.test.", "third.test."]);

        let required = Response {
            message,
            required_additional: 2,
        };
        let fitted = fit(&required, Limit::Udp512).unwrap();
        assert!(fitted.truncated);
        let back = parse(&fitted);
        assert_eq!(back.additionals.len(), 1);
        assert_eq!(back.authorities.len(), 1);
    }

    #[test]
    fn rrsigs_travel_with_the_rrset_they_cover() {
        use super::super::dnssec::Algorithm;
        use super::super::dnssec::rdata::{RRSIG, SigInput};
        let rrsig = |covered: RecordType, len: usize| {
            let input = SigInput {
                type_covered: covered,
                algorithm: Algorithm::ED25519,
                num_labels: 2,
                original_ttl: 300,
                sig_expiration: 2_000_000_000.into(),
                sig_inception: 1_000_000_000.into(),
                key_tag: 1,
                signer_name: name("example.test."),
            };
            Record::from_rdata(
                name("example.test."),
                300,
                RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, vec![7; len]))),
            )
        };
        // The A RRset's signature comes last in the section but is written
        // with it; the large TXT RRset with its signature does not fit.
        let message = reply(vec![
            a("example.test.", 1),
            txt("example.test.", 100),
            rrsig(RecordType::TXT, 300),
            rrsig(RecordType::A, 64),
        ]);
        let fitted = fit(
            &Response {
                message,
                required_additional: 0,
            },
            Limit::Udp512,
        )
        .unwrap();
        assert!(fitted.truncated);
        let kinds: Vec<RecordType> = parse(&fitted)
            .answers
            .iter()
            .map(|r| r.record_type())
            .collect();
        assert_eq!(kinds, [RecordType::A, RecordType::RRSIG]);
    }

    #[test]
    fn the_opt_record_is_always_kept() {
        let mut message = reply((0..40).map(|i| a("example.test.", i)).collect());
        message.metadata.response_code = ResponseCode::BADVERS;
        let mut edns = Edns::new();
        edns.set_max_payload(1232).set_dnssec_ok(true);
        message.set_edns(edns.clone());
        let fitted = fit(
            &Response {
                message,
                required_additional: 0,
            },
            Limit::Udp512,
        )
        .unwrap();
        assert!(fitted.truncated);
        let back = parse(&fitted);
        // BADVERS and BADSIG share the number 16 (RFC 6891 §9), which hickory reads as BADSIG.
        assert_eq!(u16::from(back.metadata.response_code), 16);
        let back_edns = back.edns.unwrap();
        assert_eq!(back_edns.max_payload(), 1232);
        assert!(back_edns.flags().dnssec_ok);
    }

    #[test]
    fn options_that_leave_no_room_are_dropped_with_tc() {
        use super::super::options::Padding;
        let mut message = reply(vec![a("example.test.", 1)]);
        let mut edns = Edns::new();
        edns.options_mut().insert(Padding(600).to_option());
        message.set_edns(edns);
        let response = Response {
            message,
            required_additional: 0,
        };
        let fitted = fit(&response, Limit::UdpEdns(512)).unwrap();
        assert!(fitted.truncated);
        assert!(fitted.bytes.len() <= 512);
        let back = parse(&fitted);
        assert!(back.answers.is_empty());
        assert_eq!(back.queries.len(), 1);
        assert!(back.edns.unwrap().options().as_ref().is_empty());

        let fitted = fit(&response, Limit::UdpEdns(1232)).unwrap();
        assert!(!fitted.truncated);
        assert_eq!(parse(&fitted).answers.len(), 1);
    }

    #[test]
    fn limits_follow_the_request() {
        fn request(transport: Transport, payload: Option<u16>) -> Request {
            let mut message = Message::new(1, MessageType::Query, OpCode::Query);
            message.add_query(Query::query(name("example.test."), RecordType::A));
            if let Some(payload) = payload {
                let mut edns = Edns::new();
                edns.set_max_payload(payload);
                message.set_edns(edns);
            }
            match Request::parse(&message.to_vec().unwrap(), transport) {
                Parsed::Request(request) => request,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(
            Limit::for_request(&request(Transport::Udp, None), 1232),
            Limit::Udp512
        );
        assert_eq!(
            Limit::for_request(&request(Transport::Udp, Some(4096)), 1232),
            Limit::UdpEdns(1232)
        );
        assert_eq!(
            Limit::for_request(&request(Transport::Udp, Some(800)), 1232),
            Limit::UdpEdns(800)
        );
        assert_eq!(
            Limit::for_request(&request(Transport::Udp, Some(100)), 1232),
            Limit::UdpEdns(512)
        );
        assert_eq!(
            Limit::for_request(&request(Transport::Tcp, Some(4096)), 1232),
            Limit::Stream
        );
        assert_eq!(Limit::UdpEdns(100).octets(), 512);
        assert_eq!(Limit::Stream.octets(), 65535);
    }

    #[test]
    fn a_stream_reply_holds_up_to_65535_octets() {
        let message = reply(
            (0..300)
                .map(|i| txt(&format!("n{i}.example.test."), 250))
                .collect(),
        );
        let response = Response {
            message,
            required_additional: 0,
        };
        let fitted = fit(&response, Limit::Stream).unwrap();
        assert!(fitted.truncated);
        assert!(fitted.bytes.len() <= 65535);
        assert!(fitted.bytes.len() > 60000);
        assert!(parse(&fitted).answers.len() < 300);
    }
}
