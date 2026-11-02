//! Passing a reply from one server on to a client unchanged, except for
//! what ties it to the client's own query.
//!
//! A relay asks the question again with its own ID, and maybe its own
//! letter case (RFC 5452 §9.1 and the 0x20 technique). [`restore`] puts
//! the client's ID and the client's question octets back into the reply's
//! bytes and changes nothing else, so every record, flag, and option the
//! server sent reaches the client as the server sent it.
//!
//! Records are never copied as byte ranges from one message into another.
//! Compressed names point into the message they are in, so a range of
//! RDATA taken elsewhere would point at the wrong octets. Code that builds
//! a new message from records seen in another decodes them and encodes
//! them again.

use std::fmt;

use super::op::{Header, MessageType};
use super::request::Request;
use super::rr::{DNSClass, Name, RecordType};
use super::serialize::binary::{BinDecodable, BinDecoder};

/// Why [`restore`] refused a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RelayError {
    /// The reply's question is not the query's question.
    QuestionMismatch,
    /// The reply is not a DNS response: shorter than a header, QR clear,
    /// or a question that does not read.
    Malformed,
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RelayError::QuestionMismatch => "the reply answers another question",
            RelayError::Malformed => "the reply is not a DNS response",
        })
    }
}

impl std::error::Error for RelayError {}

/// The length of a DNS header (RFC 1035 §4.1.1).
const HEADER: usize = 12;

/// The reply as the client's server would send it: `reply` with the ID and
/// the question's case taken from `query`. Only the header ID and the
/// question-name octets change.
///
/// The reply must hold one question equal to the query's, ignoring ASCII
/// case in the name (RFC 4343 §3), and encoded in as many octets. The
/// query's question octets then replace the reply's in place. A name
/// elsewhere in the reply that points into the question by compression
/// reads with the client's case too. An owner name written out in full
/// keeps the server's case, which RFC 4343 §4.1 permits, and RRSIGs stay
/// valid, since they cover owners in lowercase (RFC 4034 §6.2).
pub fn restore(reply: &[u8], query: &Request) -> Result<Vec<u8>, RelayError> {
    let mut decoder = BinDecoder::new(reply);
    let header = Header::read(&mut decoder).map_err(|_| RelayError::Malformed)?;
    if header.metadata.message_type != MessageType::Response {
        return Err(RelayError::Malformed);
    }
    if header.counts.queries != 1 {
        return Err(RelayError::QuestionMismatch);
    }
    let name = Name::read(&mut decoder).map_err(|_| RelayError::Malformed)?;
    let kind = RecordType::read(&mut decoder).map_err(|_| RelayError::Malformed)?;
    let class = DNSClass::read(&mut decoder).map_err(|_| RelayError::Malformed)?;
    let question = &reply[HEADER..decoder.index()];

    let asked = &query.question;
    let wanted = &query.question_bytes;
    let same = name == *asked.name()
        && kind == asked.query_type()
        && class == asked.query_class()
        && question.eq_ignore_ascii_case(wanted)
        && question[question.len() - 4..] == wanted[wanted.len() - 4..];
    if !same {
        return Err(RelayError::QuestionMismatch);
    }

    let mut bytes = reply.to_vec();
    bytes[..2].copy_from_slice(&query.message.metadata.id.to_be_bytes());
    bytes[HEADER..HEADER + wanted.len()].copy_from_slice(wanted);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::op::{Message, OpCode, Query};
    use super::super::request::Parsed;
    use super::super::rr::{RData, Record, rdata::A, rdata::CNAME};
    use super::*;
    use fictionet::stdlib::services::serve::Transport;

    fn request(id: u16, name: &str, kind: RecordType) -> Request {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
        match Request::parse(&message.to_vec().unwrap(), Transport::Udp) {
            Parsed::Request(request) => request,
            other => panic!("{other:?}"),
        }
    }

    /// The server's reply to `name`: a CNAME whose owner points into the
    /// question by compression, then an A record for the target.
    fn reply(id: u16, name: &str) -> Vec<u8> {
        let owner = Name::from_ascii(name).unwrap();
        let target = Name::from_ascii("Target.Example.NET.").unwrap();
        let mut message = Message::response(id, OpCode::Query);
        message.metadata.recursion_available = true;
        message.add_query(Query::query(owner.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(
            owner,
            300,
            RData::CNAME(CNAME(target.clone())),
        ));
        message.add_answer(Record::from_rdata(
            target,
            60,
            RData::A(A::new(192, 0, 2, 7)),
        ));
        message.to_vec().unwrap()
    }

    #[test]
    fn only_the_id_and_the_question_case_change() {
        let query = request(0x1234, "WwW.ExAmPlE.test.", RecordType::A);
        let from_server = reply(0xbeef, "www.EXAMPLE.TEST.");
        let restored = restore(&from_server, &query).unwrap();

        assert_eq!(restored.len(), from_server.len());
        let changed: Vec<usize> = (0..restored.len())
            .filter(|&i| restored[i] != from_server[i])
            .collect();
        let question = HEADER..HEADER + query.question_bytes.len();
        assert!(changed.iter().all(|&i| i < 2 || question.contains(&i)));
        assert!(changed.contains(&0) && changed.contains(&1));

        let back = Message::from_vec(&restored).unwrap();
        assert_eq!(back.metadata.id, 0x1234);
        assert!(back.metadata.recursion_available);
        assert_eq!(back.queries[0].name().to_ascii(), "WwW.ExAmPlE.test.");
        // The CNAME's owner is a pointer to the question, so it reads with
        // the client's case; the target written in full keeps the server's.
        assert_eq!(back.answers[0].name.to_ascii(), "WwW.ExAmPlE.test.");
        assert_eq!(back.answers[1].name.to_ascii(), "Target.Example.NET.");
    }

    #[test]
    fn another_question_is_refused() {
        let query = request(1, "www.example.test.", RecordType::A);
        assert_eq!(
            restore(&reply(2, "mail.example.test."), &query),
            Err(RelayError::QuestionMismatch)
        );
        let aaaa = request(1, "www.example.test.", RecordType::AAAA);
        assert_eq!(
            restore(&reply(2, "www.example.test."), &aaaa),
            Err(RelayError::QuestionMismatch)
        );
        let mut none = Message::response(2, OpCode::Query);
        none.metadata.response_code = super::super::op::ResponseCode::FormErr;
        assert_eq!(
            restore(&none.to_vec().unwrap(), &query),
            Err(RelayError::QuestionMismatch)
        );
    }

    #[test]
    fn a_reply_that_is_not_a_response_is_refused() {
        let query = request(1, "www.example.test.", RecordType::A);
        let good = reply(2, "www.example.test.");
        assert_eq!(restore(&good[..11], &query), Err(RelayError::Malformed));
        assert_eq!(restore(&good[..20], &query), Err(RelayError::Malformed));
        let mut not_a_response = good.clone();
        not_a_response[2] &= 0x7f;
        assert_eq!(restore(&not_a_response, &query), Err(RelayError::Malformed));
    }
}
