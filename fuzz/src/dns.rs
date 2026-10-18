//! Value comparisons for hickory's DNS writer and parser.

use fictionet::stdlib::protocols::dns::{ProtoError, op::Message};

/// Checks a parsed message's write/reparse using hickory's value equality.
/// Only questions exceeding the DNS size limit may prevent serialization.
/// Record sections may be truncated.
pub fn round_trip(m: &Message) {
    let bytes = match m.to_vec() {
        Ok(bytes) => bytes,
        // Hickory stores at most 64 name compression candidates. A parsed
        // input of a few KiB can use pointers to a suffix outside that set
        // and expand past 65535 bytes when written. In hickory 0.26.3,
        // encoder.rs:387-405 wraps that overflow in NotAllRecordsWritten.
        // message.rs:591 propagates it only for questions; record sections
        // use count_was_truncated (message.rs:539-552) and set TC instead.
        // Confirm the questions alone reach the same limit.
        Err(ProtoError::NotAllRecordsWritten { count, .. }) if count < m.queries.len() => {
            questions_exceed_limit(m, count);
            return;
        }
        Err(error) => panic!("DNS writer rejected a parsed message: {error:?}"),
    };
    let back = Message::from_vec(&bytes).expect("written DNS message must parse");
    written_matches(m, &back);
}

fn questions_exceed_limit(m: &Message, count: usize) {
    let mut questions = Message::new(m.metadata.id, m.metadata.message_type, m.metadata.op_code);
    questions.metadata = m.metadata;
    questions.queries.clone_from(&m.queries);
    let error = questions
        .to_vec()
        .expect_err("DNS questions alone must exceed the size limit");
    assert!(
        matches!(error, ProtoError::NotAllRecordsWritten { count: written, .. } if written == count),
        "DNS question-only encoding must fail at the same count ({count}): {error:?}"
    );
}

fn written_matches(m: &Message, back: &Message) {
    assert_eq!(back.metadata.id, m.metadata.id, "DNS id changed");
    assert_eq!(back.metadata.op_code, m.metadata.op_code);
    assert_eq!(back.metadata.message_type, m.metadata.message_type);
    assert_eq!(back.queries, m.queries);
    if back.answers.len() == m.answers.len()
        && back.authorities.len() == m.authorities.len()
        && back.additionals.len() == m.additionals.len()
        && back.edns.is_some() == m.edns.is_some()
    {
        assert_eq!(back, m, "DNS message changed without truncation");
    } else {
        // Hickory sets TC when a record section does not fit. Each section
        // must retain exactly the prefix that the writer could emit.
        assert!(back.metadata.truncation, "DNS records lost without TC");
        assert_eq!(back.answers, m.answers[..back.answers.len()]);
        assert_eq!(back.authorities, m.authorities[..back.authorities.len()]);
        assert_eq!(back.additionals, m.additionals[..back.additionals.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::protocols::dns::op::{Edns, MessageType, OpCode, Query};
    use fictionet::stdlib::protocols::dns::rr::{
        Name, RData, Record, RecordType,
        rdata::{A, CNAME},
    };

    fn reparse(m: &Message) -> Message {
        Message::from_vec(&m.to_vec().unwrap()).unwrap()
    }

    fn response() -> Message {
        let name = Name::from_ascii("www.example.test.").unwrap();
        let canonical = Name::from_ascii("example.test.").unwrap();
        let mut m = Message::response(7, OpCode::Query);
        m.add_query(Query::query(name.clone(), RecordType::A));
        m.add_answer(Record::from_rdata(
            name,
            60,
            RData::CNAME(CNAME(canonical.clone())),
        ));
        m.add_answer(Record::from_rdata(
            canonical,
            60,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        reparse(&m)
    }

    fn large_message(response: bool) -> Message {
        // Fill the writer's 64 compression slots with short distinct names,
        // then use 300 distinct 250-byte names sharing an uncached suffix.
        // The wire input stays small because it points back to that suffix.
        let mut bytes = vec![0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let count_at = if response {
            bytes[2] = 0x80;
            6
        } else {
            4
        };
        bytes[count_at..count_at + 2].copy_from_slice(&364u16.to_be_bytes());
        let mut suffix = 0;
        for i in 0..364 {
            let label = if i < 64 {
                format!("p{i:02}")
            } else {
                format!("n{:03}", i - 64)
            };
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
            if i < 64 {
                bytes.push(0);
            } else if i == 64 {
                suffix = u16::try_from(bytes.len()).unwrap();
                for (len, byte) in [(63, b'a'), (63, b'b'), (63, b'c'), (51, b'd')] {
                    bytes.push(len);
                    bytes.extend(std::iter::repeat_n(byte, usize::from(len)));
                }
                bytes.push(0);
            } else {
                bytes.extend_from_slice(&(0xc000 | suffix).to_be_bytes());
            }
            bytes.extend_from_slice(&[0, 1, 0, 1]); // A, IN
            if response {
                bytes.extend_from_slice(&[0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
            }
        }
        assert!(bytes.len() < 8192);
        Message::from_vec(&bytes).unwrap()
    }

    #[test]
    fn query_with_edns_round_trips() {
        let mut m = Message::new(7, MessageType::Query, OpCode::Query);
        m.add_query(Query::query(
            Name::from_ascii("example.test.").unwrap(),
            RecordType::A,
        ));
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.flags_mut().dnssec_ok = true;
        m.set_edns(edns);
        let m = reparse(&m);
        assert!(m.edns.is_some());
        assert_eq!(reparse(&m), m);
        round_trip(&m);
    }

    #[test]
    fn cname_and_a_round_trip() {
        let m = response();
        assert_eq!(reparse(&m), m);
        round_trip(&m);
    }

    #[test]
    fn oversized_questions_reach_buffer_limit() {
        let m = large_message(false);
        assert_eq!(m.queries.len(), 364);
        let error = m.to_vec().unwrap_err();
        assert!(
            matches!(error, ProtoError::NotAllRecordsWritten { count, .. } if count < m.queries.len()),
            "{error:?}"
        );
        round_trip(&m);
    }

    #[test]
    #[should_panic(expected = "DNS questions alone must exceed the size limit")]
    fn writable_questions_reject_reported_limit() {
        let m = response();
        assert!(!m.queries.is_empty());
        questions_exceed_limit(&m, 0);
    }

    #[test]
    fn oversized_answers_keep_prefix_with_tc() {
        let m = large_message(true);
        let back = reparse(&m);
        assert_eq!(m.answers.len(), 364);
        assert!(!m.metadata.truncation);
        assert!(back.metadata.truncation);
        assert!(!back.answers.is_empty());
        assert!(back.answers.len() < m.answers.len());
        written_matches(&m, &back);
        round_trip(&m);
    }

    #[test]
    #[should_panic(expected = "DNS id changed")]
    fn changed_id_is_rejected() {
        let m = response();
        let mut back = reparse(&m);
        back.metadata.id += 1;
        written_matches(&m, &back);
    }

    #[test]
    #[should_panic(expected = "DNS message changed without truncation")]
    fn changed_answer_is_rejected() {
        let m = response();
        let mut back = reparse(&m);
        back.answers[1].data = RData::A(A::new(192, 0, 2, 2));
        written_matches(&m, &back);
    }

    #[test]
    #[should_panic(expected = "DNS records lost without TC")]
    fn missing_tc_is_rejected() {
        let m = response();
        let mut back = reparse(&m);
        back.answers.pop().unwrap();
        written_matches(&m, &back);
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn truncated_non_prefix_is_rejected() {
        let m = response();
        let mut back = reparse(&m);
        back.metadata.truncation = true;
        back.answers.remove(0);
        written_matches(&m, &back);
    }
}
