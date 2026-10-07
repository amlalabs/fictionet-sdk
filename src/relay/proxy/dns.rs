//! Looking names up in the world: an `A` query from the sandbox's address
//! to the world's DNS server, as a UDP packet, the way the sandbox's own
//! resolver would send it under `tun`.
//!
//! This module builds the query and reads the answer. The sending, the
//! retries and the cache are in the `fictionet` binary's stack.

use std::net::{Ipv4Addr, SocketAddr};

use crate::stdlib::dns::op::{Message, MessageType, Query, ResponseCode};
use crate::stdlib::dns::rr::{Name, RData, RecordType};

/// Answers are kept at most this long, whatever their TTL.
pub const MAX_TTL: u32 = 60;

/// Why a name has no address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// NXDOMAIN, or an answer with no `A` record.
    NoSuchName,
    /// The server answered with another error, such as SERVFAIL.
    Failed(String),
}

/// A name a client asked for, checked and in the form DNS compares:
/// lowercase, with no trailing dot.
pub fn normalize(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let ok = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    ok.then_some(host)
}

/// An `A` query for `name` with ID `id`, recursion desired.
pub fn query(name: &str, id: u16) -> Option<Vec<u8>> {
    let mut m = Message::query();
    m.metadata.id = id;
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(format!("{name}.")).ok()?, RecordType::A));
    m.to_vec().ok()
}

/// Reads a datagram that came back from `from`. `None` if it is not the
/// answer to this query (another ID, another question, not from the
/// server, or not DNS), so the caller keeps waiting. Otherwise the first
/// address and how long to keep it, or why there is none.
pub fn answer(
    bytes: &[u8],
    from: SocketAddr,
    server: SocketAddr,
    name: &str,
    id: u16,
) -> Option<Result<(Ipv4Addr, u32), Lookup>> {
    if from != server {
        return None;
    }
    let m = Message::from_vec(bytes).ok()?;
    if m.metadata.id != id || m.metadata.message_type != MessageType::Response {
        return None;
    }
    let asked = Name::from_ascii(format!("{name}.")).ok()?;
    let same_question = m.queries.len() == 1
        && m.queries[0].query_type() == RecordType::A
        && m.queries[0].name().to_lowercase() == asked.to_lowercase();
    if !same_question {
        return None;
    }
    match m.metadata.response_code {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => return Some(Err(Lookup::NoSuchName)),
        other => return Some(Err(Lookup::Failed(format!("{other:?}")))),
    }
    // The first A record. With CNAMEs, it is the one at the end of the
    // chain: the answer section holds only records for this question.
    let found = m.answers.iter().find_map(|r| match &r.data {
        RData::A(a) => Some((a.0, r.ttl.min(MAX_TTL))),
        _ => None,
    });
    Some(found.ok_or(Lookup::NoSuchName))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::dns::rr::Record;
    use crate::stdlib::dns::rr::rdata::{A, CNAME};

    const SERVER: &str = "10.0.0.1:53";

    fn server() -> SocketAddr {
        SERVER.parse().unwrap()
    }

    fn reply(q: &[u8], f: impl FnOnce(&mut Message)) -> Vec<u8> {
        let q = Message::from_vec(q).unwrap();
        let mut r = Message::response(q.metadata.id, q.metadata.op_code);
        r.queries = q.queries.clone();
        f(&mut r);
        r.to_vec().unwrap()
    }

    #[test]
    fn names_are_checked_and_lowercased() {
        assert_eq!(normalize("Example.TEST.").as_deref(), Some("example.test"));
        assert_eq!(normalize("a_b-c.test").as_deref(), Some("a_b-c.test"));
        for bad in ["", ".", "a..b", "a b", "a/b", "ex\u{e4}mple.test", &"a".repeat(64), &"a.".repeat(128)] {
            assert_eq!(normalize(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn an_answer_with_an_address() {
        let q = query("example.test", 7).unwrap();
        let r = reply(&q, |r| {
            let name = Name::from_ascii("example.test.").unwrap();
            r.answers.push(Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::new(203, 0, 113, 10)))));
        });
        assert_eq!(answer(&r, server(), server(), "example.test", 7), Some(Ok((Ipv4Addr::new(203, 0, 113, 10), 60))));
    }

    #[test]
    fn a_cname_chain_gives_the_address_at_its_end() {
        let q = query("www.example.test", 9).unwrap();
        let r = reply(&q, |r| {
            let www = Name::from_ascii("www.example.test.").unwrap();
            let target = Name::from_ascii("example.test.").unwrap();
            r.answers.push(Record::from_rdata(www, 30, RData::CNAME(CNAME(target.clone()))));
            r.answers.push(Record::from_rdata(target, 20, RData::A(A(Ipv4Addr::new(203, 0, 113, 11)))));
        });
        assert_eq!(answer(&r, server(), server(), "www.example.test", 9), Some(Ok((Ipv4Addr::new(203, 0, 113, 11), 20))));
    }

    #[test]
    fn nxdomain_nodata_and_servfail() {
        let q = query("nope.test", 1).unwrap();
        let nx = reply(&q, |r| r.metadata.response_code = ResponseCode::NXDomain);
        assert_eq!(answer(&nx, server(), server(), "nope.test", 1), Some(Err(Lookup::NoSuchName)));
        let nodata = reply(&q, |_| {});
        assert_eq!(answer(&nodata, server(), server(), "nope.test", 1), Some(Err(Lookup::NoSuchName)));
        let fail = reply(&q, |r| r.metadata.response_code = ResponseCode::ServFail);
        assert!(matches!(answer(&fail, server(), server(), "nope.test", 1), Some(Err(Lookup::Failed(_)))));
    }

    #[test]
    fn other_datagrams_are_not_the_answer() {
        let q = query("example.test", 5).unwrap();
        let good = reply(&q, |_| {});
        // From another address or port.
        assert_eq!(answer(&good, "10.0.0.9:53".parse().unwrap(), server(), "example.test", 5), None);
        // Another ID.
        assert_eq!(answer(&good, server(), server(), "example.test", 6), None);
        // Another question.
        assert_eq!(answer(&good, server(), server(), "other.test", 5), None);
        // The query itself, echoed: not a response.
        assert_eq!(answer(&q, server(), server(), "example.test", 5), None);
        // Not DNS.
        assert_eq!(answer(b"hello", server(), server(), "example.test", 5), None);
        // The question in another case is the same question.
        let upper = reply(&query("EXAMPLE.test", 5).unwrap(), |_| {});
        assert!(answer(&upper, server(), server(), "example.test", 5).is_some());
    }
}
