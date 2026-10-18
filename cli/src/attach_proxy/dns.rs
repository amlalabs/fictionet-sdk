//! Looking names up in the world: an `A` query from the sandbox's address
//! to the world's DNS server, as a UDP packet, the way the sandbox's own
//! resolver would send it under `tun`.
//!
//! This module builds the query and reads the answer. The sending, the
//! retries and the cache are in the `fictionet` binary's stack.

use std::net::{Ipv4Addr, SocketAddr};

use fictionet::stdlib::protocols::dns::op::{Message, MessageType, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{Name, RData, RecordType};

/// Answers are kept at most this long, whatever their TTL.
pub const MAX_TTL: u32 = 60;

/// At most this many aliases may lead to the address.
const MAX_ALIASES: usize = 16;

/// Why a name has no address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// NXDOMAIN, or no `A` record for the queried name or its final alias.
    NoSuchName,
    /// The server answered with another error, such as SERVFAIL, or an
    /// alias chain that cycles or exceeds 16 aliases.
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
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    ok.then_some(host)
}

/// An `A` query for `name` with ID `id`, recursion desired.
pub fn query(name: &str, id: u16) -> Option<Vec<u8>> {
    let mut m = Message::query();
    m.metadata.id = id;
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(
        Name::from_ascii(format!("{name}.")).ok()?,
        RecordType::A,
    ));
    m.to_vec().ok()
}

/// Reads a datagram that came back from `from`. `None` if it is not the
/// answer to this query (another ID, another question, not from the
/// server, or not DNS), so the caller keeps waiting. Otherwise follows
/// up to 16 `CNAME` aliases from the queried name and returns the first
/// `A` record for the final name, or why there is none. The lifetime is
/// the shortest TTL among those records, capped at [`MAX_TTL`]. Unrelated
/// records are ignored; cycles and longer chains fail the lookup.
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
    let mut name = &asked;
    let mut ttl = MAX_TTL;
    let mut seen = Vec::new();
    for _ in 0..=MAX_ALIASES {
        // Name compares case-insensitively, including for cycle detection.
        if seen.contains(&name) {
            return Some(Err(Lookup::Failed("CNAME cycle".into())));
        }
        seen.push(name);
        let alias = m.answers.iter().find_map(|r| match &r.data {
            RData::CNAME(target) if &r.name == name => Some((&target.0, r.ttl)),
            _ => None,
        });
        if let Some((target, alias_ttl)) = alias {
            name = target;
            ttl = ttl.min(alias_ttl);
            continue;
        }
        let found = m.answers.iter().find_map(|r| match &r.data {
            RData::A(a) if &r.name == name => Some((a.0, ttl.min(r.ttl))),
            _ => None,
        });
        return Some(found.ok_or(Lookup::NoSuchName));
    }
    Some(Err(Lookup::Failed(format!(
        "CNAME chain exceeds {MAX_ALIASES} aliases"
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::protocols::dns::rr::Record;
    use fictionet::stdlib::protocols::dns::rr::rdata::{A, CNAME};

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
        for bad in [
            "",
            ".",
            "a..b",
            "a b",
            "a/b",
            "ex\u{e4}mple.test",
            &"a".repeat(64),
            &"a.".repeat(128),
        ] {
            assert_eq!(normalize(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn an_answer_with_an_address() {
        let q = query("example.test", 7).unwrap();
        let r = reply(&q, |r| {
            let name = Name::from_ascii("example.test.").unwrap();
            r.answers.push(Record::from_rdata(
                name,
                300,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 10))),
            ));
        });
        assert_eq!(
            answer(&r, server(), server(), "example.test", 7),
            Some(Ok((Ipv4Addr::new(203, 0, 113, 10), 60)))
        );
    }

    #[test]
    fn a_cname_chain_gives_the_address_at_its_end() {
        let q = query("www.example.test", 9).unwrap();
        let r = reply(&q, |r| {
            let www = Name::from_ascii("www.example.test.").unwrap();
            let target = Name::from_ascii("example.test.").unwrap();
            r.answers.push(Record::from_rdata(
                www,
                30,
                RData::CNAME(CNAME(target.clone())),
            ));
            r.answers.push(Record::from_rdata(
                target,
                20,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 11))),
            ));
        });
        assert_eq!(
            answer(&r, server(), server(), "www.example.test", 9),
            Some(Ok((Ipv4Addr::new(203, 0, 113, 11), 20)))
        );
    }

    fn address(name: &str, ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 11))),
        )
    }

    fn alias(name: &str, target: &str, ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            ttl,
            RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
        )
    }

    #[test]
    fn a_chain_uses_its_shortest_ttl_in_any_record_order() {
        let q = query("www.example.test", 9).unwrap();
        for (first, second, terminal, expected) in [
            (1, 30, 60, 1),
            (30, 1, 60, 1),
            (30, 60, 1, 1),
            (300, 300, 300, MAX_TTL),
            (0, 30, 60, 0),
            (30, 0, 60, 0),
            (30, 60, 0, 0),
        ] {
            let records = [
                alias("WWW.example.TEST.", "middle.test.", first),
                alias("MIDDLE.test.", "end.test.", second),
                address("END.test.", terminal),
            ];
            for order in [
                [0, 1, 2],
                [0, 2, 1],
                [1, 0, 2],
                [1, 2, 0],
                [2, 0, 1],
                [2, 1, 0],
            ] {
                let r = reply(&q, |r| {
                    r.answers = order.map(|i| records[i].clone()).to_vec();
                });
                assert_eq!(
                    answer(&r, server(), server(), "www.example.test", 9),
                    Some(Ok((Ipv4Addr::new(203, 0, 113, 11), expected))),
                    "TTLs {first}/{second}/{terminal}, order {order:?}"
                );
            }
        }
    }

    #[test]
    fn unrelated_records_do_not_supply_an_address_or_ttl() {
        let q = query("www.example.test", 9).unwrap();
        for aliases in [false, true] {
            for complete in [false, true] {
                let r = reply(&q, |r| {
                    let mut unrelated = address("unrelated.test.", 0);
                    unrelated.data = RData::A(A(Ipv4Addr::LOCALHOST));
                    r.answers.push(unrelated);
                    r.answers.push(alias("other.test.", "unrelated.test.", 0));
                    if aliases {
                        r.answers.push(alias("www.example.test.", "end.test.", 10));
                    }
                    if complete {
                        r.answers.push(address(
                            if aliases {
                                "end.test."
                            } else {
                                "www.example.test."
                            },
                            20,
                        ));
                    }
                });
                let expected = if complete {
                    Ok((
                        Ipv4Addr::new(203, 0, 113, 11),
                        if aliases { 10 } else { 20 },
                    ))
                } else {
                    Err(Lookup::NoSuchName)
                };
                assert_eq!(
                    answer(&r, server(), server(), "www.example.test", 9),
                    Some(expected)
                );
            }
        }
    }

    #[test]
    fn cname_cycles_fail_even_with_unrelated_addresses() {
        let q = query("www.example.test", 9).unwrap();
        for cycle in [
            vec![alias("www.example.test.", "WWW.EXAMPLE.TEST.", 10)],
            vec![
                alias("www.example.test.", "middle.test.", 10),
                alias("middle.test.", "end.test.", 10),
                alias("end.test.", "MIDDLE.test.", 10),
            ],
        ] {
            let r = reply(&q, |r| {
                r.answers = cycle;
                r.answers.push(address("unrelated.test.", 60));
            });
            assert!(matches!(
                answer(&r, server(), server(), "www.example.test", 9),
                Some(Err(Lookup::Failed(_)))
            ));
        }
    }

    #[test]
    fn cname_chains_are_bounded() {
        let q = query("name0.test", 9).unwrap();
        for hops in [16, 17] {
            let r = reply(&q, |r| {
                for i in 0..hops {
                    r.answers.push(alias(
                        &format!("name{i}.test."),
                        &format!("name{}.test.", i + 1),
                        30,
                    ));
                }
                r.answers.push(address(&format!("name{hops}.test."), 60));
            });
            let found = answer(&r, server(), server(), "name0.test", 9);
            if hops == 16 {
                assert_eq!(found, Some(Ok((Ipv4Addr::new(203, 0, 113, 11), 30))));
            } else {
                assert!(matches!(found, Some(Err(Lookup::Failed(_)))));
            }
        }
    }

    #[test]
    fn nxdomain_nodata_and_servfail() {
        let q = query("nope.test", 1).unwrap();
        let nx = reply(&q, |r| r.metadata.response_code = ResponseCode::NXDomain);
        assert_eq!(
            answer(&nx, server(), server(), "nope.test", 1),
            Some(Err(Lookup::NoSuchName))
        );
        let nodata = reply(&q, |_| {});
        assert_eq!(
            answer(&nodata, server(), server(), "nope.test", 1),
            Some(Err(Lookup::NoSuchName))
        );
        let fail = reply(&q, |r| r.metadata.response_code = ResponseCode::ServFail);
        assert!(matches!(
            answer(&fail, server(), server(), "nope.test", 1),
            Some(Err(Lookup::Failed(_)))
        ));
    }

    #[test]
    fn other_datagrams_are_not_the_answer() {
        let q = query("example.test", 5).unwrap();
        let good = reply(&q, |_| {});
        // From another address or port.
        assert_eq!(
            answer(
                &good,
                "10.0.0.9:53".parse().unwrap(),
                server(),
                "example.test",
                5
            ),
            None
        );
        // Another ID.
        assert_eq!(answer(&good, server(), server(), "example.test", 6), None);
        // Another question.
        assert_eq!(answer(&good, server(), server(), "other.test", 5), None);
        // The query itself, echoed: not a response.
        assert_eq!(answer(&q, server(), server(), "example.test", 5), None);
        // Not DNS.
        assert_eq!(
            answer(b"hello", server(), server(), "example.test", 5),
            None
        );
        // The question in another case is the same question.
        let upper = reply(&query("EXAMPLE.test", 5).unwrap(), |_| {});
        assert!(answer(&upper, server(), server(), "example.test", 5).is_some());
    }
}
