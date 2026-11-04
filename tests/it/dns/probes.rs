//! What an agent with `dig` sees of the test internet: the probes of the
//! RFC checklist, run from a sandbox on a simulated network whose gateway
//! is an Unbound-like resolver, with the root letters, the
//! `gtld-servers.net` servers, and the public resolvers at their real
//! addresses, all serving or resolving the seeded test hierarchy.
//!
//! Each test is one probe. Where the checklist names a real domain, the
//! probe asks the test zone that plays it: `example.com` for a signed zone
//! served as Cloudflare serves it, `dnssec-failed.com` for a broken chain.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fictionet::Attacher;
use fictionet::Cx;
use fictionet::stdlib::protocols::dns::EdeCode;
use fictionet::stdlib::protocols::dns::Nsid;
use fictionet::stdlib::protocols::dns::op::{
    Edns, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::rdata::TSIG;
use fictionet::stdlib::protocols::dns::rr::rdata::opt::EdnsOption;
use fictionet::stdlib::protocols::dns::rr::rdata::tsig::{TsigAlgorithm, TsigError};
use fictionet::stdlib::protocols::dns::rr::{DNSClass, Name, RData, Record, RecordType};
use fictionet::stdlib::services::dns::Event;
use fictionet::stdlib::world::net::Net;
use fictionet::stdlib::world::net::dns::Recursive;
use fictionet::stdlib::world::net::dns::internet::ROOT_SERVERS;
use fictionet_extras::dns::public::PUBLIC_RESOLVERS;
use fictionet_extras::dns::roots::GTLD_SERVERS;
use fictionet_test_support::dns::{
    ECH, EGRESS, EXAMPLE_COM, ROOT_SERIAL, TestInternet, WWW_EXAMPLE_COM,
};
use fictionet_test_support::sandbox::{Machine, machine};

use super::slices::{ME, edes, tcp, udp};
use crate::common::world::world;

/// The gateway, the sandbox's DHCP resolver.
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// A second sandbox's IPv6 address.
const ME6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
/// a.root-servers.net.
const A_ROOT: Ipv4Addr = Ipv4Addr::new(198, 41, 0, 4);

/// One probe's world: a sandbox at [`ME`], the test internet, and the
/// events of the gateway's resolver.
struct Probe {
    m: Machine,
    attacher: Attacher,
    internet: TestInternet,
    gateway: Arc<Mutex<Vec<Event>>>,
}

/// Runs `probe` in a world with the test internet's servers, the public
/// resolvers validating from its root, and an Unbound-like gateway.
fn probe<F, Fut>(probe: F)
where
    F: FnOnce(Cx, Probe) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    world(Duration::from_secs(300), move |fcx| async move {
        let internet = TestInternet::new();
        let at = internet.place().clone();
        let clock = TestInternet::clock();
        let anchors = internet.anchors();
        let config = internet.config();
        let gateway = Arc::new(Mutex::new(Vec::new()));
        let seen = gateway.clone();
        let (attacher, attachments) = fictionet::attachments();
        Net::new()
            .hosts(internet.hosts())
            .hosts(at.public_resolvers(|resolver, site, host| {
                let config = resolver.config(site.identity.clone());
                let config = resolver
                    .whoami(config, site, EGRESS)
                    .anchors(anchors.clone());
                host.program(Recursive::new(config, clock).per_sandbox())
            }))
            .gateway(move |host, _declared| {
                let seen = seen.clone();
                host.program(
                    Recursive::new(config.clone(), clock)
                        .on_event(move |event| seen.lock().unwrap().push(event.clone())),
                )
            })
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        probe(
            fcx.clone(),
            Probe {
                m,
                attacher,
                internet,
                gateway,
            },
        )
        .await
    })
}

/// The query `dig name rtype` sends by default: RD and AD set, and an OPT
/// record offering 1232 octets without DO.
fn dig(id: u16, name: &str, rtype: RecordType) -> Message {
    let mut query = Message::new(id, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.metadata.authentic_data = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    query.set_edns(edns);
    query
}

/// `query` with DO set, as `dig +dnssec`.
fn dnssec(mut query: Message) -> Message {
    query.edns.as_mut().unwrap().set_dnssec_ok(true);
    query
}

/// `query` with RD clear, as `dig +norec`.
fn norec(mut query: Message) -> Message {
    query.metadata.recursion_desired = false;
    query
}

/// What `server` answers `query` over UDP.
async fn send(fcx: &Cx, m: &Machine, server: impl Into<IpAddr>, query: &Message) -> Message {
    let server = SocketAddr::new(server.into(), 53);
    let reply = udp(fcx, m, server, &query.to_vec().unwrap()).await;
    let reply = Message::from_vec(&reply).expect("a reply parses");
    assert_eq!(
        reply.metadata.id, query.metadata.id,
        "the reply has the query's ID"
    );
    assert_eq!(reply.metadata.message_type, MessageType::Response);
    reply
}

/// The records of `records` of type `rtype`, as their data's text.
fn data(records: &[Record], rtype: RecordType) -> Vec<String> {
    records
        .iter()
        .filter(|record| record.record_type() == rtype)
        .map(|record| record.data.to_string())
        .collect()
}

/// The A and AAAA addresses in `records`.
fn addresses(records: &[Record]) -> Vec<IpAddr> {
    records
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
            _ => None,
        })
        .collect()
}

/// The TTL of the first record of `rtype` in `records`.
fn ttl(records: &[Record], rtype: RecordType) -> u32 {
    records
        .iter()
        .find(|record| record.record_type() == rtype)
        .unwrap_or_else(|| panic!("a {rtype} record"))
        .ttl
}

// ---------------------------------------------------------------------------
// Reachability and topology

/// P-ROOT: `dig @198.41.0.4 . NS` gives the thirteen root servers with
/// their addresses, authoritatively, and `. SOA +norec` the day's serial.
#[test]
fn p_root() {
    probe(|fcx, p| async move {
        let reply = send(&fcx, &p.m, A_ROOT, &dig(1, ".", RecordType::NS)).await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.metadata.authoritative);
        assert!(!reply.metadata.recursion_available);
        let mut servers = data(&reply.answers, RecordType::NS);
        servers.sort();
        let letters: Vec<String> = ROOT_SERVERS.iter().map(|l| l.host.to_string()).collect();
        assert_eq!(servers, letters);
        let glue = addresses(&reply.additionals);
        for letter in &ROOT_SERVERS {
            for address in letter.addresses() {
                assert!(glue.contains(&address), "{address} in {glue:?}");
            }
        }

        let reply = send(&fcx, &p.m, A_ROOT, &norec(dig(2, ".", RecordType::SOA))).await;
        assert!(reply.metadata.authoritative);
        let [soa] = reply.answers.as_slice() else {
            panic!("one SOA, got {:?}", reply.answers);
        };
        let RData::SOA(soa) = &soa.data else {
            panic!("an SOA, got {soa}");
        };
        assert_eq!(soa.serial, ROOT_SERIAL);
        assert_eq!(soa.mname.to_string(), "a.root-servers.net.");
        Ok(())
    });
}

/// P-TRACE: `dig +trace www.example.com` walks from the configured
/// resolver's `. NS` to a root letter, a `gtld-servers.net` server, and
/// `example.com`'s server, each referral carrying the DS RRset and its
/// signature, and the last hop the signed answer.
#[test]
fn p_trace() {
    probe(|fcx, p| async move {
        let roots = send(&fcx, &p.m, GATEWAY, &dnssec(dig(1, ".", RecordType::NS))).await;
        assert_eq!(data(&roots.answers, RecordType::NS).len(), 13);
        assert!(!data(&roots.answers, RecordType::RRSIG).is_empty());

        let question = || norec(dnssec(dig(2, "www.example.com.", RecordType::A)));
        let referral = send(&fcx, &p.m, A_ROOT, &question()).await;
        assert!(!referral.metadata.authoritative);
        assert!(referral.answers.is_empty());
        let mut tld = data(&referral.authorities, RecordType::NS);
        tld.sort();
        let gtld: Vec<String> = GTLD_SERVERS.iter().map(|s| s.host.to_string()).collect();
        assert_eq!(tld, gtld);
        assert_eq!(data(&referral.authorities, RecordType::DS).len(), 1);
        assert!(
            data(&referral.authorities, RecordType::RRSIG)
                .iter()
                .any(|s| s.starts_with("DS "))
        );
        let a_gtld = IpAddr::V4(GTLD_SERVERS[0].v4);
        assert!(
            addresses(&referral.additionals).contains(&a_gtld),
            "{referral}"
        );

        let referral = send(&fcx, &p.m, a_gtld, &question()).await;
        assert!(!referral.metadata.authoritative);
        let mut servers = data(&referral.authorities, RecordType::NS);
        servers.sort();
        assert_eq!(servers, ["ns1.example.com.", "ns2.example.com."]);
        assert_eq!(data(&referral.authorities, RecordType::DS).len(), 1);
        assert!(
            data(&referral.authorities, RecordType::RRSIG)
                .iter()
                .any(|s| s.starts_with("DS "))
        );
        let ns1 = IpAddr::V4(EXAMPLE_COM[0]);
        assert!(addresses(&referral.additionals).contains(&ns1));

        let answer = send(&fcx, &p.m, ns1, &question()).await;
        assert!(answer.metadata.authoritative);
        assert_eq!(addresses(&answer.answers), [IpAddr::V4(WWW_EXAMPLE_COM)]);
        assert!(
            data(&answer.answers, RecordType::RRSIG)
                .iter()
                .any(|s| s.starts_with("A "))
        );
        Ok(())
    });
}

/// P-PUBRES: every public resolver address answers, over IPv4 and IPv6,
/// with the same address the hierarchy gives.
#[test]
fn p_pubres() {
    probe(|fcx, p| async move {
        let m6 = machine(&fcx, p.attacher.attach("v6")?, ME6);
        let mut id = 0;
        for resolver in &PUBLIC_RESOLVERS {
            for address in &resolver.addresses {
                for (m, server) in [
                    (&p.m, IpAddr::V4(address.v4)),
                    (&m6, IpAddr::V6(address.v6)),
                ] {
                    id += 1;
                    let reply =
                        send(&fcx, m, server, &dig(id, "www.example.com.", RecordType::A)).await;
                    assert_eq!(
                        reply.metadata.response_code,
                        ResponseCode::NoError,
                        "{server}"
                    );
                    assert!(reply.metadata.recursion_available, "{server}");
                    assert_eq!(
                        addresses(&reply.answers),
                        [IpAddr::V4(WWW_EXAMPLE_COM)],
                        "{server}"
                    );
                }
            }
        }
        Ok(())
    });
}

/// `dig myip.opendns.com @208.67.222.222` gives the address the question
/// came from as OpenDNS sees it, the network's egress, with TTL 0 and AA
/// clear, as the real resolver answers it.
#[test]
fn p_myip() {
    probe(|fcx, p| async move {
        let opendns = Ipv4Addr::new(208, 67, 222, 222);
        let reply = send(
            &fcx,
            &p.m,
            opendns,
            &dig(1, "myip.opendns.com.", RecordType::A),
        )
        .await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(!reply.metadata.authoritative);
        assert_eq!(addresses(&reply.answers), [IpAddr::from(EGRESS)]);
        assert_eq!(ttl(&reply.answers, RecordType::A), 0);
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Header and protocol

/// P-AA: the gateway's answers carry QR, RD, and RA, and no AA.
#[test]
fn p_aa() {
    probe(|fcx, p| async move {
        let reply = send(&fcx, &p.m, GATEWAY, &dig(1, "example.com.", RecordType::A)).await;
        let flags = &reply.metadata;
        assert_eq!(flags.response_code, ResponseCode::NoError);
        assert!(flags.recursion_desired && flags.recursion_available);
        assert!(!flags.authoritative);
        assert_eq!(addresses(&reply.answers), [IpAddr::V4(WWW_EXAMPLE_COM)]);
        Ok(())
    });
}

/// P-SOA-NEG: NXDOMAIN carries the parent zone's SOA, with TTL the
/// smaller of its TTL and MINIMUM (RFC 2308 §3), and NODATA the zone's.
#[test]
fn p_soa_neg() {
    probe(|fcx, p| async move {
        let reply = send(
            &fcx,
            &p.m,
            GATEWAY,
            &dig(1, "nonexistent-xyz.com.", RecordType::A),
        )
        .await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        let soa: Vec<&Record> = reply
            .authorities
            .iter()
            .filter(|record| record.record_type() == RecordType::SOA)
            .collect();
        assert_eq!(soa.len(), 1, "{reply}");
        assert_eq!(soa[0].name.to_string(), "com.");
        assert!(soa[0].ttl <= 900);

        let reply = send(
            &fcx,
            &p.m,
            GATEWAY,
            &dig(2, "www.example.com.", RecordType::TXT),
        )
        .await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.answers.is_empty());
        let soa = reply
            .authorities
            .iter()
            .find(|record| record.record_type() == RecordType::SOA)
            .expect("an SOA");
        assert_eq!(soa.name.to_string(), "example.com.");
        assert_eq!(soa.ttl, 300);
        Ok(())
    });
}

/// P-TYPES: MX, SPF in TXT, DMARC and DKIM under underscore labels, CAA,
/// NS, SOA, SRV, HTTPS with its ECH configuration intact, PTR, and a
/// CNAME with its target.
#[test]
fn p_types() {
    probe(|fcx, p| async move {
        let cases: [(&str, RecordType, &str); 11] = [
            ("example.com.", RecordType::MX, "10 mail.example.com."),
            ("example.com.", RecordType::TXT, "v=spf1 mx -all"),
            ("_dmarc.example.com.", RecordType::TXT, "v=DMARC1; p=reject"),
            (
                "mail2026._domainkey.example.com.",
                RecordType::TXT,
                "v=DKIM1; k=ed25519",
            ),
            ("example.com.", RecordType::CAA, "letsencrypt.org"),
            ("example.com.", RecordType::NS, "ns1.example.com."),
            (
                "example.com.",
                RecordType::SOA,
                "ns1.example.com. dns.example.com. 2026110101",
            ),
            (
                "_xmpp-server._tcp.example.com.",
                RecordType::SRV,
                "5 0 5269 xmpp.example.com.",
            ),
            ("example.com.", RecordType::HTTPS, "alpn=h2,h3"),
            ("8.8.8.8.in-addr.arpa.", RecordType::PTR, "dns.google."),
            ("alias.example.com.", RecordType::CNAME, "www.example.com."),
        ];
        for (n, (name, rtype, text)) in cases.into_iter().enumerate() {
            let reply = send(&fcx, &p.m, GATEWAY, &dig(n as u16, name, rtype)).await;
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NoError,
                "{name} {rtype}"
            );
            let found = data(&reply.answers, rtype);
            assert!(
                found.iter().any(|record| record.contains(text)),
                "{name} {rtype}: {found:?}"
            );
        }
        let reply = send(
            &fcx,
            &p.m,
            GATEWAY,
            &dig(20, "example.com.", RecordType::HTTPS),
        )
        .await;
        let https = data(&reply.answers, RecordType::HTTPS).join(" ");
        assert!(
            https.contains(&format!("ech=\"{ECH}\"")) && https.contains("ipv4hint=45.33.20.80"),
            "{https}"
        );
        let reply = send(
            &fcx,
            &p.m,
            GATEWAY,
            &dig(21, "alias.example.com.", RecordType::A),
        )
        .await;
        assert_eq!(
            data(&reply.answers, RecordType::CNAME),
            ["www.example.com."]
        );
        assert_eq!(addresses(&reply.answers), [IpAddr::V4(WWW_EXAMPLE_COM)]);
        Ok(())
    });
}

/// P-ANY: `dig ANY example.com @ns1.example.com` gets the one HINFO
/// record "RFC8482" that Cloudflare's servers send (RFC 8482 §4.2).
#[test]
fn p_any() {
    probe(|fcx, p| async move {
        let query = norec(dig(1, "example.com.", RecordType::ANY));
        let reply = send(&fcx, &p.m, EXAMPLE_COM[0], &query).await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.metadata.authoritative);
        let hinfo = data(&reply.answers, RecordType::HINFO);
        assert_eq!(hinfo.len(), 1, "{reply}");
        assert!(hinfo[0].contains("RFC8482"), "{hinfo:?}");
        assert_eq!(reply.answers.len(), 1, "{reply}");
        Ok(())
    });
}

/// P-UNKNOWN: a type no record has gets NOERROR with the zone's SOA.
#[test]
fn p_unknown() {
    probe(|fcx, p| async move {
        let rtype = RecordType::from(65400);
        let reply = send(&fcx, &p.m, GATEWAY, &dig(1, "example.com.", rtype)).await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.answers.is_empty());
        assert_eq!(data(&reply.authorities, RecordType::SOA).len(), 1);
        Ok(())
    });
}

/// The NSID in `reply`, if it has one.
fn nsid(reply: &Message) -> Option<Vec<u8>> {
    let edns = reply.edns.as_ref()?;
    edns.options()
        .as_ref()
        .iter()
        .find_map(|(_, option)| Nsid::from_option(option))
        .map(|nsid| nsid.0)
}

/// P-EDNS: the ednscomp tests, at a root letter and at the gateway. No OPT
/// in the query, none in the reply (RFC 6891 §7); EDNS version 1 gets
/// BADVERS with an OPT of version 0 (§6.1.3); unknown flags and options
/// are ignored and never echoed (§6.1.2, §6.1.4); cookies are ignored as
/// an unknown option (RFC 7873 §5.2.1 lets a server without cookie
/// support do so); DO is copied (RFC 3225 §3); NSID comes only when asked
/// (RFC 5001 §2.1).
#[test]
fn p_edns() {
    probe(|fcx, p| async move {
        let letter = ROOT_SERVERS
            .iter()
            .map(|letter| letter.v4)
            .find(|v4| {
                p.internet
                    .place()
                    .site(IpAddr::V4(*v4))
                    .identity
                    .nsid
                    .is_some()
            })
            .expect("a root letter with an NSID here");
        let letter_nsid = p.internet.place().site(IpAddr::V4(letter)).identity.nsid;
        for (server, nsid_expected) in [(letter, letter_nsid), (GATEWAY, None)] {
            let mut plain = dig(1, "example.com.", RecordType::NS);
            plain.edns = None;
            let reply = send(&fcx, &p.m, server, &plain).await;
            assert!(reply.edns.is_none(), "{server}: no OPT without one");
            assert_ne!(reply.metadata.response_code, ResponseCode::FormErr);

            let reply = send(&fcx, &p.m, server, &dig(2, "example.com.", RecordType::NS)).await;
            let edns = reply.edns.as_ref().expect("an OPT");
            assert_eq!(edns.version(), 0);
            assert!(!edns.flags().dnssec_ok);
            assert_eq!(nsid(&reply), None, "{server}: no NSID unasked");

            let mut v1 = dig(3, "example.com.", RecordType::NS);
            v1.edns.as_mut().unwrap().set_version(1);
            let reply = send(&fcx, &p.m, server, &v1).await;
            assert_eq!(
                u16::from(reply.metadata.response_code),
                16,
                "{server}: BADVERS"
            );
            assert_eq!(reply.edns.as_ref().expect("an OPT").version(), 0);
            assert!(reply.answers.is_empty());

            let mut flags = dig(4, "example.com.", RecordType::NS);
            flags.edns.as_mut().unwrap().flags_mut().z = 0x80;
            let reply = send(&fcx, &p.m, server, &flags).await;
            assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
            let edns = reply.edns.as_ref().expect("an OPT");
            assert_eq!(edns.flags().z, 0, "{server}: unknown flags are zeroed");

            let mut options = dig(5, "example.com.", RecordType::NS);
            let opt = options.edns.as_mut().unwrap().options_mut();
            opt.insert(EdnsOption::Unknown(100, vec![1, 2, 3]));
            opt.insert(EdnsOption::Unknown(10, vec![0x2a; 8]));
            let reply = send(&fcx, &p.m, server, &options).await;
            assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
            let echoed = reply
                .edns
                .as_ref()
                .expect("an OPT")
                .options()
                .as_ref()
                .len();
            assert_eq!(
                echoed, 0,
                "{server}: no option is echoed, the cookie included"
            );

            let reply = send(
                &fcx,
                &p.m,
                server,
                &dnssec(dig(6, "example.com.", RecordType::NS)),
            )
            .await;
            assert!(
                reply.edns.as_ref().expect("an OPT").flags().dnssec_ok,
                "{server}: DO copied"
            );

            let mut asked = dig(7, "example.com.", RecordType::NS);
            asked
                .edns
                .as_mut()
                .unwrap()
                .options_mut()
                .insert(Nsid(Vec::new()).to_option());
            let reply = send(&fcx, &p.m, server, &asked).await;
            assert_eq!(nsid(&reply), nsid_expected, "{server}: NSID when asked");
        }
        Ok(())
    });
}

/// P-TC: `. NS +dnssec` in 512 octets from a root letter sets TC; over TCP
/// the whole answer comes with its signature.
#[test]
fn p_tc() {
    probe(|fcx, p| async move {
        let mut query = dnssec(norec(dig(1, ".", RecordType::NS)));
        query.edns.as_mut().unwrap().set_max_payload(512);
        let reply = send(&fcx, &p.m, A_ROOT, &query).await;
        assert!(reply.metadata.truncation);
        assert!(query.to_vec().unwrap().len() <= 512);

        let server = SocketAddr::new(IpAddr::V4(A_ROOT), 53);
        let replies = tcp(&fcx, &p.m, server, &[query.to_vec().unwrap()]).await;
        let reply = Message::from_vec(&replies[0]).unwrap();
        assert!(!reply.metadata.truncation);
        assert!(replies[0].len() > 512);
        assert_eq!(data(&reply.answers, RecordType::NS).len(), 13);
        assert!(
            data(&reply.answers, RecordType::RRSIG)
                .iter()
                .any(|s| s.starts_with("NS "))
        );
        Ok(())
    });
}

/// P-TCP: queries pipelined on one kept-open TCP connection to the
/// gateway each get their own reply.
#[test]
fn p_tcp() {
    probe(|fcx, p| async move {
        let server = SocketAddr::new(IpAddr::V4(GATEWAY), 53);
        let queries = [
            dig(31, "www.example.com.", RecordType::A),
            dig(32, "example.com.", RecordType::MX),
            dig(33, "www.example.org.", RecordType::A),
        ];
        let bytes: Vec<Vec<u8>> = queries.iter().map(|q| q.to_vec().unwrap()).collect();
        let replies = tcp(&fcx, &p.m, server, &bytes).await;
        let mut ids: Vec<u16> = replies
            .iter()
            .map(|reply| {
                let reply = Message::from_vec(reply).unwrap();
                assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
                assert!(!reply.answers.is_empty(), "{reply}");
                reply.metadata.id
            })
            .collect();
        ids.sort();
        assert_eq!(ids, [31, 32, 33]);
        Ok(())
    });
}

/// P-CASE: the question and the answer's owner come back in the case they
/// were asked in, from the gateway and from an authority.
#[test]
fn p_case() {
    probe(|fcx, p| async move {
        for (server, qname) in [
            (GATEWAY, "ExAmPlE.CoM."),
            (EXAMPLE_COM[0], "WwW.ExAmPlE.cOm."),
        ] {
            let reply = send(&fcx, &p.m, server, &dig(1, qname, RecordType::A)).await;
            assert_eq!(reply.queries[0].name().to_string(), qname);
            let owners: Vec<String> = reply.answers.iter().map(|r| r.name.to_string()).collect();
            assert_eq!(owners, [qname], "{server}");
        }
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Cache behavior

/// Asserts that `got` is `original` less the whole seconds an answer
/// spent in a cache: at least `least` and at most `most`, the times
/// between the first exchange's end and the repeat's start, and between
/// the first exchange's start and the repeat's end.
fn counted_down(original: u32, got: u32, least: Duration, most: Duration) {
    let most_secs = most.as_secs() + u64::from(most.subsec_nanos() > 0);
    let low = original - u32::try_from(most_secs).unwrap();
    let high = original - u32::try_from(least.as_secs()).unwrap();
    assert!(
        (low..=high).contains(&got),
        "TTL {got} after {least:?} to {most:?} from {original}"
    );
}

/// P-TTL: the first answer has the zone's TTL, and a repeat seven seconds
/// later has seven seconds less, at the gateway and at 1.1.1.1.
#[test]
fn p_ttl() {
    probe(|fcx, p| async move {
        for server in [GATEWAY, Ipv4Addr::new(1, 1, 1, 1)] {
            let query = dig(1, "www.example.com.", RecordType::A);
            let asked = fcx.now().since_start();
            let first = send(&fcx, &p.m, server, &query).await;
            let answered = fcx.now().since_start();
            assert_eq!(ttl(&first.answers, RecordType::A), 300, "{server}");
            fcx.sleep(Duration::from_secs(7)).await?;
            let again_asked = fcx.now().since_start();
            let again = send(&fcx, &p.m, server, &query).await;
            let ttl = ttl(&again.answers, RecordType::A);
            counted_down(
                300,
                ttl,
                again_asked - answered,
                fcx.now().since_start() - asked,
            );
        }
        Ok(())
    });
}

/// P-NEG-TTL: an NXDOMAIN's SOA counts down on a repeat too (RFC 2308 §6).
#[test]
fn p_neg_ttl() {
    probe(|fcx, p| async move {
        let query = dig(1, "nx.example.com.", RecordType::A);
        let asked = fcx.now().since_start();
        let first = send(&fcx, &p.m, GATEWAY, &query).await;
        let answered = fcx.now().since_start();
        assert_eq!(first.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(ttl(&first.authorities, RecordType::SOA), 300);
        fcx.sleep(Duration::from_secs(5)).await?;
        let again_asked = fcx.now().since_start();
        let again = send(&fcx, &p.m, GATEWAY, &query).await;
        assert_eq!(again.metadata.response_code, ResponseCode::NXDomain);
        let ttl = ttl(&again.authorities, RecordType::SOA);
        counted_down(
            300,
            ttl,
            again_asked - answered,
            fcx.now().since_start() - asked,
        );
        Ok(())
    });
}

/// P-NXCUT: after `nx.example.com` is NXDOMAIN, a name below it is
/// NXDOMAIN from the cache without another question (RFC 8020).
#[test]
fn p_nxcut() {
    probe(|fcx, p| async move {
        let reply = send(
            &fcx,
            &p.m,
            GATEWAY,
            &dig(1, "nx.example.com.", RecordType::A),
        )
        .await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        let before = p.gateway.lock().unwrap().len();
        let reply = send(
            &fcx,
            &p.m,
            GATEWAY,
            &dig(2, "a.b.nx.example.com.", RecordType::A),
        )
        .await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        let events = p.gateway.lock().unwrap()[before..].to_vec();
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Upstream { .. })),
            "no server was asked: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::Reply { cached: true, .. }))
        );
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Identity probes

/// P-CHAOS: `id.server` at 1.1.1.1, `version.bind` at 9.9.9.9, and
/// `hostname.bind` at k.root give what those sites gave from here, and the
/// gateway gives Unbound's version.
#[test]
fn p_chaos() {
    probe(|fcx, p| async move {
        let cases = [
            (Ipv4Addr::new(1, 1, 1, 1), "id.server.", "sjc10"),
            (
                Ipv4Addr::new(9, 9, 9, 9),
                "version.bind.",
                "Q9-P-2026080500",
            ),
            (
                ROOT_SERVERS[10].v4,
                "hostname.bind.",
                "ns2.gb-lon.k.ripe.net",
            ),
            (GATEWAY, "version.bind.", "unbound 1.26.2"),
        ];
        for (n, (server, name, text)) in cases.into_iter().enumerate() {
            let mut query = Message::new(n as u16, MessageType::Query, OpCode::Query);
            let mut question = Query::query(Name::from_ascii(name).unwrap(), RecordType::TXT);
            question.set_query_class(DNSClass::CH);
            query.add_query(question);
            let reply = send(&fcx, &p.m, server, &query).await;
            let texts: Vec<String> = reply
                .answers
                .iter()
                .filter_map(|record| match &record.data {
                    RData::TXT(txt) => Some(
                        txt.txt_data
                            .iter()
                            .map(|part| String::from_utf8_lossy(part).into_owned())
                            .collect(),
                    ),
                    _ => None,
                })
                .collect();
            assert_eq!(
                (reply.metadata.response_code, texts),
                (ResponseCode::NoError, vec![text.to_string()]),
                "{name} at {server}"
            );
        }
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Reverse and special names

/// P-REV: `dig -x 8.8.8.8` gives `dns.google.` and `dig -x 1.0.0.1`
/// gives `one.one.one.one.`.
#[test]
fn p_rev() {
    probe(|fcx, p| async move {
        for (n, (reverse, ptr)) in [
            ("8.8.8.8.in-addr.arpa.", "dns.google."),
            ("1.0.0.1.in-addr.arpa.", "one.one.one.one."),
        ]
        .into_iter()
        .enumerate()
        {
            let reply = send(
                &fcx,
                &p.m,
                GATEWAY,
                &dig(n as u16, reverse, RecordType::PTR),
            )
            .await;
            assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
            assert_eq!(data(&reply.answers, RecordType::PTR), [ptr]);
        }
        Ok(())
    });
}

/// P-LOCAL: the gateway answers the reverse names of private addresses,
/// `localhost`, `onion`, `invalid`, and `home.arpa` itself, as Unbound's
/// local zones do, and resolves `ipv4only.arpa` to its two addresses.
#[test]
fn p_local() {
    probe(|fcx, p| async move {
        let before = p.gateway.lock().unwrap().len();
        let reply = send(
            &fcx,
            &p.m,
            GATEWAY,
            &dig(1, "1.0.0.10.in-addr.arpa.", RecordType::PTR),
        )
        .await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        let reply = send(&fcx, &p.m, GATEWAY, &dig(2, "localhost.", RecordType::A)).await;
        assert_eq!(addresses(&reply.answers), [IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        for (n, name) in [(3, "foo.onion."), (4, "foo.invalid.")] {
            let reply = send(&fcx, &p.m, GATEWAY, &dig(n, name, RecordType::A)).await;
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NXDomain,
                "{name}"
            );
        }
        let reply = send(&fcx, &p.m, GATEWAY, &dig(5, "home.arpa.", RecordType::SOA)).await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(data(&reply.answers, RecordType::SOA).len(), 1);
        let events = p.gateway.lock().unwrap()[before..].to_vec();
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Upstream { .. })),
            "local names leave nothing: {events:?}"
        );

        let reply = send(
            &fcx,
            &p.m,
            GATEWAY,
            &dig(6, "ipv4only.arpa.", RecordType::A),
        )
        .await;
        let mut found = addresses(&reply.answers);
        found.sort();
        assert_eq!(
            found,
            [
                IpAddr::V4(Ipv4Addr::new(192, 0, 0, 170)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 0, 171))
            ]
        );
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// DNSSEC

/// P-AD: a query with AD set, as `dig` sends by default, gets AD for a
/// signed zone and a signed delegation and not for an unsigned one; a
/// query with neither AD nor DO never gets AD (RFC 6840 §5.7).
#[test]
fn p_ad() {
    probe(|fcx, p| async move {
        for (n, name, rtype, ad) in [
            (1, "www.example.com.", RecordType::A, true),
            (2, "com.", RecordType::NS, true),
            (3, "www.example.org.", RecordType::A, false),
        ] {
            let reply = send(&fcx, &p.m, GATEWAY, &dig(n, name, rtype)).await;
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NoError,
                "{name}"
            );
            assert_eq!(reply.metadata.authentic_data, ad, "{name}");
        }
        let mut plain = dig(4, "www.example.com.", RecordType::A);
        plain.metadata.authentic_data = false;
        let reply = send(&fcx, &p.m, GATEWAY, &plain).await;
        assert!(!reply.metadata.authentic_data);
        Ok(())
    });
}

/// P-BOGUS: a zone whose parent's DS matches none of its keys gets
/// SERVFAIL with Extended DNS Error 9, DNSKEY Missing; with CD the data
/// comes back without AD (RFC 4035 §3.2.2).
#[test]
fn p_bogus() {
    probe(|fcx, p| async move {
        let reply = send(
            &fcx,
            &p.m,
            GATEWAY,
            &dig(1, "www.dnssec-failed.com.", RecordType::A),
        )
        .await;
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(edes(&reply), [EdeCode::DNSKEY_MISSING]);
        assert!(reply.answers.is_empty());

        let mut checking_disabled = dig(2, "www.dnssec-failed.com.", RecordType::A);
        checking_disabled.metadata.checking_disabled = true;
        let reply = send(&fcx, &p.m, GATEWAY, &checking_disabled).await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(!reply.metadata.authentic_data);
        assert!(reply.metadata.checking_disabled);
        assert_eq!(
            addresses(&reply.answers),
            [IpAddr::V4(Ipv4Addr::new(45, 33, 26, 80))]
        );
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Operator behaviors

/// P-RD0: `dig +norec` at 8.8.8.8 after a recursive query answers from
/// the cache with RA and AD; the gateway, as Unbound's default access
/// control does, refuses it.
#[test]
fn p_rd0() {
    probe(|fcx, p| async move {
        let google = Ipv4Addr::new(8, 8, 8, 8);
        let warm = send(
            &fcx,
            &p.m,
            google,
            &dig(1, "www.example.com.", RecordType::A),
        )
        .await;
        assert!(warm.metadata.authentic_data);
        let reply = send(
            &fcx,
            &p.m,
            google,
            &norec(dig(2, "www.example.com.", RecordType::A)),
        )
        .await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.metadata.recursion_available && reply.metadata.authentic_data);
        assert!(!reply.metadata.recursion_desired);
        assert_eq!(addresses(&reply.answers), [IpAddr::V4(WWW_EXAMPLE_COM)]);

        let reply = send(
            &fcx,
            &p.m,
            GATEWAY,
            &norec(dig(3, "www.example.com.", RecordType::A)),
        )
        .await;
        assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
        Ok(())
    });
}

/// P-TSIG: a query signed with a key the server does not hold, at a root
/// letter and at the gateway, gets NOTAUTH with an unsigned TSIG record of
/// error BADKEY that names the key (RFC 8945 §5.2.1, §5.3.2), as BIND
/// answers it. A TSIG record that is not the last record gets FORMERR
/// (§5.2).
#[test]
fn p_tsig() {
    probe(|fcx, p| async move {
        let key = Name::from_ascii("nokey.").unwrap();
        let tsig = || {
            let data = TSIG::new(
                TsigAlgorithm::HmacSha256,
                1_700_000_000,
                300,
                vec![0x2a; 32],
                7,
                None,
                Vec::new(),
            );
            let mut record = Record::from_rdata(key.clone(), 0, data);
            record.dns_class = DNSClass::ANY;
            record
        };
        for server in [A_ROOT, GATEWAY] {
            let mut signed = dig(7, "example.com.", RecordType::NS);
            signed.set_signature(Box::new(tsig()));
            let reply = send(&fcx, &p.m, server, &signed).await;
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NotAuth,
                "{server}"
            );
            assert!(reply.answers.is_empty(), "{server}");
            let answer = reply.signature().expect("a TSIG record");
            assert_eq!(answer.name, key);
            assert_eq!(answer.dns_class, DNSClass::ANY);
            assert_eq!(answer.data.algorithm, TsigAlgorithm::HmacSha256);
            assert_eq!(answer.data.error, Some(TsigError::BadKey));
            assert!(answer.data.mac.is_empty(), "{server}: unsigned");
            assert_eq!(answer.data.oid, 7);

            let mut misplaced = dig(8, "example.com.", RecordType::NS);
            let record = tsig().map(|data| Some(RData::TSIG(data))).unwrap();
            misplaced.add_additional(record);
            misplaced.add_additional(Record::from_rdata(
                Name::from_ascii("x.").unwrap(),
                0,
                RData::A(Ipv4Addr::LOCALHOST.into()),
            ));
            let reply = send(&fcx, &p.m, server, &misplaced).await;
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::FormErr,
                "{server}"
            );
            assert!(reply.signature().is_none());
        }
        Ok(())
    });
}
