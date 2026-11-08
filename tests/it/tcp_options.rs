//! TCP options at connection setup: what a peer's SYN and ACK carried
//! reaches the accepted connection, and a listener answers handshakes with
//! options of its own, refuses them with a RST, or answers with SYN
//! cookies past its backlog. The peer is hand-made packets on one end of a
//! cable.

use fictionet_test_support::world;

use world::world;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::common::line_stack::{LineApp, LineOut, Lined};
use fictionet::stdlib::codec::{LineError, Wire};
use fictionet::stdlib::layer::Budget;
use fictionet::stdlib::network::ConnInfo;
use fictionet::stdlib::network::ConnectionExt;
use fictionet::stdlib::network::ip::{Fields, packet_with, transport_checksum};
use fictionet::stdlib::network::tcp::{
    self, AckAnswer, Answer, Handshake, SYN_OPTIONS_ROOM, SynAnswer, TcpOption,
};
use fictionet::stdlib::protocols::mptcp::{
    self, Capable, Join, Keys, MptcpOption, algorithm, reason,
};
use fictionet::stdlib::services::stack::{self, StreamLimits};
use fictionet::{Cx, End, Interface, InterfaceExt, Packet, pair};
use fictionet_test_support::timeout;

const PEER: &str = "10.0.0.1";
const SERVER: &str = "10.0.0.2";
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;
/// The listener's MPTCP key.
const KEY: u64 = 0x0123_4567_89ab_cdef;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A segment from the peer to the server's port 80. `options` is the
/// whole option area, so its length is a multiple of four.
fn segment(sport: u16, seq: u32, ack: u32, flags: u8, options: &[u8]) -> Packet {
    segment_with(sport, seq, ack, flags, options, b"")
}

/// [`segment`] with a payload.
fn segment_with(
    sport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    options: &[u8],
    payload: &[u8],
) -> Packet {
    let (src, dst) = (ip(PEER), ip(SERVER));
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&80u16.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    let offset = (20 + options.len()) / 4;
    t.extend_from_slice(&[(offset as u8) << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(options);
    t.extend_from_slice(payload);
    let sum = transport_checksum(src, dst, 6, &t);
    t[16..18].copy_from_slice(&sum.to_be_bytes());
    packet_with(src, dst, 6, Fields::default(), &t)
}

/// The TCP header and payload of a packet from the server.
fn tcp_of(p: &Packet) -> &[u8] {
    let ihl = (p.0[0] & 15) as usize * 4;
    &p.0[ihl..]
}

fn seq_of(t: &[u8]) -> u32 {
    u32::from_be_bytes(t[4..8].try_into().unwrap())
}

fn ack_of(t: &[u8]) -> u32 {
    u32::from_be_bytes(t[8..12].try_into().unwrap())
}

fn window_of(t: &[u8]) -> u16 {
    u16::from_be_bytes([t[14], t[15]])
}

fn dport_of(t: &[u8]) -> u16 {
    u16::from_be_bytes([t[2], t[3]])
}

/// The options of a TCP header as (kind, bytes after Kind and Length),
/// No-Operation as (1, []), up to End of Option List.
fn options_of(t: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let len = (t[12] >> 4) as usize * 4;
    assert!((20..=60).contains(&len), "header length {len}");
    let mut area = &t[20..len];
    let mut out = Vec::new();
    while let Some(&kind) = area.first() {
        match kind {
            0 => break,
            1 => {
                out.push((1, Vec::new()));
                area = &area[1..];
            }
            _ => {
                let n = area[1] as usize;
                assert!(n >= 2 && n <= area.len(), "a whole option: {area:?}");
                out.push((kind, area[2..n].to_vec()));
                area = &area[n..];
            }
        }
    }
    out
}

/// The first `n` bytes `conn` reads, or fewer if it ends first.
async fn read_n(fcx: &Cx, conn: &mut tcp::TcpConnection, n: usize) -> fictionet::Result<Vec<u8>> {
    let mut got = Vec::new();
    let mut buf = [0; 64];
    while got.len() < n {
        let k = conn.read(fcx, &mut buf).await?;
        if k == 0 {
            break;
        }
        got.extend_from_slice(&buf[..k]);
    }
    Ok(got)
}

/// The next packet from the server, within a second.
async fn next(fcx: &Cx, raw: &mut End) -> Option<Packet> {
    timeout(fcx, Duration::from_secs(1), raw.recv(fcx))
        .await
        .map(|p| p.unwrap())
}

/// A Linux client's SYN with MPTCP: MSS, SACK-Permitted, Timestamps,
/// No-Operation, Window Scale, then MP_CAPABLE version 1 with flags A and
/// H, padded with End of Option List.
const LINUX_SYN: [u8; 28] = [
    2, 4, 5, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7, 30, 4, 0x01, 0x81, 0, 0, 0, 0,
];

/// The options of [`LINUX_SYN`], typed.
fn linux_syn_options() -> Vec<TcpOption> {
    vec![
        TcpOption::MaxSegmentSize(1460),
        TcpOption::SackPermitted,
        TcpOption::Timestamps { tsval: 1, tsecr: 0 },
        TcpOption::NoOperation,
        TcpOption::WindowScale(7),
        TcpOption::Unknown {
            kind: mptcp::KIND,
            data: vec![0x01, 0x81],
        },
    ]
}

/// MP_TCPRST with this reason, as a TCP option.
fn tcprst(reason: u8) -> TcpOption {
    TcpOption::Unknown {
        kind: mptcp::KIND,
        data: MptcpOption::TcpRst {
            transient: false,
            reason,
        }
        .to_bytes()
        .unwrap(),
    }
}

/// Answers an MP_CAPABLE SYN as an RFC 8684 listener does: the same
/// version and flags, HMAC-SHA256, and its key.
fn answer_mp_capable(syn: &[TcpOption]) -> SynAnswer {
    let offer = syn.iter().find_map(|o| match o {
        TcpOption::Unknown { kind, data } if *kind == mptcp::KIND => match MptcpOption::parse(data)
        {
            Ok(MptcpOption::Capable(offer)) if offer.keys == Keys::Absent => Some(offer),
            _ => None,
        },
        _ => None,
    });
    let Some(offer) = offer else {
        return SynAnswer::Accept(Vec::new());
    };
    let answer = MptcpOption::Capable(Capable {
        algorithms: algorithm::HMAC_SHA256,
        keys: Keys::Sender(KEY),
        ..offer
    });
    SynAnswer::Accept(vec![TcpOption::Unknown {
        kind: mptcp::KIND,
        data: answer.to_bytes().unwrap(),
    }])
}

#[test]
fn syn_options_reach_the_connection_and_the_syn_ack_answers_mptcp() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint(&fcx, side, ip(SERVER));
        let mut listener = server.listen(80)?;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_answer = seen.clone();
        listener.answer(Box::new(move |syn: &tcp::Syn<'_>| {
            seen_by_answer.lock().unwrap().push(syn.options.to_vec());
            answer_mp_capable(syn.options)
        }));

        raw.send(segment(4000, 1000, 0, SYN, &LINUX_SYN));
        let syn_ack = next(&fcx, &mut raw).await.expect("a SYN-ACK");
        let t = tcp_of(&syn_ack);
        assert_eq!(t[13], SYN | ACK);
        let options = options_of(t);
        // The endpoint's own options first, then the answer.
        assert_eq!(options[0].0, 2, "MSS first: {options:?}");
        let (kind, data) = options.last().unwrap();
        assert_eq!(*kind, mptcp::KIND);
        assert_eq!(
            MptcpOption::parse(data).unwrap(),
            MptcpOption::Capable(Capable {
                version: mptcp::VERSION,
                checksum_required: true,
                extensibility: false,
                no_new_subflows: false,
                algorithms: algorithm::HMAC_SHA256,
                keys: Keys::Sender(KEY),
            })
        );
        assert_eq!(*seen.lock().unwrap(), [linux_syn_options()]);

        // A copy of the SYN does not ask again, and the SYN-ACK, resent
        // when the RTO passes, carries the same answer.
        raw.send(segment(4000, 1000, 0, SYN, &LINUX_SYN));
        let again = loop {
            let p = timeout(&fcx, Duration::from_secs(5), raw.recv(&fcx))
                .await
                .expect("the SYN-ACK again")?;
            if tcp_of(&p)[13] == SYN | ACK {
                break p;
            }
        };
        let mut resent_options = options.clone();
        let timestamp = &mut resent_options.iter_mut().find(|o| o.0 == 8).unwrap().1;
        timestamp[..4].copy_from_slice(&(fcx.now().since_start().as_millis() as u32).to_be_bytes());
        assert_eq!(options_of(tcp_of(&again)), resent_options);
        assert_eq!(seen.lock().unwrap().len(), 1);

        // The third ACK's options reach the connection too.
        let third = [1, 1, 253, 2];
        let iss = seq_of(t);
        raw.send(segment(4000, 1001, iss.wrapping_add(1), ACK, &third));
        let conn = listener.accept(&fcx).await?;
        assert_eq!(conn.peer_addr(), SocketAddr::new(ip(PEER), 4000));
        let SynAnswer::Accept(answered) = answer_mp_capable(&linux_syn_options()) else {
            unreachable!()
        };
        let handshake = Handshake {
            origin: tcp::HandshakeOrigin::Syn,
            syn: Some(linux_syn_options().into()),
            syn_ack: Some(answered.into()),
            syn_ipv4: Some(Arc::default()),
            syn_ack_ipv4: Some(Arc::default()),
            ack: vec![
                TcpOption::NoOperation,
                TcpOption::NoOperation,
                TcpOption::Unknown {
                    kind: 253,
                    data: Vec::new(),
                },
            ]
            .into(),
            ack_payload: 0,
            irs: 1000,
            iss,
        };
        assert_eq!(*conn.handshake().unwrap(), handshake);
        Ok(())
    });
}

#[test]
fn a_listener_without_an_answer_adds_nothing() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint(&fcx, side, ip(SERVER));
        let mut listener = server.listen(80)?;
        raw.send(segment(4000, 1000, 0, SYN, &LINUX_SYN));
        let syn_ack = next(&fcx, &mut raw).await.expect("a SYN-ACK");
        let t = tcp_of(&syn_ack);
        let kinds: Vec<u8> = options_of(t).iter().map(|o| o.0).collect();
        assert_eq!(
            kinds,
            [2, 3, 4, 8],
            "MSS, Window Scale, SACK-Permitted and Timestamps without alignment padding"
        );
        raw.send(segment(4000, 1001, seq_of(t).wrapping_add(1), ACK, &[]));
        let conn = listener.accept(&fcx).await?;
        let handshake = conn.handshake().unwrap();
        assert_eq!(handshake.syn.as_deref(), Some(&linux_syn_options()[..]));
        assert_eq!(handshake.syn_ack.as_deref(), Some(&[][..]));
        assert!(handshake.ack.is_empty());
        Ok(())
    });
}

/// Between two endpoints, the accepted side has the SYN the other sent,
/// and the side that connected has no handshake of its own.
#[test]
fn an_endpoint_s_own_syn_reaches_the_other_endpoint() {
    world(Duration::from_secs(10), |fcx| async move {
        let (a, b) = pair();
        let client = tcp::endpoint(&fcx, a, ip(PEER));
        let server = tcp::endpoint(&fcx, b, ip(SERVER));
        let mut listener = server.listen(80)?;
        let conn = client
            .connect(&fcx, SocketAddr::new(ip(SERVER), 80))
            .await?;
        let accepted = listener.accept(&fcx).await?;
        assert!(conn.handshake().is_none());
        let syn = accepted
            .handshake()
            .unwrap()
            .syn
            .clone()
            .expect("the SYN's options");
        assert!(
            matches!(
                *syn,
                [
                    TcpOption::MaxSegmentSize(1460),
                    TcpOption::WindowScale(_),
                    TcpOption::SackPermitted,
                    TcpOption::Timestamps { .. },
                ]
            ),
            "{syn:?}"
        );
        Ok(())
    });
}

#[test]
fn timestamps_and_ecn_are_negotiated_and_timestamps_advance() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint(&fcx, side, ip(SERVER));
        let mut listener = server.listen(80)?;
        raw.send(segment(4000, 0, 0, SYN | 0xc0, &LINUX_SYN));
        let syn_ack = next(&fcx, &mut raw).await.expect("a SYN-ACK");
        let t = tcp_of(&syn_ack);
        assert_eq!(t[13], SYN | ACK | 0x40);
        assert_eq!(transport_checksum(ip(SERVER), ip(PEER), 6, t), 0);
        let timestamps = |t: &[u8]| {
            let (_, value) = options_of(t)
                .into_iter()
                .find(|(kind, _)| *kind == 8)
                .unwrap();
            (
                u32::from_be_bytes(value[..4].try_into().unwrap()),
                u32::from_be_bytes(value[4..].try_into().unwrap()),
            )
        };
        let (tsval, tsecr) = timestamps(t);
        assert_eq!(tsecr, 1);
        let iss = seq_of(t);
        let again = timeout(&fcx, Duration::from_secs(2), raw.recv(&fcx))
            .await
            .expect("a retransmitted SYN-ACK")?;
        let (later, echoed) = timestamps(tcp_of(&again));
        assert_eq!(later.wrapping_sub(tsval), 1000);
        assert_eq!(echoed, 1);
        assert_eq!(tcp_of(&again)[13], SYN | ACK | 0x40);
        assert_eq!(
            transport_checksum(ip(SERVER), ip(PEER), 6, tcp_of(&again)),
            0
        );
        raw.send(segment(4000, 1, iss.wrapping_add(1), ACK, &[]));
        let conn = listener.accept(&fcx).await?;
        assert_eq!(conn.handshake().unwrap().origin, tcp::HandshakeOrigin::Syn);
        assert_eq!(conn.handshake().unwrap().irs, 0);
        let marked = segment_with(4000, 1, iss.wrapping_add(1), PSH | ACK, &[], b"a");
        raw.send(packet_with(
            ip(PEER),
            ip(SERVER),
            6,
            Fields {
                tos: 3,
                ..Fields::default()
            },
            tcp_of(&marked),
        ));
        let echo = next(&fcx, &mut raw).await.expect("a congestion echo");
        assert_eq!(tcp_of(&echo)[13] & 0x40, 0x40);
        assert_eq!(
            transport_checksum(ip(SERVER), ip(PEER), 6, tcp_of(&echo)),
            0
        );
        raw.send(segment_with(
            4000,
            2,
            iss.wrapping_add(1),
            PSH | ACK | 0x80,
            &[],
            b"b",
        ));
        let cleared = next(&fcx, &mut raw)
            .await
            .expect("the acknowledged congestion response");
        assert_eq!(tcp_of(&cleared)[13] & 0x40, 0);
        assert_eq!(
            transport_checksum(ip(SERVER), ip(PEER), 6, tcp_of(&cleared)),
            0
        );
        Ok(())
    });
}

/// A test codec binds the tuple and initial sequence, retaining no extensions.
/// Core supplies the handshake mechanics; worlds supply cookie formats.
#[derive(Debug)]
struct TestCookies;
impl tcp::SynCookies for TestCookies {
    fn issue(&self, input: &tcp::CookieInput<'_>) -> tcp::CookieReply {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, input.key);
        let message = format!("{} {} {}", input.local, input.remote, input.sequence);
        let tag = ring::hmac::sign(&key, message.as_bytes());
        tcp::CookieReply {
            sequence: u32::from_be_bytes(tag.as_ref()[..4].try_into().unwrap()),
            options: Vec::new(),
            ecn: false,
        }
    }
    fn validate(&self, input: &tcp::CookieInput<'_>, cookie: u32) -> Option<tcp::CookieState> {
        (self.issue(input).sequence == cookie).then_some(tcp::CookieState {
            mss: 1460,
            scale: None,
            sack: false,
            ecn: false,
            timestamp: None,
        })
    }
}
fn cookie_options() -> tcp::Options {
    tcp::Options::default().settings(tcp::Settings {
        cookies: Some(&TestCookies),
        ..tcp::Settings::default()
    })
}

#[test]
fn configured_cookies_decline_timestamps_and_ecn_without_retaining_state() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint_with(&fcx, side, ip(SERVER), cookie_options().backlog(1));
        let mut listener = server.listen(80)?;
        for port in [4000, 4001] {
            raw.send(segment(port, 0, 0, SYN | 0xc0, &LINUX_SYN));
        }
        let first = next(&fcx, &mut raw).await.expect("a SYN-ACK");
        let second = next(&fcx, &mut raw).await.expect("the other SYN-ACK");
        let (stateful, cookie) = if dport_of(tcp_of(&first)) == 4000 {
            (first, second)
        } else {
            (second, first)
        };
        assert_eq!(dport_of(tcp_of(&stateful)), 4000);
        assert_eq!(tcp_of(&stateful)[13], SYN | ACK | 0x40);
        assert_eq!(
            transport_checksum(ip(SERVER), ip(PEER), 6, tcp_of(&stateful)),
            0
        );
        let t = tcp_of(&cookie);
        assert_eq!(dport_of(t), 4001);
        assert_eq!(t[13], SYN | ACK);
        assert_eq!(options_of(t), [(2, vec![0x05, 0xb4])]);
        assert_eq!(transport_checksum(ip(SERVER), ip(PEER), 6, t), 0);
        raw.send(segment(4001, 1, seq_of(t).wrapping_add(1), ACK, &[]));
        let mut conn = listener.accept(&fcx).await?;
        assert_eq!(
            conn.handshake().unwrap().origin,
            tcp::HandshakeOrigin::Cookie
        );
        conn.write_all(&fcx, b"hello").await?;
        let data = next(&fcx, &mut raw)
            .await
            .expect("data without negotiated extensions");
        assert_eq!(tcp_of(&data)[13] & 0xc0, 0);
        assert!(options_of(tcp_of(&data)).is_empty());
        assert_eq!(
            transport_checksum(ip(SERVER), ip(PEER), 6, tcp_of(&data)),
            0
        );
        Ok(())
    });
}

/// Closes the connection as soon as it opens.
struct Closes;

impl LineApp for Closes {
    type Timer = ();
    type Work = std::convert::Infallible;
    type Done = std::convert::Infallible;
    type Next = std::convert::Infallible;
    type Error = std::convert::Infallible;

    fn open(&mut self, out: &mut LineOut<'_, Self>) -> Result<(), Self::Error> {
        out.close();
        Ok(())
    }

    fn line(
        &mut self,
        _: Result<Vec<u8>, LineError>,
        _: &mut LineOut<'_, Self>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn a_stack_factory_sees_the_syn_options_in_its_conn_info() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint(&fcx, side, ip(SERVER));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut listener = server.listen(80)?;
        let record = seen.clone();
        fcx.spawn(move |fcx| async move {
            let conn = listener.accept(&fcx).await?;
            let info = ConnInfo {
                handshake: conn.handshake().cloned(),
                ..ConnInfo::new(1, conn.local_addr(), conn.peer_addr())
            };
            // What the factory of the connection's stack is given.
            record
                .lock()
                .unwrap()
                .push(info.handshake.as_ref().unwrap().syn.clone());
            let (limits, budget) = (StreamLimits::default(), Budget::unlimited());
            let stack = Lined::new(Closes);
            let _ = stack::stream(&fcx, conn, &info, stack, budget, limits, |_| {}).await;
            Ok(())
        });
        raw.send(segment(4000, 1000, 0, SYN, &LINUX_SYN));
        let syn_ack = next(&fcx, &mut raw).await.expect("a SYN-ACK");
        let iss = seq_of(tcp_of(&syn_ack));
        raw.send(segment(4000, 1001, iss.wrapping_add(1), ACK, &[]));
        // The stack closes the connection once it opens.
        let fin = next(&fcx, &mut raw).await.expect("a FIN");
        assert_eq!(tcp_of(&fin)[13] & 1, 1);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].as_deref(), Some(&linux_syn_options()[..]));
        Ok(())
    });
}

/// Asserts that `t` is the RST that answers a SYN with sequence number
/// 1000 and no payload (RFC 9293 section 3.10.7.1):
/// sequence number 0, an ACK of the SYN, window 0, and `options` as its
/// only options.
fn assert_syn_reset(t: &[u8], options: &[TcpOption]) {
    assert_eq!(t[13], RST | ACK);
    assert_eq!(seq_of(t), 0);
    assert_eq!(ack_of(t), 1001);
    assert_eq!(window_of(t), 0);
    assert_eq!(tcp::options(t).as_deref(), Ok(options));
}

#[test]
fn an_answer_that_cannot_be_sent_resets_the_attempt() {
    let fits = vec![TcpOption::Unknown {
        kind: 253,
        data: vec![0xee; SYN_OPTIONS_ROOM - 2],
    }];
    let too_long = vec![TcpOption::Unknown {
        kind: 253,
        data: vec![0xee; SYN_OPTIONS_ROOM - 1],
    }];
    let unreadable = vec![TcpOption::Unknown {
        kind: 0,
        data: Vec::new(),
    }];
    let five_blocks = vec![TcpOption::Sack(vec![(1, 2); 5])];
    for (answer, sent) in [
        (fits, true),
        (too_long, false),
        (unreadable, false),
        (five_blocks, false),
    ] {
        world(Duration::from_secs(10), move |fcx| async move {
            let (mut raw, side) = pair();
            let server = tcp::endpoint(&fcx, side, ip(SERVER));
            let mut listener = server.listen(80)?;
            let expected = answer.clone();
            listener.answer(Box::new(move |_: &tcp::Syn<'_>| {
                SynAnswer::Accept(answer.clone())
            }));
            raw.send(segment(4000, 1000, 0, SYN, &LINUX_SYN));
            let reply = next(&fcx, &mut raw).await.expect("an answer");
            let t = tcp_of(&reply);
            if sent {
                assert_eq!(t[13], SYN | ACK);
                let TcpOption::Unknown { kind, data } = &expected[0] else {
                    unreachable!()
                };
                assert_eq!(options_of(t).last().unwrap(), &(*kind, data.clone()));
                // MSS, Window Scale, SACK-Permitted and Timestamps take
                // 19 bytes, and the answer fills the remaining 21.
                assert_eq!((t[12] >> 4) as usize * 4, 60);
            } else {
                assert_syn_reset(t, &[]);
                // The listener still answers the next attempt.
                listener.answer(Box::new(|_: &tcp::Syn<'_>| SynAnswer::Accept(Vec::new())));
                raw.send(segment(4001, 1000, 0, SYN, &LINUX_SYN));
                let reply = next(&fcx, &mut raw).await.expect("a SYN-ACK");
                assert_eq!(tcp_of(&reply)[13], SYN | ACK);
            }
            Ok(())
        });
    }
}

/// Refuses every SYN that carries MP_JOIN with MP_TCPRST.
fn refuse_joins(syn: &tcp::Syn<'_>) -> SynAnswer {
    let join = syn.options.iter().any(|o| match o {
        TcpOption::Unknown { kind, data } if *kind == mptcp::KIND => {
            matches!(MptcpOption::parse(data), Ok(MptcpOption::Join(_)))
        }
        _ => false,
    });
    if join {
        SynAnswer::Refuse(vec![tcprst(reason::ADMINISTRATIVELY_PROHIBITED)])
    } else {
        SynAnswer::Accept(Vec::new())
    }
}

/// An MP_JOIN SYN's option area.
fn join_area() -> Vec<u8> {
    let join = MptcpOption::Join(Join::Syn {
        backup: false,
        address_id: 1,
        token: 0x55c5_3f5d,
        random: 7,
    })
    .to_bytes()
    .unwrap();
    let mut area = vec![mptcp::KIND, join.len() as u8 + 2];
    area.extend_from_slice(&join);
    area
}

/// An MP_JOIN SYN refused as an MPTCP listener refuses one: a RST that
/// carries MP_TCPRST, formed as RFC 9293 section 3.10.7.1 specifies for a
/// SYN. The attempt never reaches accept, and the next one is answered.
#[test]
fn a_refused_attempt_gets_a_rst_with_the_answer_s_options() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint(&fcx, side, ip(SERVER));
        let mut listener = server.listen(80)?;
        listener.answer(Box::new(refuse_joins));
        raw.send(segment(4000, 1000, 0, SYN, &join_area()));
        let reply = next(&fcx, &mut raw).await.expect("a RST");
        assert_syn_reset(
            tcp_of(&reply),
            &[tcprst(reason::ADMINISTRATIVELY_PROHIBITED)],
        );
        assert!(
            next(&fcx, &mut raw).await.is_none(),
            "one RST, then nothing"
        );

        raw.send(segment(4001, 1000, 0, SYN, &LINUX_SYN));
        let syn_ack = next(&fcx, &mut raw).await.expect("a SYN-ACK");
        let t = tcp_of(&syn_ack);
        assert_eq!(t[13], SYN | ACK);
        raw.send(segment(4001, 1001, seq_of(t).wrapping_add(1), ACK, &[]));
        let conn = listener.accept(&fcx).await?;
        assert_eq!(
            conn.peer_addr().port(),
            4001,
            "the refused one never reached accept"
        );
        Ok(())
    });
}

/// A burst of refused attempts, more than the endpoint sends in one turn,
/// gets one RST each.
#[test]
fn every_refused_attempt_in_a_burst_gets_its_rst() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint(&fcx, side, ip(SERVER));
        let mut listener = server.listen(80)?;
        listener.answer(Box::new(refuse_joins));
        for port in 4000..4064 {
            raw.send(segment(port, 1000, 0, SYN, &join_area()));
        }
        let mut refused = HashSet::new();
        while let Some(reply) = next(&fcx, &mut raw).await {
            let t = tcp_of(&reply);
            assert_syn_reset(t, &[tcprst(reason::ADMINISTRATIVELY_PROHIBITED)]);
            assert!(refused.insert(dport_of(t)), "one RST per attempt");
        }
        assert_eq!(refused.len(), 64);
        Ok(())
    });
}

/// Takes a connection at its ACK unless the ACK carries option kind 253
/// with data 1, which it refuses with MP_TCPRST.
struct RefuseMarkedAcks;

impl Answer for RefuseMarkedAcks {
    fn syn(&self, _: &tcp::Syn<'_>) -> SynAnswer {
        SynAnswer::Accept(Vec::new())
    }

    fn ack(&self, handshake: &Handshake) -> AckAnswer {
        let marked = TcpOption::Unknown {
            kind: 253,
            data: vec![1],
        };
        if handshake.ack.contains(&marked) {
            AckAnswer::Refuse(vec![tcprst(reason::ADMINISTRATIVELY_PROHIBITED)])
        } else {
            AckAnswer::Accept
        }
    }
}

/// A connection refused at the ACK that completes its handshake gets a RST
/// in answer to that ACK (RFC 8684 sections 3.2 and 3.6), and
/// never reaches accept. One taken keeps the ACK's options.
#[test]
fn an_answer_refuses_a_connection_at_its_ack() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint(&fcx, side, ip(SERVER));
        let mut listener = server.listen(80)?;
        listener.answer(Box::new(RefuseMarkedAcks));
        for (port, mark) in [(4000, 1), (4001, 2)] {
            raw.send(segment(port, 1000, 0, SYN, &LINUX_SYN));
            let syn_ack = next(&fcx, &mut raw).await.expect("a SYN-ACK");
            let iss = seq_of(tcp_of(&syn_ack));
            raw.send(segment_with(
                port,
                1001,
                iss.wrapping_add(1),
                PSH | ACK,
                &[253, 3, mark, 1],
                b"hello",
            ));
            if mark == 1 {
                let reply = next(&fcx, &mut raw).await.expect("a RST");
                let t = tcp_of(&reply);
                // The ACK had ACK set, so the RST takes its sequence
                // number from it and acknowledges nothing.
                assert_eq!(t[13], RST);
                assert_eq!(seq_of(t), iss.wrapping_add(1));
                assert_eq!(window_of(t), 0);
                assert_eq!(
                    tcp::options(t),
                    Ok(vec![tcprst(reason::ADMINISTRATIVELY_PROHIBITED)])
                );
                assert!(next(&fcx, &mut raw).await.is_none(), "nothing more");
            }
        }
        let mut conn = listener.accept(&fcx).await?;
        assert_eq!(conn.peer_addr().port(), 4001, "the refused one never came");
        assert_eq!(
            *conn.handshake().unwrap().ack,
            [
                TcpOption::Unknown {
                    kind: 253,
                    data: vec![2]
                },
                TcpOption::NoOperation
            ]
        );
        assert_eq!(read_n(&fcx, &mut conn, 5).await?, b"hello");
        Ok(())
    });
}

/// Drops a connection at its ACK when the ACK carries option kind 253, and
/// stamps every segment of the others with option kind 254 holding the
/// segment's payload length, noting the length of each segment taken.
struct DropOrStamp(Arc<Mutex<Vec<usize>>>);

struct Stamp(Arc<Mutex<Vec<usize>>>);

impl tcp::Segments for Stamp {
    fn room(&self) -> usize {
        4
    }

    fn sent(&mut self, segment: &tcp::Sent<'_>) -> Vec<TcpOption> {
        let len = segment.payload.len() as u16;
        vec![TcpOption::Unknown {
            kind: 254,
            data: len.to_be_bytes().to_vec(),
        }]
    }

    fn received(&mut self, segment: &tcp::Received<'_>) -> tcp::SegmentVerdict {
        self.0.lock().unwrap().push(segment.payload.len());
        tcp::SegmentVerdict::Take
    }
}

impl Answer for DropOrStamp {
    fn syn(&self, _: &tcp::Syn<'_>) -> SynAnswer {
        SynAnswer::Accept(Vec::new())
    }

    fn ack(&self, handshake: &Handshake) -> AckAnswer {
        let marked = handshake
            .ack
            .iter()
            .any(|o| matches!(o, TcpOption::Unknown { kind: 253, .. }));
        if marked {
            AckAnswer::Drop
        } else {
            AckAnswer::Accept
        }
    }

    fn segments(&self, _: &Handshake) -> Option<Box<dyn tcp::Segments>> {
        Some(Box::new(Stamp(self.0.clone())))
    }
}

/// A connection dropped at its ACK gets nothing, not even a RST, and never
/// reaches accept. One taken carries the answer's options on each segment
/// from then on, and the answer sees each segment it takes.
#[test]
fn an_answer_drops_at_the_ack_or_stamps_the_segments() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint(&fcx, side, ip(SERVER));
        let mut listener = server.listen(80)?;
        let taken = Arc::new(Mutex::new(Vec::new()));
        listener.answer(Box::new(DropOrStamp(taken.clone())));
        raw.send(segment(4000, 1000, 0, SYN, &LINUX_SYN));
        let syn_ack = next(&fcx, &mut raw).await.expect("a SYN-ACK");
        let iss = seq_of(tcp_of(&syn_ack));
        raw.send(segment(
            4000,
            1001,
            iss.wrapping_add(1),
            ACK,
            &[253, 2, 1, 1],
        ));
        assert!(next(&fcx, &mut raw).await.is_none(), "nothing at all");

        raw.send(segment(4001, 1000, 0, SYN, &LINUX_SYN));
        let syn_ack = next(&fcx, &mut raw).await.expect("a SYN-ACK");
        let iss = seq_of(tcp_of(&syn_ack));
        raw.send(segment(4001, 1001, iss.wrapping_add(1), ACK, &[]));
        let mut conn = listener.accept(&fcx).await?;
        assert_eq!(conn.peer_addr().port(), 4001, "the dropped one never came");
        conn.write_all(&fcx, b"hi").await?;
        let data = next(&fcx, &mut raw).await.expect("data");
        let t = tcp_of(&data);
        // RFC 9293 permits options on any octet boundary.
        let timestamp = || {
            let mut value = (fcx.now().since_start().as_millis() as u32)
                .to_be_bytes()
                .to_vec();
            value.extend_from_slice(&1u32.to_be_bytes());
            (8, value)
        };
        assert_eq!(options_of(t), [timestamp(), (254, vec![0, 2])]);
        raw.send(segment_with(
            4001,
            1001,
            iss.wrapping_add(3),
            PSH | ACK,
            &[],
            b"hello",
        ));
        assert_eq!(read_n(&fcx, &mut conn, 5).await?, b"hello");
        let ack = next(&fcx, &mut raw).await.expect("an ACK");
        assert_eq!(options_of(tcp_of(&ack)), [timestamp(), (254, vec![0, 0])]);
        assert_eq!(*taken.lock().unwrap(), [0, 5]);
        Ok(())
    });
}

/// `tcp::options` reads what a segment carries, up to the first malformed
/// option, and refuses a header length that does not fit.
#[test]
fn options_reads_any_bytes() {
    let syn = segment(4000, 1000, 0, SYN, &LINUX_SYN);
    assert_eq!(tcp::options(tcp_of(&syn)), Ok(linux_syn_options()));
    let broken = segment(4000, 1000, 0, SYN, &[1, 2, 4, 5, 0xb4, 30, 9, 0]);
    assert_eq!(
        tcp::options(tcp_of(&broken)),
        Err(tcp::OptionsError::Malformed(vec![
            TcpOption::NoOperation,
            TcpOption::MaxSegmentSize(1460)
        ]))
    );
    let t = tcp_of(&syn);
    assert_eq!(tcp::options(&t[..30]), Err(tcp::OptionsError::Header));
    assert_eq!(tcp::options(&t[..10]), Err(tcp::OptionsError::Header));
    let mut short = t.to_vec();
    short[12] = 4 << 4;
    assert_eq!(tcp::options(&short), Err(tcp::OptionsError::Header));
}

/// Illegal lengths get the reset suggested by RFC 9293 section 3.1. An
/// unknown option with a readable length is ignored without losing the SYN.
#[test]
fn a_syn_with_a_malformed_option_is_answered() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint(&fcx, side, ip(SERVER));
        let mut listener = server.listen(80)?;
        let runs_past = [2, 4, 5, 0xb4, 30, 12, 0x01, 0x81];
        let odd_mss = [2, 3, 5, 0xb4];
        let unknown = [2, 3, 5, 0];
        for (port, area) in [
            (4000, &runs_past[..]),
            (4001, &odd_mss[..]),
            (4002, &unknown[..]),
        ] {
            raw.send(segment(port, 1000, 0, SYN, area));
            let reply = next(&fcx, &mut raw).await.expect("an answer");
            let t = tcp_of(&reply);
            if port < 4002 {
                assert_syn_reset(t, &[]);
                assert_eq!(transport_checksum(ip(SERVER), ip(PEER), 6, t), 0);
            } else {
                assert_eq!(t[13], SYN | ACK);
                raw.send(segment(port, 1001, seq_of(t).wrapping_add(1), ACK, &[]));
            }
        }
        let second = listener.accept(&fcx).await?;
        assert_eq!(
            second.peer_addr().port(),
            4002,
            "the malformed SYNs opened nothing"
        );
        assert_eq!(
            second.handshake().unwrap().syn.as_deref(),
            Some(
                &[TcpOption::Unknown {
                    kind: 2,
                    data: vec![5]
                }][..]
            )
        );
        Ok(())
    });
}

/// Every SYN gets a well-formed answer: a reset for illegal option lengths,
/// otherwise a SYN-ACK. Rejected options never reach the listener callback,
/// and the listener still accepts afterwards.
#[test]
fn hostile_syn_options_get_well_formed_answers() {
    world(Duration::from_secs(30), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint(&fcx, side, ip(SERVER));
        let mut listener = server.listen(80)?;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_answer = seen.clone();
        listener.answer(Box::new(move |syn: &tcp::Syn<'_>| {
            seen_by_answer.lock().unwrap().push(syn.options.to_vec());
            answer_mp_capable(syn.options)
        }));
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut byte = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        };
        // Ports whose SYN got an answer. Earlier SYN-ACKs may be resent while
        // later SYNs go out.
        let mut answered = HashSet::new();
        let mut accepted = HashSet::new();
        for i in 0..200u16 {
            let len = 4 * (byte() as usize % 11);
            let options: Vec<u8> = (0..len)
                .map(|_| match byte() % 4 {
                    0 => byte() % 12,
                    1 => mptcp::KIND,
                    _ => byte(),
                })
                .collect();
            raw.send(segment(10_000 + i, 1000, 0, SYN, &options));
            while let Some(reply) = timeout(&fcx, Duration::from_millis(50), raw.recv(&fcx)).await {
                let t = tcp_of(&reply?).to_vec();
                let port = dport_of(&t);
                if t[13] == SYN | ACK {
                    accepted.insert(port);
                } else {
                    assert_syn_reset(&t, &[]);
                }
                assert_eq!(transport_checksum(ip(SERVER), ip(PEER), 6, &t), 0);
                assert!((10_000..=10_000 + i).contains(&port));
                options_of(&t);
                answered.insert(port);
            }
        }
        assert_eq!(answered.len(), 200, "every SYN is answered");
        assert_eq!(
            accepted.len(),
            31,
            "the readable option lists in this corpus"
        );
        assert_eq!(
            seen.lock().unwrap().len(),
            31,
            "only accepted SYNs reach the callback"
        );

        raw.send(segment(4000, 1000, 0, SYN, &LINUX_SYN));
        let syn_ack = loop {
            let p = next(&fcx, &mut raw).await.expect("a SYN-ACK");
            if dport_of(tcp_of(&p)) == 4000 {
                break p;
            }
        };
        let iss = seq_of(tcp_of(&syn_ack));
        raw.send(segment(4000, 1001, iss.wrapping_add(1), ACK, &[]));
        let mut conn = listener.accept(&fcx).await?;
        assert_eq!(
            conn.handshake().unwrap().syn.as_deref(),
            Some(&linux_syn_options()[..])
        );
        conn.write_all(&fcx, b"SSH-2.0-OpenSSH_9.6\r\n").await?;
        Ok(())
    });
}

/// Past the backlog, SYNs get SYN cookies: a SYN-ACK with a Maximum
/// Segment Size and the answer's options only, and no state kept. The ACK
/// that returns a cookie opens the connection, with the data it carries,
/// and one that does not gets a RST.
#[test]
fn syns_past_the_backlog_get_syn_cookies() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let options = cookie_options().backlog(2);
        let server = tcp::endpoint_with(&fcx, side, ip(SERVER), options);
        let mut listener = server.listen(80)?;
        let added = TcpOption::Unknown {
            kind: 253,
            data: vec![9],
        };
        let answer = added.clone();
        listener.answer(Box::new(move |_: &tcp::Syn<'_>| {
            SynAnswer::Accept(vec![answer.clone()])
        }));
        for port in 5000..5004 {
            raw.send(segment(port, 1000, 0, SYN, &LINUX_SYN));
        }
        let mut iss = std::collections::HashMap::new();
        while iss.len() < 4 {
            let p = next(&fcx, &mut raw).await.expect("a SYN-ACK for each");
            let t = tcp_of(&p);
            assert_eq!(t[13], SYN | ACK);
            assert_eq!(ack_of(t), 1001);
            let kinds: Vec<u8> = options_of(t).iter().map(|o| o.0).collect();
            if dport_of(t) < 5002 {
                assert_eq!(kinds, [2, 3, 4, 8, 253], "a full SYN-ACK");
            } else {
                assert_eq!(
                    options_of(t),
                    [(2, vec![0x05, 0xb4]), (253, vec![9])],
                    "a cookie: MSS and the answer only"
                );
                assert_eq!(window_of(t), u16::MAX);
            }
            iss.entry(dport_of(t)).or_insert(seq_of(t));
        }
        let mut open = Vec::new();
        for port in [5000, 5001] {
            raw.send(segment(port, 1001, iss[&port].wrapping_add(1), ACK, &[]));
            open.push(listener.accept(&fcx).await?);
        }

        // A forged cookie gets a RST and opens nothing.
        raw.send(segment(5002, 1001, iss[&5002].wrapping_add(2), ACK, &[]));
        let reply = next(&fcx, &mut raw).await.expect("a RST");
        let t = tcp_of(&reply);
        assert_eq!((dport_of(t), t[13] & RST), (5002, RST), "{t:?}");

        // The real one opens the connection with the data it carries.
        raw.send(segment_with(
            5002,
            1001,
            iss[&5002].wrapping_add(1),
            PSH | ACK,
            &[],
            b"hi",
        ));
        let mut conn = listener.accept(&fcx).await?;
        assert_eq!(conn.peer_addr().port(), 5002);
        let handshake = conn.handshake().unwrap();
        assert_eq!(
            (handshake.syn.clone(), handshake.syn_ack.clone()),
            (None, None)
        );
        assert_eq!(read_n(&fcx, &mut conn, 2).await?, b"hi");
        conn.write_all(&fcx, b"ok").await?;
        let reply = loop {
            let p = next(&fcx, &mut raw).await.expect("the reply");
            let t = tcp_of(&p);
            if dport_of(t) == 5002 && t.len() > (t[12] >> 4) as usize * 4 {
                break p;
            }
        };
        let t = tcp_of(&reply);
        assert_eq!(seq_of(t), iss[&5002].wrapping_add(1));
        assert_eq!(&t[(t[12] >> 4) as usize * 4..], b"ok");
        Ok(())
    });
}

/// RFC 6298 retransmission backoff continues until the configured handshake
/// deadline, then the attempt is dropped without a RST.
#[test]
fn an_unanswered_handshake_is_dropped_quietly() {
    for (seconds, expected) in [(15, vec![0, 1, 3, 7]), (120, vec![0, 1, 3, 7, 15, 31, 63])] {
        world(Duration::from_secs(10), move |fcx| async move {
            let (mut raw, side) = pair();
            let server = tcp::endpoint_with(
                &fcx,
                side,
                ip(SERVER),
                tcp::Options::default().settings(tcp::Settings {
                    handshake_timeout: Duration::from_secs(seconds),
                    ..tcp::Settings::default()
                }),
            );
            let mut listener = server.listen(80)?;
            let start = fcx.now();
            raw.send(segment(4000, 1000, 0, SYN, &LINUX_SYN));
            let mut sent = Vec::new();
            while let Some(p) = timeout(&fcx, Duration::from_secs(100), raw.recv(&fcx)).await {
                let p = p?;
                assert_eq!(tcp_of(&p)[13], SYN | ACK, "only SYN-ACKs");
                sent.push((fcx.now().since_start() - start.since_start()).as_secs());
            }
            assert_eq!(sent, expected);
            // The attempt is gone: its ACK now finds nothing.
            raw.send(segment(4000, 1001, 1, ACK, &[]));
            let reply = next(&fcx, &mut raw).await.expect("a RST");
            assert_eq!(tcp_of(&reply)[13] & RST, RST);
            assert!(
                timeout(&fcx, Duration::from_secs(1), listener.accept(&fcx))
                    .await
                    .is_none()
            );
            Ok(())
        });
    }
}

#[test]
fn ipv4_syn_options_and_source_route_reply_survive_retransmission_and_cookies() {
    use fictionet::stdlib::network::ip::{self, Ipv4Option, Ipv4Reply};

    fn route(strict: bool, consumed: bool) -> Ipv4Option {
        let pointer = if consumed { 8 } else { 4 };
        let routes = vec![if consumed { "10.0.0.3" } else { PEER }.parse().unwrap()];
        if strict {
            Ipv4Option::StrictSourceRoute { pointer, routes }
        } else {
            Ipv4Option::LooseSourceRoute { pointer, routes }
        }
    }

    struct RouteReply {
        strict: bool,
        consumed: bool,
    }
    impl Answer for RouteReply {
        fn syn(&self, _syn: &tcp::Syn<'_>) -> SynAnswer {
            SynAnswer::Accept(Vec::new())
        }
        fn ipv4_options(&self, syn: &tcp::Syn<'_>) -> Option<Ipv4Reply> {
            assert_eq!(syn.to, SocketAddr::new(ip(SERVER), 80));
            assert!(matches!(
                syn.ipv4_options.first(),
                Some(Ipv4Option::RecordRoute { pointer: 4, .. })
            ));
            Some(Ipv4Reply {
                options: vec![route(self.strict, self.consumed)],
                destination: (!self.consumed).then(|| "10.0.0.3".parse().unwrap()),
            })
        }
    }
    for cookie in [false, true] {
        for strict in [false, true] {
            for consumed in [false, true] {
                world(Duration::from_secs(10), move |fcx| async move {
                    let (mut raw, side) = pair();
                    let server =
                        tcp::endpoint_with(&fcx, side, ip(SERVER), cookie_options().backlog(1));
                    let mut listener = server.listen(80)?;
                    if cookie {
                        raw.send(segment(3999, 1000, 0, SYN, &[]));
                        next(&fcx, &mut raw).await.expect("the backlog SYN-ACK");
                    }
                    listener.answer(Box::new(RouteReply { strict, consumed }));
                    let syn = segment(4000, 1000, 0, SYN | 0xc0, &LINUX_SYN);
                    let received = vec![Ipv4Option::RecordRoute {
                        pointer: 4,
                        routes: vec![std::net::Ipv4Addr::UNSPECIFIED],
                    }];
                    let syn = ip::packet_with_ipv4_options(
                        PEER.parse().unwrap(),
                        SERVER.parse().unwrap(),
                        6,
                        Fields::default(),
                        &received,
                        tcp_of(&syn),
                    )
                    .unwrap();
                    let received = ip::ipv4_options(&syn.0).unwrap();
                    raw.send(syn);
                    let reply = next(&fcx, &mut raw).await.expect("optioned SYN-ACK");
                    let check = |packet: &Packet| {
                        let header = ip::Header::parse(&packet.0).unwrap();
                        assert_eq!(header.dst, ip(if consumed { PEER } else { "10.0.0.3" }));
                        assert_eq!(header.payload.start, 28);
                        assert_eq!(
                            u16::from_be_bytes(packet.0[2..4].try_into().unwrap()) as usize,
                            packet.0.len()
                        );
                        assert_eq!(ip::checksum(&packet.0[..28]), 0);
                        assert_eq!(
                            tcp_of(packet)[13],
                            SYN | ACK | if cookie { 0 } else { 0x40 }
                        );
                        assert_eq!(
                            transport_checksum(ip(SERVER), ip(PEER), 6, tcp_of(packet)),
                            0
                        );
                        assert_eq!(
                            ip::ipv4_options(&packet.0).unwrap(),
                            vec![route(strict, consumed), Ipv4Option::EndOfList,]
                        );
                    };
                    check(&reply);
                    if !cookie {
                        let again = timeout(&fcx, Duration::from_secs(2), raw.recv(&fcx))
                            .await
                            .expect("retransmitted SYN-ACK")?;
                        check(&again);
                        // A duplicate SYN cannot replace the first SYN's retained options.
                        raw.send(segment(4000, 1000, 0, SYN, &[]));
                    } else {
                        // Free the backlog before returning the cookie.
                        raw.send(segment(3999, 1001, 0, RST, &[]));
                    }
                    raw.send(segment(
                        4000,
                        1001,
                        seq_of(tcp_of(&reply)).wrapping_add(1),
                        ACK,
                        &[],
                    ));
                    let conn = listener.accept(&fcx).await?;
                    let handshake = conn.handshake().unwrap();
                    assert_eq!(handshake.iss, seq_of(tcp_of(&reply)));
                    if cookie {
                        assert_eq!(handshake.origin, tcp::HandshakeOrigin::Cookie);
                        assert_eq!(handshake.syn_ipv4, None);
                        assert_eq!(handshake.syn_ack_ipv4, None);
                    } else {
                        assert_eq!(handshake.syn_ipv4.as_deref(), Some(received.as_slice()));
                        assert_eq!(
                            handshake.syn_ack_ipv4.as_deref(),
                            Some(&[route(strict, consumed),][..])
                        );
                    }
                    Ok(())
                });
            }
        }
    }
}

#[test]
fn declining_ipv4_options_drops_the_syn_without_consuming_backlog() {
    use fictionet::stdlib::network::ip::Ipv4Reply;

    struct DeclineOptions;
    impl Answer for DeclineOptions {
        fn syn(&self, _syn: &tcp::Syn<'_>) -> SynAnswer {
            SynAnswer::Accept(Vec::new())
        }

        fn ipv4_options(&self, syn: &tcp::Syn<'_>) -> Option<Ipv4Reply> {
            (syn.from.port() == 4001).then(Ipv4Reply::default)
        }
    }

    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint_with(&fcx, side, ip(SERVER), tcp::Options::default().backlog(1));
        let mut listener = server.listen(80)?;
        listener.answer(Box::new(DeclineOptions));
        raw.send(segment(4000, 1000, 0, SYN, &[]));
        raw.send(segment(4001, 2000, 0, SYN, &[]));
        let reply = next(&fcx, &mut raw).await.expect("the accepted SYN-ACK");
        assert_eq!(dport_of(tcp_of(&reply)), 4001);
        assert_eq!(tcp_of(&reply)[13], SYN | ACK);
        raw.send(segment(
            4001,
            2001,
            seq_of(tcp_of(&reply)).wrapping_add(1),
            ACK,
            &[],
        ));
        let conn = listener.accept(&fcx).await?;
        assert_eq!(conn.handshake().unwrap().origin, tcp::HandshakeOrigin::Syn);
        Ok(())
    });
}
