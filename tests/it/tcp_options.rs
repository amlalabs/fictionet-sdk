//! TCP options at connection setup: what a peer's SYN carried reaches the
//! accepted connection, and a listener adds options of its own to its
//! SYN-ACK. The peer is hand-made packets on one end of a cable.

use crate::common::world;

use world::world;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fictionet::stdlib::codec::{Ending, LineError, Lines, Wire};
use fictionet::stdlib::network::ip::{Fields, packet_with, transport_checksum};
use fictionet::stdlib::network::tcp::{self, SYN_OPTIONS_ROOM, TcpOption};
use fictionet::stdlib::network::{Accepted, ConnectionExt};
use fictionet::stdlib::protocols::mptcp::{self, Capable, Keys, MptcpOption, algorithm};
use fictionet::stdlib::services::serve::{self, Flow};
use fictionet::{Cx, End, Interface, InterfaceExt, Packet, pair};
use fictionet_test_support::timeout;

const PEER: &str = "10.0.0.1";
const SERVER: &str = "10.0.0.2";
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;
/// The listener's MPTCP key.
const KEY: u64 = 0x0123_4567_89ab_cdef;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A segment from the peer to the server's port 80. `options` is the
/// whole option area, so its length is a multiple of four.
fn segment(sport: u16, seq: u32, ack: u32, flags: u8, options: &[u8]) -> Packet {
    let (src, dst) = (ip(PEER), ip(SERVER));
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&80u16.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    let offset = (20 + options.len()) / 4;
    t.extend_from_slice(&[(offset as u8) << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(options);
    let sum = transport_checksum(src, dst, 6, &t);
    t[16..18].copy_from_slice(&sum.to_be_bytes());
    packet_with(src, dst, 6, Fields::default(), &t)
}

/// The TCP header and payload of a packet from the server.
fn tcp_of(p: &Packet) -> &[u8] {
    let ihl = (p.0[0] & 15) as usize * 4;
    &p.0[ihl..]
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

/// Answers an MP_CAPABLE SYN as an RFC 8684 listener does: the same
/// version and flags, HMAC-SHA256, and its key.
fn answer_mp_capable(syn: &[TcpOption]) -> Vec<TcpOption> {
    let offer = syn.iter().find_map(|o| match o {
        TcpOption::Unknown { kind, data } if *kind == mptcp::KIND => match MptcpOption::parse(data)
        {
            Ok(MptcpOption::Capable(offer)) if offer.keys == Keys::Absent => Some(offer),
            _ => None,
        },
        _ => None,
    });
    let Some(offer) = offer else {
        return Vec::new();
    };
    let answer = MptcpOption::Capable(Capable {
        algorithms: algorithm::HMAC_SHA256,
        keys: Keys::Sender(KEY),
        ..offer
    });
    vec![TcpOption::Unknown {
        kind: mptcp::KIND,
        data: answer.to_bytes().unwrap(),
    }]
}

#[test]
fn syn_options_reach_the_connection_and_the_syn_ack_answers_mptcp() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint(&fcx, side, ip(SERVER));
        let mut listener = server.listen(80)?;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_answer = seen.clone();
        listener.answer_syn(move |syn| {
            seen_by_answer.lock().unwrap().push(syn.to_vec());
            answer_mp_capable(syn)
        });

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
        assert_eq!(options_of(tcp_of(&again)), options);
        assert_eq!(seen.lock().unwrap().len(), 1);

        let iss = u32::from_be_bytes(t[4..8].try_into().unwrap());
        raw.send(segment(4000, 1001, iss.wrapping_add(1), ACK, &[]));
        let conn = listener.accept(&fcx).await?;
        assert_eq!(conn.peer_addr(), SocketAddr::new(ip(PEER), 4000));
        assert_eq!(*conn.syn_options(), *linux_syn_options());
        assert_eq!(*Accepted::syn_options(&conn), *linux_syn_options());
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
        assert_eq!(kinds, [2, 3, 4], "MSS, Window Scale, SACK-Permitted");
        let iss = u32::from_be_bytes(t[4..8].try_into().unwrap());
        raw.send(segment(4000, 1001, iss.wrapping_add(1), ACK, &[]));
        let conn = listener.accept(&fcx).await?;
        assert_eq!(*conn.syn_options(), *linux_syn_options());
        Ok(())
    });
}

/// Between two endpoints, the accepted side has the SYN the other sent,
/// and the side that connected has none.
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
        assert!(conn.syn_options().is_empty());
        let syn = accepted.syn_options();
        assert!(
            matches!(
                *syn,
                [
                    TcpOption::MaxSegmentSize(1460),
                    TcpOption::WindowScale(_),
                    TcpOption::SackPermitted
                ]
            ),
            "{syn:?}"
        );
        Ok(())
    });
}

/// Records the SYN options of each connection it serves, then closes it.
struct RecordSyn;

impl serve::Service for RecordSyn {
    type Timer = ();
    type Decoder = Lines;
    type State = Mutex<Vec<Arc<[TcpOption]>>>;
    type Error = std::convert::Infallible;

    fn decoder(&self) -> Lines {
        Lines::new(64, Ending::LfOrCrlf)
    }

    fn on_open(
        &mut self,
        seen: &Self::State,
        driver: &mut serve::Driver<'_, Lines, ()>,
    ) -> Result<Flow, Self::Error> {
        seen.lock().unwrap().push(driver.conn().syn_options.clone());
        Ok(Flow::Close)
    }

    fn on_item(
        &mut self,
        _: Result<Vec<u8>, LineError>,
        _: &Self::State,
        _: &mut serve::Driver<'_, Lines, ()>,
    ) -> Result<Flow, Self::Error> {
        Ok(Flow::Close)
    }
}

#[test]
fn a_service_sees_the_syn_options_in_its_conn_info() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint(&fcx, side, ip(SERVER));
        let seen = Arc::new(Mutex::new(Vec::new()));
        serve::listen(
            &fcx,
            server.listen(80)?,
            seen.clone(),
            || RecordSyn,
            serve::ServeOptions::default(),
        );
        raw.send(segment(4000, 1000, 0, SYN, &LINUX_SYN));
        let syn_ack = next(&fcx, &mut raw).await.expect("a SYN-ACK");
        let iss = u32::from_be_bytes(tcp_of(&syn_ack)[4..8].try_into().unwrap());
        raw.send(segment(4000, 1001, iss.wrapping_add(1), ACK, &[]));
        // The service closes the connection once it has looked.
        let fin = next(&fcx, &mut raw).await.expect("a FIN");
        assert_eq!(tcp_of(&fin)[13] & 1, 1);
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert_eq!(*seen.lock().unwrap()[0], *linux_syn_options());
        Ok(())
    });
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
            listener.answer_syn(move |_| answer.clone());
            raw.send(segment(4000, 1000, 0, SYN, &LINUX_SYN));
            let reply = next(&fcx, &mut raw).await.expect("an answer");
            let t = tcp_of(&reply);
            if sent {
                assert_eq!(t[13], SYN | ACK);
                let TcpOption::Unknown { kind, data } = &expected[0] else {
                    unreachable!()
                };
                assert_eq!(options_of(t).last().unwrap(), &(*kind, data.clone()));
                // MSS, Window Scale and SACK-Permitted take 9 bytes, the
                // answer 21, and End of Option List pads to a word.
                assert_eq!((t[12] >> 4) as usize * 4, 52);
            } else {
                assert_eq!(t[13] & RST, RST, "{expected:?}");
                // The listener still answers the next attempt.
                listener.answer_syn(|_| Vec::new());
                raw.send(segment(4001, 1000, 0, SYN, &LINUX_SYN));
                let reply = next(&fcx, &mut raw).await.expect("a SYN-ACK");
                assert_eq!(tcp_of(&reply)[13], SYN | ACK);
            }
            Ok(())
        });
    }
}

/// SYNs with every kind of broken or odd option list get a well-formed
/// SYN-ACK or nothing, the answer sees what was sent, and the listener
/// still accepts afterwards.
#[test]
fn hostile_syn_options_get_well_formed_answers() {
    world(Duration::from_secs(30), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint(&fcx, side, ip(SERVER));
        let mut listener = server.listen(80)?;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_answer = seen.clone();
        listener.answer_syn(move |syn| {
            seen_by_answer.lock().unwrap().push(syn.to_vec());
            answer_mp_capable(syn)
        });
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut byte = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        };
        // Ports whose SYN got a SYN-ACK. Earlier ones may be resent while
        // later SYNs go out.
        let mut answered = HashSet::new();
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
                assert_eq!(t[13], SYN | ACK);
                let port = u16::from_be_bytes([t[2], t[3]]);
                assert!((10_000..=10_000 + i).contains(&port));
                options_of(&t);
                answered.insert(port);
            }
        }
        assert!(answered.len() > 20, "{} answered", answered.len());
        assert!(answered.len() < 200, "malformed SYNs are dropped");
        assert_eq!(seen.lock().unwrap().len(), answered.len());

        raw.send(segment(4000, 1000, 0, SYN, &LINUX_SYN));
        let syn_ack = loop {
            let p = next(&fcx, &mut raw).await.expect("a SYN-ACK");
            if u16::from_be_bytes([tcp_of(&p)[2], tcp_of(&p)[3]]) == 4000 {
                break p;
            }
        };
        let t = tcp_of(&syn_ack);
        let iss = u32::from_be_bytes(t[4..8].try_into().unwrap());
        raw.send(segment(4000, 1001, iss.wrapping_add(1), ACK, &[]));
        let mut conn = listener.accept(&fcx).await?;
        assert_eq!(*conn.syn_options(), *linux_syn_options());
        conn.write_all(&fcx, b"SSH-2.0-OpenSSH_9.6\r\n").await?;
        Ok(())
    });
}
