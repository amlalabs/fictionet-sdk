//! Linux TCP wire contracts, exercised through the extras helper.
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::ConnectionExt;
use fictionet::stdlib::network::ip::{Fields, packet_with, transport_checksum};
use fictionet::stdlib::network::tcp::{self, AckAnswer, Answer, Handshake, SynAnswer, TcpOption};
use fictionet::stdlib::protocols::mptcp::{self, Capable, Keys, MptcpOption, algorithm};
use fictionet::{Cx, End, Interface, InterfaceExt, Packet, pair};
use fictionet_extras::linux;
use fictionet_test_support::{Done, ended_with_done, timeout, within};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn world<F, Fut>(limit: Duration, f: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = fictionet::Result> + Send + 'static,
{
    let result = within(limit, move || {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            move |cx| async move {
                f(cx).await?;
                Err(fictionet::Error::from(Done))
            },
        ))
    });
    ended_with_done(result).unwrap();
}

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
    let ihl = (p[0] & 15) as usize * 4;
    &p[ihl..]
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

#[test]
fn a_listener_without_an_answer_adds_nothing() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint_with(&fcx, side, ip(SERVER), linux::tcp());
        let mut listener = server.listen(80)?;
        raw.send(segment(4000, 1000, 0, SYN, &LINUX_SYN));
        let syn_ack = next(&fcx, &mut raw).await.expect("a SYN-ACK");
        let t = tcp_of(&syn_ack);
        let kinds: Vec<u8> = options_of(t).iter().map(|o| o.0).collect();
        assert_eq!(
            kinds,
            [2, 4, 8, 1, 3],
            "MSS, SACK-Permitted, Timestamps, No-Operation and Window Scale, as Linux lays them out"
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

#[test]
fn an_endpoint_s_own_syn_reaches_the_other_endpoint() {
    world(Duration::from_secs(10), |fcx| async move {
        let (a, b) = pair();
        let client = tcp::endpoint_with(&fcx, a, ip(PEER), linux::tcp());
        let server = tcp::endpoint_with(&fcx, b, ip(SERVER), linux::tcp());
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
                    TcpOption::SackPermitted,
                    TcpOption::Timestamps { .. },
                    TcpOption::NoOperation,
                    TcpOption::WindowScale(_),
                ]
            ),
            "{syn:?}"
        );
        Ok(())
    });
}

#[test]
fn an_answer_drops_at_the_ack_or_stamps_the_segments() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint_with(&fcx, side, ip(SERVER), linux::tcp());
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
        let ts = tcp::options(tcp_of(&syn_ack))
            .unwrap()
            .into_iter()
            .find_map(|o| match o {
                TcpOption::Timestamps { tsval, .. } => Some(tsval),
                _ => None,
            })
            .unwrap();
        let at = fcx.now();
        raw.send(segment(4001, 1001, iss.wrapping_add(1), ACK, &[]));
        let mut conn = listener.accept(&fcx).await?;
        assert_eq!(conn.peer_addr().port(), 4001, "the dropped one never came");
        conn.write_all(&fcx, b"hi").await?;
        let data = next(&fcx, &mut raw).await.expect("data");
        let t = tcp_of(&data);
        // Timestamps after two No-Operations, as Linux pads them.
        let nop = || (1, Vec::new());
        let timestamp = || {
            let mut value = ts
                .wrapping_add((fcx.now().since_start() - at.since_start()).as_millis() as u32)
                .to_be_bytes()
                .to_vec();
            value.extend_from_slice(&1u32.to_be_bytes());
            (8, value)
        };
        assert_eq!(
            options_of(t),
            [nop(), nop(), timestamp(), (254, vec![0, 2])]
        );
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
        assert_eq!(
            options_of(tcp_of(&ack)),
            [nop(), nop(), timestamp(), (254, vec![0, 0])]
        );
        assert_eq!(*taken.lock().unwrap(), [0, 5]);
        Ok(())
    });
}

#[test]
fn a_syn_with_a_malformed_option_is_answered() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint_with(&fcx, side, ip(SERVER), linux::tcp());
        let mut listener = server.listen(80)?;
        let runs_past = [2, 4, 5, 0xb4, 30, 12, 0x01, 0x81];
        let odd_mss = [2, 3, 5, 0xb4];
        for (port, area) in [(4000, &runs_past[..]), (4001, &odd_mss[..])] {
            raw.send(segment(port, 1000, 0, SYN, area));
            let syn_ack = next(&fcx, &mut raw).await.expect("a SYN-ACK");
            let t = tcp_of(&syn_ack);
            assert_eq!(t[13], SYN | ACK);
            raw.send(segment(port, 1001, seq_of(t).wrapping_add(1), ACK, &[]));
        }
        let first = listener.accept(&fcx).await?;
        assert_eq!(
            first.handshake().unwrap().syn.as_deref(),
            Some(&[TcpOption::MaxSegmentSize(1460)][..])
        );
        let second = listener.accept(&fcx).await?;
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

#[test]
fn hostile_syn_options_get_well_formed_answers() {
    world(Duration::from_secs(30), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint_with(&fcx, side, ip(SERVER), linux::tcp());
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
                let port = dport_of(&t);
                assert!((10_000..=10_000 + i).contains(&port));
                options_of(&t);
                answered.insert(port);
            }
        }
        assert_eq!(answered.len(), 200, "every SYN is answered");
        assert_eq!(seen.lock().unwrap().len(), 200);

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

#[test]
fn syns_past_the_backlog_get_syn_cookies() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let options = linux::tcp().backlog(2);
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
            let options = if port < 5002 {
                &LINUX_SYN[..]
            } else {
                &[2, 4, 5, 180][..]
            };
            raw.send(segment(port, 1000, 0, SYN, options));
        }
        let mut iss = std::collections::HashMap::new();
        while iss.len() < 4 {
            let p = next(&fcx, &mut raw).await.expect("a SYN-ACK for each");
            let t = tcp_of(&p);
            assert_eq!(t[13], SYN | ACK);
            assert_eq!(ack_of(t), 1001);
            let kinds: Vec<u8> = options_of(t).iter().map(|o| o.0).collect();
            if dport_of(t) < 5002 {
                assert_eq!(kinds, [2, 4, 8, 1, 3, 253], "a full SYN-ACK");
            } else {
                assert_eq!(
                    options_of(t),
                    [(2, vec![0x05, 0xb4]), (253, vec![9])],
                    "a cookie: MSS and the answer only"
                );
                assert_eq!(window_of(t), 64240);
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

#[test]
fn cookies_without_timestamps_decline_extensions_without_retaining_state() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint_with(&fcx, side, ip(SERVER), linux::tcp().backlog(1));
        let mut listener = server.listen(80)?;
        for port in [4000, 4001] {
            let options = if port == 4000 {
                &LINUX_SYN[..]
            } else {
                &[2, 4, 5, 180, 4, 2, 1, 3, 3, 7, 0, 0][..]
            };
            raw.send(segment(port, 0, 0, SYN | 0xc0, options));
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

#[test]
fn an_unanswered_handshake_is_dropped_quietly() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, side) = pair();
        let server = tcp::endpoint_with(&fcx, side, ip(SERVER), linux::tcp());
        let mut listener = server.listen(80)?;
        let start = fcx.now();
        raw.send(segment(4000, 1000, 0, SYN, &LINUX_SYN));
        let mut sent = Vec::new();
        while let Some(p) = timeout(&fcx, Duration::from_secs(100), raw.recv(&fcx)).await {
            let p = p?;
            assert_eq!(tcp_of(&p)[13], SYN | ACK, "only SYN-ACKs");
            sent.push((fcx.now().since_start() - start.since_start()).as_secs());
        }
        assert_eq!(sent, [0, 1, 3, 7, 15, 31]);
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
