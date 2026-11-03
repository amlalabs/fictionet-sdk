//! The honeypot from the internet's side: hand-made packets on the
//! `internet` attachment, the answers that come back, and what the log and
//! the packet capture hold afterwards.

use std::collections::HashSet;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::ip::{Fields, packet_with, transport_checksum};
use fictionet::stdlib::network::tcp::{self, TcpOption};
use fictionet::stdlib::protocols::mptcp::{
    self, Capable, Join, Keys, MptcpOption, algorithm, join_hmac, reason, token,
};
use fictionet::{Cx, End, Interface, InterfaceExt, Packet};
use honeypot_world::config::{Burst, DEFAULT_ADDRESS};
use honeypot_world::observe::Sinks;
use honeypot_world::services::SSH_BANNER;
use honeypot_world::{Clock, Config, Honeypot};
use serde_json::Value;

const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// When the test runs start, in Unix seconds.
const EPOCH: u64 = 1_800_000_000;

/// A buffer the test reads while the world writes to it.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The internet side of a running honeypot.
struct Internet {
    fcx: Cx,
    end: End,
    log: Shared,
    pcap: Shared,
    honeypot: Honeypot,
    /// Packets that crossed the attachment, both ways.
    crossed: usize,
}

impl Internet {
    fn send(&mut self, packet: Packet) {
        self.crossed += 1;
        self.end.send(packet);
    }

    /// The next packet from the world, within a second.
    async fn recv(&mut self) -> Option<Packet> {
        let deadline = self.fcx.now() + Duration::from_secs(1);
        let packet = self
            .fcx
            .race(Some(deadline), self.end.recv(&self.fcx))
            .await;
        let packet = packet.ok()?.ok()?;
        self.crossed += 1;
        Some(packet)
    }

    /// Every packet from the world until a second passes with none.
    async fn drain(&mut self) -> Vec<Packet> {
        let mut all = Vec::new();
        while let Some(p) = self.recv().await {
            all.push(p);
        }
        all
    }

    /// The log's lines.
    fn log(&self) -> Vec<Value> {
        let log = self.log.0.lock().unwrap();
        std::str::from_utf8(&log)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// The log's lines with this `event`.
    fn events(&self, event: &str) -> Vec<Value> {
        self.log()
            .into_iter()
            .filter(|v| v["event"] == event)
            .collect()
    }

    /// The pcapng blocks as (type, body).
    fn pcap_blocks(&self) -> Vec<(u32, Vec<u8>)> {
        let pcap = self.pcap.0.lock().unwrap();
        let mut rest = &pcap[..];
        let mut blocks = Vec::new();
        while !rest.is_empty() {
            let kind = u32::from_le_bytes(rest[0..4].try_into().unwrap());
            let len = u32::from_le_bytes(rest[4..8].try_into().unwrap()) as usize;
            assert_eq!(rest[len - 4..len], rest[4..8], "the block's length repeats");
            blocks.push((kind, rest[8..len - 4].to_vec()));
            rest = &rest[len..];
        }
        blocks
    }
}

/// Runs `test` against a honeypot with `config`, in virtual time.
fn honeypot<F, Fut>(config: Config, test: F)
where
    F: FnOnce(Internet) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(7),
        |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let (log, pcap) = (Shared::default(), Shared::default());
            let sinks = Sinks {
                log: Box::new(log.clone()),
                pcap: Box::new(pcap.clone()),
            };
            let honeypot = honeypot_world::start(
                &fcx,
                &config,
                Clock::at_unix_secs(EPOCH),
                sinks,
                attachments,
            )?;
            let end = attacher.attach("internet")?;
            let internet = Internet {
                fcx: fcx.clone(),
                end,
                log,
                pcap,
                honeypot,
                crossed: 0,
            };
            test(internet).await?;
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

fn server(port: u16) -> SocketAddr {
    SocketAddr::new(DEFAULT_ADDRESS, port)
}

fn client(n: u32, port: u16) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::from(0xc633_6400 + n).into(), port)
}

/// A TCP segment. `options` is padded to a word with End of Option List.
fn segment(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    options: &[u8],
    payload: &[u8],
) -> Packet {
    let mut area = options.to_vec();
    area.resize(options.len().div_ceil(4) * 4, 0);
    let mut t = Vec::new();
    t.extend_from_slice(&src.port().to_be_bytes());
    t.extend_from_slice(&dst.port().to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    let offset = (20 + area.len()) / 4;
    t.extend_from_slice(&[(offset as u8) << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(&area);
    t.extend_from_slice(payload);
    let sum = transport_checksum(src.ip(), dst.ip(), 6, &t);
    t[16..18].copy_from_slice(&sum.to_be_bytes());
    packet_with(src.ip(), dst.ip(), 6, Fields::default(), &t)
}

/// One MPTCP option's bytes, from Kind.
fn mptcp_bytes(option: MptcpOption) -> Vec<u8> {
    let data = option.to_bytes().unwrap();
    let mut bytes = vec![mptcp::KIND, data.len() as u8 + 2];
    bytes.extend_from_slice(&data);
    bytes
}

/// MSS 1460 then `rest`.
fn with_mss(rest: &[u8]) -> Vec<u8> {
    let mut options = vec![2, 4, 0x05, 0xb4];
    options.extend_from_slice(rest);
    options
}

/// A Linux client's MP_CAPABLE: version 1, HMAC-SHA256, no key.
fn linux_capable() -> MptcpOption {
    MptcpOption::Capable(Capable {
        version: 1,
        checksum_required: false,
        extensibility: false,
        no_new_subflows: false,
        algorithms: algorithm::HMAC_SHA256,
        keys: Keys::Absent,
    })
}

fn join_syn(token: u32, random: u32) -> MptcpOption {
    MptcpOption::Join(Join::Syn {
        backup: false,
        address_id: 1,
        token,
        random,
    })
}

/// The TCP header and payload of a packet.
fn tcp_of(p: &Packet) -> &[u8] {
    let ihl = (p.0[0] & 15) as usize * 4;
    &p.0[ihl..]
}

fn flags(p: &Packet) -> u8 {
    tcp_of(p)[13]
}

fn seq_of(p: &Packet) -> u32 {
    u32::from_be_bytes(tcp_of(p)[4..8].try_into().unwrap())
}

fn ack_of(p: &Packet) -> u32 {
    u32::from_be_bytes(tcp_of(p)[8..12].try_into().unwrap())
}

fn payload_of(p: &Packet) -> &[u8] {
    let t = tcp_of(p);
    &t[(t[12] >> 4) as usize * 4..]
}

/// The MPTCP options of a packet from the world.
fn mptcp_of(p: &Packet) -> Vec<MptcpOption> {
    tcp::options(tcp_of(p))
        .unwrap()
        .into_iter()
        .filter_map(|o| match o {
            TcpOption::Unknown { kind, data } if kind == mptcp::KIND => {
                Some(MptcpOption::parse(&data).unwrap())
            }
            _ => None,
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Opens a connection to the server's `port` from `from`, sends `request`
/// in the pieces given, and returns what the server sent back.
async fn exchange(net: &mut Internet, from: SocketAddr, port: u16, pieces: &[&[u8]]) -> Vec<u8> {
    net.send(segment(
        from,
        server(port),
        1000,
        0,
        SYN,
        &with_mss(&[]),
        b"",
    ));
    // Earlier connections may still be closing.
    let syn_ack = loop {
        let p = net.recv().await.expect("a SYN-ACK");
        if flags(&p) == SYN | ACK && tcp_of(&p)[2..4] == from.port().to_be_bytes() {
            break p;
        }
    };
    let iss = seq_of(&syn_ack);
    let mut seq = 1001;
    net.send(segment(from, server(port), seq, iss + 1, ACK, &[], b""));
    for piece in pieces {
        net.send(segment(
            from,
            server(port),
            seq,
            iss + 1,
            PSH | ACK,
            &[],
            piece,
        ));
        seq += piece.len() as u32;
    }
    let mut reply = Vec::new();
    for p in net.drain().await {
        if tcp_of(&p)[2..4] == from.port().to_be_bytes() {
            reply.extend_from_slice(payload_of(&p));
        }
    }
    reply
}

/// HTTP answers a request with nginx's page, however its head is split,
/// and a head past nginx's limit with a 400.
#[test]
fn http_answers_as_nginx() {
    honeypot(Config::default(), |mut net| async move {
        let request: &[u8] = b"GET / HTTP/1.1\r\nHost: 203.0.113.10\r\n\r\n";
        let (a, b) = request.split_at(request.len() - 2);
        let reply = exchange(&mut net, client(7, 46000), 80, &[a, b]).await;
        let reply = String::from_utf8(reply).unwrap();
        assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{reply}");
        assert!(reply.contains("Server: nginx/1.24.0 (Ubuntu)\r\n"));
        assert!(
            reply.contains("Date: Fri, 15 Jan 2027 08:00:00 GMT\r\n"),
            "{reply}"
        );
        assert!(reply.ends_with("</html>\n"));

        let long = vec![b'a'; 1000];
        let mut pieces: Vec<&[u8]> = vec![b"GET /"];
        pieces.extend([&long[..]; 9]);
        let reply = exchange(&mut net, client(7, 46001), 80, &pieces).await;
        let reply = String::from_utf8(reply).unwrap();
        assert!(reply.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{reply}");
        Ok(())
    });
}

/// A plain SYN gets a plain SYN-ACK, the handshake opens a connection
/// that sends the SSH banner, and the log holds the SYN, the answer and
/// the client's bytes. Every packet is in the capture.
#[test]
fn a_plain_syn_gets_ssh() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(1, 40000);
        net.send(segment(from, server(22), 1000, 0, SYN, &with_mss(&[]), b""));
        let syn_ack = net.recv().await.expect("a SYN-ACK");
        assert_eq!(flags(&syn_ack), SYN | ACK);
        assert!(mptcp_of(&syn_ack).is_empty());
        let iss = seq_of(&syn_ack);
        net.send(segment(from, server(22), 1001, iss + 1, ACK, &[], b""));
        let banner = net.recv().await.expect("the banner");
        assert_eq!(payload_of(&banner), SSH_BANNER);
        let hello = b"SSH-2.0-Go\r\n";
        let acked = iss + 1 + SSH_BANNER.len() as u32;
        net.send(segment(
            from,
            server(22),
            1001,
            acked,
            PSH | ACK,
            &[],
            hello,
        ));
        net.drain().await;

        let syn = &net.events("syn")[0];
        assert_eq!(syn["src"], "198.51.100.1:40000");
        assert_eq!(syn["dst"], "203.0.113.10:22");
        assert_eq!(syn["attachment"], "internet");
        assert_eq!(syn["seq"], 1000);
        assert_eq!(
            syn["options"],
            serde_json::json!([{"kind": "mss", "value": 1460}])
        );
        assert_eq!(syn["mptcp"], serde_json::json!([]));
        assert!(syn.get("options_fault").is_none());
        assert!(syn["at_us"].as_u64().unwrap() >= EPOCH * 1_000_000);
        let answers = net.events("answer");
        assert_eq!(answers[0]["flags"], "SYN|ACK");
        assert_eq!(answers[0]["dst"], "198.51.100.1:40000");
        let segments = net.events("segment");
        assert!(
            segments.iter().any(|s| s["payload"] == hex(hello)),
            "{segments:?}"
        );

        // Section header, interface, then one block per packet that crossed.
        let blocks = net.pcap_blocks();
        assert_eq!(blocks[0].0, 0x0a0d_0d0a);
        assert_eq!(blocks[1].0, 1);
        assert!(blocks[2..].iter().all(|(kind, _)| *kind == 6));
        assert_eq!(blocks.len() - 2, net.crossed);
        Ok(())
    });
}

/// An MP_CAPABLE SYN gets MP_CAPABLE back with a key. While that
/// connection is open, an MP_JOIN with its token gets a SYN-ACK with
/// MP_JOIN and the listener's HMAC, as from Linux, and is refused at its
/// third ACK as "administratively prohibited"; once it is gone, a join is
/// refused at its SYN as an unknown token.
#[test]
fn mp_capable_gets_a_key_and_joins_are_refused() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(2, 40001);
        let syn_options = with_mss(&mptcp_bytes(linux_capable()));
        net.send(segment(from, server(80), 5000, 0, SYN, &syn_options, b""));
        let syn_ack = net.recv().await.expect("a SYN-ACK");
        assert_eq!(flags(&syn_ack), SYN | ACK);
        let [MptcpOption::Capable(answer)] = mptcp_of(&syn_ack)[..] else {
            panic!("one MP_CAPABLE: {:?}", mptcp_of(&syn_ack));
        };
        let Keys::Sender(key) = answer.keys else {
            panic!("a key: {answer:?}")
        };
        assert_eq!(
            answer,
            Capable {
                version: 1,
                checksum_required: false,
                extensibility: false,
                no_new_subflows: false,
                algorithms: algorithm::HMAC_SHA256,
                keys: Keys::Sender(key),
            }
        );

        // The third ACK echoes both keys (RFC 8684 section 3.1).
        let client_key = 0x1111_2222_3333_4444;
        let third = mptcp_bytes(MptcpOption::Capable(Capable {
            keys: Keys::Both {
                sender: client_key,
                receiver: key,
            },
            ..answer
        }));
        let iss = seq_of(&syn_ack);
        net.send(segment(from, server(80), 5001, iss + 1, ACK, &third, b""));
        net.drain().await;
        assert_eq!(net.honeypot.mptcp_connections(), 1);

        let joiner = client(2, 40002);
        let join = with_mss(&mptcp_bytes(join_syn(token(key), 99)));
        net.send(segment(joiner, server(80), 7000, 0, SYN, &join, b""));
        let join_syn_ack = net.recv().await.expect("a SYN-ACK");
        assert_eq!(flags(&join_syn_ack), SYN | ACK);
        assert_eq!(ack_of(&join_syn_ack), 7001);
        let [
            MptcpOption::Join(Join::SynAck {
                backup: false,
                address_id: 0,
                hmac,
                random,
            }),
        ] = mptcp_of(&join_syn_ack)[..]
        else {
            panic!("one MP_JOIN: {:?}", mptcp_of(&join_syn_ack));
        };
        // HMAC-B: keyed with the listener's key then the client's, over
        // the listener's random number then the client's.
        assert_eq!(hmac[..], join_hmac(key, client_key, random, 99)[..8]);
        let join_iss = seq_of(&join_syn_ack);
        let hmac_a = join_hmac(client_key, key, 99, random);
        let third = mptcp_bytes(MptcpOption::Join(Join::Ack {
            hmac: hmac_a[..20].try_into().unwrap(),
        }));
        net.send(segment(
            joiner,
            server(80),
            7001,
            join_iss + 1,
            ACK,
            &third,
            b"",
        ));
        let refused = net.recv().await.expect("a RST");
        assert_eq!(flags(&refused), RST, "a RST in answer to the ACK");
        assert_eq!(seq_of(&refused), join_iss + 1);
        assert_eq!(
            mptcp_of(&refused),
            [MptcpOption::TcpRst {
                transient: false,
                reason: reason::ADMINISTRATIVELY_PROHIBITED
            }]
        );
        assert_eq!(net.honeypot.mptcp_connections(), 1, "the join took nothing");

        // The client ends the first connection with a RST; its token goes.
        net.send(segment(from, server(80), 5001, 0, RST, &[], b""));
        net.drain().await;
        assert_eq!(net.honeypot.mptcp_connections(), 0);
        let joiner = client(2, 40003);
        net.send(segment(joiner, server(80), 8000, 0, SYN, &join, b""));
        let refused = net.recv().await.expect("a RST");
        assert_eq!(
            mptcp_of(&refused),
            [MptcpOption::TcpRst {
                transient: false,
                reason: reason::MPTCP_SPECIFIC
            }]
        );
        net.drain().await;

        let syns = net.events("syn");
        assert_eq!(syns.len(), 3);
        assert_eq!(
            syns[0]["mptcp"][0],
            serde_json::json!({
                "subtype": "mp_capable", "version": 1, "checksum_required": false,
                "extensibility": false, "no_new_subflows": false, "algorithms": 1
            })
        );
        assert_eq!(syns[1]["mptcp"][0]["subtype"], "mp_join_syn");
        assert_eq!(syns[1]["mptcp"][0]["token"], format!("{:08x}", token(key)));
        assert_eq!(syns[1]["mptcp"][0]["token_known"], true);
        assert_eq!(syns[2]["mptcp"][0]["token_known"], false);
        let answers = net.events("answer");
        assert_eq!(answers[0]["mptcp"][0]["sender_key"], format!("{key:016x}"));
        let rsts: Vec<_> = answers
            .iter()
            .filter(|a| a["mptcp"][0]["subtype"] == "mp_tcprst")
            .collect();
        assert_eq!(rsts.len(), 2);
        assert_eq!(rsts[0]["mptcp"][0]["reason"], 3);
        assert_eq!(rsts[1]["mptcp"][0]["reason"], 1);
        // The third ACK's keys are logged as a segment.
        let third = net
            .events("segment")
            .into_iter()
            .find(|s| s["mptcp"][0]["subtype"] == "mp_capable")
            .expect("the third ACK");
        assert_eq!(
            third["mptcp"][0]["sender_key"],
            format!("{client_key:016x}")
        );
        assert_eq!(third["mptcp"][0]["receiver_key"], format!("{key:016x}"));
        // So are the join's SYN-ACK and its third ACK, with their HMACs.
        assert_eq!(answers[1]["mptcp"][0]["subtype"], "mp_join_syn_ack");
        assert_eq!(answers[1]["mptcp"][0]["hmac"], hex(&hmac));
        let join_ack = net
            .events("segment")
            .into_iter()
            .find(|s| s["mptcp"][0]["subtype"] == "mp_join_ack")
            .expect("the join's third ACK");
        assert_eq!(join_ack["mptcp"][0]["hmac"], hex(&hmac_a[..20]));
        Ok(())
    });
}

/// MP_CAPABLE of a version above 1 gets version 1 back, as Linux answers
/// it.
#[test]
fn a_higher_mptcp_version_gets_version_1() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(2, 40010);
        let offer = [30, 4, 0x02, 0x01];
        net.send(segment(
            from,
            server(80),
            5000,
            0,
            SYN,
            &with_mss(&offer),
            b"",
        ));
        let syn_ack = net.recv().await.expect("a SYN-ACK");
        let [MptcpOption::Capable(answer)] = mptcp_of(&syn_ack)[..] else {
            panic!("one MP_CAPABLE: {:?}", mptcp_of(&syn_ack));
        };
        assert_eq!(answer.version, 1);
        assert!(matches!(answer.keys, Keys::Sender(_)));
        Ok(())
    });
}

/// MP_JOINs racing from one source within the window are flagged once as
/// a burst of SYNs and once as a burst of joins; each still gets its RST,
/// and each SYN after the first gives the gap since the one before.
#[test]
fn a_burst_of_joins_is_flagged_once() {
    let config = Config {
        burst: Burst {
            window: Duration::from_millis(100),
            syns: 8,
        },
        ..Config::default()
    };
    honeypot(config, |mut net| async move {
        for n in 0..20u16 {
            let from = client(3, 41000 + n);
            let join = with_mss(&mptcp_bytes(join_syn(0xdead_beef, u32::from(n))));
            net.send(segment(from, server(22), 100, 0, SYN, &join, b""));
            net.fcx.sleep(Duration::from_millis(1)).await?;
        }
        let answers = net.drain().await;
        assert_eq!(answers.len(), 20);
        assert!(answers.iter().all(|p| flags(p) & RST == RST));
        let bursts = net.events("burst");
        assert_eq!(bursts.len(), 2, "{bursts:?}");
        assert_eq!(bursts[0]["kind"], "syns");
        assert_eq!(bursts[1]["kind"], "joins");
        for burst in &bursts {
            assert_eq!(burst["src"], "198.51.100.3");
            assert_eq!(burst["syns"], 8);
            assert_eq!(burst["window_us"], 100_000);
        }
        let syns = net.events("syn");
        assert_eq!(syns.len(), 20);
        assert!(syns[0].get("gap_us").is_none());
        assert!(syns[1..].iter().all(|s| s["gap_us"].as_u64() == Some(1000)));
        // Another source sending slowly is never a burst.
        for n in 0..10u16 {
            let from = client(4, 42000 + n);
            net.send(segment(from, server(22), 100, 0, SYN, &with_mss(&[]), b""));
            net.fcx.sleep(Duration::from_millis(200)).await?;
        }
        net.drain().await;
        assert_eq!(net.events("burst").len(), 2);
        // Its SYNs are further apart than the window, so none gives a gap.
        let slow: Vec<_> = net
            .events("syn")
            .into_iter()
            .filter(|s| s["src"].as_str().unwrap().starts_with("198.51.100.4:"))
            .collect();
        assert_eq!(slow.len(), 10);
        assert!(slow.iter().all(|s| s.get("gap_us").is_none()), "{slow:?}");
        Ok(())
    });
}

/// Broken option areas and broken packets: each is logged as far as it
/// reads, nothing panics, and the server still answers afterwards.
#[test]
fn malformed_options_are_logged_and_survived() {
    honeypot(Config::default(), |mut net| async move {
        // An option whose Length runs past the header: as on Linux, the
        // options end there and the SYN is answered, and the log keeps
        // what read.
        let from = client(5, 43000);
        let runs_past = with_mss(&[30, 12, 0x01, 0x81]);
        net.send(segment(from, server(22), 1, 0, SYN, &runs_past, b""));
        let syn_ack = net.recv().await.expect("a SYN-ACK");
        assert_eq!(flags(&syn_ack), SYN | ACK);
        assert!(mptcp_of(&syn_ack).is_empty());
        // So is MSS of Length 3, which Linux ignores.
        let odd_mss = [2, 3, 5, 0xb4];
        net.send(segment(
            client(5, 43005),
            server(22),
            1,
            0,
            SYN,
            &odd_mss,
            b"",
        ));
        let syn_ack = net.recv().await.expect("a SYN-ACK");
        assert_eq!(flags(&syn_ack), SYN | ACK);
        // An MPTCP option with an unassigned subtype: plain TCP.
        let odd = with_mss(&[30, 4, 0x90, 0]);
        net.send(segment(client(5, 43001), server(22), 1, 0, SYN, &odd, b""));
        let syn_ack = net.recv().await.expect("a SYN-ACK");
        assert!(mptcp_of(&syn_ack).is_empty());
        // MP_CAPABLE with a bad length and with no algorithm: plain TCP.
        let bad_len = with_mss(&[30, 5, 0x01, 0x81, 0, 0, 0, 0]);
        net.send(segment(
            client(5, 43002),
            server(22),
            1,
            0,
            SYN,
            &bad_len,
            b"",
        ));
        let no_alg = with_mss(&[30, 4, 0x01, 0x80]);
        net.send(segment(
            client(5, 43003),
            server(22),
            1,
            0,
            SYN,
            &no_alg,
            b"",
        ));
        for _ in 0..2 {
            let syn_ack = net.recv().await.expect("a SYN-ACK");
            assert!(mptcp_of(&syn_ack).is_empty());
        }
        // Garbage of every length, a TCP header length past the packet,
        // and a truncated IP header.
        let good = segment(client(5, 43004), server(22), 1, 0, SYN, &with_mss(&[]), b"");
        for n in 0..good.0.len() {
            net.send(Packet(good.0[..n].to_vec()));
        }
        let mut long_header = good.0.clone();
        long_header[20 + 12] = 15 << 4;
        net.send(Packet(long_header));
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..500 {
            let len = (state % 80) as usize;
            let bytes = (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect::<Vec<u8>>();
            let mut p = good.0.clone();
            p.truncate(20);
            p.extend_from_slice(&bytes);
            net.send(Packet(p));
        }
        net.drain().await;

        let syns = net.events("syn");
        let first = &syns[0];
        assert_eq!(first["options_fault"], "malformed");
        assert_eq!(
            first["options"],
            serde_json::json!([{"kind": "mss", "value": 1460}])
        );
        assert_eq!(syns[1]["options_fault"], "malformed");
        assert_eq!(
            syns[1]["options"],
            serde_json::json!([{"kind": "other", "number": 2, "data": "05"}])
        );
        assert_eq!(
            syns[2]["mptcp"][0],
            serde_json::json!({
                "subtype": "malformed",
                "fault": {"fault": "subtype", "subtype": 9},
                "data": "9000"
            })
        );
        assert_eq!(syns[3]["mptcp"][0]["fault"]["fault"], "length");
        assert_eq!(syns[4]["mptcp"][0]["fault"]["fault"], "no_algorithm");
        assert!(
            net.events("syn")
                .iter()
                .any(|s| s["options_fault"] == "header"),
            "the long header length is logged"
        );

        // The server still answers.
        let from = client(5, 43100);
        net.send(segment(from, server(80), 1, 0, SYN, &with_mss(&[]), b""));
        let syn_ack = loop {
            let p = net.recv().await.expect("a SYN-ACK");
            if tcp_of(&p)[2..4] == 43100u16.to_be_bytes() {
                break p;
            }
        };
        assert_eq!(flags(&syn_ack), SYN | ACK);
        Ok(())
    });
}

/// SYNs from thousands of spoofed sources are each logged and answered,
/// and a window later the observer holds nothing for any of them, nor the
/// MPTCP listener a token.
#[test]
fn many_sources_leave_nothing_behind() {
    honeypot(Config::default(), |mut net| async move {
        let sources = 3000u32;
        let syn = with_mss(&mptcp_bytes(linux_capable()));
        for n in 0..sources {
            let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + n)), 50000);
            net.send(segment(from, server(22), n, 0, SYN, &syn, b""));
        }
        // SYN-ACKs to sources that never answer are resent, so count the
        // sources answered.
        let mut answered = HashSet::new();
        while answered.len() < sources as usize {
            let p = net.recv().await.expect("a SYN-ACK for every source");
            assert_eq!(flags(&p), SYN | ACK);
            assert!(matches!(mptcp_of(&p)[..], [MptcpOption::Capable(_)]));
            answered.insert(p.0[16..20].to_vec());
        }
        assert_eq!(net.events("syn").len(), sources as usize);
        assert!(
            net.events("burst").is_empty(),
            "one SYN per source is no burst"
        );
        assert_eq!(net.honeypot.mptcp_connections(), 0, "no handshake finished");

        // A window later, one more SYN clears the old sources.
        net.fcx.sleep(Duration::from_secs(1)).await?;
        let from = client(6, 44000);
        net.send(segment(from, server(22), 1, 0, SYN, &with_mss(&[]), b""));
        net.drain().await;
        assert_eq!(net.honeypot.sources(), 1);
        Ok(())
    });
}

/// A sandbox attached under its own name reaches the server through the
/// network's router, and its packets are logged too.
#[test]
fn an_attached_sandbox_is_logged_too() {
    let config = Config::default();
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(9),
        |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let log = Shared::default();
            let sinks = Sinks {
                log: Box::new(log.clone()),
                pcap: Box::new(std::io::sink()),
            };
            honeypot_world::start(
                &fcx,
                &config,
                Clock::at_unix_secs(EPOCH),
                sinks,
                attachments,
            )?;
            let mut agent = attacher.attach("agent")?;
            let from = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 45000);
            let syn = with_mss(&mptcp_bytes(linux_capable()));
            agent.send(segment(from, server(22), 1, 0, SYN, &syn, b""));
            let deadline = fcx.now() + Duration::from_secs(1);
            let syn_ack = fcx.race(Some(deadline), agent.recv(&fcx)).await??;
            assert_eq!(flags(&syn_ack), SYN | ACK);
            assert_eq!(mptcp_of(&syn_ack).len(), 1);
            let log = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
            let first: Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
            assert_eq!(first["event"], "syn");
            assert_eq!(first["attachment"], "agent");
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

/// Where a packet from the world goes.
fn dst_of(p: &Packet) -> SocketAddr {
    let ip: [u8; 4] = p.0[16..20].try_into().unwrap();
    let port = u16::from_be_bytes(tcp_of(p)[2..4].try_into().unwrap());
    SocketAddr::new(Ipv4Addr::from(ip).into(), port)
}

/// Spoofed SYNs that fill the backlog do not shut the real attacker out:
/// past the backlog the server answers with SYN cookies, as Linux does, so
/// a handshake that finishes still opens, with MPTCP, and is logged. Each
/// spoofed attempt gets six SYN-ACKs, as from Linux, and is dropped
/// without a RST.
#[test]
fn a_spoofed_syn_flood_leaves_room_for_the_real_attacker() {
    honeypot(Config::default(), |mut net| async move {
        let spoofed = |n: u32| SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + n)), 50000);
        for n in 0..4096 {
            net.send(segment(
                spoofed(n),
                server(22),
                n,
                0,
                SYN,
                &with_mss(&[]),
                b"",
            ));
        }
        net.fcx.sleep(Duration::from_secs(60)).await?;

        // Window Scale and SACK-Permitted too, which a SYN-ACK that keeps
        // state answers and a SYN cookie cannot.
        let from = client(5, 43100);
        let mut offer = with_mss(&[3, 3, 7, 4, 2]);
        offer.extend_from_slice(&mptcp_bytes(linux_capable()));
        net.send(segment(from, server(22), 1000, 0, SYN, &offer, b""));
        let mut seen = Vec::new();
        let syn_ack = loop {
            let p = net.recv().await.expect("an answer");
            seen.push(p.clone());
            if dst_of(&p) == from {
                break p;
            }
        };
        assert_eq!(flags(&syn_ack), SYN | ACK);
        let kinds: Vec<u8> = tcp::options(tcp_of(&syn_ack))
            .unwrap()
            .iter()
            .map(|o| match o {
                TcpOption::MaxSegmentSize(_) => 2,
                TcpOption::Unknown { kind, .. } => *kind,
                other => panic!("a SYN cookie has no {other:?}"),
            })
            .collect();
        assert_eq!(kinds, [2, mptcp::KIND], "a SYN cookie");
        let [MptcpOption::Capable(answer)] = mptcp_of(&syn_ack)[..] else {
            panic!("MP_CAPABLE: {:?}", mptcp_of(&syn_ack));
        };
        let Keys::Sender(key) = answer.keys else {
            panic!("a key")
        };
        let third = mptcp_bytes(MptcpOption::Capable(Capable {
            keys: Keys::Both {
                sender: 0x1111,
                receiver: key,
            },
            ..answer
        }));
        let iss = seq_of(&syn_ack);
        net.send(segment(from, server(22), 1001, iss + 1, ACK, &third, b""));
        let banner = loop {
            let p = net.recv().await.expect("the banner");
            seen.push(p.clone());
            if dst_of(&p) == from && !payload_of(&p).is_empty() {
                break p;
            }
        };
        assert_eq!(payload_of(&banner), SSH_BANNER);
        assert_eq!(net.honeypot.mptcp_connections(), 1, "MPTCP after a cookie");
        let hello = b"SSH-2.0-Go\r\n";
        let acked = iss + 1 + SSH_BANNER.len() as u32;
        net.send(segment(
            from,
            server(22),
            1001,
            acked,
            PSH | ACK,
            &[],
            hello,
        ));

        // The rest of the spoofed SYN-ACKs, then quiet.
        let fcx = net.fcx.clone();
        while let Ok(p) = fcx
            .race(
                Some(fcx.now() + Duration::from_secs(40)),
                net.end.recv(&fcx),
            )
            .await
        {
            seen.push(p?);
        }
        assert!(seen.iter().all(|p| flags(p) & RST == 0), "no RST");
        for n in [0, 4095] {
            let syn_acks = seen.iter().filter(|p| dst_of(p) == spoofed(n)).count();
            assert_eq!(syn_acks, 6, "SYN-ACKs to spoofed source {n}");
        }
        let logged = net
            .events("segment")
            .into_iter()
            .any(|s| s["src"] == from.to_string() && s["payload"] == hex(hello));
        assert!(logged, "the attacker's bytes are logged");
        Ok(())
    });
}

/// The internet reaches the server and nothing else: not an attached
/// sandbox by its address, not the network's DNS, and not any address
/// beyond. What it sends is still logged.
#[test]
fn the_internet_reaches_only_the_server() {
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(9),
        |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let log = Shared::default();
            let sinks = Sinks {
                log: Box::new(log.clone()),
                pcap: Box::new(std::io::sink()),
            };
            honeypot_world::start(
                &fcx,
                &Config::default(),
                Clock::at_unix_secs(EPOCH),
                sinks,
                attachments,
            )?;
            let mut agent = attacher.attach("agent")?;
            let mut internet = attacher.attach(honeypot_world::INTERNET)?;
            let within = |fcx: &Cx| Some(fcx.now() + Duration::from_secs(2));
            let agent_addr = Ipv4Addr::new(10, 0, 0, 2);
            let own = SocketAddr::new(agent_addr.into(), 45000);
            agent.send(segment(own, server(22), 1, 0, SYN, &with_mss(&[]), b""));
            let syn_ack = fcx.race(within(&fcx), agent.recv(&fcx)).await??;
            assert_eq!(flags(&syn_ack), SYN | ACK);

            let spoofed = SocketAddr::new(agent_addr.into(), 45001);
            internet.send(segment(spoofed, server(22), 1, 0, SYN, &with_mss(&[]), b""));
            // A DNS query for a.test to the network's resolver.
            let (asker, resolver): (SocketAddr, SocketAddr) = (
                "192.0.2.99:5353".parse().unwrap(),
                "10.0.0.1:53".parse().unwrap(),
            );
            let query = [
                0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 4, b't', b'e', b's', b't', 0, 0,
                1, 0, 1,
            ];
            let mut u = Vec::new();
            u.extend_from_slice(&asker.port().to_be_bytes());
            u.extend_from_slice(&resolver.port().to_be_bytes());
            u.extend_from_slice(&(8 + query.len() as u16).to_be_bytes());
            u.extend_from_slice(&[0, 0]);
            u.extend_from_slice(&query);
            let sum = transport_checksum(asker.ip(), resolver.ip(), 17, &u);
            u[6..8].copy_from_slice(&sum.to_be_bytes());
            internet.send(packet_with(
                asker.ip(),
                resolver.ip(),
                17,
                Fields::default(),
                &u,
            ));
            let beyond: SocketAddr = "8.8.8.8:53".parse().unwrap();
            let from = client(9, 40000);
            internet.send(segment(from, beyond, 1, 0, SYN, &with_mss(&[]), b""));
            assert!(
                fcx.race(within(&fcx), internet.recv(&fcx)).await.is_err(),
                "nothing comes back"
            );
            // The agent's own SYN-ACK may come again, and nothing else.
            while let Ok(p) = fcx.race(within(&fcx), agent.recv(&fcx)).await {
                assert_eq!(dst_of(&p?), own);
            }

            let from = client(9, 40001);
            internet.send(segment(from, server(22), 1, 0, SYN, &with_mss(&[]), b""));
            let syn_ack = fcx.race(within(&fcx), internet.recv(&fcx)).await??;
            assert_eq!((flags(&syn_ack), dst_of(&syn_ack)), (SYN | ACK, from));

            let log = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
            let syns: Vec<Value> = log
                .lines()
                .map(|l| serde_json::from_str::<Value>(l).unwrap())
                .filter(|v| v["event"] == "syn" && v["attachment"] == "internet")
                .collect();
            let dsts: Vec<&str> = syns.iter().map(|s| s["dst"].as_str().unwrap()).collect();
            assert_eq!(dsts, ["203.0.113.10:22", "8.8.8.8:53", "203.0.113.10:22"]);
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

/// A SYN sent as two IP fragments is answered once whole, and logged
/// whole, as the world takes it.
#[test]
fn a_fragmented_syn_is_logged() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(8, 47000);
        let syn = segment(
            from,
            server(22),
            1000,
            0,
            SYN,
            &with_mss(&mptcp_bytes(linux_capable())),
            b"",
        );
        let (header, tcp) = syn.0.split_at(20);
        let fragment = |offset: usize, more: bool, data: &[u8]| {
            let mut p = header.to_vec();
            p.extend_from_slice(data);
            let total = p.len() as u16;
            p[2..4].copy_from_slice(&total.to_be_bytes());
            p[4..6].copy_from_slice(&77u16.to_be_bytes());
            let field = (offset / 8) as u16 | if more { 0x2000 } else { 0 };
            p[6..8].copy_from_slice(&field.to_be_bytes());
            p[10..12].copy_from_slice(&[0, 0]);
            let sum = fictionet::stdlib::network::ip::checksum(&p[..20]);
            p[10..12].copy_from_slice(&sum.to_be_bytes());
            Packet(p)
        };
        net.send(fragment(0, true, &tcp[..8]));
        net.send(fragment(8, false, &tcp[8..]));
        let syn_ack = net.recv().await.expect("a SYN-ACK");
        assert_eq!(flags(&syn_ack), SYN | ACK);
        assert!(matches!(mptcp_of(&syn_ack)[..], [MptcpOption::Capable(_)]));
        net.drain().await;
        let syns = net.events("syn");
        assert_eq!(syns.len(), 1, "{:?}", net.log());
        assert_eq!(syns[0]["src"], from.to_string());
        assert_eq!(syns[0]["mptcp"][0]["subtype"], "mp_capable");
        Ok(())
    });
}

/// Data on a SYN is in its log line.
#[test]
fn a_syn_s_payload_is_logged() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(9, 47001);
        let options = with_mss(&mptcp_bytes(linux_capable()));
        let data = b"PAYLOAD-IN-SYN";
        net.send(segment(from, server(22), 1000, 0, SYN, &options, data));
        net.drain().await;
        let syns = net.events("syn");
        assert_eq!(syns.len(), 1);
        assert_eq!(syns[0]["payload"], hex(data));
        Ok(())
    });
}
