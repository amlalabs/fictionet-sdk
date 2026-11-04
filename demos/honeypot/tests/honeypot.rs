//! The honeypot from the internet's side: hand-made packets on the
//! `internet` attachment, the answers that come back, and what the log and
//! the packet capture hold afterwards.

use std::collections::HashSet;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::ip::{self, Fields, packet_with, transport_checksum};
use fictionet::stdlib::network::tcp::{self, TcpOption};
use fictionet::stdlib::protocols::mptcp::{
    self, Capable, Dss, Join, Keys, Mapping, MptcpOption, Sequence, algorithm, join_hmac, reason,
    token,
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
    SocketAddr::new(DEFAULT_ADDRESS.into(), port)
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

/// The TCP header and payload of a packet, IPv4 or IPv6.
fn tcp_of(p: &Packet) -> &[u8] {
    fictionet::stdlib::network::ip::Header::parse(&p.0)
        .expect("an IP packet")
        .payload(&p.0)
}

fn ipv4_options(packet: Packet, options: &[fictionet::stdlib::network::ip::Ipv4Option]) -> Packet {
    use fictionet::stdlib::network::ip;
    let header = ip::Header::parse(&packet.0).unwrap();
    let (IpAddr::V4(src), IpAddr::V4(dst)) = (header.src, header.dst) else {
        panic!("IPv4 test packet")
    };
    ip::packet_with_ipv4_options(
        src,
        dst,
        6,
        Fields::default(),
        options,
        header.payload(&packet.0),
    )
    .unwrap()
}

#[test]
fn ipv4_options_echo_and_pending_retransmission_are_observed() {
    use fictionet::stdlib::network::ip::{self, Ipv4Option, Ipv4Timestamp};
    honeypot(Config::default(), |mut net| async move {
        let src = client(1, 40001);
        let options = [
            Ipv4Option::RecordRoute {
                pointer: 4,
                routes: vec![Ipv4Addr::UNSPECIFIED; 2],
            },
            Ipv4Option::Timestamp {
                pointer: 5,
                overflow: 0,
                timestamps: Ipv4Timestamp::Timestamps(vec![0; 2]),
            },
        ];
        let syn = || {
            ipv4_options(
                segment(src, server(80), 1000, 0, SYN, &with_mss(&[]), b""),
                &options,
            )
        };
        net.send(syn());
        let answer = net.recv().await.unwrap();
        assert_eq!(flags(&answer), SYN | ACK);
        let echoed = ip::ipv4_options(&answer.0).unwrap();
        let local = DEFAULT_ADDRESS;
        assert_eq!(
            echoed[0],
            Ipv4Option::RecordRoute {
                pointer: 12,
                routes: vec![local; 2]
            }
        );
        assert_eq!(
            echoed[1],
            Ipv4Option::Timestamp {
                pointer: 13,
                overflow: 0,
                timestamps: Ipv4Timestamp::Timestamps(vec![((EPOCH % 86_400) * 1000) as u32; 2]),
            }
        );
        assert_eq!(
            ip::checksum(&answer.0[..usize::from(answer.0[0] & 15) * 4]),
            0
        );
        assert_eq!(
            transport_checksum(server(80).ip(), src.ip(), 6, tcp_of(&answer)),
            0
        );
        net.send(syn());
        let repeated = net.recv().await.unwrap();
        assert_eq!(ip::ipv4_options(&repeated.0).unwrap(), echoed);
        assert_eq!(net.events("ip_options_retransmit").len(), 1);
        assert!(net.events("mptcp_no_data").is_empty());
        assert_eq!(
            net.events("syn")[0]["ipv4_options"][0]["kind"],
            "record_route"
        );
        net.send(segment(
            src,
            server(80),
            1001,
            seq_of(&answer).wrapping_add(1),
            ACK,
            &[],
            b"",
        ));
        net.send(syn());
        net.drain().await;
        assert_eq!(net.events("ip_options_retransmit").len(), 1);
        Ok(())
    });
}

#[test]
fn mptcp_no_data_is_separate_and_expires_while_quiet() {
    honeypot(Config::default(), |mut net| async move {
        net.send(segment(
            client(2, 40002),
            server(80),
            1000,
            0,
            SYN,
            &with_mss(&mptcp_bytes(linux_capable())),
            b"",
        ));
        net.recv().await.unwrap();
        assert!(net.events("mptcp_no_data").is_empty());
        net.fcx.sleep(Duration::from_secs(64)).await?;
        let records = net.events("mptcp_no_data");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["end"], "expired");
        assert_eq!(records[0]["completed"], false);
        assert!(net.events("ip_options_retransmit").is_empty());
        Ok(())
    });
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
    exchange_with(net, from, server(port), pieces).await
}

/// Opens a connection to `to` from `from`, sends `request` in the pieces
/// given, and returns what the server sent back.
async fn exchange_with(
    net: &mut Internet,
    from: SocketAddr,
    to: SocketAddr,
    pieces: &[&[u8]],
) -> Vec<u8> {
    net.send(segment(from, to, 1000, 0, SYN, &with_mss(&[]), b""));
    // Earlier connections may still be closing.
    let syn_ack = loop {
        let p = net.recv().await.expect("a SYN-ACK");
        if flags(&p) == SYN | ACK && tcp_of(&p)[2..4] == from.port().to_be_bytes() {
            break p;
        }
    };
    let iss = seq_of(&syn_ack);
    let mut seq = 1001;
    net.send(segment(from, to, seq, iss + 1, ACK, &[], b""));
    for piece in pieces {
        net.send(segment(from, to, seq, iss + 1, PSH | ACK, &[], piece));
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

/// With an IPv6 address, the server serves the same SSH and HTTP there as
/// at its IPv4 address, and the log has the same lines for it. The
/// internet still reaches no other IPv6 address.
#[test]
fn ipv6_gets_the_same_ssh_and_http() {
    let address_v6: IpAddr = "2001:db8:113::10".parse().unwrap();
    let IpAddr::V6(v6) = address_v6 else {
        unreachable!()
    };
    let config = Config {
        address_v6: Some(v6),
        ..Config::default()
    };
    honeypot(config, move |mut net| async move {
        let from: SocketAddr = "[2001:db8:1::1]:40000".parse().unwrap();
        let ssh = SocketAddr::new(address_v6, 22);
        net.send(segment(from, ssh, 1000, 0, SYN, &with_mss(&[]), b""));
        let syn_ack = net.recv().await.expect("a SYN-ACK");
        assert_eq!(flags(&syn_ack), SYN | ACK);
        assert_eq!(
            transport_checksum(address_v6, from.ip(), 6, tcp_of(&syn_ack)),
            0
        );
        let iss = seq_of(&syn_ack);
        net.send(segment(from, ssh, 1001, iss + 1, ACK, &[], b""));
        let banner = net.recv().await.expect("the banner");
        assert_eq!(payload_of(&banner), SSH_BANNER);
        let acked = iss + 1 + SSH_BANNER.len() as u32;
        net.send(segment(from, ssh, 1001, acked, ACK, &[], b""));

        let page = exchange_with(
            &mut net,
            "[2001:db8:1::1]:40001".parse().unwrap(),
            SocketAddr::new(address_v6, 80),
            &[b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"],
        )
        .await;
        let page = String::from_utf8(page).unwrap();
        assert!(page.starts_with("HTTP/1.1 200 OK\r\n"), "{page}");
        assert!(page.contains("Welcome to nginx!"));

        let elsewhere = SocketAddr::new("2001:db8:113::11".parse().unwrap(), 22);
        net.send(segment(from, elsewhere, 1, 0, SYN, &with_mss(&[]), b""));
        let from_elsewhere = net
            .drain()
            .await
            .into_iter()
            .filter(|p| ip::source(&p.0) == Some(elsewhere.ip()))
            .count();
        assert_eq!(from_elsewhere, 0, "nothing else answers");

        // The IPv4 address still serves.
        let from4 = client(1, 40002);
        net.send(segment(from4, server(22), 1, 0, SYN, &with_mss(&[]), b""));
        let syn_ack = net.recv().await.expect("an IPv4 SYN-ACK");
        assert_eq!(flags(&syn_ack), SYN | ACK);

        let syns = net.events("syn");
        let dsts: Vec<&str> = syns.iter().map(|s| s["dst"].as_str().unwrap()).collect();
        assert_eq!(
            dsts,
            [
                "[2001:db8:113::10]:22",
                "[2001:db8:113::10]:80",
                "[2001:db8:113::11]:22",
                "203.0.113.10:22"
            ]
        );
        assert!(syns.iter().all(|s| s["attachment"] == "internet"));
        assert_eq!(syns[0]["src"], "[2001:db8:1::1]:40000");
        let answers = net.events("answer");
        assert_eq!(answers[0]["flags"], "SYN|ACK");
        assert_eq!(answers[0]["src"], "[2001:db8:113::10]:22");
        Ok(())
    });
}

/// The DSS of a packet from the world, if it has one.
fn dss_of(p: &Packet) -> Option<Dss> {
    mptcp_of(p).into_iter().find_map(|o| match o {
        MptcpOption::Dss(dss) => Some(dss),
        _ => None,
    })
}

/// Opens an MPTCP connection from `from` to the server's `port`: an
/// MP_CAPABLE SYN, and a third ACK that echoes the keys with
/// `client_key`. Returns the server's key and its initial sequence
/// number.
async fn open_mptcp(
    net: &mut Internet,
    from: SocketAddr,
    port: u16,
    client_key: u64,
) -> (u64, u32) {
    let syn_options = with_mss(&mptcp_bytes(linux_capable()));
    net.send(segment(from, server(port), 5000, 0, SYN, &syn_options, b""));
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
    let third = mptcp_bytes(MptcpOption::Capable(Capable {
        keys: Keys::Both {
            sender: client_key,
            receiver: key,
        },
        ..answer
    }));
    let iss = seq_of(&syn_ack);
    net.send(segment(from, server(port), 5001, iss + 1, ACK, &third, b""));
    (key, iss)
}

/// An MP_CAPABLE SYN gets MP_CAPABLE back with a key, and once the third
/// ACK echoes the keys the server's data carries DSS: a mapping from its
/// IDSN + 1 and a Data ACK of the client's (RFC 8684 section 3.3), as a
/// Linux server sends them. The client's data without a mapping makes the
/// connection fall back, and the server sends no more DSS (section 3.7).
#[test]
fn an_mptcp_connection_speaks_dss_until_the_client_falls_back() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(2, 40001);
        let client_key = 0x1111_2222_3333_4444;
        let (key, iss) = open_mptcp(&mut net, from, 22, client_key).await;
        let banner = net.recv().await.expect("the banner");
        assert_eq!(payload_of(&banner), SSH_BANNER);
        assert_eq!(net.honeypot.mptcp_connections(), 1);
        assert_eq!(
            dss_of(&banner),
            Some(Dss {
                data_ack: Some(Sequence::Short(mptcp::idsn(client_key).advance(1).short())),
                mapping: Some(Mapping {
                    data_sequence_number: Sequence::Long(mptcp::idsn(key).advance(1)),
                    subflow_sequence_number: 1,
                    data_level_length: SSH_BANNER.len() as u16,
                    checksum: None,
                }),
                data_fin: false,
            })
        );
        let acked = iss + 1 + SSH_BANNER.len() as u32;
        // Mapped data, with a 64-bit data sequence number, is acknowledged
        // at the data level in 8 octets.
        let hello = b"SSH-2.0-x\r\n";
        let dss = mptcp_bytes(MptcpOption::Dss(Dss {
            data_ack: Some(Sequence::Long(
                mptcp::idsn(key).advance(1 + SSH_BANNER.len() as u64),
            )),
            mapping: Some(Mapping {
                data_sequence_number: Sequence::Long(mptcp::idsn(client_key).advance(1)),
                subflow_sequence_number: 1,
                data_level_length: hello.len() as u16,
                checksum: None,
            }),
            data_fin: false,
        }));
        net.send(segment(
            from,
            server(22),
            5001,
            acked,
            PSH | ACK,
            &dss,
            hello,
        ));
        let ack = net.recv().await.expect("an ACK");
        assert_eq!(ack_of(&ack), 5001 + hello.len() as u32);
        let data_ack = mptcp::idsn(client_key).advance(1 + hello.len() as u64);
        assert_eq!(
            dss_of(&ack).unwrap().data_ack,
            Some(Sequence::Long(data_ack))
        );
        // Data with no mapping: the connection falls back.
        let seq = 5001 + hello.len() as u32;
        net.send(segment(
            from,
            server(22),
            seq,
            acked,
            PSH | ACK,
            &[],
            b"plain",
        ));
        let ack = net.recv().await.expect("an ACK");
        assert_eq!(ack_of(&ack), seq + 5);
        assert_eq!(dss_of(&ack), None, "no DSS after the fall back");
        Ok(())
    });
}

/// While an MPTCP connection is open, an MP_JOIN with its token gets a
/// SYN-ACK with MP_JOIN and the listener's HMAC on the connection's port,
/// and a RST that says "administratively prohibited" on another. At the
/// third ACK, the client's HMAC decides, as on Linux: a wrong one gets
/// that RST, the right one is taken, and the subflow stays open until the
/// connection is gone. Then a join is refused at its SYN as an unknown
/// token.
#[test]
fn joins_are_answered_taken_and_refused_as_on_linux() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(2, 40001);
        let client_key = 0x1111_2222_3333_4444;
        let (key, iss) = open_mptcp(&mut net, from, 22, client_key).await;
        let banner = net.recv().await.expect("the banner");
        assert_eq!(payload_of(&banner), SSH_BANNER);
        let acked = iss + 1 + SSH_BANNER.len() as u32;
        net.send(segment(from, server(22), 5001, acked, ACK, &[], b""));
        net.drain().await;
        assert_eq!(net.honeypot.mptcp_connections(), 1);

        // A join on another port.
        let join = with_mss(&mptcp_bytes(join_syn(token(key), 99)));
        let elsewhere = client(2, 40002);
        net.send(segment(elsewhere, server(80), 7000, 0, SYN, &join, b""));
        let refused = net.recv().await.expect("a RST");
        assert_eq!(flags(&refused) & RST, RST);
        let prohibited = [MptcpOption::TcpRst {
            transient: false,
            reason: reason::ADMINISTRATIVELY_PROHIBITED,
        }];
        assert_eq!(mptcp_of(&refused), prohibited);

        // A join on the connection's port, with a wrong HMAC, then with
        // the right one.
        let mut taken = None;
        for (port, right) in [(40003, false), (40004, true)] {
            let joiner = client(2, port);
            net.send(segment(joiner, server(22), 7000, 0, SYN, &join, b""));
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
            // HMAC-B: keyed with the listener's key then the client's,
            // over the listener's random number then the client's.
            assert_eq!(hmac[..], join_hmac(key, client_key, random, 99)[..8]);
            let join_iss = seq_of(&join_syn_ack);
            let mut hmac_a: [u8; 20] = join_hmac(client_key, key, 99, random)[..20]
                .try_into()
                .unwrap();
            if !right {
                hmac_a[0] ^= 1;
            }
            let third = mptcp_bytes(MptcpOption::Join(Join::Ack { hmac: hmac_a }));
            net.send(segment(
                joiner,
                server(22),
                7001,
                join_iss + 1,
                ACK,
                &third,
                b"",
            ));
            if right {
                let fourth = net.recv().await.expect("the join confirmation ACK");
                assert_eq!(flags(&fourth), ACK);
                assert_eq!(ack_of(&fourth), 7001);
                assert!(payload_of(&fourth).is_empty());
                net.send(segment(
                    joiner,
                    server(22),
                    7001,
                    join_iss + 1,
                    PSH | ACK,
                    &[],
                    b"more",
                ));
                let answer = net.recv().await.expect("an ACK");
                assert_eq!(flags(&answer), ACK, "the subflow is open");
                assert_eq!(ack_of(&answer), 7005);
                assert!(payload_of(&answer).is_empty(), "nothing from the server");
                taken = Some(joiner);
            } else {
                let refused = net.recv().await.expect("a RST");
                assert_eq!(flags(&refused), RST, "a RST in answer to the ACK");
                assert_eq!(seq_of(&refused), join_iss + 1);
                assert_eq!(mptcp_of(&refused), prohibited);
            }
        }
        net.drain().await;
        assert_eq!(
            net.honeypot.mptcp_connections(),
            1,
            "a join is no connection"
        );

        // The client ends the connection with a RST: its token goes, and
        // the joined subflow closes.
        net.send(segment(from, server(22), 5001, 0, RST, &[], b""));
        let joiner = taken.unwrap();
        let fin = net
            .drain()
            .await
            .into_iter()
            .find(|p| dst_of(p) == joiner && flags(p) & 0x01 != 0)
            .expect("a FIN on the joined subflow");
        let fin_ack = seq_of(&fin) + 1;
        net.send(segment(
            joiner,
            server(22),
            7005,
            fin_ack,
            ACK | 0x01,
            &[],
            b"",
        ));
        net.drain().await;
        assert_eq!(net.honeypot.mptcp_connections(), 0);
        let joiner = client(2, 40005);
        net.send(segment(joiner, server(22), 8000, 0, SYN, &join, b""));
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
        assert_eq!(syns.len(), 5);
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
        assert_eq!(syns[4]["mptcp"][0]["token_known"], false);
        let answers = net.events("answer");
        assert_eq!(answers[0]["mptcp"][0]["sender_key"], format!("{key:016x}"));
        let reasons: Vec<_> = answers
            .iter()
            .filter(|a| a["mptcp"][0]["subtype"] == "mp_tcprst")
            .map(|a| a["mptcp"][0]["reason"].clone())
            .collect();
        assert_eq!(reasons, [3, 3, 1]);
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
        // So are the joins' third ACKs, and what came on the subflow.
        let join_acks = net
            .events("segment")
            .into_iter()
            .filter(|s| s["mptcp"][0]["subtype"] == "mp_join_ack")
            .count();
        assert_eq!(join_acks, 2);
        assert!(
            net.events("segment")
                .iter()
                .any(|s| s["src"] == client(2, 40004).to_string() && s["payload"] == hex(b"more"))
        );
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
        // Its checksum is right, so the header length is its only fault.
        let mut long_header = good.0.clone();
        long_header[20 + 12] = 15 << 4;
        long_header[20 + 16..20 + 18].copy_from_slice(&[0, 0]);
        let sum = transport_checksum(from.ip(), server(22).ip(), 6, &long_header[20..]);
        long_header[20 + 16..20 + 18].copy_from_slice(&sum.to_be_bytes());
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

        // Quiet traffic still releases all burst state when the window ends.
        net.fcx.sleep(Duration::from_secs(1)).await?;
        assert_eq!(net.honeypot.sources(), 0);
        Ok(())
    });
}

#[test]
fn zero_burst_window_keeps_every_first_answer() {
    honeypot(
        Config {
            burst: Burst {
                window: Duration::ZERO,
                syns: 8,
            },
            ..Config::default()
        },
        |mut net| async move {
            for n in 1..=2 {
                net.send(segment(
                    client(n, 40000),
                    server(22),
                    1,
                    0,
                    SYN,
                    &with_mss(&[]),
                    b"",
                ));
            }
            net.drain().await;
            assert_eq!(net.events("syn").len(), 2);
            assert_eq!(net.events("answer").len(), 2);
            assert_eq!(net.honeypot.sources(), 0);
            Ok(())
        },
    );
}

#[test]
fn new_bursts_expire_before_older_answer_deadlines() {
    honeypot(Config::default(), |mut net| async move {
        net.send(segment(
            client(3, 40000),
            "203.0.113.11:22".parse().unwrap(),
            1,
            0,
            SYN,
            &with_mss(&[]),
            b"",
        ));
        for n in 1..=2 {
            net.send(segment(
                client(n, 40000),
                server(22),
                1,
                0,
                SYN,
                &with_mss(&[]),
                b"",
            ));
            net.drain().await;
            assert_eq!(net.honeypot.sources(), 0);
        }
        Ok(())
    });
}

#[test]
fn burst_state_expires_after_the_attachment_leaves() {
    honeypot(Config::default(), |mut net| async move {
        net.send(segment(
            client(1, 40000),
            server(22),
            1,
            0,
            SYN,
            &with_mss(&[]),
            b"",
        ));
        net.recv().await.expect("the SYN was processed");
        drop(net.end);
        net.fcx.sleep(Duration::from_secs(1)).await?;
        assert_eq!(net.honeypot.sources(), 0);
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

/// An IPv4 fragment of `whole`, a packet with a 20-byte header: `data`
/// at `offset`, with identification `id`.
fn fragment(whole: &Packet, id: u16, offset: usize, more: bool, data: &[u8]) -> Packet {
    let mut p = whole.0[..20].to_vec();
    p.extend_from_slice(data);
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[4..6].copy_from_slice(&id.to_be_bytes());
    let field = (offset / 8) as u16 | if more { 0x2000 } else { 0 };
    p[6..8].copy_from_slice(&field.to_be_bytes());
    p[10..12].copy_from_slice(&[0, 0]);
    let sum = fictionet::stdlib::network::ip::checksum(&p[..20]);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    Packet(p)
}

/// More than 4 MiB of fragments for an address the internet does not
/// reach cannot push a SYN's first fragment out: those fragments are never
/// put together, so the SYN the world answers is in the log.
#[test]
fn fragments_for_elsewhere_cannot_hide_a_syn() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(8, 47000);
        let options = with_mss(&mptcp_bytes(linux_capable()));
        let syn = segment(from, server(22), 1000, 0, SYN, &options, b"");
        let tcp = syn.0[20..].to_vec();
        net.send(fragment(&syn, 77, 0, true, &tcp[..8]));
        let junk = segment(
            client(66, 1),
            "198.51.100.1:9".parse().unwrap(),
            1,
            0,
            ACK,
            &[],
            &[0; 1400],
        );
        for id in 0..3200 {
            net.send(fragment(&junk, id, 0, true, &junk.0[20..1420]));
        }
        net.send(fragment(&syn, 77, 8, false, &tcp[8..]));
        let syn_acks = net
            .drain()
            .await
            .into_iter()
            .filter(|p| dst_of(p) == from && flags(p) == SYN | ACK)
            .count();
        assert_eq!(syn_acks, 1, "the world answers the SYN");
        let syns = net.events("syn");
        assert_eq!(syns.len(), 1, "and the log has it");
        assert_eq!(syns[0]["src"], from.to_string());
        Ok(())
    });
}

/// A SYN whose last fragment comes 40 seconds after its first is neither
/// answered nor logged: the first waited 30 seconds at most, as on Linux
/// (ipfrag_time), and the log reads what the world takes.
#[test]
fn fragments_expire_for_the_log_as_for_the_world() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(8, 47000);
        let options = with_mss(&mptcp_bytes(linux_capable()));
        let syn = segment(from, server(22), 1000, 0, SYN, &options, b"");
        let tcp = syn.0[20..].to_vec();
        net.send(fragment(&syn, 77, 0, true, &tcp[..8]));
        net.fcx.sleep(Duration::from_secs(40)).await?;
        net.send(fragment(&syn, 77, 8, false, &tcp[8..]));
        let answers = net.drain().await;
        assert!(answers.is_empty(), "{answers:?}");
        assert!(net.events("syn").is_empty(), "{:?}", net.log());
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

/// A Linux client that speaks first maps its first bytes with MP_CAPABLE
/// and data, after a third ACK with none (RFC 8684 section 3.1). The
/// server takes that as a mapping, so the connection stays MPTCP and the
/// answer carries DSS, with a Data ACK past the request.
#[test]
fn mp_capable_with_data_maps_a_client_s_first_bytes() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(3, 41000);
        let client_key = 0x5555_6666_7777_8888;
        let (key, iss) = open_mptcp(&mut net, from, 80, client_key).await;
        let request = b"GET / HTTP/1.1\r\nHost: 203.0.113.10\r\n\r\n";
        let first = mptcp_bytes(MptcpOption::Capable(Capable {
            keys: Keys::Data {
                sender: client_key,
                receiver: key,
                data_level_length: request.len() as u16,
                checksum: None,
            },
            ..match linux_capable() {
                MptcpOption::Capable(c) => c,
                _ => unreachable!(),
            }
        }));
        net.send(segment(
            from,
            server(80),
            5001,
            iss + 1,
            PSH | ACK,
            &first,
            request,
        ));
        let replies: Vec<Packet> = net
            .drain()
            .await
            .into_iter()
            .filter(|p| !payload_of(p).is_empty())
            .collect();
        assert!(
            payload_of(&replies[0]).starts_with(b"HTTP/1.1 200 OK"),
            "{replies:?}"
        );
        let past_request = mptcp::idsn(client_key).advance(1 + request.len() as u64);
        for reply in &replies {
            let dss = dss_of(reply).expect("DSS on the answer");
            assert!(dss.mapping.is_some());
            assert_eq!(dss.data_ack, Some(Sequence::Long(past_request)));
        }
        assert_eq!(net.honeypot.mptcp_connections(), 1);
        Ok(())
    });
}

/// A DATA_FIN on a segment with no data and no FIN, as a Linux client
/// sends it when it closes, is acknowledged at once with a Data ACK past
/// it (RFC 8684 section 3.3.3).
#[test]
fn a_data_fin_alone_is_acknowledged_at_once() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(3, 41001);
        let client_key = 0x1111_2222_3333_4444;
        let (key, iss) = open_mptcp(&mut net, from, 22, client_key).await;
        let banner = net.recv().await.expect("the banner");
        assert_eq!(payload_of(&banner), SSH_BANNER);
        let acked = iss + 1 + SSH_BANNER.len() as u32;
        let data_fin = mptcp_bytes(MptcpOption::Dss(Dss {
            data_ack: Some(Sequence::Long(
                mptcp::idsn(key).advance(1 + SSH_BANNER.len() as u64),
            )),
            mapping: Some(Mapping {
                data_sequence_number: Sequence::Long(mptcp::idsn(client_key).advance(1)),
                subflow_sequence_number: 0,
                data_level_length: 1,
                checksum: None,
            }),
            data_fin: true,
        }));
        net.send(segment(from, server(22), 5001, acked, ACK, &data_fin, b""));
        let ack = net.recv().await.expect("an ACK at once");
        assert_eq!(flags(&ack) & (SYN | RST), 0);
        assert_eq!(ack_of(&ack), 5001, "no subflow byte");
        assert_eq!(
            dss_of(&ack).unwrap().data_ack,
            Some(Sequence::Long(mptcp::idsn(client_key).advance(2)))
        );
        Ok(())
    });
}

/// Sends a join SYN for `key`'s connection from `joiner`, with random 99,
/// and returns the server's random number and initial sequence number
/// from its SYN-ACK. SYN-ACKs to others that come first are skipped.
async fn join(net: &mut Internet, joiner: SocketAddr, key: u64) -> (u32, u32) {
    let syn = with_mss(&mptcp_bytes(join_syn(token(key), 99)));
    net.send(segment(joiner, server(22), 7000, 0, SYN, &syn, b""));
    let syn_ack = loop {
        let p = net.recv().await.expect("a SYN-ACK");
        if dst_of(&p) == joiner {
            break p;
        }
    };
    assert_eq!(flags(&syn_ack), SYN | ACK);
    let [MptcpOption::Join(Join::SynAck { random, .. })] = mptcp_of(&syn_ack)[..] else {
        panic!("MP_JOIN: {:?}", mptcp_of(&syn_ack));
    };
    (random, seq_of(&syn_ack))
}

/// A join's third ACK with no MP_JOIN is refused as an MPTCP-specific
/// error, as Linux refuses a join it would have to fall back.
#[test]
fn a_join_ack_without_mp_join_is_an_mptcp_error() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(4, 42000);
        let (key, _) = open_mptcp(&mut net, from, 22, 0x1111_2222_3333_4444).await;
        net.drain().await;
        let joiner = client(4, 42001);
        let (_, join_iss) = join(&mut net, joiner, key).await;
        net.send(segment(
            joiner,
            server(22),
            7001,
            join_iss + 1,
            ACK,
            &[],
            b"",
        ));
        let refused = net.recv().await.expect("a RST");
        assert_eq!(flags(&refused), RST);
        assert_eq!(
            mptcp_of(&refused),
            [MptcpOption::TcpRst {
                transient: false,
                reason: reason::MPTCP_SPECIFIC
            }]
        );
        Ok(())
    });
}

/// While spoofed SYNs fill the backlog, a join SYN gets a SYN cookie, and
/// the server keeps what it needs as Linux does: the third ACK with the
/// right HMAC is taken. A cookie join whose connection is gone by its ACK
/// is dropped with no answer.
#[test]
fn a_join_answered_with_a_syn_cookie_is_taken() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(5, 43000);
        let client_key = 0x1111_2222_3333_4444;
        let (key, _) = open_mptcp(&mut net, from, 22, client_key).await;
        net.drain().await;
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
        let hmac = |our_random| {
            let hmac: [u8; 20] = join_hmac(client_key, key, 99, our_random)[..20]
                .try_into()
                .unwrap();
            mptcp_bytes(MptcpOption::Join(Join::Ack { hmac }))
        };
        let joiner = client(5, 43001);
        let (random, join_iss) = join(&mut net, joiner, key).await;
        net.send(segment(
            joiner,
            server(22),
            7001,
            join_iss + 1,
            ACK,
            &hmac(random),
            b"",
        ));
        net.send(segment(
            joiner,
            server(22),
            7001,
            join_iss + 1,
            PSH | ACK,
            &[],
            b"more",
        ));
        let answer = loop {
            let p = net.recv().await.expect("an ACK");
            if dst_of(&p) == joiner {
                break p;
            }
        };
        assert_eq!(flags(&answer), ACK, "the subflow is open");
        assert_eq!(ack_of(&answer), 7005);

        // Another join, whose connection the client ends before the ACK.
        let late = client(5, 43002);
        let (random, join_iss) = join(&mut net, late, key).await;
        net.send(segment(from, server(22), 5001, 0, RST, &[], b""));
        net.drain().await;
        assert_eq!(
            net.honeypot.mptcp_connections(),
            0,
            "the connection is gone"
        );
        net.send(segment(
            late,
            server(22),
            7001,
            join_iss + 1,
            ACK,
            &hmac(random),
            b"",
        ));
        let fcx = net.fcx.clone();
        let deadline = fcx.now() + Duration::from_millis(500);
        while let Ok(p) = fcx.race(Some(deadline), net.end.recv(&fcx)).await {
            let p = p?;
            assert_ne!(
                dst_of(&p),
                late,
                "nothing to the late join: {:x} {:?}",
                flags(&p),
                mptcp_of(&p)
            );
        }
        Ok(())
    });
}

/// SYNs from addresses no router forwards from, plain or with MP_JOIN,
/// get nothing back.
#[test]
fn martian_sources_get_nothing() {
    honeypot(Config::default(), |mut net| async move {
        let martians = [
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "239.1.2.3",
            "240.0.0.1",
            "255.255.255.255",
        ];
        for (n, src) in martians.iter().enumerate() {
            let ip: IpAddr = src.parse().unwrap();
            let plain = SocketAddr::new(ip, 40000 + n as u16);
            net.send(segment(plain, server(22), 1, 0, SYN, &with_mss(&[]), b""));
            let joining = SocketAddr::new(ip, 41000 + n as u16);
            let join = with_mss(&mptcp_bytes(join_syn(0xdead_beef, 1)));
            net.send(segment(joining, server(22), 1, 0, SYN, &join, b""));
        }
        let answers = net.drain().await;
        assert!(answers.is_empty(), "{answers:?}");
        Ok(())
    });
}

/// An idle SSH connection gets no keepalive before sshd's login grace
/// time ends it with a FIN, as on Linux, where the first comes after two
/// hours.
#[test]
fn an_idle_ssh_connection_gets_no_keepalive() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(6, 44000);
        net.send(segment(from, server(22), 1000, 0, SYN, &with_mss(&[]), b""));
        let syn_ack = net.recv().await.expect("a SYN-ACK");
        let iss = seq_of(&syn_ack);
        net.send(segment(from, server(22), 1001, iss + 1, ACK, &[], b""));
        let banner = net.recv().await.expect("the banner");
        assert_eq!(payload_of(&banner), SSH_BANNER);
        let acked = iss + 1 + SSH_BANNER.len() as u32;
        net.send(segment(from, server(22), 1001, acked, ACK, &[], b""));
        let fcx = net.fcx.clone();
        let quiet = fcx
            .race(
                Some(fcx.now() + Duration::from_secs(115)),
                net.end.recv(&fcx),
            )
            .await;
        assert!(quiet.is_err(), "a keepalive: {quiet:?}");
        let fin = fcx
            .race(
                Some(fcx.now() + Duration::from_secs(10)),
                net.end.recv(&fcx),
            )
            .await??;
        assert_eq!(flags(&fin), ACK | 0x01, "sshd's FIN");
        Ok(())
    });
}

/// A SYN whose TCP checksum is wrong is not answered, as the world
/// discards it, and not logged either, so it counts toward no burst. The
/// capture has it.
#[test]
fn syns_with_a_wrong_checksum_are_in_the_capture_only() {
    honeypot(Config::default(), |mut net| async move {
        for port in 40001..=40008 {
            let from = client(3, port);
            let options = with_mss(&mptcp_bytes(linux_capable()));
            let mut syn = segment(from, server(22), 1000, 0, SYN, &options, b"");
            syn.0[20 + 16] ^= 0xff;
            net.send(syn);
        }
        assert!(net.drain().await.is_empty(), "no answer");
        assert!(net.events("syn").is_empty(), "{:?}", net.log());
        assert!(net.events("burst").is_empty());
        assert_eq!(net.pcap_blocks().len() - 2, 8);
        Ok(())
    });
}

/// A spoofed SYN's SYN-ACK is sent six times, as from Linux, and all six
/// are in the capture, but the log has one answer line for it.
#[test]
fn a_syn_ack_sent_again_is_logged_once() {
    honeypot(Config::default(), |mut net| async move {
        let spoofed = client(77, 45000);
        net.send(segment(spoofed, server(22), 1, 0, SYN, &with_mss(&[]), b""));
        let fcx = net.fcx.clone();
        let mut syn_acks = 0;
        while let Ok(p) = fcx
            .race(
                Some(fcx.now() + Duration::from_secs(40)),
                net.end.recv(&fcx),
            )
            .await
        {
            assert_eq!(flags(&p?), SYN | ACK);
            syn_acks += 1;
        }
        assert_eq!(syn_acks, 6);
        assert_eq!(net.pcap_blocks().len() - 2, 7, "the SYN and six SYN-ACKs");
        let answers = net.events("answer");
        assert_eq!(answers.len(), 1, "{answers:?}");
        assert_eq!(answers[0]["dst"], spoofed.to_string());
        Ok(())
    });
}

/// Writes nothing after the first `room` bytes.
#[derive(Clone)]
struct Full(Arc<Mutex<usize>>);

impl Write for Full {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut room = self.0.lock().unwrap();
        if *room == 0 {
            return Err(std::io::ErrorKind::StorageFull.into());
        }
        let n = buf.len().min(*room);
        *room -= n;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A full disk does not stop the world: with neither file taking another
/// byte, the server still answers and serves.
#[test]
fn a_full_disk_does_not_stop_the_world() {
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(7),
        |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            // Room for the capture's header and no more.
            let mut header = Vec::new();
            fictionet::stdlib::pcap::start(&mut header, &[]);
            let sinks = Sinks {
                log: Box::new(Full(Arc::new(Mutex::new(0)))),
                pcap: Box::new(Full(Arc::new(Mutex::new(header.len())))),
            };
            honeypot_world::start(
                &fcx,
                &Config::default(),
                Clock::at_unix_secs(EPOCH),
                sinks,
                attachments,
            )?;
            let mut internet = attacher.attach(honeypot_world::INTERNET)?;
            let within = |fcx: &Cx| Some(fcx.now() + Duration::from_secs(2));
            let from = client(9, 46000);
            internet.send(segment(from, server(22), 1, 0, SYN, &with_mss(&[]), b""));
            let syn_ack = fcx.race(within(&fcx), internet.recv(&fcx)).await??;
            assert_eq!(flags(&syn_ack), SYN | ACK);
            let iss = seq_of(&syn_ack);
            internet.send(segment(from, server(22), 2, iss + 1, ACK, &[], b""));
            let banner = fcx.race(within(&fcx), internet.recv(&fcx)).await??;
            assert_eq!(payload_of(&banner), SSH_BANNER);
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn fastclose_resets_the_connection_and_removes_its_token() {
    honeypot(Config::default(), |mut net| async move {
        let from = client(2, 43000);
        let (key, iss) = open_mptcp(&mut net, from, 22, 123456).await;
        let banner = net.recv().await.expect("the banner");
        let ack = iss + 1 + payload_of(&banner).len() as u32;
        let wrong = mptcp_bytes(MptcpOption::FastClose {
            receiver_key: key ^ 1,
        });
        net.send(segment(from, server(22), 5001, ack, ACK, &wrong, b""));
        net.drain().await;
        assert_eq!(net.honeypot.mptcp_connections(), 1);
        let joiner = client(2, 43002);
        let join = with_mss(&mptcp_bytes(join_syn(token(key), 99)));
        net.send(segment(joiner, server(22), 7000, 0, SYN, &join, b""));
        let syn_ack = net.recv().await.expect("the join SYN ACK");
        let [MptcpOption::Join(Join::SynAck { random, .. })] = mptcp_of(&syn_ack)[..] else {
            panic!("join nonce")
        };
        let join_iss = seq_of(&syn_ack);
        let hmac = join_hmac(123456, key, 99, random)[..20].try_into().unwrap();
        let third = mptcp_bytes(MptcpOption::Join(Join::Ack { hmac }));
        net.send(segment(
            joiner,
            server(22),
            7001,
            join_iss + 1,
            ACK,
            &third,
            b"",
        ));
        let fourth = net.recv().await.expect("the join confirmation");
        assert_eq!(flags(&fourth), ACK);
        assert_eq!(ack_of(&fourth), 7001);
        let close = mptcp_bytes(MptcpOption::FastClose { receiver_key: key });
        net.send(segment(from, server(22), 5001, ack, ACK, &close, b""));
        // Each subflow's RST carries MP_TCPRST, as Linux sends it.
        let unspecified = [MptcpOption::TcpRst {
            transient: false,
            reason: reason::UNSPECIFIED,
        }];
        let reset = net.recv().await.expect("the fastclose reset");
        assert_eq!(flags(&reset) & RST, RST);
        assert_eq!(mptcp_of(&reset), unspecified);
        let joined_reset = net.recv().await.expect("the joined subflow reset");
        assert_eq!(flags(&joined_reset) & RST, RST);
        assert_eq!(mptcp_of(&joined_reset), unspecified);
        net.drain().await;
        assert_eq!(net.honeypot.mptcp_connections(), 0);
        let join = with_mss(&mptcp_bytes(join_syn(token(key), 99)));
        net.send(segment(
            client(2, 43001),
            server(22),
            7000,
            0,
            SYN,
            &join,
            b"",
        ));
        assert_eq!(
            flags(&net.recv().await.expect("the refused join")) & RST,
            RST
        );
        Ok(())
    });
}

#[test]
fn mappings_with_invalid_checksum_mode_or_contents_reset_before_delivery() {
    for (required, checksum, handshake_data) in [
        (true, None, false),
        (true, Some(0), false),
        (false, Some(0), false),
        (true, None, true),
        (true, Some(0), true),
    ] {
        honeypot(Config::default(), move |mut net| async move {
            let from = client(2, 44000);
            let client_key = 0x123456789abcdef;
            let capable = Capable {
                version: 1,
                checksum_required: required,
                extensibility: false,
                no_new_subflows: false,
                algorithms: algorithm::HMAC_SHA256,
                keys: Keys::Absent,
            };
            let syn = with_mss(&mptcp_bytes(MptcpOption::Capable(capable)));
            net.send(segment(from, server(22), 5000, 0, SYN, &syn, b""));
            let answer = net.recv().await.expect("the SYN ACK");
            let [
                MptcpOption::Capable(Capable {
                    keys: Keys::Sender(key),
                    ..
                }),
            ] = mptcp_of(&answer)[..]
            else {
                panic!("server key")
            };
            let iss = seq_of(&answer);
            let keys = if handshake_data {
                Keys::Data {
                    sender: client_key,
                    receiver: key,
                    data_level_length: 5,
                    checksum,
                }
            } else {
                Keys::Both {
                    sender: client_key,
                    receiver: key,
                }
            };
            let third = mptcp_bytes(MptcpOption::Capable(Capable { keys, ..capable }));
            net.send(segment(
                from,
                server(22),
                5001,
                iss + 1,
                ACK,
                &third,
                if handshake_data { b"hello" } else { b"" },
            ));
            if !handshake_data {
                let banner = net.recv().await.expect("the banner");
                let mapping = mptcp_bytes(MptcpOption::Dss(Dss {
                    data_ack: None,
                    mapping: Some(Mapping {
                        data_sequence_number: Sequence::Long(mptcp::idsn(client_key).advance(1)),
                        subflow_sequence_number: 1,
                        data_level_length: 5,
                        checksum,
                    }),
                    data_fin: false,
                }));
                net.send(segment(
                    from,
                    server(22),
                    5001,
                    iss + 1 + payload_of(&banner).len() as u32,
                    PSH | ACK,
                    &mapping,
                    b"hello",
                ));
            }
            let reset = net.recv().await.expect("the checksum reset");
            assert_eq!(flags(&reset) & RST, RST);
            assert_eq!(
                mptcp_of(&reset),
                [MptcpOption::TcpRst {
                    transient: false,
                    reason: reason::MPTCP_SPECIFIC
                }]
            );
            Ok(())
        });
    }
}
