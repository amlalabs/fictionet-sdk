//! Packet and service observations inside the isolated comparison guest.

use std::ffi::CString;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::ethernet::frame::{self, Frame};
use fictionet::stdlib::network::ip;
use fictionet::stdlib::protocols::{arp, ssh};
use serde_json::{Value, json};

use crate::{Result, honeypot_diff::Profile};

struct Target {
    name: &'static str,
    source: Ipv4Addr,
    address: Ipv4Addr,
}

const TARGETS: [Target; 2] = [
    Target {
        name: "reference",
        source: Ipv4Addr::new(192, 0, 2, 1),
        address: Ipv4Addr::new(192, 0, 2, 10),
    },
    Target {
        name: "imitation",
        source: Ipv4Addr::new(198, 51, 100, 1),
        address: Ipv4Addr::new(198, 51, 100, 10),
    },
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    All,
    Defaults,
    IpOptions,
}

pub fn run(directory: &Path, selection: Selection, profile: Profile) -> Result {
    if !fs::read_to_string("/sys/class/dmi/id/sys_vendor")?.contains("QEMU")
        || !Path::new("/run/fictionet-comparison-guest").is_file()
    {
        return Err("comparison probes require the marked QEMU guest".into());
    }
    fs::create_dir_all(directory)?;
    if selection != Selection::Defaults {
        for target in &TARGETS {
            save(
                directory,
                target,
                "ip-options",
                observation(ip_options_probe(target)),
            )?;
        }
    }
    if selection == Selection::IpOptions {
        return Ok(());
    }
    // Write proposals first so the reference service's actual configuration
    // is available while the slower packet and OS probes run.
    if selection == Selection::All {
        for target in &TARGETS {
            save(directory, target, "ssh", observation(ssh_probe(target)))?;
            save(
                directory,
                target,
                "ssh-client",
                observation(ssh_client_probe(directory, target)),
            )?;
        }
    }
    std::thread::scope(|scope| -> Result {
        let idle: Vec<_> = TARGETS
            .iter()
            .map(|target| {
                scope.spawn(move || {
                    save(
                        directory,
                        target,
                        "http-idle",
                        observation(http_idle_probe(
                            directory,
                            target,
                            profile.idle_observation(),
                        )),
                    )
                })
            })
            .collect();
        if selection == Selection::All {
            for target in &TARGETS {
                save(directory, target, "raw", observation(raw_probes(target)))?;
                save(directory, target, "http", observation(http_probe(target)))?;
                save(
                    directory,
                    target,
                    "http-mptcp",
                    observation(http_mptcp_probe(target)),
                )?;
                let scan = Command::new("nmap")
                    .args([
                        "-O",
                        "-d",
                        "--packet-trace",
                        "-sS",
                        "-Pn",
                        "-n",
                        "-p22,80,81",
                        "--max-os-tries",
                        "1",
                        "--host-timeout",
                        "60s",
                        "-e",
                        target.name,
                    ])
                    .arg(target.address.to_string())
                    .output();
                let scan = match scan {
                    Ok(output) => json!({
                        "status": output.status.code(),
                        "stdout": String::from_utf8_lossy(&output.stdout),
                        "stderr": String::from_utf8_lossy(&output.stderr),
                    }),
                    Err(error) => json!({"error": error.to_string()}),
                };
                save(directory, target, "nmap", scan)?;
            }
        }
        for thread in idle {
            thread
                .join()
                .map_err(|_| "HTTP idle probe thread panicked")??;
        }
        Ok(())
    })?;
    Ok(())
}

fn observation(result: Result<Value>) -> Value {
    result.unwrap_or_else(|error| json!({"error": error.to_string()}))
}

fn save(directory: &Path, target: &Target, kind: &str, record: Value) -> Result {
    let bytes = serde_json::to_vec_pretty(&record)?;
    fs::write(
        directory.join(format!("{}-{kind}.json", target.name)),
        &bytes,
    )?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut result, "{byte:02x}").unwrap();
    }
    result
}

fn address(ip: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    }
}

fn raw_socket(target: &Target, protocol: i32) -> Result<OwnedFd> {
    // SAFETY: socket has no borrowed pointers; its owned descriptor is closed by OwnedFd.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: fd is a newly created, uniquely owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let interface = CString::new(target.name)?;
    let local = address(target.source);
    // SAFETY: both pointers refer to initialized values of the specified lengths.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            interface.as_ptr().cast(),
            interface.as_bytes_with_nul().len() as libc::socklen_t,
        )
    } < 0
        || unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&local as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(fd)
}

fn raw_probes(target: &Target) -> Result<Value> {
    let sender = raw_socket(target, libc::IPPROTO_RAW)?;
    let mut observations = Vec::new();
    let standard_options = [
        2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7,
    ];
    let probes = [
        ("ssh_syn", 22, 0x02, standard_options.as_slice()),
        ("http_syn", 80, 0x02, standard_options.as_slice()),
        ("closed_syn", 81, 0x02, standard_options.as_slice()),
        ("ssh_ack", 22, 0x10, &[][..]),
        ("closed_ack", 81, 0x10, &[][..]),
        ("ssh_ecn_syn", 22, 0xc2, standard_options.as_slice()),
        ("ssh_ect_syn", 22, 0xc2, standard_options.as_slice()),
        ("ssh_ce_syn", 22, 0xc2, standard_options.as_slice()),
        ("ssh_mptcp_syn", 22, 0x02, &[30, 4, 0x01, 0x01][..]),
        ("http_mptcp_syn", 80, 0x02, &[30, 4, 0x01, 0x01][..]),
    ];
    for (index, (name, port, flags, options)) in probes.iter().enumerate() {
        let source_port = 41000 + index as u16;
        let mut tcp = vec![0; 20];
        tcp[..2].copy_from_slice(&source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&(*port as u16).to_be_bytes());
        tcp[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        if *flags == 0x10 {
            tcp[8..12].copy_from_slice(&0x87654321u32.to_be_bytes());
        }
        tcp[12] = ((20 + options.len()) / 4) as u8 * 16;
        tcp[13] = *flags;
        tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
        tcp.extend_from_slice(options);
        let checksum = ip::transport_checksum(target.source.into(), target.address.into(), 6, &tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
        observations.push(exchange(target, &sender, name, 6, &tcp)?);
    }
    for (index, (name, payload_length, code)) in [
        ("icmp_echo_32", 32, 0),
        ("icmp_echo_1472", 1472, 0),
        ("icmp_echo_nonzero_code", 32, 9),
    ]
    .into_iter()
    .enumerate()
    {
        let mut echo = vec![0x5a; 8 + payload_length];
        echo[..8].copy_from_slice(&[8, code, 0, 0, 0x12, 0x34, 0, 0]);
        echo[6..8].copy_from_slice(&(index as u16 + 1).to_be_bytes());
        let checksum = ip::checksum(&echo);
        echo[2..4].copy_from_slice(&checksum.to_be_bytes());
        observations.push(exchange(target, &sender, name, 1, &echo)?);
    }
    let mut udp = vec![0; 12];
    udp[..2].copy_from_slice(&42000u16.to_be_bytes());
    udp[2..4].copy_from_slice(&81u16.to_be_bytes());
    udp[4..6].copy_from_slice(&12u16.to_be_bytes());
    udp[8..].copy_from_slice(b"test");
    let checksum = ip::transport_checksum(target.source.into(), target.address.into(), 17, &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    observations.push(exchange(target, &sender, "closed_udp", 17, &udp)?);
    observations.push(observation(challenge_ack(target, &sender)));
    Ok(json!(observations))
}

fn ip_options_probe(target: &Target) -> Result<Value> {
    // This address is deliberately not assigned to the guest kernel: it must
    // not send a reset or complete these pending TCP handshakes.
    let mut source = target.source.octets();
    source[3] = 2;
    let target = &Target {
        name: target.name,
        source: source.into(),
        address: target.address,
    };
    let link = PacketLink::open(target)?;
    let start = Instant::now();
    let request = arp::Packet {
        operation: arp::Operation::Request,
        sender_mac: link.mac,
        sender_ip: target.source,
        target_mac: [0; 6],
        target_ip: target.address,
    };
    let bytes = frame::frame(frame::BROADCAST, link.mac, frame::ARP, &request.encode());
    let mut neighbor = vec![link.send(&bytes, start)?];
    let remote_mac = loop {
        let Some(bytes) = link.receive(start + Duration::from_secs(5))? else {
            return Err("IPv4 options probe could not resolve the target MAC".into());
        };
        neighbor.push(frame_record(&bytes, start, "received"));
        let Some(frame) = Frame::parse(&bytes) else {
            continue;
        };
        if frame.ethertype != frame::ARP {
            continue;
        }
        let Ok(packet) = arp::Packet::receive(frame.payload) else {
            continue;
        };
        if packet.operation == arp::Operation::Reply
            && packet.sender_ip == target.address
            && packet.target_ip == target.source
            && packet.target_mac == link.mac
        {
            break packet.sender_mac;
        }
        link.answer_arp(target, &packet, start, &mut neighbor)?;
    };
    let cases = [
        ("plain", vec![]),
        (
            "record_route",
            vec![ip::Ipv4Option::RecordRoute {
                pointer: 4,
                routes: vec![Ipv4Addr::UNSPECIFIED; 9],
            }],
        ),
        (
            "timestamps",
            vec![ip::Ipv4Option::Timestamp {
                pointer: 5,
                overflow: 0,
                timestamps: ip::Ipv4Timestamp::Timestamps(vec![0; 9]),
            }],
        ),
        (
            "timestamp_addresses",
            vec![ip::Ipv4Option::Timestamp {
                pointer: 5,
                overflow: 0,
                timestamps: ip::Ipv4Timestamp::Addresses(vec![(Ipv4Addr::UNSPECIFIED, 0); 4]),
            }],
        ),
        (
            "timestamp_prespecified",
            vec![ip::Ipv4Option::Timestamp {
                pointer: 5,
                overflow: 0,
                timestamps: ip::Ipv4Timestamp::Prespecified(vec![
                    (target.address, 0),
                    (target.source, 0),
                ]),
            }],
        ),
    ];
    let mut observations = Vec::new();
    for port in [22u16, 80] {
        for (index, (name, options)) in cases.iter().enumerate() {
            let source_port = 43000 + index as u16 + if port == 80 { 10 } else { 0 };
            let mut tcp = vec![0; 20];
            tcp[..2].copy_from_slice(&source_port.to_be_bytes());
            tcp[2..4].copy_from_slice(&port.to_be_bytes());
            tcp[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
            tcp[12] = 0x50;
            tcp[13] = 0x02;
            tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
            let checksum =
                ip::transport_checksum(target.source.into(), target.address.into(), 6, &tcp);
            tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
            let packet = ip::packet_with_ipv4_options(
                target.source,
                target.address,
                6,
                ip::Fields {
                    ttl: 64,
                    id: 0x1234,
                    dont_fragment: true,
                    tos: 0,
                },
                options,
                &tcp,
            )?;
            let bytes = frame::frame(remote_mac, link.mac, frame::IPV4, &packet.0);
            let expected = ExpectedReply::for_request(6, &tcp)?;
            let start = Instant::now();
            let mut requests = Vec::new();
            let mut replies = Vec::new();
            let mut unrelated = Vec::new();
            // Exactly one ordinary retransmission while the SYN is pending.
            // No ACK, payload, reset, close or altered option set is sent.
            for attempt in 0..2 {
                requests.push(link.send(&bytes, start)?);
                let deadline = start + Duration::from_millis(750 * (attempt + 1));
                while let Some(bytes) = link.receive(deadline)? {
                    let record = frame_record(&bytes, start, "received");
                    let Some(frame) = Frame::parse(&bytes) else {
                        unrelated.push(record);
                        continue;
                    };
                    if frame.ethertype == frame::IPV4 && expected.matches(target, frame.payload) {
                        replies.push(record);
                    } else {
                        unrelated.push(record);
                    }
                    if frame.ethertype == frame::ARP
                        && let Ok(packet) = arp::Packet::receive(frame.payload)
                    {
                        link.answer_arp(target, &packet, start, &mut unrelated)?;
                    }
                }
            }
            observations.push(json!({"probe":name, "port":port, "requests":requests,
                "replies":replies, "unrelated":unrelated, "observation_ms":1500}));
        }
    }
    Ok(json!({
        "handshake_completed": false,
        "retransmissions_per_syn": 1,
        "source_address_assigned": false,
        "neighbor_resolution": neighbor,
        "observations": observations,
    }))
}

struct PacketLink {
    fd: OwnedFd,
    mac: frame::Mac,
}

impl PacketLink {
    fn open(target: &Target) -> Result<Self> {
        let interface = CString::new(target.name)?;
        // SAFETY: interface is a terminated name and socket has no borrowed pointers.
        let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: socket returns a newly owned descriptor.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                i32::from(3u16.to_be()),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: fd was just created and is uniquely owned.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let local = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::sa_family_t,
            sll_protocol: 3u16.to_be(),
            sll_ifindex: index as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        // SAFETY: local is initialized and has the stated length.
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&local as *const libc::sockaddr_ll).cast(),
                size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let address = fs::read_to_string(format!("/sys/class/net/{}/address", target.name))?;
        let octets = address
            .trim()
            .split(':')
            .map(|octet| u8::from_str_radix(octet, 16))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mac = octets.try_into().map_err(|_| "invalid probe NIC MAC")?;
        Ok(Self { fd, mac })
    }

    fn send(&self, bytes: &[u8], start: Instant) -> Result<Value> {
        // SAFETY: bytes is readable for the given length; the socket is bound to its NIC.
        let sent =
            unsafe { libc::send(self.fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if sent as usize != bytes.len() {
            return Err("short Ethernet send".into());
        }
        Ok(frame_record(bytes, start, "sent"))
    }

    fn receive(&self, deadline: Instant) -> Result<Option<Vec<u8>>> {
        while Instant::now() < deadline {
            let mut poll = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            // SAFETY: poll points to one initialized descriptor.
            let ready = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().max(1) as i32) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if ready == 0 {
                continue;
            }
            if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err("probe Ethernet socket failed".into());
            }
            if let Some(bytes) = self.try_receive()? {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    fn try_receive(&self) -> Result<Option<Vec<u8>>> {
        loop {
            let mut bytes = vec![0; 65536];
            // SAFETY: bytes is writable for its full declared length.
            let length = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if length < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() == io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                return Err(error.into());
            }
            bytes.truncate(length as usize);
            return Ok(Some(bytes));
        }
    }

    fn answer_arp(
        &self,
        target: &Target,
        packet: &arp::Packet,
        start: Instant,
        records: &mut Vec<Value>,
    ) -> Result {
        if packet.operation == arp::Operation::Request && packet.target_ip == target.source {
            let reply = packet.reply(self.mac);
            records.push(self.send(
                &frame::frame(reply.target_mac, self.mac, frame::ARP, &reply.encode()),
                start,
            )?);
        }
        Ok(())
    }
}

fn frame_record(bytes: &[u8], start: Instant, direction: &str) -> Value {
    let mut record = json!({"after_us":start.elapsed().as_micros(), "direction":direction, "frame_hex":hex(bytes)});
    if let Some(frame) = Frame::parse(bytes) {
        record["source_mac"] = json!(hex(&frame.src));
        record["destination_mac"] = json!(hex(&frame.dst));
        record["ethertype"] = json!(frame.ethertype);
        if let Some(packet) = frame::ip_packet(frame.ethertype, frame.payload) {
            record["packet"] = decode(packet);
        }
        if frame.ethertype == frame::ARP
            && let Ok(packet) = arp::Packet::receive(frame.payload)
        {
            record["arp"] = json!({"operation":packet.operation.code(), "sender_ip":packet.sender_ip, "target_ip":packet.target_ip, "sender_mac":hex(&packet.sender_mac), "target_mac":hex(&packet.target_mac)});
        }
    }
    record
}

fn exchange(
    target: &Target,
    sender: &OwnedFd,
    name: &str,
    protocol: u8,
    payload: &[u8],
) -> Result<Value> {
    let expected = ExpectedReply::for_request(protocol, payload)?;
    let receiver = raw_socket(target, expected.protocol())?;
    let request = ip::packet_with(
        target.source.into(),
        target.address.into(),
        protocol,
        ip::Fields {
            ttl: 64,
            id: 0x1234,
            dont_fragment: true,
            tos: match name {
                "ssh_ect_syn" => 2,
                "ssh_ce_syn" => 3,
                _ => 0,
            },
        },
        payload,
    )
    .0;
    let remote = address(target.address);
    let start = Instant::now();
    // SAFETY: request and remote are valid for the byte lengths passed to sendto.
    let sent = unsafe {
        libc::sendto(
            sender.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            (&remote as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if sent as usize != request.len() {
        return Err("short raw packet send".into());
    }
    let sent_us = start.elapsed().as_micros();
    let received = receive_packets_since(target, &receiver, &expected, start)?;
    Ok(
        json!({"probe":name, "request":decode(&request), "send_completed_us":sent_us, "replies":received.matched, "unrelated":received.unrelated, "observation_ms":750}),
    )
}

enum ExpectedReply {
    Tcp { local_port: u16, remote_port: u16 },
    Echo { identifier: u16, sequence: u16 },
    UdpError { local_port: u16, remote_port: u16 },
}

impl ExpectedReply {
    fn for_request(protocol: u8, body: &[u8]) -> Result<Self> {
        if body.len() < 8 {
            return Err("probe transport header is incomplete".into());
        }
        let local_port = u16::from_be_bytes([body[0], body[1]]);
        let remote_port = u16::from_be_bytes([body[2], body[3]]);
        Ok(match protocol {
            6 => Self::Tcp {
                local_port,
                remote_port,
            },
            1 => Self::Echo {
                identifier: u16::from_be_bytes([body[4], body[5]]),
                sequence: u16::from_be_bytes([body[6], body[7]]),
            },
            17 => Self::UdpError {
                local_port,
                remote_port,
            },
            _ => return Err("unsupported probe transport".into()),
        })
    }

    fn protocol(&self) -> i32 {
        match self {
            Self::Tcp { .. } => libc::IPPROTO_TCP,
            Self::Echo { .. } | Self::UdpError { .. } => libc::IPPROTO_ICMP,
        }
    }

    fn matches(&self, target: &Target, bytes: &[u8]) -> bool {
        let Some(header) = ip::Header::parse(bytes) else {
            return false;
        };
        if header.src != IpAddr::V4(target.address)
            || header.dst != IpAddr::V4(target.source)
            || i32::from(header.protocol) != self.protocol()
            || header
                .fragment
                .is_some_and(|fragment| !fragment.is_atomic())
        {
            return false;
        }
        let body = header.payload(bytes);
        match self {
            Self::Tcp {
                local_port,
                remote_port,
            } => {
                body.len() >= 20
                    && body[..2] == remote_port.to_be_bytes()
                    && body[2..4] == local_port.to_be_bytes()
            }
            Self::Echo {
                identifier,
                sequence,
            } => {
                body.len() >= 8
                    && body[0] == 0
                    && body[4..6] == identifier.to_be_bytes()
                    && body[6..8] == sequence.to_be_bytes()
            }
            Self::UdpError {
                local_port,
                remote_port,
            } => {
                if body.len() < 8 || !matches!(body[0], 3 | 4 | 5 | 11 | 12) {
                    return false;
                }
                let quoted = &body[8..];
                let Some(header) = ip::Header::parse_truncated(quoted) else {
                    return false;
                };
                let udp = header.payload(quoted);
                header.src == IpAddr::V4(target.source)
                    && header.dst == IpAddr::V4(target.address)
                    && header.protocol == 17
                    && header.fragment.is_none_or(|fragment| fragment.is_atomic())
                    && udp.len() >= 8
                    && udp[..2] == local_port.to_be_bytes()
                    && udp[2..4] == remote_port.to_be_bytes()
            }
        }
    }
}

#[derive(Default)]
struct ReceivedPackets {
    matched: Vec<Value>,
    unrelated: Vec<Value>,
}

fn receive_packets(
    target: &Target,
    receiver: &OwnedFd,
    expected: &ExpectedReply,
) -> Result<ReceivedPackets> {
    receive_packets_since(target, receiver, expected, Instant::now())
}

fn receive_packets_since(
    target: &Target,
    receiver: &OwnedFd,
    expected: &ExpectedReply,
    start: Instant,
) -> Result<ReceivedPackets> {
    let deadline = start + Duration::from_millis(750);
    let mut received = ReceivedPackets::default();
    while Instant::now() < deadline && received.matched.len() < 8 {
        let mut poll = libc::pollfd {
            fd: receiver.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        // SAFETY: poll points to one initialized pollfd.
        let ready = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().max(1) as i32) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if ready == 0 {
            break;
        }
        let mut bytes = vec![0; 65536];
        // SAFETY: bytes is writable for its entire declared capacity.
        let length = unsafe {
            libc::recv(
                receiver.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if length < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                continue;
            }
            return Err(error.into());
        }
        bytes.truncate(length as usize);
        let record = json!({"after_us":start.elapsed().as_micros(), "packet":decode(&bytes)});
        if expected.matches(target, &bytes) {
            received.matched.push(record);
        } else {
            received.unrelated.push(record);
        }
    }
    Ok(received)
}

fn challenge_ack(target: &Target, sender: &OwnedFd) -> Result<Value> {
    let receiver = raw_socket(target, libc::IPPROTO_TCP)?;
    let stream = connect(target, 80)?;
    let source_port = stream.local_addr()?.port();
    let handshake = receive_packets(
        target,
        &receiver,
        &ExpectedReply::Tcp {
            local_port: source_port,
            remote_port: 80,
        },
    )?;
    let syn_ack = handshake
        .matched
        .iter()
        .find(|packet| {
            packet["packet"]["tcp"]["flags"]
                .as_u64()
                .is_some_and(|flags| flags & 0x12 == 0x12)
        })
        .ok_or("established probe did not capture its SYN-ACK")?;
    let next = syn_ack["packet"]["tcp"]["acknowledgment"]
        .as_u64()
        .ok_or("SYN-ACK acknowledgment is absent")? as u32;
    let mut tcp = vec![0; 20];
    tcp[..2].copy_from_slice(&source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
    tcp[4..8].copy_from_slice(&next.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x02;
    tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
    let checksum = ip::transport_checksum(target.source.into(), target.address.into(), 6, &tcp);
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
    let mut result = exchange(target, sender, "established_syn", 6, &tcp)?;
    result["handshake_replies"] = json!(handshake.matched);
    result["handshake_unrelated"] = json!(handshake.unrelated);
    result["repeated"] = exchange(target, sender, "established_syn_repeated", 6, &tcp)?;
    drop(stream);
    Ok(result)
}

fn decode(bytes: &[u8]) -> Value {
    let mut record = json!({"hex":hex(bytes), "length":bytes.len()});
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return record;
    }
    let header = usize::from(bytes[0] & 15) * 4;
    if header < 20 || header > bytes.len() {
        return record;
    }
    record["ttl"] = json!(bytes[8]);
    record["tos"] = json!(bytes[1]);
    record["df"] = json!(bytes[6] & 0x40 != 0);
    record["id"] = json!(u16::from_be_bytes([bytes[4], bytes[5]]));
    record["protocol"] = json!(bytes[9]);
    record["source"] = json!(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]));
    record["destination"] = json!(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]));
    record["ip_header_length"] = json!(header);
    record["ip_options_hex"] = json!(hex(&bytes[20..header]));
    record["ip_options"] = json!(
        ip::Ipv4Options::new(&bytes[20..header])
            .map(decode_ip_option)
            .collect::<Vec<_>>()
    );
    let body = &bytes[header..];
    if bytes[9] == 6 && body.len() >= 20 {
        let tcp_header = usize::from(body[12] >> 4) * 4;
        let payload_length = (20..=body.len())
            .contains(&tcp_header)
            .then(|| body.len() - tcp_header);
        record["tcp"] = json!({
            "source_port":u16::from_be_bytes([body[0],body[1]]),
            "destination_port":u16::from_be_bytes([body[2],body[3]]),
            "sequence":u32::from_be_bytes(body[4..8].try_into().unwrap()),
            "acknowledgment":u32::from_be_bytes(body[8..12].try_into().unwrap()),
            "flags":body[13], "window":u16::from_be_bytes([body[14],body[15]]),
            "payload_length": payload_length,
            "options_hex":hex(body.get(20..tcp_header).unwrap_or_default()),
            "options":tcp_options(body.get(20..tcp_header).unwrap_or_default()),
        });
    } else if bytes[9] == 1 && body.len() >= 2 {
        record["icmp"] = json!({"type":body[0], "code":body[1]});
    }
    record
}

fn decode_ip_option(option: ip::Ipv4Option) -> Value {
    use ip::Ipv4Option::*;
    match option {
        EndOfList => json!({"name":"end"}),
        NoOperation => json!({"name":"nop"}),
        RecordRoute { pointer, routes } => {
            json!({"name":"record_route", "pointer":pointer, "routes":routes})
        }
        LooseSourceRoute { pointer, routes } => {
            json!({"name":"loose_source_route", "pointer":pointer, "routes":routes})
        }
        StrictSourceRoute { pointer, routes } => {
            json!({"name":"strict_source_route", "pointer":pointer, "routes":routes})
        }
        Timestamp {
            pointer,
            overflow,
            timestamps,
        } => {
            let (flags, entries) = match timestamps {
                ip::Ipv4Timestamp::Timestamps(values) => (0, json!(values)),
                ip::Ipv4Timestamp::Addresses(values) => (1, json!(values)),
                ip::Ipv4Timestamp::Prespecified(values) => (3, json!(values)),
                ip::Ipv4Timestamp::Unknown { flags, data } => (flags, json!({"hex":hex(&data)})),
            };
            json!({"name":"timestamp", "pointer":pointer, "overflow":overflow, "flags":flags, "entries":entries})
        }
        Security {
            security,
            compartments,
            handling_restrictions,
            transmission_control_code,
        } => {
            json!({"name":"security", "security":security, "compartments":compartments, "handling_restrictions":handling_restrictions, "transmission_control_code":hex(&transmission_control_code)})
        }
        StreamId(value) => json!({"name":"stream_id", "value":value}),
        RouterAlert(value) => json!({"name":"router_alert", "value":value}),
        Unknown { kind, data } => json!({"name":"unknown", "kind":kind, "data_hex":hex(&data)}),
        Malformed { kind, data } => json!({"name":"malformed", "kind":kind, "data_hex":hex(&data)}),
    }
}

fn tcp_options(mut bytes: &[u8]) -> Vec<Value> {
    let mut result = Vec::new();
    while let Some(&kind) = bytes.first() {
        let length = if kind <= 1 {
            1
        } else {
            usize::from(*bytes.get(1).unwrap_or(&0))
        };
        if (kind > 1 && length < 2) || length > bytes.len() {
            result.push(json!({"kind":kind,"malformed_hex":hex(bytes)}));
            break;
        }
        let option = &bytes[..length];
        let mut decoded = json!({"kind":kind,"hex":hex(option)});
        match (kind, length) {
            (0, _) => decoded["name"] = json!("end"),
            (1, _) => decoded["name"] = json!("nop"),
            (2, 4) => {
                decoded["name"] = json!("mss");
                decoded["value"] = json!(u16::from_be_bytes([option[2], option[3]]));
            }
            (3, 3) => {
                decoded["name"] = json!("window_scale");
                decoded["value"] = json!(option[2]);
            }
            (4, 2) => decoded["name"] = json!("sack_permitted"),
            (8, 10) => {
                decoded["name"] = json!("timestamps");
                decoded["value"] = json!(u32::from_be_bytes(option[2..6].try_into().unwrap()));
                decoded["echo"] = json!(u32::from_be_bytes(option[6..10].try_into().unwrap()));
            }
            (30, _) if length >= 3 => {
                decoded["name"] = json!("mptcp");
                decoded["subtype"] = json!(option[2] >> 4);
            }
            _ => {}
        }
        result.push(decoded);
        bytes = &bytes[length..];
        if kind == 0 {
            break;
        }
    }
    result
}

fn connect(target: &Target, port: u16) -> Result<TcpStream> {
    let stream = TcpStream::connect_timeout(
        &SocketAddr::new(target.address.into(), port),
        Duration::from_secs(5),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(stream)
}

fn ssh_probe(target: &Target) -> Result<Value> {
    let mut stream = BufReader::new(connect(target, 22)?);
    let version = b"SSH-2.0-FictionetComparison\r\n";
    stream.get_mut().write_all(version)?;
    let mut banner = Vec::new();
    for _ in 0..20 {
        let mut line = Vec::new();
        stream.by_ref().take(4096).read_until(b'\n', &mut line)?;
        if line.is_empty() || line.last() != Some(&b'\n') {
            return Err("missing SSH version line".into());
        }
        let identification = line.starts_with(b"SSH-");
        banner.extend_from_slice(&line);
        if identification {
            break;
        }
    }
    let mut record = json!({"request_hex":hex(version), "banner":String::from_utf8_lossy(&banner), "banner_hex":hex(&banner)});
    match ssh_kex(&mut stream) {
        Ok(Value::Object(proposal)) => record.as_object_mut().unwrap().extend(proposal),
        Ok(_) => unreachable!(),
        Err(error) => record["error"] = json!(error.to_string()),
    }
    Ok(record)
}

fn ssh_client_probe(directory: &Path, target: &Target) -> Result<Value> {
    let stdout = directory.join(format!("{}-ssh-client.stdout.log", target.name));
    let stderr = directory.join(format!("{}-ssh-client.stderr.log", target.name));
    let mut child = Command::new("ssh")
        .args([
            "-vv",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "IdentityFile=/dev/null",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PreferredAuthentications=none",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ConnectionAttempts=1",
            "-l",
            "fictionet-probe",
            "-b",
        ])
        .arg(target.source.to_string())
        .arg(target.address.to_string())
        .arg("true")
        .stdin(Stdio::null())
        .stdout(fs::File::create(&stdout)?)
        .stderr(fs::File::create(&stderr)?)
        .spawn()?;
    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        }
        if started.elapsed() >= Duration::from_secs(5) {
            child.kill()?;
            break (child.wait()?, true);
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Ok(json!({
        "status": status.code(),
        "observation_limit_reached": timed_out,
        "elapsed_ms": started.elapsed().as_millis(),
        "stdout": fs::read_to_string(stdout)?,
        "stderr": fs::read_to_string(stderr)?,
    }))
}

fn ssh_kex(stream: &mut impl Read) -> Result<Value> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length_value = u32::from_be_bytes(length) as usize;
    if !(12..=ssh::MAX_PACKET).contains(&length_value) {
        return Err("invalid SSH packet length".into());
    }
    let mut bytes = vec![0; 4 + length_value];
    bytes[..4].copy_from_slice(&length);
    stream.read_exact(&mut bytes[4..])?;
    let packet = ssh::Packet::parse(&bytes)?;
    let ssh::Message::KexInit(kex) = ssh::Message::parse(&packet.payload)? else {
        return Err("first SSH message is not KEXINIT".into());
    };
    Ok(json!({
        "kexinit_hex":hex(&bytes),
        "kex_algorithms":kex.kex_algorithms, "server_host_key_algorithms":kex.server_host_key_algorithms,
        "encryption_client_to_server":kex.encryption_client_to_server, "encryption_server_to_client":kex.encryption_server_to_client,
        "mac_client_to_server":kex.mac_client_to_server, "mac_server_to_client":kex.mac_server_to_client,
        "compression_client_to_server":kex.compression_client_to_server, "compression_server_to_client":kex.compression_server_to_client,
        "languages_client_to_server":kex.languages_client_to_server, "languages_server_to_client":kex.languages_server_to_client,
        "first_kex_packet_follows":kex.first_kex_packet_follows, "reserved":kex.reserved,
    }))
}

fn http_probe(target: &Target) -> Result<Value> {
    http_exchanges(target, connect(target, 80)?)
}

fn http_mptcp_probe(target: &Target) -> Result<Value> {
    // Linux exposes MPTCP through protocol 262 and its info through level 284.
    // SAFETY: socket returns a newly owned descriptor without borrowed pointers.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 262) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: the descriptor is newly created and uniquely owned.
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_nonblocking(true)?;
    let mut remote = address(target.address);
    remote.sin_port = 80u16.to_be();
    // SAFETY: remote is an initialized IPv4 socket address of the stated size.
    let connected = unsafe {
        libc::connect(
            fd,
            (&remote as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if connected < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error.into());
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: poll points to one initialized descriptor.
        if unsafe { libc::poll(&mut poll, 1, 5000) } <= 0 {
            return Err("MPTCP connect did not complete within five seconds".into());
        }
        if let Some(error) = stream.take_error()? {
            return Err(error.into());
        }
    }
    stream.set_nonblocking(false)?;
    let info = mptcp_info(&stream)?;
    let mut record = http_exchanges(target, stream)?;
    record["mptcp"] = info;
    Ok(record)
}

fn mptcp_info(stream: &TcpStream) -> Result<Value> {
    let mut bytes = [0u8; 256];
    let mut length = bytes.len() as libc::socklen_t;
    // SAFETY: both output buffers are initialized and writable for the supplied lengths.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            284,
            1,
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if length < 12 {
        return Err("MPTCP info did not include flags".into());
    }
    let flags = u32::from_ne_bytes(bytes[8..12].try_into()?);
    Ok(json!({
        "info_hex": hex(&bytes[..length as usize]), "flags": flags,
        "fallback": flags & 1 != 0, "remote_key_received": flags & 2 != 0,
        "negotiated": flags & 3 == 2,
    }))
}

fn http_exchanges(target: &Target, stream: TcpStream) -> Result<Value> {
    let mut stream = BufReader::new(stream);
    let mut exchanges = Vec::new();
    for path in ["/", "/missing"] {
        let request = format!("GET {path} HTTP/1.1\r\nHost: {}\r\n\r\n", target.address);
        let mut exchange = json!({"request":request, "request_hex":hex(request.as_bytes())});
        match http_response(&mut stream, &request) {
            Ok(response) => {
                exchange["headers"] = response["headers"].clone();
                exchange["response_hex"] = response["response_hex"].clone();
                exchanges.push(exchange);
            }
            Err(error) => {
                exchange["error"] = json!(error.to_string());
                exchanges.push(exchange);
                break;
            }
        }
    }
    Ok(json!({"same_connection":true,"exchanges":exchanges}))
}

fn http_idle_probe(directory: &Path, target: &Target, observation: Duration) -> Result<Value> {
    let link = PacketLink::open(target)?;
    let mut wire_file =
        fs::File::create(directory.join(format!("{}-http-idle-wire.jsonl", target.name)))?;
    let wire_start = Instant::now();
    let mut stream = BufReader::new(connect(target, 80)?);
    let local = stream.get_ref().local_addr()?;
    let remote = stream.get_ref().peer_addr()?;
    let mut wire = Vec::new();
    let request = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", target.address);
    let request_started_after_us = wire_start.elapsed().as_micros();
    let response = http_response(&mut stream, &request)?;
    let start = Instant::now();
    let idle_started_after_us = wire_start.elapsed().as_micros();
    let deadline = start + observation;
    let mut extra = Vec::new();
    let mut error = None;
    let status = loop {
        while let Some(bytes) = link.try_receive()? {
            if let Some(direction) = tcp_frame_direction(&bytes, local, remote) {
                let record = frame_record(&bytes, wire_start, direction);
                serde_json::to_writer(&mut wire_file, &record)?;
                wire_file.write_all(b"\n")?;
                wire.push(record);
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break "deadline";
        }
        let mut polls = [
            libc::pollfd {
                fd: stream.get_ref().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: link.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if stream.buffer().is_empty() {
            // SAFETY: polls contains two initialized descriptors.
            let ready =
                unsafe { libc::poll(polls.as_mut_ptr(), 2, remaining.as_millis().max(1) as i32) };
            if ready < 0 {
                let poll_error = io::Error::last_os_error();
                if poll_error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(poll_error.into());
            }
            if polls[1].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err("idle capture Ethernet socket failed".into());
            }
            // Drain packet events first, including the FIN that also makes
            // the stream readable. The next poll still observes its EOF.
            if polls[1].revents & libc::POLLIN != 0 || polls[0].revents == 0 {
                continue;
            }
        }
        stream.get_ref().set_read_timeout(Some(remaining))?;
        let mut buffer = [0; 4096];
        match stream.read(&mut buffer) {
            Ok(0) => break "eof",
            Ok(length) => {
                extra.extend_from_slice(&buffer[..length]);
                if extra.len() >= 65536 {
                    break "unexpected_data_limit";
                }
            }
            Err(read_error) if read_error.kind() == io::ErrorKind::Interrupted => {}
            Err(read_error)
                if matches!(
                    read_error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                break "deadline";
            }
            Err(read_error) => {
                error = Some(read_error.to_string());
                break "error";
            }
        }
    };
    Ok(json!({
        "request": request, "request_hex": hex(request.as_bytes()), "response": response,
        "observation_ms": observation.as_millis(), "elapsed_ms": start.elapsed().as_millis(),
        "read_status": status, "closed": match status { "eof" => Some(true), "deadline" => Some(false), _ => None }, "error": error,
        "extra_hex": hex(&extra),
        "wire":wire, "idle_started_after_us":idle_started_after_us,
        "request_started_after_us":request_started_after_us,
        "wire_timing":"userspace capture time since TCP connection attempt",
    }))
}

fn tcp_frame_direction(
    bytes: &[u8],
    local: SocketAddr,
    remote: SocketAddr,
) -> Option<&'static str> {
    let frame = Frame::parse(bytes)?;
    let packet = frame::ip_packet(frame.ethertype, frame.payload)?;
    let header = ip::Header::parse(packet)?;
    if header.protocol != 6
        || header
            .fragment
            .is_some_and(|fragment| !fragment.is_atomic())
    {
        return None;
    }
    let body = header.payload(packet);
    if body.len() < 20 {
        return None;
    }
    let source = SocketAddr::new(header.src, u16::from_be_bytes([body[0], body[1]]));
    let destination = SocketAddr::new(header.dst, u16::from_be_bytes([body[2], body[3]]));
    if source == local && destination == remote {
        Some("sent")
    } else if source == remote && destination == local {
        Some("received")
    } else {
        None
    }
}

fn http_response(stream: &mut BufReader<TcpStream>, request: &str) -> Result<Value> {
    stream.get_mut().write_all(request.as_bytes())?;
    let mut headers = Vec::new();
    loop {
        let mut line = Vec::new();
        stream.by_ref().take(8192).read_until(b'\n', &mut line)?;
        if line.is_empty() || line.last() != Some(&b'\n') {
            return Err("connection ended before the next complete HTTP header".into());
        }
        let end = line == b"\r\n";
        headers.extend_from_slice(&line);
        if headers.len() > 65536 {
            return Err("oversized HTTP headers".into());
        }
        if end {
            break;
        }
    }
    let text = String::from_utf8(headers.clone())?;
    let length: usize = text
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("Content-Length")
                .then_some(value.trim())
        })
        .ok_or("HTTP response has no content length")?
        .parse()?;
    if length > 1024 * 1024 {
        return Err("oversized HTTP body".into());
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    let mut response = headers;
    response.extend_from_slice(&body);
    Ok(json!({"headers":text, "response_hex":hex(&response)}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_capture_filters_both_directions_to_one_connection() {
        let local = SocketAddr::new(TARGETS[0].source.into(), 44000);
        let remote = SocketAddr::new(TARGETS[0].address.into(), 80);
        let make_frame = |source: SocketAddr, destination: SocketAddr, protocol| {
            let mut tcp = vec![0; 20];
            tcp[..2].copy_from_slice(&source.port().to_be_bytes());
            tcp[2..4].copy_from_slice(&destination.port().to_be_bytes());
            tcp[12] = 0x50;
            let packet = ip::packet_with(
                source.ip(),
                destination.ip(),
                protocol,
                ip::Fields::default(),
                &tcp,
            );
            frame::frame([1; 6], [2; 6], frame::IPV4, &packet.0)
        };
        assert_eq!(
            tcp_frame_direction(&make_frame(local, remote, 6), local, remote),
            Some("sent")
        );
        assert_eq!(
            tcp_frame_direction(&make_frame(remote, local, 6), local, remote),
            Some("received")
        );
        let other_port = SocketAddr::new(local.ip(), 44001);
        let other_address = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), local.port());
        for other in [other_port, other_address] {
            assert_eq!(
                tcp_frame_direction(&make_frame(other, remote, 6), local, remote),
                None
            );
            assert_eq!(
                tcp_frame_direction(&make_frame(remote, other, 6), local, remote),
                None
            );
        }
        assert_eq!(
            tcp_frame_direction(&make_frame(local, remote, 17), local, remote),
            None
        );
    }

    #[test]
    fn tcp_capture_distinguishes_empty_and_one_byte_keepalives() {
        let mut tcp = vec![0; 32];
        tcp[4..8].copy_from_slice(&12345u32.to_be_bytes());
        tcp[12] = 0x80;
        tcp[13] = 0x10;
        assert_eq!(decode(&reply(6, &tcp))["tcp"]["payload_length"], 0);
        tcp.push(0);
        let record = decode(&reply(6, &tcp));
        assert_eq!(record["tcp"]["payload_length"], 1);
        assert_eq!(record["tcp"]["sequence"], 12345);
        assert_eq!(record["tcp"]["flags"], 16);
        tcp[12] = 0xf0;
        assert!(decode(&reply(6, &tcp))["tcp"]["payload_length"].is_null());
    }

    #[test]
    fn ethernet_capture_removes_padding_and_decodes_ip_timestamps() {
        let mut packet = reply(6, &[0; 20]);
        packet.splice(20..20, [68, 4, 5, 0x20]);
        packet[0] = 0x46;
        packet[2..4].copy_from_slice(&44u16.to_be_bytes());
        ip::set_header_checksum(&mut packet[..24]);
        let bytes = frame::frame([1; 6], [2; 6], frame::IPV4, &packet);
        assert_eq!(bytes.len(), 60);
        let record = frame_record(&bytes, Instant::now(), "received");
        assert_eq!(record["frame_hex"], hex(&bytes));
        assert_eq!(record["packet"]["hex"], hex(&packet));
        assert_eq!(record["packet"]["length"], 44);
        assert_eq!(record["packet"]["ip_options_hex"], "44040520");
        assert_eq!(
            record["packet"]["ip_options"],
            json!([{
                "name":"timestamp", "pointer":5, "overflow":2, "flags":0, "entries":[]
            }])
        );
    }

    #[test]
    fn ip_option_capture_preserves_route_addresses_and_malformed_bytes() {
        let options = [7, 11, 12, 192, 0, 2, 10, 192, 0, 2, 2, 68];
        let decoded = ip::Ipv4Options::new(&options)
            .map(decode_ip_option)
            .collect::<Vec<_>>();
        assert_eq!(
            decoded,
            vec![
                json!({"name":"record_route", "pointer":12, "routes":["192.0.2.10", "192.0.2.2"]}),
                json!({"name":"malformed", "kind":68, "data_hex":""}),
            ]
        );
    }

    fn reply(protocol: u8, body: &[u8]) -> Vec<u8> {
        let target = &TARGETS[0];
        ip::packet_with(
            target.address.into(),
            target.source.into(),
            protocol,
            ip::Fields::default(),
            body,
        )
        .0
    }

    #[test]
    fn echo_correlation_rejects_stale_identity_but_retains_changed_payload() {
        let expected = ExpectedReply::Echo {
            identifier: 0x1234,
            sequence: 2,
        };
        let target = &TARGETS[0];
        let mut body = vec![0, 9, 0, 0, 0x12, 0x34, 0, 2, 7];
        assert!(expected.matches(target, &reply(1, &body)));
        body.extend_from_slice(b"changed payload");
        assert!(expected.matches(target, &reply(1, &body)));
        body[7] = 1;
        assert!(!expected.matches(target, &reply(1, &body)));
        body[7] = 2;
        body[5] = 0x35;
        assert!(!expected.matches(target, &reply(1, &body)));
    }

    #[test]
    fn tcp_correlation_checks_both_ports_and_addresses() {
        let expected = ExpectedReply::Tcp {
            local_port: 41000,
            remote_port: 80,
        };
        let target = &TARGETS[0];
        let mut body = vec![0; 20];
        body[..2].copy_from_slice(&80u16.to_be_bytes());
        body[2..4].copy_from_slice(&41000u16.to_be_bytes());
        assert!(expected.matches(target, &reply(6, &body)));
        body[..2].copy_from_slice(&81u16.to_be_bytes());
        assert!(!expected.matches(target, &reply(6, &body)));
        body[..2].copy_from_slice(&80u16.to_be_bytes());
        body[2..4].copy_from_slice(&41001u16.to_be_bytes());
        assert!(!expected.matches(target, &reply(6, &body)));
        body[2..4].copy_from_slice(&41000u16.to_be_bytes());
        let wrong_address = ip::packet_with(
            target.address.into(),
            Ipv4Addr::new(192, 0, 2, 2).into(),
            6,
            ip::Fields::default(),
            &body,
        );
        assert!(!expected.matches(target, &wrong_address.0));
    }

    #[test]
    fn udp_error_correlation_checks_the_quoted_tuple_even_when_truncated() {
        let expected = ExpectedReply::UdpError {
            local_port: 42000,
            remote_port: 81,
        };
        let target = &TARGETS[0];
        let mut udp = vec![0; 12];
        udp[..2].copy_from_slice(&42000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&81u16.to_be_bytes());
        udp[4..6].copy_from_slice(&12u16.to_be_bytes());
        let quoted = ip::packet_with(
            target.source.into(),
            target.address.into(),
            17,
            ip::Fields::default(),
            &udp,
        );
        let mut body = vec![3, 3, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&quoted.0[..28]);
        assert!(expected.matches(target, &reply(1, &body)));
        body[8 + 20..8 + 22].copy_from_slice(&42001u16.to_be_bytes());
        assert!(!expected.matches(target, &reply(1, &body)));
        body[8 + 20..8 + 22].copy_from_slice(&42000u16.to_be_bytes());
        body[8 + 22..8 + 24].copy_from_slice(&82u16.to_be_bytes());
        assert!(!expected.matches(target, &reply(1, &body)));
        body[8 + 22..8 + 24].copy_from_slice(&81u16.to_be_bytes());
        body[8 + 16..8 + 20].copy_from_slice(&[192, 0, 2, 11]);
        assert!(!expected.matches(target, &reply(1, &body)));
    }
}
