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
use fictionet::stdlib::network::ip;
use fictionet::stdlib::protocols::ssh;
use serde_json::{Value, json};

use crate::Result;

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
}

pub fn run(directory: &Path, selection: Selection) -> Result {
    if !fs::read_to_string("/sys/class/dmi/id/sys_vendor")?.contains("QEMU")
        || !Path::new("/run/fictionet-comparison-guest").is_file()
    {
        return Err("comparison probes require the marked QEMU guest".into());
    }
    fs::create_dir_all(directory)?;
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
                        observation(http_idle_probe(target)),
                    )
                })
            })
            .collect();
        if selection == Selection::All {
            for target in &TARGETS {
                save(directory, target, "raw", observation(raw_probes(target)))?;
                save(directory, target, "http", observation(http_probe(target)))?;
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
    let received = receive_packets(target, &receiver, &expected)?;
    Ok(
        json!({"probe":name, "request":decode(&request), "replies":received.matched, "unrelated":received.unrelated, "observation_ms":750}),
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
    let start = Instant::now();
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
    let body = &bytes[header..];
    if bytes[9] == 6 && body.len() >= 20 {
        let tcp_header = usize::from(body[12] >> 4) * 4;
        record["tcp"] = json!({
            "source_port":u16::from_be_bytes([body[0],body[1]]),
            "destination_port":u16::from_be_bytes([body[2],body[3]]),
            "sequence":u32::from_be_bytes(body[4..8].try_into().unwrap()),
            "acknowledgment":u32::from_be_bytes(body[8..12].try_into().unwrap()),
            "flags":body[13], "window":u16::from_be_bytes([body[14],body[15]]),
            "options_hex":hex(body.get(20..tcp_header).unwrap_or_default()),
            "options":tcp_options(body.get(20..tcp_header).unwrap_or_default()),
        });
    } else if bytes[9] == 1 && body.len() >= 2 {
        record["icmp"] = json!({"type":body[0], "code":body[1]});
    }
    record
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
    let mut stream = BufReader::new(connect(target, 80)?);
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

fn http_idle_probe(target: &Target) -> Result<Value> {
    let mut stream = BufReader::new(connect(target, 80)?);
    let request = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", target.address);
    let response = http_response(&mut stream, &request)?;
    let start = Instant::now();
    let deadline = start + Duration::from_secs(85);
    let mut extra = Vec::new();
    let mut error = None;
    let status = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break "deadline";
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
        "observation_ms": 85000, "elapsed_ms": start.elapsed().as_millis(),
        "read_status": status, "closed": match status { "eof" => Some(true), "deadline" => Some(false), _ => None }, "error": error,
        "extra_hex": hex(&extra),
    }))
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
