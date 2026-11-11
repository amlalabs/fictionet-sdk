//! Real kernel clients and deployed VFIO honeypot in two isolated QEMU guests.

use crate::{
    Result,
    rawnic::{entry, executable, node, output},
};
use fictionet::stdlib::{
    codec::{Wire, le32},
    network::{ethernet::frame, ip, tcp},
    protocols::mptcp::{self, Capable, Keys, MptcpOption},
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Guest(Child);
impl Drop for Guest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn archive(directory: &Path, target: &Path, attacker: bool) -> Result<PathBuf> {
    let role = if attacker { "attacker" } else { "sensor" };
    let mut bytes = Vec::new();
    for dir in [
        "dev", "proc", "sys", "lib", "lib64", "usr", "usr/lib", "modules", "share", "etc",
    ] {
        entry(&mut bytes, dir, 0o40755, &[]);
    }
    entry(&mut bytes, "tmp", 0o41777, &[]);
    node(&mut bytes, "dev/console", 0o020600, &[], (5, 1));
    executable(
        &mut bytes,
        &target.join("debug/honeypot-vm-guest"),
        "init",
        directory,
    )?;
    if attacker {
        for name in ["ssh", "ssh-keygen"] {
            executable(
                &mut bytes,
                &Path::new("/usr/bin").join(name),
                name,
                directory,
            )?;
        }
    } else {
        executable(
            &mut bytes,
            &target.join("debug/honeypot"),
            "honeypot",
            directory,
        )?;
    }
    let mut modules = Vec::new();
    let mut names = vec!["9p", "9pnet_virtio"];
    names.extend(if attacker {
        vec!["virtio_net"]
    } else {
        vec!["vfio-pci", "vfio_iommu_type1"]
    });
    for name in names {
        // Listing dependencies reads host module files; loading happens only in guest init.
        for line in String::from_utf8(output(
            Command::new("modprobe").args(["--show-depends", name]),
        )?)?
        .lines()
        {
            if line.starts_with("builtin ") {
                continue;
            }
            let path = line
                .strip_prefix("insmod ")
                .and_then(|line| line.split_whitespace().next())
                .ok_or("unexpected module dependency")?
                .to_owned();
            if !modules.contains(&path) {
                modules.push(path);
            }
        }
    }
    for (index, path) in modules.iter().enumerate() {
        let module = if path.ends_with(".zst") {
            output(Command::new("zstd").args(["-dc", path]))?
        } else {
            fs::read(path)?
        };
        entry(&mut bytes, &format!("modules/{index}"), 0o100644, &module);
    }
    entry(&mut bytes, "TRAILER!!!", 0, &[]);
    let path = directory.join(format!("{role}.cpio"));
    fs::write(&path, bytes)?;
    Ok(path)
}

fn start(directory: &Path, initrd: &Path, attacker: bool) -> Result<Guest> {
    let role = if attacker { "attacker" } else { "sensor" };
    let mut command = Command::new("qemu-system-x86_64");
    command.current_dir(directory).args([
        "-machine", "q35,accel=tcg", "-cpu", "max", "-m", "2G", "-smp", "2",
        "-display", "none", "-nodefaults", "-no-reboot", "-monitor", "none", "-serial",
    ]).arg(format!("file:{role}-serial.log"))
        .args(["-smbios", "type=1,manufacturer=QEMU", "-kernel", "/boot/vmlinuz-linux", "-initrd"])
        .arg(initrd).arg("-append")
        .arg(format!("console=ttyS0 panic=-1 intel_iommu=on iommu.strict=1 fictionet.rawnic=1 fictionet.honeypot={role} net.ifnames=0 rdinit=/init"))
        .args(["-device", "intel-iommu,intremap=on,caching-mode=on", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-netdev"])
        .arg(format!("stream,id=data,server={},addr.type=unix,addr.path=link.sock", if attacker { "off" } else { "on" }))
        .arg("-device")
        .arg(format!("virtio-net-pci,netdev=data,disable-legacy=on,iommu_platform=on,addr=03.0,mac=52:54:00:12:34:{},csum=off,gso=off,guest_csum=off,guest_tso4=off,guest_tso6=off,guest_ecn=off,guest_ufo=off,host_tso4=off,host_tso6=off,host_ecn=off,host_ufo=off", if attacker { "57" } else { "56" }))
        .args(["-nic", "none", "-fsdev"])
        .arg(format!("local,id=artifacts,path={role},security_model=mapped-xattr"))
        .args(["-device", "virtio-9p-pci,fsdev=artifacts,mount_tag=artifacts,addr=04.0"]);
    fs::write(
        directory.join(format!("{role}-qemu.txt")),
        format!("{command:?}\n"),
    )?;
    Ok(Guest(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(
                directory.join(format!("{role}-qemu.log")),
            )?)
            .spawn()?,
    ))
}

fn wait_until(
    guest: &mut Guest,
    deadline: Instant,
    mut ready: impl FnMut() -> Result<bool>,
) -> Result {
    loop {
        if ready()? {
            return Ok(());
        }
        if let Some(status) = guest.0.try_wait()? {
            return Err(format!("guest exited early: {status}").into());
        }
        if Instant::now() >= deadline {
            return Err("guest readiness deadline expired".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_exit(guest: &mut Guest, deadline: Instant) -> Result {
    loop {
        if let Some(status) = guest.0.try_wait()? {
            return if status.code() == Some(85) {
                Ok(())
            } else {
                Err(format!("guest failed: {status}; inspect serial and honeypot logs").into())
            };
        }
        if Instant::now() >= deadline {
            return Err("guest completion deadline expired".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct Packet {
    file: String,
    offset: usize,
    bytes: Vec<u8>,
}

fn packets(directory: &Path, prefix: &str, link: u16) -> Result<Vec<Packet>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file = entry.file_name().to_string_lossy().into_owned();
        if !file.starts_with(prefix) || !file.ends_with(".pcapng") {
            continue;
        }
        let bytes = fs::read(entry.path())?;
        let mut offset = 0;
        let mut interface = false;
        while offset < bytes.len() {
            let block = &bytes[offset..];
            let length = le32(block, 4).ok_or("truncated pcapng block")? as usize;
            if length < 12
                || !length.is_multiple_of(4)
                || length > block.len()
                || le32(block, length - 4) != Some(length as u32)
            {
                return Err("invalid pcapng block length".into());
            }
            let block = &block[..length];
            match le32(block, 0).ok_or("missing pcapng type")? {
                0x0a0d0d0a => {
                    if offset != 0 || le32(block, 8) != Some(0x1a2b3c4d) {
                        return Err("invalid pcapng section".into());
                    }
                }
                1 => {
                    if interface || block.get(8..10) != Some(link.to_le_bytes().as_slice()) {
                        return Err("unexpected pcapng link type or interface".into());
                    }
                    interface = true;
                }
                6 => {
                    let count = le32(block, 20).ok_or("missing pcapng captured length")? as usize;
                    if !interface
                        || le32(block, 8) != Some(0)
                        || le32(block, 24) != Some(count as u32)
                        || 28 + count.div_ceil(4) * 4 + 4 > length
                    {
                        return Err("invalid pcapng packet".into());
                    }
                    result.push(Packet {
                        file: file.clone(),
                        offset,
                        bytes: block[28..28 + count].to_vec(),
                    });
                }
                _ => return Err("unexpected pcapng block".into()),
            }
            offset += length;
        }
    }
    if result.is_empty() {
        return Err(format!("no {prefix} capture packets").into());
    }
    Ok(result)
}

struct Segment {
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    ack: u32,
    flags: u8,
    options: Vec<MptcpOption>,
    payload: Vec<u8>,
}

fn segment(packet: &[u8]) -> Result<Option<Segment>> {
    let header = ip::Header::parse_whole(packet).ok_or("invalid captured IP packet")?;
    if header.protocol != 6 {
        return Ok(None);
    }
    let bytes = header.payload(packet);
    if bytes.len() < 20 || ip::transport_checksum(header.src, header.dst, 6, bytes) != 0 {
        return Err("invalid captured TCP checksum or length".into());
    }
    let mut options = Vec::new();
    for option in tcp::options(bytes)? {
        if let tcp::TcpOption::Unknown { kind: 30, data } = option {
            options.push(MptcpOption::parse(&data)?);
        }
    }
    let start = usize::from(bytes[12] >> 4) * 4;
    if start < 20 || start > bytes.len() {
        return Err("invalid TCP header length".into());
    }
    Ok(Some(Segment {
        source: SocketAddr::new(header.src, u16::from_be_bytes(bytes[..2].try_into()?)),
        destination: SocketAddr::new(header.dst, u16::from_be_bytes(bytes[2..4].try_into()?)),
        sequence: u32::from_be_bytes(bytes[4..8].try_into()?),
        ack: u32::from_be_bytes(bytes[8..12].try_into()?),
        flags: bytes[13],
        options,
        payload: bytes[start..].to_vec(),
    }))
}

fn reference<'a>(event: &Value, packets: &'a [Packet]) -> Result<&'a Packet> {
    let reference = &event["capture"];
    if reference["available"] != true || reference["section"] != 0 || reference["interface"] != 0 {
        return Err("event has no persisted capture reference".into());
    }
    packets
        .iter()
        .find(|packet| {
            reference["file"] == packet.file
                && reference["offset"].as_u64() == Some(packet.offset as u64)
        })
        .ok_or_else(|| "capture reference does not resolve to a packet".into())
}

fn verify(directory: &Path) -> Result {
    let state = directory.join("sensor/state");
    let ethernet = packets(&state, "ethernet-", 1)?;
    let ip_packets = packets(&state, "ip-", 101)?;
    let ethernet_ip: Vec<_> = ethernet
        .iter()
        .filter_map(|packet| {
            let frame = frame::Frame::parse(&packet.bytes)?;
            if frame.ethertype != frame::IPV4 && frame.ethertype != frame::IPV6 {
                return None;
            }
            let header = ip::Header::parse_whole(frame.payload)?;
            frame.payload.get(..header.length)
        })
        .collect();
    let mut segments = Vec::new();
    for packet in &ip_packets {
        if !ethernet_ip.contains(&packet.bytes.as_slice()) {
            return Err("derived IP capture has no original Ethernet frame".into());
        }
        if let Some(segment) = segment(&packet.bytes)? {
            segments.push(segment);
        }
    }
    let probes: Value = serde_json::from_slice(&fs::read(directory.join("attacker/probes.json"))?)?;
    let client: SocketAddr = probes["mptcp"]["source"]
        .as_str()
        .ok_or("missing kernel source")?
        .parse()?;
    let server: SocketAddr = "192.0.2.2:80".parse()?;
    if client.ip().to_string() != "192.0.2.1"
        || probes["mptcp"]["protocol"] != 262
        || probes["mptcp"]["flags"]
            .as_u64()
            .is_none_or(|flags| flags & 3 != 2)
    {
        return Err("kernel MPTCP report does not establish negotiated MPTCP".into());
    }
    let syn = segments
        .iter()
        .find(|s| {
            s.source == client
                && s.destination == server
                && s.flags == 2
                && s.options.iter().any(|o| {
                    matches!(
                        o,
                        MptcpOption::Capable(Capable {
                            version: 1,
                            keys: Keys::Absent,
                            ..
                        })
                    )
                })
        })
        .ok_or("no kernel MP_CAPABLE SYN in capture")?;
    let answer = segments
        .iter()
        .find(|s| {
            s.source == server
                && s.destination == client
                && s.flags == 0x12
                && s.ack == syn.sequence.wrapping_add(1)
        })
        .ok_or("no matching SYN ACK in capture")?;
    let server_key = answer
        .options
        .iter()
        .find_map(|o| match o {
            MptcpOption::Capable(Capable {
                version: 1,
                keys: Keys::Sender(key),
                ..
            }) => Some(*key),
            _ => None,
        })
        .ok_or("SYN ACK has no MPTCP server key")?;
    let third = segments.iter().find(|s| s.source == client && s.destination == server && s.flags & 0x12 == 0x10
        && s.sequence == syn.sequence.wrapping_add(1) && s.ack == answer.sequence.wrapping_add(1)
        && s.options.iter().any(|o| matches!(o, MptcpOption::Capable(Capable { keys: Keys::Both { receiver, .. }, .. }) if *receiver == server_key)))
        .ok_or("no matching third ACK with both MPTCP keys")?;
    let client_key = third
        .options
        .iter()
        .find_map(|o| match o {
            MptcpOption::Capable(Capable {
                keys: Keys::Both { sender, .. },
                ..
            }) => Some(*sender),
            _ => None,
        })
        .ok_or("third ACK missing client key")?;
    if probes["mptcp"]["local_token"] != format!("{:08x}", mptcp::token(client_key)) {
        return Err("captured client key does not match independent kernel MPTCP token".into());
    }
    let request = b"GET / HTTP/1.1\r\nHost: 192.0.2.2\r\nConnection: close\r\n\r\n";
    if !segments
        .iter()
        .any(|s| s.source == client && s.destination == server && s.payload == request)
    {
        return Err("no complete kernel HTTP request in capture".into());
    }
    let response = fs::read(directory.join("attacker/http.response"))?;
    let mut captured = BTreeMap::new();
    for s in segments
        .iter()
        .filter(|s| s.source == server && s.destination == client && !s.payload.is_empty())
    {
        if !s.options.iter().any(|o| matches!(o, MptcpOption::Dss(dss) if dss.mapping.is_some() && dss.data_ack.is_some())) {
            return Err("server HTTP data missing DSS mapping or acknowledgement".into());
        }
        for (index, byte) in s.payload.iter().enumerate() {
            let offset = s.sequence.wrapping_sub(answer.sequence.wrapping_add(1)) as usize + index;
            if let Some(previous) = captured.insert(offset, *byte)
                && previous != *byte
            {
                return Err("conflicting HTTP bytes in retransmission".into());
            }
        }
    }
    if captured.len() != response.len()
        || response
            .iter()
            .enumerate()
            .any(|(index, byte)| captured.get(&index) != Some(byte))
    {
        return Err("captured HTTP response differs from complete kernel response".into());
    }
    let zero = segments
        .iter()
        .find(|s| {
            s.source.ip() == client.ip()
                && s.destination == "192.0.2.2:0".parse::<SocketAddr>().unwrap()
                && s.flags == 2
        })
        .ok_or("no literal destination zero SYN")?;
    if !segments.iter().any(|s| {
        s.source == zero.destination
            && s.destination == zero.source
            && s.flags & 0x14 == 0x14
            && s.ack == zero.sequence.wrapping_add(1)
    }) {
        return Err("no matching closed port zero reset".into());
    }
    let mut events = Vec::new();
    for entry in fs::read_dir(&state)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("events-") {
            let bytes = fs::read_to_string(entry.path())?;
            if !bytes.ends_with('\n') {
                return Err("incomplete event file".into());
            }
            for line in bytes.lines() {
                events.push(serde_json::from_str::<Value>(line)?);
            }
        }
    }
    events.sort_by_key(|e| e["sequence"].as_u64());
    let first = events.first().ok_or("no persisted events")?;
    for (index, envelope) in events.iter().enumerate() {
        if envelope["schema_version"] != 1
            || envelope["sequence"].as_u64() != Some(index as u64 + 1)
            || envelope["sensor_id"] != first["sensor_id"]
            || envelope["run_id"] != first["run_id"]
            || envelope["backend"] != "vfio"
            || envelope["capture_boundary"] != "ethernet_and_derived_ip"
        {
            return Err("invalid event provenance or sequence".into());
        }
        for name in [
            "dropped_events",
            "dropped_captures",
            "write_failures",
            "sync_failures",
        ] {
            if envelope["evidence_health"][name] != 0 {
                return Err(format!("evidence loss: {name}").into());
            }
        }
        if envelope["event"]["event"] == "ethernet_capture" {
            reference(&envelope["event"], &ethernet)?;
            for name in ["lost", "rx_queue_dropped", "tx_queue_dropped"] {
                if envelope["event"][name] != 0 {
                    return Err(format!("raw capture loss: {name}").into());
                }
            }
        }
    }
    let find = |kind: &str, predicate: &dyn Fn(&Value) -> bool| -> Result<&Value> {
        events
            .iter()
            .map(|e| &e["event"])
            .find(|e| e["event"] == kind && predicate(e))
            .ok_or_else(|| format!("missing semantic {kind} event").into())
    };
    let client_text = client.to_string();
    if probes["private_hosts"]["http_status"] != 200 || probes["private_hosts"]["tls_status"] != 200
    {
        return Err("private HTTP and TLS traversal missing".into());
    }
    find("network", &|e| {
        e["fact"]["kind"] == "dns"
            && e["fact"]["name"] == "change.northbank.internal."
            && e["fact"]["tcp"] == false
    })?;
    find("network", &|e| {
        e["fact"]["kind"] == "tls_client_hello" && e["dst"] == "10.44.0.12:443"
    })?;
    let traps: Vec<_> = events
        .iter()
        .map(|e| &e["event"])
        .filter(|e| e["event"] == "trap")
        .collect();
    let count = |kind: &str, accepted: bool| {
        traps
            .iter()
            .filter(|e| e["trap"]["kind"] == kind && e["trap"]["accepted"] == accepted)
            .count()
    };
    if probes["reviews"]["mcp_completions"] != 3
        || probes["reviews"]["a2a_sections"] != 4
        || count("prose", true) != 7
        || count("prose", false) != 5
        || count("declaration", false) == 0
    {
        return Err("trap review evidence does not match scripted approvals and refusals".into());
    }
    for payout in ["deploy_bundle", "change_review", "fleet_bundle"] {
        find("trap", &|e| {
            e["trap"]["kind"] == "payout" && e["trap"]["payout"] == payout
        })?;
    }
    for shape in ["url_password", "two_part", "three_part"] {
        find("trap", &|e| {
            e["trap"]["kind"] == "credential"
                && e["trap"]["shape"] == shape
                && e["trap"]["form"] == "whole"
        })?;
    }
    find("trap", &|e| {
        e["trap"]["kind"] == "credential" && e["trap"]["form"] == "ascii_ellipsis"
    })?;
    for probe in ["hold", "trickle"] {
        find("trap", &|e| {
            e["trap"]["kind"] == "probe"
                && e["trap"]["probe"] == probe
                && e["trap"]["end"] == "answered"
                && e["trap"]["elapsed_ms"]
                    .as_u64()
                    .is_some_and(|ms| ms >= 150000)
        })?;
    }
    find("trap", &|e| {
        e["trap"]["kind"] == "probe"
            && e["trap"]["probe"] == "hold"
            && e["trap"]["end"] == "peer_closed"
            && e["trap"]["elapsed_ms"]
                .as_u64()
                .is_some_and(|ms| ms < 150000)
    })?;
    if traps
        .iter()
        .filter(|e| {
            e["trap"]["kind"] == "probe"
                && e["trap"]["probe"] == "host_check"
                && e["trap"]["end"] == "answered"
        })
        .count()
        != 4
    {
        return Err("missing completed concurrent host checks".into());
    }
    find("trap", &|e| {
        e["trap"]["kind"] == "request" && e["trap"]["active"].as_u64().is_some_and(|n| n >= 4)
    })?;
    let has_key = |e: &Value, sender: u64, receiver: Option<u64>| {
        e["mptcp"].as_array().is_some_and(|options| {
            options.iter().any(|o| {
                o["subtype"] == "mp_capable"
                    && o["sender_key"] == format!("{sender:016x}")
                    && receiver.is_none_or(|key| o["receiver_key"] == format!("{key:016x}"))
            })
        })
    };
    let offered = find("syn", &|e| {
        e["src"] == client_text
            && e["dst"] == server.to_string()
            && e["seq"].as_u64() == Some(syn.sequence.into())
            && e["mptcp"].as_array().is_some_and(|a| {
                a.iter()
                    .any(|o| o["subtype"] == "mp_capable" && o["version"] == 1)
            })
    })?;
    let answered = find("answer", &|e| {
        e["dst"] == client_text && has_key(e, server_key, None)
    })?;
    let acknowledged = find("segment", &|e| {
        e["src"] == client_text
            && e["dst"] == server.to_string()
            && has_key(e, client_key, Some(server_key))
    })?;
    let port_zero = find("port_zero", &|e| {
        e["src"] == zero.source.to_string()
            && e["dst"] == zero.destination.to_string()
            && e["protocol"] == 6
            && e["checksum_valid"] == true
    })?;
    let zero_capture = reference(port_zero, &ip_packets)?;
    let referenced = segment(&zero_capture.bytes)?.ok_or("port zero capture is not TCP")?;
    if referenced.source != zero.source
        || referenced.destination != zero.destination
        || referenced.sequence != zero.sequence
    {
        return Err("port zero event references the wrong packet".into());
    }
    let authenticated = find("ssh", &|e| {
        e["ssh"]["event"] == "authenticated"
            && e["ssh"]["method"] == "publickey"
            && e["ssh"]["peer"]
                .as_str()
                .is_some_and(|s| s.starts_with("192.0.2.1:"))
    })?;
    let connection = &authenticated["ssh"]["connection"];
    let ssh_peer: SocketAddr = authenticated["ssh"]["peer"]
        .as_str()
        .ok_or("SSH has no peer tuple")?
        .parse()?;
    if !segments.iter().any(|s| {
        s.source == ssh_peer
            && s.destination.to_string() == "192.0.2.2:22"
            && s.flags == 2
            && s.options.is_empty()
    }) {
        return Err("authenticated SSH session has no plain TCP SYN".into());
    }
    let input_bytes: u64 = events
        .iter()
        .map(|e| &e["event"]["ssh"])
        .filter(|e| e["connection"] == *connection && e["event"] == "input")
        .filter_map(|e| e["data_bytes"].as_u64())
        .sum();
    if input_bytes == 0
        || probes["ssh"]["sent_input_bytes"] != input_bytes
        || probes["ssh"]["exit_code"] != 255
    {
        return Err("SSH input evidence differs from the client command".into());
    }
    let ended = find("ssh", &|e| {
        e["ssh"]["connection"] == *connection
            && e["ssh"]["event"] == "end"
            && e["ssh"]["reason"] == "closed"
    })?;
    find("shutdown", &|e| e["status"] == "stopped")?;
    let log = fs::read_to_string(directory.join("sensor/honeypot.log"))?;
    let shutdown = log
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|e| e["event"] == "evidence_shutdown")
        .ok_or("missing drain result")?;
    if !shutdown["error"].is_null() {
        return Err("evidence drain failed".into());
    }
    for name in [
        "queued_bytes",
        "queued_records",
        "dropped_events",
        "dropped_captures",
        "write_failures",
        "sync_failures",
        "state_limits",
    ] {
        if shutdown["metrics"][name] != 0 {
            return Err(format!("unclean final evidence metrics: {name}").into());
        }
    }
    if shutdown["metrics"]["written_events"].as_u64() != Some(events.len() as u64) {
        return Err("exported event count differs from writer result".into());
    }
    println!(
        "Verified kernel MPTCP token {:08x}, client key {client_key:016x}, server key {server_key:016x}, {} HTTP bytes",
        mptcp::token(client_key),
        response.len()
    );
    println!(
        "Verified {} events, {} original Ethernet frames and {} derived IP packets",
        events.len(),
        ethernet.len(),
        ip_packets.len()
    );
    for event in [
        offered,
        answered,
        acknowledged,
        authenticated,
        ended,
        port_zero,
    ] {
        println!("{event}");
    }
    println!("Evidence drain: {shutdown}");
    Ok(())
}

pub fn run(directory: PathBuf) -> Result {
    fs::create_dir_all(&directory)?;
    let directory = fs::canonicalize(directory)?;
    if fs::read_dir(&directory)?.next().is_some() {
        return Err("use an empty artifact directory to exclude stale evidence".into());
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    for role in ["sensor", "attacker"] {
        fs::create_dir(directory.join(role))?;
    }
    println!(
        "Building guest executables; artifacts: {}",
        directory.display()
    );
    output(Command::new("cargo").args([
        "build",
        "-p",
        "xtask",
        "--features",
        "host-tools",
        "--bin",
        "honeypot-vm-guest",
    ]))?;
    output(Command::new("cargo").args(["build", "-p", "honeypot-world", "--bin", "honeypot"]))?;
    let metadata: Value = serde_json::from_slice(&output(Command::new("cargo").args([
        "metadata",
        "--no-deps",
        "--format-version",
        "1",
    ]))?)?;
    let target = PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .ok_or("missing cargo target directory")?,
    );
    let sensor_archive = archive(&directory, &target, false)?;
    let attacker_archive = archive(&directory, &target, true)?;
    let mut sensor = start(&directory, &sensor_archive, false)?;
    // The fleet protocol includes a silent response held for 150 seconds.
    let deadline = Instant::now() + Duration::from_secs(420);
    wait_until(&mut sensor, deadline, || {
        Ok(directory.join("link.sock").exists())
    })?;
    let mut attacker = start(&directory, &attacker_archive, true)?;
    wait_until(&mut sensor, deadline, || {
        let log = match fs::read_to_string(directory.join("sensor/honeypot.log")) {
            Ok(log) => log,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        Ok(log
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .any(|e| e["event"] == "local_ready" && e["backend"] == "vfio"))
    })?;
    fs::write(directory.join("attacker/start"), [])?;
    wait_exit(&mut attacker, deadline)?;
    fs::write(directory.join("sensor/stop"), [])?;
    wait_exit(&mut sensor, deadline)?;
    verify(&directory)?;
    println!(
        "Two guest honeypot validation passed. Artifacts: {}",
        directory.display()
    );
    Ok(())
}
