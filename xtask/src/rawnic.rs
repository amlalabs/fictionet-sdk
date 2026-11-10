//! Isolated QEMU transport validation.
use crate::Result;
use std::{
    fs,
    net::{TcpListener, TcpStream},
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

pub(super) fn output(command: &mut Command) -> Result<Vec<u8>> {
    let result = command.output()?;
    if !result.status.success() {
        return Err(format!(
            "command failed: {command:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(result.stdout)
}

pub(super) fn entry(archive: &mut Vec<u8>, name: &str, mode: u32, bytes: &[u8]) {
    node(archive, name, mode, bytes, (0, 0));
}

pub(super) fn node(archive: &mut Vec<u8>, name: &str, mode: u32, bytes: &[u8], device: (u32, u32)) {
    let header = format!(
        "070701{:08x}{mode:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        0,
        0,
        0,
        1,
        0,
        bytes.len(),
        0,
        0,
        device.0,
        device.1,
        name.len() + 1,
        0
    );
    archive.extend(header.as_bytes());
    archive.extend(name.as_bytes());
    archive.push(0);
    while !archive.len().is_multiple_of(4) {
        archive.push(0);
    }
    archive.extend(bytes);
    while !archive.len().is_multiple_of(4) {
        archive.push(0);
    }
}

pub(super) fn executable(
    archive: &mut Vec<u8>,
    source: &Path,
    destination: &str,
    directory: &Path,
) -> Result {
    // Debug sections can exhaust guest memory while the initramfs is unpacked.
    // Keep the original binary for debugging and strip only its guest copy.
    let stripped = directory.join("guest-executable");
    output(
        Command::new("objcopy")
            .arg("--strip-debug")
            .arg(source)
            .arg(&stripped),
    )?;
    entry(archive, destination, 0o100755, &fs::read(&stripped)?);
    fs::remove_file(stripped)?;
    let deps = output(Command::new("ldd").arg(source))?;
    for word in String::from_utf8(deps)?
        .split_whitespace()
        .filter(|word| word.starts_with('/'))
    {
        let path = Path::new(word);
        entry(
            archive,
            word.trim_start_matches('/'),
            0o100755,
            &fs::read(path)?,
        );
    }
    Ok(())
}

#[path = "rawnic_frames.rs"]
mod frames;

#[path = "rawnic_peer.rs"]
mod peer;

use peer::{HONEYPOT_MAC, Peer};

/// The MAC IPv4 clients' frames come from.
const CLIENT_MAC: [u8; 6] = [0x52, 0x54, 0, 0xab, 0xcd, 0xef];

fn receive_tcp(peer: &mut Peer, port: u16) -> Result<Vec<u8>> {
    use fictionet::stdlib::network::{ethernet::frame, ip, tcp};
    peer.next(|bytes| {
        if !(54..=2036).contains(&bytes.len()) {
            return Err("invalid honeypot response length".into());
        }
        let frame = frame::Frame::parse(bytes).ok_or("invalid Ethernet response")?;
        let header = ip::Header::parse_whole(frame.payload).ok_or("invalid IP response")?;
        let segment = header.payload(frame.payload);
        if frame.dst != frames::GATEWAY_MAC
            || frame.src != HONEYPOT_MAC
            || frame.ethertype != frame::IPV4
            || header.src != "192.0.2.2".parse::<std::net::IpAddr>()?
            || header.dst != "192.0.2.1".parse::<std::net::IpAddr>()?
            || header.protocol != 6
            || segment.len() < 20
            || segment[..2] != 80u16.to_be_bytes()
            || ip::transport_checksum(header.src, header.dst, 6, segment) != 0
        {
            return Err("invalid honeypot TCP response".into());
        }
        tcp::options(segment)?;
        Ok((segment[2..4] == port.to_be_bytes()).then(|| segment.to_vec()))
    })
}

fn mapped_http(peer: &mut Peer) -> Result {
    use fictionet::stdlib::codec::{Stream, Wire};
    use fictionet::stdlib::network::{ethernet::frame, ip, tcp};
    use fictionet::stdlib::protocols::http1::{Event, ResponseEvents};
    use fictionet::stdlib::protocols::mptcp::{self, Capable, Dss, Keys, MptcpOption, Sequence};

    let port = 0x5678u16;
    let capable = |keys| {
        MptcpOption::Capable(Capable {
            version: 1,
            checksum_required: false,
            extensibility: false,
            no_new_subflows: false,
            algorithms: mptcp::algorithm::HMAC_SHA256,
            keys,
        })
    };
    let send = |peer: &mut Peer,
                seq: u32,
                ack: u32,
                flags: u8,
                option: MptcpOption,
                echo: u32,
                payload: &[u8]|
     -> Result {
        let option = option.to_bytes()?;
        let mut options = vec![mptcp::KIND, option.len() as u8 + 2];
        options.extend(option);
        options.extend([8, 10]);
        options.extend(1000u32.to_be_bytes());
        options.extend(echo.to_be_bytes());
        options.resize(options.len().div_ceil(4) * 4, 0);
        let mut segment = Vec::from(port.to_be_bytes());
        segment.extend(80u16.to_be_bytes());
        segment.extend(seq.to_be_bytes());
        segment.extend(ack.to_be_bytes());
        segment.extend([((20 + options.len()) / 4) as u8 * 16, flags]);
        segment.extend([0xff, 0xff, 0, 0, 0, 0]);
        segment.extend(options);
        segment.extend(payload);
        let source = "192.0.2.1".parse()?;
        let destination = "192.0.2.2".parse()?;
        let checksum = ip::transport_checksum(source, destination, 6, &segment);
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());
        let packet = ip::packet(source, destination, 6, &segment);
        peer.send(&frame::frame(
            HONEYPOT_MAC,
            CLIENT_MAC,
            frame::IPV4,
            &packet.0,
        ))
    };
    send(peer, 5000, 0, 2, capable(Keys::Absent), 0, &[])?;
    let syn_ack = receive_tcp(peer, port)?;
    if syn_ack[13] != 0x12 || syn_ack[8..12] != 5001u32.to_be_bytes() {
        return Err("invalid MPTCP handshake response".into());
    }
    let options = tcp::options(&syn_ack)?;
    let key = options
        .iter()
        .find_map(|option| match option {
            tcp::TcpOption::Unknown { kind: 30, data } => match MptcpOption::parse(data).ok()? {
                MptcpOption::Capable(Capable {
                    keys: Keys::Sender(key),
                    ..
                }) => Some(key),
                _ => None,
            },
            _ => None,
        })
        .ok_or("MPTCP handshake has no server key")?;
    let timestamp = options
        .iter()
        .find_map(|option| match option {
            tcp::TcpOption::Timestamps { tsval, tsecr: 1000 } => Some(*tsval),
            _ => None,
        })
        .ok_or("SYN-ACK did not negotiate timestamps")?;
    let server_seq = u32::from_be_bytes(syn_ack[4..8].try_into()?).wrapping_add(1);
    let client_key = 0x5555_6666_7777_8888;
    send(
        peer,
        5001,
        server_seq,
        0x10,
        capable(Keys::Both {
            sender: client_key,
            receiver: key,
        }),
        timestamp,
        &[],
    )?;
    let request = b"GET / HTTP/1.1\r\nHost: 192.0.2.2\r\n\r\n";
    send(
        peer,
        5001,
        server_seq,
        0x18,
        capable(Keys::Data {
            sender: client_key,
            receiver: key,
            data_level_length: request.len() as u16,
            checksum: None,
        }),
        timestamp,
        request,
    )?;
    let client_data = mptcp::idsn(client_key).advance(1 + request.len() as u64);
    let mut http = Stream::new(ResponseEvents::new());
    let mut received = 0;
    let mut saw_head = false;
    loop {
        let response = receive_tcp(peer, port)?;
        if response[13] & 6 != 0 {
            return Err("MPTCP HTTP exchange was reset".into());
        }
        let options = tcp::options(&response)?;
        let payload = &response[usize::from(response[12] >> 4) * 4..];
        if payload.is_empty() {
            continue;
        }
        let dss = options
            .iter()
            .find_map(|option| match option {
                tcp::TcpOption::Unknown { kind: 30, data } => {
                    match MptcpOption::parse(data).ok()? {
                        MptcpOption::Dss(dss) => Some(dss),
                        _ => None,
                    }
                }
                _ => None,
            })
            .ok_or("HTTP response has no DSS")?;
        let mapping = dss.mapping.ok_or("HTTP response has no data mapping")?;
        if response[4..8] != server_seq.wrapping_add(received as u32).to_be_bytes()
            || response[8..12] != (5001 + request.len() as u32).to_be_bytes()
            || dss.data_ack != Some(Sequence::Long(client_data))
            || mapping.data_sequence_number
                != Sequence::Long(mptcp::idsn(key).advance(1 + received as u64))
            || mapping.subflow_sequence_number != 1 + received as u32
            || usize::from(mapping.data_level_length) < payload.len()
            || !options
                .iter()
                .any(|option| matches!(option, tcp::TcpOption::Timestamps { tsecr: 1000, .. }))
        {
            return Err("invalid mapped HTTP response or timestamp echo".into());
        }
        let mut remaining = payload;
        let mut done = false;
        loop {
            let n = http.push(remaining);
            remaining = &remaining[n..];
            let mut progress = n != 0;
            while let Some(event) = http.next() {
                progress = true;
                match event? {
                    Event::Head(_) => {
                        saw_head = true;
                    }
                    Event::Body(_) => {}
                    Event::Done => {
                        if !saw_head || !remaining.is_empty() || http.buffered() != 0 {
                            return Err("HTTP response has an unexpected length".into());
                        }
                        done = true;
                        break;
                    }
                }
            }
            if remaining.is_empty() || done {
                break;
            }
            if !progress {
                return Err("HTTP response decoder made no progress".into());
            }
        }
        received += payload.len();
        let timestamp = options
            .iter()
            .find_map(|option| match option {
                tcp::TcpOption::Timestamps { tsval, .. } => Some(*tsval),
                _ => None,
            })
            .ok_or("HTTP response has no timestamp")?;
        send(
            peer,
            5001 + request.len() as u32,
            server_seq.wrapping_add(received as u32),
            0x10,
            MptcpOption::Dss(Dss {
                data_ack: Some(Sequence::Long(
                    mptcp::idsn(key).advance(1 + received as u64),
                )),
                ..Dss::default()
            }),
            timestamp,
            &[],
        )?;
        if done {
            println!(
                "Honeypot completed MP_CAPABLE and returned the complete mapped HTTP page with timestamps"
            );
            return Ok(());
        }
    }
}

fn oversized_ping(peer: &mut Peer) -> Result {
    use fictionet::stdlib::network::{ethernet::frame, ip};

    let mut echo = vec![0xa5; 4096];
    echo[..8].copy_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 1]);
    let checksum = ip::checksum(&echo);
    echo[2..4].copy_from_slice(&checksum.to_be_bytes());
    for (index, chunk) in echo.chunks(1024).enumerate() {
        let mut packet = ip::packet("192.0.2.1".parse()?, "192.0.2.2".parse()?, 1, chunk);
        packet.0[4..6].copy_from_slice(&0x4321u16.to_be_bytes());
        let fragment = (index as u16 * 128) | if index < 3 { 0x2000 } else { 0 };
        packet.0[6..8].copy_from_slice(&fragment.to_be_bytes());
        ip::set_header_checksum(&mut packet.0[..20]);
        peer.send(&frame::frame(
            HONEYPOT_MAC,
            CLIENT_MAC,
            frame::IPV4,
            &packet.0,
        ))?;
    }
    Ok(())
}

pub fn run(directory: PathBuf, egress: bool) -> Result {
    fs::create_dir_all(&directory)?;
    let directory = fs::canonicalize(directory)?;
    output(Command::new("cargo").args([
        "build",
        "-p",
        "xtask",
        "--features",
        "rawnic",
        "--bin",
        "rawnic-guest",
    ]))?;
    output(Command::new("cargo").args([
        "build",
        "-p",
        "honeypot-world",
        "--features",
        "raw-virtio",
        "--bin",
        "honeypot",
    ]))?;
    let metadata: serde_json::Value =
        serde_json::from_slice(&output(Command::new("cargo").args([
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
    let mut test_binaries = Vec::new();
    for (package, features) in [
        ("fictionet-host", "virtio-net"),
        ("honeypot-world", "raw-virtio"),
    ] {
        let test_build = output(Command::new("cargo").args([
            "test",
            "-p",
            package,
            "--no-default-features",
            "--features",
            features,
            "--lib",
            "--tests",
            "--no-run",
            "--message-format=json",
        ]))?;
        for value in String::from_utf8(test_build)?
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        {
            if value["profile"]["test"].as_bool() == Some(true)
                && let Some(path) = value["executable"].as_str()
            {
                test_binaries.push(PathBuf::from(path));
            }
        }
    }
    if test_binaries.is_empty() {
        return Err("cargo did not produce guest test binaries".into());
    }
    let mut archive = Vec::new();
    for dir in [
        "dev", "proc", "sys", "lib", "lib64", "usr", "usr/lib", "modules", "tests",
    ] {
        entry(&mut archive, dir, 0o40755, &[]);
    }
    entry(&mut archive, "tmp", 0o41777, &[]);
    node(&mut archive, "dev/console", 0o020600, &[], (5, 1));
    executable(
        &mut archive,
        &target.join("debug/rawnic-guest"),
        "init",
        &directory,
    )?;
    executable(
        &mut archive,
        &target.join("debug/honeypot"),
        "honeypot",
        &directory,
    )?;
    for (index, binary) in test_binaries.iter().enumerate() {
        executable(&mut archive, binary, &format!("tests/{index}"), &directory)?;
    }
    let mut modules = Vec::new();
    for module in ["vfio-pci", "vfio_iommu_type1", "tun"] {
        let dependencies = output(Command::new("modprobe").args(["--show-depends", module]))?;
        for line in String::from_utf8(dependencies)?.lines() {
            if line.starts_with("builtin ") {
                continue;
            }
            let path = line
                .strip_prefix("insmod ")
                .ok_or("unexpected module dependency")?
                .split_whitespace()
                .next()
                .ok_or("missing module path")?;
            if !modules.contains(&path.to_owned()) {
                modules.push(path.to_owned());
            }
        }
    }
    for (index, module) in modules.iter().enumerate() {
        let bytes = if module.ends_with(".zst") {
            output(Command::new("zstd").args(["-dc", module]))?
        } else {
            fs::read(module)?
        };
        entry(&mut archive, &format!("modules/{index}"), 0o100644, &bytes);
    }
    entry(&mut archive, "TRAILER!!!", 0, &[]);
    let initrd = directory.join("guest.cpio");
    fs::write(&initrd, archive)?;
    let listener = if egress {
        None
    } else {
        Some(TcpListener::bind("127.0.0.1:0")?)
    };
    if let Some(listener) = &listener {
        listener.set_nonblocking(true)?;
    }
    let log = directory.join("serial.log");
    fs::write(&log, [])?;
    let mut command = Command::new("qemu-system-x86_64");
    command.args([
        "-machine",
        "q35,accel=tcg",
        "-cpu",
        "max",
        "-m",
        "2G",
        "-smp",
        "2",
        "-display",
        "none",
        "-no-reboot",
        "-monitor",
        "none",
        "-serial",
    ]);
    command.arg(format!("file:{}", log.display()));
    command.args(["-smbios", "type=1,manufacturer=QEMU"]);
    command
        .args(["-kernel", "/boot/vmlinuz-linux", "-initrd"])
        .arg(initrd);
    if egress {
        command.args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);
    }
    command.args([
        "-append",
        if egress { "console=ttyS0 panic=-1 intel_iommu=on iommu.strict=1 fictionet.rawnic=1 fictionet.egress=1 rdinit=/init" } else { "console=ttyS0 panic=-1 intel_iommu=on iommu.strict=1 fictionet.rawnic=1 rdinit=/init" },
        "-device",
        "intel-iommu,intremap=on,caching-mode=on",
        "-netdev",
    ]);
    if let Some(listener) = &listener {
        command.arg(format!(
            "socket,id=frames,connect={}",
            listener.local_addr()?
        ));
    } else {
        command.arg("hubport,id=frames,hubid=0");
        command.args(["-netdev", "hubport,id=peer,hubid=0", "-device",
            "virtio-net-pci,netdev=peer,disable-legacy=on,iommu_platform=on,addr=04.0,mac=52:54:00:12:34:57"]);
    }
    command.args([
        "-device", "virtio-net-pci,netdev=frames,disable-legacy=on,iommu_platform=on,addr=03.0,mac=52:54:00:12:34:56",
        "-nic", "none",
    ]);
    if egress {
        command.args([
            "-object",
            &format!(
                "filter-dump,id=egress-capture,netdev=frames,file={}",
                directory.join("vfio.pcap").display()
            ),
        ]);
    }
    let mut child = Guest(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?,
    );

    if egress {
        let deadline = Instant::now() + Duration::from_secs(180);
        let result = loop {
            if let Some(status) = child.0.try_wait()? {
                break if status.code() == Some(85) {
                    Ok(())
                } else {
                    Err(format!("egress guest failed with {status}; inspect serial.log").into())
                };
            }
            if Instant::now() > deadline {
                break Err("egress guest timed out".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        println!("QEMU serial log: {}", log.display());
        return result;
    }
    let listener = listener.expect("raw frame peer listener");
    let result = (|| -> Result {
        let deadline = Instant::now() + Duration::from_secs(120);
        let stream: TcpStream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            if child.0.try_wait()?.is_some() || Instant::now() > deadline {
                return Err("QEMU did not connect its frame socket".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        stream.set_nodelay(true)?;
        loop {
            if fs::read_to_string(&log)?.contains("RAWNIC READY") {
                break;
            }
            if child.0.try_wait()?.is_some() || Instant::now() > deadline {
                return Err("guest did not initialize VFIO; inspect serial.log".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut peer = Peer::new(stream);
        for (index, frame) in frames::fixtures().into_iter().enumerate() {
            peer.send(&frame)?;
            let echoed = peer.recv()?;
            if echoed != frame {
                return Err("guest frame differs from byte-exact input".into());
            }
            println!(
                "Frame {}: {} bytes preserved through guest world",
                index + 1,
                frame.len()
            );
        }
        let mut acknowledgment = [0x5a; 60];
        acknowledgment[..6].copy_from_slice(&[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        peer.send(&acknowledgment)?;
        loop {
            if fs::read_to_string(&log)?.contains("HONEYPOT READY") {
                break;
            }
            if child.0.try_wait()?.is_some() || Instant::now() > deadline {
                return Err("guest did not start honeypot; inspect serial.log".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        peer::start_link(&mut peer)?;
        peer::neighbor_discovery(&mut peer)?;
        peer::ssh6(&mut peer)?;
        for (index, frame) in frames::fixtures().into_iter().enumerate() {
            peer.send(&frame)?;
            if index == 0 {
                let answer = peer.next(|bytes| Ok(Some(bytes.to_vec())))?;
                if !(54..=2036).contains(&answer.len()) {
                    return Err("invalid honeypot response length".into());
                }
                use fictionet::stdlib::network::{ip, tcp};
                let header = ip::Header::parse_whole(&answer[14..])
                    .ok_or("honeypot response is not valid IP")?;
                let segment = header.payload(&answer[14..]);
                if answer[..6] != frames::GATEWAY_MAC
                    || answer[6..12] != frame[..6]
                    || answer[12..14] != [8, 0]
                    || header.protocol != 6
                    || segment.len() < 20
                    || segment[13] != 0x12
                    || segment[..4] != [0, 80, 0x12, 0x34]
                    || segment[8..12] != 1u32.to_be_bytes()
                    || ip::transport_checksum(header.src, header.dst, header.protocol, segment) != 0
                    || !tcp::options(segment)?.iter().any(|option| {
                        matches!(option,
                        tcp::TcpOption::Unknown { kind: 30, data }
                            if data.len() == 10 && data[..2] == [1, 1])
                    })
                {
                    return Err("honeypot did not return an MPTCP SYN-ACK".into());
                }
                println!("Honeypot answered raw MPTCP SYN with a valid Ethernet SYN-ACK");
            }
        }
        oversized_ping(&mut peer)?;
        mapped_http(&mut peer)?;
        peer.send(&acknowledgment)?;
        peer.reset_link();
        peer::start_link(&mut peer)?;
        peer::neighbor_discovery(&mut peer)?;
        peer::ssh6(&mut peer)?;
        mapped_http(&mut peer)?;
        peer.send(&acknowledgment)?;
        loop {
            if let Some(status) = child.0.try_wait()? {
                if !status.success() || !fs::read_to_string(&log)?.contains("RAWNIC PASS") {
                    return Err("guest validation failed; inspect serial.log".into());
                }
                break;
            }
            if Instant::now() > deadline {
                return Err("guest validation timed out".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    })();
    println!("QEMU serial log: {}", log.display());
    result
}
