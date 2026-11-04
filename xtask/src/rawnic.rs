//! Isolated QEMU transport validation.
use crate::Result;
use std::{
    fs,
    io::{Read, Write},
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

fn output(command: &mut Command) -> Result<Vec<u8>> {
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

fn entry(archive: &mut Vec<u8>, name: &str, mode: u32, bytes: &[u8]) {
    node(archive, name, mode, bytes, (0, 0));
}

fn node(archive: &mut Vec<u8>, name: &str, mode: u32, bytes: &[u8], device: (u32, u32)) {
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

fn executable(archive: &mut Vec<u8>, source: &Path, destination: &str, directory: &Path) -> Result {
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
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::network::{ethernet::frame, ip, tcp};
    use fictionet::stdlib::protocols::mptcp::{self, Capable, Keys, MptcpOption, Sequence};

    let port = 0x5678u16;
    let send = |peer: &mut Peer,
                seq: u32,
                ack: u32,
                flags: u8,
                keys: Keys,
                echo: u32,
                payload: &[u8]|
     -> Result {
        let capable = MptcpOption::Capable(Capable {
            version: 1,
            checksum_required: false,
            extensibility: false,
            no_new_subflows: false,
            algorithms: mptcp::algorithm::HMAC_SHA256,
            keys,
        })
        .to_bytes()?;
        let mut options = vec![30, capable.len() as u8 + 2];
        options.extend(capable);
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
    send(peer, 5000, 0, 2, Keys::Absent, 0, &[])?;
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
        Keys::Both {
            sender: client_key,
            receiver: key,
        },
        timestamp,
        &[],
    )?;
    let request = b"GET / HTTP/1.1\r\nHost: 192.0.2.2\r\n\r\n";
    send(
        peer,
        5001,
        server_seq,
        0x18,
        Keys::Data {
            sender: client_key,
            receiver: key,
            data_level_length: request.len() as u16,
            checksum: None,
        },
        timestamp,
        request,
    )?;
    let client_data = mptcp::idsn(client_key).advance(1 + request.len() as u64);
    let mut http = Vec::new();
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
        if response[4..8] != server_seq.wrapping_add(http.len() as u32).to_be_bytes()
            || response[8..12] != (5001 + request.len() as u32).to_be_bytes()
            || dss.data_ack != Some(Sequence::Long(client_data))
            || mapping.data_sequence_number
                != Sequence::Long(mptcp::idsn(key).advance(1 + http.len() as u64))
            || mapping.subflow_sequence_number != 1 + http.len() as u32
            || usize::from(mapping.data_level_length) < payload.len()
            || !options
                .iter()
                .any(|option| matches!(option, tcp::TcpOption::Timestamps { tsecr: 1000, .. }))
        {
            return Err("invalid mapped HTTP response or timestamp echo".into());
        }
        http.extend_from_slice(payload);
        if http.len() > 8192 {
            return Err("HTTP response exceeds expected page size".into());
        }
        if let Some(end) = http.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let head = std::str::from_utf8(&http[..end])?;
            let length: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .ok_or("HTTP response has no content length")?
                .parse()?;
            if http.len() >= end + 4 + length {
                if !head.starts_with("HTTP/1.1 200 OK\r\n")
                    || http.len() != end + 4 + length
                    || !http[end + 4..]
                        .windows(b"Welcome to nginx!".len())
                        .any(|bytes| bytes == b"Welcome to nginx!")
                {
                    return Err("invalid HTTP response content".into());
                }
                println!(
                    "Honeypot completed MP_CAPABLE and returned the complete mapped HTTP page with timestamps"
                );
                return Ok(());
            }
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

pub fn run(directory: PathBuf) -> Result {
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
    node(&mut archive, "dev/console", 0o020600, &[], (5, 1));
    executable(
        &mut archive,
        &target.join("debug/rawnic-guest"),
        "init",
        &directory,
    )?;
    for (index, binary) in test_binaries.iter().enumerate() {
        executable(&mut archive, binary, &format!("tests/{index}"), &directory)?;
    }
    let mut modules = Vec::new();
    for module in ["vfio-pci", "vfio_iommu_type1"] {
        let dependencies = output(Command::new("modprobe").args(["--show-depends", module]))?;
        for line in String::from_utf8(dependencies)?.lines() {
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
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
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
    command.args([
        "-append",
        "console=ttyS0 panic=-1 intel_iommu=on iommu.strict=1 fictionet.rawnic=1 rdinit=/init",
        "-device",
        "intel-iommu,intremap=on,caching-mode=on",
        "-netdev",
    ]);
    command.arg(format!("socket,id=frames,connect={address}"));
    command.args([
        "-device", "virtio-net-pci,netdev=frames,disable-legacy=on,iommu_platform=on,addr=03.0,mac=52:54:00:12:34:56",
        "-nic", "none",
    ]);
    let mut child = Guest(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?,
    );

    let result = (|| -> Result {
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut stream: TcpStream = loop {
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
        for (index, frame) in frames::fixtures().into_iter().enumerate() {
            stream.write_all(&(frame.len() as u32).to_be_bytes())?;
            stream.write_all(&frame)?;
            let mut size = [0; 4];
            stream.read_exact(&mut size)?;
            let size = u32::from_be_bytes(size) as usize;
            if size > 65536 {
                return Err("invalid QEMU frame length".into());
            }
            let mut echoed = vec![0; size];
            stream.read_exact(&mut echoed)?;
            if echoed != frame {
                return Err("guest frame differs from byte-exact input".into());
            }
            println!(
                "Frame {}: {} bytes preserved through guest world",
                index + 1,
                frame.len()
            );
        }
        stream.write_all(&60u32.to_be_bytes())?;
        let mut acknowledgment = [0x5a; 60];
        acknowledgment[..6].copy_from_slice(&[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        stream.write_all(&acknowledgment)?;
        loop {
            if fs::read_to_string(&log)?.contains("HONEYPOT READY") {
                break;
            }
            if child.0.try_wait()?.is_some() || Instant::now() > deadline {
                return Err("guest did not start honeypot; inspect serial.log".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut peer = Peer::new(stream);
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
