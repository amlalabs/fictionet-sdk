//! Guest worlds reached through the same raw attachment as the honeypot.

use fictionet::stdlib::dissect::hex;
use fictionet::stdlib::network::ethernet::host::Ipv6Gateway;
use fictionet_host::VirtioNet;
use fictionet_host::raw::{EthernetFrame, RawPump};
use std::io::Write;
use std::sync::{Arc, Mutex};

pub fn run(nic: VirtioNet, expected: usize) -> fictionet::Result {
    let (pump, mut attachment) = RawPump::attach(nic)?;
    let result = fictionet::block_on(fictionet::run(
        fictionet::Seed::from_u64(0),
        move |fcx| async move {
            println!("RAWNIC READY");
            for _ in 0..expected {
                let frame = attachment.recv(&fcx).await?;
                attachment.send(&fcx, frame).await?;
            }
            attachment.flush(&fcx).await?;
            let frame = attachment.recv(&fcx).await?;
            let mut acknowledgement = vec![0x5a; 60];
            acknowledgement[..6].copy_from_slice(&attachment.mac_address());
            if frame != EthernetFrame(acknowledgement) {
                return Err(fictionet::Error::msg("unexpected raw frame acknowledgment"));
            }
            Ok(())
        },
    ));
    let stopped = pump.shutdown();
    result.and(stopped)
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct RawCapture {
    bytes: Capture,
    finished: Option<tokio::sync::oneshot::Sender<()>>,
    acknowledgement: String,
}

impl Write for RawCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let bytes = self.bytes.0.lock().unwrap();
        if String::from_utf8_lossy(&bytes).contains(&self.acknowledgement)
            && let Some(finished) = self.finished.take()
        {
            let _ = finished.send(());
        }
        Ok(())
    }
}

pub fn honeypot(nic: VirtioNet) -> fictionet::Result {
    let mut acknowledgement = vec![0x5a; 60];
    acknowledgement[..6].copy_from_slice(&nic.mac_address());
    let (pump, attachment) = RawPump::attach(nic)?;
    let log = Capture::default();
    let raw = Capture::default();
    let pcap = Capture::default();
    let (finished, received) = tokio::sync::oneshot::channel();
    let sinks = honeypot_world::observe::Sinks {
        log: Box::new(log.clone()),
        pcap: Box::new(pcap.clone()),
    };
    let raw_sink = RawCapture {
        bytes: raw.clone(),
        finished: Some(finished),
        acknowledgement: hex(&acknowledgement),
    };
    let result = fictionet::block_on(fictionet::run(
        fictionet::Seed::from_u64(0),
        move |fcx| async move {
            let config = honeypot_world::Config {
                address: crate::rawnic_frames::ADDRESS,
                address_v6: Some(crate::rawnic_frames::ADDRESS6),
                gateway: crate::rawnic_frames::GATEWAY,
                gateway_v6: Ipv6Gateway::FromRouterAdvertisements,
                ..Default::default()
            };
            let _honeypot = honeypot_world::start_raw(
                &fcx,
                &config,
                honeypot_world::Clock::at_unix_secs(0),
                sinks,
                attachment,
                Box::new(raw_sink),
            )?;
            println!("HONEYPOT READY");
            fcx.race(None, received)
                .await?
                .map_err(|_| fictionet::Error::msg("raw capture closed"))?;
            fcx.cancel();
            Ok(())
        },
    ));
    let stopped = pump.shutdown();
    result.and(stopped)?;
    let capture = pcap.0.lock().unwrap();
    let mut remaining = capture.as_slice();
    let mut oversized_reply = false;
    while !remaining.is_empty() {
        use fictionet::stdlib::codec::le32;
        use fictionet::stdlib::network::ip;
        let kind =
            le32(remaining, 0).ok_or_else(|| fictionet::Error::msg("truncated capture block"))?;
        let length = le32(remaining, 4)
            .ok_or_else(|| fictionet::Error::msg("truncated capture length"))?
            as usize;
        if length < 12
            || length > remaining.len()
            || le32(remaining, length - 4) != Some(length as u32)
        {
            return Err(fictionet::Error::msg("invalid capture block length"));
        }
        let block = &remaining[..length];
        remaining = &remaining[length..];
        if kind == 6 {
            let captured = le32(block, 20)
                .ok_or_else(|| fictionet::Error::msg("missing captured length"))?
                as usize;
            let packet = block
                .get(28..28 + captured)
                .ok_or_else(|| fictionet::Error::msg("truncated captured packet"))?;
            if let Some(header) = ip::Header::parse_whole(packet) {
                let payload = header.payload(packet);
                oversized_reply |= header.src == "192.0.2.2".parse::<std::net::IpAddr>()?
                    && header.dst == "192.0.2.1".parse::<std::net::IpAddr>()?
                    && header.protocol == 1
                    && payload.len() == 4096
                    && payload[..2] == [0, 0]
                    && payload[4..8] == [0x12, 0x34, 0, 1]
                    && payload[8..].iter().all(|byte| *byte == 0xa5)
                    && ip::checksum(payload) == 0;
            }
        }
    }
    if !oversized_reply {
        return Err(fictionet::Error::msg(
            "fragmented ping did not produce the oversized echo reply",
        ));
    }
    println!(
        "Honeypot reassembled the oversized ping and stayed available after dropping its reply"
    );
    let raw_bytes = raw.0.lock().unwrap();
    let frames: Vec<serde_json::Value> = std::str::from_utf8(&raw_bytes)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let gateway = hex(&crate::rawnic_frames::GATEWAY_MAC);
    if frames.iter().any(|entry| {
        entry["direction"] == "out"
            && entry["bytes"].as_str().is_some_and(|bytes| {
                bytes.get(24..28) == Some("0800") && !bytes.starts_with(&gateway)
            })
    }) {
        return Err(fictionet::Error::msg("IPv4 reply bypassed the gateway"));
    }
    // IPv6 unicast goes to the router; only multicast goes elsewhere.
    if frames.iter().any(|entry| {
        entry["direction"] == "out"
            && entry["bytes"].as_str().is_some_and(|bytes| {
                bytes.get(24..28) == Some("86dd")
                    && !bytes.starts_with(&gateway)
                    && !bytes.starts_with("3333")
            })
    }) {
        return Err(fictionet::Error::msg("IPv6 unicast bypassed the router"));
    }
    for frame in crate::rawnic_frames::fixtures() {
        if !frames
            .iter()
            .any(|entry| entry["direction"] == "in" && entry["bytes"] == hex(&frame))
        {
            return Err(fictionet::Error::msg(
                "honeypot did not capture complete incoming frame",
            ));
        }
    }
    let log_bytes = log.0.lock().unwrap();
    let events: Vec<serde_json::Value> = std::str::from_utf8(&log_bytes)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    for (event, subtype) in [
        ("syn", "mp_capable"),
        ("answer", "mp_capable"),
        ("segment", "dss"),
    ] {
        if !events.iter().any(|entry| {
            entry["event"] == event
                && entry["mptcp"].as_array().is_some_and(|options| {
                    options.iter().any(|option| option["subtype"] == subtype)
                })
        }) {
            return Err(fictionet::Error::msg(
                "honeypot did not log MPTCP SYN, answer and DSS",
            ));
        }
    }
    let ssh6 = std::net::SocketAddr::new(crate::rawnic_frames::ADDRESS6.into(), 22).to_string();
    if !events
        .iter()
        .any(|entry| entry["event"] == "syn" && entry["dst"] == ssh6.as_str())
    {
        return Err(fictionet::Error::msg(
            "honeypot did not log the IPv6 SYN to SSH",
        ));
    }
    println!("Honeypot captured complete Ethernet frames and logged MPTCP SYN and answer");
    println!("Honeypot logged the IPv6 SYN to SSH");
    Ok(())
}

/// Runs the shipped executable against the same guest NIC and host probes.
pub fn deployed(address: fictionet_host::PciAddress, mac: [u8; 6]) -> fictionet::Result {
    use std::fs::{self, File};
    use std::io::{self, BufRead, BufReader, Read};
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::DirBuilderExt;
    use std::process::{Command, Stdio};

    fs::DirBuilder::new()
        .mode(0o700)
        .create("/honeypot-state")?;
    // SAFETY: inotify_init1 returns a new owned descriptor on success.
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: fd is a new descriptor and ownership transfers to File.
    let mut changes = unsafe { File::from_raw_fd(fd) };
    // SAFETY: the descriptor and terminated path are valid.
    if unsafe {
        libc::inotify_add_watch(
            fd,
            c"/honeypot-state".as_ptr(),
            libc::IN_MODIFY | libc::IN_CREATE,
        )
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let mut child = Command::new("/honeypot")
        .args(["run", "--backend", "vfio", "--device", &address.to_string()])
        .args(["--address", &crate::rawnic_frames::ADDRESS.to_string()])
        .args(["--address-v6", &crate::rawnic_frames::ADDRESS6.to_string()])
        .args(["--gateway", &crate::rawnic_frames::GATEWAY.to_string()])
        .args(["--state-dir", "/honeypot-state"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut output = BufReader::new(child.stdout.take().expect("piped honeypot stdout"));
    let result = (|| -> fictionet::Result {
        let mut line = String::new();
        if output.read_line(&mut line)? == 0 {
            return Err(fictionet::Error::msg("honeypot exited before startup"));
        }
        let ready: serde_json::Value = serde_json::from_str(&line)?;
        if ready["event"] != "local_ready" || ready["backend"] != "vfio" {
            return Err(fictionet::Error::msg(
                "honeypot did not report local VFIO readiness",
            ));
        }
        print!("{line}");
        println!("HONEYPOT EXECUTABLE READY");
        let mut acknowledgement = [0x5a; 60];
        acknowledgement[..6].copy_from_slice(&mac);
        loop {
            for entry in fs::read_dir("/honeypot-state")? {
                let entry = entry?;
                if !entry.file_name().to_string_lossy().starts_with("ethernet-") {
                    continue;
                }
                let bytes = fs::read(entry.path())?;
                if captured_frame(&bytes, &acknowledgement)? {
                    return Ok(());
                }
            }
            let mut events = [0; 4096];
            if changes.read(&mut events)? == 0 {
                return Err(fictionet::Error::msg("evidence notification stream closed"));
            }
        }
    })();
    let exited = child.try_wait()?;
    if exited.is_none() {
        // SAFETY: this is the live child process started above, inside the guest.
        if unsafe { libc::kill(child.id() as i32, libc::SIGTERM) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    let status = child.wait()?;
    let mut remaining = String::new();
    output.read_to_string(&mut remaining)?;
    print!("{remaining}");
    result?;
    if exited.is_some() || !status.success() {
        return Err(fictionet::Error::msg(format!(
            "honeypot exited unexpectedly: {status}"
        )));
    }
    println!("HONEYPOT EXECUTABLE PASS");
    Ok(())
}

fn captured_frame(mut bytes: &[u8], expected: &[u8]) -> fictionet::Result<bool> {
    use fictionet::stdlib::codec::le32;
    while bytes.len() >= 8 {
        let kind = le32(bytes, 0).unwrap();
        let length = le32(bytes, 4).unwrap() as usize;
        if length < 12 {
            return Err(fictionet::Error::msg(
                "invalid Ethernet capture block length",
            ));
        }
        if length > bytes.len() {
            return Ok(false);
        }
        let block = &bytes[..length];
        if le32(block, length - 4) != Some(length as u32) {
            return Err(fictionet::Error::msg(
                "invalid Ethernet capture block trailer",
            ));
        }
        if kind == 6 {
            let captured = le32(block, 20)
                .ok_or_else(|| fictionet::Error::msg("missing Ethernet capture length"))?
                as usize;
            let frame = block
                .get(28..28 + captured)
                .ok_or_else(|| fictionet::Error::msg("truncated Ethernet capture"))?;
            if frame == expected {
                return Ok(true);
            }
        }
        bytes = &bytes[length..];
    }
    Ok(false)
}

/// Validates TUN ownership and the direct in-process packet path in the guest.
pub fn tun() -> fictionet::Result {
    use fictionet::{Interface, InterfaceExt, Packet};
    use fictionet_host::tun::{Mode, Tun};
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Read};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;

    fn ioctl(fd: i32, operation: libc::c_ulong, request: &mut [u8; 40]) -> io::Result<()> {
        // SAFETY: the caller supplies a live descriptor and a complete ifreq buffer.
        if unsafe { libc::ioctl(fd, operation, request.as_mut_ptr()) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    fn index(name: &std::ffi::CStr) -> u32 {
        // SAFETY: the interface name is terminated and read only.
        unsafe { libc::if_nametoindex(name.as_ptr()) }
    }
    let routes = fs::read("/proc/net/route")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let tun = Tun::open("hp-test", Mode::Create)?;
            let ifindex = index(c"hp-test");
            if ifindex == 0
                || Tun::open("hp-test", Mode::Create).is_ok()
                || Tun::open("hp-test", Mode::Existing).is_ok()
            {
                return Err(fictionet::Error::msg(
                    "TUN creation or ownership isolation failed",
                ));
            }
            // SAFETY: socket returns a newly owned descriptor on success.
            let descriptor = unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    (libc::ETH_P_IP as u16).to_be() as i32,
                )
            };
            if descriptor < 0 {
                return Err(io::Error::last_os_error().into());
            }
            // SAFETY: descriptor is new and ownership transfers to File.
            let packet = unsafe { File::from_raw_fd(descriptor) };
            // SAFETY: zero is a valid initial sockaddr_ll representation.
            let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            address.sll_family = libc::AF_PACKET as u16;
            address.sll_protocol = (libc::ETH_P_IP as u16).to_be();
            address.sll_ifindex = ifindex as i32;
            // SAFETY: address and its size describe a complete sockaddr_ll.
            if unsafe {
                libc::bind(
                    descriptor,
                    (&address as *const libc::sockaddr_ll).cast(),
                    std::mem::size_of_val(&address) as u32,
                )
            } < 0
            {
                return Err(io::Error::last_os_error().into());
            }
            let ignore_outgoing: i32 = 1;
            // SAFETY: the option points to one initialized integer of the stated size.
            if unsafe {
                libc::setsockopt(
                    descriptor,
                    libc::SOL_PACKET,
                    libc::PACKET_IGNORE_OUTGOING,
                    (&ignore_outgoing as *const i32).cast(),
                    std::mem::size_of_val(&ignore_outgoing) as u32,
                )
            } < 0
            {
                return Err(io::Error::last_os_error().into());
            }
            let fixture = crate::rawnic_frames::fixtures().remove(0);
            let length = u16::from_be_bytes([fixture[16], fixture[17]]) as usize;
            let expected = fixture[14..14 + length].to_vec();
            // SAFETY: descriptor and sockaddr_ll are live and bytes remain valid for this send.
            let sent = unsafe {
                libc::sendto(
                    descriptor,
                    expected.as_ptr().cast(),
                    expected.len(),
                    0,
                    (&address as *const libc::sockaddr_ll).cast(),
                    std::mem::size_of_val(&address) as u32,
                )
            };
            if sent != expected.len() as isize {
                return Err(io::Error::last_os_error().into());
            }
            // SAFETY: the descriptor remains owned, open and nonblocking until deregistration.
            let packet = unsafe { tokio::io::unix::AsyncFd::register(packet)? };
            let (end, mut peer) = fictionet::pair_with_limit(128 * 1024);
            fictionet::run(fictionet::Seed::from_u64(0), move |fcx| async move {
                fcx.spawn(move |fcx| tun.relay(fcx, end));
                let incoming = peer.recv(&fcx).await?;
                if incoming.0 != expected {
                    return Err(fictionet::Error::msg(format!(
                        "TUN ingress changed the IP packet: expected {}, received {}",
                        fictionet::stdlib::dissect::hex(&expected),
                        fictionet::stdlib::dissect::hex(&incoming.0)
                    )));
                }
                peer.send(Packet(expected.clone()));
                let received = fcx
                    .race(None, async {
                        loop {
                            let mut ready = packet.readable().await?;
                            let mut bytes = [0; 65536];
                            match ready.try_io(|fd| fd.get_ref().read(&mut bytes)) {
                                Ok(result) => return result.map(|count| bytes[..count].to_vec()),
                                Err(_) => continue,
                            }
                        }
                    })
                    .await??;
                if received != expected {
                    return Err(fictionet::Error::msg("TUN egress changed the IP packet"));
                }
                fcx.cancel();
                Ok(())
            })
            .await?;
            if index(c"hp-test") != 0 {
                return Err(fictionet::Error::msg(
                    "ephemeral TUN survived descriptor close",
                ));
            }

            let control = std::net::UdpSocket::bind("127.0.0.1:0")?;
            let open = || {
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                    .open("/dev/net/tun")
            };
            let device = open()?;
            let mut request = [0; 40];
            request[..10].copy_from_slice(b"hp-managed");
            request[16..18].copy_from_slice(&0x1001i16.to_ne_bytes());
            ioctl(device.as_raw_fd(), 0x4004_54ca, &mut request)?;
            // SAFETY: the ioctl takes an integer persistence flag, not a pointer.
            if unsafe { libc::ioctl(device.as_raw_fd(), 0x4004_54cbu64 as libc::c_ulong, 1) } < 0 {
                return Err(io::Error::last_os_error().into());
            }
            request[16..20].copy_from_slice(&1500i32.to_ne_bytes());
            ioctl(control.as_raw_fd(), libc::SIOCSIFMTU, &mut request)?;
            ioctl(control.as_raw_fd(), libc::SIOCGIFFLAGS, &mut request)?;
            let flags =
                i16::from_ne_bytes(request[16..18].try_into().unwrap()) | libc::IFF_UP as i16;
            request[16..18].copy_from_slice(&flags.to_ne_bytes());
            ioctl(control.as_raw_fd(), libc::SIOCSIFFLAGS, &mut request)?;
            drop(device);
            let flags_before = fs::read("/sys/class/net/hp-managed/tun_flags")?;
            let mtu_before = fs::read("/sys/class/net/hp-managed/mtu")?;
            let existing = Tun::open("hp-managed", Mode::Existing)?;
            if Tun::open("hp-managed", Mode::Create).is_ok() {
                return Err(fictionet::Error::msg(
                    "create mode reused an externally owned TUN",
                ));
            }
            drop(existing);
            if index(c"hp-managed") == 0
                || fs::read("/sys/class/net/hp-managed/tun_flags")? != flags_before
                || fs::read("/sys/class/net/hp-managed/mtu")? != mtu_before
            {
                return Err(fictionet::Error::msg(
                    "existing TUN settings or persistence changed",
                ));
            }
            request[16..20].copy_from_slice(&1400i32.to_ne_bytes());
            ioctl(control.as_raw_fd(), libc::SIOCSIFMTU, &mut request)?;
            if Tun::open("hp-managed", Mode::Existing).is_ok() {
                return Err(fictionet::Error::msg("unsupported TUN MTU accepted"));
            }
            let device = open()?;
            request[16..18].copy_from_slice(&0x1001i16.to_ne_bytes());
            ioctl(device.as_raw_fd(), 0x4004_54ca, &mut request)?;
            // SAFETY: the descriptor owns this guest test device and the integer disables persistence.
            if unsafe { libc::ioctl(device.as_raw_fd(), 0x4004_54cbu64 as libc::c_ulong, 0) } < 0 {
                return Err(io::Error::last_os_error().into());
            }
            drop(device);
            if index(c"hp-managed") != 0 || fs::read("/proc/net/route")? != routes {
                return Err(fictionet::Error::msg(
                    "TUN lifecycle left a device or changed IPv4 routes",
                ));
            }
            Ok(())
        })?;
    println!("TUN lifecycle and bidirectional IP traffic passed");
    Ok(())
}
