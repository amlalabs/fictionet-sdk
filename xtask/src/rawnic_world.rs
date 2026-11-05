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

/// Runs the shipped example against the same guest NIC and host probes.
pub fn example(address: fictionet_host::PciAddress, mac: [u8; 6]) -> fictionet::Result {
    use std::fs::OpenOptions;
    use std::io::{self, BufRead, BufReader, Read};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::process::{Command, Stdio};

    // The reader exists before the child opens its log, so neither open blocks.
    // SAFETY: the name is a valid C string and the permissions apply to this FIFO.
    if unsafe { libc::mkfifo(c"/raw-example.frames".as_ptr(), 0o600) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let frames = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/raw-example.frames")?;
    let mut child = Command::new("/raw_honeypot")
        .arg(address.to_string())
        .arg("/raw-example.frames")
        .args(["--address", &crate::rawnic_frames::ADDRESS.to_string()])
        .args(["--address-v6", &crate::rawnic_frames::ADDRESS6.to_string()])
        .args(["--gateway", &crate::rawnic_frames::GATEWAY.to_string()])
        .args([
            "--log",
            "/raw-example.jsonl",
            "--pcap",
            "/raw-example.pcapng",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut output = BufReader::new(child.stdout.take().expect("piped example stdout"));
    let mut frames = BufReader::new(frames);
    let result = (|| -> fictionet::Result {
        let mut line = String::new();
        if output.read_line(&mut line)? == 0 {
            return Err(fictionet::Error::msg("raw example exited before startup"));
        }
        print!("{line}");
        // The example opens its frame writer before announcing startup.
        // SAFETY: frames owns this descriptor; fcntl changes only its status flags.
        let flags = unsafe { libc::fcntl(frames.get_ref().as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe {
                libc::fcntl(
                    frames.get_ref().as_raw_fd(),
                    libc::F_SETFL,
                    flags & !libc::O_NONBLOCK,
                )
            } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        println!("RAW EXAMPLE READY");
        let mut acknowledgement = [0x5a; 60];
        acknowledgement[..6].copy_from_slice(&mac);
        let acknowledgement = hex(&acknowledgement);
        loop {
            line.clear();
            if frames.read_line(&mut line)? == 0 {
                break;
            }
            let record: serde_json::Value = serde_json::from_str(&line)?;
            if record["direction"] == "in" && record["bytes"] == acknowledgement {
                return Ok(());
            }
        }
        Err(fictionet::Error::msg(
            "raw example closed its frame log before acknowledgment",
        ))
    })();
    let exited = child.try_wait()?;
    if exited.is_none() {
        child.kill()?;
    }
    let status = child.wait()?;
    let mut remaining = String::new();
    output.read_to_string(&mut remaining)?;
    print!("{remaining}");
    result?;
    if exited.is_some() {
        return Err(fictionet::Error::msg(format!(
            "raw example exited unexpectedly: {status}"
        )));
    }
    println!("RAW EXAMPLE PASS");
    Ok(())
}
