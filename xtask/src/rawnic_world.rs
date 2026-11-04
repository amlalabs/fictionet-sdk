//! Guest worlds reached through the same raw attachment as the honeypot.

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
                address: "192.0.2.2".parse().unwrap(),
                gateway: "192.0.2.254".parse().unwrap(),
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
    println!("Honeypot captured complete Ethernet frames and logged MPTCP SYN and answer");
    Ok(())
}
