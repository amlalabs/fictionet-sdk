//! A honeypot's log and packet capture, held in memory, and the trusted
//! programs a test runs on its machines.

use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use fictionet::stdlib::codec::le32;
use fictionet::stdlib::world::net::Endpoints;
use honeypot_world::observe::Sinks;
use honeypot_world::{Config, Honeypot};

/// A sink that keeps every byte written to it.
#[derive(Clone, Default)]
pub struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Capture {
    /// Every byte written so far.
    pub fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }

    /// The packet of every pcapng Enhanced Packet Block written so far, in
    /// order. Each block's two length fields must agree.
    pub fn packets(&self) -> Vec<Vec<u8>> {
        let bytes = self.bytes();
        let mut blocks = bytes.as_slice();
        let mut packets = Vec::new();
        while !blocks.is_empty() {
            let length = le32(blocks, 4).expect("pcap block length") as usize;
            assert!(length >= 12 && length <= blocks.len(), "pcap block length");
            assert_eq!(le32(blocks, length - 4), Some(length as u32));
            if le32(blocks, 0) == Some(6) {
                let count = le32(blocks, 20).expect("captured length") as usize;
                let packet = blocks.get(28..28 + count).expect("complete packet");
                packets.push(packet.to_vec());
            }
            blocks = &blocks[length..];
        }
        packets
    }
}

/// The honeypot's observations to `log` and its packets to `pcap`.
pub fn sinks(log: &Capture, pcap: &Capture) -> Sinks {
    Sinks {
        log: Box::new(log.clone()),
        pcap: Box::new(pcap.clone()),
    }
}

/// The default server at `address`, with `gateway` as its IPv4 gateway.
pub fn config(address: Ipv4Addr, gateway: Ipv4Addr) -> Config {
    Config {
        address,
        gateway,
        ..Config::default()
    }
}

/// The TCP and UDP endpoints of a program run on the honeypot's server,
/// sharing its address.
pub async fn endpoints(honeypot: &Honeypot) -> fictionet::Result<Endpoints> {
    let (send, receive) = tokio::sync::oneshot::channel();
    let send = Mutex::new(Some(send));
    honeypot.program(move |_fcx: fictionet::Cx, endpoints: Endpoints| {
        let _ = send.lock().unwrap().take().unwrap().send(endpoints);
        async { Ok(()) }
    })?;
    Ok(receive.await?)
}
