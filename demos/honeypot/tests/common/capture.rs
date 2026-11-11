//! A honeypot's evidence, written by the real writer into a fresh state
//! directory, and the trusted programs a test runs on its machines.
//! Each test uses some of these helpers.
#![allow(dead_code)]

use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fictionet::stdlib::codec::le32;
use fictionet::stdlib::world::net::Endpoints;
use honeypot_world::evidence::{EventSink, Line, Writer, WriterConfig};
use honeypot_world::{Config, Honeypot};
use serde_json::Value;

static DIRECTORIES: AtomicU64 = AtomicU64::new(0);

/// An evidence writer into its own state directory.
pub struct Evidence {
    directory: PathBuf,
    writer: Writer,
    sink: EventSink,
}

impl Evidence {
    /// A writer into a new, empty state directory.
    pub fn new() -> Evidence {
        let directory = std::env::temp_dir().join(format!(
            "honeypot-test-{}-{}",
            std::process::id(),
            DIRECTORIES.fetch_add(1, Ordering::Relaxed)
        ));
        let (writer, sink) = Writer::open(
            WriterConfig {
                state_dir: directory.clone(),
                ..WriterConfig::default()
            },
            Vec::new(),
        )
        .unwrap();
        Evidence {
            directory,
            writer,
            sink,
        }
    }

    /// The sink the world hands its records and packets to.
    pub fn sink(&self) -> EventSink {
        self.sink.clone()
    }

    /// Drains the writer and reads what it wrote. Nothing may have been lost.
    pub fn finish(self) -> Written {
        let metrics = self.writer.shutdown(Duration::from_secs(5)).unwrap();
        assert_eq!(metrics.dropped_events, 0, "{metrics:?}");
        assert_eq!(metrics.dropped_captures, 0, "{metrics:?}");
        assert_eq!(metrics.write_failures, 0, "{metrics:?}");
        Written {
            directory: self.directory,
        }
    }
}

/// The files a stopped writer left. The directory goes when this does.
pub struct Written {
    directory: PathBuf,
}

impl Written {
    fn file(&self, prefix: &str) -> Vec<u8> {
        let mut names: Vec<_> = fs::read_dir(&self.directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with(prefix))
            .collect();
        assert!(
            names.len() <= 1,
            "one {prefix} file, not rotated: {names:?}"
        );
        names
            .pop()
            .map(|name| fs::read(self.directory.join(name)).unwrap())
            .unwrap_or_default()
    }

    /// The log's lines, as text.
    fn texts(&self) -> Vec<String> {
        String::from_utf8(self.file("events-"))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The `event` object of every line of the log, as JSON.
    pub fn events(&self) -> Vec<Value> {
        self.texts()
            .iter()
            .map(|text| serde_json::from_str::<Value>(text).unwrap()["event"].clone())
            .collect()
    }

    /// Every line of the log, read back as typed values.
    pub fn lines(&self) -> Vec<Line> {
        self.texts()
            .iter()
            .map(|text| serde_json::from_str(text).unwrap())
            .collect()
    }

    /// The IP capture file.
    pub fn ip(&self) -> Vec<u8> {
        self.file("ip-")
    }

    /// The Ethernet capture file.
    pub fn ethernet(&self) -> Vec<u8> {
        self.file("ethernet-")
    }
}

impl Drop for Written {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// The packet of every pcapng Enhanced Packet Block in `bytes`, in order.
/// Each block's two length fields must agree.
pub fn packets(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut blocks = bytes;
    let mut packets = Vec::new();
    while !blocks.is_empty() {
        let length = le32(blocks, 4).expect("pcap block length") as usize;
        assert!(length >= 12 && length <= blocks.len(), "pcap block length");
        assert_eq!(le32(blocks, length - 4), Some(length as u32));
        if le32(blocks, 0) == Some(6) {
            packets.push(packet_at(blocks, 0));
        }
        blocks = &blocks[length..];
    }
    packets
}

/// The packet of the Enhanced Packet Block at `offset` in `bytes`.
pub fn packet_at(bytes: &[u8], offset: usize) -> Vec<u8> {
    let block = &bytes[offset..];
    assert_eq!(le32(block, 0), Some(6), "an Enhanced Packet Block");
    let count = le32(block, 20).expect("captured length") as usize;
    block.get(28..28 + count).expect("complete packet").to_vec()
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
