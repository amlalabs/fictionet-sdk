//! Complete Ethernet frames reach this world before any protocol parsing.

use std::io::Write;
use std::sync::Arc;
use std::task::Waker;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fictionet::stdlib::network::ethernet::frame::Mac;
use fictionet::stdlib::network::ethernet::host::{self, Host, Ipv4Config, Ipv6Config, Received};
use fictionet::sync::Mutex;
use fictionet::time::Instant;
use fictionet::{Cx, Interface, Packet};
use fictionet_host::raw::{EthernetFrame, QueueStats, RawAttachment, RawSender};
use serde::Serialize;

use crate::observe::{Direction, Hex, Sink, Sinks};
use crate::{Clock, Config, Honeypot, INTERNET};

/// The largest IP packet one Ethernet frame carries.
const MTU: u16 = 1500;

struct Capture {
    writer: Sink,
    lost: u64,
    clock: Clock,
    receive_stats: QueueStats,
    transmit_stats: QueueStats,
    reported_queue_dropped: u64,
    reported_tx_queue_dropped: u64,
}

#[derive(Serialize)]
struct FrameRecord {
    at_us: u64,
    received_at_us: Option<u64>,
    timestamp_source: &'static str,
    direction: Direction,
    bytes: Hex,
    lost: u64,
    rx_queue_dropped: u64,
    tx_queue_dropped: u64,
    nic_rx_dropped: Option<u64>,
}

impl Capture {
    fn frame(
        &mut self,
        fcx: &Cx,
        direction: Direction,
        bytes: Vec<u8>,
        received_at: Option<SystemTime>,
    ) {
        let queue_dropped = self.receive_stats.queue_dropped();
        let tx_queue_dropped = self.transmit_stats.queue_dropped();
        let record = FrameRecord {
            at_us: self.clock.micros(fcx.now()),
            received_at_us: received_at
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_micros().min(u64::MAX as u128) as u64),
            timestamp_source: if received_at.is_some() {
                "host_system_time"
            } else {
                "world_clock"
            },
            direction,
            bytes: Hex(bytes),
            lost: self.lost,
            rx_queue_dropped: queue_dropped.saturating_sub(self.reported_queue_dropped),
            tx_queue_dropped: tx_queue_dropped.saturating_sub(self.reported_tx_queue_dropped),
            nic_rx_dropped: None,
        };
        let mut line = serde_json::to_vec(&record).expect("a frame record is serializable");
        line.push(b'\n');
        if self.writer.put(&line) {
            self.lost = 0;
            self.reported_queue_dropped = queue_dropped;
            self.reported_tx_queue_dropped = tx_queue_dropped;
        } else {
            self.lost = self.lost.saturating_add(1);
        }
    }
}

/// The server's side of the link: the host that speaks ARP and neighbor
/// discovery for it, the frame log, and the card's transmit queue.
struct Link {
    host: Host,
    capture: Capture,
    sender: RawSender,
    /// The task that waits for the host's timers. It is woken after every
    /// call that may have moved [`Host::poll_at`].
    timer: Option<Waker>,
}

impl Link {
    /// Queues and logs `frame`, including a queue rejection in its record.
    /// A frame the full transmit queue cannot take is dropped.
    fn put(&mut self, fcx: &Cx, frame: Vec<u8>) -> fictionet::Result {
        let sent = self.sender.try_send(EthernetFrame(frame.clone()));
        self.capture.frame(fcx, Direction::Out, frame, None);
        sent.map(|_| ())
    }

    /// Sends every frame the host has to send now, and wakes the timer
    /// task to read the host's next deadline.
    fn transmit(&mut self, fcx: &Cx) -> fictionet::Result {
        while let Some(frame) = self.host.transmit(fcx.now()) {
            self.put(fcx, frame)?;
        }
        self.wake_timer();
        Ok(())
    }

    fn wake_timer(&mut self) {
        if let Some(timer) = self.timer.take() {
            timer.wake();
        }
    }
}

/// The host the server is on its link: the card's MAC, both of the
/// server's addresses and both gateways from `config`, and an MTU of
/// 1500 bytes.
fn host(config: &Config, mac: Mac, now: Instant) -> fictionet::Result<Host> {
    let host = Host::new(
        host::Config {
            mac,
            mtu: MTU,
            ipv4: Some(Ipv4Config {
                address: config.address,
                gateway: config.gateway,
            }),
            ipv6: config.address_v6.map(|address| Ipv6Config {
                address,
                gateway: config.gateway_v6,
            }),
        },
        now,
    )?;
    Ok(host)
}

/// Starts the existing honeypot behind a complete Ethernet attachment.
///
/// `raw_log` receives every frame reaching the world, both ways, including
/// malformed headers, VLAN tags, unknown EtherTypes and Ethernet padding,
/// as hexadecimal JSON lines before parsing. `lost` counts refused log records and
/// `rx_queue_dropped` and `tx_queue_dropped` count frames the full host
/// queues discarded, all since the last accepted record. `nic_rx_dropped`
/// is null because device and backend losses are unavailable, not zero. Partial records
/// are completed before the next one. `sinks`
/// retain the existing IP capture and TCP option observations.
/// `received_at_us` preserves backend receipt time from the host system clock
/// before queueing, when available; `at_us` is world processing time. Neither
/// clock represents a hardware timestamp or independently observed transmission.
///
/// The link-layer work is done by an
/// [`ethernet::Host`](fictionet::stdlib::network::ethernet::Host), as a
/// Linux host does it. It answers ARP for [`Config::address`]. With
/// [`Config::address_v6`], it also has a link-local address made from the
/// card's MAC, checks both IPv6 addresses with duplicate address
/// detection before it uses them, joins their solicited-node groups with
/// MLDv2 reports, and answers neighbor solicitations for them. It resolves
/// [`Config::gateway`] with ARP, and the IPv6 gateway
/// ([`Config::gateway_v6`]) with neighbor solicitations, after learning it
/// from router advertisements when it is not configured. It asks again
/// every second until the gateway answers.
///
/// Only untagged IPv4 and IPv6 packets to one of the server's usable
/// addresses, in frames to the card's MAC, broadcast, or a multicast group
/// the host joined, enter the IP attachment. Every packet from the world
/// goes to the gateway of its family, whatever its destination. Packets
/// are dropped while that gateway is unresolved, when they are over the
/// Ethernet MTU of 1500 bytes, and when the card's transmit queue is full;
/// so are the host's own frames when the queue is full.
///
/// The driver and its polling thread must be opened outside
/// `fictionet::run` and kept alive for the run.
pub fn start_raw(
    fcx: &Cx,
    config: &Config,
    clock: Clock,
    sinks: Sinks,
    raw: RawAttachment,
    raw_log: Box<dyn Write + Send>,
) -> fictionet::Result<Honeypot> {
    let host = host(config, raw.mac_address(), fcx.now())?;
    let receive_stats = raw.receive_stats();
    let transmit_stats = raw.transmit_stats();
    let (sender, mut receiver) = raw.split();
    let (attacher, attachments) = fictionet::attachments();
    let end = Arc::new(Mutex::new(attacher.attach(INTERNET)?));
    let honeypot = crate::start(fcx, config, clock, sinks, attachments)?;
    let link = Arc::new(Mutex::new(Link {
        host,
        capture: Capture {
            writer: Sink::new(raw_log),
            lost: 0,
            clock,
            receive_stats,
            transmit_stats,
            reported_queue_dropped: 0,
            reported_tx_queue_dropped: 0,
        },
        sender,
        timer: None,
    }));
    let incoming_end = end.clone();
    let incoming = link.clone();
    fcx.spawn(move |fcx| async move {
        // Keep the attacher alive for the lifetime of its internet endpoint.
        let _attacher = attacher;
        loop {
            let received = receiver.recv_with_timestamp(&fcx).await?;
            let EthernetFrame(bytes) = received.frame;
            incoming
                .lock()
                .capture
                .frame(&fcx, Direction::In, bytes.clone(), received.received_at);
            fcx.yield_now().await?;
            let mut link = incoming.lock();
            if let Received::World(packet) = link.host.receive(fcx.now(), &bytes) {
                incoming_end.lock().send(Packet::new(packet.to_vec()));
            }
            link.transmit(&fcx)?;
        }
    });
    let timed = link.clone();
    fcx.spawn(move |fcx| async move {
        let mut timer = fictionet::Timer::new(&fcx);
        loop {
            std::future::poll_fn(|cx| {
                let mut link = timed.lock();
                link.timer = Some(cx.waker().clone());
                let deadline = link
                    .host
                    .poll_at()
                    .unwrap_or(Instant::from_since_start(Duration::MAX));
                timer.poll_until(cx, deadline)
            })
            .await?;
            timed.lock().transmit(&fcx)?;
        }
    });
    fcx.spawn(move |fcx| async move {
        loop {
            let packet = std::future::poll_fn(|cx| end.lock().poll_recv(&fcx, cx)).await?;
            let mut link = link.lock();
            if let Ok(frame) = link.host.send(fcx.now(), &packet) {
                link.put(&fcx, frame)?;
            }
            link.wake_timer();
        }
    });
    Ok(honeypot)
}
