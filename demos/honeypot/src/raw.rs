//! Complete Ethernet frames reach this world before any protocol parsing.

use std::io::Write;
use std::sync::Arc;
use std::task::Waker;
use std::time::Duration;

use fictionet::stdlib::network::ethernet::frame::Mac;
use fictionet::stdlib::network::ethernet::host::{self, Host, Ipv4Config, Ipv6Config, Received};
use fictionet::sync::Mutex;
use fictionet::time::Instant;
use fictionet::{Cx, Interface, Packet};
use fictionet_host::raw::{EthernetFrame, RawAttachment, RawReceiveStats, RawSender};
use serde::Serialize;

use crate::observe::{Direction, Hex, Sink, Sinks};
use crate::{Clock, Config, Honeypot, INTERNET};

/// The largest IP packet one Ethernet frame carries.
const MTU: u16 = 1500;

struct Capture {
    writer: Sink,
    lost: u64,
    clock: Clock,
    receive_stats: RawReceiveStats,
    reported_queue_dropped: u64,
}

#[derive(Serialize)]
struct FrameRecord {
    at_us: u64,
    direction: Direction,
    bytes: Hex,
    lost: u64,
    rx_queue_dropped: u64,
    nic_rx_dropped: Option<u64>,
}

impl Capture {
    fn frame(&mut self, fcx: &Cx, direction: Direction, bytes: &[u8]) {
        let queue_dropped = self.receive_stats.queue_dropped();
        let record = FrameRecord {
            at_us: self.clock.micros(fcx.now()),
            direction,
            bytes: Hex(bytes.to_vec()),
            lost: self.lost,
            rx_queue_dropped: queue_dropped.saturating_sub(self.reported_queue_dropped),
            nic_rx_dropped: None,
        };
        let mut line = serde_json::to_vec(&record).expect("a frame record is serializable");
        line.push(b'\n');
        if self.writer.put(&line) {
            self.lost = 0;
            self.reported_queue_dropped = queue_dropped;
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
    /// Logs `frame`, then queues it on the card. A frame the full transmit
    /// queue cannot take is dropped, as a host's full queue drops it.
    fn put(&mut self, fcx: &Cx, frame: Vec<u8>) -> fictionet::Result {
        self.capture.frame(fcx, Direction::Out, &frame);
        self.sender.try_send(EthernetFrame(frame))?;
        Ok(())
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
/// `rx_queue_dropped` counts frames the full host receive queue discarded,
/// both since the last accepted record. `nic_rx_dropped` is null because
/// device and backend losses are unavailable, not zero. Partial records
/// are completed before the next one. `sinks`
/// retain the existing IP capture and TCP option observations.
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
            reported_queue_dropped: 0,
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
            let EthernetFrame(bytes) = receiver.recv(&fcx).await?;
            incoming.lock().capture.frame(&fcx, Direction::In, &bytes);
            fcx.yield_now().await?;
            let mut link = incoming.lock();
            if let Received::World(packet) = link.host.receive(fcx.now(), &bytes) {
                incoming_end.lock().send(Packet(packet.to_vec()));
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
            if let Ok(frame) = link.host.send(fcx.now(), &packet.0) {
                link.put(&fcx, frame)?;
            }
            link.wake_timer();
        }
    });
    Ok(honeypot)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use fictionet::stdlib::network::ethernet::frame::{self, Frame};
    use fictionet::stdlib::network::ethernet::host::{
        AddressState, DELAY_FIRST_PROBE_TIME, Ipv6Gateway, REACHABLE_TIME, Unsent,
    };
    use fictionet::stdlib::network::ip;
    use fictionet::stdlib::protocols::arp;
    use fictionet_host::raw::RawWire;
    use serde_json::Value;

    use super::*;

    const MAC: Mac = [2; 6];
    const ROUTER: Mac = [4; 6];
    const ADDRESS: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const ADDRESS6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);

    fn config() -> Config {
        Config {
            address: ADDRESS,
            gateway: GATEWAY,
            ..Config::default()
        }
    }

    fn dual_stack() -> Config {
        Config {
            address_v6: Some(ADDRESS6),
            ..config()
        }
    }

    /// The host `config` makes for the card with [`MAC`], started at 0.
    fn host_of(config: &Config) -> Host {
        host(config, MAC, Instant::ZERO).unwrap()
    }

    fn arp_frame(
        dst: Mac,
        op: arp::Operation,
        sender: (Mac, Ipv4Addr),
        target: (Mac, Ipv4Addr),
    ) -> Vec<u8> {
        let p = arp::Packet {
            operation: op,
            sender_mac: sender.0,
            sender_ip: sender.1,
            target_mac: target.0,
            target_ip: target.1,
        };
        frame::frame(dst, sender.0, frame::ARP, &p.encode())
    }

    /// The host's request for the gateway: broadcast, or unicast to `to`.
    fn request_for_gateway(to: Mac) -> Vec<u8> {
        arp_frame(
            to,
            arp::Operation::Request,
            (MAC, ADDRESS),
            ([0; 6], GATEWAY),
        )
    }

    /// The gateway's reply to the host's request.
    fn gateway_reply() -> Vec<u8> {
        arp_frame(
            MAC,
            arp::Operation::Reply,
            (ROUTER, GATEWAY),
            (MAC, ADDRESS),
        )
    }

    /// The host has the server's IPv4 address and gateway, and the card's
    /// MAC: its first frame asks for that gateway from that address, and
    /// IPv6 is off without an IPv6 address.
    #[test]
    fn the_host_has_the_server_s_ipv4_address_and_gateway() {
        let mut host = host_of(&config());
        assert_eq!(host.mac(), MAC);
        assert_eq!(
            host.transmit(Instant::ZERO),
            Some(request_for_gateway(frame::BROADCAST))
        );
        let v6 = ip::packet(
            ADDRESS6.into(),
            "2001:db8:1::1".parse().unwrap(),
            6,
            &[0; 20],
        );
        assert_eq!(host.send(Instant::ZERO, &v6.0), Err(Unsent::Off));
    }

    /// The host's MTU is Ethernet's 1500 bytes.
    #[test]
    fn the_host_sends_packets_up_to_the_ethernet_mtu() {
        let mut host = host_of(&config());
        host.receive(Instant::ZERO, &gateway_reply());
        let to = "192.0.2.5".parse().unwrap();
        let full = ip::packet(ADDRESS.into(), to, 1, &[0; MTU as usize - 20]);
        assert!(host.send(Instant::ZERO, &full.0).is_ok());
        let over = ip::packet(ADDRESS.into(), to, 1, &[0; MTU as usize - 19]);
        assert_eq!(host.send(Instant::ZERO, &over.0), Err(Unsent::TooBig));
    }

    /// With [`Config::address_v6`] the host has that address and a
    /// link-local one from the card's MAC, and its IPv6 gateway is the
    /// configured one or, without one, learned from router advertisements.
    #[test]
    fn the_host_has_the_server_s_ipv6_address_and_gateway() {
        let host = host_of(&dual_stack());
        for addr in [ADDRESS6, frame::link_local(MAC)] {
            assert_eq!(host.address_state(addr), Some(AddressState::Tentative));
        }
        assert_eq!(host.ipv6_gateway(), None, "learned, so none yet");
        let gateway: Ipv6Addr = "fe80::1".parse().unwrap();
        let host = host_of(&Config {
            gateway_v6: Ipv6Gateway::Configured(gateway),
            ..dual_stack()
        });
        assert_eq!(host.ipv6_gateway(), Some((gateway, None)));
    }

    /// A buffer the test reads while the world writes to it.
    #[derive(Clone, Default)]
    struct Shared(Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        /// The raw log's records, as (direction, bytes).
        fn records(&self) -> Vec<(String, Vec<u8>)> {
            let log = self.0.lock().unwrap();
            std::str::from_utf8(&log)
                .unwrap()
                .lines()
                .map(|line| {
                    let v: Value = serde_json::from_str(line).unwrap();
                    let hex = v["bytes"].as_str().unwrap();
                    let bytes = (0..hex.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                        .collect();
                    (v["direction"].as_str().unwrap().to_owned(), bytes)
                })
                .collect()
        }
    }

    #[test]
    fn receive_losses_survive_a_refused_log_record() {
        struct Refusing {
            log: Shared,
            refuse: bool,
        }

        impl Write for Refusing {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if std::mem::take(&mut self.refuse) {
                    return Err(std::io::Error::other("disk full"));
                }
                self.log.write(bytes)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        fictionet::block_on(fictionet::run(
            fictionet::Seed::from_u64(0),
            move |fcx| async move {
                let (raw, wire) = RawAttachment::in_memory(MAC);
                while wire.try_send(EthernetFrame(vec![0; 14]))? {}
                let log = Shared::default();
                let mut capture = Capture {
                    writer: Sink::new(Box::new(Refusing {
                        log: log.clone(),
                        refuse: true,
                    })),
                    lost: 0,
                    clock: Clock::at_unix_secs(1_800_000_000),
                    receive_stats: raw.receive_stats(),
                    reported_queue_dropped: 0,
                };
                capture.frame(&fcx, Direction::In, &[1; 14]);
                assert!(log.0.lock().unwrap().is_empty());
                for _ in 0..2 {
                    assert!(!wire.try_send(EthernetFrame(vec![0; 14]))?);
                }
                capture.frame(&fcx, Direction::Out, &[2; 14]);
                assert!(!wire.try_send(EthernetFrame(vec![0; 14]))?);
                capture.frame(&fcx, Direction::In, &[3; 14]);
                capture.frame(&fcx, Direction::Out, &[4; 14]);
                let log = log.0.lock().unwrap();
                let records: Vec<Value> = std::str::from_utf8(&log)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
                assert_eq!(records.len(), 3);
                for (record, (lost, dropped)) in records.iter().zip([(1, 3), (0, 1), (0, 0)]) {
                    assert_eq!(record["lost"], lost);
                    assert_eq!(record["rx_queue_dropped"], dropped);
                    assert!(record["nic_rx_dropped"].is_null());
                    assert!(record.as_object().unwrap().contains_key("nic_rx_dropped"));
                }
                Ok(())
            },
        ))
        .unwrap();
    }

    /// Starts the raw honeypot with `config` on an in-memory wire, and runs
    /// `test` with the wire and the raw log.
    fn raw_honeypot<F, Fut>(config: Config, test: F)
    where
        F: FnOnce(Cx, RawWire, Shared) -> Fut + Send + 'static,
        Fut: Future<Output = fictionet::Result> + Send + 'static,
    {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(3),
            |fcx| async move {
                let (raw, wire) = RawAttachment::in_memory(MAC);
                let log = Shared::default();
                let sinks = Sinks {
                    log: Box::new(std::io::sink()),
                    pcap: Box::new(std::io::sink()),
                };
                start_raw(
                    &fcx,
                    &config,
                    Clock::at_unix_secs(1_800_000_000),
                    sinks,
                    raw,
                    Box::new(log.clone()),
                )?;
                test(fcx.clone(), wire, log).await?;
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }

    /// The next frame the world puts on the wire before `deadline`.
    async fn next(fcx: &Cx, wire: &mut RawWire, deadline: Instant) -> Option<Vec<u8>> {
        let frame = fcx
            .race(Some(deadline), wire.recv(fcx))
            .await
            .ok()?
            .ok()??;
        Some(frame.0)
    }

    /// A TCP SYN from `from` to the server's port 22, framed by the router.
    fn syn(from: SocketAddr) -> Vec<u8> {
        let to = SocketAddr::new(ADDRESS.into(), 22);
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&from.port().to_be_bytes());
        t[2..4].copy_from_slice(&to.port().to_be_bytes());
        t[12] = 5 << 4;
        t[13] = 0x02;
        t[14..16].copy_from_slice(&65535u16.to_be_bytes());
        let sum = ip::transport_checksum(from.ip(), to.ip(), 6, &t);
        t[16..18].copy_from_slice(&sum.to_be_bytes());
        let packet = ip::packet(from.ip(), to.ip(), 6, &t);
        frame::frame(MAC, ROUTER, frame::IPV4, &packet.0)
    }

    /// Whether `bytes` is the server's SYN-ACK to `to`, framed to the router.
    fn is_syn_ack_to(bytes: &[u8], to: SocketAddr) -> bool {
        let Some(f) = Frame::parse(bytes) else {
            return false;
        };
        let Some(p) = frame::ip_packet(f.ethertype, f.payload) else {
            return false;
        };
        let Some(header) = ip::Header::parse(p) else {
            return false;
        };
        let t = header.payload(p);
        (f.src, f.dst, f.ethertype) == (MAC, ROUTER, frame::IPV4)
            && ip::destination(p) == Some(to.ip())
            && t.len() >= 20
            && u16::from_be_bytes([t[2], t[3]]) == to.port()
            && t[13] == 0x12
    }

    /// The raw log holds every frame that crossed the card, both ways and
    /// in order, byte for byte: the host's ARP request, the gateway's
    /// reply, the client's SYN, and the server's SYN-ACK.
    #[test]
    fn every_frame_is_logged_both_ways() {
        raw_honeypot(config(), |fcx, mut wire, log| async move {
            let within = |fcx: &Cx| fcx.now() + Duration::from_millis(500);
            let request = next(&fcx, &mut wire, within(&fcx)).await;
            assert_eq!(request, Some(request_for_gateway(frame::BROADCAST)));
            wire.send(&fcx, EthernetFrame(gateway_reply())).await?;
            let client: SocketAddr = "192.0.2.5:40000".parse().unwrap();
            wire.send(&fcx, EthernetFrame(syn(client))).await?;
            let answer = next(&fcx, &mut wire, within(&fcx)).await.unwrap();
            assert!(is_syn_ack_to(&answer, client));
            let records = log.records();
            let expected = [
                ("out", request_for_gateway(frame::BROADCAST)),
                ("in", gateway_reply()),
                ("in", syn(client)),
                ("out", answer),
            ];
            assert_eq!(records.len(), expected.len());
            for ((dir, bytes), (want_dir, want_bytes)) in records.iter().zip(expected) {
                assert_eq!((dir.as_str(), bytes), (want_dir, &want_bytes));
            }
            Ok(())
        });
    }

    /// A packet from the world to a gateway gone stale starts the wait
    /// before the gateway is checked, and the timer task wakes for it: a
    /// unicast ARP request goes out [`DELAY_FIRST_PROBE_TIME`] later (RFC
    /// 4861 section 7.3.3), with no frame coming in to wake it.
    #[test]
    fn a_send_to_a_stale_gateway_wakes_the_timer_for_its_probe() {
        raw_honeypot(config(), |fcx, mut wire, log| async move {
            let within = |fcx: &Cx| fcx.now() + Duration::from_millis(500);
            next(&fcx, &mut wire, within(&fcx)).await.unwrap();
            wire.send(&fcx, EthernetFrame(gateway_reply())).await?;
            fcx.sleep(REACHABLE_TIME + Duration::from_secs(1)).await?;
            let client: SocketAddr = "192.0.2.5:40000".parse().unwrap();
            wire.send(&fcx, EthernetFrame(syn(client))).await?;
            let answer = next(&fcx, &mut wire, within(&fcx)).await.unwrap();
            assert!(is_syn_ack_to(&answer, client), "the stale MAC is used");
            let sent = fcx.now();
            let probe = request_for_gateway(ROUTER);
            let deadline = sent + DELAY_FIRST_PROBE_TIME + Duration::from_millis(500);
            let mut probed = None;
            while let Some(frame) = next(&fcx, &mut wire, deadline).await {
                if frame == probe {
                    probed = Some(fcx.now());
                    break;
                }
                assert!(is_syn_ack_to(&frame, client), "only retransmissions");
            }
            let probed = probed.expect("the stale gateway is probed");
            assert!(probed >= sent + DELAY_FIRST_PROBE_TIME);
            assert_eq!(log.records().last().unwrap(), &("out".to_owned(), probe));
            Ok(())
        });
    }
}
