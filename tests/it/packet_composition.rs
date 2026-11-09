//! The same application directly on TCP and behind a stream packet tunnel.
use crate::common::echo_stack::Echo;
use fictionet::stdlib::layer::*;
use fictionet::stdlib::network::packet::{self, Ingress, IpLayer, Scope};
use fictionet::stdlib::network::tcp::{Options, TcpLayer};
use fictionet::stdlib::network::transport::{Request, TcpControl, TcpNotice, TcpOpening};
use fictionet::stdlib::services::stack::{Boxed, Polling};
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Raw = Packets<Datagram<Ingress>, Chunk>;
type ControlPort = Messages<TcpNotice, TcpControl>;

struct Control(VecDeque<TcpControl>);
impl Layer for Control {
    type Lower = ControlPort;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;
    fn on_event(
        &mut self,
        _: &mut Env<'_, Infallible>,
        _: MessageEvent<TcpNotice>,
    ) -> Result<Admit<MessageEvent<TcpNotice>>, Infallible> {
        Ok(Admit::Taken)
    }
    fn on_command(
        &mut self,
        _: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }
    fn take_command(&mut self) -> Option<MessageCommand<TcpControl>> {
        self.0.pop_front().map(MessageCommand::Send)
    }
    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

fn endpoint(
    addr: IpAddr,
    scope: Scope,
    server: bool,
    make: impl Fn() -> Boxed + Send + 'static,
) -> Boxed<Raw> {
    let entropy = SeededEntropy::new(Seed::from_u64(9));
    let tcp = TcpLayer::new(addr, Options::default(), &entropy, Instant::ZERO).in_scope(scope);
    let commands = if server {
        vec![
            TcpControl::Listen {
                port: 1234,
                backlog: None,
                answer: None,
            },
            TcpControl::Accept {
                port: 1234,
                count: 1,
            },
        ]
    } else {
        vec![TcpControl::Connect {
            request: Request(0),
            remote: "10.0.0.1:1234".parse().unwrap(),
        }]
    };
    let children = Children::<_, ControlPort, TcpOpening>::new(4, 16 * 1024, move |_, _, _| make());
    Boxed::new(Chain::new(
        Chain::new(Chain::new(IpLayer::host(), tcp), children),
        Control(commands.into()),
    ))
}

struct Client {
    request: Option<Chunk>,
    output: Arc<Mutex<Vec<u8>>>,
}
impl Layer for Client {
    type Lower = ByteStream;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;
    fn on_event(
        &mut self,
        _: &mut Env<'_, Infallible>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        if let StreamEvent::Data(bytes) = event {
            self.output.lock().unwrap().extend_from_slice(&bytes);
        }
        Ok(Admit::Taken)
    }
    fn on_command(
        &mut self,
        _: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }
    fn take_command(&mut self) -> Option<StreamCommand> {
        self.request.take().map(StreamCommand::Write)
    }
    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

/// Bad overlapping fragments precede out-of-order valid fragments. Each
/// original packet gets its own fragment identity, including retransmits.
fn fragments(bytes: &[u8], serial: &mut u16) -> Vec<Vec<u8>> {
    assert_eq!(bytes[0] >> 4, 4);
    let header = ((bytes[0] & 15) * 4) as usize;
    let payload = &bytes[header..];
    assert!(payload.len() > 16);
    assert_eq!(bytes[9], 6);
    let mut poisoned = payload.to_vec();
    let data = usize::from(payload[12] >> 4) * 4;
    if data < poisoned.len() {
        // If overlap rejection fails, TCP receives valid-checksum bytes at
        // the expected sequence number, and the application sees corruption.
        poisoned[data] ^= 0x20;
        poisoned[16..18].fill(0);
        let mut pseudo = bytes[12..20].to_vec();
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&(poisoned.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(&poisoned);
        poisoned[16..18].copy_from_slice(&checksum(&pseudo).to_be_bytes());
    }
    let part = |payload: &[u8], start: usize, end: usize, more: bool, id: u16| {
        let mut packet = bytes[..header].to_vec();
        packet[2..4].copy_from_slice(&((header + end - start) as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        packet[6..8]
            .copy_from_slice(&((start as u16 / 8) | if more { 0x2000 } else { 0 }).to_be_bytes());
        packet[10..12].fill(0);
        let checksum = checksum(&packet);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet.extend_from_slice(&payload[start..end]);
        packet
    };
    *serial = serial.wrapping_add(2);
    vec![
        part(&poisoned, 0, 16, true, *serial),
        part(&poisoned, 8, payload.len(), false, *serial),
        part(payload, 8, payload.len(), false, serial.wrapping_add(1)),
        part(payload, 0, 8, true, serial.wrapping_add(1)),
    ]
}

/// Disturbs the inner network before framing puts it on the outer stream.
struct Fragmented {
    frames: packet::Framed,
    packets: VecDeque<Chunk>,
    serial: u16,
}
impl Layer for Fragmented {
    type Lower = ByteStream;
    type Upper = Raw;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = packet::FrameError;
    fn on_event(
        &mut self,
        env: &mut Env<'_, Infallible>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Self::Error> {
        self.frames.on_event(env, event)
    }
    fn on_command(
        &mut self,
        env: &mut Env<'_, Infallible>,
        command: PacketCommand<Chunk>,
    ) -> Result<Admit<PacketCommand<Chunk>>, Self::Error> {
        if !self.packets.is_empty() {
            return Ok(Admit::Blocked(command));
        }
        match command {
            PacketCommand::Send(bytes) => self.packets.extend(
                fragments(&bytes, &mut self.serial)
                    .into_iter()
                    .map(Chunk::new),
            ),
            PacketCommand::End => return self.frames.on_command(env, PacketCommand::End),
        }
        Ok(Admit::Taken)
    }
    fn advance(&mut self, env: &mut Env<'_, Infallible>) -> Result<bool, Self::Error> {
        let Some(packet) = self.packets.pop_front() else {
            return Ok(false);
        };
        if let Admit::Blocked(PacketCommand::Send(packet)) =
            self.frames.on_command(env, PacketCommand::Send(packet))?
        {
            self.packets.push_front(packet);
            return Ok(false);
        }
        Ok(true)
    }
    fn take_command(&mut self) -> Option<StreamCommand> {
        self.frames.take_command()
    }
    fn take_event(&mut self) -> Option<PacketEvent<Datagram<Ingress>>> {
        self.frames.take_event()
    }
}

fn echo() -> Boxed {
    Boxed::new(Echo::stack())
}

#[test]
fn unchanged_application_runs_directly_and_in_a_packet_stream_with_overlapping_fragments() {
    let mut results = Vec::new();
    for tunnel in [false, true] {
        let output = Arc::new(Mutex::new(Vec::new()));
        let client_output = output.clone();
        let client = move || {
            Boxed::new(Client {
                request: Some(Chunk::new(b"one\n".repeat(1000))),
                output: client_output.clone(),
            })
        };
        let scope = Scope::tunnel();
        let server_app: Box<dyn Fn() -> Boxed + Send> = if tunnel {
            Box::new(move || {
                Boxed::new(Chain::new(
                    Fragmented {
                        frames: packet::Framed::new(Ingress {
                            scope,
                            ..Ingress::default()
                        }),
                        packets: VecDeque::new(),
                        serial: 0,
                    },
                    endpoint("10.0.0.1".parse().unwrap(), scope, true, echo),
                ))
            })
        } else {
            Box::new(echo)
        };
        let client_app: Box<dyn Fn() -> Boxed + Send> = if tunnel {
            Box::new(move || {
                let captured = client.clone();
                Boxed::new(Chain::new(
                    Fragmented {
                        frames: packet::Framed::new(Ingress {
                            scope,
                            ..Ingress::default()
                        }),
                        packets: VecDeque::new(),
                        serial: 0,
                    },
                    endpoint("10.0.0.2".parse().unwrap(), scope, false, captured),
                ))
            })
        } else {
            Box::new(client)
        };
        let expected = [b"hello\n".as_slice(), &b"one\n".repeat(1000)].concat();
        exchange(server_app, client_app, || {
            *output.lock().unwrap() == expected
        });
        let got = output.lock().unwrap().clone();
        assert_eq!(got, expected, "tunnel={tunnel}");
        results.push(got);
    }
    assert_eq!(results[0], results[1]);
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(super) fn exchange(
    server_app: impl Fn() -> Boxed + Send + 'static,
    client_app: impl Fn() -> Boxed + Send + 'static,
    done: impl Fn() -> bool,
) {
    let mut server = Driver::new(
        endpoint("10.0.0.1".parse().unwrap(), Scope::ROOT, true, server_app),
        Arc::new(SeededEntropy::new(Seed::from_u64(3))),
        Budget::unlimited(),
        Instant::ZERO,
    );
    let mut client = Driver::new(
        endpoint("10.0.0.2".parse().unwrap(), Scope::ROOT, false, client_app),
        Arc::new(SeededEntropy::new(Seed::from_u64(4))),
        Budget::unlimited(),
        Instant::ZERO,
    );
    let (mut server_jobs, mut client_jobs) = (Polling::new(), Polling::new());
    let mut serial = 0;
    for tick in 0..10000 {
        for direction in [false, true] {
            let (from, to, jobs) = if direction {
                (&mut server, &mut client, &mut server_jobs)
            } else {
                (&mut client, &mut server, &mut client_jobs)
            };
            from.set_now(Instant::ZERO + Duration::from_millis(tick));
            from.run().unwrap();
            jobs.work(from).unwrap();
            from.run().unwrap();
            let mut packets = Vec::new();
            from.send_below(|command| {
                if let PacketCommand::Send(bytes) = command {
                    packets.extend(fragments(&bytes, &mut serial));
                }
                Admit::Taken
            });
            for packet in packets {
                let mut event =
                    PacketEvent::Packet(Datagram::new(Chunk::new(packet), Ingress::default()));
                loop {
                    to.run().unwrap();
                    match to.deliver(event).unwrap() {
                        Admit::Blocked(back) => event = back,
                        _ => break,
                    }
                }
            }
        }
        if done() {
            return;
        }
    }
    panic!("packet composition did not finish within ten simulated seconds");
}

#[test]
fn unchanged_application_runs_through_live_tcp_and_a_live_packet_tunnel() {
    use fictionet::stdlib::network::{ConnInfo, ConnectionExt};
    use fictionet::stdlib::services::stack::{self, StreamLimits};
    use fictionet::stdlib::world::net::Net;
    use fictionet::{Cx, Interface, Packet, RecvError};
    use std::task::{Context, Poll};

    struct Link {
        inner: fictionet::End,
        pending: VecDeque<Packet>,
        serial: u16,
    }
    impl Link {
        fn packets(&mut self, packet: Packet) -> Vec<Packet> {
            if packet.0.len() >= 40 && packet.0[0] >> 4 == 4 && packet.0[9] == 6 {
                fragments(&packet.0, &mut self.serial)
                    .into_iter()
                    .map(Packet)
                    .collect()
            } else {
                vec![packet]
            }
        }
    }
    impl Interface for Link {
        fn send(&mut self, packet: Packet) {
            for packet in self.packets(packet) {
                self.inner.send(packet);
            }
        }
        fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
            if let Some(packet) = self.pending.pop_front() {
                return Poll::Ready(Ok(packet));
            }
            match self.inner.poll_recv(fcx, cx) {
                Poll::Ready(Ok(packet)) => {
                    let packets = self.packets(packet);
                    self.pending.extend(packets);
                    Poll::Ready(Ok(self.pending.pop_front().expect("nonempty packet batch")))
                }
                other => other,
            }
        }
    }

    for tunnel in [false, true] {
        fictionet_test_support::world::world(Duration::from_secs(30), move |fcx| async move {
            let scope = Scope::tunnel();
            let (attacher, attachments) = fictionet::attachments();
            Net::new(fictionet_extras::network::cdn_pools())
                .ipv4_only()
                .host("echo", |host| {
                    host.at("192.0.2.1".parse::<IpAddr>().unwrap())
                        .tcp_stack(1234, move |_| {
                            if tunnel {
                                Boxed::new(Chain::new(
                                    Fragmented {
                                        frames: packet::Framed::new(Ingress {
                                            scope,
                                            ..Ingress::default()
                                        }),
                                        packets: VecDeque::new(),
                                        serial: 0,
                                    },
                                    endpoint("10.0.0.1".parse().unwrap(), scope, true, echo),
                                ))
                            } else {
                                echo()
                            }
                        })
                })
                .start(&fcx, attachments)?;
            let machine = fictionet_test_support::sandbox::machine(
                &fcx,
                Link {
                    inner: attacher.attach("client")?,
                    pending: VecDeque::new(),
                    serial: 0,
                },
                "10.0.0.2".parse::<IpAddr>().unwrap(),
            );
            let conn = machine
                .tcp
                .connect(&fcx, "192.0.2.1:1234".parse().unwrap())
                .await?;
            let info = ConnInfo::new(1, conn.local_addr(), conn.peer_addr());
            let (sent, received) = tokio::sync::oneshot::channel();
            let sent = Arc::new(Mutex::new(Some(sent)));
            let client = move || {
                let sent = sent.clone();
                Boxed::new(stack::Tunnel::new(move |fcx, mut conn| async move {
                    conn.write_all(&fcx, &b"one\n".repeat(1000)).await.unwrap();
                    let mut response = Vec::new();
                    while response.len() < 4006 {
                        let mut bytes = [0; 1024];
                        let n = conn.read(&fcx, &mut bytes).await.unwrap();
                        assert!(n > 0, "echo closed before its response completed");
                        response.extend_from_slice(&bytes[..n]);
                    }
                    sent.lock().unwrap().take().unwrap().send(response).unwrap();
                }))
            };
            let layer = if tunnel {
                Boxed::new(Chain::new(
                    Fragmented {
                        frames: packet::Framed::new(Ingress {
                            scope,
                            ..Ingress::default()
                        }),
                        packets: VecDeque::new(),
                        serial: 0,
                    },
                    endpoint("10.0.0.2".parse().unwrap(), scope, false, client),
                ))
            } else {
                client()
            };
            fcx.spawn(move |fcx| async move {
                stack::stream(
                    &fcx,
                    conn,
                    &info,
                    layer,
                    Budget::unlimited(),
                    StreamLimits::default(),
                    |_| {},
                )
                .await
                .map_err(|error| fictionet::Error::msg(error.to_string()))?;
                Ok(())
            });
            let response = received.await?;
            assert_eq!(
                response,
                [b"hello\n".as_slice(), &b"one\n".repeat(1000)].concat()
            );
            Ok(())
        });
    }
}
