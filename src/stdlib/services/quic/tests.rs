use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::*;
use crate::stdlib::layer::*;
use crate::stdlib::services::tls;
use crate::time::Instant;
use crate::{Entropy, Seed, SeededEntropy};

const DATE: u64 = 1_893_456_000;

#[derive(Debug)]
struct Calendar;
impl rustls::time_provider::TimeProvider for Calendar {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            Duration::from_secs(DATE),
        ))
    }
}
impl quinn_proto::TimeSource for Calendar {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(DATE)
    }
}

pub(super) fn configs(
    entropy: Arc<dyn Entropy>,
    datagrams: bool,
) -> (ClientConfig, ServerConfig, Arc<EndpointConfig>) {
    configs_with_protocol(entropy, datagrams, b"fictionet-test")
}

fn configs_with_protocol(
    entropy: Arc<dyn Entropy>,
    datagrams: bool,
    protocol: &[u8],
) -> (ClientConfig, ServerConfig, Arc<EndpointConfig>) {
    let cert = rustls::pki_types::CertificateDer::from(
        include_bytes!("../../../../tests/it/fixtures/tls/p256.cert.der").to_vec(),
    );
    let key = rustls::pki_types::PrivateKeyDer::try_from(
        include_bytes!("../../../../tests/it/fixtures/tls/p256.key.der").to_vec(),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let provider = Arc::new(tls::crypto_provider(entropy));
    let mut client =
        rustls::ClientConfig::builder_with_details(provider.clone(), Arc::new(Calendar))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let mut server = rustls::ServerConfig::builder_with_details(provider, Arc::new(Calendar))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    client.alpn_protocols = vec![protocol.to_vec()];
    server.alpn_protocols = client.alpn_protocols.clone();
    let mut transport = quinn_proto::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(8u32.into())
        .max_concurrent_uni_streams(8u32.into())
        .stream_receive_window(4096u32.into())
        .receive_window(32768u32.into())
        .send_window(32768)
        .datagram_receive_buffer_size(datagrams.then_some(4096));
    let transport = Arc::new(transport);
    let mut client = ClientConfig::new(Arc::new(
        quinn_proto::crypto::rustls::QuicClientConfig::try_from(client).unwrap(),
    ));
    client.transport_config(transport.clone());
    let mut server = ServerConfig::new(
        Arc::new(quinn_proto::crypto::rustls::QuicServerConfig::try_from(server).unwrap()),
        Arc::new(ring::hkdf::Prk::new_less_safe(
            ring::hkdf::HKDF_SHA256,
            &[5; 32],
        )),
    );
    server
        .transport_config(transport)
        .time_source(Arc::new(Calendar));
    let endpoint = EndpointConfig::new(Arc::new(ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        &[9; 32],
    )));
    (client, server, Arc::new(endpoint))
}

type Event = MuxEvent<ByteStream<VarInt>, Control, Stream>;

struct Peer {
    driver: Driver<QuicLayer>,
    address: SocketAddr,
    events: Vec<Event>,
    /// The first byte and version of each long header datagram this peer
    /// sent, in order
    long_headers: Vec<(u8, u32)>,
}

impl Peer {
    fn events(&mut self) -> bool {
        let mut moved = false;
        while let Some(event) = self.driver.layer_mut().take_event() {
            if let MuxEvent::Control(ControlEvent::Lost(reason)) = &event {
                panic!("connection lost: {reason}");
            }
            self.events.push(event);
            moved = true;
        }
        moved
    }

    fn opened(&mut self) -> (Child, Stream) {
        let index = self
            .events
            .iter()
            .position(|event| matches!(event, MuxEvent::Opened(..)))
            .expect("stream opened");
        let MuxEvent::Opened(child, stream, _) = self.events.remove(index) else {
            unreachable!()
        };
        (child, stream)
    }

    fn command(&mut self, command: MuxCommand<ByteStream<VarInt>, Control>) {
        assert!(matches!(
            self.driver.command(command).unwrap(),
            Admit::Taken
        ));
    }
}

struct Pair {
    client: Peer,
    server: Peer,
}

impl Pair {
    fn new() -> Self {
        Self::with_datagrams(false)
    }

    fn with_datagrams(datagrams: bool) -> Self {
        let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(7)));
        let (client, server, endpoint) = configs(entropy.clone(), datagrams);
        Self::build(
            entropy,
            client,
            server,
            endpoint.clone(),
            endpoint,
            AddressValidation::Accept,
        )
    }

    /// A pair whose client offers `preferred` with a first flight in
    /// `version`, and whose server accepts `server_versions`, most
    /// preferred first
    fn versions(
        version: u32,
        preferred: &[u32],
        server_versions: &[u32],
        validation: AddressValidation,
    ) -> Self {
        let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(7)));
        let (mut client, server, endpoint) = configs(entropy.clone(), false);
        client
            .version(version)
            .preferred_versions(VersionList::new(preferred).unwrap());
        let mut server_endpoint = (*endpoint).clone();
        server_endpoint.supported_versions(server_versions.to_vec());
        Self::build(
            entropy,
            client,
            server,
            endpoint,
            Arc::new(server_endpoint),
            validation,
        )
    }

    fn build(
        entropy: Arc<dyn Entropy>,
        client: ClientConfig,
        server: ServerConfig,
        client_endpoint: Arc<EndpointConfig>,
        server_endpoint: Arc<EndpointConfig>,
        validation: AddressValidation,
    ) -> Self {
        let epoch = std::time::Instant::now();
        let address: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let make = |endpoint: Arc<EndpointConfig>, server, client: Option<ClientConfig>| {
            let budget = Budget::new(8 << 20);
            let mut observe = Observations::new(0);
            let mut env = Env::new(Instant::ZERO, entropy.as_ref(), &budget, &mut observe);
            let mut layer = QuicLayer::new(&mut env, endpoint, server, epoch, 16, |_| 0u32.into())
                .unwrap()
                .with_address_validation(validation);
            if let Some(client) = client {
                layer
                    .connect(&mut env, client, address, "localhost")
                    .unwrap();
            }
            Driver::new(layer, entropy.clone(), budget, Instant::ZERO)
        };
        Self {
            client: Peer {
                driver: make(client_endpoint, None, Some(client)),
                address: "127.0.0.1:4444".parse().unwrap(),
                events: Vec::new(),
                long_headers: Vec::new(),
            },
            server: Peer {
                driver: make(server_endpoint, Some(Arc::new(server)), None),
                address,
                events: Vec::new(),
                long_headers: Vec::new(),
            },
        }
    }

    fn transfer(from: &mut Peer, to: &mut Peer, drop: bool) -> bool {
        let Some(command) = from.driver.take_command() else {
            return false;
        };
        let DatagramCommand::Send(datagram) = command else {
            return false;
        };
        assert!(datagram.wants_completion());
        assert_eq!(*datagram.meta(), to.address);
        if let [first, a, b, c, d, ..] = *datagram.payload()
            && first & 0x80 != 0
        {
            from.long_headers
                .push((first, u32::from_be_bytes([a, b, c, d])));
        }
        if !drop {
            let (payload, _) = datagram.into_parts();
            assert!(matches!(
                to.driver
                    .deliver(DatagramEvent::Datagram(Datagram::new(
                        payload,
                        from.address
                    )))
                    .unwrap(),
                Admit::Taken
            ));
        }
        assert!(matches!(
            from.driver.deliver(DatagramEvent::Sent(1)).unwrap(),
            Admit::Taken
        ));
        true
    }

    fn drive(&mut self) {
        for _ in 0..10000 {
            let mut moved = self.client.driver.run().unwrap() | self.server.driver.run().unwrap();
            moved |= self.client.events() | self.server.events();
            moved |= Self::transfer(&mut self.client, &mut self.server, false);
            moved |= Self::transfer(&mut self.server, &mut self.client, false);
            if !moved {
                return;
            }
        }
        panic!("QUIC did not quiesce");
    }

    fn tick(&mut self) {
        let deadline = [self.client.driver.deadline(), self.server.driver.deadline()]
            .into_iter()
            .flatten()
            .min()
            .expect("transport timer");
        self.client.driver.set_now(deadline);
        self.server.driver.set_now(deadline);
        self.drive();
    }

    fn handshake(&mut self) {
        self.drive();
        for _ in 0..10 {
            if [&self.client, &self.server].into_iter().all(|peer| {
                peer.events
                    .iter()
                    .any(|event| matches!(event, MuxEvent::Control(ControlEvent::Connected)))
            }) {
                return;
            }
            self.tick();
        }
        panic!("handshake did not complete");
    }
}

#[test]
fn protected_streams_run_over_the_datagram_carrier() {
    let mut pair = Pair::new();
    pair.handshake();
    pair.client
        .command(MuxCommand::control(ControlCommand::Open(Dir::Bi)));
    pair.drive();
    let (client, stream) = pair.client.opened();
    assert!(stream.local);
    pair.client.command(client.grant(4096));
    pair.client.command(client.send(StreamCommand::Write(
        Chunk::copy_of(pair.client.driver.budget(), b"hello").unwrap(),
    )));
    pair.client.command(client.send(StreamCommand::End));
    pair.drive();
    let (server, remote) = pair.server.opened();
    assert_eq!(remote.id, stream.id);
    assert!(!remote.local);
    assert!(
        !pair
            .server
            .events
            .iter()
            .any(|event| matches!(event, MuxEvent::Child(_, StreamEvent::Data(_))))
    );
    pair.server.command(server.grant(5));
    pair.drive();
    let bytes: Vec<u8> = pair
        .server
        .events
        .iter()
        .filter_map(|event| match event {
            MuxEvent::Child(id, StreamEvent::Data(bytes)) if *id == server.id() => {
                Some(bytes.as_ref())
            }
            _ => None,
        })
        .flatten()
        .copied()
        .collect();
    assert_eq!(bytes, b"hello");
    assert!(pair.server.events.iter().any(
        |event| matches!(event, MuxEvent::Child(id, StreamEvent::Ended) if *id == server.id())
    ));
    pair.server.command(server.send(StreamCommand::Write(
        Chunk::copy_of(pair.server.driver.budget(), b"world").unwrap(),
    )));
    pair.server.command(server.send(StreamCommand::End));
    pair.drive();
    assert!(pair.client.events.iter().any(|event| matches!(event, MuxEvent::Child(id, StreamEvent::Data(data)) if *id == client.id() && data.as_ref() == b"world")));
}

#[test]
fn finished_streams_release_adapter_slots_after_events() {
    let mut pair = Pair::new();
    pair.handshake();
    for _ in 0..32 {
        pair.client
            .command(MuxCommand::control(ControlCommand::Open(Dir::Bi)));
        pair.drive();
        let (client, _) = pair.client.opened();
        pair.client.command(client.grant(1));
        pair.client.command(client.send(StreamCommand::End));
        pair.drive();
        let (server, _) = pair.server.opened();
        pair.server.command(server.grant(1));
        pair.server.command(server.send(StreamCommand::Write(
            Chunk::copy_of(pair.server.driver.budget(), b"x").unwrap(),
        )));
        pair.server.command(server.send(StreamCommand::End));
        pair.drive();
        for (peer, child) in [(&pair.client, &client), (&pair.server, &server)] {
            let ended = peer
                .events
                .iter()
                .position(
                    |e| matches!(e, MuxEvent::Child(id, StreamEvent::Ended) if *id == child.id()),
                )
                .unwrap();
            let closed = peer
                .events
                .iter()
                .position(|e| matches!(e, MuxEvent::Closed(id) if *id == child.id()))
                .unwrap();
            assert!(ended < closed);
            assert!(!peer.events.iter().any(|e| matches!(e, MuxEvent::Child(id, StreamEvent::ReceiveReset(_) | StreamEvent::SendStopped(_)) if *id == child.id())));
        }
        let written = pair
            .server
            .events
            .iter()
            .position(
                |e| matches!(e, MuxEvent::Child(id, StreamEvent::Written(1)) if *id == server.id()),
            )
            .unwrap();
        let closed = pair
            .server
            .events
            .iter()
            .position(|e| matches!(e, MuxEvent::Closed(id) if *id == server.id()))
            .unwrap();
        assert!(written < closed);
        pair.client.events.clear();
        pair.server.events.clear();
    }
}

#[test]
fn lost_initial_is_retransmitted_by_the_environment_timer() {
    let mut pair = Pair::new();
    assert!(Pair::transfer(&mut pair.client, &mut pair.server, true));
    pair.tick();
    pair.handshake();
}

#[test]
fn lower_send_completion_is_required_before_another_packet_leaves() {
    let mut pair = Pair::new();
    let command = pair.client.driver.take_command().expect("initial packet");
    assert!(matches!(command, DatagramCommand::Send(_)));
    pair.client
        .driver
        .set_now(Instant::from_since_start(Duration::from_secs(1)));
    pair.client.driver.run().unwrap();
    assert!(pair.client.driver.take_command().is_none());
    assert!(matches!(
        pair.client.driver.deliver(DatagramEvent::Sent(1)).unwrap(),
        Admit::Taken
    ));
    assert!(pair.client.driver.take_command().is_some());
}

#[test]
fn directional_reset_preserves_the_reverse_stream() {
    let mut pair = Pair::new();
    pair.handshake();
    pair.client
        .command(MuxCommand::control(ControlCommand::Open(Dir::Bi)));
    pair.drive();
    let (client, _) = pair.client.opened();
    pair.client.command(client.grant(10));
    pair.client
        .command(client.send(StreamCommand::ResetSend(VarInt::from_u32(123))));
    pair.drive();
    let (server, _) = pair.server.opened();
    assert!(pair.server.events.iter().any(|event| matches!(event, MuxEvent::Child(id, StreamEvent::ReceiveReset(code)) if *id == server.id() && code.into_inner() == 123)));
    pair.server.command(server.send(StreamCommand::Write(
        Chunk::copy_of(pair.server.driver.budget(), b"reply").unwrap(),
    )));
    pair.drive();
    assert!(pair.client.events.iter().any(|event| matches!(event, MuxEvent::Child(id, StreamEvent::Data(bytes)) if *id == client.id() && bytes.as_ref() == b"reply")));
}

#[test]
fn a_stream_without_receive_credit_does_not_stall_its_sibling() {
    let mut pair = Pair::new();
    pair.handshake();
    let mut clients = Vec::new();
    for _ in 0..2 {
        pair.client
            .command(MuxCommand::control(ControlCommand::Open(Dir::Bi)));
        pair.drive();
        let (child, _) = pair.client.opened();
        pair.client.command(child.send(StreamCommand::Write(
            Chunk::copy_of(pair.client.driver.budget(), b"abcdefgh").unwrap(),
        )));
        clients.push(child);
        pair.drive();
    }
    let (blocked, _) = pair.server.opened();
    let (flowing, _) = pair.server.opened();
    pair.server.command(flowing.grant(8));
    pair.drive();
    assert!(pair.server.events.iter().any(|event| matches!(event,
        MuxEvent::Child(id, StreamEvent::Data(bytes)) if *id == flowing.id() && bytes.as_ref() == b"abcdefgh")));
    assert!(!pair.server.events.iter().any(|event| matches!(event,
        MuxEvent::Child(id, StreamEvent::Data(_)) if *id == blocked.id())));
    pair.server.command(blocked.grant(8));
    pair.drive();
    assert!(pair.server.events.iter().any(|event| matches!(event,
        MuxEvent::Child(id, StreamEvent::Data(bytes)) if *id == blocked.id() && bytes.as_ref() == b"abcdefgh")));
}

#[test]
fn stopped_sending_passes_buffered_receive_data_and_preserves_its_code() {
    let mut pair = Pair::new();
    pair.handshake();
    pair.client
        .command(MuxCommand::control(ControlCommand::Open(Dir::Bi)));
    pair.drive();
    let (client, _) = pair.client.opened();
    pair.client.command(client.send(StreamCommand::Write(
        Chunk::copy_of(pair.client.driver.budget(), b"first").unwrap(),
    )));
    pair.drive();
    let (server, _) = pair.server.opened();
    pair.client.command(client.grant(16));
    pair.server.command(server.send(StreamCommand::Write(
        Chunk::copy_of(pair.server.driver.budget(), b"pending").unwrap(),
    )));
    pair.server
        .command(server.send(StreamCommand::StopReceive(VarInt::MAX)));
    // Keep application receive output inside the client's layer while its
    // engine handles the peer's cancellation. Urgent extraction must work.
    let mut stopped = false;
    for _ in 0..100 {
        pair.server.driver.run().unwrap();
        Pair::transfer(&mut pair.server, &mut pair.client, false);
        pair.client.driver.run().unwrap();
        if let Some(MuxEvent::Child(id, StreamEvent::SendStopped(code))) =
            pair.client.driver.layer_mut().take_urgent()
        {
            assert_eq!(id, client.id());
            assert_eq!(code, VarInt::MAX);
            stopped = true;
            break;
        }
        Pair::transfer(&mut pair.client, &mut pair.server, false);
    }
    assert!(stopped);
    pair.drive();
    assert!(pair.client.events.iter().any(|event| matches!(event,
        MuxEvent::Child(id, StreamEvent::Data(bytes)) if *id == client.id() && bytes.as_ref() == b"pending")));
}

#[test]
fn refused_stream_storage_returns_the_same_payload_and_credit() {
    let mut pair = Pair::new();
    pair.handshake();
    pair.client
        .command(MuxCommand::control(ControlCommand::Open(Dir::Bi)));
    pair.drive();
    let (child, _) = pair.client.opened();
    let budget = pair.client.driver.budget().clone();
    let held = budget.charge(budget.limit() - budget.used()).unwrap();
    let payload = Chunk::unpaid(b"owned by caller".to_vec());
    let original = payload.slice(0..payload.len());
    let used = budget.used();
    let Admit::Blocked(command) = pair
        .client
        .driver
        .command(child.send(StreamCommand::Write(payload)))
        .unwrap()
    else {
        panic!("storage must be refused");
    };
    assert_eq!(budget.used(), used);
    let MuxOp::Child(id, StreamCommand::Write(payload)) = command.into_op() else {
        panic!("write returned");
    };
    assert_eq!(id, child.id());
    assert!(payload.shares(&original));
    drop(held);
    pair.client
        .command(child.send(StreamCommand::Write(payload)));
    pair.drive();
    let (remote, _) = pair.server.opened();
    pair.server.command(remote.grant(original.len() as u64));
    pair.drive();
    assert!(pair.server.events.iter().any(|event| matches!(event,
        MuxEvent::Child(id, StreamEvent::Data(bytes)) if *id == remote.id() && bytes.as_ref() == b"owned by caller")));
}

#[test]
fn closing_retires_the_lower_carrier_after_the_drain_timer() {
    let mut pair = Pair::new();
    pair.handshake();
    pair.client
        .command(MuxCommand::control(ControlCommand::Close(
            VarInt::from_u32(0),
        )));
    let mut ended = false;
    let mut lower_end = false;
    for _ in 0..20 {
        pair.client.driver.run().unwrap();
        while let Some(event) = pair.client.driver.layer_mut().take_event() {
            if matches!(event, MuxEvent::Control(ControlEvent::Ended)) {
                ended = true;
            }
        }
        while let Some(command) = pair.client.driver.take_command() {
            match command {
                DatagramCommand::Send(_) => {
                    assert!(matches!(
                        pair.client.driver.deliver(DatagramEvent::Sent(1)).unwrap(),
                        Admit::Taken
                    ));
                }
                DatagramCommand::End => {
                    assert!(ended);
                    lower_end = true;
                }
            }
        }
        if pair.client.driver.layer().is_terminal() {
            break;
        }
        let deadline = pair.client.driver.deadline().expect("drain timer");
        pair.client.driver.set_now(deadline);
    }
    assert!(ended && lower_end);
    assert!(pair.client.driver.layer().is_terminal());
    assert!(pair.client.driver.take_command().is_none());
}

#[test]
fn queued_writes_do_not_postpone_reading_the_reverse_direction() {
    exercise_queued_writes(false);
}

#[test]
fn queued_application_datagrams_do_not_postpone_stream_reads() {
    exercise_queued_writes(true);
}

fn exercise_queued_writes(datagrams: bool) {
    let mut pair = Pair::with_datagrams(datagrams);
    pair.handshake();
    pair.client
        .command(MuxCommand::control(ControlCommand::Open(Dir::Bi)));
    pair.drive();
    let (client, _) = pair.client.opened();
    pair.client.command(client.send(StreamCommand::Write(
        Chunk::copy_of(pair.client.driver.budget(), b"open").unwrap(),
    )));
    pair.drive();
    let (server, _) = pair.server.opened();
    pair.client.command(client.grant(5));
    for _ in 0..100 {
        pair.client.command(client.send(StreamCommand::Write(
            Chunk::copy_of(pair.client.driver.budget(), b"x").unwrap(),
        )));
    }
    pair.server.command(server.send(StreamCommand::Write(
        Chunk::copy_of(pair.server.driver.budget(), b"reply").unwrap(),
    )));
    if datagrams {
        pair.client
            .command(MuxCommand::control(ControlCommand::ReceiveDatagrams(8)));
        for _ in 0..8 {
            let data = Chunk::copy_of(pair.server.driver.budget(), b"datagram").unwrap();
            pair.server.command(application_datagram(data, false));
            pair.server.driver.run().unwrap();
            assert!(Pair::transfer(&mut pair.server, &mut pair.client, false));
        }
    } else {
        pair.server.driver.run().unwrap();
        assert!(Pair::transfer(&mut pair.server, &mut pair.client, false));
    }
    let entropy = SeededEntropy::new(Seed::from_u64(8));
    let budget = pair.client.driver.budget().clone();
    let mut observed = Observations::new(0);
    let mut env = Env::new(pair.client.driver.now(), &entropy, &budget, &mut observed);
    let mut written = 0;
    let mut read = false;
    let mut received_datagrams = 0;
    for _ in 0..10 {
        pair.client.driver.layer_mut().advance(&mut env).unwrap();
        while let Some(event) = pair.client.driver.layer_mut().take_event() {
            match event {
                MuxEvent::Child(_, StreamEvent::Written(n)) => written += n,
                MuxEvent::Child(_, StreamEvent::Data(bytes)) => {
                    assert_eq!(bytes.as_ref(), b"reply");
                    read = true;
                }
                MuxEvent::Control(ControlEvent::Datagram(DatagramEvent::Datagram(_))) => {
                    received_datagrams += 1
                }
                _ => {}
            }
        }
        if read {
            break;
        }
    }
    assert!(read, "reading progresses before the write queue drains");
    assert!(written < 100);
    assert!(
        received_datagrams < 8,
        "reading progresses before the datagram queue drains"
    );
}

#[test]
fn sustained_streams_survive_loss_duplicates_and_reordering() {
    struct Transfer {
        child: Child,
        output: Vec<u8>,
        sent: usize,
        written: u64,
        credit: u64,
        input: Vec<u8>,
        ended: bool,
        finished: bool,
    }
    impl Transfer {
        fn step(&mut self, peer: &mut Peer) {
            for event in std::mem::take(&mut peer.events) {
                match event {
                    MuxEvent::Credit(id, n) if id == self.child.id() => self.credit += n,
                    MuxEvent::Child(id, StreamEvent::Written(n)) if id == self.child.id() => {
                        self.written += n;
                    }
                    MuxEvent::Child(id, StreamEvent::Data(bytes)) if id == self.child.id() => {
                        assert!(!self.ended, "no bytes follow FIN");
                        self.input.extend_from_slice(&bytes);
                        peer.command(self.child.grant(bytes.len() as u64));
                    }
                    MuxEvent::Child(id, StreamEvent::Ended) if id == self.child.id() => {
                        assert!(!self.ended, "FIN is delivered once");
                        self.ended = true;
                    }
                    MuxEvent::Child(
                        _,
                        StreamEvent::ReceiveReset(_) | StreamEvent::SendStopped(_),
                    ) => {
                        panic!("loss does not cancel a reliable stream");
                    }
                    _ => {}
                }
            }
            if self.sent < self.output.len() && self.credit > 0 {
                let n = (self.output.len() - self.sent)
                    .min(self.credit as usize)
                    .min(977);
                let bytes =
                    Chunk::copy_of(peer.driver.budget(), &self.output[self.sent..self.sent + n])
                        .unwrap();
                peer.command(self.child.send(StreamCommand::Write(bytes)));
                self.sent += n;
                self.credit -= n as u64;
            }
            if self.sent == self.output.len() && !self.finished {
                peer.command(self.child.send(StreamCommand::End));
                self.finished = true;
            }
        }
    }

    struct Link {
        packets: std::collections::VecDeque<Chunk>,
        sent: usize,
        dropped: usize,
        duplicated: usize,
        reordered: usize,
    }
    impl Link {
        fn take(&mut self, from: &mut Peer, to: SocketAddr) {
            let Some(DatagramCommand::Send(packet)) = from.driver.take_command() else {
                return;
            };
            assert!(packet.wants_completion());
            assert_eq!(*packet.meta(), to);
            let (payload, _) = packet.into_parts();
            self.sent += 1;
            if self.sent.is_multiple_of(11) {
                self.dropped += 1;
            } else {
                if self.sent.is_multiple_of(7) {
                    self.packets.push_back(payload.slice(0..payload.len()));
                    self.duplicated += 1;
                }
                self.packets.push_back(payload);
            }
            assert!(matches!(
                from.driver.deliver(DatagramEvent::Sent(1)).unwrap(),
                Admit::Taken
            ));
        }

        fn deliver(&mut self, from: SocketAddr, to: &mut Peer, reverse: bool) {
            let packet = if reverse {
                self.reordered += usize::from(self.packets.len() > 1);
                self.packets.pop_back()
            } else {
                self.packets.pop_front()
            };
            let Some(payload) = packet else {
                return;
            };
            match to
                .driver
                .deliver(DatagramEvent::Datagram(Datagram::new(payload, from)))
                .unwrap()
            {
                Admit::Taken => {}
                Admit::Blocked(DatagramEvent::Datagram(packet)) => {
                    self.packets.push_front(packet.into_parts().0);
                }
                _ => panic!("live connection retains a refused datagram"),
            }
        }
    }

    let mut pair = Pair::new();
    pair.handshake();
    pair.client
        .command(MuxCommand::control(ControlCommand::Open(Dir::Bi)));
    pair.drive();
    let (client, _) = pair.client.opened();
    let output: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
    pair.client.command(client.send(StreamCommand::Write(
        Chunk::copy_of(pair.client.driver.budget(), &output[..1]).unwrap(),
    )));
    pair.drive();
    let (server, _) = pair.server.opened();
    pair.client.command(client.grant(127));
    pair.server.command(server.grant(113));
    let credit = pair
        .client
        .events
        .iter()
        .filter_map(|event| match event {
            MuxEvent::Credit(id, n) if *id == client.id() => Some(*n),
            _ => None,
        })
        .sum::<u64>();
    pair.client
        .events
        .retain(|event| !matches!(event, MuxEvent::Credit(..)));
    let mut transfers = [
        Transfer {
            child: client,
            output,
            sent: 1,
            written: 0,
            credit: credit - 1,
            input: Vec::new(),
            ended: false,
            finished: false,
        },
        Transfer {
            child: server,
            output: (0..96 * 1024).map(|i| (250 - i % 251) as u8).collect(),
            sent: 0,
            written: 0,
            credit: 0,
            input: Vec::new(),
            ended: false,
            finished: false,
        },
    ];
    let mut links = std::array::from_fn::<_, 2, _>(|_| Link {
        packets: Default::default(),
        sent: 0,
        dropped: 0,
        duplicated: 0,
        reordered: 0,
    });
    for round in 0..10000 {
        // Virtual network time drives both pacing and recovery. Packet
        // delivery occurs every third millisecond, alternately from each end
        // of the link queue. No host clock or sleeping drives this schedule.
        let now = Instant::from_since_start(Duration::from_millis(round));
        pair.client.driver.set_now(now);
        pair.server.driver.set_now(now);
        pair.client.driver.run().unwrap();
        pair.server.driver.run().unwrap();
        pair.client.events();
        pair.server.events();
        transfers[0].step(&mut pair.client);
        transfers[1].step(&mut pair.server);
        links[0].take(&mut pair.client, pair.server.address);
        links[1].take(&mut pair.server, pair.client.address);
        if round % 3 == 0 {
            links[0].deliver(pair.client.address, &mut pair.server, round % 2 == 0);
            links[1].deliver(pair.server.address, &mut pair.client, round % 2 != 0);
        }
        if transfers
            .iter()
            .all(|t| t.ended && t.written == t.output.len() as u64)
        {
            break;
        }
    }
    assert!(transfers.iter().all(|t| t.ended && t.finished));
    // Deliver the copies still in the link after both FINs. They must not
    // produce another byte or another terminal event.
    while links.iter().any(|link| !link.packets.is_empty()) {
        links[0].deliver(pair.client.address, &mut pair.server, false);
        links[1].deliver(pair.server.address, &mut pair.client, false);
        pair.drive();
        transfers[0].step(&mut pair.client);
        transfers[1].step(&mut pair.server);
    }
    assert_eq!(transfers[0].input, transfers[1].output);
    assert_eq!(transfers[1].input, transfers[0].output);
    for transfer in &transfers {
        assert_eq!(transfer.written, transfer.output.len() as u64);
    }
    for link in &links {
        assert!(link.dropped > 0 && link.duplicated > 0 && link.reordered > 0);
    }
    let budgets = [
        pair.client.driver.budget().clone(),
        pair.server.driver.budget().clone(),
    ];
    drop(links);
    drop(pair);
    assert!(budgets.iter().all(|budget| budget.used() == 0));
}

fn application_datagram(bytes: Chunk, tracked: bool) -> MuxCommand<ByteStream<VarInt>, Control> {
    let datagram = Datagram::new(bytes, ());
    MuxCommand::control(ControlCommand::Datagram(DatagramCommand::Send(
        if tracked {
            datagram.with_completion()
        } else {
            datagram
        },
    )))
}

fn datagram_payloads(peer: &Peer) -> Vec<Vec<u8>> {
    peer.events
        .iter()
        .filter_map(|event| match event {
            MuxEvent::Control(ControlEvent::Datagram(DatagramEvent::Datagram(datagram))) => {
                Some(datagram.payload().to_vec())
            }
            _ => None,
        })
        .collect()
}

fn datagram_completions(peer: &Peer) -> u64 {
    peer.events
        .iter()
        .filter_map(|event| match event {
            MuxEvent::Control(ControlEvent::Datagram(DatagramEvent::Sent(count))) => Some(count),
            _ => None,
        })
        .sum()
}

#[test]
fn application_datagrams_are_whole_and_independently_credited() {
    let mut pair = Pair::with_datagrams(true);
    pair.handshake();
    for (index, payload) in [&b"first"[..], &b""[..], &b"last"[..]]
        .into_iter()
        .enumerate()
    {
        for peer in [&mut pair.client, &mut pair.server] {
            let bytes = Chunk::copy_of(peer.driver.budget(), payload).unwrap();
            peer.command(application_datagram(bytes, true));
        }
        pair.drive();
        for _ in 0..10 {
            if datagram_completions(&pair.client) == index as u64 + 1
                && datagram_completions(&pair.server) == index as u64 + 1
            {
                break;
            }
            pair.tick();
        }
    }
    for peer in [&pair.client, &pair.server] {
        assert!(datagram_payloads(peer).is_empty());
        assert_eq!(datagram_completions(peer), 3);
    }
    pair.client
        .command(MuxCommand::control(ControlCommand::ReceiveDatagrams(1)));
    pair.drive();
    assert_eq!(datagram_payloads(&pair.client), [b"first".to_vec()]);
    assert!(datagram_payloads(&pair.server).is_empty());
    pair.client
        .command(MuxCommand::control(ControlCommand::ReceiveDatagrams(2)));
    pair.server
        .command(MuxCommand::control(ControlCommand::ReceiveDatagrams(3)));
    pair.drive();
    for peer in [&pair.client, &pair.server] {
        assert_eq!(
            datagram_payloads(peer),
            [b"first".to_vec(), vec![], b"last".to_vec()]
        );
    }
}

#[test]
fn application_receive_storage_is_charged_before_admission() {
    let mut pair = Pair::with_datagrams(true);
    pair.handshake();
    pair.server
        .command(MuxCommand::control(ControlCommand::ReceiveDatagrams(1)));
    // Reserve the layer's wire scratch before exhausting its budget so
    // this packet reaches the engine's application receive admission.
    assert!(matches!(
        pair.server
            .driver
            .deliver(DatagramEvent::Datagram(Datagram::new(
                Chunk::default(),
                pair.client.address
            ),))
            .unwrap(),
        Admit::Taken
    ));
    let budget = pair.server.driver.budget().clone();
    let held = budget.charge(budget.limit() - budget.used()).unwrap();
    let first = Chunk::copy_of(pair.client.driver.budget(), b"drop").unwrap();
    pair.client.command(application_datagram(first, false));
    pair.drive();
    assert!(datagram_payloads(&pair.server).is_empty());
    drop(held);
    pair.drive();
    assert!(datagram_payloads(&pair.server).is_empty());
    let next = Chunk::copy_of(pair.client.driver.budget(), b"keep").unwrap();
    pair.client.command(application_datagram(next, false));
    pair.drive();
    assert_eq!(datagram_payloads(&pair.server), [b"keep".to_vec()]);
    drop(pair);
    assert_eq!(budget.used(), 0);
}

#[test]
fn application_send_waits_for_lower_completion_and_keeps_refused_payload() {
    let mut pair = Pair::with_datagrams(true);
    pair.handshake();
    let bytes = Chunk::copy_of(pair.client.driver.budget(), b"first").unwrap();
    pair.client.command(application_datagram(bytes, true));
    let budget = Budget::new(4);
    let second = Chunk::copy_of(&budget, b"next").unwrap();
    let pointer = second.as_ptr();
    let Admit::Blocked(command) = pair
        .client
        .driver
        .command(application_datagram(second, true))
        .unwrap()
    else {
        panic!("one pending application datagram")
    };
    let MuxOp::Control(ControlCommand::Datagram(DatagramCommand::Send(datagram))) =
        command.into_op()
    else {
        panic!("same command")
    };
    assert_eq!(datagram.payload().as_ptr(), pointer);
    assert_eq!(datagram.payload(), b"next");
    assert!(datagram.wants_completion());
    assert_eq!(budget.used(), 4);
    for _ in 0..10 {
        pair.client.driver.run().unwrap();
        assert!(pair.client.driver.layer_mut().take_urgent().is_none());
        if let Some(DatagramCommand::Send(_)) = pair.client.driver.take_command() {
            assert!(pair.client.driver.layer_mut().take_urgent().is_none());
            assert!(matches!(
                pair.client.driver.deliver(DatagramEvent::Sent(1)).unwrap(),
                Admit::Taken
            ));
            if let Some(event) = pair.client.driver.layer_mut().take_urgent() {
                assert!(matches!(
                    event,
                    MuxEvent::Control(ControlEvent::Datagram(DatagramEvent::Sent(1)))
                ));
                assert!(Quic::urgent(&event));
                assert!(pair.client.driver.layer_mut().take_urgent().is_none());
                return;
            }
        }
        let at = pair.client.driver.deadline().unwrap();
        pair.client.driver.set_now(at);
    }
    panic!("application datagram never retired");
}

#[test]
fn unsupported_and_unpaid_datagrams_preserve_ownership() {
    for enabled in [false, true] {
        let mut pair = Pair::with_datagrams(enabled);
        pair.handshake();
        let source = Budget::new(4);
        let bytes = Chunk::copy_of(&source, b"held").unwrap();
        let pointer = bytes.as_ptr();
        let budget = pair.client.driver.budget();
        let _full = budget.charge(budget.limit() - budget.used()).unwrap();
        let result = pair
            .client
            .driver
            .command(application_datagram(bytes, true))
            .unwrap();
        let command = match result {
            Admit::Blocked(command) if enabled => command,
            Admit::Closed(command) if !enabled => command,
            _ => panic!("refusal must preserve the command"),
        };
        let MuxOp::Control(ControlCommand::Datagram(DatagramCommand::Send(datagram))) =
            command.into_op()
        else {
            panic!("datagram")
        };
        assert_eq!(datagram.payload().as_ptr(), pointer);
        assert_eq!(datagram.payload(), b"held");
        assert!(datagram.wants_completion());
        assert_eq!(source.used(), 4);
        assert!(pair.client.driver.layer_mut().take_urgent().is_none());
    }
}

#[test]
fn oversized_application_datagrams_retire_locally_without_closing() {
    let mut pair = Pair::with_datagrams(true);
    pair.handshake();
    let maximum = pair
        .client
        .events
        .iter()
        .find_map(|event| match event {
            MuxEvent::Control(ControlEvent::DatagramSize(Some(limit))) => Some(*limit),
            _ => None,
        })
        .unwrap();
    let bytes = Chunk::copy_of(pair.client.driver.budget(), &vec![0; maximum + 1]).unwrap();
    pair.client.command(application_datagram(bytes, true));
    pair.drive();
    assert_eq!(datagram_completions(&pair.client), 1);
    assert!(datagram_payloads(&pair.server).is_empty());
    pair.client
        .command(MuxCommand::control(ControlCommand::Open(Dir::Bi)));
    pair.drive();
    pair.client.opened();
}

#[test]
fn application_completion_passes_blocked_application_input() {
    let mut pair = Pair::with_datagrams(true);
    pair.handshake();
    pair.client
        .command(MuxCommand::control(ControlCommand::ReceiveDatagrams(1)));
    let input = Chunk::copy_of(pair.server.driver.budget(), b"pending").unwrap();
    pair.server.command(application_datagram(input, false));
    let output = Chunk::copy_of(pair.client.driver.budget(), b"reply").unwrap();
    pair.client.command(application_datagram(output, true));
    let mut completed = false;
    for _ in 0..100 {
        pair.server.driver.run().unwrap();
        Pair::transfer(&mut pair.server, &mut pair.client, false);
        pair.client.driver.run().unwrap();
        Pair::transfer(&mut pair.client, &mut pair.server, false);
        if let Some(event) = pair.client.driver.layer_mut().take_urgent() {
            assert!(matches!(
                event,
                MuxEvent::Control(ControlEvent::Datagram(DatagramEvent::Sent(1)))
            ));
            assert!(Quic::urgent(&event));
            completed = true;
            break;
        }
    }
    assert!(completed);
    pair.drive();
    assert_eq!(datagram_payloads(&pair.client), [b"pending".to_vec()]);
    assert!(pair.client.driver.layer_mut().take_urgent().is_none());
}

#[test]
fn required_stream_exhaustion_closes_with_the_callers_error() {
    let mut pair = Pair::new();
    pair.handshake();
    for _ in 0..8 {
        pair.client
            .command(MuxCommand::control(ControlCommand::Open(Dir::Uni)));
        pair.drive();
        let _ = pair.client.opened();
    }
    assert!(matches!(
        pair.client
            .driver
            .command(MuxCommand::control(ControlCommand::Open(Dir::Uni)))
            .unwrap(),
        Admit::Blocked(_)
    ));
    let code = VarInt::from_u32(0xabc);
    pair.client
        .command(MuxCommand::control(ControlCommand::OpenOrClose {
            direction: Dir::Uni,
            error: code,
        }));
    pair.client.driver.run().unwrap();
    assert!(Pair::transfer(&mut pair.client, &mut pair.server, false));
    pair.server.driver.run().unwrap();
    while let Some(event) = pair.server.driver.layer_mut().take_event() {
        pair.server.events.push(event);
    }
    assert!(pair.server.events.iter().any(|event| matches!(event,
        MuxEvent::Control(ControlEvent::Lost(quinn_proto::ConnectionError::ApplicationClosed(error))) if error.error_code == code)));
}

/// QUIC version 2 and version negotiation through two layers on the
/// simulated datagram carrier
mod versions {
    // Each test checks the version both layers settle on, the versions of the
    // long headers each peer put on the carrier, and that a stream carries
    // bytes both ways, which needs both sides to derive one version's keys.

    use super::*;

    /// The packet type bits of a long header's first byte that mean Retry in
    /// `version` (RFC 9000 section 17.2, RFC 9369 section 3.2)
    fn is_retry(first: u8, version: u32) -> bool {
        let bits = (first >> 4) & 0b11;
        match version {
            QUIC_V2 => bits == 0b00,
            _ => bits == 0b11,
        }
    }

    fn versions(peer: &Peer) -> Vec<u32> {
        peer.long_headers
            .iter()
            .map(|&(_, version)| version)
            .collect()
    }

    fn settled(pair: &Pair) -> (Option<u32>, Option<u32>) {
        (
            pair.client.driver.layer().version(),
            pair.server.driver.layer().version(),
        )
    }

    /// Open a stream, send a request one way and a response the other
    fn exchange(pair: &mut Pair) {
        pair.client
            .command(MuxCommand::control(ControlCommand::Open(Dir::Bi)));
        pair.drive();
        let (client, _) = pair.client.opened();
        pair.client.command(client.grant(64));
        pair.client.command(client.send(StreamCommand::Write(
            Chunk::copy_of(pair.client.driver.budget(), b"request").unwrap(),
        )));
        pair.client.command(client.send(StreamCommand::End));
        pair.drive();
        let (server, _) = pair.server.opened();
        pair.server.command(server.grant(64));
        pair.drive();
        assert!(pair.server.events.iter().any(|event| matches!(
            event,
            MuxEvent::Child(id, StreamEvent::Data(data)) if *id == server.id() && data.as_ref() == b"request"
        )));
        pair.server.command(server.send(StreamCommand::Write(
            Chunk::copy_of(pair.server.driver.budget(), b"response").unwrap(),
        )));
        pair.server.command(server.send(StreamCommand::End));
        pair.drive();
        assert!(pair.client.events.iter().any(|event| matches!(
            event,
            MuxEvent::Child(id, StreamEvent::Data(data)) if *id == client.id() && data.as_ref() == b"response"
        )));
    }

    #[test]
    fn a_version_2_first_flight_completes_in_version_2() {
        let mut pair = Pair::versions(
            QUIC_V2,
            &[QUIC_V2],
            &[QUIC_V1, QUIC_V2],
            AddressValidation::Accept,
        );
        pair.handshake();
        exchange(&mut pair);
        assert_eq!(settled(&pair), (Some(QUIC_V2), Some(QUIC_V2)));
        for peer in [&pair.client, &pair.server] {
            let sent = versions(peer);
            assert!(!sent.is_empty());
            assert!(sent.iter().all(|&version| version == QUIC_V2), "{sent:x?}");
        }
    }

    #[test]
    fn a_server_preferring_version_2_upgrades_a_version_1_first_flight() {
        let mut pair = Pair::versions(
            QUIC_V1,
            &[QUIC_V2, QUIC_V1],
            &[QUIC_V2, QUIC_V1],
            AddressValidation::Accept,
        );
        pair.handshake();
        exchange(&mut pair);
        assert_eq!(settled(&pair), (Some(QUIC_V2), Some(QUIC_V2)));
        let client = versions(&pair.client);
        let server = versions(&pair.server);
        assert_eq!(client[0], QUIC_V1, "the first flight is in version 1");
        assert!(
            server.iter().all(|&version| version == QUIC_V2),
            "{server:x?}"
        );
        let switched = client
            .iter()
            .position(|&version| version == QUIC_V2)
            .unwrap();
        assert!(client[switched..].iter().all(|&version| version == QUIC_V2));
    }

    #[test]
    fn a_client_that_offers_only_version_1_keeps_it() {
        let mut pair = Pair::versions(
            QUIC_V1,
            &[QUIC_V1],
            &[QUIC_V2, QUIC_V1],
            AddressValidation::Accept,
        );
        pair.handshake();
        exchange(&mut pair);
        assert_eq!(settled(&pair), (Some(QUIC_V1), Some(QUIC_V1)));
        for peer in [&pair.client, &pair.server] {
            assert!(versions(peer).iter().all(|&version| version == QUIC_V1));
        }
    }

    #[test]
    fn a_version_2_retry_is_answered_in_version_2() {
        let mut pair = Pair::versions(
            QUIC_V2,
            &[QUIC_V2],
            &[QUIC_V1, QUIC_V2],
            AddressValidation::Retry,
        );
        pair.handshake();
        exchange(&mut pair);
        assert_eq!(settled(&pair), (Some(QUIC_V2), Some(QUIC_V2)));
        let (first, version) = pair.server.long_headers[0];
        assert_eq!(version, QUIC_V2);
        assert!(is_retry(first, version), "{first:#x}");
        assert!(!is_retry(first, QUIC_V1));
        assert!(
            versions(&pair.client)
                .iter()
                .all(|&version| version == QUIC_V2)
        );
    }

    #[test]
    fn a_retry_keeps_the_original_version_before_an_upgrade() {
        let mut pair = Pair::versions(
            QUIC_V1,
            &[QUIC_V2, QUIC_V1],
            &[QUIC_V2, QUIC_V1],
            AddressValidation::Retry,
        );
        pair.handshake();
        exchange(&mut pair);
        assert_eq!(settled(&pair), (Some(QUIC_V2), Some(QUIC_V2)));
        let (first, version) = pair.server.long_headers[0];
        assert_eq!(version, QUIC_V1);
        assert!(is_retry(first, version), "{first:#x}");
        // The Initial carrying the token stays in version 1; the server's
        // answer to it upgrades.
        assert_eq!(&versions(&pair.client)[..2], &[QUIC_V1, QUIC_V1]);
        let server = versions(&pair.server);
        assert!(
            server[1..].iter().all(|&version| version == QUIC_V2),
            "{server:x?}"
        );
    }

    #[test]
    fn version_negotiation_moves_the_client_to_version_2() {
        let mut pair = Pair::versions(
            QUIC_V1,
            &[QUIC_V1, QUIC_V2],
            &[QUIC_V2],
            AddressValidation::Accept,
        );
        pair.handshake();
        exchange(&mut pair);
        assert_eq!(settled(&pair), (Some(QUIC_V2), Some(QUIC_V2)));
        let client = versions(&pair.client);
        let server = versions(&pair.server);
        assert_eq!(client[0], QUIC_V1);
        assert_eq!(server[0], 0, "a Version Negotiation packet");
        assert!(
            client[1..].iter().all(|&version| version == QUIC_V2),
            "{client:x?}"
        );
        assert!(
            server[1..].iter().all(|&version| version == QUIC_V2),
            "{server:x?}"
        );
    }
}
