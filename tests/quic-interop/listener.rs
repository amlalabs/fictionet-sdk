use super::*;

struct Client {
    quic: quiche::Connection,
    http: Option<quiche::h3::Connection>,
    local: SocketAddr,
    remote: SocketAddr,
    payload: Vec<u8>,
    sent: Option<(u64, usize)>,
    received: Vec<u8>,
    finished: bool,
    rotated: bool,
}

impl Client {
    fn new(number: u8, local: SocketAddr, remote: SocketAddr) -> Self {
        let mut config = super::super::interop::configuration();
        config.set_application_protos(&[b"h3"]).unwrap();
        let cid_bytes = [number; 16];
        let cid = quiche::ConnectionId::from_ref(&cid_bytes);
        Self {
            quic: quiche::connect(Some("localhost"), &cid, local, remote, &mut config).unwrap(),
            http: None,
            local,
            remote,
            payload: (0..20000).map(|n| (n as u8).wrapping_add(number)).collect(),
            sent: None,
            received: Vec::new(),
            finished: false,
            rotated: false,
        }
    }

    /// Whether the connection is open: not closed, and not closing at the
    /// listener's word.
    fn open(&self) -> bool {
        !self.quic.is_closed() && self.quic.peer_error().is_none()
    }

    fn receive(&mut self, bytes: &mut [u8]) {
        self.quic
            .recv(
                bytes,
                quiche::RecvInfo {
                    from: self.remote,
                    to: self.local,
                },
            )
            .unwrap();
    }

    fn progress(&mut self) {
        assert!(
            self.quic.peer_error().is_none(),
            "{:?}",
            self.quic.peer_error()
        );
        if self.quic.is_established() && self.http.is_none() {
            assert_eq!(self.quic.application_proto(), b"h3");
            self.http = Some(
                quiche::h3::Connection::with_transport(
                    &mut self.quic,
                    &quiche::h3::Config::new().unwrap(),
                )
                .unwrap(),
            );
        }
        if !self.rotated && self.quic.available_dcids() > 0 {
            let previous = self.quic.destination_id().into_owned();
            self.quic.retire_dcid(0).unwrap();
            assert_ne!(self.quic.destination_id(), previous);
            self.rotated = true;
        }
        let Some(h3) = &mut self.http else { return };
        if self.sent.is_none() {
            let length = self.payload.len().to_string();
            let headers = [
                quiche::h3::Header::new(b":method", b"POST"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"localhost"),
                quiche::h3::Header::new(b":path", b"/echo"),
                quiche::h3::Header::new(b"content-length", length.as_bytes()),
                quiche::h3::Header::new(b"cookie", b"a=1; b=2"),
            ];
            self.sent = Some((h3.send_request(&mut self.quic, &headers, false).unwrap(), 0));
        }
        let (id, offset) = self.sent.as_mut().unwrap();
        if *offset < self.payload.len() {
            match h3.send_body(&mut self.quic, *id, &self.payload[*offset..], true) {
                Ok(n) => *offset += n,
                Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {}
                Err(error) => panic!("upload: {error:?}"),
            }
        }
        let mut buffer = [0; 65535];
        loop {
            match h3.poll(&mut self.quic) {
                Ok((_, quiche::h3::Event::Headers { list, .. })) => assert!(
                    list.iter()
                        .any(|h| h.name() == b":status" && h.value() == b"200")
                ),
                Ok((_, quiche::h3::Event::Data)) => {
                    while let Ok(n) = h3.recv_body(&mut self.quic, *id, &mut buffer) {
                        self.received.extend_from_slice(&buffer[..n]);
                    }
                }
                Ok((_, quiche::h3::Event::Finished)) => {
                    assert_eq!(self.received, self.payload);
                    assert!(!self.finished);
                    self.finished = true;
                }
                Ok(event) => panic!("HTTP/3 event: {event:?}"),
                Err(quiche::h3::Error::Done) => break,
                Err(error) => panic!("HTTP/3: {error:?}"),
            }
        }
    }
}

/// Echoes, after checking and recording the connection each request came
/// over.
struct Recording {
    local: SocketAddr,
    seen: Arc<std::sync::Mutex<Vec<stdlib::network::ConnInfo>>>,
}

impl httpd::Handler for Recording {
    fn call(&self, request: web::Request, ex: &mut httpd::Exchange<'_>) -> httpd::Reply {
        let info = ex.conn();
        assert_eq!(info.local, Some(self.local));
        assert!(info.tls);
        assert_eq!(info.alpn.as_deref(), Some(b"h3".as_slice()));
        assert_eq!(info.sni.as_deref(), Some("localhost"));
        self.seen.lock().unwrap().push(info.clone());
        httpd::Handler::call(&Echo { streamed: false }, request, ex)
    }
}

fn listener_config(
    entropy: Arc<dyn Entropy>,
    connections: usize,
    connection_budget: usize,
    validation: AddressValidation,
    controller: Arc<dyn quinn_proto::congestion::ControllerFactory + Send + Sync>,
) -> ListenerConfig {
    let (_, server, endpoint) = configs_with_controller(entropy, false, b"h3", controller);
    ListenerConfig {
        endpoint,
        server: Arc::new(server),
        connections,
        streams: 16,
        connection_budget,
        validation,
        cancel: |_| 0x10cu32.into(),
    }
}

fn listener_stack(
    entropy: Arc<dyn Entropy>,
    local: SocketAddr,
    connections: usize,
    seen: Arc<std::sync::Mutex<Vec<stdlib::network::ConnInfo>>>,
) -> httpd::Http3Listener {
    listener_stack_with_controller(
        entropy,
        local,
        connections,
        seen,
        Arc::new(quinn_proto::congestion::CubicConfig::default()),
    )
}

fn listener_stack_with_controller(
    entropy: Arc<dyn Entropy>,
    local: SocketAddr,
    connections: usize,
    seen: Arc<std::sync::Mutex<Vec<stdlib::network::ConnInfo>>>,
    controller: Arc<dyn quinn_proto::congestion::ControllerFactory + Send + Sync>,
) -> httpd::Http3Listener {
    let config = listener_config(
        entropy,
        connections,
        8 << 20,
        AddressValidation::Accept,
        controller,
    );
    let listener = Listener::new(config, std::time::Instant::now(), Some(local));
    httpd::Responder::new(Recording { local, seen }).http3_listener(listener)
}

#[test]
fn listener_routes_simultaneous_http3_connections_by_id_and_reuses_slots() {
    let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(72)));
    let local = "127.0.0.1:4433".parse().unwrap();
    // All clients deliberately share the same socket address. Routing by
    // peer address would cross their cryptographic and HTTP request state.
    let remote = "127.0.0.1:4444".parse().unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let stack = listener_stack(entropy.clone(), local, 3, seen.clone());
    let mut sdk = Driver::new(stack, entropy, Budget::new(64 << 20), Instant::ZERO);
    let mut worker = stdlib::services::stack::Polling::new();
    let mut buffer = [0; 65535];
    for round in 0..3 {
        let mut peers: Vec<_> = (0..3)
            .map(|n| Client::new(1 + round * 3 + n, remote, local))
            .collect();
        let mut finished = false;
        for _ in 0..10000 {
            sdk.run().unwrap();
            worker.work(&mut sdk).unwrap();
            sdk.run().unwrap();
            if let Some(DatagramCommand::Send(datagram)) = sdk.take_command() {
                assert_eq!(*datagram.meta(), remote);
                let mut bytes = datagram.into_parts().0.into_vec();
                let header = quiche::Header::from_slice(&mut bytes, 16).unwrap();
                let peer = peers
                    .iter_mut()
                    .find(|peer| peer.quic.source_ids().any(|id| *id == header.dcid))
                    .expect("destination connection ID");
                peer.receive(&mut bytes);
                assert!(matches!(
                    sdk.deliver(DatagramEvent::Sent(1)).unwrap(),
                    Admit::Taken
                ));
            }
            for peer in &mut peers {
                peer.progress();
                while let Ok((n, _)) = peer.quic.send(&mut buffer) {
                    let chunk = Chunk::copy_of(sdk.budget(), &buffer[..n]).unwrap();
                    assert!(matches!(
                        sdk.deliver(DatagramEvent::Datagram(Datagram::new(chunk, remote)))
                            .unwrap(),
                        Admit::Taken
                    ));
                }
            }
            if peers.iter().all(|p| p.finished) {
                finished = true;
                break;
            }
        }
        assert!(finished, "HTTP/3 connections stalled");
        assert!(peers.iter().all(|peer| peer.rotated));
        assert_eq!(seen.lock().unwrap().len(), (round as usize + 1) * 3);
        for peer in &mut peers {
            peer.quic.close(true, 0x100, b"").unwrap();
            while let Ok((n, _)) = peer.quic.send(&mut buffer) {
                let chunk = Chunk::copy_of(sdk.budget(), &buffer[..n]).unwrap();
                assert!(matches!(
                    sdk.deliver(DatagramEvent::Datagram(Datagram::new(chunk, remote)))
                        .unwrap(),
                    Admit::Taken
                ));
            }
        }
        // Exercise the actual draining deadline, not wall-clock waiting.
        sdk.set_now(Instant::from_since_start(Duration::from_secs(
            (round as u64 + 1) * 10,
        )));
        for _ in 0..100 {
            sdk.run().unwrap();
            worker.work(&mut sdk).unwrap();
            if let Some(DatagramCommand::Send(_)) = sdk.take_command() {
                assert!(matches!(
                    sdk.deliver(DatagramEvent::Sent(1)).unwrap(),
                    Admit::Taken
                ));
            }
        }
    }
}

#[test]
fn world_udp_host_serves_several_http3_connections_on_one_socket() {
    use fictionet_test_support::{sandbox::machine, world::world};
    use stdlib::world::net::{Net, Pools};
    world(Duration::from_secs(60), |fcx| async move {
        let local: SocketAddr = "104.18.0.7:443".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:4000".parse().unwrap();
        let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(73)));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = seen.clone();
        let (attacher, attachments) = fictionet::attachments();
        Net::new(Pools::NONE)
            .ipv4_only()
            .host("http3", move |host| {
                host.at(local.ip())
                    .udp_stack(443, Budget::new(64 << 20), move |info| {
                        listener_stack(entropy.clone(), info.local.unwrap(), 3, observed.clone())
                    })
            })
            .start(&fcx, attachments)?;
        let client = machine(&fcx, attacher.attach("client")?, remote.ip());
        let mut socket = client.udp.bind(remote.port())?;
        let mut peers: Vec<_> = (0..3).map(|n| Client::new(41 + n, remote, local)).collect();
        let mut buffer = [0; 65535];
        loop {
            for peer in &mut peers {
                peer.progress();
                while let Ok((n, info)) = peer.quic.send(&mut buffer) {
                    socket.send_to(&buffer[..n], info.to);
                }
            }
            if peers.iter().all(|peer| peer.finished) {
                break;
            }
            let (mut bytes, source) = socket.recv(&fcx).await?;
            assert_eq!(source, local);
            let header = quiche::Header::from_slice(&mut bytes, 16).unwrap();
            let peer = peers
                .iter_mut()
                .find(|peer| peer.quic.source_ids().any(|id| *id == header.dcid))
                .expect("destination connection ID");
            peer.receive(&mut bytes);
        }
        assert!(peers.iter().all(|peer| peer.rotated));
        let observed = seen.lock().unwrap();
        assert_eq!(observed.len(), 3);
        assert!(observed.iter().all(|info| info.peer == Some(remote)));
        Ok(())
    });
}

#[test]
fn world_http3_transfers_recover_from_bidirectional_handshake_and_packet_loss() {
    use fictionet_test_support::{Done, ended_with_done, sandbox::machine, within};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use stdlib::network::{Direction, delay, filter};
    use stdlib::world::net::{Net, Pools};

    within(Duration::from_secs(60), || {
        ended_with_done(fictionet::block_on(fictionet::run(
            Seed::from_u64(74),
            |fcx| async move {
                let local: SocketAddr = "104.18.0.7:443".parse().unwrap();
                let remote: SocketAddr = "10.0.0.2:4000".parse().unwrap();
                let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(74)));
                let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
                let observed = seen.clone();
                let (attacher, attachments) = fictionet::attachments();
                Net::new(Pools::NONE)
                    .ipv4_only()
                    .host("http3", move |host| {
                        host.at(local.ip())
                            .udp_stack(443, Budget::new(64 << 20), move |info| {
                                listener_stack_with_controller(
                                    entropy.clone(),
                                    info.local.unwrap(),
                                    3,
                                    observed.clone(),
                                    Arc::new(quinn_proto::congestion::BbrConfig::default()),
                                )
                            })
                    })
                    .start(&fcx, attachments)?;
                let dropped = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
                let losses = dropped.clone();
                let mut packets = [0usize; 2];
                let lossy = filter(&fcx, attacher.attach("client")?, move |_, direction, _| {
                    let side = usize::from(direction == Direction::ToInner);
                    packets[side] += 1;
                    // Lose the first flight in both directions, then recurring packets
                    // throughout the transfer, including retransmissions and ACKs.
                    let keep = packets[side] != 1 && packets[side] % 17 != 0;
                    if !keep {
                        losses[side].fetch_add(1, Ordering::Relaxed);
                    }
                    keep
                });
                let client = machine(
                    &fcx,
                    delay(&fcx, Duration::from_millis(1), lossy),
                    remote.ip(),
                );
                let mut socket = client.udp.bind(remote.port())?;
                let mut peers: Vec<_> = (0..3)
                    .map(|n| {
                        let mut peer = Client::new(51 + n, remote, local);
                        peer.payload = (0..(1 << 20)).map(|i| (i as u8).wrapping_add(n)).collect();
                        peer
                    })
                    .collect();
                let mut buffer = [0; 65535];
                let finish_by = fcx.now() + Duration::from_secs(45);
                loop {
                    assert!(fcx.now() < finish_by, "HTTP/3 transfer did not complete");
                    for peer in &mut peers {
                        peer.progress();
                        loop {
                            match peer.quic.send(&mut buffer) {
                                Ok((n, info)) => socket.send_to(&buffer[..n], info.to),
                                Err(quiche::Error::Done) => break,
                                Err(error) => panic!("independent send: {error:?}"),
                            }
                        }
                    }
                    if peers.iter().all(|peer| peer.finished) {
                        break;
                    }
                    let timeout = peers
                        .iter()
                        .filter_map(|peer| peer.quic.timeout())
                        .min()
                        .unwrap();
                    match fcx
                        .race(
                            Some((fcx.now() + timeout).min(finish_by)),
                            socket.recv(&fcx),
                        )
                        .await
                    {
                        Ok(packet) => {
                            let (mut bytes, source) = packet?;
                            assert_eq!(source, local);
                            let header = quiche::Header::from_slice(&mut bytes, 16).unwrap();
                            let peer = peers
                                .iter_mut()
                                .find(|peer| peer.quic.source_ids().any(|id| *id == header.dcid))
                                .unwrap();
                            peer.receive(&mut bytes);
                        }
                        Err(fictionet::RaceError::Deadline) => {
                            for peer in &mut peers {
                                peer.quic.on_timeout();
                            }
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                assert!(
                    dropped
                        .iter()
                        .all(|count| count.load(Ordering::Relaxed) > 10)
                );
                assert_eq!(seen.lock().unwrap().len(), 3);
                Err(fictionet::Error::from(Done))
            },
        )))
        .unwrap();
    });
}

#[test]
fn refused_listener_admission_allocates_nothing() {
    use crate::cost::{Charged, Costs, Linear};
    let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(94)));
    let (_, server, endpoint) = configs_with_protocol(entropy.clone(), false, b"h3");
    let budget = Budget::new(0);
    let mut reports = Observations::new(0);
    let mut env = Env::new(Instant::ZERO, entropy.as_ref(), &budget, &mut reports);
    let config = ListenerConfig {
        endpoint,
        server: Arc::new(server),
        connections: 3,
        streams: 16,
        connection_budget: 1 << 20,
        validation: AddressValidation::Accept,
        cancel: |_| 0u32.into(),
    };
    let epoch = std::time::Instant::now();
    // Configuration and caller-owned input precede admission. A refused
    // listener must not create its endpoint, queues or packet copies.
    let input = DatagramEvent::Datagram(Datagram::new(
        Chunk::unpaid(vec![0; 1200]),
        "127.0.0.1:4444".parse().unwrap(),
    ));
    let mut costs = Costs::new("QUIC listener refusal");
    let (listener, refused) = costs.step(
        1200,
        0,
        Linear {
            num: 0,
            den: 1,
            fixed: 0,
        },
        || {
            let mut listener = Listener::new(config, epoch, None);
            let result = listener.on_event(&mut env, input).unwrap();
            assert!(matches!(result, Admit::Blocked(_)));
            Charged::new((listener, result), budget.used())
        },
    );
    drop((listener, refused));
    assert_eq!(budget.used(), 0);
}

struct Unread;
impl Layer for Unread {
    type Lower = Quic;
    type Upper = Top;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = std::io::Error;
    fn on_event(&mut self, _: &mut Env<'_, ()>, event: Event) -> Result<Admit<Event>, Self::Error> {
        Ok(Admit::Blocked(event))
    }
    fn on_command(
        &mut self,
        _: &mut Env<'_, ()>,
        never: std::convert::Infallible,
    ) -> Result<Admit<std::convert::Infallible>, Self::Error> {
        match never {}
    }
    fn take_command(
        &mut self,
        _: &mut Env<'_, ()>,
    ) -> Option<MuxCommand<ByteStream<VarInt>, Control>> {
        None
    }
    fn take_event(&mut self) -> Option<std::convert::Infallible> {
        None
    }
}

#[test]
fn an_unread_connection_does_not_block_another_http3_handler() {
    use stdlib::services::stack::Boxed;
    let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(95)));
    let local = "127.0.0.1:4433".parse().unwrap();
    let blocked = "127.0.0.1:4444".parse().unwrap();
    let active = "127.0.0.1:4445".parse().unwrap();
    let (_, server, endpoint) = configs_with_protocol(entropy.clone(), false, b"h3");
    let listener = Listener::new(
        ListenerConfig {
            endpoint,
            server: Arc::new(server),
            connections: 2,
            streams: 16,
            connection_budget: 8 << 20,
            validation: AddressValidation::Accept,
            cancel: |_| 0x10cu32.into(),
        },
        std::time::Instant::now(),
        Some(local),
    );
    let stack = Chain::new(
        listener,
        Children::new(2, 0, move |_, accepted: Accepted, _| {
            Some(if accepted.info.peer == Some(blocked) {
                Boxed::new(Unread)
            } else {
                Boxed::new(
                    httpd::Responder::new(Echo { streamed: false })
                        .conn(accepted.info)
                        .http3(),
                )
            })
        })
        .budgets(|_, accepted: &Accepted, _| accepted.budget.clone()),
    );
    let mut sdk = Driver::new(stack, entropy, Budget::new(64 << 20), Instant::ZERO);
    let mut worker = stdlib::services::stack::Polling::new();
    let mut peers = [
        Client::new(61, blocked, local),
        Client::new(62, active, local),
    ];
    let mut buffer = [0; 65535];
    for _ in 0..10000 {
        sdk.run().unwrap();
        worker.work(&mut sdk).unwrap();
        sdk.run().unwrap();
        if let Some(DatagramCommand::Send(datagram)) = sdk.take_command() {
            let peer = peers
                .iter_mut()
                .find(|peer| peer.local == *datagram.meta())
                .unwrap();
            peer.receive(&mut datagram.into_parts().0.into_vec());
            assert!(matches!(
                sdk.deliver(DatagramEvent::Sent(1)).unwrap(),
                Admit::Taken
            ));
        }
        for peer in &mut peers {
            peer.progress();
            while let Ok((n, _)) = peer.quic.send(&mut buffer) {
                let chunk = Chunk::copy_of(sdk.budget(), &buffer[..n]).unwrap();
                assert!(matches!(
                    sdk.deliver(DatagramEvent::Datagram(Datagram::new(chunk, peer.local)))
                        .unwrap(),
                    Admit::Taken
                ));
            }
        }
        if peers[1].finished {
            assert!(peers[0].quic.is_established());
            assert!(peers[0].sent.is_some());
            assert!(!peers[0].finished);
            return;
        }
    }
    panic!("unread sibling blocked HTTP/3");
}

type Listening = Driver<httpd::Http3Listener>;
type Working = stdlib::services::stack::Polling<<httpd::Http3Listener as Layer>::Work>;

/// Hands every datagram the listener has to the open client it is for,
/// by address and connection ID, completing each send. Records the type
/// of each.
fn flush(
    sdk: &mut Listening,
    worker: &mut Working,
    peers: &mut [Client],
    sent: &mut Vec<quiche::Type>,
) {
    loop {
        sdk.run().unwrap();
        worker.work(sdk).unwrap();
        sdk.run().unwrap();
        let Some(DatagramCommand::Send(datagram)) = sdk.take_command() else {
            return;
        };
        let to = *datagram.meta();
        let mut bytes = datagram.into_parts().0.into_vec();
        let header = quiche::Header::from_slice(&mut bytes.clone(), 16).unwrap();
        sent.push(header.ty);
        if let Some(peer) = peers.iter_mut().find(|peer| {
            peer.local == to && peer.open() && peer.quic.source_ids().any(|id| *id == header.dcid)
        }) {
            peer.receive(&mut bytes);
        }
        assert!(matches!(
            sdk.deliver(DatagramEvent::Sent(1)).unwrap(),
            Admit::Taken
        ));
    }
}

/// One round between the listener and its clients, each at its own
/// address: the listener sends all it has, then each open client makes
/// progress, unless the listener closed it, and sends. A datagram the
/// listener holds back while an answer of its own waits goes in once that
/// answer is out, as a socket would hold it. Returns the type of each
/// datagram the listener sent.
fn round(sdk: &mut Listening, worker: &mut Working, peers: &mut [Client]) -> Vec<quiche::Type> {
    let mut sent = Vec::new();
    flush(sdk, worker, peers, &mut sent);
    let mut outgoing = Vec::new();
    let mut buffer = [0; 65535];
    for peer in peers.iter_mut().filter(|peer| peer.open()) {
        peer.progress();
        while let Ok((n, _)) = peer.quic.send(&mut buffer) {
            outgoing.push((peer.local, buffer[..n].to_vec()));
        }
    }
    for (from, bytes) in outgoing {
        let chunk = Chunk::copy_of(sdk.budget(), &bytes).unwrap();
        let mut event = DatagramEvent::Datagram(Datagram::new(chunk, from));
        loop {
            match sdk.deliver(event).unwrap() {
                Admit::Taken => break,
                Admit::Blocked(held) => {
                    event = held;
                    flush(sdk, worker, peers, &mut sent);
                }
                _ => panic!("the listener closed"),
            }
        }
    }
    sent
}

/// Rounds until `done`, within a bound.
fn rounds_until(
    sdk: &mut Listening,
    worker: &mut Working,
    peers: &mut [Client],
    mut done: impl FnMut(&[Client]) -> bool,
) -> Vec<quiche::Type> {
    let mut sent = Vec::new();
    for _ in 0..10000 {
        sent.extend(round(sdk, worker, peers));
        if done(peers) {
            return sent;
        }
    }
    panic!(
        "the clients stalled: {:?}",
        peers
            .iter()
            .map(|peer| (
                peer.quic.is_established(),
                peer.sent,
                peer.received.len(),
                peer.finished,
                peer.quic.peer_error(),
                peer.quic.stats().recv,
                peer.quic.stats().sent,
            ))
            .collect::<Vec<_>>()
    );
}

fn client_at(number: u8, port: u16, server: SocketAddr) -> Client {
    Client::new(number, SocketAddr::from(([127, 0, 0, 1], port)), server)
}

/// What one connection may hold in these tests: HTTP/3's codec scratch,
/// its streams and a request body, with room to spare.
const CONNECTION: usize = 16 << 20;

#[test]
fn an_exhausted_listener_budget_refuses_new_connections_and_keeps_the_others() {
    let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(96)));
    let local: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    // The cap would admit eight; the budget pays for two connections'
    // shares and the listener's own tables, and not for a third share.
    let config = listener_config(
        entropy.clone(),
        8,
        CONNECTION,
        AddressValidation::Accept,
        Arc::new(quinn_proto::congestion::CubicConfig::default()),
    );
    let listener = Listener::new(config, std::time::Instant::now(), Some(local));
    let stack = httpd::Responder::new(Recording {
        local,
        seen: seen.clone(),
    })
    .http3_listener(listener);
    let budget = Budget::new(2 * CONNECTION + CONNECTION / 4);
    let mut sdk = Driver::new(stack, entropy, budget.clone(), Instant::ZERO);
    let mut worker = stdlib::services::stack::Polling::new();
    let mut peers = vec![client_at(81, 5001, local), client_at(82, 5002, local)];

    // Both are mid-upload when the third arrives.
    rounds_until(&mut sdk, &mut worker, &mut peers, |peers| {
        peers.iter().all(|peer| peer.sent.is_some())
    });
    assert!(peers.iter().all(|peer| !peer.finished));
    assert!(budget.used() >= 2 * CONNECTION);
    peers.push(client_at(83, 5003, local));
    rounds_until(&mut sdk, &mut worker, &mut peers, |peers| {
        peers[..2].iter().all(|peer| peer.finished) && peers[2].quic.peer_error().is_some()
    });
    let refused = peers[2].quic.peer_error().expect("a refusal");
    assert!(!refused.is_app);
    assert_eq!(refused.error_code, 0x2, "CONNECTION_REFUSED");
    assert!(!peers[2].quic.is_established());
    assert!(peers[..2].iter().all(|peer| !peer.quic.is_closed()));
    assert_eq!(seen.lock().unwrap().len(), 2);

    // Closing one gives its share back once it drains.
    peers[0].quic.close(true, 0x100, b"").unwrap();
    round(&mut sdk, &mut worker, &mut peers);
    sdk.set_now(Instant::from_since_start(Duration::from_secs(10)));
    for _ in 0..100 {
        round(&mut sdk, &mut worker, &mut peers);
    }
    peers.push(client_at(84, 5004, local));
    rounds_until(&mut sdk, &mut worker, &mut peers, |peers| peers[3].finished);
    assert!(!peers[1].quic.is_closed());
    assert_eq!(seen.lock().unwrap().len(), 3);
}

#[test]
fn a_retry_listener_keeps_no_state_until_a_client_proves_its_address() {
    let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(97)));
    let local: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let config = listener_config(
        entropy.clone(),
        2,
        CONNECTION,
        AddressValidation::Retry,
        Arc::new(quinn_proto::congestion::CubicConfig::default()),
    );
    let listener = Listener::new(config, std::time::Instant::now(), Some(local));
    let stack = httpd::Responder::new(Recording {
        local,
        seen: seen.clone(),
    })
    .http3_listener(listener);
    let budget = Budget::new(64 << 20);
    let mut sdk = Driver::new(stack, entropy, budget, Instant::ZERO);
    let mut worker = stdlib::services::stack::Polling::new();
    let mut peers = vec![client_at(91, 5001, local)];

    // The listener's first answer is a Retry; the client comes back with
    // its token and is served.
    let sent = rounds_until(&mut sdk, &mut worker, &mut peers, |peers| peers[0].finished);
    assert_eq!(sent.first(), Some(&quiche::Type::Retry));
    assert_eq!(seen.lock().unwrap().len(), 1);
}
