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
            let headers = [
                quiche::h3::Header::new(b":method", b"POST"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"localhost"),
                quiche::h3::Header::new(b":path", b"/echo"),
                quiche::h3::Header::new(b"content-length", b"20000"),
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

fn listener_stack(
    entropy: Arc<dyn Entropy>,
    local: SocketAddr,
    connections: usize,
    seen: Arc<std::sync::Mutex<Vec<stdlib::network::ConnInfo>>>,
) -> Chain<Listener, Children<httpd::Http3Server, Top, stdlib::network::ConnInfo>> {
    let (_, server, endpoint) = configs_with_protocol(entropy, false, b"h3");
    let listener = Listener::new(
        ListenerConfig {
            endpoint,
            server: Arc::new(server),
            connections,
            streams: 16,
            cancel: |_| 0x10cu32.into(),
        },
        std::time::Instant::now(),
        Some(local),
    );
    Chain::new(
        listener,
        Children::new(
            connections,
            0,
            move |_, info: stdlib::network::ConnInfo, _| {
                assert_eq!(info.local, Some(local));
                assert!(info.tls);
                assert_eq!(info.alpn.as_deref(), Some(b"h3".as_slice()));
                assert_eq!(info.sni.as_deref(), Some("localhost"));
                seen.lock().unwrap().push(info.clone());
                Some(
                    httpd::Responder::new(Echo { streamed: false })
                        .conn(info)
                        .http3(),
                )
            },
        ),
    )
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
            Charged {
                value: (listener, result),
                charged: budget.used(),
                moved: 0,
            }
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
            cancel: |_| 0x10cu32.into(),
        },
        std::time::Instant::now(),
        Some(local),
    );
    let stack = Chain::new(
        listener,
        Children::new(2, 0, move |_, info: stdlib::network::ConnInfo, _| {
            Some(if info.peer == Some(blocked) {
                Boxed::new(Unread)
            } else {
                Boxed::new(
                    httpd::Responder::new(Echo { streamed: false })
                        .conn(info)
                        .http3(),
                )
            })
        }),
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
