use super::*;
use crate::stdlib::layer::Observations;

// A packet boundary with completed negotiation, for connection-layer tests.
struct Packets(transport::Negotiated);
impl PacketTransport for Packets {
    fn resident_bytes(&self) -> usize {
        0
    }
    fn start(&mut self, _: [u8; 32], _: &mut Vec<u8>) -> Result<(), TransportError> {
        Ok(())
    }
    fn push(&mut self, bytes: &[u8]) -> usize {
        bytes.len()
    }
    fn end(&mut self) {}
    fn poll_ready(&self) -> bool {
        false
    }
    fn poll(&mut self, _: &mut Vec<u8>) -> Result<Option<transport::Event>, transport::Failure> {
        Ok(None)
    }
    fn state(&self) -> TransportState<'_> {
        TransportState::Established {
            session_id: b"session",
            negotiated: &self.0,
        }
    }
    fn needs_rekey(&self) -> bool {
        false
    }
    fn rekey(&mut self, _: &mut Vec<u8>) -> Result<(), TransportError> {
        Ok(())
    }
    fn write_packet(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), TransportError> {
        out.extend_from_slice(payload);
        Ok(())
    }
    fn disconnect(
        &mut self,
        _: ssh::DisconnectReason,
        _: &str,
        out: &mut Vec<u8>,
    ) -> Result<(), TransportError> {
        out.push(1);
        Ok(())
    }
}

fn layer() -> Ssh<tests::Observed, Packets> {
    Ssh::with_transport(
        Arc::new(Config::new(
            Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
            ssh::Identification::new("2.0", "test", None).unwrap(),
        )),
        Arc::new(tests::Observed(std::sync::Mutex::new(Vec::new()))),
        Arc::new(ConnInfo::default()),
        Packets(transport::Negotiated {
            kex: String::new(),
            host: String::new(),
            incoming: String::new(),
            outgoing: String::new(),
        }),
    )
}

#[test]
fn local_close_retires_the_child_before_peer_acknowledgment() {
    let mut layer = layer();
    let budget = Budget::unlimited();
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    layer.user = Some("guest".into());
    layer
        .connection_message(
            wire::Message::ChannelOpen {
                sender: 3,
                window: 1024,
                max_packet: 1024,
                kind: wire::OpenKind::Session,
            },
            &mut env,
        )
        .unwrap();
    let Some(MuxEvent::Opened(child, _, _)) = layer.take_event() else {
        panic!("opening missing")
    };
    layer.channels.get_mut(child.id()).unwrap().confirmed = true;
    assert!(
        layer
            .on_command(&mut env, child.send(ChannelCommand::Close))
            .unwrap()
            .moved()
    );
    assert!(
        matches!(layer.take_urgent(), Some(MuxEvent::Child(id, ChannelEvent::Stream(StreamEvent::Reset))) if id == child.id())
    );
    assert!(layer.channels.contains(child.id()));
    layer.take_command(&mut env);
    assert!(
        layer
            .on_command(&mut env, child.send(ChannelCommand::Reply(true)))
            .unwrap()
            .moved()
    );
    assert!(layer.take_command(&mut env).is_none());
    layer
        .connection_message(wire::Message::Close(0), &mut env)
        .unwrap();
    assert!(!layer.channels.contains(child.id()));
    assert!(layer.take_command(&mut env).is_none());
}

#[test]
fn local_eof_is_sent_once() {
    let mut layer = layer();
    let budget = Budget::unlimited();
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    layer.user = Some("guest".into());
    layer
        .connection_message(
            wire::Message::ChannelOpen {
                sender: 3,
                window: 1024,
                max_packet: 1024,
                kind: wire::OpenKind::Session,
            },
            &mut env,
        )
        .unwrap();
    let Some(MuxEvent::Opened(child, _, _)) = layer.take_event() else {
        panic!("opening missing")
    };
    assert!(
        layer
            .on_command(
                &mut env,
                child.send(ChannelCommand::Stream(StreamCommand::End))
            )
            .unwrap()
            .moved()
    );
    layer.take_command(&mut env);
    assert!(
        layer
            .on_command(
                &mut env,
                child.send(ChannelCommand::Stream(StreamCommand::End))
            )
            .is_err()
    );
    assert!(layer.take_command(&mut env).is_none());
}

#[test]
fn authentication_and_reserved_capacity_precede_confirmation() {
    let mut layer = layer();
    let budget = Budget::unlimited();
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    layer.reserve(&env).unwrap();
    layer.started = true;
    let open = wire::Message::ChannelOpen {
        sender: 3,
        window: 1024,
        max_packet: 1024,
        kind: wire::OpenKind::Session,
    }
    .to_bytes()
    .unwrap();
    layer.packet(0, &open, &mut env).unwrap();
    assert!(layer.take_event().is_none());
    assert!(layer.channels.is_empty());
    layer.take_command(&mut env);
    layer.user = Some("guest".into());
    layer.packet(1, &open, &mut env).unwrap();
    let Some(MuxEvent::Opened(child, _, _)) = layer.take_event() else {
        panic!("opening missing")
    };
    assert!(
        layer
            .on_command(&mut env, child.send(ChannelCommand::Accept(true)))
            .unwrap()
            .moved()
    );
    assert!(!layer.advance(&mut env).unwrap());
    assert!(layer.take_command(&mut env).is_none());
    assert!(
        layer
            .on_command(&mut env, child.grant(1024))
            .unwrap()
            .moved()
    );
    assert!(layer.advance(&mut env).unwrap());
    let Some(StreamCommand::Write(data)) = layer.take_command(&mut env) else {
        panic!("confirmation missing")
    };
    let wire::Message::ChannelOpenConfirmation { window, .. } =
        wire::Message::parse(&data).unwrap()
    else {
        panic!("unexpected response")
    };
    assert!(u64::from(window) <= layer.channels.get(child.id()).unwrap().receive);
}

#[test]
fn partial_wire_completions_credit_each_child_write_once() {
    let mut layer = layer();
    let budget = Budget::unlimited();
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    layer.user = Some("guest".into());
    layer
        .connection_message(
            wire::Message::ChannelOpen {
                sender: 3,
                window: 1024,
                max_packet: 1024,
                kind: wire::OpenKind::Session,
            },
            &mut env,
        )
        .unwrap();
    let Some(MuxEvent::Opened(child, _, _)) = layer.take_event() else {
        panic!("opening missing")
    };
    layer.flights.push_back(Flight {
        bytes: 2,
        child: None,
    });
    layer.flights.push_back(Flight {
        bytes: 5,
        child: Some((child.id(), 3)),
    });
    for n in [2, 4] {
        assert!(
            layer
                .on_event(&mut env, StreamEvent::Written(n))
                .unwrap()
                .moved()
        );
        assert!(layer.take_event().is_none());
    }
    assert!(
        layer
            .on_event(&mut env, StreamEvent::Written(1))
            .unwrap()
            .moved()
    );
    assert!(
        matches!(layer.take_event(), Some(MuxEvent::Child(id, ChannelEvent::Stream(StreamEvent::Written(3)))) if id == child.id())
    );
    assert!(layer.take_event().is_none());
    assert!(layer.on_event(&mut env, StreamEvent::Written(1)).is_err());
    assert!(layer.take_event().is_none());
}
