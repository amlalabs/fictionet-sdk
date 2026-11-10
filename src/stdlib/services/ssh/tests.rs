use super::*;
use crate::stdlib::layer::{ChildReport, Observations};

// A packet boundary with completed negotiation, for connection-layer tests.
struct Packets(transport::Negotiated);
impl PacketTransport for Packets {
    fn start(&mut self, _: [u8; 32], _: &mut Vec<u8>) -> Result<(), TransportError> {
        Ok(())
    }
    fn push(&mut self, _: &Budget, bytes: &[u8]) -> usize {
        bytes.len()
    }
    fn end(&mut self) {}
    fn poll_ready(&self) -> bool {
        false
    }
    fn poll(
        &mut self,
        _: &Budget,
        _: &mut Vec<u8>,
        _: &mut dyn FnMut(transport::Observation),
    ) -> Result<Option<transport::Event>, transport::Failure> {
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

/// Processes `payload` as the layer does, paid for first.
fn paid(
    layer: &mut Ssh<tests::Observed, Packets>,
    sequence: u32,
    payload: &[u8],
    env: &mut Env<'_, Ended>,
) -> Result<(), Error> {
    let mut paid = env.budget().charge(packet_charge(payload)).unwrap();
    layer.packet(sequence, payload, &mut paid, env)
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
            &mut budget.charge(0).unwrap(),
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
        .connection_message(
            wire::Message::Close(0),
            &mut budget.charge(0).unwrap(),
            &mut env,
        )
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
            &mut budget.charge(0).unwrap(),
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
    assert!(layer.reserve(&budget) && layer.room(&budget));
    layer.started = true;
    let open = wire::Message::ChannelOpen {
        sender: 3,
        window: 1024,
        max_packet: 1024,
        kind: wire::OpenKind::Session,
    }
    .to_bytes()
    .unwrap();
    paid(&mut layer, 0, &open, &mut env).unwrap();
    assert!(layer.take_event().is_none());
    assert!(layer.channels.is_empty());
    layer.take_command(&mut env);
    assert!(layer.room(&budget));
    layer.user = Some("guest".into());
    paid(&mut layer, 1, &open, &mut env).unwrap();
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
            &mut budget.charge(0).unwrap(),
            &mut env,
        )
        .unwrap();
    let Some(MuxEvent::Opened(child, _, _)) = layer.take_event() else {
        panic!("opening missing")
    };
    assert!(
        layer
            .flights
            .push_back(Flight {
                bytes: 2,
                child: None,
            })
            .is_ok()
    );
    assert!(
        layer
            .flights
            .push_back(Flight {
                bytes: 5,
                child: Some((child.id(), 3)),
            })
            .is_ok()
    );
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

#[test]
fn control_disconnects_while_channel_commands_wait() {
    let mut layer = layer();
    let control = layer.control();
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
            &mut budget.charge(0).unwrap(),
            &mut env,
        )
        .unwrap();
    let Some(MuxEvent::Opened(child, _, _)) = layer.take_event() else {
        panic!("opening missing")
    };
    layer.channels.get_mut(child.id()).unwrap().confirmed = true;
    // Output not yet handed to the byte stream holds back channel commands.
    assert!(layer.room(&budget));
    layer.write(b"pending").unwrap();
    let write = child.send(ChannelCommand::Stream(StreamCommand::Write(Bytes::unpaid(
        b"data".to_vec(),
    ))));
    assert!(!layer.on_command(&mut env, write).unwrap().moved());
    control.disconnect();
    assert!(layer.advance(&mut env).unwrap());
    assert!(layer.is_terminal());
    assert!(matches!(
        layer.take_command(&mut env),
        Some(StreamCommand::Write(_))
    ));
    assert!(matches!(
        layer.take_command(&mut env),
        Some(StreamCommand::End)
    ));
}

#[test]
fn control_drain_reads_only_window_adjustments_and_closes() {
    let mut layer = layer();
    let control = layer.control();
    let budget = Budget::unlimited();
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    assert!(layer.reserve(&budget) && layer.room(&budget));
    layer.started = true;
    layer.user = Some("guest".into());
    let open = |sender| {
        wire::Message::ChannelOpen {
            sender,
            window: 1024,
            max_packet: 1024,
            kind: wire::OpenKind::Session,
        }
        .to_bytes()
        .unwrap()
    };
    paid(&mut layer, 0, &open(3), &mut env).unwrap();
    let Some(MuxEvent::Opened(child, _, _)) = layer.take_event() else {
        panic!("opening missing")
    };
    let channel = layer.channels.get_mut(child.id()).unwrap();
    channel.confirmed = true;
    channel.receive = 1024;
    channel.advertised = 1024;
    let (number, window) = (channel.wire, channel.window);

    control.drain();
    paid(&mut layer, 1, &open(4), &mut env).unwrap();
    assert!(layer.take_event().is_none());
    assert_eq!(layer.channels.ids().count(), 1);
    let data = wire::Message::Data {
        recipient: number,
        data: b"after hangup".to_vec(),
    };
    paid(&mut layer, 2, &data.to_bytes().unwrap(), &mut env).unwrap();
    assert!(layer.take_event().is_none());
    let adjust = wire::Message::WindowAdjust {
        recipient: number,
        bytes: 10,
    };
    paid(&mut layer, 3, &adjust.to_bytes().unwrap(), &mut env).unwrap();
    assert!(layer.channels.get(child.id()).unwrap().window > window);
    assert!(!layer.is_terminal());
    let close = wire::Message::Close(number).to_bytes().unwrap();
    paid(&mut layer, 4, &close, &mut env).unwrap();
    assert!(layer.is_terminal());
}

fn open(sender: u32) -> Vec<u8> {
    wire::Message::ChannelOpen {
        sender,
        window: 1024,
        max_packet: 1024,
        kind: wire::OpenKind::Session,
    }
    .to_bytes()
    .unwrap()
}

/// A channel the budget cannot hold now is refused for resource shortage,
/// without taking a channel number. The connection goes on and opens the
/// next channel once memory frees. A channel the children above refuse
/// gets the cause they give: resource shortage for memory, prohibited for
/// their limit on channels.
#[test]
fn a_channel_without_memory_is_refused_and_the_connection_goes_on() {
    let mut layer = layer();
    let budget = Budget::new(4 << 20);
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    assert!(layer.reserve(&budget) && layer.room(&budget));
    layer.started = true;
    layer.user = Some("guest".into());
    // The packet is paid for; everything else is held elsewhere.
    let mut packet = budget.charge(packet_charge(&open(3))).unwrap();
    let elsewhere = budget.charge(budget.limit() - budget.used()).unwrap();
    layer.packet(0, &open(3), &mut packet, &mut env).unwrap();
    assert!(layer.take_event().is_none());
    assert!(layer.channels.is_empty());
    assert!(!layer.is_terminal());
    // The packet transport writes payloads as they are.
    let Some(StreamCommand::Write(reply)) = layer.take_command(&mut env) else {
        panic!("refusal missing")
    };
    assert!(matches!(
        wire::Message::parse(&reply).unwrap(),
        wire::Message::ChannelOpenFailure {
            recipient: 3,
            reason: 4,
            ..
        }
    ));
    drop((packet, elsewhere));
    assert!(layer.room(&budget));
    paid(&mut layer, 1, &open(4), &mut env).unwrap();
    let Some(MuxEvent::Opened(child, opening, max)) = layer.take_event() else {
        panic!("opening missing")
    };
    assert_eq!(opening.channel, 0);
    // A channel the children above refuse for want of memory is refused
    // for resource shortage too; one past their limit is prohibited.
    let full = Budget::new(4096);
    let squeezed = full.clone();
    let no_memory = children(8).budgets(move |_, _, _| squeezed.clone());
    let elsewhere = full.charge(full.limit()).unwrap();
    let opened = MuxEvent::Opened(child, opening, max);
    assert_eq!(
        refused(&mut layer, &mut env, no_memory, opened),
        (4, Closing::ResourceShortage)
    );
    drop(elsewhere);
    paid(&mut layer, 2, &open(5), &mut env).unwrap();
    let opened = layer.take_event().expect("opening missing");
    assert_eq!(
        refused(&mut layer, &mut env, children(0), opened),
        (1, Closing::Prohibited)
    );
    assert!(layer.channels.is_empty());
    assert!(!layer.is_terminal());
}

/// A channel layer that takes everything and says nothing.
struct Quiet;
impl Layer for Quiet {
    type Lower = ChannelPort;
    type Upper = Top;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = std::convert::Infallible;
    fn on_event(
        &mut self,
        _: &mut Env<'_, ()>,
        _: ChannelEvent,
    ) -> Result<Admit<ChannelEvent>, std::convert::Infallible> {
        Ok(Admit::Taken)
    }
    fn on_command(
        &mut self,
        _: &mut Env<'_, ()>,
        command: std::convert::Infallible,
    ) -> Result<Admit<std::convert::Infallible>, std::convert::Infallible> {
        match command {}
    }
    fn take_command(&mut self, _: &mut Env<'_, ()>) -> Option<ChannelCommand> {
        None
    }
    fn take_event(&mut self) -> Option<std::convert::Infallible> {
        None
    }
}

type QuietChildren = crate::stdlib::layer::Driver<Children<Quiet, Top, Owned<channel::Opening>>>;

/// Children of at most `limit` channels, as a connection's sessions are.
fn children(limit: usize) -> Children<Quiet, Top, Owned<channel::Opening>> {
    Children::new(limit, u64::from(WINDOW), |_, _, _| Some(Quiet))
}

/// Hands the connection's `opened` channel to `children`, which refuse
/// it, and their close to the connection. Returns the reason the peer
/// was told and the cause Children reported.
fn refused(
    layer: &mut Ssh<tests::Observed, Packets>,
    env: &mut Env<'_, Ended>,
    children: Children<Quiet, Top, Owned<channel::Opening>>,
    opened: MuxEvent<ChannelPort, Top, Owned<channel::Opening>>,
) -> (u32, Closing) {
    let mut driver: QuietChildren = crate::stdlib::layer::Driver::new(
        children,
        Arc::new(crate::SeededEntropy::new(crate::Seed::from_u64(2))),
        Budget::new(1 << 20),
        Instant::ZERO,
    );
    assert!(matches!(driver.deliver(opened), Ok(Admit::Taken)));
    let reported = driver
        .observations()
        .drain()
        .find_map(|report| match report {
            ChildReport::Refused(_, why) => Some(why),
            _ => None,
        })
        .expect("Children reported the refusal");
    let close = driver.take_command().expect("Children closed the channel");
    let MuxOp::Close(id, why) = *close.op() else {
        panic!("Children closed the channel")
    };
    assert_eq!(why, reported, "the close carries the reported cause");
    assert!(layer.on_command(env, close).unwrap().moved());
    assert!(matches!(layer.take_event(), Some(MuxEvent::Closed(gone)) if gone == id));
    let Some(StreamCommand::Write(reply)) = layer.take_command(env) else {
        panic!("refusal missing")
    };
    let wire::Message::ChannelOpenFailure { reason, .. } = wire::Message::parse(&reply).unwrap()
    else {
        panic!("the peer is told the channel is refused")
    };
    (reason, reported)
}

/// A channel the children take and then give up on before it is
/// confirmed is refused as failed to connect; one confirmed is closed,
/// whatever the cause, since CLOSE carries none.
#[test]
fn a_failed_channel_is_refused_before_confirmation_and_closed_after() {
    let mut layer = layer();
    let budget = Budget::unlimited();
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    assert!(layer.reserve(&budget) && layer.room(&budget));
    layer.started = true;
    layer.user = Some("guest".into());
    fn take_opened(
        layer: &mut Ssh<tests::Observed, Packets>,
        sender: u32,
        env: &mut Env<'_, Ended>,
    ) -> crate::stdlib::layer::Child {
        paid(layer, sender, &open(sender), env).unwrap();
        let Some(MuxEvent::Opened(child, _, _)) = layer.take_event() else {
            panic!("opening missing")
        };
        child
    }
    let unconfirmed = take_opened(&mut layer, 3, &mut env);
    let id = unconfirmed.id();
    assert!(
        layer
            .on_command(&mut env, unconfirmed.close(Closing::Failed))
            .unwrap()
            .moved()
    );
    assert!(matches!(layer.take_event(), Some(MuxEvent::Closed(gone)) if gone == id));
    let Some(StreamCommand::Write(reply)) = layer.take_command(&mut env) else {
        panic!("refusal missing")
    };
    assert!(matches!(
        wire::Message::parse(&reply).unwrap(),
        wire::Message::ChannelOpenFailure {
            recipient: 3,
            reason: 2,
            ..
        }
    ));
    let confirmed = take_opened(&mut layer, 4, &mut env);
    layer.channels.get_mut(confirmed.id()).unwrap().confirmed = true;
    assert!(
        layer
            .on_command(&mut env, confirmed.close(Closing::Failed))
            .unwrap()
            .moved()
    );
    let Some(StreamCommand::Write(reply)) = layer.take_command(&mut env) else {
        panic!("close missing")
    };
    assert!(matches!(
        wire::Message::parse(&reply).unwrap(),
        wire::Message::Close(4)
    ));
}

/// A decoded packet the budget cannot pay to process waits, unparsed and
/// unchanged, and goes on once memory frees: the connection does not fail
/// for want of memory.
#[test]
fn a_packet_without_memory_waits_for_it() {
    let mut layer = layer();
    let budget = Budget::new(4 << 20);
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    assert!(layer.reserve(&budget) && layer.room(&budget));
    layer.started = true;
    layer.user = Some("guest".into());
    let payload = open(3);
    let decoded = Owned::new(payload.clone(), budget.charge(payload.capacity()).unwrap());
    assert!(layer.pending_packets.push_back((0, decoded)).is_ok());
    let elsewhere = budget.charge(budget.limit() - budget.used()).unwrap();
    let used = budget.used();
    assert!(!layer.advance(&mut env).unwrap());
    assert_eq!(layer.pending_packets.len(), 1);
    assert!(layer.take_event().is_none());
    assert!(!layer.is_terminal());
    assert_eq!(budget.used(), used);
    drop(elsewhere);
    assert!(layer.advance(&mut env).unwrap());
    assert_eq!(layer.pending_packets.len(), 0);
    assert!(matches!(layer.take_event(), Some(MuxEvent::Opened(..))));
}
