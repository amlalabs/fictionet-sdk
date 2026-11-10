use super::*;
use crate::stdlib::codec::HeapBound;
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

/// Processes `payload` as the layer does, with room in the budget for it.
fn paid(
    layer: &mut Ssh<tests::Observed, Packets>,
    sequence: u32,
    payload: &[u8],
    env: &mut Env<'_, Ended>,
) -> Result<(), Error> {
    match layer.packet(sequence, payload, env)? {
        Handled::Done => Ok(()),
        Handled::Waiting => panic!("the budget has room for the packet"),
    }
}

/// Takes `message` as if it had just been parsed, charged what it holds.
fn take(
    layer: &mut Ssh<tests::Observed, Packets>,
    message: wire::Message,
    env: &mut Env<'_, Ended>,
) -> Result<(), Error> {
    let parsed = env.budget().charge(message.heap()).unwrap();
    match layer.connection_message(Owned::new(message, parsed), env)? {
        Handled::Done => Ok(()),
        Handled::Waiting => panic!("the budget has room for the message"),
    }
}

/// An authenticated account name, charged on `budget`.
fn guest(budget: &Budget) -> Owned<String> {
    Owned::new("guest".to_owned(), budget.charge("guest".len()).unwrap())
}

#[test]
fn local_close_retires_the_child_before_peer_acknowledgment() {
    let mut layer = layer();
    let budget = Budget::unlimited();
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    layer.user = Some(guest(&budget));
    take(
        &mut layer,
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
    take(&mut layer, wire::Message::Close(0), &mut env).unwrap();
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
    layer.user = Some(guest(&budget));
    take(
        &mut layer,
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
    layer.user = Some(guest(&budget));
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
    layer.user = Some(guest(&budget));
    take(
        &mut layer,
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
    layer.user = Some(guest(&budget));
    take(
        &mut layer,
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
    // Output not yet handed to the byte stream holds back channel commands.
    assert!(layer.room(&budget));
    seal(&mut layer.out, &mut layer.transport, b"pending").unwrap();
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
    layer.user = Some(guest(&budget));
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
/// without taking a channel number: the packet's parse fits, but not the
/// opening's copy of a long account name. The connection goes on and
/// opens the next channel once memory frees. A channel the children above
/// refuse gets the cause they give: resource shortage for memory,
/// prohibited for their limit on channels.
#[test]
fn a_channel_without_memory_is_refused_and_the_connection_goes_on() {
    let mut layer = layer();
    let budget = Budget::new(4 << 20);
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    assert!(layer.reserve(&budget) && layer.room(&budget));
    layer.started = true;
    let user = "u".repeat(1000);
    let name = budget.charge(user.len()).unwrap();
    layer.user = Some(Owned::new(user, name));
    // Room for the packet's parse; everything else is held elsewhere.
    let parse = wire::Message::most_heap_of(&open(3));
    let elsewhere = budget
        .charge(budget.limit() - budget.used() - parse)
        .unwrap();
    assert!(matches!(
        layer.packet(0, &open(3), &mut env).unwrap(),
        Handled::Done
    ));
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
    drop(elsewhere);
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
    layer.user = Some(guest(&budget));
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
    layer.user = Some(guest(&budget));
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

fn service_request() -> Vec<u8> {
    ssh::Message::ServiceRequest("ssh-userauth".into())
        .to_bytes()
        .unwrap()
}

fn userauth(user: &str, method: auth::Method) -> Vec<u8> {
    auth::Request {
        user: user.into(),
        service: "ssh-connection".into(),
        method,
    }
    .to_bytes()
    .unwrap()
}

fn password(user: &str) -> Vec<u8> {
    userauth(
        user,
        auth::Method::Password {
            password: b"secret".to_vec(),
            new_password: None,
        },
    )
}

/// What authenticating keeps is charged for what it holds, and nothing
/// else stays charged: while the client authenticates, the account name
/// it gave; once it has, the authenticated name alone. Every packet's
/// parse and copies were given back.
#[test]
fn authenticating_keeps_only_the_account_name_charged() {
    let mut layer = layer();
    let budget = Budget::new(4 << 20);
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    assert!(layer.reserve(&budget) && layer.room(&budget));
    layer.started = true;
    let before = budget.used();
    let user = "u".repeat(300);
    paid(&mut layer, 0, &service_request(), &mut env).unwrap();
    assert_eq!(budget.used(), before);
    paid(
        &mut layer,
        1,
        &userauth(&user, auth::Method::None),
        &mut env,
    )
    .unwrap();
    let pending = layer.auth_user.as_ref().expect("the name the client gave");
    assert_eq!(pending.charged(), Heap::heap(&**pending));
    assert_eq!(budget.used(), before + Heap::heap(&**pending));
    paid(&mut layer, 2, &password(&user), &mut env).unwrap();
    assert!(layer.auth_user.is_none() && layer.challenge.is_none());
    let signed_in = layer.user.as_ref().expect("authenticated");
    assert_eq!(signed_in.charged(), Heap::heap(&**signed_in));
    assert_eq!(budget.used(), before + Heap::heap(&**signed_in));
}

/// A packet is taken once the budget has room for its parse and what
/// handling it copies, all of it within a few copies of the packet: a
/// request of any size, not 64 heap bytes per byte of it. Until then it
/// waits, and each wait changes nothing: no state, no observation, no
/// output and no charge.
#[test]
fn a_packet_waits_unchanged_until_its_parse_and_copies_fit() {
    let mut layer = layer();
    let budget = Budget::new(4 << 20);
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    assert!(layer.reserve(&budget) && layer.room(&budget));
    layer.started = true;
    paid(&mut layer, 0, &service_request(), &mut env).unwrap();
    let observed = layer.handler.0.lock().unwrap().len();
    let written = layer.out.as_ref().unwrap().len();
    let request = password(&"u".repeat(2000));
    let mut room = 0;
    loop {
        let elsewhere = budget
            .charge(budget.limit() - budget.used() - room)
            .unwrap();
        let used = budget.used();
        match layer.packet(1, &request, &mut env).unwrap() {
            Handled::Done => break,
            Handled::Waiting => {
                assert_eq!(budget.used(), used, "a wait holds nothing");
                assert_eq!(layer.auth_requests, 0);
                assert!(layer.auth_user.is_none() && layer.user.is_none());
                assert_eq!(layer.handler.0.lock().unwrap().len(), observed);
                assert_eq!(layer.out.as_ref().unwrap().len(), written);
            }
        }
        drop(elsewhere);
        room += 1;
    }
    assert!(layer.user.is_some());
    assert!(
        room <= 4 * request.len(),
        "{room} bytes of room to take {} bytes",
        request.len()
    );
}

/// What a channel opening and a channel request hold moves on charged
/// for exactly what it holds, and once both are dropped nothing they
/// took stays charged.
#[test]
fn openings_and_channel_requests_are_charged_what_they_hold() {
    let mut layer = layer();
    let budget = Budget::new(4 << 20);
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    assert!(layer.reserve(&budget) && layer.room(&budget));
    layer.started = true;
    layer.user = Some(guest(&budget));
    let before = budget.used();
    let open = wire::Message::ChannelOpen {
        sender: 3,
        window: 1024,
        max_packet: 1024,
        kind: wire::OpenKind::DirectTcpIp(wire::TcpIp {
            host: "example.com".into(),
            port: 80,
            originator: "10.0.0.1".into(),
            originator_port: 5000,
        }),
    };
    paid(&mut layer, 0, &open.to_bytes().unwrap(), &mut env).unwrap();
    let Some(MuxEvent::Opened(_, opening, _)) = layer.take_event() else {
        panic!("opening missing")
    };
    assert_eq!(opening.charged(), opening.heap());
    let request = wire::Message::ChannelRequest {
        recipient: opening.channel,
        want_reply: true,
        request: wire::SessionRequest::Pty {
            terminal: "xterm-256color".into(),
            dimensions: wire::Dimensions::default(),
            modes: vec![
                wire::TerminalMode {
                    opcode: 53,
                    value: 1,
                };
                30
            ],
        },
    };
    paid(&mut layer, 1, &request.to_bytes().unwrap(), &mut env).unwrap();
    let Some(MuxEvent::Child(_, ChannelEvent::Request { request, .. })) = layer.take_event() else {
        panic!("request missing")
    };
    assert_eq!(request.charged(), request.heap());
    assert_eq!(budget.used(), before + opening.heap() + request.heap());
    drop((opening, request));
    assert_eq!(budget.used(), before);
}

/// Channel output is copied for its message and for the observer before
/// it is sealed. Without room for both copies the write waits, changing
/// nothing; with it, the write goes out and the copies are given back.
#[test]
fn channel_output_waits_for_its_copies() {
    let mut layer = layer();
    let budget = Budget::new(4 << 20);
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    assert!(layer.reserve(&budget) && layer.room(&budget));
    layer.started = true;
    layer.user = Some(guest(&budget));
    paid(&mut layer, 0, &open(3), &mut env).unwrap();
    let Some(MuxEvent::Opened(child, _, _)) = layer.take_event() else {
        panic!("opening missing")
    };
    let channel = layer.channels.get_mut(child.id()).unwrap();
    channel.confirmed = true;
    channel.granted = 1024;
    let data = vec![b'x'; 600];
    let write = || {
        child.send(ChannelCommand::Stream(StreamCommand::Write(Bytes::unpaid(
            data.clone(),
        ))))
    };
    let elsewhere = budget
        .charge(budget.limit() - budget.used() - (2 * data.len() - 1))
        .unwrap();
    let used = budget.used();
    assert!(!layer.on_command(&mut env, write()).unwrap().moved());
    assert_eq!(budget.used(), used);
    assert_eq!(layer.channels.get(child.id()).unwrap().granted, 1024);
    assert!(!layer.out_pending());
    drop(elsewhere);
    let elsewhere = budget
        .charge(budget.limit() - budget.used() - 2 * data.len())
        .unwrap();
    let used = budget.used();
    assert!(layer.on_command(&mut env, write()).unwrap().moved());
    assert_eq!(budget.used(), used, "the copies were given back");
    assert!(layer.out_pending());
    drop(elsewhere);
}

/// Challenges each keyboard-interactive login once, and accepts its
/// answers.
struct Challenging;
impl Handler for Challenging {
    type Session = tests::NoSession;
    fn authenticate(&self, _: &Context<'_>, attempt: &AuthAttempt<'_>) -> AuthDecision {
        if attempt.responses.is_some() {
            return AuthDecision::Accept;
        }
        AuthDecision::Challenge {
            name: String::new(),
            instruction: String::new(),
            prompts: vec![auth::Prompt {
                text: "Password: ".into(),
                echo: false,
            }],
        }
    }
    fn open(&self, _: &Context<'_>, _: &SessionRequest, _: &mut Output) -> Option<Self::Session> {
        None
    }
}

/// A challenged request is kept with the charge its parse made, for what
/// it holds; the answers give it back, and once authenticated only the
/// account name stays charged. An answer that comes without room waits,
/// with the challenge still kept.
#[test]
fn a_challenge_keeps_its_request_charged_until_answered() {
    let mut layer = Ssh::with_transport(
        Arc::new(Config::new(
            Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
            ssh::Identification::new("2.0", "test", None).unwrap(),
        )),
        Arc::new(Challenging),
        Arc::new(ConnInfo::default()),
        Packets(transport::Negotiated {
            kex: String::new(),
            host: String::new(),
            incoming: String::new(),
            outgoing: String::new(),
        }),
    );
    let budget = Budget::new(4 << 20);
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    assert!(layer.reserve(&budget) && layer.room(&budget));
    layer.started = true;
    let before = budget.used();
    let user = "u".repeat(500);
    let take = |layer: &mut Ssh<Challenging, Packets>, payload: &[u8], env: &mut Env<'_, Ended>| {
        layer.packet(0, payload, env).unwrap()
    };
    assert!(matches!(
        take(&mut layer, &service_request(), &mut env),
        Handled::Done
    ));
    let start = userauth(
        &user,
        auth::Method::KeyboardInteractive {
            language: String::new(),
            submethods: String::new(),
        },
    );
    assert!(matches!(take(&mut layer, &start, &mut env), Handled::Done));
    let (request, count) = layer.challenge.as_ref().expect("challenged");
    assert_eq!(*count, 1);
    assert_eq!(request.charged(), Heap::heap(&**request));
    let names = Heap::heap(&**layer.auth_user.as_ref().unwrap());
    assert_eq!(budget.used(), before + request.charged() + names);
    let answers = auth::Message::InfoResponse(vec![b"secret".to_vec()])
        .to_bytes()
        .unwrap();
    let elsewhere = budget.charge(budget.limit() - budget.used()).unwrap();
    assert!(matches!(
        take(&mut layer, &answers, &mut env),
        Handled::Waiting
    ));
    assert!(layer.challenge.is_some() && layer.user.is_none());
    drop(elsewhere);
    assert!(matches!(
        take(&mut layer, &answers, &mut env),
        Handled::Done
    ));
    assert!(layer.challenge.is_none());
    let signed_in = layer.user.as_ref().expect("authenticated");
    assert_eq!(budget.used(), before + Heap::heap(&**signed_in));
}

/// RFC 4254 section 5.3: a channel stays open for the peer until it has
/// our CLOSE. What it sent before that (data, a request, EOF) arrives
/// after we closed. It is dropped, nothing is answered on the closed
/// channel, and the connection and its other channels go on.
#[test]
fn what_the_peer_sent_before_our_close_arrived_is_dropped() {
    let mut layer = layer();
    let budget = Budget::unlimited();
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    layer.user = Some(guest(&budget));
    take(
        &mut layer,
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
    let channel = layer.channels.get_mut(child.id()).unwrap();
    channel.confirmed = true;
    channel.receive = 1024;
    channel.advertised = 1024;
    assert!(
        layer
            .on_command(&mut env, child.send(ChannelCommand::Close))
            .unwrap()
            .moved()
    );
    assert!(layer.take_urgent().is_some());
    assert!(layer.take_command(&mut env).is_some(), "our CLOSE");
    let late = [
        wire::Message::Data {
            recipient: 0,
            data: b"late".to_vec(),
        },
        wire::Message::ExtendedData {
            recipient: 0,
            kind: 1,
            data: b"late".to_vec(),
        },
        wire::Message::ChannelRequest {
            recipient: 0,
            want_reply: true,
            request: wire::SessionRequest::WindowChange(wire::Dimensions {
                columns: 80,
                rows: 24,
                pixel_width: 0,
                pixel_height: 0,
            }),
        },
        wire::Message::Eof(0),
    ];
    for message in late {
        take(&mut layer, message, &mut env).expect("the peer had not seen our CLOSE");
    }
    assert!(layer.take_event().is_none(), "nothing reaches the retired child");
    assert!(
        layer.take_command(&mut env).is_none(),
        "nothing is answered on a closed channel"
    );
    take(&mut layer, wire::Message::Close(0), &mut env).unwrap();
    assert!(!layer.channels.contains(child.id()));
    assert!(layer.take_command(&mut env).is_none(), "CLOSE was sent once");
}

/// Rejects every attempt after a delay.
struct Slow;
impl Handler for Slow {
    type Session = tests::NoSession;
    fn authenticate(&self, _: &Context<'_>, _: &AuthAttempt<'_>) -> AuthDecision {
        AuthDecision::Reject {
            methods: vec![AuthMethod::Password],
            partial_success: false,
            delay: Duration::from_secs(1),
        }
    }
    fn open(&self, _: &Context<'_>, _: &SessionRequest, _: &mut Output) -> Option<Self::Session> {
        None
    }
}

/// RFC 4252 section 5: a client may send several requests without
/// waiting for the replies, and the server answers each in turn. A
/// request that arrives while an earlier failure waits out its delay
/// waits behind it; it does not end the connection.
#[test]
fn a_request_sent_before_the_last_failure_waits_for_it() {
    let mut layer = Ssh::with_transport(
        Arc::new(Config::new(
            Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
            ssh::Identification::new("2.0", "test", None).unwrap(),
        )),
        Arc::new(Slow),
        Arc::new(ConnInfo::default()),
        Packets(transport::Negotiated {
            kex: String::new(),
            host: String::new(),
            incoming: String::new(),
            outgoing: String::new(),
        }),
    );
    let budget = Budget::new(4 << 20);
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    assert!(layer.reserve(&budget) && layer.room(&budget));
    layer.started = true;
    for (sequence, payload) in [service_request(), password("guest"), password("guest")]
        .into_iter()
        .enumerate()
    {
        let decoded = Owned::new(payload.clone(), budget.charge(payload.capacity()).unwrap());
        assert!(
            layer
                .pending_packets
                .push_back((sequence as u32, decoded))
                .is_ok()
        );
    }
    let mut replies = Vec::new();
    let mut step = |layer: &mut Ssh<Slow, Packets>, env: &mut Env<'_, Ended>| {
        let progressed = layer.advance(env).expect("the connection goes on");
        while let Some(StreamCommand::Write(bytes)) = layer.take_command(env) {
            replies.push(bytes.to_vec()[0]);
        }
        progressed
    };
    while step(&mut layer, &mut env) {}
    assert_eq!(layer.pending_packets.len(), 1, "the second request waits");
    let mut later = Env::new(
        Instant::ZERO + Duration::from_secs(1),
        &entropy,
        &budget,
        &mut observations,
    );
    assert!(layer.on_timer(&mut later, Timer::Failure).unwrap());
    while step(&mut layer, &mut later) {}
    assert_eq!(layer.pending_packets.len(), 0);
    let mut last = Env::new(
        Instant::ZERO + Duration::from_secs(2),
        &entropy,
        &budget,
        &mut observations,
    );
    assert!(layer.on_timer(&mut last, Timer::Failure).unwrap());
    while step(&mut layer, &mut last) {}
    assert_eq!(
        replies,
        [ssh::msg::SERVICE_ACCEPT, 51, 51],
        "a failure for each request, in order"
    );
    assert!(!layer.is_terminal());
}

/// `verification/ssh-layer/tla/Adjust.tla` at full scale, on the
/// production `Channel`. A peer sends one 64 KiB window in 1 KiB packets;
/// over every order of the connection taking a packet
/// (`consume_receive`), the child taking one (the credit `on_command`
/// adds back) and an adjustment going out while `adjustment` says one is
/// due, the peer is told of new room at most 7 times (floor(log2 64) + 1),
/// and some order reaches 7. Room is never owed while the peer has none
/// left without an adjustment being due, and the peer is never told of
/// room the child's credit does not back. With 1 reply and 64 echoes,
/// 72 messages fit russh's 100 per channel.
#[test]
fn a_full_window_brings_at_most_seven_adjustments_in_any_order() {
    use std::collections::HashMap;
    const UNIT: usize = 1024;
    let units = WINDOW as usize / UNIT;
    fn most(
        channel: &Channel,
        consumed: usize,
        held: usize,
        units: usize,
        seen: &mut HashMap<(usize, usize, u32), usize>,
    ) -> usize {
        let key = (consumed, held, channel.advertised);
        if let Some(&n) = seen.get(&key) {
            return n;
        }
        assert!(u64::from(channel.advertised) <= channel.receive);
        assert_eq!(channel.receive, WINDOW as u64 - (held * UNIT) as u64);
        if channel.advertised == 0 && channel.receive > 0 {
            assert!(channel.adjustment().is_some(), "room owed and none told");
        }
        let mut best = 0;
        if consumed < units && channel.advertised > 0 {
            let mut next = clone(channel);
            next.consume_receive(UNIT).unwrap();
            best = best.max(most(&next, consumed + 1, held + 1, units, seen));
        }
        if held > 0 {
            let mut next = clone(channel);
            next.receive += UNIT as u64;
            best = best.max(most(&next, consumed, held - 1, units, seen));
        }
        if let Some(bytes) = channel.adjustment() {
            let mut next = clone(channel);
            next.advertised += bytes;
            best = best.max(1 + most(&next, consumed, held, units, seen));
        }
        seen.insert(key, best);
        best
    }
    fn clone(c: &Channel) -> Channel {
        Channel {
            wire: c.wire,
            peer: c.peer,
            window: c.window,
            max_packet: c.max_packet,
            granted: c.granted,
            receive: c.receive,
            advertised: c.advertised,
            accepted: c.accepted,
            confirmed: c.confirmed,
            eof: c.eof,
            sent_eof: c.sent_eof,
            closed: c.closed,
        }
    }
    // Confirmed as progress confirms: advertised is the credit lent.
    let channel = Channel {
        wire: 0,
        peer: 0,
        window: WINDOW,
        max_packet: PACKET,
        granted: 0,
        receive: WINDOW as u64,
        advertised: WINDOW,
        accepted: true,
        confirmed: true,
        eof: false,
        sent_eof: false,
        closed: false,
    };
    let mut seen = HashMap::new();
    assert_eq!(most(&channel, 0, 0, units, &mut seen), 7);
}

/// Accepts only a public key whose signature verified.
struct Verifying;
impl Handler for Verifying {
    type Session = tests::NoSession;
    fn authenticate(&self, _: &Context<'_>, attempt: &AuthAttempt<'_>) -> AuthDecision {
        if attempt.signature_verified {
            return AuthDecision::Accept;
        }
        AuthDecision::Reject {
            methods: vec![AuthMethod::PublicKey],
            partial_success: false,
            delay: Duration::ZERO,
        }
    }
    fn open(&self, _: &Context<'_>, _: &SessionRequest, _: &mut Output) -> Option<Self::Session> {
        None
    }
}

/// RFC 4252 section 7: a signature that is not correct fails the request
/// with USERAUTH_FAILURE; the client may go on to another key or method.
#[test]
fn a_signature_that_does_not_verify_is_answered_with_failure() {
    let mut layer = Ssh::with_transport(
        Arc::new(Config::new(
            Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
            ssh::Identification::new("2.0", "test", None).unwrap(),
        )),
        Arc::new(Verifying),
        Arc::new(ConnInfo::default()),
        Packets(transport::Negotiated {
            kex: String::new(),
            host: String::new(),
            incoming: String::new(),
            outgoing: String::new(),
        }),
    );
    let budget = Budget::new(4 << 20);
    let entropy = crate::SeededEntropy::new(crate::Seed::from_u64(1));
    let mut observations = Observations::new(8);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    assert!(layer.reserve(&budget) && layer.room(&budget));
    layer.started = true;
    let string = |parts: &[&[u8]]| {
        let mut out = Vec::new();
        for part in parts {
            ssh::SshString(part.to_vec()).write(&mut out).unwrap();
        }
        out
    };
    let forged = userauth(
        "guest",
        auth::Method::PublicKey {
            algorithm: "ssh-ed25519".into(),
            key: string(&[b"ssh-ed25519", &[1; 32]]),
            signature: Some(string(&[b"ssh-ed25519", &[2; 64]])),
        },
    );
    let mut replies = Vec::new();
    for payload in [service_request(), forged, password("guest")] {
        // Room for the reply, as each step makes sure of first.
        assert!(layer.room(&budget));
        assert!(matches!(
            layer.packet(0, &payload, &mut env).expect("the connection goes on"),
            Handled::Done
        ));
        while let Some(StreamCommand::Write(bytes)) = layer.take_command(&mut env) {
            replies.push(bytes.to_vec()[0]);
        }
    }
    assert_eq!(replies, [ssh::msg::SERVICE_ACCEPT, 51, 51]);
    assert!(layer.user.is_none() && !layer.is_terminal());
}
