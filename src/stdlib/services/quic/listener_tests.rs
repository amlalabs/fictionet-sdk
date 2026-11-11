use super::*;
use crate::stdlib::layer::Observations;
use crate::stdlib::services::quic::tests::configs;
use crate::{Entropy, Seed, SeededEntropy};

struct Lab {
    listener: Listener,
    client: QuicLayer,
    client_config: quinn_proto::ClientConfig,
    entropy: Arc<dyn Entropy>,
    budget: Budget,
}

impl Lab {
    fn new(limit: usize) -> Self {
        let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(85)));
        let (client_config, server, endpoint) = configs(entropy.clone(), true);
        let budget = Budget::new(8 << 20);
        let epoch = EngineInstant::now();
        let mut observe = Observations::new(0);
        let mut env = Env::new(Instant::ZERO, entropy.as_ref(), &budget, &mut observe);
        let mut client =
            QuicLayer::new(&mut env, endpoint.clone(), None, epoch, 16, |_| 0u32.into()).unwrap();
        client
            .connect(
                &mut env,
                client_config.clone(),
                "127.0.0.1:4433".parse().unwrap(),
                "localhost",
            )
            .unwrap();
        let listener = Listener::new(
            ListenerConfig {
                endpoint,
                server: Arc::new(server),
                connections: limit,
                streams: 16,
                connection_budget: 1 << 20,
                validation: AddressValidation::Accept,
                cancel: |_| 0u32.into(),
            },
            epoch,
            None,
        );
        Self {
            listener,
            client,
            client_config,
            entropy,
            budget,
        }
    }

    fn initial(&mut self) -> ChildId {
        let mut observe = Observations::new(0);
        let mut env = Env::new(
            Instant::ZERO,
            self.entropy.as_ref(),
            &self.budget,
            &mut observe,
        );
        let Some(DatagramCommand::Send(datagram)) = self.client.take_command(&mut env) else {
            panic!("client Initial")
        };
        let event = DatagramEvent::Datagram(Datagram::new(
            datagram.into_parts().0,
            "127.0.0.1:4444".parse().unwrap(),
        ));
        assert!(matches!(
            self.listener.on_event(&mut env, event).unwrap(),
            Admit::Taken
        ));
        self.listener
            .sessions
            .ids()
            .next()
            .expect("accepted connection")
    }
}

#[test]
fn draining_send_owner_survives_until_its_completion() {
    let mut lab = Lab::new(1);
    let id = lab.initial();
    let mut observe = Observations::new(0);
    let mut env = Env::new(
        Instant::ZERO,
        lab.entropy.as_ref(),
        &lab.budget,
        &mut observe,
    );
    assert!(matches!(
        lab.listener.take_command(&mut env),
        Some(DatagramCommand::Send(_))
    ));
    assert_eq!(lab.listener.flight, Transmission::Connection(id));
    assert!(matches!(
        lab.listener
            .on_command(
                &mut env,
                MuxCommand::from_op(MuxOp::Close(id, Closing::Done))
            )
            .unwrap(),
        Admit::Taken
    ));
    let deadline = lab.listener.deadline().unwrap().0;
    let mut env = Env::new(deadline, lab.entropy.as_ref(), &lab.budget, &mut observe);
    assert!(lab.listener.on_timer(&mut env, ()).unwrap());
    for _ in 0..20 {
        lab.listener.advance(&mut env).unwrap();
        assert!(lab.listener.take_command(&mut env).is_none());
        lab.listener.take_event();
    }
    assert!(lab.listener.sessions.get(id).is_some());
    assert!(!lab.listener.sessions.get(id).unwrap().routing);
    assert!(matches!(
        lab.listener.on_event(&mut env, DatagramEvent::Sent(2)),
        Err(Error::Completion)
    ));
    assert_eq!(lab.listener.flight, Transmission::Connection(id));
    assert!(matches!(
        lab.listener
            .on_event(&mut env, DatagramEvent::Sent(1))
            .unwrap(),
        Admit::Taken
    ));
    for _ in 0..20 {
        lab.listener.advance(&mut env).unwrap();
        if let Some(DatagramCommand::Send(_)) = lab.listener.take_command(&mut env) {
            assert!(matches!(
                lab.listener
                    .on_event(&mut env, DatagramEvent::Sent(1))
                    .unwrap(),
                Admit::Taken
            ));
        }
        lab.listener.take_event();
    }
    assert!(lab.listener.sessions.get(id).is_none());
    assert_eq!(
        lab.listener.endpoint.as_ref().unwrap().open_connections(),
        0
    );
}

#[test]
fn recycled_engine_handle_routes_only_to_the_new_generation() {
    let mut lab = Lab::new(2);
    let old = lab.initial();
    let mut observe = Observations::new(0);
    let mut env = Env::new(
        Instant::ZERO,
        lab.entropy.as_ref(),
        &lab.budget,
        &mut observe,
    );
    assert!(matches!(
        lab.listener.take_command(&mut env),
        Some(DatagramCommand::Send(_))
    ));
    assert!(matches!(
        lab.listener
            .on_command(
                &mut env,
                MuxCommand::from_op(MuxOp::Close(old, Closing::Done))
            )
            .unwrap(),
        Admit::Taken
    ));
    let deadline = lab.listener.deadline().unwrap().0;
    let mut env = Env::new(deadline, lab.entropy.as_ref(), &lab.budget, &mut observe);
    lab.listener.on_timer(&mut env, ()).unwrap();
    for _ in 0..20 {
        lab.listener.advance(&mut env).unwrap();
    }
    let old_handle = lab
        .listener
        .sessions
        .get(old)
        .unwrap()
        .layer
        .connection
        .as_ref()
        .unwrap()
        .0;
    assert_eq!(lab.listener.routed(old_handle), None);
    // The endpoint reuses its numeric handle while the old adapter still
    // owns a UDP send. Its generation remains different at the mux boundary.
    let connection = lab
        .listener
        .endpoint
        .as_mut()
        .unwrap()
        .connect(
            lab.listener.epoch + deadline.since_start(),
            lab.client_config,
            "127.0.0.1:5555".parse().unwrap(),
            "localhost",
        )
        .unwrap();
    assert_eq!(connection.0, old_handle);
    let mut layer = QuicLayer::with_channels(
        None,
        lab.listener.epoch,
        Slots::with_budget(16, &lab.budget).unwrap(),
        |_| 0u32.into(),
    );
    layer.connection = Some(connection);
    let budget = Budget::new(1 << 20);
    let child = lab
        .listener
        .sessions
        .insert(Session {
            layer,
            share: Share {
                budget,
                _paid: lab.budget.charge(1 << 20).unwrap(),
            },
            announced: false,
            opening: None,
            closing: false,
            routing: true,
        })
        .unwrap_or_else(|_| panic!("free adapter slot"));
    assert_ne!(old, child.id());
    assert_eq!(lab.listener.routed(old_handle), Some(child.id()));
    assert!(matches!(
        lab.listener
            .on_event(&mut env, DatagramEvent::Sent(1))
            .unwrap(),
        Admit::Taken
    ));
    assert!(!lab.listener.sessions.get(old).unwrap().layer.flight.0);
}

#[test]
fn refused_listener_storage_keeps_input_before_endpoint_creation() {
    let mut lab = Lab::new(2);
    let budget = Budget::new(0);
    let mut observe = Observations::new(0);
    let mut env = Env::new(Instant::ZERO, lab.entropy.as_ref(), &budget, &mut observe);
    let input = DatagramEvent::Datagram(Datagram::new(
        Chunk::unpaid(vec![7; 1200]),
        "127.0.0.1:4444".parse().unwrap(),
    ));
    let Admit::Blocked(DatagramEvent::Datagram(datagram)) =
        lab.listener.on_event(&mut env, input).unwrap()
    else {
        panic!("unpaid listener")
    };
    assert_eq!(datagram.payload(), &[7; 1200]);
    assert!(lab.listener.endpoint.is_none());
    assert!(!lab.listener.initialized);
    assert_eq!(budget.used(), 0);
}

#[test]
fn full_listener_refuses_new_initials_and_keeps_the_existing_connection() {
    let mut lab = Lab::new(1);
    let existing = lab.initial();
    let mut observe = Observations::new(0);
    let mut env = Env::new(
        Instant::ZERO,
        lab.entropy.as_ref(),
        &lab.budget,
        &mut observe,
    );
    let mut client = QuicLayer::new(
        &mut env,
        lab.listener.config.endpoint.clone(),
        None,
        lab.listener.epoch,
        16,
        |_| 0u32.into(),
    )
    .unwrap();
    client
        .connect(
            &mut env,
            lab.client_config,
            "127.0.0.1:4433".parse().unwrap(),
            "localhost",
        )
        .unwrap();
    let Some(DatagramCommand::Send(datagram)) = client.take_command(&mut env) else {
        panic!("client Initial")
    };
    assert!(matches!(
        lab.listener
            .on_event(
                &mut env,
                DatagramEvent::Datagram(Datagram::new(
                    datagram.into_parts().0,
                    "127.0.0.1:4445".parse().unwrap(),
                ))
            )
            .unwrap(),
        Admit::Taken
    ));
    assert_eq!(lab.listener.sessions.len(), 1);
    assert!(lab.listener.sessions.get(existing).is_some());
    assert_eq!(
        lab.listener.endpoint.as_ref().unwrap().open_connections(),
        1
    );
    // The newcomer hears CONNECTION_REFUSED at once instead of waiting
    // out its handshake timer.
    let Some(DatagramCommand::Send(refusal)) = lab.listener.take_command(&mut env) else {
        panic!("refusal")
    };
    assert_eq!(
        *refusal.meta(),
        "127.0.0.1:4445".parse::<SocketAddr>().unwrap()
    );
    assert!(matches!(
        client
            .on_event(
                &mut env,
                DatagramEvent::Datagram(Datagram::new(
                    refusal.into_parts().0,
                    "127.0.0.1:4433".parse().unwrap(),
                )),
            )
            .unwrap(),
        Admit::Taken
    ));
    assert!(matches!(
        lab.listener
            .on_event(&mut env, DatagramEvent::Sent(1))
            .unwrap(),
        Admit::Taken
    ));
    client.advance(&mut env).unwrap();
    assert!(matches!(
        client.take_event(),
        Some(MuxEvent::Control(ControlEvent::Lost(
            quinn_proto::ConnectionError::ConnectionClosed(close)
        ))) if close.error_code == quinn_proto::TransportErrorCode::CONNECTION_REFUSED
    ));
    let Some(DatagramCommand::Send(response)) = lab.listener.take_command(&mut env) else {
        panic!("existing connection progresses")
    };
    assert_eq!(
        *response.meta(),
        "127.0.0.1:4444".parse::<SocketAddr>().unwrap()
    );
    assert!(matches!(
        lab.listener
            .on_event(&mut env, DatagramEvent::Ended)
            .unwrap(),
        Admit::Taken
    ));
    while lab.listener.advance(&mut env).unwrap() {
        lab.listener.take_event();
    }
    assert!(lab.listener.is_terminal());
    assert!(lab.listener.take_command(&mut env).is_none());
}

#[test]
fn closing_the_socket_cancels_pending_application_datagram_completions() {
    let mut lab = Lab::new(1);
    let id = lab.initial();
    let session = lab.listener.sessions.get_mut(id).unwrap();
    session.announced = true;
    session.layer.datagram_send = DatagramSend::Ready;
    let mut observe = Observations::new(0);
    let mut env = Env::new(
        Instant::ZERO,
        lab.entropy.as_ref(),
        &lab.budget,
        &mut observe,
    );
    assert!(matches!(
        lab.listener
            .on_event(&mut env, DatagramEvent::Ended)
            .unwrap(),
        Admit::Taken
    ));
    assert!(lab.listener.take_urgent().is_none());
    assert!(!lab.listener.on_timer(&mut env, ()).unwrap());
    assert!(lab.listener.advance(&mut env).unwrap());
    assert!(matches!(lab.listener.take_event(), Some(MuxEvent::Closed(closed)) if closed == id));
    assert!(lab.listener.is_terminal());
}

#[test]
fn unpaid_wire_input_is_dropped_before_listener_routing() {
    let mut lab = Lab::new(1);
    let mut observe = Observations::new(0);
    let mut env = Env::new(
        Instant::ZERO,
        lab.entropy.as_ref(),
        &lab.budget,
        &mut observe,
    );
    let remote = "127.0.0.1:4444".parse().unwrap();
    assert!(matches!(
        lab.listener
            .on_event(
                &mut env,
                DatagramEvent::Datagram(Datagram::new(Chunk::default(), remote))
            )
            .unwrap(),
        Admit::Taken
    ));
    let Some(DatagramCommand::Send(initial)) = lab.client.take_command(&mut env) else {
        panic!("client Initial");
    };
    let (payload, _) = initial.into_parts();
    let held = lab
        .budget
        .charge(lab.budget.limit() - lab.budget.used())
        .unwrap();
    assert!(matches!(
        lab.listener
            .on_event(
                &mut env,
                DatagramEvent::Datagram(Datagram::new(payload.clone(), remote))
            )
            .unwrap(),
        Admit::Taken
    ));
    assert_eq!(lab.listener.sessions.len(), 0);
    assert_eq!(lab.budget.used(), lab.budget.limit());
    drop(held);
    assert!(matches!(
        lab.listener
            .on_event(
                &mut env,
                DatagramEvent::Datagram(Datagram::new(payload, remote))
            )
            .unwrap(),
        Admit::Taken
    ));
    assert_eq!(lab.listener.sessions.len(), 1);
}

impl Lab {
    /// A second client's first Initial, from another address.
    fn newcomer(&mut self) -> Admit<DatagramEvent<SocketAddr>> {
        let mut observe = Observations::new(0);
        let env = &mut Env::new(
            Instant::ZERO,
            self.entropy.as_ref(),
            &self.budget,
            &mut observe,
        );
        let mut client = QuicLayer::new(
            env,
            self.listener.config.endpoint.clone(),
            None,
            self.listener.epoch,
            16,
            |_| 0u32.into(),
        )
        .unwrap();
        client
            .connect(
                env,
                self.client_config.clone(),
                "127.0.0.1:4433".parse().unwrap(),
                "localhost",
            )
            .unwrap();
        let Some(DatagramCommand::Send(initial)) = client.take_command(env) else {
            panic!("client Initial")
        };
        self.listener
            .on_event(
                env,
                DatagramEvent::Datagram(Datagram::new(
                    initial.into_parts().0,
                    "127.0.0.1:4445".parse().unwrap(),
                )),
            )
            .unwrap()
    }

    /// Closes connection `id` and runs it through draining until the
    /// listener retires it.
    fn retire(&mut self, id: ChildId) {
        let mut observe = Observations::new(0);
        let mut env = Env::new(
            Instant::ZERO,
            self.entropy.as_ref(),
            &self.budget,
            &mut observe,
        );
        let _ = self.listener.on_command(
            &mut env,
            MuxCommand::from_op(MuxOp::Close(id, Closing::Done)),
        );
        let deadline = self.listener.deadline().unwrap().0;
        let mut env = Env::new(deadline, self.entropy.as_ref(), &self.budget, &mut observe);
        self.listener.on_timer(&mut env, ()).unwrap();
        for _ in 0..40 {
            self.listener.advance(&mut env).unwrap();
            if let Some(DatagramCommand::Send(_)) = self.listener.take_command(&mut env) {
                assert!(matches!(
                    self.listener
                        .on_event(&mut env, DatagramEvent::Sent(1))
                        .unwrap(),
                    Admit::Taken
                ));
            }
            self.listener.take_event();
        }
        assert!(self.listener.sessions.get(id).is_none());
    }
}

#[test]
fn a_connection_pays_from_its_own_share_and_returns_it_once_freed() {
    let mut lab = Lab::new(1);
    let id = lab.initial();
    let share = &lab.listener.sessions.get(id).unwrap().share;
    // The connection's stream slots and the state of its first flight are
    // charged to its own budget, which the listener's budget pays for.
    assert!(share.budget.used() > 0);
    assert!(lab.budget.used() >= 1 << 20);
    // Storage the application above still holds when the connection goes.
    let held = share.budget.charge(1).unwrap();
    lab.retire(id);
    assert_eq!(lab.listener.released.as_ref().unwrap().len(), 1);
    let paid = lab.budget.used();
    assert!(paid >= 1 << 20);

    // Its share still counts: the newcomer is refused.
    assert!(matches!(lab.newcomer(), Admit::Taken));
    assert!(lab.listener.sessions.is_empty());
    let mut observe = Observations::new(0);
    let mut env = Env::new(
        Instant::ZERO,
        lab.entropy.as_ref(),
        &lab.budget,
        &mut observe,
    );
    assert!(matches!(
        lab.listener.take_command(&mut env),
        Some(DatagramCommand::Send(_))
    ));
    assert!(matches!(
        lab.listener
            .on_event(&mut env, DatagramEvent::Sent(1))
            .unwrap(),
        Admit::Taken
    ));
    // Once the last of it is freed, the next newcomer gets the share.
    drop(held);
    assert!(matches!(lab.newcomer(), Admit::Taken));
    assert_eq!(lab.listener.sessions.len(), 1);
    assert!(lab.listener.released.as_ref().unwrap().is_empty());
}

#[test]
fn a_retry_listener_admits_only_a_client_that_returns_its_token() {
    let mut lab = Lab::new(1);
    lab.listener.config.validation = AddressValidation::Retry;
    let mut observe = Observations::new(0);
    let mut env = Env::new(
        Instant::ZERO,
        lab.entropy.as_ref(),
        &lab.budget,
        &mut observe,
    );
    let remote: SocketAddr = "127.0.0.1:4444".parse().unwrap();
    let Some(DatagramCommand::Send(initial)) = lab.client.take_command(&mut env) else {
        panic!("client Initial")
    };
    let event = DatagramEvent::Datagram(Datagram::new(initial.into_parts().0, remote));
    assert!(matches!(
        lab.client
            .on_event(&mut env, DatagramEvent::Sent(1))
            .unwrap(),
        Admit::Taken
    ));
    assert!(matches!(
        lab.listener.on_event(&mut env, event).unwrap(),
        Admit::Taken
    ));
    // A Retry, and no connection or share for the unproven address.
    assert!(lab.listener.sessions.is_empty());
    assert!(lab.budget.used() < 1 << 20);
    let Some(DatagramCommand::Send(retry)) = lab.listener.take_command(&mut env) else {
        panic!("Retry")
    };
    assert!(matches!(
        lab.listener
            .on_event(&mut env, DatagramEvent::Sent(1))
            .unwrap(),
        Admit::Taken
    ));
    let retry = DatagramEvent::Datagram(Datagram::new(
        retry.into_parts().0,
        "127.0.0.1:4433".parse().unwrap(),
    ));
    assert!(matches!(
        lab.client.on_event(&mut env, retry).unwrap(),
        Admit::Taken
    ));
    // The client starts again with the token, and is admitted.
    lab.client.advance(&mut env).unwrap();
    let Some(DatagramCommand::Send(initial)) = lab.client.take_command(&mut env) else {
        panic!("Initial with the token")
    };
    let event = DatagramEvent::Datagram(Datagram::new(initial.into_parts().0, remote));
    assert!(matches!(
        lab.listener.on_event(&mut env, event).unwrap(),
        Admit::Taken
    ));
    assert_eq!(lab.listener.sessions.len(), 1);
    assert!(lab.budget.used() >= 1 << 20);
}
