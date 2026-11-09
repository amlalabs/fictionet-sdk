//! What a world host guarantees to TCP and IP layers installed through the
//! public factories: admission, reset and retirement reach the transport
//! even when it refuses a command for now, and only checked packets of the
//! host's own network reach its transports.

use crate::common::echo_stack::Echo;
use fictionet::stdlib::layer::{
    Admit, Budget, ChildId, Chunk, CommandOf, DatagramCommand, DatagramEvent, Datagrams, Env,
    EventOf, Layer, MessageCommand, MuxOp, PacketCommand, PacketEvent, Packets, Top,
};
use fictionet::stdlib::network::packet::{
    self, Ingress, IpLayer, IpPacket, IpReport, Scope, Scopes, Sort,
};
use fictionet::stdlib::network::tcp::{self, EndpointState, TcpLayer, Verdict};
use fictionet::stdlib::network::transport::Tcp;
use fictionet::stdlib::network::{ConnError, ConnectionExt, Transport};
use fictionet::stdlib::world::net::{Limits, Net};
use fictionet::time::Instant;
use fictionet_test_support::world::world;
use std::collections::{BTreeSet, VecDeque};
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The standard TCP, except that it refuses each `Hold` and `Abort` once
/// before taking it, as a TCP that bounds what it keeps may.
struct Hesitant {
    inner: TcpLayer,
    refused: bool,
}

impl Layer for Hesitant {
    type Lower = Packets<IpPacket, Chunk>;
    type Upper = Tcp;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;
    fn report_bytes(report: &()) -> Option<usize> {
        TcpLayer::report_bytes(report)
    }
    fn is_terminal(&self) -> bool {
        self.inner.is_terminal()
    }
    fn on_event(
        &mut self,
        env: &mut Env<'_, ()>,
        event: EventOf<Self::Lower>,
    ) -> Result<Admit<EventOf<Self::Lower>>, Infallible> {
        self.inner.on_event(env, event)
    }
    fn on_command(
        &mut self,
        env: &mut Env<'_, ()>,
        command: CommandOf<Self::Upper>,
    ) -> Result<Admit<CommandOf<Self::Upper>>, Infallible> {
        use fictionet::stdlib::network::transport::TcpControl;
        if let MuxOp::Control(MessageCommand::Send(
            TcpControl::Hold { .. } | TcpControl::Abort(_),
        )) = command.op()
        {
            if !self.refused {
                self.refused = true;
                return Ok(Admit::Blocked(command));
            }
            self.refused = false;
        }
        self.inner.on_command(env, command)
    }
    fn on_timer(&mut self, env: &mut Env<'_, ()>, timer: ()) -> Result<(), Infallible> {
        self.inner.on_timer(env, timer)
    }
    fn on_done(&mut self, env: &mut Env<'_, ()>, done: ()) -> Result<(), Infallible> {
        self.inner.on_done(env, done)
    }
    fn advance(&mut self, env: &mut Env<'_, ()>) -> Result<bool, Infallible> {
        self.inner.advance(env)
    }
    fn take_command(&mut self, env: &mut Env<'_, Self::Report>) -> Option<CommandOf<Self::Lower>> {
        self.inner.take_command(env)
    }
    fn take_event(&mut self) -> Option<EventOf<Self::Upper>> {
        self.inner.take_event()
    }
    fn take_urgent(&mut self) -> Option<EventOf<Self::Upper>> {
        self.inner.take_urgent()
    }
    fn take_work(&mut self) -> Option<()> {
        self.inner.take_work()
    }
    fn deadline(&self) -> Option<(Instant, ())> {
        self.inner.deadline()
    }
}

impl EndpointState for Hesitant {
    fn read_verdict(&mut self, child: ChildId) -> Verdict {
        EndpointState::read_verdict(&mut self.inner, child)
    }
    fn write_verdict(&self, child: ChildId) -> Verdict {
        EndpointState::write_verdict(&self.inner, child)
    }
    fn connect_verdict(&self, child: ChildId) -> Verdict {
        EndpointState::connect_verdict(&self.inner, child)
    }
    fn end_verdict(&self, child: ChildId) -> Option<ConnError> {
        EndpointState::end_verdict(&self.inner, child)
    }
    fn gone(&self, child: ChildId) -> bool {
        EndpointState::gone(&self.inner, child)
    }
    fn peers(&self) -> BTreeSet<IpAddr> {
        EndpointState::peers(&self.inner)
    }
    fn child_ids(&self) -> Vec<ChildId> {
        EndpointState::child_ids(&self.inner)
    }
    fn busy(&self) -> bool {
        EndpointState::busy(&self.inner)
    }
    fn limit_isolated_peers(&mut self, isolated: Box<dyn Fn(IpAddr) -> bool + Send>) {
        EndpointState::limit_isolated_peers(&mut self.inner, isolated);
    }
}

async fn greeting(fcx: &fictionet::Cx, conn: &mut tcp::TcpConnection) -> fictionet::Result {
    let mut hello = [0; 6];
    let mut used = 0;
    while used < hello.len() {
        let n = conn.read(fcx, &mut hello[used..]).await?;
        assert!(n > 0, "the echo ended before its greeting");
        used += n;
    }
    assert_eq!(&hello, b"hello\n");
    Ok(())
}

/// A TCP that refuses `Hold` and `Abort` for now still gets both: the
/// admitted connection counts against its peer while it is open, so the
/// peer's next one is reset, not served.
#[test]
fn a_tcp_that_refuses_commands_for_now_keeps_the_peer_count_and_resets() {
    world(Duration::from_secs(10), |fcx| async move {
        let server = Ipv4Addr::new(104, 18, 0, 2);
        let factory = tcp::Factory::new(|opening: tcp::Opening| Hesitant {
            inner: TcpLayer::new(opening.addr, opening.options, &opening.cx, opening.cx.now()),
            refused: false,
        });
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .limits(Limits {
                connections_per_peer: 1,
                ..Default::default()
            })
            .host("echo", |host| {
                host.at(server)
                    .tcp_factory(factory)
                    .tcp_stack(7, |_| Echo::stack())
            })
            .start(&fcx, attachments)?;
        let client = fictionet_test_support::sandbox::machine(
            &fcx,
            attacher.attach("client")?,
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let to = SocketAddr::from((server, 7));
        let mut first = client.tcp.connect(&fcx, to).await?;
        greeting(&fcx, &mut first).await?;
        let mut second = client.tcp.connect(&fcx, to).await?;
        let refused = fcx
            .race(
                Some(fcx.now() + Duration::from_secs(1)),
                second.read(&fcx, &mut [0; 1]),
            )
            .await;
        assert!(
            matches!(refused, Ok(Err(ConnError::Reset))),
            "the peer's second connection was not reset: {refused:?}"
        );
        // The first is still served.
        first.write_all(&fcx, b"ping\n").await?;
        let mut echo = [0; 5];
        let mut used = 0;
        while used < echo.len() {
            let n = first.read(&fcx, &mut echo[used..]).await?;
            assert!(n > 0, "the admitted connection ended");
            used += n;
        }
        assert_eq!(&echo, b"ping\n");
        Ok(())
    });
}

/// The standard IP layer, which also hands up, for each UDP packet, an
/// observed copy of it and a copy read on another network.
struct Copies {
    main: IpLayer,
    side: IpLayer,
    tunnel: Scope,
    extra: VecDeque<PacketEvent<IpPacket>>,
}

impl Layer for Copies {
    type Lower = Packets<fictionet::stdlib::layer::Datagram<Ingress>, Chunk>;
    type Upper = Packets<IpPacket, Chunk>;
    type Report = IpReport;
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;
    fn report_bytes(report: &IpReport) -> Option<usize> {
        IpLayer::report_bytes(report)
    }
    fn on_event(
        &mut self,
        env: &mut Env<'_, IpReport>,
        event: EventOf<Self::Lower>,
    ) -> Result<Admit<EventOf<Self::Lower>>, Infallible> {
        let copy = match &event {
            PacketEvent::Packet(raw) => Some((raw.payload().to_vec(), *raw.meta())),
            PacketEvent::Ended => None,
        };
        let admit = self.main.on_event(env, event)?;
        if let (Admit::Taken, Some((bytes, ingress))) = (&admit, copy) {
            let foreign = fictionet::stdlib::layer::Datagram::new(
                Chunk::new(bytes),
                Ingress {
                    scope: self.tunnel,
                    ..ingress
                },
            );
            let _ = self.side.on_event(env, PacketEvent::Packet(foreign))?;
            if let Some(PacketEvent::Packet(packet)) = self.side.take_event()
                && packet.sort() == Sort::Transport(Transport::Udp)
            {
                self.extra.push_back(PacketEvent::Packet(packet));
            }
        }
        Ok(admit)
    }
    fn on_command(
        &mut self,
        env: &mut Env<'_, IpReport>,
        command: PacketCommand<Chunk>,
    ) -> Result<Admit<PacketCommand<Chunk>>, Infallible> {
        self.main.on_command(env, command)
    }
    fn on_timer(&mut self, env: &mut Env<'_, IpReport>, timer: ()) -> Result<(), Infallible> {
        self.main.on_timer(env, timer)
    }
    fn take_command(&mut self, env: &mut Env<'_, Self::Report>) -> Option<PacketCommand<Chunk>> {
        self.main.take_command(env)
    }
    fn take_event(&mut self) -> Option<PacketEvent<IpPacket>> {
        let Some(event) = self.main.take_event() else {
            return self.extra.pop_front();
        };
        if let PacketEvent::Packet(packet) = &event
            && packet.sort() == Sort::Transport(Transport::Udp)
        {
            let observed =
                IpPacket::observed(Chunk::new(packet.bytes().to_vec()), *packet.ingress());
            self.extra.push_back(PacketEvent::Packet(observed));
        }
        Some(event)
    }
    fn deadline(&self) -> Option<(Instant, ())> {
        self.main.deadline()
    }
}

/// Keeps every datagram it gets.
struct Collect(Arc<Mutex<Vec<Vec<u8>>>>);

impl Layer for Collect {
    type Lower = Datagrams<SocketAddr>;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;
    fn on_event(
        &mut self,
        _: &mut Env<'_, Infallible>,
        event: DatagramEvent<SocketAddr>,
    ) -> Result<Admit<DatagramEvent<SocketAddr>>, Infallible> {
        if let DatagramEvent::Datagram(datagram) = event {
            self.0.lock().unwrap().push(datagram.payload().to_vec());
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
    fn take_command(
        &mut self,
        _: &mut Env<'_, Self::Report>,
    ) -> Option<DatagramCommand<SocketAddr>> {
        None
    }
    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

/// An IP layer installed through the public factory may hand up an
/// observed copy, or a packet of another network. The host's transports
/// take neither: each datagram the client sends reaches the application
/// once.
#[test]
fn transports_take_only_checked_packets_of_their_own_network_from_any_ip_layer() {
    world(Duration::from_secs(10), |fcx| async move {
        let server = Ipv4Addr::new(104, 18, 0, 2);
        let tunnel = Scopes::default().tunnel();
        let factory = packet::Factory::new(move |_| Copies {
            main: IpLayer::host(),
            side: IpLayer::host(),
            tunnel,
            extra: VecDeque::new(),
        });
        let received = Arc::new(Mutex::new(Vec::new()));
        let collected = received.clone();
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("sink", |host| {
                host.at(server).ip_factory(factory).udp_stack(
                    9,
                    Budget::new(64 * 1024),
                    move |_| Collect(collected.clone()),
                )
            })
            .start(&fcx, attachments)?;
        let client = fictionet_test_support::sandbox::machine(
            &fcx,
            attacher.attach("client")?,
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let mut socket = client.udp.bind(0)?;
        let sent: [&[u8]; 3] = [b"one", b"", b"three"];
        for datagram in sent {
            socket.send_to(datagram, SocketAddr::from((server, 9)));
            fcx.sleep(Duration::from_millis(10)).await?;
        }
        fcx.sleep(Duration::from_millis(500)).await?;
        assert_eq!(*received.lock().unwrap(), sent);
        Ok(())
    });
}
