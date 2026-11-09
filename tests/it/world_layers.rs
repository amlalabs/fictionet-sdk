//! What a world host guarantees to TCP layers installed through the public
//! factory: admission, reset and retirement reach the transport even when
//! it refuses a command for now.

use crate::common::echo_stack::Echo;
use fictionet::stdlib::layer::{
    Admit, ChildId, Chunk, CommandOf, Env, EventOf, Layer, MessageCommand, MuxOp, Packets,
};
use fictionet::stdlib::network::packet::CheckedIpPacket;
use fictionet::stdlib::network::tcp::{self, EndpointState, TcpLayer, Verdict};
use fictionet::stdlib::network::transport::Tcp;
use fictionet::stdlib::network::{ConnError, ConnectionExt};
use fictionet::stdlib::world::net::{Limits, Net};
use fictionet::time::Instant;
use fictionet_test_support::world::world;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// The standard TCP, except that it refuses each `Hold` and `Abort` once
/// before taking it, as a TCP that bounds what it keeps may.
struct Hesitant {
    inner: TcpLayer,
    refused: bool,
}

impl Layer for Hesitant {
    type Lower = Packets<CheckedIpPacket, Chunk>;
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
