use fictionet::Packet;
use std::any::Any;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;

use fictionet::Cx;
use fictionet::stdlib::layer::{
    Admit, Budget, ChildId, CommandOf, Env, EventOf, Layer, PacketCommand, PacketEvent, Packets,
};
use fictionet::stdlib::network::ConnError;
use fictionet::stdlib::network::packet::CheckedIpPacket;
use fictionet::stdlib::network::transport::Tcp;
use fictionet::time::Instant;

use super::{Options, TcpLayer, Verdict};

/// State queries needed by the public asynchronous connection facade.
/// Packet processing, admission, reset and retained connection counts use
/// the layer's ordinary events and `TcpControl` commands. These queries
/// neither consume stream data nor advance protocol time.
pub trait EndpointState: Any + Send {
    /// Result of a read after all queued child data has been taken.
    fn read_verdict(&mut self, child: ChildId) -> Verdict;
    /// Result of a write when the child has no credit.
    fn write_verdict(&self, child: ChildId) -> Verdict;
    /// Whether an outgoing handshake completed.
    fn connect_verdict(&self, child: ChildId) -> Verdict;
    /// Failure of a local half-close, if any.
    fn end_verdict(&self, child: ChildId) -> Option<ConnError>;
    /// Whether the transport reset or retired this connection.
    fn gone(&self, child: ChildId) -> bool;
    /// Peers still owned by the transport, including closing connections.
    fn peers(&self) -> BTreeSet<IpAddr>;
    /// Connection children in deterministic transport order.
    fn child_ids(&self) -> Vec<ChildId>;
    /// Whether bounded progress or output draining left more work to do.
    fn busy(&self) -> bool;
    /// Supplies the addresses whose sources the world prevents spoofing.
    /// Per-source handshake limits may be applied only to these peers.
    fn limit_isolated_peers(&mut self, isolated: Box<dyn Fn(IpAddr) -> bool + Send>);
}

/// Construction context for a TCP implementation, before listeners or the
/// machine's route are published.
pub struct Opening {
    /// The world's clock and entropy.
    pub cx: Cx,
    /// The local IP address.
    pub addr: IpAddr,
    /// Host transport choices supplied by the caller.
    pub options: Options,
    /// Budget for retained transport state.
    pub budget: Budget,
}

/// Constructs TCP beneath the same world application factories.
#[derive(Clone)]
pub struct Factory(Arc<dyn Fn(Opening) -> Stack + Send + Sync>);

impl Factory {
    /// Installs a packet-to-stream-children implementation. It implements
    /// the public `Tcp` control contract, including `Hold` and `Gone` after
    /// the application child closes, and the facade's state queries.
    pub fn new<L>(make: impl Fn(Opening) -> L + Send + Sync + 'static) -> Self
    where
        L: EndpointState
            + Layer<
                Lower = Packets<CheckedIpPacket, Packet>,
                Upper = Tcp,
                Report = (),
                Timer = (),
                Work = (),
                Done = (),
                Error = Infallible,
            >,
    {
        Self(Arc::new(move |opening| {
            let layer = make(opening);
            assert!(
                Layer::depth(&layer) < fictionet::stdlib::layer::MAX_DEPTH,
                "composition is too deep"
            );
            Stack(Box::new(layer))
        }))
    }

    /// Builds an implementation without starting protocol progress.
    pub fn build(&self, opening: Opening) -> Stack {
        (self.0)(opening)
    }
}

impl Default for Factory {
    fn default() -> Self {
        Self::new(|opening| {
            TcpLayer::new(opening.addr, opening.options, &opening.cx, opening.cx.now())
        })
    }
}

trait Erased: EndpointState {
    fn event(
        &mut self,
        env: &mut Env<'_, ()>,
        event: PacketEvent<CheckedIpPacket>,
    ) -> Result<Admit<PacketEvent<CheckedIpPacket>>, Infallible>;
    fn command(
        &mut self,
        env: &mut Env<'_, ()>,
        command: CommandOf<Tcp>,
    ) -> Result<Admit<CommandOf<Tcp>>, Infallible>;
    fn timer(&mut self, env: &mut Env<'_, ()>) -> Result<bool, Infallible>;
    fn advance(&mut self, env: &mut Env<'_, ()>) -> Result<bool, Infallible>;
    fn take_command(&mut self, env: &mut Env<'_, ()>) -> Option<PacketCommand<Packet>>;
    fn take_event(&mut self) -> Option<EventOf<Tcp>>;
    fn take_urgent(&mut self) -> Option<EventOf<Tcp>>;
    fn deadline(&self) -> Option<(Instant, ())>;
    fn work(&mut self) -> Option<()>;
    fn done(&mut self, env: &mut Env<'_, ()>) -> Result<(), Infallible>;
    fn terminal(&self) -> bool;
    fn depth(&self) -> usize;
}

impl<L> Erased for L
where
    L: EndpointState
        + Layer<
            Lower = Packets<CheckedIpPacket, Packet>,
            Upper = Tcp,
            Report = (),
            Timer = (),
            Work = (),
            Done = (),
            Error = Infallible,
        >,
{
    fn event(
        &mut self,
        env: &mut Env<'_, ()>,
        event: PacketEvent<CheckedIpPacket>,
    ) -> Result<Admit<PacketEvent<CheckedIpPacket>>, Infallible> {
        self.on_event(env, event)
    }
    fn command(
        &mut self,
        env: &mut Env<'_, ()>,
        command: CommandOf<Tcp>,
    ) -> Result<Admit<CommandOf<Tcp>>, Infallible> {
        self.on_command(env, command)
    }
    fn timer(&mut self, env: &mut Env<'_, ()>) -> Result<bool, Infallible> {
        self.on_timer(env, ())
    }
    fn advance(&mut self, env: &mut Env<'_, ()>) -> Result<bool, Infallible> {
        Layer::advance(self, env)
    }
    fn take_command(&mut self, env: &mut Env<'_, ()>) -> Option<PacketCommand<Packet>> {
        Layer::take_command(self, env)
    }
    fn take_event(&mut self) -> Option<EventOf<Tcp>> {
        Layer::take_event(self)
    }
    fn take_urgent(&mut self) -> Option<EventOf<Tcp>> {
        Layer::take_urgent(self)
    }
    fn deadline(&self) -> Option<(Instant, ())> {
        Layer::deadline(self)
    }
    fn work(&mut self) -> Option<()> {
        self.take_work()
    }
    fn done(&mut self, env: &mut Env<'_, ()>) -> Result<(), Infallible> {
        self.on_done(env, ())
    }
    fn terminal(&self) -> bool {
        self.is_terminal()
    }
    fn depth(&self) -> usize {
        Layer::depth(self)
    }
}

/// A factory-built TCP layer. Its public packet and child ports stay the
/// same when the implementation changes.
pub struct Stack(Box<dyn Erased>);

impl Stack {
    pub(super) fn state(&self) -> &dyn EndpointState {
        &*self.0
    }
    pub(super) fn state_mut(&mut self) -> &mut dyn EndpointState {
        &mut *self.0
    }
    #[cfg(test)]
    pub(super) fn standard(&self) -> &TcpLayer {
        (&*self.0 as &dyn Any).downcast_ref().unwrap()
    }
    #[cfg(test)]
    pub(super) fn standard_mut(&mut self) -> &mut TcpLayer {
        (&mut *self.0 as &mut dyn Any).downcast_mut().unwrap()
    }
}

impl Layer for Stack {
    type Lower = Packets<CheckedIpPacket, Packet>;
    type Upper = Tcp;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;
    fn report_bytes(_: &()) -> Option<usize> {
        Some(0)
    }
    fn depth(&self) -> usize {
        1 + self.0.depth()
    }
    fn is_terminal(&self) -> bool {
        self.0.terminal()
    }
    fn on_event(
        &mut self,
        env: &mut Env<'_, ()>,
        event: PacketEvent<CheckedIpPacket>,
    ) -> Result<Admit<PacketEvent<CheckedIpPacket>>, Infallible> {
        env.part(|env| self.0.event(env, event))
    }
    fn on_command(
        &mut self,
        env: &mut Env<'_, ()>,
        command: CommandOf<Tcp>,
    ) -> Result<Admit<CommandOf<Tcp>>, Infallible> {
        env.part(|env| self.0.command(env, command))
    }
    fn on_timer(&mut self, env: &mut Env<'_, ()>, _: ()) -> Result<bool, Infallible> {
        env.part(|env| self.0.timer(env))
    }
    fn advance(&mut self, env: &mut Env<'_, ()>) -> Result<bool, Infallible> {
        env.part(|env| self.0.advance(env))
    }
    fn take_command(&mut self, env: &mut Env<'_, ()>) -> Option<PacketCommand<Packet>> {
        env.part(|env| self.0.take_command(env))
    }
    fn take_event(&mut self) -> Option<EventOf<Tcp>> {
        self.0.take_event()
    }
    fn take_urgent(&mut self) -> Option<EventOf<Tcp>> {
        self.0.take_urgent()
    }
    fn take_work(&mut self) -> Option<()> {
        self.0.work()
    }
    fn on_done(&mut self, env: &mut Env<'_, ()>, _: ()) -> Result<(), Infallible> {
        env.part(|env| self.0.done(env))
    }
    fn deadline(&self) -> Option<(Instant, ())> {
        self.0.deadline()
    }
}

impl EndpointState for TcpLayer {
    fn read_verdict(&mut self, child: ChildId) -> Verdict {
        self.read_verdict(child)
    }
    fn write_verdict(&self, child: ChildId) -> Verdict {
        self.write_verdict(child)
    }
    fn connect_verdict(&self, child: ChildId) -> Verdict {
        self.connect_verdict(child)
    }
    fn end_verdict(&self, child: ChildId) -> Option<ConnError> {
        self.end_verdict(child)
    }
    fn gone(&self, child: ChildId) -> bool {
        self.gone(child)
    }
    fn peers(&self) -> BTreeSet<IpAddr> {
        self.peers()
    }
    fn child_ids(&self) -> Vec<ChildId> {
        self.child_ids()
    }
    fn busy(&self) -> bool {
        self.busy() || self.saturated()
    }
    fn limit_isolated_peers(&mut self, isolated: Box<dyn Fn(IpAddr) -> bool + Send>) {
        self.limit_isolated_peers(isolated);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::layer::probe::{Call, Probe, Task};
    use fictionet::stdlib::layer::{Driver, MAX_DEPTH, MessageCommand, MuxCommand};
    use fictionet::stdlib::network::transport::TcpControl;
    use fictionet::{Seed, SeededEntropy};

    type Inner = Probe<Packets<CheckedIpPacket, Packet>, Tcp>;

    /// The probe holds no connections; the facade's queries never reach it
    /// here.
    impl EndpointState for Inner {
        fn read_verdict(&mut self, _: ChildId) -> Verdict {
            Verdict::Wait
        }
        fn write_verdict(&self, _: ChildId) -> Verdict {
            Verdict::Wait
        }
        fn connect_verdict(&self, _: ChildId) -> Verdict {
            Verdict::Wait
        }
        fn end_verdict(&self, _: ChildId) -> Option<ConnError> {
            None
        }
        fn gone(&self, _: ChildId) -> bool {
            false
        }
        fn peers(&self) -> BTreeSet<IpAddr> {
            BTreeSet::new()
        }
        fn child_ids(&self) -> Vec<ChildId> {
            Vec::new()
        }
        fn busy(&self) -> bool {
            false
        }
        fn limit_isolated_peers(&mut self, _: Box<dyn Fn(IpAddr) -> bool + Send>) {}
    }

    #[test]
    fn a_built_implementation_is_lent_one_level_less_and_the_stacks_waker() {
        let (probe, notes) = Inner::new();
        let mut driver = Driver::new(
            Stack(Box::new(probe)),
            Arc::new(SeededEntropy::new(Seed::from_u64(1))),
            Budget::unlimited(),
            Instant::ZERO,
        );
        let (task, waker) = Task::new();
        driver.set_waker(&waker);
        let _ = driver.deliver(PacketEvent::Ended).unwrap();
        let unlisten = TcpControl::Unlisten { port: 80 };
        let _ = driver
            .command(MuxCommand::control(MessageCommand::Send(unlisten)))
            .unwrap();
        driver.run().unwrap();
        assert!(driver.take_command().is_none());
        driver.complete(()).unwrap();
        // The implementation sits one level below the stack, at the top.
        let room = MAX_DEPTH - (Layer::depth(driver.layer()) - 1);
        notes.assert_lent(
            &[
                Call::Event,
                Call::Command,
                Call::Timer,
                Call::Advance,
                Call::TakeCommand,
                Call::Done,
            ],
            room,
            &task,
        );
    }
}
