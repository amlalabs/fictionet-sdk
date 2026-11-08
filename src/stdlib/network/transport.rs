//! What the transport layers over the [IP layer](super::packet) offer the
//! layers above them: the ports, opening contexts and control messages of
//! TCP, UDP and a passive TCP observer.
//!
//! Each transport sits on whole IP packets and offers a [`Mux`]: one child
//! per connection or socket, opened with a context that says what it is,
//! and a control port for what concerns the endpoint as a whole.
//!
//! | Transport | Lower port | Upper port | A child is |
//! | --- | --- | --- | --- |
//! | TCP | `Packets<IpPacket, Chunk>` | [`Tcp`] | one connection, a [`ByteStream`], opened as a [`TcpOpening`] |
//! | UDP | `Packets<IpPacket, Chunk>` | [`Udp`] | one bound socket, [`Datagrams`] with the peer's address, opened as a [`UdpBound`] |
//! | TCP observer | `Packets<IpPacket, Infallible>` | [`TcpObserver`] | one observed connection, an [`ObservedStream`], opened as an [`ObservedConnection`] |
//!
//! A transport takes the packets whose
//! [`IpPacket::transport`](super::packet::IpPacket::transport) is its own,
//! ICMP errors quoting its packets included, and sends whole IP packets it
//! built. The observer sends nothing: the only command its lower port has
//! is the end, and it never gives it.
//!
//! Applications attach with [`Children`](fictionet::stdlib::layer::Children),
//! whose factory receives each child's opening context, and whatever runs
//! the endpoint (listening, connecting, binding) sits on the control port
//! above them:
//!
//! ```
//! use fictionet::stdlib::layer::{ByteStream, Chain, Children, Layer, Messages, Top};
//! use fictionet::stdlib::network::transport::{Tcp, TcpControl, TcpNotice, TcpOpening};
//!
//! /// A host's TCP: the transport, an application on every connection, and
//! /// the code that listens and connects on top.
//! fn host<T, A, C>(
//!     tcp: T,
//!     app: impl FnMut(TcpOpening) -> A + Send + 'static,
//!     control: C,
//! ) -> Chain<Chain<T, Children<A, Messages<TcpNotice, TcpControl>, TcpOpening>>, C>
//! where
//!     T: Layer<Upper = Tcp>,
//!     A: Layer<Lower = ByteStream, Upper = Top>,
//!     C: Layer<Lower = Messages<TcpNotice, TcpControl>>,
//! {
//!     let mut app = app;
//!     let children = Children::new(1024, 64 << 10, move |_, opening, _| app(opening));
//!     Chain::new(Chain::new(tcp, children), control)
//! }
//! ```

use core::any::Any;
use core::fmt;
use std::net::{IpAddr, SocketAddr};

use fictionet::stdlib::layer::{
    ByteStream, ChildId, Datagrams, Direction, Messages, Mux, ObservedStream, Top,
};
use fictionet::stdlib::network::ConnError;
use fictionet::stdlib::network::packet::Scope;
use fictionet::stdlib::network::tcp::{Answer, Handshake};
use fictionet::time::Duration;

/// The port a TCP layer offers: one [`ByteStream`] child per connection,
/// opened as a [`TcpOpening`], and [`TcpControl`] for the endpoint.
pub type Tcp = Mux<ByteStream, Messages<TcpNotice, TcpControl>, TcpOpening>;

/// The port a UDP layer offers: one child per bound socket, carrying
/// datagrams with the peer's address, opened as a [`UdpBound`], and
/// [`UdpControl`] for the endpoint.
pub type Udp = Mux<Datagrams<SocketAddr>, Messages<UdpNotice, UdpControl>, UdpBound>;

/// The port a passive TCP observer offers: one [`ObservedStream`] child per
/// observed connection, opened as an [`ObservedConnection`]. Nothing above
/// can command it.
pub type TcpObserver = Mux<ObservedStream, Top, ObservedConnection>;

/// A number the layer above chooses for a request it sends down, which the
/// answer names. The transport never reads anything into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Request(pub u64);

// ---------------------------------------------------------------------------
// TCP

/// What a TCP connection is, given when its child opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpOpening {
    /// The network the connection belongs to.
    pub scope: Scope,
    /// This side's address and port.
    pub local: SocketAddr,
    /// The peer's address and port.
    pub remote: SocketAddr,
    /// How it was opened.
    pub origin: TcpOrigin,
}

/// How a TCP connection was opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpOrigin {
    /// The listener on the local port accepted it, after this handshake.
    Accepted(Handshake),
    /// It is the connection this [`TcpControl::Connect`] asked for.
    Connected(Request),
}

/// What goes down a TCP layer's control port.
pub enum TcpControl {
    /// Listen on the literal wire `port`, zero included. Fails
    /// ([`TcpNotice::ListenFailed`]) if something listens there already or
    /// an outgoing connection uses the port. Connections whose handshake
    /// finished wait in the listener's backlog until [`TcpControl::Accept`]
    /// lets them open a child.
    Listen {
        /// The port.
        port: u16,
        /// At most this many connections wait for the final ACK of their
        /// handshake before the listener answers with SYN cookies. `None`
        /// keeps the endpoint's own.
        backlog: Option<usize>,
        /// How the listener answers SYNs and final ACKs. `None` takes
        /// every one with the endpoint's defaults.
        answer: Option<Box<dyn Answer>>,
    },
    /// Stop listening on `port` and free it. Connections it already
    /// accepted go on.
    Unlisten {
        /// The port.
        port: u16,
    },
    /// Open a connection to `remote` from an ephemeral port. Its child
    /// opens at once with [`TcpOrigin::Connected`], so closing the child
    /// gives the attempt up; it gets credit to write once the handshake is
    /// done. A connection that cannot be tried, or whose handshake fails,
    /// is reported with [`TcpNotice::ConnectFailed`], and a child it had
    /// is closed.
    Connect {
        /// The number the answer names.
        request: Request,
        /// Where to connect.
        remote: SocketAddr,
    },
    /// End every connection with a peer whose address `which` accepts at
    /// once, discarding what was still to be sent, as a reset does: for
    /// peers that are gone for good.
    AbortPeers(Box<dyn Fn(IpAddr) -> bool + Send>),
    /// Let `count` more connections from `port`'s backlog open a child, as
    /// many calls of `accept(2)` would. Until one is accepted it counts
    /// against the backlog.
    Accept {
        /// The listening port.
        port: u16,
        /// How many more.
        count: usize,
    },
    /// Hold at most `backlog` connections on `port` that are not accepted
    /// yet, from now on. Those already held stay.
    Backlog {
        /// The listening port.
        port: u16,
        /// The new backlog.
        backlog: usize,
    },
    /// Answer `port`'s handshakes with `answer` from now on.
    Answer {
        /// The listening port.
        port: u16,
        /// How it answers.
        answer: Box<dyn Answer>,
    },
    /// Reset the connection of this child at once, whether the child is
    /// open or was closed and its connection is still closing. Nothing once
    /// the connection is [gone](TcpNotice::Gone) into TIME-WAIT or forgotten.
    Abort(ChildId),
    /// Send a keepalive after this long idle, and as often after that, on
    /// the connection of an open child; `None` sends none.
    KeepAlive {
        /// The child.
        child: ChildId,
        /// The interval.
        interval: Option<Duration>,
    },
    /// Keep `item` until the connection of this child is gone: reset,
    /// retired into TIME-WAIT, or forgotten, which may be after the child
    /// is closed. Dropped at once if it is gone already. Limits that count
    /// connections hold their count here.
    Hold {
        /// The child.
        child: ChildId,
        /// What to keep.
        item: Box<dyn Any + Send>,
    },
}

impl fmt::Debug for TcpControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpControl::Listen {
                port,
                backlog,
                answer,
            } => f
                .debug_struct("Listen")
                .field("port", port)
                .field("backlog", backlog)
                .field("answer", &answer.is_some())
                .finish(),
            TcpControl::Unlisten { port } => {
                f.debug_struct("Unlisten").field("port", port).finish()
            }
            TcpControl::Connect { request, remote } => f
                .debug_struct("Connect")
                .field("request", request)
                .field("remote", remote)
                .finish(),
            TcpControl::AbortPeers(_) => f.write_str("AbortPeers"),
            TcpControl::Accept { port, count } => f
                .debug_struct("Accept")
                .field("port", port)
                .field("count", count)
                .finish(),
            TcpControl::Backlog { port, backlog } => f
                .debug_struct("Backlog")
                .field("port", port)
                .field("backlog", backlog)
                .finish(),
            TcpControl::Answer { port, .. } => {
                f.debug_struct("Answer").field("port", port).finish()
            }
            TcpControl::Abort(child) => f.debug_tuple("Abort").field(child).finish(),
            TcpControl::KeepAlive { child, interval } => f
                .debug_struct("KeepAlive")
                .field("child", child)
                .field("interval", interval)
                .finish(),
            TcpControl::Hold { child, .. } => f.debug_struct("Hold").field("child", child).finish(),
        }
    }
}

/// What comes up a TCP layer's control port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpNotice {
    /// The listener asked for is in place.
    Listening {
        /// Its port.
        port: u16,
    },
    /// The port asked for is in use.
    ListenFailed {
        /// The port.
        port: u16,
    },
    /// A connection asked for did not open.
    ConnectFailed {
        /// The request.
        request: Request,
        /// Why: refused, unreachable, timed out, or the endpoint stopped.
        error: ConnError,
    },
    /// A segment for a port nothing listens on was answered as the
    /// endpoint's closed-port policy says.
    Refused {
        /// Who sent it.
        peer: SocketAddr,
        /// Where it was going.
        local: SocketAddr,
    },
    /// The connection of this child is gone: reset by either side, retired
    /// into TIME-WAIT, or forgotten. What [`TcpControl::Hold`] kept for it
    /// is released, now or when the connection is forgotten. It may be
    /// said more than once.
    Gone(ChildId),
}

// ---------------------------------------------------------------------------
// UDP

/// What a bound UDP socket is, given when its child opens. Its datagrams
/// carry the peer's address; the destination each one was sent to stays
/// on the [`IpPacket`](super::packet::IpPacket) it arrived in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UdpBound {
    /// The network the socket belongs to.
    pub scope: Scope,
    /// The address and port it is bound to.
    pub local: SocketAddr,
    /// The [`UdpControl::Bind`] that asked for it.
    pub request: Request,
}

/// What goes down a UDP layer's control port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpControl {
    /// Bind a socket on `port`. Port zero is what the endpoint's
    /// [`Settings::port_zero`](super::udp::Settings::port_zero) says, an
    /// ephemeral port by default, never a literal port zero by analogy with
    /// TCP. It opens a child, or fails with [`UdpNotice::BindFailed`].
    Bind {
        /// The number the answer names.
        request: Request,
        /// The port.
        port: u16,
    },
    /// Receive datagrams sent to the multicast `group`.
    Join(IpAddr),
    /// Stop receiving datagrams sent to `group`.
    Leave(IpAddr),
}

/// What comes up a UDP layer's control port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpNotice {
    /// The port asked for is in use, or no ephemeral port is free.
    BindFailed {
        /// The request.
        request: Request,
        /// The port it asked for.
        port: u16,
    },
    /// A multicast group could not be joined.
    JoinFailed(IpAddr),
    /// A datagram for a port nothing is bound to was answered as the
    /// endpoint's ICMP options say.
    Refused {
        /// Who sent it.
        peer: SocketAddr,
        /// Where it was going.
        local: SocketAddr,
    },
}

// ---------------------------------------------------------------------------
// The passive TCP observer

/// What an observed TCP connection is, given when its child opens.
///
/// A connection is one generation of one pair of endpoints in one scope, so
/// the same tuple inside a tunnel and outside it, or before and after a new
/// SYN, are different connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObservedConnection {
    /// The network the connection belongs to.
    pub scope: Scope,
    /// The sender of the first packet the observer saw of it.
    /// [`Direction::Forward`] runs from here to `second`.
    pub first: SocketAddr,
    /// The other endpoint.
    pub second: SocketAddr,
    /// Which connection on this scope and pair of endpoints it is, counting
    /// from zero in the order the observer saw them start.
    pub generation: u64,
    /// The direction its SYN went, when the observer saw it: that side
    /// opened the connection. `None` when the capture started later.
    pub opened: Option<Direction>,
}

impl ObservedConnection {
    /// The endpoints in a fixed order, the lower first, with the scope and
    /// generation: the same for both directions. The order says nothing
    /// about which side is client or server.
    pub fn key(&self) -> (Scope, SocketAddr, SocketAddr, u64) {
        let (a, b) = if self.first <= self.second {
            (self.first, self.second)
        } else {
            (self.second, self.first)
        };
        (self.scope, a, b, self.generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use std::sync::{Arc, Mutex};

    use fictionet::stdlib::layer::{
        Admit, Budget, Children, Chunk, CommandOf, Credited, Datagram, DatagramEvent, Driver, Env,
        EventOf, Layer, MuxEvent, ObservedEvent, Port, Slots, StreamEvent, Termination,
    };
    use fictionet::time::Instant;
    use fictionet::{Seed, SeededEntropy};

    /// A child application that keeps every event it is given.
    struct Keep<P: Port> {
        seen: Arc<Mutex<Vec<EventOf<P>>>>,
    }

    impl<P> Layer for Keep<P>
    where
        P: Port,
    {
        type Lower = P;
        type Upper = Top;
        type Report = ();
        type Timer = ();
        type Work = ();
        type Done = ();
        type Error = Infallible;

        fn on_event(
            &mut self,
            _: &mut Env<'_, ()>,
            event: EventOf<P>,
        ) -> Result<Admit<EventOf<P>>, Infallible> {
            self.seen.lock().unwrap().push(event);
            Ok(Admit::Taken)
        }

        fn on_command(
            &mut self,
            _: &mut Env<'_, ()>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match command {}
        }

        fn take_command(&mut self) -> Option<CommandOf<P>> {
            None
        }

        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    fn drive<B: Layer<Upper = Top>, K: Port, O>(
        children: Children<B, K, O>,
    ) -> Driver<Children<B, K, O>>
    where
        EventOf<B::Lower>: Credited,
        CommandOf<B::Lower>: Credited,
    {
        Driver::new(
            children,
            Arc::new(SeededEntropy::new(Seed::from_u64(5))),
            Budget::new(1 << 20),
            Instant::ZERO,
        )
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_connection_child_is_made_from_its_opening() {
        let openings = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (o, s) = (openings.clone(), seen.clone());
        let mut d = drive(Children::<
            Keep<ByteStream>,
            Messages<TcpNotice, TcpControl>,
            TcpOpening,
        >::new(4, 1024, move |_, opening, _| {
            o.lock().unwrap().push(opening);
            Keep { seen: s.clone() }
        }));
        let opening = TcpOpening {
            scope: Scope::ROOT,
            local: addr("10.0.0.1:443"),
            remote: addr("10.0.0.2:50000"),
            origin: TcpOrigin::Connected(Request(9)),
        };
        let mut slots = Slots::new(1);
        let child = slots.insert(()).unwrap();
        let id = child.id();
        assert!(matches!(
            d.deliver(MuxEvent::Opened(child, opening.clone(), 1024)),
            Ok(Admit::Taken)
        ));
        d.run().unwrap();
        assert_eq!(*openings.lock().unwrap(), [opening]);
        let _ = d
            .deliver(MuxEvent::Child(
                id,
                StreamEvent::Data(Chunk::new(b"hi".to_vec())),
            ))
            .unwrap();
        d.run().unwrap();
        let seen = seen.lock().unwrap();
        assert!(matches!(&seen[..], [StreamEvent::Data(bytes)] if &bytes[..] == b"hi"));
    }

    #[test]
    fn a_socket_child_keeps_empty_datagrams_and_their_peers() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let mut d = drive(Children::<
            Keep<Datagrams<SocketAddr>>,
            Messages<UdpNotice, UdpControl>,
            UdpBound,
        >::new(4, 8, move |_, bound, _| {
            assert_eq!(bound.local, addr("10.0.0.1:53"));
            Keep { seen: s.clone() }
        }));
        let bound = UdpBound {
            scope: Scope::ROOT,
            local: addr("10.0.0.1:53"),
            request: Request(1),
        };
        let mut slots = Slots::new(1);
        let child = slots.insert(()).unwrap();
        let id = child.id();
        let _ = d.deliver(MuxEvent::Opened(child, bound, 1)).unwrap();
        d.run().unwrap();
        let peer = addr("10.0.0.2:1234");
        for payload in [&b""[..], b"query"] {
            let datagram = Datagram::new(Chunk::new(payload.to_vec()), peer);
            let event = MuxEvent::Child(id, DatagramEvent::Datagram(datagram));
            assert!(matches!(d.deliver(event), Ok(Admit::Taken)));
            d.run().unwrap();
        }
        let seen = seen.lock().unwrap();
        let got: Vec<(Vec<u8>, SocketAddr)> = seen
            .iter()
            .map(|event| match event {
                DatagramEvent::Datagram(d) => (d.payload().to_vec(), *d.meta()),
                DatagramEvent::Ended => panic!("the socket ended"),
            })
            .collect();
        assert_eq!(got, [(Vec::new(), peer), (b"query".to_vec(), peer)]);
    }

    #[test]
    fn an_observed_child_gets_both_directions_gaps_and_ends_in_order() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let mut d = drive(
            Children::<Keep<ObservedStream>, Top, ObservedConnection>::new(
                4,
                1024,
                move |_, _, _| Keep { seen: s.clone() },
            ),
        );
        let connection = ObservedConnection {
            scope: Scope::tunnel(),
            first: addr("10.0.0.2:50000"),
            second: addr("10.0.0.1:443"),
            generation: 0,
            opened: Some(Direction::Forward),
        };
        let mut slots = Slots::new(1);
        let child = slots.insert(()).unwrap();
        let id = child.id();
        let _ = d.deliver(MuxEvent::Opened(child, connection, 0)).unwrap();
        d.run().unwrap();
        let data = |direction, bytes: &[u8], sequence| ObservedEvent::Data {
            direction,
            bytes: Chunk::new(bytes.to_vec()),
            sequence,
            source: None,
        };
        let events = [
            data(Direction::Forward, b"GET", 1),
            data(Direction::Reverse, b"HTTP", 1),
            ObservedEvent::Gap {
                direction: Direction::Reverse,
                sequence: 5,
                missing: Some(10),
            },
            data(Direction::Reverse, b"tail", 15),
            ObservedEvent::End {
                direction: Direction::Reverse,
                cause: Termination::Truncated,
            },
            ObservedEvent::End {
                direction: Direction::Forward,
                cause: Termination::Fin,
            },
        ];
        let sent: Vec<Seen> = events.iter().map(seen_as).collect();
        for event in events {
            assert!(matches!(
                d.deliver(MuxEvent::Child(id, event)),
                Ok(Admit::Taken)
            ));
            d.run().unwrap();
        }
        let got: Vec<Seen> = seen.lock().unwrap().iter().map(seen_as).collect();
        assert_eq!(got, sent);
    }

    /// What an observed event says, without the charge its bytes carry.
    type Seen = (Direction, Vec<u8>, u64, Option<u64>, Option<Termination>);

    fn seen_as(event: &ObservedEvent) -> Seen {
        match event {
            ObservedEvent::Data {
                direction,
                bytes,
                sequence,
                ..
            } => (*direction, bytes.to_vec(), *sequence, None, None),
            ObservedEvent::Gap {
                direction,
                sequence,
                missing,
            } => (*direction, Vec::new(), *sequence, *missing, None),
            ObservedEvent::End { direction, cause } => {
                (*direction, Vec::new(), 0, None, Some(*cause))
            }
        }
    }

    #[test]
    fn an_observed_connection_has_one_key_for_both_orders() {
        let scope = Scope::tunnel();
        let forward = ObservedConnection {
            scope,
            first: addr("10.0.0.2:50000"),
            second: addr("10.0.0.1:443"),
            generation: 3,
            opened: None,
        };
        let reverse = ObservedConnection {
            first: forward.second,
            second: forward.first,
            ..forward
        };
        assert_eq!(forward.key(), reverse.key());
        assert_ne!(
            forward.key(),
            ObservedConnection {
                scope: Scope::ROOT,
                ..forward
            }
            .key()
        );
        assert_ne!(
            forward.key(),
            ObservedConnection {
                generation: 4,
                ..forward
            }
            .key()
        );
    }
}
