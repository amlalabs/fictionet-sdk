use super::*;
use crate::stdlib::layer::{Child, CommandOf, Credited, EventOf, Top};
use crate::stdlib::network::{ConnInfo, Transport};

/// Connections accepted on one datagram carrier. Each child is a complete
/// QUIC mux, suitable for `Children` with an HTTP/3 application per connection.
pub type Connections = Mux<Quic, Top, ConnInfo>;
type ListenerEvent = EventOf<Connections>;
type ListenerCommand = CommandOf<Connections>;

/// Limits and configuration shared by connections on a listener.
#[derive(Clone)]
pub struct ListenerConfig {
    /// Packet protection, connection identifiers and wire admission.
    pub endpoint: Arc<quinn_proto::EndpointConfig>,
    /// TLS and transport settings for new connections.
    pub server: Arc<quinn_proto::ServerConfig>,
    /// Maximum live connections, including handshakes and draining connections.
    pub connections: usize,
    /// Adapter stream slots per connection.
    pub streams: usize,
    /// Application error policy for generic child closure.
    pub cancel: fn(Closing) -> VarInt,
}

struct Session {
    layer: QuicLayer,
    announced: bool,
    opening: Option<Child>,
    closing: bool,
    routing: bool,
}

/// One tracked UDP send, either from the endpoint or from a connection.
/// Keeping the owner until completion also prevents recycling its slot early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transmission<T> {
    Idle,
    Endpoint,
    Connection(T),
}

impl<T: Copy> Transmission<T> {
    fn complete(&mut self, count: u64) -> Result<Option<T>, Error> {
        if count == 0 {
            return Ok(None);
        }
        if count != 1 || matches!(self, Self::Idle) {
            return Err(Error::Completion);
        }
        Ok(match std::mem::replace(self, Self::Idle) {
            Self::Connection(id) => Some(id),
            _ => None,
        })
    }
}

/// A QUIC server listener over one `Datagrams<SocketAddr>` carrier.
///
/// Compose with `Children` to serve a fresh application on each connection,
/// and attach that stack with `Host::udp_stack` or the datagram socket runner.
/// Construction allocates no connection storage; the first step reserves it
/// through `Env`. `epoch` corresponds to the world's monotonic zero. `local`
/// supplies socket metadata that the datagram carrier itself does not carry.
///
/// The endpoint routes by connection ID, including rotated identifiers and
/// peer address changes. Connections remain counted through draining. A full
/// listener ignores new Initials while continuing existing connections. No
/// early data is exposed. Metadata is captured after the TLS handshake.
/// Adapter slots are charged; endpoint routing and engine metadata still need
/// whole-engine budgeting. This carrier has no ECN or local destination data.
///
/// HTTP/3 uses the same handler factory on every accepted connection:
///
/// ```
/// use fictionet::stdlib::{
///     layer::{Chain, Children},
///     network::ConnInfo,
///     services::quic::{Listener, ListenerConfig},
///     web::httpd::Responder,
/// };
/// # fn build(config: ListenerConfig, epoch: std::time::Instant,
/// #          local: Option<std::net::SocketAddr>, responder: Responder) {
/// let applications = Children::new(config.connections, 0, move |_, info: ConnInfo, _| {
///     Some(responder.clone().conn(info).http3())
/// });
/// let stack = Chain::new(Listener::new(config, epoch, local), applications);
/// # let _ = stack;
/// # }
/// ```
///
/// Build this stack in a `Host::udp_stack` factory, passing its socket's
/// `ConnInfo::local`. Configure the TLS server to negotiate `h3`.
pub struct Listener {
    config: ListenerConfig,
    epoch: EngineInstant,
    local: Option<SocketAddr>,
    endpoint: Option<Endpoint>,
    sessions: Slots<Session>,
    initialized: bool,
    up: Option<ListenerEvent>,
    down: Option<Datagram<SocketAddr>>,
    wire: Option<ChargedBytes>,
    flight: Transmission<ChildId>,
    send_cursor: Option<ChildId>,
    event_cursor: Option<ChildId>,
    ended: bool,
}

impl Listener {
    /// Make a listener for the supplied server configuration and socket.
    pub fn new(config: ListenerConfig, epoch: EngineInstant, local: Option<SocketAddr>) -> Self {
        Self {
            sessions: Slots::new(config.connections),
            config,
            epoch,
            local,
            endpoint: None,
            initialized: false,
            up: None,
            down: None,
            wire: None,
            flight: Transmission::Idle,
            send_cursor: None,
            event_cursor: None,
            ended: false,
        }
    }

    fn init(&mut self, env: &mut Env<'_, ()>) -> bool {
        if self.initialized {
            return true;
        }
        let Some(sessions) = Slots::with_budget(self.config.connections, env.budget()) else {
            return false;
        };
        let mut seed = [0; 32];
        env.entropy().fill_random(&mut seed);
        let mut endpoint = Endpoint::new(
            self.config.endpoint.clone(),
            Some(self.config.server.clone()),
            false,
            Some(seed),
        );
        endpoint.set_datagram_receive_budget(env.budget());
        self.sessions = sessions;
        self.endpoint = Some(endpoint);
        self.initialized = true;
        true
    }

    fn now(&self, env: &Env<'_, ()>) -> Result<EngineInstant, Error> {
        self.epoch
            .checked_add(env.now().since_start())
            .ok_or(Error::Time)
    }

    fn routed(&self, handle: ConnectionHandle) -> Option<ChildId> {
        self.sessions.ids().find(|id| {
            let session = self.sessions.get(*id).unwrap();
            session.routing && session.layer.connection.as_ref().unwrap().0 == handle
        })
    }

    fn after(&self, cursor: Option<ChildId>) -> Option<ChildId> {
        self.sessions
            .ids()
            .find(|id| cursor.is_none_or(|cursor| *id > cursor))
    }

    fn next(&self, cursor: Option<ChildId>) -> Option<ChildId> {
        self.sessions
            .ids()
            .find(|id| cursor.is_none_or(|cursor| *id > cursor))
            .or_else(|| self.sessions.ids().next())
    }

    fn retire(&mut self, id: ChildId) {
        let session = self.sessions.remove(id).unwrap();
        if session.announced {
            self.up = Some(MuxEvent::Closed(id));
        }
    }
}

impl Layer for Listener {
    type Lower = Datagrams<SocketAddr>;
    type Upper = Connections;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Error;

    fn on_event(
        &mut self,
        env: &mut Env<'_, ()>,
        event: DatagramEvent<SocketAddr>,
    ) -> Result<Admit<DatagramEvent<SocketAddr>>, Error> {
        match event {
            DatagramEvent::Sent(count) => {
                if let Some(id) = self.flight.complete(count)? {
                    let session = self.sessions.get_mut(id).expect("send owner retained");
                    let _ = session.layer.on_event(env, DatagramEvent::Sent(1))?;
                }
            }
            DatagramEvent::Ended => {
                self.ended = true;
                self.down = None;
                self.wire = None;
                self.flight = Transmission::Idle;
                self.endpoint = None;
            }
            DatagramEvent::Datagram(datagram) => {
                if self.ended {
                    return Ok(Admit::Closed(DatagramEvent::Datagram(datagram)));
                }
                if datagram.payload().len() as u64 > self.config.endpoint.get_max_udp_payload_size()
                {
                    return Ok(Admit::Taken);
                }
                if self.down.is_some() || !self.init(env) {
                    return Ok(Admit::Blocked(DatagramEvent::Datagram(datagram)));
                }
                let Some(mut response) = self
                    .wire
                    .take()
                    .or_else(|| ChargedBytes::with_capacity(env.budget(), WIRE))
                else {
                    return Ok(Admit::Blocked(DatagramEvent::Datagram(datagram)));
                };
                response.clear();
                let now = self.now(env)?;
                let event = response
                    .fill(|buf| {
                        Ok::<_, ()>(self.endpoint.as_mut().unwrap().handle(
                            now,
                            *datagram.meta(),
                            None,
                            None,
                            BytesMut::from(datagram.payload()),
                            buf,
                        ))
                    })
                    .expect("endpoint response fits a UDP payload");
                let transmit = match event {
                    Some(quinn_proto::DatagramEvent::ConnectionEvent(handle, event)) => {
                        if let Some(id) = self.routed(handle) {
                            let layer = &mut self.sessions.get_mut(id).unwrap().layer;
                            layer.connection.as_mut().unwrap().1.handle_event(event);
                            layer.update_deadline();
                            layer.scan = layer.channels.len();
                        }
                        None
                    }
                    Some(quinn_proto::DatagramEvent::NewConnection(incoming)) => {
                        let channels = (self.sessions.len() < self.sessions.limit())
                            .then(|| Slots::with_budget(self.config.streams, env.budget()))
                            .flatten();
                        if let Some(channels) = channels {
                            match response
                                .fill(|buf| {
                                    Ok::<_, ()>(
                                        self.endpoint
                                            .as_mut()
                                            .unwrap()
                                            .accept(incoming, now, buf, None),
                                    )
                                })
                                .expect("accept response fits a UDP payload")
                            {
                                Ok(connection) => {
                                    let mut layer = QuicLayer::with_channels(
                                        None,
                                        self.epoch,
                                        channels,
                                        self.config.cancel,
                                    );
                                    layer.connection = Some(connection);
                                    layer.update_deadline();
                                    let child = self
                                        .sessions
                                        .insert(Session {
                                            layer,
                                            announced: false,
                                            opening: None,
                                            closing: false,
                                            routing: true,
                                        })
                                        .unwrap_or_else(|_| {
                                            unreachable!("connection slot admitted")
                                        });
                                    let id = child.id();
                                    self.sessions.get_mut(id).unwrap().opening = Some(child);
                                    None
                                }
                                Err(error) => error.response,
                            }
                        } else {
                            self.endpoint.as_mut().unwrap().ignore(incoming);
                            None
                        }
                    }
                    Some(quinn_proto::DatagramEvent::Response(transmit)) => Some(transmit),
                    None => None,
                };
                if let Some(transmit) = transmit {
                    self.down = Some(
                        Datagram::new(response.into_chunk(), transmit.destination)
                            .with_completion(),
                    );
                } else {
                    self.wire = Some(response);
                }
            }
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, ()>,
        command: ListenerCommand,
    ) -> Result<Admit<ListenerCommand>, Error> {
        if self.ended {
            return Ok(Admit::Closed(command));
        }
        match command.into_op() {
            MuxOp::Control(never) => match never {},
            MuxOp::Credit(..) | MuxOp::Window(..) => {}
            MuxOp::Child(id, command) => {
                let Some(session) = self.sessions.get_mut(id) else {
                    return Ok(Admit::Taken);
                };
                return Ok(match session.layer.on_command(env, command)? {
                    Admit::Taken => Admit::Taken,
                    Admit::Blocked(command) => {
                        Admit::Blocked(MuxCommand::from_op(MuxOp::Child(id, command)))
                    }
                    Admit::Closed(command) => {
                        Admit::Closed(MuxCommand::from_op(MuxOp::Child(id, command)))
                    }
                    Admit::Partial(_) => unreachable!("QUIC commands are atomic"),
                });
            }
            MuxOp::Close(id, why) => {
                if let Some(session) = self.sessions.get_mut(id) {
                    session.closing = true;
                    let _ = session.layer.on_command(
                        env,
                        MuxCommand::control(ControlCommand::Close((self.config.cancel)(why))),
                    )?;
                }
            }
        }
        Ok(Admit::Taken)
    }

    fn advance(&mut self, env: &mut Env<'_, ()>) -> Result<bool, Error> {
        if self.ended {
            if self.up.is_none()
                && let Some(id) = self.after(None)
            {
                self.retire(id);
                return Ok(true);
            }
            return Ok(false);
        }
        if !self.init(env) {
            return Ok(false);
        }
        let mut moved = false;
        // Service every engine even while one application holds its event.
        // Slots bound this scan; no per-packet work queue is allocated.
        let mut cursor = None;
        while let Some(id) = self.after(cursor) {
            cursor = Some(id);
            let session = self.sessions.get_mut(id).unwrap();
            let (handle, connection) = session.layer.connection.as_mut().unwrap();
            if session.routing
                && let Some(event) = connection.poll_endpoint_events()
            {
                if event.is_drained() {
                    session.routing = false;
                }
                if let Some(event) = self.endpoint.as_mut().unwrap().handle_event(*handle, event) {
                    connection.handle_event(event);
                }
                moved = true;
            }
            moved |= session.layer.advance(env)?;
            if session.closing || (!session.announced && session.layer.ending) {
                moved |= session.layer.take_event().is_some();
            }
        }
        if self.up.is_none() {
            for _ in 0..self.sessions.len() {
                let id = self.next(self.event_cursor).unwrap();
                self.event_cursor = Some(id);
                let session = self.sessions.get_mut(id).unwrap();
                if !session.routing && session.layer.is_terminal() {
                    self.retire(id);
                    return Ok(true);
                }
                if !session.announced && session.layer.connected && !session.layer.ending {
                    let connection = &session.layer.connection.as_ref().unwrap().1;
                    let handshake = connection
                        .crypto_session()
                        .handshake_data()
                        .and_then(|data| {
                            data.downcast::<quinn_proto::crypto::rustls::HandshakeData>()
                                .ok()
                        });
                    let info = ConnInfo {
                        local: self.local,
                        peer: Some(connection.remote_address()),
                        transport: Transport::Udp,
                        tls: true,
                        alpn: handshake
                            .as_ref()
                            .and_then(|h| h.protocol.as_deref())
                            .map(Arc::from),
                        sni: handshake
                            .as_ref()
                            .and_then(|h| h.server_name.as_deref())
                            .map(Arc::from),
                        ..ConnInfo::default()
                    };
                    session.announced = true;
                    self.up = Some(MuxEvent::Opened(
                        session.opening.take().expect("unannounced connection"),
                        info,
                        0,
                    ));
                    return Ok(true);
                }
                if session.announced
                    && !session.closing
                    && let Some(event) = session.layer.take_event()
                {
                    self.up = Some(MuxEvent::Child(id, event));
                    return Ok(true);
                }
            }
        }
        Ok(moved)
    }

    fn take_command(&mut self, env: &mut Env<'_, ()>) -> Option<DatagramCommand<SocketAddr>> {
        if self.ended || !matches!(self.flight, Transmission::Idle) {
            return None;
        }
        if let Some(datagram) = self.down.take() {
            self.flight = Transmission::Endpoint;
            return Some(DatagramCommand::Send(datagram));
        }
        for _ in 0..self.sessions.len() {
            let id = self.next(self.send_cursor)?;
            self.send_cursor = Some(id);
            match self.sessions.get_mut(id).unwrap().layer.take_command(env) {
                Some(DatagramCommand::Send(datagram)) => {
                    self.flight = Transmission::Connection(id);
                    return Some(DatagramCommand::Send(datagram));
                }
                Some(DatagramCommand::End) | None => {}
            }
        }
        None
    }

    fn take_event(&mut self) -> Option<ListenerEvent> {
        self.up.take()
    }

    fn take_urgent(&mut self) -> Option<ListenerEvent> {
        if self.ended {
            return None;
        }
        for _ in 0..self.sessions.len() {
            let id = self.next(self.event_cursor)?;
            self.event_cursor = Some(id);
            let session = self.sessions.get_mut(id).unwrap();
            if session.announced
                && !session.closing
                && !matches!(&self.up, Some(MuxEvent::Opened(child, ..)) if child.id() == id)
                && let Some(event) = session.layer.take_urgent()
            {
                return Some(MuxEvent::Child(id, event));
            }
        }
        None
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        if self.ended {
            return None;
        }
        self.sessions
            .ids()
            .filter_map(|id| self.sessions.get(id).unwrap().layer.deadline())
            .min()
    }

    fn on_timer(&mut self, env: &mut Env<'_, ()>, _: ()) -> Result<bool, Error> {
        if self.ended {
            return Ok(false);
        }
        let mut moved = false;
        let mut cursor = None;
        while let Some(id) = self.after(cursor) {
            cursor = Some(id);
            moved |= self.sessions.get_mut(id).unwrap().layer.on_timer(env, ())?;
        }
        Ok(moved)
    }

    fn is_terminal(&self) -> bool {
        self.ended && self.sessions.is_empty() && self.up.is_none()
    }
}

// Nested QUIC traffic already has independent stream and datagram credit.
// The connection envelope consumes no additional credit. Children still
// bounds its event descriptors, and payload admission repays owned storage.
impl Credited for Up {
    fn credit(&self) -> u64 {
        0
    }
    fn reserve(&mut self, budget: &Budget) -> bool {
        match self {
            MuxEvent::Child(_, event) => event.reserve(budget),
            MuxEvent::Control(ControlEvent::Datagram(event)) => event.reserve(budget),
            _ => true,
        }
    }
}
impl Credited for Command {
    fn credit(&self) -> u64 {
        0
    }
    fn reserve(&mut self, budget: &Budget) -> bool {
        match self.op_mut() {
            MuxOp::Child(_, command) => command.reserve(budget),
            MuxOp::Control(ControlCommand::Datagram(command)) => command.reserve(budget),
            _ => true,
        }
    }
}

#[cfg(kani)]
#[path = "../../../../verification/quic/kani/listener.rs"]
mod proofs;

#[cfg(test)]
#[path = "listener_tests.rs"]
mod tests;
