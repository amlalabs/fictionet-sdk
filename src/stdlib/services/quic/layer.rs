use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
use std::time::Instant as EngineInstant;
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use web_time::Instant as EngineInstant;

use bytes::BytesMut;
use quinn_proto::{Connection, ConnectionHandle, Dir, Endpoint, StreamId, VarInt};

use crate::stdlib::layer::{
    Admit, Budget, ByteStream, ChargedBytes, ChargedDeque, ChildId, Chunk, Closing, Datagram,
    DatagramCommand, DatagramEvent, Datagrams, Env, Layer, Mux, MuxCommand, MuxEvent, MuxOp, Port,
    Slots, StreamCommand, StreamEvent,
};
use crate::time::Instant;

/// One QUIC connection, with one byte carrier per stream and the connection's
/// `Datagrams<()>` carrier carried by `Control`.
pub type Quic = Mux<ByteStream<VarInt>, Control, Stream>;
type Up = MuxEvent<ByteStream<VarInt>, Control, Stream>;
type Command = MuxCommand<ByteStream<VarInt>, Control>;

/// Connection control, separate from independently credited streams.
pub enum Control {}

impl Port for Control {
    type Event = ControlEvent;
    type Command = ControlCommand;

    fn urgent(event: &ControlEvent) -> bool {
        matches!(event, ControlEvent::Datagram(event) if Datagrams::<()>::urgent(event))
    }
}

/// Commands that affect the connection.
pub enum ControlCommand {
    /// Open a locally initiated stream after handshake completion.
    Open(Dir),
    /// Open a required stream, or close with this application error if
    /// the peer's stream limit or the adapter's slots cannot admit it.
    /// Unlike `Open`, exhaustion does not hold the command path blocked.
    OpenOrClose {
        /// Direction of the required stream.
        direction: Dir,
        /// The application's error when that stream cannot be opened.
        error: VarInt,
    },
    /// Start graceful connection closure with an application error code.
    Close(VarInt),
    /// A command on the connection's application datagram carrier. `End`
    /// closes the connection using the caller's generic closure policy.
    Datagram(DatagramCommand<()>),
    /// Grant receive credit, in whole application datagrams, including empty ones.
    ReceiveDatagrams(u64),
}

/// Connection events.
#[derive(Debug)]
pub enum ControlEvent {
    /// The TLS handshake completed. Early application data is not exposed.
    Connected,
    /// The largest sendable application payload, or no datagram support.
    /// Announced after the handshake and whenever the active path changes it.
    DatagramSize(Option<usize>),
    /// An event on the connection's application datagram carrier. Send
    /// completions retire local attempts, including drops, not peer delivery.
    Datagram(DatagramEvent<()>),
    /// The connection was lost. Child handles will be retired.
    Lost(quinn_proto::ConnectionError),
    /// Connection closure and its draining period finished.
    Ended,
}

/// The wire identity and direction of a newly opened stream.
#[derive(Clone, Copy, Debug)]
pub struct Stream {
    /// QUIC stream identifier, including initiator and direction bits.
    pub id: StreamId,
    /// Whether this endpoint initiated the stream.
    pub local: bool,
}

/// Errors in constructing or driving the adapter.
#[derive(Debug)]
pub enum Error {
    /// Adapter storage could not be reserved.
    Budget,
    /// The caller's monotonic epoch cannot represent the supplied time.
    Time,
    /// Starting a client connection failed.
    Connect(quinn_proto::ConnectError),
    /// A command exceeded the credit issued to its stream.
    Credit,
    /// The lower carrier completed a send that was not outstanding.
    Completion,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QUIC layer: {self:?}")
    }
}
impl std::error::Error for Error {}

const WINDOW: usize = 16 * 1024;
// A single UDP payload, including an MTU probe, fits in this allocation.
const WIRE: usize = u16::MAX as usize;

struct Channel {
    stream: StreamId,
    receive: u64,
    granted: u64,
    owed: u64,
    written: u64,
    pending: ChargedDeque<Chunk>,
    readable: bool,
    receive_done: bool,
    send_done: bool,
    finish: bool,
    stopped: Option<VarInt>,
    turn: u8,
}

impl Channel {
    fn new(stream: StreamId, local: bool, budget: &Budget) -> Self {
        let send_done = stream.dir() == Dir::Uni && !local;
        Self {
            stream,
            receive: 0,
            granted: 0,
            owed: if send_done { 0 } else { WINDOW as u64 },
            written: 0,
            pending: ChargedDeque::new(budget, WINDOW),
            readable: !(stream.dir() == Dir::Uni && local),
            receive_done: stream.dir() == Dir::Uni && local,
            send_done,
            finish: false,
            stopped: None,
            turn: 0,
        }
    }
}

/// A sans-I/O QUIC connection over `Datagrams<SocketAddr>`.
///
/// A server accepts the first connection on its lower carrier and ignores
/// other Initials. Use [`Listener`] to serve many connections on one
/// datagram carrier. Address metadata is the remote socket;
/// this carrier has no ECN or local-destination metadata. MTU discovery is
/// disabled at endpoint creation because it cannot promise no fragmentation.
/// Crypto providers and calendar time belong to the supplied configuration;
/// use the world's TLS provider for deterministic simulation.
pub struct QuicLayer {
    endpoint: Option<Endpoint>,
    connection: Option<(ConnectionHandle, Connection)>,
    epoch: EngineInstant,
    channels: Slots<Channel>,
    cursor: Option<ChildId>,
    scan: usize,
    up: Option<Up>,
    notice: Option<ControlEvent>,
    down: Option<Datagram<SocketAddr>>,
    wire: Option<ChargedBytes>,
    flight: Flight,
    deadline: Option<Instant>,
    connected: bool,
    ending: bool,
    ended: bool,
    lower_ended: bool,
    cancel: fn(Closing) -> VarInt,
    accept_dir: Dir,
    datagram_send: DatagramSend,
    datagram_receive: u64,
    datagram_limit: Option<Option<usize>>,
    datagram_turn: bool,
    datagrams_ended: bool,
}

/// One application send, followed through packet construction and the
/// lower carrier's completion. A local drop has no packet to wait for.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
enum DatagramSend {
    #[default]
    Idle,
    Queued(bool),
    Flight(bool),
    Ready,
}

impl DatagramSend {
    fn retired(&mut self) {
        if let Self::Queued(tracked) | Self::Flight(tracked) = *self {
            *self = if tracked { Self::Ready } else { Self::Idle };
        }
    }

    fn packet(&mut self, pending: bool) {
        if !pending && let Self::Queued(tracked) = *self {
            *self = Self::Flight(tracked);
        }
    }

    fn completed(&mut self) {
        if matches!(self, Self::Flight(_)) {
            self.retired();
        }
    }

    fn take(&mut self) -> bool {
        if *self != Self::Ready {
            return false;
        }
        *self = Self::Idle;
        true
    }
}

/// One tracked send can be outside the layer at a time. Preparing a packet
/// is not its completion; receiving data cannot retire it either.
#[derive(Default)]
struct Flight(bool);

impl Flight {
    fn handoff(&mut self) -> bool {
        if self.0 {
            return false;
        }
        self.0 = true;
        true
    }

    fn complete(&mut self, count: u64) -> Result<(), Error> {
        if count > u64::from(self.0) {
            return Err(Error::Completion);
        }
        if count == 1 {
            self.0 = false;
        }
        Ok(())
    }
}

#[cfg(kani)]
#[path = "../../../../verification/quic/kani/layer.rs"]
mod proofs;

impl QuicLayer {
    /// Build a server or an initially unconnected client. Reserve adapter
    /// slots before drawing entropy or constructing the endpoint. `epoch`
    /// corresponds to the run's zero, not the time of this call. `cancel`
    /// supplies the application's error code for generic child closure;
    /// QUIC defines no universal mapping for these causes.
    pub fn new(
        env: &mut Env<'_, ()>,
        config: Arc<quinn_proto::EndpointConfig>,
        server: Option<Arc<quinn_proto::ServerConfig>>,
        epoch: EngineInstant,
        streams: usize,
        cancel: fn(Closing) -> VarInt,
    ) -> Result<Self, Error> {
        let channels = Slots::with_budget(streams, env.budget()).ok_or(Error::Budget)?;
        let mut seed = [0; 32];
        env.entropy().fill_random(&mut seed);
        let mut endpoint = Endpoint::new(config, server, false, Some(seed));
        endpoint.set_datagram_receive_budget(env.budget());
        Ok(Self::with_channels(Some(endpoint), epoch, channels, cancel))
    }

    fn with_channels(
        endpoint: Option<Endpoint>,
        epoch: EngineInstant,
        channels: Slots<Channel>,
        cancel: fn(Closing) -> VarInt,
    ) -> Self {
        Self {
            endpoint,
            connection: None,
            epoch,
            channels,
            cursor: None,
            scan: 0,
            up: None,
            notice: None,
            down: None,
            wire: None,
            flight: Flight::default(),
            deadline: None,
            connected: false,
            ending: false,
            ended: false,
            lower_ended: false,
            cancel,
            accept_dir: Dir::Bi,
            datagram_send: DatagramSend::Idle,
            datagram_receive: 0,
            datagram_limit: None,
            datagram_turn: true,
            datagrams_ended: false,
        }
    }

    /// Start this layer's client connection. Configuration must disable
    /// early data if its crypto session would otherwise send it.
    pub fn connect(
        &mut self,
        env: &mut Env<'_, ()>,
        config: quinn_proto::ClientConfig,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<(), Error> {
        assert!(self.connection.is_none() && !self.ending);
        let now = self.now(env)?;
        self.connection = Some(
            self.endpoint
                .as_mut()
                .expect("standalone endpoint")
                .connect(now, config, remote, server_name)
                .map_err(Error::Connect)?,
        );
        self.update_deadline();
        Ok(())
    }

    fn now(&self, env: &Env<'_, ()>) -> Result<EngineInstant, Error> {
        self.epoch
            .checked_add(env.now().since_start())
            .ok_or(Error::Time)
    }

    fn wire(&mut self, budget: &Budget) -> Option<ChargedBytes> {
        let mut bytes = self
            .wire
            .take()
            .or_else(|| ChargedBytes::with_capacity(budget, WIRE))?;
        bytes.clear();
        Some(bytes)
    }

    fn update_deadline(&mut self) {
        self.deadline = self.connection.as_mut().and_then(|(_, connection)| {
            connection
                .poll_timeout()
                .map(|at| Instant::from_since_start(at.saturating_duration_since(self.epoch)))
        });
    }

    fn channel_id(&self, stream: StreamId) -> Option<ChildId> {
        self.channels
            .ids()
            .find(|id| self.channels.get(*id).unwrap().stream == stream)
    }

    fn opened(&mut self, stream: StreamId, local: bool, budget: &Budget) {
        let mut channel = Channel::new(stream, local, budget);
        if !channel.send_done {
            let connection = &mut self.connection.as_mut().unwrap().1;
            if let Ok(Some(code)) = connection.send_stream(stream).stopped() {
                channel.stopped = Some(code);
                channel.send_done = true;
                channel.owed = 0;
                let _ = connection.send_stream(stream).reset(code);
            }
        }
        let child = self
            .channels
            .insert(channel)
            .unwrap_or_else(|_| unreachable!("slot admitted before opening"));
        self.up = Some(MuxEvent::Opened(
            child,
            Stream { id: stream, local },
            WINDOW as u64,
        ));
        self.scan = self.channels.len();
    }

    fn stop(&mut self, id: ChildId, code: VarInt) {
        let Some(channel) = self.channels.get_mut(id) else {
            return;
        };
        if let Some((_, connection)) = self.connection.as_mut() {
            if channel.stream.dir() == Dir::Bi || channel.stream.initiator() == connection.side() {
                let _ = connection.send_stream(channel.stream).reset(code);
            }
            if !channel.receive_done {
                let _ = connection.recv_stream(channel.stream).stop(code);
            }
        }
        channel.pending.clear();
        channel.send_done = true;
        channel.receive_done = true;
        channel.owed = 0;
        channel.granted = 0;
    }

    fn step_channel(&mut self, id: ChildId, budget: &Budget) -> bool {
        let Some((_, connection)) = self.connection.as_mut() else {
            return false;
        };
        let channel = self.channels.get_mut(id).unwrap();
        for offset in 0..3 {
            let turn = (channel.turn + offset) % 3;
            let moved = match turn {
                0 => Self::write_channel(connection, channel, budget),
                1 => Self::read_channel(connection, channel, budget, id, &mut self.up),
                _ => {
                    if self.up.is_none()
                        && channel.owed > 0
                        && !channel.finish
                        && !channel.send_done
                    {
                        let units = std::mem::take(&mut channel.owed);
                        channel.granted += units;
                        self.up = Some(MuxEvent::Credit(id, units));
                        true
                    } else {
                        false
                    }
                }
            };
            if moved {
                channel.turn = (turn + 1) % 3;
                return true;
            }
        }
        if channel.receive_done
            && channel.send_done
            && channel.written == 0
            && channel.stopped.is_none()
            && self.up.is_none()
        {
            self.channels.remove(id);
            self.up = Some(MuxEvent::Closed(id));
            return true;
        }
        false
    }

    fn read_datagram(&mut self, budget: &Budget) -> bool {
        if self.up.is_some() || self.datagram_receive == 0 {
            return false;
        }
        let connection = &mut self.connection.as_mut().unwrap().1;
        let Some(chunk) = connection.datagrams().recv_chunk(budget) else {
            return false;
        };
        self.datagram_receive -= 1;
        self.up = Some(MuxEvent::Control(ControlEvent::Datagram(
            DatagramEvent::Datagram(Datagram::new(chunk, ())),
        )));
        self.datagram_turn = false;
        true
    }

    fn write_channel(connection: &mut Connection, channel: &mut Channel, budget: &Budget) -> bool {
        if let Some(front) = channel.pending.front_mut() {
            match connection
                .send_stream(channel.stream)
                .write_chunk(front, budget)
            {
                Ok(written) => {
                    channel.written += written.bytes as u64;
                    channel.owed += written.bytes as u64;
                    if front.is_empty() {
                        channel.pending.pop_front();
                    }
                    return written.bytes != 0;
                }
                Err(quinn_proto::WriteError::Stopped(code)) => {
                    let _ = connection.send_stream(channel.stream).reset(code);
                    channel.stopped = Some(code);
                    channel.pending.clear();
                    channel.send_done = true;
                    channel.owed = 0;
                    return true;
                }
                Err(quinn_proto::WriteError::ClosedStream) => {
                    channel.pending.clear();
                    channel.send_done = true;
                    channel.owed = 0;
                    return true;
                }
                Err(quinn_proto::WriteError::Blocked | quinn_proto::WriteError::Budget) => {}
            }
        }
        if channel.finish && channel.pending.is_empty() && !channel.send_done {
            let _ = connection.send_stream(channel.stream).finish();
            channel.send_done = true;
            channel.owed = 0;
            return true;
        }
        false
    }

    fn read_channel(
        connection: &mut Connection,
        channel: &mut Channel,
        budget: &Budget,
        id: ChildId,
        up: &mut Option<Up>,
    ) -> bool {
        if up.is_some() {
            return false;
        }
        if channel.readable && !channel.receive_done {
            let length = channel.receive.min(WINDOW as u64) as usize;
            // Reserve before removing any bytes from the engine. A zero
            // length read observes FIN/reset without consuming stream data.
            let Some(mut bytes) = (if length == 0 {
                Some(Chunk::default())
            } else {
                Chunk::block(budget, 0, length)
            }) else {
                return false;
            };
            let mut receiver = connection.recv_stream(channel.stream);
            let Ok(mut chunks) = receiver.read(true) else {
                channel.readable = false;
                return false;
            };
            let result = chunks.next(length);
            let _ = chunks.finalize();
            match result {
                Ok(Some(chunk)) if !chunk.bytes.is_empty() => {
                    bytes.extend_within(&chunk.bytes).unwrap();
                    channel.receive -= chunk.bytes.len() as u64;
                    *up = Some(MuxEvent::Child(id, StreamEvent::Data(bytes)));
                    return true;
                }
                Ok(None) => {
                    channel.receive_done = true;
                    *up = Some(MuxEvent::Child(id, StreamEvent::Ended));
                    return true;
                }
                Err(quinn_proto::ReadError::Reset(code)) => {
                    channel.receive_done = true;
                    *up = Some(MuxEvent::Child(id, StreamEvent::ReceiveReset(code)));
                    return true;
                }
                Err(quinn_proto::ReadError::Blocked) => {
                    channel.readable = false;
                }
                Ok(Some(_)) => {}
            }
        }
        false
    }
}

impl Layer for QuicLayer {
    type Lower = Datagrams<SocketAddr>;
    type Upper = Quic;
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
                self.flight.complete(count)?;
                if count == 1 {
                    self.datagram_send.completed();
                }
            }
            DatagramEvent::Ended => {
                self.lower_ended = true;
                self.ending = true;
                self.down = None;
                self.flight = Flight::default();
                self.deadline = None;
                self.datagram_send = DatagramSend::Idle;
                if let Some((_, connection)) = self.connection.as_mut() {
                    connection.datagrams().discard_chunk();
                }
            }
            DatagramEvent::Datagram(datagram) => {
                if self.lower_ended {
                    return Ok(Admit::Closed(DatagramEvent::Datagram(datagram)));
                }
                if datagram.payload().len() as u64
                    > self
                        .endpoint
                        .as_ref()
                        .expect("standalone endpoint")
                        .config()
                        .get_max_udp_payload_size()
                {
                    return Ok(Admit::Taken);
                }
                if self.down.is_some() {
                    return Ok(Admit::Blocked(DatagramEvent::Datagram(datagram)));
                }
                let Some(mut response) = self.wire(env.budget()) else {
                    return Ok(Admit::Blocked(DatagramEvent::Datagram(datagram)));
                };
                let now = self.now(env)?;
                let event = response
                    .fill(|buf| {
                        Ok::<_, ()>(self.endpoint.as_mut().expect("standalone endpoint").handle(
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
                        if let Some((ours, connection)) = self.connection.as_mut()
                            && *ours == handle
                        {
                            connection.handle_event(event);
                        }
                        None
                    }
                    Some(quinn_proto::DatagramEvent::NewConnection(incoming)) => {
                        if self.connection.is_some() || self.ending {
                            self.endpoint
                                .as_mut()
                                .expect("standalone endpoint")
                                .ignore(incoming);
                            None
                        } else {
                            match response
                                .fill(|buf| {
                                    Ok::<_, ()>(
                                        self.endpoint
                                            .as_mut()
                                            .expect("standalone endpoint")
                                            .accept(incoming, now, buf, None),
                                    )
                                })
                                .expect("accept response fits a UDP payload")
                            {
                                Ok(connection) => {
                                    self.connection = Some(connection);
                                    None
                                }
                                Err(error) => error.response,
                            }
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
                self.update_deadline();
            }
        }
        self.scan = self.channels.len();
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, ()>,
        command: Command,
    ) -> Result<Admit<Command>, Error> {
        if self.ending {
            return Ok(Admit::Closed(command));
        }
        let now = self.now(env)?;
        let Some((_, connection)) = self.connection.as_mut() else {
            return Ok(Admit::Blocked(command));
        };
        let refused = |op| Admit::Blocked(MuxCommand::from_op(op));
        let closed = |op| Admit::Closed(MuxCommand::from_op(op));
        match command.into_op() {
            MuxOp::Control(ControlCommand::ReceiveDatagrams(credit)) => {
                self.datagram_receive = self
                    .datagram_receive
                    .checked_add(credit)
                    .ok_or(Error::Credit)?;
            }
            MuxOp::Control(ControlCommand::Datagram(DatagramCommand::Send(datagram))) => {
                if !self.connected || self.datagram_send != DatagramSend::Idle {
                    return Ok(refused(MuxOp::Control(ControlCommand::Datagram(
                        DatagramCommand::Send(datagram),
                    ))));
                }
                let tracked = datagram.wants_completion();
                let (mut data, ()) = datagram.into_parts();
                let result = connection.datagrams().send_chunk(&mut data, env.budget());
                let restore = |data| {
                    let datagram = Datagram::new(data, ());
                    MuxOp::Control(ControlCommand::Datagram(DatagramCommand::Send(
                        if tracked {
                            datagram.with_completion()
                        } else {
                            datagram
                        },
                    )))
                };
                match result {
                    Ok(true) => self.datagram_send = DatagramSend::Queued(tracked),
                    Ok(false) => return Ok(refused(restore(data))),
                    Err(quinn_proto::SendDatagramError::TooLarge) => {
                        if tracked {
                            self.datagram_send = DatagramSend::Ready;
                        }
                    }
                    Err(_) => return Ok(closed(restore(data))),
                }
            }
            MuxOp::Control(ControlCommand::Datagram(DatagramCommand::End)) => {
                connection.close(now, (self.cancel)(Closing::Done), bytes::Bytes::new());
                self.ending = true;
                self.datagram_send = DatagramSend::Idle;
            }
            MuxOp::Control(
                command @ (ControlCommand::Open(_) | ControlCommand::OpenOrClose { .. }),
            ) => {
                let (direction, error) = match command {
                    ControlCommand::Open(direction) => (direction, None),
                    ControlCommand::OpenOrClose { direction, error } => (direction, Some(error)),
                    _ => unreachable!(),
                };
                if !self.connected || self.up.is_some() {
                    return Ok(refused(MuxOp::Control(command)));
                }
                let stream = (self.channels.len() < self.channels.limit())
                    .then(|| connection.streams().open(direction))
                    .flatten();
                if let Some(stream) = stream {
                    self.opened(stream, true, env.budget());
                } else if let Some(code) = error {
                    connection.close(now, code, bytes::Bytes::new());
                    self.ending = true;
                    self.datagram_send = DatagramSend::Idle;
                } else {
                    return Ok(refused(MuxOp::Control(command)));
                }
            }
            MuxOp::Control(ControlCommand::Close(code)) => {
                connection.close(now, code, bytes::Bytes::new());
                self.ending = true;
                self.datagram_send = DatagramSend::Idle;
            }
            MuxOp::Credit(id, credit) | MuxOp::Window(id, credit, _) => {
                if let Some(channel) = self.channels.get_mut(id) {
                    channel.receive = channel.receive.checked_add(credit).ok_or(Error::Credit)?;
                }
            }
            MuxOp::Close(id, why) => {
                if self.up.is_some() {
                    return Ok(refused(MuxOp::Close(id, why)));
                }
                self.stop(id, (self.cancel)(why));
                if self.channels.remove(id).is_some() {
                    self.up = Some(MuxEvent::Closed(id));
                }
            }
            MuxOp::Child(id, command) => {
                let Some(channel) = self.channels.get_mut(id) else {
                    return Ok(closed(MuxOp::Child(id, command)));
                };
                match command {
                    StreamCommand::Write(mut bytes) => {
                        if channel.send_done || channel.finish {
                            return Ok(closed(MuxOp::Child(id, StreamCommand::Write(bytes))));
                        }
                        if bytes.len() as u64 > channel.granted {
                            return Err(Error::Credit);
                        }
                        if bytes.is_empty() {
                            return Ok(Admit::Taken);
                        }
                        let places = channel.pending.places();
                        if !channel.pending.reserve(1) {
                            return Ok(refused(MuxOp::Child(id, StreamCommand::Write(bytes))));
                        }
                        if !bytes.is_paid_by(env.budget()) && !bytes.repay(env.budget()) {
                            channel.pending.shrink_to(places);
                            return Ok(refused(MuxOp::Child(id, StreamCommand::Write(bytes))));
                        }
                        channel.granted -= bytes.len() as u64;
                        channel.pending.push_back(bytes).unwrap();
                    }
                    StreamCommand::End => {
                        channel.finish = true;
                    }
                    StreamCommand::ResetSend(code) => {
                        if channel.stream.dir() == Dir::Bi
                            || channel.stream.initiator() == connection.side()
                        {
                            let _ = connection.send_stream(channel.stream).reset(code);
                        }
                        channel.pending.clear();
                        channel.send_done = true;
                        channel.owed = 0;
                    }
                    StreamCommand::StopReceive(code) => {
                        if !channel.receive_done {
                            let _ = connection.recv_stream(channel.stream).stop(code);
                        }
                        channel.receive_done = true;
                    }
                    StreamCommand::Reset => {
                        if self.up.is_some() {
                            return Ok(refused(MuxOp::Child(id, StreamCommand::Reset)));
                        }
                        self.stop(id, (self.cancel)(Closing::Failed));
                        self.channels.remove(id);
                        self.up = Some(MuxEvent::Closed(id));
                    }
                }
            }
        }
        self.update_deadline();
        self.scan = self.channels.len();
        Ok(Admit::Taken)
    }

    fn advance(&mut self, env: &mut Env<'_, ()>) -> Result<bool, Error> {
        self.now(env)?;
        let mut moved = false;
        if let Some((handle, connection)) = self.connection.as_mut() {
            if let Some(endpoint) = self.endpoint.as_mut()
                && let Some(event) = connection.poll_endpoint_events()
            {
                if let Some(event) = endpoint.handle_event(*handle, event) {
                    connection.handle_event(event);
                }
                moved = true;
            }
            if self.notice.is_none()
                && let Some(event) = connection.poll()
            {
                match event {
                    quinn_proto::Event::Connected => {
                        self.connected = true;
                        self.notice = Some(ControlEvent::Connected);
                    }
                    quinn_proto::Event::ConnectionLost { reason } => {
                        self.ending = true;
                        self.datagram_send = DatagramSend::Idle;
                        self.notice = Some(ControlEvent::Lost(reason));
                    }
                    quinn_proto::Event::Stream(event) => match event {
                        quinn_proto::StreamEvent::Readable { id } => {
                            if let Some(id) = self.channel_id(id) {
                                self.channels.get_mut(id).unwrap().readable = true;
                            }
                        }
                        quinn_proto::StreamEvent::Stopped { id, error_code } => {
                            if let Some(id) = self.channel_id(id) {
                                let channel = self.channels.get_mut(id).unwrap();
                                let _ = self
                                    .connection
                                    .as_mut()
                                    .unwrap()
                                    .1
                                    .send_stream(channel.stream)
                                    .reset(error_code);
                                channel.stopped = Some(error_code);
                                channel.pending.clear();
                                channel.send_done = true;
                                channel.owed = 0;
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
                moved = true;
            }
        }
        if self.up.is_none() && self.notice.is_some() {
            self.up = self.notice.take().map(MuxEvent::Control);
            moved = true;
        }
        if self.up.is_none() && self.ending {
            let first = self.channels.ids().next();
            if let Some(id) = first {
                self.stop(id, (self.cancel)(Closing::Done));
                self.channels.remove(id);
                self.up = Some(MuxEvent::Closed(id));
                moved = true;
            } else if !self.datagrams_ended {
                self.datagrams_ended = true;
                self.up = Some(MuxEvent::Control(ControlEvent::Datagram(
                    DatagramEvent::Ended,
                )));
                moved = true;
            } else if !self.ended
                && (self.lower_ended
                    || self.connection.as_ref().is_none_or(|(_, c)| c.is_drained()))
            {
                self.ended = true;
                self.up = Some(MuxEvent::Control(ControlEvent::Ended));
                moved = true;
            }
        }
        if self.connected && !self.ending {
            let connection = &mut self.connection.as_mut().unwrap().1;
            if matches!(self.datagram_send, DatagramSend::Queued(_))
                && !connection.datagrams().has_pending_chunk()
            {
                self.datagram_send.retired();
                moved = true;
            }
            let limit = connection.datagrams().max_size();
            if self.up.is_none() && self.datagram_limit != Some(limit) {
                self.datagram_limit = Some(limit);
                self.up = Some(MuxEvent::Control(ControlEvent::DatagramSize(limit)));
                moved = true;
            }
            if self.datagram_turn {
                moved |= self.read_datagram(env.budget());
            }
            if self.up.is_none() && self.channels.len() < self.channels.limit() {
                let connection = &mut self.connection.as_mut().unwrap().1;
                let other = match self.accept_dir {
                    Dir::Bi => Dir::Uni,
                    Dir::Uni => Dir::Bi,
                };
                let stream = connection
                    .streams()
                    .accept(self.accept_dir)
                    .or_else(|| connection.streams().accept(other));
                if let Some(stream) = stream {
                    self.accept_dir = match stream.dir() {
                        Dir::Bi => Dir::Uni,
                        Dir::Uni => Dir::Bi,
                    };
                    self.opened(stream, false, env.budget());
                    moved = true;
                }
            }
            let next = self
                .channels
                .ids()
                .find(|id| self.cursor.is_none_or(|cursor| *id > cursor))
                .or_else(|| self.channels.ids().next());
            if let Some(id) = next {
                self.cursor = Some(id);
                if self.step_channel(id, env.budget()) {
                    if matches!(self.up, Some(MuxEvent::Child(..) | MuxEvent::Credit(..))) {
                        self.datagram_turn = true;
                    }
                    self.scan = self.channels.len();
                    moved = true;
                } else {
                    self.scan = self.scan.saturating_sub(1);
                    moved |= self.scan > 0;
                }
            }
            moved |= self.read_datagram(env.budget());
        }
        if !self.lower_ended {
            self.update_deadline();
        }
        Ok(moved)
    }

    fn take_command(&mut self, env: &mut Env<'_, ()>) -> Option<DatagramCommand<SocketAddr>> {
        if self.flight.0 || self.lower_ended {
            return None;
        }
        if self.ended && self.up.is_none() && self.notice.is_none() {
            self.lower_ended = true;
            return Some(DatagramCommand::End);
        }
        if self.down.is_none() {
            self.connection.as_ref()?;
            let now = self.now(env).ok()?;
            let mut bytes = self.wire(env.budget())?;
            let (_, connection) = self.connection.as_mut()?;
            let transmit = bytes
                .fill(|buf| Ok::<_, ()>(connection.poll_transmit(now, 1, buf)))
                .expect("one engine datagram fits a UDP payload");
            self.update_deadline();
            let Some(transmit) = transmit else {
                self.wire = Some(bytes);
                return None;
            };
            self.datagram_send.packet(
                self.connection
                    .as_mut()
                    .unwrap()
                    .1
                    .datagrams()
                    .has_pending_chunk(),
            );
            self.down =
                Some(Datagram::new(bytes.into_chunk(), transmit.destination).with_completion());
        }
        assert!(self.flight.handoff());
        self.down.take().map(DatagramCommand::Send)
    }

    fn take_event(&mut self) -> Option<Up> {
        let event = if matches!(self.up, Some(MuxEvent::Opened(..))) {
            self.up.take()
        } else {
            self.take_urgent().or_else(|| self.up.take())
        };
        if event.is_some() {
            self.scan = self.channels.len();
        }
        event
    }

    fn take_urgent(&mut self) -> Option<Up> {
        if self.datagram_send.take() {
            return Some(MuxEvent::Control(ControlEvent::Datagram(
                DatagramEvent::Sent(1),
            )));
        }
        let id = self.channels.ids().find(|id| {
            if matches!(&self.up, Some(MuxEvent::Opened(child, ..)) if child.id() == *id) {
                return false;
            }
            let channel = self.channels.get(*id).unwrap();
            channel.written != 0 || channel.stopped.is_some()
        });
        if let Some(id) = id {
            let channel = self.channels.get_mut(id).unwrap();
            if channel.written != 0 {
                return Some(MuxEvent::Child(
                    id,
                    StreamEvent::Written(std::mem::take(&mut channel.written)),
                ));
            }
            if let Some(code) = channel.stopped.take() {
                return Some(MuxEvent::Child(id, StreamEvent::SendStopped(code)));
            }
        }
        None
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        self.deadline.map(|at| (at, ()))
    }

    fn on_timer(&mut self, env: &mut Env<'_, ()>, _: ()) -> Result<bool, Error> {
        if !self.deadline.is_some_and(|at| at <= env.now()) || self.lower_ended {
            return Ok(false);
        }
        let now = self.now(env)?;
        if let Some((_, connection)) = self.connection.as_mut() {
            connection.handle_timeout(now);
        }
        self.update_deadline();
        Ok(true)
    }

    fn is_terminal(&self) -> bool {
        self.ended && self.lower_ended && self.up.is_none() && self.down.is_none() && !self.flight.0
    }
}

#[path = "listener.rs"]
mod listener;
pub use listener::{Connections, Listener, ListenerConfig};
