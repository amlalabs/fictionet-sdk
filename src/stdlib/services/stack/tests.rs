//! The runners over a simulated network: a TCP client and server, and UDP
//! sockets, on two machines joined by a link. The tests check what the
//! peers see and how a run ends, never fixed bytes.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};

use std::sync::Arc;

use super::live::READ;
use super::*;
use fictionet::stdlib::layer::framed_echo::{frames, read, stack, wire};
use fictionet::stdlib::layer::{Env, StreamCommand, StreamEvent};
use fictionet::stdlib::network::ConnError;
use fictionet::stdlib::network::{ConnectionExt, ip, tcp, udp};
use fictionet::time::Instant;
use fictionet::{Seed, block_on, lab, pair};

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 2);
const PORT: u16 = 7;

struct Machine {
    tcp: tcp::Endpoint,
    udp: udp::Endpoint,
}

/// The server's machine and the client's.
fn machines(fcx: &Cx) -> (Machine, Machine) {
    let (a, b) = pair();
    let machine = |side, addr: Ipv4Addr| {
        let (t, u, _icmp, _other) = ip::split_protocols(fcx, side);
        Machine {
            tcp: tcp::endpoint(fcx, t, IpAddr::V4(addr)),
            udp: udp::endpoint(fcx, u, IpAddr::V4(addr)),
        }
    };
    (machine(a, SERVER), machine(b, CLIENT))
}

fn server_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(SERVER), PORT)
}

/// Reads `conn` until the server ends its direction.
async fn read_to_end(fcx: &Cx, conn: &mut tcp::TcpConnection) -> Result<Vec<u8>, ConnError> {
    let mut got = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let n = conn.read(fcx, &mut buf).await?;
        if n == 0 {
            return Ok(got);
        }
        got.extend_from_slice(&buf[..n]);
    }
}

/// Accepts one connection and runs the stack `make` gives over it, while
/// `client` runs on the other machine. Returns how the server's run ended.
fn serve_one<L, F, Fut>(
    limits: StreamLimits,
    budget: Budget,
    make: impl FnOnce() -> L + Send + 'static,
    client: F,
) -> Result<StreamEnd, String>
where
    L: Layer<Lower = ByteStream, Upper = Top> + Send + 'static,
    L::Work: Job<Done = L::Done>,
    L::Report: Send,
    L::Error: core::fmt::Debug + Send,
    F: FnOnce(Cx, tcp::Endpoint) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    let ended = Arc::new(fictionet::sync::Mutex::new(None));
    let slot = ended.clone();
    block_on(lab(Seed::from_u64(1), move |fcx| async move {
        let (server, client_machine) = machines(&fcx);
        let mut listener = server.tcp.listen(PORT)?;
        let client = fcx.spawn(move |fcx| client(fcx, client_machine.tcp));
        let conn = listener.accept(&fcx).await?;
        let info = ConnInfo::new(1, conn.local_addr(), conn.peer_addr());
        let ended = stream(&fcx, conn, &info, make(), budget, limits, |_| {}).await;
        *slot.lock() = Some(ended.map_err(|e| format!("{e:?}")));
        client.join(&fcx).await?;
        // The machines run until the world stops.
        fcx.cancel();
        Ok(())
    }))
    .expect("the run finishes");
    let ended = ended.lock().take();
    ended.expect("the server ran")
}

#[test]
fn a_framed_stack_answers_over_tcp_and_finishes_when_the_client_ends() {
    let client = |fcx: Cx, tcp: tcp::Endpoint| async move {
        let mut conn = tcp.connect(&fcx, server_addr()).await?;
        let sent = frames(5);
        conn.write_all(&fcx, &wire(&sent)).await?;
        conn.shutdown(&fcx).await?;
        let got = read_to_end(&fcx, &mut conn).await?;
        assert_eq!(read(&got), sent, "every frame comes back, then the end");
        Ok(())
    };
    let ended = serve_one(StreamLimits::default(), Budget::unlimited(), stack, client);
    assert_eq!(ended, Ok(StreamEnd::Finished));
}

#[test]
fn an_idle_connection_has_its_input_ended_after_its_answers() {
    let limits = StreamLimits {
        idle: Some(Duration::from_millis(300)),
        ..StreamLimits::default()
    };
    let client = |fcx: Cx, tcp: tcp::Endpoint| async move {
        let mut conn = tcp.connect(&fcx, server_addr()).await?;
        let sent = frames(1);
        conn.write_all(&fcx, &wire(&sent)).await?;
        let got = read_to_end(&fcx, &mut conn).await?;
        assert_eq!(read(&got), sent, "the answer comes before the end");
        Ok(())
    };
    let ended = serve_one(limits, Budget::unlimited(), stack, client);
    assert_eq!(ended, Ok(StreamEnd::Idle));
}

/// Writes `left` bytes as soon as it runs, a chunk at a time.
struct Loud {
    left: usize,
}

impl Layer for Loud {
    type Lower = ByteStream;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn on_event(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        _event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn take_command(&mut self) -> Option<StreamCommand> {
        let n = self.left.min(64 * 1024);
        self.left -= n;
        (n > 0).then(|| StreamCommand::Write(Chunk::new(vec![b'x'; n])))
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

/// Takes the first bytes, then refuses input until its own timer goes off
/// `pause` later. Notes when it took the first bytes and when its input
/// ended, and ends its direction then.
struct Pauses {
    pause: Duration,
    until: Option<Instant>,
    seen: Arc<fictionet::sync::Mutex<(Option<Instant>, Option<Instant>)>>,
    end_sent: bool,
}

impl Layer for Pauses {
    type Lower = ByteStream;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Infallible>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        let mut seen = self.seen.lock();
        match event {
            StreamEvent::Data(_) if self.until.is_some() => return Ok(Admit::Blocked(event)),
            StreamEvent::Data(_) if seen.0.is_none() => {
                seen.0 = Some(env.now());
                self.until = Some(env.now() + self.pause);
            }
            StreamEvent::Ended => seen.1 = Some(env.now()),
            _ => {}
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn on_timer(&mut self, _env: &mut Env<'_, Infallible>, _timer: ()) -> Result<(), Infallible> {
        self.until = None;
        Ok(())
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        self.until.map(|at| (at, ()))
    }

    fn take_command(&mut self) -> Option<StreamCommand> {
        if self.seen.lock().1.is_some() && !self.end_sent {
            self.end_sent = true;
            return Some(StreamCommand::End);
        }
        None
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

/// The idle limit counts only time the runner spends waiting for the
/// client. While the stack refuses input the runner does not read, so the
/// client gets the whole idle time again once the stack takes it.
#[test]
fn the_idle_clock_restarts_when_the_stack_takes_input_again() {
    let idle = Duration::from_millis(300);
    let pause = Duration::from_millis(1_000);
    let limits = StreamLimits {
        idle: Some(idle),
        ..StreamLimits::default()
    };
    let seen = Arc::new(fictionet::sync::Mutex::new((None, None)));
    let kept = seen.clone();
    let pauses = move || Pauses {
        pause,
        until: None,
        seen: kept,
        end_sent: false,
    };
    let client = |fcx: Cx, tcp: tcp::Endpoint| async move {
        let mut conn = tcp.connect(&fcx, server_addr()).await?;
        conn.write_all(&fcx, b"a").await?;
        fcx.sleep_until(fcx.now() + Duration::from_millis(50))
            .await?;
        // The runner reads this, and the stack refuses it until its timer.
        conn.write_all(&fcx, b"b").await?;
        read_to_end(&fcx, &mut conn).await?;
        Ok(())
    };
    let ended = serve_one(limits, Budget::unlimited(), pauses, client);
    assert_eq!(ended, Ok(StreamEnd::Idle));
    let (first, over) = *seen.lock();
    let (first, over) = (first.expect("data came"), over.expect("input ended"));
    assert!(
        over.since_start() >= first.since_start() + pause + idle,
        "input ended {:?} after the stack took input again, before the idle limit",
        over.since_start()
            .saturating_sub(first.since_start() + pause)
    );
}

/// Bytes from the client start the idle time again, even when the stack
/// writes nothing back: a client that speaks just inside the limit keeps
/// its connection for a whole limit after it last spoke.
#[test]
fn the_idle_clock_restarts_when_the_client_speaks() {
    let idle = Duration::from_millis(300);
    let later = Duration::from_millis(250);
    let limits = StreamLimits {
        idle: Some(idle),
        ..StreamLimits::default()
    };
    let seen = Arc::new(fictionet::sync::Mutex::new((None, None)));
    let kept = seen.clone();
    // No pause: the stack takes every byte and writes none.
    let quiet = move || Pauses {
        pause: Duration::ZERO,
        until: None,
        seen: kept,
        end_sent: false,
    };
    let client = move |fcx: Cx, tcp: tcp::Endpoint| async move {
        let mut conn = tcp.connect(&fcx, server_addr()).await?;
        conn.write_all(&fcx, b"a").await?;
        fcx.sleep_until(fcx.now() + later).await?;
        conn.write_all(&fcx, b"b").await?;
        read_to_end(&fcx, &mut conn).await?;
        Ok(())
    };
    let ended = serve_one(limits, Budget::unlimited(), quiet, client);
    assert_eq!(ended, Ok(StreamEnd::Idle));
    let (first, over) = *seen.lock();
    let (first, over) = (first.expect("data came"), over.expect("input ended"));
    assert!(
        over.since_start() >= first.since_start() + later + idle,
        "input ended {:?} after the first bytes, within the idle limit of the last",
        over.since_start().saturating_sub(first.since_start())
    );
}

#[test]
fn a_client_that_stops_reading_times_out() {
    let limits = StreamLimits {
        idle: None,
        write_timeout: Some(Duration::from_millis(300)),
    };
    let loud = || Loud { left: 64 << 20 };
    let client = |fcx: Cx, tcp: tcp::Endpoint| async move {
        // Connects and never reads, holding the connection open until
        // well after the server's limit.
        let conn = tcp.connect(&fcx, server_addr()).await?;
        fcx.sleep_until(fcx.now() + Duration::from_secs(5)).await?;
        drop(conn);
        Ok(())
    };
    let ended = serve_one(limits, Budget::unlimited(), loud, client);
    assert_eq!(ended, Ok(StreamEnd::Conn(ConnError::TimedOut)));
}

#[test]
fn a_client_reset_ends_the_run() {
    let client = |fcx: Cx, tcp: tcp::Endpoint| async move {
        let mut conn = tcp.connect(&fcx, server_addr()).await?;
        // Part of a frame, then a reset.
        conn.write_all(&fcx, &wire(&frames(1))[..5]).await?;
        conn.reset();
        Ok(())
    };
    let ended = serve_one(StreamLimits::default(), Budget::unlimited(), stack, client);
    assert!(
        matches!(ended, Ok(StreamEnd::Conn(_))),
        "the run ends with the connection: {ended:?}"
    );
}

#[test]
fn a_budget_without_room_for_the_read_buffer_never_runs_the_stack() {
    let client = |fcx: Cx, tcp: tcp::Endpoint| async move {
        let mut conn = tcp.connect(&fcx, server_addr()).await?;
        conn.write_all(&fcx, &wire(&frames(1))).await?;
        // The server lets the connection go without an answer.
        let got = read_to_end(&fcx, &mut conn).await.unwrap_or_default();
        assert!(got.is_empty(), "nothing is answered");
        Ok(())
    };
    let ended = serve_one(
        StreamLimits::default(),
        Budget::new(READ - 1),
        stack,
        client,
    );
    assert_eq!(ended, Ok(StreamEnd::Budget));
}

/// Counts each sender's datagrams and answers each with the count so far:
/// what it keeps between datagrams is the conversation.
#[derive(Default)]
struct Counter {
    seen: BTreeMap<SocketAddr, u64>,
    reply: Option<Datagram<SocketAddr>>,
}

impl Layer for Counter {
    type Lower = Datagrams<SocketAddr>;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn on_event(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        event: DatagramEvent<SocketAddr>,
    ) -> Result<Admit<DatagramEvent<SocketAddr>>, Infallible> {
        match event {
            DatagramEvent::Datagram(d) if self.reply.is_some() => {
                Ok(Admit::Blocked(DatagramEvent::Datagram(d)))
            }
            DatagramEvent::Datagram(d) => {
                let from = *d.meta();
                let count = self.seen.entry(from).or_default();
                *count += 1;
                let payload = Chunk::new(count.to_be_bytes().to_vec());
                self.reply = Some(Datagram::new(payload, from));
                Ok(Admit::Taken)
            }
            DatagramEvent::Ended => Ok(Admit::Taken),
        }
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn take_command(&mut self) -> Option<DatagramCommand<SocketAddr>> {
        self.reply.take().map(DatagramCommand::Send)
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

/// Sends `payload` from `socket` and reads the count that comes back.
async fn ask(fcx: &Cx, socket: &mut udp::Socket, payload: &[u8]) -> fictionet::Result<u64> {
    socket.send_to(payload, server_addr());
    let (reply, from) = socket.recv(fcx).await?;
    assert_eq!(from, server_addr(), "the answer comes from the server");
    let count: [u8; 8] = reply.try_into().expect("a count is eight bytes");
    Ok(u64::from_be_bytes(count))
}

#[test]
fn datagrams_reach_one_conversation_and_answers_go_to_each_sender() {
    block_on(lab(Seed::from_u64(2), |fcx| async move {
        let (server, client) = machines(&fcx);
        let socket = server.udp.bind(PORT)?;
        fcx.spawn(move |fcx| async move {
            Ok(datagrams(
                &fcx,
                socket,
                server_addr(),
                Counter::default(),
                Budget::unlimited(),
                |_| {},
            )
            .await?)
        });
        let mut a = client.udp.bind(0)?;
        let mut b = client.udp.bind(0)?;
        assert_eq!(ask(&fcx, &mut a, b"one").await?, 1);
        assert_eq!(
            ask(&fcx, &mut a, b"").await?,
            2,
            "an empty datagram is a datagram"
        );
        assert_eq!(
            ask(&fcx, &mut b, b"one").await?,
            1,
            "each sender has its own count"
        );
        assert_eq!(
            ask(&fcx, &mut a, b"three").await?,
            3,
            "the conversation lasts"
        );
        fcx.cancel();
        Ok(())
    }))
    .expect("the run finishes");
}

/// A socket that is already closed, counting what is sent from it.
struct ClosedSocket {
    sent: Arc<fictionet::sync::Mutex<usize>>,
}

impl DatagramSocket for ClosedSocket {
    async fn recv(&mut self, _fcx: &Cx) -> Result<(Vec<u8>, SocketAddr), RecvError> {
        Err(RecvError::Closed)
    }

    fn send_to(&mut self, _data: &[u8], _to: SocketAddr) {
        *self.sent.lock() += 1;
    }
}

/// Once its socket closes, sends `left` goodbyes through one slot, one
/// per step of its own.
struct Goodbyes {
    left: usize,
    closing: bool,
    slot: Option<Datagram<SocketAddr>>,
}

impl Layer for Goodbyes {
    type Lower = Datagrams<SocketAddr>;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn on_event(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        event: DatagramEvent<SocketAddr>,
    ) -> Result<Admit<DatagramEvent<SocketAddr>>, Infallible> {
        if let DatagramEvent::Ended = event {
            self.closing = true;
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn advance(&mut self, _env: &mut Env<'_, Infallible>) -> Result<bool, Infallible> {
        if !self.closing || self.left == 0 || self.slot.is_some() {
            return Ok(false);
        }
        self.left -= 1;
        self.slot = Some(Datagram::new(Chunk::new(b"bye".to_vec()), server_addr()));
        Ok(true)
    }

    fn take_command(&mut self) -> Option<DatagramCommand<SocketAddr>> {
        self.slot.take().map(DatagramCommand::Send)
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

/// When the socket closes the stack sends what it still has, however many
/// rounds that takes the runner.
#[test]
fn a_closed_socket_gets_everything_the_stack_still_has() {
    let sent = Arc::new(fictionet::sync::Mutex::new(0));
    let count = sent.clone();
    block_on(lab(Seed::from_u64(3), move |fcx| async move {
        let socket = ClosedSocket { sent: count };
        let goodbyes = Goodbyes {
            left: 200,
            closing: false,
            slot: None,
        };
        datagrams(
            &fcx,
            socket,
            server_addr(),
            goodbyes,
            Budget::unlimited(),
            |_| {},
        )
        .await?;
        Ok(())
    }))
    .expect("the run finishes");
    assert_eq!(*sent.lock(), 200);
}

/// Ends its writes immediately, but receives the peer's response afterward.
struct HalfClosed {
    end: bool,
    received: Arc<fictionet::sync::Mutex<Vec<u8>>>,
}

impl Layer for HalfClosed {
    type Lower = ByteStream;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn on_event(
        &mut self,
        _: &mut Env<'_, Infallible>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        if let StreamEvent::Data(bytes) = event {
            self.received.lock().extend_from_slice(&bytes);
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

    fn take_command(&mut self) -> Option<StreamCommand> {
        std::mem::take(&mut self.end).then_some(StreamCommand::End)
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

#[test]
fn ending_writes_keeps_reading_the_peers_response() {
    let received = Arc::new(fictionet::sync::Mutex::new(Vec::new()));
    let output = received.clone();
    let response = frames(3);
    let expected = wire(&response);
    let sent = expected.clone();
    let client = move |fcx: Cx, tcp: tcp::Endpoint| async move {
        let mut conn = tcp.connect(&fcx, server_addr()).await?;
        assert!(read_to_end(&fcx, &mut conn).await?.is_empty());
        conn.write_all(&fcx, &sent).await?;
        conn.shutdown(&fcx).await?;
        Ok(())
    };
    let ended = serve_one(
        StreamLimits::default(),
        Budget::unlimited(),
        move || HalfClosed {
            end: true,
            received: output,
        },
        client,
    );
    assert_eq!(ended, Ok(StreamEnd::Finished));
    assert_eq!(*received.lock(), expected);
}

struct OneDatagram(Option<Vec<u8>>);

impl DatagramSocket for OneDatagram {
    async fn recv(&mut self, _: &Cx) -> Result<(Vec<u8>, SocketAddr), RecvError> {
        self.0
            .take()
            .map(|bytes| (bytes, server_addr()))
            .ok_or(RecvError::Closed)
    }

    fn send_to(&mut self, _: &[u8], _: SocketAddr) {}
}

#[test]
fn datagram_input_requires_its_backing_capacity_in_the_budget() {
    let mut bytes = Vec::with_capacity(256);
    bytes.push(1);
    let budget = Budget::new(bytes.capacity() - 1);
    let retained = budget.clone();
    block_on(lab(Seed::from_u64(4), move |fcx| async move {
        let result = datagrams(
            &fcx,
            OneDatagram(Some(bytes)),
            server_addr(),
            Counter::default(),
            budget,
            |_| {},
        )
        .await;
        assert!(matches!(result, Err(StackError::Budget)));
        Ok(())
    }))
    .expect("the run finishes");
    assert_eq!(retained.used(), 0);
}

struct BusyDatagram {
    work: bool,
    done: bool,
    end_sent: bool,
    visits: usize,
}

struct TwoPolls(bool);

impl Job for TwoPolls {
    type Done = ();

    fn poll(&mut self, _: Option<&Cx>, cx: &mut std::task::Context<'_>) -> Poll<()> {
        if std::mem::replace(&mut self.0, true) {
            Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

impl Layer for BusyDatagram {
    type Lower = Datagrams<SocketAddr>;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = TwoPolls;
    type Done = ();
    type Error = Infallible;

    fn on_event(
        &mut self,
        _: &mut Env<'_, Infallible>,
        _: DatagramEvent<SocketAddr>,
    ) -> Result<Admit<DatagramEvent<SocketAddr>>, Infallible> {
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn advance(&mut self, _: &mut Env<'_, Infallible>) -> Result<bool, Infallible> {
        self.visits += 1;
        assert!(
            self.visits < 512,
            "productive layers must allow pending work to run"
        );
        Ok(false)
    }

    fn take_work(&mut self) -> Option<TwoPolls> {
        std::mem::take(&mut self.work).then_some(TwoPolls(false))
    }

    fn on_done(&mut self, _: &mut Env<'_, Infallible>, _: ()) -> Result<(), Infallible> {
        self.done = true;
        Ok(())
    }

    fn take_command(&mut self) -> Option<DatagramCommand<SocketAddr>> {
        if self.end_sent {
            return None;
        }
        Some(if self.done {
            self.end_sent = true;
            DatagramCommand::End
        } else {
            DatagramCommand::Send(Datagram::new(Chunk::new(Vec::new()), server_addr()))
        })
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

#[test]
fn a_productive_datagram_layer_does_not_starve_its_pending_work() {
    block_on(lab(Seed::from_u64(5), move |fcx| async move {
        datagrams(
            &fcx,
            OneDatagram(None),
            server_addr(),
            BusyDatagram {
                work: true,
                done: false,
                end_sent: false,
                visits: 0,
            },
            Budget::unlimited(),
            |_| {},
        )
        .await?;
        Ok(())
    }))
    .expect("the work completes");
}

/// Carries one child over TCP, with a two-byte send window replenished
/// only by actual transport completions.
struct StreamChild {
    slots: fictionet::stdlib::layer::Slots<()>,
    child: fictionet::stdlib::layer::ChildId,
    opening: Option<fictionet::stdlib::layer::Child>,
    incoming: Option<StreamEvent>,
    outgoing: Option<StreamCommand>,
    receive_credit: u64,
    grant: u64,
    written: u64,
}

impl StreamChild {
    fn new() -> Self {
        let mut slots = fictionet::stdlib::layer::Slots::new(1);
        let handle = slots.insert(()).unwrap();
        Self {
            child: handle.id(),
            slots,
            opening: Some(handle),
            incoming: None,
            outgoing: None,
            receive_credit: 0,
            grant: 2,
            written: 0,
        }
    }
}

impl Layer for StreamChild {
    type Lower = ByteStream;
    type Upper = fictionet::stdlib::layer::Mux<ByteStream, Top, &'static str>;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn on_event(
        &mut self,
        _: &mut Env<'_, Infallible>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        if let StreamEvent::Written(n) = event {
            self.written += n;
            self.grant += n;
            return Ok(Admit::Taken);
        }
        if self.incoming.is_some() {
            return Ok(Admit::Blocked(event));
        }
        if let StreamEvent::Data(mut bytes) = event {
            if self.receive_credit == 0 {
                return Ok(Admit::Blocked(StreamEvent::Data(bytes)));
            }
            let n = bytes.len().min(self.receive_credit as usize);
            self.receive_credit -= n as u64;
            let prefix = bytes.split_to(n);
            self.incoming = Some(StreamEvent::Data(prefix));
            return Ok(if bytes.is_empty() {
                Admit::Taken
            } else {
                Admit::Partial(StreamEvent::Data(bytes))
            });
        }
        self.incoming = Some(event);
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _: &mut Env<'_, Infallible>,
        command: fictionet::stdlib::layer::MuxCommand<ByteStream, Top>,
    ) -> Result<Admit<fictionet::stdlib::layer::MuxCommand<ByteStream, Top>>, Infallible> {
        use fictionet::stdlib::layer::MuxOp;
        if matches!(command.op(), MuxOp::Child(..)) && self.outgoing.is_some() {
            return Ok(Admit::Blocked(command));
        }
        match command.into_op() {
            MuxOp::Child(child, command) => {
                assert!(self.slots.contains(child));
                self.outgoing = Some(command);
            }
            MuxOp::Credit(child, n) => {
                assert_eq!(child, self.child);
                self.receive_credit += n;
            }
            MuxOp::Close(child) => {
                self.slots.remove(child);
                self.outgoing = Some(StreamCommand::Reset);
            }
            MuxOp::Control(never) => match never {},
        }
        Ok(Admit::Taken)
    }

    fn take_command(&mut self) -> Option<StreamCommand> {
        self.outgoing.take()
    }

    fn take_event(
        &mut self,
    ) -> Option<fictionet::stdlib::layer::MuxEvent<ByteStream, Top, &'static str>> {
        use fictionet::stdlib::layer::MuxEvent;
        if let Some(child) = self.opening.take() {
            return Some(MuxEvent::Opened(child, "http", u64::MAX));
        }
        if let Some(completion) = self.take_urgent() {
            return Some(completion);
        }
        if self.grant > 0 {
            return Some(MuxEvent::Credit(
                self.child,
                std::mem::take(&mut self.grant),
            ));
        }
        self.incoming
            .take()
            .map(|event| MuxEvent::Child(self.child, event))
    }

    fn take_urgent(
        &mut self,
    ) -> Option<fictionet::stdlib::layer::MuxEvent<ByteStream, Top, &'static str>> {
        (self.written > 0).then(|| {
            fictionet::stdlib::layer::MuxEvent::Child(
                self.child,
                StreamEvent::Written(std::mem::take(&mut self.written)),
            )
        })
    }
}

#[test]
fn an_async_http_child_runs_over_the_live_stream_with_a_small_window() {
    use fictionet::stdlib::layer::{Chain, Children};
    use fictionet::stdlib::web::httpd::{self, Body, Exchange, Handler, Http1, Reply};
    struct Deferred;
    impl Handler for Deferred {
        fn call(&self, request: http::Request<Body>, _: &mut Exchange<'_>) -> Reply {
            let path = request.uri().path().to_owned();
            Reply::Later(Box::new(move |fcx| {
                Box::pin(async move {
                    fcx.yield_now().await?;
                    Ok(httpd::text(http::StatusCode::OK, &path))
                })
            }))
        }
    }
    let client = |fcx: Cx, tcp: tcp::Endpoint| async move {
        let mut conn = tcp.connect(&fcx, server_addr()).await?;
        conn.write_all(
            &fcx,
            b"GET /child-response HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        )
        .await?;
        conn.shutdown(&fcx).await?;
        let bytes = read_to_end(&fcx, &mut conn).await?;
        let response =
            fictionet::stdlib::protocols::http1::Response::parse_for(&bytes, "GET").unwrap();
        assert_eq!(response.head.status, 200);
        assert_eq!(response.body, b"/child-response");
        Ok(())
    };
    let result = serve_one(
        StreamLimits::default(),
        Budget::new(1024 * 1024),
        || {
            Chain::new(
                StreamChild::new(),
                Children::new(1, 65536, |_, context, _| {
                    assert_eq!(context, "http");
                    Http1::new(Deferred)
                }),
            )
        },
        client,
    );
    assert_eq!(result, Ok(StreamEnd::Finished));
}

type FrameWait = std::pin::Pin<Box<dyn Future<Output = Result<(), Cancelled>> + Send>>;

/// The handler returns before this body first uses its context.
struct LazyFrames {
    context: Cx,
    left: usize,
    waiting: Option<FrameWait>,
}

impl http_body::Body for LazyFrames {
    type Data = bytes::Bytes;
    type Error = Cancelled;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<bytes::Bytes>, Cancelled>>> {
        if self.left == 0 {
            return Poll::Ready(None);
        }
        if self.waiting.is_none() {
            let context = self.context.clone();
            self.waiting = Some(Box::pin(async move {
                context.sleep(Duration::from_millis(1)).await
            }));
        }
        match self.waiting.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.waiting = None;
                self.left -= 1;
                Poll::Ready(Some(
                    result.map(|()| http_body::Frame::data(bytes::Bytes::from_static(b"x"))),
                ))
            }
        }
    }
}

fn serve_lazy_frames(frames: usize) {
    use fictionet::stdlib::web::httpd::{Body, Exchange, Handler, Http1, Reply};
    struct Lazy(usize);
    impl Handler for Lazy {
        fn call(&self, _: http::Request<Body>, _: &mut Exchange<'_>) -> Reply {
            let left = self.0;
            Reply::Later(Box::new(move |context| {
                Box::pin(async move {
                    Ok(http::Response::new(Body::new(LazyFrames {
                        context,
                        left,
                        waiting: None,
                    })))
                })
            }))
        }
    }
    let client = move |fcx: Cx, tcp: tcp::Endpoint| async move {
        let mut conn = tcp.connect(&fcx, server_addr()).await?;
        conn.write_all(
            &fcx,
            b"GET /lazy HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        )
        .await?;
        let bytes = read_to_end(&fcx, &mut conn).await?;
        let response = fictionet::stdlib::protocols::http1::Response::parse_for(&bytes, "GET")
            .expect("the lazy body completes its HTTP framing");
        assert_eq!(response.head.status, 200);
        assert_eq!(response.body.len(), frames);
        Ok(())
    };
    let result = serve_one(
        StreamLimits::default(),
        Budget::new(1024 * 1024),
        move || Http1::new(Lazy(frames)),
        client,
    );
    assert_eq!(result, Ok(StreamEnd::Finished));
}

#[test]
fn a_returned_body_can_start_work_with_its_captured_context() {
    serve_lazy_frames(1);
}

#[test]
fn a_streaming_body_releases_completed_frame_jobs() {
    serve_lazy_frames(130);
}
