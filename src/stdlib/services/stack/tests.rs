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

/// A TCP connection hands what it received over as the chunks it came up
/// in, and sends pieces of a chunk the caller gives it: the stream runner
/// moves bytes both ways without copying them.
#[test]
fn tcp_hands_received_chunks_over_and_sends_pieces_of_chunks() {
    use fictionet::stdlib::network::Read;
    let request = vec![7u8; 3000];
    let reply = vec![9u8; 3000];
    let (sent, expected) = (request.clone(), reply.clone());
    block_on(lab(Seed::from_u64(1), move |fcx| async move {
        let (server, client_machine) = machines(&fcx);
        let mut listener = server.tcp.listen(PORT)?;
        let client = fcx.spawn(move |fcx| async move {
            let mut conn = client_machine.tcp.connect(&fcx, server_addr()).await?;
            conn.write_all(&fcx, &sent).await?;
            conn.shutdown(&fcx).await?;
            assert_eq!(read_to_end(&fcx, &mut conn).await?, expected);
            Ok(())
        });
        let mut conn = listener.accept(&fcx).await?;
        let budget = Budget::new(request.len());
        let mut got = Vec::new();
        let mut buf = vec![0u8; 1024];
        loop {
            match poll_fn(|cx| conn.poll_read_owned(&fcx, cx, &mut buf)).await? {
                Read::Copied(0) => break,
                Read::Copied(n) => panic!("{n} bytes were copied out of the chunks"),
                Read::Owned(mut chunk) => {
                    assert!(!chunk.is_empty() && chunk.len() <= buf.len());
                    assert!(chunk.recharge(&budget));
                    got.extend_from_slice(&chunk);
                }
            }
        }
        assert_eq!(got, request);
        assert_eq!(budget.used(), 0, "every handed chunk was released");
        let mut reply = Chunk::new(reply);
        while !reply.is_empty() {
            let n = poll_fn(|cx| conn.poll_write_chunk(&fcx, cx, &reply)).await?;
            reply.advance(n);
        }
        conn.shutdown(&fcx).await?;
        client.join(&fcx).await?;
        fcx.cancel();
        Ok(())
    }))
    .expect("the run finishes");
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

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
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

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
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

    fn take_command(
        &mut self,
        _: &mut Env<'_, Self::Report>,
    ) -> Option<DatagramCommand<SocketAddr>> {
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

    fn take_command(
        &mut self,
        _: &mut Env<'_, Self::Report>,
    ) -> Option<DatagramCommand<SocketAddr>> {
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

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        std::mem::take(&mut self.end).then_some(StreamCommand::End)
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

/// Input the stack refuses as closed is over, as it is for an application
/// on a transport child (`session::tests::input_refused_as_closed_is_over`):
/// a stack that also ended its direction finishes without waiting for the
/// idle limit.
#[test]
fn input_refused_as_closed_is_over() {
    let limits = StreamLimits {
        idle: Some(Duration::from_secs(30)),
        ..StreamLimits::default()
    };
    let client = |fcx: Cx, tcp: tcp::Endpoint| async move {
        let mut conn = tcp.connect(&fcx, server_addr()).await?;
        conn.write_all(&fcx, b"x").await?;
        read_to_end(&fcx, &mut conn).await?;
        let waited = fcx.now().since_start();
        assert!(waited < Duration::from_secs(30), "ended after {waited:?}");
        Ok(())
    };
    let ended = serve_one(
        limits,
        Budget::unlimited(),
        super::session::tests::Closes::default,
        client,
    );
    assert_eq!(ended, Ok(StreamEnd::Finished));
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
fn an_oversized_datagram_is_dropped_without_ending_the_conversation() {
    struct DatagramsIn {
        incoming: std::collections::VecDeque<(Vec<u8>, SocketAddr)>,
        sent: Arc<fictionet::sync::Mutex<Vec<(u64, SocketAddr)>>>,
    }
    impl DatagramSocket for DatagramsIn {
        async fn recv(&mut self, _: &Cx) -> Result<(Vec<u8>, SocketAddr), RecvError> {
            self.incoming.pop_front().ok_or(RecvError::Closed)
        }
        fn send_to(&mut self, data: &[u8], to: SocketAddr) {
            self.sent
                .lock()
                .push((u64::from_be_bytes(data.try_into().unwrap()), to));
        }
    }
    for limit in [255, 256] {
        let mut bytes = Vec::with_capacity(256);
        bytes.push(1);
        let budget = Budget::new(limit);
        let retained = budget.clone();
        let sent = Arc::new(fictionet::sync::Mutex::new(Vec::new()));
        let replies = sent.clone();
        let first = server_addr();
        let second = SocketAddr::new(CLIENT.into(), PORT + 1);
        block_on(lab(Seed::from_u64(4), move |fcx| async move {
            let socket = DatagramsIn {
                incoming: [
                    (vec![1], first),
                    (bytes, first),
                    (Vec::new(), first),
                    (vec![2], second),
                ]
                .into(),
                sent,
            };
            let mut reports = Vec::new();
            let result = datagrams(
                &fcx,
                socket,
                server_addr(),
                Counter::default(),
                budget,
                |report| reports.push(report),
            )
            .await;
            assert_eq!(
                reports,
                [DatagramReport::Dropped {
                    from: first,
                    bytes: 1
                }]
            );
            assert!(result.is_ok());
            Ok(())
        }))
        .expect("the run finishes");
        assert_eq!(*replies.lock(), [(1, first), (2, first), (1, second)]);
        assert_eq!(retained.used(), 0);
    }
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

    fn take_command(
        &mut self,
        _: &mut Env<'_, Self::Report>,
    ) -> Option<DatagramCommand<SocketAddr>> {
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

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
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
                    Some(Http1::new(Deferred))
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

struct Extraction<P: fictionet::stdlib::layer::Port> {
    command: Option<fictionet::stdlib::layer::CommandOf<P>>,
    extracted: Arc<std::sync::atomic::AtomicUsize>,
}

impl<P: fictionet::stdlib::layer::Port> Layer for Extraction<P> {
    type Lower = P;
    type Upper = Top;
    type Report = ();
    type Timer = Infallible;
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn report_bytes(_: &()) -> Option<usize> {
        Some(0)
    }

    fn on_event(
        &mut self,
        _: &mut Env<'_, ()>,
        _: fictionet::stdlib::layer::EventOf<P>,
    ) -> Result<Admit<fictionet::stdlib::layer::EventOf<P>>, Infallible> {
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _: &mut Env<'_, ()>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn take_command(
        &mut self,
        env: &mut Env<'_, ()>,
    ) -> Option<fictionet::stdlib::layer::CommandOf<P>> {
        self.extracted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        env.report(());
        self.command.take()
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

struct ExtractionConnection {
    fail: bool,
}

impl Connection for ExtractionConnection {
    fn poll_read(
        &mut self,
        _: &Cx,
        _: &mut std::task::Context<'_>,
        _: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        Poll::Pending
    }

    fn poll_write(
        &mut self,
        _: &Cx,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        Poll::Ready(if self.fail {
            Err(ConnError::Broken)
        } else {
            Ok(bytes.len())
        })
    }

    fn poll_shutdown(
        &mut self,
        _: &Cx,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), ConnError>> {
        Poll::Ready(if self.fail {
            Err(ConnError::Broken)
        } else {
            Ok(())
        })
    }
}

fn check_stream_extraction(command: Option<StreamCommand>, fail: bool) {
    block_on(lab(Seed::from_u64(81), move |fcx| async move {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let reset = matches!(command, Some(StreamCommand::Reset));
        let end = matches!(command, Some(StreamCommand::End));
        let extracted = Arc::new(AtomicUsize::new(0));
        let layer = Extraction::<ByteStream> {
            command,
            extracted: extracted.clone(),
        };
        let mut live = live::Live::new(
            &fcx,
            ExtractionConnection { fail },
            layer,
            Budget::unlimited(),
            StreamLimits::default(),
        );
        let mut reports = 0;
        let result = live.poll(
            &fcx,
            &mut std::task::Context::from_waker(std::task::Waker::noop()),
            &mut |event| match event {},
            &mut |_| reports += 1,
        );
        assert!(extracted.load(Ordering::Relaxed) > 0);
        assert_eq!(
            reports,
            extracted.load(Ordering::Relaxed),
            "every extraction report reaches the observer before polling returns"
        );
        if fail {
            assert!(matches!(
                result,
                Poll::Ready(Ok(live::Halt::Conn(ConnError::Broken)))
            ));
        } else if reset {
            assert!(matches!(
                result,
                Poll::Ready(Ok(live::Halt::End(StreamEnd::Reset)))
            ));
        } else {
            assert!(result.is_pending());
            assert_eq!(live.shut(), end);
        }
        Ok(())
    }))
    .unwrap();
}

#[test]
fn stream_extraction_reports_before_waiting() {
    check_stream_extraction(None, false);
}

#[test]
fn stream_extraction_reports_before_ending() {
    check_stream_extraction(Some(StreamCommand::End), false);
}

#[test]
fn stream_extraction_reports_before_reset() {
    check_stream_extraction(Some(StreamCommand::Reset), false);
}

#[test]
fn stream_extraction_reports_before_write_failure() {
    check_stream_extraction(Some(StreamCommand::Write(Chunk::new(vec![1]))), true);
}

#[test]
fn stream_extraction_reports_before_shutdown_failure() {
    check_stream_extraction(Some(StreamCommand::End), true);
}

struct WaitingDatagrams;

impl DatagramSocket for WaitingDatagrams {
    async fn recv(&mut self, _: &Cx) -> Result<(Vec<u8>, SocketAddr), RecvError> {
        std::future::pending().await
    }

    fn send_to(&mut self, _: &[u8], _: SocketAddr) {}
}

fn check_datagram_extraction(command: Option<DatagramCommand<SocketAddr>>) {
    block_on(lab(Seed::from_u64(82), move |fcx| async move {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let end = command.is_some();
        let extracted = Arc::new(AtomicUsize::new(0));
        let reported = Arc::new(AtomicUsize::new(0));
        let observed = reported.clone();
        let layer = Extraction::<Datagrams<SocketAddr>> {
            command,
            extracted: extracted.clone(),
        };
        let mut report = move |event| {
            assert!(matches!(event, DatagramReport::Layer(())));
            observed.fetch_add(1, Ordering::Relaxed);
        };
        let mut running = pin!(run_datagrams(
            &fcx,
            WaitingDatagrams,
            layer,
            Budget::unlimited(),
            &mut report
        ));
        poll_fn(|cx| {
            let result = running.as_mut().poll(cx);
            assert!(extracted.load(Ordering::Relaxed) > 0);
            assert_eq!(
                reported.load(Ordering::Relaxed),
                extracted.load(Ordering::Relaxed),
                "every extraction report reaches the observer before polling returns"
            );
            if end {
                assert!(matches!(result, Poll::Ready(Ok(()))));
            } else {
                assert!(result.is_pending());
            }
            Poll::Ready(())
        })
        .await;
        Ok(())
    }))
    .unwrap();
}

#[test]
fn datagram_extraction_reports_before_waiting() {
    check_datagram_extraction(None);
}

#[test]
fn datagram_extraction_reports_before_ending() {
    check_datagram_extraction(Some(DatagramCommand::End));
}

/// A request to stop that another task makes, outside the layer's calls:
/// it wakes the layer through the waker the layer kept.
#[derive(Default)]
struct Stop {
    asked: std::sync::atomic::AtomicBool,
    waker: Mutex<Option<std::task::Waker>>,
}

impl Stop {
    fn ask(&self) {
        self.asked.store(true, Ordering::Release);
        if let Some(waker) = self.waker.lock().clone() {
            waker.wake();
        }
    }

    /// Keeps the layer's waker the first time, then reads the request.
    fn asked(&self, env: &Env<'_, Infallible>) -> bool {
        self.waker.lock().get_or_insert_with(|| env.waker());
        self.asked.load(Ordering::Acquire)
    }
}

/// Reads nothing and says nothing until it is asked to stop, then ends
/// its direction.
struct StopsWhenAsked<P> {
    stop: Arc<Stop>,
    stopping: bool,
    ended: bool,
    port: std::marker::PhantomData<fn() -> P>,
}

impl<P> StopsWhenAsked<P> {
    fn new(stop: Arc<Stop>) -> Self {
        StopsWhenAsked {
            stop,
            stopping: false,
            ended: false,
            port: std::marker::PhantomData,
        }
    }
}

/// The end of a direction, on each port the runners carry.
trait Ends: fictionet::stdlib::layer::Port {
    fn end() -> Self::Command;
}

impl Ends for ByteStream {
    fn end() -> StreamCommand {
        StreamCommand::End
    }
}

impl Ends for Datagrams<SocketAddr> {
    fn end() -> DatagramCommand<SocketAddr> {
        DatagramCommand::End
    }
}

impl<P: Ends> Layer for StopsWhenAsked<P> {
    type Lower = P;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn is_terminal(&self) -> bool {
        self.ended
    }

    fn advance(&mut self, env: &mut Env<'_, Infallible>) -> Result<bool, Infallible> {
        let asked = self.stop.asked(env);
        let moved = asked && !self.stopping;
        self.stopping |= asked;
        Ok(moved)
    }

    fn on_event(
        &mut self,
        _: &mut Env<'_, Infallible>,
        _: P::Event,
    ) -> Result<Admit<P::Event>, Infallible> {
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn take_command(&mut self, _: &mut Env<'_, Infallible>) -> Option<P::Command> {
        (self.stopping && !self.ended).then(|| {
            self.ended = true;
            P::end()
        })
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

/// A stream stack that waits for nothing the runner can see, neither
/// input nor a timer, ends when another task wakes it.
#[test]
fn a_stream_stack_woken_from_another_task_runs_and_ends() {
    let stop = Arc::new(Stop::default());
    let asks = stop.clone();
    let client = move |fcx: Cx, tcp: tcp::Endpoint| async move {
        let mut conn = tcp.connect(&fcx, server_addr()).await?;
        fcx.sleep(Duration::from_secs(1)).await?;
        asks.ask();
        assert!(read_to_end(&fcx, &mut conn).await?.is_empty());
        Ok(())
    };
    let ended = serve_one(
        StreamLimits::default(),
        Budget::unlimited(),
        move || StopsWhenAsked::<ByteStream>::new(stop),
        client,
    );
    assert_eq!(ended, Ok(StreamEnd::Finished));
}

/// The same for a datagram stack whose socket brings nothing.
#[test]
fn a_datagram_stack_woken_from_another_task_runs_and_ends() {
    block_on(lab(Seed::from_u64(4), |fcx| async move {
        let (server, _client) = machines(&fcx);
        let socket = server.udp.bind(PORT)?;
        let stop = Arc::new(Stop::default());
        let layer = StopsWhenAsked::<Datagrams<SocketAddr>>::new(stop.clone());
        let run = fcx.spawn(move |fcx| async move {
            Ok(datagrams(
                &fcx,
                socket,
                server_addr(),
                layer,
                Budget::unlimited(),
                |_| {},
            )
            .await?)
        });
        fcx.sleep(Duration::from_secs(1)).await?;
        stop.ask();
        run.join(&fcx).await?;
        fcx.cancel();
        Ok(())
    }))
    .expect("the run finishes");
}

mod flush {
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Waker};

    use std::time::Duration;

    use fictionet::stdlib::layer::{
        Admit, Budget, ByteStream, Chunk, Env, Layer, StreamCommand, StreamEvent, Top,
    };
    use fictionet::stdlib::network::{ConnError, ConnInfo, Connection};
    use fictionet::{Cx, Seed, block_on, lab};

    use super::super::{Opened, StreamEnd, StreamLimits, stream};

    /// Passes writes down and everything from below up, as they are.
    #[derive(Default)]
    struct Pass {
        down: VecDeque<StreamCommand>,
        up: VecDeque<StreamEvent>,
    }

    impl Layer for Pass {
        type Lower = ByteStream;
        type Upper = ByteStream;
        type Report = Infallible;
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = ConnError;

        fn on_event(
            &mut self,
            _: &mut Env<'_, Infallible>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, ConnError> {
            self.up.push_back(event);
            Ok(Admit::Taken)
        }

        fn on_command(
            &mut self,
            _: &mut Env<'_, Infallible>,
            command: StreamCommand,
        ) -> Result<Admit<StreamCommand>, ConnError> {
            self.down.push_back(command);
            Ok(Admit::Taken)
        }

        fn take_command(&mut self, _: &mut Env<'_, Infallible>) -> Option<StreamCommand> {
            self.down.pop_front()
        }

        fn take_event(&mut self) -> Option<StreamEvent> {
            self.up.pop_front()
        }
    }

    /// Takes every write at once, and flushes only once `flushed` is set.
    struct Held {
        taken: Vec<u8>,
        flushed: Arc<AtomicBool>,
    }

    impl Connection for Held {
        fn poll_read(
            &mut self,
            _: &Cx,
            _: &mut Context<'_>,
            _: &mut [u8],
        ) -> Poll<Result<usize, ConnError>> {
            Poll::Pending
        }

        fn poll_write(
            &mut self,
            _: &Cx,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<Result<usize, ConnError>> {
            self.taken.extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(&mut self, _: &Cx, _: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
            if self.flushed.load(Ordering::Relaxed) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn poll_shutdown(&mut self, _: &Cx, _: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A stack's bytes count as written only once the connection under it
    /// flushed them, so a flush above waits for the flush below, and the
    /// next write waits with it.
    #[test]
    fn a_flush_waits_for_the_connection_underneath_to_flush() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let flushed = Arc::new(AtomicBool::new(false));
            let conn = Held {
                taken: Vec::new(),
                flushed: flushed.clone(),
            };
            let mut opened = Opened::new(&fcx, conn, Pass::default(), Budget::unlimited());
            let mut cx = Context::from_waker(Waker::noop());
            assert_eq!(
                opened.poll_write(&fcx, &mut cx, b"first"),
                Poll::Ready(Ok(5))
            );
            assert!(opened.poll_flush(&fcx, &mut cx).is_pending());
            assert_eq!(opened.conn().taken, b"first");
            assert!(opened.poll_write(&fcx, &mut cx, b"second").is_pending());
            flushed.store(true, Ordering::Relaxed);
            assert_eq!(opened.poll_flush(&fcx, &mut cx), Poll::Ready(Ok(())));
            assert_eq!(
                opened.poll_write(&fcx, &mut cx, b"second"),
                Poll::Ready(Ok(6))
            );
            assert_eq!(opened.poll_flush(&fcx, &mut cx), Poll::Ready(Ok(())));
            assert_eq!(opened.conn().taken, b"firstsecond");
            Ok(())
        }))
        .unwrap();
    }

    /// Writes once, then waits for its peer.
    #[derive(Default)]
    struct Once {
        sent: bool,
    }

    impl Layer for Once {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = Infallible;
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = ConnError;

        fn on_event(
            &mut self,
            _: &mut Env<'_, Infallible>,
            _: StreamEvent,
        ) -> Result<Admit<StreamEvent>, ConnError> {
            Ok(Admit::Taken)
        }

        fn on_command(
            &mut self,
            _: &mut Env<'_, Infallible>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, ConnError> {
            match command {}
        }

        fn take_command(&mut self, _: &mut Env<'_, Infallible>) -> Option<StreamCommand> {
            (!std::mem::replace(&mut self.sent, true))
                .then(|| StreamCommand::Write(Chunk::new(b"hello".to_vec())))
        }

        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    /// Bytes the connection took but never flushed are a stalled write.
    #[test]
    fn a_write_the_connection_never_flushes_times_out() {
        block_on(lab(Seed::from_u64(2), |fcx| async move {
            let conn = Held {
                taken: Vec::new(),
                flushed: Arc::new(AtomicBool::new(false)),
            };
            let limits = StreamLimits {
                idle: None,
                write_timeout: Some(Duration::from_secs(1)),
            };
            let info = ConnInfo::default();
            let end = stream(
                &fcx,
                conn,
                &info,
                Once::default(),
                Budget::unlimited(),
                limits,
                |_| {},
            )
            .await
            .expect("the run ends with how it ended");
            assert_eq!(end, StreamEnd::Conn(ConnError::TimedOut));
            Ok(())
        }))
        .unwrap();
    }
}
