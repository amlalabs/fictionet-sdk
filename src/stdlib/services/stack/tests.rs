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
            Ok(datagrams(&fcx, socket, server_addr(), Counter::default(), |_| {}).await?)
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
