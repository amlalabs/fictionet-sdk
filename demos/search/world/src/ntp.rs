//! The time server the workstation sets its clock from: Ubuntu's own
//! `ntp.ubuntu.com`, answering with the session's time.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::layer::{
    Admit, Budget, Chunk, Datagram, DatagramCommand, DatagramEvent, Datagrams, Env, Layer, Top,
};
use fictionet::stdlib::protocols::ntp::{self, Leap, Packet, ServerInfo, Timestamp};
use fictionet::stdlib::world::net::Host;

use crate::pages::Pages;

/// The name Ubuntu's clock asks for the time.
pub const HOST: &str = "ntp.ubuntu.com";

/// The time server, answering on UDP port 123 with the time
/// [`Pages::session_now`] gives.
pub(crate) fn host(pages: Arc<Pages>) -> Host {
    let host = Host::new(HOST).dns_name(HOST).ipv4_only();
    serve(host, move || pages.session_now())
}

/// Serves NTP on `host`'s UDP port 123 with the time `clock` reads.
fn serve(host: Host, clock: impl Fn() -> SystemTime + Clone + Send + Sync + 'static) -> Host {
    host.udp_stack(ntp::PORT, Budget::new(128 * 1024), move |_| {
        TimeServer::new(clock.clone())
    })
}

/// An NTP server over UDP: one conversation for the socket's whole life,
/// answering each client request with the time `clock` reads.
struct TimeServer<C> {
    clock: C,
    /// The answer the socket has not taken yet.
    reply: Option<Datagram<SocketAddr>>,
}

impl<C: Fn() -> SystemTime> TimeServer<C> {
    fn new(clock: C) -> TimeServer<C> {
        TimeServer { clock, reply: None }
    }

    /// The reply to `request`, if it is a request a server answers.
    fn answer(&self, request: &[u8]) -> Option<Vec<u8>> {
        let request = Packet::parse(request).ok()?;
        let at = (self.clock)();
        let now = timestamp(at);
        // Answers as a stratum 2 pool server does: synced to an upstream
        // server a minute ago, a few milliseconds away, with a clock read
        // to tens of nanoseconds and no leap second coming.
        let server = ServerInfo {
            leap: Leap::None,
            stratum: 2,
            precision: -24,
            root_delay: 0x0000_00a4,
            root_dispersion: 0x0000_0049,
            reference_id: [194, 58, 204, 148],
            reference: timestamp(at - std::time::Duration::from_secs(64)),
        };
        // A packet that is not a request, such as a server's reply, gets
        // no answer, as from a real server.
        let reply = ntp::server_reply(&request, &server, now, now).ok()?;
        let mut bytes = Vec::with_capacity(ntp::HEADER_LEN);
        reply.write(&mut bytes).ok()?;
        Some(bytes)
    }
}

impl<C: Fn() -> SystemTime> Layer for TimeServer<C> {
    type Lower = Datagrams<SocketAddr>;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Infallible>,
        event: DatagramEvent<SocketAddr>,
    ) -> Result<Admit<DatagramEvent<SocketAddr>>, Infallible> {
        let datagram = match event {
            DatagramEvent::Datagram(d) if self.reply.is_some() => {
                return Ok(Admit::Blocked(DatagramEvent::Datagram(d)));
            }
            DatagramEvent::Datagram(d) => d,
            DatagramEvent::Ended => return Ok(Admit::Taken),
        };
        let client = *datagram.meta();
        // An answer the budget has no room for is not sent, as a busy
        // server drops a request.
        // Parsing copies the trailer; the transactional writer uses one
        // temporary header alongside the final reply allocation.
        let temporary = datagram.payload().len().saturating_sub(ntp::HEADER_LEN);
        let Some(reservation) = temporary.checked_add(2 * ntp::HEADER_LEN) else {
            return Ok(Admit::Taken);
        };
        if let Some(mut charge) = env.budget().charge(reservation)
            && let Some(bytes) = self.answer(datagram.payload())
        {
            charge.set(ntp::HEADER_LEN);
            let payload = Chunk::with_charge(bytes, charge);
            self.reply = Some(Datagram::new(payload, client));
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

    fn take_command(&mut self) -> Option<DatagramCommand<SocketAddr>> {
        self.reply.take().map(DatagramCommand::Send)
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

fn timestamp(time: SystemTime) -> Timestamp {
    let since = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp::from_unix(since.as_secs() as i64, since.subsec_nanos())
}

#[cfg(kani)]
#[path = "../../../../verification/layer-runtime/kani/ntp.rs"]
mod proofs;

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::layer::{Budget, Driver};
    use fictionet::stdlib::protocols::ntp::Mode;
    use fictionet::time::Instant;
    use fictionet::{Seed, SeededEntropy};
    use std::time::Duration;

    /// The session's clock in these tests.
    fn session() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_762_560_000)
    }

    type Server = TimeServer<fn() -> SystemTime>;

    fn server() -> Driver<Server> {
        let entropy = Arc::new(SeededEntropy::new(Seed::from_u64(0)));
        Driver::new(
            TimeServer::new(session as fn() -> SystemTime),
            entropy,
            Budget::unlimited(),
            Instant::ZERO,
        )
    }

    /// Hands the server one datagram from `from`, and returns what it
    /// sends, with where to.
    fn send(
        server: &mut Driver<Server>,
        from: SocketAddr,
        bytes: &[u8],
    ) -> Vec<(Vec<u8>, SocketAddr)> {
        let datagram = Datagram::new(Chunk::new(bytes.to_vec()), from);
        let admit = server
            .deliver(DatagramEvent::Datagram(datagram))
            .expect("the server never fails");
        assert!(matches!(admit, Admit::Taken), "a datagram is taken whole");
        server.run().expect("the server never fails");
        let mut sent = Vec::new();
        server.send_below(|command| {
            if let DatagramCommand::Send(d) = command {
                let (payload, to) = d.into_parts();
                sent.push((payload.to_vec(), to));
            }
            Admit::Taken
        });
        sent
    }

    fn client(port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 2], port))
    }

    #[test]
    fn reply_memory_is_reserved_before_parsing_and_encoding() {
        let mut request = Packet::client_request(Timestamp::from_unix(1_000, 7));
        request.trailer = vec![0; 4];
        let bytes = request.to_bytes().unwrap();
        for limit in [99, 100] {
            let budget = Budget::new(limit);
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counted = calls.clone();
            let mut driver = Driver::new(
                TimeServer::new(move || {
                    counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    session()
                }),
                Arc::new(SeededEntropy::new(Seed::from_u64(0))),
                budget.clone(),
                Instant::ZERO,
            );
            let event =
                DatagramEvent::Datagram(Datagram::new(Chunk::new(bytes.clone()), client(1)));
            assert!(matches!(driver.deliver(event).unwrap(), Admit::Taken));
            let command = driver.layer_mut().take_command();
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::Relaxed),
                usize::from(limit == 100)
            );
            assert_eq!(command.is_some(), limit == 100);
            assert_eq!(
                budget.used(),
                if limit == 100 { ntp::HEADER_LEN } else { 0 }
            );
            drop(driver);
            assert_eq!(
                budget.used(),
                if limit == 100 { ntp::HEADER_LEN } else { 0 }
            );
            drop(command);
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn a_client_request_gets_the_session_time_back_to_its_sender() {
        let mut server = server();
        let asked = Timestamp::from_unix(1_000, 7);
        let request = Packet::client_request(asked).to_bytes().unwrap();
        let sent = send(&mut server, client(40_000), &request);
        assert_eq!(sent.len(), 1, "one request, one answer");
        let (bytes, to) = &sent[0];
        assert_eq!(*to, client(40_000), "the answer goes to the client");
        let answer = Packet::parse(bytes).expect("the answer is NTP");
        assert_eq!(answer.mode, Mode::Server);
        assert_eq!(answer.origin, asked, "the client can match the answer");
        assert_eq!(answer.transmit, timestamp(session()));
    }

    #[test]
    fn one_conversation_answers_each_request_and_nothing_else() {
        let mut server = server();
        let request = Packet::client_request(Timestamp::from_unix(1_000, 0))
            .to_bytes()
            .unwrap();
        let reply = Packet::parse(&send(&mut server, client(1), &request)[0].0).unwrap();
        // A server's reply, an empty datagram and bytes that are not NTP
        // get no answer, and the conversation goes on after them.
        assert!(send(&mut server, client(2), &reply.to_bytes().unwrap()).is_empty());
        assert!(send(&mut server, client(2), b"").is_empty());
        assert!(send(&mut server, client(2), b"hello").is_empty());
        let sent = send(&mut server, client(2), &request);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1, client(2));
    }

    #[test]
    fn a_sandbox_sets_its_clock_from_the_host_over_the_network() {
        use fictionet::stdlib::network::route::Prefix;
        use fictionet::stdlib::world::net::{Net, Pools};
        use fictionet_test_support::sandbox;
        use std::net::{IpAddr, Ipv4Addr};

        const SERVER: Ipv4Addr = Ipv4Addr::new(192, 168, 95, 11);
        const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 40, 0, 50);
        let result = fictionet::block_on(fictionet::lab(Seed::from_u64(1), |fcx| async move {
            let subnet = Prefix {
                addr: IpAddr::V4(Ipv4Addr::new(10, 40, 0, 0)),
                len: 24,
            };
            let host = serve(Host::new("ntp").ipv4_only().at(SERVER), session);
            let net = Net::new(Pools::NONE)
                .subnet(subnet)
                .ipv4_only()
                .host("ntp", |_| host);
            let (attacher, attachments) = fictionet::attachments();
            net.start(&fcx, attachments)?;
            let client = sandbox::machine(&fcx, attacher.attach("workstation")?, CLIENT);
            let mut socket = client.udp.bind(0)?;
            let to = SocketAddr::new(SERVER.into(), ntp::PORT);
            for second in [1_000, 1_064] {
                let asked = Timestamp::from_unix(second, 0);
                socket.send_to(&Packet::client_request(asked).to_bytes()?, to);
                let (bytes, from) = socket.recv(&fcx).await?;
                assert_eq!(from, to, "the answer comes from port 123");
                let answer = Packet::parse(&bytes)?;
                assert_eq!(answer.mode, Mode::Server);
                assert_eq!(answer.origin, asked, "it answers this request");
                assert_eq!(answer.transmit, timestamp(session()));
            }
            fcx.cancel();
            Ok(())
        }));
        result.unwrap();
    }
}
