//! DNS questions put to real servers on the internet, as a
//! [`Source`] for a world's relays.
//!
//! [`Live`] sends each question from the host, over UDP and then over
//! TCP when the reply comes back truncated, on a Tokio runtime it owns.
//! The world's executor only waits for the outcome.

use std::future::{Future, ready};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::runtime::Runtime;
use tokio::task::AbortHandle;

use fictionet::Cx;
use fictionet::stdlib::protocols::dns::op::{Message, MessageType, OpCode, Query};
use fictionet::stdlib::protocols::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::protocols::dns::{Parsed, Request, restore};
use fictionet::stdlib::services::dns::authority::{Ask, Observed};
use fictionet::stdlib::services::serve::Transport;
use fictionet::stdlib::world::net::dns::Source;
use fictionet::sync::Mutex;

/// The largest DNS message a UDP datagram or a TCP frame can carry: the
/// length prefix on TCP is two octets (RFC 1035 §4.2.2), and EDNS lets a
/// UDP reply be as large (RFC 6891 §6.2.5).
const MAX_MESSAGE: usize = u16::MAX as usize;

/// `ns1.google.com`, which answers a TXT question for
/// [`WHOAMI`] with the address the question came from.
const WHOAMI_SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(216, 239, 32, 10)), 53);

/// Google's name for asking which address a question came from.
const WHOAMI: &str = "o-o.myaddr.l.google.com.";

/// The internet's DNS servers, asked from this host.
///
/// Each question goes out as it came, with one change: a fresh ID drawn
/// from the run's seeded random stream, so a guest never chooses the ID a
/// real server sees (RFC 5452 §9.2). A datagram that does not carry that
/// ID and the question back is not the reply and is ignored, as RFC 5452
/// §9.1 requires; a UDP reply with TC set is asked again over TCP
/// (RFC 7766 §5). The reply comes back as it arrived, with the fresh ID,
/// for the relay to put the asker's back. A refused or unreachable server
/// is [`Observed::Unreachable`].
///
/// A question waits until its reply comes. The engine that asked decides
/// how long to wait, and its driver drops the question when it gives up,
/// which stops it here too.
pub struct Live {
    runtime: Option<Runtime>,
    egress: Mutex<Option<IpAddr>>,
}

impl Default for Live {
    fn default() -> Live {
        Live::new()
    }
}

impl Live {
    /// A source that asks the internet from this host.
    pub fn new() -> Live {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("fictionet-dns")
            .build()
            .expect("create the DNS runtime");
        Live {
            runtime: Some(runtime),
            egress: Mutex::new(None),
        }
    }

    /// This host's public IPv4 address, as a real authority sees it: the
    /// answer `ns1.google.com` gives for `o-o.myaddr.l.google.com` TXT.
    /// The first answer is kept, so the internet is asked once. `None`
    /// when the server cannot be reached or its answer holds no address.
    pub async fn egress(&self, fcx: &Cx) -> Option<IpAddr> {
        self.whoami(fcx, WHOAMI_SERVER).await
    }

    /// The address `server` says a whoami question came from.
    async fn whoami(&self, fcx: &Cx, server: SocketAddr) -> Option<IpAddr> {
        if let Some(address) = *self.egress.lock() {
            return Some(address);
        }
        let mut question = Message::new(0, MessageType::Query, OpCode::Query);
        question.add_query(Query::query(
            Name::from_ascii(WHOAMI).expect("a valid name"),
            RecordType::TXT,
        ));
        let ask = Ask {
            server,
            transport: Transport::Udp,
            query: question.to_vec().ok()?,
        };
        let Observed::Reply(reply) = self.ask(fcx, ask).await else {
            return None;
        };
        let address = Message::from_vec(&reply)
            .ok()?
            .answers
            .into_iter()
            .find_map(|record| match record.data {
                RData::TXT(txt) => txt
                    .txt_data
                    .iter()
                    .find_map(|text| IpAddr::from_str(std::str::from_utf8(text).ok()?).ok()),
                _ => None,
            })?;
        Some(*self.egress.lock().get_or_insert(address))
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        // The last owner may be dropped inside another runtime's task.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl Source for Live {
    fn ask<'a>(
        &'a self,
        fcx: &'a Cx,
        ask: Ask,
    ) -> Pin<Box<dyn Future<Output = Observed> + Send + 'a>> {
        let Parsed::Request(request) = Request::parse(&ask.query, ask.transport) else {
            return Box::pin(ready(Observed::Timeout));
        };
        let mut id = [0; 2];
        fcx.fill_random(&mut id);
        let mut query = ask.query;
        query[..2].copy_from_slice(&id);
        let exchange = Exchange {
            server: ask.server,
            id: u16::from_be_bytes(id),
            query,
            request,
        };
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let runtime = self
            .runtime
            .as_ref()
            .expect("the runtime lives as long as Live");
        let task = runtime.spawn(async move {
            let observed = match ask.transport {
                Transport::Udp => exchange.udp().await,
                Transport::Tcp => exchange.tcp().await,
            };
            let _ = sender.send(observed);
        });
        let abort = Abort(task.abort_handle());
        Box::pin(async move {
            let _abort = abort;
            receiver.await.unwrap_or(Observed::Timeout)
        })
    }
}

/// One question on its way to a real server.
struct Exchange {
    server: SocketAddr,
    /// The ID the question went out with.
    id: u16,
    /// The question's octets, with that ID.
    query: Vec<u8>,
    /// The question as asked, to tell its reply from other datagrams.
    request: Request,
}

impl Exchange {
    /// Asks over UDP, and over TCP when the reply is truncated. If TCP
    /// then brings nothing, the truncated reply is what the client saw.
    async fn udp(&self) -> Observed {
        let reply = match self.datagram().await {
            Ok(reply) => reply,
            Err(_) => return Observed::Unreachable,
        };
        // TC is bit 1 of the third header octet (RFC 1035 §4.1.1).
        if reply[2] & 0x02 == 0 {
            return Observed::Reply(reply);
        }
        match self.tcp().await {
            Observed::Reply(whole) => Observed::Reply(whole),
            Observed::Unreachable | Observed::Timeout => Observed::Reply(reply),
        }
    }

    /// The first datagram from the server that answers the question.
    async fn datagram(&self) -> io::Result<Vec<u8>> {
        let local = match self.server {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let socket = UdpSocket::bind(SocketAddr::new(local, 0)).await?;
        // A connected socket takes datagrams only from the server, and
        // reports the server's port unreachable as a refused receive.
        socket.connect(self.server).await?;
        socket.send(&self.query).await?;
        let mut buffer = vec![0; MAX_MESSAGE];
        loop {
            let length = socket.recv(&mut buffer).await?;
            if self.answers(&buffer[..length]) {
                buffer.truncate(length);
                return Ok(buffer);
            }
        }
    }

    /// Asks over one TCP connection (RFC 7766 §6.2.1). A connection that
    /// cannot be made is unreachable; one that ends before the reply is a
    /// timeout, since no reply came.
    async fn tcp(&self) -> Observed {
        let Ok(mut stream) = TcpStream::connect(self.server).await else {
            return Observed::Unreachable;
        };
        let mut frame = Vec::with_capacity(2 + self.query.len());
        frame.extend_from_slice(&(self.query.len() as u16).to_be_bytes());
        frame.extend_from_slice(&self.query);
        if stream.write_all(&frame).await.is_err() {
            return Observed::Timeout;
        }
        loop {
            let mut length = [0; 2];
            if stream.read_exact(&mut length).await.is_err() {
                return Observed::Timeout;
            }
            let mut reply = vec![0; usize::from(u16::from_be_bytes(length))];
            if stream.read_exact(&mut reply).await.is_err() {
                return Observed::Timeout;
            }
            if self.answers(&reply) {
                return Observed::Reply(reply);
            }
        }
    }

    /// Whether `reply` is the server's reply to this question: the same
    /// ID, QR set, and the question back (RFC 5452 §9.1).
    fn answers(&self, reply: &[u8]) -> bool {
        reply.len() >= 2
            && u16::from_be_bytes([reply[0], reply[1]]) == self.id
            && restore(reply, &self.request).is_ok()
    }
}

struct Abort(AbortHandle);

impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::Seed;
    use fictionet::stdlib::protocols::dns::rr::Record;
    use fictionet::stdlib::protocols::dns::rr::rdata::{A, TXT};
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn run<F: Future<Output = ()> + Send + 'static>(test: impl FnOnce(Cx) -> F + Send) {
        fictionet::block_on(fictionet::run(Seed::from_u64(1), |fcx| {
            let test = test(fcx);
            async move {
                test.await;
                Ok(())
            }
        }))
        .unwrap();
    }

    fn query(id: u16, name: &str, kind: RecordType) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
        message.to_vec().unwrap()
    }

    /// A reply to `query` with `answers`, and TC set when `truncated`.
    fn reply_to(query: &[u8], answers: Vec<Record>, truncated: bool) -> Vec<u8> {
        let query = Message::from_vec(query).unwrap();
        let mut reply = Message::response(query.metadata.id, OpCode::Query);
        reply.metadata.authoritative = true;
        reply.metadata.truncation = truncated;
        reply.add_query(query.queries[0].clone());
        for answer in answers {
            reply.add_answer(answer);
        }
        reply.to_vec().unwrap()
    }

    /// A UDP socket and a TCP listener on the same loopback port.
    fn sockets() -> (UdpSocket, TcpListener) {
        loop {
            let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()) {
                udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                return (udp, tcp);
            }
        }
    }

    #[test]
    fn a_truncated_reply_is_asked_again_over_tcp() {
        let (udp, tcp) = sockets();
        let server = udp.local_addr().unwrap();
        let (seen, queries) = mpsc::channel();
        let answer = Record::from_rdata(
            Name::from_ascii("www.example.test.").unwrap(),
            300,
            RData::A(A::new(192, 0, 2, 1)),
        );
        let record = answer.clone();
        let server_thread = thread::spawn(move || {
            let mut buffer = [0; 512];
            let (length, client) = udp.recv_from(&mut buffer).unwrap();
            let asked = buffer[..length].to_vec();
            // A datagram with another ID comes first, as a spoofed reply
            // would, and must be ignored.
            let mut spoofed = reply_to(&asked, vec![], false);
            spoofed[1] ^= 1;
            udp.send_to(&spoofed, client).unwrap();
            udp.send_to(&reply_to(&asked, vec![], true), client)
                .unwrap();
            seen.send(asked).unwrap();

            let (mut stream, _) = tcp.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut length = [0; 2];
            stream.read_exact(&mut length).unwrap();
            let mut asked = vec![0; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut asked).unwrap();
            let whole = reply_to(&asked, vec![record], false);
            stream
                .write_all(&(whole.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&whole).unwrap();
            seen.send(asked).unwrap();
        });
        run(async move |fcx| {
            let live = Live::new();
            let asked = query(0x1234, "www.example.test.", RecordType::A);
            let observed = live
                .ask(
                    &fcx,
                    Ask {
                        server,
                        transport: Transport::Udp,
                        query: asked.clone(),
                    },
                )
                .await;
            let Observed::Reply(bytes) = observed else {
                panic!("expected a reply, got {observed:?}");
            };
            let reply = Message::from_vec(&bytes).unwrap();
            assert!(!reply.metadata.truncation);
            assert_eq!(reply.answers, vec![answer]);

            let over_udp = queries.recv().unwrap();
            let over_tcp = queries.recv().unwrap();
            // The server saw a fresh ID, the same on both transports, and
            // otherwise the question as it was asked.
            assert_ne!(over_udp[..2], asked[..2]);
            assert_eq!(over_udp, over_tcp);
            assert_eq!(over_udp[2..], asked[2..]);
            assert_eq!(bytes[..2], over_udp[..2], "the reply as received");
        });
        server_thread.join().unwrap();
    }

    #[test]
    fn a_closed_port_is_unreachable() {
        let (udp, tcp) = sockets();
        let server = udp.local_addr().unwrap();
        drop((udp, tcp));
        run(async move |fcx| {
            let live = Live::new();
            for transport in [Transport::Udp, Transport::Tcp] {
                let ask = Ask {
                    server,
                    transport,
                    query: query(1, "www.example.test.", RecordType::A),
                };
                assert_eq!(live.ask(&fcx, ask).await, Observed::Unreachable);
            }
        });
    }

    #[test]
    fn egress_is_the_address_in_the_whoami_answer_and_is_asked_once() {
        let (udp, _tcp) = sockets();
        let server = udp.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let mut buffer = [0; 512];
            let (length, client) = udp.recv_from(&mut buffer).unwrap();
            let asked = &buffer[..length];
            let question = Message::from_vec(asked).unwrap();
            assert_eq!(question.queries[0].name().to_ascii(), WHOAMI);
            assert_eq!(question.queries[0].query_type(), RecordType::TXT);
            let answer = Record::from_rdata(
                Name::from_ascii(WHOAMI).unwrap(),
                60,
                RData::TXT(TXT::new(vec!["203.0.113.9".to_string()])),
            );
            udp.send_to(&reply_to(asked, vec![answer], false), client)
                .unwrap();
            // A second question would find no one answering.
            drop(udp);
        });
        run(async move |fcx| {
            let live = Live::new();
            let expected = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
            assert_eq!(live.whoami(&fcx, server).await, expected);
            assert_eq!(live.whoami(&fcx, server).await, expected);
        });
        server_thread.join().unwrap();
    }
}
