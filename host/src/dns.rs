//! A world's lookups put to real servers on the internet, as an
//! [`Upstream`] for its learned zones.
//!
//! [`Live`] sends each lookup from the host, over UDP and then over TCP
//! when the response comes back truncated, on a Tokio runtime it owns.
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
use fictionet::stdlib::protocols::dns::op::{Edns, Message, MessageType, OpCode, Query};
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData, RecordType};
use fictionet::stdlib::protocols::dns::{Nsid, read_message, stream_framed};
use fictionet::stdlib::services::dns::{Looked, Lookup};
use fictionet::stdlib::world::net::dns::Upstream;
use fictionet::sync::Mutex;

/// The largest DNS message a UDP datagram or a TCP frame can carry: the
/// length prefix on TCP is two octets (RFC 1035 §4.2.2), and EDNS lets a
/// UDP reply be as large (RFC 6891 §6.2.5).
const MAX_MESSAGE: usize = u16::MAX as usize;

/// The UDP payload size a lookup advertises: the size the DNS Flag Day
/// 2020 settled on (RFC 6891 §6.2.5).
const PAYLOAD: u16 = 1232;

/// `ns1.google.com`, which answers a TXT question for
/// [`WHOAMI`] with the address the question came from.
const WHOAMI_SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(216, 239, 32, 10)), 53);

/// Google's name for asking which address a question came from.
const WHOAMI: &str = "o-o.myaddr.l.google.com.";

/// The zone [`WHOAMI`] is in.
const WHOAMI_ZONE: &str = "google.com.";

/// The internet's DNS servers, asked from this host.
///
/// Each lookup goes out as one query: a fresh ID drawn from the run's
/// seeded random stream (RFC 5452 §9.2), the lookup's question and RD
/// bit, and an OPT record with a 1232-octet payload, DO set (RFC 3225 §3),
/// and an NSID request (RFC 5001). A datagram that does not carry that ID
/// and the question back is not the response and is ignored, as RFC 5452
/// §9.1 requires; a UDP response with TC set is asked again over TCP
/// (RFC 7766 §5). The response comes back decoded. A refused or
/// unreachable server is [`Looked::Unreachable`].
///
/// A lookup waits until its response comes. The engine that made it
/// decides how long to wait, and its driver drops the lookup when it
/// gives up, which stops it here too.
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
    /// An upstream that asks the internet from this host.
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
        let question = Query::query(
            Name::from_ascii(WHOAMI).expect("a valid name"),
            RecordType::TXT,
        );
        let zone = LowerName::new(&Name::from_ascii(WHOAMI_ZONE).expect("a valid name"));
        let lookup = Lookup::new(server, zone, &question);
        let Looked::Response(response) = self.lookup(fcx, lookup).await else {
            return None;
        };
        let address = response
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

impl Upstream for Live {
    fn lookup<'a>(
        &'a self,
        fcx: &'a Cx,
        lookup: Lookup,
    ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
        let mut id = [0; 2];
        fcx.fill_random(&mut id);
        let id = u16::from_be_bytes(id);
        let Ok(query) = query(id, &lookup).to_vec() else {
            return Box::pin(ready(Looked::NoReply));
        };
        let exchange = Exchange {
            server: lookup.server,
            id,
            query,
            lookup,
        };
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let runtime = self
            .runtime
            .as_ref()
            .expect("the runtime lives as long as Live");
        let task = runtime.spawn(async move {
            let _ = sender.send(exchange.udp().await);
        });
        let abort = Abort(task.abort_handle());
        Box::pin(async move {
            let _abort = abort;
            receiver.await.unwrap_or(Looked::NoReply)
        })
    }
}

/// The query for `lookup` with `id`: its question and RD bit, and an OPT
/// record with DO set and an NSID request.
fn query(id: u16, lookup: &Lookup) -> Message {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = lookup.recursion_desired;
    message.add_query(lookup.question.clone());
    let mut edns = Edns::new();
    edns.set_max_payload(PAYLOAD).set_dnssec_ok(true);
    edns.options_mut().insert(Nsid(Vec::new()).to_option());
    message.set_edns(edns);
    message
}

/// One lookup on its way to a real server.
struct Exchange {
    server: SocketAddr,
    /// The ID the query went out with.
    id: u16,
    /// The query's octets.
    query: Vec<u8>,
    /// The lookup, to tell its response from other datagrams.
    lookup: Lookup,
}

impl Exchange {
    /// Asks over UDP, and over TCP when the response is truncated. If TCP
    /// then brings nothing, the truncated response is what came.
    async fn udp(&self) -> Looked {
        let response = match self.datagram().await {
            Ok(response) => response,
            Err(_) => return Looked::Unreachable,
        };
        if !response.metadata.truncation {
            return Looked::Response(response);
        }
        match self.tcp().await {
            Looked::Response(whole) => Looked::Response(whole),
            Looked::Unreachable | Looked::NoReply => Looked::Response(response),
        }
    }

    /// The first datagram from the server that answers the lookup.
    async fn datagram(&self) -> io::Result<Message> {
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
            if let Some(response) = self.response(&buffer[..length]) {
                return Ok(response);
            }
        }
    }

    /// Asks over one TCP connection (RFC 7766 §6.2.1). A connection that
    /// cannot be made is unreachable; one that ends before the response
    /// brought none.
    async fn tcp(&self) -> Looked {
        let Ok(mut stream) = TcpStream::connect(self.server).await else {
            return Looked::Unreachable;
        };
        // A query no stream can carry reaches no server.
        let Some(frame) = stream_framed(&self.query) else {
            return Looked::Unreachable;
        };
        if stream.write_all(&frame).await.is_err() {
            return Looked::NoReply;
        }
        loop {
            let mut length = [0; 2];
            if stream.read_exact(&mut length).await.is_err() {
                return Looked::NoReply;
            }
            let mut reply = vec![0; usize::from(u16::from_be_bytes(length))];
            if stream.read_exact(&mut reply).await.is_err() {
                return Looked::NoReply;
            }
            if let Some(response) = self.response(&reply) {
                return Looked::Response(response);
            }
        }
    }

    /// `reply` decoded, if it is the server's response to this lookup: the
    /// query's ID, QR set, and the question back (RFC 5452 §9.1).
    fn response(&self, reply: &[u8]) -> Option<Message> {
        let response = read_message(reply).ok()?;
        (response.metadata.id == self.id && self.lookup.answered_by(&response)).then_some(response)
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

    fn lookup(server: SocketAddr, name: &str, kind: RecordType) -> Lookup {
        let zone = LowerName::new(&Name::from_ascii("example.test.").unwrap());
        Lookup::new(
            server,
            zone,
            &Query::query(Name::from_ascii(name).unwrap(), kind),
        )
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
            let looked = live
                .lookup(&fcx, lookup(server, "www.example.test.", RecordType::A))
                .await;
            let Looked::Response(response) = looked else {
                panic!("expected a response, got {looked:?}");
            };
            assert!(!response.metadata.truncation);
            assert_eq!(response.answers, vec![answer]);

            let over_udp = queries.recv().unwrap();
            let over_tcp = queries.recv().unwrap();
            // The same query on both transports: the lookup's question,
            // no recursion, and DO with an NSID request.
            assert_eq!(over_udp, over_tcp);
            let query = Message::from_vec(&over_udp).unwrap();
            assert!(!query.metadata.recursion_desired);
            assert_eq!(query.queries[0].name().to_ascii(), "www.example.test.");
            let edns = query.edns.expect("an OPT record");
            assert!(edns.flags().dnssec_ok);
            assert!(
                edns.options()
                    .as_ref()
                    .iter()
                    .any(|(_, option)| Nsid::from_option(option).is_some())
            );
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
            let looked = live
                .lookup(&fcx, lookup(server, "www.example.test.", RecordType::A))
                .await;
            assert_eq!(looked, Looked::Unreachable);
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
