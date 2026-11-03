//! A world's lookups put to real servers on the internet, as an
//! [`Upstream`] for its learned zones.
//!
//! [`Internet`] asks each lookup from the host through hickory's
//! transports (`hickory-net`): over UDP, and over TCP when the response
//! comes back truncated, on a Tokio runtime it owns. The world's executor
//! only waits for the outcome.

use std::future::Future;
use std::pin::Pin;

use futures_util::StreamExt;
use hickory_net::DnsStreamHandle;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpStream;
use tokio::runtime::Runtime;
use tokio::task::AbortHandle;

use fictionet::Cx;
use fictionet::stdlib::protocols::dns::op::{Edns, Message, MessageType, OpCode, SerialMessage};
use fictionet::stdlib::protocols::dns::read_message;
use fictionet::stdlib::services::dns::{Looked, Lookup};
use fictionet::stdlib::world::net::dns::Upstream;

/// The UDP payload size a lookup advertises: the size the DNS Flag Day
/// 2020 settled on (RFC 6891 §6.2.5).
const PAYLOAD: u16 = 1232;

/// The internet's DNS servers, asked from this host.
///
/// Each lookup goes out as one query over UDP through hickory's
/// `UdpStream`: a fresh ID drawn from the run's seeded random stream
/// (RFC 5452 §9.2) from a source port hickory picks at random, the
/// lookup's question without recursion, and an OPT record with a
/// 1232-octet payload and DO set (RFC 3225 §3). A
/// datagram from another address or port, or without that ID and the
/// question back, is ignored (RFC 5452 §9.1), and so is one that does not
/// decode. A UDP response with TC set is asked again over one TCP
/// connection through hickory's `TcpClientStream` (RFC 7766 §5), and a
/// truncated response is never given as the outcome: its sections may be
/// incomplete (RFC 2181 §9). Responses are decoded with
/// [`read_message`], which also reads records with empty RDATA
/// (RFC 3597 §4). A server that refuses the TCP connection, or a UDP
/// socket the host cannot open, is [`Looked::Unreachable`]; a TCP response
/// that does not answer the lookup, or a connection that ends without
/// one, is [`Looked::NoReply`].
///
/// A query is sent once and waits until its response comes. The engine
/// that made it decides how long to wait, and its driver drops the lookup
/// when it gives up, which stops it here too.
pub struct Internet {
    runtime: Option<Runtime>,
}

impl Default for Internet {
    fn default() -> Internet {
        Internet::new()
    }
}

impl Internet {
    /// An upstream that asks the internet from this host.
    pub fn new() -> Internet {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("fictionet-dns")
            .build()
            .expect("create the DNS runtime");
        Internet {
            runtime: Some(runtime),
        }
    }
}

impl Drop for Internet {
    fn drop(&mut self) {
        // The last owner may be dropped inside another runtime's task.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl Upstream for Internet {
    fn lookup<'a>(
        &'a self,
        fcx: &'a Cx,
        lookup: Lookup,
    ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
        let mut id = [0; 2];
        fcx.fill_random(&mut id);
        let id = u16::from_be_bytes(id);
        let query = query(id, &lookup);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let runtime = self
            .runtime
            .as_ref()
            .expect("the runtime lives as long as Internet");
        let task = runtime.spawn(async move {
            let _ = sender.send(ask(&lookup, id, query).await);
        });
        let abort = Abort(task.abort_handle());
        Box::pin(async move {
            let _abort = abort;
            receiver.await.unwrap_or(Looked::NoReply)
        })
    }
}

/// The query for `lookup` with `id`: its question without recursion, and
/// an OPT record with DO set.
fn query(id: u16, lookup: &Lookup) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.add_query(lookup.question.clone());
    let mut edns = Edns::new();
    edns.set_max_payload(PAYLOAD).set_dnssec_ok(true);
    message.set_edns(edns);
    message
        .to_vec()
        .expect("a query of one question and an OPT record writes")
}

/// What `lookup.server` gives `query`, whose ID is `id`: over UDP, and
/// over TCP when the UDP response is truncated.
async fn ask(lookup: &Lookup, id: u16, query: Vec<u8>) -> Looked {
    let server = lookup.server;
    let provider = TokioRuntimeProvider::new();
    let (udp, mut handle) = UdpStream::new(server, None, None, false, provider.clone());
    let Ok(mut udp) = udp.await else {
        return Looked::Unreachable;
    };
    if handle
        .send(SerialMessage::new(query.clone(), server))
        .is_err()
    {
        return Looked::Unreachable;
    }
    let response = loop {
        match udp.next().await {
            Some(Ok(datagram)) => {
                let from = datagram.addr();
                let same_server = from.ip().to_canonical() == server.ip().to_canonical()
                    && from.port() == server.port();
                if let Some(response) = answer_to(lookup, id, datagram.bytes())
                    && same_server
                {
                    break response;
                }
            }
            Some(Err(_)) => return Looked::Unreachable,
            None => return Looked::NoReply,
        }
    };
    if !response.metadata.truncation {
        return Looked::Response(response);
    }
    let (tcp, mut handle) = TcpClientStream::new(server, None, None, provider);
    let Ok(mut tcp) = tcp.await else {
        return Looked::Unreachable;
    };
    if handle.send(SerialMessage::new(query, server)).is_err() {
        return Looked::NoReply;
    }
    match tcp.next().await {
        Some(Ok(message)) => match answer_to(lookup, id, message.bytes()) {
            Some(response) if !response.metadata.truncation => Looked::Response(response),
            _ => Looked::NoReply,
        },
        Some(Err(_)) | None => Looked::NoReply,
    }
}

/// `bytes` decoded, when they are a response with `id` that answers
/// `lookup`.
fn answer_to(lookup: &Lookup, id: u16, bytes: &[u8]) -> Option<Message> {
    let response = read_message(bytes).ok()?;
    (response.metadata.id == id && lookup.answered_by(&response)).then_some(response)
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
    use fictionet::stdlib::protocols::dns::op::Query;
    use fictionet::stdlib::protocols::dns::rr::rdata::A;
    use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData, Record, RecordType};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, UdpSocket};
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
            let mut buffer = [0; 1232];
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
            let internet = Internet::new();
            let looked = internet
                .lookup(&fcx, lookup(server, "www.example.test.", RecordType::A))
                .await;
            let Looked::Response(response) = looked else {
                panic!("expected a response, got {looked:?}");
            };
            assert!(!response.metadata.truncation);
            assert_eq!(response.answers, vec![answer]);

            let over_udp = queries.recv().unwrap();
            let over_tcp = queries.recv().unwrap();
            // The same query on both transports, ID included: the
            // lookup's question, no recursion, and DO with no options.
            assert_eq!(over_udp, over_tcp);
            let query = Message::from_vec(&over_udp).unwrap();
            assert!(!query.metadata.recursion_desired);
            assert_eq!(query.queries.len(), 1);
            assert_eq!(query.queries[0].name().to_ascii(), "www.example.test.");
            let edns = query.edns.expect("an OPT record");
            assert!(edns.flags().dnssec_ok);
            assert_eq!(edns.max_payload(), PAYLOAD);
            assert!(edns.options().as_ref().is_empty());
        });
        server_thread.join().unwrap();
    }

    /// A truncated response whose server then refuses TCP is no outcome:
    /// the lookup is unreachable, and the partial response is dropped.
    #[test]
    fn a_truncated_reply_without_tcp_is_unreachable() {
        let (udp, tcp) = sockets();
        let server = udp.local_addr().unwrap();
        drop(tcp);
        let server_thread = thread::spawn(move || {
            let mut buffer = [0; 1232];
            let (length, client) = udp.recv_from(&mut buffer).unwrap();
            udp.send_to(&reply_to(&buffer[..length], vec![], true), client)
                .unwrap();
        });
        run(async move |fcx| {
            let internet = Internet::new();
            let looked = internet
                .lookup(&fcx, lookup(server, "www.example.test.", RecordType::A))
                .await;
            assert_eq!(looked, Looked::Unreachable);
        });
        server_thread.join().unwrap();
    }

    /// A record of any type may have empty RDATA (RFC 3597 §4), which
    /// hickory reads only in an UPDATE message: the response still comes
    /// back, with the record in it.
    #[test]
    fn a_record_with_empty_rdata_is_read() {
        let (udp, _tcp) = sockets();
        let server = udp.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let mut buffer = [0; 1232];
            let (length, client) = udp.recv_from(&mut buffer).unwrap();
            let mut reply = reply_to(&buffer[..length], vec![], false);
            // One answer: the question's name (a pointer to offset 12),
            // TYPE65281, class IN, TTL 300, and RDLENGTH 0.
            reply[7] = 1;
            reply.extend_from_slice(&[0xc0, 12, 0xff, 0x01, 0, 1, 0, 0, 1, 44, 0, 0]);
            udp.send_to(&reply, client).unwrap();
        });
        run(async move |fcx| {
            let internet = Internet::new();
            let looked = internet
                .lookup(
                    &fcx,
                    lookup(server, "nul.example.test.", RecordType::Unknown(65281)),
                )
                .await;
            let Looked::Response(response) = looked else {
                panic!("expected a response, got {looked:?}");
            };
            assert_eq!(response.answers.len(), 1);
            assert_eq!(
                response.answers[0].record_type(),
                RecordType::Unknown(65281)
            );
            assert_eq!(response.answers[0].ttl, 300);
        });
        server_thread.join().unwrap();
    }
}
