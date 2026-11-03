//! A world's lookups put to real servers on the internet, as an
//! [`Upstream`] for its learned zones.
//!
//! [`Internet`] asks each lookup from the host through hickory's client
//! transports (`hickory-net`): over UDP, and over TCP when the response
//! comes back truncated, on a Tokio runtime it owns. The world's executor
//! only waits for the outcome.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::time::Duration;

use futures_util::StreamExt;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_net::xfer::DnsRequestSender;
use hickory_net::{DnsHandle, NetError};
use tokio::runtime::Runtime;
use tokio::task::AbortHandle;

use fictionet::Cx;
use fictionet::stdlib::protocols::dns::Nsid;
use fictionet::stdlib::protocols::dns::op::{
    DnsRequest, DnsRequestOptions, DnsResponse, Edns, Message, MessageType, OpCode, Query,
};
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData, RecordType};
use fictionet::stdlib::services::dns::{Looked, Lookup};
use fictionet::stdlib::world::net::dns::Upstream;
use fictionet::sync::Mutex;

/// The UDP payload size a lookup advertises: the size the DNS Flag Day
/// 2020 settled on (RFC 6891 §6.2.5).
const PAYLOAD: u16 = 1232;

/// How long hickory's transports wait on their own: without end, since
/// the engine that made a lookup decides how long to wait and drops the
/// lookup when it gives up.
const NO_TIMEOUT: Duration = Duration::MAX;

/// `ns1.google.com`, which answers a TXT question for [`WHOAMI`] with the
/// address the question came from.
const WHOAMI_SERVER: std::net::SocketAddr =
    std::net::SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(216, 239, 32, 10)), 53);

/// Google's name for asking which address a question came from.
const WHOAMI: &str = "o-o.myaddr.l.google.com.";

/// The zone [`WHOAMI`] is in.
const WHOAMI_ZONE: &str = "google.com.";

/// The internet's DNS servers, asked from this host.
///
/// Each lookup goes out as one query over UDP through hickory's
/// `UdpClientStream`: a fresh ID drawn from the run's seeded random stream
/// (RFC 5452 §9.2) from a random source port, the lookup's question and
/// RD bit, and an OPT record with a 1232-octet payload, DO set (RFC 3225
/// §3), and an NSID request (RFC 5001). hickory ignores a datagram from
/// another address or port, or without that ID and the question back
/// (RFC 5452 §9.1). A UDP response with TC set is asked again over one
/// TCP connection through hickory's `TcpClientStream` (RFC 7766 §5), and
/// a truncated response is never given as the outcome: its sections may
/// be incomplete (RFC 2181 §9). The response comes back decoded. A server
/// that refuses the TCP connection, or that the host cannot send to, is
/// [`Looked::Unreachable`]; a response that does not answer the lookup's
/// question, or a connection that ends without one, is
/// [`Looked::NoReply`].
///
/// A query is sent once and waits until its response comes. The engine
/// that made it decides how long to wait, and its driver drops the lookup
/// when it gives up, which stops it here too.
pub struct Internet {
    runtime: Option<Runtime>,
    egress: Mutex<Option<IpAddr>>,
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
    async fn whoami(&self, fcx: &Cx, server: std::net::SocketAddr) -> Option<IpAddr> {
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
        let request = request(u16::from_be_bytes(id), &lookup);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let runtime = self
            .runtime
            .as_ref()
            .expect("the runtime lives as long as Internet");
        let task = runtime.spawn(async move {
            let _ = sender.send(ask(&lookup, request).await);
        });
        let abort = Abort(task.abort_handle());
        Box::pin(async move {
            let _abort = abort;
            receiver.await.unwrap_or(Looked::NoReply)
        })
    }
}

/// The request for `lookup` with `id`: its question and RD bit, and an OPT
/// record with DO set and an NSID request.
fn request(id: u16, lookup: &Lookup) -> DnsRequest {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = lookup.recursion_desired;
    message.add_query(lookup.question.clone());
    let mut edns = Edns::new();
    edns.set_max_payload(PAYLOAD).set_dnssec_ok(true);
    edns.options_mut().insert(Nsid(Vec::new()).to_option());
    message.set_edns(edns);
    let mut options = DnsRequestOptions::default();
    options.recursion_desired = lookup.recursion_desired;
    options.edns_payload_len = PAYLOAD;
    options.edns_set_dnssec_ok = true;
    DnsRequest::new(message, options)
}

/// What `lookup.server` gives `request`: over UDP, and over TCP when the
/// UDP response is truncated.
async fn ask(lookup: &Lookup, request: DnsRequest) -> Looked {
    let provider = TokioRuntimeProvider::new();
    let mut udp = UdpClientStream::builder(lookup.server, provider.clone())
        .with_timeout(Some(NO_TIMEOUT))
        // hickory counts the first send among its tries.
        .with_max_retries(1)
        .build();
    let response = match udp.send_message(request.clone()).next().await {
        Some(Ok(response)) => response,
        Some(Err(error)) => return failed(error),
        None => return Looked::NoReply,
    };
    if !response.metadata.truncation {
        return answered(lookup, response);
    }
    let Ok(tcp) = TcpClientStream::exchange(lookup.server, None, NO_TIMEOUT, None, provider).await
    else {
        return Looked::Unreachable;
    };
    match tcp.send(request).next().await {
        Some(Ok(response)) if !response.metadata.truncation => answered(lookup, response),
        Some(Err(error)) => failed(error),
        Some(Ok(_)) | None => Looked::NoReply,
    }
}

/// `response` as the outcome of `lookup`, if it answers the lookup's
/// question.
fn answered(lookup: &Lookup, response: DnsResponse) -> Looked {
    let response = response.into_message();
    if lookup.answered_by(&response) {
        Looked::Response(response)
    } else {
        Looked::NoReply
    }
}

/// What a transport's `error` means for a lookup: the host could not send
/// or connect, or no response came.
fn failed(error: NetError) -> Looked {
    match error {
        NetError::Io(_) => Looked::Unreachable,
        _ => Looked::NoReply,
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
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
    use std::sync::mpsc;
    use std::thread;

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

    /// The query's ID, which hickory's TCP transport sets afresh.
    fn without_id(query: &[u8]) -> Message {
        let mut query = Message::from_vec(query).unwrap();
        query.metadata.id = 0;
        query
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
            // The same query on both transports: the lookup's question,
            // no recursion, and DO with an NSID request.
            assert_eq!(without_id(&over_udp), without_id(&over_tcp));
            let query = Message::from_vec(&over_udp).unwrap();
            assert!(!query.metadata.recursion_desired);
            assert_eq!(query.queries.len(), 1);
            assert_eq!(query.queries[0].name().to_ascii(), "www.example.test.");
            let edns = query.edns.expect("an OPT record");
            assert!(edns.flags().dnssec_ok);
            assert_eq!(edns.max_payload(), PAYLOAD);
            assert!(
                edns.options()
                    .as_ref()
                    .iter()
                    .any(|(_, option)| Nsid::from_option(option).is_some())
            );
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

    #[test]
    fn egress_is_the_address_in_the_whoami_answer_and_is_asked_once() {
        let (udp, _tcp) = sockets();
        let server = udp.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let mut buffer = [0; 1232];
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
            let internet = Internet::new();
            let expected = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
            assert_eq!(internet.whoami(&fcx, server).await, expected);
            assert_eq!(internet.whoami(&fcx, server).await, expected);
        });
        server_thread.join().unwrap();
    }
}
