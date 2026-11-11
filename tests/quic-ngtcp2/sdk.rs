// The SDK's QUIC layer as an endpoint on the simulated link, with the
// interop runner's applications above it: hq-interop on both sides, and
// the SDK's own HTTP/3 server.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fictionet::stdlib::layer::*;
use fictionet::stdlib::services::quic::*;
use fictionet::stdlib::services::stack::Polling;
use fictionet::stdlib::services::tls;
use fictionet::stdlib::web::{self, httpd};
use fictionet::time::Instant;
use fictionet::{Entropy, Seed, SeededEntropy};

use crate::network::{Endpoint, Side};
use crate::ngtcp2::{CERTIFICATE, KEY};

const DATE: u64 = 1_893_456_000;

#[derive(Debug)]
struct Calendar;
impl rustls::time_provider::TimeProvider for Calendar {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            Duration::from_secs(DATE),
        ))
    }
}
impl quinn_proto::TimeSource for Calendar {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(DATE)
    }
}

pub const SERVER: &str = "127.0.0.1:4433";
pub const CLIENT: &str = "127.0.0.1:4444";

/// How an SDK endpoint takes part in version negotiation
#[derive(Clone, Copy, Debug)]
pub struct Versions<'a> {
    /// A client's first flight
    pub first: u32,
    /// Most preferred first: a client's offer, a server's accepted versions
    pub preferred: &'a [u32],
}

fn configs(
    entropy: Arc<dyn Entropy>,
    alpn: &[u8],
    versions: Versions<'_>,
) -> (ClientConfig, ServerConfig, Arc<EndpointConfig>) {
    let cert = rustls::pki_types::CertificateDer::from(CERTIFICATE.to_vec());
    let key = rustls::pki_types::PrivateKeyDer::try_from(KEY.to_vec()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let provider = Arc::new(tls::crypto_provider(entropy));
    let mut client =
        rustls::ClientConfig::builder_with_details(provider.clone(), Arc::new(Calendar))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let mut server = rustls::ServerConfig::builder_with_details(provider, Arc::new(Calendar))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    client.alpn_protocols = vec![alpn.to_vec()];
    server.alpn_protocols = client.alpn_protocols.clone();
    let mut transport = quinn_proto::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(100u32.into())
        .max_concurrent_uni_streams(8u32.into())
        .stream_receive_window((1u32 << 20).into())
        .receive_window((4u32 << 20).into())
        .send_window(4 << 20);
    let transport = Arc::new(transport);
    let mut client = ClientConfig::new(Arc::new(
        quinn_proto::crypto::rustls::QuicClientConfig::try_from(client).unwrap(),
    ));
    client
        .transport_config(transport.clone())
        .version(versions.first)
        .preferred_versions(VersionList::new(versions.preferred).unwrap());
    let mut server = ServerConfig::new(
        Arc::new(quinn_proto::crypto::rustls::QuicServerConfig::try_from(server).unwrap()),
        Arc::new(ring::hkdf::Prk::new_less_safe(
            ring::hkdf::HKDF_SHA256,
            &[5; 32],
        )),
    );
    server
        .transport_config(transport)
        .time_source(Arc::new(Calendar));
    let mut endpoint = EndpointConfig::new(Arc::new(ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        &[9; 32],
    )));
    endpoint.supported_versions(versions.preferred.to_vec());
    (client, server, Arc::new(endpoint))
}

/// The datagram side of an SDK stack
pub struct Sdk<L: Layer<Lower = Datagrams<SocketAddr>>> {
    pub driver: Driver<L>,
    remote: SocketAddr,
}

impl<L> Sdk<L>
where
    L: Layer<Lower = Datagrams<SocketAddr>>,
    L::Error: std::fmt::Debug,
{
    fn receive(&mut self, datagram: &[u8], now: Duration) {
        self.driver.set_now(Instant::from_since_start(now));
        let payload = Chunk::copy_of(self.driver.budget(), datagram).expect("budget");
        let admitted = self
            .driver
            .deliver(DatagramEvent::Datagram(Datagram::new(payload, self.remote)))
            .unwrap();
        assert!(matches!(admitted, Admit::Taken));
    }

    /// The next datagram the stack hands down, completed at once: the link
    /// takes every datagram, then drops or queues it
    fn take(&mut self) -> Option<Vec<u8>> {
        let DatagramCommand::Send(datagram) = self.driver.take_command()? else {
            return None;
        };
        assert_eq!(*datagram.meta(), self.remote);
        let (payload, _) = datagram.into_parts();
        let admitted = self.driver.deliver(DatagramEvent::Sent(1)).unwrap();
        assert!(matches!(admitted, Admit::Taken));
        Some(payload.into_vec())
    }

    fn timer(&self) -> Option<Duration> {
        self.driver.deadline().map(Instant::since_start)
    }
}

fn layer(
    env: &mut Env<'_, ()>,
    endpoint: Arc<EndpointConfig>,
    server: Option<ServerConfig>,
    validation: AddressValidation,
) -> QuicLayer {
    QuicLayer::new(
        env,
        endpoint,
        server.map(Arc::new),
        std::time::Instant::now(),
        16,
        |_| 0u32.into(),
    )
    .unwrap()
    .with_address_validation(validation)
}

type Command = MuxCommand<ByteStream<VarInt>, Control>;

/// Commands the layer has not taken yet, offered again in order once it
/// has made progress, as `Admit::Blocked` asks
#[derive(Default)]
struct Outbox(VecDeque<Command>);

impl Outbox {
    fn push(&mut self, command: Command) {
        self.0.push_back(command);
    }

    /// Offer queued commands until the layer stops taking them; whether it
    /// took any
    fn flush(&mut self, driver: &mut Driver<QuicLayer>) -> bool {
        let mut moved = false;
        while let Some(command) = self.0.pop_front() {
            match driver.command(command).unwrap() {
                Admit::Taken => moved = true,
                Admit::Partial(rest) => {
                    self.0.push_front(rest);
                    return true;
                }
                Admit::Blocked(command) => {
                    self.0.push_front(command);
                    return moved;
                }
                // A grant or write for a stream that has already ended
                Admit::Closed(_) => moved = true,
            }
        }
        moved
    }
}

/// One hq-interop stream: the bytes it sends, and those it received
struct HqStream {
    child: Child,
    output: Vec<u8>,
    sent: usize,
    credit: u64,
    finish: bool,
    finished: bool,
    input: Vec<u8>,
    ended: bool,
    /// A client's request index
    request: Option<usize>,
}

/// The interop runner's hq-interop application: a client sends
/// "GET /path\r\n" and FIN on its own stream for each file; the server
/// answers with the file and FIN
pub struct Hq {
    side: Side,
    files: BTreeMap<String, Vec<u8>>,
    requests: Vec<String>,
    responses: Vec<Option<Vec<u8>>>,
    streams: Vec<HqStream>,
    outbox: Outbox,
    pub lost: Option<quinn_proto::ConnectionError>,
    pub ended: bool,
    closing: bool,
}

const GRANT: u64 = 1 << 16;

impl Hq {
    fn new(side: Side) -> Self {
        Self {
            side,
            files: BTreeMap::new(),
            requests: Vec::new(),
            responses: Vec::new(),
            streams: Vec::new(),
            outbox: Outbox::default(),
            lost: None,
            ended: false,
            closing: false,
        }
    }

    fn event(&mut self, event: MuxEvent<ByteStream<VarInt>, Control, Stream>) {
        match event {
            MuxEvent::Control(ControlEvent::Connected) => {
                if self.side == Side::Client {
                    for _ in &self.requests {
                        self.outbox
                            .push(MuxCommand::control(ControlCommand::Open(Dir::Bi)));
                    }
                }
            }
            MuxEvent::Control(ControlEvent::Lost(error)) => self.lost = Some(error),
            MuxEvent::Control(ControlEvent::Ended) => self.ended = true,
            MuxEvent::Opened(child, stream, _) => {
                self.outbox.push(child.grant(GRANT));
                let request = (self.side == Side::Client).then(|| {
                    // Streams open in the order they were asked for.
                    assert!(stream.local);
                    self.streams.iter().filter(|s| s.request.is_some()).count()
                });
                let output = request
                    .map(|i| format!("GET {}\r\n", self.requests[i]).into_bytes())
                    .unwrap_or_default();
                self.streams.push(HqStream {
                    child,
                    output,
                    sent: 0,
                    credit: 0,
                    finish: request.is_some(),
                    finished: false,
                    input: Vec::new(),
                    ended: false,
                    request,
                });
            }
            MuxEvent::Credit(id, n) => {
                if let Some(stream) = self.streams.iter_mut().find(|s| s.child.id() == id) {
                    stream.credit += n;
                }
            }
            MuxEvent::Child(id, StreamEvent::Data(bytes)) => {
                let stream = self
                    .streams
                    .iter_mut()
                    .find(|s| s.child.id() == id)
                    .unwrap();
                assert!(!stream.ended, "no bytes follow FIN");
                stream.input.extend_from_slice(&bytes);
                self.outbox.push(stream.child.grant(bytes.len() as u64));
            }
            MuxEvent::Child(id, StreamEvent::Ended) => {
                let stream = self
                    .streams
                    .iter_mut()
                    .find(|s| s.child.id() == id)
                    .unwrap();
                assert!(!stream.ended, "FIN arrives once");
                stream.ended = true;
                match stream.request {
                    Some(i) => self.responses[i] = Some(std::mem::take(&mut stream.input)),
                    None => {
                        let request = std::str::from_utf8(&stream.input).unwrap();
                        let path = request
                            .strip_prefix("GET ")
                            .and_then(|rest| rest.strip_suffix("\r\n"))
                            .expect("an hq-interop request");
                        stream.output = self.files[path].clone();
                        stream.finish = true;
                    }
                }
            }
            MuxEvent::Child(_, StreamEvent::ReceiveReset(_) | StreamEvent::SendStopped(_)) => {
                panic!("an hq-interop stream was cancelled")
            }
            _ => {}
        }
    }

    /// Queue each stream's next write within its credit, and its FIN
    fn write(&mut self, budget: &Budget) {
        for stream in &mut self.streams {
            if stream.sent < stream.output.len() && stream.credit > 0 {
                let n = (stream.output.len() - stream.sent)
                    .min(stream.credit as usize)
                    .min(16 << 10);
                let bytes =
                    Chunk::copy_of(budget, &stream.output[stream.sent..stream.sent + n]).unwrap();
                self.outbox
                    .push(stream.child.send(StreamCommand::Write(bytes)));
                stream.sent += n;
                stream.credit -= n as u64;
            }
            if stream.finish && !stream.finished && stream.sent == stream.output.len() {
                self.outbox.push(stream.child.send(StreamCommand::End));
                stream.finished = true;
            }
        }
    }

    /// A client's responses, once all are complete
    pub fn responses(&self) -> Option<Vec<Vec<u8>>> {
        self.responses.iter().cloned().collect()
    }
}

/// An SDK endpoint running hq-interop
pub struct SdkHq {
    pub sdk: Sdk<QuicLayer>,
    pub app: Hq,
}

impl SdkHq {
    fn new(side: Side, versions: Versions<'_>, validation: AddressValidation, seed: u64) -> Self {
        let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(seed)));
        let (client, server, endpoint) = configs(entropy.clone(), b"hq-interop", versions);
        let budget = Budget::new(64 << 20);
        let mut observations = Observations::new(0);
        let mut env = Env::new(Instant::ZERO, entropy.as_ref(), &budget, &mut observations);
        let (server, remote) = match side {
            Side::Client => (None, SERVER),
            Side::Server => (Some(server), CLIENT),
        };
        let mut quic = layer(&mut env, endpoint, server, validation);
        if side == Side::Client {
            quic.connect(&mut env, client, SERVER.parse().unwrap(), "localhost")
                .unwrap();
        }
        Self {
            sdk: Sdk {
                driver: Driver::new(quic, entropy, budget, Instant::ZERO),
                remote: remote.parse().unwrap(),
            },
            app: Hq::new(side),
        }
    }

    /// A client fetching `paths`
    pub fn client(versions: Versions<'_>, paths: &[String], seed: u64) -> Self {
        let mut this = Self::new(Side::Client, versions, AddressValidation::Accept, seed);
        this.app.requests = paths.to_vec();
        this.app.responses = vec![None; paths.len()];
        this
    }

    /// A server with `files`
    pub fn server(
        versions: Versions<'_>,
        validation: AddressValidation,
        files: &BTreeMap<String, Vec<u8>>,
        seed: u64,
    ) -> Self {
        let mut this = Self::new(Side::Server, versions, validation, seed);
        this.app.files = files.clone();
        this
    }

    /// Close the connection with application error 0
    pub fn close(&mut self) {
        if !self.app.closing {
            self.app.closing = true;
            self.app
                .outbox
                .push(MuxCommand::control(ControlCommand::Close(0u32.into())));
        }
    }
}

impl Endpoint for SdkHq {
    fn receive(&mut self, datagram: &[u8], now: Duration) {
        self.sdk.receive(datagram, now);
    }

    fn transmit(&mut self, now: Duration) -> Option<Vec<u8>> {
        self.sdk.driver.set_now(Instant::from_since_start(now));
        loop {
            let mut moved = self.sdk.driver.run().unwrap();
            while let Some(event) = self.sdk.driver.layer_mut().take_event() {
                self.app.event(event);
                moved = true;
            }
            self.app.write(self.sdk.driver.budget());
            moved |= self.app.outbox.flush(&mut self.sdk.driver);
            if let Some(datagram) = self.sdk.take() {
                return Some(datagram);
            }
            if !moved {
                return None;
            }
        }
    }

    fn timer(&self) -> Option<Duration> {
        self.sdk.timer()
    }

    fn version(&self) -> Option<u32> {
        self.sdk.driver.layer().version()
    }
}

struct Files(BTreeMap<String, Vec<u8>>);

impl httpd::Handler for Files {
    fn call(&self, request: web::Request, _: &mut httpd::Exchange<'_>) -> httpd::Reply {
        let body = self
            .0
            .get(request.head.path())
            .map(|bytes| httpd::Body::Full(Chunk::unpaid(bytes.clone())))
            .expect("a known path");
        httpd::Reply::Now(web::Response::new(body))
    }
}

type H3Stack = Chain<QuicLayer, httpd::Http3Server>;

/// The SDK's HTTP/3 server over its QUIC layer, serving `files`
pub struct SdkH3 {
    sdk: Sdk<H3Stack>,
    worker: Polling<<H3Stack as Layer>::Work>,
}

impl SdkH3 {
    pub fn server(versions: Versions<'_>, files: &BTreeMap<String, Vec<u8>>, seed: u64) -> Self {
        let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(seed)));
        let (_, server, endpoint) = configs(entropy.clone(), b"h3", versions);
        let budget = Budget::new(64 << 20);
        let mut observations = Observations::new(0);
        let mut env = Env::new(Instant::ZERO, entropy.as_ref(), &budget, &mut observations);
        let quic = layer(&mut env, endpoint, Some(server), AddressValidation::Accept);
        let responder = httpd::Responder::new(Files(files.clone()));
        Self {
            sdk: Sdk {
                driver: Driver::new(
                    Chain::new(quic, responder.http3()),
                    entropy,
                    budget,
                    Instant::ZERO,
                ),
                remote: CLIENT.parse().unwrap(),
            },
            worker: Polling::new(),
        }
    }
}

impl Endpoint for SdkH3 {
    fn receive(&mut self, datagram: &[u8], now: Duration) {
        self.sdk.receive(datagram, now);
    }

    fn transmit(&mut self, now: Duration) -> Option<Vec<u8>> {
        self.sdk.driver.set_now(Instant::from_since_start(now));
        loop {
            let mut moved = self.sdk.driver.run().unwrap();
            moved |= self.worker.work(&mut self.sdk.driver).unwrap();
            if let Some(datagram) = self.sdk.take() {
                return Some(datagram);
            }
            if !moved {
                return None;
            }
        }
    }

    fn timer(&self) -> Option<Duration> {
        self.sdk.timer()
    }

    fn version(&self) -> Option<u32> {
        self.sdk.driver.layer().lower().version()
    }
}
