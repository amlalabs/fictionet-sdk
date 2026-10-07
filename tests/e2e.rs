//! End to end, in one process: two machines joined by a router, each built
//! from stdlib parts. The server is `split_protocols` + `tcp::endpoint` +
//! `tls::server`. The client is `split_protocols` + `tcp::endpoint` + a
//! rustls client. Every byte crosses as IP packets through both splits, the
//! router and a delayed link.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use fictionet::prelude::*;
use fictionet::stdlib::tls::{self, ServerConfig};
use fictionet::stdlib::{ConnError, Connection, delay, ip, route, tcp};
use fictionet::{Cx, Interface, Packet, RecvError, block_on, pair, run};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

/// Runs `f` on its own thread and fails the test if it takes longer than
/// `limit`, instead of hanging.
fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit).expect("timed out")
}

/// The world returns this error once the test is done, which cancels the
/// endpoints, router and splits, so the run ends.
#[derive(Debug)]
struct Done;
impl std::fmt::Display for Done {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("done")
    }
}
impl std::error::Error for Done {}

fn world<F, Fut>(limit: Duration, f: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    let result = within(limit, move || {
        block_on(run(move |fcx| async move {
            f(fcx).await?;
            Err(fictionet::Error::from(Done))
        }))
    });
    match result {
        Err(e) if e.downcast_ref::<Done>().is_some() => {}
        Err(e) => panic!("the world failed: {e}"),
        Ok(()) => panic!("the world should end with Done"),
    }
}

// ---------------------------------------------------------------------------
// A rustls client over any Connection.

#[derive(Debug)]
#[allow(dead_code)] // The fields show in failure messages.
enum ClientError {
    Conn(ConnError),
    Tls(rustls::Error),
    Truncated,
}

impl From<ConnError> for ClientError {
    fn from(e: ConnError) -> Self {
        ClientError::Conn(e)
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ClientError {}

struct Client<C> {
    conn: C,
    tls: ClientConnection,
}

impl<C: Connection> Client<C> {
    async fn connect(fcx: &Cx, conn: C, config: Arc<ClientConfig>, name: &str) -> Result<Self, ClientError> {
        let name = ServerName::try_from(name.to_owned()).unwrap();
        let tls = ClientConnection::new(config, name).unwrap();
        let mut c = Client { conn, tls };
        while c.tls.is_handshaking() {
            c.flush(fcx).await?;
            if !c.tls.is_handshaking() {
                break;
            }
            c.read_more(fcx).await?;
        }
        c.flush(fcx).await?;
        Ok(c)
    }

    async fn flush(&mut self, fcx: &Cx) -> Result<(), ClientError> {
        while self.tls.wants_write() {
            let mut out = Vec::new();
            self.tls.write_tls(&mut out).unwrap();
            self.conn.write_all(fcx, &out).await?;
        }
        Ok(())
    }

    async fn read_more(&mut self, fcx: &Cx) -> Result<(), ClientError> {
        let mut buf = vec![0; 16 * 1024];
        let n = self.conn.read(fcx, &mut buf).await?;
        if n == 0 && self.tls.is_handshaking() {
            return Err(ClientError::Truncated);
        }
        let mut data = &buf[..n];
        loop {
            self.tls.read_tls(&mut data).unwrap();
            let r = self.tls.process_new_packets();
            let _ = self.flush(fcx).await;
            r.map_err(ClientError::Tls)?;
            if data.is_empty() {
                return Ok(());
            }
        }
    }

    /// Reads application data. `Ok(0)` is the server's close_notify.
    async fn read(&mut self, fcx: &Cx, buf: &mut [u8]) -> Result<usize, ClientError> {
        loop {
            match self.tls.reader().read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => self.read_more(fcx).await?,
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Err(ClientError::Truncated),
                Err(e) => panic!("{e}"),
            }
        }
    }

    async fn write_all(&mut self, fcx: &Cx, mut data: &[u8]) -> Result<(), ClientError> {
        while !data.is_empty() {
            let n = self.tls.writer().write(&data[..data.len().min(16 * 1024)]).unwrap();
            data = &data[n..];
            self.flush(fcx).await?;
        }
        Ok(())
    }

    /// Sends close_notify and a FIN. Reading still works.
    async fn close(&mut self, fcx: &Cx) -> Result<(), ClientError> {
        self.tls.send_close_notify();
        self.flush(fcx).await?;
        self.conn.shutdown(fcx).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Certificates: a world CA and a leaf for the server.

struct Certs {
    roots: RootCertStore,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn certs(name: &str) -> Certs {
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca.self_signed(&ca_key).unwrap();
    let mut leaf = CertificateParams::new(vec![name.to_owned()]).unwrap();
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    Certs {
        roots,
        chain: vec![leaf.der().clone()],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    }
}

fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The test.

const NAME: &str = "wiki.test";
const UP: usize = 1024 * 1024;
const DOWN: usize = 2 * 1024 * 1024;

/// One machine: its cable split by protocol, and a TCP endpoint on the TCP
/// end. Pings and UDP are left unanswered.
fn machine(fcx: &Cx, cable: impl Interface, addr: IpAddr) -> tcp::Endpoint {
    let (tcp, _udp, _icmp, _other) = ip::split_protocols(fcx, cable);
    tcp::endpoint(fcx, tcp, addr)
}

fn https_through_a_router(server_addr: &str, client_addr: &str, server_prefix: &str, client_prefix: &str) {
    let server_ip: IpAddr = server_addr.parse().unwrap();
    let client_ip: IpAddr = client_addr.parse().unwrap();
    let server_prefix: route::Prefix = server_prefix.parse().unwrap();
    let client_prefix: route::Prefix = client_prefix.parse().unwrap();
    world(Duration::from_secs(60), move |fcx| async move {
        let certs = certs(NAME);

        // Two cables into the router. The client's link has 5 ms of delay
        // each way.
        let (router_to_server, server_cable) = pair();
        let (router_to_client, client_cable) = pair();
        let client_cable = delay(&fcx, Duration::from_millis(5), client_cable);
        let _router = route::router(
            &fcx,
            vec![
                (server_prefix, Box::new(router_to_server) as Box<dyn Interface>),
                (client_prefix, Box::new(router_to_client)),
            ],
        );
        let server = machine(&fcx, server_cable, server_ip);
        let client = machine(&fcx, client_cable, client_ip);

        let mut config = tls::config_builder(&fcx, SystemTime::now(), rustls::crypto::ring::default_provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs.chain, certs.key)?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config: Arc<ServerConfig> = Arc::new(config);

        let mut listener = server.listen(443)?;
        let served = fcx.spawn(move |fcx| async move {
            let conn = listener.accept(&fcx).await?;
            assert_eq!(conn.peer_addr().ip(), client_ip);
            let hello = tls::server(&fcx, conn).await?;
            assert_eq!(hello.server_name(), Some(NAME));
            let mut conn = hello.finish(&fcx, config).await?;
            assert_eq!(conn.alpn(), Some(&b"http/1.1"[..]));
            assert_eq!(conn.inner().local_addr(), SocketAddr::new(server_ip, 443));
            // Read the whole upload, up to the client's close_notify.
            let mut got = Vec::new();
            let mut buf = vec![0; 64 * 1024];
            loop {
                let n = conn.read(&fcx, &mut buf).await?;
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert!(got == pattern(UP, 1), "the upload arrived changed ({} bytes)", got.len());
            conn.write_all(&fcx, &pattern(DOWN, 2)).await?;
            conn.shutdown(&fcx).await?;
            Ok(())
        });

        let mut client_config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(certs.roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let conn = client.connect(&fcx, SocketAddr::new(server_ip, 443)).await?;
        assert_eq!(conn.local_addr().ip(), client_ip);
        let mut tls = Client::connect(&fcx, conn, Arc::new(client_config), NAME).await?;
        assert_eq!(tls.tls.alpn_protocol(), Some(&b"http/1.1"[..]));
        tls.write_all(&fcx, &pattern(UP, 1)).await?;
        tls.close(&fcx).await?;
        let mut got = Vec::new();
        let mut buf = vec![0; 64 * 1024];
        loop {
            let n = tls.read(&fcx, &mut buf).await?;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert!(got == pattern(DOWN, 2), "the download arrived changed ({} bytes)", got.len());
        served.join(&fcx).await?;
        Ok(())
    });
}

#[test]
fn https_through_a_router_v4() {
    https_through_a_router("10.0.0.1", "10.0.0.2", "10.0.0.1/32", "10.0.0.0/24");
}

#[test]
fn https_through_a_router_v6() {
    https_through_a_router("fd00::1", "fd00::2", "fd00::1/128", "fd00::/64");
}

// ---------------------------------------------------------------------------
// ACK pacing.

/// Counts the TCP segments that cross a cable, by direction, and whether
/// they carry data.
struct Count<I> {
    inner: I,
    counts: Arc<Mutex<[usize; 4]>>,
}

fn carries_data(p: &[u8]) -> bool {
    let ihl = ((p[0] & 0x0f) as usize) * 4;
    let total = u16::from_be_bytes([p[2], p[3]]) as usize;
    total > ihl + ((p[ihl + 12] >> 4) as usize) * 4
}

impl<I: Interface> Interface for Count<I> {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        let r = self.inner.poll_recv(fcx, cx);
        if let Poll::Ready(Ok(p)) = &r {
            self.counts.lock().unwrap()[carries_data(&p.0) as usize] += 1;
        }
        r
    }

    fn send(&mut self, p: Packet) {
        self.counts.lock().unwrap()[2 + carries_data(&p.0) as usize] += 1;
        self.inner.send(p)
    }
}

/// A receiver that gets a window of data in one go still ACKs about every
/// second segment, as a kernel does. One ACK per window would make the
/// sender's slow start grow by one segment per round trip, which made a
/// 2 MiB transfer over a 2 ms round trip take 50 round trips.
#[test]
fn a_receiver_acks_every_second_segment() {
    let counts = Arc::new(Mutex::new([0usize; 4]));
    let seen = counts.clone();
    world(Duration::from_secs(60), move |fcx| async move {
        let (a, b) = pair();
        let b = delay(&fcx, Duration::from_millis(5), b);
        let b = Count { inner: b, counts: seen };
        let sender = tcp::endpoint(&fcx, a, "10.0.0.1".parse().unwrap());
        let receiver = tcp::endpoint(&fcx, b, "10.0.0.2".parse().unwrap());
        let mut listener = sender.listen(80)?;
        let sent = fcx.spawn(move |fcx| async move {
            let mut conn = listener.accept(&fcx).await?;
            conn.write_all(&fcx, &pattern(DOWN, 3)).await?;
            conn.shutdown(&fcx).await?;
            let mut buf = [0; 1];
            let _ = conn.read(&fcx, &mut buf).await;
            Ok(())
        });
        let mut conn = receiver.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
        let mut got = 0;
        let mut buf = vec![0; 64 * 1024];
        loop {
            let n = conn.read(&fcx, &mut buf).await?;
            if n == 0 {
                break;
            }
            got += n;
        }
        assert_eq!(got, DOWN);
        drop(conn);
        sent.join(&fcx).await?;
        Ok(())
    });
    // [received without data, received with data, sent without, sent with]
    let [_, data_in, acks_out, _] = *counts.lock().unwrap();
    assert!(data_in > 1000, "{data_in} data segments");
    assert!(acks_out * 3 >= data_in, "{acks_out} ACKs for {data_in} data segments");
}
