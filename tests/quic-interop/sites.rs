// Sites a world serves with `httpd::Server::served_by`, fetched over
// HTTP/3 by independent quiche clients on a sandbox machine. Packets go
// through the world's IP and UDP layers to the site's UDP port 443. The
// worlds run on the real clock, which quiche's timers also read, so a
// client recovers from a lost packet in the time the world sees pass.

use super::*;
use std::net::IpAddr;

use fictionet::stdlib::services::ca::Ca;
use fictionet::stdlib::web::{self, httpd};
use fictionet::stdlib::world::net::{Host, Net, Pools};
use fictionet_test_support::{Done, certs::issue, ended_with_done, sandbox::machine, within};
use quiche::h3::NameValue;

/// A page that names its site and the path it was asked for.
struct Page(&'static str);

impl httpd::Handler for Page {
    fn call(&self, request: web::Request, _: &mut httpd::Exchange<'_>) -> httpd::Reply {
        assert_eq!(
            request.head.version(),
            stdlib::protocols::http1::Version::Http3
        );
        let body = format!("{} {}", self.0, request.head.path());
        httpd::Reply::Now(web::Response::new(body.into()))
    }
}

/// A quiche configuration for HTTP/3 that trusts `cas`, with room for
/// pages.
fn trusting(cas: &[&Ca]) -> quiche::Config {
    let dir = tempfile::tempdir().unwrap();
    let roots = dir.path().join("roots.pem");
    let pems: String = cas.iter().map(|ca| ca.cert_pem()).collect();
    std::fs::write(&roots, pems).unwrap();
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .load_verify_locations_from_file(roots.to_str().unwrap())
        .unwrap();
    config.verify_peer(true);
    config.set_application_protos(&[b"h3"]).unwrap();
    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(1472);
    config.set_max_send_udp_payload_size(1200);
    config.set_initial_max_data(1 << 20);
    config.set_initial_max_stream_data_bidi_local(1 << 18);
    config.set_initial_max_stream_data_bidi_remote(1 << 18);
    config.set_initial_max_stream_data_uni(1 << 18);
    config.set_initial_max_streams_bidi(16);
    config.set_initial_max_streams_uni(16);
    config.set_disable_active_migration(true);
    config
}

/// One GET over its own HTTP/3 connection.
struct Get {
    quic: quiche::Connection,
    http: Option<quiche::h3::Connection>,
    local: SocketAddr,
    server: SocketAddr,
    authority: String,
    path: String,
    stream: Option<u64>,
    status: Option<Vec<u8>>,
    alt_svc: Option<Vec<u8>>,
    body: Vec<u8>,
    done: bool,
}

impl Get {
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: &mut quiche::Config,
        number: u16,
        local: SocketAddr,
        server: SocketAddr,
        sni: &str,
        authority: &str,
        path: &str,
    ) -> Get {
        let mut id = [0x5a; 16];
        id[..2].copy_from_slice(&number.to_be_bytes());
        let id = quiche::ConnectionId::from_ref(&id);
        Get {
            quic: quiche::connect(Some(sni), &id, local, server, config).unwrap(),
            http: None,
            local,
            server,
            authority: authority.to_owned(),
            path: path.to_owned(),
            stream: None,
            status: None,
            alt_svc: None,
            body: Vec::new(),
            done: false,
        }
    }

    /// Whether it got its page, or its connection is over.
    fn finished(&self) -> bool {
        self.done || self.quic.is_closed() || self.quic.is_draining()
    }

    fn progress(&mut self) {
        if self.quic.is_closed() {
            return;
        }
        if self.quic.is_established() && self.http.is_none() {
            assert_eq!(self.quic.application_proto(), b"h3");
            self.http = Some(
                quiche::h3::Connection::with_transport(
                    &mut self.quic,
                    &quiche::h3::Config::new().unwrap(),
                )
                .unwrap(),
            );
        }
        let Some(h3) = &mut self.http else { return };
        if self.stream.is_none() {
            let headers = [
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", self.authority.as_bytes()),
                quiche::h3::Header::new(b":path", self.path.as_bytes()),
            ];
            self.stream = Some(h3.send_request(&mut self.quic, &headers, true).unwrap());
        }
        let mut buffer = [0; 65535];
        loop {
            match h3.poll(&mut self.quic) {
                Ok((_, quiche::h3::Event::Headers { list, .. })) => {
                    let field = |name: &[u8]| {
                        list.iter()
                            .find(|h| h.name() == name)
                            .map(|h| h.value().to_vec())
                    };
                    self.status = field(b":status");
                    self.alt_svc = field(b"alt-svc");
                }
                Ok((id, quiche::h3::Event::Data)) => {
                    while let Ok(n) = h3.recv_body(&mut self.quic, id, &mut buffer) {
                        self.body.extend_from_slice(&buffer[..n]);
                    }
                }
                Ok((_, quiche::h3::Event::Finished)) => self.done = true,
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(error) => panic!("HTTP/3: {error:?}"),
            }
        }
    }
}

/// Runs every GET to its end, or until its connection closes, over one
/// UDP socket of the client machine. Datagrams go to the GET whose
/// connection ID they name.
async fn fetch(
    fcx: &fictionet::Cx,
    socket: &mut stdlib::network::udp::Socket,
    gets: &mut [Get],
) -> fictionet::Result {
    let mut buffer = [0; 65535];
    let finish_by = fcx.now() + Duration::from_secs(45);
    loop {
        for get in gets.iter_mut() {
            get.progress();
            loop {
                match get.quic.send(&mut buffer) {
                    Ok((n, info)) => socket.send_to(&buffer[..n], info.to),
                    Err(quiche::Error::Done) => break,
                    Err(error) => panic!("client send: {error:?}"),
                }
            }
        }
        if gets.iter().all(Get::finished) {
            return Ok(());
        }
        assert!(
            fcx.now() < finish_by,
            "the GETs did not finish: {:?}",
            gets.iter()
                .map(|get| (
                    get.done,
                    get.quic.is_established(),
                    get.quic.peer_error(),
                    get.quic.local_error(),
                    get.quic.stats().recv,
                ))
                .collect::<Vec<_>>()
        );
        let timeout = gets
            .iter()
            .filter_map(|get| get.quic.timeout())
            .min()
            .unwrap_or(Duration::from_millis(100));
        match fcx
            .race(Some((fcx.now() + timeout).min(finish_by)), socket.recv(fcx))
            .await
        {
            Ok(packet) => {
                let (mut bytes, source) = packet?;
                let header = quiche::Header::from_slice(&mut bytes, 16).unwrap();
                if let Some(get) = gets
                    .iter_mut()
                    .find(|get| get.quic.source_ids().any(|id| *id == header.dcid))
                {
                    assert_eq!(source, get.server);
                    let to = get.local;
                    let _ = get
                        .quic
                        .recv(&mut bytes, quiche::RecvInfo { from: source, to });
                }
            }
            Err(fictionet::RaceError::Deadline) => {
                for get in gets.iter_mut() {
                    get.quic.on_timeout();
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
}

const CLIENT: &str = "10.0.0.2:4000";

/// Runs `world` on the real clock, as the quiche clients' timers are.
fn on_the_real_clock<F, Fut>(seed: u64, world: F)
where
    F: FnOnce(fictionet::Cx) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = fictionet::Result> + Send + 'static,
{
    within(Duration::from_secs(60), move || {
        ended_with_done(fictionet::block_on(fictionet::run(
            Seed::from_u64(seed),
            move |fcx| async move {
                world(fcx).await?;
                Err(fictionet::Error::from(Done))
            },
        )))
        .unwrap();
    });
}

#[test]
fn a_site_serves_http3_to_many_clients_at_once_on_udp_443() {
    on_the_real_clock(75, |fcx| async move {
        let site: IpAddr = "104.18.0.7".parse()?;
        let (ca, leaf) = issue(&fcx, "H3 CA", &["www.test"])?;
        let key = leaf.certified_key();
        let (attacher, attachments) = fictionet::attachments();
        Net::new(Pools::NONE)
            .ipv4_only()
            .add_host(
                httpd::Server::new(Page("www"))
                    .tls_with(move |_| key.clone())
                    .served_by(Host::new("www").dns_name("www.test").at(site)),
            )
            .start(&fcx, attachments)?;
        let client: SocketAddr = CLIENT.parse()?;
        let machine = machine(&fcx, attacher.attach("client")?, client.ip());
        let mut socket = machine.udp.bind(client.port())?;
        let mut config = trusting(&[&ca]);
        let server = SocketAddr::new(site, 443);
        let mut gets: Vec<Get> = (0..32)
            .map(|n| {
                Get::new(
                    &mut config,
                    n,
                    client,
                    server,
                    "www.test",
                    "www.test",
                    &format!("/{n}"),
                )
            })
            .collect();
        fetch(&fcx, &mut socket, &mut gets).await?;
        for (n, get) in gets.iter().enumerate() {
            assert!(get.done, "GET /{n}: {:?}", get.quic.peer_error());
            assert_eq!(get.status.as_deref(), Some(b"200".as_slice()));
            assert_eq!(get.body, format!("www /{n}").into_bytes());
        }
        Ok(())
    });
}

#[test]
fn sites_at_one_address_share_udp_443_each_with_its_own_certificate() {
    on_the_real_clock(76, |fcx| async move {
        let shared: IpAddr = "104.18.0.8".parse()?;
        let (ca_a, leaf_a) = issue(&fcx, "A CA", &["a.test"])?;
        let (ca_b, leaf_b) = issue(&fcx, "B CA", &["b.test"])?;
        let (key_a, key_b) = (leaf_a.certified_key(), leaf_b.certified_key());
        let (attacher, attachments) = fictionet::attachments();
        Net::new(Pools::NONE)
            .ipv4_only()
            .add_host(
                httpd::Server::new(Page("a"))
                    .tls_with(move |_| key_a.clone())
                    .served_by(Host::new("a").dns_name("a.test").at(shared)),
            )
            .add_host(
                httpd::Server::new(Page("b"))
                    .tls_with(move |_| key_b.clone())
                    .served_by(Host::new("b").dns_name("b.test").at(shared)),
            )
            .start(&fcx, attachments)?;
        let client: SocketAddr = CLIENT.parse()?;
        let machine = machine(&fcx, attacher.attach("client")?, client.ip());
        let mut socket = machine.udp.bind(client.port())?;
        let server = SocketAddr::new(shared, 443);
        // Each client trusts only its site's CA, so a handshake succeeds
        // only with that site's own certificate.
        let mut only_a = trusting(&[&ca_a]);
        let mut only_b = trusting(&[&ca_b]);
        let mut gets = vec![
            Get::new(&mut only_a, 1, client, server, "a.test", "a.test", "/x"),
            Get::new(&mut only_b, 2, client, server, "b.test", "b.test", "/y"),
            Get::new(&mut only_a, 3, client, server, "a.test", "a.test", "/z"),
            Get::new(&mut only_a, 4, client, server, "c.test", "c.test", "/"),
        ];
        fetch(&fcx, &mut socket, &mut gets).await?;
        for (get, body) in gets[..3].iter().zip(["a /x", "b /y", "a /z"]) {
            assert!(get.done, "{}: {:?}", get.authority, get.quic.peer_error());
            assert_eq!(get.status.as_deref(), Some(b"200".as_slice()));
            assert_eq!(get.body, body.as_bytes());
            // HTTP/3 responses advertise HTTP/3 as the others do.
            assert_eq!(
                get.alt_svc.as_deref(),
                Some(br#"h3=":443"; ma=86400"#.as_slice())
            );
        }
        // No site has the name: the handshake ends without a connection.
        assert!(!gets[3].quic.is_established());
        assert!(gets[3].quic.peer_error().is_some());
        Ok(())
    });
}
