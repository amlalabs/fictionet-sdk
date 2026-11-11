//! HTTP/3 on UDP port 443 for the sites a [`Server`](super::Server) serves
//! over TLS, sharing the socket among the hosts at one address.

use std::any::Any;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::server::{ClientHello, ResolvesServerCert};

use fictionet::Cx;
use fictionet::stdlib::layer::{Budget, Closing, Datagrams};
use fictionet::stdlib::network::ConnInfo;
use fictionet::stdlib::protocols::http3::error_code as code;
use fictionet::stdlib::services::quic::{
    AddressValidation, EndpointConfig, Epoch, Listener, ListenerConfig, ServerConfig, VarInt,
};
use fictionet::stdlib::services::stack::Boxed;
use fictionet::stdlib::services::tls::{self, CertifiedKey};
use fictionet::stdlib::world::net::{DatagramServer, PreparedShare};

use super::sites::HTTP3_CONNECTIONS;
use super::{Handler, Limits, Observe, Responder, VHost, VirtualHosts};

/// Picks a site's certificate for one handshake, at once.
pub(super) type PickNow = Arc<dyn Fn(&Cx) -> Arc<CertifiedKey> + Send + Sync>;

/// What a connection may hold besides its request body: its streams,
/// packets in flight both ways and HTTP/3's own state.
const CONNECTION_EXTRA: usize = 16 << 20;

/// What the socket holds besides its connections: the endpoint's routing
/// tables, the connection slots, the TLS session store, and the datagram
/// being read and the one being answered.
fn socket_extra() -> usize {
    quinn_proto::Endpoint::reserved_bytes(HTTP3_CONNECTIONS) + (8 << 20)
}

/// The sites one UDP socket serves: their handlers by host, and their
/// certificates by name.
#[derive(Default)]
struct Sites {
    vhosts: VirtualHosts,
    certificates: HashMap<String, PickNow>,
}

/// HTTP/3 for the sites at one address, as [`Server::served_by`](super::Server::served_by)
/// installs it: the first host's serves the UDP socket, and later hosts at
/// the address add their sites to it.
#[derive(Clone)]
pub(super) struct Http3Sites {
    vhost: VHost,
    default_host: bool,
    pick: PickNow,
    limits: Limits,
    observe: Option<Observe>,
    date: Option<SystemTime>,
    sites: Arc<RwLock<HashMap<SocketAddr, Sites>>>,
}

impl Http3Sites {
    pub(super) fn new(
        vhost: VHost,
        default_host: bool,
        pick: PickNow,
        limits: Limits,
        observe: Option<Observe>,
        date: Option<SystemTime>,
    ) -> Http3Sites {
        Http3Sites {
            vhost,
            default_host,
            pick,
            limits,
            observe,
            date,
            sites: Arc::default(),
        }
    }

    /// The QUIC listener's configuration for the socket at `local`: TLS 1.3
    /// with `h3` only, certificates by SNI from the sites there, keys and
    /// time from the run.
    fn config(&self, fcx: &Cx, local: SocketAddr, budget: &Budget) -> ListenerConfig {
        let start = self.date.unwrap_or(UNIX_EPOCH);
        let mut crypto = tls::config_builder(fcx, start)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("the run's provider speaks TLS 1.3")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Certificates {
                fcx: fcx.clone(),
                provider: tls::crypto_provider(Arc::new(fcx.clone())),
                sites: self.sites.clone(),
                local,
            }));
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        crypto.session_storage =
            tls::session_store(budget).expect("a new socket's budget holds its session store");
        let crypto = quinn_proto::crypto::rustls::QuicServerConfig::try_from(crypto)
            .expect("TLS 1.3 offers QUIC's initial suite");
        let mut token_key = [0; 32];
        fcx.fill_random(&mut token_key);
        let mut server = ServerConfig::new(
            Arc::new(crypto),
            Arc::new(ring::hkdf::Prk::new_less_safe(
                ring::hkdf::HKDF_SHA256,
                &token_key,
            )),
        );
        let mut transport = quinn_proto::TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(VarInt::from_u32(self.limits.streams))
            // The client's control stream and its two QPACK streams.
            .max_concurrent_uni_streams(3u32.into())
            .stream_receive_window((1u32 << 20).into())
            .receive_window((4u32 << 20).into())
            .send_window(4 << 20)
            .datagram_receive_buffer_size(None);
        server
            .transport_config(Arc::new(transport))
            .time_source(Arc::new(WorldTime {
                fcx: fcx.clone(),
                start,
            }));
        let mut reset_key = [0; 32];
        fcx.fill_random(&mut reset_key);
        let endpoint = EndpointConfig::new(Arc::new(ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            &reset_key,
        )));
        ListenerConfig {
            endpoint: Arc::new(endpoint),
            server: Arc::new(server),
            connections: HTTP3_CONNECTIONS,
            // Requests, and three streams of each side's own.
            streams: self.limits.streams as usize + 6,
            connection_budget: connection_budget(&self.limits),
            validation: AddressValidation::Accept,
            cancel: |closing| {
                VarInt::from_u64(match closing {
                    Closing::Done => code::NO_ERROR,
                    Closing::Prohibited | Closing::ResourceShortage => code::EXCESSIVE_LOAD,
                    Closing::Failed => code::INTERNAL_ERROR,
                })
                .expect("HTTP/3 error codes are varints")
            },
        }
    }
}

/// What one HTTP/3 connection may hold: a request body as large as the
/// limits allow, and the rest of the connection besides.
fn connection_budget(limits: &Limits) -> usize {
    limits.body.saturating_add(CONNECTION_EXTRA)
}

impl DatagramServer for Http3Sites {
    fn stack(&self, fcx: &Cx, info: &ConnInfo) -> (Boxed<Datagrams<SocketAddr>>, Budget) {
        let local = info.local.expect("a bound socket has an address");
        let budget = Budget::new(
            HTTP3_CONNECTIONS
                .saturating_mul(connection_budget(&self.limits))
                .saturating_add(socket_extra()),
        );
        let vhosts = self
            .sites
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .entry(local)
            .or_default()
            .vhosts
            .clone();
        let handler: Arc<dyn Handler> = Arc::new(vhosts);
        let listener = Listener::new(self.config(fcx, local, &budget), Epoch::now(), Some(local));
        let stack = Responder::shared(handler)
            .limits(self.limits)
            .maybe_observe(self.observe.clone())
            .maybe_date(self.date)
            .http3_listener(listener);
        (Boxed::new(stack), budget)
    }

    fn prepare_share(
        &self,
        local: SocketAddr,
        names: &[String],
        other: &Arc<dyn DatagramServer>,
    ) -> Option<PreparedShare> {
        let other: &dyn Any = &**other;
        let site = other.downcast_ref::<Http3Sites>()?;
        let (vhost, default_host, pick) =
            (site.vhost.clone(), site.default_host, site.pick.clone());
        let names = names.to_vec();
        let sites = self.sites.clone();
        Some(PreparedShare::new(move || {
            let mut sites = sites.write().unwrap_or_else(|e| e.into_inner());
            let at = sites.entry(local).or_default();
            for name in names {
                at.vhosts.insert(&name, vhost.clone());
                at.certificates.insert(name, pick.clone());
            }
            if default_host {
                at.vhosts.set_default(vhost);
            }
        }))
    }
}

/// Each handshake's certificate, picked by the name the client asked for
/// among the sites at the socket's address. A name with no site there
/// aborts the handshake.
struct Certificates {
    fcx: Cx,
    provider: rustls::crypto::CryptoProvider,
    sites: Arc<RwLock<HashMap<SocketAddr, Sites>>>,
    local: SocketAddr,
}

impl std::fmt::Debug for Certificates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificates")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for Certificates {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = hello
            .server_name()?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let pick = self
            .sites
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&self.local)?
            .certificates
            .get(&name)?
            .clone();
        let certificate = pick(&self.fcx);
        rustls::sign::CertifiedKey::from_der(
            certificate.chain.clone(),
            certificate.key.clone_key(),
            &self.provider,
        )
        .ok()
        .map(Arc::new)
    }
}

/// The world's date for QUIC's address tokens: its date at the start of
/// the run plus the run's clock.
struct WorldTime {
    fcx: Cx,
    start: SystemTime,
}

impl quinn_proto::TimeSource for WorldTime {
    fn now(&self) -> SystemTime {
        self.start + self.fcx.now().since_start()
    }
}
