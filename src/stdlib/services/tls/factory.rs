use fictionet::sync::Mutex;
use std::collections::VecDeque;
use std::sync::{Arc, Weak};

use fictionet::Cx;
use fictionet::stdlib::layer::{Budget, ByteStream, Layer, Side};
use fictionet::stdlib::network::ConnInfo;
use fictionet::stdlib::services::stack::{BoxError, Boxed, Job};
use fictionet::time::Instant;

use super::{HandshakeError, Secure, TlsLayer};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::future::Future;
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

/// Authoritative negotiation state. Failure must remain failure even after
/// an implementation has handed its error to the driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handshake<'a> {
    /// No application may be constructed yet.
    Pending,
    /// The authenticated stream is ready for its application.
    Established {
        /// The name requested by the peer, if present.
        server_name: Option<&'a str>,
        /// The application protocol agreed with the peer, if present.
        alpn: Option<&'a [u8]>,
    },
    /// Negotiation failed; no application may be constructed.
    Failed,
}

/// A replaceable TLS stream layer. Metadata is authoritative only once
/// established. Implementations retain plaintext until the upper layer
/// accepts it, and enforce the opening handshake deadline.
pub trait Negotiation: Layer<Lower = ByteStream, Upper = ByteStream> {
    /// Current handshake state and negotiated metadata.
    fn handshake(&self) -> Handshake<'_>;
}

/// Certificate material independent of the TLS implementation.
/// DER wrappers describe standard certificate and private-key encodings;
/// they contain no TLS engine configuration or signing implementation.
pub struct CertifiedKey {
    /// The leaf certificate followed by its issuing chain, in DER.
    pub chain: Vec<CertificateDer<'static>>,
    /// The private key in PKCS#1, PKCS#8, or SEC1 DER encoding.
    pub key: PrivateKeyDer<'static>,
}

/// The listener's selected certificate and application protocols.
pub struct Selected {
    /// Certificate material for the requested name.
    pub certificate: Arc<CertifiedKey>,
    /// Protocols offered by that name's application, in preference order.
    pub alpn: Vec<Vec<u8>>,
}

impl Selected {
    /// Builds a rustls configuration from the selected material. This is
    /// an adapter for rustls layers; another implementation reads the DER
    /// material directly. Clock and randomness come from the run. Its
    /// [`session_store`](super::session_store) is paid for from `sessions`,
    /// the budget of whatever keeps the configuration, once; fails with
    /// [`rustls::Error::BudgetExhausted`] if that has no room. The
    /// configuration bounds its handshake output
    /// ([`ServerConfig::most_connection`](super::ServerConfig::most_connection)),
    /// so a connection's handshake waits for memory and never fails for it.
    pub fn rustls_config(
        &self,
        cx: &Cx,
        start: SystemTime,
        sessions: &Budget,
    ) -> Result<super::ServerConfig, rustls::Error> {
        let mut config = super::config_builder(cx, start)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                self.certificate.chain.clone(),
                self.certificate.key.clone_key(),
            )?;
        config.alpn_protocols = self.alpn.clone();
        config.session_storage = super::session_store(sessions)?;
        Ok(config)
    }
}

/// An asynchronous certificate selection. `None` refuses the name.
/// Dropping the future cancels selection.
pub type Selecting = Pin<Box<dyn Future<Output = Option<Selected>> + Send>>;

/// Selects certificate material by the name in the client's hello.
pub type Selection = Arc<dyn Fn(Cx, Option<String>) -> Selecting + Send + Sync>;

/// What a TLS factory receives for one accepted connection, before
/// negotiation.
pub struct Opening {
    /// Runtime context, including deterministic entropy.
    pub cx: Cx,
    /// Connection identity before negotiation.
    pub info: ConnInfo,
    /// The connection's allocation budget.
    pub budget: Budget,
    /// Absolute deadline, including asynchronous certificate selection.
    pub deadline: Instant,
    /// The listener's per-name certificate selection. Invoke this with the
    /// client's requested name to use the world's certificates; application
    /// routing follows the name reported in `Handshake::Established`.
    pub select: Selection,
}

type Application = Box<dyn FnOnce(Handshake<'_>) -> Option<Boxed> + Send>;
type Make = dyn Fn(Opening, Application) -> Boxed + Send + Sync;

/// A listener's TLS implementation. The default composition is
/// `Chain<TlsLayer, Later<Boxed>>`, through [`Secure`]. Applications are
/// constructed only after successful negotiation, before plaintext delivery.
#[derive(Clone)]
pub struct Factory {
    make: Arc<Make>,
    error: fn(BoxError) -> HandshakeError,
}

// Engine configurations retain resumption state only for the same run,
// certificate object and protocol list. Expired material leaves the cache.
const CONFIG_CACHE_LIMIT: usize = 64;

struct CachedConfig {
    cx: Cx,
    certificate: Weak<CertifiedKey>,
    alpn: Vec<Vec<u8>>,
    config: Arc<super::ServerConfig>,
}

struct Configs {
    entries: VecDeque<CachedConfig>,
    /// What the configurations' session stores are paid from.
    sessions: Budget,
}

impl Configs {
    fn new(sessions: Budget) -> Self {
        Self {
            entries: VecDeque::new(),
            sessions,
        }
    }

    fn get(
        &mut self,
        cx: &Cx,
        selected: &Selected,
        start: SystemTime,
        configure: &dyn Fn(&mut super::ServerConfig),
    ) -> Result<Arc<super::ServerConfig>, rustls::Error> {
        self.entries
            .retain(|entry| !entry.cx.is_cancelled() && entry.certificate.strong_count() != 0);
        let certificate = Arc::downgrade(&selected.certificate);
        if let Some(index) = self.entries.iter().position(|entry| {
            Arc::ptr_eq(&entry.cx.run, &cx.run)
                && Weak::ptr_eq(&entry.certificate, &certificate)
                && entry.alpn == selected.alpn
        }) {
            let entry = self.entries.remove(index).expect("cache entry exists");
            let config = entry.config.clone();
            self.entries.push_back(entry);
            return Ok(config);
        }
        if self.entries.len() == CONFIG_CACHE_LIMIT {
            // Before the new one is paid for, so its store can use what
            // the oldest gives back.
            self.entries.pop_front();
        }
        let mut config = selected.rustls_config(cx, start, &self.sessions)?;
        configure(&mut config);
        let config = Arc::new(config);
        self.entries.push_back(CachedConfig {
            cx: cx.clone(),
            certificate,
            alpn: selected.alpn.clone(),
            config: config.clone(),
        });
        Ok(config)
    }
}

impl Factory {
    /// Uses `make` to construct a fresh replacement layer per connection.
    pub fn new<T>(make: impl Fn(Opening) -> T + Send + Sync + 'static) -> Self
    where
        T: Negotiation + Send + 'static,
        T::Report: core::fmt::Debug + Send + 'static,
        T::Work: Job<Done = T::Done>,
        T::Done: Send + 'static,
        T::Error: Into<BoxError> + core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    {
        Self {
            make: Arc::new(move |opening, application| {
                Boxed::new(Secure::new(make(opening), move |tls: &T| {
                    application(tls.handshake())
                }))
            }),
            error: |error| {
                let error = match error.downcast::<Side<T::Error, BoxError>>() {
                    Ok(error) => match *error {
                        Side::Lower(error) => error.into(),
                        Side::Upper(error) => error,
                    },
                    Err(error) => error,
                };
                match error.downcast::<HandshakeError>() {
                    Ok(error) => *error,
                    Err(error) => HandshakeError::Failed(error.to_string()),
                }
            },
        }
    }

    /// Uses the stdlib TLS layer with rustls settings chosen by `configure`.
    /// Certificates and ALPN still come from the listener's neutral selection.
    /// `start` is the world's date at the start of the run. Up to 64 recent
    /// configurations retain session resumption state, isolated by run,
    /// certificate identity and ALPN. Reuse the certificate's `Arc` to resume;
    /// changing material or protocols starts fresh session state. `configure`
    /// runs only when a configuration is built, not on cache hits. Eviction
    /// may cause a later connection to perform a full handshake. Each
    /// configuration's session store is paid for from `sessions` once, when
    /// it is built, so the sessions connections leave hold nothing they
    /// allocated; a configuration `sessions` has no room for is not built,
    /// and the name is refused.
    pub fn rustls(
        start: SystemTime,
        sessions: Budget,
        configure: impl Fn(&mut super::ServerConfig) + Send + Sync + 'static,
    ) -> Self {
        let configure = Arc::new(configure);
        let cache = Arc::new(Mutex::new(Configs::new(sessions)));
        Self::new(move |opening| {
            let (configure, cache) = (configure.clone(), cache.clone());
            TlsLayer::selecting(move |cx, hello| {
                let selected = (opening.select)(cx, hello.server_name().map(str::to_owned));
                let (configure, cache, cx) = (configure.clone(), cache.clone(), opening.cx.clone());
                async move {
                    let selected = selected.await?;
                    cache.lock().get(&cx, &selected, start, &*configure).ok()
                }
            })
            .handshake_by(opening.deadline)
        })
    }

    /// Converts an error from this factory's boxed stack for TLS observers.
    /// Standard handshake errors retain their classification; replacement
    /// errors of another type are reported as `HandshakeError::Failed`.
    pub fn handshake_error(&self, error: BoxError) -> HandshakeError {
        (self.error)(error)
    }

    /// Composes this listener's TLS with the negotiated application.
    /// Returning `None` refuses the authenticated stream and resets it.
    pub fn build(
        &self,
        opening: Opening,
        application: impl FnOnce(Handshake<'_>) -> Option<Boxed> + Send + 'static,
    ) -> Boxed {
        (self.make)(opening, Box::new(application))
    }
}

impl Default for Factory {
    /// Uses the run's clock relative to the Unix epoch, without client
    /// authentication. Resumption ticket lifetimes follow elapsed run time.
    /// Use [`Factory::rustls`] to set a world date for certificate validation.
    fn default() -> Self {
        Self::rustls(UNIX_EPOCH, Budget::unlimited(), |_| {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Wire;

    fn certificate(cx: &Cx) -> Arc<CertifiedKey> {
        use fictionet::stdlib::{protocols::x509, services::ca::Ca};
        Ca::new(cx, "Cache CA")
            .unwrap()
            .issue(
                cx,
                &["cache.example"],
                x509::Validity {
                    not_before: x509::Time::from_unix(1_700_000_000).unwrap(),
                    not_after: x509::Time::from_unix(2_000_000_000).unwrap(),
                },
            )
            .unwrap()
            .certified_key()
    }

    #[test]
    fn configurations_resume_only_with_the_same_material_and_protocols() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(92),
            |cx| async move {
                let mut cache = Configs::new(Budget::unlimited());
                let mut selected = Selected {
                    certificate: certificate(&cx),
                    alpn: vec![b"first".to_vec()],
                };
                let first = cache.get(&cx, &selected, UNIX_EPOCH, &|_| {})?;
                let reused = cache.get(&cx, &selected, UNIX_EPOCH, &|_| {
                    panic!("cached config rebuilt")
                })?;
                assert!(Arc::ptr_eq(&first, &reused));
                selected.alpn = vec![b"second".to_vec()];
                let changed = cache.get(&cx, &selected, UNIX_EPOCH, &|_| {})?;
                assert!(!Arc::ptr_eq(
                    &first.session_storage,
                    &changed.session_storage
                ));
                selected.alpn = vec![b"first".to_vec()];
                selected.certificate = Arc::new(CertifiedKey {
                    chain: selected.certificate.chain.clone(),
                    key: selected.certificate.key.clone_key(),
                });
                let rotated = cache.get(&cx, &selected, UNIX_EPOCH, &|_| {})?;
                assert!(!Arc::ptr_eq(
                    &first.session_storage,
                    &rotated.session_storage
                ));
                assert_eq!(
                    cache.entries.len(),
                    1,
                    "expired certificate entries leave the cache"
                );
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn configuration_cache_evicts_the_least_recently_used_entry() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(93),
            |cx| async move {
                let mut cache = Configs::new(Budget::unlimited());
                let mut selected = Selected {
                    certificate: certificate(&cx),
                    alpn: vec![vec![0]],
                };
                let oldest = cache.get(&cx, &selected, UNIX_EPOCH, &|_| {})?;
                selected.alpn = vec![vec![1]];
                let touched = cache.get(&cx, &selected, UNIX_EPOCH, &|_| {})?;
                for protocol in 2..=CONFIG_CACHE_LIMIT {
                    selected.alpn = vec![vec![protocol as u8]];
                    cache.get(&cx, &selected, UNIX_EPOCH, &|_| {})?;
                }
                assert_eq!(cache.entries.len(), CONFIG_CACHE_LIMIT);
                selected.alpn = vec![vec![1]];
                assert!(Arc::ptr_eq(
                    &touched,
                    &cache.get(&cx, &selected, UNIX_EPOCH, &|_| {})?
                ));
                selected.alpn = vec![vec![0]];
                assert!(!Arc::ptr_eq(
                    &oldest,
                    &cache.get(&cx, &selected, UNIX_EPOCH, &|_| {})?
                ));
                selected.alpn = vec![vec![1]];
                assert!(Arc::ptr_eq(
                    &touched,
                    &cache.get(&cx, &selected, UNIX_EPOCH, &|_| {})?
                ));
                assert_eq!(cache.entries.len(), CONFIG_CACHE_LIMIT);
                Ok(())
            },
        ))
        .unwrap();
    }

    /// A configuration's session store is charged to the cache's budget
    /// once, when the configuration is built, and given back when the last
    /// holder drops it; a budget without room for it builds nothing. The
    /// configuration bounds its handshake output.
    #[test]
    fn a_configurations_sessions_are_paid_once_by_its_keeper() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(96),
            |cx| async move {
                let store = super::super::SESSIONS
                    * (rustls::server::SLOT_KEY + rustls::server::SLOT_VALUE);
                let selected = Selected {
                    certificate: certificate(&cx),
                    alpn: vec![b"first".to_vec()],
                };

                let tight = Budget::new(store / 2);
                let mut cache = Configs::new(tight.clone());
                assert!(cache.get(&cx, &selected, UNIX_EPOCH, &|_| {}).is_err());
                assert_eq!(tight.used(), 0);

                let budget = Budget::new(4 * store);
                let mut cache = Configs::new(budget.clone());
                let config = cache.get(&cx, &selected, UNIX_EPOCH, &|_| {})?;
                let paid = budget.used();
                assert!(paid >= store);
                assert!(config.most_connection().is_some());
                cache.get(&cx, &selected, UNIX_EPOCH, &|_| {
                    panic!("cached config rebuilt")
                })?;
                assert_eq!(budget.used(), paid, "a hit pays again");
                drop(cache);
                assert_eq!(budget.used(), paid, "the config's holder still has it");
                drop(config);
                assert_eq!(budget.used(), 0);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn cached_configurations_do_not_cross_runs() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(94),
            |cx| async move {
                let mut cache = Configs::new(Budget::unlimited());
                let selected = Selected {
                    certificate: certificate(&cx),
                    alpn: Vec::new(),
                };
                let first = cache.get(&cx, &selected, UNIX_EPOCH, &|_| {})?;
                fictionet::lab(fictionet::Seed::from_u64(95), move |other| async move {
                    assert!(!cx.is_cancelled());
                    let second = cache.get(&other, &selected, UNIX_EPOCH, &|_| {})?;
                    assert!(!Arc::ptr_eq(&first, &second));
                    assert!(!Arc::ptr_eq(
                        &first.session_storage,
                        &second.session_storage
                    ));
                    Ok(())
                })
                .await
            },
        ))
        .unwrap();
    }

    #[test]
    fn selected_material_is_available_without_a_tls_engine_and_stays_immutable() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(91),
            |cx| async move {
                use fictionet::stdlib::protocols::x509;
                use fictionet::stdlib::services::ca::Ca;
                let ca = Ca::new(&cx, "Selection CA")?;
                let certificate = ca
                    .issue(
                        &cx,
                        &["selected.example"],
                        x509::Validity {
                            not_before: x509::Time::from_unix(1_700_000_000)?,
                            not_after: x509::Time::from_unix(2_000_000_000)?,
                        },
                    )?
                    .certified_key();
                let chain = certificate.chain.clone();
                let key = certificate.key.secret_der().to_vec();
                let selected = Selected {
                    certificate: certificate.clone(),
                    alpn: vec![b"example".to_vec()],
                };
                let parsed = x509::Certificate::parse(&selected.certificate.chain[0])?;
                assert_eq!(
                    parsed.tbs.issuer,
                    x509::Certificate::parse(&ca.cert_der())?.tbs.subject
                );
                let mut configured =
                    selected.rustls_config(&cx, UNIX_EPOCH, &Budget::unlimited())?;
                assert_eq!(configured.alpn_protocols, selected.alpn);
                configured.alpn_protocols.clear();
                assert_eq!(certificate.chain, chain);
                assert_eq!(certificate.key.secret_der(), key);
                assert!(!selected.alpn.is_empty());
                Ok(())
            },
        ))
        .unwrap();
    }
}
