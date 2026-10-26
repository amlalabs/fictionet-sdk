//! Issue host certificates using the world clock and its certificate authority.

use fictionet::{Cx, stdlib::services::tls::ServerConfig};
use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex, OnceLock},
    time::SystemTime,
};

/// The world's certificate authority, which signs a certificate for each
/// host at its first handshake.
pub struct Ca {
    pub(super) issuer: fictionet_extras::zscaler::Zscaler,
    pub(super) start: SystemTime,
    /// The earliest time the guest's clock may read during the run: copied
    /// pages put it back to the day they were copied.
    earliest: SystemTime,
    /// A chain the guest does not trust, for hosts whose real certificate
    /// no browser trusts.
    untrusted: OnceLock<fictionet_extras::zscaler::Zscaler>,
}

impl Ca {
    /// A CA under the kept `roots`, whose guest trusts their root, with a
    /// seeded issuing CA and certificates that hold from `earliest` as well
    /// as from `start`, for a guest whose clock reads `earliest` during the
    /// run.
    pub fn new(
        fcx: &Cx,
        roots: &fictionet_extras::zscaler::Roots,
        earliest: SystemTime,
        start: SystemTime,
    ) -> fictionet::Result<Ca> {
        let unix = |at: SystemTime| time::OffsetDateTime::from(at).unix_timestamp();
        Ok(Ca {
            issuer: fictionet_extras::zscaler::zscaler_since(
                fcx,
                roots,
                unix(earliest),
                unix(start),
            )?,
            start,
            earliest,
            untrusted: OnceLock::new(),
        })
    }

    fn world_now(&self, fcx: &Cx) -> time::OffsetDateTime {
        time::OffsetDateTime::from(self.start + fcx.now().since_start())
    }

    /// Issues the site's Zscaler chain against the run clock.
    pub fn config(
        &self,
        fcx: &Cx,
        host: &str,
    ) -> fictionet::Result<(Arc<ServerConfig>, String, String)> {
        let world_now = self.world_now(fcx);
        let earliest = time::OffsetDateTime::from(self.earliest).min(world_now);
        let leaf = self.issuer.issue_since(
            fcx,
            &[host],
            earliest.unix_timestamp(),
            world_now.unix_timestamp(),
        )?;
        let config = leaf.server_config(fcx, self.start)?;
        let day = |t: time::OffsetDateTime| {
            format!("{:04}-{:02}-{:02}", t.year(), t.month() as u8, t.day())
        };
        Ok((
            config,
            day(earliest - time::Duration::days(1)),
            day(world_now + time::Duration::days(395)),
        ))
    }

    /// A chain for `host` that fails verification the way the real host's
    /// does: expired or not yet valid on the same day, issued for the names
    /// the real certificate names, or from an issuer the guest does not
    /// trust.
    pub fn refused(
        &self,
        fcx: &Cx,
        host: &str,
        refusal: &Refusal,
    ) -> fictionet::Result<Arc<ServerConfig>> {
        const YEAR: i64 = 395 * 86_400;
        let now = self.world_now(fcx).unix_timestamp();
        let leaf = match refusal {
            // A leaf's window runs from a day before its issue to 395 days after.
            Refusal::Expired { not_after } => self.issuer.issue(fcx, &[host], not_after - YEAR)?,
            Refusal::NotYetValid { not_before } => {
                self.issuer.issue(fcx, &[host], not_before + 86_400)?
            }
            Refusal::WrongName { presented } => {
                let names: Vec<&str> = presented.iter().map(String::as_str).collect();
                self.issuer.issue(fcx, &names, now)?
            }
            Refusal::Untrusted => {
                let untrusted = match self.untrusted.get() {
                    Some(untrusted) => untrusted,
                    None => {
                        let made = fictionet_extras::zscaler::zscaler(
                            fcx,
                            fictionet_extras::zscaler::DEFAULT_CLOUD,
                            now,
                        )?;
                        self.untrusted.get_or_init(|| made)
                    }
                };
                untrusted.issue(fcx, &[host], now)?
            }
        };
        leaf.server_config(fcx, self.start)
    }
}

/// How a real host's certificate fails a browser's verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Past its `notAfter`, in Unix seconds.
    Expired { not_after: i64 },
    /// Before its `notBefore`, in Unix seconds.
    NotYetValid { not_before: i64 },
    /// Issued for other names.
    WrongName { presented: Vec<String> },
    /// Not issued by a trusted root.
    Untrusted,
}

/// What the real hosts' TLS handshakes showed, one check per host.
#[derive(Default)]
pub struct Upstream {
    checks: Mutex<HashMap<String, Arc<Check>>>,
}

#[derive(Default)]
struct Check {
    verdict: Mutex<Option<Option<Refusal>>>,
    done: Condvar,
}

impl Upstream {
    /// Starts checking `host`'s real certificate, unless a check started.
    pub fn start(&self, host: &str) {
        self.check(host);
    }

    fn check(&self, host: &str) -> Arc<Check> {
        let mut checks = self.checks.lock().unwrap();
        if let Some(check) = checks.get(host) {
            return check.clone();
        }
        let check = Arc::new(Check::default());
        checks.insert(host.to_owned(), check.clone());
        let (running, host) = (check.clone(), host.to_owned());
        std::thread::spawn(move || {
            let verdict = verify(&host);
            *running.verdict.lock().unwrap() = Some(verdict);
            running.done.notify_all();
        });
        check
    }

    /// How `host`'s real certificate fails verification, once its check
    /// ends; `None` when it verifies or the host cannot be reached.
    pub fn refusal(&self, host: &str) -> Option<Refusal> {
        let check = self.check(host);
        let mut verdict = check.verdict.lock().unwrap();
        while verdict.is_none() {
            verdict = check.done.wait(verdict).unwrap();
        }
        verdict.clone().flatten()
    }
}

/// Shakes hands with the real `host` on port 443 as a browser would, with
/// the Mozilla roots.
fn verify(host: &str) -> Option<Refusal> {
    use rustls::{CertificateError, Error};
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .ok()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_owned()).ok()?;
    let mut connection = rustls::ClientConnection::new(Arc::new(config), name).ok()?;
    let mut socket = std::net::TcpStream::connect((host, 443)).ok()?;
    while connection.is_handshaking() {
        let Err(error) = connection.complete_io(&mut socket) else {
            continue;
        };
        let Some(Error::InvalidCertificate(certificate)) = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<Error>())
        else {
            return None;
        };
        let seconds = |time: &rustls::pki_types::UnixTime| time.as_secs() as i64;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs() as i64);
        return Some(match certificate {
            CertificateError::ExpiredContext { not_after, .. } => Refusal::Expired {
                not_after: seconds(not_after),
            },
            CertificateError::Expired => Refusal::Expired {
                not_after: now - 86_400,
            },
            CertificateError::NotValidYetContext { not_before, .. } => Refusal::NotYetValid {
                not_before: seconds(not_before),
            },
            CertificateError::NotValidYet => Refusal::NotYetValid {
                not_before: now + 86_400,
            },
            CertificateError::NotValidForNameContext { presented, .. } if !presented.is_empty() => {
                Refusal::WrongName {
                    presented: presented.clone(),
                }
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                Refusal::WrongName {
                    presented: vec![format!("invalid.{host}")],
                }
            }
            _ => Refusal::Untrusted,
        });
    }
    None
}
