//! Issue host certificates using the world clock and its certificate authority.

use fictionet::{Cx, stdlib::services::tls::ServerConfig};
use std::{path::Path, sync::Arc, time::SystemTime};

/// The world's certificate authority, which signs a certificate for each
/// host at its first handshake.
pub struct Ca {
    issuer: fictionet::stdlib::services::ca::Ca,
    start: SystemTime,
}

impl Ca {
    /// Makes a seeded CA and writes its public certificate for the agent.
    pub fn new(fcx: &Cx, dir: &Path, start: SystemTime) -> fictionet::Result<Ca> {
        let ca = Self::in_memory(fcx, start)?;
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("ca.pem"), ca.cert_pem())?;
        Ok(ca)
    }

    /// Makes a seeded CA without writing files, for an in-process world.
    pub fn in_memory(fcx: &Cx, start: SystemTime) -> fictionet::Result<Ca> {
        Ok(Ca {
            issuer: fictionet::stdlib::services::ca::Ca::new(fcx, "Internet Security Root CA")?,
            start,
        })
    }

    /// Returns the public root certificate in PEM format for a guest to trust.
    pub fn cert_pem(&self) -> String {
        self.issuer.cert_pem()
    }

    /// A certificate for `host`: the host as CN and SAN, for server auth,
    /// issued 30 days before the world's date. The chain sent is the leaf,
    /// then the CA. Returns the TLS config and the validity, for the log.
    ///
    /// A client checks the certificate against its own clock, which is the
    /// host's, not the world's. So the validity covers both: it starts 30
    /// days before the earlier of the two, and lasts 90 days, or longer if
    /// that would end within 30 days of the later one.
    pub fn config(
        &self,
        fcx: &Cx,
        host: &str,
    ) -> fictionet::Result<(Arc<ServerConfig>, String, String)> {
        let world_now = time::OffsetDateTime::from(self.start + fcx.now().since_start());
        let host_now = time::OffsetDateTime::now_utc();
        let not_before = world_now.min(host_now) - time::Duration::days(30);
        let not_after = (not_before + time::Duration::days(90))
            .max(world_now.max(host_now) + time::Duration::days(30));
        let leaf = self.issuer.issue(
            fcx,
            &[host],
            fictionet::stdlib::protocols::x509::Validity {
                not_before: fictionet::stdlib::protocols::x509::Time::from_unix(
                    not_before.unix_timestamp(),
                )?,
                not_after: fictionet::stdlib::protocols::x509::Time::from_unix(
                    not_after.unix_timestamp(),
                )?,
            },
        )?;
        let config = leaf.server_config(fcx, self.start)?;
        let day = |t: time::OffsetDateTime| {
            format!("{:04}-{:02}-{:02}", t.year(), t.month() as u8, t.day())
        };
        Ok((config, day(not_before), day(not_after)))
    }
}
