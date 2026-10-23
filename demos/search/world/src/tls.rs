//! Issue host certificates using the world clock and its certificate authority.

use fictionet::{Cx, stdlib::services::tls::ServerConfig};
use std::{path::Path, sync::Arc, time::SystemTime};

/// The world's certificate authority, which signs a certificate for each
/// host at its first handshake.
pub struct Ca {
    pub(super) issuer: fictionet_extras::zscaler::Zscaler,
    pub(super) start: SystemTime,
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
            issuer: fictionet_extras::zscaler::zscaler(
                fcx,
                fictionet_extras::zscaler::DEFAULT_CLOUD,
                time::OffsetDateTime::from(start).unix_timestamp(),
            )?,
            start,
        })
    }

    /// Returns the public root certificate in PEM format for a guest to trust.
    pub fn cert_pem(&self) -> String {
        self.issuer.root_pem().to_owned()
    }

    /// Issues the site's Zscaler chain against the run clock.
    pub fn config(
        &self,
        fcx: &Cx,
        host: &str,
    ) -> fictionet::Result<(Arc<ServerConfig>, String, String)> {
        let world_now = time::OffsetDateTime::from(self.start + fcx.now().since_start());
        let leaf = self
            .issuer
            .issue(fcx, &[host], world_now.unix_timestamp())?;
        let config = leaf.server_config(fcx, self.start)?;
        let day = |t: time::OffsetDateTime| {
            format!("{:04}-{:02}-{:02}", t.year(), t.month() as u8, t.day())
        };
        Ok((
            config,
            day(world_now - time::Duration::days(1)),
            day(world_now + time::Duration::days(395)),
        ))
    }
}
