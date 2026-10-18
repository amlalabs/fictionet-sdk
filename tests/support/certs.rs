use fictionet::{
    Cx, Result,
    stdlib::{
        protocols::x509::{Time, Validity},
        services::ca::{Ca, Leaf},
    },
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// A server certificate and the roots that trust it.
pub struct Certs {
    pub roots: RootCertStore,
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

/// Makes the named CA and a server certificate valid from 2000 until 2100.
pub fn issue(fcx: &Cx, issuer: &str, names: &[&str]) -> Result<(Ca, Leaf)> {
    let ca = Ca::new(fcx, issuer)?;
    let leaf = ca.issue(
        fcx,
        names,
        Validity {
            not_before: Time::from_unix(946684800)?,
            not_after: Time::from_unix(4102444800)?,
        },
    )?;
    Ok((ca, leaf))
}

/// Makes a CA and a server certificate for the names.
pub fn certs(fcx: &Cx, names: &[&str]) -> Certs {
    let (ca, leaf) = issue(fcx, "Test CA", names).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der()).unwrap();
    Certs {
        roots,
        chain: leaf.chain,
        key: leaf.key,
    }
}
