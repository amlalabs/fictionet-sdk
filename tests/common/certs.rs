use fictionet::{
    Cx,
    stdlib::{
        ca::Ca,
        x509::{Time, Validity},
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

/// Makes a CA and a server certificate for the names.
pub fn certs(fcx: &Cx, names: &[&str]) -> Certs {
    let ca = Ca::new(fcx, "Test CA").unwrap();
    let leaf = ca
        .issue(
            fcx,
            names,
            Validity {
                not_before: Time::from_unix(946684800).unwrap(),
                not_after: Time::from_unix(4102444800).unwrap(),
            },
        )
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der()).unwrap();
    Certs {
        roots,
        chain: leaf.chain,
        key: leaf.key,
    }
}
