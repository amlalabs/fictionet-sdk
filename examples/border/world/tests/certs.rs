//! The CAs on disk, and the chains a client builds from them.

use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use border_world::certs;
use fictionet::stdlib::ca::Leaf;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

fn tempdir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("border-certs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Runs a TLS handshake in memory. Returns the client's error, if any.
fn handshake(leaf: Leaf, root: CertificateDer<'static>, name: &str) -> Result<(), rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(leaf.chain, leaf.key)?;
    let mut roots = RootCertStore::empty();
    roots.add(root)?;
    let client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut c = ClientConnection::new(
        Arc::new(client),
        ServerName::try_from(name.to_owned()).unwrap(),
    )?;
    let mut s = ServerConnection::new(Arc::new(server))?;
    for _ in 0..10 {
        let mut buf = Vec::new();
        c.write_tls(&mut buf).unwrap();
        s.read_tls(&mut buf.as_slice()).unwrap();
        s.process_new_packets()?;
        let mut buf = Vec::new();
        s.write_tls(&mut buf).unwrap();
        c.read_tls(&mut buf.as_slice()).unwrap();
        c.process_new_packets()?;
        if !c.is_handshaking() && !s.is_handshaking() {
            c.writer().write_all(b"hello").unwrap();
            let mut buf = Vec::new();
            c.write_tls(&mut buf).unwrap();
            s.read_tls(&mut buf.as_slice()).unwrap();
            s.process_new_packets()?;
            let mut got = [0u8; 5];
            s.reader().read_exact(&mut got).unwrap();
            assert_eq!(&got, b"hello");
            return Ok(());
        }
    }
    panic!("the handshake did not finish");
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn the_lab_ca_signs_leaves_a_client_trusts() {
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(1),
        |fcx| async move {
            let dir = tempdir("lab");
            certs::make_ca(&fcx, &dir).unwrap();
            let mode = std::fs::metadata(dir.join("ca.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
            let root = CertificateDer::from_pem_file(dir.join("ca.pem")).unwrap();
            assert!(contains(&root, certs::LAB_CA_NAME));
            let ca = certs::load(&dir).unwrap();
            let leaf = certs::leaf(
                &fcx,
                &ca,
                &["kestrelmoor.co.uk", "www.kestrelmoor.co.uk"],
                Ipv4Addr::new(84, 21, 44, 10),
            )
            .unwrap();
            assert_eq!(leaf.chain.len(), 2);
            assert_eq!(leaf.chain[1], root);
            handshake(leaf, root.clone(), "www.kestrelmoor.co.uk").unwrap();
            let leaf = certs::leaf(
                &fcx,
                &ca,
                &["kestrelmoor.co.uk"],
                Ipv4Addr::new(84, 21, 44, 10),
            )
            .unwrap();
            assert!(handshake(leaf, root, "status.harbourline.net").is_err());
            std::fs::remove_dir_all(&dir).unwrap();
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn the_home_chain_goes_through_the_intermediate_to_the_root() {
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(1),
        |fcx| async move {
            let dir = tempdir("home");
            certs::make_pki(&fcx, &dir).unwrap();
            let root = CertificateDer::from_pem_file(dir.join("root.pem")).unwrap();
            let intermediate = CertificateDer::from_pem_file(dir.join("ca.pem")).unwrap();
            assert!(contains(&root, "DigiCert Global Root G3"));
            assert!(contains(
                &intermediate,
                "DigiCert Global G3 TLS ECC SHA384 2020 CA1"
            ));
            let ca = certs::load(&dir).unwrap();
            let leaf = certs::leaf(
                &fcx,
                &ca,
                &["status.harbourline.net"],
                Ipv4Addr::new(84, 21, 60, 20),
            )
            .unwrap();
            // Leaf, then the intermediate. The root is in the client's store only.
            assert_eq!(leaf.chain[1], intermediate);
            handshake(leaf, root, "status.harbourline.net").unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn the_impostor_is_not_trusted_and_names_its_rogue_root() {
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(1),
        |fcx| async move {
            let dir = tempdir("rogue");
            certs::make_ca(&fcx, &dir).unwrap();
            let trusted = CertificateDer::from_pem_file(dir.join("ca.pem")).unwrap();
            let rogue = certs::rogue_ca(&fcx).unwrap();
            let leaf = certs::leaf(
                &fcx,
                &rogue,
                &["kestrelmoor.co.uk", "www.kestrelmoor.co.uk"],
                Ipv4Addr::new(84, 21, 44, 10),
            )
            .unwrap();
            assert!(contains(&leaf.chain[1], "Anchorpoint Root CA R1"));
            let err = handshake(leaf, trusted, "kestrelmoor.co.uk").unwrap_err();
            assert!(
                matches!(
                    err,
                    rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
                ),
                "{err:?}"
            );
            // Each run makes a new rogue CA.
            assert_ne!(certs::rogue_ca(&fcx).unwrap().cert_der(), rogue.cert_der());
            std::fs::remove_dir_all(&dir).unwrap();
            Ok(())
        },
    ))
    .unwrap();
}
