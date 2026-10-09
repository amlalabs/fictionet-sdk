use fictionet::stdlib::{
    ca::Ca,
    codec::Wire,
    dns::rr::{RData, RecordType},
    http1, sandbox, web,
    x509::{Time, Validity},
};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn sandbox_looks_up_connects_and_requests_with_optional_roots() {
    let result = fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(9),
        |fcx| async move {
            let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
            let ca = Ca::new(&fcx, "Lab CA")?;
            let leaf = ca.issue(
                &fcx,
                &["site.test"],
                Validity {
                    not_before: Time::from_unix(1_700_000_000)?,
                    not_after: Time::from_unix(1_900_000_000)?,
                },
            )?;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.cert_der())?;
            let roots = Arc::new(roots);
            let config = leaf.server_config(&fcx, start)?;
            let (attacher, attachments) = fictionet::attachments();
            web::Sites::new(move |name| {
                (name == "site.test").then(|| {
                    web::Site::new(axum::Router::new().fallback(|| async { "hello" })).tls({
                        let config = config.clone();
                        move |_| config.clone()
                    })
                })
            })
            .start(&fcx, attachments)?;
            let machine =
                sandbox::machine(&fcx, attacher.attach("client")?, Ipv4Addr::new(10, 0, 0, 2));
            let answer = machine
                .lookup(
                    &fcx,
                    Ipv4Addr::new(10, 0, 0, 1).into(),
                    "site.test",
                    RecordType::A,
                )
                .await?;
            let address = answer
                .answers
                .iter()
                .find_map(|r| match r.data {
                    RData::A(a) => Some(a.0),
                    _ => None,
                })
                .unwrap();
            let to = SocketAddr::new(address.into(), 443);
            let mut conn = machine
                .tls(&fcx, to, "site.test", Some(&roots), start)
                .await?;
            let request = http1::Request::parse(b"GET / HTTP/1.1\r\nHost: site.test\r\n\r\n")?;
            let response = sandbox::request(&fcx, &mut conn, &request).await?;
            assert_eq!(response.head.status, 200);
            assert_eq!(response.body, b"hello");
            let empty = Arc::new(rustls::RootCertStore::empty());
            assert!(
                machine
                    .tls(&fcx, to, "site.test", Some(&empty), start)
                    .await
                    .is_err()
            );
            let mut conn = machine.tls(&fcx, to, "site.test", None, start).await?;
            assert_eq!(
                sandbox::request(&fcx, &mut conn, &request).await?.body,
                b"hello"
            );
            Err(fictionet::Error::msg("finished"))
        },
    ));
    assert_eq!(result.unwrap_err().to_string(), "finished");
}
