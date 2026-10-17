use super::*;

// ---------------------------------------------------------------------------
// TLS by name

/// A server config for `names`, and roots that trust it.
fn tls_pair(fcx: &Cx, names: &[&str]) -> (Arc<rustls::ServerConfig>, Arc<rustls::RootCertStore>) {
    let (ca, leaf) = certs::issue(fcx, "Test CA", names).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der()).unwrap();
    (
        leaf.server_config(fcx, std::time::SystemTime::now())
            .unwrap(),
        Arc::new(roots),
    )
}

/// A connection whose TLS handshake is cut short by a cancel ends as
/// cancelled, not as a broken connection.
#[test]
fn a_cancel_during_the_tls_handshake_is_a_cancel() {
    world(Duration::from_secs(60), |fcx| async move {
        let (config, _roots) = tls_pair(&fcx, &["a.test"]);
        let (server, _su, client, _cu) = two_machines(&fcx);
        let mut listener = server.listen(443)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        fcx.spawn(move |fcx| async move {
            let conn = listener.accept(&fcx).await?;
            let _ = fcx
                .region(|region_fcx| async move {
                    let stopper = region_fcx.clone();
                    region_fcx.spawn(move |fcx| async move {
                        fcx.sleep(Duration::from_millis(50)).await?;
                        stopper.cancel();
                        Ok(())
                    });
                    let opts = ServeOptions::default().tls(config);
                    let served = serve::connection(
                        &region_fcx,
                        conn,
                        ConnInfo::default(),
                        &mut Echo,
                        &(),
                        &opts,
                    )
                    .await;
                    let _ = tx.send(format!("{:?}", served.map(|_| ())));
                    Ok(())
                })
                .await;
            Ok(())
        });
        // The client connects and never says hello.
        let _conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 443))
            .await?;
        let result = fcx
            .race(Some(fcx.now() + Duration::from_secs(10)), rx)
            .await??;
        // Not a closed connection, nor a broken one: the one cancel.
        assert_eq!(result, "Err(Cancelled)");
        let tls = fcx
            .events()
            .wait(&fcx, 1, Duration::from_secs(2), |e| {
                e.is("tls", "handshake")
            })
            .await?;
        assert_eq!(tls[0].str("outcome"), Some("cancelled"));
        Ok(())
    });
}

#[test]
fn net_routes_tls_by_name_to_each_service() {
    /// Answers each line in upper case.
    struct Upper;
    service_fixture! {
        Upper => (Lines, (), Infallible);
        decoder(self) {
            Lines::new(64, Ending::LfOrCrlf)
        }
        on_item(self, line: Result<Vec<u8>, LineError>; _, driver) -> Flow {
            driver
                .reply()
                .extend_from_slice(&line.unwrap_or_default().to_ascii_uppercase());
            driver.reply().push(b'\n');
            Ok(Flow::Continue)
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let result = rt.block_on(lab(fictionet::Seed::from_u64(1), move |fcx| async move {
        let (config, roots) = tls_pair(&fcx, &["a.test", "b.test"]);
        let kept = fcx.events();
        let (attacher, attachments) = fictionet::attachments();
        let (ca, cb) = (config.clone(), config.clone());
        let addr = Ipv4Addr::new(10, 40, 0, 2);
        Net::new()
            .ipv4_only()
            .add_host(
                fictionet::stdlib::net::Host::new("tls")
                    .at(addr)
                    .tls(6514, "a.test", move |_| ca.clone(), Arc::new(()), || Echo)
                    .tls(6514, "b.test", move |_| cb.clone(), Arc::new(()), || Upper),
            )
            .start(&fcx, attachments)?;
        let s = machine(&fcx, attacher.attach("agent")?, ME);
        let connect = |name: &'static str| {
            let roots = roots.clone();
            let s = &s;
            let fcx = &fcx;
            async move {
                let tcp = s
                    .tcp
                    .connect(fcx, SocketAddr::new(addr.into(), 6514))
                    .await
                    .map_err(std::io::Error::other)?;
                let client = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
                tokio_rustls::TlsConnector::from(Arc::new(client))
                    .connect(
                        rustls::pki_types::ServerName::try_from(name).unwrap(),
                        tcp.into_tokio(fcx),
                    )
                    .await
            }
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut a = connect("a.test").await?;
        let mut buf = [0u8; 64];
        let n = a.read(&mut buf).await?;
        assert_eq!(&buf[..n], b"hello\n");
        let mut b = connect("b.test").await?;
        b.write_all(b"shout\n").await?;
        let n = b.read(&mut buf).await?;
        assert_eq!(&buf[..n], b"SHOUT\n");
        assert!(connect("c.test").await.is_err());
        let tls = kept
            .wait(&fcx, 3, Duration::from_secs(2), |e| {
                e.is("tls", "handshake")
            })
            .await?;
        let seen: Vec<(Option<&str>, Option<&str>)> = tls
            .iter()
            .map(|e| (e.str("sni"), e.str("outcome")))
            .collect();
        assert_eq!(
            seen,
            [
                (Some("a.test"), Some("accepted")),
                (Some("b.test"), Some("accepted")),
                (Some("c.test"), Some("rejected"))
            ]
        );
        Err::<(), fictionet::Error>(Done.into())
    }));
    assert!(result.unwrap_err().downcast_ref::<Done>().is_some());
}

/// SMTP-style STARTTLS: the banner, then `STARTTLS`, then TLS on the same
/// connection with the same service.
struct Mail {
    tls: bool,
}

service_fixture! {
    Mail => (Lines, (), Infallible);
    decoder(self) {
        Lines::new(512, Ending::LfOrCrlf)
    }
    on_open(self; _, driver) -> Flow {
        // After STARTTLS the client speaks first.
        self.tls = driver.conn().tls;
        if !self.tls {
            driver.reply().extend_from_slice(b"220 mail ready\r\n");
        }
        Ok(Flow::Continue)
    }
    on_item(self, line: Result<Vec<u8>, LineError>; _, driver) -> Flow {
        let line = line.unwrap_or_default();
        match line.as_slice() {
            b"STARTTLS" if !self.tls => {
                driver.reply().extend_from_slice(b"220 go ahead\r\n");
                Ok(Flow::Upgrade(Upgrade::Tls))
            }
            b"EHLO" => {
                let sni = driver.conn().sni.as_deref().unwrap_or("-").to_owned();
                driver.reply().extend_from_slice(
                    format!("250 hello tls={} sni={sni}\r\n", self.tls).as_bytes(),
                );
                Ok(Flow::Continue)
            }
            _ => {
                driver.reply().extend_from_slice(b"500 what\r\n");
                Ok(Flow::Continue)
            }
        }
    }
}

#[test]
fn the_harness_resumes_after_starttls() {
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Mail { tls: false }, ());
    assert_eq!(h.open().unwrap(), b"220 mail ready\r\n");
    let wake = h.wake_handle();
    let got = h.push(b"STARTTLS\r\n");
    assert!(
        matches!(got, Err(HarnessError::Upgraded(Upgrade::Tls))),
        "{got:?}"
    );
    assert_eq!(h.output(), b"220 mail ready\r\n220 go ahead\r\n");
    // What a TLS layer would hand on after its handshake.
    let mut conn = ConnInfo::default().over_tls(Some("mail.test"), None);
    conn.id = Some(1);
    h.resume(conn).unwrap();
    assert_eq!(
        h.push(b"EHLO\r\n").unwrap(),
        b"250 hello tls=true sni=mail.test\r\n"
    );
    // A handle taken before STARTTLS still wakes the service after it.
    assert!(!wake.is_closed());
}

#[test]
fn net_performs_starttls_for_a_service_that_asks() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let result = rt.block_on(lab(fictionet::Seed::from_u64(1), move |fcx| async move {
        let (config, roots) = tls_pair(&fcx, &["mail.test"]);
        let kept = fcx.events();
        let (attacher, attachments) = fictionet::attachments();
        let addr = Ipv4Addr::new(10, 40, 0, 25);
        let opts = ServeOptions::default().starttls(config.clone());
        Net::new()
            .ipv4_only()
            .host("mail", |h| {
                h.at(addr).dns_name("mail.test").tcp_with(
                    25,
                    Arc::new(()),
                    || Mail { tls: false },
                    opts,
                )
            })
            .start(&fcx, attachments)?;
        let s = machine(&fcx, attacher.attach("agent")?, ME);
        let mut tcp = s
            .tcp
            .connect(&fcx, SocketAddr::new(addr.into(), 25))
            .await?;
        assert_eq!(read_some(&fcx, &mut tcp, 16).await, b"220 mail ready\r\n");
        tcp.write_all(&fcx, b"STARTTLS\r\n").await?;
        assert_eq!(read_some(&fcx, &mut tcp, 14).await, b"220 go ahead\r\n");
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client))
            .connect(
                rustls::pki_types::ServerName::try_from("mail.test").unwrap(),
                tcp.into_tokio(&fcx),
            )
            .await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tls.write_all(b"EHLO\r\n").await?;
        let mut buf = [0u8; 128];
        let n = tls.read(&mut buf).await?;
        assert_eq!(&buf[..n], b"250 hello tls=true sni=mail.test\r\n");
        let handshakes = kept
            .wait(&fcx, 1, Duration::from_secs(2), |e| {
                e.is("tls", "handshake")
            })
            .await?;
        assert_eq!(handshakes[0].str("outcome"), Some("accepted"));
        Err::<(), fictionet::Error>(Done.into())
    }));
    assert!(result.unwrap_err().downcast_ref::<Done>().is_some());
}

/// A STARTTLS handshake has the network's handshake limit. Before, it had
/// the service's default of 10 seconds.
#[test]
fn net_limits_a_starttls_handshake() {
    world(Duration::from_secs(60), move |fcx| async move {
        let (config, _roots) = tls_pair(&fcx, &["mail.test"]);
        let kept = fcx.events();
        let (attacher, attachments) = fictionet::attachments();
        let addr = Ipv4Addr::new(10, 40, 0, 25);
        let limits = fictionet::stdlib::net::Limits {
            handshake: Duration::from_millis(200),
            ..Default::default()
        };
        let opts = ServeOptions::default().starttls(config);
        Net::new()
            .ipv4_only()
            .limits(limits)
            .host("mail", |h| {
                h.at(addr)
                    .tcp_with(25, Arc::new(()), || Mail { tls: false }, opts)
            })
            .start(&fcx, attachments)?;
        let s = machine(&fcx, attacher.attach("agent")?, ME);
        let mut conn = s
            .tcp
            .connect(&fcx, SocketAddr::new(addr.into(), 25))
            .await?;
        assert_eq!(read_some(&fcx, &mut conn, 16).await, b"220 mail ready\r\n");
        conn.write_all(&fcx, b"STARTTLS\r\n").await?;
        assert_eq!(read_some(&fcx, &mut conn, 14).await, b"220 go ahead\r\n");
        // The client never starts its handshake.
        let handshake = kept
            .wait(&fcx, 1, Duration::from_secs(2), |e| {
                e.is("tls", "handshake")
            })
            .await?;
        assert_ne!(handshake[0].str("outcome"), Some("accepted"));
        Ok(())
    });
}
