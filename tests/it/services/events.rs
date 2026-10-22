use super::*;

/// A reader set after a connection opened still sees that connection's
/// earlier events, and its later ones.
#[test]
fn a_reader_added_mid_connection_sees_its_events() {
    crate::common::world::observed_world(Duration::from_secs(60), |fcx, log| async move {
        let (server, _su, client, _cu) = two_machines(&fcx);
        serve::listen(
            &fcx,
            server.listen(7)?,
            Arc::new(()),
            || Echo,
            ServeOptions::default(),
        );
        let mut conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 7))
            .await?;
        conn.write_all(&fcx, b"before\n").await?;
        assert_eq!(read_some(&fcx, &mut conn, 13).await, b"hello\nbefore\n");
        let seen = log.clone();
        assert_eq!(seen.of("echo", "line")[0].summary, "before");
        conn.write_all(&fcx, b"after\n").await?;
        assert_eq!(read_some(&fcx, &mut conn, 6).await, b"after\n");
        log.wait(&fcx, 0, 2, Duration::from_secs(2), |e| e.is("echo", "line"))
            .await?;
        assert_eq!(
            seen.of("echo", "line")
                .iter()
                .map(|e| e.summary.as_str())
                .collect::<Vec<_>>(),
            ["before", "after"]
        );
        Ok(())
    });
}

/// A network's events start with one that puts the run's clock on a
/// calendar.
#[test]
fn a_net_starts_its_events_with_a_wall_clock_anchor() {
    let log = Arc::new(fictionet_test_support::EventLog::default());
    world::seeded_real_world(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(42))
            .observer(log.clone())
            .fields(Fields::new().with("world_date", "2026-10-06")),
        Duration::from_secs(60),
        move |fcx| async move {
            let (_attacher, attachments) = fictionet::attachments();
            Net::new().start(&fcx, attachments)?;
            let starts = log.of("run", "start");
            assert_eq!(starts.len(), 1);
            let first = &starts[0];
            assert!(first.is("run", "start"));
            assert_eq!(first.at, fictionet::time::Instant::ZERO);
            assert_eq!(
                first.str("seed"),
                Some(fictionet::Seed::from_u64(42).to_string().as_str())
            );
            assert_eq!(first.str("rng"), Some("chacha20-v1"));
            assert_eq!(first.str("world_date"), Some("2026-10-06"));
            assert!(
                first
                    .get("wall")
                    .and_then(json::Value::as_f64)
                    .is_some_and(|w| w > 1.7e9)
            );
            Ok(())
        },
    );
}

/// `Host::tcp` records each connection's opening and closing, as
/// `Host::tcp_with` does by default. Before, `tcp` turned them off.
#[test]
fn net_records_connections_on_a_tcp_port() {
    crate::common::world::observed_world(Duration::from_secs(60), |fcx, kept| async move {
        let (attacher, attachments) = fictionet::attachments();
        let addr = Ipv4Addr::new(10, 40, 0, 1);
        Net::new()
            .ipv4_only()
            .host("svc", |h| h.at(addr).tcp(7, Arc::new(()), || Echo))
            .start(&fcx, attachments)?;
        let s = machine(&fcx, attacher.attach("agent")?, ME);
        let mut conn = s.tcp.connect(&fcx, SocketAddr::new(addr.into(), 7)).await?;
        conn.write_all(&fcx, b"quit\n").await?;
        assert_eq!(read_some(&fcx, &mut conn, 10).await, b"hello\nbye\n");
        let closed = kept
            .wait(&fcx, 0, 1, Duration::from_secs(2), |e| {
                e.is("conn", "close")
            })
            .await?;
        let opened = kept.of("conn", "open");
        assert_eq!(opened.len(), 1, "{opened:?}");
        assert_eq!((opened[0].conn.id, closed[0].conn.id), (Some(1), Some(1)));
        Ok(())
    });
}
