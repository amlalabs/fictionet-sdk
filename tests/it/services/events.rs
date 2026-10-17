use super::*;
use fictionet::observe::Layer;

// ---------------------------------------------------------------------------
// Events

#[test]
fn event_layers_keep_field_order_and_render_json_values() {
    let event = Event::new("test", "values")
        .summary("all field types")
        .field("text", "hello\n\"world\"")
        .field("number", 42u32)
        .field("flag", true)
        .field("none", json::Value::Null)
        .field("array", json::Value::parse(br#"[1,"two",null]"#).unwrap())
        .field("object", json::Value::parse(br#"{"a":false}"#).unwrap());
    let original = event.clone();
    let layer = Layer::from_event(&event);
    assert_eq!(layer.name, "test.values");
    assert_eq!(layer.summary, "all field types");
    assert_eq!(layer.buf, 0);
    assert_eq!(layer.range, (0, 0));
    assert_eq!(
        layer
            .fields
            .iter()
            .map(|field| (field.name.as_str(), field.value.as_str(), field.range))
            .collect::<Vec<_>>(),
        [
            ("text", "hello\n\"world\"", None),
            ("number", "42", None),
            ("flag", "true", None),
            ("none", "null", None),
            ("array", r#"[1,"two",null]"#, None),
            ("object", r#"{"a":false}"#, None),
        ]
    );
    assert_eq!(event, original);
    assert_eq!(
        Layer::from_event(&Event::new("test", "empty")),
        Layer::new("test.empty", 0, (0, 0))
    );
}

#[test]
fn every_run_keeps_its_events_and_writes_them_as_json_lines() {
    let path = std::env::temp_dir().join(format!("fictionet-events-{}.jsonl", std::process::id()));
    let p = path.clone();
    world(Duration::from_secs(60), move |fcx| async move {
        let events = fcx.events();
        let conn = ConnInfo::new(
            9,
            "10.0.0.1:80".parse().unwrap(),
            "10.0.0.2:4000".parse().unwrap(),
        );
        for i in 0..3u64 {
            fcx.record(
                Event::new("test", "n")
                    .conn(&conn)
                    .summary(format!("n={i}"))
                    .field("i", i)
                    .field("none", fictionet::events::opt(None::<u64>)),
            );
        }
        // A file set after the first events still gets them all.
        events.to_file(&p)?;
        assert_eq!(
            events.all().iter().map(|e| e.seq).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(events.dropped(), 0);
        let layer = Layer::from_event(&events.all()[1]);
        assert_eq!(layer.name, "test.n");
        assert_eq!(layer.summary, "n=1");
        assert_eq!(events.lost(), 0);
        Ok(())
    });
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<json::Value> = text
        .lines()
        .map(|l| json::Value::parse(l.as_bytes()).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(
        lines[1].get("source").and_then(json::Value::as_str),
        Some("test")
    );
    assert_eq!(lines[1].get("conn").and_then(json::Value::as_u64), Some(9));
    assert_eq!(
        lines[1].get("peer").and_then(json::Value::as_str),
        Some("10.0.0.2:4000")
    );
    let fields = lines[1].get("fields").unwrap();
    assert_eq!(fields.get("i").and_then(json::Value::as_u64), Some(1));
    assert!(fields.get("none").unwrap().is_null());
    let _ = std::fs::remove_file(&path);
}

/// A reader set after a connection opened still sees that connection's
/// earlier events, and its later ones.
#[test]
fn a_reader_added_mid_connection_sees_its_events() {
    world(Duration::from_secs(60), |fcx| async move {
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
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s = seen.clone();
        fcx.events().subscribe(move |e| {
            if e.is("echo", "line") {
                s.lock().unwrap().push(e.summary.clone());
            }
        });
        conn.write_all(&fcx, b"after\n").await?;
        assert_eq!(read_some(&fcx, &mut conn, 6).await, b"after\n");
        fcx.events()
            .wait(&fcx, 2, Duration::from_secs(2), |e| e.is("echo", "line"))
            .await?;
        assert_eq!(*seen.lock().unwrap(), ["before", "after"]);
        Ok(())
    });
}

/// A network's events start with one that puts the run's clock on a
/// calendar.
#[test]
fn a_net_starts_its_events_with_a_wall_clock_anchor() {
    world::seeded_real_world(
        fictionet::Seed::from_u64(42),
        Duration::from_secs(60),
        |fcx| async move {
            let kept = fcx.events();
            let (_attacher, attachments) = fictionet::attachments();
            let date = Fields::new().with("world_date", "2026-10-06");
            Net::new().start_fields(date).start(&fcx, attachments)?;
            let first = &kept.all()[0];
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
    world(Duration::from_secs(60), |fcx| async move {
        let kept = fcx.events();
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
            .wait(&fcx, 1, Duration::from_secs(2), |e| e.is("conn", "close"))
            .await?;
        let opened = kept.of("conn", "open");
        assert_eq!(opened.len(), 1, "{opened:?}");
        assert_eq!((opened[0].conn.id, closed[0].conn.id), (Some(1), Some(1)));
        Ok(())
    });
}
