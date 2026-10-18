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
fn installed_observers_keep_events_and_write_json_lines() {
    let path = std::env::temp_dir().join(format!("fictionet-events-{}.jsonl", std::process::id()));
    let evidence = Arc::new(fictionet::events::Memory::default());
    let jsonl = Arc::new(
        fictionet::events::Jsonl::open(&path, fictionet::events::Limits::default()).unwrap(),
    );
    let options = fictionet::RunOptions::new(fictionet::Seed::from_u64(1)).observer(Arc::new(
        fictionet::events::Fanout::new(vec![evidence.clone(), jsonl.clone()]),
    ));
    world::seeded_world(options, Duration::from_secs(60), move |fcx| async move {
        let events = evidence;
        let conn = ConnInfo::new(
            9,
            "10.0.0.1:80".parse().unwrap(),
            "10.0.0.2:4000".parse().unwrap(),
        );
        for i in 0..3u64 {
            fcx.emit("test", "n", |event| {
                event
                    .conn(&conn)
                    .summary(format!("n={i}"))
                    .field("i", i)
                    .field("none", fictionet::events::opt(None::<u64>))
            });
        }
        assert_eq!(
            events
                .checked_all()
                .unwrap()
                .iter()
                .map(|e| e.seq)
                .collect::<Vec<_>>(),
            [1, 2, 3, 4]
        );
        assert_eq!(events.dropped(), 0);
        let layer = Layer::from_event(&events.checked_all().unwrap()[2]);
        assert_eq!(layer.name, "test.n");
        assert_eq!(layer.summary, "n=1");
        Ok(())
    });
    jsonl.finish().unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<json::Value> = text
        .lines()
        .map(|l| json::Value::parse(l.as_bytes()).unwrap())
        .collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(
        lines[2].get("source").and_then(json::Value::as_str),
        Some("test")
    );
    assert_eq!(lines[2].get("conn").and_then(json::Value::as_u64), Some(9));
    assert_eq!(
        lines[2].get("peer").and_then(json::Value::as_str),
        Some("10.0.0.2:4000")
    );
    let fields = lines[2].get("fields").unwrap();
    assert_eq!(fields.get("i").and_then(json::Value::as_u64), Some(1));
    assert!(fields.get("none").unwrap().is_null());
    let _ = std::fs::remove_file(&path);
}

/// A reader set after a connection opened still sees that connection's
/// earlier events, and its later ones.
#[test]
fn a_reader_added_mid_connection_sees_its_events() {
    crate::common::world::observed_world(Duration::from_secs(60), |fcx, evidence| async move {
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
        let seen = evidence.clone();
        assert_eq!(
            seen.checked_of("echo", "line").unwrap()[0].summary,
            "before"
        );
        conn.write_all(&fcx, b"after\n").await?;
        assert_eq!(read_some(&fcx, &mut conn, 6).await, b"after\n");
        evidence
            .wait(&fcx, 2, Duration::from_secs(2), |e| e.is("echo", "line"))
            .await?;
        assert_eq!(
            seen.checked_of("echo", "line")
                .unwrap()
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
    let evidence = Arc::new(fictionet::events::Memory::default());
    world::seeded_real_world(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(42))
            .observer(evidence.clone())
            .fields(Fields::new().with("world_date", "2026-10-06")),
        Duration::from_secs(60),
        move |fcx| async move {
            let kept = evidence;
            let (_attacher, attachments) = fictionet::attachments();
            Net::new().start(&fcx, attachments)?;
            let starts = kept.checked_of("run", "start").unwrap();
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
    crate::common::world::observed_world(Duration::from_secs(60), |fcx, evidence| async move {
        let kept = evidence;
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
        let opened = kept.checked_of("conn", "open").unwrap();
        assert_eq!(opened.len(), 1, "{opened:?}");
        assert_eq!((opened[0].conn.id, closed[0].conn.id), (Some(1), Some(1)));
        Ok(())
    });
}
