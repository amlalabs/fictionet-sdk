use super::*;
use crate::dashboard::PACKET_TICK;
use crate::{
    Class, DashboardHandle, DashboardObserver, DashboardOptions, Envelope, Match, Options, Session,
    Value,
};
use fictionet::stdlib::codec::le32;
use fictionet::{Cx, Interface, InterfaceExt, Packet, RunOptions, Seed, block_on, lab};

fn ip() -> Packet {
    Packet(vec![0x45; 20])
}

/// Runs `world` in a lab observed by a dashboard with `options`.
fn with_dashboard<F, Fut>(options: DashboardOptions, world: F) -> DashboardObserver
where
    F: FnOnce(Cx, DashboardHandle) -> Fut + Send,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    let dashboard = DashboardObserver::new(options);
    let handle = dashboard.handle();
    block_on(lab(
        RunOptions::new(Seed::from_u64(1)).observer(dashboard.observer()),
        move |cx| world(cx, handle),
    ))
    .unwrap();
    dashboard
}

/// Registers `count` pairs as links and returns their kept ends and numbers.
async fn links(cx: &Cx, handle: &DashboardHandle, count: usize) -> (Vec<fictionet::End>, Vec<u64>) {
    let mut ends = Vec::new();
    for _ in 0..count {
        let (mut a, b) = fictionet::pair();
        a = cx.tap("test", a);
        ends.extend([a, b]);
    }
    cx.yield_now().await.unwrap();
    let numbers = handle
        .0
        .collector
        .topology()
        .links
        .keys()
        .map(|id| id.get())
        .collect();
    (ends, numbers)
}

fn text(value: &Value) -> String {
    String::from_utf8_lossy(&value.bytes).into_owned()
}

fn call(session: &mut Session, id: u32, request: &str, now: Instant) -> Value {
    let mut values = session.request(id, request, now, None);
    assert_eq!(values.len(), 1, "{request}");
    values.remove(0)
}

fn packets(link: u64, after: u64) -> String {
    format!(r#"{{"op":"packets","link":"e{link}","after":{after}}}"#)
}

fn names(values: &[Value]) -> Vec<String> {
    values
        .iter()
        .map(|v| match v.envelope() {
            Some(Envelope::Event { name, .. }) => name,
            other => panic!("{other:?}"),
        })
        .collect()
}

fn watch_of(handle: &DashboardHandle, link: u64, now: Instant) -> Arc<LinkWatch> {
    handle.0.watches.existing(link, now).unwrap()
}

fn key(n: usize) -> (String, Vec<u8>, Vec<u8>) {
    (
        "CLIENT_TRAFFIC_SECRET_0".into(),
        (n as u64).to_be_bytes().repeat(4),
        vec![0xab; 32],
    )
}

fn log_key(cx: &Cx, key: &(String, Vec<u8>, Vec<u8>)) {
    cx.tls_key_log(None).unwrap().log(&key.0, &key.1, &key.2);
}

/// The SSLKEYLOGFILE text of a pcapng file's secrets block, if any.
fn exported_keys(file: &[u8]) -> String {
    let mut i = 0;
    while i < file.len() {
        let len = le32(file, i + 4).unwrap() as usize;
        if le32(file, i).unwrap() == 0x0a {
            assert_eq!(le32(file, i + 8).unwrap(), 0x544c_534b);
            let key_len = le32(file, i + 12).unwrap() as usize;
            return String::from_utf8(file[i + 16..i + 16 + key_len].to_vec()).unwrap();
        }
        i += len;
    }
    String::new()
}

/// A whole `pcap` reply: its first value, then the rest from `poll`.
fn download(session: &mut Session, id: u32, link: u64, now: Instant) -> Vec<u8> {
    let first = call(
        session,
        id,
        &format!(r#"{{"op":"pcap","link":"e{link}"}}"#),
        now,
    );
    assert!(first.binary, "{}", text(&first));
    let mut file = first.bytes;
    let mut end = first.end;
    while !end {
        let piece = session
            .poll(now, None)
            .into_iter()
            .find(|v| v.id == id)
            .unwrap();
        assert!(piece.binary);
        file.extend(piece.bytes);
        end = piece.end;
    }
    file
}

fn startup(mut collector: Options) -> DashboardOptions {
    let mut classes = collector.policy.classes().to_vec();
    for class in &mut classes {
        if class.name == "packets" {
            class.when = crate::When::Always;
        }
    }
    collector.policy = Arc::new(crate::policy::Standard { classes });
    DashboardOptions {
        collector,
        ..DashboardOptions::default()
    }
}

#[test]
fn capture_reports_eviction_separately_from_sampling_without_renumbering() {
    let options = startup(Options {
        policy: crate::tests::policy([Class::new("packets").count(2).bytes(1024).burst(64)]),
        ..Options::default()
    });
    with_dashboard(options, |cx, handle| async move {
        let (mut ends, links) = links(&cx, &handle, 1).await;
        let mut session = handle.session();
        let now = Instant::now();
        call(&mut session, 1, &packets(links[0], 0), now);
        for _ in 0..67 {
            ends[0].send(ip());
        }
        let watch = watch_of(&handle, links[0], now);
        watch.pump(&handle.0);
        let (missed, rows) = watch.rows_after(0, 10);
        assert_eq!(missed, 0);
        assert_eq!(rows.len(), 2);
        for ((seq, row), (expected, skipped, evicted)) in rows.iter().zip([(1, 0, 64), (2, 1, 0)]) {
            assert_eq!(*seq, expected);
            assert!(row.starts_with(&format!(r#"{{"seq":{expected},"#)));
            assert!(row.contains(&format!(r#""skipped":{skipped},"evicted":{evicted},"#)));
            assert!(
                watch
                    .detail(*seq)
                    .unwrap()
                    .starts_with(&format!(r#"{{"seq":{seq},"#))
            );
        }
        watch.pump(&handle.0);
        assert_eq!(watch.rows_after(0, 10), (0, rows));
        Ok(())
    });
}

#[test]
fn capture_reports_overflow_from_an_empty_capture() {
    let options = startup(Options {
        policy: crate::tests::policy([Class::new("packets").count(2).bytes(20).burst(64)]),
        ..Options::default()
    });
    with_dashboard(options, |cx, handle| async move {
        let (mut ends, links) = links(&cx, &handle, 1).await;
        let mut session = handle.session();
        let now = Instant::now();
        call(&mut session, 1, &packets(links[0], 0), now);
        let watch = watch_of(&handle, links[0], now);
        for _ in 0..3 {
            ends[0].send(Packet(vec![0; 21]));
        }
        watch.pump(&handle.0);
        watch.pump(&handle.0);
        assert!(watch.rows_after(0, 10).1.is_empty());
        for _ in 0..2 {
            ends[0].send(ip());
            watch.pump(&handle.0);
        }
        let (_, rows) = watch.rows_after(0, 10);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].1.contains(r#""skipped":0,"evicted":0"#));
        let losses = handle.0.collector.losses();
        let overflow = losses
            .streams
            .iter()
            .find(|loss| loss.reason == fictionet::events::LossReason::Overflow)
            .unwrap();
        assert_eq!(overflow.count, 3);
        assert_eq!(overflow.class, Some(4));
        assert!(rows[1].1.contains(r#""skipped":0,"evicted":0"#));
        Ok(())
    });
}

#[test]
fn quiet_capture_keeps_keys_after_the_collector_ring_rotates() {
    let bounds = crate::Bounds {
        count: 100,
        bytes: 1 << 20,
    };
    let options = startup(Options {
        policy: crate::tests::policy([
            Class::new("keys").count(bounds.count).bytes(bounds.bytes),
            Class::new("packets").count(4096).bytes(8 << 20).burst(64),
        ]),
        ..Options::default()
    });
    with_dashboard(options, move |cx, handle| async move {
        let (mut ends, links) = links(&cx, &handle, 1).await;
        let mut session = handle.session();
        let now = Instant::now();
        call(&mut session, 1, &packets(links[0], 0), now);
        let watch = watch_of(&handle, links[0], now);
        log_key(&cx, &key(0));
        let original = handle.0.collector.keylog();
        ends[0].send(ip());
        watch.pump(&handle.0);
        let rows = watch.rows_after(0, 10);

        // Sessions elsewhere rotate the collector's ring without new packets here.
        for n in 1..=bounds.count {
            log_key(&cx, &key(n));
        }
        watch.pump(&handle.0);
        assert_eq!(watch.rows_after(0, 10), rows);
        let current = handle.0.collector.keylog();
        assert_eq!(current.lines().count(), bounds.count);
        assert!(!current.contains(&original));
        let exported = exported_keys(&download(&mut session, 2, links[0], now));
        assert_eq!(watch.cached_keys(), 1);
        assert_eq!(exported, current);

        // Traffic resumes: the watch's bounded cache also forgets the old key.
        ends[0].send(ip());
        watch.pump(&handle.0);
        assert_eq!(watch.cached_keys(), bounds.count);
        assert_eq!(watch.rows_after(0, 10).1.len(), 2);
        assert_eq!(
            exported_keys(&download(&mut session, 3, links[0], now)),
            current
        );
        Ok(())
    });
}

#[test]
fn capture_deduplicates_complete_key_lines() {
    with_dashboard(startup(Options::default()), |cx, handle| async move {
        let (mut ends, links) = links(&cx, &handle, 1).await;
        let mut session = handle.session();
        let now = Instant::now();
        call(&mut session, 1, &packets(links[0], 0), now);
        let watch = watch_of(&handle, links[0], now);
        log_key(&cx, &key(0));
        ends[0].send(ip());
        watch.pump(&handle.0);
        let original = handle.0.collector.keylog();
        log_key(&cx, &key(0));
        let mut server = key(0);
        server.0 = "SERVER_TRAFFIC_SECRET_0".into();
        log_key(&cx, &server);
        let mut different = key(0);
        different.2 = vec![0xcd; 32];
        log_key(&cx, &different);
        ends[0].send(ip());
        watch.pump(&handle.0);
        let all = handle.0.collector.keylog();
        assert_eq!(all.lines().count(), 4);
        let exported = exported_keys(&download(&mut session, 2, links[0], now));
        assert_eq!(exported, all.strip_prefix(&original).unwrap());
        assert_eq!(exported.lines().count(), 3);
        Ok(())
    });
}

#[test]
fn capture_keeps_rows_and_keys_after_the_run_ends() {
    let mut expected = String::new();
    let dashboard = with_dashboard(startup(Options::default()), |cx, handle| async move {
        let (mut ends, _) = links(&cx, &handle, 1).await;
        log_key(&cx, &key(0));
        ends[0].send(ip());
        Ok(())
    });
    let handle = dashboard.handle();
    expected.push_str(&handle.0.collector.keylog());
    assert_eq!(expected.lines().count(), 1);
    let link = handle.0.collector.find_link(1).unwrap().get();
    let mut session = handle.session();
    let now = Instant::now();
    let values = session.request(1, &packets(link, 0), now, None);
    assert_eq!(names(&values), ["link"]);
    let values = session.poll(now, None);
    assert_eq!(names(&values), ["packet", "end"]);
    assert!(text(&values[1]).contains("the link closed"));
    let file = download(&mut session, 2, link, now);
    assert_eq!(exported_keys(&file), expected);
}

#[test]
fn a_subscription_does_not_keep_its_run_or_link_alive() {
    let saved = Arc::new(Mutex::new(None));
    let save = saved.clone();
    let dashboard = with_dashboard(DashboardOptions::default(), move |cx, handle| async move {
        let (ends, links) = links(&cx, &handle, 1).await;
        let now = Instant::now();
        let id = handle.0.collector.find_link(links[0]).unwrap();
        let subscription = handle
            .0
            .watches
            .acquire(&handle.0.collector, links[0], now, || {
                Some((id, crate::view::describe(&handle, id)))
            })
            .unwrap();
        log_key(&cx, &key(0));
        let expected = handle.0.collector.keylog();
        let mut ends = ends;
        ends[0].send(ip());
        subscription.watch().pump(&handle.0);
        drop(ends);
        let export = handle.0.collector.export(&crate::export::Selection {
            streams: vec![
                fictionet::events::Stream::Packets(id),
                fictionet::events::Stream::Keys,
            ],
            ..Default::default()
        });
        *save.lock() = Some((
            subscription,
            Arc::downgrade(&handle.0),
            expected,
            id,
            export,
        ));
        Ok(())
    });
    assert!(dashboard.handle().0.collector.ended().is_some());
    let (subscription, weak, expected, id, mut export) = saved.lock().take().unwrap();
    assert!(!dashboard.handle().0.collector.live(id));
    drop(dashboard);
    assert!(weak.upgrade().is_none());
    let watch = subscription.watch().clone();
    assert_eq!(watch.rows_after(0, 10).1.len(), 1);
    let (file, end) = export.next_chunk();
    assert!(end);
    assert_eq!(exported_keys(&file), expected);
    let weak = Arc::downgrade(&watch);
    drop(watch);
    assert!(weak.upgrade().is_some());
    drop(subscription);
    assert!(weak.upgrade().is_none());
}

#[test]
fn watch_capacity_shares_watches_and_refuses_new_links_while_all_are_active() {
    let options = DashboardOptions {
        watches: 1,
        ..DashboardOptions::default()
    };
    with_dashboard(options, |cx, handle| async move {
        let (mut ends, links) = links(&cx, &handle, 2).await;
        let now = Instant::now();
        let mut first = handle.session();
        let mut second = handle.session();
        call(&mut first, 1, &packets(links[0], 0), now);
        let original = watch_of(&handle, links[0], now);
        call(&mut second, 1, &packets(links[0], 0), now);
        assert!(Arc::ptr_eq(&original, &watch_of(&handle, links[0], now)));
        assert_eq!(handle.0.watches.kept(), [links[0]]);
        assert_eq!(
            text(&call(&mut second, 2, &packets(999, 0), now)),
            r#"{"error":"no such link"}"#
        );
        for id in 3..6 {
            assert_eq!(
                text(&call(&mut second, id, &packets(links[1], 0), now)),
                r#"{"error":"this world has too many watched links"}"#
            );
            assert!(handle.0.watches.existing(links[1], now).is_none());
        }
        first.request(7, r#"{"op":"cancel","id":1}"#, now, None);
        assert!(call(&mut first, 8, &packets(links[1], 0), now).end);
        ends[0].send(ip());
        let shared = watch_of(&handle, links[0], now);
        shared.pump(&handle.0);
        assert_eq!(shared.rows_after(0, 10).1.len(), 1);
        second.request(9, r#"{"op":"cancel","id":1}"#, now, None);
        assert_eq!(handle.0.watches.kept(), [links[0]], "idle history lingers");
        let weak = Arc::downgrade(&original);
        drop((original, shared));
        assert!(weak.upgrade().is_some());
        assert!(!call(&mut first, 10, &packets(links[1], 0), now).end);
        assert!(weak.upgrade().is_none());
        assert_eq!(
            handle.0.watches.kept(),
            [links[1]],
            "admission forgets idle history"
        );
        let file = call(
            &mut second,
            11,
            &format!(r#"{{"op":"pcap","link":"e{}"}}"#, links[0]),
            now,
        );
        assert!(file.binary);
        assert_eq!(&file.bytes[..4], &[0x0a, 0x0d, 0x0d, 0x0a]);
        Ok(())
    });
}

#[test]
fn admission_evicts_longest_idle_watches_first() {
    let options = DashboardOptions {
        watches: 3,
        ..DashboardOptions::default()
    };
    with_dashboard(options, |cx, handle| async move {
        let (_ends, links) = links(&cx, &handle, 5).await;
        let now = Instant::now();
        let mut session = handle.session();
        for (id, link) in links[..3].iter().enumerate() {
            call(&mut session, id as u32 + 1, &packets(*link, 0), now);
        }
        // Release out of link order. Active links are never victims.
        session.request(10, r#"{"op":"cancel","id":3}"#, now, None);
        session.request(11, r#"{"op":"cancel","id":2}"#, now, None);
        assert_eq!(
            text(&call(&mut session, 12, &packets(999, 0), now)),
            r#"{"error":"no such link"}"#
        );
        assert_eq!(handle.0.watches.kept(), links[..3]);
        call(&mut session, 13, &packets(links[3], 0), now);
        assert_eq!(handle.0.watches.kept(), [links[0], links[1], links[3]]);
        call(&mut session, 14, &packets(links[4], 0), now);
        assert_eq!(handle.0.watches.kept(), [links[0], links[3], links[4]]);
        Ok(())
    });
}

#[test]
fn a_zero_watch_limit_refuses_every_link() {
    let options = DashboardOptions {
        watches: 0,
        ..DashboardOptions::default()
    };
    with_dashboard(options, |cx, handle| async move {
        let (_ends, links) = links(&cx, &handle, 1).await;
        let mut session = handle.session();
        let now = Instant::now();
        assert_eq!(
            text(&call(&mut session, 1, &packets(links[0], 0), now)),
            r#"{"error":"this world has too many watched links"}"#
        );
        assert_eq!(
            text(&call(&mut session, 2, &packets(999, 0), now)),
            r#"{"error":"no such link"}"#
        );
        assert!(handle.0.watches.kept().is_empty());
        Ok(())
    });
}

#[test]
fn subscribers_share_a_watch_and_reuse_its_history() {
    with_dashboard(DashboardOptions::default(), |cx, handle| async move {
        let (mut ends, links) = links(&cx, &handle, 1).await;
        let now = Instant::now();
        let mut session = handle.session();
        call(&mut session, 1, &packets(links[0], 0), now);
        call(&mut session, 2, &packets(links[0], 0), now);
        let watch = watch_of(&handle, links[0], now);
        session.request(3, r#"{"op":"cancel","id":1}"#, now, None);
        handle.0.watches.reap(now + LINGER);
        ends[0].send(ip());
        watch.pump(&handle.0);
        assert_eq!(watch.rows_after(0, 10).1.len(), 1);

        session.request(4, r#"{"op":"cancel","id":2}"#, now, None);
        ends[0].send(ip());
        watch.pump(&handle.0);
        assert_eq!(
            watch.rows_after(0, 10).1.len(),
            1,
            "nothing is captured on demand with no subscriber"
        );
        call(&mut session, 5, &packets(links[0], 0), now);
        let resumed = watch_of(&handle, links[0], now);
        assert!(Arc::ptr_eq(&watch, &resumed));
        ends[0].send(ip());
        resumed.pump(&handle.0);
        assert_eq!(resumed.rows_after(0, 10).1.len(), 2);
        Ok(())
    });
}

#[test]
fn an_on_demand_link_captures_only_while_watched() {
    with_dashboard(DashboardOptions::default(), |cx, handle| async move {
        let (mut ends, links) = links(&cx, &handle, 1).await;
        let id = handle.0.collector.find_link(links[0]).unwrap();
        let captured = || handle.0.collector.packets(id, 0, usize::MAX).packets.len();
        ends[0].send(ip());
        assert_eq!(captured(), 0);
        let now = Instant::now();
        let mut session = handle.session();
        call(&mut session, 1, &packets(links[0], 0), now);
        ends[0].send(ip());
        assert_eq!(captured(), 1);
        let values = session.poll(now, None);
        assert_eq!(names(&values), ["packet"]);
        session.request(2, r#"{"op":"cancel","id":1}"#, now, None);
        ends[0].send(ip());
        assert_eq!(captured(), 1);
        // The decoded rows stay for a while, for `packet` and `pcap`.
        assert!(
            call(
                &mut session,
                3,
                &format!(r#"{{"op":"packet","link":"e{}","seq":1}}"#, links[0]),
                now
            )
            .envelope()
            .is_none()
        );
        Ok(())
    });
}

#[test]
fn idle_watches_are_forgotten_after_the_linger() {
    with_dashboard(DashboardOptions::default(), |cx, handle| async move {
        let (_ends, links) = links(&cx, &handle, 1).await;
        let watches = &handle.0.watches;
        let now = Instant::now();
        let mut session = handle.session();
        call(&mut session, 1, &packets(links[0], 0), now);
        session.request(2, r#"{"op":"cancel","id":1}"#, now, None);
        assert!(watches.existing(links[0], now + LINGER / 2).is_some());
        assert!(watches.existing(links[0], now + LINGER).is_none());

        // A client that goes away without saying when starts the linger
        // at the next time a caller gives.
        call(&mut session, 3, &packets(links[0], 0), now);
        drop(session);
        let later = now + LINGER * 3;
        watches.reap(later);
        assert!(watches.existing(links[0], later + LINGER / 2).is_some());
        assert!(watches.existing(links[0], later + LINGER).is_none());

        // A watch with a subscriber is kept however long it runs.
        let mut session = handle.session();
        call(&mut session, 1, &packets(links[0], 0), now);
        let kept = watch_of(&handle, links[0], now);
        assert!(Arc::ptr_eq(
            &watches.existing(links[0], now + LINGER * 10).unwrap(),
            &kept
        ));
        Ok(())
    });
}

#[test]
fn packet_subscribers_report_overruns_once_before_retained_rows() {
    for (limit, bytes, retained) in [(2, ROW_BYTES, 2), (4, 0, 0)] {
        with_dashboard(DashboardOptions::default(), move |cx, handle| async move {
            let (mut ends, links) = links(&cx, &handle, 1).await;
            let now = Instant::now();
            let mut session = handle.session();
            // A new subscriber, a lagging subscriber, and one already caught up.
            for (id, after) in [(1, 0), (2, 1), (3, 4)] {
                call(&mut session, id, &packets(links[0], after), now);
            }
            watch_of(&handle, links[0], now).set_limits(limit, bytes);
            for _ in 0..4 {
                ends[0].send(ip());
            }
            let mut values = session.poll(now, None).into_iter();
            for (id, after) in [(1, 0), (2, 1)] {
                let gap = values.next().unwrap();
                assert_eq!(gap.id, id);
                let next = 5 - retained;
                let missed = next - after - 1;
                assert_eq!(
                    text(&gap),
                    format!(
                        r#"{{"event":"gap","data":{{"stream":"packets:{}","class":null,"after":{after},"next":{next},"missed":{missed}}}}}"#,
                        links[0]
                    )
                );
                for seq in next..=4 {
                    let packet = values.next().unwrap();
                    assert_eq!(packet.id, id);
                    assert!(
                        text(&packet)
                            .starts_with(&format!(r#"{{"event":"packet","data":{{"seq":{seq},"#))
                    );
                }
            }
            assert!(values.next().is_none());
            // Even an entirely evicted batch advances each subscriber's cursor.
            assert!(session.poll(now + Duration::from_secs(1), None).is_empty());
            Ok(())
        });
    }
}

#[test]
fn a_custom_registry_reaches_watch_json() {
    let mut registry = Registry::new();
    registry.register(
        "custom",
        |s| {
            if s.ports.0 == 9000 || s.ports.1 == 9000 {
                Match::Yes
            } else {
                Match::No
            }
        },
        |_| {
            [
                crate::protocols::Modbus::new(true),
                crate::protocols::Modbus::new(false),
            ]
        },
    );
    let options = DashboardOptions {
        protocols: registry,
        ..DashboardOptions::default()
    };
    with_dashboard(options, |cx, handle| async move {
        let (mut ends, links) = links(&cx, &handle, 1).await;
        let now = Instant::now();
        let mut session = handle.session();
        call(&mut session, 1, &packets(links[0], 0), now);
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&52u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20..22].copy_from_slice(&40000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&9000u16.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x18;
        packet.extend_from_slice(&[0, 7, 0, 0, 0, 6, 1, 3, 0, 2, 0, 1]);
        ends[0].send(Packet(packet));
        let values = session.poll(now, None);
        assert_eq!(names(&values), ["packet"]);
        assert!(text(&values[0]).contains(r#""proto":"Modbus/TCP""#));
        let detail = text(&call(
            &mut session,
            2,
            &format!(r#"{{"op":"packet","link":"e{}","seq":1}}"#, links[0]),
            now,
        ));
        assert!(detail.contains(r#""buf":0,"range":[40,52]"#), "{detail}");
        assert!(detail.contains("address 2, quantity 1"), "{detail}");
        Ok(())
    });
}

/// The decoded size of one `ip()` row, measured on a dashboard of its own.
fn row_bytes() -> usize {
    let dashboard = with_dashboard(startup(Options::default()), |cx, handle| async move {
        let (mut ends, links) = links(&cx, &handle, 1).await;
        let mut session = handle.session();
        call(&mut session, 1, &packets(links[0], 0), Instant::now());
        ends[0].send(ip());
        session.poll(Instant::now(), None);
        Ok(())
    });
    dashboard.handle().0.watches.total()
}

#[test]
fn the_aggregate_budget_forgets_idle_watches_first_then_the_oldest_rows() {
    let row = row_bytes();
    assert!(row > 0);
    let options = DashboardOptions {
        watch_bytes: 4 * row + row / 2,
        ..startup(Options::default())
    };
    with_dashboard(options, move |cx, handle| async move {
        let (mut ends, links) = links(&cx, &handle, 2).await;
        let (active, idle) = (links[0], links[1]);
        let now = Instant::now();
        let mut session = handle.session();
        let mut lagging = handle.session();
        call(&mut session, 1, &packets(active, 0), now);
        call(&mut lagging, 1, &packets(active, 0), now);
        for _ in 0..2 {
            ends[0].send(ip());
        }
        assert_eq!(session.poll(now, None).len(), 2);

        // The idle watch's rows are newer than the active watch's.
        call(&mut session, 2, &packets(idle, 0), now);
        for _ in 0..2 {
            ends[2].send(ip());
        }
        assert_eq!(session.poll(now + PACKET_TICK, None).len(), 2);
        session.request(3, r#"{"op":"cancel","id":2}"#, now, None);
        assert_eq!(handle.0.watches.total(), 4 * row);

        ends[0].send(ip());
        assert_eq!(
            names(&session.poll(now + 2 * PACKET_TICK, None)),
            ["packet"]
        );
        assert_eq!(handle.0.watches.kept(), [active]);
        assert_eq!(handle.0.watches.total(), 3 * row);
        assert_eq!(
            text(&call(
                &mut session,
                4,
                &format!(r#"{{"op":"packet","link":"e{idle}","seq":1}}"#),
                now
            )),
            r#"{"error":"nothing is watching that link"}"#
        );

        for _ in 0..2 {
            ends[0].send(ip());
        }
        assert_eq!(session.poll(now + 3 * PACKET_TICK, None).len(), 2);
        assert_eq!(handle.0.watches.total(), 4 * row);
        let values = lagging.poll(now, None);
        assert_eq!(
            names(&values),
            ["gap", "packet", "packet", "packet", "packet"]
        );
        assert_eq!(
            text(&values[0]),
            format!(
                r#"{{"event":"gap","data":{{"stream":"packets:{}","class":null,"after":0,"next":2,"missed":1}}}}"#,
                active
            )
        );
        Ok(())
    });
}

#[test]
fn a_late_watch_of_a_startup_link_sees_packets_from_before_it() {
    with_dashboard(
        DashboardOptions {
            collector: crate::Options::default(),
            ..Default::default()
        },
        |cx, handle| async move {
            let (attacher, mut attachments) = fictionet::attachments();
            let mut sandbox = attacher.attach("guest").unwrap();
            let mut attachment = attachments.next(&cx).await?;
            for _ in 0..3 {
                sandbox.send(ip());
                attachment.recv(&cx).await?;
            }
            cx.yield_now().await?;
            let link = handle
                .0
                .collector
                .topology()
                .links
                .keys()
                .next()
                .unwrap()
                .get();
            let now = Instant::now();
            let mut session = handle.session();
            let start = call(&mut session, 1, &packets(link, 0), now);
            assert!(text(&start).contains(r#""b":"s"#), "{}", text(&start));
            let values = session.poll(now, None);
            assert_eq!(names(&values), ["packet", "packet", "packet"]);
            assert!(text(&values[0]).contains(r#""side":1,"#));
            Ok(())
        },
    );
}

#[test]
fn a_capture_of_a_detached_sandbox_stays_readable() {
    let dashboard = with_dashboard(
        DashboardOptions {
            collector: crate::Options::default(),
            ..Default::default()
        },
        |cx, _| async move {
            let (attacher, mut attachments) = fictionet::attachments();
            let mut sandbox = attacher.attach("guest").unwrap();
            let mut attachment = attachments.next(&cx).await?;
            for _ in 0..3 {
                sandbox.send(ip());
                attachment.recv(&cx).await?;
            }
            drop((sandbox, attachment));
            cx.yield_now().await?;
            Ok(())
        },
    );
    let handle = dashboard.handle();
    assert!(handle.0.collector.topology().links.is_empty());
    let link = handle.0.collector.find_link(1).unwrap().get();
    let now = Instant::now();
    let mut session = handle.session();
    let start = call(&mut session, 1, &packets(link, 0), now);
    assert_eq!(
        text(&start),
        format!(r#"{{"event":"link","data":{{"id":"e{link}","a":null,"b":null,"label":null}}}}"#)
    );
    let values = session.poll(now, None);
    assert_eq!(names(&values), ["packet", "packet", "packet", "end"]);
    assert!(text(&values[3]).contains("the link closed"));
    let detail = call(
        &mut session,
        2,
        &format!(r#"{{"op":"packet","link":"e{link}","seq":3}}"#),
        now,
    );
    assert!(text(&detail).starts_with(r#"{"seq":3,"#));
    let file = download(&mut session, 3, link, now);
    assert_eq!(&file[..4], &[0x0a, 0x0d, 0x0d, 0x0a]);
}
