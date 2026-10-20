use super::*;
use fictionet::events::{ConnInfo, GroupId, KeyMeta, LinkType, PacketRef, Side, TaskId};
use fictionet::time::ms;
use fictionet::{Interface, InterfaceExt, Packet, RunOptions, Seed, block_on, lab};

pub(crate) fn policy(classes: impl IntoIterator<Item = Class>) -> Arc<dyn Policy> {
    let mut policy = crate::policy::Standard::default();
    for class in classes {
        for existing in &mut policy.classes {
            if existing.name == class.name {
                *existing = class;
            }
        }
    }
    Arc::new(policy)
}

fn evictions(batch: &PacketBatch) -> u64 {
    batch.evicted.iter().map(|(_, count)| count).sum()
}

fn with_link(
    options: Options,
    test: impl FnOnce(Arc<Collector>, LinkId) + Send + 'static,
) -> Arc<Collector> {
    let collector = Arc::new(Collector::with_options(options));
    let reader = collector.clone();
    block_on(lab(
        RunOptions::new(Seed::from_u64(3)).observer(collector.clone()),
        move |cx| async move {
            let (mut a, _b) = fictionet::pair();
            a = cx.tap("test", a);
            cx.yield_now().await?;
            let id = *reader.topology().links.keys().next().unwrap();
            test(reader, id);
            a.send(Packet(vec![0; 1]));
            Ok(())
        },
    ))
    .unwrap();
    collector
}

fn packet(collector: &Collector, link: LinkId, seq: u64, at: Instant, bytes: &[u8]) {
    collector.observe(
        Stamp {
            stream: Stream::Packets(link),
            seq,
            at,
        },
        Observation::Packet(PacketRef {
            link,
            tap: "test",
            sandbox: None,
            side: Side::A,
            len: bytes.len(),
            link_type: LinkType::Ip,
            bytes,
        }),
    );
}

fn count(collector: &Collector, stream: Stream, reason: LossReason) -> u64 {
    collector
        .losses()
        .streams
        .iter()
        .filter(|loss| loss.stream == stream && loss.reason == reason)
        .map(|loss| loss.count)
        .sum()
}

#[test]
fn sampling_uses_run_time_and_keeps_stream_sequences() {
    with_link(
        Options {
            policy: policy([Class::new("packets")
                .count(4096)
                .bytes(8 << 20)
                .snap(65_535)
                .burst(64)]),
            ..Options::default()
        },
        |collector, link| {
            for seq in 1..=1000 {
                packet(&collector, link, seq, Instant::ZERO, &[1]);
            }
            let copies = collector.packets(link, 0, usize::MAX);
            assert_eq!(evictions(&copies), 0);
            assert_eq!(copies.packets.len(), 128);
            assert_eq!(
                copies.packets[..64]
                    .iter()
                    .map(|p| p.stamp.seq)
                    .collect::<Vec<_>>(),
                (1..=64).collect::<Vec<_>>()
            );
            assert_eq!(copies.packets[64].stamp.seq, 65);
            assert_eq!(copies.packets[65].stamp.seq, 67);
            assert_eq!(copies.packets[66].stamp.seq, 69);
            assert_eq!(
                copies.packets.iter().filter(|p| p.stamp.seq <= 256).count(),
                64 + 32 + 16 + 8
            );
            assert_eq!(copies.packets[65].skipped, 1);
            assert_eq!(
                count(&collector, Stream::Packets(link), LossReason::Sampling),
                872
            );
            packet(&collector, link, 1001, Instant::ZERO + ms(100), &[2]);
            let next = collector.packets(link, copies.cursor, 1);
            assert_eq!(next.packets[0].stamp.seq, 1001);
            assert_eq!(
                next.packets[0].skipped,
                1000 - copies.packets.last().unwrap().stamp.seq
            );
        },
    );
}

#[test]
fn packet_bounds_and_snap_length_report_separate_losses() {
    for bounds in [
        Bounds {
            count: 2,
            bytes: 100,
        },
        Bounds {
            count: 100,
            bytes: 8,
        },
    ] {
        with_link(
            Options {
                policy: policy([Class::new("packets")
                    .count(bounds.count)
                    .bytes(bounds.bytes)
                    .snap(4)
                    .burst(64)]),
                ..Options::default()
            },
            |collector, link| {
                for seq in 1..=5 {
                    packet(&collector, link, seq, Instant::ZERO, &[7; 10]);
                }
                let batch = collector.packets(link, 0, 10);
                assert_eq!(evictions(&batch), 3);
                assert_eq!(batch.cursor, 5);
                assert_eq!(
                    batch
                        .packets
                        .iter()
                        .map(|p| p.stamp.seq)
                        .collect::<Vec<_>>(),
                    [4, 5]
                );
                assert!(
                    batch
                        .packets
                        .iter()
                        .all(|p| p.original_len == 10 && p.bytes.len() == 4)
                );
                assert_eq!(
                    count(&collector, Stream::Packets(link), LossReason::Truncation),
                    5
                );
                assert_eq!(
                    count(&collector, Stream::Packets(link), LossReason::Eviction),
                    3
                );
                let first = collector.packets(link, 0, 1);
                assert_eq!(evictions(&first), 3);
                assert_eq!(first.packets.len(), 1);
                assert_eq!(first.packets[0].stamp.seq, 4);
                assert_eq!(first.packets[0].skipped, 0);
                let last = collector.packets(link, 4, 10);
                assert_eq!(evictions(&last), 3);
                assert_eq!(last.packets.len(), 1);
                assert_eq!(last.packets[0].stamp.seq, 5);
                for after in [5, u64::MAX] {
                    let batch = collector.packets(link, after, 10);
                    assert!(batch.packets.is_empty());
                }
            },
        );
    }
}

#[test]
fn demand_opens_watched_classes_and_is_counted_per_link() {
    for when in [When::Always, When::Watched] {
        let mut class = Class::new("packets").count(4096).bytes(8 << 20);
        class.when = when;
        with_link(
            Options {
                policy: policy([class]),
                ..Options::default()
            },
            move |collector, link| {
                let interest = Interest::Packet(PacketRef {
                    link,
                    tap: "test",
                    sandbox: None,
                    side: Side::A,
                    len: 1,
                    bytes: &[0],
                    link_type: LinkType::Ip,
                });
                assert_eq!(collector.enabled(interest), when == When::Always);
                let first = collector.capture_demand(link).unwrap();
                let second = collector.capture_demand(link).unwrap();
                assert!(collector.enabled(interest));
                drop(first);
                assert!(collector.enabled(interest));
                drop(second);
                assert_eq!(collector.enabled(interest), when == When::Always);
            },
        );
    }
    with_link(
        Options {
            policy: <dyn Policy>::events(),
            ..Options::default()
        },
        |collector, link| {
            let _demand = collector.capture_demand(link);
            packet(&collector, link, 1, Instant::ZERO, &[0]);
            assert!(collector.packets(link, 0, 10).packets.is_empty());
        },
    );
}

#[test]
fn aggregate_pressure_evicts_the_largest_ring_first() {
    let collector = Arc::new(Collector::with_options(Options {
        policy: policy([Class::new("packets")
            .count(4096)
            .bytes(8 << 20)
            .snap(65_535)
            .burst(64)]),
        bytes: 6,
        ..Options::default()
    }));
    let reader = collector.clone();
    block_on(lab(
        RunOptions::new(Seed::from_u64(7)).observer(collector),
        move |cx| async move {
            let (a, _b) = fictionet::pair();
            let (c, _d) = fictionet::pair();
            let _a = cx.tap("a", a);
            let _c = cx.tap("b", c);
            cx.yield_now().await?;
            let links: Vec<_> = reader.topology().links.keys().copied().collect();
            packet(&reader, links[0], 1, Instant::ZERO, &[0; 1]);
            packet(&reader, links[1], 1, Instant::ZERO, &[1; 4]);
            packet(&reader, links[0], 2, Instant::ZERO, &[2; 2]);
            assert_eq!(evictions(&reader.packets(links[0], 0, 10)), 0);
            assert_eq!(evictions(&reader.packets(links[1], 0, 10)), 1);
            assert_eq!(
                reader
                    .packets(links[0], 0, 10)
                    .packets
                    .iter()
                    .map(|copy| copy.bytes.to_vec())
                    .collect::<Vec<_>>(),
                [vec![0; 1], vec![2; 2]]
            );
            assert!(reader.packets(links[1], 0, 10).packets.is_empty());
            assert_eq!(
                count(&reader, Stream::Packets(links[1]), LossReason::Eviction),
                1
            );
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn key_count_and_byte_bounds_preserve_redaction_and_keylog() {
    for bounds in [
        Bounds {
            count: 2,
            bytes: 8192,
        },
        Bounds {
            count: 20,
            bytes: 2 * (size_of::<Key>() + 13 + 2 + 3),
        },
    ] {
        let collector = Arc::new(Collector::with_options(Options {
            policy: policy([Class::new("keys").count(bounds.count).bytes(bounds.bytes)]),
            ..Options::default()
        }));
        let reader = collector.clone();
        block_on(lab(
            RunOptions::new(Seed::from_u64(1)).observer(collector.clone()),
            move |cx| async move {
                let logger = cx.tls_key_log(None).unwrap();
                for _ in 0..4 {
                    logger.log("CLIENT_RANDOM", &[0, 255], &[128, 1, 2]);
                }
                assert_eq!(reader.keys().len(), 2);
                assert_eq!(reader.keys()[0].stamp.seq, 3);
                assert_eq!(reader.keys()[0].secret(), &[128, 1, 2]);
                assert!(!format!("{:?}", reader.keys()).contains("128, 1, 2"));
                assert_eq!(reader.keylog(), "CLIENT_RANDOM 00ff 800102\n".repeat(2));
                Ok(())
            },
        ))
        .unwrap();
        assert_eq!(count(&collector, Stream::Keys, LossReason::Eviction), 2);
    }
    let collector = Arc::new(Collector::with_options(Options {
        policy: policy([Class::new("keys").count(10).bytes(1)]),
        ..Options::default()
    }));
    block_on(lab(
        RunOptions::new(Seed::from_u64(1)).observer(collector.clone()),
        |cx| async move {
            cx.tls_key_log(None)
                .unwrap()
                .log("CLIENT_RANDOM", &[0], &[1]);
            Ok(())
        },
    ))
    .unwrap();
    assert!(collector.keys().is_empty());
    assert_eq!(count(&collector, Stream::Keys, LossReason::Overflow), 1);
    assert!(
        !Collector::with_options(Options {
            policy: <dyn Policy>::events(),
            ..Options::default()
        })
        .enabled(Interest::TlsKey(KeyMeta {
            label: "test",
            connection: Some(&ConnInfo::default())
        }))
    );
}

#[test]
fn topology_bounds_and_unicode_truncation_remain_visible() {
    let collector = Arc::new(Collector::with_options(Options {
        topology: TopologyLimits {
            groups: 2,
            name_bytes: 5,
            ..TopologyLimits::default()
        },
        ..Options::default()
    }));
    let reader = collector.clone();
    block_on(lab(
        RunOptions::new(Seed::from_u64(1)).observer(collector.clone()),
        move |cx| async move {
            let groups: Vec<_> = (0..10).map(|_| cx.group("éééé")).collect();
            cx.yield_now().await?;
            let snapshot = reader.topology();
            assert_eq!(snapshot.groups.len(), 2);
            assert!(snapshot.groups.values().all(|group| group.name == "éé"));
            assert_eq!(snapshot.refused, 8);
            assert!(snapshot.incomplete);
            assert!(snapshot.truncated_bytes >= 8);
            drop(groups);
            cx.yield_now().await?;
            let removed = reader.topology();
            assert!(removed.groups.is_empty());
            assert!(removed.revision > snapshot.revision);
            assert_eq!(removed.missing, 8);
            Ok(())
        },
    ))
    .unwrap();
    assert!(collector.ended().is_some());
}

fn world_snapshot() -> (String, Vec<PacketCopy>) {
    let collector = Arc::new(Collector::with_options(Options {
        policy: policy([Class::new("packets")
            .count(4096)
            .bytes(8 << 20)
            .snap(65_535)
            .burst(64)]),
        ..Options::default()
    }));
    let reader = collector.clone();
    let result = Arc::new(Mutex::new(None));
    let saved = result.clone();
    let snapshots = result.clone();
    let (attacher, mut attachments) = fictionet::attachments();
    let mut sandbox = attacher.attach("guest").unwrap();
    block_on(lab(
        RunOptions::new(Seed::from_u64(7)).observer(collector.clone()),
        move |cx| async move {
            let group = cx.group("network");
            let host = group.host("machine");
            let (mut a, mut b) = fictionet::pair();
            a = cx.tap("uplink", a);
            let observed = reader.clone();
            let task = host.spawn(move |cx| async move {
                let packet = b.recv(&cx).await?;
                b.send(packet);
                let reader = observed;
                let snapshot = reader.topology();
                assert_eq!(snapshot.groups.len(), 2);
                assert_eq!(snapshot.hosts.len(), 2);
                assert_eq!(snapshot.links.len(), 2);
                assert!(snapshot.tasks.len() >= 2);
                assert!(!snapshot.incomplete, "{snapshot:?}");
                let link = *snapshot
                    .links
                    .iter()
                    .find(|(_, link)| link.tap == "uplink")
                    .unwrap()
                    .0;
                assert_eq!(
                    reader.topology().counters()[&link][0],
                    fictionet::events::Counts {
                        packets: 1,
                        bytes: 12
                    }
                );
                let copies = reader.packets(link, 0, 100).packets;
                assert_eq!(copies.len(), 2);
                *saved.lock() = Some((snapshot, copies));
                Ok(())
            });
            let mut attachment = attachments.next(&cx).await?;
            sandbox.send(Packet(vec![7; 3]));
            attachment.recv(&cx).await?;
            a.send(Packet(vec![1; 12]));
            cx.yield_now().await?;
            assert_eq!(a.recv(&cx).await?, Packet(vec![1; 12]));
            let snapshot = snapshots.lock().as_ref().unwrap().0.clone();
            task.join(&cx).await?;
            drop(a);
            drop(attachment);
            drop(sandbox);
            drop(host);
            drop(group);
            cx.yield_now().await?;
            assert!(reader.topology().links.is_empty());
            assert!(reader.topology().revision > snapshot.revision);
            Ok(())
        },
    ))
    .unwrap();
    let (snapshot, copies) = result.lock().take().unwrap();
    (format!("{snapshot:?}"), copies)
}

#[test]
fn lab_topology_and_capture_repeat_and_removal_is_visible() {
    assert_eq!(world_snapshot(), world_snapshot());
}

#[test]
fn spawned_tasks_remain_visible_after_their_parent_ends() {
    let collector = Arc::new(Collector::with_options(Options::default()));
    let reader = collector.clone();
    block_on(lab(
        RunOptions::new(Seed::from_u64(7)).observer(collector.clone()),
        move |cx| async move {
            cx.spawn(move |_| async move {
                let snapshot = reader.topology();
                assert_eq!(
                    snapshot
                        .tasks
                        .iter()
                        .map(|(id, task)| (
                            id.get(),
                            task.parent.map(TaskId::get),
                            task.group.map(GroupId::get),
                        ))
                        .collect::<Vec<_>>(),
                    [(2, None, None), (3, None, Some(1))]
                );
                assert_eq!(snapshot.groups.len(), 1);
                let (id, group) = snapshot.groups.first_key_value().unwrap();
                assert_eq!((id.get(), group.name.as_str()), (1, "children"));
                assert_eq!(snapshot.missing, 0);
                assert_eq!(snapshot.refused, 0);
                assert!(!snapshot.incomplete);
                Ok(())
            });
            cx.group("children").spawn(|_| async { Ok(()) });
            Ok(())
        },
    ))
    .unwrap();
    let snapshot = collector.topology();
    assert!(snapshot.tasks.is_empty());
    assert!(snapshot.groups.is_empty());
    assert_eq!(snapshot.missing, 0);
    assert_eq!(snapshot.refused, 0);
    assert!(!snapshot.incomplete);
    assert!(collector.losses().streams.is_empty());
}

#[test]
fn connection_bindings_follow_hosts_and_release_their_budget() {
    let collector = Arc::new(Collector::with_options(Options {
        topology: TopologyLimits {
            connections: 1,
            name_bytes: 8,
            ..TopologyLimits::default()
        },
        ..Options::default()
    }));
    let reader = collector.clone();
    block_on(lab(
        RunOptions::new(Seed::from_u64(2)).observer(collector),
        move |cx| async move {
            let host = cx.host("server");
            let first = ConnInfo::new(
                1,
                "10.0.0.1:443".parse().unwrap(),
                "10.0.0.2:5000".parse().unwrap(),
            )
            .over_tls(Some("example.test"), Some(b"h2"));
            let second = ConnInfo::new(
                2,
                "10.0.0.1:443".parse().unwrap(),
                "10.0.0.2:5001".parse().unwrap(),
            );
            host.connection_opened(&first);
            host.connection_opened(&second);
            cx.yield_now().await?;
            let snapshot = reader.topology();
            assert_eq!(snapshot.connections.len(), 1);
            let binding = &snapshot.connections[0];
            assert_eq!(binding.conn.sni.as_deref(), Some("example."));
            assert_eq!(binding.conn.alpn.as_deref(), Some(b"h2".as_slice()));
            assert_eq!(binding.host, snapshot.hosts.keys().next().copied());
            assert!(snapshot.tasks.contains_key(&binding.task.unwrap()));
            assert_eq!(snapshot.refused, 1);
            assert_eq!(snapshot.truncated_bytes, 4);
            host.connection_closed(&first);
            host.connection_opened(&second);
            cx.yield_now().await?;
            let snapshot = reader.topology();
            assert_eq!(snapshot.connections.len(), 1);
            assert_eq!(snapshot.connections[0].conn, second);
            host.connection_closed(&second);
            cx.yield_now().await?;
            assert!(reader.topology().connections.is_empty());
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn topology_byte_bounds_and_missing_references_are_counted() {
    let collector = Arc::new(Collector::with_options(Options {
        topology: TopologyLimits {
            bytes: 0,
            ..TopologyLimits::default()
        },
        ..Options::default()
    }));
    let reader = collector.clone();
    block_on(lab(
        RunOptions::new(Seed::from_u64(4)).observer(collector),
        move |cx| async move {
            let host = cx.host("machine");
            let (a, _b) = fictionet::pair();
            let _a = cx.tap("label", a);
            cx.yield_now().await?;
            let snapshot = reader.topology();
            assert!(snapshot.tasks.is_empty());
            assert!(snapshot.groups.is_empty());
            assert!(snapshot.hosts.is_empty());
            assert!(snapshot.links.is_empty());
            assert!(snapshot.refused >= 2);
            assert!(snapshot.missing >= 2);
            assert!(snapshot.incomplete);
            drop(host);
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn producer_losses_and_exhausted_loss_detail_remain_queryable() {
    let collector = Collector::with_options(Options {
        loss_streams: 1,
        ..Options::default()
    });
    for (stream, reason) in [
        (Stream::Events, LossReason::Staging),
        (Stream::Keys, LossReason::Overflow),
        (Stream::Topology, LossReason::Staging),
        (Stream::Keys, LossReason::Truncation),
    ] {
        collector.lost(Loss {
            stream,
            reason,
            count: 3,
            bytes: Some(10),
            seqs: Some(1..=3),
        });
    }
    let status = collector.losses();
    assert_eq!(status.streams.len(), 1);
    assert_eq!(status.streams[0].count, 3);
    assert_eq!(status.untracked.len(), 3);
    assert_eq!(
        status.untracked.iter().map(|loss| loss.count).sum::<u64>(),
        9
    );
    assert!(collector.topology().incomplete);
    assert_eq!(collector.events().checked_all().unwrap_err().lost, 3);
    collector.end(Instant::ZERO + ms(10));
    collector.end(Instant::ZERO + ms(20));
    assert_eq!(collector.ended(), Some(Instant::ZERO + ms(10)));
}

#[test]
fn packet_interest_does_not_take_the_collector_lock() {
    with_link(
        Options {
            policy: policy([Class::new("packets")
                .count(4096)
                .bytes(8 << 20)
                .snap(65_535)
                .burst(64)]),
            ..Options::default()
        },
        |collector, link| {
            let _state = collector.state.lock();
            assert!(collector.enabled(Interest::Packet(PacketRef {
                link,
                tap: "test",
                sandbox: None,
                side: Side::A,
                len: 1,
                bytes: &[0],
                link_type: LinkType::Ip
            })));
        },
    );
}

#[test]
fn event_retention_separates_noise_and_reports_each_loss_cause() {
    use fictionet::events::{Event, Fields};
    let collector = Collector::with_options(Options {
        policy: policy([
            Class::new("events").count(2).bytes(8192),
            Class::new("noise").count(1).bytes(8192),
        ]),
        ..Options::default()
    });
    for (index, event) in [
        Event::new("shop", "order"),
        Event::new("net", "drop").repeat(Fields::new()),
        Event::new("net", "drop").repeat(Fields::new()),
        Event::new("shop", "order").truncated(),
    ]
    .iter()
    .enumerate()
    {
        collector.observe(
            Stamp {
                stream: Stream::Events,
                seq: index as u64 + 1,
                at: Instant::ZERO,
            },
            Observation::Event(event),
        );
    }
    assert_eq!(
        collector
            .events()
            .after(0, 10)
            .iter()
            .map(|event| event.seq)
            .collect::<Vec<_>>(),
        [1, 3, 4]
    );
    assert_eq!(count(&collector, Stream::Events, LossReason::Eviction), 1);
    assert_eq!(count(&collector, Stream::Events, LossReason::Truncation), 1);
    let mut event = Event::new("shop", "huge");
    event.summary = "x".repeat(9000);
    collector.observe(
        Stamp {
            stream: Stream::Events,
            seq: 5,
            at: Instant::ZERO,
        },
        Observation::Event(&event),
    );
    assert_eq!(count(&collector, Stream::Events, LossReason::Overflow), 1);
}

#[test]
fn an_oversized_copy_reports_overflow_and_preserves_retained_copies() {
    with_link(
        Options {
            policy: policy([Class::new("packets").count(2).bytes(4)]),
            ..Options::default()
        },
        |collector, link| {
            packet(&collector, link, 1, Instant::ZERO, &[0; 4]);
            packet(&collector, link, 2, Instant::ZERO, &[0; 8]);
            let batch = collector.packets(link, 0, 10);
            assert_eq!(evictions(&batch), 0);
            assert_eq!(batch.cursor, 1);
            assert_eq!(batch.packets.len(), 1);
            assert_eq!(batch.packets[0].stamp.seq, 1);
            assert_eq!(collector.packets(link, 1, 10).cursor, 2);
            packet(&collector, link, 3, Instant::ZERO, &[1; 4]);
            let batch = collector.packets(link, 2, 10);
            assert_eq!(evictions(&batch), 1);
            assert_eq!(batch.packets[0].stamp.seq, 3);
            assert_eq!(batch.packets[0].omissions, 2);
            assert_eq!(
                count(&collector, Stream::Packets(link), LossReason::Overflow),
                1
            );
        },
    );
}

#[test]
fn waking_an_event_reader_can_inspect_the_collector() {
    use fictionet::events::Event;
    use std::future::Future;
    use std::task::{Context, Wake, Waker};
    struct Reader(Arc<Collector>);
    impl Wake for Reader {
        fn wake(self: Arc<Self>) {
            let _ = self.0.losses();
        }
    }
    let collector = Arc::new(Collector::default());
    block_on(lab(
        RunOptions::new(Seed::from_u64(2)),
        move |cx| async move {
            let mut wait = Box::pin(collector.events().wait(&cx, 0, 2, ms(100), |_| true));
            let waker = Waker::from(Arc::new(Reader(collector.clone())));
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            collector.observe(
                Stamp {
                    stream: Stream::Events,
                    seq: 1,
                    at: Instant::ZERO,
                },
                Observation::Event(&Event::new("test", "ready")),
            );
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            collector.lost(Loss::staged(Stream::Events, 1));
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_ready()
            );
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn a_first_packet_is_classified_before_topology_arrives() {
    let source = Arc::new(Collector::default());
    let reader = source.clone();
    block_on(lab(
        RunOptions::new(Seed::from_u64(5)).observer(source),
        move |cx| async move {
            let (a, _b) = fictionet::pair();
            let (c, _d) = fictionet::pair();
            let _a = cx.tap("first", a);
            let _c = cx.tap("second", c);
            cx.yield_now().await?;
            let snapshot = reader.topology();
            let links: Vec<_> = snapshot.links.iter().collect();
            let collector = Collector::default();
            for (index, (id, _)) in links.iter().enumerate() {
                let packet = PacketRef {
                    link: **id,
                    tap: if index == 0 { "first" } else { "second" },
                    sandbox: (index == 0).then_some("guest"),
                    side: Side::A,
                    len: 1,
                    link_type: LinkType::Ip,
                    bytes: &[7],
                };
                assert_eq!(collector.enabled(Interest::Packet(packet)), index == 0);
                collector.observe(
                    Stamp {
                        stream: Stream::Packets(**id),
                        seq: 1,
                        at: Instant::ZERO,
                    },
                    Observation::Packet(packet),
                );
            }
            assert!(collector.topology().links.is_empty());
            assert_eq!(collector.packets(*links[0].0, 0, 10).packets.len(), 1);
            assert!(collector.packets(*links[1].0, 0, 10).packets.is_empty());
            for (index, (id, link)) in links.iter().enumerate() {
                collector.observe(
                    Stamp {
                        stream: Stream::Topology,
                        seq: index as u64 + 1,
                        at: Instant::ZERO,
                    },
                    Observation::Topology(TopologyRef::LinkAdded {
                        link: **id,
                        creator: None,
                        host: None,
                        sandbox: None,
                        counters: link.counters.clone(),
                    }),
                );
            }
            let batch = collector.packets(*links[0].0, 0, 10);
            assert_eq!(batch.packets.len(), 1);
            assert_eq!(batch.packets[0].bytes.as_ref(), &[7]);
            assert_eq!(&*batch.packets[0].tap, "first");
            assert_eq!(batch.packets[0].class, 3);
            assert!(collector.packets(*links[1].0, 0, 10).packets.is_empty());
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn removed_captures_stay_readable_and_evict_before_active_captures() {
    let collector = Arc::new(Collector::with_options(Options {
        policy: policy([Class::new("packets")
            .count(4096)
            .bytes(8 << 20)
            .snap(65_535)
            .burst(64)]),
        bytes: 6,
        ..Options::default()
    }));
    let reader = collector.clone();
    block_on(lab(
        RunOptions::new(Seed::from_u64(7)).observer(collector),
        move |cx| async move {
            let (a, _b) = fictionet::pair();
            let (mut c, d) = fictionet::pair();
            let _a = cx.tap("active", a);
            c = cx.tap("removed", c);
            cx.yield_now().await?;
            let links: Vec<_> = reader.topology().links.keys().copied().collect();
            packet(&reader, links[0], 1, Instant::ZERO, &[1; 3]);
            packet(&reader, links[1], 1, Instant::ZERO, &[2; 3]);
            drop((c, d));
            cx.yield_now().await?;
            assert!(!reader.topology().links.contains_key(&links[1]));
            assert_eq!(
                reader.packets(links[1], 0, 10).packets[0].bytes.as_ref(),
                &[2; 3]
            );
            packet(&reader, links[0], 2, Instant::ZERO, &[3; 3]);
            assert_eq!(reader.packets(links[0], 0, 10).packets.len(), 2);
            assert_eq!(evictions(&reader.packets(links[1], 0, 10)), 1);
            assert!(reader.packets(links[1], 0, 10).packets.is_empty());
            assert_eq!(
                count(&reader, Stream::Packets(links[1]), LossReason::Eviction),
                1
            );
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn removed_capture_metadata_keeps_the_link_count_bound() {
    let collector = Arc::new(Collector::with_options(Options {
        policy: policy([Class::new("packets")
            .count(4096)
            .bytes(8 << 20)
            .snap(65_535)
            .burst(64)]),
        topology: TopologyLimits {
            links: 2,
            ..TopologyLimits::default()
        },
        ..Options::default()
    }));
    let reader = collector.clone();
    block_on(lab(
        RunOptions::new(Seed::from_u64(8)).observer(collector),
        move |cx| async move {
            let mut previous = Vec::new();
            for _ in 0..8 {
                let (mut a, b) = fictionet::pair();
                a = cx.tap("short link", a);
                cx.yield_now().await?;
                let link = *reader.topology().links.keys().next().unwrap();
                packet(&reader, link, 1, Instant::ZERO, &[0]);
                previous.push(link);
                assert!(reader.state.lock().captures.links.len() <= 2);
                drop((a, b));
                cx.yield_now().await?;
                assert_eq!(reader.packets(link, 0, 1).packets.len(), 1);
            }
            assert!(reader.packets(previous[0], 0, 1).packets.is_empty());
            assert_eq!(reader.packets(previous[6], 0, 1).packets.len(), 1);
            assert_eq!(reader.packets(previous[7], 0, 1).packets.len(), 1);
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn aggregation_preserves_packets_keys_topology_and_loss() {
    let collector = Arc::new(Collector::with_options(Options {
        policy: policy([Class::new("packets")
            .count(4096)
            .bytes(8 << 20)
            .snap(65_535)
            .burst(64)]),
        ..Options::default()
    }));
    let aggregate = Arc::new(crate::Aggregate::new(collector.clone()));
    let reader = collector.clone();
    let destination = aggregate.clone();
    block_on(lab(
        RunOptions::new(Seed::from_u64(7)).observer(aggregate),
        move |cx| async move {
            let (mut a, mut b) = fictionet::pair();
            a = cx.tap("collected", a);
            a.send(Packet(vec![1, 2, 3]));
            assert_eq!(b.recv(&cx).await?.0, [1, 2, 3]);
            cx.yield_now().await?;
            let link = *reader.topology().links.keys().next().unwrap();
            assert_eq!(
                reader.packets(link, 0, 10).packets[0].bytes.as_ref(),
                [1, 2, 3]
            );
            cx.tls_key_log(None)
                .unwrap()
                .log("CLIENT_RANDOM", &[0], &[1]);
            assert_eq!(reader.keylog(), "CLIENT_RANDOM 00 01\n");
            destination.lost(Loss {
                stream: Stream::Packets(link),
                reason: LossReason::Staging,
                count: 2,
                bytes: Some(6),
                seqs: Some(2..=3),
            });
            assert_eq!(
                count(&reader, Stream::Packets(link), LossReason::Staging),
                2
            );
            Ok(())
        },
    ))
    .unwrap();
    assert!(collector.ended().is_some());
}

#[test]
fn one_ring_evicts_the_same_way_for_events_packets_and_keys() {
    struct KeysOnly(Arc<Collector>);
    impl Observer for KeysOnly {
        fn enabled(&self, interest: Interest<'_>) -> bool {
            matches!(interest, Interest::TlsKey(_) | Interest::Topology(_))
        }
        fn observe(&self, stamp: Stamp, item: Observation<'_>) {
            self.0.observe(stamp, item);
        }
    }
    let event = fictionet::events::Event::new("test", "item").summary("x".repeat(512));
    let size = event.size();
    for bounds in [
        Bounds {
            count: 2,
            bytes: size * 10,
        },
        Bounds {
            count: 10,
            bytes: size * 2,
        },
    ] {
        let collector = Arc::new(Collector::with_options(Options {
            policy: policy(
                ["events", "packets", "keys"]
                    .map(|name| Class::new(name).count(bounds.count).bytes(bounds.bytes)),
            ),
            ..Options::default()
        }));
        let reader = collector.clone();
        let event = event.clone();
        block_on(lab(
            RunOptions::new(Seed::from_u64(1)).observer(Arc::new(KeysOnly(collector))),
            move |cx| async move {
                let (a, _b) = fictionet::pair();
                let _a = cx.tap("test", a);
                cx.yield_now().await?;
                let link = *reader.topology().links.keys().next().unwrap();
                let logger = cx.tls_key_log(None).unwrap();
                let secret = vec![0; size - size_of::<Key>() - 1];
                for seq in 1..=5 {
                    reader.observe(
                        Stamp {
                            stream: Stream::Events,
                            seq,
                            at: Instant::ZERO,
                        },
                        Observation::Event(&event),
                    );
                    packet(&reader, link, seq, Instant::ZERO, &vec![0; size]);
                    logger.log("k", &[], &secret);
                }
                assert_eq!(reader.events().retained(), (2, size * 2));
                assert_eq!(reader.packets(link, 0, 10).packets.len(), 2);
                assert_eq!(reader.keys().len(), 2);
                for stream in [Stream::Events, Stream::Packets(link), Stream::Keys] {
                    let rows: Vec<_> = reader
                        .losses()
                        .streams
                        .into_iter()
                        .filter(|loss| loss.stream == stream)
                        .collect();
                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows[0].reason, LossReason::Eviction);
                    assert_eq!(rows[0].count, 3);
                    assert_eq!(rows[0].bytes, Some((3 * size) as u64));
                }
                assert_eq!(reader.events().batch(None, 10).evicted, [3]);
                assert_eq!(evictions(&reader.packets(link, 0, 10)), 3);
                assert_eq!(reader.state.lock().keys.rings[&2].evicted, 3);
                Ok(())
            },
        ))
        .unwrap();
    }
}

const WORK_CLASSES: [Class; 5] = [
    Class::new("events").count(50_000).bytes(16 << 20).rank(3),
    Class::new("noise")
        .count(5_000)
        .bytes(2 << 20)
        .burst(64)
        .rank(1),
    Class::new("keys").count(20_000).bytes(8 << 20).rank(4),
    Class::new("agent").count(8_192).bytes(32 << 20).rank(2),
    Class::new("bulk")
        .watched()
        .count(4_096)
        .bytes(1 << 20)
        .snap(96)
        .burst(64),
];
struct WorkPolicy;
impl Policy for WorkPolicy {
    fn classes(&self) -> &[Class] {
        &WORK_CLASSES
    }
    fn admit(&self, interest: Interest<'_>) -> Admit {
        use fictionet::stdlib::network::ip;
        let jump = "10.10.5.20".parse::<std::net::IpAddr>().unwrap();
        let mirror = "10.10.5.30".parse::<std::net::IpAddr>().unwrap();
        match interest {
            Interest::Event(_, conn)
                if conn
                    .sandbox
                    .as_ref()
                    .is_some_and(|sandbox| &*sandbox.name == "jump") =>
            {
                Admit::Skip
            }
            Interest::Event(meta, _) if meta.source == "console" => Admit::Skip,
            Interest::Event(meta, _) if meta.source == "net" && meta.kind == "blocked" => {
                Admit::Class(1)
            }
            Interest::Event(..) => Admit::Build,
            Interest::TlsKey(_) => Admit::Class(2),
            Interest::Packet(p) if p.sandbox == Some("jump") => Admit::Skip,
            Interest::Packet(p) if p.sandbox.is_some() => {
                match ip::Header::parse_truncated(p.bytes) {
                    Some(h) if h.src == jump || h.dst == jump => Admit::Skip,
                    Some(h) if h.src == mirror || h.dst == mirror => Admit::Class(4),
                    _ => Admit::Class(3),
                }
            }
            Interest::Packet(_) => Admit::Class(4),
            Interest::Topology(_) => Admit::Build,
        }
    }
    fn sort(&self, observation: &Observation<'_>) -> Option<usize> {
        match observation {
            Observation::Event(event) => Some(usize::from(event.repeat_fields().is_some())),
            _ => None,
        }
    }
}

#[test]
fn a_policy_skips_an_event_before_its_builder_runs() {
    let collector = Arc::new(Collector::new(Arc::new(WorkPolicy)));
    block_on(lab(
        RunOptions::new(Seed::from_u64(1)).observer(collector.clone()),
        |cx| async move {
            cx.emit("console", "traffic", |_| panic!("declined builder ran"));
            cx.emit("http", "request", |event| event);
            Ok(())
        },
    ))
    .unwrap();
    assert!(
        collector
            .events()
            .after(0, usize::MAX)
            .iter()
            .all(|event| event.source != "console")
    );
    assert_eq!(
        collector
            .events()
            .checked_of("http", "request")
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_policy_sorts_a_built_event_by_its_repeat_mark() {
    use fictionet::events::{Event, Fields};
    let collector = Collector::with_options(Options {
        policy: policy([
            Class::new("events").count(1).bytes(8192),
            Class::new("noise").count(1).bytes(8192),
        ]),
        ..Options::default()
    });
    for (index, event) in [
        Event::new("test", "item"),
        Event::new("test", "item").repeat(Fields::new()),
        Event::new("test", "item").repeat(Fields::new()),
    ]
    .iter()
    .enumerate()
    {
        collector.observe(
            Stamp {
                stream: Stream::Events,
                seq: index as u64 + 1,
                at: Instant::ZERO,
            },
            Observation::Event(event),
        );
    }
    assert_eq!(
        collector
            .events()
            .after(0, 10)
            .iter()
            .map(|event| event.seq)
            .collect::<Vec<_>>(),
        [1, 3]
    );
    assert_eq!(collector.events().batch(None, 10).evicted, [0, 1]);
}

#[test]
fn noise_and_events_classes_evict_independently() {
    use fictionet::events::{Event, Fields};
    let collector = Collector::new(policy([
        Class::new("events").count(2).bytes(8192),
        Class::new("noise").count(3).bytes(8192),
    ]));
    for seq in 1..=100 {
        let event = if seq <= 2 {
            Event::new("http", "request")
        } else {
            Event::new("net", "blocked")
                .field("destination", seq)
                .repeat(Fields::new())
        };
        collector.observe(
            Stamp {
                stream: Stream::Events,
                seq,
                at: Instant::ZERO,
            },
            Observation::Event(&event),
        );
    }
    assert_eq!(
        collector
            .events()
            .after(0, 100)
            .iter()
            .map(|event| event.seq)
            .collect::<Vec<_>>(),
        [1, 2, 98, 99, 100]
    );
    assert_eq!(collector.events().batch(None, 100).evicted, [0, 95]);
    assert_eq!(count(&collector, Stream::Events, LossReason::Eviction), 95);
}

#[test]
fn a_burst_bound_thins_noise_and_counts_sampling() {
    use fictionet::events::{Event, Fields};
    let burst = 4;
    let collector = Collector::new(policy([Class::new("noise")
        .count(100)
        .bytes(1 << 20)
        .burst(burst)]));
    for seq in 1..=16 {
        let at = Instant::ZERO + ms(if seq <= 8 { 0 } else { 100 });
        collector.observe(
            Stamp {
                stream: Stream::Events,
                seq,
                at,
            },
            Observation::Event(&Event::new("net", "blocked").repeat(Fields::new())),
        );
    }
    assert_eq!(
        collector
            .events()
            .after(0, 100)
            .iter()
            .map(|event| event.seq)
            .collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 7, 9, 10, 11, 12, 13, 15]
    );
    assert_eq!(count(&collector, Stream::Events, LossReason::Sampling), 4);
    assert_eq!(collector.events().losses().events(), 4);
}

fn work_packet(destination: [u8; 4], seq: u32, payload: &[u8]) -> Packet {
    let mut bytes = vec![0; 40];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&[10, 10, 5, 40]);
    bytes[16..20].copy_from_slice(&destination);
    bytes[20..22].copy_from_slice(&40_000u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&80u16.to_be_bytes());
    bytes[24..28].copy_from_slice(&seq.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x18;
    bytes.extend_from_slice(payload);
    Packet(bytes)
}

#[test]
fn console_traffic_costs_nothing_when_excluded() {
    use fictionet::events::Fanout;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Probe {
        collector: Arc<Collector>,
        packets: AtomicUsize,
    }
    impl Observer for Probe {
        fn enabled(&self, interest: Interest<'_>) -> bool {
            matches!(interest, Interest::Packet(_)) && self.collector.enabled(interest)
        }
        fn observe(&self, _: Stamp, item: Observation<'_>) {
            if matches!(item, Observation::Packet(_)) {
                self.packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    let collector = Arc::new(Collector::new(Arc::new(WorkPolicy)));
    let probe = Arc::new(Probe {
        collector: collector.clone(),
        packets: AtomicUsize::new(0),
    });
    let reader = collector.clone();
    let observed = probe.clone();
    block_on(lab(
        RunOptions::new(Seed::from_u64(1)).observer(Arc::new(Fanout::new(vec![collector, probe]))),
        move |cx| async move {
            let (attacher, mut attachments) = fictionet::attachments();
            let mut jump = attacher.attach("jump").unwrap();
            let mut guest = attacher.attach("guest").unwrap();
            let mut jump_link = attachments.get(&cx, "jump").await?;
            let mut guest_link = attachments.get(&cx, "guest").await?;
            cx.yield_now().await?;
            let topology = reader.topology();
            let guest_id = *topology
                .links
                .iter()
                .find(|(_, link)| link.sandbox.as_deref() == Some("guest"))
                .unwrap()
                .0;
            let jump_id = *topology
                .links
                .iter()
                .find(|(_, link)| link.sandbox.as_deref() == Some("jump"))
                .unwrap()
                .0;
            let console = work_packet([10, 10, 5, 20], 1, &[7; 120]);
            let mut reply = console.clone();
            reply.0[12..16].copy_from_slice(&[10, 10, 5, 20]);
            reply.0[16..20].copy_from_slice(&[10, 10, 5, 40]);
            let mut agent = Vec::new();
            for index in 0..2000 {
                if index % 2 == 0 {
                    guest.send(console.clone());
                    guest_link.recv(&cx).await?;
                } else {
                    guest_link.send(reply.clone());
                    guest.recv(&cx).await?;
                }
                jump.send(reply.clone());
                jump_link.recv(&cx).await?;
                jump_link.send(console.clone());
                jump.recv(&cx).await?;
                if index % 10 == 0 {
                    let packet = work_packet([10, 10, 5, 50], index, &[index as u8; 120]);
                    agent.push(packet.0.clone());
                    guest.send(packet);
                    guest_link.recv(&cx).await?;
                }
            }
            assert_eq!(cx.now(), Instant::ZERO);
            assert_eq!(observed.packets.load(Ordering::Relaxed), 200);
            let batch = reader.packets(guest_id, 0, usize::MAX);
            assert_eq!(batch.cursor, 200);
            assert_eq!(
                batch
                    .packets
                    .iter()
                    .map(|p| p.bytes.as_ref())
                    .collect::<Vec<_>>(),
                agent.iter().map(Vec::as_slice).collect::<Vec<_>>()
            );
            assert!(
                batch
                    .packets
                    .iter()
                    .all(|p| p.class == 3 && p.skipped == 0 && p.original_len == p.bytes.len())
            );
            assert_eq!(evictions(&batch), 0);
            assert!(!reader.state.lock().captures.links.contains_key(&jump_id));
            for reason in [
                LossReason::Sampling,
                LossReason::Truncation,
                LossReason::Eviction,
            ] {
                assert_eq!(count(&reader, Stream::Packets(guest_id), reason), 0);
            }
            let crossings = |id| {
                reader.topology().counters()[&id]
                    .iter()
                    .map(|count| count.packets)
                    .sum::<u64>()
            };
            assert_eq!(crossings(guest_id) - batch.cursor, 2000);
            assert_eq!(
                crossings(jump_id) - reader.packets(jump_id, 0, 1).cursor,
                4000
            );
            Ok(())
        },
    ))
    .unwrap();
}

#[cfg(feature = "decode")]
#[test]
fn agent_traffic_keeps_full_fidelity_under_load() {
    let dashboard = DashboardObserver::new(DashboardOptions {
        collector: Options {
            policy: Arc::new(WorkPolicy),
            ..Options::default()
        },
        ..DashboardOptions::default()
    });
    let handle = dashboard.handle();
    block_on(lab(
        RunOptions::new(Seed::from_u64(1)).observer(dashboard.observer()),
        move |cx| async move {
            let (attacher, mut attachments) = fictionet::attachments();
            let _jump = attacher.attach("jump").unwrap();
            let mut guest = attacher.attach("guest").unwrap();
            let _jump_link = attachments.get(&cx, "jump").await?;
            let mut guest_link = attachments.get(&cx, "guest").await?;
            cx.yield_now().await?;
            let collector = &handle.0.collector;
            let link = *collector
                .topology()
                .links
                .iter()
                .find(|(_, link)| link.sandbox.as_deref() == Some("guest"))
                .unwrap()
                .0;
            let _demand = collector.capture_demand(link).unwrap();
            let request = format!(
                "GET /load HTTP/1.1\r\nHost: site.test\r\nX-Padding: {}\r\n\r\n",
                "x".repeat(1000)
            );
            let mut agent = Vec::new();
            let windows = 50;
            let per_window = 1000;
            let bulk = WORK_CLASSES[4];
            let burst = bulk.burst.unwrap();
            let kept_per_window = (0..per_window)
                .filter(|index: &u64| {
                    *index < burst || index.is_multiple_of(1u64 << (*index / burst).min(30))
                })
                .count();
            let retained = bulk.count.min(bulk.bytes / bulk.snap.unwrap());
            let expected_evicted = kept_per_window * windows - retained;
            let expected_sampled = windows * (per_window as usize - kept_per_window);
            assert!(expected_evicted > 0 && expected_sampled > 0);
            for window in 0..windows {
                for index in 0..per_window {
                    guest.send(work_packet([10, 10, 5, 30], index as u32, &[7; 200]));
                    guest_link.recv(&cx).await?;
                    if window % 5 == 0 && index == 500 {
                        let part = window / 5;
                        let start = request.len() * part / 10;
                        let end = request.len() * (part + 1) / 10;
                        let packet = work_packet(
                            [10, 10, 5, 50],
                            start as u32 + 1,
                            &request.as_bytes()[start..end],
                        );
                        agent.push(packet.0.clone());
                        guest.send(packet);
                        guest_link.recv(&cx).await?;
                    }
                }
                cx.sleep(ms(100)).await?;
            }
            let batch = collector.packets(link, 0, usize::MAX);
            let copies: Vec<_> = batch
                .packets
                .iter()
                .filter(|copy| copy.class == 3)
                .collect();
            assert_eq!(copies.len(), 10);
            assert_eq!(
                copies
                    .iter()
                    .map(|copy| copy.bytes.as_ref())
                    .collect::<Vec<_>>(),
                agent.iter().map(Vec::as_slice).collect::<Vec<_>>()
            );
            assert!(
                copies
                    .iter()
                    .all(|copy| copy.skipped == 0 && copy.original_len == copy.bytes.len())
            );
            assert!(
                copies
                    .windows(2)
                    .all(|pair| pair[0].stamp.seq < pair[1].stamp.seq)
            );
            assert_eq!(batch.evicted, [(3, 0), (4, expected_evicted as u64)]);
            assert_eq!(
                batch.packets.iter().filter(|copy| copy.class == 4).count(),
                retained
            );
            assert_eq!(
                count(collector, Stream::Packets(link), LossReason::Sampling),
                expected_sampled as u64
            );
            assert_eq!(
                count(collector, Stream::Packets(link), LossReason::Eviction),
                expected_evicted as u64
            );
            let subscription = handle
                .0
                .watches
                .acquire(collector, link.get(), std::time::Instant::now(), || {
                    Some((link, "{}".into()))
                })
                .unwrap();
            let watch = subscription.watch();
            let mut cursor = 0;
            let mut agent_rows = 0;
            let mut http = 0;
            let mut http_rows = 0;
            let mut sampled = 0;
            let mut evicted = 0;
            loop {
                let drained = watch.pump(&handle.0);
                let (missed, rows) = watch.rows_after(cursor, usize::MAX);
                assert_eq!(missed, 0);
                for (seq, row) in rows {
                    cursor = seq;
                    if row.contains("\"class\":\"agent\"") {
                        agent_rows += 1;
                        assert!(row.contains("\"skipped\":0,\"evicted\":0"), "{row}");
                        let detail = watch.detail(seq).unwrap();
                        http += detail
                            .matches("\"name\":\"Hypertext Transfer Protocol\"")
                            .count();
                        if row.contains("\"proto\":\"HTTP\"") {
                            http_rows += 1;
                            assert!(row.contains("GET /load HTTP/1.1"), "{row}");
                        }
                    } else {
                        assert!(row.contains("\"class\":\"bulk\""), "{row}");
                        if !row.contains("\"skipped\":0,") {
                            sampled += 1;
                        }
                        if !row.contains("\"evicted\":0,") {
                            evicted += 1;
                        }
                    }
                }
                if drained {
                    break;
                }
            }
            assert_eq!(agent_rows, 10);
            assert_eq!(http, 1);
            assert_eq!(http_rows, 1);
            assert!(sampled > 0 && evicted > 0);
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn checked_of_ignores_losses_of_other_kinds() {
    use fictionet::events::{Event, Fields};
    let collector = Collector::new(policy([
        Class::new("events").count(2),
        Class::new("noise").count(1),
    ]));
    for seq in 1..=10 {
        let event = if seq == 1 {
            Event::new("http", "request")
        } else {
            Event::new("net", "noise").repeat(Fields::new())
        };
        collector.observe(
            Stamp {
                stream: Stream::Events,
                seq,
                at: Instant::ZERO,
            },
            Observation::Event(&event),
        );
    }
    assert_eq!(
        collector
            .events()
            .checked_of("http", "request")
            .unwrap()
            .len(),
        1
    );
    assert!(collector.events().checked_of("net", "noise").is_err());
    assert!(collector.events().checked_all().is_err());
}

#[test]
fn checked_of_refuses_after_a_loss_of_its_kind() {
    struct Split([Class; 2]);
    impl Policy for Split {
        fn classes(&self) -> &[Class] {
            &self.0
        }
        fn admit(&self, interest: Interest<'_>) -> Admit {
            match interest {
                Interest::Event(_, conn) => Admit::Class(usize::from(conn.id == Some(2))),
                _ => Admit::Skip,
            }
        }
        fn sort(&self, _: &Observation<'_>) -> Option<usize> {
            panic!("already classified")
        }
    }
    let collector = Collector::new(Arc::new(Split([
        Class::new("first").count(1),
        Class::new("second").count(1),
    ])));
    for (seq, id) in [(1, 1), (2, 2), (3, 2)] {
        let mut event = fictionet::events::Event::new("http", "request");
        event.conn.id = Some(id);
        collector.observe(
            Stamp {
                stream: Stream::Events,
                seq,
                at: Instant::ZERO,
            },
            Observation::Event(&event),
        );
    }
    assert_eq!(collector.events().after(0, 10).len(), 2);
    assert!(collector.events().checked_of("http", "request").is_err());
    let losses = collector.losses();
    assert_eq!(losses.streams.len(), 1);
    assert_eq!(losses.streams[0].class, Some(1));
    assert_eq!(losses.streams[0].event, Some(("http", "request")));
}

#[test]
fn checked_of_refuses_after_a_core_loss() {
    let collector = Collector::default();
    collector.lost(Loss::staged(Stream::Events, 3));
    for (source, kind) in [("http", "request"), ("net", "noise"), ("other", "kind")] {
        assert_eq!(
            collector
                .events()
                .checked_of(source, kind)
                .unwrap_err()
                .lost,
            3
        );
    }
    assert_eq!(collector.losses().streams[0].class, None);
    assert_eq!(collector.losses().streams[0].event, None);
    assert_eq!(collector.losses().events(), 3);
}

#[test]
fn every_loss_has_a_stream_a_class_and_a_reason() {
    use fictionet::events::Event;
    let collector = Collector::new(policy([Class::new("events").count(1)]));
    for seq in 1..=2 {
        collector.observe(
            Stamp {
                stream: Stream::Events,
                seq,
                at: Instant::ZERO,
            },
            Observation::Event(&Event::new("http", "request")),
        );
    }
    collector.lost(Loss::staged(Stream::Events, 2));
    let losses = collector.losses();
    assert_eq!(losses.streams.len(), 2);
    let eviction = &losses.streams[0];
    assert_eq!(eviction.stream, Stream::Events);
    assert_eq!(eviction.class, Some(0));
    assert_eq!(eviction.reason, LossReason::Eviction);
    assert_eq!(eviction.count, 1);
    assert_eq!(
        eviction.bytes,
        Some(Event::new("http", "request").size() as u64)
    );
    assert_eq!(eviction.event, Some(("http", "request")));
    let staged = &losses.streams[1];
    assert_eq!(staged.stream, Stream::Events);
    assert_eq!(staged.class, None);
    assert_eq!(staged.reason, LossReason::Staging);
    assert_eq!(staged.count, 2);
    assert_eq!(staged.event, None);
}

fn pcap_blocks(file: &[u8]) -> Vec<(u32, &[u8])> {
    use fictionet::stdlib::codec::le32;
    let mut blocks = Vec::new();
    let mut offset = 0;
    while offset < file.len() {
        let length = le32(file, offset + 4).unwrap() as usize;
        assert_eq!(length % 4, 0);
        assert_eq!(le32(file, offset + length - 4).unwrap() as usize, length);
        blocks.push((
            le32(file, offset).unwrap(),
            &file[offset + 8..offset + length - 4],
        ));
        offset += length;
    }
    assert_eq!(offset, file.len());
    blocks
}

fn pcap_file(export: &mut crate::export::Export) -> Vec<u8> {
    let mut file = Vec::new();
    loop {
        let (bytes, last) = export.next_chunk();
        file.extend(bytes);
        if last {
            return file;
        }
    }
}

#[test]
fn a_download_of_an_unwatched_link_comes_from_the_ring() {
    with_link(
        Options {
            policy: policy([Class::new("packets").count(4)]),
            ..Options::default()
        },
        |collector, link| {
            packet(&collector, link, 1, Instant::ZERO, &[0x45; 20]);
            let mut export = collector.export(&crate::export::Selection {
                streams: vec![Stream::Packets(link)],
                ..Default::default()
            });
            let file = pcap_file(&mut export);
            let blocks = pcap_blocks(&file);
            assert_eq!(
                blocks.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
                [0x0a0d0d0a, 1, 6]
            );
            assert_eq!(&blocks[2].1[20..40], &[0x45; 20]);
            assert!(!collector.demand.load()[&link].enabled());
        },
    );
}

#[test]
fn a_long_capture_downloads_in_pieces_that_join_into_pcapng() {
    use fictionet::stdlib::codec::le32;
    let collector = Arc::new(Collector::new(policy([Class::new("packets")
        .count(4096)
        .bytes(8 << 20)])));
    block_on(lab(
        RunOptions::new(Seed::from_u64(1)).observer(collector.clone()),
        |cx| async move {
            let (a, _b) = fictionet::pair();
            let _a = cx.tap("test", a);
            cx.yield_now().await?;
            let link = *collector.topology().links.keys().next().unwrap();
            cx.tls_key_log(None).unwrap().log(
                "CLIENT_TRAFFIC_SECRET_0",
                &7u64.to_be_bytes(),
                &[0xab; 32],
            );
            let mut data = vec![0; 1200];
            data[0] = 0x45;
            data[2..4].copy_from_slice(&1200u16.to_be_bytes());
            data[9] = 17;
            for seq in 1..=300 {
                packet(&collector, link, seq, Instant::ZERO, &data);
            }
            let mut export = collector.export(&crate::export::Selection {
                streams: vec![Stream::Packets(link), Stream::Keys],
                ..Default::default()
            });
            let (first, last) = export.next_chunk();
            assert!(!last);
            assert!(first.len() < 2 * (1 << 18));
            let mut file = first;
            file.extend(pcap_file(&mut export));
            let blocks = pcap_blocks(&file);
            assert_eq!(
                blocks
                    .iter()
                    .take(3)
                    .map(|(kind, _)| *kind)
                    .collect::<Vec<_>>(),
                [0x0a0d0d0a, 1, 0x0a]
            );
            let packets: Vec<_> = blocks.iter().filter(|(kind, _)| *kind == 6).collect();
            assert_eq!(packets.len(), 300);
            for (_, block) in packets {
                assert_eq!(le32(block, 12).unwrap(), 1200);
                assert_eq!(le32(block, 16).unwrap(), 1200);
                assert_eq!(&block[20..1220], &data);
            }
            let keylog = collector.keylog();
            let key_block = blocks[2].1;
            let length = le32(key_block, 4).unwrap() as usize;
            assert_eq!(&key_block[8..8 + length], keylog.as_bytes());
            assert!(keylog.starts_with("CLIENT_TRAFFIC_SECRET_0 0000000000000007"));
            Ok(())
        },
    ))
    .unwrap();
}

#[cfg(feature = "page")]
#[test]
fn jsonl_and_pcapng_share_a_selection() {
    use fictionet::events::{Event, Sandbox};
    use fictionet::stdlib::codec::le32;
    struct ByConnection([Class; 2]);
    impl Policy for ByConnection {
        fn classes(&self) -> &[Class] {
            &self.0
        }
        fn admit(&self, interest: Interest<'_>) -> Admit {
            match interest {
                Interest::Event(_, conn) => Admit::Class(usize::from(conn.id != Some(1))),
                Interest::Packet(packet) => {
                    Admit::Class(usize::from(packet.bytes.last() != Some(&1)))
                }
                Interest::TlsKey(key) => Admit::Class(usize::from(
                    key.connection.and_then(|conn| conn.id) != Some(1),
                )),
                Interest::Topology(_) => Admit::Build,
            }
        }
        fn sort(&self, _: &Observation<'_>) -> Option<usize> {
            panic!("already classified")
        }
    }
    let collector = Arc::new(Collector::new(Arc::new(ByConnection([
        Class::new("agent").snap(28),
        Class::new("bulk"),
    ]))));
    block_on(lab(
        RunOptions::new(Seed::from_u64(1)).observer(collector.clone()),
        |cx| async move {
            let (a, _b) = fictionet::pair();
            let (c, _d) = fictionet::pair();
            let (_a, _c) = (cx.tap("alpha", a), cx.tap("beta", c));
            cx.yield_now().await?;
            let links: Vec<_> = collector.topology().links.keys().copied().collect();
            for seq in 1..=6 {
                let mut event = Event::new("http", "request");
                event.conn.id = Some(if seq % 2 == 1 { 1 } else { 2 });
                event.conn.sandbox = Some(Sandbox {
                    id: 1,
                    name: if seq <= 4 {
                        "alpha".into()
                    } else {
                        "beta".into()
                    },
                    addr: None,
                    addr_v6: None,
                });
                collector.observe(
                    Stamp {
                        stream: Stream::Events,
                        seq,
                        at: Instant::ZERO,
                    },
                    Observation::Event(&event),
                );
                cx.tls_key_log(Some(&event.conn)).unwrap().log(
                    "CLIENT_RANDOM",
                    &[seq as u8],
                    &[seq as u8],
                );
                for (link, host) in links.iter().zip(["alpha", "beta"]) {
                    let mut data = vec![0; 40];
                    data[0] = 0x45;
                    data[2..4].copy_from_slice(&40u16.to_be_bytes());
                    data[39] = event.conn.id.unwrap() as u8;
                    collector.observe(
                        Stamp {
                            stream: Stream::Packets(*link),
                            seq,
                            at: Instant::ZERO,
                        },
                        Observation::Packet(PacketRef {
                            link: *link,
                            tap: host,
                            sandbox: Some(host),
                            side: Side::A,
                            len: data.len(),
                            link_type: LinkType::Ip,
                            bytes: &data,
                        }),
                    );
                }
            }
            let mut merged = collector.export(&crate::export::Selection {
                streams: vec![Stream::Packets(links[1]), Stream::Packets(links[0])],
                ..Default::default()
            });
            let merged_file = pcap_file(&mut merged);
            let merged_blocks = pcap_blocks(&merged_file);
            assert_eq!(
                merged_blocks
                    .iter()
                    .filter(|(kind, _)| *kind == 0x0a0d0d0a)
                    .count(),
                2
            );
            let comments: Vec<_> = merged_blocks
                .iter()
                .filter(|(kind, _)| *kind == 6)
                .map(|(_, block)| packet_comment(block))
                .collect();
            assert_eq!(comments.len(), 12);
            for (rows, host) in comments.chunks(6).zip(["beta", "alpha"]) {
                for (index, comment) in rows.iter().enumerate() {
                    assert_eq!(comment["seq"], index + 1);
                    assert_eq!(comment["class"], index % 2);
                    assert_eq!(comment["source"], host);
                }
            }
            let mut export = collector.export(&crate::export::Selection {
                streams: vec![
                    Stream::Events,
                    Stream::Packets(links[0]),
                    Stream::Packets(links[1]),
                    Stream::Keys,
                ],
                classes: Some(vec![0]),
                sandbox: Some("alpha".into()),
                after: 1,
                through: Some(4),
                ..Default::default()
            });
            let lines: Vec<serde_json::Value> = export
                .jsonl()
                .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
                .collect();
            let events: Vec<_> = lines
                .iter()
                .filter(|line| line.get("seq").is_some())
                .collect();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["seq"], 3);
            assert_eq!(events[0]["class"], 0);
            assert_eq!(events[0]["sandbox"]["name"], "alpha");
            assert_eq!(export.keylog(), "CLIENT_RANDOM 03 03\n");
            let file = pcap_file(&mut export);
            let blocks = pcap_blocks(&file);
            assert_eq!(
                blocks
                    .iter()
                    .filter(|(kind, _)| *kind == 0x0a0d0d0a)
                    .count(),
                1
            );
            let packets: Vec<_> = blocks.iter().filter(|(kind, _)| *kind == 6).collect();
            assert_eq!(packets.len(), 1);
            assert_eq!(le32(packets[0].1, 12).unwrap(), 28);
            assert_eq!(le32(packets[0].1, 16).unwrap(), 40);
            let comment = packet_comment(packets[0].1);
            assert_eq!(comment["seq"], 3);
            assert_eq!(comment["class"], 0);
            assert_eq!(comment["source"], "alpha");
            assert!(lines.iter().any(|line| line["type"] == "loss"
                && line["class"] == 0
                && line["reason"] == "truncation"));
            Ok(())
        },
    ))
    .unwrap();
}

#[cfg(feature = "page")]
fn packet_comment(block: &[u8]) -> serde_json::Value {
    use fictionet::stdlib::codec::{le16, le32};
    let at = 20 + (le32(block, 12).unwrap() as usize).div_ceil(4) * 4;
    assert_eq!(le16(block, at).unwrap(), 1);
    let length = le16(block, at + 2).unwrap() as usize;
    serde_json::from_slice(&block[at + 4..at + 4 + length]).unwrap()
}

#[cfg(feature = "page")]
#[test]
fn a_flow_label_is_a_pcapng_comment() {
    with_link(
        Options {
            policy: policy([Class::new("packets")]),
            ..Options::default()
        },
        |collector, link| {
            let data = work_packet([192, 0, 2, 1], 0, b"hello").0;
            let header = fictionet::stdlib::network::ip::Header::parse_truncated(&data).unwrap();
            let payload = header.payload(&data);
            let src =
                std::net::SocketAddr::new(header.src, u16::from_be_bytes([payload[0], payload[1]]))
                    .to_string();
            let dst =
                std::net::SocketAddr::new(header.dst, header.dst_port(&data).unwrap()).to_string();
            packet(&collector, link, 1, Instant::ZERO, &data);
            let labels = vec![
                crate::page::Label {
                    id: 1,
                    target: crate::page::LabelTarget::Flow {
                        link: link.to_string(),
                        a: dst,
                        b: src,
                    },
                    text: "agent request".into(),
                    at: 0.0,
                },
                crate::page::Label {
                    id: 2,
                    target: crate::page::LabelTarget::Flow {
                        link: link.to_string(),
                        a: "other".into(),
                        b: "flow".into(),
                    },
                    text: "unrelated".into(),
                    at: 0.0,
                },
            ];
            let mut export = collector.export(&crate::export::Selection {
                streams: vec![Stream::Packets(link)],
                labels,
                ..Default::default()
            });
            let file = pcap_file(&mut export);
            let blocks = pcap_blocks(&file);
            let comment = packet_comment(blocks.iter().find(|(kind, _)| *kind == 6).unwrap().1);
            assert_eq!(comment["labels"], serde_json::json!(["agent request"]));
            assert_eq!(comment["source"], "test");
            assert_eq!(comment["kind"], "packets");
        },
    );
}

#[test]
fn core_packet_loss_breaks_the_next_copy_continuity() {
    with_link(
        Options {
            policy: policy([Class::new("packets")]),
            ..Options::default()
        },
        |collector, link| {
            packet(&collector, link, 1, Instant::ZERO, &[0x45; 20]);
            collector.lost(Loss::staged(Stream::Packets(link), 1));
            packet(&collector, link, 2, Instant::ZERO, &[0x45; 20]);
            let copies = collector.packets(link, 0, 10).packets;
            assert_eq!(copies[0].omissions, 0);
            assert_eq!(copies[1].omissions, 1);
            assert_eq!(collector.losses().streams[0].class, None);
        },
    );
}

#[test]
fn bulk_is_evicted_before_agent_under_the_shared_budget() {
    let agent = WORK_CLASSES[3];
    let bulk = WORK_CLASSES[4];
    let agent_size = 65_536;
    let agent_count = agent.count.min(agent.bytes / agent_size);
    let bulk_size = bulk.snap.unwrap();
    let bulk_count = bulk.count.min(bulk.bytes / bulk_size);
    let bytes = agent_count * agent_size + bulk_count * bulk_size / 2;
    with_link(Options::default(), move |source, link| {
        let collector = Collector::with_options(Options {
            policy: Arc::new(WorkPolicy),
            bytes,
            ..Options::default()
        });
        collector.observe(
            Stamp {
                stream: Stream::Topology,
                seq: 1,
                at: Instant::ZERO,
            },
            Observation::Topology(TopologyRef::LinkAdded {
                link,
                creator: None,
                host: None,
                sandbox: None,
                counters: source.topology().links[&link].counters.clone(),
            }),
        );
        let _demand = collector.capture_demand(link).unwrap();
        let data = vec![0; agent_size];
        for seq in 1..=agent_count {
            collector.observe(
                Stamp {
                    stream: Stream::Packets(link),
                    seq: seq as u64,
                    at: Instant::ZERO,
                },
                Observation::Packet(PacketRef {
                    link,
                    tap: "guest",
                    sandbox: Some("guest"),
                    side: Side::A,
                    len: data.len(),
                    bytes: &data,
                    link_type: LinkType::Ip,
                }),
            );
        }
        for index in 1..=bulk_count {
            packet(
                &collector,
                link,
                (agent_count + index) as u64,
                Instant::ZERO + ms(index as u64 * 100),
                &vec![0; bulk_size],
            );
        }
        let batch = collector.packets(link, 0, usize::MAX);
        let bulk_kept = (bytes - agent_count * agent_size) / bulk_size;
        assert_eq!(
            batch.packets.iter().filter(|copy| copy.class == 3).count(),
            agent_count
        );
        assert_eq!(
            batch.packets.iter().filter(|copy| copy.class == 4).count(),
            bulk_kept
        );
        assert_eq!(
            batch.evicted,
            [(3, 0), (4, (bulk_count - bulk_kept) as u64)]
        );
    });
}

#[test]
fn events_survive_packet_load_under_the_default_policy() {
    use fictionet::events::Event;
    let source = Arc::new(Collector::default());
    let reader = source.clone();
    block_on(lab(
        RunOptions::new(Seed::from_u64(1)).observer(source),
        move |cx| async move {
            let mut ends = Vec::new();
            for _ in 0..10 {
                let (a, b) = fictionet::pair();
                ends.push((cx.tap("guest", a), b));
            }
            cx.yield_now().await?;
            let collector = Collector::default();
            let classes = collector.options.policy.classes();
            let event = Event::new("http", "request");
            let event_count = classes[0].count.min(classes[0].bytes / event.size());
            let packet_size = classes[3].snap.unwrap();
            let packet_count = classes[3].count.min(classes[3].bytes / packet_size);
            // Ten full packet rings need more than the packets' share of the
            // default budget, so the shared budget must evict.
            let links = reader.topology().links.len();
            assert!(links * classes[3].bytes > policy::PACKET_BYTES);
            for seq in 1..=event_count {
                collector.observe(
                    Stamp {
                        stream: Stream::Events,
                        seq: seq as u64,
                        at: Instant::ZERO,
                    },
                    Observation::Event(&event),
                );
            }
            let data = vec![0; packet_size];
            for link in reader.topology().links.keys() {
                for seq in 1..=packet_count + 2 {
                    collector.observe(
                        Stamp {
                            stream: Stream::Packets(*link),
                            seq: seq as u64,
                            at: Instant::ZERO + ms(seq as u64 * 100),
                        },
                        Observation::Packet(PacketRef {
                            link: *link,
                            tap: "guest",
                            sandbox: Some("guest"),
                            side: Side::A,
                            len: data.len(),
                            bytes: &data,
                            link_type: LinkType::Ip,
                        }),
                    );
                }
            }
            let sent = links * (packet_count + 2);
            let kept: usize = reader
                .topology()
                .links
                .keys()
                .map(|link| collector.packets(*link, 0, usize::MAX).packets.len())
                .sum();
            let evicted: usize = reader
                .topology()
                .links
                .keys()
                .map(|link| evictions(&collector.packets(*link, 0, 0)) as usize)
                .sum();
            assert!(kept < links * packet_count);
            assert_eq!(kept + evicted, sent);
            let state = collector.state.lock();
            let keys: usize = state.keys.rings.values().map(|ring| ring.bytes).sum();
            let retained = collector.events.retained_bytes() + keys + state.captures.bytes;
            drop(state);
            assert!(retained <= collector.options.bytes);
            assert_eq!(
                collector
                    .events()
                    .checked_of("http", "request")
                    .unwrap()
                    .len(),
                event_count
            );
            assert_eq!(count(&collector, Stream::Events, LossReason::Eviction), 0);
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn checked_of_returns_truncated_events_with_their_flag() {
    use fictionet::events::Event;
    for loss_streams in [0, 1] {
        let collector = Collector::with_options(Options {
            loss_streams,
            ..Options::default()
        });
        collector.observe(
            Stamp {
                stream: Stream::Events,
                seq: 1,
                at: Instant::ZERO,
            },
            Observation::Event(
                &Event::new("http", "request")
                    .field("path", "shortened")
                    .truncated(),
            ),
        );
        for events in [
            collector.events().checked_of("http", "request").unwrap(),
            collector.events().checked_all().unwrap(),
        ] {
            assert_eq!(events.len(), 1);
            assert!(events[0].is_truncated());
            assert_eq!(events[0].seq, 1);
        }
        let losses = collector.losses();
        assert_eq!(losses.events(), 1);
        assert_eq!(
            losses
                .streams
                .iter()
                .filter(|loss| loss.reason == LossReason::Truncation)
                .map(|loss| loss.count)
                .sum::<u64>()
                + losses
                    .untracked
                    .iter()
                    .filter(|loss| loss.reason == LossReason::Truncation)
                    .map(|loss| loss.count)
                    .sum::<u64>(),
            1
        );
    }
}

#[test]
fn kept_packets_share_the_tap_name() {
    with_link(
        Options {
            policy: policy([Class::new("packets")]),
            ..Options::default()
        },
        |collector, link| {
            packet(&collector, link, 1, Instant::ZERO, &[1]);
            packet(&collector, link, 2, Instant::ZERO, &[2]);
            let batch = collector.packets(link, 0, 10);
            assert_eq!(batch.packets.len(), 2);
            assert!(Arc::ptr_eq(&batch.packets[0].tap, &batch.packets[1].tap));
        },
    );
}

#[test]
fn delivery_classifies_a_packet_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct CountPolicy(AtomicUsize);
    impl Policy for CountPolicy {
        fn classes(&self) -> &[Class] {
            &WORK_CLASSES
        }
        fn admit(&self, interest: Interest<'_>) -> Admit {
            if matches!(interest, Interest::Packet(_)) {
                self.0.fetch_add(1, Ordering::Relaxed);
                Admit::Class(3)
            } else {
                Admit::Skip
            }
        }
        fn sort(&self, _: &Observation<'_>) -> Option<usize> {
            panic!("packet sorting")
        }
    }
    with_link(Options::default(), |_, link| {
        let policy = Arc::new(CountPolicy(AtomicUsize::new(0)));
        let collector = Collector::new(policy.clone());
        packet(&collector, link, 1, Instant::ZERO, &[1]);
        assert_eq!(policy.0.load(Ordering::Relaxed), 1);
        assert_eq!(collector.packets(link, 0, 10).packets[0].class, 3);
    });
}
