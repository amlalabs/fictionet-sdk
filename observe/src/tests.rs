use super::*;
use fictionet::events::{ConnInfo, GroupId, KeyMeta, LinkType, PacketRef, Side, TaskId};
use fictionet::time::ms;
use fictionet::{Interface, InterfaceExt, Packet, RunOptions, Seed, block_on, lab};

fn with_link(
    options: Options,
    test: impl FnOnce(Arc<Collector>, LinkId) + Send + 'static,
) -> Arc<Collector> {
    let collector = Arc::new(Collector::new(options));
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
            capture: CapturePolicy::Startup,
            ..Options::default()
        },
        |collector, link| {
            for seq in 1..=1000 {
                packet(&collector, link, seq, Instant::ZERO, &[1]);
            }
            let copies = collector.packets(link, 0, usize::MAX);
            assert_eq!(copies.missed, 0);
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
                capture: CapturePolicy::Startup,
                packets: bounds,
                snap_len: 4,
                ..Options::default()
            },
            |collector, link| {
                for seq in 1..=5 {
                    packet(&collector, link, seq, Instant::ZERO, &[7; 10]);
                }
                let batch = collector.packets(link, 0, 10);
                assert_eq!(batch.missed, 3);
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
                assert_eq!(first.missed, 3);
                assert_eq!(first.packets.len(), 1);
                assert_eq!(first.packets[0].stamp.seq, 4);
                assert_eq!(first.packets[0].skipped, 0);
                for (after, missed) in [(1, 2), (2, 1), (3, 0)] {
                    assert_eq!(collector.packets(link, after, 10).missed, missed);
                }
                let last = collector.packets(link, 4, 10);
                assert_eq!(last.missed, 0);
                assert_eq!(last.packets.len(), 1);
                assert_eq!(last.packets[0].stamp.seq, 5);
                for after in [5, u64::MAX] {
                    let batch = collector.packets(link, after, 10);
                    assert_eq!(batch.missed, 0);
                    assert!(batch.packets.is_empty());
                }
            },
        );
    }
}

#[test]
fn capture_follows_policy_and_reference_counted_demand() {
    for policy in [
        CapturePolicy::Off,
        CapturePolicy::Startup,
        CapturePolicy::Demand,
    ] {
        with_link(
            Options {
                capture: policy,
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
                assert_eq!(
                    collector.enabled(interest),
                    policy == CapturePolicy::Startup
                );
                let first = collector.capture_demand(link);
                let second = collector.capture_demand(link);
                assert_eq!(first.is_some(), policy != CapturePolicy::Off);
                assert_eq!(collector.enabled(interest), policy != CapturePolicy::Off);
                drop(first);
                assert_eq!(collector.enabled(interest), policy != CapturePolicy::Off);
                drop(second);
                assert_eq!(
                    collector.enabled(interest),
                    policy == CapturePolicy::Startup
                );
            },
        );
    }
}

#[test]
fn aggregate_budget_evicts_the_oldest_copy_across_links() {
    let collector = Arc::new(Collector::new(Options {
        capture: CapturePolicy::Startup,
        packet_bytes: 6,
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
            packet(&reader, links[0], 1, Instant::ZERO, &[0; 3]);
            packet(&reader, links[1], 1, Instant::ZERO, &[1; 3]);
            packet(&reader, links[0], 2, Instant::ZERO, &[2; 3]);
            assert_eq!(reader.packets(links[0], 0, 10).missed, 1);
            assert_eq!(reader.packets(links[1], 0, 10).missed, 0);
            assert_eq!(
                reader.packets(links[0], 0, 10).packets[0].bytes.as_ref(),
                &[2; 3]
            );
            assert_eq!(
                count(&reader, Stream::Packets(links[0]), LossReason::Eviction),
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
        let collector = Arc::new(Collector::new(Options {
            keys: Some(bounds),
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
    let collector = Arc::new(Collector::new(Options {
        keys: Some(Bounds {
            count: 10,
            bytes: 1,
        }),
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
        !Collector::new(Options {
            keys: None,
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
    let collector = Arc::new(Collector::new(Options {
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
    let collector = Arc::new(Collector::new(Options {
        capture: CapturePolicy::Startup,
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
    let collector = Arc::new(Collector::new(Options::default()));
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
    let collector = Arc::new(Collector::new(Options {
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
    let collector = Arc::new(Collector::new(Options {
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
    let collector = Collector::new(Options {
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
    assert_eq!(collector.events().checked_all().unwrap_err().dropped, 3);
    collector.end(Instant::ZERO + ms(10));
    collector.end(Instant::ZERO + ms(20));
    assert_eq!(collector.ended(), Some(Instant::ZERO + ms(10)));
}

#[test]
fn packet_interest_does_not_take_the_collector_lock() {
    with_link(
        Options {
            capture: CapturePolicy::Startup,
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
    let collector = Collector::new(Options {
        events: Some(Limits::new(2, 8192)),
        noise: Limits::new(1, 8192),
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
fn an_oversized_copy_evicts_old_copies_and_advances_empty_cursors() {
    with_link(
        Options {
            capture: CapturePolicy::Startup,
            packets: Bounds { count: 2, bytes: 4 },
            ..Options::default()
        },
        |collector, link| {
            packet(&collector, link, 1, Instant::ZERO, &[0; 4]);
            packet(&collector, link, 2, Instant::ZERO, &[0; 8]);
            let batch = collector.packets(link, 0, 10);
            assert_eq!(batch.missed, 2);
            assert_eq!(batch.cursor, 2);
            assert!(batch.packets.is_empty());
            assert_eq!(collector.packets(link, 1, 10).missed, 1);
            assert_eq!(collector.packets(link, 2, 10).missed, 0);
            packet(&collector, link, 3, Instant::ZERO, &[1; 4]);
            let batch = collector.packets(link, 2, 10);
            assert_eq!(batch.missed, 0);
            assert_eq!(batch.packets[0].cursor, 3);
            assert_eq!(
                count(&collector, Stream::Packets(link), LossReason::Eviction),
                2
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
fn startup_capture_accepts_packets_before_out_of_order_registration() {
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
            let collector = Collector::new(Options {
                capture: CapturePolicy::Startup,
                ..Options::default()
            });
            for (index, (id, link)) in links.iter().rev().enumerate() {
                if index == 1 {
                    packet(&collector, **id, 1, Instant::ZERO, &[7]);
                }
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
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn removed_captures_stay_readable_and_evict_before_active_captures() {
    let collector = Arc::new(Collector::new(Options {
        capture: CapturePolicy::Startup,
        packet_bytes: 6,
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
            assert_eq!(reader.packets(links[1], 0, 10).missed, 1);
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
    let collector = Arc::new(Collector::new(Options {
        capture: CapturePolicy::Startup,
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
    let collector = Arc::new(Collector::new(Options {
        capture: CapturePolicy::Startup,
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
        let collector = Arc::new(Collector::new(Options {
            events: Some(Limits::new(bounds.count, bounds.bytes)),
            capture: CapturePolicy::Startup,
            packets: bounds,
            keys: Some(bounds),
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
                    if stream != Stream::Events {
                        assert_eq!(rows[0].bytes, Some((3 * size) as u64));
                    }
                }
                assert_eq!(reader.events().display_batch(None, 10).evicted, [3, 0]);
                assert_eq!(reader.packets(link, 0, 10).missed, 3);
                assert_eq!(reader.state.lock().keys.ring.evicted, 3);
                Ok(())
            },
        ))
        .unwrap();
    }
}
