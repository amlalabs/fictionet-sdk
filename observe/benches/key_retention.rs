fn main() {
    divan::main();
}

#[divan::bench(sample_count = 3, sample_size = 1)]
fn full_ring(bencher: divan::Bencher) {
    use fictionet::{RunOptions, Seed, events::*, time::Instant};
    use fictionet_observe::{Admit, Class, Collector, Options, Policy};
    use std::sync::Arc;
    struct Selection([Class; 2]);
    impl Policy for Selection {
        fn classes(&self) -> &[Class] {
            &self.0
        }
        fn admit(&self, interest: Interest<'_>) -> Admit {
            match interest {
                Interest::TlsKey(_) => Admit::Class(0),
                Interest::Packet(_) => Admit::Class(1),
                _ => Admit::Build,
            }
        }
        fn sort(&self, item: &Observation<'_>) -> Option<usize> {
            match item {
                Observation::TlsKey(_) => Some(0),
                Observation::Packet(_) => Some(1),
                _ => None,
            }
        }
    }
    let collector = Arc::new(Collector::with_options(Options {
        policy: Arc::new(Selection([
            Class::new("keys").count(2000).bytes(8 << 20),
            Class::new("packets").count(128).bytes(8 << 20),
        ])),
        ..Options::default()
    }));
    let reader = collector.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        fictionet::block_on(fictionet::lab(
            RunOptions::new(Seed::from_u64(1)).observer(collector),
            move |cx| async move {
                let (a, _b) = fictionet::pair();
                let _a = cx.tap("traffic", a);
                cx.yield_now().await?;
                let link = *reader.topology().links.keys().next().unwrap();
                let logger = cx.tls_key_log(None).unwrap();
                for n in 0u64..2000 {
                    let mut random = [1; 32];
                    random[..8].copy_from_slice(&n.to_le_bytes());
                    logger.log("CLIENT_RANDOM", &random, &[2; 48]);
                }
                let bytes = vec![0; 65535];
                for seq in 1..=128 {
                    reader.observe(
                        Stamp {
                            stream: Stream::Packets(link),
                            seq,
                            at: Instant::ZERO,
                        },
                        Observation::Packet(PacketRef {
                            link,
                            tap: "traffic",
                            sandbox: None,
                            side: Side::A,
                            len: bytes.len(),
                            link_type: LinkType::Ip,
                            bytes: &bytes,
                        }),
                    );
                }
                assert_eq!(
                    reader
                        .packets(link, 0, 200)
                        .packets
                        .iter()
                        .map(|p| p.bytes.len())
                        .sum::<usize>(),
                    128 * 65535
                );
                assert_eq!(reader.keys().len(), 2000);
                ready_tx.send(logger).unwrap();
                done_rx.recv().unwrap();
                assert_eq!(reader.keys().len(), 2000);
                Ok(())
            },
        ))
        .unwrap()
    });
    let logger = ready_rx.recv().unwrap();
    bencher.bench_local(|| logger.log("CLIENT_RANDOM", &[7; 32], &[2; 48]));
    done_tx.send(()).unwrap();
    worker.join().unwrap();
}
