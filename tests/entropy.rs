use std::future::{Future, poll_fn};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use fictionet::stdlib::{ConnectionExt, filter, tcp};
use fictionet::{Entropy, Seed, SeededEntropy, block_on, pair, run};

#[test]
fn interleaved_runs_have_independent_contiguous_streams() {
    let mut cx = Context::from_waker(Waker::noop());
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let make = |seed| {
        let contexts = contexts.clone();
        Box::pin(run(seed, move |fcx| async move {
            contexts.lock().unwrap().push(fcx);
            poll_fn(|_| Poll::<fictionet::Result>::Pending).await
        }))
    };
    let seed = Seed::from_u64(42);
    let mut a = make(seed);
    let mut b = make(seed);
    let mut c = make(Seed::from_u64(43));
    assert!(a.as_mut().poll(&mut cx).is_pending());
    assert!(b.as_mut().poll(&mut cx).is_pending());
    assert!(c.as_mut().poll(&mut cx).is_pending());
    let contexts = contexts.lock().unwrap();
    let oracle = SeededEntropy::new(seed);
    let mut expected = [0; 137];
    oracle.fill_random(&mut expected);
    let mut first = [0; 137];
    let mut second = [0; 137];
    contexts[0].fill_random(&mut first[..3]);
    contexts[1].fill_random(&mut second[..71]);
    first[3..11].copy_from_slice(&contexts[0].clone().random_u64().to_le_bytes());
    contexts[0].fill_random(&mut first[11..]);
    contexts[1].fill_random(&mut second[71..]);
    assert_eq!(first, expected);
    assert_eq!(second, expected);
    let mut different = [0; 137];
    contexts[2].fill_random(&mut different);
    assert_ne!(different, expected);
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Trace {
    syns: Vec<(Vec<u8>, bool)>,
    port: u16,
    draws: Vec<u64>,
}

fn connection_trace(seed: Seed) -> Trace {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let output = trace.clone();
    block_on(run(seed, move |fcx| async move {
        let a: IpAddr = "10.0.0.1".parse()?;
        let b: IpAddr = "10.0.0.2".parse()?;
        let (left, right) = pair();
        let seen = output.clone();
        let right = filter(&fcx, right, move |fcx, _, packet| {
            let bytes = &packet.0;
            let header = usize::from(bytes[0] & 15) * 4;
            if bytes[header + 13] & 2 != 0 {
                let keep = fcx.random_f64() >= 0.3;
                // Ports and initial sequence numbers, excluding wall-clock-dependent fields.
                seen.lock()
                    .unwrap()
                    .syns
                    .push((bytes[header..header + 8].to_vec(), keep));
                keep
            } else {
                true
            }
        });
        let client = tcp::endpoint(&fcx, left, a);
        let server = tcp::endpoint(&fcx, right, b);
        let mut listener = server.listen(80)?;
        fcx.spawn(move |fcx| async move {
            let mut connection = listener.accept(&fcx).await?;
            connection.write_all(&fcx, b"seeded").await?;
            Ok(())
        });
        let mut connection = client.connect(&fcx, SocketAddr::new(b, 80)).await?;
        let mut bytes = [0; 6];
        let mut at = 0;
        while at < bytes.len() {
            let n = connection.read(&fcx, &mut bytes[at..]).await?;
            assert!(n > 0);
            at += n;
        }
        assert_eq!(&bytes, b"seeded");
        let mut trace = output.lock().unwrap();
        trace.port = u16::from_be_bytes(trace.syns[0].0[..2].try_into().unwrap());
        trace.draws = (0..8).map(|_| fcx.random_u64()).collect();
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
    Arc::try_unwrap(trace).unwrap().into_inner().unwrap()
}

#[test]
fn seed_repeats_tcp_sequences_ports_and_loss_decisions() {
    let first = connection_trace(Seed::from_u64(7));
    assert!(first.syns.len() >= 2);
    assert!(first.syns.iter().any(|(_, keep)| !keep), "{first:?}");
    assert_eq!(first, connection_trace(Seed::from_u64(7)));
    let other = connection_trace(Seed::from_u64(8));
    assert_ne!(first.syns[0].0, other.syns[0].0);
    assert_ne!(first.port, other.port);
    assert_ne!(first.draws, other.draws);
}
