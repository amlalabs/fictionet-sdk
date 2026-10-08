//! Putting things between sandboxes and the world: `Attachments::map` and
//! `stdlib::filter`.

mod common;

use common::within;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fictionet::prelude::*;
use fictionet::stdlib::{self, Direction};
use fictionet::time::ms;
use fictionet::{Interface, Packet, RecvError, attachments, block_on, run};

#[test]
fn map_wraps_each_sandbox_and_keeps_its_name() {
    within(Duration::from_secs(5), || {
        let (attacher, attachments) = attachments();
        let mut agent = attacher.attach("agent").unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        block_on(run(move |fcx| async move {
            let mut mapped = attachments.map(&fcx, move |fcx, sandbox| {
                c.fetch_add(1, Ordering::SeqCst);
                stdlib::delay(fcx, ms(30), sandbox)
            });
            let mut world = mapped.get(&fcx, "agent").await?;
            assert_eq!(world.name(), "agent");
            assert_eq!(world.mtu(), 1500);

            // Sandbox to world, through the delay.
            let t0 = fcx.now();
            agent.send(Packet(vec![1]));
            assert_eq!(world.recv(&fcx).await?, Packet(vec![1]));
            assert!(fcx.now().since_start() - t0.since_start() >= ms(30));

            // World to sandbox.
            world.send(Packet(vec![2]));
            assert_eq!(agent.recv(&fcx).await?, Packet(vec![2]));

            // Dropping the mapped attachment ends the delay's task, which
            // drops the sandbox's own attachment: the sandbox is cut off.
            drop(world);
            assert_eq!(agent.recv(&fcx).await, Err(RecvError::Closed));
            Ok(())
        }))
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn dropping_the_mapped_attachments_ends_the_run() {
    within(Duration::from_secs(5), || {
        let (attacher, attachments) = attachments();
        block_on(run(move |fcx| async move {
            let mapped = attachments.map(&fcx, |_fcx, sandbox| sandbox);
            drop(mapped);
            Ok(())
        }))
        .unwrap();
        // The map task dropped the original `Attachments`, so a sandbox
        // that attaches now is turned away.
        let mut late = attacher.attach("late").unwrap();
        block_on(run(move |fcx| async move {
            assert_eq!(late.recv(&fcx).await, Err(RecvError::Closed));
            Ok(())
        }))
        .unwrap();
    });
}

#[test]
fn a_sandbox_that_detached_before_it_was_taken_is_skipped() {
    within(Duration::from_secs(5), || {
        let (attacher, attachments) = attachments();
        block_on(run(move |fcx| async move {
            let mut mapped = attachments.map(&fcx, |fcx, sandbox| {
                stdlib::filter(fcx, sandbox, |_, _, _| true)
            });
            // Taking the barrier puts the first sandbox in the mapped queue.
            let first = attacher.attach("agent").unwrap();
            let barrier = attacher.attach("barrier").unwrap();
            drop(mapped.get(&fcx, "barrier").await?);
            drop(barrier);
            drop(first);
            let mut second = attacher.attach("agent").unwrap();
            let mut world = mapped.get(&fcx, "agent").await?;
            second.send(Packet(vec![7]));
            assert_eq!(world.recv(&fcx).await?, Packet(vec![7]));
            Ok(())
        }))
        .unwrap();
    });
}

/// Until the world takes a mapped sandbox, nothing reads its packets: the
/// wrap has not run, so a filter cannot pile what the agent sends into a
/// queue that no one reads. This holds through chained maps.
#[test]
fn a_mapped_sandbox_is_not_read_until_the_world_takes_it() {
    within(Duration::from_secs(5), || {
        let (attacher, attachments) = attachments();
        let mut agent = attacher.attach("agent").unwrap();
        block_on(run(move |fcx| async move {
            let (wraps, seen) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
            let (w, s) = (wraps.clone(), seen.clone());
            let counting = move |fcx: &fictionet::Cx, sandbox: fictionet::Attachment| {
                w.fetch_add(1, Ordering::SeqCst);
                let s = s.clone();
                stdlib::filter(fcx, sandbox, move |_, direction, _| {
                    if direction == Direction::FromInner {
                        s.fetch_add(1, Ordering::SeqCst);
                    }
                    true
                })
            };
            let mut mapped = attachments.map(&fcx, counting.clone()).map(&fcx, counting);
            for i in 0..1000u16 {
                agent.send(Packet(i.to_be_bytes().to_vec()));
            }
            // The map tasks have had many turns to run.
            fcx.sleep(ms(20)).await?;
            assert_eq!(wraps.load(Ordering::SeqCst), 0);
            assert_eq!(seen.load(Ordering::SeqCst), 0);

            // Taking it runs both wraps, and every packet comes through in
            // order.
            let mut world = mapped.get(&fcx, "agent").await?;
            assert_eq!(wraps.load(Ordering::SeqCst), 2);
            for i in 0..1000u16 {
                assert_eq!(world.recv(&fcx).await?, Packet(i.to_be_bytes().to_vec()));
            }
            assert_eq!(seen.load(Ordering::SeqCst), 2000);
            Ok(())
        }))
        .unwrap();
    });
}

#[test]
fn maps_chain_with_the_first_closest_to_the_sandbox() {
    within(Duration::from_secs(5), || {
        let (attacher, attachments) = attachments();
        let mut agent = attacher.attach("agent").unwrap();
        block_on(run(move |fcx| async move {
            // The first map drops packets that start with 0. The second
            // sees only what the first let through.
            let seen = Arc::new(AtomicUsize::new(0));
            let s = seen.clone();
            let mut mapped = attachments
                .map(&fcx, |fcx, sandbox| {
                    stdlib::filter(fcx, sandbox, |_, _, p| p.0[0] != 0)
                })
                .map(&fcx, move |fcx, sandbox| {
                    let s = s.clone();
                    stdlib::filter(fcx, sandbox, move |_, _, _| {
                        s.fetch_add(1, Ordering::SeqCst);
                        true
                    })
                });
            let mut world = mapped.get(&fcx, "agent").await?;
            agent.send(Packet(vec![0]));
            agent.send(Packet(vec![1]));
            assert_eq!(world.recv(&fcx).await?, Packet(vec![1]));
            assert_eq!(seen.load(Ordering::SeqCst), 1);
            Ok(())
        }))
        .unwrap();
    });
}

#[test]
fn filter_sees_both_directions_and_drops_what_it_rejects() {
    within(Duration::from_secs(5), || {
        let (mut a, b) = fictionet::pair();
        block_on(run(move |fcx| async move {
            let log = Arc::new(std::sync::Mutex::new(Vec::new()));
            let l = log.clone();
            let mut outer = stdlib::filter(&fcx, b, move |_, direction, packet| {
                l.lock().unwrap().push((direction, packet.0.clone()));
                packet.0 != [9]
            });
            a.send(Packet(vec![9]));
            a.send(Packet(vec![1]));
            assert_eq!(outer.recv(&fcx).await?, Packet(vec![1]));
            outer.send(Packet(vec![9]));
            outer.send(Packet(vec![2]));
            assert_eq!(a.recv(&fcx).await?, Packet(vec![2]));
            assert_eq!(
                *log.lock().unwrap(),
                [
                    (Direction::FromInner, vec![9]),
                    (Direction::FromInner, vec![1]),
                    (Direction::ToInner, vec![9]),
                    (Direction::ToInner, vec![2]),
                ]
            );
            // Closing one side ends the task, which closes the other.
            drop(outer);
            assert_eq!(a.recv(&fcx).await, Err(RecvError::Closed));
            Ok(())
        }))
        .unwrap();
    });
}

/// `Interface` is implemented for what `map` hands out, so it boxes like
/// any other.
#[test]
fn mapped_attachments_box_as_interfaces() {
    within(Duration::from_secs(5), || {
        let (attacher, attachments) = attachments();
        let mut agent = attacher.attach("agent").unwrap();
        block_on(run(move |fcx| async move {
            let mut mapped = attachments.map(&fcx, |_fcx, sandbox| {
                Box::new(sandbox) as Box<dyn Interface>
            });
            let mut world: Box<dyn Interface> = Box::new(mapped.get(&fcx, "agent").await?);
            agent.send(Packet(vec![3]));
            assert_eq!(world.recv(&fcx).await?, Packet(vec![3]));
            Ok(())
        }))
        .unwrap();
    });
}
