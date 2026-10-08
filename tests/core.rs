//! The core: cables, the context, regions, `run` and `block_on`.

mod common;

use common::within;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use fictionet::prelude::*;
use fictionet::time::ms;
use fictionet::{
    AttachError, Cancelled, Interface, JoinError, Packet, RecvError, attachments, block_on, pair,
    run,
};

#[derive(Debug)]
struct Boom(&'static str);
impl std::fmt::Display for Boom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Boom {}

#[test]
fn the_run_future_is_send() {
    fn assert_send<T: Send>(_: &T) {}
    let future = run(fictionet::Seed::random(), |_fcx| async { Ok(()) });
    assert_send(&future);
}

#[test]
fn sleeps_end_in_deadline_order() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let o = order.clone();
    let started = std::time::Instant::now();
    within(Duration::from_secs(5), move || {
        block_on(run(fictionet::Seed::random(), move |fcx| async move {
            for d in [30u64, 10, 20] {
                let o = o.clone();
                fcx.spawn(move |fcx| async move {
                    fcx.sleep(ms(d)).await?;
                    o.lock().unwrap().push(d);
                    Ok(())
                });
            }
            Ok(())
        }))
    })
    .unwrap();
    assert_eq!(*order.lock().unwrap(), [10, 20, 30]);
    assert!(started.elapsed() >= ms(30));
}

#[test]
fn now_follows_sleep() {
    within(Duration::from_secs(5), || {
        block_on(run(fictionet::Seed::random(), |fcx| async move {
            let t0 = fcx.now();
            fcx.sleep(ms(20)).await?;
            let t1 = fcx.now();
            assert!(t1.since_start() - t0.since_start() >= ms(20));
            // A deadline in the past returns at once.
            fcx.sleep_until(t0).await?;
            Ok(())
        }))
    })
    .unwrap();
}

#[test]
fn random_numbers_differ() {
    within(Duration::from_secs(5), || {
        block_on(run(fictionet::Seed::random(), |fcx| async move {
            let a: Vec<u64> = (0..8).map(|_| fcx.random_u64()).collect();
            assert!(a.windows(2).any(|w| w[0] != w[1]));
            for _ in 0..1000 {
                let f = fcx.random_f64();
                assert!((0.0..1.0).contains(&f));
            }
            Ok(())
        }))
    })
    .unwrap();
}

/// A region ends only after all of its work has ended, and `Ok` from the
/// world does not cancel that work.
#[test]
fn ok_does_not_cancel_and_the_run_waits_for_all_work() {
    let finished = Arc::new(AtomicBool::new(false));
    let saw_cancel = Arc::new(AtomicBool::new(true));
    let (f, c) = (finished.clone(), saw_cancel.clone());
    let started = std::time::Instant::now();
    within(Duration::from_secs(5), move || {
        block_on(run(fictionet::Seed::random(), move |fcx| async move {
            fcx.spawn(move |fcx| async move {
                fcx.sleep(ms(50)).await?;
                c.store(fcx.is_cancelled(), Ordering::SeqCst);
                f.store(true, Ordering::SeqCst);
                Ok(())
            });
            Ok(())
        }))
    })
    .unwrap();
    assert!(finished.load(Ordering::SeqCst));
    assert!(!saw_cancel.load(Ordering::SeqCst));
    assert!(started.elapsed() >= ms(50));
}

/// Every kind of wait ends with `Cancelled` when the region fails.
#[test]
fn cancellation_ends_every_wait() {
    let results = Arc::new(Mutex::new(Vec::<String>::new()));
    let r = results.clone();
    let out = within(Duration::from_secs(5), move || {
        block_on(run(fictionet::Seed::random(), move |fcx| async move {
            let (mut a, b) = pair();
            let r1 = r.clone();
            fcx.spawn(move |fcx| async move {
                let res = fcx.sleep(Duration::from_secs(60)).await;
                r1.lock().unwrap().push(format!("sleep {res:?}"));
                Ok(())
            });
            let r2 = r.clone();
            fcx.spawn(move |fcx| async move {
                let _b = b;
                let res = a.recv(&fcx).await;
                r2.lock().unwrap().push(format!("recv {res:?}"));
                Ok(())
            });
            let r3 = r.clone();
            fcx.spawn(move |fcx| async move {
                fcx.cancelled().await;
                r3.lock().unwrap().push("cancelled".into());
                Ok(())
            });
            // Work that outlives the cancel until its joiner has seen it.
            let joined = Arc::new(AtomicBool::new(false));
            let j = joined.clone();
            let forever = fcx.spawn(move |_fcx| async move {
                std::future::poll_fn(|cx| {
                    if j.load(Ordering::SeqCst) {
                        return std::task::Poll::Ready(Ok(()));
                    }
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                })
                .await
            });
            let r4 = r.clone();
            fcx.spawn(move |fcx| async move {
                let res = forever.join(&fcx).await;
                joined.store(true, Ordering::SeqCst);
                r4.lock().unwrap().push(format!("join {res:?}"));
                Ok(())
            });
            let (_attacher, mut attachments) = attachments();
            let r5 = r.clone();
            fcx.spawn(move |fcx| async move {
                let res = attachments.get(&fcx, "nope").await;
                r5.lock().unwrap().push(format!("get {:?}", res.err()));
                let res = attachments.next(&fcx).await;
                r5.lock().unwrap().push(format!("next {:?}", res.err()));
                Ok(())
            });
            let r7 = r.clone();
            fcx.spawn(move |fcx| async move {
                let res = fcx.race(None, std::future::pending::<()>()).await;
                r7.lock().unwrap().push(format!("race {res:?}"));
                Ok(())
            });
            let (port, _other) = pair();
            let r8 = r.clone();
            fcx.spawn(move |fcx| async move {
                let mut ports =
                    fictionet::stdlib::ports::Ports::new(
                        vec![Box::new(port) as Box<dyn Interface>],
                    );
                let res = ports.next(&fcx, None, |_| std::task::Poll::Pending).await;
                r8.lock().unwrap().push(format!("ports {:?}", res.err()));
                Ok(())
            });
            let r9 = r.clone();
            fcx.spawn(move |fcx| async move {
                let res = fcx
                    .events()
                    .wait(&fcx, 1, Duration::from_secs(60), |_| false)
                    .await;
                r9.lock().unwrap().push(format!("events {:?}", res.err()));
                Ok(())
            });
            let r6 = r.clone();
            fcx.spawn(move |fcx| async move {
                // Busy: yield_now itself reports the cancel.
                loop {
                    if let Err(c) = fcx.yield_now().await {
                        r6.lock().unwrap().push(format!("yield {c:?}"));
                        return Ok(());
                    }
                }
            });
            fcx.sleep(ms(20)).await?;
            Err(Boom("stop").into())
        }))
    });
    assert_eq!(out.unwrap_err().to_string(), "stop");
    let mut results = results.lock().unwrap().clone();
    results.sort();
    assert_eq!(
        results,
        [
            "cancelled",
            "events Some(Cancelled)",
            "get Some(Cancelled)",
            "join Err(Cancelled)",
            "next Some(Cancelled)",
            "ports Some(Cancelled)",
            "race Err(Cancelled)",
            "recv Err(Cancelled)",
            "sleep Err(Cancelled)",
            "yield Cancelled",
        ]
    );
}

/// A spawned task's error fails the region: siblings and the world are
/// cancelled, and the task's own error comes out of `run`.
#[test]
fn task_error_cancels_siblings_and_comes_out_of_run() {
    let sibling = Arc::new(Mutex::new(None));
    let s = sibling.clone();
    let out = within(Duration::from_secs(5), move || {
        block_on(run(fictionet::Seed::random(), move |fcx| async move {
            fcx.spawn(move |fcx| async move {
                *s.lock().unwrap() = Some(fcx.sleep(Duration::from_secs(60)).await);
                Ok(())
            });
            fcx.spawn(|fcx| async move {
                fcx.sleep(ms(10)).await?;
                Err(Boom("task failed").into())
            });
            // The world waits too, and stops with `?` on Cancelled. The
            // task's error is the one that comes out.
            fcx.sleep(Duration::from_secs(60)).await?;
            Ok(())
        }))
    });
    let err = out.unwrap_err();
    assert!(err.downcast_ref::<Boom>().is_some(), "{err}");
    assert_eq!(*sibling.lock().unwrap(), Some(Err(Cancelled)));
}

#[test]
fn join_returns_what_the_work_returned() {
    within(Duration::from_secs(5), || {
        block_on(run(fictionet::Seed::random(), |fcx| async move {
            let ok = fcx.spawn(|fcx| async move {
                fcx.sleep(ms(5)).await?;
                Ok(())
            });
            ok.join(&fcx).await?;
            // An already finished task joins at once.
            let quick = fcx.spawn(|_fcx| async { Ok(()) });
            fcx.sleep(ms(5)).await?;
            quick.join(&fcx).await?;
            Ok(())
        }))
    })
    .unwrap();

    let (out, joined) = within(Duration::from_secs(5), || {
        let joined = Arc::new(Mutex::new(None));
        let j = joined.clone();
        let out = block_on(run(fictionet::Seed::random(), move |fcx| async move {
            let bad = fcx.spawn(|_fcx| async { Err(Boom("bad").into()) });
            // The join gets the error, though the failure also cancels the
            // region the joiner waits in.
            *j.lock().unwrap() = Some(bad.join(&fcx).await);
            Ok(())
        }));
        let joined = joined.lock().unwrap().take();
        (out, joined)
    });
    // The joiner holds the task's own error, the one `run` returns: the
    // same value, not a copy of its message.
    let out = out.unwrap_err();
    let Some(Err(JoinError::Failed(e))) = joined else {
        panic!("{joined:?}")
    };
    assert_eq!(e.downcast_ref::<Boom>().map(|b| b.0), Some("bad"));
    assert!(std::ptr::addr_eq(&*e, &*out));
    let joined = JoinError::Failed(e);
    assert_eq!(joined.to_string(), "the task failed");
    assert_eq!(
        fictionet::ErrorChain(&joined).to_string(),
        "the task failed: bad"
    );
    assert!(std::error::Error::source(&joined).is_some_and(|s| s.is::<Boom>()));
}

/// A task that is always ready but yields every 64 packets cannot starve
/// another task.
#[test]
fn a_busy_task_cannot_starve_another() {
    let spins = Arc::new(AtomicU64::new(0));
    let s = spins.clone();
    within(Duration::from_secs(5), move || {
        block_on(run(fictionet::Seed::random(), move |fcx| async move {
            let stop = Arc::new(AtomicBool::new(false));
            let st = stop.clone();
            fcx.spawn(move |fcx| async move {
                // A cable that loops back into itself: recv is always ready.
                let (mut a, mut b) = pair();
                b.send(Packet(vec![0]));
                let mut n = 0u32;
                while !st.load(Ordering::SeqCst) {
                    let p = a.recv(&fcx).await?;
                    a.send(p.clone());
                    std::mem::swap(&mut a, &mut b);
                    s.fetch_add(1, Ordering::SeqCst);
                    n += 1;
                    if n.is_multiple_of(64) {
                        fcx.yield_now().await?;
                    }
                }
                Ok(())
            });
            let mut turns = 0;
            while turns < 100 {
                fcx.yield_now().await?;
                turns += 1;
            }
            fcx.sleep(ms(10)).await?;
            stop.store(true, Ordering::SeqCst);
            Ok(())
        }))
    })
    .unwrap();
    assert!(spins.load(Ordering::SeqCst) > 64);
}

#[test]
fn cable_delivers_in_order_then_closed() {
    within(Duration::from_secs(5), || {
        block_on(run(fictionet::Seed::random(), |fcx| async move {
            let (mut a, mut b) = pair();
            for i in 0..3u8 {
                a.send(Packet(vec![i]));
            }
            b.send(Packet(vec![9]));
            drop(a);
            for i in 0..3u8 {
                assert_eq!(b.recv(&fcx).await, Ok(Packet(vec![i])));
            }
            assert_eq!(b.recv(&fcx).await, Err(RecvError::Closed));
            assert_eq!(b.recv(&fcx).await, Err(RecvError::Closed));
            // Sending into a closed cable loses the packet quietly.
            b.send(Packet(vec![1]));
            Ok(())
        }))
    })
    .unwrap();
}

#[test]
fn cable_wakes_across_threads() {
    within(Duration::from_secs(5), || {
        let (mut a, b) = pair();
        let sender = std::thread::spawn(move || {
            let mut b = b;
            for i in 0..100u8 {
                b.send(Packet(vec![i]));
                if i % 10 == 0 {
                    std::thread::sleep(ms(1));
                }
            }
        });
        block_on(run(fictionet::Seed::random(), move |fcx| async move {
            for i in 0..100u8 {
                assert_eq!(a.recv(&fcx).await?, Packet(vec![i]));
            }
            assert_eq!(a.recv(&fcx).await, Err(RecvError::Closed));
            Ok(())
        }))
        .unwrap();
        sender.join().unwrap();
    });
}

#[test]
fn boxed_interfaces_work() {
    within(Duration::from_secs(5), || {
        block_on(run(fictionet::Seed::random(), |fcx| async move {
            let (a, mut b) = pair();
            let mut list: Vec<Box<dyn Interface>> = vec![Box::new(a)];
            list[0].send(Packet(vec![7]));
            assert_eq!(b.recv(&fcx).await?, Packet(vec![7]));
            b.send(Packet(vec![8]));
            assert_eq!(list[0].recv(&fcx).await?, Packet(vec![8]));
            Ok(())
        }))
    })
    .unwrap();
}

#[test]
fn attacher_name_rules() {
    let (attacher, mut attachments) = attachments();
    assert_eq!(attacher.attach("").unwrap_err(), AttachError::BadName);
    assert_eq!(
        attacher.attach(&"x".repeat(256)).unwrap_err(),
        AttachError::BadName
    );
    let long = attacher.attach(&"x".repeat(255)).unwrap();
    let abc = attacher.attach("abc").unwrap();
    let clone = attacher.clone();
    assert_eq!(clone.attach("abc").unwrap_err(), AttachError::Taken);
    // Freed when the sandbox's end closes.
    drop(abc);
    let mut abc = clone.attach("abc").unwrap();
    drop(long);

    within(Duration::from_secs(5), move || {
        block_on(run(fictionet::Seed::random(), move |fcx| async move {
            // `get` skips other names, and sandboxes that detached before
            // they were handed out: the first "abc", and the long name.
            let mut second = attachments.get(&fcx, "abc").await?;
            assert_eq!(second.name(), "abc");
            assert_eq!(second.mtu(), 1500);
            let kept = attacher.attach("kept").unwrap();
            let first = attachments.next(&fcx).await.unwrap();
            assert_eq!(first.name(), "kept");
            drop((first, kept));

            abc.send(Packet(vec![1]));
            assert_eq!(second.recv(&fcx).await?, Packet(vec![1]));
            second.send(Packet(vec![2]));
            assert_eq!(abc.recv(&fcx).await?, Packet(vec![2]));

            // Freed when the world's end closes, too.
            assert_eq!(attacher.attach("abc").unwrap_err(), AttachError::Taken);
            drop(second);
            assert_eq!(abc.recv(&fcx).await, Err(RecvError::Closed));
            let _again = attacher.attach("abc").unwrap();

            // A sandbox can attach while the world waits.
            let a2 = attacher.clone();
            fcx.spawn(move |fcx| async move {
                fcx.sleep(ms(10)).await?;
                let end = a2.attach("late").unwrap();
                std::mem::forget(end);
                Ok(())
            });
            let late = attachments.get(&fcx, "late").await?;
            assert_eq!(late.name(), "late");
            Ok(())
        }))
    })
    .unwrap();
}

#[test]
fn block_on_wakes_from_another_thread() {
    let (tx, rx) = mpsc::channel::<()>();
    let flag = Arc::new(AtomicBool::new(false));
    let f = flag.clone();
    let waker_slot: Arc<Mutex<Option<std::task::Waker>>> = Arc::default();
    let ws = waker_slot.clone();
    std::thread::spawn(move || {
        rx.recv().unwrap();
        f.store(true, Ordering::SeqCst);
        if let Some(w) = ws.lock().unwrap().take() {
            w.wake();
        }
    });
    let mut sent = false;
    let value = within(Duration::from_secs(5), move || {
        block_on(std::future::poll_fn(move |cx| {
            if flag.load(Ordering::SeqCst) {
                return std::task::Poll::Ready(42);
            }
            *waker_slot.lock().unwrap() = Some(cx.waker().clone());
            if !sent {
                sent = true;
                tx.send(()).unwrap();
            }
            std::task::Poll::Pending
        }))
    });
    assert_eq!(value, 42);
    assert_eq!(block_on(async { 7 }), 7);
}

/// Dropping the run future drops the world and all of its work at once.
#[test]
fn dropping_the_run_drops_everything() {
    let (world_end, mut outside) = pair();
    let mut future = Box::pin(run(fictionet::Seed::random(), move |fcx| async move {
        fcx.spawn(move |fcx| async move {
            let mut end = world_end;
            loop {
                let p = end.recv(&fcx).await?;
                end.send(p);
            }
        });
        Ok(())
    }));
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    for _ in 0..3 {
        assert!(future.as_mut().poll(&mut cx).is_pending());
    }
    drop(future);
    let out = within(Duration::from_secs(5), move || {
        block_on(run(fictionet::Seed::random(), move |fcx| async move {
            assert_eq!(outside.recv(&fcx).await, Err(RecvError::Closed));
            Ok(())
        }))
    });
    out.unwrap();
}

/// A wait polled outside the run, here on another thread with `block_on`,
/// still ends when the region is cancelled.
#[test]
fn cancellation_reaches_waits_outside_the_run() {
    let (tx, rx) = mpsc::channel();
    let out = within(Duration::from_secs(5), move || {
        block_on(run(fictionet::Seed::random(), move |fcx| async move {
            let outside = fcx.clone();
            let (mut a, _b) = pair();
            std::thread::spawn(move || {
                let res = block_on(async {
                    (
                        outside.sleep(Duration::from_secs(60)).await,
                        a.recv(&outside).await,
                    )
                });
                tx.send(res).unwrap();
            });
            fcx.sleep(ms(20)).await?;
            Err(Boom("stop").into())
        }))
    });
    assert_eq!(out.unwrap_err().to_string(), "stop");
    let (sleep, recv) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(sleep, Err(Cancelled));
    assert_eq!(recv, Err(RecvError::Cancelled));
}

/// `run` is polled by tokio like any other future, and cable ends work in
/// tokio tasks next to it.
#[test]
fn runs_on_tokio() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_time()
        .build()
        .unwrap();
    rt.block_on(async {
        let (mut inside, mut outside) = pair();
        let echo = tokio::spawn(run(fictionet::Seed::random(), move |fcx| async move {
            loop {
                match inside.recv(&fcx).await {
                    Ok(p) => inside.send(p),
                    Err(RecvError::Closed) => return Ok(()),
                    Err(e) => return Err(e.into()),
                }
            }
        }));
        let client = tokio::spawn(run(fictionet::Seed::random(), move |fcx| async move {
            for i in 0..100u8 {
                outside.send(Packet(vec![i]));
                assert_eq!(outside.recv(&fcx).await?, Packet(vec![i]));
                if i % 25 == 0 {
                    fcx.sleep(ms(1)).await?;
                }
            }
            Ok(())
        }));
        client.await.unwrap().unwrap();
        echo.await.unwrap().unwrap();
    });
}

/// A sleep too long for the clock to represent waits until cancelled. It
/// does not panic.
#[test]
fn a_sleep_without_end_waits_until_cancelled() {
    let res = within(Duration::from_secs(5), || {
        block_on(run(fictionet::Seed::random(), |fcx| async move {
            fcx.spawn(|fcx| async move {
                assert_eq!(fcx.sleep(Duration::MAX).await, Err(Cancelled));
                let far = fcx.now() + Duration::from_secs(u64::MAX / 2);
                assert_eq!(fcx.sleep_until(far).await, Err(Cancelled));
                Ok(())
            });
            fcx.sleep(ms(20)).await?;
            Err(Boom("stop").into())
        }))
    });
    assert_eq!(res.unwrap_err().to_string(), "stop");
}

/// Many waits outside the run, each in its own tokio task, stay asleep
/// until something happens. Cancelling the region still ends every one.
#[test]
fn many_waits_outside_the_run_stay_idle() {
    const WAITERS: usize = 1500;
    let polls = Arc::new(AtomicU64::new(0));
    let ended = Arc::new(AtomicU64::new(0));
    let (p, e) = (polls.clone(), ended.clone());
    // The sandbox ends of the cables stay open until the test ends, so the
    // waits end by the cancel, not by a closed cable.
    let keep = Arc::new(Mutex::new(Vec::new()));
    let k = keep.clone();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_time()
        .build()
        .unwrap();
    let out = rt.block_on(async move {
        tokio::spawn(run(fictionet::Seed::random(), move |fcx| async move {
            for _ in 0..WAITERS {
                let (mut mine, theirs) = pair();
                k.lock().unwrap().push(theirs);
                let (fcx, polls, ended) = (fcx.clone(), p.clone(), e.clone());
                tokio::spawn(async move {
                    let mut recv = std::pin::pin!(mine.recv(&fcx));
                    let res = std::future::poll_fn(|cx| {
                        polls.fetch_add(1, Ordering::SeqCst);
                        recv.as_mut().poll(cx)
                    })
                    .await;
                    assert_eq!(res, Err(RecvError::Cancelled));
                    ended.fetch_add(1, Ordering::SeqCst);
                });
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            let settled = p.load(Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(300)).await;
            let later = p.load(Ordering::SeqCst);
            assert!(
                later - settled < 10,
                "{} polls of idle waits in 300 ms",
                later - settled
            );
            Err(Boom("stop").into())
        }))
        .await
        .unwrap()
    });
    assert_eq!(out.unwrap_err().to_string(), "stop");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while ended.load(Ordering::SeqCst) < WAITERS as u64 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(ended.load(Ordering::SeqCst), WAITERS as u64);
}

/// Dropping the run also ends waits outside it: they read `Cancelled`, and
/// joins of dropped work end too.
#[test]
fn dropping_the_run_ends_waits_outside_it() {
    let (tx, rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();
    let mut future = Box::pin(run(fictionet::Seed::random(), move |fcx| async move {
        let task = fcx.spawn(|fcx| async move {
            fcx.cancelled().await;
            Ok(())
        });
        let outside = fcx.clone();
        std::thread::spawn(move || {
            let res = block_on(async {
                let mut join = std::pin::pin!(task.join(&outside));
                let mut ready_tx = Some(ready_tx);
                let joined = std::future::poll_fn(|cx| {
                    let result = join.as_mut().poll(cx);
                    if result.is_pending()
                        && let Some(tx) = ready_tx.take()
                    {
                        tx.send(()).unwrap();
                    }
                    result
                })
                .await
                .map_err(|e| e.to_string());
                outside.cancelled().await;
                joined
            });
            tx.send(res).unwrap();
        });
        Ok(())
    }));
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    for _ in 0..3 {
        assert!(future.as_mut().poll(&mut cx).is_pending());
    }
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the outside join was not polled");
    drop(future);
    let res = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("a wait outside the run did not end");
    assert_eq!(res, Err("the join stopped".to_owned()));
}

#[test]
fn cancel_stops_the_world_cleanly() {
    let (attacher, attachments) = attachments();
    let mut agent = attacher.attach("agent").unwrap();
    let ended = Arc::new(AtomicU64::new(0));
    let e = ended.clone();
    let out = within(Duration::from_secs(5), move || {
        block_on(run(fictionet::Seed::random(), move |fcx| async move {
            // An echo world: it passes the cancel up with `?`.
            fcx.spawn(move |fcx| async move {
                let mut attachments = attachments;
                let mut sandbox = attachments.get(&fcx, "agent").await?;
                loop {
                    let packet = sandbox.recv(&fcx).await?;
                    sandbox.send(packet);
                }
            });
            // A task that would sleep for a minute.
            fcx.spawn(move |fcx| async move {
                let r = fcx.sleep(Duration::from_secs(60)).await;
                e.fetch_add(1, Ordering::SeqCst);
                r?;
                Ok(())
            });
            agent.send(Packet(vec![0x45, 0, 0, 20]));
            assert_eq!(agent.recv(&fcx).await?, Packet(vec![0x45, 0, 0, 20]));
            fcx.cancel();
            assert!(fcx.is_cancelled());
            Ok(())
        }))
    });
    out.unwrap();
    assert_eq!(ended.load(Ordering::SeqCst), 1);
}

#[test]
fn an_error_before_cancel_is_still_reported() {
    let out = within(Duration::from_secs(5), || {
        block_on(run(fictionet::Seed::random(), |fcx| async move {
            let failing = fcx.spawn(|_fcx| async { Err(Boom("first").into()) });
            assert!(failing.join(&fcx).await.is_err());
            fcx.cancel();
            Ok(())
        }))
    });
    assert_eq!(out.unwrap_err().to_string(), "first");
}

#[test]
fn errors_after_cancel_are_dropped_even_when_not_cancellations() {
    let out = within(Duration::from_secs(5), || {
        block_on(run(fictionet::Seed::random(), |fcx| async move {
            fcx.spawn(|fcx| async move {
                fcx.cancelled().await;
                Err(Boom("after").into())
            });
            fcx.cancel();
            Ok(())
        }))
    });
    out.unwrap();
}

#[test]
fn cancel_from_another_thread_stops_the_run() {
    let (tx, rx) = mpsc::channel();
    let stopper = std::thread::spawn(move || {
        let fcx: fictionet::Cx = rx.recv().unwrap();
        fcx.cancel();
    });
    let out = within(Duration::from_secs(5), move || {
        block_on(run(fictionet::Seed::random(), move |fcx| async move {
            tx.send(fcx.clone()).unwrap();
            fcx.sleep(Duration::from_secs(60)).await?;
            Ok(())
        }))
    });
    out.unwrap();
    stopper.join().unwrap();
}

#[test]
fn an_outside_wait_raced_against_cancelled_ends() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let out = runtime.block_on(async {
        let world = run(fictionet::Seed::random(), |fcx| async move {
            fcx.spawn(|fcx| async move {
                // A wait Fictionet knows nothing about.
                let never = std::future::pending::<()>();
                tokio::select! {
                    _ = never => {}
                    _ = fcx.cancelled() => {}
                }
                Ok(())
            });
            fcx.sleep(ms(10)).await?;
            fcx.cancel();
            Ok(())
        });
        tokio::time::timeout(Duration::from_secs(5), world).await
    });
    out.expect("the run did not end").unwrap();
}

/// A joiner that sees a task fail and then cancels must not erase the
/// failure: the region takes the error before the joiner is woken. Here
/// the joiner's waker cancels the moment it is woken, so it lands exactly
/// between the two.
#[test]
fn a_joiner_that_cancels_after_a_failure_keeps_the_error() {
    let out = within(Duration::from_secs(5), || {
        block_on(run(fictionet::Seed::random(), |fcx| async move {
            let (ready, mut waiting) = pair();
            let task = fcx.spawn(move |fcx| async move {
                assert_eq!(waiting.recv(&fcx).await, Err(RecvError::Closed));
                Err(Boom("failed").into())
            });
            // Poll the join once, outside the run's own tasks, with the
            // cancelling waker, then leave it waiting.
            let waker = std::task::Waker::from(Arc::new(CancelOnWake(fcx.clone())));
            let watcher = fcx.clone();
            std::thread::spawn(move || {
                let mut join = std::pin::pin!(task.join(&watcher));
                let _ = join
                    .as_mut()
                    .poll(&mut std::task::Context::from_waker(&waker));
                drop(ready);
                block_on(watcher.cancelled());
            });
            Ok(())
        }))
    });
    assert_eq!(out.unwrap_err().to_string(), "failed");
}

/// Cancels the run through a clone of its `Cx` the moment it is woken.
struct CancelOnWake(fictionet::Cx);
impl std::task::Wake for CancelOnWake {
    fn wake(self: Arc<Self>) {
        self.0.cancel();
    }
}

/// A task that fails while it still holds an interface: dropping the task
/// closes the interface, which wakes a watcher outside the run that
/// cancels. The failure came first, so `run` still returns it.
#[test]
fn a_cancel_woken_by_dropping_a_failed_task_keeps_the_error() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    let out = within(Duration::from_secs(5), || {
        let (inside, mut outside) = pair();
        let (tx, rx) = mpsc::channel();
        let mut world = Box::pin(run(fictionet::Seed::random(), move |fcx| async move {
            tx.send(fcx.clone()).unwrap();
            fcx.spawn(move |_| {
                std::future::poll_fn(move |_| {
                    let _held = &inside;
                    Poll::Ready(Err(Boom("failed while holding a link").into()))
                })
            });
            Ok(())
        }));
        assert!(
            world
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let fcx = rx.recv().unwrap();
        let wake = Waker::from(Arc::new(CancelOnWake(fcx.clone())));
        assert!(
            outside
                .poll_recv(&fcx, &mut Context::from_waker(&wake))
                .is_pending()
        );
        block_on(world)
    });
    assert_eq!(out.unwrap_err().to_string(), "failed while holding a link");
}

/// A joiner outside the run, polled the moment it is woken, gets the
/// failed task's message: the result is there before the failure cancels
/// the region.
#[test]
fn a_joiner_outside_the_run_gets_the_message_of_a_failed_task() {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    type JoinFuture = Pin<Box<dyn Future<Output = Result<(), JoinError>> + Send>>;
    /// Polls the join again, right inside `wake`.
    struct RePoll {
        job: Mutex<Option<JoinFuture>>,
        result: Mutex<Option<String>>,
    }
    impl RePoll {
        fn poll(&self, wake: &Waker) {
            let Some(mut job) = self.job.lock().unwrap().take() else {
                return;
            };
            match job.as_mut().poll(&mut Context::from_waker(wake)) {
                Poll::Ready(value) => {
                    *self.result.lock().unwrap() = Some(match value {
                        Ok(()) => "ok".into(),
                        Err(JoinError::Failed(e)) => e.to_string(),
                        Err(JoinError::Cancelled) => "cancelled".into(),
                    })
                }
                Poll::Pending => *self.job.lock().unwrap() = Some(job),
            }
        }
    }
    impl std::task::Wake for RePoll {
        fn wake(self: Arc<Self>) {
            self.poll(Waker::noop());
        }
    }
    let (out, joined) = within(Duration::from_secs(5), || {
        let (tx, rx) = mpsc::channel();
        let mut world = Box::pin(run(fictionet::Seed::random(), move |fcx| async move {
            let task = fcx.spawn(|_| async { Err(Boom("the worker failed").into()) });
            tx.send((task, fcx.clone())).unwrap();
            fcx.cancelled().await;
            Ok(())
        }));
        assert!(
            world
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let (task, fcx) = rx.recv().unwrap();
        let watcher = Arc::new(RePoll {
            job: Mutex::new(Some(Box::pin(async move { task.join(&fcx).await }))),
            result: Mutex::new(None),
        });
        watcher.poll(&Waker::from(watcher.clone()));
        let out = block_on(world);
        let joined = watcher.result.lock().unwrap().clone();
        (out, joined)
    });
    assert_eq!(out.unwrap_err().to_string(), "the worker failed");
    assert_eq!(joined.as_deref(), Some("the worker failed"));
}

#[test]
fn dropping_the_run_drops_tasks_in_spawn_order() {
    struct RecordDrop(usize, Arc<Mutex<Vec<usize>>>);
    impl Drop for RecordDrop {
        fn drop(&mut self) {
            self.1.lock().unwrap().push(self.0);
        }
    }
    let log = Arc::new(Mutex::new(Vec::new()));
    let inside = log.clone();
    let mut future = Box::pin(run(fictionet::Seed::random(), move |fcx| async move {
        for id in [8, 3, 12, 1, 9] {
            let guard = RecordDrop(id, inside.clone());
            fcx.spawn(move |_fcx| async move {
                let _guard = guard;
                std::future::pending::<()>().await;
                Ok(())
            });
        }
        Ok(())
    }));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(future.as_mut().poll(&mut cx).is_pending());
    assert!(future.as_mut().poll(&mut cx).is_pending());
    assert!(log.lock().unwrap().is_empty());
    drop(future);
    assert_eq!(*log.lock().unwrap(), [8, 3, 12, 1, 9]);
}
