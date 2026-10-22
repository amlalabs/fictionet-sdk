use std::future::{Future, pending, poll_fn};
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use fictionet::time::{Instant, ms};
use fictionet::{Cancelled, JoinError, RaceError, RunMode, Seed, Timer, block_on, lab};

#[test]
fn idle_drains_spawned_and_woken_work_before_advancing_time() {
    let stage = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    block_on(fictionet::lab(Seed::from_u64(1), move |cx| async move {
        let child = stage.clone();
        let task = cx.spawn(move |cx| async move {
            for _ in 0..100 {
                cx.yield_now().await?;
            }
            cx.spawn(move |cx| async move {
                child.store(1, std::sync::atomic::Ordering::SeqCst);
                cx.sleep(ms(1)).await?;
                child.store(2, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            });
            Ok(())
        });
        cx.idle().await?;
        assert_eq!(cx.now(), Instant::ZERO);
        assert_eq!(stage.load(std::sync::atomic::Ordering::SeqCst), 1);
        task.join(&cx).await?;
        cx.idle().await?;
        assert_eq!(cx.now(), Instant::ZERO);
        cx.sleep(ms(1)).await?;
        cx.idle().await?;
        assert_eq!(stage.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(cx.now(), Instant::ZERO + ms(1));
        cx.cancel();
        assert_eq!(cx.idle().await, Err(Cancelled));
        Ok(())
    }))
    .unwrap();
}

#[test]
fn dropped_idle_waits_do_not_delay_the_clock() {
    block_on(lab(Seed::from_u64(1), |cx| async move {
        let mut idle = Box::pin(cx.idle());
        poll_fn(|task| {
            assert!(idle.as_mut().poll(task).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(idle);
        cx.sleep(ms(1)).await?;
        assert_eq!(cx.now(), Instant::ZERO + ms(1));
        Ok(())
    }))
    .unwrap();
}

#[test]
fn a_minute_passes_without_waiting_a_minute() {
    let real = std::time::Instant::now();
    block_on(lab(Seed::from_u64(1), |cx| async move {
        assert_eq!(cx.mode(), RunMode::Lab);
        assert_eq!(cx.now(), Instant::ZERO);
        cx.sleep(Duration::from_secs(60)).await?;
        assert_eq!(cx.now().since_start(), Duration::from_secs(60));
        Ok(())
    }))
    .unwrap();
    assert!(real.elapsed() < Duration::from_secs(5));
}

#[test]
fn deadlines_and_equal_deadlines_wake_in_order() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let out = log.clone();
    block_on(lab(Seed::from_u64(1), move |cx| async move {
        for (id, deadline) in [(0, 30), (1, 10), (2, 10), (3, 20), (4, 10)] {
            let out = out.clone();
            cx.spawn(move |cx| async move {
                cx.sleep(ms(deadline)).await?;
                out.lock().unwrap().push((id, cx.now().since_start()));
                Ok(())
            });
        }
        Ok(())
    }))
    .unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        [
            (1, ms(10)),
            (2, ms(10)),
            (4, ms(10)),
            (3, ms(20)),
            (0, ms(30))
        ]
    );
}

#[test]
fn reset_and_drop_remove_old_deadlines() {
    block_on(lab(Seed::from_u64(1), |cx| async move {
        let mut early = Timer::new(&cx);
        let mut late = Timer::new(&cx);
        let mut dropped = Timer::new(&cx);
        poll_fn(|task| {
            assert!(early.poll_until(task, Instant::ZERO + ms(100)).is_pending());
            assert!(early.poll_until(task, Instant::ZERO + ms(20)).is_pending());
            assert!(late.poll_until(task, Instant::ZERO + ms(1)).is_pending());
            assert!(late.poll_until(task, Instant::ZERO + ms(40)).is_pending());
            assert!(dropped.poll_until(task, Instant::ZERO + ms(2)).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(dropped);
        poll_fn(|task| early.poll_until(task, Instant::ZERO + ms(20))).await?;
        assert_eq!(cx.now().since_start(), ms(20));
        poll_fn(|task| late.poll_until(task, Instant::ZERO + ms(40))).await?;
        assert_eq!(cx.now().since_start(), ms(40));
        Ok(())
    }))
    .unwrap();
}

#[test]
fn cancellation_wins_at_the_deadline_but_race_polls_work_first() {
    block_on(lab(Seed::from_u64(1), |cx| async move {
        cx.spawn(|cx| async move {
            cx.sleep(ms(10)).await?;
            cx.cancel();
            Ok(())
        });
        cx.spawn(|cx| async move {
            let mut timer = Timer::new(&cx);
            let mut sleep = pin!(cx.sleep(ms(10)));
            poll_fn(|task| {
                assert!(sleep.as_mut().poll(task).is_pending());
                assert!(timer.poll_until(task, Instant::ZERO + ms(10)).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(sleep.await, Err(Cancelled));
            assert_eq!(
                poll_fn(|task| timer.poll_until(task, cx.now())).await,
                Err(Cancelled)
            );
            assert_eq!(cx.now().since_start(), ms(10));
            assert_eq!(cx.race(Some(cx.now()), async { 7 }).await, Ok(7));
            assert_eq!(
                cx.race(Some(cx.now()), pending::<()>()).await,
                Err(RaceError::Cancelled)
            );
            Ok(())
        });
        Ok(())
    }))
    .unwrap();
    block_on(lab(Seed::from_u64(1), |cx| async move {
        let deadline = Instant::ZERO + ms(10);
        assert_eq!(
            cx.race(Some(deadline), cx.sleep_until(deadline)).await,
            Ok(Ok(()))
        );
        assert_eq!(cx.now(), deadline);
        Ok(())
    }))
    .unwrap();
}

#[test]
fn spawns_and_self_wakes_drain_before_time_advances() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let out = log.clone();
    block_on(lab(Seed::from_u64(1), move |cx| async move {
        let mut polls = 0;
        poll_fn(|task| {
            assert_eq!(cx.now(), Instant::ZERO);
            polls += 1;
            if polls < 100 {
                task.waker().wake_by_ref();
                return Poll::Pending;
            }
            let out = out.clone();
            cx.spawn(move |cx| async move {
                out.lock().unwrap().push(cx.now().since_start());
                cx.sleep(ms(5)).await?;
                out.lock().unwrap().push(cx.now().since_start());
                Ok(())
            });
            // Spawning admitted work, without self-waking, must prevent a jump.
            Poll::Ready(())
        })
        .await;
        cx.sleep(ms(10)).await?;
        assert_eq!(cx.now().since_start(), ms(10));
        Ok(())
    }))
    .unwrap();
    assert_eq!(*log.lock().unwrap(), [Duration::ZERO, ms(5)]);
}

#[test]
fn a_retained_context_cannot_reopen_a_completed_region() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        for outcome in ["ok", "failed", "stopped"] {
            let mut retained = None;
            let result = fcx
                .region(|child| {
                    retained = Some(child.clone());
                    async move {
                        match outcome {
                            "failed" => Err(fictionet::Error::msg("first failure")),
                            "stopped" => {
                                child.cancel();
                                Ok(())
                            }
                            _ => Ok(()),
                        }
                    }
                })
                .await;
            if outcome == "failed" {
                assert_eq!(result.unwrap_err().to_string(), "first failure");
            } else {
                result?;
            }
            let child = retained.unwrap();
            assert_eq!(child.is_cancelled(), outcome != "ok");
            let held = Arc::new(());
            let captured = held.clone();
            let task = child.spawn(move |_fcx| async move {
                let _held = captured;
                Err(fictionet::Error::msg("late failure"))
            });
            assert!(matches!(task.join(&fcx).await, Err(JoinError::Cancelled)));
            assert_eq!(Arc::strong_count(&held), 1);
            assert_eq!(child.is_cancelled(), outcome != "ok");
            assert!(!fcx.is_cancelled());
        }
        Ok(())
    }))
    .unwrap();
}

#[test]
fn an_active_cancelled_region_can_spawn_cleanup_work() {
    let cleaned = Arc::new(Mutex::new(false));
    let out = cleaned.clone();
    block_on(lab(Seed::from_u64(1), move |fcx| async move {
        fcx.region(|child| async move {
            child.spawn(move |fcx| async move {
                fcx.cancelled().await;
                fcx.spawn(move |fcx| async move {
                    assert!(fcx.is_cancelled());
                    assert_eq!(fcx.sleep(ms(1)).await, Err(Cancelled));
                    *out.lock().unwrap() = true;
                    Ok(())
                });
                Ok(())
            });
            child.cancel();
            Ok(())
        })
        .await?;
        assert!(*cleaned.lock().unwrap());
        Ok(())
    }))
    .unwrap();
}

#[test]
fn infinite_sleeps_are_unarmed_and_cancellable() {
    block_on(lab(Seed::from_u64(1), |cx| async move {
        cx.spawn(|cx| async move {
            assert_eq!(cx.sleep(Duration::MAX).await, Err(Cancelled));
            assert_eq!(cx.now().since_start(), ms(1));
            Ok(())
        });
        cx.sleep(ms(1)).await?;
        cx.cancel();
        Ok(())
    }))
    .unwrap();
    let error = block_on(lab(Seed::from_u64(1), |cx| async move {
        cx.sleep(Duration::MAX).await?;
        Ok(())
    }))
    .unwrap_err();
    assert!(error.to_string().contains("lab deadlock"));
}

#[test]
fn overflow_waits_are_unarmed_and_virtual_time_is_bounded() {
    let error = block_on(lab(Seed::from_u64(1), |cx| async move {
        cx.sleep(ms(1)).await?;
        cx.sleep(Duration::MAX).await?;
        Ok(())
    }))
    .unwrap_err();
    assert!(error.to_string().contains("lab deadlock"));
    let error = block_on(lab(Seed::from_u64(1), |cx| async move {
        cx.sleep(Duration::from_micros(i64::MAX as u64) + ms(1))
            .await?;
        Ok(())
    }))
    .unwrap_err();
    assert!(error.to_string().contains("signed microsecond"));
}

#[test]
fn a_live_task_without_a_deadline_reports_deadlock() {
    let error = block_on(lab(Seed::from_u64(1), |_| async {
        pending::<()>().await;
        Ok(())
    }))
    .unwrap_err();
    assert!(error.to_string().contains("lab deadlock"));
}

async fn clock_world(cx: fictionet::Cx, duration: Duration) -> fictionet::Result {
    assert_eq!(cx.now(), Instant::ZERO);
    cx.sleep(duration).await?;
    assert_eq!(cx.now().since_start(), duration);
    cx.sleep(duration).await?;
    assert_eq!(cx.now().since_start(), duration * 2);
    Ok(())
}

#[test]
fn two_labs_can_be_interleaved_on_one_thread() {
    let mut a = pin!(lab(Seed::from_u64(1), |cx| { clock_world(cx, ms(10)) }));
    let mut b = pin!(lab(Seed::from_u64(2), |cx| { clock_world(cx, ms(37)) }));
    let mut task = Context::from_waker(Waker::noop());
    let (mut done_a, mut done_b) = (false, false);
    while !done_a || !done_b {
        if !done_a && let Poll::Ready(result) = a.as_mut().poll(&mut task) {
            result.unwrap();
            done_a = true;
        }
        if !done_b && let Poll::Ready(result) = b.as_mut().poll(&mut task) {
            result.unwrap();
            done_b = true;
        }
    }
}

#[test]
fn a_lab_moves_between_host_threads() {
    let mut world = Box::pin(lab(Seed::from_u64(1), |cx| clock_world(cx, ms(100))));
    assert!(
        world
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    std::thread::spawn(move || block_on(world))
        .join()
        .unwrap()
        .unwrap();
}

#[cfg(feature = "web-proxy")]
#[test]
fn real_upstreams_can_be_used_in_a_lab() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let upstream = std::sync::Arc::new(fictionet_host::Client::new());
        let _proxy = fictionet::stdlib::web::proxy(&fcx, upstream.clone())?;
        let _forward =
            fictionet::stdlib::web::forward(&fcx, "http://127.0.0.1:8080".parse()?, upstream)?;
        Ok(())
    }))
    .unwrap();
}

fn recorded_world() -> Vec<(Duration, u64)> {
    let draws = Arc::new(Mutex::new(Vec::new()));
    let output = draws.clone();
    block_on(lab(Seed::from_u64(7), move |cx| async move {
        for _ in 0..4 {
            cx.sleep(ms(15)).await?;
            output
                .lock()
                .unwrap()
                .push((cx.now().since_start(), cx.random_u64()));
        }
        Ok(())
    }))
    .unwrap();
    Arc::try_unwrap(draws).unwrap().into_inner().unwrap()
}

#[test]
fn lab_draws_and_times_repeat() {
    let first = recorded_world();
    assert_eq!(first.len(), 4);
    assert_eq!(first, recorded_world());
}
