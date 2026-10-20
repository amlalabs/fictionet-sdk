use std::future::{Future, pending, poll_fn};
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use fictionet::time::{Instant, ms};
use fictionet::{Cancelled, JoinError, RaceError, RunMode, RunOptions, Seed, Timer, block_on, lab};

#[test]
fn idle_drains_spawned_and_woken_work_before_advancing_time() {
    block_on(crate::common::observed_lab(
        Seed::from_u64(1),
        |cx, log| async move {
            let task = cx.spawn(|cx| async move {
                for _ in 0..100 {
                    cx.yield_now().await?;
                }
                cx.spawn(|cx| async move {
                    cx.emit("test", "ready", |event| event);
                    cx.sleep(ms(1)).await?;
                    cx.emit("test", "later", |event| event);
                    Ok(())
                });
                Ok(())
            });
            cx.idle().await?;
            assert_eq!(cx.now(), Instant::ZERO);
            assert_eq!(log.checked_of("test", "ready").unwrap().len(), 1);
            assert!(log.checked_of("test", "later").unwrap().is_empty());
            task.join(&cx).await?;
            cx.idle().await?;
            assert_eq!(cx.now(), Instant::ZERO);
            cx.sleep(ms(1)).await?;
            cx.idle().await?;
            assert_eq!(log.checked_of("test", "later").unwrap().len(), 1);
            assert_eq!(cx.now(), Instant::ZERO + ms(1));
            cx.cancel();
            assert_eq!(cx.idle().await, Err(Cancelled));
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn dropped_idle_waits_do_not_delay_the_clock() {
    block_on(lab(RunOptions::new(Seed::from_u64(1)), |cx| async move {
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
fn event_wait_wakes_at_each_raw_fact() {
    for _ in 0..3 {
        block_on(crate::common::observed_lab(
            Seed::from_u64(1),
            |cx, log| async move {
                cx.spawn(|cx| async move {
                    cx.sleep(Duration::from_nanos(7)).await?;
                    cx.emit("test", "ready", |event| event);
                    cx.emit("test", "repeat", |event| event);
                    cx.sleep(ms(2)).await?;
                    cx.emit("test", "repeat", |event| event);
                    Ok(())
                });
                let got = log
                    .wait(&cx, 0, 1, ms(1), |e| e.is("test", "ready"))
                    .await?;
                assert_eq!(got.len(), 1);
                assert_eq!(cx.now().since_start(), Duration::from_nanos(7));
                let checks = std::sync::Mutex::new(Vec::new());
                let got = log
                    .wait(&cx, 0, 2, Duration::from_secs(2), |e| {
                        if e.is("test", "repeat") {
                            checks.lock().unwrap().push(cx.now());
                            true
                        } else {
                            false
                        }
                    })
                    .await?;
                assert_eq!(got.len(), 2);
                let first = Instant::ZERO + Duration::from_nanos(7);
                assert_eq!(cx.now(), first + ms(2));
                assert_eq!(*checks.lock().unwrap(), [first, cx.now()]);
                Ok(())
            },
        ))
        .unwrap();
    }
}

#[test]
fn event_wait_stops_at_its_exact_limit() {
    for limit in [Duration::ZERO, Duration::from_nanos(1), ms(1), ms(15)] {
        block_on(crate::common::observed_lab(
            Seed::from_u64(1),
            |fcx, log| async move {
                fcx.sleep(ms(3)).await?;
                fcx.emit("test", "tick", |event| event);
                let start = fcx.now();
                let got = log
                    .wait(&fcx, 0, 2, limit, |event| event.is("test", "tick"))
                    .await?;
                assert_eq!(got.len(), 1);
                assert_eq!(fcx.now(), start + limit);
                Ok(())
            },
        ))
        .unwrap();
    }
}

#[test]
fn event_wait_accepts_an_overflowing_limit() {
    block_on(crate::common::observed_lab(
        Seed::from_u64(1),
        |fcx, log| async move {
            fcx.sleep(ms(1)).await?;
            fcx.spawn(|fcx| async move {
                fcx.sleep(ms(1)).await?;
                fcx.emit("test", "tick", |event| event);
                Ok(())
            });
            let got = log
                .wait(&fcx, 0, 1, Duration::MAX, |event| event.is("test", "tick"))
                .await?;
            assert_eq!(got.len(), 1);
            assert_eq!(fcx.now().since_start(), ms(2));
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn event_wait_cancellation_wins_at_the_deadline() {
    block_on(crate::common::observed_lab(
        Seed::from_u64(1),
        |fcx, log| async move {
            let mut wait = pin!(log.wait(&fcx, 0, 1, ms(1), |e| e.is("test", "tick")));
            poll_fn(|cx| {
                assert!(wait.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            fcx.sleep(ms(1)).await?;
            fcx.emit("test", "tick", |event| event);
            fcx.cancel();
            assert!(
                wait.await
                    .unwrap_err()
                    .downcast_ref::<Cancelled>()
                    .is_some()
            );
            assert_eq!(fcx.now().since_start(), ms(1));
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn a_minute_passes_without_waiting_a_minute() {
    let real = std::time::Instant::now();
    block_on(lab(RunOptions::new(Seed::from_u64(1)), |cx| async move {
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
    block_on(lab(
        RunOptions::new(Seed::from_u64(1)),
        move |cx| async move {
            for (id, deadline) in [(0, 30), (1, 10), (2, 10), (3, 20), (4, 10)] {
                let out = out.clone();
                cx.spawn(move |cx| async move {
                    cx.sleep(ms(deadline)).await?;
                    out.lock().unwrap().push((id, cx.now().since_start()));
                    Ok(())
                });
            }
            Ok(())
        },
    ))
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
    block_on(lab(RunOptions::new(Seed::from_u64(1)), |cx| async move {
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
    block_on(lab(RunOptions::new(Seed::from_u64(1)), |cx| async move {
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
    block_on(lab(RunOptions::new(Seed::from_u64(1)), |cx| async move {
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
    block_on(lab(
        RunOptions::new(Seed::from_u64(1)),
        move |cx| async move {
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
        },
    ))
    .unwrap();
    assert_eq!(*log.lock().unwrap(), [Duration::ZERO, ms(5)]);
}

#[test]
fn a_retained_context_cannot_reopen_a_completed_region() {
    block_on(lab(RunOptions::new(Seed::from_u64(1)), |fcx| async move {
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
    block_on(lab(
        RunOptions::new(Seed::from_u64(1)),
        move |fcx| async move {
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
        },
    ))
    .unwrap();
}

#[test]
fn infinite_sleeps_are_unarmed_and_cancellable() {
    block_on(lab(RunOptions::new(Seed::from_u64(1)), |cx| async move {
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
    let error = block_on(lab(RunOptions::new(Seed::from_u64(1)), |cx| async move {
        cx.sleep(Duration::MAX).await?;
        Ok(())
    }))
    .unwrap_err();
    assert!(error.to_string().contains("lab deadlock"));
}

#[test]
fn overflow_waits_are_unarmed_and_virtual_time_is_bounded() {
    let error = block_on(lab(RunOptions::new(Seed::from_u64(1)), |cx| async move {
        cx.sleep(ms(1)).await?;
        cx.sleep(Duration::MAX).await?;
        Ok(())
    }))
    .unwrap_err();
    assert!(error.to_string().contains("lab deadlock"));
    let error = block_on(lab(RunOptions::new(Seed::from_u64(1)), |cx| async move {
        cx.sleep(Duration::from_micros(i64::MAX as u64) + ms(1))
            .await?;
        Ok(())
    }))
    .unwrap_err();
    assert!(error.to_string().contains("signed microsecond"));
}

#[test]
fn a_live_task_without_a_deadline_reports_deadlock() {
    let error = block_on(lab(RunOptions::new(Seed::from_u64(1)), |_| async {
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
    let mut a = pin!(lab(RunOptions::new(Seed::from_u64(1)), |cx| {
        clock_world(cx, ms(10))
    }));
    let mut b = pin!(lab(RunOptions::new(Seed::from_u64(2)), |cx| {
        clock_world(cx, ms(37))
    }));
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
    let mut world = Box::pin(lab(RunOptions::new(Seed::from_u64(1)), |cx| {
        clock_world(cx, ms(100))
    }));
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

#[test]
fn real_io_is_refused_before_opening_resources() {
    block_on(lab(RunOptions::new(Seed::from_u64(1)), |fcx| async move {
        assert!(
            fcx.require_real_io()
                .unwrap_err()
                .to_string()
                .contains("lab")
        );
        #[cfg(feature = "web-proxy")]
        {
            assert!(
                fictionet::stdlib::web::proxy(&fcx)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("lab")
            );
            assert!(
                fictionet::stdlib::web::forward(&fcx, "http://127.0.0.1:8080".parse()?)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("lab")
            );
        }
        Ok(())
    }))
    .unwrap();
}

fn recorded_world() -> Vec<u8> {
    let log = Arc::new(fictionet_observe::Memory::default());
    let out = log.clone();
    block_on(lab(
        RunOptions::new(Seed::from_u64(7)).observer(out.clone()),
        move |cx| async move {
            assert!(matches!(
                out.checked_of("run", "start").unwrap()[0].get("wall"),
                Some(fictionet::stdlib::protocols::json::Value::Null)
            ));
            for i in 0..4 {
                cx.sleep(ms(15)).await?;
                cx.emit("test", "draw", |event| {
                    event.field("i", i).field("draw", cx.random_u64())
                });
            }
            // Each repeat is delivered as a raw fact.
            cx.emit("test", "repeat", |event| event);
            cx.emit("test", "repeat", |event| event);
            Ok(())
        },
    ))
    .unwrap();
    crate::common::log_bytes(&log)
}

#[test]
fn lab_event_bytes_repeat() {
    assert_eq!(recorded_world(), recorded_world());
}

#[test]
fn seeded_service_faults_repeat_at_the_same_points() {
    use fictionet::events::ConnInfo;
    use fictionet::prelude::*;
    use fictionet::stdlib::codec::{ByteFault, Ending, LineError, Lines, Rule, Trigger};
    use fictionet::stdlib::network::tcp;
    use fictionet::stdlib::services::serve::{self, FaultPlan, Flow, Plan, ServeOptions};

    struct Echo;
    service_fixture! {
        Echo => (Lines, (), std::convert::Infallible);
        decoder(self) { Lines::new(64, Ending::LfOrCrlf) }
        on_item(self, line: Result<Vec<u8>, LineError>; _, driver) -> Flow {
            driver.reply().extend_from_slice(&line.unwrap());
            driver.reply().push(b'\n');
            Ok(Flow::Continue)
        }
    }

    let episode = |seed| {
        let log = Arc::new(fictionet_observe::Memory::default());
        let output = log.clone();
        let points = Arc::new(Mutex::new(Vec::new()));
        let replies = points.clone();
        block_on(lab(
            RunOptions::new(Seed::from_u64(seed)).observer(output),
            move |cx| async move {
                let (a, b) = fictionet::pair();
                let client = tcp::endpoint(&cx, a, "10.0.0.2".parse()?);
                let server = tcp::endpoint(&cx, b, "10.0.0.1".parse()?);
                let mut listener = server.listen(7)?;
                cx.spawn(move |cx| async move {
                    let conn = listener.accept(&cx).await?;
                    let info = ConnInfo::new(1, conn.local_addr(), conn.peer_addr());
                    let options = ServeOptions::default().faults(FaultPlan::new(Plan {
                        outbound: vec![Rule {
                            when: Trigger::Chance { take: 1, out_of: 2 },
                            fault: ByteFault::Corrupt {
                                offset: Some(0),
                                xor: 1,
                            },
                        }],
                        ..Plan::default()
                    }));
                    serve::connection(&cx, conn, info, &mut Echo, &(), &options).await?;
                    Ok(())
                });
                let mut conn = client.connect(&cx, "10.0.0.1:7".parse()?).await?;
                for i in 0..32 {
                    conn.write_all(&cx, b"a\n").await?;
                    let mut reply = [0; 2];
                    let mut filled = 0;
                    while filled < reply.len() {
                        let n = conn.read(&cx, &mut reply[filled..]).await?;
                        assert_ne!(n, 0);
                        filled += n;
                    }
                    assert!(reply == *b"a\n" || reply == *b"`\n");
                    let fault = reply[0] == b'`';
                    replies.lock().unwrap().push((i, cx.now(), fault));
                    cx.emit("client", "reply", |event| {
                        event.field("i", i).field("fault", fault)
                    });
                }
                cx.cancel();
                Ok(())
            },
        ))
        .unwrap();
        let events = crate::common::log_bytes(&log);
        let points = points.lock().unwrap().clone();
        (events, points)
    };
    let first = episode(41);
    assert!(first.1.iter().any(|(_, _, fault)| *fault));
    assert!(first.1.iter().any(|(_, _, fault)| !fault));
    assert_eq!(first, episode(41));
    let other = episode(42);
    assert_ne!(first.0, other.0);
    assert_ne!(first.1, other.1);
}
