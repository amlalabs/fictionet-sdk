use std::future::{Future, pending, poll_fn};
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use fictionet::time::{Instant, ms};
use fictionet::{Cancelled, RaceError, RunMode, Seed, Timer, block_on, lab};

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
    let mut a = pin!(lab(Seed::from_u64(1), |cx| clock_world(cx, ms(10))));
    let mut b = pin!(lab(Seed::from_u64(2), |cx| clock_world(cx, ms(37))));
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

#[test]
fn real_io_is_refused_before_opening_resources() {
    block_on(lab(Seed::from_u64(1), |cx| async move {
        assert!(
            cx.require_real_io()
                .unwrap_err()
                .to_string()
                .contains("lab")
        );
        #[cfg(feature = "web-proxy")]
        assert!(
            fictionet::stdlib::web::proxy(&cx)
                .err()
                .unwrap()
                .to_string()
                .contains("lab")
        );
        Ok(())
    }))
    .unwrap();
}

#[derive(Clone)]
struct Bytes(Arc<Mutex<Vec<u8>>>, std::thread::ThreadId);
impl std::io::Write for Bytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        assert_eq!(self.1, std::thread::current().id());
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn recorded_world() -> Vec<u8> {
    let bytes = Bytes(Arc::default(), std::thread::current().id());
    let out = bytes.clone();
    block_on(lab(Seed::from_u64(7), move |cx| async move {
        use fictionet::events::{Event, Fields};
        let log = cx.events();
        log.to_writer(Box::new(out.clone()));
        log.start(&cx, Fields::default());
        assert!(
            !out.0.lock().unwrap().is_empty(),
            "the sink writes synchronously"
        );
        assert!(matches!(
            log.of("run", "start")[0].get("wall"),
            Some(fictionet::stdlib::json::Value::Null)
        ));
        for i in 0..4 {
            cx.sleep(ms(15)).await?;
            cx.record(
                Event::new("test", "draw")
                    .field("i", i)
                    .field("draw", cx.random_u64()),
            );
        }
        // Open repeat windows are flushed when the run ends, in order.
        cx.record_repeat(Event::new("test", "repeat"), Fields::default());
        cx.record_repeat(Event::new("test", "repeat"), Fields::default());
        assert_eq!(log.lost(), 0);
        Ok(())
    }))
    .unwrap();
    bytes.0.lock().unwrap().clone()
}

#[test]
fn lab_event_bytes_repeat() {
    assert_eq!(recorded_world(), recorded_world());
}
