//! Kani proof over `Jobs::poll`, the part of the runners that polls a
//! stack's work and hands back what finished. It is what wakes a stack for
//! something from outside it, such as another connection's message: the
//! work waits for it, and its result reaches the stack. Included from
//! `src/stdlib/services/stack/job.rs` under `cfg(kani)` as a child module,
//! so it drives the real `Jobs` and may read its private fields.

use super::*;
use std::sync::atomic::AtomicUsize;

/// Work that is ready on its `ready_at`th poll, counting its polls, whose
/// owner may end.
struct Probe {
    polls: Arc<AtomicUsize>,
    ready_at: usize,
    ended: Arc<AtomicBool>,
}

impl Job for Probe {
    type Done = usize;

    fn cancelled(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }

    fn poll(&mut self, _: Option<&Cx>, _: &mut Context<'_>) -> Poll<usize> {
        let polled = self.polls.fetch_add(1, Ordering::SeqCst) + 1;
        if polled >= self.ready_at {
            Poll::Ready(polled)
        } else {
            Poll::Pending
        }
    }
}

/// One piece of work, polled over four rounds, ready on its first, second
/// or third poll, and its owner ending before any round or never. Work is
/// never polled once its owner has ended; what finished is handed back
/// exactly once, with what that poll returned, when it finished before its
/// owner ended, and never otherwise; and the work is gone once it is done
/// or its owner ended.
#[kani::proof]
#[kani::unwind(6)]
fn finished_work_comes_back_once_and_ended_work_is_never_polled() {
    let polls = Arc::new(AtomicUsize::new(0));
    let ended = Arc::new(AtomicBool::new(false));
    let ready_at: usize = kani::any();
    kani::assume((1..=3).contains(&ready_at));
    // The round before which the owner ends; 4 is never.
    let end_at: usize = kani::any();
    kani::assume(end_at <= 4);
    let mut jobs: Jobs<Probe> = Jobs::new();
    jobs.running.push(Running {
        work: Some(Probe {
            polls: polls.clone(),
            ready_at,
            ended: ended.clone(),
        }),
        completed: false,
        region: None,
    });
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut handed = 0;
    for round in 0..4 {
        if round == end_at {
            ended.store(true, Ordering::SeqCst);
        }
        let before = polls.load(Ordering::SeqCst);
        let _ = jobs.poll(None, &mut cx, |done| {
            handed += 1;
            assert_eq!(done, polls.load(Ordering::SeqCst));
            Ok::<(), ()>(())
        });
        if round >= end_at {
            assert_eq!(polls.load(Ordering::SeqCst), before);
        }
    }
    // Polled once a round from the first, it finishes in round ready_at - 1.
    let finished = ready_at - 1 < end_at;
    assert_eq!(handed, usize::from(finished));
    assert!(jobs.is_empty() == (finished || end_at < 4));
}
