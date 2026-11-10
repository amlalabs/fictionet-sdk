//! What starting a job costs a stack that is already running: the job's
//! own value, and nothing in the table that runs it or in the context it
//! runs in, whether jobs come one after another or many at once.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use fictionet::stdlib::layer::{
    Admit, ByteStream, Env, Harness, Layer, StreamCommand, StreamEvent, Top,
};
use fictionet::stdlib::services::stack::{Job, Polling};
use fictionet::{Cx, Seed, block_on, lab};

use crate::common::alloc::allocations;

/// Counts the test moves: the jobs it wants handed over, and how many of
/// them may be done.
#[derive(Default)]
struct Counts {
    wanted: AtomicUsize,
    allowed: AtomicUsize,
}

/// The `index`th job: done once the test allows that many.
struct Numbered {
    index: usize,
    counts: Arc<Counts>,
}

impl Job for Numbered {
    type Done = ();

    fn poll(&mut self, fcx: Option<&Cx>, _: &mut Context<'_>) -> Poll<()> {
        assert!(fcx.is_some_and(|fcx| !fcx.is_cancelled()));
        if self.index < self.counts.allowed.load(Ordering::Relaxed) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// Hands over jobs as the test wants them, and counts those done.
struct Jobs {
    counts: Arc<Counts>,
    made: usize,
    done: usize,
}

impl Layer for Jobs {
    type Lower = ByteStream;
    type Upper = Top;
    type Report = ();
    type Timer = ();
    type Work = Numbered;
    type Done = ();
    type Error = Infallible;

    fn on_event(
        &mut self,
        _: &mut Env<'_, ()>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        Ok(Admit::Closed(event))
    }

    fn on_command(
        &mut self,
        _: &mut Env<'_, ()>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn take_command(&mut self, _: &mut Env<'_, ()>) -> Option<StreamCommand> {
        None
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }

    fn take_work(&mut self) -> Option<Numbered> {
        if self.made >= self.counts.wanted.load(Ordering::Relaxed) {
            return None;
        }
        self.made += 1;
        Some(Numbered {
            index: self.made - 1,
            counts: self.counts.clone(),
        })
    }

    fn on_done(&mut self, _: &mut Env<'_, ()>, (): ()) -> Result<(), Infallible> {
        self.done += 1;
        Ok(())
    }
}

/// Runs `steps` steps of a stack whose jobs run in a world, `running` of
/// them at a time: each step one more job is allowed to finish and one
/// more is handed over. Returns the allocations the measured steps made,
/// after as many steps of warm-up.
fn steady(running: usize, steps: usize) -> usize {
    let measured = Arc::new(AtomicUsize::new(usize::MAX));
    let out = measured.clone();
    block_on(lab(Seed::from_u64(41), move |fcx| async move {
        let counts = Arc::new(Counts::default());
        counts.wanted.store(running, Ordering::Relaxed);
        let stack = Jobs {
            counts: counts.clone(),
            made: 0,
            done: 0,
        };
        let mut harness =
            Harness::new(Seed::from_u64(41), stack).with_worker(Polling::in_world(fcx.clone()));
        let step = |harness: &mut Harness<Jobs>| {
            counts.allowed.fetch_add(1, Ordering::Relaxed);
            counts.wanted.fetch_add(1, Ordering::Relaxed);
            harness.settle().unwrap();
            assert_eq!(harness.jobs(), running);
        };
        harness.settle().unwrap();
        for _ in 0..steps {
            step(&mut harness);
        }
        let ((), allocated) = allocations(|| {
            for _ in 0..steps {
                step(&mut harness);
            }
        });
        assert_eq!(harness.layer().done, 2 * steps);
        out.store(allocated, Ordering::Relaxed);
        Ok(())
    }))
    .unwrap();
    measured.load(Ordering::Relaxed)
}

/// Jobs that come and go one at a time allocate nothing once the first
/// has run: the table's places and the job's context are used again.
#[test]
fn jobs_one_after_another_allocate_nothing() {
    assert_eq!(steady(0, 200), 0);
}

/// The same with many jobs running at once: as one ends and another
/// starts, the table keeps its places and the ended job's context goes to
/// the next.
#[test]
fn jobs_many_at_once_allocate_nothing_as_they_come_and_go() {
    for running in [1, 5, 10, 40] {
        assert_eq!(steady(running, 200), 0, "{running} at once");
    }
}
