//! A layer that notes the environment each call hands it, for the tests of
//! layers that lend their own environment to a part ([`Env::part`]).

use core::convert::Infallible;
use core::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Wake, Waker};

use fictionet::stdlib::layer::{Admit, CommandOf, Env, EventOf, Layer, MAX_DEPTH, Port};
use fictionet::time::Instant;

/// Which call a [`Probe`] got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Call {
    Event,
    Command,
    Timer,
    Done,
    Advance,
    TakeCommand,
}

/// What a [`Probe`] saw of one call: the depth left where it sits, and the
/// waker its environment gives.
struct Seen {
    call: Call,
    room: usize,
    waker: Waker,
}

/// What a [`Probe`] saw, shared with the test that placed it.
#[derive(Clone, Default)]
pub(crate) struct Notes(Arc<Mutex<Vec<Seen>>>);

/// A layer over `Lo` offering `Up` that takes every event and command,
/// declines its timer, which is always due, gives no events or commands,
/// and asks for one piece of work, noting the environment of each call.
pub(crate) struct Probe<Lo, Up> {
    depth: usize,
    notes: Notes,
    /// The work not yet asked for.
    work: bool,
    ports: PhantomData<fn() -> (Lo, Up)>,
}

impl<Lo: Port, Up: Port> Probe<Lo, Up> {
    /// A probe one level deep, and what it will see.
    pub(crate) fn new() -> (Probe<Lo, Up>, Notes) {
        let notes = Notes::default();
        let probe = Probe {
            depth: 1,
            notes: notes.clone(),
            work: true,
            ports: PhantomData,
        };
        (probe, notes)
    }

    /// The depth left where `env` sits: the shallowest part that does not
    /// fit below it.
    fn room<E>(env: &Env<'_, E>) -> usize {
        (1..=MAX_DEPTH + 1)
            .find(|&depth| {
                !env.fits_below(&Probe::<Lo, Up> {
                    depth,
                    notes: Notes::default(),
                    work: false,
                    ports: PhantomData,
                })
            })
            .unwrap_or(MAX_DEPTH + 1)
    }

    fn note<E>(&self, env: &Env<'_, E>, call: Call) {
        let seen = Seen {
            call,
            room: Self::room(env),
            waker: env.waker(),
        };
        self.notes.0.lock().unwrap().push(seen);
    }
}

impl<Lo: Port, Up: Port> Layer for Probe<Lo, Up> {
    type Lower = Lo;
    type Upper = Up;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;

    fn depth(&self) -> usize {
        self.depth
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, ()>,
        _: EventOf<Lo>,
    ) -> Result<Admit<EventOf<Lo>>, Infallible> {
        self.note(env, Call::Event);
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, ()>,
        _: CommandOf<Up>,
    ) -> Result<Admit<CommandOf<Up>>, Infallible> {
        self.note(env, Call::Command);
        Ok(Admit::Taken)
    }

    fn on_timer(&mut self, env: &mut Env<'_, ()>, (): ()) -> Result<bool, Infallible> {
        self.note(env, Call::Timer);
        Ok(false)
    }

    fn on_done(&mut self, env: &mut Env<'_, ()>, (): ()) -> Result<(), Infallible> {
        self.note(env, Call::Done);
        Ok(())
    }

    fn advance(&mut self, env: &mut Env<'_, ()>) -> Result<bool, Infallible> {
        self.note(env, Call::Advance);
        Ok(false)
    }

    fn take_command(&mut self, env: &mut Env<'_, ()>) -> Option<CommandOf<Lo>> {
        self.note(env, Call::TakeCommand);
        None
    }

    fn take_event(&mut self) -> Option<EventOf<Up>> {
        None
    }

    fn take_work(&mut self) -> Option<()> {
        std::mem::take(&mut self.work).then_some(())
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        Some((Instant::ZERO, ()))
    }
}

/// A task waker that counts its wakes, to hand a driver as the task that
/// runs its stack.
#[derive(Default)]
pub(crate) struct Task(AtomicUsize);

impl Task {
    /// A task, and a waker for it.
    pub(crate) fn new() -> (Arc<Task>, Waker) {
        let task = Arc::new(Task::default());
        let waker = Waker::from(task.clone());
        (task, waker)
    }

    fn wakes(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

impl Wake for Task {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

impl Notes {
    /// Checks that each of `calls` reached the probe, and that every call
    /// that did saw `room` levels left and the stack's own waker: one waker
    /// for all of them, and waking it wakes `task`, the task the stack's
    /// driver was told runs it, once.
    pub(crate) fn assert_lent(&self, calls: &[Call], room: usize, task: &Task) {
        let seen = self.0.lock().unwrap();
        for call in calls {
            assert!(
                seen.iter().any(|seen| seen.call == *call),
                "{call:?} never reached the part"
            );
        }
        for each in seen.iter() {
            assert_eq!(
                each.room, room,
                "{:?} reached the part with {} levels left, not {room}",
                each.call, each.room
            );
            assert!(
                each.waker.will_wake(&seen[0].waker),
                "{:?} reached the part with a waker of its own",
                each.call
            );
            let before = task.wakes();
            each.waker.wake_by_ref();
            assert_eq!(
                task.wakes(),
                before + 1,
                "the waker {:?} lent the part does not wake the stack",
                each.call
            );
        }
    }
}
