# Runtime verification

This pass models the runtime of the SDK at `8ccf47fae`: task spawning and
cancellation, wakers and their release order relative to locks, timers and the
clock, regions and joins, and `block_on`. The models are TLA+ specifications in
[verification/runtime/tla](verification/runtime/tla), checked with TLC through
`cargo xtask runtime-verify tlc`. [verification/runtime/README.md](verification/runtime/README.md)
has the table of specs, their correspondence to the Rust, the bounds, and the
ablations.

No bug was confirmed. Every passing configuration completed with an empty queue
and no violation, and every ablation violated exactly the property its config
names, so the properties have teeth. No production code is changed.

## What was modeled and checked

Each locked section of the Rust is one step of a model; anything another thread
can do between two locked sections is its own step. The four specs and their
passing runs:

| Config | Rust | Generated | Distinct | Depth | Result |
| --- | --- | ---: | ---: | ---: | --- |
| `Executor_base` | `RunState::poll`, `TaskWaker`, `RunShared::spawn` and `wake_all`, `Queue::outer` (`src/run.rs`) | 6,415 | 1,369 | 16 | `OuterIsWoken`, `QueuedMeansQueued`, `WakesArePolled`, `CancelsAreSeen` |
| `Region_base` | `Cx::region` and `Cx::spawn` (`src/cx.rs`), `Region` (`src/cx/region.rs`), `Task::join` (`src/cx/task.rs`), the end-of-task steps and `Drop for RunState` (`src/run.rs`) | 124,050 | 30,395 | 17 | `LiveCounts`, `NoTaskOutlives`, `AdmissionClosed`, `ErrorIsAFailure`, `JoinerSeesFailure`, `DroppedRunIsCancelled`, `ReturnMatches`, `OwnerReturns` |
| `LabClock_base` | `Clock` in lab mode (`src/clock.rs`), `Timer` (`src/cx/timer.rs`), `Cx::idle`, `RunShared::idle` and the end of a turn (`src/run.rs`) | 1,322,969 | 526,048 | 39 | `Monotonic`, `WakesInOrderAndInTime`, `EntriesOwned`, `SleepersHaveEntries`, `SleepersWake` |
| `Timers_base` | `Timers::add`, `reset`, `remove`, `State::take_due`, `Timers::thread` (`src/timer.rs`) | 131,483 | 21,878 | 19 | `NoEarlyFire`, `SleepIsSafe`, `DueTimersFire` |

The properties say, in the runtime's terms: a task that is woken is polled
again, even when the wake lands during its own poll; queued work between polls
of the run always comes with a wake of whatever polls the run; a cancel gets
every task polled once more; a region's `live` count is exact, no task outlives
its region, admission closes with completion, the kept error is a failure and
never a cancel, a failure reaches a joiner in the region it cancels, and a
region awaited outside a dropped run says `Cancelled`; the lab clock never
moves back, wakes timers only once due and in the order they were set, leaves
no entry behind after a move or a drop, and keeps jumping while a task loops on
`Cx::idle`; the host timer thread never fires early and never sleeps past a
live deadline.

Ablations, each run alone and each violating the property it names:

| Config | Turns off | Violated | Distinct states to the counterexample |
| --- | --- | --- | ---: |
| `Executor_without_resetqueued` | `queued` cleared before a poll | `WakesArePolled` | 862 |
| `Executor_without_morewake` | the self-wake when work was queued during a turn | `OuterIsWoken` | 38 |
| `Region_without_finishfirst` | `JoinState::finish` before `task_done` | `JoinerSeesFailure` | 703 |
| `Region_without_donewake` | the owner's wake at `live = 0` | `OwnerReturns` | 24,507 |
| `Region_without_cancelfirst` | `root.cancel` before the dropped tasks end | `DroppedRunIsCancelled` | 804 |
| `LabClock_without_idlewoken` | `Queue::idle_woken` | `SleepersWake` | 9,806 |
| `LabClock_without_freshid` | the new id `Clock::reset` takes | `WakesInOrderAndInTime` | 2,175 |
| `LabClock_without_max` | `advance` keeping `max(now, deadline)` | `Monotonic` | 4,026 |
| `Timers_without_stalecheck` | `take_due` skipping stale heap pairs | `NoEarlyFire` | 637 |
| `Timers_without_notify` | the `Condvar` notify for an earlier deadline | `SleepIsSafe` | 4 |

Three of the ablations are the bugs earlier rounds fixed in `16abcc1bb` and
`6a0cc67c3` (the idle point, the moved timer's id, the clock moving back); the
models find each of them again when its fix is turned off.

## Bugs

None confirmed. The code was read against the models for the bug classes the
last rounds found, with these outcomes:

- Wakers released under a lock. Every site that replaces, removes or wakes a
  waker does so after its guard is dropped: `CancelWait::clear`,
  `Region::cancel`, `update_foreign`, `task_done`, `poll_done`,
  `Task::join`, `JoinState::finish`, `RunShared::idle` and its `Wait`,
  `RunShared::spawn`, `schedule`, `wake_all`, `RunState::poll` (the outer
  waker, the idle wakers, the lab's due wakers), `Drop for RunState`,
  `Clock::reset`, `update`, `remove`, `HostWake::wake`, `Timers::reset`,
  `remove` and `thread`. The two inserts that happen under a lock
  (`Clock::register`, `Timers::add`) use fresh ids, so they never replace a
  waker. `Clock::arm` calls `Timers::reset` with the clock locked, which can
  drop the previous `HostWake` clone there; that type's drop is a reference
  count on a `Weak<Clock>` and runs no other code.
- Drops that leave work registered. `Timer`, `CancelWait`, the idle `Wait`,
  `Clock` (its host entry) and the region future's `CancelOnDrop` all
  unregister on drop; `LabClock`'s `EntriesOwned` checks the timer side.
- Lock order. The run's queue lock is taken before the clock's in the lab's
  time jump; the clock's is taken before the timer thread's in `arm`; the
  timer thread releases its own lock before waking a `HostWake`, which takes
  the clock's; the region's lock is never held across a call out. No cycle.

The 22 unit tests of these modules pass unchanged
(`cargo test -p fictionet --lib -- cx:: run:: clock:: timer:: block_on:: sync::`).

Two behaviours were noted and left alone, as they match the documentation and
are not failures:

- A task that loops `idle().await; yield_now().await` keeps a lab's clock
  from advancing, because the yield makes the run busy and the next idle wait
  counts as a new idle point. The documented rule is that a repeated idle wait
  with no work in between waits for the next idle point; a yield is work.
- A spawn from a retained `Cx` after the run's future has returned `Ready`
  but before that future is dropped is queued and reported `Cancelled` only
  when the future is dropped. Every executor drops a finished future at once.

## Kani

Kani 0.68.0 cannot compile the `fictionet` crate for a harness in it: its
`RustcIntrinsicsPass` panics in `kani-compiler/src/intrinsics.rs:243` while
collecting the items reachable from a `Region` harness (an internal compiler
error, not a property failure). A standalone crate that includes
`src/cx/region.rs` by path with shims for `RunShared` compiles under Kani, but
CBMC had not decided a four-call harness over `Region` after twenty minutes,
with the symbolic `std::sync::Mutex` and `BTreeMap` dominating the formula. No
Kani harness is part of this pass; the bounded proofs over the runtime are the
TLC runs above.

## What the models leave out

The real clock with an origin (its registrations are the lab's code; the host
driver it arms is the `Timers` spec); `Cx::race` and `Cx::yield_now`; the
foreign cancel wakers of `RegionState::foreign` and `Cx::register_cancel`
(their release order has unit tests in `src/cx/region.rs`); `Region::child`'s
list of children; the heap rebuild in `Timers`; `block_on`; the thread-local
current task that `is_current_task` reads; panics; memory; the `Waker`
contract. The bounds are two tasks per spec, deadlines 1 and 2 in the lab, one
stale wake per task, two harness deadlines, and instants 0 to 3 for the host
timers. The models say what the runtime does with a task's choices, not what
world code chooses.

## Rerunning

```sh
export TLA2TOOLS=/home/souvik/.cache/adorably-fv/tla2tools.jar
export JAVA=/home/souvik/.local/jdk21/bin/java
export TMPDIR="$CARGO_TARGET_DIR/runtime-verify/temp"
mkdir -p "$TMPDIR"
systemd-run --user --scope -p MemoryMax=12G -q cargo xtask runtime-verify tlc
```

TLC's output for each config is under `runtime-verify/tlc/` in Cargo's target
directory.
