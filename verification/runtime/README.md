# Runtime verification

TLA+ models of the runtime's state machines, checked with TLC through
`cargo xtask runtime-verify`, the way `mptcp-verify` checks the MPTCP models.
The models are finite cuts through `src/run.rs`, `src/cx.rs`, `src/cx/region.rs`,
`src/cx/task.rs`, `src/cx/timer.rs`, `src/clock.rs` and `src/timer.rs`. Each
locked section of the Rust is one step of a model, and anything another thread
can do between two locked sections is a separate step, so the interleavings the
Rust allows are the ones TLC explores.

```sh
export TLA2TOOLS=/home/souvik/.cache/adorably-fv/tla2tools.jar
export JAVA=/home/souvik/.local/jdk21/bin/java
export TMPDIR="$CARGO_TARGET_DIR/runtime-verify/temp"
mkdir -p "$TMPDIR"
systemd-run --user --scope -p MemoryMax=12G -q cargo xtask runtime-verify tlc
```

`runtime-verify tlc [spec] [config]` checks every config, those of one spec, or
one config. A passing config runs once with all of its properties; a config
with an `\* expect violation:` line is an ablation that turns one line of the
Rust off and must violate exactly the property it names. Output goes under
`runtime-verify/tlc/` in Cargo's target directory.

| Spec | Cut and Rust correspondence | Properties |
|---|---|---|
| Executor | `RunState::poll` in `src/run.rs` as three steps: the locked start of a turn (new tasks get slots, `wake_all` queues every task, `ready` becomes the turn), one task's poll, and the locked end (`polling` off, `more`, the self-wake). `TaskWaker::wake_by_ref` with its `queued` flag, `RunShared::spawn`, `RunShared::wake_all`, and the outer waker in `Queue::outer`. Wakes and spawns come from any thread at any time, also during a task's poll. | Queued work between polls of the run always comes with a wake of the outer; a live task is in the queue exactly when `queued` is set, and never twice; every wake of a live task is followed by a poll of it, including a wake during its own poll; after a cancel every task is polled once more |
| Region | `Cx::region` as the owner (`f`'s future, then `Region::poll_done`, `take_error`, `cut_short`), `Cx::spawn` with `try_start_task`, the four steps of `RunState::poll` when a task ends (`record_error`, drop, `JoinState::finish`, `task_done`), `Task::join` from a `Cx` of the region, `Cx::cancel` on the region or its parent, `Region::cancel` cascading from the parent, `CancelOnDrop`, and `Drop for RunState` as two steps (`root.cancel`, then every dropped task counted as ended) | `live` counts the tasks that started and have not ended; a returned owner has no live task; a completed region has no live work; the region's error is a failure, never a cancel; a failure reaches a joiner in the region it cancels; a region awaited outside a dropped run returns `Cancelled`, not `Ok`; the owner's result follows from the region's state; the owner returns once the last task ends |
| LabClock | `Clock::add`, `reset`, `update`, `remove`, `advance` and `take_due` in lab mode, `Timer::poll_until` and `clear` for a task's sleep and for an owned timer that moves its deadline, `Cx::idle` through `RunShared::idle` and `Queue::idle_woken`, the end of a turn (`more`, the idle wake, the time jump, the lab deadlock), and a harness thread that reads the clock and registers a deadline later | The clock never moves back; every jump wakes only timers whose deadline has passed, in the order they were set, a moved timer counting from its move; every clock entry belongs to a timer that holds its id and deadline; a sleeping task that is not queued has an entry; every sleeping task is woken, also while another task loops on `Cx::idle` |
| Timers | `Timers::add`, `reset` and `remove` in `src/timer.rs`, `State::take_due` with the stale heap pairs a move or a removal leaves, and `Timers::thread` sleeping on the `Condvar` until the heap's earliest deadline. The lock is held while the thread runs and free while it sleeps or wakes timers. | No timer fires before its deadline; the thread never sleeps past a live deadline without a notify pending; every due timer fires, moves or is removed |

Bounds: Executor and LabClock have two tasks; Region has two tasks and a joiner
on one of them; LabClock names deadlines 1 and 2, allows one stale wake per
task and two deadlines from the harness thread; Timers has two timers and
instants 0 to 3. No state constraint prunes exploration. Each ablation keeps
the bounds of its passing config.

| Ablation | Turns off | Violates |
|---|---|---|
| `Executor_without_resetqueued` | `queued` cleared before a task's poll | `WakesArePolled`: a wake during the poll is dropped |
| `Executor_without_morewake` | the self-wake when work was queued during a turn | `OuterIsWoken` |
| `Region_without_finishfirst` | `JoinState::finish` before `task_done` | `JoinerSeesFailure`: a joiner in the failing region hears `Cancelled` |
| `Region_without_donewake` | `task_done` waking the owner at `live = 0` | `OwnerReturns` |
| `Region_without_cancelfirst` | `root.cancel` before the dropped tasks are counted as ended | `DroppedRunIsCancelled`: the owner outside the run returns `Ok` |
| `LabClock_without_idlewoken` | `Queue::idle_woken` | `SleepersWake`: a task looping on idle stops the clock |
| `LabClock_without_freshid` | the new id `Clock::reset` takes | `WakesInOrderAndInTime`: a moved timer wakes before one set earlier |
| `LabClock_without_max` | `advance` keeping the clock at `max(now, deadline)` | `Monotonic`: the clock moves back for a stale deadline |
| `Timers_without_stalecheck` | `take_due` skipping a pair whose deadline is not its timer's | `NoEarlyFire` |
| `Timers_without_notify` | the `Condvar` notify for an earlier deadline | `SleepIsSafe` |

What the models leave out: the real clock (`Clock` with an origin; Timers covers
the host driver it uses, the Clock side is the same code as the lab's apart
from `arm`), `Cx::race` and `Cx::yield_now` (plain compositions of the modeled
waits), foreign cancel wakers in `RegionState::foreign` (`register_cancel`,
`update_foreign`, `CancelWait`; the Rust tests in `src/cx/region.rs` check
their release order), `Region::child`'s list of children, the heap rebuild in
`Timers`, `block_on`, and the thread-local current task that `is_current_task`
reads. Panics, memory and the `Waker` contract are assumed. Tasks in the
models end, sleep, idle or wait as they choose; the models do not say what
world code does, only what the runtime does with it.
