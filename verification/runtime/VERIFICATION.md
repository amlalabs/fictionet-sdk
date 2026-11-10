# Runtime verification

This pass models the runtime of the SDK at `8ccf47fae`: task spawning and
cancellation, wakers and their release order relative to locks, timers and the
clock, regions and joins, and `block_on`. The models are TLA+ specifications in
[verification/runtime/tla](tla), checked with TLC. [verification/runtime/README.md](README.md)
has the table of specs, their correspondence to the Rust, the bounds, and the
ablations.

In the original pass, no bug was confirmed and no production code changed.
Every passing configuration completed with an empty queue and no violation,
and every ablation violated exactly the property its config names. The later
descendant-ownership change and its new evidence are recorded next.

## Descendant task ownership

The original pass below modeled one region's own task count. The layer job
runner also creates nested regions directly, so returning or dropping an
opened stack exposed a missing obligation: the enclosing region must join
those descendant tasks, even when their intermediate context was dropped.

At `b0fb45ee2`, `Region::try_start_task` reserves every ancestor from root to leaf,
refusing a completed or expired ancestor. A rejected local admission rolls
all successful reservations back. `task_done` releases leaf-to-root and
wakes each region whose subtree count reaches zero. Failure remains local:
ancestor releases pass no error or cancellation. The structural parent is
weak; an active region retains its parent only while tasks are counted, so
dropping an intermediate context cannot lose accounting, and retaining an
idle context cannot keep a region waiting.

`RegionTree.tla` models two admissions into a fixed four-region tree, with
one step per ancestor reservation/release and independent completion
checks between them. It checks exact count conservation, closed admission,
no task outliving any joined ancestor, no leaked rejected reservations and
failure isolation. Its progress property assumes weak fairness of each
task's transitions, including that running tasks eventually finish; it
proves neither termination of arbitrary user futures nor cancellation of
code that ignores cancellation. Retention of the intermediate parent Arc
is tested in production Rust, not represented as a heap in the model.

| Config | Generated | Distinct | Result |
| --- | ---: | ---: | --- |
| `RegionTree_base` | 70,485 | 23,984 | all five invariants and `Settles` hold, depth 23 |
| `RegionTree_without_ancestorcounts` | 2,489 | 1,278 | `NoTaskOutlives` violated |
| `RegionTree_without_ancestoradmission` | 233 | 190 | `ClosedCounts` violated |
| `RegionTree_without_rollback` | 820 | 497 | `NoLeakedReservations` violated |
| `RegionTree_without_errorisolation` | 2,181 | 1,089 | `ErrorIsolation` violated |

The existing `Region.tla` was rerun unchanged as the single-region case:
124,050 generated states, 30,395 distinct, depth 17, all properties pass.
Its mutations still violate their named properties: missing completion
wake has 24,507 distinct states; finishing after the count decrement has
1,006; cancelling the run after decrementing its tasks has 1,122.

The production tests cover descendant completion, intermediate-context
release, rejected admission rollback, task failure isolation, a completed
job whose producer must remain live, and dropping an `Opened` while its
spawned task is active. Task-start acknowledgements establish the setup
ordering without sleeps or timing assumptions.

A direct Kani attempt over `Region` methods could not reach verification:
Kani 0.68.0 internally panicked at `kani-compiler/src/intrinsics.rs:243`,
`assertion failed: matches!(output.kind(), TyKind::RigidTy(RigidTy::Int(IntTy::I32)))`,
while compiling the real mutex/futex path. No lock stub or altered runtime
semantics was substituted. The newly attempted harness was removed because
it prevents Kani compilation; there was no preexisting runtime Kani harness
to disable. This property has TLC and executable-test evidence, not a
successful Kani proof.

All region TLC reruns used `~/.cache/adorably-fv/jdk/bin/java -Xmx6g`,
`tlc2.TLC -workers 4`, an 8 GiB systemd scope with no swap, and state
directories under `~/.cache/adorably-fv/states` on the home volume.

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
  `remove` and `thread`, and since `04ff2b09d` `ContextLease::poll_unborrowed`
  and `Drop for ContextLease` (the waiter is taken under the lease's lock and
  woken or dropped after it). The two inserts that happen under a lock
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
list of children; the heap rebuild in `Timers`; `block_on`; the run's note
of the task it polls, which `RunShared::is_polling` reads; panics; memory; the `Waker`
contract. The bounds are two tasks per spec, deadlines 1 and 2 in the lab, one
stale wake per task, two harness deadlines, and instants 0 to 3 for the host
timers. The models say what the runtime does with a task's choices, not what
world code chooses.

Two abstractions read against the code at `e2858ccc4`, neither of which a
property of its model can see: `Region.tla`'s `Spawn` refuses a task only
when the child region has completed, while `Region::try_start_task` since
`b0fb45ee2` also refuses when an ancestor has completed or its `Arc` has
gone, which `RegionTree.tla` checks (`CheckAncestors`); and `LabClock.tla`'s
`EndTurn` wakes the idle waits in task-number order (`Ordered` over the task
ids), while `RunState::poll` wakes `Queue::idle` in the order the waits
registered (its `next_idle` keys). The model's `Spawn` after the owner was
dropped also admits a task the code may refuse once the parent region has
completed. The counts in the tables above are from the runs recorded when
each section was written; the audit reran only the two `JobContext` configs.

## Rerunning

```sh
export JAVA=/home/souvik/.local/jdk21/bin/java
export TLA2TOOLS=/home/souvik/.cache/adorably-fv/tla2tools.jar
cd verification/runtime/tla
for cfg in *.cfg; do
  "$JAVA" -XX:+UseParallelGC -cp "$TLA2TOOLS" tlc2.TLC -workers 4 \
    -metadir "$CARGO_TARGET_DIR/runtime-tlc/${cfg%.cfg}" \
    -config "$cfg" "${cfg%%_*}.tla"
done
```

Each ablation's config names the property it must violate.

## Deferred work from returned contexts

The job runner now waits for borrowed contexts before joining a successfully
completed job region. `ContextLease` counts those references independently of
tasks, propagates through cloned and nested contexts, and wakes the runner
when the last borrow ends. Cancellation still drains tasks without waiting
for retained contexts. Completed jobs must release private context clones
and transfer contexts needed later into their result. Lease metadata is
fixed context-owned storage, like region metadata: active jobs are bounded
by the job limit and retained contexts keep their metadata after cancellation.

`JobContext_base.cfg` passes both invariants: 98 generated states, 31 distinct,
depth 6. `JobContext_without_borrow.cfg` violates `BorrowKeepsAdmission` with
a borrow, a returned result, and premature retirement (24 distinct states to
the counterexample). Both ran with the cached JDK, a 2 GiB heap, two workers,
a 10 GiB systemd limit and state storage on the home volume. This model
projects lifecycle transitions, not the implementation of atomic references,
mutexes or waker registration. RegionTree continues to cover descendant task
accounting separately.

The audit at `e2858ccc4` took the guard `~cancelled` off `Borrow` and
`Start`: `Cx::clone` and `Cx::spawn` check neither the region's `cancelled`
nor the lease, and `Region::try_start_task` refuses only a completed region,
so a retained context can be cloned and can start a task after a cancel until
`poll_done` closes the region. The model had forbidden both. With them
allowed the base config still passes with the same 31 distinct states (98
generated, up from 86) and the ablation still violates `BorrowKeepsAdmission`.

When the serving engine was deleted, `Jobs::poll` gained a rule: work whose
own region was cancelled, as when a task it spawned failed, is never polled
again, as work whose owner ended is not, and its region is made before that
check. That is the model's `Cancel` followed by `Reap`, which the code had
not done for a cancel from inside the job. Both configurations were rerun on
the new code and gave the results above.

The real HTTP regressions return a body that captures its handler context
and starts its first clock wait only when a frame is polled. The one-frame
response succeeds, as does a 130-frame response exceeding the 64 job slots.
Focused tests check last-borrow wakeup and parent retention by a nested lease.
The existing Kani compiler limitation above also prevents a direct proof
over the mutex-backed context lease; no Kani success is claimed for it.

On the completed implementation, all 19 context and region unit tests pass;
the combined stack and TLS unit selection passes all 24 tests.
