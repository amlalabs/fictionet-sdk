----------------------------- MODULE Region -----------------------------
\* A region made by Cx::region (src/cx.rs), the tasks Cx::spawn starts in
\* it (src/cx/region.rs), the run loop's steps when a task ends
\* (RunState::poll in src/run.rs), a joiner (Task::join in src/cx/task.rs)
\* and the run being dropped (Drop for RunState in src/run.rs).
\*
\* The owner is the future Cx::region returns. Its work is `f`'s future,
\* polled inside the owner. The owner may be inside the run or outside it,
\* so it can be dropped on its own and it can outlive a dropped run.
EXTENDS Naturals, FiniteSets

CONSTANTS
    Tasks,             \* the tasks that may be spawned into the child
    Joined,            \* the task a joiner in the child region waits for
    FinishBeforeDone,  \* run loop: join.finish before region.task_done
    DoneWakes,         \* Region::task_done wakes the owner at live = 0
    CancelBeforeEnd    \* Drop for RunState: root.cancel before task_done

ASSUME Joined \in Tasks

Regions == {"parent", "child"}

VARIABLES
    cancelled,    \* Region::cancelled, per region
    stopped,      \* Region::stopped, per region
    live,         \* RegionState::live of the child
    completed,    \* RegionState::completed of the child
    error,        \* RegionState::error of the child: "none", a task or "work"
    cancelEnded,  \* RegionState::cancel_ended of the child
    doneWaiter,   \* RegionState::done holds the owner's waker
    ownerWoken,   \* that waker was woken and the owner not polled since
    owner,        \* "work", "waitDone", "returned" or "dropped"
    result,       \* what Cx::region returned: "none", "ok", "cancelled" or an error
    task,         \* per task: "unspawned", "refused", "running", "failing1", "failing2", "ended"
    outcome,      \* per task: "none", "ok", "err", "cancel" or "dropped"
    join,         \* JoinState::result per task: "none", "ok", "failed" or "cancelled"
    joiner,       \* Task::join's result for Joined: "none", "ok", "failed" or "cancelled"
    runDropped,   \* "no", "cancelling" (one of the two drop steps done) or "yes"
    otherCancel,      \* history: the child was cancelled by something other than Joined's failure
    droppedWithWork   \* history: the run was dropped while the child had running tasks

vars == <<cancelled, stopped, live, completed, error, cancelEnded, doneWaiter,
          ownerWoken, owner, result, task, outcome, join, joiner, runDropped,
          otherCancel, droppedWithWork>>

Counted(t) == task[t] \in {"running", "failing1"} \/ (task[t] = "failing2" /\ FinishBeforeDone)

Running == {t \in Tasks : task[t] \in {"running", "failing1", "failing2"}}

Init ==
    /\ cancelled \in [Regions -> BOOLEAN]
    /\ cancelled["child"] = cancelled["parent"]   \* Region::child cancels a child of a cancelled parent
    /\ stopped = [r \in Regions |-> FALSE]
    /\ live = 0 /\ completed = FALSE /\ error = "none" /\ cancelEnded = FALSE
    /\ doneWaiter = FALSE /\ ownerWoken = FALSE
    /\ owner = "work" /\ result = "none"
    /\ task = [t \in Tasks |-> "unspawned"]
    /\ outcome = [t \in Tasks |-> "none"]
    /\ join = [t \in Tasks |-> "none"]
    /\ joiner = "none"
    /\ runDropped = "no"
    /\ otherCancel = cancelled["child"]
    /\ droppedWithWork = FALSE

\* Region::cancel on the child, and the cascade from the parent. Every
\* cancel but the one Joined's own failure causes is noted.
CancelChild == cancelled' = [cancelled EXCEPT !["child"] = TRUE]
CancelBoth == cancelled' = [r \in Regions |-> TRUE]
OtherCancel == otherCancel' = TRUE

\* Region::record_error: the first error, unless Cx::cancel stopped the region.
Record(who) == IF error = "none" /\ ~stopped["child"] THEN who ELSE error

\* Region::task_done at live = 0 wakes the owner's waker, if it is there.
Wake(newLive) == ownerWoken' = (ownerWoken \/ (newLive = 0 /\ doneWaiter /\ DoneWakes))

----------------------------------------------------------------------------
\* Cancelling from outside the child.

\* The parent fails or is cancelled from outside: Region::cancel cascades.
CancelParent ==
    /\ ~cancelled["parent"]
    /\ CancelBoth /\ OtherCancel
    /\ UNCHANGED <<stopped, live, completed, error, cancelEnded, doneWaiter, ownerWoken,
                   owner, result, task, outcome, join, joiner, runDropped, droppedWithWork>>

\* Cx::cancel on a Cx of the parent: stops the parent, cancels the child.
StopParent ==
    /\ ~stopped["parent"]
    /\ stopped' = [stopped EXCEPT !["parent"] = TRUE]
    /\ CancelBoth /\ OtherCancel
    /\ UNCHANGED <<live, completed, error, cancelEnded, doneWaiter, ownerWoken,
                   owner, result, task, outcome, join, joiner, runDropped, droppedWithWork>>

\* Cx::cancel on a Cx of the child.
StopChild ==
    /\ ~stopped["child"]
    /\ stopped' = [stopped EXCEPT !["child"] = TRUE]
    /\ CancelChild /\ OtherCancel
    /\ UNCHANGED <<live, completed, error, cancelEnded, doneWaiter, ownerWoken,
                   owner, result, task, outcome, join, joiner, runDropped, droppedWithWork>>

----------------------------------------------------------------------------
\* Cx::spawn into the child, from any Cx of it, at any time.

Spawn(t) ==
    /\ task[t] = "unspawned"
    /\ IF completed THEN
           \* Region::try_start_task refuses; the join reports Cancelled.
           /\ task' = [task EXCEPT ![t] = "refused"]
           /\ join' = [join EXCEPT ![t] = "cancelled"]
           /\ UNCHANGED <<live, ownerWoken>>
       ELSE IF runDropped # "no" THEN
           \* RunShared::spawn gives the future back: task_done at once.
           /\ task' = [task EXCEPT ![t] = "refused"]
           /\ join' = [join EXCEPT ![t] = "cancelled"]
           /\ live' = live
           /\ Wake(live)
       ELSE
           /\ task' = [task EXCEPT ![t] = "running"]
           /\ live' = live + 1
           /\ UNCHANGED <<join, ownerWoken>>
    /\ UNCHANGED <<cancelled, stopped, completed, error, cancelEnded, doneWaiter,
                   owner, result, outcome, joiner, runDropped, otherCancel, droppedWithWork>>

----------------------------------------------------------------------------
\* A task ends. The run loop runs these steps in RunState::poll.

\* Ok: finish the join, then task_done. Nothing observable depends on the order.
EndOk(t) ==
    /\ task[t] = "running" /\ runDropped = "no"
    /\ task' = [task EXCEPT ![t] = "ended"]
    /\ outcome' = [outcome EXCEPT ![t] = "ok"]
    /\ join' = [join EXCEPT ![t] = "ok"]
    /\ live' = live - 1
    /\ Wake(live - 1)
    /\ UNCHANGED <<cancelled, stopped, completed, error, cancelEnded, doneWaiter,
                   owner, result, joiner, runDropped, otherCancel, droppedWithWork>>

\* A cancel: Region::ended_by_cancel, the join reports Cancelled, task_done(false).
\* The task may have waited on another region's Cx, so this needs no cancel here.
EndCancel(t) ==
    /\ task[t] = "running" /\ runDropped = "no"
    /\ task' = [task EXCEPT ![t] = "ended"]
    /\ outcome' = [outcome EXCEPT ![t] = "cancel"]
    /\ cancelEnded' = TRUE
    /\ join' = [join EXCEPT ![t] = "cancelled"]
    /\ live' = live - 1
    /\ Wake(live - 1)
    /\ UNCHANGED <<cancelled, stopped, completed, error, doneWaiter,
                   owner, result, joiner, runDropped, otherCancel, droppedWithWork>>

\* An error, step 1: Region::record_error, then the future is dropped.
FailBegin(t) ==
    /\ task[t] = "running" /\ runDropped = "no"
    /\ task' = [task EXCEPT ![t] = "failing1"]
    /\ outcome' = [outcome EXCEPT ![t] = "err"]
    /\ error' = Record(t)
    /\ UNCHANGED <<cancelled, stopped, live, completed, cancelEnded, doneWaiter, ownerWoken,
                   owner, result, join, joiner, runDropped, otherCancel, droppedWithWork>>

\* Steps 2 and 3: join.finish and region.task_done(true), in the configured order.
Finish(t) == join' = [join EXCEPT ![t] = "failed"]
Done(t) == /\ live' = live - 1
           /\ CancelChild
           /\ otherCancel' = (otherCancel \/ t # Joined)
           /\ Wake(live - 1)

FailMid(t) ==
    /\ task[t] = "failing1"
    /\ task' = [task EXCEPT ![t] = "failing2"]
    /\ IF FinishBeforeDone
       THEN Finish(t) /\ UNCHANGED <<live, cancelled, otherCancel, ownerWoken>>
       ELSE Done(t) /\ UNCHANGED join
    /\ UNCHANGED <<stopped, completed, error, cancelEnded, doneWaiter,
                   owner, result, outcome, joiner, runDropped, droppedWithWork>>

FailEnd(t) ==
    /\ task[t] = "failing2"
    /\ task' = [task EXCEPT ![t] = "ended"]
    /\ IF FinishBeforeDone
       THEN Done(t) /\ UNCHANGED join
       ELSE Finish(t) /\ UNCHANGED <<live, cancelled, otherCancel, ownerWoken>>
    /\ UNCHANGED <<stopped, completed, error, cancelEnded, doneWaiter,
                   owner, result, outcome, joiner, runDropped, droppedWithWork>>

----------------------------------------------------------------------------
\* Task::join on Joined, from a Cx of the child. Polled when there is
\* something to see: a stored result wins over the cancel.
JoinerPoll ==
    /\ joiner = "none"
    /\ join[Joined] # "none" \/ cancelled["child"]
    /\ joiner' = IF join[Joined] # "none" THEN join[Joined] ELSE "cancelled"
    /\ UNCHANGED <<cancelled, stopped, live, completed, error, cancelEnded, doneWaiter,
                   ownerWoken, owner, result, task, outcome, join, runDropped,
                   otherCancel, droppedWithWork>>

----------------------------------------------------------------------------
\* The owner: Cx::region.

\* `f`'s future returns. An error is kept with Region::fail; a cancel is noted.
WorkEnd(o) ==
    /\ owner = "work"
    /\ owner' = "waitDone"
    /\ CASE o = "ok" -> UNCHANGED <<error, cancelled, cancelEnded, otherCancel>>
         [] o = "err" -> /\ error' = Record("work")
                         /\ CancelChild /\ OtherCancel
                         /\ UNCHANGED cancelEnded
         [] o = "cancel" -> /\ cancelEnded' = TRUE
                            /\ UNCHANGED <<error, cancelled, otherCancel>>
    /\ UNCHANGED <<stopped, live, completed, doneWaiter, ownerWoken, result, task,
                   outcome, join, joiner, runDropped, droppedWithWork>>

\* Region::poll_done, then take_error and cut_short. Polled first without a
\* waker, and after that only when woken.
Expected ==
    IF error # "none" THEN error
    ELSE IF cancelled["child"] /\ ~stopped["child"] /\ cancelEnded THEN "cancelled"
    ELSE "ok"

PollDone ==
    /\ owner = "waitDone"
    /\ ~doneWaiter \/ ownerWoken
    /\ ownerWoken' = FALSE
    /\ IF live = 0
       THEN /\ completed' = TRUE
            /\ owner' = "returned"
            /\ result' = Expected
            /\ UNCHANGED doneWaiter
       ELSE /\ doneWaiter' = TRUE
            /\ UNCHANGED <<completed, owner, result>>
    /\ UNCHANGED <<cancelled, stopped, live, error, cancelEnded, task, outcome, join,
                   joiner, runDropped, otherCancel, droppedWithWork>>

\* The owner's future is dropped before it ends: CancelOnDrop cancels the child.
DropOwner ==
    /\ owner \in {"work", "waitDone"}
    /\ owner' = "dropped"
    /\ CancelChild /\ OtherCancel
    /\ UNCHANGED <<stopped, live, completed, error, cancelEnded, doneWaiter, ownerWoken,
                   result, task, outcome, join, joiner, runDropped, droppedWithWork>>

----------------------------------------------------------------------------
\* Drop for RunState: the run's tasks are dropped between polls. Two steps:
\* every region is cancelled, and every dropped task is counted as ended by
\* the cancel, in the configured order.

DropCancel ==
    /\ CancelBoth /\ OtherCancel
    /\ UNCHANGED <<stopped, live, completed, error, cancelEnded, doneWaiter, ownerWoken,
                   owner, result, task, outcome, join, joiner>>

DropEnd ==
    /\ task' = [t \in Tasks |-> IF task[t] = "running" THEN "ended" ELSE task[t]]
    /\ outcome' = [t \in Tasks |-> IF task[t] = "running" THEN "dropped" ELSE outcome[t]]
    /\ join' = [t \in Tasks |-> IF task[t] = "running" THEN "cancelled" ELSE join[t]]
    /\ cancelEnded' = (cancelEnded \/ Running # {})
    /\ live' = live - Cardinality(Running)
    /\ Wake(live - Cardinality(Running))
    /\ UNCHANGED <<cancelled, stopped, completed, error, doneWaiter,
                   owner, result, joiner, otherCancel>>

DropRunFirst ==
    /\ runDropped = "no"
    /\ \A t \in Tasks : task[t] \notin {"failing1", "failing2"}
    /\ runDropped' = "cancelling"
    /\ droppedWithWork' = (droppedWithWork \/ (Running # {} /\ owner \in {"work", "waitDone"}))
    /\ IF CancelBeforeEnd THEN DropCancel ELSE DropEnd

DropRunSecond ==
    /\ runDropped = "cancelling"
    /\ runDropped' = "yes"
    /\ UNCHANGED droppedWithWork
    /\ IF CancelBeforeEnd THEN DropEnd ELSE DropCancel

----------------------------------------------------------------------------

Next ==
    \/ CancelParent \/ StopParent \/ StopChild
    \/ \E t \in Tasks : Spawn(t) \/ EndOk(t) \/ EndCancel(t) \/ FailBegin(t) \/ FailMid(t) \/ FailEnd(t)
    \/ JoinerPoll
    \/ \E o \in {"ok", "err", "cancel"} : WorkEnd(o)
    \/ PollDone \/ DropOwner
    \/ DropRunFirst \/ DropRunSecond

\* The run loop finishes the steps of an ending task and of a drop, and
\* the owner is polled when it is woken.
Fairness ==
    /\ \A t \in Tasks : WF_vars(FailMid(t)) /\ WF_vars(FailEnd(t))
    /\ WF_vars(PollDone)
    /\ WF_vars(DropRunSecond)

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------
\* Properties.

\* RegionState::live counts the tasks that started and have not been
\* counted as ended.
LiveCounts == live = Cardinality({t \in Tasks : Counted(t)})

\* No task outlives its region: once the owner has returned, every task of
\* the region has ended.
NoTaskOutlives == owner = "returned" => live = 0 /\ Running = {}

\* Admission closes with completion: a completed region has no live work.
AdmissionClosed == completed => live = 0

\* A region's error is the first failure, never a cancel.
ErrorIsAFailure ==
    error \in Tasks => outcome[error] = "err"

\* A failure that cancels the region reaches a joiner in that region, when
\* nothing else cancelled the region.
JoinerSeesFailure ==
    (outcome[Joined] = "err" /\ ~otherCancel /\ joiner # "none") => joiner = "failed"

\* A region awaited outside a dropped run says it was cut short, not that
\* it finished.
DroppedRunIsCancelled ==
    (droppedWithWork /\ owner = "returned" /\ error = "none" /\ ~stopped["child"])
        => result = "cancelled"

\* What Cx::region returns follows from the region's state at that moment.
ReturnMatches ==
    [][(owner # "returned" /\ owner' = "returned") => result' = Expected]_vars

\* The owner returns once every task has ended, unless more work is
\* spawned first: the done wake is not lost.
OwnerReturns ==
    [](owner = "waitDone" /\ live = 0 => <>(owner \in {"returned", "dropped"} \/ live > 0))

=============================================================================
