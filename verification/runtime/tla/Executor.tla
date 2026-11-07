---------------------------- MODULE Executor ----------------------------
\* The run loop of src/run.rs: RunState::poll takes turns over the tasks
\* in Queue::ready, TaskWaker puts a woken task back, RunShared::spawn adds
\* tasks, Region::cancel asks for every task to be polled once
\* (RunShared::wake_all), and whatever polls the run is woken through
\* Queue::outer. Wakes come from other threads at any time, so each locked
\* section of the Rust is one step here and a task's poll is two.
EXTENDS Naturals, Sequences

CONSTANTS
    Tasks,        \* the tasks that may be spawned
    ResetQueued,  \* RunState::poll clears TaskWaker::queued before a poll
    WakeOnMore    \* RunState::poll wakes the outer when work is queued at the end of a turn

VARIABLES
    slot,       \* per task: "none", "incoming", "live" or "done"
    queued,     \* TaskWaker::queued per task
    ready,      \* Queue::ready
    turn,       \* RunState::turn: the tasks left to poll in this turn
    incoming,   \* Queue::incoming
    polling,    \* Queue::polling
    wakeAll,    \* Queue::wake_all
    outerWoken, \* the outer waker was woken and the run not polled since
    phase,      \* "idle" (between polls of the run), "turn", "inPoll" or "ended"
    current,    \* the task being polled, in phase "inPoll"
    waiting,    \* per task: a waker of it is held by something that will wake it
    pendingWake,  \* history per task: woken, and not polled since
    cancelSince   \* history per task: wake_all asked for, and not polled since

vars == <<slot, queued, ready, turn, incoming, polling, wakeAll, outerWoken,
          phase, current, waiting, pendingWake, cancelSince>>

Range(s) == {s[i] : i \in DOMAIN s}

Live == {t \in Tasks : slot[t] = "live"}

Init ==
    /\ slot = [t \in Tasks |-> "none"]
    /\ queued = [t \in Tasks |-> FALSE]
    /\ ready = <<>> /\ turn = <<>> /\ incoming = <<>>
    /\ polling = FALSE /\ wakeAll = FALSE
    /\ outerWoken = TRUE    \* the executor polls a new future once
    /\ phase = "idle" /\ current = 0
    /\ waiting = [t \in Tasks |-> FALSE]
    /\ pendingWake = [t \in Tasks |-> FALSE]
    /\ cancelSince = [t \in Tasks |-> FALSE]

\* Waking Queue::outer when the run is not polling.
WakeOuter == outerWoken' = (outerWoken \/ ~polling)

----------------------------------------------------------------------------
\* Cx::spawn, from any thread: RunShared::spawn.
Spawn(t) ==
    /\ slot[t] = "none" /\ phase # "ended"
    /\ slot' = [slot EXCEPT ![t] = "incoming"]
    /\ incoming' = Append(incoming, t)
    /\ WakeOuter
    /\ UNCHANGED <<queued, ready, turn, polling, wakeAll, phase, current, waiting,
                   pendingWake, cancelSince>>

\* TaskWaker::wake_by_ref, from any thread: a held waker fires, or a stale
\* one wakes the task for nothing.
Wake(t) ==
    /\ slot[t] \in {"live", "done"} /\ phase # "ended"
    /\ waiting' = [waiting EXCEPT ![t] = FALSE]
    /\ pendingWake' = [pendingWake EXCEPT ![t] = (slot[t] = "live")]
    /\ IF queued[t]
       THEN UNCHANGED <<queued, ready, outerWoken>>
       ELSE /\ queued' = [queued EXCEPT ![t] = TRUE]
            /\ ready' = Append(ready, t)
            /\ WakeOuter
    /\ UNCHANGED <<slot, turn, incoming, polling, wakeAll, phase, current, cancelSince>>

\* Region::cancel, from any thread: RunShared::wake_all.
WakeAllRequest ==
    /\ phase # "ended"
    /\ wakeAll' = TRUE
    /\ cancelSince' = [t \in Tasks |-> cancelSince[t] \/ slot[t] \in {"incoming", "live"}]
    /\ WakeOuter
    /\ UNCHANGED <<slot, queued, ready, turn, incoming, polling, phase, current, waiting,
                   pendingWake>>

----------------------------------------------------------------------------
\* RunState::poll.

\* The locked section at the start of a turn: new tasks get slots and a
\* place in the queue, a cancel queues every task that is not queued, and
\* the queue becomes this turn.
RECURSIVE QueueAll(_, _, _)
QueueAll(ts, q, r) ==
    IF ts = {} THEN <<q, r>>
    ELSE LET t == CHOOSE x \in ts : \A y \in ts : x <= y
         IN IF q[t] THEN QueueAll(ts \ {t}, q, r)
            ELSE QueueAll(ts \ {t}, [q EXCEPT ![t] = TRUE], Append(r, t))

BeginTurn ==
    /\ phase = "idle" /\ outerWoken
    /\ outerWoken' = FALSE
    /\ polling' = TRUE
    /\ slot' = [t \in Tasks |-> IF slot[t] = "incoming" THEN "live" ELSE slot[t]]
    /\ LET admitted == [t \in Tasks |-> queued[t] \/ slot[t] = "incoming"]
           readyIn == ready \o incoming
           all == IF wakeAll
                  THEN QueueAll({t \in Tasks : slot'[t] = "live"}, admitted, readyIn)
                  ELSE <<admitted, readyIn>>
       IN /\ queued' = all[1]
          /\ turn' = all[2]
    /\ ready' = <<>>
    /\ incoming' = <<>>
    /\ wakeAll' = FALSE
    /\ phase' = "turn"
    /\ UNCHANGED <<current, waiting, pendingWake, cancelSince>>

\* The next task of the turn. A task whose slot is gone is skipped.
NextTask ==
    /\ phase = "turn" /\ turn # <<>>
    /\ LET t == Head(turn)
       IN /\ turn' = Tail(turn)
          /\ IF slot[t] = "live"
             THEN /\ phase' = "inPoll"
                  /\ current' = t
                  /\ queued' = IF ResetQueued THEN [queued EXCEPT ![t] = FALSE] ELSE queued
                  /\ pendingWake' = [pendingWake EXCEPT ![t] = FALSE]
                  /\ cancelSince' = [cancelSince EXCEPT ![t] = FALSE]
             ELSE UNCHANGED <<phase, current, queued, pendingWake, cancelSince>>
    /\ UNCHANGED <<slot, ready, incoming, polling, wakeAll, outerWoken, waiting>>

\* The poll returns Pending. The task has handed its waker to something,
\* or waits for a cancel alone, which needs no waker (Cx::register_cancel
\* for the current task).
PollPending(w) ==
    /\ phase = "inPoll"
    /\ phase' = "turn"
    /\ waiting' = [waiting EXCEPT ![current] = w]
    /\ current' = 0
    /\ UNCHANGED <<slot, queued, ready, turn, incoming, polling, wakeAll, outerWoken,
                   pendingWake, cancelSince>>

\* The poll returns Ready: the slot goes.
PollReady ==
    /\ phase = "inPoll"
    /\ phase' = "turn"
    /\ slot' = [slot EXCEPT ![current] = "done"]
    /\ waiting' = [waiting EXCEPT ![current] = FALSE]
    /\ pendingWake' = [pendingWake EXCEPT ![current] = FALSE]
    /\ cancelSince' = [cancelSince EXCEPT ![current] = FALSE]
    /\ current' = 0
    /\ UNCHANGED <<queued, ready, turn, incoming, polling, wakeAll, outerWoken>>

\* The locked section at the end of a turn. With no slots and nothing
\* incoming the run ends. Otherwise, work that arrived during the turn
\* makes the run wake itself.
EndTurn ==
    /\ phase = "turn" /\ turn = <<>>
    /\ polling' = FALSE
    /\ IF Live = {} /\ incoming = <<>>
       THEN /\ phase' = "ended"
            /\ UNCHANGED outerWoken
       ELSE /\ phase' = "idle"
            /\ LET more == ready # <<>> \/ incoming # <<>> \/ wakeAll
               IN outerWoken' = (outerWoken \/ (more /\ WakeOnMore))
    /\ UNCHANGED <<slot, queued, ready, turn, incoming, wakeAll, current, waiting,
                   pendingWake, cancelSince>>

----------------------------------------------------------------------------

Next ==
    \/ \E t \in Tasks : Spawn(t) \/ Wake(t)
    \/ WakeAllRequest
    \/ BeginTurn \/ NextTask \/ \E w \in BOOLEAN : PollPending(w) \/ PollReady \/ EndTurn

\* The executor polls the run whenever it is woken, and a poll finishes.
Fairness ==
    /\ WF_vars(BeginTurn)
    /\ WF_vars(NextTask)
    /\ WF_vars(PollPending(TRUE) \/ PollPending(FALSE) \/ PollReady)
    /\ WF_vars(EndTurn)

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------
\* Properties.

\* Queued work between polls of the run always comes with a wake of
\* whatever polls it.
OuterIsWoken ==
    (phase = "idle" /\ (ready # <<>> \/ incoming # <<>> \/ wakeAll)) => outerWoken

\* TaskWaker::queued says whether a live task is in the ready queue or the
\* turn: a woken task is always queued, and never twice.
QueuedMeansQueued ==
    \A t \in Live :
        /\ queued[t] <=> (t \in Range(ready) \/ t \in Range(turn))
        /\ Len(SelectSeq(ready, LAMBDA x : x = t)) + Len(SelectSeq(turn, LAMBDA x : x = t)) <= 1

\* A live task that was woken is polled again: no wake is lost, not even
\* one that arrives while the task is being polled.
WakesArePolled ==
    \A t \in Tasks : [](pendingWake[t] => <>(~pendingWake[t]))

\* After a cancel every task of the run is polled once more, so every wait
\* on a Cx sees it without a waker of its own.
CancelsAreSeen ==
    \A t \in Tasks : [](cancelSince[t] => <>(~cancelSince[t]))

=============================================================================
