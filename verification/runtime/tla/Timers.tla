----------------------------- MODULE Timers -----------------------------
\* The host wake driver of a real run, src/timer.rs: each real Clock owns
\* one Driver. Driver::set gives it the clock's earliest deadline, or none,
\* and notifies its thread when that deadline is earlier than the one it
\* held; the thread (native::Shared::run) sleeps on a
\* Condvar until that deadline, forgets it and wakes the clock; dropping
\* the clock closes the driver and the thread ends. The thread starts with
\* the first deadline. Clock::arm calls set only when the earliest deadline
\* changes, and again after a wake, since the driver forgot it.
EXTENDS Naturals

CONSTANTS
    MaxTime,     \* the last instant; deadlines are 1..MaxTime
    Notify,      \* Driver::set notifies the thread (the code)
    CloseNotify  \* dropping the driver notifies the thread (the code)

Deadlines == 1..MaxTime

VARIABLES
    now,       \* the host clock
    deadline,  \* State::deadline, 0 for none
    thread,    \* "unstarted", "running" (holding the lock), "waking" (lock
               \* released, waking the clock), "sleeping" or "ended"
    planned,   \* the deadline the sleeping thread waits for, 0 for none
    notified,  \* Condvar::notify_one not yet consumed by a wait
    closed     \* State::closed: the clock is gone

vars == <<now, deadline, thread, planned, notified, closed>>

Init ==
    /\ now = 0
    /\ deadline = 0
    /\ thread = "unstarted"
    /\ planned = 0
    /\ notified = FALSE
    /\ closed = FALSE

\* The lock is free while the thread sleeps or wakes the clock.
Unlocked == thread # "running"

\* Driver::set, from the clock. The first deadline starts the thread. Only
\* an earlier deadline, or one where none was, notifies the thread.
Earlier(d) == d # 0 /\ (deadline = 0 \/ d < deadline)

Set(d) ==
    /\ Unlocked /\ ~closed
    /\ deadline' = d
    /\ thread' = IF thread = "unstarted" /\ d # 0 THEN "running" ELSE thread
    /\ notified' = (notified \/ (Notify /\ Earlier(d)))
    /\ UNCHANGED <<now, planned, closed>>

\* The clock is dropped, and its driver with it.
Close ==
    /\ Unlocked /\ ~closed
    /\ closed' = TRUE
    /\ notified' = (notified \/ CloseNotify)
    /\ UNCHANGED <<now, deadline, thread, planned>>

\* The thread holds the lock: it ends once closed; with its deadline due it
\* forgets it and releases the lock to wake the clock; otherwise it sleeps
\* until the deadline, or until notified.
ThreadRun ==
    /\ thread = "running"
    /\ IF closed THEN
           /\ thread' = "ended"
           /\ UNCHANGED <<deadline, planned, notified>>
       ELSE IF deadline # 0 /\ deadline <= now THEN
           /\ deadline' = 0
           /\ thread' = "waking"
           /\ UNCHANGED <<planned, notified>>
       ELSE
           /\ planned' = deadline
           /\ thread' = "sleeping"
           /\ notified' = FALSE   \* a wait consumes a notify that came before it
           /\ UNCHANGED deadline
    /\ UNCHANGED <<now, closed>>

\* The clock was woken; the thread takes the lock again.
ThreadRelock ==
    /\ thread = "waking"
    /\ thread' = "running"
    /\ UNCHANGED <<now, deadline, planned, notified, closed>>

\* The wait returns: the deadline came, a notify came, or for no reason.
ThreadWake ==
    /\ thread = "sleeping"
    /\ thread' = "running"
    /\ notified' = FALSE
    /\ UNCHANGED <<now, deadline, planned, closed>>

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<deadline, thread, planned, notified, closed>>

Next ==
    \/ \E d \in 0..MaxTime : Set(d)
    \/ Close
    \/ ThreadRun \/ ThreadRelock \/ ThreadWake \/ Tick

\* The thread runs when it holds the lock and takes it back after waking
\* the clock. It leaves its wait when its deadline has come or it was
\* notified; a spurious return is allowed but not relied on.
Fairness ==
    /\ WF_vars(ThreadRun)
    /\ WF_vars(ThreadRelock)
    /\ WF_vars(ThreadWake /\ (notified \/ (planned # 0 /\ now >= planned)))
    /\ WF_vars(Tick)

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------
\* Properties.

\* The thread never sleeps past the deadline it holds: while it sleeps with
\* no notify pending, it waits for that deadline or an earlier one, and
\* waits with no deadline only when it holds none.
SleepIsSafe ==
    (thread = "sleeping" /\ ~notified /\ ~closed)
        => (deadline = 0 \/ (planned # 0 /\ planned <= deadline))

\* A deadline that has come is acted on: the clock is woken for it (the
\* driver forgets it), or the clock moved or took it away.
DueFires ==
    [](deadline # 0 /\ deadline <= now /\ ~closed
        => <>(deadline = 0 \/ deadline > now \/ closed))

\* Once the clock is gone, its driver's thread ends, or never started.
ThreadEnds == [](closed => <>(thread \in {"ended", "unstarted"}))

=============================================================================
