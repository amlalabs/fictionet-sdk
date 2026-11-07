----------------------------- MODULE Timers -----------------------------
\* The host wake driver of src/timer.rs: Timers::add, reset and remove,
\* State::take_due with its stale heap entries, and Timers::thread, which
\* sleeps on a Condvar until the earliest deadline. Each run's Clock::arm
\* is one client, moving its one host entry to the run's earliest deadline;
\* here the clients are abstract timer ids.
EXTENDS Naturals, FiniteSets

CONSTANTS
    Ids,        \* the timers
    MaxTime,    \* the last instant; deadlines are 1..MaxTime
    StaleCheck, \* take_due skips a heap entry whose deadline is not its timer's
    Notify      \* add and reset notify the thread of an earlier deadline

Deadlines == 1..MaxTime

VARIABLES
    now,       \* the host clock
    heap,      \* State::heap, as the set of its <<deadline, id>> pairs
    entries,   \* State::entries: each timer's deadline, 0 when absent
    thread,    \* "running" (holding the lock), "waking" (lock released, wakers running) or "sleeping"
    planned,   \* the deadline the sleeping thread waits for, 0 for none
    notified,  \* Condvar::notify_one not yet consumed by a wait
    early      \* history: a timer was fired before its deadline

vars == <<now, heap, entries, thread, planned, notified, early>>

Live == {id \in Ids : entries[id] # 0}
HeapMin == IF heap = {} THEN 0 ELSE (CHOOSE p \in heap : \A q \in heap : p[1] <= q[1])[1]

Init ==
    /\ now = 0
    /\ heap = {}
    /\ entries = [id \in Ids |-> 0]
    /\ thread = "running"
    /\ planned = 0
    /\ notified = FALSE
    /\ early = FALSE

\* The lock is free while the thread sleeps or wakes timers.
Unlocked == thread # "running"

\* Timers::add and reset both push a heap entry and notify the thread when
\* the deadline is earlier than the heap's top.
Push(id, d) ==
    /\ heap' = heap \cup {<<d, id>>}
    /\ entries' = [entries EXCEPT ![id] = d]
    /\ notified' = (notified \/ (Notify /\ (heap = {} \/ d < HeapMin)))

\* Timers::add, for a timer that has no entry.
Add(id, d) ==
    /\ Unlocked /\ entries[id] = 0
    /\ Push(id, d)
    /\ UNCHANGED <<now, thread, planned, early>>

\* Timers::reset, to another deadline. The old heap entry stays and is
\* stale. A timer that fired already is added again under its id.
Reset(id, d) ==
    /\ Unlocked /\ entries[id] # d
    /\ Push(id, d)
    /\ UNCHANGED <<now, thread, planned, early>>

\* Timers::remove: only the entry goes; the heap keeps a stale pair.
Remove(id) ==
    /\ Unlocked /\ entries[id] # 0
    /\ entries' = [entries EXCEPT ![id] = 0]
    /\ UNCHANGED <<now, heap, thread, planned, notified, early>>

\* State::take_due under the lock: stale pairs are dropped from the top of
\* the heap, due timers are fired, and the next deadline is read. With
\* timers due the thread releases the lock to wake them; otherwise it
\* sleeps until the next deadline, or until notified.
Stale(p) == entries[p[2]] # p[1]
Dropped == IF StaleCheck THEN {p \in heap : Stale(p)} ELSE {}
Kept == heap \ Dropped
Due == {p \in Kept : p[1] <= now /\ entries[p[2]] # 0}

ThreadRun ==
    /\ thread = "running"
    /\ IF Due # {} THEN
           /\ heap' = Kept \ Due
           /\ entries' = [id \in Ids |-> IF \E p \in Due : p[2] = id THEN 0 ELSE entries[id]]
           /\ early' = (early \/ \E p \in Due : entries[p[2]] > now)
           /\ thread' = "waking"
           /\ UNCHANGED <<planned, notified>>
       ELSE
           /\ heap' = Kept
           /\ planned' = IF Kept = {} THEN 0
                         ELSE (CHOOSE p \in Kept : \A q \in Kept : p[1] <= q[1])[1]
           /\ thread' = "sleeping"
           /\ notified' = FALSE   \* a wait consumes a notify that came before it
           /\ UNCHANGED <<entries, early>>
    /\ UNCHANGED now

\* The wakers were woken; the thread takes the lock again.
ThreadRelock ==
    /\ thread = "waking"
    /\ thread' = "running"
    /\ UNCHANGED <<now, heap, entries, planned, notified, early>>

\* The wait returns: the deadline came, a notify came, or for no reason.
ThreadWake ==
    /\ thread = "sleeping"
    /\ thread' = "running"
    /\ notified' = FALSE
    /\ UNCHANGED <<now, heap, entries, planned, early>>

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<heap, entries, thread, planned, notified, early>>

Next ==
    \/ \E id \in Ids : \E d \in Deadlines : Add(id, d) \/ Reset(id, d)
    \/ \E id \in Ids : Remove(id)
    \/ ThreadRun \/ ThreadRelock \/ ThreadWake \/ Tick

\* The thread runs when it holds the lock and takes it back after waking
\* timers. It leaves its wait when its deadline has come or it was
\* notified; a spurious return is allowed but not relied on.
Fairness ==
    /\ WF_vars(ThreadRun)
    /\ WF_vars(ThreadRelock)
    /\ WF_vars(ThreadWake /\ (notified \/ (planned # 0 /\ now >= planned)))
    /\ WF_vars(Tick)

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------
\* Properties.

\* No timer is woken before its deadline, whatever stale pairs the heap holds.
NoEarlyFire == ~early

\* The thread never sleeps past a live deadline: while it sleeps without a
\* notify pending, every live timer is due no earlier than its planned wake.
SleepIsSafe ==
    (thread = "sleeping" /\ ~notified) =>
        (Live = {} \/ (planned # 0 /\ \A id \in Live : entries[id] >= planned))

\* Every timer that is due is fired, or moved, or removed.
DueTimersFire ==
    \A id \in Ids : [](entries[id] # 0 /\ entries[id] <= now => <>(entries[id] = 0 \/ entries[id] > now))

=============================================================================
