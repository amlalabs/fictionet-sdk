---------------------------- MODULE LabClock ----------------------------
\* The lab clock of src/clock.rs (Clock::add, reset, update, remove,
\* advance and take_due), the owned Timer of src/cx/timer.rs
\* (Timer::poll_until and clear), and the idle point of a lab: Cx::idle
\* through RunShared::idle and the end of a turn in RunState::poll
\* (src/run.rs). Tasks of the run sleep, idle or end; a harness thread
\* polls a Timer of its own with a clock reading that can go stale.
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Tasks,           \* the run's tasks, as their numbers
    Deadlines,       \* the instants a sleep may name
    MaxSpurious,     \* how many times a stale waker may wake a task
    IdleWoken,       \* Queue::idle_woken: a repeated idle wait waits for the next idle point
    FreshIdOnReset,  \* Clock::reset registers under a new id
    MaxOnAdvance,    \* Clock::advance never moves the clock back
    MaxArms          \* how many deadlines the harness thread sets in all

Harness == 0        \* the timer polled outside the run
Who == Tasks \cup {Harness}

VARIABLES
    now,        \* State::now
    entries,    \* State::entries: records with at, id and who
    nextId,     \* State::next_id
    nextSeq,    \* history: a counter of registrations, for the wake order
    timer,      \* per owner: Entry::at (deadline, 0 for none), Entry::id (entry, 0 for none)
                \* and the deadline last polled for (wanted, 0 for none)
    seq,        \* per owner: the registration count when its entry was last set
    tstate,     \* per task: "fresh", "ready", "sleeping", "idle" or "done"
    ready,      \* Queue::ready
    turn,       \* RunState::turn
    idle,       \* Queue::idle, as the tasks waiting
    idleWoken,  \* Queue::idle_woken
    phase,      \* "turn", "between" or "ended"
    hphase,     \* the harness: "none", "read" (holds a clock reading), "armed" or "woken"
    hseen,      \* the harness's clock reading
    spurious,   \* per task: stale wakes so far
    harms,      \* deadlines the harness has set so far
    wakeOk      \* history: every Clock::advance so far woke timers in order and in time

vars == <<now, entries, nextId, nextSeq, timer, seq, tstate, ready, turn, idle,
          idleWoken, phase, hphase, hseen, spurious, harms, wakeOk>>

Range(s) == {s[i] : i \in DOMAIN s}
Queued(t) == t \in Range(ready) \/ t \in Range(turn)
Max(a, b) == IF a >= b THEN a ELSE b
NoTimer == [deadline |-> 0, entry |-> 0, wanted |-> 0]

Init ==
    /\ now = 0
    /\ entries = {}
    /\ nextId = 1 /\ nextSeq = 1
    /\ timer = [w \in Who |-> NoTimer]
    /\ seq = [w \in Who |-> 0]
    /\ tstate = [t \in Tasks |-> "fresh"]
    /\ ready = <<>>
    /\ turn = <<>>
    /\ idle = {}
    /\ idleWoken = FALSE
    /\ phase = "between"
    /\ hphase = "none" /\ hseen = 0
    /\ spurious = [t \in Tasks |-> 0]
    /\ harms = 0
    /\ wakeOk = TRUE

----------------------------------------------------------------------------
\* Timer::poll_until for a deadline that has not passed: the clock entry
\* is added, moved or kept.

\* Clock::add.
Add(w, at) ==
    /\ entries' = entries \cup {[at |-> at, id |-> nextId, who |-> w]}
    /\ nextId' = nextId + 1
    /\ timer' = [timer EXCEPT ![w] = [deadline |-> at, entry |-> nextId, wanted |-> at]]
    /\ seq' = [seq EXCEPT ![w] = nextSeq]
    /\ nextSeq' = nextSeq + 1

\* Clock::reset: the old entry goes, if it is still there, and the timer
\* is registered again.
Reset(w, at) ==
    LET old == timer[w].entry
        id == IF FreshIdOnReset THEN nextId ELSE old
    IN /\ entries' = {e \in entries : e.id # old} \cup {[at |-> at, id |-> id, who |-> w]}
       /\ nextId' = nextId + 1
       /\ timer' = [timer EXCEPT ![w] = [deadline |-> at, entry |-> id, wanted |-> at]]
       /\ seq' = [seq EXCEPT ![w] = nextSeq]
       /\ nextSeq' = nextSeq + 1

\* The entry stays where it is: at most its waker changes (Clock::update),
\* and the timer notes the deadline it was polled for.
Keep(w, at) ==
    /\ timer' = [timer EXCEPT ![w].wanted = at]
    /\ UNCHANGED <<entries, nextId, seq, nextSeq>>

\* Timer::poll_until with the clock read as `reading`: the same deadline,
\* or a later one while the entry has yet to come, keeps the entry, which
\* wakes the owner first; an earlier deadline, or one polled for once the
\* entry's instant has passed, moves it.
Register(w, at, reading) ==
    IF timer[w].entry = 0 THEN Add(w, at)
    ELSE IF timer[w].deadline = at THEN Keep(w, at)
    ELSE IF timer[w].deadline < at /\ reading < timer[w].deadline THEN Keep(w, at)
    ELSE Reset(w, at)

\* Timer::clear: the entry goes, if it is still there.
Clear(w) ==
    /\ entries' = {e \in entries : e.id # timer[w].entry}
    /\ timer' = [timer EXCEPT ![w] = NoTimer]
    /\ UNCHANGED <<nextId, seq, nextSeq>>

----------------------------------------------------------------------------
\* The run loop.

\* A turn starts with the tasks that are ready. A lab polls itself again
\* after every turn, so a turn may be empty.
BeginTurn ==
    /\ phase = "between"
    /\ turn' = ready
    /\ ready' = <<>>
    /\ phase' = "turn"
    /\ UNCHANGED <<now, entries, nextId, nextSeq, timer, seq, tstate, idle, idleWoken,
                   hphase, hseen, spurious, harms, wakeOk>>

\* The next task of the turn is polled. A sleeping task woken before its
\* deadline keeps waiting, or moves its deadline as a driver with an owned
\* Timer does. A task whose wait is over ends, sleeps until a later
\* instant with a new Timer, or waits for the run to go idle.
Polling == phase = "turn" /\ turn # <<>>
Current == Head(turn)
Early == tstate[Current] = "sleeping" /\ now < timer[Current].wanted
Without == {e \in entries : e.id # timer[Current].entry}

\* Woken before the deadline: Timer::poll_until keeps the entry.
PollWait ==
    /\ Polling /\ Early
    /\ turn' = Tail(turn)
    /\ Register(Current, timer[Current].wanted, now)
    /\ UNCHANGED <<now, tstate, ready, idle, idleWoken, phase, hphase, hseen, spurious, harms, wakeOk>>

\* The task's wait is over, and it ends: its Timer is dropped.
PollDone ==
    /\ Polling /\ ~Early
    /\ turn' = Tail(turn)
    /\ tstate' = [tstate EXCEPT ![Current] = "done"]
    /\ entries' = Without
    /\ timer' = [timer EXCEPT ![Current] = NoTimer]
    /\ UNCHANGED <<now, nextId, nextSeq, seq, ready, idle, idleWoken, phase, hphase, hseen,
                   spurious, harms, wakeOk>>

\* The task's wait is over, and it waits for the run to go idle.
PollIdle ==
    /\ Polling /\ ~Early
    /\ turn' = Tail(turn)
    /\ tstate' = [tstate EXCEPT ![Current] = "idle"]
    /\ idle' = idle \cup {Current}
    /\ entries' = Without
    /\ timer' = [timer EXCEPT ![Current] = NoTimer]
    /\ UNCHANGED <<now, nextId, nextSeq, seq, ready, idleWoken, phase, hphase, hseen,
                   spurious, harms, wakeOk>>

\* The task sleeps until a later instant: a new Timer when its wait was
\* over, or the deadline of its owned Timer moved when woken early.
PollSleep(d) ==
    /\ Polling /\ d > now
    /\ turn' = Tail(turn)
    /\ IF Early
       THEN /\ d # timer[Current].wanted
            /\ Register(Current, d, now)
            /\ UNCHANGED tstate
       ELSE /\ tstate' = [tstate EXCEPT ![Current] = "sleeping"]
            /\ entries' = Without \cup {[at |-> d, id |-> nextId, who |-> Current]}
            /\ timer' = [timer EXCEPT ![Current] = [deadline |-> d, entry |-> nextId, wanted |-> d]]
            /\ nextId' = nextId + 1
            /\ seq' = [seq EXCEPT ![Current] = nextSeq]
            /\ nextSeq' = nextSeq + 1
    /\ UNCHANGED <<now, ready, idle, idleWoken, phase, hphase, hseen, spurious, harms, wakeOk>>

\* The end of a turn: more work means another turn; a first idle wait
\* since the last idle point is woken; otherwise the clock jumps to the
\* earliest deadline, and with no deadline the lab reports a deadlock.
Earliest == CHOOSE e \in entries : \A f \in entries : e.at <= f.at
RECURSIVE Ordered(_)
Ordered(es) ==
    IF es = {} THEN <<>>
    ELSE LET e == CHOOSE e \in es : \A f \in es : e.at < f.at \/ (e.at = f.at /\ e.id <= f.id)
         IN <<e.who>> \o Ordered(es \ {e})
InOrder(ws) == \A i, j \in DOMAIN ws : i < j => seq[ws[i]] <= seq[ws[j]]

EndTurn ==
    /\ phase = "turn" /\ turn = <<>>
    /\ LET more == ready # <<>>
           repeated == idleWoken /\ IdleWoken
           wakeIdle == ~more /\ idle # {} /\ ~repeated
       IN IF more THEN
              /\ phase' = "between"
              /\ idleWoken' = FALSE
              /\ UNCHANGED <<now, entries, tstate, ready, idle, hphase, wakeOk>>
          ELSE IF wakeIdle THEN
              /\ phase' = "between"
              /\ idleWoken' = TRUE
              /\ ready' = Ordered({[at |-> 0, id |-> t, who |-> t] : t \in idle})
              /\ idle' = {}
              /\ tstate' = [t \in Tasks |-> IF t \in idle THEN "ready" ELSE tstate[t]]
              /\ UNCHANGED <<now, entries, hphase, wakeOk>>
          ELSE IF entries = {} THEN
              /\ phase' = "ended"
              /\ idleWoken' = FALSE
              /\ UNCHANGED <<now, entries, tstate, ready, idle, hphase, wakeOk>>
          ELSE
              LET at == Earliest.at
                  new == IF MaxOnAdvance THEN Max(now, at) ELSE at
                  due == {e \in entries : e.at <= new}
                  woken == Ordered(due)
              IN /\ phase' = "between"
                 /\ idleWoken' = FALSE
                 /\ now' = new
                 /\ entries' = entries \ due
                 /\ wakeOk' = (wakeOk /\ InOrder(woken) /\ \A w \in Range(woken) : timer[w].deadline <= new)
                 /\ ready' = SelectSeq(woken, LAMBDA w : w \in Tasks)
                 /\ tstate' = [t \in Tasks |-> IF t \in Range(woken) THEN "ready" ELSE tstate[t]]
                 /\ hphase' = IF Harness \in Range(woken) THEN "woken" ELSE hphase
                 /\ UNCHANGED idle
    /\ UNCHANGED <<nextId, nextSeq, timer, seq, turn, hseen, spurious, harms>>

\* A fresh task is admitted to the run.
Admit(t) ==
    /\ tstate[t] = "fresh" /\ phase # "ended"
    /\ tstate' = [tstate EXCEPT ![t] = "ready"]
    /\ ready' = Append(ready, t)
    /\ UNCHANGED <<now, entries, nextId, nextSeq, timer, seq, turn, idle, idleWoken, phase,
                   hphase, hseen, spurious, harms, wakeOk>>

\* A stale waker wakes a sleeping task before its deadline.
Spurious(t) ==
    /\ tstate[t] = "sleeping" /\ ~Queued(t) /\ spurious[t] < MaxSpurious /\ phase # "ended"
    /\ spurious' = [spurious EXCEPT ![t] = @ + 1]
    /\ ready' = Append(ready, t)
    /\ UNCHANGED <<now, entries, nextId, nextSeq, timer, seq, tstate, turn, idle, idleWoken,
                   phase, hphase, hseen, harms, wakeOk>>

----------------------------------------------------------------------------
\* The harness thread polls its own Timer. It reads the clock, and some
\* time later registers a deadline after that reading, which the lab may
\* have passed by then. A Timer whose deadline it finds passed is cleared.

HarnessRead ==
    /\ hphase \in {"none", "armed", "woken"} /\ phase # "ended"
    /\ hseen' = now
    /\ hphase' = "read"
    /\ IF hphase = "woken" THEN Clear(Harness) ELSE UNCHANGED <<entries, nextId, timer, seq, nextSeq>>
    /\ UNCHANGED <<now, tstate, ready, turn, idle, idleWoken, phase, spurious, harms, wakeOk>>

HarnessArm(at) ==
    /\ hphase = "read" /\ at > hseen /\ harms < MaxArms
    /\ Register(Harness, at, hseen)
    /\ hphase' = "armed"
    /\ harms' = harms + 1
    /\ UNCHANGED <<now, tstate, ready, turn, idle, idleWoken, phase, hseen, spurious, wakeOk>>

\* The harness drops its Timer.
HarnessDrop ==
    /\ hphase \in {"armed", "woken"}
    /\ Clear(Harness)
    /\ hphase' = "none"
    /\ UNCHANGED <<now, tstate, ready, turn, idle, idleWoken, phase, hseen, spurious, harms, wakeOk>>

----------------------------------------------------------------------------

Poll == PollWait \/ PollDone \/ PollIdle \/ \E d \in Deadlines : PollSleep(d)

Next ==
    \/ BeginTurn \/ EndTurn \/ Poll
    \/ \E t \in Tasks : Admit(t) \/ Spurious(t)
    \/ HarnessRead \/ HarnessDrop
    \/ \E at \in Deadlines : HarnessArm(at)

\* The run keeps taking turns and polls the tasks of each.
Fairness ==
    /\ WF_vars(BeginTurn)
    /\ WF_vars(EndTurn)
    /\ WF_vars(Poll)

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------
\* Properties.

\* The lab clock never moves back, not even for a deadline a harness
\* thread set after the clock passed it.
Monotonic == [][now' >= now]_vars

\* Every Clock::advance woke only timers whose deadline had passed, and
\* timers due at the same instant in the order they were set, a moved
\* timer counting from its move.
WakesInOrderAndInTime == wakeOk

\* Every clock entry belongs to a Timer that holds its id and deadline:
\* nothing is left registered after a move or a drop.
EntriesOwned ==
    \A e \in entries : timer[e.who].entry = e.id /\ timer[e.who].deadline = e.at

\* A sleeping task that is not queued has an entry: its wake cannot be lost.
SleepersHaveEntries ==
    \A t \in Tasks : (tstate[t] = "sleeping" /\ ~Queued(t)) => \E e \in entries : e.who = t

\* Every sleeping task is woken: the clock keeps jumping, also while other
\* tasks loop on Cx::idle.
SleepersWake ==
    \A t \in Tasks : [](tstate[t] = "sleeping" => <>(tstate[t] # "sleeping" \/ Queued(t)))

=============================================================================
