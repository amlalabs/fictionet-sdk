------------------------------- MODULE Ports -------------------------------
(* The ready-slot scheduling of src/stdlib/network/ports.rs: one task
   serving many interfaces. `Ports::next` registers the task's waker in
   `ReadyInner::task`, pops slots from `ReadyInner::slots` and polls each
   with its own `SlotWaker`; an interface that has nothing registers that
   waker and gives Pending. When the interface later has a packet, or its
   peer closes, it wakes the slot waker, which queues the slot and wakes
   the task (`SlotWaker::wake_by_ref`). `Ports::add`, `replace` and
   `close` run between calls to `next`.

   The slots' interfaces are abstract: `data` says a slot has a packet,
   `gone` that its peer closed. *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Slots,         \* the slot numbers
    RegisterFirst, \* the task puts its waker in the queue before it drains
                   \* the queue (Ports::next as written); FALSE: after
    NoSlot

VARIABLES
    open,      \* slots that hold a port
    data,      \* slots whose interface has a packet waiting
    gone,      \* slots whose interface's peer closed
    queue,     \* ReadyInner::slots, in order
    armed,     \* slots whose interface holds the slot's waker
    taskWaker, \* ReadyInner::task holds the task's waker
    pc,        \* the task: "idle", "drain", "poll", "parking" or "parked"
    woken,     \* the task's waker was woken since it last began a poll
    polling    \* the slot popped and about to be polled

vars == <<open, data, gone, queue, armed, taskWaker, pc, woken, polling>>

Range(s) == {s[i] : i \in DOMAIN s}

Init ==
    /\ open = {} /\ data = {} /\ gone = {}
    /\ queue = <<>> /\ armed = {}
    /\ taskWaker = FALSE
    /\ pc = "idle" /\ woken = FALSE
    /\ polling = NoSlot

\* ReadyInner::push: at most once.
Push(q, i) == IF i \in Range(q) THEN q ELSE Append(q, i)

-----------------------------------------------------------------------------
\* The task is polled: at the start of next, or again after a wake.
Begin ==
    /\ pc = "idle" \/ (pc = "parked" /\ woken)
    /\ pc' = "drain"
    /\ woken' = FALSE
    /\ taskWaker' = IF RegisterFirst THEN TRUE ELSE taskWaker
    /\ UNCHANGED <<open, data, gone, queue, armed, polling>>

\* ReadyInner::pop.
Pop ==
    /\ pc = "drain" /\ queue # <<>>
    /\ polling' = Head(queue)
    /\ queue' = Tail(queue)
    /\ pc' = "poll"
    /\ UNCHANGED <<open, data, gone, armed, taskWaker, woken>>

\* The popped slot is polled with its slot waker.
Poll ==
    /\ pc = "poll"
    /\ LET i == polling IN
       /\ polling' = NoSlot
       /\ IF i \notin open THEN
             \* A closed slot still in the queue: skipped.
             /\ pc' = "drain"
             /\ UNCHANGED <<open, data, gone, queue, armed>>
          ELSE IF i \in data THEN
             \* Ready(packet): the slot goes to the back, in case it has more.
             /\ data' = data \ {i}
             /\ queue' = Push(queue, i)
             /\ pc' = "idle"
             /\ UNCHANGED <<open, gone, armed>>
          ELSE IF i \in gone THEN
             \* Ready(Err(Closed)): Ports::close, Event::Closed.
             /\ open' = open \ {i}
             /\ gone' = gone \ {i}
             /\ armed' = armed \ {i}
             /\ pc' = "idle"
             /\ UNCHANGED <<data, queue>>
          ELSE
             \* Pending: the interface holds the slot waker.
             /\ armed' = armed \cup {i}
             /\ pc' = "drain"
             /\ UNCHANGED <<open, data, gone, queue>>
    /\ UNCHANGED <<taskWaker, woken>>

\* The pop found the queue empty: the loop ends.
Empty ==
    /\ pc = "drain" /\ queue = <<>>
    /\ pc' = "parking"
    /\ UNCHANGED <<open, data, gone, queue, armed, taskWaker, woken, polling>>

\* The task returns Pending, after the sleep and cancel registrations.
Park ==
    /\ pc = "parking"
    /\ taskWaker' = IF RegisterFirst THEN taskWaker ELSE TRUE
    /\ pc' = "parked"
    /\ UNCHANGED <<open, data, gone, queue, armed, woken, polling>>

\* SlotWaker::wake_by_ref, when the interface at i holds the waker: the
\* slot is queued and the task's waker taken and woken.
Wake(i) ==
    /\ queue' = IF i \in armed THEN Push(queue, i) ELSE queue
    /\ armed' = armed \ {i}
    /\ woken' = (woken \/ (i \in armed /\ taskWaker))
    /\ taskWaker' = (taskWaker /\ i \notin armed)

\* A packet reaches the interface at i. None does once its peer closed: a
\* cable drops what is sent into a closed direction.
Deliver(i) ==
    /\ i \in open /\ i \notin data /\ i \notin gone
    /\ data' = data \cup {i}
    /\ Wake(i)
    /\ UNCHANGED <<open, gone, pc, polling>>

\* The interface's peer closes.
PeerClose(i) ==
    /\ i \in open /\ i \notin gone
    /\ gone' = gone \cup {i}
    /\ Wake(i)
    /\ UNCHANGED <<open, data, pc, polling>>

\* Ports::add or Ports::replace into a free slot, between polls. The new
\* port may already hold a packet.
Add(i) ==
    /\ pc = "idle" /\ i \notin open
    /\ open' = open \cup {i}
    /\ queue' = Push(queue, i)
    /\ \E d \in BOOLEAN : data' = IF d THEN data \cup {i} ELSE data \ {i}
    /\ gone' = gone \ {i}
    /\ UNCHANGED <<armed, taskWaker, pc, woken, polling>>

\* Ports::close, between polls: the interface and its waker go.
Close(i) ==
    /\ pc = "idle" /\ i \in open
    /\ open' = open \ {i}
    /\ data' = data \ {i}
    /\ gone' = gone \ {i}
    /\ armed' = armed \ {i}
    /\ UNCHANGED <<queue, taskWaker, pc, woken, polling>>

Task == Begin \/ Pop \/ Poll \/ Empty \/ Park

Next ==
    \/ Task
    \/ \E i \in Slots : Deliver(i) \/ PeerClose(i) \/ Add(i) \/ Close(i)

Spec == Init /\ [][Next]_vars /\ WF_vars(Task)

-----------------------------------------------------------------------------
\* The queue holds each slot at most once.
AtMostOnce == \A i, j \in DOMAIN queue : queue[i] = queue[j] => i = j

\* Every open slot is somewhere the task will find it: its interface holds
\* the slot waker, it is queued, or it is being polled.
SlotIsSomewhere ==
    \A i \in open : i \in armed \/ i \in Range(queue) \/ polling = i

\* A parked task with its waker taken is woken.
NoLostTask == pc = "parked" /\ ~taskWaker => woken

\* A slot with a packet, or whose peer closed, is served: the task takes
\* the packet or closes the slot, unless the caller closes it first.
Served ==
    \A i \in Slots :
        /\ [](i \in open /\ i \in data => <>(i \notin open \/ i \notin data))
        /\ [](i \in open /\ i \in gone => <>(i \notin open))
=============================================================================
