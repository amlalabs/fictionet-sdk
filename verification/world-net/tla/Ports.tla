------------------------------- MODULE Ports -------------------------------
(* The ready-slot scheduling of src/stdlib/network/ports.rs: one task
   serving many interfaces. Each slot has a bit in a bitmap (`Ready`) that
   its `SlotWaker` sets with no lock. `Ports::serve` searches the bitmap
   from the slot after the one served last (`cursor`), clears the bit it
   finds and polls that slot with its slot waker; an interface that has
   nothing keeps that waker and gives Pending. When the interface later
   has a packet, or its peer closes, it wakes the slot waker, which sets
   the slot's bit and then, as a second step, wakes the task if the task
   is parked (`sync::Parked::wake`).

   `Ports::next` serves; finding no bit, it parks the task's waker and
   serves once more before it returns Pending. `Ports::add`, `replace` and
   `close` run between calls to `next`.

   The slots' interfaces are abstract: `data` says a slot has a packet,
   `gone` that its peer closed. The bitmap is the set `bits`; its summary
   words, which only speed the search, are left out. The fences in
   `Parked::park` and `Parked::wake` make each step below atomic and the
   steps of different threads interleave in one order, which is how TLC
   runs them. *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    N,                \* the number of slots
    RecheckAfterPark, \* next serves once more after parking (the code);
                      \* FALSE: it returns Pending right after parking
    NoSlot

Slots == 0..(N - 1)

VARIABLES
    open,      \* slots that hold a port
    data,      \* slots whose interface has a packet waiting
    gone,      \* slots whose interface's peer closed
    bits,      \* the bitmap: slots whose bit is set
    cursor,    \* where the next search starts
    armed,     \* slots whose interface holds the slot's waker
    notifying, \* slots whose waker set the bit and has yet to look at the
               \* task's parked flag
    parked,    \* the task's parked flag is up
    taskWaker, \* the task's Parked holds its waker
    pc,        \* the task: "idle", "serve", "poll", "parking" or "parked"
    again,     \* the task is in the look after parking
    woken,     \* the task's waker was woken since it last began a poll
    polling    \* the slot found and about to be polled

vars == <<open, data, gone, bits, cursor, armed, notifying, parked, taskWaker,
          pc, again, woken, polling>>

Init ==
    /\ open = {} /\ data = {} /\ gone = {}
    /\ bits = {} /\ cursor = 0 /\ armed = {} /\ notifying = {}
    /\ parked = FALSE /\ taskWaker = FALSE
    /\ pc = "idle" /\ again = FALSE /\ woken = FALSE
    /\ polling = NoSlot

\* The first slot with its bit set at or after `from`, wrapping around.
Dist(i, from) == IF i >= from THEN i - from ELSE i + N - from
First(set, from) == CHOOSE i \in set : \A j \in set : Dist(i, from) <= Dist(j, from)

-----------------------------------------------------------------------------
\* The task is polled: at the start of next, or again after a wake.
Begin ==
    /\ pc = "idle" \/ (pc = "parked" /\ woken)
    /\ pc' = "serve"
    /\ again' = FALSE
    /\ woken' = FALSE
    /\ UNCHANGED <<open, data, gone, bits, cursor, armed, notifying, parked,
                   taskWaker, polling>>

\* Ready::find and Ready::clear.
Find ==
    /\ pc = "serve" /\ bits # {}
    /\ LET i == First(bits, cursor) IN
       /\ polling' = i
       /\ bits' = bits \ {i}
       /\ cursor' = (i + 1) % N
    /\ pc' = "poll"
    /\ UNCHANGED <<open, data, gone, armed, notifying, parked, taskWaker,
                   again, woken>>

\* The found slot is polled with its slot waker.
Poll ==
    /\ pc = "poll"
    /\ LET i == polling IN
       /\ polling' = NoSlot
       /\ IF i \notin open THEN
             \* A closed slot whose bit was still set: skipped.
             /\ pc' = "serve"
             /\ UNCHANGED <<open, data, gone, bits, armed>>
          ELSE IF i \in data THEN
             \* Ready(packet): its bit is set again, in case it has more.
             /\ data' = data \ {i}
             /\ bits' = bits \cup {i}
             /\ pc' = "idle"
             /\ UNCHANGED <<open, gone, armed>>
          ELSE IF i \in gone THEN
             \* Ready(Err(Closed)): Ports::close, Event::Closed.
             /\ open' = open \ {i}
             /\ gone' = gone \ {i}
             /\ armed' = armed \ {i}
             /\ pc' = "idle"
             /\ UNCHANGED <<data, bits>>
          ELSE
             \* Pending: the interface holds the slot waker.
             /\ armed' = armed \cup {i}
             /\ pc' = "serve"
             /\ UNCHANGED <<open, data, gone, bits>>
    /\ UNCHANGED <<cursor, notifying, parked, taskWaker, again, woken>>

\* The search found no bit set.
Empty ==
    /\ pc = "serve" /\ bits = {}
    /\ pc' = IF again THEN "parked" ELSE "parking"
    /\ UNCHANGED <<open, data, gone, bits, cursor, armed, notifying, parked,
                   taskWaker, again, woken, polling>>

\* Parked::park: leave the task's waker, raise the flag; then serve once
\* more.
Park ==
    /\ pc = "parking"
    /\ taskWaker' = TRUE
    /\ parked' = TRUE
    /\ pc' = IF RecheckAfterPark THEN "serve" ELSE "parked"
    /\ again' = TRUE
    /\ UNCHANGED <<open, data, gone, bits, cursor, armed, notifying, woken,
                   polling>>

\* SlotWaker::wake_by_ref, first step, when the interface at i holds the
\* waker: the slot's bit is set.
Mark(i) ==
    /\ bits' = IF i \in armed THEN bits \cup {i} ELSE bits
    /\ notifying' = IF i \in armed THEN notifying \cup {i} ELSE notifying
    /\ armed' = armed \ {i}

\* SlotWaker::wake_by_ref, second step: Parked::wake.
Notify(i) ==
    /\ i \in notifying
    /\ notifying' = notifying \ {i}
    /\ woken' = woken \/ (parked /\ taskWaker)
    /\ taskWaker' = IF parked THEN FALSE ELSE taskWaker
    /\ parked' = FALSE
    /\ UNCHANGED <<open, data, gone, bits, cursor, armed, pc, again, polling>>

\* A packet reaches the interface at i. None does once its peer closed: a
\* cable drops what is sent into a closed direction.
Deliver(i) ==
    /\ i \in open /\ i \notin data /\ i \notin gone
    /\ data' = data \cup {i}
    /\ Mark(i)
    /\ UNCHANGED <<open, gone, cursor, parked, taskWaker, pc, again, woken,
                   polling>>

\* The interface's peer closes.
PeerClose(i) ==
    /\ i \in open /\ i \notin gone
    /\ gone' = gone \cup {i}
    /\ Mark(i)
    /\ UNCHANGED <<open, data, cursor, parked, taskWaker, pc, again, woken,
                   polling>>

\* Ports::add or Ports::replace into a free slot, between polls. The new
\* port may already hold a packet.
Add(i) ==
    /\ pc = "idle" /\ i \notin open
    /\ open' = open \cup {i}
    /\ bits' = bits \cup {i}
    /\ \E d \in BOOLEAN : data' = IF d THEN data \cup {i} ELSE data \ {i}
    /\ gone' = gone \ {i}
    /\ UNCHANGED <<cursor, armed, notifying, parked, taskWaker, pc, again,
                   woken, polling>>

\* Ports::close, between polls: the interface and its waker go.
Close(i) ==
    /\ pc = "idle" /\ i \in open
    /\ open' = open \ {i}
    /\ data' = data \ {i}
    /\ gone' = gone \ {i}
    /\ armed' = armed \ {i}
    /\ UNCHANGED <<bits, cursor, notifying, parked, taskWaker, pc, again,
                   woken, polling>>

Task == Begin \/ Find \/ Poll \/ Empty \/ Park

Next ==
    \/ Task
    \/ \E i \in Slots : Deliver(i) \/ PeerClose(i) \/ Add(i) \/ Close(i) \/ Notify(i)

Spec == Init /\ [][Next]_vars /\ WF_vars(Task) /\ \A i \in Slots : WF_vars(Notify(i))

-----------------------------------------------------------------------------
TypeOK ==
    /\ open \subseteq Slots /\ data \subseteq Slots /\ gone \subseteq Slots
    /\ bits \subseteq Slots /\ armed \subseteq Slots /\ notifying \subseteq Slots
    /\ cursor \in Slots
    /\ pc \in {"idle", "serve", "poll", "parking", "parked"}

\* The flag is up only with a waker behind it.
FlagHasWaker == parked => taskWaker

\* Every open slot is somewhere the task will find it: its interface holds
\* the slot waker, its bit is set, or it is being polled.
SlotIsSomewhere ==
    \A i \in open : i \in armed \/ i \in bits \/ polling = i

\* A parked task with a bit set has a wake on its way: its waker is parked
\* and a slot waker has yet to look at the flag.
NoLostTask ==
    pc = "parked" /\ ~woken /\ bits # {} => parked /\ notifying # {}

\* A slot with a packet, or whose peer closed, is served: the task takes
\* the packet or closes the slot, unless the caller closes it first.
Served ==
    \A i \in Slots :
        /\ [](i \in open /\ i \in data => <>(i \notin open \/ i \notin data))
        /\ [](i \in open /\ i \in gone => <>(i \notin open))
=============================================================================
