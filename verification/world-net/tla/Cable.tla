------------------------------- MODULE Cable -------------------------------
(* A cable from src/cable.rs: two ends, two directions, each a lock-free
   queue with one sender and one receiver, and the receiver's parked waker
   (`sync::Parked`).

   `End::poll_recv` takes a queued packet, or reports Closed once the queue
   is empty and the direction closed. Finding neither, it parks: it leaves
   its waker and raises the `parked` flag, then looks once more, and only
   then returns Pending. `End::send` queues into the other direction unless
   it is closed or full, and then, as a second step, takes and wakes the
   waker if the flag is up. `End::drop` closes both directions, drops what
   was queued for the dropped end and its own parked waker, and then, as a
   second step, wakes the other end's parked receiver.

   The fences in `Parked::park` and `Parked::wake` make each step below
   atomic and the steps of different threads interleave in one order, which
   is how TLC runs them. A take is one step: the code reads the queue, then
   `closed`, then the queue again, and the sender queues before it closes,
   so the three reads give what one atomic read would. *)
EXTENDS Naturals

CONSTANTS
    MaxQueued,        \* the queue's limit, in packets
    RecheckAfterPark, \* poll_recv looks once more after parking (the code);
                      \* FALSE: it returns Pending right after parking
    DropWakesPeer     \* End::drop wakes the other end's parked receiver
                      \* (the code); FALSE: it leaves it be

Sides == {0, 1}
Other(s) == 1 - s

VARIABLES
    queued,    \* queued[s]: packets waiting for end s
    parked,    \* parked[s]: dirs[s].receiver's flag is up
    waker,     \* waker[s]: dirs[s].receiver holds a waker
    closed,    \* closed[s]: dirs[s].closed
    dropped,   \* dropped[s]: end s was dropped
    woken,     \* woken[s]: the receiver at s was woken since it last polled
    sawClosed, \* sawClosed[s]: poll_recv at s gave Closed
    rpc,       \* rpc[s]: the receiver at s: "idle", "parking", "recheck"
               \* or "waiting" (it returned Pending)
    spc,       \* spc[s]: the sender at s: "ready", or "pushed" when it has
               \* queued a packet and has yet to look at the flag
    dpc        \* dpc[s]: "live", "closing" (dropped, the peer not yet
               \* woken) or "gone"

vars == <<queued, parked, waker, closed, dropped, woken, sawClosed, rpc, spc, dpc>>

Init ==
    /\ queued = [s \in Sides |-> 0]
    /\ parked = [s \in Sides |-> FALSE]
    /\ waker = [s \in Sides |-> FALSE]
    /\ closed = [s \in Sides |-> FALSE]
    /\ dropped = [s \in Sides |-> FALSE]
    /\ woken = [s \in Sides |-> FALSE]
    /\ sawClosed = [s \in Sides |-> FALSE]
    /\ rpc = [s \in Sides |-> "idle"]
    /\ spc = [s \in Sides |-> "ready"]
    /\ dpc = [s \in Sides |-> "live"]

\* Parked::wake on direction t: if the flag is up, take the waker and wake it.
WakeParked(t) ==
    /\ woken' = [woken EXCEPT ![t] = @ \/ (parked[t] /\ waker[t])]
    /\ waker' = [waker EXCEPT ![t] = IF parked[t] THEN FALSE ELSE @]
    /\ parked' = [parked EXCEPT ![t] = FALSE]

-----------------------------------------------------------------------------
\* End::send from s: queue into dirs[Other(s)].
Push(s) ==
    /\ ~dropped[s] /\ spc[s] = "ready"
    /\ LET t == Other(s) IN
       IF closed[t] \/ queued[t] = MaxQueued
       THEN UNCHANGED <<queued, spc>>
       ELSE /\ queued' = [queued EXCEPT ![t] = @ + 1]
            /\ spc' = [spc EXCEPT ![s] = "pushed"]
    /\ UNCHANGED <<parked, waker, closed, dropped, woken, sawClosed, rpc, dpc>>

\* End::send, second step: Parked::wake.
Notify(s) ==
    /\ spc[s] = "pushed"
    /\ WakeParked(Other(s))
    /\ spc' = [spc EXCEPT ![s] = "ready"]
    /\ UNCHANGED <<queued, closed, dropped, sawClosed, rpc, dpc>>

\* End::take at s, as one step: a packet, Closed, or nothing.
Take(s, next) ==
    IF queued[s] > 0 THEN
        /\ queued' = [queued EXCEPT ![s] = @ - 1]
        /\ rpc' = [rpc EXCEPT ![s] = "idle"]
        /\ UNCHANGED sawClosed
    ELSE IF closed[s] THEN
        /\ sawClosed' = [sawClosed EXCEPT ![s] = TRUE]
        /\ rpc' = [rpc EXCEPT ![s] = "idle"]
        /\ UNCHANGED queued
    ELSE
        /\ rpc' = [rpc EXCEPT ![s] = next]
        /\ UNCHANGED <<queued, sawClosed>>

\* End::poll_recv at s begins: the receiver is idle, or was woken.
Look(s) ==
    /\ ~dropped[s]
    /\ rpc[s] = "idle" \/ (rpc[s] = "waiting" /\ woken[s])
    /\ woken' = [woken EXCEPT ![s] = FALSE]
    /\ Take(s, "parking")
    /\ UNCHANGED <<parked, waker, closed, dropped, spc, dpc>>

\* Parked::park: leave the waker, raise the flag.
Park(s) ==
    /\ rpc[s] = "parking"
    /\ waker' = [waker EXCEPT ![s] = TRUE]
    /\ parked' = [parked EXCEPT ![s] = TRUE]
    /\ rpc' = [rpc EXCEPT ![s] = IF RecheckAfterPark THEN "recheck" ELSE "waiting"]
    /\ UNCHANGED <<queued, closed, dropped, woken, sawClosed, spc, dpc>>

\* The look after parking.
Recheck(s) ==
    /\ rpc[s] = "recheck"
    /\ Take(s, "waiting")
    /\ UNCHANGED <<parked, waker, closed, dropped, woken, spc, dpc>>

\* End::drop at s: never in the middle of its own send or poll.
Drop(s) ==
    /\ dpc[s] = "live"
    /\ rpc[s] \in {"idle", "waiting"} /\ spc[s] = "ready"
    /\ LET t == Other(s) IN
       /\ dropped' = [dropped EXCEPT ![s] = TRUE]
       /\ closed' = [closed EXCEPT ![s] = TRUE, ![t] = TRUE]
       /\ queued' = [queued EXCEPT ![s] = 0]
       /\ parked' = [parked EXCEPT ![s] = FALSE]
       /\ waker' = [waker EXCEPT ![s] = FALSE]
       /\ dpc' = [dpc EXCEPT ![s] = "closing"]
    /\ UNCHANGED <<woken, sawClosed, rpc, spc>>

\* End::drop, second step: wake the other end's parked receiver.
DropNotify(s) ==
    /\ dpc[s] = "closing"
    /\ IF DropWakesPeer
       THEN WakeParked(Other(s))
       ELSE UNCHANGED <<parked, waker, woken>>
    /\ dpc' = [dpc EXCEPT ![s] = "gone"]
    /\ UNCHANGED <<queued, closed, dropped, sawClosed, rpc, spc>>

Receiver(s) == Look(s) \/ Park(s) \/ Recheck(s)

Next == \E s \in Sides :
    Push(s) \/ Notify(s) \/ Receiver(s) \/ Drop(s) \/ DropNotify(s)

Spec == Init /\ [][Next]_vars
    /\ \A s \in Sides : WF_vars(Receiver(s)) /\ WF_vars(Notify(s)) /\ WF_vars(DropNotify(s))

-----------------------------------------------------------------------------
TypeOK ==
    /\ \A s \in Sides : queued[s] \in 0..MaxQueued
    /\ \A s \in Sides : rpc[s] \in {"idle", "parking", "recheck", "waiting"}
    /\ \A s \in Sides : spc[s] \in {"ready", "pushed"}
    /\ \A s \in Sides : dpc[s] \in {"live", "closing", "gone"}

\* The flag is up only with a waker behind it.
FlagHasWaker == \A s \in Sides : parked[s] => waker[s]

\* A receiver asleep with something to read has a wake on its way: its
\* waker is parked and a send or a drop has yet to look at the flag.
WakeIsComing ==
    \A s \in Sides :
        rpc[s] = "waiting" /\ ~woken[s] /\ ~dropped[s] /\ (queued[s] > 0 \/ closed[s])
        => /\ parked[s]
           /\ (spc[Other(s)] = "pushed" \/ dpc[Other(s)] = "closing")

\* Closed comes only after every queued packet was read, and nothing is
\* queued after it.
ClosedAfterDrain == \A s \in Sides : sawClosed[s] => queued[s] = 0 /\ closed[s]

\* Nothing is queued for a dropped end, and a direction is closed exactly
\* when an end was dropped.
NoQueueForTheDropped == \A s \in Sides : dropped[s] => queued[s] = 0
ClosedMeansDropped == \A s \in Sides : closed[s] = (dropped[0] \/ dropped[1])

\* A receiver that returned Pending with something to read is woken.
WakeAfterPark ==
    \A s \in Sides :
        [](rpc[s] = "waiting" /\ (queued[s] > 0 \/ closed[s]) => <>(woken[s] \/ dropped[s]))

\* The end left behind learns the cable is closed.
LearnsClosed ==
    \A s \in Sides : [](closed[s] /\ ~dropped[s] => <>(sawClosed[s] \/ dropped[s]))
=============================================================================
