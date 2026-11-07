------------------------------- MODULE Cable -------------------------------
(* A cable from src/cable.rs: two ends, two directions. `End::poll_recv`
   takes a queued packet, reports Closed once the queue is empty and the
   direction closed, or registers the receiver's waker. `End::send` queues
   into the other direction unless it is closed or full, and wakes the
   receiver waiting there. `End::drop` closes both directions, drops what
   was queued for the dropped end, and wakes the receiver at the other end.
   Each of those runs under the direction's lock, so each is one step. *)
EXTENDS Naturals

CONSTANTS
    MaxQueued,     \* the queue's limit, in packets
    DropWakesPeer  \* End::drop takes and wakes the other end's waker (the
                   \* code); FALSE: it leaves it be

Sides == {0, 1}
Other(s) == 1 - s

VARIABLES
    queued,    \* queued[s]: packets waiting for end s: dirs[s].queue
    waiter,    \* waiter[s]: dirs[s].waker holds the receiver's waker
    closed,    \* closed[s]: dirs[s].closed
    dropped,   \* dropped[s]: end s was dropped
    woken,     \* woken[s]: the receiver at s was woken since it last polled
    sawClosed  \* sawClosed[s]: poll_recv at s gave Closed

vars == <<queued, waiter, closed, dropped, woken, sawClosed>>

Init ==
    /\ queued = [s \in Sides |-> 0]
    /\ waiter = [s \in Sides |-> FALSE]
    /\ closed = [s \in Sides |-> FALSE]
    /\ dropped = [s \in Sides |-> FALSE]
    /\ woken = [s \in Sides |-> FALSE]
    /\ sawClosed = [s \in Sides |-> FALSE]

\* A receiver polls when it is not parked, or was woken.
MayPoll(s) == ~waiter[s] \/ woken[s]

-----------------------------------------------------------------------------
\* End::send from s into dirs[Other(s)].
Send(s) ==
    /\ ~dropped[s]
    /\ LET t == Other(s) IN
       IF closed[t] \/ queued[t] = MaxQueued
       THEN UNCHANGED <<queued, waiter, woken>>
       ELSE /\ queued' = [queued EXCEPT ![t] = @ + 1]
            /\ woken' = [woken EXCEPT ![t] = @ \/ waiter[t]]
            /\ waiter' = [waiter EXCEPT ![t] = FALSE]
    /\ UNCHANGED <<closed, dropped, sawClosed>>

\* End::poll_recv at s.
Recv(s) ==
    /\ ~dropped[s] /\ MayPoll(s)
    /\ woken' = [woken EXCEPT ![s] = FALSE]
    /\ IF queued[s] > 0 THEN
          /\ queued' = [queued EXCEPT ![s] = @ - 1]
          /\ UNCHANGED <<waiter, sawClosed>>
       ELSE IF closed[s] THEN
          /\ sawClosed' = [sawClosed EXCEPT ![s] = TRUE]
          /\ UNCHANGED <<queued, waiter>>
       ELSE
          /\ waiter' = [waiter EXCEPT ![s] = TRUE]
          /\ UNCHANGED <<queued, sawClosed>>
    /\ UNCHANGED <<closed, dropped>>

\* End::drop at s.
Drop(s) ==
    /\ ~dropped[s]
    /\ LET t == Other(s) IN
       /\ dropped' = [dropped EXCEPT ![s] = TRUE]
       /\ closed' = [closed EXCEPT ![s] = TRUE, ![t] = TRUE]
       /\ queued' = [queued EXCEPT ![s] = 0]
       /\ waiter' = IF DropWakesPeer
                    THEN [waiter EXCEPT ![s] = FALSE, ![t] = FALSE]
                    ELSE [waiter EXCEPT ![s] = FALSE]
       /\ woken' = IF DropWakesPeer
                   THEN [woken EXCEPT ![t] = @ \/ waiter[t]]
                   ELSE woken
    /\ UNCHANGED sawClosed

Next == \E s \in Sides : Send(s) \/ Recv(s) \/ Drop(s)

Spec == Init /\ [][Next]_vars /\ \A s \in Sides : WF_vars(Recv(s))

-----------------------------------------------------------------------------
\* A parked receiver has nothing waiting: no packet, no close.
NothingForTheParked ==
    \A s \in Sides : waiter[s] /\ ~woken[s] => queued[s] = 0 /\ ~closed[s]

\* Closed comes only after every queued packet was read, and nothing is
\* queued after it.
ClosedAfterDrain == \A s \in Sides : sawClosed[s] => queued[s] = 0 /\ closed[s]

\* Nothing is queued for a dropped end, and a direction is closed exactly
\* when an end was dropped.
NoQueueForTheDropped == \A s \in Sides : dropped[s] => queued[s] = 0
ClosedMeansDropped == \A s \in Sides : closed[s] = (dropped[0] \/ dropped[1])

\* The end left behind learns the cable is closed.
LearnsClosed ==
    \A s \in Sides : [](closed[s] /\ ~dropped[s] => <>(sawClosed[s] \/ dropped[s]))
=============================================================================
