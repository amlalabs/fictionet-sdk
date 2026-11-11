---------------------------- MODULE Listener ----------------------------
EXTENDS Naturals, FiniteSets, Resources
CONSTANTS BoundAdmission, ForgetRoute, RetainFlight, ChargeFirst
VARIABLES live, used, handles, routed, endpoint, flight, storage
vars == <<live, used, handles, routed, endpoint, flight, storage>>
Sessions == 1..3
Handles == 1..2
Init == /\ live = {} /\ used = {} /\ routed = {}
        /\ handles = [s \in Sessions |-> 0]
        /\ endpoint = [h \in Handles |-> 0]
        /\ flight = 0 /\ storage = Store(0)

(* Each session is a unique child generation, not an engine slab index.
   Two adapter slots remain occupied through draining and local sends. *)
Accept(s, h) ==
    /\ s \notin used /\ endpoint[h] = 0
    /\ (~BoundAdmission \/ Cardinality(live) < 2)
    /\ LET b == Begin(storage)
           paid == IF ChargeFirst THEN ReserveTo(b, b.held + 1) ELSE b
       IN storage' = Grow(paid, 1)
    /\ live' = live \cup {s} /\ used' = used \cup {s}
    /\ handles' = [handles EXCEPT ![s] = h]
    /\ routed' = routed \cup {s}
    /\ endpoint' = [endpoint EXCEPT ![h] = s]
    /\ UNCHANGED flight

(* The engine can recycle its handle before the application consumes its
   end event. Disable adapter routing before handing Drained to Endpoint. *)
Drain(s) ==
    /\ s \in routed /\ endpoint[handles[s]] = s
    /\ endpoint' = [endpoint EXCEPT ![handles[s]] = 0]
    /\ routed' = IF ForgetRoute THEN routed \ {s} ELSE routed
    /\ UNCHANGED <<live, used, handles, flight, storage>>

Send(s) == /\ s \in live /\ flight = 0 /\ flight' = s
           /\ UNCHANGED <<live, used, handles, routed, endpoint, storage>>
Complete == /\ flight # 0 /\ flight' = 0
            /\ UNCHANGED <<live, used, handles, routed, endpoint, storage>>
Retire(s) ==
    /\ s \in live /\ endpoint[handles[s]] # s
    /\ (~RetainFlight \/ flight # s)
    /\ live' = live \ {s} /\ routed' = routed \ {s}
    /\ storage' = Shrink(Begin(storage), 1)
    /\ UNCHANGED <<used, handles, endpoint, flight>>
ReleaseStorage == /\ storage.reserved > storage.held
                  /\ storage' = Release(Begin(storage), storage.reserved - storage.held)
                  /\ UNCHANGED <<live, used, handles, routed, endpoint, flight>>
Quiescent == /\ used = Sessions /\ live = {} /\ flight = 0
             /\ storage.reserved = 0 /\ UNCHANGED vars
Next == (\E s \in Sessions, h \in Handles : Accept(s, h))
        \/ (\E s \in Sessions : Drain(s) \/ Send(s) \/ Retire(s))
        \/ Complete \/ ReleaseStorage \/ Quiescent
Spec == Init /\ [][Next]_vars
Bounded == Cardinality(live) <= 2
RoutesCurrent == \A s \in routed : endpoint[handles[s]] = s
CompletionOwned == flight # 0 => flight \in live
PaidStorage == Paid(storage) /\ Tracks(storage, Cardinality(live))
WithinBudget == WithinLimit(storage, 2)
=======================================================================
