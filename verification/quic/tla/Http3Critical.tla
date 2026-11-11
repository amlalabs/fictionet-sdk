------------------------- MODULE Http3Critical -------------------------
EXTENDS Naturals, FiniteSets, Resources
CONSTANTS Unique, CloseCritical, ChargeFirst, CompleteBound
VARIABLES seen, accepted, closed, storage, allocated, flight, completed
vars == <<seen, accepted, closed, storage, allocated, flight, completed>>
Types == {"control", "encoder", "decoder"}
Init == /\ seen = {} /\ accepted = [t \in Types |-> 0]
        /\ closed = FALSE /\ storage = Store(0) /\ allocated = FALSE
        /\ flight \in 0..2 /\ completed = 0

(* Connection slots are reserved before allocation. The size is abstract;
   this is the admission order, not a bound on the allocating codecs. *)
Allocate == /\ ~allocated /\ ~closed
            /\ LET s == Begin(storage)
                   paid == IF ChargeFirst THEN Reserve(s, 1) ELSE s
               IN storage' = Grow(paid, 1)
            /\ allocated' = TRUE
            /\ UNCHANGED <<seen, accepted, closed, flight, completed>>
Open(t) == /\ allocated /\ ~closed /\ accepted[t] < 2
           /\ IF Unique /\ t \in seen
                 THEN /\ closed' = TRUE /\ UNCHANGED <<seen, accepted>>
                 ELSE /\ seen' = seen \cup {t}
                      /\ accepted' = [accepted EXCEPT ![t] = @ + 1]
                      /\ UNCHANGED closed
           /\ UNCHANGED <<storage, allocated, flight, completed>>
End(t) == /\ allocated /\ ~closed /\ t \in seen
          /\ closed' = CloseCritical
          /\ seen' = seen \ {t}
          /\ UNCHANGED <<accepted, storage, allocated, flight, completed>>
Complete(n) == /\ ~closed /\ n \in 1..3
               /\ (~CompleteBound \/ n <= flight)
               /\ flight' = flight - n /\ completed' = completed + n
               /\ UNCHANGED <<seen, accepted, closed, storage, allocated>>
Next == Allocate \/ (\E t \in Types : Open(t) \/ End(t)) \/ (\E n \in 1..3 : Complete(n))
Spec == Init /\ [][Next]_vars
OneOfEach == \A t \in Types : accepted[t] <= 1
CriticalOpen == ~closed => \A t \in Types : accepted[t] > 0 => t \in seen
PaidStorage == Paid(storage) /\ WithinLimit(storage, 1) /\ Tracks(storage, IF allocated THEN 1 ELSE 0)
CompletionOwned == flight >= 0
=======================================================================
