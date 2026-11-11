-------------------------- MODULE FinalSize --------------------------
EXTENDS Integers
CONSTANTS Limit, CheckHigh, HonorKnown
VARIABLES high, final
vars == <<high, final>>
RFC == INSTANCE RfcFinalSize

Init == high = 0 /\ final = -1

(* quinn-proto/src/connection/streams/recv.rs: valid_final_size guards
   Recv::ingest and Recv::reset. high projects the flow-accounted end:
   max(Recv::end, known final size), since StreamsState accounts for a
   reset's final size without changing Recv::end. A stopped stream's
   accepted FIN is its last transition before the caller forgets it. *)
Receive == \E end \in 0..Limit, fin \in BOOLEAN:
    /\ (~CheckHigh \/ ~fin \/ end >= high)
    /\ (~HonorKnown \/ final = -1 \/
            (end <= final /\ (~fin \/ end = final)))
    /\ high' = IF end > high THEN end ELSE high
    /\ final' = IF fin THEN end ELSE final

Spec == Init /\ [][Receive]_vars
Refines == RFC!Spec
WithinFinal == final = -1 \/ high <= final
NoFinal == final = -1
=====================================================================
