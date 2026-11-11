------------------------ MODULE RfcFinalSize ------------------------
EXTENDS Integers

(* RFC 9000 sections 4.5 and 20.1: stream accounting uses the greatest
   received end offset. FIN and RESET_STREAM declare the same immutable
   final size. A final size cannot be below data already accounted for.
   Data delivery, flow control limits and closed-stream forgetting are
   separate from this specification. Rejected inputs stutter. *)
CONSTANT Limit
VARIABLES high, final
vars == <<high, final>>
Init == high = 0 /\ final = -1

Data == \E end \in 0..Limit:
    /\ final = -1 \/ end <= final
    /\ high' = IF end > high THEN end ELSE high
    /\ UNCHANGED final

Declare == \E size \in high..Limit:
    /\ final = -1 \/ final = size
    /\ final' = size /\ high' = size

Spec == Init /\ [][Data \/ Declare]_vars
====================================================================
