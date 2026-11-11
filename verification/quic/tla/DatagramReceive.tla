-------------------------- MODULE DatagramReceive --------------------------
EXTENDS Integers, Sequences

(* DatagramState::received separates the advertised wire limit from local *)
(* storage. The frame parser supplies the actual encoded size. This model *)
(* checks protocol admission and eviction, not heap allocation costs.     *)
CONSTANTS WireLimit, Window, Metadata, ConfuseStorage, IgnoreEncoding
VARIABLES queue, closed, lastWire, lastPayload
vars == <<queue, closed, lastWire, lastPayload>>

RECURSIVE Held(_)
Held(q) == IF q = <<>> THEN 0 ELSE Head(q) + Metadata + Held(Tail(q))
RECURSIVE Evict(_, _)
Evict(q, n) == IF Held(q) + n <= Window THEN q ELSE Evict(Tail(q), n)

Init == /\ queue = <<>> /\ closed = FALSE
        /\ lastWire = 0 /\ lastPayload = 0

Receive(payload, header) ==
    /\ ~closed
    /\ lastWire' = payload + header
    /\ lastPayload' = payload
    /\ LET invalid == IF ConfuseStorage
                       THEN payload + Metadata > Window
                       ELSE IF IgnoreEncoding
                            THEN payload > WireLimit
                            ELSE payload + header > WireLimit
       IN /\ closed' = invalid
          /\ queue' = IF invalid \/ payload + Metadata > Window THEN queue
                      ELSE Append(Evict(queue, payload + Metadata), payload)

Read == /\ queue # <<>>
        /\ queue' = Tail(queue)
        /\ UNCHANGED <<closed, lastWire, lastPayload>>
Next == (\E payload \in 0..(WireLimit + 1), header \in 1..3:
          Receive(payload, header)) \/ Read
Spec == Init /\ [][Next]_vars

WireAdmission == closed = (lastWire > WireLimit)
WithinWindow == Held(queue) <= Window
NoDelivery == queue = <<>>
=============================================================================
