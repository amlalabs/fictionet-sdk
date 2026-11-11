-------------------------- MODULE ReceiveAdmission --------------------------
EXTENDS Integers, FiniteSets, Resources

(* Two protected packets, each with two reliable frames. Authentication *)
(* precedes frame processing, and a storage refusal closes the connection. *)
(* Close output can include previously queued ACKs just like normal output. *)
CONSTANT AckOnAuthentication
VARIABLES stage, stored, processed, pending, sent, closed, storage
vars == <<stage, stored, processed, pending, sent, closed, storage>>
Packets == 0..1
Frames == Packets \X (0..1)
Limit == 3

Init == /\ stage = [p \in Packets |-> "wire"]
        /\ stored = {} /\ processed = {} /\ pending = {} /\ sent = {}
        /\ closed = FALSE /\ storage = Store(0)

Authenticate(p) ==
    /\ ~closed /\ stage[p] = "wire"
    /\ stage' = [stage EXCEPT ![p] = "first"]
    /\ pending' = IF AckOnAuthentication THEN pending \cup {p} ELSE pending
    /\ UNCHANGED <<stored, processed, sent, closed, storage>>

Frame(p, f) ==
    /\ ~closed /\ stage[p] = (IF f = 0 THEN "first" ELSE "last")
    /\ Cardinality(stored) < Limit
    /\ stored' = stored \cup {<<p, f>>}
    /\ storage' = Grow(Reserve(Begin(storage), 1), 1)
    /\ stage' = [stage EXCEPT ![p] = IF f = 0 THEN "last" ELSE "done"]
    /\ processed' = IF f = 1 THEN processed \cup {p} ELSE processed
    /\ pending' = IF f = 1 THEN pending \cup {p} ELSE pending
    /\ UNCHANGED <<sent, closed>>

Refuse(p) ==
    /\ ~closed /\ stage[p] \in {"first", "last"}
    /\ Cardinality(stored) = Limit
    /\ stage' = [stage EXCEPT ![p] = "rejected"] /\ closed' = TRUE
    /\ UNCHANGED <<stored, processed, pending, sent, storage>>

Malformed(p) ==
    /\ ~closed /\ stage[p] \in {"first", "last"}
    /\ stage' = [stage EXCEPT ![p] = "rejected"] /\ closed' = TRUE
    /\ UNCHANGED <<stored, processed, pending, sent, storage>>

Transmit == /\ pending # {}
            /\ sent' = sent \cup pending /\ pending' = {}
            /\ UNCHANGED <<stage, stored, processed, closed, storage>>

Next == Transmit \/ (\E p \in Packets: Authenticate(p) \/ Refuse(p) \/ Malformed(p))
        \/ (\E p \in Packets, f \in 0..1: Frame(p, f))
Spec == Init /\ [][Next]_vars
TypeOK == /\ stage \in [Packets -> {"wire", "first", "last", "done", "rejected"}]
          /\ stored \subseteq Frames /\ processed \subseteq Packets
          /\ pending \subseteq Packets /\ sent \subseteq Packets /\ closed \in BOOLEAN
AckAfterProcessing == (pending \cup sent) \subseteq processed
ReliableFramesRetained == \A p \in processed: {<<p, 0>>, <<p, 1>>} \subseteq stored
StoragePaid == Paid(storage) /\ WithinLimit(storage, Limit)
StorageTracked == Tracks(storage, Cardinality(stored))
NoCompletedPacket == sent = {}
=============================================================================
