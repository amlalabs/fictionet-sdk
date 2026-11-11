---------------------------- MODULE SendBacking ----------------------------
EXTENDS Integers, Resources

(***************************************************************************)
(* One already-paid application backing, split by ChunkSource::pop_chunk,  *)
(* retained by SendBuffer, and released after its last view disappears.    *)
(* A unit is one payload byte. Queue and range metadata are outside this   *)
(* model. Freeing and releasing payment are separate internal steps so the *)
(* peak before a free is still checked against its reservation.            *)
(***************************************************************************)
CONSTANTS Size, Capacities, CopyOnTake, EarlyRelease
VARIABLES source, admitted, acknowledged, freed, store, capacity
vars == <<source, admitted, acknowledged, freed, store, capacity>>

Init == /\ capacity \in Capacities
        /\ capacity >= Size
        /\ source = Size
        /\ admitted = 0
        /\ acknowledged = 0
        /\ freed = FALSE
        /\ store = Grow(Reserve(Store(0), capacity), capacity)

Take(n) == /\ n \in 1..source
           /\ source' = source - n
           /\ admitted' = admitted + n
           /\ store' = IF CopyOnTake
                        THEN Shrink(Grow(Begin(store), n), n)
                        ELSE Begin(store)
           /\ UNCHANGED <<acknowledged, freed>>

Ack(n) == /\ n \in (acknowledged + 1)..admitted
          /\ acknowledged' = n
          /\ store' = IF EarlyRelease /\ n < admitted
                       THEN Release(Begin(store), capacity)
                       ELSE Begin(store)
          /\ UNCHANGED <<source, admitted, freed>>

Reset == /\ acknowledged < admitted
         /\ acknowledged' = admitted
         /\ store' = Begin(store)
         /\ UNCHANGED <<source, admitted, freed>>

DropSource == /\ source > 0
              /\ source' = 0
              /\ store' = Begin(store)
              /\ UNCHANGED <<admitted, acknowledged, freed>>

Free == /\ source = 0 /\ acknowledged = admitted /\ ~freed
        /\ freed' = TRUE
        /\ store' = Shrink(Begin(store), capacity)
        /\ UNCHANGED <<source, admitted, acknowledged>>

Repay == /\ freed /\ store.reserved > 0
         /\ store' = Release(Begin(store), store.reserved)
         /\ UNCHANGED <<source, admitted, acknowledged, freed>>

Next == /\ ((\E n \in 1..Size: Take(n) \/ Ack(n)) \/ Reset \/ DropSource \/ Free \/ Repay)
        /\ UNCHANGED capacity
Spec == Init /\ [][Next]_vars
TypeOK == /\ source \in 0..Size
          /\ admitted \in 0..Size
          /\ acknowledged \in 0..admitted
          /\ freed \in BOOLEAN
          /\ source + admitted <= Size
          /\ freed => (source = 0 /\ acknowledged = admitted)
BackingPaid == Paid(store)
BackingBounded == WithinLimit(store, capacity)
BackingTracked == Tracks(store, IF freed THEN 0 ELSE capacity)
=============================================================================
