-------------------------- MODULE SendDescriptors --------------------------
EXTENDS Integers, Resources

(* One unit is a send descriptor. Payload owners and range trees are not  *)
(* represented. Capacity grows geometrically; old and new storage coexist *)
(* during replacement. ACKs free entries but retain capacity for reuse.   *)
CONSTANTS Limit, MaxCapacity, ReserveGrowth, ReleaseOnAck
VARIABLES capacity, entries, store, closed
vars == <<capacity, entries, store, closed>>

Init == /\ capacity = 0 /\ entries = 0
        /\ store = Store(0) /\ closed = FALSE

Write == /\ ~closed
         /\ IF entries < capacity
               THEN /\ entries' = entries + 1
                    /\ store' = Begin(store)
                    /\ UNCHANGED capacity
               ELSE LET next == IF capacity = 0 THEN 4 ELSE 2 * capacity
                        admitted == ~ReserveGrowth \/ store.reserved + next <= Limit
                    IN /\ next <= MaxCapacity
                       /\ admitted
                       /\ store' = Shrink(Grow(
                            IF ReserveGrowth THEN Reserve(Begin(store), next)
                                             ELSE Begin(store), next), capacity)
                       /\ capacity' = next
                       /\ entries' = entries + 1
         /\ UNCHANGED closed

Ack == /\ ~closed /\ entries > 0
       /\ entries' \in 0..(entries - 1)
       /\ store' = IF ReleaseOnAck THEN Release(Begin(store), store.reserved)
                                  ELSE Begin(store)
       /\ UNCHANGED <<capacity, closed>>

Discard == /\ ~closed
           /\ closed' = TRUE /\ entries' = 0 /\ capacity' = 0
           /\ store' = Shrink(Begin(store), capacity)

Repay == /\ closed /\ store.reserved > 0
         /\ store' = Release(Begin(store), store.reserved)
         /\ UNCHANGED <<capacity, entries, closed>>

Next == Write \/ Ack \/ Discard \/ Repay
Spec == Init /\ [][Next]_vars
TypeOK == /\ capacity \in {0, 4, 8}
          /\ entries \in 0..capacity /\ closed \in BOOLEAN
          /\ closed => capacity = 0
DescriptorsPaid == Paid(store)
DescriptorsBounded == WithinLimit(store, Limit)
DescriptorsTracked == Tracks(store, capacity)
=============================================================================
