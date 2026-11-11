------------------------------ MODULE QpackTable ------------------------------
EXTENDS Naturals, Sequences, Resources

(* One unit is an entry slot or a payload unit. The table's wire capacity
   is five units, with one overhead unit per entry. Slots grow 0, 2, 4, 8.
   A replacement keeps the old and new arrays simultaneously. Eviction
   frees payloads but retains slots. This abstracts Table::insert and
   Table::evict_to; QpackSync checks when eviction is permitted. *)
CONSTANTS ChargeGrowth, ChargePayload, KeepSlotCharge, EvictFirst
VARIABLES entries, slots, store
vars == <<entries, slots, store>>
RECURSIVE Payload(_)
Payload(q) == IF Len(q) = 0 THEN 0 ELSE Head(q) + Payload(Tail(q))
WireSize(q) == Payload(q) + Len(q)
Init == /\ entries = <<>> /\ slots = 0 /\ store = Store(0)

Insert(n) ==
    /\ n \in 0..2 /\ Len(entries) < 6
    /\ (~EvictFirst \/ WireSize(entries) + n + 1 <= 5)
    /\ LET next == IF Len(entries) < slots THEN slots
                   ELSE IF slots = 0 THEN 2 ELSE 2 * slots
           old == Begin(store)
           paidSlots == IF ChargeGrowth THEN Reserve(old, next) ELSE old
           grown == IF next = slots THEN old
                    ELSE Release(Shrink(Grow(paidSlots, next), slots), slots)
           paidPayload == IF ChargePayload THEN Reserve(grown, n) ELSE grown
       IN /\ slots' = next
          /\ store' = Grow(paidPayload, n)
    /\ entries' = Append(entries, n)

Evict ==
    /\ Len(entries) > 0
    /\ LET freed == Head(entries)
           emptied == Release(Shrink(Begin(store), freed), freed)
       IN store' = IF KeepSlotCharge THEN emptied ELSE Release(emptied, slots)
    /\ entries' = Tail(entries)
    /\ UNCHANGED slots

Next == (\E n \in 0..2 : Insert(n)) \/ Evict
Spec == Init /\ [][Next]_vars
TablePaid == Paid(store)
TableTracked == Tracks(store, slots + Payload(entries))
WireBound == WireSize(entries) <= 5
SlotBound == slots <= 8
TableBound == WithinLimit(store, 5 + 3 * 8) /\ store.peak <= 5 + 3 * 8
=============================================================================
