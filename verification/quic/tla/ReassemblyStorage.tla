------------------------ MODULE ReassemblyStorage ------------------------
EXTENDS Integers, Resources

(* Descriptor growth retains the geometric allocation history. Compaction *)
(* reuses those descriptors and creates one backing while input is live.  *)
(* Application slices share that backing after the assembler is cleared. *)
CONSTANTS Limit, UnpaidDescriptors, UnpaidCopy, EarlyRelease
VARIABLES capacity, count, sourceLive, copied, refs, heap, source, copy
vars == <<capacity, count, sourceLive, copied, refs, heap, source, copy>>
Payload == 4
Owner == 1

Init == /\ capacity = 0 /\ count = 0
        /\ sourceLive = TRUE /\ copied = FALSE /\ refs = 0
        /\ heap = Store(0)
        /\ source = Grow(Store(Payload), Payload)
        /\ copy = Store(0)

GrowHeap ==
    /\ count = capacity /\ capacity < 4
    /\ LET next == IF capacity = 0 THEN 2 ELSE 2 * capacity
           paid == IF UnpaidDescriptors THEN Begin(heap)
                   ELSE Reserve(Begin(heap), next)
       IN /\ next + heap.reserved + source.reserved + copy.reserved <= Limit
          /\ heap' = Shrink(Grow(paid, next), capacity)
          /\ capacity' = next
    /\ UNCHANGED <<count, sourceLive, copied, refs, source, copy>>

Insert == /\ count < capacity /\ sourceLive /\ ~copied
          /\ count' = count + 1
          /\ heap' = Begin(heap)
          /\ UNCHANGED <<capacity, sourceLive, copied, refs, source, copy>>

Compact ==
    /\ count > 0 /\ sourceLive /\ ~copied
    /\ heap.reserved + source.reserved + Payload + Owner <= Limit
    /\ LET paid == IF UnpaidCopy THEN Begin(copy)
                   ELSE Reserve(Begin(copy), Payload + Owner)
       IN copy' = Grow(paid, Payload + Owner)
    /\ copied' = TRUE /\ refs' = 1 /\ count' = 1
    /\ heap' = Begin(heap)
    /\ UNCHANGED <<capacity, sourceLive, source>>

ReleaseSources ==
    /\ copied /\ sourceLive
    /\ sourceLive' = FALSE /\ source' = Shrink(Begin(source), Payload)
    /\ UNCHANGED <<capacity, count, copied, refs, heap, copy>>

Slice == /\ copied /\ refs = 1
         /\ refs' = 2 /\ copy' = Begin(copy)
         /\ UNCHANGED <<capacity, count, sourceLive, copied, heap, source>>

DropSlice ==
    /\ refs > 0 /\ refs' = refs - 1
    /\ copy' = IF refs = 1 THEN Shrink(Begin(copy), Payload + Owner)
               ELSE IF EarlyRelease THEN Release(Begin(copy), Payload + Owner)
               ELSE Begin(copy)
    /\ UNCHANGED <<capacity, count, sourceLive, copied, heap, source>>

Clear == /\ count > 0 /\ copied
         /\ count' = 0 /\ heap' = Begin(heap)
         /\ UNCHANGED <<capacity, sourceLive, copied, refs, source, copy>>

Close == /\ count = 0 /\ capacity > 0 /\ copied
         /\ capacity' = 0 /\ heap' = Shrink(Begin(heap), capacity)
         /\ UNCHANGED <<count, sourceLive, copied, refs, source, copy>>

Repay ==
    /\ (capacity = 0 /\ heap.reserved > 0)
       \/ (~sourceLive /\ source.reserved > 0)
       \/ (copied /\ refs = 0 /\ copy.reserved > 0)
    /\ heap' = IF capacity = 0 THEN Release(Begin(heap), heap.reserved) ELSE Begin(heap)
    /\ source' = IF ~sourceLive THEN Release(Begin(source), source.reserved) ELSE Begin(source)
    /\ copy' = IF refs = 0 THEN Release(Begin(copy), copy.reserved) ELSE Begin(copy)
    /\ UNCHANGED <<capacity, count, sourceLive, copied, refs>>

Next == GrowHeap \/ Insert \/ Compact \/ ReleaseSources \/ Slice \/ DropSlice
        \/ Clear \/ Close \/ Repay
Spec == Init /\ [][Next]_vars
TypeOK == /\ capacity \in {0, 2, 4} /\ count \in 0..capacity
          /\ sourceLive \in BOOLEAN /\ copied \in BOOLEAN /\ refs \in 0..2
StoragePaid == Paid(heap) /\ Paid(source) /\ Paid(copy)
StorageBounded == heap.reserved + source.reserved + copy.reserved <= Limit
StorageTracked == /\ Tracks(heap, capacity)
                  /\ Tracks(source, IF sourceLive THEN Payload ELSE 0)
                  /\ Tracks(copy, IF refs > 0 THEN Payload + Owner ELSE 0)
=============================================================================
