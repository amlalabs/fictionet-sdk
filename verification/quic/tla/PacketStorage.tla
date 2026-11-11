--------------------------- MODULE PacketStorage ---------------------------
EXTENDS Integers, FiniteSets, Resources

(* One datagram backing with at most three mutable packet views. Freezing a *)
(* view allocates its Bytes owner; subsequent frame slices share that owner. *)
(* Backing includes payload and shared metadata in abstract storage units.  *)
CONSTANTS Backing, Owner, Limit, UnpaidCopy, UnpaidSplit, EarlyRelease
VARIABLES started, refs, frozen, store
vars == <<started, refs, frozen, store>>
Views == 0..2
Live == {i \in Views: refs[i] > 0}
Owners == Live \cap frozen
Needed == (IF Live = {} THEN 0 ELSE Backing) + Owner * Cardinality(Live)
Held == (IF Live = {} THEN 0 ELSE Backing) + Owner * Cardinality(Owners)

Init == /\ started = FALSE
        /\ refs = [i \in Views |-> 0]
        /\ frozen = {}
        /\ store = Store(0)

Copy == /\ ~started
        /\ Backing + Owner <= Limit
        /\ started' = TRUE
        /\ refs' = [refs EXCEPT ![0] = 1]
        /\ store' = Grow(IF UnpaidCopy THEN Begin(store)
                         ELSE Reserve(Begin(store), Backing + Owner), Backing)
        /\ UNCHANGED frozen

Split(i, j) == /\ i \in Live \ frozen /\ j \notin Live
               /\ store.reserved + Owner <= Limit
               /\ refs' = [refs EXCEPT ![j] = 1]
               /\ frozen' = frozen \ {j}
               /\ store' = IF UnpaidSplit THEN Begin(store)
                            ELSE Reserve(Begin(store), Owner)
               /\ UNCHANGED started

Freeze(i) == /\ i \in Live \ frozen
             /\ frozen' = frozen \cup {i}
             /\ store' = Grow(Begin(store), Owner)
             /\ UNCHANGED <<started, refs>>

Slice(i) == /\ i \in Owners /\ refs[i] < 2
            /\ refs' = [refs EXCEPT ![i] = @ + 1]
            /\ store' = Begin(store)
            /\ UNCHANGED <<started, frozen>>

Drop(i) == /\ i \in Live
           /\ refs' = [refs EXCEPT ![i] = @ - 1]
           /\ LET freedOwner == IF refs[i] = 1 /\ i \in frozen THEN Owner ELSE 0
                  freedBacking == IF Live = {i} /\ refs[i] = 1 THEN Backing ELSE 0
              IN store' = IF EarlyRelease /\ refs[i] > 1
                           THEN Release(Begin(store), Backing)
                           ELSE Shrink(Begin(store), freedOwner + freedBacking)
           /\ UNCHANGED <<started, frozen>>

Repay == /\ store.reserved > Needed
         /\ store' = Release(Begin(store), store.reserved - Needed)
         /\ UNCHANGED <<started, refs, frozen>>

Next == Copy \/ Repay \/ (\E i \in Views: Freeze(i) \/ Slice(i) \/ Drop(i))
        \/ (\E i, j \in Views: Split(i, j))
Spec == Init /\ [][Next]_vars
TypeOK == /\ started \in BOOLEAN /\ refs \in [Views -> 0..2]
          /\ frozen \subseteq Views
StoragePaid == Paid(store)
StorageBounded == WithinLimit(store, Limit)
StorageTracked == Tracks(store, Held)
SplitReserved == store.reserved >= Needed
=============================================================================
