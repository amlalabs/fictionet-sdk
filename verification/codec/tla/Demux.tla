------------------------------ MODULE Demux ------------------------------
\* The shared budget of fictionet::stdlib::codec::Demux (src/stdlib/codec/demux.rs).
\*
\* A Demux keeps one cached charge, `total`, for the input allocations and
\* decoder-held bytes of every live stream. Each owner operation first settles
\* the one stream that may have escaped through get_mut (Demux::total), then
\* does its work. This spec has one action per owner method and one for the
\* caller's direct change of an escaped stream.
\*
\*   Open(k, g), Push(k, g)   push_with_budget: a new key, an existing key
\*   End(k)                   end
\*   Remove(k)                remove
\*   GetMut(k), Mutate(k)     get_mut, and the caller's change to that stream
\*   Shrink                   shrink
\*   Visit                    one iteration of next's loop
\*
\* Streams are abstract: `alloc` is Stream::allocated, `held` is Decode::held,
\* `done` is Stream::is_done. What a decoder does on next is nondeterministic:
\* its held bytes move within MaxHeld and it may yield an item, an error, or
\* nothing. The constants ChargeOpenHeld, ChargeExcess and BlameGrower are
\* the rules the ablation configs switch off; BlameGrower off is the code
\* before the fix, which blamed whichever stream was settled while the total
\* was over budget.
EXTENDS Integers, FiniteSets
CONSTANTS Keys, MaxStreams, MaxBytes, MaxAlloc, MaxHeld, None,
          ChargeOpenHeld, ChargeExcess, BlameGrower
VARIABLES state,    \* key -> "absent" (no entry), "live" (a stream), "closed" (released)
          alloc,    \* key -> Stream::allocated of a live stream
          held,     \* key -> Decode::held of a live stream
          done,     \* key -> Stream::is_done
          pending,  \* key -> Entry::error holds a Refused behind a delivered item
          ready,    \* the ready set
          total,    \* the cached charge, Demux::total
          dirty,    \* None, or [key, before]: the stream that escaped through get_mut
          excess    \* None, or the key charged with an excess
vars == <<state, alloc, held, done, pending, ready, total, dirty, excess>>

Bytes(k) == alloc[k] + held[k]
Entries == {k \in Keys : state[k] # "absent"}
Live == {k \in Keys : state[k] = "live"}
RECURSIVE SumOf(_, _)
SumOf(f, S) == IF S = {} THEN 0
               ELSE LET k == CHOOSE k \in S : TRUE IN f[k] + SumOf(f, S \ {k})
Charge == SumOf([k \in Keys |-> Bytes(k)], Live)
Max0(n) == IF n < 0 THEN 0 ELSE n
Min(a, b) == IF a < b THEN a ELSE b

\* Demux::total: the escaped stream's delta is applied once. An excess is
\* charged to that key when it grew (BlameGrower); the budget may already be
\* exceeded by a stream charged earlier.
Escaped == dirty # None /\ state[dirty.key] = "live"
Settled == IF Escaped THEN total - dirty.before + Bytes(dirty.key) ELSE total
Grew == Bytes(dirty.key) > dirty.before
SettledExcess == IF Escaped /\ Settled > MaxBytes /\ ChargeExcess /\ (Grew \/ ~BlameGrower)
                 THEN dirty.key ELSE excess

Init == /\ state = [k \in Keys |-> "absent"]
        /\ alloc = [k \in Keys |-> 0] /\ held = [k \in Keys |-> 0]
        /\ done = [k \in Keys |-> FALSE] /\ pending = [k \in Keys |-> FALSE]
        /\ ready = {} /\ total = 0 /\ dirty = None /\ excess = None

Unopened == UNCHANGED <<state, alloc, held, done, pending, ready>>

\* push_with_budget on a key without an entry: the factory's decoder is
\* charged before the stream opens, then input is accepted under the room left.
Open(k, growth) ==
    /\ state[k] = "absent"
    /\ dirty' = None /\ excess' = SettledExcess
    /\ LET t == Settled
           limit == Min(MaxBytes, t + growth)
       IN IF Cardinality(Entries) >= MaxStreams THEN total' = t /\ Unopened
          ELSE \E h \in 0..MaxHeld :
            IF ChargeOpenHeld /\ h > Max0(limit - t) THEN total' = t /\ Unopened
            ELSE LET t2 == t + h
                     room == Max0(limit - t2)
                 IN \E a \in 0..Min(room, MaxAlloc) :
                    /\ state' = [state EXCEPT ![k] = "live"]
                    /\ held' = [held EXCEPT ![k] = h]
                    /\ alloc' = [alloc EXCEPT ![k] = a]
                    /\ done' = [done EXCEPT ![k] = FALSE]
                    /\ pending' = [pending EXCEPT ![k] = FALSE]
                    /\ total' = t2 + a
                    /\ ready' = ready \cup {k}

\* push_with_budget on an existing key. A closed key and a done stream take
\* and drop the bytes. Otherwise the allocation grows by at most the room.
Push(k, growth) ==
    /\ state[k] # "absent"
    /\ dirty' = None /\ excess' = SettledExcess
    /\ LET t == Settled
           room == Max0(Min(MaxBytes, t + growth) - t)
       IN IF state[k] = "closed" \/ done[k] THEN total' = t /\ Unopened
          ELSE \E a \in alloc[k]..Min(alloc[k] + room, MaxAlloc), accepted \in BOOLEAN :
            /\ alloc' = [alloc EXCEPT ![k] = a]
            /\ total' = t - alloc[k] + a
            /\ ready' = IF accepted THEN ready \cup {k} ELSE ready
            /\ UNCHANGED <<state, held, done, pending>>

End(k) ==
    /\ state[k] # "absent"
    /\ dirty' = None /\ excess' = SettledExcess /\ total' = Settled
    /\ ready' = IF state[k] = "live" /\ ~done[k] THEN ready \cup {k} ELSE ready
    /\ UNCHANGED <<state, alloc, held, done, pending>>

Remove(k) ==
    /\ state[k] # "absent"
    /\ LET t == Settled
           ex == SettledExcess
       IN /\ dirty' = None
          /\ excess' = IF ex = k THEN None ELSE ex
          /\ total' = IF state[k] = "live" THEN t - Bytes(k) ELSE t
    /\ ready' = ready \ {k}
    /\ state' = [state EXCEPT ![k] = "absent"]
    /\ alloc' = [alloc EXCEPT ![k] = 0] /\ held' = [held EXCEPT ![k] = 0]
    /\ done' = [done EXCEPT ![k] = FALSE] /\ pending' = [pending EXCEPT ![k] = FALSE]

GetMut(k) ==
    /\ state[k] = "live"
    /\ total' = Settled /\ excess' = SettledExcess
    /\ dirty' = [key |-> k, before |-> Bytes(k)]
    /\ ready' = ready \cup {k}
    /\ UNCHANGED <<state, alloc, held, done, pending>>

\* The caller changes the escaped stream: pushes, shrinks, or a mode change
\* that moves decoder state. The contract asks the caller to keep the budget;
\* the owner recovers from one excess, so one unsettled excess is allowed.
Mutate(k) ==
    /\ dirty # None /\ dirty.key = k /\ state[k] = "live"
    /\ \E h \in 0..MaxHeld, a \in 0..MaxAlloc :
        /\ excess = None \/ total - dirty.before + a + h <= MaxBytes
        /\ held' = [held EXCEPT ![k] = h]
        /\ alloc' = [alloc EXCEPT ![k] = a]
    /\ UNCHANGED <<state, done, pending, ready, total, dirty, excess>>

\* shrink: every live stream's allocation may fall; the charge is recounted.
Shrink ==
    /\ dirty' = None /\ excess' = SettledExcess
    /\ \E a \in [Live -> 0..MaxAlloc] :
        /\ \A k \in Live : a[k] <= alloc[k]
        /\ alloc' = [k \in Keys |-> IF k \in Live THEN a[k] ELSE alloc[k]]
        /\ total' = SumOf([k \in Keys |-> alloc'[k] + held[k]], Live)
    /\ UNCHANGED <<state, held, done, pending, ready>>

\* Releasing a stream: its charge leaves the total and its key closes.
Release(k, t, item) ==
    /\ state' = [state EXCEPT ![k] = "closed"]
    /\ total' = t - Bytes(k)
    /\ alloc' = [alloc EXCEPT ![k] = 0] /\ held' = [held EXCEPT ![k] = 0]
    /\ done' = [done EXCEPT ![k] = FALSE]
    /\ pending' = [pending EXCEPT ![k] = (item = "ok")]
    /\ ready' = IF item = "ok" THEN ready ELSE ready \ {k}

\* One iteration of next's loop. An excess key is visited first and, over
\* budget, released without decoding. A closed key delivers its pending error
\* and leaves the ready set. A live stream decodes: its held bytes move and it
\* yields an item, an error, or nothing; if the charge then exceeds the budget
\* the stream is released, its item still delivered.
Visit ==
    /\ dirty' = None
    /\ LET t == Settled
           ex == SettledExcess
       IN IF ex # None /\ t > MaxBytes
          THEN excess' = None /\ Release(ex, t, "none")
          ELSE /\ excess' = None
               /\ IF ready = {} THEN total' = t /\ Unopened
                  ELSE \E k \in ready :
                    IF state[k] = "closed"
                    THEN /\ ready' = ready \ {k}
                         /\ pending' = [pending EXCEPT ![k] = FALSE]
                         /\ total' = t
                         /\ UNCHANGED <<state, alloc, held, done>>
                    ELSE IF t > MaxBytes THEN Release(k, t, "none")
                    ELSE \E h \in 0..MaxHeld, item \in {"ok", "err", "none"}, d \in BOOLEAN :
                      /\ item = "err" => d
                      /\ done[k] => (item = "none" /\ h = held[k] /\ d)
                      /\ LET t2 == t - Bytes(k) + alloc[k] + h
                         IN IF t2 > MaxBytes
                            THEN /\ state' = [state EXCEPT ![k] = "closed"]
                                 /\ total' = t - Bytes(k)
                                 /\ alloc' = [alloc EXCEPT ![k] = 0]
                                 /\ held' = [held EXCEPT ![k] = 0]
                                 /\ done' = [done EXCEPT ![k] = FALSE]
                                 /\ pending' = [pending EXCEPT ![k] = (item = "ok")]
                                 /\ ready' = IF item = "ok" THEN ready ELSE ready \ {k}
                            ELSE /\ total' = t2
                                 /\ held' = [held EXCEPT ![k] = h]
                                 /\ done' = [done EXCEPT ![k] = d]
                                 /\ ready' = IF item = "none" \/ d THEN ready \ {k} ELSE ready
                                 /\ UNCHANGED <<state, alloc, pending>>

Growth == 0..MaxBytes
Next == \/ \E k \in Keys, g \in Growth : Open(k, g) \/ Push(k, g)
        \/ \E k \in Keys : End(k) \/ Remove(k) \/ GetMut(k) \/ Mutate(k)
        \/ Shrink
        \/ Visit
Spec == Init /\ [][Next]_vars

\* The cached charge is the sum over live streams whenever no stream is out
\* on loan through get_mut.
Charged == dirty = None => total = Charge
\* With nothing on loan and no excess pending, the charge is within budget.
BudgetKept == dirty = None /\ excess = None => total <= MaxBytes
\* An excess always names a live stream, so it can be released.
ExcessLive == excess # None => state[excess] = "live"
\* An error waiting behind a delivered item will be visited.
PendingVisited == \A k \in Keys : pending[k] => k \in ready /\ state[k] = "closed"
\* Ready keys have entries, and entries never exceed the stream limit.
ReadyHasEntry == ready \subseteq Entries /\ Cardinality(Entries) <= MaxStreams
\* The first visit after an excess releases that stream and no other.
ExcessReleasedFirst ==
    [][Visit /\ SettledExcess # None /\ Settled > MaxBytes
       => /\ state'[SettledExcess] = "closed"
          /\ \A k \in Keys \ {SettledExcess} : state'[k] = state[k]]_vars
=============================================================================
