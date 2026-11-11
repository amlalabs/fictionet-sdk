---------------------------- MODULE Assembly ----------------------------
(***************************************************************************)
(* A unit kept from pieces in charged storage; one model unit stands for *)
(* some bytes. Deliver is each of the three ways a unit is kept:         *)
(*   - src/stdlib/protocols/http1.rs, RequestStream::push: HTTP/1 head   *)
(*     assembly, doubling what it holds (DoubleCapacity = FALSE), in new *)
(*     blocks from the pools or Chunk::block, each charged whole while   *)
(*     the old one is held (ChargeWhole), no floor, waiting for memory  *)
(*     when refused;                                                       *)
(*   - src/stdlib/protocols/http2.rs, HeaderBlocks::join: HTTP/2 header  *)
(*     blocks in ChargedSegments (src/stdlib/layer/charged.rs, extend),  *)
(*     keeping a first segment of Floor between blocks, waiting when     *)
(*     refused (Segmented);                                                *)
(*   - src/stdlib/web/httpd/http2/respond.rs, collect_into: the request  *)
(*     body Respond collects, in ChargedSegments, no floor; a refusal    *)
(*     ends the request (FailWhenRefused). A body whose content-length  *)
(*     is known takes one segment of exactly that length with its first *)
(*     piece (Known). One of unknown length in more than one segment is  *)
(*     copied once into a block of its length, charged first, when it  *)
(*     is handed on (JoinWhole, Body::from_segments).                    *)
(* Segmented storage never moves: a piece fills the room in the last     *)
(* segment, and the rest goes in one new segment, charged before it is  *)
(* allocated, of the rest or a share of what is held (held \div Share,   *)
(* within LeastSegment and MostSegment) if that is more, never past      *)
(* UnitLimit; when the budget has no room for that, as much of it as    *)
(* fits, down to the rest or LeastSegment.                                *)
(* Moving storage (Segmented = FALSE) is the HTTP/2 storage before:      *)
(* ChargedBytes, doubling the capacity (DoubleCapacity), each move       *)
(* charged whole beside the old allocation (ChargeWhole), and the        *)
(* largest block that fits when doubling does not (LargestWhenRefused). *)
(* Before 84530d0d5 a move charged only the growth (ChargeWhole = FALSE).*)
(* A piece the budget refuses and that waits is no step at all.          *)
(* Finish is decode and clear_to(floor), or handing a head or body on.   *)
(* OtherParts is the rest of the shared budget: another of the client's *)
(* connections, taking and freeing room between units, and within one   *)
(* too when BudgetMovesInUnit.                                            *)
(*                                                                         *)
(* Pool rounding, spare capacity in the first delivered chunk and the    *)
(* places of segments (a fixed size each, counted by the Kani harnesses *)
(* and the tests) are abstracted away: a first block has the delivery's  *)
(* size. A unit is at most UnitLimit, or exactly its known length, in    *)
(* pieces of the sizes in PieceSizes, and one of unknown length may end  *)
(* after any piece.                                                        *)
(***************************************************************************)
EXTENDS Naturals, Resources

CONSTANTS UnitLimit,          \* the unit's limit: the head, block or body limit
          PieceSizes,         \* the sizes a delivery or fragment piece takes
          BudgetLimit,        \* the budget the unit shares with OtherParts
          Floor,              \* storage kept between units (HeaderBlocks::keep)
          FailWhenRefused,    \* a refusal ends the unit (Respond) instead of waiting
          DoubleCapacity,     \* doubling the capacity (HTTP/2) or what is held (HTTP/1)
          BudgetMovesInUnit,  \* the rest of the budget changes while a unit is joined
          Double,             \* full storage is replaced by storage at least twice as large
          LargestWhenRefused, \* refused that, the largest block that fits, not one of exactly the need
          ChargeWhole,        \* a move charges the whole new block beside the old
          ChargeFirst,        \* storage is charged before it is allocated
          Segmented,          \* growth adds a segment and moves nothing
          Known,              \* the unit's length is known from its first piece
          JoinWhole,          \* a unit in more than one segment is copied whole when handed on
          Share,              \* a new segment is at least what is held divided by this
          LeastSegment,       \* the least segment, unless the rest or the limit needs less
          MostSegment,        \* the most a share makes a segment
          HeldShares,         \* HeldBound: Share * peak <= HeldShares * input + Share * HeldFixed
          HeldFixed

ASSUME /\ UnitLimit > 0 /\ BudgetLimit >= Floor
       /\ Floor \in 0..UnitLimit
       /\ PieceSizes # {} /\ PieceSizes \subseteq 1..UnitLimit
       /\ Share > 0 /\ LeastSegment > 0 /\ MostSegment >= LeastSegment
       /\ Known => (Floor = 0 /\ FailWhenRefused)

Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b
Clamp(x, lo, hi) == Min(Max(x, lo), hi)

\* Segmented storage moves nothing it holds, so the only copy is the join
\* of a unit handed on whole, once.
\* Doubling the capacity: the capacities moved out of before the last
\* move form a series in which each is at least twice the one before, so
\* they come to less than twice the last of them, and the delivery that
\* made that move brought the unit past it. The cap at UnitLimit only
\* stops the series: a block at the limit never moves again.
\* Doubling what is held (HTTP/1): if h is what a move copies, each h is
\* more than twice the h two moves before, so the copies come to less
\* than twice the last two; the unit is past both, and so less than three
\* times what was received.
\* A block the budget had no room to double is the largest that fits; it
\* moves at most once more, since a move needs room for a larger block
\* beside it, and that move copies less than the unit holds.
CopyPer == IF Segmented THEN 1 ELSE IF DoubleCapacity THEN 2 ELSE 3

\* The first block copies nothing that was held, and nor does a move out
\* of an empty floor: there is no fixed copying to add.
CopyFixed == 0

VARIABLES held,     \* the unit's bytes kept so far
          capacity, \* the storage that holds them: the block, or the segments
          segments, \* how many segments the storage is in
          length,   \* the unit's length: known, or its limit
          free,     \* the budget's room
          others,   \* what the rest of the budget holds
          store,    \* the assembly's storage (Resources.tla)
          received, \* the unit's bytes delivered
          copied,   \* bytes copied into fresh storage by moves and joins
          phase     \* joining, done, or failed
vars == <<held, capacity, segments, length, free, others, store, received, copied, phase>>

\* The unit's size, which what it holds is bounded by: the length it gave
\* when known, which is reserved whole, or what has arrived.
Input == IF Known THEN length ELSE received

FloorSegments == IF Floor > 0 THEN 1 ELSE 0

Init ==
    /\ held = 0 /\ capacity = Floor /\ segments = FloorSegments
    /\ length \in IF Known THEN 1..UnitLimit ELSE {UnitLimit}
    /\ others \in 0..(BudgetLimit - Floor)
    /\ free = BudgetLimit - Floor - others
    /\ store = Grow(Reserve(Store(0), Floor), Floor)
    /\ received = 0 /\ copied = 0 /\ phase = "joining"

\* What a move to `target` charges: the whole new block, or, as
\* ChargedBytes did before 84530d0d5, only its growth.
Extra(target) == IF ChargeWhole THEN target ELSE target - capacity

\* The largest block the budget has room for.
LargestFit == IF ChargeWhole THEN free ELSE capacity + free

\* The block a full one is replaced by, for `need` bytes.
Target(need) ==
    LET want == IF Double
                THEN Min(UnitLimit, Max(need, 2 *
                         (IF DoubleCapacity THEN capacity ELSE held)))
                ELSE need
    IN IF Extra(want) <= free THEN want
       ELSE IF LargestWhenRefused THEN LargestFit
       ELSE need

\* A move to `target`, threaded through the store in the code's order:
\* charge, allocate, (copy,) free the old block, give its charge back.
\* Without ChargeWhole the old block's charge became part of the new one,
\* and nothing is given back.
Move(target) ==
    LET start == Begin(store)
        made == IF ChargeFirst THEN Grow(Reserve(start, Extra(target)), target)
                ELSE Reserve(Grow(start, target), Extra(target))
        dropped == Shrink(made, capacity)
    IN Release(dropped, IF ChargeWhole THEN capacity ELSE 0)

\* The segment a piece whose `rest` does not fit in the room left wants,
\* and the least it takes (ChargedSegments::extend), or, for the first
\* piece of a unit of known length, exactly that length
\* (ChargedSegments::with_capacity).
Want(rest) ==
    IF Known /\ capacity = 0 THEN length
    ELSE Min(Max(rest, Clamp(held \div Share, LeastSegment, MostSegment)),
             UnitLimit - capacity)
Least(rest) ==
    IF Known /\ capacity = 0 THEN length
    ELSE Max(rest, Min(Want(rest), LeastSegment))

\* A failed unit: its storage and charge go.
Fail ==
    /\ store' = Release(Shrink(Begin(store), capacity), capacity)
    /\ free' = free + capacity /\ capacity' = 0 /\ held' = 0 /\ segments' = 0
    /\ phase' = "failed"
    /\ UNCHANGED <<copied, received, length>>

\* A piece of n bytes.
Deliver(n) ==
    /\ phase = "joining" /\ received + n <= length
    /\ LET need == held + n
           target == Target(need)
           rest == need - capacity
       IN IF need <= capacity
          THEN \* Kept in place.
               /\ held' = need /\ received' = received + n
               /\ store' = Begin(store)
               /\ UNCHANGED <<capacity, segments, free, copied, phase, length>>
          ELSE IF Segmented
          THEN IF Least(rest) <= free
               THEN \* One more segment, charged, then allocated; nothing moves.
                    LET segment == Min(Want(rest), free)
                    IN /\ store' = Grow(Reserve(Begin(store), segment), segment)
                       /\ capacity' = capacity + segment
                       /\ segments' = segments + 1
                       /\ held' = need /\ received' = received + n
                       /\ free' = free - segment
                       /\ UNCHANGED <<copied, phase, length>>
               ELSE /\ FailWhenRefused
                    /\ Fail
          ELSE IF need <= target /\ Extra(target) <= free
          THEN /\ store' = Move(target)
               /\ capacity' = target /\ held' = need
               /\ free' = free - Extra(target)
                           + (IF ChargeWhole THEN capacity ELSE 0)
               /\ copied' = copied + held
               /\ received' = received + n
               /\ UNCHANGED <<segments, phase, length>>
          ELSE \* Refused. A head or header block waits: no step. A body ends,
               \* and its storage and charge go.
               /\ FailWhenRefused
               /\ Fail
    /\ UNCHANGED others

\* The unit is whole: what it held past the floor goes. A unit handed on
\* whole from more than one segment is first copied into a block of its
\* length, charged before it is allocated; with no room for that it fails.
Finish ==
    /\ phase = "joining" /\ received > 0 /\ (Known => received = length)
    /\ IF JoinWhole /\ segments > 1
       THEN IF held <= free
            THEN LET joined == Grow(Reserve(Begin(store), held), held)
                     freed == Release(Shrink(joined, capacity), capacity)
                 IN /\ store' = Release(Shrink(freed, held), held)
                    /\ copied' = copied + held
                    /\ free' = free + capacity /\ capacity' = 0 /\ held' = 0
                    /\ segments' = 0 /\ phase' = "done"
                    /\ UNCHANGED <<others, received, length>>
            ELSE Fail /\ UNCHANGED others
       ELSE /\ store' = Release(Shrink(Begin(store), capacity - Floor), capacity - Floor)
            /\ free' = free + capacity - Floor /\ capacity' = Floor /\ held' = 0
            /\ segments' = FloorSegments /\ phase' = "done"
            /\ UNCHANGED <<others, received, copied, length>>

\* The next unit, of a length of its own when known.
Start ==
    /\ phase \in {"done", "failed"}
    /\ received' = 0 /\ copied' = 0 /\ phase' = "joining"
    /\ length' \in IF Known THEN 1..UnitLimit ELSE {UnitLimit}
    /\ store' = Begin(store)
    /\ UNCHANGED <<held, capacity, segments, free, others>>

OtherParts ==
    /\ BudgetMovesInUnit \/ phase # "joining"
    /\ others' \in 0..(BudgetLimit - store.reserved)
    /\ free' = BudgetLimit - store.reserved - others'
    /\ store' = Begin(store)
    /\ UNCHANGED <<held, capacity, segments, length, received, copied, phase>>

Next == (\E n \in PieceSizes : Deliver(n)) \/ Finish \/ Start \/ OtherParts
Spec == Init /\ [][Next]_vars

\* No moment held more than the assembly had reserved.
AssemblyPaid == Paid(store)
\* What it reserved, and the rest of the budget, stay within the limit.
AssemblyWithinLimit ==
    /\ WithinLimit(store, BudgetLimit - others)
    /\ free + others + store.reserved = BudgetLimit
\* The store holds the storage the state says.
AssemblyTracks == Tracks(store, capacity)
\* The copying is linear in what arrived.
LinearCopy == copied <= CopyPer * received + CopyFixed
\* No moment held more than HeldShares / Share times the unit's size and
\* a fixed term: what the budget must have for the unit. For segmented
\* storage, the unit's bytes, the room in its last segment (a share of
\* them, or the least segment) and the floor; for a known length, the
\* length; for a unit joined when handed on, its bytes once more.
HeldBound == Share * store.peak <= HeldShares * Input + Share * HeldFixed
=============================================================================
