---------------------------- MODULE Assembly ----------------------------
(***************************************************************************)
(* A unit joined from pieces into charged storage; one model unit stands *)
(* for some bytes. Deliver is each of the three joins:                  *)
(*   - src/stdlib/protocols/http1.rs, RequestStream::push: HTTP/1 head   *)
(*     assembly, doubling what it holds (DoubleCapacity = FALSE), in new *)
(*     blocks from the pools or Chunk::block, each charged whole while   *)
(*     the old one is held (ChargeWhole), no floor, waiting for memory  *)
(*     when refused;                                                       *)
(*   - src/stdlib/protocols/http2.rs, HeaderBlocks::join and             *)
(*     assembly_capacity: HTTP/2 header blocks in ChargedBytes, doubling *)
(*     the capacity, keeping a floor between blocks, waiting when        *)
(*     refused;                                                            *)
(*   - src/stdlib/web/httpd/http2/respond.rs, collect_into: the request  *)
(*     body Respond collects in ChargedBytes, doubling the capacity, no  *)
(*     floor; a refusal ends the request (FailWhenRefused).               *)
(* When the budget has no room for the doubled block, each takes the    *)
(* largest it has room for, if that holds what is needed                 *)
(* (LargestWhenRefused). ChargedBytes (src/stdlib/layer/charged.rs,     *)
(* grow_to and grow_within) charges the growth and the old allocation    *)
(* together, reallocates, then gives the old one's charge back           *)
(* (ChargeWhole). Before 84530d0d5 it charged only the growth, so the   *)
(* old and the new were both held with only the new charged             *)
(* (ChargeWhole = FALSE, the _without_chargewhole controls).             *)
(* A piece the budget refuses and that waits is no step at all.          *)
(* Finish is decode and clear_to(floor), or handing a head or body on.   *)
(* OtherParts is the rest of the shared budget: another of the client's *)
(* connections, taking and freeing room between units, and within one   *)
(* too when BudgetMovesInUnit.                                            *)
(*                                                                         *)
(* Pool rounding and spare capacity in the first delivered chunk are     *)
(* abstracted away: a first block has the delivery's size. A unit is at  *)
(* most UnitLimit, in pieces of the sizes in PieceSizes, and may end     *)
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
          ChargeFirst         \* storage is charged before it is allocated

ASSUME /\ UnitLimit > 0 /\ BudgetLimit >= Floor
       /\ Floor \in 0..UnitLimit
       /\ PieceSizes # {} /\ PieceSizes \subseteq 1..UnitLimit

Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b

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
CopyPer == IF DoubleCapacity THEN 2 ELSE 3

\* The first block copies nothing that was held, and nor does a move out
\* of an empty floor: there is no fixed copying to add.
CopyFixed == 0

VARIABLES held,     \* the unit's bytes joined so far
          capacity, \* the block that holds them
          free,     \* the budget's room
          others,   \* what the rest of the budget holds
          store,    \* the assembly's storage (Resources.tla)
          received, \* the unit's bytes delivered
          copied,   \* bytes copied into fresh storage by moves
          phase     \* joining, done, or failed
vars == <<held, capacity, free, others, store, received, copied, phase>>

Init ==
    /\ held = 0 /\ capacity = Floor
    /\ others \in 0..(BudgetLimit - Floor)
    /\ free = BudgetLimit - Floor - others
    /\ store = Grow(Reserve(Store(0), Floor), Floor)
    /\ received = 0 /\ copied = 0 /\ phase = "joining"

\* What a move to `target` charges: the whole new block, or, as
\* ChargedBytes does, only its growth.
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

\* A piece of n bytes.
Deliver(n) ==
    /\ phase = "joining" /\ received + n <= UnitLimit
    /\ LET need == held + n
           target == Target(need)
       IN IF need <= capacity
          THEN \* Joined in place.
               /\ held' = need /\ received' = received + n
               /\ store' = Begin(store)
               /\ UNCHANGED <<capacity, free, copied, phase>>
          ELSE IF need <= target /\ Extra(target) <= free
          THEN /\ store' = Move(target)
               /\ capacity' = target /\ held' = need
               /\ free' = free - Extra(target)
                           + (IF ChargeWhole THEN capacity ELSE 0)
               /\ copied' = copied + held
               /\ received' = received + n
               /\ UNCHANGED phase
          ELSE \* Refused. A head or header block waits: no step. A body ends,
               \* and its storage and charge go.
               /\ FailWhenRefused
               /\ store' = Release(Shrink(Begin(store), capacity), capacity)
               /\ free' = free + capacity /\ capacity' = 0 /\ held' = 0
               /\ phase' = "failed"
               /\ UNCHANGED <<copied, received>>
    /\ UNCHANGED others

\* The unit is whole: what it held past the floor goes.
Finish ==
    /\ phase = "joining" /\ received > 0
    /\ store' = Release(Shrink(Begin(store), capacity - Floor), capacity - Floor)
    /\ free' = free + capacity - Floor /\ capacity' = Floor /\ held' = 0
    /\ phase' = "done"
    /\ UNCHANGED <<others, received, copied>>

\* The next unit.
Start ==
    /\ phase \in {"done", "failed"}
    /\ received' = 0 /\ copied' = 0 /\ phase' = "joining"
    /\ store' = Begin(store)
    /\ UNCHANGED <<held, capacity, free, others>>

OtherParts ==
    /\ BudgetMovesInUnit \/ phase # "joining"
    /\ others' \in 0..(BudgetLimit - store.reserved)
    /\ free' = BudgetLimit - store.reserved - others'
    /\ store' = Begin(store)
    /\ UNCHANGED <<held, capacity, received, copied, phase>>

Next == (\E n \in PieceSizes : Deliver(n)) \/ Finish \/ Start \/ OtherParts
Spec == Init /\ [][Next]_vars

\* No moment held more than the assembly had reserved.
AssemblyPaid == Paid(store)
\* What it reserved, and the rest of the budget, stay within the limit.
AssemblyWithinLimit ==
    /\ WithinLimit(store, BudgetLimit - others)
    /\ free + others + store.reserved = BudgetLimit
\* The store holds the block the state says.
AssemblyTracks == Tracks(store, capacity)
\* The copying is linear in what arrived.
LinearCopy == copied <= CopyPer * received + CopyFixed
=============================================================================
