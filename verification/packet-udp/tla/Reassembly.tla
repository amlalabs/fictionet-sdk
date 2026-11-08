----------------------------- MODULE Reassembly -----------------------------
(* Fragment reassembly under one IP layer: `IpLayer::take_in`, `on_timer`
   and `deadline` in src/stdlib/network/packet.rs (lines 438-476, 533-536
   and 549-551), over `Reassembly` in src/stdlib/network/ip.rs:
   `reassemble` (lines 668-680), `push_fragment` (683-797), `take`, `kill`
   (800-824) and `expire` (856-863).

   Two networks send one packet each with the same key: the same
   addresses, identification and protocol, as a tunnel's network and the
   world's can. Each packet is two fragments, the first (offset 0, more to
   come, with the header) and the last. A fragment's bytes are its
   network's, so the same place from the other network is "the same place
   with other bytes" and kills the packet (RFC 5722), and an exact copy is
   ignored. Sizes are in units: a packet costs PartialCost, a fragment
   PieceCost more; the code's 192 and 64 plus data bytes scale the same
   way. Time is whole ticks; a packet expires Timeout ticks after its
   first fragment, and `expire(now)` drops those with expires <= now.

   The driver (src/stdlib/layer/driver.rs, `deliver` and `run`) hands a
   packet in without firing due timers, so `Arrive` may run with a due
   deadline and `Timer` is a separate step. *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Nets,          \* the networks packets come from
    Mine,          \* the layer's own network: IpLayer::host_in(scope)
    Keys,          \* reassembly keys (address pair, id, protocol)
    PartialCost,   \* PARTIAL_COST, in units
    PieceCost,     \* PIECE_COST, in units
    MaxWaiting,    \* MAX_WAITING, in units
    Timeout,       \* V4_TIMEOUT, in ticks
    MaxTime,       \* the last tick explored
    MaxArrivals,   \* how many fragments arrive in all
    BindScope,     \* take_in drops other networks' packets (the code)
    KeyHasScope,   \* the table key holds the network (the other fix)
    ExpireOnPush,  \* reassemble expires before it takes a fragment (the code)
    Evict          \* reassemble drops the oldest while over MaxWaiting (the code)

ASSUME Mine \in Nets

Offsets == {0, 1}           \* first and last fragment
Any == "any"
TableKeys == (Nets \cup {Any}) \X Keys
TK(n, k) == <<IF KeyHasScope THEN n ELSE Any, k>>

Piece == [off : Offsets, net : Nets, at : 0..MaxTime]
NoPartial == [live |-> FALSE, dead |-> FALSE, pieces |-> {}, expires |-> 0]

VARIABLES
    now,       \* Env::now
    table,     \* table[tk]: Reassembly::partial, by_expiry
    size,      \* Reassembly::size
    delivered, \* packets IpLayer::take_in handed up, with their pieces
    arrivals   \* fragments offered so far

vars == <<now, table, size, delivered, arrivals>>

Cost(p) == IF p.dead THEN PartialCost ELSE PartialCost + PieceCost * Cardinality(p.pieces)
Live == {tk \in TableKeys : table[tk].live}

RECURSIVE SumCost(_)
SumCost(S) == IF S = {} THEN 0
              ELSE LET tk == CHOOSE x \in S : TRUE
                   IN Cost(table[tk]) + SumCost(S \ {tk})

Init ==
    /\ now = 0
    /\ table = [tk \in TableKeys |-> NoPartial]
    /\ size = 0
    /\ delivered = {}
    /\ arrivals = 0

\* Reassembly::expire(t): drops every live packet with expires <= t.
Expired(tbl, t) == {tk \in TableKeys : tbl[tk].live /\ tbl[tk].expires <= t}
ExpireTable(tbl, t) == [tk \in TableKeys |-> IF tk \in Expired(tbl, t) THEN NoPartial ELSE tbl[tk]]

RECURSIVE CostOf(_, _)
CostOf(tbl, S) == IF S = {} THEN 0
                  ELSE LET tk == CHOOSE x \in S : TRUE
                       IN (IF tbl[tk].dead THEN PartialCost
                           ELSE PartialCost + PieceCost * Cardinality(tbl[tk].pieces))
                          + CostOf(tbl, S \ {tk})

\* The cap loop at the end of `reassemble`: while over, drop the packet that
\* expires soonest (`by_expiry.first()`).
RECURSIVE Cap(_, _)
Cap(tbl, sz) ==
    LET live == {tk \in TableKeys : tbl[tk].live} IN
    IF ~Evict \/ sz <= MaxWaiting \/ live = {} THEN <<tbl, sz>>
    ELSE LET oldest == CHOOSE tk \in live :
                         \A o \in live : tbl[tk].expires <= tbl[o].expires
         IN Cap([tbl EXCEPT ![oldest] = NoPartial], sz - CostOf(tbl, {oldest}))

-----------------------------------------------------------------------------
\* Time passes.
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<table, size, delivered, arrivals>>

\* Driver::run fires the layer's timer once its deadline (the soonest
\* expiry) has come: IpLayer::on_timer, Reassembly::expire.
Timer ==
    /\ Expired(table, now) # {}
    /\ table' = ExpireTable(table, now)
    /\ size' = size - CostOf(table, Expired(table, now))
    /\ UNCHANGED <<now, delivered, arrivals>>

\* One fragment from network n, key k, at offset off reaches take_in.
Arrive(n, k, off) ==
    /\ arrivals < MaxArrivals
    /\ arrivals' = arrivals + 1
    /\ UNCHANGED now
    /\ IF BindScope /\ n # Mine
       THEN UNCHANGED <<table, size, delivered>>   \* IpReport::OtherScope
       ELSE
         LET t0 == IF ExpireOnPush THEN ExpireTable(table, now) ELSE table
             s0 == IF ExpireOnPush THEN size - CostOf(table, Expired(table, now)) ELSE size
             tk == TK(n, k)
             fresh == ~t0[tk].live
             p0 == IF fresh
                   THEN [live |-> TRUE, dead |-> FALSE, pieces |-> {},
                         expires |-> now + Timeout]
                   ELSE t0[tk]
             s1 == IF fresh THEN s0 + PartialCost ELSE s0
             same == {q \in p0.pieces : q.off = off}
             new == [off |-> off, net |-> n, at |-> now]
         IN
         IF p0.dead THEN
            \* A dropped packet keeps dropping its fragments.
            /\ table' = [t0 EXCEPT ![tk] = p0]
            /\ size' = s1
            /\ UNCHANGED delivered
         ELSE IF same # {} /\ (\E q \in same : q.net = n) THEN
            \* An exact copy is ignored.
            /\ table' = [t0 EXCEPT ![tk] = p0]
            /\ size' = s1
            /\ UNCHANGED delivered
         ELSE IF same # {} THEN
            \* The same place with other bytes: kill.
            /\ table' = [t0 EXCEPT ![tk] = [p0 EXCEPT !.dead = TRUE, !.pieces = {}]]
            /\ size' = s1 - PieceCost * Cardinality(p0.pieces)
            /\ UNCHANGED delivered
         ELSE
            LET pieces == p0.pieces \cup {new}
                whole == {q.off : q \in pieces} = Offsets
            IN IF whole THEN
                  \* `take` and `finish`: handed up with this fragment's
                  \* ingress.
                  LET r == Cap([t0 EXCEPT ![tk] = NoPartial], s1 + PieceCost - Cost([p0 EXCEPT !.pieces = pieces]))
                  IN /\ table' = r[1]
                     /\ size' = r[2]
                     /\ delivered' = delivered \cup
                          {[net |-> n, pieces |-> pieces, start |-> p0.expires - Timeout]}
               ELSE
                  LET r == Cap([t0 EXCEPT ![tk] = [p0 EXCEPT !.pieces = pieces]], s1 + PieceCost)
                  IN /\ table' = r[1]
                     /\ size' = r[2]
                     /\ UNCHANGED delivered

Next ==
    \/ Tick
    \/ Timer
    \/ \E n \in Nets, k \in Keys, off \in Offsets : Arrive(n, k, off)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
TypeOK ==
    /\ now \in 0..MaxTime
    /\ size \in Nat
    /\ \A tk \in TableKeys : table[tk].pieces \subseteq Piece

\* A packet handed up is made of its own network's fragments, and goes up
\* as that network's.
NoScopeMix == \A d \in delivered : \A q \in d.pieces : q.net = d.net

\* At most MaxWaiting units wait after each fragment.
WithinBudget == size <= MaxWaiting

\* `size` is the sum of the packets' sizes (Reassembly::check).
SizeAccounts == size = SumCost(Live)

\* Every fragment of a packet handed up came before the packet's time was
\* up: an expired packet is never completed.
NoLateJoin == \A d \in delivered : \A q \in d.pieces : q.at < d.start + Timeout
=============================================================================
