----------------------------- MODULE Reassembly -----------------------------
(* Fragment reassembly under one IP layer: `IpLayer::take_in`, `on_timer`
   and `deadline` in src/stdlib/network/packet.rs (lines 526-564, 629-632
   and 645-647), over `Reassembly` in src/stdlib/network/ip.rs: `reassemble`
   (lines 672-684), `push_fragment` (687-805), `take` (808-813), `kill`
   (822-832) and `expire` (864-871). Lines checked on 2026-11-10 at
   8c582367b.

   The IP layer has no network of its own: it takes raw packets from the
   input path its endpoint owns. Where packets of several networks arrive
   together, `NetworkInput::accept` (packet.rs 418-436) passes on only one
   network's, ahead of the IP layer and so ahead of reassembly. The model
   keeps two networks that send one packet each with the same key (the
   same addresses, identification and protocol, as a tunnel's network and
   the world's can), and BindScope says whether only one of them reaches
   this IP layer: TRUE for an endpoint's own input or a `NetworkInput`
   ahead of it, FALSE for one IP layer fed both, the code before the first
   pass. Since the key has no network (ip.rs `Key`), the table is keyed by
   Keys alone; the earlier `KeyHasScope` flag, a design the code did not
   take, is retired.

   Each packet is two fragments, the first (offset 0, more to come, with
   the header) and the last. A fragment carries one of the byte patterns in
   Data. A fragment at the place of one waiting, with the same bytes, is an
   exact copy and is ignored (push_fragment 728-742); the code compares
   bytes, not networks, so a copy from the other network is ignored too.
   The same place with other bytes is an overlap and kills the packet
   (RFC 5722; 762-779, `kill`), which stays dead, dropping its later
   fragments (725-727), until it expires or the cap drops it. Overlap
   picks this or the two orders the RFCs forbid, for the controls. Partial
   overlaps, the lengths and the "more fragments" flag on a copy are not
   modeled: a fragment is whole at its offset. Sizes are in units: a packet
   costs PartialCost, a fragment PieceCost more; the code's 1536 and 96 plus
   data bytes (and the first fragment's header) scale the same way. Time is
   whole ticks; a packet expires Timeout ticks after its first fragment,
   and `expire(now)` drops those with expires <= now. A packet handed up
   carries the bytes `finish` builds (ip.rs 931-957): each piece's bytes in
   offset order, as the `BTreeMap` of pieces gives them.

   The driver (src/stdlib/layer/driver.rs: `deliver` 269-281, `run`
   313-345) hands a packet in without firing due timers, so `Arrive` may
   run with a due deadline and `Timer` is a separate step. The IPv4 path
   for a whole packet (packet.rs 534-540) only expires; it is not modeled
   apart from that. *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Nets,          \* the networks packets come from
    Mine,          \* the network that reaches this IP layer
    Keys,          \* reassembly keys (address pair, id, protocol): ip.rs `Key`
    Data,          \* the byte patterns a fragment may carry
    PartialCost,   \* PARTIAL_COST, in units
    PieceCost,     \* PIECE_COST, in units
    MaxWaiting,    \* MAX_WAITING, in units
    Timeout,       \* V4_TIMEOUT, in ticks
    MaxTime,       \* the last tick explored
    MaxArrivals,   \* how many fragments arrive in all
    BindScope,     \* only Mine's packets reach the layer (the code)
    ExpireOnPush,  \* reassemble expires before it takes a fragment (the code)
    Evict,         \* reassemble drops the oldest while over MaxWaiting (the code)
    Overlap,       \* "reject" (the code), "first" or "last": what an overlap does
    ByOffset       \* finish lays the pieces out by offset (the code)

ASSUME Mine \in Nets
ASSUME Overlap \in {"reject", "first", "last"}

Offsets == {0, 1}           \* first and last fragment

Piece == [off : Offsets, net : Nets, data : Data, at : 0..MaxTime, seq : 1..MaxArrivals]
NoPartial == [live |-> FALSE, dead |-> FALSE, pieces |-> {}, expires |-> 0]

VARIABLES
    now,       \* Env::now
    table,     \* table[k]: Reassembly::partial, by_expiry
    size,      \* Reassembly::size
    delivered, \* packets IpLayer::take_in handed up, with their pieces and bytes
    arrivals,  \* fragments offered so far
    last       \* a history variable, not code: the last fragment take_in got

vars == <<now, table, size, delivered, arrivals, last>>

NoLast == [off |-> 0, data |-> "none", at |-> 0, seq |-> 0]

Cost(p) == IF p.dead THEN PartialCost ELSE PartialCost + PieceCost * Cardinality(p.pieces)
Live == {k \in Keys : table[k].live}

RECURSIVE SumCost(_)
SumCost(S) == IF S = {} THEN 0
              ELSE LET k == CHOOSE x \in S : TRUE
                   IN Cost(table[k]) + SumCost(S \ {k})

Init ==
    /\ now = 0
    /\ table = [k \in Keys |-> NoPartial]
    /\ size = 0
    /\ delivered = {}
    /\ arrivals = 0
    /\ last = NoLast

\* Reassembly::expire(t): drops every live packet with expires <= t.
Expired(tbl, t) == {k \in Keys : tbl[k].live /\ tbl[k].expires <= t}
ExpireTable(tbl, t) == [k \in Keys |-> IF k \in Expired(tbl, t) THEN NoPartial ELSE tbl[k]]

RECURSIVE CostOf(_, _)
CostOf(tbl, S) == IF S = {} THEN 0
                  ELSE LET k == CHOOSE x \in S : TRUE
                       IN (IF tbl[k].dead THEN PartialCost
                           ELSE PartialCost + PieceCost * Cardinality(tbl[k].pieces))
                          + CostOf(tbl, S \ {k})

\* The cap loop at the end of `reassemble`: while over, drop the packet that
\* expires soonest (`by_expiry.first()`).
RECURSIVE Cap(_, _)
Cap(tbl, sz) ==
    LET live == {k \in Keys : tbl[k].live} IN
    IF ~Evict \/ sz <= MaxWaiting \/ live = {} THEN <<tbl, sz>>
    ELSE LET oldest == CHOOSE k \in live :
                         \A o \in live : tbl[k].expires <= tbl[o].expires
         IN Cap([tbl EXCEPT ![oldest] = NoPartial], sz - CostOf(tbl, {oldest}))

\* `finish`: the bytes at each offset. By offset, as the code's BTreeMap
\* gives them; otherwise in the order the pieces arrived, so the piece that
\* came first goes first.
Bytes(pieces) ==
    IF ByOffset
    THEN [o \in Offsets |-> (CHOOSE q \in pieces : q.off = o).data]
    ELSE LET first == CHOOSE q \in pieces : \A r \in pieces : q.seq <= r.seq
             second == CHOOSE q \in pieces : q # first
         IN [o \in Offsets |-> IF o = 0 THEN first.data ELSE second.data]

-----------------------------------------------------------------------------
\* Time passes.
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<table, size, delivered, arrivals, last>>

\* Driver::run fires the layer's timer once its deadline (the soonest
\* expiry) has come: IpLayer::on_timer, Reassembly::expire.
Timer ==
    /\ Expired(table, now) # {}
    /\ table' = ExpireTable(table, now)
    /\ size' = size - CostOf(table, Expired(table, now))
    /\ UNCHANGED <<now, delivered, arrivals, last>>

\* The pieces after `new` joins `p0`, in the order the RFCs forbid.
Joined(p0, new, same) ==
    IF Overlap = "first" THEN p0.pieces
    ELSE (p0.pieces \ same) \cup {new}

\* One fragment from network n, key k, at offset off, carrying bytes dat,
\* reaches take_in.
Arrive(n, k, off, dat) ==
    /\ arrivals < MaxArrivals
    /\ arrivals' = arrivals + 1
    /\ UNCHANGED now
    /\ last' = IF BindScope /\ n # Mine THEN last
               ELSE [off |-> off, data |-> dat, at |-> now, seq |-> arrivals + 1]
    /\ IF BindScope /\ n # Mine
       THEN UNCHANGED <<table, size, delivered>>   \* NetworkInput passes it to another input
       ELSE
         LET t0 == IF ExpireOnPush THEN ExpireTable(table, now) ELSE table
             s0 == IF ExpireOnPush THEN size - CostOf(table, Expired(table, now)) ELSE size
             fresh == ~t0[k].live
             p0 == IF fresh
                   THEN [live |-> TRUE, dead |-> FALSE, pieces |-> {},
                         expires |-> now + Timeout]
                   ELSE t0[k]
             s1 == IF fresh THEN s0 + PartialCost ELSE s0
             same == {q \in p0.pieces : q.off = off}
             new == [off |-> off, net |-> n, data |-> dat, at |-> now, seq |-> arrivals + 1]
             \* What the table holds after the fragment, and whether it
             \* completed the packet.
             pieces == IF same = {} THEN p0.pieces \cup {new} ELSE Joined(p0, new, same)
             whole == {q.off : q \in pieces} = Offsets
             \* Add `pieces`, handing the packet up if they are whole, then
             \* run the cap.
             Keep ==
               IF whole THEN
                  \* `take` and `finish`: handed up with this fragment's
                  \* ingress.
                  LET r == Cap([t0 EXCEPT ![k] = NoPartial], s1 - Cost(p0))
                  IN /\ table' = r[1]
                     /\ size' = r[2]
                     /\ delivered' = delivered \cup
                          {[key |-> k, net |-> n, pieces |-> pieces,
                            bytes |-> Bytes(pieces), start |-> p0.expires - Timeout]}
               ELSE
                  LET grown == PieceCost * (Cardinality(pieces) - Cardinality(p0.pieces))
                      r == Cap([t0 EXCEPT ![k] = [p0 EXCEPT !.pieces = pieces]], s1 + grown)
                  IN /\ table' = r[1]
                     /\ size' = r[2]
                     /\ UNCHANGED delivered
         IN
         IF p0.dead THEN
            \* A dropped packet keeps dropping its fragments.
            /\ table' = [t0 EXCEPT ![k] = p0]
            /\ size' = s1
            /\ UNCHANGED delivered
         ELSE IF \E q \in same : q.data = dat THEN
            \* An exact copy is ignored.
            /\ table' = [t0 EXCEPT ![k] = p0]
            /\ size' = s1
            /\ UNCHANGED delivered
         ELSE IF same # {} /\ Overlap = "reject" THEN
            \* The same place with other bytes: kill.
            /\ table' = [t0 EXCEPT ![k] = [p0 EXCEPT !.dead = TRUE, !.pieces = {}]]
            /\ size' = s1 - PieceCost * Cardinality(p0.pieces)
            /\ UNCHANGED delivered
         ELSE Keep

Next ==
    \/ Tick
    \/ Timer
    \/ \E n \in Nets, k \in Keys, off \in Offsets, dat \in Data : Arrive(n, k, off, dat)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
TypeOK ==
    /\ now \in 0..MaxTime
    /\ size \in Nat
    /\ \A k \in Keys : table[k].pieces \subseteq Piece

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

-----------------------------------------------------------------------------
\* The refinement. RFC 791 section 3.2, RFC 8200 section 4.5 and RFC 5722
\* (RfcReassembly.tla) see one buffer per key, with no networks and no
\* costs: a live packet is an open buffer, or a dead one, started Timeout
\* ticks before it expires; a piece is a fragment without its network.
\* `last` is a history variable: the code keeps no copy of a fragment it
\* drops, but every fragment that reaches take_in is a step of the RFCs'
\* spec, so a code that ignored an overlap would be seen doing so.
Frag(q) == [off |-> q.off, data |-> q.data, at |-> q.at, seq |-> q.seq]
Frags(ps) == {Frag(q) : q \in ps}

Rfc == INSTANCE RfcReassembly WITH
    Offsets <- Offsets,
    MaxSeq <- MaxArrivals,
    last <- last,
    buf <- [k \in Keys |->
              IF ~table[k].live
              THEN [state |-> "none", frags |-> {}, start |-> 0]
              ELSE [state |-> IF table[k].dead THEN "dead" ELSE "open",
                    frags |-> Frags(table[k].pieces),
                    start |-> table[k].expires - Timeout]],
    delivered <- {[key |-> d.key, bytes |-> d.bytes, frags |-> Frags(d.pieces)] :
                    d \in delivered}

RfcSpec == Rfc!Spec
RfcWholeOnly == Rfc!WholeOnly
RfcInTime == Rfc!InTime
RfcTheirBytes == Rfc!TheirBytes
RfcOnceEach == Rfc!OnceEach

\* Throwaway invariants for the witness configs: each fails, which shows
\* the case it names is reached.
NoDelivery == delivered = {}
NoDeadPacket == \A k \in Keys : ~table[k].dead
NoMixedBytes == \A d \in delivered : d.bytes[0] = d.bytes[1]
=============================================================================
