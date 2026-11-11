------------------------------ MODULE Holding ------------------------------
(***************************************************************************)
(* What TCP and below hold, against what pays for it, at every moment of  *)
(* a step (verification/README.md, "Resource properties"; Resources.tla). *)
(* Three holders, each with a store [held, peak, reserved] threaded       *)
(* through its allocations and frees in the code's order:                 *)
(*                                                                         *)
(* - Reassembly (src/stdlib/network/ip.rs, `Reassembly`): unfinished      *)
(*   packets under a cap. `push_fragment` makes room first (`make_room`,  *)
(*   dropping the packets that expire soonest, its own by its place),     *)
(*   then copies the fragment in. `expire` moves a timed-out packet's     *)
(*   first fragment out of it, dropping the rest first, and keeps it      *)
(*   until `take_expired`. The store's reservation is the cap,            *)
(*   `MOST_HELD`. A unit is a byte counted against the cap.              *)
(* - A UDP socket (src/stdlib/network/udp/sockets.rs, `Socket::keep`):    *)
(*   each datagram's header and bytes are charged to the layer's budget,  *)
(*   then copied; the queue's places are charged before they grow and     *)
(*   stay paid. The store's reservation is what the socket charged.       *)
(* - A TCP receive store (smoltcp/src/socket/tcp/rx.rs, `RxStore`): its   *)
(*   places and every backing's header are charged when the socket opens *)
(*   (`PLACES`); each piece it copies, and each block a join makes, is    *)
(*   charged its bytes before it is made. Past Segs chunks two neighbors  *)
(*   are joined in a new block, which holds both pieces, before they go.  *)
(*                                                                         *)
(* Each holder has one flag per order the code keeps; a control config    *)
(* turns one off, the order before the fix or a mutation, and must        *)
(* violate the holder's Paid. Sizes are small abstract units.             *)
(***************************************************************************)
EXTENDS Naturals, Sequences, Resources

CONSTANTS
    Keys,          \* reassembly keys
    Cap,           \* MAX_WAITING, in units
    PartialCost,   \* PARTIAL_COST
    PieceCost,     \* PIECE_COST
    ExpiredCost,   \* EXPIRED_COST
    Datas,         \* the data sizes a fragment, datagram or segment carries
    Budget,        \* the UDP layer's budget
    Header,        \* Chunk::HEADER
    Place,         \* one place in a queue
    Segs,          \* SEGMENTS
    MaxSteps,      \* how many steps are explored
    RoomFirst,     \* reassembly makes room before it copies (the code)
    MoveFirst,     \* expiry drops a packet's pieces before it keeps the first (the code)
    ChargeFirst,   \* a socket and a store charge before they copy (the code)
    HeadersPaid    \* PLACES counts the backings' headers (the code)

ASSUME ExpiredCost + 1 <= PartialCost + PieceCost

VARIABLES
    parts,   \* parts[k]: the units packet k counts, 0 when there is none
    order,   \* the packets by deadline, soonest first
    kept,    \* the first fragments kept, each its units with ExpiredCost
    rs,      \* the reassembly's store
    queue,   \* the socket's datagrams, each its bytes
    places,  \* the queue's places
    us,      \* the socket's store
    chunks,  \* the receive store's blocks, each its bytes
    opened,  \* the receive store's socket is open
    ts,      \* the receive store's store
    steps

vars == <<parts, order, kept, rs, queue, places, us, chunks, opened, ts, steps>>

RECURSIVE SumSeq(_)
SumSeq(s) == IF s = <<>> THEN 0 ELSE Head(s) + SumSeq(Tail(s))

RECURSIVE SumParts(_)
SumParts(ks) == IF ks = {} THEN 0
                ELSE LET k == CHOOSE x \in ks : TRUE IN parts[k] + SumParts(ks \ {k})

Counted == SumParts(Keys) + SumSeq(kept)

Init ==
    /\ parts = [k \in Keys |-> 0]
    /\ order = <<>>
    /\ kept = <<>>
    /\ rs = Store(Cap)
    /\ queue = <<>>
    /\ places = 0
    /\ us = Store(0)
    /\ chunks = <<>>
    /\ opened = FALSE
    /\ ts = Store(0)
    /\ steps = 0

Others == <<queue, places, us, chunks, opened, ts>>
Rest == <<parts, order, kept, rs>>

(***************************************************************************)
(* Reassembly                                                             *)
(***************************************************************************)

\* The soonest packets, in order, that dropping must take so that `left`
\* is within the cap; `own` stands at its place in `seq`.
RECURSIVE Victims(_, _)
Victims(seq, left) ==
    IF left <= Cap \/ seq = <<>> THEN <<>>
    ELSE <<Head(seq)>> \o Victims(Tail(seq), left - Head(seq)[2])

\* The deadline order with each packet's units, a fresh `k` at the end.
WithUnits(k, added, fresh) ==
    LET known == [i \in 1..Len(order) |->
                    <<order[i], IF order[i] = k THEN parts[k] + added ELSE parts[order[i]]>>]
    IN IF fresh THEN known \o <<<<k, added>>>> ELSE known

RECURSIVE ShrinkAll(_, _)
ShrinkAll(s, vs) == IF vs = <<>> THEN s ELSE ShrinkAll(Shrink(s, Head(vs)[2]), Tail(vs))

Dropped(vs) == {vs[i][1] : i \in 1..Len(vs)}

\* A fragment of `d` units for packet `k`.
Arrive(k, d) ==
    LET fresh == parts[k] = 0
        added == d + PieceCost + (IF fresh THEN PartialCost ELSE 0)
        seq == WithUnits(k, added, fresh)
        vs == Victims(seq, Counted + added)
        gone == Dropped(vs)
        survives == k \notin gone
        \* The code: room first, then the copy. Before the fix: the copy,
        \* then the soonest dropped while past the cap.
        s0 == Begin(rs)
        s1 == IF RoomFirst
              THEN LET dropped == ShrinkAll(s0, SelectSeq(vs, LAMBDA v : v[1] # k))
                   IN IF survives THEN Grow(dropped, added)
                      ELSE IF fresh THEN dropped ELSE Shrink(dropped, parts[k])
              ELSE ShrinkAll(Grow(s0, added), vs)
    IN
    /\ parts' = [x \in Keys |->
                   IF x \in gone THEN 0
                   ELSE IF x = k THEN parts[k] + added ELSE parts[x]]
    /\ order' = SelectSeq(IF fresh /\ survives THEN Append(order, k) ELSE order,
                          LAMBDA x : x \notin gone)
    /\ kept' = kept
    /\ rs' = s1

\* The soonest packet times out: its first fragment, `f` units, is kept
\* with ExpiredCost, never more than the packet counted.
Expire(f) ==
    /\ order # <<>>
    /\ LET k == Head(order)
           keep == f + ExpiredCost
           s0 == Begin(rs)
           s1 == IF MoveFirst
                 THEN Grow(Shrink(s0, parts[k]), keep)
                 ELSE Shrink(Grow(Grow(s0, f), ExpiredCost), parts[k])
       IN
       /\ keep <= parts[k]
       /\ parts' = [parts EXCEPT ![k] = 0]
       /\ order' = Tail(order)
       /\ kept' = Append(kept, keep)
       /\ rs' = s1

\* The caller takes the oldest kept first fragment.
TakeExpired ==
    /\ kept # <<>>
    /\ kept' = Tail(kept)
    /\ rs' = Shrink(Begin(rs), Head(kept))
    /\ UNCHANGED <<parts, order>>

(***************************************************************************)
(* A UDP socket                                                           *)
(***************************************************************************)

\* A datagram of `d` bytes: its header and bytes charged, then copied; a
\* place grown first if the queue is full, its growth charged first. A
\* refusal keeps nothing.
Datagram(d) ==
    LET grow == IF Len(queue) = places THEN (IF places = 0 THEN 1 ELSE places) ELSE 0
        cost == Header + d + grow * Place
        s0 == Begin(us)
        s1 == IF ChargeFirst
              THEN Grow(Grow(Reserve(s0, cost), grow * Place), Header + d)
              ELSE Reserve(Grow(Grow(s0, grow * Place), Header + d), cost)
    IN
    /\ us.reserved + cost <= Budget
    /\ queue' = Append(queue, d)
    /\ places' = places + grow
    /\ us' = s1

\* The port above takes the oldest: its header and bytes go back; its
\* place stays paid for.
TakeDatagram ==
    /\ queue # <<>>
    /\ queue' = Tail(queue)
    /\ us' = Release(Shrink(Begin(us), Header + Head(queue)), Header + Head(queue))
    /\ UNCHANGED places

(***************************************************************************)
(* A TCP receive store                                                    *)
(***************************************************************************)

Places == Segs * Place + (IF HeadersPaid THEN (Segs + 1) * Header ELSE 0)

\* The socket opens: PLACES charged, the places allocated.
Open ==
    /\ ~opened
    /\ opened' = TRUE
    /\ ts' = Grow(Reserve(Begin(ts), Places), Segs * Place)
    /\ UNCHANGED chunks

\* The two neighbors joined when a piece needs a place and none is free:
\* the first two, in a block of twice their bytes, charged and made
\* before they go.
Join(s) ==
    LET a == chunks[1]
        b == chunks[2]
        block == 2 * (a + b)
        made == IF ChargeFirst THEN Grow(Reserve(s, block), block + Header)
                ELSE Reserve(Grow(s, block + Header), block)
    IN Release(Shrink(Shrink(made, a + Header), b + Header), a + b)

\* A segment of `d` bytes whose piece the store copies: a place made by a
\* join if none is free, then the copy charged and made.
Segment(d) ==
    /\ opened
    /\ LET full == Len(chunks) = Segs
           s0 == Begin(ts)
           s1 == IF full THEN Join(s0) ELSE s0
           rest == IF full THEN <<2 * (chunks[1] + chunks[2])>> \o SubSeq(chunks, 3, Len(chunks))
                   ELSE chunks
           s2 == IF ChargeFirst THEN Grow(Reserve(s1, d), d + Header)
                 ELSE Reserve(Grow(s1, d + Header), d)
       IN
       /\ chunks' = Append(rest, d)
       /\ ts' = s2
    /\ UNCHANGED opened

\* The application reads the oldest chunk: its block goes back.
Read ==
    /\ chunks # <<>>
    /\ chunks' = Tail(chunks)
    /\ ts' = Release(Shrink(Begin(ts), Head(chunks) + Header), Head(chunks))
    /\ UNCHANGED opened

(***************************************************************************)

Next ==
    /\ steps < MaxSteps
    /\ steps' = steps + 1
    /\ \/ /\ \E k \in Keys, d \in Datas : Arrive(k, d)
          /\ UNCHANGED Others
       \/ /\ \E f \in Datas : Expire(f)
          /\ UNCHANGED Others
       \/ /\ TakeExpired
          /\ UNCHANGED Others
       \/ /\ \E d \in Datas : Datagram(d)
          /\ UNCHANGED <<Rest, chunks, opened, ts>>
       \/ /\ TakeDatagram
          /\ UNCHANGED <<Rest, chunks, opened, ts>>
       \/ /\ Open
          /\ UNCHANGED <<Rest, queue, places, us>>
       \/ /\ \E d \in Datas : Segment(d)
          /\ UNCHANGED <<Rest, queue, places, us>>
       \/ /\ Read
          /\ UNCHANGED <<Rest, queue, places, us>>

Spec == Init /\ [][Next]_vars

ReassemblyPaid == Paid(rs)
ReassemblyWithinCap == Counted <= Cap
ReassemblyTracks == Tracks(rs, Counted)
SocketPaid == Paid(us)
SocketWithinBudget == WithinLimit(us, Budget)
SocketTracks == Tracks(us, places * Place + SumSeq(queue) + Len(queue) * Header)
StorePaid == Paid(ts)
StoreTracks == Tracks(ts, (IF opened THEN Segs * Place ELSE 0)
                          + SumSeq(chunks) + Len(chunks) * Header)
=============================================================================
