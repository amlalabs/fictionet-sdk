--------------------------- MODULE RfcReassembly ---------------------------
(* What the RFCs ask of fragment reassembly at a destination host, written
   without any of the code's bookkeeping. Reassembly.tla refines it.

   RFC 791 section 3.2 (and RFC 815): fragments that share a key (source,
   destination, protocol and identification for IPv4; source, destination
   and identification for IPv6) are put back together in one buffer, each
   fragment's data at its offset, and the datagram goes up once its data is
   complete. RFC 8200 section 4.5: reassembly of a packet is abandoned if it
   is not complete within the reassembly timeout (60 seconds for IPv6) of
   the first fragment's arrival; if any two fragments overlap, reassembly
   is abandoned and its fragments discarded; an exact copy of a fragment
   already there may be dropped instead. RFC 5722 section 4: once a
   fragment overlaps, the whole datagram, including fragments not yet
   received, is silently discarded. RFC 1122 section 3.3.2 lets a host give
   up a reassembly when it runs out of buffer space, which is the `evict`
   argument of `Arrive`.

   The model's fragments are whole at an offset (Offsets), as in
   Reassembly.tla, so two fragments overlap exactly when they share an
   offset. A fragment record carries its offset, its bytes (one of the
   patterns in Data), the tick it arrived and an arrival number (seq) that
   tells two arrivals of the same bytes apart. A buffer that was abandoned
   for an overlap stays "dead" until its timeout, discarding what comes. *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Keys,         \* reassembly keys
    Offsets,      \* the places a fragment may take
    Data,         \* the byte patterns a fragment may carry
    Timeout,      \* the reassembly timeout, in ticks
    MaxTime,      \* the last tick
    MaxSeq        \* the most arrivals

Frag == [off : Offsets, data : Data, at : 0..MaxTime, seq : 1..MaxSeq]
None == [state |-> "none", frags |-> {}, start |-> 0]
NoFrag == [off |-> 0, data |-> "none", at |-> 0, seq |-> 0]

VARIABLES
    now,        \* the time
    buf,        \* buf[k]: the reassembly buffer of key k
    delivered,  \* datagrams handed up: [key, bytes, frags]
    last        \* the last fragment that reached the host, kept or not

vars == <<now, buf, delivered, last>>

Init ==
    /\ now = 0
    /\ buf = [k \in Keys |-> None]
    /\ delivered = {}
    /\ last = NoFrag

\* A buffer whose reassembly timeout has passed.
Due(b, t) == b.state # "none" /\ b.start + Timeout <= t

\* The datagram a complete buffer holds: each offset's bytes.
Bytes(fs) == [o \in Offsets |-> (CHOOSE g \in fs : g.off = o).data]

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<buf, delivered, last>>

\* RFC 8200 section 4.5: an incomplete reassembly is abandoned at its
\* timeout. The timer may fire for some of the due buffers at a time.
Expire(S) ==
    /\ S # {}
    /\ \A k \in S : Due(buf[k], now)
    /\ buf' = [k \in Keys |-> IF k \in S THEN None ELSE buf[k]]
    /\ UNCHANGED <<now, delivered, last>>

\* Fragment f arrives under key k. Every arrival is a step, the ones that
\* change no buffer (a copy, a fragment of a dead datagram) included, so an
\* implementation that keeps a buffer open past an overlap cannot pass the
\* overlap off as nothing happening. Arrival numbers only grow. A buffer
\* past its timeout is gone first, so a late fragment starts a new
\* reassembly instead of joining. Then the host may give up the
\* reassemblies in evict for want of space (RFC 1122 section 3.3.2).
Arrive(k, f, evict) ==
    /\ f.at = now
    /\ f.seq > last.seq
    /\ last' = f
    /\ LET b == IF Due(buf[k], now) THEN None ELSE buf[k]
           same == {g \in b.frags : g.off = f.off}
           added == b.frags \cup {f}
           whole == {g.off : g \in added} = Offsets
           next ==
             CASE b.state = "dead" -> b
               [] same # {} /\ \E g \in same : g.data = f.data -> b
               [] same # {} -> [state |-> "dead", frags |-> {}, start |-> b.start]
               [] whole -> None
               [] b.state = "none" -> [state |-> "open", frags |-> {f}, start |-> now]
               [] OTHER -> [b EXCEPT !.frags = added]
           up == b.state # "dead" /\ same = {} /\ whole
       IN /\ buf' = [j \in Keys |-> IF j \in evict THEN None
                                    ELSE IF j = k THEN next ELSE buf[j]]
          /\ delivered' = IF up
                          THEN delivered \cup {[key |-> k, bytes |-> Bytes(added), frags |-> added]}
                          ELSE delivered
    /\ UNCHANGED now

Next ==
    \/ Tick
    \/ \E S \in SUBSET Keys : Expire(S)
    \/ \E k \in Keys, f \in Frag, evict \in SUBSET Keys : Arrive(k, f, evict)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* What every datagram handed up satisfies. Each follows from Next; they
\* are checked on Reassembly.tla through the refinement mapping too.

\* RFC 791 section 3.2: a datagram goes up only whole, one fragment at each
\* offset (exact copies were dropped, and an overlap abandons it).
WholeOnly ==
    \A d \in delivered :
        /\ {g.off : g \in d.frags} = Offsets
        /\ \A g, h \in d.frags : g.off = h.off => g = h

\* RFC 8200 section 4.5: every fragment of a datagram handed up arrived
\* before the timeout counted from its first fragment.
InTime ==
    \A d \in delivered :
        \A g, h \in d.frags : g.at < h.at + Timeout

\* The bytes handed up are the bytes its fragments carried, each at its
\* offset: neither first-wins nor last-wins, since nothing overlapped.
TheirBytes ==
    \A d \in delivered : \A g \in d.frags : d.bytes[g.off] = g.data

\* At most once per arrival set: no arrival is part of two datagrams.
OnceEach ==
    \A d, e \in delivered :
        d # e => {g.seq : g \in d.frags} \cap {g.seq : g \in e.frags} = {}
=============================================================================
