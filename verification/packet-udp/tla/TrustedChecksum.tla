--------------------------- MODULE TrustedChecksum ---------------------------
(* The rule a packet's trusted-checksum flag must keep: the flag says the
   checksum in the packet was computed, or verified, over the bytes the
   packet holds now, so code that sees it set may skip verifying.

   A packet type with such a flag is being written on comp/buf-core and
   comp/buf-tcp. On 2026-11-10 neither branch had a commit past main
   (3db7a847e); the buf-core worktree held a new `buf` crate, not yet
   committed, whose `Chunk` (buf/src/chunk.rs) is a view of a backing that
   clones and pieces share, with no flag yet. This model takes its
   operations from that `Chunk` and from how the current code handles
   checksums: `fictionet::Packet` is a plain byte vector, and checksums are
   written by `ip::set_header_checksum` and the transports' encoders and
   checked by `Header::check` and `wire::Datagram::checksum_ok`
   (src/stdlib/network/ip.rs, udp/wire.rs). The mapping below names, per
   action, the Rust each should be checked against once the flag lands.

   Bytes and checksum. A backing holds Cap cells of one bit each; a packet
   (a handle) is a view [lo, hi) of one backing. The checksum covers the
   cells [cov, hi) and sits in cell cov: it is valid when that cell is the
   parity of the others. Parity stands in for the RFC 1071 sum: as with the
   sum, changing any one covered cell breaks it, and it can be updated
   incrementally (RFC 1624). Cells in [lo, cov) are not covered, as the
   IPv4 TTL is not covered by a transport checksum. For a transport
   checksum, the pseudo-header fields (RFC 768, RFC 9293 section 3.1, RFC
   8200 section 8.1) count as covered: a write to an address must clear a
   UDP or TCP packet's flag.

   Per action, the Rust it maps to once the flag lands:
     Arrive     a packet read from the wire: `Chunk::unpaid`, `Chunk::paid`,
                `Chunk::copy_of`; the flag starts clear.
     Compute    writing the checksum: `ip::set_header_checksum`,
                `udp::wire::encode`, the TCP segment encoder, then setting
                the flag.
     Verify     `Header::check` (IPv4 header checksum),
                `wire::Datagram::checksum_ok`, the TCP checksum check; the
                flag is set only when they pass.
     Write      `Chunk::get_mut`, `Chunk::make_mut`, `Chunk::fill`, or any
                `&mut [u8]` over the bytes.
     Rewrite    a header field changed with an incremental checksum update
                (RFC 1624), as a NAT or a TTL decrement does; none in the
                code yet.
     MakeMut    `Chunk::make_mut` on shared backing: a copy of exactly the
                view's bytes in a backing of its own.
     Prepend    `Chunk::prepend`: a header written in front.
     Advance    `Chunk::advance`: a header taken off the front.
     SplitTo    `Chunk::split_to` (and `Chunk::slice`, its one-sided form).
     Clone      `impl Clone for Chunk`: a second view of the same backing.
     Coalesce   `Chunk::extend_within`: another packet's bytes appended, as
                TCP coalescing of segments would.
     Drop       `impl Drop for Chunk`.

   Broken picks one wrong rule, for the controls; "none" is the rule as it
   must be. *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Handles,    \* the packets (views) at once
    Backings,   \* the backings they may use
    Cap,        \* cells in a backing
    Broken      \* "none", or the one wrong rule a control checks

ASSUME Broken \in {"none", "noverify", "writekeeps", "sharedwrite",
                   "rewritekeeps", "splitkeeps", "coalescekeeps"}

Cells == 1..Cap
Bits == {0, 1}
Dead == [live |-> FALSE, back |-> CHOOSE b \in Backings : TRUE, lo |-> 1, hi |-> 1,
         cov |-> 1, flag |-> FALSE, seen |-> <<>>]

VARIABLES
    pk,     \* pk[h]: handle h's view, flag, and the covered bytes last checked
    data    \* data[b]: backing b's cells

vars == <<pk, data>>

RECURSIVE Parity(_, _, _)
\* The parity of cells lo..hi-1 of backing cells d.
Parity(d, lo, hi) == IF lo >= hi THEN 0 ELSE (d[lo] + Parity(d, lo + 1, hi)) % 2

Valid(p, d) == p.cov < p.hi /\ d[p.cov] = Parity(d, p.cov + 1, p.hi)
\* The covered cells of p, as a sequence.
Covered(p, d) == [j \in 1..(p.hi - p.cov) |-> d[p.cov + j - 1]]

Live == {h \in Handles : pk[h].live}
Free == {b \in Backings : \A h \in Live : pk[h].back # b}
Unique(h) == \A g \in Live \ {h} : pk[g].back # pk[h].back
\* Writing through h's view: only when it alone holds its backing, as
\* `get_mut`, `prepend`, `extend_within` and `fill` require.
MayWrite(h) == Unique(h) \/ Broken = "sharedwrite"

Init ==
    /\ data = [b \in Backings |-> [c \in Cells |-> 0]]
    /\ pk = [h \in Handles |-> Dead]

-----------------------------------------------------------------------------
\* A packet comes off the wire into a free backing, with its flag clear.
\* lo > 1 leaves headroom; cov is where its checksum sits.
Arrive(h, b, lo, hi, cov, bytes) ==
    /\ ~pk[h].live /\ b \in Free
    /\ 1 <= lo /\ lo <= cov /\ cov < hi /\ hi <= Cap + 1
    /\ data' = [data EXCEPT ![b] = bytes]
    /\ pk' = [pk EXCEPT ![h] = [live |-> TRUE, back |-> b, lo |-> lo, hi |-> hi,
                                cov |-> cov, flag |-> FALSE, seen |-> <<>>]]

\* The checksum is written over the covered bytes, and the flag set.
Compute(h) ==
    LET p == pk[h]
        d == [data[p.back] EXCEPT ![p.cov] = Parity(data[p.back], p.cov + 1, p.hi)]
    IN /\ p.live /\ p.cov < p.hi /\ MayWrite(h)
       /\ data' = [data EXCEPT ![p.back] = d]
       /\ pk' = [pk EXCEPT ![h].flag = TRUE, ![h].seen = Covered(p, d)]

\* The checksum is verified; the flag is set only if it holds.
Verify(h) ==
    LET p == pk[h] IN
    /\ p.live
    /\ IF Valid(p, data[p.back]) \/ Broken = "noverify"
       THEN pk' = [pk EXCEPT ![h].flag = TRUE, ![h].seen = Covered(p, data[p.back])]
       ELSE UNCHANGED pk
    /\ UNCHANGED data

\* Cell i of h's view gets bit v. A covered cell clears the flag.
Write(h, i, v) ==
    LET p == pk[h] IN
    /\ p.live /\ p.lo <= i /\ i < p.hi /\ MayWrite(h)
    /\ data' = [data EXCEPT ![p.back][i] = v]
    /\ pk' = [pk EXCEPT ![h].flag = IF i >= p.cov /\ Broken # "writekeeps"
                                    THEN FALSE ELSE @]

\* A covered cell other than the checksum changes, and the checksum is
\* updated for it incrementally: valid before means valid after, so the
\* flag stays, and what it was checked over is the new bytes.
Rewrite(h, i, v) ==
    LET p == pk[h]
        d0 == data[p.back]
        update == Broken # "rewritekeeps"
        d == [d0 EXCEPT ![i] = v,
                        ![p.cov] = IF update THEN (d0[p.cov] + d0[i] + v) % 2 ELSE d0[p.cov]]
    IN /\ p.live /\ p.cov < i /\ i < p.hi /\ MayWrite(h)
       /\ data' = [data EXCEPT ![p.back] = d]
       /\ pk' = [pk EXCEPT ![h].seen = IF p.flag /\ update THEN Covered(p, d) ELSE @]

\* make_mut on shared backing: the view's bytes are copied into a free
\* backing. The bytes are the same, so the flag stays.
MakeMut(h, b) ==
    LET p == pk[h] IN
    /\ p.live /\ ~Unique(h) /\ b \in Free
    /\ data' = [data EXCEPT ![b] = [c \in Cells |-> IF p.lo <= c /\ c < p.hi
                                                    THEN data[p.back][c] ELSE 0]]
    /\ pk' = [pk EXCEPT ![h].back = b]

\* A header cell is written in front, in the headroom. The covered bytes do
\* not change, so the flag stays.
Prepend(h, v) ==
    LET p == pk[h] IN
    /\ p.live /\ p.lo > 1 /\ MayWrite(h)
    /\ data' = [data EXCEPT ![p.back][p.lo - 1] = v]
    /\ pk' = [pk EXCEPT ![h].lo = p.lo - 1]

\* The first cell is taken off. Cutting the checksum cell clears the flag;
\* the view then has no checksum, so cov moves with lo.
Advance(h) ==
    LET p == pk[h] IN
    /\ p.live /\ p.lo + 1 < p.hi
    /\ pk' = [pk EXCEPT ![h].lo = p.lo + 1,
                        ![h].cov = IF p.cov = p.lo THEN p.lo + 1 ELSE @,
                        ![h].flag = IF p.cov = p.lo THEN FALSE ELSE @]
    /\ UNCHANGED data

\* split_to(n): g takes the first n cells, h keeps the rest, sharing the
\* backing. When the checksum lies in the front, it no longer covers what
\* either piece holds and both flags clear; when it lies in the back, h's
\* covered bytes are unchanged and its flag stays. The front piece has no
\* checksum of its own.
SplitTo(h, g, n) ==
    LET p == pk[h]
        cut == p.lo + n
        front == p.cov < cut
        keep == Broken = "splitkeeps"
    IN /\ p.live /\ ~pk[g].live /\ g # h /\ 0 < n /\ cut < p.hi
       /\ pk' = [pk EXCEPT
                   ![g] = [p EXCEPT !.hi = cut,
                                    !.cov = IF front THEN p.cov ELSE p.lo,
                                    !.flag = IF front /\ keep THEN p.flag ELSE FALSE,
                                    !.seen = IF front /\ keep THEN p.seen ELSE <<>>],
                   ![h] = [p EXCEPT !.lo = cut,
                                    !.cov = IF front THEN cut ELSE p.cov,
                                    !.flag = IF front /\ ~keep THEN FALSE ELSE p.flag]]
       /\ UNCHANGED data

\* A second view of the same backing, with the same flag: same bytes.
Clone(h, g) ==
    /\ pk[h].live /\ ~pk[g].live /\ g # h
    /\ pk' = [pk EXCEPT ![g] = pk[h]]
    /\ UNCHANGED data

\* g's bytes are appended to h within its backing's room. The checksum
\* covers to the end, so its covered bytes grow and the flag clears.
Coalesce(h, g) ==
    LET p == pk[h]
        q == pk[g]
        n == q.hi - q.lo
        d == [c \in Cells |-> IF p.hi <= c /\ c < p.hi + n
                              THEN data[q.back][q.lo + c - p.hi]
                              ELSE data[p.back][c]]
    IN /\ p.live /\ q.live /\ g # h /\ MayWrite(h) /\ p.hi + n <= Cap + 1
       /\ data' = [data EXCEPT ![p.back] = d]
       /\ pk' = [pk EXCEPT ![h].hi = p.hi + n,
                           ![h].flag = IF Broken = "coalescekeeps" THEN @ ELSE FALSE]

Drop(h) ==
    /\ pk[h].live
    /\ pk' = [pk EXCEPT ![h] = Dead]
    /\ UNCHANGED data

Next ==
    \/ \E h \in Handles, b \in Backings, lo, hi, cov \in 1..(Cap + 1),
          bytes \in [Cells -> Bits] : Arrive(h, b, lo, hi, cov, bytes)
    \/ \E h \in Handles : Compute(h) \/ Verify(h) \/ Advance(h) \/ Drop(h)
    \/ \E h \in Handles, i \in Cells, v \in Bits : Write(h, i, v) \/ Rewrite(h, i, v)
    \/ \E h \in Handles, b \in Backings : MakeMut(h, b)
    \/ \E h \in Handles, v \in Bits : Prepend(h, v)
    \/ \E h, g \in Handles, n \in 1..Cap : SplitTo(h, g, n)
    \/ \E h, g \in Handles : Clone(h, g) \/ Coalesce(h, g)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
TypeOK ==
    \A h \in Live :
        /\ pk[h].back \in Backings
        /\ 1 <= pk[h].lo /\ pk[h].lo <= pk[h].cov /\ pk[h].cov < pk[h].hi
        /\ pk[h].hi <= Cap + 1

\* The flag is set only over the bytes it was computed or verified over:
\* none of the covered bytes changed since, except by an incremental
\* update that kept the checksum.
FlagMeansChecked == \A h \in Live : pk[h].flag => pk[h].seen = Covered(pk[h], data[pk[h].back])

\* What a reader relies on: a packet whose flag is set carries a valid
\* checksum, so verifying it again would pass.
FlagMeansValid == \A h \in Live : pk[h].flag => Valid(pk[h], data[pk[h].back])

\* Throwaway invariants for the witness configs: each fails, which shows
\* the case it names is reached with the flag set.
NoFlaggedClone == ~\E h, g \in Live : h # g /\ pk[h].back = pk[g].back /\ pk[h].flag /\ pk[g].flag
NoFlaggedHeader == ~\E h \in Live : pk[h].flag /\ pk[h].lo < pk[h].cov
=============================================================================
