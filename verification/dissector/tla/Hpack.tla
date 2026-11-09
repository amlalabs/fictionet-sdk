------------------------------ MODULE Hpack ------------------------------
(* The passive HPACK tables of an HTTP/2 capture (src/stdlib/dissect/      *)
(* http2.rs), one per direction, against the decoder tables of the        *)
(* endpoints they follow. Each direction's encoder sends header blocks:   *)
(* a literal with incremental indexing and a new name, one whose name is  *)
(* one of the two newest dynamic entries' (index 62 or 63), or a size     *)
(* update. The capture reads a block, or cannot read it (a frame too long *)
(* to keep, a block past its limit, one cut off by another frame:         *)
(* `PartialBlocks` then forgets the table), or misses bytes of the        *)
(* direction, which stops it.                                             *)
(* Entries are their sizes, in units where the smallest entry HPACK       *)
(* allows (32 bytes: an empty name and value, `ENTRY_OVERHEAD`) is Ov;    *)
(* each entry carries a fresh id, so equal entries are the same entry.    *)
(*                                                                        *)
(* Source lines, at the commit in README.md:                              *)
(*   PartialTable::default, forget          http2.rs 75-90                *)
(*   PartialTable::evict                    http2.rs 111-124              *)
(*   PartialTable::decode_block, read_block http2.rs 127-186              *)
(*     (size update, literal with                                         *)
(*     incremental indexing, unknown name)                                *)
(*   PartialBlocks::forget, read_fragment   http2.rs 351-354, 396-504     *)
(*     (blocks not read forget the table)                                 *)
(*   Capture::reset (a gap stops the        http2.rs 1422-1427            *)
(*     direction)                                                         *)
(*   the endpoint: hpack::Table::read_block protocols/hpack.rs 625-685    *)
(*                                                                        *)
(* Left out: the HPACK grammar and Huffman coding, indexed fields and     *)
(* literals without indexing (they change no table), SETTINGS, which the  *)
(* passive table does not read (the encoder's size updates bound the      *)
(* endpoint's table), and how frames carry blocks (CONTINUATION,          *)
(* padding: the Kani harnesses over `CaptureInputs` and `unpad`).         *)
EXTENDS Naturals, Sequences

CONSTANTS Blocks,             \* blocks each direction's encoder sends
          Ov,                 \* the smallest entry
          Sizes,              \* entry sizes the encoder inserts
          Maxes,              \* table maximums its size updates set
          Cap,                \* the most the passive table keeps (hpack::MAX_TABLE)
          Start,              \* the maximum both tables start with (4096)
          StrictSure,         \* sure again only when one more smallest entry would not fit
          ForgetUnsure,       \* forget makes the table unsure
          CapUnsure,          \* evicting past the cap makes the table unsure
          UnknownNameForgets, \* a new entry whose name is not known forgets the table
          GapStops            \* missing bytes stop the direction

Dirs == {1, 2}
None == 0 - 1   \* not a Nat: the maximum is not known
Sum(t) == LET RECURSIVE S(_) S(s) == IF s = <<>> THEN 0 ELSE Head(s).size + S(Tail(s)) IN S(t)
(* DynamicTable::evict: drop the oldest entries until the rest fit.       *)
RECURSIVE Evict(_, _)
Evict(t, max) == IF Sum(t) <= max THEN t ELSE Evict(SubSeq(t, 1, Len(t) - 1), max)

VARIABLES sent,     \* sent[d]: blocks d's encoder sent
          ids,      \* entries made so far
          ep,       \* ep[d]: the endpoint's table, newest first
          emax,     \* emax[d]: the endpoint's maximum
          pt,       \* pt[d]: the passive table, newest first
          pmax,     \* pmax[d]: its maximum, or None
          unsure,   \* unsure[d]: older entries may be unknown
          stopped,  \* stopped[d]: the direction is not read further
          failed    \* failed[d]: a block the capture read failed
vars == <<sent, ids, ep, emax, pt, pmax, unsure, stopped, failed>>

Init == /\ sent = [d \in Dirs |-> 0] /\ ids = 0
        /\ ep = [d \in Dirs |-> <<>>] /\ emax = [d \in Dirs |-> Start]
        /\ pt = [d \in Dirs |-> <<>>] /\ pmax = [d \in Dirs |-> Start]
        /\ unsure = [d \in Dirs |-> FALSE] /\ stopped = [d \in Dirs |-> FALSE]
        /\ failed = [d \in Dirs |-> FALSE]

(* PartialTable::evict on table t with maximum m and unsure u.            *)
PEvict(t, m, u) ==
  LET t1 == IF m # None THEN Evict(t, m) ELSE t
      t2 == Evict(t1, Cap)
      u2 == u \/ (CapUnsure /\ t2 # t1)
      sure == m # None /\ IF StrictSure THEN Sum(t2) + Ov > m ELSE Sum(t2) + Ov >= m
  IN [t |-> t2, u |-> u2 /\ ~sure]

Forget(d) == /\ pt' = [pt EXCEPT ![d] = <<>>] /\ pmax' = [pmax EXCEPT ![d] = None]
             /\ unsure' = [unsure EXCEPT ![d] = unsure[d] \/ ForgetUnsure]

(* What the capture does with block b of direction d: read it, fail to    *)
(* read it, or miss it with the bytes around it.                          *)
Capture(d, b, how) ==
  CASE how = "read" ->
         IF b.op = "resize"
         THEN LET e == PEvict(pt[d], b.max, unsure[d])
              IN /\ pt' = [pt EXCEPT ![d] = e.t] /\ pmax' = [pmax EXCEPT ![d] = b.max]
                 /\ unsure' = [unsure EXCEPT ![d] = e.u] /\ UNCHANGED <<stopped, failed>>
         ELSE IF b.op = "named" /\ Len(pt[d]) < b.k
         THEN IF unsure[d]
              THEN IF UnknownNameForgets
                   THEN Forget(d) /\ UNCHANGED <<stopped, failed>>
                   ELSE UNCHANGED <<pt, pmax, unsure, stopped, failed>>
              ELSE \* An index past what it knows while sure: Error::Index.
                   /\ failed' = [failed EXCEPT ![d] = TRUE]
                   /\ Forget(d) /\ UNCHANGED stopped
         ELSE LET e == PEvict(<<b.entry>> \o pt[d], pmax[d], unsure[d])
              IN /\ pt' = [pt EXCEPT ![d] = e.t] /\ unsure' = [unsure EXCEPT ![d] = e.u]
                 /\ UNCHANGED <<pmax, stopped, failed>>
    [] how = "unread" -> Forget(d) /\ UNCHANGED <<stopped, failed>>
    [] how = "gap" ->
         IF GapStops
         THEN Forget(d) /\ stopped' = [stopped EXCEPT ![d] = TRUE] /\ UNCHANGED failed
         ELSE UNCHANGED <<pt, pmax, unsure, stopped, failed>>

(* Direction d's encoder sends a block; its endpoint decodes it.          *)
Send(d) ==
  /\ sent[d] < Blocks
  /\ sent' = [sent EXCEPT ![d] = sent[d] + 1]
  /\ \E op \in {"new", "named", "resize"}, k \in 1..2, s \in Sizes, m \in Maxes,
        how \in {"read", "unread", "gap"} :
       /\ op = "named" => k <= Len(ep[d])   \* the encoder names only an entry it holds
       /\ op # "named" => k = 1
       /\ LET entry == [id |-> ids + 1, size |-> s]
              b == [op |-> op, k |-> k, entry |-> entry, max |-> m]
          IN /\ ids' = IF op = "resize" THEN ids ELSE ids + 1
             /\ IF op = "resize"
                THEN /\ emax' = [emax EXCEPT ![d] = m]
                     /\ ep' = [ep EXCEPT ![d] = Evict(ep[d], m)]
                ELSE /\ ep' = [ep EXCEPT ![d] = Evict(<<entry>> \o ep[d], emax[d])]
                     /\ UNCHANGED emax
             /\ IF stopped[d] THEN UNCHANGED <<pt, pmax, unsure, stopped, failed>>
                ELSE Capture(d, b, how)

Next == \E d \in Dirs : Send(d)
Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* At every index both tables hold, a read direction's passive table has  *)
(* its endpoint's entry, so a header shown for an index the encoder may   *)
(* name is the one the endpoint decodes; while sure, it holds every entry *)
(* the endpoint holds, so a name it does not know is never taken for one  *)
(* that is not there. It may hold older entries the endpoint evicted, when *)
(* inserts came while its maximum was not known: the encoder cannot name  *)
(* them, since the endpoint would refuse the block.                       *)
InStep ==
  \A d \in Dirs : ~stopped[d] =>
    /\ \A i \in 1..Len(pt[d]) : i <= Len(ep[d]) => pt[d][i] = ep[d][i]
    /\ ~unsure[d] => Len(pt[d]) >= Len(ep[d])

(* A block the encoder could send and the capture read never fails.       *)
NeverFails == \A d \in Dirs : ~failed[d]
=============================================================================
