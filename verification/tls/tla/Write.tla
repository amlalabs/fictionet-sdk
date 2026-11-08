------------------------------ MODULE Write ------------------------------
(* Write cancellation in TlsConnection::poll_write                          *)
(* (src/stdlib/services/tls.rs:570-633) over Io::poll_flush (tls.rs:165)    *)
(* and Io::collect (tls.rs:154).                                            *)
(*                                                                          *)
(* A caller writes `call`, a short string. poll_write runs to its return    *)
(* in one step, as the synchronous function it is; the flushes inside it    *)
(* may return Pending (the connection below registered the waker), fail,    *)
(* or return Ready. The layer is abstract: it takes one write at a time and *)
(* credits it as the flush completes its ciphertext. That a Ready flush has *)
(* credited every accepted write is Layer.tla's FlushedMeansCredited; the   *)
(* FlushCredits flag drops it. After a Pending the caller retries the same  *)
(* bytes, or drops the future and later writes other bytes.                 *)
EXTENDS Integers, Sequences

CONSTANTS
  Alphabet,      \* bytes a caller writes
  MaxLen,        \* the longest write
  Chunk,         \* the most poll_write offers the layer at once (16 KiB, tls.rs:600)
  MaxCalls,      \* how many poll_write calls one behavior makes
  MatchContent,  \* a retry is credited only if it starts with the earlier bytes (tls.rs:590)
  TakePending,   \* poll_write takes the earlier write when it settles it (tls.rs:584)
  RememberWrite, \* poll_write keeps an accepted write for its retry (tls.rs:620)
  FlushCredits   \* a Ready flush has credited every accepted write (Layer.tla)

VARIABLES
  call,       \* the bytes of the call in progress, <<>> when none
  calls,      \* calls made
  pw,         \* Io::pending_write, <<>> for None
  credited,   \* Io::credited
  inflight,   \* plaintext the layer accepted and has not credited
  dirty,      \* the layer has output a flush must move
  failed,     \* the connection below failed
  segs,       \* history: every accepted write, in order
  settled,    \* history: indexes of segs confirmed to a caller or given up
  confirmed,  \* history: indexes confirmed with Ok
  twice,      \* history: a write was confirmed twice
  wrong,      \* history: Ok(k) for bytes that are not the call's first k
  dup,        \* history: a write was accepted while the one before was unsettled
  hang        \* history: Pending with no waker registered
vars == <<call, calls, pw, credited, inflight, dirty, failed, segs, settled, confirmed,
          twice, wrong, dup, hang>>

Strings == UNION {[1..n -> Alphabet] : n \in 1..MaxLen}
Min(a, b) == IF a < b THEN a ELSE b
Prefix(p, d) == Len(p) <= Len(d) /\ SubSeq(d, 1, Len(p)) = p

Init == /\ call = <<>> /\ calls = 0 /\ pw = <<>> /\ credited = 0 /\ inflight = 0
        /\ dirty = FALSE /\ failed = FALSE /\ segs = <<>> /\ settled = {} /\ confirmed = {}
        /\ twice = FALSE /\ wrong = FALSE /\ dup = FALSE /\ hang = FALSE

Start == /\ call = <<>> /\ calls < MaxCalls /\ ~failed
         /\ \E d \in Strings : call' = d
         /\ calls' = calls + 1
         /\ UNCHANGED <<pw, credited, inflight, dirty, failed, segs, settled, confirmed,
                        twice, wrong, dup, hang>>

\* The caller drops a pending write's future.
Drop == /\ call # <<>>
        /\ call' = <<>>
        /\ UNCHANGED <<calls, pw, credited, inflight, dirty, failed, segs, settled, confirmed,
                       twice, wrong, dup, hang>>

\* Ok(k) confirms the newest accepted write.
Confirm(k, cs, st) ==
  LET i == Len(segs') IN
  /\ confirmed' = cs \cup {i}
  /\ settled' = st \cup {i}
  /\ twice' = (twice \/ i \in cs)
  /\ wrong' = (wrong \/ segs'[i] # SubSeq(call, 1, k))

\* poll_write(call), from the top, with the first flush Ready
\* (tls.rs:579-583): what it credited (cr0) and left uncredited (inf0).
AfterFlush(cr0, inf0) ==
  IF pw # <<>> /\ cr0 < Len(pw)
  THEN \* tls.rs:585-587: Pending, and nothing will wake the caller
       /\ hang' = TRUE
       /\ UNCHANGED <<call, pw, segs, settled, confirmed, twice, wrong, dup, failed>>
       /\ inflight' = inf0 /\ dirty' = FALSE
       /\ credited' = cr0
  ELSE
  LET matched == pw # <<>> /\ (Prefix(pw, call) \/ ~MatchContent)
      cr1     == IF pw # <<>> THEN cr0 - Len(pw) ELSE cr0
      gaveUp  == IF pw # <<>> /\ ~matched THEN {Len(segs)} ELSE {}
  IN
  IF matched
  THEN \* tls.rs:590-591: Ok(previous.len())
       /\ segs' = segs
       /\ Confirm(Len(pw), confirmed, settled)
       /\ pw' = IF TakePending THEN <<>> ELSE pw
       /\ credited' = IF TakePending THEN cr1 ELSE cr0
       /\ call' = <<>>
       /\ inflight' = inf0 /\ dirty' = FALSE
       /\ UNCHANGED <<failed, dup, hang>>
  ELSE IF inf0 > 0
  THEN \* the layer refuses the write: tls.rs:614, Pending with no waker
       /\ hang' = TRUE /\ credited' = cr1 /\ pw' = <<>>
       /\ settled' = settled \cup gaveUp
       /\ inflight' = inf0 /\ dirty' = FALSE
       /\ UNCHANGED <<call, segs, confirmed, twice, wrong, dup, failed>>
  ELSE
  LET n    == Min(Len(call), Chunk)
      seg  == SubSeq(call, 1, n)
      st1  == settled \cup gaveUp
  IN
  /\ segs' = Append(segs, seg)
  /\ dup' = (dup \/ (Len(segs) > 0 /\ Len(segs) \notin st1))
  /\ \E second \in {"ready", "pending", "err"} :
       CASE second = "ready" ->
              \* tls.rs:622-628
              LET cr2 == IF FlushCredits THEN cr1 + n ELSE cr1 IN
              IF cr2 < n
              THEN /\ hang' = TRUE /\ credited' = cr2
                   /\ pw' = IF RememberWrite THEN seg ELSE <<>>
                   /\ inflight' = IF FlushCredits THEN 0 ELSE n
                   /\ dirty' = FALSE /\ settled' = st1
                   /\ UNCHANGED <<call, confirmed, twice, wrong, failed>>
              ELSE /\ Confirm(n, confirmed, st1)
                   /\ credited' = cr2 - n /\ pw' = <<>> /\ inflight' = 0 /\ dirty' = FALSE
                   /\ call' = <<>>
                   /\ UNCHANGED <<failed, hang>>
         [] second = "pending" ->
              \* tls.rs:631: the connection registered the waker; part of
              \* the ciphertext, or all of it, may have gone
              \E done \in BOOLEAN :
                /\ credited' = IF done THEN cr1 + n ELSE cr1
                /\ inflight' = IF done THEN 0 ELSE n
                /\ dirty' = ~done
                /\ pw' = IF RememberWrite THEN seg ELSE <<>>
                /\ settled' = st1
                /\ UNCHANGED <<call, confirmed, twice, wrong, failed, hang>>
         [] second = "err" ->
              /\ failed' = TRUE /\ credited' = cr1
              /\ pw' = IF RememberWrite THEN seg ELSE <<>>
              /\ settled' = st1 /\ inflight' = n /\ dirty' = TRUE
              /\ UNCHANGED <<call, confirmed, twice, wrong, hang>>

PollWrite ==
  /\ call # <<>> /\ ~failed /\ ~hang
  /\ IF dirty
     THEN \E first \in {"ready", "pending", "err"} :
            CASE first = "ready" ->
                   /\ AfterFlush(IF FlushCredits THEN credited + inflight ELSE credited,
                                 IF FlushCredits THEN 0 ELSE inflight)
                   /\ UNCHANGED calls
              [] first = "pending" ->
                   \E done \in BOOLEAN :
                     /\ credited' = IF done THEN credited + inflight ELSE credited
                     /\ inflight' = IF done THEN 0 ELSE inflight
                     /\ dirty' = ~done
                     /\ UNCHANGED <<call, calls, pw, failed, segs, settled, confirmed, twice,
                                    wrong, dup, hang>>
              [] first = "err" ->
                   /\ failed' = TRUE
                   /\ UNCHANGED <<call, calls, pw, credited, inflight, dirty, segs, settled,
                                  confirmed, twice, wrong, dup, hang>>
     ELSE /\ AfterFlush(credited, inflight)   \* nothing to flush: Ready at once
          /\ UNCHANGED calls

Next == Start \/ Drop \/ PollWrite

Spec == Init /\ [][Next]_vars

TypeOK == credited \in Nat /\ inflight \in Nat /\ pw \in Seq(Alphabet)

\* No write is confirmed to a caller twice.
ConfirmedOnce == ~twice
\* Ok(k) is returned only when the call's first k bytes are the write it
\* confirms.
ConfirmedIsTheCallers == ~wrong
\* A retry never sends its bytes again: a new write is accepted only after
\* the one before it was confirmed or given up for other bytes.
NoDuplicate == ~dup
\* poll_write never returns Pending unless the connection below will wake
\* the caller.
NoHang == ~hang

=============================================================================
