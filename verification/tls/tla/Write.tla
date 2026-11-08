------------------------------ MODULE Write ------------------------------
(* Write cancellation in `Opened::poll_write`                               *)
(* (src/stdlib/services/stack/open.rs:205-251), the connection a TLS layer *)
(* opened over TCP is, over `Opened::pump` (open.rs:131-141), which runs   *)
(* the stack and its connection with `Live::poll`                          *)
(* (src/stdlib/services/stack/live.rs:161-181), and `Above::take`          *)
(* (open.rs:55-79), which counts what the stack reports written.           *)
(*                                                                          *)
(* A caller writes `call`, a short string. poll_write runs to its return    *)
(* in one step, as the synchronous function it is. Each pump inside it      *)
(* either fails, or returns once nothing more can move, having registered   *)
(* the caller's waker with what can move next (`Live::poll` returns         *)
(* Pending then, or wakes the caller itself after a busy stretch,           *)
(* live.rs:384-386). The pump never returns Ready(Ok): while it runs, the   *)
(* layer may credit what it accepted, or not yet. The layer is abstract: it *)
(* takes one write at a time and credits it once its ciphertext is written. *)
(* After a Pending the caller retries the same bytes, or drops the future   *)
(* and later writes other bytes.                                            *)
(*                                                                          *)
(* The model of the replaced `TlsConnection::poll_write`, whose flush could *)
(* return Ready before the layer credited a write, is in git history; its   *)
(* `FlushCredits` rule has no counterpart here.                             *)
EXTENDS Integers, Sequences

CONSTANTS
  Alphabet,      \* bytes a caller writes
  MaxLen,        \* the longest write
  Chunk,         \* the most poll_write offers the layer at once (WRITE, open.rs:17)
  MaxCalls,      \* how many poll_write calls one behavior makes
  MatchContent,  \* a retry is credited only if it starts with the earlier bytes (open.rs:220)
  TakePending,   \* poll_write takes the earlier write when it settles it (open.rs:215, 168)
  RememberWrite, \* poll_write keeps an accepted write for its retry (open.rs:244)
  PumpFirst      \* poll_write runs the stack before it looks at the earlier write (open.rs:214)

VARIABLES
  call,       \* the bytes of the call in progress, <<>> when none
  calls,      \* calls made
  pw,         \* Opened::pending, <<>> for None
  credited,   \* Above::written
  inflight,   \* plaintext the layer accepted and has not credited
  dirty,      \* the layer has output a pump must move
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

\* poll_write(call) after its first pump (open.rs:214), which left cr0
\* credited and inf0 uncredited. `woken` says whether that pump registered
\* the caller's waker.
AfterPump(cr0, inf0, woken) ==
  IF pw # <<>> /\ cr0 < Len(pw)
  THEN \* open.rs:216-219: Pending until the earlier write is credited
       /\ hang' = (hang \/ ~woken)
       /\ UNCHANGED <<call, pw, segs, settled, confirmed, twice, wrong, dup, failed>>
       /\ inflight' = inf0 /\ dirty' = (inf0 > 0)
       /\ credited' = cr0
  ELSE
  LET matched == pw # <<>> /\ (Prefix(pw, call) \/ ~MatchContent)
      cr1     == IF pw # <<>> THEN cr0 - Len(pw) ELSE cr0
      gaveUp  == IF pw # <<>> /\ ~matched THEN {Len(segs)} ELSE {}
  IN
  IF matched
  THEN \* open.rs:220-222: Ok(previous.len())
       /\ segs' = segs
       /\ Confirm(Len(pw), confirmed, settled)
       /\ pw' = IF TakePending THEN <<>> ELSE pw
       /\ credited' = IF TakePending THEN cr1 ELSE cr0
       /\ call' = <<>>
       /\ inflight' = inf0 /\ dirty' = (inf0 > 0)
       /\ UNCHANGED <<failed, dup, hang>>
  ELSE IF inf0 > 0
  THEN \* the layer refuses the write: open.rs:239, Pending
       /\ hang' = (hang \/ ~woken) /\ credited' = cr1 /\ pw' = <<>>
       /\ settled' = settled \cup gaveUp
       /\ inflight' = inf0 /\ dirty' = TRUE
       /\ UNCHANGED <<call, segs, confirmed, twice, wrong, dup, failed>>
  ELSE
  LET n    == Min(Len(call), Chunk)
      seg  == SubSeq(call, 1, n)
      st1  == settled \cup gaveUp
  IN
  /\ segs' = Append(segs, seg)
  /\ dup' = (dup \/ (Len(segs) > 0 /\ Len(segs) \notin st1))
  \* The second pump (open.rs:245): it fails, or registers the waker with
  \* the layer's ciphertext all written or not yet.
  /\ \E second \in {"credited", "waiting", "err"} :
       CASE second = "credited" ->
              \* open.rs:246-250: Ok(n)
              /\ Confirm(n, confirmed, st1)
              /\ credited' = cr1 /\ pw' = <<>> /\ inflight' = 0 /\ dirty' = FALSE
              /\ call' = <<>>
              /\ UNCHANGED <<failed, hang>>
         [] second = "waiting" ->
              \* open.rs:246-247: Pending, the write kept for its retry
              /\ credited' = cr1 /\ inflight' = n /\ dirty' = TRUE
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
  /\ IF ~PumpFirst
     THEN /\ AfterPump(credited, inflight, FALSE)   \* no pump, no waker
          /\ UNCHANGED calls
     ELSE \E first \in {"waiting", "err"}, done \in BOOLEAN :
            CASE first = "waiting" ->
                   \* the pump ran what could run: the ciphertext of what is
                   \* in flight is written (done) or not yet
                   LET d == dirty /\ done IN
                   /\ AfterPump(IF d THEN credited + inflight ELSE credited,
                                IF d THEN 0 ELSE inflight, TRUE)
                   /\ UNCHANGED calls
              [] first = "err" ->
                   /\ failed' = TRUE
                   /\ UNCHANGED <<call, calls, pw, credited, inflight, dirty, segs, settled,
                                  confirmed, twice, wrong, dup, hang>>

\* What is in flight is written while the caller waits.
Flush == /\ dirty /\ ~failed
         /\ credited' = credited + inflight /\ inflight' = 0 /\ dirty' = FALSE
         /\ UNCHANGED <<call, calls, pw, failed, segs, settled, confirmed, twice, wrong,
                        dup, hang>>

Next == Start \/ Drop \/ PollWrite \/ Flush

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
\* poll_write never returns Pending unless something will wake the caller.
NoHang == ~hang

=============================================================================
