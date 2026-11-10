---------------------------- MODULE RecordTrace ----------------------------
(* Checks a log of the real vendored rustls against Record (the RFC).    *)
(*                                                                       *)
(* The log comes from rustls/src/budget/record_trace.rs, which runs a     *)
(* real ServerConnection (paid from a test budget that refuses on         *)
(* demand) and a real ClientConnection through a seeded schedule: reads  *)
(* split at random boundaries, writes of 0, 1 and 2^14 bytes, key         *)
(* updates both ways, close_notify, garbage records injected, budget      *)
(* refusals. Each entry is one observation:                              *)
(*                                                                       *)
(*  send    x put a record on the wire: outer content type, length class *)
(*          and, where the test knows it (from what the reader made of   *)
(*          it, or from the call that made it), its inner kind;          *)
(*  recv    x read the next record of the other's stream: outer type,    *)
(*          length class, accepted or failed, plaintext delivered;      *)
(*  wseq    x's write_seq after a call, rseq x's read_seq after a read;  *)
(*  forge   the test injected a garbage record into x's stream;          *)
(*  refuse  the budget refused a growth at the server, and whether any   *)
(*          state (sequence numbers, queued output, plaintext, buffers   *)
(*          held, handshake state) changed across it.                    *)
(*                                                                       *)
(* Each step below is a Record step pinned to the entries it accounts     *)
(* for. Record is nondeterministic where the log is silent (an           *)
(* encrypted record's inner type, whether a failure's alert follows), so *)
(* the log is a behavior of Record when some behavior consumes all of it: *)
(* the invariant TraceIncomplete is then violated, which is the pass.    *)
(* Record's own invariants are checked on the way. A log Record cannot    *)
(* follow leaves TraceIncomplete holding everywhere.                     *)
EXTENDS Record

CONSTANT Log
VARIABLE i

tvars == <<vars, i>>

InLog(k) == i + k - 1 <= Len(Log)
E(k) == Log[i + k - 1]

Outer(r) == IF r.e > 0 /\ V = "1.3" THEN "app" ELSE r.t

\* What the log says of a record's inner kind, against the record.
Kind(it, r) ==
  CASE it = "app" -> r.t = "app"
    [] it = "close" -> r.t = "alert" /\ r.k = "close"
    [] it = "fatal" -> r.t = "alert" /\ r.k = "fatal"
    [] it = "chg" -> r.ne >= 0
    [] it = "hs" -> r.t = "hs" /\ r.ne < 0
    [] it = "ccs" -> r.t = "ccs"
    [] OTHER -> TRUE

SendMatches(k, x, r) ==
  /\ InLog(k) /\ E(k).a = "send" /\ E(k).x = x
  /\ E(k).t = Outer(r) /\ E(k).len = r.len /\ Kind(E(k).it, r)

\* The records x sent in this step, against the entries from the k-th.
SentMatch(x, k) ==
  LET new == SubSeq(sent'[x], Len(sent[x]) + 1, Len(sent'[x])) IN
  /\ \A m \in 1 .. Len(new) : SendMatches(k + m - 1, x, new[m])
  /\ i' = i + k - 1 + Len(new)

\* A writer's step: its records are the next send entries.
TSend ==
  \E x \in Sides :
    /\ \/ SendScript(x) \/ SendApp(x) \/ SendKU(x) \/ SendClose(x) \/ SendCompat(x)
       \/ SendHs(x)
    /\ Len(sent'[x]) > Len(sent[x])
    /\ SentMatch(x, 1)

\* A reader's step: the recv entry, then the alert its failure sent, if any.
TRecv ==
  \E x \in Sides :
    /\ InLog(1) /\ E(1).a = "recv" /\ E(1).x = x
    /\ wire[Peer(x)] # <<>>
    /\ LET r == Head(wire[Peer(x)])
           v == Verdict(st[x], r)
       IN /\ E(1).t = Outer(r) /\ E(1).len = r.len
          /\ E(1).o = v.o
          /\ E(1).data = IF v.o = "accept" /\ r.t = "app" /\ r.pl # "Z" THEN r.pl ELSE "none"
          /\ Receive(x)
          /\ SentMatch(x, 2)

\* The test injected a garbage record.
TForge ==
  /\ InLog(1) /\ E(1).a = "forge"
  /\ Forge(E(1).x)
  /\ Len(wire'[E(1).x]) > 0
  /\ LET r == wire'[E(1).x][Len(wire'[E(1).x])] IN ~r.a /\ r.len = E(1).len
  /\ i' = i + 1

\* The real sequence numbers against Record's. A KeyUpdate in reply is
\* encrypted when it is owed (enqueue_key_update_notification): the real
\* write keys are then already the new ones, at 0.
TSnap ==
  /\ InLog(1) /\ E(1).a \in {"wseq", "rseq"}
  /\ LET x == E(1).x IN
     \/ st[x].dead
     \/ E(1).a = "wseq" /\ E(1).v = IF st[x].pend THEN 0 ELSE IF st[x].we > 0 THEN st[x].ws ELSE 0
     \/ E(1).a = "rseq" /\ E(1).v = IF st[x].re > 0 THEN st[x].rs ELSE 0
  /\ UNCHANGED vars /\ i' = i + 1

\* A budget refusal: a stuttering step of Record, so nothing may change.
TRefuse ==
  /\ InLog(1) /\ E(1).a = "refuse" /\ ~E(1).changed
  /\ UNCHANGED vars /\ i' = i + 1

TraceNext == TSend \/ TRecv \/ TForge \/ TSnap \/ TRefuse

TraceSpec == Init /\ i = 1 /\ [][TraceNext]_tvars

\* Violated once the whole log is consumed: the pass.
TraceIncomplete == i <= Len(Log)
=============================================================================
