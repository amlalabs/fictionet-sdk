------------------------------ MODULE Layer ------------------------------
(* The server TLS layer in src/stdlib/services/tls/layer.rs, driven as     *)
(* Driver (src/stdlib/layer/driver.rs) and Harness                         *)
(* (src/stdlib/layer/harness.rs) drive it, over a carrier that takes       *)
(* ciphertext as slowly as it likes and reports what it took with          *)
(* StreamEvent::Written.                                                   *)
(*                                                                         *)
(* The whole connection is one record `s`. Its fields named after          *)
(* TlsLayer's fields are those fields; each operator below is the Rust     *)
(* function it names, with its file:line. rustls is abstract: its send     *)
(* queue, its decrypted plaintext, and what process_new_packets may do     *)
(* with the peer's next bytes in each phase. Bytes are units: a record of  *)
(* m plaintext units is m + Overhead ciphertext units, and one CHUNK is    *)
(* Chunk units, so a record can span two chunks as a 16 KiB record does.   *)
(*                                                                         *)
(* The hello work is the layer's `Pick` job (layer.rs:61-90): the world    *)
(* takes it and answers with a config or a refusal, whenever it likes.     *)
(* The handshake deadline is a timer that may go off at any moment before  *)
(* the handshake is done (Timeout). The credit `take_event` hands up is    *)
(* also what `take_urgent` (layer.rs:630-632) hands up when a `Chain` or   *)
(* the `Driver` takes it past a refused event: both take the same counter  *)
(* whole, so UpperTakes is either.                                         *)
EXTENDS Integers

CONSTANTS
  Chunk,      \* CHUNK (layer.rs:20) in units
  Overhead,   \* ciphertext units a record adds to its plaintext
  MaxWrite,   \* the largest Write the application offers, in units
  MaxPlain,   \* the most plaintext one record from the peer carries
  MaxInputs,  \* how many inputs the peer offers in one behavior
  MaxCmds,    \* how many commands the application offers in one behavior
  \* Each flag is the code as it is when TRUE. A config that sets one to
  \* FALSE names the property TLC must then violate.
  QuietAfterClose, \* rustls queues nothing once close_notify is sent (fix 1, rustls common_state.rs)
  DropLateDone,    \* on_done of a failed layer sends nothing (fix 2, layer.rs:473-476)
  CheckWritten,    \* on_event refuses a Written larger than what is out (layer.rs:308)
  CarrierRepeats,  \* the carrier may report a byte it never took (a broken carrier)
  CountProduced,   \* advance counts every chunk it hands below in `produced` (layer.rs:562)
  Fence,           \* credit waits until `delivered` reaches the fence (layer.rs:283)
  TakeCredit,      \* take_event takes the credit it hands up (layer.rs:625, 631)
  CheckHandshake,  \* on_command blocks a Write while handshaking (layer.rs:438)
  CheckClosing,    \* on_command refuses everything once closing (layer.rs:424)
  EndAfterDrain,   \* advance sends End only when no output is pending (layer.rs:605)
  EndOnce,         \* advance sends End once (`end_sent`, layer.rs:605-606)
  AbortClears,     \* abort drops the queued output (layer.rs:260, 263)
  CreditOnWritten, \* a Written calls credit_written (layer.rs:314)
  ClearAlert,      \* advance drops a fully written alert (layer.rs:559)
  ReadAfterClose,  \* advance still reads plaintext after close_notify is queued (layer.rs:574)
  RustlsHoldsEarlyData, \* rustls's reader yields nothing before the handshake ends (an assumption)
  HandshakeDeadline \* the layer has a handshake deadline (handshake_by, layer.rs:159-162) that may pass

ASSUME Chunk \in Nat \ {0} /\ Overhead \in Nat \ {0} /\ MaxWrite \in Nat \ {0}
ASSUME MaxPlain \in Nat \ {0} /\ MaxInputs \in Nat /\ MaxCmds \in Nat

VARIABLE s

None == [k |-> "none", n |-> 0]
Cmd(k, n) == [k |-> k, n |-> n]
Min(a, b) == IF a < b THEN a ELSE b

Phases == {"init", "acceptor", "accepted", "hs", "open", "none"}
(* ph abstracts the Option fields acceptor, accepted and tls:            *)
(*   init      all None, initialized = false                            *)
(*   acceptor  acceptor is Some                                         *)
(*   accepted  accepted is Some: the hello is complete                  *)
(*   hs, open  tls is Some, handshaking or not                          *)
(*   none      all None again: after an error, a rejection or abort     *)

Init ==
  s = [ \* TlsLayer (layer.rs:108-136)
        ph |-> "init", hello |-> FALSE, work |-> FALSE,
        alert |-> "no",          \* None, or Some before ("pending") and after ("written") its bytes
        reject |-> FALSE, fb |-> "unset", failure |-> FALSE, failed |-> FALSE,
        inEnded |-> FALSE, ended |-> FALSE, closing |-> FALSE, endSent |-> FALSE,
        reset |-> FALSE, resetSent |-> FALSE, below |-> None, above |-> None,
        produced |-> 0, delivered |-> 0, pend |-> 0, fence |-> -1, credit |-> 0,
        \* rustls: its send queue, other output ahead of the pending write's
        \* record (qa), that record (qd), output after it (qb); a KeyUpdate
        \* reply waiting for the next message (ku); decrypted plaintext;
        \* close_notify received; EOF seen; close_notify or a fatal alert sent
        qa |-> 0, qd |-> 0, qb |-> 0, ku |-> FALSE, plain |-> 0,
        peerClose |-> FALSE, eof |-> FALSE, sentFatal |-> FALSE,
        \* the driver's held command (Driver::below) and the carrier
        dbelow |-> None, unrep |-> 0, cEnded |-> FALSE, cReset |-> FALSE, lied |-> FALSE,
        \* the application above, the world doing the hello work, the peer
        cmd |-> None, cmds |-> 0, workTaken |-> FALSE, doneGiven |-> FALSE,
        inp |-> "none", ins |-> 0, peerDone |-> FALSE,
        \* history, for the properties
        acc |-> 0, acked |-> 0, lost |-> 0, gEnd |-> -1, taken |-> 0, dropped |-> 0,
        endAt |-> -1, ends |-> 0, early |-> FALSE, dataEarly |-> FALSE,
        writeEarly |-> FALSE, afterClose |-> FALSE, afterEnd |-> FALSE,
        endEarly |-> FALSE, stopped |-> FALSE ]

-----------------------------------------------------------------------------
(* rustls, abstract *)

WantsWrite(t) == t.ph \in {"hs", "open"} /\ t.qa + t.qd + t.qb > 0
\* ServerConnection::wants_read, given wants_write is false
WantsRead(t) == t.plain = 0 /\ ~t.peerClose

\* queue_tls_message: a pending KeyUpdate reply goes first
Append(t, k) ==
  LET kk == k + (IF t.ku THEN 1 ELSE 0) IN
  IF t.qd > 0 THEN [t EXCEPT !.qb = @ + kk, !.ku = FALSE]
              ELSE [t EXCEPT !.qa = @ + kk, !.ku = FALSE]

\* writer().write of m units: one record after everything queued
AppendData(t, m) ==
  LET kk == IF t.ku THEN 1 ELSE 0 IN
  IF t.qd > 0 THEN [t EXCEPT !.qd = @ + t.qb + kk + m + Overhead, !.qb = 0, !.ku = FALSE]
              ELSE [t EXCEPT !.qa = @ + kk, !.qd = m + Overhead, !.ku = FALSE]

\* CommonState::send_fatal_alert (rustls/src/common_state.rs). Before the
\* fix it queued the alert even after close_notify (and failed a
\* debug_assert in debug builds); with the fix it queues nothing then.
FatalAlert(t) ==
  IF t.sentFatal /\ QuietAfterClose THEN t ELSE [Append(t, 1) EXCEPT !.sentFatal = TRUE]

\* the TLS 1.2 no_renegotiation warning (common_state.rs process_main_protocol)
Renegotiation(t) == IF t.sentFatal /\ QuietAfterClose THEN t ELSE Append(t, 1)

\* CommonState::send_close_notify: nothing once an alert was sent
CloseNotify(t) == IF t.sentFatal THEN t ELSE [Append(t, 1) EXCEPT !.sentFatal = TRUE]

-----------------------------------------------------------------------------
(* TlsLayer *)

Handshaking(t) == t.ph # "open"                           \* is_handshaking, layer.rs:202

OutputPending(t) ==                                       \* output_pending, layer.rs:222
  \/ t.below.k # "none"
  \/ t.produced # t.delivered
  \/ t.alert # "no"
  \/ t.reject
  \/ WantsWrite(t)

Fail(t) ==                                                \* fail, layer.rs:230
  IF t.failed THEN t ELSE [t EXCEPT !.failure = TRUE, !.failed = TRUE, !.closing = TRUE]

CreditWritten(t) ==                                       \* credit_written, layer.rs:282
  IF (IF Fence THEN t.fence # -1 /\ t.delivered >= t.fence ELSE t.pend # 0)
  THEN [t EXCEPT !.credit = @ + t.pend, !.pend = 0, !.fence = -1, !.gEnd = -1,
                 !.early = @ \/ (t.pend > 0 /\ ~(t.gEnd # -1 /\ t.delivered >= t.gEnd))]
  ELSE t

Abort(t) ==                                               \* abort, layer.rs:253
  [t EXCEPT !.reset = TRUE, !.inEnded = TRUE, !.closing = TRUE, !.work = FALSE,
            !.above = None,
            !.below = IF AbortClears THEN None ELSE @,
            !.ph = IF AbortClears THEN "none" ELSE @,
            !.qa = IF AbortClears THEN 0 ELSE @,
            !.qd = IF AbortClears THEN 0 ELSE @,
            !.qb = IF AbortClears THEN 0 ELSE @,
            !.ku = FALSE, !.plain = 0,
            !.hello = FALSE, !.alert = "no", !.reject = FALSE, !.failure = FALSE,
            !.delivered = t.produced, !.pend = 0, !.fence = -1, !.credit = 0,
            !.lost = @ + t.pend + t.credit, !.gEnd = -1]

\* The output arm of advance, layer.rs:538-573.
Produce(t) ==
  LET n  == IF t.reject THEN 1                          \* UNRECOGNIZED_NAME
            ELSE IF t.alert = "pending" THEN 1          \* AcceptedAlert::write
            ELSE IF t.alert = "written" THEN 0
            ELSE Min(Chunk, t.qa + t.qd + t.qb)         \* write_tls into one CHUNK
      tls == ~t.reject /\ t.alert = "no"
      ta == IF tls THEN Min(n, t.qa) ELSE 0
      td == IF tls THEN Min(n - ta, t.qd) ELSE 0
      tb == IF tls THEN n - ta - td ELSE 0
      qd2 == t.qd - td
      t1 == [t EXCEPT
               !.qa = IF qd2 = 0 THEN (t.qa - ta) + (t.qb - tb) ELSE t.qa - ta,
               !.qd = qd2,
               !.qb = IF qd2 = 0 THEN 0 ELSE t.qb - tb,
               !.gEnd = IF t.qd > 0 /\ qd2 = 0 THEN t.produced + ta + td ELSE @,
               !.reject = FALSE,
               !.alert = IF t.alert = "pending" THEN "written"
                         ELSE IF t.alert = "written" /\ ClearAlert THEN "no" ELSE @]
      t2 == IF n = 0 THEN t1
            ELSE [t1 EXCEPT !.produced = IF CountProduced \/ tls THEN @ + n ELSE @,
                            !.below = Cmd("write", n)]
  IN IF t2.pend # 0 /\ t2.fence = -1 /\ ~WantsWrite(t2)
     THEN CreditWritten([t2 EXCEPT !.fence = t2.produced])
     ELSE t2

Readable(t) == t.plain > 0 \/ t.peerClose \/ t.eof

\* The plaintext arm of advance, layer.rs:579-601: reader().into_first_chunk()
Read(t) ==
  IF t.plain > 0
  THEN [t EXCEPT !.above = Cmd("data", Min(t.plain, Chunk)), !.plain = @ - Min(t.plain, Chunk),
                 !.dataEarly = @ \/ Handshaking(t)]
  ELSE IF t.peerClose
  THEN [t EXCEPT !.ended = TRUE, !.inEnded = TRUE, !.above = Cmd("ended", 0)]
  ELSE [t EXCEPT !.ended = TRUE, !.above = Cmd("ended", 0)]   \* UnexpectedEof

\* One call of advance (layer.rs:499-617) that returns Ok(true) or an Err.
\* A call that returns Ok(false) changes nothing and is not a step.
AdvanceNext(t) ==
  IF t.reset
  THEN IF t.below.k = "none" /\ ~t.resetSent
       THEN [t EXCEPT !.below = Cmd("reset", 0), !.resetSent = TRUE]
       ELSE t
  ELSE IF ~t.hello /\ t.ph = "accepted"
  THEN [t EXCEPT !.hello = TRUE, !.work = TRUE]
  ELSE IF t.below.k = "none" /\ (t.reject \/ t.alert # "no" \/ WantsWrite(t))
  THEN Produce(t)
  ELSE IF t.above.k = "none" /\ ~t.ended /\ ~t.failed /\ t.ph \in {"hs", "open"}
          /\ (ReadAfterClose \/ ~t.closing) /\ Readable(t)
  THEN Read(t)
  ELSE IF t.closing /\ (~t.endSent \/ ~EndOnce) /\ (~OutputPending(t) \/ ~EndAfterDrain)
          /\ t.below.k = "none"
  THEN [t EXCEPT !.endSent = TRUE, !.below = Cmd("end", 0), !.endAt = t.produced]
  ELSE IF t.failed /\ ~OutputPending(t) /\ t.failure
  THEN [t EXCEPT !.failure = FALSE, !.stopped = TRUE]       \* Err(failure)
  ELSE t

Advance ==
  /\ ~s.stopped
  /\ AdvanceNext(s) # s
  /\ s' = AdvanceNext(s)

-----------------------------------------------------------------------------
(* The peer's bytes and the carrier's reports: on_event, layer.rs:300-413 *)

PeerSends ==
  /\ ~s.stopped /\ s.inp = "none" /\ ~s.peerDone /\ s.ins < MaxInputs
  /\ \E k \in {"data", "ended", "reset"} :
       s' = [s EXCEPT !.inp = k, !.ins = @ + 1, !.peerDone = (k # "data"),
                      !.cReset = @ \/ k = "reset"]   \* a peer reset resets the carrier too

DataBlocked(t) ==                                         \* layer.rs:348-357
  \/ t.ph = "accepted" \/ t.above.k # "none" \/ t.below.k # "none"
  \/ (t.ph \in {"hs", "open"} /\ (WantsWrite(t) \/ ~WantsRead(t)))

\* What the acceptor or process_new_packets makes of the next bytes.
Accept(t, o) ==                                           \* layer.rs:388-402
  CASE o = "partial" -> t
    [] o = "hello"   -> [t EXCEPT !.ph = "accepted"]
    [] o = "bad"     -> Fail([t EXCEPT !.ph = "none",
                                       !.alert = IF t.fb = "hs" THEN "pending" ELSE "no"])

Process(t, o) ==                                          \* layer.rs:404, process
  CASE o = "progress"   -> t
    [] o = "done"       -> [t EXCEPT !.ph = "open"]
    [] o = "ticket"     -> Append([t EXCEPT !.ph = "open"], 1)   \* done, with a NewSessionTicket
    [] o = "failalert"  -> Fail(FatalAlert(t))
    [] o = "failquiet"  -> Fail(t)                               \* the peer's own alert
    [] o = "app"        -> [t EXCEPT !.plain = MaxPlain]
    [] o = "close"      -> [t EXCEPT !.peerClose = TRUE]
    [] o = "keyupdate"  -> [t EXCEPT !.ku = TRUE]
    [] o = "reneg"      -> Renegotiation(t)

Outcomes(t) ==
  CASE t.ph = "hs"   -> {"progress", "done", "ticket", "failalert", "failquiet"}
                          \cup (IF RustlsHoldsEarlyData THEN {} ELSE {"app"})
    [] t.ph = "open" -> {"progress", "app", "close", "keyupdate", "reneg", "failalert", "failquiet"}
    [] OTHER         -> {}

DeliverData ==
  /\ s.inp \in {"data", "last"} /\ ~DataBlocked(s)
  /\ LET t0 == IF s.ph = "init" THEN [s EXCEPT !.ph = "acceptor"] ELSE s IN
     \E whole \in (IF s.inp = "last" THEN {TRUE} ELSE BOOLEAN) :
       LET rest == IF whole THEN "none" ELSE "last" IN   \* Partial: the rest is taken next time
       IF t0.ph = "acceptor"
       THEN \E fb \in (IF t0.fb = "unset" THEN {"hs", "other"} ELSE {t0.fb}) :
              LET t1 == [t0 EXCEPT !.fb = fb] IN
              \E o \in (IF fb = "hs" THEN {"partial", "hello", "bad"} ELSE {"partial", "bad"}) :
                s' = [Accept(t1, o) EXCEPT !.inp = rest]
       ELSE IF t0.ph \in {"hs", "open"}
       THEN \E o \in Outcomes(t0) : s' = [Process(t0, o) EXCEPT !.inp = rest]
       ELSE s' = [t0 EXCEPT !.inp = "none"]                     \* Closed, layer.rs:374

DeliverEnded ==                                           \* layer.rs:324-342
  /\ s.inp = "ended"
  /\ ~(s.ph \in {"hs", "open"} /\ s.plain > 0)                    \* Blocked
  /\ s' = LET t == [s EXCEPT !.inEnded = TRUE, !.inp = "none"] IN
          IF Handshaking(t) THEN Fail(t) ELSE [t EXCEPT !.eof = TRUE]

DeliverInput ==
  /\ ~s.stopped /\ s.inp # "none"
  /\ IF s.reset \/ (s.inp # "reset" /\ (s.inEnded \/ s.failed))
     THEN s' = [s EXCEPT !.inp = "none"]                         \* Closed, layer.rs:306, 323
     ELSE IF s.inp = "reset"
     THEN s' = [Abort(s) EXCEPT !.resetSent = TRUE, !.above = Cmd("reset", 0), !.inp = "none"]
     ELSE IF s.inp = "ended" THEN DeliverEnded
     ELSE DeliverData

DeliverWritten ==                                         \* layer.rs:306-316
  /\ ~s.stopped /\ s.unrep > 0
  /\ IF s.reset
     THEN s' = [s EXCEPT !.unrep = 0]                            \* Closed: the harness drops it
     ELSE IF CheckWritten /\ s.unrep > s.produced - s.delivered
     THEN s' = [s EXCEPT !.stopped = TRUE]                       \* Err: completed more than once
     ELSE LET t == [s EXCEPT !.delivered = @ + s.unrep, !.unrep = 0] IN
          s' = IF CreditOnWritten THEN CreditWritten(t) ELSE t

-----------------------------------------------------------------------------
(* The application above: on_command, layer.rs:415-466, and take_event *)

Writes == {Cmd("write", n) : n \in 1..MaxWrite}

UpperOffers ==
  /\ ~s.stopped /\ s.cmd.k = "none" /\ s.cmds < MaxCmds
  /\ \E c \in Writes \cup {Cmd("end", 0), Cmd("reset", 0)} :
       s' = [s EXCEPT !.cmd = c, !.cmds = @ + 1]

\* A refused write stays with its owner, who may drop it: a cancelled write.
UpperCancels ==
  /\ ~s.stopped /\ s.cmd.k = "write"
  /\ s' = [s EXCEPT !.cmd = None]

WriteBlocked(t) ==                                        \* layer.rs:438
  \/ (CheckHandshake /\ Handshaking(t))
  \/ t.pend # 0
  \/ OutputPending(t)

UpperCommand ==
  /\ ~s.stopped /\ s.cmd.k # "none"
  /\ IF s.cmd.k = "reset" /\ ~s.reset
     THEN s' = [Abort(s) EXCEPT !.cmd = None]                    \* layer.rs:420
     ELSE IF s.failed \/ s.reset \/ (s.closing /\ (CheckClosing \/ s.cmd.k # "write"))
     THEN s' = [s EXCEPT !.cmd = None]                           \* Closed, layer.rs:424
     ELSE IF s.cmd.k = "end"
     THEN /\ ~Handshaking(s)                                     \* else Blocked
          /\ s' = [CloseNotify([s EXCEPT !.closing = TRUE]) EXCEPT !.cmd = None]
     ELSE /\ s.cmd.k = "write"
          /\ ~WriteBlocked(s)
          /\ LET m == Min(s.cmd.n, Chunk) IN
             s' = [AppendData(s, m) EXCEPT
                     !.pend = m, !.acc = @ + m,
                     !.writeEarly = @ \/ Handshaking(s),
                     !.afterClose = @ \/ s.closing,
                     !.cmd = IF s.cmd.n > m THEN Cmd("write", s.cmd.n - m) ELSE None]

UpperTakes ==                                             \* take_event, layer.rs:623-628, and take_urgent, 630-632
  /\ ~s.stopped
  /\ IF s.credit # 0
     THEN s' = [s EXCEPT !.acked = @ + s.credit, !.credit = IF TakeCredit THEN 0 ELSE @]
     ELSE /\ s.above.k # "none"
          /\ s' = [s EXCEPT !.above = None]

-----------------------------------------------------------------------------
(* The world: take_work (layer.rs:634-643) and on_done (layer.rs:468-497) *)

TakeWork ==
  /\ ~s.stopped /\ s.work
  /\ s' = [s EXCEPT !.work = FALSE, !.workTaken = s.hello]

Done ==
  /\ ~s.stopped /\ s.workTaken /\ ~s.doneGiven
  /\ LET t == [s EXCEPT !.doneGiven = TRUE] IN
     IF (t.failed \/ t.reset) /\ DropLateDone
     THEN s' = t                                                 \* the fix: nothing more to send
     ELSE IF t.ph # "accepted"
     THEN s' = [t EXCEPT !.stopped = TRUE]                       \* Err: no client hello
     ELSE \E o \in {"reject", "ok", "err"} :
            s' = CASE o = "reject" -> Fail([t EXCEPT !.work = FALSE, !.ph = "none", !.reject = TRUE])
                   [] o = "ok"     -> Append([t EXCEPT !.work = FALSE, !.ph = "hs"], 1)
                   [] o = "err"    -> Fail([t EXCEPT !.work = FALSE, !.ph = "none", !.alert = "pending"])

\* The handshake deadline goes off (on_timer, layer.rs:645-653; `deadline`
\* at 655-659 names it only while handshaking and not failed): the hello
\* work is dropped and the handshake fails with no alert of its own.
Timeout ==
  /\ HandshakeDeadline /\ ~s.stopped
  /\ Handshaking(s) /\ ~s.failed /\ ~s.reset
  /\ s' = Fail([s EXCEPT !.work = FALSE, !.ph = IF s.ph = "accepted" THEN "none" ELSE @])

-----------------------------------------------------------------------------
(* The driver's held command and the carrier below *)

TakeCommand ==                                            \* send_below -> take_command
  /\ ~s.stopped /\ s.dbelow.k = "none" /\ s.below.k # "none"
  /\ s' = [s EXCEPT !.dbelow = s.below, !.below = None]

CarrierTakes ==
  /\ ~s.stopped /\ s.dbelow.k # "none"
  /\ IF s.cEnded \/ s.cReset
     THEN s' = [s EXCEPT !.dbelow = None,                        \* Closed
                         !.dropped = @ + s.dbelow.n,
                         !.ends = @ + (IF s.dbelow.k = "end" THEN 1 ELSE 0),
                         !.afterEnd = @ \/ (s.dbelow.k = "write" /\ s.cEnded)]
     ELSE CASE s.dbelow.k = "write" ->
                 \E k \in 1..s.dbelow.n :
                   s' = [s EXCEPT !.unrep = @ + k, !.taken = @ + k,
                                  !.dbelow = IF k = s.dbelow.n THEN None
                                             ELSE Cmd("write", s.dbelow.n - k)]
            [] s.dbelow.k = "end" ->
                 s' = [s EXCEPT !.cEnded = TRUE, !.dbelow = None, !.ends = @ + 1,
                                !.endEarly = @ \/ s.delivered < s.endAt]
            [] s.dbelow.k = "reset" ->
                 s' = [s EXCEPT !.cReset = TRUE, !.dbelow = None]

\* A broken carrier reports one byte it never took.
CarrierLies ==
  /\ CarrierRepeats /\ ~s.stopped /\ ~s.lied
  /\ s' = [s EXCEPT !.unrep = @ + 1, !.lied = TRUE]

-----------------------------------------------------------------------------

Next ==
  \/ Advance \/ PeerSends \/ DeliverInput \/ DeliverWritten
  \/ UpperOffers \/ UpperCancels \/ UpperCommand \/ UpperTakes
  \/ TakeWork \/ Done \/ Timeout \/ TakeCommand \/ CarrierTakes \/ CarrierLies

\* The driver keeps running the layer, moving its output and offering the
\* peer's input (which may stay blocked), the carrier
\* eventually takes what it is given, and the application takes events.
Fairness ==
  /\ WF_s(Advance) /\ WF_s(TakeCommand) /\ WF_s(CarrierTakes)
  /\ WF_s(DeliverWritten) /\ WF_s(UpperTakes) /\ WF_s(DeliverInput)

Spec == Init /\ [][Next]_s /\ Fairness

-----------------------------------------------------------------------------
(* Properties *)

TypeOK ==
  /\ s.ph \in Phases
  /\ s.produced \in Nat /\ s.delivered \in Nat /\ s.pend \in Nat /\ s.credit \in Nat
  /\ s.qa \in Nat /\ s.qd \in Nat /\ s.qb \in Nat
  /\ s.qd = 0 => s.qb = 0
  /\ s.below.k \in {"none", "write", "end", "reset"}
  /\ s.dbelow.k \in {"none", "write", "end", "reset"}

Len(c) == IF c.k = "write" THEN c.n ELSE 0

\* Every ciphertext unit counted in `produced` is completed, still out
\* (in the layer, in the driver, taken but not yet reported), or was
\* dropped by a closed carrier.
Conservation ==
  ~s.reset => s.produced = s.delivered + s.unrep + Len(s.below) + Len(s.dbelow) + s.dropped

\* Write completion never runs ahead of what went out.
Bounded == s.delivered <= s.produced

\* Each accepted plaintext unit is acknowledged at most once: it is
\* acknowledged, lost to a reset, or still owed.
ExactlyOnce == s.acc = s.acked + s.lost + s.pend + s.credit

\* A write is acknowledged only after the carrier reported every unit of
\* the ciphertext that carries it.
CreditAfterDelivery == ~s.early

\* No application plaintext is accepted for sending before the handshake
\* completes. (Plaintext the other way comes only from rustls's reader,
\* which yields nothing before the handshake ends; the model's rustls
\* decrypts nothing in "hs", so `dataEarly` is rustls's guarantee, kept
\* here as a check of the model, not of the layer.)
NoWriteBeforeHandshake == ~s.writeEarly
NoReadBeforeHandshake == ~s.dataEarly

\* No plaintext is accepted once close_notify is queued.
NoPlaintextAfterClose == ~s.afterClose

\* No ciphertext goes below after End.
NoWriteAfterEnd == ~s.afterEnd

\* End reaches the carrier only after every byte before it was completed.
EndAfterDrainInv == ~s.endEarly

\* One End at most.
OneEnd == s.ends <= 1

\* After a reset, nothing more is written and nothing more is credited.
ResetStops == s.reset => (s.below.k \in {"none", "reset"} /\ s.credit = 0 /\ s.pend = 0)

\* Once the driver holds nothing, every completion was delivered, and the
\* layer has no output pending, no accepted write is still waiting for
\* credit: a write waits for credit only while its ciphertext is out, so a
\* runner that keeps moving output and completions credits it. The
\* replaced TlsConnection relied on this at a Ready flush; `Opened`
\* (services/stack/open.rs) waits for the credit itself (Write.tla).
FlushedMeansCredited ==
  (s.dbelow.k = "none" /\ s.unrep = 0 /\ ~OutputPending(s) /\ ~s.reset)
    => s.pend = 0

\* Every accepted write is eventually acknowledged, or the connection
\* reports its loss (a reset, or an error returned).
PendingResolves == s.pend > 0 ~> (s.pend = 0 \/ s.stopped)

\* close_notify, or a failure, ends the stream below.
CloseCompletes == s.closing ~> (s.cEnded \/ s.cReset \/ s.stopped)

\* A failure is returned once its alert is out, unless a reset comes first.
FailureReported == s.failed ~> (s.stopped \/ s.reset)

\* Decrypted plaintext reaches the application, half-closed or not.
PlaintextDelivered == s.plain > 0 ~> (s.plain = 0 \/ s.failed \/ s.stopped)

=============================================================================
