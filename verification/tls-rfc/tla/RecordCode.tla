---------------------------- MODULE RecordCode ----------------------------
(* The vendored rustls record layer, server side, as the SDK's TLS layer   *)
(* drives it, refining Record (the RFC). The client and the attacker are   *)
(* Record's own abstract client and attacker; the server is the code.      *)
(*                                                                         *)
(* Source, checked against comp/fv-tls at b3f4510d7 (2026-11-10):          *)
(*  rustls/src/conn.rs: read_tls 814; process_new_packets 971 (output_paid *)
(*    at entry, reserve_step before each record, release_step);            *)
(*    keep_plaintext 1066; deframe 1091; process_more_input 1122 (the      *)
(*    unprotected change_cipher_spec size check 1173, the TLS 1.3          *)
(*    ciphertext size check 1186, reserve_plaintext before                 *)
(*    decrypt_incoming, the trial-decryption skip branch and its           *)
(*    add_discard, RejectedEarlyDataInterleavedWithHandshakeMessage,       *)
(*    MessageInterleavedWithHandshakeMessage, finish_trial_decryption);    *)
(*    handle_deframe_error 1289; process_msg 1321;                         *)
(*    maybe_refresh_traffic_keys 1428; refresh_traffic_keys 1446.          *)
(*  rustls/src/msgs/deframer/buffers.rs: resize 176, take_plaintext 244,   *)
(*    DeframerVecBuffer::read 277 (one record per call), prepare_read 311, *)
(*    arriving_end 343.                                                    *)
(*  rustls/src/msgs/message/outbound.rs read_opaque_message_header 271 and *)
(*    rustls/src/msgs/deframer/mod.rs DeframerIter::next 48: an oversize   *)
(*    header is record_overflow, an empty record not application data is  *)
(*    decode_error.                                                        *)
(*  rustls/src/record_layer.rs: decrypt_incoming 60 (the unprotected 2^14  *)
(*    limit; read_seq bumped only on success; trial decryption),           *)
(*    encrypt_outgoing 110 (write_seq bumped per encryption),              *)
(*    doing_trial_decryption 234.                                          *)
(*  rustls/src/common_state.rs: reserve_step 186, reserve_plaintext 200,   *)
(*    release_step 241, output_paid 247, with_control_room 257,            *)
(*    send_msg_encrypt 490, send_appdata_encrypt 506 (the stop before a    *)
(*    record that would take the keys' last sequence number),              *)
(*    send_single_fragment 570 (nothing once output_unpaid; pays before    *)
(*    encrypting; output_unpaid when queue_paid fails), flush_plaintext   *)
(*    664, queue_paid 683 (nothing queued after a dropped KeyUpdate),      *)
(*    perhaps_write_key_update 695, send_msg 704,                          *)
(*    accept_received_plaintext 748, send_fatal_alert 821,                 *)
(*    send_close_notify 848, queue_close_notify 854, should_update_key     *)
(*    965, enqueue_key_update_notification 983, buffer_plaintext 1009      *)
(*    (perhaps_write_key_update before it pays), send_plain 1035.          *)
(*  rustls/src/vecbuf.rs: pay 195, push_paid 217, push_charged 245,       *)
(*    reserve 274, release_reserve 287.                                    *)
(*  rustls/src/server/tls13.rs handle_key_update 1395 and ExpectTraffic's  *)
(*    handle; rustls/src/tls13/key_schedule.rs                             *)
(*    update_encrypter_and_notify 510,                                     *)
(*    request_key_update_and_update_encrypter 516.                         *)
(*  src/stdlib/services/tls/layer.rs: process 273; on_event Data 451      *)
(*    (reads only with no output queued, no plaintext waiting and no      *)
(*    wants_budget, then processes; OutOfMemory -> Blocked; any other     *)
(*    read error fails); on_command End 535 and Write 542 (one chunk of   *)
(*    at most 2^14, only when no output is pending); advance 655 (process *)
(*    again on wants_budget) and 703 (take_first_chunk).                   *)
(*                                                                         *)
(* The budget is an oracle that may refuse any growth: each refusal is a  *)
(* step of its own, named in `lastStep`.                                  *)
(*                                                                         *)
(* Abstractions. The server's handshake messages are a script (Record's    *)
(* Script("S")), emitted once the code reaches them; the handshake flight  *)
(* is emitted record by record after the ClientHello is processed (the    *)
(* code does it within that call; nothing the server does runs between).   *)
(* A layer write is one record (CHUNK = 2^14). The read buffer is the      *)
(* parts of a handshake message being joined (hsHeld), nb whole records    *)
(* after them, and part: some of the next one. Flags are the code as it is *)
(* when TRUE; a control sets one FALSE and names the property it breaks.   *)
(*                                                                         *)
(* Bounds as Record's, plus SoftLimit (the write keys' record limit,       *)
(* write_seq_max; 2 makes the second record under one key trigger the     *)
(* automatic key update, a large value turns it off).                     *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
  V, Early, Allowance, Frag, Compat, Wide, AppPls,
  MaxAppC, MaxAppS, MaxKU, MaxForge, MaxBad, MaxHs, Misbehave,
  SoftLimit,
  ExactCapacity,          \* push_paid never meets an allocation larger than paid (ring's encrypters)
  MarkUnpaidAfterEncrypt, \* send_single_fragment: output_unpaid when queue_paid fails (1f181ea41)
  DropAfterLostKeyUpdate, \* queue_paid: nothing queued after a dropped KeyUpdate (1f181ea41)
  ReserveStep,            \* process_new_packets: reserve_step before each record
  ReserveBeforeDecrypt,   \* process_more_input: reserve_plaintext before decrypt_incoming
  OneRecordPerRead,       \* DeframerVecBuffer::read stops at the end of the record arriving
  FailTrialWhenJoining,   \* a failed trial decryption with handshake parts held is an error
  PlaintextLimit,         \* decrypt_incoming: unprotected records at most 2^14 (dec84f1c2)
  CcsSizeCheck,           \* process_more_input: the same for change_cipher_spec (4ae1c83e6)
  CiphertextLimit13,      \* process_more_input: TLS 1.3 records at most 2^14+256 (dec84f1c2)
  HeaderBoundInclusive,   \* header check: 2^14+2048 allowed (dec84f1c2)
  HeaderOverflowAlert     \* header check: record_overflow, not decode_error (dec84f1c2)

ASSUME MaxHs = 0   \* the client sends Record's script alone

None == [t |-> "none"]

VARIABLES
  \* the client and the attacker, as in Record
  cwire, cst, csent, cacc, cgot, cdue, forged, bad, fails,
  \* the server
  sv,      \* rustls's state, below
  q,       \* sendable_tls: records queued, not yet written
  outS,    \* records written, not yet read by the client
  plainQ,  \* received_plaintext: ids of application data not yet taken
  \* history
  ssent,   \* records queued, in order
  sacc,    \* records accepted
  taken,   \* ids the layer took up
  sdue,    \* positions in ssent after which a KeyUpdate is owed
  encLog,  \* <<epoch, seq>> of every encryption, queued or not
  ghost    \* [afterGap, budgetFail, waitFail, skipHeld, charges, skipped, lastStep]

cvars == <<cwire, cst, csent, cacc, cgot, cdue, forged, bad>>
svars == <<sv, q, outS, plainQ, ssent, sacc, taken, sdue, encLog>>
vars == <<cvars, fails, svars, ghost>>


-----------------------------------------------------------------------------
(* The refinement mapping of the server *)

Dead == sv.err \/ sv.unpaid

\* Record's After, for the writer's keys alone.
AfterW(s, r) ==
  IF r.ne >= 0 THEN [s EXCEPT !.we = r.ne, !.ws = 0]
  ELSE IF r.e > 0 THEN [s EXCEPT !.ws = @ + 1]
  ELSE s

\* The writer's keys and next sequence number, as the records queued so
\* far left them (a KeyUpdate encrypted and waiting is not yet sent).
RECURSIVE WOf(_)
WOf(seq) == IF seq = <<>> THEN [we |-> 0, ws |-> 0]
            ELSE AfterW(WOf(SubSeq(seq, 1, Len(seq) - 1)), seq[Len(seq)])

Cnt(seq, P(_)) == Cardinality({i \in DOMAIN seq : P(seq[i])})
IsScript(r) == r.t \in {"hs", "ccs"} /\ r.k \in {"hs", "ccs", "fin"}
IsApp(r) == r.t = "app"
IsKUReq(r) == r.k = "kureq"

MapS ==
  LET w == WOf(ssent) IN
  [we |-> w.we, ws |-> w.ws,
   re |-> IF Dead THEN -1 ELSE sv.re, rs |-> IF Dead THEN -1 ELSE sv.rs,
   sp |-> Cnt(ssent, IsScript) + 1, finR |-> sv.finR, more |-> sv.hsHeld,
   trial |-> sv.trial /\ ~Dead /\ ~sv.hsHeld, allow |-> sv.allow, pend |-> sv.kuQ # None,
   closeS |-> sv.closeSent, closeR |-> sv.closeR, dead |-> Dead, cc |-> FALSE,
   appW |-> Cnt(ssent, IsApp), kuW |-> Cnt(ssent, IsKUReq), hsX |-> 0]

R == INSTANCE Record WITH
       ReplyFirst <- TRUE, CheckSeq <- TRUE, IgnoreAfterClose <- TRUE,
       QuietAfterClose <- TRUE, CheckSize <- TRUE,
       wire <- [x \in {"C", "S"} |-> IF x = "C" THEN cwire ELSE outS \o q],
       st <- [x \in {"C", "S"} |-> IF x = "C" THEN cst ELSE MapS],
       sent <- [x \in {"C", "S"} |-> IF x = "C" THEN csent ELSE ssent],
       acc <- [x \in {"C", "S"} |-> IF x = "C" THEN cacc ELSE sacc],
       got <- [x \in {"C", "S"} |-> IF x = "C" THEN cgot ELSE taken \o plainQ],
       due <- [x \in {"C", "S"} |-> IF x = "C" THEN cdue ELSE sdue]

-----------------------------------------------------------------------------
(* The client and the attacker: Record's actions over the client's state. *)

Prefixes(s, isApp) == R!Prefixes(s, isApp)

CPut(em, upd) ==
  /\ cwire' = cwire \o em.recs
  /\ csent' = csent \o em.recs
  /\ cst' = upd

CWriting == ~cst.dead /\ ~cst.closeS

CSendScript ==
  /\ CWriting /\ ~R!ScriptDone(cst, "C")
  /\ LET step == R!Script("C")[cst.sp] IN
     IF step.t = "none"
     THEN /\ cst' = [cst EXCEPT !.we = step.ne, !.ws = 0, !.sp = @ + 1]
          /\ UNCHANGED <<cwire, csent>>
     ELSE LET em == R!Emission(cst, FALSE, step.t, step.k, "S", "S", step.ne, 0)
          IN CPut(em, [em.st EXCEPT !.sp = @ + 1])
  /\ UNCHANGED <<cacc, cgot, cdue, forged, bad, fails, svars>>

CSendApp ==
  /\ CWriting /\ R!CanApp(cst, "C") /\ cst.appW < MaxAppC
  /\ \E pl \in AppPls, p \in Prefixes(cst, TRUE):
       \E len \in R!HonestLens(pl, cst.we > 0):
         LET em == R!Emission(cst, p, "app", "data", pl, len, -1, cst.appW + 1)
         IN CPut(em, [em.st EXCEPT !.appW = @ + 1])
  /\ UNCHANGED <<cacc, cgot, cdue, forged, bad, fails, svars>>

CSendKU ==
  /\ V = "1.3" /\ CWriting /\ R!ScriptDone(cst, "C")
  /\ \/ /\ cst.pend
        /\ LET em == R!Emission(cst, FALSE, "hs", "ku", "S", "S", -2, 0)
           IN CPut(em, [em.st EXCEPT !.pend = FALSE])
     \/ /\ cst.kuW < MaxKU
        /\ \E p \in Prefixes(cst, FALSE):
             LET em == R!Emission(cst, p, "hs", "kureq", "S", "S", -2, 0)
             IN CPut(em, [em.st EXCEPT !.kuW = @ + 1])
  /\ UNCHANGED <<cacc, cgot, cdue, forged, bad, fails, svars>>

CSendClose ==
  /\ CWriting /\ R!ScriptDone(cst, "C")
  /\ \E p \in Prefixes(cst, FALSE):
       LET em == R!Emission(cst, p, "alert", "close", "S", "S", -1, 0)
       IN CPut(em, [em.st EXCEPT !.closeS = TRUE])
  /\ UNCHANGED <<cacc, cgot, cdue, forged, bad, fails, svars>>

CSendCompat ==
  /\ V = "1.3" /\ Compat /\ CWriting /\ ~cst.cc
  /\ cst.sp > 1 /\ ~R!ScriptDone(cst, "C")
  /\ LET r == [t |-> "ccs", k |-> "ccs", e |-> 0, n |-> 0, a |-> TRUE, len |-> "S",
               pl |-> "S", ne |-> -1, id |-> 0]
     IN CPut([recs |-> <<r>>], [cst EXCEPT !.cc = TRUE])
  /\ UNCHANGED <<cacc, cgot, cdue, forged, bad, fails, svars>>

CAbort ==
  /\ ~cst.dead
  /\ cst' = [cst EXCEPT !.dead = TRUE, !.re = -1, !.rs = -1, !.trial = FALSE]
  /\ UNCHANGED <<cwire, csent, cacc, cgot, cdue, forged, bad, fails, svars>>

CSendBad ==
  /\ Misbehave /\ bad < MaxBad /\ ~cst.dead
  /\ \/ /\ ~cst.closeS
        /\ \E b \in R!BadRecs(cst):
             LET r == R!Mk(cst, b.t, b.k, b.pl, b.len, -1, 0)
             IN CPut([recs |-> <<r>>], R!After(cst, r))
     \/ /\ cst.closeS
        /\ LET r == R!Mk(cst, "app", "data", "S", "S", -1, cst.appW + 1)
           IN CPut([recs |-> <<r>>], [R!After(cst, r) EXCEPT !.appW = @ + 1])
  /\ bad' = bad + 1
  /\ UNCHANGED <<cacc, cgot, cdue, forged, fails, svars>>

ForgedRecs == {[t |-> "app", k |-> "data", e |-> 0, n |-> 0, a |-> FALSE, len |-> l,
                pl |-> "S", ne |-> -1, id |-> 0] : l \in {"S", IF V = "1.3" THEN "O2" ELSE "O4"}}

\* The attacker, into the client's stream, or into the server's where it
\* is after everything the server queued (wire["S"] is outS \o q).
Forge ==
  /\ forged < MaxForge
  /\ \/ /\ \E r \in ForgedRecs \cup {csent[i] : i \in {j \in DOMAIN csent : csent[j].e > 0}}:
             cwire' = Append(cwire, r)
        /\ UNCHANGED outS
     \/ /\ q = <<>>
        /\ \E r \in ForgedRecs \cup {ssent[i] : i \in {j \in DOMAIN ssent : ssent[j].e > 0}}:
             outS' = Append(outS, r)
        /\ UNCHANGED cwire
  /\ forged' = forged + 1
  /\ UNCHANGED <<cst, csent, cacc, cgot, cdue, bad, fails, sv, q, plainQ, ssent, sacc,
                 taken, sdue, encLog, ghost>>

\* The client reads the server's next record, as Record's Receive.
CReceive ==
  /\ ~cst.dead /\ outS # <<>>
  /\ LET r == Head(outS)
         s == cst
         v == R!Verdict(s, r)
     IN /\ outS' = Tail(outS)
        /\ CASE v.o = "ignore" -> UNCHANGED <<cst, cwire, csent, cacc, cgot, cdue, fails>>
             [] v.o = "skip" ->
                  /\ cst' = [cst EXCEPT !.allow = @ - 1]
                  /\ UNCHANGED <<cwire, csent, cacc, cgot, cdue, fails>>
             [] v.o = "accept" ->
                  /\ cst' = R!AfterAccept(s, r)
                  /\ cacc' = Append(cacc, R!AccEntry(s, r))
                  /\ cgot' = IF r.t = "app" /\ r.pl # "Z" THEN Append(cgot, r.id) ELSE cgot
                  /\ cdue' = IF r.k = "kureq" /\ ~s.pend THEN cdue \cup {Len(csent)} ELSE cdue
                  /\ UNCHANGED <<cwire, csent, fails>>
             [] v.o = "fail" ->
                  LET quiet == s.closeS
                      fail(al) == [x |-> "C", r |-> r, prot |-> R!IsProt(s, r), al |-> al,
                                   why |-> v.why, quiet |-> quiet]
                  IN /\ \/ /\ quiet \/ ~R!Mandated(v.why)
                           /\ cst' = [s EXCEPT !.dead = TRUE, !.re = -1, !.rs = -1, !.trial = FALSE]
                           /\ fails' = Append(fails, fail("none"))
                           /\ UNCHANGED <<cwire, csent>>
                        \/ /\ ~quiet
                           /\ \E p \in Prefixes(s, FALSE), al \in R!AlertsFor(v.why):
                                LET em == R!Emission(s, p, "alert", "fatal", "S", "S", -1, 0)
                                IN /\ cwire' = cwire \o em.recs
                                   /\ csent' = csent \o em.recs
                                   /\ cst' = [em.st EXCEPT !.dead = TRUE, !.re = -1, !.rs = -1, !.trial = FALSE]
                                   /\ fails' = Append(fails, fail(al))
                     /\ UNCHANGED <<cacc, cgot, cdue>>
  /\ UNCHANGED <<forged, bad, sv, q, plainQ, ssent, sacc, taken, sdue, encLog, ghost>>

ClientNext == CSendScript \/ CSendApp \/ CSendKU \/ CSendClose \/ CSendCompat
              \/ CAbort \/ CSendBad \/ Forge \/ CReceive

-----------------------------------------------------------------------------
(* The server: rustls *)

Pushes == IF ExactCapacity THEN {TRUE} ELSE {TRUE, FALSE}

\* encrypt_outgoing's record under the current write keys (record_layer.rs).
Enc(v, t, k, pl, len, ne, id) == R!Mk([we |-> v.we, ws |-> v.wseq], t, k, pl, len, ne, id)

\* send_single_fragment once paid for, with queue_paid and
\* perhaps_write_key_update: every result the budget allows. `out` is
\* what reaches sendable_tls, `enc` the encryption made.
SendPaid(v, r) ==
  IF v.unpaid THEN {[v |-> v, out |-> <<>>, enc |-> <<>>]}
  ELSE {LET kuGo == v.kuQ # None
            v1 == [v EXCEPT !.kuQ = None,
                            !.unpaid = kuGo /\ ~kuOK,
                            !.wseq = IF r.e > 0 THEN v.wseq + 1 ELSE v.wseq,
                            !.pendRefresh = @ \/ (V = "1.3" /\ r.t # "alert" /\ r.e > 0
                                                  /\ v.wseq >= SoftLimit)]
            pre == IF kuGo /\ kuOK THEN <<v.kuQ>> ELSE <<>>
            drop == v1.unpaid /\ DropAfterLostKeyUpdate
            go == ~drop /\ recOK
            \* send_msg marks every refused unprotected record; the flag is the
            \* encrypted path (send_single_fragment)
            v2 == IF ~drop /\ ~recOK /\ (MarkUnpaidAfterEncrypt \/ r.e = 0)
                  THEN [v1 EXCEPT !.unpaid = TRUE] ELSE v1
            v3 == IF r.ne >= 0 THEN [v2 EXCEPT !.we = r.ne, !.wseq = 0] ELSE v2
        IN [v |-> v3, out |-> pre \o (IF go THEN <<r>> ELSE <<>>),
            enc |-> IF r.e > 0 THEN <<<<r.e, r.n>>>> ELSE <<>>]
        : kuOK \in Pushes, recOK \in Pushes}

\* The ghost after records reach sendable_tls with or without output_unpaid.
Gh(g, unpaidBefore, out) == [g EXCEPT !.afterGap = @ \/ (unpaidBefore /\ out # <<>>)]

\* Queueing `out` and recording it.
Queue(out) ==
  /\ q' = q \o out
  /\ ssent' = ssent \o out

Step(name) == ghost' = [ghost EXCEPT !.lastStep = name]

Refusals == {"refuse_read", "refuse_step", "refuse_plain", "refuse_pay", "refuse_room"}

\* What the server touches only through rustls's protocol state.
Proto == <<sv.re, sv.rs, sv.we, sv.wseq, sv.kuQ, sv.trial, sv.allow, sv.hsHeld,
           sv.finR, sv.closeR, sv.closeSent, sv.sentFatal, sv.err, sv.unpaid,
           sv.phase, q, ssent, sacc, plainQ, encLog, cwire>>

-----------------------------------------------------------------------------
(* read_tls, as the layer calls it *)

\* The layer offers the client's bytes only with no output queued, no
\* plaintext waiting and no record waiting for the budget.
CanRead ==
  /\ sv.pc = "idle" /\ ~sv.err /\ ~sv.closeR
  /\ q = <<>> /\ plainQ = <<>> /\ ~sv.wantsBudget
  /\ sv.nb < Len(cwire)

\* prepare_read grows the buffer first: the budget may refuse, and nothing
\* is read (OutOfMemory, the layer keeps the bytes).
ReadRefuse ==
  /\ CanRead /\ ~(OneRecordPerRead /\ sv.nb >= 1)
  /\ Step("refuse_read")
  /\ UNCHANGED <<cvars, fails, svars>>

\* A whole record is buffered: read fails with ErrorKind::Other, which the
\* layer takes as a failure. The layer never calls read then (checked).
ReadWaiting ==
  /\ CanRead /\ OneRecordPerRead /\ sv.nb >= 1
  /\ sv' = [sv EXCEPT !.err = TRUE]
  /\ ghost' = [ghost EXCEPT !.waitFail = TRUE, !.lastStep = "read_waiting"]
  /\ UNCHANGED <<cvars, fails, q, outS, plainQ, ssent, sacc, taken, sdue, encLog>>

\* Some of the record arriving, or the rest of it; without
\* OneRecordPerRead, also the records after it.
Read ==
  /\ CanRead /\ ~(OneRecordPerRead /\ sv.nb >= 1)
  /\ \/ sv' = [sv EXCEPT !.part = TRUE]
     \/ sv' = [sv EXCEPT !.part = FALSE, !.nb = @ + 1, !.pc = "read"]
     \/ /\ ~OneRecordPerRead /\ sv.nb + 2 <= Len(cwire)
        /\ sv' = [sv EXCEPT !.part = FALSE, !.nb = @ + 2, !.pc = "read"]
  /\ Step("read")
  /\ UNCHANGED <<cvars, fails, q, outS, plainQ, ssent, sacc, taken, sdue, encLog>>

-----------------------------------------------------------------------------
(* process_new_packets for the first whole record buffered *)

Outer(r) == IF r.e > 0 /\ V = "1.3" THEN "app" ELSE r.t

\* read_opaque_message_header and DeframerIter::next.
HeaderAlert(r) ==
  CASE R!Ord[r.len] = 6 \/ (R!Ord[r.len] = 5 /\ ~HeaderBoundInclusive) ->
         IF HeaderOverflowAlert THEN "record_overflow" ELSE "decode_error"
    [] Outer(r) # "app" /\ r.len = "Z" -> "decode_error"
    [] OTHER -> "ok"

\* The record leaves the buffer (processed or skipped).
Consumed(v) == [v EXCEPT !.nb = @ - 1]

\* The server fails on r: the alert, if any, is sent as send_fatal_alert
\* sends it (nothing once a close_notify or fatal alert went), paid from
\* the room reserve_step charged; then the state is an error.
FailWith(v0, r, prot, al) ==
  LET v == Consumed(v0)
      send == al # "none" /\ ~v.sentFatal
      entry == [x |-> "S", r |-> r, prot |-> R!IsProt(MapS, r),
                al |-> IF send THEN al ELSE "none",
                why |-> R!Verdict(MapS, r).why, quiet |-> v.closeSent]
  IN /\ cwire' = Tail(cwire)
     /\ fails' = Append(fails, entry)
     /\ \/ /\ ~send
           /\ sv' = [v EXCEPT !.err = TRUE, !.wantsBudget = FALSE]
           /\ UNCHANGED <<q, ssent, encLog>> /\ ghost' = [ghost EXCEPT !.lastStep = "fail"]
        \/ /\ send
           /\ \E payOK \in (IF ReserveStep THEN {TRUE} ELSE BOOLEAN):
                IF ~payOK \/ v.unpaid
                THEN /\ sv' = [v EXCEPT !.unpaid = TRUE, !.sentFatal = TRUE, !.err = TRUE,
                                        !.wantsBudget = FALSE]
                     /\ UNCHANGED <<q, ssent, encLog>>
                     /\ ghost' = [ghost EXCEPT !.budgetFail = @ \/ ~payOK, !.lastStep = "fail"]
                ELSE \E o \in SendPaid(v, Enc(v, "alert", "fatal", "S", "S", -1, 0)):
                       /\ sv' = [o.v EXCEPT !.sentFatal = TRUE, !.err = TRUE, !.wantsBudget = FALSE]
                       /\ Queue(o.out) /\ encLog' = encLog \o o.enc
                       /\ ghost' = [Gh(ghost, v.unpaid, o.out) EXCEPT !.lastStep = "fail"]
     /\ UNCHANGED <<sacc, plainQ, sdue>>

\* r accepted with the server in state v1 (read state already moved on);
\* v0 is the state before, for the history.
AcceptWith(v0, v1, r, prot) ==
  /\ cwire' = Tail(cwire)
  /\ sacc' = Append(sacc, [r |-> r, prot |-> prot, ke |-> v0.re, ks |-> v0.rs])
  /\ plainQ' = IF r.t = "app" /\ r.pl # "Z" THEN Append(plainQ, r.id) ELSE plainQ
  /\ UNCHANGED fails

\* process_msg (conn.rs) and the state's handle, for a record that passed
\* the record layer: v has the read state after decryption.
Message(v0, v, r, prot) ==
  LET acc(v1) == /\ AcceptWith(v0, v1, r, prot)
                 /\ sv' = [v1 EXCEPT !.wantsBudget = FALSE]
                 /\ UNCHANGED <<q, ssent, encLog, sdue>>
                 /\ ghost' = [ghost EXCEPT !.lastStep = "accept"]
      un == FailWith(v0, r, prot, "unexpected_message")
  IN
  CASE r.t = "ccs" ->
         \* TLS 1.3: dropped during the handshake if it is the one valid byte (is_valid_ccs)
         IF V = "1.3" THEN (IF ~v.finR /\ r.pl = "S" THEN acc(Consumed(v)) ELSE un)
         ELSE IF v.phase = "hs1" /\ v.re = 0
              THEN acc([Consumed(v) EXCEPT !.re = 3, !.rs = 0])
              ELSE un
    [] r.t = "alert" ->
         IF r.pl = "Z" THEN FailWith(v0, r, prot, "decode_error")
         ELSE IF r.k = "close" /\ v.finR THEN acc([Consumed(v) EXCEPT !.closeR = TRUE])
         ELSE \* a fatal alert, or close_notify before the handshake ends: an error, no alert
              /\ AcceptWith(v0, v, r, prot)
              /\ sv' = [Consumed(v) EXCEPT !.err = TRUE, !.wantsBudget = FALSE]
              /\ UNCHANGED <<q, ssent, encLog, sdue>>
              /\ ghost' = [ghost EXCEPT !.lastStep = "accept"]
    [] r.t = "app" ->
         IF v.finR THEN acc(Consumed(v)) ELSE un
    [] r.t = "hs" ->
         CASE v.phase = "ch" /\ r.k = "hs" ->
                acc([Consumed(v) EXCEPT !.phase = IF V = "1.3" THEN "hs" ELSE "hs1",
                                        !.pc = "flight",
                                        !.re = IF V = "1.3" THEN R!RecvEpoch(r) ELSE 0,
                                        !.rs = 0,
                                        !.trial = V = "1.3" /\ R!TrialAfter(r)])
           [] v.phase = "hs" /\ r.k = "fin" ->
                acc([Consumed(v) EXCEPT !.phase = "open", !.finR = TRUE, !.re = 3, !.rs = 0])
           [] v.phase = "hs1" /\ r.k = "fin" /\ v.re = 3 ->
                acc([Consumed(v) EXCEPT !.phase = "open", !.finR = TRUE, !.pc = "flight"])
           [] v.phase = "open" /\ V = "1.3" /\ r.k \in {"ku", "kureq"} ->
                \* handle_key_update: a reply (once), then the new read keys
                LET reply == r.k = "kureq" /\ v.kuQ = None
                    v1 == [Consumed(v) EXCEPT !.re = @ + 1, !.rs = 0]
                IN /\ AcceptWith(v0, v1, r, prot)
                   /\ sdue' = IF reply THEN sdue \cup {Len(ssent)} ELSE sdue
                   /\ UNCHANGED <<q, ssent>>
                   /\ IF ~reply
                      THEN /\ sv' = [v1 EXCEPT !.wantsBudget = FALSE]
                           /\ UNCHANGED encLog
                           /\ ghost' = [ghost EXCEPT !.lastStep = "accept"]
                      ELSE \E payOK \in (IF ReserveStep THEN {TRUE} ELSE BOOLEAN):
                             IF ~payOK
                             THEN /\ sv' = [v1 EXCEPT !.unpaid = TRUE, !.err = TRUE,
                                                      !.wantsBudget = FALSE]
                                  /\ UNCHANGED encLog
                                  /\ ghost' = [ghost EXCEPT !.budgetFail = TRUE, !.lastStep = "accept"]
                             ELSE LET ku == Enc(v1, "hs", "ku", "S", "S", -2, 0) IN
                                  /\ sv' = [v1 EXCEPT !.kuQ = ku, !.we = @ + 1, !.wseq = 0,
                                                      !.wantsBudget = FALSE]
                                  /\ encLog' = Append(encLog, <<ku.e, ku.n>>)
                                  /\ ghost' = [ghost EXCEPT !.lastStep = "accept"]
           [] OTHER -> un

\* The record after the held handshake parts, once it passed the record
\* layer (v: read state after it, prot: it was decrypted).
AfterLayer(v0, v, r, prot) ==
  CASE v.hsHeld /\ r.t # "hs" ->
         FailWith(v0, r, prot, "none")    \* MessageInterleavedWithHandshakeMessage
    [] r.t = "hs" /\ r.k = "frag" ->
         /\ AcceptWith(v0, [Consumed(v) EXCEPT !.hsHeld = TRUE], r, prot)
         /\ sv' = [Consumed(v) EXCEPT !.hsHeld = TRUE, !.wantsBudget = FALSE]
         /\ UNCHANGED <<q, ssent, encLog, sdue>>
         /\ ghost' = [ghost EXCEPT !.lastStep = "accept"]
    [] r.t = "hs" ->
         \* the message is whole: trial decryption ends (finish_trial_decryption)
         Message(v0, [v EXCEPT !.hsHeld = FALSE, !.trial = FALSE], r, prot)
    [] OTHER -> Message(v0, v, r, prot)

\* A refusal before the record was taken: the record stays, wants_budget.
RefuseWith(v, name) ==
  /\ sv' = [v EXCEPT !.wantsBudget = TRUE]
  /\ Step(name)
  /\ UNCHANGED <<cwire, fails, q, ssent, sacc, plainQ, encLog, sdue>>

\* The record failed decryption while rejected early data is skipped.
TrialSkip(v, r) ==
  IF v.hsHeld /\ FailTrialWhenJoining
  THEN FailWith(v, r, TRUE, "none")      \* RejectedEarlyDataInterleavedWithHandshakeMessage
  ELSE LET v1 == [v EXCEPT !.allow = @ - 1] IN
       \/ \* the skip is recorded: the record leaves the buffer (add_discard)
          /\ sv' = [Consumed(v1) EXCEPT !.wantsBudget = FALSE]
          /\ cwire' = Tail(cwire)
          /\ ghost' = [ghost EXCEPT !.charges = @ + 1, !.skipped = @ + 1,
                                    !.skipHeld = @ \/ v.hsHeld, !.lastStep = "skip"]
          /\ UNCHANGED <<fails, q, ssent, sacc, plainQ, encLog, sdue>>
       \/ \* another whole record follows in the buffer, and reserve_plaintext
          \* refuses it in the same pass: the skip is not recorded, but the
          \* trial allowance was charged
          /\ v.nb >= 2
          /\ sv' = [v1 EXCEPT !.wantsBudget = TRUE]
          /\ ghost' = [ghost EXCEPT !.charges = @ + 1, !.lastStep = "refuse_plain"]
          /\ UNCHANGED <<cwire, fails, q, ssent, sacc, plainQ, encLog, sdue>>

\* process_more_input for record r with the reserve_step room charged.
Layer(v, r) ==
  LET hdr == HeaderAlert(r)
      decrypting == v.re > 0
      ok == r.a /\ r.e = v.re /\ r.n = v.rs
  IN
  CASE hdr # "ok" -> FailWith(v, r, FALSE, hdr)
    [] Outer(r) = "ccs" /\ ~v.hsHeld ->
         \* allowed plaintext: no decryption
         IF CcsSizeCheck /\ R!Ord[r.len] > 2 THEN FailWith(v, r, FALSE, "record_overflow")
         ELSE AfterLayer(v, v, r, FALSE)
    [] V = "1.3" /\ decrypting /\ CiphertextLimit13 /\ R!Ord[r.len] >= 4 ->
         FailWith(v, r, TRUE, "record_overflow")
    [] decrypting ->
         \E plainOK \in BOOLEAN:
           IF ReserveBeforeDecrypt /\ ~plainOK THEN RefuseWith(v, "refuse_plain")
           ELSE IF ok
           THEN IF r.pl = "O" THEN FailWith(v, r, TRUE, "record_overflow")
                ELSE LET v1 == [v EXCEPT !.rs = @ + 1] IN
                     IF ~plainOK THEN RefuseWith(v1, "refuse_plain")
                     ELSE AfterLayer(v, v1, r, TRUE)
           ELSE IF v.trial /\ v.allow > 0 THEN TrialSkip(v, r)
           ELSE FailWith(v, r, TRUE, "bad_record_mac")
    [] OTHER ->
         IF PlaintextLimit /\ R!Ord[r.len] > 2 THEN FailWith(v, r, FALSE, "record_overflow")
         ELSE AfterLayer(v, v, r, FALSE)

Process ==
  /\ sv.pc \in {"idle", "read"} /\ ~sv.err /\ sv.nb >= 1
  /\ UNCHANGED <<cst, csent, cacc, cgot, cdue, forged, bad, outS, taken>>
  /\ IF sv.unpaid
     THEN /\ sv' = [sv EXCEPT !.err = TRUE, !.pc = "idle"]
          /\ Step("fail_unpaid")
          /\ UNCHANGED <<cwire, fails, q, ssent, sacc, plainQ, encLog, sdue>>
     ELSE \E stepOK \in BOOLEAN:
            IF ~stepOK THEN RefuseWith([sv EXCEPT !.pc = "idle"], "refuse_step")
            ELSE Layer([sv EXCEPT !.pc = "idle"], Head(cwire))

-----------------------------------------------------------------------------
(* The server's handshake flight, emitted once the code reaches it *)

ServerScript == R!Script("S")

Flight ==
  /\ sv.pc = "flight" /\ ~Dead
  /\ LET i == sv.fl
         step == ServerScript[i]
         r == Enc(sv, step.t, step.k, "S", "S", step.ne, 0)
         last == i = Len(ServerScript) \/ (V = "1.2" /\ i = 1)
     IN \E o \in SendPaid(sv, r):
          /\ sv' = [o.v EXCEPT !.pc = IF last THEN "idle" ELSE "flight", !.fl = i + 1,
                               !.mayWrite = @ \/ i = Len(ServerScript)]
          /\ Queue(o.out) /\ encLog' = encLog \o o.enc
          /\ ghost' = [Gh(ghost, sv.unpaid, o.out) EXCEPT !.lastStep = "flight"]
  /\ UNCHANGED <<cvars, fails, outS, plainQ, sacc, taken, sdue>>

-----------------------------------------------------------------------------
(* Writer::write of one chunk, as the layer's Write command calls it *)

\* send_appdata_encrypt stops before a record that would take the last
\* sequence number the keys allow, asking for a key update first.
Stops(v) == V = "1.3" /\ v.wseq > 0 /\ v.wseq + 1 >= SoftLimit

\* send_plain of one record's worth (pl), the KeyUpdate waiting already queued.
WriteRecord(pl) ==
  IF sv.unpaid
  THEN /\ sv' = [sv EXCEPT !.err = TRUE, !.pc = "idle"]    \* check_error
       /\ Step("fail_unpaid")
       /\ UNCHANGED <<q, ssent, encLog>>
  ELSE IF Stops(sv)
  THEN /\ sv' = [sv EXCEPT !.pendRefresh = TRUE, !.pc = "refresh", !.wpl = pl]
       /\ Step("write_stop")
       /\ UNCHANGED <<q, ssent, encLog>>
  ELSE \E payOK \in BOOLEAN:
         IF ~payOK
         THEN \* nothing taken: the layer keeps the chunk and comes back
              /\ sv' = [sv EXCEPT !.pc = IF sv.pendRefresh THEN "refresh" ELSE "idle",
                                  !.wpl = "none"]
              /\ Step("refuse_pay")
              /\ UNCHANGED <<q, ssent, encLog>>
         ELSE \E o \in SendPaid(sv, Enc(sv, "app", "data", pl, IF pl = "F" THEN "O1" ELSE "S", -1, sv.appW + 1)):
                LET sentIt == \E i \in DOMAIN o.out : o.out[i].t = "app" IN
                /\ sv' = [o.v EXCEPT !.appW = IF sentIt THEN @ + 1 ELSE @,
                                     !.pc = IF o.v.pendRefresh THEN "refresh" ELSE "idle",
                                     !.wpl = "none"]
                /\ Queue(o.out) /\ encLog' = encLog \o o.enc
                /\ ghost' = [Gh(ghost, sv.unpaid, o.out) EXCEPT !.lastStep = "write"]

\* The layer's Write: writer().write of one chunk (check_error first).
Write ==
  /\ sv.pc = "idle" /\ ~sv.err /\ ~sv.closing /\ sv.finR /\ sv.mayWrite
  /\ q = <<>> /\ sv.appW < MaxAppS
  /\ \E pl \in AppPls \ {"Z"}:
       IF sv.unpaid
       THEN /\ sv' = [sv EXCEPT !.err = TRUE]
            /\ Step("fail_unpaid")
       ELSE /\ sv' = [sv EXCEPT !.pc = "write", !.wpl = pl]
            /\ Step("write_start")
  /\ UNCHANGED <<cvars, fails, outS, plainQ, sacc, taken, sdue, q, ssent, encLog>>

\* buffer_plaintext first calls perhaps_write_key_update: a KeyUpdate
\* waiting to go is queued before anything is paid for, so it goes even
\* if the budget then refuses the record.
WriteKU ==
  /\ sv.pc \in {"write", "rewrite"} /\ sv.kuQ # None
  /\ \E kuOK \in Pushes:
       /\ sv' = [sv EXCEPT !.kuQ = None, !.unpaid = ~kuOK]
       /\ Queue(IF kuOK THEN <<sv.kuQ>> ELSE <<>>)
       /\ ghost' = [ghost EXCEPT !.lastStep = "write_ku"]
  /\ UNCHANGED <<cvars, fails, outS, plainQ, sacc, taken, sdue, encLog>>

\* The record of the write (pc "write"), or of its rest after a key
\* update asked for by a stop (pc "rewrite", send_plaintext's loop).
WriteRec ==
  /\ sv.pc \in {"write", "rewrite"} /\ sv.kuQ = None
  /\ WriteRecord(sv.wpl)
  /\ UNCHANGED <<cvars, fails, outS, plainQ, sacc, taken, sdue>>

\* maybe_refresh_traffic_keys: a key update request with control room
\* charged first; refused, it stays pending.
Refresh ==
  /\ sv.pc = "refresh"
  /\ IF ~sv.pendRefresh
     THEN /\ sv' = [sv EXCEPT !.pc = "idle", !.wpl = "none"]
          /\ Step("refresh_none")
          /\ UNCHANGED <<q, ssent, encLog>>
     ELSE \E roomOK \in BOOLEAN:
            IF ~roomOK
            THEN /\ sv' = [sv EXCEPT !.pc = "idle", !.wpl = "none"]
                 /\ Step("refuse_room")
                 /\ UNCHANGED <<q, ssent, encLog>>
            ELSE LET v == [sv EXCEPT !.pendRefresh = FALSE] IN
                 \E o \in SendPaid(v, Enc(v, "hs", "kureq", "S", "S", -2, 0)):
                   LET v2 == [o.v EXCEPT !.we = v.we + 1, !.wseq = 0, !.pendRefresh = FALSE] IN
                   /\ sv' = [v2 EXCEPT !.err = @ \/ v2.unpaid,
                                       !.pc = IF sv.wpl # "none" /\ ~v2.unpaid THEN "rewrite" ELSE "idle",
                                       !.wpl = IF ~v2.unpaid THEN @ ELSE "none"]
                   /\ Queue(o.out) /\ encLog' = encLog \o o.enc
                   /\ ghost' = [Gh(ghost, sv.unpaid, o.out) EXCEPT !.lastStep = "refresh"]
  /\ UNCHANGED <<cvars, fails, outS, plainQ, sacc, taken, sdue>>

\* The layer's End: send_close_notify with control room charged first.
Close ==
  /\ sv.pc = "idle" /\ ~sv.err /\ ~sv.closing /\ sv.finR /\ sv.mayWrite
  /\ IF sv.sentFatal
     THEN /\ sv' = [sv EXCEPT !.closing = TRUE]
          /\ Step("close") /\ UNCHANGED <<q, ssent, encLog>>
     ELSE \E roomOK \in BOOLEAN:
            IF ~roomOK
            THEN /\ Step("refuse_room") /\ UNCHANGED <<sv, q, ssent, encLog>>
            ELSE LET v == [sv EXCEPT !.sentFatal = TRUE, !.closeSent = TRUE, !.closing = TRUE] IN
                 IF v.unpaid
                 THEN /\ sv' = v /\ Step("close") /\ UNCHANGED <<q, ssent, encLog>>
                 ELSE \E o \in SendPaid(v, Enc(v, "alert", "close", "S", "S", -1, 0)):
                        /\ sv' = o.v
                        /\ Queue(o.out) /\ encLog' = encLog \o o.enc
                        /\ ghost' = [Gh(ghost, sv.unpaid, o.out) EXCEPT !.lastStep = "close"]
  /\ UNCHANGED <<cvars, fails, outS, plainQ, sacc, taken, sdue>>

\* The layer writes the next queued record below.
Flush ==
  /\ q # <<>>
  /\ outS' = Append(outS, Head(q)) /\ q' = Tail(q)
  /\ Step("flush")
  /\ UNCHANGED <<cvars, fails, sv, plainQ, ssent, sacc, taken, sdue, encLog>>

\* The layer takes the first plaintext chunk up (take_first_chunk).
Take ==
  /\ plainQ # <<>>
  /\ taken' = Append(taken, Head(plainQ)) /\ plainQ' = Tail(plainQ)
  /\ Step("take")
  /\ UNCHANGED <<cvars, fails, sv, q, outS, ssent, sacc, sdue, encLog>>

ServerNext == ReadRefuse \/ ReadWaiting \/ Read \/ Process \/ Flight \/ Write
              \/ WriteKU \/ WriteRec \/ Refresh \/ Close \/ Flush \/ Take

-----------------------------------------------------------------------------

Init ==
  /\ cwire = <<>> /\ cst = R!St0 /\ csent = <<>> /\ cacc = <<>> /\ cgot = <<>>
  /\ cdue = {} /\ forged = 0 /\ bad = 0 /\ fails = <<>>
  /\ sv = [phase |-> "ch", re |-> 0, rs |-> 0, trial |-> FALSE, allow |-> Allowance,
           hsHeld |-> FALSE, finR |-> FALSE, we |-> 0, wseq |-> 0, mayWrite |-> FALSE,
           kuQ |-> None, unpaid |-> FALSE, err |-> FALSE, sentFatal |-> FALSE,
           closeSent |-> FALSE, closeR |-> FALSE, pendRefresh |-> FALSE,
           wantsBudget |-> FALSE, nb |-> 0, part |-> FALSE, pc |-> "idle",
           wpl |-> "none", closing |-> FALSE, appW |-> 0, fl |-> 1]
  /\ q = <<>> /\ outS = <<>> /\ plainQ = <<>>
  /\ ssent = <<>> /\ sacc = <<>> /\ taken = <<>> /\ sdue = {} /\ encLog = <<>>
  /\ ghost = [afterGap |-> FALSE, budgetFail |-> FALSE, waitFail |-> FALSE,
              skipHeld |-> FALSE, charges |-> 0, skipped |-> 0, lastStep |-> "init"]

Next == (ClientNext /\ ghost' = [ghost EXCEPT !.lastStep = "peer"]) \/ ServerNext

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties *)

\* The RFC's, through the mapping.
AuthBeforeDeliver == R!AuthBeforeDeliver
NonceUnique == R!NonceUnique
NoGap == R!NoGap
KUOrder == R!KUOrder
KUReplyFirst == R!KUReplyFirst
NoSendAfterClose == R!NoSendAfterClose
IgnoreAfterCloseProp == R!IgnoreAfterCloseProp
FatalEnds == R!FatalEnds
AccLegal == R!AccLegal
RightAlert == R!RightAlert
NoFalseReject == R!NoFalseReject
HonestWriter == R!HonestWriter

\* The code refines the RFC.
Refines == R!Spec

\* No keys and sequence number encrypt two records, queued or not.
EncUnique == \A i, j \in DOMAIN encLog : i # j => encLog[i] # encLog[j]

\* A record encrypted and not queued (but the KeyUpdate waiting to go)
\* means the connection has failed; and nothing is queued after that.
HoleMeansFailed ==
  \A i \in DOMAIN encLog :
    \/ \E j \in DOMAIN ssent : <<ssent[j].e, ssent[j].n>> = encLog[i]
    \/ sv.kuQ # None /\ <<sv.kuQ.e, sv.kuQ.n>> = encLog[i]
    \/ sv.unpaid
NothingAfterGap == ~ghost.afterGap

\* A refused growth changes no protocol state: sequence numbers, keys,
\* queued output, buffered input, plaintext (only wants_budget).
RefusalChangesNothing ==
  [][ghost'.lastStep \in Refusals => UNCHANGED Proto]_vars

\* A refusal of a charge made before anything irreversible never fails
\* the connection: everything refused can be retried.
RefusalsRetry == ~ghost.budgetFail

\* The layer never reads while a whole record waits (read would fail).
NoWaitingRead == ~ghost.waitFail

\* One record per read: at most one whole record is ever buffered past
\* the handshake parts being joined, so a pass sees at most one.
AtMostOneRecord == sv.nb <= 1

\* The skip path's add_discard assumes nothing before the skipped record
\* is still in use: no handshake parts are held when a record is skipped.
SkipDiscardsSkipped == ~ghost.skipHeld

\* Each skipped record is charged once against the early data allowance.
TrialChargedOnce == ghost.charges = ghost.skipped

=============================================================================
