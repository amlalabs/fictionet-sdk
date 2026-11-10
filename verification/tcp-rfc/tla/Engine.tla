------------------------------- MODULE Engine -------------------------------
(* The smoltcp socket that Fictionet's TCP runs on, at the level of its    *)
(* fields, and the check that it refines Rfc9293: every step it takes is a *)
(* step RFC 9293 allows, with the departures the README names.             *)
(*                                                                         *)
(* Lines are smoltcp/src/socket/tcp.rs at the head of comp/fv-tcp:         *)
(*   Process        `process`, from the repeated-SYN test to the reply     *)
(*                  (1857-2330): every branch below names its arm          *)
(*   AckSyn         `acknowledges_syn` (2352)                              *)
(*   InWindow       `segment_in_window` (1812-1840)                        *)
(*   WinEnd         `receive_window_end` (1121-1127)                       *)
(*   Remember       `remember_window` (1129-1137), called by `ack_reply`   *)
(*                  (1711) and by `dispatch` for every segment (2908)      *)
(*   NotAccepted    `accepts` (1780) and the interface's answer for no     *)
(*                  socket, `rst_reply` (smoltcp/src/iface/interface/      *)
(*                  tcp.rs 36-41, socket/tcp.rs 1667)                      *)
(*   Close, Abort   `close` (1407), `abort` (1460)                         *)
(*   Listen, Connect `listen` (1313), `connect` (1361) through `reset`     *)
(*   Transmit       `dispatch`'s advance of `local_seq_max` (2881)         *)
(*   Expire         `forget_connection` from `dispatch` (2654)             *)
(* SeqNumber's order (smoltcp/src/wire/tcp.rs 94-99) is CLt and friends:   *)
(* the wrapping difference as a signed number, with no order at all at     *)
(* exactly half the space.                                                 *)
(*                                                                         *)
(* Fields kept: state, listen_endpoint (as `passive`), local_seq_no (una), *)
(* local_seq_max (smax), tx_buffer.len() (txlen), closed_before_syn_ack    *)
(* (cbsa), remote_seq_no (rsn), rx_buffer.len() (rxlen), remote_win_end    *)
(* (winEnd), the assembler (asm, offsets from RCV.NXT), rx_fin_received    *)
(* (rfin), and whether the SYN went out with a window (synWin: the         *)
(* remote_last_win SYN-SENT reads). Left out: timers, RTT, congestion,     *)
(* remote_last_seq (only retransmission reads it), window scaling (shift   *)
(* 0), options, timestamps, SACK, segment options, the peer's window       *)
(* (the endpoint may always send). `hq` is a history variable: the octets  *)
(* the user queued, which Rfc9293's `queued` needs and the socket forgets  *)
(* as they are acknowledged.                                               *)
(*                                                                         *)
(* The three Fix constants are TRUE for the code; each control sets one    *)
(* FALSE to put back the code as it was before the fix of this pass.       *)
EXTENDS Integers, FiniteSets

CONSTANTS N, Cap, Data, MaxText, IRS, RepeatSynAck,
          FixUnorderedAck,   \* 8b882f969: an ACK half the space away is challenged
          FixBareFin,        \* 8b882f969: an unacceptable bare FIN is ACKed at once
          FixSynSentFin,     \* 5a652ed66: a bad ACK with FIN in SYN-SENT is reset
          FixSecondFin,      \* a FIN after the peer's FIN drops nothing
          FixFinBoundsText,  \* text held past a FIN is not taken with it
          FixTimeWaitAck,    \* TIME-WAIT answers a closed window's segment
          \* The departures Rfc9293 is instantiated with; TRUE for the code.
          SpecAckBeforeSeqInSynReceived, SpecChallengeSynInSynReceived,
          SpecNoAckDroppedFirst, SpecAckCheckedBeforeSeq,
          SpecRateLimitEmptyOutOfWindow, SpecEmptyAckAtRightEdge,
          SpecFinAtRightEdge, SpecOpenInTimeWait

VARIABLES state, passive, una, smax, txlen, cbsa, rsn, rxlen, winEnd, asm,
          rfin, synWin, hq, out, panicked, seg

cvars == <<state, passive, una, smax, txlen, cbsa, rsn, rxlen, winEnd, asm,
           rfin, synWin, hq, out, panicked, seg>>

Seq == 0..(N - 1)
None == -1
Half == N \div 2
Add(a, k) == (a + k) % N
Off(a, b) == (b - a) % N

\* SeqNumber's PartialOrd: the wrapping difference a - b read as signed;
\* no order at exactly half the space.
D(a, b) == (a - b) % N
CLt(a, b) == D(a, b) > Half
CGt(a, b) == D(a, b) > 0 /\ D(a, b) < Half
CLe(a, b) == a = b \/ CLt(a, b)
CGe(a, b) == a = b \/ CGt(a, b)
CMax(a, b) == IF CGt(a, b) THEN a ELSE b
CMin(a, b) == IF CLt(a, b) THEN a ELSE b
\* `a - b` into usize panics unless a is at or after b.
SubOK(a, b) == D(a, b) < Half

Controls == {"NONE", "SYN", "FIN", "RST"}
Segments == [seq : Seq, ack : Seq \cup {None}, ctl : Controls,
             len : 0..MaxText]
Peer == {s \in Segments : s.ctl \in {"RST", "SYN"} => s.len = 0}
CtlLen(s) == IF s.ctl \in {"SYN", "FIN"} THEN 1 ELSE 0

NoOut == [k |-> "None", s |-> None, a |-> None]
NoSeg == [seq |-> None, ack |-> None, ctl |-> "NONE", len |-> 0]
AckOut(sq, ak) == [k |-> "Ack", s |-> sq, a |-> ak]
\* rst_reply: <SEQ=SEG.ACK><RST>, or <SEQ=0><ACK=SEG.SEQ+SEG.LEN><RST,ACK>.
RstOf(s) == IF s.ack # None THEN [k |-> "Rst", s |-> s.ack, a |-> None]
            ELSE [k |-> "RstAck", s |-> 0, a |-> Add(s.seq, s.len + CtlLen(s))]

RcvNxt == Add(rsn, rxlen)
\* receive_window_end: the furthest edge advertised, within the buffer,
\* and never behind RCV.NXT.
WinEnd == CMax(CMin(IF winEnd = None THEN RcvNxt ELSE winEnd, Add(rsn, Cap)),
               RcvNxt)
\* remember_window after an ACK of RCV.NXT with the window the buffer has:
\* min(ack + (cap - rxlen), rsn + cap) = rsn + cap.
Remember(r) == Add(r, Cap)
Min2(a, b) == IF a < b THEN a ELSE b

SynUnacked == state \in {"SynSent", "SynReceived"}
              \/ (state \in {"FinWait1", "Closing"} /\ cbsa)
FinSent == state \in {"FinWait1", "LastAck", "Closing"}
AckSyn(a) == a = Add(una, 1) /\ CLe(a, smax)

TypeOK ==
  /\ state \in {"Closed", "Listen", "SynSent", "SynReceived", "Established",
                "FinWait1", "FinWait2", "CloseWait", "Closing", "LastAck",
                "TimeWait"}
  /\ passive \in BOOLEAN /\ una \in Seq /\ smax \in Seq /\ txlen \in 0..Data
  /\ cbsa \in BOOLEAN /\ rsn \in Seq /\ rxlen \in 0..Cap
  /\ winEnd \in Seq \cup {None} /\ asm \subseteq 1..(Cap - 1)
  /\ rfin \in BOOLEAN /\ synWin \in BOOLEAN /\ hq \in 0..Data
  /\ panicked \in BOOLEAN

\* No step of the socket may panic (a SeqNumber subtraction that underflows,
\* or acknowledging more than tx_buffer holds).
NoPanic == ~panicked

---------------------------------------------------------------------------
(* Arrival.                                                               *)

Unchanged == UNCHANGED <<state, passive, una, smax, txlen, cbsa, rsn, rxlen,
                         winEnd, asm, rfin, synWin, hq, panicked>>
Drop == out' = NoOut /\ Unchanged
\* ack_reply: <SEQ=local_seq_max><ACK=RCV.NXT>, and the window remembered.
AckNow == /\ out' = AckOut(smax, RcvNxt) /\ winEnd' = Remember(rsn)
          /\ UNCHANGED <<state, passive, una, smax, txlen, cbsa, rsn, rxlen,
                         asm, rfin, synWin, hq, panicked>>
\* challenge_ack_reply: the same, unless the rate limit holds it back.
Challenge == AckNow \/ Drop

\* The interface's answer when no socket accepts the segment.
NotAccepted(s) == out' = (IF s.ctl = "RST" THEN NoOut ELSE RstOf(s)) /\ Unchanged

\* segment_in_window, with the segment's end counting a FIN.
InWindow(s, ws, we) ==
  LET ss == s.seq
      se == Add(s.seq, s.len + (IF s.ctl = "FIN" THEN 1 ELSE 0))
  IN
  IF ss = se /\ se = Add(ws, N - 1) THEN FALSE
  ELSE CASE ss = se /\ ws = we -> ws = ss
         [] ss = se -> CLe(ws, ss) /\ (CLt(ss, we) \/ (ss = we /\ s.ctl = "NONE"))
         [] ws = we -> ss = ws
         [] OTHER -> (CLe(ws, ss) /\ CLt(ss, we)) \/ (CLt(ws, se) /\ CLe(se, we))

\* The longest run 0, 1, ... of offsets in S.
RECURSIVE Run(_, _)
Run(S, i) == IF i \in S THEN 1 + Run(S, i + 1) ELSE 0

\* After the state match: the ACK, the text, the reply (2187-2330).
\* st1 is the state the match chose; rsn1, rfin1 what it did to them.
Finish(s, st1, rsn1, rfin1, ackLen, ws, payOff, payLen, probe) ==
  LET oldAck == s.ack # None /\ CLt(s.ack, una)
      newAck == s.ack # None /\ ~oldAck
      una1 == IF newAck THEN s.ack ELSE una
      \* dequeue_allocated asserts ackLen <= txlen (ring_buffer.rs 298); past
      \* it the socket panics, which NoPanic reports.
      txlen1 == IF ackLen > txlen THEN 0 ELSE txlen - ackLen
      cbsa1 == IF newAck /\ SynUnacked /\ CGt(s.ack, una) THEN FALSE ELSE cbsa
      \* add_then_remove_front at payOff, then enqueue the contiguous front.
      \* Offsets are from ws; the FIN, if taken, moved rsn but not ws.
      pos == {payOff + i : i \in {j \in 0..(MaxText - 1) : j < payLen}}
      all == asm \cup pos
      contig == Run(all, 0)
      \* The fix: a FIN taken ends the stream at its own sequence number.
      take == IF FixFinBoundsText /\ rfin1 /\ ~rfin THEN Min2(contig, payOff + payLen)
              ELSE contig
      asm1 == IF FixFinBoundsText /\ rfin1 /\ ~rfin THEN {}
              ELSE {a - contig : a \in {b \in all : b >= contig}}
      rxlen1 == rxlen + take
      reply == IF payLen = 0 THEN probe ELSE (asm1 # {} \/ asm # {})
  IN
  /\ state' = st1 /\ una' = una1 /\ txlen' = txlen1 /\ cbsa' = cbsa1
  /\ rsn' = rsn1 /\ rfin' = rfin1
  /\ rxlen' = (IF payLen = 0 THEN rxlen ELSE rxlen1)
  /\ asm' = (IF payLen = 0 THEN asm ELSE asm1)
  /\ panicked' = (panicked \/ ackLen > txlen \/ (payLen > 0 /\ rxlen1 > Cap))
  /\ IF reply
       THEN /\ out' = AckOut(smax, Add(rsn', rxlen'))
            /\ winEnd' = Add(rsn', Cap)
       ELSE out' = NoOut /\ UNCHANGED winEnd
  /\ UNCHANGED <<passive, smax, synWin, hq>>


Process(s) ==
  LET sentSyn == SynUnacked
      sentFin == FinSent
      ws == RcvNxt
      we == WinEnd
      ss == s.seq
      seEnd == Add(s.seq, s.len)       \* segment_end: text only
  IN
  CASE \* 1857: a repeated SYN in SYN-RECEIVED, with the Linux setting.
       RepeatSynAck /\ state = "SynReceived" /\ s.ctl = "SYN" /\ s.ack = None
         /\ Add(s.seq, 1) = rsn -> Drop
       \* 1867: a SYN in any state but LISTEN and SYN-SENT.
    [] s.ctl = "SYN" /\ state \notin {"Listen", "SynSent"} -> Challenge
       \* 1882-1934: the ACK checks.
    [] state = "SynSent" /\ s.ctl = "RST" /\ s.ack = None -> Drop
    [] state = "SynSent" /\ s.ctl = "RST" /\ ~AckSyn(s.ack) -> Drop
    [] state = "SynSent" /\ s.ctl = "SYN" /\ s.ack # None /\ ~AckSyn(s.ack) ->
         out' = RstOf(s) /\ Unchanged
    [] state = "SynSent" /\ s.ctl \in {"NONE", "FIN"} /\ s.ack # None
         /\ (s.ctl = "NONE" \/ FixSynSentFin) ->
         IF AckSyn(s.ack) THEN Drop ELSE out' = RstOf(s) /\ Unchanged
    [] state = "SynSent" /\ s.ctl \notin {"SYN", "RST"} -> Drop
    [] s.ctl # "RST" /\ s.ack = None /\ state \notin {"Listen", "SynSent"} -> Drop
    [] state = "SynReceived" /\ s.ctl # "RST" /\ ~AckSyn(s.ack) ->
         out' = RstOf(s) /\ Unchanged
    [] s.ctl # "RST" /\ state \notin {"Listen", "SynSent", "SynReceived"}
         /\ (IF FixUnorderedAck THEN ~CLe(s.ack, smax)
             ELSE CGe(s.ack, una) /\ CGt(s.ack, smax)) -> Challenge
       \* 1947: a RST not exactly at RCV.NXT.
    [] s.ctl = "RST" /\ state # "SynSent" /\ ss # ws ->
         IF CLe(ws, ss) /\ CLt(ss, we) THEN Challenge ELSE Drop
       \* 1961-2003: outside the window.
    [] s.ctl # "RST" /\ state \notin {"Listen", "SynSent"}
         /\ ~InWindow(s, ws, we) ->
         IF (IF FixBareFin THEN s.len + CtlLen(s) > 0 ELSE s.len > 0)
            /\ s.ctl \in {"NONE", "FIN"}
           THEN AckNow ELSE Challenge
    [] OTHER ->
       LET inWin == s.ctl # "RST" /\ state \notin {"Listen", "SynSent"}
           oS == CMax(ws, ss)
           oE == CMin(we, seEnd)
           payLen == IF inWin /\ ~rfin THEN D(oE, oS) ELSE 0
           payOff == IF inWin /\ ~rfin THEN D(oS, ws) ELSE 0
           probe == inWin /\ ws = we /\ s.len > 0
           txStart == Add(una, IF sentSyn THEN 1 ELSE 0)
           rawLen == IF s.ctl # "RST" /\ s.ack # None /\ CGe(s.ack, txStart)
                       THEN D(s.ack, txStart) ELSE 0
           ackOfFin == sentFin /\ rawLen = txlen + 1
           ackLen == IF ackOfFin THEN rawLen - 1 ELSE rawLen
           \* 2030: a FIN past a gap or past the window is ignored; with the
           \* fix, so is a FIN after the peer's FIN.
           ctl == IF s.ctl = "FIN"
                     /\ (CLt(ws, ss) \/ CGt(seEnd, we) \/ (FixSecondFin /\ rfin))
                  THEN "NONE" ELSE s.ctl
           go(st1, rsn1, rfin1) ==
             Finish(s, st1, rsn1, rfin1, ackLen, ws, payOff, payLen, probe)
       IN
       CASE \* 2039-2058: RST.
            ctl = "RST" /\ state = "Listen" -> Drop
         [] ctl = "RST" /\ state = "SynReceived" /\ passive ->
              /\ state' = "Listen" /\ rxlen' = 0 /\ rfin' = FALSE
              /\ una' = 0 /\ smax' = 0 /\ rsn' = 0 /\ txlen' = 0
              /\ cbsa' = FALSE /\ winEnd' = None /\ asm' = {} /\ synWin' = FALSE
              /\ hq' = 0 /\ out' = NoOut /\ UNCHANGED <<passive, panicked>>
         [] ctl = "RST" ->
              state' = "Closed" /\ out' = NoOut
              /\ UNCHANGED <<passive, una, smax, txlen, cbsa, rsn, rxlen, winEnd,
                             asm, rfin, synWin, hq, panicked>>
            \* 2061: LISTEN takes a SYN. The ISS is 0.
         [] state = "Listen" /\ ctl = "SYN" ->
              /\ una' = 0 /\ smax' = 0 /\ rsn' = Add(s.seq, 1)
              /\ state' = "SynReceived" /\ out' = NoOut
              /\ UNCHANGED <<passive, txlen, cbsa, rxlen, winEnd, asm, rfin,
                             synWin, hq, panicked>>
         [] state = "SynReceived" /\ ctl = "NONE" -> go("Established", rsn, rfin)
         [] state = "SynReceived" /\ ctl = "FIN" -> go("CloseWait", Add(rsn, 1), TRUE)
            \* 2090: SYN-SENT takes the peer's SYN.
         [] state = "SynSent" /\ ctl = "SYN" ->
              LET r1 == Add(s.seq, 1) IN
              /\ rsn' = r1
              /\ winEnd' = Add(r1, IF synWin THEN Cap ELSE 0)
              /\ state' = (IF s.ack # None THEN "Established" ELSE "SynReceived")
              /\ una' = (IF s.ack # None THEN s.ack ELSE una)
              /\ out' = NoOut
              /\ UNCHANGED <<passive, smax, txlen, cbsa, rxlen, asm, rfin, synWin,
                             hq, panicked>>
         [] state = "Established" /\ ctl = "NONE" -> go("Established", rsn, rfin)
         [] state = "Established" /\ ctl = "FIN" -> go("CloseWait", Add(rsn, 1), TRUE)
         [] state = "FinWait1" /\ ctl = "NONE" ->
              go(IF ackOfFin THEN "FinWait2" ELSE "FinWait1", rsn, rfin)
         [] state = "FinWait1" /\ ctl = "FIN" ->
              go(IF ackOfFin THEN "TimeWait" ELSE "Closing", Add(rsn, 1), TRUE)
         [] state = "FinWait2" /\ ctl = "NONE" -> go("FinWait2", rsn, rfin)
         [] state = "FinWait2" /\ ctl = "FIN" -> go("TimeWait", Add(rsn, 1), TRUE)
         [] state = "Closing" /\ ctl = "NONE" ->
              go(IF ackOfFin THEN "TimeWait" ELSE "Closing", rsn, rfin)
         [] state = "CloseWait" /\ ctl = "NONE" -> go("CloseWait", rsn, rfin)
         [] FixTimeWaitAck /\ state = "TimeWait" /\ ctl = "NONE" -> go("TimeWait", rsn, rfin)
         [] state = "LastAck" /\ ctl = "NONE" ->
              go(IF ackOfFin THEN "Closed" ELSE "LastAck", rsn, rfin)
         [] OTHER -> Drop

Arrive(s) ==
  /\ state # "Closed"
  /\ s \in Peer
  /\ state \in {"Listen", "SynSent"} /\ s.ctl = "SYN" => s.seq = IRS
  /\ IF state = "Listen" /\ (s.ack # None \/ s.ctl = "RST")
       THEN NotAccepted(s)
       ELSE Process(s)

---------------------------------------------------------------------------
(* Sending, and the user.                                                 *)

\* dispatch sends the next SYN, octet or FIN, and every segment but the
\* first SYN carries an ACK whose window it remembers.
Transmit ==
  LET k == Off(una, smax)
      synDue == SynUnacked /\ smax = una
      dataDue == /\ state \in {"Established", "CloseWait", "FinWait1", "LastAck", "Closing"}
                 /\ ~SynUnacked /\ k < txlen
      finDue == /\ FinSent /\ ~SynUnacked /\ k = txlen
  IN
  /\ synDue \/ dataDue \/ finDue
  /\ smax' = Add(smax, 1)
  /\ IF state = "SynSent"
       THEN synWin' = TRUE /\ UNCHANGED winEnd
       ELSE winEnd' = Add(rsn, Cap) /\ UNCHANGED synWin
  /\ out' = NoOut
  /\ UNCHANGED <<state, passive, una, txlen, cbsa, rsn, rxlen, asm, rfin, hq,
                 panicked>>

\* A pure ACK or window update from dispatch.
Advertise ==
  /\ state \notin {"Closed", "Listen", "SynSent"}
  /\ winEnd' = Add(rsn, Cap) /\ out' = NoOut
  /\ UNCHANGED <<state, passive, una, smax, txlen, cbsa, rsn, rxlen, asm, rfin,
                 synWin, hq, panicked>>

\* reset() of listen and connect: everything but the state starts again.
Restart(st, p) ==
  /\ state \in {"Closed", "TimeWait"} /\ state' = st /\ passive' = p
  /\ una' = 0 /\ smax' = 0 /\ txlen' = 0 /\ cbsa' = FALSE /\ rsn' = 0
  /\ rxlen' = 0 /\ winEnd' = None /\ asm' = {} /\ rfin' = FALSE
  /\ synWin' = FALSE /\ hq' = 0 /\ out' = NoOut /\ UNCHANGED panicked

Listen == Restart("Listen", TRUE)
Connect == Restart("SynSent", FALSE)

Send ==
  /\ state \in {"Established", "CloseWait"} /\ hq < Data
  /\ txlen' = txlen + 1 /\ hq' = hq + 1 /\ out' = NoOut
  /\ UNCHANGED <<state, passive, una, smax, cbsa, rsn, rxlen, winEnd, asm, rfin,
                 synWin, panicked>>

Receive ==
  /\ rxlen > 0 /\ rxlen' = rxlen - 1 /\ rsn' = Add(rsn, 1) /\ out' = NoOut
  /\ UNCHANGED <<state, passive, una, smax, txlen, cbsa, winEnd, asm, rfin,
                 synWin, hq, panicked>>

Close ==
  /\ state \in {"Listen", "SynSent", "SynReceived", "Established", "CloseWait"}
  /\ state' = CASE state \in {"Listen", "SynSent"} -> "Closed"
                [] state \in {"SynReceived", "Established"} -> "FinWait1"
                [] OTHER -> "LastAck"
  /\ cbsa' = (state = "SynReceived" \/ cbsa)
  /\ out' = NoOut
  /\ UNCHANGED <<passive, una, smax, txlen, rsn, rxlen, winEnd, asm, rfin,
                 synWin, hq, panicked>>

\* abort, a timeout in dispatch, and TIME-WAIT's end (forget_connection
\* keeps the octets not yet read).
Abort == /\ state # "Closed" /\ state' = "Closed" /\ out' = NoOut
         /\ UNCHANGED <<passive, una, smax, txlen, cbsa, rsn, rxlen, winEnd,
                        asm, rfin, synWin, hq, panicked>>
Expire == state = "TimeWait" /\ Abort

Init ==
  /\ state = "Closed" /\ passive = FALSE /\ una = 0 /\ smax = 0 /\ txlen = 0
  /\ cbsa = FALSE /\ rsn = 0 /\ rxlen = 0 /\ winEnd = None /\ asm = {}
  /\ rfin = FALSE /\ synWin = FALSE /\ hq = 0 /\ out = NoOut
  /\ panicked = FALSE /\ seg = NoSeg

\* `seg` names the segment of an arrival step, as in Rfc9293.
Next ==
  \/ seg' \in Peer /\ Arrive(seg')
  \/ /\ seg' = NoSeg
     /\ \/ Transmit \/ Advertise
        \/ Listen \/ Connect \/ Send \/ Receive \/ Close \/ Abort \/ Expire

CSpec == Init /\ [][Next]_cvars

\* What TLC tells states apart by: everything but the last segment and
\* reply, which no later step reads.
View == <<state, passive, una, smax, txlen, cbsa, rsn, rxlen, winEnd, asm,
          rfin, synWin, hq, panicked>>

---------------------------------------------------------------------------
(* The refinement mapping. A closed socket is the RFC's CLOSED, whatever  *)
(* its fields still hold, but for the octets not yet read.                *)

Open == state # "Closed"
M(v, dflt) == IF Open THEN v ELSE dflt

RFC == INSTANCE Rfc9293 WITH
  st <- state,
  passive <- M(passive, FALSE),
  una <- M(una, 0),
  nxt <- M(smax, 0),
  queued <- M(hq, 0),
  finQ <- M(state \in {"FinWait1", "FinWait2", "Closing", "TimeWait", "LastAck"}, FALSE),
  rnxt <- M(RcvNxt, 0),
  redge <- M(WinEnd, 0),
  rbuf <- rxlen,
  held <- M(IF rfin THEN {} ELSE {Add(RcvNxt, o) : o \in asm}, {}),
  sfin <- M(rfin, FALSE),
  out <- out,
  seg <- seg,
  RepeatSynAck <- RepeatSynAck,
  AckBeforeSeqInSynReceived <- SpecAckBeforeSeqInSynReceived,
  ChallengeSynInSynReceived <- SpecChallengeSynInSynReceived,
  NoAckDroppedFirst <- SpecNoAckDroppedFirst,
  AckCheckedBeforeSeq <- SpecAckCheckedBeforeSeq,
  RateLimitEmptyOutOfWindow <- SpecRateLimitEmptyOutOfWindow,
  EmptyAckAtRightEdge <- SpecEmptyAckAtRightEdge,
  FinAtRightEdge <- SpecFinAtRightEdge,
  OpenInTimeWait <- SpecOpenInTimeWait

Refines == RFC!Spec
=============================================================================
