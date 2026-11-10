------------------------------ MODULE Rfc9293 ------------------------------
(* One TCP endpoint as RFC 9293 describes it, written from the RFC and not *)
(* from the code: the state machine of section 3.3.2, the processing of an *)
(* arriving segment of section 3.10.7 (LISTEN 3.10.7.2, SYN-SENT 3.10.7.3, *)
(* every other state 3.10.7.4: the acceptability test, RST, SYN, ACK, text *)
(* and FIN, in that order), RFC 5961's answers to RST (3.2), SYN (4.2) and *)
(* to an ACK of data never sent (5.2, with 7's rate limit), the user calls *)
(* of 3.10.1 to 3.10.5 (OPEN, SEND, RECEIVE, CLOSE, ABORT) and the timeouts *)
(* of 3.10.8 (the user timeout and TIME-WAIT's end).                       *)
(*                                                                         *)
(* The peer is any sender: every step may bring any segment, with any      *)
(* sequence number, any acknowledgment number or none, one control (none,  *)
(* SYN, FIN or RST) and up to MaxText octets of text. That is how RFC 5961 *)
(* sees the network: the off-path attacker and the guest that knows its    *)
(* own numbers are both in this set.                                       *)
(*                                                                         *)
(* Sequence numbers are taken modulo N, as the RFC takes them modulo 2^32  *)
(* (section 3.4): every comparison below is written, as the RFC writes     *)
(* them, as an offset from the left end of an interval, so nothing depends *)
(* on N but the room it leaves. N must exceed twice the widest interval a  *)
(* connection uses (sending: SYN, Data octets and FIN; receiving: Cap and  *)
(* a FIN), so that every value a peer can send is somewhere in the space:  *)
(* inside the window, behind it, ahead of it, or exactly half the space    *)
(* away, where RFC 1982's order is undefined. The initial send sequence    *)
(* number is 0: the RFC lets the ISS be any value, and every comparison is *)
(* invariant under adding a constant to all send-side numbers, so 0 loses  *)
(* nothing. The same holds of the IRS, which the configs fix with IRS.     *)
(*                                                                         *)
(* What the RFC leaves to the implementation is left open here: an ACK may *)
(* go out at once or later (3.8.6.3), text past a hole may be held or      *)
(* dropped (3.10.7.4, seventh), the right window edge may move right at    *)
(* any time but never left (3.8.6.2.2), and a challenge ACK may be held    *)
(* back by RFC 5961 section 7's rate limit. Segments the endpoint sends of *)
(* its own accord (SYN, text, FIN, pure ACKs and window updates) only move *)
(* SND.NXT and the window; `out` is the reply to an arriving segment.      *)
(*                                                                         *)
(* Each Boolean constant below is a departure from the RFC that an         *)
(* implementation may make deliberately. Set to FALSE, the spec is the     *)
(* RFC as written. The README names, for each, the clause it leaves and    *)
(* why the Fictionet stack makes it.                                       *)
EXTENDS Integers, FiniteSets

CONSTANTS
  N,            \* the size of the sequence space
  Cap,          \* receive buffer: RCV.WND plus the octets not yet read
  Data,         \* octets the user may SEND in one connection
  MaxText,      \* most text octets in one arriving segment
  IRS,          \* the sequence number of every opening SYN (see above)
  RepeatSynAck,               \* a repeated SYN in SYN-RECEIVED: SYN-ACK again
  AckBeforeSeqInSynReceived,  \* SYN-RECEIVED: a bad ACK resets before the seq check
  ChallengeSynInSynReceived,  \* SYN-RECEIVED: a SYN is challenged, not a return to LISTEN
  NoAckDroppedFirst,          \* a segment without ACK is dropped before the seq check
  AckCheckedBeforeSeq,        \* an ACK of unsent data is challenged before the seq check
  RateLimitEmptyOutOfWindow,  \* an unacceptable empty segment's ACK may be held back
  EmptyAckAtRightEdge,        \* an empty segment at RCV.NXT+RCV.WND is acceptable
  FinAtRightEdge,             \* a FIN in order at RCV.NXT+RCV.WND is taken
  OpenInTimeWait              \* OPEN on a connection in TIME-WAIT starts a new one

ASSUME N % 2 = 0 /\ N > 2 * (Data + 2) /\ N > 2 * (Cap + 1)
ASSUME MaxText <= Cap /\ IRS \in 0..(N - 1)

States == {"Closed", "Listen", "SynSent", "SynReceived", "Established",
           "FinWait1", "FinWait2", "CloseWait", "Closing", "LastAck",
           "TimeWait"}
Synchronized == {"Established", "FinWait1", "FinWait2", "CloseWait",
                 "Closing", "LastAck", "TimeWait"}
Seq == 0..(N - 1)
None == -1
Half == N \div 2

\* Modulo-N arithmetic (RFC 9293 section 3.4).
Add(a, k) == (a + k) % N
Off(a, b) == (b - a) % N          \* how far b lies ahead of a

\* Every segment a peer can send.
Controls == {"NONE", "SYN", "FIN", "RST"}
Segments == [seq : Seq, ack : Seq \cup {None}, ctl : Controls,
             len : 0..MaxText]
\* RST and SYN carry no text here: RFC 5961 answers them whatever they
\* carry, and the code drops both texts unread.
\* (IsPeer tests one segment without building the set, which RfcTrace's
\* large N needs.)
IsPeer(s) == /\ s.seq \in Seq /\ (s.ack \in Seq \/ s.ack = None)
             /\ s.ctl \in Controls /\ s.len \in 0..MaxText
             /\ (s.ctl \in {"RST", "SYN"} => s.len = 0)
Peer == {s \in Segments : s.ctl \in {"RST", "SYN"} => s.len = 0}
SegLen(s) == s.len + (IF s.ctl \in {"SYN", "FIN"} THEN 1 ELSE 0)
NoSeg == [seq |-> None, ack |-> None, ctl |-> "NONE", len |-> 0]

\* Replies to an arriving segment.
NoOut == [k |-> "None", s |-> None, a |-> None]
AckOut(sq, ak) == [k |-> "Ack", s |-> sq, a |-> ak]
RstOut(sq) == [k |-> "Rst", s |-> sq, a |-> None]          \* <SEQ=SEG.ACK><CTL=RST>
RstAckOut(ak) == [k |-> "RstAck", s |-> 0, a |-> ak]       \* <SEQ=0><ACK=..><CTL=RST,ACK>
Outs == {NoOut} \cup [k : {"Ack"}, s : Seq, a : Seq]
        \cup [k : {"Rst"}, s : Seq, a : {None}]
        \cup [k : {"RstAck"}, s : {0}, a : Seq]

VARIABLES
  st,       \* the connection state
  passive,  \* the connection came from a passive OPEN (LISTEN)
  una,      \* SND.UNA
  nxt,      \* SND.NXT: the highest sequence number sent, plus one
  queued,   \* octets the user has SENT so far
  finQ,     \* the user has CLOSEd: a FIN follows the queued octets
  rnxt,     \* RCV.NXT
  redge,    \* RCV.NXT + RCV.WND: the right window edge
  rbuf,     \* octets taken in but not yet RECEIVEd by the user
  held,     \* sequence numbers of text held past a hole
  sfin,     \* the peer's FIN has been taken
  out,      \* the reply to the last arriving segment
  seg       \* the last arriving segment, or NoSeg

vars == <<st, passive, una, nxt, queued, finQ, rnxt, redge, rbuf, held,
          sfin, out, seg>>

\* The ISS is 0: SYN at 0, the octets at 1..queued, the FIN after them.
FinSeq == Add(1, queued)
Wnd == Off(rnxt, redge)
InWin(x) == Off(rnxt, x) < Wnd
\* SND.UNA < a =< SND.NXT, as offsets from SND.UNA.
NewAck(a) == Off(una, a) >= 1 /\ Off(una, a) <= Off(una, nxt)
\* SEG.ACK > SND.NXT; at exactly half the space RFC 1982 has no order.
AheadAck(a) == Off(nxt, a) \in 1..(Half - 1)
UnorderedAck(a) == Off(nxt, a) = Half

TypeOK ==
  /\ st \in States /\ passive \in BOOLEAN
  /\ una \in Seq /\ nxt \in Seq /\ queued \in 0..Data /\ finQ \in BOOLEAN
  /\ rnxt \in Seq /\ redge \in Seq /\ rbuf \in 0..Cap
  /\ held \subseteq Seq /\ sfin \in BOOLEAN /\ out \in Outs
  /\ seg \in Peer \cup {NoSeg}

---------------------------------------------------------------------------
(* Pieces of a step.                                                      *)

Reply(o) == out' = o
\* The window edge after a step: never left of where it was, unless RCV.NXT
\* passed it, and never more than the buffer holds.
EdgeFrom(low) == redge' \in {Add(rnxt', o) : o \in low..(Cap - rbuf')}
KeepEdge == EdgeFrom(IF Off(rnxt', redge) <= Cap THEN Off(rnxt', redge) ELSE 0)

Fresh(s, p) ==
  /\ st' = s /\ passive' = p /\ una' = 0 /\ nxt' = 0 /\ queued' = 0
  /\ finQ' = FALSE /\ rnxt' = 0 /\ redge' = 0 /\ held' = {}
  /\ sfin' = FALSE
\* Leaving a connection; the octets taken stay readable.
ToClosed == Fresh("Closed", FALSE) /\ UNCHANGED rbuf

Ignore == Reply(NoOut) /\ UNCHANGED <<st, passive, una, nxt, queued, finQ,
                                       rnxt, redge, rbuf, held, sfin>>
Answer(o) == Reply(o) /\ UNCHANGED <<st, passive, una, nxt, queued, finQ,
                                      rnxt, redge, rbuf, held, sfin>>
\* An ACK changes nothing but the window it advertises.
AnswerAck == /\ UNCHANGED <<st, passive, una, nxt, queued, finQ, rnxt, rbuf,
                            held, sfin>>
             /\ KeepEdge /\ Reply(AckOut(nxt, rnxt))
AnswerChallenge == AnswerAck \/ Ignore

---------------------------------------------------------------------------
(* Section 3.10.7.2: LISTEN.                                              *)

\* A RST is ignored, an ACK is answered with <SEQ=SEG.ACK><CTL=RST>, a SYN
\* opens SYN-RECEIVED (its SYN-ACK goes out with SendNext), anything else
\* is dropped. Text on the SYN is not kept: see the README.
ListenSyn(s) ==
  /\ st = "Listen" /\ s.ctl = "SYN" /\ s.ack = None
  /\ st' = "SynReceived" /\ passive' = TRUE /\ una' = 0 /\ nxt' = 0
  /\ queued' = 0 /\ finQ' = FALSE /\ held' = {} /\ sfin' = FALSE
  /\ rnxt' = Add(s.seq, 1) /\ rbuf' = 0 /\ EdgeFrom(0)
  /\ Reply(NoOut)

---------------------------------------------------------------------------
(* Section 3.10.7.3: SYN-SENT.                                            *)

\* ISS < SEG.ACK =< SND.NXT.
SynAckOK(a) == Off(0, a) >= 1 /\ Off(0, a) <= Off(0, nxt)

SynSentArrive(s) ==
  CASE s.ack # None /\ ~SynAckOK(s.ack) ->
         IF s.ctl = "RST" THEN Ignore ELSE Answer(RstOut(s.ack))
    [] s.ctl = "RST" ->
         IF s.ack # None THEN ToClosed /\ Reply(NoOut) ELSE Ignore
    [] s.ctl = "SYN" ->
         /\ rnxt' = Add(s.seq, 1) /\ held' = {} /\ rbuf' = 0
         /\ IF s.ack # None
              THEN st' = "Established" /\ una' = s.ack
              ELSE st' = "SynReceived" /\ una' = una
         /\ EdgeFrom(0)
         /\ out' \in {NoOut, AckOut(nxt, rnxt')}
         /\ UNCHANGED <<passive, nxt, queued, finQ, sfin>>
    [] OTHER -> Ignore

---------------------------------------------------------------------------
(* Section 3.10.7.4: SYN-RECEIVED and the synchronized states.            *)

\* The acceptability test of the first check, as offsets from RCV.NXT.
Acceptable(s) ==
  LET L == SegLen(s) IN
  IF L = 0
    THEN IF Wnd = 0 THEN s.seq = rnxt
         ELSE \/ InWin(s.seq)
              \/ (EmptyAckAtRightEdge /\ s.ctl = "NONE" /\ s.seq = redge)
    ELSE IF Wnd = 0
           THEN FinAtRightEdge /\ s.ctl = "FIN" /\ s.len = 0 /\ s.seq = rnxt
           ELSE InWin(s.seq) \/ InWin(Add(s.seq, L - 1))

\* "If the RCV.WND is zero, no segments will be acceptable, but special
\* allowance should be made to accept valid ACKs": text at RCV.NXT of a
\* closed window counts for its ACK alone, and is answered.
ZeroWindowAllowance(s) == Wnd = 0 /\ s.seq = rnxt /\ s.len > 0

\* The first check's reply to an unacceptable segment.
RejectReply(s) ==
  IF RateLimitEmptyOutOfWindow /\ SegLen(s) = 0
    THEN AnswerChallenge ELSE AnswerAck

\* The longest run of sequence numbers from x that are all in S.
RECURSIVE RunFrom(_, _, _)
RunFrom(x, S, bound) ==
  IF bound = 0 \/ x \notin S THEN 0 ELSE 1 + RunFrom(Add(x, 1), S, bound - 1)

\* The fifth check onwards, for an acceptable segment with an ACK that is
\* not ahead of SND.NXT (or a closed window's ACK-only segment, `textOk`
\* FALSE). `st1` is the state after the ACK of SYN-RECEIVED.
Proceed(s, st1, textOk) ==
  LET una1 == IF NewAck(s.ack) THEN s.ack ELSE una
      finAcked == finQ /\ una1 = Add(FinSeq, 1)
      \* ACK processing of FIN-WAIT-1, CLOSING, LAST-ACK.
      st2 == CASE st1 = "FinWait1" /\ finAcked -> "FinWait2"
               [] st1 = "Closing" /\ finAcked -> "TimeWait"
               [] st1 = "LastAck" /\ finAcked -> "Closed"
               [] OTHER -> st1
      takes == textOk /\ ~sfin /\ st2 \in {"Established", "FinWait1", "FinWait2"}
      fin == Add(s.seq, s.len)
      text == {Add(s.seq, i) : i \in {j \in 0..(MaxText - 1) : j < s.len}}
      inWin == {x \in text : InWin(x)}
      avail == held \cup inWin
      \* Text after a FIN in the same segment cannot exist; held text past
      \* it is the peer's error and is not taken.
      limit == IF s.ctl = "FIN" THEN Off(rnxt, fin) ELSE N
      k == IF takes THEN RunFrom(rnxt, avail, limit) ELSE 0
      rnxt1 == Add(rnxt, k)
      finIn == /\ takes /\ s.ctl = "FIN" /\ rnxt1 = fin
               /\ (InWin(fin) \/ (FinAtRightEdge /\ fin = redge))
      st3 == IF ~finIn THEN st2
             ELSE CASE st2 = "FinWait1" -> IF finAcked THEN "TimeWait" ELSE "Closing"
                    [] st2 = "FinWait2" -> "TimeWait"
                    [] OTHER -> "CloseWait"
  IN
  IF st2 = "Closed"
    \* A closed window's segment is answered as unacceptable, before its
    \* ACK closes the connection.
    THEN ToClosed /\ Reply(IF textOk THEN NoOut ELSE AckOut(nxt, rnxt))
    ELSE
      /\ st' = st3 /\ una' = una1
      /\ rnxt' = IF finIn THEN Add(rnxt1, 1) ELSE rnxt1
      /\ sfin' = (sfin \/ finIn)
      /\ rbuf' = rbuf + k
      /\ IF finIn \/ ~takes THEN held' \in SUBSET {x \in held : InWin(x) /\ x # rnxt}
                                 /\ (finIn => held' = {})
         ELSE held' \in SUBSET {x \in avail : x \notin {Add(rnxt, i) : i \in 0..k}}
      /\ KeepEdge
      /\ IF textOk THEN out' \in {NoOut, AckOut(nxt, rnxt')}
                   ELSE Reply(AckOut(nxt, rnxt'))
      /\ UNCHANGED <<passive, nxt, queued, finQ>>

\* Back to LISTEN, as RST or SYN in a passive SYN-RECEIVED has it.
BackToListen ==
  /\ Fresh("Listen", TRUE) /\ rbuf' = 0 /\ Reply(NoOut)

\* From the first check on, in the RFC's order.
InOrder(s) ==
  LET acc == Acceptable(s)
      zw == ZeroWindowAllowance(s)
  IN
  CASE \* First check: an unacceptable segment.
       ~acc /\ ~zw ->
         IF s.ctl = "RST" THEN Ignore ELSE
         RejectReply(s)
       \* Second check, RST (RFC 5961 section 3.2).
    [] s.ctl = "RST" ->
         IF s.seq # rnxt THEN AnswerChallenge
         ELSE IF st = "SynReceived" /\ passive THEN BackToListen
         ELSE ToClosed /\ Reply(NoOut)
       \* Fifth check, the ACK field.
    [] s.ack = None -> Ignore
    [] st = "SynReceived" ->
         IF NewAck(s.ack) THEN Proceed(s, "Established", ~zw)
         ELSE Answer(RstOut(s.ack))
    [] AheadAck(s.ack) -> AnswerChallenge
    [] UnorderedAck(s.ack) -> AnswerChallenge \/ Proceed(s, st, ~zw)
    [] OTHER -> Proceed(s, st, ~zw)

SyncArrive(s) ==
  CASE \* A repeated SYN in SYN-RECEIVED (a setting; the code's Linux look).
       RepeatSynAck /\ st = "SynReceived" /\ s.ctl = "SYN" /\ s.ack = None
         /\ Add(s.seq, 1) = rnxt -> Ignore
       \* Fourth check, a SYN. RFC 5961 section 4.2 challenges it wherever
       \* its sequence number lies. The first check still comes first in
       \* SYN-RECEIVED, and an acceptable SYN sends a passive open back to
       \* LISTEN.
    [] s.ctl = "SYN" /\ st = "SynReceived" /\ ~ChallengeSynInSynReceived ->
         IF ~Acceptable(s) THEN AnswerAck
         ELSE IF passive THEN BackToListen
         ELSE AnswerChallenge
    [] s.ctl = "SYN" -> AnswerChallenge
       \* Departures that look at the ACK before the sequence number.
    [] NoAckDroppedFirst /\ s.ctl # "RST" /\ s.ack = None -> Ignore
    [] AckBeforeSeqInSynReceived /\ st = "SynReceived" /\ s.ctl # "RST"
         /\ s.ack # None /\ ~NewAck(s.ack) -> Answer(RstOut(s.ack))
    [] AckCheckedBeforeSeq /\ st \in Synchronized /\ s.ctl # "RST"
         /\ s.ack # None /\ AheadAck(s.ack) -> AnswerChallenge
    [] AckCheckedBeforeSeq /\ st \in Synchronized /\ s.ctl # "RST"
         /\ s.ack # None /\ UnorderedAck(s.ack) ->
         AnswerChallenge \/ InOrder(s)
    [] OTHER -> InOrder(s)

Arrive(s) ==
  /\ st # "Closed"
  /\ IsPeer(s)
  /\ st \in {"Listen", "SynSent"} /\ s.ctl = "SYN" => s.seq = IRS
  /\ CASE st = "Listen" ->
            IF s.ctl = "SYN" /\ s.ack = None THEN ListenSyn(s)
            ELSE IF s.ctl = "RST" \/ s.ack = None THEN Ignore
            ELSE Answer(RstOut(s.ack))
       [] st = "SynSent" -> SynSentArrive(s)
       [] OTHER -> SyncArrive(s)

---------------------------------------------------------------------------
(* Sending: SYN, text and FIN each take the next sequence number (3.8.1). *)
(* Retransmissions resend from SND.UNA without moving SND.NXT.            *)

SendNext ==
  LET k == Off(0, nxt) IN
  /\ \/ /\ st \in {"SynSent", "SynReceived", "FinWait1", "Closing"} /\ k = 0
      \/ /\ st \in {"Established", "CloseWait", "FinWait1", "LastAck", "Closing"}
         /\ k >= 1 /\ k < 1 + queued
      \/ /\ st \in {"FinWait1", "LastAck", "Closing"} /\ finQ
         /\ k = 1 + queued
  /\ nxt' = Add(nxt, 1)
  /\ UNCHANGED <<st, passive, una, queued, finQ, rnxt, rbuf, held, sfin>>
  /\ IF st \in {"SynSent", "Listen"} THEN UNCHANGED redge ELSE KeepEdge
  /\ Reply(NoOut)

\* A pure ACK or window update.
Advertise ==
  /\ st \notin {"Closed", "Listen", "SynSent"}
  /\ UNCHANGED <<st, passive, una, nxt, queued, finQ, rnxt, rbuf, held, sfin>>
  /\ KeepEdge /\ Reply(NoOut)

---------------------------------------------------------------------------
(* User calls and timeouts.                                               *)

\* OPEN (3.10.1). On a connection that exists the RFC answers "connection
\* already exists"; TIME-WAIT counts as one.
MayOpen == st = "Closed" \/ (OpenInTimeWait /\ st = "TimeWait")
Listen == MayOpen /\ Fresh("Listen", TRUE) /\ rbuf' = 0 /\ Reply(NoOut)
Connect == MayOpen /\ Fresh("SynSent", FALSE) /\ rbuf' = 0 /\ Reply(NoOut)

Send ==
  /\ st \in {"Established", "CloseWait"} /\ queued < Data /\ ~finQ
  /\ queued' = queued + 1 /\ Reply(NoOut)
  /\ UNCHANGED <<st, passive, una, nxt, finQ, rnxt, redge, rbuf, held, sfin>>

Receive ==
  /\ rbuf > 0 /\ rbuf' = rbuf - 1 /\ Reply(NoOut)
  /\ UNCHANGED <<st, passive, una, nxt, queued, finQ, rnxt, redge, held, sfin>>

Close ==
  /\ CASE st \in {"Listen", "SynSent"} -> ToClosed
       [] st \in {"SynReceived", "Established"} ->
            /\ st' = "FinWait1" /\ finQ' = TRUE
            /\ UNCHANGED <<passive, una, nxt, queued, rnxt, redge, rbuf, held, sfin>>
       [] st = "CloseWait" ->
            /\ st' = "LastAck" /\ finQ' = TRUE
            /\ UNCHANGED <<passive, una, nxt, queued, rnxt, redge, rbuf, held, sfin>>
       [] OTHER -> FALSE
  /\ Reply(NoOut)

\* ABORT, the user timeout, and TIME-WAIT's end all leave the connection.
Abort == st # "Closed" /\ ToClosed /\ Reply(NoOut)
TimeWaitEnds == st = "TimeWait" /\ ToClosed /\ Reply(NoOut)

Init ==
  /\ st = "Closed" /\ passive = FALSE /\ una = 0 /\ nxt = 0 /\ queued = 0
  /\ finQ = FALSE /\ rnxt = 0 /\ redge = 0 /\ rbuf = 0 /\ held = {}
  /\ sfin = FALSE /\ out = NoOut /\ seg = NoSeg

\* `seg` names the segment of an arrival step. It changes nothing that
\* follows, so the configs leave it and `out` out of the VIEW; it lets TLC
\* check a step of the code against the arrival of that one segment.
Next ==
  \/ seg' \in Peer /\ Arrive(seg')
  \/ /\ seg' = NoSeg
     /\ \/ SendNext \/ Advertise
        \/ Listen \/ Connect \/ Send \/ Receive \/ Close \/ Abort
        \/ TimeWaitEnds

Spec == Init /\ [][Next]_vars

\* What TLC tells states apart by.
View == <<st, passive, una, nxt, queued, finQ, rnxt, redge, rbuf, held, sfin>>

---------------------------------------------------------------------------
(* What the RFC guarantees, checked of the spec itself.                   *)

\* ISS =< SND.UNA =< SND.NXT =< the FIN's sequence number plus one.
SendOrder == Off(0, una) <= Off(0, nxt) /\ Off(0, nxt) <= Data + 2
\* The window never offers more than the buffer holds.
WindowFits == st \notin {"Closed", "Listen", "SynSent"} => Wnd + rbuf <= Cap
\* Text held past a hole lies inside the window, past RCV.NXT.
HeldInWindow == \A x \in held : InWin(x) /\ x # rnxt
\* Nothing is held or taken after the peer's FIN.
NothingAfterFin == sfin => held = {}
\* A reply never acknowledges a sequence number not yet taken.
\* (A step property: `out` is outside the VIEW.)
\* An ACK goes to RCV.NXT as it was or as the segment moved it; the one
\* sent as a closed window's segment closes the connection goes with the
\* RCV.NXT it had.
AckNoFurther == [][out'.k = "Ack" => out'.a \in {rnxt, rnxt'}]_vars
\* Only CLOSE moves to the states that send a FIN.
FinOnlyAfterClose == st \in {"FinWait1", "FinWait2", "Closing", "LastAck"} => finQ
=============================================================================
