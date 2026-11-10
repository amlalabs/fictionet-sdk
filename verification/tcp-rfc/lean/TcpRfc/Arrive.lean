import TcpRfc.Seq

/-!
# SEGMENT ARRIVES (RFC 9293 section 3.10.7)

`arrive d t s` is what an endpoint with connection record `t` does when
segment `s` arrives: the record after it and the one segment it answers
with. It follows the RFC's checks in their order for CLOSED (3.10.7.1),
LISTEN (3.10.7.2), SYN-SENT (3.10.7.3) and every other state (3.10.7.4:
acceptability, RST, SYN, ACK, text, FIN), with RFC 5961's answers to a RST
(section 3.2), to a SYN in a synchronized state (4.2) and to an ACK of data
never sent (5.2, rate limited by section 7).

Where the RFC leaves a choice, the model makes one and says so:

* An ACK that is owed may go out at once or later (3.8.6.3). The model
  answers at once whenever `RCV.NXT` moves, whenever text arrives past a
  hole (RFC 5681 section 4.2's duplicate ACK; MAY-13), and for text at the
  left edge of a closed window ("special allowance should be made to accept
  valid ACKs", 3.10.7.4). A segment that moves nothing is not answered.
* Text past a hole may be held (SHLD-31) or dropped. Either way it does not
  move `RCV.NXT` now, which is all a single step shows; the record keeps no
  reassembly queue. The ACK of such a segment is processed.
* RFC 1982 leaves the ACK exactly 2^31 past `SND.NXT` unordered. RFC 5961
  allows a challenge or treating it as old; the model challenges it
  (`ahead`), so it is never taken as new.
* RCV.WND follows the buffer (3.10.7.4, seventh): taken text shrinks it,
  a FIN does not, so the right edge never moves left.
* After the peer's FIN, text is ignored and a further FIN changes nothing
  (eighth: "remain in" the state); its ACK still counts. The model does
  not move RCV.NXT over such a FIN.
* A SYN in a synchronized state is challenged wherever its sequence number
  lies, as RFC 5961 section 4.2 says ("irrespective of the sequence
  number"); in SYN-RECEIVED the first check still comes first.

Each field of `Departures` is a deliberate departure of an implementation;
with every field false, `arrive` is the RFC. `Departures.smoltcp` is the
Fictionet stack's set.
-/

namespace TcpRfc

inductive State
  | closed | listen | synSent | synReceived
  | established | finWait1 | finWait2 | closeWait | closing | lastAck | timeWait
  deriving DecidableEq, Repr, Inhabited

/-- The synchronized states of section 3.10.7.4. -/
def State.synchronized : State → Bool
  | .established | .finWait1 | .finWait2 | .closeWait | .closing | .lastAck | .timeWait => true
  | _ => false

/-- States in which arriving text is taken (3.10.7.4, seventh). -/
def State.takesText : State → Bool
  | .established | .finWait1 | .finWait2 => true
  | _ => false

/-- The one control a segment carries. smoltcp's parser drops SYN with FIN
    and gives RST priority over the others; PSH changes nothing here. -/
inductive Ctl | none | syn | fin | rst
  deriving DecidableEq, Repr, Inhabited

structure Segment where
  seq : Seq
  ack : Option Seq
  ctl : Ctl
  /-- Octets of text. -/
  text : Nat
  deriving DecidableEq, Repr, Inhabited

/-- SEG.LEN: text, SYN and FIN (3.4). -/
def Segment.len (s : Segment) : Nat :=
  s.text + (match s.ctl with | .syn | .fin => 1 | _ => 0)

/-- The connection record, with the variables of section 3.3.1 that
    segment arrival reads or writes. -/
structure Tcb where
  state : State
  iss : Seq
  irs : Seq
  sndUna : Seq
  sndNxt : Seq
  rcvNxt : Seq
  rcvWnd : Nat
  /-- Our SYN has gone out. -/
  synSent : Bool
  /-- Our FIN has gone out: it is the number just before `SND.NXT`. -/
  finSent : Bool
  /-- The peer's FIN has arrived and been taken. -/
  peerFin : Bool
  /-- The connection came from LISTEN. -/
  passive : Bool
  deriving DecidableEq, Repr, Inhabited

inductive Reply
  | none
  /-- `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`. -/
  | ack (seq ack : Seq)
  /-- The same segment as an RFC 5961 challenge ACK, which section 7 lets a
      rate limit hold back. -/
  | challenge (seq ack : Seq)
  /-- `<SEQ=SEG.ACK><CTL=RST>`. -/
  | rst (seq : Seq)
  /-- `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`. -/
  | rstAck (ack : Seq)
  /-- `<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>`. -/
  | synAck (seq ack : Seq)
  deriving DecidableEq, Repr, Inhabited

/-- Deliberate departures from the RFC. Each is used in `arrive` only
    together with the condition of the same name below, which the locality
    theorems in `Theorems.lean` rely on. -/
structure Departures where
  /-- SYN-RECEIVED: a repeated SYN (its SEQ one before RCV.NXT, no ACK) is
      dropped so the SYN-ACK goes out again. RFC 9293 3.10.7.4 sends a
      passive open back to LISTEN. smoltcp: `Settings::repeat_syn_ack`,
      off by default. -/
  repeatSynAck : Bool
  /-- SYN-RECEIVED: an ACK that does not acknowledge our SYN draws
      `<SEQ=SEG.ACK><CTL=RST>` before the sequence check, as Linux's
      `tcp_check_req` does. RFC 9293 3.10.7.4 checks the sequence number
      first (an unacceptable segment gets an ACK) and the ACK fifth.
      smoltcp: `process`, the `(State::SynReceived, _, Some(ack_number))`
      arm of the first match. -/
  ackBeforeSeqInSynReceived : Bool
  /-- SYN-RECEIVED: a SYN gets a challenge ACK, wherever it lies. RFC 9293
      3.10.7.4 (fourth check) returns a passive open to LISTEN after the
      sequence check. smoltcp: `process`, the SYN test before the first
      match. -/
  challengeSynInSynReceived : Bool
  /-- SYN-RECEIVED and synchronized states: a segment without ACK and
      without RST is dropped before the sequence check, as Linux's
      `tcp_rcv_state_process` does. RFC 9293 3.10.7.4 answers an
      unacceptable one with an ACK (first check) and drops an acceptable
      one at the fifth. smoltcp: `process`, `(_, _, None) => return None`. -/
  noAckDroppedFirst : Bool
  /-- Synchronized states: an ACK ahead of SND.NXT gets a challenge ACK
      before the sequence check. RFC 9293 checks the sequence first, so an
      unacceptable segment would get a plain ACK. smoltcp: `process`, the
      last arm of the first match. -/
  ackCheckedBeforeSeq : Bool
  /-- An unacceptable segment with no text and no FIN is answered with a
      challenge ACK, which the rate limit may hold back, instead of the
      plain ACK of RFC 9293 3.10.7.4 (first check). Linux's
      `tcp_oow_rate_limited` does the same. smoltcp: `process`, the
      `segment_len() > 0` test. -/
  rateLimitEmptyOutOfWindow : Bool
  /-- A segment with no text, no FIN and no RST at exactly
      RCV.NXT+RCV.WND, with RCV.WND > 0, is acceptable: a peer that filled
      the window sends its next ACK there. RFC 9293 table 6 asks
      `SEG.SEQ < RCV.NXT+RCV.WND`. smoltcp: `segment_in_window`. -/
  emptyAckAtRightEdge : Bool
  /-- A FIN in order that sits exactly at RCV.NXT+RCV.WND is taken: a
      FIN-only segment at RCV.NXT of a zero window (`test_zero_window_fin`;
      Linux takes it too), or a FIN right after text that fills the window.
      RFC 9293 3.10.7.4 trims "any portions that lie outside the window
      (including SYN and FIN)". smoltcp: `process`, the FIN test leaves the
      FIN out of `segment_end`, and `segment_in_window` accepts any segment
      at the left edge of a closed window. -/
  finAtRightEdge : Bool
  /-- Text on a SYN-ACK is not taken. RFC 9293 3.10.7.3 says such text
      should be processed (and text on any SYN queued). smoltcp: `process`
      gives LISTEN and SYN-SENT an empty payload. -/
  textOnSynDropped : Bool
  deriving DecidableEq, Repr

/-- The RFC as written. -/
def Departures.rfc : Departures :=
  { repeatSynAck := false, ackBeforeSeqInSynReceived := false,
    challengeSynInSynReceived := false, noAckDroppedFirst := false,
    ackCheckedBeforeSeq := false, rateLimitEmptyOutOfWindow := false,
    emptyAckAtRightEdge := false, finAtRightEdge := false,
    textOnSynDropped := false }

/-- The vendored smoltcp socket with its default settings. -/
def Departures.smoltcp : Departures :=
  { repeatSynAck := false, ackBeforeSeqInSynReceived := true,
    challengeSynInSynReceived := true, noAckDroppedFirst := true,
    ackCheckedBeforeSeq := true, rateLimitEmptyOutOfWindow := true,
    emptyAckAtRightEdge := true, finAtRightEdge := true,
    textOnSynDropped := true }

/-! ## The segments each departure is about -/

/-- SYN-RECEIVED or synchronized: the states of 3.10.7.4. -/
def otherState (t : Tcb) : Bool := t.state == .synReceived || t.state.synchronized

def repeatSynAckCase (t : Tcb) (s : Segment) : Bool :=
  t.state == .synReceived && s.ctl == .syn && s.ack.isNone && adv s.seq 1 == t.rcvNxt

def ackBeforeSeqCase (t : Tcb) (s : Segment) : Bool :=
  t.state == .synReceived && s.ctl != .rst && s.ctl != .syn &&
    (match s.ack with | some a => !ltLe t.sndUna a t.sndNxt | none => false)

def challengeSynCase (t : Tcb) (s : Segment) : Bool :=
  t.state == .synReceived && s.ctl == .syn

def noAckCase (t : Tcb) (s : Segment) : Bool :=
  otherState t && s.ctl != .rst && s.ctl != .syn && s.ack.isNone

def ackAheadCase (t : Tcb) (s : Segment) : Bool :=
  t.state.synchronized && s.ctl != .rst && s.ctl != .syn &&
    (match s.ack with | some a => decide (ahead a t.sndNxt) | none => false)

def emptyOutOfWindowCase (t : Tcb) (s : Segment) : Bool :=
  otherState t && s.ctl == .none && s.text == 0 && !acceptable t.rcvNxt t.rcvWnd s.seq 0

def emptyRightEdgeCase (t : Tcb) (s : Segment) : Bool :=
  otherState t && s.ctl == .none && s.text == 0 && t.rcvWnd != 0 &&
    s.seq == adv t.rcvNxt t.rcvWnd

/-- The FIN of `s` comes in order and sits at RCV.NXT+RCV.WND. -/
def finEdgeCase (t : Tcb) (s : Segment) : Bool :=
  otherState t && s.ctl == .fin && dist s.seq t.rcvNxt + t.rcvWnd == s.text

def synTextCase (t : Tcb) (s : Segment) : Bool :=
  t.state == .synSent && s.ctl == .syn && s.ack.isSome && s.text != 0

/-! ## Arrival -/

def ackOf (t : Tcb) : Reply := .ack t.sndNxt t.rcvNxt
def challengeOf (t : Tcb) : Reply := .challenge t.sndNxt t.rcvNxt

/-- How far before RCV.NXT the segment starts: zero when it starts at
    RCV.NXT. -/
def back (t : Tcb) (s : Segment) : Nat := dist s.seq t.rcvNxt

/-- The segment starts at or before RCV.NXT and its text reaches it: the
    "idealized segment that begins at RCV.NXT" once trimmed. -/
def inOrder (t : Tcb) (s : Segment) : Bool := decide (back t s ≤ s.text)

/-- 3.10.7.1. -/
def closedArrive (t : Tcb) (s : Segment) : Tcb × Reply :=
  if s.ctl == .rst then (t, .none)
  else match s.ack with
    | some a => (t, .rst a)
    | none => (t, .rstAck (adv s.seq s.len))

/-- 3.10.7.2. A SYN's text is queued for SYN-RECEIVED, where it waits for
    ESTABLISHED, so it does not move RCV.NXT now. -/
def listenArrive (t : Tcb) (s : Segment) : Tcb × Reply :=
  if s.ctl == .rst then (t, .none)
  else match s.ack with
    | some a => (t, .rst a)
    | none =>
      if s.ctl == .syn then
        let r := adv s.seq 1
        ({ t with state := .synReceived, irs := s.seq, rcvNxt := r, sndUna := t.iss,
                  sndNxt := adv t.iss 1, synSent := true, finSent := false,
                  peerFin := false, passive := true },
         .synAck t.iss r)
      else (t, .none)

/-- 3.10.7.3. -/
def synSentArrive (d : Departures) (t : Tcb) (s : Segment) : Tcb × Reply :=
  match s.ack with
  | some a =>
    if !ltLe t.iss a t.sndNxt then
      (if s.ctl == .rst then (t, .none) else (t, .rst a))
    else if s.ctl == .rst then ({ t with state := .closed }, .none)
    else if s.ctl == .syn then
      -- SND.UNA > ISS: ESTABLISHED, then text from the sixth step on.
      let taken := if d.textOnSynDropped && synTextCase t s then 0 else min s.text t.rcvWnd
      let r := adv s.seq (1 + taken)
      ({ t with state := .established, irs := s.seq, rcvNxt := r,
                rcvWnd := t.rcvWnd - taken, sndUna := a },
       .ack t.sndNxt r)
    else (t, .none)
  | none =>
    if s.ctl == .syn then
      let r := adv s.seq 1
      ({ t with state := .synReceived, irs := s.seq, rcvNxt := r }, .synAck t.iss r)
    else (t, .none)

/-- The fifth check on, for an acceptable segment whose ACK `a` is not
    ahead of SND.NXT. `st1` is the state after SYN-RECEIVED's ACK; `zw`
    marks text at the left edge of a closed window, which counts for its
    ACK alone and is answered. -/
def proceed (d : Departures) (t : Tcb) (s : Segment) (a : Seq) (st1 : State) (zw : Bool) :
    Tcb × Reply :=
  let newAck := ltLe t.sndUna a t.sndNxt
  let una1 := if newAck then a else t.sndUna
  let finAcked := t.finSent && newAck && a == t.sndNxt
  let st2 := match st1 with
    | .finWait1 => if finAcked then State.finWait2 else .finWait1
    | .closing => if finAcked then .timeWait else .closing
    | .lastAck => if finAcked then .closed else .lastAck
    | x => x
  -- Closed-window text is unacceptable and answered by the first check,
  -- with the numbers from before the step, even when its ACK closes.
  if st2 == .closed then
    ({ t with state := .closed, sndUna := una1 }, if zw then ackOf t else .none)
  else
    let takes := !zw && !t.peerFin && st2.takesText
    let ord := takes && inOrder t s
    -- The FIN's offset from RCV.NXT: the new text before it.
    let p := s.text - back t s
    let taken := if ord then min p t.rcvWnd else 0
    let finIn := ord && s.ctl == .fin &&
      (decide (p < t.rcvWnd) || (d.finAtRightEdge && finEdgeCase t s))
    let moved := taken + (if finIn then 1 else 0)
    let r1 := adv t.rcvNxt moved
    let st3 := if finIn then
        (match st2 with
         | .finWait1 => if finAcked then State.timeWait else .closing
         | .finWait2 => .timeWait
         | _ => .closeWait)
      else st2
    let t' := { t with state := st3, sndUna := una1, rcvNxt := r1,
                       rcvWnd := t.rcvWnd - taken, peerFin := t.peerFin || finIn }
    let reply :=
      if zw || moved != 0 || (takes && s.text != 0) then Reply.ack t.sndNxt r1 else .none
    (t', reply)

/-- 3.10.7.4 from the first check on. -/
def checks (d : Departures) (t : Tcb) (s : Segment) : Tcb × Reply :=
  -- RFC 5961 section 3.2 judges a RST by its sequence number alone.
  let acc := acceptable t.rcvNxt t.rcvWnd s.seq (if s.ctl == .rst then 0 else s.len) ||
    (d.emptyAckAtRightEdge && emptyRightEdgeCase t s) ||
    (d.finAtRightEdge && finEdgeCase t s && t.rcvWnd == 0 && s.text == 0)
  let zw := t.rcvWnd == 0 && s.seq == t.rcvNxt && s.text != 0
  -- First: the sequence number.
  if !acc && !zw then
    if s.ctl == .rst then (t, .none)
    else if d.rateLimitEmptyOutOfWindow && emptyOutOfWindowCase t s then (t, challengeOf t)
    else (t, ackOf t)
  -- Second: RST (RFC 5961 section 3.2).
  else if s.ctl == .rst then
    if s.seq != t.rcvNxt then (t, challengeOf t)
    else if t.state == .synReceived && t.passive then ({ t with state := .listen }, .none)
    else ({ t with state := .closed }, .none)
  -- Fifth: the ACK field.
  else match s.ack with
    | none => (t, .none)
    | some a =>
      if t.state == .synReceived then
        if ltLe t.sndUna a t.sndNxt then proceed d t s a .established zw else (t, .rst a)
      else if decide (ahead a t.sndNxt) then (t, challengeOf t)
      else proceed d t s a t.state zw

/-- SYN-RECEIVED and the synchronized states, with the departures that
    come before the first check. -/
def otherArrive (d : Departures) (t : Tcb) (s : Segment) : Tcb × Reply :=
  if d.repeatSynAck && repeatSynAckCase t s then (t, .none)
  -- Fourth: a SYN. In SYN-RECEIVED the first check comes first.
  else if s.ctl == .syn && t.state == .synReceived &&
      !(d.challengeSynInSynReceived && challengeSynCase t s) then
    if !acceptable t.rcvNxt t.rcvWnd s.seq s.len then (t, ackOf t)
    else if t.passive then ({ t with state := .listen }, .none)
    else (t, challengeOf t)
  else if s.ctl == .syn then (t, challengeOf t)
  else if d.noAckDroppedFirst && noAckCase t s then (t, .none)
  else match s.ack with
    | some a =>
      if d.ackBeforeSeqInSynReceived && ackBeforeSeqCase t s then (t, .rst a)
      else if d.ackCheckedBeforeSeq && ackAheadCase t s then (t, challengeOf t)
      else checks d t s
    | none => checks d t s

def arrive (d : Departures) (t : Tcb) (s : Segment) : Tcb × Reply :=
  match t.state with
  | .closed => closedArrive t s
  | .listen => listenArrive t s
  | .synSent => synSentArrive d t s
  | _ => otherArrive d t s

end TcpRfc
