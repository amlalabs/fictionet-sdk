------------------------------ MODULE RfcFlow ------------------------------
(* RFC 9113 flow control and SETTINGS for one direction of DATA, written   *)
(* from the RFC's text, not from the code. One endpoint sends DATA and     *)
(* reads the other's WINDOW_UPDATE and SETTINGS; the other receives DATA    *)
(* and grants credit. An implementation module INSTANCEs this module once *)
(* per direction it takes part in and maps its own state onto the         *)
(* variables below; each rule is a property TLC checks on that mapping.   *)
(*                                                                        *)
(* Every step of the implementation is labeled by `ev`, the frame it read *)
(* or wrote and what it did about it:                                     *)
(*   k      "data" (DATA read), "send" (DATA written), "wu" (WINDOW_UPDATE *)
(*          read), "grant" (WINDOW_UPDATE written), "settings" (a well-    *)
(*          formed SETTINGS without ACK read), "badSettings" (a malformed *)
(*          SETTINGS read), "ack" (SETTINGS ACK read), "headers", "none"   *)
(*   s      the stream, 0 for the connection                              *)
(*   n      the DATA frame's length field: payload, pad length byte and    *)
(*          padding                                                       *)
(*   inc    the WINDOW_UPDATE increment                                    *)
(*   vals   the SETTINGS values in order, each <<identifier, value>>       *)
(*   bad    for "badSettings": "stream" (not on stream 0), "length" (not a *)
(*          multiple of 6), "ackPayload" (ACK with a payload)              *)
(*   v      the verdict: "ok", "ignored", a stream error ("streamFlow",    *)
(*          "streamProtocol", "streamClosed": RST_STREAM) or a connection  *)
(*          error ("connFlow", "connProtocol", "connFrameSize": GOAWAY)    *)
(*   ack    a SETTINGS ACK was written in this step                        *)
(*   goaway the code of the GOAWAY written in this step, as a verdict      *)
(*          name, or "none"                                               *)
(*                                                                        *)
(* Values are abstract: `Max` stands for 2^31 - 1 and every window, value *)
(* and increment is a small integer around it. The rules compare windows  *)
(* with Max and add or subtract; they keep their meaning at any scale.    *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS Max,        \* 2^31 - 1
          FrameMin,   \* 2^14, the least SETTINGS_MAX_FRAME_SIZE
          FrameLimit, \* 2^24 - 1, the largest
          Streams     \* stream identifiers, all above 0

VARIABLES ev,       \* the step's frame and verdict
          conn,     \* the connection window, as the sender keeps it
          win,      \* each stream's window, as the sender keeps it
          bound,    \* the most each stream may carry, as the receiver judges
          active,   \* the sender may still send DATA on the stream
          known,    \* the stream has left idle
          init,     \* SETTINGS_INITIAL_WINDOW_SIZE the sender took last
          pending,  \* values announced to the sender it has not acknowledged
          acked,    \* the value it acknowledged last
          frameMax, \* SETTINGS_MAX_FRAME_SIZE the sender took last
          settled   \* the peer's first SETTINGS was read
vars == <<ev, conn, win, bound, active, known, init, pending, acked, frameMax, settled>>

ConnErrors == {"connFlow", "connProtocol", "connFrameSize"}
StreamErrors == {"streamFlow", "streamProtocol", "streamClosed"}

\* The values one SETTINGS frame carries for one identifier, in order.
Values(vals, id) == [i \in 1..Len(SelectSeq(vals, LAMBDA e : e[1] = id)) |->
                       SelectSeq(vals, LAMBDA e : e[1] = id)[i][2]]
Range(seq) == {seq[i] : i \in DOMAIN seq}

\* Section 6.5.2: values no endpoint may announce.
Invalid(e) == CASE e[1] = 2 /\ e[2] \notin {0, 1} -> "connProtocol"
                [] e[1] = 4 /\ e[2] > Max -> "connFlow"
                [] e[1] = 5 /\ (e[2] < FrameMin \/ e[2] > FrameLimit) -> "connProtocol"
                [] OTHER -> "none"
InvalidCodes(vals) == {Invalid(vals[i]) : i \in DOMAIN vals} \ {"none"}

\* Section 6.9.2: each SETTINGS_INITIAL_WINDOW_SIZE moves every active
\* stream's window by the change, in order; a value that takes one past
\* Max fails the connection.
Inits(vals) == SelectSeq(Values(vals, 4), LAMBDA x : x <= Max)
Overflows(vals) == \E x \in Range(Inits(vals)), s \in Streams :
                     active[s] /\ win[s] + (x - init) > Max
Errors(vals) == InvalidCodes(vals) \cup (IF Overflows(vals) THEN {"connFlow"} ELSE {})
Last(seq, otherwise) == IF seq = <<>> THEN otherwise ELSE seq[Len(seq)]
FinalInit(vals) == Last(Inits(vals), init)
FinalFrame(vals) == Last(Values(vals, 5), frameMax)

\* The largest initial window the sender may still be sending under: the
\* last it acknowledged or any announced since (section 6.5.3: a value
\* takes effect for the announcer only at the ACK).
SlackMax == LET all == {acked} \cup Range(pending)
            IN CHOOSE m \in all : \A x \in all : x <= m

---------------------------------------------------------------------------
(* The sender's rules *)

\* Section 6.9.1 and 4.2: DATA goes out only within both windows and the
\* frame size the receiver set, on a stream that may still send, and takes
\* its length off both windows.
SendWithinWindows ==
  [][ev'.k = "send" /\ ev'.n > 0 =>
       /\ active[ev'.s]
       /\ ev'.n <= conn /\ ev'.n <= win[ev'.s] /\ ev'.n <= frameMax
       /\ conn' = conn - ev'.n
       /\ win'[ev'.s] = win[ev'.s] - ev'.n]_vars

\* Section 6.9: an increment of 0 is a connection error on stream 0 and a
\* stream error on a stream (a stream that can send no more may ignore it;
\* section 5.1 makes one on an idle stream a connection error).
WindowUpdateZero ==
  [][ev'.k = "wu" /\ ev'.inc = 0 /\ settled =>
       IF ev'.s = 0 THEN ev'.v = "connProtocol"
       ELSE \/ ev'.v = "streamProtocol"
            \/ ev'.v = "ignored" /\ ~active[ev'.s]
            \/ ev'.v = "connProtocol" /\ ~known[ev'.s]]_vars

\* Section 5.1: WINDOW_UPDATE on an idle stream is a connection error.
WindowUpdateIdle ==
  [][ev'.k = "wu" /\ ev'.s # 0 /\ settled /\ ~known[ev'.s] => ev'.v = "connProtocol"]_vars

\* Section 6.9.1: the connection window grows by the increment, and past
\* Max the connection fails with FLOW_CONTROL_ERROR.
ConnWindowUpdate ==
  [][ev'.k = "wu" /\ ev'.s = 0 /\ ev'.inc > 0 /\ settled =>
       IF conn + ev'.inc > Max THEN ev'.v = "connFlow"
       ELSE ev'.v = "ok" /\ conn' = conn + ev'.inc]_vars

\* Sections 6.9.1 and 6.9: a stream's window grows by the increment, and
\* past Max the stream, not the connection, ends with RST_STREAM
\* FLOW_CONTROL_ERROR. On a stream that can send no more it is no error.
StreamWindowUpdate ==
  [][ev'.k = "wu" /\ ev'.s # 0 /\ ev'.inc > 0 /\ settled /\ known[ev'.s] =>
       /\ ev'.v \notin ConnErrors
       /\ active[ev'.s] =>
            IF win[ev'.s] + ev'.inc > Max THEN ev'.v = "streamFlow"
            ELSE ev'.v = "ok" /\ win'[ev'.s] = win[ev'.s] + ev'.inc]_vars

\* Sections 6.5.2, 6.5.3 and 6.9.2: a SETTINGS frame is processed value by
\* value, in order. A value no endpoint may announce, or an initial window
\* that takes an active stream past Max, fails the connection with the
\* code of one of them. Otherwise the last value of each identifier holds:
\* every active stream's window moves by the change of initial window
\* (and may go below zero), the connection window does not move, and the
\* frame size is the one announced. Unknown identifiers change nothing.
SettingsApplied ==
  [][ev'.k = "settings" =>
       LET vals == ev'.vals IN
       IF Errors(vals) = {} THEN
         /\ ev'.v = "ok"
         /\ init' = FinalInit(vals)
         /\ frameMax' = FinalFrame(vals)
         /\ conn' = conn
         /\ \A s \in Streams : active[s] => win'[s] = win[s] + (init' - init)
       ELSE ev'.v \in Errors(vals)]_vars

\* Section 6.5.3: the ACK goes out once every value is applied, and only
\* then.
SettingsAcked ==
  [][ev'.k = "settings" => (ev'.ack <=> ev'.v = "ok")]_vars

\* Section 6.5: SETTINGS not on stream 0 is a connection PROTOCOL_ERROR; a
\* length not a multiple of 6, or an ACK with a payload, a connection
\* FRAME_SIZE_ERROR. None is acknowledged.
SettingsFrame ==
  [][ev'.k = "badSettings" =>
       /\ ev'.v = (IF ev'.bad = "stream" THEN "connProtocol" ELSE "connFrameSize")
       /\ ~ev'.ack]_vars

\* Section 6.5.3: an ACK for SETTINGS sent ends their wait: values the
\* sender had not acknowledged now hold for it in the order announced. An
\* ACK when none is awaited is not defined by the RFC; ignoring it and
\* treating it as a connection PROTOCOL_ERROR are both allowed.
AckHandling ==
  [][ev'.k = "ack" /\ settled =>
       IF pending # <<>>
         THEN ev'.v = "ok" /\ pending' = Tail(pending) /\ acked' = Head(pending)
         ELSE ev'.v \in {"ok", "ignored", "connProtocol"}]_vars

\* Section 3.4: the first frame after the preface is SETTINGS; any other is
\* a connection PROTOCOL_ERROR.
FirstFrameSettings ==
  [][ev'.k \in {"data", "wu", "ack", "headers"} /\ ~settled => ev'.v = "connProtocol"]_vars

---------------------------------------------------------------------------
(* The receiver's rules *)

\* Sections 6.9 and 6.9.1: every DATA frame, padding and pad length byte
\* included, counts against the connection window unless it ends the
\* connection; one accepted counts against its stream's window too.
DataDebits ==
  [][ev'.k = "data" /\ settled /\ ev'.v \notin ConnErrors =>
       /\ conn' = conn - ev'.n
       /\ ev'.v = "ok" => /\ win'[ev'.s] = win[ev'.s] - ev'.n
                          /\ bound'[ev'.s] = bound[ev'.s] - ev'.n]_vars

\* Section 6.9.1: DATA past the connection window is a connection
\* FLOW_CONTROL_ERROR (NoFalseFlowError says when one may come for DATA
\* within it).
ConnExcess ==
  [][ev'.k = "data" /\ settled /\ ev'.n > conn => ev'.v = "connFlow"]_vars

\* Section 6.9.1: DATA the sender may send is never refused for flow
\* control: a FLOW_CONTROL_ERROR for DATA within the connection window
\* means it passed the stream's bound.
NoFalseFlowError ==
  [][ev'.k = "data" /\ settled /\ ev'.v \in {"streamFlow", "connFlow"} /\ ev'.n <= conn =>
       ev'.n > bound[ev'.s]]_vars

\* Section 6.9.1 lets a receiver refuse DATA past a stream's window, with a
\* stream or a connection error. Checked where the code chooses to.
StreamExcessRefused ==
  [][ev'.k = "data" /\ settled /\ active[ev'.s] /\ ev'.n <= conn /\ ev'.n > bound[ev'.s] =>
       ev'.v \in {"streamFlow", "connFlow"}]_vars

\* Section 6.9.1: credit is never 0 and never takes a window past Max.
GrantWithinMax ==
  [][ev'.k = "grant" =>
       /\ ev'.inc > 0
       /\ ev'.s = 0 => conn' = conn + ev'.inc /\ conn' <= Max
       /\ ev'.s # 0 => bound'[ev'.s] = bound[ev'.s] + ev'.inc /\ bound'[ev'.s] <= Max]_vars

\* Sections 6.5.3 and 6.9.2: until the sender acknowledges a smaller
\* initial window, it may still send under the larger one; the receiver's
\* bound covers every window the sender may hold.
BoundCovers == \A s \in Streams : active[s] => bound[s] >= win[s] + (SlackMax - init)

---------------------------------------------------------------------------
(* Either side *)

\* Section 5.4.1: a connection error is answered with GOAWAY carrying its
\* code.
ConnErrorGoaway ==
  [][ev'.v \in ConnErrors => ev'.goaway = ev'.v]_vars
=============================================================================
