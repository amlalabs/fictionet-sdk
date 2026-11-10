------------------------------ MODULE Http2Rfc ------------------------------
(* The HTTP/2 server layer `Http2` (src/stdlib/web/httpd/http2.rs) against *)
(* RFC 9113's flow control and SETTINGS (RfcFlow.tla): the client's DATA  *)
(* against the server's receive windows and the credit it returns; the    *)
(* server's DATA within the client's windows; the client's WINDOW_UPDATE   *)
(* and SETTINGS, their checks and the ACK. Each action follows the Rust   *)
(* step it names; two INSTANCEs of RfcFlow check the client-to-server and *)
(* server-to-client directions.                                           *)
(*                                                                        *)
(* Source lines, at the commit in README.md (section "Http2Rfc"):          *)
(*   decoder: setting_valid                  protocols/http2.rs 465-477    *)
(*            zero increment (decode_payload) protocols/http2.rs 488-599   *)
(*            frame scopes (Inputs::decode)  protocols/http2.rs 884-965    *)
(*   Http2::write_reset, end_stream          http2.rs 780-801, 1064-1093   *)
(*   on_data                                 http2.rs 1218-1276           *)
(*   peer_setting                            http2.rs 1279-1304           *)
(*   on_frame: the first frame               http2.rs 1306-1326           *)
(*   dispatch: SETTINGS, WINDOW_UPDATE arms  http2.rs 1367-1426           *)
(*   on_input: stream-scope refusals         http2.rs 1475-1514           *)
(*   release, credit_back                    http2.rs 1583-1627, 2349-2352 *)
(*   send_one, sendable                      http2.rs 1777-1868, 2358-2362 *)
(*   written: a finished stream's end        http2.rs 1887-1947           *)
(*   grown, shifted                          http2.rs 2366-2374           *)
(*                                                                        *)
(* Abstractions. `Max` stands for 2^31 - 1, `Default` for 65,535 (the     *)
(* server's receive windows and the client's initial window before its   *)
(* SETTINGS), `FrameMin` for 2^14 and `FrameLimit` for 2^24 - 1. Bytes are *)
(* units. The child of each stream reads all it holds at once and its     *)
(* credit is a whole window, as `Responder` composes it; `Flow.tla` has    *)
(* the children. Each SETTINGS frame is one of `SettingsFrames`. Streams  *)
(* open in order; even and reset-list expiry are left out (Lifecycle.tla).*)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS Max, Default, FrameMin, FrameLimit, Streams,
          DataLens,       \* DATA payload lengths the client sends
          Pads,           \* padding lengths, -1 for an unpadded frame
          Incs,           \* WINDOW_UPDATE increments the client sends
          SettingsFrames, \* SETTINGS frames the client sends, as value sequences
          RespBytes,      \* response body bytes per stream
          MaxFrames,      \* client frames
          \* The rules of the code; a control turns one off.
          SkipEnded,      \* initial window changes skip streams whose END_STREAM is framed
          ShiftStreams,   \* initial window changes move stream windows
          CountPadding,   \* on_data counts padding and its length byte
          CheckConn,      \* on_data refuses DATA past the connection window
          CheckStream,    \* on_data resets a stream past its window
          CheckOverflow,  \* a stream WINDOW_UPDATE past 2^31 - 1 resets it
          ZeroReset,      \* a zero increment on an open stream resets it
          TakeAck,        \* an ACK while one is awaited ends the wait
          FrameCap,       \* send_one keeps to the frame size
          SendCheck,      \* send_one keeps to the stream window
          PositiveCredit, \* credit_back returns credit only when there is some
          SendGoaway,     \* a connection error writes GOAWAY
          CheckFirst,     \* the first frame must be SETTINGS
          AckAfterApply,  \* the ACK is written once every value is applied
          RefuseBadSettings, \* the decoder refuses malformed SETTINGS
          CheckIdle,      \* WINDOW_UPDATE on an idle stream fails the connection
          CheckConnOverflow, \* connection credit past 2^31 - 1 fails it
          RecvOwn         \* on_data judges DATA by the stream's receive window

VARIABLES phase,      \* "open" or "failed" (GOAWAY queued, the end behind it)
          received,   \* Http2::received_settings
          awaiting,   \* Http2::awaiting_ack
          recvWindow, \* Http2::recv_window
          sendWindow, \* Http2::send_window
          initial,    \* Http2::initial
          frame,      \* Http2::frame
          st,         \* each stream: "idle", "open" (in Http2::streams) or "gone"
          rclosed,    \* Receive::closed
          ignored,    \* in Http2::resets
          rwin,       \* Receive::window
          swin,       \* Response::window
          held,       \* Delivery::windowed_bytes
          queued,     \* Response::queued_bytes
          made,       \* response bytes the child sent
          reply,      \* Response::reply: "body", "ending" or "ended"
          lastStream, \* Http2::last_stream
          ev,         \* the step, for RfcFlow
          frames      \* client frames sent
vars == <<phase, received, awaiting, recvWindow, sendWindow, initial, frame, st, rclosed,
          ignored, rwin, swin, held, queued, made, reply, lastStream, ev, frames>>
streamVars == <<st, rclosed, ignored, rwin, swin, held, queued, made, reply>>

ConnErrors == {"connFlow", "connProtocol", "connFrameSize"}
Min(a, b) == IF a < b THEN a ELSE b

Ev(dir, k, s, n, inc, vals, bad, v, ack) ==
  [dir |-> dir, k |-> k, s |-> s, n |-> n, inc |-> inc, vals |-> vals, bad |-> bad, v |-> v,
   ack |-> ack, goaway |-> IF v \in ConnErrors /\ SendGoaway THEN v ELSE "none"]
None == Ev("none", "none", 0, 0, 0, <<>>, "none", "ok", FALSE)

Init ==
  /\ phase = "open" /\ received = FALSE /\ awaiting = TRUE
  /\ recvWindow = Default /\ sendWindow = Default /\ initial = Default /\ frame = FrameMin
  /\ st = [s \in Streams |-> "idle"]
  /\ rclosed = [s \in Streams |-> FALSE]
  /\ ignored = [s \in Streams |-> FALSE]
  /\ rwin = [s \in Streams |-> 0]
  /\ swin = [s \in Streams |-> 0]
  /\ held = [s \in Streams |-> 0]
  /\ queued = [s \in Streams |-> 0]
  /\ made = [s \in Streams |-> 0]
  /\ reply = [s \in Streams |-> "body"]
  /\ lastStream = 0 /\ ev = None /\ frames = 0

ClientFrame == phase = "open" /\ frames < MaxFrames /\ frames' = frames + 1

\* `fail`: GOAWAY with the code, then the end; nothing else moves.
FailAck(dir, k, s, n, inc, vals, bad, v, ack) ==
  /\ phase' = "failed"
  /\ ev' = Ev(dir, k, s, n, inc, vals, bad, v, ack)
  /\ UNCHANGED <<received, awaiting, recvWindow, sendWindow, initial, frame, streamVars,
                 lastStream>>
Fail(dir, k, s, n, inc, vals, bad, v) == FailAck(dir, k, s, n, inc, vals, bad, v, FALSE)

\* The first-frame check of `on_frame`.
Early == ~received /\ CheckFirst

\* `write_reset` after `end_stream`: the stream's held bytes are dropped and
\* its late frames ignored.
Reset(s) ==
  /\ st' = [st EXCEPT ![s] = "gone"]
  /\ held' = [held EXCEPT ![s] = 0]
  /\ ignored' = [ignored EXCEPT ![s] = TRUE]

---------------------------------------------------------------------------
(* The client's frames *)

\* `setting_valid`, in the decoder: the frame is refused at the first value
\* no endpoint may announce.
Invalid(e) == CASE e[1] = 2 /\ e[2] \notin {0, 1} -> "connProtocol"
                [] e[1] = 4 /\ e[2] > Max -> "connFlow"
                [] e[1] = 5 /\ (e[2] < FrameMin \/ e[2] > FrameLimit) -> "connProtocol"
                [] OTHER -> "none"

\* The streams `peer_setting` moves for SETTINGS_INITIAL_WINDOW_SIZE.
Moved(s) == ShiftStreams /\ st[s] = "open" /\ (SkipEnded => reply[s] # "ended")

\* `peer_setting`, value by value: `shifted` refuses a window past 2^31 - 1
\* and the first refusal ends the loop.
RECURSIVE Apply(_, _)
Apply(r, es) ==
  IF es = <<>> \/ r.err # "none" THEN r
  ELSE LET e == Head(es) IN
       IF e[1] = 4 THEN
         IF \E s \in Streams : Moved(s) /\ r.swin[s] + (e[2] - r.initial) > Max
           THEN [r EXCEPT !.err = "connFlow"]
           ELSE Apply([r EXCEPT !.swin = [s \in Streams |->
                                           IF Moved(s) THEN r.swin[s] + (e[2] - r.initial)
                                           ELSE r.swin[s]],
                                !.initial = e[2]], Tail(es))
       ELSE IF e[1] = 5 THEN Apply([r EXCEPT !.frame = e[2]], Tail(es))
       ELSE Apply(r, Tail(es))

ClientSettings(vals) ==
  /\ ClientFrame
  /\ LET bad == SelectSeq(vals, LAMBDA e : Invalid(e) # "none")
         r == Apply([err |-> "none", swin |-> swin, initial |-> initial, frame |-> frame], vals)
     IN IF bad # <<>>
          THEN Fail("out", "settings", 0, 0, 0, vals, "none", Invalid(bad[1]))
          ELSE IF r.err # "none"
            THEN FailAck("out", "settings", 0, 0, 0, vals, "none", r.err, ~AckAfterApply)
            ELSE \* Every value is applied: now the ACK.
                 /\ received' = TRUE
                 /\ swin' = r.swin /\ initial' = r.initial /\ frame' = r.frame
                 /\ ev' = Ev("out", "settings", 0, 0, 0, vals, "none", "ok", TRUE)
                 /\ UNCHANGED <<phase, awaiting, recvWindow, sendWindow, st, rclosed, ignored,
                                rwin, held, queued, made, reply, lastStream>>

\* SETTINGS the decoder refuses for its header: on a stream, a length not a
\* multiple of 6, an ACK with a payload. Connection errors from the decoder.
ClientBadSettings(bad) ==
  /\ ClientFrame
  /\ IF RefuseBadSettings
       THEN Fail("out", "badSettings", 0, 0, 0, <<>>, bad,
                 IF bad = "stream" THEN "connProtocol" ELSE "connFrameSize")
       ELSE \* Taken as SETTINGS with no values.
            /\ received' = TRUE
            /\ ev' = Ev("out", "badSettings", 0, 0, 0, <<>>, bad, "ok", TRUE)
            /\ UNCHANGED <<phase, awaiting, recvWindow, sendWindow, initial, frame, streamVars,
                           lastStream>>

\* SETTINGS with ACK. One while none is awaited is a connection error.
ClientAck ==
  /\ ClientFrame
  /\ IF Early THEN Fail("in", "ack", 0, 0, 0, <<>>, "none", "connProtocol")
     ELSE IF awaiting /\ TakeAck
       THEN /\ awaiting' = FALSE
            /\ ev' = Ev("in", "ack", 0, 0, 0, <<>>, "none", "ok", FALSE)
            /\ UNCHANGED <<phase, received, recvWindow, sendWindow, initial, frame, streamVars,
                           lastStream>>
       ELSE Fail("in", "ack", 0, 0, 0, <<>>, "none", "connProtocol")

\* HEADERS opening a new stream; its send window is the initial window now.
ClientHeaders(s, end) ==
  /\ ClientFrame
  /\ st[s] = "idle" /\ s > lastStream
  /\ IF Early THEN Fail("in", "headers", s, 0, 0, <<>>, "none", "connProtocol")
     ELSE /\ st' = [st EXCEPT ![s] = "open"]
          /\ rwin' = [rwin EXCEPT ![s] = Default]
          /\ swin' = [swin EXCEPT ![s] = initial]
          /\ rclosed' = [rclosed EXCEPT ![s] = end]
          /\ lastStream' = s
          /\ ev' = Ev("in", "headers", s, 0, 0, <<>>, "none", "ok", FALSE)
          /\ UNCHANGED <<phase, received, awaiting, recvWindow, sendWindow, initial, frame,
                         ignored, held, queued, made, reply>>

\* DATA with `d` payload bytes and padding `p` (-1: not padded). Its length
\* field, the RFC's measure, is the payload, the pad length byte and the
\* padding; `on_data` counts `data.len() + padding.len() + 1`.
ClientData(s, d, p, end) ==
  /\ ClientFrame
  /\ LET n == d + (IF p >= 0 THEN p + 1 ELSE 0)
         size == d + (IF p >= 0 /\ CountPadding THEN p + 1 ELSE 0)
         rw == recvWindow - size
         w == rwin[s] - size
         limit == IF RecvOwn THEN rwin[s] ELSE swin[s]
         E(v) == Ev("in", "data", s, n, 0, <<>>, "none", v, FALSE)
         Keep == UNCHANGED <<phase, received, awaiting, sendWindow, initial, frame, lastStream>>
     IN IF Early THEN Fail("in", "data", s, n, 0, <<>>, "none", "connProtocol")
        ELSE IF rw < 0 /\ CheckConn THEN Fail("in", "data", s, n, 0, <<>>, "none", "connFlow")
        ELSE IF ignored[s]
          THEN /\ recvWindow' = rw /\ ev' = E("ignored") /\ Keep /\ UNCHANGED streamVars
        ELSE IF st[s] # "open"
          THEN IF s > lastStream
                 THEN Fail("in", "data", s, n, 0, <<>>, "none", "connProtocol")
                 ELSE /\ recvWindow' = rw /\ ev' = E("streamClosed") /\ Keep
                      /\ Reset(s)
                      /\ UNCHANGED <<rclosed, rwin, swin, queued, made, reply>>
        ELSE IF rclosed[s]
          THEN /\ recvWindow' = rw /\ ev' = E("streamClosed") /\ Keep
               /\ Reset(s)
               /\ UNCHANGED <<rclosed, rwin, swin, queued, made, reply>>
        ELSE IF limit - size < 0 /\ CheckStream
          THEN /\ recvWindow' = rw /\ ev' = E("streamFlow") /\ Keep
               /\ rwin' = [rwin EXCEPT ![s] = w]
               /\ Reset(s)
               /\ UNCHANGED <<rclosed, swin, queued, made, reply>>
        ELSE /\ recvWindow' = rw /\ ev' = E("ok") /\ Keep
             /\ rwin' = [rwin EXCEPT ![s] = w]
             /\ held' = [held EXCEPT ![s] = @ + d]
             /\ rclosed' = [rclosed EXCEPT ![s] = end]
             /\ UNCHANGED <<st, ignored, swin, queued, made, reply>>

\* WINDOW_UPDATE on `s` (0: the connection). An increment of 0 is refused by
\* the decoder: on stream 0 as a connection error, on a stream as a stream
\* error that `on_input` resolves.
ClientUpdate(s, inc) ==
  /\ ClientFrame
  /\ LET E(v) == ev' = Ev("out", "wu", s, 0, inc, <<>>, "none", v, FALSE)
         F(v) == Fail("out", "wu", s, 0, inc, <<>>, "none", v)
         Keep == UNCHANGED <<phase, received, awaiting, recvWindow, initial, frame, lastStream>>
     IN IF inc = 0 THEN
          IF s = 0 \/ ~received THEN F("connProtocol")
          ELSE IF s > lastStream /\ CheckIdle THEN F("connProtocol")
          ELSE IF ignored[s] THEN E("ignored") /\ Keep /\ UNCHANGED <<sendWindow, streamVars>>
          ELSE IF st[s] = "open" /\ ZeroReset
            THEN /\ E("streamProtocol") /\ Keep /\ UNCHANGED sendWindow
                 /\ Reset(s)
                 /\ UNCHANGED <<rclosed, rwin, swin, queued, made, reply>>
          ELSE E("ignored") /\ Keep /\ UNCHANGED <<sendWindow, streamVars>>
        ELSE IF Early THEN F("connProtocol")
        ELSE IF s = 0 THEN
          IF sendWindow + inc > Max /\ CheckConnOverflow THEN F("connFlow")
          ELSE /\ sendWindow' = sendWindow + inc /\ E("ok") /\ Keep
               /\ UNCHANGED streamVars
        ELSE IF st[s] = "open" THEN
          IF swin[s] + inc > Max /\ CheckOverflow
            THEN /\ E("streamFlow") /\ Keep /\ UNCHANGED sendWindow
                 /\ Reset(s)
                 /\ UNCHANGED <<rclosed, rwin, swin, queued, made, reply>>
            ELSE /\ swin' = [swin EXCEPT ![s] = @ + inc] /\ E("ok") /\ Keep
                 /\ UNCHANGED <<sendWindow, st, rclosed, ignored, rwin, held, queued, made,
                                reply>>
        ELSE IF s > lastStream /\ CheckIdle THEN F("connProtocol")
        ELSE E("ignored") /\ Keep /\ UNCHANGED <<sendWindow, streamVars>>

---------------------------------------------------------------------------
(* The server *)

Quiet == ev' = None /\ UNCHANGED frames

\* The child sends its body (`on_child`), one piece within its credit.
ChildData(s) ==
  /\ phase = "open" /\ st[s] = "open" /\ reply[s] = "body" /\ made[s] = 0
  /\ queued' = [queued EXCEPT ![s] = @ + RespBytes]
  /\ made' = [made EXCEPT ![s] = RespBytes]
  /\ Quiet
  /\ UNCHANGED <<phase, received, awaiting, recvWindow, sendWindow, initial, frame, st, rclosed,
                 ignored, rwin, swin, held, reply, lastStream>>

\* The child ends its body.
ChildEnd(s) ==
  /\ phase = "open" /\ st[s] = "open" /\ reply[s] = "body"
  /\ reply' = [reply EXCEPT ![s] = "ending"]
  /\ Quiet
  /\ UNCHANGED <<phase, received, awaiting, recvWindow, sendWindow, initial, frame, st, rclosed,
                 ignored, rwin, swin, held, queued, made, lastStream>>

\* `send_one`: a DATA frame within both windows and the frame size, or,
\* with the body all out, the empty DATA frame with END_STREAM.
SendOne(s) ==
  /\ phase = "open" /\ st[s] = "open"
  /\ IF queued[s] > 0
       THEN /\ swin[s] > 0 \/ ~SendCheck
            /\ sendWindow > 0
            /\ LET cap == IF FrameCap THEN Min(frame, FrameMin) ELSE queued[s]
                   room == IF SendCheck THEN swin[s] ELSE queued[s]
                   n == Min(Min(queued[s], sendWindow), Min(room, cap))
               IN /\ queued' = [queued EXCEPT ![s] = @ - n]
                  /\ swin' = [swin EXCEPT ![s] = @ - n]
                  /\ sendWindow' = sendWindow - n
                  /\ ev' = Ev("out", "send", s, n, 0, <<>>, "none", "ok", FALSE)
            /\ UNCHANGED reply
       ELSE /\ reply[s] = "ending"
            /\ reply' = [reply EXCEPT ![s] = "ended"]
            /\ ev' = Ev("out", "send", s, 0, 0, <<>>, "none", "ok", FALSE)
            /\ UNCHANGED <<queued, swin, sendWindow>>
  /\ UNCHANGED <<phase, received, awaiting, recvWindow, initial, frame, st, rclosed, ignored,
                 rwin, held, made, lastStream, frames>>

\* `written`: the transport took the END_STREAM; the stream ends, with
\* RST_STREAM NO_ERROR if the request is still open.
Written(s) ==
  /\ phase = "open" /\ st[s] = "open" /\ reply[s] = "ended"
  /\ st' = [st EXCEPT ![s] = "gone"]
  /\ held' = [held EXCEPT ![s] = 0]
  /\ ignored' = [ignored EXCEPT ![s] = ~rclosed[s]]
  /\ Quiet
  /\ UNCHANGED <<phase, received, awaiting, recvWindow, sendWindow, initial, frame, rclosed,
                 rwin, swin, queued, made, reply, lastStream>>

\* The child reads what it holds.
ChildReads(s) ==
  /\ phase = "open" /\ st[s] = "open" /\ held[s] > 0
  /\ held' = [held EXCEPT ![s] = 0]
  /\ Quiet
  /\ UNCHANGED <<phase, received, awaiting, recvWindow, sendWindow, initial, frame, st, rclosed,
                 ignored, rwin, swin, queued, made, reply, lastStream>>

\* `credit_back`: what tops a window up to its room, once that is more
\* than none and at least half of what the client has left; -1 for none.
CreditBack(w, room) ==
  IF (room - w > 0 \/ ~PositiveCredit) /\ room - w >= w \div 2 THEN room - w ELSE -1

HeldAll == LET RECURSIVE Sum(_) Sum(S) == IF S = {} THEN 0
                                          ELSE LET x == CHOOSE x \in S : TRUE
                                               IN held[x] + Sum(S \ {x})
           IN Sum(Streams)

\* `release`: connection credit for the bytes no stream holds.
GrantConnection ==
  /\ phase = "open"
  /\ LET back == CreditBack(recvWindow, Default - HeldAll)
     IN /\ back >= 0
        /\ recvWindow' = recvWindow + back
        /\ ev' = Ev("in", "grant", 0, 0, back, <<>>, "none", "ok", FALSE)
  /\ UNCHANGED <<phase, received, awaiting, sendWindow, initial, frame, streamVars, lastStream,
                 frames>>

\* `release`: a stream's credit, once its child read all it was given.
GrantStream(s) ==
  /\ phase = "open" /\ st[s] = "open"
  /\ LET back == CreditBack(rwin[s], Default - held[s])
     IN /\ back >= 0
        /\ rwin' = [rwin EXCEPT ![s] = @ + back]
        /\ ev' = Ev("in", "grant", s, 0, back, <<>>, "none", "ok", FALSE)
  /\ UNCHANGED <<phase, received, awaiting, recvWindow, sendWindow, initial, frame, st, rclosed,
                 ignored, swin, held, queued, made, reply, lastStream, frames>>

Next ==
  \/ \E vals \in SettingsFrames : ClientSettings(vals)
  \/ \E bad \in {"stream", "length", "ackPayload"} : ClientBadSettings(bad)
  \/ ClientAck
  \/ \E s \in Streams, end \in BOOLEAN : ClientHeaders(s, end)
  \/ \E s \in Streams, d \in DataLens, p \in Pads, end \in BOOLEAN : ClientData(s, d, p, end)
  \/ \E s \in {0} \cup Streams, inc \in Incs : ClientUpdate(s, inc)
  \/ \E s \in Streams : ChildData(s) \/ ChildEnd(s) \/ SendOne(s) \/ Written(s)
                        \/ ChildReads(s) \/ GrantStream(s)
  \/ GrantConnection

Spec == Init /\ [][Next]_vars

\* The SETTINGS frames of the configurations, with Max 4, Default 2,
\* FrameMin 1 and FrameLimit 2: an initial window up (to 3) and down (to 0,
\* which leaves a stream that sent below zero), two initial windows where
\* the second can pass Max, one past Max, a valid frame size with an
\* unknown identifier, a frame size and an ENABLE_PUSH no endpoint may
\* announce, and an empty frame.
\* Unpadded DATA, padded with none (the pad length byte alone), with one.
ClientPads == {-1, 0, 1}

ClientSettingsFrames ==
  { <<<<4, 3>>>>, <<<<4, 0>>>>, <<<<4, 1>>, <<4, 4>>>>, <<<<4, 5>>>>,
    <<<<5, 2>>, <<9, 7>>>>, <<<<5, 0>>>>, <<<<2, 2>>>>, <<>> }

---------------------------------------------------------------------------
(* Refinement: the two directions of RfcFlow *)

Only(dir) == IF ev.dir = dir THEN ev ELSE None

\* Client to server: the server receives. The client's windows are the
\* server's receive windows (the model has no frames in flight); the
\* server announces no window settings, so the receiver's bound is the
\* window itself; the ACK the client owes is for the server's SETTINGS.
In == INSTANCE RfcFlow WITH
        ev <- Only("in"),
        conn <- recvWindow,
        win <- rwin,
        bound <- rwin,
        active <- [s \in Streams |-> st[s] = "open" /\ ~rclosed[s]],
        known <- [s \in Streams |-> st[s] # "idle" \/ s <= lastStream],
        init <- Default,
        pending <- IF awaiting THEN <<Default>> ELSE <<>>,
        acked <- Default,
        frameMax <- FrameMin,
        settled <- received

\* Server to client: the server sends, and applies the client's settings
\* as it reads them. A stream whose END_STREAM is framed sends no more.
Out == INSTANCE RfcFlow WITH
        ev <- Only("out"),
        conn <- sendWindow,
        win <- swin,
        bound <- swin,
        active <- [s \in Streams |-> st[s] = "open" /\ reply[s] # "ended"],
        known <- [s \in Streams |-> st[s] # "idle" \/ s <= lastStream],
        init <- initial,
        pending <- <<>>,
        acked <- initial,
        frameMax <- frame,
        settled <- received

DataDebits == In!DataDebits
ConnExcess == In!ConnExcess
NoFalseFlowError == In!NoFalseFlowError
StreamExcessRefused == In!StreamExcessRefused
GrantWithinMax == In!GrantWithinMax
AckHandling == In!AckHandling
FirstFrameData == In!FirstFrameSettings
FirstFrameUpdate == Out!FirstFrameSettings
SendWithinWindows == Out!SendWithinWindows
WindowUpdateZero == Out!WindowUpdateZero
WindowUpdateIdle == Out!WindowUpdateIdle
ConnWindowUpdate == Out!ConnWindowUpdate
StreamWindowUpdate == Out!StreamWindowUpdate
SettingsApplied == Out!SettingsApplied
SettingsAcked == Out!SettingsAcked
SettingsFrame == Out!SettingsFrame
ConnErrorGoaway == In!ConnErrorGoaway /\ Out!ConnErrorGoaway
=============================================================================
