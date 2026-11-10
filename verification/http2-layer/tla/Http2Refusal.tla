---------------------------- MODULE Http2Refusal ----------------------------
(* How the HTTP/2 server layer `Http2` (src/stdlib/web/httpd/http2.rs)     *)
(* ends a connection it refuses, against RFC 9113 (RfcGoaway.tla): past     *)
(* its budget (`over_budget`), at one of its limits on the client (too     *)
(* many resets, pending resets or CONTINUATION frames), or for the         *)
(* client's protocol error (`fail`). Output is a queue of pieces (`sent`)  *)
(* the transport takes in order; a DATA frame of the largest size goes as  *)
(* a header piece and a payload piece. The GOAWAY that ends a connection  *)
(* is paid for when it opens (`last_words`) and has a place kept for it   *)
(* behind every piece (`push_piece` reserves two).                         *)
(*                                                                        *)
(* Source lines, at the commit in README.md (section "Http2Refusal"):      *)
(*   Http2::open: last_words                http2.rs 559-606               *)
(*   push_piece, frame_for, control         http2.rs 637-685               *)
(*   goaway                                 http2.rs 687-700               *)
(*   fail, close, end_all                   http2.rs 703-731               *)
(*   over_budget, finish                    http2.rs 736-776               *)
(*   write_reset                            http2.rs 780-801               *)
(*   admit: refused streams                 http2.rs 831-911               *)
(*   on_headers: last_stream, draining      http2.rs 1128-1216             *)
(*   on_frame: CONTINUATION limit           http2.rs 1306-1326             *)
(*   dispatch: RST_STREAM, PING, GOAWAY     http2.rs 1427-1466             *)
(*   read: input past the budget            http2.rs 1519-1576             *)
(*   send_one: a DATA frame in two pieces   http2.rs 1777-1868             *)
(*   written: a finished stream's reset     http2.rs 1887-1947             *)
(*   advance: graceful shutdown             http2.rs 2102-2158             *)
(*   take_command                           http2.rs 2160-2176             *)
(*                                                                        *)
(* Abstractions. The budget is a count of units: a frame's bytes cost one, *)
(* a stream one, and each place of `sent` past the `Keep` it holds from    *)
(* the start one; a DATA payload is the child's allocation and costs none *)
(* here. Anything else that can run out of budget (events for children,   *)
(* input storage, a body piece) is `Squeeze`, which takes a unit, and      *)
(* `Elsewhere`, which finds the budget spent. Streams 1 and 3; a header   *)
(* block the client begins in HEADERS may be cut off by a refusal before  *)
(* its CONTINUATION.                                                       *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS Streams, Budget, Keep, MaxSteps, MaxWindow,
          Guard,        \* push_piece queues nothing once the connection is closing
          Reserve,      \* push_piece keeps a place free behind every piece
          MinLast,      \* the end's GOAWAY keeps the last stream of any before it
          KeepPayload,  \* over_budget keeps the payload of a header the transport took
          WithLastWords, \* the end's GOAWAY is paid for at the start
          LastOnRead,   \* a stream becomes the last once its block is read whole
          EndAll,       \* closing ends every stream
          StopReading   \* nothing is read once the connection is closing

VARIABLES phase,     \* "open", "closing" (the end queued behind the output), "closed"
          sent,      \* Http2::sent: the pieces queued, the first `taken` with the transport
          taken,     \* Http2::taken
          cap,       \* the places `sent` holds
          wire,      \* the pieces the transport wrote
          free,      \* budget units left
          lastWords, \* Http2::last_words is charged
          streams,   \* Http2::streams
          lastStream,\* Http2::last_stream
          goawayLast,\* Http2::goaway_last (MaxWindow for none)
          pending,   \* the stream of a header block begun, or 0
          draining,  \* Http2::draining
          shut,      \* graceful shutdown: "no", "asked", "done"
          cause,     \* history: why the connection ends
          acted,     \* history: streams the server opened
          lost,      \* history: a refusal's GOAWAY did not fit
          nextFrame, \* frame numbers
          steps
vars == <<phase, sent, taken, cap, wire, free, lastWords, streams, lastStream, goawayLast,
          pending, draining, shut, cause, acted, lost, nextFrame, steps>>
outVars == <<sent, taken, cap, wire, free, lastWords, goawayLast, lost, nextFrame>>

Piece(kind, part, code, last) ==
  [f |-> nextFrame, kind |-> kind, part |-> part, code |-> code, last |-> last]
Cost(p) == IF p.part = "payload" \/ (p.kind = "goaway" /\ p.code # "NO_ERROR") THEN 0 ELSE 1
Min(a, b) == IF a < b THEN a ELSE b

Init ==
  /\ phase = "open" /\ sent = <<>> /\ taken = 0 /\ cap = Keep /\ wire = <<>>
  \* `open` charges the end's GOAWAY.
  /\ lastWords = WithLastWords /\ free = Budget - (IF WithLastWords THEN 1 ELSE 0)
  /\ streams = {} /\ lastStream = 0 /\ goawayLast = MaxWindow /\ pending = 0 /\ draining = FALSE
  /\ shut = "no" /\ cause = "none" /\ acted = {} /\ lost = FALSE /\ nextFrame = 1 /\ steps = 0

Step == (phase = "open" \/ ~StopReading) /\ steps < MaxSteps /\ steps' = steps + 1

---------------------------------------------------------------------------
(* The connection's end, as state transformers: records of the output     *)
(* variables and the streams.                                             *)

\* `close` and `end_all`: every stream ends (its child is told) and frees
\* its unit; the end goes behind what is queued.
Close(o) == IF o.phase # "open" THEN o
            ELSE IF ~EndAll THEN [o EXCEPT !.phase = "closing"]
            ELSE [o EXCEPT !.phase = "closing", !.free = @ + Cardinality(o.streams),
                           !.streams = {}]

\* `finish`: the GOAWAY in the place kept for it, paid for at the start.
Finish(o, code, why) ==
  LET last == IF MinLast THEN Min(o.lastStream, o.goawayLast) ELSE o.lastStream
      g == [f |-> o.nextFrame, kind |-> "goaway", part |-> "whole", code |-> code, last |-> last]
      fits == Len(o.sent) < o.cap
      o2 == IF o.lastWords
              THEN [o EXCEPT !.lastWords = FALSE, !.nextFrame = @ + 1,
                             !.sent = IF fits THEN Append(@, g) ELSE @,
                             !.lost = @ \/ ~fits,
                             !.cause = IF @ = "none" THEN why ELSE @]
              ELSE [o EXCEPT !.lost = @ \/ o.phase = "open",
                             !.cause = IF @ = "none" THEN why ELSE @]
  IN Close(o2)

\* `over_budget`: what the transport has not taken is dropped, except the
\* payload of a header it took, and the GOAWAY ENHANCE_YOUR_CALM follows.
OverBudget(o) ==
  IF o.phase # "open" THEN o
  ELSE LET keep == IF KeepPayload /\ o.taken < Len(o.sent) /\ o.sent[o.taken + 1].part = "payload"
                   THEN 1 ELSE 0
           cut == o.taken + keep
           dropped == SubSeq(o.sent, cut + 1, Len(o.sent))
           refund == LET RECURSIVE R(_) R(q) == IF q = <<>> THEN 0 ELSE Cost(Head(q)) + R(Tail(q))
                     IN R(dropped)
       IN Finish([o EXCEPT !.sent = SubSeq(@, 1, cut), !.free = @ + refund],
                 "ENHANCE_YOUR_CALM", "budget")

\* `push_piece` for a piece whose bytes are charged (`charged`): two places
\* free, the second kept for the last GOAWAY, or the connection ends.
Push(o, p, charged) ==
  IF Guard /\ o.phase # "open"
    THEN [o EXCEPT !.free = @ + charged]  \* the bytes are dropped
  ELSE LET room == IF Reserve THEN 2 ELSE 1
           grow == IF Len(o.sent) + room > o.cap THEN Len(o.sent) + room - o.cap ELSE 0
       IN IF grow > o.free
            THEN OverBudget([o EXCEPT !.free = @ + charged])
            ELSE [o EXCEPT !.cap = @ + grow, !.free = @ - grow, !.sent = Append(@, p),
                           !.nextFrame = @ + 1]

\* `frame_for`: the frame's bytes are charged, then queued.
Frame(o, kind, code, last) ==
  IF o.free < 1 THEN OverBudget(o)
  ELSE Push([o EXCEPT !.free = @ - 1],
            [f |-> o.nextFrame, kind |-> kind, part |-> "whole", code |-> code, last |-> last], 1)

\* `goaway` for a graceful end: an ordinary frame, the last stream never
\* growing.
Goaway(o, last) ==
  LET l == Min(last, o.goawayLast)
  IN Frame([o EXCEPT !.goawayLast = l], "goaway", "NO_ERROR", l)

\* The state as a record, and back.
Now == [phase |-> phase, sent |-> sent, taken |-> taken, cap |-> cap, free |-> free,
        lastWords |-> lastWords, streams |-> streams, lastStream |-> lastStream,
        goawayLast |-> goawayLast, cause |-> cause, lost |-> lost, nextFrame |-> nextFrame]
Becomes(o) ==
  /\ phase' = o.phase /\ sent' = o.sent /\ taken' = o.taken /\ cap' = o.cap
  /\ free' = o.free /\ lastWords' = o.lastWords /\ streams' = o.streams
  /\ lastStream' = o.lastStream /\ goawayLast' = o.goawayLast /\ cause' = o.cause
  /\ lost' = o.lost /\ nextFrame' = o.nextFrame

---------------------------------------------------------------------------
(* What happens on an open connection *)

\* A header block for new stream `s` read whole (`on_headers`): it becomes
\* the last stream; while draining it is refused with RST_STREAM
\* REFUSED_STREAM, as when `admit` finds no budget for its state.
Opens(s) ==
  IF ~draining /\ free >= 1
    THEN /\ Becomes([Now EXCEPT !.lastStream = s, !.streams = @ \cup {s}, !.free = @ - 1])
         /\ acted' = acted \cup {s}
    ELSE /\ Becomes(Frame([Now EXCEPT !.lastStream = s], "rst", "REFUSED_STREAM", 0))
         /\ UNCHANGED acted

\* HEADERS for a new stream. With `begin`, the block continues in a
\* CONTINUATION still to come, and nothing is decoded yet.
ClientHeaders(s, begin) ==
  /\ Step /\ pending = 0 /\ s > lastStream
  /\ IF begin
       THEN /\ pending' = s
            /\ Becomes(IF LastOnRead THEN Now ELSE [Now EXCEPT !.lastStream = s])
            /\ UNCHANGED acted
       ELSE pending' = 0 /\ Opens(s)
  /\ UNCHANGED <<wire, draining, shut>>

\* The CONTINUATION that ends a header block begun.
ClientContinuation ==
  /\ Step /\ pending # 0
  /\ pending' = 0
  /\ Opens(pending)
  /\ UNCHANGED <<wire, draining, shut>>

\* A control frame: a SETTINGS ACK, a PING's answer, a WINDOW_UPDATE.
Control ==
  /\ Step
  /\ Becomes(Frame(Now, "ctl", "", 0))
  /\ UNCHANGED <<wire, pending, draining, shut, acted>>

\* `send_one`, a DATA frame of the largest size: its header, charged, then
\* its payload, the child's.
SendData(s) ==
  /\ Step /\ s \in streams
  /\ LET o1 == IF free < 1 THEN OverBudget(Now)
               ELSE Push([Now EXCEPT !.free = @ - 1], Piece("data", "head", "", 0), 1)
         o2 == IF o1.phase = "open" /\ Len(o1.sent) > Len(sent)
               THEN Push(o1, [f |-> nextFrame, kind |-> "data", part |-> "payload", code |-> "",
                              last |-> 0], 0)
               ELSE o1
     IN Becomes(o2)
  /\ UNCHANGED <<wire, pending, draining, shut, acted>>

\* `written`: a stream's END_STREAM went out with its request still open;
\* the stream ends and RST_STREAM NO_ERROR follows.
Finished(s) ==
  /\ Step /\ s \in streams
  /\ Becomes(Frame([Now EXCEPT !.streams = @ \ {s}, !.free = @ + 1], "rst", "NO_ERROR", 0))
  /\ UNCHANGED <<wire, pending, draining, shut, acted>>

\* The client's GOAWAY: the server drains, with a GOAWAY of its own.
ClientGoaway ==
  /\ Step
  /\ draining' = TRUE
  /\ Becomes(Goaway(Now, lastStream))
  /\ UNCHANGED <<wire, pending, shut, acted>>

\* `advance` after `graceful_shutdown`: GOAWAY with 2^31 - 1, then a PING.
Shutdown ==
  /\ Step /\ shut = "no"
  /\ shut' = "done"
  /\ Becomes(Frame(Goaway(Now, MaxWindow), "ping", "", 0))
  /\ UNCHANGED <<wire, pending, draining, acted>>

\* A limit on the client (resets, pending resets, CONTINUATION frames, the
\* last possibly in the middle of a header block): ENHANCE_YOUR_CALM by
\* `fail`, nothing dropped.
Limit ==
  /\ Step
  /\ Becomes(Finish(Now, "ENHANCE_YOUR_CALM", "error"))
  /\ UNCHANGED <<wire, pending, draining, shut, acted>>

\* The client's protocol error: `fail`.
ProtocolError ==
  /\ Step
  /\ Becomes(Finish(Now, "PROTOCOL_ERROR", "error"))
  /\ UNCHANGED <<wire, pending, draining, shut, acted>>

\* Something else takes a unit of the budget.
Squeeze ==
  /\ Step /\ free > 0
  /\ Becomes([Now EXCEPT !.free = @ - 1])
  /\ UNCHANGED <<wire, pending, draining, shut, acted>>

\* Something else (an event for a child, input, a body piece) finds no
\* budget: `over_budget`.
Elsewhere ==
  /\ Step /\ free = 0
  /\ Becomes(OverBudget(Now))
  /\ UNCHANGED <<wire, pending, draining, shut, acted>>

---------------------------------------------------------------------------
(* The transport, in any phase *)

\* `take_command`: the next piece goes to the transport.
Take ==
  /\ taken < Len(sent)
  /\ taken' = taken + 1
  /\ UNCHANGED <<phase, sent, cap, wire, free, lastWords, streams, lastStream, goawayLast,
                 pending, draining, shut, cause, acted, lost, nextFrame, steps>>

\* `written`: the first piece taken is written; it gives back its unit, and
\* a drained queue its places past `Keep`.
Written ==
  /\ taken > 0
  /\ wire' = Append(wire, Head(sent))
  /\ sent' = Tail(sent)
  /\ taken' = taken - 1
  /\ LET back == IF Tail(sent) = <<>> THEN cap - Keep ELSE 0
     IN /\ free' = free + Cost(Head(sent)) + back
        /\ cap' = cap - back
  /\ UNCHANGED <<phase, lastWords, streams, lastStream, goawayLast, pending, draining, shut, cause, acted,
                 lost, nextFrame, steps>>

\* `take_command`: the end, once every piece before it is taken.
End ==
  /\ phase = "closing" /\ taken = Len(sent)
  /\ phase' = "closed"
  /\ UNCHANGED <<sent, taken, cap, wire, free, lastWords, streams, lastStream, goawayLast,
                 pending, draining, shut, cause, acted, lost, nextFrame, steps>>

Next ==
  \/ \E s \in Streams, begin \in BOOLEAN : ClientHeaders(s, begin)
  \/ ClientContinuation \/ Control \/ ClientGoaway \/ Shutdown \/ Limit \/ ProtocolError
  \/ Squeeze \/ Elsewhere
  \/ \E s \in Streams : SendData(s) \/ Finished(s)
  \/ Take \/ Written \/ End

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Refinement *)

R == INSTANCE RfcGoaway WITH
       out <- wire \o sent,
       cause <- cause,
       acted <- acted,
       unread <- pending,
       live <- streams

TerminalLast == R!TerminalLast
RefusalSaysGoaway == R!RefusalSaysGoaway
WholeFrames == R!WholeFrames
LastNeverGrows == R!LastNeverGrows
LastCoversActed == R!LastCoversActed
NoStreamCarriedOn == R!NoStreamCarriedOn
NothingAfterEnd == R!NothingAfterEnd

\* The code's own promise: the end's GOAWAY always has its place.
GoawayFits == ~lost
=============================================================================
