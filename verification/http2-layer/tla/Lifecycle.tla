---------------------------- MODULE Lifecycle ----------------------------
(* The lives of a connection's streams and of the children that answer    *)
(* them: `Http2` in src/stdlib/web/httpd/http2.rs, `Children` in          *)
(* src/stdlib/layer/children.rs and `Respond` in                          *)
(* src/stdlib/web/httpd/http2/respond.rs.                                 *)
(*                                                                        *)
(* A client HEADERS on a new stream opens a child (`Http2::admit`, an      *)
(* `Opened` event up); the request's end goes up as `End`. The child      *)
(* (`Respond`) collects the body until the request ends or its body       *)
(* deadline fires, makes its answer, possibly as work the runtime polls,  *)
(* and sends a head, body and end down, which `Http2::on_child` frames.   *)
(* A stream is over when its END_STREAM is written (`Http2::written`),     *)
(* when either side resets it, or when the connection closes; each time   *)
(* `Http2::end_stream` frees its slot and sends its child `Closed`, on     *)
(* which `Children` drops the child with its timers and cancels its work. *)
(* GOAWAY: the client's own, or `Http2::graceful_shutdown` (GOAWAY with   *)
(* 2^31 - 1 and a PING, then GOAWAY with the last stream once the PING    *)
(* returns); while draining, new streams are refused and the connection   *)
(* closes once no stream is left.                                         *)
(*                                                                        *)
(* Source lines, at the commit in README.md:                              *)
(*   Http2::goaway, fail, close           http2.rs 411-447                *)
(*   Http2::write_reset, reset            http2.rs 479-519                *)
(*   Http2::admit                          http2.rs 530-577                *)
(*   Http2::end_stream                     http2.rs 630-646                *)
(*   Http2::headers_on, on_headers         http2.rs 654-768                *)
(*   Http2::on_data (stream states)        http2.rs 770-830                *)
(*   RST_STREAM, PING, GOAWAY arms         http2.rs 933-969                *)
(*   Http2::on_child                       http2.rs 1120-1146              *)
(*   Http2::send_one (the end)             http2.rs 1248-1310              *)
(*   Http2::written                        http2.rs 1327-1380              *)
(*   MuxOp::Child, Credit, Close arms      http2.rs 1446-1499              *)
(*   Http2::advance (shutdown, drain)      http2.rs 1523-1570              *)
(*   Children: Opened, terminal Closed,    children.rs 431-496,            *)
(*     a command out of a child            children.rs 374-397             *)
(*   Respond: on_event (Closed), on_timer, respond.rs 448-491, 501-510,    *)
(*     on_done, advance, respond           respond.rs 512-554, 394-436     *)
(*                                                                        *)
(* Left out: flow control and body bytes (Flow.tla), SETTINGS             *)
(* (Settings.tla), the reset list's one-second expiry and its bound (late *)
(* frames on a stream the server reset are ignored for the whole run),   *)
(* PRIORITY, HPACK, budgets and the error-reset limits.                   *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Ids,          \* the client's stream identifiers, odd
          MaxStreams,   \* Limits::streams, and the slots
          MaxFrames,    \* how many frames the client sends
          Refusable,    \* streams whose child `Children` may refuse
          Max,          \* 2^31 - 1, above every identifier
          RecordLast,       \* `on_headers` records a new stream as `last_stream`
          RefuseWhenDraining, \* `on_headers` refuses new streams while draining
          MinGoaway,        \* `goaway` never sends a larger last stream than before
          WaitForStreams,   \* `advance` closes a draining connection only with no stream left
          EndOnClientReset, \* the RST_STREAM arm ends the stream
          EndOnWritten,     \* `written` ends a stream once its END_STREAM is written
          RemoveSlot,       \* `end_stream` frees the stream's slot
          ChildrenRetire,   \* `Children` drops a child on `Closed`
          CancelWork        \* `Children` cancels a dropped child's work

ASSUME \A i \in Ids : i % 2 = 1 /\ i < Max

None == 0
Live == {"open", "remote"}

VARIABLES st,        \* the connection's stream: idle, open, remote (half closed from the client), gone
          reply,     \* Stream::reply: waiting, body, ending, ended (END_STREAM queued)
          slot,      \* the stream's child id is live in `Slots`
          last,      \* Http2::last_stream
          goawayLast,\* Http2::goaway_last, None before the first GOAWAY
          draining,  \* Http2::draining
          shutdown,  \* graceful shutdown: none, asked, pinged, done
          phase,     \* the connection: open, closing, closed
          up,        \* events for the children, in order: <<kind, stream>>
          down,      \* commands from the children, in order: <<kind, stream>>
          kid,       \* the child in `Children`: none, live, retired
          kstage,    \* Respond's stage: collecting, making, head (its answer made), done
          ended,     \* Respond: the request ended
          work,      \* the child's work is live in the runtime
          timer,     \* the child's body deadline is armed
          clientRst, \* the client reset the stream
          serverRst, \* the server reset the stream
          frames,    \* frames the client sent
          afterReset,\* history: a frame other than RST_STREAM queued for a reset stream
          pastGoaway,\* history: a stream opened above a GOAWAY's last stream
          grew,      \* history: a GOAWAY's last stream above an earlier one
          cutOff     \* history: a drain closed the connection under a live stream
vars == <<st, reply, slot, last, goawayLast, draining, shutdown, phase, up, down, kid,
          kstage, ended, work, timer, clientRst, serverRst, frames, afterReset, pastGoaway,
          grew, cutOff>>
connVars == <<st, reply, slot, last, goawayLast, draining, shutdown, phase>>
kidVars == <<kid, kstage, ended, work, timer>>
history == <<afterReset, pastGoaway, grew, cutOff>>

LiveIds == {i \in Ids : st[i] \in Live}

Init ==
  /\ st = [i \in Ids |-> "idle"]
  /\ reply = [i \in Ids |-> "waiting"]
  /\ slot = [i \in Ids |-> FALSE]
  /\ last = 0
  /\ goawayLast = None
  /\ draining = FALSE
  /\ shutdown = "none"
  /\ phase = "open"
  /\ up = <<>>
  /\ down = <<>>
  /\ kid = [i \in Ids |-> "none"]
  /\ kstage = [i \in Ids |-> "collecting"]
  /\ ended = [i \in Ids |-> FALSE]
  /\ work = [i \in Ids |-> FALSE]
  /\ timer = [i \in Ids |-> FALSE]
  /\ clientRst = [i \in Ids |-> FALSE]
  /\ serverRst = [i \in Ids |-> FALSE]
  /\ frames = 0
  /\ afterReset = FALSE
  /\ pastGoaway = FALSE
  /\ grew = FALSE
  /\ cutOff = FALSE

---------------------------------------------------------------------------
(* The connection's steps, as operators on the next state of its          *)
(* variables. Each conjoins the primed values it sets.                    *)

\* `Http2::goaway`: the last stream sent is never more than one sent before.
GoawayTo(l) ==
  LET sent == IF MinGoaway /\ goawayLast # None /\ goawayLast < l THEN goawayLast ELSE l
  IN /\ goawayLast' = sent
     /\ grew' = (grew \/ (goawayLast # None /\ sent > goawayLast))

\* `Http2::end_stream` for every stream in `S`: each leaves `streams`, frees
\* its slot and sends its child `Closed`.
EndStreams(S, s, u) ==
  /\ st' = [i \in Ids |-> IF i \in S THEN "gone" ELSE s[i]]
  /\ slot' = [i \in Ids |-> IF i \in S /\ RemoveSlot THEN FALSE ELSE slot[i]]
  /\ \E order \in [1..Cardinality(S) -> S] :
       /\ \A k, m \in 1..Cardinality(S) : k # m => order[k] # order[m]
       /\ up' = u \o [k \in 1..Cardinality(S) |-> <<"closed", order[k]>>]

\* A frame other than RST_STREAM is queued for stream `i`.
Framed(i) == afterReset' = (afterReset \/ clientRst[i] \/ serverRst[i])

\* `Http2::write_reset`: the stream ends and RST_STREAM goes out.
WriteReset(i) ==
  /\ EndStreams(IF st[i] \in Live THEN {i} ELSE {}, st, up)
  /\ serverRst' = [serverRst EXCEPT ![i] = TRUE]

\* `Http2::fail` and `Http2::close`: GOAWAY, every live stream ends.
Fail ==
  /\ GoawayTo(last)
  /\ EndStreams(LiveIds, st, up)
  /\ phase' = "closing"
  /\ UNCHANGED <<reply, last, draining, shutdown>>

ClientFrame == /\ phase = "open" /\ frames < MaxFrames /\ frames' = frames + 1

---------------------------------------------------------------------------
(* The client *)

\* What the code knows of a stream: whether it is in `resets` (the server
\* reset it; its late frames are ignored), in `streams`, or neither, then
\* told apart only by `last_stream`.
Ignored(i) == st[i] = "gone" /\ serverRst[i]
Unknown(i) == ~Ignored(i) /\ st[i] \notin Live

\* `Http2::on_headers` after `Http2::headers_on`: HEADERS on `i`, with
\* END_STREAM `end`.
Headers(i, end) ==
  /\ ClientFrame
  /\ \/ \* A stream the server reset: ignored.
        /\ Ignored(i)
        /\ UNCHANGED <<connVars, up, serverRst, history>>
     \/ \* Trailers on an open stream end its request.
        /\ st[i] = "open" /\ end
        /\ st' = [st EXCEPT ![i] = "remote"]
        /\ up' = Append(up, <<"end", i>>)
        /\ UNCHANGED <<reply, slot, last, goawayLast, draining, shutdown, phase, serverRst,
                       history>>
     \/ \* Trailers without END_STREAM, or HEADERS after the request ended.
        /\ (st[i] = "open" /\ ~end) \/ st[i] = "remote"
        /\ WriteReset(i)
        /\ UNCHANGED <<reply, last, goawayLast, draining, shutdown, phase, history>>
     \/ \* A stream that ended, or one below an identifier already used.
        /\ Unknown(i) /\ i <= last
        /\ Fail
        /\ UNCHANGED <<serverRst, afterReset, pastGoaway, cutOff>>
     \/ \* A new stream.
        /\ Unknown(i) /\ i > last
        /\ last' = IF RecordLast THEN i ELSE last
        /\ IF (RefuseWhenDraining /\ draining) \/ Cardinality(LiveIds) >= MaxStreams
                \/ Cardinality({j \in Ids : slot[j]}) >= MaxStreams
             THEN \* Refused, not counted as the client's error.
                  /\ st' = [st EXCEPT ![i] = "gone"]
                  /\ serverRst' = [serverRst EXCEPT ![i] = TRUE]
                  /\ UNCHANGED <<slot, up, pastGoaway>>
             ELSE /\ st' = [st EXCEPT ![i] = IF end THEN "remote" ELSE "open"]
                  /\ slot' = [slot EXCEPT ![i] = TRUE]
                  /\ up' = Append(up, <<"opened", i>>)
                       \o (IF end THEN <<<<"end", i>>>> ELSE <<>>)
                  /\ pastGoaway' = (pastGoaway \/ (goawayLast # None /\ i > goawayLast))
                  /\ UNCHANGED serverRst
        /\ UNCHANGED <<reply, goawayLast, draining, shutdown, phase, afterReset, grew, cutOff>>
  /\ UNCHANGED <<down, kidVars, clientRst>>

\* `Http2::on_data` for a DATA frame with END_STREAM on `i`.
DataEnd(i) ==
  /\ ClientFrame
  /\ \/ /\ Ignored(i)
        /\ UNCHANGED <<connVars, up, serverRst, history>>
     \/ /\ st[i] = "open"
        /\ st' = [st EXCEPT ![i] = "remote"]
        /\ up' = Append(up, <<"end", i>>)
        /\ UNCHANGED <<reply, slot, last, goawayLast, draining, shutdown, phase, serverRst,
                       history>>
     \/ /\ st[i] = "remote" \/ (Unknown(i) /\ i <= last)
        /\ WriteReset(i)
        /\ UNCHANGED <<reply, last, goawayLast, draining, shutdown, phase, history>>
     \/ /\ Unknown(i) /\ i > last
        /\ Fail
        /\ UNCHANGED <<serverRst, afterReset, pastGoaway, cutOff>>
  /\ UNCHANGED <<down, kidVars, clientRst>>

\* The RST_STREAM arm of `Http2::on_frame`: one on a stream above
\* `last_stream` names an idle stream and ends the connection.
ClientReset(i) ==
  /\ ClientFrame
  /\ \/ /\ i > last
        /\ Fail
        /\ UNCHANGED <<clientRst, afterReset, pastGoaway, cutOff>>
     \/ /\ i <= last
        /\ clientRst' = [clientRst EXCEPT ![i] = TRUE]
        /\ IF EndOnClientReset /\ st[i] \in Live
             THEN EndStreams({i}, st, up)
             ELSE UNCHANGED <<st, slot, up>>
        /\ UNCHANGED <<reply, last, goawayLast, draining, shutdown, phase, history>>
  /\ UNCHANGED <<down, kidVars, serverRst>>

\* The GOAWAY arm: the server drains and answers with its own.
ClientGoaway ==
  /\ ClientFrame
  /\ draining' = TRUE
  /\ GoawayTo(last)
  /\ UNCHANGED <<st, reply, slot, last, shutdown, phase, up, down, kidVars, clientRst,
                 serverRst, afterReset, pastGoaway, cutOff>>

\* The PING arm with the acknowledgment of the shutdown PING.
PingAck ==
  /\ ClientFrame
  /\ shutdown = "pinged"
  /\ shutdown' = "done"
  /\ draining' = TRUE
  /\ GoawayTo(last)
  /\ UNCHANGED <<st, reply, slot, last, phase, up, down, kidVars, clientRst, serverRst,
                 afterReset, pastGoaway, cutOff>>

---------------------------------------------------------------------------
(* The server *)

\* `Http2::graceful_shutdown`.
AskShutdown ==
  /\ phase = "open" /\ shutdown = "none"
  /\ shutdown' = "asked"
  /\ UNCHANGED <<st, reply, slot, last, goawayLast, draining, phase, up, down, kidVars,
                 clientRst, serverRst, frames, history>>

\* `Http2::advance`: GOAWAY with 2^31 - 1, then the PING.
StartShutdown ==
  /\ phase = "open" /\ shutdown = "asked" /\ ~draining
  /\ shutdown' = "pinged"
  /\ GoawayTo(Max)
  /\ UNCHANGED <<st, reply, slot, last, draining, phase, up, down, kidVars, clientRst,
                 serverRst, frames, afterReset, pastGoaway, cutOff>>

\* `Http2::advance`: a draining connection closes once no stream is left.
Drained ==
  /\ phase = "open" /\ draining
  /\ (~WaitForStreams \/ LiveIds = {})
  /\ cutOff' = (cutOff \/ LiveIds # {})
  /\ EndStreams(LiveIds, st, up)
  /\ phase' = "closing"
  /\ UNCHANGED <<reply, last, goawayLast, draining, shutdown, down, kidVars, clientRst,
                 serverRst, frames, afterReset, pastGoaway, grew>>

\* The transport takes the end.
TakeEnd ==
  /\ phase = "closing"
  /\ phase' = "closed"
  /\ UNCHANGED <<st, reply, slot, last, goawayLast, draining, shutdown, up, down, kidVars,
                 clientRst, serverRst, frames, history>>

\* `Http2::on_child` and the `Close` arm of `Http2::on_command`: the next
\* command from the children, for the stream whose child it names. A
\* command from a child whose slot is gone names no stream.
OnChild ==
  /\ down # <<>>
  /\ phase = "open"
  /\ LET c == Head(down)[1]
         i == Head(down)[2]
     IN /\ down' = Tail(down)
        /\ IF ~(slot[i] /\ st[i] \in Live)
             THEN UNCHANGED <<st, reply, slot, up, serverRst, afterReset>>
           ELSE IF c = "head" /\ reply[i] = "waiting"
             THEN /\ reply' = [reply EXCEPT ![i] = "body"]
                  /\ Framed(i)
                  /\ UNCHANGED <<st, slot, up, serverRst>>
           ELSE IF c = "data" /\ reply[i] = "body"
             THEN /\ Framed(i)
                  /\ UNCHANGED <<st, reply, slot, up, serverRst>>
           ELSE IF c = "end" /\ reply[i] = "body"
             THEN /\ reply' = [reply EXCEPT ![i] = "ending"]
                  /\ UNCHANGED <<st, slot, up, serverRst, afterReset>>
           ELSE \* A reset, a close by the children, or a command out of order.
                /\ WriteReset(i)
                /\ UNCHANGED <<reply, afterReset>>
  /\ UNCHANGED <<last, goawayLast, draining, shutdown, phase, kidVars, clientRst, frames,
                 pastGoaway, grew, cutOff>>

\* `Http2::send_one`: the end of a response whose body is out.
SendEnd(i) ==
  /\ phase = "open" /\ st[i] \in Live /\ reply[i] = "ending"
  /\ reply' = [reply EXCEPT ![i] = "ended"]
  /\ Framed(i)
  /\ UNCHANGED <<st, slot, last, goawayLast, draining, shutdown, phase, up, down, kidVars,
                 clientRst, serverRst, frames, pastGoaway, grew, cutOff>>

\* `Http2::written`: the END_STREAM is written; the stream is over, and one
\* whose request is still open is reset with NO_ERROR.
Written(i) ==
  /\ phase = "open" /\ st[i] \in Live /\ reply[i] = "ended" /\ EndOnWritten
  /\ EndStreams({i}, st, up)
  /\ serverRst' = [serverRst EXCEPT ![i] = (st[i] = "open") \/ @]
  /\ UNCHANGED <<reply, last, goawayLast, draining, shutdown, phase, down, kidVars,
                 clientRst, frames, history>>

---------------------------------------------------------------------------
(* The children: `Children` delivering events, and `Respond` *)

\* `Children::on_event`: the next event goes to its child.
Deliver ==
  /\ up # <<>>
  /\ LET k == Head(up)[1]
         i == Head(up)[2]
     IN /\ up' = Tail(up)
        /\ CASE k = "opened" ->
                  \* A new child; its body deadline runs until the request ends.
                  /\ kid' = [kid EXCEPT ![i] = "live"]
                  /\ timer' = [timer EXCEPT ![i] = TRUE]
                  /\ UNCHANGED <<kstage, ended, work, down>>
             [] k = "end" ->
                  /\ ended' = [ended EXCEPT ![i] = kid[i] = "live" \/ @]
                  /\ UNCHANGED <<kid, kstage, work, timer, down>>
             [] k = "closed" ->
                  IF ChildrenRetire
                    THEN \* Dropped with its timers, its work cancelled, and `Close` down;
                         \* a child `Children` already refused is gone, and nothing happens.
                         /\ kid' = [kid EXCEPT ![i] = "retired"]
                         /\ timer' = [timer EXCEPT ![i] = FALSE]
                         /\ work' = [work EXCEPT ![i] = IF CancelWork THEN FALSE ELSE @]
                         /\ down' = IF kid[i] = "live" THEN Append(down, <<"close", i>>) ELSE down
                         /\ UNCHANGED <<kstage, ended>>
                    ELSE \* Delivered as any event: `Respond` stops answering.
                         /\ kstage' = [kstage EXCEPT ![i] = "done"]
                         /\ UNCHANGED <<kid, ended, work, timer, down>>
  /\ UNCHANGED <<connVars, clientRst, serverRst, frames, history>>

KidLive(i) == kid[i] = "live"

\* `Children` refuses a live child (its inbox full, its storage over the
\* budget, or the child failed): the child is dropped with its timers and
\* work, and `Close` goes down, which resets the stream.
Refuse(i) ==
  /\ KidLive(i) /\ i \in Refusable
  /\ kid' = [kid EXCEPT ![i] = "retired"]
  /\ timer' = [timer EXCEPT ![i] = FALSE]
  /\ work' = [work EXCEPT ![i] = FALSE]
  /\ down' = Append(down, <<"close", i>>)
  /\ UNCHANGED <<connVars, up, kstage, ended, clientRst, serverRst, frames, history>>

\* `Respond::advance`: the request ended; the handler's answer is work.
Dispatch(i) ==
  /\ KidLive(i) /\ kstage[i] = "collecting" /\ ended[i]
  /\ kstage' = [kstage EXCEPT ![i] = "making"]
  /\ work' = [work EXCEPT ![i] = TRUE]
  /\ timer' = [timer EXCEPT ![i] = FALSE]
  /\ UNCHANGED <<connVars, up, down, kid, ended, clientRst, serverRst, frames, history>>

\* `Respond::on_timer`: the body deadline answers without the handler.
Deadline(i) ==
  /\ KidLive(i) /\ timer[i]
  /\ timer' = [timer EXCEPT ![i] = FALSE]
  /\ kstage' = [kstage EXCEPT ![i] = IF @ = "collecting" THEN "head" ELSE @]
  /\ UNCHANGED <<connVars, up, down, kid, ended, work, clientRst, serverRst, frames, history>>

\* The runtime finishes the work: `Respond::on_done` has its answer, or
\* resets the stream.
WorkDone(i) ==
  /\ work[i]
  /\ work' = [work EXCEPT ![i] = FALSE]
  /\ \/ /\ KidLive(i) /\ kstage[i] = "making"
        /\ kstage' = [kstage EXCEPT ![i] = "head"]
        /\ UNCHANGED down
     \/ /\ KidLive(i) /\ kstage[i] = "making"
        /\ kstage' = [kstage EXCEPT ![i] = "done"]
        /\ down' = Append(down, <<"reset", i>>)
     \/ /\ ~(KidLive(i) /\ kstage[i] = "making")
        /\ UNCHANGED <<kstage, down>>
  /\ UNCHANGED <<connVars, up, kid, ended, timer, clientRst, serverRst, frames, history>>

\* `Respond::respond`, three times: the head, a body piece and the end go
\* down in order. (`Children` takes one at a time; the connection frames
\* each as it comes, between other streams' commands.)
Respond(i) ==
  /\ KidLive(i) /\ kstage[i] = "head"
  /\ kstage' = [kstage EXCEPT ![i] = "done"]
  /\ down' = down \o <<<<"head", i>>, <<"data", i>>, <<"end", i>>>>
  /\ UNCHANGED <<connVars, up, kid, ended, work, timer, clientRst, serverRst, frames, history>>

Next ==
  \/ \E i \in Ids, end \in BOOLEAN : Headers(i, end)
  \/ \E i \in Ids : DataEnd(i) \/ ClientReset(i)
  \/ ClientGoaway \/ PingAck
  \/ AskShutdown \/ StartShutdown \/ Drained \/ TakeEnd
  \/ OnChild
  \/ \E i \in Ids : SendEnd(i) \/ Written(i)
  \/ Deliver
  \/ \E i \in Ids : Dispatch(i) \/ Deadline(i) \/ WorkDone(i) \/ Respond(i) \/ Refuse(i)

\* Every step of the server and the children happens once it can; the
\* client sends what it likes.
Fairness ==
  /\ WF_vars(StartShutdown) /\ WF_vars(Drained) /\ WF_vars(TakeEnd)
  /\ WF_vars(OnChild) /\ WF_vars(Deliver)
  /\ \A i \in Ids : /\ WF_vars(SendEnd(i)) /\ WF_vars(Written(i))
                    /\ WF_vars(Dispatch(i)) /\ WF_vars(Deadline(i))
                    /\ WF_vars(WorkDone(i)) /\ WF_vars(Respond(i))

Spec == Init /\ [][Next]_vars /\ Fairness

---------------------------------------------------------------------------
(* Properties *)

\* The stream's state as RFC 9113 section 5.1 names it, from what the
\* server read and queued.
Rfc(i) ==
  CASE st[i] = "idle" /\ i > last -> "idle"
    [] st[i] = "open" /\ reply[i] # "ended" -> "open"
    [] st[i] = "open" /\ reply[i] = "ended" -> "local"
    [] st[i] = "remote" /\ reply[i] # "ended" -> "remote"
    [] OTHER -> "closed"

Allowed == {<<"idle", "open">>, <<"idle", "remote">>, <<"idle", "closed">>,
            <<"open", "local">>, <<"open", "remote">>, <<"open", "closed">>,
            <<"local", "closed">>, <<"remote", "closed">>}

\* Streams move only along the RFC's state machine: none comes back.
LegalTransitions ==
  [][\A i \in Ids : Rfc(i) = Rfc(i)' \/ <<Rfc(i), Rfc(i)'>> \in Allowed]_vars

\* No stream opens above the last stream of a GOAWAY the server sent
\* (RFC 9113 section 6.8).
NoStreamPastGoaway == ~pastGoaway

\* The last stream of each GOAWAY is never above an earlier one's (RFC 9113
\* section 6.8: endpoints MUST NOT increase it).
GoawayNeverGrows == ~grew

\* Nothing but RST_STREAM is queued for a stream once either side reset it
\* (RFC 9113 section 5.1, closed).
NoFrameAfterReset == ~afterReset

\* A child lives only while its stream does, or until the `Closed` already
\* on its way reaches it.
ChildRetiresWithStream ==
  \A i \in Ids : kid[i] = "live" =>
    (st[i] \in Live \/ \E k \in 1..Len(up) : up[k] = <<"closed", i>>)

\* A retired child has no work running and no timer armed.
NoWorkAfterRetire == \A i \in Ids : work[i] => kid[i] = "live"
NoTimerAfterRetire == \A i \in Ids : timer[i] => kid[i] = "live"

\* The slots hold exactly the live streams' children, so a closed stream
\* never keeps a later one out.
SlotsMatchStreams == \A i \in Ids : slot[i] <=> st[i] \in Live

\* A drain lets the streams in flight finish or be reset; it never cuts one
\* off by closing the connection under it.
InFlightFinish == ~cutOff

\* Every stream ends, and a draining connection closes.
StreamsEnd == \A i \in Ids : (st[i] \in Live) ~> (st[i] = "gone" \/ phase # "open")
DrainingCloses == draining ~> (phase = "closed")
=============================================================================
