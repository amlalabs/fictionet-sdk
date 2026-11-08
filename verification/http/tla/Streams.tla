---------------------------- MODULE Streams ----------------------------
(* The HTTP/2 server's stream states in src/stdlib/web/httpd/http2.rs   *)
(* and http2/respond.rs: how the connection layer's `Http2::on_headers`, *)
(* `Http2::admit`, `Http2::on_data`, the RST_STREAM arm of               *)
(* `Http2::on_frame`, `Http2::response_head`, `Http2::send_one` and      *)
(* `Http2::written`, with the exchange child's `Respond` (`dispatch`,    *)
(* `respond`), move one connection's streams between the states of RFC  *)
(* 9113 section 5.1, with the server's reset list (`resets`) and the     *)
(* stream limit (`Limits::streams`). The child's work between them is    *)
(* one atomic step: the handler is called once, after the request ends  *)
(* or its body is refused.                                               *)
EXTENDS Naturals, FiniteSets
CONSTANTS Ids,          \* the client's stream identifiers, odd
          MaxStreams,   \* Limits::streams
          ResetMax,     \* RESET_MAX, the most streams in `resets`
          Responses,    \* response body sizes, in DATA frames of one unit
          IgnoreAfterReset,       \* `Http2::ignored` consulted in headers and data
          RefuseOverLimit,        \* the stream limit refuses new streams
          HalfClosedIsStreamError,\* DATA after END_STREAM resets the stream
          CheckBelowLast          \* HEADERS below last_stream ends the connection

ASSUME \A i \in Ids : i % 2 = 1
ASSUME MaxStreams \in Nat /\ ResetMax \in Nat /\ Responses \subseteq Nat

VARIABLES sstate,     \* per stream: Idle, Open, HalfRemote, Ignored or Closed
          last,       \* Http2::last_stream
          dispatched, \* Stream::request taken: the handler was called
          headSent,   \* the response HEADERS frame is out
          endSent,    \* the response's END_STREAM is out
          pending,    \* response body units left to send
          ignored,    \* Http2::resets, as the number of streams in it
          goaway,     \* a connection error ended the connection
          tookAfterEnd \* history: body bytes taken after the request's END_STREAM
vars == <<sstate, last, dispatched, headSent, endSent, pending, ignored, goaway, tookAfterEnd>>

States == {"Idle", "Open", "HalfRemote", "Ignored", "Closed"}
Live == {"Open", "HalfRemote"}
LiveIds == {i \in Ids : sstate[i] \in Live}
\* A stream the client never opened but whose identifier a later stream
\* passed (RFC 9113 section 5.1.1): closed, though never in `streams`.
Implicit(i) == sstate[i] = "Idle" /\ i <= last
TrulyIdle(i) == sstate[i] = "Idle" /\ i > last

TypeOK == /\ sstate \in [Ids -> States]
          /\ last \in Nat
          /\ dispatched \in [Ids -> BOOLEAN]
          /\ headSent \in [Ids -> BOOLEAN]
          /\ endSent \in [Ids -> BOOLEAN]
          /\ pending \in [Ids -> Nat]
          /\ ignored \in Nat
          /\ goaway \in BOOLEAN
          /\ tookAfterEnd \in [Ids -> BOOLEAN]

Init == /\ sstate = [i \in Ids |-> "Idle"]
        /\ last = 0
        /\ dispatched = [i \in Ids |-> FALSE]
        /\ headSent = [i \in Ids |-> FALSE]
        /\ endSent = [i \in Ids |-> FALSE]
        /\ pending = [i \in Ids |-> 0]
        /\ ignored = 0
        /\ goaway = FALSE
        /\ tookAfterEnd = [i \in Ids |-> FALSE]

\* `Http2::fail`: GOAWAY, and the connection closes.
Fail == /\ goaway' = TRUE
        /\ UNCHANGED <<sstate, last, dispatched, headSent, endSent, pending, ignored, tookAfterEnd>>

\* `Http2::write_reset`: the stream leaves `streams`, and its late frames
\* are ignored while `resets` has room for it.
ResetTo == IF ignored < ResetMax THEN "Ignored" ELSE "Closed"
Reset(i) == /\ sstate' = [sstate EXCEPT ![i] = ResetTo]
            /\ ignored' = IF ResetTo = "Ignored" THEN ignored + 1 ELSE ignored

\* `Respond` (`dispatch`): the request reaches the handler; its response has
\* `r` units of body.
Dispatch(i, r) == /\ dispatched' = [dispatched EXCEPT ![i] = TRUE]
                  /\ pending' = [pending EXCEPT ![i] = r]
NoDispatch == UNCHANGED <<dispatched, pending>>

Ignored(i) == sstate[i] = "Ignored" /\ IgnoreAfterReset

\* `Http2::on_headers`, after `Http2::headers_on`: a HEADERS frame on `i`
\* with END_STREAM `end`. On an open stream it is the trailers.
Headers(i, end, r) ==
  /\ ~goaway
  /\ UNCHANGED <<headSent, endSent, tookAfterEnd>>
  /\ \/ /\ Ignored(i)
        /\ UNCHANGED <<sstate, last, dispatched, pending, ignored, goaway>>
     \/ /\ sstate[i] = "HalfRemote"
        /\ Reset(i)
        /\ UNCHANGED <<last, dispatched, pending, goaway>>
     \/ /\ sstate[i] = "Open" /\ ~end
        /\ Reset(i)
        /\ UNCHANGED <<last, dispatched, pending, goaway>>
     \/ /\ sstate[i] = "Open" /\ end
        /\ sstate' = [sstate EXCEPT ![i] = "HalfRemote"]
        /\ IF dispatched[i] THEN NoDispatch ELSE Dispatch(i, r)
        /\ UNCHANGED <<last, ignored, goaway>>
     \/ /\ sstate[i] = "Closed" \/ (sstate[i] = "Ignored" /\ ~IgnoreAfterReset)
        /\ Fail
     \/ /\ Implicit(i) /\ CheckBelowLast
        /\ Fail
     \/ /\ TrulyIdle(i) \/ (Implicit(i) /\ ~CheckBelowLast)
        /\ last' = IF i > last THEN i ELSE last
        /\ IF Cardinality(LiveIds) >= MaxStreams /\ RefuseOverLimit
             THEN Reset(i) /\ NoDispatch
             ELSE /\ sstate' = [sstate EXCEPT ![i] = IF end THEN "HalfRemote" ELSE "Open"]
                  /\ IF end THEN Dispatch(i, r) ELSE NoDispatch
                  /\ UNCHANGED ignored
        /\ UNCHANGED goaway

\* `Http2::on_data`: a DATA frame on `i` with END_STREAM `end`. Flow control
\* is Flow.tla's; here every frame fits the windows.
Data(i, end, r) ==
  /\ ~goaway
  /\ UNCHANGED <<last, headSent, endSent>>
  /\ \/ /\ Ignored(i)
        /\ UNCHANGED <<sstate, dispatched, pending, ignored, goaway, tookAfterEnd>>
     \/ /\ TrulyIdle(i)
        /\ Fail
     \/ /\ sstate[i] = "Closed" \/ Implicit(i) \/ (sstate[i] = "Ignored" /\ ~IgnoreAfterReset)
        /\ Reset(i)
        /\ UNCHANGED <<dispatched, pending, goaway, tookAfterEnd>>
     \/ /\ sstate[i] = "HalfRemote" /\ HalfClosedIsStreamError
        /\ Reset(i)
        /\ UNCHANGED <<dispatched, pending, goaway, tookAfterEnd>>
     \/ /\ sstate[i] = "Open" \/ (sstate[i] = "HalfRemote" /\ ~HalfClosedIsStreamError)
        /\ sstate' = [sstate EXCEPT ![i] = IF end THEN "HalfRemote" ELSE sstate[i]]
        /\ tookAfterEnd' = [tookAfterEnd EXCEPT ![i] = tookAfterEnd[i] \/ sstate[i] = "HalfRemote"]
        /\ IF end /\ ~dispatched[i] THEN Dispatch(i, r) ELSE NoDispatch
        /\ UNCHANGED <<ignored, goaway>>

\* The RST_STREAM arm of `Http2::on_frame`, then `Http2::end_stream`: the stream
\* and its response go away. The server's reset list is not consulted or
\* extended.
ClientReset(i) ==
  /\ ~goaway
  /\ UNCHANGED <<last, dispatched, headSent, endSent, pending, ignored, tookAfterEnd>>
  /\ \/ /\ TrulyIdle(i)
        /\ Fail
     \/ /\ sstate[i] \in Live
        /\ sstate' = [sstate EXCEPT ![i] = "Closed"]
        /\ UNCHANGED goaway
     \/ /\ sstate[i] \notin Live /\ ~TrulyIdle(i)
        /\ UNCHANGED <<sstate, goaway>>

\* `Http2::on_timer`: a reset stream's second passes, and its late frames
\* are no longer ignored.
Expire(i) == /\ sstate[i] = "Ignored"
             /\ sstate' = [sstate EXCEPT ![i] = "Closed"]
             /\ ignored' = ignored - 1
             /\ UNCHANGED <<last, dispatched, headSent, endSent, pending, goaway, tookAfterEnd>>

\* `Respond::on_timer` with a body deadline, or `Http2::on_data` with a body
\* over its limit: the handler is called before the request ends.
EarlyAnswer(i, r) == /\ ~goaway
                     /\ sstate[i] = "Open" /\ ~dispatched[i]
                     /\ Dispatch(i, r)
                     /\ UNCHANGED <<sstate, last, headSent, endSent, ignored, goaway, tookAfterEnd>>

\* `Http2::written`: the response ended. A request still arriving is
\* asked to stop with RST_STREAM(NO_ERROR); a finished one closes the stream.
Done(i) == IF sstate[i] = "HalfRemote"
             THEN sstate' = [sstate EXCEPT ![i] = "Closed"] /\ UNCHANGED ignored
             ELSE Reset(i)

\* `Http2::response_head`: the response HEADERS frame, with END_STREAM when
\* the body is empty.
SendHead(i) == /\ ~goaway
               /\ sstate[i] \in Live /\ dispatched[i] /\ ~headSent[i]
               /\ headSent' = [headSent EXCEPT ![i] = TRUE]
               /\ IF pending[i] = 0
                    THEN endSent' = [endSent EXCEPT ![i] = TRUE] /\ Done(i)
                    ELSE UNCHANGED <<endSent, sstate, ignored>>
               /\ UNCHANGED <<last, dispatched, pending, goaway, tookAfterEnd>>

\* `Http2::send_one`: one DATA frame of the body.
SendData(i) == /\ ~goaway
               /\ sstate[i] \in Live /\ headSent[i] /\ pending[i] > 0
               /\ pending' = [pending EXCEPT ![i] = pending[i] - 1]
               /\ UNCHANGED <<sstate, last, dispatched, headSent, endSent, ignored, goaway, tookAfterEnd>>

\* `Http2::send_one`: the empty DATA frame with END_STREAM after the body.
SendEnd(i) == /\ ~goaway
              /\ sstate[i] \in Live /\ headSent[i] /\ pending[i] = 0 /\ ~endSent[i]
              /\ endSent' = [endSent EXCEPT ![i] = TRUE]
              /\ Done(i)
              /\ UNCHANGED <<last, dispatched, headSent, pending, goaway, tookAfterEnd>>

\* The keyed work of one stream's response, which the serve driver polls
\* beside every other stream's.
Respond(i) == SendHead(i) \/ SendData(i) \/ SendEnd(i)

Client == \E i \in Ids : \/ \E end \in BOOLEAN, r \in Responses : Headers(i, end, r) \/ Data(i, end, r)
                         \/ ClientReset(i)
Server == \E i \in Ids : \/ \E r \in Responses : EarlyAnswer(i, r)
                         \/ Respond(i) \/ Expire(i)
Next == Client \/ Server
Spec == Init /\ [][Next]_vars /\ \A i \in Ids : WF_vars(Respond(i))

\* RFC 9113 section 5.1.2: no more streams open or half-closed than announced.
Concurrency == Cardinality(LiveIds) <= MaxStreams
\* The reset list holds at most RESET_MAX streams, and counts exactly them.
IgnoredBounded == ignored <= ResetMax /\ ignored = Cardinality({i \in Ids : sstate[i] = "Ignored"})
\* RFC 9113 section 5.1.1: every stream the server has seen is at or
\* below the last identifier it took.
UsedBelowLast == \A i \in Ids : (sstate[i] # "Idle" \/ dispatched[i]) => i <= last
\* A response is written only for a request the handler saw, and ends once.
AnsweredOnce == \A i \in Ids : (headSent[i] => dispatched[i]) /\ (endSent[i] => headSent[i])
\* RFC 9113 section 5.1, half-closed (remote): no body is taken after the
\* request's END_STREAM.
NoBodyAfterEnd == \A i \in Ids : ~tookAfterEnd[i]

\* RFC 9113 section 5.1, half-closed (remote): DATA or HEADERS after the
\* request's END_STREAM is a stream error, and the connection goes on.
HalfClosedFramesAreStreamErrors ==
  [][\A i \in Ids, end \in BOOLEAN, r \in Responses :
      (sstate[i] = "HalfRemote" /\ (Data(i, end, r) \/ Headers(i, end, r)))
        => ~goaway' /\ sstate'[i] \in {"Ignored", "Closed"}]_vars
\* RFC 9113 sections 5.1 and 6.4: DATA or RST_STREAM on an idle stream
\* ends the connection.
IdleFramesEndConnection ==
  [][\A i \in Ids : TrulyIdle(i) /\ (ClientReset(i) \/ \E end \in BOOLEAN, r \in Responses : Data(i, end, r))
        => goaway']_vars
\* RFC 9113 sections 5.1 and 5.1.1: HEADERS on a closed stream, or below an
\* identifier already used, ends the connection.
ClosedHeadersEndConnection ==
  [][\A i \in Ids, end \in BOOLEAN, r \in Responses :
      (sstate[i] = "Closed" \/ Implicit(i)) /\ Headers(i, end, r) => goaway']_vars
\* RFC 9113 section 5.1, closed after RST_STREAM sent: late frames on a
\* stream the server reset are ignored while it remembers the reset.
LateFramesIgnored ==
  [][\A i \in Ids : sstate[i] = "Ignored"
      /\ (ClientReset(i) \/ \E end \in BOOLEAN, r \in Responses : Data(i, end, r) \/ Headers(i, end, r))
        => UNCHANGED vars]_vars
\* RFC 9113 section 8.1: the response's END_STREAM closes a stream whose
\* request ended, and resets one whose request is still arriving.
EndStreamClosesStream ==
  [][\A i \in Ids : (~endSent[i] /\ endSent'[i])
      => /\ sstate[i] = "HalfRemote" => sstate'[i] = "Closed"
         /\ sstate[i] = "Open" => sstate'[i] \in {"Ignored", "Closed"}]_vars
\* Every request the handler saw gets its whole response, unless its
\* stream or the connection ends first.
ResponsesEnd == \A i \in Ids : dispatched[i] ~> (endSent[i] \/ sstate[i] \notin Live \/ goaway)
=============================================================================
