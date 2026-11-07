------------------------------ MODULE Flow ------------------------------
(* HTTP/2 flow control in src/stdlib/web/httpd/http2.rs: the receive      *)
(* windows `Http2::data` debits and `Accept` with `release_window`        *)
(* refills by WINDOW_UPDATE; the send windows `Sending::poll_next` spends  *)
(* and the WINDOW_UPDATE and SETTINGS arms of `Http2::frame` refill; and   *)
(* the wakers that restart a response waiting for credit. Bytes are in    *)
(* units: a DATA frame carries one unit of payload and `extra` units of   *)
(* padding, and the windows hold a few units instead of 65,535 bytes.     *)
EXTENDS Integers, FiniteSets
CONSTANTS Ids,        \* the client's stream identifiers, odd
          RecvWindow, \* 65_535: the server's initial receive windows, connection and stream
          SendWindow, \* 65_535: the server's initial connection send window and SETTINGS_INITIAL_WINDOW_SIZE
          MaxWindow,  \* 2^31 - 1: the most a window may hold
          Frame,      \* the most payload in one DATA frame the server sends
          Responses,  \* response body sizes
          Requests,   \* request body sizes
          Initials,   \* values the client's SETTINGS_INITIAL_WINDOW_SIZE takes
          Extras,     \* padding per DATA frame the client sends
          CountPadding,           \* `Http2::data` debits padding and its length byte
          CheckConnectionWindow,  \* a negative connection window ends the connection
          CheckStreamWindow,      \* a negative stream window resets the stream
          ReleaseCredit,          \* `Accept` returns credit by WINDOW_UPDATE
          SpendWithinWindows,     \* `Sending::poll_next` sends no more than both windows allow
          WakeOnConnectionUpdate, \* a connection WINDOW_UPDATE wakes every waiting response
          WakeOnStreamUpdate,     \* a stream WINDOW_UPDATE wakes its response
          WakeOnSettings          \* SETTINGS_INITIAL_WINDOW_SIZE wakes every waiting response

ASSUME \A i \in Ids : i % 2 = 1
ASSUME RecvWindow \in Nat /\ SendWindow \in Nat /\ MaxWindow \in Nat /\ SendWindow <= MaxWindow
ASSUME Frame \in Nat \ {0}
ASSUME Responses \subseteq Nat /\ Requests \subseteq Nat /\ Initials \subseteq 0..MaxWindow
ASSUME Extras \subseteq Nat

VARIABLES sstate,       \* per stream: Idle, Open, HalfRemote or Closed
          last,         \* Http2::last_stream
          recvConn,     \* Outbound::recv_window
          recvStream,   \* Window::recv_window
          creditConn,   \* what the client may still send on the connection
          creditStream, \* what the client may still send on each stream
          sendConn,     \* Outbound::window
          sendStream,   \* Window::available
          initial,      \* Outbound::initial
          reqLeft,      \* request body units the client still has to send
          dispatched,   \* the handler was called
          pending,      \* response body units left to send
          headSent,     \* the response HEADERS frame is out
          endSent,      \* the response's END_STREAM is out
          waiting,      \* Sending stored its waker: it is not polled until woken
          goaway,       \* a connection error ended the connection
          overspent     \* history: the server sent DATA beyond a window
vars == <<sstate, last, recvConn, recvStream, creditConn, creditStream, sendConn, sendStream,
          initial, reqLeft, dispatched, pending, headSent, endSent, waiting, goaway, overspent>>

Live == {"Open", "HalfRemote"}
LiveIds == {i \in Ids : sstate[i] \in Live}
TrulyIdle(i) == sstate[i] = "Idle" /\ i > last
Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b

TypeOK == /\ sstate \in [Ids -> {"Idle", "Open", "HalfRemote", "Closed"}]
          /\ last \in Nat
          /\ recvConn \in Int /\ recvStream \in [Ids -> Int]
          /\ creditConn \in Int /\ creditStream \in [Ids -> Int]
          /\ sendConn \in Int /\ sendStream \in [Ids -> Int] /\ initial \in Nat
          /\ reqLeft \in [Ids -> Nat] /\ dispatched \in [Ids -> BOOLEAN]
          /\ pending \in [Ids -> Nat] /\ headSent \in [Ids -> BOOLEAN]
          /\ endSent \in [Ids -> BOOLEAN] /\ waiting \in [Ids -> BOOLEAN]
          /\ goaway \in BOOLEAN /\ overspent \in BOOLEAN

Init == /\ sstate = [i \in Ids |-> "Idle"]
        /\ last = 0
        /\ recvConn = RecvWindow /\ recvStream = [i \in Ids |-> RecvWindow]
        /\ creditConn = RecvWindow /\ creditStream = [i \in Ids |-> RecvWindow]
        /\ sendConn = SendWindow /\ sendStream = [i \in Ids |-> SendWindow] /\ initial = SendWindow
        /\ reqLeft = [i \in Ids |-> 0] /\ dispatched = [i \in Ids |-> FALSE]
        /\ pending = [i \in Ids |-> 0] /\ headSent = [i \in Ids |-> FALSE]
        /\ endSent = [i \in Ids |-> FALSE] /\ waiting = [i \in Ids |-> FALSE]
        /\ goaway = FALSE /\ overspent = FALSE

Dispatch(i, r) == /\ dispatched' = [dispatched EXCEPT ![i] = TRUE]
                  /\ pending' = [pending EXCEPT ![i] = r]
NoDispatch == UNCHANGED <<dispatched, pending>>

\* `Http2::headers` on a new stream: the request has `q` units of body to
\* come, and its response `r` units. The stream's windows start at the
\* receive default and the client's initial window.
Open(i, q, r) ==
  /\ ~goaway /\ TrulyIdle(i)
  /\ last' = i
  /\ sstate' = [sstate EXCEPT ![i] = IF q = 0 THEN "HalfRemote" ELSE "Open"]
  /\ reqLeft' = [reqLeft EXCEPT ![i] = q]
  /\ recvStream' = [recvStream EXCEPT ![i] = RecvWindow]
  /\ creditStream' = [creditStream EXCEPT ![i] = RecvWindow]
  /\ sendStream' = [sendStream EXCEPT ![i] = initial]
  /\ IF q = 0 THEN Dispatch(i, r) ELSE NoDispatch
  /\ UNCHANGED <<recvConn, creditConn, sendConn, initial, headSent, endSent, waiting, goaway,
                 overspent>>

\* The `size` of a DATA frame in `Http2::data`: payload, padding and the
\* padding length byte.
Size(extra) == 1 + (IF CountPadding /\ extra > 0 THEN extra ELSE 0)
\* What the frame costs the client under RFC 9113 section 6.9.
Charge(extra) == 1 + extra

\* `Http2::data` on an open stream: the client sends one unit of its body,
\* with `extra` padding, within the credit it has. The connection window
\* is debited first, for every stream; then the stream's window.
ClientData(i, extra, r) ==
  /\ ~goaway /\ sstate[i] = "Open" /\ reqLeft[i] > 0
  /\ Charge(extra) <= creditConn /\ Charge(extra) <= creditStream[i]
  /\ creditConn' = creditConn - Charge(extra)
  /\ creditStream' = [creditStream EXCEPT ![i] = creditStream[i] - Charge(extra)]
  /\ recvConn' = recvConn - Size(extra)
  /\ recvStream' = [recvStream EXCEPT ![i] = recvStream[i] - Size(extra)]
  /\ reqLeft' = [reqLeft EXCEPT ![i] = reqLeft[i] - 1]
  /\ sstate' = [sstate EXCEPT ![i] = IF reqLeft[i] = 1 THEN "HalfRemote" ELSE "Open"]
  /\ IF reqLeft[i] = 1 /\ ~dispatched[i] THEN Dispatch(i, r) ELSE NoDispatch
  /\ UNCHANGED <<last, sendConn, sendStream, initial, headSent, endSent, waiting, goaway, overspent>>

\* `Http2::data` from a client that sends beyond its credit: the connection
\* window check ends the connection; the stream window check resets the
\* stream. The frame still counts against the client's connection credit.
ClientOverData(i, extra) ==
  /\ ~goaway /\ sstate[i] = "Open"
  /\ Charge(extra) > creditConn \/ Charge(extra) > creditStream[i]
  /\ UNCHANGED <<last, sendConn, sendStream, initial, reqLeft, dispatched, pending, headSent,
                 endSent, waiting, overspent>>
  /\ creditConn' = creditConn - Charge(extra)
  /\ creditStream' = [creditStream EXCEPT ![i] = creditStream[i] - Charge(extra)]
  /\ recvConn' = recvConn - Size(extra)
  /\ IF recvConn' < 0 /\ CheckConnectionWindow
       THEN goaway' = TRUE /\ UNCHANGED <<sstate, recvStream>>
       ELSE /\ recvStream' = [recvStream EXCEPT ![i] = recvStream[i] - Size(extra)]
            /\ sstate' = [sstate EXCEPT ![i] =
                           IF recvStream'[i] < 0 /\ CheckStreamWindow THEN "Closed" ELSE "Open"]
            /\ UNCHANGED goaway

\* `Accept::poll_next` with `release_window`: once the client used at
\* least half of what it has left, the server returns that credit by
\* WINDOW_UPDATE, on the connection and on each live stream.
Due(window) == RecvWindow - window > 0 /\ RecvWindow - window >= window \div 2
Release ==
  /\ ~goaway /\ ReleaseCredit
  /\ Due(recvConn) \/ \E i \in LiveIds : Due(recvStream[i])
  /\ creditConn' = IF Due(recvConn) THEN creditConn + (RecvWindow - recvConn) ELSE creditConn
  /\ recvConn' = IF Due(recvConn) THEN RecvWindow ELSE recvConn
  /\ creditStream' = [i \in Ids |-> IF i \in LiveIds /\ Due(recvStream[i])
                                      THEN creditStream[i] + (RecvWindow - recvStream[i])
                                      ELSE creditStream[i]]
  /\ recvStream' = [i \in Ids |-> IF i \in LiveIds /\ Due(recvStream[i])
                                    THEN RecvWindow ELSE recvStream[i]]
  /\ UNCHANGED <<sstate, last, sendConn, sendStream, initial, reqLeft, dispatched, pending,
                 headSent, endSent, waiting, goaway, overspent>>

\* The WINDOW_UPDATE arm of `Http2::frame` for stream zero: the client
\* adds `inc` to the connection window. Past the maximum, the connection
\* ends; otherwise every waiting response wakes.
ConnectionUpdate(inc) ==
  /\ ~goaway
  /\ UNCHANGED <<sstate, last, recvConn, recvStream, creditConn, creditStream, sendStream,
                 initial, reqLeft, dispatched, pending, headSent, endSent, overspent>>
  /\ IF sendConn + inc > MaxWindow
       THEN goaway' = TRUE /\ UNCHANGED <<sendConn, waiting>>
       ELSE /\ sendConn' = sendConn + inc
            /\ waiting' = IF WakeOnConnectionUpdate THEN [i \in Ids |-> FALSE] ELSE waiting
            /\ UNCHANGED goaway

\* The WINDOW_UPDATE arm of `Http2::frame` for a live stream: the client
\* adds `inc` to the stream's window. Past the maximum, the stream is
\* reset; otherwise its response wakes.
StreamUpdate(i, inc) ==
  /\ ~goaway /\ sstate[i] \in Live
  /\ UNCHANGED <<last, recvConn, recvStream, creditConn, creditStream, sendConn, initial,
                 reqLeft, dispatched, pending, headSent, endSent, goaway, overspent>>
  /\ IF sendStream[i] + inc > MaxWindow
       THEN /\ sstate' = [sstate EXCEPT ![i] = "Closed"]
            /\ UNCHANGED <<sendStream, waiting>>
       ELSE /\ sendStream' = [sendStream EXCEPT ![i] = sendStream[i] + inc]
            /\ waiting' = IF WakeOnStreamUpdate THEN [waiting EXCEPT ![i] = FALSE] ELSE waiting
            /\ UNCHANGED sstate

\* The SETTINGS arm of `Http2::frame` with SETTINGS_INITIAL_WINDOW_SIZE `v`:
\* every live stream's window moves by the difference. Past the maximum,
\* the connection ends; otherwise every waiting response wakes.
Settings(v) ==
  /\ ~goaway
  /\ UNCHANGED <<sstate, last, recvConn, recvStream, creditConn, creditStream, sendConn,
                 reqLeft, dispatched, pending, headSent, endSent, overspent>>
  /\ IF \E i \in LiveIds : sendStream[i] + (v - initial) > MaxWindow
       THEN goaway' = TRUE /\ UNCHANGED <<sendStream, initial, waiting>>
       ELSE /\ sendStream' = [i \in Ids |-> IF i \in LiveIds THEN sendStream[i] + (v - initial)
                                                             ELSE sendStream[i]]
            /\ initial' = v
            /\ waiting' = IF WakeOnSettings THEN [i \in Ids |-> FALSE] ELSE waiting
            /\ UNCHANGED goaway

\* The RST_STREAM arm of `Http2::frame`: the stream and its response go away.
ClientReset(i) ==
  /\ ~goaway /\ sstate[i] \in Live
  /\ sstate' = [sstate EXCEPT ![i] = "Closed"]
  /\ UNCHANGED <<last, recvConn, recvStream, creditConn, creditStream, sendConn, sendStream,
                 initial, reqLeft, dispatched, pending, headSent, endSent, waiting, goaway,
                 overspent>>

\* `Http2::on_timer` with a body deadline: the handler is called before
\* the request ends.
EarlyAnswer(i, r) ==
  /\ ~goaway /\ sstate[i] = "Open" /\ ~dispatched[i]
  /\ Dispatch(i, r)
  /\ UNCHANGED <<sstate, last, recvConn, recvStream, creditConn, creditStream, sendConn,
                 sendStream, initial, reqLeft, headSent, endSent, waiting, goaway, overspent>>

\* `Http2::on_done`: the stream closes, with RST_STREAM(NO_ERROR) if the
\* request is still arriving.
Done(i) == sstate' = [sstate EXCEPT ![i] = "Closed"]

\* `Sending::poll_next`: the response HEADERS frame.
SendHead(i) ==
  /\ ~goaway /\ sstate[i] \in Live /\ dispatched[i] /\ ~headSent[i]
  /\ headSent' = [headSent EXCEPT ![i] = TRUE]
  /\ IF pending[i] = 0 THEN endSent' = [endSent EXCEPT ![i] = TRUE] /\ Done(i)
                       ELSE UNCHANGED <<endSent, sstate>>
  /\ UNCHANGED <<last, recvConn, recvStream, creditConn, creditStream, sendConn, sendStream,
                 initial, reqLeft, dispatched, pending, waiting, goaway, overspent>>

\* `Sending::poll_next` with body left: `n` is the least of what is left,
\* the connection window, the stream window and the frame size. With
\* nothing to send it stores its waker and waits; otherwise it spends `n`
\* from both windows.
Allowed(i) == IF SpendWithinWindows
                THEN Min(Min(pending[i], Max(sendConn, 0)), Min(Max(sendStream[i], 0), Frame))
                ELSE Min(pending[i], Frame)
SendData(i) ==
  /\ ~goaway /\ sstate[i] \in Live /\ headSent[i] /\ pending[i] > 0 /\ ~waiting[i]
  /\ UNCHANGED <<sstate, last, recvConn, recvStream, creditConn, creditStream, initial, reqLeft,
                 dispatched, headSent, endSent, goaway>>
  /\ IF Allowed(i) = 0
       THEN /\ waiting' = [waiting EXCEPT ![i] = TRUE]
            /\ UNCHANGED <<pending, sendConn, sendStream, overspent>>
       ELSE /\ pending' = [pending EXCEPT ![i] = pending[i] - Allowed(i)]
            /\ sendConn' = sendConn - Allowed(i)
            /\ sendStream' = [sendStream EXCEPT ![i] = sendStream[i] - Allowed(i)]
            /\ overspent' = (overspent \/ Allowed(i) > sendConn \/ Allowed(i) > sendStream[i])
            /\ UNCHANGED waiting

\* `Sending::poll_next`: the empty DATA frame with END_STREAM after the body.
SendEnd(i) ==
  /\ ~goaway /\ sstate[i] \in Live /\ headSent[i] /\ pending[i] = 0 /\ ~endSent[i]
  /\ endSent' = [endSent EXCEPT ![i] = TRUE]
  /\ Done(i)
  /\ UNCHANGED <<last, recvConn, recvStream, creditConn, creditStream, sendConn, sendStream,
                 initial, reqLeft, dispatched, pending, headSent, waiting, goaway, overspent>>

Respond(i) == SendHead(i) \/ SendData(i) \/ SendEnd(i)
Body(i) == \E extra \in Extras, r \in Responses : ClientData(i, extra, r)
\* A client that wants its answer grants credit once the server has none.
Grant(i) == sendStream[i] <= 0 /\ \E inc \in 1..MaxWindow : StreamUpdate(i, inc)
GrantConnection == sendConn <= 0 /\ \E inc \in 1..MaxWindow : ConnectionUpdate(inc)
SettingsChange == \E v \in Initials : Settings(v)

Client == \/ \E i \in Ids : \/ \E q \in Requests, r \in Responses : Open(i, q, r)
                            \/ Body(i) \/ ClientReset(i)
                            \/ \E extra \in Extras : ClientOverData(i, extra)
                            \/ \E inc \in 1..MaxWindow : StreamUpdate(i, inc)
          \/ \E inc \in 1..MaxWindow : ConnectionUpdate(inc)
          \/ SettingsChange
Server == \/ Release
          \/ \E i \in Ids : Respond(i) \/ \E r \in Responses : EarlyAnswer(i, r)
Next == Client \/ Server

\* The serve driver polls a response whenever it is woken and runs `Accept`
\* after every input batch. The client sends the body it declared and
\* grants credit when the server runs out. A client that keeps moving its
\* initial window can hold every response back forever, so the liveness
\* properties are for one that settles on a value.
Spec == /\ Init /\ [][Next]_vars
        /\ \A i \in Ids : WF_vars(Respond(i)) /\ WF_vars(Grant(i)) /\ WF_vars(Body(i))
        /\ WF_vars(GrantConnection) /\ WF_vars(Release)
        /\ <>[][~SettingsChange]_vars

\* RFC 9113 section 6.9.1: the server never sends more than either window allows.
ServerSpendsWithinWindows == ~overspent
\* RFC 9113 section 6.9.1: no send window exceeds 2^31 - 1 while the connection lives.
SendWindowsBounded ==
  ~goaway => sendConn <= MaxWindow /\ \A i \in LiveIds : sendStream[i] <= MaxWindow
\* RFC 9113 section 6.9: a client within its credit never runs the server's
\* receive windows negative, and the connection stays up for it.
ReceiveWindowsNonNegative ==
  ~goaway => recvConn >= 0 /\ \A i \in LiveIds : recvStream[i] >= 0
\* The server's receive accounting is the client's: both count the padding
\* and its length byte, and credit returns in the amount that was used.
CreditMatchesWindow ==
  ~goaway => creditConn = recvConn /\ \A i \in LiveIds : creditStream[i] = recvStream[i]
\* RFC 9113 section 6.9.1: DATA beyond the connection window is a
\* connection error, and beyond a stream window a stream error.
OverflowRejected ==
  [][\A i \in Ids, extra \in Extras : ClientOverData(i, extra) =>
      IF Charge(extra) > creditConn THEN goaway' ELSE sstate'[i] = "Closed"]_vars
\* No response waits for credit once the connection and its stream have some.
NoLostWake == \A i \in Ids : ~goaway /\ waiting[i] /\ sstate[i] \in Live /\ pending[i] > 0
                 ~> ~waiting[i] \/ sstate[i] \notin Live \/ goaway
\* Every request the handler saw gets its whole response, unless its
\* stream or the connection ends first.
ResponsesEnd == \A i \in Ids : dispatched[i] ~> (endSent[i] \/ sstate[i] \notin Live \/ goaway)
\* Every request body the client declared arrives, unless its stream or
\* the connection ends first: the server returns credit before the client
\* runs out.
RequestsEnd == \A i \in Ids : sstate[i] = "Open" ~> (sstate[i] # "Open" \/ goaway)
=============================================================================
