----------------------------- MODULE SessionRfc -----------------------------
(* `Session` (src/stdlib/protocols/http2.rs), one direction of an HTTP/2   *)
(* connection read without I/O, against RFC 9113's flow control and       *)
(* SETTINGS (RfcFlow.tla). The direction carries DATA from a sender A to   *)
(* a receiver B. `Session` reads A's frames and is given B's SETTINGS and *)
(* WINDOW_UPDATE, routed from the other direction (`peer_settings`,        *)
(* `peer_window_update`) and stream openings (`peer_open`). It keeps each  *)
(* stream's window as the most A may send: until A acknowledges a smaller *)
(* initial window, A may still send under a larger one. A applies each     *)
(* SETTINGS as it reads it, so A's own windows count from the initial      *)
(* window B announced last; an overflow is judged on those.               *)
(*                                                                        *)
(* Source lines, at the commit in README.md (section "SessionRfc"):        *)
(*   decoder: setting_valid                protocols/http2.rs 465-477      *)
(*            frame scopes (Inputs::decode) protocols/http2.rs 884-965     *)
(*   SettingsState::apply                  protocols/http2.rs 1033-1056    *)
(*   Session::peer_open, open_stream       protocols/http2.rs 1604-1619    *)
(*   apply_peer, set_initial_window        protocols/http2.rs 1673-1733    *)
(*   acknowledge_settings                  protocols/http2.rs 1740-1761    *)
(*   peer_window_update                    protocols/http2.rs 1769-1801    *)
(*   stream_state                          protocols/http2.rs 1809-1822    *)
(*   step: stream errors, HEADERS, DATA,   protocols/http2.rs 1857-2007    *)
(*         SETTINGS ACK                                                    *)
(*   credited, initial_fits                protocols/http2.rs 2015-2025    *)
(*                                                                        *)
(* Abstractions. `Max` stands for 2^31 - 1 and `Default` for 65,535. A's  *)
(* first SETTINGS has been read. Streams are tracked from their opening   *)
(* (`peer_open` or A's HEADERS) and are not retired or reset by the peer   *)
(* (the stream states are the sibling models'); A's frames on a stream it *)
(* ended, and its frame size, are left out. Each SETTINGS frame B sends   *)
(* is one of `SettingsFrames`.                                            *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS Max, Default, FrameMin, FrameLimit, Streams,
          DataLens, Pads, Incs, SettingsFrames, MaxFrames,
          \* The rules of the code; a control turns one off.
          SkipClosed,     \* initial window changes skip ended streams
          LatestCredit,   \* credit is judged on A's window, from the last value
          LatestInitial,  \* an initial window is judged on A's window
          StreamOverflow, \* stream credit past 2^31 - 1 ends only the stream
          StreamErrors,   \* a stream-scope refusal is reported, not a stop
          Envelope,       \* windows count from the largest unacknowledged value
          DataEnvelope,   \* DATA is judged against that window, not A's
          CountPadding,   \* DATA costs its whole length
          CheckConn,      \* DATA past the connection window stops
          CheckConnCredit,\* connection credit past 2^31 - 1 stops
          AckFront        \* an ACK settles the oldest SETTINGS

VARIABLES stopped,    \* Session::stopped
          window,     \* Session::window
          tracked,    \* in Session::streams
          headers,    \* StreamState::headers
          closed,     \* StreamState::closed
          sw,         \* StreamState::window
          envelope,   \* Session::initial_window
          latest,     \* Session::peer.initial_window_size
          updates,    \* Session::settings_updates: [window, max] per SETTINGS
          ackedInit,  \* history: the initial window of the SETTINGS A acknowledged last
          ev,         \* the step, for RfcFlow
          frames      \* frames read or routed
vars == <<stopped, window, tracked, headers, closed, sw, envelope, latest, updates, ackedInit,
          ev, frames>>
streamVars == <<tracked, headers, closed, sw>>

ConnErrors == {"connFlow", "connProtocol", "connFrameSize"}
Maximum(S) == CHOOSE m \in S : \A x \in S : x <= m

Ev(k, s, n, inc, vals, v) ==
  [dir |-> "d", k |-> k, s |-> s, n |-> n, inc |-> inc, vals |-> vals, bad |-> "none",
   v |-> v, ack |-> FALSE, goaway |-> "none"]
None == Ev("none", 0, 0, 0, <<>>, "ok")

Init ==
  /\ stopped = FALSE /\ window = Default
  /\ tracked = [s \in Streams |-> FALSE]
  /\ headers = [s \in Streams |-> FALSE]
  /\ closed = [s \in Streams |-> FALSE]
  /\ sw = [s \in Streams |-> 0]
  /\ envelope = Default /\ latest = Default /\ updates = <<>> /\ ackedInit = Default
  /\ ev = None /\ frames = 0

Step == ~stopped /\ frames < MaxFrames /\ frames' = frames + 1

\* `remember`: the error is kept and the direction stops.
Stop(k, s, n, inc, vals, v) ==
  /\ stopped' = TRUE
  /\ ev' = Ev(k, s, n, inc, vals, v)
  /\ UNCHANGED <<window, streamVars, envelope, latest, updates, ackedInit>>

\* `set_initial_window`: the windows of streams that may still send count
\* from `to` instead.
Shifted(to) == [s \in Streams |->
                  IF tracked[s] /\ (~closed[s] \/ ~SkipClosed) THEN sw[s] + (to - envelope)
                  ELSE sw[s]]

\* `peer_open` and `stream_state`: a new stream's window is the initial
\* window it counts from.
PeerOpen(s) ==
  /\ Step /\ ~tracked[s]
  /\ tracked' = [tracked EXCEPT ![s] = TRUE]
  /\ sw' = [sw EXCEPT ![s] = envelope]
  /\ ev' = Ev("open", s, 0, 0, <<>>, "ok")
  /\ UNCHANGED <<stopped, window, headers, closed, envelope, latest, updates, ackedInit>>

\* A's HEADERS on a stream it has not ended.
Headers(s, end) ==
  /\ Step /\ ~closed[s]
  /\ tracked' = [tracked EXCEPT ![s] = TRUE]
  /\ sw' = IF tracked[s] THEN sw ELSE [sw EXCEPT ![s] = envelope]
  /\ headers' = [headers EXCEPT ![s] = TRUE]
  /\ closed' = [closed EXCEPT ![s] = end]
  /\ ev' = Ev("headers", s, 0, 0, <<>>, "ok")
  /\ UNCHANGED <<stopped, window, envelope, latest, updates, ackedInit>>

\* A's DATA: `d` payload bytes and padding `p` (-1: not padded). `step`
\* charges the frame's length field, `h.length`.
Data(s, d, p, end) ==
  /\ Step /\ ~closed[s]
  /\ LET n == d + (IF p >= 0 THEN p + 1 ELSE 0)
         cost == IF CountPadding THEN n ELSE d
         room == IF DataEnvelope THEN sw[s] ELSE sw[s] - envelope + latest
         F(v) == Stop("data", s, n, 0, <<>>, v)
     IN IF window < cost /\ CheckConn THEN F("connFlow")
        ELSE IF ~tracked[s] \/ ~headers[s] THEN F("connProtocol")
        ELSE IF cost # 0 /\ room < cost THEN F("connFlow")
        ELSE /\ window' = window - cost
             /\ sw' = [sw EXCEPT ![s] = @ - cost]
             /\ closed' = [closed EXCEPT ![s] = end]
             /\ ev' = Ev("data", s, n, 0, <<>>, "ok")
             /\ UNCHANGED <<stopped, tracked, headers, envelope, latest, updates, ackedInit>>

\* `SettingsState::apply` refuses a value no endpoint may announce.
Invalid(e) == CASE e[1] = 2 /\ e[2] \notin {0, 1} -> "connProtocol"
                [] e[1] = 4 /\ e[2] > Max -> "connFlow"
                [] e[1] = 5 /\ (e[2] < FrameMin \/ e[2] > FrameLimit) -> "connProtocol"
                [] OTHER -> "none"
Inits(vals) == {vals[i][2] : i \in {j \in DOMAIN vals : vals[j][1] = 4}}

\* `apply_peer`: B's SETTINGS, routed. `initial_fits` judges each stream
\* that may still send at the largest initial window of the frame, counted
\* from A's window; the windows then count from the larger of that and the
\* initial window they counted from (or, without `Envelope`, the last).
PeerSettings(vals) ==
  /\ Step
  /\ LET bad == {Invalid(vals[i]) : i \in DOMAIN vals} \ {"none"}
         final == IF Inits(vals) = {} THEN latest
                  ELSE vals[CHOOSE i \in DOMAIN vals :
                              vals[i][1] = 4 /\ \A j \in DOMAIN vals : vals[j][1] = 4 => j <= i][2]
         most == Maximum(Inits(vals) \cup {final})
         to == IF Envelope THEN Maximum({envelope, most}) ELSE final
         Judged(s) == tracked[s] /\ (~closed[s] \/ ~SkipClosed)
         over == \E s \in Streams :
                   Judged(s) /\ IF LatestInitial THEN sw[s] - envelope + most > Max
                                ELSE sw[s] + (Maximum({envelope, most}) - envelope) > Max
     IN IF bad # {} THEN Stop("settings", 0, 0, 0, vals, CHOOSE v \in bad : TRUE)
        ELSE IF over THEN Stop("settings", 0, 0, 0, vals, "connFlow")
        ELSE /\ sw' = Shifted(to)
             /\ envelope' = to
             /\ latest' = final
             /\ updates' = Append(updates, [window |-> final, max |-> most])
             /\ ev' = Ev("settings", 0, 0, 0, vals, "ok")
             /\ UNCHANGED <<stopped, window, tracked, headers, closed, ackedInit>>

\* `acknowledge_settings`: A's ACK settles the oldest SETTINGS; the windows
\* count from its value, or a larger one still unacknowledged.
Ack ==
  /\ Step
  /\ IF updates = <<>>
       THEN /\ ev' = Ev("ack", 0, 0, 0, <<>>, "ignored")
            /\ UNCHANGED <<stopped, window, streamVars, envelope, latest, updates, ackedInit>>
       ELSE LET at == IF AckFront THEN 1 ELSE Len(updates)
                done == updates[at]
                rest == [i \in 1..(Len(updates) - 1) |-> IF i < at THEN updates[i] ELSE updates[i + 1]]
                to == Maximum({done.window} \cup {rest[i].max : i \in DOMAIN rest})
            IN /\ sw' = Shifted(to)
               /\ envelope' = to
               /\ updates' = rest
               /\ ackedInit' = done.window
               /\ ev' = Ev("ack", 0, 0, 0, <<>>, "ok")
               /\ UNCHANGED <<stopped, window, tracked, headers, closed, latest>>

\* `peer_window_update`: B's credit, routed. On a stream, `credited`.
PeerUpdate(s, inc) ==
  /\ Step
  /\ LET E(v) == ev' = Ev("wu", s, 0, inc, <<>>, v)
         F(v) == Stop("wu", s, 0, inc, <<>>, v)
         Keep == UNCHANGED <<stopped, envelope, latest, updates, ackedInit>>
     IN IF s = 0 THEN
          IF window + inc > Max /\ CheckConnCredit THEN F("connFlow")
          ELSE window' = window + inc /\ E("ok") /\ Keep /\ UNCHANGED streamVars
        ELSE IF ~tracked[s] \/ closed[s] THEN E("ignored") /\ Keep /\ UNCHANGED <<window, streamVars>>
        ELSE IF (IF LatestCredit THEN sw[s] - envelope + latest + inc > Max
                 ELSE sw[s] + inc > Max)
          THEN IF StreamOverflow
                 THEN E("streamFlow") /\ Keep /\ UNCHANGED <<window, streamVars>>
                 ELSE F("connFlow")
          ELSE /\ sw' = [sw EXCEPT ![s] = @ + inc] /\ E("ok") /\ Keep
               /\ UNCHANGED <<window, tracked, headers, closed>>

\* A's WINDOW_UPDATE with no credit: the decoder refuses it, on stream 0 for
\* the connection, on a stream for the stream; `step` reports a stream's.
ZeroUpdate(s) ==
  /\ Step
  /\ IF s # 0 /\ StreamErrors
       THEN /\ ev' = Ev("wu", s, 0, 0, <<>>, "streamProtocol")
            /\ UNCHANGED <<stopped, window, streamVars, envelope, latest, updates, ackedInit>>
       ELSE Stop("wu", s, 0, 0, <<>>, "connProtocol")

Next ==
  \/ \E s \in Streams : PeerOpen(s)
  \/ \E s \in Streams, end \in BOOLEAN : Headers(s, end)
  \/ \E s \in Streams, d \in DataLens, p \in Pads, end \in BOOLEAN : Data(s, d, p, end)
  \/ \E vals \in SettingsFrames : PeerSettings(vals)
  \/ Ack
  \/ \E s \in {0} \cup Streams, inc \in Incs : PeerUpdate(s, inc)
  \/ \E s \in {0} \cup Streams : ZeroUpdate(s)

Spec == Init /\ [][Next]_vars

\* With Max 4 and Default 2: an initial window up, down to 1 and to 0, a
\* frame that goes up to Max and ends at 1 (A's window is 1 after it while
\* the window here may still be 4), one past Max, an ENABLE_PUSH no
\* endpoint may announce, and an empty frame.
PeerSettingsFrames ==
  { <<<<4, 3>>>>, <<<<4, 1>>>>, <<<<4, 0>>>>, <<<<4, 4>>, <<4, 1>>>>, <<<<4, 5>>>>,
    <<<<2, 2>>>>, <<>> }
PeerPads == {-1, 0}

---------------------------------------------------------------------------
(* Refinement *)

\* RfcFlow for this direction: A's windows count from the initial window
\* announced last; the window here is the bound DATA is judged by.
R == INSTANCE RfcFlow WITH
       conn <- window,
       win <- [s \in Streams |-> IF tracked[s] THEN sw[s] - envelope + latest ELSE 0],
       bound <- sw,
       active <- [s \in Streams |-> tracked[s] /\ ~closed[s]],
       known <- tracked,
       init <- latest,
       pending <- [i \in 1..Len(updates) |-> updates[i].window],
       acked <- ackedInit,
       frameMax <- FrameMin,
       settled <- TRUE

DataDebits == R!DataDebits
ConnExcess == R!ConnExcess
NoFalseFlowError == R!NoFalseFlowError
BoundCovers == R!BoundCovers
WindowUpdateZero == R!WindowUpdateZero
ConnWindowUpdate == R!ConnWindowUpdate
StreamWindowUpdate == R!StreamWindowUpdate
SettingsApplied == R!SettingsApplied
AckHandling == R!AckHandling
=============================================================================
