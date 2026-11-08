----------------------------- MODULE Settings -----------------------------
(* SETTINGS and their acknowledgment in the HTTP/2 connection layer,      *)
(* `Http2` in src/stdlib/web/httpd/http2.rs.                              *)
(*                                                                        *)
(* The server sends its SETTINGS when the connection opens and starts the *)
(* acknowledgment deadline (`Http2::open`); the client's ACK stops it, an *)
(* ACK when none is awaited is a connection error, and the deadline       *)
(* passing first fails the connection with SETTINGS_TIMEOUT                *)
(* (`Http2::on_timer`). The client's first frame must be a SETTINGS        *)
(* without ACK (`Http2::on_frame`). Each client SETTINGS is applied, value *)
(* by value (`Http2::peer_setting`), then acknowledged; an initial window *)
(* that takes a stream past 2^31 - 1 is a connection error. After an      *)
(* `Upgrade: h2c` the HTTP2-Settings values apply before stream 1 opens   *)
(* (`Http2::upgraded`), and the client's preface SETTINGS still comes      *)
(* first. Only SETTINGS_INITIAL_WINDOW_SIZE is modeled: it is the one     *)
(* whose application can fail.                                            *)
(*                                                                        *)
(* Source lines, at the commit in README.md:                              *)
(*   Http2::upgraded                       http2.rs 255-269               *)
(*   Http2::open, SETTINGS and deadline    http2.rs 308-336               *)
(*   Http2::peer_setting (id 4), shifted   http2.rs 833-850, 1642-1644    *)
(*   on_frame: first frame, SETTINGS arm   http2.rs 852-858, 887-913      *)
(*   WINDOW_UPDATE arm (stream), grown     http2.rs 914-932, 1636-1638    *)
(*   Http2::on_timer                       http2.rs 1501-1521             *)
EXTENDS Integers, Sequences

CONSTANTS Values,        \* initial window values the client's SETTINGS carry
          Default,       \* 65_535, the initial window before any SETTINGS
          MaxWindow,     \* 2^31 - 1
          Increments,    \* WINDOW_UPDATE increments on stream 1
          MaxFrames,     \* how many frames the client sends
          H2c,           \* the connection began with `Upgrade: h2c`
          H2cInitial,    \* the initial window its HTTP2-Settings carried
          CheckFirst,     \* the first frame must be SETTINGS without ACK
          CheckAwaiting,  \* an ACK when none is awaited fails the connection
          ClearDeadline,  \* the ACK stops the deadline
          ArmDeadline,    \* `open` starts the deadline
          AckAfterApply,  \* the ACK is queued once every value is applied
          AckEvery        \* every SETTINGS is acknowledged, not only the first

VARIABLES phase,      \* open, or failed (GOAWAY queued)
          code,       \* the error of the GOAWAY: none, protocol, flow, timeout
          awaiting,   \* Http2::awaiting_ack
          deadline,   \* Http2::settings_deadline is set
          received,   \* Http2::received_settings
          initial,    \* Http2::initial
          stream,     \* stream 1 is open
          window,     \* stream 1's send window
          settings,   \* client SETTINGS frames the server took
          acks,       \* ACKs the server queued
          frames,     \* frames the client sent
          ackedUnapplied, \* history: an ACK went out for values not applied
          ignoredAck,     \* history: an unexpected ACK did not fail the connection
          spurious,       \* history: SETTINGS_TIMEOUT after the ACK came
          early           \* history: a frame before the first SETTINGS was acted on
vars == <<phase, code, awaiting, deadline, received, initial, stream, window, settings,
          acks, frames, ackedUnapplied, ignoredAck, spurious, early>>
history == <<ackedUnapplied, ignoredAck, spurious, early>>

Init ==
  /\ phase = "open" /\ code = "none"
  /\ awaiting = TRUE
  /\ deadline = ArmDeadline
  /\ received = FALSE
  \* `Http2::upgraded`: the HTTP2-Settings apply, then stream 1 opens with
  \* the initial window they set.
  /\ initial = IF H2c THEN H2cInitial ELSE Default
  /\ stream = H2c
  /\ window = IF H2c THEN H2cInitial ELSE 0
  /\ settings = 0 /\ acks = 0 /\ frames = 0
  /\ ackedUnapplied = FALSE /\ ignoredAck = FALSE /\ spurious = FALSE /\ early = FALSE

Fail(c) == phase' = "failed" /\ code' = c

ClientFrame == phase = "open" /\ frames < MaxFrames /\ frames' = frames + 1

\* The first-frame check of `Http2::on_frame`: anything but SETTINGS without
\* ACK before the first SETTINGS ends the connection.
NotFirst ==
  /\ ~received /\ CheckFirst
  /\ Fail("protocol")
  /\ UNCHANGED <<awaiting, deadline, received, initial, stream, window, settings, acks,
                 history>>

\* SETTINGS with SETTINGS_INITIAL_WINDOW_SIZE `v`: `peer_setting` moves the
\* open stream's window by the change, failing past 2^31 - 1; the ACK
\* follows the values (or, before 733f6c2c2, came first).
ClientSettings(v) ==
  /\ ClientFrame
  /\ LET fits == ~stream \/ window + (v - initial) <= MaxWindow
         ack == AckEvery \/ ~received
     IN /\ received' = TRUE
        /\ settings' = settings + 1
        /\ IF fits
             THEN /\ initial' = v
                  /\ window' = IF stream THEN window + (v - initial) ELSE window
                  /\ acks' = acks + (IF ack THEN 1 ELSE 0)
                  /\ UNCHANGED <<phase, code, ackedUnapplied>>
             ELSE /\ Fail("flow")
                  /\ acks' = acks + (IF ack /\ ~AckAfterApply THEN 1 ELSE 0)
                  /\ ackedUnapplied' = (ackedUnapplied \/ (ack /\ ~AckAfterApply))
                  /\ UNCHANGED <<initial, window>>
  /\ UNCHANGED <<awaiting, deadline, stream, ignoredAck, spurious, early>>

\* SETTINGS with ACK.
ClientAck ==
  /\ ClientFrame
  /\ \/ NotFirst
     \/ /\ received \/ ~CheckFirst
        /\ early' = (early \/ ~received)
        /\ IF awaiting
             THEN /\ awaiting' = FALSE
                  /\ deadline' = IF ClearDeadline THEN FALSE ELSE deadline
                  /\ UNCHANGED <<phase, code, ignoredAck>>
             ELSE IF CheckAwaiting
               THEN Fail("protocol") /\ UNCHANGED <<awaiting, deadline, ignoredAck>>
               ELSE ignoredAck' = TRUE /\ UNCHANGED <<phase, code, awaiting, deadline>>
        /\ UNCHANGED <<received, initial, stream, window, settings, acks, ackedUnapplied,
                       spurious>>

\* HEADERS opening stream 1 with prior knowledge: its window is the
\* initial window now.
ClientHeaders ==
  /\ ClientFrame
  /\ ~stream
  /\ \/ NotFirst
     \/ /\ received \/ ~CheckFirst
        /\ early' = (early \/ ~received)
        /\ stream' = TRUE
        /\ window' = initial
        /\ UNCHANGED <<phase, code, awaiting, deadline, received, initial, settings, acks,
                       ackedUnapplied, ignoredAck, spurious>>

\* WINDOW_UPDATE on stream 1 (`grown`): past 2^31 - 1 resets the stream.
ClientUpdate(inc) ==
  /\ ClientFrame
  /\ stream
  /\ \/ NotFirst
     \/ /\ received \/ ~CheckFirst
        /\ early' = (early \/ ~received)
        /\ IF window + inc <= MaxWindow
             THEN window' = window + inc /\ UNCHANGED stream
             ELSE stream' = FALSE /\ UNCHANGED window
        /\ UNCHANGED <<phase, code, awaiting, deadline, received, initial, settings, acks,
                       ackedUnapplied, ignoredAck, spurious>>

\* `Http2::on_timer`: the acknowledgment deadline passes.
Timeout ==
  /\ phase = "open" /\ deadline
  /\ Fail("timeout")
  /\ deadline' = FALSE
  /\ spurious' = (spurious \/ ~awaiting)
  /\ UNCHANGED <<awaiting, received, initial, stream, window, settings, acks, frames,
                 ackedUnapplied, ignoredAck, early>>

Next ==
  \/ \E v \in Values : ClientSettings(v)
  \/ ClientAck \/ ClientHeaders
  \/ \E inc \in Increments : ClientUpdate(inc)
  \/ Timeout

Spec == Init /\ [][Next]_vars /\ WF_vars(Timeout)

---------------------------------------------------------------------------
(* Properties *)

\* Every client SETTINGS the server took on an open connection got one ACK,
\* in order (RFC 9113 section 6.5.3).
AckEach == phase = "open" => acks = settings

\* No ACK goes out for SETTINGS whose values were not all applied (RFC 9113
\* section 6.5.3: the ACK follows processing every value).
AckOnlyApplied == ~ackedUnapplied

\* An ACK when none is awaited is a connection error.
UnexpectedAckFails == ~ignoredAck

\* SETTINGS_TIMEOUT only while the ACK is still awaited.
NoTimeoutAfterAck == ~spurious

\* Nothing before the client's first SETTINGS is acted on (RFC 9113
\* section 3.4).
FirstFrameSettings == ~early

\* A client that never acknowledges loses the connection to SETTINGS_TIMEOUT
\* or another error (RFC 9113 section 6.5.3).
UnackedTimesOut == <>[]awaiting => <>(phase = "failed")
=============================================================================
