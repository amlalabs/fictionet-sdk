------------------------------ MODULE Flow ------------------------------
(* Flow control of the HTTP/2 connection layer and its exchange children: *)
(* `Http2` in src/stdlib/web/httpd/http2.rs over `Children` in            *)
(* src/stdlib/layer/children.rs.                                          *)
(*                                                                        *)
(* Receive side. `Http2::on_data` debits the connection and stream        *)
(* windows and hands the bytes to `Http2::tell`, which queues them in     *)
(* `Stream::pending` behind earlier events and calls `Http2::forward`;    *)
(* `forward` moves them up as far as the child's credit (`Stream::credit`) *)
(* goes, splitting a body piece larger than that credit. Bytes waiting in  *)
(* `pending` that came within the windows are `Stream::held`; the body an  *)
(* `Upgrade: h2c` request brought over HTTP/1 waits there as              *)
(* `Stream::outside` (`Http2::open`, `Http2::tell_outside`). `Children`    *)
(* gives each child its window of credit units and grants them again as  *)
(* the child reads (the Credit arm of `Http2::on_command`). Once a batch  *)
(* is over (`Http2::advance`), `Http2::release` returns credit by         *)
(* WINDOW_UPDATE, once it is at least half of what the client has left:   *)
(* on the connection for the bytes it no longer holds, on a stream for    *)
(* what its child can take once the child has read all it was given      *)
(* (`Stream::peak`). A release is due (`batch`) after input, after a      *)
(* child's grant, and after a stream with held bytes ends                 *)
(* (`Http2::end_stream`).                                                 *)
(*                                                                        *)
(* Send side. `Http2::admit` grants a child `SEND_CREDIT` for its body;   *)
(* `Http2::on_child` takes body pieces within `Stream::granted` into      *)
(* `Stream::out`; `Http2::send_one` frames the least of what is queued,   *)
(* both send windows and the frame size, and `Http2::grant` gives the      *)
(* child credit for what went out. The WINDOW_UPDATE arm of               *)
(* `Http2::on_frame` and `Http2::peer_setting` (SETTINGS_INITIAL_WINDOW_SIZE) *)
(* refill the windows, with the 2^31 - 1 checks.                          *)
(*                                                                        *)
(* Source lines (http2.rs unless named), at the commit in README.md:      *)
(*   Http2::open, the h2c body             http2.rs 341-358               *)
(*   Http2::admit, initial credits         http2.rs 530-577               *)
(*   Http2::tell, tell_outside, forward    http2.rs 582-627               *)
(*   Http2::end_stream                     http2.rs 630-646               *)
(*   Http2::on_data                        http2.rs 770-830               *)
(*   Http2::peer_setting (id 4), shifted   http2.rs 833-850, 1642-1644    *)
(*   WINDOW_UPDATE arm, grown              http2.rs 914-932, 1636-1638    *)
(*   RST_STREAM arm of on_frame            http2.rs 933-948               *)
(*   Http2::release, credit_back           http2.rs 1071-1103, 1619-1622  *)
(*   Http2::on_child, Data arm             http2.rs 1120-1146             *)
(*   Http2::send_one, sendable             http2.rs 1248-1310, 1628-1632  *)
(*   Http2::grant, more_credit             http2.rs 1314-1323, 1648-1650  *)
(*   Credit arm of Http2::on_command       http2.rs 1469-1481             *)
(*   Http2::advance, the release gate      http2.rs 1523-1570             *)
(*   Children: the window, its grants,     children.rs 398-404, 431-480,  *)
(*     credit taken by events              children.rs 481-550            *)
(*                                                                        *)
(* Bytes are units; windows hold a few. Every stream is open from the     *)
(* start (Lifecycle.tla has the states). The h2c stream, `Up`, has ended  *)
(* from the client's side and sends no DATA. A child reads all it holds   *)
(* at once, and answers once it has read the whole body, as `Respond`     *)
(* does; a stalled child never reads. Its response is `Response` units,   *)
(* sent in pieces within its credit. `send_one` takes from the stream's   *)
(* queued bytes as one run (the code also stops at the end of the front   *)
(* piece, which only makes frames smaller).                               *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS Ids,          \* the client's stream identifiers
          Window,       \* WINDOW: each receive window
          ChildWindow,  \* the credit `Children` gives each child (Http2::WINDOW in `Responder`)
          FrameMax,     \* units per DATA frame, either way
          Body,         \* request body units on a stream that is not `Up`
          H2cBody,      \* units of the h2c request's body; 0: no h2c stream
          Stalled,      \* streams whose child never reads
          Resettable,   \* streams the client may reset
          SendCredit,   \* SEND_CREDIT
          Response,     \* response body units per stream
          InitialSend,  \* the client's SETTINGS_INITIAL_WINDOW_SIZE, and its connection window
          MaxWindow,    \* 2^31 - 1
          Increments,   \* WINDOW_UPDATE increments the client sends
          Initials,     \* values the client moves SETTINGS_INITIAL_WINDOW_SIZE to
          SplitToCredit,     \* `forward` splits a body piece larger than the credit
          HeldOnlyWindowed,  \* the h2c body is `outside`, not `held`
          CountHeld,         \* `release` keeps back the credit of held bytes
          FollowChild,       \* a stream's credit returns once its child read all it was given
          ReleaseOnCredit,   \* a child's grant makes a release due
          ReleaseOnEnd,      \* a stream ending with held bytes makes a release due
          CheckOverflow,     \* window updates and initial changes past 2^31 - 1 fail
          SpendWithinWindows,\* `send_one` sends no more than both windows allow
          CountOutBytes,     \* `grant` counts bytes queued but not framed
          RecordGrant        \* `grant` adds what it gives to `Stream::granted`

Up == CHOOSE i \in Ids : \A j \in Ids : i <= j
H2c == H2cBody > 0
IsUp(i) == H2c /\ i = Up
Total(i) == IF IsUp(i) THEN H2cBody ELSE Body
Min(a, b) == IF a < b THEN a ELSE b
Max0(a) == IF a > 0 THEN a ELSE 0

ASSUME Window > 0 /\ ChildWindow \in 1..Window /\ FrameMax > 0 /\ SendCredit > 0
ASSUME Stalled \subseteq Ids /\ Resettable \subseteq Ids
ASSUME InitialSend \in 0..MaxWindow /\ Initials \subseteq 0..MaxWindow
ASSUME 1 \in Increments

RECURSIVE SumOf(_, _)
SumOf(f, S) == IF S = {} THEN 0
               ELSE LET x == CHOOSE x \in S : TRUE IN f[x] + SumOf(f, S \ {x})

RECURSIVE WindowedIn(_)
\* The units of `pending` that came within the windows.
WindowedIn(p) == IF p = <<>> THEN 0
                 ELSE (IF Head(p).win THEN Head(p).n ELSE 0) + WindowedIn(Tail(p))

RECURSIVE Fwd(_, _)
\* `Http2::forward` over `pending` `p` with credit `c`: what is left, and
\* how many units went up.
Fwd(p, c) ==
  IF p = <<>> THEN <<p, 0>>
  ELSE IF Head(p).n <= c
       THEN LET r == Fwd(Tail(p), c - Head(p).n) IN <<r[1], r[2] + Head(p).n>>
  ELSE IF SplitToCredit /\ c > 0
       THEN <<<<[Head(p) EXCEPT !.n = @ - c]>> \o Tail(p), c>>
  ELSE <<p, 0>>

VARIABLES connRecv,   \* Http2::recv_window
          clientConn, \* what the client may still send on the connection
          recv,       \* Stream::recv_window
          clientRecv, \* what the client may still send on each stream
          sentBody,   \* request body units the client sent
          pend,       \* Stream::pending: <<[n, win]>>, win: came within the windows
          held,       \* Stream::held
          outside,    \* Stream::outside
          credit,     \* Stream::credit
          inbox,      \* units the child holds unread (Children's inbox)
          got,        \* units that reached the child
          batch,      \* Http2::batch: a release is due
          sendConn,   \* Http2::send_window
          sendStream, \* Stream::send_window
          initial,    \* Http2::initial
          granted,    \* Stream::granted
          cmdCredit,  \* the child's credit for its commands, in Children
          outBytes,   \* Stream::out_bytes
          respLeft,   \* response units the child has not sent down
          sentResp,   \* response units framed
          reset,      \* streams that ended in a reset
          failed,     \* the connection failed
          overspent,  \* history: a DATA frame went past a send window
          resetHonest \* history: a child sent within its credit and was reset
recvVars == <<connRecv, clientConn, recv, clientRecv, sentBody>>
pendVars == <<pend, held, outside, credit, inbox, got, batch>>
sendVars == <<sendConn, sendStream, initial, granted, cmdCredit, outBytes, respLeft, sentResp>>
vars == <<recvVars, pendVars, sendVars, reset, failed, overspent, resetHonest>>

UpH2c == <<[n |-> H2cBody, win |-> ~HeldOnlyWindowed]>>
StartFwd == Fwd(UpH2c, ChildWindow)

Init ==
  /\ connRecv = Window /\ clientConn = Window
  /\ recv = [i \in Ids |-> Window] /\ clientRecv = [i \in Ids |-> Window]
  /\ sentBody = [i \in Ids |-> 0]
  \* `Http2::open`: the h2c body is told to stream 1 behind its opening;
  \* `Children` grants the child its window and `forward` moves it up.
  /\ pend = [i \in Ids |-> IF IsUp(i) THEN StartFwd[1] ELSE <<>>]
  /\ held = [i \in Ids |-> IF IsUp(i) /\ ~HeldOnlyWindowed THEN H2cBody - StartFwd[2] ELSE 0]
  /\ outside = [i \in Ids |-> IF IsUp(i) /\ HeldOnlyWindowed THEN H2cBody - StartFwd[2] ELSE 0]
  /\ credit = [i \in Ids |-> IF IsUp(i) THEN ChildWindow - StartFwd[2] ELSE ChildWindow]
  /\ inbox = [i \in Ids |-> IF IsUp(i) THEN StartFwd[2] ELSE 0]
  /\ got = [i \in Ids |-> IF IsUp(i) THEN StartFwd[2] ELSE 0]
  /\ batch = FALSE
  /\ sendConn = InitialSend
  /\ sendStream = [i \in Ids |-> InitialSend]
  /\ initial = InitialSend
  /\ granted = [i \in Ids |-> SendCredit]
  /\ cmdCredit = [i \in Ids |-> SendCredit]
  /\ outBytes = [i \in Ids |-> 0]
  /\ respLeft = [i \in Ids |-> Response]
  /\ sentResp = [i \in Ids |-> 0]
  /\ reset = {}
  /\ failed = FALSE
  /\ overspent = FALSE
  /\ resetHonest = FALSE

Live(i) == ~failed /\ i \notin reset

\* `forward` on stream `i` once its pending queue is `p`, its credit `c`
\* and its held count `h`: the units that go up come out of `outside`
\* first, since the h2c body is first in `pending`.
Forward(i, p, c, h) ==
  LET r == Fwd(p, c)
      m == r[2]
      o == Min(m, outside[i])
  IN /\ pend' = [pend EXCEPT ![i] = r[1]]
     /\ credit' = [credit EXCEPT ![i] = c - m]
     /\ outside' = [outside EXCEPT ![i] = @ - o]
     /\ held' = [held EXCEPT ![i] = h - (m - o)]
     /\ inbox' = [inbox EXCEPT ![i] = @ + m]
     /\ got' = [got EXCEPT ![i] = @ + m]

\* `Http2::end_stream` on `i` for a reset: what waits for its child is
\* dropped with it.
Drop(i) ==
  /\ reset' = reset \cup {i}
  /\ pend' = [pend EXCEPT ![i] = <<>>]
  /\ held' = [held EXCEPT ![i] = 0]
  /\ outside' = [outside EXCEPT ![i] = 0]
  /\ batch' = (batch \/ (ReleaseOnEnd /\ held[i] > 0))
  /\ UNCHANGED <<credit, inbox, got>>

\* `Http2::on_data` with `Http2::tell`: `n` units on stream `i`, within
\* the client's windows.
ClientData(i, n) ==
  /\ Live(i) /\ ~IsUp(i)
  /\ sentBody[i] + n <= Body
  /\ n <= clientConn /\ n <= clientRecv[i]
  /\ clientConn' = clientConn - n
  /\ clientRecv' = [clientRecv EXCEPT ![i] = @ - n]
  /\ connRecv' = connRecv - n
  /\ recv' = [recv EXCEPT ![i] = @ - n]
  /\ sentBody' = [sentBody EXCEPT ![i] = @ + n]
  /\ Forward(i, Append(pend[i], [n |-> n, win |-> TRUE]), credit[i], held[i] + n)
  /\ batch' = TRUE
  /\ UNCHANGED <<sendVars, reset, failed, overspent, resetHonest>>

\* The child reads what it holds; `Children` grants those units again and
\* the Credit arm of `Http2::on_command` forwards what waits.
ChildRead(i) ==
  /\ Live(i) /\ i \notin Stalled
  /\ inbox[i] > 0
  /\ LET r == Fwd(pend[i], credit[i] + inbox[i])
         m == r[2]
         o == Min(m, outside[i])
     IN /\ pend' = [pend EXCEPT ![i] = r[1]]
        /\ credit' = [credit EXCEPT ![i] = @ + inbox[i] - m]
        /\ outside' = [outside EXCEPT ![i] = @ - o]
        /\ held' = [held EXCEPT ![i] = @ - (m - o)]
        /\ inbox' = [inbox EXCEPT ![i] = m]
        /\ got' = [got EXCEPT ![i] = @ + m]
        /\ batch' = (batch \/ ReleaseOnCredit)
  /\ UNCHANGED <<recvVars, sendVars, reset, failed, overspent, resetHonest>>

\* The RST_STREAM arm of `Http2::on_frame`: the client resets `i`.
ClientReset(i) ==
  /\ Live(i) /\ i \in Resettable
  /\ Drop(i)
  /\ UNCHANGED <<recvVars, sendVars, failed, overspent, resetHonest>>

\* `credit_back`: what tops a window up to `room`, once that is at least
\* half of what the client has left.
Back(window, room) == LET b == room - window
                      IN IF b > 0 /\ b >= window \div 2 THEN b ELSE 0
Held(h) == IF CountHeld THEN h ELSE 0
\* `Http2::release`: the connection's room is a window less what it holds;
\* a stream's is what its child can take, once the child has read all it
\* was given (`Stream::peak`), or before the change a window less what the
\* connection holds for it.
StreamBack(i) ==
  IF FollowChild
    THEN IF credit[i] = ChildWindow THEN Back(recv[i], Min(credit[i], Window) - held[i]) ELSE 0
    ELSE Back(recv[i], Window - Held(held[i]))
Release ==
  /\ ~failed /\ batch
  /\ LET c == Back(connRecv, Window - Held(SumOf(held, Ids))) IN
       /\ connRecv' = connRecv + c
       /\ clientConn' = clientConn + c
  /\ recv' = [i \in Ids |-> IF i \in reset THEN recv[i] ELSE recv[i] + StreamBack(i)]
  /\ clientRecv' = [i \in Ids |-> IF i \in reset THEN clientRecv[i]
                                   ELSE clientRecv[i] + StreamBack(i)]
  /\ batch' = FALSE
  /\ UNCHANGED <<sentBody, pend, held, outside, credit, inbox, got, sendVars, reset, failed,
                 overspent, resetHonest>>

\* The child, having read the whole body, sends `n` response units within
\* its credit in `Children`; `Http2::on_child` takes them within
\* `Stream::granted`, or resets the stream.
ChildSend(i, n) ==
  /\ Live(i) /\ i \notin Stalled
  /\ got[i] = Total(i) /\ inbox[i] = 0
  /\ n \in 1..Min(respLeft[i], cmdCredit[i])
  /\ cmdCredit' = [cmdCredit EXCEPT ![i] = @ - n]
  /\ respLeft' = [respLeft EXCEPT ![i] = @ - n]
  /\ IF n <= granted[i]
       THEN /\ granted' = [granted EXCEPT ![i] = @ - n]
            /\ outBytes' = [outBytes EXCEPT ![i] = @ + n]
            /\ UNCHANGED <<reset, resetHonest, pendVars>>
       ELSE /\ Drop(i)
            /\ resetHonest' = TRUE
            /\ UNCHANGED <<granted, outBytes>>
  /\ UNCHANGED <<recvVars, sendConn, sendStream, initial, sentResp, failed, overspent>>

\* `Http2::send_one`, then `Http2::grant`.
Sendable(i) == IF SpendWithinWindows
                 THEN Min(Min(outBytes[i], FrameMax), Min(Max0(sendConn), Max0(sendStream[i])))
                 ELSE Min(outBytes[i], FrameMax)
SendOne(i) ==
  /\ Live(i)
  /\ Sendable(i) > 0
  /\ LET n == Sendable(i)
         out == outBytes[i] - n
         more == SendCredit - (granted[i] + (IF CountOutBytes THEN out ELSE 0))
         give == IF more > 0 /\ respLeft[i] > 0 THEN more ELSE 0
     IN /\ overspent' = (overspent \/ n > Max0(sendConn) \/ n > Max0(sendStream[i]))
        /\ sendConn' = sendConn - n
        /\ sendStream' = [sendStream EXCEPT ![i] = @ - n]
        /\ outBytes' = [outBytes EXCEPT ![i] = out]
        /\ sentResp' = [sentResp EXCEPT ![i] = @ + n]
        /\ granted' = [granted EXCEPT ![i] = @ + (IF RecordGrant THEN give ELSE 0)]
        /\ cmdCredit' = [cmdCredit EXCEPT ![i] = @ + give]
  /\ UNCHANGED <<recvVars, pendVars, initial, respLeft, reset, failed, resetHonest>>

\* The WINDOW_UPDATE arm of `Http2::on_frame`: `checked_add` past 2^31 - 1
\* fails the connection, or resets the stream.
ConnUpdate(inc) ==
  /\ ~failed
  /\ IF CheckOverflow /\ sendConn + inc > MaxWindow
       THEN failed' = TRUE /\ UNCHANGED sendConn
       ELSE sendConn' = sendConn + inc /\ UNCHANGED failed
  /\ UNCHANGED <<recvVars, pendVars, sendStream, initial, granted, cmdCredit, outBytes,
                 respLeft, sentResp, reset, overspent, resetHonest>>
StreamUpdate(i, inc) ==
  /\ Live(i)
  /\ IF CheckOverflow /\ sendStream[i] + inc > MaxWindow
       THEN Drop(i) /\ UNCHANGED sendStream
       ELSE sendStream' = [sendStream EXCEPT ![i] = @ + inc] /\ UNCHANGED <<reset, pendVars>>
  /\ UNCHANGED <<recvVars, sendConn, initial, granted, cmdCredit, outBytes, respLeft,
                 sentResp, failed, overspent, resetHonest>>

\* `Http2::peer_setting`, SETTINGS_INITIAL_WINDOW_SIZE: every open stream's
\* window moves by the change.
Settings(v) ==
  /\ ~failed /\ v # initial
  /\ LET d == v - initial IN
       IF CheckOverflow /\ \E i \in Ids \ reset : sendStream[i] + d > MaxWindow
         THEN failed' = TRUE /\ UNCHANGED <<sendStream, initial>>
         ELSE /\ sendStream' = [i \in Ids |-> IF i \in reset THEN sendStream[i]
                                               ELSE sendStream[i] + d]
              /\ initial' = v
              /\ UNCHANGED failed
  /\ UNCHANGED <<recvVars, pendVars, sendConn, granted, cmdCredit, outBytes, respLeft,
                 sentResp, reset, overspent, resetHonest>>

\* A client that grants credit when a response waits for it: the fairness
\* of the liveness properties rests on this.
Replenish(i) ==
  /\ Live(i) /\ outBytes[i] > 0
  /\ \/ sendConn <= 0 /\ ConnUpdate(1)
     \/ sendStream[i] <= 0 /\ StreamUpdate(i, 1)

Next ==
  \/ \E i \in Ids, n \in 1..FrameMax : ClientData(i, n)
  \/ \E i \in Ids : ChildRead(i)
  \/ \E i \in Ids : ClientReset(i)
  \/ Release
  \/ \E i \in Ids, n \in 1..Response : ChildSend(i, n)
  \/ \E i \in Ids : SendOne(i)
  \/ \E inc \in Increments : ConnUpdate(inc)
  \/ \E i \in Ids, inc \in Increments : StreamUpdate(i, inc)
  \/ \E v \in Initials : Settings(v)

Fairness ==
  /\ \A i \in Ids : WF_vars(\E n \in 1..FrameMax : ClientData(i, n))
  /\ \A i \in Ids : WF_vars(ChildRead(i))
  /\ WF_vars(Release)
  /\ \A i \in Ids : WF_vars(\E n \in 1..Response : ChildSend(i, n))
  /\ \A i \in Ids : WF_vars(SendOne(i))
  /\ \A i \in Ids : WF_vars(Replenish(i))
  \* A client that gives up on a stuck stream resets it in the end.
  /\ \A i \in Resettable : WF_vars(ClientReset(i))

Spec == Init /\ [][Next]_vars /\ Fairness

---------------------------------------------------------------------------
(* Properties *)

TypeOK ==
  /\ connRecv \in Int /\ clientConn \in Int
  /\ held \in [Ids -> Nat] /\ outside \in [Ids -> Nat]
  /\ credit \in [Ids -> Nat] /\ inbox \in [Ids -> Nat]
  /\ granted \in [Ids -> Nat] /\ cmdCredit \in [Ids -> Nat] /\ outBytes \in [Ids -> Nat]

\* The client never holds credit for bytes the connection still holds: what
\* it may send plus what waits in `pending` from within the windows is at
\* most a window (RFC 9113 section 6.9). The held counters agree with the
\* pending queues.
ReleasedOnlyFreed ==
  /\ clientConn + SumOf([i \in Ids |-> WindowedIn(pend[i])], Ids) <= Window
  /\ \A i \in Ids \ reset : clientRecv[i] + WindowedIn(pend[i]) <= Window
  /\ \A i \in Ids : held[i] = WindowedIn(pend[i])

\* When each child's credit is a whole window, as `Responder` composes it,
\* the connection never holds a request byte for a child: the client may
\* send a stream only what its child can take.
NothingHeld == ChildWindow >= Window => \A i \in Ids : held[i] = 0

\* No send window ever holds more than 2^31 - 1 (RFC 9113 section 6.9.1).
SendWindowsBounded ==
  /\ sendConn <= MaxWindow
  /\ \A i \in Ids : sendStream[i] <= MaxWindow

\* No DATA frame goes past either send window.
ServerSpendsWithinWindows == ~overspent

\* The connection holds at most `SEND_CREDIT` of a stream's response that
\* it has not framed, granted or queued.
ChildWithinGrant == \A i \in Ids : granted[i] + outBytes[i] <= SendCredit

\* The connection and the child's carrier agree on the child's credit, so
\* a child that sends within its credit is never reset for it.
CreditAgrees == /\ ~resetHonest
                /\ \A i \in Ids \ reset : cmdCredit[i] = granted[i]

\* Every request body unit reaches its child, h2c body included, when the
\* child reads.
BodyReachesChild == \A i \in Ids \ Stalled :
                      <>(failed \/ i \in reset \/ got[i] = Total(i))

\* The client gets to send every body it has, whatever another stream's
\* child does, once it stops moving its initial window.
SettlesSettings == <>[][~\E v \in Initials : Settings(v)]_vars
RequestsEnd == SettlesSettings =>
                 \A i \in Ids \ Stalled :
                   IsUp(i) \/ <>(failed \/ i \in reset \/ sentBody[i] = Body)

\* Every response goes out whole.
ResponsesEnd == SettlesSettings =>
                  \A i \in Ids \ Stalled : <>(failed \/ i \in reset \/ sentResp[i] = Response)
=============================================================================
