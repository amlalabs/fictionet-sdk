---------------------------- MODULE H2cSwitch ----------------------------
(* How a connection's bytes reach HTTP/2 when the version is chosen on the *)
(* connection: `Switch<Detect, Versions>` (src/stdlib/web/httpd/detect.rs, *)
(* src/stdlib/layer/switch.rs) reads the first bytes until they tell the  *)
(* preface (HTTP/2 with prior knowledge) from HTTP/1, then hands them, and *)
(* everything after, to `Http2` or to HTTP/1; HTTP/1 is                   *)
(* `Switch<Http1, Upgraded>` (src/stdlib/web/httpd/native.rs), which after *)
(* answering `Upgrade: h2c` with 101 hands the bytes past the request to   *)
(* the `Http2` its request became (`Http2::upgraded`).                     *)
(*                                                                        *)
(* The client's bytes are tokens, each its own position, so a lost,       *)
(* repeated or reordered byte shows. The preface is two tokens. The       *)
(* client sends its bytes in chunks of one or two, then its end. The      *)
(* transport below offers each delivery again until it is taken (a        *)
(* `Partial` leaves the rest to offer, `Blocked` all of it), as the stack *)
(* runner and `Harness` do.                                               *)
(*                                                                        *)
(* Source lines, at the commit in README.md:                              *)
(*   Detect::on_event, scan                detect.rs 108-153, 202-213     *)
(*   Detect::handover                      detect.rs 223-250              *)
(*   Switch::on_event, Switch::advance     switch.rs 133-148, 198-234     *)
(*   Http1::on_event (data, end)           native.rs 895-993              *)
(*   Http1::finish, Http1::hand_on         native.rs 776-820              *)
(*   Http1::handover                       native.rs 1110-1121            *)
(*   Http2::on_event (data, end)           http2.rs 1405-1429             *)
(*   Http2::read (one delivery at a time,  http2.rs 1025-1064             *)
(*     the end once it is read)                                           *)
(*                                                                        *)
(* Left out: what HTTP/1 does with the request (Pipeline.tla in           *)
(* verification/http), the 101's bytes and their `Written` (the handoff   *)
(* waits for them; here one step), budgets, deadlines and resets.         *)
EXTENDS Naturals, Sequences

CONSTANTS Mode,          \* "pk": the preface first; "h2c": an Upgrade: h2c request first; "h1": HTTP/1
          StreamCap,     \* tokens HTTP/1's decoder buffer holds
          LeftoverRoom,  \* entries HTTP/1 stages while switching (4 in the code)
          TakeDeciding,   \* `scan` takes the byte that decides
          HandFirst,      \* `Detect::handover` hands on the bytes it read
          LeftoversFirst, \* a switch offers its leftovers before newer input
          KeepUnread,     \* `hand_on` hands on the decoder's unread bytes
          BlockWhenFull,  \* `Http1::on_event` blocks input while its staging is full
          EndAfterData    \* `hand_on` puts the client's end after the bytes

Preface == <<"p1", "p2">>
Msg == CASE Mode = "pk" -> <<"p1", "p2", "f1", "f2">>
         [] Mode = "h2c" -> <<"u", "p1", "p2", "f1", "f2">>
         [] Mode = "h1" -> <<"p1", "x", "y">>
L == Len(Msg)
\* What HTTP/2 must read: every byte with prior knowledge; the bytes after
\* the request after an upgrade.
Expected == CASE Mode = "pk" -> [k \in 1..L |-> k]
              [] Mode = "h2c" -> [k \in 1..L - 1 |-> k + 1]
              [] Mode = "h1" -> <<>>
Range(a, b) == [k \in 1..(b - a + 1) |-> a + k - 1]
IsPrefix(s, t) == Len(s) <= Len(t) /\ SubSeq(t, 1, Len(s)) = s
Data(s) == [k |-> "data", s |-> s]
End == [k |-> "end"]

VARIABLES sent,      \* tokens the client sent so far
          ended,     \* the client sent its end
          cur,       \* the delivery the transport offers, or none
          outer,     \* the outer switch: detect, or then
          first,     \* Detect::first
          chosen,    \* Detect::chosen: none, h1, h2
          dEnded,    \* Detect::peer_ended
          below,     \* the outer switch's leftovers, in order
          inner,     \* the inner switch: h1, or then (HTTP/2 after h2c)
          h1phase,   \* Http1: reading, answering, switching, closed
          buf,       \* Http1's decoder buffer
          h1ended,   \* Http1::peer_ended
          leftover,  \* Http1::leftover
          h1got,     \* tokens HTTP/1 read as HTTP/1
          ibelow,    \* the inner switch's leftovers
          h2in,      \* Http2::input: the delivery being read
          h2got,     \* tokens Http2 read
          h2ended    \* Http2::peer_ended
vars == <<sent, ended, cur, outer, first, chosen, dEnded, below, inner, h1phase, buf, h1ended,
          leftover, h1got, ibelow, h2in, h2got, h2ended>>
detectVars == <<first, chosen, dEnded>>
h1Vars == <<h1phase, buf, h1ended, leftover, h1got>>
h2Vars == <<h2in, h2got, h2ended>>

Init ==
  /\ sent = 0 /\ ended = FALSE /\ cur = [k |-> "none"]
  /\ outer = "detect" /\ first = <<>> /\ chosen = "none" /\ dEnded = FALSE
  /\ below = <<>> /\ inner = "h1"
  /\ h1phase = "reading" /\ buf = <<>> /\ h1ended = FALSE /\ leftover = <<>> /\ h1got = <<>>
  /\ ibelow = <<>>
  /\ h2in = <<>> /\ h2got = <<>> /\ h2ended = FALSE

\* The client's next delivery: one or two tokens, or its end.
Send ==
  /\ cur.k = "none"
  /\ \/ \E n \in 1..2 :
          /\ sent + n <= L
          /\ cur' = Data(Range(sent + 1, sent + n))
          /\ sent' = sent + n
          /\ UNCHANGED ended
     \/ /\ sent = L /\ ~ended
        /\ cur' = End
        /\ ended' = TRUE
        /\ UNCHANGED sent
  /\ UNCHANGED <<outer, detectVars, below, inner, h1Vars, ibelow, h2Vars>>

---------------------------------------------------------------------------
(* Each layer's `on_event`, as an operator: given an event `e`, the admit *)
(* answer ([a, rest]) together with the layer's next state.              *)

Taken == [a |-> "taken"]
Blocked == [a |-> "blocked"]
Partial(s) == [a |-> "partial", rest |-> Data(s)]

RECURSIVE ScanFrom(_, _)
\* `scan`: reads tokens of `s` into `f` until they decide. The result:
\* first, chosen, how many of `s` were taken.
ScanFrom(f, s) ==
  IF s = <<>> THEN [f |-> f, c |-> "none", n |-> 0]
  ELSE LET f2 == Append(f, Head(s))
           matches == Msg[Head(s)] = Preface[Len(f2)]
       IN IF ~matches
            THEN [f |-> f2, c |-> "h1", n |-> IF TakeDeciding THEN 1 ELSE 0]
          ELSE IF Len(f2) = Len(Preface)
            THEN [f |-> f2, c |-> "h2", n |-> IF TakeDeciding THEN 1 ELSE 0]
          ELSE LET r == ScanFrom(f2, Tail(s)) IN [r EXCEPT !.n = @ + 1]

\* `Detect::on_event`.
DetectOn(e) ==
  IF chosen # "none" THEN [ans |-> Blocked, first |-> first, chosen |-> chosen, ended |-> dEnded]
  ELSE IF e.k = "end" THEN [ans |-> Taken, first |-> first, chosen |-> "h1", ended |-> TRUE]
  ELSE LET r == ScanFrom(first, e.s)
       IN [ans |-> IF r.n = Len(e.s) THEN Taken ELSE Partial(SubSeq(e.s, r.n + 1, Len(e.s))),
           first |-> r.f, chosen |-> r.c, ended |-> dEnded]

\* `Http2::on_event`: one delivery at a time, read whole before the next.
H2On(e) ==
  IF e.k = "end" THEN [ans |-> Taken, in |-> h2in, ended |-> TRUE]
  ELSE IF h2in # <<>> THEN [ans |-> Blocked, in |-> h2in, ended |-> h2ended]
  ELSE [ans |-> Taken, in |-> e.s, ended |-> h2ended]

\* `Http1::on_event`.
H1On(e) ==
  IF e.k = "end"
    THEN [ans |-> Taken, buf |-> buf, ended |-> TRUE,
          leftover |-> IF h1phase = "switching" /\ ~h1ended THEN Append(leftover, End)
                       ELSE leftover]
  ELSE IF h1phase = "switching"
    THEN IF Len(leftover) >= LeftoverRoom
           THEN IF BlockWhenFull
                  THEN [ans |-> Blocked, buf |-> buf, ended |-> h1ended, leftover |-> leftover]
                  ELSE [ans |-> Taken, buf |-> buf, ended |-> h1ended, leftover |-> leftover]
           ELSE [ans |-> Taken, buf |-> buf, ended |-> h1ended, leftover |-> Append(leftover, e)]
  ELSE LET n == IF StreamCap - Len(buf) < Len(e.s) THEN StreamCap - Len(buf) ELSE Len(e.s)
       IN [ans |-> IF n = 0 THEN Blocked
                   ELSE IF n < Len(e.s) THEN Partial(SubSeq(e.s, n + 1, Len(e.s)))
                   ELSE Taken,
           buf |-> buf \o SubSeq(e.s, 1, n), ended |-> h1ended, leftover |-> leftover]

\* The version server under the outer switch takes `e`: HTTP/2 with prior
\* knowledge, or HTTP/1's switch, which once it switched hands `e` to the
\* upgraded HTTP/2 behind its own leftovers.
ToH2 == chosen = "h2" \/ (inner = "then" /\ (ibelow = <<>> \/ ~LeftoversFirst))
InnerBlocked == inner = "then" /\ ibelow # <<>> /\ LeftoversFirst
ServerAns(e) == IF ToH2 THEN H2On(e).ans
                ELSE IF InnerBlocked THEN Blocked
                ELSE H1On(e).ans
ServerStep(e) ==
  IF ToH2
    THEN LET r == H2On(e) IN
           /\ h2in' = r.in /\ h2ended' = r.ended
           /\ UNCHANGED <<h1Vars, ibelow, h2got>>
  ELSE IF InnerBlocked
    THEN UNCHANGED <<h1Vars, ibelow, h2Vars>>
  ELSE LET r == H1On(e) IN
         /\ buf' = r.buf /\ h1ended' = r.ended /\ leftover' = r.leftover
         /\ UNCHANGED <<h1phase, h1got, ibelow, h2Vars>>

---------------------------------------------------------------------------
(* Steps *)

\* What an admit answer leaves to offer again.
After(e, ans) == IF ans.a = "partial" THEN ans.rest
                 ELSE IF ans.a = "blocked" THEN e ELSE [k |-> "none"]

\* The transport offers its delivery to the outer switch.
Offer ==
  /\ cur.k # "none"
  /\ \/ /\ outer = "detect"
        /\ LET r == DetectOn(cur) IN
             /\ first' = r.first /\ chosen' = r.chosen /\ dEnded' = r.ended
             /\ cur' = After(cur, r.ans)
        /\ UNCHANGED <<below, h1Vars, ibelow, h2Vars>>
     \/ \* `Switch::on_event` blocks newer input behind its leftovers.
        /\ outer = "then" /\ (below = <<>> \/ ~LeftoversFirst)
        /\ ServerStep(cur)
        /\ cur' = After(cur, ServerAns(cur))
        /\ UNCHANGED <<detectVars, below>>
  /\ UNCHANGED <<sent, ended, outer, inner>>

\* `Switch::advance` on the outer switch: `Detect::handover` once it chose,
\* then one leftover at a time to the server.
OuterAdvance ==
  \/ /\ outer = "detect" /\ chosen # "none"
     /\ outer' = "then"
     /\ below' = (IF first # <<>> /\ HandFirst THEN <<Data(first)>> ELSE <<>>)
                 \o (IF dEnded THEN <<End>> ELSE <<>>)
     /\ UNCHANGED <<sent, ended, cur, detectVars, inner, h1Vars, ibelow, h2Vars>>
  \/ /\ outer = "then" /\ below # <<>>
     /\ LET ans == ServerAns(Head(below)) IN
          /\ ans # Blocked
          /\ ServerStep(Head(below))
          /\ below' = IF ans.a = "partial" THEN <<ans.rest>> \o Tail(below) ELSE Tail(below)
     /\ UNCHANGED <<sent, ended, cur, outer, detectVars, inner>>

\* HTTP/1 reads its decoder buffer: the upgrade request, then (h2c) waits
\* to answer it; any other token it reads as HTTP/1.
H1Read ==
  /\ outer = "then" /\ chosen = "h1" /\ inner = "h1"
  /\ h1phase = "reading" /\ buf # <<>>
  /\ IF Msg[Head(buf)] = "u"
       THEN h1phase' = "answering" /\ UNCHANGED h1got
       ELSE h1got' = Append(h1got, Head(buf)) /\ UNCHANGED h1phase
  /\ buf' = Tail(buf)
  /\ UNCHANGED <<sent, ended, cur, outer, detectVars, below, inner, h1ended, leftover, ibelow,
                 h2Vars>>

\* The 101 is written: `finish` and `hand_on` gather the unread bytes and
\* the client's end for the successor.
HandOn ==
  /\ inner = "h1" /\ h1phase = "answering"
  /\ h1phase' = "switching"
  /\ LET bytes == IF buf # <<>> /\ KeepUnread THEN <<Data(buf)>> ELSE <<>>
         end == IF h1ended THEN <<End>> ELSE <<>>
     IN leftover' = IF EndAfterData THEN bytes \o end ELSE end \o bytes
  /\ buf' = <<>>
  /\ UNCHANGED <<sent, ended, cur, outer, detectVars, below, inner, h1ended, h1got, ibelow,
                 h2Vars>>

\* `Switch::advance` on HTTP/1's switch: `Http1::handover`, then one
\* leftover at a time to the upgraded HTTP/2.
InnerAdvance ==
  \/ /\ inner = "h1" /\ h1phase = "switching"
     /\ inner' = "then"
     /\ ibelow' = leftover
     /\ h1phase' = "closed"
     /\ leftover' = <<>>
     /\ UNCHANGED <<sent, ended, cur, outer, detectVars, below, buf, h1ended, h1got, h2Vars>>
  \/ /\ inner = "then" /\ ibelow # <<>>
     /\ LET r == H2On(Head(ibelow)) IN
          /\ r.ans # Blocked
          /\ h2in' = r.in /\ h2ended' = r.ended
          /\ ibelow' = Tail(ibelow)
     /\ UNCHANGED <<sent, ended, cur, outer, detectVars, below, inner, h1Vars, h2got>>

\* `Http2::read`: the delivery is read into the frame decoder.
H2Read ==
  /\ h2in # <<>>
  /\ h2got' = h2got \o h2in
  /\ h2in' = <<>>
  /\ UNCHANGED <<sent, ended, cur, outer, detectVars, below, inner, h1Vars, ibelow, h2ended>>

Next == Send \/ Offer \/ OuterAdvance \/ H1Read \/ HandOn \/ InnerAdvance \/ H2Read

Spec == Init /\ [][Next]_vars
          /\ WF_vars(Send) /\ WF_vars(Offer) /\ WF_vars(OuterAdvance) /\ WF_vars(H1Read)
          /\ WF_vars(HandOn) /\ WF_vars(InnerAdvance) /\ WF_vars(H2Read)

---------------------------------------------------------------------------
(* Properties *)

\* HTTP/2 reads the bytes it should, each once and in order, from the first.
H2GetsTheRest == IsPrefix(h2got \o h2in, Expected)

\* The client's end reaches HTTP/2 only after every byte did.
H2EndLast == h2ended => h2got \o h2in = Expected

\* HTTP/1, when it is the version, reads the whole input as HTTP/1.
H1GetsTheInput == Mode = "h1" => IsPrefix(h1got \o buf, [k \in 1..L |-> k])

\* Every byte HTTP/2 should read reaches it, and so does the end.
H2GetsAll == <>(h2got = Expected /\ h2ended)

\* With HTTP/1 chosen, every byte reaches HTTP/1.
H1GetsAll == <>(h1got = [k \in 1..L |-> k])
=============================================================================
