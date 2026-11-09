------------------------------ MODULE Pipeline ------------------------------
(***************************************************************************)
(* The HTTP/1 layer's request/response pipeline and its handoff to a       *)
(* tunnel after a CONNECT or an upgrade: `Http1` in                        *)
(* src/stdlib/web/httpd/native.rs inside `Switch<Http1, Tunnel>`           *)
(* (src/stdlib/layer/switch.rs), with the `Tunnel` it switches to          *)
(* (src/stdlib/services/stack/tunnel.rs).                                 *)
(*                                                                         *)
(* The client's bytes are a sequence of tokens chosen at the start: a      *)
(* whole request ("P" keep-alive, "Q" with Connection: close, "C" CONNECT, *)
(* "U" an upgrade request) or bytes that are not HTTP ("X"). A token is    *)
(* its index in that sequence, so every queue below holds indices and a    *)
(* lost, repeated or reordered byte shows as a gap or a repeat.            *)
(* Sizes are in tokens: the request decoder's buffer holds StreamCap of    *)
(* them, the tunnel takes a chunk while it holds fewer than TunnelRoom.    *)
(*                                                                         *)
(* Source, by action (written at 50b69c60d; line numbers of e2858ccc4,   *)
(* checked 2026-11-09; native.rs has changed much since 50b69c60d, and    *)
(* every rule below was found again in it):                               *)
(*   Chunk, ClientEnd     the peer and the driver below (stack/live.rs:205-224)*)
(*   OfferData, OfferEnd  Http1::on_event (native.rs:895-993); after the   *)
(*                        switch Switch::on_event (switch.rs:167-195) and  *)
(*                        Tunnel::on_event (tunnel.rs:142-166)             *)
(*   Read                 Http1::advance in Reading (native.rs:1071) ->    *)
(*                        Http1::read (native.rs:374-444), dispatch        *)
(*                        (native.rs:461-557), fail (native.rs:560-614)    *)
(*   Make                 Work::poll and Http1::on_done (native.rs:1010-1063)*)
(*   Respond              Http1::respond (native.rs:617-681), start        *)
(*                        (native.rs:685-742), piece (native.rs:745-772),  *)
(*                        finish (native.rs:776-789), hand_on              *)
(*                        (native.rs:793-820), all_written (native.rs:339) *)
(*   Abort                on_timer, over_budget and a failed work: close   *)
(*                        (native.rs:344-364, 368-371, 1003-1008)          *)
(*   TakeCommand          Http1::take_command (native.rs:1081-1088)        *)
(*   Written              StreamEvent::Written (native.rs:963-966)         *)
(*   Handover             Switch::advance in First (switch.rs:247-266) ->  *)
(*                        Http1::handover (native.rs:1110-1121)            *)
(*   FeedBelow            Switch::advance in Then (switch.rs:267-284)      *)
(*   TunnelRead           TunnelConn::poll_read (tunnel.rs:259-286)        *)
(*                                                                         *)
(* `after` (the bytes behind a request the decoder has finished, bounded  *)
(* by StreamCap) is never filled: `sdone` is set only together with Close *)
(* or the 400 path, which leave Reading and Answering, and the `after`    *)
(* branch of HttpData needs both. The code is the same: `read` (native.rs *)
(* 374-386) is the only caller of `Stream::next`, and it closes as soon   *)
(* as the decoder is done, so `Http1::on_event`'s `after` buffer (native.rs *)
(* 924-948) is not reached either. Allocation refusal closes via Abort;   *)
(* this model abstracts byte allocations, whose reservation precedes      *)
(* encoding.                                                               *)
(* Each flag is a rule of the code; a *_without_<flag>.cfg turns one off   *)
(* and names the property TLC must then find violated.                     *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    L,            \* tokens the client sends
    Kinds,        \* the token kinds the client may send
    StreamCap,    \* the request decoder's buffer, in tokens
    TunnelRoom,   \* the tunnel takes a chunk while it holds fewer
    MaxChunk,     \* the most tokens in one chunk from below
    Bodies,       \* response sizes after the head, in pieces
    WaitWritten,          \* all_written waits for Written (native.rs:339-341)
    ReadOnlyInReading,    \* advance reads only in Reading (native.rs:1071)
    KeepUnread,           \* hand_on passes the unread bytes (native.rs:795-802)
    LeftoverInSwitching,  \* Data while Switching joins the leftover (native.rs:911-923)
    EndLast,              \* hand_on puts the peer's end last (native.rs:816-818)
    HandOverAfterWritten, \* handover only once Switching (native.rs:1111-1113)
    LeftoverFirst,        \* Switch blocks new input behind leftovers (switch.rs:190)
    FeedLeftovers,        \* Switch feeds a leftover on each advance (switch.rs:271-276)
    CloseAfterBare101     \* a 101 without an UpgradeHandler closes (native.rs:702-706, b69a3806f)

Tokens == 1..L
None == "none"
Min(a, b) == IF a < b THEN a ELSE b
Range(s) == {s[i] : i \in DOMAIN s}
\* Consecutive indices from a + 1.
Run(a, n) == [j \in 1..n |-> a + j]

(* A response as the handler gives it. `hands`: a 101, or a 2xx to       *)
(* CONNECT, carrying an UpgradeHandler, which sets `next` in start.      *)
(* `close`: what dispatch and encode decide; CONNECT never keeps the     *)
(* connection alive (native.rs:466) unless it hands on (native.rs:690-701). *)
(* `s101`: the status is 101.                                            *)
Resp(body, making, hands, close, s101) ==
    [left |-> 1 + body, making |-> making, hands |-> hands,
     close |-> close, s101 |-> s101, started |-> FALSE, on |-> TRUE]
\* No response: `responding` is None.
NoResp == [left |-> 0, making |-> FALSE, hands |-> FALSE, close |-> FALSE,
           s101 |-> FALSE, started |-> FALSE, on |-> FALSE]

Responses(kind) ==
    CASE kind = "P" -> {Resp(b, m, FALSE, FALSE, FALSE) : b \in Bodies, m \in BOOLEAN}
      [] kind = "Q" -> {Resp(b, m, FALSE, TRUE, FALSE) : b \in Bodies, m \in BOOLEAN}
      [] kind = "U" -> {Resp(0, m, TRUE, FALSE, TRUE) : m \in BOOLEAN}
                       \cup {Resp(0, m, FALSE, CloseAfterBare101, TRUE) : m \in BOOLEAN}
                       \cup {Resp(b, m, FALSE, FALSE, FALSE) : b \in Bodies, m \in BOOLEAN}
      [] kind = "C" -> {Resp(0, m, TRUE, FALSE, FALSE) : m \in BOOLEAN}
                       \cup {Resp(b, m, FALSE, TRUE, FALSE) : b \in Bodies, m \in BOOLEAN}

VARIABLES
    wire,       \* the kind of each token
    sent,       \* tokens the driver has taken from the peer
    cur,        \* the chunk the driver is offering (kept while blocked)
    clientEnd,  \* the peer's end is waiting to be offered
    endSent,    \* the peer has ended
    \* Http1
    phase, buf, eof, sdone, closeNext, after, peerEnded, resp, next,
    out, queued, handed, written, leftover, pos,
    \* Switch and Tunnel
    switched, below, inbound, tEnded, tIn,
    \* history, for the properties
    reqsRead, respsDone, badRead, badHandover, handPos, head101, readAfter101

client == <<wire, sent, cur, clientEnd, endSent>>
http == <<phase, buf, eof, sdone, closeNext, after, peerEnded, resp, next,
          out, queued, handed, written, leftover, pos>>
tunnel == <<switched, below, inbound, tEnded, tIn>>
history == <<reqsRead, respsDone, badRead, badHandover, handPos, head101,
             readAfter101>>
vars == <<client, http, tunnel, history>>

AfterLen == LET F[i \in 0..Len(after)] ==
                    IF i = 0 THEN 0 ELSE F[i - 1] + Len(after[i])
            IN F[Len(after)]

(* native.rs:339-341 *)
AllWritten == out = <<>> /\ (~WaitWritten \/ written >= handed)

Init ==
    /\ wire \in [Tokens -> Kinds]
    /\ sent = 0 /\ cur = <<>> /\ clientEnd = FALSE /\ endSent = FALSE
    /\ phase = "Reading" /\ buf = <<>> /\ eof = FALSE /\ sdone = FALSE
    /\ closeNext = FALSE /\ after = <<>> /\ peerEnded = FALSE
    /\ resp = NoResp /\ next = None /\ out = <<>>
    /\ queued = 0 /\ handed = 0 /\ written = 0 /\ leftover = <<>> /\ pos = 0
    /\ switched = FALSE /\ below = <<>> /\ inbound = <<>> /\ tEnded = FALSE
    /\ tIn = <<>>
    /\ reqsRead = 0 /\ respsDone = 0
    /\ badRead = FALSE /\ badHandover = FALSE /\ handPos = 0
    /\ head101 = FALSE /\ readAfter101 = FALSE

(* close (native.rs:344-364): what is queued is written, then End. *)
Close ==
    IF phase \in {"Closing", "Closed"}
    THEN UNCHANGED <<phase, out, resp, next>>
    ELSE /\ phase' = "Closing"
         /\ out' = Append(out, "End")
         /\ resp' = NoResp
         /\ next' = None

-----------------------------------------------------------------------------
(* The peer and the driver *)

Chunk ==
    /\ cur = <<>> /\ sent < L
    /\ \E k \in 1..MaxChunk :
        /\ sent + k <= L
        /\ cur' = Run(sent, k)
        /\ sent' = sent + k
    /\ UNCHANGED <<wire, clientEnd, endSent, http, tunnel, history>>

ClientEnd ==
    /\ cur = <<>> /\ sent = L /\ ~endSent
    /\ clientEnd' = TRUE /\ endSent' = TRUE
    /\ UNCHANGED <<wire, sent, cur, http, tunnel, history>>

(* Tunnel::on_event, Data (tunnel.rs:150-159): taken whole while it holds *)
(* less than its room; refused once the stream ended.                     *)
TunnelTakes(d) ==
    /\ Len(inbound) < TunnelRoom \/ tEnded
    /\ IF tEnded
       THEN UNCHANGED <<inbound, tIn>>
       ELSE /\ inbound' = inbound \o d
            /\ tIn' = tIn \o d

(* Http1::on_event, Data (native.rs:904-962). *)
HttpData ==
    \/ /\ phase \in {"Closing", "Closed"} \/ peerEnded
       /\ cur' = <<>>
       /\ UNCHANGED <<http>>
    \/ /\ phase = "Switching" /\ ~peerEnded
       /\ Len(leftover) < 4
       /\ cur' = <<>>
       /\ IF LeftoverInSwitching
          THEN /\ leftover' = Append(leftover, [t |-> "data", d |-> cur])
               /\ UNCHANGED <<buf>>
          ELSE \* Pushed into the request stream, which nothing reads now.
               /\ buf' = buf \o cur
               /\ UNCHANGED <<leftover>>
       /\ UNCHANGED <<phase, eof, sdone, closeNext, after, peerEnded, resp,
                      next, out, queued, handed, written, pos>>
    \/ /\ phase \in {"Reading", "Answering"} /\ ~peerEnded /\ sdone
       /\ AfterLen < StreamCap
       /\ LET n == Min(Len(cur), StreamCap - AfterLen)
          IN /\ after' = Append(after, SubSeq(cur, 1, n))
             /\ cur' = SubSeq(cur, n + 1, Len(cur))
       /\ UNCHANGED <<phase, buf, eof, sdone, closeNext, peerEnded, resp, next,
                      out, queued, handed, written, leftover, pos>>
    \/ /\ phase \in {"Reading", "Answering"} /\ ~peerEnded /\ ~sdone
       /\ Len(buf) < StreamCap
       /\ LET n == Min(Len(cur), StreamCap - Len(buf))
          IN /\ buf' = buf \o SubSeq(cur, 1, n)
             /\ cur' = SubSeq(cur, n + 1, Len(cur))
       /\ UNCHANGED <<phase, eof, sdone, closeNext, after, peerEnded, resp,
                      next, out, queued, handed, written, leftover, pos>>

OfferData ==
    /\ cur # <<>>
    /\ IF ~switched
       THEN /\ HttpData
            /\ UNCHANGED <<tunnel>>
       ELSE \* Switch::on_event: leftovers first (switch.rs:190).
            /\ below = <<>> \/ ~LeftoverFirst
            /\ TunnelTakes(cur)
            /\ cur' = <<>>
            /\ UNCHANGED <<http, switched, below, tEnded>>
    /\ UNCHANGED <<wire, sent, clientEnd, endSent, history>>

(* Http1::on_event, Ended (native.rs:967-977); Tunnel::on_event, Ended. *)
OfferEnd ==
    /\ clientEnd /\ cur = <<>>
    /\ clientEnd' = FALSE
    /\ IF ~switched
       THEN /\ peerEnded' = TRUE
            /\ IF phase = "Switching"
               THEN /\ leftover' = Append(leftover, [t |-> "end"])
                    /\ UNCHANGED <<eof>>
               ELSE /\ eof' = (eof \/ ~sdone)
                    /\ UNCHANGED <<leftover>>
            /\ UNCHANGED <<phase, buf, sdone, closeNext, after, resp, next, out,
                           queued, handed, written, pos, tunnel>>
       ELSE /\ below = <<>> \/ ~LeftoverFirst
            /\ tEnded' = TRUE
            /\ UNCHANGED <<http, switched, below, inbound, tIn>>
    /\ UNCHANGED <<wire, sent, cur, endSent, history>>

-----------------------------------------------------------------------------
(* Http1 *)

(* Http1::read (native.rs:374-444), one request at a time. A request is *)
(* read whole: Head, Body and Done. *)
Read ==
    /\ ~switched
    /\ phase = "Reading" \/ (~ReadOnlyInReading /\ phase = "Answering")
    /\ \/ \* After a CONNECT or a close the decoder ends: is_done.
          /\ closeNext \/ (buf = <<>> /\ eof)
          /\ sdone' = TRUE
          /\ Close
          /\ UNCHANGED <<buf, closeNext, queued, pos, reqsRead, badRead,
                         readAfter101>>
       \/ /\ ~closeNext /\ buf # <<>>
          /\ LET t == Head(buf) IN
             IF wire[t] = "X"
             THEN \* fail (native.rs:599-613): a 400, then close.
                  /\ sdone' = TRUE
                  /\ queued' = queued + 1
                  /\ phase' = "Closing"
                  /\ out' = out \o <<"R", "End">>
                  /\ resp' = NoResp /\ next' = None
                  /\ UNCHANGED <<buf, closeNext, pos, reqsRead, badRead,
                                 readAfter101>>
             ELSE /\ buf' = Tail(buf)
                  /\ pos' = t
                  /\ closeNext' = (wire[t] \in {"Q", "C"})
                  /\ reqsRead' = reqsRead + 1
                  /\ badRead' = (badRead \/ written < queued)
                  /\ readAfter101' = (readAfter101 \/ head101)
                  /\ resp' \in Responses(wire[t])
                  /\ phase' = "Answering"
                  /\ UNCHANGED <<sdone, out, queued, next>>
    /\ UNCHANGED <<client, eof, after, peerEnded, handed, written, leftover,
                   tunnel, respsDone, badHandover, handPos, head101>>

(* The handler's later answer arrives (on_done, native.rs:1010-1063). *)
Make ==
    /\ ~switched /\ phase = "Answering" /\ resp.on /\ resp.making
    /\ resp' = [resp EXCEPT !.making = FALSE]
    /\ UNCHANGED <<client, phase, buf, eof, sdone, closeNext, after, peerEnded,
                   next, out, queued, handed, written, leftover, pos, tunnel,
                   history>>

(* hand_on (native.rs:793-820): the unread bytes, the bytes past the end *)
(* of HTTP, then the peer's end. *)
Unread == IF KeepUnread /\ buf # <<>> THEN <<[t |-> "data", d |-> buf]>> ELSE <<>>
AfterData == LET F[i \in 0..Len(after)] ==
                    IF i = 0 THEN <<>> ELSE F[i - 1] \o after[i]
             IN F[Len(after)]
Afters == IF after = <<>> THEN <<>> ELSE <<[t |-> "data", d |-> AfterData]>>
Ends == IF peerEnded THEN <<[t |-> "end"]>> ELSE <<>>
HandOn ==
    /\ leftover' = IF EndLast THEN Unread \o Afters \o Ends
                              ELSE Ends \o Unread \o Afters
    /\ buf' = <<>> /\ after' = <<>>
    /\ phase' = "Switching"
    /\ handPos' = pos

(* Http1::respond (native.rs:617-681): one piece once the last is written. *)
Respond ==
    /\ ~switched /\ phase = "Answering" /\ resp.on /\ ~resp.making
    /\ AllWritten
    /\ IF resp.left > 0
       THEN \* start (native.rs:685-742) sets `next` with the head; piece.
            /\ out' = Append(out, "R")
            /\ queued' = queued + 1
            /\ resp' = [resp EXCEPT !.left = @ - 1, !.started = TRUE]
            /\ next' = IF ~resp.started /\ resp.hands THEN "tunnel" ELSE next
            /\ head101' = (head101 \/ (~resp.started /\ resp.s101 /\ ~resp.hands))
            /\ UNCHANGED <<phase, buf, after, leftover, respsDone, handPos>>
       ELSE \* finish (native.rs:776-789).
            /\ respsDone' = respsDone + 1
            /\ resp' = NoResp
            /\ IF next # None
               THEN /\ HandOn
                    /\ UNCHANGED <<out, next>>
               ELSE /\ IF resp.close
                       THEN Close
                       ELSE /\ phase' = "Reading"
                            /\ UNCHANGED <<out, next>>
                    /\ UNCHANGED <<buf, after, leftover, handPos>>
            /\ UNCHANGED <<queued, head101>>
    /\ UNCHANGED <<client, eof, sdone, closeNext, peerEnded, handed, written,
                   pos, tunnel, reqsRead, badRead, badHandover, readAfter101>>

(* A deadline, the budget or a failed work closes the connection. *)
Abort ==
    /\ ~switched /\ phase \in {"Reading", "Answering"}
    /\ \/ Close
       \/ \* over_budget (native.rs:368-371): nothing more is written.
          /\ phase' = "Closing" /\ out' = <<"End">>
          /\ resp' = NoResp /\ next' = None
    /\ UNCHANGED <<client, buf, eof, sdone, closeNext, after, peerEnded,
                   queued, handed, written, leftover, pos, tunnel, history>>

(* The layer below takes Http1's next command, and later writes it. *)
TakeCommand ==
    /\ ~switched /\ out # <<>>
    /\ out' = Tail(out)
    /\ IF Head(out) = "R"
       THEN /\ handed' = handed + 1 /\ UNCHANGED <<phase>>
       ELSE /\ phase' = "Closed" /\ UNCHANGED <<handed>>
    /\ UNCHANGED <<client, buf, eof, sdone, closeNext, after, peerEnded,
                   resp, next, queued, written, leftover, pos, tunnel, history>>

Written ==
    /\ written < handed
    /\ written' = written + 1
    /\ UNCHANGED <<client, phase, buf, eof, sdone, closeNext, after, peerEnded,
                   resp, next, out, queued, handed, leftover, pos, tunnel,
                   history>>

-----------------------------------------------------------------------------
(* Switch and Tunnel *)

(* Switch::advance (switch.rs:247-266) with Http1::handover. *)
Handover ==
    /\ ~switched /\ next # None
    /\ phase = "Switching" \/ ~HandOverAfterWritten
    /\ switched' = TRUE
    /\ below' = leftover
    /\ leftover' = <<>>
    /\ phase' = "Closed"
    /\ next' = None
    /\ badHandover' = (badHandover \/ out # <<>> \/ written < queued)
    /\ handPos' = IF phase = "Switching" THEN handPos ELSE pos
    /\ UNCHANGED <<client, buf, eof, sdone, closeNext, after, peerEnded, resp,
                   out, queued, handed, written, pos, inbound, tEnded, tIn,
                   reqsRead, respsDone, badRead, head101, readAfter101>>

(* Switch::advance in Then (switch.rs:271-276): one leftover to the tunnel. *)
FeedBelow ==
    /\ FeedLeftovers
    /\ switched /\ below # <<>>
    /\ LET e == Head(below) IN
       IF e.t = "data"
       THEN /\ TunnelTakes(e.d) /\ UNCHANGED <<tEnded>>
       ELSE /\ tEnded' = TRUE /\ UNCHANGED <<inbound, tIn>>
    /\ below' = Tail(below)
    /\ UNCHANGED <<client, http, switched, history>>

TunnelRead ==
    /\ switched /\ inbound # <<>>
    /\ inbound' = Tail(inbound)
    /\ UNCHANGED <<client, http, switched, below, tEnded, tIn, history>>

Next ==
    \/ Chunk \/ ClientEnd \/ OfferData \/ OfferEnd
    \/ Read \/ Make \/ Respond \/ Abort \/ TakeCommand \/ Written
    \/ Handover \/ FeedBelow \/ TunnelRead

(* Fair to everything that moves bytes; not to Abort. *)
Fairness ==
    /\ WF_vars(Chunk) /\ WF_vars(ClientEnd) /\ WF_vars(OfferData)
    /\ WF_vars(OfferEnd) /\ WF_vars(Read) /\ WF_vars(Make)
    /\ WF_vars(Respond) /\ WF_vars(TakeCommand) /\ WF_vars(Written)
    /\ WF_vars(Handover) /\ WF_vars(FeedBelow) /\ WF_vars(TunnelRead)

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Properties *)

TypeOK ==
    /\ phase \in {"Reading", "Answering", "Switching", "Closing", "Closed"}
    /\ Len(buf) <= StreamCap + MaxChunk
    /\ AfterLen <= StreamCap
    /\ Range(buf) \subseteq Tokens /\ Range(tIn) \subseteq Tokens
    /\ written <= handed /\ handed <= queued

(* One request in flight: a request is read only after the one before it *)
(* was answered. *)
OneInFlight == reqsRead - respsDone \in {0, 1}

(* The next request is read only once every byte of the response before *)
(* it has been written, not only handed below. *)
ReadAfterWritten == ~badRead

(* The handover happens only once the last response is written: nothing *)
(* of HTTP is left to send when the tunnel takes the stream, so no       *)
(* response byte can follow it.                                          *)
HandoverAfterWritten == ~badHandover

(* The tunnel's input is the bytes after the request, first, in order and *)
(* once: always a run of consecutive tokens from the one after it. *)
TunnelGetsTheRest == switched => tIn = Run(handPos, Len(tIn))

(* The peer's end reaches the tunnel only after every byte did. *)
TunnelEndsLast == tEnded => tIn = Run(handPos, L - handPos)

(* Every byte after the request reaches the tunnel. *)
TunnelGetsAll == [](switched => <>(Len(tIn) = L - handPos))

(* After a 101, HTTP is over: no request is read on the connection. *)
NoHttpAfter101 == ~readAfter101

=============================================================================
