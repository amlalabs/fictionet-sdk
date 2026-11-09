----------------------------- MODULE GrpcCall -----------------------------
(***************************************************************************)
(* The read side of gRPC calls on one HTTP/2 connection: each call's DATA *)
(* bytes, split into chunks anywhere, read as length-prefixed messages by *)
(* its own Grpc layer, and handed to an application that may fall behind. *)
(*                                                                         *)
(* Source, at the commit named in verification/hpack-grpc/README.md:      *)
(*   src/stdlib/web/httpd/http2/grpc.rs                                    *)
(*     WAITING                                  line 19                    *)
(*     Grpc::fail, ::finish                     lines 168-185              *)
(*     Grpc::messages (the read loop, the early *)
(*       prefix check, the client's end)        lines 205-259              *)
(*     on_event: Data, Trailers/End, Closed     lines 288-339              *)
(*     on_command: Status ends the call         lines 341-372              *)
(*     advance calls messages                   lines 374-383              *)
(*   src/stdlib/protocols/grpc.rs                                          *)
(*     prefix_len, message_len, parse_message   lines 344-388              *)
(*                                                                         *)
(* Scaled: the 5-byte prefix is a flag byte and one length byte (Header = *)
(* 2; Kani proves the 4-byte length is read exactly), MAX_MESSAGE is      *)
(* Limit and Http2::WINDOW is Window. A byte is a record: a flag or a     *)
(* length carries its value; a body byte names its call, its message and  *)
(* its place, so a message read across a boundary shows. The connection's *)
(* budget is left out: running out of it fails a call the way an          *)
(* oversized buffer does.                                                 *)
(*                                                                         *)
(* Each flag below is TRUE in the code; a *_without_<flag>.cfg sets one   *)
(* FALSE and must violate the invariant its first comment line names.     *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Calls,          \* the calls on the connection
    Header,         \* the prefix length, 5 in the code
    Limit,          \* MAX_MESSAGE
    Window,         \* Http2::WINDOW
    Waiting,        \* WAITING: events waiting for the application
    MaxMsgs,        \* messages a client writes on a call
    MaxChunk,       \* the most bytes in one DATA chunk
    Lengths,        \* body lengths a client may declare
    CheckLimit,     \* parse_message: a length over the limit is refused
    BoundBuffer,    \* on_event: bytes past a message and a window are refused
    EndCheck,       \* messages: an end inside a message fails the call
    EndWhenRoom,    \* messages: the end waits until every whole message is read
    CheckEarly,     \* the headers of messages waiting for room are checked
    OwnBuffer       \* each call reads only its own bytes

None == "none"

Flag(v) == [kind |-> "flag", v |-> v, call |-> 0, msg |-> 0, k |-> 0]
Length(v) == [kind |-> "len", v |-> v, call |-> 0, msg |-> 0, k |-> 0]
Body(c, m, k) == [kind |-> "body", v |-> 0, call |-> c, msg |-> m, k |-> k]

\* A message the client writes: its flag and declared length, and the body
\* it sends (as long as it declares).
Wire(c, m, f, l) == <<Flag(f), Length(l)>> \o [k \in 1..l |-> Body(c, m, k)]
Data(c, m, l) == [k \in 1..l |-> Body(c, m, k)]

\* parse_message: Ok(None) is "wait", errors are "flag" and "large".
Parse(b) ==
    IF Len(b) = 0 THEN [r |-> "wait"]
    ELSE IF b[1].v > 1 THEN [r |-> "flag"]
    ELSE IF Len(b) < Header THEN [r |-> "wait"]
    ELSE IF CheckLimit /\ b[2].v > Limit THEN [r |-> "large"]
    ELSE IF Len(b) < Header + b[2].v THEN [r |-> "wait"]
    ELSE [r |-> "message", flag |-> b[1].v, data |-> SubSeq(b, Header + 1, Header + b[2].v),
          used |-> Header + b[2].v]

Drop(s, n) == SubSeq(s, n + 1, Len(s))

\* The first rule broken by the prefixes of the whole messages waiting at
\* the start of b and of the first one not yet whole: "flag", "large", or
\* "none".
RECURSIVE Broken(_)
Broken(b) ==
    LET p == Parse(b) IN
    CASE p.r = "message" -> Broken(Drop(b, p.used))
      [] p.r = "wait" -> "none"
      [] OTHER -> p.r

\* The whole messages at the start of b.
RECURSIVE Msgs(_)
Msgs(b) ==
    LET p == Parse(b) IN
    IF p.r = "message"
    THEN <<[flag |-> p.flag, data |-> p.data]>> \o Msgs(Drop(b, p.used))
    ELSE <<>>

\* Whether bytes are whole messages, with nothing left over.
RECURSIVE Whole(_)
Whole(b) == LET p == Parse(b) IN
            IF b = <<>> THEN TRUE ELSE p.r = "message" /\ Whole(Drop(b, p.used))

Why(r) == IF r = "large" THEN "exhausted" ELSE "internal"

VARIABLES
    written,  \* per call: the messages the client wrote, [flag, len]
    out,      \* per call: bytes written and not yet sent
    st,       \* per call: the Grpc layer's state
    got,      \* per call: messages the application read
    recv,     \* per call: the bytes the layer took (ghost)
    closed    \* per call: the client ended it

vars == <<written, out, st, got, recv, closed>>

Fresh == [partial |-> <<>>, up |-> <<>>, readOver |-> FALSE, clientEnded |-> FALSE,
          finished |-> FALSE, outcome |-> None, endHandled |-> FALSE]

Init ==
    /\ written = [c \in Calls |-> <<>>]
    /\ out = [c \in Calls |-> <<>>]
    /\ st = [c \in Calls |-> Fresh]
    /\ got = [c \in Calls |-> <<>>]
    /\ recv = [c \in Calls |-> <<>>]
    /\ closed = [c \in Calls |-> FALSE]

\* Grpc::fail
Fail(s, why) ==
    [s EXCEPT !.readOver = TRUE, !.partial = <<>>,
              !.finished = TRUE,
              !.outcome = IF s.finished THEN s.outcome ELSE why]

\* The loop of Grpc::messages, from `at`, while the application has room.
RECURSIVE Read(_, _)
Read(s, at) ==
    IF Len(s.up) >= Waiting THEN [s |-> s, at |-> at, failed |-> FALSE]
    ELSE LET p == Parse(Drop(s.partial, at)) IN
         CASE p.r = "message" ->
                Read([s EXCEPT !.up = Append(s.up, [kind |-> "message", flag |-> p.flag,
                                                     data |-> p.data])],
                     at + p.used)
           [] p.r = "wait" -> [s |-> s, at |-> at, failed |-> FALSE]
           [] OTHER -> [s |-> Fail(s, Why(p.r)), at |-> 0, failed |-> TRUE]

\* Grpc::messages
Messages(s) ==
    IF s.finished /\ s.readOver /\ s.partial = <<>> THEN s
    ELSE LET r == Read(s, 0) IN
         IF r.failed THEN r.s
         ELSE LET s1 == [r.s EXCEPT !.partial = Drop(r.s.partial, r.at)]
              IN IF CheckEarly /\ Broken(s1.partial) # "none"
                 THEN Fail(s1, Why(Broken(s1.partial)))
                 ELSE IF s1.clientEnded /\ (~EndWhenRoom \/ Len(s1.up) < Waiting)
                 THEN IF s1.partial = <<>> \/ ~EndCheck
                      THEN [s1 EXCEPT !.clientEnded = FALSE, !.endHandled = TRUE,
                                      !.up = Append(s1.up, [kind |-> "ended", flag |-> 0,
                                                            data |-> <<>>])]
                      ELSE [Fail(s1, "truncated") EXCEPT !.clientEnded = FALSE,
                                                         !.endHandled = TRUE]
                 ELSE s1

\* The client writes its next message on call c.
Write(c, f, l) ==
    /\ Len(written[c]) < MaxMsgs
    /\ ~closed[c]
    /\ written' = [written EXCEPT ![c] = Append(@, [flag |-> f, len |-> l])]
    /\ out' = [out EXCEPT ![c] = @ \o Wire(c, Len(written[c]) + 1, f, l)]
    /\ UNCHANGED <<st, got, recv, closed>>

\* One DATA chunk of n bytes on call c reaches its layer: on_event's Data
\* arm. With one buffer for every call, a call reads its siblings' bytes.
Send(c, n) ==
    /\ n \in 1..Len(out[c])
    /\ LET chunk == SubSeq(out[c], 1, n)
           buffer(d) == IF OwnBuffer THEN d ELSE CHOOSE x \in Calls : TRUE
           s == st[buffer(c)]
       IN /\ out' = [out EXCEPT ![c] = Drop(@, n)]
          /\ IF s.readOver
             THEN UNCHANGED <<st, recv>>
             ELSE /\ recv' = [recv EXCEPT ![c] = @ \o chunk]
                  /\ st' = [st EXCEPT ![buffer(c)] =
                        IF BoundBuffer /\ Len(s.partial) + n > Limit + Header + Window
                        THEN Fail(s, "exhausted")
                        ELSE Messages([s EXCEPT !.partial = @ \o chunk])]
    /\ UNCHANGED <<written, got, closed>>

\* The client ends call c (END_STREAM or trailers); bytes it had not sent
\* are never sent: a client may end inside a message.
End(c) ==
    /\ ~closed[c]
    /\ closed' = [closed EXCEPT ![c] = TRUE]
    /\ out' = [out EXCEPT ![c] = <<>>]
    /\ LET s == st[c] IN
       IF s.readOver
       THEN UNCHANGED st
       ELSE st' = [st EXCEPT ![c] = Messages([s EXCEPT !.readOver = TRUE,
                                                       !.clientEnded = TRUE])]
    /\ UNCHANGED <<written, got, recv>>

\* The application reads the next event: take_event, then advance.
Take(c) ==
    /\ st[c].up # <<>>
    /\ LET s == st[c]
           e == Head(s.up)
       IN /\ got' = [got EXCEPT ![c] = IF e.kind = "message"
                                       THEN Append(@, [flag |-> e.flag, data |-> e.data])
                                       ELSE @]
          /\ st' = [st EXCEPT ![c] = Messages([s EXCEPT !.up = Tail(s.up)])]
    /\ UNCHANGED <<written, out, recv, closed>>

\* The application ends the call with a status: on_command, then advance.
Answer(c) ==
    /\ ~st[c].finished
    /\ LET s == st[c] IN
       st' = [st EXCEPT ![c] = Messages([s EXCEPT !.finished = TRUE, !.outcome = "answered"])]
    /\ UNCHANGED <<written, out, got, recv, closed>>

Next ==
    \E c \in Calls :
        \/ \E f \in 0..2, l \in Lengths : Write(c, f, l)
        \/ \E n \in 1..MaxChunk : Send(c, n)
        \/ End(c)
        \/ Take(c)
        \/ Answer(c)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                             *)

\* The messages the client wrote, as the application must see them.
Sent(c) == [i \in 1..Len(written[c]) |->
              [flag |-> written[c][i].flag, data |-> Data(c, i, written[c][i].len)]]

IsPrefix(a, b) == Len(a) <= Len(b) /\ \A i \in 1..Len(a) : a[i] = b[i]

Queued(c) == [i \in 1..Len(SelectSeq(st[c].up, LAMBDA e : e.kind = "message")) |->
                LET e == SelectSeq(st[c].up, LAMBDA e : e.kind = "message")[i]
                IN [flag |-> e.flag, data |-> e.data]]

\* Each call's application reads exactly the messages its client wrote,
\* in order, however the chunks split them, and none of another call's.
Exact == \A c \in Calls : IsPrefix(got[c] \o Queued(c), Sent(c))

\* No message with a flag other than 0 or 1, or longer than the limit,
\* reaches the application.
WithinRules == \A c \in Calls : \A i \in 1..Len(got[c]) :
                  got[c][i].flag <= 1 /\ Len(got[c][i].data) <= Limit

\* A call holds at most a message and a window of unread bytes.
Bounded == \A c \in Calls : Len(st[c].partial) <= Limit + Header + Window

\* A prefix that breaks the rules is refused as soon as it arrives: no call
\* holds one, at a message boundary, while its application falls behind.
RefusedAtHeader == \A c \in Calls : Broken(st[c].partial) = "none"

\* The application sees the end only after every byte of the call made
\* whole messages, and all of them reached it.
EndedWhole == \A c \in Calls :
    (\E i \in 1..Len(st[c].up) : st[c].up[i].kind = "ended")
        => Whole(recv[c]) /\ got[c] \o Queued(c) = Msgs(recv[c])

\* A call whose bytes stop inside a message is failed, not ended.
TruncationReported == \A c \in Calls :
    st[c].endHandled /\ ~Whole(recv[c]) => st[c].outcome # None

\* A call is reported truncated only when its bytes stop inside a message.
NoFalseTruncation == \A c \in Calls :
    st[c].outcome = "truncated" => ~Whole(recv[c])
=============================================================================
