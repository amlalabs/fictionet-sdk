------------------------------ MODULE Stream ------------------------------
(* One direction of a TCP connection as the dissector reads it            *)
(* (src/stdlib/dissect): the observer hands up its bytes, gaps and end;   *)
(* `Dissector::apply` gives them to the connection's `Conversation`,      *)
(* which holds a prefix until a protocol is chosen and then drives it; a  *)
(* registered protocol is a `Pair` of `Observed` readers, each a bounded  *)
(* `Stream` and the placement of its last bytes in the packet shown.      *)
(*                                                                        *)
(* The sender's bytes are tokens, each its own position, in messages of L *)
(* tokens. A reader frames by what it reads, not by the tokens' message,  *)
(* so after missing bytes it frames wherever it stands. Three kinds of    *)
(* reader:                                                                *)
(*   "stop"  framing only a length marks (TLS records, HTTP/2 frames, DNS *)
(*           over TCP): after a gap the direction stops;                  *)
(*   "head"  HTTP/1: after a gap it reads again from a head, which names  *)
(*           itself (a request or status line), taken here as a message's *)
(*           first token. The code finds the next head at the first blank *)
(*           line (`Http1::find`) and reads everything before it as one   *)
(*           head: the bytes of a cut body before that head make it fail, *)
(*           and `decode` skips the head with them (http1.rs 130-147).    *)
(*           This reader skips only to the next head, so it shows         *)
(*           messages the code loses after a gap inside a body; nothing   *)
(*           the code shows is missing from it;                           *)
(*   "close" a message read to the end of the stream (a decoder a user   *)
(*           may register, `UntilClose` in the tests): it completes only  *)
(*           at a FIN.                                                    *)
(* Each event comes while a packet is shown: packets are numbered from 1, *)
(* and 0 is the end of the capture (`Dissector::finish`), which shows no  *)
(* packet. Bytes come from the packet shown or, released past a hole that *)
(* filled, from an earlier one.                                           *)
(*                                                                        *)
(* Source lines, at the commit in README.md:                              *)
(*   Dissector::finish, apply (Data, Gap, End)  mod.rs 497-510, 938-1025  *)
(*   Conversation::lost, end, data           conversation.rs 67-170       *)
(*   Pair::lost, Pair::end, end_elsewhere    registry.rs 258-320          *)
(*   Observed::reset, data_with, end         present.rs 293-404           *)
(*   Place::locate                           present.rs 101-118           *)
(*   Stream::with_next (Need at EOF is       codec/stream.rs 248-329      *)
(*     Truncated, 308-316)                                                *)
(*   Dns::decode, next, reset                protocols/dns.rs 59-151      *)
(*   Http1::decode (a head), Http1::reset    protocols/http1.rs 128-296   *)
(*   Capture::reset (HTTP/2 stops)           http2.rs 1422-1427, 1059     *)
(*   TlsSession::lost (TLS records stop)     tls.rs 128-137               *)
(*                                                                        *)
(* Left out: what a message says, read-ahead limits and refusal (a        *)
(* refused direction stops, as after a gap), a conversation no protocol   *)
(* matches (rejected: it shows nothing), and the other direction, which   *)
(* shares only the selection.                                             *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Kind,          \* "stop", "head" or "close"
          N,             \* messages the sender sends
          L,             \* tokens a message has
          MaxPkt,        \* packets shown before the capture ends
          MaxGaps,       \* gaps the observer reports
          StopOnReset,   \* a "stop" reader's reset ends its direction (Dns::reset, Capture::reset, TlsSession::lost)
          HeadOnly,      \* a "head" reader reads again only from a head
          DropBuffer,    \* Observed::reset drops the bytes it held
          TellEarly,     \* Conversation tells the protocol it chooses of a gap before it
          ShownPacket,   \* apply places bytes only in the packet it shows: none at the end
          ClearAtEnd,    \* an end clears the packet run before Observed::end
          FinFinishes,   \* a FIN ends the readers (Observed::end), as end-of-stream
          OthersDiscard, \* any other end discards what they held (Pair::end -> lost)
          EndAfterChoice \* a FIN before the choice reaches the protocol after the prefix

T == N * L
Tok(i) == [m |-> ((i - 1) \div L) + 1, k |-> ((i - 1) % L) + 1]
Causes == {"fin", "reset", "truncated", "finalized"}
Range(s) == {s[j] : j \in DOMAIN s}
\* An item given a buffer of its own points into no packet.
Buffer == MaxPkt + 1

VARIABLES next,      \* the next token the sender's stream has for the observer
          pkt,       \* the packet shown: 1..MaxPkt, or 0 at the end of the capture
          last,      \* the last packet decoded (Dissector::packets)
          src,       \* src[i]: the packet token i came in, once delivered
          lost,      \* tokens the observer reported missing
          gaps,      \* gaps reported
          chosen,    \* the conversation chose its protocol
          prefix,    \* tokens held until then
          early,     \* Conversation::lost_early
          held,      \* the reader's unread tokens: [i, ch] (index, run)
          seeking,   \* a "head" reader looks for a head after a gap
          stopped,   \* the reader's direction stopped
          run,       \* the last run handed to the reader: [ch, known] (Place)
          runs,      \* runs handed so far
          reported,  \* what the reader showed: [idx, whole, ptr]
          ended,     \* the direction ended, and how ("" while open)
          atEnd,     \* the tokens the reader held when it ended
          incomplete \* the end's packet is tagged incomplete
vars == <<next, pkt, last, src, lost, gaps, chosen, prefix, early, held, seeking, stopped,
          run, runs, reported, ended, atEnd, incomplete>>

Init == /\ next = 1 /\ pkt = 1 /\ last = 1
        /\ src = [i \in 1..T |-> 0] /\ lost = {} /\ gaps = 0
        /\ chosen = FALSE /\ prefix = <<>> /\ early = FALSE
        /\ held = <<>> /\ seeking = FALSE /\ stopped = FALSE
        /\ run = [ch |-> 0, known |-> FALSE] /\ runs = 0
        /\ reported = <<>> /\ ended = "" /\ atEnd = <<>> /\ incomplete = FALSE

(* Place::locate: an item points into the packet shown only when all its  *)
(* tokens are in the last run and that run's offset is known.             *)
Ptr(item, r) == IF r.known /\ \A j \in DOMAIN item : item[j].ch = r.ch THEN pkt ELSE Buffer
Idx(item) == [j \in DOMAIN item |-> item[j].i]
Show(item, whole, r) == [idx |-> Idx(item), whole |-> whole, ptr |-> Ptr(item, r)]

(* Frame what the reader holds, item by item, as data_with's loop does.   *)
(* A "head" reader looking for a head skips tokens until one starts a     *)
(* message. Returns [held, seeking, out].                                 *)
RECURSIVE Frame(_, _, _, _)
Frame(h, seek, r, out) ==
  IF Kind = "close" \/ h = <<>> THEN [held |-> h, seeking |-> seek, out |-> out]
  ELSE IF seek /\ Tok(h[1].i).k # 1 THEN Frame(Tail(h), seek, r, out)
  ELSE IF Len(h) >= L
       THEN Frame(SubSeq(h, L + 1, Len(h)), FALSE, r, Append(out, Show(SubSeq(h, 1, L), TRUE, r)))
       ELSE [held |-> h, seeking |-> FALSE, out |-> out]

(* Observed::data_with with one run of tokens.                            *)
Feed(toks, r) ==
  IF stopped THEN /\ UNCHANGED <<held, seeking, reported>>
  ELSE LET f == Frame(held \o toks, seeking, r, <<>>)
       IN /\ held' = f.held /\ seeking' = f.seeking /\ reported' = reported \o f.out

(* Pair::lost: Observed::reset drops the buffer and resets the decoder.   *)
Reset == /\ held' = IF DropBuffer THEN <<>> ELSE held
         /\ stopped' = (stopped \/ (Kind = "stop" /\ StopOnReset))
         /\ seeking' = (Kind = "head" /\ HeadOnly)

Open == ended = "" /\ next <= T + 1

(* ObservedEvent::Data: one or two tokens, from the packet shown or       *)
(* released from an earlier one. The run's offset is known when the       *)
(* source is the packet apply was told it shows.                          *)
Data(n, from) ==
  /\ Open /\ next + n - 1 <= T
  /\ from \in (IF pkt = 0 THEN 1..last ELSE 1..pkt)
  /\ src' = [i \in 1..T |-> IF i \in next..next + n - 1 THEN from ELSE src[i]]
  /\ next' = next + n
  /\ LET ch == runs + 1
         toks == [j \in 1..n |-> [i |-> next + j - 1, ch |-> ch]]
         r == [ch |-> ch, known |-> from = (IF ShownPacket THEN pkt ELSE last)]
     IN IF chosen
        THEN /\ runs' = ch /\ run' = r /\ Feed(toks, r)
             /\ UNCHANGED <<chosen, prefix, early, stopped>>
        ELSE \/ /\ prefix' = prefix \o toks
                /\ UNCHANGED <<chosen, early, held, seeking, stopped, run, runs, reported>>
             \/ \* Selection: the earlier prefix is flushed with no offset, after
                \* the gap before it if TellEarly, then this run with its own.
                LET flush == [j \in DOMAIN prefix |-> [prefix[j] EXCEPT !.ch = ch]]
                    none == [ch |-> ch, known |-> FALSE]
                    mine == [j \in 1..n |-> [toks[j] EXCEPT !.ch = ch + 1]]
                    r2 == [r EXCEPT !.ch = ch + 1]
                    stop0 == early /\ TellEarly /\ Kind = "stop" /\ StopOnReset
                    seek0 == early /\ TellEarly /\ Kind = "head" /\ HeadOnly
                    f1 == IF stop0 THEN [held |-> <<>>, seeking |-> FALSE, out |-> <<>>]
                          ELSE Frame(flush, seek0, none, <<>>)
                    f2 == IF stop0 THEN f1 ELSE Frame(f1.held \o mine, f1.seeking, r2, f1.out)
                IN /\ chosen' = TRUE /\ prefix' = <<>> /\ early' = early
                   /\ stopped' = stop0
                   /\ held' = f2.held /\ seeking' = f2.seeking
                   /\ reported' = reported \o f2.out
                   /\ runs' = ch + 1 /\ run' = r2
  /\ UNCHANGED <<pkt, last, lost, gaps, ended, atEnd, incomplete>>

(* ObservedEvent::Gap: the next token is missing.                         *)
Gap ==
  /\ Open /\ next <= T /\ gaps < MaxGaps
  /\ lost' = lost \cup {next} /\ next' = next + 1 /\ gaps' = gaps + 1
  /\ IF chosen
     THEN /\ Reset /\ UNCHANGED <<prefix, early>>
     ELSE /\ early' = TRUE /\ prefix' = <<>> /\ UNCHANGED <<held, seeking, stopped>>
  /\ UNCHANGED <<pkt, last, src, chosen, run, runs, reported, ended, atEnd, incomplete>>

(* ObservedEvent::End. A FIN only once every byte came, as the observer   *)
(* says; at the end of the capture the end is truncated if bytes are     *)
(* missing before it, else finalized.                                     *)
End(cause) ==
  /\ Open
  /\ cause = "fin" => next = T + 1
  /\ cause \in {"truncated", "finalized"} <=> pkt = 0
  /\ ended' = cause
  \* What the reader held and still read: Observed::waiting.
  /\ atEnd' = IF chosen /\ ~stopped THEN held ELSE <<>>
  /\ incomplete' = (cause # "fin" /\ chosen /\ ~stopped /\ held # <<>>)
  /\ IF ~chosen
     THEN \* Conversation::end before the choice: a FIN keeps the prefix
          \* (ended_early); any other end discards it as missing bytes
          \* (Conversation::lost, which also sets lost_early).
          /\ prefix' = IF cause = "fin" THEN prefix ELSE <<>>
          /\ early' = IF cause = "fin" THEN early ELSE TRUE
          /\ UNCHANGED <<held, seeking, stopped, run, reported>>
     ELSE IF (cause = "fin" /\ FinFinishes) \/ (cause # "fin" /\ ~OthersDiscard)
     THEN \* Observed::end: the decoder sees the end of its input. Whole items
          \* were framed already; what is left completes a "close" message,
          \* and is a truncation for the others.
          LET r == IF ClearAtEnd THEN [run EXCEPT !.known = FALSE] ELSE run
          IN /\ run' = r
             /\ reported' = IF held = <<>> \/ stopped THEN reported
                            ELSE Append(reported, Show(held, Kind = "close", r))
             /\ held' = <<>>
             /\ UNCHANGED <<prefix, early, seeking, stopped>>
     ELSE /\ held' = <<>> /\ stopped' = TRUE
          /\ UNCHANGED <<prefix, early, seeking, run, reported>>
  /\ UNCHANGED <<next, pkt, last, src, lost, gaps, chosen, runs>>

(* The other direction's bytes choose the protocol (Conversation::data,   *)
(* the loop over both directions): this direction's prefix goes to it     *)
(* with no offset, after the gap before it if TellEarly, and then, if     *)
(* this direction already ended with a FIN, that end (Observed::end with  *)
(* the packet run cleared, as Pair::end does).                            *)
OtherChooses ==
  /\ ~chosen
  /\ LET ch == runs + 1
         flush == [j \in DOMAIN prefix |-> [prefix[j] EXCEPT !.ch = ch]]
         none == [ch |-> ch, known |-> FALSE]
         stop0 == early /\ TellEarly /\ Kind = "stop" /\ StopOnReset
         seek0 == early /\ TellEarly /\ Kind = "head" /\ HeadOnly
         f == IF stop0 THEN [held |-> <<>>, seeking |-> FALSE, out |-> <<>>]
              ELSE Frame(flush, seek0, none, <<>>)
         fin == ended = "fin" /\ ~stop0
         finish == fin /\ EndAfterChoice
     IN /\ chosen' = TRUE /\ prefix' = <<>> /\ runs' = ch /\ run' = none
        /\ stopped' = stop0 /\ seeking' = f.seeking
        /\ held' = IF finish THEN <<>> ELSE f.held
        /\ reported' = reported \o f.out
                       \o (IF finish /\ f.held # <<>> THEN <<Show(f.held, Kind = "close", none)>>
                           ELSE <<>>)
        /\ atEnd' = IF fin THEN f.held ELSE atEnd
  /\ UNCHANGED <<next, pkt, last, src, lost, gaps, early, ended, incomplete>>

NextPacket == /\ pkt # 0 /\ last < MaxPkt /\ pkt' = last + 1 /\ last' = last + 1
              /\ UNCHANGED <<next, src, lost, gaps, chosen, prefix, early, held, seeking, stopped,
                             run, runs, reported, ended, atEnd, incomplete>>
Finish == /\ pkt # 0 /\ pkt' = 0
          /\ UNCHANGED <<next, last, src, lost, gaps, chosen, prefix, early, held, seeking, stopped,
                         run, runs, reported, ended, atEnd, incomplete>>

Next == \/ \E n \in 1..2, from \in 1..MaxPkt : Data(n, from)
        \/ Gap
        \/ OtherChooses
        \/ \E c \in Causes : End(c)
        \/ NextPacket
        \/ Finish

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
IsMessage(idx) == /\ Len(idx) = L /\ Tok(idx[1]).k = 1
                  /\ \A j \in 2..L : idx[j] = idx[1] + j - 1
Whole(idx) == idx = [j \in 1..T |-> j]

(* Every message shown whole is one message of the sender's, all of it    *)
(* and nothing else; read to the close, it is the whole stream.           *)
ItemsAreMessages ==
  \A j \in DOMAIN reported :
    reported[j].whole => IF Kind = "close" THEN Whole(reported[j].idx) ELSE IsMessage(reported[j].idx)

(* Nothing shown holds bytes from both sides of a gap.                    *)
NoJoinAcrossGap ==
  \A j \in DOMAIN reported, g \in lost :
    LET idx == reported[j].idx IN ~(\E a, b \in DOMAIN idx : idx[a] < g /\ g < idx[b])

(* A reader whose framing only a length marks shows nothing from after    *)
(* its first gap.                                                         *)
StopsAfterGap ==
  Kind = "stop" => \A j \in DOMAIN reported, g \in lost : \A i \in Range(reported[j].idx) : i < g

(* An item that points into the packet shown is all in it: the packet is  *)
(* a packet, not the end of the capture, and every token came in it.     *)
PointsOnlyIntoItsPacket ==
  \A j \in DOMAIN reported :
    reported[j].ptr # Buffer =>
      /\ reported[j].ptr # 0
      /\ \A i \in Range(reported[j].idx) : src[i] = reported[j].ptr

(* A FIN finishes what the reader held: read to the close, a message     *)
(* completes; any other partial message is shown cut short, never whole. *)
FinFinishesHeld ==
  ended = "fin" =>
    /\ held = <<>>
    /\ atEnd # <<>> =>
         /\ reported # <<>>
         /\ reported[Len(reported)].idx = Idx(atEnd)
         /\ reported[Len(reported)].whole = (Kind = "close")

(* Any other end discards what the reader held, shows nothing for it, and *)
(* tags the packet incomplete when a message was cut.                     *)
OthersDiscardHeld ==
  ended \notin {"", "fin"} =>
    /\ held = <<>>
    /\ atEnd # <<>> => incomplete
    /\ \A j \in DOMAIN reported : Range(reported[j].idx) \cap Range(Idx(atEnd)) = {}
=============================================================================
