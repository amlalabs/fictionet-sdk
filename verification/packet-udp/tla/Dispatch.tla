------------------------------ MODULE Dispatch ------------------------------
(* The IP layer's slots: `IpLayer` in src/stdlib/network/packet.rs.
   `on_event` (lines 496-515) refuses input while a packet or an answer
   waits, and takes a packet in with `take_in` (438-476); `on_command`
   (517-531) takes one command from the transports; `take_command`
   (538-543) gives the answer before the command; `take_event` (545-547)
   hands the packet up; `on_timer` (533-536) expires waiting fragments.

   What `take_in` makes of a packet is its kind, fixed per packet and
   explored over every assignment: a whole packet for a transport, a packet
   refused with an answer or without one (`Intake::Refused`), a fragment
   that waits, or a fragment that completes a packet with every fragment
   waiting (`Intake::Whole` from reassembly). How reassembly decides is in
   Reassembly.tla; which transport a packet goes to is `Transport::read`,
   a function of its bytes, checked with Kani. *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Ids,             \* the raw packets offered from below
    CheckUpSlot,     \* on_event refuses while a packet waits (the code)
    CheckAnswerSlot, \* on_event refuses while an answer waits (the code)
    FilterAnswers    \* take_in sends no answer once output ended (the code)

Transports == {"tcp", "udp"}
Kinds == Transports \cup {"answered", "silent", "wait", "done"}
None == "none"
NoAnswer == 0  \* no packet: Ids are positive

VARIABLES
    kind,        \* kind[i]: what take_in makes of packet i
    fate,        \* fate[i]: where packet i is
    up,          \* IpLayer::up: [what, ids, t]
    answer,      \* IpLayer::answer: the packet it answers, or NoAnswer
    down,        \* IpLayer::down: None, "send" or "end"
    inputClosed, \* IpLayer::input_closed
    outputClosed,\* IpLayer::output_closed
    handed,      \* handed[i]: how many times packet i went up
    handedTo,    \* handedTo[i]: the transport it went to
    owed,        \* packets whose answer take_in made
    answered,    \* packets whose answer went down
    endBelow,    \* the end went down
    sendAfterEnd,\* a packet went down after the end
    endedUp,     \* how many ends went up
    afterEnded   \* a packet went up after the end

vars == <<kind, fate, up, answer, down, inputClosed, outputClosed, handed,
          handedTo, owed, answered, endBelow, sendAfterEnd, endedUp, afterEnded>>

Empty == [what |-> None, ids |-> {}, t |-> None]

Init ==
    /\ kind \in [Ids -> Kinds]
    /\ fate = [i \in Ids |-> "new"]
    /\ up = Empty
    /\ answer = NoAnswer
    /\ down = None
    /\ inputClosed = FALSE
    /\ outputClosed = FALSE
    /\ handed = [i \in Ids |-> 0]
    /\ handedTo = [i \in Ids |-> None]
    /\ owed = {}
    /\ answered = {}
    /\ endBelow = FALSE
    /\ sendAfterEnd = FALSE
    /\ endedUp = 0
    /\ afterEnded = FALSE

Below == <<down, outputClosed, answered, endBelow, sendAfterEnd>>
Above == <<handed, handedTo, endedUp, afterEnded>>

\* IpLayer::take_in, on a layer with room.
TakeIn(i) ==
    CASE kind[i] \in Transports ->
            /\ up' = [what |-> "packet", ids |-> {i}, t |-> kind[i]]
            /\ fate' = [fate EXCEPT ![i] = "up"]
            /\ UNCHANGED <<answer, owed>>
      [] kind[i] = "answered" ->
            LET make == ~(FilterAnswers /\ outputClosed) IN
            /\ answer' = IF make THEN i ELSE NoAnswer
            /\ owed' = IF make THEN owed \cup {i} ELSE owed
            /\ fate' = [fate EXCEPT ![i] = "refused"]
            /\ UNCHANGED up
      [] kind[i] = "silent" ->
            /\ fate' = [fate EXCEPT ![i] = "refused"]
            /\ UNCHANGED <<up, answer, owed>>
      [] kind[i] = "wait" ->
            /\ fate' = [fate EXCEPT ![i] = "waiting"]
            /\ UNCHANGED <<up, answer, owed>>
      [] kind[i] = "done" ->
            LET parts == {j \in Ids : fate[j] = "waiting"} \cup {i} IN
            /\ up' = [what |-> "packet", ids |-> parts, t |-> "udp"]
            /\ fate' = [j \in Ids |-> IF j \in parts THEN "up" ELSE fate[j]]
            /\ UNCHANGED <<answer, owed>>

\* IpLayer::on_event with a packet: Closed and Blocked hand it back.
Offer(i) ==
    /\ fate[i] \in {"new", "held"}
    /\ IF inputClosed
          \/ (CheckUpSlot /\ up.what # None)
          \/ (CheckAnswerSlot /\ answer # NoAnswer)
       THEN /\ fate' = [fate EXCEPT ![i] = "held"]
            /\ UNCHANGED <<up, answer, owed>>
       ELSE TakeIn(i)
    /\ UNCHANGED <<kind, inputClosed>>
    /\ UNCHANGED Below
    /\ UNCHANGED Above

\* IpLayer::on_event with the end, when the layer has room.
OfferEnd ==
    /\ ~inputClosed /\ up.what = None /\ answer = NoAnswer
    /\ inputClosed' = TRUE
    /\ up' = [what |-> "ended", ids |-> {}, t |-> None]
    /\ UNCHANGED <<kind, fate, answer, owed>>
    /\ UNCHANGED Below
    /\ UNCHANGED Above

\* IpLayer::on_timer: Reassembly::expire drops the waiting fragments.
Timer ==
    /\ \E j \in Ids : fate[j] = "waiting"
    /\ fate' = [j \in Ids |-> IF fate[j] = "waiting" THEN "expired" ELSE fate[j]]
    /\ UNCHANGED <<kind, up, answer, down, inputClosed, outputClosed, owed>>
    /\ UNCHANGED <<answered, endBelow, sendAfterEnd>>
    /\ UNCHANGED Above

\* IpLayer::take_event: the transport above takes what is up.
TakeEvent ==
    /\ up.what # None
    /\ up' = Empty
    /\ IF up.what = "packet"
       THEN /\ handed' = [j \in Ids |-> IF j \in up.ids THEN handed[j] + 1 ELSE handed[j]]
            /\ handedTo' = [j \in Ids |-> IF j \in up.ids THEN up.t ELSE handedTo[j]]
            /\ fate' = [j \in Ids |-> IF j \in up.ids THEN "handed" ELSE fate[j]]
            /\ afterEnded' = (afterEnded \/ endedUp > 0)
            /\ UNCHANGED endedUp
       ELSE /\ endedUp' = endedUp + 1
            /\ UNCHANGED <<handed, handedTo, fate, afterEnded>>
    /\ UNCHANGED <<kind, answer, inputClosed, owed>>
    /\ UNCHANGED Below

\* IpLayer::on_command: a transport sends a packet or the end.
Command(c) ==
    /\ ~outputClosed /\ down = None
    /\ down' = c
    /\ outputClosed' = (c = "end")
    /\ UNCHANGED <<kind, fate, up, answer, inputClosed, owed>>
    /\ UNCHANGED <<answered, endBelow, sendAfterEnd>>
    /\ UNCHANGED Above

\* IpLayer::take_command: the answer first, then the transport's command.
TakeCommand ==
    /\ answer # NoAnswer \/ down # None
    /\ IF answer # NoAnswer
       THEN /\ answered' = answered \cup {answer}
            /\ answer' = NoAnswer
            /\ sendAfterEnd' = (sendAfterEnd \/ endBelow)
            /\ UNCHANGED <<down, endBelow>>
       ELSE /\ down' = None
            /\ endBelow' = (endBelow \/ down = "end")
            /\ sendAfterEnd' = (sendAfterEnd \/ (endBelow /\ down = "send"))
            /\ UNCHANGED <<answered, answer>>
    /\ UNCHANGED <<kind, fate, up, inputClosed, outputClosed, owed>>
    /\ UNCHANGED Above

Next ==
    \/ \E i \in Ids : Offer(i)
    \/ OfferEnd
    \/ Timer
    \/ TakeEvent
    \/ \E c \in {"send", "end"} : Command(c)
    \/ TakeCommand

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
TypeOK ==
    /\ fate \in [Ids -> {"new", "held", "waiting", "refused", "expired", "up", "handed"}]
    /\ answer \in Ids \cup {NoAnswer}
    /\ down \in {None, "send", "end"}

\* Every packet the layer took is in exactly one place: waiting, refused,
\* expired, in the up slot, or handed up; a packet in the up slot is there.
NothingLost == \A i \in Ids : fate[i] = "up" <=> i \in up.ids

\* No packet goes up twice, and each goes to the transport it was sorted to.
ExactlyOnce ==
    \A i \in Ids :
        /\ handed[i] <= 1
        /\ handed[i] = 1 /\ kind[i] \in Transports => handedTo[i] = kind[i]

\* An answer take_in made waits or has gone down: none is overwritten.
AnswersKept == \A i \in owed : answer = i \/ i \in answered

\* Nothing goes down after the end.
NoSendAfterEnd == ~sendAfterEnd

\* The end goes up once, after every packet.
EndedOnce == endedUp <= 1 /\ ~afterEnded
=============================================================================
