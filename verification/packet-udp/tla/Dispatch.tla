------------------------------ MODULE Dispatch ------------------------------
(* The IP layer's slots: `IpLayer` in src/stdlib/network/packet.rs (lines
   checked on 2026-11-10 at 8c582367b). `on_event` (lines 592-611) refuses
   input while a packet or an answer waits, and takes a raw packet in with
   `take_in` (526-564), which hands it up through `checked` (567-572) or
   reports it; `on_command` (613-627) takes one command from the
   transports; `take_command` (634-639) gives the answer before the
   command; `take_event` (641-643) hands the packet up; `on_timer`
   (629-632) expires waiting fragments. The endpoint takes what is up
   through `Driver::send_above` in `drive`, src/stdlib/network/endpoint.rs
   (lines 44 on; the dispatch is 114-149), which sends it where
   `destination` (30-36) says: TCP, UDP, or the host's ICMP for
   `Sort::Icmp` and `Sort::Other`.

   The layer has no network: it takes raw packets from the input path its
   endpoint owns (Reassembly.tla has the networks). What `take_in` makes of
   a packet is its kind, fixed per packet and explored over every
   assignment: a whole packet for TCP, UDP or ICMP; an ICMP error quoting a
   TCP or UDP packet; a packet refused with an answer or without one
   (`Intake::Refused`, or `IpReport::Malformed` when `checked` refuses it);
   a fragment that waits; or a fragment that completes a packet with every
   fragment waiting (`Intake::Whole` from reassembly), whose kind is `gram`.
   How reassembly decides is in Reassembly.tla. Where a packet goes is
   `Sort::read` (packet.rs 200-229), a function of its bytes checked with
   Kani, then `destination`; `Dest` below is the two together, and
   QuoteErrors is the branch of `Sort::read` that sends an ICMP error to
   the transport of the packet it quotes. A protocol the host has no
   transport for goes to the host's ICMP too, so the model's "icmp" kind
   stands for both. A "done" fragment here completes every waiting
   fragment, and `Timer` expires every one: coarser than the code, which
   completes and expires per key, but the slots see only whether a packet
   is waiting. *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Ids,             \* the raw packets offered from below
    GramKinds,       \* the kinds a reassembled packet may have
    MaxSends,        \* how many packets the transports send
    CheckUpSlot,     \* on_event refuses while a packet waits (the code)
    CheckAnswerSlot, \* on_event refuses while an answer waits (the code)
    FilterAnswers,   \* take_in sends no answer once output ended (the code)
    QuoteErrors      \* Sort::read sends ICMP errors to the quoted transport (the code)

Whole == {"tcp", "udp", "icmp", "errtcp", "errudp"}
Kinds == Whole \cup {"answered", "silent", "wait", "done"}
ASSUME GramKinds \subseteq Whole
None == "none"
NoAnswer == 0  \* no packet: Ids are positive

\* Sort::read, then destination.
Dest(k) ==
    CASE k = "tcp" -> "tcp"
      [] k = "udp" -> "udp"
      [] k = "icmp" -> "icmp"
      [] k = "errtcp" -> IF QuoteErrors THEN "tcp" ELSE "icmp"
      [] k = "errudp" -> IF QuoteErrors THEN "udp" ELSE "icmp"

VARIABLES
    kind,        \* kind[i]: what take_in makes of packet i
    gram,        \* the kind of the packet the fragments make
    fate,        \* fate[i]: where packet i is
    up,          \* IpLayer::up: [what, ids, t]
    answer,      \* IpLayer::answer: the packet it answers, or NoAnswer
    down,        \* IpLayer::down: None, "send" or "end"
    issued,      \* how many sends the transports gave on_command
    inputClosed, \* IpLayer::input_closed
    outputClosed,\* IpLayer::output_closed
    handed,      \* handed[i]: how many times packet i went up
    handedTo,    \* handedTo[i]: where it went
    owed,        \* packets whose answer take_in made
    answered,    \* packets whose answer went down
    endBelow,    \* the end went down
    sendAfterEnd,\* a packet went down after the end
    endedUp,     \* how many ends went up
    afterEnded   \* a packet went up after the end

vars == <<kind, gram, fate, up, answer, down, issued, inputClosed, outputClosed,
          handed, handedTo, owed, answered, endBelow, sendAfterEnd, endedUp,
          afterEnded>>

Empty == [what |-> None, ids |-> {}, t |-> None]

Init ==
    /\ kind \in [Ids -> Kinds]
    /\ gram \in GramKinds
    /\ fate = [i \in Ids |-> "new"]
    /\ up = Empty
    /\ answer = NoAnswer
    /\ down = None
    /\ issued = 0
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

Fixed == <<kind, gram>>
Below == <<down, issued, outputClosed, answered, endBelow, sendAfterEnd>>
Above == <<handed, handedTo, endedUp, afterEnded>>

\* IpLayer::take_in, on a layer with room.
TakeIn(i) ==
    CASE kind[i] \in Whole ->
            /\ up' = [what |-> "packet", ids |-> {i}, t |-> Dest(kind[i])]
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
            /\ up' = [what |-> "packet", ids |-> parts, t |-> Dest(gram)]
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
    /\ UNCHANGED <<Fixed, inputClosed>>
    /\ UNCHANGED Below
    /\ UNCHANGED Above

\* IpLayer::on_event with the end, when the layer has room.
OfferEnd ==
    /\ ~inputClosed /\ up.what = None /\ answer = NoAnswer
    /\ inputClosed' = TRUE
    /\ up' = [what |-> "ended", ids |-> {}, t |-> None]
    /\ UNCHANGED <<Fixed, fate, answer, owed>>
    /\ UNCHANGED Below
    /\ UNCHANGED Above

\* IpLayer::on_timer: Reassembly::expire drops the waiting fragments.
Timer ==
    /\ \E j \in Ids : fate[j] = "waiting"
    /\ fate' = [j \in Ids |-> IF fate[j] = "waiting" THEN "expired" ELSE fate[j]]
    /\ UNCHANGED <<Fixed, up, answer, inputClosed, owed>>
    /\ UNCHANGED Below
    /\ UNCHANGED Above

\* IpLayer::take_event: the endpoint takes what is up.
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
    /\ UNCHANGED <<Fixed, answer, inputClosed, owed>>
    /\ UNCHANGED Below

\* IpLayer::on_command: a transport sends a packet or the end.
Command(c) ==
    /\ ~outputClosed /\ down = None
    /\ c = "send" => issued < MaxSends
    /\ down' = c
    /\ issued' = IF c = "send" THEN issued + 1 ELSE issued
    /\ outputClosed' = (c = "end")
    /\ UNCHANGED <<Fixed, fate, up, answer, inputClosed, owed>>
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
    /\ UNCHANGED <<Fixed, fate, up, issued, inputClosed, outputClosed, owed>>
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

\* No packet goes up twice, and each goes where it was sorted.
ExactlyOnce ==
    \A i \in Ids :
        /\ handed[i] <= 1
        /\ handed[i] = 1 /\ kind[i] \in Whole => handedTo[i] = Dest(kind[i])

\* An answer take_in made waits or has gone down: none is overwritten.
AnswersKept == \A i \in owed : answer = i \/ i \in answered

\* Nothing goes down after the end.
NoSendAfterEnd == ~sendAfterEnd

\* The end goes up once, after every packet.
EndedOnce == endedUp <= 1 /\ ~afterEnded

-----------------------------------------------------------------------------
\* The refinement: RFC 1122 sections 3.2.1 and 3.2.2 and RFC 8200's answer
\* (RfcIpInput.tla). A packet is taken once on_event took it in; it went
\* up when the endpoint took it from the up slot; the transports' sends
\* that went down are those issued less one still in the down slot.
Rfc == INSTANCE RfcIpInput WITH
    taken <- {i \in Ids : fate[i] \notin {"new", "held"}},
    upCount <- handed,
    upTo <- handedTo,
    expired <- {i \in Ids : fate[i] = "expired"},
    sent <- issued - (IF down = "send" THEN 1 ELSE 0),
    inputEnded <- inputClosed,
    endedDown <- endBelow

RfcSpec == Rfc!Spec

\* Throwaway invariants for the witness config: each fails, which shows
\* the case it names is reached.
NoReassembledError == \A i \in Ids : ~(kind[i] = "done" /\ gram = "errudp" /\ handed[i] = 1)
NoAnswerSent == answered = {}
=============================================================================
