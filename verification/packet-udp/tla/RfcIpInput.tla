----------------------------- MODULE RfcIpInput -----------------------------
(* What the RFCs ask of a host's IP input, written without the code's slots.
   Dispatch.tla refines it.

   RFC 1122 section 3.2.1: a host takes datagrams from the link and passes
   each valid one to the protocol its header names (3.2.1.1-3.2.1.8 list
   what makes one invalid, which is silently discarded). Section 3.2.1.4: a
   fragmented datagram goes up once, after reassembly; reassembly of one
   that does not complete in time is abandoned (RFC 791 section 3.2, and
   RfcReassembly.tla for the reassembly itself). Section 3.2.2: an ICMP
   error message is passed up to the transport protocol whose packet it
   quotes (3.2.2.1 for Destination Unreachable, and 4.1.3.3 and 4.2.3.9 say
   UDP and TCP take them); other ICMP messages go to ICMP. RFC 8200 section
   4 and RFC 4443 section 3.4: a packet refused for its extension headers
   gets at most one ICMPv6 Parameter Problem back, and only where the RFC
   asks for one. A packet is never sent after the output's end, and nothing
   goes up after the input's end has.

   What each packet is (its kind) is fixed per packet, as in Dispatch.tla:
   a whole datagram for TCP, UDP or ICMP, an ICMP error quoting a TCP or
   UDP packet, a packet refused with an answer or without one, a fragment
   that waits, or a fragment that completes a datagram, whose kind is
   `gram`. A datagram here is a set of packet ids: one whole packet, or the
   fragments that completed one. *)
EXTENDS Naturals, FiniteSets

CONSTANTS Ids

Targets == {"tcp", "udp", "icmp"}
Whole == {"tcp", "udp", "icmp", "errtcp", "errudp"}
None == "none"

\* The protocol a valid datagram of kind k goes to.
Target(k) ==
    CASE k = "tcp" -> "tcp"
      [] k = "udp" -> "udp"
      [] k = "icmp" -> "icmp"
      [] k = "errtcp" -> "tcp"
      [] k = "errudp" -> "udp"

VARIABLES
    kind,       \* kind[i]: what packet i is
    gram,       \* the kind of datagram the fragments make
    taken,      \* packets the host took from the link
    upCount,    \* upCount[i]: how many times packet i went up
    upTo,       \* upTo[i]: the protocol it went to
    expired,    \* fragments whose reassembly was abandoned
    answered,   \* refused packets whose answer went back
    sent,       \* packets the transports sent that went down
    inputEnded, \* the link's end arrived
    endedUp,    \* how many times the end went up
    endedDown   \* the output's end went down

vars == <<kind, gram, taken, upCount, upTo, expired, answered, sent,
          inputEnded, endedUp, endedDown>>

Init ==
    /\ kind \in [Ids -> Whole \cup {"answered", "silent", "wait", "done"}]
    /\ gram \in Whole
    /\ taken = {}
    /\ upCount = [i \in Ids |-> 0]
    /\ upTo = [i \in Ids |-> None]
    /\ expired = {}
    /\ answered = {}
    /\ sent = 0
    /\ inputEnded = FALSE
    /\ endedUp = 0
    /\ endedDown = FALSE

Fixed == <<kind, gram>>

\* The host takes packet i from the link, before the link's end.
Take(i) ==
    /\ i \notin taken /\ ~inputEnded
    /\ taken' = taken \cup {i}
    /\ UNCHANGED <<Fixed, upCount, upTo, expired, answered, sent, inputEnded, endedUp, endedDown>>

\* Datagram D goes up to protocol t, once, before the end goes up: a whole
\* packet to the protocol it names, or the fragments that completed one,
\* none abandoned.
IsDatagram(D, t) ==
    \/ \E i \in D : D = {i} /\ kind[i] \in Whole /\ t = Target(kind[i])
    \/ \E d \in D : /\ kind[d] = "done"
                    /\ \A j \in D \ {d} : kind[j] = "wait"
                    /\ t = Target(gram)

Deliver(D, t) ==
    /\ D # {} /\ D \subseteq taken /\ D \cap expired = {}
    /\ \A i \in D : upCount[i] = 0
    /\ endedUp = 0
    /\ IsDatagram(D, t)
    /\ upCount' = [i \in Ids |-> IF i \in D THEN upCount[i] + 1 ELSE upCount[i]]
    /\ upTo' = [i \in Ids |-> IF i \in D THEN t ELSE upTo[i]]
    /\ UNCHANGED <<Fixed, taken, expired, answered, sent, inputEnded, endedUp, endedDown>>

\* Reassembly of waiting fragments is abandoned.
Expire(S) ==
    /\ S # {} /\ S \subseteq taken \ expired
    /\ \A i \in S : kind[i] = "wait" /\ upCount[i] = 0
    /\ expired' = expired \cup S
    /\ UNCHANGED <<Fixed, taken, upCount, upTo, answered, sent, inputEnded, endedUp, endedDown>>

\* The one answer a refused packet may get, before the output's end.
Answer(i) ==
    /\ i \in taken /\ kind[i] = "answered" /\ i \notin answered /\ ~endedDown
    /\ answered' = answered \cup {i}
    /\ UNCHANGED <<Fixed, taken, upCount, upTo, expired, sent, inputEnded, endedUp, endedDown>>

\* A transport's packet goes down, before the output's end.
Send ==
    /\ ~endedDown
    /\ sent' = sent + 1
    /\ UNCHANGED <<Fixed, taken, upCount, upTo, expired, answered, inputEnded, endedUp, endedDown>>

EndDown ==
    /\ ~endedDown
    /\ endedDown' = TRUE
    /\ UNCHANGED <<Fixed, taken, upCount, upTo, expired, answered, sent, inputEnded, endedUp>>

InputEnd ==
    /\ ~inputEnded
    /\ inputEnded' = TRUE
    /\ UNCHANGED <<Fixed, taken, upCount, upTo, expired, answered, sent, endedUp, endedDown>>

\* The end goes up once, after the link's end.
EndUp ==
    /\ inputEnded /\ endedUp = 0
    /\ endedUp' = 1
    /\ UNCHANGED <<Fixed, taken, upCount, upTo, expired, answered, sent, inputEnded, endedDown>>

Next ==
    \/ \E i \in Ids : Take(i) \/ Answer(i)
    \/ \E D \in SUBSET Ids, t \in Targets : Deliver(D, t)
    \/ \E S \in SUBSET Ids : Expire(S)
    \/ Send \/ EndDown \/ InputEnd \/ EndUp

Spec == Init /\ [][Next]_vars
=============================================================================
