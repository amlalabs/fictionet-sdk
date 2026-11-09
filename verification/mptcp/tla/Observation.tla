---------------------------- MODULE Observation ----------------------------
(***************************************************************************)
(* The honeypot's Observer in demos/honeypot/src/observe.rs.               *)
(*                                                                         *)
(* Spec (SYN counts and answers):                                          *)
(*   Syn        Observer::syn: recent, pending, awaited (epoch is the      *)
(*              SYN's time there, answers its count) and Source::syns      *)
(*   Tick       Observer::expire's loop over `recent` (ExpireState)        *)
(*   Answer     Observer::answered                                         *)
(*   Cleanup    Observer::expire's loop over `pending` (MatchEpoch: only   *)
(*              the entry whose time awaited still holds removes it)       *)
(*   Open/Close the contract that a route keeps nothing per source:        *)
(*              Routed::poll_recv in src/stdlib/world/net/attachments.rs   *)
(*              inserts nothing, and the test                              *)
(*              a_public_route_keeps_nothing_per_source checks it. Nothing *)
(*              in the code corresponds to LastClose.                      *)
(* SignalSpec (probe attempts), all in Observer::observe unless named:     *)
(*   SignalSyn     the incoming SYN branch: a probe per attachment and     *)
(*                 tuple with its current initial sequence; a SYN with a   *)
(*                 new one removes the tuple's probe first; a repeat of a  *)
(*                 probe with IPv4 options is an IpOptionsRetransmit, in   *)
(*                 any phase                                               *)
(*   SignalAnswer  the outgoing SYN-ACK matching the probe, before it      *)
(*                 completed                                               *)
(*   SignalAck     the ACK matching both sequences (Probe::completed)      *)
(*   SignalData    `belongs` and Probe::payload                            *)
(*   SignalClose   `closing` and Probe::report with ProbeEnd::Close        *)
(*   SignalExpire  Observer::expire's probe loop, ProbeEnd::Expired        *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences
CONSTANTS Sources, Window, MaxTime, MaxSyns, ExpireState, LastClose, MatchEpoch
VARIABLES now, recent, count, connections, routed, pending, epoch, answers
VARIABLES probes, syns, evidence, opened
vars == <<now, recent, count, connections, routed, pending, epoch, answers,
          probes, syns, evidence, opened>>
Init == /\ probes = <<>> /\ syns = 0 /\ evidence = {} /\ opened = {}
        /\ now = 0 /\ recent = <<>> /\ pending = <<>>
        /\ count = [s \in Sources |-> 0]
        /\ connections = [s \in Sources |-> 0] /\ routed = {}
        /\ epoch = [s \in Sources |-> 0] /\ answers = [s \in Sources |-> 0]
Live(s, records, t) == {i \in 1..Len(records) : records[i].src = s /\ records[i].at + Window > t}
Syn(s) ==
    /\ Len(recent) < MaxSyns /\ now < MaxTime
    /\ recent' = Append(recent, [src |-> s, at |-> now])
    /\ count' = [count EXCEPT ![s] = @ + 1]
    /\ pending' = Append(pending, [src |-> s, at |-> now])
    /\ epoch' = [epoch EXCEPT ![s] = now] /\ answers' = [answers EXCEPT ![s] = @ + 1]
    /\ UNCHANGED <<now, connections, routed>>
Tick ==
    /\ now < MaxTime /\ now' = now + 1
    /\ count' = IF ExpireState THEN [s \in Sources |-> Cardinality(Live(s, recent, now'))] ELSE count
    /\ UNCHANGED <<recent, connections, routed, pending, epoch, answers>>
Answer(s) == /\ answers[s] > 0 /\ answers' = [answers EXCEPT ![s] = @ - 1]
             /\ UNCHANGED <<now, recent, count, connections, routed, pending, epoch>>
Cleanup ==
    /\ Len(pending) > 0
    /\ LET p == Head(pending) IN
        /\ p.at + Window <= now \/ p.at # epoch[p.src]
        /\ answers' = IF (p.at = epoch[p.src] \/ ~MatchEpoch)
                      THEN [answers EXCEPT ![p.src] = 0] ELSE answers
    /\ pending' = Tail(pending)
    /\ UNCHANGED <<now, recent, count, connections, routed, epoch>>
Open(s) == /\ connections[s] < 2 /\ connections' = [connections EXCEPT ![s] = @ + 1]
           /\ routed' = routed \cup {s}
           /\ UNCHANGED <<now, recent, count, pending, epoch, answers>>
Close(s) == /\ connections[s] > 0 /\ connections' = [connections EXCEPT ![s] = @ - 1]
            /\ routed' = IF connections[s] = 1 /\ LastClose THEN routed \ {s} ELSE routed
            /\ UNCHANGED <<now, recent, count, pending, epoch, answers>>
Next == /\ Tick \/ Cleanup \/ (\E s \in Sources : Syn(s) \/ Answer(s) \/ Open(s) \/ Close(s))
        /\ UNCHANGED <<probes, syns, evidence, opened>>
Spec == Init /\ [][Next]_vars
WindowExact == \A s \in Sources : count[s] = Cardinality(Live(s, recent, now))
RoutedExact == routed = {s \in Sources : connections[s] > 0}
FreshAnswerPreserved == [][Cleanup => \A s \in Sources : epoch[s] + Window > now => answers'[s] = answers[s]]_vars

\* The signal sub-specification shares the same source, time and SYN bounds.
\* A source abstracts an attachment and endpoint tuple; the sequence is separate.
ProbeKeys == Sources \X (0..1)
EmptyProbe == [phase |-> "absent", sequence |-> 0, at |-> 0,
               initial |-> FALSE, capable |-> FALSE, payload |-> FALSE,
               server |-> -1, repeats |-> 0]
SignalInit == /\ now = 0 /\ syns = 0 /\ evidence = {} /\ opened = {}
              /\ probes = [k \in ProbeKeys |-> EmptyProbe]
              /\ recent = <<>> /\ pending = <<>> /\ routed = {}
              /\ count = [s \in Sources |-> 0]
              /\ connections = [s \in Sources |-> 0]
              /\ epoch = [s \in Sources |-> 0] /\ answers = [s \in Sources |-> 0]
LiveProbe(p) == p.phase # "absent" /\ p.at + Window > now
SignalSyn(s, sequence, options, capable, payload) ==
    /\ syns < MaxSyns /\ now < MaxTime
    /\ LET k == <<s, sequence>>
           p == probes[k]
           repeated == LiveProbe(p)
           \* The code keeps one probe per tuple, with its current initial
           \* sequence: a SYN with another one removes that probe first,
           \* with no report, whether or not the new SYN starts a probe.
           other == <<s, 1 - sequence>>
       IN /\ p.phase = "absent" \/ repeated
          /\ probes' = [q \in ProbeKeys |->
               IF q = k THEN
                   IF repeated THEN IF p.phase = "pending"
                        THEN [p EXCEPT !.repeats = @ + 1, !.payload = (@ \/ payload)]
                        ELSE [p EXCEPT !.payload = (@ \/ payload)]
                   ELSE IF options \/ capable
                        THEN [EmptyProbe EXCEPT !.phase = "pending", !.sequence = sequence,
                              !.at = now, !.initial = options, !.capable = capable, !.payload = payload]
                        ELSE p
               ELSE IF q = other /\ ~repeated /\ LiveProbe(probes[q]) THEN EmptyProbe
               ELSE probes[q]]
          /\ evidence' = IF repeated /\ p.initial
              THEN evidence \cup {[kind |-> "trigger", initial |-> p.initial,
                   previous |-> p.sequence, sequence |-> sequence, live |-> LiveProbe(p),
                   pending |-> p.phase = "pending", capable |-> p.capable,
                   payload |-> p.payload]} ELSE evidence
    /\ syns' = syns + 1
    /\ UNCHANGED <<now, opened>>
SignalAnswer(s, server) ==
    /\ LiveProbe(probes[s]) /\ probes[s].phase = "pending"
    /\ probes' = [probes EXCEPT ![s].server = server]
    /\ UNCHANGED <<now, syns, evidence, opened>>
SignalAck(s, sequence, acknowledgement, payload) ==
    /\ LiveProbe(probes[s]) /\ probes[s].phase = "pending" /\ probes[s].server # -1
    /\ sequence = probes[s].sequence + 1 /\ acknowledgement = probes[s].server + 1
    /\ probes' = [probes EXCEPT ![s].phase = "open", ![s].payload = (@ \/ payload)]
    /\ opened' = opened \cup {[sequence |-> sequence, expected |-> probes[s].sequence + 1,
                                 acknowledgement |-> acknowledgement, server |-> probes[s].server]}
    /\ UNCHANGED <<now, syns, evidence>>
Matches(k, s, sequence) == k[1] = s /\ LiveProbe(probes[k]) /\
    (probes[k].phase = "open" \/ sequence = probes[k].sequence + 1)
SignalData(s, sequence) ==
    /\ \E k \in ProbeKeys : Matches(k, s, sequence) /\ ~probes[k].payload
    /\ probes' = [k \in ProbeKeys |-> IF Matches(k, s, sequence)
                       THEN [probes[k] EXCEPT !.payload = TRUE] ELSE probes[k]]
    /\ UNCHANGED <<now, syns, evidence, opened>>
NoData(p) == [kind |-> "no_data", initial |-> p.initial, previous |-> p.sequence,
             sequence |-> p.sequence, live |-> LiveProbe(p), pending |-> p.phase = "pending",
             capable |-> p.capable, payload |-> p.payload]
SignalClose(s, sequence) ==
    /\ LiveProbe(probes[s])
    /\ probes[s].phase = "open" \/ sequence = probes[s].sequence + 1
    /\ evidence' = IF probes[s].capable /\ ~probes[s].payload
                    THEN evidence \cup {NoData(probes[s])} ELSE evidence
    /\ probes' = [probes EXCEPT ![s] = EmptyProbe]
    /\ UNCHANGED <<now, syns, opened>>
SignalExpire(s) ==
    /\ probes[s].phase # "absent" /\ probes[s].at + Window <= now
    /\ evidence' = IF probes[s].capable /\ ~probes[s].payload
                    THEN evidence \cup {NoData(probes[s])} ELSE evidence
    /\ probes' = [probes EXCEPT ![s] = EmptyProbe]
    /\ UNCHANGED <<now, syns, opened>>
SignalTick == /\ now < MaxTime /\ now' = now + 1
              /\ UNCHANGED <<probes, syns, evidence, opened>>
SignalNext ==
    /\ SignalTick \/
        (\E k \in ProbeKeys : SignalExpire(k) \/
          (\E sequence \in 0..2 : SignalClose(k, sequence)) \/
          (\E server \in 0..1 : SignalAnswer(k, server)) \/
          (\E sequence \in 0..2, acknowledgement \in 0..2, payload \in BOOLEAN :
            SignalAck(k, sequence, acknowledgement, payload))) \/
        (\E s \in Sources, sequence \in 0..2 : SignalData(s, sequence)) \/
        (\E s \in Sources, sequence \in 0..1, options \in BOOLEAN, capable \in BOOLEAN,
            payload \in BOOLEAN : SignalSyn(s, sequence, options, capable, payload))
    /\ UNCHANGED <<recent, count, connections, routed, pending, epoch, answers>>
SignalSpec == SignalInit /\ [][SignalNext]_vars
TriggerEvidence == \A event \in evidence : event.kind = "trigger" =>
    event.initial /\ event.previous = event.sequence /\ event.live
NoDataEvidence == \A event \in evidence : event.kind = "no_data" =>
    event.capable /\ ~event.payload
HandshakeEvidence == \A event \in opened :
    event.sequence = event.expected /\
    event.acknowledgement = event.server + 1
RepeatedSynKeepsInitial == [][\A s \in ProbeKeys :
    probes[s].phase = "pending" /\ probes'[s].repeats > probes[s].repeats =>
    probes'[s].initial = probes[s].initial /\ probes'[s].at = probes[s].at]_vars
OtherAttemptsPreserved == [][
    syns < MaxSyns /\ now < MaxTime /\ syns' = syns + 1 =>
    \A s \in Sources, sequence \in 0..1,
    options \in BOOLEAN, capable \in BOOLEAN, payload \in BOOLEAN :
    SignalSyn(s, sequence, options, capable, payload) =>
    \A k \in ProbeKeys \ {<<s, sequence>>} :
        probes'[k] = probes[k] \/ (k[1] = s /\ probes'[k] = EmptyProbe)]_vars
CompletedSynNotReopened == [][
    syns < MaxSyns /\ now < MaxTime /\ syns' = syns + 1 =>
    \A s \in Sources, sequence \in 0..1,
    options \in BOOLEAN, capable \in BOOLEAN, payload \in BOOLEAN :
    SignalSyn(s, sequence, options, capable, payload) /\ LiveProbe(probes[<<s, sequence>>]) /\
    probes[<<s, sequence>>].phase = "open" =>
    probes'[<<s, sequence>>] = [probes[<<s, sequence>>] EXCEPT !.payload = (@ \/ payload)]]_vars
=============================================================================
