---------------------------- MODULE Observation ----------------------------
EXTENDS Naturals, FiniteSets, Sequences
CONSTANTS Sources, Window, MaxTime, MaxSyns, ExpireState, LastClose, MatchEpoch
VARIABLES now, recent, count, connections, routed, pending, epoch, answers
vars == <<now, recent, count, connections, routed, pending, epoch, answers>>
Init == /\ now = 0 /\ recent = <<>> /\ pending = <<>>
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
Next == Tick \/ Cleanup \/ (\E s \in Sources : Syn(s) \/ Answer(s) \/ Open(s) \/ Close(s))
Spec == Init /\ [][Next]_vars
WindowExact == \A s \in Sources : count[s] = Cardinality(Live(s, recent, now))
RoutedExact == routed = {s \in Sources : connections[s] > 0}
FreshAnswerPreserved == [][Cleanup => \A s \in Sources : epoch[s] + Window > now => answers'[s] = answers[s]]_vars
=============================================================================
