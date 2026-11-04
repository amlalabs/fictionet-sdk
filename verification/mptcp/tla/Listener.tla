----------------------------- MODULE Listener -----------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Peers, Backlog, ReuseSyn, CheckCookie, KeepTimeWait, BoundQueue
VARIABLES embryos, ready, active, waiting, cookie, forged, duplicate
vars == <<embryos, ready, active, waiting, cookie, forged, duplicate>>
Init == /\ embryos = {} /\ ready = {} /\ active = {} /\ waiting = {}
        /\ cookie = {} /\ forged = FALSE /\ duplicate = FALSE
Syn(p) ==
    /\ p \notin ready \cup active
    /\ p \notin waiting \/ ~KeepTimeWait
    /\ LET full == Cardinality(embryos \cup ready) >= Backlog
       IN /\ embryos' = IF full \/ p \in waiting THEN embryos ELSE embryos \cup {p}
          /\ cookie' = IF full THEN cookie \cup {p} ELSE cookie
    /\ duplicate' = (duplicate \/ (p \in embryos /\ ~ReuseSyn))
    /\ active' = IF p \in waiting THEN active \cup {p} ELSE active
    /\ UNCHANGED <<ready, waiting, forged>>
Ack(p, valid) ==
    /\ p \notin active \cup waiting \cup ready
    /\ p \in embryos \/ (p \in cookie /\ valid) \/ ~CheckCookie
    /\ Cardinality(ready) < Backlog \/ ~BoundQueue
    /\ ready' = ready \cup {p} /\ embryos' = embryos \ {p}
    /\ forged' = (forged \/ (p \notin embryos /\ (p \notin cookie \/ ~valid)))
    /\ UNCHANGED <<active, waiting, cookie, duplicate>>
Accept(p) == /\ p \in ready /\ ready' = ready \ {p} /\ active' = active \cup {p}
             /\ UNCHANGED <<embryos, waiting, cookie, forged, duplicate>>
Close(p) == /\ p \in active /\ active' = active \ {p} /\ waiting' = waiting \cup {p}
            /\ UNCHANGED <<embryos, ready, cookie, forged, duplicate>>
Expire(p) == /\ p \in embryos \cup waiting
             /\ embryos' = embryos \ {p} /\ waiting' = waiting \ {p}
             /\ UNCHANGED <<ready, active, cookie, forged, duplicate>>
Next == (\E p \in Peers : Syn(p) \/ Accept(p) \/ Close(p) \/ Expire(p))
        \/ (\E p \in Peers, v \in BOOLEAN : Ack(p, v))
Spec == Init /\ [][Next]_vars
BoundedBacklog == Cardinality(ready) <= Backlog
NoForgedCookie == ~forged
RepeatedSynReuses == ~duplicate
TimeWaitIsolated == active \cap waiting = {}
=============================================================================
