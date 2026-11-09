----------------------------- MODULE Listener -----------------------------
(***************************************************************************)
(* One listening port of TcpLayer in src/stdlib/network/tcp/engine.rs,     *)
(* three peer tuples at a time.                                            *)
(*                                                                         *)
(*   Syn     ingress and attempt: a SYN for a tuple no connection has is   *)
(*           kept in `embryonic` while embryonic and ready together are    *)
(*           under the backlog, and answered with a SYN cookie from the    *)
(*           configured codec otherwise. ReuseSyn: a SYN for a tuple in    *)
(*           by_tuple goes to that handshake's socket, which sends its     *)
(*           SYN-ACK again. KeepTimeWait: the same for a tuple whose       *)
(*           connection is in TIME-WAIT, where smoltcp answers with a      *)
(*           challenge ACK.                                                *)
(*   Ack     completed, for a kept handshake, and take_cookie, for an ACK  *)
(*           that returns a cookie. CheckCookie: SynCookies::validate.     *)
(*           BoundQueue: while `ready` is full, take_cookie refuses an ACK *)
(*           that returns a cookie, and ingress drops one that would       *)
(*           complete a kept handshake, which stays in SYN-RECEIVED.       *)
(*   Accept  offer, on TcpControl::Accept                                  *)
(*   Close   housekeeping retiring an orphan in TIME-WAIT                  *)
(*   Expire  expire_handshakes; smoltcp's TIME-WAIT timer and              *)
(*           housekeeping's removal of the closed socket, or its           *)
(*           MAX_TIME_WAIT eviction                                        *)
(***************************************************************************)
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
    \* While ready is full, an ACK that returns a cookie is refused
    \* (take_cookie) and one completing a kept handshake is dropped
    \* (ingress); the kept handshake stays in embryos.
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
