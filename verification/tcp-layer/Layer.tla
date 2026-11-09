------------------------------- MODULE Layer -------------------------------
(***************************************************************************)
(* TcpLayer (src/stdlib/network/tcp/engine.rs) as the layer above sees it  *)
(* through the Tcp port of src/stdlib/network/transport.rs: the children   *)
(* it opens, what TcpControl::Hold keeps, TcpNotice::Gone, Abort, Accept,  *)
(* and the timers each connection arms.  The host above is a process that *)
(* only sends TcpControl commands and child commands, and only reads what *)
(* comes up: the boundary a replacement TCP implements.                    *)
(*                                                                         *)
(* Connections are of two kinds.  `Accepted` ones come from peers to one   *)
(* listening port; `Connected` ones are TcpControl::Connect from the host. *)
(*                                                                         *)
(* Model                     engine.rs (lines at e2858ccc4)                *)
(*   Syn                      attempt 1378, ingress 1328-1368               *)
(*   FinalAck                 completed 1619 (AckAnswer 1644-1678)          *)
(*   EmbryoRst                ingress 1311-1317, Listen::relisten 411      *)
(*   HandshakeExpires         expire_handshakes 1688                        *)
(*   Offer                    offer 1910, open_child 1890                   *)
(*   HostAccept               control, TcpControl::Accept 2158             *)
(*   HostConnect              connect 2067 (open_child at once, 2106)      *)
(*   SynAck, ConnectFails     smoltcp, then refresh 1963 / connect_failed  *)
(*                            2035                                          *)
(*   HostHold, HostAbort      control, TcpControl::Hold 2191, Abort 2174   *)
(*   HostClose, HostEnd       on_command MuxOp::Close 2514 -> orphan 924;  *)
(*                            StreamCommand::End 2495 -> close_if_drained  *)
(*                            891                                           *)
(*   HostRead                 MuxOp::Credit 2507 -> refresh (data comes up)*)
(*   HostKeepAlive            control, TcpControl::KeepAlive 2181          *)
(*   PeerData/Fin/AckFin/Rst  ingress after smoltcp's process, 1258-1307   *)
(*   Timeout, Egress,         smoltcp's own timer (dispatch), the RST of   *)
(*   TimeWaitExpires          an aborted socket going out, TIME-WAIT's end *)
(*   Release                  refresh 1979-1985 (Conn::released)            *)
(*   Housekeeping             housekeeping 1807-1835                        *)
(*   ArmOrphan, ClearOrphan,  expire_orphans 1720-1741                      *)
(*   OrphanExpires                                                          *)
(*   EvictTimeWait            housekeeping 1836-1843                        *)
(*   Stop                     stop 1852                                     *)
(*   Gone(c)                  gone 2363                                     *)
(*                                                                         *)
(* Segment validation, sequence numbers, windows and retransmission are    *)
(* smoltcp's: a peer event is one smoltcp accepted.  SYN cookies, the      *)
(* per-peer limit and the listener's SYN answer are left out: they decide  *)
(* whether a handshake starts, not what follows.  A SYN the code answers   *)
(* with a cookie (attempt 1408) is a Syn the model refuses.  The cookie    *)
(* path once let `ready` pass the backlog (a cookie's ACK was admitted     *)
(* while `ready` alone had room, and the kept handshakes completed with no *)
(* check); ingress now drops an ACK that would complete a kept handshake   *)
(* while `ready` is full, and verification/mptcp/tla/Listener.tla, which   *)
(* has the cookie path, checks BoundedBacklog.  Not modeled either: the    *)
(* UP_ROOM                                                                  *)
(* check that makes `offer` return early (1912), and End on a child whose  *)
(* socket is not yet open (close_if_drained in SYN-SENT).  Bytes are       *)
(* booleans.                                                               *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
  Accepted, Connected,  \* the connections of each kind
  Backlog,              \* the listener's backlog
  MaxGrants,            \* how many TcpControl::Accept the host may send
  \* Each TRUE for the code.  FALSE keeps a rule as it was, or weakens it.
  ReleaseOpen,          \* Release exists: gone while the child is open
  GoneGuards,           \* Hold and Abort ask gone(), not only `retired`
  StopReleases,         \* stop() releases what every connection held
  ClearOrphanTimer,     \* expire_orphans clears gives_up off FIN-WAIT-2
  CountAccepts,         \* offer uses up one Accept per child
  LiveAfterHandshake,   \* a connecting child carries bytes only once open
  CountUntilGone,       \* closing a child leaves what it held alone
  ResetReleases,        \* abort and connect_failed release what was held
  OfferReady,           \* offer takes only what finished its handshake
  BoundBacklog,         \* a SYN past the backlog starts no connection
  SayGone,              \* Release says TcpNotice::Gone
  OfferSaysGone         \* a child opened for a reset connection is told

Conns == Accepted \cup Connected

Socks == {"None", "SynSent", "SynRcvd", "Est", "CloseWait", "FinWait1",
          "FinWait2", "Closing", "LastAck", "TimeWait", "Closed"}
Writable == {"Est", "CloseWait"}
\* smoltcp's waits_for_answer, without the keepalive cases.
WaitsForAnswer == {"SynSent", "SynRcvd", "FinWait1", "Closing", "LastAck"}

VARIABLES
  conn,     \* per connection, the record below
  granted,  \* TcpControl::Accept counts the host sent
  credits,  \* Listen::accept: how many more children the listener opens
  stopped   \* TcpLayer::stopped

vars == <<conn, granted, credits, stopped>>

(* Per connection:
   sock      the smoltcp state ("None": no socket yet)
   at        "none" | "embryonic" | "ready" | "conn" | "removed": the
             listener's queues, a connection in `conns`, or gone from it
   child     "none" | "open" | "closed": never opened, held by the host,
             closed by the host (or by the layer, for a failed connect)
   mapped    the child is in `children`: TcpLayer::mapped
   live      Conn::live: the child's stream carries bytes
   credited  the layer granted the child send credit
   wasOpen   the socket reached ESTABLISHED (or later)
   accepted  the listener's answer took the final ACK
   rx        bytes wait unread
   rst, retired, released, orphaned   the Conn flags
   endpoint  smoltcp still names the peer: a RST is still to go out
   held      Conn::held is not empty
   kept      the host's Hold was kept (not dropped as gone)
   said      TcpNotice::Gone went up for its child
   keepAlive, timeout   the socket's keepalive and timeout are set
   givesUp   Conn::gives_up for an orphan: "none" | "armed"          *)
Fresh == [sock |-> "None", at |-> "none", child |-> "none", mapped |-> FALSE,
          live |-> FALSE, credited |-> FALSE, wasOpen |-> FALSE,
          accepted |-> FALSE, rx |-> FALSE, rst |-> FALSE, retired |-> FALSE,
          released |-> FALSE, orphaned |-> FALSE, endpoint |-> FALSE,
          held |-> FALSE, kept |-> FALSE, said |-> FALSE,
          keepAlive |-> TRUE, timeout |-> TRUE, givesUp |-> "none"]

Init ==
  /\ conn = [c \in Conns |-> Fresh]
  /\ granted = 0 /\ credits = 0 /\ stopped = FALSE

\* TcpLayer::gone for the child of c.
Gone(c) == stopped \/ ~conn[c].mapped \/ conn[c].at = "removed"
           \/ conn[c].rst \/ conn[c].retired \/ conn[c].released

InQueue(q) == {c \in Accepted : conn[c].at = q}

\* Set fields of c's record.
Set(c, r) == conn' = [conn EXCEPT ![c] = r]

\* remove_conn: the Conn goes with what it held; a mapped child is
\* removed from `children` and named in TcpNotice::Gone.
Removed(r) == [r EXCEPT !.at = "removed", !.held = FALSE, !.mapped = FALSE,
                        !.said = r.said \/ r.mapped, !.givesUp = "none"]

\* abort: a RST to go, the Reset event, and Gone for a mapped child.
\* With ResetReleases FALSE, what it held stays until the Conn goes.
Aborted(r) == [r EXCEPT !.sock = "Closed", !.rst = TRUE,
                        !.endpoint = r.sock # "None",
                        !.held = r.held /\ ~ResetReleases,
                        !.said = r.said \/ r.mapped]

\* smoltcp's close: the FIN.
Fin(s) == CASE s = "Est" -> "FinWait1" [] s = "CloseWait" -> "LastAck"
               [] s = "SynSent" -> "Closed" [] OTHER -> s

-----------------------------------------------------------------------------
\* The listener.  With BoundBacklog FALSE a SYN starts a connection
\* however many wait.
Syn(c) ==
  /\ ~stopped /\ c \in Accepted /\ conn[c].sock = "None"
  /\ BoundBacklog =>
       /\ Cardinality(InQueue("ready")) < Backlog
       /\ Cardinality(InQueue("embryonic")) + Cardinality(InQueue("ready")) < Backlog
  /\ Set(c, [conn[c] EXCEPT !.sock = "SynRcvd", !.at = "embryonic"])
  /\ UNCHANGED <<granted, credits, stopped>>

\* The ACK that completes the handshake; the listener's Answer::ack takes
\* it, refuses it with a RST, or drops it.  Either of the last two forgets
\* the connection at once.
FinalAck(c) ==
  /\ ~stopped /\ conn[c].at = "embryonic" /\ conn[c].sock = "SynRcvd"
  /\ \/ Set(c, [conn[c] EXCEPT !.sock = "Est", !.at = "ready",
                                !.accepted = TRUE, !.wasOpen = TRUE])
     \/ Set(c, [conn[c] EXCEPT !.sock = "Closed", !.at = "removed"])
  /\ UNCHANGED <<granted, credits, stopped>>

\* A RST in SYN-RECEIVED puts the socket back to LISTEN; the connection
\* is forgotten.
EmbryoRst(c) ==
  /\ ~stopped /\ conn[c].at = "embryonic"
  /\ Set(c, [conn[c] EXCEPT !.sock = "Closed", !.at = "removed"])
  /\ UNCHANGED <<granted, credits, stopped>>

HandshakeExpires(c) ==
  /\ conn[c].at = "embryonic" /\ conn[c].sock = "SynRcvd"
  /\ Set(c, [conn[c] EXCEPT !.sock = "Closed", !.at = "removed"])
  /\ UNCHANGED <<granted, credits, stopped>>

\* offer: a connection from the ready queue opens a child, using up one
\* Accept, and the child may write at once.  One the peer reset while it
\* waited opens gone, and Gone goes up with it.  With OfferReady FALSE it
\* also takes one still waiting for the final ACK.
Offer(c) ==
  /\ ~stopped /\ credits > 0
  /\ \/ conn[c].at = "ready"
     \/ ~OfferReady /\ conn[c].at = "embryonic"
  /\ Set(c, [conn[c] EXCEPT !.at = "conn", !.child = "open", !.mapped = TRUE,
                            !.live = TRUE,
                            !.credited = conn[c].sock \in Writable,
                            !.said = OfferSaysGone /\ conn[c].rst])
  /\ credits' = IF CountAccepts THEN credits - 1 ELSE credits
  /\ UNCHANGED <<granted, stopped>>

-----------------------------------------------------------------------------
\* The host, through the port.
HostAccept ==
  /\ granted < MaxGrants
  /\ granted' = granted + 1 /\ credits' = credits + 1
  /\ UNCHANGED <<conn, stopped>>

\* connect: the child opens at once, before the handshake.
HostConnect(c) ==
  /\ ~stopped /\ c \in Connected /\ conn[c].sock = "None"
  /\ Set(c, [conn[c] EXCEPT !.sock = "SynSent", !.at = "conn", !.child = "open",
                            !.mapped = TRUE, !.live = ~LiveAfterHandshake])
  /\ UNCHANGED <<granted, credits, stopped>>

\* Hold: kept unless the connection is gone.  The host may hold through a
\* GoneWatch after it closed the child, as hosts.rs does.
HostHold(c) ==
  /\ conn[c].child # "none" /\ ~conn[c].kept
  /\ LET keep == IF GoneGuards THEN ~Gone(c)
                 ELSE conn[c].mapped /\ conn[c].at = "conn" /\ ~conn[c].retired
     IN Set(c, [conn[c] EXCEPT !.held = keep, !.kept = keep])
  /\ UNCHANGED <<granted, credits, stopped>>

\* Abort: a reset, while the connection is not gone.
HostAbort(c) ==
  /\ conn[c].child # "none"
  /\ LET act == IF GoneGuards THEN ~Gone(c)
                ELSE conn[c].mapped /\ conn[c].at = "conn" /\ ~conn[c].retired
     IN IF act THEN Set(c, Aborted(conn[c])) ELSE UNCHANGED conn
  /\ UNCHANGED <<granted, credits, stopped>>

\* Close: orphan.  Unread bytes reset the connection; otherwise the FIN
\* follows.  Keepalives stop and the orphan timeout applies.
HostClose(c) ==
  /\ conn[c].child = "open"
  /\ LET r0 == [conn[c] EXCEPT !.child = "closed", !.keepAlive = FALSE,
                               !.orphaned = ~stopped,
                               !.held = IF CountUntilGone THEN conn[c].held
                                        ELSE FALSE]
         r1 == IF stopped THEN Removed(r0)
               ELSE IF conn[c].rx THEN Aborted(r0)
               ELSE [r0 EXCEPT !.sock = Fin(conn[c].sock)]
     IN Set(c, r1)
  /\ UNCHANGED <<granted, credits, stopped>>

HostEnd(c) ==
  /\ ~stopped /\ conn[c].child = "open" /\ conn[c].sock \in Writable
  /\ Set(c, [conn[c] EXCEPT !.sock = Fin(conn[c].sock)])
  /\ UNCHANGED <<granted, credits, stopped>>

HostRead(c) ==
  /\ conn[c].child = "open" /\ conn[c].live /\ conn[c].rx
  /\ Set(c, [conn[c] EXCEPT !.rx = FALSE])
  /\ UNCHANGED <<granted, credits, stopped>>

\* KeepAlive: refused for an orphan; a child must be mapped.
HostKeepAlive(c) ==
  /\ conn[c].mapped /\ ~conn[c].orphaned /\ conn[c].at = "conn"
  /\ conn[c].keepAlive = FALSE
  /\ Set(c, [conn[c] EXCEPT !.keepAlive = TRUE])
  /\ UNCHANGED <<granted, credits, stopped>>

-----------------------------------------------------------------------------
\* The peer, for an established or connecting connection.
Peerable(c) == ~stopped /\ conn[c].at \in {"ready", "conn"}

\* The SYN-ACK: the connect is open; refresh makes the child live and
\* grants credit.
SynAck(c) ==
  /\ Peerable(c) /\ conn[c].sock = "SynSent"
  /\ Set(c, [conn[c] EXCEPT !.sock = "Est", !.wasOpen = TRUE,
                            !.live = conn[c].child = "open" \/ conn[c].live,
                            !.credited = conn[c].child = "open"])
  /\ UNCHANGED <<granted, credits, stopped>>

\* refresh finds the socket of a connecting child closed (a RST, an ICMP
\* error or its timeout): connect_failed closes the child, unmaps it and
\* orphans the socket.
ConnectFails(c) ==
  /\ ~stopped /\ conn[c].at = "conn" /\ conn[c].sock = "Closed"
  /\ conn[c].child = "open" /\ ~conn[c].live
  /\ Set(c, [conn[c] EXCEPT !.child = "closed",
                            !.mapped = FALSE, !.orphaned = TRUE,
                            !.keepAlive = FALSE, !.endpoint = FALSE,
                            !.held = conn[c].held /\ ~ResetReleases,
                            !.said = conn[c].said \/ ResetReleases])
  /\ UNCHANGED <<granted, credits, stopped>>

PeerData(c) ==
  /\ Peerable(c) /\ conn[c].sock \in {"Est", "FinWait1", "FinWait2"}
  /\ Set(c, [conn[c] EXCEPT !.rx = TRUE])
  /\ UNCHANGED <<granted, credits, stopped>>

PeerFin(c) ==
  /\ Peerable(c) /\ conn[c].sock \in {"Est", "FinWait1", "FinWait2"}
  /\ \E acked \in BOOLEAN :
       LET s == CASE conn[c].sock = "Est" -> "CloseWait"
                  [] conn[c].sock = "FinWait1" /\ acked -> "TimeWait"
                  [] conn[c].sock = "FinWait1" -> "Closing"
                  [] OTHER -> "TimeWait"
       IN Set(c, [conn[c] EXCEPT !.sock = s])
  /\ UNCHANGED <<granted, credits, stopped>>

\* The ACK of this side's FIN.  LAST-ACK's closes the socket, which
\* ingress takes as the end of the connection: rst, held cleared, Gone.
PeerAckFin(c) ==
  /\ Peerable(c) /\ conn[c].sock \in {"FinWait1", "Closing", "LastAck"}
  /\ LET s == CASE conn[c].sock = "FinWait1" -> "FinWait2"
                [] conn[c].sock = "Closing" -> "TimeWait"
                [] OTHER -> "Closed"
         r == [conn[c] EXCEPT !.sock = s]
     IN Set(c, IF s = "Closed"
               THEN [r EXCEPT !.rst = TRUE, !.held = FALSE,
                              !.said = r.said \/ r.mapped]
               ELSE r)
  /\ UNCHANGED <<granted, credits, stopped>>

PeerRst(c) ==
  /\ Peerable(c)
  /\ conn[c].sock \in {"SynSent", "Est", "CloseWait", "FinWait1", "FinWait2",
                       "Closing", "LastAck", "TimeWait"}
  /\ Set(c, [conn[c] EXCEPT !.sock = "Closed", !.rst = TRUE, !.held = FALSE,
                            !.endpoint = FALSE, !.said = conn[c].said \/ conn[c].mapped])
  /\ UNCHANGED <<granted, credits, stopped>>

-----------------------------------------------------------------------------
\* Timers.  Which timers c has armed, as the code arms them.
Armed(c) ==
  LET r == conn[c] IN
  IF r.at \in {"none", "removed"} THEN {} ELSE
    { t \in {"handshake"} : r.at = "embryonic" }
    \cup { t \in {"timeout"} : r.timeout /\ r.at # "embryonic" /\
             (r.sock \in WaitsForAnswer \/
              (r.keepAlive /\ r.sock \in Writable \cup {"FinWait2"})) }
    \cup { t \in {"keepalive"} : r.keepAlive /\ r.at # "embryonic" /\
             r.sock \in Writable \cup {"FinWait2"} }
    \cup { t \in {"orphan"} : r.givesUp = "armed" }
    \cup { t \in {"timewait"} : r.sock = "TimeWait" }

\* smoltcp's timeout: the socket closes, with a RST to go.
Timeout(c) ==
  /\ ~stopped /\ "timeout" \in Armed(c)
  /\ Set(c, [conn[c] EXCEPT !.sock = "Closed", !.endpoint = TRUE])
  /\ UNCHANGED <<granted, credits, stopped>>

Egress(c) ==
  /\ conn[c].at \in {"ready", "conn"} /\ conn[c].sock = "Closed" /\ conn[c].endpoint
  /\ Set(c, [conn[c] EXCEPT !.endpoint = FALSE])
  /\ UNCHANGED <<granted, credits, stopped>>

TimeWaitExpires(c) ==
  /\ ~stopped /\ "timewait" \in Armed(c)
  /\ Set(c, [conn[c] EXCEPT !.sock = "Closed", !.endpoint = FALSE])
  /\ UNCHANGED <<granted, credits, stopped>>

\* refresh, for an open, live child: a socket that reached TIME-WAIT or
\* closed on its own lets go of what it held and is gone.  With SayGone
\* FALSE it lets go without telling the host.
Release(c) ==
  /\ ReleaseOpen /\ ~stopped
  /\ conn[c].child = "open" /\ conn[c].live
  /\ conn[c].sock \in {"TimeWait", "Closed"}
  /\ ~conn[c].rst /\ ~conn[c].released
  /\ Set(c, [conn[c] EXCEPT !.released = TRUE, !.held = FALSE,
                            !.said = conn[c].said \/ (SayGone /\ conn[c].mapped)])
  /\ UNCHANGED <<granted, credits, stopped>>

\* housekeeping's orphan loop: closed and its RST gone, it is removed; in
\* TIME-WAIT, it retires: no timeout, nothing held, child unmapped, Gone.
Housekeeping(c) ==
  /\ conn[c].orphaned /\ conn[c].at = "conn"
  /\ \/ /\ conn[c].sock = "Closed" /\ ~conn[c].endpoint
        /\ Set(c, Removed(conn[c]))
     \/ /\ conn[c].sock = "TimeWait" /\ ~conn[c].retired
        /\ conn[c].givesUp = "none"
        /\ Set(c, [conn[c] EXCEPT !.retired = TRUE, !.timeout = FALSE,
                                  !.held = FALSE, !.mapped = FALSE,
                                  !.said = conn[c].said \/ conn[c].mapped])
  /\ UNCHANGED <<granted, credits, stopped>>

\* expire_orphans runs before housekeeping in each step: it arms an
\* orphan's timer in FIN-WAIT-2, removes it when due, and clears the timer
\* once the orphan left FIN-WAIT-2.
ArmOrphan(c) ==
  /\ ~stopped /\ conn[c].orphaned /\ conn[c].at = "conn"
  /\ conn[c].sock = "FinWait2" /\ conn[c].givesUp = "none"
  /\ Set(c, [conn[c] EXCEPT !.givesUp = "armed"])
  /\ UNCHANGED <<granted, credits, stopped>>

OrphanExpires(c) ==
  /\ ~stopped /\ conn[c].orphaned /\ conn[c].at = "conn"
  /\ conn[c].sock = "FinWait2" /\ conn[c].givesUp = "armed"
  /\ Set(c, Removed(conn[c]))
  /\ UNCHANGED <<granted, credits, stopped>>

\* With ClearOrphanTimer FALSE, the timer is left alone: housekeeping in
\* the same step then retires the orphan with its timer still armed.
ClearOrphan(c) ==
  /\ conn[c].orphaned /\ conn[c].at = "conn"
  /\ conn[c].sock # "FinWait2" /\ conn[c].givesUp = "armed"
  /\ IF ClearOrphanTimer
     THEN Set(c, [conn[c] EXCEPT !.givesUp = "none"])
     ELSE /\ conn[c].sock = "TimeWait" /\ ~conn[c].retired
          /\ Set(c, [conn[c] EXCEPT !.retired = TRUE, !.timeout = FALSE,
                                    !.held = FALSE, !.mapped = FALSE,
                                    !.said = conn[c].said \/ conn[c].mapped])
  /\ UNCHANGED <<granted, credits, stopped>>

EvictTimeWait(c) ==
  /\ conn[c].retired /\ conn[c].at = "conn"
  /\ Set(c, Removed(conn[c]))
  /\ UNCHANGED <<granted, credits, stopped>>

\* stop: every socket aborted, Reset for live children, held released and
\* Gone said; orphans removed.
Stop ==
  /\ ~stopped
  /\ stopped' = TRUE
  /\ conn' = [c \in Conns |->
       LET r == conn[c]
           a == IF r.at \in {"embryonic", "ready", "conn"}
                THEN [r EXCEPT !.sock = "Closed", !.endpoint = FALSE,
                               !.held = IF StopReleases THEN FALSE ELSE r.held,
                               !.said = r.said \/ (StopReleases /\ r.mapped)]
                ELSE r
       IN IF r.orphaned /\ r.at = "conn" THEN Removed(a) ELSE a]
  /\ UNCHANGED <<granted, credits>>

-----------------------------------------------------------------------------
Next ==
  \/ HostAccept \/ Stop
  \/ \E c \in Conns :
       \/ Syn(c) \/ FinalAck(c) \/ EmbryoRst(c) \/ HandshakeExpires(c) \/ Offer(c)
       \/ HostConnect(c) \/ HostHold(c) \/ HostAbort(c) \/ HostClose(c)
       \/ HostEnd(c) \/ HostRead(c) \/ HostKeepAlive(c)
       \/ SynAck(c) \/ ConnectFails(c)
       \/ PeerData(c) \/ PeerFin(c) \/ PeerAckFin(c) \/ PeerRst(c)
       \/ Timeout(c) \/ Egress(c) \/ TimeWaitExpires(c) \/ Release(c)
       \/ Housekeeping(c) \/ ArmOrphan(c) \/ OrphanExpires(c) \/ ClearOrphan(c)
       \/ EvictTimeWait(c)

\* The layer steps and its timers come; the host and the peer owe nothing.
Fairness ==
  \A c \in Conns :
    /\ WF_vars(Release(c)) /\ WF_vars(Housekeeping(c)) /\ WF_vars(Egress(c))
    /\ WF_vars(TimeWaitExpires(c)) /\ WF_vars(ArmOrphan(c))
    /\ WF_vars(OrphanExpires(c)) /\ WF_vars(ClearOrphan(c))
    /\ WF_vars(ConnectFails(c))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
TypeOK ==
  /\ \A c \in Conns :
       /\ conn[c].sock \in Socks
       /\ conn[c].at \in {"none", "embryonic", "ready", "conn", "removed"}
       /\ conn[c].child \in {"none", "open", "closed"}
       /\ conn[c].givesUp \in {"none", "armed"}
  /\ granted \in 0..MaxGrants /\ credits \in 0..MaxGrants /\ stopped \in BOOLEAN

\* An accepted connection's child opens only after the listener's answer
\* took the final ACK, and never more children than Accepts.
ChildAfterHandshake ==
  \A c \in Accepted : conn[c].child # "none" => conn[c].accepted
OpenedWithinAccepts ==
  Cardinality({c \in Accepted : conn[c].child # "none"}) <= granted
\* What waits for accept stays within the backlog.
BacklogBound == Cardinality(InQueue("ready")) <= Backlog

\* A child carries bytes, and is granted credit, only once its socket
\* finished the handshake.
BytesAfterHandshake ==
  \A c \in Conns : (conn[c].live \/ conn[c].credited) => conn[c].wasOpen

\* What a limit holds lasts exactly until the connection is gone: never
\* while it is gone, and never released earlier, whatever the child does.
HeldOnlyUntilGone == \A c \in Conns : conn[c].held => ~Gone(c)
CountedUntilGone ==
  \A c \in Conns : (conn[c].kept /\ ~Gone(c)) => conn[c].held

\* The host learns of each release through the port: Gone goes up when
\* what was held is let go, and a host counting by Gone agrees.
ReleaseSaid ==
  [][\A c \in Conns : (conn[c].held /\ ~conn'[c].held) => conn'[c].said]_vars
SaidMeansReleased == \A c \in Conns : conn[c].said => ~conn[c].held
\* Every child whose connection is gone was told so: a host that reads only
\* TcpNotice::Gone knows exactly what gone() knows.
GoneIsSaid ==
  \A c \in Conns : (conn[c].child # "none" /\ Gone(c)) => conn[c].said

\* Abort on a connection that is gone changes nothing.
AbortAfterGoneIsNothing ==
  [][\A c \in Conns : (HostAbort(c) /\ Gone(c)) => UNCHANGED conn]_vars

\* A stopped endpoint holds nothing.
StopHoldsNothing == stopped => \A c \in Conns : ~conn[c].held

\* A retired, released or removed connection has no timer left but the
\* end of TIME-WAIT.
NoTimerWhenGone ==
  \A c \in Conns :
    (conn[c].retired \/ conn[c].released \/ conn[c].at = "removed")
      => Armed(c) \subseteq {"timewait"}

\* A connection the transport let go is eventually gone, and what it held
\* released, whether or not the host ever closes the child.
GoneWhateverTheChild ==
  \A c \in Conns :
    (conn[c].at = "conn" /\ conn[c].sock \in {"TimeWait", "Closed"})
      ~> (Gone(c) /\ ~conn[c].held)
=============================================================================
