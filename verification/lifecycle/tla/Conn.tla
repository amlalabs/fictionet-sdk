----------------------------- MODULE Conn -----------------------------
(***************************************************************************)
(* One TCP connection's life in src/stdlib/network/tcp/engine.rs and the   *)
(* handles of tcp.rs, from the moment `accept` or `connect` handed out its *)
(* TcpConnection: the smoltcp socket state, the `Conn` bookkeeping of      *)
(* `TcpLayer`, the handle, the orphan and TIME-WAIT lists, what            *)
(* `TcpControl::Hold` keeps, and when a `GoneWatch` is ready.               *)
(*                                                                         *)
(*   Read, Write, Shutdown, Drop, ResetHandle, WatchReset, Hold            *)
(*       TcpConnection::poll_read, poll_write, poll_shutdown, Drop,         *)
(*       TcpConnection::reset, GoneWatch::reset, hold_until_gone, through   *)
(*       the layer's credit, End, Abort, close and Hold                     *)
(*   Orphan, Abort, CloseIfDrained, Remove                                 *)
(*       TcpLayer::orphan, abort, close_if_drained, remove_conn             *)
(*   PeerData, PeerAck, PeerFin, PeerRst                                   *)
(*       TcpLayer::ingress after smoltcp's `process`, and the flags it sets *)
(*   Timeout, Egress, TimeWaitExpires                                      *)
(*       smoltcp's own timeout (an abort), the RST going out after an      *)
(*       abort, and TIME-WAIT's expiry                                      *)
(*   Housekeeping, ExpireOrphans, GivesUpDue, EvictTimeWait                *)
(*       TcpLayer::housekeeping's orphan loop and TIME-WAIT cap,           *)
(*       TcpLayer::expire_orphans, its timer                                *)
(*   Stop                                                                   *)
(*       Shared::stop, through TcpLayer::stop                              *)
(*                                                                         *)
(* Bytes are booleans: `rx` says unread bytes wait, in the receive buffer  *)
(* or come up to the handle and not read yet, `tx` that the send buffer    *)
(* holds bytes the peer has not acknowledged.                              *)
(* Segment validation, sequence numbers, windows, retransmission and the   *)
(* handshake are smoltcp's and out of scope: a peer event here is one      *)
(* smoltcp accepted.  The socket's timeout is an action that may fire      *)
(* whenever the socket waits for the peer.                                 *)
(***************************************************************************)
EXTENDS Naturals

\* Both TRUE for the code.  OrphanTimer FALSE leaves out expire_orphans;
\* ResetUnread FALSE drops a handle with unread bytes as if they were read.
CONSTANTS OrphanTimer, ResetUnread

Open == {"Established", "FinWait1", "FinWait2", "CloseWait", "Closing", "LastAck"}
States == Open \cup {"TimeWait", "Closed"}

VARIABLES
  tcp,        \* the smoltcp state
  endpoint,   \* smoltcp still names the peer: a RST can still go out
  rx, tx,     \* unread bytes; unacknowledged bytes
  finRecv,    \* smoltcp took the peer's FIN; Conn::fin
  rst,        \* Conn::rst: a RST came, or this side aborted
  shut,       \* Conn::shut
  orphaned,   \* Conn::orphaned
  retired,    \* Conn::retired
  handle,     \* "alive" | "dropped"
  inConns,    \* the Conn and its socket exist
  inOrphans,  \* State::orphans
  inTimeWait, \* State::time_wait
  held,       \* Conn::held is not empty
  givesUp,    \* Conn::gives_up: "none" | "armed" | "due"
  stopped     \* State::stopped

vars == <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired, handle,
          inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

Init ==
  /\ tcp = "Established" /\ endpoint = TRUE
  /\ rx \in BOOLEAN /\ tx = FALSE
  /\ finRecv = FALSE /\ rst = FALSE /\ shut = FALSE
  /\ orphaned = FALSE /\ retired = FALSE
  /\ handle = "alive"
  /\ inConns = TRUE /\ inOrphans = FALSE /\ inTimeWait = FALSE
  /\ held \in BOOLEAN
  /\ givesUp = "none"
  /\ stopped = FALSE

\* GoneWatch::poll_gone is ready.
Gone == stopped \/ ~inConns \/ rst \/ retired

-----------------------------------------------------------------------------
\* State::remove_conn: the Conn is dropped, with what it held, and its
\* watchers are woken.
Remove ==
  /\ inConns' = FALSE /\ inOrphans' = FALSE /\ inTimeWait' = FALSE /\ held' = FALSE

\* smoltcp's close: the FIN, once it may go.
Closed(s) ==
  CASE s = "Established" -> "FinWait1"
    [] s = "CloseWait" -> "LastAck"
    [] OTHER -> s

\* State::close_if_drained, on the state after the step's other effects.
CloseIfDrained(shutNow, txNow, s) == IF shutNow /\ ~txNow THEN Closed(s) ELSE s

-----------------------------------------------------------------------------
\* The handle.
\* poll_read takes the unread bytes.
Read ==
  /\ handle = "alive" /\ ~stopped /\ rx
  /\ rx' = FALSE
  /\ UNCHANGED <<tcp, endpoint, tx, finRecv, rst, shut, orphaned, retired, handle,
                 inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

\* poll_write queues bytes while the send half is open.
Write ==
  /\ handle = "alive" /\ ~stopped /\ ~shut /\ tcp \in {"Established", "CloseWait"}
  /\ tx' = TRUE
  /\ UNCHANGED <<tcp, endpoint, rx, finRecv, rst, shut, orphaned, retired, handle,
                 inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

\* poll_shutdown: the FIN follows the last acknowledgement.
Shutdown ==
  /\ handle = "alive" /\ ~stopped
  /\ shut' = TRUE
  /\ tcp' = CloseIfDrained(TRUE, tx, tcp)
  /\ UNCHANGED <<endpoint, rx, tx, finRecv, rst, orphaned, retired, handle,
                 inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

\* State::abort: a RST, and the watchers woken.
AbortSocket == tcp' = "Closed" /\ rst' = TRUE

\* State::orphan, after the handle is gone.
Orphan(abort) ==
  IF stopped THEN
    /\ Remove
    /\ UNCHANGED <<tcp, endpoint, rst, shut, orphaned, retired, givesUp>>
  ELSE
    /\ IF abort \/ (ResetUnread /\ rx)
       THEN AbortSocket /\ shut' = shut
       ELSE shut' = TRUE /\ tcp' = CloseIfDrained(TRUE, tx, tcp) /\ rst' = rst
    /\ orphaned' = TRUE /\ inOrphans' = TRUE
    /\ UNCHANGED <<endpoint, retired, inConns, inTimeWait, held, givesUp>>

\* Drop for TcpConnection.
Drop ==
  /\ handle = "alive"
  /\ handle' = "dropped"
  /\ Orphan(FALSE)
  /\ UNCHANGED <<rx, tx, finRecv, stopped>>

\* TcpConnection::reset: the abort, then the handle's drop.
ResetHandle ==
  /\ handle = "alive"
  /\ handle' = "dropped"
  /\ IF stopped THEN
       /\ Remove
       /\ UNCHANGED <<tcp, endpoint, rst, shut, orphaned, retired, givesUp>>
     ELSE
       /\ AbortSocket
       /\ orphaned' = TRUE /\ inOrphans' = TRUE
       /\ UNCHANGED <<endpoint, shut, retired, inConns, inTimeWait, held, givesUp>>
  /\ UNCHANGED <<rx, tx, finRecv, stopped>>

\* GoneWatch::reset, from anyone who kept a watch.
WatchReset ==
  /\ inConns /\ ~retired
  /\ AbortSocket
  /\ UNCHANGED <<endpoint, rx, tx, finRecv, shut, orphaned, retired, handle,
                 inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

\* hold_until_gone: kept unless the connection has retired.
Hold ==
  /\ inConns /\ ~retired /\ ~held
  /\ held' = TRUE
  /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired, handle,
                 inConns, inOrphans, inTimeWait, givesUp, stopped>>

-----------------------------------------------------------------------------
\* The peer, through smoltcp's `process` and State::ingress.
Live == inConns /\ ~stopped

\* Data: taken while the receive half is open and before the peer's FIN.
PeerData ==
  /\ Live /\ tcp \in {"Established", "FinWait1", "FinWait2"} /\ ~finRecv
  /\ rx' = TRUE
  /\ UNCHANGED <<tcp, endpoint, tx, finRecv, rst, shut, orphaned, retired, handle,
                 inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

\* An acknowledgement: of data, and perhaps of this side's FIN.  LAST-ACK's
\* final one forgets the peer.  Then close_if_drained.
PeerAck ==
  /\ Live /\ tcp \in Open
  /\ tx' = FALSE
  /\ \E finAcked \in BOOLEAN :
       LET s == CASE tcp = "FinWait1" /\ finAcked -> "FinWait2"
                  [] tcp = "Closing" /\ finAcked -> "TimeWait"
                  [] tcp = "LastAck" /\ finAcked -> "Closed"
                  [] OTHER -> tcp
       IN /\ tcp' = CloseIfDrained(shut, FALSE, s)
          /\ endpoint' = IF s = "Closed" THEN FALSE ELSE endpoint
  /\ UNCHANGED <<rx, finRecv, rst, shut, orphaned, retired, handle,
                 inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

\* The peer's FIN; it may acknowledge this side's FIN too.
PeerFin ==
  /\ Live /\ ~finRecv /\ tcp \in {"Established", "FinWait1", "FinWait2"}
  /\ finRecv' = TRUE
  /\ \E finAcked \in BOOLEAN :
       LET s == CASE tcp = "Established" -> "CloseWait"
                  [] tcp = "FinWait1" /\ finAcked -> "TimeWait"
                  [] tcp = "FinWait1" -> "Closing"
                  [] OTHER -> "TimeWait"
       IN /\ tcp' = CloseIfDrained(shut, IF finAcked THEN FALSE ELSE tx, s)
          /\ tx' = IF finAcked THEN FALSE ELSE tx
  /\ UNCHANGED <<endpoint, rx, rst, shut, orphaned, retired, handle,
                 inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

\* The peer's RST: smoltcp forgets the peer; ingress notes the reset,
\* clears what is held, and wakes the watchers.
PeerRst ==
  /\ Live /\ tcp # "Closed"
  /\ tcp' = "Closed" /\ endpoint' = FALSE /\ rst' = TRUE /\ held' = FALSE
  /\ UNCHANGED <<rx, tx, finRecv, shut, orphaned, retired, handle,
                 inConns, inOrphans, inTimeWait, givesUp, stopped>>

\* smoltcp's timeout: an abort, with the RST still to go out.  It can fire
\* while the socket waits for an acknowledgement, and on a live handle's
\* keepalives.  An orphan sends no keepalives, so FIN-WAIT-2 is left to
\* expire_orphans.
Timeout ==
  /\ Live /\ tcp \in Open
  /\ tx \/ tcp \in {"FinWait1", "Closing", "LastAck"} \/ handle = "alive"
  /\ tcp' = "Closed"
  /\ UNCHANGED <<endpoint, rx, tx, finRecv, rst, shut, orphaned, retired, handle,
                 inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

\* The RST of an aborted socket goes out: smoltcp forgets the peer.
Egress ==
  /\ inConns /\ tcp = "Closed" /\ endpoint
  /\ endpoint' = FALSE
  /\ UNCHANGED <<tcp, rx, tx, finRecv, rst, shut, orphaned, retired, handle,
                 inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

TimeWaitExpires ==
  /\ Live /\ tcp = "TimeWait"
  /\ tcp' = "Closed" /\ endpoint' = FALSE
  /\ UNCHANGED <<rx, tx, finRecv, rst, shut, orphaned, retired, handle,
                 inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

-----------------------------------------------------------------------------
\* The endpoint's task.
\* housekeeping's orphan loop: a closed socket whose RST has gone is
\* removed; one in TIME-WAIT retires, releasing what it held and waking
\* its watchers.
Housekeeping ==
  /\ inOrphans
  /\ \/ /\ tcp = "Closed" /\ ~endpoint
        /\ Remove
        /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired,
                       handle, givesUp, stopped>>
     \/ /\ tcp = "TimeWait" /\ ~retired
        /\ retired' = TRUE /\ held' = FALSE /\ inTimeWait' = TRUE
        /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, handle,
                       inConns, inOrphans, givesUp, stopped>>

\* expire_orphans: an orphan in FIN-WAIT-2 is given up after the orphan
\* timeout, whatever the peer sends meanwhile.
ExpireOrphans ==
  /\ OrphanTimer /\ inOrphans
  /\ \/ /\ tcp = "FinWait2" /\ givesUp = "none"
        /\ givesUp' = "armed"
        /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired,
                       handle, inConns, inOrphans, inTimeWait, held, stopped>>
     \/ /\ tcp = "FinWait2" /\ givesUp = "due"
        /\ Remove
        /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired,
                       handle, givesUp, stopped>>
     \/ /\ tcp # "FinWait2" /\ givesUp # "none"
        /\ givesUp' = "none"
        /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired,
                       handle, inConns, inOrphans, inTimeWait, held, stopped>>

GivesUpDue ==
  /\ givesUp = "armed" /\ givesUp' = "due"
  /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired, handle,
                 inConns, inOrphans, inTimeWait, held, stopped>>

\* housekeeping: past MAX_TIME_WAIT, the oldest retired orphans go.
EvictTimeWait ==
  /\ inTimeWait
  /\ Remove
  /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired, handle,
                 givesUp, stopped>>

\* Shared::stop: every socket is aborted, every orphan removed.
Stop ==
  /\ ~stopped
  /\ stopped' = TRUE
  /\ tcp' = IF inConns THEN "Closed" ELSE tcp
  /\ IF inOrphans
     THEN Remove
     ELSE UNCHANGED <<inConns, inOrphans, held>> /\ inTimeWait' = FALSE
  /\ UNCHANGED <<endpoint, rx, tx, finRecv, rst, shut, orphaned, retired, handle, givesUp>>

-----------------------------------------------------------------------------
Next ==
  \/ Read \/ Write \/ Shutdown \/ Drop \/ ResetHandle \/ WatchReset \/ Hold
  \/ PeerData \/ PeerAck \/ PeerFin \/ PeerRst
  \/ Timeout \/ Egress \/ TimeWaitExpires
  \/ Housekeeping \/ ExpireOrphans \/ GivesUpDue \/ EvictTimeWait
  \/ Stop

\* The endpoint's task runs, the RST goes out, timers go off.  The peer
\* owes nothing.
Fairness ==
  WF_vars(Housekeeping) /\ WF_vars(ExpireOrphans) /\ WF_vars(GivesUpDue)
  /\ WF_vars(Egress) /\ WF_vars(TimeWaitExpires) /\ WF_vars(Timeout)

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
TypeOK ==
  /\ tcp \in States
  /\ endpoint \in BOOLEAN /\ rx \in BOOLEAN /\ tx \in BOOLEAN
  /\ finRecv \in BOOLEAN /\ rst \in BOOLEAN /\ shut \in BOOLEAN
  /\ orphaned \in BOOLEAN /\ retired \in BOOLEAN
  /\ handle \in {"alive", "dropped"}
  /\ inConns \in BOOLEAN /\ inOrphans \in BOOLEAN /\ inTimeWait \in BOOLEAN
  /\ held \in BOOLEAN
  /\ givesUp \in {"none", "armed", "due"}
  /\ stopped \in BOOLEAN

\* The lists agree with the flags and with each other.
Bookkeeping ==
  /\ inOrphans => inConns /\ orphaned
  /\ inConns /\ orphaned => inOrphans
  /\ inTimeWait => inOrphans /\ retired
  /\ retired => inTimeWait \/ ~inConns
  /\ retired => tcp \in {"TimeWait", "Closed"}
  /\ handle = "dropped" /\ inConns => orphaned
  /\ orphaned => handle = "dropped"
  /\ ~inConns => ~held /\ ~inOrphans /\ ~inTimeWait

\* Nothing is held past retirement or removal, and stopping leaves no
\* orphan or TIME-WAIT state behind.
HeldOnlyWhileCounted == held => inConns /\ ~retired
StopCleans == stopped => ~inOrphans /\ ~inTimeWait /\ (handle = "dropped" => ~inConns)

\* The gone watch is ready exactly when the doc says: reset by either
\* side, retired into TIME-WAIT, removed, or the endpoint stopped.
GoneMeans == Gone <=> (stopped \/ ~inConns \/ rst \/ retired)

\* A FIN goes only after every queued byte is acknowledged.
FinAfterDrain ==
  [][(tcp \in {"Established", "CloseWait"} /\ tcp' \in {"FinWait1", "LastAck"}) => ~tx']_vars

\* Dropping the handle resets a connection with unread bytes, and closes
\* one without them.
DropResetsUnread ==
  [][(Drop /\ ~stopped /\ rx) => rst']_vars
DropClosesRead ==
  [][(Drop /\ ~stopped /\ ~rx) => (shut' /\ rst' = rst)]_vars

\* A reset from the peer, or retirement, releases what was held.
ResetReleases == [][PeerRst => ~held']_vars
RetireReleases == [][(Housekeeping /\ retired' /\ ~retired) => ~held']_vars

\* An orphan is eventually gone for its watchers, and eventually removed.
OrphanWatched == (handle = "dropped") ~> Gone
OrphanRemoved == (handle = "dropped") ~> ~inConns
\* What a connection holds is released once its handle is dropped.
HeldReleased == (handle = "dropped") ~> ~held
=============================================================================
