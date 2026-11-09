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
(*       Retirement delegates these same operations for world admission   *)
(*       (tcp.rs 2092); a control the transport refuses for now waits in   *)
(*       Host::controls (tcp.rs 1159, offered again by offer_controls at   *)
(*       1456) until it takes it, as here, where the layer takes every one.*)
(*   Orphan, Abort, CloseIfDrained, Remove                                 *)
(*       TcpLayer::orphan, abort, close_if_drained, remove_conn             *)
(*   Release                                                                *)
(*       TcpLayer::refresh for an open child whose socket reached          *)
(*       TIME-WAIT or closed on its own (Conn::released)                   *)
(*   PeerData, PeerAck, PeerFin, PeerRst                                   *)
(*       TcpLayer::ingress after smoltcp's `process`, and the flags it sets *)
(*   Timeout, Egress, TimeWaitExpires                                      *)
(*       smoltcp's own timeout (an abort), the RST going out after an      *)
(*       abort, and TIME-WAIT's expiry                                      *)
(*   Housekeeping, ExpireOrphans, GivesUpDue, EvictTimeWait                *)
(*       TcpLayer::housekeeping's orphan loop and TIME-WAIT cap,           *)
(*       TcpLayer::expire_orphans, its timer                                *)
(*   Stop                                                                   *)
(*       Shared::stop and Host::stop (tcp.rs 1603, 1542), which hand the   *)
(*       layer PacketEvent::Ended, through TcpLayer::stop (engine.rs 1852) *)
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

\* Each TRUE for the code.  FALSE keeps a rule as it was, or weakens it:
\*   OrphanTimer     expire_orphans exists
\*   ResetUnread     a drop with unread bytes resets (FALSE: as if read)
\*   ReleaseOpen     refresh lets go of an open child's connection once its
\*                   socket reached TIME-WAIT or closed (FALSE: before
\*                   773c5c1a3, kept until the child closed)
\*   AbortReleases   abort lets go of what was held (FALSE: before 2124865df)
\*   CountUntilGone  closing the child leaves what it held alone (FALSE: the
\*                   count is tied to the child's lifetime)
CONSTANTS OrphanTimer, ResetUnread, ReleaseOpen, AbortReleases, CountUntilGone

Open == {"Established", "FinWait1", "FinWait2", "CloseWait", "Closing", "LastAck"}
States == Open \cup {"TimeWait", "Closed"}

VARIABLES
  tcp,        \* the smoltcp state
  endpoint,   \* smoltcp still names the peer: a RST can still go out
  rx, tx,     \* unread bytes; unacknowledged bytes
  finRecv,    \* smoltcp took the peer's FIN; Conn::fin
  rst,        \* Conn::rst: a RST came, this side aborted, or the socket
              \* closed on a segment (LAST-ACK's final ACK)
  shut,       \* Conn::shut
  orphaned,   \* Conn::orphaned
  retired,    \* Conn::retired
  released,   \* Conn::released
  handle,     \* "alive" | "dropped"
  inConns,    \* the Conn and its socket exist (TcpLayer::conns)
  inOrphans,  \* TcpLayer::orphans
  inTimeWait, \* TcpLayer::time_wait
  held,       \* Conn::held is not empty
  givesUp,    \* Conn::gives_up: "none" | "armed" | "due"
  stopped     \* TcpLayer::stopped

vars == <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired, released,
          handle, inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

Init ==
  /\ tcp = "Established" /\ endpoint = TRUE
  /\ rx \in BOOLEAN /\ tx = FALSE
  /\ finRecv = FALSE /\ rst = FALSE /\ shut = FALSE
  /\ orphaned = FALSE /\ retired = FALSE /\ released = FALSE
  /\ handle = "alive"
  /\ inConns = TRUE /\ inOrphans = FALSE /\ inTimeWait = FALSE
  /\ held \in BOOLEAN
  /\ givesUp = "none"
  /\ stopped = FALSE

\* TcpLayer::gone, which GoneWatch::poll_gone reads.
Gone == stopped \/ ~inConns \/ rst \/ retired \/ released

-----------------------------------------------------------------------------
\* TcpLayer::remove_conn: the Conn is dropped, with what it held, and its
\* watchers are woken.
Remove ==
  /\ inConns' = FALSE /\ inOrphans' = FALSE /\ inTimeWait' = FALSE /\ held' = FALSE

\* smoltcp's close: the FIN, once it may go.
Closed(s) ==
  CASE s = "Established" -> "FinWait1"
    [] s = "CloseWait" -> "LastAck"
    [] OTHER -> s

\* TcpLayer::close_if_drained, on the state after the step's other effects.
CloseIfDrained(shutNow, txNow, s) == IF shutNow /\ ~txNow THEN Closed(s) ELSE s

-----------------------------------------------------------------------------
\* The handle.
\* poll_read takes the unread bytes.
Read ==
  /\ handle = "alive" /\ ~stopped /\ rx
  /\ rx' = FALSE
  /\ UNCHANGED <<tcp, endpoint, tx, finRecv, rst, shut, orphaned, retired, released,
                 handle, inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

\* poll_write queues bytes while the send half is open.
Write ==
  /\ handle = "alive" /\ ~stopped /\ ~shut /\ tcp \in {"Established", "CloseWait"}
  /\ tx' = TRUE
  /\ UNCHANGED <<tcp, endpoint, rx, finRecv, rst, shut, orphaned, retired, released,
                 handle, inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

\* poll_shutdown: the FIN follows the last acknowledgement.
Shutdown ==
  /\ handle = "alive" /\ ~stopped
  /\ shut' = TRUE
  /\ tcp' = CloseIfDrained(TRUE, tx, tcp)
  /\ UNCHANGED <<endpoint, rx, tx, finRecv, rst, orphaned, retired, released, handle,
                 inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

\* TcpLayer::abort: a RST, the watchers woken, and what was held let go.
AbortSocket ==
  /\ tcp' = "Closed" /\ rst' = TRUE
  /\ held' = (held /\ ~AbortReleases)

\* TcpLayer::orphan, after the handle is gone (MuxOp::Close).  `abort` is
\* the TcpControl::Abort the handle sent first, which the layer takes only
\* while the connection is not gone.
Orphan(abort) ==
  IF stopped THEN
    /\ Remove
    /\ UNCHANGED <<tcp, endpoint, rst, shut, orphaned, retired, released, givesUp>>
  ELSE
    /\ IF (abort /\ ~Gone) \/ (ResetUnread /\ rx)
       THEN AbortSocket /\ shut' = shut
       ELSE /\ shut' = TRUE /\ tcp' = CloseIfDrained(TRUE, tx, tcp) /\ rst' = rst
            /\ held' = (held /\ CountUntilGone)
    /\ orphaned' = TRUE /\ inOrphans' = TRUE
    /\ UNCHANGED <<endpoint, retired, released, inConns, inTimeWait, givesUp>>

\* Drop for TcpConnection.
Drop ==
  /\ handle = "alive"
  /\ handle' = "dropped"
  /\ Orphan(FALSE)
  /\ UNCHANGED <<rx, tx, finRecv, stopped>>

\* TcpConnection::reset: Abort, then the handle's drop.
ResetHandle ==
  /\ handle = "alive"
  /\ handle' = "dropped"
  /\ Orphan(TRUE)
  /\ UNCHANGED <<rx, tx, finRecv, stopped>>

\* GoneWatch::reset, from anyone who kept a watch: TcpControl::Abort,
\* nothing once the connection is gone.
WatchReset ==
  /\ ~Gone
  /\ AbortSocket
  /\ UNCHANGED <<endpoint, rx, tx, finRecv, shut, orphaned, retired, released, handle,
                 inConns, inOrphans, inTimeWait, givesUp, stopped>>

\* hold_until_gone: TcpControl::Hold, kept unless the connection is gone.
Hold ==
  /\ ~Gone /\ ~held
  /\ held' = TRUE
  /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired, released,
                 handle, inConns, inOrphans, inTimeWait, givesUp, stopped>>

\* refresh, for the open child: a socket that reached TIME-WAIT or closed
\* on its own (its timeout, TIME-WAIT's end) lets go of what it held, and
\* the connection is gone.
Release ==
  /\ ReleaseOpen /\ handle = "alive" /\ inConns /\ ~stopped
  /\ tcp \in {"TimeWait", "Closed"} /\ ~rst /\ ~released
  /\ released' = TRUE /\ held' = FALSE
  /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired, handle,
                 inConns, inOrphans, inTimeWait, givesUp, stopped>>

-----------------------------------------------------------------------------
\* The peer, through smoltcp's `process` and TcpLayer::ingress.
Live == inConns /\ ~stopped

\* Data: taken while the receive half is open and before the peer's FIN.
PeerData ==
  /\ Live /\ tcp \in {"Established", "FinWait1", "FinWait2"} /\ ~finRecv
  /\ rx' = TRUE
  /\ UNCHANGED <<tcp, endpoint, tx, finRecv, rst, shut, orphaned, retired, released,
                 handle, inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

\* An acknowledgement: of data, and perhaps of this side's FIN.  LAST-ACK's
\* final one forgets the peer, and ingress takes the socket's close as the
\* end of the connection: rst, what was held cleared, Gone.  Then
\* close_if_drained.
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
          /\ rst' = (rst \/ s = "Closed")
          /\ held' = (held /\ s # "Closed")
  /\ UNCHANGED <<rx, finRecv, shut, orphaned, retired, released, handle,
                 inConns, inOrphans, inTimeWait, givesUp, stopped>>

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
  /\ UNCHANGED <<endpoint, rx, rst, shut, orphaned, retired, released, handle,
                 inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

\* The peer's RST: smoltcp forgets the peer; ingress notes the reset,
\* clears what is held, and wakes the watchers.
PeerRst ==
  /\ Live /\ tcp # "Closed"
  /\ tcp' = "Closed" /\ endpoint' = FALSE /\ rst' = TRUE /\ held' = FALSE
  /\ UNCHANGED <<rx, tx, finRecv, shut, orphaned, retired, released, handle,
                 inConns, inOrphans, inTimeWait, givesUp, stopped>>

\* smoltcp's timeout: an abort, with the RST still to go out.  It can fire
\* while the socket waits for an acknowledgement, and on a live handle's
\* keepalives (smoltcp's `waits_for_answer`: FIN-WAIT-1, CLOSING and
\* LAST-ACK always; ESTABLISHED and CLOSE-WAIT with bytes to send or
\* keepalives on; FIN-WAIT-2 only with keepalives on).  `orphan` turns
\* keepalives off, so an orphan in FIN-WAIT-2 is left to expire_orphans.
\* A live handle is taken to have keepalives on, as a connection starts.
Timeout ==
  /\ Live /\ tcp \in Open
  /\ tx \/ tcp \in {"FinWait1", "Closing", "LastAck"} \/ handle = "alive"
  /\ tcp' = "Closed"
  /\ UNCHANGED <<endpoint, rx, tx, finRecv, rst, shut, orphaned, retired, released,
                 handle, inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

\* The RST of an aborted socket goes out: smoltcp forgets the peer.
Egress ==
  /\ inConns /\ tcp = "Closed" /\ endpoint
  /\ endpoint' = FALSE
  /\ UNCHANGED <<tcp, rx, tx, finRecv, rst, shut, orphaned, retired, released, handle,
                 inConns, inOrphans, inTimeWait, held, givesUp, stopped>>

TimeWaitExpires ==
  /\ Live /\ tcp = "TimeWait"
  /\ tcp' = "Closed" /\ endpoint' = FALSE
  /\ UNCHANGED <<rx, tx, finRecv, rst, shut, orphaned, retired, released, handle,
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
                       released, handle, givesUp, stopped>>
     \/ /\ tcp = "TimeWait" /\ ~retired
        /\ retired' = TRUE /\ held' = FALSE /\ inTimeWait' = TRUE
        /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, released,
                       handle, inConns, inOrphans, givesUp, stopped>>

\* expire_orphans: an orphan in FIN-WAIT-2 is given up after the orphan
\* timeout, whatever the peer sends meanwhile.
ExpireOrphans ==
  /\ OrphanTimer /\ inOrphans
  /\ \/ /\ tcp = "FinWait2" /\ givesUp = "none"
        /\ givesUp' = "armed"
        /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired,
                       released, handle, inConns, inOrphans, inTimeWait, held, stopped>>
     \/ /\ tcp = "FinWait2" /\ givesUp = "due"
        /\ Remove
        /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired,
                       released, handle, givesUp, stopped>>
     \/ /\ tcp # "FinWait2" /\ givesUp # "none"
        /\ givesUp' = "none"
        /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired,
                       released, handle, inConns, inOrphans, inTimeWait, held, stopped>>

GivesUpDue ==
  /\ givesUp = "armed" /\ givesUp' = "due"
  /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired, released,
                 handle, inConns, inOrphans, inTimeWait, held, stopped>>

\* housekeeping: past MAX_TIME_WAIT, the oldest retired orphans go.
EvictTimeWait ==
  /\ inTimeWait
  /\ Remove
  /\ UNCHANGED <<tcp, endpoint, rx, tx, finRecv, rst, shut, orphaned, retired, released,
                 handle, givesUp, stopped>>

\* Shared::stop: every socket is aborted and lets go of what it held, every
\* orphan is removed.
Stop ==
  /\ ~stopped
  /\ stopped' = TRUE
  /\ tcp' = IF inConns THEN "Closed" ELSE tcp
  /\ held' = FALSE
  /\ IF inOrphans
     THEN Remove
     ELSE UNCHANGED <<inConns, inOrphans>> /\ inTimeWait' = FALSE
  /\ UNCHANGED <<endpoint, rx, tx, finRecv, rst, shut, orphaned, retired, released,
                 handle, givesUp>>

-----------------------------------------------------------------------------
Next ==
  \/ Read \/ Write \/ Shutdown \/ Drop \/ ResetHandle \/ WatchReset \/ Hold
  \/ Release
  \/ PeerData \/ PeerAck \/ PeerFin \/ PeerRst
  \/ Timeout \/ Egress \/ TimeWaitExpires
  \/ Housekeeping \/ ExpireOrphans \/ GivesUpDue \/ EvictTimeWait
  \/ Stop

\* The endpoint's task runs, the RST goes out, timers go off.  The peer
\* and the handle owe nothing.
Fairness ==
  WF_vars(Housekeeping) /\ WF_vars(ExpireOrphans) /\ WF_vars(GivesUpDue)
  /\ WF_vars(Egress) /\ WF_vars(TimeWaitExpires) /\ WF_vars(Timeout)
  /\ WF_vars(Release)

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
TypeOK ==
  /\ tcp \in States
  /\ endpoint \in BOOLEAN /\ rx \in BOOLEAN /\ tx \in BOOLEAN
  /\ finRecv \in BOOLEAN /\ rst \in BOOLEAN /\ shut \in BOOLEAN
  /\ orphaned \in BOOLEAN /\ retired \in BOOLEAN /\ released \in BOOLEAN
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

\* What is held lasts only while the connection is not gone: never past a
\* reset by either side, retirement, release, removal or the stop.
HeldOnlyWhileCounted == held => ~Gone
StopCleans == stopped => ~inOrphans /\ ~inTimeWait /\ (handle = "dropped" => ~inConns)

\* The gone watch is ready only once the transport is done with the
\* connection: stopped, removed, reset, or its socket in TIME-WAIT or
\* closed.  Never while it is open or closing, whatever the handle does.
GoneMeans ==
  Gone => (stopped \/ ~inConns \/ rst \/ tcp \in {"TimeWait", "Closed"})

\* What is held is let go only when the connection becomes gone: closing
\* the handle does not release it while the connection is still closing.
CountedUntilDone == [][(held /\ ~held') => Gone']_vars

\* A FIN goes only after every queued byte is acknowledged.
FinAfterDrain ==
  [][(tcp \in {"Established", "CloseWait"} /\ tcp' \in {"FinWait1", "LastAck"}) => ~tx']_vars

\* Dropping the handle resets a connection with unread bytes, and closes
\* one without them.
DropResetsUnread ==
  [][(Drop /\ ~stopped /\ rx) => rst']_vars
DropClosesRead ==
  [][(Drop /\ ~stopped /\ ~rx) => (shut' /\ rst' = rst)]_vars

\* A reset from either side, or retirement, releases what was held.
ResetReleases == [][(~rst /\ rst') => ~held']_vars
RetireReleases == [][(Housekeeping /\ retired' /\ ~retired) => ~held']_vars

\* An orphan is eventually gone for its watchers, and eventually removed.
OrphanWatched == (handle = "dropped") ~> Gone
OrphanRemoved == (handle = "dropped") ~> ~inConns
\* What a connection holds is released once its handle is dropped.
HeldReleased == (handle = "dropped") ~> ~held
\* A connection whose socket reached TIME-WAIT or closed is eventually
\* gone, and what it held released, whether or not the handle is ever
\* dropped.
GoneWhateverTheHandle ==
  (inConns /\ tcp \in {"TimeWait", "Closed"}) ~> (Gone /\ ~held)
=============================================================================
