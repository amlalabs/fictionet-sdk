----------------------------- MODULE Admission -----------------------------
(* Admission, reset and retirement of world TCP connections through the
   public transport boundary, for any TCP a host installs with
   `tcp::Factory`.

   The host side is `Machine::add` in src/stdlib/world/net/hosts.rs: the
   listener's `tcp::Application` has a `budget` selector, which
   `Children::budgets` runs when a child opens and before the application
   exists, and a `make` factory. The selector calls `Peers::admit_transport`
   (hosts.rs), which takes a `PeerGuard` from `Peers::enter` and hands it to
   `Retirement::hold_until_gone`, or calls `Retirement::reset` and returns a
   budget of zero, so `Children` refuses the child without building the
   application. The world's `Retirement` is `tcp::GoneWatch`
   (src/stdlib/network/tcp.rs), whose `hold_until_gone` and `reset` send
   `TcpControl::Hold` and `TcpControl::Abort` through `Host::control`. A
   port's `Counted` limit in `StackAccept::stack` takes the same path.
   `Children::close_finished` closes a finished application's child
   (src/stdlib/layer/children.rs); nothing on the host side releases a
   guard then.

   The transport is any implementation of the `Tcp` port
   (src/stdlib/network/transport.rs): it keeps what `Hold` gives it until
   the connection is gone, drops it at once if the connection is gone
   already, and an `Abort` on a live connection makes it gone. It may take
   a control command or refuse it for now (`Admit::Blocked`): the port lets
   a layer apply backpressure to any command. The standard `TcpLayer`
   never refuses a control command; a replacement may.

   `Host::control` puts each control command at the back of
   `Host::controls`, and `Host::pump`, which runs whenever the host steps
   the transport (each packet, timer, command and visit), offers the queue
   in order with `Host::offer_controls` until the transport refuses one.
   The code before this pass handed the command to `Host::command`, which
   dropped a refused one: `Retry = FALSE`. `Listen` and `Connect`, whose
   answer the caller reads at once, go through `Host::request` and are
   never queued; they are not admission and are left out here.

   Source lines (checked against main e2858ccc4):
     Open        hosts.rs 1798-1810 (`Listener::attach`, the `budget`
                 selector and `make`), 1345 `Peers::admit_transport`,
                 1357 `Peers::enter`; tcp/applications.rs 22-42 (the
                 `Children` of the connections, with `close_finished`
                 and the `budgets` selector); children.rs 870 (budget
                 chosen before storage), 877-886 (a budget of zero
                 cannot hold the receive window, so the child is
                 refused), 888 (the factory); hosts.rs 242
                 (`StackAccept::stack`, the port's `Counted` limit)
     Offer       tcp.rs 1432 `Host::control`, 1456
                 `Host::offer_controls`, 1478 `Host::pump`; 2063
                 `GoneWatch::reset`, 2084 `GoneWatch::hold_until_gone`
     Finish      children.rs 451 `close_finished`, 824 (the close)
     Retire,
     TakeHold,
     TakeAbort   transport.rs 193-215 `TcpControl::Abort` and
                 `TcpControl::Hold`, 292-296 `TcpNotice::Gone`, the
                 contract every TCP implements; tcp/engine.rs for the
                 standard one (verification/tcp-layer), whose `refuses`
                 (2203) refuses a child's write only, never a control
     guard       hosts.rs 1376 `PeerGuard::drop`
   Stopping the endpoint (tcp.rs 1603 `Shared::stop`) drops the queue
   with the items it holds, `Host::control` (1433) drops a command given
   to a stopped endpoint, and a transport that answers `Admit::Closed`
   loses the command (1470), as a stopped transport holds nothing; none
   of that is modeled.

   What is left out: the bytes, the handshake, which TCP state a closing
   connection is in (the tcp-layer and lifecycle models), and the
   attachment that carried the peer (`world-net/tla/Attachments.tla`). A
   connection is one child of the transport, opened once. The other
   controls `Host::pump` queues (`Accept` for a listener, `Abort` for a
   stray child, tcp.rs 1499-1505) share the queue with Hold and Abort:
   they delay a command behind them, never drop it. An admitted child
   that `Children` then refuses for its child limit or its sandbox
   budget (children.rs 874-886) is closed, not reset, with its guard in
   the transport's Hold; here every admitted connection is built. The
   contract lets a transport release what Hold kept when the connection
   is gone or when it is forgotten (transport.rs 294-295); the transport
   here releases at gone, as the standard one does (tcp.rs 2029-2031),
   so `NotHeldWhenGone` asks more of a replacement than the contract. *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Conns,        \* the connections, all from one peer address
    Max,          \* Limits::connections_per_peer for that peer
    MayBlock,     \* TRUE: the transport may refuse control commands for now
    Retry,        \* TRUE: Host::control queues refused commands (the code)
    AdmitFirst,   \* TRUE: admission runs before the application is built
    ChildOwnsGuard, \* TRUE: closing the application releases the guard
    ReleaseOnGone   \* TRUE: the transport releases what it holds once gone

VARIABLES
    conn,      \* conn[c]: "idle" | "open" | "gone", in the transport
    child,     \* child[c]: "none" | "app" | "closed", the application child
    guard,     \* guard[c]: "none" | "queued" | "held" | "released"
    verdict,   \* verdict[c]: "none" | "admitted" | "refused"
    built,     \* built[c]: the application of c was constructed
    pending,   \* the host's queue of refused control commands
    blocking   \* the transport refuses control commands now

vars == <<conn, child, guard, verdict, built, pending, blocking>>

Commands == [kind : {"hold", "abort"}, c : Conns]
Hold(c) == [kind |-> "hold", c |-> c]
Abort(c) == [kind |-> "abort", c |-> c]

\* The guards alive: queued in a Hold, or kept by the transport. A guard
\* counts against the peer from Peers::enter until PeerGuard::drop.
Live == {c \in Conns : guard[c] \in {"queued", "held"}}
Count == Cardinality(Live)

Init ==
    /\ conn = [c \in Conns |-> "idle"]
    /\ child = [c \in Conns |-> "none"]
    /\ guard = [c \in Conns |-> "none"]
    /\ verdict = [c \in Conns |-> "none"]
    /\ built = [c \in Conns |-> FALSE]
    /\ pending = <<>>
    /\ blocking = FALSE

\* What the transport does with a control command it takes.
TakeHold(c) ==
    IF conn[c] = "gone"
    THEN /\ guard' = [guard EXCEPT ![c] = "released"]
         /\ UNCHANGED conn
    ELSE /\ guard' = [guard EXCEPT ![c] = "held"]
         /\ UNCHANGED conn

TakeAbort(c) ==
    IF conn[c] = "gone"
    THEN UNCHANGED <<conn, guard>>
    ELSE /\ conn' = [conn EXCEPT ![c] = "gone"]
         /\ guard' = IF guard[c] = "held" /\ ReleaseOnGone
                     THEN [guard EXCEPT ![c] = "released"] ELSE guard

\* A peer finishes a handshake and the transport opens a child for it.
Arrive(c) ==
    /\ conn[c] = "idle"
    /\ conn' = [conn EXCEPT ![c] = "open"]
    /\ UNCHANGED <<child, guard, verdict, built, pending, blocking>>

\* Children handles the child's opening: the budget selector admits or
\* refuses, then the factory builds the application, or the child is
\* refused. The opening may be handled after the connection is gone: the
\* event waited in the host's queue. Host::control offers the command.
\* With Retry, a refused or queued-behind command waits in `pending`;
\* without it, a refused command is dropped, and with it the guard.
Open(c) ==
    /\ conn[c] # "idle" /\ child[c] = "none"
    /\ LET admit == Count < Max
           cmd == IF admit THEN Hold(c) ELSE Abort(c)
           offered == ~Retry /\ blocking
       IN
       /\ verdict' = [verdict EXCEPT ![c] = IF admit THEN "admitted" ELSE "refused"]
       /\ child' = [child EXCEPT ![c] = IF admit \/ ~AdmitFirst THEN "app" ELSE "closed"]
       /\ built' = [built EXCEPT ![c] = admit \/ ~AdmitFirst]
       /\ IF Retry
          THEN /\ pending' = Append(pending, cmd)
               /\ guard' = IF admit THEN [guard EXCEPT ![c] = "queued"] ELSE guard
               /\ UNCHANGED conn
          ELSE IF offered
          THEN \* Refused and dropped: Host::command ignored the Admit.
               /\ guard' = IF admit THEN [guard EXCEPT ![c] = "released"] ELSE guard
               /\ UNCHANGED <<conn, pending>>
          ELSE /\ UNCHANGED pending
               /\ IF admit THEN TakeHold(c) ELSE TakeAbort(c)
    /\ UNCHANGED blocking

\* The host steps the transport and offers the head of its queue.
Offer ==
    /\ pending # <<>> /\ ~blocking
    /\ LET cmd == Head(pending) IN
       IF cmd.kind = "hold" THEN TakeHold(cmd.c) ELSE TakeAbort(cmd.c)
    /\ pending' = Tail(pending)
    /\ UNCHANGED <<child, verdict, built, blocking>>

\* A replacement transport starts or stops refusing control commands.
Block ==
    /\ MayBlock /\ ~blocking
    /\ blocking' = TRUE
    /\ UNCHANGED <<conn, child, guard, verdict, built, pending>>

Unblock ==
    /\ blocking
    /\ blocking' = FALSE
    /\ UNCHANGED <<conn, child, guard, verdict, built, pending>>

\* The application finishes and Children::close_finished closes its child.
\* The connection goes on closing in the transport.
Finish(c) ==
    /\ child[c] = "app"
    /\ child' = [child EXCEPT ![c] = "closed"]
    /\ guard' = IF ChildOwnsGuard /\ guard[c] \in {"queued", "held"}
                THEN [guard EXCEPT ![c] = "released"] ELSE guard
    /\ UNCHANGED <<conn, verdict, built, pending, blocking>>

\* The transport retires the connection or the peer resets it: TIME-WAIT,
\* a timeout, a RST. What it held goes with it.
Retire(c) ==
    /\ conn[c] = "open"
    /\ conn' = [conn EXCEPT ![c] = "gone"]
    /\ guard' = IF guard[c] = "held" /\ ReleaseOnGone
                THEN [guard EXCEPT ![c] = "released"] ELSE guard
    /\ UNCHANGED <<child, verdict, built, pending, blocking>>

Next ==
    \/ \E c \in Conns : Arrive(c) \/ Open(c) \/ Finish(c) \/ Retire(c)
    \/ Offer \/ Block \/ Unblock

\* The host keeps stepping the transport whenever it may take a command
\* (Host::pump runs on every packet, command and timer of the transport),
\* and a transport that refuses for now takes commands again later: a
\* command offered again and again while the transport keeps unblocking
\* is taken.
Spec == Init /\ [][Next]_vars /\ SF_vars(Offer) /\ WF_vars(Unblock)

-----------------------------------------------------------------------------
TypeOK ==
    /\ conn \in [Conns -> {"idle", "open", "gone"}]
    /\ child \in [Conns -> {"none", "app", "closed"}]
    /\ guard \in [Conns -> {"none", "queued", "held", "released"}]
    /\ verdict \in [Conns -> {"none", "admitted", "refused"}]
    /\ built \in [Conns -> BOOLEAN]
    /\ pending \in Seq(Commands)
    /\ blocking \in BOOLEAN

\* An admitted connection counts against its peer until the transport says
\* it is gone, through every closing state, whatever its application does.
CountedUntilGone ==
    \A c \in Conns : verdict[c] = "admitted" /\ conn[c] # "gone" => c \in Live

\* The transport keeps no guard of a connection that is gone.
NotHeldWhenGone == \A c \in Conns : conn[c] = "gone" => guard[c] # "held"

\* The peer never has more connections counted than it may.
WithinLimit == Count <= Max

\* An application is built only for an admitted connection.
BuiltOnlyAdmitted == \A c \in Conns : built[c] => verdict[c] = "admitted"

\* A refused connection is reset.
RefusedAreReset == \A c \in Conns : verdict[c] = "refused" ~> conn[c] = "gone"

\* A guard of a connection that is gone is let go.
GoneReleases ==
    \A c \in Conns : (conn[c] = "gone" /\ c \in Live) ~> guard[c] = "released"
=============================================================================
