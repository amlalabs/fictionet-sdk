----------------------------- MODULE UdpSockets -----------------------------
(* The receive side of the UDP layer, `UdpLayer` in
   src/stdlib/network/udp/sockets.rs: `bind` (lines 243-277) opens a child
   on a free port, `take_in` (315-371) queues a datagram for the socket on
   its port or refuses it, `socket_event` (374-401) hands a socket's next
   datagram up within the credit granted, or its end once the queue is
   empty, `on_event` with `PacketEvent::Ended` (430-439) marks every
   socket ending, and `on_command` closes a socket by its handle
   (`MuxOp::Close`, 480-482) or by its own end (`DatagramCommand::End`,
   483-487, with `MuxEvent::Closed` from `take_event`, 520-528). `close`
   (285-291) removes the socket's slot, with its queue, and frees the port.

   Child ids are never reused: `Slots` gives each child a new generation
   (checked in verification/layer). A datagram's size is 0 (empty) or 1;
   it costs its size plus DatagramCost against Queue, as DATAGRAM_COST and
   QUEUE do. A datagram that fits the queue is also charged to the layer's
   budget (`env.budget().charge(cost)`, 358); when the budget has no room
   it is dropped and reported like one for a full queue, so Arrive may
   drop any datagram that fits. Each arriving packet is of some network
   and is checked or an observed copy. The code's lower port carries only
   CheckedIpPacket, so CheckChecked is the type, not a branch.

   The code visits sockets in the order of its `ready` list (`wake`,
   217-225) and gives a socket's send credit back (`MuxEvent::Credit`,
   381-384) before its next datagram; the model lets any socket with an
   event go next, which includes that order. The send side, that credit
   and ICMP answers are left out: none moves a received datagram. *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Ports,            \* the ports sockets bind
    Nets,             \* the networks packets come from
    Mine,             \* the endpoint's input network
    MaxChildren,      \* how many sockets are ever bound
    MaxArrivals,      \* how many packets arrive
    MaxGrant,         \* the most credit outstanding per socket
    Queue,            \* QUEUE, in units
    DatagramCost,     \* DATAGRAM_COST, in units
    CheckScope,       \* NetworkInput passes on one network's packets (the code)
    CheckChecked,     \* the lower port carries only CheckedIpPacket (the code)
    KeepEmpty,        \* take_in queues empty datagrams (the code)
    RemoveOnClose,    \* close removes the slot and its queue (the code)
    QueueInSocket,    \* the queue belongs to the socket, not the port (the code)
    FreePort,         \* close frees the port (the code)
    EndAfterQueue     \* the end goes up only once the queue is empty (the code)

ASSUME Mine \in Nets

Children == 1..MaxChildren
Arrivals == 1..MaxArrivals
NoChild == 0

Closed == [state |-> "free", port |-> 0, queue |-> <<>>, bytes |-> 0,
           granted |-> 0, ending |-> FALSE, ended |-> FALSE]

VARIABLES
    sock,         \* sock[c]: the socket of child c
    portOf,       \* portOf[p]: UdpLayer::ports
    orphan,       \* orphan[p]: a closed socket's queue, kept by port when
                  \* ~QueueInSocket
    nextChild,    \* the next child id Slots gives
    dg,           \* dg[d]: what arrived as datagram d
    arrived,      \* how many arrived
    delivered,    \* <<c, d>>: datagram d went up on child c
    refused,      \* datagrams take_in did not queue: filtered or no socket
    dropped,      \* datagrams dropped with a report (UdpReport::Dropped):
                  \* a full queue, or no room in the budget
    discarded,    \* datagrams queued on a socket that then closed
    inputEnded,   \* UdpLayer::input_ended
    byEnd,        \* children closed by their own end
    closedQ,      \* UdpLayer::closed
    closedSeen,   \* closedSeen[c]: MuxEvent::Closed(c) went up
    endedSeen,    \* endedSeen[c]: DatagramEvent::Ended went up
    afterEnded,   \* a datagram went up after its child's end
    afterClose,   \* a datagram or end went up for a closed child
    boundTo       \* boundTo[c]: the port child c was bound to

vars == <<sock, portOf, orphan, nextChild, boundTo, dg, arrived, delivered, refused,
          dropped, discarded, inputEnded, byEnd, closedQ, closedSeen,
          endedSeen, afterEnded, afterClose>>

Init ==
    /\ sock = [c \in Children |-> Closed]
    /\ portOf = [p \in Ports |-> NoChild]
    /\ orphan = [p \in Ports |-> <<>>]
    /\ nextChild = 1
    /\ dg = [d \in Arrivals |-> [port |-> 0, net |-> Mine, checked |-> TRUE,
                                  size |-> 0, for |-> NoChild]]
    /\ arrived = 0
    /\ delivered = {}
    /\ refused = {}
    /\ dropped = {}
    /\ discarded = {}
    /\ inputEnded = FALSE
    /\ byEnd = {}
    /\ closedQ = <<>>
    /\ closedSeen = [c \in Children |-> 0]
    /\ endedSeen = [c \in Children |-> 0]
    /\ afterEnded = FALSE
    /\ afterClose = FALSE
    /\ boundTo = [c \in Children |-> 0]

Seen == <<closedSeen, endedSeen, afterEnded, afterClose>>
Gone == [port |-> 0, net |-> Mine, checked |-> TRUE, size |-> 0, for |-> NoChild]
Cost(d) == dg[d].size + DatagramCost
RECURSIVE SumCost(_)
SumCost(q) == IF q = <<>> THEN 0 ELSE Cost(Head(q)) + SumCost(Tail(q))
Elems(q) == {q[i] : i \in 1..Len(q)}

-----------------------------------------------------------------------------
\* UdpControl::Bind on a free port.
Bind(p) ==
    /\ portOf[p] = NoChild /\ nextChild <= MaxChildren
    /\ LET c == nextChild
           q == IF QueueInSocket THEN <<>> ELSE orphan[p]
       IN /\ sock' = [sock EXCEPT ![c] = [Closed EXCEPT !.state = "open", !.port = p,
                                           !.queue = q, !.bytes = SumCost(q),
                                           !.ending = inputEnded]]
          /\ portOf' = [portOf EXCEPT ![p] = c]
          /\ orphan' = [orphan EXCEPT ![p] = <<>>]
          /\ nextChild' = c + 1
          /\ boundTo' = [boundTo EXCEPT ![c] = p]
    /\ UNCHANGED <<dg, arrived, delivered, refused, dropped, discarded,
                   inputEnded, byEnd, closedQ>>
    /\ UNCHANGED Seen

\* A packet the IP layer sorted to UDP reaches take_in. `room` is whether
\* the budget has room for the datagram (`env.budget().charge(cost)`).
Arrive(p, n, checked, size, room) ==
    /\ ~inputEnded /\ arrived < MaxArrivals
    /\ LET d == arrived + 1
           c == portOf[p]
           rec == [port |-> p, net |-> n, checked |-> checked, size |-> size, for |-> c]
           filtered == (CheckScope /\ n # Mine) \/ (CheckChecked /\ ~checked)
           \* No property reads what a refused or dropped datagram was, so
           \* those are all recorded alike, which keeps the state space small.
           gone == filtered \/ c = NoChild
                   \/ (KeepEmpty /\ (sock[c].bytes + size + DatagramCost > Queue \/ ~room))
       IN /\ arrived' = d
          /\ dg' = [dg EXCEPT ![d] = IF gone THEN Gone ELSE rec]
          /\ IF filtered \/ c = NoChild THEN
                /\ refused' = refused \cup {d}
                /\ UNCHANGED <<sock, dropped>>
             ELSE IF ~KeepEmpty /\ size = 0 THEN
                UNCHANGED <<sock, refused, dropped>>
             ELSE IF sock[c].bytes + size + DatagramCost > Queue \/ ~room THEN
                /\ dropped' = dropped \cup {d}
                /\ UNCHANGED <<sock, refused>>
             ELSE
                /\ sock' = [sock EXCEPT ![c].queue = Append(@, d),
                                        ![c].bytes = @ + size + DatagramCost]
                /\ UNCHANGED <<refused, dropped>>
    /\ UNCHANGED <<portOf, orphan, nextChild, boundTo, delivered, discarded, inputEnded,
                   byEnd, closedQ>>
    /\ UNCHANGED Seen

\* MuxOp::Credit: the port above grants one unit.
Grant(c) ==
    /\ sock[c].state = "open" /\ sock[c].granted < MaxGrant
    /\ sock' = [sock EXCEPT ![c].granted = @ + 1]
    /\ UNCHANGED <<portOf, orphan, nextChild, boundTo, dg, arrived, delivered, refused,
                   dropped, discarded, inputEnded, byEnd, closedQ>>
    /\ UNCHANGED Seen

\* What socket_event can still see of child c: a socket in its slot.
InSlot(c) == sock[c].state = "open" \/ (~RemoveOnClose /\ sock[c].state = "closed")

\* socket_event: the socket's next datagram, within its credit.
Deliver(c) ==
    /\ InSlot(c) /\ sock[c].granted > 0 /\ sock[c].queue # <<>>
    /\ LET d == Head(sock[c].queue) IN
       /\ sock' = [sock EXCEPT ![c].queue = Tail(@), ![c].granted = @ - 1,
                               ![c].bytes = @ - Cost(d)]
       /\ delivered' = delivered \cup {<<c, d>>}
       /\ afterEnded' = (afterEnded \/ endedSeen[c] > 0)
       /\ afterClose' = (afterClose \/ sock[c].state # "open")
    /\ UNCHANGED <<portOf, orphan, nextChild, boundTo, dg, arrived, refused, dropped,
                   discarded, inputEnded, byEnd, closedQ, closedSeen, endedSeen>>

\* socket_event: the socket's end, once its queue is empty.
EndEvent(c) ==
    /\ InSlot(c) /\ sock[c].ending /\ ~sock[c].ended
    /\ EndAfterQueue => sock[c].queue = <<>>
    /\ sock' = [sock EXCEPT ![c].ended = TRUE]
    /\ endedSeen' = [endedSeen EXCEPT ![c] = @ + 1]
    /\ afterClose' = (afterClose \/ sock[c].state # "open")
    /\ UNCHANGED <<portOf, orphan, nextChild, boundTo, dg, arrived, delivered, refused,
                   dropped, discarded, inputEnded, byEnd, closedQ, closedSeen,
                   afterEnded>>

\* on_event(PacketEvent::Ended).
InputEnd ==
    /\ ~inputEnded
    /\ inputEnded' = TRUE
    /\ sock' = [c \in Children |-> IF sock[c].state = "open"
                                    THEN [sock[c] EXCEPT !.ending = TRUE]
                                    ELSE sock[c]]
    /\ UNCHANGED <<portOf, orphan, nextChild, boundTo, dg, arrived, delivered, refused,
                   dropped, discarded, byEnd, closedQ>>
    /\ UNCHANGED Seen

\* UdpLayer::close, by the handle (MuxOp::Close) or by the child's own end
\* (DatagramCommand::End, which also says so with MuxEvent::Closed).
Close(c, own) ==
    /\ sock[c].state = "open"
    /\ LET p == sock[c].port
           q == sock[c].queue
       IN /\ sock' = [sock EXCEPT ![c] =
                        IF RemoveOnClose THEN [Closed EXCEPT !.state = "closed"]
                        ELSE [@ EXCEPT !.state = "closed"]]
          /\ portOf' = IF FreePort THEN [portOf EXCEPT ![p] = NoChild] ELSE portOf
          /\ orphan' = IF QueueInSocket THEN orphan ELSE [orphan EXCEPT ![p] = q]
          /\ discarded' = IF RemoveOnClose /\ QueueInSocket
                          THEN discarded \cup Elems(q) ELSE discarded
          /\ byEnd' = IF own THEN byEnd \cup {c} ELSE byEnd
          /\ closedQ' = IF own THEN Append(closedQ, c) ELSE closedQ
    /\ UNCHANGED <<nextChild, boundTo, dg, arrived, delivered, refused, dropped, inputEnded>>
    /\ UNCHANGED Seen

\* take_event: MuxEvent::Closed for a child closed by its own end.
TakeClosed ==
    /\ closedQ # <<>>
    /\ closedSeen' = [closedSeen EXCEPT ![Head(closedQ)] = @ + 1]
    /\ closedQ' = Tail(closedQ)
    /\ UNCHANGED <<sock, portOf, orphan, nextChild, boundTo, dg, arrived, delivered,
                   refused, dropped, discarded, inputEnded, byEnd>>
    /\ UNCHANGED <<endedSeen, afterEnded, afterClose>>

Next ==
    \/ \E p \in Ports : Bind(p)
    \/ \E p \in Ports, n \in Nets, ck \in BOOLEAN, sz \in {0, 1}, room \in BOOLEAN :
          Arrive(p, n, ck, sz, room)
    \/ \E c \in Children : Grant(c) \/ Deliver(c) \/ EndEvent(c)
    \/ InputEnd
    \/ \E c \in Children, own \in BOOLEAN : Close(c, own)
    \/ TakeClosed

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
Queued == UNION {Elems(sock[c].queue) : c \in Children} \cup UNION {Elems(orphan[p]) : p \in Ports}
Up == {pair[2] : pair \in delivered}

\* A datagram goes up only on the child it was queued for, which is bound
\* to its port: datagrams never cross sockets, even when a port is
\* closed and bound again.
NoCrossSocket ==
    \A pair \in delivered : dg[pair[2]].for = pair[1] /\ dg[pair[2]].port = boundTo[pair[1]]

\* Only the layer's own network reaches its sockets.
NoCrossScope == \A pair \in delivered : dg[pair[2]].net = Mine

\* Only checked packets reach its sockets: an observed copy never does.
OnlyChecked == \A pair \in delivered : dg[pair[2]].checked

\* Every datagram that arrived, empty ones included, is in exactly one
\* place: refused, dropped with a report (a full queue or no room in the
\* budget), queued, gone up, or discarded with its socket.
Accounted ==
    \A d \in 1..arrived :
        Cardinality({S \in {refused, dropped, Queued, Up, discarded} : d \in S}) = 1

\* A socket holds at most Queue units, so at most Queue datagrams however
\* small: an empty one costs DatagramCost.
QueueBounded == \A c \in Children : Len(sock[c].queue) <= Queue

\* A closed child hears nothing more, except one MuxEvent::Closed when it
\* closed by its own end.
RetiredSilent ==
    /\ ~afterClose
    /\ \A c \in Children : closedSeen[c] <= 1 /\ (closedSeen[c] = 1 => c \in byEnd)

\* A socket's end goes up once, after its last datagram.
EndedLast == ~afterEnded /\ \A c \in Children : endedSeen[c] <= 1

\* The port map names exactly the open sockets.
PortsMatch ==
    \A p \in Ports :
        portOf[p] # NoChild <=> \E c \in Children : sock[c].state = "open" /\ sock[c].port = p
=============================================================================
