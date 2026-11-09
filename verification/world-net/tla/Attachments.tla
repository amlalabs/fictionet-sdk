---------------------------- MODULE Attachments ----------------------------
(* The attachment lifecycle of the world network,
   src/stdlib/world/net/attachments.rs, and the bookkeeping that names a
   sandbox for each address.

   A filtered sandbox (`filter`, `Attached`) attaches, binds one address of
   the sandboxes' subnet (`Filter::sent_v4`, `Bindings::bind`,
   `Filter::bound_now`) and detaches (`Attached::drop`). A routed sandbox
   (`Context::routed`, `Routed`) is the route at 0.0.0.0/0 and detaches in
   `Routed::drop`. The router follows through its edit queue
   (`Router::add`, `Edit::Route` in `route::router`) and sees a link close
   some time later (`ports::Event::Closed`). The connections are the ones
   `abort_peers` resets on the machines; the packets are the ones a machine
   attributes with `Hooks::sandbox_at` when they arrive.

   Since the world rebuild on the TCP, UDP and IP layers, a machine names
   the sandbox when the transport opens the connection's child, before the
   application exists: the `budget` selector and `make` factory that
   `Machine::add` gives `tcp::Listener::attach` (src/stdlib/world/net/hosts.rs
   1798-1867, `Hooks::sandbox_at` at 1807 and 1818). `abort_peers` is
   `Machines::abort_peers` (hosts.rs 1302), which reads the peers through the
   transport's `EndpointState::peers` (src/stdlib/network/tcp/factory.rs 35)
   and sends `TcpControl::AbortPeers` (`tcp::Endpoint::abort_peers`,
   src/stdlib/network/tcp.rs 1686); a transport that refuses the command for
   now gets it again (`Host::control`, tcp.rs 1432;
   world-layers/tla/Admission.tla). Closing
   an application does not end the modeled connection. Packet dispatch
   and protocol bytes are outside this model. *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    Filtered,      \* names of sandboxes the network filters: Net's default
    Routed,        \* names of sandboxes attached as the route at 0.0.0.0/0
    Addrs,         \* the sandboxes' subnet: what a filtered sandbox may bind
    Hosts,         \* the machines' addresses
    Outside,       \* addresses only the default route has
    MaxLife,       \* how many times each name may attach
    None,          \* no attachment
    Host,          \* what carried a connection a host made: no sandbox
    OwnByRoutesTo, \* TRUE: a route owns the sources `Destinations::routes_to`
                   \* accepts, in `Hooks::sandbox_of` and `Routed::drop` alike.
                   \* FALSE: the code at 8ccf47fae: `sandbox_of` names the
                   \* route for every address its prefix holds, and
                   \* `Routed::drop` resets every peer no sandbox binds
    KeepByAddr     \* TRUE: `Hooks::by_addr` keeps an entry after its sandbox
                   \* detaches, until another binds the address (the code)

Names == Filtered \cup Routed
Peers == Addrs \cup Hosts \cup Outside
Ids == [name : Names, life : 1..MaxLife]
Id(n, k) == [name |-> n, life |-> k]

VARIABLES
    life,       \* life[n]: how often n has attached; Id(n, life[n]) is its latest
    open,       \* attachments whose sandbox end is open
    closing,    \* attachments whose sandbox end dropped, world side not yet
    attached,   \* Hooks::attached: the attachments with an entry
    lease,      \* lease[a]: Leases::by_addr with bound: the attachment at a
    last,       \* last[a]: the attachment that bound a most recently (history)
    byAddr,     \* Hooks::by_addr
    routeOwner, \* Hooks::routes at 0.0.0.0/0: the last routed attachment
    table,      \* table[a]: the router's /32 route for a: whose link
    routePort,  \* the router's default route: whose link
    edits,      \* the router's pending edits, in order
    conns,      \* connections open on machines: [peer, via]
    inflight,   \* packets on their way to a machine: [peer, via]
    wrong,      \* a drop reset a connection it did not carry
    misattributed \* a connection or packet was put down to the wrong sandbox

vars == <<life, open, closing, attached, lease, last, byAddr, routeOwner,
          table, routePort, edits, conns, inflight, wrong, misattributed>>

Init ==
    /\ life = [n \in Names |-> 0]
    /\ open = {} /\ closing = {} /\ attached = {}
    /\ lease = [a \in Addrs |-> None]
    /\ last = [a \in Addrs |-> None]
    /\ byAddr = [a \in Addrs |-> None]
    /\ routeOwner = None
    /\ table = [a \in Addrs |-> None]
    /\ routePort = None
    /\ edits = <<>>
    /\ conns = {} /\ inflight = {}
    /\ wrong = FALSE /\ misattributed = FALSE

Current(n) == Id(n, life[n])
Live(n) == life[n] > 0 /\ Current(n) \in open
Held(id) == {a \in Addrs : lease[a] = id}

\* Destinations::routes_to at 0.0.0.0/0: an address no subnet, gateway,
\* machine or longer route has. Here that is an outside address.
RoutesTo(p) == p \in Outside

\* The sources Hooks::sandbox_of puts down to the route.
RouteHas(p) == IF OwnByRoutesTo THEN RoutesTo(p) ELSE TRUE

\* Hooks::sandbox_of: the sandbox that bound the address, else the route.
SandboxOf(p) ==
    IF p \in Addrs /\ byAddr[p] # None THEN byAddr[p]
    ELSE IF routeOwner # None /\ RouteHas(p) THEN routeOwner
    ELSE None

\* The peers Routed::drop resets.
Resets(p) ==
    IF OwnByRoutesTo THEN RoutesTo(p)
    ELSE p \notin {a \in Addrs : byAddr[a] # None}

\* Whether putting a connection or packet from p, carried by via, down to
\* SandboxOf(p) is right. The network knows a sender by its address, so a
\* subnet address names its sender, or the sandbox that bound the address
\* most recently once it changed hands. An outside address names the route's
\* sandbox. A host's own connection names no sandbox.
Attributed(p, via) ==
    LET s == SandboxOf(p) IN
    IF via = Host THEN s = None
    ELSE IF p \in Addrs THEN s = via \/ s = last[p]
    ELSE s # None /\ s.name = via.name

-----------------------------------------------------------------------------
\* The sandbox called n attaches: Attached::new, or Context::routed, which
\* takes the route's entry at once and asks the router for the route.
Attach(n) ==
    /\ life[n] < MaxLife
    /\ ~Live(n)
    /\ LET id == Id(n, life[n] + 1) IN
       /\ life' = [life EXCEPT ![n] = @ + 1]
       /\ open' = open \cup {id}
       /\ attached' = attached \cup {id}
       /\ IF n \in Routed
          THEN /\ routeOwner' = id
               /\ edits' = Append(edits, [kind |-> "route", id |-> id])
          ELSE UNCHANGED <<routeOwner, edits>>
    /\ UNCHANGED <<closing, lease, last, byAddr, table, routePort, conns,
                   inflight, wrong, misattributed>>

\* A filtered sandbox binds a free address: Bindings::bind gives Bind::New,
\* and Filter::bound_now records it and asks the router for a /32.
Bind(n, a) ==
    /\ n \in Filtered /\ Live(n)
    /\ lease[a] = None /\ Held(Current(n)) = {}
    /\ lease' = [lease EXCEPT ![a] = Current(n)]
    /\ last' = [last EXCEPT ![a] = Current(n)]
    /\ byAddr' = [byAddr EXCEPT ![a] = Current(n)]
    /\ edits' = Append(edits, [kind |-> "host", addr |-> a, id |-> Current(n)])
    /\ UNCHANGED <<life, open, closing, attached, routeOwner, table, routePort,
                   conns, inflight, wrong, misattributed>>

\* Routed::drop: the attachment goes, and the connections it reset with it.
RoutedDropped(id) ==
    /\ attached' = attached \ {id}
    /\ closing' = closing \ {id}
    /\ open' = open \ {id}
    /\ conns' = {c \in conns : ~Resets(c.peer)}
    /\ wrong' = (wrong \/ \E c \in conns : Resets(c.peer) /\ c.via # id)

\* The router takes a /32 edit: Table::unroute, then Table::insert.
EditHost ==
    /\ edits # <<>> /\ Head(edits).kind = "host"
    /\ table' = [table EXCEPT ![Head(edits).addr] = Head(edits).id]
    /\ edits' = Tail(edits)
    /\ UNCHANGED <<life, open, closing, attached, lease, last, byAddr,
                   routeOwner, routePort, conns, inflight, wrong, misattributed>>

\* The router takes a route edit. The old route's interface, left with no
\* prefix, is dropped: Ports::close, so Routed::drop, at once.
EditRoute ==
    /\ edits # <<>> /\ Head(edits).kind = "route"
    /\ LET new == Head(edits).id IN
       /\ routePort' = new
       /\ IF routePort # None /\ routePort # new
          THEN RoutedDropped(routePort)
          ELSE UNCHANGED <<attached, closing, open, conns, wrong>>
    /\ edits' = Tail(edits)
    /\ UNCHANGED <<life, lease, last, byAddr, routeOwner, table, inflight,
                   misattributed>>

\* The router sees a filtered sandbox's link close, which the end of its
\* filter task closed: Event::Closed, Table::remove_port.
RouterSeesLinkClosed(a) ==
    /\ table[a] # None /\ table[a] \notin attached
    /\ table' = [table EXCEPT ![a] = None]
    /\ UNCHANGED <<life, open, closing, attached, lease, last, byAddr,
                   routeOwner, routePort, edits, conns, inflight, wrong,
                   misattributed>>

\* The router sees the routed sandbox's end closed: Routed::poll_recv gives
\* Closed, the port is closed and the Routed dropped.
RouterSeesRouteClosed ==
    /\ routePort # None /\ routePort \in closing
    /\ RoutedDropped(routePort)
    /\ routePort' = None
    /\ UNCHANGED <<life, lease, last, byAddr, routeOwner, table, edits,
                   inflight, misattributed>>

\* What n's attachment can send to a machine: a filtered sandbox from its
\* bound address, a routed one from an outside address once the router
\* sends the route's way. A connection also needs the answers to come back.
Carries(n, p) ==
    /\ Live(n)
    /\ IF n \in Filtered THEN p \in Addrs /\ lease[p] = Current(n)
       ELSE RoutesTo(p) /\ routePort = Current(n)

Answered(n, p) ==
    IF n \in Filtered THEN table[p] = Current(n) ELSE TRUE

\* A machine accepts a connection from n's attachment and names a sandbox
\* for it: the factory in `Machine::add` (hosts.rs 1810), Hooks::sandbox_at.
Connect(n, p) ==
    /\ Carries(n, p) /\ Answered(n, p)
    /\ conns' = conns \cup {[peer |-> p, via |-> Current(n)]}
    /\ misattributed' = (misattributed \/ ~Attributed(p, Current(n)))
    /\ UNCHANGED <<life, open, closing, attached, lease, last, byAddr,
                   routeOwner, table, routePort, edits, inflight, wrong>>

\* A host connects to another host.
ConnectHost(h) ==
    /\ conns' = conns \cup {[peer |-> h, via |-> Host]}
    /\ misattributed' = (misattributed \/ ~Attributed(h, Host))
    /\ UNCHANGED <<life, open, closing, attached, lease, last, byAddr,
                   routeOwner, table, routePort, edits, inflight, wrong>>

\* A connection ends by itself.
Close(c) ==
    /\ conns' = conns \ {c}
    /\ UNCHANGED <<life, open, closing, attached, lease, last, byAddr,
                   routeOwner, table, routePort, edits, inflight, wrong,
                   misattributed>>

\* A packet from n's attachment is on its way to a machine.
Send(n, p) ==
    /\ Carries(n, p)
    /\ inflight' = inflight \cup {[peer |-> p, via |-> Current(n)]}
    /\ UNCHANGED <<life, open, closing, attached, lease, last, byAddr,
                   routeOwner, table, routePort, edits, conns, wrong,
                   misattributed>>

\* The packet arrives and the machine names a sandbox for it.
Arrive(pk) ==
    /\ inflight' = inflight \ {pk}
    /\ misattributed' = (misattributed \/ ~Attributed(pk.peer, pk.via))
    /\ UNCHANGED <<life, open, closing, attached, lease, last, byAddr,
                   routeOwner, table, routePort, edits, conns, wrong>>

\* The sandbox end drops: the name is free at once; the world side follows.
Detach(n) ==
    /\ Live(n)
    /\ open' = open \ {Current(n)}
    /\ closing' = closing \cup {Current(n)}
    /\ UNCHANGED <<life, attached, lease, last, byAddr, routeOwner, table,
                   routePort, edits, conns, inflight, wrong, misattributed>>

\* Attached::drop, at the end of the filter task: the connections from its
\* addresses are reset, its leases released, by_addr kept.
FilteredDropped(id) ==
    /\ id \in closing /\ id.name \in Filtered
    /\ attached' = attached \ {id}
    /\ closing' = closing \ {id}
    /\ conns' = {c \in conns : c.peer \notin Held(id)}
    /\ wrong' = (wrong \/ \E c \in conns : c.peer \in Held(id) /\ c.via # id)
    /\ lease' = [a \in Addrs |-> IF lease[a] = id THEN None ELSE lease[a]]
    /\ byAddr' = IF KeepByAddr THEN byAddr
                 ELSE [a \in Addrs |-> IF byAddr[a] = id THEN None ELSE byAddr[a]]
    /\ UNCHANGED <<life, open, last, routeOwner, table, routePort, edits,
                   inflight, misattributed>>

Router == EditHost \/ EditRoute \/ RouterSeesRouteClosed
          \/ \E a \in Addrs : RouterSeesLinkClosed(a)
Drops == \E id \in Ids : FilteredDropped(id)

Next ==
    \/ \E n \in Names : Attach(n) \/ Detach(n)
    \/ \E n \in Filtered, a \in Addrs : Bind(n, a)
    \/ \E n \in Names, p \in Peers : Connect(n, p) \/ Send(n, p)
    \/ \E h \in Hosts : ConnectHost(h)
    \/ \E c \in conns : Close(c)
    \/ \E pk \in inflight : Arrive(pk)
    \/ Router
    \/ Drops

Spec == Init /\ [][Next]_vars /\ WF_vars(Router) /\ WF_vars(Drops)

-----------------------------------------------------------------------------
\* One attachment per address.
LeaseExclusive ==
    \A a, b \in Addrs : lease[a] # None /\ lease[a] = lease[b] => a = b

\* by_addr names the attachment that bound each address most recently,
\* which is its holder while one holds it.
ByAddrNamesLast == \A a \in Addrs : byAddr[a] = last[a]

\* An attachment has its entry, so its budget, exactly while it is alive.
EntryWhileAlive == attached = open \cup closing

\* No connection outlives the attachment that carried it.
NoStaleConnections == \A c \in conns : c.via # Host => c.via \in attached

\* A detaching attachment resets only connections it carried.
AbortsOnlyOwn == ~wrong

\* Every connection and packet is put down to its sender, or to the latest
\* holder of a subnet address that changed hands.
Attribution == ~misattributed

\* Once the router has taken every edit, each bound address goes out on
\* its holder's link.
TableFollowsLeases ==
    edits = <<>> => \A a \in Addrs : lease[a] # None => table[a] = lease[a]

\* A /32 to a dropped attachment's link goes.
StaleRoutesGo ==
    \A a \in Addrs :
        [](table[a] \notin attached \cup {None}
           => <>(table[a] \in attached \cup {None}))

\* A dropped sandbox end is followed by its world side.
DropsFinish == \A id \in Ids : [](id \in closing => <>(id \notin closing))
=============================================================================
