------------------------------ MODULE Staging ------------------------------
(* How a world installs a host on its machines, in
   src/stdlib/world/net/hosts.rs.

   `Installation::place_inner` stages every address of the host
   (`Machine::stage`) and prepares the host's services on it
   (`Machine::prepare`); only once all of them are prepared does it publish
   each new machine's route (`Router::add`) and commit
   (`PreparedMachine::commit`). `Installation::place_on_lan` and
   `Installation::gateway` stage and prepare one address, then join it to
   the network, which may fail, and commit. The world's lock is held for
   the whole installation, so installations do not interleave.

   `Machine::stage` returns the machine already at the address, or builds
   a new one: `network::endpoint::prepare` builds its IP layer from the
   host's `packet::Factory`, its TCP from `tcp::Factory`
   (`tcp::prepare_transport`) and its UDP (`udp::prepare_transport`), and
   the packet dispatcher's future, `endpoint::drive`, which owns both
   transports' packet drivers. Nothing runs: the future is spawned by the
   `start` closure that `commit` calls.

   `Machine::prepare` binds, for each declaration in order, a UDP socket
   (`udp::Endpoint::bind`) or, for a TCP port the machine does not serve
   yet, a listener (`tcp::Endpoint::listen`), and checks sharing and TLS
   names; any of these may fail. On an existing machine the sockets and
   listeners are live in its transports while they are staged. A failure
   returns before commit, and dropping the prepared ports and machines
   releases them: `udp::Socket::drop`, `tcp::Listener::drop`, and
   `PacketDriver::drop`, which stops a transport whose task never ran.

   `Machine::add`, called by `commit` after `start`, attaches the
   application factories: `udp::Socket::attach` for each socket and
   `tcp::Listener::attach` for each new listener, whose
   `tcp::Application` builds the stack for each connection. A TCP port the
   machine served already keeps its listener and factory, which reads the
   port's services when each connection opens.

   Ports here stand for both TCP ports and UDP ports; a declaration of a
   port the preparation already took is shared. Every reason a declaration
   may fail (a port another host serves, TLS names, sharing) is one
   nondeterministic failure. Programs, names and the addresses' family are
   left out.

   Source lines, in src/stdlib/world/net/hosts.rs unless named (at the
   commit that adds this model):
     Begin        1127 `place_inner`, 1196 `place_on_lan`, 1259 `gateway`
     Stage        1170, 1231, 1265 (the calls); 1517 `Machine::stage`, 1532
                  `network::endpoint::prepare` (endpoint.rs 228), 1592 the
                  unspawned task
     Declare      1598 `Machine::prepare`: 1607 `bind`, 1622 `listen`
     NextAddress  1168-1174 (the address loop)
     Fail         the `?` at 1171, 1174, 1232, 1238, 1266, 1268, and the
                  drops: udp.rs 240 and tcp.rs 1096 `PacketDriver::drop`
     Commit       1175-1180 (`Router::add`, then commit), 1236-1240 (the
                  LAN join), 1268-1273 (the gateway); 1487
                  `PreparedMachine::commit`; 1764 `Machine::add`, 1769 and
                  601 (`udp::Socket::attach`), 1798 (`tcp::Listener::attach`)
     Connect      endpoint.rs 54 `drive`, the dispatcher every packet of the
                  machine passes; 1810 the factory *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    V4, V6,         \* a host's two addresses, staged in this order
    Ports,          \* ports a host may declare
    MaxDecls,       \* declarations per host
    MaxInstalls,    \* installations in a run
    Joins,          \* TRUE: a join after preparation may fail (LAN, gateway)
    PublishEarly,   \* TRUE: a new machine's route is published when staged
    StartEarly,     \* TRUE: a new machine's task starts when staged
    AttachEarly,    \* TRUE: a factory is attached when its port is bound
    KeepOnFailure,  \* TRUE: a failure leaves what preparation bound
    BuildAgain      \* TRUE: staging builds a driver for an existing machine

AddrList == <<V4, V6>>
Addrs == {V4, V6}

VARIABLES
    phase,      \* "idle" | "staging" | "joining"
    outcome,    \* "none" | "failed" | "committed": the last installation's
    installs,   \* installations begun
    placed,     \* the addresses of this installation
    targets,    \* the addresses left to stage, in order
    staged,     \* the addresses staged by this installation
    decls,      \* this installation's declarations
    pos,        \* the next declaration at the address being prepared
    exists,     \* exists[a]: a machine is in the world at a, running
    route,      \* route[a]: a route to a is published
    drivers,    \* drivers[a]: packet dispatchers running at a
    built,      \* built[a]: a dispatcher built by this installation at a
    ports,      \* ports[a]: the ports a's machine serves
    attached,   \* attached[a]: the ports with an application factory
    temp,       \* temp[a]: ports this preparation bound at a
    before,     \* the world when this installation began
    served      \* <<a, p>>: an application was built for a connection

vars == <<phase, outcome, installs, placed, targets, staged, decls, pos,
          exists, route, drivers, built, ports, attached, temp, before, served>>

World == [exists |-> exists, route |-> route, drivers |-> drivers,
          ports |-> ports, attached |-> attached]

\* The ports bound in a's transports.
Bound(a) == ports[a] \cup temp[a]

Declared == {decls[i] : i \in DOMAIN decls}

Init ==
    /\ phase = "idle" /\ outcome = "none" /\ installs = 0
    /\ placed = {} /\ targets = <<>> /\ staged = {} /\ decls = <<>> /\ pos = 1
    /\ exists \in [Addrs -> BOOLEAN]
    /\ route = exists
    /\ drivers = [a \in Addrs |-> IF exists[a] THEN 1 ELSE 0]
    /\ built = [a \in Addrs |-> FALSE]
    /\ ports \in [Addrs -> SUBSET Ports]
    /\ \A a \in Addrs : ~exists[a] => ports[a] = {}
    /\ attached = ports
    /\ temp = [a \in Addrs |-> {}]
    /\ before = [exists |-> exists, route |-> route, drivers |-> drivers,
                 ports |-> ports, attached |-> attached]
    /\ served = {}

Decls == UNION {[1..n -> Ports] : n \in 1..MaxDecls}

\* A host's installation begins: Installation::place.
Begin ==
    /\ phase = "idle" /\ installs < MaxInstalls
    /\ \E at \in SUBSET Addrs \ {{}}, d \in Decls :
        /\ placed' = at
        /\ targets' = SelectSeq(AddrList, LAMBDA a : a \in at)
        /\ decls' = d
    /\ phase' = "staging" /\ installs' = installs + 1 /\ pos' = 1
    /\ staged' = {} /\ before' = World
    /\ UNCHANGED <<outcome, exists, route, drivers, built, ports, attached,
                   temp, served>>

Current == Head(targets)

\* Machine::stage: the machine there, or a new one built and not started.
Stage ==
    /\ phase = "staging" /\ targets # <<>> /\ Current \notin staged
    /\ LET a == Current
           build == ~exists[a] \/ BuildAgain
       IN
       /\ staged' = staged \cup {a}
       /\ route' = IF PublishEarly /\ ~exists[a]
                   THEN [route EXCEPT ![a] = TRUE] ELSE route
       /\ drivers' = IF StartEarly /\ build
                     THEN [drivers EXCEPT ![a] = @ + 1] ELSE drivers
       /\ built' = [built EXCEPT ![a] = build /\ ~StartEarly]
    /\ UNCHANGED <<phase, outcome, installs, placed, targets, decls, pos,
                   exists, ports, attached, temp, before, served>>

\* Machine::prepare takes the next declaration at the current address: a
\* port neither served nor taken by this preparation is bound.
Declare ==
    /\ phase = "staging" /\ targets # <<>> /\ Current \in staged
    /\ pos <= Len(decls)
    /\ LET a == Current
           p == decls[pos]
           new == p \notin Bound(a)
       IN
       /\ temp' = IF new THEN [temp EXCEPT ![a] = @ \cup {p}] ELSE temp
       /\ attached' = IF new /\ AttachEarly
                      THEN [attached EXCEPT ![a] = @ \cup {p}] ELSE attached
    /\ pos' = pos + 1
    /\ UNCHANGED <<phase, outcome, installs, placed, targets, staged, decls,
                   exists, route, drivers, built, ports, before, served>>

\* Every declaration at the current address is prepared: the next address.
NextAddress ==
    /\ phase = "staging" /\ targets # <<>> /\ Current \in staged
    /\ pos > Len(decls)
    /\ targets' = Tail(targets) /\ pos' = 1
    /\ phase' = IF Tail(targets) = <<>> /\ Joins THEN "joining" ELSE "staging"
    /\ UNCHANGED <<outcome, installs, placed, staged, decls, exists, route,
                   drivers, built, ports, attached, temp, before, served>>

\* A failure: of a declaration, or of the join. The prepared ports and
\* machines are dropped, which releases what they bound and every driver
\* they built.
Fail ==
    /\ phase \in {"staging", "joining"}
    /\ phase' = "idle" /\ outcome' = "failed"
    /\ temp' = IF KeepOnFailure THEN temp ELSE [a \in Addrs |-> {}]
    /\ built' = [a \in Addrs |-> FALSE]
    /\ targets' = <<>> /\ staged' = {}
    /\ UNCHANGED <<installs, placed, decls, pos, exists, route, drivers,
                   ports, attached, before, served>>

\* Everything is prepared, and joined where that is asked: the routes are
\* published, the new machines start and enter the world, and the
\* factories are attached (Router::add, PreparedMachine::commit,
\* Machine::add). Commit cannot fail.
Commit ==
    /\ \/ phase = "staging" /\ targets = <<>> /\ ~Joins
       \/ phase = "joining"
    /\ phase' = "idle" /\ outcome' = "committed"
    /\ route' = [a \in Addrs |-> route[a] \/ a \in staged]
    /\ drivers' = [a \in Addrs |-> IF built[a] THEN drivers[a] + 1 ELSE drivers[a]]
    /\ exists' = [a \in Addrs |-> exists[a] \/ a \in staged]
    /\ ports' = [a \in Addrs |-> ports[a] \cup temp[a]]
    /\ attached' = [a \in Addrs |-> attached[a] \cup temp[a]]
    /\ temp' = [a \in Addrs |-> {}]
    /\ built' = [a \in Addrs |-> FALSE]
    /\ staged' = {}
    /\ UNCHANGED <<installs, placed, targets, decls, pos, before, served>>

\* A connection reaches port p at a: its packets are dispatched only by a
\* running driver on a published route, and only a port with a factory
\* builds an application for it.
Connect(a, p) ==
    /\ route[a] /\ drivers[a] > 0 /\ p \in attached[a]
    /\ served' = served \cup {<<a, p>>}
    /\ UNCHANGED <<phase, outcome, installs, placed, targets, staged, decls,
                   pos, exists, route, drivers, built, ports, attached, temp,
                   before>>

Next ==
    \/ Begin \/ Stage \/ Declare \/ NextAddress \/ Fail \/ Commit
    \/ \E a \in Addrs, p \in Ports : Connect(a, p)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* Nothing a preparation does is visible before it commits: a route only
\* to a machine in the world, a running driver only there, and a factory
\* only on a port the machine serves.
RouteOnlyToMachines == \A a \in Addrs : route[a] => exists[a]
RunsOnlyInTheWorld == \A a \in Addrs : drivers[a] > 0 => exists[a]
FactoriesOnlyOnServedPorts == \A a \in Addrs : attached[a] \subseteq ports[a]

\* An application is built only for a port its machine serves.
ServedOnlyInstalled == \A s \in served : s[2] \in ports[s[1]]

\* One packet dispatcher per machine: no second IP pass, no duplicate driver.
OneDispatcher == \A a \in Addrs : drivers[a] <= 1

\* A failed installation leaves the world as it found it, with nothing
\* bound for it.
FailureLeavesTheWorld ==
    phase = "idle" /\ outcome = "failed"
    => World = before /\ \A a \in Addrs : temp[a] = {}

\* A committed installation serves every declaration at every address, on
\* a published route with one running driver, each port with its factory.
CommitServesAll ==
    phase = "idle" /\ outcome = "committed"
    => \A a \in placed :
        /\ exists[a] /\ route[a] /\ drivers[a] = 1
        /\ Declared \subseteq ports[a] /\ Declared \subseteq attached[a]
=============================================================================
