----------------------------- MODULE Binding -----------------------------
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Ports, Ephemeral, NoPort
SmallEphemeral == <<49152, 65535>>
ASSUME /\ 0 \in Ports
       /\ Len(Ephemeral) > 0
       /\ {Ephemeral[i] : i \in 1..Len(Ephemeral)} \subseteq Ports \ {0}
       /\ Cardinality({Ephemeral[i] : i \in 1..Len(Ephemeral)}) = Len(Ephemeral)
       /\ NoPort \notin Ports

VARIABLES listening, clients, reserved, cursor
allocation == <<listening, clients, reserved, cursor>>

Advance(i) == IF i = Len(Ephemeral) THEN 1 ELSE i + 1
At(offset) == ((cursor - 1 + offset) % Len(Ephemeral)) + 1
Available == {n \in 0..(Len(Ephemeral) - 1) : reserved[Ephemeral[At(n)]] = 0}

AllocationInit ==
    /\ listening = {}
    /\ clients = [p \in Ports |-> NoPort]
    /\ reserved = [p \in Ports |-> 0]
    /\ cursor \in 1..Len(Ephemeral)

\* Endpoint listen checks both maps under one state lock.
Listen(p) ==
    /\ p \notin listening /\ reserved[p] = 0
    /\ listening' = listening \cup {p}
    /\ reserved' = [reserved EXCEPT ![p] = @ + 1]
    /\ UNCHANGED <<clients, cursor>>

\* Listener drop frees its reservation. Accepted server connections do not
\* own this reservation, and therefore do not delay a later listener.
DropListener(p) ==
    /\ p \in listening
    /\ listening' = listening \ {p}
    /\ reserved' = [reserved EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<clients, cursor>>

\* The loop advances even past occupied ports, stopping at the first free
\* port. A complete unsuccessful traversal returns to the initial cursor.
Connect(destination) ==
    /\ Available # {}
    /\ LET offset == CHOOSE n \in Available : \A m \in Available : n <= m
           index == At(offset)
           port == Ephemeral[index]
       IN /\ clients' = [clients EXCEPT ![port] = destination]
          /\ reserved' = [reserved EXCEPT ![port] = @ + 1]
          /\ cursor' = Advance(index)
    /\ UNCHANGED listening

\* remove_conn releases only outgoing reservations. Handle drop merely
\* orphans a connection; this transition is its later actual removal.
RemoveClient(p) ==
    /\ clients[p] # NoPort
    /\ clients' = [clients EXCEPT ![p] = NoPort]
    /\ reserved' = [reserved EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<listening, cursor>>

AllocationNext == \E p \in Ports : Listen(p) \/ DropListener(p) \/
                                      Connect(p) \/ RemoveClient(p)

AllocationTypes ==
    /\ listening \subseteq Ports
    /\ clients \in [Ports -> Ports \cup {NoPort}]
    /\ reserved \in [Ports -> 0..2]
    /\ cursor \in 1..Len(Ephemeral)
ReservationConservation ==
    \A p \in Ports : reserved[p] =
        (IF p \in listening THEN 1 ELSE 0) + (IF clients[p] # NoPort THEN 1 ELSE 0)
ExclusiveReservation == \A p \in listening : clients[p] = NoPort
EphemeralSource ==
    \A p \in Ports : clients[p] # NoPort => p \in {Ephemeral[i] : i \in 1..Len(Ephemeral)}
AvailableMeansAllocatable ==
    (\E p \in {Ephemeral[i] : i \in 1..Len(Ephemeral)} : reserved[p] = 0)
    <=> Available # {}
LiteralDestination ==
    [][\A destination \in Ports : Connect(destination) =>
        \A p \in Ports : clients'[p] # clients[p] => clients'[p] = destination]_allocation

\* Plain nonsharing host services: prepare owns temporary listeners until
\* every declaration succeeds. A duplicate rejects the whole preparation.
\* Machine::stage prepares the shared packet driver before these listeners;
\* PreparedMachine::commit starts it only after preparation succeeds.
\* Source lines (src/stdlib/world/net/hosts.rs): Machine::prepare 1598,
\* its listen 1622, PreparedMachine::commit 1487, Machine::add 1764. Listen
\* goes through Host::request (src/stdlib/network/tcp.rs 1448), which never
\* queues it, so a failed listen leaves the transport nothing to take later;
\* Unlisten, sent by Listener::drop, waits in Host::controls if refused.
\* World-layers Staging.tla models the same preparation across machines,
\* routes, packet dispatchers and application factories.
VARIABLES installed, held, pending, request, position, phase, before
preparation == <<installed, held, pending, request, position, phase, before>>
PreparationInit ==
    /\ installed = {} /\ held = {} /\ pending = {}
    /\ request = <<>> /\ position = 1 /\ phase = "idle" /\ before = {}
Begin(declarations) ==
    /\ phase = "idle"
    /\ request' = declarations /\ position' = 1 /\ phase' = "preparing"
    /\ before' = installed
    /\ UNCHANGED <<installed, held, pending>>
Prepare ==
    /\ phase = "preparing" /\ position <= Len(request)
    /\ LET p == request[position]
       IN IF p \in installed \cup pending
          THEN /\ phase' = "rejected"
               /\ held' = held \ pending /\ pending' = {}
               /\ UNCHANGED position
          ELSE /\ held' = held \cup {p} /\ pending' = pending \cup {p}
               /\ position' = position + 1 /\ UNCHANGED phase
    /\ UNCHANGED <<installed, request, before>>
Commit ==
    /\ phase = "preparing" /\ position > Len(request)
    /\ installed' = installed \cup pending /\ pending' = {}
    /\ phase' = "committed"
    /\ UNCHANGED <<held, request, position, before>>
Finish ==
    /\ phase \in {"rejected", "committed"} /\ phase' = "idle"
    /\ UNCHANGED <<installed, held, pending, request, position, before>>
Requests == UNION {[1..n -> Ports] : n \in 1..3}
PreparationNext ==
    (\E declarations \in Requests : Begin(declarations)) \/ Prepare \/ Commit \/ Finish
PreparationTypes ==
    /\ installed \subseteq Ports /\ held \subseteq Ports /\ pending \subseteq Ports
    /\ before \subseteq Ports /\ request \in {<<>>} \cup Requests
    /\ position \in 1..4 /\ phase \in {"idle", "preparing", "rejected", "committed"}
ListenerOwnership == held = installed \cup pending
NoPrematurePublish == phase \in {"preparing", "rejected"} => installed = before
RejectedReleasesListeners == phase = "rejected" => held = before
vars == <<allocation, preparation>>
AllocationSpec == AllocationInit /\ PreparationInit /\
                  [][AllocationNext /\ UNCHANGED preparation]_vars
PreparationSpec == AllocationInit /\ PreparationInit /\
                   [][PreparationNext /\ UNCHANGED allocation]_vars
=============================================================================
