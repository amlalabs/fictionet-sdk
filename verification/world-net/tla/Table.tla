------------------------------- MODULE Table -------------------------------
(* The router's route table in src/stdlib/network/route.rs: `Table` with
   its three views (`routes`, `by_port`, `lengths`), as `router` drives
   them. An `Edit::Route` adds a port for a set of prefixes, moving each
   from its old port (`Table::unroute`, `Table::insert`) and closing an old
   port left with none (`Ports::close`); an `Event::Closed` drops every
   route of the port (`Table::remove_port`). `Table::best` walks the
   lengths in use from the longest.

   Addresses have two bits, so the prefixes are a /0, two /1 and four /2,
   enough for every way one route can shadow another. *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Ports,        \* the slots a port can take
    NoPort,
    CloseOrphans, \* a port left with no prefix is closed (the code)
    CountLengths  \* insert counts the prefix's length (the code)

Addrs == 0..3
Lengths == 0..2
Prefixes == {[net |-> 0, len |-> 0]}
            \cup {[net |-> n, len |-> 1] : n \in {0, 2}}
            \cup {[net |-> n, len |-> 2] : n \in Addrs}

\* The prefix of length len that holds address a: Prefix::canonical.
Of(a, len) == [net |-> (a \div 2 ^ (2 - len)) * 2 ^ (2 - len), len |-> len]
Holds(p, a) == Of(a, p.len) = p

VARIABLES
    routes,  \* routes[p]: the port prefix p goes out on, or NoPort
    byPort,  \* byPort[i]: the prefixes that go out on port i
    lengths, \* lengths[len]: how many routes have that length
    open     \* the ports that hold an interface

vars == <<routes, byPort, lengths, open>>

Init ==
    /\ routes = [p \in Prefixes |-> NoPort]
    /\ byPort = [i \in Ports |-> {}]
    /\ lengths = [len \in Lengths |-> 0]
    /\ open = {}

Count(S, len) == Cardinality({p \in S : p.len = len})

\* Edit::Route: an interface takes a free slot i for the prefixes S.
Edit(S, i) ==
    /\ S # {} /\ i \notin open
    /\ LET moved == {p \in S : routes[p] # NoPort}
           olds == {routes[p] : p \in moved}
           orphans == {o \in olds : byPort[o] \subseteq S}
       IN /\ routes' = [p \in Prefixes |-> IF p \in S THEN i ELSE routes[p]]
          /\ byPort' = [j \in Ports |-> IF j = i THEN S ELSE byPort[j] \ S]
          /\ lengths' = [len \in Lengths |->
                           lengths[len]
                           + (IF CountLengths THEN Count(S \ moved, len) ELSE 0)]
          /\ open' = (open \cup {i}) \ (IF CloseOrphans THEN orphans ELSE {})

\* Event::Closed(i): Table::remove_port.
Closed(i) ==
    /\ i \in open
    /\ routes' = [p \in Prefixes |-> IF routes[p] = i THEN NoPort ELSE routes[p]]
    /\ byPort' = [byPort EXCEPT ![i] = {}]
    /\ lengths' = [len \in Lengths |-> lengths[len] - Count(byPort[i], len)]
    /\ open' = open \ {i}

Next == \E i \in Ports : (\E S \in SUBSET Prefixes : Edit(S, i)) \/ Closed(i)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
Max(S) == CHOOSE m \in S : \A x \in S : x <= m

\* Table::best: the longest length in use whose prefix for a has a route.
Best(a) ==
    LET lens == {len \in Lengths : lengths[len] > 0 /\ routes[Of(a, len)] # NoPort}
    IN IF lens = {} THEN NoPort ELSE routes[Of(a, Max(lens))]

\* What best should be: the route of the longest prefix that holds a.
Longest(a) ==
    LET lens == {p.len : p \in {p \in Prefixes : routes[p] # NoPort /\ Holds(p, a)}}
    IN IF lens = {} THEN NoPort ELSE routes[Of(a, Max(lens))]

ByPortInverse == \A i \in Ports : byPort[i] = {p \in Prefixes : routes[p] = i}
LengthsCount ==
    \A len \in Lengths :
        lengths[len] = Cardinality({p \in Prefixes : routes[p] # NoPort /\ p.len = len})
RoutedPortsOpen == \A p \in Prefixes : routes[p] # NoPort => routes[p] \in open
OpenPortsRouted == \A i \in open : byPort[i] # {}
BestIsLongest == \A a \in Addrs : Best(a) = Longest(a)
=============================================================================
