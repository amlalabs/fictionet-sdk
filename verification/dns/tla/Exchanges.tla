------------------------------ MODULE Exchanges ------------------------------
(***************************************************************************)
(* The step contract of `services::dns::exchange`, which every DNS engine  *)
(* keeps: tokens, matching, generations, sharing, and termination.         *)
(*                                                                         *)
(* Two clients ask questions that need the same upstream work: one         *)
(* resolution both wait on. The engine sends that work to one of two       *)
(* servers under a fresh token, the namespace generation and an exchange   *)
(* identity, with a deadline one second ahead. A deadline that passes      *)
(* abandons the exchange and the engine tries the other server; when both  *)
(* are tried, every waiter gets SERVFAIL. The servers answer with the data *)
(* of the session the exchange was sent in.                                *)
(*                                                                         *)
(* The network delivers in any order. It may duplicate one message, and an *)
(* off-path attacker may inject one reply with the outstanding transmit's  *)
(* 16-bit ID but the wrong tuple: another source address or another        *)
(* question. A reply that arrives after its deadline is late. A client's   *)
(* connection may go (Gone), and the world may start a new session         *)
(* (Advance).                                                              *)
(*                                                                         *)
(* Ablation flags: IdOnly matches a reply on the 16-bit ID alone;          *)
(* FlushOnly clears the cache on a new session but keeps no generations,   *)
(* so outstanding exchanges survive it; CancelShared tears down the shared *)
(* work when any one client goes.                                         *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Clients,       \* the clients sharing the work
    ServerAddrs,   \* the two servers the work may go to
    Attacker,      \* the off-path attacker's source address
    MaxTime,       \* the clock runs 0..MaxTime; MaxTime stands for "MaxTime or later"
    MaxExchanges,  \* exchange identities run 1..MaxExchanges
    MaxGeneration, \* generations run 1..MaxGeneration
    MaxDup,        \* messages the network may duplicate
    MaxSpoof,      \* replies the attacker may inject
    MaxGone,       \* client connections that may go
    IdOnly,        \* ablation: match on the 16-bit ID alone
    FlushOnly,     \* ablation: a new session only clears the cache
    CancelShared,  \* ablation: Gone tears down shared work
    None

Q == "q"          \* the question the shared work asks
OtherQ == "other" \* another question, for a spoofed reply
TxId == 1         \* the transmit's 16-bit ID; the attacker is assumed to guess it

\* What a server answers in session g.
Data(g) == IF g = 1 THEN "data1" ELSE "data2"

VARIABLES
    now,       \* the clock
    gen,       \* the engine's generation
    nextId,    \* the last exchange identity issued
    out,       \* outstanding exchanges: [token, to, qn, txid, deadline]
    tried,     \* servers tried for the work in this generation
    cache,     \* the work's result: None or [val, gen] (gen: the exchange's generation)
    waiters,   \* clients waiting on the shared work
    cstate,    \* [Clients -> "idle" | "waiting" | "answered" | "gone"]
    answers,   \* [Clients -> number of answers sent]
    last,      \* [Clients -> None or [data, at]]: generations of the last answer's data and of the engine then
    net,       \* messages in flight
    dups, spoofs, gones,
    seen       \* replies the engine has already been handed, without their copy number

engine == <<gen, nextId, out, tried, cache, waiters, cstate, answers, last>>
vars == <<now, gen, nextId, out, tried, cache, waiters, cstate, answers, last, net,
          dups, spoofs, gones, seen>>

\* A reply message. from is the server that answered, or the attacker; sent is
\* the generation of the exchange it answers, kept to state the properties.
Reply(token, from, qn, txid, val, sent, copy) ==
    [k |-> "r", token |-> token, from |-> from, qn |-> qn, txid |-> txid, val |-> val,
     sent |-> sent, copy |-> copy]
Transmit(x) ==
    [k |-> "q", token |-> x.token, from |-> x.to, qn |-> x.qn, txid |-> x.txid, val |-> None,
     sent |-> x.token[1], copy |-> 1]

Strip(m) == [m EXCEPT !.copy = 1]

\* Rule 4 of the step contract: the token is outstanding, and the source,
\* the ID, and the question equal the transmit's (RFC 5452 section 9.1).
Matches(x, m) ==
    /\ m.token = x.token
    /\ m.txid = x.txid
    /\ ~IdOnly => m.from = x.to /\ m.qn = x.qn

Init ==
    /\ now = 0
    /\ gen = 1
    /\ nextId = 0
    /\ out = {}
    /\ tried = {}
    /\ cache = None
    /\ waiters = {}
    /\ cstate = [c \in Clients |-> "idle"]
    /\ answers = [c \in Clients |-> 0]
    /\ last = [c \in Clients |-> None]
    /\ net = {}
    /\ dups = 0 /\ spoofs = 0 /\ gones = 0
    /\ seen = {}

\* Each client in cs gets one answer now, rendered from data of generation d.
AnswerAll(cs, d) ==
    /\ cstate' = [c \in Clients |-> IF c \in cs THEN "answered" ELSE cstate[c]]
    /\ answers' = [c \in Clients |-> IF c \in cs THEN answers[c] + 1 ELSE answers[c]]
    /\ last' = [c \in Clients |-> IF c \in cs THEN [data |-> d, at |-> gen] ELSE last[c]]

(* A client's query arrives. A cached result answers it at once; otherwise *)
(* it waits on the shared work.                                           *)
Query(c) ==
    /\ cstate[c] = "idle"
    /\ IF cache # None
       THEN AnswerAll({c}, cache.gen) /\ UNCHANGED waiters
       ELSE /\ waiters' = waiters \cup {c}
            /\ cstate' = [cstate EXCEPT ![c] = "waiting"]
            /\ UNCHANGED <<answers, last>>
    /\ UNCHANGED <<now, gen, nextId, out, tried, cache, net, dups, spoofs, gones, seen>>

(* The engine sends the work to an untried server under a fresh token. *)
Send ==
    /\ waiters # {}
    /\ out = {}
    /\ cache = None
    /\ nextId < MaxExchanges
    /\ \E s \in ServerAddrs \ tried :
         LET x == [token |-> <<gen, nextId + 1>>, to |-> s, qn |-> Q, txid |-> TxId, deadline |-> now + 1]
         IN  /\ out' = {x}
             /\ net' = net \cup {Transmit(x)}
    /\ nextId' = nextId + 1
    /\ UNCHANGED <<now, gen, tried, cache, waiters, cstate, answers, last, dups, spoofs, gones, seen>>

(* Every server was tried: the waiters get SERVFAIL. *)
GiveUp ==
    /\ waiters # {}
    /\ out = {}
    /\ cache = None
    /\ tried = ServerAddrs
    /\ AnswerAll(waiters, gen)
    /\ waiters' = {}
    /\ UNCHANGED <<now, gen, nextId, out, tried, cache, net, dups, spoofs, gones, seen>>

(* A server answers a transmit with the data of the session it was sent in. *)
ServeOne(m) ==
    /\ m.k = "q"
    /\ net' = (net \ {m}) \cup {Reply(m.token, m.from, m.qn, m.txid, Data(m.sent), m.sent, 1)}
    /\ UNCHANGED <<now, gen, nextId, out, tried, cache, waiters, cstate, answers, last,
                   dups, spoofs, gones, seen>>

(* The engine is handed a reply. A matching one completes the work and   *)
(* answers every waiter; anything else changes nothing (Event::Ignored).  *)
DeliverOne(m) ==
    /\ m.k = "r"
    /\ net' = net \ {m}
    /\ seen' = seen \cup {Strip(m)}
    /\ IF \E x \in out : Matches(x, m)
       THEN /\ out' = {}
            /\ cache' = [val |-> m.val, gen |-> m.sent]
            /\ AnswerAll(waiters, m.sent)
            /\ waiters' = {}
            /\ UNCHANGED <<tried>>
       ELSE UNCHANGED <<out, tried, cache, waiters, cstate, answers, last>>
    /\ UNCHANGED <<now, gen, nextId, dups, spoofs, gones>>

(* The deadline passed: the exchange is abandoned and its server counts as *)
(* tried. Its reply may still arrive, late.                                *)
TimeoutOne(x) ==
    /\ now >= x.deadline \/ now = MaxTime
    /\ out' = out \ {x}
    /\ tried' = tried \cup {x.to}
    /\ UNCHANGED <<now, gen, nextId, cache, waiters, cstate, answers, last, net,
                   dups, spoofs, gones, seen>>

(* The driver calls handle(Tick) when now reaches the next deadline. *)
Tick ==
    /\ out # {}
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<gen, nextId, out, tried, cache, waiters, cstate, answers, last, net,
                   dups, spoofs, gones, seen>>

(* A client's connection goes. The engine drops only what that client     *)
(* alone was waiting for.                                                 *)
Gone(c) ==
    /\ cstate[c] = "waiting"
    /\ gones < MaxGone
    /\ gones' = gones + 1
    /\ cstate' = [cstate EXCEPT ![c] = "gone"]
    /\ IF CancelShared \/ waiters = {c}
       THEN /\ waiters' = {}
            /\ out' = {}
       ELSE /\ waiters' = waiters \ {c}
            /\ UNCHANGED out
    /\ UNCHANGED <<now, gen, nextId, tried, cache, answers, last, net, dups, spoofs, seen>>

(* The world starts a new session and the driver calls advance. With       *)
(* generations, every outstanding exchange is abandoned, derived state     *)
(* goes, and waiting queries restart under the new generation.             *)
Advance ==
    /\ gen < MaxGeneration
    /\ gen' = gen + 1
    /\ cache' = None
    /\ IF FlushOnly
       THEN UNCHANGED <<out, tried>>
       ELSE /\ out' = {}
            /\ tried' = {}
    /\ UNCHANGED <<now, nextId, waiters, cstate, answers, last, net, dups, spoofs, gones, seen>>

DuplicateOne(m) ==
    /\ dups < MaxDup
    /\ m.copy = 1
    /\ dups' = dups + 1
    /\ net' = net \cup {[m EXCEPT !.copy = 2]}
    /\ UNCHANGED <<now, gen, nextId, out, tried, cache, waiters, cstate, answers, last,
                   spoofs, gones, seen>>

(* An off-path reply with the outstanding transmit's ID and token slot but *)
(* the wrong source or question.                                          *)
SpoofOne(x) ==
    /\ spoofs < MaxSpoof
    /\ spoofs' = spoofs + 1
    /\ \E from \in {x.to, Attacker}, qn \in {Q, OtherQ} :
         /\ from # x.to \/ qn # Q
         /\ net' = net \cup {Reply(x.token, from, qn, x.txid, "forged", x.token[1], 1)}
    /\ UNCHANGED <<now, gen, nextId, out, tried, cache, waiters, cstate, answers, last,
                   dups, gones, seen>>

\* Each step on some message or exchange, named so traces show which one ran.
Serve == \E m \in net : ServeOne(m)
Deliver == \E m \in net : DeliverOne(m)
Timeout == \E x \in out : TimeoutOne(x)
Duplicate == \E m \in net : DuplicateOne(m)
Spoof == \E x \in out : SpoofOne(x)

Next ==
    \/ \E c \in Clients : Query(c)
    \/ Send
    \/ GiveUp
    \/ Serve
    \/ Deliver
    \/ Timeout
    \/ Tick
    \/ \E c \in Clients : Gone(c)
    \/ Advance
    \/ Duplicate
    \/ Spoof

(* The engine works, the servers answer, the network delivers, and the     *)
(* driver ticks at deadlines. Queries, Gone, Advance, duplicates, and       *)
(* spoofs are never forced.                                               *)
Fairness ==
    /\ WF_vars(Send) /\ WF_vars(GiveUp) /\ WF_vars(Tick)
    /\ WF_vars(Serve)
    /\ WF_vars(Deliver)
    /\ WF_vars(Timeout)

Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ Fairness

-----------------------------------------------------------------------------
(* Properties *)

\* The reply m is the genuine answer to the outstanding exchange x.
Genuine(x, m) == m.token = x.token /\ m.txid = x.txid /\ m.from = x.to /\ m.qn = x.qn

(* Engine state changes on a handed reply only if its token is outstanding  *)
(* and its tuple matches the transmit's. It relates two states, so configs  *)
(* list it under PROPERTY.                                                 *)
MatchRequiresTuple ==
    [][\A m \in net : (m.k = "r" /\ m \notin net' /\ engine' # engine) => \E x \in out : Genuine(x, m)]_vars

(* No cache entry and no answer rests on an exchange of an older           *)
(* generation than the engine's at the time.                              *)
ObsoleteNeverPopulates ==
    /\ cache # None => cache.gen = gen
    /\ \A c \in Clients : last[c] # None => last[c].data = last[c].at

(* A second copy of a reply changes nothing. A PROPERTY, like the first. *)
DuplicateHarmless ==
    [][\A m \in net : (m.k = "r" /\ m \notin net' /\ Strip(m) \in seen) => UNCHANGED engine]_vars

(* After Gone(c), every other client still waits on live work or has its *)
(* answer.                                                                *)
CancelPreservesWaiters ==
    \A c \in Clients : cstate[c] = "waiting" => c \in waiters

OneAnswerPerQuery ==
    \A c \in Clients : answers[c] <= 1

EveryAcceptedAnswered ==
    \A c \in Clients : (cstate[c] = "waiting") ~> (cstate[c] \in {"answered", "gone"})

=============================================================================
