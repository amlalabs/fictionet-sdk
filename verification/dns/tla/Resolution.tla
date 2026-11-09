----------------------------- MODULE Resolution -----------------------------
(***************************************************************************)
(* The recursive resolver of `services::dns::resolver` against a small     *)
(* hierarchy.                                                              *)
(*                                                                         *)
(* Zones: the root, "tld", and two zones below it, "sld.tld" and           *)
(* "alt.tld". Each zone has two servers. Server 1 answers from the data;   *)
(* server 2 is lame: the root's answers REFUSED and the others send an     *)
(* upward referral to the root, which a resolver must not follow.          *)
(*                                                                         *)
(* Names: an address (www), a CNAME to it (cn), an empty non-terminal      *)
(* (ent, with a.ent below it), a name that does not exist (nx), the        *)
(* nameserver host of sld.tld with glue in tld (ns), a CNAME loop across   *)
(* two zones (loop.sld to loop.alt and back), and a wildcard (x.w.alt      *)
(* matches *.w.alt). Every record is of type A or CNAME, so a question of  *)
(* type AAAA is answered NODATA, after any CNAME. One world edit changes   *)
(* www and ns and creates nx.                                              *)
(*                                                                         *)
(* With Rogue, server 1 of alt.tld also sends a record for www.sld.tld,    *)
(* outside its bailiwick: any authority the resolver asks may send         *)
(* anything.                                                               *)
(*                                                                         *)
(* Each client asks a fixed script of questions, each a name and a type    *)
(* (A or AAAA), one at a time, as a stub resolver does; two clients asking *)
(* the same question share one resolution. Each client's question has its  *)
(* own budget of MaxWork queries (RFC 1034 section 5.3.3). A resolution    *)
(* charges the client that started it; once that client's budget is spent, *)
(* a waiting client with queries left takes it over, and the spent client  *)
(* gets SERVFAIL (Resolver::take_over). The resolver starts with the       *)
(* root's servers as hints and keeps every cut it learns (NS TTLs outlast  *)
(* MaxTime). The cache keeps answers by name and type.                     *)
(*                                                                         *)
(* Each query goes out from a port of Ports with a DNS ID of IDs, both     *)
(* drawn for it, and the server's reply repeats them and the question      *)
(* (RFC 5452). The resolver takes a reply only when it comes from the      *)
(* server it asked, over the same transport, to that port, with that ID    *)
(* and question. An off-path attacker sends at most MaxSpoof forged        *)
(* replies with a poisoned answer, each to an exchange the resolver has    *)
(* outstanding, from the server it asked, and guesses every field of the   *)
(* exchange but one: the port, the ID, or the question's type.             *)
(*                                                                         *)
(* The network loses at most MaxLoss messages and truncates at most MaxTc  *)
(* UDP replies. A lost message enables the timeout of its exchange; the    *)
(* clock plays no part in timeouts. The clock only ages cache entries, and *)
(* it does not advance while a reply is in flight or before the resolver   *)
(* acts on it, since simulated round trips are far shorter than a TTL      *)
(* second.                                                                 *)
(*                                                                         *)
(* Ablation flags: CheckBailiwick, BoundWork, CacheTc, CheckExpiry,        *)
(* FailureAsNegative, CacheBounded, CountDown, CheckId, CheckPort,         *)
(* CheckType, CacheByName, and SharedBound. Each is the rule as the design *)
(* states it when TRUE (FALSE for CacheTc, FailureAsNegative,              *)
(* CacheBounded, CacheByName, and SharedBound).                            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Clients,           \* clients of the resolver
    Script,            \* the distinct questions every client asks, in this order
    MaxTime,           \* the clock runs 0..MaxTime
    MaxWork,           \* upstream queries per client question (Config.work.queries)
    MaxChain,          \* CNAME restarts per resolution (Config.work.depth)
    MaxLoss,           \* messages the network may lose
    MaxTc,             \* UDP replies the network may truncate
    MaxEdits,          \* world edits (0 or 1)
    MaxSpoof,          \* forged replies the attacker may send
    Ports,             \* the ports a query may go out from
    IDs,               \* the DNS IDs a query may carry
    Rogue,             \* server 1 of alt.tld adds an out-of-bailiwick record
    CheckBailiwick,    \* records outside the answering zone are dropped
    BoundWork,         \* the work and chain bounds are kept
    CacheTc,           \* ablation: a truncated reply is cached
    CheckExpiry,       \* entries are never used at or after their expiry
    FailureAsNegative, \* ablation: a failure is cached as NXDOMAIN
    CacheBounded,      \* ablation: a failure the work bound caused is cached
    CountDown,         \* a fetched record goes out with the TTL it has left
    CheckId,           \* a reply must carry the query's DNS ID
    CheckPort,         \* a reply must come to the query's port
    CheckType,         \* a reply's question must have the query's type
    CacheByName,       \* ablation: the cache keeps answers by name alone
    SharedBound,       \* ablation: only the client that started a resolution pays for it
    None               \* a model value for "nothing here"

-----------------------------------------------------------------------------
(* The namespace *)

Root == "."
Zones == {".", "tld", "sld.tld", "alt.tld"}
Types == {"A", "AAAA"}

\* The parent of every name the model uses.
Up == "tld" :> "." @@ "sld.tld" :> "tld" @@ "alt.tld" :> "tld"
   @@ "www.sld.tld" :> "sld.tld" @@ "cn.sld.tld" :> "sld.tld"
   @@ "ent.sld.tld" :> "sld.tld" @@ "a.ent.sld.tld" :> "ent.sld.tld"
   @@ "nx.sld.tld" :> "sld.tld" @@ "ns.sld.tld" :> "sld.tld"
   @@ "loop.sld.tld" :> "sld.tld" @@ "loop.alt.tld" :> "alt.tld"
   @@ "w.alt.tld" :> "alt.tld" @@ "*.w.alt.tld" :> "w.alt.tld"
   @@ "x.w.alt.tld" :> "w.alt.tld"

RECURSIVE AtOrBelow(_, _)
\* a is b or a descendant of b.
AtOrBelow(a, b) == a = b \/ (a # Root /\ AtOrBelow(Up[a], b))

StrictlyBelow(a, b) == a # b /\ AtOrBelow(a, b)

\* The deepest zone whose apex is at or above n: the zone that answers for n.
ZoneOf(n) == CHOOSE z \in Zones : AtOrBelow(n, z)
                /\ \A y \in Zones : AtOrBelow(n, y) => AtOrBelow(z, y)

\* The zone directly below z on the way down to n's zone.
ChildToward(z, n) == CHOOSE c \in Zones \ {Root} : Up[c] = z /\ AtOrBelow(n, c)

\* The records of the data at version v (0 before the edit, 1 after).
Rrs(v) ==
    { [o |-> "www.sld.tld",   t |-> "A",     val |-> IF v = 0 THEN "W0" ELSE "W1", ttl |-> 2],
      [o |-> "cn.sld.tld",    t |-> "CNAME", val |-> "www.sld.tld",                ttl |-> 1],
      [o |-> "a.ent.sld.tld", t |-> "A",     val |-> "E0",                         ttl |-> 2],
      [o |-> "ns.sld.tld",    t |-> "A",     val |-> IF v = 0 THEN "G0" ELSE "G1", ttl |-> 2],
      [o |-> "loop.sld.tld",  t |-> "CNAME", val |-> "loop.alt.tld",               ttl |-> 2],
      [o |-> "loop.alt.tld",  t |-> "CNAME", val |-> "loop.sld.tld",               ttl |-> 2],
      [o |-> "*.w.alt.tld",   t |-> "A",     val |-> "X0",                         ttl |-> 1] }
    \cup (IF v = 1 THEN {[o |-> "nx.sld.tld", t |-> "A", val |-> "N1", ttl |-> 1]} ELSE {})

\* The SOA minimum of every zone: the TTL of negative answers (RFC 2308 section 3).
NegTtl == 1
\* Config.failure_ttl in seconds (RFC 9520 section 3.2).
FailureTtl == 1

\* The glue tld holds for sld.tld's nameserver. The edit changes the child's
\* own address record, not the parent's copy, as happens in real zones.
Glue == [n |-> "ns.sld.tld", val |-> "G0", ttl |-> 2]

NodeAtOrBelow(v, n) == \E r \in Rrs(v) : AtOrBelow(r.o, n)
Own(v, n) == {r \in Rrs(v) : r.o = n}
\* The wildcard that synthesizes n: *.<parent of n>, when n has no node.
Wild(v, n) == {r \in Rrs(v) : n # Root /\ r.o = "*." \o Up[n]}

\* What the zone holds for "n qt" at version v (RFC 1034 section 4.3.2,
\* RFC 4592): a CNAME, the record of type qt, NODATA at a node or a wildcard
\* without one, or NXDOMAIN.
Lookup(v, n, qt) ==
    LET own == Own(v, n)
        wild == Wild(v, n)
        One(rs) == CHOOSE r \in rs : TRUE
    IN  IF \E r \in own : r.t = "CNAME"
        THEN LET r == One({x \in own : x.t = "CNAME"}) IN [t |-> "cname", val |-> r.val, ttl |-> r.ttl]
        ELSE IF \E r \in own : r.t = qt
        THEN LET r == One({x \in own : x.t = qt}) IN [t |-> qt, val |-> r.val, ttl |-> r.ttl]
        ELSE IF NodeAtOrBelow(v, n) THEN [t |-> "nodata", val |-> None, ttl |-> NegTtl]
        ELSE IF \E r \in wild : r.t = qt
        THEN LET r == One({x \in wild : x.t = qt}) IN [t |-> qt, val |-> r.val, ttl |-> r.ttl]
        ELSE IF wild # {} THEN [t |-> "nodata", val |-> None, ttl |-> NegTtl]
        ELSE [t |-> "nx", val |-> None, ttl |-> NegTtl]

\* Server <<z, 1>> answers from the data; server <<z, 2>> is lame.
Servers == Zones \X {1, 2}
ServersOf(z) == {z} \X {1, 2}

\* The names whose answers the resolver may cache, and the cache's keys.
CacheNames == {"www.sld.tld", "cn.sld.tld", "ent.sld.tld", "nx.sld.tld", "ns.sld.tld",
               "loop.sld.tld", "loop.alt.tld", "x.w.alt.tld"}
CacheKeys == CacheNames \X Types

\* Where the cache keeps the answer for n of type qt.
Key(n, qt) == IF CacheByName THEN <<n, "A">> ELSE <<n, qt>>

\* The record Rogue adds, and the answer a forged reply carries.
Poison == [n |-> "www.sld.tld", val |-> "Poison", ttl |-> 2]

Questions == {Script[i] : i \in 1..Len(Script)}

\* The scripts the configs pick with "Script <- ...", since a config file
\* cannot write a sequence.
ScriptBase == << <<"cn.sld.tld", "A">>, <<"www.sld.tld", "A">>, <<"ent.sld.tld", "A">>,
                 <<"nx.sld.tld", "A">>, <<"x.w.alt.tld", "A">> >>
ScriptConcurrent == << <<"cn.sld.tld", "A">>, <<"www.sld.tld", "A">> >>
ScriptLoop == << <<"loop.sld.tld", "A">> >>
ScriptRogue == << <<"x.w.alt.tld", "A">>, <<"www.sld.tld", "A">> >>
ScriptEdit == << <<"www.sld.tld", "A">>, <<"ns.sld.tld", "A">>, <<"nx.sld.tld", "A">> >>
ScriptTypes == << <<"cn.sld.tld", "AAAA">>, <<"www.sld.tld", "A">>, <<"x.w.alt.tld", "AAAA">>,
                  <<"x.w.alt.tld", "A">> >>
ScriptSpoof == << <<"www.sld.tld", "A">> >>

-----------------------------------------------------------------------------
VARIABLES
    now,      \* the clock
    ver,      \* the data version the servers serve
    editAt,   \* when the edit happened (None before)
    cache,    \* [CacheKeys -> entry or None]
    known,    \* the zones whose cut and server addresses the resolver holds
    res,      \* [Questions -> resolution or None]: one per question, shared by its clients
    waiting,  \* [Questions -> clients waiting on that resolution]
    asked,    \* [Clients -> questions asked]
    ans,      \* [Clients -> [Questions -> answer or None]]
    spent,    \* [Clients -> [Questions -> queries the client's question paid for]]
    net,      \* messages in flight
    lost,     \* messages lost so far
    tcs,      \* replies truncated so far
    spoofs    \* forged replies sent so far

vars == <<now, ver, editAt, cache, known, res, waiting, asked, ans, spent, net, lost, tcs, spoofs>>

\* A cache entry. rank is "auth" or "glue" (RFC 2181 section 5.4.1); from is
\* the zone of the server that sent it, or for a failure the zone whose
\* servers the resolution tried; failure says it was written for a failed
\* resolution, and tried holds the servers and transports that resolution
\* tried at that zone.
Entry(t, val, ttl, rank, from) ==
    [t |-> t, val |-> val, ttl |-> ttl, readAt |-> now, rank |-> rank, from |-> from,
     failure |-> FALSE, tried |-> {}]

\* The entry a failed resolution r leaves at the name its chain reached.
FailEntry(t, r) == [Entry(t, None, FailureTtl, "auth", r.zone) EXCEPT !.failure = TRUE, !.tried = r.tried]

Usable(e) ==
    /\ e # None
    /\ e.rank = "auth"
    /\ CheckExpiry => now < e.readAt + e.ttl

\* The deepest zone the resolver holds a cut for that contains n.
Closest(n) == CHOOSE z \in known : AtOrBelow(n, z)
                 /\ \A y \in known : AtOrBelow(n, y) => AtOrBelow(z, y)

\* got is the entry the last reply brought for qn, which serves this
\* resolution whether or not the cache keeps it (RFC 1035 section 7.4). out
\* is the exchange outstanding: [s, tcp, port, id]. payer is the waiting
\* client whose budget pays for its queries.
NewRes(q, payer) == [qn |-> q[1], zone |-> Closest(q[1]), tried |-> {}, out |-> None,
                     payer |-> payer, chain |-> 0, recs |-> {}, got |-> None]

\* The work and chain counters count every query and restart, with or
\* without the bounds kept, and stop one past their bound, which is enough
\* to see a resolution go past it and keeps the state space finite.
Min(a, b) == IF a < b THEN a ELSE b

\* What a resolution records about each entry it uses: the name and type it
\* was read for, and fetched, which says the entry came in a reply to this
\* resolution, FALSE that it was read from the cache.
Used(n, qt, e, fetched) == [n |-> n, qt |-> qt, t |-> e.t, val |-> e.val, ttl |-> e.ttl,
                            readAt |-> e.readAt, rank |-> e.rank, failure |-> e.failure,
                            fetched |-> fetched]

\* The TTL a record has left now, as the client sees it: counted down from
\* when it was read, and 0 once it has run out (cache::ttl_left). Without
\* CountDown, a record fetched for the resolution keeps the TTL it came
\* with, as if the answer copied it from the reply.
TtlLeft(u) == IF ~CountDown /\ u.fetched THEN u.ttl
              ELSE IF now < u.readAt + u.ttl THEN u.readAt + u.ttl - now ELSE 0

\* A used record as the answer renders it, with the TTL it goes out with.
Rendered(u) == [n |-> u.n, qt |-> u.qt, t |-> u.t, val |-> u.val, ttl |-> u.ttl, readAt |-> u.readAt,
                rank |-> u.rank, failure |-> u.failure, fetched |-> u.fetched, left |-> TtlLeft(u)]

Rcode(t) == CASE t \in {"A", "AAAA", "cname"} -> "NOERROR"
              [] t = "nodata" -> "NODATA" [] t = "nx" -> "NXDOMAIN" [] t = "fail" -> "SERVFAIL"

\* A message: a query, or a reply, to the exchange of resolution q, about
\* "qn qt", to or from server srv, over TCP or UDP, from or to port, with the
\* DNS ID id. spoof marks a forged reply; the resolver cannot see it.
Msg(k, q, qn, qt, srv, tcp, port, id, tc, body) ==
    [k |-> k, q |-> q, qn |-> qn, qt |-> qt, srv |-> srv, tcp |-> tcp, port |-> port, id |-> id,
     tc |-> tc, body |-> body, spoof |-> FALSE]
Body(kind, to, rr, extra) == [kind |-> kind, to |-> to, rr |-> rr, extra |-> extra]

\* The reply server s sends for "n qt" at the current version.
Respond(s, n, qt) ==
    LET z == s[1] IN
    IF s[2] = 2
    THEN IF z = Root THEN Body("refused", None, None, {})
         ELSE Body("referral", Root, None, {})
    ELSE IF ~AtOrBelow(n, z) THEN Body("refused", None, None, {})
    ELSE IF ZoneOf(n) # z
    THEN Body("referral", ChildToward(z, n), None,
              IF ChildToward(z, n) = "sld.tld" THEN {Glue} ELSE {})
    ELSE Body("answer", None, Lookup(ver, n, qt),
              IF Rogue /\ z = "alt.tld" THEN {Poison} ELSE {})

\* Whether resolution r of question q takes reply m: from the server it
\* asked, over the same transport, to its port, with its ID and question
\* (RFC 5452 section 9.1).
Matches(m, q, r) ==
    /\ r # None
    /\ r.out # None
    /\ m.srv = r.out.s
    /\ m.tcp = r.out.tcp
    /\ CheckPort => m.port = r.out.port
    /\ CheckId => m.id = r.out.id
    /\ m.qn = r.qn
    /\ CheckType => m.qt = q[2]

-----------------------------------------------------------------------------
Init ==
    /\ now = 0
    /\ ver = 0
    /\ editAt = None
    /\ cache = [k \in CacheKeys |-> None]
    /\ known = {Root}
    /\ res = [q \in Questions |-> None]
    /\ waiting = [q \in Questions |-> {}]
    /\ asked = [c \in Clients |-> {}]
    /\ ans = [c \in Clients |-> [q \in Questions |-> None]]
    /\ spent = [c \in Clients |-> [q \in Questions |-> 0]]
    /\ net = {}
    /\ lost = 0
    /\ tcs = 0
    /\ spoofs = 0

(* A client asks the next question of the script once its last one is      *)
(* answered, as a stub resolver does. It joins the resolution already       *)
(* running for that question, if another client started one.              *)
Ask(c, q) ==
    /\ Cardinality(asked[c]) < Len(Script)
    /\ q = Script[Cardinality(asked[c]) + 1]
    /\ \A p \in asked[c] : ans[c][p] # None
    /\ asked' = [asked EXCEPT ![c] = @ \cup {q}]
    /\ waiting' = [waiting EXCEPT ![q] = @ \cup {c}]
    /\ res' = IF res[q] = None THEN [res EXCEPT ![q] = NewRes(q, c)] ELSE res
    /\ UNCHANGED <<now, ver, editAt, cache, known, ans, spent, net, lost, tcs, spoofs>>

\* An answer to a client, rendered now. bound says the work bound ended it.
Answer(rcode, recs, bound) ==
    [rcode |-> rcode, at |-> now, recs |-> {Rendered(u) : u \in recs}, bound |-> bound]

\* Every waiter of q gets the answer, rendered now.
Finish(q, rcode, recs, bound) ==
    /\ ans' = [c \in Clients |-> IF c \in waiting[q]
                                  THEN [ans[c] EXCEPT ![q] = Answer(rcode, recs, bound)]
                                  ELSE ans[c]]
    /\ res' = [res EXCEPT ![q] = None]
    /\ waiting' = [waiting EXCEPT ![q] = {}]

(* The resolution fails: every server was tried. The failure is cached for  *)
(* failure_ttl (RFC 9520). Rust caches one that persists longer (RFC 9520  *)
(* section 3.2), which the Lean cache model checks; here each lasts the    *)
(* same.                                                                   *)
Fail(q) ==
    LET r == res[q]
        e == FailEntry(IF FailureAsNegative THEN "nx" ELSE "fail", r)
    IN  /\ cache' = [cache EXCEPT ![Key(r.qn, q[2])] = e]
        /\ Finish(q, Rcode(e.t), {Used(r.qn, q[2], e, FALSE)}, FALSE)

(* No client waiting on the resolution has queries left: SERVFAIL. The      *)
(* bound is each question's budget and says nothing of the servers, so the  *)
(* failure is not cached for other clients, as Resolution::send leaves it   *)
(* out of the cache (RFC 9520 section 3.2).                                *)
FailBounded(q) ==
    LET r == res[q]
        e == FailEntry("fail", r)
    IN  /\ cache' = IF CacheBounded THEN [cache EXCEPT ![Key(r.qn, q[2])] = e] ELSE cache
        /\ Finish(q, "SERVFAIL", {}, TRUE)

\* Whether client p, waiting on q, may pay for one more query of q's
\* resolution: it has queries left, and with SharedBound it is the payer.
CanPay(q, p) ==
    /\ p \in waiting[q]
    /\ BoundWork => spent[p][q] < MaxWork
    /\ SharedBound => p = res[q].payer

\* The clients that may pay for q's next query: its payer while it can, or
\* else any waiting client that can, which takes the resolution over.
Payers(q) == IF CanPay(q, res[q].payer) THEN {res[q].payer}
             ELSE {p \in waiting[q] : CanPay(q, p)}

(* Client p pays for one more query of q's resolution. A p other than the   *)
(* payer takes the resolution over from the payer, whose budget is spent:   *)
(* the payer gets SERVFAIL and stops waiting, and the others wait on        *)
(* (Resolver::take_over). The caller sets res'[q].payer to p.              *)
Charge(q, p) ==
    LET payer == res[q].payer IN
    /\ spent' = [spent EXCEPT ![p][q] = Min(@ + 1, MaxWork + 1)]
    /\ IF p = payer
       THEN UNCHANGED <<waiting, ans>>
       ELSE /\ ans' = [ans EXCEPT ![payer][q] = Answer("SERVFAIL", {}, TRUE)]
            /\ waiting' = [waiting EXCEPT ![q] = @ \ {payer}]

\* A record is live while its TTL has not run out.
Live(u) == now < u.readAt + u.ttl

(* A resolution with no exchange outstanding takes its next step: from the  *)
(* reply it just got, or from the cache when it can, otherwise a query to a *)
(* server of the closest cut, from a port and with an ID drawn for it.      *)
Advance(q) ==
    /\ res[q] # None
    /\ res[q].out = None
    /\ LET r == res[q]
           fetched == r.got # None
           e == IF fetched THEN r.got ELSE cache[Key(r.qn, q[2])]
           have == fetched \/ Usable(e)
       IN
       \/ /\ have
          /\ e.t # "cname"
          /\ LET recs == r.recs \cup {Used(r.qn, q[2], e, fetched)} IN
             IF CheckExpiry /\ \E u \in recs : ~u.fetched /\ ~Live(u)
             \* A link the cache gave ran out while the chase went on: follow the
             \* chain again from the question, keeping the work done so far (the
             \* queries stay charged to their payers) but counting the aliases
             \* afresh, as Resolver::answer_asker clears the pieces the alias
             \* count is read from. A link that came for this resolution serves
             \* it with the TTL it has left, even 0: following again could only
             \* fetch it again.
             THEN /\ res' = [res EXCEPT ![q] = NewRes(q, r.payer)]
                  /\ UNCHANGED <<waiting, ans>>
             ELSE Finish(q, Rcode(e.t), recs, FALSE)
          /\ UNCHANGED <<cache, spent, net>>
       \/ /\ have
          /\ e.t = "cname"
          /\ IF BoundWork /\ r.chain >= MaxChain
             \* The chain is too long: SERVFAIL, keeping the cached CNAME.
             THEN /\ Finish(q, "SERVFAIL", {}, FALSE)
                  /\ UNCHANGED <<cache, spent, net>>
             ELSE /\ res' = [res EXCEPT ![q] = [qn |-> e.val, zone |-> Closest(e.val), tried |-> {},
                                              out |-> None, payer |-> r.payer,
                                              chain |-> Min(r.chain + 1, MaxChain + 1),
                                              recs |-> r.recs \cup {Used(r.qn, q[2], e, fetched)},
                                              got |-> None]]
                  /\ UNCHANGED <<cache, waiting, ans, spent, net>>
       \/ /\ ~have
          /\ IF Payers(q) = {}
             THEN FailBounded(q) /\ UNCHANGED <<spent, net>>
             ELSE IF \A s \in ServersOf(r.zone) : <<s, FALSE>> \in r.tried
             THEN Fail(q) /\ UNCHANGED <<spent, net>>
             ELSE \E p \in Payers(q), s \in ServersOf(r.zone), port \in Ports, id \in IDs :
                    /\ <<s, FALSE>> \notin r.tried
                    /\ res' = [res EXCEPT ![q].out = [s |-> s, tcp |-> FALSE, port |-> port, id |-> id],
                                          ![q].payer = p]
                    /\ Charge(q, p)
                    /\ net' = net \cup {Msg("q", q, r.qn, q[2], s, FALSE, port, id, FALSE, None)}
                    /\ UNCHANGED cache
    /\ UNCHANGED <<now, ver, editAt, known, asked, lost, tcs, spoofs>>

(* A server gets a query and replies at once from the data it serves now,   *)
(* repeating the query's port, ID, and question.                           *)
ServeOne(m) ==
    /\ m \in net
    /\ m.k = "q"
    /\ net' = (net \ {m}) \cup {Msg("r", m.q, m.qn, m.qt, m.srv, m.tcp, m.port, m.id, FALSE,
                                    Respond(m.srv, m.qn, m.qt))}
    /\ UNCHANGED <<now, ver, editAt, cache, known, res, waiting, asked, ans, spent, lost, tcs, spoofs>>

\* Caching rules for an extra record, glue included: an entry is replaced only
\* by one of equal or higher rank (RFC 2181 section 5.4.1). Extra records are
\* addresses, of type A.
CacheExtra(c, x, rank, zone) ==
    LET k == Key(x.n, "A") IN
    IF x.n \in CacheNames /\ (CheckBailiwick => AtOrBelow(x.n, zone))
       /\ (c[k] = None \/ c[k].rank = "glue" \/ rank = "auth")
    THEN [c EXCEPT ![k] = Entry("A", x.val, x.ttl, rank, zone)]
    ELSE c

RECURSIVE CacheAll(_, _, _, _)
CacheAll(c, xs, rank, zone) ==
    IF xs = {} THEN c
    ELSE LET x == CHOOSE y \in xs : TRUE IN CacheAll(CacheExtra(c, x, rank, zone), xs \ {x}, rank, zone)

(* The resolver takes a reply for the exchange it has outstanding. *)
ReceiveOne(m) ==
    /\ m \in net
    /\ m.k = "r"
    /\ Matches(m, m.q, res[m.q])
    /\ LET q == m.q
           r == res[q]
           b == m.body
           tried == r.tried \cup {<<r.out.s, r.out.tcp>>}
       IN
       CASE m.tc ->
              \* RFC 7766: retry the same server over TCP. A truncated reply is
              \* never cached (RFC 2181 section 9).
              /\ cache' = IF CacheTc
                          THEN [cache EXCEPT ![Key(r.qn, q[2])] = Entry("nodata", None, NegTtl, "auth", m.srv[1])]
                          ELSE cache
              /\ IF Payers(q) = {}
                 THEN /\ res' = [res EXCEPT ![q].out = None, ![q].tried = tried]
                      /\ net' = net \ {m}
                      /\ UNCHANGED <<waiting, ans, spent>>
                 ELSE \E p \in Payers(q), port \in Ports, id \in IDs :
                      /\ res' = [res EXCEPT ![q].out = [s |-> m.srv, tcp |-> TRUE, port |-> port, id |-> id],
                                            ![q].tried = tried, ![q].payer = p]
                      /\ Charge(q, p)
                      /\ net' = (net \ {m}) \cup {Msg("q", q, r.qn, q[2], m.srv, TRUE, port, id, FALSE, None)}
              /\ UNCHANGED known
         [] b.kind = "refused" ->
              /\ res' = [res EXCEPT ![q].out = None, ![q].tried = tried]
              /\ net' = net \ {m}
              /\ UNCHANGED <<cache, known, waiting, ans, spent>>
         [] b.kind = "referral" ->
              \* A referral must lead strictly below the current cut and to a zone
              \* at or above the name; anything else is lame.
              /\ IF StrictlyBelow(b.to, r.zone) /\ AtOrBelow(r.qn, b.to)
                 THEN /\ known' = known \cup {b.to}
                      /\ cache' = CacheAll(cache, b.extra, "glue", m.srv[1])
                      /\ res' = [res EXCEPT ![q].out = None, ![q].zone = b.to, ![q].tried = {}]
                      /\ net' = net \ {m}
                 ELSE /\ res' = [res EXCEPT ![q].out = None, ![q].tried = tried]
                      /\ net' = net \ {m}
                      /\ UNCHANGED <<cache, known>>
              /\ UNCHANGED <<waiting, ans, spent>>
         [] b.kind = "answer" ->
              LET e == Entry(b.rr.t, b.rr.val, b.rr.ttl, "auth", m.srv[1]) IN
              /\ cache' = CacheAll([cache EXCEPT ![Key(r.qn, q[2])] = e], b.extra, "auth", m.srv[1])
              /\ res' = [res EXCEPT ![q].out = None, ![q].got = e]
              /\ net' = net \ {m}
              /\ UNCHANGED <<known, waiting, ans, spent>>
    /\ UNCHANGED <<now, ver, editAt, asked, lost, tcs, spoofs>>

(* A reply no outstanding exchange takes changes nothing: it is dropped,   *)
(* as `Event::Ignored`.                                                    *)
IgnoreOne(m) ==
    /\ m \in net
    /\ m.k = "r"
    /\ ~Matches(m, m.q, res[m.q])
    /\ net' = net \ {m}
    /\ UNCHANGED <<now, ver, editAt, cache, known, res, waiting, asked, ans, spent, lost, tcs, spoofs>>

(* The exchange's query or reply was lost, so its timeout fires. A forged   *)
(* reply in flight does not stand for the real one.                        *)
Timeout(q) ==
    /\ res[q] # None
    /\ res[q].out # None
    /\ ~\E m \in net : m.q = q /\ ~m.spoof
    /\ res' = [res EXCEPT ![q].tried = @ \cup {<<res[q].out.s, res[q].out.tcp>>}, ![q].out = None]
    /\ UNCHANGED <<now, ver, editAt, cache, known, waiting, asked, ans, spent, net, lost, tcs, spoofs>>

(* The attacker forges a reply to an exchange of q the resolver has         *)
(* outstanding, from the server it asked, over its transport, about the     *)
(* name it asked, with a poisoned answer. It guesses every field but one:   *)
(* the port, the ID, or the question's type is not the exchange's.          *)
SpoofOne(q) ==
    /\ spoofs < MaxSpoof
    /\ res[q] # None
    /\ res[q].out # None
    /\ \E port \in Ports, id \in IDs, qt \in Types :
         /\ ~(port = res[q].out.port /\ id = res[q].out.id /\ qt = q[2])
         /\ net' = net \cup {[Msg("r", q, res[q].qn, qt, res[q].out.s, res[q].out.tcp, port, id, FALSE,
                                  Body("answer", None, [t |-> qt, val |-> Poison.val, ttl |-> Poison.ttl], {}))
                              EXCEPT !.spoof = TRUE]}
    /\ spoofs' = spoofs + 1
    /\ UNCHANGED <<now, ver, editAt, cache, known, res, waiting, asked, ans, spent, lost, tcs>>

LoseOne(m) ==
    /\ m \in net
    /\ lost < MaxLoss
    /\ net' = net \ {m}
    /\ lost' = lost + 1
    /\ UNCHANGED <<now, ver, editAt, cache, known, res, waiting, asked, ans, spent, tcs, spoofs>>

(* A UDP reply too large for the path arrives with TC and no records. *)
TruncateOne(m) ==
    /\ m \in net
    /\ m.k = "r" /\ ~m.tcp /\ ~m.tc /\ ~m.spoof
    /\ tcs < MaxTc
    /\ net' = (net \ {m}) \cup {[m EXCEPT !.tc = TRUE, !.body = Body("empty", None, None, {})]}
    /\ tcs' = tcs + 1
    /\ UNCHANGED <<now, ver, editAt, cache, known, res, waiting, asked, ans, spent, lost, spoofs>>

\* The clock does not advance while a reply is in flight or before the
\* resolver has acted on it.
Tick ==
    /\ now < MaxTime
    /\ \A m \in net : m.k = "q"
    /\ \A q \in Questions : IF res[q] = None THEN TRUE ELSE res[q].got = None
    /\ now' = now + 1
    \* An expired entry is gone: it can never be used again.
    /\ cache' = IF CheckExpiry
                THEN [k \in CacheKeys |-> IF cache[k] # None /\ now + 1 >= cache[k].readAt + cache[k].ttl
                                          THEN None ELSE cache[k]]
                ELSE cache
    /\ UNCHANGED <<ver, editAt, known, res, waiting, asked, ans, spent, net, lost, tcs, spoofs>>

WorldEdit ==
    /\ ver < MaxEdits
    /\ ver' = ver + 1
    /\ editAt' = now
    /\ UNCHANGED <<now, cache, known, res, waiting, asked, ans, spent, net, lost, tcs, spoofs>>

\* Each network step on some message, named so traces show which one ran.
Serve == \E m \in net : ServeOne(m)
Receive == \E m \in net : ReceiveOne(m)
Ignore == \E m \in net : IgnoreOne(m)
Lose == \E m \in net : LoseOne(m)
Truncate == \E m \in net : TruncateOne(m)
Spoof == \E q \in Questions : SpoofOne(q)

Next ==
    \/ \E c \in Clients, q \in Questions : Ask(c, q)
    \/ \E q \in Questions : Advance(q)
    \/ \E q \in Questions : Timeout(q)
    \/ Serve
    \/ Receive
    \/ Ignore
    \/ Lose
    \/ Truncate
    \/ Spoof
    \/ Tick
    \/ WorldEdit

(* The network delivers and the resolver works. Asking, losing, truncating,  *)
(* forging, the clock, and the edit are never forced.                       *)
Fairness ==
    /\ \A q \in Questions : WF_vars(Advance(q)) /\ WF_vars(Timeout(q))
    /\ WF_vars(Serve)
    /\ WF_vars(Receive)
    /\ WF_vars(Ignore)

Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ Fairness

Symmetry == Permutations(Clients)

-----------------------------------------------------------------------------
(* Properties *)

\* The data versions that held at time s. At the edit's own second both did.
VersionsAt(s) == IF editAt = None THEN {ver}
                 ELSE IF s < editAt THEN {0}
                 ELSE IF s > editAt THEN {1}
                 ELSE {0, 1}

\* Some second within the record's TTL before t at which the data said u for
\* the name and type it was read for. A record fetched for the resolution
\* that ran out before t reached the client with TTL 0; its TTL counts back
\* from its last second instead.
TrueWithin(u, t) ==
    LET end == IF u.fetched THEN Min(t, u.readAt + u.ttl - 1) ELSE t IN
    \E s \in 0..MaxTime : s <= end /\ s > end - u.ttl /\
        \E v \in VersionsAt(s) : LET l == Lookup(v, u.n, u.qt) IN l.t = u.t /\ l.val = u.val

Answers == {ans[c][q] : c \in Clients, q \in Questions} \ {None}

(* Every record of a NOERROR answer was in the data, for the name and type  *)
(* it was read for, at some second within its TTL before the reply.         *)
AnswersTrueWithinTtl ==
    \A a \in Answers : a.rcode = "NOERROR" => \A u \in a.recs : TrueWithin(u, a.at)

\* The name holds no record of type qt and no CNAME, at its own node or, with
\* nothing at or below it, at the wildcard that would answer for it.
LacksType(v, n, qt) ==
    \A r \in (IF NodeAtOrBelow(v, n) THEN Own(v, n) ELSE Wild(v, n)) : r.t \notin {qt, "CNAME"}

(* NXDOMAIN only for a name with no node at or below it and no wildcard;     *)
(* NODATA only for a name that exists, at a node or by a wildcard, without   *)
(* the type asked. Both held within the TTL.                                *)
NegativeTrue ==
    \A a \in Answers : \A u \in a.recs :
        /\ (a.rcode = "NXDOMAIN" /\ u.t = "nx") =>
             \E s \in 0..MaxTime : s <= a.at /\ s > a.at - u.ttl /\
                 \E v \in VersionsAt(s) : ~NodeAtOrBelow(v, u.n) /\ Wild(v, u.n) = {}
        /\ (a.rcode = "NODATA" /\ u.t = "nodata") =>
             \E s \in 0..MaxTime : s <= a.at /\ s > a.at - u.ttl /\
                 \E v \in VersionsAt(s) : (NodeAtOrBelow(v, u.n) \/ Wild(v, u.n) # {}) /\
                     LacksType(v, u.n, u.qt)

(* Every cached record came from a server for a zone at or above its name. *)
NoPoison ==
    \A k \in CacheKeys : cache[k] # None => AtOrBelow(k[1], cache[k].from)

(* No answer to a client rests on glue. *)
GlueNeverAnswers ==
    \A a \in Answers : \A u \in a.recs : u.rank = "auth"

(* No answer uses a record read from the cache at or after its expiry. A    *)
(* record fetched for the resolution serves it even after its TTL has run   *)
(* out (RFC 1035 section 7.4). Every record goes out with a TTL that ends   *)
(* by its own expiry, so with TTL 0 once it has run out.                    *)
TtlSound ==
    \A a \in Answers : \A u \in a.recs :
        /\ ~u.fetched => a.at < u.readAt + u.ttl
        /\ a.at + u.left <= u.readAt + u.ttl \/ u.left = 0

(* Every cached NXDOMAIN or NODATA was true, for its name and type, at some *)
(* second within its TTL from when it was stored: so nothing a reply did    *)
(* not show, such as a truncated reply's empty sections (RFC 2181 section   *)
(* 9), is cached as a negative.                                             *)
CachedNegativeTrue ==
    \A k \in CacheKeys : (cache[k] # None /\ cache[k].t \in {"nx", "nodata"}) =>
        \E s \in cache[k].readAt .. Min(now, cache[k].readAt + cache[k].ttl - 1) :
            \E v \in VersionsAt(s) : Lookup(v, k[1], k[2]).t = cache[k].t

(* A failure never answers NXDOMAIN or NODATA (RFC 9520). *)
FailureNeverNegative ==
    \A a \in Answers : a.rcode \in {"NXDOMAIN", "NODATA"} => \A u \in a.recs : ~u.failure

(* A cached failure says every server of its zone failed: the resolution   *)
(* that wrote it tried each of them (RFC 9520 section 3.1). So a failure the *)
(* work bound caused before every server was tried, which says nothing of   *)
(* the servers, is never cached for another client.                        *)
CachedFailureTriedAll ==
    \A k \in CacheKeys : (cache[k] # None /\ cache[k].failure) =>
        \A s \in ServersOf(cache[k].from) : <<s, FALSE>> \in cache[k].tried

(* Each client's question stays within its work bound, and each resolution  *)
(* within its chain bound.                                                  *)
WorkBounded ==
    /\ \A c \in Clients, q \in Questions : spent[c][q] <= MaxWork
    /\ \A q \in Questions : res[q] # None => res[q].chain <= MaxChain

(* The work bound is each client question's own (RFC 1034 section 5.3.3):  *)
(* a client fails for want of queries only once its own budget is spent,    *)
(* never because another client that started the resolution spent its own. *)
BoundIsOwn ==
    \A c \in Clients, q \in Questions :
        (ans[c][q] # None /\ ans[c][q].bound) => spent[c][q] >= MaxWork

(* The resolver follows only referrals that lead strictly down toward the   *)
(* name; the cut it works from always contains the name. It relates two     *)
(* states, so configs list it under PROPERTY.                              *)
ReferralsDescend ==
    /\ [](\A q \in Questions : res[q] # None => AtOrBelow(res[q].qn, res[q].zone))
    /\ [][\A q \in Questions :
            (res[q] # None /\ res'[q] # None /\ res'[q].qn = res[q].qn /\ res'[q].zone # res[q].zone)
            => StrictlyBelow(res'[q].zone, res[q].zone)]_vars

(* The CNAME loop always ends in SERVFAIL. *)
LoopServfails ==
    \A c \in Clients : \A q \in Questions :
        (q[1] \in {"loop.sld.tld", "loop.alt.tld"} /\ ans[c][q] # None) => ans[c][q].rcode = "SERVFAIL"

(* Every query asked is answered. *)
EveryQueryAnswered ==
    \A c \in Clients, q \in Questions : (q \in asked[c]) ~> (ans[c][q] # None)

=============================================================================
