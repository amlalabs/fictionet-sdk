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
(* matches *.w.alt). One world edit changes www and ns and creates nx.     *)
(*                                                                         *)
(* With Rogue, server 1 of alt.tld also sends a record for www.sld.tld,    *)
(* outside its bailiwick: a real authority seen through a live source may  *)
(* send anything.                                                          *)
(*                                                                         *)
(* Each client asks a fixed script of A questions, one at a time, as a stub *)
(* resolver does; two clients asking the same question share one           *)
(* resolution. The resolver starts with the root's servers as hints and    *)
(* keeps every cut it learns (NS TTLs outlast MaxTime).                    *)
(*                                                                         *)
(* The network loses at most MaxLoss messages and truncates at most MaxTc  *)
(* UDP replies. A lost message enables the timeout of its exchange; the    *)
(* clock plays no part in timeouts. The clock only ages cache entries, and *)
(* it does not advance while a reply is in flight, since simulated round   *)
(* trips are far shorter than a TTL second.                                *)
(*                                                                         *)
(* Ablation flags: CheckBailiwick, BoundWork, CacheTc, CheckExpiry, and    *)
(* FailureAsNegative. Each is the rule as the design states it when TRUE   *)
(* (FALSE for CacheTc and FailureAsNegative).                              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Clients,           \* clients of the resolver
    Script,            \* the distinct A questions every client asks, in this order
    MaxTime,           \* the clock runs 0..MaxTime
    MaxWork,           \* upstream queries per resolution (Config.work.queries)
    MaxChain,          \* CNAME restarts per resolution (Config.work.depth)
    MaxLoss,           \* messages the network may lose
    MaxTc,             \* UDP replies the network may truncate
    MaxEdits,          \* world edits (0 or 1)
    Rogue,             \* server 1 of alt.tld adds an out-of-bailiwick record
    CheckBailiwick,    \* records outside the answering zone are dropped
    BoundWork,         \* the work and chain bounds are kept
    CacheTc,           \* ablation: a truncated reply is cached
    CheckExpiry,       \* entries are never used at or after their expiry
    FailureAsNegative, \* ablation: a failure is cached as NXDOMAIN
    None               \* a model value for "nothing here"

-----------------------------------------------------------------------------
(* The namespace *)

Root == "."
Zones == {".", "tld", "sld.tld", "alt.tld"}

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

\* What the zone holds for "n A" at version v (RFC 1034 section 4.3.2, RFC 4592).
Lookup(v, n) ==
    LET own == Own(v, n)
        wild == Wild(v, n)
    IN  IF \E r \in own : r.t = "CNAME" THEN [t |-> "cname", val |-> (CHOOSE r \in own : r.t = "CNAME").val,
                                              ttl |-> (CHOOSE r \in own : r.t = "CNAME").ttl]
        ELSE IF \E r \in own : r.t = "A" THEN [t |-> "a", val |-> (CHOOSE r \in own : r.t = "A").val,
                                              ttl |-> (CHOOSE r \in own : r.t = "A").ttl]
        ELSE IF NodeAtOrBelow(v, n) THEN [t |-> "nodata", val |-> None, ttl |-> NegTtl]
        ELSE IF wild # {} THEN [t |-> "a", val |-> (CHOOSE r \in wild : TRUE).val,
                                ttl |-> (CHOOSE r \in wild : TRUE).ttl]
        ELSE [t |-> "nx", val |-> None, ttl |-> NegTtl]

\* Server <<z, 1>> answers from the data; server <<z, 2>> is lame.
Servers == Zones \X {1, 2}
ServersOf(z) == {z} \X {1, 2}

\* The names whose answers the resolver may cache.
CacheNames == {"www.sld.tld", "cn.sld.tld", "ent.sld.tld", "nx.sld.tld", "ns.sld.tld",
               "loop.sld.tld", "loop.alt.tld", "x.w.alt.tld"}

Poison == [n |-> "www.sld.tld", val |-> "Poison", ttl |-> 2]

Questions == {Script[i] : i \in 1..Len(Script)}

\* The scripts the configs pick with "Script <- ...", since a config file
\* cannot write a sequence.
ScriptBase == <<"cn.sld.tld", "www.sld.tld", "ent.sld.tld", "nx.sld.tld", "x.w.alt.tld">>
ScriptConcurrent == <<"cn.sld.tld", "www.sld.tld">>
ScriptLoop == <<"loop.sld.tld">>
ScriptRogue == <<"x.w.alt.tld", "www.sld.tld">>
ScriptEdit == <<"www.sld.tld", "ns.sld.tld", "nx.sld.tld">>

-----------------------------------------------------------------------------
VARIABLES
    now,      \* the clock
    ver,      \* the data version the servers serve
    editAt,   \* when the edit happened (None before)
    cache,    \* [CacheNames -> entry or None]
    known,    \* the zones whose cut and server addresses the resolver holds
    res,      \* [Questions -> resolution or None]: one per question, shared by its clients
    waiting,  \* [Questions -> clients waiting on that resolution]
    asked,    \* [Clients -> questions asked]
    ans,      \* [Clients -> [Questions -> answer or None]]
    net,      \* messages in flight
    lost,     \* messages lost so far
    tcs       \* replies truncated so far

vars == <<now, ver, editAt, cache, known, res, waiting, asked, ans, net, lost, tcs>>

\* A cache entry. rank is "auth" or "glue" (RFC 2181 section 5.4.1); from is
\* the zone of the server that sent it; tc says it came from a truncated
\* reply; failure says it was written for a failed resolution.
Entry(t, val, ttl, rank, from, tc, failure) ==
    [t |-> t, val |-> val, ttl |-> ttl, readAt |-> now, rank |-> rank, from |-> from,
     tc |-> tc, failure |-> failure]

Usable(e) ==
    /\ e # None
    /\ e.rank = "auth"
    /\ CheckExpiry => now < e.readAt + e.ttl

\* The deepest zone the resolver holds a cut for that contains n.
Closest(n) == CHOOSE z \in known : AtOrBelow(n, z)
                 /\ \A y \in known : AtOrBelow(n, y) => AtOrBelow(z, y)

NewRes(q) == [qn |-> q, zone |-> Closest(q), tried |-> {}, out |-> None,
              work |-> 0, chain |-> 0, recs |-> {}]

\* What an answer to a client records about each entry it used.
Used(n, e) == [n |-> n, t |-> e.t, val |-> e.val, ttl |-> e.ttl, readAt |-> e.readAt,
               rank |-> e.rank, failure |-> e.failure]

Rcode(t) == CASE t = "a" -> "NOERROR" [] t = "cname" -> "NOERROR"
              [] t = "nodata" -> "NODATA" [] t = "nx" -> "NXDOMAIN" [] t = "fail" -> "SERVFAIL"

Msg(k, q, qn, srv, tcp, tc, body) ==
    [k |-> k, q |-> q, qn |-> qn, srv |-> srv, tcp |-> tcp, tc |-> tc, body |-> body]
Body(kind, to, rr, extra) == [kind |-> kind, to |-> to, rr |-> rr, extra |-> extra]

\* The reply server s sends for "n A" at the current version.
Respond(s, n) ==
    LET z == s[1] IN
    IF s[2] = 2
    THEN IF z = Root THEN Body("refused", None, None, {})
         ELSE Body("referral", Root, None, {})
    ELSE IF ~AtOrBelow(n, z) THEN Body("refused", None, None, {})
    ELSE IF ZoneOf(n) # z
    THEN Body("referral", ChildToward(z, n), None,
              IF ChildToward(z, n) = "sld.tld" THEN {Glue} ELSE {})
    ELSE Body("answer", None, Lookup(ver, n),
              IF Rogue /\ z = "alt.tld" THEN {Poison} ELSE {})

-----------------------------------------------------------------------------
Init ==
    /\ now = 0
    /\ ver = 0
    /\ editAt = None
    /\ cache = [n \in CacheNames |-> None]
    /\ known = {Root}
    /\ res = [q \in Questions |-> None]
    /\ waiting = [q \in Questions |-> {}]
    /\ asked = [c \in Clients |-> {}]
    /\ ans = [c \in Clients |-> [q \in Questions |-> None]]
    /\ net = {}
    /\ lost = 0
    /\ tcs = 0

(* A client asks the next question of the script once its last one is      *)
(* answered, as a stub resolver does. It joins the resolution already       *)
(* running for that question, if another client started one.              *)
Ask(c, q) ==
    /\ Cardinality(asked[c]) < Len(Script)
    /\ q = Script[Cardinality(asked[c]) + 1]
    /\ \A p \in asked[c] : ans[c][p] # None
    /\ asked' = [asked EXCEPT ![c] = @ \cup {q}]
    /\ waiting' = [waiting EXCEPT ![q] = @ \cup {c}]
    /\ res' = IF res[q] = None THEN [res EXCEPT ![q] = NewRes(q)] ELSE res
    /\ UNCHANGED <<now, ver, editAt, cache, known, ans, net, lost, tcs>>

\* Every waiter of q gets the answer, rendered now.
Finish(q, rcode, recs) ==
    /\ ans' = [c \in Clients |-> IF c \in waiting[q]
                                  THEN [ans[c] EXCEPT ![q] = [rcode |-> rcode, recs |-> recs, at |-> now]]
                                  ELSE ans[c]]
    /\ res' = [res EXCEPT ![q] = None]
    /\ waiting' = [waiting EXCEPT ![q] = {}]

(* The resolution fails: every server was tried, or the work bound was    *)
(* reached. The failure is cached for failure_ttl (RFC 9520).             *)
Fail(q) ==
    LET r == res[q]
        e == Entry(IF FailureAsNegative THEN "nx" ELSE "fail", None, FailureTtl, "auth",
                   r.zone, FALSE, TRUE)
    IN  /\ cache' = [cache EXCEPT ![r.qn] = e]
        /\ Finish(q, Rcode(e.t), {Used(r.qn, e)})

\* A record is live while its TTL has not run out.
Live(u) == now < u.readAt + u.ttl

(* A resolution with no exchange outstanding takes its next step: from the  *)
(* cache when it can, otherwise a query to a server of the closest cut.    *)
Advance(q) ==
    /\ res[q] # None
    /\ res[q].out = None
    /\ LET r == res[q]
           e == cache[r.qn]
       IN
       \/ /\ Usable(e)
          /\ e.t # "cname"
          /\ LET recs == r.recs \cup {Used(r.qn, e)} IN
             IF CheckExpiry /\ \E u \in recs : ~Live(u)
             \* A link of the chain ran out while the chase went on: follow the
             \* chain again from the question, keeping the work done so far.
             THEN /\ res' = [res EXCEPT ![q] = [NewRes(q) EXCEPT !.work = r.work, !.chain = r.chain]]
                  /\ UNCHANGED <<waiting, ans>>
             ELSE Finish(q, Rcode(e.t), recs)
          /\ UNCHANGED <<cache, net>>
       \/ /\ Usable(e)
          /\ e.t = "cname"
          /\ IF BoundWork /\ r.chain >= MaxChain
             \* The chain is too long: SERVFAIL, keeping the cached CNAME.
             THEN /\ Finish(q, "SERVFAIL", {})
                  /\ UNCHANGED <<cache, net>>
             ELSE /\ res' = [res EXCEPT ![q] = [qn |-> e.val, zone |-> Closest(e.val), tried |-> {},
                                              out |-> None, work |-> r.work,
                                              chain |-> IF BoundWork THEN r.chain + 1 ELSE 0,
                                              recs |-> r.recs \cup {Used(r.qn, e)}]]
                  /\ UNCHANGED <<cache, waiting, ans, net>>
       \/ /\ ~Usable(e)
          /\ IF BoundWork /\ r.work >= MaxWork
             THEN Fail(q) /\ UNCHANGED net
             ELSE IF \A s \in ServersOf(r.zone) : <<s, FALSE>> \in r.tried
             THEN Fail(q) /\ UNCHANGED net
             ELSE \E s \in ServersOf(r.zone) :
                    /\ <<s, FALSE>> \notin r.tried
                    /\ res' = [res EXCEPT ![q].out = <<s, FALSE>>,
                                          ![q].work = IF BoundWork THEN @ + 1 ELSE 0]
                    /\ net' = net \cup {Msg("q", q, r.qn, s, FALSE, FALSE, None)}
                    /\ UNCHANGED <<cache, waiting, ans>>
    /\ UNCHANGED <<now, ver, editAt, known, asked, lost, tcs>>

(* A server gets a query and replies at once from the data it serves now. *)
ServeOne(m) ==
    /\ m \in net
    /\ m.k = "q"
    /\ net' = (net \ {m}) \cup {Msg("r", m.q, m.qn, m.srv, m.tcp, FALSE, Respond(m.srv, m.qn))}
    /\ UNCHANGED <<now, ver, editAt, cache, known, res, waiting, asked, ans, lost, tcs>>

\* Caching rules for an extra record, glue included: an entry is replaced only
\* by one of equal or higher rank (RFC 2181 section 5.4.1).
CacheExtra(c, x, rank, zone) ==
    IF x.n \in CacheNames /\ (CheckBailiwick => AtOrBelow(x.n, zone))
       /\ (c[x.n] = None \/ c[x.n].rank = "glue" \/ rank = "auth")
    THEN [c EXCEPT ![x.n] = Entry("a", x.val, x.ttl, rank, zone, FALSE, FALSE)]
    ELSE c

RECURSIVE CacheAll(_, _, _, _)
CacheAll(c, xs, rank, zone) ==
    IF xs = {} THEN c
    ELSE LET x == CHOOSE y \in xs : TRUE IN CacheAll(CacheExtra(c, x, rank, zone), xs \ {x}, rank, zone)

(* The resolver takes a reply for the exchange it has outstanding. *)
ReceiveOne(m) ==
    /\ m \in net
    /\ m.k = "r"
    /\ res[m.q] # None
    /\ res[m.q].out = <<m.srv, m.tcp>>
    /\ LET q == m.q
           r == res[q]
           b == m.body
           tried == r.tried \cup {r.out}
       IN
       CASE m.tc ->
              \* RFC 7766: retry the same server over TCP. A truncated reply is
              \* never cached (RFC 2181 section 9).
              /\ cache' = IF CacheTc
                          THEN [cache EXCEPT ![r.qn] = Entry("nodata", None, NegTtl, "auth",
                                                               m.srv[1], TRUE, FALSE)]
                          ELSE cache
              /\ IF BoundWork /\ r.work >= MaxWork
                 THEN /\ res' = [res EXCEPT ![q].out = None, ![q].tried = tried]
                      /\ net' = net \ {m}
                 ELSE /\ res' = [res EXCEPT ![q].out = <<m.srv, TRUE>>, ![q].tried = tried,
                                            ![q].work = IF BoundWork THEN @ + 1 ELSE 0]
                      /\ net' = (net \ {m}) \cup {Msg("q", q, r.qn, m.srv, TRUE, FALSE, None)}
              /\ UNCHANGED known
         [] b.kind = "refused" ->
              /\ res' = [res EXCEPT ![q].out = None, ![q].tried = tried]
              /\ net' = net \ {m}
              /\ UNCHANGED <<cache, known>>
         [] b.kind = "referral" ->
              \* A referral must lead strictly below the current cut and to a zone
              \* at or above the name; anything else is lame.
              IF StrictlyBelow(b.to, r.zone) /\ AtOrBelow(r.qn, b.to)
              THEN /\ known' = known \cup {b.to}
                   /\ cache' = CacheAll(cache, b.extra, "glue", m.srv[1])
                   /\ res' = [res EXCEPT ![q].out = None, ![q].zone = b.to, ![q].tried = {}]
                   /\ net' = net \ {m}
              ELSE /\ res' = [res EXCEPT ![q].out = None, ![q].tried = tried]
                   /\ net' = net \ {m}
                   /\ UNCHANGED <<cache, known>>
         [] b.kind = "answer" ->
              /\ cache' = CacheAll([cache EXCEPT ![r.qn] = Entry(b.rr.t, b.rr.val, b.rr.ttl, "auth",
                                                                   m.srv[1], FALSE, FALSE)],
                                   b.extra, "auth", m.srv[1])
              /\ res' = [res EXCEPT ![q].out = None]
              /\ net' = net \ {m}
              /\ UNCHANGED known
    /\ UNCHANGED <<now, ver, editAt, waiting, asked, ans, lost, tcs>>

(* The exchange's message was lost, so its timeout fires. *)
Timeout(q) ==
    /\ res[q] # None
    /\ res[q].out # None
    /\ ~\E m \in net : m.q = q
    /\ res' = [res EXCEPT ![q].tried = @ \cup {res[q].out}, ![q].out = None]
    /\ UNCHANGED <<now, ver, editAt, cache, known, waiting, asked, ans, net, lost, tcs>>

LoseOne(m) ==
    /\ m \in net
    /\ lost < MaxLoss
    /\ net' = net \ {m}
    /\ lost' = lost + 1
    /\ UNCHANGED <<now, ver, editAt, cache, known, res, waiting, asked, ans, tcs>>

(* A UDP reply too large for the path arrives with TC and no records. *)
TruncateOne(m) ==
    /\ m \in net
    /\ m.k = "r" /\ ~m.tcp /\ ~m.tc
    /\ tcs < MaxTc
    /\ net' = (net \ {m}) \cup {[m EXCEPT !.tc = TRUE, !.body = Body("empty", None, None, {})]}
    /\ tcs' = tcs + 1
    /\ UNCHANGED <<now, ver, editAt, cache, known, res, waiting, asked, ans, lost>>

Tick ==
    /\ now < MaxTime
    /\ \A m \in net : m.k = "q"
    /\ now' = now + 1
    \* An expired entry is gone: it can never be used again.
    /\ cache' = IF CheckExpiry
                THEN [n \in CacheNames |-> IF cache[n] # None /\ now + 1 >= cache[n].readAt + cache[n].ttl
                                           THEN None ELSE cache[n]]
                ELSE cache
    /\ UNCHANGED <<ver, editAt, known, res, waiting, asked, ans, net, lost, tcs>>

WorldEdit ==
    /\ ver < MaxEdits
    /\ ver' = ver + 1
    /\ editAt' = now
    /\ UNCHANGED <<now, cache, known, res, waiting, asked, ans, net, lost, tcs>>

\* Each network step on some message, named so traces show which one ran.
Serve == \E m \in net : ServeOne(m)
Receive == \E m \in net : ReceiveOne(m)
Lose == \E m \in net : LoseOne(m)
Truncate == \E m \in net : TruncateOne(m)

Next ==
    \/ \E c \in Clients, q \in Questions : Ask(c, q)
    \/ \E q \in Questions : Advance(q)
    \/ \E q \in Questions : Timeout(q)
    \/ Serve
    \/ Receive
    \/ Lose
    \/ Truncate
    \/ Tick
    \/ WorldEdit

(* The network delivers and the resolver works. Asking, losing, truncating,  *)
(* the clock, and the edit are never forced.                                *)
Fairness ==
    /\ \A q \in Questions : WF_vars(Advance(q)) /\ WF_vars(Timeout(q))
    /\ WF_vars(Serve)
    /\ WF_vars(Receive)

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

\* Some second within the record's TTL before t at which the data said u.
TrueWithin(u, t) ==
    \E s \in 0..MaxTime : s <= t /\ s > t - u.ttl /\
        \E v \in VersionsAt(s) : LET l == Lookup(v, u.n) IN l.t = u.t /\ l.val = u.val

Answers == {ans[c][q] : c \in Clients, q \in Questions} \ {None}

(* Every record of a NOERROR answer was in the data at some second within   *)
(* its TTL before the reply.                                                *)
AnswersTrueWithinTtl ==
    \A a \in Answers : a.rcode = "NOERROR" => \A u \in a.recs : TrueWithin(u, a.at)

(* NXDOMAIN only for a name with no node at or below it and no wildcard;     *)
(* NODATA only for a node without the type. Both held within the TTL.       *)
NegativeTrue ==
    \A a \in Answers : \A u \in a.recs :
        /\ (a.rcode = "NXDOMAIN" /\ u.t = "nx") =>
             \E s \in 0..MaxTime : s <= a.at /\ s > a.at - u.ttl /\
                 \E v \in VersionsAt(s) : ~NodeAtOrBelow(v, u.n) /\ Wild(v, u.n) = {}
        /\ (a.rcode = "NODATA" /\ u.t = "nodata") =>
             \E s \in 0..MaxTime : s <= a.at /\ s > a.at - u.ttl /\
                 \E v \in VersionsAt(s) : NodeAtOrBelow(v, u.n) /\
                     ~\E r \in Own(v, u.n) : r.t \in {"A", "CNAME"}

(* Every cached record came from a server for a zone at or above its name. *)
NoPoison ==
    \A n \in CacheNames : cache[n] # None => AtOrBelow(n, cache[n].from)

(* No answer to a client rests on glue. *)
GlueNeverAnswers ==
    \A a \in Answers : \A u \in a.recs : u.rank = "auth"

(* No answer uses a record at or after its expiry. *)
TtlSound ==
    \A a \in Answers : \A u \in a.recs : a.at < u.readAt + u.ttl

(* Nothing from a truncated reply is cached. *)
TcNotCached ==
    \A n \in CacheNames : cache[n] # None => ~cache[n].tc

(* A failure never answers NXDOMAIN or NODATA (RFC 9520). *)
FailureNeverNegative ==
    \A a \in Answers : a.rcode \in {"NXDOMAIN", "NODATA"} => \A u \in a.recs : ~u.failure

(* Each resolution stays within its work and chain bounds. *)
WorkBounded ==
    \A q \in Questions : res[q] # None => res[q].work <= MaxWork /\ res[q].chain <= MaxChain

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
    \A c \in Clients : \A q \in Questions \cap {"loop.sld.tld", "loop.alt.tld"} :
        ans[c][q] # None => ans[c][q].rcode = "SERVFAIL"

(* Every query asked is answered. *)
EveryQueryAnswered ==
    \A c \in Clients, q \in Questions : (q \in asked[c]) ~> (ans[c][q] # None)

=============================================================================
