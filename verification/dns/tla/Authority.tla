------------------------------ MODULE Authority ------------------------------
(***************************************************************************)
(* The authority engine of `services::dns::authority` serving three        *)
(* addresses of one world: a root server, a TLD server, and the server of  *)
(* an edited zone "fict".                                                  *)
(*                                                                         *)
(* The root and TLD servers both run Overlay(Copies).below("fict", Lazy),  *)
(* as Mirror::wrap puts an overlay on every server a mirror makes. Each    *)
(* answers from the learned copy of its zone: the facts filed from         *)
(* responses of the real server at its address. A question the copy does   *)
(* not settle is looked up: the server returns Need with a lookup of the   *)
(* client's question at its own address, the driver puts it to the         *)
(* upstream, the engine files the response into the copy the lookup names  *)
(* and asks the authority again. For a question at or below "fict" the     *)
(* overlay reads the edited zone's apex NS RRset and the addresses of its  *)
(* target "ns.fict" from the lazy zone, then asks its base for "fict DS".  *)
(* The real TLD server serves fict's parent, so the TLD server refers: a   *)
(* referral composed from what it read, or SERVFAIL when the target's      *)
(* address is not there. The real root server does not: its response to    *)
(* "fict DS" refers to the TLD, a cut the root's copy files, which settles *)
(* every name below the TLD, so the root server answers the question from  *)
(* its copy with no second lookup. The fict server answers from a Lazy     *)
(* zone whose Provider says, per name, Present, Absent, or Unknown, and    *)
(* whose answers change as the world runs.                                 *)
(*                                                                         *)
(* Every lookup passes the world's Only policy before the upstream sees    *)
(* it; a refused lookup gives NoReply. The upstream answers after any      *)
(* delay, may fail (Unreachable or NoReply), and returns the real server's *)
(* response as it is when it answers. The real data may change once.       *)
(* Requests that need the same lookup wait on one. A request that needs a  *)
(* lookup it already made gets no reply. A new session drops what every    *)
(* copy learned and abandons the pending lookups.                          *)
(*                                                                         *)
(* A revision is a snapshot of the lazy zone: the world's state (what the  *)
(* provider says) and the names the zone has inserted. Revisions grow when *)
(* the world changes and when a view inserts a name, including while other *)
(* requests wait on a lookup.                                              *)
(*                                                                         *)
(* Ablation flags: NoPolicy (no Only), RootExempt (lookups at root and TLD *)
(* servers skip the policy), UnknownAsAbsent (a view reads Unknown as      *)
(* Absent, and a copy reads a question it does not settle as NXDOMAIN),    *)
(* MixedRevision (the lazy view reads the name and the wildcard under two  *)
(* lock acquisitions), Reask (the engine puts a lookup again when a        *)
(* request needs one it already made), ParkInView (the overlay parks while *)
(* it still holds its read of the lazy zone), NoShare (each need puts its  *)
(* own lookup, even when the same one is pending), AnyZone (a response is  *)
(* filed into every copy, not only the one its lookup names), WakeOne (a   *)
(* finished lookup wakes only the request that started it).                *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Reqs,            \* the requests guests send: [id, srv, q]
    MaxRevision,     \* the world changes only while fewer revisions than this exist
    MaxGeneration,   \* generations run 1..MaxGeneration
    MaxRealChanges,  \* changes to the real servers' data
    Failures,        \* the upstream may fail
    NoPolicy,        \* ablation: no Only policy
    RootExempt,      \* ablation: lookups at the root and TLD servers skip the policy
    UnknownAsAbsent, \* ablation: Unknown is read as Absent
    MixedRevision,   \* ablation: the lazy view reads under two lock acquisitions
    Reask,           \* ablation: a lookup a request already made is put again
    ParkInView,      \* ablation: the overlay parks while holding its read of the lazy zone
    NoShare,         \* ablation: requests never wait on a lookup already pending
    AnyZone,         \* ablation: a response is filed into every copy
    WakeOne,         \* ablation: a finished lookup wakes only the request that started it
    None

Apex == "fict"
\* The target of the apex NS RRset, whose addresses a referral carries.
NsTarget == "ns.fict"
Wildcard == "*.fict"
\* Names at or below the edited apex. Everything else is unedited.
Edited == {"fict", "ns.fict", "a.fict", "b.fict", "c.fict", "*.fict"}

\* The servers whose zones are learned copies of the real servers' zones.
Copied == {"root", "tld"}
\* The questions a copy may hold the answer to.
Questions == {"www.real", "nx.real", "leak.evil", "fict DS", "a.fict"}

\* The world's predicate for lookups: the guest-chosen name "leak.evil" must
\* never reach a real server, whichever server it is addressed to.
Allowed(l) == l.q # "leak.evil"

PolicyPasses(l) ==
    \/ NoPolicy
    \/ RootExempt /\ l.srv \in Copied
    \/ Allowed(l)

\* What the provider says about n while the world is at w.
Provider(w, n) ==
    CASE n = Apex     -> "present"
      [] n = NsTarget -> IF w = 0 THEN "present" ELSE "unknown"
      [] n = "a.fict" -> IF w = 0 THEN "absent" ELSE "present"
      [] n = "b.fict" -> "unknown"
      [] n = "c.fict" -> "absent"
      [] n = Wildcard -> IF w = 0 THEN "absent" ELSE "present"

\* The real server's response to lookup l while the real data is at v, and
\* its RCODE: "nx.real" does not exist.
RealReply(l, v) == <<l.srv, l.q, v>>
RealRcode(q) == IF q = "nx.real" THEN "NXDOMAIN" ELSE "NOERROR"

\* A question at or below the edited apex at a server the overlay runs on.
Crosses(r) == r.q \in Edited /\ r.srv \in Copied

\* Whether the real server at srv serves fict's parent: its response to
\* "fict DS" has AA and the parent's SOA. The TLD server does; the root
\* server refers to the TLD.
Serves(srv) == srv = "tld"

\* A crossing question at a server of fict's parent gets a referral.
Referral(r) == Crosses(r) /\ Serves(r.srv)

\* The questions a response to x at server z settles in z's copy. The root's
\* response to a question below the TLD is a referral to it, a cut that
\* settles every question below the TLD; any other response settles its own
\* question.
BelowTld == {"fict DS", "a.fict"}
Settles(z, x) == IF z = "root" /\ x \in BelowTld THEN BelowTld ELSE {x}

DsLookup(r) == [srv |-> r.srv, q |-> "fict DS"]
OwnLookup(r) == [srv |-> r.srv, q |-> r.q]

\* The fict server answers from the lazy zone with no lookup.
FromView(r) == r.srv = "fict"

Observations == {"reply", "unreachable", "noreply"}

\* The request sets the configs pick with "Reqs <- ...".
Real == [id |-> "real", srv |-> "root", q |-> "www.real"]
Real2 == [id |-> "real2", srv |-> "root", q |-> "www.real"]
RealTld == [id |-> "realtld", srv |-> "tld", q |-> "www.real"]
NxReal == [id |-> "nx", srv |-> "root", q |-> "nx.real"]
Leak == [id |-> "leak", srv |-> "root", q |-> "leak.evil"]
LazyA == [id |-> "a", srv |-> "fict", q |-> "a.fict"]
LazyB == [id |-> "b", srv |-> "fict", q |-> "b.fict"]
LazyC == [id |-> "c", srv |-> "fict", q |-> "c.fict"]
Cross == [id |-> "cross", srv |-> "tld", q |-> "a.fict"]
CrossRoot == [id |-> "crossroot", srv |-> "root", q |-> "a.fict"]
ReqsBase == {Real, NxReal, Leak, LazyB, Cross, CrossRoot}
ReqsFail == {Real, Leak, Cross, CrossRoot}
ReqsLazy == {LazyA, LazyB, LazyC, Cross}
ReqsAdvance == {Real, Cross}
ReqsShare == {Real, Real2, RealTld}

VARIABLES
    world,     \* the world's state: what the provider says
    ins,       \* names the lazy zone has inserted
    history,   \* every revision so far: [w, ins]
    rev,       \* revisions so far, less one
    real,      \* the real servers' data version
    realSeen,  \* real versions that have existed
    gen,       \* the engine's generation
    st,        \* [Reqs -> "new" | "reading" | "overlay" | "parked" | "done"]
    looked,    \* [Reqs -> lookups made for the request in this generation]
    partial,   \* [Reqs -> None or facts read so far under the lazy zone's lock]
    reply,     \* [Reqs -> None or the reply sent]
    nNeeds,    \* [Reqs -> needs the request parked on in this generation]
    waiting,   \* [Reqs -> None or the token of the lookup it waits on]
    pending,   \* the engine's pending lookups: [token, lookup, by]
    copy,      \* [Copied -> [Questions -> None or the filed response [v, val]]]
    atSource,  \* lookups the upstream is working on: [token, lookup]
    obsq,      \* what lookups gave, on its way back: [token, lookup, obs, v]
    reached,   \* every lookup the upstream has received
    sent       \* every response the upstream sent: [lookup, v]

vars == <<world, ins, history, rev, real, realSeen, gen, st, looked, partial, reply, nNeeds,
          waiting, pending, copy, atSource, obsq, reached, sent>>

FactAt(s, n) == IF n \in s.ins THEN "present" ELSE Provider(s.w, n)
Fact(n) == FactAt([w |-> world, ins |-> ins], n)

\* How the lazy view reads a fact.
Read(f) == IF UnknownAsAbsent /\ f = "unknown" THEN "absent" ELSE f

EmptyCopy == [x \in Questions |-> None]

Init ==
    /\ world = 0
    /\ ins = {}
    /\ history = {[w |-> 0, ins |-> {}]}
    /\ rev = 0
    /\ real = 0
    /\ realSeen = {0}
    /\ gen = 1
    /\ st = [r \in Reqs |-> "new"]
    /\ looked = [r \in Reqs |-> {}]
    /\ partial = [r \in Reqs |-> None]
    /\ reply = [r \in Reqs |-> None]
    /\ nNeeds = [r \in Reqs |-> 0]
    /\ waiting = [r \in Reqs |-> None]
    /\ pending = {}
    /\ copy = [z \in Copied |-> EmptyCopy]
    /\ atSource = {}
    /\ obsq = {}
    /\ reached = {}
    /\ sent = {}

\* A reply. facts are the facts of the lazy zone it rests on, as the zone
\* held them; copied are the facts of a copy it rests on: [srv, x, v, val]
\* for the response to x filed in the copy of srv's zone, with x None for a
\* question the copy did not settle.
Reply(rcode, val, facts, copied) == [rcode |-> rcode, val |-> val, facts |-> facts, copied |-> copied]

\* The filed response in copy z that settles question q, or None.
Entry(z, q) ==
    IF \E x \in Questions : copy[z][x] # None /\ q \in Settles(z, x)
    THEN LET x == CHOOSE y \in Questions : copy[z][y] # None /\ q \in Settles(z, y)
         IN  [srv |-> z, x |-> x, v |-> copy[z][x].v, val |-> copy[z][x].val]
    ELSE None

\* The reply the lazy view gives for q from the facts read for q and the
\* wildcard (RFC 1034 section 4.3.2, RFC 4592). Unknown is SERVFAIL, never a
\* negative.
ViewReply(q, fq, fw) ==
    CASE Read(fq) = "present" -> Reply("NOERROR", <<q, "A">>, {<<q, fq>>}, {})
      [] Read(fq) = "unknown" -> Reply("SERVFAIL", None, {<<q, fq>>}, {})
      [] Read(fw) = "present" -> Reply("NOERROR", <<q, "A", "wild">>, {<<q, fq>>, <<Wildcard, fw>>}, {})
      [] Read(fw) = "unknown" -> Reply("SERVFAIL", None, {<<q, fq>>, <<Wildcard, fw>>}, {})
      [] OTHER                -> Reply("NXDOMAIN", None, {<<q, fq>>, <<Wildcard, fw>>}, {})

\* The names a view inserts: those the provider gave records for.
Inserted(q, fq, fw) ==
    {n \in {q, Wildcard} : (n = q /\ fq = "present") \/ (n = Wildcard /\ Read(fq) = "absent" /\ fw = "present")}

\* A view that inserts names makes a new revision.
Grow(new) ==
    IF new \subseteq ins
    THEN UNCHANGED <<ins, history, rev>>
    ELSE /\ ins' = ins \cup new
         /\ history' = history \cup {[w |-> world, ins |-> ins \cup new]}
         /\ rev' = rev + 1

(* The fict server answers from Lazy::view, which takes the zone's lock    *)
(* once and reads every fact the question needs at one revision.          *)
View(r) ==
    /\ st[r] = "new"
    /\ FromView(r)
    /\ ~MixedRevision
    /\ LET fq == Fact(r.q)
           fw == Fact(Wildcard)
       IN  /\ reply' = [reply EXCEPT ![r] = ViewReply(r.q, fq, fw)]
           /\ Grow(Inserted(r.q, fq, fw))
    /\ st' = [st EXCEPT ![r] = "done"]
    /\ UNCHANGED <<world, real, realSeen, gen, looked, partial, nNeeds, waiting, pending, copy,
                   atSource, obsq, reached, sent>>

(* With MixedRevision the view reads the name under one lock acquisition... *)
ReadName(r) ==
    /\ st[r] = "new"
    /\ FromView(r)
    /\ MixedRevision
    /\ partial' = [partial EXCEPT ![r] = Fact(r.q)]
    /\ Grow(IF Fact(r.q) = "present" THEN {r.q} ELSE {})
    /\ st' = [st EXCEPT ![r] = "reading"]
    /\ UNCHANGED <<world, real, realSeen, gen, looked, reply, nNeeds, waiting, pending, copy,
                   atSource, obsq, reached, sent>>

(* ...and the wildcard under another. *)
ReadRest(r) ==
    /\ st[r] = "reading"
    /\ LET fq == partial[r]
           fw == Fact(Wildcard)
       IN  /\ reply' = [reply EXCEPT ![r] = ViewReply(r.q, fq, fw)]
           /\ Grow(Inserted(r.q, fq, fw) \ {r.q})
    /\ partial' = [partial EXCEPT ![r] = None]
    /\ st' = [st EXCEPT ![r] = "done"]
    /\ UNCHANGED <<world, real, realSeen, gen, looked, nNeeds, waiting, pending, copy,
                   atSource, obsq, reached, sent>>

(* The engine calls respond. An overlay first reads the edited zone's apex *)
(* NS RRset and the address of its target under one view of the lazy      *)
(* zone, holding what it read, at either server. The engine runs one       *)
(* respond at a time, so nothing else moves until the step below ends it.  *)
ReadOverlay(r) ==
    /\ st[r] = "new"
    /\ ~FromView(r)
    /\ Crosses(r)
    /\ LET fa == Fact(Apex)
           fn == Fact(NsTarget)
       IN  /\ partial' = [partial EXCEPT ![r] = {<<Apex, fa>>, <<NsTarget, fn>>}]
           /\ Grow(IF fn = "present" THEN {NsTarget} ELSE {})
    /\ st' = [st EXCEPT ![r] = "overlay"]
    /\ UNCHANGED <<world, real, realSeen, gen, looked, reply, nNeeds, waiting, pending, copy,
                   atSource, obsq, reached, sent>>

\* The reply copy z gives for q from the response e that settles it.
CopyReply(e, q) ==
    Reply(RealRcode(q), e.val, {}, {[srv |-> e.srv, x |-> e.x, v |-> e.v, val |-> e.val]})

(* Authority::respond at a server of a learned zone, as a function of what *)
(* the copy holds and, for a crossing question, of what the overlay read:  *)
(* a reply, or the lookup the question needs. The overlay asks its base     *)
(* for "fict DS" first; at a server of fict's parent the referral rests on  *)
(* what it read and is SERVFAIL without the target's address, and at any    *)
(* other server the base answers the question itself.                      *)
Respond(r) ==
    LET z == r.srv
        own == Entry(z, r.q)
        ds == Entry(z, "fict DS")
        read == IF Crosses(r) THEN partial[r] ELSE {}
        unglued == \E f \in read : f[1] = NsTarget /\ Read(f[2]) # "present"
        fromCopy ==
            IF own # None THEN [kind |-> "reply", reply |-> CopyReply(own, r.q)]
            ELSE IF UnknownAsAbsent
            THEN [kind |-> "reply", reply |-> Reply("NXDOMAIN", None, {}, {[srv |-> z, x |-> None, v |-> None, val |-> None]})]
            ELSE [kind |-> "need", lookup |-> OwnLookup(r)]
    IN  IF ~Crosses(r) THEN fromCopy
        ELSE IF ds = None THEN [kind |-> "need", lookup |-> DsLookup(r)]
        ELSE IF ~Serves(z) THEN fromCopy
        ELSE LET dsFact == {[srv |-> ds.srv, x |-> ds.x, v |-> ds.v, val |-> ds.val]} IN
             IF unglued THEN [kind |-> "reply", reply |-> Reply("SERVFAIL", None, read, dsFact)]
             ELSE [kind |-> "reply", reply |-> Reply("NOERROR", <<"referral", Apex>>, read, dsFact)]

\* The lookup a request needs now, or None.
NeedOf(r) == IF Respond(r).kind = "need" THEN Respond(r).lookup ELSE None

(* The engine acts on the step. A Need for a lookup the request already     *)
(* made gets no reply. Any other Need parks the request: on the same        *)
(* lookup when it is pending, or else under a fresh token on a new one,     *)
(* which goes through the policy; a refused lookup comes back as NoReply    *)
(* without reaching the upstream. An overlay lets go of what it read from   *)
(* the lazy zone first.                                                     *)
Step(r) ==
    /\ \/ st[r] = "new" /\ ~Crosses(r)
       \/ st[r] = "overlay"
    /\ ~FromView(r)
    /\ LET s == Respond(r)
           released == [partial EXCEPT ![r] = None]
       IN  /\ UNCHANGED <<ins, history, rev>>
           /\ IF s.kind = "reply"
              THEN /\ reply' = [reply EXCEPT ![r] = s.reply]
                   /\ st' = [st EXCEPT ![r] = "done"]
                   /\ partial' = released
                   /\ UNCHANGED <<nNeeds, waiting, pending, atSource, obsq, reached>>
              ELSE IF s.lookup \in looked[r] /\ ~Reask
              THEN /\ reply' = [reply EXCEPT ![r] = Reply("SILENT", None, {}, {})]
                   /\ st' = [st EXCEPT ![r] = "done"]
                   /\ partial' = released
                   /\ UNCHANGED <<nNeeds, waiting, pending, atSource, obsq, reached>>
              ELSE LET a == s.lookup
                       tok == <<gen, r.id, nNeeds[r]>>
                       shared == {p \in pending : p.lookup = a}
                   IN  /\ st' = [st EXCEPT ![r] = "parked"]
                       /\ nNeeds' = [nNeeds EXCEPT ![r] = @ + 1]
                       /\ partial' = IF ParkInView THEN partial ELSE released
                       /\ IF shared # {} /\ ~NoShare
                          THEN /\ waiting' = [waiting EXCEPT ![r] = (CHOOSE p \in shared : TRUE).token]
                               /\ UNCHANGED <<pending, atSource, obsq, reached>>
                          ELSE /\ waiting' = [waiting EXCEPT ![r] = tok]
                               /\ pending' = pending \cup {[token |-> tok, lookup |-> a, by |-> r]}
                               /\ IF PolicyPasses(a)
                                  THEN /\ atSource' = atSource \cup {[token |-> tok, lookup |-> a]}
                                       /\ reached' = reached \cup {a}
                                       /\ UNCHANGED obsq
                                  ELSE /\ obsq' = obsq \cup {[token |-> tok, lookup |-> a, obs |-> "noreply",
                                                              v |-> None]}
                                       /\ UNCHANGED <<atSource, reached>>
                       /\ UNCHANGED reply
    /\ UNCHANGED <<world, real, realSeen, gen, looked, copy, sent>>

(* The upstream finishes a lookup: the real server's response as it is now, *)
(* or a failure.                                                           *)
SourceOne(x) ==
    /\ atSource' = atSource \ {x}
    /\ \E o \in (IF Failures THEN Observations ELSE {"reply"}) :
         /\ obsq' = obsq \cup {[token |-> x.token, lookup |-> x.lookup, obs |-> o,
                                v |-> IF o = "reply" THEN real ELSE None]}
         /\ sent' = IF o = "reply" THEN sent \cup {[lookup |-> x.lookup, v |-> real]} ELSE sent
    /\ UNCHANGED <<world, ins, history, rev, real, realSeen, gen, st, looked, partial, reply, nNeeds,
                   waiting, pending, copy, reached>>

\* A response filed into copy z: the copies the lookup names, or with
\* AnyZone every copy.
FiledInto(l) == IF AnyZone THEN Copied ELSE {l.srv}

(* What a lookup gave comes back. Only a pending token counts: the engine  *)
(* files a response into the copy the lookup names, then asks the          *)
(* authority again for every request that waited on the lookup.            *)
ObserveOne(o) ==
    /\ obsq' = obsq \ {o}
    /\ IF \E p \in pending : p.token = o.token
       THEN LET p == CHOOSE p \in pending : p.token = o.token
                woken == {r \in Reqs : st[r] = "parked" /\ waiting[r] = o.token /\ (~WakeOne \/ r = p.by)}
            IN  /\ pending' = pending \ {p}
                /\ copy' = IF o.obs = "reply"
                           THEN [z \in Copied |-> IF z \in FiledInto(o.lookup)
                                                  THEN [copy[z] EXCEPT ![o.lookup.q] =
                                                          [v |-> o.v, val |-> RealReply(o.lookup, o.v)]]
                                                  ELSE copy[z]]
                           ELSE copy
                /\ st' = [r \in Reqs |-> IF r \in woken THEN "new" ELSE st[r]]
                /\ looked' = [r \in Reqs |-> IF r \in woken THEN looked[r] \cup {o.lookup} ELSE looked[r]]
                /\ waiting' = [r \in Reqs |-> IF r \in woken THEN None ELSE waiting[r]]
       ELSE UNCHANGED <<pending, copy, st, looked, waiting>>
    /\ UNCHANGED <<world, ins, history, rev, real, realSeen, gen, partial, reply, nNeeds, atSource,
                   reached, sent>>

(* The world runs: the provider's answers change, a new revision. *)
WorldChange ==
    /\ world = 0
    /\ rev < MaxRevision
    /\ world' = 1
    /\ history' = history \cup {[w |-> 1, ins |-> ins]}
    /\ rev' = rev + 1
    /\ UNCHANGED <<ins, real, realSeen, gen, st, looked, partial, reply, nNeeds, waiting, pending,
                   copy, atSource, obsq, reached, sent>>

RealChange ==
    /\ real < MaxRealChanges
    /\ real' = real + 1
    /\ realSeen' = realSeen \cup {real + 1}
    /\ UNCHANGED <<world, ins, history, rev, gen, st, looked, partial, reply, nNeeds, waiting,
                   pending, copy, atSource, obsq, reached, sent>>

(* A new session: every copy drops what it learned, the pending lookups    *)
(* are abandoned, and parked requests restart under the new generation     *)
(* with no lookups made; what an abandoned lookup gives is ignored.        *)
Advance ==
    /\ gen < MaxGeneration
    /\ gen' = gen + 1
    /\ copy' = [z \in Copied |-> EmptyCopy]
    /\ pending' = {}
    /\ st' = [r \in Reqs |-> IF st[r] = "parked" THEN "new" ELSE st[r]]
    /\ looked' = [r \in Reqs |-> IF st[r] = "done" THEN looked[r] ELSE {}]
    /\ nNeeds' = [r \in Reqs |-> IF st[r] = "done" THEN nNeeds[r] ELSE 0]
    /\ waiting' = [r \in Reqs |-> None]
    /\ UNCHANGED <<world, ins, history, rev, real, realSeen, partial, reply, atSource, obsq,
                   reached, sent>>

Source == \E x \in atSource : SourceOne(x)
Observe == \E o \in obsq : ObserveOne(o)

\* No respond is half done: no overlay has read the lazy zone and not yet
\* stepped. `A` runs only then.
Quiet(A) == (\A r \in Reqs : st[r] # "overlay") /\ A

Next ==
    \/ \E r \in Reqs : Quiet(View(r))
    \/ \E r \in Reqs : Quiet(ReadName(r))
    \/ \E r \in Reqs : Quiet(ReadRest(r))
    \/ \E r \in Reqs : Quiet(ReadOverlay(r))
    \/ \E r \in Reqs : Step(r)
    \/ Quiet(Source)
    \/ Quiet(Observe)
    \/ Quiet(WorldChange)
    \/ Quiet(RealChange)
    \/ Quiet(Advance)

(* The engine works and the upstream answers eventually; its delay is any  *)
(* number of steps. The world, the real data, and sessions change freely.  *)
Fairness ==
    /\ \A r \in Reqs : /\ WF_vars(Quiet(View(r))) /\ WF_vars(Quiet(ReadName(r)))
                       /\ WF_vars(Quiet(ReadRest(r))) /\ WF_vars(Quiet(ReadOverlay(r)))
                       /\ WF_vars(Step(r))
    /\ WF_vars(Quiet(Source))
    /\ WF_vars(Quiet(Observe))

Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ Fairness

-----------------------------------------------------------------------------
(* Properties *)

(* Every fact a server serves from its copy was filed from a response the   *)
(* real server of that zone sent to that question: never a guess, and never *)
(* another zone's data.                                                    *)
NeverGuess ==
    \A r \in Reqs : reply[r] # None =>
        \A c \in reply[r].copied : c.x # None =>
            LET l == [srv |-> c.srv, q |-> c.x] IN
            [lookup |-> l, v |-> c.v] \in sent /\ c.val = RealReply(l, c.v)

(* No lookup the policy refuses reaches the upstream, root and TLD lookups *)
(* included.                                                               *)
PolicyHolds ==
    \A l \in reached : Allowed(l)

(* No NXDOMAIN or NODATA rests on an unknown fact: of the lazy zone, or a  *)
(* question the copy does not settle.                                      *)
UnknownNeverNegative ==
    \A r \in Reqs : (reply[r] # None /\ reply[r].rcode \in {"NXDOMAIN", "NODATA"}) =>
        /\ \A f \in reply[r].facts : f[2] \in {"present", "absent"}
        /\ \A c \in reply[r].copied : c.x # None

(* Every reply from the lazy zone agrees with one revision of it. *)
CoherentRevision ==
    \A r \in Reqs : reply[r] # None =>
        \E s \in history : \A f \in reply[r].facts : FactAt(s, f[1]) = f[2]

(* A request needs at most one lookup per generation: the question itself,  *)
(* or for a crossing question the overlay's "fict DS", whose response       *)
(* settles the question at the root. Requests that need the same lookup     *)
(* wait on one: no two pending lookups are the same.                        *)
OneAskPerNeed ==
    /\ \A r \in Reqs : nNeeds[r] <= 1
    /\ \A p1, p2 \in pending : p1.lookup = p2.lookup => p1 = p2

(* No lookup goes out again for a request once it came back to it (the    *)
(* response, or Unreachable or NoReply in its place) in that generation.   *)
(* It relates two states, so configs list it under PROPERTY.               *)
NoAskAfterReply ==
    [][\A r \in Reqs : nNeeds'[r] > nNeeds[r] => NeedOf(r) \notin looked[r]]_vars

(* A request parked on a lookup holds no part of a view: the zone's lock is *)
(* taken only inside view, which never waits on a lookup, and the overlay  *)
(* reads the lazy zone before it parks, not across the lookup.             *)
NoLockAcrossAsk ==
    \A r \in Reqs : st[r] = "parked" => partial[r] = None

(* Every request that waits on a lookup is answered or silently dropped. *)
EveryParkedAnswered ==
    \A r \in Reqs : (st[r] = "parked") ~> (st[r] = "done")

=============================================================================
