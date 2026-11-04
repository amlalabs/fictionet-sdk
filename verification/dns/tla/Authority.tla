------------------------------ MODULE Authority ------------------------------
(***************************************************************************)
(* The authority engine of `services::dns::authority` serving three        *)
(* addresses of one world: a root server, a TLD server, and the server of  *)
(* an edited zone "fict".                                                  *)
(*                                                                         *)
(* The root and TLD servers both run Overlay(Base).below("fict", Lazy).    *)
(* Base is any authority that may return Need: it answers each question    *)
(* from the response a lookup of that question filed, and a question it    *)
(* holds no response for is looked up. The server returns Need with a      *)
(* lookup of the client's question at its own address, the driver puts it  *)
(* to the upstream, the engine files the response through Authority::file  *)
(* and asks the authority again. How an authority files a response is its  *)
(* own: here each filed response settles the question it answered. For a   *)
(* question at or below "fict" the overlay reads the edited zone's apex NS *)
(* RRset and the addresses of its target "ns.fict" from the lazy zone,     *)
(* then asks its base for "fict DS". The TLD server's base serves fict's   *)
(* parent, so the TLD server refers: a referral composed from what it      *)
(* read, or SERVFAIL when the target's address is not there. The root      *)
(* server's base does not, so the root server answers as its base does.    *)
(* The fict server answers from a Lazy zone whose Provider says, per name, *)
(* Present, Absent, or Unknown, and whose answers change as the world      *)
(* runs.                                                                   *)
(*                                                                         *)
(* Every lookup passes the world's Only policy before the upstream sees    *)
(* it; a refused lookup gives NoReply. The upstream answers after any      *)
(* delay, and may fail (Unreachable or NoReply). Requests that need the    *)
(* same lookup wait on one. A request that needs a lookup it already made  *)
(* gets no reply. A new session drops what every base filed and abandons   *)
(* the pending lookups.                                                    *)
(*                                                                         *)
(* A revision is a snapshot of the lazy zone: the world's state (what the  *)
(* provider says) and the names the zone has inserted. Revisions grow when *)
(* the world changes and when a view inserts a name, including while other *)
(* requests wait on a lookup.                                              *)
(*                                                                         *)
(* Ablation flags: NoPolicy (no Only), RootExempt (lookups at root and TLD *)
(* servers skip the policy), UnknownAsAbsent (a view reads Unknown as      *)
(* Absent, and a base reads a question it holds no response for as         *)
(* NXDOMAIN), MixedRevision (the lazy view reads the name and the wildcard *)
(* under two lock acquisitions), Reask (the engine puts a lookup again     *)
(* when a request needs one it already made), ParkInView (the overlay      *)
(* parks while it still holds its read of the lazy zone), NoShare (each    *)
(* need puts its own lookup, even when the same one is pending), WakeOne   *)
(* (a finished lookup wakes only the request that started it).             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Reqs,            \* the requests guests send: [id, srv, q]
    MaxRevision,     \* the world changes only while fewer revisions than this exist
    MaxGeneration,   \* generations run 1..MaxGeneration
    Failures,        \* the upstream may fail
    NoPolicy,        \* ablation: no Only policy
    RootExempt,      \* ablation: lookups at the root and TLD servers skip the policy
    UnknownAsAbsent, \* ablation: Unknown is read as Absent
    MixedRevision,   \* ablation: the lazy view reads under two lock acquisitions
    Reask,           \* ablation: a lookup a request already made is put again
    ParkInView,      \* ablation: the overlay parks while holding its read of the lazy zone
    NoShare,         \* ablation: requests never wait on a lookup already pending
    WakeOne,         \* ablation: a finished lookup wakes only the request that started it
    None

Apex == "fict"
\* The target of the apex NS RRset, whose addresses a referral carries.
NsTarget == "ns.fict"
Wildcard == "*.fict"
\* Names at or below the edited apex. Everything else is unedited.
Edited == {"fict", "ns.fict", "a.fict", "b.fict", "c.fict", "*.fict"}

\* The servers whose base looks up what it does not hold.
Looking == {"root", "tld"}
\* The questions a base may hold a response to.
Questions == {"www.real", "nx.real", "leak.evil", "fict DS", "a.fict"}

\* The world's predicate for lookups: the guest-chosen name "leak.evil" must
\* never reach the upstream, whichever server it is addressed to.
Allowed(l) == l.q # "leak.evil"

PolicyPasses(l) ==
    \/ NoPolicy
    \/ RootExempt /\ l.srv \in Looking
    \/ Allowed(l)

\* What the provider says about n while the world is at w.
Provider(w, n) ==
    CASE n = Apex     -> "present"
      [] n = NsTarget -> IF w = 0 THEN "present" ELSE "unknown"
      [] n = "a.fict" -> IF w = 0 THEN "absent" ELSE "present"
      [] n = "b.fict" -> "unknown"
      [] n = "c.fict" -> "absent"
      [] n = Wildcard -> IF w = 0 THEN "absent" ELSE "present"

\* The RCODE of the upstream's response to question q: "nx.real" does not
\* exist.
UpstreamRcode(q) == IF q = "nx.real" THEN "NXDOMAIN" ELSE "NOERROR"

\* A question at or below the edited apex at a server the overlay runs on.
Crosses(r) == r.q \in Edited /\ r.srv \in Looking

\* Whether the base at srv serves fict's parent: its reply to "fict DS" has
\* AA and the parent's SOA. The TLD server's does; the root server's refers
\* to the TLD.
Serves(srv) == srv = "tld"

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
    gen,       \* the engine's generation
    st,        \* [Reqs -> "new" | "reading" | "overlay" | "parked" | "done"]
    looked,    \* [Reqs -> lookups made for the request in this generation]
    partial,   \* [Reqs -> None or facts read so far under the lazy zone's lock]
    reply,     \* [Reqs -> None or the reply sent]
    nNeeds,    \* [Reqs -> needs the request parked on in this generation]
    waiting,   \* [Reqs -> None or the token of the lookup it waits on]
    pending,   \* the engine's pending lookups: [token, lookup, by]
    filed,     \* [Looking -> [Questions -> None or the RCODE of the filed response]]
    atUpstream, \* lookups the upstream is working on: [token, lookup]
    obsq,      \* what lookups gave, on its way back: [token, lookup, obs]
    reached    \* every lookup the upstream has received

vars == <<world, ins, history, rev, gen, st, looked, partial, reply, nNeeds, waiting, pending,
          filed, atUpstream, obsq, reached>>

FactAt(s, n) == IF n \in s.ins THEN "present" ELSE Provider(s.w, n)
Fact(n) == FactAt([w |-> world, ins |-> ins], n)

\* How the lazy view reads a fact.
Read(f) == IF UnknownAsAbsent /\ f = "unknown" THEN "absent" ELSE f

NothingFiled == [x \in Questions |-> None]

Init ==
    /\ world = 0
    /\ ins = {}
    /\ history = {[w |-> 0, ins |-> {}]}
    /\ rev = 0
    /\ gen = 1
    /\ st = [r \in Reqs |-> "new"]
    /\ looked = [r \in Reqs |-> {}]
    /\ partial = [r \in Reqs |-> None]
    /\ reply = [r \in Reqs |-> None]
    /\ nNeeds = [r \in Reqs |-> 0]
    /\ waiting = [r \in Reqs |-> None]
    /\ pending = {}
    /\ filed = [z \in Looking |-> NothingFiled]
    /\ atUpstream = {}
    /\ obsq = {}
    /\ reached = {}

\* A reply. facts are the facts of the lazy zone it rests on, as the zone
\* held them; held are the questions a base answered it from, None for a
\* question the base held no response for.
Reply(rcode, val, facts, held) == [rcode |-> rcode, val |-> val, facts |-> facts, held |-> held]

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
    /\ UNCHANGED <<world, gen, looked, partial, nNeeds, waiting, pending, filed, atUpstream, obsq,
                   reached>>

(* With MixedRevision the view reads the name under one lock acquisition... *)
ReadName(r) ==
    /\ st[r] = "new"
    /\ FromView(r)
    /\ MixedRevision
    /\ partial' = [partial EXCEPT ![r] = Fact(r.q)]
    /\ Grow(IF Fact(r.q) = "present" THEN {r.q} ELSE {})
    /\ st' = [st EXCEPT ![r] = "reading"]
    /\ UNCHANGED <<world, gen, looked, reply, nNeeds, waiting, pending, filed, atUpstream, obsq,
                   reached>>

(* ...and the wildcard under another. *)
ReadRest(r) ==
    /\ st[r] = "reading"
    /\ LET fq == partial[r]
           fw == Fact(Wildcard)
       IN  /\ reply' = [reply EXCEPT ![r] = ViewReply(r.q, fq, fw)]
           /\ Grow(Inserted(r.q, fq, fw) \ {r.q})
    /\ partial' = [partial EXCEPT ![r] = None]
    /\ st' = [st EXCEPT ![r] = "done"]
    /\ UNCHANGED <<world, gen, looked, nNeeds, waiting, pending, filed, atUpstream, obsq, reached>>

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
    /\ UNCHANGED <<world, gen, looked, reply, nNeeds, waiting, pending, filed, atUpstream, obsq,
                   reached>>

(* Authority::respond at a root or TLD server, as a function of what its   *)
(* base holds and, for a crossing question, of what the overlay read: a    *)
(* reply, or the lookup the question needs. The overlay asks its base for  *)
(* "fict DS" first; at a server of fict's parent the referral rests on     *)
(* what it read and is SERVFAIL without the target's address, and at any   *)
(* other server the base answers the question itself.                      *)
Respond(r) ==
    LET z == r.srv
        read == IF Crosses(r) THEN partial[r] ELSE {}
        unglued == \E f \in read : f[1] = NsTarget /\ Read(f[2]) # "present"
        fromBase ==
            IF filed[z][r.q] # None
            THEN [kind |-> "reply", reply |-> Reply(filed[z][r.q], <<z, r.q>>, {}, {r.q})]
            ELSE IF UnknownAsAbsent
            THEN [kind |-> "reply", reply |-> Reply("NXDOMAIN", None, {}, {None})]
            ELSE [kind |-> "need", lookup |-> OwnLookup(r)]
    IN  IF ~Crosses(r) THEN fromBase
        ELSE IF filed[z]["fict DS"] = None THEN [kind |-> "need", lookup |-> DsLookup(r)]
        ELSE IF ~Serves(z) THEN fromBase
        ELSE IF unglued THEN [kind |-> "reply", reply |-> Reply("SERVFAIL", None, read, {"fict DS"})]
        ELSE [kind |-> "reply", reply |-> Reply("NOERROR", <<"referral", Apex>>, read, {"fict DS"})]

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
                   /\ UNCHANGED <<nNeeds, waiting, pending, atUpstream, obsq, reached>>
              ELSE IF s.lookup \in looked[r] /\ ~Reask
              THEN /\ reply' = [reply EXCEPT ![r] = Reply("SILENT", None, {}, {})]
                   /\ st' = [st EXCEPT ![r] = "done"]
                   /\ partial' = released
                   /\ UNCHANGED <<nNeeds, waiting, pending, atUpstream, obsq, reached>>
              ELSE LET a == s.lookup
                       tok == <<gen, r.id, nNeeds[r]>>
                       shared == {p \in pending : p.lookup = a}
                   IN  /\ st' = [st EXCEPT ![r] = "parked"]
                       /\ nNeeds' = [nNeeds EXCEPT ![r] = @ + 1]
                       /\ partial' = IF ParkInView THEN partial ELSE released
                       /\ IF shared # {} /\ ~NoShare
                          THEN /\ waiting' = [waiting EXCEPT ![r] = (CHOOSE p \in shared : TRUE).token]
                               /\ UNCHANGED <<pending, atUpstream, obsq, reached>>
                          ELSE /\ waiting' = [waiting EXCEPT ![r] = tok]
                               /\ pending' = pending \cup {[token |-> tok, lookup |-> a, by |-> r]}
                               /\ IF PolicyPasses(a)
                                  THEN /\ atUpstream' = atUpstream \cup {[token |-> tok, lookup |-> a]}
                                       /\ reached' = reached \cup {a}
                                       /\ UNCHANGED obsq
                                  ELSE /\ obsq' = obsq \cup {[token |-> tok, lookup |-> a, obs |-> "noreply"]}
                                       /\ UNCHANGED <<atUpstream, reached>>
                       /\ UNCHANGED reply
    /\ UNCHANGED <<world, gen, looked, filed>>

(* The upstream finishes a lookup: a response, or a failure. *)
UpstreamOne(x) ==
    /\ atUpstream' = atUpstream \ {x}
    /\ \E o \in (IF Failures THEN Observations ELSE {"reply"}) :
         obsq' = obsq \cup {[token |-> x.token, lookup |-> x.lookup, obs |-> o]}
    /\ UNCHANGED <<world, ins, history, rev, gen, st, looked, partial, reply, nNeeds, waiting,
                   pending, filed, reached>>

(* What a lookup gave comes back. Only a pending token counts: the engine  *)
(* files a response through Authority::file into the base at the address   *)
(* the lookup names, then asks the authority again for every request that  *)
(* waited on the lookup.                                                   *)
ObserveOne(o) ==
    /\ obsq' = obsq \ {o}
    /\ IF \E p \in pending : p.token = o.token
       THEN LET p == CHOOSE p \in pending : p.token = o.token
                woken == {r \in Reqs : st[r] = "parked" /\ waiting[r] = o.token /\ (~WakeOne \/ r = p.by)}
            IN  /\ pending' = pending \ {p}
                /\ filed' = IF o.obs = "reply"
                            THEN [filed EXCEPT ![o.lookup.srv][o.lookup.q] = UpstreamRcode(o.lookup.q)]
                            ELSE filed
                /\ st' = [r \in Reqs |-> IF r \in woken THEN "new" ELSE st[r]]
                /\ looked' = [r \in Reqs |-> IF r \in woken THEN looked[r] \cup {o.lookup} ELSE looked[r]]
                /\ waiting' = [r \in Reqs |-> IF r \in woken THEN None ELSE waiting[r]]
       ELSE UNCHANGED <<pending, filed, st, looked, waiting>>
    /\ UNCHANGED <<world, ins, history, rev, gen, partial, reply, nNeeds, atUpstream, reached>>

(* The world runs: the provider's answers change, a new revision. *)
WorldChange ==
    /\ world = 0
    /\ rev < MaxRevision
    /\ world' = 1
    /\ history' = history \cup {[w |-> 1, ins |-> ins]}
    /\ rev' = rev + 1
    /\ UNCHANGED <<ins, gen, st, looked, partial, reply, nNeeds, waiting, pending, filed,
                   atUpstream, obsq, reached>>

(* A new session: every base drops what it filed, the pending lookups are  *)
(* abandoned, and parked requests restart under the new generation with    *)
(* no lookups made; what an abandoned lookup gives is ignored.             *)
Advance ==
    /\ gen < MaxGeneration
    /\ gen' = gen + 1
    /\ filed' = [z \in Looking |-> NothingFiled]
    /\ pending' = {}
    /\ st' = [r \in Reqs |-> IF st[r] = "parked" THEN "new" ELSE st[r]]
    /\ looked' = [r \in Reqs |-> IF st[r] = "done" THEN looked[r] ELSE {}]
    /\ nNeeds' = [r \in Reqs |-> IF st[r] = "done" THEN nNeeds[r] ELSE 0]
    /\ waiting' = [r \in Reqs |-> None]
    /\ UNCHANGED <<world, ins, history, rev, partial, reply, atUpstream, obsq, reached>>

Upstream == \E x \in atUpstream : UpstreamOne(x)
Observe == \E o \in obsq : ObserveOne(o)

\* No respond is half done: no overlay has read the lazy zone and not yet
\* stepped. `A` runs only then.
Quiet(A) == (\A r \in Reqs : st[r] # "overlay") /\ A

\* No respond but r's is half done: r's own step may end its respond call.
Alone(r, A) == (\A o \in Reqs \ {r} : st[o] # "overlay") /\ A

Next ==
    \/ \E r \in Reqs : Quiet(View(r))
    \/ \E r \in Reqs : Quiet(ReadName(r))
    \/ \E r \in Reqs : Quiet(ReadRest(r))
    \/ \E r \in Reqs : Quiet(ReadOverlay(r))
    \/ \E r \in Reqs : Alone(r, Step(r))
    \/ Quiet(Upstream)
    \/ Quiet(Observe)
    \/ Quiet(WorldChange)
    \/ Quiet(Advance)

(* The engine works and the upstream answers eventually; its delay is any  *)
(* number of steps. The world and sessions change freely.                  *)
Fairness ==
    /\ \A r \in Reqs : /\ WF_vars(Quiet(View(r))) /\ WF_vars(Quiet(ReadName(r)))
                       /\ WF_vars(Quiet(ReadRest(r))) /\ WF_vars(Quiet(ReadOverlay(r)))
                       /\ WF_vars(Alone(r, Step(r)))
    /\ WF_vars(Quiet(Upstream))
    /\ WF_vars(Quiet(Observe))

Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ Fairness

-----------------------------------------------------------------------------
(* Properties *)

(* No lookup the policy refuses reaches the upstream, root and TLD lookups *)
(* included.                                                               *)
PolicyHolds ==
    \A l \in reached : Allowed(l)

(* No NXDOMAIN or NODATA rests on an unknown fact: of the lazy zone, or a  *)
(* question a base holds no response for.                                  *)
UnknownNeverNegative ==
    \A r \in Reqs : (reply[r] # None /\ reply[r].rcode \in {"NXDOMAIN", "NODATA"}) =>
        /\ \A f \in reply[r].facts : f[2] \in {"present", "absent"}
        /\ None \notin reply[r].held

(* Every reply from the lazy zone agrees with one revision of it. *)
CoherentRevision ==
    \A r \in Reqs : reply[r] # None =>
        \E s \in history : \A f \in reply[r].facts : FactAt(s, f[1]) = f[2]

(* A request needs at most one lookup per fact per generation: the         *)
(* question itself, and for a crossing question the overlay's "fict DS"    *)
(* first. Requests that need the same lookup wait on one: no two pending   *)
(* lookups are the same.                                                   *)
OneAskPerNeed ==
    /\ \A r \in Reqs : nNeeds[r] <= IF Crosses(r) THEN 2 ELSE 1
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
