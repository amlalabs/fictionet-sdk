------------------------------ MODULE Authority ------------------------------
(***************************************************************************)
(* The authority engine of `services::dns::authority` serving three        *)
(* addresses of one world: a root server, a TLD server, and the server of  *)
(* an edited zone "fict".                                                  *)
(*                                                                         *)
(* The root server runs Relay: every question is relayed to the real      *)
(* server at that address through a source. The TLD server runs           *)
(* Overlay(Relay).below("fict", Lazy): a question for an unedited name is  *)
(* relayed the same way; a question at or below "fict" gets a referral     *)
(* composed from the edited zone's apex NS RRset and the addresses of its  *)
(* target "ns.fict", read from the lazy zone, after the overlay asks the   *)
(* real TLD server for "fict DS" (DO=1). A fact of that read the zone does *)
(* not know makes the referral SERVFAIL. The fict server answers from a   *)
(* Lazy zone whose Provider says, per name, Present, Absent, or Unknown,   *)
(* and whose answers change as the world runs.                             *)
(*                                                                         *)
(* Every ask passes the world's Only policy before the source sees it; a   *)
(* refused ask is a Timeout. The source answers after any delay, may fail  *)
(* (Unreachable or Timeout), and returns the real server's reply as it is  *)
(* when the source asks. The real data may change once.                    *)
(*                                                                         *)
(* A revision is a snapshot of the lazy zone: the world's state (what the  *)
(* provider says) and the names the zone has inserted. Revisions grow when *)
(* the world changes and when a view inserts a name, including while other *)
(* requests wait on the source.                                            *)
(*                                                                         *)
(* Ablation flags: NoPolicy (no Only), RootExempt (asks to root and TLD    *)
(* servers skip the policy), UnknownAsAbsent (the view reads Unknown as    *)
(* Absent), MixedRevision (the view reads the name and the wildcard under  *)
(* two lock acquisitions, so a revision can grow in between), ReaskTimeout *)
(* (respond asks again after a timeout), ParkInView (the overlay sends its *)
(* DS ask while it still holds its read of the lazy zone).                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Reqs,            \* the requests guests send: [id, srv, q]
    MaxRevision,     \* the world changes only while fewer revisions than this exist
    MaxGeneration,   \* generations run 1..MaxGeneration
    MaxRealChanges,  \* changes to the real servers' data
    Failures,        \* the source may fail
    NoPolicy,        \* ablation: no Only policy
    RootExempt,      \* ablation: asks to the root and TLD servers skip the policy
    UnknownAsAbsent, \* ablation: Unknown is read as Absent
    MixedRevision,   \* ablation: the view reads under two lock acquisitions
    ReaskTimeout,    \* ablation: respond asks again after a timeout
    ParkInView,      \* ablation: the overlay asks while holding its read of the lazy zone
    None

Apex == "fict"
\* The target of the apex NS RRset, whose addresses a referral carries.
NsTarget == "ns.fict"
Wildcard == "*.fict"
\* Names at or below the edited apex. Everything else is unedited.
Edited == {"fict", "ns.fict", "a.fict", "b.fict", "c.fict", "*.fict"}

\* The world's predicate for asks: the guest-chosen name "leak.evil" must never
\* reach a real server, whichever server it is addressed to.
Allowed(ask) == ask.q # "leak.evil"

PolicyPasses(ask) ==
    \/ NoPolicy
    \/ RootExempt /\ ask.srv \in {"root", "tld"}
    \/ Allowed(ask)

\* What the provider says about n while the world is at w.
Provider(w, n) ==
    CASE n = Apex     -> "present"
      [] n = NsTarget -> IF w = 0 THEN "present" ELSE "unknown"
      [] n = "a.fict" -> IF w = 0 THEN "absent" ELSE "present"
      [] n = "b.fict" -> "unknown"
      [] n = "c.fict" -> "absent"
      [] n = Wildcard -> IF w = 0 THEN "absent" ELSE "present"

\* The real server's reply to an ask while the real data is at v.
RealReply(ask, v) == <<ask.srv, ask.q, v>>

\* A question the overlay at the TLD server answers with a referral.
Crosses(r) == r.q \in Edited /\ r.srv = "tld"

\* The ask a request needs: the overlay's DS ask for a question that crosses
\* the apex at the TLD server, the relayed question otherwise.
AskOf(r) ==
    IF Crosses(r) THEN [srv |-> "tld", q |-> "fict DS"]
    ELSE [srv |-> r.srv, q |-> r.q]

\* The fict server answers from the lazy zone with no ask.
FromView(r) == r.srv = "fict"

Observations == {"reply", "unreachable", "timeout"}

\* The request sets the configs pick with "Reqs <- ...".
Real == [id |-> "real", srv |-> "root", q |-> "www.real"]
Leak == [id |-> "leak", srv |-> "root", q |-> "leak.evil"]
LazyA == [id |-> "a", srv |-> "fict", q |-> "a.fict"]
LazyB == [id |-> "b", srv |-> "fict", q |-> "b.fict"]
LazyC == [id |-> "c", srv |-> "fict", q |-> "c.fict"]
Cross == [id |-> "cross", srv |-> "tld", q |-> "a.fict"]
ReqsBase == {Real, Leak, LazyB, Cross}
ReqsLazy == {LazyA, LazyB, LazyC, Cross}
ReqsAdvance == {Real, Cross}

\* Authority::respond for a request that is not answered from the view, as a
\* function of what is known: None, or the observation for its ask.
Respond(r, k) ==
    IF k = None THEN "need"
    ELSE IF k.obs = "reply" THEN "reply"
    ELSE IF ReaskTimeout /\ k.obs = "timeout" THEN "need"
    ELSE "silent"

VARIABLES
    world,     \* the world's state: what the provider says
    ins,       \* names the lazy zone has inserted
    history,   \* every revision so far: [w, ins]
    rev,       \* revisions so far, less one
    real,      \* the real servers' data version
    realSeen,  \* real versions that have existed
    gen,       \* the engine's generation
    st,        \* [Reqs -> "new" | "reading" | "parked" | "done"]
    known,     \* [Reqs -> None or [obs, v]]: the request's Known
    partial,   \* [Reqs -> None or facts read so far]: only with MixedRevision
    reply,     \* [Reqs -> None or the reply sent]
    nAsks,     \* [Reqs -> asks sent for the request in this generation]
    atSource,  \* asks the source is working on: [token, ask]
    obsq,      \* observations on their way back: [token, ask, obs, v]
    reached    \* every ask the source has received

vars == <<world, ins, history, rev, real, realSeen, gen, st, known, partial, reply, nAsks,
          atSource, obsq, reached>>

FactAt(s, n) == IF n \in s.ins THEN "present" ELSE Provider(s.w, n)
Fact(n) == FactAt([w |-> world, ins |-> ins], n)

\* How the view reads a fact.
Read(f) == IF UnknownAsAbsent /\ f = "unknown" THEN "absent" ELSE f

Init ==
    /\ world = 0
    /\ ins = {}
    /\ history = {[w |-> 0, ins |-> {}]}
    /\ rev = 0
    /\ real = 0
    /\ realSeen = {0}
    /\ gen = 1
    /\ st = [r \in Reqs |-> "new"]
    /\ known = [r \in Reqs |-> None]
    /\ partial = [r \in Reqs |-> None]
    /\ reply = [r \in Reqs |-> None]
    /\ nAsks = [r \in Reqs |-> 0]
    /\ atSource = {}
    /\ obsq = {}
    /\ reached = {}

\* A reply. facts are the facts of the lazy zone it rests on, as the zone
\* held them; v is the real data version a relayed reply came from.
Reply(rcode, val, facts, v) == [rcode |-> rcode, val |-> val, facts |-> facts, v |-> v]

\* The reply the view gives for q from the facts read for q and the wildcard
\* (RFC 1034 section 4.3.2, RFC 4592). Unknown is SERVFAIL, never a negative.
ViewReply(q, fq, fw) ==
    CASE Read(fq) = "present" -> Reply("NOERROR", <<q, "A">>, {<<q, fq>>}, None)
      [] Read(fq) = "unknown" -> Reply("SERVFAIL", None, {<<q, fq>>}, None)
      [] Read(fw) = "present" -> Reply("NOERROR", <<q, "A", "wild">>, {<<q, fq>>, <<Wildcard, fw>>}, None)
      [] Read(fw) = "unknown" -> Reply("SERVFAIL", None, {<<q, fq>>, <<Wildcard, fw>>}, None)
      [] OTHER                -> Reply("NXDOMAIN", None, {<<q, fq>>, <<Wildcard, fw>>}, None)

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
    /\ UNCHANGED <<world, real, realSeen, gen, known, partial, nAsks, atSource, obsq, reached>>

(* With MixedRevision the view reads the name under one lock acquisition... *)
ReadName(r) ==
    /\ st[r] = "new"
    /\ FromView(r)
    /\ MixedRevision
    /\ partial' = [partial EXCEPT ![r] = Fact(r.q)]
    /\ Grow(IF Fact(r.q) = "present" THEN {r.q} ELSE {})
    /\ st' = [st EXCEPT ![r] = "reading"]
    /\ UNCHANGED <<world, real, realSeen, gen, known, reply, nAsks, atSource, obsq, reached>>

(* ...and the wildcard under another. *)
ReadRest(r) ==
    /\ st[r] = "reading"
    /\ LET fq == partial[r]
           fw == Fact(Wildcard)
       IN  /\ reply' = [reply EXCEPT ![r] = ViewReply(r.q, fq, fw)]
           /\ Grow(Inserted(r.q, fq, fw) \ {r.q})
    /\ partial' = [partial EXCEPT ![r] = None]
    /\ st' = [st EXCEPT ![r] = "done"]
    /\ UNCHANGED <<world, real, realSeen, gen, known, nAsks, atSource, obsq, reached>>

(* The engine calls respond. A Need parks the request under a token and   *)
(* sends its ask through the policy: a refused ask comes back as Timeout   *)
(* without reaching the source.                                           *)
Step(r) ==
    /\ st[r] = "new"
    /\ ~FromView(r)
    /\ LET a == AskOf(r)
           tok == <<gen, r.id>>
           \* An overlay first reads the edited zone's apex NS RRset and the
           \* addresses of its target, under one view of the lazy zone.
           fa == Fact(Apex)
           fn == Fact(NsTarget)
           read == IF Crosses(r) THEN {<<Apex, fa>>, <<NsTarget, fn>>} ELSE {}
           unknown == Crosses(r) /\ "unknown" \in {Read(fa), Read(fn)}
       IN  /\ IF Crosses(r) THEN Grow(IF fn = "present" THEN {NsTarget} ELSE {})
              ELSE UNCHANGED <<ins, history, rev>>
           /\ CASE unknown ->
                  /\ reply' = [reply EXCEPT ![r] = Reply("SERVFAIL", None, read, None)]
                  /\ st' = [st EXCEPT ![r] = "done"]
                  /\ UNCHANGED <<nAsks, atSource, obsq, reached, partial>>
                [] Respond(r, known[r]) = "need" ->
                  /\ st' = [st EXCEPT ![r] = "parked"]
                  /\ nAsks' = [nAsks EXCEPT ![r] = @ + 1]
                  /\ partial' = IF ParkInView /\ Crosses(r) THEN [partial EXCEPT ![r] = read] ELSE partial
                  /\ IF PolicyPasses(a)
                     THEN /\ atSource' = atSource \cup {[token |-> tok, ask |-> a]}
                          /\ reached' = reached \cup {a}
                          /\ UNCHANGED obsq
                     ELSE /\ obsq' = obsq \cup {[token |-> tok, ask |-> a, obs |-> "timeout", v |-> None]}
                          /\ UNCHANGED <<atSource, reached>>
                  /\ UNCHANGED reply
                [] Respond(r, known[r]) = "reply" ->
                  /\ reply' = [reply EXCEPT ![r] = Reply("NOERROR", known[r].val, read, known[r].v)]
                  /\ st' = [st EXCEPT ![r] = "done"]
                  /\ UNCHANGED <<nAsks, atSource, obsq, reached, partial>>
                [] Respond(r, known[r]) = "silent" ->
                  /\ reply' = [reply EXCEPT ![r] = Reply("SILENT", None, {}, None)]
                  /\ st' = [st EXCEPT ![r] = "done"]
                  /\ UNCHANGED <<nAsks, atSource, obsq, reached, partial>>
    /\ UNCHANGED <<world, real, realSeen, gen, known>>

(* The source finishes an ask: the real server's reply as it is now, or a  *)
(* failure.                                                               *)
SourceOne(x) ==
    /\ atSource' = atSource \ {x}
    /\ \E o \in (IF Failures THEN Observations ELSE {"reply"}) :
         obsq' = obsq \cup {[token |-> x.token, ask |-> x.ask, obs |-> o,
                             v |-> IF o = "reply" THEN real ELSE None]}
    /\ UNCHANGED <<world, ins, history, rev, real, realSeen, gen, st, known, partial, reply, nAsks, reached>>

\* The parked request a token belongs to, if it is still live.
Owner(tok) == {r \in Reqs : st[r] = "parked" /\ tok = <<gen, r.id>>}

(* An observation comes back. Only a live token adds it to its request's   *)
(* Known; the engine then calls respond again.                            *)
ObserveOne(o) ==
    /\ obsq' = obsq \ {o}
    /\ IF Owner(o.token) # {}
       THEN LET r == CHOOSE x \in Owner(o.token) : TRUE IN
            /\ known' = [known EXCEPT ![r] = [obs |-> o.obs, v |-> o.v,
                                              val |-> IF o.obs = "reply" THEN RealReply(o.ask, o.v) ELSE None]]
            /\ st' = [st EXCEPT ![r] = "new"]
       ELSE UNCHANGED <<known, st>>
    /\ UNCHANGED <<world, ins, history, rev, real, realSeen, gen, partial, reply, nAsks, atSource, reached>>

(* The world runs: the provider's answers change, a new revision. *)
WorldChange ==
    /\ world = 0
    /\ rev < MaxRevision
    /\ world' = 1
    /\ history' = history \cup {[w |-> 1, ins |-> ins]}
    /\ rev' = rev + 1
    /\ UNCHANGED <<ins, real, realSeen, gen, st, known, partial, reply, nAsks, atSource, obsq, reached>>

RealChange ==
    /\ real < MaxRealChanges
    /\ real' = real + 1
    /\ realSeen' = realSeen \cup {real + 1}
    /\ UNCHANGED <<world, ins, history, rev, gen, st, known, partial, reply, nAsks, atSource, obsq, reached>>

(* A new session: parked requests restart under the new generation with   *)
(* nothing known; observations for old tokens are ignored when they come. *)
Advance ==
    /\ gen < MaxGeneration
    /\ gen' = gen + 1
    /\ st' = [r \in Reqs |-> IF st[r] = "parked" THEN "new" ELSE st[r]]
    /\ known' = [r \in Reqs |-> IF st[r] = "done" THEN known[r] ELSE None]
    /\ nAsks' = [r \in Reqs |-> IF st[r] = "done" THEN nAsks[r] ELSE 0]
    /\ UNCHANGED <<world, ins, history, rev, real, realSeen, partial, reply, atSource, obsq, reached>>

Source == \E x \in atSource : SourceOne(x)
Observe == \E o \in obsq : ObserveOne(o)

Next ==
    \/ \E r \in Reqs : View(r)
    \/ \E r \in Reqs : ReadName(r)
    \/ \E r \in Reqs : ReadRest(r)
    \/ \E r \in Reqs : Step(r)
    \/ Source
    \/ Observe
    \/ WorldChange
    \/ RealChange
    \/ Advance

(* The engine works and the source answers eventually; its delay is any   *)
(* number of steps. The world, the real data, and sessions change freely.  *)
Fairness ==
    /\ \A r \in Reqs : WF_vars(View(r)) /\ WF_vars(ReadName(r)) /\ WF_vars(ReadRest(r)) /\ WF_vars(Step(r))
    /\ WF_vars(Source)
    /\ WF_vars(Observe)

Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ Fairness

-----------------------------------------------------------------------------
(* Properties *)

Unedited(r) == r.q \notin Edited

(* A relayed reply for an unedited name is the real server's reply to that *)
(* question as it was when the source asked: never a guess.               *)
NeverGuess ==
    \A r \in Reqs : (Unedited(r) /\ reply[r] # None /\ reply[r].rcode # "SILENT") =>
        reply[r].v \in realSeen /\ reply[r].val = RealReply(AskOf(r), reply[r].v)

(* No ask the policy refuses reaches the source, root and TLD asks included. *)
PolicyHolds ==
    \A a \in reached : Allowed(a)

(* No NXDOMAIN or NODATA rests on an Unknown fact. *)
UnknownNeverNegative ==
    \A r \in Reqs : (reply[r] # None /\ reply[r].rcode \in {"NXDOMAIN", "NODATA"}) =>
        \A f \in reply[r].facts : f[2] \in {"present", "absent"}

(* Every reply from the lazy zone agrees with one revision of it. *)
CoherentRevision ==
    \A r \in Reqs : reply[r] # None =>
        \E s \in history : \A f \in reply[r].facts : FactAt(s, f[1]) = f[2]

(* More observations never turn a reply into a Need (Lean: respond_monotone). *)
(* Each request here needs one ask, so once it knows what that ask observed, *)
(* whatever that was, it never needs another.                              *)
RespondMonotone ==
    \A r \in Reqs : known[r] # None => Respond(r, known[r]) # "need"

(* A request sends at most one ask per Need, and one Need per generation. *)
OneAskPerNeed ==
    \A r \in Reqs : nAsks[r] <= 1

(* A request parked on an ask holds no part of a view: the zone's lock is   *)
(* taken only inside view, which never waits on an ask, and the overlay    *)
(* reads the lazy zone before it asks, not across the ask.                 *)
NoLockAcrossAsk ==
    \A r \in Reqs : st[r] = "parked" => partial[r] = None

(* Every request that waits on an ask is answered or silently dropped. *)
EveryParkedAnswered ==
    \A r \in Reqs : (st[r] = "parked") ~> (st[r] = "done")

=============================================================================
