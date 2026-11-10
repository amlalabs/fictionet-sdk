----------------------------- MODULE Validation -----------------------------
(***************************************************************************)
(* The DNSSEC validator of `protocols::dns::dnssec` and the resolver's     *)
(* rendering of its result, over a path root, tld, sld, where the answer   *)
(* is an RRset in sld.                                                     *)
(*                                                                         *)
(* The validator is a function of records, anchors, a policy, a time, and  *)
(* a verifier. So the model has no steps: every behavior is one initial    *)
(* state that fixes the published records, the faults, the query flags,   *)
(* and who produced the records, and the properties are checked over every *)
(* such state. Each config frees some dimensions of the data and fixes the *)
(* rest:                                                                   *)
(*                                                                         *)
(*   anchor     the configured trust anchor: none configured, one for some *)
(*              other tree ("elsewhere"), or one naming key A or key B     *)
(*   signer[z]  the key zone z is signed with: A, B, or none (unsigned)    *)
(*   proof[z]   what z's parent says about z: a DS naming key A or B, a    *)
(*              signed no-DS proof, an NSEC3 opt-out cover with a closest- *)
(*              encloser proof, an NSEC denying the name, an NSEC that     *)
(*              matches the name but lacks the NS bit, or nothing          *)
(*   window[z]  when z's signatures are valid: past, now, or future        *)
(*   alg[z]     the algorithm the DS (or the anchor) names for z:          *)
(*              supported, SHA-1 based (5 or 7), or unknown                *)
(*   changed[z] whether an RRset of z changed after it was signed          *)
(*   edited[z]  whether the world edited an RRset of z                     *)
(*   clock      the validator's clock: now, or skewed to past or future    *)
(*   reach[z]   whether z's DNSKEY and DS sets can be fetched              *)
(*   cached     whether the answer comes from the resolver's cache, with   *)
(*              the validation an earlier query without CD made            *)
(*                                                                         *)
(* The world's own zones, complete or lazy, publish the same records       *)
(* (Lean: lazy_agrees_complete), so where the records come from is not     *)
(* modelled here. The signer implementation (A or B) produces the same     *)
(* records by contract (signer_agnostic), and the validator must not see   *)
(* it. RecordsOnly is checked by self-composition: two copies of the       *)
(* validator, each with its own signer, get records of their own, which    *)
(* differ where the second copy's changed2 makes them differ, and must     *)
(* agree whenever their records are equal.                                 *)
(*                                                                         *)
(* Ablation flags: PolicyAlgs is the policy value (adding "sha1" accepts   *)
(* algorithm 5), TrustUpstreamAd copies an upstream AD bit,                *)
(* MissingAsInsecure reads a failed fetch as Insecure, SignerPeek lets the *)
(* validator skip a check for records from signer A, and CheckNsBit FALSE  *)
(* takes a matching NSEC without the NS bit as a no-DS proof.              *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    AnchorChoices, SignerChoices, ProofChoices, WindowChoices, AlgChoices,
    ChangedChoices, EditedChoices, ClockChoices, ReachChoices, ImplChoices,
    PolicyAlgs,        \* the algorithms AlgorithmPolicy.validate admits
    TrustUpstreamAd,   \* ablation: AD from upstream reaches the client
    MissingAsInsecure, \* ablation: a failed fetch is Insecure
    SignerPeek,        \* ablation: the validator reads the signer implementation
    CheckNsBit         \* FALSE is the ablation: a no-DS proof needs no NS bit

Path == <<"root", "tld", "sld">>
Zones == {"root", "tld", "sld"}
Children == {"tld", "sld"}
Windows == <<"past", "now", "future">>
Pos(w) == CHOOSE i \in 1..3 : Windows[i] = w

VARIABLES
    anchor, signer, proof, window, alg, changed, edited, clock, reach,
    do, adq, cd, upstreamAd,       \* the query's DO, AD, and CD bits; the upstream reply's AD bit
    cached,                        \* the answer comes from the cache, validated by an earlier query
    impl1, impl2,
    changed2                       \* what changed after signing in the second copy's records

vars == <<anchor, signer, proof, window, alg, changed, edited, clock, reach, do, adq, cd,
          upstreamAd, cached, impl1, impl2, changed2>>

Init ==
    /\ anchor \in AnchorChoices
    /\ signer \in [Zones -> SignerChoices]
    /\ proof \in [Children -> ProofChoices]
    /\ window \in [Zones -> WindowChoices]
    /\ alg \in [Zones -> AlgChoices]
    /\ changed \in [Zones -> ChangedChoices]
    /\ edited \in [Zones -> EditedChoices]
    /\ clock \in ClockChoices
    /\ reach \in [Zones -> ReachChoices]
    /\ do \in BOOLEAN /\ adq \in BOOLEAN /\ cd \in BOOLEAN /\ upstreamAd \in BOOLEAN
    /\ cached \in BOOLEAN
    /\ impl1 \in ImplChoices /\ impl2 \in ImplChoices
    /\ changed2 \in [Zones -> ChangedChoices]

Next == UNCHANGED vars
Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Published records. Every signer publishes the same records for the      *)
(* same zone data (Lean: signer_agnostic), and so do the world's complete  *)
(* and lazy zones (lazy_agrees_complete). The faults are what the          *)
(* validator's fetches and clock see.                                      *)

(* Whether z's records, as copy `run` of the validator gets them, changed  *)
(* after they were signed. The world signs its zones over their edits, so  *)
(* only a fault changes them.                                              *)
Stale(run, z) == (IF run = 1 THEN changed ELSE changed2)[z]

\* The records copy `run` of the validator gets.
Records(run) ==
    [anchor |-> anchor, signer |-> signer, proof |-> proof, window |-> window, alg |-> alg,
     changed |-> [z \in Zones |-> Stale(run, z)], clock |-> clock, reach |-> reach]

V(kind, why) == [kind |-> kind, why |-> why]

\* The key a DS proof names, or "none" for any other proof.
DsKey(p) == CASE p = "DsA" -> "A" [] p = "DsB" -> "B" [] OTHER -> "none"

(* The validator, walking down from the anchor. At zone i it holds the key *)
(* the link above names. The resolver fetches a zone's DS and DNSKEY sets  *)
(* together (Resolver::link); the validator reads them in order. Below the *)
(* anchor's zone it reads the DS set the parent served first              *)
(* (Check::delegation), so an unreachable zone there is Indeterminate      *)
(* before its algorithm is looked at. The algorithm comes from that DS set *)
(* or the anchor, so an unsupported one makes the zone Insecure before its *)
(* DNSKEY set is read (Check::dnskeys), whatever that fetch gave           *)
(* (RFC 4035 section 5.2, RFC 9905 section 2).                             *)
Unreachable == IF MissingAsInsecure THEN V("Insecure", "Missing") ELSE V("Indeterminate", "ede5")

RECURSIVE Walk(_, _, _, _)
Walk(r, impl, i, expect) ==
    LET z == Path[i] IN
    IF i > 1 /\ ~r.reach[z] THEN Unreachable
    ELSE IF r.alg[z] \notin PolicyAlgs THEN V("Insecure", "UnsupportedAlgorithm")
    ELSE IF ~r.reach[z] THEN Unreachable
    ELSE IF r.signer[z] = "none" THEN V("Bogus", "ede9")
    ELSE IF r.signer[z] # expect THEN V("Bogus", "ede9")
    ELSE IF Pos(r.window[z]) < Pos(r.clock) THEN V("Bogus", "ede7")
    ELSE IF Pos(r.window[z]) > Pos(r.clock) THEN V("Bogus", "ede8")
    ELSE IF r.changed[z] /\ ~(SignerPeek /\ impl = "A") THEN V("Bogus", "ede6")
    ELSE IF i = Len(Path) THEN V("Secure", "none")
    ELSE LET c == Path[i + 1]
             p == r.proof[c] IN
         \* Every kind of proof below needs the child's DS set or its denial.
         IF ~r.reach[c] THEN Unreachable
         ELSE CASE p \in {"DsA", "DsB"} -> Walk(r, impl, i + 1, DsKey(p))
                [] p = "NoDs"           -> V("Insecure", "ProvenNoDs")
                [] p = "OptOutCover"    -> V("Insecure", "OptOutCovered")
                \* A covering NSEC proves no delegation, so the proof stays
                \* unproven (Nsecs::no_ds, from_proof).
                [] p = "Nsec"           -> V("Bogus", "ede12")
                \* A signed NSEC that matches the child's name but lacks the
                \* NS bit shows the name is no delegation, so it proves no
                \* unsigned delegation there (RFC 6840 section 4.4,
                \* Nsecs::no_ds and Nsec3s::no_ds). An attacker can replay
                \* one from a name that is not a cut.
                [] p = "NsecNoNs"       ->
                     IF CheckNsBit THEN V("Bogus", "ede12") ELSE V("Insecure", "ProvenNoDs")
                [] p = "Nothing"        -> V("Bogus", "ede12")   \* no DS and no denial

Validate(r, impl) ==
    IF r.anchor = "none" THEN V("NotPerformed", "none")
    ELSE IF r.anchor = "elsewhere" THEN V("Insecure", "NoAnchor")
    ELSE Walk(r, impl, 1, r.anchor)

Result == Validate(Records(1), impl1)
Result2 == Validate(Records(2), impl2)

(* What the resolver established for the answer it renders. With CD the    *)
(* client checks signatures itself, so the resolver does not validate a    *)
(* fresh answer (NotPerformed); an answer from the cache keeps what an     *)
(* earlier query without CD established.                                  *)
Established == IF cd /\ ~cached THEN V("NotPerformed", "none") ELSE Result

(* The resolver's answer to the client. *)
Rendered ==
    LET bad == Result.kind \in {"Bogus", "Indeterminate"} IN
    [rcode |-> IF ~reach["sld"] \/ (bad /\ ~cd) THEN "SERVFAIL" ELSE "NOERROR",
     data  |-> reach["sld"] /\ (~bad \/ cd),
     ad    |-> (Established.kind = "Secure" /\ (do \/ adq)) \/ (TrustUpstreamAd /\ upstreamAd)]

-----------------------------------------------------------------------------
(* The chain stated without the walk. *)

\* The key the anchor or the parent's DS names for Path[j].
Expect(j) == IF j = 1 THEN anchor ELSE DsKey(proof[Path[j]])

\* Path[j] is signed by that key, reachable, current, unchanged, and its
\* algorithm is admitted.
Good(j) ==
    LET z == Path[j] IN
    /\ reach[z] /\ signer[z] = Expect(j) /\ window[z] = clock /\ ~Stale(1, z)
    /\ alg[z] \in PolicyAlgs

\* A validated chain runs from a configured anchor through every zone above Path[i].
SecureTo(i) ==
    /\ anchor \in {"A", "B"}
    /\ \A j \in 1..(i - 1) : Good(j)
    /\ \A j \in 2..(i - 1) : proof[Path[j]] \in {"DsA", "DsB"}

ChainHolds == SecureTo(Len(Path) + 1)

(* Properties *)

SecureImpliesChain == Result.kind = "Secure" => ChainHolds

(* Insecure needs a proof: no anchor covers the name, or below a validated  *)
(* chain there is a signed no-DS proof, an opt-out cover, or a DS link      *)
(* whose algorithm the policy does not admit. Below the anchor's zone the   *)
(* proof is the parent's word on the DS set, so that set must have been     *)
(* fetched.                                                                *)
InsecureNeedsProof ==
    Result.kind = "Insecure" =>
        \/ anchor = "elsewhere"
        \/ \E i \in 1..Len(Path) :
              /\ SecureTo(i)
              /\ i = 1 \/ reach[Path[i]]
              /\ \/ alg[Path[i]] \notin PolicyAlgs
                 \/ i > 1 /\ proof[Path[i]] \in {"NoDs", "OptOutCover"}

(* A zone below a validated chain whose DS set cannot be fetched leaves the *)
(* answer Indeterminate, whatever that set or its denial would have said.  *)
UnreachableLinkIndeterminate ==
    ~MissingAsInsecure =>
        \A i \in 2..Len(Path) :
            SecureTo(i) /\ ~reach[Path[i]] => Result.kind = "Indeterminate"

(* A valid chain is never reported as anything but Secure. *)
NoDowngrade == ChainHolds => Result.kind = "Secure"

IndeterminateOnlyUnreachable ==
    Result.kind = "Indeterminate" => \E z \in Zones : ~reach[z]

(* AD only for Secure data when the query had DO or AD; never for          *)
(* NotPerformed, and never because an upstream set it.                     *)
AdOnlySecure == Rendered.ad => Result.kind = "Secure" /\ (do \/ adq)

BogusServfails == Result.kind = "Bogus" /\ ~cd => Rendered.rcode = "SERVFAIL"

(* With CD the client gets the data whatever the validation found, when    *)
(* the data could be fetched at all.                                      *)
CdPassesData == cd /\ reach["sld"] => Rendered.rcode = "NOERROR" /\ Rendered.data

(* Under the default policy a zone whose DS names algorithm 5 or 7 below a *)
(* validated chain is Insecure, never Secure (RFC 9905 section 2).         *)
Sha1Insecure ==
    \A i \in 1..Len(Path) :
        (SecureTo(i) /\ alg[Path[i]] = "sha1"
         /\ (i = 1 \/ (proof[Path[i]] \in {"DsA", "DsB"} /\ reach[Path[i]])))
        => Result.kind = "Insecure"

(* Two validators fed equal records from different signers reach the       *)
(* same result.                                                            *)
RecordsOnly ==
    Records(1) = Records(2) => Result = Result2

(* check_chain at build time, with each problem it reports. An RRset       *)
(* changed after signing is SignatureInvalid.                              *)
ChainProblems ==
    { <<"DsMismatch", c>> : c \in {c \in Children : proof[c] \in {"DsA", "DsB"} /\ signer[c] # DsKey(proof[c])} }
    \cup { <<"NoDsProofMissing", c>> : c \in {c \in Children : proof[c] \in {"Nsec", "NsecNoNs", "Nothing"}} }
    \cup { <<"WindowClosed", z>> : z \in {z \in Zones : signer[z] # "none" /\ window[z] # "now"} }
    \cup { <<"UnsupportedAlgorithm", z>> : z \in {z \in Zones : signer[z] # "none" /\ alg[z] \notin PolicyAlgs} }
    \cup { <<"SignatureInvalid", z>> : z \in {z \in Zones : signer[z] # "none" /\ Stale(1, z)} }

(* A tree check_chain passes, under the anchor of its own root key, with    *)
(* every zone reachable and the clock right, validates Secure or Insecure. *)
CheckChainAgrees ==
    (ChainProblems = {} /\ anchor \in {"A", "B"} /\ anchor = signer["root"]
     /\ \A z \in Zones : reach[z] /\ clock = "now")
    => Result.kind \in {"Secure", "Insecure"}

-----------------------------------------------------------------------------
(* Witnesses: each must be reachable, so each "Never..." form must fail. *)

AllSignedBy(k) == \A z \in Zones : signer[z] = k
AllDs(p) == \A c \in Children : proof[c] = p

\* A zone of the world's own that it edited, signed with the world's key
\* under the world's anchor, validates Secure: the world signs its edits.
EditedWorldZoneSecure ==
    anchor = "B" /\ AllSignedBy("B") /\ AllDs("DsB")
    /\ (\E z \in Zones : edited[z])
    /\ Result.kind = "Secure"

\* A zone the world re-signs under a real parent's DS is Bogus.
EditedUnderRealAnchorBogus ==
    anchor = "A" /\ signer["root"] = "A" /\ signer["tld"] = "A" /\ AllDs("DsA")
    /\ signer["sld"] = "B" /\ Result.kind = "Bogus"

\* A zone invented under an opt-out parent (com, net, org) is Insecure.
InventedUnderOptOutInsecure ==
    anchor = "A" /\ signer["root"] = "A" /\ signer["tld"] = "A" /\ proof["tld"] = "DsA"
    /\ proof["sld"] = "OptOutCover" /\ signer["sld"] = "B" /\ Result = V("Insecure", "OptOutCovered")

\* A TLD invented under the real root, which denies with NSEC, is Bogus.
InventedTldUnderNsecBogus ==
    anchor = "A" /\ signer["root"] = "A" /\ proof["tld"] = "Nsec" /\ signer["tld"] = "B"
    /\ Result.kind = "Bogus"

\* A world root signed with the world's key, under the world's anchor.
WorldRootAllSecure ==
    anchor = "B" /\ AllSignedBy("B") /\ AllDs("DsB") /\ Result.kind = "Secure"

\* An unsigned root under the IANA anchor is Bogus.
UnsignedWithIanaAnchorBogus ==
    anchor = "A" /\ signer["root"] = "none" /\ Result.kind = "Bogus"

NoAnchorsNotPerformed ==
    anchor = "none" /\ Result.kind = "NotPerformed" /\ ~Rendered.ad

NeverEditedWorldZoneSecure == ~EditedWorldZoneSecure
NeverEditedUnderRealAnchorBogus == ~EditedUnderRealAnchorBogus
NeverInventedUnderOptOutInsecure == ~InventedUnderOptOutInsecure
NeverInventedTldUnderNsecBogus == ~InventedTldUnderNsecBogus
NeverWorldRootAllSecure == ~WorldRootAllSecure
NeverUnsignedWithIanaAnchorBogus == ~UnsignedWithIanaAnchorBogus
NeverNoAnchorsNotPerformed == ~NoAnchorsNotPerformed

=============================================================================
