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
(*              encloser proof, an NSEC denying the name, or nothing       *)
(*   window[z]  when z's signatures are valid: past, now, or future        *)
(*   alg[z]     the algorithm the DS (or the anchor) names for z:          *)
(*              supported, SHA-1 based (5 or 7), or unknown                *)
(*   changed[z] whether an RRset of z changed after it was signed          *)
(*   clock      the validator's clock: now, or skewed to past or future    *)
(*   reach[z]   whether z's DNSKEY and DS sets can be fetched              *)
(*   cached     whether the answer comes from the resolver's cache, with   *)
(*              the validation an earlier query without CD made            *)
(*                                                                         *)
(* The provider (Complete, Lazy, Relayed) and the signer implementation    *)
(* (A or B) produce the same records by contract; the validator must not   *)
(* see them. RecordsOnly is checked by self-composition: two copies of the *)
(* validator, each with its own provider and signer, get records of their  *)
(* own, which differ where the second copy's changed2 differs, and must    *)
(* agree whenever their records are equal.                                 *)
(*                                                                         *)
(* Ablation flags: PolicyAlgs is the policy value (adding "sha1" accepts   *)
(* algorithm 5), TrustUpstreamAd copies an upstream AD bit,                *)
(* MissingAsInsecure reads a failed fetch as Insecure, SignerPeek lets the *)
(* validator skip a check for records from signer A.                       *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    AnchorChoices, SignerChoices, ProofChoices, WindowChoices, AlgChoices,
    ChangedChoices, ClockChoices, ReachChoices, ProviderChoices, ImplChoices,
    PolicyAlgs,        \* the algorithms AlgorithmPolicy.validate admits
    TrustUpstreamAd,   \* ablation: AD from upstream reaches the client
    MissingAsInsecure, \* ablation: a failed fetch is Insecure
    SignerPeek         \* ablation: the validator reads the signer implementation

Path == <<"root", "tld", "sld">>
Zones == {"root", "tld", "sld"}
Children == {"tld", "sld"}
Windows == <<"past", "now", "future">>
Pos(w) == CHOOSE i \in 1..3 : Windows[i] = w

VARIABLES
    anchor, signer, proof, window, alg, changed, clock, reach,
    do, adq, cd, upstreamAd,       \* the query's DO, AD, and CD bits; the upstream reply's AD bit
    cached,                        \* the answer comes from the cache, validated by an earlier query
    provider1, impl1, provider2, impl2,
    changed2                       \* what changed after signing in the second copy's records

vars == <<anchor, signer, proof, window, alg, changed, clock, reach, do, adq, cd, upstreamAd,
          cached, provider1, impl1, provider2, impl2, changed2>>

Init ==
    /\ anchor \in AnchorChoices
    /\ signer \in [Zones -> SignerChoices]
    /\ proof \in [Children -> ProofChoices]
    /\ window \in [Zones -> WindowChoices]
    /\ alg \in [Zones -> AlgChoices]
    /\ changed \in [Zones -> ChangedChoices]
    /\ clock \in ClockChoices
    /\ reach \in [Zones -> ReachChoices]
    /\ do \in BOOLEAN /\ adq \in BOOLEAN /\ cd \in BOOLEAN /\ upstreamAd \in BOOLEAN
    /\ cached \in BOOLEAN
    /\ provider1 \in ProviderChoices /\ impl1 \in ImplChoices
    /\ provider2 \in ProviderChoices /\ impl2 \in ImplChoices
    /\ changed2 \in [Zones -> ChangedChoices]

Next == UNCHANGED vars
Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Published records. Every provider and signer publishes the same records *)
(* for the same zone data (Lean: lazy_agrees_complete and                  *)
(* signer_agnostic); the faults are what the validator's fetches and clock *)
(* see.                                                                    *)

\* The records copy `run` of the validator gets.
Records(run) ==
    [anchor |-> anchor, signer |-> signer, proof |-> proof, window |-> window, alg |-> alg,
     changed |-> IF run = 1 THEN changed ELSE changed2, clock |-> clock, reach |-> reach]

V(kind, why) == [kind |-> kind, why |-> why]

\* The key a DS proof names, or "none" for any other proof.
DsKey(p) == CASE p = "DsA" -> "A" [] p = "DsB" -> "B" [] OTHER -> "none"

(* The validator, walking down from the anchor. At zone i it holds the key *)
(* the link above names. The algorithm comes from the DS or anchor, so an  *)
(* unsupported one makes the zone Insecure before any fetch (RFC 4035      *)
(* section 5.2, RFC 9905 section 2).                                       *)
RECURSIVE Walk(_, _, _, _)
Walk(r, impl, i, expect) ==
    LET z == Path[i] IN
    IF r.alg[z] \notin PolicyAlgs THEN V("Insecure", "UnsupportedAlgorithm")
    ELSE IF ~r.reach[z] THEN (IF MissingAsInsecure THEN V("Insecure", "Missing") ELSE V("Indeterminate", "ede5"))
    ELSE IF r.signer[z] = "none" THEN V("Bogus", "ede9")
    ELSE IF r.signer[z] # expect THEN V("Bogus", "ede9")
    ELSE IF Pos(r.window[z]) < Pos(r.clock) THEN V("Bogus", "ede7")
    ELSE IF Pos(r.window[z]) > Pos(r.clock) THEN V("Bogus", "ede8")
    ELSE IF r.changed[z] /\ ~(SignerPeek /\ impl = "A") THEN V("Bogus", "ede6")
    ELSE IF i = Len(Path) THEN V("Secure", "none")
    ELSE LET p == r.proof[Path[i + 1]] IN
         CASE p \in {"DsA", "DsB"} -> Walk(r, impl, i + 1, DsKey(p))
           [] p = "NoDs"           -> V("Insecure", "ProvenNoDs")
           [] p = "OptOutCover"    -> V("Insecure", "OptOutCovered")
           [] p = "Nsec"           -> V("Bogus", "ede6")    \* the proof denies the delegation itself
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
    /\ reach[z] /\ signer[z] = Expect(j) /\ window[z] = clock /\ ~changed[z]
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
(* whose algorithm the policy does not admit.                             *)
InsecureNeedsProof ==
    Result.kind = "Insecure" =>
        \/ anchor = "elsewhere"
        \/ \E i \in 1..Len(Path) :
              /\ SecureTo(i)
              /\ \/ alg[Path[i]] \notin PolicyAlgs
                 \/ i > 1 /\ proof[Path[i]] \in {"NoDs", "OptOutCover"}

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
        (SecureTo(i) /\ alg[Path[i]] = "sha1" /\ (i = 1 \/ proof[Path[i]] \in {"DsA", "DsB"}))
        => Result.kind = "Insecure"

(* Two validators fed equal records from different providers and signers   *)
(* reach the same result.                                                 *)
RecordsOnly ==
    Records(1) = Records(2) => Result = Result2

(* check_chain over complete zones at build time, with each problem it      *)
(* reports. An RRset changed after signing is SignatureInvalid.            *)
ChainProblems ==
    { <<"DsMismatch", c>> : c \in {c \in Children : proof[c] \in {"DsA", "DsB"} /\ signer[c] # DsKey(proof[c])} }
    \cup { <<"NoDsProofMissing", c>> : c \in {c \in Children : proof[c] \in {"Nsec", "Nothing"}} }
    \cup { <<"WindowClosed", z>> : z \in {z \in Zones : signer[z] # "none" /\ window[z] # "now"} }
    \cup { <<"UnsupportedAlgorithm", z>> : z \in {z \in Zones : signer[z] # "none" /\ alg[z] \notin PolicyAlgs} }
    \cup { <<"SignatureInvalid", z>> : z \in {z \in Zones : signer[z] # "none" /\ changed[z]} }

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

\* Unedited zones relayed from real servers validate under the real anchor.
RelayedUneditedSecure ==
    provider1 = "Relayed" /\ anchor = "A" /\ AllSignedBy("A") /\ AllDs("DsA") /\ Result.kind = "Secure"

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

NeverRelayedUneditedSecure == ~RelayedUneditedSecure
NeverEditedUnderRealAnchorBogus == ~EditedUnderRealAnchorBogus
NeverInventedUnderOptOutInsecure == ~InventedUnderOptOutInsecure
NeverInventedTldUnderNsecBogus == ~InventedTldUnderNsecBogus
NeverWorldRootAllSecure == ~WorldRootAllSecure
NeverUnsignedWithIanaAnchorBogus == ~UnsignedWithIanaAnchorBogus
NeverNoAnchorsNotPerformed == ~NoAnchorsNotPerformed

=============================================================================
