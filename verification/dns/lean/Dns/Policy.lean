/-
  The algorithm policy (§8.5): the IANA registry columns that RFC 9904 and RFC 9905 set, the default policy
  `iana` derived from them, and what the policy does to validation.

  RFC 9904 (November 2025) obsoletes RFC 8624 and moves the algorithm recommendations into IANA registry
  columns. RFC 9905 (November 2025) says RSASHA1 (5) and RSASHA1-NSEC3-SHA1 (7) "MUST NOT be used when
  creating DS records", that validating resolvers "MUST treat RSASHA1 and RSASHA1-NSEC3-SHA1 DS records as
  insecure", and that they "MUST treat DNSSEC signing algorithms RSASHA1 and RSASHA1-NSEC3-SHA1 as
  unsupported". SHA-1 as a DS digest (type 1) is MUST NOT for delegation and stays RECOMMENDED for
  validation. Both RFCs and both registries were read on 2026-11-01; the rows below are the registries'
  assigned values on that day.

  Rust: `protocols::dns::dnssec::{AlgorithmPolicy, AlgorithmPolicy::iana}`.
-/
import Dns.Dnssec

namespace Dns.Policy
open Dns.Zone Dns.Dnssec

/-! ## The registries -/

/-- A requirement level in a registry column (RFC 9904 §2, §3). -/
inductive Level where
  | must
  | recommended
  | may
  | notRecommended
  | mustNot
deriving DecidableEq, Repr

/-- A row of "DNS Security Algorithm Numbers": the number and its four DNSSEC columns. -/
structure AlgorithmRow where
  number : Nat
  useSigning : Level
  useValidation : Level
  implementSigning : Level
  implementValidation : Level
deriving DecidableEq, Repr

/-- A row of "Digest Algorithms": the number and its four columns. -/
structure DigestRow where
  number : Nat
  useDelegation : Level
  useValidation : Level
  implementDelegation : Level
  implementValidation : Level
deriving DecidableEq, Repr

open Level in
/-- The zone-signing rows of "DNS Security Algorithm Numbers" (https://www.iana.org/assignments/dns-sec-alg-numbers),
read on 2026-11-01. Rows without DNSSEC columns (0, 2, 252) and the private-use rows 253 and 254 are left out. -/
def algorithms : List AlgorithmRow :=
  [⟨1, mustNot, mustNot, mustNot, mustNot⟩,                -- RSAMD5
   ⟨3, mustNot, mustNot, mustNot, mustNot⟩,                -- DSA
   ⟨5, mustNot, recommended, notRecommended, must⟩,        -- RSASHA1, updated by RFC 9905
   ⟨6, mustNot, mustNot, mustNot, mustNot⟩,                -- DSA-NSEC3-SHA1
   ⟨7, mustNot, recommended, notRecommended, must⟩,        -- RSASHA1-NSEC3-SHA1, updated by RFC 9905
   ⟨8, recommended, recommended, must, must⟩,              -- RSASHA256
   ⟨10, notRecommended, recommended, notRecommended, must⟩, -- RSASHA512
   ⟨12, mustNot, mustNot, mustNot, mustNot⟩,               -- ECC-GOST, RFC 9906
   ⟨13, recommended, recommended, must, must⟩,             -- ECDSAP256SHA256
   ⟨14, may, recommended, may, recommended⟩,               -- ECDSAP384SHA384
   ⟨15, recommended, recommended, recommended, recommended⟩, -- ED25519
   ⟨16, may, recommended, may, recommended⟩,               -- ED448
   ⟨17, may, may, may, may⟩,                               -- SM2SM3
   ⟨18, may, may, may, may⟩,                               -- ML-DSA-44
   ⟨23, may, may, may, may⟩]                               -- ECC-GOST12

open Level in
/-- The assigned rows of "Digest Algorithms" (https://www.iana.org/assignments/ds-rr-types), read on 2026-11-01. -/
def digests : List DigestRow :=
  [⟨0, mustNot, mustNot, mustNot, mustNot⟩,                -- reserved
   ⟨1, mustNot, recommended, mustNot, must⟩,               -- SHA-1, updated by RFC 9905
   ⟨2, recommended, recommended, must, must⟩,              -- SHA-256
   ⟨3, mustNot, mustNot, mustNot, mustNot⟩,                -- GOST R 34.11-94, RFC 9906
   ⟨4, may, recommended, may, recommended⟩,                -- SHA-384
   ⟨5, may, may, may, may⟩,                                -- GOST R 34.11-2012
   ⟨6, may, may, may, may⟩]                                -- SM3

/-- RSASHA1 and RSASHA1-NSEC3-SHA1, which validators must treat as unsupported (RFC 9905 §2). -/
def rfc9905Unsupported : List Nat := [5, 7]

/-- The algorithms the signer implements (§8.2) and the verifier can check: ring has no Ed448, so 16 is
neither. -/
def implementedAlgorithms : List Nat := [8, 10, 13, 14, 15]

/-- The digest types the code computes. -/
def implementedDigests : List Nat := [1, 2, 4]

def strong (l : Level) : Bool := l == .must || l == .recommended

def usable (l : Level) : Bool := strong l || l == .may

/-! ## The default policy -/

/-- The policy RFC 9904 and RFC 9905 give: validate 8, 10, 13, 14, and 15 (5 and 7 treated as unsupported per
RFC 9905 §2); accept DS digests 1, 2, and 4; sign with 8, 13, 14, and 15; delegate with 2 and 4. NSEC3
iterations above 100 are Insecure: RFC 9276 Appendix A found that limit interoperable. -/
def iana : AlgorithmPolicy :=
  { validate := [8, 10, 13, 14, 15]
    digests := [1, 2, 4]
    sign := [8, 13, 14, 15]
    delegate := [2, 4]
    maxIterations := 100 }

/-- `iana` is the registries read through RFC 9905: validate what "Use for DNSSEC Validation" marks MUST or
RECOMMENDED, except what RFC 9905 makes unsupported and what the code cannot check; accept the digests that
column marks so; sign and delegate with what the code implements and the use columns do not forbid or
discourage. -/
theorem iana_matches_registry :
    iana.validate = (algorithms.filter fun r => strong r.useValidation && !rfc9905Unsupported.contains r.number &&
      implementedAlgorithms.contains r.number).map (·.number) ∧
    iana.digests = (digests.filter fun r => strong r.useValidation && implementedDigests.contains r.number).map
      (·.number) ∧
    iana.sign = (algorithms.filter fun r => usable r.useSigning && implementedAlgorithms.contains r.number).map
      (·.number) ∧
    iana.delegate = (digests.filter fun r => usable r.useDelegation && implementedDigests.contains r.number).map
      (·.number) := by
  decide

/-- How the default policy treats each row: algorithms 5 and 7 are unsupported, SHA-1 still links a parent to
a child. -/
theorem iana_treat :
    iana.treat 5 2 = .unsupportedAlgorithm ∧ iana.treat 7 2 = .unsupportedAlgorithm ∧
      iana.treat 8 1 = .supported ∧ iana.treat 13 2 = .supported ∧ iana.treat 16 2 = .unsupportedAlgorithm ∧
      iana.treat 13 3 = .unsupportedDigest := by
  decide

/-! ## What the policy does to validation -/

variable {S : SigScheme}

/-- Under the default policy an answer signed only with algorithm 5 or 7 is never Secure (RFC 9905 §2). -/
theorem sha1_never_secure {A : List Anchor} {t : Nat} {C : Chain S} {set : RRset} {sigs : List (Rrsig S)}
    {ds : List (Signed S)} (h5 : ∀ r ∈ sigs, r.hdr.alg = 5 ∨ r.hdr.alg = 7) :
    validateRrset (some A) iana t C set sigs ds ≠ .secure := by
  intro h
  obtain ⟨_, _, _, apex, keys, _, _, hf⟩ := secure_iff.mp h
  have : ∃ r ∈ sigs, SigBy iana t apex keys (rrsetCover set) r := by
    rcases hf with ⟨r, hr, h, _⟩ | ⟨r, hr, h, _⟩ <;> exact ⟨r, hr, h⟩
  obtain ⟨r, hr, hu, _⟩ := this
  simp only [Dnssec.usable, Bool.and_eq_true] at hu
  rcases h5 r hr with h' | h' <;> rw [h'] at hu <;> exact absurd hu.1.2 (by decide)

theorem descend_append {P : AlgorithmPolicy} {t : Nat} {owner : Name} {apex : Name} {keys : List Key}
    {pre : Chain S} {apex' : Name} {keys' : List Key} (h : Reaches P t owner apex keys pre apex' keys')
    (rest : Chain S) : descend P t owner apex keys (pre ++ rest) = descend P t owner apex' keys' rest := by
  induction h with
  | nil => rfl
  | cons hl _ ih => simp [descend, linkStep_ok.mpr hl, ih]

/-- A DS set the policy does not support makes the zone below Insecure, never Bogus, whatever its DNSKEY set
and signatures are: at the anchor, -/
theorem unsupported_is_insecure_not_bogus {A : List Anchor} {P : AlgorithmPolicy} {t : Nat} {C : Chain S}
    {set : RRset} {sigs : List (Rrsig S)} {ds : List (Signed S)} {a : Anchor} {l0 : Link S} {ls0 : Chain S}
    (ha : anchorFor A set.owner = some a) (hC : C = l0 :: ls0) (hl : l0.apex = a.owner) (hne : a.ds ≠ [])
    (hun : ∀ d ∈ a.ds, P.treat d.keyAlg d.dtype ≠ .supported) :
    validateRrset (some A) P t C set sigs ds = .insecure (unsupportedWhy P a.ds) := by
  have hk : keyStep P t a.owner a.ds l0.keys = .error (.insecure (unsupportedWhy P a.ds)) :=
    keyStep_insecure.mpr ⟨hne, hun, rfl⟩
  unfold validateRrset walk
  simp only [ha, hC, hl, ne_eq, not_true_eq_false, ↓reduceIte, hk]

/-- and at any link a secure chain reaches, when the parent signed that DS set. -/
theorem unsupported_link_insecure {A : List Anchor} {P : AlgorithmPolicy} {t : Nat} {C : Chain S} {set : RRset}
    {sigs : List (Rrsig S)} {ds : List (Signed S)} {l0 : Link S} {ls0 pre post : Chain S} {ks0 : List Key}
    {apex : Name} {keys : List Key} {l : Link S} {sd : Signed S} {dss : List Ds}
    (h0 : Anchored A P t set.owner C l0 ls0 ks0) (hr : Reaches P t set.owner l0.apex ks0 pre apex keys)
    (hls : ls0 = pre ++ l :: post) (hs : strictly l.apex apex = true) (hu : under set.owner l.apex = true)
    (hp : l.parent = some (.ds sd)) (hd : DsSigned P t apex keys l.apex sd dss) (hne : dss ≠ [])
    (hun : ∀ d ∈ dss, P.treat d.keyAlg d.dtype ≠ .supported) :
    validateRrset (some A) P t C set sigs ds = .insecure (unsupportedWhy P dss) := by
  obtain ⟨a, ha, hC, hl, hk⟩ := h0
  have hlink : linkStep P t set.owner apex keys l = .error (.insecure (unsupportedWhy P dss)) := by
    unfold linkStep
    simp only [hs, hu, Bool.and_self, Bool.not_true, Bool.false_eq_true, ↓reduceIte, hp]
    rw [dsStep_ok.mpr hd]
    exact keyStep_insecure.mpr ⟨hne, hun, rfl⟩
  have hw : walk A P t set.owner C = .stop (.insecure (unsupportedWhy P dss)) := by
    unfold walk
    rw [ha, hC]
    simp only [hl, ne_eq, not_true_eq_false, ↓reduceIte]
    rw [hl] at hk hr
    rw [keyStep_ok.mpr hk]
    simp only
    rw [hls, descend_append hr]
    simp [descend, hlink]
  simp [validateRrset, hw]

/-- Under the default policy a zone whose DS records name only algorithms 5 and 7 is Insecure. -/
theorem sha1_ds_insecure {A : List Anchor} {t : Nat} {C : Chain S} {set : RRset} {sigs : List (Rrsig S)}
    {ds : List (Signed S)} {a : Anchor} {l0 : Link S} {ls0 : Chain S}
    (ha : anchorFor A set.owner = some a) (hC : C = l0 :: ls0) (hl : l0.apex = a.owner) (hne : a.ds ≠ [])
    (h5 : ∀ d ∈ a.ds, d.keyAlg = 5 ∨ d.keyAlg = 7) :
    validateRrset (some A) iana t C set sigs ds = .insecure .unsupportedAlgorithm := by
  have hun : ∀ d ∈ a.ds, iana.treat d.keyAlg d.dtype ≠ .supported := by
    intro d hd
    rcases h5 d hd with h | h <;> simp [AlgorithmPolicy.treat, h, iana]
  rw [unsupported_is_insecure_not_bogus ha hC hl hne hun]
  have : unsupportedWhy iana a.ds = .unsupportedAlgorithm := by
    have hall : a.ds.all (fun d => !iana.validate.contains d.keyAlg) = true := by
      rw [List.all_eq_true]
      intro d hd
      rcases h5 d hd with h | h <;> simp [h, iana]
    unfold unsupportedWhy
    simp only [hall, ↓reduceIte]
  rw [this]

/-- With no anchors configured nothing is validated, and AD is never set for data that was not validated: AD
needs Secure (RFC 6840 §5.7, §5.8). -/
theorem not_performed_never_ad (P : AlgorithmPolicy) (t : Nat) (C : Chain S) (set : RRset) (sigs : List (Rrsig S))
    (ds : List (Signed S)) (q : Request) (rc : Rcode) (doBit ad : Bool) :
    validateRrset none P t C set sigs ds = .notPerformed ∧ validateDenial none P t C q rc ds = .notPerformed ∧
      adBit .notPerformed doBit ad = false ∧ ∀ v, adBit v doBit ad = true → v = .secure := by
  refine ⟨rfl, rfl, rfl, fun v h => ?_⟩
  simp only [adBit, Bool.and_eq_true, beq_iff_eq] at h
  exact h.1

end Dns.Policy
