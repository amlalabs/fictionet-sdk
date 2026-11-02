/-
  DNSSEC as data plus a separate policy (§8 of the design): keys, DS records, RRSIGs, NSEC and NSEC3 records,
  the validator, offline zone signing, and the covering records an online signer makes.

  The validator is a function of records, trust anchors, an algorithm policy, a time, and a signature
  scheme. It has no path to a signer or a data provider. Signatures are symbolic: `SigScheme` asks only that
  a signature made with a private key verifies under its public key, and that a signature that verifies was
  made with a private key whose public key is the one it verified under. That second law is what an
  unforgeable signature means in a symbolic model, and it is what makes `secure_sound` say something about
  authenticity.

  Names are lowercase (Rust's `LowerName`), so the canonical order of RFC 4034 §6.1 is the label order of
  `Dns/Name.lean` without the fold.

  Rust: `protocols::dns::dnssec::{Algorithm, AlgorithmPolicy, ZoneKey, Sign, KeySet, sign, Verify, TrustAnchor,
  Anchors, proof, Chain, Validation, Insecure, validate_rrset, validate_denial}` and
  `services::dns::zone::{signed, cover}`.
-/
import Dns.Zone
import Dns.Partial

namespace Dns.Dnssec
open Zone

/-! ## Records -/

/-- A DNSKEY: the public key octets, the algorithm, and the SEP bit (flags 257 rather than 256). -/
structure Key where
  pub : Bytes
  alg : Nat
  sep : Bool
deriving DecidableEq, Repr

/-- One DS record: the algorithm of the key it names, the digest type, and the digest. -/
structure Ds where
  keyAlg : Nat
  dtype : Nat
  digest : Bytes
deriving DecidableEq, Repr

/-- The RRSIG fields a signature covers besides the records: algorithm, signer, labels, original TTL, and the
validity window (RFC 4034 §3.1). The type covered is the signed RRset's own. -/
structure Header where
  alg : Nat
  signer : Name
  labels : Nat
  ttl : Nat
  inception : Nat
  expiration : Nat
deriving DecidableEq, Repr

/-- An NSEC record (RFC 4034 §4). -/
structure Nsec where
  owner : Name
  next : Name
  types : List Nat
deriving DecidableEq, Repr

/-- An NSEC3 record (RFC 5155 §3): the hashed owner and the next hashed owner as numbers, in the zone `zone`.
The salt is empty and the iterations are what the record says. -/
structure Nsec3 where
  zone : Name
  hash : Nat
  next : Nat
  types : List Nat
  optOut : Bool
  iterations : Nat
deriving DecidableEq, Repr

/-- What an RRSIG can cover. A DS set is an RRset of type 43. -/
inductive Payload where
  | rrset (s : RRset)
  | keys (owner : Name) (ks : List Key)
  | nsec (r : Nsec)
  | nsec3 (r : Nsec3)
deriving DecidableEq, Repr

/-- The to-be-signed data: the RRSIG fields and the records (RFC 4034 §3.1.8.1). -/
structure Tbs where
  hdr : Header
  data : Payload
deriving DecidableEq, Repr

namespace RType
def NSEC := 47
def RRSIG := 46
def DNSKEY := 48
def NSEC3 := 50
end RType

/-! ## The signature scheme -/

/-- A signature scheme, symbolically. `verify_sound` is unforgeability: a signature that verifies under a
public key was made with a private key whose public key that is. DS digests and NSEC3 hashes are the
protocol's own operations; `hash` maps a name to its NSEC3 hash, a number below `hashSpace`. -/
class SigScheme where
  Priv : Type
  Sig : Type
  pub : Priv → Bytes
  sign : Priv → Tbs → Sig
  verify : Bytes → Tbs → Sig → Bool
  digest : Name → Key → Bytes
  hash : Name → Nat
  hashSpace : Nat
  verify_sign : ∀ p m, verify (pub p) m (sign p m) = true
  verify_sound : ∀ k m s, verify k m s = true → ∃ p, pub p = k ∧ s = sign p m
  hash_lt : ∀ n, hash n < hashSpace

variable {S : SigScheme}

/-- An RRSIG: the covered fields and the signature. -/
structure Rrsig (S : SigScheme) where
  hdr : Header
  sig : S.Sig

/-- Records of one kind with the RRSIGs over them. -/
structure Signed (S : SigScheme) where
  data : Payload
  sigs : List (Rrsig S)

/-- The DS records in a DS RRset. -/
def dsOf (s : RRset) : List Ds :=
  s.rdata.filterMap fun
    | .ds _ alg dt dig => some ⟨alg, dt, dig⟩
    | _ => none

/-! ## The algorithm policy (§8.5)

The policy is a value of its own, separate from what the scheme can verify. The numbers are registry
values, not an enum, so a new registry entry needs no change here. `Dns/Policy.lean` gives the IANA
registry's values. -/

structure AlgorithmPolicy where
  /-- Algorithms whose signatures may make an answer Secure (RFC 4035 §5.2). -/
  validate : List Nat
  /-- DS digest types that may link a parent to a child. -/
  digests : List Nat
  /-- Algorithms and digest types this world may create records with. -/
  sign : List Nat
  delegate : List Nat
  /-- NSEC3 iterations above this make an answer Insecure (RFC 9276 §3.2). -/
  maxIterations : Nat
deriving DecidableEq, Repr

/-- How the policy treats one DS record. -/
inductive Treatment where
  | supported
  | unsupportedAlgorithm
  | unsupportedDigest
deriving DecidableEq, Repr

/-- A DS record whose key algorithm is outside `validate` names an unsupported algorithm; one whose digest
type is outside `digests` an unsupported digest (RFC 4035 §5.2, RFC 9905 §2). -/
def AlgorithmPolicy.treat (P : AlgorithmPolicy) (alg dtype : Nat) : Treatment :=
  if !P.validate.contains alg then .unsupportedAlgorithm
  else if !P.digests.contains dtype then .unsupportedDigest
  else .supported

/-! ## Results (§8.6) -/

/-- Extended DNS Error codes for DNSSEC (RFC 8914 §4). -/
inductive Ede where
  | unsupportedAlgorithm
  | unsupportedDigest
  | indeterminate
  | bogus
  | expired
  | notYetValid
  | dnskeyMissing
  | rrsigsMissing
  | noZoneKeyBit
  | nsecMissing
  | expiredBeforeValid
  | nsec3Iterations
deriving DecidableEq, Repr

def Ede.code : Ede → Nat
  | .unsupportedAlgorithm => 1 | .unsupportedDigest => 2 | .indeterminate => 5 | .bogus => 6
  | .expired => 7 | .notYetValid => 8 | .dnskeyMissing => 9 | .rrsigsMissing => 10 | .noZoneKeyBit => 11
  | .nsecMissing => 12 | .expiredBeforeValid => 25 | .nsec3Iterations => 27

/-- Why an answer is Insecure: each is a proof, never a missing record. -/
inductive Insecure where
  | provenNoDs
  | optOutCovered
  | noAnchor
  | unsupportedAlgorithm
  | unsupportedDigest
  | nsec3Iterations
deriving DecidableEq, Repr

/-- What a validator established for one answer. -/
inductive Validation where
  /-- The resolver did not validate: no anchors are configured. -/
  | notPerformed
  | secure
  | insecure (why : Insecure)
  | bogus (ede : Ede)
  /-- Needed records could not be obtained (RFC 4035 §4.3). -/
  | indeterminate
deriving DecidableEq, Repr

/-- AD on an answer to a client: only for Secure data, and only when the query had DO or AD
(RFC 6840 §5.7, §5.8). -/
def adBit (v : Validation) (doBit ad : Bool) : Bool := v == .secure && (doBit || ad)

/-! ## Order and coverage -/

/-- The canonical order of RFC 4034 §6.1 on lowercase names. -/
def before (a b : Name) : Bool := Name.labelsLt a.reverse b.reverse

/-- An NSEC from `o` to `n` covers `q`: `q` sorts strictly between them. The last NSEC of a zone points back
to the apex, so its interval wraps (RFC 4034 §4.1.1). -/
def covers (o n q : Name) : Bool :=
  if before o n then before o q && before q n else before o q || before q n

/-- The NSEC3 form of `covers`, on hashes (RFC 5155 §1.3). -/
def covers3 (o n x : Nat) : Bool :=
  if o < n then o < x && x < n else o < x || x < n

/-- The strict ancestors of a name, deepest first. -/
def ancestors (q : Name) : List Name := (List.range q.length).map fun i => q.drop (i + 1)

/-- The ancestor of `q` one label longer than its ancestor `ce` (RFC 5155 §1.3). -/
def nextCloser (q ce : Name) : Name := q.drop (q.length - ce.length - 1)

def hasType (ts : List Nat) (t : Nat) : Bool := ts.contains t

def nsecs (ps : List Payload) : List Nsec := ps.filterMap fun
  | .nsec r => some r
  | _ => none

def nsec3s (ps : List Payload) : List Nsec3 := ps.filterMap fun
  | .nsec3 r => some r
  | _ => none

/-! ## Signatures -/

/-- The validity window holds at `t` (RFC 4034 §3.1.5, RFC 4035 §5.3.1). -/
def windowOk (t : Nat) (h : Header) : Bool := h.inception ≤ t && t ≤ h.expiration

/-- The RRset an RRSIG with this header covers for `set`, in canonical form: the set with the original TTL,
and, when the RRSIG counts fewer labels than the owner has, the wildcard it was expanded from
(RFC 4035 §5.3.2). -/
def expanded (h : Header) (set : RRset) : Option RRset :=
  if h.labels = set.owner.length then some { set with ttl := h.ttl }
  else if h.labels < set.owner.length then
    some { set with owner := [42] :: set.owner.drop (set.owner.length - h.labels), ttl := h.ttl }
  else none

/-- What the RRSIG with header `h` covers when it is offered for `set`. -/
def rrsetCover (set : RRset) (h : Header) : Option Payload := (expanded h set).map .rrset

/-- The same, with no wildcard expansion: what an RRSIG over a DS set covers. -/
def exactCover (set : RRset) (h : Header) : Option Payload :=
  if h.labels = set.owner.length then some (.rrset { set with ttl := h.ttl }) else none

/-- An RRSIG the validator considers: by this zone, with an algorithm the policy validates that one of the
zone's trusted keys uses (RFC 4035 §5.3.1, RFC 6840 §5.11). -/
def usable (P : AlgorithmPolicy) (apex : Name) (keys : List Key) (r : Rrsig S) : Bool :=
  r.hdr.signer == apex && P.validate.contains r.hdr.alg && keys.any (·.alg == r.hdr.alg)

/-- The RRSIG is usable, its window holds, and it verifies under one of the keys over what it covers. -/
def verifies (P : AlgorithmPolicy) (t : Nat) (apex : Name) (keys : List Key) (cover : Header → Option Payload)
    (r : Rrsig S) : Bool :=
  usable P apex keys r && windowOk t r.hdr &&
    match cover r.hdr with
    | some d => keys.any fun k => k.alg == r.hdr.alg && S.verify k.pub ⟨r.hdr, d⟩ r.sig
    | none => false

/-- Why none of the usable RRSIGs verified: there are none (EDE 10), or the window of the first one is
inverted (25), past (7), or not yet open (8), or its signature is bad (6). -/
def failure (t : Nat) : List (Rrsig S) → Ede
  | [] => .rrsigsMissing
  | r :: _ =>
    if r.hdr.expiration < r.hdr.inception then .expiredBeforeValid
    else if r.hdr.expiration < t then .expired
    else if t < r.hdr.inception then .notYetValid
    else .bogus

/-- The payloads of the denial records whose RRSIGs verify; the others are ignored. -/
def verified (P : AlgorithmPolicy) (t : Nat) (apex : Name) (keys : List Key) (ds : List (Signed S)) :
    List Payload :=
  (ds.filter fun d => d.sigs.any (verifies P t apex keys fun _ => some d.data)).map (·.data)

/-! ## Denial proofs (RFC 4035 §5.4, RFC 5155 §8) -/

/-- The NSEC3 records match `n`. -/
def matches3 (rs : List Nsec3) (n : Name) : Bool := rs.any (·.hash == S.hash n)

/-- The closest provable encloser of `q`: its deepest strict ancestor with a matching NSEC3
(RFC 5155 §8.3). -/
def closest3 (rs : List Nsec3) (q : Name) : Option Name := (ancestors q).find? (matches3 (S := S) rs)

/-- Some NSEC3 covers the hash of `n`, with the opt-out flag `optOut`. -/
def covered3 (rs : List Nsec3) (n : Name) (optOut : Bool) : Bool :=
  rs.any fun r => covers3 r.hash r.next (S.hash n) && r.optOut == optOut

/-- `q` does not exist, by NSEC3 (RFC 5155 §8.4): a closest encloser, its next closer name covered, and the
wildcard at the closest encloser covered. `some false` when the next closer's cover is an ordinary one,
`some true` when only an opt-out cover exists. -/
def nx3 (rs : List Nsec3) (q : Name) : Option Bool :=
  match closest3 (S := S) rs q with
  | none => none
  | some ce =>
    if !(rs.any fun r => covers3 r.hash r.next (S.hash (wild ce))) then none
    else if covered3 (S := S) rs (nextCloser q ce) false then some false
    else if covered3 (S := S) rs (nextCloser q ce) true then some true
    else none

/-- The name an NSEC covering `q` proves is the closest encloser: the deepest ancestor of `q` that is an
ancestor of the NSEC's owner or next name (RFC 4035 §5.4). -/
def closestNsec (r : Nsec) (q : Name) : Option Name :=
  (ancestors q).find? fun a => under r.owner a || under r.next a

/-- An NSEC proves that nothing exists at or below `q`: it covers `q` and its next name is not below `q`. -/
def nsecNone (r : Nsec) (q : Name) : Bool := covers r.owner r.next q && !under r.next q

/-- `q` does not exist, by NSEC: an NSEC proves nothing is at or below `q`, and an NSEC covers the wildcard at
the closest encloser it proves. -/
def nx (rs : List Nsec) (q : Name) : Bool :=
  rs.any fun r => nsecNone r q && match closestNsec r q with
    | some ce => rs.any fun r' => covers r'.owner r'.next (wild ce)
    | none => false

/-- `q` has no RRset of type `qt`, by NSEC: its own NSEC lacks the type and CNAME; or `q` is an empty
non-terminal (an NSEC covers it and its next name is below it); or no closer match exists and the wildcard's
NSEC lacks the type and CNAME (RFC 4035 §3.1.3.4). -/
def nodata (rs : List Nsec) (q : Name) (qt : Nat) : Bool :=
  (rs.any fun r => r.owner == q && !hasType r.types qt && !hasType r.types 5) ||
  (rs.any fun r => covers r.owner r.next q && under r.next q && r.next != q) ||
  (rs.any fun r => nsecNone r q && match closestNsec r q with
    | some ce => rs.any fun r' => r'.owner == wild ce && !hasType r'.types qt && !hasType r'.types 5
    | none => false)

/-- `q` has no RRset of type `qt`, by NSEC3: a matching NSEC3 lacking the type and CNAME (RFC 5155 §8.5), or a
closest encloser proof and a wildcard NSEC3 lacking them (RFC 5155 §8.7). -/
def nodata3 (rs : List Nsec3) (q : Name) (qt : Nat) : Bool :=
  (rs.any fun r => r.hash == S.hash q && !hasType r.types qt && !hasType r.types 5) ||
  match closest3 (S := S) rs q with
  | some ce =>
    rs.any (fun r => covers3 r.hash r.next (S.hash (nextCloser q ce))) &&
      rs.any fun r => r.hash == S.hash (wild ce) && !hasType r.types qt && !hasType r.types 5
  | none => false

/-- An opt-out NSEC3 covers the next closer name of a closest provable encloser of `c`: an unsigned delegation
may exist there (RFC 5155 §8.6, §6). -/
def optOut3 (rs : List Nsec3) (c : Name) : Bool :=
  match closest3 (S := S) rs c with
  | some ce => covered3 (S := S) rs (nextCloser c ce) true
  | none => false

/-- A delegation record set: NS present, DS and SOA absent. -/
def insecureCut (ts : List Nat) : Bool := hasType ts 2 && !hasType ts 43 && !hasType ts 6

/-- What the verified denial records at a cut to `c` prove about its DS set (RFC 4035 §5.2, RFC 5155 §8.6,
RFC 9276 §3.2): no DS, an opt-out cover, iterations above the limit, or nothing. -/
def noDsProof (P : AlgorithmPolicy) (c : Name) (ps : List Payload) : Option Insecure :=
  if (nsecs ps).any (fun r => r.owner == c && insecureCut r.types) then some .provenNoDs
  else if (nsec3s ps).any (fun r => P.maxIterations < r.iterations) then some .nsec3Iterations
  else if (nsec3s ps).any (fun r => r.hash == S.hash c && insecureCut r.types) then some .provenNoDs
  else if optOut3 (S := S) (nsec3s ps) c then some .optOutCovered
  else none

/-- What verified denial records prove for a negative answer to `q`. -/
def denialResult (P : AlgorithmPolicy) (q : Request) (rc : Rcode) (ps : List Payload) : Validation :=
  let rs := nsecs ps
  let rs3 := nsec3s ps
  if rc = .nxdomain then
    if nx rs q.qname then .secure
    else if rs3.any (fun r => P.maxIterations < r.iterations) then .insecure .nsec3Iterations
    else match nx3 (S := S) rs3 q.qname with
      | some false => .secure
      | some true => .insecure .optOutCovered
      | none => .bogus .nsecMissing
  else
    if nodata rs q.qname q.qtype then .secure
    else if rs3.any (fun r => P.maxIterations < r.iterations) then .insecure .nsec3Iterations
    else if nodata3 (S := S) rs3 q.qname q.qtype then .secure
    else if q.qtype = 43 && optOut3 (S := S) rs3 q.qname then .insecure .optOutCovered
    else .bogus .nsecMissing

/-- A wildcard expansion of `owner` from an RRSIG with `labels` labels is backed by a proof that no closer
name exists: an NSEC covering `owner`, or an NSEC3 covering the next closer name (RFC 4035 §5.3.4,
RFC 5155 §8.8). -/
def wildcardProof (ps : List Payload) (owner : Name) (labels : Nat) : Bool :=
  (nsecs ps).any (fun r => covers r.owner r.next owner) ||
  (nsec3s ps).any fun r => covers3 r.hash r.next (S.hash (owner.drop (owner.length - labels - 1)))

/-! ## The chain (§8.6) -/

/-- What a parent says about a child's DS set: the signed DS RRset, or signed denial records. -/
inductive Delegation (S : SigScheme) where
  | ds (set : Signed S)
  | noDs (denial : List (Signed S))

/-- One zone on the path from an anchor down. `none` marks a fetch that failed. The anchored zone's
`parent` is not read: the anchor stands in for it. -/
structure Link (S : SigScheme) where
  apex : Name
  parent : Option (Delegation S)
  keys : Option (Signed S)

abbrev Chain (S : SigScheme) := List (Link S)

structure Anchor where
  owner : Name
  ds : List Ds
deriving DecidableEq, Repr

/-- Keeps the deeper of the best anchor so far and `a`, when `a` is at or above `n`. -/
def anchorStep (n : Name) (best : Option Anchor) (a : Anchor) : Option Anchor :=
  if under n a.owner then
    match best with
    | some b => if b.owner.length < a.owner.length then some a else best
    | none => some a
  else best

/-- The deepest anchor at or above `n`; the first of equally deep ones. -/
def anchorFor (A : List Anchor) (n : Name) : Option Anchor := A.foldl (anchorStep n) none

/-- The DS records the policy supports. -/
def supported (P : AlgorithmPolicy) (dss : List Ds) : List Ds :=
  dss.filter fun d => P.treat d.keyAlg d.dtype == .supported

/-- The reason a non-empty DS set with no supported record is Insecure. -/
def unsupportedWhy (P : AlgorithmPolicy) (dss : List Ds) : Insecure :=
  if dss.all (fun d => !P.validate.contains d.keyAlg) then .unsupportedAlgorithm else .unsupportedDigest

/-- The keys of the DNSKEY set that a supported DS names: SEP keys whose algorithm and digest match. -/
def anchored (apex : Name) (sup : List Ds) (ks : List Key) : List Key :=
  ks.filter fun k => k.sep && sup.any fun d => d.keyAlg == k.alg && d.digest == S.digest apex k

/-- From a DS set to the zone's trusted keys: an empty supported set makes the zone Insecure; a missing
DNSKEY set is Indeterminate; otherwise a key the DS names must sign the DNSKEY set. -/
def keyStep (P : AlgorithmPolicy) (t : Nat) (apex : Name) (dss : List Ds) (ko : Option (Signed S)) :
    Except Validation (List Key) :=
  if dss = [] then .error (.bogus .dnskeyMissing)
  else if supported P dss = [] then .error (.insecure (unsupportedWhy P dss))
  else match ko with
    | none => .error .indeterminate
    | some sk =>
      match sk.data with
      | .keys o ks =>
        if o ≠ apex then .error (.bogus .dnskeyMissing)
        else
          let a := anchored (S := S) apex (supported P dss) ks
          if a = [] then .error (.bogus .dnskeyMissing)
          else if sk.sigs.any (verifies P t apex a fun _ => some (.keys apex ks)) then .ok ks
          else .error (.bogus (failure t (sk.sigs.filter (usable P apex a))))
      | _ => .error (.bogus .dnskeyMissing)

/-- From a parent's trusted keys to the child's DS records: the DS RRset for the child, signed by the parent. -/
def dsStep (P : AlgorithmPolicy) (t : Nat) (papex : Name) (pkeys : List Key) (c : Name) (sd : Signed S) :
    Except Validation (List Ds) :=
  match sd.data with
  | .rrset s =>
    if s.owner ≠ c ∨ s.rtype ≠ 43 then .error (.bogus .dnskeyMissing)
    else if sd.sigs.any (verifies P t papex pkeys (exactCover s)) then .ok (dsOf s)
    else .error (.bogus (failure t (sd.sigs.filter (usable P papex pkeys))))
  | _ => .error (.bogus .dnskeyMissing)

/-- One step down the chain, from the zone at `papex` with trusted keys `pkeys` to link `l`. -/
def linkStep (P : AlgorithmPolicy) (t : Nat) (owner papex : Name) (pkeys : List Key) (l : Link S) :
    Except Validation (List Key) :=
  if !(strictly l.apex papex && under owner l.apex) then .error .indeterminate
  else match l.parent with
    | none => .error .indeterminate
    | some (.noDs ds) =>
      match noDsProof (S := S) P l.apex (verified P t papex pkeys ds) with
      | some why => .error (.insecure why)
      | none => .error (.bogus .nsecMissing)
    | some (.ds sd) =>
      match dsStep P t papex pkeys l.apex sd with
      | .ok dss => keyStep P t l.apex dss l.keys
      | .error v => .error v

/-- Where a walk down the chain ends: a zone with trusted keys, or a final result. -/
inductive Walk where
  | trusted (apex : Name) (keys : List Key)
  | stop (v : Validation)
deriving DecidableEq, Repr

def descend (P : AlgorithmPolicy) (t : Nat) (owner : Name) : Name → List Key → Chain S → Walk
  | apex, keys, [] => .trusted apex keys
  | apex, keys, l :: ls =>
    match linkStep P t owner apex keys l with
    | .ok ks => descend P t owner l.apex ks ls
    | .error v => .stop v

/-- Walks from the anchor for `owner` down the chain. No anchor at or above `owner` is Insecure; a chain that
does not start at the anchor is Indeterminate. -/
def walk (A : List Anchor) (P : AlgorithmPolicy) (t : Nat) (owner : Name) (C : Chain S) : Walk :=
  match anchorFor A owner with
  | none => .stop (.insecure .noAnchor)
  | some a =>
    match C with
    | [] => .stop .indeterminate
    | l :: ls =>
      if l.apex ≠ a.owner then .stop .indeterminate
      else match keyStep P t l.apex a.ds l.keys with
        | .ok ks => descend P t owner l.apex ks ls
        | .error v => .stop v

/-! ## Validation -/

/-- An RRset at the zone with trusted keys: Secure when an RRSIG over it verifies, and, for a wildcard
expansion, when the denial records prove no closer name exists. -/
def rrsetResult (P : AlgorithmPolicy) (t : Nat) (apex : Name) (keys : List Key) (set : RRset)
    (sigs : List (Rrsig S)) (ds : List (Signed S)) : Validation :=
  let ok := verifies P t apex keys (rrsetCover set)
  if sigs.any (fun r => ok r && !(r.hdr.labels < set.owner.length)) then .secure
  else if sigs.any (fun r => ok r && r.hdr.labels < set.owner.length &&
      wildcardProof (S := S) (verified P t apex keys ds) set.owner r.hdr.labels) then .secure
  else if sigs.any ok then .bogus .nsecMissing
  else .bogus (failure t (sigs.filter (usable P apex keys)))

/-- `validate_rrset`: anchors (`none` when the resolver has none), policy, time, chain, the RRset, its RRSIGs,
and the denial records of the answer. -/
def validateRrset (A : Option (List Anchor)) (P : AlgorithmPolicy) (t : Nat) (C : Chain S) (set : RRset)
    (sigs : List (Rrsig S)) (ds : List (Signed S)) : Validation :=
  match A with
  | none => .notPerformed
  | some A =>
    match walk A P t set.owner C with
    | .stop v => v
    | .trusted apex keys => rrsetResult P t apex keys set sigs ds

/-- `validate_denial`: a negative answer to `q` with RCODE `rc` and the denial records of its authority
section. -/
def validateDenial (A : Option (List Anchor)) (P : AlgorithmPolicy) (t : Nat) (C : Chain S) (q : Request)
    (rc : Rcode) (ds : List (Signed S)) : Validation :=
  match A with
  | none => .notPerformed
  | some A =>
    match walk A P t q.qname C with
    | .stop v => v
    | .trusted apex keys => denialResult (S := S) P q rc (verified P t apex keys ds)

/-! ## The canonical order -/

theorem before_irrefl (a : Name) : before a a = false := Name.labelsLt_irrefl _

theorem before_trans {a b c : Name} (h1 : before a b = true) (h2 : before b c = true) : before a c = true :=
  Name.labelsLt_trans _ _ _ h1 h2

theorem before_total (a b : Name) : before a b = true ∨ a = b ∨ before b a = true := by
  rcases Name.labelsLt_total a.reverse b.reverse with h | h | h
  · exact Or.inl h
  · exact Or.inr (Or.inl (List.reverse_inj.mp h))
  · exact Or.inr (Or.inr h)

theorem before_asymm {a b : Name} (h : before a b = true) : before b a = false := by
  cases h' : before b a
  · rfl
  · have := before_trans h h'; rw [before_irrefl] at this; cases this

theorem labelsLt_append (Q : List Label) (x : Label) (R : List Label) : Name.labelsLt Q (Q ++ x :: R) = true := by
  induction Q with
  | nil => rfl
  | cons a Q ih => simp [Name.labelsLt, Name.labelLt_irrefl, ih]

/-- A name sorts after its ancestors (RFC 4034 §6.1). -/
theorem under_before {p q : Name} (h : under p q = true) : p = q ∨ before q p = true := by
  obtain ⟨t, rfl⟩ := (under_iff p q).mp h
  cases ht : t.reverse with
  | nil => left; simp [List.reverse_eq_nil_iff.mp ht]
  | cons x R => right; unfold before; rw [List.reverse_append, ht]; exact labelsLt_append _ _ _

theorem prefix_between : ∀ (Q T N : List Label), Name.labelsLt Q N = true → Name.labelsLt N (Q ++ T) = true →
    Q <+: N
  | [], _, _, _, _ => List.nil_prefix
  | _ :: _, _, [], h1, _ => by simp [Name.labelsLt] at h1
  | a :: Q, T, b :: N, h1, h2 => by
    simp only [Name.labelsLt, Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, List.cons_append] at h1 h2
    rcases h1 with h1 | ⟨rfl, h1⟩
    · rcases h2 with h2 | ⟨rfl, _⟩
      · have := Name.labelLt_trans _ _ _ h1 h2; rw [Name.labelLt_irrefl] at this; cases this
      · rw [Name.labelLt_irrefl] at h1; cases h1
    · rcases h2 with h2 | ⟨_, h2⟩
      · rw [Name.labelLt_irrefl] at h2; cases h2
      · exact List.cons_prefix_cons.mpr ⟨rfl, prefix_between Q T N h1 h2⟩

/-- Names below `q` sort right after it: a name between `q` and a descendant of `q` is below `q` too. -/
theorem under_between {p q n : Name} (hp : under p q = true) (h1 : before q n = true) (h2 : before n p = true) :
    under n q = true := by
  obtain ⟨t, rfl⟩ := (under_iff p q).mp hp
  unfold before at h1 h2
  rw [List.reverse_append] at h2
  exact (under_iff n q).mpr (List.reverse_prefix.mp (prefix_between _ _ _ h1 h2))

/-! ## The anchor -/

theorem foldl_anchorStep (n : Name) : ∀ (A : List Anchor) (init : Option Anchor),
    (∀ a, A.foldl (anchorStep n) init = some a → init = some a ∨ (a ∈ A ∧ under n a.owner = true)) ∧
    (A.foldl (anchorStep n) init = none ↔ init = none ∧ ∀ a ∈ A, under n a.owner = false) := by
  intro A
  induction A with
  | nil => intro init; simp
  | cons b A ih =>
    intro init
    obtain ⟨h1, h2⟩ := ih (anchorStep n init b)
    simp only [List.foldl_cons]
    refine ⟨fun a ha => ?_, ?_⟩
    · rcases h1 a ha with h | h
      · unfold anchorStep at h
        by_cases hu : under n b.owner = true
        · simp only [hu, ↓reduceIte] at h
          cases init with
          | none => cases h; exact Or.inr ⟨List.mem_cons_self, hu⟩
          | some c =>
            simp only at h
            split at h
            · cases h; exact Or.inr ⟨List.mem_cons_self, hu⟩
            · exact Or.inl h
        · simp only [hu, Bool.false_eq_true, ↓reduceIte] at h; exact Or.inl h
      · exact Or.inr ⟨List.mem_cons_of_mem _ h.1, h.2⟩
    · rw [h2]
      unfold anchorStep
      by_cases hu : under n b.owner = true
      · simp only [hu, ↓reduceIte, List.mem_cons, forall_eq_or_imp]
        cases init with
        | none => simp
        | some c => simp only; split <;> simp
      · simp only [hu, Bool.false_eq_true, ↓reduceIte, List.mem_cons, forall_eq_or_imp]
        simp

theorem anchorFor_some {A : List Anchor} {n : Name} {a : Anchor} (h : anchorFor A n = some a) :
    a ∈ A ∧ under n a.owner = true := by
  rcases (foldl_anchorStep n A none).1 a h with h | h
  · cases h
  · exact h

theorem anchorFor_none {A : List Anchor} {n : Name} : anchorFor A n = none ↔ ∀ a ∈ A, under n a.owner = false := by
  rw [anchorFor, (foldl_anchorStep n A none).2]; simp

/-! ## What each step of the validator checks, as propositions -/

/-- The RRSIG `r` is usable, its window holds at `t`, and it verifies under one of `keys` over what `cover`
says it covers. -/
def SigBy (P : AlgorithmPolicy) (t : Nat) (apex : Name) (keys : List Key) (cover : Header → Option Payload)
    (r : Rrsig S) : Prop :=
  usable P apex keys r = true ∧ windowOk t r.hdr = true ∧
    ∃ d, cover r.hdr = some d ∧ ∃ k ∈ keys, k.alg = r.hdr.alg ∧ S.verify k.pub ⟨r.hdr, d⟩ r.sig = true

theorem verifies_iff {P : AlgorithmPolicy} {t : Nat} {apex : Name} {keys : List Key}
    {cover : Header → Option Payload} {r : Rrsig S} :
    verifies P t apex keys cover r = true ↔ SigBy P t apex keys cover r := by
  unfold verifies SigBy
  cases hc : cover r.hdr with
  | none => simp
  | some d => simp [List.any_eq_true, Bool.and_eq_true, beq_iff_eq, and_assoc]

theorem any_verifies_iff {P : AlgorithmPolicy} {t : Nat} {apex : Name} {keys : List Key}
    {cover : Header → Option Payload} {sigs : List (Rrsig S)} :
    sigs.any (verifies P t apex keys cover) = true ↔ ∃ r ∈ sigs, SigBy P t apex keys cover r := by
  simp only [List.any_eq_true, verifies_iff]

/-- The parent at `papex` with trusted keys `pkeys` signed the DS RRset for `c`, whose records are `dss`. -/
def DsSigned (P : AlgorithmPolicy) (t : Nat) (papex : Name) (pkeys : List Key) (c : Name) (sd : Signed S)
    (dss : List Ds) : Prop :=
  ∃ s, sd.data = .rrset s ∧ s.owner = c ∧ s.rtype = 43 ∧ dss = dsOf s ∧
    ∃ r ∈ sd.sigs, SigBy P t papex pkeys (exactCover s) r

/-- The DNSKEY set `ks` of the zone at `apex` was fetched, holds a SEP key that a supported DS record of
`dss` names, and that key signed it. -/
def KeysSigned (P : AlgorithmPolicy) (t : Nat) (apex : Name) (dss : List Ds) (ko : Option (Signed S))
    (ks : List Key) : Prop :=
  ∃ sk, ko = some sk ∧ sk.data = .keys apex ks ∧
    ∃ k ∈ ks, k.sep = true ∧
      (∃ d ∈ dss, P.treat d.keyAlg d.dtype = .supported ∧ d.keyAlg = k.alg ∧ d.digest = S.digest apex k) ∧
      ∃ r ∈ sk.sigs, SigBy P t apex [k] (fun _ => some (.keys apex ks)) r

/-- A DS set Insecure for its algorithms or digests: not empty, no record supported, and the reason
`unsupportedWhy` gives. -/
def UnsupportedDs (P : AlgorithmPolicy) (dss : List Ds) (why : Insecure) : Prop :=
  dss ≠ [] ∧ (∀ d ∈ dss, P.treat d.keyAlg d.dtype ≠ .supported) ∧ why = unsupportedWhy P dss

theorem supported_nil_iff {P : AlgorithmPolicy} {dss : List Ds} :
    supported P dss = [] ↔ ∀ d ∈ dss, P.treat d.keyAlg d.dtype ≠ .supported := by
  simp [supported, List.filter_eq_nil_iff]

theorem mem_supported {P : AlgorithmPolicy} {dss : List Ds} {d : Ds} :
    d ∈ supported P dss ↔ d ∈ dss ∧ P.treat d.keyAlg d.dtype = .supported := by
  simp [supported]

theorem mem_anchored {apex : Name} {sup : List Ds} {ks : List Key} {k : Key} :
    k ∈ anchored (S := S) apex sup ks ↔
      k ∈ ks ∧ k.sep = true ∧ ∃ d ∈ sup, d.keyAlg = k.alg ∧ d.digest = S.digest apex k := by
  simp [anchored, List.any_eq_true, Bool.and_eq_true, beq_iff_eq]

theorem dsStep_ok {P : AlgorithmPolicy} {t : Nat} {papex : Name} {pkeys : List Key} {c : Name} {sd : Signed S}
    {dss : List Ds} : dsStep P t papex pkeys c sd = .ok dss ↔ DsSigned P t papex pkeys c sd dss := by
  unfold dsStep DsSigned
  cases hd : sd.data with
  | rrset s =>
    simp only [Payload.rrset.injEq, exists_eq_left']
    by_cases hc : s.owner ≠ c ∨ s.rtype ≠ 43
    · simp only [hc, ↓reduceIte, reduceCtorEq, false_iff, not_and]
      intro h1 h2; exact absurd (Or.elim hc (· h1) (· h2)) id
    · simp only [hc, ↓reduceIte]
      have hc' : s.owner = c ∧ s.rtype = 43 := by simpa [not_or] using hc
      by_cases hv : sd.sigs.any (verifies P t papex pkeys (exactCover s)) = true
      · simp only [hv, ↓reduceIte, Except.ok.injEq]
        rw [any_verifies_iff] at hv
        constructor
        · rintro rfl; exact ⟨hc'.1, hc'.2, rfl, hv⟩
        · rintro ⟨_, _, rfl, _⟩; rfl
      · simp only [hv, Bool.false_eq_true, ↓reduceIte, reduceCtorEq, false_iff, not_and]
        rw [any_verifies_iff] at hv
        intro _ _ _ h; exact hv h
  | keys _ _ => simp
  | nsec _ => simp
  | nsec3 _ => simp

theorem dsStep_error_ne_secure {P : AlgorithmPolicy} {t : Nat} {papex : Name} {pkeys : List Key} {c : Name}
    {sd : Signed S} {v : Validation} (h : dsStep P t papex pkeys c sd = .error v) :
    ∃ e, v = .bogus e := by
  unfold dsStep at h
  split at h
  · split at h
    · cases h; exact ⟨_, rfl⟩
    · split at h
      · cases h
      · cases h; exact ⟨_, rfl⟩
  · cases h; exact ⟨_, rfl⟩

theorem keyStep_ok {P : AlgorithmPolicy} {t : Nat} {apex : Name} {dss : List Ds} {ko : Option (Signed S)}
    {ks : List Key} : keyStep P t apex dss ko = .ok ks ↔ KeysSigned P t apex dss ko ks := by
  constructor
  · intro h
    unfold keyStep at h
    split at h; · cases h
    split at h; · cases h
    rename_i _ hsup
    cases ko with
    | none => cases h
    | some sk =>
      simp only at h
      split at h
      · rename_i o ks' hdata
        split at h; · cases h
        rename_i ho
        simp only [Decidable.not_not] at ho
        subst ho
        split at h; · cases h
        split at h
        · rename_i hv
          cases h
          obtain ⟨r, hr, hu, hw, d, hcov, k, hk, hka, hver⟩ := any_verifies_iff.mp hv
          obtain ⟨hk1, hk2, d', hd', hd1, hd2⟩ := mem_anchored.mp hk
          obtain ⟨hd'1, hd'2⟩ := mem_supported.mp hd'
          refine ⟨sk, rfl, hdata, k, hk1, hk2, ⟨d', hd'1, hd'2, hd1, hd2⟩, r, hr, ?_, hw, d, hcov, k,
            List.mem_singleton_self _, hka, hver⟩
          simp only [usable, Bool.and_eq_true, beq_iff_eq, List.any_cons, List.any_nil, Bool.or_false] at hu ⊢
          exact ⟨hu.1, hka⟩
        · cases h
      · cases h
  · rintro ⟨sk, rfl, hdata, k, hk, hsep, ⟨d, hd, hdt, hda, hdd⟩, r, hr, hu, hw, d', hcov, k', hk', hka, hver⟩
    have hkk : k' = k := List.mem_singleton.mp hk'
    rw [hkk] at hka hver
    have hne : dss ≠ [] := List.ne_nil_of_mem hd
    have hsup : supported P dss ≠ [] := List.ne_nil_of_mem (mem_supported.mpr ⟨hd, hdt⟩)
    have hka' : k ∈ anchored (S := S) apex (supported P dss) ks :=
      mem_anchored.mpr ⟨hk, hsep, d, mem_supported.mpr ⟨hd, hdt⟩, hda, hdd⟩
    have hna : anchored (S := S) apex (supported P dss) ks ≠ [] := List.ne_nil_of_mem hka'
    have hv : sk.sigs.any (verifies P t apex (anchored (S := S) apex (supported P dss) ks)
        fun _ => some (.keys apex ks)) = true := by
      refine any_verifies_iff.mpr ⟨r, hr, ?_, hw, d', hcov, k, hka', hka, hver⟩
      simp only [usable, Bool.and_eq_true, beq_iff_eq, List.any_eq_true] at hu ⊢
      exact ⟨hu.1, k, hka', by simpa using hka⟩
    unfold keyStep
    simp only [hne, hsup, ↓reduceIte, hdata, ne_eq, not_true_eq_false, hna, hv]

theorem keyStep_insecure {P : AlgorithmPolicy} {t : Nat} {apex : Name} {dss : List Ds} {ko : Option (Signed S)}
    {why : Insecure} : keyStep P t apex dss ko = .error (.insecure why) ↔ UnsupportedDs P dss why := by
  unfold keyStep UnsupportedDs
  by_cases h0 : dss = []
  · simp [h0]
  · simp only [h0, ↓reduceIte, ne_eq, not_false_eq_true, true_and]
    by_cases h1 : supported P dss = []
    · simp only [h1, ↓reduceIte, Except.error.injEq, Validation.insecure.injEq]
      rw [supported_nil_iff] at h1
      exact ⟨fun h => ⟨h1, h.symm⟩, fun h => h.2.symm⟩
    · simp only [h1, ↓reduceIte]
      have : ¬ ∀ d ∈ dss, P.treat d.keyAlg d.dtype ≠ .supported := fun h => h1 (supported_nil_iff.mpr h)
      simp only [this, false_and, iff_false]
      cases ko with
      | none => simp
      | some sk =>
        simp only
        split
        · split; · simp
          split; · simp
          split <;> simp
        · simp

theorem keyStep_error_ne_secure {P : AlgorithmPolicy} {t : Nat} {apex : Name} {dss : List Ds}
    {ko : Option (Signed S)} {v : Validation} (h : keyStep P t apex dss ko = .error v) : v ≠ .secure := by
  intro hv; subst hv
  unfold keyStep at h
  split at h; · cases h
  split at h; · cases h
  cases ko with
  | none => cases h
  | some sk =>
    simp only at h
    split at h
    · split at h; · cases h
      split at h; · cases h
      split at h <;> cases h
    · cases h

/-- One link of the chain is trusted: it lies strictly below its parent and at or above the name, the parent
signed its DS set, and a key that set names signed its DNSKEY set `ks`. -/
def LinkOk (P : AlgorithmPolicy) (t : Nat) (owner papex : Name) (pkeys : List Key) (l : Link S) (ks : List Key) :
    Prop :=
  strictly l.apex papex = true ∧ under owner l.apex = true ∧
    ∃ sd dss, l.parent = some (.ds sd) ∧ DsSigned P t papex pkeys l.apex sd dss ∧ KeysSigned P t l.apex dss l.keys ks

/-- What a no-DS answer must hold for each reason, among the verified denial records `ps` for the cut `c`. -/
def NoDsEvidence (P : AlgorithmPolicy) (c : Name) (ps : List Payload) : Insecure → Prop
  | .provenNoDs =>
    (∃ r ∈ nsecs ps, r.owner = c ∧ insecureCut r.types = true) ∨
      (∃ r ∈ nsec3s ps, r.hash = S.hash c ∧ insecureCut r.types = true)
  | .nsec3Iterations => ∃ r ∈ nsec3s ps, P.maxIterations < r.iterations
  | .optOutCovered =>
    ∃ ce, closest3 (S := S) (nsec3s ps) c = some ce ∧
      ∃ r ∈ nsec3s ps, covers3 r.hash r.next (S.hash (nextCloser c ce)) = true ∧ r.optOut = true
  | _ => False

theorem noDsProof_some {P : AlgorithmPolicy} {c : Name} {ps : List Payload} {why : Insecure}
    (h : noDsProof (S := S) P c ps = some why) : NoDsEvidence (S := S) P c ps why := by
  unfold noDsProof at h
  split at h
  · rename_i h1; cases h
    obtain ⟨r, hr, hr'⟩ := List.any_eq_true.mp h1
    simp only [Bool.and_eq_true, beq_iff_eq] at hr'
    exact Or.inl ⟨r, hr, hr'⟩
  split at h
  · rename_i h2; cases h
    obtain ⟨r, hr, hr'⟩ := List.any_eq_true.mp h2
    exact ⟨r, hr, by simpa using hr'⟩
  split at h
  · rename_i h3; cases h
    obtain ⟨r, hr, hr'⟩ := List.any_eq_true.mp h3
    simp only [Bool.and_eq_true, beq_iff_eq] at hr'
    exact Or.inr ⟨r, hr, hr'⟩
  split at h
  · rename_i h4; cases h
    unfold optOut3 at h4
    split at h4
    · rename_i ce hce
      obtain ⟨r, hr, hr'⟩ := List.any_eq_true.mp h4
      simp only [Bool.and_eq_true, beq_iff_eq] at hr'
      exact ⟨ce, hce, r, hr, hr'⟩
    · cases h4
  · cases h

theorem noDsProof_of_evidence {P : AlgorithmPolicy} {c : Name} {ps : List Payload} {why : Insecure}
    (h : NoDsEvidence (S := S) P c ps why) : ∃ w, noDsProof (S := S) P c ps = some w := by
  unfold noDsProof
  split; · exact ⟨_, rfl⟩
  rename_i h1
  split; · exact ⟨_, rfl⟩
  rename_i h2
  split; · exact ⟨_, rfl⟩
  rename_i h3
  split; · exact ⟨_, rfl⟩
  rename_i h4
  exfalso
  cases why with
  | provenNoDs =>
    rcases h with ⟨r, hr, h1', h2'⟩ | ⟨r, hr, h1', h2'⟩
    · exact h1 (List.any_eq_true.mpr ⟨r, hr, by simp [h1', h2']⟩)
    · exact h3 (List.any_eq_true.mpr ⟨r, hr, by simp [h1', h2']⟩)
  | nsec3Iterations =>
    obtain ⟨r, hr, h'⟩ := h
    exact h2 (List.any_eq_true.mpr ⟨r, hr, by simpa using h'⟩)
  | optOutCovered =>
    obtain ⟨ce, hce, r, hr, h1', h2'⟩ := h
    apply h4
    unfold optOut3
    rw [hce]
    exact List.any_eq_true.mpr ⟨r, hr, by simp [h1', h2']⟩
  | noAnchor => exact h
  | unsupportedAlgorithm => exact h
  | unsupportedDigest => exact h

/-- One link of the chain is Insecure: it lies strictly below its parent and at or above the name, and the
parent proved it has no DS, or signed a DS set the policy does not support. -/
def LinkInsecure (P : AlgorithmPolicy) (t : Nat) (owner papex : Name) (pkeys : List Key) (l : Link S)
    (why : Insecure) : Prop :=
  strictly l.apex papex = true ∧ under owner l.apex = true ∧
    ((∃ ds, l.parent = some (.noDs ds) ∧ NoDsEvidence (S := S) P l.apex (verified P t papex pkeys ds) why) ∨
      (∃ sd dss, l.parent = some (.ds sd) ∧ DsSigned P t papex pkeys l.apex sd dss ∧ UnsupportedDs P dss why))

theorem linkStep_ok {P : AlgorithmPolicy} {t : Nat} {owner papex : Name} {pkeys : List Key} {l : Link S}
    {ks : List Key} : linkStep P t owner papex pkeys l = .ok ks ↔ LinkOk P t owner papex pkeys l ks := by
  unfold linkStep LinkOk
  by_cases hp : (strictly l.apex papex && under owner l.apex) = true
  · simp only [hp, Bool.not_true, Bool.false_eq_true, ↓reduceIte]
    simp only [Bool.and_eq_true] at hp
    simp only [hp, true_and]
    cases hl : l.parent with
    | none => simp
    | some dl =>
      cases dl with
      | noDs ds => simp only; split <;> simp
      | ds sd =>
        simp only [Option.some.injEq, Delegation.ds.injEq, exists_and_left, exists_eq_left']
        cases hs : dsStep P t papex pkeys l.apex sd with
        | error v =>
          simp only [reduceCtorEq, false_iff, not_exists, not_and]
          intro dss hd; rw [← dsStep_ok, hs] at hd; cases hd
        | ok dss =>
          simp only
          rw [keyStep_ok]
          constructor
          · intro h; exact ⟨dss, dsStep_ok.mp hs, h⟩
          · rintro ⟨dss', hd, hk⟩
            rw [← dsStep_ok, hs] at hd; cases hd; exact hk
  · simp only [hp, Bool.not_false, ↓reduceIte, reduceCtorEq, false_iff, not_and]
    simp only [Bool.and_eq_true, not_and] at hp
    intro h1 h2; exact absurd h2 (hp h1)

theorem linkStep_insecure {P : AlgorithmPolicy} {t : Nat} {owner papex : Name} {pkeys : List Key} {l : Link S}
    {why : Insecure} (h : linkStep P t owner papex pkeys l = .error (.insecure why)) :
    LinkInsecure P t owner papex pkeys l why := by
  unfold linkStep at h
  by_cases hp : (strictly l.apex papex && under owner l.apex) = true
  · simp only [hp, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at h
    simp only [Bool.and_eq_true] at hp
    refine ⟨hp.1, hp.2, ?_⟩
    cases hl : l.parent with
    | none => rw [hl] at h; cases h
    | some dl =>
      rw [hl] at h
      cases dl with
      | noDs ds =>
        simp only at h
        split at h
        · rename_i w hw; cases h; exact Or.inl ⟨ds, rfl, noDsProof_some hw⟩
        · cases h
      | ds sd =>
        simp only at h
        split at h
        · rename_i dss hs
          exact Or.inr ⟨sd, dss, rfl, dsStep_ok.mp hs, keyStep_insecure.mp h⟩
        · rename_i v hs
          cases h
          obtain ⟨e, he⟩ := dsStep_error_ne_secure hs; cases he
  · simp only [hp, Bool.not_false, ↓reduceIte] at h; cases h

theorem linkStep_of_insecure {P : AlgorithmPolicy} {t : Nat} {owner papex : Name} {pkeys : List Key}
    {l : Link S} {why : Insecure} (h : LinkInsecure P t owner papex pkeys l why) :
    ∃ w, linkStep P t owner papex pkeys l = .error (.insecure w) := by
  obtain ⟨h1, h2, h3⟩ := h
  unfold linkStep
  simp only [h1, h2, Bool.and_self, Bool.not_true, Bool.false_eq_true, ↓reduceIte]
  rcases h3 with ⟨ds, hl, he⟩ | ⟨sd, dss, hl, hd, hu⟩
  · rw [hl]
    obtain ⟨w, hw⟩ := noDsProof_of_evidence he
    simp only [hw]; exact ⟨w, rfl⟩
  · rw [hl]; simp only
    rw [dsStep_ok.mpr hd]
    exact ⟨why, keyStep_insecure.mpr hu⟩

theorem linkStep_error_ne_secure {P : AlgorithmPolicy} {t : Nat} {owner papex : Name} {pkeys : List Key}
    {l : Link S} {v : Validation} (h : linkStep P t owner papex pkeys l = .error v) : v ≠ .secure := by
  intro hv; subst hv
  unfold linkStep at h
  split at h; · cases h
  split at h
  · cases h
  · split at h <;> cases h
  · split at h
    · exact keyStep_error_ne_secure h rfl
    · rename_i hs; cases h; obtain ⟨e, he⟩ := dsStep_error_ne_secure hs; cases he

/-! ## The walk down the chain, as propositions -/

/-- The chain authenticates the keys `keys'` of the zone at `apex'`, link by link, starting from the zone at
`apex` whose keys `keys` are trusted. -/
inductive Reaches (P : AlgorithmPolicy) (t : Nat) (owner : Name) : Name → List Key → Chain S → Name → List Key → Prop
  | nil {apex : Name} {keys : List Key} : Reaches P t owner apex keys [] apex keys
  | cons {apex : Name} {keys : List Key} {l : Link S} {ls : Chain S} {ks : List Key} {apex' : Name}
      {keys' : List Key} :
      LinkOk P t owner apex keys l ks → Reaches P t owner l.apex ks ls apex' keys' →
      Reaches P t owner apex keys (l :: ls) apex' keys'

/-- The walk from the zone at `apex` with keys `keys` stops Insecure for the reason `why` at some link. -/
inductive StopsInsecure (P : AlgorithmPolicy) (t : Nat) (owner : Name) : Name → List Key → Chain S → Insecure → Prop
  | here {apex : Name} {keys : List Key} {l : Link S} {ls : Chain S} {why : Insecure} :
      LinkInsecure P t owner apex keys l why → StopsInsecure P t owner apex keys (l :: ls) why
  | next {apex : Name} {keys : List Key} {l : Link S} {ls : Chain S} {ks : List Key} {why : Insecure} :
      LinkOk P t owner apex keys l ks → StopsInsecure P t owner l.apex ks ls why →
      StopsInsecure P t owner apex keys (l :: ls) why

theorem descend_trusted {P : AlgorithmPolicy} {t : Nat} {owner : Name} :
    ∀ (C : Chain S) (apex : Name) (keys : List Key) (apex' : Name) (keys' : List Key),
      descend P t owner apex keys C = .trusted apex' keys' ↔ Reaches P t owner apex keys C apex' keys' := by
  intro C
  induction C with
  | nil =>
    intro apex keys apex' keys'
    simp only [descend, Walk.trusted.injEq]
    constructor
    · rintro ⟨rfl, rfl⟩; exact .nil
    · intro h; cases h; exact ⟨rfl, rfl⟩
  | cons l ls ih =>
    intro apex keys apex' keys'
    simp only [descend]
    constructor
    · intro h
      split at h
      · rename_i ks hs; exact .cons (linkStep_ok.mp hs) ((ih _ _ _ _).mp h)
      · cases h
    · intro h
      cases h with
      | cons hl hr =>
        rw [linkStep_ok.mpr hl]; exact (ih _ _ _ _).mpr hr

theorem descend_insecure {P : AlgorithmPolicy} {t : Nat} {owner : Name} :
    ∀ (C : Chain S) (apex : Name) (keys : List Key) (why : Insecure),
      descend P t owner apex keys C = .stop (.insecure why) → StopsInsecure P t owner apex keys C why := by
  intro C
  induction C with
  | nil => intro _ _ _ h; cases h
  | cons l ls ih =>
    intro apex keys why h
    simp only [descend] at h
    split at h
    · rename_i ks hs; exact .next (linkStep_ok.mp hs) (ih _ _ _ h)
    · rename_i v hs; cases h; exact .here (linkStep_insecure hs)

theorem descend_of_stops {P : AlgorithmPolicy} {t : Nat} {owner : Name} {C : Chain S} {apex : Name}
    {keys : List Key} {why : Insecure} (h : StopsInsecure P t owner apex keys C why) :
    ∃ w, descend P t owner apex keys C = .stop (.insecure w) := by
  induction h with
  | here hl =>
    obtain ⟨w, hw⟩ := linkStep_of_insecure hl
    exact ⟨w, by simp [descend, hw]⟩
  | next hl _ ih =>
    obtain ⟨w, hw⟩ := ih
    exact ⟨w, by simp [descend, linkStep_ok.mpr hl, hw]⟩

theorem descend_stop_ne_secure {P : AlgorithmPolicy} {t : Nat} {owner : Name} :
    ∀ (C : Chain S) (apex : Name) (keys : List Key) (v : Validation),
      descend P t owner apex keys C = .stop v → v ≠ .secure := by
  intro C
  induction C with
  | nil => intro _ _ _ h; cases h
  | cons l ls ih =>
    intro apex keys v h
    simp only [descend] at h
    split at h
    · exact ih _ _ _ h
    · rename_i v' hs; cases h; exact linkStep_error_ne_secure hs

/-- The first link is the anchored zone, and a key the anchor's DS names signed its DNSKEY set `ks0`. -/
def Anchored (A : List Anchor) (P : AlgorithmPolicy) (t : Nat) (owner : Name) (C : Chain S) (l0 : Link S)
    (ls0 : Chain S) (ks0 : List Key) : Prop :=
  ∃ a, anchorFor A owner = some a ∧ C = l0 :: ls0 ∧ l0.apex = a.owner ∧ KeysSigned P t l0.apex a.ds l0.keys ks0

theorem walk_trusted {A : List Anchor} {P : AlgorithmPolicy} {t : Nat} {owner : Name} {C : Chain S}
    {apex : Name} {keys : List Key} :
    walk A P t owner C = .trusted apex keys ↔
      ∃ l0 ls0 ks0, Anchored A P t owner C l0 ls0 ks0 ∧ Reaches P t owner l0.apex ks0 ls0 apex keys := by
  constructor
  · intro h
    unfold walk at h
    cases ha : anchorFor A owner with
    | none => rw [ha] at h; cases h
    | some a =>
      rw [ha] at h
      cases C with
      | nil => cases h
      | cons l ls =>
        simp only at h
        split at h
        · cases h
        · rename_i hl
          simp only [Decidable.not_not] at hl
          split at h
          · rename_i ks hk
            refine ⟨l, ls, ks, ⟨a, ha, rfl, hl, ?_⟩, ?_⟩
            · exact keyStep_ok.mp hk
            · exact (descend_trusted _ _ _ _ _).mp h
          · cases h
  · rintro ⟨l0, ls0, ks0, ⟨a, ha, rfl, hl, hk⟩, hr⟩
    unfold walk
    rw [ha]
    simp only [hl, ne_eq, not_true_eq_false, ↓reduceIte]
    rw [hl] at hk
    rw [keyStep_ok.mpr hk]
    rw [hl] at hr
    exact (descend_trusted _ _ _ _ _).mpr hr

/-- Why a walk is Insecure: no anchor; the anchor's DS set unsupported; or a link further down. -/
def InsecureCase (A : List Anchor) (P : AlgorithmPolicy) (t : Nat) (owner : Name) (C : Chain S) (why : Insecure) :
    Prop :=
  (anchorFor A owner = none ∧ why = .noAnchor) ∨
    ∃ a l0 ls0, anchorFor A owner = some a ∧ C = l0 :: ls0 ∧ l0.apex = a.owner ∧
      (UnsupportedDs P a.ds why ∨
        ∃ ks0, KeysSigned P t l0.apex a.ds l0.keys ks0 ∧ StopsInsecure P t owner l0.apex ks0 ls0 why)

theorem walk_insecure {A : List Anchor} {P : AlgorithmPolicy} {t : Nat} {owner : Name} {C : Chain S}
    {why : Insecure} (h : walk A P t owner C = .stop (.insecure why)) : InsecureCase A P t owner C why := by
  unfold walk at h
  cases ha : anchorFor A owner with
  | none => rw [ha] at h; cases h; exact Or.inl ⟨ha, rfl⟩
  | some a =>
    rw [ha] at h
    cases C with
    | nil => cases h
    | cons l ls =>
      simp only at h
      split at h
      · cases h
      · rename_i hl
        simp only [Decidable.not_not] at hl
        refine Or.inr ⟨a, l, ls, ha, rfl, hl, ?_⟩
        split at h
        · rename_i ks hk
          exact Or.inr ⟨ks, keyStep_ok.mp hk, descend_insecure _ _ _ _ h⟩
        · rename_i v hk; cases h; exact Or.inl (keyStep_insecure.mp hk)

theorem walk_of_insecure {A : List Anchor} {P : AlgorithmPolicy} {t : Nat} {owner : Name} {C : Chain S}
    {why : Insecure} (h : InsecureCase A P t owner C why) : ∃ w, walk A P t owner C = .stop (.insecure w) := by
  unfold walk
  rcases h with ⟨ha, _⟩ | ⟨a, l, ls, ha, rfl, hl, h⟩
  · rw [ha]; exact ⟨_, rfl⟩
  · rw [ha]
    simp only [hl, ne_eq, not_true_eq_false, ↓reduceIte]
    rcases h with hu | ⟨ks, hk, hs⟩
    · rw [keyStep_insecure.mpr hu]; exact ⟨why, rfl⟩
    · rw [← hl, keyStep_ok.mpr hk]; exact descend_of_stops hs

theorem walk_stop_ne_secure {A : List Anchor} {P : AlgorithmPolicy} {t : Nat} {owner : Name} {C : Chain S}
    {v : Validation} (h : walk A P t owner C = .stop v) : v ≠ .secure := by
  unfold walk at h
  split at h
  · cases h; simp
  · split at h
    · cases h; simp
    · split at h
      · cases h; simp
      · split at h
        · exact descend_stop_ne_secure _ _ _ _ h
        · rename_i hk; cases h; exact keyStep_error_ne_secure hk

/-! ## Secure and Insecure, exactly -/

/-- The RRset's own check at the zone with trusted keys: an RRSIG over it verifies, and a wildcard expansion
comes with the proof that no closer name exists. -/
def FinalSigned (P : AlgorithmPolicy) (t : Nat) (apex : Name) (keys : List Key) (set : RRset)
    (sigs : List (Rrsig S)) (ds : List (Signed S)) : Prop :=
  (∃ r ∈ sigs, SigBy P t apex keys (rrsetCover set) r ∧ ¬ r.hdr.labels < set.owner.length) ∨
    ∃ r ∈ sigs, SigBy P t apex keys (rrsetCover set) r ∧ r.hdr.labels < set.owner.length ∧
      wildcardProof (S := S) (verified P t apex keys ds) set.owner r.hdr.labels = true

theorem rrsetResult_secure {P : AlgorithmPolicy} {t : Nat} {apex : Name} {keys : List Key} {set : RRset}
    {sigs : List (Rrsig S)} {ds : List (Signed S)} :
    rrsetResult P t apex keys set sigs ds = .secure ↔ FinalSigned P t apex keys set sigs ds := by
  unfold rrsetResult FinalSigned
  simp only
  by_cases h1 : (sigs.any fun r => verifies P t apex keys (rrsetCover set) r &&
      !decide (r.hdr.labels < set.owner.length)) = true
  · simp only [h1, ↓reduceIte, true_iff]
    obtain ⟨r, hr, h⟩ := List.any_eq_true.mp h1
    simp only [Bool.and_eq_true, Bool.not_eq_true', decide_eq_false_iff_not] at h
    exact Or.inl ⟨r, hr, verifies_iff.mp h.1, h.2⟩
  · simp only [h1, Bool.false_eq_true, ↓reduceIte]
    have n1 : ¬ ∃ r ∈ sigs, SigBy P t apex keys (rrsetCover set) r ∧ ¬ r.hdr.labels < set.owner.length := by
      rintro ⟨r, hr, h, h'⟩
      exact h1 (List.any_eq_true.mpr ⟨r, hr, by simp [verifies_iff.mpr h, h']⟩)
    simp only [n1, false_or]
    by_cases h2 : (sigs.any fun r => verifies P t apex keys (rrsetCover set) r &&
        decide (r.hdr.labels < set.owner.length) &&
        wildcardProof (S := S) (verified P t apex keys ds) set.owner r.hdr.labels) = true
    · simp only [h2, ↓reduceIte, true_iff]
      obtain ⟨r, hr, h⟩ := List.any_eq_true.mp h2
      simp only [Bool.and_eq_true, decide_eq_true_eq] at h
      exact ⟨r, hr, verifies_iff.mp h.1.1, h.1.2, h.2⟩
    · simp only [h2, Bool.false_eq_true, ↓reduceIte]
      have n2 : ¬ ∃ r ∈ sigs, SigBy P t apex keys (rrsetCover set) r ∧ r.hdr.labels < set.owner.length ∧
          wildcardProof (S := S) (verified P t apex keys ds) set.owner r.hdr.labels = true := by
        rintro ⟨r, hr, h, h', h''⟩
        exact h2 (List.any_eq_true.mpr ⟨r, hr, by simp [verifies_iff.mpr h, h', h'']⟩)
      simp only [n2, iff_false]
      split <;> simp

theorem rrsetResult_ne_insecure {P : AlgorithmPolicy} {t : Nat} {apex : Name} {keys : List Key} {set : RRset}
    {sigs : List (Rrsig S)} {ds : List (Signed S)} {why : Insecure} :
    rrsetResult P t apex keys set sigs ds ≠ .insecure why := by
  unfold rrsetResult
  simp only
  split; · simp
  split; · simp
  split <;> simp

/-- A properly signed chain for `set`: the anchored zone's DNSKEY set signed by a key the anchor names, each
link below signed by the one above, and an RRSIG over `set` by the last zone's keys. -/
def SecureChain (A : List Anchor) (P : AlgorithmPolicy) (t : Nat) (C : Chain S) (set : RRset)
    (sigs : List (Rrsig S)) (ds : List (Signed S)) : Prop :=
  ∃ l0 ls0 ks0 apex keys, Anchored A P t set.owner C l0 ls0 ks0 ∧ Reaches P t set.owner l0.apex ks0 ls0 apex keys ∧
    FinalSigned P t apex keys set sigs ds

theorem secure_iff {A : List Anchor} {P : AlgorithmPolicy} {t : Nat} {C : Chain S} {set : RRset}
    {sigs : List (Rrsig S)} {ds : List (Signed S)} :
    validateRrset (some A) P t C set sigs ds = .secure ↔ SecureChain A P t C set sigs ds := by
  unfold validateRrset SecureChain
  simp only
  constructor
  · intro h
    split at h
    · rename_i v hw; subst h; exact absurd rfl (walk_stop_ne_secure hw)
    · rename_i apex keys hw
      obtain ⟨l0, ls0, ks0, ha, hr⟩ := walk_trusted.mp hw
      exact ⟨l0, ls0, ks0, apex, keys, ha, hr, rrsetResult_secure.mp h⟩
  · rintro ⟨l0, ls0, ks0, apex, keys, ha, hr, hf⟩
    rw [walk_trusted.mpr ⟨l0, ls0, ks0, ha, hr⟩]
    exact rrsetResult_secure.mpr hf

/-- Every properly signed chain validates Secure. -/
theorem secure_complete {A : List Anchor} {P : AlgorithmPolicy} {t : Nat} {C : Chain S} {set : RRset}
    {sigs : List (Rrsig S)} {ds : List (Signed S)} (h : SecureChain A P t C set sigs ds) :
    validateRrset (some A) P t C set sigs ds = .secure :=
  secure_iff.mpr h

/-- Insecure needs a proof: no anchor at or above the name, or a link reached through a secure chain whose
parent proved it has no DS, or whose DS set the policy does not support. A missing record never makes an
answer Insecure. -/
theorem insecure_needs_proof {A : List Anchor} {P : AlgorithmPolicy} {t : Nat} {C : Chain S} {set : RRset}
    {sigs : List (Rrsig S)} {ds : List (Signed S)} {why : Insecure}
    (h : validateRrset (some A) P t C set sigs ds = .insecure why) : InsecureCase A P t set.owner C why := by
  unfold validateRrset at h
  simp only at h
  split at h
  · rename_i v hw; subst h; exact walk_insecure hw
  · exact absurd h rrsetResult_ne_insecure

/-- And every such proof makes the answer Insecure. -/
theorem insecure_complete {A : List Anchor} {P : AlgorithmPolicy} {t : Nat} {C : Chain S} {set : RRset}
    {sigs : List (Rrsig S)} {ds : List (Signed S)} {why : Insecure} (h : InsecureCase A P t set.owner C why) :
    ∃ w, validateRrset (some A) P t C set sigs ds = .insecure w := by
  obtain ⟨w, hw⟩ := walk_of_insecure h
  exact ⟨w, by simp [validateRrset, hw]⟩

/-! ## Authenticity -/

/-- `Vouched A C z k`: the key `k` of the zone at `z` is vouched for, starting from an anchor, by signatures
in the chain `C`, each made with the private key of a key already vouched for. It is the anchored key, a
member of a DNSKEY set that a vouched key's holder signed, or named by a DS set for `z` that the holder of a
vouched key of the parent signed. -/
inductive Vouched (A : List Anchor) (C : Chain S) : Name → Key → Prop
  | anchor {a : Anchor} {d : Ds} {k : Key} :
      a ∈ A → d ∈ a.ds → d.digest = S.digest a.owner k → Vouched A C a.owner k
  | keyset {z : Name} {k : Key} {p : S.Priv} {l : Link S} {sk : Signed S} {ks : List Key} {r : Rrsig S} {k' : Key} :
      Vouched A C z k → l ∈ C → l.apex = z → l.keys = some sk → sk.data = .keys z ks → r ∈ sk.sigs →
      S.pub p = k.pub → r.sig = S.sign p ⟨r.hdr, .keys z ks⟩ → k' ∈ ks → Vouched A C z k'
  | delegation {z : Name} {k : Key} {p : S.Priv} {l : Link S} {sd : Signed S} {s : RRset} {r : Rrsig S} {d : Ds}
      {k' : Key} :
      Vouched A C z k → l ∈ C → l.parent = some (.ds sd) → sd.data = .rrset s → s.owner = l.apex →
      r ∈ sd.sigs → r.hdr.signer = z → S.pub p = k.pub →
      r.sig = S.sign p ⟨r.hdr, .rrset { s with ttl := r.hdr.ttl }⟩ →
      d ∈ dsOf s → d.digest = S.digest l.apex k' → Vouched A C l.apex k'

theorem keys_vouched {A : List Anchor} {C : Chain S} {P : AlgorithmPolicy} {t : Nat} {l : Link S} {dss : List Ds}
    {ks : List Key} (hk : KeysSigned P t l.apex dss l.keys ks) (hl : l ∈ C)
    (hd : ∀ d ∈ dss, ∀ k, d.digest = S.digest l.apex k → Vouched A C l.apex k) :
    ∀ k' ∈ ks, Vouched A C l.apex k' := by
  obtain ⟨sk, hsk, hdata, k, _, _, ⟨d, hdm, _, _, hdd⟩, r, hr, _, _, d', hcov, k'', hk'', _, hver⟩ := hk
  have hkk : k'' = k := List.mem_singleton.mp hk''
  rw [hkk] at hver
  simp only [Option.some.injEq] at hcov; subst hcov
  obtain ⟨p, hp, hsig⟩ := S.verify_sound _ _ _ hver
  intro k' hk'
  exact .keyset (hd d hdm k hdd) hl rfl hsk hdata hr hp hsig hk'

theorem reaches_vouched {A : List Anchor} {C : Chain S} {P : AlgorithmPolicy} {t : Nat} {owner : Name}
    {apex : Name} {keys : List Key} {ls : Chain S} {apex' : Name} {keys' : List Key}
    (h : Reaches P t owner apex keys ls apex' keys') (hsub : ∀ l ∈ ls, l ∈ C)
    (hv : ∀ k ∈ keys, Vouched A C apex k) : (∀ k ∈ keys', Vouched A C apex' k) ∧
      (under owner apex = true → under owner apex' = true) := by
  induction h with
  | nil => exact ⟨hv, id⟩
  | @cons apex keys l ls ks apex' keys' hl _ ih =>
    obtain ⟨_, hu, sd, dss, hpar, ⟨s, hdata, hown, _, rfl, r, hr, husable, _, d, hcov, kp, hkp, _, hver⟩, hks⟩ := hl
    have hlC : l ∈ C := hsub l List.mem_cons_self
    have hd : ∀ d ∈ dsOf s, ∀ k, d.digest = S.digest l.apex k → Vouched A C l.apex k := by
      intro d' hd' k hdig
      unfold exactCover at hcov
      split at hcov
      · simp only [Option.some.injEq] at hcov; subst hcov
        obtain ⟨p, hp, hsig⟩ := S.verify_sound _ _ _ hver
        simp only [usable, Bool.and_eq_true, beq_iff_eq] at husable
        exact .delegation (hv kp hkp) hlC hpar hdata hown hr husable.1.1 hp hsig hd' hdig
      · cases hcov
    have := keys_vouched hks hlC hd
    obtain ⟨h1, _⟩ := ih (fun l' hl' => hsub l' (List.mem_cons_of_mem _ hl')) this
    exact ⟨h1, fun _ => (ih (fun l' hl' => hsub l' (List.mem_cons_of_mem _ hl')) this).2 hu⟩

/-- Secure means authentic: the RRset's type and records, with the original TTL and owner (or the wildcard
it was expanded from), were signed with the private key of a key vouched for from an anchor, by the zone the
RRset is in. -/
theorem secure_sound {A : List Anchor} {P : AlgorithmPolicy} {t : Nat} {C : Chain S} {set : RRset}
    {sigs : List (Rrsig S)} {ds : List (Signed S)} (h : validateRrset (some A) P t C set sigs ds = .secure) :
    ∃ apex k p r x, Vouched A C apex k ∧ S.pub p = k.pub ∧ r ∈ sigs ∧ r.hdr.signer = apex ∧
      under set.owner apex = true ∧ expanded r.hdr set = some x ∧ x.rtype = set.rtype ∧ x.rdata = set.rdata ∧
      r.sig = S.sign p ⟨r.hdr, .rrset x⟩ := by
  obtain ⟨l0, ls0, ks0, apex, keys, ⟨a, ha, hC, hl0, hk0⟩, hr, hf⟩ := secure_iff.mp h
  obtain ⟨haA, hau⟩ := anchorFor_some ha
  have hv0 : ∀ k ∈ ks0, Vouched A C l0.apex k := by
    refine keys_vouched hk0 (by rw [hC]; exact List.mem_cons_self) ?_
    intro d hd k hdig
    rw [hl0] at hdig ⊢
    exact .anchor haA hd hdig
  obtain ⟨hv, hu⟩ := reaches_vouched hr (fun l hl => by rw [hC]; exact List.mem_cons_of_mem _ hl) hv0
  have hfin : ∃ r ∈ sigs, SigBy P t apex keys (rrsetCover set) r := by
    rcases hf with ⟨r, hr, h, _⟩ | ⟨r, hr, h, _⟩ <;> exact ⟨r, hr, h⟩
  obtain ⟨r, hr', husable, _, d, hcov, k, hk, _, hver⟩ := hfin
  obtain ⟨p, hp, hsig⟩ := S.verify_sound _ _ _ hver
  unfold rrsetCover at hcov
  cases hx : expanded r.hdr set with
  | none => rw [hx] at hcov; cases hcov
  | some x =>
    rw [hx] at hcov; simp only [Option.map_some, Option.some.injEq] at hcov; subst hcov
    simp only [usable, Bool.and_eq_true, beq_iff_eq] at husable
    have hxs : x.rtype = set.rtype ∧ x.rdata = set.rdata := by
      unfold expanded at hx
      split at hx
      · cases hx; exact ⟨rfl, rfl⟩
      · split at hx
        · cases hx; exact ⟨rfl, rfl⟩
        · cases hx
    exact ⟨apex, k, p, r, x, hv k hk, hp, hr', husable.1.1, hu (by rw [hl0]; exact hau), hx, hxs.1, hxs.2, hsig⟩

/-! ## Signing (§8.2, §8.3) -/

/-- What a signer offers: its DNSKEY and a deterministic signing function. Rust's `Sign` trait. -/
structure Signer (S : SigScheme) where
  dnskey : Key
  sign : Tbs → S.Sig

/-- The signer that holds the private key `p`. -/
def Signer.ofPriv (p : S.Priv) (alg : Nat) (sep : Bool) : Signer S := ⟨⟨S.pub p, alg, sep⟩, S.sign p⟩

structure Window where
  inception : Nat
  expiration : Nat
deriving DecidableEq, Repr

/-- How a signed zone denies: NSEC, or NSEC3 with an empty salt and iterations 0 (RFC 9276 §3.1). -/
inductive Denial where
  | nsec
  | nsec3 (optOut : Bool)
deriving DecidableEq, Repr

/-- The labels an RRSIG over records owned by `o` counts: a leading `*` is not counted (RFC 4034 §3.1.3). -/
def labelsOf : Name → Nat
  | [42] :: rest => rest.length
  | o => o.length

/-- One RRSIG by each signer over `d`, whose owner has `labels` labels and whose TTL is `ttl`. -/
def sigsBy (ss : List (Signer S)) (apex : Name) (w : Window) (labels ttl : Nat) (d : Payload) :
    List (Rrsig S) :=
  ss.map fun s =>
    let h : Header := ⟨s.dnskey.alg, apex, labels, ttl, w.inception, w.expiration⟩
    ⟨h, s.sign ⟨h, d⟩⟩

/-- The signers of the DNSKEY set: the SEP keys, or every key when none has the bit. -/
def keySigners (ss : List (Signer S)) : List (Signer S) :=
  if ss.any (·.dnskey.sep) then ss.filter (·.dnskey.sep) else ss

/-- The signers of everything else: the keys without the SEP bit, or every key when all have it. -/
def dataSigners (ss : List (Signer S)) : List (Signer S) :=
  if ss.any (!·.dnskey.sep) then ss.filter (!·.dnskey.sep) else ss

/-- The types a node holds, as an NSEC or NSEC3 bitmap lists them (RFC 4034 §4.1.2). -/
def nodeTypes : Node → List Nat
  | .data sets => sets.map (·.rtype)
  | .dname d sets => d.rtype :: sets.map (·.rtype)
  | .cut _ ds _ => 2 :: (ds.map fun _ => 43).toList
  | .empty => []

/-- An NSEC's bitmap: the node's types, DNSKEY at the apex, and RRSIG and NSEC, which every NSEC owner has. -/
def nsecTypes (apex n : Name) (nd : Node) : List Nat :=
  nodeTypes nd ++ (if n = apex then [48] else []) ++ [46, 47]

/-- Whether a node has signed RRsets of its own: not an empty non-terminal, nor a cut without DS. -/
def signedAt : Node → Bool
  | .empty => false
  | .cut _ ds _ => ds.isSome
  | _ => true

/-- An NSEC3's bitmap: the node's types, DNSKEY at the apex, and RRSIG when the name has signed RRsets
(RFC 5155 §3.2). -/
def nsec3Types (apex n : Name) (nd : Node) : List Nat :=
  nodeTypes nd ++ (if n = apex then [48] else []) ++ (if signedAt nd then [46] else [])

/-- Inserts into a list sorted by `lt`, keeping one copy of equal elements. -/
def insertBy {α : Type} [DecidableEq α] (lt : α → α → Bool) (a : α) : List α → List α
  | [] => [a]
  | b :: r => if lt a b then a :: b :: r else if a = b then b :: r else b :: insertBy lt a r

def sortBy {α : Type} [DecidableEq α] (lt : α → α → Bool) (l : List α) : List α := l.foldr (insertBy lt) []

/-- Consecutive pairs of a list, the last paired with `f`. -/
def ringFrom {α : Type} : List α → α → List (α × α)
  | [], _ => []
  | [a], f => [(a, f)]
  | a :: b :: r, f => (a, b) :: ringFrom (b :: r) f

/-- Consecutive pairs of a sorted list, the last paired with the first: the links of an NSEC or NSEC3
chain (RFC 4034 §4.1.1). -/
def ring {α : Type} : List α → List (α × α)
  | [] => []
  | f :: r => ringFrom (f :: r) f

/-- The NSEC3 record that matches `n`, with the hash after `n`'s as its next hash. -/
def match3 (apex : Name) (optOut : Bool) (n : Name) (types : List Nat) : Nsec3 :=
  ⟨apex, S.hash n, if S.hash n + 1 = S.hashSpace then 0 else S.hash n + 1, types, optOut, 0⟩

/-- The authoritative RRset a node holds with the type and records of `s`: a cut holds only its DS set. -/
def heldIn (s : RRset) : Node → Option RRset
  | .cut _ ds _ => ds.filter fun x => x.rtype == s.rtype && x.rdata == s.rdata
  | nd => (nodeSets nd).find? fun x => x.rtype == s.rtype && x.rdata == s.rdata

/-- The name a negative answer is about: the last CNAME target of the answer, or the question name. -/
def finalName (q : Request) (r : Response) : Name :=
  if q.qtype = 5 then q.qname
  else match r.answer.getLast? with
    | some s => if s.rtype = 5 then (cnameTarget s).getD q.qname else q.qname
    | none => q.qname

/-- The cut a referral names: no answer, AA=0, and one NS set in authority. -/
def referralCut (r : Response) : Option Name :=
  match r.authority with
  | [ns] => if r.rcode = .noerror && !r.aa && r.answer.isEmpty && ns.rtype == 2 then some ns.owner else none
  | _ => none

/-- A negative answer: NXDOMAIN, or NOERROR with the SOA in authority. -/
def negativeAnswer (r : Response) : Bool :=
  r.rcode == .nxdomain || (r.rcode == .noerror && r.authority.any (·.rtype == 6))

/-- A zone signed offline, as `dnssec-signzone` does: its signers, window, and denial. Its records are
computed from these. An unsigned zone has no signers. -/
structure SignedZone (S : SigScheme) where
  zone : Zone
  signers : List (Signer S)
  window : Window
  denial : Denial

namespace SignedZone
variable (sz : SignedZone S)

def apex : Name := sz.zone.apex

def keys : List Key := sz.signers.map (·.dnskey)

/-- NSEC and NSEC3 records take the negative TTL: min(SOA TTL, MINIMUM) (RFC 9077 §3). -/
def denialTtl : Nat := negTtl sz.zone.soa

def optOut : Bool :=
  match sz.denial with
  | .nsec => false
  | .nsec3 o => o

/-- The DNSKEY set with its RRSIGs, made by the SEP keys. Its TTL is the SOA's. -/
def keySet : Signed S :=
  ⟨.keys sz.apex sz.keys,
    sigsBy (keySigners sz.signers) sz.apex sz.window sz.apex.length sz.zone.soa.ttl (.keys sz.apex sz.keys)⟩

/-- An RRset with its RRSIGs. -/
def signSet (s : RRset) : Signed S :=
  ⟨.rrset s, sigsBy (dataSigners sz.signers) sz.apex sz.window (labelsOf s.owner) s.ttl (.rrset s)⟩

def signNsec (r : Nsec) : Signed S :=
  ⟨.nsec r, sigsBy (dataSigners sz.signers) sz.apex sz.window (labelsOf r.owner) sz.denialTtl (.nsec r)⟩

def signNsec3 (r : Nsec3) : Signed S :=
  ⟨.nsec3 r, sigsBy (dataSigners sz.signers) sz.apex sz.window (sz.apex.length + 1) sz.denialTtl (.nsec3 r)⟩

/-- Every name the zone holds a node at, in canonical order. Names below a cut other than glue are not
nodes, and empty non-terminals have no node. -/
def names : List Name := sortBy before (sz.zone.nodes.map (·.1))

/-- The complete NSEC chain (RFC 4035 §2.3). -/
def nsecChain : List Nsec :=
  (ring sz.names).filterMap fun (o, n) => (sz.zone.node o).map fun nd => ⟨o, n, nsecTypes sz.apex o nd⟩

/-- A cut without DS, which opt-out leaves out of an NSEC3 chain. -/
def unsignedCut : Node → Bool
  | .cut _ ds _ => ds.isNone
  | _ => false

/-- The names an NSEC3 chain covers: each node's name and each empty non-terminal between it and the apex
(RFC 5155 §7.1). With opt-out, unsigned delegations and the empty non-terminals only they need are left
out. -/
def names3 : List Name :=
  let own := (sz.zone.nodes.filter fun e => !(sz.optOut && unsignedCut e.2)).map (·.1)
  sortBy before (own ++ own.flatMap fun n => (ancestors n).filter (under · sz.apex))

/-- The complete NSEC3 chain, in hash order. Names whose hashes collide share one record. -/
def nsec3Chain : List Nsec3 :=
  (ring (sortBy (· < ·) (sz.names3.map S.hash))).filterMap fun (h, nx) =>
    (sz.names3.find? (S.hash · == h)).map fun n =>
      ⟨sz.apex, h, nx, (match sz.zone.look n with
        | .present nd => nsec3Types sz.apex n nd
        | _ => []), sz.optOut, 0⟩

def nsecWith (f : Nsec → Bool) : List (Signed S) := ((sz.nsecChain.find? f).map sz.signNsec).toList

def nsec3With (f : Nsec3 → Bool) : List (Signed S) := ((sz.nsec3Chain.find? f).map sz.signNsec3).toList

def nsec3Matching (n : Name) : List (Signed S) := sz.nsec3With (·.hash == S.hash n)

def nsec3Covering (n : Name) : List (Signed S) := sz.nsec3With fun r => covers3 r.hash r.next (S.hash n)

/-- The closest provable encloser of `n` in the NSEC3 chain. -/
def chainEncloser (n : Name) : Name :=
  ((ancestors n).find? fun a => sz.nsec3Chain.any (·.hash == S.hash a)).getD sz.apex

/-- The proof a referral to the cut `m` carries when the child has no DS: the NSEC at the cut, the NSEC3 that
matches it, or, for a delegation an opt-out chain leaves out, the closest encloser's NSEC3 and the opt-out
NSEC3 that covers the next closer name (RFC 4035 §3.1.4, RFC 5155 §7.2.7). -/
def noDsRecords (m : Name) : List (Signed S) :=
  match sz.denial with
  | .nsec => sz.nsecWith (·.owner == m)
  | .nsec3 _ =>
    if sz.nsec3Chain.any (·.hash == S.hash m) then sz.nsec3Matching m
    else sz.nsec3Matching (sz.chainEncloser m) ++ sz.nsec3Covering (nextCloser m (sz.chainEncloser m))

/-- The RRSIGs a signed zone serves with an RRset of a response: those over the RRset at its own node, or over
the wildcard it was expanded from. A cut's NS set is not authoritative and has none; neither has a CNAME a
DNAME synthesized (RFC 6672 §5.3.1). -/
def sigsFor (s : RRset) : List (Rrsig S) :=
  match (sz.zone.node s.owner).bind (heldIn s) with
  | some x => (sz.signSet x).sigs
  | none =>
    match (sz.zone.node (wild (sz.zone.closest s.owner))).bind (heldIn s) with
    | some x => (sz.signSet x).sigs
    | none => []

/-- The denial records of a response with DO=1 (RFC 4035 §3.1.3): for a referral without DS the proof that
there is none; for NXDOMAIN and NODATA the proof of the negative about the final name; for each wildcard
expansion the proof that no closer name exists. -/
def denialFor (q : Request) (r : Response) : List (Signed S) :=
  let z := sz.zone
  let f := finalName q r
  let ce := z.closest f
  let cut : List (Signed S) :=
    match referralCut r with
    | some m =>
      match z.node m with
      | some (.cut _ none _) => sz.noDsRecords m
      | _ => []
    | none => []
  let neg : List (Signed S) :=
    if !negativeAnswer r then []
    else if r.rcode = .nxdomain then
      match sz.denial with
      | .nsec => sz.nsecWith (nsecNone · f) ++ sz.nsecWith (fun x => covers x.owner x.next (wild ce))
      | .nsec3 _ => sz.nsec3Matching ce ++ sz.nsec3Covering (nextCloser f ce) ++ sz.nsec3Covering (wild ce)
    else
      match sz.denial, z.node f, z.presentB f with
      | .nsec, some _, _ => sz.nsecWith (·.owner == f)
      | .nsec, none, true => sz.nsecWith fun x => covers x.owner x.next f && under x.next f
      | .nsec, none, false => sz.nsecWith (nsecNone · f) ++ sz.nsecWith (·.owner == wild ce)
      | .nsec3 _, _, true => sz.nsec3Matching f
      | .nsec3 _, _, false =>
        sz.nsec3Matching ce ++ sz.nsec3Covering (nextCloser f ce) ++ sz.nsec3Matching (wild ce)
  let wilds : List (Signed S) :=
    if negativeAnswer r then []
    else r.answer.flatMap fun s =>
      if (z.node s.owner).isSome then []
      else match sz.denial with
        | .nsec => sz.nsecWith fun x => covers x.owner x.next s.owner
        | .nsec3 _ => sz.nsec3Covering (nextCloser s.owner (z.closest s.owner))
  cut ++ neg ++ wilds

/-- A referral with DO=1 carries the child's DS set after the NS set (RFC 4035 §3.1.4). -/
def dsFor (r : Response) : List RRset :=
  match referralCut r with
  | some m =>
    match sz.zone.node m with
    | some (.cut _ (some ds) _) => [ds]
    | _ => []
  | none => []

end SignedZone

/-- A response with DO=1: each answer and authority RRset with its RRSIGs, and the denial records. -/
structure SignedAnswer (S : SigScheme) where
  rcode : Rcode
  aa : Bool
  answer : List (RRset × List (Rrsig S))
  authority : List (RRset × List (Rrsig S))
  additional : List RRset
  denial : List (Signed S)

/-- The answer a signed zone gives with DO=1. -/
def SignedZone.answerDo (sz : SignedZone S) (q : Request) (any : AnyResponse) : Answered × Option (SignedAnswer S) :=
  match answer sz.zone q any with
  | .response r =>
    let auth := r.authority ++ sz.dsFor r
    (.response r, some ⟨r.rcode, r.aa, r.answer.map (fun s => (s, sz.sigsFor s)),
      auth.map (fun s => (s, sz.sigsFor s)), r.additional, sz.denialFor q r⟩)
  | .unknown n => (.unknown n, none)

/-- What a validating client concludes from a signed answer: a result for each answer RRset, and for a
negative answer a result for its denial. -/
def validateAnswer (A : Option (List Anchor)) (P : AlgorithmPolicy) (t : Nat) (C : Chain S) (q : Request)
    (sa : SignedAnswer S) : List Validation × Option Validation :=
  let r : Response := ⟨sa.rcode, sa.aa, sa.answer.map (·.1), sa.authority.map (·.1), sa.additional, 0⟩
  (sa.answer.map (fun (s, sigs) => validateRrset A P t C s sigs sa.denial),
    if negativeAnswer r then some (validateDenial A P t C ⟨finalName q r, q.qtype⟩ sa.rcode sa.denial)
    else none)

/-! ## Covering records for zones that grow (§8.3)

An online signer cannot keep a complete chain over a zone that grows: an aggressive-NSEC client (RFC 8198)
would deny names added later. It makes covering records for one question at a time, and only from what the
view knows: an unknown fact gives no record at all. -/

/-- What a denial is about: the name, one type at an existing name, or the names between a wildcard's
closest encloser and the name it was expanded for. -/
inductive Denied where
  | name
  | type (t : Nat)
  | wildcard (ce : Name)
deriving DecidableEq, Repr

/-- The first of `as` whose fact is present, with its node; unknown when a fact before it is unknown. -/
def firstPresent (look : Name → Fact Node) : List Name → Fact (Name × Node)
  | [] => .absent
  | a :: as =>
    match look a with
    | .present nd => .present (a, nd)
    | .absent => firstPresent look as
    | .unknown => .unknown

/-- The closest encloser of `q` in a view: its deepest strict ancestor at or below the apex whose fact is
present. -/
def closestIn (look : Name → Fact Node) (apex q : Name) : Fact (Name × Node) :=
  firstPresent look ((ancestors q).filter (under · apex))

/-- Labels of `\255` prepended, as long as possible, until the name takes 255 octets. -/
def fillName (room : Nat) (n : Name) : Name :=
  if h : room < 2 then n
  else
    let k := min 63 (room - 1)
    fillName (room - (k + 1)) (List.replicate k 255 :: n)
termination_by room
decreasing_by omega

/-- The immediate predecessor of `q` in canonical order (RFC 4471 §3.1.1). -/
def pred (apex q : Name) : Name :=
  if q = apex then fillName (255 - Name.wireLen q) q
  else
    match q with
    | [] => []
    | l :: rest =>
      if l = [0] then rest
      else
        match l.getLast? with
        | some 0 => fillName (255 - Name.wireLen (l.dropLast :: rest)) (l.dropLast :: rest)
        | some o =>
          let o' := if 65 ≤ o - 1 ∧ o - 1 ≤ 90 then 64 else o - 1
          let room := 255 - Name.wireLen q
          let l' := l.dropLast ++ [o'] ++ List.replicate (min (63 - l.length) room) 255
          fillName (255 - Name.wireLen (l' :: rest)) (l' :: rest)
        | none => rest

/-- The label after `l` among labels no longer than it: the last octet below 255 incremented, skipping
uppercase letters, and the octets after it removed (RFC 4471 §3.1.2 step 3). -/
def incLabel (l : Label) : Option Label :=
  match l.reverse.dropWhile (· == 255) with
  | [] => none
  | o :: rest => some ((o :: rest).reverse.dropLast ++ [if 65 ≤ o + 1 ∧ o + 1 ≤ 90 then 91 else o + 1])

/-- The first name after `q` and every name below it: `q`'s leftmost label with a zero octet appended, or
incremented when it cannot grow (RFC 4471 §3.1.2 steps 2 and 3). -/
def succTree : Name → Name
  | [] => []
  | l :: rest =>
    if l.length < 63 ∧ Name.wireLen (l :: rest) < 255 then (l ++ [0]) :: rest
    else
      match incLabel l with
      | some l' => l' :: rest
      | none => succTree rest

/-- A minimally covering NSEC for a name that does not exist (RFC 4470 §3): from its predecessor to the first
name after it and its descendants, with only RRSIG and NSEC in the bitmap. -/
def epsilonNsec (apex q : Name) : Nsec := ⟨pred apex q, succTree q, [46, 47]⟩

/-- An NSEC3 white lie for `n` (RFC 7129 §5): from the hash before `n`'s to the hash after it. -/
def whiteLie (apex : Name) (optOut : Bool) (n : Name) : Nsec3 :=
  let h := S.hash n
  ⟨apex, if h = 0 then S.hashSpace - 1 else h - 1, if h + 1 = S.hashSpace then 0 else h + 1, [], optOut, 0⟩

/-- The covering records for `q` from a view, or `unknown` when a fact they rest on is unknown. A record only
narrows what a proof denies; it never supplies knowledge, so `cover` returns records only for facts the
view knows, and `absent` when the view contradicts the denial asked for. -/
def cover (look : Name → Fact Node) (apex : Name) (denial : Denial) (q : Name) : Denied → Fact (List Payload)
  | .type _ =>
    match look q with
    | .unknown => .unknown
    | .absent => .absent
    | .present nd =>
      .present [match denial with
        | .nsec => .nsec ⟨q, [0] :: q, nsecTypes apex q nd⟩
        | .nsec3 o => .nsec3 (match3 (S := S) apex o q (nsec3Types apex q nd))]
  | .name =>
    match look q with
    | .unknown => .unknown
    | .present _ => .absent
    | .absent =>
      match closestIn look apex q with
      | .unknown => .unknown
      | .absent => .absent
      | .present (ce, cnd) =>
        match look (wild ce) with
        | .unknown => .unknown
        | .present _ => .absent
        | .absent =>
          .present (match denial with
            | .nsec => [.nsec (epsilonNsec apex q), .nsec (epsilonNsec apex (wild ce))]
            | .nsec3 o => [.nsec3 (match3 (S := S) apex o ce (nsec3Types apex ce cnd)),
                .nsec3 (whiteLie (S := S) apex o (nextCloser q ce)), .nsec3 (whiteLie (S := S) apex o (wild ce))])
  | .wildcard ce =>
    match look q with
    | .unknown => .unknown
    | .present _ => .absent
    | .absent =>
      match closestIn look apex q with
      | .unknown => .unknown
      | .absent => .absent
      | .present (ce', _) =>
        if ce' = ce then
          .present (match denial with
            | .nsec => [.nsec (epsilonNsec apex q)]
            | .nsec3 o => [.nsec3 (whiteLie (S := S) apex o (nextCloser q ce))])
        else .absent

/-! ## Sorted chains -/

section Sorted
variable {α : Type} [DecidableEq α] {lt : α → α → Bool}

theorem mem_insertBy (a : α) : ∀ (l : List α) (x : α), x ∈ insertBy lt a l ↔ x = a ∨ x ∈ l := by
  intro l
  induction l with
  | nil => simp [insertBy]
  | cons b r ih =>
    intro x
    unfold insertBy
    split
    · simp
    · split
      · rename_i hab; subst hab; simp
      · simp only [List.mem_cons, ih]; constructor <;> rintro (h | h | h) <;> simp [h]

theorem mem_sortBy (l : List α) (x : α) : x ∈ sortBy lt l ↔ x ∈ l := by
  induction l with
  | nil => simp [sortBy]
  | cons a l ih =>
    simp only [sortBy, List.foldr_cons] at ih ⊢
    rw [mem_insertBy, ih]; simp

variable (trans : ∀ x y z, lt x y = true → lt y z = true → lt x z = true)
  (tot : ∀ x y, lt x y = true ∨ x = y ∨ lt y x = true)
include trans tot

theorem pairwise_insertBy (a : α) : ∀ (l : List α), l.Pairwise (lt · · = true) →
    (insertBy lt a l).Pairwise (lt · · = true) := by
  intro l
  induction l with
  | nil => intro _; simp [insertBy]
  | cons b r ih =>
    intro h
    rw [List.pairwise_cons] at h
    unfold insertBy
    split
    · rename_i hab
      refine List.Pairwise.cons ?_ (List.Pairwise.cons h.1 h.2)
      intro y hy
      rcases List.mem_cons.mp hy with rfl | hy
      · exact hab
      · exact trans _ _ _ hab (h.1 y hy)
    · split
      · exact List.Pairwise.cons h.1 h.2
      · rename_i hab hne
        have hba : lt b a = true := by
          rcases tot a b with h' | h' | h'
          · simp [h'] at hab
          · exact absurd h' hne
          · exact h'
        refine List.Pairwise.cons ?_ (ih h.2)
        intro y hy
        rcases (mem_insertBy a r y).mp hy with rfl | hy
        · exact hba
        · exact h.1 y hy

theorem pairwise_sortBy (l : List α) : (sortBy lt l).Pairwise (lt · · = true) := by
  induction l with
  | nil => simp [sortBy]
  | cons a l ih =>
    simp only [sortBy, List.foldr_cons] at ih ⊢
    exact pairwise_insertBy trans tot a _ ih

end Sorted

theorem mem_ringFrom {α : Type} : ∀ (l : List α) (f o n : α), (o, n) ∈ ringFrom l f →
    (∃ xs ys, l = xs ++ o :: n :: ys) ∨ (l.getLast? = some o ∧ n = f)
  | [], _, _, _, h => by simp [ringFrom] at h
  | [a], f, o, n, h => by
    simp only [ringFrom, List.mem_singleton, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact Or.inr ⟨rfl, rfl⟩
  | a :: b :: r, f, o, n, h => by
    simp only [ringFrom, List.mem_cons, Prod.mk.injEq] at h
    rcases h with ⟨rfl, rfl⟩ | h
    · exact Or.inl ⟨[], r, rfl⟩
    · rcases mem_ringFrom (b :: r) f o n (by simpa using h) with ⟨xs, ys, he⟩ | ⟨hl, hn⟩
      · exact Or.inl ⟨a :: xs, ys, by rw [he]; rfl⟩
      · exact Or.inr ⟨by rw [List.getLast?_cons_cons]; exact hl, hn⟩

theorem consecutive {α : Type} {lt : α → α → Bool} {xs ys : List α} {o n : α}
    (h : (xs ++ o :: n :: ys).Pairwise (lt · · = true)) :
    lt o n = true ∧ ∀ p ∈ xs ++ o :: n :: ys, p = o ∨ p = n ∨ lt p o = true ∨ lt n p = true := by
  rw [List.pairwise_append] at h
  obtain ⟨_, h2, h3⟩ := h
  rw [List.pairwise_cons] at h2
  obtain ⟨h21, h22⟩ := h2
  rw [List.pairwise_cons] at h22
  refine ⟨h21 n List.mem_cons_self, fun p hp => ?_⟩
  rcases List.mem_append.mp hp with hp | hp
  · exact Or.inr (Or.inr (Or.inl (h3 p hp o List.mem_cons_self)))
  · rcases List.mem_cons.mp hp with rfl | hp
    · exact Or.inl rfl
    · rcases List.mem_cons.mp hp with rfl | hp
      · exact Or.inr (Or.inl rfl)
      · exact Or.inr (Or.inr (Or.inr (h22.1 p hp)))

theorem wraps {α : Type} {lt : α → α → Bool} {f o : α} {r : List α} (h : (f :: r).Pairwise (lt · · = true))
    (hl : (f :: r).getLast? = some o) :
    (∀ p ∈ f :: r, p = o ∨ lt p o = true) ∧ (∀ p ∈ f :: r, p = f ∨ lt f p = true) := by
  refine ⟨fun p hp => ?_, fun p hp => ?_⟩
  · obtain ⟨ys, hys⟩ := List.getLast?_eq_some_iff.mp hl
    rw [hys] at h hp
    rw [List.pairwise_append] at h
    rcases List.mem_append.mp hp with hp | hp
    · exact Or.inr (h.2.2 p hp o (List.mem_singleton_self _))
    · exact Or.inl (List.mem_singleton.mp hp)
  · rcases List.mem_cons.mp hp with rfl | hp
    · exact Or.inl rfl
    · exact Or.inr ((List.pairwise_cons.mp h).1 p hp)

/-- An NSEC of a complete chain that proves nothing exists at or below `q` is right: the zone holds no node at
or below `q`. -/
theorem nsec_cover_sound (sz : SignedZone S) {r : Nsec} {q : Name} (hr : r ∈ sz.nsecChain)
    (hc : nsecNone r q = true) : sz.zone.presentB q = false := by
  have trans : ∀ x y z, before x y = true → before y z = true → before x z = true := fun _ _ _ => before_trans
  have sorted := pairwise_sortBy trans before_total (sz.zone.nodes.map (·.1))
  unfold SignedZone.nsecChain at hr
  obtain ⟨⟨o, n⟩, hon, hr⟩ := List.mem_filterMap.mp hr
  simp only at hr
  cases hnd : sz.zone.node o with
  | none => rw [hnd] at hr; cases hr
  | some nd =>
    rw [hnd] at hr; simp only [Option.map_some, Option.some.injEq] at hr; subst hr
    simp only [nsecNone, Bool.and_eq_true, Bool.not_eq_true'] at hc
    obtain ⟨hcov, hnq⟩ := hc
    cases hp : sz.zone.presentB q with
    | false => rfl
    | true =>
      exfalso
      obtain ⟨⟨p, pnd⟩, hpn, hpq⟩ := (sz.zone.presentB_iff q).mp hp
      have hpu : under p q = true := (under_iff p q).mpr hpq
      have hpmem : p ∈ sz.names := by
        unfold SignedZone.names; rw [mem_sortBy]; exact List.mem_map.mpr ⟨_, hpn, rfl⟩
      -- `p` sorts at or after `q`
      have hqp : p = q ∨ before q p = true := under_before hpu
      -- a name strictly between `q` and `p` would be below `q`
      have nmid : ∀ m, before q m = true → (m = p ∨ before m p = true) → under m q = true := by
        intro m h1 h2
        rcases h2 with rfl | h2
        · exact hpu
        · exact under_between hpu h1 h2
      have hnu : under n q = false := hnq
      generalize hl : sz.names = l at hon hpmem sorted
      unfold SignedZone.names at hl
      rw [hl] at sorted
      cases l with
      | nil => simp [ring] at hon
      | cons f rest =>
        simp only [ring] at hon
        rcases mem_ringFrom (f :: rest) f o n hon with ⟨xs, ys, he⟩ | ⟨hlast, hnf⟩
        · rw [he] at sorted hpmem
          obtain ⟨hon', hall⟩ := consecutive sorted
          simp only [covers, hon', ↓reduceIte, Bool.and_eq_true] at hcov
          obtain ⟨hoq, hqn⟩ := hcov
          rcases hall p hpmem with rfl | rfl | h | h
          · -- p = o, yet o sorts before q and p at or after it
            rcases hqp with rfl | h
            · rw [before_irrefl] at hoq; cases hoq
            · have := before_trans hoq h; rw [before_irrefl] at this; cases this
          · rcases hqp with rfl | _
            · rw [before_irrefl] at hqn; cases hqn
            · rw [hpu] at hnu; cases hnu
          · rcases hqp with rfl | h'
            · have := before_trans hoq h; rw [before_irrefl] at this; cases this
            · have := before_trans (before_trans hoq h') h; rw [before_irrefl] at this; cases this
          · rcases hqp with rfl | _
            · have := before_trans hqn h; rw [before_irrefl] at this; cases this
            · rw [nmid n hqn (Or.inr h)] at hnu; cases hnu
        · obtain ⟨hmax, hmin⟩ := wraps sorted hlast
          rw [hnf] at hcov hnu
          have hno : before o f = false := by
            cases h : before o f
            · rfl
            · rcases hmax f List.mem_cons_self with rfl | h'
              · rw [before_irrefl] at h; cases h
              · have := before_trans h h'; rw [before_irrefl] at this; cases this
          simp only [covers, hno, Bool.false_eq_true, ↓reduceIte, Bool.or_eq_true] at hcov
          rcases hcov with hoq | hqf
          · rcases hmax p hpmem with rfl | h
            · rcases hqp with rfl | h'
              · rw [before_irrefl] at hoq; cases hoq
              · have := before_trans hoq h'; rw [before_irrefl] at this; cases this
            · rcases hqp with rfl | h'
              · have := before_trans hoq h; rw [before_irrefl] at this; cases this
              · have := before_trans (before_trans hoq h') h; rw [before_irrefl] at this; cases this
          · rcases hmin p hpmem with rfl | h
            · rcases hqp with rfl | _
              · rw [before_irrefl] at hqf; cases hqf
              · rw [hpu] at hnu; cases hnu
            · rcases hqp with rfl | _
              · have := before_trans hqf h; rw [before_irrefl] at this; cases this
              · rw [nmid f hqf (Or.inr h)] at hnu; cases hnu

theorem covers3_white {k M x : Nat} (hn : k < M) (hx : x < M)
    (h : covers3 (if k = 0 then M - 1 else k - 1) (if k + 1 = M then 0 else k + 1) x = true) : x = k := by
  generalize ho : (if k = 0 then M - 1 else k - 1) = o at h
  generalize hn' : (if k + 1 = M then 0 else k + 1) = n at h
  unfold covers3 at h
  split at ho <;> split at hn' <;> split at h <;>
    (try simp only [Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq] at h) <;> omega

/-- An NSEC3 white lie covers only the hash of the name it was made for (RFC 7129 §5). -/
theorem white_lie_covers_only_qname (apex : Name) (optOut : Bool) (n : Name) {x : Nat} (hx : x < S.hashSpace)
    (h : covers3 (whiteLie (S := S) apex optOut n).hash (whiteLie (S := S) apex optOut n).next x = true) :
    x = S.hash n := by
  simp only [whiteLie] at h
  exact covers3_white (S.hash_lt n) hx h

/-- A covering record never rests on an unknown fact: an unknown name, or an unknown fact on the way up to
its closest encloser, gives `unknown` and no record. -/
theorem cover_unknown_is_unknown (look : Name → Fact Node) (apex : Name) (denial : Denial) (q : Name)
    (kind : Denied) :
    (look q = .unknown → cover (S := S) look apex denial q kind = .unknown) ∧
      (look q = .absent → closestIn look apex q = .unknown → kind ≠ .type 0 → (∀ t, kind ≠ .type t) →
        cover (S := S) look apex denial q kind = .unknown) := by
  refine ⟨fun h => ?_, fun h hce _ hk => ?_⟩
  · cases kind <;> simp [cover, h]
  · cases kind with
    | type t => exact absurd rfl (hk t)
    | name => simp [cover, h, hce]
    | wildcard ce => simp [cover, h, hce]

/-- And a covering record for a name's nonexistence exists only when the view knows the name is absent, its
closest encloser is present, and the wildcard there is absent. -/
theorem cover_knows {look : Name → Fact Node} {apex : Name} {denial : Denial} {q : Name} {ps : List Payload}
    (h : cover (S := S) look apex denial q .name = .present ps) :
    look q = .absent ∧ ∃ ce cnd, closestIn look apex q = .present (ce, cnd) ∧ look (wild ce) = .absent := by
  simp only [cover] at h
  cases hq : look q with
  | unknown => rw [hq] at h; cases h
  | present _ => rw [hq] at h; cases h
  | absent =>
    rw [hq] at h
    simp only at h
    cases hce : closestIn look apex q with
    | unknown => rw [hce] at h; cases h
    | absent => rw [hce] at h; cases h
    | present c =>
      obtain ⟨ce, cnd⟩ := c
      rw [hce] at h
      simp only at h
      cases hw : look (wild ce) with
      | unknown => rw [hw] at h; cases h
      | present _ => rw [hw] at h; cases h
      | absent => exact ⟨rfl, ce, cnd, rfl, hw⟩

/-! ## Opt-out never proves a name away -/

theorem denial_secure_nx {A : List Anchor} {P : AlgorithmPolicy} {t : Nat} {C : Chain S} {q : Request}
    {ds : List (Signed S)} (h : validateDenial (some A) P t C q .nxdomain ds = .secure) :
    ∃ apex keys, walk A P t q.qname C = .trusted apex keys ∧
      (nx (nsecs (verified P t apex keys ds)) q.qname = true ∨
        ∃ ce, closest3 (S := S) (nsec3s (verified P t apex keys ds)) q.qname = some ce ∧
          ∃ r ∈ nsec3s (verified P t apex keys ds),
            covers3 r.hash r.next (S.hash (nextCloser q.qname ce)) = true ∧ r.optOut = false) := by
  unfold validateDenial at h
  simp only at h
  split at h
  · rename_i v hw; subst h; exact absurd rfl (walk_stop_ne_secure hw)
  · rename_i apex keys hw
    refine ⟨apex, keys, hw, ?_⟩
    unfold denialResult at h
    simp only [↓reduceIte] at h
    split at h
    · rename_i hn; exact Or.inl hn
    · right
      split at h
      · cases h
      · cases h3 : nx3 (S := S) (nsec3s (verified P t apex keys ds)) q.qname with
        | none => rw [h3] at h; cases h
        | some b =>
          rw [h3] at h
          cases b with
          | true => cases h
          | false =>
            unfold nx3 at h3
            split at h3
            · cases h3
            · rename_i ce hce
              split at h3
              · cases h3
              · split at h3
                · rename_i hcov
                  obtain ⟨r, hr, hr'⟩ := List.any_eq_true.mp hcov
                  simp only [Bool.and_eq_true, beq_iff_eq] at hr'
                  exact ⟨ce, hce, r, hr, hr'.1, by simpa using hr'.2⟩
                · split at h3 <;> cases h3

/-- A denial whose only cover for the next closer name is an opt-out NSEC3 is never Secure: opt-out says an
unsigned delegation may exist there (RFC 5155 §6, §9.2). -/
theorem optout_never_secure_denial {A : List Anchor} {P : AlgorithmPolicy} {t : Nat} {C : Chain S} {q : Request}
    {ds : List (Signed S)} {apex : Name} {keys : List Key} (hw : walk A P t q.qname C = .trusted apex keys)
    (hn : nx (nsecs (verified P t apex keys ds)) q.qname = false)
    (ho : ∀ ce, closest3 (S := S) (nsec3s (verified P t apex keys ds)) q.qname = some ce →
      ∀ r ∈ nsec3s (verified P t apex keys ds), covers3 r.hash r.next (S.hash (nextCloser q.qname ce)) = true →
        r.optOut = true) :
    validateDenial (some A) P t C q .nxdomain ds ≠ .secure := by
  intro h
  obtain ⟨apex', keys', hw', hp⟩ := denial_secure_nx h
  rw [hw] at hw'; cases hw'
  rcases hp with hp | ⟨ce, hce, r, hr, hcov, hopt⟩
  · rw [hn] at hp; cases hp
  · rw [ho ce hce r hr hcov] at hopt; cases hopt

/-! ## Answers of a signed zone validate -/

/-- A signer that holds the private key of its DNSKEY and signs with it. -/
def Signer.Honest (s : Signer S) : Prop := ∃ p, s.dnskey.pub = S.pub p ∧ ∀ m, s.sign m = S.sign p m

namespace SignedZone
variable (sz : SignedZone S)

/-- The anchor for a signed zone: a DS record of digest type `dt` for each SEP key. -/
def anchor (dt : Nat) : Anchor :=
  ⟨sz.apex, (keySigners sz.signers).filterMap fun s =>
    if s.dnskey.sep then some ⟨s.dnskey.alg, dt, S.digest sz.apex s.dnskey⟩ else none⟩

/-- The one-link chain of a zone validated by its own anchor. -/
def link : Link S := ⟨sz.apex, none, some sz.keySet⟩

end SignedZone

theorem honest_verifies {s : Signer S} (hs : s.Honest) (h : Header) (d : Payload) :
    S.verify s.dnskey.pub ⟨h, d⟩ (s.sign ⟨h, d⟩) = true := by
  obtain ⟨p, hp, hsign⟩ := hs
  rw [hp, hsign]; exact S.verify_sign _ _

theorem mem_keySigners {ss : List (Signer S)} {s : Signer S} (h : s ∈ keySigners ss) : s ∈ ss := by
  unfold keySigners at h; split at h
  · exact (List.mem_filter.mp h).1
  · exact h

theorem mem_dataSigners {ss : List (Signer S)} {s : Signer S} (h : s ∈ dataSigners ss) : s ∈ ss := by
  unfold dataSigners at h; split at h
  · exact (List.mem_filter.mp h).1
  · exact h

theorem dataSigners_nonempty {ss : List (Signer S)} (h : ss ≠ []) : ∃ s, s ∈ dataSigners ss := by
  unfold dataSigners
  split
  · rename_i hs
    obtain ⟨s, hs, hs'⟩ := List.any_eq_true.mp hs
    exact ⟨s, List.mem_filter.mpr ⟨hs, hs'⟩⟩
  · obtain ⟨s, hs⟩ := List.exists_mem_of_ne_nil ss h
    exact ⟨s, hs⟩

theorem sep_keySigner {ss : List (Signer S)} {s : Signer S} (hs : s ∈ ss) (hsep : s.dnskey.sep = true) :
    s ∈ keySigners ss := by
  unfold keySigners
  have : ss.any (·.dnskey.sep) = true := List.any_eq_true.mpr ⟨s, hs, hsep⟩
  simp only [this, ↓reduceIte]
  exact List.mem_filter.mpr ⟨hs, hsep⟩

/-- What makes a signed zone's own signatures verify at `t`: honest signers, algorithms the policy validates,
and an open window. -/
structure SignsWell (sz : SignedZone S) (P : AlgorithmPolicy) (t : Nat) : Prop where
  honest : ∀ s ∈ sz.signers, s.Honest
  alg : ∀ s ∈ sz.signers, P.validate.contains s.dnskey.alg = true
  window : sz.window.inception ≤ t ∧ t ≤ sz.window.expiration

theorem SignsWell.windowOk {sz : SignedZone S} {P : AlgorithmPolicy} {t : Nat} (hw : SignsWell sz P t)
    (a : Nat) (sg : Name) (lb tt : Nat) :
    windowOk t ⟨a, sg, lb, tt, sz.window.inception, sz.window.expiration⟩ = true := by
  simp [Dnssec.windowOk, hw.window.1, hw.window.2]

/-- A signed zone's SEP keys sign its DNSKEY set, so a supported DS record that names one makes the whole set
trusted. -/
theorem keySet_signed {sz : SignedZone S} {P : AlgorithmPolicy} {t : Nat} (hw : SignsWell sz P t) {dss : List Ds}
    {s0 : Signer S} (hs0 : s0 ∈ sz.signers) (hsep0 : s0.dnskey.sep = true) {d : Ds} (hd : d ∈ dss)
    (hdt : P.treat d.keyAlg d.dtype = .supported) (hda : d.keyAlg = s0.dnskey.alg)
    (hdd : d.digest = S.digest sz.apex s0.dnskey) : KeysSigned P t sz.apex dss (some sz.keySet) sz.keys := by
  refine ⟨sz.keySet, rfl, rfl, s0.dnskey, List.mem_map.mpr ⟨s0, hs0, rfl⟩, hsep0, ⟨d, hd, hdt, hda, hdd⟩, ?_⟩
  refine ⟨_, List.mem_map.mpr ⟨s0, sep_keySigner hs0 hsep0, rfl⟩, ?_, hw.windowOk _ _ _ _, _, rfl, s0.dnskey,
    List.mem_singleton_self _, rfl, honest_verifies (hw.honest s0 hs0) _ _⟩
  simp only [usable, beq_self_eq_true, hw.alg s0 hs0, Bool.and_self, List.any_cons, List.any_nil, Bool.or_false]

/-- An RRset a zone signed, offered at its own owner with any TTL, passes the zone's own check. -/
theorem signSet_final {sz : SignedZone S} {P : AlgorithmPolicy} {t : Nat} (hw : SignsWell sz P t)
    (hne : sz.signers ≠ []) {set x : RRset} (ds : List (Signed S)) (hown : x.owner = set.owner)
    (htype : x.rtype = set.rtype) (hdata : x.rdata = set.rdata) (hlab : labelsOf x.owner = x.owner.length) :
    FinalSigned P t sz.apex sz.keys set (sz.signSet x).sigs ds := by
  obtain ⟨s1, hs1⟩ := dataSigners_nonempty hne
  have hs1' := mem_dataSigners hs1
  refine Or.inl ⟨_, List.mem_map.mpr ⟨s1, hs1, rfl⟩, ⟨?_, hw.windowOk _ _ _ _, .rrset x, ?_, s1.dnskey,
    List.mem_map.mpr ⟨s1, hs1', rfl⟩, rfl, honest_verifies (hw.honest s1 hs1') _ _⟩, ?_⟩
  · simp only [usable, beq_self_eq_true, hw.alg s1 hs1', Bool.and_self, Bool.true_and, List.any_eq_true, beq_iff_eq]
    exact ⟨s1.dnskey, List.mem_map.mpr ⟨s1, hs1', rfl⟩, rfl⟩
  · simp only [rrsetCover, expanded, hown]
    cases x; cases set; simp_all
  · show ¬ labelsOf x.owner < set.owner.length
    rw [hlab, hown]; exact Nat.lt_irrefl _

/-- The RRSIGs a zone serves with an RRset of one of its own nodes are its signatures over that node's RRset. -/
theorem sigsFor_own (sz : SignedZone S) (hwf : sz.zone.WF) {s : RRset} {nd : Node}
    (hnode : sz.zone.node s.owner = some nd) (hcut : ∀ ns d g, nd ≠ .cut ns d g)
    (hheld : ∃ x ∈ nodeSets nd, x.rtype = s.rtype ∧ x.rdata = s.rdata) :
    ∃ x, sz.sigsFor s = (sz.signSet x).sigs ∧ x.owner = s.owner ∧ x.rtype = s.rtype ∧ x.rdata = s.rdata := by
  have hfind : ∃ x, (nodeSets nd).find? (fun x => x.rtype == s.rtype && x.rdata == s.rdata) = some x := by
    obtain ⟨x, hx, h1, h2⟩ := hheld
    cases hf : (nodeSets nd).find? (fun x => x.rtype == s.rtype && x.rdata == s.rdata) with
    | some y => exact ⟨y, rfl⟩
    | none => exact absurd (List.find?_eq_none.mp hf x hx) (by simp [h1, h2])
  obtain ⟨x, hx⟩ := hfind
  have hxm := List.mem_of_find?_eq_some hx
  have hxp := List.find?_some hx
  simp only [Bool.and_eq_true, beq_iff_eq] at hxp
  have hxo : x.owner = s.owner := by
    have hw := hwf.2 s.owner nd hnode
    cases nd with
    | data sets => exact hw x hxm
    | dname d sets =>
      simp only [nodeSets, List.mem_cons] at hxm
      rcases hxm with rfl | hxm
      · exact hw.1
      · exact hw.2 x hxm
    | cut ns d g => exact absurd rfl (hcut ns d g)
    | empty => simp [nodeSets] at hxm
  refine ⟨x, ?_, hxo, hxp.1, hxp.2⟩
  unfold SignedZone.sigsFor
  rw [hnode]
  cases nd with
  | cut ns d g => exact absurd rfl (hcut ns d g)
  | data sets => simp only [Option.bind_some, heldIn, hx]
  | dname d sets => simp only [Option.bind_some, heldIn, hx]
  | empty => simp only [Option.bind_some, heldIn, hx]

theorem anchorFor_zone (sz : SignedZone S) (dt : Nat) {n : Name} (hin : under n sz.apex = true) :
    anchorFor [sz.anchor dt] n = some (sz.anchor dt) := by
  simp [anchorFor, anchorStep, SignedZone.anchor, hin]

/-- A signed zone's anchor names each of its SEP keys. -/
theorem anchor_keys {sz : SignedZone S} {P : AlgorithmPolicy} {t dt : Nat} (hw : SignsWell sz P t)
    (hdt : P.digests.contains dt = true) {s0 : Signer S} (hs0 : s0 ∈ sz.signers) (hsep0 : s0.dnskey.sep = true) :
    KeysSigned P t sz.apex (sz.anchor dt).ds (some sz.keySet) sz.keys := by
  refine keySet_signed hw hs0 hsep0 (d := ⟨s0.dnskey.alg, dt, S.digest sz.apex s0.dnskey⟩) ?_ ?_ rfl rfl
  · exact List.mem_filterMap.mpr ⟨s0, sep_keySigner hs0 hsep0, by simp [hsep0]⟩
  · simp only [AlgorithmPolicy.treat, hw.alg s0 hs0, hdt, Bool.not_true, Bool.false_eq_true, ↓reduceIte]

/-- Every RRset a signed zone signs validates Secure under the zone's own anchor, while the signature window
holds, when every signer is honest and uses an algorithm the policy validates and some signer has the SEP
bit. -/
theorem signed_sets_validate (sz : SignedZone S) (P : AlgorithmPolicy) (t dt : Nat) (hw : SignsWell sz P t)
    (hdt : P.digests.contains dt = true) (hsep : ∃ s ∈ sz.signers, s.dnskey.sep = true) {set x : RRset}
    (ds : List (Signed S)) (hown : x.owner = set.owner) (htype : x.rtype = set.rtype) (hdata : x.rdata = set.rdata)
    (hlab : labelsOf x.owner = x.owner.length) (hin : under set.owner sz.apex = true) :
    validateRrset (some [sz.anchor dt]) P t [sz.link] set (sz.signSet x).sigs ds = .secure := by
  obtain ⟨s0, hs0, hsep0⟩ := hsep
  exact secure_complete ⟨sz.link, [], sz.keys, sz.apex, sz.keys,
    ⟨sz.anchor dt, anchorFor_zone sz dt hin, rfl, rfl, anchor_keys hw hdt hs0 hsep0⟩, .nil,
    signSet_final hw (List.ne_nil_of_mem hs0) ds hown htype hdata hlab⟩

/-- The RRsets a signed zone serves from its own nodes, with the RRSIGs it serves for them, validate Secure
under the zone's own anchor. The TTL may be lower than the stored one, as for the SOA of a negative answer. -/
theorem signed_answers_validate (sz : SignedZone S) (P : AlgorithmPolicy) (t dt : Nat) (hw : SignsWell sz P t)
    (hdt : P.digests.contains dt = true) (hsep : ∃ s ∈ sz.signers, s.dnskey.sep = true) (hwf : sz.zone.WF)
    {s : RRset} {nd : Node} (ds : List (Signed S)) (hnode : sz.zone.node s.owner = some nd)
    (hcut : ∀ ns d g, nd ≠ .cut ns d g) (hheld : ∃ x ∈ nodeSets nd, x.rtype = s.rtype ∧ x.rdata = s.rdata)
    (hlab : labelsOf s.owner = s.owner.length) (hin : under s.owner sz.apex = true) :
    validateRrset (some [sz.anchor dt]) P t [sz.link] s (sz.sigsFor s) ds = .secure := by
  obtain ⟨x, hsig, hxo, hxt, hxd⟩ := sigsFor_own sz hwf hnode hcut hheld
  rw [hsig]
  exact signed_sets_validate sz P t dt hw hdt hsep ds hxo hxt hxd (by rw [hxo]; exact hlab) hin

/-! ## A concrete scheme

Private keys are numbers and the public key of `p` is the one octet string `[p]`. A signature is the pair
of the private key and the message, so it verifies exactly when its key is the verifying key's and its
message is the one asked about. A DS digest is the identity on an encoding of the owner and the key. These
are symbolic, as in the vectors (§18.3): the differential test checks them with an oracle `Verify` and then
ties them to real signatures. The NSEC3 hash is the real one, SHA-1 over the owner's canonical wire form with
an empty salt and no extra iterations (RFC 5155 §5), so NSEC3 vectors agree with real proof code. -/

namespace Symbolic

/-- A name's canonical wire form (RFC 4034 §6.2): lowercase labels, each after its length, then the root. -/
def wire (n : Name) : List Nat := (n.flatMap fun l => l.length :: l) ++ [0]

def rotl (x : UInt32) (k : UInt32) : UInt32 := (x <<< k) ||| (x >>> (32 - k))

def be32 (a b c d : Nat) : UInt32 :=
  (a.toUInt32 <<< 24) ||| (b.toUInt32 <<< 16) ||| (c.toUInt32 <<< 8) ||| d.toUInt32

/-- The SHA-1 message schedule of one 64-octet block (FIPS 180-4 §6.1.2). -/
def schedule (blk : List Nat) : Array UInt32 := Id.run do
  let b := blk.toArray
  let mut w : Array UInt32 := #[]
  for i in [0:16] do
    w := w.push (be32 b[4 * i]! b[4 * i + 1]! b[4 * i + 2]! b[4 * i + 3]!)
  for i in [16:80] do
    w := w.push (rotl (w[i - 3]! ^^^ w[i - 8]! ^^^ w[i - 14]! ^^^ w[i - 16]!) 1)
  return w

def compress (h : UInt32 × UInt32 × UInt32 × UInt32 × UInt32) (blk : List Nat) :
    UInt32 × UInt32 × UInt32 × UInt32 × UInt32 := Id.run do
  let w := schedule blk
  let (h0, h1, h2, h3, h4) := h
  let mut a := h0
  let mut b := h1
  let mut c := h2
  let mut d := h3
  let mut e := h4
  for i in [0:80] do
    let (f, k) : UInt32 × UInt32 :=
      if i < 20 then ((b &&& c) ||| ((~~~ b) &&& d), 0x5A827999)
      else if i < 40 then (b ^^^ c ^^^ d, 0x6ED9EBA1)
      else if i < 60 then ((b &&& c) ||| (b &&& d) ||| (c &&& d), 0x8F1BBCDC)
      else (b ^^^ c ^^^ d, 0xCA62C1D6)
    let t := rotl a 5 + f + e + k + w[i]!
    e := d
    d := c
    c := rotl b 30
    b := a
    a := t
  return (h0 + a, h1 + b, h2 + c, h3 + d, h4 + e)

/-- The padded message cut into 64-octet blocks (FIPS 180-4 §5.1.1, §5.2.1). -/
def blocks (msg : List Nat) : List (List Nat) :=
  let len := msg.length
  let padded := msg ++ [128] ++ List.replicate ((119 - len % 64) % 64) 0 ++
    (List.range 8).reverse.map fun i => (len * 8) / 2 ^ (8 * i) % 256
  (List.range (padded.length / 64)).map fun i => (padded.drop (64 * i)).take 64

def toNat160 : UInt32 × UInt32 × UInt32 × UInt32 × UInt32 → Nat
  | (h0, h1, h2, h3, h4) => h0.toNat * 2 ^ 128 + h1.toNat * 2 ^ 96 + h2.toNat * 2 ^ 64 + h3.toNat * 2 ^ 32 + h4.toNat

/-- SHA-1 (FIPS 180-4 §6.1), as a 160-bit number. -/
def sha1 (msg : List Nat) : Nat :=
  toNat160 ((blocks msg).foldl compress (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0))

theorem sha1_lt (msg : List Nat) : sha1 msg < 2 ^ 160 := by
  unfold sha1
  generalize (List.foldl compress _ _) = r
  obtain ⟨h0, h1, h2, h3, h4⟩ := r
  have := h0.toNat_lt; have := h1.toNat_lt; have := h2.toNat_lt; have := h3.toNat_lt; have := h4.toNat_lt
  simp only [toNat160]
  omega

instance scheme : SigScheme where
  Priv := Nat
  Sig := Nat × Tbs
  pub p := [p]
  sign p m := (p, m)
  verify k m s := k == [s.1] && s.2 == m
  digest o k := wire o ++ [if k.sep then 1 else 0, k.alg] ++ k.pub
  hash n := sha1 (wire n)
  hashSpace := 2 ^ 160
  verify_sign p m := by simp
  verify_sound k m s h := by
    simp only [Bool.and_eq_true, beq_iff_eq] at h
    exact ⟨s.1, h.1.symm, by rw [← h.2]⟩
  hash_lt n := sha1_lt _

end Symbolic

end Dns.Dnssec
