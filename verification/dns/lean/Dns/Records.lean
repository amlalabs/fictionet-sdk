/-
  Providers and signers as functions to published records.

  The validator reads published records only. Two things make records: the data (a complete zone, or a lazy
  zone that asks a provider) and the signers. `lazy_agrees_complete` says a lazy zone over a provider that
  agrees with a complete zone answers every question as that zone does. `signer_agnostic` says the records an
  online signer publishes depend on a signer only through its DNSKEY and its signing function, so two
  implementations that agree on those publish the same records. `validate_records_only` composes the two:
  whatever the provider and whichever signer, the validator reaches the same result. Saying only "equal
  records give equal validation" would be congruence of a function and prove nothing; the content is in the
  two theorems it is built from.

  Rust: `services::dns::zone::{Lazy, Provider, Signed}`, `protocols::dns::dnssec::Sign`, and the acceptance
  test's provider and signer combinations.
-/
import Dns.Partial
import Dns.Dnssec

namespace Dns.Records
open Dns.Zone Dns.Dnssec

/-! ## Lazy zones that ask for every name the answer reads -/

/-- The node a provider's RRsets make at `n`: an empty non-terminal when it gives none (RFC 8020), otherwise the
node `Lazy` inserts. -/
def providedNode (apex n : Name) (sets : List RRset) : Node :=
  if sets = [] then .empty else nodeOf apex n sets

def provided (apex n : Name) : Fact (List RRset) → Fact Node
  | .present sets => .present (providedNode apex n sets)
  | .absent => .absent
  | .unknown => .unknown

/-- The facts a lazy zone answers from, all under its one lock: what it holds, and for every other name the
answer reads, what the provider says. -/
def onDemand (p : Provider) (s : Lazy) (n : Name) : Fact Node :=
  if s.zone.presentB n then s.zone.look n else provided s.apex n (p n)

/-- A lazy zone's answer. -/
def lazyAnswer (p : Provider) (s : Lazy) (req : Request) (any : AnyResponse) : Answered :=
  answerWith (onDemand p s) s.apex s.soa any req

/-- The provider a complete zone defines: a node's own RRsets (a cut's NS and DS, not its glue), no RRsets at an
empty non-terminal, and absent for every other name. -/
def zoneProvider (z : Zone) : Provider := fun n =>
  match z.node n with
  | some nd => .present (nodeSets nd)
  | none => if z.presentB n then .present [] else .absent

/-- The lazy zone holds part of `z`: the same apex and SOA, and each fact it holds is `z`'s. -/
def HoldsPart (s : Lazy) (z : Zone) : Prop :=
  s.apex = z.apex ∧ s.soa = z.soa ∧ ∀ n, s.zone.presentB n = true → s.zone.look n = z.look n

/-- Each node of `z` that the lazy zone does not hold is one a provider can describe: its RRsets make the same
node. A cut whose glue matters is held from the start. -/
def Describable (s : Lazy) (z : Zone) : Prop :=
  ∀ n nd, z.node n = some nd → s.zone.presentB n = false → providedNode z.apex n (nodeSets nd) = nd

/-- The provider agrees with `z` on every name the lazy zone does not hold. -/
def ProviderAgrees (p : Provider) (s : Lazy) (z : Zone) : Prop :=
  ∀ n, s.zone.presentB n = false → p n = zoneProvider z n

theorem onDemand_eq {p : Provider} {s : Lazy} {z : Zone} (hs : HoldsPart s z) (hd : Describable s z)
    (hp : ProviderAgrees p s z) : onDemand p s = z.look := by
  funext n
  unfold onDemand
  by_cases hn : s.zone.presentB n = true
  · simp only [hn, ↓reduceIte]; exact hs.2.2 n hn
  · have hn' : s.zone.presentB n = false := by simpa using hn
    simp only [hn', Bool.false_eq_true, ↓reduceIte, hp n hn', zoneProvider, hs.1]
    cases hnode : z.node n with
    | some nd => simp only [provided, hd n nd hnode hn', Zone.look_of_node hnode]
    | none =>
      simp only
      cases hpres : z.presentB n with
      | true => simp [provided, providedNode, Zone.look, hnode, hpres]
      | false => simp [provided, Zone.look, hnode, hpres]

/-- A lazy zone over a provider that agrees with the complete zone `z` answers every question as `z` does. -/
theorem lazy_agrees_complete {p : Provider} {s : Lazy} {z : Zone} (hs : HoldsPart s z) (hd : Describable s z)
    (hp : ProviderAgrees p s z) (req : Request) (any : AnyResponse) : lazyAnswer p s req any = answer z req any := by
  unfold lazyAnswer answer
  rw [onDemand_eq hs hd hp, hs.1, hs.2.1]

/-- A lazy zone that starts with the apex node of `z` holds part of it, when `z` holds no node above its apex. -/
theorem holdsPart_apex (z : Zone) (nd : Node) (rev : Nat) (hnd : z.node z.apex = some nd)
    (hup : ∀ e ∈ z.nodes, e.1 = z.apex ∨ ¬ e.1 <:+ z.apex) : HoldsPart ⟨z.apex, z.soa, [(z.apex, nd)], rev⟩ z := by
  refine ⟨rfl, rfl, fun n hn => ?_⟩
  simp only [Lazy.zone, Zone.presentB, List.any_cons, List.any_nil, Bool.or_false] at hn
  have hsuf : n <:+ z.apex := (under_iff _ _).mp hn
  by_cases he : n = z.apex
  · subst he
    rw [Zone.look_of_node hnd]
    simp [Zone.look, Zone.node, Lazy.zone]
  · have hnone : z.node n = none := by
      cases h : z.node n with
      | none => rfl
      | some nd' =>
        rcases hup (n, nd') (lookup_mem h) with h' | h'
        · exact absurd h' he
        · exact absurd hsuf h'
    have hpres : z.presentB n = true := (z.presentB_mono hsuf (z.node_present hnd))
    have hlook : (⟨z.apex, z.soa, [(z.apex, nd)]⟩ : Zone).node n = none := by
      simp only [Zone.node, List.lookup]
      have : (n == z.apex) = false := by simpa using he
      simp [this]
    have hz : z.look n = .present .empty := by simp [Zone.look, hnone, hpres]
    rw [hz]
    simp only [Zone.look, Lazy.zone, hlook]
    simp [Zone.presentB, hn]

/-- `Describable` as a check over the zone's nodes. -/
def describableB (s : Lazy) (z : Zone) : Bool :=
  z.nodes.all fun e => s.zone.presentB e.1 || providedNode z.apex e.1 (nodeSets e.2) == e.2

theorem describable_of (s : Lazy) (z : Zone) (h : describableB s z = true) : Describable s z := by
  intro n nd hnode hn
  have := (List.all_eq_true.mp h) (n, nd) (lookup_mem hnode)
  simp only [hn, Bool.false_or, beq_iff_eq] at this
  exact this

theorem zoneProvider_agrees (s : Lazy) (z : Zone) : ProviderAgrees (zoneProvider z) s z := fun _ _ => rfl

/-! ## Signers as an interface -/

/-- What a signer offers: Rust's `Sign` trait. Any type can implement it: a key in memory, a key loaded from
PKCS#8, a wrapper around a hardware module. -/
class Sign (σ : Type) (S : SigScheme) where
  dnskey : σ → Key
  sign : σ → Tbs → S.Sig

instance {S : SigScheme} : Sign (Signer S) S := ⟨Signer.dnskey, Signer.sign⟩

variable {S : SigScheme}

/-- What the published records can depend on: each signer's DNSKEY and signing function, in order. -/
def signerView {σ : Type} [Sign σ S] (ss : List σ) : List (Key × (Tbs → S.Sig)) :=
  ss.map fun x => (Sign.dnskey (S := S) x, Sign.sign x)

/-- Two lists of signers, of any two implementations, that agree one for one on DNSKEY and signatures. -/
inductive Agnostic {σ τ : Type} [Sign σ S] [Sign τ S] : List σ → List τ → Prop
  | nil : Agnostic [] []
  | cons {x : σ} {y : τ} {xs : List σ} {ys : List τ} :
      Sign.dnskey (S := S) x = Sign.dnskey (S := S) y → (∀ m, Sign.sign (S := S) x m = Sign.sign y m) →
      Agnostic xs ys → Agnostic (x :: xs) (y :: ys)

/-! ## What an online signer publishes (`Signed<D>`) -/

def signedBy (v : List (Key × (Tbs → S.Sig))) (apex : Name) (w : Window) (labels ttl : Nat) (d : Payload) :
    List (Rrsig S) :=
  v.map fun (k, f) =>
    let h : Header := ⟨k.alg, apex, labels, ttl, w.inception % 4294967296, w.expiration % 4294967296, S.keyTag k⟩
    ⟨h, f ⟨h, d⟩⟩

/-- The signers of the DNSKEY set: the SEP keys, or all when none has the bit. -/
def keyOnes (v : List (Key × (Tbs → S.Sig))) : List (Key × (Tbs → S.Sig)) :=
  if v.any (·.1.sep) then v.filter (·.1.sep) else v

/-- The signers of everything else: the keys without the SEP bit, or all when every key has it. -/
def dataOnes (v : List (Key × (Tbs → S.Sig))) : List (Key × (Tbs → S.Sig)) :=
  if v.any (!·.1.sep) then v.filter (!·.1.sep) else v

/-- The records published for one question. -/
structure Published (S : SigScheme) where
  answered : Answered
  answer : List (RRset × List (Rrsig S))
  authority : List (RRset × List (Rrsig S))
  denial : Fact (List (Signed S))
  keys : Signed S

/-- The labels an RRSIG over a denial record counts: its owner's, and for NSEC3 the hashed label and the
apex. -/
def payloadLabels (apex : Name) : Payload → Nat
  | .nsec r => labelsOf r.owner
  | .nsec3 _ => apex.length + 1
  | .rrset s => labelsOf s.owner
  | .keys o _ => o.length

/-- What the denial of a negative answer is about: the name for NXDOMAIN; for NODATA the type at a name that
exists, or the names below the closest encloser of a wildcard. -/
def deniedKind (look : Name → Fact Node) (apex : Name) (q : Request) (r : Response) (f : Name) : Denied :=
  if r.rcode = .nxdomain then .name
  else match look f with
    | .present _ => .type q.qtype
    | _ =>
      match closestIn look apex f with
      | .present (ce, _) => .wildcard ce
      | _ => .name

/-- The records an online signer publishes over the facts `look` with the signers `v`: the answer, an RRSIG by
each data signer over each answer and authority RRset as served, covering records for a negative answer, and
the DNSKEY set. -/
def publishWith (v : List (Key × (Tbs → S.Sig))) (look : Name → Fact Node) (apex : Name) (soa : RRset)
    (any : AnyResponse) (denial : Denial) (w : Window) (q : Request) : Published S :=
  let keyset : Signed S :=
    ⟨.keys apex (v.map (·.1)), signedBy (keyOnes v) apex w apex.length soa.ttl (.keys apex (v.map (·.1)))⟩
  let signSet (s : RRset) : RRset × List (Rrsig S) :=
    (s, signedBy (dataOnes v) apex w s.owner.length s.ttl (.rrset s))
  match answerWith look apex soa any q with
  | .response r =>
    let f := finalName q r
    let denialRecords : Fact (List (Signed S)) :=
      if negativeAnswer r then
        match cover (S := S) look apex denial f (deniedKind look apex q r f) with
        | .present ps =>
          .present (ps.map fun d => ⟨d, signedBy (dataOnes v) apex w (payloadLabels apex d) (negTtl soa) d⟩)
        | .absent => .absent
        | .unknown => .unknown
      else .present []
    ⟨.response r, r.answer.map signSet, r.authority.map signSet, denialRecords, keyset⟩
  | .unknown n => ⟨.unknown n, [], [], .unknown, keyset⟩

def publish {σ : Type} [Sign σ S] (ss : List σ) (look : Name → Fact Node) (apex : Name) (soa : RRset)
    (any : AnyResponse) (denial : Denial) (w : Window) (q : Request) : Published S :=
  publishWith (signerView ss) look apex soa any denial w q

theorem signerView_eq {σ τ : Type} [Sign σ S] [Sign τ S] {xs : List σ} {ys : List τ} (h : Agnostic (S := S) xs ys) :
    signerView (S := S) xs = signerView (S := S) ys := by
  induction h with
  | nil => rfl
  | cons hk hs _ ih =>
    simp only [signerView, List.map_cons, List.cons.injEq, Prod.mk.injEq] at ih ⊢
    exact ⟨⟨hk, funext hs⟩, ih⟩

/-- Two signers that agree on DNSKEY and signatures publish the same records, whatever they are inside. -/
theorem signer_agnostic {σ τ : Type} [Sign σ S] [Sign τ S] {xs : List σ} {ys : List τ} (h : Agnostic (S := S) xs ys)
    (look : Name → Fact Node) (apex : Name) (soa : RRset) (any : AnyResponse) (denial : Denial) (w : Window)
    (q : Request) :
    publish (S := S) xs look apex soa any denial w q = publish (S := S) ys look apex soa any denial w q := by
  unfold publish
  rw [signerView_eq h]

/-! ## The validator sees only published records -/

/-- What a validating client concludes from published records: nothing when no answer was published, else a
result for each answer RRset and, for a negative answer, for its denial. The zone's own link carries the
published DNSKEY set below the links `pre` and the parent's DS answer `parent`. -/
def validatePublished (A : Option (List Anchor)) (P : AlgorithmPolicy) (t : Nat) (pre : Chain S)
    (parent : Option (Delegation S)) (apex : Name) (q : Request) (pub : Published S) :
    Option (List Validation × Option Validation) :=
  let C := pre ++ [⟨apex, parent, some pub.keys⟩]
  match pub.answered, pub.denial with
  | .unknown _, _ => none
  | .response r, d =>
    let ds := match d with
      | .present ds => ds
      | _ => []
    some (pub.answer.map (fun (s, sigs) => validateRrset A P t C s sigs ds),
      if negativeAnswer r then
        (match d with
          | .present _ => some (validateDenial A P t C ⟨finalName q r, q.qtype⟩ r.rcode ds)
          | _ => some .indeterminate)
      else none)

/-- Equal published records reach equal validation: whatever lazy zone over whatever agreeing provider serves
the data, and whichever implementation signs it, the validator reaches what it reaches for the complete zone
signed by any signer that agrees on DNSKEY and signatures. It is the composition of `lazy_agrees_complete`
(through `onDemand_eq`, so the covering records agree too) and `signer_agnostic`. -/
theorem validate_records_only {σ τ : Type} [Sign σ S] [Sign τ S] {p : Provider} {s : Lazy} {z : Zone}
    (hs : HoldsPart s z) (hd : Describable s z) (hp : ProviderAgrees p s z) {xs : List σ} {ys : List τ}
    (hxy : Agnostic (S := S) xs ys) (A : Option (List Anchor)) (P : AlgorithmPolicy) (t : Nat) (pre : Chain S)
    (parent : Option (Delegation S)) (any : AnyResponse) (denial : Denial) (w : Window) (q : Request) :
    validatePublished A P t pre parent s.apex q (publish (S := S) xs (onDemand p s) s.apex s.soa any denial w q) =
      validatePublished A P t pre parent z.apex q (publish (S := S) ys z.look z.apex z.soa any denial w q) := by
  rw [onDemand_eq hs hd hp, hs.1, hs.2.1, signer_agnostic hxy]

/-- So two lazy zones over two providers that agree with the same complete zone, signed by two agreeing
signers, lead the validator to the same result. -/
theorem validate_providers_agree {σ τ : Type} [Sign σ S] [Sign τ S] {p₁ p₂ : Provider} {s₁ s₂ : Lazy} {z : Zone}
    (hs₁ : HoldsPart s₁ z) (hd₁ : Describable s₁ z) (hp₁ : ProviderAgrees p₁ s₁ z)
    (hs₂ : HoldsPart s₂ z) (hd₂ : Describable s₂ z) (hp₂ : ProviderAgrees p₂ s₂ z)
    {xs : List σ} {ys : List τ} (hxy : Agnostic (S := S) xs ys) (A : Option (List Anchor)) (P : AlgorithmPolicy)
    (t : Nat) (pre : Chain S) (parent : Option (Delegation S)) (any : AnyResponse) (denial : Denial) (w : Window)
    (q : Request) :
    validatePublished A P t pre parent s₁.apex q
        (publish (S := S) xs (onDemand p₁ s₁) s₁.apex s₁.soa any denial w q) =
      validatePublished A P t pre parent s₂.apex q
        (publish (S := S) ys (onDemand p₂ s₂) s₂.apex s₂.soa any denial w q) := by
  rw [validate_records_only hs₁ hd₁ hp₁ hxy, ← validate_records_only hs₂ hd₂ hp₂ (Agnostic.refl ys)]
where
  Agnostic.refl {ρ : Type} [Sign ρ S] : ∀ (l : List ρ), Agnostic (S := S) l l
    | [] => .nil
    | _ :: l => .cons rfl (fun _ => rfl) (Agnostic.refl l)

end Dns.Records
