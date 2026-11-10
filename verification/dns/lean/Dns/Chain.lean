/-
  `check_chain`: an advisory check over the signed zones a world built. It reports a DS set that names
  none of the child's keys, a delegation without DS whose parent gives no proof of that, a signature window
  closed at the check's time, the key algorithms of a zone none of whose keys uses an algorithm the policy
  validates, and the algorithms of a DS set none of whose records does, since one such algorithm is enough
  for a path (RFC 6840 §5.11). A world that wants a broken chain on purpose leaves the problem in, and the
  resolver then does the standard thing.

  `check_sound`: when the check reports nothing, every RRset each zone serves validates Secure or Insecure
  along the chain from the anchor, never Bogus or Indeterminate. `check_complete`: every problem the tree
  has is reported, and `check_reports_real`: nothing else is.

  The tree is a list of signed zones; a zone's parent is the zone whose apex is its deepest strict ancestor.

  Rust: `services::dns::zone::chain::{check_chain, ChainProblem}`. Rust also verifies every signature, and
  reports an RRset left without a signature in an algorithm the policy validates as a problem of its own. In
  this model every data signer signs every RRset, so `check_sound` takes that as `DataAlgorithms`.
-/
import Dns.Dnssec

namespace Dns.Chain
open Dns.Zone Dns.Dnssec

variable {S : SigScheme}

inductive Problem where
  | dsMismatch (parent child : Name)
  | noDsProofMissing (parent child : Name)
  | windowClosed (apex : Name) (time : Nat)
  | unsupportedAlgorithm (apex : Name) (alg : Nat)
deriving DecidableEq, Repr

abbrev Tree (S : SigScheme) := List (SignedZone S)

/-- Keeps the deeper of the best parent so far and `z`, when `z`'s apex is strictly above `c`. -/
def parentStep (c : Name) (best : Option (SignedZone S)) (z : SignedZone S) : Option (SignedZone S) :=
  if strictly c z.apex then
    match best with
    | some b => if b.apex.length < z.apex.length then some z else best
    | none => some z
  else best

/-- The parent of `c` in the tree: the zone whose apex is the deepest strict ancestor of `c`'s. -/
def parentOf (tr : Tree S) (c : SignedZone S) : Option (SignedZone S) := tr.foldl (parentStep c.apex) none

/-- The DS RRset the parent holds at the child's apex, if it holds a cut there with one. -/
def dsAt (p : SignedZone S) (c : Name) : Option RRset :=
  match p.zone.node c with
  | some (.cut _ ds _) => ds
  | _ => none

/-! ## The check -/

/-- Whether the policy validates some key algorithm among `keys`. -/
def anyValidated (P : AlgorithmPolicy) (keys : List Key) : Bool := keys.any fun k => P.validate.contains k.alg

/-- The algorithms of a DS set at the cut `n` when none of them is one the policy validates: one DS record with
such an algorithm is enough for a path (RFC 6840 §5.11), and with none the child is Insecure (RFC 9905 §2). -/
def dsProblems (P : AlgorithmPolicy) : Name × Node → List Problem
  | (n, .cut _ (some set) _) =>
    if (dsOf set).any (fun d => P.validate.contains d.keyAlg) then []
    else (dsOf set).map fun d => .unsupportedAlgorithm n d.keyAlg
  | _ => []

/-- Problems of one zone: its window is closed at `t`; none of its keys uses an algorithm the policy validates,
when each key's algorithm is reported (RFC 6840 §5.11); and the DS sets at its cuts whose algorithms the policy
does not validate. An unsigned zone has no window and no key to report. -/
def zoneProblems (P : AlgorithmPolicy) (t : Nat) (z : SignedZone S) : List Problem :=
  (if z.signers ≠ [] ∧ z.window.holds t = false then [.windowClosed z.apex t] else []) ++
    (if anyValidated P z.keys then [] else z.signers.map fun s => .unsupportedAlgorithm z.apex s.dnskey.alg) ++
    z.zone.nodes.flatMap (dsProblems P)

/-- The parent's DS set for `c` is empty, or the policy supports some of it and none of it names a SEP key of
`c`. -/
def dsMismatchB (P : AlgorithmPolicy) (p c : SignedZone S) : Bool :=
  match dsAt p c.apex with
  | some set =>
    dsOf set == [] ||
      (supported P (dsOf set) != [] && anchored (S := S) c.apex (supported P (dsOf set)) c.keys == [])
  | none => false

/-- The parent delegates to `c` without DS and its referral proves nothing about DS, or it does not delegate
to `c` at all. -/
def noDsMissingB (P : AlgorithmPolicy) (p c : SignedZone S) : Bool :=
  match p.zone.node c.apex with
  | some (.cut _ none _) => (noDsProof (S := S) P c.apex ((p.noDsRecords c.apex).map (·.data))).isNone
  | some (.cut _ (some _) _) => false
  | _ => true

def edgeProblems (P : AlgorithmPolicy) (p c : SignedZone S) : List Problem :=
  (if dsMismatchB P p c then [.dsMismatch p.apex c.apex] else []) ++
    (if noDsMissingB P p c then [.noDsProofMissing p.apex c.apex] else [])

/-- `check_chain`: every zone's problems, and every delegation's from its parent. -/
def check (tr : Tree S) (P : AlgorithmPolicy) (t : Nat) : List Problem :=
  tr.flatMap (zoneProblems P t) ++
    tr.flatMap fun c =>
      match parentOf tr c with
      | some p => edgeProblems P p c
      | none => []

/-! ## The problems as propositions -/

/-- What each problem says about the tree. -/
def Holds (tr : Tree S) (P : AlgorithmPolicy) (t : Nat) : Problem → Prop
  | .windowClosed a time =>
    ∃ z ∈ tr, z.apex = a ∧ time = t ∧ z.signers ≠ [] ∧ z.window.holds t = false
  | .unsupportedAlgorithm a alg =>
    (∃ z ∈ tr, z.apex = a ∧ (∃ s ∈ z.signers, s.dnskey.alg = alg) ∧ ∀ s ∈ z.signers, s.dnskey.alg ∉ P.validate) ∨
      ∃ z ∈ tr, ∃ ns set g, (a, Node.cut ns (some set) g) ∈ z.zone.nodes ∧ (∃ d ∈ dsOf set, d.keyAlg = alg) ∧
        ∀ d ∈ dsOf set, d.keyAlg ∉ P.validate
  | .dsMismatch pa ca =>
    ∃ c ∈ tr, ∃ p, parentOf tr c = some p ∧ p.apex = pa ∧ c.apex = ca ∧ ∃ set, dsAt p c.apex = some set ∧
      (dsOf set = [] ∨ ((∃ d ∈ dsOf set, P.treat d.keyAlg d.dtype = .supported) ∧
        ¬ ∃ k ∈ c.keys, k.sep = true ∧ ∃ d ∈ dsOf set, P.treat d.keyAlg d.dtype = .supported ∧ d.keyAlg = k.alg ∧
          d.digest = S.digest c.apex k))
  | .noDsProofMissing pa ca =>
    ∃ c ∈ tr, ∃ p, parentOf tr c = some p ∧ p.apex = pa ∧ c.apex = ca ∧
      ((∃ ns g, p.zone.node c.apex = some (.cut ns none g) ∧
          ∀ w, ¬ NoDsEvidence (S := S) P c.apex ((p.noDsRecords c.apex).map (·.data)) w) ∨
        ∀ ns ds g, p.zone.node c.apex ≠ some (.cut ns ds g))

theorem anyValidated_false {P : AlgorithmPolicy} {z : SignedZone S} :
    anyValidated P z.keys = false ↔ ∀ s ∈ z.signers, s.dnskey.alg ∉ P.validate := by
  simp [anyValidated, SignedZone.keys]

theorem mem_dsProblems {P : AlgorithmPolicy} {n : Name} {nd : Node} {prob : Problem} :
    prob ∈ dsProblems P (n, nd) ↔ ∃ ns set g, nd = .cut ns (some set) g ∧
      (∃ d ∈ dsOf set, prob = .unsupportedAlgorithm n d.keyAlg) ∧ ∀ d ∈ dsOf set, d.keyAlg ∉ P.validate := by
  cases nd with
  | cut ns ds g =>
    cases ds with
    | none => simp [dsProblems]
    | some set =>
      constructor
      · intro h
        simp only [dsProblems] at h
        split at h
        · cases h
        · rename_i hv
          obtain ⟨d, hd, rfl⟩ := List.mem_map.mp h
          refine ⟨ns, set, g, rfl, ⟨d, hd, rfl⟩, fun d' hd' hm => hv ?_⟩
          exact List.any_eq_true.mpr ⟨d', hd', by simpa using hm⟩
      · rintro ⟨ns', set', g', heq, ⟨d, hd, rfl⟩, hall⟩
        cases heq
        simp only [dsProblems]
        split
        · rename_i hv
          obtain ⟨d', hd', hc⟩ := List.any_eq_true.mp hv
          exact absurd (by simpa using hc) (hall d' hd')
        · exact List.mem_map.mpr ⟨d, hd, rfl⟩
  | data _ => simp [dsProblems]
  | dname _ _ => simp [dsProblems]
  | empty => simp [dsProblems]

theorem zoneProblems_iff {P : AlgorithmPolicy} {t : Nat} {z : SignedZone S} {prob : Problem} :
    prob ∈ zoneProblems P t z ↔
      (prob = .windowClosed z.apex t ∧ z.signers ≠ [] ∧ z.window.holds t = false) ∨
        (∃ s ∈ z.signers, prob = .unsupportedAlgorithm z.apex s.dnskey.alg ∧
          ∀ s' ∈ z.signers, s'.dnskey.alg ∉ P.validate) ∨
        ∃ n ns set g, (n, Node.cut ns (some set) g) ∈ z.zone.nodes ∧
          (∃ d ∈ dsOf set, prob = .unsupportedAlgorithm n d.keyAlg) ∧ ∀ d ∈ dsOf set, d.keyAlg ∉ P.validate := by
  unfold zoneProblems
  simp only [List.mem_append, List.mem_flatMap]
  constructor
  · rintro ((h | h) | ⟨e, he, h⟩)
    · split at h
      · rename_i hc; exact Or.inl ⟨List.mem_singleton.mp h, hc⟩
      · cases h
    · split at h
      · cases h
      · rename_i hv
        obtain ⟨s, hs, rfl⟩ := List.mem_map.mp h
        exact Or.inr (Or.inl ⟨s, hs, rfl, anyValidated_false.mp (by simpa using hv)⟩)
    · obtain ⟨n, nd⟩ := e
      obtain ⟨ns, set, g, rfl, hd, hall⟩ := mem_dsProblems.mp h
      exact Or.inr (Or.inr ⟨n, ns, set, g, he, hd, hall⟩)
  · rintro (⟨rfl, hc⟩ | ⟨s, hs, rfl, hall⟩ | ⟨n, ns, set, g, he, hd, hall⟩)
    · left; left; simp [hc]
    · left; right
      rw [show anyValidated P z.keys = false from anyValidated_false.mpr hall]
      exact List.mem_map.mpr ⟨s, hs, rfl⟩
    · right
      exact ⟨(n, .cut ns (some set) g), he, mem_dsProblems.mpr ⟨ns, set, g, rfl, hd, hall⟩⟩

theorem dsMismatchB_iff {P : AlgorithmPolicy} {p c : SignedZone S} :
    dsMismatchB P p c = true ↔ ∃ set, dsAt p c.apex = some set ∧
      (dsOf set = [] ∨ ((∃ d ∈ dsOf set, P.treat d.keyAlg d.dtype = .supported) ∧
        ¬ ∃ k ∈ c.keys, k.sep = true ∧ ∃ d ∈ dsOf set, P.treat d.keyAlg d.dtype = .supported ∧ d.keyAlg = k.alg ∧
          d.digest = S.digest c.apex k)) := by
  unfold dsMismatchB
  cases dsAt p c.apex with
  | none => simp
  | some set =>
    simp only [Option.some.injEq, exists_eq_left', Bool.or_eq_true, beq_iff_eq, Bool.and_eq_true, bne_iff_ne, ne_eq]
    have hsup : ¬ supported P (dsOf set) = [] ↔ ∃ d ∈ dsOf set, P.treat d.keyAlg d.dtype = .supported := by
      constructor
      · intro h
        obtain ⟨d, hd⟩ := List.exists_mem_of_ne_nil _ h
        exact ⟨d, mem_supported.mp hd⟩
      · rintro ⟨d, hd, ht⟩
        exact List.ne_nil_of_mem (mem_supported.mpr ⟨hd, ht⟩)
    have hanc : anchored (S := S) c.apex (supported P (dsOf set)) c.keys = [] ↔
        ¬ ∃ k ∈ c.keys, k.sep = true ∧ ∃ d ∈ dsOf set, P.treat d.keyAlg d.dtype = .supported ∧ d.keyAlg = k.alg ∧
          d.digest = S.digest c.apex k := by
      rw [List.eq_nil_iff_forall_not_mem]
      constructor
      · rintro h ⟨k, hk, hsep, d, hd, hdt, hda, hdd⟩
        exact h k (mem_anchored.mpr ⟨hk, hsep, d, mem_supported.mpr ⟨hd, hdt⟩, hda, hdd⟩)
      · intro h k hk
        obtain ⟨hk, hsep, d, hd, hda, hdd⟩ := mem_anchored.mp hk
        exact h ⟨k, hk, hsep, d, (mem_supported.mp hd).1, (mem_supported.mp hd).2, hda, hdd⟩
    rw [hsup, hanc]

theorem noDsMissingB_iff {P : AlgorithmPolicy} {p c : SignedZone S} :
    noDsMissingB P p c = true ↔
      (∃ ns g, p.zone.node c.apex = some (.cut ns none g) ∧
          ∀ w, ¬ NoDsEvidence (S := S) P c.apex ((p.noDsRecords c.apex).map (·.data)) w) ∨
        ∀ ns ds g, p.zone.node c.apex ≠ some (.cut ns ds g) := by
  unfold noDsMissingB
  cases hn : p.zone.node c.apex with
  | none => simp
  | some nd =>
    cases nd with
    | cut ns ds g =>
      cases ds with
      | none =>
        simp only [Option.isNone_iff_eq_none]
        constructor
        · intro h
          refine Or.inl ⟨ns, g, rfl, fun w hw => ?_⟩
          obtain ⟨w', hw'⟩ := noDsProof_of_evidence hw
          rw [h] at hw'; cases hw'
        · rintro (⟨_, _, _, hev⟩ | hno)
          · cases hp : noDsProof (S := S) P c.apex ((p.noDsRecords c.apex).map (·.data)) with
            | none => rfl
            | some w => exact absurd (noDsProof_some hp) (hev w)
          · exact absurd rfl (hno ns none g)
      | some set =>
        simp only [Bool.false_eq_true, false_iff, not_or]
        refine ⟨?_, fun h => h ns (some set) g rfl⟩
        rintro ⟨_, _, h, _⟩
        simp at h
    | data _ => simp
    | dname _ _ => simp
    | empty => simp

theorem edgeProblems_iff {P : AlgorithmPolicy} {p c : SignedZone S} {prob : Problem} :
    prob ∈ edgeProblems P p c ↔
      (prob = .dsMismatch p.apex c.apex ∧ dsMismatchB P p c = true) ∨
        (prob = .noDsProofMissing p.apex c.apex ∧ noDsMissingB P p c = true) := by
  unfold edgeProblems
  simp only [List.mem_append]
  constructor
  · rintro (h | h)
    · split at h
      · exact Or.inl ⟨List.mem_singleton.mp h, by assumption⟩
      · cases h
    · split at h
      · exact Or.inr ⟨List.mem_singleton.mp h, by assumption⟩
      · cases h
  · rintro (⟨rfl, h⟩ | ⟨rfl, h⟩)
    · left; simp [h]
    · right; simp [h]

theorem mem_check {tr : Tree S} {P : AlgorithmPolicy} {t : Nat} {prob : Problem} :
    prob ∈ check tr P t ↔ (∃ z ∈ tr, prob ∈ zoneProblems P t z) ∨
      ∃ c ∈ tr, ∃ p, parentOf tr c = some p ∧ prob ∈ edgeProblems P p c := by
  unfold check
  simp only [List.mem_append, List.mem_flatMap]
  constructor
  · rintro (h | ⟨c, hc, h⟩)
    · exact Or.inl h
    · right
      cases hp : parentOf tr c with
      | none => rw [hp] at h; cases h
      | some p => rw [hp] at h; exact ⟨c, hc, p, hp, h⟩
  · rintro (h | ⟨c, hc, p, hp, h⟩)
    · exact Or.inl h
    · right; exact ⟨c, hc, by rw [hp]; exact h⟩

/-- Every problem the tree has is reported. -/
theorem check_complete {tr : Tree S} {P : AlgorithmPolicy} {t : Nat} {prob : Problem} (h : Holds tr P t prob) :
    prob ∈ check tr P t := by
  rw [mem_check]
  cases prob with
  | windowClosed a time =>
    obtain ⟨z, hz, rfl, rfl, hs, hw⟩ := h
    exact Or.inl ⟨z, hz, zoneProblems_iff.mpr (Or.inl ⟨rfl, hs, hw⟩)⟩
  | unsupportedAlgorithm a alg =>
    rcases h with ⟨z, hz, rfl, ⟨s, hs, rfl⟩, hall⟩ | ⟨z, hz, ns, set, g, he, ⟨d, hd, rfl⟩, hall⟩
    · exact Or.inl ⟨z, hz, zoneProblems_iff.mpr (Or.inr (Or.inl ⟨s, hs, rfl, hall⟩))⟩
    · exact Or.inl ⟨z, hz, zoneProblems_iff.mpr (Or.inr (Or.inr ⟨a, ns, set, g, he, ⟨d, hd, rfl⟩, hall⟩))⟩
  | dsMismatch pa ca =>
    obtain ⟨c, hc, p, hp, rfl, rfl, h⟩ := h
    exact Or.inr ⟨c, hc, p, hp, edgeProblems_iff.mpr (Or.inl ⟨rfl, dsMismatchB_iff.mpr h⟩)⟩
  | noDsProofMissing pa ca =>
    obtain ⟨c, hc, p, hp, rfl, rfl, h⟩ := h
    exact Or.inr ⟨c, hc, p, hp, edgeProblems_iff.mpr (Or.inr ⟨rfl, noDsMissingB_iff.mpr h⟩)⟩

/-- And nothing the tree does not have. -/
theorem check_reports_real {tr : Tree S} {P : AlgorithmPolicy} {t : Nat} {prob : Problem}
    (h : prob ∈ check tr P t) : Holds tr P t prob := by
  rcases mem_check.mp h with ⟨z, hz, h⟩ | ⟨c, hc, p, hp, h⟩
  · rcases zoneProblems_iff.mp h with ⟨rfl, hs, hw⟩ | ⟨s, hs, rfl, hall⟩ | ⟨n, ns, set, g, he, ⟨d, hd, rfl⟩, hall⟩
    · exact ⟨z, hz, rfl, rfl, hs, hw⟩
    · exact Or.inl ⟨z, hz, rfl, ⟨s, hs, rfl⟩, hall⟩
    · exact Or.inr ⟨z, hz, ns, set, g, he, ⟨d, hd, rfl⟩, hall⟩
  · rcases edgeProblems_iff.mp h with ⟨rfl, hm⟩ | ⟨rfl, hm⟩
    · exact ⟨c, hc, p, hp, rfl, rfl, dsMismatchB_iff.mp hm⟩
    · exact ⟨c, hc, p, hp, rfl, rfl, noDsMissingB_iff.mp hm⟩

/-! ## The chain a path down the tree gives -/

/-- The link for `c` below its parent `p`: the parent's DS set with its RRSIGs, or its proof that there is none
(no proof at all when it does not delegate to `c`), and `c`'s DNSKEY set. -/
def linkBelow (p c : SignedZone S) : Link S :=
  ⟨c.apex, some (match p.zone.node c.apex with
    | some (.cut _ (some set) _) => .ds (p.signSet set)
    | some (.cut _ none _) => .noDs (p.noDsRecords c.apex)
    | _ => .noDs []), some c.keySet⟩

theorem linkBelow_apex (p c : SignedZone S) : (linkBelow p c).apex = c.apex := rfl

def pairs : SignedZone S → List (SignedZone S) → Chain S
  | _, [] => []
  | p, c :: cs => linkBelow p c :: pairs c cs

/-- The chain for a path starting at the anchored zone `z0`. -/
def chainOf (z0 : SignedZone S) (rest : List (SignedZone S)) : Chain S := z0.link :: pairs z0 rest

/-- A path down the tree from `p` to `last`: each zone's parent is the one before it. -/
inductive Descends (tr : Tree S) : SignedZone S → List (SignedZone S) → SignedZone S → Prop
  | nil {z : SignedZone S} : Descends tr z [] z
  | cons {p c : SignedZone S} {cs : List (SignedZone S)} {last : SignedZone S} :
      c ∈ tr → parentOf tr c = some p → Descends tr c cs last → Descends tr p (c :: cs) last

theorem foldl_parentStep (c : Name) : ∀ (tr : Tree S) (init : Option (SignedZone S)),
    ∀ z, tr.foldl (parentStep c) init = some z → init = some z ∨ (z ∈ tr ∧ strictly c z.apex = true) := by
  intro tr
  induction tr with
  | nil => intro init z h; exact Or.inl h
  | cons b tr ih =>
    intro init z h
    simp only [List.foldl_cons] at h
    rcases ih _ z h with h | h
    · unfold parentStep at h
      by_cases hu : strictly c b.apex = true
      · simp only [hu, ↓reduceIte] at h
        cases init with
        | none => cases h; exact Or.inr ⟨List.mem_cons_self, hu⟩
        | some y =>
          simp only at h
          split at h
          · cases h; exact Or.inr ⟨List.mem_cons_self, hu⟩
          · exact Or.inl h
      · simp only [hu, Bool.false_eq_true, ↓reduceIte] at h; exact Or.inl h
    · exact Or.inr ⟨List.mem_cons_of_mem _ h.1, h.2⟩

theorem parentOf_some {tr : Tree S} {c p : SignedZone S} (h : parentOf tr c = some p) :
    p ∈ tr ∧ strictly c.apex p.apex = true := by
  rcases foldl_parentStep c.apex tr none p h with h | h
  · cases h
  · exact h

theorem descends_last_mem {tr : Tree S} {p : SignedZone S} {cs : List (SignedZone S)} {last : SignedZone S}
    (h : Descends tr p cs last) (hp : p ∈ tr) : last ∈ tr := by
  induction h with
  | nil => exact hp
  | cons hcm _ _ ih => exact ih hcm

theorem under_trans {a b c : Name} (h1 : under a b = true) (h2 : under b c = true) : under a c = true :=
  (under_iff a c).mpr (((under_iff b c).mp h2).trans ((under_iff a b).mp h1))

theorem under_of_strictly {a b : Name} (h : strictly a b = true) : under a b = true := by
  simp only [strictly, Bool.and_eq_true] at h; exact h.1

theorem descends_under {tr : Tree S} {p : SignedZone S} {cs : List (SignedZone S)} {last : SignedZone S}
    (h : Descends tr p cs last) : under last.apex p.apex = true := by
  induction h with
  | nil => exact (under_iff _ _).mpr (List.suffix_refl _)
  | cons _ hp _ ih => exact under_trans ih (under_of_strictly (parentOf_some hp).2)

/-! ## Soundness -/

/-- What the soundness of the check rests on besides the check: honest signers, and DS sets that are DS
RRsets owned by the child. -/
structure WellFormed (tr : Tree S) : Prop where
  honest : ∀ z ∈ tr, ∀ s ∈ z.signers, s.Honest
  dsSets : ∀ z ∈ tr, ∀ n ns set g, z.zone.node n = some (.cut ns (some set) g) → set.owner = n ∧ set.rtype = 43

/-- The DS-set condition of `WellFormed` as a check over the zones' nodes. -/
def dsSetsB (tr : Tree S) : Bool :=
  tr.all fun z => z.zone.nodes.all fun e =>
    match e.2 with
    | .cut _ (some set) _ => set.owner == e.1 && set.rtype == 43
    | _ => true

theorem dsSets_of {tr : Tree S} (h : dsSetsB tr = true) :
    ∀ z ∈ tr, ∀ n ns set g, z.zone.node n = some (.cut ns (some set) g) → set.owner = n ∧ set.rtype = 43 := by
  intro z hz n ns set g hn
  have := (List.all_eq_true.mp ((List.all_eq_true.mp h) z hz)) (n, .cut ns (some set) g) (lookup_mem hn)
  simpa using this

/-- What Rust's check that every RRset carries a signature in an algorithm the policy validates adds to `check` in
this model, where every data signer signs every RRset: when some key of a zone uses such an algorithm, a key that
signs its data does too. Rust reports each RRset without one as a problem of its own. -/
def DataAlgorithms (tr : Tree S) (P : AlgorithmPolicy) : Prop :=
  ∀ z ∈ tr, (∃ s ∈ z.signers, P.validate.contains s.dnskey.alg = true) →
    ∃ s ∈ dataSigners z.signers, P.validate.contains s.dnskey.alg = true

theorem zone_signsWell {tr : Tree S} {P : AlgorithmPolicy} {t : Nat} (hc : check tr P t = []) (hwf : WellFormed tr)
    (hd : DataAlgorithms tr P) {z : SignedZone S} (hz : z ∈ tr) (hne : z.signers ≠ []) : SignsWell z P t := by
  refine ⟨hwf.honest z hz, hd z hz ?_, ?_⟩
  · apply Classical.byContradiction
    intro hno
    have hall : ∀ s ∈ z.signers, s.dnskey.alg ∉ P.validate := by
      intro s hs ha
      exact hno ⟨s, hs, by simpa using ha⟩
    obtain ⟨s, hs⟩ := List.exists_mem_of_ne_nil _ hne
    have : Problem.unsupportedAlgorithm z.apex s.dnskey.alg ∈ check tr P t :=
      mem_check.mpr (Or.inl ⟨z, hz, zoneProblems_iff.mpr (Or.inr (Or.inl ⟨s, hs, rfl, hall⟩))⟩)
    rw [hc] at this; cases this
  · apply Classical.byContradiction
    intro hw
    have : Problem.windowClosed z.apex t ∈ check tr P t :=
      mem_check.mpr (Or.inl ⟨z, hz, zoneProblems_iff.mpr (Or.inl ⟨rfl, hne, Bool.eq_false_iff.mpr hw⟩)⟩)
    rw [hc] at this; cases this

theorem sigsBy_verifies {sz : SignedZone S} {P : AlgorithmPolicy} {t : Nat} (hw : SignsWell sz P t)
    (lbl ttl : Nat) (d : Payload) (cover : Header → Option Payload)
    (hcov : ∀ h : Header, h.labels = lbl → h.ttl = ttl → cover h = some d) :
    (sigsBy (dataSigners sz.signers) sz.apex sz.window lbl ttl d).any (verifies P t sz.apex sz.keys cover) =
      true := by
  obtain ⟨s1, hs1, ha1⟩ := hw.dataAlg
  have hs1' := mem_dataSigners hs1
  refine any_verifies_iff.mpr ⟨_, List.mem_map.mpr ⟨s1, hs1, rfl⟩, ?_, hw.windowOk _ _ _ _ _, d, hcov _ rfl rfl,
    s1.dnskey, List.mem_map.mpr ⟨s1, hs1', rfl⟩, rfl, rfl, honest_verifies (hw.honest s1 hs1') _ _⟩
  simp only [usable, beq_self_eq_true, ha1, Bool.and_self, Bool.true_and, List.any_eq_true, beq_iff_eq]
  exact ⟨s1.dnskey, List.mem_map.mpr ⟨s1, hs1', rfl⟩, rfl⟩

/-- The records made by the zone's data signers. -/
def ByData (sz : SignedZone S) (d : Signed S) : Prop :=
  ∃ lbl ttl, d.sigs = sigsBy (dataSigners sz.signers) sz.apex sz.window lbl ttl d.data

theorem noDsRecords_form (sz : SignedZone S) (m : Name) : ∀ d ∈ sz.noDsRecords m, ByData sz d := by
  have h1 : ∀ f d, d ∈ sz.nsecWith f → ByData sz d := by
    intro f d hd
    simp only [SignedZone.nsecWith, Option.mem_toList, Option.map_eq_some_iff] at hd
    obtain ⟨r, _, rfl⟩ := hd
    exact ⟨_, _, rfl⟩
  have h3 : ∀ f d, d ∈ sz.nsec3With f → ByData sz d := by
    intro f d hd
    simp only [SignedZone.nsec3With, Option.mem_toList, Option.map_eq_some_iff] at hd
    obtain ⟨r, _, rfl⟩ := hd
    exact ⟨_, _, rfl⟩
  intro d hd
  unfold SignedZone.noDsRecords at hd
  split at hd
  · exact h1 _ d hd
  · split at hd
    · exact h3 _ d hd
    · rcases List.mem_append.mp hd with hd | hd
      · exact h3 _ d hd
      · exact h3 _ d hd

theorem verified_noDs {sz : SignedZone S} {P : AlgorithmPolicy} {t : Nat} (hw : SignsWell sz P t) (m : Name) :
    verified P t sz.apex sz.keys (sz.noDsRecords m) = (sz.noDsRecords m).map (·.data) := by
  unfold verified
  rw [List.filter_eq_self.mpr]
  intro d hd
  obtain ⟨lbl, ttl, hs⟩ := noDsRecords_form sz m d hd
  rw [hs]
  exact sigsBy_verifies hw lbl ttl d.data _ fun _ _ _ => rfl

/-- One step down a path: from the trusted zone `p`, the link to its child `c` is trusted with `c`'s keys or
stops Insecure. -/
theorem link_step {tr : Tree S} {P : AlgorithmPolicy} {t : Nat} (hc : check tr P t = []) (hwf : WellFormed tr)
    (hdata : DataAlgorithms tr P)
    {owner : Name} {p c : SignedZone S} (hp : p ∈ tr) (hpne : p.signers ≠ []) (hcm : c ∈ tr)
    (hpar : parentOf tr c = some p) (hu : under owner c.apex = true) :
    (linkStep P t owner p.apex p.keys (linkBelow p c) = .ok c.keys ∧ c.signers ≠ []) ∨
      ∃ w, linkStep P t owner p.apex p.keys (linkBelow p c) = .error (.insecure w) := by
  have hpw := zone_signsWell hc hwf hdata hp hpne
  have hedge : edgeProblems P p c = [] := by
    cases h : edgeProblems P p c with
    | nil => rfl
    | cons prob _ =>
      have : prob ∈ check tr P t := mem_check.mpr (Or.inr ⟨c, hcm, p, hpar, by rw [h]; exact List.mem_cons_self⟩)
      rw [hc] at this; cases this
  have hnm : dsMismatchB P p c = false := by
    cases h : dsMismatchB P p c
    · rfl
    · have : Problem.dsMismatch p.apex c.apex ∈ edgeProblems P p c := edgeProblems_iff.mpr (Or.inl ⟨rfl, h⟩)
      rw [hedge] at this; cases this
  have hnd : noDsMissingB P p c = false := by
    cases h : noDsMissingB P p c
    · rfl
    · have : Problem.noDsProofMissing p.apex c.apex ∈ edgeProblems P p c := edgeProblems_iff.mpr (Or.inr ⟨rfl, h⟩)
      rw [hedge] at this; cases this
  have hstrict := (parentOf_some hpar).2
  unfold linkStep linkBelow
  simp only [hstrict, hu, Bool.and_self, Bool.not_true, Bool.false_eq_true, ↓reduceIte]
  unfold noDsMissingB at hnd
  unfold dsMismatchB dsAt at hnm
  cases hn : p.zone.node c.apex with
  | none => rw [hn] at hnd; cases hnd
  | some nd =>
    rw [hn] at hnd hnm
    cases nd with
    | data _ => cases hnd
    | dname _ _ => cases hnd
    | empty => cases hnd
    | cut ns ds g =>
      cases ds with
      | none =>
        simp only at hnd ⊢
        right
        rw [verified_noDs hpw]
        cases hproof : noDsProof (S := S) P c.apex ((p.noDsRecords c.apex).map (·.data)) with
        | none => rw [hproof] at hnd; cases hnd
        | some w => exact ⟨w, rfl⟩
      | some set =>
        simp only at hnm ⊢
        obtain ⟨hown, htype⟩ := hwf.dsSets p hp c.apex ns set g hn
        have hv : (p.signSet set).sigs.any (verifies P t p.apex p.keys (exactCover set)) = true := by
          refine sigsBy_verifies hpw _ _ _ _ fun h hl ht => ?_
          simp only [exactCover, hl, ↓reduceIte, ht]
        have hds : dsStep P t p.apex p.keys c.apex (p.signSet set) = .ok (dsOf set) := by
          unfold dsStep
          simp only [SignedZone.signSet, hown] at hv ⊢
          simp only [htype, ne_eq, not_true_eq_false, or_self, ↓reduceIte, hv]
        rw [hds]
        simp only
        simp only [Bool.or_eq_false_iff, beq_eq_false_iff_ne, ne_eq, Bool.and_eq_false_iff,
          bne_eq_false_iff_eq] at hnm
        obtain ⟨hne, hsup⟩ := hnm
        rcases hsup with hsup | hanc
        · right
          exact ⟨_, keyStep_insecure.mpr ⟨hne, supported_nil_iff.mp hsup, rfl⟩⟩
        · left
          obtain ⟨k, hk⟩ := List.exists_mem_of_ne_nil _ hanc
          obtain ⟨hkk, hsep, d, hd, hda, hdd⟩ := mem_anchored.mp hk
          obtain ⟨s', hs', rfl⟩ := List.mem_map.mp hkk
          have hcne : c.signers ≠ [] := List.ne_nil_of_mem hs'
          have hcw := zone_signsWell hc hwf hdata hcm hcne
          obtain ⟨hdm, hdt⟩ := mem_supported.mp hd
          exact ⟨keyStep_ok.mpr (keySet_signed hcw hs' hsep hdm hdt hda hdd), hcne⟩

/-- Down a whole path from a trusted zone: trusted at the last zone, or Insecure on the way. -/
theorem path_walk {tr : Tree S} {P : AlgorithmPolicy} {t : Nat} (hc : check tr P t = []) (hwf : WellFormed tr)
    (hdata : DataAlgorithms tr P)
    {owner : Name} {p : SignedZone S} {cs : List (SignedZone S)} {last : SignedZone S} (h : Descends tr p cs last)
    (hp : p ∈ tr) (hpne : p.signers ≠ []) (hu : under owner last.apex = true) :
    (descend P t owner p.apex p.keys (pairs p cs) = .trusted last.apex last.keys ∧ last.signers ≠ []) ∨
      ∃ w, descend P t owner p.apex p.keys (pairs p cs) = .stop (.insecure w) := by
  induction h with
  | nil => exact Or.inl ⟨rfl, hpne⟩
  | @cons p c cs last hcm hpar hrest ih =>
    have huc : under owner c.apex = true := under_trans hu (descends_under hrest)
    rcases link_step hc hwf hdata hp hpne hcm hpar huc with ⟨hl, hcne⟩ | ⟨w, hl⟩
    · rcases ih hcm hcne hu with ⟨hd, hlast⟩ | ⟨w, hd⟩
      · left; exact ⟨by simp only [pairs, descend, hl, linkBelow_apex, hd], hlast⟩
      · right; exact ⟨w, by simp only [pairs, descend, hl, linkBelow_apex, hd]⟩
    · right; exact ⟨w, by simp only [pairs, descend, hl]⟩

theorem anchor_owner (sz : SignedZone S) (dt : Nat) : (sz.anchor dt).owner = sz.apex := rfl

/-- When the check reports nothing, every RRset a zone of the tree serves from its own nodes validates Secure
or Insecure along the chain from the anchored zone `z0` down a path of the tree, under `z0`'s own anchor, whose
SEP keys include one in an algorithm the policy validates. It is never Bogus and never Indeterminate. -/
theorem check_sound {tr : Tree S} {P : AlgorithmPolicy} {t dt : Nat} (hc : check tr P t = []) (hwf : WellFormed tr)
    (hdata : DataAlgorithms tr P) (hdt : P.digests.contains dt = true) {z0 : SignedZone S}
    {rest : List (SignedZone S)} {zn : SignedZone S} (h0 : z0 ∈ tr)
    (hsep : ∃ s ∈ z0.signers, s.dnskey.sep = true ∧ P.validate.contains s.dnskey.alg = true)
    (hpath : Descends tr z0 rest zn)
    (hzwf : zn.zone.WF) {s : RRset} {nd : Node} (ds : List (Signed S)) (hnode : zn.zone.node s.owner = some nd)
    (hcut : ∀ ns d g, nd ≠ .cut ns d g) (hheld : ∃ x ∈ nodeSets nd, x.rtype = s.rtype ∧ x.rdata = s.rdata)
    (hin : under s.owner zn.apex = true) :
    validateRrset (some [z0.anchor dt]) P t (chainOf z0 rest) s (zn.sigsFor s) ds = .secure ∨
      ∃ w, validateRrset (some [z0.anchor dt]) P t (chainOf z0 rest) s (zn.sigsFor s) ds = .insecure w := by
  obtain ⟨s0, hs0, hsep0, ha0⟩ := hsep
  have hne0 : z0.signers ≠ [] := List.ne_nil_of_mem hs0
  have hw0 := zone_signsWell hc hwf hdata h0 hne0
  have hin0 : under s.owner z0.apex = true := under_trans hin (descends_under hpath)
  have hwalk : walk [z0.anchor dt] P t s.owner (chainOf z0 rest) =
      descend P t s.owner z0.apex z0.keys (pairs z0 rest) := by
    unfold walk chainOf
    rw [anchorFor_zone z0 dt hin0]
    simp only [SignedZone.link, anchor_owner, ne_eq, not_true_eq_false, ↓reduceIte]
    rw [keyStep_ok.mpr (anchor_keys hw0 hdt hs0 hsep0 ha0)]
  rcases path_walk hc hwf hdata hpath h0 hne0 hin with ⟨hd, hnen⟩ | ⟨w, hd⟩
  · left
    obtain ⟨x, hsig, hxo, hxt, hxd⟩ := sigsFor_own zn hzwf hnode hcut hheld
    have hwn := zone_signsWell hc hwf hdata (descends_last_mem hpath h0) hnen
    simp only [validateRrset, hwalk, hd, hsig]
    exact rrsetResult_secure.mpr (signSet_final hwn ds hxo hxt hxd)
  · right
    exact ⟨w, by simp [validateRrset, hwalk, hd]⟩

end Dns.Chain
