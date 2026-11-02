/-
  Views that may not know every fact (§5.1, §5.4): the answer over a view, its soundness against every
  complete zone that agrees with the view, and `Lazy` zones that grow from a provider and answer from one
  revision.

  Rust: `services::dns::zone::{View, ZoneData, Lazy, Provider, Revision}` and `answer` over a `View`.
-/
import Dns.Zone

namespace Dns.Zone

/-- What a zone knows for one question, all at one revision. -/
structure View where
  apex : Name
  soa : RRset
  node : Name → Fact Node
  revision : Nat

def answerPartial (v : View) (req : Request) (any : AnyResponse) : Answered :=
  answerWith v.node v.apex v.soa any req

/-! ## Refinement: knowing more never changes a known answer -/

/-- `l2` knows at least what `l1` knows, and agrees with it there. -/
def Refines (l1 l2 : Name → Fact Node) : Prop := ∀ n, l1 n ≠ .unknown → l2 n = l1 n

/-- A complete zone agrees with a view: same apex and SOA, and every present or absent fact of the view holds
in the zone. -/
def Agrees (v : View) (z : Zone) : Prop := v.apex = z.apex ∧ v.soa = z.soa ∧ Refines v.node z.look

section Refine
variable {l1 l2 : Name → Fact Node} (R : Refines l1 l2)
include R

theorem get_ref {n : Name} {o : Option Node} (h : get l1 n = .ok o) : get l2 n = .ok o := by
  unfold get at h ⊢
  have hk : l1 n ≠ .unknown := by intro hu; rw [hu] at h; cases h
  rw [R n hk]; exact h

theorem atApex_ref {apex : Name} {L : Loc} (h : atApex l1 apex = .ok L) : atApex l2 apex = .ok L := by
  unfold atApex at h ⊢
  cases hg : get l1 apex with
  | error e => rw [hg] at h; cases h
  | ok o => rw [get_ref R hg]; rw [hg] at h; exact h

theorem child_ref {q p : Name} {L : Loc} (h : child l1 q p = .ok L) : child l2 q p = .ok L := by
  unfold child at h ⊢
  cases hg : get l1 q with
  | error e => rw [hg] at h; cases h
  | ok o => rw [get_ref R hg]; rw [hg] at h; exact h

theorem locate_ref (apex : Name) : ∀ q L, locate l1 apex q = .ok L → locate l2 apex q = .ok L := by
  intro q
  induction q with
  | nil =>
    intro L h
    unfold locate at h ⊢
    by_cases hq : ([] : Name) = apex
    · simp only [hq, ↓reduceIte] at h ⊢; exact atApex_ref R h
    · simp only [hq, ↓reduceIte] at h ⊢; exact h
  | cons l p ih =>
    intro L h
    unfold locate at h ⊢
    by_cases hq : l :: p = apex
    · simp only [hq, ↓reduceIte] at h ⊢; exact atApex_ref R h
    · simp only [hq, ↓reduceIte] at h ⊢
      cases hl : locate l1 apex p with
      | error e => rw [hl] at h; cases h
      | ok Lp =>
        rw [ih Lp hl]; rw [hl] at h
        cases Lp with
        | node n nd =>
          cases nd with
          | dname d s => exact h
          | data _ => exact child_ref R h
          | cut _ _ _ => exact child_ref R h
          | empty => exact child_ref R h
        | _ => exact h

omit R in
theorem collect_ref {f1 f2 : Name → M (List RRset)} (hf : ∀ t a, f1 t = .ok a → f2 t = .ok a) :
    ∀ ts a, collect f1 ts = .ok a → collect f2 ts = .ok a := by
  intro ts
  induction ts with
  | nil => intro a h; exact h
  | cons t ts ih =>
    intro a h
    unfold collect at h ⊢
    cases h1 : f1 t with
    | error e => rw [h1] at h; cases h
    | ok b =>
      rw [hf t b h1]; rw [h1] at h
      cases h2 : collect f1 ts with
      | error e => simp only [h2] at h; cases h
      | ok c => rw [ih c h2]; simp only [h2] at h; exact h

theorem addrsOf_ref {apex t : Name} {a : List RRset} (h : addrsOf l1 apex t = .ok a) :
    addrsOf l2 apex t = .ok a := by
  unfold addrsOf at h ⊢
  by_cases hu : under t apex = true
  · simp only [hu, ↓reduceIte] at h ⊢
    cases hl : locate l1 apex t with
    | error e => rw [hl] at h; cases h
    | ok L => rw [locate_ref R apex t L hl]; rw [hl] at h; exact h
  · simp only [hu] at h ⊢; exact h

theorem siblingGlue_ref {apex m t : Name} {a : List RRset} (h : siblingGlue l1 apex m t = .ok a) :
    siblingGlue l2 apex m t = .ok a := by
  unfold siblingGlue at h ⊢
  by_cases hu : (under t apex && !under t m) = true
  · simp only [hu, ↓reduceIte] at h ⊢
    cases hl : locate l1 apex t with
    | error e => rw [hl] at h; cases h
    | ok L => rw [locate_ref R apex t L hl]; rw [hl] at h; exact h
  · simp only [hu] at h ⊢; exact h

theorem referral_ref {apex m : Name} {ns : RRset} {g : List RRset} {o : Out}
    (h : referral l1 apex m ns g = .ok o) : referral l2 apex m ns g = .ok o := by
  unfold referral at h ⊢
  cases hc : collect (siblingGlue l1 apex m) (targets ns) with
  | error e => rw [hc] at h; cases h
  | ok s =>
    rw [collect_ref (fun t a h => siblingGlue_ref R h) _ _ hc]; rw [hc] at h; exact h

theorem exact_ref {apex : Name} {soa : RRset} {any : AnyResponse} {q : Name} {qtype : Nat} {sets : List RRset}
    {o : Out} (h : exact l1 apex soa any q qtype sets = .ok o) : exact l2 apex soa any q qtype sets = .ok o := by
  unfold exact at h ⊢
  by_cases ht : qtype = 255
  · simp only [ht, ↓reduceIte] at h ⊢; exact h
  · simp only [ht, ↓reduceIte] at h ⊢
    cases hf : sets.find? (·.rtype == qtype) with
    | none => simp only [hf] at h ⊢; exact h
    | some s =>
      simp only [hf] at h ⊢
      cases hc : collect (addrsOf l1 apex) (targets s) with
      | error e => rw [hc] at h; cases h
      | ok a => rw [collect_ref (fun t a h => addrsOf_ref R h) _ _ hc]; rw [hc] at h; exact h

theorem step_ref {apex : Name} {soa : RRset} {any : AnyResponse} {q : Name} {qtype : Nat} {o : Out}
    (h : step l1 apex soa any q qtype = .ok o) : step l2 apex soa any q qtype = .ok o := by
  unfold step at h ⊢
  cases hl : locate l1 apex q with
  | error e => rw [hl] at h; cases h
  | ok L =>
    rw [locate_ref R apex q L hl]; rw [hl] at h
    cases L with
    | outside => exact h
    | cut m ns ds g =>
      simp only at h ⊢
      split
      · rename_i hc; simp only [hc, and_self, ↓reduceIte] at h; exact h
      · rename_i hc; simp only [hc, ↓reduceIte] at h; exact referral_ref R h
    | dname m d => exact h
    | node n nd => exact exact_ref R h
    | absent c =>
      simp only at h ⊢
      cases hg : get l1 (wild c) with
      | error e => rw [hg] at h; cases h
      | ok og =>
        rw [get_ref R hg]; rw [hg] at h
        cases og with
        | none => exact h
        | some nd =>
          cases nd with
          | cut ns ds g => exact referral_ref R h
          | data _ => exact exact_ref R h
          | dname _ _ => exact exact_ref R h
          | empty => exact exact_ref R h

theorem chase_ref {apex : Name} {soa : RRset} {any : AnyResponse} {qtype : Nat} :
    ∀ f seen acc q r, chase l1 apex soa any qtype f seen acc q = .ok r →
      chase l2 apex soa any qtype f seen acc q = .ok r := by
  intro f
  induction f with
  | zero => intro _ _ _ _ h; exact h
  | succ f ih =>
    intro seen acc q r h
    unfold chase at h ⊢
    cases hs : step l1 apex soa any q qtype with
    | error e => rw [hs] at h; cases h
    | ok o =>
      rw [step_ref R hs]; rw [hs] at h
      cases o with
      | done rc aa an au ad req => exact h
      | restart an t =>
        simp only at h ⊢
        split
        · rename_i hc; simp only [hc, ↓reduceIte] at h; exact h
        · rename_i hc; simp only [hc, ↓reduceIte] at h; exact ih _ _ _ _ h

theorem answerWith_ref {apex : Name} {soa : RRset} {any : AnyResponse} {req : Request} {r : Response}
    (h : answerWith l1 apex soa any req = .response r) : answerWith l2 apex soa any req = .response r := by
  by_cases hu : under req.qname apex = true
  · rw [answerWith_inside hu] at h ⊢
    generalize chainFuel = F at h ⊢
    cases hc : chase l1 apex soa any req.qtype F [] [] req.qname with
    | error e => rw [hc] at h; cases h
    | ok r' => rw [chase_ref R _ _ _ _ _ hc]; rw [hc] at h; exact h
  · rw [answerWith_outside hu] at h ⊢; exact h

end Refine

/-- If a view answers, every complete zone that agrees with it gives the same response. So an unknown fact
never becomes NXDOMAIN or NODATA: a negative the view gives is the negative of every agreeing zone. -/
theorem answer_partial_sound (v : View) (req : Request) (any : AnyResponse) (r : Response)
    (h : answerPartial v req any = .response r) : ∀ z, Agrees v z → answer z req any = .response r := by
  intro z ⟨ha, hs, R⟩
  unfold answer
  rw [← ha, ← hs]
  exact answerWith_ref R h

/-! ## The quantifier is never empty

A view built from a finite list of facts, one per name, in which nothing present lies at or below a name
known absent, has a complete zone that agrees with it. -/

def View.ofFacts (apex : Name) (soa : RRset) (facts : List (Name × Fact Node)) (rev : Nat) : View :=
  ⟨apex, soa, fun n => (facts.lookup n).getD .unknown, rev⟩

/-- One fact per name, and no present node at or below a name known absent. -/
def Consistent (facts : List (Name × Fact Node)) : Prop :=
  (facts.map Prod.fst).Nodup ∧
    ∀ p ∈ facts, ∀ q ∈ facts, p.2 = .absent → q.2 ≠ .absent → q.2 ≠ .unknown → ¬ p.1 <:+ q.1

/-- A label longer than every label the facts mention. -/
def freshLabel (facts : List (Name × Fact Node)) : Label :=
  List.replicate ((facts.map fun p => (p.1.map List.length).sum).sum + 1) 120

def nonEmptyNode : Name × Fact Node → Option (Name × Node)
  | (n, .present nd) => if nd = .empty then none else some (n, nd)
  | _ => none

def entChild (fl : Label) : Name × Fact Node → Option (Name × Node)
  | (n, .present .empty) => some (fl :: n, .data [])
  | _ => none

/-- A complete zone that agrees with the facts: their non-empty nodes, and under each empty non-terminal a
child with a fresh label. -/
def witness (apex : Name) (soa : RRset) (facts : List (Name × Fact Node)) : Zone :=
  ⟨apex, soa, facts.filterMap nonEmptyNode ++ facts.filterMap (entChild (freshLabel facts))⟩

theorem sum_le_of_mem {f : α → Nat} {x : α} : ∀ {l : List α}, x ∈ l → f x ≤ (l.map f).sum
  | _ :: _, .head _ => by simp
  | _ :: _, .tail _ h => by simp; have := sum_le_of_mem (f := f) h; omega

theorem fresh_long {facts : List (Name × Fact Node)} {p : Name × Fact Node} (hp : p ∈ facts) {l : Label}
    (hl : l ∈ p.1) : l.length < (freshLabel facts).length := by
  have h1 : l.length ≤ (p.1.map List.length).sum := sum_le_of_mem hl
  have h2 := sum_le_of_mem (f := fun p : Name × Fact Node => (p.1.map List.length).sum) hp
  simp [freshLabel]; omega

/-- A name the facts mention never has the fresh label first. -/
theorem fresh_ne {facts : List (Name × Fact Node)} {p : Name × Fact Node} (hp : p ∈ facts) (m : Name) :
    p.1 ≠ freshLabel facts :: m := by
  intro h
  have := fresh_long hp (l := freshLabel facts) (by rw [h]; simp)
  omega

theorem lookup_append_left {l1 l2 : List (Name × Node)} {n : Name} {v : Node} (h : l1.lookup n = some v) :
    (l1 ++ l2).lookup n = some v := by
  induction l1 with
  | nil => simp [List.lookup] at h
  | cons e es ih =>
    obtain ⟨k, w⟩ := e
    cases hnk : (n == k) with
    | true => simp only [List.lookup, List.cons_append, hnk] at h ⊢; exact h
    | false => simp only [List.lookup, List.cons_append, hnk] at h ⊢; exact ih h

theorem lookup_none_of_not_mem {l : List (Name × Node)} {n : Name} (h : ∀ p ∈ l, p.1 ≠ n) : l.lookup n = none := by
  induction l with
  | nil => rfl
  | cons e es ih =>
    obtain ⟨k, w⟩ := e
    have hk : (n == k) = false := by
      simp only [beq_eq_false_iff_ne, ne_eq]; exact fun e => h (k, w) (by simp) e.symm
    simp only [List.lookup, hk]
    exact ih fun p hp => h p (by simp [hp])

theorem nonEmptyNode_fst {q : Name × Fact Node} {p : Name × Node} (h : nonEmptyNode q = some p) : p.1 = q.1 := by
  obtain ⟨n, f⟩ := q
  cases f with
  | present nd =>
    by_cases he : nd = .empty
    · simp [nonEmptyNode, he] at h
    · simp only [nonEmptyNode, he, ↓reduceIte, Option.some.injEq] at h; rw [← h]
  | absent => simp [nonEmptyNode] at h
  | unknown => simp [nonEmptyNode] at h

theorem entChild_spec {fl : Label} {q : Name × Fact Node} {p : Name × Node} (h : entChild fl q = some p) :
    p.1 = fl :: q.1 ∧ q.2 = .present .empty := by
  obtain ⟨n, f⟩ := q
  unfold entChild at h
  split at h
  · simp only [Option.some.injEq] at h; subst h; simp_all
  · cases h

theorem lookup_filterMap_nonEmpty (facts : List (Name × Fact Node)) (hnd : (facts.map Prod.fst).Nodup)
    (n : Name) : (facts.filterMap nonEmptyNode).lookup n =
      match facts.lookup n with
      | some (.present nd) => if nd = .empty then none else some nd
      | _ => none := by
  induction facts with
  | nil => rfl
  | cons e es ih =>
    obtain ⟨k, f⟩ := e
    simp only [List.map_cons, List.nodup_cons] at hnd
    have ih := ih hnd.2
    rw [List.filterMap_cons]
    by_cases hk : n = k
    · subst hk
      have hrest : (es.filterMap nonEmptyNode).lookup n = none := by
        apply lookup_none_of_not_mem
        intro p hp heq
        obtain ⟨q, hq, hq'⟩ := List.mem_filterMap.mp hp
        apply hnd.1
        rw [List.mem_map]
        exact ⟨q, hq, by rw [← nonEmptyNode_fst hq', heq]⟩
      cases f with
      | present nd =>
        by_cases he : nd = .empty
        · subst he
          simp only [show nonEmptyNode (n, .present .empty) = none by simp [nonEmptyNode]]
          simp [List.lookup, hrest]
        · simp only [show nonEmptyNode (n, .present nd) = some (n, nd) by simp [nonEmptyNode, he]]
          simp [List.lookup, he]
      | absent =>
        simp only [show nonEmptyNode (n, .absent) = none from rfl]
        simp [List.lookup, hrest]
      | unknown =>
        simp only [show nonEmptyNode (n, .unknown) = none from rfl]
        simp [List.lookup, hrest]
    · have hb : (n == k) = false := by simp [hk]
      cases f with
      | present nd =>
        by_cases he : nd = .empty
        · subst he
          simp only [show nonEmptyNode (k, .present .empty) = none by simp [nonEmptyNode]]
          simp [List.lookup, hb, ih]
        · simp only [show nonEmptyNode (k, .present nd) = some (k, nd) by simp [nonEmptyNode, he]]
          simp [List.lookup, hb, ih]
      | absent =>
        simp only [show nonEmptyNode (k, .absent) = none from rfl]
        simp [List.lookup, hb, ih]
      | unknown =>
        simp only [show nonEmptyNode (k, .unknown) = none from rfl]
        simp [List.lookup, hb, ih]

theorem lookup_mem_facts {facts : List (Name × Fact Node)} {n : Name} {f : Fact Node}
    (h : facts.lookup n = some f) : (n, f) ∈ facts := by
  induction facts with
  | nil => simp [List.lookup] at h
  | cons e es ih =>
    obtain ⟨k, w⟩ := e
    simp only [List.lookup] at h
    split at h
    · rename_i hk; simp at hk h; subst hk; subst h; simp
    · exact List.mem_cons_of_mem _ (ih h)

theorem nonEmptyNode_spec {q : Name × Fact Node} {p : Name × Node} (h : nonEmptyNode q = some p) :
    p.1 = q.1 ∧ ∃ nd, q.2 = .present nd := by
  obtain ⟨n, f⟩ := q
  cases f with
  | present nd => exact ⟨nonEmptyNode_fst h, nd, rfl⟩
  | absent => simp [nonEmptyNode] at h
  | unknown => simp [nonEmptyNode] at h

/-- Every consistent finite view has a complete zone that agrees with it, so `answer_partial_sound` never
quantifies over nothing. -/
theorem agreeing_zone_exists (apex : Name) (soa : RRset) (facts : List (Name × Fact Node)) (rev : Nat)
    (hc : Consistent facts) : ∃ z, Agrees (View.ofFacts apex soa facts rev) z := by
  obtain ⟨hnd, habs⟩ := hc
  let z := witness apex soa facts
  have hfl := @fresh_ne facts
  -- nodes of the second part never sit at a name the facts mention
  have hsecond : ∀ n f, (n, f) ∈ facts → (facts.filterMap (entChild (freshLabel facts))).lookup n = none := by
    intro n f hmem
    apply lookup_none_of_not_mem
    intro p hp heq
    obtain ⟨q, _, hq'⟩ := List.mem_filterMap.mp hp
    obtain ⟨h1, _⟩ := entChild_spec hq'
    exact hfl hmem _ (heq.symm.trans h1)
  refine ⟨z, rfl, rfl, fun n hk => ?_⟩
  simp only [View.ofFacts] at hk ⊢
  cases hl : facts.lookup n with
  | none => rw [hl] at hk; exact absurd rfl hk
  | some f =>
    have hmem := lookup_mem_facts hl
    have h1 := lookup_filterMap_nonEmpty facts hnd n
    rw [hl] at h1
    simp only [Option.getD_some]
    cases f with
    | unknown => rw [hl] at hk; exact absurd rfl hk
    | present nd =>
      by_cases he : nd = .empty
      · subst he
        simp only [↓reduceIte] at h1
        have hn : z.node n = none := by
          simp only [Zone.node, z, witness]
          rw [List.lookup_append, h1, hsecond n _ hmem]; rfl
        have hp : z.presentB n = true := by
          rw [Zone.presentB_iff]
          refine ⟨(freshLabel facts :: n, .data []), ?_, List.suffix_cons _ _⟩
          simp only [z, witness, List.mem_append, List.mem_filterMap]
          exact Or.inr ⟨(n, .present .empty), hmem, rfl⟩
        simp [Zone.look, hn, hp]
      · simp only [he, ↓reduceIte] at h1
        exact z.look_of_node (lookup_append_left h1)
    | absent =>
      simp only at h1
      have hn : z.node n = none := by
        simp only [Zone.node, z, witness]
        rw [List.lookup_append, h1, hsecond n _ hmem]; rfl
      have hp : z.presentB n = false := by
        cases hpb : z.presentB n with
        | false => rfl
        | true =>
          obtain ⟨p, hp, hs⟩ := (z.presentB_iff n).mp hpb
          simp only [z, witness, List.mem_append, List.mem_filterMap] at hp
          rcases hp with ⟨q, hq, hq'⟩ | ⟨q, hq, hq'⟩
          · obtain ⟨h1, nd, h2⟩ := nonEmptyNode_spec hq'
            rw [h1] at hs
            exact absurd hs (habs _ hmem q hq rfl (by rw [h2]; simp) (by rw [h2]; simp))
          · obtain ⟨h1, h2⟩ := entChild_spec hq'
            rw [h1] at hs
            rcases List.suffix_cons_iff.mp hs with h | h
            · exact absurd h (hfl hmem q.1)
            · exact absurd h (habs _ hmem q hq rfl (by rw [h2]; simp) (by rw [h2]; simp))
      simp [Zone.look, hn, hp]

/-! ## Unknown facts end the answer -/

/-- The walk reaches `q`: every proper ancestor at or below the apex is known present and diverts nothing. -/
def View.Reaches (v : View) (q : Name) : Prop :=
  ∀ m, m ≠ q → m <:+ q → v.apex <:+ m →
    ∃ nd, v.node m = .present nd ∧ (∀ d s, nd ≠ .dname d s) ∧ (m ≠ v.apex → ∀ ns ds g, nd ≠ .cut ns ds g)

theorem locate_apex (look : Name → Fact Node) (apex : Name) : locate look apex apex = atApex look apex := by
  cases apex with
  | nil => simp [locate]
  | cons l p => simp [locate]

theorem View.locate_reach (v : View) : ∀ q, v.apex <:+ q → v.Reaches q →
    (∀ nd, v.node q = .present nd → (q ≠ v.apex → ∀ ns ds g, nd ≠ .cut ns ds g) →
      locate v.node v.apex q = .ok (.node q nd)) ∧
    (v.node q = .unknown → locate v.node v.apex q = .error q) ∧
    (∀ l p, q = l :: p → q ≠ v.apex → v.node q = .absent → locate v.node v.apex q = .ok (.absent p)) := by
  intro q
  induction q with
  | nil =>
    intro hq _
    have ha : v.apex = [] := List.eq_nil_of_suffix_nil hq
    have hloc : locate v.node v.apex [] = atApex v.node v.apex := by
      have := locate_apex v.node v.apex
      rw [ha] at this ⊢; exact this
    refine ⟨fun nd h _ => ?_, fun h => ?_, fun l p h => by cases h⟩
    · rw [hloc]; simp [atApex, get, ha, h]
    · rw [hloc]; simp [atApex, get, ha, h]
  | cons l p ih =>
    intro hq hr
    by_cases heq : l :: p = v.apex
    · have hloc : locate v.node v.apex (l :: p) = atApex v.node v.apex := by
        have := locate_apex v.node v.apex
        rw [← heq] at this ⊢; exact this
      refine ⟨fun nd h _ => ?_, fun h => ?_, fun _ _ _ h => absurd heq h⟩
      · rw [hloc]; simp [atApex, get, ← heq, h]
      · rw [hloc]; simp [atApex, get, ← heq, h]
    have hp : v.apex <:+ p := suffix_cons_ne hq (Ne.symm heq)
    have hrp : v.Reaches p := fun m h1 h2 h3 =>
      hr m (fun h => absurd (h ▸ h2).length_le (by simp)) (h2.trans (List.suffix_cons _ _)) h3
    obtain ⟨ndp, hndp, hnd, hcut⟩ := hr p (List.cons_ne_self l p).symm (List.suffix_cons _ _) hp
    have hlp := (ih hp hrp).1 ndp hndp hcut
    have hloc : locate v.node v.apex (l :: p) = child v.node (l :: p) p := locate_cons_node heq hlp hnd
    refine ⟨fun nd h hc => ?_, fun h => ?_, fun l' p' he _ h => ?_⟩
    · rw [hloc]; unfold child get; rw [h]
      cases nd with
      | cut ns ds g => exact absurd rfl (hc heq ns ds g)
      | _ => rfl
    · rw [hloc]; unfold child get; rw [h]
    · cases he
      rw [hloc]; unfold child get; rw [h]
theorem answerPartial_error (v : View) (req : Request) (any : AnyResponse) (hq : v.apex <:+ req.qname) {e : Name}
    (h : step v.node v.apex v.soa any req.qname req.qtype = .error e) : answerPartial v req any = .unknown e := by
  unfold answerPartial answerWith
  rw [chainFuel_succ]
  simp [(under_iff _ _).mpr hq, chase, h]

/-- An unknown fact on the walk ends the answer with that name, never with NXDOMAIN or NODATA: the name itself
when the walk reaches it, or the wildcard when the name is known absent and the wildcard is not known. -/
theorem unknown_never_negative (v : View) (req : Request) (any : AnyResponse) (hq : v.apex <:+ req.qname)
    (hr : v.Reaches req.qname) :
    (v.node req.qname = .unknown → answerPartial v req any = .unknown req.qname) ∧
    (∀ l p, req.qname = l :: p → req.qname ≠ v.apex → v.node req.qname = .absent →
      v.node (wild p) = .unknown → answerPartial v req any = .unknown (wild p)) := by
  obtain ⟨_, h2, h3⟩ := v.locate_reach req.qname hq hr
  refine ⟨fun hu => answerPartial_error v req any hq ?_, fun l p he hne ha hw => answerPartial_error v req any hq ?_⟩
  · unfold step; rw [h2 hu]
  · unfold step; rw [h3 l p he hne ha]; simp [get, hw]

/-! ## Lazy zones (§5.4) -/

/-- Decides names as they are asked: their RRsets, nothing at or below them, or not known. -/
abbrev Provider := Name → Fact (List RRset)

/-- A zone that grows. `held` only grows, and each insertion is a new revision. -/
structure Lazy where
  apex : Name
  soa : RRset
  held : List (Name × Node)
  revision : Nat

def Lazy.zone (s : Lazy) : Zone := ⟨s.apex, s.soa, s.held⟩

/-- The node a provider's RRsets make: NS below the apex is a cut, a DNAME a DNAME node. -/
def nodeOf (apex n : Name) (sets : List RRset) : Node :=
  match sets.find? (·.rtype == 2) with
  | some ns => if n ≠ apex then .cut ns (sets.find? (·.rtype == 43)) [] else nodeAt sets
  | none => nodeAt sets

/-- The names one question needs: the path from the apex to the name and the wildcard below each name on
it. -/
def needed (apex q : Name) : List Name :=
  let path := (List.range (q.length - apex.length + 1)).map fun k => q.drop k
  path ++ path.map wild

/-- Asks the provider about each needed name the zone holds no node at. Present RRsets are inserted, each a new
revision; absent and unknown answers are reported, not kept. -/
def fill (p : Provider) : Lazy → List Name → Lazy × List (Name × Fact Node)
  | s, [] => (s, [])
  | s, n :: ns =>
    if (s.zone.node n).isSome then fill p s ns
    else match p n with
      | .present sets => fill p { s with held := (n, nodeOf s.apex n sets) :: s.held, revision := s.revision + 1 } ns
      | .absent => ((fill p s ns).1, (n, .absent) :: (fill p s ns).2)
      | .unknown => ((fill p s ns).1, (n, .unknown) :: (fill p s ns).2)

/-- The view for one question, and the zone after it: every fact is read from the zone after the provider was
asked, under one lock, so the view is one revision. -/
def lazyView (p : Provider) (s : Lazy) (q : Name) : View × Lazy :=
  let ns := needed s.apex q
  let r := fill p s ns
  (⟨s.apex, s.soa, fun n =>
      if n ∈ ns then (if r.1.zone.presentB n then r.1.zone.look n else (r.2.lookup n).getD .unknown)
      else .unknown, r.1.revision⟩, r.1)

theorem fill_keeps (p : Provider) : ∀ ns s, (fill p s ns).1.apex = s.apex ∧ (fill p s ns).1.soa = s.soa ∧
    s.revision ≤ (fill p s ns).1.revision ∧ (∀ e ∈ s.held, e ∈ (fill p s ns).1.held) ∧
    ∀ e ∈ (fill p s ns).2, e.2 = .absent ∨ e.2 = .unknown := by
  intro ns
  induction ns with
  | nil => intro s; simp [fill]
  | cons n ns ih =>
    intro s
    by_cases hpres : (s.zone.node n).isSome = true
    · simp only [fill, hpres, ↓reduceIte]; exact ih s
    · cases hp : p n with
      | present sets =>
        simp only [fill, hpres, Bool.false_eq_true, ↓reduceIte, hp]
        obtain ⟨h1, h2, h3, h4, h5⟩ := ih ⟨s.apex, s.soa, (n, nodeOf s.apex n sets) :: s.held, s.revision + 1⟩
        exact ⟨h1, h2, by simp at h3; omega, fun e he => h4 e (by simp [he]), h5⟩
      | absent =>
        simp only [fill, hpres, Bool.false_eq_true, ↓reduceIte, hp]
        obtain ⟨h1, h2, h3, h4, h5⟩ := ih s
        refine ⟨h1, h2, h3, h4, fun e he => ?_⟩
        simp only [List.mem_cons] at he
        rcases he with rfl | he
        · exact Or.inl rfl
        · exact h5 e he
      | unknown =>
        simp only [fill, hpres, Bool.false_eq_true, ↓reduceIte, hp]
        obtain ⟨h1, h2, h3, h4, h5⟩ := ih s
        refine ⟨h1, h2, h3, h4, fun e he => ?_⟩
        simp only [List.mem_cons] at he
        rcases he with rfl | he
        · exact Or.inr rfl
        · exact h5 e he

/-- A lazy zone's view is one revision: every fact it knows is the fact of the zone it leaves behind, at that
zone's revision. The zone only grows. -/
theorem lazy_view_one_revision (p : Provider) (s : Lazy) (q : Name) :
    (lazyView p s q).1.revision = (lazyView p s q).2.revision ∧
      Agrees (lazyView p s q).1 (lazyView p s q).2.zone ∧
      s.revision ≤ (lazyView p s q).2.revision ∧ ∀ e ∈ s.held, e ∈ (lazyView p s q).2.held := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := fill_keeps p (needed s.apex q) s
  refine ⟨rfl, ⟨by simp [lazyView, Lazy.zone, h1], by simp [lazyView, Lazy.zone, h2], fun n hk => ?_⟩, h3, h4⟩
  simp only [lazyView] at hk ⊢
  by_cases hn : n ∈ needed s.apex q
  · simp only [hn, ↓reduceIte] at hk ⊢
    by_cases hp : (fill p s (needed s.apex q)).1.zone.presentB n = true
    · simp only [hp, ↓reduceIte]
    · simp only [hp, Bool.false_eq_true, ↓reduceIte] at hk ⊢
      cases hl : (fill p s (needed s.apex q)).2.lookup n with
      | none => rw [hl] at hk; exact absurd rfl hk
      | some f =>
        simp only [Option.getD_some]
        rcases h5 _ (lookup_mem_facts hl) with hf | hf
        · simp only at hf; subst hf
          exact ((Zone.look_absent_iff _ _).mpr (by simpa using hp))
        · simp only at hf; subst hf; rw [hl] at hk; exact absurd rfl hk
  · simp only [hn, ↓reduceIte] at hk; exact absurd rfl hk

/-- So a lazy view's answer, when it has one, is the answer of the zone it leaves behind. -/
theorem lazy_answer (p : Provider) (s : Lazy) (q : Name) (req : Request) (any : AnyResponse) (r : Response)
    (h : answerPartial (lazyView p s q).1 req any = .response r) :
    answer (lazyView p s q).2.zone req any = .response r :=
  answer_partial_sound _ req any r h _ (lazy_view_one_revision p s q).2.1

end Dns.Zone
