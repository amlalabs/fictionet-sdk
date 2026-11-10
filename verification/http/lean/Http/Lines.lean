import Http.Wire
import Http.Rfc9112

/-!
# What an accepted head looks like

Lemmas about `Wire.readHead` and `Wire.splitHead`: a head the decoder ends
is a run of lines, each ended by CR LF with no LF inside, then an empty line;
and `splitHead` gives back exactly those lines. `Http/Smuggling.lean` builds
on them.
-/

namespace Http.Lines

open Wire

/-- Lines joined, each with its CR LF. -/
def joinLines (ls : List Bytes) : Bytes := (ls.map (· ++ [13, 10])).flatten

@[simp] theorem joinLines_nil : joinLines [] = [] := rfl
@[simp] theorem joinLines_cons (l : Bytes) (ls : List Bytes) :
    joinLines (l :: ls) = l ++ 13 :: 10 :: joinLines ls := by
  simp [joinLines]

/-! ## Lists -/

theorem findIdx?_hit {p : Nat → Bool} (l r : Bytes) (a : Nat)
    (hl : ∀ x ∈ l, p x = false) (ha : p a = true) :
    (l ++ a :: r).findIdx? p = some l.length := by
  induction l with
  | nil => simp [List.findIdx?_cons, ha]
  | cons x xs ih =>
    have hx : p x = false := hl x (by simp)
    simp [List.findIdx?_cons, hx, ih (fun y hy => hl y (by simp [hy]))]

/-- What `findIdx?` finding `i` says about the list. -/
theorem findIdx?_some {p : Nat → Bool} {l : Bytes} {i : Nat} (h : l.findIdx? p = some i) :
    ∃ a, l = l.take i ++ a :: l.drop (i + 1) ∧ p a = true ∧ ∀ x ∈ l.take i, p x = false := by
  induction l generalizing i with
  | nil => simp at h
  | cons x xs ih =>
    rw [List.findIdx?_cons] at h
    by_cases hx : p x = true
    · simp [hx] at h
      subst h
      exact ⟨x, by simp, hx, by simp⟩
    · simp [hx] at h
      obtain ⟨j, hj, rfl⟩ := h
      obtain ⟨a, h1, h2, h3⟩ := ih hj
      refine ⟨a, ?_, h2, ?_⟩
      · simp only [List.take_succ_cons, List.drop_succ_cons, List.cons_append]
        exact congrArg (x :: ·) h1
      · intro y hy
        simp only [List.take_succ_cons, List.mem_cons] at hy
        rcases hy with rfl | hy
        · simpa using hx
        · exact h3 y hy

/-- A prefix of `take` is a prefix of the list. -/
theorem eq_of_take_eq {xs p q : Bytes} {k : Nat} (h : xs.take k = p ++ q) :
    xs = p ++ xs.drop p.length := by
  have h1 : xs.take p.length = p := by
    have : (xs.take k).take p.length = p := by rw [h]; simp
    rw [List.take_take] at this
    by_cases hk : p.length ≤ k
    · rwa [Nat.min_eq_left hk] at this
    · have hlen := congrArg List.length h
      simp at hlen
      omega
  conv => lhs; rw [← List.take_append_drop p.length xs]
  rw [h1]

/-! ## `lineStep` -/

/-- The first LF found in a prefix of `w` splits `w` there. -/
theorem split_at_lf {w : Bytes} {k i : Nat} (hi : (w.take k).findIdx? (· == 10) = some i) :
    ∃ A C, w = A ++ 10 :: C ∧ A.length = i ∧ 10 ∉ A := by
  obtain ⟨a, hsplit, ha, hpre⟩ := findIdx?_some hi
  have ha' : a = 10 := by simpa using ha
  subst ha'
  have hlen : i < (w.take k).length := by
    have := congrArg List.length hsplit
    simp only [List.length_append, List.length_cons, List.length_take, List.length_drop] at this ⊢
    omega
  refine ⟨(w.take k).take i, (w.take k).drop (i + 1) ++ w.drop k, ?_, ?_, ?_⟩
  · conv => lhs; rw [← List.take_append_drop k w]
    conv => lhs; rw [hsplit]
    simp
  · simp only [List.length_take] at hlen ⊢; omega
  · intro hmem
    have := hpre 10 hmem
    simp at this

/-- A line `lineStep` accepts: its content, CR LF, then the rest; no LF in
the content, and at most `max` bytes of it. -/
theorem lineStep_ok {max : Nat} {w l : Bytes} {n : Nat}
    (h : lineStep max w = .line (.ok l) n) :
    n = l.length + 2 ∧ w = l ++ 13 :: 10 :: w.drop n ∧ 10 ∉ l ∧ l.length ≤ max := by
  unfold lineStep at h
  simp only [findByte] at h
  split at h
  · rename_i i hi
    obtain ⟨A, C, hw, hA, h10⟩ := split_at_lf hi
    subst hw
    rcases List.eq_nil_or_concat A with hA0 | ⟨A', a, rfl⟩
    · subst hA0
      simp at hA
      subst hA
      simp at h
    · simp at hA
      subst hA
      simp only [List.concat_eq_append] at h h10
      by_cases ha : a = 13
      · subst ha
        by_cases hmax : max < A'.length
        · simp [hmax] at h
        · simp [hmax] at h
          obtain ⟨rfl, rfl⟩ := h
          refine ⟨rfl, ?_, ?_, by omega⟩
          · simp
            have e : A' ++ 13 :: 10 :: C = (A' ++ [13, 10]) ++ C := by simp
            rw [e, show A'.length + 1 + 1 = (A' ++ [13, 10]).length by simp, List.drop_left]
          intro hm
          exact h10 (by simp [hm])
      · simp [ha] at h
        split at h <;> simp at h
  · split at h <;> simp at h


/-! ## `readHead` -/

/-- Where `headLoop` ends a head: after the lines already scanned come
complete lines, then an empty line. Lines after the first are not empty
(the first empty one ends the head), and none holds an LF. -/
theorem headLoop_done {lim : Limits} {input : Bytes} :
    ∀ fuel scanned count n, headLoop lim input fuel scanned count = .done n →
      ∃ ls rest, input.drop scanned = joinLines ls ++ 13 :: 10 :: rest ∧
        n = scanned + (joinLines ls).length + 2 ∧ (∀ l ∈ ls, 10 ∉ l) ∧
        (scanned = 0 → ls ≠ []) ∧ (∀ l ∈ (if scanned = 0 then ls.tail else ls), l ≠ []) := by
  intro fuel
  induction fuel with
  | zero => intro _ _ _ h; simp [headLoop] at h
  | succ fuel ih =>
    intro scanned count n h
    simp only [headLoop] at h
    split at h
    · simp at h
    · simp at h
    · rename_i line k hstep
      obtain ⟨hk, hw, hlf, _⟩ := lineStep_ok hstep
      have hdrop : input.drop scanned = line ++ 13 :: 10 :: input.drop (scanned + k) := by
        have h1 := eq_of_take_eq (p := line ++ [13, 10]) (q := List.drop k _)
          (by rw [List.append_assoc]; exact hw)
        rw [h1]
        simp [List.drop_drop, hk]
      by_cases hdone : (!(scanned == 0) && line.isEmpty) = true
      · simp only [hdone, ite_true, HeadRes.done.injEq] at h
        simp only [Bool.and_eq_true, Bool.not_eq_true', beq_eq_false_iff_ne, ne_eq,
          List.isEmpty_iff] at hdone
        obtain ⟨hs, rfl⟩ := hdone
        refine ⟨[], input.drop (scanned + k), by simpa using hdrop, by subst h; simp at hk ⊢; omega,
          by simp, by simp [hs], by simp [hs]⟩
      · simp only [hdone, Bool.false_eq_true, ite_false] at h
        split at h
        · simp at h
        · obtain ⟨ls, rest, h1, h2, h3, _, h5⟩ := ih (scanned + k) _ n h
          have hk0 : scanned + k ≠ 0 := by omega
          simp only [hk0, ite_false] at h5
          refine ⟨line :: ls, rest, ?_, ?_, ?_, by simp, ?_⟩
          · rw [hdrop, h1]; simp
          · rw [h2, hk]; simp; omega
          · intro l hl
            simp at hl
            rcases hl with rfl | hl
            · exact hlf
            · exact h3 l hl
          · by_cases hs : scanned = 0
            · simp [hs]; exact h5
            · simp only [hs, ite_false, List.mem_cons]
              intro l hl
              rcases hl with rfl | hl
              · intro he
                apply hdone
                simp [hs, he]
              · exact h5 l hl
    · split at h
      · simp at h
      · split at h <;> simp at h

/-- A head `readHead` ends: its first line, then non-empty field lines, each
with CR LF, then an empty line. -/
theorem readHead_done {lim : Limits} {input : Bytes} {n : Nat} (h : readHead lim input = .done n) :
    ∃ first ls rest, input = joinLines (first :: ls) ++ 13 :: 10 :: rest ∧
      n = (joinLines (first :: ls)).length + 2 ∧ 10 ∉ first ∧ (∀ l ∈ ls, 10 ∉ l ∧ l ≠ []) := by
  obtain ⟨ls, rest, h1, h2, h3, h4, h5⟩ := headLoop_done _ 0 0 n h
  match ls, h4 rfl with
  | first :: ls, _ =>
    refine ⟨first, ls, rest, by simpa using h1, by simpa using h2, h3 first (by simp), ?_⟩
    intro l hl
    exact ⟨h3 l (by simp [hl]), by simpa using h5 l (by simpa using hl)⟩

/-! ## `splitHead` -/

theorem splitBy_line (l r : Bytes) (h : 10 ∉ l) : splitBy 10 (l ++ 10 :: r) = l :: splitBy 10 r := by
  induction l with
  | nil => simp [splitBy]
  | cons x xs ih =>
    have hx : x ≠ 10 := fun e => h (by simp [e])
    have hxs : 10 ∉ xs := fun e => h (by simp [e])
    simp [splitBy, hx, ih hxs]

theorem splitBy_join (ls : List Bytes) (h : ∀ l ∈ ls, 10 ∉ l) :
    splitBy 10 (joinLines ls ++ [13, 10]) = ls.map (· ++ [13]) ++ [[13], []] := by
  induction ls with
  | nil => decide
  | cons l ls ih =>
    have hl : 10 ∉ l ++ [13] := by simpa using h l (by simp)
    have e : joinLines (l :: ls) ++ [13, 10] = (l ++ [13]) ++ 10 :: (joinLines ls ++ [13, 10]) := by
      simp
    rw [e, splitBy_line _ _ hl, ih (fun x hx => h x (by simp [hx]))]
    simp

theorem stripCr_line (l : Bytes) : stripCr (l ++ [13]) = some l := by
  simp [stripCr]

/-- Field lines and the fields `headerParts` reads from them. -/
inductive Parts : List Bytes → List (Bytes × Bytes) → Prop
  | nil : Parts [] []
  | cons {l p ls ps} : headerParts l = .ok p → Parts ls ps → Parts (l :: ls) (p :: ps)

theorem fieldLines_join (ls : List Bytes) (h : ∀ l ∈ ls, l ≠ []) :
    ∀ acc fs, fieldLines (ls.map (· ++ [13]) ++ [[13], []]) acc = .ok fs →
      ∃ ps, Parts ls ps ∧ fs = acc.reverse ++ ps := by
  induction ls with
  | nil =>
    intro acc fs hf
    simp [fieldLines, stripCr] at hf
    exact ⟨[], .nil, by simp [hf]⟩
  | cons l ls ih =>
    intro acc fs hf
    have hl : l ≠ [] := h l (by simp)
    simp only [List.map_cons, List.cons_append, fieldLines, stripCr_line] at hf
    have : l.isEmpty = false := by simpa using hl
    simp only [this, Bool.false_eq_true, ite_false] at hf
    split at hf
    · simp at hf
    · rename_i p hp
      obtain ⟨ps, h1, h2⟩ := ih (fun x hx => h x (by simp [hx])) _ _ hf
      exact ⟨p :: ps, .cons hp h1, by simp [h2]⟩

/-- What `splitHead` makes of a head `readHead` ended. -/
theorem splitHead_join {first : Bytes} {ls : List Bytes} {line : Bytes} {fs : List (Bytes × Bytes)}
    (h1 : 10 ∉ first) (h2 : ∀ l ∈ ls, 10 ∉ l ∧ l ≠ [])
    (h : splitHead (joinLines (first :: ls) ++ [13, 10]) = .ok (line, fs)) :
    line = first ∧ Parts ls fs := by
  rw [splitHead, splitBy_join (first :: ls) (by
    intro l hl; simp at hl; rcases hl with rfl | hl; exact h1; exact (h2 l hl).1)] at h
  simp only [List.map_cons, List.cons_append, stripCr_line] at h
  split at h
  · simp at h
  · rename_i fs' hfs
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    obtain ⟨ps, hps, rfl⟩ := fieldLines_join ls (fun l hl => (h2 l hl).2) [] fs' hfs
    exact ⟨rfl, by simpa using hps⟩

end Http.Lines
