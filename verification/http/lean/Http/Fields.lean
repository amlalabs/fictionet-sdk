import Http.Wire
import Http.Rfc9112

/-!
# The framing fields: what `Wire.fields` accepts

`Wire.fields` walks the field lines once, in order, and keeps the length,
the transfer codings, and the connection options in one `Fields`. Only the
length and the codings decide the framing. This file projects the walk onto
those two (`fieldStepP`), then reads off, for a head the decoder accepts,
exactly which `Content-Length` and `Transfer-Encoding` values it had.
-/

namespace Http.FieldsProof

open Wire

/-! ## Folds -/

theorem foldlM_proj {α β γ ε : Type} {f : β → α → Except ε β} {g : γ → α → Except ε γ}
    {π : β → γ} (h : ∀ b a, (f b a).map π = g (π b) a) :
    ∀ (xs : List α) (b : β), (xs.foldlM f b).map π = xs.foldlM g (π b) := by
  intro xs
  induction xs with
  | nil => intro b; rfl
  | cons x xs ih =>
    intro b
    simp only [List.foldlM_cons]
    have hb := h b x
    cases hf : f b x with
    | error e =>
      rw [hf] at hb
      simp only [Except.map] at hb
      rw [← hb]
      rfl
    | ok b' =>
      rw [hf] at hb
      simp only [Except.map] at hb
      rw [← hb]
      exact ih b'

/-- Every element a successful fold went through passed the step. -/
theorem foldlM_ok_forall {α β ε : Type} {f : β → α → Except ε β} {P : α → Prop}
    (h : ∀ b a b', f b a = .ok b' → P a) :
    ∀ (xs : List α) (b r : β), xs.foldlM f b = .ok r → ∀ a ∈ xs, P a := by
  intro xs
  induction xs with
  | nil => intro _ _ _ a ha; simp at ha
  | cons x xs ih =>
    intro b r hr a ha
    simp only [List.foldlM_cons] at hr
    cases hf : f b x with
    | error e => rw [hf] at hr; cases hr
    | ok b' =>
      rw [hf] at hr
      simp only [List.mem_cons] at ha
      rcases ha with rfl | ha
      · exact h b a b' hf
      · exact ih b' r hr a ha

/-! ## The coding state -/

abbrev T3 := Bool × Bool × Bool

/-- `transfer`, `chunked` and `unsupported` of a `Fields`. -/
def te3 (r : Fields) : T3 := (r.transfer, r.chunked, r.unsupported)

/-- `teStep` on the coding state alone. -/
def te3Step (t : T3) (x : Bytes) : Except Error T3 :=
  if (trim x).isEmpty then .ok t
  else if t.2.1 then .error .chunkedNotLast
  else if !token (trim x) then .error .transferEncoding
  else .ok (true, eqCI (trim x) (str "chunked"), t.2.2 || !eqCI (trim x) (str "chunked"))

theorem teStep_proj (r : Fields) (x : Bytes) : (teStep r x).map te3 = te3Step (te3 r) x := by
  simp only [teStep, te3Step, te3]
  by_cases h1 : (trim x).isEmpty = true
  · simp [h1, Except.map, te3]
  · by_cases h2 : r.chunked = true
    · simp [h1, h2, Except.map]
    · by_cases h3 : token (trim x) = true <;> simp [h1, h2, h3, Except.map, te3]

/-- The length and the coding state. -/
abbrev P := Option Nat × T3

def proj (r : Fields) : P := (r.length, te3 r)

/-- Whether a `Connection` value passes `connection`. -/
def connOk (value : Bytes) : Bool :=
  (splitBy 44 value).all fun v => (trim v).isEmpty || token (trim v)

theorem connSteps_proj :
    ∀ (xs : List Bytes) (st : Fields × Bool), (xs.foldlM connStep st).map (fun s => proj s.1) =
      if xs.all (fun v => (trim v).isEmpty || token (trim v)) then .ok (proj st.1) else .error .header := by
  intro xs
  induction xs with
  | nil => intro st; rfl
  | cons x xs ih =>
    intro st
    simp only [List.foldlM_cons, List.all_cons]
    unfold connStep
    by_cases he : (trim x).isEmpty = true
    · simp only [he, ite_true, Bool.true_or, Bool.true_and]
      exact ih st
    · by_cases ht : token (trim x) = true
      · simp only [he, ht, Bool.false_eq_true, ite_false, Bool.not_true, Bool.or_true, Bool.true_and]
        exact ih _
      · simp [he, ht, Except.map]; rfl

theorem connection_proj (value : Bytes) (st : Fields × Bool) :
    (connection value st).map (fun s => proj s.1) =
      if connOk value then .ok (proj st.1) else .error .header :=
  connSteps_proj _ st

/-- `fieldStep` on the length and the coding state. -/
def fieldStepP (v : Version) (p : P) (f : Bytes × Bytes) : Except Error P :=
  if !validField f.1 f.2 then .error .header
  else if eqCI f.1 (str "content-length") then (contentLength f.2 p.1).map (·, p.2)
  else if eqCI f.1 (str "transfer-encoding") then
    if v == .h10 then .error .http10TransferEncoding
    else ((splitBy 44 f.2).foldlM te3Step p.2).map (p.1, ·)
  else if eqCI f.1 (str "connection") then
    if connOk f.2 then .ok p else .error .header
  else .ok p
/-- A quantity every step keeps is kept by a successful fold. -/
theorem foldlM_keeps {α β γ ε : Type} {f : β → α → Except ε β} (Q : β → γ)
    (h : ∀ b a b', f b a = .ok b' → Q b' = Q b) :
    ∀ (xs : List α) (b r : β), xs.foldlM f b = .ok r → Q r = Q b := by
  intro xs
  induction xs with
  | nil => intro b r hr; simp only [List.foldlM, pure, Except.pure, Except.ok.injEq] at hr; rw [hr]
  | cons x xs ih =>
    intro b r hr
    simp only [List.foldlM_cons] at hr
    cases hf : f b x with
    | error e => rw [hf] at hr; cases hr
    | ok b' =>
      rw [hf] at hr
      rw [ih b' r hr, h b x b' hf]

theorem teFold_length : ∀ (xs : List Bytes) (r r' : Fields),
    xs.foldlM teStep r = .ok r' → r'.length = r.length := by
  apply foldlM_keeps Fields.length
  intro b a b' h
  simp only [teStep] at h
  by_cases h1 : (trim a).isEmpty = true
  · simp [h1] at h; rw [← h]
  · by_cases h2 : b.chunked = true
    · simp [h1, h2] at h
    · by_cases h3 : token (trim a) = true
      · simp [h1, h2, h3] at h; rw [← h]
      · simp [h1, h2, h3] at h
theorem fieldStep_proj (v : Version) (st : Fields × Bool) (f : Bytes × Bytes) :
    (fieldStep v st f).map (fun s => proj s.1) = fieldStepP v (proj st.1) f := by
  unfold fieldStep fieldStepP
  by_cases h1 : (!validField f.1 f.2) = true
  · simp only [h1, ite_true]; rfl
  simp only [h1, Bool.false_eq_true, ite_false]
  by_cases h2 : eqCI f.1 (str "content-length") = true
  · simp only [h2, ite_true]
    cases h : contentLength f.2 st.1.length <;> simp [proj, h, Except.map, te3]
  simp only [h2, Bool.false_eq_true, ite_false]
  by_cases h3 : eqCI f.1 (str "transfer-encoding") = true
  · simp only [h3, ite_true, transferEncoding]
    by_cases hv : (v == .h10) = true
    · simp only [hv, ite_true]; rfl
    · simp only [hv, Bool.false_eq_true, ite_false]
      have := foldlM_proj (f := teStep) (g := te3Step) (π := te3) teStep_proj (splitBy 44 f.2) st.1
      have e : (proj st.1).2 = te3 st.1 := rfl
      rw [e, ← this]
      cases hc : (splitBy 44 f.2).foldlM teStep st.1 with
      | error => rfl
      | ok a => simp [Except.map, proj]; exact teFold_length _ _ _ hc
  simp only [h3, Bool.false_eq_true, ite_false]
  by_cases h4 : eqCI f.1 (str "connection") = true
  · simp only [h4, ite_true]
    exact connection_proj f.2 st
  · simp only [h4, Bool.false_eq_true, ite_false]; rfl

/-- What `fields` accepted, on the length and the coding state. -/
theorem fields_proj {fs : List (Bytes × Bytes)} {v : Version} {r : Fields}
    (h : fields fs v = .ok r) :
    ¬(hasName fs "transfer-encoding" = true ∧ hasName fs "content-length" = true) ∧
      fs.foldlM (fieldStepP v) (none, (false, false, false)) = .ok (proj r) ∧
      (hasName fs "transfer-encoding" = true → r.transfer = true) := by
  unfold fields at h
  simp only at h
  by_cases hb : (hasName fs "transfer-encoding" && hasName fs "content-length") = true
  · simp [hb] at h
  · simp only [hb, Bool.false_eq_true, ite_false] at h
    have hp := foldlM_proj (f := fieldStep v) (g := fieldStepP v) (π := fun s => proj s.1)
      (fieldStep_proj v) fs (({} : Fields), false)
    cases hfold : fs.foldlM (fieldStep v) (({} : Fields), false) with
    | error e => rw [hfold] at h; cases h
    | ok s =>
      obtain ⟨r0, k0⟩ := s
      rw [hfold] at h hp
      simp only at h
      by_cases ht : (hasName fs "transfer-encoding" && !r0.transfer) = true
      · simp [ht] at h
      · simp only [ht, Bool.false_eq_true, ite_false, Except.ok.injEq] at h
        subst h
        refine ⟨by simpa using hb, ?_, ?_⟩
        · simp only [Except.map] at hp
          rw [show proj ((({} : Fields), false).1) = (none, (false, false, false)) from rfl] at hp
          rw [← hp]; rfl
        · intro hte; simpa [hte] using ht

/-! ## Reading the walk back -/

/-- The fields named `name`. -/
def named' (fs : List (Bytes × Bytes)) (name : String) : List (Bytes × Bytes) :=
  fs.filter fun f => eqCI f.1 (str name)

/-- The raw list elements of the fields named `name`, in order. -/
def elems (fs : List (Bytes × Bytes)) (name : String) : List Bytes :=
  (named' fs name).flatMap fun f => splitBy 44 f.2

theorem walk_valid {v : Version} :
    ∀ (fs : List (Bytes × Bytes)) p p', fs.foldlM (fieldStepP v) p = .ok p' →
      ∀ f ∈ fs, validField f.1 f.2 = true := by
  apply foldlM_ok_forall
  intro b a b' h
  unfold fieldStepP at h
  split at h
  · cases h
  · rename_i hv; simpa using hv

theorem cl_te_distinct : eqCI (str "content-length") (str "transfer-encoding") = false := by decide +kernel
theorem cl_conn_distinct : eqCI (str "content-length") (str "connection") = false := by decide +kernel
theorem te_conn_distinct : eqCI (str "transfer-encoding") (str "connection") = false := by decide +kernel


/-- Without a `Transfer-Encoding` field, the walk is the `Content-Length`
fold over every element of every `Content-Length` field, in order. -/
theorem walk_noTe {v : Version} :
    ∀ (fs : List (Bytes × Bytes)) (len : Option Nat) (t : T3) (p' : P),
      (∀ f ∈ fs, eqCI f.1 (str "transfer-encoding") = false) →
      fs.foldlM (fieldStepP v) (len, t) = .ok p' →
      p'.2 = t ∧ (elems fs "content-length").foldlM clStep len = .ok p'.1 := by
  intro fs
  induction fs with
  | nil =>
    intro len t p' _ h
    simp only [List.foldlM, pure, Except.pure, Except.ok.injEq] at h
    subst h
    exact ⟨rfl, rfl⟩
  | cons f fs ih =>
    intro len t p' hte h
    have hf : eqCI f.1 (str "transfer-encoding") = false := hte f (by simp)
    simp only [List.foldlM_cons] at h
    unfold fieldStepP at h
    by_cases hv : (!validField f.1 f.2) = true
    · simp [hv] at h; cases h
    simp only [hv, Bool.false_eq_true, ite_false] at h
    by_cases hcl : eqCI f.1 (str "content-length") = true
    · simp only [hcl, ite_true] at h
      cases hc : contentLength f.2 len with
      | error e => rw [hc] at h; cases h
      | ok l =>
        rw [hc] at h
        obtain ⟨h1, h2⟩ := ih l t p' (fun g hg => hte g (by simp [hg])) h
        refine ⟨h1, ?_⟩
        simp only [elems, named', List.filter_cons, hcl, ite_true, List.flatMap_cons,
          List.foldlM_append]
        simp only [contentLength] at hc
        rw [hc]
        exact h2
    · simp only [hcl, Bool.false_eq_true, ite_false, hf] at h
      have hrest : elems (f :: fs) "content-length" = elems fs "content-length" := by
        simp [elems, named', List.filter_cons, hcl]
      rw [hrest]
      by_cases hco : eqCI f.1 (str "connection") = true
      · simp only [hco, ite_true] at h
        by_cases hok : connOk f.2 = true
        · simp only [hok, ite_true] at h
          exact ih len t p' (fun g hg => hte g (by simp [hg])) h
        · simp [hok] at h; cases h
      · simp only [hco, Bool.false_eq_true, ite_false] at h
        exact ih len t p' (fun g hg => hte g (by simp [hg])) h

/-- Without a `Content-Length` field, the walk is the coding fold over every
element of every `Transfer-Encoding` field, in order, on HTTP/1.1 only. -/
theorem walk_noCl {v : Version} :
    ∀ (fs : List (Bytes × Bytes)) (len : Option Nat) (t : T3) (p' : P),
      (∀ f ∈ fs, eqCI f.1 (str "content-length") = false) →
      fs.foldlM (fieldStepP v) (len, t) = .ok p' →
      p'.1 = len ∧ (hasName fs "transfer-encoding" = true → v = .h11) ∧
        (elems fs "transfer-encoding").foldlM te3Step t = .ok p'.2 := by
  intro fs
  induction fs with
  | nil =>
    intro len t p' _ h
    simp only [List.foldlM, pure, Except.pure, Except.ok.injEq] at h
    subst h
    exact ⟨rfl, by simp [hasName], rfl⟩
  | cons f fs ih =>
    intro len t p' hcl h
    have hf : eqCI f.1 (str "content-length") = false := hcl f (by simp)
    have ih' := fun len t p' => ih len t p' (fun g hg => hcl g (by simp [hg]))
    simp only [List.foldlM_cons] at h
    cases hs : fieldStepP v (len, t) f with
    | error e => rw [hs] at h; cases h
    | ok p1 =>
      rw [hs] at h
      change fs.foldlM (fieldStepP v) p1 = .ok p' at h
      unfold fieldStepP at hs
      by_cases hv : (!validField f.1 f.2) = true
      · simp [hv] at hs
      simp only [hv, Bool.false_eq_true, ite_false, hf] at hs
      by_cases hte : eqCI f.1 (str "transfer-encoding") = true
      · simp only [hte, ite_true] at hs
        by_cases h10 : (v == .h10) = true
        · simp [h10] at hs
        simp only [h10, Bool.false_eq_true, ite_false] at hs
        cases hc : (splitBy 44 f.2).foldlM te3Step t with
        | error e => rw [hc] at hs; cases hs
        | ok t' =>
          rw [hc] at hs
          simp only [Except.map, Except.ok.injEq] at hs
          subst hs
          obtain ⟨h1, _, h3⟩ := ih' len t' p' h
          refine ⟨h1, ?_, ?_⟩
          · intro _; cases v
            · exact absurd rfl h10
            · rfl
          · simp only [elems, named', List.filter_cons, hte, ite_true, List.flatMap_cons,
              List.foldlM_append]
            rw [hc]
            exact h3
      · simp only [hte, Bool.false_eq_true, ite_false] at hs
        have hrest : elems (f :: fs) "transfer-encoding" = elems fs "transfer-encoding" := by
          simp [elems, named', hte]
        have hname : hasName (f :: fs) "transfer-encoding" = hasName fs "transfer-encoding" := by
          simp [hasName, hte]
        rw [hrest, hname]
        by_cases hco : eqCI f.1 (str "connection") = true
        · simp only [hco, ite_true] at hs
          by_cases hok : connOk f.2 = true
          · simp only [hok, ite_true, Except.ok.injEq] at hs
            subst hs
            exact ih' len t p' h
          · simp [hok] at hs
        · simp only [hco, Bool.false_eq_true, ite_false, Except.ok.injEq] at hs
          subst hs
          exact ih' len t p' h

/-! ## The folds' results -/

/-- The `Content-Length` fold: every element is the same number, the result. -/
theorem cl_fold : ∀ (xs : List Bytes) (acc res : Option Nat), xs.foldlM clStep acc = .ok res →
    (∀ x ∈ xs, decimal (trim x) = res) ∧ (xs = [] → res = acc) ∧
      (xs ≠ [] → ∀ a, acc = some a → res = some a) := by
  intro xs
  induction xs with
  | nil =>
    intro acc res h
    simp only [List.foldlM, pure, Except.pure, Except.ok.injEq] at h
    subst h
    simp
  | cons x xs ih =>
    intro acc res h
    simp only [List.foldlM_cons] at h
    unfold clStep at h
    cases hd : decimal (trim x) with
    | none => rw [hd] at h; cases h
    | some n =>
      rw [hd] at h
      by_cases hc : (acc.any (· != n)) = true
      · simp [hc] at h; cases h
      · simp only [hc, Bool.false_eq_true, ite_false] at h
        obtain ⟨h1, h2, h3⟩ := ih (some n) res h
        have hres : res = some n := by
          by_cases he : xs = []
          · exact h2 he
          · exact h3 he n rfl
        refine ⟨?_, by simp, ?_⟩
        · intro y hy
          simp only [List.mem_cons] at hy
          rcases hy with rfl | hy
          · rw [hd, hres]
          · exact h1 y hy
        · intro _ a ha
          subst ha
          simp only [Option.any_some, bne_iff_ne, ne_eq, decide_eq_true_eq, Decidable.not_not] at hc
          rw [hres, hc]


/-- A `Content-Length` fold over at least one element gives a number. -/
theorem cl_fold_some {x : Bytes} {xs : List Bytes} {acc res : Option Nat}
    (h : (x :: xs).foldlM clStep acc = .ok res) : ∃ n, res = some n := by
  simp only [List.foldlM_cons] at h
  unfold clStep at h
  cases hd : decimal (trim x) with
  | none => rw [hd] at h; cases h
  | some n =>
    rw [hd] at h
    by_cases hc : (acc.any (· != n)) = true
    · simp [hc] at h; cases h
    · simp only [hc, Bool.false_eq_true, ite_false] at h
      obtain ⟨_, h2, h3⟩ := cl_fold xs (some n) res h
      by_cases he : xs = []
      · exact ⟨n, h2 he⟩
      · exact ⟨n, h3 he n rfl⟩
/-- The non-empty elements, without their whitespace. -/
def nonEmpty (xs : List Bytes) : List Bytes := (xs.map trim).filter fun x => !x.isEmpty

/-- After `chunked` no element may follow. -/
theorem te3_after_chunked : ∀ (xs : List Bytes) (tr un : Bool) (t' : T3),
    xs.foldlM te3Step (tr, true, un) = .ok t' → nonEmpty xs = [] ∧ t' = (tr, true, un) := by
  intro xs
  induction xs with
  | nil =>
    intro tr un t' h
    simp only [List.foldlM, pure, Except.pure, Except.ok.injEq] at h
    exact ⟨rfl, h.symm⟩
  | cons x xs ih =>
    intro tr un t' h
    simp only [List.foldlM_cons] at h
    unfold te3Step at h
    by_cases he : (trim x).isEmpty = true
    · simp only [he, ite_true] at h
      obtain ⟨h1, h2⟩ := ih tr un t' h
      exact ⟨by simp [nonEmpty, he] at h1 ⊢; exact h1, h2⟩
    · simp [he] at h; cases h

/-- A coding fold that ends in `chunked` with nothing unsupported read
exactly one coding, `chunked`. -/
theorem te3_chunked : ∀ (xs : List Bytes) (tr un tr' : Bool),
    xs.foldlM te3Step (tr, false, un) = .ok (tr', true, false) →
      un = false ∧ ∃ x, nonEmpty xs = [x] ∧ token x = true ∧ eqCI x (str "chunked") = true := by
  intro xs
  induction xs with
  | nil =>
    intro tr un tr' h
    simp [List.foldlM, pure, Except.pure] at h
  | cons x xs ih =>
    intro tr un tr' h
    simp only [List.foldlM_cons] at h
    unfold te3Step at h
    by_cases he : (trim x).isEmpty = true
    · simp only [he, ite_true] at h
      obtain ⟨h1, y, h2, h3⟩ := ih tr un tr' h
      exact ⟨h1, y, by simp [nonEmpty, he] at h2 ⊢; exact h2, h3⟩
    · simp only [he, Bool.false_eq_true, ite_false] at h
      by_cases ht : token (trim x) = true
      · simp only [ht, Bool.not_true, Bool.false_eq_true, ite_false] at h
        by_cases hc : eqCI (trim x) (str "chunked") = true
        · simp only [hc, Bool.not_true, Bool.or_false] at h
          obtain ⟨h1, h2⟩ := te3_after_chunked xs true un _ h
          simp only [Prod.mk.injEq] at h2
          refine ⟨h2.2.2.symm, trim x, ?_, ht, hc⟩
          simp [nonEmpty, he]
          simpa [nonEmpty] using h1
        · simp only [hc, Bool.false_eq_true, Bool.not_false, Bool.or_true] at h
          have := (ih true true tr' h).1
          cases this
      · simp [ht] at h; cases h

end Http.FieldsProof
