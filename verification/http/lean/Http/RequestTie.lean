import Http.Smuggling
import Http.Request

/-!
# `Request.lean` is the decoder's framing

`Http.requestFraming` in `Request.lean` states the request framing rules of
RFC 9112 sections 6.1 and 6.3 over an abstract head: the named transfer
codings and the `Content-Length` elements. This file ties it to the
decoder: for every head `Wire.fields` and `Wire.requestFraming` accept,
`Http.requestFraming` of the head's codings and lengths gives the same
framing. `Wire` is tied to the Rust decoder by the vectors, and
`Gen.lean` also writes `framing.json`, whose expected results come from
`Http.requestFraming` itself.
-/

namespace Http.RequestTie

open Wire FieldsProof Smuggling

/-- The codings `Request.lean` reads from a head: one per non-empty list
element of every `Transfer-Encoding` field, `true` for `chunked`; `none`
without the field. -/
def teAbs (fs : List (Bytes × Bytes)) : Option (List Bool) :=
  if hasName fs "transfer-encoding" then
    some ((nonEmpty (elems fs "transfer-encoding")).map (eqCI · (str "chunked")))
  else none

/-- The `Content-Length` elements `Request.lean` reads: each a number or
`none`; `none` without the field. -/
def clAbs (fs : List (Bytes × Bytes)) : Option (List (Option Nat)) :=
  if hasName fs "content-length" then some ((elems fs "content-length").map (decimal ∘ trim))
  else none

theorem no_name {fs : List (Bytes × Bytes)} {name : String} (h : hasName fs name = false) :
    ∀ g ∈ fs, eqCI g.1 (str name) = false := by
  intro g hg
  cases he : eqCI g.1 (str name)
  · rfl
  · have : hasName fs name = true := List.any_eq_true.mpr ⟨g, hg, he⟩
    rw [h] at this; cases this

theorem elems_nil {fs : List (Bytes × Bytes)} {name : String} (h : hasName fs name = false) :
    elems fs name = [] := by
  have : named' fs name = [] := by
    simp only [named', List.filter_eq_nil_iff]
    intro g hg
    simp [no_name h g hg]
  simp [elems, this]

theorem elems_ne_nil {fs : List (Bytes × Bytes)} {name : String} (h : hasName fs name = true) :
    elems fs name ≠ [] := by
  obtain ⟨g, hg, he⟩ := List.any_eq_true.mp h
  have hmem : g ∈ named' fs name := List.mem_filter.mpr ⟨hg, he⟩
  intro hnil
  have : splitBy 44 g.2 = [] := by
    simp only [elems, List.flatMap_eq_nil_iff] at hnil
    exact hnil g hmem
  exact splitBy_ne_nil 44 g.2 this

theorem replicate_of_all {α : Type} [DecidableEq α] {l : List α} {a : α} (h : ∀ x ∈ l, x = a) :
    l = List.replicate l.length a := List.eq_replicate_iff.mpr ⟨rfl, h⟩

/-- **The tie.** For every request head the decoder accepts, the framing
rules of `Request.lean`, applied to that head's codings and lengths, give
the decoder's framing. -/
theorem wire_framing_is_request {fs : List (Bytes × Bytes)} {v : Version} {r : Fields} {f : Framing}
    (hf : fields fs v = .ok r) (hr : Wire.requestFraming r = .ok f) :
    Http.requestFraming v (teAbs fs) (clAbs fs) = .ok f := by
  obtain ⟨hboth, hwalk, htr⟩ := fields_proj hf
  unfold Wire.requestFraming at hr
  by_cases hte : hasName fs "transfer-encoding" = true
  · have hcl : hasName fs "content-length" = false := by
      cases h : hasName fs "content-length"
      · rfl
      · exact absurd ⟨hte, h⟩ hboth
    obtain ⟨_, h11, hfold⟩ := walk_noCl fs none _ _ (no_name hcl) hwalk
    have hv := h11 hte
    subst hv
    have htrue := htr hte
    simp only [htrue, ite_true] at hr
    by_cases hch : r.chunked = true
    · simp only [hch, Bool.not_true, Bool.false_eq_true, ite_false] at hr
      by_cases hun : r.unsupported = true
      · simp [hun] at hr
      · simp only [hun, Bool.false_eq_true, ite_false, Except.ok.injEq] at hr
        subst hr
        have hp : (proj r).2 = (true, true, false) := by
          simp [proj, te3, htrue, hch, hun]
        rw [hp] at hfold
        obtain ⟨_, x, hx, _, hchunk⟩ := te3_chunked _ false false true hfold
        simp only [teAbs, clAbs, hte, hcl, ite_true, Bool.false_eq_true, ite_false, hx,
          List.map_cons, List.map_nil, hchunk]
        rfl
    · have hch' : r.chunked = false := by simpa using hch
      simp [hch'] at hr
  · have hte' : hasName fs "transfer-encoding" = false := by simpa using hte
    obtain ⟨hp2, hfold⟩ := walk_noTe fs none _ _ (no_name hte') hwalk
    have htrf : r.transfer = false := by
      have := congrArg (fun t : T3 => t.1) hp2
      simpa [proj, te3] using this
    simp only [htrf, Bool.false_eq_true, ite_false] at hr
    obtain ⟨hall, hnil, _⟩ := cl_fold _ none _ hfold
    by_cases hcl : hasName fs "content-length" = true
    · have hne := elems_ne_nil hcl
      obtain ⟨n, hn⟩ : ∃ n, (proj r).1 = some n := by
        cases he : elems fs "content-length" with
        | nil => exact absurd he hne
        | cons y ys => rw [he] at hfold; exact cl_fold_some hfold
      have hrl : r.length = some n := hn
      simp only [hrl, Except.ok.injEq] at hr
      subst hr
      have hsome : ∀ x ∈ (elems fs "content-length").map (decimal ∘ trim), x = some n := by
        intro x hx
        simp only [List.mem_map, Function.comp] at hx
        obtain ⟨y, hy, rfl⟩ := hx
        rw [hall y hy, hn]
      have hlen : ((elems fs "content-length").map (decimal ∘ trim)).length =
          ((elems fs "content-length").map (decimal ∘ trim)).length - 1 + 1 := by
        have : ((elems fs "content-length").map (decimal ∘ trim)) ≠ [] := by simpa using hne
        have := List.length_pos_iff.mpr this
        omega
      simp only [teAbs, clAbs, hte', hcl, ite_true, Bool.false_eq_true, ite_false]
      rw [replicate_of_all hsome, hlen]
      exact same_lengths_accepted v _ n
    · have hcl' : hasName fs "content-length" = false := by simpa using hcl
      have hlen : r.length = none := hnil (elems_nil hcl')
      simp only [hlen, Except.ok.injEq] at hr
      subst hr
      simp only [teAbs, clAbs, hte', hcl', Bool.false_eq_true, ite_false]
      rfl

end Http.RequestTie
