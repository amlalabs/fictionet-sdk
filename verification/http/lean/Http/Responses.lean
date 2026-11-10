import Http.RequestTie

/-!
# Response framing: the decoder follows RFC 9112 section 6.3

For every response head `Wire.fields` accepts, `Wire.responseFraming` (the
response decoder's `response_framing`) frames the body as every recipient
in the family `Rfc.responseFraming` does: items 1 and 2 (no body for HEAD,
1xx, 204, 304 and a 2xx to CONNECT), item 4 (chunked when chunked is the
final coding, the close otherwise), items 6 and 8. Heads the RFC calls
invalid (items 3 and 5) the decoder refuses.
-/

namespace Http.Responses

open Wire FieldsProof Smuggling RequestTie

/-- The coding fold from any state: the transfer flag is set by any coding,
`chunked` is whether the last coding is `chunked`, and every coding is a
token. -/
theorem te3_fold : ∀ (xs : List Bytes) (tr ch un : Bool) (t : T3),
    xs.foldlM te3Step (tr, ch, un) = .ok t →
      (nonEmpty xs = [] → t.1 = tr ∧ t.2.1 = ch) ∧
      (∀ y ys, nonEmpty xs = y :: ys → t.1 = true ∧ t.2.1 = eqCI ((y :: ys).getLast (by simp)) (str "chunked") ∧
        ∀ x ∈ y :: ys, token x = true) := by
  intro xs
  induction xs with
  | nil =>
    intro tr ch un t h
    simp only [List.foldlM, pure, Except.pure, Except.ok.injEq] at h
    subst h
    exact ⟨fun _ => ⟨rfl, rfl⟩, fun y ys h => by simp [nonEmpty] at h⟩
  | cons x xs ih =>
    intro tr ch un t h
    simp only [List.foldlM_cons] at h
    unfold te3Step at h
    by_cases he : (trim x).isEmpty = true
    · simp only [he, ite_true] at h
      have hne : nonEmpty (x :: xs) = nonEmpty xs := by simp [nonEmpty, he]
      rw [hne]
      exact ih tr ch un t h
    · simp only [he, Bool.false_eq_true, ite_false] at h
      by_cases hch : ch = true
      · simp [hch] at h; cases h
      simp only [hch, Bool.false_eq_true, ite_false] at h
      by_cases ht : token (trim x) = true
      · simp only [ht, Bool.not_true, Bool.false_eq_true, ite_false] at h
        obtain ⟨ih1, ih2⟩ := ih _ _ _ t h
        have hne : nonEmpty (x :: xs) = trim x :: nonEmpty xs := by simp [nonEmpty, he]
        rw [hne]
        refine ⟨fun h => by simp at h, ?_⟩
        intro y ys hy
        simp only [List.cons.injEq] at hy
        obtain ⟨rfl, hys⟩ := hy
        cases hrest : nonEmpty xs with
        | nil =>
          obtain ⟨a1, a2⟩ := ih1 hrest
          rw [hrest] at hys; subst hys
          refine ⟨a1, by simp [a2], ?_⟩
          intro z hz; simp at hz; subst hz; exact ht
        | cons z zs =>
          obtain ⟨b1, b2, b3⟩ := ih2 z zs hrest
          rw [hrest] at hys; subst hys
          refine ⟨b1, by rw [b2]; simp [List.getLast_cons], ?_⟩
          intro w hw
          simp only [List.mem_cons] at hw
          rcases hw with rfl | hw
          · exact ht
          · exact b3 w (by simp [hw])
      · simp [ht] at h; cases h

theorem map_self {f : Bytes → Bytes} : ∀ l : List Bytes, (∀ x ∈ l, f x = x) → l.map f = l
  | [], _ => rfl
  | x :: l, h => by simp [h x (by simp), map_self l (fun y hy => h y (by simp [hy]))]

/-- The method class of `Wire` as the RFC's. -/
def asked : Method → Rfc.Asked
  | .other => .other
  | .head => .head
  | .connect => .connect

/-- **Response framing.** For every response head the decoder accepts,
every recipient frames the body as the decoder does, except one that uses
its option to refuse a repeated `Content-Length`, which refuses the
response. -/
theorem response_framing_agrees {fs : List (Bytes × Bytes)} {v : Version} {r : Fields}
    (hf : fields fs v = .ok r) (m : Method) (code : Nat) (c : Rfc.Choices) :
    Rfc.responseFraming c (asked m) code fs = some (responseFraming code r m) ∨
      (c.clList = false ∧ Rfc.responseFraming c (asked m) code fs = none) := by
  obtain ⟨hboth, hwalk, htr⟩ := fields_proj hf
  unfold Rfc.responseFraming responseFraming
  simp only []
  -- items 1 and 2: the same responses have no body
  by_cases hno : (asked m == .head || decide (code < 200) || code == 204 || code == 304) = true
  · rw [if_pos hno]
    left
    have : ((decide (code < 200) || code == 204) ||
        (m == .head || code == 304 || (m == .connect && decide (200 ≤ code) && decide (code < 300)))) = true := by
      cases m <;> simp_all [asked] <;> omega
    by_cases h1 : (decide (code < 200) || code == 204) = true
    · simp [h1]
    · simp only [h1, Bool.false_eq_true, ite_false]
      simp only [h1, Bool.false_or] at this
      simp [this]
  rw [if_neg hno]
  have hlow : ¬(decide (code < 200) || code == 204) = true := by
    intro h; apply hno; cases m <;> simp_all [asked]
  rw [if_neg hlow]
  by_cases hcon : (asked m == .connect && decide (code < 300)) = true
  · rw [if_pos hcon]
    left
    have : (m == .head || code == 304 || (m == .connect && decide (200 ≤ code) && decide (code < 300))) = true := by
      cases m <;> simp_all [asked] <;> omega
    simp [this]
  rw [if_neg hcon]
  have hmid : ¬(m == .head || code == 304 || (m == .connect && decide (200 ≤ code) && decide (code < 300))) = true := by
    intro h; cases m <;> simp_all [asked] <;> omega
  rw [if_neg hmid]
  -- items 3, 4, 6 and 8
  by_cases hte : hasName fs "transfer-encoding" = true
  · have hcl : hasName fs "content-length" = false := by
      cases h : hasName fs "content-length"
      · rfl
      · exact absurd ⟨hte, h⟩ hboth
    obtain ⟨_, _, hfold⟩ := walk_noCl fs none _ _ (no_name hcl) hwalk
    have htrue := htr hte
    obtain ⟨h1, h2⟩ := te3_fold _ false false false _ hfold
    have hteR : Rfc.values fs "transfer-encoding" ≠ [] := (hasName_iff fs _).mp hte
    have hclR : Rfc.values fs "content-length" = [] := by
      have : ¬Rfc.values fs "content-length" ≠ [] := by
        intro h; rw [← hasName_iff] at h; rw [hcl] at h; cases h
      simpa using this
    rw [if_pos hteR]
    simp only [hclR, ne_eq, not_true_eq_false, decide_false, Bool.false_and, Bool.false_eq_true,
      ite_false]
    left
    cases hE : nonEmpty (elems fs "transfer-encoding") with
    | nil =>
      have := (h1 hE).1
      simp [proj, te3, htrue] at this
    | cons y ys =>
      obtain ⟨_, hch, htok⟩ := h2 y ys hE
      have hcod : Rfc.codings fs = y :: ys := by
        simp only [Rfc.codings, flat_values]
        rw [filter_ne_nil, show List.filter (fun x => !x.isEmpty)
          (List.map Wire.trim (elems fs "transfer-encoding")) =
            nonEmpty (elems fs "transfer-encoding") from rfl, hE]
        exact map_self _ (fun x hx => by
          rw [token_noSemi (htok x hx), stripOws_eq, token_trim (htok x hx)])
      have hchr : r.chunked = eqCI ((y :: ys).getLast (by simp)) (str "chunked") := hch
      rw [hcod, List.getLast?_eq_getLast (by simp)]
      simp only [ci_eq, show Rfc.ascii "chunked" = str "chunked" from rfl]
      rw [← hchr]
      cases hc : r.chunked <;> simp [htrue]
  · have hte' : hasName fs "transfer-encoding" = false := by simpa using hte
    obtain ⟨hp2, hfold⟩ := walk_noTe fs none _ _ (no_name hte') hwalk
    have htrf : r.transfer = false := by
      have := congrArg (fun t : T3 => t.1) hp2
      simpa [proj, te3] using this
    have hchf : r.chunked = false := by
      have := congrArg (fun t : T3 => t.2.1) hp2
      simpa [proj, te3] using this
    have hteR : ¬Rfc.values fs "transfer-encoding" ≠ [] := by
      intro h; rw [← hasName_iff] at h; rw [hte'] at h; cases h
    rw [if_neg hteR]
    simp only [hchf, htrf, Bool.false_eq_true, ite_false]
    obtain ⟨hall, hnil, _⟩ := cl_fold _ none _ hfold
    by_cases hcl : hasName fs "content-length" = true
    · have hclR : Rfc.values fs "content-length" ≠ [] := (hasName_iff fs _).mp hcl
      rw [if_pos hclR]
      have hne := elems_ne_nil hcl
      obtain ⟨n, hn⟩ : ∃ n, (proj r).1 = some n := by
        cases he : elems fs "content-length" with
        | nil => exact absurd he hne
        | cons y ys => rw [he] at hfold; exact cl_fold_some hfold
      have hrl : r.length = some n := hn
      simp only [hrl]
      have hdig : ∀ y ∈ (elems fs "content-length").map Wire.trim,
          y ≠ [] ∧ y.all Rfc.DIGIT = true ∧ Rfc.decimalValue y = n := by
        intro y hy
        simp only [List.mem_map] at hy
        obtain ⟨z, hz, rfl⟩ := hy
        have := hall z hz
        rw [hn] at this
        exact decimal_some this
      unfold Rfc.contentLength
      simp only [flat_values]
      cases hes : (elems fs "content-length").map Wire.trim with
      | nil => simp at hes; exact absurd hes hne
      | cons e rest =>
        rw [hes] at hdig
        have hall' : ((e :: rest).all fun x => x ≠ [] && x.all Rfc.DIGIT) = true := by
          apply List.all_eq_true.mpr
          intro y hy
          obtain ⟨h1, h2, _⟩ := hdig y hy
          simp [h1, h2]
        simp only [hall', Bool.not_true, Bool.false_eq_true, ite_false]
        have heq : (rest.all fun x => Rfc.decimalValue x == Rfc.decimalValue e) = true := by
          apply List.all_eq_true.mpr
          intro y hy
          rw [(hdig y (by simp [hy])).2.2, (hdig e (by simp)).2.2]
          simp
        by_cases hrest : rest = []
        · left
          simp [hrest, (hdig e (by simp)).2.2]
        · cases hc : c.clList
          · right
            simp [hrest, hc]
          · left
            simp [hc, heq, (hdig e (by simp)).2.2]
            intro x hx; exact (hdig x (by simp [hx])).2.2
    · have hclR : ¬Rfc.values fs "content-length" ≠ [] := by
        intro h; rw [← hasName_iff] at h; exact hcl h
      rw [if_neg hclR]
      have hcl' : hasName fs "content-length" = false := by simpa using hcl
      have hlen : r.length = none := hnil (elems_nil hcl')
      simp [hlen]

end Http.Responses
