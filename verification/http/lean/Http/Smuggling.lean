import Http.Lines
import Http.Fields

/-!
# No request smuggling: the server and every RFC 9112 recipient agree

The main theorem, `request_agrees`, says: for every request the server's
decoder (`Wire.request1`, tied to `RequestEvents` by the vectors) accepts,
every recipient in the family `Rfc.request` (every combination of the
tolerances RFC 9112 allows, `Rfc.Choices`) that accepts the same bytes finds
the same head, the same method, the same body framing, the same body and the
same end of the message; and the recipients that take the RFC's tolerances
(bare LF, bare CR, obs-fold, whitespace, Transfer-Encoding over
Content-Length) accept it, so their agreement is not empty. A front end that
follows RFC 9112 cannot see a message boundary where the server sees none,
or miss one the server sees.
-/

namespace Http.Smuggling

open Wire Lines

/-! ## Characters: the RFC's definitions and the decoder's agree -/

theorem tchar_eq (b : Nat) : Rfc.tchar b = Wire.tchar b := by
  simp only [Rfc.tchar, Wire.tchar, Wire.isAlnum, Wire.isDigit, Wire.isAlpha, Rfc.DIGIT, Rfc.ALPHA,
    List.contains_eq_mem, List.mem_cons, List.mem_nil_iff, or_false]
  apply Bool.eq_iff_iff.mpr
  simp only [Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq]
  omega

theorem tchar_fun : Rfc.tchar = Wire.tchar := funext tchar_eq

theorem token_eq (bs : Bytes) : Rfc.token bs = Wire.token bs := by
  simp only [Rfc.token, Wire.token, tchar_fun]
  cases bs <;> simp

theorem ows_eq (b : Nat) : Rfc.ows b = Wire.isWs b := by
  simp [Rfc.ows, Wire.isWs, Rfc.SP, Rfc.HTAB]

theorem stripOws_eq (bs : Bytes) : Rfc.stripOws bs = Wire.trim bs := by
  have : Rfc.ows = Wire.isWs := funext ows_eq
  simp [Rfc.stripOws, Wire.trim, this]

theorem lower_eq (b : Nat) : Rfc.lowerB b = Wire.lower b := by
  simp [Rfc.lowerB, Wire.lower]

theorem ci_eq (a b : Bytes) : Rfc.ci a b = Wire.eqCI a b := by
  have : Rfc.lowerB = Wire.lower := funext lower_eq
  simp [Rfc.ci, Wire.eqCI, this]

/-- A token has no whitespace, CR or LF in it. -/
theorem tchar_not_ws {b : Nat} (h : Wire.tchar b = true) : Rfc.ws b = false ∧ b ≠ 13 ∧ b ≠ 10 := by
  simp only [Wire.tchar, Wire.isAlnum, Wire.isDigit, Wire.isAlpha, List.contains_eq_mem,
    List.mem_cons, List.mem_nil_iff, or_false, Bool.or_eq_true, Bool.and_eq_true,
    decide_eq_true_eq] at h
  simp only [Rfc.ws, Rfc.SP, Rfc.HTAB, Rfc.CR, Bool.or_eq_false_iff, beq_eq_false_iff_ne]
  omega

theorem fieldByte_not_crlf {b : Nat} (h : Wire.fieldByte b = true) : b ≠ 13 ∧ b ≠ 10 := by
  simp only [Wire.fieldByte, Bool.or_eq_true, beq_iff_eq, Bool.and_eq_true, decide_eq_true_eq,
    bne_iff_ne] at h
  omega

/-! ## Trimming -/

theorem mem_takeWhile {p : Nat → Bool} {l : Bytes} {x : Nat} (h : x ∈ l.takeWhile p) : p x = true :=
  List.all_eq_true.mp List.all_takeWhile x h

/-- `trim` takes only spaces and tabs off either end. -/
theorem trim_split (bs : Bytes) :
    ∃ a z, bs = a ++ Wire.trim bs ++ z ∧ (∀ x ∈ a, Wire.isWs x = true) ∧ (∀ x ∈ z, Wire.isWs x = true) := by
  refine ⟨bs.takeWhile Wire.isWs, ((bs.dropWhile Wire.isWs).reverse.takeWhile Wire.isWs).reverse, ?_, ?_, ?_⟩
  · have hd : bs.dropWhile Wire.isWs =
        ((bs.dropWhile Wire.isWs).reverse.dropWhile Wire.isWs).reverse ++
          ((bs.dropWhile Wire.isWs).reverse.takeWhile Wire.isWs).reverse := by
      conv => lhs; rw [← List.reverse_reverse (List.dropWhile Wire.isWs bs),
        ← List.takeWhile_append_dropWhile (p := Wire.isWs) (l := (List.dropWhile Wire.isWs bs).reverse)]
      rw [List.reverse_append]
    simp only [Wire.trim]
    conv => lhs; rw [← List.takeWhile_append_dropWhile (p := Wire.isWs) (l := bs), hd]
    simp
  · intro x hx
    exact mem_takeWhile hx
  · intro x hx
    rw [List.mem_reverse] at hx
    exact mem_takeWhile hx


/-- A field line the decoder accepted: a token, a colon, and a value of field
bytes with spaces and tabs around it. -/
theorem headerParts_ok {l name value : Bytes} (h : headerParts l = .ok (name, value)) :
    ∃ raw, l = name ++ 58 :: raw ∧ value = Wire.trim raw ∧ 58 ∉ name := by
  unfold headerParts at h
  simp only [findByte] at h
  split at h
  · simp at h
  · rename_i i hi
    split at h
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨a, hsplit, ha, hpre⟩ := findIdx?_some hi
      have ha' : a = 58 := by simpa using ha
      subst ha'
      refine ⟨l.drop (i + 1), hsplit, rfl, ?_⟩
      intro hm
      have := hpre 58 hm
      simp at this
    · simp at h


/-- A field line the decoder accepted (`headerParts`, then `validField` in
`fields`): no CR or LF in it, it does not start with whitespace, and the RFC
reads the same name and value from it. -/
theorem accepted_field {l name value : Bytes} (h : headerParts l = .ok (name, value))
    (hv : validField name value = true) :
    13 ∉ l ∧ 10 ∉ l ∧ Rfc.ows (l.headD 0) = false ∧ Rfc.field l = some (name, value) := by
  obtain ⟨raw, rfl, rfl, h58⟩ := headerParts_ok h
  simp only [validField, Bool.and_eq_true, beq_iff_eq] at hv
  obtain ⟨⟨htok, hbytes⟩, _⟩ := hv
  have hne : name ≠ [] := by intro e; simp [e, Wire.token] at htok
  have htc : ∀ x ∈ name, Wire.tchar x = true := by
    simp only [Wire.token, Bool.and_eq_true] at htok
    exact List.all_eq_true.mp htok.2
  obtain ⟨a, z, hraw, ha, hz⟩ := trim_split raw
  have hrawb : ∀ x ∈ raw, x ≠ 13 ∧ x ≠ 10 := by
    intro x hx
    rw [hraw] at hx
    simp only [List.mem_append] at hx
    rcases hx with (hx | hx) | hx
    · have := ha x hx; simp [Wire.isWs] at this; omega
    · exact fieldByte_not_crlf (List.all_eq_true.mp hbytes x hx)
    · have := hz x hx; simp [Wire.isWs] at this; omega
  refine ⟨?_, ?_, ?_, ?_⟩
  · simp only [List.mem_append, List.mem_cons, not_or]
    refine ⟨fun hm => (tchar_not_ws (htc 13 hm)).2.1 rfl, by decide, fun hm => (hrawb 13 hm).1 rfl⟩
  · simp only [List.mem_append, List.mem_cons, not_or]
    refine ⟨fun hm => (tchar_not_ws (htc 10 hm)).2.2 rfl, by decide, fun hm => (hrawb 10 hm).2 rfl⟩
  · match name, hne, htc with
    | x :: _, _, htc =>
      have := tchar_not_ws (htc x (by simp))
      simp only [List.cons_append, List.headD_cons]
      simp only [Rfc.ws, Bool.or_eq_false_iff] at this
      simp [Rfc.ows, this.1.1.1.1]
  · simp only [Rfc.field]
    rw [findIdx?_hit name raw 58 (fun x hx => by
      have : x ≠ 58 := fun e => h58 (e ▸ hx)
      simpa using this) (by decide)]
    simp [token_eq, htok, stripOws_eq]

/-! ## The RFC's lines over an accepted head -/

/-- A line with no CR or LF in it, ended by CR LF, is that line to every
recipient. -/
theorem rfc_line (c : Rfc.Choices) (l r : Bytes) (h13 : 13 ∉ l) (h10 : 10 ∉ l) :
    Rfc.line c (l ++ 13 :: 10 :: r) = some (l, r) := by
  have hl : ∀ x ∈ l ++ [13], (x == Rfc.LF) = false := by
    intro x hx
    simp only [List.mem_append, List.mem_singleton] at hx
    rcases hx with hx | rfl
    · have : x ≠ 10 := fun e => h10 (e ▸ hx)
      simpa [Rfc.LF] using this
    · decide
  have e : l ++ 13 :: 10 :: r = (l ++ [13]) ++ 10 :: r := by simp
  simp only [Rfc.line]
  rw [e, findIdx?_hit (l ++ [13]) r 10 hl (by decide)]
  have ht : ((l ++ [13]) ++ 10 :: r).take (l ++ [13]).length = l ++ [13] := List.take_left
  have hd : ((l ++ [13]) ++ 10 :: r).drop ((l ++ [13]).length + 1) = r := by
    have e2 : (l ++ [13]) ++ 10 :: r = l ++ (13 :: 10 :: r) := by simp
    rw [e2, List.length_append, List.length_singleton, Nat.add_assoc, List.drop_append]
    simp [List.drop_eq_nil_of_le]
  simp only []
  rw [ht, hd]

  simp [Rfc.CR, h13]

/-- The field lines of an accepted head, to every recipient: the same lines,
then the bytes after the head. -/
theorem rfc_fieldLines (c : Rfc.Choices) (ls : List Bytes) (r : Bytes)
    (h : ∀ l ∈ ls, 13 ∉ l ∧ 10 ∉ l ∧ l ≠ [] ∧ Rfc.ows (l.headD 0) = false) :
    ∀ fuel acc, ls.length < fuel →
      Rfc.fieldLines c fuel (joinLines ls ++ 13 :: 10 :: r) acc = some (acc.reverse ++ ls, r) := by
  induction ls with
  | nil =>
    intro fuel acc hf
    match fuel, hf with
    | fuel + 1, _ =>
      simp only [joinLines_nil, List.nil_append, Rfc.fieldLines]
      rw [show (13 :: 10 :: r : Bytes) = [] ++ 13 :: 10 :: r from rfl,
        rfc_line c [] r (by simp) (by simp)]
      simp
  | cons l ls ih =>
    intro fuel acc hf
    obtain ⟨h13, h10, hne, hows⟩ := h l (by simp)
    match fuel, hf with
    | fuel + 1, hf =>
      simp only [joinLines_cons, List.append_assoc, List.cons_append, Rfc.fieldLines]
      rw [rfc_line c l _ h13 h10]
      have he : l.isEmpty = false := by simpa using hne
      simp only [he, hows, Bool.false_eq_true, ite_false]
      rw [ih (fun x hx => h x (by simp [hx])) fuel (l :: acc) (by simp at hf; omega)]
      simp



/-! ## Tokens -/

theorem token_bytes {x : Bytes} (h : token x = true) : ∀ b ∈ x, Wire.tchar b = true := by
  simp only [Wire.token, Bool.and_eq_true] at h
  exact List.all_eq_true.mp h.2

theorem token_ne_nil {x : Bytes} (h : token x = true) : x ≠ [] := by
  intro e; simp [e, Wire.token] at h

theorem takeWhile_all {p : Nat → Bool} : ∀ (l : Bytes), (∀ b ∈ l, p b = true) → l.takeWhile p = l
  | [], _ => rfl
  | b :: l, h => by simp [List.takeWhile_cons, h b (by simp), takeWhile_all l (fun x hx => h x (by simp [hx]))]

theorem dropWhile_none {p : Nat → Bool} : ∀ (l : Bytes), (∀ b ∈ l, p b = false) → l.dropWhile p = l
  | [], _ => rfl
  | b :: l, h => by simp [List.dropWhile_cons, h b (by simp)]

theorem trim_of_no_ws {x : Bytes} (h : ∀ b ∈ x, Wire.isWs b = false) : Wire.trim x = x := by
  simp only [Wire.trim]
  rw [dropWhile_none x h, dropWhile_none x.reverse (fun b hb => h b (List.mem_reverse.mp hb)),
    List.reverse_reverse]

theorem tchar_isWs {b : Nat} (h : Wire.tchar b = true) : Wire.isWs b = false := by
  have := (tchar_not_ws h).1
  simp only [Rfc.ws, Rfc.SP, Rfc.HTAB, Rfc.CR, Bool.or_eq_false_iff, beq_eq_false_iff_ne] at this
  simp only [Wire.isWs, Bool.or_eq_false_iff, beq_eq_false_iff_ne]
  omega

theorem token_trim {x : Bytes} (h : token x = true) : Wire.trim x = x :=
  trim_of_no_ws fun b hb => tchar_isWs (token_bytes h b hb)

theorem token_noSemi {x : Bytes} (h : token x = true) : x.takeWhile (· != 0x3B) = x := by
  apply takeWhile_all
  intro b hb
  have hb2 := token_bytes h b hb
  have : b ≠ 0x3B := by
    intro e; subst e
    simp [Wire.tchar, Wire.isAlnum, Wire.isDigit, Wire.isAlpha] at hb2
  simpa using this

theorem filter_ne_nil (l : List Bytes) :
    List.filter (fun e => decide (e ≠ [])) l = List.filter (fun x => !x.isEmpty) l := by
  congr 1; funext e; cases e <;> rfl
/-! ## Lists of values -/

theorem splitBy_ne_nil (c : Nat) (bs : Bytes) : splitBy c bs ≠ [] := by
  cases bs with
  | nil => simp [splitBy]
  | cons b rest =>
    simp only [splitBy]
    split
    · simp
    · split <;> simp

theorem elements_go (bs cur : Bytes) :
    Rfc.elements.go bs cur =
      match splitBy 44 bs with
      | [] => []
      | p :: ps => Wire.trim (cur.reverse ++ p) :: ps.map Wire.trim := by
  induction bs generalizing cur with
  | nil => simp [Rfc.elements.go, splitBy, stripOws_eq]
  | cons b rest ih =>
    by_cases hb : b = 44
    · subst hb
      simp only [Rfc.elements.go, splitBy, beq_self_eq_true, ite_true, stripOws_eq]
      rw [ih]
      cases h : splitBy 44 rest with
      | nil => exact absurd h (splitBy_ne_nil 44 rest)
      | cons p ps => simp
    · have hb' : (b == 44) = false := by simpa using hb
      simp only [Rfc.elements.go, splitBy, hb', Bool.false_eq_true, ite_false]
      rw [ih]
      cases h : splitBy 44 rest with
      | nil => exact absurd h (splitBy_ne_nil 44 rest)
      | cons p ps => simp

theorem elements_eq (bs : Bytes) : Rfc.elements bs = (splitBy 44 bs).map Wire.trim := by
  simp only [Rfc.elements]
  rw [elements_go]
  cases h : splitBy 44 bs with
  | nil => exact absurd h (splitBy_ne_nil 44 bs)
  | cons p ps => simp

theorem values_eq (fs : List (Bytes × Bytes)) (name : String) :
    Rfc.values fs name = (FieldsProof.named' fs name).map (·.2) := by
  have : Rfc.ci = Wire.eqCI := funext fun a => funext fun b => ci_eq a b
  simp [Rfc.values, FieldsProof.named', this, Rfc.ascii, Wire.str]

theorem hasName_iff (fs : List (Bytes × Bytes)) (name : String) :
    hasName fs name = true ↔ Rfc.values fs name ≠ [] := by
  rw [values_eq]
  simp [hasName, FieldsProof.named', List.filter_eq_nil_iff]

theorem flat_values (fs : List (Bytes × Bytes)) (name : String) :
    (Rfc.values fs name).flatMap Rfc.elements = (FieldsProof.elems fs name).map Wire.trim := by
  rw [values_eq]
  simp [FieldsProof.elems, elements_eq, List.flatMap_map, List.map_flatMap]

theorem decimal_some {x : Bytes} {n : Nat} (h : Wire.decimal x = some n) :
    x ≠ [] ∧ x.all Rfc.DIGIT = true ∧ Rfc.decimalValue x = n := by
  unfold Wire.decimal at h
  by_cases hx : (x.isEmpty || !x.all Wire.isDigit) = true
  · simp [hx] at h
  · simp only [hx, Bool.false_eq_true, ite_false] at h
    simp only [Bool.or_eq_true, Bool.not_eq_true', not_or, Bool.not_eq_false] at hx
    have hd : Wire.isDigit = Rfc.DIGIT := by
      funext b; simp [Wire.isDigit, Rfc.DIGIT]
    by_cases hm : Wire.digitsValue 10 (· - 48) x ≤ Wire.u64Max
    · simp only [hm, ite_true, Option.some.injEq] at h
      refine ⟨by simpa using hx.1, by rw [← hd]; exact hx.2, ?_⟩
      rw [← h]
      simp [Rfc.decimalValue, Wire.digitsValue]
    · simp [hm] at h

/-! ## The body framing agrees -/

/-- The minor version of an HTTP version. -/
def minor : Version → Nat
  | .h10 => 0
  | .h11 => 1

/-- For a head the decoder accepted, every recipient frames the body as the
decoder does, except one that uses its option to refuse a repeated
`Content-Length` (RFC 9110 section 8.6), which refuses the request. -/
theorem framing_agrees {fs : List (Bytes × Bytes)} {v : Version} {r : Fields} {f : Framing}
    (hf : fields fs v = .ok r) (hr : requestFraming r = .ok f) (c : Rfc.Choices) :
    Rfc.requestFraming c (minor v) fs = some f ∨
      (c.clList = false ∧ Rfc.requestFraming c (minor v) fs = none) := by
  obtain ⟨hboth, hwalk, htr⟩ := FieldsProof.fields_proj hf
  have hvalid := FieldsProof.walk_valid fs _ _ hwalk
  unfold requestFraming at hr
  unfold Rfc.requestFraming
  by_cases hte : hasName fs "transfer-encoding" = true
  · -- Transfer-Encoding alone: one coding, chunked, on HTTP/1.1
    have hcl : hasName fs "content-length" = false := by
      cases h : hasName fs "content-length"
      · rfl
      · exact absurd ⟨hte, h⟩ hboth
    have hnocl : ∀ g ∈ fs, eqCI g.1 (str "content-length") = false := by
      intro g hg
      cases h : eqCI g.1 (str "content-length")
      · rfl
      · have : hasName fs "content-length" = true := List.any_eq_true.mpr ⟨g, hg, h⟩
        rw [hcl] at this; cases this
    obtain ⟨_, h11, hfold⟩ := FieldsProof.walk_noCl fs none _ _ hnocl hwalk
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
        have hp : (FieldsProof.proj r).2 = (true, true, false) := by
          simp [FieldsProof.proj, FieldsProof.te3, htrue, hch, hun]
        rw [hp] at hfold
        obtain ⟨_, x, hx, htok, hchunk⟩ := FieldsProof.te3_chunked _ false false true hfold
        have hcod : Rfc.codings fs = [x] := by
          simp only [Rfc.codings, flat_values]
          rw [filter_ne_nil, show List.filter (fun x => !x.isEmpty)
            (List.map Wire.trim (FieldsProof.elems fs "transfer-encoding")) =
              FieldsProof.nonEmpty (FieldsProof.elems fs "transfer-encoding") from rfl, hx]
          simp [token_noSemi htok, stripOws_eq, token_trim htok]
        have hteR : Rfc.values fs "transfer-encoding" ≠ [] := (hasName_iff fs _).mp hte
        have hclR : ¬Rfc.values fs "content-length" ≠ [] := by
          intro h; rw [← hasName_iff] at h; rw [hcl] at h; cases h
        left
        have hclR' : Rfc.values fs "content-length" = [] := by simpa using hclR
        rw [if_pos hteR]
        simp [hclR', minor, hcod, ci_eq, show Rfc.ascii "chunked" = str "chunked" from rfl, hchunk]
    · have hch' : r.chunked = false := by simpa using hch
      simp [hch'] at hr
  · have hte' : hasName fs "transfer-encoding" = false := by simpa using hte
    have hnote : ∀ g ∈ fs, eqCI g.1 (str "transfer-encoding") = false := by
      intro g hg
      cases h : eqCI g.1 (str "transfer-encoding")
      · rfl
      · have : hasName fs "transfer-encoding" = true := List.any_eq_true.mpr ⟨g, hg, h⟩
        rw [hte'] at this; cases this
    obtain ⟨hp2, hfold⟩ := FieldsProof.walk_noTe fs none _ _ hnote hwalk
    have htrf : r.transfer = false := by
      have := congrArg (fun t : FieldsProof.T3 => t.1) hp2
      simpa [FieldsProof.proj, FieldsProof.te3] using this
    simp only [htrf, Bool.false_eq_true, ite_false] at hr
    have hteR : ¬Rfc.values fs "transfer-encoding" ≠ [] := by
      intro h; rw [← hasName_iff] at h; rw [hte'] at h; cases h
    simp only []
    rw [if_neg hteR]
    obtain ⟨hall, hnil, _⟩ := FieldsProof.cl_fold _ none _ hfold
    by_cases hcl : hasName fs "content-length" = true
    · have hclR : Rfc.values fs "content-length" ≠ [] := (hasName_iff fs _).mp hcl
      rw [if_pos hclR]
      -- every element is the decoder's length
      have hne : FieldsProof.elems fs "content-length" ≠ [] := by
        have : Rfc.values fs "content-length" ≠ [] := hclR
        rw [values_eq] at this
        simp only [FieldsProof.elems]
        cases hn : FieldsProof.named' fs "content-length" with
        | nil => rw [hn] at this; simp at this
        | cons g gs =>
          simp only [List.flatMap_cons]
          intro he
          have := splitBy_ne_nil 44 g.2
          simp_all
      obtain ⟨n, hn⟩ : ∃ n, (FieldsProof.proj r).1 = some n := by
        cases he : FieldsProof.elems fs "content-length" with
        | nil => exact absurd he hne
        | cons y ys => rw [he] at hfold; exact FieldsProof.cl_fold_some hfold
      have hrl : r.length = some n := hn
      simp only [hrl, Except.ok.injEq] at hr
      subst hr
      have hdig : ∀ y ∈ (FieldsProof.elems fs "content-length").map Wire.trim,
          y ≠ [] ∧ y.all Rfc.DIGIT = true ∧ Rfc.decimalValue y = n := by
        intro y hy
        simp only [List.mem_map] at hy
        obtain ⟨z, hz, rfl⟩ := hy
        have := hall z hz
        rw [hn] at this
        exact decimal_some this
      unfold Rfc.contentLength
      simp only [flat_values]
      cases hes : (FieldsProof.elems fs "content-length").map Wire.trim with
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
      have hempty : FieldsProof.elems fs "content-length" = [] := by
        have : Rfc.values fs "content-length" = [] := by simpa using hclR
        rw [values_eq] at this
        simp only [FieldsProof.elems]
        simp only [List.map_eq_nil_iff] at this
        rw [this]; rfl
      have hlen : r.length = none := hnil hempty
      simp [hlen] at hr
      subst hr
      left; rfl


/-! ## The request line -/

/-- The parts `splitBy` makes, joined back with the separator. -/
def joinWith (c : Nat) : List Bytes → Bytes
  | [] => []
  | [p] => p
  | p :: ps => p ++ c :: joinWith c ps

theorem splitBy_inv (c : Nat) :
    ∀ xs : Bytes, joinWith c (splitBy c xs) = xs ∧ ∀ p ∈ splitBy c xs, c ∉ p := by
  intro xs
  induction xs with
  | nil => simp [splitBy, joinWith]
  | cons b rest ih =>
    obtain ⟨ih1, ih2⟩ := ih
    by_cases hb : b = c
    · subst hb
      simp only [splitBy, beq_self_eq_true, ite_true]
      refine ⟨?_, ?_⟩
      · cases h : splitBy b rest with
        | nil => exact absurd h (splitBy_ne_nil b rest)
        | cons p ps => rw [h] at ih1; simp [joinWith, ih1]
      · intro p hp
        simp only [List.mem_cons] at hp
        rcases hp with rfl | hp
        · simp
        · exact ih2 p hp
    · have hb' : (b == c) = false := by simpa using hb
      simp only [splitBy, hb', Bool.false_eq_true, ite_false]
      cases h : splitBy c rest with
      | nil => exact absurd h (splitBy_ne_nil c rest)
      | cons p ps =>
        rw [h] at ih1 ih2
        refine ⟨?_, ?_⟩
        · cases ps with
          | nil => simp [joinWith] at ih1 ⊢; exact ih1
          | cons q qs => simp [joinWith] at ih1 ⊢; exact ih1
        · intro x hx
          simp only [List.mem_cons] at hx
          rcases hx with rfl | hx
          · simp only [List.mem_cons, not_or]
            exact ⟨fun e => hb e.symm, ih2 p (by simp)⟩
          · exact ih2 x (by simp [hx])

theorem spaces_go_part (p rest cur : Bytes) (h : Rfc.SP ∉ p) :
    Rfc.spaces.go (p ++ rest) cur = Rfc.spaces.go rest (p.reverse ++ cur) := by
  induction p generalizing cur with
  | nil => rfl
  | cons b p ih =>
    have hb : (b == Rfc.SP) = false := by
      have : b ≠ Rfc.SP := fun e => h (by simp [e])
      simpa using this
    simp only [List.cons_append, Rfc.spaces.go, hb, Bool.false_eq_true, ite_false]
    rw [ih _ (fun e => h (by simp [e]))]
    simp

theorem words_go_part (p rest cur : Bytes) (h : ∀ b ∈ p, Rfc.ws b = false) :
    Rfc.words.go (p ++ rest) cur = Rfc.words.go rest (p.reverse ++ cur) := by
  induction p generalizing cur with
  | nil => rfl
  | cons b p ih =>
    simp only [List.cons_append, Rfc.words.go, h b (by simp), Bool.false_eq_true, ite_false]
    rw [ih _ (fun x hx => h x (by simp [hx]))]
    simp

theorem version_lit10 : Rfc.version (str "HTTP/1.0") = some 0 := by decide +kernel
theorem version_lit11 : Rfc.version (str "HTTP/1.1") = some 1 := by decide +kernel
theorem lit10_clean : ∀ b ∈ str "HTTP/1.0", Rfc.ws b = false ∧ b ≠ 13 ∧ b ≠ 10 ∧ b ≠ 32 := by
  decide +kernel
theorem lit11_clean : ∀ b ∈ str "HTTP/1.1", Rfc.ws b = false ∧ b ≠ 13 ∧ b ≠ 10 ∧ b ≠ 32 := by
  decide +kernel
theorem lit10_ne : str "HTTP/1.0" ≠ [] := by decide +kernel
theorem lit11_ne : str "HTTP/1.1" ≠ [] := by decide +kernel

theorem parseVersion_ok {ver : Bytes} {v : Version} (h : parseVersion ver = .ok v) :
    Rfc.version ver = some (minor v) ∧ ver ≠ [] ∧ ∀ b ∈ ver, Rfc.ws b = false ∧ b ≠ 13 ∧ b ≠ 10 ∧ b ≠ 32 := by
  unfold parseVersion at h
  by_cases h0 : ver = str "HTTP/1.0"
  · subst h0
    simp at h
    subst h
    exact ⟨version_lit10, lit10_ne, lit10_clean⟩
  · by_cases h1 : ver = str "HTTP/1.1"
    · subst h1
      have : (str "HTTP/1.1" == str "HTTP/1.0") = false := by decide +kernel
      simp [this] at h
      subst h
      exact ⟨version_lit11, lit11_ne, lit11_clean⟩
    · simp [h0, h1] at h

theorem graphic_clean {b : Nat} (h : (graphic b && b != 35) = true) :
    Rfc.ws b = false ∧ b ≠ 13 ∧ b ≠ 10 ∧ b ≠ 32 := by
  simp only [graphic, Bool.and_eq_true, decide_eq_true_eq, bne_iff_ne] at h
  simp only [Rfc.ws, Rfc.SP, Rfc.HTAB, Rfc.CR, Bool.or_eq_false_iff, beq_eq_false_iff_ne]
  omega

/-- A request line the decoder accepted, with a target `validTarget`
accepted: no CR or LF in it, not empty, and every recipient reads the same
method and version from it. -/
theorem requestLine_ok {first m t : Bytes} {v : Version}
    (h : requestLine first = .ok (m, t, v)) (ht : validTarget m t = true) :
    13 ∉ first ∧ 10 ∉ first ∧ first ≠ [] ∧ ∀ c, Rfc.requestLine c first = some (m, minor v) := by
  unfold validTarget at ht
  have hpre : token m = true ∧ t ≠ [] ∧ ∀ b ∈ t, (graphic b && b != 35) = true := by
    by_cases hc : (!token m || t.isEmpty || !t.all (fun b => graphic b && b != 35)) = true
    · simp [hc] at ht
    · simp only [Bool.or_eq_true, Bool.not_eq_true', not_or, Bool.not_eq_false] at hc
      exact ⟨hc.1.1, by simpa using hc.1.2, List.all_eq_true.mp hc.2⟩
  obtain ⟨hm, htne, htb⟩ := hpre
  unfold requestLine at h
  obtain ⟨hinv, hsep⟩ := splitBy_inv 32 first
  split at h
  · rename_i mm tt ver more hsplit
    cases hv : parseVersion ver with
    | error e => rw [hv] at h; cases h
    | ok v' =>
      rw [hv] at h
      by_cases hmore : more.isEmpty = true
      · have hmore' : more = [] := by simpa using hmore
        subst hmore'
        simp only [hmore, Bool.not_true, Bool.false_eq_true, ite_false] at h
        by_cases hu : (!utf8 mm || !utf8 tt) = true
        · simp [hu] at h
        · simp only [hu, Bool.false_eq_true, ite_false, Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨e1, e2, e3⟩ := h
          subst mm tt v'
          obtain ⟨hver, hvne, hvb⟩ := parseVersion_ok hv
          rw [hsplit] at hinv
          have hfirst : first = m ++ 32 :: t ++ 32 :: ver := by
            rw [← hinv]; simp [joinWith]
          have hmb : ∀ b ∈ m, Rfc.ws b = false ∧ b ≠ 13 ∧ b ≠ 10 ∧ b ≠ 32 := by
            intro b hb
            have := tchar_not_ws (token_bytes hm b hb)
            refine ⟨this.1, this.2.1, this.2.2, ?_⟩
            have h1 := this.1
            simp only [Rfc.ws, Rfc.SP, Bool.or_eq_false_iff, beq_eq_false_iff_ne] at h1
            exact h1.1.1.1.1
          have htb' : ∀ b ∈ t, Rfc.ws b = false ∧ b ≠ 13 ∧ b ≠ 10 ∧ b ≠ 32 :=
            fun b hb => graphic_clean (htb b hb)
          refine ⟨?_, ?_, ?_, ?_⟩
          · rw [hfirst]
            simp only [List.mem_append, List.mem_cons, not_or]
            refine ⟨⟨fun h => (hmb 13 h).2.1 rfl, by decide, fun h => (htb' 13 h).2.1 rfl⟩, by decide,
              fun h => (hvb 13 h).2.1 rfl⟩
          · rw [hfirst]
            simp only [List.mem_append, List.mem_cons, not_or]
            refine ⟨⟨fun h => (hmb 10 h).2.2.1 rfl, by decide, fun h => (htb' 10 h).2.2.1 rfl⟩, by decide,
              fun h => (hvb 10 h).2.2.1 rfl⟩
          · rw [hfirst]; simp
          · intro c
            have hmne := token_ne_nil hm
            have hparts : (if c.wordsAnyWs then Rfc.words first else Rfc.spaces first) = [m, t, ver] := by
              rw [hfirst]
              split
              · simp only [Rfc.words]
                rw [List.append_assoc, words_go_part m _ [] (fun b hb => (hmb b hb).1)]
                cases hmr : m.reverse with
                | nil => simp at hmr; exact absurd hmr hmne
                | cons a as =>
                  simp only [List.cons_append, List.append_nil, Rfc.words.go, Rfc.ws, Rfc.SP,
                    beq_self_eq_true, Bool.true_or, ite_true, List.isEmpty_cons, Bool.false_eq_true,
                    ite_false]
                  rw [← hmr, List.reverse_reverse,
                    words_go_part t _ [] (fun b hb => (htb' b hb).1)]
                  cases htr : t.reverse with
                  | nil => simp at htr; exact absurd htr htne
                  | cons a2 as2 =>
                    simp only [List.cons_append, List.append_nil, Rfc.words.go, Rfc.ws, Rfc.SP,
                      beq_self_eq_true, Bool.true_or, ite_true, List.isEmpty_cons, Bool.false_eq_true,
                      ite_false]
                    rw [← htr, List.reverse_reverse]
                    have := words_go_part ver [] [] (fun b hb => (hvb b hb).1)
                    simp only [List.append_nil] at this
                    rw [this]
                    cases hvr : ver.reverse with
                    | nil => simp at hvr; exact absurd hvr hvne
                    | cons a3 as3 =>
                      simp [Rfc.words.go]
                      rw [← List.reverse_reverse ver, hvr]; simp
              · simp only [Rfc.spaces]
                rw [List.append_assoc, spaces_go_part m _ [] (fun hb => (hmb _ hb).2.2.2 rfl)]
                simp only [List.cons_append, List.append_nil, Rfc.spaces.go, Rfc.SP, beq_self_eq_true,
                  ite_true, List.reverse_reverse]
                rw [spaces_go_part t _ [] (fun hb => (htb' _ hb).2.2.2 rfl)]
                simp only [List.cons_append, List.append_nil, Rfc.spaces.go, Rfc.SP, beq_self_eq_true,
                  ite_true, List.reverse_reverse]
                have := spaces_go_part ver [] [] (fun hb => (hvb _ hb).2.2.2 rfl)
                simp only [List.append_nil] at this
                rw [this]
                simp [Rfc.spaces.go]
            simp only [Rfc.requestLine, hparts, token_eq, hm, htne]
            have hnows : t.any Rfc.ws = false := by
              apply List.any_eq_false.mpr
              intro b hb; simp [(htb' b hb).1]
            simp [hnows, hver, htne]
      · simp [hmore] at h
  · cases h


/-! ## Empty lines before the request -/

def crlfs (j : Nat) : Bytes := (List.replicate j [13, 10]).flatten

theorem crlfs_succ (j : Nat) : crlfs (j + 1) = 13 :: 10 :: crlfs j := by
  simp [crlfs, List.replicate_succ]

theorem crlfs_length (j : Nat) : (crlfs j).length = 2 * j := by
  induction j with
  | zero => rfl
  | succ j ih => rw [crlfs_succ]; simp [ih]; omega

/-- Where `requestStart` found the head: after `j` empty lines, at most
`MAX_EMPTY_LINES`. -/
theorem requestStart_go {lim : Limits} {input : Bytes} {eof : Bool} {e : Nat} {hd : RequestHead}
    {r : Fields} {f : Framing} :
    ∀ fuel pos empty, empty ≤ maxEmptyLines → requestStart.go lim input eof fuel pos empty = .head e hd r f →
      ∃ j rest0 n, input.drop pos = crlfs j ++ rest0 ∧ empty + j ≤ maxEmptyLines ∧
        readHead lim rest0 = .done n ∧ requestHead (rest0.take n) = .ok (hd, r, f) ∧
        e = pos + 2 * j + n := by
  intro fuel
  induction fuel with
  | zero => intro _ _ _ h; simp [requestStart.go] at h
  | succ fuel ih =>
    intro pos empty hle h
    simp only [requestStart.go] at h
    by_cases h13 : input.drop pos = [13]
    · simp [h13] at h
    have h13' : (input.drop pos == [13]) = false := by simpa using h13
    simp only [h13', Bool.false_eq_true, ite_false] at h
    by_cases hcrlf : (input.drop pos).take 2 = [13, 10]
    · have hc' : ((input.drop pos).take 2 == [13, 10]) = true := by simpa using hcrlf
      simp only [hc', ite_true] at h
      by_cases hmax : empty ≥ maxEmptyLines
      · simp [hmax] at h
      simp only [hmax, ite_false] at h
      obtain ⟨j, rest0, n, h1, h2, h3, h4, h5⟩ := ih (pos + 2) (empty + 1) (by omega) h
      refine ⟨j + 1, rest0, n, ?_, by omega, h3, h4, by omega⟩
      rw [crlfs_succ]
      have : input.drop pos = [13, 10] ++ input.drop (pos + 2) := by
        rw [← hcrlf, ← List.drop_drop, List.take_append_drop]
      rw [this, h1]; rfl
    · have hc' : ((input.drop pos).take 2 == [13, 10]) = false := by simpa using hcrlf
      simp only [hc', Bool.false_eq_true, ite_false] at h
      split at h
      · cases h
      · cases h
      · rename_i n hn
        split at h
        · cases h
        · rename_i hd' r' f' hreq
          simp only [Start.head.injEq] at h
          obtain ⟨rfl, rfl, rfl, rfl⟩ := h
          refine ⟨0, input.drop pos, n, by simp [crlfs], by omega, hn, hreq, by omega⟩

/-- No request line is empty, so every recipient refuses a request whose
empty lines it does not skip. -/
theorem requestLine_nil (c : Rfc.Choices) : Rfc.requestLine c [] = none := by
  unfold Rfc.requestLine
  have e : (if c.wordsAnyWs then Rfc.words [] else Rfc.spaces []) = (if c.wordsAnyWs then [] else [[]]) := by
    simp [Rfc.words, Rfc.words.go, Rfc.spaces, Rfc.spaces.go]
  rw [e]
  cases c.wordsAnyWs <;> rfl

theorem skipEmpty_crlfs (c : Rfc.Choices) (first rest : Bytes) (h13 : 13 ∉ first) (h10 : 10 ∉ first)
    (hne : first ≠ []) :
    ∀ j k, Rfc.skipEmpty c k (crlfs j ++ first ++ 13 :: 10 :: rest) =
      crlfs (j - k) ++ first ++ 13 :: 10 :: rest := by
  intro j
  induction j with
  | zero =>
    intro k
    cases k with
    | zero => rfl
    | succ k =>
      simp only [crlfs, List.replicate_zero, List.flatten_nil, List.nil_append, Rfc.skipEmpty]
      rw [List.append_assoc, rfc_line c first rest h13 h10]
      cases first with
      | nil => exact absurd rfl hne
      | cons a as => simp
  | succ j ih =>
    intro k
    cases k with
    | zero => rfl
    | succ k =>
      simp only [Rfc.skipEmpty]
      rw [crlfs_succ, show (13 :: 10 :: crlfs j ++ first ++ 13 :: 10 :: rest) =
        [] ++ 13 :: 10 :: (crlfs j ++ first ++ 13 :: 10 :: rest) by simp,
        rfc_line c [] _ (by simp) (by simp)]
      simp only
      rw [ih k]
      rw [Nat.add_sub_add_right]


/-! ## The head agrees -/

theorem parts_accepted : ∀ {ls : List Bytes} {fs : List (Bytes × Bytes)}, Parts ls fs →
    (∀ p ∈ fs, validField p.1 p.2 = true) →
    (∀ l ∈ ls, 13 ∉ l ∧ 10 ∉ l ∧ l ≠ [] ∧ Rfc.ows (l.headD 0) = false) ∧ ls.mapM Rfc.field = some fs
  | _, _, .nil, _ => ⟨by simp, rfl⟩
  | l :: ls, p :: ps, .cons hp hrest, hv => by
    obtain ⟨h1, h2⟩ := parts_accepted hrest (fun q hq => hv q (by simp [hq]))
    obtain ⟨a13, a10, aows, afield⟩ := accepted_field hp (hv p (by simp))
    have hne : l ≠ [] := by
      obtain ⟨raw, hl, _, _⟩ := headerParts_ok hp
      rw [hl]; simp
    refine ⟨?_, ?_⟩
    · intro x hx
      simp only [List.mem_cons] at hx
      rcases hx with rfl | hx
      · exact ⟨a13, a10, hne, aows⟩
      · exact h1 x hx
    · simp [List.mapM_cons, afield, h2]

theorem joinLines_length_ge (ls : List Bytes) : 2 * ls.length ≤ (joinLines ls).length := by
  induction ls with
  | nil => simp
  | cons l ls ih => simp; omega

/-- **The head.** For a request head the server's decoder accepts, every
recipient in the family finds the same end of the head, the same method and
the same body framing, or refuses the request; and it refuses it only by
skipping fewer empty lines before it than the server does (the server skips
up to eight) or by refusing a repeated `Content-Length`. -/
theorem head_agrees {lim : Limits} {input : Bytes} {eof : Bool} {e : Nat} {hd : RequestHead}
    {r : Fields} {f : Framing} (h : requestStart lim input eof = .head e hd r f) (c : Rfc.Choices) :
    Rfc.requestHead c input = some ⟨e, hd.method, f, input.drop e⟩ ∨
      (Rfc.requestHead c input = none ∧ (c.emptyLines < maxEmptyLines ∨ c.clList = false)) := by
  obtain ⟨j, rest0, n, h1, h2, h3, h4, h5⟩ := requestStart_go _ 0 0 (by decide) h
  simp only [List.drop_zero, Nat.zero_add] at h1 h2 h5
  obtain ⟨first, ls, rest1, hr0, hn, hf10, hls⟩ := readHead_done h3
  have htake : rest0.take n = joinLines (first :: ls) ++ [13, 10] := by
    rw [hr0, hn, show joinLines (first :: ls) ++ 13 :: 10 :: rest1 =
        (joinLines (first :: ls) ++ [13, 10]) ++ rest1 by simp,
      show (joinLines (first :: ls)).length + 2 = (joinLines (first :: ls) ++ [13, 10]).length by simp; omega]
    exact List.take_left
  rw [htake] at h4
  unfold Wire.requestHead at h4
  cases hsplit : splitHead (joinLines (first :: ls) ++ [13, 10]) with
  | error err => rw [hsplit] at h4; cases h4
  | ok lf =>
    obtain ⟨line, fs⟩ := lf
    rw [hsplit] at h4
    obtain ⟨rfl, hparts⟩ := splitHead_join hf10 hls hsplit
    simp only at h4
    cases hrl : Wire.requestLine line with
    | error err => rw [hrl] at h4; cases h4
    | ok mtv =>
      obtain ⟨m, t, v⟩ := mtv
      rw [hrl] at h4
      simp only at h4
      by_cases hvt : validTarget m t = true
      · simp only [hvt, Bool.not_true, Bool.false_eq_true, ite_false] at h4
        by_cases hvh : validHost v fs = true
        · simp only [hvh, Bool.not_true, Bool.false_eq_true, ite_false] at h4
          cases hfl : fields fs v with
          | error err => rw [hfl] at h4; cases h4
          | ok r' =>
            rw [hfl] at h4
            simp only at h4
            cases hrf : Wire.requestFraming r' with
            | error err => rw [hrf] at h4; cases h4
            | ok f' =>
              rw [hrf] at h4
              simp only [Except.ok.injEq, Prod.mk.injEq] at h4
              obtain ⟨rfl, rfl, rfl⟩ := h4
              obtain ⟨l13, l10, lne, hrline⟩ := requestLine_ok hrl hvt
              have hvalid : ∀ p ∈ fs, validField p.1 p.2 = true :=
                FieldsProof.walk_valid fs _ _ (FieldsProof.fields_proj hfl).2.1
              obtain ⟨hlines, hmap⟩ := parts_accepted hparts hvalid
              have hinput : input = crlfs j ++ line ++ 13 :: 10 :: (joinLines ls ++ 13 :: 10 :: rest1) := by
                rw [h1, hr0]; simp
              have hfuel : ls.length < (joinLines ls ++ 13 :: 10 :: rest1).length := by
                have := joinLines_length_ge ls
                simp; omega
              have hend : input.length - rest1.length = e := by
                rw [hinput, h5, hn]
                simp [crlfs_length]
                omega
              have hdrop : input.drop e = rest1 := by
                rw [hinput, h5, hn]
                rw [show 2 * j + ((joinLines (line :: ls)).length + 2) =
                  (crlfs j ++ line ++ 13 :: 10 :: (joinLines ls ++ [13, 10])).length by
                    simp [crlfs_length]; omega]
                rw [show crlfs j ++ line ++ 13 :: 10 :: (joinLines ls ++ 13 :: 10 :: rest1) =
                  (crlfs j ++ line ++ 13 :: 10 :: (joinLines ls ++ [13, 10])) ++ rest1 by simp]
                exact List.drop_left
              unfold Rfc.requestHead
              rw [hinput, skipEmpty_crlfs c line _ l13 l10 lne j c.emptyLines]
              by_cases hE : j ≤ c.emptyLines
              · rw [show j - c.emptyLines = 0 by omega]
                rw [show crlfs 0 = [] from rfl, List.nil_append]
                rw [List.append_assoc, rfc_line c line _ l13 l10]
                simp only [hrline c]
                rw [rfc_fieldLines c ls rest1 hlines _ [] hfuel]
                simp only [List.reverse_nil, List.nil_append, hmap]
                rcases framing_agrees hfl hrf c with hok | ⟨hcl, hnone⟩
                · left
                  rw [hok]
                  simp only [Option.some.injEq, Rfc.Head.mk.injEq]
                  have hinput' : input = crlfs j ++ (line ++ 13 :: 10 :: (joinLines ls ++ 13 :: 10 :: rest1)) := by
                    rw [hinput]; simp
                  rw [← hinput', hend, hdrop]
                  simp
                · right
                  rw [hnone]
                  exact ⟨by simp, Or.inr hcl⟩
              · right
                obtain ⟨k, hk⟩ : ∃ k, j - c.emptyLines = k + 1 := ⟨j - c.emptyLines - 1, by omega⟩
                rw [hk, crlfs_succ]
                rw [show (13 :: 10 :: crlfs k ++ line ++ 13 :: 10 :: (joinLines ls ++ 13 :: 10 :: rest1))
                  = [] ++ 13 :: 10 :: (crlfs k ++ line ++ 13 :: 10 :: (joinLines ls ++ 13 :: 10 :: rest1))
                  by simp, rfc_line c [] _ (by simp) (by simp)]
                simp only [requestLine_nil]
                exact ⟨by simp, Or.inl (by omega)⟩
        · simp [hvh] at h4
      · simp [hvt] at h4

end Http.Smuggling
