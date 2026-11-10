import Http.Smuggling

/-!
# The body: the decoder and every RFC 9112 recipient read the same body

For a message whose head the decoder accepted, `runBody` reads the body in
blocks. Whenever it finishes the body (reports `Done`), every recipient in
the family `Rfc.body` reads exactly the bytes of those blocks, and the
message ends at the same byte: for a length, for chunks (section 7.1, with
any of the line tolerances), and for a body that runs to the close.
-/

namespace Http.BodyProof

open Wire Lines Smuggling

/-! ## Fuel -/

theorem trailers_mono (c : Rfc.Choices) :
    ∀ m bs r, Rfc.trailers c m bs = some r → ∀ m', m ≤ m' → Rfc.trailers c m' bs = some r := by
  intro m
  induction m with
  | zero => intro _ _ h; simp [Rfc.trailers] at h
  | succ m ih =>
    intro bs r h m' hm
    obtain ⟨m'', rfl⟩ : ∃ m'', m' = m'' + 1 := ⟨m' - 1, by omega⟩
    simp only [Rfc.trailers] at h ⊢
    cases hl : Rfc.line c bs with
    | none => rw [hl] at h; cases h
    | some p =>
      obtain ⟨l, rest⟩ := p
      rw [hl] at h
      simp only at h ⊢
      by_cases he : l.isEmpty = true
      · simp only [he, ite_true] at h ⊢; exact h
      · simp only [he, Bool.false_eq_true, ite_false] at h ⊢
        by_cases hf : (Rfc.field l).isSome = true
        · simp only [hf, ite_true] at h ⊢; exact ih rest r h m'' (by omega)
        · simp [hf] at h

theorem chunked_mono (c : Rfc.Choices) :
    ∀ m bs r, Rfc.chunked c m bs = some r → ∀ m', m ≤ m' → Rfc.chunked c m' bs = some r := by
  intro m
  induction m with
  | zero => intro _ _ h; simp [Rfc.chunked] at h
  | succ m ih =>
    intro bs r h m' hm
    obtain ⟨m'', rfl⟩ : ∃ m'', m' = m'' + 1 := ⟨m' - 1, by omega⟩
    simp only [Rfc.chunked] at h ⊢
    cases hl : Rfc.line c bs with
    | none => rw [hl] at h; cases h
    | some p =>
      obtain ⟨l, rest⟩ := p
      rw [hl] at h
      simp only at h ⊢
      cases hs : Rfc.chunkSize l with
      | none => rw [hs] at h; cases h
      | some n =>
        rw [hs] at h
        cases n with
        | zero => exact h
        | succ k =>
          simp only at h ⊢
          by_cases hlen : rest.length < k + 1
          · simp [hlen] at h
          · simp only [hlen, ite_false] at h ⊢
            cases ha : Rfc.line c (rest.drop (k + 1)) with
            | none => rw [ha] at h; cases h
            | some q =>
              obtain ⟨l2, after⟩ := q
              rw [ha] at h
              cases l2 with
              | cons _ _ => cases h
              | nil =>
                simp only at h ⊢
                cases hc : Rfc.chunked c m after with
                | none => rw [hc] at h; cases h
                | some dr =>
                  rw [hc] at h
                  rw [ih after dr hc m'' (by omega)]
                  exact h


/-! ## Characters of chunk-size lines -/

theorem isHex_eq (b : Nat) : Wire.isHex b = Rfc.HEXDIG b := by
  simp [Wire.isHex, Wire.isDigit, Rfc.HEXDIG, Rfc.DIGIT]

theorem hexVal_eq (b : Nat) : Wire.hexVal b = Rfc.hexValue1 b := by
  simp [Wire.hexVal, Wire.isDigit, Rfc.hexValue1, Rfc.DIGIT]

theorem hexNumber_some {line : Bytes} {k : Nat} (h : hexNumber line = some k) :
    line ≠ [] ∧ (∀ b ∈ line, Rfc.HEXDIG b = true) ∧ Rfc.hexValue line = k := by
  unfold hexNumber at h
  by_cases hx : (line.isEmpty || !line.all Wire.isHex) = true
  · simp [hx] at h
  · simp only [hx, Bool.false_eq_true, ite_false] at h
    simp only [Bool.or_eq_true, Bool.not_eq_true', not_or, Bool.not_eq_false] at hx
    by_cases hm : Wire.digitsValue 16 Wire.hexVal line ≤ Wire.u64Max
    · simp only [hm, ite_true, Option.some.injEq] at h
      refine ⟨by simpa using hx.1, fun b hb => by rw [← isHex_eq]; exact List.all_eq_true.mp hx.2 b hb, ?_⟩
      rw [← h]
      have : Wire.hexVal = Rfc.hexValue1 := funext hexVal_eq
      simp [Rfc.hexValue, Wire.digitsValue, this]
    · simp [hm] at h

theorem hexdig_clean {b : Nat} (h : Rfc.HEXDIG b = true) : b ≠ 13 ∧ b ≠ 10 ∧ b ≠ 59 ∧ Rfc.ows b = false := by
  simp only [Rfc.HEXDIG, Rfc.DIGIT, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq] at h
  simp only [Rfc.ows, Rfc.SP, Rfc.HTAB, Bool.or_eq_false_iff, beq_eq_false_iff_ne]
  omega

theorem chunkSize_hex {line : Bytes} {k : Nat} (h : hexNumber line = some k) :
    Rfc.chunkSize line = some k := by
  obtain ⟨hne, hall, hv⟩ := hexNumber_some h
  have ht : line.takeWhile Rfc.HEXDIG = line := takeWhile_all line hall
  simp only [Rfc.chunkSize, ht, List.drop_length, List.dropWhile_nil, List.isEmpty_nil, Bool.true_or,
    ite_true]
  have : line.isEmpty = false := by simpa using hne
  simp [this, hv]

theorem line_shorter {c : Rfc.Choices} {bs l rest : Bytes} (h : Rfc.line c bs = some (l, rest)) :
    rest.length < bs.length := by
  unfold Rfc.line at h
  dsimp only at h
  cases hf : bs.findIdx? (· == Rfc.LF) with
  | none => rw [hf] at h; cases h
  | some i =>
    rw [hf] at h
    have hlt : i < bs.length := by
      obtain ⟨a, hs, _, _⟩ := findIdx?_some hf
      have := congrArg List.length hs
      simp at this
      omega
    simp only at h
    split at h
    · cases h
    · split at h
      · split at h
        · simp only [Option.some.injEq, Prod.mk.injEq] at h
          rw [← h.2]; simp; omega
        · cases h
      · simp only [Option.some.injEq, Prod.mk.injEq] at h
        rw [← h.2]; simp; omega

/-! ## What is left of a body -/

/-- What every recipient makes of the rest of a body from the decoder's
state `s` at the bytes `bs`: the body bytes still to come, and the bytes
after the message. -/
def Spec (c : Rfc.Choices) : Body → Bytes → Bytes × Bytes → Prop
  | .done, bs, (b, rest) => b = [] ∧ rest = bs
  | .length k, bs, (b, rest) => k ≤ bs.length ∧ b = bs.take k ∧ rest = bs.drop k
  | .close, bs, (b, rest) => b = bs ∧ rest = []
  | .size, bs, r => Rfc.chunked c bs.length bs = some r
  | .data k, bs, (b, rest) =>
    k ≤ bs.length ∧ ∃ after b', Rfc.line c (bs.drop k) = some ([], after) ∧
      Rfc.chunked c after.length after = some (b', rest) ∧ b = bs.take k ++ b'
  | .dataEnd, bs, r => ∃ after, Rfc.line c bs = some ([], after) ∧ Rfc.chunked c after.length after = some r
  | .trailers, bs, (b, rest) => b = [] ∧ Rfc.trailers c bs.length bs = some rest
  | _, _, _ => False

/-- The body bytes among a decoder's events. -/
def bodyBytes : List Event → Bytes
  | [] => []
  | .body b :: evs => b ++ bodyBytes evs
  | _ :: evs => bodyBytes evs

theorem crlf_line (c : Rfc.Choices) (tail : Bytes) : Rfc.line c (13 :: 10 :: tail) = some ([], tail) :=
  rfc_line c [] tail (by simp) (by simp)



/-! ## One step, per state -/

/-- `Need` at the end of input with nothing buffered is a failure. -/
def needOr (eof : Bool) (bs : Bytes) : BodyStep :=
  if eof && bs.isEmpty then .fail .incomplete else .need

theorem bodyStep_done (lim : Limits) (bs : Bytes) (eof : Bool) : bodyStep lim .done bs eof = .done := rfl

theorem bodyStep_finished (lim : Limits) (bs : Bytes) (eof : Bool) :
    bodyStep lim .finished bs eof = .finish := rfl

theorem bodyStep_boundary (lim : Limits) (bs : Bytes) (eof : Bool) :
    bodyStep lim .boundary bs eof = .finish := rfl

theorem bodyStep_length (lim : Limits) (k : Nat) (bs : Bytes) (eof : Bool) :
    bodyStep lim (.length k) bs eof =
      if bs.length < min k (max lim.bodyChunk 1) then needOr eof bs
      else .emit (bs.take (min k (max lim.bodyChunk 1)))
        (if k - min k (max lim.bodyChunk 1) == 0 then .done
         else .length (k - min k (max lim.bodyChunk 1))) := by
  unfold bodyStep needOr
  by_cases h : bs.length < min k (max lim.bodyChunk 1)
  · simp [h]
  · simp only [h, ite_false]

theorem bodyStep_data (lim : Limits) (k : Nat) (bs : Bytes) (eof : Bool) :
    bodyStep lim (.data k) bs eof =
      if bs.length < min k (max lim.bodyChunk 1) then needOr eof bs
      else .emit (bs.take (min k (max lim.bodyChunk 1)))
        (if k - min k (max lim.bodyChunk 1) == 0 then .dataEnd
         else .data (k - min k (max lim.bodyChunk 1))) := by
  unfold bodyStep needOr
  by_cases h : bs.length < min k (max lim.bodyChunk 1)
  · simp [h]
  · simp only [h, ite_false]

theorem bodyStep_close (lim : Limits) (bs : Bytes) (eof : Bool) :
    bodyStep lim .close bs eof =
      if min bs.length (max lim.bodyChunk 1) == max lim.bodyChunk 1 ||
          (eof && min bs.length (max lim.bodyChunk 1) != 0) then
        .emit (bs.take (min bs.length (max lim.bodyChunk 1))) .close
      else if eof then .emit [] .finished
      else needOr eof bs := by
  unfold bodyStep needOr
  by_cases h1 : (min bs.length (max lim.bodyChunk 1) == max lim.bodyChunk 1 ||
      (eof && min bs.length (max lim.bodyChunk 1) != 0)) = true
  · simp only [h1, ite_true]
  · simp only [h1, Bool.false_eq_true, ite_false]
    by_cases h2 : eof = true <;> simp [h2]

theorem bodyStep_chunk (lim : Limits) (s : Body) (bs : Bytes) (eof : Bool)
    (hs : s = .size ∨ s = .dataEnd ∨ s = .trailers) :
    bodyStep lim s bs eof =
      match chunkStep s bs with
      | .need => needOr eof bs
      | other => other := by
  rcases hs with rfl | rfl | rfl <;>
  · unfold bodyStep needOr
    rfl


/-! ## One step of `runBody` -/

section Run
variable {lim : Limits} {input : Bytes} {eof close : Bool} {fuel : Nat} {s : Body} {pos : Nat}

theorem run_empty {e : MsgEnd} (h : runBody lim input eof close (fuel + 1) s pos = ([], e))
    {evs : List Event} {fin : MsgEnd} (h' : runBody lim input eof close (fuel + 1) s pos = (evs, fin))
    {d : Nat} (hd : Event.done d ∈ evs) : False := by
  rw [h] at h'
  simp only [Prod.mk.injEq] at h'
  rw [← h'.1] at hd
  simp at hd

theorem run_need (hb : bodyStep lim s (input.drop pos) eof = .need) :
    runBody lim input eof close (fuel + 1) s pos = ([], .stop (needStop input pos eof)) := by
  simp [runBody, hb]

theorem run_fail {e : Error} (hb : bodyStep lim s (input.drop pos) eof = .fail e) :
    runBody lim input eof close (fuel + 1) s pos = ([], .stop (.failed e)) := by
  simp [runBody, hb]

theorem run_finish (hb : bodyStep lim s (input.drop pos) eof = .finish) :
    runBody lim input eof close (fuel + 1) s pos = ([], .stop (.ended pos)) := by
  simp [runBody, hb]

theorem run_done (hb : bodyStep lim s (input.drop pos) eof = .done) :
    runBody lim input eof close (fuel + 1) s pos =
      ([.done pos], if close then .stop (.ended pos) else .next pos) := by
  simp [runBody, hb]

theorem run_end {bytes : Bytes} (hb : bodyStep lim s (input.drop pos) eof = .emit bytes .finished) :
    runBody lim input eof close (fuel + 1) s pos = ([.done pos], .stop (.ended pos)) := by
  simp [runBody, hb]

theorem run_emit {bytes : Bytes} {next : Body} (hb : bodyStep lim s (input.drop pos) eof = .emit bytes next)
    (hn : next ≠ .finished) :
    runBody lim input eof close (fuel + 1) s pos =
      (.body bytes :: (runBody lim input eof close fuel next (pos + bytes.length)).1,
        (runBody lim input eof close fuel next (pos + bytes.length)).2) := by
  simp [runBody, hb, hn]

theorem run_skip {n : Nat} {next : Body} (hb : bodyStep lim s (input.drop pos) eof = .skip n next) :
    runBody lim input eof close (fuel + 1) s pos = runBody lim input eof close fuel next (pos + n) := by
  simp [runBody, hb]

end Run


/-! ## Each state -/

/-- The claim of `runBody_spec` for one amount of fuel. -/
def Claim (lim : Limits) (input : Bytes) (eof close : Bool) (c : Rfc.Choices) (fuel : Nat) : Prop :=
  ∀ s pos evs fin d, runBody lim input eof close fuel s pos = (evs, fin) →
    Event.done d ∈ evs → Spec c s (input.drop pos) (bodyBytes evs, input.drop d)

section Cases
variable {lim : Limits} {input : Bytes} {eof close : Bool} {c : Rfc.Choices} {fuel : Nat}

theorem bodyBytes_body (b : Bytes) (evs : List Event) : bodyBytes (.body b :: evs) = b ++ bodyBytes evs := rfl

/-- The common part of a length and a chunk's data: a block of `n` bytes,
then the rest from the next state. -/
theorem block_step {s next : Body} {pos n : Nat} {evs : List Event} {fin : MsgEnd} {d : Nat}
    (ih : Claim lim input eof close c fuel)
    (hb : bodyStep lim s (input.drop pos) eof = .emit ((input.drop pos).take n) next)
    (hn : next ≠ .finished) (hlen : n ≤ (input.drop pos).length)
    (h : runBody lim input eof close (fuel + 1) s pos = (evs, fin)) (hd : Event.done d ∈ evs) :
    ∃ evs', bodyBytes evs = (input.drop pos).take n ++ bodyBytes evs' ∧
      Spec c next ((input.drop pos).drop n) (bodyBytes evs', input.drop d) := by
  have hl : ((input.drop pos).take n).length = n := by simp only [List.length_take]; omega
  rw [run_emit hb hn, hl] at h
  simp only [Prod.mk.injEq] at h
  obtain ⟨rfl, _⟩ := h
  simp only [List.mem_cons, reduceCtorEq, false_or] at hd
  have := ih next _ _ _ d (Prod.eta _).symm hd
  rw [← List.drop_drop] at this
  exact ⟨_, rfl, this⟩

theorem step_length {k pos : Nat} {evs : List Event} {fin : MsgEnd} {d : Nat}
    (ih : Claim lim input eof close c fuel)
    (h : runBody lim input eof close (fuel + 1) (.length k) pos = (evs, fin)) (hd : Event.done d ∈ evs) :
    Spec c (.length k) (input.drop pos) (bodyBytes evs, input.drop d) := by
  have hb := bodyStep_length lim k (input.drop pos) eof
  generalize hN : min k (max lim.bodyChunk 1) = n at hb
  have hnk : n ≤ k := hN ▸ Nat.min_le_left _ _
  by_cases hlt : (input.drop pos).length < n
  · rw [if_pos hlt] at hb
    unfold needOr at hb
    split at hb
    · exact (run_empty (run_fail hb) h hd).elim
    · exact (run_empty (run_need hb) h hd).elim
  · rw [if_neg hlt] at hb
    by_cases hr : k - n = 0
    · have hb' : bodyStep lim (.length k) (input.drop pos) eof = .emit ((input.drop pos).take n) .done := by
        rw [hb]; simp [hr]
      obtain ⟨evs', hbytes, h1, h2⟩ := block_step ih hb' (by simp) (by omega) h hd
      have hkn : k = n := by omega
      subst hkn
      refine ⟨by omega, ?_, ?_⟩
      · rw [hbytes, h1]; simp
      · rw [h2]
    · have hb' : bodyStep lim (.length k) (input.drop pos) eof =
          .emit ((input.drop pos).take n) (.length (k - n)) := by
        rw [hb]; simp [hr]
      obtain ⟨evs', hbytes, h1, h2, h3⟩ := block_step ih hb' (by simp) (by omega) h hd
      refine ⟨?_, ?_, ?_⟩
      · simp only [List.length_drop] at h1 hlt ⊢; omega
      · rw [hbytes, h2, ← List.take_add]; congr 1; omega
      · rw [h3, List.drop_drop]; congr 1; omega

theorem step_data {k pos : Nat} {evs : List Event} {fin : MsgEnd} {d : Nat}
    (ih : Claim lim input eof close c fuel)
    (h : runBody lim input eof close (fuel + 1) (.data k) pos = (evs, fin)) (hd : Event.done d ∈ evs) :
    Spec c (.data k) (input.drop pos) (bodyBytes evs, input.drop d) := by
  have hb := bodyStep_data lim k (input.drop pos) eof
  generalize hN : min k (max lim.bodyChunk 1) = n at hb
  have hnk : n ≤ k := hN ▸ Nat.min_le_left _ _
  by_cases hlt : (input.drop pos).length < n
  · rw [if_pos hlt] at hb
    unfold needOr at hb
    split at hb
    · exact (run_empty (run_fail hb) h hd).elim
    · exact (run_empty (run_need hb) h hd).elim
  · rw [if_neg hlt] at hb
    by_cases hr : k - n = 0
    · have hb' : bodyStep lim (.data k) (input.drop pos) eof = .emit ((input.drop pos).take n) .dataEnd := by
        rw [hb]; simp [hr]
      obtain ⟨evs', hbytes, after, h1, h2⟩ := block_step ih hb' (by simp) (by omega) h hd
      have hkn : k = n := by omega
      subst hkn
      exact ⟨by omega, after, bodyBytes evs', h1, h2, hbytes⟩
    · have hb' : bodyStep lim (.data k) (input.drop pos) eof =
          .emit ((input.drop pos).take n) (.data (k - n)) := by
        rw [hb]; simp [hr]
      obtain ⟨evs', hbytes, h1, after, b', h2, h3, h4⟩ := block_step ih hb' (by simp) (by omega) h hd
      refine ⟨?_, after, b', ?_, h3, ?_⟩
      · simp at h1 ⊢; omega
      · rw [List.drop_drop, show n + (k - n) = k by omega] at h2; exact h2
      · rw [hbytes, h4, ← List.append_assoc, ← List.take_add]; congr 2; omega

theorem step_close {pos : Nat} {evs : List Event} {fin : MsgEnd} {d : Nat}
    (ih : Claim lim input eof close c fuel)
    (h : runBody lim input eof close (fuel + 1) .close pos = (evs, fin)) (hd : Event.done d ∈ evs) :
    Spec c .close (input.drop pos) (bodyBytes evs, input.drop d) := by
  have hb := bodyStep_close lim (input.drop pos) eof
  generalize hN : min (input.drop pos).length (max lim.bodyChunk 1) = n at hb
  have hn : n ≤ (input.drop pos).length := hN ▸ Nat.min_le_left _ _
  by_cases hfull : (n == max lim.bodyChunk 1 || (eof && n != 0)) = true
  · rw [if_pos hfull] at hb
    obtain ⟨evs', hbytes, h1, h2⟩ := block_step ih hb (by simp) hn h hd
    refine ⟨?_, h2⟩
    rw [hbytes, h1, List.take_append_drop]
  · rw [if_neg hfull] at hb
    by_cases heof : eof = true
    · rw [if_pos heof] at hb
      rw [run_end hb] at h
      simp only [Prod.mk.injEq] at h
      obtain ⟨rfl, _⟩ := h
      simp only [List.mem_singleton, Event.done.injEq] at hd
      rw [hd]
      have hn0 : n = 0 := by
        simp only [heof, Bool.true_and, Bool.or_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, not_or,
          Decidable.not_not] at hfull
        exact hfull.2
      have hempty : input.drop pos = [] := by
        rw [← hN] at hn0
        have : max lim.bodyChunk 1 ≥ 1 := by omega
        have : (input.drop pos).length = 0 := by omega
        exact List.eq_nil_of_length_eq_zero this
      simp only [bodyBytes, hempty]; exact ⟨rfl, rfl⟩
    · rw [if_neg heof] at hb
      have hf : eof = false := by simpa using heof
      subst hf
      unfold needOr at hb
      simp only [Bool.false_and, Bool.false_eq_true, ite_false] at hb
      exact (run_empty (run_need hb) h hd).elim

end Cases


section Chunks
variable {lim : Limits} {input : Bytes} {eof close : Bool} {c : Rfc.Choices} {fuel : Nat}

/-- A step that cannot end the body ends no body. -/
theorem no_done_of_empty {s : Body} {pos : Nat} {evs : List Event} {fin : MsgEnd} {d : Nat}
    (hb : bodyStep lim s (input.drop pos) eof = .need ∨ ∃ e, bodyStep lim s (input.drop pos) eof = .fail e)
    (h : runBody lim input eof close (fuel + 1) s pos = (evs, fin)) (hd : Event.done d ∈ evs) : False := by
  rcases hb with hb | ⟨e, hb⟩
  · exact run_empty (run_need hb) h hd
  · exact run_empty (run_fail hb) h hd

theorem needOr_cases (eof : Bool) (bs : Bytes) : needOr eof bs = .need ∨ ∃ e, needOr eof bs = .fail e := by
  unfold needOr; split
  · exact Or.inr ⟨_, rfl⟩
  · exact Or.inl rfl

/-- The state after the CR LF that follows a chunk's data, or the last
chunk. -/
def crlfNext : Body → Body
  | .trailers => .done
  | _ => .size

/-- After a chunk's data, or the last chunk: CR LF, or no body. -/
theorem crlf_step {s : Body} {pos : Nat} {evs : List Event} {fin : MsgEnd} {d : Nat}
    (hs : s = .dataEnd ∨ s = .trailers)
    (h : runBody lim input eof close (fuel + 1) s pos = (evs, fin)) (hd : Event.done d ∈ evs) :
    ∃ tail, input.drop pos = 13 :: 10 :: tail ∧ input.drop (pos + 2) = tail ∧
      runBody lim input eof close fuel (crlfNext s) (pos + 2) = (evs, fin) := by
  cases hbs : input.drop pos with
  | nil =>
    have hb : bodyStep lim s (input.drop pos) eof = needOr eof [] := by
      rw [hbs]; rcases hs with rfl | rfl <;> rfl
    exact (no_done_of_empty (by rw [hb]; exact needOr_cases _ _) h hd).elim
  | cons b rest =>
    by_cases h13 : b = 13
    · subst h13
      cases rest with
      | nil =>
        have hb : bodyStep lim s (input.drop pos) eof = needOr eof [13] := by
          rw [hbs]; rcases hs with rfl | rfl <;> simp [bodyStep, chunkStep, needOr]
        exact (no_done_of_empty (by rw [hb]; exact needOr_cases _ _) h hd).elim
      | cons b2 tail =>
        by_cases h10 : b2 = 10
        · subst h10
          have hb : bodyStep lim s (input.drop pos) eof = .skip 2 (crlfNext s) := by
            rw [hbs]; rcases hs with rfl | rfl <;> simp [bodyStep, chunkStep, crlfNext]
          refine ⟨tail, rfl, ?_, ?_⟩
          · rw [← List.drop_drop, hbs]; rfl
          · rw [← run_skip hb]; exact h
        · have hb : ∃ e, bodyStep lim s (input.drop pos) eof = .fail e := by
            rw [hbs]; rcases hs with rfl | rfl
            · exact ⟨.chunkEnding, by simp [bodyStep, chunkStep, h10]⟩
            · exact ⟨.trailers, by simp [bodyStep, chunkStep, h10]⟩
          exact (no_done_of_empty (Or.inr hb) h hd).elim
    · have hb : ∃ e, bodyStep lim s (input.drop pos) eof = .fail e := by
        rw [hbs]; rcases hs with rfl | rfl
        · exact ⟨.chunkEnding, by simp [bodyStep, chunkStep, h13]⟩
        · exact ⟨.trailers, by simp [bodyStep, chunkStep, h13]⟩
      exact (no_done_of_empty (Or.inr hb) h hd).elim

theorem step_dataEnd {pos : Nat} {evs : List Event} {fin : MsgEnd} {d : Nat}
    (ih : Claim lim input eof close c fuel)
    (h : runBody lim input eof close (fuel + 1) .dataEnd pos = (evs, fin)) (hd : Event.done d ∈ evs) :
    Spec c .dataEnd (input.drop pos) (bodyBytes evs, input.drop d) := by
  obtain ⟨tail, h1, h2, h3⟩ := crlf_step (Or.inl rfl) h hd
  have := ih .size _ _ _ d h3 hd
  rw [h2] at this
  rw [h1]
  exact ⟨tail, crlf_line c tail, this⟩

theorem step_trailers {pos : Nat} {evs : List Event} {fin : MsgEnd} {d : Nat}
    (ih : Claim lim input eof close c fuel)
    (h : runBody lim input eof close (fuel + 1) .trailers pos = (evs, fin)) (hd : Event.done d ∈ evs) :
    Spec c .trailers (input.drop pos) (bodyBytes evs, input.drop d) := by
  obtain ⟨tail, h1, h2, h3⟩ := crlf_step (Or.inr rfl) h hd
  obtain ⟨hb, hdrop⟩ := ih .done _ _ _ d h3 hd
  rw [h2] at hdrop
  rw [h1]
  refine ⟨hb, ?_⟩
  simp only [List.length_cons, Rfc.trailers, crlf_line]
  simp [hdrop]

theorem step_size {pos : Nat} {evs : List Event} {fin : MsgEnd} {d : Nat}
    (ih : Claim lim input eof close c fuel)
    (h : runBody lim input eof close (fuel + 1) .size pos = (evs, fin)) (hd : Event.done d ∈ evs) :
    Spec c .size (input.drop pos) (bodyBytes evs, input.drop d) := by
  have hb := bodyStep_chunk lim .size (input.drop pos) eof (Or.inl rfl)
  simp only [chunkStep] at hb
  cases hl : lineStep maxChunkLine (input.drop pos) with
  | need =>
    rw [hl] at hb
    exact (no_done_of_empty (by rw [hb]; exact needOr_cases _ _) h hd).elim
  | line res n =>
    rw [hl] at hb
    cases res with
    | error err =>
      cases err <;> exact (no_done_of_empty (Or.inr ⟨_, hb⟩) h hd).elim
    | ok line =>
      simp only at hb
      obtain ⟨hnl, hsplit, hl10, _⟩ := lineStep_ok hl
      by_cases hsemi : line.contains 59 = true
      · simp only [hsemi, ite_true] at hb
        exact (no_done_of_empty (Or.inr ⟨_, hb⟩) h hd).elim
      simp only [hsemi, Bool.false_eq_true, ite_false] at hb
      cases hx : hexNumber line with
      | none =>
        rw [hx] at hb
        exact (no_done_of_empty (Or.inr ⟨_, hb⟩) h hd).elim
      | some k =>
        rw [hx] at hb
        obtain ⟨_, hall, _⟩ := hexNumber_some hx
        have l13 : 13 ∉ line := fun hm => (hexdig_clean (hall 13 hm)).1 rfl
        have hcs := chunkSize_hex hx
        have hrl : Rfc.line c (input.drop pos) = some (line, (input.drop pos).drop n) := by
          conv => lhs; rw [hsplit]
          exact rfc_line c line _ l13 hl10
        have hlen : (input.drop pos).length = ((input.drop pos).length - 1) + 1 := by
          have h6 := congrArg List.length hsplit
          simp only [List.length_append, List.length_cons, List.length_drop] at h6 ⊢; omega
        have e : (input.drop pos).drop n = input.drop (pos + n) := List.drop_drop
        cases k with
        | zero =>
          simp only at hb
          rw [run_skip hb] at h
          obtain ⟨hbytes, ht⟩ := ih _ _ _ _ d h hd
          show Rfc.chunked c (input.drop pos).length (input.drop pos) = some (bodyBytes evs, input.drop d)
          rw [hlen]
          simp only [Rfc.chunked, hrl, hcs, hbytes]
          rw [e, ht]
          rfl
        | succ k =>
          simp only at hb
          rw [run_skip hb] at h
          obtain ⟨h1, after, b', h2, h3, h4⟩ := ih _ _ _ _ d h hd
          show Rfc.chunked c (input.drop pos).length (input.drop pos) = some (bodyBytes evs, input.drop d)
          rw [hlen]
          simp only [Rfc.chunked, hrl, hcs]
          rw [e]
          have hlt : ¬(input.drop (pos + n)).length < k + 1 := by omega
          rw [if_neg hlt, h2]
          have hshort : after.length ≤ (input.drop pos).length - 1 := by
            have h5 := line_shorter h2
            have h6 := congrArg List.length hsplit
            simp only [List.length_drop, List.length_append, List.length_cons] at h5 h6 ⊢
            omega
          simp only
          rw [chunked_mono c _ _ _ h3 _ hshort, h4]
          rfl

end Chunks

/-- **The body.** From any state, if the decoder reports `Done` at offset
`d`, the body bytes it reported and the bytes from `d` on are what every
recipient reads for the rest of that body. -/
theorem runBody_spec (lim : Limits) (input : Bytes) (eof close : Bool) (c : Rfc.Choices) :
    ∀ fuel, Claim lim input eof close c fuel := by
  intro fuel
  induction fuel with
  | zero =>
    intro s pos evs fin d h hd
    simp only [runBody, Prod.mk.injEq] at h
    rw [← h.1] at hd
    simp at hd
  | succ fuel ih =>
    intro s pos evs fin d h hd
    cases s with
    | done =>
      rw [run_done (bodyStep_done _ _ _)] at h
      simp only [Prod.mk.injEq] at h
      obtain ⟨rfl, _⟩ := h
      simp only [List.mem_singleton, Event.done.injEq] at hd
      rw [hd]
      exact ⟨rfl, rfl⟩
    | finished => exact (run_empty (run_finish (bodyStep_finished _ _ _)) h hd).elim
    | boundary => exact (run_empty (run_finish (bodyStep_boundary _ _ _)) h hd).elim
    | length k => exact step_length ih h hd
    | data k => exact step_data ih h hd
    | close => exact step_close ih h hd
    | size => exact step_size ih h hd
    | dataEnd => exact step_dataEnd ih h hd
    | trailers => exact step_trailers ih h hd

/-- The first state of a body framed by `f`, as `Reader::begin` sets it, is
what the RFC reads for the whole body. -/
theorem begin_spec (c : Rfc.Choices) (f : Framing) (close : Bool) (bs : Bytes) (r : Bytes × Bytes)
    (h : Spec c (begin f close).1 bs r) : Rfc.body c f bs = some r := by
  obtain ⟨b, rest⟩ := r
  cases f with
  | empty => obtain ⟨rfl, rfl⟩ := h; rfl
  | length n =>
    cases n with
    | zero => obtain ⟨rfl, rfl⟩ := h; simp [Rfc.body]
    | succ n =>
      obtain ⟨h1, rfl, rfl⟩ := h
      simp [Rfc.body]; omega
  | chunked => exact h
  | close => obtain ⟨rfl, rfl⟩ := h; rfl


/-! ## No request smuggling -/

theorem bodyBytes_head (m t : Bytes) (v : Version) (st e : Nat) (evs : List Event) :
    bodyBytes (.head m t v st e :: evs) = bodyBytes evs := rfl

/-- **No request smuggling.** Take any input and any message the server's
decoder reads from its start to the end (`Done` at offset `d`). Every
recipient in the RFC 9112 family reads that message with the same head end,
method, framing, body and end, or refuses it; and a recipient refuses it
only if it skips fewer empty lines before a request than the server does
(at most eight) or refuses a repeated `Content-Length`. Since
`Wire.requests` reads each message of a pipeline with `request1` from where
the last one ended, this holds for every message of a pipeline. -/
theorem request_agrees {lim : Limits} {input : Bytes} {eof : Bool} {evs : List Event} {fin : MsgEnd}
    {d : Nat} (h : request1 lim input eof = (evs, fin)) (hd : Event.done d ∈ evs) (c : Rfc.Choices) :
    ∃ (e : Nat) (rh : RequestHead) (f : Framing), evs.head? = some (.head rh.method rh.target rh.version 0 e) ∧
      (Rfc.request c input = some ⟨⟨e, rh.method, f, input.drop e⟩, bodyBytes evs, input.drop d⟩ ∨
        (Rfc.request c input = none ∧ (c.emptyLines < maxEmptyLines ∨ c.clList = false))) := by
  unfold request1 at h
  cases hs : requestStart lim input eof with
  | stop s =>
    rw [hs] at h
    simp only [Prod.mk.injEq] at h
    rw [← h.1] at hd
    simp at hd
  | head e hd' r f =>
    rw [hs] at h
    simp only at h
    generalize hb : begin f (r.close || hd'.method == str "CONNECT") = sc at h
    obtain ⟨s, close⟩ := sc
    simp only at h
    cases hrun : runBody lim input eof close (input.length + 2) s e with
    | mk evs' fin' =>
      rw [hrun] at h
      simp only [Prod.mk.injEq] at h
      obtain ⟨rfl, _⟩ := h
      simp only [List.mem_cons, reduceCtorEq, false_or] at hd
      have hspec := runBody_spec lim input eof close c _ s e evs' fin' d hrun hd
      have hs' : (begin f (r.close || hd'.method == str "CONNECT")).1 = s := by rw [hb]
      rw [← hs'] at hspec
      have hbody := begin_spec c f _ _ _ hspec
      refine ⟨e, hd', f, rfl, ?_⟩
      rw [bodyBytes_head]
      rcases head_agrees hs c with hh | ⟨hn, hwhy⟩
      · left
        simp only [Rfc.request, hh, hbody]
      · right
        simp only [Rfc.request, hn]
        exact ⟨trivial, hwhy⟩

/-- The recipients that take every tolerance, or none of them but the
repeated `Content-Length` and the empty lines, accept every message the
server accepts, with the same boundaries: the agreement in
`request_agrees` is never vacuous. -/
theorem request_accepted {lim : Limits} {input : Bytes} {eof : Bool} {evs : List Event} {fin : MsgEnd}
    {d : Nat} (h : request1 lim input eof = (evs, fin)) (hd : Event.done d ∈ evs) (c : Rfc.Choices)
    (hc1 : maxEmptyLines ≤ c.emptyLines) (hc2 : c.clList = true) :
    ∃ (e : Nat) (rh : RequestHead) (f : Framing), evs.head? = some (.head rh.method rh.target rh.version 0 e) ∧
      Rfc.request c input = some ⟨⟨e, rh.method, f, input.drop e⟩, bodyBytes evs, input.drop d⟩ := by
  obtain ⟨e, hd', f, h1, h2⟩ := request_agrees h hd c
  rcases h2 with h2 | ⟨_, h3⟩
  · exact ⟨e, hd', f, h1, h2⟩
  · rcases h3 with h3 | h3
    · omega
    · rw [hc2] at h3; cases h3

end Http.BodyProof
