import Hpack.Block

/-!
# What the block decoder guarantees

The grammar round trip (`parse_write`: every well-formed sequence of
representations, written, reads back as itself), the order rule
(`parse_updates_first`), and the decoder's size update and table rules:
`decode_reduced`, `acks_then_block`, `decode_updates`, `decode_state`.
-/

namespace Hpack

/-! ## Writing reads back -/

theorem encodeInt_head (p flags v : Nat) :
    ∃ rest, encodeInt p flags v = (flags + min v (mask p)) :: rest := by
  unfold encodeInt
  split
  · exact ⟨[], by rw [Nat.min_eq_left (by omega)]⟩
  · exact ⟨_, by rw [Nat.min_eq_right (by omega)]⟩

theorem readInt_encode (p flags v : Nat) (rest : Bytes) (hp : 1 ≤ p ∧ p ≤ 8)
    (hf : flags % 2 ^ p = 0) (hv : v < intBound) :
    readInt p (encodeInt p flags v ++ rest) = .ok (v, rest) := by
  unfold readInt
  rw [decode_encode p flags v rest hp hf hv]
  simp

/-- A string an encoder may write: octets, within `maxString`, and, if Huffman
coded, within `maxString` coded too. -/
def Lit.Wf (l : Lit) : Prop :=
  (∀ b ∈ l.s, b < 256) ∧ l.s.length ≤ maxString ∧ (l.huff = true → (encode l.s).length ≤ maxString)

theorem maxString_lt : maxString < intBound := by decide

theorem readStr_write (l : Lit) (rest : Bytes) (h : l.Wf) :
    readStr (writeStr l ++ rest) = .ok (l.s, rest) := by
  obtain ⟨hb, hl, hh⟩ := h
  have m7 : mask 7 = 127 := rfl
  by_cases hu : l.huff = true
  · have hL := hh hu
    have e : writeStr l ++ rest = encodeInt 7 128 (encode l.s).length ++ (encode l.s ++ rest) := by
      simp [writeStr, hu]
    obtain ⟨t, ht⟩ := encodeInt_head 7 128 (encode l.s).length
    have hhead : (writeStr l ++ rest).head? = some (128 + min (encode l.s).length (mask 7)) := by
      rw [e, ht]; rfl
    unfold readStr
    rw [hhead]
    simp only
    rw [e, readInt_encode 7 128 _ _ (by decide) (by decide) (by have := maxString_lt; omega)]
    simp only [show ¬ maxString < (encode l.s).length by omega, ite_false, List.length_append,
      show ¬ (encode l.s).length + rest.length < (encode l.s).length by omega,
      show 128 ≤ 128 + min (encode l.s).length (mask 7) by omega, ite_true,
      List.take_left', List.drop_left']
    rw [decode_encode_huffman maxString l.s hb hl]
  · have e : writeStr l ++ rest = encodeInt 7 0 l.s.length ++ (l.s ++ rest) := by
      simp [writeStr, hu]
    obtain ⟨t, ht⟩ := encodeInt_head 7 0 l.s.length
    have hhead : (writeStr l ++ rest).head? = some (0 + min l.s.length (mask 7)) := by
      rw [e, ht]; rfl
    unfold readStr
    rw [hhead]
    simp only
    rw [e, readInt_encode 7 0 _ _ (by decide) (by decide) (by have := maxString_lt; omega)]
    simp only [show ¬ maxString < l.s.length by omega, ite_false, List.length_append,
      show ¬ l.s.length + rest.length < l.s.length by omega,
      show ¬ 128 ≤ 0 + min l.s.length (mask 7) by omega,
      List.take_left', List.drop_left']

/-- A representation an encoder may write: indexes from 1 and below 2^64, sizes
below 2^64, strings that are `Lit.Wf`. -/
def WRep.Wf : WRep → Prop
  | .indexed i => 0 < i ∧ i < intBound
  | .update n => n < intBound
  | .literal (.literal l) v _ => l.Wf ∧ v.Wf
  | .literal (.index i) v _ => 0 < i ∧ i < intBound ∧ v.Wf

theorem rep_isUpdate (w : WRep) : w.rep.isUpdate = w.isUpdate := by
  rcases w with i | ⟨n, v, ix⟩ | n
  · rfl
  · cases n <;> rfl
  · rfl

theorem readLiteral_write (ix : Indexing) (n : WName) (v : Lit) (rest : Bytes)
    (hw : (WRep.literal n v ix).Wf) :
    readLiteral ix (ixPrefix ix).1 (writeLiteral (ixPrefix ix).1 (ixPrefix ix).2 n v ++ rest)
      = .ok ((WRep.literal n v ix).rep, rest) := by
  have hp : 1 ≤ (ixPrefix ix).1 ∧ (ixPrefix ix).1 ≤ 8 := by cases ix <;> decide
  have hf : (ixPrefix ix).2 % 2 ^ (ixPrefix ix).1 = 0 := by cases ix <;> decide
  cases n with
  | literal l =>
    obtain ⟨hl, hv⟩ := hw
    simp only [writeLiteral, List.append_assoc, readLiteral]
    rw [readInt_encode _ _ 0 _ hp hf (by decide)]
    simp only [readName, ite_true]
    rw [readStr_write l _ hl]
    simp only
    rw [readStr_write v _ hv]
    rfl
  | index i =>
    obtain ⟨h0, hi, hv⟩ := hw
    simp only [writeLiteral, List.append_assoc, readLiteral]
    rw [readInt_encode _ _ i _ hp hf hi]
    simp only [readName, show ¬ i = 0 by omega, ite_false]
    rw [readStr_write v _ hv]
    rfl

/-- The name index a literal carries: 0 for a name of its own. -/
def WName.idx : WName → Nat
  | .literal _ => 0
  | .index i => i

theorem writeLiteral_head (p flags : Nat) (n : WName) (v : Lit) :
    ∃ rest, writeLiteral p flags n v = (flags + min n.idx (mask p)) :: rest := by
  cases n with
  | literal l =>
    obtain ⟨t, ht⟩ := encodeInt_head p flags 0
    exact ⟨t ++ (writeStr l ++ writeStr v), by simp only [writeLiteral, WName.idx, ht, List.cons_append]⟩
  | index i =>
    obtain ⟨t, ht⟩ := encodeInt_head p flags i
    exact ⟨t ++ writeStr v, by simp only [writeLiteral, WName.idx, ht, List.cons_append]⟩

/-- A literal's first byte is no size update and no indexed field, and its
pattern gives back its indexing and prefix width. -/
theorem literal_byte (ix : Indexing) (x : Nat) (hx : x ≤ mask (ixPrefix ix).1) :
    ¬ ((ixPrefix ix).2 + x) / 32 = 1 ∧ ¬ 128 ≤ (ixPrefix ix).2 + x ∧
      literalKind ((ixPrefix ix).2 + x) = (ix, (ixPrefix ix).1) := by
  match ix with
  | .incremental =>
    have hx' : x ≤ 63 := hx
    simp only [ixPrefix, literalKind, show 64 ≤ 64 + x by omega, ite_true]
    refine ⟨?_, ?_, ?_⟩ <;> first | omega | trivial
  | .never =>
    have hx' : x ≤ 15 := hx
    simp only [ixPrefix, literalKind, show ¬ 64 ≤ 16 + x by omega,
      show (16 + x) / 16 = 1 by omega, ite_true, ite_false]
    refine ⟨?_, ?_, ?_⟩ <;> first | omega | trivial
  | .without =>
    have hx' : x ≤ 15 := hx
    simp only [ixPrefix, literalKind, show ¬ 64 ≤ 0 + x by omega,
      show ¬ (0 + x) / 16 = 1 by omega, ite_false]
    refine ⟨?_, ?_, ?_⟩ <;> first | omega | trivial

/-- Every well-formed representation reads back as itself, from its first byte's
pattern, whatever follows; a size update only before any field. -/
theorem readRep_write (started : Bool) (w : WRep) (rest : Bytes) (hw : w.Wf)
    (hs : started = true → w.isUpdate = false) :
    readRep started (writeRep w ++ rest) = .ok (w.rep, rest) := by
  rcases w with i | ⟨n, v, ix⟩ | u
  · obtain ⟨h0, hi⟩ := hw
    obtain ⟨t, ht⟩ := encodeInt_head 7 128 i
    have m7 : mask 7 = 127 := rfl
    have hh : (writeRep (.indexed i) ++ rest).head? = some (128 + min i (mask 7)) := by
      simp only [writeRep, ht]; rfl
    unfold readRep
    rw [hh]
    simp only [show ¬ (128 + min i (mask 7)) / 32 = 1 by omega, ite_false,
      show 128 ≤ 128 + min i (mask 7) by omega, ite_true]
    simp only [writeRep]
    rw [readInt_encode 7 128 i rest (by decide) (by decide) hi]
    simp [show ¬ i = 0 by omega, WRep.rep]
  · have hh : (writeRep (.literal n v ix) ++ rest).head? =
        some ((ixPrefix ix).2 + min n.idx (mask (ixPrefix ix).1)) := by
      obtain ⟨t, ht⟩ := writeLiteral_head (ixPrefix ix).1 (ixPrefix ix).2 n v
      simp only [writeRep, ht]; rfl
    obtain ⟨k1, k2, k3⟩ := literal_byte ix _ (Nat.min_le_right n.idx _)
    unfold readRep
    rw [hh]
    simp only [k1, k2, ite_false]
    rw [k3]
    exact readLiteral_write ix n v rest hw
  · have hs' : started = false := by
      cases started
      · rfl
      · exact absurd (hs rfl) (by simp [WRep.isUpdate])
    obtain ⟨t, ht⟩ := encodeInt_head 5 32 u
    have m5 : mask 5 = 31 := rfl
    have hh : (writeRep (.update u) ++ rest).head? = some (32 + min u (mask 5)) := by
      simp only [writeRep, ht]; rfl
    unfold readRep
    rw [hh]
    simp only [show (32 + min u (mask 5)) / 32 = 1 by omega, ite_true, hs']
    simp only [writeRep, Bool.false_eq_true, ite_false]
    rw [readInt_encode 5 32 u rest (by decide) (by decide) hw]
    rfl

theorem writeRep_ne_nil (w : WRep) : writeRep w ≠ [] := by
  rcases w with i | ⟨n, v, ix⟩ | u
  · obtain ⟨t, ht⟩ := encodeInt_head 7 128 i; simp [writeRep, ht]
  · obtain ⟨t, ht⟩ := writeLiteral_head (ixPrefix ix).1 (ixPrefix ix).2 n v
    simp [writeRep, ht]
  · obtain ⟨t, ht⟩ := encodeInt_head 5 32 u; simp [writeRep, ht]

/-- Size updates only before every field (section 4.2), from `started` on. -/
def Ordered : Bool → List WRep → Prop
  | _, [] => True
  | s, w :: ws => (s = true → w.isUpdate = false) ∧ Ordered (s || !w.isUpdate) ws

/-- Section 6 round trip: well-formed representations with their size updates
first, written one after another, read back as themselves. -/
theorem parse_write (s : Bool) (ws : List WRep) (hw : ∀ w ∈ ws, w.Wf) (ho : Ordered s ws) :
    parseBlock s (writeBlock ws) = (ws.map WRep.rep, none) := by
  induction ws generalizing s with
  | nil => simp [writeBlock, parseBlock]
  | cons w ws ih =>
    obtain ⟨ho1, ho2⟩ := ho
    have hread := readRep_write s w (writeBlock ws) (hw w (by simp)) ho1
    have hne : writeRep w ++ writeBlock ws ≠ [] := by simp [writeRep_ne_nil]
    rw [show writeBlock (w :: ws) = writeRep w ++ writeBlock ws by simp [writeBlock]]
    rw [parseBlock, dif_neg hne]
    split
    · next e he => rw [hread] at he; cases he
    · next r rest he =>
      rw [hread] at he
      simp only [Except.ok.injEq, Prod.mk.injEq] at he
      obtain ⟨rfl, rfl⟩ := he
      rw [rep_isUpdate, ih (s || !w.isUpdate) (fun x hx => hw x (by simp [hx])) ho2]
      simp

/-! ## The order of size updates -/

/-- Size updates only before every field, for decoded representations. -/
def RepOrdered : Bool → List Rep → Prop
  | _, [] => True
  | s, r :: rs => (s = true → r.isUpdate = false) ∧ RepOrdered (s || !r.isUpdate) rs

theorem readLiteral_kind (ix : Indexing) (p : Nat) (bs rest : Bytes) (r : Rep)
    (h : readLiteral ix p bs = .ok (r, rest)) : r.isUpdate = false := by
  unfold readLiteral at h
  split at h
  · cases h
  · split at h
    · cases h
    · split at h
      · cases h
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h
        rw [← h.1]; rfl

theorem readRep_started (bs rest : Bytes) (r : Rep) (h : readRep true bs = .ok (r, rest)) :
    r.isUpdate = false := by
  unfold readRep at h
  split at h
  · cases h
  · split at h
    · simp at h
    · split at h
      · split at h
        · cases h
        · split at h
          · cases h
          · simp only [Except.ok.injEq, Prod.mk.injEq] at h
            rw [← h.1]; rfl
      · exact readLiteral_kind _ _ _ _ _ h

/-- Section 4.2: a size update after a field is never read. Whatever the bytes,
the representations read have every size update before every field; a size
update after a field stops the block with `sizeUpdateOrder`. -/
theorem parse_updates_first (s : Bool) (bs : Bytes) : RepOrdered s (parseBlock s bs).1 := by
  induction hn : bs.length using Nat.strongRecOn generalizing s bs with
  | _ n ih =>
    rw [parseBlock]
    split
    · trivial
    · split
      · trivial
      · next r rest he =>
        refine ⟨?_, ih rest.length (by have := readRep_shorter _ _ _ _ he; omega) _ _ rfl⟩
        intro hs
        subst hs
        exact readRep_started _ _ _ he

/-! ## The decoder's rules -/

/-- What an accepted size update checked, and what it did. -/
theorem applyRep_update (st st' : St) (u : Nat) (h : applyRep st (.update u) = .ok st') :
    ¬ (st.updates = 2 ∨ (st.updates = 1 ∧ u < st.previous)) ∧ u ≤ st.dec.settings ∧
    overOwed st.dec.required u = false ∧
    st' = { st with
      dec := { st.dec with required := none, max := u, dyn := st.dec.dyn.evict u }
      updates := st.updates + 1
      previous := u } := by
  simp only [applyRep] at h
  split at h
  · cases h
  · next h1 =>
    split at h
    · cases h
    · next h2 =>
      split at h
      · cases h
      · next h3 =>
        simp only [Except.ok.injEq] at h
        exact ⟨h1, by omega, by simpa using h3, h.symm⟩

/-- An accepted field owed no reduction, and leaves the settings and the count
of size updates as they were. -/
theorem applyRep_field (st st' : St) (r : Rep) (hr : r.isUpdate = false)
    (h : applyRep st r = .ok st') :
    st.dec.required = none ∧ st'.updates = st.updates ∧ st'.previous = st.previous ∧
      st'.dec.settings = st.dec.settings ∧ st'.dec.required = none := by
  cases r with
  | update u => cases hr
  | indexed i =>
    simp only [applyRep] at h
    split at h
    · cases h
    · next hq =>
      split at h
      · cases h
      · simp only [Except.ok.injEq] at h
        rw [← h]
        simp only [Bool.not_eq_true, Option.isSome_eq_false_iff, Option.isNone_iff_eq_none] at hq
        exact ⟨hq, rfl, rfl, rfl, hq⟩
  | literal n v ix =>
    simp only [applyRep] at h
    split at h
    · cases h
    · next hq =>
      simp only [Bool.not_eq_true, Option.isSome_eq_false_iff, Option.isNone_iff_eq_none] at hq
      split at h
      · cases h
      · split at h
        · simp only [Except.ok.injEq] at h; rw [← h]; exact ⟨hq, rfl, rfl, rfl, hq⟩
        · simp only [Except.ok.injEq] at h; rw [← h]; exact ⟨hq, rfl, rfl, rfl, hq⟩

theorem applyAll_inv (P : St → Prop) (hstep : ∀ st r st', P st → applyRep st r = .ok st' → P st')
    (rs : List Rep) (st st' : St) (hp : P st) (h : applyAll st rs = .ok st') : P st' := by
  induction rs generalizing st with
  | nil => simp [applyAll] at h; rw [← h]; exact hp
  | cons r rs ih =>
    simp only [applyAll] at h
    split at h
    · cases h
    · next st1 h1 => exact ih st1 (hstep st r st1 hp h1) h

/-- What a successful block leaves: its representations all applied, nothing
left unread, and no reduction still owed. -/
theorem decode_ok (d : Decoder) (bs : Bytes) (fs : List Field) (d' : Decoder)
    (h : decodeBlock d bs = .ok (fs, d')) :
    bs.length ≤ maxBlock ∧ (parseBlock false bs).2 = none ∧
    ∃ st, applyAll (St.start d) (parseBlock false bs).1 = .ok st ∧ st.dec = d' ∧
      st.out.reverse = fs ∧ d'.required = none := by
  rw [decodeBlock_ok_iff] at h
  unfold decodeParsed at h
  split at h
  · cases h
  · next hb =>
    split at h
    · cases h
    · next st hst =>
      split at h
      · cases h
      · next hn =>
        split at h
        · cases h
        · next hr =>
          simp only [Except.ok.injEq, Prod.mk.injEq] at h
          refine ⟨by omega, hn, st, hst, h.2, h.1, ?_⟩
          rw [← h.2]
          cases hq : st.dec.required <;> simp_all

/-- A reduction is owed: a block is accepted only if it starts with a size update
at or below the owed size (section 4.2). -/
theorem decode_reduced (d : Decoder) (bs : Bytes) (fs : List Field) (d' : Decoder) (m : Nat)
    (hm : d.required = some m) (h : decodeBlock d bs = .ok (fs, d')) :
    ∃ u rest, (parseBlock false bs).1 = .update u :: rest ∧ u ≤ m := by
  obtain ⟨_, _, st, hst, hd, _, hr⟩ := decode_ok d bs fs d' h
  match hp : (parseBlock false bs).1, hst with
  | [], hst =>
    simp only [applyAll, Except.ok.injEq] at hst
    subst hst
    simp only [St.start] at hd
    subst hd
    rw [hm] at hr
    cases hr
  | r :: rest, hst =>
    simp only [applyAll] at hst
    split at hst
    · cases hst
    · next st1 h1 =>
      cases r with
      | update u =>
        refine ⟨u, rest, rfl, ?_⟩
        obtain ⟨_, _, hov, _⟩ := applyRep_update _ _ u h1
        simp only [St.start, overOwed, hm, decide_eq_false_iff_not] at hov
        omega
      | indexed i => simp [applyRep, St.start, hm] at h1
      | literal n v ix => simp [applyRep, St.start, hm] at h1

theorem acks_required (d : Decoder) (ls : List Nat) (l : Nat) (hl : l ∈ ls)
    (hlt : min l maxTable < d.max) :
    ∃ m, (ls.foldl Decoder.ack d).required = some m ∧ m ≤ min l maxTable := by
  -- Acknowledgments never change the table's maximum.
  have keep : ∀ (ls : List Nat) (d : Decoder), (ls.foldl Decoder.ack d).max = d.max := by
    intro ls
    induction ls with
    | nil => intro d; rfl
    | cons x xs ih => intro d; simp only [List.foldl_cons]; rw [ih]; rfl
  -- Once owed, a reduction only gets smaller.
  have stay : ∀ (ls : List Nat) (d : Decoder) (m : Nat), d.required = some m →
      ∃ m', (ls.foldl Decoder.ack d).required = some m' ∧ m' ≤ m := by
    intro ls
    induction ls with
    | nil => intro d m h; exact ⟨m, h, Nat.le_refl _⟩
    | cons x xs ih =>
      intro d m h
      simp only [List.foldl_cons]
      have : ∃ m1, (d.ack x).required = some m1 ∧ m1 ≤ m := by
        simp only [Decoder.ack, h]
        split
        · exact ⟨_, rfl, Nat.min_le_left _ _⟩
        · exact ⟨m, rfl, Nat.le_refl _⟩
      obtain ⟨m1, h1, hle⟩ := this
      obtain ⟨m', h', hle'⟩ := ih (d.ack x) m1 h1
      exact ⟨m', h', by omega⟩
  induction ls generalizing d with
  | nil => cases hl
  | cons x xs ih =>
    simp only [List.foldl_cons]
    rcases List.mem_cons.mp hl with rfl | hl'
    · have : ∃ m1, (d.ack l).required = some m1 ∧ m1 ≤ min l maxTable := by
        simp only [Decoder.ack, hlt, ite_true]
        cases d.required <;> simp <;> omega
      obtain ⟨m1, h1, hle⟩ := this
      obtain ⟨m', h', hle'⟩ := stay xs (d.ack l) m1 h1
      exact ⟨m', h', by omega⟩
    · exact ih (d.ack x) hl' (by simpa [Decoder.ack] using hlt)

/-- Section 4.2 with SETTINGS: after acknowledged limits, every one of them below
the table's maximum, the next block is accepted only if it starts with a size
update at or below each of those limits (capped at `maxTable`), so at or below
the least. -/
theorem acks_then_block (d : Decoder) (ls : List Nat) (bs : Bytes) (fs : List Field) (d' : Decoder)
    (h : decodeBlock (ls.foldl Decoder.ack d) bs = .ok (fs, d')) :
    ∀ l ∈ ls, min l maxTable < d.max →
      ∃ u rest, (parseBlock false bs).1 = .update u :: rest ∧ u ≤ min l maxTable := by
  intro l hl hlt
  obtain ⟨m, hm, hle⟩ := acks_required d ls l hl hlt
  obtain ⟨u, rest, hp, hu⟩ := decode_reduced _ bs fs d' m hm h
  exact ⟨u, rest, hp, by omega⟩

/-- The size updates among representations. -/
def updatesOf : List Rep → List Nat
  | [] => []
  | .update u :: rs => u :: updatesOf rs
  | _ :: rs => updatesOf rs

theorem applyAll_updates (rs : List Rep) (st st' : St) (h : applyAll st rs = .ok st')
    (h2 : st.updates ≤ 2) :
    st.updates + (updatesOf rs).length ≤ 2 ∧ (∀ u ∈ updatesOf rs, u ≤ st.dec.settings) ∧
    (st.updates = 1 → ∀ u ∈ (updatesOf rs).head?, st.previous ≤ u) ∧
    (updatesOf rs).Pairwise (· ≤ ·) := by
  induction rs generalizing st with
  | nil => simp [updatesOf]; omega
  | cons r rs ih =>
    simp only [applyAll] at h
    split at h
    · cases h
    · next st1 h1 =>
      cases r with
      | update u =>
        obtain ⟨hord, hset, _, rfl⟩ := applyRep_update st st1 u h1
        obtain ⟨i1, i2, i3, i4⟩ := ih _ h (by simp only; omega)
        simp only at i1 i2 i3
        refine ⟨by simp only [updatesOf, List.length_cons]; omega, ?_, ?_, ?_⟩
        · intro x hx
          simp only [updatesOf, List.mem_cons] at hx
          rcases hx with rfl | hx
          · exact hset
          · exact i2 x hx
        · intro h1 x hx
          simp only [updatesOf, List.head?_cons, Option.mem_def, Option.some.injEq] at hx
          subst hx
          omega
        · simp only [updatesOf, List.pairwise_cons]
          refine ⟨?_, i4⟩
          intro b hb
          cases hu : updatesOf rs with
          | nil => rw [hu] at hb; cases hb
          | cons b' rest =>
            rw [hu] at hb i1 i3
            simp only [List.length_cons] at i1
            have hr : rest = [] := List.length_eq_zero_iff.mp (by omega)
            subst hr
            simp only [List.mem_singleton] at hb
            subst hb
            exact i3 (by omega) _ rfl
      | indexed i =>
        obtain ⟨_, e1, e2, e3, _⟩ := applyRep_field st st1 _ rfl h1
        have := ih st1 h (by omega)
        simp only [updatesOf, e1, e2, e3] at this ⊢
        exact this
      | literal n v ix =>
        obtain ⟨_, e1, e2, e3, _⟩ := applyRep_field st st1 _ rfl h1
        have := ih st1 h (by omega)
        simp only [updatesOf, e1, e2, e3] at this ⊢
        exact this

/-- A block's size updates: each at or below the acknowledged settings limit
(section 6.3), and, the rule Rust adds to section 4.2, at most two of them,
the second at least the first. -/
theorem decode_updates (d : Decoder) (bs : Bytes) (fs : List Field) (d' : Decoder)
    (h : decodeBlock d bs = .ok (fs, d')) :
    let us := updatesOf (parseBlock false bs).1
    us.length ≤ 2 ∧ us.Pairwise (· ≤ ·) ∧ ∀ u ∈ us, u ≤ d.settings := by
  obtain ⟨_, _, st, hst, _, _, _⟩ := decode_ok d bs fs d' h
  obtain ⟨i1, i2, _, i4⟩ := applyAll_updates _ _ _ hst (by simp [St.start])
  simp only [St.start] at i1 i2
  exact ⟨by omega, i4, i2⟩

/-- The table after any accepted block: its size the exact sum of its entries and
within its maximum; its maximum the one before or a size update's, at or below
the settings limit; the settings limit unchanged; no reduction owed. -/
theorem decode_state (d : Decoder) (bs : Bytes) (fs : List Field) (d' : Decoder)
    (hx : d.dyn.Exact) (hs : d.dyn.size ≤ d.max) (h : decodeBlock d bs = .ok (fs, d')) :
    d'.dyn.Exact ∧ d'.dyn.size ≤ d'.max ∧ d'.settings = d.settings ∧ d'.required = none ∧
      (d'.max = d.max ∨ d'.max ≤ d.settings) := by
  obtain ⟨_, _, st, hst, hd, _, hr⟩ := decode_ok d bs fs d' h
  let P : St → Prop := fun st => st.dec.dyn.Exact ∧ st.dec.dyn.size ≤ st.dec.max ∧
    st.dec.settings = d.settings ∧ (st.dec.max = d.max ∨ st.dec.max ≤ d.settings)
  have step : ∀ st r st', P st → applyRep st r = .ok st' → P st' := by
    intro st r st' ⟨p1, p2, p3, p4⟩ h1
    cases r with
    | update u =>
      simp only [applyRep] at h1
      split at h1
      · cases h1
      · split at h1
        · cases h1
        · next hset =>
          split at h1
          · cases h1
          · simp only [Except.ok.injEq] at h1
            rw [← h1]
            obtain ⟨_, e2, e3⟩ := evict_fit u st.dec.dyn p1
            exact ⟨e2, e3, p3, Or.inr (by simp only; omega)⟩
    | indexed i =>
      simp only [applyRep] at h1
      split at h1
      · cases h1
      · split at h1
        · cases h1
        · simp only [Except.ok.injEq] at h1; rw [← h1]; exact ⟨p1, p2, p3, p4⟩
    | literal n v ix =>
      simp only [applyRep] at h1
      split at h1
      · cases h1
      · split at h1
        · cases h1
        · split at h1
          · simp only [Except.ok.injEq] at h1
            rw [← h1]
            obtain ⟨e1, e2⟩ := insert_exact st.dec.max _ st.dec.dyn p1
            exact ⟨e1, e2, p3, p4⟩
          · simp only [Except.ok.injEq] at h1; rw [← h1]; exact ⟨p1, p2, p3, p4⟩
  obtain ⟨q1, q2, q3, q4⟩ := applyAll_inv P step _ _ _ ⟨hx, hs, rfl, Or.inl rfl⟩ hst
  rw [hd] at q1 q2 q3 q4
  exact ⟨q1, q2, q3, hr, q4⟩

end Hpack
