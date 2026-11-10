import Hpack.Encoder
import Hpack.Rules

/-!
# Encoder and decoder in step (RFC 7541 sections 2.2, 4.2 and 6)

`InStep enc dec` relates one direction's encoder to the decoder at the other
end. With no size change owed, their tables and maximum sizes are the same.
With one owed, the encoder's table is the decoder's evicted to the least size
the encoder chose, and the decoder owes no reduction below it.

The SETTINGS acknowledgment is taken to go out before the next block, as the
server does (`HpackSync.tla`, `ImmediateAck`): `inStep_settings` applies a
limit to both ends at once.

`block_round_trip`: from ends in step, any block an encoder writes, for any
`Policy` whose Huffman strings fit `maxString`, decodes to exactly its fields,
never-indexed flags included, and leaves the ends in step with nothing owed.
-/

namespace Hpack

/-- A field an encoder takes: octets, each string within `maxString`. -/
def Field.Wf (f : Field) : Prop :=
  (∀ b ∈ f.name, b < 256) ∧ (∀ b ∈ f.value, b < 256) ∧
  f.name.length ≤ maxString ∧ f.value.length ≤ maxString

/-- What the two ends agree on, given the size the encoder still owes a block. -/
def Owed : Option Nat → Encoder → Decoder → Prop
  | none, enc, dec => enc.dyn = dec.dyn ∧ enc.max = dec.max ∧ dec.required = none
  | some m, enc, dec => m ≤ enc.max ∧ enc.dyn = dec.dyn.evict m ∧ ∀ r, dec.required = some r → m ≤ r

/-- The encoder and the decoder at the other end are in step. -/
structure InStep (enc : Encoder) (dec : Decoder) : Prop where
  settings : enc.settings = dec.settings
  capped : dec.settings ≤ maxTable
  maxOk : enc.max ≤ enc.settings
  encExact : enc.dyn.Exact
  encFits : enc.dyn.size ≤ enc.max
  decExact : dec.dyn.Exact
  owed : Owed enc.pending enc dec

/-! ## Tables -/

theorem dyn_ext (a b : Dyn) (ha : a.Exact) (hb : b.Exact) (h : a.entries = b.entries) : a = b := by
  obtain ⟨ea, sa⟩ := a
  obtain ⟨eb, sb⟩ := b
  simp only [Dyn.Exact] at ha hb h
  subst h
  subst ha
  subst hb
  rfl

theorem evict_evict (d : Dyn) (h : d.Exact) (c1 c2 : Nat) :
    (d.evict c1).evict c2 = d.evict (min c1 c2) := by
  obtain ⟨a1, a2, _⟩ := evict_fit c1 d h
  obtain ⟨b1, b2, _⟩ := evict_fit c2 (d.evict c1) a2
  obtain ⟨c1', c2', _⟩ := evict_fit (min c1 c2) d h
  apply dyn_ext _ _ b2 c2'
  rw [b1, a1, c1', fit_fit]

theorem sumSize_ge (es : List Entry) : 32 * es.length ≤ sumSize es := by
  induction es with
  | nil => simp [sumSize]
  | cons e es ih => simp only [sumSize, List.length_cons]; have := entry_size_pos e; omega

theorem empty_exact : Dyn.empty.Exact := rfl

/-! ## Indexes -/

theorem lookup_all (d : Dyn) (k : Nat) (hk : 1 ≤ k) :
    lookup d k = (staticEntries ++ d.entries)[k - 1]? := by
  unfold lookup
  rw [static_length]
  simp only [show ¬ k = 0 by omega, ite_false]
  split
  · rw [List.getElem?_append_left (by rw [static_length]; omega)]
  · rw [List.getElem?_append_right (by rw [static_length]; omega), static_length]
    congr 1 <;> omega

theorem firstIndex_spec (p : Entry → Bool) (l : List Entry) (i k : Nat)
    (h : firstIndex p l i = k) (hk : k ≠ 0) (hi : 1 ≤ i) :
    i ≤ k ∧ k < i + l.length ∧ ∃ e, l[k - i]? = some e ∧ p e = true := by
  induction l generalizing i with
  | nil => simp [firstIndex] at h; omega
  | cons e es ih =>
    simp only [firstIndex] at h
    split at h
    · next he => subst h; exact ⟨Nat.le_refl _, by simp, e, by simp, he⟩
    · obtain ⟨a, b, e', he', hp⟩ := ih (i + 1) h (by omega)
      refine ⟨by omega, by simp; omega, e', ?_, hp⟩
      rw [show k - i = (k - (i + 1)) + 1 by omega]
      simpa using he'

/-- An index the encoder finds names that entry, and is in range. -/
theorem found (p : Entry → Bool) (d : Dyn) (k : Nat)
    (h : firstIndex p (staticEntries ++ d.entries) 1 = k) (hk : k ≠ 0) :
    1 ≤ k ∧ k ≤ 61 + d.entries.length ∧ ∃ e, lookup d k = some e ∧ p e = true := by
  obtain ⟨a, b, e, he, hp⟩ := firstIndex_spec p _ 1 k h hk (Nat.le_refl _)
  simp only [List.length_append, static_length] at b
  exact ⟨a, by omega, e, by rw [lookup_all d k a]; exact he, hp⟩

/-! ## The fields of a block -/

/-- A table the encoder holds: sizes exact, within a maximum within `maxTable`. -/
def Holds (d : Dyn) (max : Nat) : Prop := d.Exact ∧ d.size ≤ max ∧ max ≤ maxTable

theorem holds_entries (d : Dyn) (max : Nat) (h : Holds d max) : d.entries.length ≤ 2048 := by
  obtain ⟨hx, hs, hm⟩ := h
  have := sumSize_ge d.entries
  unfold Dyn.Exact at hx
  unfold maxTable at hm
  omega

/-- The policy's Huffman strings, within `maxString` decoded, are within it coded. -/
def Policy.Wf (pol : Policy) : Prop :=
  ∀ s : Bytes, s.length ≤ maxString → pol.huff s = true → (encode s).length ≤ maxString

theorem lit_wf (pol : Policy) (hp : pol.Wf) (s : Bytes) (hb : ∀ b ∈ s, b < 256)
    (hl : s.length ≤ maxString) : (pol.lit s).Wf :=
  ⟨hb, hl, fun h => hp s hl h⟩

theorem chooseIx_never (pol : Policy) (max : Nat) (f : Field) :
    decide (chooseIx pol max f = .never) = f.never := by
  unfold chooseIx
  cases f.never
  · simp only [Bool.false_eq_true, ite_false]; split <;> rfl
  · rfl

/-- The name the encoder writes is a well-formed reference or string, and the
decoder resolves it to the field's name. -/
theorem chooseName_ok (pol : Policy) (hp : pol.Wf) (d : Dyn) (hd : d.entries.length ≤ 2048)
    (f : Field) (hf : f.Wf) (ix : Indexing) :
    (WRep.literal (chooseName pol d f) (pol.lit f.value) ix).Wf ∧
      resolveName d (chooseName pol d f).toName = some f.name := by
  obtain ⟨fb1, fb2, fl1, fl2⟩ := hf
  unfold chooseName
  split
  · next h =>
    obtain ⟨k1, k2, e, he, hpe⟩ := found _ d (nameIndex d f) rfl h.2
    simp only [beq_iff_eq] at hpe
    refine ⟨⟨by omega, by unfold intBound; omega, lit_wf pol hp _ fb2 fl2⟩, ?_⟩
    show (lookup d (nameIndex d f)).map (·.name) = some f.name
    rw [he]
    simp [hpe]
  · exact ⟨⟨lit_wf pol hp _ fb1 fl1, lit_wf pol hp _ fb2 fl2⟩, rfl⟩


@[simp] theorem Policy.lit_s (pol : Policy) (s : Bytes) : (pol.lit s).s = s := rfl

/-- One field: the representation the encoder chooses is well formed and no
size update, and a decoder whose table is the encoder's, owing nothing, reads
it as the field and changes its table as the encoder does. -/
theorem chooseRep_apply (pol : Policy) (hp : pol.Wf) (max : Nat) (d : Dyn) (hd : Holds d max)
    (f : Field) (hf : f.Wf) (st : St)
    (hdyn : st.dec.dyn = d) (hmax : st.dec.max = max) (hreq : st.dec.required = none) :
    (chooseRep pol max d f).Wf ∧ (chooseRep pol max d f).isUpdate = false ∧
      applyRep st (chooseRep pol max d f).rep = .ok { st with
        out := f :: st.out
        dec := { st.dec with
          dyn := if (chooseRep pol max d f).adds then d.insert max ⟨f.name, f.value⟩ else d } } := by
  have hn := holds_entries d max hd
  obtain ⟨⟨dd, dm, ds, dr⟩, su, sp, so⟩ := st
  simp only at hdyn hmax hreq
  subst dd dm dr
  unfold chooseRep
  split
  · next hix =>
    simp only [Bool.not_eq_true'] at hix
    obtain ⟨_, hnev, hne⟩ := hix
    obtain ⟨k1, k2, e, he, hpe⟩ := found _ d (exactIndex d f) rfl hne
    simp only [Bool.and_eq_true, beq_iff_eq] at hpe
    have hfe : (⟨e.name, e.value, false⟩ : Field) = f := by
      obtain ⟨fn, fv, fnev⟩ := f
      simp only at hpe hnev
      rw [hpe.1, hpe.2, hnev]
    refine ⟨⟨by omega, by unfold intBound; omega⟩, rfl, ?_⟩
    simp only [WRep.rep, applyRep, Option.isSome_none, Bool.false_eq_true, ite_false]
    rw [show lookup d (exactIndex d f) = some e from he]
    simp only [WRep.adds, Bool.false_eq_true, ite_false, hfe]
  · obtain ⟨hw, hres⟩ := chooseName_ok pol hp d hn f hf (chooseIx pol max f)
    refine ⟨hw, rfl, ?_⟩
    simp only [WRep.rep, applyRep, Option.isSome_none, Bool.false_eq_true, ite_false,
      Policy.lit_s, hres, chooseIx_never]
    by_cases hinc : chooseIx pol max f = .incremental
    · have hadds : (WRep.literal (chooseName pol d f) (pol.lit f.value) (chooseIx pol max f)).adds
          = true := by rw [hinc]; rfl
      simp only [hadds, ite_true]
      simp only [hinc, ite_true]
    · have hadds : (WRep.literal (chooseName pol d f) (pol.lit f.value) (chooseIx pol max f)).adds
          = false := by
        unfold WRep.adds
        split
        · next h => exact absurd (by injection h) hinc
        · rfl
      simp only [hadds, Bool.false_eq_true, ite_false]
      simp only [hinc, ite_false]

/-- All the fields of a block, one after another. -/
theorem chooseAll_apply (pol : Policy) (hp : pol.Wf) (max : Nat) (fs : List Field)
    (hfs : ∀ f ∈ fs, f.Wf) (d : Dyn) (hd : Holds d max) (st : St)
    (hdyn : st.dec.dyn = d) (hmax : st.dec.max = max) (hreq : st.dec.required = none) :
    (∀ w ∈ (chooseAll pol max d fs).1, w.Wf ∧ w.isUpdate = false) ∧
    Holds (chooseAll pol max d fs).2 max ∧
    ∃ st', applyAll st ((chooseAll pol max d fs).1.map WRep.rep) = .ok st' ∧
      st'.dec = { st.dec with dyn := (chooseAll pol max d fs).2 } ∧
      st'.out = fs.reverse ++ st.out := by
  induction fs generalizing d st with
  | nil =>
    refine ⟨by simp [chooseAll], hd, st, by simp [chooseAll, applyAll], ?_, by simp⟩
    cases h : st.dec; simp only [h] at hdyn; simp [chooseAll, hdyn]
  | cons f fs ih =>
    obtain ⟨w1, w2, h1⟩ := chooseRep_apply pol hp max d hd f (hfs f (by simp)) st hdyn hmax hreq
    let d1 := if (chooseRep pol max d f).adds then d.insert max ⟨f.name, f.value⟩ else d
    have hd1 : Holds d1 max := by
      simp only [d1]
      split
      · obtain ⟨e1, e2⟩ := insert_exact max _ d hd.1
        exact ⟨e1, e2, hd.2.2⟩
      · exact hd
    obtain ⟨r1, r2, st2, h2, d2, o2⟩ :=
      ih (fun g hg => hfs g (by simp [hg])) d1 hd1
        { st with out := f :: st.out, dec := { st.dec with dyn := d1 } } rfl hmax hreq
    refine ⟨?_, r2, st2, ?_, ?_, ?_⟩
    · intro w hw
      simp only [chooseAll, List.mem_cons] at hw
      rcases hw with rfl | hw
      · exact ⟨w1, w2⟩
      · exact r1 w hw
    · simp only [chooseAll, List.map_cons, applyAll, h1]
      exact h2
    · rw [d2]; rfl
    · rw [o2]; simp

/-! ## Settings and capacities -/

theorem setSettings_lt (enc : Encoder) (l : Nat) (h : min l maxTable < enc.max) :
    enc.setSettings l = { enc with
      settings := min l maxTable
      pending := some (match enc.pending with | none => min l maxTable | some m => min m (min l maxTable))
      max := min l maxTable
      dyn := enc.dyn.evict (min l maxTable) } := by
  simp only [Encoder.setSettings, Encoder.resize, h, ite_true]
  rfl

theorem setSettings_ge (enc : Encoder) (l : Nat) (h : ¬ min l maxTable < enc.max) :
    enc.setSettings l = { enc with settings := min l maxTable } := by
  simp [Encoder.setSettings, h]

/-! ## Headline theorems -/

/-- A new encoder and a new decoder with the same settings limit are in step. -/
theorem inStep_new (l : Nat) : InStep (Encoder.new l) (Decoder.new l) := by
  unfold Encoder.new Decoder.new
  by_cases h : min l maxTable < 4096
  · rw [setSettings_lt _ _ h]
    have fits := (evict_fit (min l maxTable) Dyn.empty empty_exact).2
    refine ⟨rfl, Nat.min_le_right _ _, Nat.le_refl _, fits.1, fits.2, empty_exact, ?_⟩
    simp only [Owed]
    refine ⟨Nat.le_refl _, by first | rfl | trivial, ?_⟩
    intro r hr
    simp only [h, ite_true, Option.some.injEq] at hr
    omega
  · rw [setSettings_ge _ _ h]
    refine ⟨rfl, Nat.min_le_right _ _, by simp only; omega, empty_exact, by simp [Dyn.empty],
      empty_exact, ?_⟩
    simp only [Owed, h, ite_false]
    exact ⟨by first | rfl | trivial, by first | rfl | trivial, by first | rfl | trivial⟩

/-- A SETTINGS_HEADER_TABLE_SIZE applied by the encoder on arrival and by the
decoder on its acknowledgment keeps them in step. -/
theorem inStep_settings (enc : Encoder) (dec : Decoder) (l : Nat) (h : InStep enc dec) :
    InStep (enc.setSettings l) (dec.ack l) := by
  obtain ⟨hs, hc, hm, hx, hf, hdx, ho⟩ := h
  have hl : min l maxTable ≤ maxTable := Nat.min_le_right _ _
  by_cases hlt : min l maxTable < enc.max
  · rw [setSettings_lt _ _ hlt]
    have fits := (evict_fit (min l maxTable) enc.dyn hx).2
    refine ⟨rfl, hl, Nat.le_refl _, fits.1, fits.2, hdx, ?_⟩
    cases hp : enc.pending with
    | none =>
      rw [hp] at ho
      obtain ⟨o1, o2, o3⟩ := ho
      simp only [Owed, Decoder.ack, ← o2, hlt, ite_true, o3, ← o1]
      exact ⟨Nat.le_refl _, by first | rfl | trivial, fun r hr => by simp at hr; omega⟩
    | some m =>
      rw [hp] at ho
      obtain ⟨o1, o2, o3⟩ := ho
      simp only [Owed, Decoder.ack]
      refine ⟨Nat.min_le_right _ _, by rw [o2, evict_evict _ hdx], ?_⟩
      intro r hr
      split at hr
      · cases hq : dec.required with
        | none => rw [hq] at hr; simp at hr; omega
        | some r0 => have := o3 r0 hq; rw [hq] at hr; simp at hr; omega
      · have := o3 r hr; omega
  · rw [setSettings_ge _ _ hlt]
    refine ⟨rfl, hl, by simp only; omega, hx, hf, hdx, ?_⟩
    cases hp : enc.pending with
    | none =>
      rw [hp] at ho
      obtain ⟨o1, o2, o3⟩ := ho
      simp only [Owed, Decoder.ack, ← o2, hlt, ite_false, o3]
      exact ⟨o1, by first | rfl | trivial, by first | rfl | trivial⟩
    | some m =>
      rw [hp] at ho
      obtain ⟨o1, o2, o3⟩ := ho
      simp only [Owed, Decoder.ack]
      refine ⟨o1, o2, ?_⟩
      intro r hr
      split at hr
      · cases hq : dec.required with
        | none => rw [hq] at hr; simp at hr; omega
        | some r0 => have := o3 r0 hq; rw [hq] at hr; simp at hr; omega
      · exact o3 r hr

/-- A maximum the encoder chooses within the settings limit keeps them in step. -/
theorem inStep_capacity (enc enc' : Encoder) (dec : Decoder) (c : Nat) (h : InStep enc dec)
    (hc : enc.setCapacity c = some enc') : InStep enc' dec := by
  obtain ⟨hs, hcap, hm, hx, hf, hdx, ho⟩ := h
  unfold Encoder.setCapacity at hc
  split at hc
  · cases hc
  · next hle =>
    simp only [Option.some.injEq] at hc
    subst hc
    have fits := (evict_fit c enc.dyn hx).2
    refine ⟨hs, hcap, by simp only [Encoder.resize]; omega, fits.1, fits.2, hdx, ?_⟩
    simp only [Encoder.resize]
    cases hp : enc.pending with
    | none =>
      rw [hp] at ho
      obtain ⟨o1, o2, o3⟩ := ho
      simp only [Owed]
      exact ⟨Nat.le_refl _, by rw [o1], by simp [o3]⟩
    | some m =>
      rw [hp] at ho
      obtain ⟨o1, o2, o3⟩ := ho
      simp only [Owed]
      refine ⟨Nat.min_le_right _ _, by rw [o2, evict_evict _ hdx], ?_⟩
      intro r hr
      have := o3 r hr
      omega

theorem ordered_block (ups cs : List WRep) (hu : ∀ w ∈ ups, w.isUpdate = true)
    (hc : ∀ w ∈ cs, w.isUpdate = false) : Ordered false (ups ++ cs) := by
  have fields : ∀ (s : Bool) (cs : List WRep), (∀ w ∈ cs, w.isUpdate = false) → Ordered s cs := by
    intro s cs hc
    induction cs generalizing s with
    | nil => trivial
    | cons w ws ih => exact ⟨fun _ => hc w (by simp), ih _ (fun x hx => hc x (by simp [hx]))⟩
  induction ups with
  | nil => exact fields false cs hc
  | cons w ws ih =>
    refine ⟨by simp, ?_⟩
    simp only [hu w (by simp), Bool.not_true, Bool.or_false]
    exact ih (fun x hx => hu x (by simp [hx]))

theorem applyAll_append (st st1 : St) (a b : List Rep) (h : applyAll st a = .ok st1) :
    applyAll st (a ++ b) = applyAll st1 b := by
  induction a generalizing st with
  | nil => simp [applyAll] at h; subst h; rfl
  | cons r rs ih =>
    simp only [applyAll, List.cons_append] at h ⊢
    split at h
    · cases h
    · next st' h' => exact ih st' h

/-- The size updates an encoder starts a block with take the decoder to the
encoder's table and maximum, owing nothing. -/
theorem updates_apply (enc : Encoder) (dec : Decoder) (h : InStep enc dec) :
    (∀ w ∈ enc.updates, w.isUpdate = true ∧ w.Wf) ∧
    ∃ st, applyAll (St.start dec) (enc.updates.map WRep.rep) = .ok st ∧
      st.dec = { dyn := enc.dyn, max := enc.max, settings := dec.settings, required := none } ∧
      st.out = [] := by
  obtain ⟨hs, hcap, hm, hx, hf, hdx, ho⟩ := h
  have hmt : maxTable < intBound := by decide
  unfold Encoder.updates
  cases hpen : enc.pending with
  | none =>
    rw [hpen] at ho
    obtain ⟨o1, o2, o3⟩ := ho
    refine ⟨by simp, St.start dec, by simp [applyAll], ?_, rfl⟩
    cases dec
    simp only [St.start] at o1 o2 o3 ⊢
    rw [o1, o2, o3]
  | some m =>
    rw [hpen] at ho
    dsimp only
    obtain ⟨o1, o2, o3⟩ := ho
    have nreq : overOwed dec.required m = false := by
      cases hq : dec.required with
      | none => rfl
      | some r => have := o3 r hq; simp [overOwed]; omega
    have first : applyRep (St.start dec) (.update m) = .ok
        ⟨{ dec with required := none, max := m, dyn := dec.dyn.evict m }, 1, m, []⟩ := by
      simp only [applyRep, St.start, nreq, Bool.false_eq_true, ite_false]
      rw [if_neg (by omega), if_neg (by omega)]
    split
    · next heq =>
      refine ⟨?_, ⟨{ dec with required := none, max := m, dyn := dec.dyn.evict m }, 1, m, []⟩,
        by simp only [List.map_cons, List.map_nil, WRep.rep, applyAll, first], ?_, rfl⟩
      · intro w hw
        simp only [List.mem_singleton] at hw
        subst hw
        exact ⟨rfl, by simp only [WRep.Wf]; omega⟩
      · subst heq
        rw [o2]
    · next hne =>
      have second : applyRep ⟨{ dec with required := none, max := m, dyn := dec.dyn.evict m }, 1, m, []⟩
          (.update enc.max) = .ok
          ⟨{ dec with required := none, max := enc.max, dyn := (dec.dyn.evict m).evict enc.max },
            2, enc.max, []⟩ := by
        simp only [applyRep, overOwed, Bool.false_eq_true, ite_false]
        rw [if_neg (by omega), if_neg (by omega)]
      refine ⟨?_, ⟨{ dec with required := none, max := enc.max, dyn := (dec.dyn.evict m).evict enc.max }, 2, enc.max, []⟩,
        by simp only [List.map_cons, List.map_nil, WRep.rep, applyAll, first, second], ?_, rfl⟩
      · intro w hw
        simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false] at hw
        rcases hw with rfl | rfl
        · exact ⟨rfl, by simp only [WRep.Wf]; omega⟩
        · exact ⟨rfl, by simp only [WRep.Wf]; omega⟩
      · show ({ dec with required := none, max := enc.max, dyn := (dec.dyn.evict m).evict enc.max } : Decoder) = _
        rw [evict_evict _ hdx, Nat.min_eq_left o1, ← o2]

/-- Sections 2.2, 4.2 and 6 together: from an encoder and a decoder in step, any
block the encoder writes, for any policy whose Huffman strings fit `maxString`,
decodes to exactly the fields it was given, in order and with their
never-indexed flags, and leaves the two in step with nothing owed. -/
theorem block_round_trip (enc : Encoder) (dec : Decoder) (pol : Policy) (fs : List Field)
    (h : InStep enc dec) (hp : pol.Wf) (hfs : ∀ f ∈ fs, f.Wf)
    (hlen : (writeBlock (enc.block pol fs).1).length ≤ maxBlock) :
    ∃ dec', decodeBlock dec (writeBlock (enc.block pol fs).1) = .ok (fs, dec') ∧
      InStep (enc.block pol fs).2 dec' ∧ (enc.block pol fs).2.pending = none := by
  obtain ⟨hu, st2, hst2, hd2, ho2⟩ := updates_apply enc dec h
  obtain ⟨hs, hcap, hm, hx, hf, hdx, _⟩ := h
  have hold : Holds enc.dyn enc.max := ⟨hx, hf, by omega⟩
  obtain ⟨cw, chold, st3, hst3, hd3, ho3⟩ :=
    chooseAll_apply pol hp enc.max fs hfs enc.dyn hold st2 (by rw [hd2]) (by rw [hd2]) (by rw [hd2])
  have hparse := parse_write false (enc.updates ++ (chooseAll pol enc.max enc.dyn fs).1)
    (by
      intro w hw
      rcases List.mem_append.mp hw with hw | hw
      · exact (hu w hw).2
      · exact (cw w hw).1)
    (ordered_block _ _ (fun w hw => (hu w hw).1) (fun w hw => (cw w hw).2))
  refine ⟨st3.dec, ?_, ?_, rfl⟩
  · simp only [Encoder.block] at hlen ⊢
    rw [decodeBlock_ok_iff]
    unfold decodeParsed
    rw [if_neg (by omega), hparse]
    simp only [List.map_append]
    rw [applyAll_append _ _ _ _ hst2, hst3]
    simp only [hd3, hd2, Option.isSome_none, Bool.false_eq_true, ite_false, ho3, ho2,
      List.append_nil, List.reverse_reverse]
  · simp only [Encoder.block]
    rw [hd3, hd2]
    exact ⟨hs, hcap, hm, chold.1, chold.2.1, chold.1, ⟨rfl, rfl, rfl⟩⟩

/-- The choice Rust's encoder makes satisfies the policy's condition: it codes a
string with Huffman only when that is shorter. -/
theorem rustPolicy_wf (huffman : Bool) : (rustPolicy huffman).Wf := by
  intro s hl hh
  simp only [rustPolicy, Bool.and_eq_true, decide_eq_true_eq] at hh
  omega

end Hpack
