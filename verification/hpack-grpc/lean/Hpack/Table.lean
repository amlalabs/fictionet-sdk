import Hpack.Int

/-!
# The tables (RFC 7541 sections 2.3 and 4)

`staticTable` is Appendix A, taken from the RFC text. A dynamic table keeps
its entries newest first with its size beside them, as `DynamicTable` in
Rust does. `Dyn.insert` adds an entry first and then evicts the oldest
entries until the size fits, the order the Rust code uses; `rfcInsert` is
section 4.4's order (evict to make room, then add, or empty the table for
an entry larger than the capacity), and `insert_is_rfc` proves the two the
same. `lookup` is section 2.3.3's index space.
-/

namespace Hpack


/-- RFC 7541 Appendix A, in index order from 1. -/
def staticTable : List (String × String) := [
  (":authority", ""), -- 1
  (":method", "GET"), -- 2
  (":method", "POST"), -- 3
  (":path", "/"), -- 4
  (":path", "/index.html"), -- 5
  (":scheme", "http"), -- 6
  (":scheme", "https"), -- 7
  (":status", "200"), -- 8
  (":status", "204"), -- 9
  (":status", "206"), -- 10
  (":status", "304"), -- 11
  (":status", "400"), -- 12
  (":status", "404"), -- 13
  (":status", "500"), -- 14
  ("accept-charset", ""), -- 15
  ("accept-encoding", "gzip, deflate"), -- 16
  ("accept-language", ""), -- 17
  ("accept-ranges", ""), -- 18
  ("accept", ""), -- 19
  ("access-control-allow-origin", ""), -- 20
  ("age", ""), -- 21
  ("allow", ""), -- 22
  ("authorization", ""), -- 23
  ("cache-control", ""), -- 24
  ("content-disposition", ""), -- 25
  ("content-encoding", ""), -- 26
  ("content-language", ""), -- 27
  ("content-length", ""), -- 28
  ("content-location", ""), -- 29
  ("content-range", ""), -- 30
  ("content-type", ""), -- 31
  ("cookie", ""), -- 32
  ("date", ""), -- 33
  ("etag", ""), -- 34
  ("expect", ""), -- 35
  ("expires", ""), -- 36
  ("from", ""), -- 37
  ("host", ""), -- 38
  ("if-match", ""), -- 39
  ("if-modified-since", ""), -- 40
  ("if-none-match", ""), -- 41
  ("if-range", ""), -- 42
  ("if-unmodified-since", ""), -- 43
  ("last-modified", ""), -- 44
  ("link", ""), -- 45
  ("location", ""), -- 46
  ("max-forwards", ""), -- 47
  ("proxy-authenticate", ""), -- 48
  ("proxy-authorization", ""), -- 49
  ("range", ""), -- 50
  ("referer", ""), -- 51
  ("refresh", ""), -- 52
  ("retry-after", ""), -- 53
  ("server", ""), -- 54
  ("set-cookie", ""), -- 55
  ("strict-transport-security", ""), -- 56
  ("transfer-encoding", ""), -- 57
  ("user-agent", ""), -- 58
  ("vary", ""), -- 59
  ("via", ""), -- 60
  ("www-authenticate", "") -- 61
]

/-- A header field's name and value, as octets. -/
structure Entry where
  name : Bytes
  value : Bytes
  deriving DecidableEq, Repr

/-- Section 4.1: an entry's size is its name, its value, and 32 octets. -/
def Entry.size (e : Entry) : Nat := e.name.length + e.value.length + 32

/-- The sizes of entries, summed. -/
def sumSize : List Entry → Nat
  | [] => 0
  | e :: es => e.size + sumSize es

/-- The text's octets. -/
def octets (s : String) : Bytes := s.toUTF8.toList.map (·.toNat)

/-- Appendix A as entries. -/
def staticEntries : List Entry := staticTable.map (fun (n, v) => ⟨octets n, octets v⟩)

/-- A dynamic table: entries newest first, and their size, kept beside them. -/
structure Dyn where
  entries : List Entry
  size : Nat
  deriving DecidableEq, Repr

def Dyn.empty : Dyn := ⟨[], 0⟩

/-- The kept size is the exact sum of the entries' sizes. -/
def Dyn.Exact (d : Dyn) : Prop := d.size = sumSize d.entries

/-- Section 4.4's eviction: the oldest entry goes while the size is over `cap`. -/
def Dyn.evict (cap : Nat) (d : Dyn) : Dyn :=
  if d.size ≤ cap then d
  else if h : d.entries = [] then d
  else Dyn.evict cap ⟨d.entries.dropLast, d.size - (d.entries.getLast h).size⟩
termination_by d.entries.length
decreasing_by
  simp only [List.length_dropLast]
  have := List.length_pos_iff.mpr h
  omega

/-- Adding an entry, as Rust does it: first, then evict to the capacity. -/
def Dyn.insert (cap : Nat) (e : Entry) (d : Dyn) : Dyn :=
  Dyn.evict cap ⟨e :: d.entries, d.size + e.size⟩

/-- Section 4.4's order: an entry larger than the capacity empties the table;
otherwise the oldest entries go until it fits, and then it is added. -/
def rfcInsert (cap : Nat) (e : Entry) (d : Dyn) : Dyn :=
  if cap < e.size then Dyn.empty
  else
    let d' := d.evict (cap - e.size)
    ⟨e :: d'.entries, d'.size + e.size⟩

/-- The newest entries that fit `cap` together. -/
def fit (cap : Nat) : List Entry → List Entry
  | [] => []
  | e :: es => if e.size ≤ cap then e :: fit (cap - e.size) es else []

/-- Section 2.3.3: index 0 is no entry, 1 to 61 the static table, and from 62 the
dynamic table, newest first. -/
def lookup (d : Dyn) (i : Nat) : Option Entry :=
  if i = 0 then none
  else if i ≤ staticEntries.length then staticEntries[i - 1]?
  else d.entries[i - staticEntries.length - 1]?

/-! ## Sums and fitting -/

theorem sumSize_append (a b : List Entry) : sumSize (a ++ b) = sumSize a + sumSize b := by
  induction a with
  | nil => simp [sumSize]
  | cons e a ih => simp [sumSize, ih]; omega

theorem entry_size_pos (e : Entry) : 32 ≤ e.size := by unfold Entry.size; omega

theorem fit_sum (cap : Nat) (es : List Entry) : sumSize (fit cap es) ≤ cap := by
  induction es generalizing cap with
  | nil => simp [fit, sumSize]
  | cons e es ih =>
    simp only [fit]
    split
    · simp only [sumSize]; have := ih (cap - e.size); omega
    · simp [sumSize]

theorem fit_prefix (cap : Nat) (es : List Entry) : fit cap es <+: es := by
  induction es generalizing cap with
  | nil => simp [fit]
  | cons e es ih =>
    simp only [fit]
    split
    · exact List.cons_prefix_cons.mpr ⟨rfl, ih _⟩
    · exact List.nil_prefix

theorem fit_self (cap : Nat) (es : List Entry) (h : sumSize es ≤ cap) : fit cap es = es := by
  induction es generalizing cap with
  | nil => rfl
  | cons e es ih =>
    simp only [sumSize] at h
    simp only [fit, show e.size ≤ cap by omega, ite_true, ih (cap - e.size) (by omega)]

theorem fit_dropLast (cap : Nat) (es : List Entry) (h : cap < sumSize es) :
    fit cap es = fit cap es.dropLast := by
  induction es generalizing cap with
  | nil => simp [sumSize] at h
  | cons e rest ih =>
    simp only [sumSize] at h
    cases rest with
    | nil =>
      simp only [sumSize] at h
      simp [fit, show ¬ e.size ≤ cap by omega]
    | cons f rest' =>
      rw [List.dropLast_cons_of_ne_nil (by simp)]
      conv => lhs; rw [fit]
      conv => rhs; rw [fit]
      split
      · rw [ih (cap - e.size) (by omega)]
      · rfl

/-- Eviction removes the fewest oldest entries: every longer run of the newest
entries is over the capacity. -/
theorem fit_longest (cap : Nat) (es : List Entry) (k : Nat) (h : sumSize (es.take k) ≤ cap) :
    min k es.length ≤ (fit cap es).length := by
  induction es generalizing cap k with
  | nil => simp
  | cons e es ih =>
    cases k with
    | zero => simp
    | succ k =>
      simp only [List.take_succ_cons, sumSize] at h
      simp only [fit, show e.size ≤ cap by omega, ite_true, List.length_cons]
      have := ih (cap - e.size) k (by omega)
      omega

theorem fit_fit (c1 c2 : Nat) (es : List Entry) : fit c2 (fit c1 es) = fit (min c1 c2) es := by
  induction es generalizing c1 c2 with
  | nil => rfl
  | cons e es ih =>
    simp only [fit]
    by_cases h1 : e.size ≤ c1
    · simp only [h1, ite_true, fit]
      by_cases h2 : e.size ≤ c2
      · simp only [h2, ite_true, show e.size ≤ min c1 c2 by omega, ih]
        congr 2; omega
      · simp [h2, show ¬ e.size ≤ min c1 c2 by omega]
    · simp [h1, fit, show ¬ e.size ≤ min c1 c2 by omega]

/-! ## Eviction and insertion -/

/-- Eviction keeps exactly the newest entries that fit, and the size stays the
exact sum, within the capacity. -/
theorem evict_fit (cap : Nat) (d : Dyn) (h : d.Exact) :
    (d.evict cap).entries = fit cap d.entries ∧ (d.evict cap).Exact ∧ (d.evict cap).size ≤ cap := by
  induction d using Dyn.evict.induct cap with
  | case1 d hle =>
    rw [Dyn.evict, if_pos hle]
    unfold Dyn.Exact at h
    exact ⟨(fit_self cap _ (by omega)).symm, h, hle⟩
  | case2 d hle he =>
    unfold Dyn.Exact at h
    rw [he] at h
    simp [sumSize] at h
    omega
  | case3 d hle he ih =>
    rw [Dyn.evict, if_neg hle, dif_neg he]
    have hsplit := List.dropLast_concat_getLast he
    unfold Dyn.Exact at h
    have hs : d.size = sumSize d.entries.dropLast + (d.entries.getLast he).size := by
      conv => lhs; rw [h, ← hsplit]
      rw [sumSize_append]; simp [sumSize]
    obtain ⟨e1, e2, e3⟩ := ih (by unfold Dyn.Exact; simp only; omega)
    refine ⟨?_, e2, e3⟩
    rw [e1, fit_dropLast cap d.entries (by omega)]

theorem insert_fit (cap : Nat) (e : Entry) (d : Dyn) (h : d.Exact) :
    (d.insert cap e).entries = fit cap (e :: d.entries) ∧ (d.insert cap e).Exact ∧
      (d.insert cap e).size ≤ cap := by
  unfold Dyn.insert
  apply evict_fit
  unfold Dyn.Exact at h ⊢
  simp only [sumSize]; omega

/-! ## Headline theorems -/

/-- Inserting first and then evicting, as Rust does, is section 4.4's insertion. -/
theorem insert_is_rfc (cap : Nat) (e : Entry) (d : Dyn) (h : d.Exact) :
    d.insert cap e = rfcInsert cap e d := by
  obtain ⟨i1, i2, _⟩ := insert_fit cap e d h
  unfold rfcInsert
  split
  · next hc =>
    have : (d.insert cap e).entries = [] := by rw [i1]; simp [fit, show ¬ e.size ≤ cap by omega]
    cases hd : d.insert cap e with
    | mk es sz =>
      rw [hd] at this i2
      simp only at this
      subst this
      unfold Dyn.Exact at i2
      simp only [sumSize] at i2
      simp [Dyn.empty, i2]
  · next hc =>
    obtain ⟨v1, v2, _⟩ := evict_fit (cap - e.size) d h
    cases hd : d.insert cap e with
    | mk es sz =>
      rw [hd] at i1 i2
      simp only at i1
      unfold Dyn.Exact at i2 v2
      simp only at i2
      rw [i1]
      simp only [fit, show e.size ≤ cap by omega, ite_true, Dyn.mk.injEq, true_and, ← v1]
      rw [i2, i1]
      simp only [sumSize, fit, show e.size ≤ cap by omega, ite_true, ← v1, ← v2]
      omega

/-- After any insertion the size is the exact sum of the entries, within the capacity. -/
theorem insert_exact (cap : Nat) (e : Entry) (d : Dyn) (h : d.Exact) :
    (d.insert cap e).Exact ∧ (d.insert cap e).size ≤ cap :=
  ⟨(insert_fit cap e d h).2.1, (insert_fit cap e d h).2.2⟩

/-- An entry that fits is first after it is added; the entries after it are the
newest of the old ones that fit beside it, so only the oldest were evicted. -/
theorem insert_first (cap : Nat) (e : Entry) (d : Dyn) (h : d.Exact) (hc : e.size ≤ cap) :
    (d.insert cap e).entries = e :: fit (cap - e.size) d.entries := by
  rw [(insert_fit cap e d h).1]
  simp [fit, hc]

/-- Section 4.4: an entry larger than the capacity empties the table and is not added. -/
theorem insert_oversized (cap : Nat) (e : Entry) (d : Dyn) (h : d.Exact) (hc : cap < e.size) :
    d.insert cap e = Dyn.empty := by
  rw [insert_is_rfc cap e d h]
  simp [rfcInsert, hc]

/-- The static table has Appendix A's 61 entries. -/
theorem static_length : staticEntries.length = 61 := by decide

/-- Index 0 and every index past both tables name nothing; every index from 1 to
the end of the dynamic table names an entry. -/
theorem lookup_some (d : Dyn) (i : Nat) :
    (lookup d i).isSome ↔ 1 ≤ i ∧ i ≤ 61 + d.entries.length := by
  unfold lookup
  rw [static_length]
  by_cases h0 : i = 0
  · simp [h0]
  · simp only [h0, ite_false]
    by_cases hs : i ≤ 61
    · simp only [hs, ite_true, Option.isSome_iff_ne_none, ne_eq,
        List.getElem?_eq_none_iff, static_length]
      omega
    · simp only [hs, ite_false, Option.isSome_iff_ne_none, ne_eq, List.getElem?_eq_none_iff]
      omega

/-- After an insertion that fits, index 62 is the new entry, and each older entry
kept moves up one index. -/
theorem lookup_insert (cap : Nat) (e : Entry) (d : Dyn) (h : d.Exact) (hc : e.size ≤ cap)
    (k : Nat) :
    lookup (d.insert cap e) 62 = some e ∧
    lookup (d.insert cap e) (63 + k) =
      if k < (fit (cap - e.size) d.entries).length then lookup d (62 + k) else none := by
  have hf := insert_first cap e d h hc
  unfold lookup
  rw [static_length, hf]
  refine ⟨by simp, ?_⟩
  simp only [show ¬ 63 + k = 0 by omega, show ¬ 63 + k ≤ 61 by omega, ite_false,
    show ¬ 62 + k = 0 by omega, show ¬ 62 + k ≤ 61 by omega,
    show 63 + k - 61 - 1 = k + 1 by omega, show 62 + k - 61 - 1 = k by omega,
    List.getElem?_cons_succ]
  split
  · next hk =>
    have hp := fit_prefix (cap - e.size) d.entries
    rw [List.getElem?_eq_getElem hk]
    obtain ⟨t, ht⟩ := hp
    conv => rhs; rw [← ht]
    rw [List.getElem?_append_left hk, List.getElem?_eq_getElem hk]
  · next hk => simp; omega

end Hpack
