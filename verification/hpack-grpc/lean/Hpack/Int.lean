/-!
# Prefix integers (RFC 7541 section 5.1)

`rfcInt` is the section's decoding with no bound: any value, any length.
`decodeInt` is the same walk with the bound the Rust code (`prefix_int::read`)
has: the value must fit in 64 bits and the integer must end within
`maxBytes` (11) bytes, prefix byte included. `encodeInt` is the section's
encoding, which is the shortest form.

Bytes are natural numbers; theorems that need it say each is below 256.
-/

namespace Hpack

abbrev Bytes := List Nat

/-- The most bytes the Rust decoder reads for one integer, prefix byte included. -/
def maxBytes : Nat := 11

/-- The values the Rust decoder holds: those below 2^64. -/
def intBound : Nat := 2 ^ 64

/-- The all-ones value of a `p`-bit prefix. -/
def mask (p : Nat) : Nat := 2 ^ p - 1

/-- Why an integer could not be read. -/
inductive IntError where
  | truncated
  | overflow
  deriving DecidableEq, Repr

/-- The continuation bytes after a full prefix, with no bound. `i` counts the
continuation bytes read before these, `acc` is the value so far. Gives the
value and the bytes used in all, the prefix byte included. -/
def rfcRest : Nat → Bytes → Nat → Option (Nat × Nat)
  | _, [], _ => none
  | i, b :: rest, acc =>
    let acc := acc + b % 128 * 2 ^ (7 * i)
    if b < 128 then some (acc, i + 2) else rfcRest (i + 1) rest acc

/-- RFC 7541 section 5.1 decoding of a `p`-bit prefix integer, with no bound.
`none` when the input ends inside the integer. -/
def rfcInt (p : Nat) : Bytes → Option (Nat × Nat)
  | [] => none
  | b :: rest =>
    if b % 2 ^ p < mask p then some (b % 2 ^ p, 1) else rfcRest 0 rest (mask p)

/-- `rfcRest` with the Rust bound: at most ten continuation bytes, and the value
below 2^64 after each byte. Ten continuation bytes that all continue are an
overflow before the input is looked at again, as in Rust's loop. -/
def boundedRest : Nat → Bytes → Nat → Except IntError (Nat × Nat)
  | i, [], _ => if 10 ≤ i then .error .overflow else .error .truncated
  | i, b :: rest, acc =>
    if 10 ≤ i then .error .overflow
    else
      let acc := acc + b % 128 * 2 ^ (7 * i)
      if intBound ≤ acc then .error .overflow
      else if b < 128 then .ok (acc, i + 2)
      else boundedRest (i + 1) rest acc

/-- The Rust decoder (`prefix_int::read`) as a model: section 5.1 within 64 bits
and 11 bytes. -/
def decodeInt (p : Nat) : Bytes → Except IntError (Nat × Nat)
  | [] => .error .truncated
  | b :: rest =>
    if b % 2 ^ p < mask p then .ok (b % 2 ^ p, 1) else boundedRest 0 rest (mask p)

/-- The continuation bytes of a value past the prefix, least significant group first. -/
def encodeRest (r : Nat) : Bytes :=
  if r < 128 then [r] else (r % 128 + 128) :: encodeRest (r / 128)
termination_by r
decreasing_by omega

/-- RFC 7541 section 5.1 encoding: `flags` in the bits above the prefix. -/
def encodeInt (p flags v : Nat) : Bytes :=
  if v < mask p then [flags + v] else (flags + mask p) :: encodeRest (v - mask p)

/-! ## Facts about the pieces -/

theorem mask_lt (p : Nat) : mask p < 2 ^ p := by
  unfold mask
  have := Nat.one_le_two_pow (n := p)
  omega

theorem encodeRest_lt (r : Nat) : ∀ b ∈ encodeRest r, b < 256 := by
  induction r using Nat.strongRecOn with
  | _ r ih =>
    rw [encodeRest]
    split
    · simp; omega
    · intro b hb
      simp only [List.mem_cons] at hb
      rcases hb with hb | hb
      · omega
      · exact ih (r / 128) (by omega) b hb

theorem encodeRest_ne_nil (r : Nat) : encodeRest r ≠ [] := by
  rw [encodeRest]; split <;> simp

/-- A value below `128 ^ k` takes at most `k` continuation bytes. -/
theorem encodeRest_length (r k : Nat) (hk : 1 ≤ k) (h : r < 128 ^ k) :
    (encodeRest r).length ≤ k := by
  induction k generalizing r with
  | zero => omega
  | succ k ih =>
    rw [encodeRest]
    split
    · simp only [List.length_cons, List.length_nil]; omega
    · simp only [List.length_cons]
      have hk' : 1 ≤ k := by
        rcases Nat.eq_zero_or_pos k with h0 | h0
        · subst h0; simp at h; omega
        · omega
      have : r / 128 < 128 ^ k := by
        rw [Nat.pow_succ] at h
        exact Nat.div_lt_of_lt_mul (by rw [Nat.mul_comm]; exact h)
      have := ih (r / 128) hk' this
      omega

/-- The continuation bytes read back, within the bound, as the value they carry. -/
theorem boundedRest_encodeRest (r i acc : Nat) (rest : Bytes)
    (hv : acc + r * 2 ^ (7 * i) < intBound)
    (hl : i + (encodeRest r).length ≤ 10) :
    boundedRest i (encodeRest r ++ rest) acc
      = .ok (acc + r * 2 ^ (7 * i), i + 1 + (encodeRest r).length) := by
  induction r using Nat.strongRecOn generalizing i acc with
  | _ r ih =>
    by_cases hr : r < 128
    · have e : encodeRest r = [r] := by rw [encodeRest]; simp [hr]
      rw [e] at hl ⊢
      simp only [List.length_cons, List.length_nil] at hl
      simp only [List.cons_append, List.nil_append, boundedRest]
      have h1 : ¬ 10 ≤ i := by omega
      have h2 : r % 128 = r := Nat.mod_eq_of_lt hr
      simp only [h1, ite_false, h2, hr, ite_true]
      have h3 : ¬ intBound ≤ acc + r * 2 ^ (7 * i) := by omega
      simp [h3]
    · have e : encodeRest r = (r % 128 + 128) :: encodeRest (r / 128) := by
        rw [encodeRest]; simp [hr]
      rw [e] at hl ⊢
      simp only [List.length_cons] at hl
      simp only [List.cons_append, boundedRest]
      have h1 : ¬ 10 ≤ i := by omega
      have hm : (r % 128 + 128) % 128 = r % 128 := by omega
      have hb : ¬ r % 128 + 128 < 128 := by omega
      have split_r : r * 2 ^ (7 * i) = r % 128 * 2 ^ (7 * i) + r / 128 * 2 ^ (7 * (i + 1)) := by
        have e : 2 ^ (7 * (i + 1)) = 128 * 2 ^ (7 * i) := by
          rw [Nat.mul_add, Nat.pow_add, Nat.mul_comm]
        rw [e, ← Nat.mul_assoc, Nat.mul_comm (r / 128) 128, ← Nat.add_mul, Nat.mod_add_div]
      have hacc : ¬ intBound ≤ acc + r % 128 * 2 ^ (7 * i) := by omega
      simp only [h1, ite_false, hm, hacc, hb]
      have := ih (r / 128) (by omega) (i + 1) (acc + r % 128 * 2 ^ (7 * i))
        (by rw [Nat.add_assoc, ← split_r]; exact hv) (by omega)
      rw [this, Nat.add_assoc, ← split_r]
      simp only [List.length_cons]
      congr 2
      omega

/-! ## Headline theorems -/

/-- Section 5.1 round trip: every value below 2^64, behind any prefix width from 1
to 8 and any flags in the bits above the prefix, reads back as itself, using
exactly the bytes written, whatever follows them. -/
theorem decode_encode (p flags v : Nat) (rest : Bytes)
    (hp : 1 ≤ p ∧ p ≤ 8) (hf : flags % 2 ^ p = 0) (hv : v < intBound) :
    decodeInt p (encodeInt p flags v ++ rest) = .ok (v, (encodeInt p flags v).length) := by
  have hm := mask_lt p
  unfold encodeInt
  split
  · next h =>
    simp only [List.cons_append, List.nil_append, decodeInt, List.length_cons, List.length_nil]
    have : (flags + v) % 2 ^ p = v := by
      rw [Nat.add_mod, hf, Nat.zero_add, Nat.mod_mod, Nat.mod_eq_of_lt (by omega)]
    simp [this, h]
  · next h =>
    simp only [List.cons_append, decodeInt, List.length_cons]
    have e : (flags + mask p) % 2 ^ p = mask p := by
      rw [Nat.add_mod, hf, Nat.zero_add, Nat.mod_mod, Nat.mod_eq_of_lt hm]
    simp only [e, Nat.lt_irrefl, ite_false]
    have hlen : (encodeRest (v - mask p)).length ≤ 10 := by
      apply encodeRest_length _ 10 (by omega)
      have : intBound < 128 ^ 10 := by decide
      omega
    rw [boundedRest_encodeRest (v - mask p) 0 (mask p) rest
      (by simp; omega) (by omega)]
    simp only [Nat.mul_zero, Nat.pow_zero, Nat.mul_one]
    congr 2 <;> omega

/-- The encoding fits the Rust bound: at most 11 bytes for every value below 2^64. -/
theorem encode_length (p flags v : Nat) (hp : 1 ≤ p) (hv : v < intBound) :
    (encodeInt p flags v).length ≤ maxBytes := by
  unfold encodeInt maxBytes
  split
  · simp
  · simp only [List.length_cons]
    have : (encodeRest (v - mask p)).length ≤ 10 := by
      apply encodeRest_length _ 10 (by omega)
      have : intBound < 128 ^ 10 := by decide
      omega
    omega

/-- The encoding is bytes, and the first keeps the flags: its bits above the prefix
are exactly `flags`'. -/
theorem encode_bytes (p flags v : Nat) (hp : 1 ≤ p ∧ p ≤ 8)
    (hf : flags % 2 ^ p = 0) (hb : flags < 256) :
    (∀ b ∈ encodeInt p flags v, b < 256) ∧
    ∃ b rest, encodeInt p flags v = b :: rest ∧ b / 2 ^ p = flags / 2 ^ p := by
  have hm := mask_lt p
  have h8 : 2 ^ p ≤ 256 := by
    have := Nat.pow_le_pow_right (n := 2) (by decide) hp.2
    simpa using this
  -- flags is a multiple of 2^p below 256, so flags + x stays below 256 for x < 2^p.
  have hfl : flags + 2 ^ p ≤ 256 := by
    have hd := Nat.div_add_mod flags (2 ^ p)
    rw [hf, Nat.add_zero] at hd
    have hq : flags / 2 ^ p < 256 / 2 ^ p := by
      apply Nat.div_lt_div_of_lt_of_dvd
      · exact Nat.pow_dvd_pow 2 hp.2
      · exact hb
    have e : 256 / 2 ^ p * 2 ^ p = 256 := Nat.div_mul_cancel (Nat.pow_dvd_pow 2 hp.2)
    have : (flags / 2 ^ p + 1) * 2 ^ p ≤ 256 / 2 ^ p * 2 ^ p :=
      Nat.mul_le_mul_right _ hq
    rw [Nat.add_mul, Nat.one_mul, e, Nat.mul_comm, hd] at this
    exact this
  have div_keep : ∀ x, x < 2 ^ p → (flags + x) / 2 ^ p = flags / 2 ^ p := by
    intro x hx
    have hd := Nat.div_add_mod flags (2 ^ p)
    rw [hf, Nat.add_zero] at hd
    rw [← hd, Nat.add_comm, Nat.add_mul_div_left _ _ (Nat.two_pow_pos p),
      Nat.div_eq_of_lt hx, Nat.zero_add, Nat.mul_div_cancel_left _ (Nat.two_pow_pos p)]
  unfold encodeInt
  split
  · next h =>
    refine ⟨by simp; omega, flags + v, [], rfl, div_keep v (by omega)⟩
  · refine ⟨?_, flags + mask p, _, rfl, div_keep _ hm⟩
    intro b hb
    simp only [List.mem_cons] at hb
    rcases hb with hb | hb
    · omega
    · exact encodeRest_lt _ b hb

/-- The flag bits above the prefix never change what is read. -/
theorem decode_ignores_flags (p b f : Nat) (rest : Bytes) (hf : f % 2 ^ p = 0) :
    decodeInt p ((b % 2 ^ p + f) :: rest) = decodeInt p (b :: rest) := by
  have : (b % 2 ^ p + f) % 2 ^ p = b % 2 ^ p := by
    rw [Nat.add_mod, hf, Nat.add_zero, Nat.mod_mod, Nat.mod_mod]
  simp [decodeInt, this]

theorem rfcRest_mono (i : Nat) (bs : Bytes) (acc v n : Nat) (h : rfcRest i bs acc = some (v, n)) :
    acc ≤ v ∧ i + 2 ≤ n := by
  induction bs generalizing i acc with
  | nil => simp [rfcRest] at h
  | cons b rest ih =>
    simp only [rfcRest] at h
    split at h
    · simp at h; omega
    · have := ih (i + 1) _ h; omega

theorem boundedRest_of_rfcRest (i : Nat) (bs : Bytes) (acc v n : Nat)
    (h : rfcRest i bs acc = some (v, n)) :
    boundedRest i bs acc = if v < intBound ∧ n ≤ maxBytes then .ok (v, n) else .error .overflow := by
  induction bs generalizing i acc with
  | nil => simp [rfcRest] at h
  | cons b rest ih =>
    simp only [rfcRest] at h
    simp only [boundedRest]
    have hmb : maxBytes = 11 := rfl
    -- What the walk reaches is at least the value so far, at least this byte on.
    have low : acc + b % 128 * 2 ^ (7 * i) ≤ v ∧ i + 2 ≤ n := by
      split at h
      · simp only [Option.some.injEq, Prod.mk.injEq] at h; omega
      · have := rfcRest_mono _ _ _ _ _ h; omega
    by_cases hi : 10 ≤ i
    · simp only [hi, ite_true]
      rw [if_neg (by omega)]
    · simp only [hi, ite_false]
      by_cases hb : intBound ≤ acc + b % 128 * 2 ^ (7 * i)
      · simp only [hb, ite_true]
        rw [if_neg (by omega)]
      · simp only [hb, ite_false]
        split at h
        · next hlt =>
          simp only [Option.some.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl⟩ := h
          simp only [hlt, ite_true]
          rw [if_pos (by omega)]
        · next hlt =>
          simp only [hlt, ite_false]
          exact ih _ _ h

/-- The Rust bound is exactly where section 5.1 integers are refused: a complete
integer is read as section 5.1 reads it when its value is below 2^64 and it
takes at most 11 bytes, and is an overflow otherwise. -/
theorem decode_complete (p : Nat) (bs : Bytes) (v n : Nat) (hp : p ≤ 8)
    (h : rfcInt p bs = some (v, n)) :
    decodeInt p bs = if v < intBound ∧ n ≤ maxBytes then .ok (v, n) else .error .overflow := by
  cases bs with
  | nil => simp [rfcInt] at h
  | cons b rest =>
    simp only [rfcInt] at h
    simp only [decodeInt]
    split
    · next hlt =>
      simp only [hlt, ite_true, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      have : b % 2 ^ p < intBound := by
        have h1 := Nat.mod_lt b (Nat.two_pow_pos p)
        have h2 : 2 ^ p ≤ 2 ^ 8 := Nat.pow_le_pow_right (by decide) hp
        unfold intBound; omega
      simp [this, maxBytes]
    · next hlt =>
      simp only [hlt, ite_false] at h
      exact boundedRest_of_rfcRest _ _ _ _ _ h

theorem rfcRest_none (i : Nat) (bs : Bytes) (acc : Nat) :
    rfcRest i bs acc = none ↔ ∀ b ∈ bs, 128 ≤ b := by
  induction bs generalizing i acc with
  | nil => simp [rfcRest]
  | cons b rest ih =>
    simp only [rfcRest, List.mem_cons, forall_eq_or_imp]
    split
    · simp; omega
    · rw [ih]; simp; omega

theorem boundedRest_truncated (i : Nat) (bs : Bytes) (acc : Nat)
    (hc : ∀ b ∈ bs, 128 ≤ b) (ha : acc < intBound) :
    (boundedRest i bs acc = .error .truncated ↔ ∃ r, boundedRest i (bs ++ [0]) acc = .ok r) := by
  induction bs generalizing i acc with
  | nil =>
    simp only [boundedRest, List.nil_append]
    by_cases hi : 10 ≤ i
    · simp [hi]
    · have : ¬ intBound ≤ acc := by omega
      simp [hi, this]
  | cons b rest ih =>
    simp only [List.cons_append, boundedRest]
    by_cases hi : 10 ≤ i
    · simp [hi]
    · simp only [hi, ite_false]
      by_cases hb : intBound ≤ acc + b % 128 * 2 ^ (7 * i)
      · simp [hb]
      · have h128 : ¬ b < 128 := by have := hc b (by simp); omega
        simp only [hb, ite_false, h128]
        exact ih (i + 1) _ (fun x hx => hc x (by simp [hx])) (by omega)

/-- Without a byte that ends the integer, the walk never gives a value. -/
theorem boundedRest_no_end (bs : Bytes) (hc : ∀ b ∈ bs, 128 ≤ b) :
    ∀ i acc r, boundedRest i bs acc ≠ .ok r := by
  induction bs with
  | nil => intro i acc r; simp only [boundedRest]; split <;> simp
  | cons x xs ih =>
    intro i acc r
    have hx : ¬ x < 128 := by have := hc x (by simp); omega
    simp only [boundedRest, hx, ite_false]
    split
    · simp
    · split
      · simp
      · exact ih (fun y hy => hc y (List.mem_cons_of_mem x hy)) _ _ r

/-- Input that ends inside an integer is never read as one. It is `truncated`
exactly when one more byte ending the integer would make it one the Rust bound
accepts; past the bound it is an overflow already. -/
theorem decode_truncated (p : Nat) (bs : Bytes) (hp : 1 ≤ p ∧ p ≤ 8)
    (h : rfcInt p bs = none) (hne : bs ≠ []) :
    (∀ r, decodeInt p bs ≠ .ok r) ∧
    (decodeInt p bs = .error .truncated ↔ ∃ r, decodeInt p (bs ++ [0]) = .ok r) := by
  cases bs with
  | nil => exact absurd rfl hne
  | cons b rest =>
    simp only [rfcInt] at h
    split at h
    · simp at h
    · next hlt =>
      have hc := (rfcRest_none _ _ _).1 h
      have hmask : mask p < intBound := by
        have := mask_lt p
        have : 2 ^ p ≤ 2 ^ 8 := Nat.pow_le_pow_right (by decide) hp.2
        unfold intBound; omega
      simp only [decodeInt, List.cons_append, hlt, ite_false]
      exact ⟨fun r => boundedRest_no_end rest hc 0 (mask p) r,
        boundedRest_truncated 0 rest (mask p) hc hmask⟩

end Hpack
