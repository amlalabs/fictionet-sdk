/-!
# Sequence numbers (RFC 9293 section 3.4)

Sequence numbers are 32-bit and every comparison is modulo 2^32. The RFC
writes its tests as chains such as `SND.UNA < SEG.ACK =< SND.NXT` and means
them as offsets from the left end of the chain: `SEG.ACK` lies 1 to
`SND.NXT - SND.UNA` octets past `SND.UNA`. This file defines those offset
tests on `UInt32`, the RFC's four-case acceptability table, and the
signed-distance order smoltcp's `SeqNumber` uses, and proves where they agree:
the offset test is the table read over unbounded integers, across
wraparound; the signed order agrees with the offsets for every window below
2^31 and fails at 2^31, where it leaves two numbers unordered.
-/

namespace TcpRfc

abbrev Seq := UInt32

/-- The size of the sequence space. -/
abbrev M : Nat := 4294967296
/-- Half of it: the distance at which RFC 1982 order is undefined. -/
abbrev H : Nat := 2147483648

/-- How far `b` lies ahead of `a`, modulo 2^32. -/
def dist (a b : Seq) : Nat := (b - a).toNat

/-- `a` advanced by `n` octets. -/
def adv (a : Seq) (n : Nat) : Seq := a + UInt32.ofNat n

/-- `omega` with the two constants unfolded to numerals. -/
macro "seq_omega" : tactic => `(tactic| (try simp only [M, H] at *) <;> omega)

theorem lt_M (a : Seq) : a.toNat < M := UInt32.toNat_lt_size a

theorem dist_eq (a b : Seq) : dist a b = (M - a.toNat + b.toNat) % M := by
  unfold dist; rw [UInt32.toNat_sub]

theorem adv_toNat (a : Seq) (n : Nat) : (adv a n).toNat = (a.toNat + n % M) % M := by
  unfold adv; rw [UInt32.toNat_add, UInt32.toNat_ofNat']

theorem ofNat_toNat' (n : Nat) : (UInt32.ofNat n).toNat = n % M := UInt32.toNat_ofNat'

theorem seq_eq_iff (a b : Seq) : a = b ↔ a.toNat = b.toNat := UInt32.toNat_inj.symm

theorem dist_lt (a b : Seq) : dist a b < M := by
  rw [dist_eq]; exact Nat.mod_lt _ (by decide)

@[simp] theorem dist_self (a : Seq) : dist a a = 0 := by
  rw [dist_eq]; have := lt_M a; seq_omega

theorem dist_zero_iff (a b : Seq) : dist a b = 0 ↔ a = b := by
  rw [dist_eq, seq_eq_iff]; have := lt_M a; have := lt_M b; seq_omega

/-- Advancing by `n` puts the number `n` ahead, modulo 2^32. -/
theorem dist_adv (a : Seq) (n : Nat) : dist a (adv a n) = n % M := by
  rw [dist_eq, adv_toNat]; have := lt_M a; seq_omega

/-- Offsets add along the circle. -/
theorem dist_trans (a b c : Seq) : dist a c = (dist a b + dist b c) % M := by
  simp only [dist_eq]; have := lt_M a; have := lt_M b; have := lt_M c; seq_omega

/-- Going back is the complement of going forward. -/
theorem dist_symm (a b : Seq) (h : a ≠ b) : dist b a = M - dist a b := by
  rw [Ne, seq_eq_iff] at h
  simp only [dist_eq]; have := lt_M a; have := lt_M b; seq_omega

/-! ## The RFC's chains, as offsets -/

/-- `a < b =< c` (RFC 9293 section 3.4), as offsets from `a`. -/
def ltLe (a b c : Seq) : Bool := decide (0 < dist a b ∧ dist a b ≤ dist a c)

/-- `a =< b < c`, as offsets from `a`. -/
def leLt (a b c : Seq) : Bool := decide (dist a b < dist a c)

/-- The four cases of the acceptability test (RFC 9293 section 3.4, table
    6 of section 3.10.7.4), each written as the RFC writes it, with the
    chains read as offsets from `RCV.NXT`. -/
def table (rcvNxt : Seq) (wnd : Nat) (seq : Seq) (len : Nat) : Bool :=
  match len, wnd with
  | 0, 0 => seq == rcvNxt
  | 0, _ + 1 => leLt rcvNxt seq (adv rcvNxt wnd)
  | _ + 1, 0 => false
  | _ + 1, _ + 1 =>
    leLt rcvNxt seq (adv rcvNxt wnd) || leLt rcvNxt (adv seq (len - 1)) (adv rcvNxt wnd)

/-- The same test as `arrive` uses it: how far past `RCV.NXT` the first and
    last octets lie, against `RCV.WND`. -/
def acceptable (rcvNxt : Seq) (wnd : Nat) (seq : Seq) (len : Nat) : Bool :=
  if len = 0 then
    if wnd = 0 then seq == rcvNxt else decide (dist rcvNxt seq < wnd)
  else
    wnd != 0 && (decide (dist rcvNxt seq < wnd) || decide (dist rcvNxt (adv seq (len - 1)) < wnd))

/-- The offset test is the RFC's table, for every window that fits in the
    sequence space and every 32-bit value of `RCV.NXT` and `SEG.SEQ`. -/
theorem acceptable_eq_table (rcvNxt seq : Seq) (wnd len : Nat) (hw : wnd < M) :
    acceptable rcvNxt wnd seq len = table rcvNxt wnd seq len := by
  cases len <;> cases wnd <;>
    simp only [acceptable, table, leLt, dist_adv, Nat.mod_eq_of_lt hw] <;> simp

/-- The table over unbounded integers: where the segment lies against the
    window before any reduction modulo 2^32. -/
def tableNat (R W S L : Nat) : Prop :=
  if L = 0 then (if W = 0 then S = R else R ≤ S ∧ S < R + W)
  else W ≠ 0 ∧ ((R ≤ S ∧ S < R + W) ∨ (R ≤ S + L - 1 ∧ S + L - 1 < R + W))

/-- Across wraparound: take any unbounded `RCV.NXT` = `R` and `SEG.SEQ` =
    `S` less than half the space apart, a window and a segment no longer
    than half the space. The 32-bit test on the reduced numbers says what
    the table says on the unbounded ones. -/
theorem acceptable_lift (R W S L : Nat) (hW : W < H) (hL : L ≤ H)
    (h1 : S < R + H) (h2 : R < S + H) :
    acceptable (UInt32.ofNat R) W (UInt32.ofNat S) L = true ↔ tableNat R W S L := by
  have hb : (UInt32.ofNat S == UInt32.ofNat R) = decide (S % M = R % M) := by
    rw [Bool.eq_iff_iff, beq_iff_eq, decide_eq_true_iff, seq_eq_iff, ofNat_toNat', ofNat_toNat']
  unfold acceptable tableNat
  rw [hb]
  simp only [dist_eq, adv_toNat, ofNat_toNat']
  by_cases hl : L = 0 <;> by_cases hw : W = 0 <;> simp [hl, hw] <;> seq_omega

/-! ## smoltcp's order

`SeqNumber` compares by the sign of the 32-bit difference and returns no
order when the difference is exactly 2^31 (`i32::MIN`), so every `<`, `<=`,
`>` and `>=` on such a pair is false. -/

/-- `a < b` in `SeqNumber`'s order. -/
def sLt (a b : Seq) : Prop := 0 < dist a b ∧ dist a b < H
/-- `a <= b` in `SeqNumber`'s order. -/
def sLe (a b : Seq) : Prop := dist a b < H

instance (a b : Seq) : Decidable (sLt a b) := by unfold sLt; infer_instance
instance (a b : Seq) : Decidable (sLe a b) := by unfold sLe; infer_instance

/-- Half the space apart, neither number is before or after the other. -/
theorem half_unordered (a b : Seq) (h : dist a b = H) :
    ¬ sLe a b ∧ ¬ sLe b a ∧ ¬ sLt a b ∧ ¬ sLt b a := by
  have hne : a ≠ b := fun e => by subst e; simp at h
  have := dist_symm a b hne
  unfold sLe sLt; seq_omega

/-- Any other two numbers are ordered one way or the other. -/
theorem ordered_otherwise (a b : Seq) (h : dist a b ≠ H) : sLe a b ∨ sLe b a := by
  by_cases e : a = b
  · subst e; left; simp [sLe]
  · have := dist_symm a b e; have := dist_lt a b; unfold sLe; seq_omega

/-- The window test as smoltcp writes it, `start <= seq && seq < end` in
    `SeqNumber`'s order, is the RFC's offset test for every window below
    2^31, at every 32-bit position. -/
theorem signed_window_iff (ws s : Seq) (W : Nat) (hW : W < H) :
    (sLe ws s ∧ sLt s (adv ws W)) ↔ dist ws s < W := by
  unfold sLe sLt
  simp only [dist_eq, adv_toNat]
  have := lt_M ws; have := lt_M s
  seq_omega

/-- At a window of exactly 2^31 the signed test fails: it rejects
    `SEG.SEQ = RCV.NXT`, which the RFC accepts. smoltcp's window is at most
    2^30 octets (a 16-bit field shifted by at most 14), so the code never
    reaches this point. -/
theorem signed_window_fails_at_half (ws : Seq) :
    dist ws ws < H ∧ ¬ (sLe ws ws ∧ sLt ws (adv ws H)) := by
  refine ⟨by simp, ?_⟩
  unfold sLe sLt
  simp only [dist_eq, adv_toNat]
  have := lt_M ws
  seq_omega

/-! ## Acknowledgments -/

/-- An ACK of something not yet sent: `SEG.ACK > SND.NXT`. RFC 1982 leaves
    the point exactly 2^31 away unordered; the model counts it here, so it
    is challenged and never taken as new. -/
def ahead (ack sndNxt : Seq) : Prop := 0 < dist sndNxt ack ∧ dist sndNxt ack ≤ H

instance (a b : Seq) : Decidable (ahead a b) := by unfold ahead; infer_instance

/-- smoltcp's check, `!(ack <= SND.MAX)` in `SeqNumber`'s order, is
    exactly `ahead`, at every 32-bit value, the 2^31 point included. -/
theorem signed_ahead_iff (a nxt : Seq) : ¬ sLe a nxt ↔ ahead a nxt := by
  unfold sLe ahead
  by_cases e : a = nxt
  · subst e; simp
  · have := dist_symm a nxt e; have := dist_lt a nxt; seq_omega

/-- A new ACK is never ahead, while less than half the space is in
    flight. -/
theorem new_not_ahead (una a nxt : Seq) (hf : dist una nxt < H)
    (hn : ltLe una a nxt = true) : ¬ ahead a nxt := by
  unfold ltLe at hn; unfold ahead
  simp only [decide_eq_true_eq] at hn
  have := dist_trans una a nxt
  have := dist_trans una nxt a
  have := dist_lt a nxt; have := dist_lt nxt a
  by_cases e : a = nxt
  · subst e; simp
  · have := dist_symm a nxt e; seq_omega

/-- smoltcp takes an ACK as new when it is not ahead and not before
    SND.UNA: `ack <= SND.MAX && !(ack < SND.UNA)`. With less than half the
    space in flight that is the RFC's `SND.UNA < SEG.ACK =< SND.NXT`, or
    the ACK repeats `SND.UNA`. -/
theorem signed_advance_iff (una a nxt : Seq) (hf : dist una nxt < H) :
    (sLe a nxt ∧ ¬ sLt a una) ↔ (a = una ∨ ltLe una a nxt = true) := by
  unfold sLe sLt ltLe
  simp only [decide_eq_true_eq, seq_eq_iff, dist_eq] at *
  have := lt_M a; have := lt_M una; have := lt_M nxt
  seq_omega

end TcpRfc
