/-
The receive window of one SSH channel, for every value (RFC 4254
section 5.2). Source: src/stdlib/services/ssh.rs `Channel::adjustment`
(owed = receive.saturating_sub(advertised), at most u32::MAX - advertised,
due once owed > 0 and owed >= advertised), `Channel::consume_receive`
(data lowers both, within both), `on_command` (Credit raises receive,
refused past u32::MAX), `progress` (an adjustment adds what is owed).
`receive` is a u64 kept at most u32::MAX; `advertised` is a u32.
Core Lean only; every proof is `omega` over Nat.
-/

namespace Adjust

/-- u32::MAX. -/
def U : Nat := 4294967295

/-- What `Channel::adjustment` computes before it decides. -/
def owed (receive advertised : Nat) : Nat :=
  min (receive - advertised) (U - advertised)

/-- Whether `Channel::adjustment` returns `Some`. -/
def due (receive advertised : Nat) : Prop :=
  owed receive advertised > 0 ∧ owed receive advertised ≥ advertised

/-- The channel's state as these lemmas need it. -/
structure W where
  receive : Nat
  advertised : Nat

/-- What every reachable state keeps: the peer was never told of room the
child's credit does not back, and both fit their types. -/
def Good (w : W) : Prop :=
  w.advertised ≤ w.receive ∧ w.receive ≤ U

/-- `consume_receive n`: accepted only within both. -/
def consume (w : W) (n : Nat) : W := ⟨w.receive - n, w.advertised - n⟩
/-- Credit from Children; refused past u32::MAX. -/
def credit (w : W) (n : Nat) : W := ⟨w.receive + n, w.advertised⟩
/-- An adjustment of what is owed. -/
def adjust (w : W) : W := ⟨w.receive, w.advertised + owed w.receive w.advertised⟩

theorem consume_good (w : W) (n : Nat) (h : Good w)
    (hn : n ≤ w.advertised) : Good (consume w n) := by
  unfold Good consume at *; simp only at *; omega

theorem credit_good (w : W) (n : Nat) (h : Good w)
    (hn : w.receive + n ≤ U) : Good (credit w n) := by
  unfold Good credit at *; simp only at *; omega

/-- An adjustment tells the peer of all the credit and no more: advertised
becomes receive, and it never overflows a u32. -/
theorem adjust_exact (w : W) (h : Good w) :
    (adjust w).advertised = w.receive ∧ Good (adjust w) := by
  unfold Good adjust owed U at *; simp only at *; omega

/-- Never dry: a peer with no room left hears of any room owed. -/
theorem never_dry (w : W) (h : Good w) (h0 : w.advertised = 0)
    (hr : w.receive > 0) : due w.receive w.advertised := by
  unfold due owed U Good at *; omega

/-- Each adjustment at least doubles what the peer may send. -/
theorem adjust_doubles (w : W) (hd : due w.receive w.advertised) :
    (adjust w).advertised ≥ 2 * w.advertised := by
  unfold due adjust owed U at *; simp only at *; omega

/-- No adjustment is due while the peer still has more than half of the
credit: none goes out per packet while room remains. -/
theorem quiet_above_half (w : W) (h : Good w)
    (hh : 2 * w.advertised > w.receive) : ¬ due w.receive w.advertised := by
  unfold due owed Good U at *; omega

/-- With no room owed, nothing is due. -/
theorem quiet_when_told (w : W) (h : Good w) (he : w.advertised = w.receive) :
    ¬ due w.receive w.advertised := by
  unfold due owed Good U at *; omega

end Adjust
