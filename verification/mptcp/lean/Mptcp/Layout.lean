import Mptcp.Option

namespace Mptcp

/-- Standard option sizes, excluding any MPTCP bytes. The Linux policy is
    an input, corresponding only to fictionet-extras::linux::settings. -/
def optionSize (linux mss scale sack timestamp : Bool) : Nat :=
  (if mss then 4 else 0) + (if scale then (if linux then 4 else 3) else 0) +
  (if sack then (if linux && !timestamp then 4 else 2) else 0) +
  (if timestamp then (if linux && !sack then 12 else 10) else 0)

def padded (n : Nat) : Nat := (n + 3) / 4 * 4

def room (linux mss scale sack timestamp : Bool) : Nat :=
  40 - optionSize linux mss scale sack timestamp

theorem standard_options_fit (linux mss scale sack timestamp : Bool) :
    optionSize linux mss scale sack timestamp ≤ 20 := by
  cases linux <;> cases mss <;> cases scale <;> cases sack <;> cases timestamp <;> decide

theorem mptcp_fits (linux mss scale sack timestamp : Bool) (extra : Nat)
    (h : extra ≤ room linux mss scale sack timestamp) :
    padded (optionSize linux mss scale sack timestamp + extra) ≤ 40 := by
  have hs := standard_options_fit linux mss scale sack timestamp
  unfold room at h
  unfold padded
  omega

theorem header_aligned (n : Nat) : padded n % 4 = 0 := by
  unfold padded
  omega

theorem syn_room : room false true true true true = 21 ∧
    room true true true true true = 20 := by decide

theorem dss_room : room false false false false true = 30 ∧
    room true false false false true = 28 := by decide

/-- RFC 5681 permits acknowledging every second full-sized segment. -/
def ackDue (segments : Nat) : Bool := segments ≥ 2

theorem second_segment_acked : ackDue 2 = true := rfl

end Mptcp
