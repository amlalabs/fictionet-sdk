import Mptcp.Pure

namespace Mptcp

/-- Data offsets are relative to IDSN + 1. TCP has already delivered the
    subflow in order; mappings may put those bytes in another data order. -/
structure ReceiveState where
  next : Nat := 0
  ready : List Nat := []
  output : List Nat := []
  fin : Option Nat := none
  failed : Bool := false
  fallback : Bool := false
  deriving Repr

def drain : Nat → ReceiveState → ReceiveState
  | 0, s => s
  | fuel + 1, s =>
    if s.ready.contains s.next then
      drain fuel { s with
        next := s.next + 1
        ready := s.ready.filter (· != s.next)
        output := s.output ++ [s.next + 65] }
    else s

/-- A complete one-byte mapping, a pure DATA_FIN, or a loss of mapping.
    The checksum fault is an adversary, not an alternate checksum. -/
def receive (s : ReceiveState) (kind index : Nat) : ReceiveState :=
  if s.failed || s.fallback then s
  else if kind = 2 then
    if s.ready.isEmpty && s.fin.isNone then { s with fallback := true }
    else { s with failed := true }
  else if kind = 3 then { s with failed := true }
  else if kind = 1 then
    if index < s.next || s.ready.any (· ≥ index) || s.fin.any (· != index) then
      { s with failed := true }
    else { s with fin := some index }
  else if s.fin.any (index ≥ ·) then { s with failed := true }
  else if index < s.next then s
  else drain (s.ready.length + 1) { s with ready := s.ready ++ [index] }

def dataAck (s : ReceiveState) : Nat :=
  s.next + if s.fin == some s.next then 1 else 0

theorem failed_terminal (s : ReceiveState) (h : s.failed = true) (kind index : Nat) :
    receive s kind index = s := by simp [receive, h]

theorem fin_blocks_later_data (s : ReceiveState) (f i : Nat)
    (h : s.failed = false) (b : s.fallback = false) (hf : s.fin = some f) (hi : f ≤ i) :
    (receive s 0 i).failed = true := by simp [receive, h, b, hf, hi]

theorem fallback_keeps_gap (s : ReceiveState) (h : s.failed = false)
    (b : s.fallback = false) (pending : s.ready.isEmpty = false) :
    (receive s 2 0).failed = true := by simp [receive, h, b, pending]

end Mptcp
