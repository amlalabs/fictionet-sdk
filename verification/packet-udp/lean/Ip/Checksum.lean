import Lean

/-! The Internet checksum (RFC 1071) and its incremental update (RFC 1624). -/

namespace Ip.Checksum

/-- The vector files this module writes: `(file stem, cases)`. -/
def vectors (_seed : Nat) : List (String × Lean.Json) := []

end Ip.Checksum
