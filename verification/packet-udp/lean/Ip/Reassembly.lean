import Lean

/-! Fragment reassembly (RFC 791, RFC 815, RFC 8200 section 4.5, RFC 5722). -/

namespace Ip.Reassembly

/-- The vector files this module writes: `(file stem, cases)`. -/
def vectors (_seed : Nat) : List (String × Lean.Json) := []

end Ip.Reassembly
