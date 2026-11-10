import Lean

/-! IPv6 extension headers as a destination checks them (RFC 8200 section 4, RFC 7112). -/

namespace Ip.Ext6

/-- The vector files this module writes: `(file stem, cases)`. -/
def vectors (_seed : Nat) : List (String × Lean.Json) := []

end Ip.Ext6
