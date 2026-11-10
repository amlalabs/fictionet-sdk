import Lean

/-! ICMP and ICMPv6 messages the engine generates (RFC 792, RFC 1122 section 3.2.2, RFC 4443). -/

namespace Ip.Icmp

/-- The vector files this module writes: `(file stem, cases)`. -/
def vectors (_seed : Nat) : List (String × Lean.Json) := []

end Ip.Icmp
