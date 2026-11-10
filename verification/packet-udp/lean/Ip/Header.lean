import Lean
import Ip.Checksum

/-! IPv4 header validation (RFC 791, RFC 1122 section 3.2.1) and the router hop (RFC 1812 section 5.3.1). -/

namespace Ip.Header

/-- The vector files this module writes: `(file stem, cases)`. -/
def vectors (_seed : Nat) : List (String × Lean.Json) := []

end Ip.Header
