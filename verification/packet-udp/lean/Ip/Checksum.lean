import Lean

/-! The Internet checksum (RFC 1071) and its incremental update (RFC 1624).

The reference definitions here are RFC 1071 written plainly, one 16-bit
word at a time. Octets are `Nat`s below 256. Other modules import these
names; keep them stable. -/

namespace Ip.Checksum

/-- The data as 16-bit big-endian words, an odd last octet padded with a
zero octet (RFC 1071 section 1, step 1). -/
def words : List Nat → List Nat
  | [] => []
  | [a] => [a * 256]
  | a :: b :: rest => (a * 256 + b) :: words rest

/-- One's-complement addition of two 16-bit words: the end-around carry
(RFC 1071 section 1, step 2). -/
def addOnes (a b : Nat) : Nat :=
  if a + b ≥ 65536 then a + b - 65535 else a + b

/-- The one's-complement sum of a list of 16-bit words, from 0. -/
def onesSum (ws : List Nat) : Nat := ws.foldl addOnes 0

/-- The Internet checksum of the data: the complement of the one's-complement
sum of its words (RFC 1071 section 1, step 3). -/
def checksum (bytes : List Nat) : Nat := 65535 - onesSum (words bytes)

/-- The vector files this module writes: `(file stem, cases)`. -/
def vectors (_seed : Nat) : List (String × Lean.Json) := []

end Ip.Checksum
