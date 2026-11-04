import Mptcp.Option

namespace Mptcp

/-- Network byte order, truncating to the requested width. -/
def be : Nat → Nat → Octets
  | 0, _ => []
  | n + 1, v => be n (v / 256) ++ [v % 256]

def readBe : Octets → Nat
  | [] => 0
  | b :: bs => b * 256 ^ bs.length + readBe bs

@[simp] theorem be_length (n v : Nat) : (be n v).length = n := by
  induction n generalizing v <;> simp [be, *]

def delta (near low : Nat) : Int :=
  let r := (low + 4294967296 - near % 4294967296) % 4294967296
  if r < 2147483648 then r else (r : Int) - 4294967296

def expand (near low : Nat) : Nat :=
  (((near : Int) + delta near low) % 18446744073709551616).toNat

/-- The chosen representative is within a signed half-window, with the
    exactly-half-window tie assigned to the older sequence. -/
theorem delta_bounds (near low : Nat) :
    -2147483648 ≤ delta near low ∧ delta near low < 2147483648 := by
  unfold delta
  dsimp only
  split <;> omega

theorem expand_low (near low : Nat) (h : low < 4294967296) :
    expand near low % 4294967296 = low := by
  unfold expand delta
  dsimp only
  split <;> omega

theorem expand_bounded (near low : Nat) : expand near low < 18446744073709551616 := by
  unfold expand
  omega

/-- Internet-checksum words; an odd last byte occupies the high octet. -/
def wordSum : Octets → Nat
  | [] => 0
  | [a] => a * 256
  | a :: b :: rest => a * 256 + b + wordSum rest

/-- End-around carry, including both representations of zero. -/
def checksum (sum : Nat) : Nat :=
  65535 - if sum = 0 then 0 else (sum - 1) % 65535 + 1

def dssChecksum (dsn ssn length : Nat) (data : Octets) : Nat :=
  checksum (wordSum (be 8 dsn ++ be 4 ssn ++ be 2 length ++ [0, 0] ++ data))

theorem checksum_bound (sum : Nat) : checksum sum < 65536 := by
  unfold checksum
  split <;> omega

/-- Appending the checksum balances the one's-complement sum. -/
theorem checksum_balances (sum : Nat) : (sum + checksum sum) % 65535 = 0 := by
  unfold checksum
  split <;> omega

theorem odd_byte_high (a : Nat) : wordSum [a] = a * 256 := rfl

def rotr (x : UInt32) (n : Nat) : UInt32 :=
  (x >>> n.toUInt32) ||| (x <<< (32 - n).toUInt32)

def shaConstants : Array UInt32 := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

def compress (state : Array UInt32) (block : Octets) : Array UInt32 := Id.run do
  let mut w : Array UInt32 := #[]
  for i in [:16] do w := w.push (readBe ((block.drop (4 * i)).take 4)).toUInt32
  for i in [16:64] do
    let x := w[i - 15]!
    let y := w[i - 2]!
    let s0 := rotr x 7 ^^^ rotr x 18 ^^^ (x >>> 3)
    let s1 := rotr y 17 ^^^ rotr y 19 ^^^ (y >>> 10)
    w := w.push (w[i - 16]! + s0 + w[i - 7]! + s1)
  let mut h := state
  for i in [:64] do
    let a := h[0]!; let b := h[1]!; let c := h[2]!; let d := h[3]!
    let e := h[4]!; let f := h[5]!; let g := h[6]!; let z := h[7]!
    let s1 := rotr e 6 ^^^ rotr e 11 ^^^ rotr e 25
    let ch := (e &&& f) ^^^ (~~~e &&& g)
    let t1 := z + s1 + ch + shaConstants[i]! + w[i]!
    let s0 := rotr a 2 ^^^ rotr a 13 ^^^ rotr a 22
    let maj := (a &&& b) ^^^ (a &&& c) ^^^ (b &&& c)
    h := #[t1 + s0 + maj, a, b, c, d + t1, e, f, g]
  return (List.range 8).toArray.map (fun i => state[i]! + h[i]!)

/-- FIPS 180-4 SHA-256, evaluated in Lean; no external hash oracle. -/
def shaState (data : Octets) : Array UInt32 := Id.run do
  let padding := (64 - (data.length + 9) % 64) % 64
  let bytes := data ++ [128] ++ List.replicate padding 0 ++ be 8 (data.length * 8)
  let mut h : Array UInt32 := #[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
  for i in [:bytes.length / 64] do
    h := compress h ((bytes.drop (64 * i)).take 64)
  return h

def digestBytes (h : Array UInt32) : Octets :=
  (List.range 8).flatMap (fun i => be 4 h[i]!.toNat)

def sha256 (data : Octets) : Octets := digestBytes (shaState data)

def keyDigest (key : Nat) : Octets := sha256 (be 8 key)
def token (key : Nat) : Nat := readBe ((keyDigest key).take 4)
def idsn (key : Nat) : Nat := readBe ((keyDigest key).drop 24)

def hmac (key data : Octets) : Octets :=
  let k := key ++ List.replicate (64 - key.length) 0
  sha256 (k.map (fun b => Nat.xor b 92) ++ sha256 (k.map (fun b => Nat.xor b 54) ++ data))

def joinHmac (own peer ownRandom peerRandom : Nat) : Octets :=
  hmac (be 8 own ++ be 8 peer) (be 4 ownRandom ++ be 4 peerRandom)

theorem key_bytes (key : Nat) : (be 8 key).length = 8 := be_length 8 key

theorem readBe_append (a b : Octets) :
    readBe (a ++ b) = readBe a * 256 ^ b.length + readBe b := by
  induction a with
  | nil => simp [readBe]
  | cons x xs ih =>
    simp [readBe, ih, Nat.pow_add, Nat.mul_assoc, Nat.add_mul, Nat.add_assoc]

/-- All 64 key bits survive the network byte order conversion. -/
theorem readBe_be (width value : Nat) (h : value < 256 ^ width) :
    readBe (be width value) = value := by
  induction width generalizing value with
  | zero => simp at h; simp [be, readBe, h]
  | succ width ih =>
    have hv : value / 256 < 256 ^ width := by
      rw [Nat.pow_succ] at h
      omega
    simp only [be, readBe_append, List.length_singleton, Nat.pow_one, ih _ hv]
    simp [readBe]
    omega

theorem be_octets (width value : Nat) : ∀ b ∈ be width value, b < 256 := by
  induction width generalizing value with
  | zero => simp [be]
  | succ width ih =>
    intro b hb
    simp only [be, List.mem_append, List.mem_singleton] at hb
    rcases hb with hb | hb
    · exact ih _ _ hb
    · subst b; omega

theorem readBe_bound (bs : Octets) (h : ∀ b ∈ bs, b < 256) : readBe bs < 256 ^ bs.length := by
  induction bs with
  | nil => simp [readBe]
  | cons b bs ih =>
    have hb := h b (by simp)
    have ht := ih (by intro x hx; exact h x (by simp [hx]))
    have hm : b * 256 ^ bs.length ≤ 255 * 256 ^ bs.length :=
      Nat.mul_le_mul_right _ (by omega)
    simp only [readBe, List.length_cons, Nat.pow_succ]
    omega

theorem sha256_length (bytes : Octets) : (sha256 bytes).length = 32 := by
  simp [sha256, digestBytes, List.length_flatMap, List.range_succ]

theorem sha256_octets (bytes : Octets) : ∀ b ∈ sha256 bytes, b < 256 := by
  intro b hb
  simp only [sha256, digestBytes, List.mem_flatMap] at hb
  rcases hb with ⟨i, _, hi⟩
  exact be_octets 4 _ b hi

/-- Token extraction is the high 32 bits of the full digest. -/
theorem token_high_bits (key : Nat) :
    token key = readBe (keyDigest key) / 256 ^ 28 := by
  have len : (keyDigest key).length = 32 := sha256_length _
  have eq := readBe_append ((keyDigest key).take 4) ((keyDigest key).drop 4)
  have bound := readBe_bound ((keyDigest key).drop 4)
    (by intro b hb; exact sha256_octets _ b (List.mem_of_mem_drop hb))
  simp only [List.take_append_drop, List.length_drop, len] at eq bound
  simp only [Nat.reduceSub, Nat.reducePow] at eq bound
  unfold token
  omega

/-- IDSN extraction is the low 64 bits of the full digest. -/
theorem idsn_low_bits (key : Nat) :
    idsn key = readBe (keyDigest key) % 256 ^ 8 := by
  have len : (keyDigest key).length = 32 := sha256_length _
  have eq := readBe_append ((keyDigest key).take 24) ((keyDigest key).drop 24)
  have bound := readBe_bound ((keyDigest key).drop 24)
    (by intro b hb; exact sha256_octets _ b (List.mem_of_mem_drop hb))
  simp only [List.take_append_drop, List.length_drop, len] at eq bound
  simp only [Nat.reduceSub, Nat.reducePow] at eq bound
  unfold idsn
  omega

theorem join_material_lengths (own peer a b : Nat) :
    (be 8 own ++ be 8 peer).length = 16 ∧ (be 4 a ++ be 4 b).length = 8 := by simp

theorem join_hmac_length (own peer a b : Nat) : (joinHmac own peer a b).length = 32 := by
  exact sha256_length _

end Mptcp
