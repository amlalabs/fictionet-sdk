import Lean

/-! The Internet checksum (RFC 1071) and its incremental update (RFC 1624).

The reference definitions here are RFC 1071 written plainly, one 16-bit
word at a time. Octets are `Nat`s below 256. Other modules import these
names; keep them stable.

Below the reference is the Rust code as it is (`sum`, `fold` and
`pseudo_header_sum` in `src/stdlib/network/ip.rs`), and the theorems that
tie the two together. The Rust accumulator is a `u64`; here it is a `Nat`.
The Rust caller keeps the sum inside 64 bits (the doc comments of `sum` and
`pseudo_header_sum` say how), so the two agree on every input the code
takes. -/

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

/-- Every element is an octet. -/
def Octets (data : List Nat) : Prop := ∀ b ∈ data, b < 256

/-! ## The Rust code -/

/-- The first loop of `sum`: the whole four-octet chunks of the data
(`as_chunks::<4>`), each read as a big-endian `u32` and added, and the
octets left over. -/
def quads : List Nat → Nat × List Nat
  | a :: b :: c :: d :: rest =>
    (a * 16777216 + b * 65536 + c * 256 + d + (quads rest).1, (quads rest).2)
  | [] => (0, [])
  | [a] => (0, [a])
  | [a, b] => (0, [a, b])
  | [a, b, c] => (0, [a, b, c])

/-- The second loop of `sum`: the whole two-octet chunks of what is left,
each read as a big-endian `u16` and added, and the octet left over. -/
def pairs : List Nat → Nat × List Nat
  | a :: b :: rest =>
    (a * 256 + b + (pairs rest).1, (pairs rest).2)
  | [] => (0, [])
  | [a] => (0, [a])

/-- The last step of `sum`: an odd last octet, shifted left by 8. -/
def odd : List Nat → Nat
  | [last] => last * 256
  | [] => 0
  | _ :: _ :: _ => 0

/-- Rust's `sum(acc, data)`: four octets at a time, then pairs, then an odd
octet shifted left by 8, all added to `acc` without folding. -/
def sum (acc : Nat) (data : List Nat) : Nat :=
  acc + (quads data).1 + (pairs (quads data).2).1 + odd (pairs (quads data).2).2

/-- The loop of Rust's `fold`: while the sum has bits above 16, add them
back in at the bottom. -/
def foldNat (acc : Nat) : Nat :=
  if acc < 65536 then acc else foldNat (acc % 65536 + acc / 65536)
termination_by acc
decreasing_by omega

/-- Rust's `fold(acc)`: the folded sum, complemented (`!(acc as u16)`). -/
def fold (acc : Nat) : Nat := 65535 - foldNat acc

/-- Rust's `pseudo_header_sum(acc, endpoints, protocol, len)`: the address
octets summed as data, then the protocol and the length added as plain
integers. -/
def pseudoHeaderSum (acc : Nat) (src dst : List Nat) (protocol len : Nat) : Nat :=
  sum (sum acc src) dst + protocol + len

/-- Rust's `transport_checksum(src, dst, protocol, data)` for addresses of
one family. -/
def transportChecksum (src dst : List Nat) (protocol : Nat) (data : List Nat) : Nat :=
  fold (sum (pseudoHeaderSum 0 src dst protocol data.length) data)

/-! ## The pseudo-headers as the RFCs lay them out -/

/-- The IPv4 pseudo-header (RFC 768, RFC 9293 section 3.1): source,
destination, a zero octet, the protocol, and the 16-bit length. -/
def pseudo4 (src dst : List Nat) (protocol len : Nat) : List Nat :=
  src ++ dst ++ [0, protocol, len / 256, len % 256]

/-- The IPv6 pseudo-header (RFC 8200 section 8.1): source, destination,
the 32-bit upper-layer length, three zero octets, and the next header. -/
def pseudo6 (src dst : List Nat) (protocol len : Nat) : List Nat :=
  src ++ dst ++
    [len / 16777216, len / 65536 % 256, len / 256 % 256, len % 256, 0, 0, 0, protocol]

/-! ## One's-complement arithmetic in closed form -/

/-- The value in `0 ..= 65535` that both `foldNat` and `onesSum` give for a
sum `n`: 0 only for 0, and otherwise the representative of `n` modulo
65535 in `1 ..= 65535`. -/
def rep (n : Nat) : Nat := if n = 0 then 0 else (n - 1) % 65535 + 1

theorem rep_lt (n : Nat) : rep n < 65536 := by
  unfold rep; split <;> omega

theorem rep_congr {a b : Nat} (hmod : a % 65535 = b % 65535) (hz : a = 0 ↔ b = 0) :
    rep a = rep b := by
  unfold rep
  have h1 := hz.1
  have h2 := hz.2
  repeat' split
  all_goals omega

theorem foldNat_eq_rep (n : Nat) : foldNat n = rep n := by
  fun_induction foldNat n with
  | case1 n h => unfold rep; split <;> omega
  | case2 n h ih => rw [ih]; unfold rep; split <;> split <;> omega

theorem addOnes_rep (s w : Nat) (hw : w < 65536) : addOnes (rep s) w = rep (s + w) := by
  unfold addOnes rep
  repeat' split
  all_goals omega

theorem foldl_addOnes (ws : List Nat) (s : Nat) (h : ∀ w ∈ ws, w < 65536) :
    ws.foldl addOnes (rep s) = rep (s + ws.sum) := by
  induction ws generalizing s with
  | nil => simp
  | cons w ws ih =>
    simp only [List.foldl_cons, List.sum_cons]
    rw [addOnes_rep s w (h w (by simp)), ih (s + w) (fun x hx => h x (by simp [hx]))]
    congr 1
    omega

theorem onesSum_eq_rep (ws : List Nat) (h : ∀ w ∈ ws, w < 65536) :
    onesSum ws = rep ws.sum := by
  have h0 : rep 0 = 0 := by simp [rep]
  have := foldl_addOnes ws 0 h
  rw [h0, Nat.zero_add] at this
  exact this

/-! ## Words -/

theorem words_lt (data : List Nat) (h : Octets data) : ∀ w ∈ words data, w < 65536 := by
  fun_induction words data with
  | case1 => simp
  | case2 a =>
    have := h a (by simp)
    simp only [List.mem_singleton]
    omega
  | case3 a b rest ih =>
    have ha := h a (by simp)
    have hb := h b (by simp)
    intro w hw
    simp only [List.mem_cons] at hw
    rcases hw with hw | hw
    · omega
    · exact ih (fun x hx => h x (by simp [hx])) w hw

theorem words_append (xs ys : List Nat) (h : xs.length % 2 = 0) :
    words (xs ++ ys) = words xs ++ words ys := by
  fun_induction words xs with
  | case1 => simp
  | case2 a => simp at h
  | case3 a b rest ih =>
    simp only [List.cons_append, words, List.cons.injEq, true_and]
    exact ih (by simp at h; omega)

theorem checksum_eq_rep (data : List Nat) (h : Octets data) :
    checksum data = 65535 - rep (words data).sum := by
  unfold checksum
  rw [onesSum_eq_rep _ (words_lt data h)]

theorem checksum_lt (data : List Nat) : checksum data < 65536 := by
  unfold checksum; omega

theorem octets_append {xs ys : List Nat} : Octets (xs ++ ys) ↔ Octets xs ∧ Octets ys := by
  unfold Octets
  simp only [List.mem_append]
  constructor
  · intro h; exact ⟨fun b hb => h b (Or.inl hb), fun b hb => h b (Or.inr hb)⟩
  · intro h b hb; rcases hb with hb | hb
    · exact h.1 b hb
    · exact h.2 b hb

/-- Data with a few octets in the middle, each below 256. -/
theorem octets_mid {xs mid ys : List Nat} (hx : Octets xs) (hm : ∀ b ∈ mid, b < 256)
    (hy : Octets ys) : Octets (xs ++ mid ++ ys) :=
  octets_append.2 ⟨octets_append.2 ⟨hx, hm⟩, hy⟩

/-! ## The Rust `sum` against the words -/

theorem quads_spec (data : List Nat) :
    ∃ k, (quads data).1 + (words (quads data).2).sum = (words data).sum + 65535 * k ∧
      k ≤ (words data).sum := by
  fun_induction quads data with
  | case1 a b c d rest ih =>
    obtain ⟨k, h1, h2⟩ := ih
    refine ⟨k + (a * 256 + b), ?_, ?_⟩
    · simp only [words, List.sum_cons]
      omega
    · simp only [words, List.sum_cons]
      omega
  | case2 => exact ⟨0, by simp, by simp⟩
  | case3 a => exact ⟨0, by simp, by simp⟩
  | case4 a b => exact ⟨0, by simp, by simp⟩
  | case5 a b c => exact ⟨0, by simp, by simp⟩

theorem pairs_spec (data : List Nat) :
    (pairs data).1 + (words (pairs data).2).sum = (words data).sum ∧
      (pairs data).2.length < 2 := by
  fun_induction pairs data with
  | case1 a b rest ih =>
    simp only [words, List.sum_cons]
    omega
  | case2 => simp
  | case3 a => simp

theorem odd_spec (rest : List Nat) (h : rest.length < 2) : odd rest = (words rest).sum := by
  match rest, h with
  | [], _ => simp [odd, words]
  | [a], _ => simp [odd, words]

/-- What `sum` adds to its accumulator: the sum of the data's words, plus a
multiple of 65535 no larger than that sum (each four-octet chunk counts its
first word 65536 times, and 65536 is 1 more than 65535). -/
theorem sum_spec (acc : Nat) (data : List Nat) :
    ∃ k, sum acc data = acc + (words data).sum + 65535 * k ∧ k ≤ (words data).sum := by
  obtain ⟨k, h1, h2⟩ := quads_spec data
  obtain ⟨h3, h4⟩ := pairs_spec (quads data).2
  have h5 := odd_spec _ h4
  refine ⟨k, ?_, h2⟩
  unfold sum
  omega

/-- The one's-complement value of a raw sum is not changed by adding a
multiple of 65535 that is zero whenever the sum is. -/
theorem rep_shift (n k : Nat) (h : k ≤ n) : rep (n + 65535 * k) = rep n := by
  exact rep_congr (by omega) ⟨fun _ => by omega, fun _ => by omega⟩

/-! ## Headline theorems: Rust's checksum is RFC 1071's -/

/-- Rust's `checksum` (`fold(sum(0, data))`) is RFC 1071's checksum, for
data of every length, odd lengths included (RFC 1071 section 1;
`ip::checksum`, `ip::sum`, `ip::fold`). -/
theorem rust_checksum (data : List Nat) (h : Octets data) :
    fold (sum 0 data) = checksum data := by
  obtain ⟨k, h1, h2⟩ := sum_spec 0 data
  unfold fold
  rw [foldNat_eq_rep, h1, checksum_eq_rep data h, Nat.zero_add, rep_shift _ _ h2]

/-- Two calls of Rust's `sum`, as `pseudo_header_sum` and its callers chain
them, give the checksum of the two parts' words side by side: each part
pads an odd last octet on its own (RFC 1071 section 2(B), "byte order
independence" and "parallel summation"). -/
theorem rust_sum_sum (xs ys : List Nat) (hx : Octets xs) (hy : Octets ys) :
    fold (sum (sum 0 xs) ys) = 65535 - onesSum (words xs ++ words ys) := by
  obtain ⟨kx, h1, h2⟩ := sum_spec 0 xs
  obtain ⟨ky, h3, h4⟩ := sum_spec (sum 0 xs) ys
  have hw : ∀ w ∈ words xs ++ words ys, w < 65536 := by
    intro w hw
    rcases List.mem_append.1 hw with hw | hw
    · exact words_lt xs hx w hw
    · exact words_lt ys hy w hw
  unfold fold
  rw [foldNat_eq_rep, onesSum_eq_rep _ hw, List.sum_append]
  congr 1
  exact rep_congr (by omega) ⟨fun _ => by omega, fun _ => by omega⟩

/-- Sums split at an even offset add: the checksum of two parts summed
apart is the checksum of the whole (RFC 1071 section 2(B)). -/
theorem rust_split (xs ys : List Nat) (hx : Octets xs) (hy : Octets ys)
    (heven : xs.length % 2 = 0) :
    fold (sum (sum 0 xs) ys) = checksum (xs ++ ys) := by
  rw [rust_sum_sum xs ys hx hy, checksum, words_append xs ys heven]

/-- Rust's `transport_checksum` over IPv4 is the RFC 1071 checksum of the
RFC 768 pseudo-header followed by the data, for every 16-bit length
(`pseudo_header_sum` adds `len` as a plain integer). -/
theorem rust_pseudo4 (src dst data : List Nat) (protocol len : Nat)
    (hs : src.length = 4) (hd : dst.length = 4) (hos : Octets src) (hod : Octets dst)
    (hdata : Octets data) (hp : protocol < 256) (hl : len < 65536) :
    fold (sum (pseudoHeaderSum 0 src dst protocol len) data) =
      checksum (pseudo4 src dst protocol len ++ data) := by
  obtain ⟨ks, h1, h2⟩ := sum_spec 0 src
  obtain ⟨kd, h3, h4⟩ := sum_spec (sum 0 src) dst
  obtain ⟨kx, h5, h6⟩ := sum_spec (pseudoHeaderSum 0 src dst protocol len) data
  have hocts : Octets (pseudo4 src dst protocol len ++ data) := by
    unfold pseudo4
    exact octets_mid (octets_append.2 ⟨hos, hod⟩) (by intro b hb; simp at hb; omega) hdata
  rw [checksum_eq_rep _ hocts]
  unfold fold
  rw [foldNat_eq_rep]
  congr 1
  have hw : words (pseudo4 src dst protocol len ++ data) =
      words src ++ (words dst ++ (protocol :: (len / 256 * 256 + len % 256) :: words data)) := by
    simp only [pseudo4, List.append_assoc]
    rw [words_append src _ (by omega), words_append dst _ (by omega)]
    simp [words] <;> omega
  rw [hw]
  simp only [List.sum_append, List.sum_cons]
  unfold pseudoHeaderSum at h5 ⊢
  exact rep_congr (by omega) ⟨fun _ => by omega, fun _ => by omega⟩

/-- The high 16 bits of a length, from its top two octets. -/
theorem len_hi (len : Nat) : len / 16777216 * 256 + len / 65536 % 256 = len / 65536 := by
  have h1 : len / 65536 / 256 = len / 16777216 := by simp [Nat.div_div_eq_div_mul]
  have h2 := Nat.div_add_mod (len / 65536) 256
  omega

/-- The low 16 bits of a length, from its bottom two octets. -/
theorem len_lo (len : Nat) : len / 256 % 256 * 256 + len % 256 = len % 65536 := by
  have h1 := Nat.div_add_mod len 256
  have h2 := Nat.div_add_mod (len / 256) 256
  have h3 : len / 256 / 256 = len / 65536 := by simp [Nat.div_div_eq_div_mul]
  have h4 := Nat.div_add_mod len 65536
  omega

/-- Rust's `transport_checksum` over IPv6 is the RFC 1071 checksum of the
RFC 8200 section 8.1 pseudo-header followed by the data, for every length
up to 2^32: adding `len` as one integer is the same as adding its two
16-bit halves. -/
theorem rust_pseudo6 (src dst data : List Nat) (protocol len : Nat)
    (hs : src.length = 16) (hd : dst.length = 16) (hos : Octets src) (hod : Octets dst)
    (hdata : Octets data) (hp : protocol < 256) (hl : len < 4294967296) :
    fold (sum (pseudoHeaderSum 0 src dst protocol len) data) =
      checksum (pseudo6 src dst protocol len ++ data) := by
  obtain ⟨ks, h1, h2⟩ := sum_spec 0 src
  obtain ⟨kd, h3, h4⟩ := sum_spec (sum 0 src) dst
  obtain ⟨kx, h5, h6⟩ := sum_spec (pseudoHeaderSum 0 src dst protocol len) data
  have hocts : Octets (pseudo6 src dst protocol len ++ data) := by
    unfold pseudo6
    exact octets_mid (octets_append.2 ⟨hos, hod⟩) (by intro b hb; simp at hb; omega) hdata
  rw [checksum_eq_rep _ hocts]
  unfold fold
  rw [foldNat_eq_rep]
  congr 1
  have hw : words (pseudo6 src dst protocol len ++ data) =
      words src ++ (words dst ++
        ((len / 16777216 * 256 + len / 65536 % 256) :: (len / 256 % 256 * 256 + len % 256) ::
          0 :: protocol :: words data)) := by
    simp only [pseudo6, List.append_assoc]
    rw [words_append src _ (by omega), words_append dst _ (by omega)]
    simp [words] <;> omega
  rw [hw]
  simp only [List.sum_append, List.sum_cons]
  unfold pseudoHeaderSum at h5 ⊢
  -- The two 16-bit halves of the 32-bit length add to the length less a
  -- multiple of 65535.
  have hhi := len_hi len
  have hlo := len_lo len
  exact rep_congr (by omega) ⟨fun _ => by omega, fun _ => by omega⟩

/-! ## Verification and the two zeros -/

/-- A checksum written into its field verifies: over the data with the
field filled in by `checksum`, the checksum is 0 (RFC 1071 section 1,
"to check a checksum"). The field is any 16-bit word at an even offset. -/
theorem verifies (xs ys : List Nat) (hx : Octets xs) (hy : Octets ys)
    (heven : xs.length % 2 = 0) :
    checksum (xs ++ [checksum (xs ++ [0, 0] ++ ys) / 256,
                     checksum (xs ++ [0, 0] ++ ys) % 256] ++ ys) = 0 := by
  have hoz : Octets (xs ++ [0, 0] ++ ys) :=
    octets_mid hx (by intro b hb; simp at hb; omega) hy
  have hc := checksum_eq_rep _ hoz
  have hlt := rep_lt (words (xs ++ [0, 0] ++ ys)).sum
  generalize hcv : checksum (xs ++ [0, 0] ++ ys) = c at hc
  have hof : Octets (xs ++ [c / 256, c % 256] ++ ys) :=
    octets_mid hx (by intro b hb; simp at hb; omega) hy
  rw [checksum_eq_rep _ hof]
  simp only [List.append_assoc, words_append xs _ heven, List.sum_append] at hc hlt ⊢
  simp only [List.cons_append, words, List.sum_cons] at hc hlt ⊢
  unfold rep at hc hlt ⊢
  repeat' split <;> try omega
  all_goals (split at hc <;> omega)

/-- An all-zero sum folds to 0xffff: Rust's `fold(0)` is 0xffff, the
checksum of all-zero data, of any length, is 0xffff, and that is the only
sum that folds to 0xffff. -/
theorem fold_zero : fold 0 = 65535 := by
  simp [fold, foldNat_eq_rep, rep]

theorem fold_eq_ffff_iff (n : Nat) : fold n = 65535 ↔ n = 0 := by
  unfold fold; rw [foldNat_eq_rep]; unfold rep; split <;> omega

/-- The other zero: `fold` gives 0x0000 exactly for a nonzero multiple of
65535, the one's-complement "negative zero" 0xffff (RFC 1071 section 1,
RFC 1624 section 3). -/
theorem fold_eq_zero_iff (n : Nat) : fold n = 0 ↔ n ≠ 0 ∧ n % 65535 = 0 := by
  unfold fold; rw [foldNat_eq_rep]; unfold rep; split <;> omega

theorem words_zero_sum (data : List Nat) (h : ∀ b ∈ data, b = 0) : (words data).sum = 0 := by
  fun_induction words data with
  | case1 => simp
  | case2 a => simp [h a (by simp)]
  | case3 a b rest ih =>
    simp only [List.sum_cons, h a (by simp), h b (by simp)]
    rw [ih (fun x hx => h x (by simp [hx]))]

theorem checksum_of_zeros (n : Nat) : checksum (List.replicate n 0) = 65535 := by
  have hz := words_zero_sum (List.replicate n 0) (fun b hb => (List.mem_replicate.1 hb).2)
  rw [checksum_eq_rep _ (fun b hb => by rw [(List.mem_replicate.1 hb).2]; omega), hz]
  simp [rep]

/-- The two zeros of one's complement in a checksum field: when the rest
of the data does not sum to zero, a field of 0x0000 and a field of 0xffff
give the same checksum, so both verify or neither does. Over all-zero data
they differ: 0xffff verifies there and 0x0000 does not. -/
theorem zero_fields_agree (xs ys : List Nat) (hx : Octets xs) (hy : Octets ys)
    (heven : xs.length % 2 = 0) (hrest : (words xs).sum + (words ys).sum ≠ 0) :
    checksum (xs ++ [0, 0] ++ ys) = checksum (xs ++ [255, 255] ++ ys) := by
  have ho : ∀ v, v < 256 → Octets (xs ++ [v, v] ++ ys) := fun v hv =>
    octets_mid hx (by intro b hb; simp at hb; omega) hy
  rw [checksum_eq_rep _ (ho 0 (by omega)), checksum_eq_rep _ (ho 255 (by omega))]
  simp only [List.append_assoc, words_append xs _ heven, List.sum_append, List.cons_append,
    List.nil_append,
    words, List.sum_cons]
  congr 1
  exact rep_congr (by omega) ⟨fun _ => by omega, fun _ => by omega⟩

/-! ## Errors the checksum always catches -/

theorem octets_set (data : List Nat) (i v : Nat) (h : Octets data) (hv : v < 256) :
    Octets (data.set i v) := by
  intro b hb
  rcases List.mem_or_eq_of_mem_set hb with hb | hb
  · exact h b hb
  · omega

theorem getD_lt (data : List Nat) (i : Nat) (h : Octets data) : data.getD i 0 < 256 := by
  rw [List.getD_eq_getElem?_getD]
  cases hget : data[i]? with
  | none => simp
  | some b => simpa using h b (List.mem_of_getElem? hget)

/-- Setting one octet moves the word sum by the change in that octet,
weighted 256 at an even offset and 1 at an odd one. -/
theorem words_set_sum (data : List Nat) (i v : Nat) (hi : i < data.length) :
    (words (data.set i v)).sum + (if i % 2 = 0 then data.getD i 0 * 256 else data.getD i 0) =
      (words data).sum + (if i % 2 = 0 then v * 256 else v) := by
  fun_induction words data generalizing i with
  | case1 => simp at hi
  | case2 a =>
    have : i = 0 := by simp at hi; omega
    subst this
    simp [words] <;> omega
  | case3 a b rest ih =>
    match i, hi with
    | 0, _ => simp [words] <;> omega
    | 1, _ => simp [words] <;> omega
    | j + 2, hj =>
      have := ih j (by simp at hj; omega)
      have hmod : (j + 2) % 2 = j % 2 := by omega
      simp only [List.set_cons_succ, List.getD_cons_succ, words, List.sum_cons, hmod]
      by_cases hc : j % 2 = 0 <;> simp [hc] at this ⊢ <;> omega

/-- Any change to one octet changes the checksum, so data with a single
corrupted octet never verifies (RFC 1071 section 2(B): the sum moves by at
most 255 · 256, less than 65535). -/
theorem one_octet_detected (data : List Nat) (i v : Nat) (h : Octets data) (hv : v < 256)
    (hi : i < data.length) (hne : v ≠ data.getD i 0) :
    checksum (data.set i v) ≠ checksum data := by
  rw [checksum_eq_rep _ (octets_set data i v h hv), checksum_eq_rep _ h]
  have hs := words_set_sum data i v hi
  have hold := getD_lt data i h
  unfold rep
  by_cases hc : i % 2 = 0
  · rw [if_pos hc, if_pos hc] at hs
    split <;> split <;> omega
  · rw [if_neg hc, if_neg hc] at hs
    split <;> split <;> omega

/-- A single flipped bit is always detected. -/
theorem one_bit_detected (data : List Nat) (i j : Nat) (h : Octets data) (hj : j < 8)
    (hi : i < data.length) :
    checksum (data.set i (data.getD i 0 ^^^ 2 ^ j)) ≠ checksum data := by
  have hb := getD_lt data i h
  apply one_octet_detected data i _ h _ hi
  · intro heq
    have := congrArg (fun x => x.testBit j) heq
    simp [Nat.testBit_xor, Nat.testBit_two_pow_self] at this
  · have : 2 ^ j < 2 ^ 8 := Nat.pow_lt_pow_right (by decide) hj
    exact Nat.xor_lt_two_pow (n := 8) hb this

/-! ## Vectors

`checksum.json`: cases for `ip::checksum`, `ip::fold`, two chained calls of
`ip::sum`, `ip::pseudo_header_sum` and `ip::transport_checksum`. Every
expected value is computed by the reference above (`checksum` over the
RFC layout, or `onesSum` of the words), never by the Rust model. -/

/-- A step of a 64-bit linear congruential generator (Knuth's MMIX
constants): deterministic per seed. -/
def step (s : Nat) : Nat := (s * 6364136223846793005 + 1442695040888963407) % 18446744073709551616

/-- `n` octets drawn from `seed`. -/
def octets (seed n : Nat) : List Nat := Id.run do
  let mut s := step seed
  let mut out := #[]
  for _ in [0:n] do
    s := step s
    out := out.push (s / 4294967296 % 256)
  return out.toList

open Lean (Json toJson)

def jsonOctets (data : List Nat) : Json := toJson data

/-- A case of one operation with named fields. -/
def case (op : String) (fields : List (String × Json)) : Json :=
  Json.mkObj (("op", Json.str op) :: fields)

def checksumCase (data : List Nat) : Json :=
  case "checksum" [("data", jsonOctets data), ("expected", toJson (checksum data))]

def foldCase (acc : Nat) : Json :=
  case "fold" [("acc", toJson acc), ("expected", toJson (65535 - rep acc))]

def splitCase (xs ys : List Nat) : Json :=
  case "split" [("a", jsonOctets xs), ("b", jsonOctets ys),
    ("expected", toJson (65535 - onesSum (words xs ++ words ys)))]

def pseudoCase (src dst : List Nat) (protocol len : Nat) (data : List Nat) : Json :=
  let expected := if src.length = 4 then checksum (pseudo4 src dst protocol len ++ data)
    else checksum (pseudo6 src dst protocol len ++ data)
  case "pseudo" [("src", jsonOctets src), ("dst", jsonOctets dst),
    ("protocol", toJson protocol), ("len", toJson len), ("data", jsonOctets data),
    ("expected", toJson expected)]

def transportCase (src dst : List Nat) (protocol : Nat) (data : List Nat) : Json :=
  let len := data.length
  let expected := if src.length = 4 then checksum (pseudo4 src dst protocol len ++ data)
    else checksum (pseudo6 src dst protocol len ++ data)
  case "transport" [("src", jsonOctets src), ("dst", jsonOctets dst),
    ("protocol", toJson protocol), ("data", jsonOctets data), ("expected", toJson expected)]

def checksumVectors (seed : Nat) : List Json := Id.run do
  let mut out := #[]
  -- Every length from 0 to 64, random octets.
  for n in [0:65] do
    out := out.push (checksumCase (octets (seed * 1000 + n) n))
  -- All zeros (the sum is 0, the checksum 0xffff) and all ones (a nonzero
  -- multiple of 65535, the checksum 0x0000), even and odd lengths.
  for n in [0:12] do
    out := out.push (checksumCase (List.replicate n 0))
    out := out.push (checksumCase (List.replicate n 255))
  -- Data whose words sum to a multiple of 65535 with carries.
  for n in [1:9] do
    let d := octets (seed * 7 + n) (2 * n)
    let c := checksum d
    out := out.push (checksumCase (d ++ [c / 256, c % 256]))
    out := out.push (checksumCase (d ++ [255 - c / 256, 255 - c % 256]))
  -- Folds of edge sums and random 48-bit and 62-bit ones.
  for acc in [0, 1, 65534, 65535, 65536, 131070, 131071, 4294967295, 4294901760,
      65535 * 65537, 18446744073709551615 / 4] do
    out := out.push (foldCase acc)
  for i in [0:24] do
    let s := step (seed * 31 + i)
    out := out.push (foldCase (s % 281474976710656))
    out := out.push (foldCase (s / 4))
    out := out.push (foldCase (65535 * (s % 4294967296)))
  -- Two chained sums, either part odd or even.
  for i in [0:40] do
    let s := step (seed * 131 + i)
    let xs := octets s (s / 7 % 13)
    let ys := octets (s + 1) (s / 101 % 13)
    out := out.push (splitCase xs ys)
  -- Pseudo-headers with lengths at the edges, up to 2^32 - 1 for IPv6.
  for i in [0:24] do
    let s := step (seed * 977 + i)
    let data := octets (s + 3) (s % 23)
    let proto := [6, 17, 58, 1, s / 13 % 256][i % 5]!
    let len4 := [0, 1, 65535, 65534, data.length, s / 3 % 65536][i % 6]!
    let len6 := [0, 65535, 65536, 4294967295, 4294901760, data.length, s / 5 % 4294967296][i % 7]!
    out := out.push (pseudoCase (octets s 4) (octets (s + 1) 4) proto len4 data)
    out := out.push (pseudoCase (octets s 16) (octets (s + 2) 16) proto len6 data)
    out := out.push (transportCase (octets s 4) (octets (s + 1) 4) proto data)
    out := out.push (transportCase (octets s 16) (octets (s + 2) 16) proto data)
  return out.toList

/-- The vector files this module writes: `(file stem, cases)`. -/
def vectors (seed : Nat) : List (String × Lean.Json) :=
  [("checksum", Json.arr (checksumVectors seed).toArray)]

end Ip.Checksum
