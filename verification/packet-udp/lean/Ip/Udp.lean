import Lean
import Ip.Checksum
import Ip.Header

/-! UDP (RFC 768) and its checksum over IPv4 and IPv6 (RFC 8200 section
8.1, RFC 1122 section 4.1.3).

The reference here is RFC 768 read plainly: `parse` is
`Datagram::parse`, `checksumOk` is `ip::udp_checksum_ok` and
`Datagram::checksum_ok`, `encode` is `udp::encode` and `encodedLen` is
`udp::encoded_len`, in `src/stdlib/network/udp/wire.rs` and
`src/stdlib/network/ip.rs`. Addresses are octet lists: 4 octets for IPv4,
16 for IPv6. -/

namespace Ip.Udp

open Ip.Checksum
open Ip.Header (get be16)

/-- `Datagram::parse`: a datagram's octets end at its length field, which
counts the 8-octet header and the data (RFC 768, "Length"). Fewer than 8
octets, a length below 8 or a length past the octets is no datagram; octets
after the length are not the datagram's. -/
def parse (bytes : List Nat) : Option (List Nat) :=
  if bytes.length ≥ 8 ∧ 8 ≤ be16 (get bytes 4) (get bytes 5) ∧
      be16 (get bytes 4) (get bytes 5) ≤ bytes.length then
    some (bytes.take (be16 (get bytes 4) (get bytes 5)))
  else none

/-- The pseudo-header of the addresses' family, with the UDP length. -/
def pseudo (src dst : List Nat) (len : Nat) : List Nat :=
  if src.length = 4 then pseudo4 src dst 17 len else pseudo6 src dst 17 len

/-- Whether a datagram from `src` to `dst` has a good checksum. Addresses
of two families have no pseudo-header and never do. A zero checksum field
means "no checksum" over IPv4 (RFC 768) and is never valid over IPv6
(RFC 8200 section 8.1). Otherwise the checksum over the pseudo-header and
the datagram must verify. -/
def checksumOk (src dst udp : List Nat) : Bool :=
  if src.length ≠ dst.length ∨ udp.length < 8 then false
  else if get udp 6 = 0 ∧ get udp 7 = 0 then src.length = 4
  else checksum (pseudo src dst udp.length ++ udp) = 0

/-- The UDP header: ports, length and checksum, each 16 bits. -/
def header (sport dport len c : Nat) : List Nat :=
  [sport / 256, sport % 256, dport / 256, dport % 256, len / 256, len % 256, c / 256, c % 256]

/-- The checksum `encode` writes: the checksum over the pseudo-header and
the datagram with the field zero, with a computed 0 sent as 0xffff (RFC
768: "If the computed checksum is zero, it is transmitted as all ones";
RFC 8200 section 8.1). -/
def sentChecksum (src dst : List Nat) (sport dport : Nat) (payload : List Nat) : Nat :=
  let len := 8 + payload.length
  let c := checksum (pseudo src dst len ++ header sport dport len 0 ++ payload)
  if c = 0 then 65535 else c

/-- `udp::encode`: the header and the payload. -/
def encode (src dst : List Nat) (sport dport : Nat) (payload : List Nat) : List Nat :=
  header sport dport (8 + payload.length) (sentChecksum src dst sport dport payload) ++ payload

/-- Why `encoded_len` refuses. -/
inductive LenError
  | family
  | length
  deriving DecidableEq, Repr

/-- `udp::encoded_len`: the most data one IP packet with a basic header
holds, 65,535 less the 20-octet IPv4 header and the UDP header, or less
only the UDP header over IPv6, where the payload length leaves out the
fixed header. -/
def encodedLen (v4 mixed : Bool) (n : Nat) : Except LenError Nat :=
  if mixed then .error .family
  else if n > (if v4 then 65507 else 65527) then .error .length
  else .ok (8 + n)

/-! ## The Rust checksum code -/

/-- Rust's `udp_checksum_ok(src, dst, udp)` for addresses of one family:
`transport_checksum` is `fold(sum(pseudo_header_sum(...), udp))`. -/
def checksumOkRust (src dst udp : List Nat) : Bool :=
  if src.length ≠ dst.length ∨ udp.length < 8 then false
  else if get udp 6 = 0 ∧ get udp 7 = 0 then src.length = 4
  else transportChecksum src dst 17 udp = 0

theorem transport_eq (src dst data : List Nat) (hos : Octets src) (hod : Octets dst)
    (hd : Octets data) (hlen : (src.length = 4 ∧ dst.length = 4 ∧ data.length < 65536) ∨
      (src.length = 16 ∧ dst.length = 16 ∧ data.length < 4294967296)) :
    transportChecksum src dst 17 data = checksum (pseudo src dst data.length ++ data) := by
  unfold transportChecksum pseudo
  rcases hlen with ⟨h1, h2, h3⟩ | ⟨h1, h2, h3⟩
  · rw [if_pos h1]
    exact rust_pseudo4 src dst data 17 data.length h1 h2 hos hod hd (by omega) h3
  · rw [if_neg (by omega)]
    exact rust_pseudo6 src dst data 17 data.length h1 h2 hos hod hd (by omega) h3

/-- Rust's UDP checksum check is the reference's: the pseudo-header sum
with the length as one integer is the RFC 768 or RFC 8200 pseudo-header,
for every datagram of a length its family allows. -/
theorem rust_checksumOk (src dst udp : List Nat) (hos : Octets src) (hod : Octets dst)
    (hu : Octets udp) (hlen : (src.length = 4 ∧ dst.length = 4 ∧ udp.length < 65536) ∨
      (src.length = 16 ∧ dst.length = 16 ∧ udp.length < 4294967296)) :
    checksumOkRust src dst udp = checksumOk src dst udp := by
  unfold checksumOkRust checksumOk
  rw [transport_eq src dst udp hos hod hu hlen]

/-! ## What `parse` takes -/

/-- `Datagram::parse` takes exactly the octets whose length field is at
least 8 and within them, and reads up to that length, trailing octets left
out (RFC 768; RFC 1122 section 4.1.3.4 leaves trailing octets to IP's total
length). -/
theorem parse_some_iff (bytes d : List Nat) :
    parse bytes = some d ↔
      bytes.length ≥ 8 ∧ 8 ≤ be16 (get bytes 4) (get bytes 5) ∧
        be16 (get bytes 4) (get bytes 5) ≤ bytes.length ∧
        d = bytes.take (be16 (get bytes 4) (get bytes 5)) := by
  unfold parse
  split
  · rename_i h
    simp only [Option.some.injEq]
    constructor
    · intro hd; exact ⟨h.1, h.2.1, h.2.2, hd.symm⟩
    · intro hd; exact hd.2.2.2.symm
  · rename_i h
    simp only [reduceCtorEq, false_iff]
    intro hd
    exact h ⟨hd.1, hd.2.1, hd.2.2.1⟩

/-! ## The zero checksum -/

/-- A zero checksum field means "no checksum" over IPv4: the datagram is
taken whatever its octets (RFC 768). -/
theorem zero_field_v4 (src dst udp : List Nat) (hs : src.length = 4) (hd : dst.length = 4)
    (hl : 8 ≤ udp.length) (h6 : get udp 6 = 0) (h7 : get udp 7 = 0) :
    checksumOk src dst udp = true := by
  unfold checksumOk
  simp [hs, hd, h6, h7]
  omega

/-- A zero checksum field is never valid over IPv6 (RFC 8200 section 8.1:
"IPv6 receivers must discard UDP packets containing a zero checksum"). -/
theorem zero_field_v6 (src dst udp : List Nat) (hs : src.length = 16)
    (h6 : get udp 6 = 0) (h7 : get udp 7 = 0) :
    checksumOk src dst udp = false := by
  unfold checksumOk
  simp [hs, h6, h7]

/-! ## What `encode` writes -/

theorem header_octets (sport dport len c : Nat) (hs : sport < 65536) (hd : dport < 65536)
    (hl : len < 65536) (hc : c < 65536) : Octets (header sport dport len c) := by
  intro b hb
  simp [header] at hb
  omega

theorem pseudo_octets (src dst : List Nat) (len : Nat) (hos : Octets src) (hod : Octets dst)
    (hl : len < 65536) : Octets (pseudo src dst len) := by
  unfold pseudo pseudo4 pseudo6
  split <;>
  · exact octets_append.2 ⟨octets_append.2 ⟨hos, hod⟩, by intro b hb; simp at hb; omega⟩

theorem pseudo_even (src dst : List Nat) (len : Nat)
    (hlen : (src.length = 4 ∧ dst.length = 4) ∨ (src.length = 16 ∧ dst.length = 16)) :
    (pseudo src dst len).length % 2 = 0 := by
  unfold pseudo pseudo4 pseudo6
  split <;> simp <;> omega

theorem sentChecksum_range (src dst : List Nat) (sport dport : Nat) (payload : List Nat) :
    0 < sentChecksum src dst sport dport payload ∧ sentChecksum src dst sport dport payload < 65536 := by
  unfold sentChecksum
  dsimp only
  split
  · omega
  · have := checksum_lt (pseudo src dst (8 + payload.length) ++
      header sport dport (8 + payload.length) 0 ++ payload)
    omega

/-- What `encode` writes reads back: `parse` takes all of it, with the
ports and payload given, and its checksum field is never zero, so the
datagram is never sent with "no checksum" over either family. -/
theorem encode_parses (src dst : List Nat) (sport dport : Nat) (payload : List Nat)
    (hs : sport < 65536) (hd : dport < 65536) (hl : 8 + payload.length < 65536) :
    parse (encode src dst sport dport payload) = some (encode src dst sport dport payload) ∧
      be16 (get (encode src dst sport dport payload) 0)
        (get (encode src dst sport dport payload) 1) = sport ∧
      be16 (get (encode src dst sport dport payload) 2)
        (get (encode src dst sport dport payload) 3) = dport ∧
      (encode src dst sport dport payload).drop 8 = payload ∧
      ¬ (get (encode src dst sport dport payload) 6 = 0 ∧
        get (encode src dst sport dport payload) 7 = 0) := by
  have hc := sentChecksum_range src dst sport dport payload
  unfold encode header
  generalize sentChecksum src dst sport dport payload = c at hc
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · unfold parse
    split
    · rw [List.take_of_length_le]
      simp [Header.get, be16] <;> omega
    · rename_i hcond
      exfalso
      apply hcond
      simp [Header.get, be16] <;> omega
  · simp [Header.get, be16] <;> omega
  · simp [Header.get, be16] <;> omega
  · simp
  · simp [Header.get] <;> omega

/-- What `encode` writes verifies, over IPv4 and IPv6 (RFC 768, RFC 8200
section 8.1), including a computed checksum of zero sent as 0xffff. -/
theorem encode_verifies (src dst : List Nat) (sport dport : Nat) (payload : List Nat)
    (hos : Octets src) (hod : Octets dst) (hop : Octets payload)
    (hfam : (src.length = 4 ∧ dst.length = 4) ∨ (src.length = 16 ∧ dst.length = 16))
    (hs : sport < 65536) (hd : dport < 65536) (hl : 8 + payload.length < 65536) :
    checksumOk src dst (encode src dst sport dport payload) = true := by
  have hlen : (encode src dst sport dport payload).length = 8 + payload.length := by
    simp [encode, header]; omega
  have hparts := encode_parses src dst sport dport payload hs hd hl
  obtain ⟨_, _, _, _, hnz⟩ := hparts
  unfold checksumOk
  rw [if_neg (by rw [hlen]; omega), if_neg hnz, hlen]
  simp only [decide_eq_true_eq]
  -- The datagram as pseudo-header and front ++ field ++ payload.
  let len := 8 + payload.length
  let xs := pseudo src dst len ++ [sport / 256, sport % 256, dport / 256, dport % 256,
    len / 256, len % 256]
  have hxs : Octets xs := by
    apply octets_append.2
    refine ⟨pseudo_octets src dst len hos hod (by omega), ?_⟩
    intro b hb
    simp at hb
    omega
  have hxe : xs.length % 2 = 0 := by
    have := pseudo_even src dst len hfam
    simp only [xs, List.length_append, List.length_cons, List.length_nil]
    omega
  have hzero : pseudo src dst len ++ header sport dport len 0 ++ payload = xs ++ [0, 0] ++ payload := by
    simp [xs, header]
  have he : pseudo src dst len ++ encode src dst sport dport payload =
      xs ++ [sentChecksum src dst sport dport payload / 256,
        sentChecksum src dst sport dport payload % 256] ++ payload := by
    simp [xs, encode, header, len]
  rw [he]
  unfold sentChecksum
  dsimp only
  rw [show pseudo src dst (8 + payload.length) ++ header sport dport (8 + payload.length) 0 ++
    payload = xs ++ [0, 0] ++ payload from hzero]
  split
  · rename_i h0
    show checksum (xs ++ [255, 255] ++ payload) = 0
    rw [← zero_fields_agree xs payload hxs hop hxe ?_]
    · exact h0
    · intro hsum
      have hz : Octets (xs ++ [0, 0] ++ payload) := by
        apply octets_append.2; refine ⟨octets_append.2 ⟨hxs, ?_⟩, hop⟩
        intro b hb; simp at hb; omega
      rw [checksum_eq_rep _ hz] at h0
      simp only [List.append_assoc, words_append xs _ hxe, List.sum_append, List.cons_append,
        words, List.sum_cons, List.nil_append] at h0
      rw [show (words xs).sum + (0 * 256 + 0 + (words payload).sum) = 0 by omega] at h0
      simp [rep] at h0
  · exact verifies xs payload hxs hop hxe

/-! ## Errors the UDP checksum catches -/

/-- One changed octet anywhere in a datagram that verified, the length
field included, fails the checksum over IPv6. Over IPv4 it fails too,
unless it leaves a checksum field of zero, which reads as "no checksum"
(RFC 768). -/
theorem one_octet_fails (src dst udp : List Nat) (i v : Nat) (hos : Octets src)
    (hod : Octets dst) (hu : Octets udp)
    (hfam : (src.length = 4 ∧ dst.length = 4) ∨ (src.length = 16 ∧ dst.length = 16))
    (hul : udp.length < 65536) (hv : v < 256) (hi : i < udp.length) (hne : v ≠ udp.getD i 0)
    (hok : checksumOk src dst udp = true)
    (hfield : ¬ (get udp 6 = 0 ∧ get udp 7 = 0))
    (hnew : ¬ (get (udp.set i v) 6 = 0 ∧ get (udp.set i v) 7 = 0)) :
    checksumOk src dst (udp.set i v) = false := by
  unfold checksumOk at hok ⊢
  have hsl : (udp.set i v).length = udp.length := List.length_set
  rw [hsl, if_neg hnew]
  split at hok
  · cases hok
  · rename_i hfl
    try rw [if_neg hfield] at hok
    rw [if_neg hfl]
    simp only [decide_eq_true_eq] at hok
    simp only [decide_eq_false_iff_not]
    have hset : pseudo src dst udp.length ++ udp.set i v =
        (pseudo src dst udp.length ++ udp).set ((pseudo src dst udp.length).length + i) v := by
      rw [List.set_append_right _ _ (by omega)]
      simp
    rw [hset]
    have hall : Octets (pseudo src dst udp.length ++ udp) :=
      octets_append.2 ⟨pseudo_octets src dst udp.length hos hod hul, hu⟩
    have := one_octet_detected (pseudo src dst udp.length ++ udp)
      ((pseudo src dst udp.length).length + i) v hall hv (by simp; omega) (by
        rw [List.getD_eq_getElem?_getD, List.getElem?_append_right (by omega),
          Nat.add_sub_cancel_left, ← List.getD_eq_getElem?_getD]
        exact hne)
    rw [hok] at this
    exact this

/-! ## `encoded_len` -/

/-- `encoded_len` refuses mixed families, and otherwise takes a payload
exactly when the datagram fits one IP packet with a basic header, so the
16-bit UDP length and IP length that `encode` and `packet` write never
wrap. -/
theorem encodedLen_ok (v4 : Bool) (n m : Nat) :
    encodedLen v4 false n = .ok m ↔ m = 8 + n ∧ m + (if v4 then 20 else 0) ≤ 65535 := by
  cases v4
  · by_cases h : n > 65527 <;> simp [encodedLen, h] <;> omega
  · by_cases h : n > 65507 <;> simp [encodedLen, h] <;> omega

theorem encodedLen_mixed (v4 : Bool) (n : Nat) : encodedLen v4 true n = .error .family := by
  simp [encodedLen]

/-! ## Vectors

`udp.json`: `parse` over random octets with every length-field case,
`checksum_ok` over encoded datagrams, changed ones, zero fields and mixed
families, `encode` (with payloads whose checksum comes out 0), and
`encoded_len` at its limits. -/

open Lean (Json toJson)

def setLen (bytes : List Nat) (len : Nat) : List Nat :=
  (bytes.set 4 (len / 256)).set 5 (len % 256)

def parseCase (bytes : List Nat) : Json :=
  Json.mkObj [("op", Json.str "parse"), ("bytes", toJson bytes),
    ("expected", match parse bytes with
      | none => Json.null
      | some d => Json.mkObj [("src_port", toJson (be16 (get d 0) (get d 1))),
          ("dst_port", toJson (be16 (get d 2) (get d 3))), ("length", toJson d.length),
          ("payload", toJson (d.drop 8))])]

def checksumCase (src dst udp : List Nat) : Json :=
  Json.mkObj [("op", Json.str "checksum_ok"), ("src", toJson src), ("dst", toJson dst),
    ("udp", toJson udp), ("expected", toJson (checksumOk src dst udp))]

def encodeCase (src dst : List Nat) (sport dport : Nat) (payload : List Nat) : Json :=
  Json.mkObj [("op", Json.str "encode"), ("src", toJson src), ("dst", toJson dst),
    ("src_port", toJson sport), ("dst_port", toJson dport), ("payload", toJson payload),
    ("expected", toJson (encode src dst sport dport payload))]

def lenCase (v4 mixed : Bool) (n : Nat) : Json :=
  Json.mkObj [("op", Json.str "encoded_len"), ("v4", toJson v4), ("mixed", toJson mixed),
    ("len", toJson n),
    ("expected", match encodedLen v4 mixed n with
      | .ok m => toJson m
      | .error .family => Json.str "family"
      | .error .length => Json.str "length")]

/-- A payload whose last two octets make the checksum come out 0 before
the 0xffff rule, so `encode` must write 0xffff. -/
def zeroPayload (src dst : List Nat) (sport dport : Nat) (front : List Nat) : List Nat :=
  let len := 8 + front.length + 2
  let s := (words (pseudo src dst len ++ header sport dport len 0 ++ front ++ [0, 0])).sum
  let w := 65535 - rep s
  front ++ [w / 256, w % 256]

def udpVectors (seed : Nat) : List Json := Id.run do
  let mut out := #[]
  for i in [0:60] do
    let s := step (seed * 7727 + i)
    let n := s % 24
    let bytes := octets s n
    let t := step s
    for len in [t % 8, 8, n, n + 1 + t / 3 % 5, 8 + t / 7 % 12, 65535] do
      out := out.push (parseCase (setLen bytes len))
  for i in [0:60] do
    let s := step (seed * 6151 + i)
    let v6 := s % 2 = 0
    let src := octets s (if v6 then 16 else 4)
    let dst := octets (s + 1) (if v6 then 16 else 4)
    let sport := s / 3 % 65536
    let dport := s / 5 % 65536
    let front := octets (s + 2) (s / 7 % 20)
    let payload := if i % 4 = 0 then zeroPayload src dst sport dport front else front
    out := out.push (encodeCase src dst sport dport payload)
    let d := encode src dst sport dport payload
    out := out.push (checksumCase src dst d)
    -- one octet changed
    let t := step s
    let at_ := t % d.length
    let v := (get d at_ + 1 + t / 3 % 255) % 256
    out := out.push (checksumCase src dst (d.set at_ v))
    -- the zero field and the other zero
    out := out.push (checksumCase src dst ((d.set 6 0).set 7 0))
    out := out.push (checksumCase src dst ((d.set 6 255).set 7 255))
    -- the other family's addresses, and mixed families
    out := out.push (checksumCase (octets s (if v6 then 4 else 16)) dst ((d.set 6 0).set 7 0))
    out := out.push (checksumCase src (octets s (if v6 then 4 else 16)) d)
    -- too short
    out := out.push (checksumCase src dst (d.take (t / 7 % 8)))
  for n in [0, 1, 65506, 65507, 65508, 65526, 65527, 65528, 1000000] do
    out := out.push (lenCase true false n)
    out := out.push (lenCase false false n)
    out := out.push (lenCase true true n)
    out := out.push (lenCase false true n)
  return out.toList

/-- The vector files this module writes: `(file stem, cases)`. -/
def vectors (seed : Nat) : List (String × Lean.Json) :=
  [("udp", Json.arr (udpVectors seed).toArray)]

end Ip.Udp
