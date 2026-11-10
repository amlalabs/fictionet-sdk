import Lean
import Ip.Checksum

/-! IPv4 header validation (RFC 791 section 3.1, RFC 1122 section 3.2.1),
the header builders, and the router hop (RFC 1812 section 5.3.1, RFC 1624).

`v4` is RFC 791's header read plainly, with the length rules of RFC 1122
section 3.2.1.1 and RFC 791's total length; `check` adds the header
checksum (RFC 1122 section 3.2.1.2) and the source address rules (RFC 1122
section 3.2.1.3). They follow `v4`, `v4_checked`, `Header::check`,
`Header::parse_whole`, `Header::payload` and `Header::dst_port` in
`src/stdlib/network/ip.rs`. `build` is `packet_with` and
`packet_with_ipv4_options`, and `hop` is `hop`, byte for byte. -/

namespace Ip.Header

open Ip.Checksum

/-- The octet at `i`, or 0 past the end. -/
def get (bytes : List Nat) (i : Nat) : Nat := bytes.getD i 0

/-- A big-endian 16-bit field. -/
def be16 (a b : Nat) : Nat := a * 256 + b

/-- An IPv4 fragment's fields: identification, offset in octets, and
"more fragments". -/
structure Fragment where
  id : Nat
  offset : Nat
  more : Bool
  deriving DecidableEq, Repr

/-- What `Header` holds for an IPv4 packet: addresses, protocol, the
payload's range `[start, stop)`, the total length, and the fragment. -/
structure Parsed where
  src : List Nat
  dst : List Nat
  protocol : Nat
  start : Nat
  stop : Nat
  length : Nat
  fragment : Option Fragment
  deriving DecidableEq, Repr

/-- The rules an IPv4 header must meet to be read (RFC 791 section 3.1):
version 4, a header length (IHL, in 32-bit words) of at least 5 that fits
the bytes, and a total length no shorter than the header and, unless the
packet may be cut short (`truncated`, the copy inside an ICMP error), no
longer than the bytes. -/
def Readable (bytes : List Nat) (truncated : Bool) : Prop :=
  bytes.length ≥ 20 ∧ get bytes 0 / 16 = 4 ∧ get bytes 0 % 16 * 4 ≥ 20 ∧
    get bytes 0 % 16 * 4 ≤ bytes.length ∧
    get bytes 0 % 16 * 4 ≤ be16 (get bytes 2) (get bytes 3) ∧
    (truncated = true ∨ be16 (get bytes 2) (get bytes 3) ≤ bytes.length)

instance (bytes : List Nat) (truncated : Bool) : Decidable (Readable bytes truncated) := by
  unfold Readable; infer_instance

/-- The fragment fields (RFC 791 section 3.1): the flags word is octets 6
and 7; bit 0x8000 is reserved and bit 0x4000 is "don't fragment", neither
of which makes a fragment. A packet is a fragment when "more fragments"
(0x2000) is set or the offset (the low 13 bits, in units of 8 octets) is
not 0. -/
def fragmentOf (bytes : List Nat) : Option Fragment :=
  let flags := be16 (get bytes 6) (get bytes 7)
  if flags % 16384 = 0 then none
  else some { id := be16 (get bytes 4) (get bytes 5), offset := flags % 8192 * 8,
              more := flags / 8192 % 2 = 1 }

/-- An IPv4 header read without its checksum (`Header::parse`, and
`Header::parse_truncated` with `truncated`). The payload runs from the
header length to the total length, cut to the bytes present; bytes past the
total length are not the packet's. -/
def v4 (bytes : List Nat) (truncated : Bool) : Option Parsed :=
  if Readable bytes truncated then
    let total := be16 (get bytes 2) (get bytes 3)
    some { src := (bytes.drop 12).take 4, dst := (bytes.drop 16).take 4,
           protocol := get bytes 9, start := get bytes 0 % 16 * 4,
           stop := min total bytes.length, length := total, fragment := fragmentOf bytes }
  else none

/-- A source address a host must not take a packet from (RFC 1122 section
3.2.1.3): the limited broadcast address 255.255.255.255 (case (c)) or a
class D multicast address, 224.0.0.0/4 (case (e)). -/
def badSource (src : List Nat) : Bool :=
  src == [255, 255, 255, 255] || (224 ≤ src.getD 0 0 && src.getD 0 0 < 240)

/-- An IPv4 header as a host that is the packet's destination takes it in
(`Header::check`): readable as a whole packet, with a header checksum that
verifies (RFC 1122 section 3.2.1.2), from a source a host may hear from
(section 3.2.1.3). -/
def check (bytes : List Nat) : Option Parsed :=
  match v4 bytes false with
  | some h => if checksum (bytes.take h.start) = 0 ∧ badSource h.src = false then some h else none
  | none => none

/-- `Header::parse_whole`: `check`, and not a fragment. -/
def whole (bytes : List Nat) : Option Parsed :=
  match check bytes with
  | some h => if h.fragment = none then some h else none
  | none => none

/-- `Header::payload`. -/
def payload (h : Parsed) (bytes : List Nat) : List Nat :=
  (bytes.drop h.start).take (h.stop - h.start)

/-- `Header::dst_port`: the destination port of a TCP (6) or UDP (17)
packet, which is octets 2 and 3 of the payload. None for another protocol,
for a fragment after the first, or when the payload is shorter than 4. -/
def dstPort (h : Parsed) (bytes : List Nat) : Option Nat :=
  if (match h.fragment with | some f => f.offset != 0 | none => false) then none
  else if h.protocol ≠ 6 ∧ h.protocol ≠ 17 then none
  else if (payload h bytes).length ≥ 4 then
    some (be16 (get (payload h bytes) 2) (get (payload h bytes) 3))
  else none

/-! ## What `v4` and `check` accept -/

/-- `Header::parse` and `parse_truncated` take a header exactly when
RFC 791's length rules hold. -/
theorem v4_some_iff (bytes : List Nat) (truncated : Bool) :
    (v4 bytes truncated).isSome ↔ Readable bytes truncated := by
  unfold v4; split <;> simp_all

/-- The payload of a read header lies inside the bytes, from the header
length to the total length; a header read whole ends at the total length,
and one read from a cut packet at the bytes present. -/
theorem v4_payload (bytes : List Nat) (truncated : Bool) (h : Parsed)
    (hv : v4 bytes truncated = some h) :
    20 ≤ h.start ∧ h.start ≤ h.stop ∧ h.stop ≤ bytes.length ∧ h.start = get bytes 0 % 16 * 4 ∧
      h.length = be16 (get bytes 2) (get bytes 3) ∧
      (truncated = false → h.stop = h.length) := by
  unfold v4 at hv
  split at hv
  · rename_i hr
    unfold Readable at hr
    cases hv
    dsimp only
    refine ⟨by omega, by omega, by omega, rfl, rfl, ?_⟩
    intro ht; subst ht; simp at hr; omega
  · cases hv

/-- `Header::check` takes exactly what `parse` reads whose header checksum
verifies (RFC 1122 section 3.2.1.2) and whose source is not broadcast or
multicast (section 3.2.1.3). -/
theorem check_some_iff (bytes : List Nat) (h : Parsed) :
    check bytes = some h ↔
      v4 bytes false = some h ∧ checksum (bytes.take h.start) = 0 ∧ badSource h.src = false := by
  unfold check
  split
  · rename_i h' hv
    constructor
    · intro hc
      split at hc
      · cases hc; exact ⟨hv, by simp_all⟩
      · cases hc
    · rintro ⟨hv', hc, hs⟩
      rw [hv] at hv'; cases hv'
      simp [hc, hs]
  · rename_i hv
    simp only [reduceCtorEq, false_iff]
    rintro ⟨hv', _⟩
    rw [hv'] at hv
    cases hv

/-- `Header::parse_whole` takes no fragment, and takes what `check` takes
otherwise. -/
theorem whole_some_iff (bytes : List Nat) (h : Parsed) :
    whole bytes = some h ↔ check bytes = some h ∧ h.fragment = none := by
  unfold whole
  split
  · rename_i h' hc
    rw [hc]
    constructor
    · intro hw; split at hw
      · cases hw; simp_all
      · cases hw
    · rintro ⟨hh, hf⟩; cases hh; simp [hf]
  · rename_i hc
    constructor
    · intro hw; cases hw
    · rintro ⟨hh, _⟩; rw [hh] at hc; cases hc

theorem get_set_ne (bytes : List Nat) (i j v : Nat) (h : i ≠ j) :
    get (bytes.set i v) j = get bytes j := by
  unfold get
  simp [List.getD_eq_getElem?_getD, List.getElem?_set, h]

/-- The reader does not look at the type of service (octet 1), the TTL
(octet 8) or the checksum field (octets 10 and 11): a host does not
discard a packet for its TTL (RFC 1122 section 3.2.1.7), and only `check`
reads the checksum. -/
theorem v4_ignores (bytes : List Nat) (truncated : Bool) (i v : Nat)
    (hi : i = 1 ∨ i = 8 ∨ i = 10 ∨ i = 11) :
    v4 (bytes.set i v) truncated = v4 bytes truncated := by
  have hne : ∀ j, j ∈ [0, 2, 3, 4, 5, 6, 7, 9] → get (bytes.set i v) j = get bytes j := by
    intro j hj
    apply get_set_ne
    simp at hj
    omega
  have hd12 : (bytes.set i v).drop 12 = bytes.drop 12 := by
    apply List.drop_set_of_lt; omega
  have hd16 : (bytes.set i v).drop 16 = bytes.drop 16 := by
    apply List.drop_set_of_lt; omega
  have h0 := hne 0 (by simp)
  have h2 := hne 2 (by simp)
  have h3 := hne 3 (by simp)
  have h4 := hne 4 (by simp)
  have h5 := hne 5 (by simp)
  have h6 := hne 6 (by simp)
  have h7 := hne 7 (by simp)
  have h9 := hne 9 (by simp)
  unfold v4 Readable fragmentOf
  simp only [List.length_set, h0, h2, h3, h4, h5, h6, h7, h9, hd12, hd16]

/-- The reserved flag (0x8000) and "don't fragment" (0x4000) change
nothing a reader returns. -/
theorem v4_ignores_flag_bits (bytes : List Nat) (truncated : Bool) (v : Nat)
    (hv : v % 64 = get bytes 6 % 64) :
    v4 (bytes.set 6 v) truncated = v4 bytes truncated := by
  have hne : ∀ j, j ∈ [0, 2, 3, 4, 5, 7, 9] → get (bytes.set 6 v) j = get bytes j := by
    intro j hj
    apply get_set_ne
    simp at hj
    omega
  have hd12 : (bytes.set 6 v).drop 12 = bytes.drop 12 := by
    apply List.drop_set_of_lt; omega
  have hd16 : (bytes.set 6 v).drop 16 = bytes.drop 16 := by
    apply List.drop_set_of_lt; omega
  have h0 := hne 0 (by simp)
  have h2 := hne 2 (by simp)
  have h3 := hne 3 (by simp)
  have h4 := hne 4 (by simp)
  have h5 := hne 5 (by simp)
  have h7 := hne 7 (by simp)
  have h9 := hne 9 (by simp)
  by_cases hl : 6 < bytes.length
  · have h6 : get (bytes.set 6 v) 6 = v := by
      unfold get; simp [List.getD_eq_getElem?_getD, List.getElem?_set, hl]
    have hfrag : fragmentOf (bytes.set 6 v) = fragmentOf bytes := by
      unfold fragmentOf
      simp only [h4, h5, h6, h7, be16]
      have e1 : (v * 256 + get bytes 7) % 16384 = (get bytes 6 * 256 + get bytes 7) % 16384 := by
        omega
      have e2 : (v * 256 + get bytes 7) % 8192 = (get bytes 6 * 256 + get bytes 7) % 8192 := by
        omega
      have e3 : (v * 256 + get bytes 7) / 8192 % 2 = (get bytes 6 * 256 + get bytes 7) / 8192 % 2 := by
        omega
      by_cases hz : (get bytes 6 * 256 + get bytes 7) % 16384 = 0
      · simp [hz, e1]
      · simp [hz, e1, e2, e3] <;> exact decide_eq_decide.mpr Iff.rfl
    unfold v4 Readable
    simp only [List.length_set, h0, h2, h3, h9, hd12, hd16, hfrag]
  · rw [List.set_eq_of_length_le (by omega)]

/-- `dst_port` gives no port for a fragment after the first, or for a
protocol other than TCP and UDP. -/
theorem dstPort_none (h : Parsed) (bytes : List Nat)
    (hf : (∃ f, h.fragment = some f ∧ f.offset ≠ 0) ∨ (h.protocol ≠ 6 ∧ h.protocol ≠ 17)) :
    dstPort h bytes = none := by
  unfold dstPort
  rcases hf with ⟨f, hf, ho⟩ | hp
  · rw [hf]
    simp [ho]
  · split <;> simp [hp]

/-! ## The builders -/

/-- The octets of the header fields before the checksum. -/
def front (hl total tos id : Nat) (df : Bool) (ttl protocol : Nat) : List Nat :=
  [64 + hl / 4, tos, total / 256, total % 256, id / 256, id % 256,
   if df then 64 else 0, 0, ttl, protocol]

/-- The header length for `n` octets of options: padded with zero octets
to a multiple of four. -/
def headerLen (n : Nat) : Nat := 20 + (n + 3) / 4 * 4

/-- `packet_with_ipv4_options(src, dst, protocol, fields, options,
payload)` for option octets `options` (and `packet_with` for none): the
header, its checksum computed over it with the field zero (as
`set_header_checksum` does: `fold(sum(0, header))` is `checksum` by
`rust_checksum`), and the payload. -/
def build (src dst : List Nat) (protocol ttl tos id : Nat) (df : Bool)
    (options payload : List Nat) : List Nat :=
  let hl := headerLen options.length
  let total := hl + payload.length
  let rest := src ++ dst ++ options ++ List.replicate (hl - 20 - options.length) 0
  let c := checksum (front hl total tos id df ttl protocol ++ [0, 0] ++ rest)
  front hl total tos id df ttl protocol ++ [c / 256, c % 256] ++ rest ++ payload

/-- `packet_with` over IPv6: version 6, the traffic class, a zero flow
label, the payload length, the next header and the hop limit. -/
def build6 (src dst : List Nat) (protocol ttl tos : Nat) (payload : List Nat) : List Nat :=
  [96 + tos / 16, tos % 16 * 16, 0, 0, payload.length / 256, payload.length % 256,
   protocol, ttl] ++ src ++ dst ++ payload

theorem front_length (hl total tos id : Nat) (df : Bool) (ttl protocol : Nat) :
    (front hl total tos id df ttl protocol).length = 10 := by
  simp [front]

theorem front_octets (hl total tos id : Nat) (df : Bool) (ttl protocol : Nat)
    (hhl : hl < 64) (ht : total < 65536) (htos : tos < 256) (hid : id < 65536)
    (httl : ttl < 256) (hp : protocol < 256) :
    Octets (front hl total tos id df ttl protocol) := by
  intro b hb
  simp only [front, List.mem_cons, List.not_mem_nil] at hb
  cases df <;> simp at hb <;> omega

/-- The header `check` reads from a built packet. -/
def built (src dst : List Nat) (protocol hl plen : Nat) : Parsed :=
  { src := src, dst := dst, protocol := protocol, start := hl, stop := hl + plen,
    length := hl + plen, fragment := none }

/-- What the builders write reads back (RFC 791 section 3.1): for every
pair of addresses, protocol, TTL, type of service, identification and
"don't fragment" flag, all option octets up to 40 and every payload that
fits, `check` takes the packet, with its addresses and protocol, the
header length the options make, the payload as given, and no fragment, so
its header checksum verifies. The source must be one a host may hear from
(`badSource`), as `check` asks. -/
theorem build_checks (src dst options data : List Nat) (protocol ttl tos id : Nat)
    (df : Bool) (hs : src.length = 4) (hd : dst.length = 4) (hos : Octets src)
    (hod : Octets dst) (hoo : Octets options) (hopt : options.length ≤ 40)
    (hp : protocol < 256) (httl : ttl < 256) (htos : tos < 256) (hid : id < 65536)
    (hlen : headerLen options.length + data.length < 65536)
    (hsrc : badSource src = false) :
    check (build src dst protocol ttl tos id df options data) =
        some (built src dst protocol (headerLen options.length) data.length) ∧
      payload (built src dst protocol (headerLen options.length) data.length)
        (build src dst protocol ttl tos id df options data) = data := by
  have hl20 : 20 + options.length ≤ headerLen options.length := by unfold headerLen; omega
  have hl60 : headerLen options.length ≤ 60 := by unfold headerLen; omega
  have hl4 : headerLen options.length % 4 = 0 := by unfold headerLen; omega
  unfold build
  dsimp only
  generalize headerLen options.length = hl at *
  have hfo := front_octets hl (hl + data.length) tos id df ttl protocol
    (by omega) hlen htos hid httl hp
  have hro : Octets (src ++ dst ++ options ++ List.replicate (hl - 20 - options.length) 0) :=
    octets_append.2 ⟨octets_append.2 ⟨octets_append.2 ⟨hos, hod⟩, hoo⟩,
      fun b hb => by rw [(List.mem_replicate.1 hb).2]; omega⟩
  have hver := verifies _ _ hfo hro (by simp [front_length])
  have hrl : (src ++ dst ++ options ++ List.replicate (hl - 20 - options.length) 0).length =
      hl - 12 := by simp; omega
  have hsrc4 : ((src ++ dst ++ options ++ List.replicate (hl - 20 - options.length) 0) ++
      data).take 4 = src := by
    simp only [List.append_assoc]
    rw [List.take_left' hs]
  have hdst4 : (((src ++ dst ++ options ++ List.replicate (hl - 20 - options.length) 0) ++
      data).drop 4).take 4 = dst := by
    simp only [List.append_assoc]
    rw [List.drop_left' hs, List.take_left' hd]
  have hcl := checksum_lt (front hl (hl + data.length) tos id df ttl protocol ++ [0, 0] ++
    (src ++ dst ++ options ++ List.replicate (hl - 20 - options.length) 0))
  generalize checksum (front hl (hl + data.length) tos id df ttl protocol ++ [0, 0] ++
    (src ++ dst ++ options ++ List.replicate (hl - 20 - options.length) 0)) = c at *
  generalize src ++ dst ++ options ++ List.replicate (hl - 20 - options.length) 0 = rest at *
  have hhdr : (front hl (hl + data.length) tos id df ttl protocol ++ [c / 256, c % 256] ++
      rest ++ data).take hl =
      front hl (hl + data.length) tos id df ttl protocol ++ [c / 256, c % 256] ++ rest := by
    rw [List.take_left']
    simp [front_length]; omega
  have hpl : (front hl (hl + data.length) tos id df ttl protocol ++ [c / 256, c % 256] ++
      rest ++ data).drop hl = data := by
    rw [List.drop_left']
    simp [front_length]; omega
  have hread : v4 (front hl (hl + data.length) tos id df ttl protocol ++ [c / 256, c % 256] ++
      rest ++ data) false = some (built src dst protocol hl data.length) := by
    have hR : Readable (front hl (hl + data.length) tos id df ttl protocol ++
        [c / 256, c % 256] ++ rest ++ data) false := by
      unfold Readable get be16
      simp only [front, List.cons_append, List.nil_append, List.length_cons,
        List.length_append, List.getD_cons_succ, List.getD_cons_zero]
      exact ⟨by omega, by omega, by omega, by omega, by omega, Or.inr (by omega)⟩
    unfold v4
    rw [if_pos hR]
    unfold fragmentOf built get be16
    simp only [front, List.cons_append, List.nil_append, List.length_cons,
      List.length_append, List.getD_cons_succ, List.getD_cons_zero, List.drop_succ_cons,
      List.drop_zero, hsrc4, hdst4]
    cases df <;> simp <;> omega
  constructor
  · unfold check
    rw [hread]
    have hck : checksum ((front hl (hl + data.length) tos id df ttl protocol ++
        [c / 256, c % 256] ++ rest ++ data).take (built src dst protocol hl data.length).start) =
        0 := by
      simp only [built]
      rw [hhdr]
      exact hver
    have hbs : badSource (built src dst protocol hl data.length).src = false := by
      simpa [built] using hsrc
    simp only [hck, hbs, and_self, if_true]
  · unfold payload built
    simp only [Nat.add_sub_cancel_left, hpl]
    exact List.take_length

/-! ## The router hop -/

/-- What `hop` did: `Hop::Forward`, `Hop::Expired` or `Hop::NotIp`. -/
inductive HopResult
  | forward
  | expired
  | notIp
  deriving DecidableEq, Repr

/-- The checksum `hop` writes, RFC 1624 equation 3: HC' = ~(~HC + ~m + m'),
where m is the old 16-bit word holding the TTL and the protocol, and m' the
new one. `!hc` and `!old` are 16-bit complements, and `fold` complements
the folded sum. -/
def hopChecksum (ttl protocol hc0 hc1 : Nat) : Nat :=
  fold ((65535 - be16 hc0 hc1) + (65535 - be16 ttl protocol) + be16 (ttl - 1) protocol)

/-- Rust's `hop(packet)`. -/
def hop (p : List Nat) : HopResult × List Nat :=
  if get p 0 / 16 = 4 ∧ p.length ≥ 20 then
    if get p 8 ≤ 1 then (.expired, p)
    else
      let c := hopChecksum (get p 8) (get p 9) (get p 10) (get p 11)
      (.forward, ((p.set 8 (get p 8 - 1)).set 10 (c / 256)).set 11 (c % 256))
  else if get p 0 / 16 = 6 ∧ p.length ≥ 40 then
    if get p 7 ≤ 1 then (.expired, p) else (.forward, p.set 7 (get p 7 - 1))
  else (.notIp, p)

/-- Rust's `set_header_checksum(header)`: the field zeroed, the checksum
computed (`fold(sum(0, header))`, which is `checksum` by `rust_checksum`)
and written. -/
def setHeaderChecksum (h : List Nat) : List Nat :=
  let z := (h.set 10 0).set 11 0
  (z.set 10 (checksum z / 256)).set 11 (checksum z % 256)

/-- A router drops an IPv4 packet whose TTL is 0 or 1 and leaves it as it
was (RFC 1812 section 5.3.1), and forwards any other. -/
theorem hop_v4_expired (p : List Nat) (hv : get p 0 / 16 = 4) (hl : 20 ≤ p.length) :
    ((hop p).1 = .expired ↔ get p 8 ≤ 1) ∧ (get p 8 ≤ 1 → (hop p).2 = p) := by
  unfold hop
  rw [if_pos ⟨hv, hl⟩]
  by_cases ht : get p 8 ≤ 1 <;> simp [ht]

/-- A router drops an IPv6 packet whose hop limit is 0 or 1, and otherwise
lowers it by one and changes nothing else (RFC 8200 section 3; IPv6 has no
header checksum). -/
theorem hop_v6 (p : List Nat) (hv : get p 0 / 16 = 6) (hl : 40 ≤ p.length) :
    hop p = if get p 7 ≤ 1 then (.expired, p) else (.forward, p.set 7 (get p 7 - 1)) := by
  unfold hop
  rw [if_neg (by omega), if_pos ⟨hv, hl⟩]

/-- The packet `hop` forwards over IPv4: the TTL lowered by one, the
checksum field rewritten, and every other octet, the payload included, as
it was. -/
theorem hop_v4 (b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 : Nat) (tail : List Nat)
    (hv : b0 / 16 = 4) (hl : 8 ≤ tail.length) (ht : 1 < b8) :
    hop ([b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11] ++ tail) =
      (.forward, [b0, b1, b2, b3, b4, b5, b6, b7, b8 - 1, b9,
        hopChecksum b8 b9 b10 b11 / 256, hopChecksum b8 b9 b10 b11 % 256] ++ tail) := by
  unfold hop
  simp only [get, List.cons_append, List.nil_append, List.length_cons, List.getD_cons_succ,
    List.getD_cons_zero, List.set_cons_succ, List.set_cons_zero]
  rw [if_pos ⟨hv, by omega⟩, if_neg (by omega)]

set_option maxRecDepth 8000 in
/-- The incremental update keeps the header's checksum: the header after
the hop has the same checksum as before (RFC 1624 section 3). A header that
verified still verifies, and one that did not still does not, so a router
never repairs a corrupted header. The header is the 12 octets before the
addresses and `rest`, the addresses and options, of an even length (IHL ·
4 - 12). -/
theorem hop_keeps_checksum (b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 : Nat) (rest : List Nat)
    (hb : Octets [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11]) (hr : Octets rest)
    (hv : b0 / 16 = 4) (ht : 1 < b8) :
    checksum ([b0, b1, b2, b3, b4, b5, b6, b7, b8 - 1, b9,
        hopChecksum b8 b9 b10 b11 / 256, hopChecksum b8 b9 b10 b11 % 256] ++ rest) =
      checksum ([b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11] ++ rest) := by
  have h0 := hb b0 (by simp)
  have h8 := hb b8 (by simp)
  have h9 := hb b9 (by simp)
  have h10 := hb b10 (by simp)
  have h11 := hb b11 (by simp)
  have hcl : hopChecksum b8 b9 b10 b11 < 65536 := by unfold hopChecksum fold; omega
  have ho : Octets ([b0, b1, b2, b3, b4, b5, b6, b7, b8 - 1, b9,
      hopChecksum b8 b9 b10 b11 / 256, hopChecksum b8 b9 b10 b11 % 256] ++ rest) := by
    refine octets_append.2 ⟨?_, hr⟩
    intro b hb'
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hb'
    rcases hb' with h | h | h | h | h | h | h | h | h | h | h | h <;>
      first | omega | exact hb _ (by simp [h])
  rw [checksum_eq_rep _ ho, checksum_eq_rep _ (octets_append.2 ⟨hb, hr⟩)]
  simp only [List.cons_append, List.nil_append, words, List.sum_cons]
  congr 1
  have hy : rep (65535 - be16 b10 b11 + (65535 - be16 b8 b9) + be16 (b8 - 1) b9) =
      (65535 - be16 b10 b11 + (65535 - be16 b8 b9) + be16 (b8 - 1) b9 - 1) % 65535 + 1 := by
    unfold rep; split <;> unfold be16 at * <;> omega
  unfold hopChecksum fold at *
  rw [foldNat_eq_rep, hy]
  unfold be16 at *
  exact rep_congr (by omega) ⟨fun _ => by omega, fun _ => by omega⟩

set_option maxRecDepth 8000 in
/-- The incremental update writes what recomputing the checksum would:
for every header that verifies and every TTL above 1, the header after the
hop is the header with its TTL lowered and `set_header_checksum` run over
it (RFC 1624 sections 3 and 5). That holds for a received checksum of
0xffff too, where RFC 1141's equation 2 went wrong. -/
theorem hop_is_recompute (b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 : Nat) (rest : List Nat)
    (hb : Octets [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11]) (hr : Octets rest)
    (hv : b0 / 16 = 4) (ht : 1 < b8)
    (hverify : checksum ([b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11] ++ rest) = 0) :
    [b0, b1, b2, b3, b4, b5, b6, b7, b8 - 1, b9,
        hopChecksum b8 b9 b10 b11 / 256, hopChecksum b8 b9 b10 b11 % 256] ++ rest =
      setHeaderChecksum ([b0, b1, b2, b3, b4, b5, b6, b7, b8 - 1, b9, b10, b11] ++ rest) := by
  have h0 := hb b0 (by simp)
  have h8 := hb b8 (by simp)
  have h9 := hb b9 (by simp)
  have h10 := hb b10 (by simp)
  have h11 := hb b11 (by simp)
  have hz : Octets ([b0, b1, b2, b3, b4, b5, b6, b7, b8 - 1, b9, 0, 0] ++ rest) := by
    refine octets_append.2 ⟨?_, hr⟩
    intro b hb'
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hb'
    rcases hb' with h | h | h | h | h | h | h | h | h | h | h | h <;>
      first | omega | exact hb _ (by simp [h])
  unfold setHeaderChecksum
  simp only [List.cons_append, List.nil_append, List.set_cons_succ, List.set_cons_zero]
  have hc : hopChecksum b8 b9 b10 b11 =
      checksum (b0 :: b1 :: b2 :: b3 :: b4 :: b5 :: b6 :: b7 :: (b8 - 1) :: b9 :: 0 :: 0 :: rest) := by
    have hzc := checksum_eq_rep _ hz
    simp only [List.cons_append, List.nil_append] at hzc
    rw [hzc]
    rw [checksum_eq_rep _ (octets_append.2 ⟨hb, hr⟩)] at hverify
    simp only [List.cons_append, List.nil_append, words, List.sum_cons] at hverify ⊢
    have hlt := rep_lt (b0 * 256 + b1 + (b2 * 256 + b3 + (b4 * 256 + b5 + (b6 * 256 + b7 +
      (b8 * 256 + b9 + (b10 * 256 + b11 + (words rest).sum))))))
    have hy : rep (65535 - be16 b10 b11 + (65535 - be16 b8 b9) + be16 (b8 - 1) b9) =
        (65535 - be16 b10 b11 + (65535 - be16 b8 b9) + be16 (b8 - 1) b9 - 1) % 65535 + 1 := by
      unfold rep; split <;> unfold be16 at * <;> omega
    unfold hopChecksum fold
    rw [foldNat_eq_rep, hy]
    unfold rep at hverify hlt ⊢
    unfold be16
    repeat' split
    all_goals (split at hverify <;> omega)
  rw [hc]

/-! ## Vectors

`header.json`: random and mutated IPv4 packets, each read by `v4` whole
and cut short, `check`, `whole`, `payload` and `dstPort`; and packets the
builders write. `hop.json`: IPv4 and IPv6 packets through `hop`. -/

open Lean (Json toJson)

def jsonParsed : Option Parsed → Json
  | none => Json.null
  | some h => Json.mkObj [
      ("src", toJson h.src), ("dst", toJson h.dst), ("protocol", toJson h.protocol),
      ("start", toJson h.start), ("end", toJson h.stop), ("length", toJson h.length),
      ("fragment", match h.fragment with
        | none => Json.null
        | some f => Json.mkObj [("id", toJson f.id), ("offset", toJson f.offset),
            ("more", toJson f.more)])]

def parseCase (bytes : List Nat) : Json :=
  let read := v4 bytes false
  Json.mkObj [("op", Json.str "parse"), ("bytes", toJson bytes),
    ("parse", jsonParsed read), ("truncated", jsonParsed (v4 bytes true)),
    ("check", jsonParsed (check bytes)), ("whole", jsonParsed (whole bytes)),
    ("payload", match read with | some h => toJson (payload h bytes) | none => Json.null),
    ("dst_port", match read with
      | some h => match dstPort h bytes with | some p => toJson p | none => Json.null
      | none => Json.null)]

/-- The header with its checksum field filled in from the reference, when
its header length fits the bytes. -/
def refill (p : List Nat) : List Nat :=
  let hl := get p 0 % 16 * 4
  if hl ≥ 20 ∧ hl ≤ p.length then
    let z := (p.set 10 0).set 11 0
    let c := checksum (z.take hl)
    (z.set 10 (c / 256)).set 11 (c % 256)
  else p

/-- A random IPv4 packet with a correct checksum: options in a third of
them, fragment fields, TTLs of 0 and 1, sources that are broadcast or
multicast, and trailing bytes after the total length. -/
def randomPacket (s : Nat) : List Nat :=
  let s1 := step s
  let s2 := step s1
  let s3 := step s2
  let ihl := if s1 % 3 = 0 then 5 + s1 / 3 % 11 else 5
  let hl := ihl * 4
  let payload := octets s2 (s2 % 40)
  let total := hl + payload.length
  let protocol := [6, 17, 1, 58, 47, s3 % 256][s3 / 7 % 6]!
  let flags := [0, 16384, 8192, s3 / 13 % 8192, 32768, 8192 + s3 / 17 % 8192,
    49152, 16384 + s3 / 19 % 8192][s3 / 23 % 8]!
  let ttl := [64, 0, 1, 2, 255, s1 / 29 % 256][s1 / 31 % 6]!
  let src := match s2 / 37 % 8 with
    | 0 => [255, 255, 255, 255]
    | 1 => (224 + s2 / 41 % 16) :: octets s3 3
    | 2 => [0, 0, 0, 0]
    | 3 => (240 + s2 / 43 % 16) :: octets s3 3
    | _ => octets (s3 + 1) 4
  let id := s3 / 47 % 65536
  let tos := s1 / 53 % 256
  let header := [64 + ihl, tos, total / 256, total % 256, id / 256, id % 256,
    flags / 256, flags % 256, ttl, protocol, 0, 0] ++ src ++ octets (s3 + 2) 4 ++
    octets (s3 + 3) (hl - 20)
  refill (header ++ payload ++ octets (s3 + 4) (s1 / 59 % 4))

/-- The identification that makes the header's computed checksum 0, so
that a field of 0xffff (the other zero) verifies too. -/
def zeroingId (p : List Nat) : List Nat :=
  let hl := get p 0 % 16 * 4
  let z := ((((p.set 4 0).set 5 0).set 10 0).set 11 0)
  let id := 65535 - rep (words (z.take hl)).sum
  ((z.set 4 (id / 256)).set 5 (id % 256))

/-- The mutations of one packet. -/
def mutations (s : Nat) (p : List Nat) : List (List Nat) :=
  let hl := get p 0 % 16 * 4
  let t := step (s + 7)
  let setTotal (n : Nat) := (p.set 2 (n / 256)).set 3 (n % 256)
  [p,
   -- another version that is not IP (IPv6 is the other reader's), with
   -- the checksum still right
   refill (p.set 0 ([0, 1, 5, 7, 15][t / 3 % 5]! * 16 + get p 0 % 16)),
   -- a header length below 5 words
   p.set 0 (64 + t / 5 % 5),
   refill ((p.set 0 (64 + t / 5 % 5))),
   -- a header length past the bytes
   p.take (hl - 1 - t % 4),
   -- a total length below the header length, and past the bytes
   refill (setTotal (t / 7 % hl)),
   refill (setTotal (p.length + 1 + t / 11 % 8)),
   -- the total length exactly the bytes, so no trailing bytes
   refill (setTotal p.length),
   -- one flipped bit in the header, which the checksum catches
   p.set (t / 13 % hl) (get p (t / 13 % hl) ^^^ 2 ^ (t / 17 % 8)),
   -- the checksum field's two zeros
   zeroingId p,
   (((zeroingId p).set 10 255).set 11 255),
   -- the reserved and "don't fragment" bits flipped
   refill (p.set 6 (get p 6 ^^^ 128)),
   refill (p.set 6 (get p 6 ^^^ 64)),
   -- fewer than 20 bytes
   p.take (t / 19 % 20)]

def headerVectors (seed : Nat) : List Json := Id.run do
  let mut out := #[]
  for i in [0:60] do
    let s := step (seed * 10007 + i)
    for m in mutations s (randomPacket s) do
      out := out.push (parseCase m)
  -- Bytes that are mostly noise, version 4.
  for i in [0:40] do
    let s := step (seed * 7919 + i)
    let noise := octets s (s % 64)
    out := out.push (parseCase (match noise with | [] => [] | b :: r => (64 + b % 16) :: r))
  return out.toList

/-- One IPv4 option given to `packet_with_ipv4_options`: `none` is No
Operation (type 1), `some (kind, data)` an option of a type the reader does
not know, written as type, length (2 plus the data) and data (RFC 791
section 3.1). -/
def optionOctets : List (Option (Nat × List Nat)) → List Nat
  | [] => []
  | none :: rest => 1 :: optionOctets rest
  | some (kind, data) :: rest => kind :: (data.length + 2) :: data ++ optionOctets rest

def jsonOption : Option (Nat × List Nat) → Json
  | none => Json.mkObj [("nop", toJson true)]
  | some (kind, data) => Json.mkObj [("kind", toJson kind), ("data", toJson data)]

def buildCase (s : Nat) : List Json :=
  let s1 := step s
  let s2 := step s1
  let v6 := s1 % 4 = 0
  let src := if v6 then octets s1 16 else
    match s1 / 3 % 6 with
    | 0 => [255, 255, 255, 255]
    | 1 => 224 :: octets s2 3
    | _ => octets s1 4
  let dst := octets s2 (if v6 then 16 else 4)
  let protocol := s2 / 5 % 256
  let ttl := [64, 0, 1, 255, s2 / 7 % 256][s2 / 11 % 5]!
  let tos := s2 / 13 % 256
  let id := s2 / 17 % 65536
  let df : Bool := s2 / 19 % 2 = 0
  -- Option types the reader does not know: not 0, 1, 7, 68, 130, 131, 136,
  -- 137 or 148.
  let kinds := [25, 30, 82, 94, 149, 158, 222, 10]
  let options : List (Option (Nat × List Nat)) :=
    if v6 then [] else
    match s1 / 23 % 4 with
    | 0 => []
    | 1 => [none]
    | 2 => [some (kinds[s2 / 29 % 8]!, octets s2 (s2 / 31 % 12)), none]
    | _ => [none, some (kinds[s2 / 37 % 8]!, octets (s2 + 1) (s2 / 41 % 30)), none, none]
  let payload := octets (s2 + 2) (s2 / 43 % 30)
  let bytes := if v6 then build6 src dst protocol ttl tos payload
    else build src dst protocol ttl tos id df (optionOctets options) payload
  let case := Json.mkObj [("op", Json.str "build"), ("src", toJson src), ("dst", toJson dst),
    ("protocol", toJson protocol), ("ttl", toJson ttl), ("tos", toJson tos),
    ("id", toJson id), ("dont_fragment", toJson df),
    ("options", Json.arr (options.map jsonOption).toArray), ("payload", toJson payload),
    ("expected", toJson bytes)]
  if v6 then [case] else [case, parseCase bytes]

def buildVectors (seed : Nat) : List Json :=
  (List.range 60).flatMap fun i => buildCase (step (seed * 104729 + i))

def hopResult : HopResult → String
  | .forward => "forward"
  | .expired => "expired"
  | .notIp => "not_ip"

def hopCase (p : List Nat) : Json :=
  let (r, after) := hop p
  let hl := get p 0 % 16 * 4
  let recomputed :=
    if r = .forward ∧ get p 0 / 16 = 4 ∧ hl ≥ 20 ∧ hl ≤ p.length ∧ checksum (p.take hl) = 0 then
      toJson (setHeaderChecksum ((p.set 8 (get p 8 - 1)).take hl))
    else Json.null
  Json.mkObj [("bytes", toJson p), ("result", Json.str (hopResult r)), ("after", toJson after),
    ("recomputed", recomputed)]

def hopVectors (seed : Nat) : List Json := Id.run do
  let mut out := #[]
  for i in [0:80] do
    let s := step (seed * 15485863 + i)
    let p := randomPacket s
    out := out.push (hopCase p)
    -- the received checksum 0xffff (RFC 1624 section 3's case)
    let z := zeroingId p
    out := out.push (hopCase ((z.set 10 255).set 11 255))
    -- a checksum that does not verify
    out := out.push (hopCase (p.set 11 (get p 11 ^^^ 1)))
    -- IPv6 with every hop limit edge
    let v6 := 96 :: octets s 39 ++ octets (s + 1) (s % 9)
    out := out.push (hopCase (v6.set 7 [0, 1, 2, 255, s / 3 % 256][i % 5]!))
  -- Too short for the field, and not IP at all.
  for n in [0, 1, 7, 8, 19, 39] do
    out := out.push (hopCase ((64 + 5) :: octets (seed + n) (n - 1) |>.take n))
    out := out.push (hopCase ((96 :: octets (seed + n) 50).take n))
  for v in [0, 5, 7, 15] do
    out := out.push (hopCase (v * 16 :: octets (seed + v) 45))
  return out.toList

/-- The vector files this module writes: `(file stem, cases)`. -/
def vectors (seed : Nat) : List (String × Lean.Json) :=
  [("header", Json.arr (headerVectors seed ++ buildVectors seed).toArray),
   ("hop", Json.arr (hopVectors seed).toArray)]

