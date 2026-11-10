import Lean
import Ip.Checksum
import Ip.Ext6

/-! ICMP and ICMPv6 messages the engine generates (RFC 792, RFC 1122
section 3.2.2, RFC 1812 section 4.3.2, RFC 4443).

Every ICMP message the engine sends comes from two functions in
`src/stdlib/network/icmp.rs`: `Options::error` (behind `error`,
`host_unreachable`, `time_exceeded`, `address_unreachable`,
`ip::parameter_problem` and the UDP layer's `port_unreachable`) and
`Options::echo_reply`. `error` and `echoReply` below follow them with the
default `Options`; `parse` and `parseWhole` follow `Header::parse` and
`Header::parse_whole`, and `ipPacket` follows `ip::packet_with`.

The theorems say what the RFCs ask of the messages: the type, code and
second word; the quoted part and the message size; the checksums (RFC 1071
over the message for ICMP, over the RFC 8200 section 8.1 pseudo-header
and the message for ICMPv6); when no error may be sent; and that an echo
reply carries the request's identifier, sequence number and data. The
vector file `icmp.json` ties the model to the Rust:
`tests/ip_vectors/icmp.rs` replays it. -/

namespace Ip.Icmp

open Ip.Ext6 (Bytes byte be16 Mode Chain Reject chain6)
open Ip.Checksum (words addOnes onesSum checksum)

/-! ## The one's-complement sum: filling in a checksum makes it verify -/

theorem foldl_mod (ws : List Nat) :
    ∀ acc, (ws.foldl addOnes acc) % 65535 = (acc + ws.sum) % 65535 := by
  induction ws with
  | nil => intro acc; simp
  | cons w ws ih =>
    intro acc
    simp only [List.foldl_cons, List.sum_cons]
    rw [ih]
    unfold addOnes
    split <;> omega

theorem foldl_le (ws : List Nat) (hw : ∀ w ∈ ws, w ≤ 65535) :
    ∀ acc, acc ≤ 65535 → ws.foldl addOnes acc ≤ 65535 := by
  induction ws with
  | nil => intro acc h; simpa using h
  | cons w ws ih =>
    intro acc h
    simp only [List.foldl_cons]
    apply ih (fun x hx => hw x (by simp [hx]))
    have := hw w (by simp)
    unfold addOnes; split <;> omega

theorem foldl_pos (ws : List Nat) :
    ∀ acc, (0 < acc ∨ ∃ w ∈ ws, 0 < w) → 0 < ws.foldl addOnes acc := by
  induction ws with
  | nil => intro acc h; simpa using h
  | cons w ws ih =>
    intro acc h
    simp only [List.foldl_cons]
    apply ih
    by_cases hw : 0 < w
    · left; unfold addOnes; split <;> omega
    · rcases h with h | ⟨x, hx, hpos⟩
      · left; unfold addOnes; split <;> omega
      · simp only [List.mem_cons] at hx
        rcases hx with rfl | hx
        · omega
        · right; exact ⟨x, hx, hpos⟩

/-- Writing the complement of the sum into a zero word makes the sum of
every word `0xffff`: the RFC 1071 check. -/
theorem fill_word (a c : List Nat) (ha : ∀ w ∈ a, w ≤ 65535) (hc : ∀ w ∈ c, w ≤ 65535) :
    onesSum (a ++ (65535 - onesSum (a ++ 0 :: c)) :: c) = 65535 := by
  unfold onesSum
  have hall : ∀ w ∈ a ++ 0 :: c, w ≤ 65535 := by
    intro w hw; simp only [List.mem_append, List.mem_cons] at hw
    rcases hw with h | rfl | h
    · exact ha w h
    · omega
    · exact hc w h
  have hS := foldl_le _ hall 0 (by omega)
  generalize hS0 : (a ++ 0 :: c).foldl addOnes 0 = S at hS
  have hall1 : ∀ w ∈ a ++ (65535 - S) :: c, w ≤ 65535 := by
    intro w hw; simp only [List.mem_append, List.mem_cons] at hw
    rcases hw with h | rfl | h
    · exact ha w h
    · omega
    · exact hc w h
  have h1 := foldl_le _ hall1 0 (by omega)
  have m0 := foldl_mod (a ++ 0 :: c) 0
  have m1 := foldl_mod (a ++ (65535 - S) :: c) 0
  rw [hS0] at m0
  simp only [List.sum_append, List.sum_cons, Nat.zero_add] at m0 m1
  have pos : 0 < (a ++ (65535 - S) :: c).foldl addOnes 0 := by
    apply foldl_pos
    right
    by_cases hx : 0 < 65535 - S
    · exact ⟨_, by simp, hx⟩
    · -- S = 65535, so some word of `a` or `c` is positive.
      have hSpos : 0 < S := by omega
      rw [← hS0] at hSpos
      refine Classical.byContradiction fun hno => ?_
      have hz : ∀ w ∈ a ++ 0 :: c, w = 0 := by
        intro w hw
        simp only [List.mem_append, List.mem_cons] at hw
        rcases hw with h | rfl | h
        · exact Nat.eq_zero_of_not_pos fun hp => hno ⟨w, by simp [h], hp⟩
        · rfl
        · exact Nat.eq_zero_of_not_pos fun hp => hno ⟨w, by simp [h], hp⟩
      have : (a ++ 0 :: c).foldl addOnes 0 = 0 := by
        clear hS0 hSpos m0 hall hno
        generalize a ++ 0 :: c = ws at hz
        suffices ∀ acc, acc = 0 → ws.foldl addOnes acc = 0 from this 0 rfl
        induction ws with
        | nil => intro acc h; simpa using h
        | cons w ws ih =>
          intro acc h
          simp only [List.foldl_cons]
          apply ih (fun x hx => hz x (by simp [hx]))
          have := hz w (by simp); subst this; subst h; decide
      omega
  omega

theorem words_append : ∀ (pre rest : List Nat), pre.length % 2 = 0 →
    words (pre ++ rest) = words pre ++ words rest
  | [], _, _ => rfl
  | [_], _, h => by simp at h
  | a :: b :: pre, rest, h => by
    simp only [List.cons_append, words, List.cons_append]
    rw [words_append pre rest (by simp at h; omega)]

theorem words_le : ∀ (bs : List Nat), (∀ x ∈ bs, x < 256) → ∀ w ∈ words bs, w ≤ 65535
  | [], _ => by simp [words]
  | [a], h => by
    have := h a (by simp)
    simp [words]; omega
  | a :: b :: rest, h => by
    have ha := h a (by simp)
    have hb := h b (by simp)
    intro w hw
    simp only [words, List.mem_cons] at hw
    rcases hw with rfl | hw
    · omega
    · exact words_le rest (fun x hx => h x (by simp [hx])) w hw

/-- A message `[t, c, 0, 0] ++ rest` with its checksum filled in, after an
even-length prefix `pre` (the IPv6 pseudo-header, or nothing). -/
def filled (pre : Bytes) (t c : Nat) (rest : Bytes) : Bytes :=
  let s := checksum (pre ++ [t, c, 0, 0] ++ rest)
  [t, c, s / 256, s % 256] ++ rest

/-- **Checksums verify.** A message whose checksum the engine filled in has
the RFC 1071 checksum 0 over the prefix and the message: over the message
alone for ICMP (RFC 792), over the pseudo-header and the message for
ICMPv6 (RFC 4443 section 2.3, RFC 8200 section 8.1). -/
theorem filled_verifies (pre : Bytes) (t c : Nat) (rest : Bytes)
    (hpre : pre.length % 2 = 0) (hp : ∀ x ∈ pre, x < 256) (ht : t < 256) (hc : c < 256)
    (hr : ∀ x ∈ rest, x < 256) :
    checksum (pre ++ filled pre t c rest) = 0 := by
  simp only [filled, checksum]
  have hS : onesSum (words (pre ++ [t, c, 0, 0] ++ rest)) ≤ 65535 := by
    unfold onesSum
    apply foldl_le _ _ 0 (by omega)
    apply words_le
    intro x hx; simp only [List.mem_append, List.mem_cons] at hx
    rcases hx with (h | h | h | h | h | h) | h
    · exact hp x h
    · omega
    · omega
    · omega
    · omega
    · simp at h
    · exact hr x h
  generalize hs : 65535 - onesSum (words (pre ++ [t, c, 0, 0] ++ rest)) = s
  have hsv : s / 256 * 256 + s % 256 = s := by omega
  have e1 : words (pre ++ ([t, c, s / 256, s % 256] ++ rest)) =
      (words pre ++ [t * 256 + c]) ++ s :: words rest := by
    rw [words_append pre _ hpre]
    simp [words, hsv]
  have e0 : words (pre ++ [t, c, 0, 0] ++ rest) = (words pre ++ [t * 256 + c]) ++ 0 :: words rest := by
    rw [List.append_assoc, words_append pre _ hpre]
    simp [words]
  rw [e0] at hs
  rw [e1, ← hs, fill_word]
  · intro w hw
    simp only [List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hw
    rcases hw with h | rfl
    · exact words_le pre hp w h
    · omega
  · exact words_le rest hr

/-! ## Addresses and headers -/

/-- An IPv4 address (4 octets) or an IPv6 address (16 octets). -/
inductive Addr where
  | v4 (a : Bytes)
  | v6 (a : Bytes)
  deriving DecidableEq, Repr

def Addr.bytes : Addr → Bytes
  | .v4 a => a
  | .v6 a => a

/-- IPv6 loopback, `::1`. -/
def loopback6 : Bytes := List.replicate 15 0 ++ [1]

/-- `is_one_host` in `icmp.rs`: not the unspecified address, the "this
network" block 0/8, loopback, multicast, the class E block 240/4 or the
limited broadcast address (which is in 240/4) over IPv4; not the
unspecified address, loopback or multicast over IPv6. -/
def oneHost : Addr → Bool
  | .v4 a => byte a 0 != 0 && byte a 0 != 127 && decide (byte a 0 < 224)
  | .v6 a => !(a.all (· == 0)) && byte a 0 != 255 && a != loopback6

/-- An IPv4 address that does not name one host, in RFC 1122's words
(sections 3.2.1.3 and 3.2.2; RFC 1812 sections 4.3.2.7 and 5.3.7): a zero
address, an address in network 0, a loopback address, the limited
broadcast address, a multicast address, or a class E address. -/
def notOneHostV4 (a : Bytes) : Prop :=
  a = [0, 0, 0, 0] ∨ byte a 0 = 0 ∨ byte a 0 = 127 ∨ a = [255, 255, 255, 255] ∨
    (224 ≤ byte a 0 ∧ byte a 0 < 240) ∨ 240 ≤ byte a 0

/-- `is_one_host` is RFC 1122's rule for IPv4. -/
theorem oneHost_v4 (a : Bytes) (h4 : a.length = 4) :
    oneHost (.v4 a) = true ↔ ¬notOneHostV4 a := by
  match a, h4 with
  | [x, y, z, w], _ =>
    have hb : byte [x, y, z, w] 0 = x := rfl
    simp only [oneHost, notOneHostV4, hb, Bool.and_eq_true, bne_iff_ne, ne_eq, decide_eq_true_eq]
    constructor
    · rintro ⟨⟨h0, h1⟩, h2⟩ hn
      rcases hn with hn | hn | hn | hn | hn | hn
      · simp only [List.cons.injEq] at hn; exact h0 hn.1
      · exact h0 hn
      · exact h1 hn
      · simp only [List.cons.injEq] at hn; omega
      · omega
      · omega
    · intro hn
      refine ⟨⟨fun h => hn (Or.inr (Or.inl h)), fun h => hn (Or.inr (Or.inr (Or.inl h)))⟩, ?_⟩
      apply Classical.byContradiction
      intro hc
      rcases Nat.lt_or_ge x 240 with h | h
      · exact hn (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl ⟨by omega, h⟩)))))
      · exact hn (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr h)))))

/-- An IPv4 multicast destination (224/4) or the limited broadcast address. -/
def groupV4 (a : Bytes) : Prop :=
  (224 ≤ byte a 0 ∧ byte a 0 < 240) ∨ a = [255, 255, 255, 255]

/-- What the engine reads of a packet's header (`Header`). -/
structure Hdr where
  src : Addr
  dst : Addr
  proto : Nat
  start : Nat
  stop : Nat
  /-- A fragment of any kind. -/
  isFrag : Bool
  /-- A fragment after the first. -/
  later : Bool
  deriving DecidableEq, Repr

def slice (b : Bytes) (i j : Nat) : Bytes := (b.drop i).take (j - i)

/-- `v4` in `ip.rs` on a whole packet: the header length is `byte b 0 % 16 * 4`
and the total length `be16 b 2`. -/
def parseV4 (b : Bytes) : Option Hdr :=
  if b.length < 20 ∨ byte b 0 % 16 * 4 < 20 ∨ b.length < byte b 0 % 16 * 4 ∨
      be16 b 2 < byte b 0 % 16 * 4 ∨ b.length < be16 b 2 then none
  else some {
    src := .v4 (slice b 12 16), dst := .v4 (slice b 16 20), proto := byte b 9,
    start := byte b 0 % 16 * 4, stop := be16 b 2, isFrag := be16 b 6 % 16384 != 0,
    later := be16 b 6 % 8192 != 0 }

/-- `v6` in `ip.rs` from a walked chain. -/
def ofChain (b : Bytes) (c : Chain) : Hdr :=
  { src := .v6 (slice b 8 24), dst := .v6 (slice b 24 40), proto := c.proto,
    start := c.upper, stop := c.stop, isFrag := c.frag.isSome,
    later := match c.frag with | some (pos, _) => be16 b (pos + 2) / 8 != 0 | none => false }

/-- `Header::parse`. -/
def parse (b : Bytes) : Option Hdr :=
  if byte b 0 / 16 = 4 ∧ b.length > 0 then parseV4 b
  else if byte b 0 / 16 = 6 then
    match chain6 b (.read false) with
    | .ok c => some (ofChain b c)
    | .error _ => none
  else none

/-- `Header::parse_whole`: `Header::check`, which also checks the IPv4
header checksum (RFC 1122 section 3.2.1.2), and no fragment. -/
def parseWhole (b : Bytes) : Option Hdr :=
  if byte b 0 / 16 = 4 ∧ b.length > 0 then
    match parseV4 b with
    | some h => if checksum (b.take h.start) = 0 ∧ h.isFrag = false then some h else none
    | none => none
  else if byte b 0 / 16 = 6 then
    match chain6 b .check with
    | .ok c => if c.frag.isNone then some (ofChain b c) else none
    | .error _ => none
  else none

/-- The header fields `ip::packet_with` takes. -/
structure Fields where
  ttl : Nat := 64
  tos : Nat := 0
  id : Nat := 0
  df : Bool := true

/-- `ip::packet_with`: a 20-byte IPv4 header with its checksum, or a 40-byte
IPv6 header, then the payload. -/
def ipPacket (src dst : Addr) (proto : Nat) (f : Fields) (payload : Bytes) : Bytes :=
  match src, dst with
  | .v4 s, .v4 d =>
    let h0 := [69, f.tos, (20 + payload.length) / 256 % 256, (20 + payload.length) % 256,
      f.id / 256 % 256, f.id % 256, if f.df then 64 else 0, 0, f.ttl, proto, 0, 0] ++ s ++ d
    (h0.set 10 (checksum h0 / 256)).set 11 (checksum h0 % 256) ++ payload
  | .v6 s, .v6 d =>
    [96 + f.tos / 16, f.tos * 16 % 256, 0, 0, payload.length / 256 % 256, payload.length % 256,
      proto, f.ttl] ++ s ++ d ++ payload
  | _, _ => []

/-- The RFC 8200 section 8.1 pseudo-header for ICMPv6 (next header 58). -/
def pseudo6 (src dst : Bytes) (len : Nat) : Bytes :=
  src ++ dst ++ [len / 16777216 % 256, len / 65536 % 256, len / 256 % 256, len % 256, 0, 0, 0, 58]

/-- The prefix the checksum covers ahead of a message from `src` to `dst`:
none for ICMP, the pseudo-header for ICMPv6. -/
def prefixOf (src dst : Addr) (len : Nat) : Bytes :=
  match src, dst with
  | .v6 s, .v6 d => pseudo6 s d len
  | _, _ => []

def word32 (w : Nat) : Bytes := [w / 16777216 % 256, w / 65536 % 256, w / 256 % 256, w % 256]

/-! ## Errors (`Options::error`) -/

/-- The ICMP types that are queries or replies (echo, timestamp,
information, address mask), which `error` answers about over IPv4. -/
def queryV4 (t : Nat) : Bool := t == 0 || t == 8 || (13 ≤ t && t ≤ 18)

/-- The first byte of the upper-layer bytes, if there is one. -/
def firstByte (b : Bytes) (h : Hdr) : Option Nat :=
  if h.start < h.stop then some (byte b h.start) else none

/-- Whether `error` answers, and if so with which protocol and quote limit. -/
def allowed (b : Bytes) (h : Hdr) (src : Addr) : Option (Nat × Nat) :=
  match h.src, h.dst, src with
  | .v4 _, .v4 d, .v4 _ =>
    if h.later = true ∨ oneHost h.src = false then none
    else if d = [255, 255, 255, 255] ∨ (224 ≤ byte d 0 ∧ byte d 0 < 240) then none
    else if h.proto = 1 ∧ ¬(firstByte b h).any queryV4 = true then none
    else some (1, 548)
  | .v6 _, .v6 d, .v6 _ =>
    if oneHost h.src = false ∨ byte d 0 = 255 then none
    else if h.proto = 58 ∧ h.later = false ∧
        (firstByte b h).all (fun t => t < 128 ∨ (133 ≤ t ∧ t ≤ 137)) = true then none
    else some (58, 1232)
  | _, _, _ => none

/-- `Options::error` with the default options: the error of `kind` and
`code`, with second word `w`, about `b`, from `src`. The quote limit is
576 - 28 over IPv4 and 1280 - 48 over IPv6. -/
def error (b : Bytes) (src : Addr) (kind code w : Nat) : Option Bytes :=
  match parse b with
  | none => none
  | some h =>
    match allowed b h src with
    | none => none
    | some (proto, limit) =>
      some (ipPacket src h.src proto {}
        (filled (prefixOf src h.src (8 + min h.stop limit)) kind code
          (word32 w ++ b.take (min h.stop limit))))

/-- `ip::destination`. -/
def destination (b : Bytes) : Option Addr :=
  if byte b 0 / 16 = 4 ∧ b.length ≥ 20 then some (.v4 (slice b 16 20))
  else if byte b 0 / 16 = 6 ∧ b.length ≥ 40 then some (.v6 (slice b 24 40))
  else none

/-- `ip::parameter_problem`: ICMPv6 Parameter Problem (type 4) from the
packet's destination. -/
def parameterProblem (b : Bytes) : Reject → Option Bytes
  | .discard => none
  | .problem code ptr =>
    match destination b with
    | some d => error b d 4 code ptr
    | none => none

/-! ## Echo replies (`Options::echo_reply`) -/

/-- The message of an echo reply to `icmp`: type `rep`, the request's code,
a new checksum, and every byte after the checksum unchanged. -/
def replyMessage (addr src : Addr) (rep : Nat) (icmp : Bytes) : Bytes :=
  filled (prefixOf addr src icmp.length) rep (byte icmp 1) (icmp.drop 4)

/-- `Options::echo_reply` with the default options. -/
def echoReply (b : Bytes) (addr : Addr) : Option Bytes :=
  match parseWhole b with
  | none => none
  | some h =>
    if h.dst ≠ addr ∨ oneHost h.src = false then none
    else
      match addr with
      | .v4 _ =>
        if h.proto ≠ 1 ∨ (slice b h.start h.stop).length < 8 ∨
            byte (slice b h.start h.stop) 0 ≠ 8 ∨ byte (slice b h.start h.stop) 1 ≠ 0 ∨
            checksum (slice b h.start h.stop) ≠ 0 then none
        else
          some (ipPacket addr h.src 1 { id := be16 b 4, tos := byte b 1, df := false }
            (replyMessage addr h.src 0 (slice b h.start h.stop)))
      | .v6 _ =>
        if h.proto ≠ 58 ∨ (slice b h.start h.stop).length < 8 ∨
            byte (slice b h.start h.stop) 0 ≠ 128 ∨ byte (slice b h.start h.stop) 1 ≠ 0 ∨
            checksum (prefixOf h.src addr (slice b h.start h.stop).length ++
              slice b h.start h.stop) ≠ 0 then none
        else
          some (b.take 4 ++
            (ipPacket addr h.src 58 {} (replyMessage addr h.src 129 (slice b h.start h.stop))).drop 4)

/-! ## Lemmas about octets, addresses and headers -/

theorem byte_lt (b : Bytes) (hb : ∀ x ∈ b, x < 256) (i : Nat) : byte b i < 256 := by
  unfold byte
  rw [List.getD_eq_getElem?_getD]
  cases h : b[i]? with
  | none => simp
  | some x => simpa using hb x (List.mem_of_getElem? h)

theorem slice_lt (b : Bytes) (hb : ∀ x ∈ b, x < 256) (i j : Nat) : ∀ x ∈ slice b i j, x < 256 :=
  fun x hx => hb x (List.mem_of_mem_drop (List.mem_of_mem_take hx))

theorem slice_length (b : Bytes) (i j : Nat) (h : j ≤ b.length) (hij : i ≤ j) :
    (slice b i j).length = j - i := by
  simp only [slice, List.length_take, List.length_drop]; omega

theorem chain6_long (b : Bytes) (m : Mode) (c : Chain) (h : chain6 b m = .ok c) : 40 ≤ b.length := by
  unfold chain6 at h
  split at h
  · simp at h
  · omega

/-- What `parse` reads: two addresses of one family and of its length, from
their places in the packet; and an end within the packet, after a header
of at most 60 bytes over IPv4. -/
theorem parse_facts (b : Bytes) (h : Hdr) (hp : parse b = some h) :
    h.stop ≤ b.length ∧
    ((h.src = .v4 (slice b 12 16) ∧ h.dst = .v4 (slice b 16 20) ∧ (slice b 12 16).length = 4 ∧
        (slice b 16 20).length = 4 ∧ h.start ≤ 60) ∨
      (h.src = .v6 (slice b 8 24) ∧ h.dst = .v6 (slice b 24 40) ∧ (slice b 8 24).length = 16 ∧
        (slice b 24 40).length = 16)) := by
  unfold parse at hp
  by_cases h4 : byte b 0 / 16 = 4 ∧ b.length > 0
  · rw [if_pos h4] at hp
    unfold parseV4 at hp
    by_cases hn : b.length < 20 ∨ byte b 0 % 16 * 4 < 20 ∨ b.length < byte b 0 % 16 * 4 ∨
        be16 b 2 < byte b 0 % 16 * 4 ∨ b.length < be16 b 2
    · rw [if_pos hn] at hp; simp at hp
    · rw [if_neg hn] at hp
      cases hp
      refine ⟨by dsimp only; omega, Or.inl ⟨rfl, rfl, slice_length b 12 16 (by omega) (by omega),
        slice_length b 16 20 (by omega) (by omega), by dsimp only; omega⟩⟩
  · rw [if_neg h4] at hp
    by_cases h6 : byte b 0 / 16 = 6
    · rw [if_pos h6] at hp
      cases hc : chain6 b (.read false) with
      | error r => rw [hc] at hp; simp at hp
      | ok c =>
        rw [hc] at hp
        simp only [Option.some.injEq] at hp
        subst hp
        have := chain6_long b _ c hc
        exact ⟨Ip.Ext6.stop_le b c hc, Or.inr ⟨rfl, rfl, slice_length b 8 24 (by omega) (by omega),
          slice_length b 24 40 (by omega) (by omega)⟩⟩
    · rw [if_neg h6] at hp; simp at hp

/-- The same for `parseWhole`. -/
theorem parseWhole_facts (b : Bytes) (h : Hdr) (hp : parseWhole b = some h) :
    (h.src = .v4 (slice b 12 16) ∧ h.dst = .v4 (slice b 16 20) ∧ (slice b 12 16).length = 4 ∧
        (slice b 16 20).length = 4) ∨
      (h.src = .v6 (slice b 8 24) ∧ h.dst = .v6 (slice b 24 40) ∧ (slice b 8 24).length = 16 ∧
        (slice b 24 40).length = 16) := by
  unfold parseWhole at hp
  by_cases h4 : byte b 0 / 16 = 4 ∧ b.length > 0
  · rw [if_pos h4] at hp
    cases hv : parseV4 b with
    | none => rw [hv] at hp; simp at hp
    | some h' =>
      rw [hv] at hp
      have hh : h' = h := by
        simp only [] at hp
        split at hp
        · simpa using hp
        · simp at hp
      subst hh
      unfold parseV4 at hv
      by_cases hn : b.length < 20 ∨ byte b 0 % 16 * 4 < 20 ∨ b.length < byte b 0 % 16 * 4 ∨
          be16 b 2 < byte b 0 % 16 * 4 ∨ b.length < be16 b 2
      · rw [if_pos hn] at hv; simp at hv
      · rw [if_neg hn] at hv
        cases hv
        exact Or.inl ⟨rfl, rfl, slice_length b 12 16 (by omega) (by omega),
          slice_length b 16 20 (by omega) (by omega)⟩
  · rw [if_neg h4] at hp
    by_cases h6 : byte b 0 / 16 = 6
    · rw [if_pos h6] at hp
      cases hc : chain6 b .check with
      | error r => rw [hc] at hp; simp at hp
      | ok c =>
        rw [hc] at hp
        simp only [] at hp
        split at hp
        · simp only [Option.some.injEq] at hp
          subst hp
          have := chain6_long b _ c hc
          exact Or.inr ⟨rfl, rfl, slice_length b 8 24 (by omega) (by omega),
            slice_length b 24 40 (by omega) (by omega)⟩
        · simp at hp
    · rw [if_neg h6] at hp; simp at hp

theorem pseudo6_length (s d : Bytes) (len : Nat) :
    (pseudo6 s d len).length = s.length + d.length + 8 := by
  simp only [pseudo6, List.length_append, List.length_cons, List.length_nil]

theorem pseudo6_lt (s d : Bytes) (len : Nat) (hs : ∀ x ∈ s, x < 256) (hd : ∀ x ∈ d, x < 256) :
    ∀ x ∈ pseudo6 s d len, x < 256 := by
  intro x hx
  simp only [pseudo6, List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hx
  rcases hx with (h | h) | h | h | h | h | h | h | h | h
  · exact hs x h
  · exact hd x h
  all_goals omega

theorem word32_lt (w : Nat) : ∀ x ∈ word32 w, x < 256 := by
  intro x hx
  simp only [word32, List.mem_cons, List.not_mem_nil, or_false] at hx
  omega

/-- The prefix a checksum covers has an even length and octets below 256,
when the addresses are an IPv6 packet's. -/
theorem prefix_ok (src dst : Addr) (len : Nat) (hs : ∀ x ∈ src.bytes, x < 256)
    (hd : ∀ x ∈ dst.bytes, x < 256) (hsl : src.bytes.length % 2 = 0)
    (hdl : dst.bytes.length % 2 = 0) :
    (prefixOf src dst len).length % 2 = 0 ∧ ∀ x ∈ prefixOf src dst len, x < 256 := by
  cases src with
  | v4 s => cases dst <;> simp [prefixOf]
  | v6 s =>
    cases dst with
    | v4 d => simp [prefixOf]
    | v6 d =>
      simp only [prefixOf]
      simp only [Addr.bytes] at hs hd hsl hdl
      exact ⟨by rw [pseudo6_length]; omega, pseudo6_lt s d len hs hd⟩

/-- The cases in which `allowed` answers. -/
theorem allowed_cases (b : Bytes) (h : Hdr) (src : Addr) (proto limit : Nat)
    (ha : allowed b h src = some (proto, limit)) :
    (proto = 1 ∧ limit = 548 ∧ ∃ s d f, h.src = .v4 s ∧ h.dst = .v4 d ∧ src = .v4 f ∧
      ¬(h.later = true ∨ oneHost (.v4 s) = false) ∧
      ¬(d = [255, 255, 255, 255] ∨ (224 ≤ byte d 0 ∧ byte d 0 < 240)) ∧
      ¬(h.proto = 1 ∧ ¬(firstByte b h).any queryV4 = true)) ∨
    (proto = 58 ∧ limit = 1232 ∧ ∃ s d f, h.src = .v6 s ∧ h.dst = .v6 d ∧ src = .v6 f ∧
      ¬(oneHost (.v6 s) = false ∨ byte d 0 = 255) ∧
      ¬(h.proto = 58 ∧ h.later = false ∧
        (firstByte b h).all (fun t => t < 128 ∨ (133 ≤ t ∧ t ≤ 137)) = true)) := by
  unfold allowed at ha
  cases hs : h.src with
  | v4 s =>
    cases hd : h.dst with
    | v4 d =>
      cases src with
      | v4 f =>
        rw [hs, hd] at ha
        simp only [] at ha
        by_cases hA : h.later = true ∨ oneHost (.v4 s) = false
        · rw [if_pos hA] at ha; simp at ha
        · rw [if_neg hA] at ha
          by_cases hB : d = [255, 255, 255, 255] ∨ (224 ≤ byte d 0 ∧ byte d 0 < 240)
          · rw [if_pos hB] at ha; simp at ha
          · rw [if_neg hB] at ha
            by_cases hC : h.proto = 1 ∧ ¬(firstByte b h).any queryV4 = true
            · rw [if_pos hC] at ha; simp at ha
            · rw [if_neg hC] at ha
              simp only [Option.some.injEq, Prod.mk.injEq] at ha
              exact Or.inl ⟨ha.1.symm, ha.2.symm, s, d, f, rfl, rfl, rfl, hA, hB, hC⟩
      | v6 f => rw [hs, hd] at ha; simp at ha
    | v6 d => cases src <;> (rw [hs, hd] at ha; simp at ha)
  | v6 s =>
    cases hd : h.dst with
    | v6 d =>
      cases src with
      | v6 f =>
        rw [hs, hd] at ha
        simp only [] at ha
        by_cases hA : oneHost (.v6 s) = false ∨ byte d 0 = 255
        · rw [if_pos hA] at ha; simp at ha
        · rw [if_neg hA] at ha
          by_cases hC : h.proto = 58 ∧ h.later = false ∧
              (firstByte b h).all (fun t => t < 128 ∨ (133 ≤ t ∧ t ≤ 137)) = true
          · rw [if_pos hC] at ha; simp at ha
          · rw [if_neg hC] at ha
            simp only [Option.some.injEq, Prod.mk.injEq] at ha
            exact Or.inr ⟨ha.1.symm, ha.2.symm, s, d, f, rfl, rfl, rfl, hA, hC⟩
      | v4 f => rw [hs, hd] at ha; simp at ha
    | v4 d => cases src <;> (rw [hs, hd] at ha; simp at ha)

/-! ## Theorems about errors -/

/-- The message inside an error: type, code, the checksum, the second word,
and the quoted bytes. -/
theorem error_message (b : Bytes) (src : Addr) (kind code w : Nat) (out : Bytes)
    (he : error b src kind code w = some out) :
    ∃ h proto limit, parse b = some h ∧ allowed b h src = some (proto, limit) ∧
      out = ipPacket src h.src proto {}
        (filled (prefixOf src h.src (8 + min h.stop limit)) kind code
          (word32 w ++ b.take (min h.stop limit))) := by
  unfold error at he
  cases hp : parse b with
  | none => rw [hp] at he; simp at he
  | some h =>
    rw [hp] at he
    cases ha : allowed b h src with
    | none => simp [ha] at he
    | some pl =>
      obtain ⟨proto, limit⟩ := pl
      simp only [ha, Option.some.injEq] at he
      exact ⟨h, proto, limit, by first | rfl | exact hp, by first | rfl | exact ha, he.symm⟩

/-- The quote limits: over IPv4 the error, with its 20-byte header and
8-byte ICMP header, stays within 576 bytes (RFC 1812 section 4.3.2.3) and
quotes at least the header and 8 bytes of data (RFC 792, RFC 1122
section 3.2.2), or the whole packet when it is shorter; over IPv6 it
quotes as much of the packet as fits in the minimum MTU of 1,280 bytes
(RFC 4443 section 2.4(c)). -/
theorem error_quote (b : Bytes) (h : Hdr) (src : Addr) (proto limit : Nat)
    (hp : parse b = some h) (ha : allowed b h src = some (proto, limit)) :
    (proto = 1 ∧ 20 + 8 + min h.stop limit ≤ 576 ∧ min h.stop (h.start + 8) ≤ min h.stop limit ∧
        min h.stop limit ≤ b.length) ∨
      (proto = 58 ∧ 40 + 8 + min h.stop limit ≤ 1280 ∧
        (min h.stop limit = h.stop ∨ 40 + 8 + min h.stop limit = 1280) ∧
        min h.stop limit ≤ b.length) := by
  obtain ⟨hst, hfam⟩ := parse_facts b h hp
  rcases allowed_cases b h src proto limit ha with
    ⟨rfl, rfl, s, d, f, hs, -⟩ | ⟨rfl, rfl, s, d, f, hs, -⟩
  · rcases hfam with ⟨-, -, -, -, h60⟩ | ⟨hs6, -⟩
    · exact Or.inl ⟨rfl, by omega, by omega, by omega⟩
    · rw [hs] at hs6; cases hs6
  · exact Or.inr ⟨rfl, by omega, by omega, by omega⟩

/-- **ICMP checksums.** The message of every error the engine sends carries
an RFC 1071 checksum that verifies: over the message for ICMP (RFC 792),
over the pseudo-header and the message for ICMPv6 (RFC 4443 section
2.3). -/
theorem error_checksum (b : Bytes) (src : Addr) (kind code w : Nat) (out : Bytes)
    (he : error b src kind code w = some out) (hb : ∀ x ∈ b, x < 256)
    (hsb : ∀ x ∈ src.bytes, x < 256) (hse : src.bytes.length % 2 = 0)
    (hk : kind < 256) (hc : code < 256) :
    ∃ h proto m, parse b = some h ∧ out = ipPacket src h.src proto {} m ∧
      byte m 0 = kind ∧ byte m 1 = code ∧ (m.drop 4).take 4 = word32 w ∧
      checksum (prefixOf src h.src m.length ++ m) = 0 := by
  obtain ⟨h, proto, limit, hp, ha, rfl⟩ := error_message b src kind code w out he
  have hq := error_quote b h src proto limit hp ha
  have hql : min h.stop limit ≤ b.length := by rcases hq with h | h <;> omega
  refine ⟨h, proto, _, hp, rfl, by simp [filled, byte], by simp [filled, byte],
    by simp [filled, word32], ?_⟩
  have hlen : (filled (prefixOf src h.src (8 + min h.stop limit)) kind code
      (word32 w ++ b.take (min h.stop limit))).length = 8 + min h.stop limit := by
    simp only [filled, word32, List.length_append, List.length_cons, List.length_nil,
      List.length_take]
    omega
  rw [hlen]
  have hrest : ∀ x ∈ word32 w ++ b.take (min h.stop limit), x < 256 := by
    intro x hx
    simp only [List.mem_append] at hx
    rcases hx with hx | hx
    · exact word32_lt w x hx
    · exact hb x (List.mem_of_mem_take hx)
  have hsrc : (∀ x ∈ h.src.bytes, x < 256) ∧ h.src.bytes.length % 2 = 0 := by
    rcases (parse_facts b h hp).2 with ⟨hs, -, hl, -⟩ | ⟨hs, -, hl, -⟩
    · rw [hs]; exact ⟨slice_lt b hb _ _, by simp only [Addr.bytes]; omega⟩
    · rw [hs]; exact ⟨slice_lt b hb _ _, by simp only [Addr.bytes]; omega⟩
  have hpre := prefix_ok src h.src (8 + min h.stop limit) hsb hsrc.1 hse hsrc.2
  exact filled_verifies _ _ _ _ hpre.1 hpre.2 hk hc hrest

/-- The ICMP types that are error messages (RFC 792, RFC 1122 section
3.2.2): destination unreachable, source quench, redirect, time exceeded and
parameter problem. -/
def isErrorV4 (t : Nat) : Bool := t == 3 || t == 4 || t == 5 || t == 11 || t == 12

/-- RFC 1122 section 3.2.2 (and RFC 1812 section 4.3.2.7 for routers): an
ICMP error is never sent about an ICMP error message, a datagram to a
broadcast or multicast address, a fragment other than the first, or a
datagram whose source does not name one host. -/
def rfcForbidsV4 (b : Bytes) (h : Hdr) (s d : Bytes) : Prop :=
  h.later = true ∨ notOneHostV4 s ∨ groupV4 d ∨ (h.proto = 1 ∧ (firstByte b h).any isErrorV4 = true)

/-- **No forbidden ICMP error.** Every ICMP error the engine sends about an
IPv4 packet is one RFC 1122 section 3.2.2 allows. -/
theorem error_v4_allowed (b f : Bytes) (k c w : Nat) (out : Bytes)
    (he : error b (.v4 f) k c w = some out) :
    ∃ h s d, parse b = some h ∧ h.src = .v4 s ∧ h.dst = .v4 d ∧ ¬rfcForbidsV4 b h s d := by
  obtain ⟨h, proto, limit, hp, ha, -⟩ := error_message b _ k c w out he
  rcases allowed_cases b h _ proto limit ha with
    ⟨-, -, s, d, f', hs, hd, -, hA, hB, hC⟩ | ⟨-, -, s, d, f', -, -, hf, -⟩
  · refine ⟨h, s, d, hp, hs, hd, ?_⟩
    have hsl : s.length = 4 := by
      rcases (parse_facts b h hp).2 with ⟨hs', -, hl, -⟩ | ⟨hs', -⟩
      · rw [hs] at hs'; cases hs'; exact hl
      · rw [hs] at hs'; cases hs'
    have hone : oneHost (.v4 s) = true := by
      cases ho : oneHost (.v4 s)
      · exact absurd (Or.inr ho) hA
      · rfl
    intro hF
    rcases hF with hl | hn | hg | ⟨hpr, hfirst⟩
    · exact hA (Or.inl hl)
    · exact (oneHost_v4 s hsl).1 hone hn
    · rcases hg with hg | hg
      · exact hB (Or.inr hg)
      · exact hB (Or.inl hg)
    · apply hC ⟨hpr, ?_⟩
      cases hfb : firstByte b h with
      | none => rw [hfb] at hfirst; simp at hfirst
      | some t =>
        rw [hfb] at hfirst
        simp only [Option.any_some, isErrorV4, Bool.or_eq_true, beq_iff_eq] at hfirst
        rcases hfirst with (((h1 | h1) | h1) | h1) | h1 <;> (subst h1; decide)
  · cases hf

/-- Conversely, the engine sends every IPv4 error RFC 1122 allows, except
about ICMP messages that are neither queries nor errors, or have no type
byte. -/
theorem error_v4_sent (b f : Bytes) (k c w : Nat) (h : Hdr) (s d : Bytes)
    (hp : parse b = some h) (hs : h.src = .v4 s) (hd : h.dst = .v4 d)
    (hn : ¬rfcForbidsV4 b h s d) (hq : h.proto = 1 → (firstByte b h).any queryV4 = true) :
    (error b (.v4 f) k c w).isSome = true := by
  have hsl : s.length = 4 := by
    rcases (parse_facts b h hp).2 with ⟨hs', -, hl, -⟩ | ⟨hs', -⟩
    · rw [hs] at hs'; cases hs'; exact hl
    · rw [hs] at hs'; cases hs'
  have hone : oneHost (.v4 s) = true := (oneHost_v4 s hsl).2 (fun x => hn (Or.inr (Or.inl x)))
  have hA : ¬(h.later = true ∨ oneHost h.src = false) := by
    rintro (hl | ho)
    · exact hn (Or.inl hl)
    · rw [hs, hone] at ho; cases ho
  have hB : ¬(d = [255, 255, 255, 255] ∨ (224 ≤ byte d 0 ∧ byte d 0 < 240)) := by
    rintro (hg | hg)
    · exact hn (Or.inr (Or.inr (Or.inl (Or.inr hg))))
    · exact hn (Or.inr (Or.inr (Or.inl (Or.inl hg))))
  have hC : ¬(h.proto = 1 ∧ ¬(firstByte b h).any queryV4 = true) := by
    rintro ⟨hpr, hnq⟩
    exact hnq (hq hpr)
  have ha : allowed b h (.v4 f) = some (1, 548) := by
    unfold allowed
    rw [hs, hd]
    simp only []
    rw [← hs, if_neg hA, if_neg hB, if_neg hC]
  unfold error
  rw [hp]
  simp only [ha, Option.isSome_some]

/-- The ICMPv6 types that are error messages (RFC 4443 section 2.1: types
0 to 127), and Redirect (RFC 4861), about which no error is sent. -/
def isErrorV6 (t : Nat) : Bool := t < 128 || t == 137

/-- RFC 4443 section 2.4(e): an ICMPv6 error is never sent about an ICMPv6
error message or Redirect (e.1, e.2), a packet to a multicast address
(e.3, but see below), or a packet whose source does not name one node: the
unspecified address or a multicast address (e.6). A fragment after the
first holds no ICMPv6 type. -/
def rfcForbidsV6 (b : Bytes) (h : Hdr) (s d : Bytes) : Prop :=
  (h.proto = 58 ∧ h.later = false ∧ (firstByte b h).any isErrorV6 = true) ∨ byte d 0 = 255 ∨
    s.all (· == 0) = true ∨ byte s 0 = 255

/-- **No forbidden ICMPv6 error.** Every ICMPv6 error the engine sends is
one RFC 4443 section 2.4(e) allows. -/
theorem error_v6_allowed (b f : Bytes) (k c w : Nat) (out : Bytes)
    (he : error b (.v6 f) k c w = some out) :
    ∃ h s d, parse b = some h ∧ h.src = .v6 s ∧ h.dst = .v6 d ∧ ¬rfcForbidsV6 b h s d := by
  obtain ⟨h, proto, limit, hp, ha, -⟩ := error_message b _ k c w out he
  rcases allowed_cases b h _ proto limit ha with
    ⟨-, -, s, d, f', -, -, hf, -⟩ | ⟨-, -, s, d, f', hs, hd, -, hA, hC⟩
  · cases hf
  · refine ⟨h, s, d, hp, hs, hd, ?_⟩
    rintro (⟨hpr, hl, hfirst⟩ | hm | hz | hm)
    · apply hC ⟨hpr, hl, ?_⟩
      cases hfb : firstByte b h with
      | none => rw [hfb] at hfirst; simp at hfirst
      | some t =>
        rw [hfb] at hfirst
        simp only [Option.any_some, isErrorV6, Bool.or_eq_true, decide_eq_true_eq,
          beq_iff_eq] at hfirst
        simp only [Option.all_some, decide_eq_true_eq]
        omega
    · exact hA (Or.inr hm)
    · exact hA (Or.inl (by simp [oneHost, hz]))
    · exact hA (Or.inl (by simp [oneHost, hm]))

/-- Conversely, the engine sends every ICMPv6 error RFC 4443 section 2.4(e)
allows, except from loopback, about Neighbor Discovery messages (types 133
to 136, which stay on one link), about an ICMPv6 message with no type byte,
and the two exceptions of (e.3): Packet Too Big, which the engine never
generates, and Parameter Problem code 2 for an option whose type starts
with the bits 10, which `parameter_problem` does not send to a multicast
destination (it has no unicast address of the host to send from). -/
theorem error_v6_sent (b f : Bytes) (k c w : Nat) (h : Hdr) (s d : Bytes)
    (hp : parse b = some h) (hs : h.src = .v6 s) (hd : h.dst = .v6 d)
    (hn : ¬rfcForbidsV6 b h s d) (hl : s ≠ loopback6)
    (hq : h.proto = 58 → h.later = false →
      (firstByte b h).any (fun t => 128 ≤ t ∧ ¬(133 ≤ t ∧ t ≤ 136)) = true) :
    (error b (.v6 f) k c w).isSome = true := by
  have hz : s.all (· == 0) = false := by
    cases hx : s.all (· == 0)
    · rfl
    · exact absurd (Or.inr (Or.inr (Or.inl hx))) hn
  have hb : byte s 0 ≠ 255 := fun hx => hn (Or.inr (Or.inr (Or.inr hx)))
  have hone : oneHost (.v6 s) = true := by simp [oneHost, hz, hb, hl]
  have hA : ¬(oneHost h.src = false ∨ byte d 0 = 255) := by
    rintro (ho | hm)
    · rw [hs, hone] at ho; cases ho
    · exact hn (Or.inr (Or.inl hm))
  have hC : ¬(h.proto = 58 ∧ h.later = false ∧
      (firstByte b h).all (fun t => t < 128 ∨ (133 ≤ t ∧ t ≤ 137)) = true) := by
    rintro ⟨hpr, hlt, hall⟩
    have hq' := hq hpr hlt
    cases hfb : firstByte b h with
    | none => rw [hfb] at hq'; simp at hq'
    | some t =>
      rw [hfb] at hq' hall
      simp only [Option.any_some, Option.all_some, decide_eq_true_eq] at hq' hall
      apply hn (Or.inl ⟨hpr, hlt, ?_⟩)
      rw [hfb]
      simp only [Option.any_some, isErrorV6, Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq]
      omega
  have ha : allowed b h (.v6 f) = some (58, 1232) := by
    unfold allowed
    rw [hs, hd]
    simp only []
    rw [← hs, if_neg hA, if_neg hC]
  unfold error
  rw [hp]
  simp only [ha, Option.isSome_some]

/-- RFC 8200 section 4.2: an unrecognized option whose type starts with the
bits 10 is answered with Parameter Problem whatever the destination; one
that starts with 11 only when the destination is not multicast. -/
def rfcAnswersOption (b : Bytes) (p : Nat) : Prop :=
  byte b p / 64 = 2 ∨ byte b 24 ≠ 255

/-- **Option answers.** When the engine answers an unrecognized option
(Parameter Problem code 2), RFC 8200 section 4.2 asks for that answer too:
the option's type starts with 10 or 11 and the destination is not
multicast. The converse misses one case, a 10 option to a multicast
destination, which `error_v6_sent` names. -/
theorem parameter_problem_option (b : Bytes) (p : Nat) (out : Bytes)
    (hc : chain6 b .check = .error (.problem 2 p))
    (h : parameterProblem b (.problem 2 p) = some out) :
    2 ≤ byte b p / 64 ∧ byte b 24 ≠ 255 ∧ rfcAnswersOption b p := by
  have h2 := Ip.Ext6.chain6_problem2 b p hc
  obtain ⟨hl, hv⟩ := Ip.Ext6.chain6_problem_header b .check 2 p hc
  have hd : destination b = some (.v6 (slice b 24 40)) := by
    unfold destination
    rw [if_neg (by omega), if_pos ⟨hv, hl⟩]
  simp only [parameterProblem, hd] at h
  obtain ⟨hh, s, d, hp, hs, hdst, hn⟩ := error_v6_allowed b _ 4 2 p out h
  rcases (parse_facts b hh hp).2 with ⟨hs', -⟩ | ⟨-, hd', -, -⟩
  · rw [hs] at hs'; cases hs'
  · rw [hdst] at hd'
    cases hd'
    have hm : byte b 24 ≠ 255 := by
      intro hm
      apply hn (Or.inr (Or.inl ?_))
      have : byte (slice b 24 40) 0 = byte b 24 := by
        simp only [slice, byte, List.getD_eq_getElem?_getD, List.getElem?_take,
          List.getElem?_drop]
        simp
      rw [this]; exact hm
    exact ⟨h2, hm, Or.inr hm⟩

/-! ## Echo replies -/

/-- **Echo replies.** A reply goes from the address the request was sent to
back to the request's source, which names one host. Its message is the
request's with the reply type (0 over IPv4, RFC 792; 129 over IPv6, RFC
4443 section 4.2), the same code, and the request's identifier, sequence
number and data (every byte after the checksum) unchanged, and its
checksum verifies. -/
theorem echo_reply_copies (b : Bytes) (addr : Addr) (out : Bytes)
    (he : echoReply b addr = some out) (hb : ∀ x ∈ b, x < 256) :
    ∃ h rep, parseWhole b = some h ∧ h.dst = addr ∧ oneHost h.src = true ∧
      8 ≤ (slice b h.start h.stop).length ∧
      ((∃ a, addr = .v4 a) ∧ rep = 0 ∧
          out = ipPacket addr h.src 1 { id := be16 b 4, tos := byte b 1, df := false }
            (replyMessage addr h.src rep (slice b h.start h.stop)) ∨
        (∃ a, addr = .v6 a) ∧ rep = 129 ∧
          out = b.take 4 ++ (ipPacket addr h.src 58 {}
            (replyMessage addr h.src rep (slice b h.start h.stop))).drop 4) ∧
      (replyMessage addr h.src rep (slice b h.start h.stop)).drop 4 =
        (slice b h.start h.stop).drop 4 ∧
      byte (replyMessage addr h.src rep (slice b h.start h.stop)) 0 = rep ∧
      byte (replyMessage addr h.src rep (slice b h.start h.stop)) 1 =
        byte (slice b h.start h.stop) 1 ∧
      checksum (prefixOf addr h.src (slice b h.start h.stop).length ++
        replyMessage addr h.src rep (slice b h.start h.stop)) = 0 := by
  unfold echoReply at he
  cases hw : parseWhole b with
  | none => rw [hw] at he; simp at he
  | some h =>
    rw [hw] at he
    simp only [] at he
    by_cases hok : h.dst ≠ addr ∨ oneHost h.src = false
    · rw [if_pos hok] at he; simp at he
    · rw [if_neg hok] at he
      have hdst : h.dst = addr := Classical.byContradiction fun hne => hok (Or.inl hne)
      have hone : oneHost h.src = true := by
        cases hx : oneHost h.src
        · exact absurd (Or.inr hx) hok
        · rfl
      have hil : ∀ x ∈ slice b h.start h.stop, x < 256 := slice_lt b hb _ _
      have hpre : (prefixOf addr h.src (slice b h.start h.stop).length).length % 2 = 0 ∧
          ∀ x ∈ prefixOf addr h.src (slice b h.start h.stop).length, x < 256 := by
        rcases parseWhole_facts b h hw with ⟨hs, hd, hsl, hdl⟩ | ⟨hs, hd, hsl, hdl⟩
        · rw [← hdst, hs, hd]
          exact prefix_ok _ _ _ (slice_lt b hb _ _) (slice_lt b hb _ _)
            (by simp only [Addr.bytes]; omega) (by simp only [Addr.bytes]; omega)
        · rw [← hdst, hs, hd]
          exact prefix_ok _ _ _ (slice_lt b hb _ _) (slice_lt b hb _ _)
            (by simp only [Addr.bytes]; omega) (by simp only [Addr.bytes]; omega)
      have common : ∀ rep, rep < 256 → 8 ≤ (slice b h.start h.stop).length →
          (replyMessage addr h.src rep (slice b h.start h.stop)).drop 4 =
            (slice b h.start h.stop).drop 4 ∧
          byte (replyMessage addr h.src rep (slice b h.start h.stop)) 0 = rep ∧
          byte (replyMessage addr h.src rep (slice b h.start h.stop)) 1 =
            byte (slice b h.start h.stop) 1 ∧
          checksum (prefixOf addr h.src (slice b h.start h.stop).length ++
            replyMessage addr h.src rep (slice b h.start h.stop)) = 0 := by
        intro rep hrep h8
        refine ⟨by simp [replyMessage, filled], by simp [replyMessage, filled, byte],
          by simp [replyMessage, filled, byte], ?_⟩
        exact filled_verifies _ _ _ _ hpre.1 hpre.2 hrep (byte_lt _ hil 1)
          (fun x hx => hil x (List.mem_of_mem_drop hx))
      cases addr with
      | v4 a =>
        simp only [] at he
        by_cases hc : h.proto ≠ 1 ∨ (slice b h.start h.stop).length < 8 ∨
            byte (slice b h.start h.stop) 0 ≠ 8 ∨ byte (slice b h.start h.stop) 1 ≠ 0 ∨
            checksum (slice b h.start h.stop) ≠ 0
        · rw [if_pos hc] at he; simp at he
        · rw [if_neg hc] at he
          have h8 : 8 ≤ (slice b h.start h.stop).length :=
            Classical.byContradiction fun hn => hc (Or.inr (Or.inl (by omega)))
          simp only [Option.some.injEq] at he
          exact ⟨h, 0, by first | rfl | exact hw, hdst, hone, h8, Or.inl ⟨⟨a, rfl⟩, rfl, he.symm⟩,
            common 0 (by omega) h8⟩
      | v6 a =>
        simp only [] at he
        by_cases hc : h.proto ≠ 58 ∨ (slice b h.start h.stop).length < 8 ∨
            byte (slice b h.start h.stop) 0 ≠ 128 ∨ byte (slice b h.start h.stop) 1 ≠ 0 ∨
            checksum (prefixOf h.src (.v6 a) (slice b h.start h.stop).length ++
              slice b h.start h.stop) ≠ 0
        · rw [if_pos hc] at he; simp at he
        · rw [if_neg hc] at he
          have h8 : 8 ≤ (slice b h.start h.stop).length :=
            Classical.byContradiction fun hn => hc (Or.inr (Or.inl (by omega)))
          simp only [Option.some.injEq] at he
          exact ⟨h, 129, by first | rfl | exact hw, hdst, hone, h8, Or.inr ⟨⟨a, rfl⟩, rfl, he.symm⟩,
            common 129 (by omega) h8⟩

/-! ## Vectors -/

open Ip.Ext6 (Gen rand pick randBytes genPacket rejectJson)

/-- An IPv4 source: mostly one host, sometimes one of each kind that is not. -/
def genV4Src : Gen Bytes := do
  let r ← randBytes 3
  let k ← rand 12
  let m ← rand 16
  let e ← rand 15
  let u ← rand 223
  return match k with
    | 0 => [0, 0, 0, 0]
    | 1 => 0 :: r
    | 2 => 127 :: r
    | 3 => (224 + m) :: r
    | 4 => (240 + e) :: r
    | 5 => [255, 255, 255, 255]
    | _ => (1 + u) :: r

def genV4Dst : Gen Bytes := do
  let r ← randBytes 3
  let k ← rand 8
  let m ← rand 16
  let u ← rand 223
  return match k with
    | 0 => [255, 255, 255, 255]
    | 1 => (224 + m) :: r
    | _ => (1 + u) :: r

def genV6Src : Gen Bytes := do
  let r ← randBytes 15
  let k ← rand 10
  return match k with
    | 0 => List.replicate 16 0
    | 1 => loopback6
    | 2 => 255 :: r
    | _ => 32 :: 1 :: r.drop 1

def genV6Dst : Gen Bytes := do
  let r ← randBytes 14
  let k ← rand 6
  return match k with
    | 0 => 255 :: 2 :: r
    | _ => 32 :: 1 :: r

def genLen : Gen Nat := do
  let k ← rand 10
  let a ← rand 1400
  let b ← rand 700
  let c ← rand 40
  return match k with
    | 0 => a
    | 1 => b
    | _ => c

/-- A random IPv4 packet, mostly well formed. -/
def genV4 : Gen Bytes := do
  let ihl ← pick [5, 5, 5, 5, 5, 6, 8, 15, 4]
  let other ← rand 256
  let proto ← pick [1, 1, 1, 6, 17, other]
  let plen ← genLen
  let payload ← randBytes plen
  let t0 ← rand 256
  let kind ← pick [0, 3, 4, 5, 8, 9, 11, 12, 13, 14, 17, 18, 30, 42, t0]
  let payload := if proto = 1 ∧ plen > 0 then kind :: payload.drop 1 else payload
  let hl := max ihl 5 * 4
  let k ← rand 12
  let more ← rand 8
  let less ← rand 30
  let total := match k with
    | 0 => hl + plen + 1 + more
    | 1 => hl + plen - min (hl + plen) less
    | _ => hl + plen
  let total := min total 65535
  let off ← rand 8191
  let off2 ← rand 8192
  let flags ← pick [0, 0, 0, 16384, 8192, 1 + off, 8192 + off2]
  let tos ← rand 256
  let id1 ← rand 256
  let id2 ← rand 256
  let ttl ← rand 256
  let src ← genV4Src
  let dst ← genV4Dst
  let opts ← randBytes (hl - 20)
  let h0 := [64 + ihl, tos, total / 256, total % 256, id1, id2, flags / 256, flags % 256, ttl,
    proto, 0, 0] ++ src ++ dst ++ opts
  let c := checksum h0
  let bad ← rand 10
  let h1 := if bad = 0 then h0 else (h0.set 10 (c / 256)).set 11 (c % 256)
  return h1 ++ payload

/-- A random IPv6 packet: half with no extension headers, half from the
extension-header generator with new addresses. -/
def genV6 : Gen Bytes := do
  let chain ← genPacket
  let src ← genV6Src
  let dst ← genV6Dst
  let other ← rand 256
  let proto ← pick [58, 58, 58, 6, 17, other]
  let plen ← genLen
  let payload ← randBytes plen
  let t0 ← rand 256
  let kind ← pick [1, 2, 3, 4, 100, 127, 128, 129, 133, 134, 135, 136, 137, 138, t0]
  let payload := if proto = 58 ∧ plen > 0 then kind :: payload.drop 1 else payload
  let k ← rand 12
  let len := if k = 0 then plen + 1 else plen
  let hop ← rand 256
  let which ← rand 2
  if which = 0 then
    return if chain.length ≥ 40 then chain.take 8 ++ src ++ dst ++ chain.drop 40 else chain
  else
    return [96, 0, 0, 0, len / 256, len % 256, proto, hop] ++ src ++ dst ++ payload

def genFrom (six : Bool) : Gen Addr := do
  let flip ← rand 10
  let six := if flip = 0 then !six else six
  let r6 ← randBytes 14
  let r4 ← randBytes 3
  return if six then .v6 (32 :: 1 :: r6) else .v4 (10 :: r4)

/-- An echo request, mostly one the host answers. -/
def genEcho : Gen (Bytes × Addr) := do
  let six := (← rand 2) == 0
  let n ← genLen
  let data ← randBytes n
  let odd ← rand 8
  let t0 ← rand 256
  let other ← pick [0, 8, 13, 128, 129, t0]
  let kind := if odd = 0 then other else if six then 128 else 8
  let oddCode ← rand 10
  let c0 ← rand 256
  let code := if oddCode = 0 then c0 else 0
  let idseq ← randBytes 4
  let rest := idseq ++ data
  let short ← rand 12
  let keep ← rand 4
  let rest := if short = 0 then rest.take keep else rest
  let me ← genFrom six
  let me := match six, me with
    | true, .v4 _ => Addr.v6 (32 :: 1 :: List.replicate 14 7)
    | false, .v6 _ => Addr.v4 [10, 0, 0, 1]
    | _, a => a
  let s6 ← genV6Src
  let s4 ← genV4Src
  let src := if six then Addr.v6 s6 else Addr.v4 s4
  let elsewhere ← rand 10
  let other ← genFrom six
  let dst := if elsewhere = 0 then other else me
  let msg := filled (prefixOf src dst (4 + rest.length)) kind code rest
  let corrupt ← rand 10
  let msg := if corrupt = 0 then msg.set 7 ((byte msg 7 + 1) % 256) else msg
  let ttl ← rand 256
  let tos ← rand 256
  let id ← rand 65536
  let df ← rand 2
  let p := ipPacket src dst (if six then 58 else 1) { ttl, tos, id, df := df = 0 } msg
  let variant ← rand 14
  let n := msg.length + 8
  let p := match variant with
    | 0 => p.set 6 (byte p 6 ||| 32)
    | 1 => p.set 11 ((byte p 11 + 1) % 256)
    | 2 =>
      -- Over IPv6, the same request behind a Hop-by-Hop header with a PadN option.
      if six then p.take 4 ++ [n / 256, n % 256, 0] ++ (p.drop 7).take 33 ++
          [58, 0, 1, 4, 0, 0, 0, 0] ++ msg
      else p
    | _ => p
  return (p, me)

open Lean in
def bytesJson (o : Option Bytes) : Json :=
  match o with
  | some b => toJson b
  | none => Json.null

open Lean in
def genCase : Gen Json := do
  let k ← rand 8
  let six := (← rand 2) == 0
  let p6 ← genV6
  let p4 ← genV4
  let from_ ← genFrom six
  let kind ← rand 256
  let code ← rand 256
  let w ← rand 4294967296
  let c4 ← rand 4
  let ptr ← rand 80
  let (p, me) ← genEcho
  if k ≤ 1 then
    return Json.mkObj [("fn", Json.str "echo"), ("packet", toJson p), ("addr", toJson me.bytes),
      ("out", bytesJson (echoReply p me))]
  else if k = 2 then
    let r : Reject := match chain6 p6 .check with
      | .error r => r
      | .ok _ => .problem c4 ptr
    return Json.mkObj [("fn", Json.str "parameter_problem"), ("packet", toJson p6),
      ("reject", rejectJson r), ("out", bytesJson (parameterProblem p6 r))]
  else
    let pkt := if six then p6 else p4
    let (name, kind, code, w) : String × Nat × Nat × Nat :=
      if k = 3 then ("time_exceeded", if from_ matches .v4 _ then 11 else 3, 0, 0)
      else if k = 4 then
        match from_ with
        | .v4 _ => ("host_unreachable", 3, 1, 0)
        | .v6 _ => ("address_unreachable", 1, 3, 0)
      else ("error", kind, code, w)
    let base := [("fn", Json.str name), ("packet", toJson pkt), ("from", toJson from_.bytes),
      ("out", bytesJson (error pkt from_ kind code w))]
    return Json.mkObj (if name = "error" then
      base ++ [("kind", toJson kind), ("code", toJson code), ("word", toJson w)] else base)

open Lean in
def vectors (seed : Nat) : List (String × Json) :=
  let go : Gen (Array Json) := do
    let mut out := #[]
    for _ in [0:5000] do
      out := out.push (← genCase)
    return out
  [("icmp", Json.arr (go.run' (seed + 58)))]

end Ip.Icmp
