import Lean

/-! IPv6 extension headers as a destination host checks them (RFC 8200
sections 3 and 4 to 4.6, RFC 7112 section 5, RFC 6946).

Two definitions of the same decision:

- `chain6` follows `chain6` and `check_options` in
  `src/stdlib/network/ip.rs` step for step: one loop over the chain that
  checks each header as it goes and returns at the first fault.
- `rfcCheck` is the RFC's account: first lay the chain out as RFC 8200
  section 4 describes it (`decode`), then apply the rules of sections 4.1
  to 4.5 to the headers in order (`faultOf`, `scan`), then the first
  fragment rule of RFC 7112 section 5 (`tail`).

`chain6_check_eq_rfc` proves the two equal for every byte list. The vector
file `ext6.json` ties `chain6` to the Rust: `tests/ip_vectors/ext6.rs`
replays it against `Header::check`, `Header::parse`,
`Header::parse_truncated` and `strip_extension_headers`.

Octets are `Nat`s. A read past the end gives 0, which the length checks
make harmless: where the Rust's `get` returns `None`, the header runs past
the packet either way. -/

namespace Ip.Ext6

abbrev Bytes := List Nat

/-- The octet at offset `i`, 0 past the end. -/
def byte (b : Bytes) (i : Nat) : Nat := b.getD i 0

/-- The 16-bit big-endian field at offset `i`. -/
def be16 (b : Bytes) (i : Nat) : Nat := byte b i * 256 + byte b (i + 1)

/-- The 32-bit big-endian field at offset `i`. -/
def be32 (b : Bytes) (i : Nat) : Nat := be16 b i * 65536 + be16 b (i + 2)

-- Next Header values (IANA protocol numbers; RFC 8200 section 4). They are
-- notations for the numbers, so that `simp` and `decide` see the numbers.
scoped notation "HBH" => (0 : Nat)
scoped notation "TCP" => (6 : Nat)
scoped notation "UDP" => (17 : Nat)
scoped notation "ROUTING" => (43 : Nat)
scoped notation "FRAG" => (44 : Nat)
scoped notation "AUTH" => (51 : Nat)
scoped notation "ICMPV6" => (58 : Nat)
scoped notation "NONE" => (59 : Nat)
scoped notation "DEST" => (60 : Nat)

/-- Why a host does not take a packet in (`Reject` in the Rust). -/
inductive Reject where
  /-- Drop it silently. -/
  | discard
  /-- Drop it and answer with ICMPv6 Parameter Problem (type 4). -/
  | problem (code pointer : Nat)
  deriving DecidableEq, Repr

/-- A walked chain (`Chain` in the Rust). -/
structure Chain where
  proto : Nat
  upper : Nat
  protoAt : Nat
  /-- The first Fragment header: where it starts, and where the byte naming it is. -/
  frag : Option (Nat × Nat)
  /-- The packet's end: the payload length, cut to the bytes present. -/
  stop : Nat
  /-- 40 plus the payload length. -/
  length : Nat
  deriving DecidableEq, Repr

/-- How the walk goes (`Walk` in the Rust). -/
inductive Mode where
  | read (truncated : Bool)
  | check
  deriving DecidableEq, Repr

/-- The extension headers this host walks: Hop-by-Hop Options, Destination
Options, Routing, Authentication and Fragment (RFC 8200 section 4.1). -/
def isExt (next : Nat) : Bool :=
  next == HBH || next == DEST || next == ROUTING || next == AUTH || next == FRAG

/-- An extension header's length in bytes. Hop-by-Hop, Destination Options
and Routing count 8-byte units after the first 8 (RFC 8200 sections 4.3,
4.4, 4.6); the Authentication header counts 4-byte units after the first
two (RFC 4302 section 2.2); a Fragment header is 8 bytes (section 4.5). -/
def extLen (b : Bytes) (next pos : Nat) : Nat :=
  if next = AUTH then (byte b (pos + 1) + 2) * 4
  else if next = FRAG then 8
  else (byte b (pos + 1) + 1) * 8

theorem extLen_ge (b : Bytes) (next pos : Nat) : 8 ≤ extLen b next pos := by
  unfold extLen; split
  · omega
  · split <;> omega

/-- A first fragment: offset 0, more to come. -/
def isFirst (b : Bytes) : Option (Nat × Nat) → Bool
  | none => false
  | some (pos, _) => be16 b (pos + 2) / 8 == 0 && be16 b (pos + 2) % 2 == 1

/-- The upper-layer header's fixed part that a first fragment must hold
(RFC 7112 section 5): 20 bytes of TCP, 8 of UDP, 4 of ICMPv6 (RFC 4443
section 2.1), none for others. -/
def need (p : Nat) : Nat :=
  if p = TCP then 20 else if p = UDP then 8 else if p = ICMPV6 then 4 else 0

/-! ## The code: `check_options` and `chain6` -/

/-- `check_options` over the header that starts at `base`, `len` bytes
long, from offset `i` in it. `none` when every option passes. -/
def optWalk (b : Bytes) (base len i : Nat) : Option Reject :=
  if _ : i < len then
    if byte b (base + i) = 0 then optWalk b base len (i + 1)
    else if i + 2 > len ∨ i + 2 + byte b (base + i + 1) > len then some .discard
    else if byte b (base + i) = 1 then optWalk b base len (i + 2 + byte b (base + i + 1))
    else if byte b (base + i) / 64 = 0 then optWalk b base len (i + 2 + byte b (base + i + 1))
    else if byte b (base + i) / 64 = 1 then some .discard
    else some (.problem 2 (base + i))
  else none
termination_by len - i

/-- One header's checks in the loop of `chain6`, and the Fragment header
it notes. -/
def step (b : Bytes) (mode : Mode) (next nextAt pos len : Nat) (frag : Option (Nat × Nat)) :
    Except Reject (Option (Nat × Nat)) :=
  if mode = .check ∧ (next = HBH ∨ next = DEST) then
    match optWalk b pos len 2 with
    | some r => .error r
    | none => .ok frag
  else if mode = .check ∧ next = ROUTING ∧ byte b (pos + 3) ≠ 0 then .error (.problem 0 (pos + 2))
  else if next = FRAG then
    match frag with
    | some _ => if mode = .check then .error .discard else .ok frag
    | none => .ok (some (pos, nextAt))
  else .ok frag

/-- After the loop of `chain6`: the first fragment rule, and the chain. -/
def finish (b : Bytes) (mode : Mode) (fin length next nextAt pos : Nat)
    (frag : Option (Nat × Nat)) : Except Reject Chain :=
  if mode = .check ∧ isFirst b frag = true ∧ fin - pos < need next then .error (.problem 3 0)
  else .ok ⟨next, pos, nextAt, frag, fin, length⟩

/-- The loop of `chain6`: at the header `next`, named by the byte at
offset `nextAt`, starting at offset `pos`. A Fragment header with a
nonzero offset (`8 ≤ be16`) ends the walk. -/
def walkFrom (b : Bytes) (mode : Mode) (fin length next nextAt pos : Nat)
    (frag : Option (Nat × Nat)) : Except Reject Chain :=
  if mode = .check ∧ next = HBH ∧ nextAt ≠ 6 then .error (.problem 1 nextAt)
  else if isExt next then
    if _ : pos + extLen b next pos ≤ fin then
      match step b mode next nextAt pos (extLen b next pos) frag with
      | .error r => .error r
      | .ok frag' =>
        if next = FRAG ∧ 8 ≤ be16 b (pos + 2) then
          finish b mode fin length (byte b pos) pos (pos + extLen b next pos) frag'
        else walkFrom b mode fin length (byte b pos) pos (pos + extLen b next pos) frag'
    else if mode = .check then
      .error (if isFirst b frag = true ∧ next ≠ FRAG then .problem 3 0 else .discard)
    else .ok ⟨NONE, min pos fin, nextAt, frag, fin, length⟩
  else finish b mode fin length next nextAt pos frag
termination_by fin - pos
decreasing_by have := extLen_ge b next pos; omega

/-- `chain6` in `ip.rs`: the walk of an IPv6 packet's chain. -/
def chain6 (b : Bytes) (mode : Mode) : Except Reject Chain :=
  if b.length < 40 ∨ byte b 0 / 16 ≠ 6 then .error .discard
  else if b.length < 40 + be16 b 4 ∧ mode ≠ .read true then .error .discard
  else walkFrom b mode (min (40 + be16 b 4) b.length) (40 + be16 b 4) (byte b 6) 6 40 none

/-! ## The RFC's account -/

/-- One option of a Hop-by-Hop or Destination Options header (RFC 8200
section 4.2). -/
inductive Opt where
  /-- Pad1: one zero byte. -/
  | pad1
  /-- A type-length-value option of this type, starting at offset `pos`. -/
  | tlv (type pos : Nat)
  /-- An option whose length runs past its header. -/
  | bad
  deriving DecidableEq, Repr

/-- The options of the header that starts at `base`, `len` bytes long, from
offset `i`, in order. -/
def opts (b : Bytes) (base len i : Nat) : List Opt :=
  if _ : i < len then
    if byte b (base + i) = 0 then .pad1 :: opts b base len (i + 1)
    else if len < i + 2 + byte b (base + i + 1) then [.bad]
    else .tlv (byte b (base + i)) (base + i) :: opts b base len (i + 2 + byte b (base + i + 1))
  else []
termination_by len - i

/-- What one option asks of a destination (RFC 8200 section 4.2): Pad1 and
PadN nothing; for any other, unknown here, its type's two high bits: 00
skip it, 01 discard the packet, 10 and 11 discard it and send Parameter
Problem code 2 pointing at the option. (For 11 the RFC sends the answer
only when the destination is not multicast: `parameter_problem_option` in
`Icmp.lean` takes that up.) An option that runs past its header is
discarded, as Linux does; the RFC does not say. -/
def action : Opt → Option Reject
  | .pad1 => none
  | .bad => some .discard
  | .tlv t pos =>
    if t = 1 then none
    else if t / 64 = 0 then none
    else if t / 64 = 1 then some .discard
    else some (.problem 2 pos)

/-- The first option that asks for something, in order. -/
def optionsVerdict (b : Bytes) (base len : Nat) : Option Reject :=
  (opts b base len 2).findSome? action

/-- One extension header in the chain: its Next Header value (the kind),
where it starts, its length, and where the byte naming it is. -/
structure Ext where
  kind : Nat
  start : Nat
  len : Nat
  nhAt : Nat
  deriving DecidableEq, Repr

/-- How a chain ends. -/
inductive Stop where
  /-- At the upper-layer header, or at the bytes after a non-first
  fragment's Fragment header, which belong to the first fragment's chain
  (RFC 8200 section 4.5). -/
  | upper (proto pos protoAt : Nat)
  /-- At an extension header that runs past the packet. -/
  | past (kind pos nhAt : Nat)
  deriving DecidableEq, Repr

/-- The chain laid out as RFC 8200 section 4 describes it: each header's
Next Header byte names the next, up to the upper-layer header. -/
def decode (b : Bytes) (fin next nextAt pos : Nat) : List Ext × Stop :=
  if isExt next then
    if _ : pos + extLen b next pos ≤ fin then
      if next = FRAG ∧ 8 ≤ be16 b (pos + 2) then
        ([⟨next, pos, extLen b next pos, nextAt⟩], .upper (byte b pos) (pos + extLen b next pos) pos)
      else
        (⟨next, pos, extLen b next pos, nextAt⟩ ::
            (decode b fin (byte b pos) pos (pos + extLen b next pos)).1,
          (decode b fin (byte b pos) pos (pos + extLen b next pos)).2)
    else ([], .past next pos nextAt)
  else ([], .upper next pos nextAt)
termination_by fin - pos
decreasing_by all_goals (have := extLen_ge b next pos; omega)

/-- What one header asks of the destination host, in the order the RFC
gives (`seen`: a Fragment header came earlier):

- Hop-by-Hop Options anywhere but right after the IPv6 header: Parameter
  Problem code 1, pointing at the Next Header byte that names it
  (RFC 8200 sections 4.1 and 4.3).
- Hop-by-Hop and Destination Options: their options (section 4.2,
  `optionsVerdict`).
- A Routing header with Segments Left above 0: this host knows no
  routing type, so code 0, pointing at the Routing Type (section 4.4).
  With Segments Left 0 it is skipped.
- A second Fragment header: discarded. This is the code's choice, not
  the RFC's (section 4.1 asks hosts to take headers any number of times):
  a fragment inside a fragment. -/
def faultOf (b : Bytes) (seen : Bool) (e : Ext) : Option Reject :=
  if e.kind = HBH ∧ e.nhAt ≠ 6 then some (.problem 1 e.nhAt)
  else if e.kind = HBH ∨ e.kind = DEST then optionsVerdict b e.start e.len
  else if e.kind = ROUTING ∧ byte b (e.start + 3) ≠ 0 then some (.problem 0 (e.start + 2))
  else if e.kind = FRAG ∧ seen = true then some .discard
  else none

/-- The first header that asks for something, in order. -/
def scan (b : Bytes) : Bool → List Ext → Option Reject
  | _, [] => none
  | seen, e :: es =>
    match faultOf b seen e with
    | some r => some r
    | none => scan b (seen || e.kind == FRAG) es

/-- The first Fragment header in a chain. -/
def firstFragOf : List Ext → Option (Nat × Nat)
  | [] => none
  | e :: es => if e.kind = FRAG then some (e.start, e.nhAt) else firstFragOf es

/-- How the chain ends: RFC 7112 section 5 asks a first fragment to hold the
whole chain and the upper-layer header, else Parameter Problem code 3 with
pointer 0. Any other header that runs past the packet discards it; a
misplaced Hop-by-Hop header is reported first, as for one that fits. -/
def tail (b : Bytes) (fin length : Nat) (frag : Option (Nat × Nat)) : Stop → Except Reject Chain
  | .upper p u pa =>
    if Mode.check = Mode.check ∧ isFirst b frag = true ∧ fin - u < need p then .error (.problem 3 0)
    else .ok ⟨p, u, pa, frag, fin, length⟩
  | .past k _ nh =>
    if k = HBH ∧ nh ≠ 6 then .error (.problem 1 nh)
    else .error (if isFirst b frag = true ∧ k ≠ FRAG then .problem 3 0 else .discard)

/-- The decision for a decoded chain, with `frag` the Fragment header found
before it. -/
def resolve (b : Bytes) (fin length : Nat) (frag : Option (Nat × Nat))
    (d : List Ext × Stop) : Except Reject Chain :=
  match scan b frag.isSome d.1 with
  | some r => .error r
  | none => tail b fin length (frag.or (firstFragOf d.1)) d.2

/-- The RFC's decision for a packet that arrives at its destination. A
packet shorter than 40 bytes, or than its payload length says (RFC 8200
section 3), is not a whole IPv6 packet and is discarded. Bytes past the
payload length are not the packet's. A payload length of 0 with a
Hop-by-Hop header (a jumbogram, RFC 2675) leaves no room for that header,
so the packet is discarded: no link here carries more than 65,575 bytes. -/
def rfcCheck (b : Bytes) : Except Reject Chain :=
  if b.length < 40 ∨ byte b 0 / 16 ≠ 6 then .error .discard
  else if b.length < 40 + be16 b 4 then .error .discard
  else resolve b (40 + be16 b 4) (40 + be16 b 4) none (decode b (40 + be16 b 4) (byte b 6) 6 40)

/-! ## The two agree -/

theorem optWalk_eq (b : Bytes) (base len : Nat) :
    ∀ n i, len - i = n → optWalk b base len i = (opts b base len i).findSome? action := by
  intro n
  induction n using Nat.strongRecOn with
  | ind n ih =>
    intro i hn
    rw [optWalk, opts]
    by_cases hi : i < len
    · rw [dif_pos hi, dif_pos hi]
      by_cases h0 : byte b (base + i) = 0
      · rw [if_pos h0, if_pos h0, List.findSome?_cons]
        simp only [action]
        exact ih (len - (i + 1)) (by omega) (i + 1) rfl
      · rw [if_neg h0, if_neg h0]
        by_cases hl : len < i + 2 + byte b (base + i + 1)
        · have h' : i + 2 > len ∨ i + 2 + byte b (base + i + 1) > len := by omega
          rw [if_pos h', if_pos hl]
          rfl
        · have h' : ¬(i + 2 > len ∨ i + 2 + byte b (base + i + 1) > len) := by omega
          rw [if_neg h', if_neg hl, List.findSome?_cons]
          have ih' := ih (len - (i + 2 + byte b (base + i + 1))) (by omega)
            (i + 2 + byte b (base + i + 1)) rfl
          by_cases h1 : byte b (base + i) = 1
          · rw [if_pos h1]; simp only [action, if_pos h1]; exact ih'
          · rw [if_neg h1]
            by_cases h2 : byte b (base + i) / 64 = 0
            · rw [if_pos h2]; simp only [action, if_neg h1, if_pos h2]; exact ih'
            · rw [if_neg h2]
              by_cases h3 : byte b (base + i) / 64 = 1
              · rw [if_pos h3]; simp only [action, if_neg h1, if_neg h2, if_pos h3]
              · rw [if_neg h3]; simp only [action, if_neg h1, if_neg h2, if_neg h3]
    · rw [dif_neg hi, dif_neg hi]
      rfl

/-- The Rust `check_options` loop decides as RFC 8200 section 4.2 does. -/
theorem optWalk_eq_rfc (b : Bytes) (base len : Nat) :
    optWalk b base len 2 = optionsVerdict b base len :=
  optWalk_eq b base len _ 2 rfl

-- Unfolding `walkFrom` and `decode` one step at a time.

theorem walk_hbh {b : Bytes} {mode : Mode} {fin length next nextAt pos : Nat}
    {frag : Option (Nat × Nat)} (hh : mode = .check ∧ next = HBH ∧ nextAt ≠ 6) :
    walkFrom b mode fin length next nextAt pos frag = .error (.problem 1 nextAt) := by
  rw [walkFrom, if_pos hh]

theorem walk_ext {b : Bytes} {mode : Mode} {fin length next nextAt pos : Nat}
    {frag : Option (Nat × Nat)} (hh : ¬(mode = .check ∧ next = HBH ∧ nextAt ≠ 6))
    (hx : isExt next = true) (hfit : pos + extLen b next pos ≤ fin) :
    walkFrom b mode fin length next nextAt pos frag =
      match step b mode next nextAt pos (extLen b next pos) frag with
      | .error r => .error r
      | .ok frag' =>
        if next = FRAG ∧ 8 ≤ be16 b (pos + 2) then
          finish b mode fin length (byte b pos) pos (pos + extLen b next pos) frag'
        else walkFrom b mode fin length (byte b pos) pos (pos + extLen b next pos) frag' := by
  rw [walkFrom, if_neg hh, if_pos hx, dif_pos hfit]

theorem walk_past {b : Bytes} {mode : Mode} {fin length next nextAt pos : Nat}
    {frag : Option (Nat × Nat)} (hh : ¬(mode = .check ∧ next = HBH ∧ nextAt ≠ 6))
    (hx : isExt next = true) (hfit : ¬pos + extLen b next pos ≤ fin) :
    walkFrom b mode fin length next nextAt pos frag =
      if mode = .check then
        .error (if isFirst b frag = true ∧ next ≠ FRAG then .problem 3 0 else .discard)
      else .ok ⟨NONE, min pos fin, nextAt, frag, fin, length⟩ := by
  rw [walkFrom, if_neg hh, if_pos hx, dif_neg hfit]

theorem walk_upper {b : Bytes} {mode : Mode} {fin length next nextAt pos : Nat}
    {frag : Option (Nat × Nat)} (hh : ¬(mode = .check ∧ next = HBH ∧ nextAt ≠ 6))
    (hx : ¬isExt next = true) :
    walkFrom b mode fin length next nextAt pos frag = finish b mode fin length next nextAt pos frag := by
  rw [walkFrom, if_neg hh, if_neg hx]

theorem decode_ext {b : Bytes} {fin next nextAt pos : Nat} (hx : isExt next = true)
    (hfit : pos + extLen b next pos ≤ fin) :
    decode b fin next nextAt pos =
      if next = FRAG ∧ 8 ≤ be16 b (pos + 2) then
        ([⟨next, pos, extLen b next pos, nextAt⟩], .upper (byte b pos) (pos + extLen b next pos) pos)
      else
        (⟨next, pos, extLen b next pos, nextAt⟩ ::
            (decode b fin (byte b pos) pos (pos + extLen b next pos)).1,
          (decode b fin (byte b pos) pos (pos + extLen b next pos)).2) := by
  rw [decode, if_pos hx, dif_pos hfit]

theorem decode_past {b : Bytes} {fin next nextAt pos : Nat} (hx : isExt next = true)
    (hfit : ¬pos + extLen b next pos ≤ fin) :
    decode b fin next nextAt pos = ([], .past next pos nextAt) := by
  rw [decode, if_pos hx, dif_neg hfit]

theorem decode_upper {b : Bytes} {fin next nextAt pos : Nat} (hx : ¬isExt next = true) :
    decode b fin next nextAt pos = ([], .upper next pos nextAt) := by
  rw [decode, if_neg hx]

/-- In check mode, a header's checks in the loop are the RFC's `faultOf`,
and the Fragment header it notes is the first one. -/
theorem step_check (b : Bytes) (next nextAt pos len : Nat) (frag : Option (Nat × Nat))
    (hh : ¬(next = HBH ∧ nextAt ≠ 6)) :
    step b .check next nextAt pos len frag =
      match faultOf b frag.isSome ⟨next, pos, len, nextAt⟩ with
      | some r => .error r
      | none => .ok (if next = FRAG then frag.or (some (pos, nextAt)) else frag) := by
  unfold step faultOf
  simp only [true_and]
  rw [if_neg hh]
  by_cases h1 : next = HBH ∨ next = DEST
  · have hn : next ≠ FRAG := by rcases h1 with h | h <;> (rw [h]; decide)
    simp only [if_pos h1, optWalk_eq_rfc]
    cases optionsVerdict b pos len with
    | some r => rfl
    | none => simp only [if_neg hn]
  · simp only [if_neg h1]
    by_cases h2 : next = ROUTING ∧ byte b (pos + 3) ≠ 0
    · simp only [if_pos h2]
    · simp only [if_neg h2]
      by_cases h3 : next = FRAG
      · rw [if_pos h3]
        cases frag with
        | none => simp [h3]
        | some x => simp [h3]
      · rw [if_neg h3]
        simp [h3]

theorem walkFrom_check (b : Bytes) (fin length : Nat) :
    ∀ n next nextAt pos frag, fin - pos = n →
      walkFrom b .check fin length next nextAt pos frag =
        resolve b fin length frag (decode b fin next nextAt pos) := by
  intro n
  induction n using Nat.strongRecOn with
  | ind n ih =>
    intro next nextAt pos frag hn
    by_cases hh : next = HBH ∧ nextAt ≠ 6
    · -- A misplaced Hop-by-Hop header: code 1, whether it fits or not.
      rw [walk_hbh ⟨rfl, hh⟩]
      obtain ⟨h1, h2⟩ := hh
      subst h1
      by_cases hfit : pos + extLen b HBH pos ≤ fin
      · rw [decode_ext (by decide) hfit, if_neg (fun h => absurd h.1 (by decide))]
        simp [resolve, scan, faultOf, h2]
      · rw [decode_past (by decide) hfit]
        simp [resolve, scan, tail, h2]
    · have hh' : ¬(Mode.check = Mode.check ∧ next = HBH ∧ nextAt ≠ 6) := fun h => hh h.2
      by_cases hx : isExt next = true
      · by_cases hfit : pos + extLen b next pos ≤ fin
        · rw [walk_ext hh' hx hfit, decode_ext hx hfit, step_check b next nextAt pos _ frag hh]
          have hlen := extLen_ge b next pos
          cases hf : faultOf b frag.isSome ⟨next, pos, extLen b next pos, nextAt⟩ with
          | some r =>
            simp only []
            split <;> simp [resolve, scan, hf]
          | none =>
            simp only []
            by_cases hl : next = FRAG ∧ 8 ≤ be16 b (pos + 2)
            · rw [if_pos hl, if_pos hl]
              obtain ⟨hl1, -⟩ := hl
              subst hl1
              simp [resolve, scan, hf, firstFragOf, tail, finish]
            · rw [if_neg hl, if_neg hl, ih _ (by omega) _ _ _ _ rfl]
              simp only [resolve, scan, hf]
              by_cases hfr : next = FRAG
              · subst hfr
                cases frag <;> simp [firstFragOf]
              · have hk : (next == FRAG) = false := by simpa using hfr
                simp [hfr, hk, firstFragOf]
        · rw [walk_past hh' hx hfit, decode_past hx hfit]
          simp only [resolve, scan, tail, firstFragOf, Option.or_none, if_neg hh, if_true]
      · rw [walk_upper hh' hx, decode_upper hx]
        simp only [resolve, scan, tail, firstFragOf, Option.or_none, finish]

/-- **Theorem 1.** The code's walk of an IPv6 extension-header chain, as a
destination host takes the packet in, decides every byte list exactly as
the RFC's account does (RFC 8200 sections 3, 4.1 to 4.5; RFC 7112
section 5). -/
theorem chain6_check_eq_rfc (b : Bytes) : chain6 b .check = rfcCheck b := by
  unfold chain6 rfcCheck
  by_cases h1 : b.length < 40 ∨ byte b 0 / 16 ≠ 6
  · rw [if_pos h1, if_pos h1]
  · rw [if_neg h1, if_neg h1]
    by_cases h2 : b.length < 40 + be16 b 4
    · rw [if_pos ⟨h2, by simp⟩, if_pos h2]
    · have h2' : ¬(b.length < 40 + be16 b 4 ∧ Mode.check ≠ Mode.read true) := fun h => h2 h.1
      rw [if_neg h2', if_neg h2]
      have hmin : min (40 + be16 b 4) b.length = 40 + be16 b 4 := Nat.min_eq_left (by omega)
      rw [hmin, walkFrom_check b _ _ _ _ _ _ _ rfl]

/-! ## Positions -/

theorem step_frag (b : Bytes) (mode : Mode) (next nextAt pos len : Nat)
    (frag f' : Option (Nat × Nat)) (h : step b mode next nextAt pos len frag = .ok f') :
    f' = none → frag = none ∧ next ≠ FRAG := by
  intro hf
  subst hf
  unfold step at h
  by_cases h1 : mode = .check ∧ (next = HBH ∨ next = DEST)
  · rw [if_pos h1] at h
    have hn : next ≠ FRAG := by rcases h1.2 with h | h <;> (rw [h]; decide)
    cases hw : optWalk b pos len 2 with
    | some r => rw [hw] at h; simp at h
    | none => rw [hw] at h; simp at h; exact ⟨h, hn⟩
  · rw [if_neg h1] at h
    by_cases h2 : mode = .check ∧ next = ROUTING ∧ byte b (pos + 3) ≠ 0
    · rw [if_pos h2] at h; simp at h
    · rw [if_neg h2] at h
      by_cases h3 : next = FRAG
      · rw [if_pos h3] at h
        cases frag with
        | none => simp at h
        | some x =>
          by_cases hm : mode = .check
          · simp [hm] at h
          · simp [hm] at h
      · rw [if_neg h3] at h
        simp at h
        exact ⟨h, h3⟩

/-- Every walk ends at the packet's end, with the upper-layer header between
where it started and the end, and with no Fragment header found it stops at
a protocol that is no extension header. -/
theorem walkFrom_pos (b : Bytes) (mode : Mode) (fin length : Nat) :
    ∀ n next nextAt pos frag, fin - pos = n → pos ≤ fin → ∀ c,
      walkFrom b mode fin length next nextAt pos frag = .ok c →
        c.stop = fin ∧ c.length = length ∧ pos ≤ c.upper ∧ c.upper ≤ fin ∧
          (c.frag = none → frag = none ∧ isExt c.proto = false) := by
  intro n
  induction n using Nat.strongRecOn with
  | ind n ih =>
    intro next nextAt pos frag hn hat c h
    by_cases hh : mode = .check ∧ next = HBH ∧ nextAt ≠ 6
    · rw [walk_hbh hh] at h; simp at h
    · by_cases hx : isExt next = true
      · by_cases hfit : pos + extLen b next pos ≤ fin
        · rw [walk_ext hh hx hfit] at h
          have hlen := extLen_ge b next pos
          cases hs : step b mode next nextAt pos (extLen b next pos) frag with
          | error r => rw [hs] at h; simp at h
          | ok f' =>
            rw [hs] at h
            simp only [] at h
            have hfr := step_frag b mode next nextAt pos _ frag f' hs
            by_cases hl : next = FRAG ∧ 8 ≤ be16 b (pos + 2)
            · rw [if_pos hl] at h
              unfold finish at h
              split at h
              · simp at h
              · obtain rfl := Except.ok.inj h
                refine ⟨rfl, rfl, by dsimp only; omega, by dsimp only; omega, fun h0 => ?_⟩
                exact absurd hl.1 (hfr h0).2
            · rw [if_neg hl] at h
              obtain ⟨h1, h2, h3, h4, h5⟩ := ih _ (by omega) _ _ _ _ rfl (by omega) c h
              refine ⟨h1, h2, by omega, h4, fun h0 => ?_⟩
              obtain ⟨h6, h7⟩ := h5 h0
              exact ⟨(hfr h6).1, h7⟩
        · rw [walk_past hh hx hfit] at h
          split at h
          · simp at h
          · obtain rfl := Except.ok.inj h
            refine ⟨rfl, rfl, by dsimp only; omega, by dsimp only; omega, fun h0 => ⟨h0, rfl⟩⟩
      · rw [walk_upper hh hx] at h
        unfold finish at h
        split at h
        · simp at h
        · obtain rfl := Except.ok.inj h
          exact ⟨rfl, rfl, Nat.le_refl _, hat, fun h0 => ⟨h0, by simpa using hx⟩⟩

theorem chain6_pos (b : Bytes) (mode : Mode) (c : Chain) (h : chain6 b mode = .ok c) :
    c.stop = min (40 + be16 b 4) b.length ∧ c.length = 40 + be16 b 4 ∧ 40 ≤ c.upper ∧
      c.upper ≤ c.stop ∧ c.stop ≤ b.length ∧ (c.frag = none → isExt c.proto = false) := by
  unfold chain6 at h
  split at h
  · simp at h
  · rename_i h1
    split at h
    · simp at h
    · obtain ⟨h3, h4, h5, h6, h7⟩ := walkFrom_pos b mode _ _ _ _ _ _ _ rfl (by omega) c h
      exact ⟨h3, h4, h5, by omega, by omega, fun h0 => (h7 h0).2⟩

theorem stop_le (b : Bytes) (c : Chain) (h : chain6 b (.read false) = .ok c) :
    c.stop ≤ b.length := (chain6_pos b _ c h).2.2.2.2.1

/-! ## Pointers -/

theorem opts_tlv (b : Bytes) (base len : Nat) :
    ∀ n i, len - i = n → ∀ t pos, Opt.tlv t pos ∈ opts b base len i → byte b pos = t := by
  intro n
  induction n using Nat.strongRecOn with
  | ind n ih =>
    intro i hn t pos hm
    rw [opts] at hm
    by_cases hi : i < len
    · rw [dif_pos hi] at hm
      by_cases h0 : byte b (base + i) = 0
      · rw [if_pos h0] at hm
        simp only [List.mem_cons, reduceCtorEq, false_or] at hm
        exact ih _ (by omega) (i + 1) rfl t pos hm
      · rw [if_neg h0] at hm
        by_cases hl : len < i + 2 + byte b (base + i + 1)
        · rw [if_pos hl] at hm; simp at hm
        · rw [if_neg hl] at hm
          simp only [List.mem_cons, Opt.tlv.injEq] at hm
          rcases hm with ⟨h1, h2⟩ | hm
          · subst h1; subst h2; rfl
          · exact ih _ (by omega) _ rfl t pos hm
    · rw [dif_neg hi] at hm; simp at hm

theorem action_problem2 (o : Opt) (b : Bytes) (base len p : Nat) (hm : o ∈ opts b base len 2)
    (h : action o = some (.problem 2 p)) : 2 ≤ byte b p / 64 := by
  cases o with
  | pad1 => simp [action] at h
  | bad => simp [action] at h
  | tlv t pos =>
    have ht := opts_tlv b base len _ 2 rfl t pos hm
    simp only [action] at h
    by_cases h1 : t = 1
    · simp [h1] at h
    · by_cases h2 : t / 64 = 0
      · simp [h1, h2] at h
      · by_cases h3 : t / 64 = 1
        · simp [h1, h2, h3] at h
        · simp only [h1, h2, h3, if_false, Option.some.injEq, Reject.problem.injEq] at h
          obtain ⟨-, rfl⟩ := h
          rw [ht]; omega

theorem scan_problem2 (b : Bytes) :
    ∀ (es : List Ext) seen p, scan b seen es = some (.problem 2 p) → 2 ≤ byte b p / 64 := by
  intro es
  induction es with
  | nil => intro seen p h; simp [scan] at h
  | cons e es ih =>
    intro seen p h
    simp only [scan] at h
    split at h
    · rename_i r hr
      cases h
      unfold faultOf at hr
      by_cases f1 : e.kind = HBH ∧ e.nhAt ≠ 6
      · rw [if_pos f1] at hr; simp at hr
      · rw [if_neg f1] at hr
        by_cases f2 : e.kind = HBH ∨ e.kind = DEST
        · rw [if_pos f2] at hr
          unfold optionsVerdict at hr
          obtain ⟨o, hmem, ho⟩ := List.exists_of_findSome?_eq_some hr
          exact action_problem2 o b _ _ p hmem ho
        · rw [if_neg f2] at hr
          by_cases f3 : e.kind = ROUTING ∧ byte b (e.start + 3) ≠ 0
          · rw [if_pos f3] at hr; simp at hr
          · rw [if_neg f3] at hr
            by_cases f4 : e.kind = FRAG ∧ seen = true
            · rw [if_pos f4] at hr; simp at hr
            · rw [if_neg f4] at hr; simp at hr
    · exact ih _ _ h

/-- Only a header that read as a whole IPv6 header gets a Parameter
Problem. -/
theorem chain6_problem_header (b : Bytes) (m : Mode) (code p : Nat)
    (h : chain6 b m = .error (.problem code p)) : 40 ≤ b.length ∧ byte b 0 / 16 = 6 := by
  unfold chain6 at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · omega

/-- **Option pointers.** A Parameter Problem code 2 points at an option
whose type's two high bits are 10 or 11 (RFC 8200 section 4.2). -/
theorem chain6_problem2 (b : Bytes) (p : Nat) (h : chain6 b .check = .error (.problem 2 p)) :
    2 ≤ byte b p / 64 := by
  rw [chain6_check_eq_rfc] at h
  unfold rfcCheck at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · unfold resolve at h
      split at h
      · rename_i r hr
        cases h
        exact scan_problem2 b _ _ _ hr
      · generalize (decode b (40 + be16 b 4) (byte b 6) 6 40).2 = s at h
        cases s with
        | upper =>
          simp only [tail] at h
          split at h <;> simp at h
        | past =>
          simp only [tail] at h
          split at h
          · simp at h
          · split at h <;> simp at h

/-! ## Stripping -/

/-- `strip_extension_headers`. -/
def strip (b : Bytes) : Except Reject (Option Bytes) :=
  match chain6 b .check with
  | .error r => .error r
  | .ok c =>
    if c.frag.isSome then .error .discard
    else if c.upper = 40 then .ok none
    else
      .ok (some ((((b.take 40).set 4 ((c.stop - c.upper) / 256)).set 5 ((c.stop - c.upper) % 256)).set
        6 c.proto ++ (b.drop c.upper).take (c.stop - c.upper)))

theorem chain6_version (b : Bytes) (m : Mode) (c : Chain) (h : chain6 b m = .ok c) :
    byte b 0 / 16 = 6 := by
  unfold chain6 at h
  split at h
  · simp at h
  · omega

/-- The fixed header of a stripped packet, read at offset `i < 40`. -/
theorem strip_byte (b : Bytes) (n p : Nat) (rest : Bytes) (hb40 : 40 ≤ b.length) (i : Nat)
    (hi : i < 40) :
    byte ((((b.take 40).set 4 (n / 256)).set 5 (n % 256)).set 6 p ++ rest) i =
      if i = 6 then p else if i = 5 then n % 256 else if i = 4 then n / 256 else byte b i := by
  have hm : min 40 b.length = 40 := by omega
  have hH : ((((b.take 40).set 4 (n / 256)).set 5 (n % 256)).set 6 p).length = 40 := by
    simp [hm]
  simp only [byte, List.getD_eq_getElem?_getD]
  rw [List.getElem?_append_left (by rw [hH]; exact hi)]
  simp only [List.getElem?_set, List.getElem?_take, List.length_set, List.length_take, hm]
  by_cases e6 : i = 6
  · subst e6; simp
  · by_cases e5 : i = 5
    · subst e5; simp
    · by_cases e4 : i = 4
      · subst e4; simp
      · have : ¬(6 = i) := fun h => e6 h.symm
        have : ¬(5 = i) := fun h => e5 h.symm
        have : ¬(4 = i) := fun h => e4 h.symm
        simp [*]

/-- **Stripping.** When `strip_extension_headers` takes headers out, the
result is the original fixed header with the upper-layer protocol as its
Next Header (no extension header), the upper-layer bytes' length as its
payload length, its other bytes unchanged, then exactly the upper-layer
bytes; and a destination takes it in with no extension headers left
(RFC 8200 sections 3 and 4). -/
theorem strip_spec (b out : Bytes) (h : strip b = .ok (some out)) :
    ∃ c, chain6 b .check = .ok c ∧ c.frag = none ∧ 40 < c.upper ∧
      isExt c.proto = false ∧
      out.length = 40 + (c.stop - c.upper) ∧
      out.drop 40 = (b.drop c.upper).take (c.stop - c.upper) ∧
      (∀ i, i < 40 → i ≠ 4 → i ≠ 5 → i ≠ 6 → byte out i = byte b i) ∧
      byte out 6 = c.proto ∧ be16 out 4 = c.stop - c.upper ∧
      chain6 out .check =
        .ok ⟨c.proto, 40, 6, none, 40 + (c.stop - c.upper), 40 + (c.stop - c.upper)⟩ := by
  unfold strip at h
  split at h
  · simp at h
  · rename_i c hc
    split at h
    · simp at h
    · rename_i hf
      split at h
      · simp at h
      · rename_i hu
        simp only [Except.ok.injEq, Option.some.injEq] at h
        subst h
        refine ⟨c, hc, ?_⟩
        have hfn : c.frag = none := by simpa using hf
        obtain ⟨h1, h2, h3, h4, h5, h6⟩ := chain6_pos b .check c hc
        have hx := h6 hfn
        have hv := chain6_version b .check c hc
        have hb40 : 40 ≤ b.length := by omega
        have hn5 : c.stop - c.upper ≤ b.length - c.upper := by omega
        generalize c.stop - c.upper = n at *
        have hm : min 40 b.length = 40 := by omega
        have hH : ((((b.take 40).set 4 (n / 256)).set 5 (n % 256)).set 6 c.proto).length = 40 := by
          simp [hm]
        have hT : ((b.drop c.upper).take n).length = n := by simp; omega
        have hbyte := strip_byte b n c.proto ((b.drop c.upper).take n) hb40
        have hb6 := hbyte 6 (by omega)
        have hb4 := hbyte 4 (by omega)
        have hb5 := hbyte 5 (by omega)
        have hb0 := hbyte 0 (by omega)
        simp only [if_true, show (5 : Nat) ≠ 6 by decide, show (4 : Nat) ≠ 6 by decide,
          show (4 : Nat) ≠ 5 by decide, show (0 : Nat) ≠ 6 by decide,
          show (0 : Nat) ≠ 5 by decide, show (0 : Nat) ≠ 4 by decide, if_false] at hb6 hb4 hb5 hb0
        have hbe : be16 ((((b.take 40).set 4 (n / 256)).set 5 (n % 256)).set 6 c.proto ++
            (b.drop c.upper).take n) 4 = n := by
          unfold be16; rw [hb4, hb5]; omega
        refine ⟨hfn, by omega, hx, by rw [List.length_append, hH, hT], List.drop_left' hH, ?_,
          hb6, hbe, ?_⟩
        · intro i hi e4 e5 e6
          rw [hbyte i hi, if_neg e6, if_neg e5, if_neg e4]
        · unfold chain6
          rw [if_neg (by rw [List.length_append, hH, hb0]; omega)]
          rw [if_neg (by rw [hbe, List.length_append, hH, hT]; omega)]
          rw [hbe, List.length_append, hH, hT, Nat.min_self, hb6]
          rw [walk_upper (by simp) (by simp [hx])]
          simp [finish, isFirst]

/-! ## Vectors -/

/-- A seeded pseudo-random source (a 64-bit LCG, high bits). -/
abbrev Gen := StateM Nat

def rand (n : Nat) : Gen Nat := do
  let s ← get
  let s' := (s * 6364136223846793005 + 1442695040888963407) % 18446744073709551616
  set s'
  return (s' / 4294967296) % (max n 1)

def pick {α} [Inhabited α] (xs : List α) : Gen α := do
  return xs.getD (← rand xs.length) default

def randBytes (n : Nat) : Gen Bytes := do
  let mut out := #[]
  for _ in [0:n] do
    out := out.push (← rand 256)
  return out.toList

/-- Options filling `room` bytes, mostly well formed. -/
def genOptions (room : Nat) : Gen Bytes := do
  let mut out : Array Nat := #[]
  let mut left := room
  for _ in [0:room] do
    if left = 0 then break
    let k ← rand 10
    if k = 0 then
      out := out.push 0
      left := left - 1
    else if k ≤ 2 && left ≥ 2 then
      let n ← rand (left - 1)
      out := out.push 1 |>.push n
      for _ in [0:n] do out := out.push 0
      left := left - 2 - n
    else if k ≤ 8 && left ≥ 2 then
      let high ← rand 4
      let low ← rand 64
      let t := high * 64 + low
      let t := if t ≤ 1 then 2 else t
      let n ← rand (left - 1)
      out := out.push t |>.push n
      out := out ++ (← randBytes n).toArray
      left := left - 2 - n
    else
      -- A length that runs past the header.
      let t ← rand 254
      let extra ← rand 4
      out := out.push (t + 2) |>.push (left + extra)
      left := left - (min left 2)
  return (out.toList ++ List.replicate left 0).take room

/-- One extension header of kind `kind` naming `next`. -/
def genExt (kind next : Nat) : Gen Bytes := do
  if kind = FRAG then
    let first ← rand 3
    let off ← if first = 0 then pure 0 else rand 8192
    let more ← rand 2
    let res ← rand 4
    let v := off * 8 + res * 2 + more
    return [next, ← rand 256, v / 256, v % 256] ++ (← randBytes 4)
  else if kind = AUTH then
    let k ← pick [1, 2, 4]
    return [next, k] ++ (← randBytes ((k + 2) * 4 - 2))
  else if kind = ROUTING then
    let k ← rand 3
    let sl ← if (← rand 2) = 0 then pure 0 else rand 256
    return [next, k, ← rand 256, sl] ++ (← randBytes ((k + 1) * 8 - 4))
  else
    let k ← rand 3
    return [next, k] ++ (← genOptions ((k + 1) * 8 - 2))

/-- A random IPv6 packet with an extension-header chain. -/
def genPacket : Gen Bytes := do
  let n ← rand 5
  let mut kinds : Array Nat := #[]
  for _ in [0:n] do
    kinds := kinds.push (← pick [HBH, HBH, DEST, DEST, ROUTING, FRAG, FRAG, AUTH])
  let upper ← pick [TCP, UDP, ICMPV6, NONE, 135, 1, 50, ← rand 256]
  let names := kinds.toList.drop 1 ++ [upper]
  let mut body : Bytes := []
  for (k, nx) in kinds.toList.zip names do
    body := body ++ (← genExt k nx)
  body := body ++ (← randBytes (← rand 30))
  let first := kinds.toList.headD upper
  let more ← rand 8
  let less ← rand 24
  let len := match ← rand 10 with
    | 0 => body.length + 1 + more
    | 1 => body.length - min body.length less
    | 2 => 0
    | _ => body.length
  let version ← pick [6, 6, 6, 6, 6, 6, 6, 6, 6, 5]
  let tc ← rand 16
  let src ← randBytes 16
  let dst ← if (← rand 4) = 0 then pure (255 :: (← randBytes 15)) else randBytes 16
  let fixed := [version * 16 + tc, ← rand 256, ← rand 256, ← rand 256, len / 256 % 256, len % 256,
    first, ← rand 256] ++ src ++ dst
  let packet := fixed ++ body
  if (← rand 12) = 0 then
    let keep ← rand packet.length
    return packet.take keep
  else
    return packet

open Lean in
def rejectJson : Reject → Json
  | .discard => Json.mkObj [("reject", Json.str "discard")]
  | .problem c p => Json.mkObj [("reject", Json.str "problem"), ("code", toJson c),
      ("pointer", toJson p)]

open Lean in
def chainJson (b : Bytes) : Except Reject Chain → Json
  | .error r => rejectJson r
  | .ok c => Json.mkObj [
      ("proto", toJson c.proto), ("upper", toJson c.upper), ("end", toJson c.stop),
      ("length", toJson c.length),
      ("frag", match c.frag with
        | none => Json.null
        | some (pos, _) => Json.mkObj [("id", toJson (be32 b (pos + 4))),
            ("offset", toJson (be16 b (pos + 2) / 8 * 8)),
            ("more", toJson (be16 b (pos + 2) % 2 == 1))])]

open Lean in
def vectors (seed : Nat) : List (String × Json) :=
  let cases : List Json := (Id.run do
    let mut out := #[]
    let mut s := seed + 6
    for _ in [0:4000] do
      let (b, s') := genPacket.run s
      s := s'
      let readJson : Mode → Json := fun m => match chain6 b m with
        | .error _ => Json.null
        | r => chainJson b r
      let stripJson := match strip b with
        | .error r => rejectJson r
        | .ok none => Json.mkObj [("none", toJson true)]
        | .ok (some o) => Json.mkObj [("packet", toJson o)]
      out := out.push (Json.mkObj [("packet", toJson b), ("check", chainJson b (chain6 b .check)),
        ("parse", readJson (.read false)), ("truncated", readJson (.read true)),
        ("strip", stripJson)])
    return out.toList)
  [("ext6", Json.arr cases.toArray)]

end Ip.Ext6
