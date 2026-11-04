/-
  Theorems about the option codec: totality (in `Option.lean`), the length
  rules each subtype obeys, and decoding as the inverse of encoding. Octet fields are octet
  lists of fixed length (`Wf`); bit fields are in range.
-/
import Mptcp.Option

namespace Mptcp

/-! ## List helpers: taking and dropping a known-length prefix. -/

theorem take_append_len {α} (a b : List α) : (a ++ b).take a.length = a := by
  induction a with
  | nil => simp
  | cons x xs ih => simp

theorem drop_append_len {α} (a b : List α) : (a ++ b).drop a.length = b := by
  induction a with
  | nil => simp
  | cons x xs ih => simp

theorem take_of_len {α} (a b : List α) (n : Nat) (h : a.length = n) : (a ++ b).take n = a := by
  subst h; exact take_append_len a b

theorem drop_of_len {α} (a b : List α) (n : Nat) (h : a.length = n) : (a ++ b).drop n = b := by
  subst h; exact drop_append_len a b

/-! ## Well-formedness

    A value is well formed when its octet fields are octet lists of the
    length the wire form fixes, and its bit fields are in range. Rust encodes
    those lengths in its field types; Lean requires them explicitly. -/

def Keys.Wf : Keys → Prop
  | .absent => True
  | .sender k => IsOctets k 8
  | .both s r => IsOctets s 8 ∧ IsOctets r 8
  | .data s r dll c =>
    IsOctets s 8 ∧ IsOctets r 8 ∧ IsOctets dll 2 ∧
      (c = none ∨ ∃ cs, c = some cs ∧ IsOctets cs 2)

def Capable.Wf (c : Capable) : Prop :=
  c.version ≤ 15 ∧ 1 ≤ c.algorithms ∧ c.algorithms ≤ 31 ∧ c.keys.Wf ∧
    (c.version = 0 → c.keys.hasKey = true)

def Join.Wf : Join → Prop
  | .syn _ aid token random => aid < 256 ∧ IsOctets token 4 ∧ IsOctets random 4
  | .synAck _ aid hmac random => aid < 256 ∧ IsOctets hmac 8 ∧ IsOctets random 4
  | .ack hmac => IsOctets hmac 20

def SeqW : Sequence → Prop
  | .short v => IsOctets v 4
  | .long v => IsOctets v 8

def OptSeqW : Option Sequence → Prop
  | none => True
  | some s => SeqW s

def Mapping.Wf (m : Mapping) : Prop :=
  SeqW m.dsn ∧ IsOctets m.subflowSeq 4 ∧ IsOctets m.dll 2 ∧
    (m.checksum = none ∨ ∃ cs, m.checksum = some cs ∧ IsOctets cs 2)

def Dss.Wf (d : Dss) : Prop :=
  OptSeqW d.dataAck ∧ (d.mapping = none ∨ ∃ m, d.mapping = some m ∧ m.Wf)

def Addr.Wf : Addr → Prop
  | .v4 o => IsOctets o 4
  | .v6 o => IsOctets o 16

def AddAddr.Wf (a : AddAddr) : Prop :=
  a.addressId < 256 ∧ a.address.Wf ∧
    (a.port = none ∨ ∃ p, a.port = some p ∧ IsOctets p 2) ∧
    (a.hmac = none ∨ ∃ h, a.hmac = some h ∧ IsOctets h 8)

def Opt.Wf : Opt → Prop
  | .capable c => c.Wf
  | .join j => j.Wf
  | .dss d => d.Wf
  | .addAddr a => a.Wf
  | .removeAddr ids => 1 ≤ ids.length ∧ ids.length ≤ 37 ∧ ∀ b ∈ ids, b < 256
  | .prio _ => True
  | .fail v => IsOctets v 8
  | .fastClose v => IsOctets v 8
  | .tcpRst _ reason => reason < 256

end Mptcp

namespace Mptcp

set_option maxRecDepth 4096
set_option maxHeartbeats 4000000

@[simp] theorem take_append_fixed {α} (a b : List α) (h : a.length = n) :
    (a ++ b).take n = a := take_of_len a b n h
@[simp] theorem drop_append_fixed {α} (a b : List α) (h : a.length = n) :
    (a ++ b).drop n = b := drop_of_len a b n h

/-- Reserved and experimental subtypes are reported, not interpreted. -/
theorem unknown_subtype (sub low : Nat) (rest : Octets) (length : Nat)
    (h : 9 ≤ sub) : dispatch sub low rest length = .error (.subtype sub) := by
  unfold dispatch
  split <;> first | omega | rfl

theorem overlong (data : Octets) (h : 38 < data.length) :
    parse data = .error (.tooLong (data.length + 2)) := by
  simp [parse, MAX_LEN, show 40 < data.length + 2 by omega]

theorem empty_malformed : parse [] = .error .noSubtype := by rfl

/-- No reserved bits are needed to encode the flags of MP_CAPABLE. -/
theorem capable_flags (a : Nat) (ha : a < 32) (b c d : Bool) :
    let f := a + b2n b * 32 + b2n c * 64 + b2n d * 128
    f % 32 = a ∧ (f / 32 % 2 == 1) = b ∧
      (f / 64 % 2 == 1) = c ∧ (f / 128 % 2 == 1) = d := by
  cases b <;> cases c <;> cases d <;> simp [b2n] <;> omega

/-- The inverse for MP_CAPABLE, including the data on the third ACK. -/
theorem capable_roundtrip (c : Capable) (h : c.Wf) :
    (emit (.capable c)).bind parse = .ok (.capable c) := by
  rcases c with ⟨v, check, ext, no, alg, keys⟩
  rcases h with ⟨hv, ha, hb, hk, hz⟩
  dsimp at hv ha hb hz
  have nv : ¬ 15 < v := by omega
  have na : alg ≠ 0 := by omega
  have nb : ¬ 31 < alg := by omega
  have vd : v / 16 = 0 := by omega
  have vm : v % 16 = v := by omega
  have flags := capable_flags alg (by omega) no ext check
  dsimp at flags
  rcases flags with ⟨fa, fn, fe, fc⟩
  cases keys with
  | absent =>
    simp only [Keys.hasKey, Bool.false_eq_true, imp_false] at hz
    simp (disch := omega) [List.take_of_length_le, List.drop_of_length_le, *, emit, parse, dispatch, parseCapable, buildCapable, keysBytes,
      Except.bind, MAX_LEN, ALG_ALL, Keys.Wf, Keys.hasKey]
  | sender k =>
    rcases hk with ⟨hl, _⟩
    simp (disch := omega) [List.take_of_length_le, List.drop_of_length_le, *, emit, parse, dispatch, parseCapable, buildCapable, keysBytes,
      Except.bind, MAX_LEN, ALG_ALL, Keys.hasKey]
  | both s r =>
    rcases hk with ⟨⟨hs, _⟩, ⟨hr, _⟩⟩
    simp (disch := omega) [List.take_of_length_le, List.drop_of_length_le, *, emit, parse, dispatch, parseCapable, buildCapable, keysBytes,
      Except.bind, MAX_LEN, ALG_ALL, Keys.hasKey]
  | data s r dll cs =>
    simp only [Keys.hasKey, Bool.false_eq_true, imp_false] at hz
    rcases hk with ⟨⟨hs, _⟩, ⟨hr, _⟩, ⟨hd, _⟩, hc⟩
    rcases hc with hc | ⟨cs', hc, ⟨hl, _⟩⟩ <;> subst cs
    all_goals simp (disch := omega) [List.take_of_length_le, List.drop_of_length_le, *, emit, parse, dispatch, parseCapable, buildCapable, keysBytes,
      Except.bind, MAX_LEN, ALG_ALL, Keys.hasKey, List.append_assoc, List.drop_append, List.take_append]

/-- Every MP_JOIN form round-trips with its complete authentication bytes. -/
theorem join_roundtrip (j : Join) (h : j.Wf) :
    (emit (.join j)).bind parse = .ok (.join j) := by
  cases j with
  | syn b aid t r =>
    rcases h with ⟨_, ⟨ht, _⟩, ⟨hr, _⟩⟩
    cases b <;> simp (disch := omega) [List.take_of_length_le, List.drop_of_length_le, *, emit, parse, dispatch, parseJoin, MAX_LEN, Except.bind]
  | synAck b aid t r =>
    rcases h with ⟨_, ⟨ht, _⟩, ⟨hr, _⟩⟩
    cases b <;> simp (disch := omega) [List.take_of_length_le, List.drop_of_length_le, *, emit, parse, dispatch, parseJoin, MAX_LEN, Except.bind]
  | ack t =>
    rcases h with ⟨ht, _⟩
    simp (disch := omega) [List.take_of_length_le, List.drop_of_length_le, *, emit, parse, dispatch, parseJoin, MAX_LEN, Except.bind]

/-- The DSS inverse checks all flag combinations, both sequence widths and
    optional checksums, without restricting the byte values. -/
theorem dss_roundtrip (d : Dss) (h : d.Wf) :
    (emit (.dss d)).bind parse = .ok (.dss d) := by
  rcases d with ⟨ack, mapping, fin⟩
  rcases h with ⟨ha, hm⟩
  dsimp at ha hm
  cases ack <;> try (rename_i a; cases a <;> rcases ha with ⟨ha, _⟩)
  all_goals cases mapping
  all_goals try (
    rename_i m
    have hw : m.Wf := by simpa using hm
    rcases m with ⟨dsn, ssn, dll, cs⟩
    rcases hw with ⟨hd, ⟨hs, _⟩, ⟨hl, _⟩, hc⟩
    dsimp at hd hs hl hc
    cases dsn <;> rcases hd with ⟨hd, _⟩
    all_goals rcases hc with hc | ⟨v, hc, ⟨hv, _⟩⟩ <;> subst cs)
  all_goals cases fin <;>
    simp (disch := omega) [List.take_of_length_le, List.drop_of_length_le, *, emit, parse, dispatch, parseDss, seqBytes, dssFlags, mapBytes,
      MAX_LEN, Except.bind, List.append_assoc, List.drop_append, List.take_append]

theorem add_addr_roundtrip (a : AddAddr) (h : a.Wf) :
    (emit (.addAddr a)).bind parse = .ok (.addAddr a) := by
  rcases a with ⟨aid, addr, port, mac⟩
  rcases h with ⟨_, ha, hp, hm⟩
  dsimp at hp hm
  cases addr <;> rcases ha with ⟨ha, _⟩
  all_goals rcases hp with hp | ⟨p, hp, ⟨hlp, _⟩⟩ <;> subst port
  all_goals rcases hm with hm | ⟨m, hm, ⟨hlm, _⟩⟩ <;> subst mac
  all_goals simp (disch := omega) [List.take_of_length_le, List.drop_of_length_le, *, emit, parse, dispatch, parseAddAddr, MAX_LEN, Except.bind,
    List.append_assoc, List.drop_append, List.take_append]

/-- Decoding is the inverse of encoding for every well-formed option. -/
theorem decode_encode (o : Opt) (h : o.Wf) :
    (emit o).bind parse = .ok o := by
  cases o with
  | capable c => exact capable_roundtrip c h
  | join j => exact join_roundtrip j h
  | dss d => exact dss_roundtrip d h
  | addAddr a => exact add_addr_roundtrip a h
  | removeAddr ids =>
    rcases h with ⟨hmin, hmax, _⟩
    have hn : ids ≠ [] := by intro eq; simp [eq] at hmin
    have hb : ¬ 40 < ids.length + 3 := by omega
    have hl : ¬ 37 < ids.length := by omega
    cases ids with
    | nil => contradiction
    | cons x xs =>
      have hx : ¬ 37 < xs.length + 1 := by simpa using hl
      have hy : ¬ 40 < xs.length + 1 + 1 + 2 := by simp only [List.length_cons] at hb; omega
      simp [*, emit, parse, dispatch, MAX_LEN, Except.bind]
  | prio b => cases b <;> rfl
  | fail v =>
    rcases h with ⟨hl, _⟩
    simp (disch := omega) [List.take_of_length_le, List.drop_of_length_le, *, emit, parse, dispatch, parseFailLike, MAX_LEN, Except.bind]
  | fastClose v =>
    rcases h with ⟨hl, _⟩
    simp (disch := omega) [List.take_of_length_le, List.drop_of_length_le, *, emit, parse, dispatch, parseFailLike, MAX_LEN, Except.bind]
  | tcpRst b r => cases b <;> rfl

/-- Exact lengths in the RFC figures; flags determine the DSS widths and
    whether ADD_ADDR is an echo. This is separate from the byte parser. -/
def lengthRule (sub low flags length : Nat) : Bool :=
  match sub with
  | 0 => (flags % 32 != 0) &&
      (if low = 0 then length == 12 || length == 20
       else [4,12,20,22,24].contains length)
  | 1 => [12,16,24].contains length
  | 2 =>
    let ack := if flags % 2 = 0 then 0 else if flags / 2 % 2 = 0 then 4 else 8
    let mapping := if flags / 4 % 2 = 0 then 0 else if flags / 8 % 2 = 0 then 10 else 14
    length == 4 + ack + mapping || (mapping != 0 && length == 6 + ack + mapping)
  | 3 =>
    let mac := if low % 2 = 1 then 0 else 8
    [8 + mac, 10 + mac, 20 + mac, 22 + mac].contains length
  | 4 => length ≥ 4
  | 5 => length == 3
  | 6 | 7 => length == 12
  | 8 => length == 4
  | _ => false

def accepted : Except Error Opt → Bool
  | .ok _ => true
  | .error _ => false

@[simp] theorem accepted_ok (o : Opt) : accepted (.ok o) = true := rfl
@[simp] theorem accepted_error (e : Error) : accepted (.error e) = false := rfl

@[simp] theorem accepted_ite (p : Prop) [Decidable p] (a b : Except Error Opt) :
    accepted (if p then a else b) = if p then accepted a else accepted b := by
  split <;> rfl

/-- Every multi-byte option obeys its exact length rule, including malformed
    DSS flag/length combinations. Payload bytes cannot affect that rule. -/
theorem parse_length_rule (first flags : Nat) (tail : Octets) :
    accepted (parse (first :: flags :: tail)) =
      (decide (tail.length + 4 ≤ 40) &&
       lengthRule (first / 16) (first % 16) flags (tail.length + 4)) := by
  simp only [parse, List.length_cons, MAX_LEN]
  by_cases h : 40 < tail.length + 1 + 1 + 2
  · simp [h, accepted, show ¬tail.length + 4 ≤ 40 by omega]
  · simp only [h, ↓reduceIte]
    have bound : tail.length + 4 ≤ 40 := by omega
    simp only [bound, decide_true, Bool.true_and]
    unfold dispatch
    split <;> simp [lengthRule, *, parseCapable, buildCapable, parseJoin,
      parseDss, parseAddAddr, parseFailLike, accepted_ite, Keys.hasKey]
    case h_1 =>
      by_cases hz : tail = [] <;> by_cases hv : first % 16 = 0 <;>
        by_cases ha : flags % 32 = 0 <;> simp (disch := omega) [*, Bool.beq_eq_decide_eq]
      all_goals (apply Bool.eq_iff_iff.mpr; simp; omega)
    case h_3 =>
      by_cases a : flags % 2 = 0 <;> by_cases b : flags / 2 % 2 = 0 <;>
        by_cases m : flags / 4 % 2 = 0 <;> by_cases d : flags / 8 % 2 = 0
      all_goals simp (disch := omega) [*, show flags / 2 % 2 = 1 ↔ ¬ flags / 2 % 2 = 0 by omega,
        show flags / 8 % 2 = 1 ↔ ¬ flags / 8 % 2 = 0 by omega,
        Bool.beq_eq_decide_eq]
      all_goals have lengths :
        tail.length = 0 ∨ tail.length = 1 ∨ tail.length = 2 ∨ tail.length = 3 ∨ tail.length = 4 ∨ tail.length = 5 ∨
        tail.length = 6 ∨ tail.length = 7 ∨ tail.length = 8 ∨ tail.length = 9 ∨ tail.length = 10 ∨ tail.length = 11 ∨
        tail.length = 12 ∨ tail.length = 13 ∨ tail.length = 14 ∨ tail.length = 15 ∨ tail.length = 16 ∨ tail.length = 17 ∨
        tail.length = 18 ∨ tail.length = 19 ∨ tail.length = 20 ∨ tail.length = 21 ∨ tail.length = 22 ∨ tail.length = 23 ∨
        tail.length = 24 ∨ tail.length = 25 ∨ tail.length = 26 ∨ tail.length = 27 ∨ tail.length = 28 ∨ tail.length = 29 ∨
        tail.length = 30 ∨ tail.length = 31 ∨ tail.length = 32 ∨ tail.length = 33 ∨ tail.length = 34 ∨ tail.length = 35 ∨
        tail.length = 36 := by omega
      all_goals rcases lengths with
        hl | hl | hl | hl | hl | hl | hl | hl |
        hl | hl | hl | hl | hl | hl | hl | hl |
        hl | hl | hl | hl | hl | hl | hl | hl |
        hl | hl | hl | hl | hl | hl | hl | hl |
        hl | hl | hl | hl | hl
      all_goals by_cases empty : tail = []
      all_goals simp (disch := omega) [*, accepted]
      all_goals omega
    case h_4 =>
      by_cases echo : first % 2 = 1 <;> by_cases enough : 8 ≤ tail.length
      all_goals simp (disch := omega) [echo, show tail.length - 8 + 8 = tail.length ↔ 8 ≤ tail.length by omega,
        show ¬ 8 ≤ tail.length → tail.length - 8 = 0 by omega, enough]
      all_goals have lengths :
        tail.length = 0 ∨ tail.length = 1 ∨ tail.length = 2 ∨ tail.length = 3 ∨ tail.length = 4 ∨ tail.length = 5 ∨
        tail.length = 6 ∨ tail.length = 7 ∨ tail.length = 8 ∨ tail.length = 9 ∨ tail.length = 10 ∨ tail.length = 11 ∨
        tail.length = 12 ∨ tail.length = 13 ∨ tail.length = 14 ∨ tail.length = 15 ∨ tail.length = 16 ∨ tail.length = 17 ∨
        tail.length = 18 ∨ tail.length = 19 ∨ tail.length = 20 ∨ tail.length = 21 ∨ tail.length = 22 ∨ tail.length = 23 ∨
        tail.length = 24 ∨ tail.length = 25 ∨ tail.length = 26 ∨ tail.length = 27 ∨ tail.length = 28 ∨ tail.length = 29 ∨
        tail.length = 30 ∨ tail.length = 31 ∨ tail.length = 32 ∨ tail.length = 33 ∨ tail.length = 34 ∨ tail.length = 35 ∨
        tail.length = 36 := by omega
      all_goals rcases lengths with
        hl | hl | hl | hl | hl | hl | hl | hl |
        hl | hl | hl | hl | hl | hl | hl | hl |
        hl | hl | hl | hl | hl | hl | hl | hl |
        hl | hl | hl | hl | hl | hl | hl | hl |
        hl | hl | hl | hl | hl
      all_goals by_cases empty : tail = []
      all_goals simp (disch := omega) [*, accepted]
      all_goals omega
    case h_7 => simp [Bool.beq_eq_decide_eq]
    case h_8 => simp [Bool.beq_eq_decide_eq]
    case h_9 => cases tail <;> simp


/-- At Length 3 only MP_PRIO has a complete layout. -/
theorem singleton_length_rule (first : Nat) :
    accepted (parse [first]) = (first / 16 == 5) := by
  simp only [parse, List.length_cons, List.length_nil, MAX_LEN]
  simp only [show ¬40 < 0 + 1 + 2 by decide, ↓reduceIte]
  unfold dispatch
  split <;> simp [*, parseCapable, parseJoin, parseDss, parseAddAddr, parseFailLike, accepted]
  all_goals omega

end Mptcp

namespace Ipv4

abbrev Bytes := List Nat

/-- Byte lists retain the exact address and timestamp octets. -/
inductive Opt where
  | eol | nop
  | route (kind pointer : Nat) (slots : Bytes)
  | timestamp (pointer flags : Nat) (slots : Bytes)
  | security (data : Bytes)
  | stream (data : Bytes)
  | alert (data : Bytes)
  | unknown (kind : Nat) (data : Bytes)
  | malformed (kind : Nat) (data : Bytes)
  deriving Repr, DecidableEq

def routeKind (kind : Nat) : Bool := [7,131,137].contains kind

def knownKind (kind : Nat) : Bool := [0,1,7,68,130,131,136,137,148].contains kind

def timestampLength (flags length : Nat) : Bool :=
  if flags % 16 = 0 then length % 4 == 0
  else if flags % 16 = 1 ∨ flags % 16 = 3 then length % 8 == 0
  else true

/-- Validation is separate from framing; malformed known options retain length. -/
def body (kind : Nat) (data : Bytes) : Opt :=
  let bad := Opt.malformed kind ((data.length + 2) :: data)
  if routeKind kind then
    match data with
    | pointer :: slots =>
      if 4 ≤ pointer ∧ slots.length % 4 = 0 then .route kind pointer slots else bad
    | [] => bad
  else if kind = 68 then
    match data with
    | pointer :: flags :: slots =>
      if 5 ≤ pointer ∧ timestampLength flags slots.length then .timestamp pointer flags slots else bad
    | _ => bad
  else if kind = 130 then if data.length = 9 then .security data else bad
  else if kind = 136 then if data.length = 2 then .stream data else bad
  else if kind = 148 then if data.length = 2 then .alert data else bad
  else .unknown kind data

def parseFuel : Nat → Bytes → List Opt
  | 0, _ => []
  | _ + 1, [] => []
  | _ + 1, 0 :: _ => [.eol]
  | fuel + 1, 1 :: rest => .nop :: parseFuel fuel rest
  | fuel + 1, kind :: length :: rest =>
    if length < 2 ∨ rest.length < length - 2 then [.malformed kind (length :: rest)]
    else body kind (rest.take (length - 2)) :: parseFuel fuel (rest.drop (length - 2))
  | _ + 1, [kind] => [.malformed kind []]

def parse (input : Bytes) : List Opt := parseFuel input.length input

def framed (kind : Nat) (data : Bytes) : Bytes := kind :: (data.length + 2) :: data

def emit : Opt → Bytes
  | .eol => [0]
  | .nop => [1]
  | .route kind pointer slots => framed kind (pointer :: slots)
  | .timestamp pointer flags slots => framed 68 (pointer :: flags :: slots)
  | .security data => framed 130 data
  | .stream data => framed 136 data
  | .alert data => framed 148 data
  | .unknown kind data => framed kind data
  | .malformed kind data => kind :: data

def Opt.Wf : Opt → Prop
  | .eol | .nop => True
  | .route kind pointer slots => routeKind kind = true ∧ 4 ≤ pointer ∧ slots.length % 4 = 0 ∧ slots.length ≤ 37
  | .timestamp pointer flags slots => 5 ≤ pointer ∧ timestampLength flags slots.length = true ∧ slots.length ≤ 36
  | .security data => data.length = 9
  | .stream data | .alert data => data.length = 2
  | .unknown kind data => knownKind kind = false ∧ data.length ≤ 38
  | .malformed _ _ => False

/-- Decoding the complete framed option, independent of following padding. -/
def decode (input : Bytes) : Option Opt :=
  match input with
  | [0] => some .eol
  | [1] => some .nop
  | kind :: length :: data =>
    if length = data.length + 2 ∧ length ≤ 40 ∧ 2 ≤ kind then some (body kind data) else none
  | _ => none

theorem route_kind_bounds (kind : Nat) (h : routeKind kind = true) :
    2 ≤ kind ∧ kind ≠ 68 ∧ kind ≠ 130 ∧ kind ≠ 136 ∧ kind ≠ 148 := by
  simp [routeKind] at h
  rcases h with h | h | h <;> omega

theorem unknown_kind (kind : Nat) (h : knownKind kind = false) :
    2 ≤ kind ∧ routeKind kind = false ∧ kind ≠ 68 ∧ kind ≠ 130 ∧ kind ≠ 136 ∧ kind ≠ 148 := by
  simp [knownKind] at h
  simp [routeKind, h]
  omega

/-- All recognized lengths, including opaque unknown timestamp flags. -/
theorem decode_encode (option : Opt) (h : option.Wf) :
    decode (emit option) = some option := by
  cases option with
  | eol => rfl
  | nop => rfl
  | route kind pointer slots =>
    rcases h with ⟨hk, hp, hs, hl⟩
    have hb := route_kind_bounds kind hk
    simp (disch := omega) [emit, framed, decode, body, hk, hp, hs, hb, hl]
  | timestamp pointer flags slots =>
    rcases h with ⟨hp, hs, hl⟩
    simp (disch := omega) [emit, framed, decode, body, routeKind, hp, hs, hl]
  | security data => simp [Opt.Wf] at h; simp [emit, framed, decode, body, routeKind, h]
  | stream data => simp [Opt.Wf] at h; simp [emit, framed, decode, body, routeKind, h]
  | alert data => simp [Opt.Wf] at h; simp [emit, framed, decode, body, routeKind, h]
  | unknown kind data =>
    rcases h with ⟨hk, hl⟩
    rcases unknown_kind kind hk with ⟨hb, hr, ht, hs, hi, ha⟩
    simp (disch := omega) [emit, framed, decode, body, hr, ht, hs, hi, ha, hl, hb]
  | malformed kind data => exact False.elim h

theorem encoded_length (option : Opt) (h : option.Wf) :
    1 ≤ (emit option).length ∧ (emit option).length ≤ 40 := by
  cases option <;> simp_all [Opt.Wf, emit, framed] <;> omega

theorem unknown_preserved (kind : Nat) (data : Bytes) (h : knownKind kind = false) :
    body kind data = .unknown kind data := by
  rcases unknown_kind kind h with ⟨_, hr, ht, hs, hi, ha⟩
  simp [body, hr, ht, hs, hi, ha]

theorem route_length_rule (kind pointer : Nat) (slots : Bytes) (h : routeKind kind = true) :
    body kind (pointer :: slots) = .route kind pointer slots ↔
      4 ≤ pointer ∧ slots.length % 4 = 0 := by
  simp [body, h]

theorem timestamp_length_rule (pointer flags : Nat) (slots : Bytes) :
    body 68 (pointer :: flags :: slots) = .timestamp pointer flags slots ↔
      5 ≤ pointer ∧ timestampLength flags slots.length = true := by
  simp [body, routeKind]

theorem security_length_rule (data : Bytes) :
    body 130 data = .security data ↔ data.length = 9 := by
  simp [body, routeKind]

theorem stream_length_rule (data : Bytes) :
    body 136 data = .stream data ↔ data.length = 2 := by
  simp [body, routeKind]

theorem alert_length_rule (data : Bytes) :
    body 148 data = .alert data ↔ data.length = 2 := by
  simp [body, routeKind]

theorem eol_stops (tail : Bytes) : parse (0 :: tail) = [.eol] := by
  simp [parse, parseFuel]

theorem malformed_frame_preserved (kind length : Nat) (data : Bytes)
    (hk : 2 ≤ kind) (h : length < 2 ∨ data.length < length - 2) :
    parse (kind :: length :: data) = [.malformed kind (length :: data)] := by
  cases kind with
  | zero => omega
  | succ kind => cases kind with
    | zero => omega
    | succ kind => simp [parse, parseFuel, h]

theorem walk_framed (kind : Nat) (data : Bytes) (h : 2 ≤ kind) :
    parse (framed kind data) = [body kind data] := by
  cases kind with
  | zero => omega
  | succ kind => cases kind with
    | zero => omega
    | succ kind =>
      simp (disch := omega) [parse, parseFuel, framed, Nat.add_comm, Nat.add_left_comm, Nat.add_assoc]
      omega

/-- The actual iterator, with its byte-length fuel, inverts the encoder. -/
theorem walk_encode (option : Opt) (h : option.Wf) :
    parse (emit option) = [option] := by
  cases option with
  | eol => rfl
  | nop => rfl
  | route kind pointer slots =>
    rcases h with ⟨hk, hp, hs, _⟩
    have hb := (route_kind_bounds kind hk).1
    simp [emit, walk_framed kind _ hb, body, hk, hp, hs]
  | timestamp pointer flags slots =>
    rcases h with ⟨hp, hs, _⟩
    simp [emit, walk_framed 68 _ (by omega), body, routeKind, hp, hs]
  | security data => simp [Opt.Wf] at h; simp [emit, walk_framed 130 _ (by omega), body, routeKind, h]
  | stream data => simp [Opt.Wf] at h; simp [emit, walk_framed 136 _ (by omega), body, routeKind, h]
  | alert data => simp [Opt.Wf] at h; simp [emit, walk_framed 148 _ (by omega), body, routeKind, h]
  | unknown kind data =>
    rcases h with ⟨hk, _⟩
    have hb := (unknown_kind kind hk).1
    simp [emit, walk_framed kind _ hb, unknown_preserved kind data hk]
  | malformed kind data => exact False.elim h

/-- A terminator may only occur at the end of a typed option list. -/
def OptionsWf : List Opt → Prop
  | [] => True
  | option :: rest => option.Wf ∧ (option = .eol → rest = []) ∧ OptionsWf rest

theorem walk_framed_tail (kind : Nat) (data tail : Bytes) (fuel : Nat)
    (h : 2 ≤ kind) :
    parseFuel (fuel + 1) (framed kind data ++ tail) =
      body kind data :: parseFuel fuel tail := by
  cases kind with
  | zero => omega
  | succ kind => cases kind with
    | zero => omega
    | succ kind =>
      simp (disch := omega) [framed, parseFuel, List.take_append, List.drop_append]
      all_goals omega

/-- Fuel counts options, so the encoded byte count always supplies enough. -/
theorem walk_options_fuel (options : List Opt) :
    ∀ fuel, OptionsWf options → (options.flatMap emit).length ≤ fuel →
      parseFuel fuel (options.flatMap emit) = options := by
  induction options with
  | nil => intro fuel _ _; cases fuel <;> rfl
  | cons option rest ih =>
    intro fuel h bound
    rcases h with ⟨ho, he, hr⟩
    have size := encoded_length option ho
    have room : (emit option).length + (rest.flatMap emit).length ≤ fuel := by
      simpa using bound
    cases fuel with
    | zero => omega
    | succ fuel =>
      have remaining : (rest.flatMap emit).length ≤ fuel := by omega
      have tail := ih fuel hr remaining
      simp only [List.flatMap_cons]
      cases option with
      | eol => have empty := he rfl; subst rest; rfl
      | nop => simpa [emit, parseFuel] using congrArg (Opt.nop :: ·) tail
      | route kind pointer slots =>
        rcases ho with ⟨hk, hp, hs, _⟩
        have hb := (route_kind_bounds kind hk).1
        simp [emit, walk_framed_tail kind _ _ fuel hb, body, hk, hp, hs, tail]
      | timestamp pointer flags slots =>
        rcases ho with ⟨hp, hs, _⟩
        simp [emit, walk_framed_tail 68 _ _ fuel (by omega), body, routeKind, hp, hs, tail]
      | security data =>
        simp [emit, walk_framed_tail 130 _ _ fuel (by omega), body, routeKind,
          show data.length = 9 from ho, tail]
      | stream data =>
        simp [emit, walk_framed_tail 136 _ _ fuel (by omega), body, routeKind,
          show data.length = 2 from ho, tail]
      | alert data =>
        simp [emit, walk_framed_tail 148 _ _ fuel (by omega), body, routeKind,
          show data.length = 2 from ho, tail]
      | unknown kind data =>
        rcases ho with ⟨hk, _⟩
        have hb := (unknown_kind kind hk).1
        simp [emit, walk_framed_tail kind _ _ fuel hb, unknown_preserved kind data hk, tail]
      | malformed kind data => exact False.elim ho

/-- The complete typed list round-trips through the actual option walker. -/
theorem walk_options_encode (options : List Opt) (h : OptionsWf options) :
    parse (options.flatMap emit) = options :=
  walk_options_fuel options _ h (Nat.le_refl _)

/-- Replacing a selected field leaves the other wire bytes untouched. -/
def replace (input : Bytes) (offset : Nat) (value : Bytes) : Bytes :=
  input.take offset ++ value ++ input.drop (offset + value.length)

def unicast (host address : Bytes) : Bool :=
  address != host && address != [255,255,255,255] && address != [0,0,0,0] &&
    !(224 ≤ address[0]! && address[0]! ≤ 239)

/-- Two visits represent receive compilation and reply construction. -/
def echoVisits : Nat → Nat → Bytes → Bytes → Bytes → Option Bytes
  | 0, _, _, _, input => some input
  | visits + 1, initial, host, stamp, input => do
    let pointer := input[2]!
    let length := input.length
    if pointer > length then return input
    if pointer + 3 > length then none else do
      let offset := pointer - 1
      let kind := input[0]!
      let flags := input[3]! % 16
      let value ← if kind = 7 then some host
        else if flags = 0 then some stamp
        else if flags = 1 then
          if pointer + 7 > length then none else some (host ++ stamp)
        else if flags = 3 then
          if pointer + 7 > length then
            if pointer = initial then none else some []
          else if unicast host ((input.drop offset).take 4) then some []
          else some (((input.drop offset).take 4) ++ stamp)
        else some []
      if value = [] then return input
      let next := (replace input offset value).set 2 (pointer + value.length)
      echoVisits visits initial host stamp next

def echoRecord (host stamp : Bytes) (option : Opt) : Option Opt := do
  let input := emit option
  let pointer := input[2]!
  let flags := input[3]! % 16
  let overflow := input[3]! / 16
  let input ← if input[0]! = 68 ∧ pointer > input.length ∧ flags ≠ 3 then
      if overflow = 15 then none else some (input.set 3 (input[3]! + 16))
    else some input
  let output ← echoVisits 2 pointer host stamp input
  (parse output).head?

/-- Source-route addresses are taken at the original byte offsets, even for
    a pointer that is not aligned to an address boundary. -/
def consumedRoutes : Nat → Bytes → Nat → List Bytes
  | 0, _, _ => []
  | fuel + 1, input, offset =>
    if offset > 3 then ((input.drop (offset - 1)).take 4) :: consumedRoutes fuel input (offset - 4)
    else []

def echoSource (remote : Bytes) (option : Opt) : Option (Bytes × Opt) := do
  let input := emit option
  let offset := min input[2]! (input.length + 1) - 4
  if offset ≤ 3 then none else do
    let first := (input.drop (offset - 1)).take 4
    let reversed := consumedRoutes input.length input (offset - 4)
    let lastOffset := offset - 4 * (reversed.length + 1)
    let redundant := (input.drop (lastOffset + 3)).take 4 == remote
    if redundant && reversed.isEmpty then none else do
      let routes := if redundant then reversed.take (reversed.length - 1) else reversed
      let result := body input[0]! (4 :: ((routes ++ [remote]).flatten))
      return (first, result)

/-- Echo ignores unrelated options, rejects malformed and duplicate meaningful
    options, and emits RR, Timestamp, source route in Linux order. -/
def echo (options : List Opt) (host remote stamp : Bytes) : Option (Option Bytes × List Opt) := do
  if options.any (fun o => match o with | .malformed _ _ => true | _ => false) then none else do
    let records := options.filter (fun o => match o with | .route 7 _ _ => true | _ => false)
    let timestamps := options.filter (fun o => match o with | .timestamp _ _ _ => true | _ => false)
    let sources := options.filter (fun o => match o with | .route kind _ _ => kind != 7 | _ => false)
    if records.length > 1 ∨ timestamps.length > 1 ∨ sources.length > 1 then none else do
      let mut output := []
      for option in records ++ timestamps do
        if (emit option).length > 40 then none else do
          let result ← echoRecord host stamp option
          output := output ++ [result]
      let mut destination := none
      for option in sources do
        if (emit option).length > 40 then none else do
          if let some (first, result) := echoSource remote option then
            destination := some first
            output := output ++ [result]
      return (destination, output)

theorem echo_unknown (kind : Nat) (data host remote stamp : Bytes) :
    echo [.unknown kind data] host remote stamp = some (none, []) := by
  simp [echo]

end Ipv4
