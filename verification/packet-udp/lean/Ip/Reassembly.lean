import Lean
import Ip.Checksum

/-! Fragment reassembly (RFC 791 section 3.2, RFC 815, RFC 8200 section 4.5,
RFC 5722, RFC 6946).

A model of `Reassembly` in `src/stdlib/network/ip.rs` that follows
`Reassembly::reassemble`, `push_fragment`, `take`, `kill`, `expire`,
`arrived` and `finish` step for step, the theorems about it, and the
`reassembly` vectors that `tests/ip_vectors/reassembly.rs` replays against
`Reassembly::push`.

Modelling choices:
- Octets are `Nat`s below 256. Time is a `Nat` count of milliseconds; the
  theorems only add and compare times, so the unit does not matter.
- The code's `HashMap<Key, Partial>` is an association list with distinct
  keys, and its `by_expiry` index is read off that list: the code's
  `check` asserts that the two agree. The cap drops the entry with the
  soonest deadline; between equal deadlines the model drops the first in
  the list, where the code drops the least `Key`. The cap theorem does not
  depend on which one goes.
- A piece carries the "more fragments" flag of the fragment it came from.
  The code does not store it: it is a ghost field the step never reads,
  there for the soundness theorem. `got` is the code's `have` (a Lean
  keyword).
- `arrived` reads IPv6 chains as `chain6` does for chains it accepts. A
  chain `chain6` refuses never reaches reassembly (`Reassembly::push`
  refuses it first); those checks are the extension-header model's. -/

namespace Ip.Reassembly

/-! ## Constants (ip.rs 527-540) -/

/-- `MAX_WAITING`: 4 MiB. -/
def MAX_WAITING : Nat := 4194304
/-- `PIECE_COST`: what one waiting fragment costs beyond its data. -/
def PIECE_COST : Nat := 64
/-- `PARTIAL_COST`: what one unfinished packet costs beyond its fragments. -/
def PARTIAL_COST : Nat := 192
/-- `V4_TIMEOUT`: 30 s. -/
def V4_TIMEOUT : Nat := 30000
/-- `V6_TIMEOUT`: 60 s (RFC 8200 section 4.5). -/
def V6_TIMEOUT : Nat := 60000
/-- The largest IPv4 total length, IPv6 payload length and fragment end. -/
def MAX_LEN : Nat := 65535

/-! ## State -/

/-- Which packet a fragment belongs to (`Key`): source, destination,
identification and, for IPv4, protocol (RFC 791 section 3.2, RFC 8200
section 4.5). Addresses are their octets. -/
inductive Key where
  | v4 (src dst : List Nat) (id proto : Nat)
  | v6 (src dst : List Nat) (id : Nat)
  deriving DecidableEq, Repr

/-- One fragment, read from a packet (`Arrived`). `header` is the headers in
front of the data, for the first fragment only. -/
structure Frag where
  key : Key
  offset : Nat
  more : Bool
  data : List Nat
  header : Option (List Nat)
  timeout : Nat

/-- Where a fragment's data ends. -/
def Frag.stop (f : Frag) : Nat := f.offset + f.data.length

/-- A fragment with no offset and no more to come: the whole packet in one
fragment (RFC 6946's atomic fragment). -/
def Frag.atomic (f : Frag) : Prop := f.offset = 0 ∧ f.more = false

instance (f : Frag) : Decidable f.atomic := by unfold Frag.atomic; infer_instance

/-- A fragment the code discards on sight: a non-last fragment whose length
is not a multiple of 8, or an empty one (ip.rs 698-702). -/
def Frag.bad (f : Frag) : Prop := (f.more = true ∧ f.data.length % 8 ≠ 0) ∨ f.data = []

instance (f : Frag) : Decidable f.bad := by unfold Frag.bad; infer_instance

/-- A waiting fragment's data at its offset. `more` is a ghost field. -/
structure Piece where
  off : Nat
  data : List Nat
  more : Bool
  deriving DecidableEq, Repr

/-- Where a piece's data ends. -/
def Piece.stop (q : Piece) : Nat := q.off + q.data.length

/-- The piece a fragment would add. -/
def Frag.piece (f : Frag) : Piece := ⟨f.offset, f.data, f.more⟩

/-- One packet being put back together, or dropped (`Partial`). -/
structure Partial where
  dead : Bool
  header : Option (List Nat)
  /-- `pieces`, the code's `BTreeMap` by offset, in ascending order. -/
  pieces : List Piece
  total : Option Nat
  got : Nat
  size : Nat
  expires : Nat

/-- `Reassembly`: the unfinished packets and the bytes they count. -/
structure State where
  parts : List (Key × Partial)
  size : Nat

/-- The empty table (`Reassembly::default`). -/
def State.empty : State := ⟨[], 0⟩

/-! ## The association list -/

/-- `partial.get(key)`. -/
def get? : List (Key × Partial) → Key → Option Partial
  | [], _ => none
  | (k', p) :: rest, k => if k' = k then some p else get? rest k

/-- `partial.insert(key, p)`: replaces an entry, or adds one at the end. -/
def put : List (Key × Partial) → Key → Partial → List (Key × Partial)
  | [], k, p => [(k, p)]
  | (k', p') :: rest, k, p => if k' = k then (k, p) :: rest else (k', p') :: put rest k p

/-- `partial.remove(key)`. -/
def del : List (Key × Partial) → Key → List (Key × Partial)
  | [], _ => []
  | (k', p') :: rest, k => if k' = k then rest else (k', p') :: del rest k

/-- The sum of the entries' sizes. -/
def sizes : List (Key × Partial) → Nat
  | [] => 0
  | (_, p) :: rest => p.size + sizes rest

/-- The soonest deadline and its key; between equal deadlines, the first. -/
def soonestE : List (Key × Partial) → Option (Key × Nat)
  | [] => none
  | (k, p) :: rest =>
    match soonestE rest with
    | some (k', t) => if t < p.expires then some (k', t) else some (k, p.expires)
    | none => some (k, p.expires)

/-- The key with the soonest deadline: `by_expiry.first()`. -/
def soonest (ps : List (Key × Partial)) : Option Key := (soonestE ps).map (·.1)

/-! ## Pieces -/

/-- `pieces.range(..=x).next_back()`: the piece with the greatest offset at
or before `x`. -/
def pred? (ps : List Piece) (x : Nat) : Option Piece :=
  (ps.filter (fun q => decide (q.off ≤ x))).getLast?

/-- `pieces.range(x + 1..).next()`: the piece with the least offset after
`x`. -/
def succ? (ps : List Piece) (x : Nat) : Option Piece :=
  ps.find? (fun q => decide (x < q.off))

/-- `pieces.insert(offset, data)`, at an offset not yet there. -/
def insertPiece (q : Piece) : List Piece → List Piece
  | [] => [q]
  | r :: rest => if q.off < r.off then q :: r :: rest else r :: insertPiece q rest

/-! ## Building the whole packet (`finish`, ip.rs 926-952) -/

/-- Writes a 16-bit big-endian word at byte `i`. -/
def setWord (h : List Nat) (i v : Nat) : List Nat :=
  (h.set i (v / 256)).set (i + 1) (v % 256)

/-- `set_header_checksum`: zero the checksum field, compute RFC 1071 over
the header, write it. -/
def setHeaderChecksum (h : List Nat) : List Nat :=
  let h0 := setWord h 10 0
  setWord h0 10 (Checksum.checksum h0)

/-- Whether the headers are IPv4's: the version in the top four bits. -/
def isV4 (header : List Nat) : Bool := header.headD 0 / 16 == 4

/-- The length field `finish` writes: IPv4's total length, or IPv6's payload
length (the fixed header is 40 bytes). -/
def lenField (header : List Nat) (total : Nat) : Nat :=
  if isV4 header then header.length + total else header.length - 40 + total

/-- `finish`: the first fragment's headers, then the data. `none` if the
length field cannot say the length. For IPv4: total length rewritten,
"more fragments" and the offset cleared, "don't fragment" kept (byte 6 is
masked with `0x40`), the header checksum recomputed. For IPv6: the payload
length rewritten. -/
def finish (header : List Nat) (datas : List (List Nat)) (total : Nat) : Option (List Nat) :=
  if MAX_LEN < lenField header total then none
  else if isV4 header then
    some (setHeaderChecksum (((setWord header 2 (lenField header total)).set 6
      (header.getD 6 0 &&& 0x40)).set 7 0) ++ datas.flatten)
  else some (setWord header 4 (lenField header total) ++ datas.flatten)

/-! ## The steps -/

/-- A new unfinished packet, with its deadline (`or_insert_with`). -/
def fresh (expires : Nat) : Partial := ⟨false, none, [], none, 0, PARTIAL_COST, expires⟩

/-- What `kill` leaves of a packet: dead, its fragments freed. -/
def Partial.killed (p : Partial) : Partial :=
  { p with dead := true, header := none, pieces := [], got := 0, size := PARTIAL_COST }

/-- `Reassembly::kill` (ip.rs 819-832). -/
def kill (s : State) (k : Key) : State :=
  match get? s.parts k with
  | none => s
  | some p => ⟨put s.parts k p.killed, s.size - (p.size - PARTIAL_COST)⟩

/-- `Reassembly::take` (ip.rs 807-813), and `remove`. -/
def take (s : State) (k : Key) : State :=
  match get? s.parts k with
  | none => s
  | some p => ⟨del s.parts k, s.size - p.size⟩

/-- `Reassembly::expire` (ip.rs 863-871): drops every packet whose deadline
is at or before `now`. -/
def expire (s : State) (now : Nat) : State :=
  ⟨s.parts.filter (fun e => decide (now < e.2.expires)),
   s.size - sizes (s.parts.filter (fun e => decide (e.2.expires ≤ now)))⟩

/-- The cap loop in `reassemble` (ip.rs 677-682), with fuel for each entry. -/
def capLoop : Nat → State → State
  | 0, s => s
  | n + 1, s =>
    if MAX_WAITING < s.size then
      match soonest s.parts with
      | none => s
      | some k => capLoop n (take s k)
    else s

/-- The cap: drops the soonest deadlines while more than `MAX_WAITING`
bytes wait. -/
def cap (s : State) : State := capLoop s.parts.length s

/-- What a step made of a packet (`Intake`, and `push_fragment`'s result). -/
inductive Out where
  | whole (bytes : List Nat)
  | waiting
  | discarded
  | refused
  deriving DecidableEq, Repr

/-- An exact copy of a waiting fragment, by offset and bytes (ip.rs 732-735). -/
def isCopy (p : Partial) (f : Frag) : Bool :=
  match pred? p.pieces f.offset with
  | some q => q.off == f.offset && q.data == f.data
  | none => false

/-- The length checks (ip.rs 744-761): a last fragment must agree with the
length and end after every piece; any other must end before the length. -/
def lengthOk (p : Partial) (f : Frag) : Bool :=
  if f.more then !(p.total.any (fun t => decide (t ≤ f.stop)))
  else p.total.all (fun t => decide (t = f.stop)) &&
    !(p.pieces.getLast?.any (fun q => decide (f.stop < q.stop)))

/-- The overlap checks against the neighbors (ip.rs 762-775). -/
def overlapOk (p : Partial) (f : Frag) : Bool :=
  !((pred? p.pieces f.offset).any (fun q => decide (f.offset < q.stop))) &&
  !((succ? p.pieces f.offset).any (fun q => decide (q.off < f.stop)))

/-- The length a last fragment sets, whether or not its checks pass
(ip.rs 745-758). -/
def Partial.setLen (p : Partial) (f : Frag) : Partial :=
  if f.more then p else { p with total := some f.stop }

/-- The packet after a fragment passes every check (ip.rs 780-790). -/
def Partial.add (p : Partial) (f : Frag) : Partial :=
  let header := match f.header, p.header with
    | some h, none => some h
    | _, old => old
  let hdr := match f.header, p.header with
    | some h, none => h.length
    | _, _ => 0
  { p with header := header, pieces := insertPiece f.piece p.pieces, got := p.got + f.data.length,
           size := p.size + (f.data.length + PIECE_COST + hdr) }

/-- The packet a fragment joins, made if there is none (`entry(key)
.or_insert_with`, ip.rs 709-724): its deadline is the first fragment's
arrival plus the timeout. -/
def lookup (s : State) (f : Frag) (now : Nat) : State × Partial :=
  match get? s.parts f.key with
  | some p => (s, p)
  | none => (⟨put s.parts f.key (fresh (now + f.timeout)), s.size + PARTIAL_COST⟩,
             fresh (now + f.timeout))

/-- The rest of `push_fragment` (ip.rs 725-804), for a fragment of the
packet `p` that the table `s` holds. -/
def admit (s : State) (p : Partial) (f : Frag) : State × Out :=
  if p.dead then (s, .discarded)
  else if isCopy p f then
    if decide (p.total = some f.stop) != f.more then (s, .waiting)
    else (kill s f.key, .discarded)
  else
    let ok := lengthOk p f && overlapOk p f
    let p := p.setLen f
    if !ok then (kill ⟨put s.parts f.key p, s.size⟩ f.key, .discarded)
    else
      let q := p.add f
      let s' : State := ⟨put s.parts f.key q, s.size + (q.size - p.size)⟩
      match q.header with
      | some h =>
        if q.total = some q.got then
          match finish h (q.pieces.map (·.data)) q.got with
          | some b => (take s' f.key, .whole b)
          | none => (take s' f.key, .discarded)
        else (s', .waiting)
      | none => (s', .waiting)

/-- `push_fragment` (ip.rs 686-805), for a packet `arrived` read as a
fragment. -/
def pushFragment (s : State) (f : Frag) (now : Nat) : State × Out :=
  if f.atomic then
    match f.header with
    | none => (s, .discarded)
    | some h =>
      match finish h [f.data] f.data.length with
      | some b => (s, .whole b)
      | none => (s, .discarded)
  else if f.bad then (s, .discarded)
  else if MAX_LEN < f.stop then (kill s f.key, .discarded)
  else admit (lookup s f now).1 (lookup s f now).2 f

/-- `reassemble` (ip.rs 665-684): expire, take the fragment, cap. -/
def reassemble (s : State) (f : Frag) (now : Nat) : State × Out :=
  let r := pushFragment (expire s now) f now
  (cap r.1, r.2)

/-! ## Reading packets (`arrived`, ip.rs 874-924) -/

/-- A 16-bit big-endian word at byte `i`. -/
def be16 (b : List Nat) (i : Nat) : Nat := b.getD i 0 * 256 + b.getD (i + 1) 0

/-- A 32-bit big-endian word at byte `i`. -/
def be32 (b : List Nat) (i : Nat) : Nat := be16 b i * 65536 + be16 b (i + 2)

/-- Bytes `i` to `j`. -/
def slice (b : List Nat) (i j : Nat) : List Nat := (b.drop i).take (j - i)

/-- An IPv4 fragment (`v4_checked`, then `arrived`): a whole header with a
verifying checksum (RFC 1122 section 3.2.1.2) and "more fragments" or an
offset set. -/
def arrived4 (b : List Nat) : Option Frag :=
  let ihl := b.getD 0 0 % 16 * 4
  let total := be16 b 2
  if b.length < 20 ∨ ihl < 20 ∨ b.length < ihl ∨ total < ihl ∨ b.length < total then none
  else if Checksum.checksum (b.take ihl) ≠ 0 then none
  else
    let flags := be16 b 6
    if flags % 16384 = 0 then none
    else
      let offset := flags % 8192 * 8
      some ⟨.v4 (slice b 12 16) (slice b 16 20) (be16 b 4) (b.getD 9 0), offset,
        flags / 8192 % 2 == 1, slice b ihl total,
        if offset = 0 then some (b.take ihl) else none, V4_TIMEOUT⟩

/-- An IPv6 header chain as `chain6` walks one it accepts: the upper-layer
protocol, where it starts, and the first fragment header with the place of
the "next header" byte that names it. -/
structure Chain where
  proto : Nat
  upper : Nat
  frag : Option (Nat × Nat)

/-- The extension headers `chain6` reads past: Hop-by-Hop (0), Destination
Options (60), Routing (43), Authentication (51) and Fragment (44). -/
def isExt (next : Nat) : Prop := next = 0 ∨ next = 60 ∨ next = 43 ∨ next = 51 ∨ next = 44

instance (next : Nat) : Decidable (isExt next) := by unfold isExt; infer_instance

/-- An extension header's length, from its length field (RFC 8200 section
4; the Authentication header counts 4-byte units past the first two). -/
def extLen (b : List Nat) (next pos : Nat) : Nat :=
  if next = 44 then 8
  else if next = 51 then (b.getD (pos + 1) 0 + 2) * 4
  else (b.getD (pos + 1) 0 + 1) * 8

/-- The walk in `chain6` (ip.rs 1300-1406). `none` where `chain6` refuses
the chain for running past the packet or for a second fragment header.
In a fragment after the first, the walk stops after the fragment header. -/
def walk (b : List Nat) (stop : Nat) : Nat → Nat → Nat → Nat → Option (Nat × Nat) → Option Chain
  | 0, _, _, _, _ => none
  | fuel + 1, next, nextAt, pos, frag =>
    if ¬ isExt next then some ⟨next, pos, frag⟩
    else if b.length ≤ pos + 1 ∨ stop < pos + extLen b next pos then none
    else if next = 44 ∧ frag.isSome then none
    else if next = 44 ∧ be16 b (pos + 2) / 8 ≠ 0 then
      some ⟨b.getD pos 0, pos + extLen b next pos, some (pos, nextAt)⟩
    else walk b stop fuel (b.getD pos 0) pos (pos + extLen b next pos)
      (if next = 44 then some (pos, nextAt) else frag)

/-- `chain6`'s walk from the fixed header. -/
def chain (b : List Nat) : Option Chain :=
  walk b (40 + be16 b 4) b.length (b.getD 6 0) 6 40 none

/-- An IPv6 fragment (`arrived`): the headers in front of the fragment
header, with the "next header" byte that named it naming what it named,
are the first fragment's headers. -/
def arrived6 (b : List Nat) : Option Frag :=
  let stop := 40 + be16 b 4
  if b.length < 40 ∨ b.length < stop then none
  else
    match chain b with
    | none => none
    | some c =>
      match c.frag with
      | none => none
      | some (pos, nextAt) =>
        let om := be16 b (pos + 2)
        let offset := om / 8 * 8
        some ⟨.v6 (slice b 8 24) (slice b 24 40) (be32 b (pos + 4)), offset, om % 2 == 1,
          slice b (pos + 8) stop,
          if offset = 0 then some ((b.take pos).set nextAt (b.getD pos 0)) else none, V6_TIMEOUT⟩

/-- `arrived`: a fragment, or `none` for a packet that is not one. -/
def arrived (b : List Nat) : Option Frag :=
  if b.headD 0 / 16 = 4 then arrived4 b
  else if b.headD 0 / 16 = 6 then arrived6 b
  else none

/-- `strip_extension_headers` on a whole IPv6 packet whose chain is
accepted; `none` for one that still holds a fragment header. -/
def strip (b : List Nat) : Option (List Nat) :=
  let stop := 40 + be16 b 4
  match chain b with
  | none => none
  | some c =>
    if c.frag.isSome then none
    else if c.upper = 40 then some b
    else some ((setWord (b.take 40) 4 (stop - c.upper)).set 6 c.proto ++ slice b c.upper stop)

/-- `reassemble` on a packet: one `arrived` does not read as a fragment
comes back as it is. -/
def reassemblePkt (s : State) (b : List Nat) (now : Nat) : State × Out :=
  match arrived b with
  | none => (cap (expire s now), .whole b)
  | some f => reassemble s f now

/-- `Reassembly::push` on a packet whose IPv6 chain `chain6` accepts: a
whole IPv6 packet has its extension headers taken out. -/
def push (s : State) (b : List Nat) (now : Nat) : State × Out :=
  let r := reassemblePkt s b now
  match r.2 with
  | .whole w =>
    if w.headD 0 / 16 = 6 then
      match strip w with
      | some w' => (r.1, .whole w')
      | none => (r.1, .refused)
    else r
  | _ => r

/-- Every step's result, from the empty table. -/
def run (steps : List (Nat × List Nat)) : List Out :=
  (steps.foldl (fun (acc : State × Array Out) (st : Nat × List Nat) =>
    let r := push acc.1 st.2 st.1
    (r.1, acc.2.push r.2)) (State.empty, #[])).2.toList


/-! ## Proofs: the association list -/

/-- The size counted for a key, 0 if it has no entry. -/
def oldSize (ps : List (Key × Partial)) (k : Key) : Nat := ((get? ps k).map (·.size)).getD 0

theorem get?_put_self (ps : List (Key × Partial)) (k : Key) (p : Partial) :
    get? (put ps k p) k = some p := by
  induction ps with
  | nil => simp [put, get?]
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    by_cases h : k' = k <;> simp [put, get?, h, ih]

theorem get?_put_ne (ps : List (Key × Partial)) {k k' : Key} (p : Partial) (h : k' ≠ k) :
    get? (put ps k p) k' = get? ps k' := by
  induction ps with
  | nil => simp [put, get?, Ne.symm h]
  | cons e rest ih =>
    obtain ⟨k'', p'⟩ := e
    by_cases h1 : k'' = k
    · subst h1; simp [put, get?, Ne.symm h]
    · by_cases h2 : k'' = k'
      · subst h2; simp [put, get?, h1]
      · simp [put, get?, h1, h2, ih]

theorem get?_del_ne (ps : List (Key × Partial)) {k k' : Key} (h : k' ≠ k) :
    get? (del ps k) k' = get? ps k' := by
  induction ps with
  | nil => simp [del, get?]
  | cons e rest ih =>
    obtain ⟨k'', p'⟩ := e
    by_cases h1 : k'' = k
    · subst h1; simp [del, get?, Ne.symm h]
    · by_cases h2 : k'' = k'
      · subst h2; simp [del, get?, h1]
      · simp [del, get?, h1, h2, ih]

theorem sizes_put (ps : List (Key × Partial)) (k : Key) (p : Partial) :
    sizes (put ps k p) + oldSize ps k = sizes ps + p.size := by
  induction ps with
  | nil => simp [put, sizes, oldSize, get?]
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    by_cases h : k' = k
    · simp [put, sizes, oldSize, get?, h]; omega
    · simp [put, sizes, oldSize, get?, h] at ih ⊢; omega

theorem sizes_del (ps : List (Key × Partial)) (k : Key) :
    sizes (del ps k) + oldSize ps k = sizes ps := by
  induction ps with
  | nil => simp [del, sizes, oldSize, get?]
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    by_cases h : k' = k
    · simp [del, sizes, oldSize, get?, h]; omega
    · simp [del, sizes, oldSize, get?, h] at ih ⊢; omega

theorem mem_put {ps : List (Key × Partial)} {k : Key} {p : Partial} {e : Key × Partial}
    (h : e ∈ put ps k p) : e = (k, p) ∨ e ∈ ps := by
  induction ps with
  | nil => simp [put] at h; exact Or.inl h
  | cons e' rest ih =>
    obtain ⟨k', p'⟩ := e'
    by_cases hk : k' = k
    · simp [put, hk] at h
      rcases h with h | h
      · exact Or.inl h
      · exact Or.inr (List.mem_cons_of_mem _ h)
    · simp [put, hk] at h
      rcases h with h | h
      · exact Or.inr (h ▸ List.mem_cons_self)
      · rcases ih h with h' | h'
        · exact Or.inl h'
        · exact Or.inr (List.mem_cons_of_mem _ h')

theorem mem_del {ps : List (Key × Partial)} {k : Key} {e : Key × Partial}
    (h : e ∈ del ps k) : e ∈ ps := by
  induction ps with
  | nil => simp [del] at h
  | cons e' rest ih =>
    obtain ⟨k', p'⟩ := e'
    by_cases hk : k' = k
    · simp [del, hk] at h; exact List.mem_cons_of_mem _ h
    · simp [del, hk] at h
      rcases h with h | h
      · exact h ▸ List.mem_cons_self
      · exact List.mem_cons_of_mem _ (ih h)

theorem get?_mem {ps : List (Key × Partial)} {k : Key} {p : Partial}
    (h : get? ps k = some p) : (k, p) ∈ ps := by
  induction ps with
  | nil => simp [get?] at h
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    by_cases hk : k' = k
    · simp [get?, hk] at h; subst hk; subst h; exact List.mem_cons_self
    · simp [get?, hk] at h; exact List.mem_cons_of_mem _ (ih h)

theorem keys_put (ps : List (Key × Partial)) (k : Key) (p : Partial) :
    (put ps k p).map (·.1) = if k ∈ ps.map (·.1) then ps.map (·.1) else ps.map (·.1) ++ [k] := by
  induction ps with
  | nil => simp [put]
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    by_cases hk : k' = k
    · subst hk; simp [put]
    · simp only [put, hk, ite_false, List.map_cons, ih, List.mem_cons]
      by_cases hm : k ∈ rest.map (·.1)
      · simp [hm]
      · simp [hm, Ne.symm hk]

theorem nodup_put {ps : List (Key × Partial)} (k : Key) (p : Partial)
    (h : (ps.map (·.1)).Nodup) : ((put ps k p).map (·.1)).Nodup := by
  rw [keys_put]
  split
  · exact h
  · next hm =>
    rw [List.nodup_append]
    exact ⟨h, List.nodup_cons.mpr ⟨by simp, List.nodup_nil⟩, fun a ha b hb => by
      simp at hb; subst hb; intro e; subst e; exact hm ha⟩

theorem del_sublist (ps : List (Key × Partial)) (k : Key) : (del ps k).Sublist ps := by
  induction ps with
  | nil => simp [del]
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    by_cases hk : k' = k
    · simp [del, hk]
    · simp [del, hk]; exact ih

theorem nodup_del {ps : List (Key × Partial)} (k : Key)
    (h : (ps.map (·.1)).Nodup) : ((del ps k).map (·.1)).Nodup :=
  h.sublist ((del_sublist ps k).map _)

theorem get?_del_self {ps : List (Key × Partial)} {k : Key}
    (h : (ps.map (·.1)).Nodup) : get? (del ps k) k = none := by
  induction ps with
  | nil => simp [del, get?]
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    simp only [List.map_cons, List.nodup_cons] at h
    by_cases hk : k' = k
    · subst hk
      simp only [del, ite_true]
      clear ih
      induction rest with
      | nil => simp [get?]
      | cons e r ih2 =>
        obtain ⟨k'', p''⟩ := e
        simp only [List.map_cons, List.mem_cons, not_or, List.nodup_cons] at h
        simp [get?, Ne.symm h.1.1]
        exact ih2 ⟨h.1.2, h.2.2⟩
    · simp [del, get?, hk, ih h.2]

theorem put_put (ps : List (Key × Partial)) (k : Key) (p q : Partial) :
    put (put ps k p) k q = put ps k q := by
  induction ps with
  | nil => simp [put]
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    by_cases hk : k' = k <;> simp [put, hk, ih]

theorem del_put (ps : List (Key × Partial)) (k : Key) (p : Partial) :
    del (put ps k p) k = del ps k := by
  induction ps with
  | nil => simp [put, del]
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    by_cases hk : k' = k <;> simp [put, del, hk, ih]

theorem length_del {ps : List (Key × Partial)} {k : Key} {p : Partial}
    (h : get? ps k = some p) : (del ps k).length + 1 = ps.length := by
  induction ps with
  | nil => simp [get?] at h
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    by_cases hk : k' = k
    · simp [del, hk]
    · simp [get?, hk] at h; simp [del, hk, ih h]

theorem sizes_filter (ps : List (Key × Partial)) (c : Key × Partial → Bool) :
    sizes (ps.filter c) + sizes (ps.filter (fun e => !c e)) = sizes ps := by
  induction ps with
  | nil => simp [sizes]
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    by_cases hc : c (k', p') = true
    · simp [List.filter, hc, sizes]; omega
    · simp [List.filter, hc, sizes]; omega


theorem get?_filter_some {ps : List (Key × Partial)} {k : Key} {p : Partial}
    (c : Key × Partial → Bool) (hk : get? ps k = some p) (hc : c (k, p) = true) :
    get? (ps.filter c) k = some p := by
  induction ps with
  | nil => simp [get?] at hk
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    by_cases h : k' = k
    · subst h; simp [get?] at hk; subst hk; simp [List.filter, hc, get?]
    · simp [get?, h] at hk
      by_cases hc' : c (k', p') = true
      · simp [List.filter, hc', get?, h, ih hk]
      · simp [List.filter, hc', ih hk]

theorem get?_filter_none {ps : List (Key × Partial)} {k : Key}
    (c : Key × Partial → Bool) (hk : get? ps k = none) : get? (ps.filter c) k = none := by
  induction ps with
  | nil => simp [get?]
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    by_cases h : k' = k
    · simp [get?, h] at hk
    · simp [get?, h] at hk
      by_cases hc' : c (k', p') = true
      · simp [List.filter, hc', get?, h, ih hk]
      · simp [List.filter, hc', ih hk]

theorem get?_of_mem {ps : List (Key × Partial)} {k : Key} {p : Partial}
    (h : (k, p) ∈ ps) : ∃ p', get? ps k = some p' := by
  induction ps with
  | nil => simp at h
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    by_cases hk : k' = k
    · exact ⟨p', by simp [get?, hk]⟩
    · simp [get?, hk]
      rcases List.mem_cons.mp h with h | h
      · simp at h; exact absurd h.1.symm hk
      · exact ih h

theorem soonestE_mem {ps : List (Key × Partial)} {k : Key} {t : Nat}
    (h : soonestE ps = some (k, t)) : ∃ p, (k, p) ∈ ps := by
  induction ps generalizing k t with
  | nil => simp [soonestE] at h
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    simp only [soonestE] at h
    split at h
    · next k'' t' heq =>
      split at h
      · simp at h; obtain ⟨rfl, rfl⟩ := h
        obtain ⟨p, hp⟩ := ih heq
        exact ⟨p, List.mem_cons_of_mem _ hp⟩
      · simp at h; obtain ⟨rfl, rfl⟩ := h; exact ⟨p', List.mem_cons_self⟩
    · simp at h; obtain ⟨rfl, rfl⟩ := h; exact ⟨p', List.mem_cons_self⟩

theorem soonestE_none {ps : List (Key × Partial)} (h : soonestE ps = none) : ps = [] := by
  cases ps with
  | nil => rfl
  | cons e rest =>
    obtain ⟨k', p'⟩ := e
    simp only [soonestE] at h
    split at h
    · split at h <;> simp at h
    · simp at h

theorem oldSize_le {ps : List (Key × Partial)} {k : Key} : oldSize ps k ≤ sizes ps := by
  have := sizes_del ps k; omega

theorem oldSize_some {ps : List (Key × Partial)} {k : Key} {p : Partial}
    (h : get? ps k = some p) : oldSize ps k = p.size := by
  simp [oldSize, h]

/-! ## Proofs: the invariant -/

/-- The data bytes of some pieces. -/
def lens (ps : List Piece) : Nat := (ps.map fun q => q.data.length).sum

/-- What some pieces count against the cap. -/
def pieceCost (ps : List Piece) : Nat := (ps.map fun q => q.data.length + PIECE_COST).sum

/-- What a first fragment's headers count. -/
def hdrCost (h : Option (List Nat)) : Nat := (h.map List.length).getD 0

/-- Pieces in ascending order that do not overlap. -/
def Sorted (ps : List Piece) : Prop := ps.Pairwise fun a b => a.stop ≤ b.off

/-- What holds of every packet in the table. -/
structure PartialOk (p : Partial) : Prop where
  sorted : Sorted p.pieces
  nonempty : ∀ q ∈ p.pieces, q.data ≠ []
  got : p.got = lens p.pieces
  size : p.size = PARTIAL_COST + pieceCost p.pieces + hdrCost p.header
  dead : p.dead = true → p.pieces = [] ∧ p.header = none
  bound : ∀ t, p.total = some t → ∀ q ∈ p.pieces, q.stop ≤ t
  last : ∀ q ∈ p.pieces, (q.more = false ↔ p.total = some q.stop)
  eight : ∀ q ∈ p.pieces, q.more = true → q.data.length % 8 = 0
  limit : ∀ q ∈ p.pieces, q.stop ≤ MAX_LEN

/-- The table's invariant without the cap. -/
structure Inv0 (s : State) : Prop where
  nodup : (s.parts.map (·.1)).Nodup
  size : s.size = sizes s.parts
  ok : ∀ e ∈ s.parts, PartialOk e.2

theorem ok_of_get {s : State} {k : Key} {p : Partial} (hs : Inv0 s) (h : get? s.parts k = some p) :
    PartialOk p := hs.ok _ (get?_mem h)

theorem mem_of_mem_filter' {α} {l : List α} {c : α → Bool} {x : α} (h : x ∈ l.filter c) : x ∈ l :=
  (List.mem_filter.mp h).1

/-- The table's invariant: `Inv0` and the cap. -/
def Inv (s : State) : Prop := Inv0 s ∧ s.size ≤ MAX_WAITING

/-- Everything `Reassembly::check` asserts (ip.rs 839-861): the cap; the
sizes add up; the pieces of each packet ascend and do not overlap; `have`
is their bytes; none passes the length. The code's `by_expiry` index is read
off the entries here, so its agreement with the map holds by construction. -/
def Check (s : State) : Prop :=
  s.size ≤ MAX_WAITING ∧ s.size = sizes s.parts ∧
  ∀ e ∈ s.parts, Sorted e.2.pieces ∧ e.2.got = lens e.2.pieces ∧
    ∀ t, e.2.total = some t → ∀ q ∈ e.2.pieces, q.stop ≤ t

theorem check_of_inv {s : State} (h : Inv s) : Check s :=
  ⟨h.2, h.1.size, fun e he => ⟨(h.1.ok e he).sorted, (h.1.ok e he).got, (h.1.ok e he).bound⟩⟩

theorem inv_empty : Inv State.empty :=
  ⟨⟨by simp [State.empty], by simp [State.empty, sizes], by simp [State.empty]⟩,
   by simp [State.empty, MAX_WAITING]⟩

theorem partialOk_size {p : Partial} (h : PartialOk p) : PARTIAL_COST ≤ p.size := by
  rw [h.size]; omega

theorem killed_ok (p : Partial) : PartialOk p.killed := by
  constructor <;> simp [Partial.killed, Sorted, lens, pieceCost, hdrCost]

theorem fresh_ok (t : Nat) : PartialOk (fresh t) := by
  constructor <;> simp [fresh, Sorted, lens, pieceCost, hdrCost]

theorem inv0_put {s : State} {k : Key} {p : Partial} {sz : Nat} (hs : Inv0 s) (hp : PartialOk p)
    (hsz : sz + oldSize s.parts k = s.size + p.size) : Inv0 ⟨put s.parts k p, sz⟩ := by
  refine ⟨nodup_put k p hs.nodup, ?_, ?_⟩
  · have := sizes_put s.parts k p; have := hs.size; simp only; omega
  · intro e he
    rcases mem_put he with h | h
    · subst h; exact hp
    · exact hs.ok e h

theorem inv0_del {s : State} {k : Key} {sz : Nat} (hs : Inv0 s)
    (hsz : sz + oldSize s.parts k = s.size) : Inv0 ⟨del s.parts k, sz⟩ := by
  refine ⟨nodup_del k hs.nodup, ?_, fun e he => hs.ok e (mem_del he)⟩
  have := sizes_del s.parts k; have := hs.size; simp only; omega

theorem kill_inv0 {s : State} (k : Key) (hs : Inv0 s) : Inv0 (kill s k) ∧ (kill s k).size ≤ s.size := by
  unfold kill
  split
  · exact ⟨hs, Nat.le_refl _⟩
  · next p hp =>
    have hok := ok_of_get hs hp
    have := partialOk_size hok
    have h1 := oldSize_some hp
    have h2 : p.size ≤ s.size := by have := @oldSize_le s.parts k; rw [hs.size]; omega
    refine ⟨inv0_put hs (killed_ok p) ?_, ?_⟩
    · simp [Partial.killed]; omega
    · simp only; omega

theorem take_inv0 {s : State} (k : Key) (hs : Inv0 s) : Inv0 (take s k) ∧ (take s k).size ≤ s.size := by
  unfold take
  split
  · exact ⟨hs, Nat.le_refl _⟩
  · next p hp =>
    have h1 := oldSize_some hp
    have h2 : p.size ≤ s.size := by have := @oldSize_le s.parts k; rw [hs.size]; omega
    exact ⟨inv0_del hs (by omega), by simp only; omega⟩

theorem expire_inv0 {s : State} (now : Nat) (hs : Inv0 s) :
    Inv0 (expire s now) ∧ (expire s now).size ≤ s.size := by
  have hf := sizes_filter s.parts (fun e => decide (now < e.2.expires))
  have e1 : (s.parts.filter fun e => !decide (now < e.2.expires)) =
      s.parts.filter fun e => decide (e.2.expires ≤ now) := by
    apply List.filter_congr
    intro e _
    apply Bool.eq_iff_iff.mpr
    simp only [Bool.not_eq_true', decide_eq_false_iff_not, decide_eq_true_eq]
    exact Nat.not_lt
  rw [e1] at hf
  refine ⟨⟨hs.nodup.sublist ((List.filter_sublist).map _), ?_, ?_⟩, ?_⟩
  · simp only [expire]; have := hs.size; omega
  · intro e he; exact hs.ok e (mem_of_mem_filter' he)
  · simp only [expire]; omega

theorem capLoop_inv0 : ∀ (n : Nat) {s : State}, Inv0 s →
    Inv0 (capLoop n s) ∧ (capLoop n s).size ≤ s.size ∧
    (s.parts.length ≤ n → (capLoop n s).size ≤ MAX_WAITING)
  | 0, s, hs => by
    refine ⟨hs, Nat.le_refl _, fun hn => ?_⟩
    have : s.parts = [] := List.eq_nil_of_length_eq_zero (by omega)
    simp [capLoop, hs.size, this, sizes, MAX_WAITING]
  | n + 1, s, hs => by
    unfold capLoop
    split
    · split
      · next hn =>
        have := soonestE_none (by simpa [soonest] using hn)
        refine ⟨hs, Nat.le_refl _, fun _ => ?_⟩
        simp [hs.size, this, sizes, MAX_WAITING]
      · next k hk =>
        obtain ⟨⟨k', t⟩, hkt, rfl⟩ : ∃ x, soonestE s.parts = some x ∧ x.1 = k := by
          simp [soonest] at hk; obtain ⟨t, ht⟩ := hk; exact ⟨_, ht, rfl⟩
        obtain ⟨p, hp⟩ := soonestE_mem hkt
        obtain ⟨p', hp'⟩ := get?_of_mem hp
        have ht := take_inv0 k' hs
        have ih := capLoop_inv0 n ht.1
        refine ⟨ih.1, Nat.le_trans ih.2.1 ht.2, fun hn => ih.2.2 ?_⟩
        have := length_del hp'
        simp only [take, hp']; omega
    · exact ⟨hs, Nat.le_refl _, fun _ => by omega⟩

theorem cap_inv {s : State} (hs : Inv0 s) : Inv (cap s) ∧ (cap s).size ≤ s.size :=
  let h := capLoop_inv0 s.parts.length hs
  ⟨⟨h.1, h.2.2 (Nat.le_refl _)⟩, h.2.1⟩

theorem capLoop_id : ∀ (n : Nat) {s : State}, s.size ≤ MAX_WAITING → capLoop n s = s
  | 0, _, _ => rfl
  | _ + 1, _, h => by simp [capLoop, Nat.not_lt.mpr h]

theorem cap_id {s : State} (h : s.size ≤ MAX_WAITING) : cap s = s := capLoop_id _ h

/-! ## Proofs: pieces -/

theorem mem_of_getLast? {α} : ∀ {l : List α} {b : α}, l.getLast? = some b → b ∈ l
  | [], _, h => by simp at h
  | [a], b, h => by simp at h; simp [h]
  | a :: c :: rest, b, h => by
    rw [List.getLast?_cons_cons] at h
    exact List.mem_cons_of_mem _ (mem_of_getLast? h)

theorem pairwise_getLast? {α} {R : α → α → Prop} :
    ∀ {l : List α} {a b : α}, l.Pairwise R → l.getLast? = some b → a ∈ l → a = b ∨ R a b
  | [], _, _, _, h, _ => by simp at h
  | [x], a, b, _, h, ha => by simp at h ha; exact Or.inl (ha.trans h)
  | x :: y :: rest, a, b, hp, h, ha => by
    rw [List.getLast?_cons_cons] at h
    rcases List.mem_cons.mp ha with rfl | ha
    · exact Or.inr ((List.pairwise_cons.mp hp).1 b (mem_of_getLast? h))
    · exact pairwise_getLast? (List.pairwise_cons.mp hp).2 h ha

theorem pairwise_find? {α} {R : α → α → Prop} {c : α → Bool} :
    ∀ {l : List α} {a b : α}, l.Pairwise R → l.find? c = some b → a ∈ l → c a = true →
      b = a ∨ R b a
  | [], _, _, _, h, _, _ => by simp at h
  | x :: rest, a, b, hp, h, ha, hc => by
    by_cases hx : c x = true
    · simp only [List.find?_cons, hx] at h
      cases h
      rcases List.mem_cons.mp ha with rfl | ha
      · exact Or.inl rfl
      · exact Or.inr ((List.pairwise_cons.mp hp).1 a ha)
    · simp only [List.find?_cons, (by simpa using hx : c x = false)] at h
      rcases List.mem_cons.mp ha with rfl | ha
      · exact absurd hc hx
      · exact pairwise_find? (List.pairwise_cons.mp hp).2 h ha hc

/-- `q` and `r` share no byte. -/
def Apart (q r : Piece) : Prop := r.stop ≤ q.off ∨ q.stop ≤ r.off

theorem stop_pos {q : Piece} (h : q.data ≠ []) : q.off < q.stop := by
  have : q.data.length ≠ 0 := by simpa using h
  simp [Piece.stop]; omega


theorem pred?_some {ps : List Piece} {x : Nat} {b : Piece} (h : pred? ps x = some b) :
    b ∈ ps ∧ b.off ≤ x := by
  unfold pred? at h
  have := mem_of_getLast? h
  simpa using this

theorem succ?_some {ps : List Piece} {x : Nat} {b : Piece} (h : succ? ps x = some b) :
    b ∈ ps ∧ x < b.off :=
  ⟨List.mem_of_find?_eq_some h, by simpa using List.find?_some h⟩

/-- What the two neighbor checks say. -/
theorem overlapOk_eq (p : Partial) (f : Frag) :
    overlapOk p f = true ↔ (∀ b, pred? p.pieces f.offset = some b → b.stop ≤ f.offset) ∧
      (∀ b, succ? p.pieces f.offset = some b → f.stop ≤ b.off) := by
  unfold overlapOk
  cases pred? p.pieces f.offset <;> cases succ? p.pieces f.offset <;> simp

/-- What the length checks say. -/
theorem lengthOk_eq (p : Partial) (f : Frag) :
    lengthOk p f = true ↔ (f.more = true → ∀ t, p.total = some t → f.stop < t) ∧
      (f.more = false → (∀ t, p.total = some t → t = f.stop) ∧
        ∀ b, p.pieces.getLast? = some b → b.stop ≤ f.stop) := by
  unfold lengthOk
  cases f.more <;> cases p.total <;> cases p.pieces.getLast? <;> simp

/-- The neighbor checks see every overlap: on ascending, non-overlapping,
nonempty pieces, `overlapOk` holds exactly when the fragment overlaps no
piece (ip.rs 762-775 against RFC 5722's "any overlap"). -/
theorem overlapOk_iff {p : Partial} {f : Frag} (hs : Sorted p.pieces)
    (hn : ∀ q ∈ p.pieces, q.data ≠ []) (hf : f.data ≠ []) :
    overlapOk p f = true ↔ ∀ r ∈ p.pieces, Apart f.piece r := by
  have hfp : f.offset < f.stop := by
    have : f.data.length ≠ 0 := by simpa using hf
    simp [Frag.stop]; omega
  have hpst : f.piece.stop = f.stop := rfl
  have hpo : f.piece.off = f.offset := rfl
  rw [overlapOk_eq]
  constructor
  · rintro ⟨hP, hS⟩ r hr
    have hrn := stop_pos (hn r hr)
    by_cases hro : r.off ≤ f.offset
    · -- r is at or before the fragment: the last such piece ends before it
      left
      show r.stop ≤ f.offset
      have hmem : r ∈ p.pieces.filter (fun q => decide (q.off ≤ f.offset)) := by
        simp [List.mem_filter, hr, hro]
      cases hpr : pred? p.pieces f.offset with
      | none =>
        unfold pred? at hpr
        rw [List.getLast?_eq_none_iff] at hpr
        rw [hpr] at hmem; simp at hmem
      | some b =>
        have hb := hP b hpr
        rcases pairwise_getLast? (hs.filter _) hpr hmem with rfl | hrb
        · exact hb
        · have := stop_pos (hn b (pred?_some hpr).1); omega
    · -- r is after: the first such piece starts after it
      right
      show f.stop ≤ r.off
      cases hsr : succ? p.pieces f.offset with
      | none =>
        unfold succ? at hsr
        have := List.find?_eq_none.mp hsr r hr
        simp at this; omega
      | some b =>
        have hb := hS b hsr
        rcases pairwise_find? hs hsr hr (by simp; omega) with rfl | hbr
        · exact hb
        · have := stop_pos (hn b (succ?_some hsr).1); omega
  · intro h
    refine ⟨fun b hb => ?_, fun b hb => ?_⟩
    · obtain ⟨hbm, hbo⟩ := pred?_some hb
      have ha := h b hbm
      simp only [Apart, hpo, hpst] at ha
      omega
    · obtain ⟨hbm, hbo⟩ := succ?_some hb
      have ha := h b hbm
      have := stop_pos (hn b hbm)
      simp only [Apart, hpo, hpst] at ha
      omega

theorem mem_insertPiece {q r : Piece} {ps : List Piece} :
    r ∈ insertPiece q ps ↔ r = q ∨ r ∈ ps := by
  induction ps with
  | nil => simp [insertPiece]
  | cons x rest ih =>
    unfold insertPiece
    split
    · simp
    · simp only [List.mem_cons, ih]; exact or_left_comm

theorem lens_insertPiece (q : Piece) (ps : List Piece) :
    lens (insertPiece q ps) = q.data.length + lens ps := by
  induction ps with
  | nil => simp [insertPiece, lens]
  | cons x rest ih =>
    unfold insertPiece
    split
    · simp [lens]
    · simp [lens] at ih ⊢; omega

theorem pieceCost_insertPiece (q : Piece) (ps : List Piece) :
    pieceCost (insertPiece q ps) = q.data.length + PIECE_COST + pieceCost ps := by
  induction ps with
  | nil => simp [insertPiece, pieceCost]
  | cons x rest ih =>
    unfold insertPiece
    split
    · simp [pieceCost]
    · simp [pieceCost] at ih ⊢; omega

theorem sorted_insertPiece {q : Piece} {ps : List Piece} (hs : Sorted ps)
    (ha : ∀ r ∈ ps, Apart q r) (hn : ∀ r ∈ ps, r.data ≠ []) (hq : q.data ≠ []) :
    Sorted (insertPiece q ps) := by
  induction ps with
  | nil => simp [insertPiece, Sorted]
  | cons x rest ih =>
    have hx := stop_pos (hn x List.mem_cons_self)
    have hqp := stop_pos hq
    have hs' := List.pairwise_cons.mp hs
    unfold insertPiece
    split
    · next hlt =>
      have hqx : q.stop ≤ x.off := by
        rcases ha x List.mem_cons_self with h | h
        · omega
        · exact h
      refine List.pairwise_cons.mpr ⟨?_, hs⟩
      intro r hr
      rcases List.mem_cons.mp hr with rfl | hr
      · exact hqx
      · have := hs'.1 r hr; omega
    · next hge =>
      have hxq : x.stop ≤ q.off := by
        rcases ha x List.mem_cons_self with h | h
        · exact h
        · omega
      refine List.pairwise_cons.mpr ⟨?_, ih hs'.2 (fun r hr => ha r (List.mem_cons_of_mem _ hr))
        (fun r hr => hn r (List.mem_cons_of_mem _ hr))⟩
      intro r hr
      rcases mem_insertPiece.mp hr with rfl | hr
      · exact hxq
      · exact hs'.1 r hr

/-- On ascending pieces, the last one ends last. -/
theorem stop_le_last {ps : List Piece} {b r : Piece} (hs : Sorted ps)
    (hn : ∀ q ∈ ps, q.data ≠ []) (hb : ps.getLast? = some b) (hr : r ∈ ps) : r.stop ≤ b.stop := by
  rcases pairwise_getLast? hs hb hr with rfl | h
  · exact Nat.le_refl _
  · have := stop_pos (hn b (mem_of_getLast? hb)); omega

/-! ## Proofs: one step keeps the invariant -/

theorem lookup_inv0 {s : State} {f : Frag} {now : Nat} (hs : Inv0 s) :
    Inv0 (lookup s f now).1 ∧ get? (lookup s f now).1.parts f.key = some (lookup s f now).2 ∧
    PartialOk (lookup s f now).2 := by
  unfold lookup
  split
  · next p hp => exact ⟨hs, hp, ok_of_get hs hp⟩
  · next hp =>
    refine ⟨inv0_put hs (fresh_ok _) ?_, get?_put_self _ _ _, fresh_ok _⟩
    simp [oldSize, hp, fresh]

@[simp] theorem setLen_pieces (p : Partial) (f : Frag) : (p.setLen f).pieces = p.pieces := by
  unfold Partial.setLen; split <;> rfl
@[simp] theorem setLen_header (p : Partial) (f : Frag) : (p.setLen f).header = p.header := by
  unfold Partial.setLen; split <;> rfl
@[simp] theorem setLen_got (p : Partial) (f : Frag) : (p.setLen f).got = p.got := by
  unfold Partial.setLen; split <;> rfl
@[simp] theorem setLen_size (p : Partial) (f : Frag) : (p.setLen f).size = p.size := by
  unfold Partial.setLen; split <;> rfl
@[simp] theorem setLen_dead (p : Partial) (f : Frag) : (p.setLen f).dead = p.dead := by
  unfold Partial.setLen; split <;> rfl
@[simp] theorem setLen_expires (p : Partial) (f : Frag) : (p.setLen f).expires = p.expires := by
  unfold Partial.setLen; split <;> rfl
theorem setLen_total (p : Partial) (f : Frag) :
    (p.setLen f).total = if f.more then p.total else some f.stop := by
  unfold Partial.setLen; split <;> simp_all

@[simp] theorem add_pieces (p : Partial) (f : Frag) : (p.add f).pieces = insertPiece f.piece p.pieces := rfl
@[simp] theorem add_got (p : Partial) (f : Frag) : (p.add f).got = p.got + f.data.length := rfl
@[simp] theorem add_dead (p : Partial) (f : Frag) : (p.add f).dead = p.dead := rfl
@[simp] theorem add_total (p : Partial) (f : Frag) : (p.add f).total = p.total := rfl
@[simp] theorem add_expires (p : Partial) (f : Frag) : (p.add f).expires = p.expires := rfl

/-- The headers a packet keeps: the first fragment's, once one arrives. -/
theorem add_header (p : Partial) (f : Frag) :
    (p.add f).header = (if p.header = none then f.header else p.header) := by
  cases hf : f.header <;> cases hp : p.header <;> simp [Partial.add, hf, hp]

theorem add_size (p : Partial) (f : Frag) :
    (p.add f).size + hdrCost p.header = p.size + f.data.length + PIECE_COST + hdrCost (p.add f).header := by
  cases hf : f.header <;> cases hp : p.header <;> simp [Partial.add, hf, hp, hdrCost] <;> omega

theorem hdrCost_add_le (p : Partial) (f : Frag) : hdrCost p.header ≤ hdrCost (p.add f).header := by
  rw [add_header]; split <;> simp_all [hdrCost]


/-- A fragment that passes every check leaves a packet that keeps the
invariant. -/
theorem add_ok {p : Partial} {f : Frag} (hp : PartialOk p) (hd : p.dead = false)
    (hb : ¬ f.bad) (hlim : f.stop ≤ MAX_LEN) (hl : lengthOk p f = true) (ho : overlapOk p f = true) :
    PartialOk ((p.setLen f).add f) := by
  have hf : f.data ≠ [] := fun h => hb (Or.inr h)
  have h8 : f.more = true → f.data.length % 8 = 0 := fun hm => by
    simp only [Frag.bad, not_or, not_and, Decidable.not_not] at hb; exact hb.1 hm
  have ha := (overlapOk_iff hp.sorted hp.nonempty hf).mp ho
  have hfs : f.offset < f.stop := by
    have : f.data.length ≠ 0 := by simpa using hf
    simp [Frag.stop]; omega
  have hpst : f.piece.stop = f.stop := rfl
  have hpo : f.piece.off = f.offset := rfl
  -- the length checks, on the packet before the length is set
  have hlen : ∀ t, p.total = some t → (f.more = true → f.stop < t) ∧ (f.more = false → t = f.stop) := by
    intro t ht
    unfold lengthOk at hl
    cases hm : f.more <;> simp [hm, ht] at hl ⊢ <;> omega
  have hlast : f.more = false → ∀ r ∈ p.pieces, r.stop ≤ f.stop := by
    intro hm r hr
    unfold lengthOk at hl
    simp only [hm, Bool.false_eq_true, ite_false, Bool.and_eq_true, Bool.not_eq_true'] at hl
    cases hlb : p.pieces.getLast? with
    | none => simp at hlb; simp [hlb] at hr
    | some b =>
      have := hl.2; simp [hlb] at this
      have := stop_le_last hp.sorted hp.nonempty hlb hr; omega
  have hmem : ∀ {q}, q ∈ ((p.setLen f).add f).pieces → q = f.piece ∨ q ∈ p.pieces := fun hq => by
    simpa using mem_insertPiece.mp (by simpa using hq)
  constructor
  · simpa using sorted_insertPiece hp.sorted (fun r hr => ha r hr) hp.nonempty hf
  · intro q hq
    rcases hmem hq with rfl | hq
    · exact hf
    · exact hp.nonempty q hq
  · simp [lens_insertPiece, hp.got, Frag.piece]; omega
  · have := add_size (p.setLen f) f
    simp only [setLen_header, setLen_size, setLen_pieces] at this ⊢
    rw [add_pieces, pieceCost_insertPiece, hp.size] at *
    simp [Frag.piece] at this ⊢; omega
  · simp [hd]
  · intro t ht q hq
    rw [add_total, setLen_total] at ht
    rcases hmem hq with rfl | hq
    · rw [hpst]
      cases hm : f.more
      · simp [hm] at ht; omega
      · simp [hm] at ht; have := (hlen t ht).1 hm; omega
    · cases hm : f.more
      · simp [hm] at ht; subst ht; exact hlast hm q hq
      · simp [hm] at ht; exact hp.bound t ht q hq
  · intro q hq
    rw [add_total, setLen_total]
    rcases hmem hq with rfl | hq
    · rw [hpst]
      cases hm : f.more
      · simp [Frag.piece, hm]
      · simp only [Frag.piece, hm, ite_true]
        constructor
        · intro h; cases h
        · intro ht; have := (hlen _ ht).1 hm; omega
    · cases hm : f.more
      · -- the other pieces end elsewhere, so none of them was the last
        simp only [ite_false, Bool.false_eq_true]
        have hap := ha q hq
        have hqn := stop_pos (hp.nonempty q hq)
        have hne : q.stop ≠ f.stop := by
          simp only [Apart, hpo, hpst] at hap; omega
        have hl' := hp.last q hq
        cases ht : p.total with
        | none => simp [ht] at hl'; simp [hl', Ne.symm hne]
        | some t =>
          have := (hlen t ht).2 hm; subst this
          rw [ht] at hl'; exact hl'
      · simp only [ite_true]; exact hp.last q hq
  · intro q hq
    rcases hmem hq with rfl | hq
    · exact h8
    · exact hp.eight q hq
  · intro q hq
    rcases hmem hq with rfl | hq
    · exact hlim
    · exact hp.limit q hq

theorem admit_inv0 {s : State} {p : Partial} {f : Frag} (hs : Inv0 s)
    (hg : get? s.parts f.key = some p) (hp : PartialOk p) (hb : ¬ f.bad)
    (hlim : f.stop ≤ MAX_LEN) : Inv0 (admit s p f).1 := by
  unfold admit
  try dsimp only
  split
  · exact hs
  split
  · split
    · exact hs
    · exact (kill_inv0 _ hs).1
  · next hd hc =>
    simp only [Bool.not_eq_true] at hd
    split
    · next hok =>
      -- killed: the length set on the way is dropped with the fragments
      unfold kill
      simp only [get?_put_self, put_put]
      apply inv0_put hs (killed_ok _)
      have := oldSize_some hg
      have := partialOk_size hp
      have h2 : p.size ≤ s.size := by
        have := @oldSize_le s.parts f.key; rw [oldSize_some hg] at this; rw [hs.size]; exact this
      simp [Partial.killed]; omega
    · next hok =>
      replace hok : lengthOk p f = true ∧ overlapOk p f = true := by simpa using hok
      have hq := add_ok hp hd hb hlim hok.1 hok.2
      have hle : (p.setLen f).size ≤ ((p.setLen f).add f).size := by
        have h1 := add_size (p.setLen f) f; have h2 := hdrCost_add_le (p.setLen f) f
        simp only [setLen_header, setLen_size] at h1 h2 ⊢; omega
      have hput : Inv0 ⟨put s.parts f.key ((p.setLen f).add f),
          s.size + (((p.setLen f).add f).size - (p.setLen f).size)⟩ := by
        apply inv0_put hs hq
        have := oldSize_some hg
        simp at hle ⊢; omega
      split
      · split
        · split
          · exact (take_inv0 _ hput).1
          · exact (take_inv0 _ hput).1
        · exact hput
      · exact hput


theorem pushFragment_inv0 {s : State} (f : Frag) (now : Nat) (hs : Inv0 s) :
    Inv0 (pushFragment s f now).1 := by
  unfold pushFragment
  split
  · split
    · exact hs
    · split <;> exact hs
  split
  · exact hs
  split
  · exact (kill_inv0 _ hs).1
  · next _ hb hlim =>
    obtain ⟨h1, h2, h3⟩ := lookup_inv0 (f := f) (now := now) hs
    exact admit_inv0 h1 h2 h3 hb (Nat.not_lt.mp hlim)

/-- **The cap and the accounting** (ip.rs 675-682, 839-861). From any table
that keeps the invariant, a step leaves one that keeps it: at most
`MAX_WAITING` bytes are counted, the count is the sum of the packets'
sizes, and every packet's size is `PARTIAL_COST`, plus its first
fragment's headers, plus each piece's data and `PIECE_COST`. -/
theorem reassemble_inv {s : State} (f : Frag) (now : Nat) (hs : Inv s) :
    Inv (reassemble s f now).1 :=
  (cap_inv (pushFragment_inv0 f now (expire_inv0 now hs.1).1)).1

/-- So everything `Reassembly::check` asserts holds after every step. -/
theorem reassemble_check {s : State} (f : Frag) (now : Nat) (hs : Inv s) :
    Check (reassemble s f now).1 :=
  check_of_inv (reassemble_inv f now hs)

/-! ## Proofs: no holes (RFC 815) -/

/-- The pieces cover `[a, t)` one after another, each nonempty: the first
at `a`, each next where the one before ends, the last ending at `t`. -/
def Tiles : Nat → Nat → List Piece → Prop
  | a, t, [] => a = t
  | a, t, q :: rest => q.off = a ∧ q.data ≠ [] ∧ Tiles q.stop t rest

/-- RFC 815's test: no hole is left in `[a, t)`; every byte there is in a
piece. -/
def NoHoles (a t : Nat) (ps : List Piece) : Prop :=
  ∀ i, a ≤ i → i < t → ∃ q ∈ ps, q.off ≤ i ∧ i < q.stop

theorem lens_tiles : ∀ {ps : List Piece} {a t : Nat}, Sorted ps → (∀ q ∈ ps, q.data ≠ []) →
    (∀ q ∈ ps, a ≤ q.off ∧ q.stop ≤ t) → a ≤ t →
    lens ps ≤ t - a ∧ (lens ps = t - a ↔ Tiles a t ps)
  | [], a, t, _, _, _, hat => by simp [lens, Tiles]; omega
  | q :: rest, a, t, hs, hn, hb, hat => by
    have hs' := List.pairwise_cons.mp hs
    have hq := hb q List.mem_cons_self
    have hqn := hn q List.mem_cons_self
    have hqp := stop_pos hqn
    have ih := lens_tiles (a := q.stop) (t := t) hs'.2 (fun r hr => hn r (List.mem_cons_of_mem _ hr))
      (fun r hr => ⟨hs'.1 r hr, (hb r (List.mem_cons_of_mem _ hr)).2⟩) hq.2
    have hl : lens (q :: rest) = q.data.length + lens rest := by simp [lens]
    have hst : q.stop = q.off + q.data.length := rfl
    rw [hl]
    refine ⟨by omega, ?_⟩
    simp only [Tiles]
    constructor
    · intro h
      have h1 : q.off = a := by omega
      exact ⟨h1, hqn, ih.2.mp (by omega)⟩
    · rintro ⟨h1, -, h2⟩
      have := ih.2.mpr h2; omega

theorem tiles_noHoles : ∀ {ps : List Piece} {a t : Nat}, Tiles a t ps → NoHoles a t ps
  | [], a, t, h, i, hi, hit => by simp [Tiles] at h; omega
  | q :: rest, a, t, h, i, hi, hit => by
    obtain ⟨h1, _, h2⟩ := h
    by_cases hiq : i < q.stop
    · exact ⟨q, List.mem_cons_self, by omega, hiq⟩
    · obtain ⟨r, hr, hr'⟩ := tiles_noHoles h2 i (by omega) hit
      exact ⟨r, List.mem_cons_of_mem _ hr, hr'⟩

theorem noHoles_tiles : ∀ {ps : List Piece} {a t : Nat}, Sorted ps → (∀ q ∈ ps, q.data ≠ []) →
    (∀ q ∈ ps, a ≤ q.off ∧ q.stop ≤ t) → a ≤ t → NoHoles a t ps → Tiles a t ps
  | [], a, t, _, _, _, hat, h => by
    simp only [Tiles]
    refine Classical.byContradiction fun hne => ?_
    obtain ⟨q, hq, _⟩ := h a (Nat.le_refl _) (by omega)
    simp at hq
  | q :: rest, a, t, hs, hn, hb, hat, h => by
    have hs' := List.pairwise_cons.mp hs
    have hq := hb q List.mem_cons_self
    have hqn := hn q List.mem_cons_self
    have hqp := stop_pos hqn
    have hoff : q.off = a := by
      refine Classical.byContradiction fun hne => ?_
      obtain ⟨r, hr, hr1, hr2⟩ := h a (Nat.le_refl _) (by omega)
      rcases List.mem_cons.mp hr with rfl | hr
      · omega
      · have := hs'.1 r hr; omega
    refine ⟨hoff, hqn, noHoles_tiles hs'.2 (fun r hr => hn r (List.mem_cons_of_mem _ hr))
      (fun r hr => ⟨hs'.1 r hr, (hb r (List.mem_cons_of_mem _ hr)).2⟩) hq.2 ?_⟩
    intro i hi hit
    obtain ⟨r, hr, hr1, hr2⟩ := h i (by omega) hit
    rcases List.mem_cons.mp hr with rfl | hr
    · omega
    · exact ⟨r, hr, hr1, hr2⟩

/-- **The completion test is RFC 815's** (RFC 815 sections 3-6, RFC 8200
section 4.5). For a packet in the table with length `t`, the code's test
`have == total` holds exactly when the pieces tile `[0, t)`, and exactly when
no hole is left. The code keeps an interval map with no overlaps instead of
RFC 815's hole list; on such a map, counting bytes finds the holes. -/
theorem complete_iff_noHoles {p : Partial} {t : Nat} (hp : PartialOk p) (ht : p.total = some t) :
    (p.got = t ↔ Tiles 0 t p.pieces) ∧ (p.got = t ↔ NoHoles 0 t p.pieces) := by
  have hb : ∀ q ∈ p.pieces, 0 ≤ q.off ∧ q.stop ≤ t := fun q hq => ⟨Nat.zero_le _, hp.bound t ht q hq⟩
  have h := lens_tiles hp.sorted hp.nonempty hb (Nat.zero_le _)
  rw [hp.got]
  refine ⟨by simpa using h.2, ?_⟩
  rw [show (lens p.pieces = t) ↔ lens p.pieces = t - 0 by simp, h.2]
  exact ⟨tiles_noHoles, noHoles_tiles hp.sorted hp.nonempty hb (Nat.zero_le _)⟩

theorem tiles_ge : ∀ {ps : List Piece} {a t : Nat} {q : Piece}, Tiles a t ps → q ∈ ps → a ≤ q.off
  | [], _, _, _, _, hq => by simp at hq
  | r :: rest, a, t, q, h, hq => by
    obtain ⟨h1, h2, h3⟩ := h
    rcases List.mem_cons.mp hq with rfl | hq
    · omega
    · have := tiles_ge h3 hq; have := stop_pos h2; omega

theorem tiles_le : ∀ {ps : List Piece} {a t : Nat}, Tiles a t ps → a ≤ t
  | [], _, _, h => by simp [Tiles] at h; omega
  | r :: rest, a, t, h => by
    obtain ⟨h1, h2, h3⟩ := h
    have := tiles_le h3; have := stop_pos h2; omega

theorem tiles_stop : ∀ {ps : List Piece} {a t : Nat} {q : Piece}, Tiles a t ps → q ∈ ps → q.stop ≤ t
  | [], _, _, _, _, hq => by simp at hq
  | r :: rest, a, t, q, h, hq => by
    obtain ⟨h1, h2, h3⟩ := h
    rcases List.mem_cons.mp hq with rfl | hq
    · exact tiles_le h3
    · exact tiles_stop h3 hq

theorem tiles_lens : ∀ {ps : List Piece} {a t : Nat}, Tiles a t ps → lens ps = t - a
  | [], _, _, h => by simp [Tiles] at h; simp [lens]; omega
  | r :: rest, a, t, h => by
    obtain ⟨h1, h2, h3⟩ := h
    have ih := tiles_lens h3
    have hle := tiles_le h3
    have hl : lens (r :: rest) = r.data.length + lens rest := by simp [lens]
    rw [hl, ih]; simp only [Piece.stop] at hle ⊢; omega

/-- Each byte of the data is the byte of the one piece that covers it. -/
theorem tiles_byte : ∀ {ps : List Piece} {a t : Nat} {q : Piece} {i : Nat}, Tiles a t ps →
    q ∈ ps → i < q.data.length → (ps.map (·.data)).flatten[q.off - a + i]? = q.data[i]?
  | [], _, _, _, _, _, hq, _ => by simp at hq
  | r :: rest, a, t, q, i, h, hq, hi => by
    obtain ⟨h1, h2, h3⟩ := h
    simp only [List.map_cons, List.flatten_cons]
    by_cases hqr : q = r
    · subst hqr
      rw [List.getElem?_append_left (by omega)]
      congr 1; omega
    · have hq' : q ∈ rest := by
        rcases List.mem_cons.mp hq with h | h
        · exact absurd h hqr
        · exact h
      have hge := tiles_ge h3 hq'
      rw [List.getElem?_append_right (by simp [Piece.stop] at hge; omega)]
      have := tiles_byte h3 hq' hi
      rw [← this]; congr 1; simp [Piece.stop] at hge ⊢; omega

/-! ## Proofs: soundness -/

/-- Every piece and first-fragment header in the table came from a
fragment in `hist` with the packet's key. -/
def Hist (hist : List Frag) (s : State) : Prop :=
  ∀ e ∈ s.parts, (∀ q ∈ e.2.pieces, ∃ g ∈ hist, g.key = e.1 ∧ g.piece = q) ∧
    (∀ h, e.2.header = some h → ∃ g ∈ hist, g.key = e.1 ∧ g.header = some h)

theorem hist_mono {hist : List Frag} {f : Frag} {s : State} (h : Hist hist s) : Hist (f :: hist) s :=
  fun e he => ⟨fun q hq => let ⟨g, hg, h'⟩ := (h e he).1 q hq; ⟨g, List.mem_cons_of_mem _ hg, h'⟩,
    fun x hx => let ⟨g, hg, h'⟩ := (h e he).2 x hx; ⟨g, List.mem_cons_of_mem _ hg, h'⟩⟩

theorem hist_put {hist : List Frag} {s : State} {k : Key} {p : Partial} {sz : Nat} (h : Hist hist s)
    (hp : (∀ q ∈ p.pieces, ∃ g ∈ hist, g.key = k ∧ g.piece = q) ∧
      (∀ x, p.header = some x → ∃ g ∈ hist, g.key = k ∧ g.header = some x)) :
    Hist hist ⟨put s.parts k p, sz⟩ := by
  intro e he
  rcases mem_put he with rfl | he
  · exact hp
  · exact h e he

theorem hist_sub {hist : List Frag} {s : State} {ps : List (Key × Partial)} {sz : Nat}
    (h : Hist hist s) (hsub : ∀ e ∈ ps, e ∈ s.parts) : Hist hist ⟨ps, sz⟩ :=
  fun e he => h e (hsub e he)

theorem hist_kill {hist : List Frag} {s : State} (k : Key) (h : Hist hist s) : Hist hist (kill s k) := by
  unfold kill; split
  · exact h
  · exact hist_put h ⟨by simp [Partial.killed], by simp [Partial.killed]⟩

theorem hist_take {hist : List Frag} {s : State} (k : Key) (h : Hist hist s) : Hist hist (take s k) := by
  unfold take; split
  · exact h
  · exact hist_sub h (fun e he => mem_del he)

theorem hist_capLoop {hist : List Frag} : ∀ (n : Nat) {s : State}, Hist hist s → Hist hist (capLoop n s)
  | 0, _, h => h
  | n + 1, s, h => by
    unfold capLoop
    split
    · split
      · exact h
      · exact hist_capLoop n (hist_take _ h)
    · exact h

theorem hist_lookup {hist : List Frag} {s : State} {f : Frag} {now : Nat} (h : Hist hist s) :
    Hist hist (lookup s f now).1 ∧
    (∀ q ∈ (lookup s f now).2.pieces, ∃ g ∈ hist, g.key = f.key ∧ g.piece = q) ∧
    (∀ x, (lookup s f now).2.header = some x → ∃ g ∈ hist, g.key = f.key ∧ g.header = some x) := by
  unfold lookup
  split
  · next p hp => exact ⟨h, (h _ (get?_mem hp)).1, (h _ (get?_mem hp)).2⟩
  · exact ⟨hist_put h ⟨by simp [fresh], by simp [fresh]⟩, by simp [fresh], by simp [fresh]⟩

theorem hist_add {hist : List Frag} {p : Partial} {f : Frag}
    (hp : (∀ q ∈ p.pieces, ∃ g ∈ hist, g.key = f.key ∧ g.piece = q) ∧
      (∀ x, p.header = some x → ∃ g ∈ hist, g.key = f.key ∧ g.header = some x)) :
    (∀ q ∈ ((p.setLen f).add f).pieces,
        ∃ g ∈ f :: hist, g.key = f.key ∧ g.piece = q) ∧
      (∀ x, ((p.setLen f).add f).header = some x →
        ∃ g ∈ f :: hist, g.key = f.key ∧ g.header = some x) := by
  constructor
  · intro q hq
    rw [add_pieces, setLen_pieces] at hq
    rcases mem_insertPiece.mp hq with rfl | hq
    · exact ⟨f, List.mem_cons_self, rfl, rfl⟩
    · obtain ⟨g, hg, h'⟩ := hp.1 q hq; exact ⟨g, List.mem_cons_of_mem _ hg, h'⟩
  · intro x hx
    rw [add_header, setLen_header] at hx
    split at hx
    · exact ⟨f, List.mem_cons_self, rfl, hx⟩
    · obtain ⟨g, hg, h'⟩ := hp.2 x hx; exact ⟨g, List.mem_cons_of_mem _ hg, h'⟩


theorem hist_admit {hist : List Frag} {s : State} {p : Partial} {f : Frag} (h : Hist hist s)
    (hp : (∀ q ∈ p.pieces, ∃ g ∈ hist, g.key = f.key ∧ g.piece = q) ∧
      (∀ x, p.header = some x → ∃ g ∈ hist, g.key = f.key ∧ g.header = some x)) :
    Hist (f :: hist) (admit s p f).1 := by
  have h' := hist_mono (f := f) h
  unfold admit
  try dsimp only
  split
  · exact h'
  split
  · split
    · exact h'
    · exact hist_kill _ h'
  split
  · unfold kill; simp only [get?_put_self, put_put]
    exact hist_put h' ⟨by simp [Partial.killed], by simp [Partial.killed]⟩
  · have hput := hist_put (sz := s.size + (((p.setLen f).add f).size -
        (p.setLen f).size)) h' (hist_add hp)
    split
    · split
      · split
        · exact hist_take _ hput
        · exact hist_take _ hput
      · exact hput
    · exact hput

theorem hist_pushFragment {hist : List Frag} {s : State} (f : Frag) (now : Nat) (h : Hist hist s) :
    Hist (f :: hist) (pushFragment s f now).1 := by
  have h' := hist_mono (f := f) h
  unfold pushFragment
  split
  · split
    · exact h'
    · split <;> exact h'
  split
  · exact h'
  split
  · exact hist_kill _ h'
  · obtain ⟨h1, h2, h3⟩ := hist_lookup (f := f) (now := now) h
    exact hist_admit h1 ⟨h2, h3⟩

theorem hist_expire {hist : List Frag} {s : State} (now : Nat) (h : Hist hist s) :
    Hist hist (expire s now) :=
  hist_sub h (fun e he => mem_of_mem_filter' he)

/-- `Hist` holds of the fragments taken so far after every step. -/
theorem hist_reassemble {hist : List Frag} {s : State} (f : Frag) (now : Nat) (h : Hist hist s) :
    Hist (f :: hist) (reassemble s f now).1 :=
  hist_capLoop _ (hist_pushFragment f now (hist_expire now h))

theorem finish_flatten {h : List Nat} {ds ds' : List (List Nat)} {t : Nat}
    (e : ds.flatten = ds'.flatten) : finish h ds t = finish h ds' t := by
  simp [finish, e]

theorem length_setWord (h : List Nat) (i v : Nat) : (setWord h i v).length = h.length := by
  simp [setWord]

theorem finish_shape {h : List Nat} {ds : List (List Nat)} {t : Nat} {w : List Nat}
    (e : finish h ds t = some w) : ∃ h', h'.length = h.length ∧ w = h' ++ ds.flatten := by
  unfold finish at e
  split at e
  · simp at e
  · split at e
    · injection e with e; subst e
      exact ⟨_, by simp [setHeaderChecksum, length_setWord], rfl⟩
    · injection e with e; subst e
      exact ⟨_, length_setWord _ _ _, rfl⟩

/-- What a whole packet is made of: the first fragment's headers `h`, and
pieces `ps` from fragments taken for its key that tile `[0, t)`, the one
ending at `t` with "more fragments" clear and every other with it set;
each data byte is the byte of the piece that covers it. -/
def BuiltFrom (hist : List Frag) (k : Key) (w : List Nat) : Prop :=
  ∃ h ps t, (∃ g ∈ hist, g.key = k ∧ g.header = some h) ∧
    (∀ q ∈ ps, ∃ g ∈ hist, g.key = k ∧ g.piece = q) ∧
    Tiles 0 t ps ∧ (∀ q ∈ ps, q.more = false ↔ q.stop = t) ∧
    finish h (ps.map (·.data)) t = some w ∧
    ∀ q ∈ ps, ∀ i < q.data.length, w[h.length + q.off + i]? = q.data[i]?

theorem builtFrom_of {hist : List Frag} {k : Key} {w h : List Nat} {ps : List Piece} {t : Nat}
    (hh : ∃ g ∈ hist, g.key = k ∧ g.header = some h)
    (hq : ∀ q ∈ ps, ∃ g ∈ hist, g.key = k ∧ g.piece = q) (ht : Tiles 0 t ps)
    (hm : ∀ q ∈ ps, q.more = false ↔ q.stop = t) (hw : finish h (ps.map (·.data)) t = some w) :
    BuiltFrom hist k w := by
  refine ⟨h, ps, t, hh, hq, ht, hm, hw, fun q hq i hi => ?_⟩
  obtain ⟨h', hl, rfl⟩ := finish_shape hw
  rw [List.getElem?_append_right (by omega)]
  have := tiles_byte ht hq hi
  simp at this
  rw [← this]; congr 1; omega

/-- **Soundness** (RFC 791 section 3.2, RFC 815, RFC 8200 section 4.5). In
a table that keeps the invariant and whose pieces came from `hist`, every
whole packet a step hands out is built from the first fragment's headers
and fragments taken for its key, `hist` and this one, that do not overlap
and cover `[0, total)` exactly, with the last one's "more fragments" flag
clear and every other's set, each byte from the one fragment covering it. -/
theorem reassemble_sound {hist : List Frag} {s : State} {f : Frag} {now : Nat} {w : List Nat}
    (hs : Inv s) (hh : Hist hist s) (hw : (reassemble s f now).2 = .whole w) :
    BuiltFrom (f :: hist) f.key w := by
  simp only [reassemble] at hw
  have hs1 := (expire_inv0 now hs.1).1
  have hh1 := hist_expire now hh
  generalize expire s now = s1 at hs1 hh1 hw
  unfold pushFragment at hw
  split at hw
  · -- one fragment: the whole packet
    next hat =>
    split at hw
    · simp at hw
    · next x hx =>
      split at hw
      · next b hb =>
        simp at hw; subst hw
        obtain ⟨ho, hm⟩ := hat
        by_cases hd : f.data = []
        · refine builtFrom_of (ps := []) (t := f.data.length) ⟨f, List.mem_cons_self, rfl, hx⟩
            (by simp) (by simp [Tiles, hd]) (by simp) ?_
          rw [finish_flatten (ds' := [f.data]) (by simp [hd])]; exact hb
        · refine builtFrom_of (ps := [f.piece]) (t := f.data.length) ⟨f, List.mem_cons_self, rfl, hx⟩
            (by simp) ?_ ?_ (by simpa [Frag.piece] using hb)
          · simp [Tiles, Frag.piece, ho, hd, Piece.stop]
          · simp [Frag.piece, hm, Piece.stop, ho]
      · simp at hw
  split at hw
  · simp at hw
  split at hw
  · simp at hw
  · next hna hb hlim =>
    obtain ⟨hl1, hl2, hl3⟩ := lookup_inv0 (f := f) (now := now) hs1
    obtain ⟨-, hq2, hq3⟩ := hist_lookup (f := f) (now := now) hh1
    generalize lookup s1 f now = l at hl1 hl2 hl3 hq2 hq3 hw
    obtain ⟨s2, p⟩ := l
    simp only at hl1 hl2 hl3 hq2 hq3 hw
    unfold admit at hw
    try dsimp only at hw
    split at hw
    · simp at hw
    split at hw
    · split at hw <;> simp at hw
    split at hw
    · simp at hw
    · next hd _ hok =>
      replace hok : lengthOk p f = true ∧ overlapOk p f = true := by simpa using hok
      replace hd : p.dead = false := by simpa using hd
      have hok' := add_ok hl3 hd hb (Nat.not_lt.mp hlim) hok.1 hok.2
      have hha := hist_add ⟨hq2, hq3⟩
      generalize ((p.setLen f).add f) = q at hok' hha hw
      split at hw
      · next h hqh =>
        split at hw
        · next htot =>
          split at hw
          · next b hfin =>
            simp at hw; subst hw
            have ht := (complete_iff_noHoles hok' htot).1.mp rfl
            refine builtFrom_of (hha.2 h hqh) hha.1 ht ?_ hfin
            intro r hr; rw [hok'.last r hr, htot, Option.some.injEq]; exact eq_comm
          · simp at hw
        · simp at hw
      · simp at hw

/-! ## Proofs: the overlap rule and the limits -/

theorem get?_expire_keep {s : State} {k : Key} {p : Partial} {now : Nat}
    (hg : get? s.parts k = some p) (h : now < p.expires) : get? (expire s now).parts k = some p :=
  get?_filter_some _ hg (by simp [h])

theorem get?_filter_gone {ps : List (Key × Partial)} {k : Key} {p : Partial}
    (c : Key × Partial → Bool) (hn : (ps.map (·.1)).Nodup) (hk : get? ps k = some p)
    (hc : c (k, p) = false) : get? (ps.filter c) k = none := by
  induction ps with
  | nil => simp [get?] at hk
  | cons e rest ih =>
    obtain ⟨k', p'⟩ := e
    simp only [List.map_cons, List.nodup_cons] at hn
    by_cases h : k' = k
    · subst h; simp [get?] at hk; subst hk
      simp only [List.filter, hc]
      -- k has no other entry
      clear ih
      induction rest with
      | nil => simp [get?]
      | cons e r ih2 =>
        obtain ⟨k'', p''⟩ := e
        simp only [List.map_cons, List.mem_cons, not_or, List.nodup_cons] at hn
        cases hc'' : c (k'', p'') <;> simp [List.filter, hc'', get?, Ne.symm hn.1.1] <;>
          first | exact ih2 ⟨hn.1.2, hn.2.2⟩ | exact ih2 ⟨hn.1.2, hn.2.2⟩
    · simp [get?, h] at hk
      cases hc' : c (k', p') <;> simp [List.filter, hc', get?, h, ih hn.2 hk]

theorem get?_expire_gone {s : State} {k : Key} {p : Partial} {now : Nat} (hs : Inv0 s)
    (hg : get? s.parts k = some p) (h : p.expires ≤ now) : get? (expire s now).parts k = none :=
  get?_filter_gone _ hs.nodup hg (by simp; omega)

theorem get?_take {s : State} {k k' : Key} {p : Partial} (hs : Inv0 s)
    (h : get? (take s k).parts k' = some p) : get? s.parts k' = some p := by
  unfold take at h
  split at h
  · exact h
  · by_cases hk : k' = k
    · subst hk; simp [get?_del_self hs.nodup] at h
    · rwa [get?_del_ne _ hk] at h

theorem get?_capLoop : ∀ (n : Nat) {s : State} {k : Key} {p : Partial}, Inv0 s →
    get? (capLoop n s).parts k = some p → get? s.parts k = some p
  | 0, _, _, _, _, h => h
  | n + 1, s, k, p, hs, h => by
    unfold capLoop at h
    split at h
    · split at h
      · exact h
      · exact get?_take hs (get?_capLoop n (take_inv0 _ hs).1 h)
    · exact h

theorem get?_cap {s : State} {k : Key} {p : Partial} (hs : Inv0 s)
    (h : get? (cap s).parts k = some p) : get? s.parts k = some p :=
  get?_capLoop _ hs h

theorem sorted_apart : ∀ {ps : List Piece} {q r : Piece}, Sorted ps → (∀ x ∈ ps, x.data ≠ []) →
    q ∈ ps → r ∈ ps → q ≠ r → Apart q r
  | [], _, _, _, _, hq, _, _ => by simp at hq
  | x :: rest, q, r, hs, hn, hq, hr, hne => by
    have hs' := List.pairwise_cons.mp hs
    rcases List.mem_cons.mp hq with h1 | h1 <;> rcases List.mem_cons.mp hr with h2 | h2
    · exact absurd (h1.trans h2.symm) hne
    · subst h1; exact Or.inr (hs'.1 r h2)
    · subst h2; exact Or.inl (hs'.1 q h1)
    · exact sorted_apart hs'.2 (fun y hy => hn y (List.mem_cons_of_mem _ hy)) h1 h2 hne

theorem pred?_self {ps : List Piece} {q : Piece} (hs : Sorted ps) (hn : ∀ x ∈ ps, x.data ≠ [])
    (hq : q ∈ ps) : pred? ps q.off = some q := by
  have hmem : q ∈ ps.filter (fun r => decide (r.off ≤ q.off)) := by simp [hq]
  unfold pred?
  cases hb : (ps.filter (fun r => decide (r.off ≤ q.off))).getLast? with
  | none =>
    rw [List.getLast?_eq_none_iff] at hb; rw [hb] at hmem; simp at hmem
  | some b =>
    have hbm := mem_of_getLast? hb
    simp at hbm
    rcases pairwise_getLast? (hs.filter _) hb hmem with rfl | h
    · rfl
    · have := stop_pos (hn q hq); omega

theorem kill_get {s : State} {k : Key} {p' : Partial} (h : get? (kill s k).parts k = some p') :
    p'.dead = true ∧ ∃ p, get? s.parts k = some p ∧ p'.expires = p.expires := by
  unfold kill at h
  split at h
  · next hn => simp [hn] at h
  · next p hp => simp [get?_put_self] at h; subst h; exact ⟨rfl, p, hp, rfl⟩

/-- Whatever `admit` leaves at the fragment's key keeps the packet's
deadline, and is dead when the fragment was discarded. -/
theorem admit_get {s : State} {p : Partial} {f : Frag} (hs : Inv0 s)
    (hg : get? s.parts f.key = some p) {p' : Partial}
    (h : get? (admit s p f).1.parts f.key = some p') :
    p'.expires = p.expires ∧ ((admit s p f).2 = .discarded → p'.dead = true) := by
  revert h
  unfold admit
  try dsimp only
  split
  · next hd => intro h; rw [hg] at h; cases h; exact ⟨rfl, fun _ => hd⟩
  split
  · split
    · intro h; rw [hg] at h; cases h; exact ⟨rfl, fun h => by simp at h⟩
    · intro h
      obtain ⟨hd, q, hq, he⟩ := kill_get h
      rw [hg] at hq; cases hq; exact ⟨he, fun _ => hd⟩
  split
  · intro h
    obtain ⟨hd, q, hq, he⟩ := kill_get h
    rw [get?_put_self] at hq; cases hq
    refine ⟨?_, fun _ => hd⟩
    rw [he]; simp
  · have hn : ((put s.parts f.key ((p.setLen f).add f)).map
        (·.1)).Nodup := nodup_put _ _ hs.nodup
    split
    · split
      · split
        · intro h; simp [take, get?_put_self, get?_del_self hn] at h
        · intro h; simp [take, get?_put_self, get?_del_self hn] at h
      · intro h; simp only [get?_put_self, Option.some.injEq] at h; subst h
        refine ⟨by simp, fun h => by simp at h⟩
    · intro h; simp only [get?_put_self, Option.some.injEq] at h; subst h
      refine ⟨by simp, fun h => by simp at h⟩

theorem reassemble_admit {s : State} {f : Frag} {now : Nat} {p : Partial}
    (hg : get? (expire s now).parts f.key = some p) (hna : ¬ f.atomic) (hnb : ¬ f.bad)
    (hlim : f.stop ≤ MAX_LEN) :
    reassemble s f now = (cap (admit (expire s now) p f).1, (admit (expire s now) p f).2) := by
  simp [reassemble, pushFragment, hna, hnb, Nat.not_lt.mpr hlim, lookup, hg]

/-- What a fragment that `admit` discards leaves at its key, after the
cap: nothing, or the dead packet with its deadline. -/
theorem discarded_dead {s : State} {f : Frag} {now : Nat} {p : Partial} (hs : Inv s)
    (hg : get? (expire s now).parts f.key = some p) (hna : ¬ f.atomic) (hnb : ¬ f.bad)
    (hlim : f.stop ≤ MAX_LEN) (hd : (admit (expire s now) p f).2 = .discarded) :
    (reassemble s f now).2 = .discarded ∧ ∀ p', get? (reassemble s f now).1.parts f.key = some p' →
      p'.dead = true ∧ p'.expires = p.expires := by
  have hs1 := (expire_inv0 now hs.1).1
  rw [reassemble_admit hg hna hnb hlim]
  refine ⟨hd, fun p' h => ?_⟩
  have h' := get?_cap (admit_inv0 hs1 hg (ok_of_get hs1 hg) hnb hlim) h
  have := admit_get hs1 hg h'
  exact ⟨this.2 hd, this.1⟩

theorem isCopy_iff {p : Partial} {f : Frag} :
    isCopy p f = true ↔ ∃ r, pred? p.pieces f.offset = some r ∧ r.off = f.offset ∧ r.data = f.data := by
  unfold isCopy
  cases pred? p.pieces f.offset <;> simp

/-- **Overlaps kill the packet** (RFC 5722 section 4, RFC 8200 section 4.5,
and RFC 8900 section 3.5's advice for IPv4). A fragment that overlaps a
waiting one of its packet and is not an exact copy of it (the same offset,
the same bytes and the same "more fragments" flag) is discarded, and with
it the packet: what stays at the key is dead, until its deadline. -/
theorem overlap_kills {s : State} {f : Frag} {now : Nat} {p : Partial} {q : Piece} (hs : Inv s) (hg : get? s.parts f.key = some p)
    (hd : p.dead = false) (hexp : now < p.expires) (hna : ¬ f.atomic) (hnb : ¬ f.bad)
    (hlim : f.stop ≤ MAX_LEN) (hq : q ∈ p.pieces) (hov : ¬ Apart f.piece q) (hne : q ≠ f.piece) :
    (reassemble s f now).2 = .discarded ∧ ∀ p', get? (reassemble s f now).1.parts f.key = some p' →
      p'.dead = true ∧ p'.expires = p.expires := by
  have hp := ok_of_get hs.1 hg
  have hg1 := get?_expire_keep hg hexp
  apply discarded_dead hs hg1 hna hnb hlim
  have hf : f.data ≠ [] := fun h => hnb (Or.inr h)
  unfold admit
  try dsimp only
  rw [if_neg (by simp [hd])]
  split
  · next hc =>
    obtain ⟨r, hr, hro, hrd⟩ := isCopy_iff.mp hc
    have hrm : r ∈ p.pieces := mem_of_mem_filter' (mem_of_getLast? hr)
    -- the copy is the piece the fragment overlaps
    have hrq : r = q := by
      refine Classical.byContradiction fun hrq => ?_
      have := sorted_apart hp.sorted hp.nonempty hrm hq hrq
      apply hov
      simp [Apart, Frag.piece, Piece.stop] at this ⊢
      rw [← hro, ← hrd]; omega
    subst hrq
    have hrs : r.stop = f.stop := by simp [Piece.stop, Frag.stop, hro, hrd]
    have hl := hp.last r hrm
    rw [hrs] at hl
    have hm : r.more ≠ f.more := fun h => hne (by cases r; simp [Frag.piece] at *; simp_all)
    rw [if_neg]
    cases hrm' : r.more <;> cases hfm : f.more <;> simp_all
  · skip
    have : overlapOk p f = false := by
      refine Classical.byContradiction fun h => ?_
      simp only [Bool.not_eq_false] at h
      exact hov (by
        have := (overlapOk_iff hp.sorted hp.nonempty hf).mp h q hq
        simp [Apart] at this ⊢; omega)
    simp [this]

/-- **Exact copies are ignored** (RFC 8200 section 4.5 leaves duplicates
to the receiver; RFC 5722 kills only overlaps). A copy of a waiting
fragment, with the same offset, bytes and "more fragments" flag, changes
nothing but the expiry the step does anyway. -/
theorem copy_ignored {s : State} {f : Frag} {now : Nat} {p : Partial} (hs : Inv s)
    (hg : get? s.parts f.key = some p) (hd : p.dead = false) (hexp : now < p.expires)
    (hna : ¬ f.atomic) (hq : f.piece ∈ p.pieces) :
    reassemble s f now = (expire s now, .waiting) := by
  have hp := ok_of_get hs.1 hg
  have hg1 := get?_expire_keep hg hexp
  have hnb : ¬ f.bad := by
    intro hb
    rcases hb with ⟨hm, h8⟩ | hb
    · exact h8 (hp.eight _ hq hm)
    · exact hp.nonempty _ hq hb
  have hlim : f.stop ≤ MAX_LEN := hp.limit _ hq
  rw [reassemble_admit hg1 hna hnb hlim]
  have he := expire_inv0 now hs.1
  have hc : isCopy p f = true := by
    rw [isCopy_iff]; exact ⟨f.piece, pred?_self hp.sorted hp.nonempty hq, rfl, rfl⟩
  have hl := hp.last _ hq
  simp only [Frag.piece, Piece.stop] at hl
  have hw : (decide (p.total = some f.stop) != f.more) = true := by
    cases hm : f.more <;> simp_all [Frag.stop]
  simp only [admit, hd, hc, hw, ite_true, Bool.false_eq_true, ite_false]
  rw [cap_id (Nat.le_trans he.2 hs.2)]

/-- **A last fragment that disagrees on the length kills the packet**
(RFC 8200 section 4.5; RFC 791 takes the length from the last fragment). -/
theorem length_disagreement_kills {s : State} {f : Frag} {now : Nat} {p : Partial} {t : Nat}
    (hs : Inv s) (hg : get? s.parts f.key = some p) (hd : p.dead = false) (hexp : now < p.expires)
    (ht : p.total = some t) (hm : f.more = false) (hstop : f.stop ≠ t) (hna : ¬ f.atomic)
    (hnb : ¬ f.bad) (hlim : f.stop ≤ MAX_LEN) :
    (reassemble s f now).2 = .discarded ∧ ∀ p', get? (reassemble s f now).1.parts f.key = some p' →
      p'.dead = true ∧ p'.expires = p.expires := by
  have hp := ok_of_get hs.1 hg
  have hg1 := get?_expire_keep hg hexp
  apply discarded_dead hs hg1 hna hnb hlim
  unfold admit
  try dsimp only
  rw [if_neg (by simp [hd])]
  split
  · rw [if_neg]; simp [ht, hm, Ne.symm hstop]
  · simp [lengthOk, hm, ht, Ne.symm hstop]

/-- **A dead packet stays dead** (RFC 5722 section 4: the fragments that
come after are discarded too). Until its deadline, every fragment of a
dropped packet but a one-fragment packet is discarded, and the key holds
nothing, or the dead packet with the same deadline. -/
theorem dead_stays_dead {s : State} {f : Frag} {now : Nat} {p : Partial} (hs : Inv s)
    (hg : get? s.parts f.key = some p) (hd : p.dead = true) (hexp : now < p.expires)
    (hna : ¬ f.atomic) :
    (reassemble s f now).2 = .discarded ∧ ∀ p', get? (reassemble s f now).1.parts f.key = some p' →
      p'.dead = true ∧ p'.expires = p.expires := by
  have hg1 := get?_expire_keep hg hexp
  have he := expire_inv0 now hs.1
  by_cases hnb : f.bad
  · simp only [reassemble, pushFragment, hna, hnb, ite_true, ite_false]
    refine ⟨by simp, fun p' h => ?_⟩
    rw [cap_id (Nat.le_trans he.2 hs.2), hg1] at h; cases h; exact ⟨hd, rfl⟩
  by_cases hlim : MAX_LEN < f.stop
  · simp only [reassemble, pushFragment, hna, hnb, hlim, ite_true, ite_false]
    refine ⟨by simp, fun p' h => ?_⟩
    obtain ⟨hd', q, hq, hqe⟩ := kill_get (get?_cap (kill_inv0 _ he.1).1 h)
    rw [hg1] at hq; cases hq; exact ⟨hd', hqe⟩
  · apply discarded_dead hs hg1 hna hnb (Nat.not_lt.mp hlim)
    simp [admit, hd]

/-- **A fragment ending past 65,535 bytes is discarded** (RFC 8200 section
4.5; RFC 791's 13-bit offset and 16-bit length). A packet waiting at its
key is killed; with none waiting, nothing is kept. -/
theorem too_long_discarded {s : State} {f : Frag} {now : Nat} (hs : Inv s) (hna : ¬ f.atomic)
    (hnb : ¬ f.bad) (hlim : MAX_LEN < f.stop) :
    (reassemble s f now).2 = .discarded ∧
    (∀ p', get? (reassemble s f now).1.parts f.key = some p' → p'.dead = true) ∧
    (get? (expire s now).parts f.key = none → get? (reassemble s f now).1.parts f.key = none) := by
  have he := expire_inv0 now hs.1
  simp only [reassemble, pushFragment, hna, hnb, hlim, ite_true, ite_false]
  refine ⟨by simp, fun p' h => (kill_get (get?_cap (kill_inv0 _ he.1).1 h)).1, fun hn => ?_⟩
  cases h : get? (cap (kill (expire s now) f.key)).parts f.key with
  | none => rfl
  | some p' =>
    obtain ⟨-, q, hq, -⟩ := kill_get (get?_cap (kill_inv0 _ he.1).1 h)
    rw [hn] at hq; cases hq

/-- `finish` refuses exactly a length its field cannot say: an IPv4 total
length or an IPv6 payload length over 65,535 (RFC 791 section 3.1, RFC
8200 section 3). -/
theorem finish_none_iff (h : List Nat) (ds : List (List Nat)) (t : Nat) :
    finish h ds t = none ↔ MAX_LEN < lenField h t := by
  unfold finish
  split
  · simp_all
  · split <;> simp_all

/-- **One-fragment packets pass alone** (RFC 6946 section 4: an atomic
fragment is handed up whatever else waits for its key). -/
theorem atomic_alone {s : State} {f : Frag} {now : Nat} {h : List Nat} (hs : Inv s)
    (ha : f.atomic) (hh : f.header = some h) :
    reassemble s f now = (expire s now,
      match finish h [f.data] f.data.length with
      | some b => .whole b
      | none => .discarded) := by
  have he := expire_inv0 now hs.1
  simp only [reassemble, pushFragment, ha, ite_true, hh]
  have hc := cap_id (Nat.le_trans he.2 hs.2)
  cases finish h [f.data] f.data.length <;> simp [hc]

/-- **Bad fragments are discarded** and change nothing (RFC 8200 section
4.5: a non-last fragment whose length is not a multiple of 8; and a
fragment with no data). -/
theorem bad_discarded {s : State} {f : Frag} {now : Nat} (hs : Inv s) (hna : ¬ f.atomic)
    (hb : f.bad) : reassemble s f now = (expire s now, .discarded) := by
  have he := expire_inv0 now hs.1
  simp only [reassemble, pushFragment, hna, hb, ite_true, ite_false]
  rw [cap_id (Nat.le_trans he.2 hs.2)]

/-- **The deadline is the first fragment's arrival plus the timeout**
(RFC 8200 section 4.5: 60 seconds from the first-arriving fragment). A
packet a fragment starts has its deadline set then, and keeps it. -/
theorem first_fragment_deadline {s : State} {f : Frag} {now : Nat} (hs : Inv s)
    (hn : get? (expire s now).parts f.key = none) (hna : ¬ f.atomic) (hnb : ¬ f.bad)
    (hlim : f.stop ≤ MAX_LEN) :
    ∀ p', get? (reassemble s f now).1.parts f.key = some p' → p'.expires = now + f.timeout := by
  intro p' h
  have he := expire_inv0 now hs.1
  have hl := lookup_inv0 (f := f) (now := now) he.1
  simp only [reassemble, pushFragment, hna, hnb, Nat.not_lt.mpr hlim, ite_false] at h
  have h' := get?_cap (admit_inv0 hl.1 hl.2.1 hl.2.2 hnb hlim) h
  have := (admit_get hl.1 hl.2.1 h').1
  rw [this]; simp [lookup, hn, fresh]

/-- A fragment that starts a packet completes it only if it is the whole
packet in one fragment. -/
theorem admit_fresh_whole {s : State} {e : Nat} {f : Frag} {w : List Nat}
    (hw : (admit s (fresh e) f).2 = .whole w) : f.offset = 0 ∧ f.more = false := by
  have hc : isCopy (fresh e) f = false := by simp [isCopy, fresh, pred?]
  unfold admit at hw
  try dsimp only at hw
  rw [if_neg (by simp [fresh]), if_neg (by simp [hc])] at hw
  try dsimp only at hw
  split at hw
  · simp at hw
  split at hw
  · split at hw
    · next htot =>
      rw [add_total, setLen_total, add_got, setLen_got] at htot
      cases hm : f.more
      · simp only [hm, Bool.false_eq_true, ite_false, fresh, Option.some.injEq] at htot
        simp [Frag.stop] at htot
        exact ⟨by omega, rfl⟩
      · simp [hm, fresh] at htot
    · simp at hw
  · simp at hw

/-- **A fragment at or after its packet's deadline completes nothing**
(RFC 8200 section 4.5; ip.rs 669-673, the fix for `Reassembly_lateexpiry`).
The packet is dropped before the fragment is looked at, so the fragment
starts a packet of its own, and only a one-fragment packet comes out. -/
theorem late_completes_nothing {s : State} {f : Frag} {now : Nat} {p : Partial} {w : List Nat}
    (hs : Inv s) (hg : get? s.parts f.key = some p) (hlate : p.expires ≤ now)
    (hw : (reassemble s f now).2 = .whole w) : f.atomic := by
  refine Classical.byContradiction fun hna => ?_
  have hn := get?_expire_gone hs.1 hg hlate
  simp only [reassemble] at hw
  unfold pushFragment at hw
  rw [if_neg hna] at hw
  split at hw
  · simp at hw
  split at hw
  · simp at hw
  have hl : lookup (expire s now) f now = (⟨put (expire s now).parts f.key (fresh (now + f.timeout)),
      (expire s now).size + PARTIAL_COST⟩, fresh (now + f.timeout)) := by simp [lookup, hn]
  rw [hl] at hw
  exact hna (admit_fresh_whole hw)

/-! ## Proofs: completeness -/

/-- The fragment that carries piece `q` of a packet with key `k`, first
fragment headers `h` and timeout `tmo`: the headers go with offset 0. -/
def fragOf (k : Key) (h : List Nat) (tmo : Nat) (q : Piece) : Frag :=
  ⟨k, q.off, q.more, q.data, if q.off = 0 then some h else none, tmo⟩

/-- `P` cuts a packet's `t` data bytes into fragments as RFC 791 section
3.2 and RFC 8200 section 4.5 allow: nonempty, contiguous pieces from 0 to
`t`, every one but the last with "more fragments" set and a multiple of 8
bytes long. -/
structure Cut (P : List Piece) (t : Nat) : Prop where
  tiles : Tiles 0 t P
  flags : ∀ q ∈ P, q.more = false ↔ q.stop = t
  eight : ∀ q ∈ P, q.more = true → q.data.length % 8 = 0

/-- Steps through fragments with their arrival times. -/
def runF : State → List (Frag × Nat) → State × List Out
  | s, [] => (s, [])
  | s, (f, now) :: rest =>
    let r := reassemble s f now
    let r' := runF r.1 rest
    (r'.1, r.2 :: r'.2)

theorem tiles_sorted : ∀ {ps : List Piece} {a t : Nat}, Tiles a t ps → Sorted ps
  | [], _, _, _ => List.Pairwise.nil
  | q :: rest, a, t, h => by
    obtain ⟨_, _, h3⟩ := h
    exact List.pairwise_cons.mpr ⟨fun r hr => tiles_ge h3 hr, tiles_sorted h3⟩

theorem tiles_nonempty : ∀ {ps : List Piece} {a t : Nat}, Tiles a t ps → ∀ q ∈ ps, q.data ≠ []
  | [], _, _, _, _, hq => by simp at hq
  | r :: rest, a, t, h, q, hq => by
    obtain ⟨_, h2, h3⟩ := h
    rcases List.mem_cons.mp hq with rfl | hq
    · exact h2
    · exact tiles_nonempty h3 q hq

theorem piece_eta (q : Piece) : (⟨q.off, q.data, q.more⟩ : Piece) = q := by cases q; rfl

theorem fragOf_piece (k : Key) (h : List Nat) (tmo : Nat) (q : Piece) :
    (fragOf k h tmo q).piece = q := piece_eta q

theorem lens_filter (ps : List Piece) (c : Piece → Bool) :
    lens (ps.filter c) + lens (ps.filter (fun r => !c r)) = lens ps := by
  induction ps with
  | nil => simp [lens]
  | cons x rest ih =>
    cases hc : c x <;> simp [List.filter, hc, lens] at ih ⊢ <;> omega

theorem pieceCost_filter_le (ps : List Piece) (c : Piece → Bool) :
    pieceCost (ps.filter c) ≤ pieceCost ps := by
  induction ps with
  | nil => simp [pieceCost]
  | cons x rest ih =>
    cases hc : c x <;> simp [List.filter, hc, pieceCost] at ih ⊢ <;> omega

theorem lens_pos {ps : List Piece} {r : Piece} (hr : r ∈ ps) (hn : r.data ≠ []) : 0 < lens ps := by
  induction ps with
  | nil => simp at hr
  | cons x rest ih =>
    simp only [lens, List.map_cons, List.sum_cons]
    rcases List.mem_cons.mp hr with rfl | hr
    · have : r.data.length ≠ 0 := by simpa using hn
      omega
    · have := ih hr; simp only [lens] at this; omega

theorem insertPiece_front {q : Piece} : ∀ {l : List Piece}, (∀ x ∈ l, q.off < x.off) →
    insertPiece q l = q :: l
  | [], _ => rfl
  | x :: _, h => by simp [insertPiece, h x List.mem_cons_self]

/-- Adding a piece of a cut to the pieces taken so far keeps them in the
cut's order. -/
theorem insertPiece_filter {S : List Piece} {q : Piece} : ∀ {P : List Piece}, Sorted P →
    (∀ x ∈ P, x.data ≠ []) → q ∈ P → q ∉ S →
    insertPiece q (P.filter fun r => decide (r ∈ S)) = P.filter fun r => decide (r ∈ q :: S)
  | [], _, _, hq, _ => by simp at hq
  | r :: rest, hs, hn, hq, hqS => by
    have hs' := List.pairwise_cons.mp hs
    have hr := stop_pos (hn r List.mem_cons_self)
    by_cases hrq : r = q
    · subst hrq
      have hrest : ∀ x ∈ rest, r.off < x.off := fun x hx => by have := hs'.1 x hx; omega
      have hnot : r ∉ rest := fun h => by have := hrest r h; omega
      rw [List.filter_cons_of_neg (by simpa using hqS), List.filter_cons_of_pos (by simp)]
      rw [insertPiece_front (fun x hx => hrest x (mem_of_mem_filter' hx))]
      congr 1
      apply List.filter_congr
      intro x hx
      have : x ≠ r := fun e => hnot (e ▸ hx)
      simp [this]
    · have hq' : q ∈ rest := by
        rcases List.mem_cons.mp hq with h | h
        · exact absurd h.symm hrq
        · exact h
      have hlt : ¬ q.off < r.off := by have := hs'.1 q hq'; omega
      have ih := insertPiece_filter hs'.2 (fun x hx => hn x (List.mem_cons_of_mem _ hx)) hq' hqS
      by_cases hrS : r ∈ S
      · rw [List.filter_cons_of_pos (by simpa using hrS), List.filter_cons_of_pos (by simp [hrS])]
        simp only [insertPiece, hlt, ite_false, ih]
      · rw [List.filter_cons_of_neg (by simpa using hrS),
          List.filter_cons_of_neg (by simp [hrS, hrq])]
        exact ih

/-- The packet at the key, after some pieces `S` of the cut arrived. -/
def Shape (P : List Piece) (h : List Nat) (t e : Nat) (S : List Piece) (p : Partial) : Prop :=
  p.dead = false ∧ p.header = (if S.any (fun r => r.off == 0) then some h else none) ∧
  p.pieces = P.filter (fun r => decide (r ∈ S)) ∧
  p.total = (if S.any (fun r => !r.more) then some t else none) ∧ p.expires = e

/-- The table after the pieces `S` of the cut arrived: the packet waits in
that shape, and the table holds at most `s0` bytes besides it. -/
def Track (P : List Piece) (h : List Nat) (t e : Nat) (k : Key) (s0 : Nat) (s : State)
    (S : List Piece) : Prop :=
  Inv s ∧ (∀ x ∈ S, x ∈ P) ∧
  (S = [] → get? s.parts k = none ∧ s.size ≤ s0) ∧
  (S ≠ [] → ∃ p, get? s.parts k = some p ∧ Shape P h t e S p ∧ s.size ≤ s0 + p.size)

theorem track_lookup {P : List Piece} {h : List Nat} {t tmo t0 : Nat} {k : Key} {s0 : Nat}
    {s : State} {S : List Piece} {f : Frag} {now : Nat}
    (htr : Track P h t (t0 + tmo) k s0 s S) (hnow : now < t0 + tmo) (hfirst : S = [] → now = t0)
    (hfk : f.key = k) (hft : f.timeout = tmo) :
    Inv0 (lookup (expire s now) f now).1 ∧
    get? (lookup (expire s now) f now).1.parts k = some (lookup (expire s now) f now).2 ∧
    Shape P h t (t0 + tmo) S (lookup (expire s now) f now).2 ∧
    (lookup (expire s now) f now).1.size ≤ s0 + (lookup (expire s now) f now).2.size := by
  obtain ⟨hinv, -, hnil, hcons⟩ := htr
  have he := expire_inv0 now hinv.1
  have hl := lookup_inv0 (f := f) (now := now) he.1
  rw [hfk] at hl
  refine ⟨hl.1, hl.2.1, ?_⟩
  by_cases hS : S = []
  · subst hS
    obtain ⟨hn, hsz⟩ := hnil rfl
    have hn1 := get?_filter_none (fun e => decide (now < e.2.expires)) hn
    have : lookup (expire s now) f now = (⟨put (expire s now).parts f.key (fresh (now + f.timeout)),
        (expire s now).size + PARTIAL_COST⟩, fresh (now + f.timeout)) := by
      simp [lookup, hfk]; rw [show (expire s now).parts = s.parts.filter _ from rfl, hn1]
    rw [this]
    refine ⟨⟨rfl, by simp [fresh], by simp [fresh], by simp [fresh], by simp [fresh, hft, hfirst rfl]⟩, ?_⟩
    simp [fresh]; omega
  · obtain ⟨p, hp, hsh, hsz⟩ := hcons hS
    have hp1 := get?_expire_keep hp (by rw [hsh.2.2.2.2]; exact hnow)
    have : lookup (expire s now) f now = (expire s now, p) := by simp [lookup, hfk, hp1]
    rw [this]
    exact ⟨hsh, show (expire s now).size ≤ s0 + p.size by omega⟩

/-- One step of the completeness proof: a piece of the cut arrives before
the deadline. A piece already here is ignored; a new one joins; the last
missing one completes the packet. -/
theorem track_step {P : List Piece} {h : List Nat} {t tmo t0 : Nat} {k : Key} {s0 : Nat}
    {s : State} {S : List Piece} {q : Piece} {now : Nat}
    (hcut : Cut P t) (hlen : lenField h t ≤ MAX_LEN)
    (hbud : s0 + PARTIAL_COST + pieceCost P + h.length ≤ MAX_WAITING)
    (hmany : ∀ r ∈ P, ¬ (r.off = 0 ∧ r.more = false))
    (htr : Track P h t (t0 + tmo) k s0 s S) (hq : q ∈ P) (hnow : now < t0 + tmo)
    (hfirst : S = [] → now = t0) :
    (q ∈ S → (reassemble s (fragOf k h tmo q) now).2 = .waiting ∧
        Track P h t (t0 + tmo) k s0 (reassemble s (fragOf k h tmo q) now).1 S) ∧
    (q ∉ S → (∀ x ∈ P, x ∈ q :: S) → ∃ w, finish h (P.map (·.data)) t = some w ∧
        (reassemble s (fragOf k h tmo q) now).2 = .whole w) ∧
    (q ∉ S → ¬ (∀ x ∈ P, x ∈ q :: S) → (reassemble s (fragOf k h tmo q) now).2 = .waiting ∧
        Track P h t (t0 + tmo) k s0 (reassemble s (fragOf k h tmo q) now).1 (q :: S)) := by
  have hSP := htr.2.1
  have hsort := tiles_sorted hcut.tiles
  have hne := tiles_nonempty hcut.tiles
  have hqn := hne q hq
  have hqstop := tiles_stop hcut.tiles hq
  have htl : t ≤ MAX_LEN := by
    have : t ≤ lenField h t := by unfold lenField; split <;> omega
    omega
  -- distinct pieces of the cut are apart, and have distinct offsets and ends
  have hapart : ∀ r ∈ P, r ≠ q → Apart q r := fun r hr hrq =>
    sorted_apart hsort hne hq hr (Ne.symm hrq)
  have hoff : ∀ r ∈ P, r.off = q.off → r = q := fun r hr he => by
    refine Classical.byContradiction fun hrq => ?_
    have := hapart r hr hrq; have := stop_pos (hne r hr); have := stop_pos hqn
    simp [Apart] at *; omega
  have hlastu : ∀ r ∈ P, r.more = false → q.more = false → r = q := fun r hr hm hqm => by
    refine Classical.byContradiction fun hrq => ?_
    have h1 := (hcut.flags r hr).mp hm; have h2 := (hcut.flags q hq).mp hqm
    have := hapart r hr hrq; have := stop_pos (hne r hr); have := stop_pos hqn
    simp [Apart] at *; omega
  let f := fragOf k h tmo q
  have hfp : f.piece = q := fragOf_piece k h tmo q
  have hna : ¬ f.atomic := fun ha => hmany q hq ha
  have hnb : ¬ f.bad := by
    simp only [Frag.bad, f, fragOf, not_or, not_and]
    exact ⟨fun hm => by have := hcut.eight q hq hm; omega, hqn⟩
  have hlim : f.stop ≤ MAX_LEN := by simp [f, fragOf, Frag.stop]; simp [Piece.stop] at hqstop; omega
  obtain ⟨hl1, hl2, hsh, hsz⟩ := track_lookup (f := f) htr hnow hfirst rfl rfl
  have hred : reassemble s f now = (cap (admit (lookup (expire s now) f now).1
      (lookup (expire s now) f now).2 f).1, (admit (lookup (expire s now) f now).1
      (lookup (expire s now) f now).2 f).2) := by
    simp [reassemble, pushFragment, hna, hnb, Nat.not_lt.mpr hlim]
  show (q ∈ S → (reassemble s f now).2 = .waiting ∧ Track P h t (t0 + tmo) k s0 (reassemble s f now).1 S) ∧
    (q ∉ S → (∀ x ∈ P, x ∈ q :: S) → ∃ w, finish h (P.map (·.data)) t = some w ∧
        (reassemble s f now).2 = .whole w) ∧
    (q ∉ S → ¬ (∀ x ∈ P, x ∈ q :: S) → (reassemble s f now).2 = .waiting ∧
        Track P h t (t0 + tmo) k s0 (reassemble s f now).1 (q :: S))
  rw [hred]
  generalize lookup (expire s now) f now = l at hl1 hl2 hsh hsz
  obtain ⟨s2, p⟩ := l
  simp only at hl1 hl2 hsh hsz ⊢
  obtain ⟨hd, hh, hpc, htot, hexp⟩ := hsh
  have hpk : f.key = k := rfl
  have hpok := ok_of_get hl1 hl2
  have hcap : ∀ {x : State}, x.size ≤ MAX_WAITING → cap x = x := fun h => cap_id h
  have hpsize : p.size ≤ PARTIAL_COST + pieceCost P + h.length := by
    rw [hpok.size, hpc]
    have := pieceCost_filter_le P (fun r => decide (r ∈ S))
    have : hdrCost p.header ≤ h.length := by rw [hh]; split <;> simp [hdrCost]
    omega
  refine ⟨fun hqS => ?_, fun hqS hcov => ?_, fun hqS hcov => ?_⟩
  · -- a copy: ignored
    have hqp : q ∈ p.pieces := by rw [hpc]; simp [hq, hqS]
    have hc : isCopy p f = true := by
      rw [isCopy_iff]
      exact ⟨q, pred?_self hpok.sorted hpok.nonempty hqp, rfl, rfl⟩
    have hw : (decide (p.total = some f.stop) != f.more) = true := by
      have hl := hpok.last q hqp
      have hfs : f.stop = q.stop := rfl
      have hfm : f.more = q.more := rfl
      rw [hfs, hfm]
      cases hm : q.more
      · rw [hm] at hl; simp [hl.mp rfl]
      · rw [hm] at hl
        have : ¬ p.total = some q.stop := fun h => by have := hl.mpr h; cases this
        simp [this]
    have hadm : admit s2 p f = (s2, .waiting) := by
      simp only [admit, hd, hc, hw, ite_true, Bool.false_eq_true, ite_false]
    rw [hadm]
    simp only
    rw [hcap (by omega)]
    refine ⟨by simp, ⟨hl1, by omega⟩, hSP, fun h0 => absurd (h0 ▸ hqS) (by simp), fun _ =>
      ⟨p, hl2, ⟨hd, hh, hpc, htot, hexp⟩, hsz⟩⟩
  all_goals
    -- a new piece: it passes every check and joins
    have hnc : isCopy p f = false := by
      cases hc : isCopy p f
      · rfl
      · obtain ⟨r, hr, hro, -⟩ := isCopy_iff.mp hc
        have hrm : r ∈ p.pieces := mem_of_mem_filter' (mem_of_getLast? hr)
        rw [hpc] at hrm
        simp at hrm
        have := hoff r hrm.1 hro
        subst this; exact absurd hrm.2 hqS
    have hlok : lengthOk p f = true := by
      rw [lengthOk_eq]
      have hfs : f.stop = q.stop := rfl
      have hfm : f.more = q.more := rfl
      rw [hfs, hfm]
      refine ⟨fun hm t' ht => ?_, fun hm => ⟨fun t' ht => ?_, fun b hb => ?_⟩⟩
      · have hqt : q.stop ≠ t := fun e => by
          have := (hcut.flags q hq).mpr e; rw [hm] at this; cases this
        have h1 : t' = t := by
          rw [htot] at ht; split at ht
          · injection ht with ht; exact ht.symm
          · cases ht
        omega
      · -- the last fragment is not here yet, so no length is set
        have hnone : S.any (fun r => !r.more) = false := by
          rw [List.any_eq_false]
          intro r hr hrm
          have hrm' : r.more = false := by simpa using hrm
          exact hqS (hlastu r (hSP r hr) hrm' hm ▸ hr)
        simp [htot, hnone] at ht
      · have hbm := mem_of_getLast? hb
        rw [hpc] at hbm
        have hbP : b ∈ P := mem_of_mem_filter' hbm
        have := tiles_stop hcut.tiles hbP
        have hqt := (hcut.flags q hq).mp hm
        omega
    have hook : overlapOk p f = true := by
      rw [overlapOk_iff hpok.sorted hpok.nonempty hqn]
      intro r hr
      rw [hpc] at hr; simp at hr
      rw [hfp]
      exact hapart r hr.1 (fun e => hqS (e ▸ hr.2))
    have hq' := add_ok hpok hd hnb hlim hlok hook
    -- the new packet's shape
    have hpieces : ((p.setLen f).add f).pieces =
        P.filter (fun r => decide (r ∈ q :: S)) := by
      rw [add_pieces, setLen_pieces, hfp, hpc]
      exact insertPiece_filter hsort hne hq hqS
    have hheader : ((p.setLen f).add f).header =
        (if (q :: S).any (fun r => r.off == 0) then some h else none) := by
      have h0 : q.off = 0 → S.any (fun r => r.off == 0) = false := fun hq0 => by
        rw [List.any_eq_false]; intro r hr hr0; simp at hr0
        exact hqS (hoff r (hSP r hr) (by omega) ▸ hr)
      rw [add_header, setLen_header, hh]
      by_cases hq0 : q.off = 0
      · simp [h0 hq0, hq0, f, fragOf, List.any_cons]
      · by_cases ha : S.any (fun r => r.off == 0) = true <;> simp [ha, hq0, f, fragOf, List.any_cons]
    have htotal : ((p.setLen f).add f).total =
        (if (q :: S).any (fun r => !r.more) then some t else none) := by
      rw [add_total, setLen_total]
      have hfm : f.more = q.more := rfl
      rw [hfm]
      cases hm : q.more
      · have := (hcut.flags q hq).mp hm
        simp only [Bool.false_eq_true, ite_false, List.any_cons, hm, Bool.not_false, Bool.true_or,
          ite_true, Option.some.injEq]
        simp [Frag.stop, f, fragOf]; simp [Piece.stop] at this; omega
      · simp [htot, List.any_cons, hm]
    have hexp' : ((p.setLen f).add f).expires = t0 + tmo := by
      simp [hexp]
    have hpsz : ((p.setLen f).add f).size ≤
        PARTIAL_COST + pieceCost P + h.length := by
      rw [hq'.size, hpieces, hheader]
      have := pieceCost_filter_le P (fun r => decide (r ∈ q :: S))
      have : hdrCost (if (q :: S).any (fun r => r.off == 0) then some h else none) ≤ h.length := by
        split <;> simp [hdrCost]
      omega
    have hgrow : p.size ≤ ((p.setLen f).add f).size := by
      have h1 := add_size (p.setLen f) f; have h2 := hdrCost_add_le (p.setLen f) f
      simp only [setLen_header, setLen_size] at h1 h2 ⊢; omega
    have hpsz1 : (p.setLen f).size = p.size := by simp
  · -- the last missing piece: the whole packet
    have hall : P.filter (fun r => decide (r ∈ q :: S)) = P := by
      rw [List.filter_eq_self]; intro r hr; simpa using hcov r hr
    have hgot : ((p.setLen f).add f).got = t := by
      rw [hq'.got, hpieces, hall, tiles_lens hcut.tiles]; simp
    -- the first piece and the last piece are here
    obtain ⟨r0, hr0, hr00⟩ : ∃ r ∈ P, r.off = 0 := by
      cases hP : P with
      | nil =>
        rw [hP] at hq; simp at hq
      | cons r rest =>
        have := hcut.tiles; rw [hP] at this
        exact ⟨r, List.mem_cons_self, this.1⟩
    have hany0 : (q :: S).any (fun r => r.off == 0) = true := by
      rw [List.any_eq_true]; exact ⟨r0, hcov r0 hr0, by simp [hr00]⟩
    obtain ⟨rl, hrl, hrlm⟩ : ∃ r ∈ P, r.more = false := by
      refine Classical.byContradiction fun hno => ?_
      simp only [not_exists, not_and, Bool.not_eq_false] at hno
      -- every piece has more set: the cut cannot end at t
      have hP : P ≠ [] := fun e => by rw [e] at hq; simp at hq
      obtain ⟨b, hb⟩ : ∃ b, P.getLast? = some b := by
        cases h' : P.getLast? with
        | none => exact absurd (List.getLast?_eq_none_iff.mp h') hP
        | some b => exact ⟨b, rfl⟩
      have hbm := mem_of_getLast? hb
      have hst : b.stop = t := by
        have hl := tiles_lens hcut.tiles
        have := lens_tiles hsort hne (fun r hr => ⟨Nat.zero_le _, tiles_stop hcut.tiles hr⟩)
          (tiles_le hcut.tiles)
        -- every piece ends at or before b's end, and the pieces fill [0, t)
        have hcov' := tiles_noHoles hcut.tiles
        refine Classical.byContradiction fun hbt => ?_
        have hbt' : b.stop < t := by have := tiles_stop hcut.tiles hbm; omega
        obtain ⟨r, hr, hr1, hr2⟩ := hcov' b.stop (Nat.zero_le _) hbt'
        have := stop_le_last hsort hne hb hr
        omega
      have := (hcut.flags b hbm).mpr hst
      rw [hno b hbm] at this; simp at this
    have hanyl : (q :: S).any (fun r => !r.more) = true := by
      rw [List.any_eq_true]; exact ⟨rl, hcov rl hrl, by simp [hrlm]⟩
    have hfin : finish h (P.map (·.data)) t ≠ none := by
      rw [ne_eq, finish_none_iff]; omega
    obtain ⟨w, hw⟩ : ∃ w, finish h (P.map (·.data)) t = some w := by
      cases h' : finish h (P.map (·.data)) t with
      | none => exact absurd h' hfin
      | some w => exact ⟨w, rfl⟩
    refine ⟨w, hw, ?_⟩
    have hhs : ((p.setLen f).add f).header = some h := by
      rw [hheader, hany0]; rfl
    have hts : ((p.setLen f).add f).total = some t := by
      rw [htotal, hanyl]; rfl
    simp only [admit, hd, hnc, hlok, hook, Bool.and_self, Bool.not_true, Bool.false_eq_true,
      ite_false]
    simp only [hhs, hts, hgot, ite_true, hpieces, hall, hw]
  · -- another new piece: waiting
    have hlt : ((p.setLen f).add f).got < t := by
      rw [hq'.got, hpieces]
      obtain ⟨x, hx, hxn⟩ : ∃ x ∈ P, x ∉ q :: S := by
        refine Classical.byContradiction fun hno => ?_; simp only [not_exists, not_and, Decidable.not_not] at hno; exact hcov hno
      have hsplit := lens_filter P (fun r => decide (r ∈ q :: S))
      have hpos := lens_pos (ps := P.filter fun r => !decide (r ∈ q :: S)) (r := x)
        (by simp [hx]; simpa using hxn) (hne x hx)
      rw [tiles_lens hcut.tiles] at hsplit
      omega
    have hwait : admit s2 p f = (⟨put s2.parts f.key ((p.setLen f).add f),
        s2.size + (((p.setLen f).add f).size -
          (p.setLen f).size)⟩, .waiting) := by
      simp only [admit, hd, hnc, hlok, hook, Bool.and_self, Bool.not_true, Bool.false_eq_true,
        ite_false]
      split
      · next hx hxh =>
        rw [if_neg]
        intro ht
        rw [htotal] at ht
        split at ht
        · injection ht with ht; omega
        · cases ht
      · rfl
    rw [hwait]
    have hinv := inv0_put (sz := s2.size + (((p.setLen f).add f).size -
          (p.setLen f).size)) hl1 hq'
      (by rw [oldSize_some hl2, hpsz1]; omega)
    have hsmall : s2.size + (((p.setLen f).add f).size -
          (p.setLen f).size) ≤ MAX_WAITING := by
      rw [hpsz1]; omega
    simp only
    rw [hcap hsmall]
    refine ⟨by simp, ⟨hinv, hsmall⟩, fun x hx => ?_, fun h0 => by simp at h0, fun _ => ?_⟩
    · rcases List.mem_cons.mp hx with rfl | hx
      · exact hq
      · exact hSP x hx
    · refine ⟨_, get?_put_self _ _ _, ⟨by simp [hd], hheader, hpieces,
        htotal, hexp'⟩, ?_⟩
      rw [hpsz1]; simp only; omega

/-- Every piece of `ds` is in `P`, arrives before the deadline, and the last
one is the only arrival of its piece. -/
theorem run_track {P : List Piece} {h : List Nat} {t tmo t0 : Nat} {k : Key} {s0 : Nat}
    (hcut : Cut P t) (hlen : lenField h t ≤ MAX_LEN)
    (hbud : s0 + PARTIAL_COST + pieceCost P + h.length ≤ MAX_WAITING)
    (hmany : ∀ r ∈ P, ¬ (r.off = 0 ∧ r.more = false)) :
    ∀ (pre : List (Piece × Nat)) (q : Piece) (tq : Nat) (s : State) (S : List Piece),
      Track P h t (t0 + tmo) k s0 s S →
      (∀ d ∈ pre ++ [(q, tq)], d.1 ∈ P ∧ d.2 < t0 + tmo) →
      (S = [] → (pre ++ [(q, tq)]).head?.map (·.2) = some t0) →
      q ∉ S → (∀ d ∈ pre, d.1 ≠ q) → (∀ x ∈ P, x ∈ S ∨ ∃ d ∈ pre ++ [(q, tq)], d.1 = x) →
      ∃ w, finish h (P.map (·.data)) t = some w ∧
        (runF s ((pre ++ [(q, tq)]).map fun d => (fragOf k h tmo d.1, d.2))).2 =
          List.replicate pre.length .waiting ++ [.whole w]
  | [], q, tq, s, S, htr, hds, hfirst, hqS, _, hcov => by
    have hst := track_step (q := q) (now := tq) hcut hlen hbud hmany htr
      (hds (q, tq) (by simp)).1 (hds (q, tq) (by simp)).2 (fun h0 => by simpa using hfirst h0)
    obtain ⟨w, hw, hout⟩ := hst.2.1 hqS (fun x hx => by
      rcases hcov x hx with h' | ⟨d, hd, rfl⟩
      · exact List.mem_cons_of_mem _ h'
      · simp at hd; subst hd; exact List.mem_cons_self)
    exact ⟨w, hw, by simp [runF, hout]⟩
  | (r, tr) :: pre, q, tq, s, S, htr, hds, hfirst, hqS, hpre, hcov => by
    have hrq : r ≠ q := hpre (r, tr) List.mem_cons_self
    have hst := track_step (q := r) (now := tr) hcut hlen hbud hmany htr
      (hds (r, tr) (by simp)).1 (hds (r, tr) (by simp)).2 (fun h0 => by simpa using hfirst h0)
    have hnot : ¬ ∀ x ∈ P, x ∈ r :: S := fun hall => by
      rcases List.mem_cons.mp (hall q (hds (q, tq) (by simp)).1) with h' | h'
      · exact hrq h'.symm
      · exact hqS h'
    -- after r, the table tracks S' and the rest is the same kind of run
    obtain ⟨S', hout, htr'⟩ : ∃ S', (reassemble s (fragOf k h tmo r) tr).2 = .waiting ∧
        Track P h t (t0 + tmo) k s0 (reassemble s (fragOf k h tmo r) tr).1 S' ∧
        (∀ x, x ∈ S' ↔ x = r ∨ x ∈ S) := by
      by_cases hrS : r ∈ S
      · exact ⟨S, (hst.1 hrS).1, (hst.1 hrS).2, fun x => ⟨Or.inr, fun h' => h'.elim (· ▸ hrS) id⟩⟩
      · exact ⟨r :: S, (hst.2.2 hrS hnot).1, (hst.2.2 hrS hnot).2, fun x => by simp⟩
    obtain ⟨htr', hS'⟩ := htr'
    have hne : S' ≠ [] := fun e => by have := (hS' r).mpr (Or.inl rfl); rw [e] at this; simp at this
    obtain ⟨w, hw, hrest⟩ := run_track hcut hlen hbud hmany pre q tq _ S' htr'
      (fun d hd => hds d (List.mem_cons_of_mem _ hd)) (fun e => absurd e hne)
      (fun h' => by rcases (hS' q).mp h' with h' | h'; exact hrq h'.symm; exact hqS h')
      (fun d hd => hpre d (List.mem_cons_of_mem _ hd))
      (fun x hx => by
        rcases hcov x hx with h' | ⟨d, hd, rfl⟩
        · exact Or.inl ((hS' x).mpr (Or.inr h'))
        · rcases List.mem_cons.mp hd with rfl | hd
          · exact Or.inl ((hS' _).mpr (Or.inl rfl))
          · exact Or.inr ⟨d, hd, rfl⟩)
    refine ⟨w, hw, ?_⟩
    simp only [List.cons_append, List.map_cons, runF, hout, List.length_cons, List.replicate_succ,
      List.cons_append]
    rw [hrest]

/-- **Completeness** (RFC 791 section 3.2, RFC 8200 section 4.5). Take any
packet: key `k`, first fragment headers `h`, and data cut by `P` into `t`
bytes of fragments as the RFCs allow, with a length its header can say.
Deliver its fragments in any order, with any exact copies, every one before
the first arrival plus the timeout, into a table that keeps the invariant,
holds nothing for `k`, and has room for the whole packet under the cap.
Then every step waits until the last missing fragment arrives, and that
step hands out exactly one whole packet: `finish` of the first fragment's
headers and the data in order, which `finish_ipv4` and `finish_ipv6`
describe byte by byte. -/
theorem complete {s : State} {k : Key} {h : List Nat} {tmo t t0 : Nat} {P : List Piece}
    (pre : List (Piece × Nat)) (q : Piece) (tq : Nat)
    (hs : Inv s) (hk : get? s.parts k = none) (hcut : Cut P t) (hlen : lenField h t ≤ MAX_LEN)
    (hbud : s.size + PARTIAL_COST + pieceCost P + h.length ≤ MAX_WAITING)
    (hin : ∀ d ∈ pre ++ [(q, tq)], d.1 ∈ P)
    (hcover : ∀ x ∈ P, ∃ d ∈ pre ++ [(q, tq)], d.1 = x)
    (hlast : ∀ d ∈ pre, d.1 ≠ q)
    (ht0 : (pre ++ [(q, tq)]).head?.map (·.2) = some t0)
    (htime : ∀ d ∈ pre ++ [(q, tq)], d.2 < t0 + tmo) :
    ∃ w, finish h (P.map (·.data)) t = some w ∧
      (runF s ((pre ++ [(q, tq)]).map fun d => (fragOf k h tmo d.1, d.2))).2 =
        List.replicate pre.length .waiting ++ [.whole w] := by
  by_cases hmany : ∀ r ∈ P, ¬ (r.off = 0 ∧ r.more = false)
  · exact run_track hcut hlen hbud hmany pre q tq s [] ⟨hs, by simp, fun _ => ⟨hk, by omega⟩,
      fun h' => absurd rfl h'⟩ (fun d hd => ⟨hin d hd, htime d hd⟩) (fun _ => ht0) (by simp) hlast
      (fun x hx => Or.inr (hcover x hx))
  · -- one fragment: it is the whole packet, alone
    simp only [Classical.not_forall, Decidable.not_not] at hmany
    obtain ⟨r, hr, hr0, hrm⟩ := hmany
    have hrt := (hcut.flags r hr).mp hrm
    have hP : P = [r] := by
      have hT := hcut.tiles
      cases hP : P with
      | nil => rw [hP] at hr; simp at hr
      | cons x rest =>
        rw [hP] at hT hr
        obtain ⟨hx0, hxn, hrest⟩ := hT
        have hxr : x = r := by
          rcases List.mem_cons.mp hr with h' | h'
          · exact h'.symm
          · have := tiles_ge hrest h'; have := stop_pos hxn; omega
        subst hxr
        have : rest = [] := by
          cases rest with
          | nil => rfl
          | cons y _ =>
            have := hrest.1; have := hrest.2.1; have hle := tiles_le hrest.2.2
            have := stop_pos hrest.2.1; simp [Piece.stop] at *; omega
        rw [this]
    subst hP
    have hall : ∀ d ∈ pre ++ [(q, tq)], d.1 = r := fun d hd => by simpa using hin d hd
    have hqr : q = r := hall (q, tq) (by simp)
    have hpre : pre = [] := by
      cases pre with
      | nil => rfl
      | cons d _ => exact absurd ((hall d (by simp)).trans hqr.symm) (hlast d (by simp))
    subst hpre hqr
    have hfin : finish h [q.data] t ≠ none := by rw [ne_eq, finish_none_iff]; omega
    obtain ⟨w, hw⟩ : ∃ w, finish h [q.data] t = some w := by
      cases h' : finish h [q.data] t with
      | none => exact absurd h' hfin
      | some w => exact ⟨w, rfl⟩
    have hlen' : q.data.length = t := by simp [Piece.stop] at hrt; omega
    refine ⟨w, by simpa using hw, ?_⟩
    have ha : (fragOf k h tmo q).atomic := ⟨hr0, hrm⟩
    have hh : (fragOf k h tmo q).header = some h := by simp [fragOf, hr0]
    simp only [List.nil_append, List.map_cons, List.map_nil, runF, List.length_nil,
      List.replicate_zero]
    rw [atomic_alone hs ha hh]
    simp only [fragOf, hlen', hw]

/-- The premises of `complete` are met by real cuts: here 9 bytes in two
fragments, 8 and 1. -/
theorem cut_witness : Cut [⟨0, [1, 2, 3, 4, 5, 6, 7, 8], true⟩, ⟨8, [9], false⟩] 9 := by
  refine ⟨?_, ?_, ?_⟩ <;> simp [Tiles, Piece.stop]

/-! ## Proofs: the whole packet's headers -/

theorem addOnes_le {a b : Nat} (ha : a ≤ 65535) (hb : b ≤ 65535) : Checksum.addOnes a b ≤ 65535 := by
  unfold Checksum.addOnes; split <;> omega

theorem addOnes_mod (a b : Nat) : Checksum.addOnes a b % 65535 = (a + b) % 65535 := by
  unfold Checksum.addOnes; split <;> omega

theorem addOnes_pos {a b : Nat} (ha : 0 < a) (hb : b ≤ 65535) : 0 < Checksum.addOnes a b := by
  unfold Checksum.addOnes; split <;> omega

theorem foldl_addOnes_le : ∀ {ws : List Nat} {acc : Nat}, acc ≤ 65535 → (∀ w ∈ ws, w ≤ 65535) →
    ws.foldl Checksum.addOnes acc ≤ 65535
  | [], _, ha, _ => ha
  | w :: ws, acc, ha, hw => by
    simp only [List.foldl_cons]
    exact foldl_addOnes_le (ws := ws) (acc := Checksum.addOnes acc w)
      (addOnes_le ha (hw w List.mem_cons_self)) (fun x hx => hw x (List.mem_cons_of_mem _ hx))

theorem foldl_addOnes_mod : ∀ (ws : List Nat) (acc : Nat),
    ws.foldl Checksum.addOnes acc % 65535 = (acc + ws.sum) % 65535
  | [], acc => by simp
  | w :: ws, acc => by
    simp only [List.foldl_cons, List.sum_cons]
    rw [foldl_addOnes_mod ws]
    have := addOnes_mod acc w
    omega

theorem foldl_addOnes_pos : ∀ {ws : List Nat} {acc : Nat}, 0 < acc → (∀ w ∈ ws, w ≤ 65535) →
    0 < ws.foldl Checksum.addOnes acc
  | [], _, ha, _ => ha
  | w :: ws, acc, ha, hw => by
    simp only [List.foldl_cons]
    exact foldl_addOnes_pos (ws := ws) (acc := Checksum.addOnes acc w)
      (addOnes_pos ha (hw w List.mem_cons_self)) (fun x hx => hw x (List.mem_cons_of_mem _ hx))

theorem words_le : ∀ {b : List Nat}, (∀ x ∈ b, x < 256) → ∀ w ∈ Checksum.words b, w ≤ 65535
  | [], _, _, hw => by simp [Checksum.words] at hw
  | [a], hb, w, hw => by
    simp [Checksum.words] at hw; have := hb a (by simp); omega
  | a :: c :: rest, hb, w, hw => by
    simp only [Checksum.words, List.mem_cons] at hw
    rcases hw with rfl | hw
    · have := hb a (by simp); have := hb c (by simp); omega
    · exact words_le (fun x hx => hb x (by simp [hx])) w hw

theorem words_setWord : ∀ (i : Nat) {b : List Nat} (c : Nat), 2 * i + 1 < b.length →
    Checksum.words (setWord b (2 * i) c) = (Checksum.words b).set i (c / 256 * 256 + c % 256)
  | 0, a :: d :: rest, c, _ => by simp [setWord, Checksum.words]
  | i + 1, a :: d :: rest, c, hl => by
    have ih := words_setWord i (b := rest) c (by simp at hl; omega)
    simp only [setWord] at ih ⊢
    rw [show 2 * (i + 1) = 2 * i + 1 + 1 by omega]
    simp only [List.set_cons_succ, Checksum.words, ih]
  | _, [], _, hl => by simp at hl
  | _, [_], _, hl => by simp at hl <;> omega

theorem sum_set : ∀ (l : List Nat) (i c : Nat), i < l.length →
    (l.set i c).sum + l.getD i 0 = l.sum + c
  | [], _, _, h => by simp at h
  | x :: rest, 0, c, _ => by simp; omega
  | x :: rest, i + 1, c, h => by
    have := sum_set rest i c (by simp at h; omega)
    simp only [List.set_cons_succ, List.sum_cons, List.getD_cons_succ]; omega

theorem getD_words : ∀ (b : List Nat) (i : Nat), 2 * i + 1 < b.length →
    (Checksum.words b).getD i 0 = b.getD (2 * i) 0 * 256 + b.getD (2 * i + 1) 0
  | [], _, h => by simp at h
  | [_], _, h => by simp at h <;> omega
  | a :: d :: rest, 0, _ => by simp [Checksum.words]
  | a :: d :: rest, i + 1, h => by
    have := getD_words rest i (by simp at h; omega)
    rw [show 2 * (i + 1) = 2 * i + 1 + 1 by omega]
    simp only [Checksum.words, List.getD_cons_succ, this]

theorem length_words_gt : ∀ {b : List Nat} {i : Nat}, 2 * i + 1 < b.length → i < (Checksum.words b).length
  | [], _, h => by simp at h
  | [_], _, h => by simp at h <;> omega
  | a :: d :: rest, 0, _ => by simp [Checksum.words]
  | a :: d :: rest, i + 1, h => by
    simp only [Checksum.words, List.length_cons]
    have := length_words_gt (b := rest) (i := i) (by simp at h; omega); omega

theorem getD_set_ne (l : List Nat) {i j : Nat} (a : Nat) (h : i ≠ j) :
    (l.set i a).getD j 0 = l.getD j 0 := by
  simp [List.getD_eq_getElem?_getD, List.getElem?_set, h]

theorem mem_set_lt {l : List Nat} {i c x : Nat} (hl : ∀ y ∈ l, y < 256) (hc : c < 256)
    (hx : x ∈ l.set i c) : x < 256 := by
  rcases List.mem_or_eq_of_mem_set hx with hx | hx
  · exact hl x hx
  · omega

theorem setWord_lt {l : List Nat} {i v : Nat} (hl : ∀ y ∈ l, y < 256) (hv : v ≤ 65535) :
    ∀ x ∈ setWord l i v, x < 256 := fun x hx =>
  mem_set_lt (fun y hy => mem_set_lt hl (by omega) hy) (by omega) hx

/-- Writing the RFC 1071 checksum of a header with a zero checksum field
into the field makes the header verify: its checksum is then 0 (RFC 1071
section 1, RFC 791 section 3.1). -/
theorem checksum_setHeaderChecksum {b : List Nat} (hl : 12 ≤ b.length) (hb : ∀ x ∈ b, x < 256)
    (h0 : 0 < b.getD 0 0) : Checksum.checksum (setHeaderChecksum b) = 0 := by
  have hl0 : (setWord b 10 0).length = b.length := length_setWord _ _ _
  have hb0 : ∀ x ∈ setWord b 10 0, x < 256 := setWord_lt hb (by omega)
  have hwle := words_le hb0
  have hS : Checksum.onesSum (Checksum.words (setWord b 10 0)) ≤ 65535 :=
    foldl_addOnes_le (Nat.zero_le _) hwle
  -- the checksum field of the zeroed header is word 5, and it is 0
  have hz : (Checksum.words (setWord b 10 0)).getD 5 0 = 0 := by
    rw [getD_words _ 5 (by omega)]
    simp (disch := omega) [setWord, List.getD_eq_getElem?_getD, List.getElem?_set, show 10 < b.length by omega, show 11 < b.length by omega]
  -- word 0 is not 0: the version is there
  have hfirst : 0 < (Checksum.words (setWord b 10 0)).getD 0 0 := by
    rw [getD_words _ 0 (by omega)]
    have : (setWord b 10 0).getD 0 0 = b.getD 0 0 := by
      simp (disch := omega) [setWord, List.getD_eq_getElem?_getD, List.getElem?_set, show 10 < b.length by omega, show 11 < b.length by omega]
    simp only [Nat.mul_zero, Nat.zero_add] at this ⊢
    rw [this]; omega
  have hlen5 : 5 < (Checksum.words (setWord b 10 0)).length := length_words_gt (by omega)
  have hw : Checksum.words (setHeaderChecksum b) = (Checksum.words (setWord b 10 0)).set 5
      (65535 - Checksum.onesSum (Checksum.words (setWord b 10 0))) := by
    have := words_setWord 5 (b := setWord b 10 0)
      (65535 - Checksum.onesSum (Checksum.words (setWord b 10 0))) (by omega)
    rw [show 2 * 5 = 10 from rfl] at this
    simp only [setHeaderChecksum, Checksum.checksum]
    rw [this]; congr 1; omega
  generalize Checksum.words (setWord b 10 0) = ws at hwle hS hz hfirst hlen5 hw
  -- the sum with the checksum in place is 65535, and not 0
  have hsum := sum_set ws 5 (65535 - Checksum.onesSum ws) hlen5
  rw [hz] at hsum
  have hmod := foldl_addOnes_mod ws 0
  have hmod' := foldl_addOnes_mod (ws.set 5 (65535 - Checksum.onesSum ws)) 0
  have hle' : ∀ w ∈ ws.set 5 (65535 - Checksum.onesSum ws), w ≤ 65535 := by
    intro w hw'
    rcases List.mem_or_eq_of_mem_set hw' with hw' | hw'
    · exact hwle w hw'
    · omega
  have hle := foldl_addOnes_le (acc := 0) (by omega) hle'
  have hpos : 0 < (ws.set 5 (65535 - Checksum.onesSum ws)).foldl Checksum.addOnes 0 := by
    match ws, hfirst, hlen5, hwle with
    | w0 :: rest, hf, _, hw0 =>
      simp only [List.getD_cons_zero] at hf
      simp only [List.set_cons_succ, List.foldl_cons]
      have h0le := hw0 w0 List.mem_cons_self
      apply foldl_addOnes_pos (by unfold Checksum.addOnes; split <;> omega)
      intro x hx
      exact hle' x (by simp only [List.set_cons_succ]; exact List.mem_cons_of_mem _ hx)
  rw [Checksum.checksum, hw]
  simp only [Checksum.onesSum] at hS hsum hmod hmod' hle hpos ⊢
  simp only [Nat.zero_add] at hmod hmod'
  omega

/-- **The reassembled IPv4 header** (RFC 791 sections 3.1 and 3.2). For the
first fragment's header `h` (version 4, octets), `finish` gives `h` with
the total length rewritten to the header plus the data, "more fragments"
and the offset cleared, "don't fragment" kept, every other field as it was
but the checksum, and a checksum that verifies; the data follows. -/
theorem finish_ipv4 {h : List Nat} {ds : List (List Nat)} {t : Nat} (hv : isV4 h = true)
    (hl : 20 ≤ h.length) (hb : ∀ x ∈ h, x < 256) (hlen : h.length + t ≤ MAX_LEN) :
    ∃ h', finish h ds t = some (h' ++ ds.flatten) ∧ h'.length = h.length ∧
      h'[2]? = some ((h.length + t) / 256) ∧ h'[3]? = some ((h.length + t) % 256) ∧
      h'[6]? = some (h.getD 6 0 &&& 0x40) ∧ h'[7]? = some 0 ∧
      (∀ i, i ≠ 2 → i ≠ 3 → i ≠ 6 → i ≠ 7 → i ≠ 10 → i ≠ 11 → h'[i]? = h[i]?) ∧
      Checksum.checksum h' = 0 := by
  have hmax : h.length + t ≤ 65535 := hlen
  have hlf : lenField h t = h.length + t := by simp [lenField, hv]
  have h6 : h.getD 6 0 &&& 0x40 < 256 := by
    have : h.getD 6 0 < 256 := by
      rw [List.getD_eq_getElem?_getD]
      cases hh : h[6]? with
      | none => simp
      | some y => simp; exact hb y (List.mem_of_getElem? hh)
    exact Nat.lt_of_le_of_lt Nat.and_le_left this
  refine ⟨setHeaderChecksum (((setWord h 2 (h.length + t)).set 6 (h.getD 6 0 &&& 0x40)).set 7 0),
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · simp [finish, hlf, hv, Nat.not_lt.mpr hlen]
  · simp [setHeaderChecksum, length_setWord]
  · simp (disch := omega) [setHeaderChecksum, setWord, List.getElem?_set, show 2 < h.length by omega, show 3 < h.length by omega, show 6 < h.length by omega, show 7 < h.length by omega]
  · simp (disch := omega) [setHeaderChecksum, setWord, List.getElem?_set, show 2 < h.length by omega, show 3 < h.length by omega, show 6 < h.length by omega, show 7 < h.length by omega]
  · simp (disch := omega) [setHeaderChecksum, setWord, List.getElem?_set, show 2 < h.length by omega, show 3 < h.length by omega, show 6 < h.length by omega, show 7 < h.length by omega]
  · simp (disch := omega) [setHeaderChecksum, setWord, List.getElem?_set, show 2 < h.length by omega, show 3 < h.length by omega, show 6 < h.length by omega, show 7 < h.length by omega]
  · intro i h2 h3 h6' h7 h10 h11
    simp [setHeaderChecksum, setWord, List.getElem?_set, Ne.symm h2, Ne.symm h3, Ne.symm h6',
      Ne.symm h7, Ne.symm h10, Ne.symm h11]
  · apply checksum_setHeaderChecksum
    · simp [setWord]; omega
    · intro x hx
      exact mem_set_lt (fun y hy => mem_set_lt (setWord_lt hb hmax) h6 hy) (by omega) hx
    · rw [getD_set_ne _ _ (by decide : (7:Nat) ≠ 0), getD_set_ne _ _ (by decide : (6:Nat) ≠ 0)]
      unfold setWord
      rw [getD_set_ne _ _ (by decide : (2 + 1 : Nat) ≠ 0), getD_set_ne _ _ (by decide : (2:Nat) ≠ 0)]
      cases h with
      | nil => simp at hl
      | cons x xs =>
        simp only [isV4, List.headD_cons, beq_iff_eq] at hv
        simp only [List.getD_cons_zero]; omega

/-- **The reassembled IPv6 header** (RFC 8200 section 4.5). `finish` gives
the first fragment's headers with the payload length rewritten to the
headers after the fixed one plus the data, every other byte as it was; the
data follows. Which "next header" byte names what comes after is set by
`arrived6`: see `arrived6_names_fragment`. -/
theorem finish_ipv6 {h : List Nat} {ds : List (List Nat)} {t : Nat} (hv : isV4 h = false)
    (hlen : h.length - 40 + t ≤ MAX_LEN) :
    finish h ds t = some (setWord h 4 (h.length - 40 + t) ++ ds.flatten) ∧
      (setWord h 4 (h.length - 40 + t)).length = h.length ∧
      ∀ i, i ≠ 4 → i ≠ 5 → (setWord h 4 (h.length - 40 + t))[i]? = h[i]? := by
  have hlf : lenField h t = h.length - 40 + t := by simp [lenField, hv]
  refine ⟨by simp [finish, hlf, hv, Nat.not_lt.mpr hlen], length_setWord _ _ _, fun i h4 h5 => ?_⟩
  simp [setWord, List.getElem?_set, Ne.symm h4, Ne.symm h5]

/-- **The IPv6 first fragment's headers** (RFC 8200 section 4.5): the
headers in front of the Fragment header, with the "next header" byte that
named the Fragment header (44) now naming what the Fragment header named. -/
theorem arrived6_header {b : List Nat} {f : Frag} {hd : List Nat} (ha : arrived6 b = some f)
    (hh : f.header = some hd) :
    ∃ pos nextAt c, chain b = some c ∧ c.frag = some (pos, nextAt) ∧
      hd = (b.take pos).set nextAt (b.getD pos 0) ∧ f.offset = 0 ∧
      f.data = slice b (pos + 8) (40 + be16 b 4) := by
  unfold arrived6 at ha
  try dsimp only at ha
  split at ha
  · simp at ha
  · split at ha
    · simp at ha
    · next c hc =>
      split at ha
      · simp at ha
      · next pos nextAt hf =>
        injection ha with ha; subst ha
        simp at hh
        exact ⟨pos, nextAt, c, hc, hf, hh.2.symm, hh.1, rfl⟩

/-- The walk records a Fragment header only where a "next header" byte
names 44, and that byte comes before it. -/
theorem walk_frag : ∀ (fuel : Nat) {b : List Nat} {stop next nextAt pos : Nat}
    {frag : Option (Nat × Nat)} {c : Chain},
    (next = b.getD nextAt 0) → nextAt < pos →
    (∀ a n, frag = some (a, n) → b.getD n 0 = 44 ∧ n < a) →
    walk b stop fuel next nextAt pos frag = some c →
    ∀ a n, c.frag = some (a, n) → b.getD n 0 = 44 ∧ n < a
  | 0, _, _, _, _, _, _, _, _, _, _, h => by simp [walk] at h
  | fuel + 1, b, stop, next, nextAt, pos, frag, c, hn, hlt, hfr, h => by
    unfold walk at h
    by_cases h1 : ¬ isExt next
    · rw [if_pos h1] at h; injection h with h; subst h; exact hfr
    rw [if_neg h1] at h
    by_cases h2 : b.length ≤ pos + 1 ∨ stop < pos + extLen b next pos
    · rw [if_pos h2] at h; cases h
    rw [if_neg h2] at h
    by_cases h3 : next = 44 ∧ frag.isSome
    · rw [if_pos h3] at h; cases h
    rw [if_neg h3] at h
    have hfr' : ∀ a n, (if next = 44 then some (pos, nextAt) else frag) = some (a, n) →
        b.getD n 0 = 44 ∧ n < a := by
      intro a n he
      by_cases h44 : next = 44
      · rw [if_pos h44] at he
        injection he with he
        injection he with h1 h2
        subst h1 h2
        exact ⟨by rw [← hn]; exact h44, hlt⟩
      · rw [if_neg h44] at he
        exact hfr a n he
    have hpos : 0 < extLen b next pos := by
      unfold extLen; split <;> (try split) <;> omega
    by_cases h4 : next = 44 ∧ be16 b (pos + 2) / 8 ≠ 0
    · rw [if_pos h4] at h
      injection h with h; subst h
      intro a n hc
      exact hfr' a n (by rw [if_pos h4.1]; exact hc)
    · rw [if_neg h4] at h
      exact walk_frag fuel rfl (by omega) hfr' h

theorem arrived6_names_fragment {b : List Nat} {f : Frag} {hd : List Nat} (ha : arrived6 b = some f)
    (hh : f.header = some hd) :
    ∃ pos nextAt, nextAt < pos ∧ b.getD nextAt 0 = 44 ∧ hd = (b.take pos).set nextAt (b.getD pos 0) := by
  obtain ⟨pos, nextAt, c, hc, hf, hhd, -, -⟩ := arrived6_header ha hh
  have := walk_frag _ rfl (by omega) (by simp) hc pos nextAt hf
  exact ⟨pos, nextAt, this.2, this.1, hhd⟩

/-- `arrived` sets the timeouts: 30 s for IPv4, 60 s for IPv6. -/
theorem arrived_timeout {b : List Nat} {f : Frag} (ha : arrived b = some f) :
    (f.timeout = V4_TIMEOUT ∧ ∃ s d i p, f.key = .v4 s d i p) ∨
    (f.timeout = V6_TIMEOUT ∧ ∃ s d i, f.key = .v6 s d i) := by
  unfold arrived at ha
  split at ha
  · left
    unfold arrived4 at ha
    try dsimp only at ha
    split at ha; · simp at ha
    split at ha; · simp at ha
    split at ha; · simp at ha
    injection ha with ha; subst ha; exact ⟨rfl, _, _, _, _, rfl⟩
  · split at ha
    · right
      unfold arrived6 at ha
      try dsimp only at ha
      split at ha; · simp at ha
      split at ha; · simp at ha
      split at ha; · simp at ha
      injection ha with ha; subst ha; exact ⟨rfl, _, _, _, rfl⟩
    · simp at ha

/-- `arrived` gives headers only with a fragment at offset 0. -/
theorem arrived_header {b : List Nat} {f : Frag} {hd : List Nat} (ha : arrived b = some f)
    (hh : f.header = some hd) : f.offset = 0 := by
  unfold arrived at ha
  split at ha
  · unfold arrived4 at ha
    try dsimp only at ha
    split at ha; · simp at ha
    split at ha; · simp at ha
    split at ha; · simp at ha
    injection ha with ha; subst ha; simp at hh; exact hh.1
  · split at ha
    · obtain ⟨_, _, _, _, _, _, h0, _⟩ := arrived6_header ha hh; exact h0
    · simp at ha

/-! ## Vectors

Random IPv4 and IPv6 packets, cut into fragments, sent in random order
with copies, overlaps, disagreeing lengths, late fragments, other keys,
ends past 65,535 and bad fragments. Each step's expected result is what
`push` above makes of it. The cap (4 MiB) is never reached here; it is
proved below instead. -/

namespace Gen

abbrev Rng := StateM Nat

def next : Rng Nat := modifyGet fun s =>
  let s' := (s * 6364136223846793005 + 1442695040888963407) % 18446744073709551616
  (s' / 65536, s')

/-- A number below `n` (`n ≥ 1`). -/
def below (n : Nat) : Rng Nat := do return (← next) % (max n 1)

def coin : Rng Bool := do return (← below 2) == 0

def bytes (n : Nat) : Rng (List Nat) := do
  let mut a : Array Nat := #[]
  for _ in [0:n] do
    a := a.push (← below 256)
  return a.toList

def pick {α} [Inhabited α] (l : List α) : Rng α := do return l.getD (← below l.length) default

def shuffle {α} (l : List α) : Rng (List α) := do
  let mut src := l.toArray
  let mut out : Array α := #[]
  for _ in [0:l.length] do
    let i ← below src.size
    match src[i]? with
    | some x =>
      out := out.push x
      src := src.eraseIdxIfInBounds i
    | none => pure ()
  return out.toList

/-- Two lists merged in a random order, each keeping its own order. -/
def interleave {α} (a b : List α) : Rng (List α) := do
  let mut a := a
  let mut b := b
  let mut out : Array α := #[]
  for _ in [0:a.length + b.length] do
    match a, b with
    | x :: a', y :: b' =>
      if ← coin then
        out := out.push x
        a := a'
      else
        out := out.push y
        b := b'
    | x :: a', [] =>
      out := out.push x
      a := a'
    | [], y :: b' =>
      out := out.push y
      b := b'
    | [], [] => pure ()
  return out.toList

def w16 (v : Nat) : List Nat := [v / 256 % 256, v % 256]

def w32 (v : Nat) : List Nat := w16 (v / 65536) ++ w16 v

/-- How one packet's fragments are written: offset, "more fragments",
data. -/
structure Family where
  write : Nat → Bool → List Nat → List Nat
  timeout : Nat

/-- An IPv4 packet's fragment builder. Options go in the first fragment, and
in later ones when `copy`. "Don't fragment" and the reserved bit are random. -/
def v4Family (id : Nat) : Rng Family := do
  let src ← bytes 4
  let dst ← bytes 4
  let proto ← pick [17, 6, 1, 99]
  let tos ← below 256
  let ttl ← below 256
  let df ← coin
  let evil := (← below 4) == 0
  let nopt ← pick [0, 0, 4, 8, 40]
  let options ← bytes nopt
  let copy ← coin
  let mk := fun (offset : Nat) (more : Bool) (data : List Nat) =>
    let opts := if offset = 0 ∨ copy then options else []
    let ihl := 20 + opts.length
    let flags := (if evil then 32768 else 0) + (if df then 16384 else 0) +
      (if more then 8192 else 0) + offset / 8
    let h := [64 + ihl / 4, tos] ++ w16 (ihl + data.length) ++ w16 id ++ w16 flags ++
      [ttl, proto, 0, 0] ++ src ++ dst ++ opts
    setHeaderChecksum h ++ data
  return ⟨mk, V4_TIMEOUT⟩

/-- An IPv6 packet's fragment builder: an optional Hop-by-Hop header in
front of the fragment header, and `first` named by the first fragment's
fragment header. Later fragments may name something else there (RFC 8200
section 4.5: only the first fragment's is used). -/
def v6Family (id : Nat) (first : Nat) : Rng Family := do
  let src ← bytes 16
  let dst ← bytes 16
  let hbh ← coin
  let later ← pick [first, first, 17, 6]
  let mk := fun (offset : Nat) (more : Bool) (data : List Nat) =>
    let unfrag := if hbh then [44, 0, 1, 4, 0, 0, 0, 0] else []
    let fh := [if offset = 0 then first else later, 0] ++
      w16 (offset + (if more then 1 else 0)) ++ w32 id
    [0x60, 0, 0, 0] ++ w16 (unfrag.length + 8 + data.length) ++ [if hbh then 0 else 44, 64] ++
      src ++ dst ++ unfrag ++ fh ++ data
  return ⟨mk, V6_TIMEOUT⟩

/-- A random packet: its builder and its data. IPv6 data may start with a
Destination Options header, which is then in the first fragment. -/
def packet (v6 : Bool) (len : Nat) : Rng (Family × List Nat) := do
  let id ← below 65536
  if v6 then
    let upper ← pick [17, 253, 59]
    let dopt ← coin
    let payload ← bytes (max len 24)
    let data := if dopt then [upper, 0, 1, 4, 0, 0, 0, 0] ++ payload else payload
    let id ← below 4294967296
    return (← v6Family id (if dopt then 60 else upper), data)
  else
    return (← v4Family id, ← bytes (max len 1))

/-- Cuts `t` bytes into pieces: every piece but the last a multiple of 8,
the first at least `minFirst` long. -/
def cuts (t minFirst maxUnits : Nat) : Rng (List (Nat × Nat)) := do
  let mut off := 0
  let mut out : Array (Nat × Nat) := #[]
  for _ in [0:t] do
    if off < t then
      let n := 8 * (1 + (← below maxUnits))
      let n := if off = 0 then max n minFirst else n
      let n := if t ≤ off + n then t - off else n
      out := out.push (off, n)
      off := off + n
  return out.toList

/-- One packet's fragments: offset, "more fragments", data. -/
def fragments (data : List Nat) (minFirst maxUnits : Nat) : Rng (List (Nat × Bool × List Nat)) := do
  let cs ← cuts data.length minFirst maxUnits
  return cs.map fun (o, n) => (o, decide (o + n < data.length), slice data o (o + n))

/-- Adds copies of random fragments at random places. -/
def withCopies {α} (l : List α) (n : Nat) : Rng (List α) := do
  let mut l := l
  for _ in [0:n] do
    let i ← below l.length
    let j ← below (l.length + 1)
    match l[i]? with
    | some x => l := l.take j ++ [x] ++ l.drop j
    | none => pure ()
  return l

/-- Gives each packet a time: from `t0`, a few hundred milliseconds apart. -/
def timed (t0 : Nat) (ps : List (List Nat)) : Rng (List (Nat × List Nat)) := do
  let mut t := t0
  let mut out : Array (Nat × List Nat) := #[]
  for p in ps do
    t := t + (← below 400)
    out := out.push (t, p)
  return out.toList

/-- A fragment written by a packet's builder. -/
def build (fam : Family) (fr : Nat × Bool × List Nat) : List Nat := fam.write fr.1 fr.2.1 fr.2.2

/-- One random case of the given scenario. -/
def scenario (kind : Nat) (v6 : Bool) : Rng (String × List (Nat × List Nat)) := do
  let len ← pick [8, 16, 24, 40, 100, 200, 333, 600, 1000]
  let len := len + (← below 9)
  let (fam, data) ← packet v6 len
  let frs ← fragments data (if v6 then 16 else 8) (← pick [1, 2, 4, 8, 20])
  let t0 ← below 1000000
  let name := if v6 then "IPv6" else "IPv4"
  let some (o, m, d) := frs[← below frs.length]? | return ("no fragments", [])
  match kind with
  | 0 =>
    let order ← withCopies (← shuffle frs) (← below 4)
    return (s!"{name}: fragments in any order with copies", ← timed t0 (order.map (build fam)))
  | 1 =>
    -- A fragment over part of another, with the original's bytes there or
    -- other bytes.
    let shift := 8 * (1 + (← below 2))
    let n := 8 * (1 + (← below 3))
    let o' := if o > shift ∧ (← coin) then o - shift else o + shift
    let ext ← if ← coin then pure (slice data o' (o' + n)) else bytes n
    let ext ← if ext.isEmpty then bytes n else pure ext
    let m' := decide (o' + ext.length < data.length) || (← coin)
    let order ← shuffle ((o', m', ext) :: frs)
    return (s!"{name}: partial overlap", ← timed t0 (order.map (build fam)))
  | 2 =>
    let i ← if v6 ∧ o = 0 then (8 + ·) <$> below (d.length - 8) else below d.length
    let d' := d.set i ((d.getD i 0 + 1 + (← below 255)) % 256)
    let order ← shuffle ((o, m, d') :: frs)
    return (s!"{name}: same place, other bytes", ← timed t0 (order.map (build fam)))
  | 3 =>
    let order ← shuffle ((o, !m, d) :: frs)
    return (s!"{name}: copy with the other MF flag", ← timed t0 (order.map (build fam)))
  | 4 =>
    -- A last fragment that ends somewhere else.
    let delta := 8 * (1 + (← below 4))
    let d' ← bytes (1 + (← below 16))
    let o' := if data.length > delta ∧ (← coin) then max 8 ((data.length - delta) / 8 * 8)
      else data.length / 8 * 8 + delta
    let order ← shuffle ((o', false, d') :: frs)
    return (s!"{name}: disagreeing lengths", ← timed t0 (order.map (build fam)))
  | 5 =>
    -- A pause just before, at, or past the deadline, then the rest.
    let order ← withCopies (← shuffle frs) (← below 2)
    let k ← below (order.length + 1)
    let steps ← timed t0 (order.map (build fam))
    let gap := fam.timeout + (← pick [0, 0, 1, 500]) - (← pick [0, 1, 0])
    let steps := steps.take k ++ (steps.drop k).map fun (t, p) => (t + gap, p)
    return (s!"{name}: late fragments", steps)
  | 6 =>
    -- Two packets at once: another identification, or the other family.
    let v6' := if ← coin then !v6 else v6
    let (fam2, data2) ← packet v6' (← pick [16, 64, 200])
    let frs2 ← fragments data2 16 (← pick [1, 2, 8])
    let a ← withCopies (← shuffle frs) (← below 2)
    let b ← withCopies (← shuffle frs2) (← below 2)
    let order ← interleave (a.map (build fam)) (b.map (build fam2))
    return (s!"{name}: two packets interleaved", ← timed t0 order)
  | 7 =>
    let o' ← pick [65528, 65520, 65512]
    let d' ← bytes (24 + 8 * (← below 2))
    let order ← shuffle frs
    let k ← below (order.length + 1)
    let order := order.take k ++ [(o', ← coin, d')] ++ order.drop k
    return (s!"{name}: an end past 65,535", ← timed t0 (order.map (build fam)))
  | 8 =>
    -- A non-last length not a multiple of 8, and a fragment with no data.
    let cut := d.take (max 1 (d.length - 1 - (← below 7)))
    let cut := if cut.length % 8 = 0 then cut ++ [0] else cut
    let empty := (max o 8 + 8 * (← below 3), ← coin, ([] : List Nat))
    let order ← shuffle ((max o 8, true, cut) :: empty :: frs)
    return (s!"{name}: bad fragments", ← timed t0 (order.map (build fam)))
  | 9 =>
    -- The whole packet in one fragment, next to waiting ones of its key.
    let ps := (← shuffle frs).map (build fam)
    let k ← below (ps.length + 1)
    let one := build fam (0, false, data)
    return (s!"{name}: one-fragment packet", ← timed t0 (ps.take k ++ [one] ++ ps.drop k))
  | 10 =>
    -- A copy with its TTL or hop limit changed: an IPv4 header that no
    -- longer verifies, or an IPv6 copy with the same data.
    let ps := (← shuffle frs).map (build fam)
    let k ← below ps.length
    let p := ps.getD k []
    let pos := if v6 then 7 else 8
    let broken := p.set pos (p.getD pos 0 ^^^ 1)
    let j ← below (ps.length + 1)
    return (s!"{name}: broken copy", ← timed t0 (ps.take j ++ [broken] ++ ps.drop j))
  | _ =>
    -- An overlap kills the packet; once its time is up the same key makes
    -- a packet again.
    let i ← if v6 ∧ o = 0 then (8 + ·) <$> below (d.length - 8) else below d.length
    let d' := d.set i ((d.getD i 0 + 1) % 256)
    let first ← timed t0 (((o, m, d') :: frs).map (build fam))
    let tl := (first.getLast?.map (·.1)).getD t0
    let again ← timed (tl + fam.timeout + (← below 2000)) ((← shuffle frs).map (build fam))
    return (s!"{name}: dead until expiry, then again", first ++ again)

/-- A packet whose reassembled length field is 65,535, or one more. -/
def atLimit (v6 over : Bool) : Rng (String × List (Nat × List Nat)) := do
  if v6 then
    -- A Hop-by-Hop header in front of the fragment header: the payload
    -- length is 8 + data.
    let src ← bytes 16
    let dst ← bytes 16
    let t := 65527 + (if over then 1 else 0)
    let data ← bytes t
    let mk := fun (o : Nat) (m : Bool) (d : List Nat) =>
      [0x60, 0, 0, 0] ++ w16 (8 + 8 + d.length) ++ [0, 64] ++ src ++ dst ++
        [44, 0, 1, 4, 0, 0, 0, 0] ++ [253, 0] ++ w16 (o + (if m then 1 else 0)) ++ w32 7 ++ d
    let frs ← fragments data 16 180
    return (s!"IPv6: reassembled payload length {8 + t}", ← timed 0 (frs.map fun (o, m, d) => mk o m d))
  else
    -- 40 bytes of options in the first fragment: the total length is
    -- 60 + data.
    let src ← bytes 4
    let dst ← bytes 4
    let t := 65475 + (if over then 1 else 0)
    let data ← bytes t
    let mk := fun (o : Nat) (m : Bool) (d : List Nat) =>
      let opts := if o = 0 then List.replicate 40 1 else []
      let ihl := 20 + opts.length
      let h := [64 + ihl / 4, 0] ++ w16 (ihl + d.length) ++ w16 7 ++
        w16 ((if m then 8192 else 0) + o / 8) ++ [64, 17, 0, 0] ++ src ++ dst ++ opts
      setHeaderChecksum h ++ d
    let frs ← fragments data 8 180
    return (s!"IPv4: reassembled total length {60 + t}", ← timed 0 (frs.map fun (o, m, d) => mk o m d))

def hexDigit (n : Nat) : Char := if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)

def hex (b : List Nat) : String :=
  b.foldl (fun s x => (s.push (hexDigit (x / 16))).push (hexDigit (x % 16))) ""

def expectJson : Out → Lean.Json
  | .whole b => Lean.Json.mkObj [("whole", Lean.Json.str (hex b))]
  | .waiting => Lean.Json.str "waiting"
  | .discarded => Lean.Json.str "discarded"
  | .refused => Lean.Json.str "refused"

def caseJson (name : String) (steps : List (Nat × List Nat)) : Lean.Json :=
  let outs := run steps
  Lean.Json.mkObj [("name", Lean.Json.str name),
    ("steps", Lean.Json.arr ((steps.zip outs).map fun ((t, p), o) =>
      Lean.Json.mkObj [("at_ms", Lean.Json.num (Lean.JsonNumber.fromNat t)),
        ("packet", Lean.Json.str (hex p)), ("expect", expectJson o)]).toArray)]

/-- Twelve scenarios, both families, `rounds` cases of each, then the four
cases at the length limit. -/
def cases (rounds : Nat) : Rng (List Lean.Json) := do
  let mut out : Array Lean.Json := #[]
  for r in [0:rounds] do
    for kind in [0:12] do
      for v6 in [false, true] do
        let (name, steps) ← scenario kind v6
        out := out.push (caseJson s!"{name} #{r}" steps)
  for v6 in [false, true] do
    for over in [false, true] do
      let (name, steps) ← atLimit v6 over
      out := out.push (caseJson name steps)
  return out.toList

end Gen

/-- The vector files this module writes: `(file stem, cases)`. -/
def vectors (seed : Nat) : List (String × Lean.Json) :=
  [("reassembly", Lean.Json.arr ((Gen.cases 25).run' (seed + 1)).toArray)]

end Ip.Reassembly
