import Hpack.Huffman
import Hpack.Table

/-!
# Header blocks (RFC 7541 sections 3, 4.2, 6 and 6.3)

A block is read in two layers, as in Rust. `parseRaw` reads the
representations (section 6) until the bytes end or one cannot be read,
leaving their strings undecoded as `Representations` does; `applyAllRaw`
checks each one's owed reduction and name index, decodes its strings, and
applies it to a `Decoder`, which holds the dynamic table, its maximum
size, the acknowledged settings limit, and the reduction a settings change
still requires. The first error of either layer, in wire order, is the
block's: reading a representation never depends on the table, so reading
them all first and applying them after gives the error Rust gives when it
reads and applies one at a time. `parseBlock` and `applyAll` are the same
block with its strings decoded as they are read; the theorems are stated
over them, and `decodeBlock_ok_iff` ties them to `decodeBlock`.

The Rust code's resource bounds are part of the model, as named constants:
`maxString` on each string, encoded or decoded (`MAX_STRING`), `maxBlock` on
an encoded block (`MAX_BLOCK`), and `maxTable` on the settings limit
(`MAX_TABLE`). Its size update rule is stricter than section 4.2 asks of a
decoder: at most two updates, the second at least the first.
-/

namespace Hpack

/-- `MAX_STRING`: the most octets in one string, encoded or decoded. -/
def maxString : Nat := 65536
/-- `MAX_BLOCK`: the most bytes in one encoded block. -/
def maxBlock : Nat := 262144
/-- `MAX_TABLE`: the settings limit is capped here. -/
def maxTable : Nat := 65536

/-- The errors `Table::decode_block` gives, one for each `hpack::Error` variant
it can return. -/
inductive Err where
  | truncated
  | integerOverflow
  | stringTooLong
  | huffman
  | index
  | tableSize
  | sizeUpdateOrder
  | missingSizeUpdate
  | blockTooLong
  deriving DecidableEq, Repr

/-- A literal's indexing instruction (sections 6.2.1 to 6.2.3). -/
inductive Indexing where
  | incremental
  | without
  | never
  deriving DecidableEq, Repr, Inhabited

/-- A literal's name: octets, or the index of an entry whose name it takes. -/
inductive Name where
  | literal (s : Bytes)
  | index (i : Nat)
  deriving DecidableEq, Repr

/-- One representation (section 6), its strings decoded. -/
inductive Rep where
  | indexed (i : Nat)
  | literal (n : Name) (v : Bytes) (ix : Indexing)
  | update (size : Nat)
  deriving DecidableEq, Repr

def Rep.isUpdate : Rep → Bool
  | .update _ => true
  | _ => false

/-- An integer and the bytes after it. -/
def readInt (p : Nat) (bs : Bytes) : Except Err (Nat × Bytes) :=
  match decodeInt p bs with
  | .ok (v, n) => .ok (v, bs.drop n)
  | .error .truncated => .error .truncated
  | .error .overflow => .error .integerOverflow

/-- Section 5.2: a string literal, its octets and the bytes after it. Its length
and its decoded octets are each at most `maxString`. -/
def readStr (bs : Bytes) : Except Err (Bytes × Bytes) :=
  match bs.head? with
  | none => .error .truncated
  | some b =>
    match readInt 7 bs with
    | .error e => .error e
    | .ok (len, rest) =>
      if maxString < len then .error .stringTooLong
      else if rest.length < len then .error .truncated
      else if 128 ≤ b then
        match decode maxString (rest.take len) with
        | .ok s => .ok (s, rest.drop len)
        | .error .invalid => .error .huffman
        | .error .tooLong => .error .stringTooLong
      else .ok (rest.take len, rest.drop len)

/-- A literal's name, index 0 being a name of its own, and the bytes after it. -/
def readName (i : Nat) (rest : Bytes) : Except Err (Name × Bytes) :=
  if i = 0 then
    match readStr rest with
    | .error e => .error e
    | .ok (s, r) => .ok (.literal s, r)
  else .ok (.index i, rest)

/-- A literal field (sections 6.2.1 to 6.2.3): its name index behind a `p`-bit
prefix, its name if the index is 0, then its value. -/
def readLiteral (ix : Indexing) (p : Nat) (bs : Bytes) : Except Err (Rep × Bytes) :=
  match readInt p bs with
  | .error e => .error e
  | .ok (i, rest) =>
    match readName i rest with
    | .error e => .error e
    | .ok (n, rest) =>
      match readStr rest with
      | .error e => .error e
      | .ok (v, rest) => .ok (.literal n v ix, rest)

/-- The indexing instruction and name prefix a literal's first byte gives:
`01` incremental (6 bits), `0001` never indexed (4 bits), `0000` without (4 bits). -/
def literalKind (b : Nat) : Indexing × Nat :=
  if 64 ≤ b then (.incremental, 6) else if b / 16 = 1 then (.never, 4) else (.without, 4)

/-- One representation and the bytes after it. `started` says a field came
before, after which a size update is refused (section 4.2). -/
def readRep (started : Bool) (bs : Bytes) : Except Err (Rep × Bytes) :=
  match bs.head? with
  | none => .error .truncated
  | some b =>
    if b / 32 = 1 then
      if started then .error .sizeUpdateOrder
      else
        match readInt 5 bs with
        | .error e => .error e
        | .ok (n, rest) => .ok (.update n, rest)
    else if 128 ≤ b then
      match readInt 7 bs with
      | .error e => .error e
      | .ok (i, rest) => if i = 0 then .error .index else .ok (.indexed i, rest)
    else readLiteral (literalKind b).1 (literalKind b).2 bs

/-! ## Reading consumes bytes -/

theorem boundedRest_used (i : Nat) (bs : Bytes) (acc v n : Nat)
    (h : boundedRest i bs acc = .ok (v, n)) : i + 2 ≤ n ∧ n ≤ i + 1 + bs.length := by
  induction bs generalizing i acc with
  | nil => simp only [boundedRest] at h; split at h <;> cases h
  | cons b rest ih =>
    simp only [boundedRest] at h
    split at h
    · cases h
    · split at h
      · cases h
      · split at h
        · simp only [Except.ok.injEq, Prod.mk.injEq] at h; simp; omega
        · have := ih _ _ h; simp; omega

theorem decodeInt_used (p : Nat) (bs : Bytes) (v n : Nat) (h : decodeInt p bs = .ok (v, n)) :
    1 ≤ n ∧ n ≤ bs.length := by
  cases bs with
  | nil => simp [decodeInt] at h
  | cons b rest =>
    simp only [decodeInt] at h
    split at h
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h; simp; omega
    · have := boundedRest_used _ _ _ _ _ h; simp; omega

theorem readInt_shorter (p : Nat) (bs rest : Bytes) (v : Nat) (h : readInt p bs = .ok (v, rest)) :
    rest.length < bs.length := by
  unfold readInt at h
  split at h
  · next v' n hd =>
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    have := decodeInt_used p bs v' n hd
    rw [← h.2, List.length_drop]; omega
  · cases h
  · cases h

theorem readStr_shorter (bs rest s : Bytes) (h : readStr bs = .ok (s, rest)) :
    rest.length < bs.length := by
  unfold readStr at h
  split at h
  · cases h
  · split at h
    · cases h
    · next len r hr =>
      have := readInt_shorter 7 _ r len hr
      split at h
      · cases h
      · split at h
        · cases h
        · split at h
          · split at h
            · simp only [Except.ok.injEq, Prod.mk.injEq] at h
              rw [← h.2, List.length_drop]; omega
            · cases h
            · cases h
          · simp only [Except.ok.injEq, Prod.mk.injEq] at h
            rw [← h.2, List.length_drop]; omega

theorem readName_shorter (i : Nat) (bs rest : Bytes) (n : Name)
    (h : readName i bs = .ok (n, rest)) : rest.length ≤ bs.length := by
  unfold readName at h
  split at h
  · split at h
    · cases h
    · next s r hs =>
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.2]; exact Nat.le_of_lt (readStr_shorter _ _ _ hs)
  · simp only [Except.ok.injEq, Prod.mk.injEq] at h
    rw [← h.2]; exact Nat.le_refl _

theorem readLiteral_shorter (ix : Indexing) (p : Nat) (bs rest : Bytes) (r : Rep)
    (h : readLiteral ix p bs = .ok (r, rest)) : rest.length < bs.length := by
  unfold readLiteral at h
  split at h
  · cases h
  · next i r1 hr1 =>
    have h1 := readInt_shorter _ _ _ _ hr1
    split at h
    · cases h
    · next n r2 hname =>
      have h2 := readName_shorter _ _ _ _ hname
      split at h
      · cases h
      · next v r3 hv =>
        simp only [Except.ok.injEq, Prod.mk.injEq] at h
        rw [← h.2]
        have := readStr_shorter _ _ _ hv
        omega

theorem readRep_shorter (started : Bool) (bs rest : Bytes) (r : Rep)
    (h : readRep started bs = .ok (r, rest)) : rest.length < bs.length := by
  unfold readRep at h
  split at h
  · cases h
  · split at h
    · split at h
      · cases h
      · split at h
        · cases h
        · next n r' hr =>
          simp only [Except.ok.injEq, Prod.mk.injEq] at h
          rw [← h.2]; exact readInt_shorter _ _ _ _ hr
    · split at h
      · split at h
        · cases h
        · next i r' hr =>
          split at h
          · cases h
          · simp only [Except.ok.injEq, Prod.mk.injEq] at h
            rw [← h.2]; exact readInt_shorter _ _ _ _ hr
      · exact readLiteral_shorter _ _ _ _ _ h

/-- A block's representations, read until the bytes end or one cannot be read,
with the error that stopped them. -/
def parseBlock (started : Bool) (bs : Bytes) : List Rep × Option Err :=
  if hb : bs = [] then ([], none)
  else
    match h : readRep started bs with
    | .error e => ([], some e)
    | .ok (r, rest) =>
      let next := parseBlock (started || !r.isUpdate) rest
      (r :: next.1, next.2)
termination_by bs.length
decreasing_by exact readRep_shorter _ _ _ _ h

/-! ## Representations as Rust reads them

`Representations` reads a block without decoding its strings: each string
literal's length is checked against `maxString` and its octets must be
there, and the Huffman code is left to whoever uses the string (`Text`).
`Table::read_block` then checks the reduction owed and a name's index
before it decodes the name, and the name before the value. So of two
faults in one literal, a truncated value, an owed reduction or a bad name
index comes before an invalid Huffman string. RFC 7541 orders no decoding
error before another (each ends the connection with `COMPRESSION_ERROR`),
so `decodeBlock` takes Rust's documented order. `parseBlock` above, which
decodes as it reads, is the same block seen with its strings decoded:
`decodeBlock_ok_iff` below shows the two accept the same blocks with the
same results. -/

/-- A string literal as read and not yet decoded (`Text`): whether it is
Huffman coded, and its encoded octets. -/
structure Raw where
  huff : Bool
  octets : Bytes
  deriving DecidableEq, Repr

/-- Section 5.2's grammar without the decoding: a string literal of at most
`maxString` encoded octets, and the bytes after it (`Reader::text`). -/
def readRaw (bs : Bytes) : Except Err (Raw × Bytes) :=
  match bs.head? with
  | none => .error .truncated
  | some b =>
    match readInt 7 bs with
    | .error e => .error e
    | .ok (len, rest) =>
      if maxString < len then .error .stringTooLong
      else if rest.length < len then .error .truncated
      else .ok (⟨decide (128 ≤ b), rest.take len⟩, rest.drop len)

/-- A string's octets (`Text::decoded_len`, `Text::decode_into`): a Huffman
string decodes to at most `maxString` octets. -/
def Raw.decoded (r : Raw) : Except Err Bytes :=
  if r.huff then
    match decode maxString r.octets with
    | .ok s => .ok s
    | .error .invalid => .error .huffman
    | .error .tooLong => .error .stringTooLong
  else .ok r.octets

/-- A literal's name as read (`hpack::Name`). -/
inductive RawName where
  | literal (s : Raw)
  | index (i : Nat)
  deriving DecidableEq, Repr

/-- One representation as read (`hpack::Representation`). -/
inductive RawRep where
  | indexed (i : Nat)
  | literal (n : RawName) (v : Raw) (ix : Indexing)
  | update (size : Nat)
  deriving DecidableEq, Repr

def RawRep.isUpdate : RawRep → Bool
  | .update _ => true
  | _ => false

def readRawName (i : Nat) (rest : Bytes) : Except Err (RawName × Bytes) :=
  if i = 0 then
    match readRaw rest with
    | .error e => .error e
    | .ok (s, r) => .ok (.literal s, r)
  else .ok (.index i, rest)

def readRawLiteral (ix : Indexing) (p : Nat) (bs : Bytes) : Except Err (RawRep × Bytes) :=
  match readInt p bs with
  | .error e => .error e
  | .ok (i, rest) =>
    match readRawName i rest with
    | .error e => .error e
    | .ok (n, rest) =>
      match readRaw rest with
      | .error e => .error e
      | .ok (v, rest) => .ok (.literal n v ix, rest)

/-- `Representations::read`: `readRep` with its strings left undecoded. -/
def readRawRep (started : Bool) (bs : Bytes) : Except Err (RawRep × Bytes) :=
  match bs.head? with
  | none => .error .truncated
  | some b =>
    if b / 32 = 1 then
      if started then .error .sizeUpdateOrder
      else
        match readInt 5 bs with
        | .error e => .error e
        | .ok (n, rest) => .ok (.update n, rest)
    else if 128 ≤ b then
      match readInt 7 bs with
      | .error e => .error e
      | .ok (i, rest) => if i = 0 then .error .index else .ok (.indexed i, rest)
    else readRawLiteral (literalKind b).1 (literalKind b).2 bs

theorem readRaw_shorter (bs rest : Bytes) (s : Raw) (h : readRaw bs = .ok (s, rest)) :
    rest.length < bs.length := by
  unfold readRaw at h
  split at h
  · cases h
  · split at h
    · cases h
    · next len r hr =>
      have := readInt_shorter 7 _ r len hr
      split at h
      · cases h
      · split at h
        · cases h
        · simp only [Except.ok.injEq, Prod.mk.injEq] at h
          rw [← h.2, List.length_drop]; omega

theorem readRawRep_shorter (started : Bool) (bs rest : Bytes) (r : RawRep)
    (h : readRawRep started bs = .ok (r, rest)) : rest.length < bs.length := by
  unfold readRawRep at h
  split at h
  · cases h
  · split at h
    · split at h
      · cases h
      · split at h
        · cases h
        · next n r' hr =>
          simp only [Except.ok.injEq, Prod.mk.injEq] at h
          rw [← h.2]; exact readInt_shorter _ _ _ _ hr
    · split at h
      · split at h
        · cases h
        · next i r' hr =>
          split at h
          · cases h
          · simp only [Except.ok.injEq, Prod.mk.injEq] at h
            rw [← h.2]; exact readInt_shorter _ _ _ _ hr
      · unfold readRawLiteral at h
        split at h
        · cases h
        · next i r1 hr1 =>
          have h1 := readInt_shorter _ _ _ _ hr1
          split at h
          · cases h
          · next n r2 hname =>
            have h2 : r2.length ≤ r1.length := by
              unfold readRawName at hname
              split at hname
              · split at hname
                · cases hname
                · next s r hs =>
                  simp only [Except.ok.injEq, Prod.mk.injEq] at hname
                  rw [← hname.2]; exact Nat.le_of_lt (readRaw_shorter _ _ _ hs)
              · simp only [Except.ok.injEq, Prod.mk.injEq] at hname
                rw [← hname.2]; exact Nat.le_refl _
            split at h
            · cases h
            · next v r3 hv =>
              simp only [Except.ok.injEq, Prod.mk.injEq] at h
              rw [← h.2]
              have := readRaw_shorter _ _ _ hv
              omega

/-- A block's representations as `Representations` reads them, until the bytes
end or one cannot be read, with the error that stopped them. -/
def parseRaw (started : Bool) (bs : Bytes) : List RawRep × Option Err :=
  if hb : bs = [] then ([], none)
  else
    match h : readRawRep started bs with
    | .error e => ([], some e)
    | .ok (r, rest) =>
      let next := parseRaw (started || !r.isUpdate) rest
      (r :: next.1, next.2)
termination_by bs.length
decreasing_by exact readRawRep_shorter _ _ _ _ h

def RawName.decoded : RawName → Except Err Name
  | .literal s =>
    match s.decoded with
    | .error e => .error e
    | .ok t => .ok (.literal t)
  | .index i => .ok (.index i)

/-- A representation with its strings decoded, the name first. -/
def RawRep.decoded : RawRep → Except Err Rep
  | .indexed i => .ok (.indexed i)
  | .update n => .ok (.update n)
  | .literal n v ix =>
    match n.decoded with
    | .error e => .error e
    | .ok n' =>
      match v.decoded with
      | .error e => .error e
      | .ok v' => .ok (.literal n' v' ix)

/-- Every representation decoded, in order. -/
def decodeAll : List RawRep → Except Err (List Rep)
  | [] => .ok []
  | r :: rs =>
    match r.decoded with
    | .error e => .error e
    | .ok x =>
      match decodeAll rs with
      | .error e => .error e
      | .ok xs => .ok (x :: xs)

/-! ## The decoder -/

/-- A decoded header field. `never` is the never-indexed instruction (section 6.2.3). -/
structure Field where
  name : Bytes
  value : Bytes
  never : Bool
  deriving DecidableEq, Repr

/-- One direction's decoder: the dynamic table, its maximum size, the acknowledged
settings limit, and the reduction a settings change still requires. -/
structure Decoder where
  dyn : Dyn
  max : Nat
  settings : Nat
  required : Option Nat
  deriving DecidableEq, Repr

/-- `Table::new`: the table starts at 4096 (section 4.2); a settings limit below
that requires a reduction at the start of the first block. -/
def Decoder.new (limit : Nat) : Decoder :=
  let s := min limit maxTable
  ⟨Dyn.empty, 4096, s, if s < 4096 then some s else none⟩

/-- `Table::set_settings_limit`: an acknowledged SETTINGS_HEADER_TABLE_SIZE. A limit
below the table's maximum requires a reduction to it or below at the start of
the next block; several keep the least (section 4.2). -/
def Decoder.ack (d : Decoder) (limit : Nat) : Decoder :=
  let l := min limit maxTable
  { d with
    settings := l
    required := if l < d.max then some (match d.required with | none => l | some m => min m l)
                else d.required }

/-- A block being applied: the decoder, the size updates so far and the last of
them, and the fields so far, newest first. -/
structure St where
  dec : Decoder
  updates : Nat
  previous : Nat
  out : List Field
  deriving DecidableEq, Repr

def St.start (d : Decoder) : St := ⟨d, 0, 0, []⟩

/-- A name for a literal: its own octets, or the name of the entry it indexes. -/
def resolveName (d : Dyn) : Name → Option Bytes
  | .literal s => some s
  | .index i => (lookup d i).map (·.name)

/-- Whether a size update is above the reduction still owed. -/
def overOwed : Option Nat → Nat → Bool
  | some m, size => decide (m < size)
  | none, _ => false

/-- Section 6's processing of one representation. -/
def applyRep (st : St) : Rep → Except Err St
  | .update size =>
    if st.updates = 2 ∨ (st.updates = 1 ∧ size < st.previous) then .error .sizeUpdateOrder
    else if st.dec.settings < size then .error .tableSize
    else if overOwed st.dec.required size then
      .error .missingSizeUpdate
    else .ok { st with
      dec := { st.dec with required := none, max := size, dyn := st.dec.dyn.evict size }
      updates := st.updates + 1
      previous := size }
  | .indexed i =>
    if st.dec.required.isSome then .error .missingSizeUpdate
    else match lookup st.dec.dyn i with
      | none => .error .index
      | some e => .ok { st with out := ⟨e.name, e.value, false⟩ :: st.out }
  | .literal n v ix =>
    if st.dec.required.isSome then .error .missingSizeUpdate
    else match resolveName st.dec.dyn n with
      | none => .error .index
      | some name =>
        let out := ⟨name, v, ix = .never⟩ :: st.out
        if ix = .incremental then
          .ok { st with out, dec := { st.dec with dyn := st.dec.dyn.insert st.dec.max ⟨name, v⟩ } }
        else .ok { st with out }

def applyAll : St → List Rep → Except Err St
  | st, [] => .ok st
  | st, r :: rs =>
    match applyRep st r with
    | .error e => .error e
    | .ok st' => applyAll st' rs

/-- What `Table::read_block` checks of a representation before it decodes
its strings: for a literal, the reduction owed, then its name's index. -/
def St.precheck (st : St) : RawRep → Option Err
  | .literal n _ _ =>
    if st.dec.required.isSome then some .missingSizeUpdate
    else
      match n with
      | .index i => if (lookup st.dec.dyn i).isSome then none else some .index
      | .literal _ => none
  | _ => none

/-- `Table::read_block` on one representation as read: the checks before its
strings, then its strings decoded, then section 6's processing. -/
def applyRaw (st : St) (r : RawRep) : Except Err St :=
  match st.precheck r with
  | some e => .error e
  | none =>
    match r.decoded with
    | .error e => .error e
    | .ok rep => applyRep st rep

def applyAllRaw : St → List RawRep → Except Err St
  | st, [] => .ok st
  | st, r :: rs =>
    match applyRaw st r with
    | .error e => .error e
    | .ok st' => applyAllRaw st' rs

/-- `Table::decode_block`: one complete block, its fields in order and the decoder
after it. Each representation is read, then applied, in wire order; the error
is the first met, in Rust's order. -/
def decodeBlock (d : Decoder) (bs : Bytes) : Except Err (List Field × Decoder) :=
  if maxBlock < bs.length then .error .blockTooLong
  else
    match applyAllRaw (St.start d) (parseRaw false bs).1 with
    | .error e => .error e
    | .ok st =>
      match (parseRaw false bs).2 with
      | some e => .error e
      | none => if st.dec.required.isSome then .error .missingSizeUpdate
                else .ok (st.out.reverse, st.dec)

/-- The same block over its decoded representations: what it accepts, and
with what result, is `decodeBlock`'s (`decodeBlock_ok_iff`). -/
def decodeParsed (d : Decoder) (bs : Bytes) : Except Err (List Field × Decoder) :=
  if maxBlock < bs.length then .error .blockTooLong
  else
    match applyAll (St.start d) (parseBlock false bs).1 with
    | .error e => .error e
    | .ok st =>
      match (parseBlock false bs).2 with
      | some e => .error e
      | none => if st.dec.required.isSome then .error .missingSizeUpdate
                else .ok (st.out.reverse, st.dec)

/-! ## Rust's order accepts the blocks the decoded view accepts -/

/-- `readStr` is `readRaw`, then the string decoded. -/
theorem readStr_eq (bs : Bytes) :
    readStr bs = (match readRaw bs with
      | .error e => .error e
      | .ok (r, rest) =>
        match r.decoded with
        | .error e => .error e
        | .ok s => .ok (s, rest)) := by
  unfold readStr readRaw Raw.decoded
  split
  · rfl
  · next b _ =>
    split
    · rfl
    · split
      · rfl
      · split
        · rfl
        · by_cases hh : 128 ≤ b
          · simp only [hh, ite_true, decide_true]
            split <;> rfl
          · simp [hh]

theorem readStr_ok (bs rest s : Bytes) :
    readStr bs = .ok (s, rest) ↔ ∃ r, readRaw bs = .ok (r, rest) ∧ r.decoded = .ok s := by
  rw [readStr_eq]
  constructor
  · intro h
    split at h
    · cases h
    · next r rest' hr =>
      split at h
      · cases h
      · next s' hs =>
        simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        exact ⟨r, hr, hs⟩
  · rintro ⟨r, hr, hs⟩
    simp [hr, hs]

theorem readName_ok (i : Nat) (bs rest : Bytes) (n : Name) :
    readName i bs = .ok (n, rest) ↔
      ∃ rn, readRawName i bs = .ok (rn, rest) ∧ rn.decoded = .ok n := by
  unfold readName readRawName
  split
  · constructor
    · intro h
      split at h
      · cases h
      · next s r hs =>
        simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨raw, hraw, hd⟩ := (readStr_ok _ _ _).mp hs
        exact ⟨.literal raw, by simp [hraw], by simp [RawName.decoded, hd]⟩
    · rintro ⟨rn, h, hd⟩
      split at h
      · cases h
      · next raw r hraw =>
        simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        cases ht : raw.decoded with
        | error e => simp [RawName.decoded, ht] at hd
        | ok t =>
          simp only [RawName.decoded, ht, Except.ok.injEq] at hd
          subst hd
          simp [(readStr_ok _ _ _).mpr ⟨raw, hraw, ht⟩]
  · constructor
    · intro h
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨.index i, rfl, rfl⟩
    · rintro ⟨rn, h, hd⟩
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      simp only [RawName.decoded, Except.ok.injEq] at hd
      rw [hd]

theorem readLiteral_ok (ix : Indexing) (p : Nat) (bs rest : Bytes) (rep : Rep) :
    readLiteral ix p bs = .ok (rep, rest) ↔
      ∃ r, readRawLiteral ix p bs = .ok (r, rest) ∧ r.decoded = .ok rep := by
  unfold readLiteral readRawLiteral
  split
  · simp
  · constructor
    · intro h
      split at h
      · cases h
      · next n r2 hn =>
        split at h
        · cases h
        · next v r3 hv =>
          simp only [Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl⟩ := h
          obtain ⟨rn, hrn, hdn⟩ := (readName_ok _ _ _ _).mp hn
          obtain ⟨rv, hrv, hdv⟩ := (readStr_ok _ _ _).mp hv
          exact ⟨.literal rn rv ix, by simp [hrn, hrv], by simp [RawRep.decoded, hdn, hdv]⟩
    · rintro ⟨r, h, hd⟩
      split at h
      · cases h
      · next rn r2 hrn =>
        split at h
        · cases h
        · next rv r3 hrv =>
          simp only [Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl⟩ := h
          simp only [RawRep.decoded] at hd
          split at hd
          · cases hd
          · next n' hn' =>
            split at hd
            · cases hd
            · next v' hv' =>
              simp only [Except.ok.injEq] at hd
              subst hd
              simp [(readName_ok _ _ _ _).mpr ⟨rn, hrn, hn'⟩, (readStr_ok _ _ _).mpr ⟨rv, hrv, hv'⟩]

/-- A representation without strings reads alike either way. -/
theorem ok_plain (x : Rep) (r : RawRep) (hx : r.decoded = .ok x) (a rest : Bytes) (rep : Rep) :
    (Except.ok (x, a) : Except Err (Rep × Bytes)) = .ok (rep, rest) ↔
      ∃ r', (Except.ok (r, a) : Except Err (RawRep × Bytes)) = .ok (r', rest) ∧
        r'.decoded = .ok rep := by
  constructor
  · intro h
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨r, rfl, hx⟩
  · rintro ⟨r', h, hd⟩
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    rw [hx] at hd
    simp only [Except.ok.injEq] at hd
    rw [hd]

theorem readRep_ok (s : Bool) (bs rest : Bytes) (rep : Rep) :
    readRep s bs = .ok (rep, rest) ↔
      ∃ r, readRawRep s bs = .ok (r, rest) ∧ r.decoded = .ok rep := by
  unfold readRep readRawRep
  split
  · simp
  · split
    · split
      · simp
      · split
        · simp
        · exact ok_plain _ (.update _) rfl _ _ _
    · split
      · split
        · simp
        · split
          · simp
          · exact ok_plain _ (.indexed _) rfl _ _ _
      · exact readLiteral_ok _ _ _ _ _

theorem RawRep.decoded_isUpdate (r : RawRep) (rep : Rep) (h : r.decoded = .ok rep) :
    rep.isUpdate = r.isUpdate := by
  cases r with
  | indexed i =>
    simp only [RawRep.decoded, Except.ok.injEq] at h; subst h; rfl
  | update n =>
    simp only [RawRep.decoded, Except.ok.injEq] at h; subst h; rfl
  | literal n v ix =>
    simp only [RawRep.decoded] at h
    split at h
    · cases h
    · split at h
      · cases h
      · simp only [Except.ok.injEq] at h; subst h; rfl

/-- A block's representations read and decoded as Rust does are the ones
`parseBlock` reads, and both read to the end. -/
theorem parse_ok (s : Bool) (bs : Bytes) (reps : List Rep) :
    parseBlock s bs = (reps, none) ↔
      ∃ raws, parseRaw s bs = (raws, none) ∧ decodeAll raws = .ok reps := by
  induction hn : bs.length using Nat.strongRecOn generalizing s bs reps with
  | _ n ih =>
    rw [parseBlock, parseRaw]
    by_cases hb : bs = []
    · simp only [hb, dite_true, Prod.mk.injEq, and_true]
      constructor
      · rintro rfl; exact ⟨[], rfl, rfl⟩
      · rintro ⟨raws, rfl, hd⟩
        simp only [decodeAll, Except.ok.injEq] at hd
        exact hd
    · rw [dif_neg hb, dif_neg hb]
      constructor
      · intro h
        split at h
        · simp at h
        · next rep rest hrep =>
          simp only [Prod.mk.injEq] at h
          obtain ⟨rfl, hnone⟩ := h
          obtain ⟨raw, hraw, hd⟩ := (readRep_ok _ _ _ _).mp hrep
          have hlt := readRep_shorter _ _ _ _ hrep
          obtain ⟨raws, hp, hds⟩ := (ih rest.length (by omega) (s || !rep.isUpdate) rest _ rfl).mp
            (Prod.ext rfl hnone)
          refine ⟨raw :: raws, ?_, by simp [decodeAll, hd, hds]⟩
          split
          · next e he => rw [hraw] at he; cases he
          · next raw' rest' he =>
            rw [hraw] at he
            simp only [Except.ok.injEq, Prod.mk.injEq] at he
            obtain ⟨rfl, rfl⟩ := he
            rw [← RawRep.decoded_isUpdate _ _ hd, hp]
      · rintro ⟨raws, h, hd⟩
        split at h
        · simp at h
        · next raw rest hraw =>
          simp only [Prod.mk.injEq] at h
          obtain ⟨rfl, hnone⟩ := h
          simp only [decodeAll] at hd
          split at hd
          · cases hd
          · next rep hrep =>
            split at hd
            · cases hd
            · next reps' hreps =>
              simp only [Except.ok.injEq] at hd
              subst hd
              have hlt := readRawRep_shorter _ _ _ _ hraw
              have htail := (ih rest.length (by omega) (s || !raw.isUpdate) rest reps' rfl).mpr
                ⟨_, Prod.ext rfl hnone, hreps⟩
              have hread := (readRep_ok s bs rest rep).mpr ⟨raw, hraw, hrep⟩
              split
              · next e he => rw [hread] at he; cases he
              · next rep' rest' he =>
                rw [hread] at he
                simp only [Except.ok.injEq, Prod.mk.injEq] at he
                obtain ⟨rfl, rfl⟩ := he
                rw [RawRep.decoded_isUpdate _ _ hrep, htail]

theorem applyRaw_ok (st st' : St) (r : RawRep) :
    applyRaw st r = .ok st' ↔ ∃ rep, r.decoded = .ok rep ∧ applyRep st rep = .ok st' := by
  unfold applyRaw
  constructor
  · intro h
    split at h
    · cases h
    · split at h
      · cases h
      · next rep hrep => exact ⟨rep, hrep, h⟩
  · rintro ⟨rep, hd, ha⟩
    have hpre : st.precheck r = none := by
      cases r with
      | indexed i => rfl
      | update n => rfl
      | literal n v ix =>
        simp only [RawRep.decoded] at hd
        split at hd
        · cases hd
        · next n' hn =>
          split at hd
          · cases hd
          · simp only [Except.ok.injEq] at hd
            subst hd
            simp only [applyRep] at ha
            simp only [St.precheck]
            split at ha
            · cases ha
            · next hreq =>
              rw [if_neg hreq]
              cases n with
              | literal s => rfl
              | index i =>
                simp only [RawName.decoded, Except.ok.injEq] at hn
                subst hn
                simp only [resolveName] at ha
                split at ha
                · cases ha
                · next x hx =>
                  cases hl : lookup st.dec.dyn i
                  · rw [hl] at hx; cases hx
                  · simp [hl]
    simp [hpre, hd, ha]

theorem applyAllRaw_ok (st st' : St) (raws : List RawRep) :
    applyAllRaw st raws = .ok st' ↔
      ∃ reps, decodeAll raws = .ok reps ∧ applyAll st reps = .ok st' := by
  induction raws generalizing st with
  | nil =>
    simp only [applyAllRaw, decodeAll, Except.ok.injEq]
    constructor
    · rintro rfl; exact ⟨[], rfl, rfl⟩
    · rintro ⟨reps, rfl, h⟩
      simp only [applyAll, Except.ok.injEq] at h
      exact h
  | cons r rs ih =>
    simp only [applyAllRaw]
    constructor
    · intro h
      split at h
      · cases h
      · next st1 h1 =>
        obtain ⟨rep, hd, ha⟩ := (applyRaw_ok _ _ _).mp h1
        obtain ⟨reps, hds, has⟩ := (ih st1).mp h
        exact ⟨rep :: reps, by simp [decodeAll, hd, hds], by simp [applyAll, ha, has]⟩
    · rintro ⟨reps, hd, ha⟩
      simp only [decodeAll] at hd
      split at hd
      · cases hd
      · next rep hrep =>
        split at hd
        · cases hd
        · next reps' hreps =>
          simp only [Except.ok.injEq] at hd
          subst hd
          simp only [applyAll] at ha
          split at ha
          · cases ha
          · next st1 h1 =>
            have h1' := (applyRaw_ok _ _ _).mpr ⟨rep, hrep, h1⟩
            simp only [h1']
            exact (ih st1).mpr ⟨reps', hreps, ha⟩

/-- `decodeBlock`, in Rust's order, accepts exactly the blocks `decodeParsed`
accepts, with the same fields and decoder after; the two differ only in which
error a block with more than one fault reports. -/
theorem decodeBlock_ok_iff (d : Decoder) (bs : Bytes) (x : List Field × Decoder) :
    decodeBlock d bs = .ok x ↔ decodeParsed d bs = .ok x := by
  unfold decodeBlock decodeParsed
  split
  · simp
  · constructor
    · intro h
      split at h
      · cases h
      · next st hst =>
        split at h
        · cases h
        · next hn =>
          obtain ⟨reps, hd, ha⟩ := (applyAllRaw_ok _ _ _).mp hst
          have hp : parseBlock false bs = (reps, none) :=
            (parse_ok false bs reps).mpr ⟨_, Prod.ext rfl hn, hd⟩
          simpa [hp, ha] using h
    · intro h
      split at h
      · cases h
      · next st hst =>
        split at h
        · cases h
        · next hn =>
          obtain ⟨raws, hp, hd⟩ := (parse_ok false bs _).mp (Prod.ext rfl hn)
          have ha : applyAllRaw (St.start d) raws = .ok st :=
            (applyAllRaw_ok _ _ _).mpr ⟨_, hd, hst⟩
          simpa [hp, ha] using h

/-! ## What a block keeps -/

/-- `MAX_HEADERS` and `MAX_DECODED`: the most headers, and the most name and value
octets, a decoded block keeps; the encoder refuses more. -/
def maxHeaders : Nat := 256
def maxDecoded : Nat := 65536

/-- `Block::keep`: the decoded fields a block keeps within `limit` octets and
`maxHeaders` headers, in order, and how many it leaves out. A field left out
still changed the table. This is a resource bound of the Rust code, not of
RFC 7541. -/
def retainFrom (limit : Nat) : List Field → List Field → Nat → Nat → List Field × Nat
  | [], kept, _, more => (kept.reverse, more)
  | f :: fs, kept, used, more =>
    let len := f.name.length + f.value.length
    if maxHeaders ≤ kept.length ∨ limit - used < len then retainFrom limit fs kept used (more + 1)
    else retainFrom limit fs (f :: kept) (used + len) more

def retain (limit : Nat) (fs : List Field) : List Field × Nat := retainFrom limit fs [] 0 0

/-! ## Writing representations -/

/-- A string as an encoder writes it: Huffman coded or not. -/
structure Lit where
  huff : Bool
  s : Bytes
  deriving DecidableEq, Repr

/-- A representation as an encoder writes it, with each string's coding. -/
inductive WName where
  | literal (l : Lit)
  | index (i : Nat)
  deriving DecidableEq, Repr

inductive WRep where
  | indexed (i : Nat)
  | literal (n : WName) (v : Lit) (ix : Indexing)
  | update (size : Nat)
  deriving DecidableEq, Repr

/-- Section 5.2 writing: the length behind a 7-bit prefix with the H bit, then the
octets, coded or not. -/
def writeStr (l : Lit) : Bytes :=
  if l.huff then encodeInt 7 128 (encode l.s).length ++ encode l.s
  else encodeInt 7 0 l.s.length ++ l.s

/-- A literal's name prefix width and pattern bits (sections 6.2.1 to 6.2.3). -/
def ixPrefix : Indexing → Nat × Nat
  | .incremental => (6, 64)
  | .without => (4, 0)
  | .never => (4, 16)

/-- A literal: the name index (0 for a name of its own), the name, the value. -/
def writeLiteral (p flags : Nat) : WName → Lit → Bytes
  | .literal l, v => encodeInt p flags 0 ++ (writeStr l ++ writeStr v)
  | .index i, v => encodeInt p flags i ++ writeStr v

/-- Section 6 writing. -/
def writeRep : WRep → Bytes
  | .indexed i => encodeInt 7 128 i
  | .update n => encodeInt 5 32 n
  | .literal n v ix => writeLiteral (ixPrefix ix).1 (ixPrefix ix).2 n v

def WRep.isUpdate : WRep → Bool
  | .update _ => true
  | _ => false

/-- The block's bytes. -/
def writeBlock (ws : List WRep) : Bytes := ws.flatMap writeRep

/-- What a written representation reads back as. -/
def WName.toName : WName → Name
  | .literal l => .literal l.s
  | .index i => .index i

def WRep.rep : WRep → Rep
  | .indexed i => .indexed i
  | .update n => .update n
  | .literal n v ix => .literal n.toName v.s ix

end Hpack
