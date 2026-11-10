import Hpack.Huffman
import Hpack.Table

/-!
# Header blocks (RFC 7541 sections 3, 4.2, 6 and 6.3)

A block is read in two layers, as in Rust. `parseBlock` reads the
representations (section 6) until the bytes end or one cannot be read;
`applyAll` applies them in order to a `Decoder`, which holds the dynamic
table, its maximum size, the acknowledged settings limit, and the
reduction a settings change still requires. The first error of either
layer, in wire order, is the block's: the parse of a representation never
depends on the table, so reading them all first and applying them after
gives the error Rust gives when it reads and applies one at a time.

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

/-- Section 6's processing of one representation. -/
def applyRep (st : St) : Rep → Except Err St
  | .update size =>
    if st.updates = 2 ∨ (st.updates = 1 ∧ size < st.previous) then .error .sizeUpdateOrder
    else if st.dec.settings < size then .error .tableSize
    else if (match st.dec.required with | some m => decide (m < size) | none => false) then
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

/-- `Table::decode_block`: one complete block, its fields in order and the decoder
after it. -/
def decodeBlock (d : Decoder) (bs : Bytes) : Except Err (List Field × Decoder) :=
  if maxBlock < bs.length then .error .blockTooLong
  else
    let parsed := parseBlock false bs
    match applyAll (St.start d) parsed.1 with
    | .error e => .error e
    | .ok st =>
      match parsed.2 with
      | some e => .error e
      | none => if st.dec.required.isSome then .error .missingSizeUpdate
                else .ok (st.out.reverse, st.dec)

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
def WRep.rep : WRep → Rep
  | .indexed i => .indexed i
  | .update n => .update n
  | .literal (.literal l) v ix => .literal (.literal l.s) v.s ix
  | .literal (.index i) v ix => .literal (.index i) v.s ix

end Hpack
