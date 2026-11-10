import Hpack.Block

/-!
# Encoders (RFC 7541 sections 4.2, 6 and 7)

An encoder keeps its own copy of the dynamic table, its maximum size, the
peer's settings limit, and the least size it chose since the last block,
which the next block must signal (section 4.2). `Encoder.block` writes a
block for a `Policy`: whether to refer to an entry that matches a field,
to an entry with its name, whether to add fields to the table, and which
strings to code with Huffman. Fields marked never-indexed are always
never-indexed literals (section 7.1.3). `rustPolicy` is the choice
`hpack::Encoder::encode_block` makes; the vectors compare its bytes with
Rust's.
-/

namespace Hpack

/-- How an encoder chooses representations. -/
structure Policy where
  /-- Refer to the first entry whose name and value match. -/
  useIndex : Bool
  /-- Refer to the first entry whose name matches. -/
  useName : Bool
  /-- Add fields to the table when its maximum is not 0. -/
  index : Bool
  /-- Code this string with Huffman. -/
  huff : Bytes → Bool

/-- The choice `Encoder::encode_block` makes: references whenever there is a
match, every field added while the table has room for any, and Huffman when
it is enabled and shorter. -/
def rustPolicy (huffman : Bool) : Policy :=
  { useIndex := true, useName := true, index := true,
    huff := fun s => huffman && decide ((encode s).length < s.length) }

/-- One direction's encoder. -/
structure Encoder where
  dyn : Dyn
  max : Nat
  settings : Nat
  pending : Option Nat
  deriving DecidableEq, Repr

/-- A new maximum size: the table shrinks to it, and the least one chosen since
the last block is kept for the next block's first size update. -/
def Encoder.resize (enc : Encoder) (c : Nat) : Encoder :=
  { enc with
    pending := some (match enc.pending with | none => c | some m => min m c)
    max := c
    dyn := enc.dyn.evict c }

/-- `Encoder::set_settings_limit`: the peer's SETTINGS_HEADER_TABLE_SIZE, applied
when it arrives. A limit below the maximum shrinks the table to it. -/
def Encoder.setSettings (enc : Encoder) (limit : Nat) : Encoder :=
  let l := min limit maxTable
  let enc := { enc with settings := l }
  if l < enc.max then enc.resize l else enc

/-- `Encoder::new`: the table starts at 4096, then the settings limit applies. -/
def Encoder.new (limit : Nat) : Encoder :=
  (⟨Dyn.empty, 4096, 4096, none⟩ : Encoder).setSettings limit

/-- `Encoder::set_capacity`: a maximum the encoder chooses, at most the settings limit. -/
def Encoder.setCapacity (enc : Encoder) (c : Nat) : Option Encoder :=
  if enc.settings < c ∨ maxTable < c then none else some (enc.resize c)

/-- The first index, from 1, of an entry the test accepts, or 0 for none. -/
def firstIndex (p : Entry → Bool) : List Entry → Nat → Nat
  | [], _ => 0
  | e :: es, i => if p e then i else firstIndex p es (i + 1)

/-- The first entry, static then dynamic, whose name and value are the field's. -/
def exactIndex (d : Dyn) (f : Field) : Nat :=
  firstIndex (fun e => e.name == f.name && e.value == f.value) (staticEntries ++ d.entries) 1

/-- The first entry, static then dynamic, whose name is the field's. -/
def nameIndex (d : Dyn) (f : Field) : Nat :=
  firstIndex (fun e => e.name == f.name) (staticEntries ++ d.entries) 1

/-- A string as the policy codes it. -/
def Policy.lit (pol : Policy) (s : Bytes) : Lit := ⟨pol.huff s, s⟩

/-- A literal's indexing: never-indexed fields stay so (section 7.1.3); others
are added when the policy says and the table can hold anything. -/
def chooseIx (pol : Policy) (max : Nat) (f : Field) : Indexing :=
  if f.never then .never else if pol.index ∧ max ≠ 0 then .incremental else .without

/-- A literal's name: an entry's, when the policy refers to names and one matches. -/
def chooseName (pol : Policy) (d : Dyn) (f : Field) : WName :=
  if pol.useName ∧ nameIndex d f ≠ 0 then .index (nameIndex d f) else .literal (pol.lit f.name)

/-- The representation the policy chooses for a field, given the table. -/
def chooseRep (pol : Policy) (max : Nat) (d : Dyn) (f : Field) : WRep :=
  if pol.useIndex ∧ !f.never ∧ exactIndex d f ≠ 0 then .indexed (exactIndex d f)
  else .literal (chooseName pol d f) (pol.lit f.value) (chooseIx pol max f)

/-- Whether a representation adds its field to the table. -/
def WRep.adds : WRep → Bool
  | .literal _ _ .incremental => true
  | _ => false

/-- The size updates a block starts with: the least size chosen since the last
block, then the current maximum when it differs (section 4.2). -/
def Encoder.updates (enc : Encoder) : List WRep :=
  match enc.pending with
  | none => []
  | some m => if enc.max = m then [.update m] else [.update m, .update enc.max]

/-- The fields' representations, each chosen against the table as the ones
before it left it. -/
def chooseAll (pol : Policy) (max : Nat) : Dyn → List Field → List WRep × Dyn
  | d, [] => ([], d)
  | d, f :: fs =>
    let w := chooseRep pol max d f
    let rest := chooseAll pol max (if w.adds then d.insert max ⟨f.name, f.value⟩ else d) fs
    (w :: rest.1, rest.2)

/-- A block: its representations and the encoder after it. -/
def Encoder.block (enc : Encoder) (pol : Policy) (fs : List Field) : List WRep × Encoder :=
  (enc.updates ++ (chooseAll pol enc.max enc.dyn fs).1,
   { enc with dyn := (chooseAll pol enc.max enc.dyn fs).2, pending := none })


/-- `encode_block`'s check: at most `maxHeaders` fields, no string past
`maxString`, at most `maxDecoded` octets in all. -/
def writable (fs : List Field) : Bool :=
  fs.length ≤ maxHeaders &&
  fs.all (fun f => f.name.length ≤ maxString && f.value.length ≤ maxString) &&
  (fs.map (fun f => f.name.length + f.value.length)).sum ≤ maxDecoded

end Hpack
