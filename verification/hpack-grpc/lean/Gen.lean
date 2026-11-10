import Hpack
import Lean

/-!
Writes the vectors `tests/hpack_vectors.rs` replays on the Rust code. Every
expected result is computed here by the Lean model; nothing is a literal
copied from Rust. Bytes are hex strings.

`lake exe gen <dir> <seed>` writes one file per kind into `<dir>`.
-/

open Hpack Lean

abbrev G := StateT Nat IO

def step (n : Nat) : Nat := (n * 6364136223846793005 + 1442695040888963407) % 18446744073709551616

/-- A number below `n` (0 when `n` is 0). -/
def rand (n : Nat) : G Nat := do
  let s := step (← get)
  set s
  pure (if n = 0 then 0 else s / 4294967296 % n)

def chance (num den : Nat) : G Bool := return (← rand den) < num

def pick [Inhabited α] (xs : List α) : G α := return xs[← rand xs.length]!

def randBytes (n : Nat) : G Bytes := do
  let mut out := []
  for _ in [:n] do
    out := (← rand 256) :: out
  return out

def hexDigit (n : Nat) : Char := if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)

def hex (bs : Bytes) : String := Id.run do
  let mut out := ""
  for b in bs do
    out := (out.push (hexDigit (b / 16))).push (hexDigit (b % 16))
  return out

def obj (fields : List (String × Json)) : Json := Json.mkObj fields
def num (n : Nat) : Json := toJson n
def str (s : String) : Json := toJson s

/-- Streams one JSON array of cases into `<dir>/<name>.json`. -/
def write (dir : System.FilePath) (name : String) (seed : Nat)
    (generate : (Json → IO Unit) → G Unit) : IO Unit := do
  IO.FS.withFile (dir / (name ++ ".json")) .write fun handle => do
    let count ← IO.mkRef 0
    handle.putStr "["
    let emit := fun (value : Json) => do
      let n ← count.get
      if n > 0 then handle.putStr ","
      handle.putStr value.compress
      count.set (n + 1)
    let _ ← (generate emit).run seed
    handle.putStr "]\n"
    IO.println s!"{name}.json: {← count.get} cases"

/-! ## Integers -/

def intErrText : IntError → String
  | .truncated => "truncated"
  | .overflow => "overflow"

def intDecodeCase (p : Nat) (input : Bytes) : Json :=
  match decodeInt p input with
  | .ok (v, n) => obj [("prefix", num p), ("input", str (hex input)), ("value", num v), ("used", num n)]
  | .error e => obj [("prefix", num p), ("input", str (hex input)), ("error", str (intErrText e))]

/-- Values at and around every boundary: each prefix's mask, each power of two
up to 2^70, and 2^64 itself. -/
def intValues (p : Nat) : List Nat :=
  let m := mask p
  [0, 1, m - 1, m, m + 1, m + 127, m + 128, m + 129, m + 16383, m + 16384] ++
  (List.range 71).flatMap (fun k => [2 ^ k - 1, 2 ^ k, 2 ^ k + 1]) ++
  [2 ^ 64 - 1 - m, 2 ^ 64 - m, 2 ^ 64 - 1, 2 ^ 64, 2 ^ 64 + 1]

/-- The same value with its last byte made a continuation followed by a zero
byte: a longer, nonminimal encoding. -/
def nonminimal (e : Bytes) : Bytes :=
  match e.getLast? with
  | some b => if 1 < e.length then e.dropLast ++ [b + 128, 0] else e
  | none => e

def intDecodeVectors (emit : Json → IO Unit) : G Unit := do
  for p in List.range' 1 8 do
    for b in List.range 256 do
      emit (intDecodeCase p [b])
    let m := mask p
    for v in intValues p do
      let e := encodeInt p 0 v
      let flags := (← rand 256) / 2 ^ p * 2 ^ p
      let flagged := match e with | b :: rest => (b + flags) :: rest | [] => []
      emit (intDecodeCase p e)
      emit (intDecodeCase p flagged)
      emit (intDecodeCase p (e ++ [← rand 256, ← rand 256]))
      for cut in List.range e.length do
        emit (intDecodeCase p (e.take cut))
      let mut longer := e
      for _ in [:4] do
        longer := nonminimal longer
        emit (intDecodeCase p longer)
    for k in List.range 13 do
      let ones := m :: List.replicate k 255
      emit (intDecodeCase p ones)
      for last in [0, 1, 127] do
        emit (intDecodeCase p (ones ++ [last]))
    for _ in [:64] do
      let len ← rand 13
      let first := m + (← rand 256) / 2 ^ p * 2 ^ p
      emit (intDecodeCase p (first :: (← randBytes len)))

def intEncodeVectors (emit : Json → IO Unit) : G Unit := do
  for p in List.range' 1 8 do
    let high := 255 / 2 ^ p * 2 ^ p
    for v in intValues p do
      if v < intBound then
        for flags in [0, high, (← rand 256) / 2 ^ p * 2 ^ p] do
          emit (obj [("prefix", num p), ("flags", num flags), ("value", num v),
            ("output", str (hex (encodeInt p flags v)))])
    for _ in [:32] do
      let v := (← rand 4294967296) * 4294967296 + (← rand 4294967296)
      let v := v / 2 ^ (← rand 64)
      emit (obj [("prefix", num p), ("flags", num 0), ("value", num v),
        ("output", str (hex (encodeInt p 0 v)))])

/-! ## Huffman -/

def huffErrText : HuffError → String
  | .invalid => "invalid"
  | .tooLong => "too_long"

def huffDecodeCase (lim : Nat) (bytes : Bytes) : Json :=
  match decode lim bytes with
  | .ok s => obj [("input", str (hex bytes)), ("limit", num lim), ("output", str (hex s))]
  | .error e => obj [("input", str (hex bytes)), ("limit", num lim), ("error", str (huffErrText e))]

/-- A string of octets: text most of the time, any octet otherwise. -/
def randText (n : Nat) : G Bytes := do
  if ← chance 1 2 then
    let mut out := []
    for _ in [:n] do
      out := (32 + (← rand 95)) :: out
    return out
  else randBytes n

def huffEncodeVectors (emit : Json → IO Unit) : G Unit := do
  let one := fun (s : Bytes) => obj [("input", str (hex s)), ("output", str (hex (encode s)))]
  emit (one [])
  for x in List.range 256 do
    emit (one [x])
  emit (one (List.range 256))
  for _ in [:256] do
    emit (one (← randText (← rand 120)))

/-- Bits made bytes, when they fill whole bytes. -/
def whole (bits : List Bool) : Option Bytes :=
  if bits.length % 8 = 0 then some (pack bits) else none

def huffDecodeVectors (emit : Json → IO Unit) : G Unit := do
  let ones := fun k => List.replicate k true
  -- Every symbol, padded with every number of bits up to 16 that fills a byte,
  -- with each padding bit in turn made zero, and followed by EOS.
  for x in List.range 256 do
    let c := codeBits x
    for k in List.range 17 do
      if let some bytes := whole (c ++ ones k) then
        emit (huffDecodeCase 8 bytes)
        for j in List.range k do
          if let some bytes := whole (c ++ (ones k).set j false) then
            emit (huffDecodeCase 8 bytes)
    let withEos := c ++ codeBits eos
    emit (huffDecodeCase 8 (pack (withEos ++ ones (padLen withEos.length))))
    let eosFirst := codeBits eos ++ c
    emit (huffDecodeCase 8 (pack (eosFirst ++ ones (padLen eosFirst.length))))
  -- Random strings: as encoded, with padding a byte too long, with a bit
  -- flipped, with EOS between two symbols, under limits around their length.
  for _ in [:400] do
    let s ← randText (← rand 40)
    let bits := encodeBits s
    let pad := padLen bits.length
    let good := pack (bits ++ ones pad)
    for lim in [s.length, s.length - 1, 0, maxString] do
      emit (huffDecodeCase lim good)
    emit (huffDecodeCase maxString (pack (bits ++ ones (pad + 8))))
    if 0 < pad then
      emit (huffDecodeCase maxString (pack (bits ++ (ones pad).set (← rand pad) false)))
    let all := bits ++ ones pad
    if 0 < all.length then
      let j ← rand all.length
      emit (huffDecodeCase maxString (pack (all.set j (!all[j]!))))
    let at_ ← rand (s.length + 1)
    let mixed := encodeBits (s.take at_) ++ codeBits eos ++ encodeBits (s.drop at_)
    emit (huffDecodeCase maxString (pack (mixed ++ ones (padLen mixed.length))))
  -- Random bytes.
  for _ in [:400] do
    emit (huffDecodeCase 64 (← randBytes (← rand 12)))
  -- Runs of ones from 1 to 5 bytes: up to 29 ones stay in the code, 30 are EOS.
  for n in List.range' 1 5 do
    emit (huffDecodeCase 64 (List.replicate n 255))

/-! ## Blocks -/

def errText : Err → String
  | .truncated => "truncated"
  | .integerOverflow => "integer_overflow"
  | .stringTooLong => "string_too_long"
  | .huffman => "huffman"
  | .index => "index"
  | .tableSize => "table_size"
  | .sizeUpdateOrder => "size_update_order"
  | .missingSizeUpdate => "missing_size_update"
  | .blockTooLong => "block_too_long"

def fieldJson (f : Field) : Json := Json.arr #[str (hex f.name), str (hex f.value), toJson f.never]
def entryJson (e : Entry) : Json := Json.arr #[str (hex e.name), str (hex e.value)]

def names : List String :=
  [":method", ":path", ":authority", ":status", "content-type", "x-a", "set-cookie",
   "custom-key", "date", "cache-control", ""]
def values : List String :=
  ["GET", "/", "", "no-cache", "gzip, deflate", "custom-value", "www.example.com", "302", "200"]

/-- A string: a common name or value, short random octets, or a long text that
makes the table evict. -/
def genStr : G Bytes := do
  let r ← rand 20
  if r < 4 then return octets (← pick names)
  else if r < 8 then return octets (← pick values)
  else if r < 16 then randText (← rand 40)
  else if r < 19 then randText (100 + (← rand 1400))
  else randText (2000 + (← rand 3000))

def genLit : G Lit := return ⟨← chance 1 2, ← genStr⟩

/-- An index: in the static table, in the dynamic table, and, unless clean, just
past it, far past it, or 0. -/
def genIndex (d : Decoder) (clean : Bool) : G Nat := do
  let len := d.dyn.entries.length
  let r ← rand (if clean then 16 else 20)
  if r < 8 then return 1 + (← rand 61)
  else if r < 16 then
    if 0 < len then return 62 + (← rand len) else return 1 + (← rand 61)
  else if r < 18 then return 62 + len + (← rand 3)
  else if r < 19 then return (← rand 4294967296) * 1024
  else return 0

/-- A string that claims Huffman coding but is random bytes. -/
def junkHuffman : G Bytes := do
  let bytes ← randBytes (1 + (← rand 6))
  return encodeInt 7 128 bytes.length ++ bytes

def genField (d : Decoder) (clean : Bool) : G WRep := do
  if (← rand 10) < 4 then return .indexed (← genIndex d clean)
  let ix ← pick [Indexing.incremental, .incremental, .without, .never]
  let n ← if ← chance 1 2 then pure (WName.index (← genIndex d clean))
    else pure (WName.literal (← genLit))
  return .literal n (← genLit) ix

/-- A size: small enough to make the table evict, or anywhere up to `top`. -/
def genSize (top : Nat) : G Nat := do
  if ← chance 1 2 then rand (min top 300 + 1) else rand (top + 1)

/-- Size updates that follow the rules: the owed reduction, then perhaps a larger
size, or now and then a change of the encoder's own. -/
def cleanUpdates (d : Decoder) : G (List WRep) := do
  let top := match d.required with | some m => m | none => d.settings
  if d.required.isNone && (← chance 3 4) then return []
  let u1 ← genSize top
  if ← chance 1 2 then return [.update u1, .update (u1 + (← rand (d.settings - u1 + 1)))]
  else return [.update u1]

/-- Size updates that break a rule as often as they keep them. -/
def noisyUpdates (d : Decoder) : G (List WRep) := do
  let r ← rand 100
  match d.required with
  | some m =>
    if r < 50 then cleanUpdates d
    else if r < 75 then return []
    else return [.update (m + 1 + (← rand 100))]
  | none =>
    if r < 40 then return []
    else if r < 60 then cleanUpdates d
    else if r < 75 then
      let u1 ← genSize d.settings
      return [.update u1, .update (u1 / 2)]
    else if r < 88 then
      return [.update (← genSize d.settings), .update d.settings, .update d.settings]
    else return [.update (d.settings + 1 + (← rand 1000))]

/-- A block: three in four follow the rules (their references are in range when
the block starts), the rest break one now and then and may be cut, changed or
extended. -/
def genBlock (d : Decoder) : G Bytes := do
  let clean ← chance 3 4
  let ups ← if clean then cleanUpdates d else noisyUpdates d
  let mut fields := []
  for _ in [:(← rand (if ← chance 1 10 then 24 else 8))] do
    fields := fields ++ [← genField d clean]
  if clean then return writeBlock (ups ++ fields)
  if (← chance 1 5) && 0 < fields.length then
    fields := fields.take 1 ++ [.update (← genSize d.settings)] ++ fields.drop 1
  let mut bytes := writeBlock (ups ++ fields)
  if ← chance 1 5 then
    bytes := bytes ++ [0x00] ++ (← junkHuffman) ++ writeStr ⟨false, [0x61]⟩
  let r ← rand 100
  if r < 25 && 0 < bytes.length then return bytes.take (← rand bytes.length)
  else if r < 40 && 0 < bytes.length then return bytes.set (← rand bytes.length) (← rand 256)
  else if r < 47 then return bytes ++ (← randBytes (1 + (← rand 3)))
  else return bytes


/-- One step of a session: `Some` decoder to go on with, `none` after an error. -/
def blockStep (d : Decoder) (bytes : Bytes) : Json × Option Decoder :=
  match decodeBlock d bytes with
  | .error e => (obj [("block", str (hex bytes)), ("error", str (errText e))], none)
  | .ok (fs, d') =>
    let (kept, more) := retain maxDecoded fs
    (obj [("block", str (hex bytes)), ("fields", Json.arr (kept.map fieldJson).toArray),
      ("more", num more),
      ("table", Json.arr (d'.dyn.entries.map entryJson).toArray),
      ("size", num d'.dyn.size), ("max", num d'.max)], some d')

def ackStep (d : Decoder) (limit : Nat) : Json × Decoder :=
  (obj [("ack", num limit)], d.ack limit)

def session (settings : Nat) (steps : List Json) : Json :=
  obj [("settings", num settings), ("steps", Json.arr steps.toArray)]

/-- A session of the given blocks, stopping at the first error. -/
def fixedSession (settings : Nat) (blocks : List Bytes) : Json := Id.run do
  let mut d := Decoder.new settings
  let mut steps := []
  for b in blocks do
    let (j, next) := blockStep d b
    steps := steps ++ [j]
    match next with
    | some d' => d := d'
    | none => break
  return session settings steps

def unhex (s : String) : Bytes :=
  let digit := fun (c : Char) => if c.isDigit then c.toNat - 48 else c.toNat - 87
  let cs := s.toList.filter (· != ' ')
  (List.range (cs.length / 2)).map (fun i => digit cs[2 * i]! * 16 + digit cs[2 * i + 1]!)

/-- RFC 7541 Appendix C.3 to C.6, as wire bytes; the expected fields and tables
come from the model. -/
def appendixC : List (Nat × List String) := [
  (4096, ["828684410f7777772e6578616d706c652e636f6d", "828684be58086e6f2d6361636865",
    "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"]),
  (4096, ["828684418cf1e3c2e5f23a6ba0ab90f4ff", "828684be5886a8eb10649cbf",
    "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"]),
  (256, ["3fe101",
    "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
    "4803333037c1c0bf",
    "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31"]),
  (256, ["3fe101",
    "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
    "4883640effc1c0bf",
    "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007"])]

def blockVectors (emit : Json → IO Unit) : G Unit := do
  for (settings, blocks) in appendixC do
    emit (fixedSession settings (blocks.map unhex))
  -- The bounds: a Huffman string that decodes past maxString, a raw length past
  -- it, a block past maxBlock, an index past 2^64, size updates at and past 2^64.
  let big := encode (List.replicate (maxString + 1) 48)
  emit (fixedSession 4096 [[0x00] ++ writeStr ⟨false, octets "x"⟩ ++ encodeInt 7 128 big.length ++ big])
  emit (fixedSession 4096 [[0x00] ++ encodeInt 7 0 (maxString + 1)])
  emit (fixedSession 4096 [[0x00] ++ encodeInt 7 0 maxString])
  emit (fixedSession 4096 [List.replicate (maxBlock + 1) 0x82])
  emit (fixedSession 4096 [List.replicate maxBlock 0x82])
  emit (fixedSession 4096 [encodeInt 7 128 (2 ^ 64)])
  emit (fixedSession 4096 [encodeInt 7 128 (2 ^ 64 - 1)])
  emit (fixedSession 4096 [encodeInt 5 32 (2 ^ 64 - 1)])
  emit (fixedSession 4096 [encodeInt 5 32 (2 ^ 64)])
  emit (fixedSession maxTable [encodeInt 5 32 maxTable])
  emit (fixedSession (maxTable + 1) [encodeInt 5 32 (maxTable + 1)])
  -- References to a 4,000-octet entry: past maxDecoded octets the block keeps no
  -- more, and past maxHeaders headers none at all.
  let entry := writeRep (.literal (.literal ⟨false, octets "x"⟩) ⟨false, List.replicate 4000 118⟩ .incremental)
  emit (fixedSession 4096 [entry, List.replicate 20 0xbe, List.replicate 300 0x82 ++ [0xbe]])
  -- An entry exactly the capacity, and one octet more, which empties the table.
  for extra in [0, 1] do
    let value := List.replicate (100 - 32 - 1 + extra) 118
    emit (fixedSession 100 [encodeInt 5 32 100 ++ writeRep (.literal (.literal ⟨false, [120]⟩) ⟨false, [97]⟩ .incremental),
      writeRep (.literal (.literal ⟨false, [121]⟩) ⟨false, value⟩ .incremental)])
  -- Random sessions.
  for _ in [:600] do
    let settings ← pick [0, 1, 32, 64, 100, 256, 4096, 4096, 4096, 4096, maxTable, maxTable + 4]
    let mut d := Decoder.new settings
    let mut steps := []
    for _ in [:(1 + (← rand 12))] do
      if ← chance 3 20 then
        let (j, d') := ackStep d (← pick [0, 1, 32, 50, 64, 100, 256, 1000, 4096, 4096, maxTable, maxTable + 1])
        steps := steps ++ [j]
        d := d'
      else
        let (j, next) := blockStep d (← genBlock d)
        steps := steps ++ [j]
        match next with
        | some d' => d := d'
        | none => break
    emit (session settings steps)

/-! ## The encoder -/

def genEncField (seen : List Bytes) : G Field := do
  let name ← if ← chance 3 4 then pure (octets (← pick names)) else randText (← rand 30)
  let value ← if (0 < seen.length) && (← chance 1 2) then pick seen
    else if ← chance 1 20 then randText (300 + (← rand 1200))
    else if ← chance 1 2 then pure (octets (← pick values))
    else randText (← rand 40)
  return ⟨name, value, ← chance 1 8⟩

def encoderVectors (emit : Json → IO Unit) : G Unit := do
  for _ in [:400] do
    let settings ← pick [0, 64, 100, 256, 4096, 4096, 4096, maxTable, maxTable + 7]
    let mut enc := Encoder.new settings
    let mut dec := Decoder.new settings
    let mut huffman := true
    let mut seen : List Bytes := []
    let mut steps : List Json := []
    for _ in [:(1 + (← rand 16))] do
      let r ← rand 100
      if r < 12 then
        let l ← pick [0, 32, 64, 100, 256, 1000, 4096, maxTable, maxTable + 1]
        enc := enc.setSettings l
        dec := dec.ack l
        steps := steps ++ [obj [("settings", num l)]]
      else if r < 20 then
        let c ← if ← chance 3 4 then genSize enc.settings else pure (enc.settings + 1 + (← rand 10))
        match enc.setCapacity c with
        | some e =>
          enc := e
          steps := steps ++ [obj [("capacity", num c), ("ok", toJson true)]]
        | none => steps := steps ++ [obj [("capacity", num c), ("ok", toJson false)]]
      else if r < 25 then
        huffman := !huffman
        steps := steps ++ [obj [("huffman", toJson huffman)]]
      else
        let mut fs : List Field := []
        let count ← if ← chance 1 50 then pure (maxHeaders + 1) else rand 12
        for _ in [:count] do
          let f ← genEncField seen
          seen := (f.value :: seen).take 16
          fs := fs ++ [f]
        if ← chance 1 100 then
          fs := fs ++ [⟨octets "x-big", List.replicate (maxString + 1) 120, false⟩]
        let fj := Json.arr (fs.map fieldJson).toArray
        if !writable fs then
          steps := steps ++ [obj [("fields", fj), ("error", str "unwritable")]]
        else
          let (ws, enc') := enc.block (rustPolicy huffman) fs
          let bytes := writeBlock ws
          match decodeBlock dec bytes with
          | .ok (decoded, dec') =>
            enc := enc'
            dec := dec'
            steps := steps ++ [obj [("fields", fj), ("output", str (hex bytes)),
              ("size", num enc.dyn.size),
              ("decoded", Json.arr ((retain maxDecoded decoded).1.map fieldJson).toArray),
              ("more", num (retain maxDecoded decoded).2)]]
          | .error e =>
            throw (IO.userError s!"the model's own block does not decode: {errText e}")
    emit (obj [("settings", num settings), ("steps", Json.arr steps.toArray)])

def main (args : List String) : IO Unit := do
  let [dir, seed] := args | throw (IO.userError "expected output directory and seed")
  let some seed := seed.toNat? | throw (IO.userError "seed must be a natural number")
  IO.FS.createDirAll dir
  write dir "int_decode" seed intDecodeVectors
  write dir "int_encode" seed intEncodeVectors
  write dir "huffman_encode" seed huffEncodeVectors
  write dir "huffman_decode" seed huffDecodeVectors
  write dir "blocks" seed blockVectors
  write dir "encoder" seed encoderVectors
