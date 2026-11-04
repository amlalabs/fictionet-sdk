import Mptcp
import Lean

open Mptcp Lean

def obj (fields : List (String × Json)) : Json := Json.mkObj fields
def num (n : Nat) : Json := toJson n
def nums (ns : List Nat) : Json := toJson ns

def errorText : Mptcp.Error → String
  | .unwritable => "unwritable"
  | .noSubtype => "empty"
  | .tooLong n => s!"long:{n}"
  | .subtype n => s!"subtype:{n}"
  | .length s n => s!"length:{s}:{n}"
  | .noAlgorithm => "algorithm"

def seqFields : Sequence → List Nat
  | .short v => [4, readBe v]
  | .long v => [8, readBe v]

def optNum (v : Option Octets) : List Nat :=
  match v with | none => [0] | some bs => [1, readBe bs]

/-- Semantic fields compared independently of Rust's writer. -/
def fields : Opt → List Nat
  | .capable c =>
    [0, c.version, b2n c.checksumRequired, b2n c.extensibility, b2n c.noNewSubflows, c.algorithms] ++
    (match c.keys with
      | .absent => [0]
      | .sender s => [1, readBe s]
      | .both s r => [2, readBe s, readBe r]
      | .data s r n cs => [3, readBe s, readBe r, readBe n] ++ optNum cs)
  | .join (.syn b a t r) => [1, 0, b2n b, a, readBe t, readBe r]
  | .join (.synAck b a h r) => [1, 1, b2n b, a] ++ h ++ [readBe r]
  | .join (.ack h) => [1, 2] ++ h
  | .dss d => [2, b2n d.dataFin] ++
      (match d.dataAck with | none => [0] | some s => seqFields s) ++
      (match d.mapping with
       | none => [0]
       | some m => seqFields m.dsn ++ [readBe m.subflowSeq, readBe m.dll] ++ optNum m.checksum)
  | .addAddr a => [3, a.addressId] ++
      (match a.address with | .v4 bs => [4] ++ bs | .v6 bs => [16] ++ bs) ++
      optNum a.port ++ (match a.hmac with | none => [0] | some h => [1] ++ h)
  | .removeAddr ids => [4] ++ ids
  | .prio b => [5, b2n b]
  | .fail d => [6, readBe d]
  | .fastClose k => [7, readBe k]
  | .tcpRst t r => [8, b2n t, r]

def codecCase (input : Octets) : Json :=
  match Mptcp.parse input with
  | .error e => obj [("input", nums input), ("error", toJson (errorText e))]
  | .ok o =>
    match emit o with
    | .error e => obj [("input", nums input), ("error", toJson (errorText e))]
    | .ok output => obj [("input", nums input), ("output", nums output), ("fields", nums (fields o))]

def step (n : Nat) : Nat := (n * 6364136223846793005 + 1442695040888963407) % 18446744073709551616

def octets (seed length : Nat) : Octets := Id.run do
  let mut s := seed
  let mut out := []
  for _ in [:length] do
    s := step s
    out := (s / 4294967296 % 256) :: out
  return out.reverse

def codecVectors (seed : Nat) (emit : Json → IO Unit) : IO Unit := do
  emit (codecCase [])
  for first in [:256] do
    emit (codecCase [first])
    let flags := if first / 16 = 2 then List.range 32
                 else if first / 16 = 0 then [0,1,2,3,16,31,32,33,64,65,128,129,255]
                 else [0, seed % 256, 255]
    for f in flags do
      for length in [:41] do
        emit (codecCase (first :: f :: octets (step (seed + first * 256 + f)) length))

def cryptoVectors (seed : Nat) (emit : Json → IO Unit) : IO Unit := do
  let mut s := seed
  for i in [:128] do
    let key := if i = 0 then 0 else if i = 1 then 18446744073709551615 else step s
    let peer := step key
    let a := peer % 4294967296
    let b := step peer % 4294967296
    let data := octets (step peer) (i % 65)
    let dll := data.length + i % 2
    emit (obj [("key", num key), ("peer", num peer), ("a", num a), ("b", num b),
      ("token", num (token key)), ("idsn", num (idsn key)),
      ("hmac", nums (joinHmac key peer a b)), ("data", nums data), ("length", num dll),
      ("checksum", num (dssChecksum key a dll data))])
    s := step peer

def sequenceVectors (seed : Nat) (emit : Json → IO Unit) : IO Unit := do
  let mut s := seed
  let edges := [0,1,2147483647,2147483648,2147483649,4294967295,4294967296,
    4294967297,18446744073709551614,18446744073709551615]
  for near in edges ++ (List.range 128).map (fun i => step (seed + i)) do
    for offset in [0,1,2147483647,2147483648,2147483649,4294967295, s % 4294967296] do
      let low := (near + offset) % 4294967296
      emit (obj [("near", num near), ("low", num low), ("expanded", num (expand near low))])
      s := step s

/-- The option kinds and NOPs in order; payload values are checked by codec vectors. -/
def layoutKinds (linux scale sack timestamp : Bool) (extra : Nat) : List Nat :=
  let ws := if scale then (if linux then [1,3] else [3]) else []
  let sa := if sack then (if linux && !timestamp then [1,1,4] else [4]) else []
  let ts := if timestamp then (if linux && !sack then [1,1,8] else [8]) else []
  [2] ++ (if linux then sa ++ ts ++ ws else ws ++ sa ++ ts) ++ (if extra > 0 then [30] else [])

def layoutVectors (emit : Json → IO Unit) : IO Unit := do
  for linux in [false,true] do
    for scale in [false,true] do
      for sack in [false,true] do
        for timestamp in [false,true] do
          for extra in [0,4,12,16,20] do
            emit (obj [("linux", toJson linux), ("scale", toJson scale),
              ("sack", toJson sack), ("timestamp", toJson timestamp), ("extra", num extra),
              ("length", num (padded (optionSize linux true scale sack timestamp + extra))),
              ("room", num (room linux true scale sack timestamp)),
              ("synBudget", num (room true true true true true)),
              ("segmentBudget", num (room true false false false true)),
              ("ackSegments", num (if linux then 1 else 2)),
              ("ackInclusive", toJson (!linux)),
              ("kinds", nums (layoutKinds linux scale sack timestamp extra))])

def dataVectors (seed : Nat) (emit : Json → IO Unit) : IO Unit := do
  let orders := [[0,1,2], [0,2,1], [1,0,2], [1,2,0], [2,0,1], [2,1,0], [0,0,1], [2,2,0]]
  for order in orders do
    for fin in [0,1,2,3] do
      for position in [:4] do
        for checksums in [false,true] do
          let data := order.map (fun i => (0, i))
          let events := data.take position ++ [(1,fin)] ++ data.drop position ++ [(2,0)]
          let mut s : ReceiveState := {}
          let mut steps := #[]
          for (kind,index) in events do
            s := receive s kind index
            steps := steps.push (obj [("kind",num kind), ("index",num index),
              ("output",nums s.output), ("ack",num (dataAck s)),
              ("error",toJson s.failed), ("fallback",toJson s.fallback)])
          emit (obj [("key",num (step seed)), ("checksums",toJson checksums), ("steps",Json.arr steps)])
  for events in [[(0,0),(0,1),(2,0)], [(0,1),(2,0)], [(3,0),(2,0)], [(1,0),(1,1)]] do
    let mut s : ReceiveState := {}
    let mut steps := #[]
    for (kind,index) in events do
      s := receive s kind index
      steps := steps.push (obj [("kind",num kind), ("index",num index),
        ("output",nums s.output), ("ack",num (dataAck s)),
        ("error",toJson s.failed), ("fallback",toJson s.fallback)])
    emit (obj [("key",num (step seed)), ("checksums",toJson true), ("steps",Json.arr steps)])

def transmitVectors (seed : Nat) (emit : Json → IO Unit) : IO Unit := do
  let key := step seed
  let base := idsn key
  for i in [:65540] do
    let offset := 1 + i * 65535
    emit (obj [("key",num key), ("offset",num offset),
      ("dsn",num ((base + offset) % 18446744073709551616))])
  for i in [65538,65539,65537] do
    let offset := 1 + i * 65535
    emit (obj [("key",num key), ("offset",num offset),
      ("dsn",num ((base + offset) % 18446744073709551616))])

def ipv4Fields : Ipv4.Opt → List Nat
  | .eol => [0]
  | .nop => [1]
  | .route kind pointer slots => [2,kind,pointer] ++ slots
  | .timestamp pointer flags slots => [3,pointer,flags] ++ slots
  | .security data => [4] ++ data
  | .stream data => [5] ++ data
  | .alert data => [6] ++ data
  | .unknown kind data => [7,kind] ++ data
  | .malformed kind data => [8,kind] ++ data

def ipv4Case (input : List Nat) : Json :=
  let options := Ipv4.parse input
  let output := options.flatMap Ipv4.emit
  let malformed := options.any (fun o => match o with | .malformed _ _ => true | _ => false)
  let base := [("input",nums input), ("fields",toJson (options.map ipv4Fields))]
  if malformed || output.length > 40 then obj (base ++ [("error",toJson true)])
  else obj (base ++ [("output",nums output)])

def ipv4Vectors (seed : Nat) (emit : Json → IO Unit) : IO Unit := do
  for input in [[],[0],[1],[0,255],[1,0,255],[7],[7,0],[7,1],[7,8,4],
      [7,3,3,1,0],[68,4,4,0,1,0],[148,4,0,0,136,4,0,1]] do
    emit (ipv4Case input)
  for kind in [:256] do
    for length in [:42] do
      let data := octets (step (seed + kind * 256 + length)) length
      emit (ipv4Case (Ipv4.framed kind data))
  for kind in [7,131,137] do
    for pointer in [0,1,3,4,5,8,39,40,41,255] do
      for length in [:39] do
        emit (ipv4Case (Ipv4.framed kind (pointer :: octets (seed + length) length)))
  for flags in [:256] do
    for pointer in [0,4,5,6,9,41,255] do
      for length in [:38] do
        emit (ipv4Case (Ipv4.framed 68 (pointer :: flags :: octets (seed + flags + length) length)))

def ipv4EchoCase (input host remote : List Nat) (timestamp : Nat) : Json :=
  let base := [("input", nums input), ("local", nums host), ("remote", nums remote),
               ("timestamp", num timestamp)]
  match Ipv4.echo (Ipv4.parse input) host remote (be 4 timestamp) with
  | none => obj (base ++ [("error", toJson true)])
  | some (destination, options) => obj (base ++
      [("destination", toJson destination), ("fields", toJson (options.map ipv4Fields)),
       ("output", nums (options.flatMap Ipv4.emit))])

def ipv4EchoVectors (seed : Nat) (emit : Json → IO Unit) : IO Unit := do
  let host := [192,0,2,1]
  let remote := [198,51,100,2]
  let timestamp := step seed % 86400000
  let send := fun input => emit (ipv4EchoCase input host remote timestamp)
  for input in [[],[0],[1],[7],[7,2],[68,3,5],[7,3,4,7,3,4],
      [68,4,5,0,68,4,5,0],[131,3,4,137,3,4],
      [148,4,0,0,1,136,4,0,1,0,7,3,4],
      [131,7,8,198,51,100,2],
      [131,11,12,198,51,100,2,203,0,113,3]] do
    send input
  for kind in [7,131,137] do
    for pointer in [:256] do
      for count in [:10] do
        send (Ipv4.framed kind (pointer :: octets (seed + count) (4 * count)))
  for flags in [:256] do
    for pointer in [0,4,5,6,8,9,10,12,13,17,21,29,37,40,41,255] do
      for length in [0,4,8,12,16,24,32,36] do
        send (Ipv4.framed 68 (pointer :: flags :: octets (seed + flags + length) length))
  for address in [host,remote,[0,0,0,0],[255,255,255,255],[224,0,0,1]] do
    for pointer in [5,6,9,13,17,21] do
      send (Ipv4.framed 68 ([pointer,3] ++ address ++ [0,0,0,0] ++ host ++ [0,0,0,0]))
  for kind in [:256] do
    send (Ipv4.framed kind (octets (seed + kind) 4))
  for ordering in [[7,68,131],[131,68,7],[68,7,137]] do
    let parts := ordering.map (fun kind => if kind = 68 then
        Ipv4.framed kind ([5,1] ++ octets seed 8)
      else Ipv4.framed kind (8 :: octets seed 8))
    send parts.flatten

def write (dir : System.FilePath) (name : String)
    (generate : (Json → IO Unit) → IO Unit) : IO Unit := do
  IO.FS.withFile (dir / (name ++ ".json")) .write fun handle => do
    let count ← IO.mkRef 0
    handle.putStr "["
    generate fun value => do
      let n ← count.get
      if n > 0 then handle.putStr ","
      handle.putStr value.compress
      count.set (n + 1)
    handle.putStr "]\n"
    IO.println s!"{name}.json: {← count.get} cases"

def main (args : List String) : IO Unit := do
  let [dir, seed] := args | throw (IO.userError "expected output directory and seed")
  let some seed := seed.toNat? | throw (IO.userError "seed must be a natural number")
  IO.FS.createDirAll dir
  write dir "codec" (codecVectors seed)
  write dir "crypto" (cryptoVectors seed)
  write dir "sequence" (sequenceVectors seed)
  write dir "layout" layoutVectors
  write dir "data" (dataVectors seed)
  write dir "transmit" (transmitVectors seed)
  write dir "ipv4" (ipv4Vectors seed)
  write dir "ipv4_echo" (ipv4EchoVectors seed)
