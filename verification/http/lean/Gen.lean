/-
  Test vectors for `tests/http1_vectors.rs`. Every expected value is computed by
  the executable definitions of `Http/Wire.lean`, whose properties
  `Http/Smuggling.lean` proves:

  * `requests.json`: `Wire.requests`, the strict request decoder the server runs;
  * `responses.json`: `Wire.responses`, the response decoder, with a queue of
    request methods.

  Usage: `lake exe gen <dir> <seed>`. The output depends only on the seed.

  Each input is built from parts that reach every rule of the decoders (start
  lines, framing fields, chunked bodies, pipelines, leading empty lines, limits),
  then sometimes cut short or given one wrong byte. The bytes are a JSON array.
-/
import Http.Wire
import Http.Request
import Lean

open Http Http.Wire Lean

/-! ## Randomness (splitmix64) -/

structure Rng where
  s : UInt64

def Rng.next (r : Rng) : UInt64 × Rng :=
  let s := r.s + 0x9E3779B97F4A7C15
  let z := (s ^^^ (s >>> 30)) * 0xBF58476D1CE4E5B9
  let z := (z ^^^ (z >>> 27)) * 0x94D049BB133111EB
  (z ^^^ (z >>> 31), ⟨s⟩)

abbrev G := StateM Rng

def rand : G UInt64 := modifyGet fun r => r.next
def rNat (n : Nat) : G Nat := do
  if n == 0 then return 0
  return (← rand).toNat % n
def chance (k : Nat) : G Bool := do return (← rNat k) == 0
def pick {α : Type} [Inhabited α] (xs : Array α) : G α := do return xs[← rNat xs.size]!

/-! ## Parts -/

def methods : Array String :=
  #["GET", "GET", "POST", "POST", "PUT", "HEAD", "CONNECT", "OPTIONS", "get", "G T", "",
    "GE(T", "M\x7f", "PATCH", "X-Y~"]

def targets : Array String :=
  #["/", "/", "/a?b=c", "/x/y", "*", "http://h.test/x", "HTTPS://h.test:8443/?q",
    "http://[::1]:80/", "http://[::ffff:192.0.2.1]/", "http://[1::2::3]/", "http://[::1/",
    "http://u@h/", "http://h:99999/", "http://h:/", "ftp://h/", "a.test:443", "[::1]:443",
    "a.test", "h:", "/a#b", "", "/\x7f", "/é", "http://h%41/", "http://[1:2:3:4:5:6:7:8]/",
    "http://[::1.2.3.04]/", "http://[1:2:3:4:5:6:1.2.3.4]/"]

def versions : Array String :=
  #["HTTP/1.1", "HTTP/1.1", "HTTP/1.1", "HTTP/1.0", "HTTP/1.2", "http/1.1", "HTTP/2.0",
    "HTTP/1.1 ", "HTTP/1"]

def hosts : Array String :=
  #["a.test", "a.test", "a.test:8080", "[::1]", "[::1]:80", "", "a b", "a.test:x", "a@b",
    "[zz]", "a.test:65536", "x_y.test"]

def lengths : Array String :=
  #["0", "3", "3", "003", "3, 3", "3,3", "3,4", "", "+3", "-1", "3 3", "0x3", " 3 ",
    "18446744073709551615", "18446744073709551616", "1,", ",1", "5"]

def codings : Array String :=
  #["chunked", "chunked", "chunked", "Chunked", "gzip, chunked", "chunked, gzip",
    "chunked,chunked", ",chunked,", " , chunked", "chunked;q=1", "identity", "", " ", "gzip",
    "chunked , ", "x y"]

def connections : Array String :=
  #["close", "keep-alive", "Upgrade", "close, x", "a b", "", ", ,", "Keep-Alive, Close"]

def others : Array String :=
  #["Accept: */*", "X-Empty:", "X-Tab:\tv\t", "X-High: \xc3\xa9", "Expect: 100-continue",
    "Upgrade: websocket", "X: a:b"]

/-- Field lines that break the field syntax. -/
def badLines : Array Bytes :=
  #[str " folded", str "\tfolded", str "Host : a", str "Bad Name: x", str "NoColon",
    str ": empty", [88, 58, 32, 97, 13, 98], [88, 58, 0], [88, 58, 32, 127], [0xff, 58, 32, 120],
    [0xc3, 0xa9, 58, 32, 120], str "X:\x01"]

def crlf : Bytes := [13, 10]

def line (s : Bytes) : Bytes := s ++ crlf

/-- The part of a message that is written wrongly, if any. One fault per
message keeps every rule reachable: a message with many faults fails at the
first. -/
inductive Fault
  | none | method | target | version | space | host | twoHosts | length | lengths
  | coding | codings | both | chunkSize | chunkEnd | lastChunk | trailer | fieldLine
  | connection | status | reason
  deriving BEq, Inhabited

def faults : Array Fault :=
  #[.none, .none, .none, .none, .none, .method, .target, .version, .space, .host, .twoHosts,
    .length, .lengths, .coding, .codings, .both, .chunkSize, .chunkEnd, .lastChunk, .trailer,
    .fieldLine, .connection]

/-- A chunked body; `fault` writes one of its parts wrongly. -/
def chunked (fault : Fault) : G Bytes := do
  let n ← rNat 4
  let wrong ← rNat (n + 1)
  let mut out : Bytes := []
  for i in [0:n] do
    let size ← pick #[1, 2, 3, 10, 17, 26]
    let hex := (Nat.toDigits 16 size).map (·.toNat)
    let mine := i == wrong
    let sizeLine ← if mine && fault == .chunkSize then
        pick #[str "0" ++ hex, hex ++ str ";x=1", hex ++ str " ;x", hex ++ str " ", str " " ++ hex,
          str "", str "ffffffffffffffffff", str "10000000000000000",
          (hex.map fun b => if 97 ≤ b then b - 32 else b), str "g", str "+1", str "0x1"]
      else pure hex
    let ending ← if mine && fault == .chunkEnd then pick #[[10], [13], [13, 13]] else pure crlf
    let after ← if mine && fault == .chunkEnd then pick #[[10], [], str "xx", [13]] else pure crlf
    out := out ++ sizeLine ++ ending ++ List.replicate size 120 ++ after
  let last ← if fault == .lastChunk then pick #[str "0;x", str "00", str "0 ", str "000"]
    else pure (str "0")
  out := out ++ line last
  if fault == .trailer then out := out ++ line (← pick #[str "X-Trailer: v", str "bad trailer"])
  let close ← if fault == .trailer && (← chance 2) then pick #[[10], [13], str "x"] else pure crlf
  return out ++ close

/-- The framing a message's fault needs: 0 none, 1 Content-Length,
2 chunked, 3 both fields; with no fault, any of the first three. -/
def framingFor (fault : Fault) : G Nat :=
  if fault == .both then pure 3
  else if [Fault.coding, .codings, .chunkSize, .chunkEnd, .lastChunk, .trailer].contains fault then
    pure 2
  else if fault == .length || fault == .lengths then pure 1
  else rNat 3

/-- A request, with at most one fault. -/
def request : G Bytes := do
  let fault ← pick faults
  let m ← if fault == .method then pick methods
    else pick #["GET", "GET", "POST", "PUT", "OPTIONS", "CONNECT", "HEAD"]
  let t ← if fault == .target then pick targets
    else if m == "CONNECT" then pure "a.test:443"
    else if m == "OPTIONS" && (← chance 2) then pure "*"
    else pick #["/", "/a?b=c", "http://h.test/x", "https://[::1]:8443/"]
  let framing ← framingFor fault
  let v ← if fault == .version then pick versions
    else if framing ≥ 2 then pure "HTTP/1.1"
    else pick #["HTTP/1.1", "HTTP/1.1", "HTTP/1.1", "HTTP/1.0"]
  let sp ← if fault == .space then pick #["  ", "\t", " \t"] else pure " "
  let mut fields : List Bytes := []
  if fault == .host then fields := fields ++ [str ("Host: " ++ (← pick hosts))]
  else if v == "HTTP/1.1" || (← chance 2) then fields := fields ++ [str "Host: a.test"]
  if fault == .twoHosts then fields := fields ++ [str (← pick #["Host: b.test", "host: a.test"])]
  let mut body : Bytes := []
  if framing == 1 then
    let (l, k) ← if fault == .length || fault == .lengths then
        pick #[("0", 0), ("003", 3), ("3, 3", 3), ("3,3", 3), ("3,4", 3), ("", 0), ("+3", 3),
          ("-1", 0), ("3 3", 3), ("0x3", 3), (" 3 ", 3), ("18446744073709551616", 0), ("1,", 1),
          (",1", 1), ("3,,3", 3)]
      else pick #[("0", 0), ("3", 3), ("5", 5), ("12", 12)]
    fields := fields ++ [str ("Content-Length: " ++ l)]
    body := List.replicate k 97
    if fault == .lengths then
      fields := fields ++ [str ("content-length: " ++ (← pick #["3", "4", "03", "x"]))]
  if framing == 2 then
    let c ← if fault == .coding then pick codings else pure (← pick #["chunked", "Chunked", "CHUNKED"])
    fields := fields ++ [str ("Transfer-Encoding: " ++ c)]
    if fault == .codings then
      fields := fields ++ [str ("Transfer-Encoding: " ++ (← pick #["chunked", "gzip", "", ","]))]
    body ← chunked fault
  if fault == .both then
    let te := str "Transfer-Encoding: chunked"
    let cl := str "Content-Length: 3"
    fields := fields ++ (if ← chance 2 then [te, cl] else [cl, te])
    body ← chunked .none
  if fault == .connection then fields := fields ++ [str ("Connection: " ++ (← pick connections))]
  else if ← chance 5 then fields := fields ++ [str (← pick #["Connection: keep-alive", "Connection: close"])]
  if ← chance 3 then fields := fields ++ [str (← pick others)]
  if fault == .fieldLine then
    let pos ← rNat (fields.length + 1)
    fields := fields.take pos ++ [← pick badLines] ++ fields.drop pos
  let start := str m ++ str sp ++ str t ++ str " " ++ str v
  return line start ++ (fields.flatMap line) ++ crlf ++ body

def responseFaults : Array Fault :=
  #[.none, .none, .none, .none, .version, .length, .lengths, .coding, .codings, .both, .chunkSize,
    .chunkEnd, .lastChunk, .trailer, .fieldLine, .connection, .status, .reason]

/-- A response, with at most one fault. -/
def response : G Bytes := do
  let fault ← pick responseFaults
  let code ← if fault == .status then pick #["199", "600", "20", "2000", "abc", "099", "-20"]
    else pick #["200", "200", "200", "100", "101", "103", "204", "304", "404", "500"]
  let framing ← framingFor fault
  let framing ← if framing == 0 && (← chance 3) then pure 4 else pure framing
  let v ← if fault == .version then pick versions
    else if framing == 2 || framing == 3 then pure "HTTP/1.1"
    else pick #["HTTP/1.1", "HTTP/1.1", "HTTP/1.0"]
  let reason ← if fault == .reason then pick #[" a\x01", " a\x7f"]
    else pick #[" OK", "", " ", " Not\tFound", " \xc3\xa9"]
  let mut fields : List Bytes := []
  let mut body : Bytes := []
  if framing == 1 then
    let (l, k) ← if fault == .length || fault == .lengths then
        pick #[("003", 3), ("3, 3", 3), ("3,4", 3), ("", 0), ("+3", 3), ("x", 0)]
      else pick #[("0", 0), ("3", 3), ("5", 5)]
    fields := fields ++ [str ("Content-Length: " ++ l)]
    body := List.replicate k 98
    if fault == .lengths then fields := fields ++ [str (← pick #["Content-Length: 3", "Content-Length: 4"])]
  if framing == 2 then
    let c ← if fault == .coding then pick codings else pure "chunked"
    fields := fields ++ [str ("Transfer-Encoding: " ++ c)]
    if fault == .codings then
      fields := fields ++ [str ("Transfer-Encoding: " ++ (← pick #["chunked", "gzip", ""]))]
    body ← chunked fault
  if framing == 4 then body := List.replicate (← rNat 5) 99
  if fault == .both then
    fields := fields ++ [str "Transfer-Encoding: chunked", str "Content-Length: 3"]
    body ← chunked .none
  if fault == .connection then fields := fields ++ [str ("Connection: " ++ (← pick connections))]
  else if ← chance 5 then fields := fields ++ [str "Connection: close"]
  if fault == .fieldLine then fields := fields ++ [← pick badLines]
  return line (str v ++ str " " ++ str code ++ str reason) ++ (fields.flatMap line) ++ crlf ++ body

def byteValues : Array Nat := #[0, 9, 10, 13, 32, 44, 58, 59, 48, 97, 127, 0xff]

/-- Cuts the input short, or changes one byte, or neither. -/
def mutate (input : Bytes) : G Bytes := do
  match ← rNat 8 with
  | 0 => return input.take (← rNat (input.length + 1))
  | 1 =>
    if input.isEmpty then return input
    let pos ← rNat input.length
    let b ← if ← chance 2 then pick byteValues else rNat 256
    return input.set pos b
  | 2 =>
    let pos ← rNat (input.length + 1)
    return input.take pos ++ [← pick byteValues] ++ input.drop pos
  | _ => return input

def defaults : Limits :=
  { startLine := 8192, headerLine := 8192, headers := 100, head := 65536, bodyChunk := 8192 }

/-- The default limits, or small ones that the inputs reach. -/
def limits : G Limits := do
  if !(← chance 6) then return { defaults with bodyChunk := ← pick #[8192, 1, 2, 5] }
  return { startLine := 10 + (← rNat 30), headerLine := 8 + (← rNat 24),
           headers := ← rNat 6, head := 30 + (← rNat 120), bodyChunk := ← rNat 9 }


/-! ## JSON -/

def nums (bs : Bytes) : Json := toJson bs

def versionName : Version → String
  | .h10 => "HTTP/1.0"
  | .h11 => "HTTP/1.1"

def eventJson : Event → Json
  | .head m t v status e => Json.mkObj [("head", Json.mkObj
      [("method", nums m), ("target", nums t), ("version", toJson (versionName v)),
       ("status", toJson status), ("end", toJson e)])]
  | .body bs => Json.mkObj [("body", nums bs)]
  | .done e => Json.mkObj [("done", toJson e)]

def stopJson : Stop → Json
  | .waiting n => Json.mkObj [("waiting", toJson n)]
  | .ended n => Json.mkObj [("ended", toJson n)]
  | .truncated => Json.mkObj [("truncated", toJson true)]
  | .failed e => Json.mkObj [("failed", toJson e.name)]

def limitsJson (l : Limits) : Json :=
  Json.mkObj [("start_line", toJson l.startLine), ("header_line", toJson l.headerLine),
    ("headers", toJson l.headers), ("head", toJson l.head), ("body_chunk", toJson l.bodyChunk)]

def methodName : Method → String
  | .other => "GET"
  | .head => "HEAD"
  | .connect => "CONNECT"

def caseJson (l : Limits) (ms : List Method) (input : Bytes) (eof : Bool)
    (r : List Event × Stop) : Json :=
  Json.mkObj [("limits", limitsJson l), ("methods", toJson (ms.map methodName)),
    ("input", nums input), ("eof", toJson eof),
    ("events", Json.arr (r.1.map eventJson).toArray), ("stop", stopJson r.2)]

/-! ## Cases -/

/-- Inputs written out by hand: the smuggling shapes of RFC 9112 section 11.2
and the edges of each rule, before the random ones. -/
def fixedRequests : List Bytes :=
  let h := "Host: a.test\r\n"
  [ "GET / HTTP/1.1\r\n" ++ h ++ "\r\n",
    "POST / HTTP/1.1\r\n" ++ h ++ "Content-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    "POST / HTTP/1.1\r\n" ++ h ++ "Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\n",
    "POST / HTTP/1.1\r\n" ++ h ++ "Transfer-Encoding: xchunked\r\n\r\n",
    "POST / HTTP/1.1\r\n" ++ h ++ "Transfer-Encoding : chunked\r\n\r\n",
    "POST / HTTP/1.1\r\n" ++ h ++ "Transfer-Encoding:\x0bchunked\r\n\r\n",
    "POST / HTTP/1.1\r\n" ++ h ++ "Transfer-Encoding: chunked\r\n \r\n\r\n0\r\n\r\n",
    "POST / HTTP/1.1\r\n" ++ h ++ "Content-Length: 1\r\nContent-Length: 2\r\n\r\nab",
    "POST / HTTP/1.1\r\n" ++ h ++ "Content-Length: 1\r\nContent-Length: 1\r\n\r\naGET / HTTP/1.1\r\n" ++ h ++ "\r\n",
    "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    "POST / HTTP/1.1\r\n" ++ h ++ "Transfer-Encoding: chunked\r\n\r\n1;a=b\r\nx\r\n0\r\n\r\n",
    "POST / HTTP/1.1\r\n" ++ h ++ "Transfer-Encoding: chunked\r\n\r\n1\nx\r\n0\r\n\r\n",
    "POST / HTTP/1.1\r\n" ++ h ++ "Transfer-Encoding: chunked\r\n\r\n10000000000000000\r\n",
    "POST / HTTP/1.1\r\n" ++ h ++ "Transfer-Encoding: chunked\r\n\r\n0\r\nX: y\r\n\r\n",
    "GET / HTTP/1.1\n" ++ h ++ "\r\n",
    "GET / HTTP/1.1\r\nHost: a.test\n\r\n",
    "GET / HTTP/1.1\r\nHost: a\rtest\r\n\r\n",
    "GET /\r HTTP/1.1\r\n" ++ h ++ "\r\n",
    "\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\nGET / HTTP/1.1\r\n" ++ h ++ "\r\n",
    "\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\nGET / HTTP/1.1\r\n" ++ h ++ "\r\n",
    "\n" ++ "GET / HTTP/1.1\r\n" ++ h ++ "\r\n",
    "CONNECT a.test:443 HTTP/1.1\r\n" ++ h ++ "\r\nraw tunnel bytes",
    "CONNECT a.test:443 HTTP/1.1\r\n" ++ h ++ "Content-Length: 2\r\n\r\nabtunnel",
    "GET / HTTP/1.1\r\n" ++ h ++ "Connection: close\r\n\r\nGET / HTTP/1.1\r\n" ++ h ++ "\r\n",
    "GET / HTTP/1.0\r\n\r\nGET / HTTP/1.0\r\n\r\n",
    "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET / HTTP/1.0\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: a.test\r\nHost: a.test\r\n\r\n",
    "GET / HTTP/1.1\r\n\r\n",
    "GET http://[::1]:8080/x HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n",
    "OPTIONS * HTTP/1.1\r\n" ++ h ++ "\r\n",
    "GET * HTTP/1.1\r\n" ++ h ++ "\r\n",
    "\r",
    "" ].map str

def fixedResponses : List (List Method × Bytes) :=
  [ ([.other], "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab"),
    ([.head], "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"),
    ([.connect], "HTTP/1.1 200 OK\r\n\r\ntunnel"),
    ([.other], "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\nframes"),
    ([.other], "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n"),
    ([.other], "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nuntil close"),
    ([.other], "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"),
    ([.other], "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n"),
    ([.other], "HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"),
    ([.other], "HTTP/1.0 200 OK\r\n\r\nall of it"),
    ([.other], "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"),
    ([.other], "HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n") ].map fun (ms, s) => (ms, str s)

def requestVectors (seed : Nat) (emit : Json → IO Unit) : IO Unit := do
  for input in fixedRequests do
    for eof in [false, true] do
      emit (caseJson defaults [] input eof (requests defaults input eof))
  let mut rng : Rng := ⟨seed.toUInt64⟩
  for _ in [0:6000] do
    let ((l, input, eof), r) := (do
      let l ← limits
      let empty ← if ← chance 8 then rNat 10 else pure 0
      let count ← pick #[1, 1, 2, 3]
      let mut input := (List.replicate empty crlf).flatten
      for _ in [0:count] do input := input ++ (← request)
      let cut ← mutate input
      let eof ← chance 2
      return (l, cut, eof) : G _).run rng
    rng := r
    emit (caseJson l [] input eof (requests l input eof))

def responseVectors (seed : Nat) (emit : Json → IO Unit) : IO Unit := do
  for (ms, input) in fixedResponses do
    for eof in [false, true] do
      emit (caseJson defaults ms input eof (responses defaults ms input eof))
  let mut rng : Rng := ⟨(seed + 0x5bd1e995).toUInt64⟩
  for _ in [0:4000] do
    let ((l, ms, input, eof), r) := (do
      let l ← limits
      let count ← pick #[1, 1, 2, 3]
      let mut ms : List Method := []
      let mut input : Bytes := []
      for _ in [0:count] do
        let m ← pick #[Method.other, .other, .head, .connect]
        ms := ms ++ [m]
        input := input ++ (← response)
      let cut ← mutate input
      let eof ← chance 2
      return (l, ms, cut, eof) : G _).run rng
    rng := r
    emit (caseJson l ms input eof (responses l ms input eof))

/-! ## `framing.json`: the rules of `Request.lean` -/

def rejectName : Http.Reject → String
  | .transferEncodingAndContentLength => "TransferEncodingAndContentLength"
  | .contentLength => "ContentLength"
  | .conflictingContentLength => "ConflictingContentLength"
  | .http10TransferEncoding => "Http10TransferEncoding"
  | .chunkedNotLast => "ChunkedNotLast"
  | .transferEncoding => "TransferEncoding"
  | .requestTransferEncoding => "RequestTransferEncoding"
  | .unsupportedTransferCoding => "UnsupportedTransferCoding"

/-- List elements written into one or two field lines named `name`, with
empty elements here and there when `empties` (for `Transfer-Encoding`:
`Request.lean` reads an empty `Content-Length` element as an invalid one,
so none is written there). -/
def listFields (name : String) (elems : List String) (empties : Bool) : G (List Bytes) := do
  let mut parts : List String := []
  for e in elems do
    if empties && (← chance 5) then parts := parts ++ [""]
    parts := parts ++ [e]
  if parts.isEmpty then parts := [← pick #["", ",", " "]]
  let cut ← rNat (parts.length + 1)
  let one := ", ".intercalate (parts.take cut)
  let two := ", ".intercalate (parts.drop cut)
  let lines := (if cut == 0 then [] else [one]) ++ (if cut == parts.length then [] else [two])
  let lines := if lines.isEmpty then [""] else lines
  return lines.map fun l => str (name ++ ": " ++ l)

/-- A request head written from the abstract framing fields of
`Request.lean`, and what `Http.requestFraming` says of them: the body the
decoder must then read, or the refusal. -/
def framingCase : G Json := do
  let v : Version := if ← chance 3 then .h10 else .h11
  let te ← if ← chance 2 then pure none else do
    let k ← rNat 4
    let mut cs : List Bool := []
    for _ in [0:k] do cs := cs ++ [← chance 2]
    pure (some cs)
  let cl ← if ← chance 2 then pure none else do
    let k ← pick #[1, 1, 2, 3]
    let n ← pick #[0, 3, 5]
    let mut ls : List (Option Nat) := []
    for _ in [0:k] do
      let bad ← chance 6
      let other ← chance 6
      ls := ls ++ [if bad then none else if other then some (n + 1) else some n]
    pure (some ls)
  let mut fields : List Bytes := [str "Host: a.test"]
  if let some cs := te then
    let names ← cs.mapM fun c => if c then pure "chunked" else pick #["gzip", "deflate", "x-custom"]
    fields := fields ++ (← listFields "Transfer-Encoding" names true)
  if let some ls := cl then
    let names := ls.map fun l => match l with | some n => toString n | none => "x1"
    let cls ← listFields "Content-Length" names false
    fields := if ← chance 2 then fields ++ cls else cls ++ fields
  let start := str ("POST / " ++ (if v == .h10 then "HTTP/1.0" else "HTTP/1.1"))
  let head := line start ++ fields.flatMap line ++ crlf
  let expected := Http.requestFraming v te cl
  let (body, expect) : Bytes × Json := match expected with
    | .error rej => ([], Json.mkObj [("error", toJson (rejectName rej))])
    | .ok .empty => ([], Json.mkObj [("body", nums [])])
    | .ok (.length n) => (List.replicate n 97, Json.mkObj [("body", nums (List.replicate n 97))])
    | .ok .chunked => (str "3\r\nabc\r\n0\r\n\r\n", Json.mkObj [("body", nums (str "abc"))])
    | .ok .close => ([], Json.mkObj [("body", nums [])])
  return Json.mkObj [("input", nums (head ++ body)), ("expect", expect)]

def framingVectors (seed : Nat) (emit : Json → IO Unit) : IO Unit := do
  let mut rng : Rng := ⟨(seed + 0x2545F491).toUInt64⟩
  for _ in [0:4000] do
    let (j, r) := framingCase.run rng
    rng := r
    emit j

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
  write dir "requests" (requestVectors seed)
  write dir "responses" (responseVectors seed)
  write dir "framing" (framingVectors seed)
