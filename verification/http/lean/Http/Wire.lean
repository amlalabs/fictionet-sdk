import Http.Framing

/-!
# The HTTP/1 decoders, byte by byte

The strict request decoder `http1::RequestEvents` (which the server in
`web/httpd/native.rs` runs on every connection) and the response decoder
`http1::ResponseEvents`, as executable functions over bytes. Each
definition names the function of `src/stdlib/protocols/http1.rs` it
follows. `Gen.lean` runs these functions to make the vectors that
`tests/http1_vectors.rs` replays against the Rust decoders, so the two must
agree on every event and on how the stream ends.

Bytes are natural numbers below 256. A decoder here reads its whole input
at once; the Rust decoders read it in pieces, and the replay feeds the
vectors in random pieces to check that the pieces do not matter.
-/

namespace Http.Wire

abbrev Bytes := List Nat

/-! ## Bytes -/

def isDigit (b : Nat) : Bool := 48 ≤ b && b ≤ 57
def isAlpha (b : Nat) : Bool := (65 ≤ b && b ≤ 90) || (97 ≤ b && b ≤ 122)
def isAlnum (b : Nat) : Bool := isDigit b || isAlpha b

/-- `ascii::is_tchar`: RFC 9110 section 5.6.2 `tchar`. -/
def tchar (b : Nat) : Bool :=
  isAlnum b || [33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126].contains b

/-- `field_byte` in `http1.rs`: HTAB, SP, visible ASCII and every byte above
ASCII (`obs-text`), so not CR, LF, NUL, other controls or DEL. -/
def fieldByte (b : Nat) : Bool := b == 9 || (32 ≤ b && b != 127)

/-- `u8::is_ascii_graphic`. -/
def graphic (b : Nat) : Bool := 33 ≤ b && b ≤ 126

/-- SP or HTAB. -/
def isWs (b : Nat) : Bool := b == 32 || b == 9

/-- `token` in `http1.rs`. -/
def token (bs : Bytes) : Bool := !bs.isEmpty && bs.all tchar

/-- `ascii::trim_ows`. -/
def trim (bs : Bytes) : Bytes := ((bs.dropWhile isWs).reverse.dropWhile isWs).reverse

/-- `<[u8]>::split` on one byte: `""` gives `[""]`, `"a,"` gives `["a", ""]`. -/
def splitBy (c : Nat) : Bytes → List Bytes
  | [] => [[]]
  | b :: rest =>
    if b == c then [] :: splitBy c rest
    else
      match splitBy c rest with
      | [] => [[b]]
      | x :: xs => (b :: x) :: xs

/-- ASCII case folding, for `eq_ignore_ascii_case`. -/
def lower (b : Nat) : Nat := if 65 ≤ b && b ≤ 90 then b + 32 else b

def eqCI (a b : Bytes) : Bool := a.map lower == b.map lower

def str (s : String) : Bytes := s.toUTF8.toList.map (·.toNat)

def u64Max : Nat := 18446744073709551615

def digitsValue (radix : Nat) (val : Nat → Nat) (bs : Bytes) : Nat :=
  bs.foldl (fun n b => n * radix + val b) 0

/-- `ascii::decimal(b, usize::MAX, u64::MAX)`: one or more digits whose
value fits in a `u64`, leading zeros allowed. -/
def decimal (bs : Bytes) : Option Nat :=
  if bs.isEmpty || !bs.all isDigit then none
  else
    let n := digitsValue 10 (· - 48) bs
    if n ≤ u64Max then some n else none

def isHex (b : Nat) : Bool := isDigit b || (65 ≤ b && b ≤ 70) || (97 ≤ b && b ≤ 102)

def hexVal (b : Nat) : Nat :=
  if isDigit b then b - 48 else if 65 ≤ b && b ≤ 70 then b - 55 else b - 87

/-- `number(b, 16, _)`: one or more hex digits whose value fits in a `u64`. -/
def hexNumber (bs : Bytes) : Option Nat :=
  if bs.isEmpty || !bs.all isHex then none
  else
    let n := digitsValue 16 hexVal bs
    if n ≤ u64Max then some n else none

/-- `core::str::from_utf8(..).is_ok()`. -/
def utf8 (bs : Bytes) : Bool := ByteArray.validateUTF8 (ByteArray.mk (bs.map UInt8.ofNat).toArray)

def findByte (c : Nat) (bs : Bytes) : Option Nat := bs.findIdx? (· == c)

/-! ## Errors and limits -/

/-- The variants of `http1::Error` the decoders return. -/
inductive Error
  | startLineTooLong
  | headerLineTooLong
  | tooManyHeaders
  | headTooLong
  | lineEnding
  | incomplete
  | startLine
  | version
  | header
  | host
  | contentLength
  | conflictingContentLength
  | transferEncodingAndContentLength
  | transferEncoding
  | chunkedNotLast
  | requestTransferEncoding
  | unsupportedTransferCoding
  | http10TransferEncoding
  | chunkLineTooLong
  | chunkSize
  | chunkExtension
  | chunkEnding
  | trailers
  deriving DecidableEq, Repr

/-- The `Debug` spelling of each variant, which the replay compares. -/
def Error.name : Error → String
  | .startLineTooLong => "StartLineTooLong"
  | .headerLineTooLong => "HeaderLineTooLong"
  | .tooManyHeaders => "TooManyHeaders"
  | .headTooLong => "HeadTooLong"
  | .lineEnding => "LineEnding"
  | .incomplete => "Incomplete"
  | .startLine => "StartLine"
  | .version => "Version"
  | .header => "Header"
  | .host => "Host"
  | .contentLength => "ContentLength"
  | .conflictingContentLength => "ConflictingContentLength"
  | .transferEncodingAndContentLength => "TransferEncodingAndContentLength"
  | .transferEncoding => "TransferEncoding"
  | .chunkedNotLast => "ChunkedNotLast"
  | .requestTransferEncoding => "RequestTransferEncoding"
  | .unsupportedTransferCoding => "UnsupportedTransferCoding"
  | .http10TransferEncoding => "Http10TransferEncoding"
  | .chunkLineTooLong => "ChunkLineTooLong"
  | .chunkSize => "ChunkSize"
  | .chunkExtension => "ChunkExtension"
  | .chunkEnding => "ChunkEnding"
  | .trailers => "Trailers"

/-- `http1::Limits`, without the whole-message limits the event decoders do
not use. The vectors keep every limit far below `Buffer::MAX_LIMIT`, so the
clamp in `Limits::bounded` changes only a zero `bodyChunk`, to one. -/
structure Limits where
  startLine : Nat
  headerLine : Nat
  headers : Nat
  head : Nat
  bodyChunk : Nat
  deriving Repr

/-- `MAX_CHUNK_LINE`. -/
def maxChunkLine : Nat := 128
/-- `MAX_EMPTY_LINES`. -/
def maxEmptyLines : Nat := 8

/-! ## Lines -/

inductive LineErr
  | tooLong
  | bareLf
  deriving DecidableEq, Repr

inductive LineStep
  | need
  | line (r : Except LineErr Bytes) (used : Nat)

/-- `codec::Lines` with `Ending::Crlf`, called as the HTTP decoders call it
(never at the end of input): the first LF within `max + 2` bytes ends a
line, which must have a CR before it and at most `max` bytes before that
CR. No LF within `max + 2` bytes is an overlong line. A CR anywhere else is
part of the line. -/
def lineStep (max : Nat) (input : Bytes) : LineStep :=
  let cap := max + 2
  let stop := min input.length cap
  match findByte 10 (input.take stop) with
  | some i =>
    let cr := i > 0 && input[i - 1]? == some 13
    let content := if cr then i - 1 else i
    if content > max then .line (.error .tooLong) (i + 1)
    else if !cr then .line (.error .bareLf) (i + 1)
    else .line (.ok (input.take content)) (i + 1)
  | none => if stop ≥ cap then .line (.error .tooLong) stop else .need

/-! ## The head: `Reader::head` -/

inductive HeadRes
  | need
  | err (e : Error)
  | done (n : Nat)
  deriving DecidableEq, Repr

/-- The loop of `Reader::head`, from `scanned` bytes of complete lines and
`count` fields. -/
def headLoop (lim : Limits) (input : Bytes) : Nat → Nat → Nat → HeadRes
  | 0, _, _ => .need
  | fuel + 1, scanned, count =>
    let rest := input.drop scanned
    let room := lim.head - scanned
    let window := rest.take room
    let first := scanned == 0
    match lineStep (if first then lim.startLine else lim.headerLine) window with
    | .line (.error .tooLong) _ => .err (if first then .startLineTooLong else .headerLineTooLong)
    | .line (.error .bareLf) _ => .err .lineEnding
    | .line (.ok line) n =>
      if !first && line.isEmpty then .done (scanned + n)
      else if !first && count + 1 > lim.headers then .err .tooManyHeaders
      else headLoop lim input fuel (scanned + n) (if first then count else count + 1)
    | .need =>
      if input.isEmpty && scanned == 0 then .need
      else if window.length == room then .err .headTooLong
      else .need

/-- `Reader::head` from the start of a head: the length of the head, through
its empty line. -/
def readHead (lim : Limits) (input : Bytes) : HeadRes :=
  headLoop lim input (input.length + 1) 0 0

/-! ## Head syntax: `split_head`, `header_parts`, `request_line`, `status_line` -/

/-- `line_end(line, false)`: a line without its CR, which must be there. -/
def stripCr (raw : Bytes) : Option Bytes :=
  if raw.getLast? == some 13 then some raw.dropLast else none

/-- `header_parts(line, false)`: the name before the first colon, which must
be UTF-8, and the value after it without outer whitespace. -/
def headerParts (line : Bytes) : Except Error (Bytes × Bytes) :=
  match findByte 58 line with
  | none => .error .header
  | some colon =>
    let name := line.take colon
    if utf8 name then .ok (name, trim (line.drop (colon + 1))) else .error .header

/-- The field lines of `split_head`, after the start line. -/
def fieldLines : List Bytes → List (Bytes × Bytes) → Except Error (List (Bytes × Bytes))
  | [], _ => .error .incomplete
  | raw :: rest, acc =>
    match stripCr raw with
    | none => .error .lineEnding
    | some line =>
      if line.isEmpty then .ok acc.reverse
      else
        match headerParts line with
        | .error e => .error e
        | .ok f => fieldLines rest (f :: acc)

/-- `split_head(b, false)`: the start line and the fields of a head. -/
def splitHead (b : Bytes) : Except Error (Bytes × List (Bytes × Bytes)) :=
  match splitBy 10 b with
  | [] => .error .lineEnding
  | raw :: rest =>
    match stripCr raw with
    | none => .error .lineEnding
    | some first =>
      match fieldLines rest [] with
      | .error e => .error e
      | .ok fs => .ok (first, fs)

/-- `version`. -/
def parseVersion (b : Bytes) : Except Error Version :=
  if b == str "HTTP/1.0" then .ok .h10
  else if b == str "HTTP/1.1" then .ok .h11
  else .error .version

/-- `request_line(line, false)`: method, target and version, split at single
spaces. -/
def requestLine (line : Bytes) : Except Error (Bytes × Bytes × Version) :=
  match splitBy 32 line with
  | method :: target :: ver :: more =>
    match parseVersion ver with
    | .error e => .error e
    | .ok v =>
      if !more.isEmpty then .error .startLine
      else if !utf8 method || !utf8 target then .error .startLine
      else .ok (method, target, v)
  | _ => .error .startLine

/-- `<[u8]>::splitn(3, ' ')`. -/
def splitn3 (line : Bytes) : List Bytes :=
  match findByte 32 line with
  | none => [line]
  | some i =>
    let rest := line.drop (i + 1)
    match findByte 32 rest with
    | none => [line.take i, rest]
    | some j => [line.take i, rest.take j, rest.drop (j + 1)]

/-- `status_line`. -/
def statusLine (line : Bytes) : Except Error (Version × Nat × Bytes) :=
  match splitn3 line with
  | ver :: rest =>
    match parseVersion ver with
    | .error e => .error e
    | .ok v =>
      match rest with
      | [] => .error .startLine
      | status :: more =>
        if status.length != 3 then .error .startLine
        else
          match decimal status with
          | none => .error .startLine
          | some code =>
            let reason := (more.head?).getD []
            if !(100 ≤ code && code ≤ 599) || !reason.all fieldByte then .error .startLine
            else .ok (v, code, reason)
  | [] => .error .startLine

/-! ## Targets and Host: `validate_target`, `valid_authority`, `validate_host` -/

/-- `ascii::is_uri_reg_name_char`. -/
def regNameChar (b : Nat) : Bool := isAlnum b || (str "-._~!$&'()*+,;=").contains b

/-- `Parser::read_number` of `core::net` over a prefix of `s`: at least one
digit and at most `max` (more is a failure), no leading zero unless
`zeroPrefix`, value at most `bound`. Returns the value and the rest. -/
def readNumber (radix max bound : Nat) (zeroPrefix : Bool) (s : Bytes) : Option (Nat × Bytes) :=
  let digit := fun b => if radix == 16 then isHex b else isDigit b
  let val := fun b => if radix == 16 then hexVal b else b - 48
  let ds := s.takeWhile digit
  if ds.isEmpty || ds.length > max then none
  else if !zeroPrefix && ds.head? == some 48 && ds.length > 1 then none
  else
    let n := digitsValue radix val ds
    if n ≤ bound then some (n, s.drop ds.length) else none

/-- `Parser::read_ipv4_addr`: four decimal octets separated by dots. -/
def readIpv4 (s : Bytes) : Option Bytes :=
  match readNumber 10 3 255 false s with
  | none => none
  | some (_, s) =>
    let rec more : Nat → Bytes → Option Bytes
      | 0, s => some s
      | k + 1, 46 :: s =>
        match readNumber 10 3 255 false s with
        | none => none
        | some (_, s) => more k s
      | _ + 1, _ => none
    more 3 s

/-- `read_separator(':', i, inner)`: a colon first unless `i = 0`. -/
def sep (i : Nat) (s : Bytes) : Option Bytes :=
  if i == 0 then some s else match s with | 58 :: s => some s | _ => none

/-- `read_groups` of `Parser::read_ipv6_addr`: the groups read, whether the
last was an embedded IPv4 address, and the rest. -/
def readGroups (limit : Nat) (s : Bytes) : Nat × Bool × Bytes :=
  let rec go : Nat → Nat → Bytes → Nat × Bool × Bytes
    | 0, i, s => (i, false, s)
    | fuel + 1, i, s =>
      if i ≥ limit then (i, false, s)
      else
        let v4 := if i + 1 < limit then (sep i s).bind readIpv4 else none
        match v4 with
        | some s' => (i + 2, true, s')
        | none =>
          match (sep i s).bind (readNumber 16 4 65535 true) with
          | some (_, s') => go fuel (i + 1) s'
          | none => (i, false, s)
  go (limit + 1) 0 s

/-- `Ipv6Addr::from_str`. -/
def ipv6 (s : Bytes) : Bool :=
  let (head, headV4, s) := readGroups 8 s
  if head == 8 then s.isEmpty
  else if headV4 then false
  else
    match s with
    | 58 :: 58 :: s =>
      let (_, _, s) := readGroups (8 - (head + 1)) s
      s.isEmpty
    | _ => false

/-- `valid_authority`. -/
def validAuthority (value : Bytes) (requirePort : Bool) : Bool :=
  if value.isEmpty || !value.all graphic || value.any (fun b => (str "/@?#,").contains b) then false
  else
    let split : Option (Bytes × Bytes) :=
      if value.head? == some 91 then
        match findByte 93 value with
        | none => none
        | some e =>
          let ip := (value.drop 1).take (e - 1)
          if utf8 ip && ipv6 ip then some (value.take (e + 1), value.drop (e + 1)) else none
      else
        let colonAt := (findByte 58 value).getD value.length
        let host := value.take colonAt
        if host.all (fun b => regNameChar b || b == 37) then some (host, value.drop colonAt)
        else none
    match split with
    | none => false
    | some (host, port) =>
      !host.isEmpty &&
        (if port.isEmpty then !requirePort
         else
           port.head? == some 58 &&
             ((!requirePort && port.length == 1) ||
               (match decimal (port.drop 1) with
                | some n => n ≤ 65535
                | none => false)))

/-- `str::split_once("://")`. -/
def splitScheme : Bytes → Option (Bytes × Bytes)
  | [] => none
  | 58 :: 47 :: 47 :: rest => some ([], rest)
  | b :: rest => (splitScheme rest).map fun (s, r) => (b :: s, r)

/-- `validate_target`. -/
def validTarget (method target : Bytes) : Bool :=
  if !token method || target.isEmpty || !target.all (fun b => graphic b && b != 35) then false
  else if method == str "CONNECT" then validAuthority target true
  else if target == str "*" then method == str "OPTIONS"
  else if target.head? == some 47 then true
  else
    match splitScheme target with
    | some (scheme, rest) =>
      let authority := rest.takeWhile (fun b => b != 47 && b != 63)
      (eqCI scheme (str "http") || eqCI scheme (str "https")) && validAuthority authority false
    | none => false

def named (fs : List (Bytes × Bytes)) (name : String) : List Bytes :=
  (fs.filter fun (n, _) => eqCI n (str name)).map (·.2)

/-- `validate_host`. -/
def validHost (v : Version) (fs : List (Bytes × Bytes)) : Bool :=
  match named fs "host" with
  | [] => v == .h10
  | [h] => h.isEmpty || validAuthority h false
  | _ => false

/-! ## The framing fields: `fields`, `request_framing`, `response_framing` -/

/-- `Fields`. -/
structure Fields where
  length : Option Nat := none
  transfer : Bool := false
  chunked : Bool := false
  unsupported : Bool := false
  close : Bool := false
  deriving DecidableEq, Repr

/-- One list element of `content_length`: a decimal number, equal to the
ones before it. -/
def clStep (acc : Option Nat) (v : Bytes) : Except Error (Option Nat) :=
  match decimal (trim v) with
  | none => .error .contentLength
  | some n => if acc.any (· != n) then .error .conflictingContentLength else .ok (some n)

/-- `content_length`: each list element a decimal number, all equal. -/
def contentLength (value : Bytes) (length : Option Nat) : Except Error (Option Nat) :=
  (splitBy 44 value).foldlM clStep length

/-- One list element of `transfer_encoding`. -/
def teStep (r : Fields) (v : Bytes) : Except Error Fields :=
  let v := trim v
  if v.isEmpty then .ok r
  else if r.chunked then .error .chunkedNotLast
  else if !token v then .error .transferEncoding
  else
    let c := eqCI v (str "chunked")
    .ok { r with transfer := true, chunked := c, unsupported := r.unsupported || !c }

/-- `transfer_encoding`: each non-empty list element a token, none after
`chunked`. -/
def transferEncoding (value : Bytes) (v : Version) (r : Fields) : Except Error Fields :=
  if v == .h10 then .error .http10TransferEncoding
  else (splitBy 44 value).foldlM teStep r

/-- One list element of the `connection` arm of `fields`. -/
def connStep (st : Fields × Bool) (v : Bytes) : Except Error (Fields × Bool) :=
  let v := trim v
  if v.isEmpty then .ok st
  else if !token v then .error .header
  else .ok ({ st.1 with close := st.1.close || eqCI v (str "close") },
    st.2 || eqCI v (str "keep-alive"))

/-- The `connection` arm of `fields`: each non-empty element a token. -/
def connection (value : Bytes) (st : Fields × Bool) : Except Error (Fields × Bool) :=
  (splitBy 44 value).foldlM connStep st

/-- A field line as `fields` checks it: `valid_field`. -/
def validField (n value : Bytes) : Bool := token n && value.all fieldByte && trim value == value

/-- One field of the loop in `fields`, with whether `keep-alive` was named. -/
def fieldStep (v : Version) (st : Fields × Bool) (f : Bytes × Bytes) : Except Error (Fields × Bool) :=
  if !validField f.1 f.2 then .error .header
  else if eqCI f.1 (str "content-length") then
    match contentLength f.2 st.1.length with
    | .error e => .error e
    | .ok l => .ok ({ st.1 with length := l }, st.2)
  else if eqCI f.1 (str "transfer-encoding") then
    match transferEncoding f.2 v st.1 with
    | .error e => .error e
    | .ok r => .ok (r, st.2)
  else if eqCI f.1 (str "connection") then connection f.2 st
  else .ok st

def hasName (fs : List (Bytes × Bytes)) (name : String) : Bool :=
  fs.any fun f => eqCI f.1 (str name)

/-- `fields`. -/
def fields (fs : List (Bytes × Bytes)) (v : Version) : Except Error Fields :=
  let hasTe := hasName fs "transfer-encoding"
  if hasTe && hasName fs "content-length" then .error .transferEncodingAndContentLength
  else
    match fs.foldlM (fieldStep v) ({}, false) with
    | .error e => .error e
    | .ok (r, keep) =>
      if hasTe && !r.transfer then .error .transferEncoding
      else .ok { r with close := r.close || (v == .h10 && !keep) }

/-- `request_framing`. -/
def requestFraming (r : Fields) : Except Error Framing :=
  if r.transfer then
    if !r.chunked then .error .requestTransferEncoding
    else if r.unsupported then .error .unsupportedTransferCoding
    else .ok .chunked
  else .ok (match r.length with | some n => .length n | none => .empty)

/-- `Method` in `http1.rs`: the method classes response framing tells apart. -/
inductive Method
  | other
  | head
  | connect
  deriving DecidableEq, Repr, Inhabited

/-- `response_framing`. -/
def responseFraming (status : Nat) (r : Fields) (m : Method) : Framing :=
  if status < 200 || status == 204 then .empty
  else if m == .head || status == 304 || (m == .connect && 200 ≤ status && status < 300) then .empty
  else if r.chunked then .chunked
  else if r.transfer then .close
  else match r.length with
    | some n => .length n
    | none => .close

/-- A request head as the decoder reports it. -/
structure RequestHead where
  method : Bytes
  target : Bytes
  version : Version
  fields : List (Bytes × Bytes)

/-- `request_syntax(b, false)` then `request_info`: the head, its `Fields`
and its framing, or the refusal `RequestError::reason` names. -/
def requestHead (b : Bytes) : Except Error (RequestHead × Fields × Framing) :=
  match splitHead b with
  | .error e => .error e
  | .ok (line, fs) =>
    match requestLine line with
    | .error e => .error e
    | .ok (method, target, v) =>
      if !validTarget method target then .error .startLine
      else if !validHost v fs then .error .host
      else
        match fields fs v with
        | .error e => .error e
        | .ok r =>
          match requestFraming r with
          | .error e => .error e
          | .ok f => .ok ({ method, target, version := v, fields := fs }, r, f)

/-- `head_size`, as `response_size` calls it with the limits. -/
def responseSize (reason : Bytes) (fs : List (Bytes × Bytes)) (lim : Limits) : Except Error Unit := do
  let start := reason.length + 13
  if start > lim.startLine then throw .startLineTooLong
  if fs.length > lim.headers then throw .tooManyHeaders
  let total ← fs.foldlM (init := start + 4) fun total (n, v) => do
    let line := n.length + 1 + v.length
    if line > lim.headerLine then throw .headerLineTooLong
    pure (total + line + 2)
  if total > lim.head then throw .headTooLong

/-! ## Bodies: `Reader::begin`, `Reader::body`, `chunk_framing` -/

/-- `State` in `http1.rs`, without `Head`, which the decoders below hold as
a separate phase. -/
inductive Body
  | length (n : Nat)
  | size
  | data (n : Nat)
  | dataEnd
  | trailers
  | close
  | done
  | boundary
  | finished
  deriving DecidableEq, Repr

/-- `Reader::begin`: the first body state, and whether the connection ends
after the body. -/
def begin (f : Framing) (close : Bool) : Body × Bool :=
  match f with
  | .empty => (.done, close)
  | .length 0 => (.done, close)
  | .length n => (.length n, close)
  | .chunked => (.size, close)
  | .close => (.close, true)

/-- What a decoder reports. `head` and `done` carry the stream offset where
they end; `body` carries a block's bytes. -/
inductive Event
  | head (method target : Bytes) (v : Version) (status : Nat) (endAt : Nat)
  | body (bytes : Bytes)
  | done (endAt : Nat)
  deriving Repr

/-- How the stream stops: waiting for more input with `consumed` bytes read
(`Stream::next` gives `None` without the end of input), ended cleanly
(`None` after the end of input, or after `Step::End`), `Fail::Truncated`
(the input ended inside a unit), or `Fail::Protocol`. -/
inductive Stop
  | waiting (consumed : Nat)
  | ended (consumed : Nat)
  | truncated
  | failed (e : Error)
  deriving Repr, DecidableEq

/-- One step of `Reader::body` from state `s`, on the unread `input`. -/
inductive BodyStep
  | need
  | fail (e : Error)
  | emit (bytes : Bytes) (next : Body)
  | skip (n : Nat) (next : Body)
  | done
  | finish

/-- The strict chunk framing of `chunk_framing`: a size line, or the CRLF
after a chunk's data or after the last chunk. -/
def chunkStep (s : Body) (input : Bytes) : BodyStep :=
  match s with
  | .size =>
    match lineStep maxChunkLine input with
    | .need => .need
    | .line (.error .tooLong) _ => .fail .chunkLineTooLong
    | .line (.error .bareLf) _ => .fail .lineEnding
    | .line (.ok line) n =>
      if line.contains 59 then .fail .chunkExtension
      else
        match hexNumber line with
        | none => .fail .chunkSize
        | some 0 => .skip n .trailers
        | some k => .skip n (.data k)
  | _ =>
    let trailer := s == .trailers
    let err := if trailer then Error.trailers else Error.chunkEnding
    match input with
    | [] => .need
    | b :: rest =>
      if b != 13 then .fail err
      else
        match rest with
        | [] => .need
        | c :: _ => if c != 10 then .fail err else .skip 2 (if trailer then .done else .size)

/-- `Reader::body` in the body states. -/
def bodyStep (lim : Limits) (s : Body) (input : Bytes) (eof : Bool) : BodyStep :=
  let chunk := max lim.bodyChunk 1
  let step : BodyStep := match s with
    | .finished => .finish
    | .boundary => .finish
    | .done => .done
    | .length left | .data left =>
      let n := min left chunk
      if input.length < n then .need
      else
        let r := left - n
        .emit (input.take n)
          (match s with
           | .length _ => if r == 0 then .done else .length r
           | _ => if r == 0 then .dataEnd else .data r)
    | .close =>
      let n := min input.length chunk
      if n == chunk || (eof && n != 0) then .emit (input.take n) .close
      else if eof then .emit [] .finished
      else .need
    | .size | .dataEnd | .trailers => chunkStep s input
  match step with
  | .need => if eof && input.isEmpty then .fail .incomplete else .need
  | other => other

/-! ## The decoders

A decoder reads one message at a time from the start of the input it is
given: `request1` and `response1` are one message, from wherever the last
one ended, and `requests` and `responses` run them one after another, as
`Stream` does. Every theorem about one message therefore holds for every
message of a pipeline. -/

/-- The stop for a `Step::Need` at offset `pos`. -/
def needStop (input : Bytes) (pos : Nat) (eof : Bool) : Stop :=
  if !eof then .waiting pos
  else if pos ≥ input.length then .ended pos
  else .truncated

/-- How one message ends: done at offset `used`, with the connection going
on to read the next message there, or the stream stops. -/
inductive MsgEnd
  | next (used : Nat)
  | stop (s : Stop)
  deriving Repr, DecidableEq

/-- `Reader::body` until the body is done: from state `s` at offset `pos`,
the events and how the message ends. `close` is whether the connection ends
after this message (`Reader::close`, which `State::Boundary` reads). -/
def runBody (lim : Limits) (input : Bytes) (eof : Bool) (close : Bool) :
    Nat → Body → Nat → List Event × MsgEnd
  | 0, _, pos => ([], .stop (.waiting pos))
  | fuel + 1, s, pos =>
    match bodyStep lim s (input.drop pos) eof with
    | .need => ([], .stop (needStop input pos eof))
    | .fail e => ([], .stop (.failed e))
    | .emit bytes next =>
      if next == .finished then ([.done pos], .stop (.ended pos))
      else
        let (evs, e) := runBody lim input eof close fuel next (pos + bytes.length)
        (.body bytes :: evs, e)
    | .skip n next => runBody lim input eof close fuel next (pos + n)
    | .done => ([.done pos], if close then .stop (.ended pos) else .next pos)
    | .finish => ([], .stop (.ended pos))

/-- How a request's head ends: the stream stops, or the head ends at offset
`endAt` (the empty lines before it included) with its `Fields` and framing. -/
inductive Start
  | stop (s : Stop)
  | head (endAt : Nat) (h : RequestHead) (r : Fields) (f : Framing)

/-- The head part of `RequestEvents::scan_request` from the start of
`input`: up to `MAX_EMPTY_LINES` empty lines, then the head. -/
def requestStart (lim : Limits) (input : Bytes) (eof : Bool) : Start :=
  let rec go : Nat → Nat → Nat → Start
    | 0, pos, _ => .stop (.waiting pos)
    | fuel + 1, pos, empty =>
      let rest := input.drop pos
      if rest == [13] then .stop (needStop input pos eof)
      else if rest.take 2 == [13, 10] then
        if empty ≥ maxEmptyLines then .stop (.failed .startLine)
        else go fuel (pos + 2) (empty + 1)
      else
        match readHead lim rest with
        | .need => .stop (needStop input pos eof)
        | .err e => .stop (.failed e)
        | .done n =>
          match requestHead (rest.take n) with
          | .error e => .stop (.failed e)
          | .ok (h, r, f) => .head (pos + n) h r f
  go (maxEmptyLines + 2) 0 0

/-- One request of `RequestEvents::scan_request` from the start of `input`:
the head, then the body. Every CONNECT ends HTTP after its message. -/
def request1 (lim : Limits) (input : Bytes) (eof : Bool) : List Event × MsgEnd :=
  match requestStart lim input eof with
  | .stop s => ([], .stop s)
  | .head e h r f =>
    let (s, close) := begin f (r.close || h.method == str "CONNECT")
    let (evs, fin) := runBody lim input eof close (input.length + 2) s e
    (.head h.method h.target h.version 0 e :: evs, fin)

def Event.shift (k : Nat) : Event → Event
  | .head m t v st e => .head m t v st (e + k)
  | .body bs => .body bs
  | .done e => .done (e + k)

def Stop.shift (k : Nat) : Stop → Stop
  | .waiting n => .waiting (n + k)
  | .ended n => .ended (n + k)
  | s => s

/-- `RequestEvents` driven by `Stream` over the whole `input`, with the end
of input when `eof`: the events in order, and how the stream stops. -/
def requests (lim : Limits) (input : Bytes) (eof : Bool) : List Event × Stop :=
  let rec go : Nat → Nat → List Event × Stop
    | 0, pos => ([], .waiting pos)
    | fuel + 1, pos =>
      let (evs, e) := request1 lim (input.drop pos) eof
      let evs := evs.map (·.shift pos)
      match e with
      | .next used =>
        let (more, s) := go fuel (pos + used)
        (evs ++ more, s)
      | .stop s => (evs, s.shift pos)
  go (input.length + 1) 0

/-- `Method::parse` for a queued method: the class, or `none` for a name
that is not a token, which `expect_method` refuses. -/
def methodClass (m : Bytes) : Option Method :=
  if !token m then none
  else if m == str "HEAD" then some .head
  else if m == str "CONNECT" then some .connect
  else some .other

/-- The status line and the fields of a response head: `response_head`. -/
def responseHead (b : Bytes) : Except Error (Version × Nat × Bytes × List (Bytes × Bytes) × Fields) :=
  match splitHead b with
  | .error e => .error e
  | .ok (line, fs) =>
    match statusLine line with
    | .error e => .error e
    | .ok (v, code, reason) =>
      match fields fs v with
      | .error e => .error e
      | .ok r => .ok (v, code, reason, fs, r)

/-- One response of `ResponseEvents::scan` (without `skip_chunk_extras`)
from the start of `input`, to a request of class `m`: the events, how it
ends, and whether it was final (status 200 or more), which takes `m` off the
queue. -/
def response1 (lim : Limits) (m : Method) (input : Bytes) (eof : Bool) :
    List Event × MsgEnd × Bool :=
  match readHead lim input with
  | .need => ([], .stop (needStop input 0 eof), false)
  | .err e => ([], .stop (.failed e), false)
  | .done n =>
    match responseHead (input.take n) with
    | .error e => ([], .stop (.failed e), false)
    | .ok (v, code, reason, fs, r) =>
      match responseSize reason fs lim with
      | .error e => ([], .stop (.failed e), false)
      | .ok () =>
        let tunnel := code == 101 || (m == .connect && 200 ≤ code && code < 300)
        let (s, close) := begin (responseFraming code r m) ((code ≥ 200 && r.close) || tunnel)
        let (evs, e) := runBody lim input eof close (input.length + 2) s n
        (.head [] [] v code n :: evs, e, code ≥ 200)

/-- `ResponseEvents` driven by `Stream`, with `methods` queued by
`expect_method` in order. With none queued, a response is framed as one to
GET. -/
def responses (lim : Limits) (methods : List Method) (input : Bytes) (eof : Bool) :
    List Event × Stop :=
  let rec go : Nat → List Method → Nat → List Event × Stop
    | 0, _, pos => ([], .waiting pos)
    | fuel + 1, ms, pos =>
      let (evs, e, final) := response1 lim (ms.head?.getD .other) (input.drop pos) eof
      let evs := evs.map (·.shift pos)
      match e with
      | .next used =>
        let (more, s) := go fuel (if final then ms.drop 1 else ms) (pos + used)
        (evs ++ more, s)
      | .stop s => (evs, s.shift pos)
  go (input.length + 1) methods 0

end Http.Wire

