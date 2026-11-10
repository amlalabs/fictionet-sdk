import Http.Framing

/-!
# RFC 9112 message framing, written from the RFC

What any recipient that follows RFC 9112 (with RFC 9110 for fields and
lists) makes of the bytes of an HTTP/1.1 message: where its head ends, how
its body is framed (section 6.3), where a chunked body ends and what it
holds (section 7.1). Nothing here is taken from the Rust code; each
definition cites the text it follows.

The RFC lets recipients differ in a few places. `Choices` names each one,
so a parser here is a whole family: one member per choice of tolerances.
`Http/Smuggling.lean` proves that every member agrees with the server on
every message the server accepts, which is what rules out request
smuggling between the server and any RFC 9112 front end.
-/

namespace Http.Rfc

abbrev Bytes := List Nat

/-! ## Characters (RFC 5234 appendix B.1, RFC 9110 section 5.6) -/

def DIGIT (b : Nat) : Bool := 0x30 ≤ b && b ≤ 0x39
def ALPHA (b : Nat) : Bool := (0x41 ≤ b && b ≤ 0x5A) || (0x61 ≤ b && b ≤ 0x7A)
def HEXDIG (b : Nat) : Bool := DIGIT b || (0x41 ≤ b && b ≤ 0x46) || (0x61 ≤ b && b ≤ 0x66)
def SP : Nat := 0x20
def HTAB : Nat := 0x09
def CR : Nat := 0x0D
def LF : Nat := 0x0A

/-- RFC 9110 section 5.6.2: `tchar = "!" / "#" / "$" / "%" / "&" / "'" /
"*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA`. -/
def tchar (b : Nat) : Bool :=
  [0x21, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2A, 0x2B, 0x2D, 0x2E, 0x5E, 0x5F, 0x60, 0x7C,
    0x7E].contains b || DIGIT b || ALPHA b

/-- `token = 1*tchar`. -/
def token (bs : Bytes) : Bool := bs ≠ [] && bs.all tchar

/-- RFC 9110 section 5.6.3: `OWS = *( SP / HTAB )`. -/
def ows (b : Nat) : Bool := b == SP || b == HTAB

/-- Whitespace in the sense of RFC 9112 section 3: SP, HTAB, VT, FF and bare
CR may all separate the parts of a request line for a recipient that parses
on whitespace. -/
def ws (b : Nat) : Bool := b == SP || b == HTAB || b == 0x0B || b == 0x0C || b == CR

/-- A field value without the optional whitespace around it (RFC 9110
section 5.5: "a field value does not include leading or trailing
whitespace"). -/
def stripOws (bs : Bytes) : Bytes := ((bs.dropWhile ows).reverse.dropWhile ows).reverse

/-- ASCII case-insensitive equality: field names (RFC 9110 section 5.1) and
transfer coding names (RFC 9112 section 7) are case-insensitive. -/
def lowerB (b : Nat) : Nat := if 0x41 ≤ b && b ≤ 0x5A then b + 0x20 else b
def ci (a b : Bytes) : Bool := a.map lowerB == b.map lowerB

def ascii (s : String) : Bytes := s.toUTF8.toList.map (·.toNat)

/-- The elements of a comma-separated list (RFC 9110 section 5.6.1), each
without its optional whitespace. Empty elements stay, so that each rule can
say what it does with them. -/
def elements (bs : Bytes) : List Bytes :=
  let rec go : Bytes → Bytes → List Bytes
    | [], cur => [stripOws cur.reverse]
    | b :: rest, cur => if b == 0x2C then stripOws cur.reverse :: go rest [] else go rest (b :: cur)
  go bs []

def decimalValue (bs : Bytes) : Nat := bs.foldl (fun n b => n * 10 + (b - 0x30)) 0

def hexValue1 (b : Nat) : Nat :=
  if DIGIT b then b - 0x30 else if 0x41 ≤ b && b ≤ 0x46 then b - 0x37 else b - 0x57

def hexValue (bs : Bytes) : Nat := bs.foldl (fun n b => n * 16 + hexValue1 b) 0

/-! ## The tolerances the RFC allows -/

/-- Each place where RFC 9112 or RFC 9110 lets a recipient choose. -/
structure Choices where
  /-- Section 2.2: "a recipient MAY recognize a single LF as a line
  terminator and ignore any preceding CR". -/
  lfAlone : Bool
  /-- Section 2.2: a recipient of a bare CR "MUST consider that element to
  be invalid or replace each bare CR with SP". `true` replaces. -/
  bareCrAsSp : Bool
  /-- Section 2.2: whitespace between the start line and the first field
  line: "MUST either reject the message as invalid or consume each
  whitespace-preceded line without further processing of it". `true`
  consumes. -/
  consumeWsLines : Bool
  /-- Section 5.2: a server that receives an obs-fold "MUST either reject
  the message ... or replace each received obs-fold with one or more SP
  octets". `true` replaces. -/
  unfold : Bool
  /-- Section 2.2: "SHOULD ignore at least one empty line (CRLF) received
  prior to the request-line". The number ignored. -/
  emptyLines : Nat
  /-- Section 3: "recipients MAY instead parse on whitespace-delimited word
  boundaries". -/
  wordsAnyWs : Bool
  /-- Sections 6.1 and 6.3 item 3: with both Transfer-Encoding and
  Content-Length, a server "MAY reject" the request, or "the
  Transfer-Encoding overrides the Content-Length". `true` overrides. -/
  teOverridesCl : Bool
  /-- RFC 9110 section 8.6: a Content-Length "consisting of the same decimal
  value repeated as a comma-separated list" (or in repeated fields, which
  section 5.3 combines into one list) the recipient "MAY either reject the
  message as invalid or replace that invalid field value with a single
  instance of the decimal value". `true` replaces. -/
  clList : Bool

/-! ## Lines (section 2.2) -/

/-- The next line: its content and what follows its terminator, or `none`
if there is no LF yet or the line is invalid under `c`. A line ends at LF
with CR before it, or at a bare LF when `c.lfAlone`. A CR left in the
content is a bare CR: replaced with SP or refused. -/
def line (c : Choices) (bs : Bytes) : Option (Bytes × Bytes) :=
  match bs.findIdx? (· == LF) with
  | none => none
  | some i =>
    let raw := bs.take i
    let rest := bs.drop (i + 1)
    let content :=
      if raw.getLast? == some CR then some raw.dropLast
      else if c.lfAlone then some raw
      else none
    match content with
    | none => none
    | some content =>
      if content.contains CR then
        if c.bareCrAsSp then some (content.map fun b => if b == CR then SP else b, rest)
        else none
      else some (content, rest)

/-- The field lines of a head, after its start line, up to and through the
empty line that ends the head (section 2.1: `*( field-line CRLF ) CRLF`):
the field lines and the bytes after the head. A line that starts with
whitespace right after the start line is consumed or refused (section 2.2);
one after a field line is an obs-fold, unfolded into the field before it or
refused (section 5.2). `fuel` bounds the lines; it is the input's length. -/
def fieldLines (c : Choices) : Nat → Bytes → List Bytes → Option (List Bytes × Bytes)
  | 0, _, _ => none
  | fuel + 1, bs, acc =>
    match line c bs with
    | none => none
    | some (l, rest) =>
      if l.isEmpty then some (acc.reverse, rest)
      else if ows (l.headD 0) then
        match acc with
        | [] => if c.consumeWsLines then fieldLines c fuel rest [] else none
        | prev :: more =>
          if c.unfold then fieldLines c fuel rest ((prev ++ [SP] ++ l.dropWhile ows) :: more)
          else none
      else fieldLines c fuel rest (l :: acc)

/-- Section 5.1: `field-line = field-name ":" OWS field-value OWS`, the name
a token with no whitespace before the colon ("A server MUST reject, with a
response status code of 400 (Bad Request), any received request message
that contains whitespace between a header field name and colon"). -/
def field (l : Bytes) : Option (Bytes × Bytes) :=
  match l.findIdx? (· == 0x3A) with
  | none => none
  | some i =>
    let name := l.take i
    if token name then some (name, stripOws (l.drop (i + 1))) else none

/-- Section 2.3: `HTTP-version = HTTP-name "/" DIGIT "." DIGIT`, with
`HTTP-name = %s"HTTP"`, case-sensitive. The minor version of an HTTP/1.x
message; other majors are not HTTP/1.1 and are refused. -/
def version (bs : Bytes) : Option Nat :=
  match bs with
  | [0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, d] => if DIGIT d then some (d - 0x30) else none
  | _ => none

/-- The words of a request line split at whitespace runs, for
`c.wordsAnyWs`. -/
def words (bs : Bytes) : List Bytes :=
  let rec go : Bytes → Bytes → List Bytes
    | [], cur => if cur.isEmpty then [] else [cur.reverse]
    | b :: rest, cur =>
      if ws b then (if cur.isEmpty then go rest [] else cur.reverse :: go rest [])
      else go rest (b :: cur)
  go bs []

/-- The parts of a request line split at single spaces. -/
def spaces (bs : Bytes) : List Bytes :=
  let rec go : Bytes → Bytes → List Bytes
    | [], cur => [cur.reverse]
    | b :: rest, cur => if b == SP then cur.reverse :: go rest [] else go rest (b :: cur)
  go bs []

/-- Section 3: `request-line = method SP request-target SP HTTP-version`,
with `method = token` and a target with no whitespace in it. The method and
the minor version. -/
def requestLine (c : Choices) (l : Bytes) : Option (Bytes × Nat) :=
  match (if c.wordsAnyWs then words l else spaces l) with
  | [m, t, v] =>
    if token m && t ≠ [] && !t.any ws then (version v).map (m, ·) else none
  | _ => none

/-! ## Framing (section 6) -/

/-- The values of the fields named `name`, in order. Section 5.3 combines
repeated fields into one comma-separated list in this order. -/
def values (fs : List (Bytes × Bytes)) (name : String) : List Bytes :=
  (fs.filter fun (n, _) => ci n (ascii name)).map (·.2)

/-- RFC 9112 section 6.1: `Transfer-Encoding = #transfer-coding`, with
`transfer-coding = token *( OWS ";" OWS transfer-parameter )`. The coding
names in order: the list's non-empty elements (RFC 9110 section 5.6.1: "a
recipient MUST parse and ignore a reasonable number of empty list
elements"), each name before its parameters. -/
def codings (fs : List (Bytes × Bytes)) : List Bytes :=
  ((values fs "transfer-encoding").flatMap elements).filter (· ≠ []) |>.map
    fun e => stripOws (e.takeWhile (· != 0x3B))

/-- RFC 9110 section 8.6: `Content-Length = 1*DIGIT`. The length the field
lines give, or `none` for an invalid value: an element that is not
`1*DIGIT`, elements that differ, or a list at all when `c.clList` is off. -/
def contentLength (c : Choices) (fs : List (Bytes × Bytes)) : Option Nat :=
  let es := (values fs "content-length").flatMap elements
  match es with
  | [] => none
  | e :: rest =>
    if !(es.all fun x => x ≠ [] && x.all DIGIT) then none
    else if rest ≠ [] && !c.clList then none
    else if rest.all (fun x => decimalValue x == decimalValue e) then some (decimalValue e)
    else none

/-- The body framing of a request, section 6.3, for minor version `minor`;
`none` where the RFC has the server refuse the request.

* Item 3: both fields present: refuse, or let Transfer-Encoding override.
* Section 6.1: "A server or client that receives an HTTP/1.0 message
  containing a Transfer-Encoding header field MUST treat the message as if
  the framing is faulty": refused.
* Item 4: "If a Transfer-Encoding header field is present in a request and
  the chunked transfer coding is not the final encoding, the message body
  length cannot be determined reliably; the server MUST respond with the
  400 (Bad Request) status code and then close the connection." Otherwise
  the body is chunked.
* Item 5: an invalid Content-Length: "the server MUST respond with a 400".
* Item 6: a valid Content-Length is the body's length.
* Item 7: "If this is a request message and none of the above are true,
  then the message body length is zero". -/
def requestFraming (c : Choices) (minor : Nat) (fs : List (Bytes × Bytes)) : Option Framing :=
  let te := values fs "transfer-encoding" ≠ []
  let cl := values fs "content-length" ≠ []
  if te then
    if cl && !c.teOverridesCl then none
    else if minor == 0 then none
    else
      match (codings fs).getLast? with
      | some last => if ci last (ascii "chunked") then some .chunked else none
      | none => none
  else if cl then (contentLength c fs).map .length
  else some .empty

/-- The request method's part in response framing. -/
inductive Asked
  | other
  | head
  | connect
  deriving DecidableEq, Repr

/-- The body framing of a response with status `status` to a request of
kind `m`, section 6.3; `none` where the RFC calls the response invalid.

* Item 1: "Any response to a HEAD request and any response with a 1xx
  (Informational), 204 (No Content), or 304 (Not Modified) status code is
  always terminated by the first empty line after the header fields".
* Item 2: "Any 2xx (Successful) response to a CONNECT request implies that
  the connection will become a tunnel immediately after the empty line".
* Item 3: both fields: "the Transfer-Encoding overrides the
  Content-Length", or the message is handled as an error.
* Item 4: "If a Transfer-Encoding header field is present and the chunked
  transfer coding (Section 7.1) is the final encoding, the message body
  length is determined by reading and decoding the chunked data ... If a
  Transfer-Encoding header field is present in a response and the chunked
  transfer coding is not the final encoding, the message body length is
  determined by reading the connection until it is closed by the server."
* Item 5: an invalid Content-Length in a response: "the user agent MUST
  close the connection to the server and discard the received response".
* Items 6 and 8: a valid length, or else the body runs to the close. -/
def responseFraming (c : Choices) (m : Asked) (status : Nat) (fs : List (Bytes × Bytes)) :
    Option Framing :=
  let te := values fs "transfer-encoding" ≠ []
  let cl := values fs "content-length" ≠ []
  if m == .head || status < 200 || status == 204 || status == 304 then some .empty
  else if m == .connect && status < 300 then some .empty
  else if te then
    if cl && !c.teOverridesCl then none
    else
      match (codings fs).getLast? with
      | some last => if ci last (ascii "chunked") then some .chunked else some .close
      | none => some .close
  else if cl then (contentLength c fs).map .length
  else some .close

/-! ## Chunked bodies (section 7.1) -/

/-- A chunk-size line, `chunk-size [ chunk-ext ]`, with
`chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )`:
the size, and nothing but an extension after it. A recipient "MUST ignore
unrecognized chunk extensions" (section 7.1.1), so the extension's content
is not read here; that only makes this parser accept more. -/
def chunkSize (l : Bytes) : Option Nat :=
  let digits := l.takeWhile HEXDIG
  let ext := (l.drop digits.length).dropWhile ows
  if digits.isEmpty then none
  else if ext.isEmpty || ext.headD 0 == 0x3B then some (hexValue digits)
  else none

/-- The trailer section, `*( field-line CRLF ) CRLF`: the bytes after its
empty line. Trailer fields are discarded (section 7.1.2 lets a recipient
do so); each must still be a field line. -/
def trailers (c : Choices) : Nat → Bytes → Option Bytes
  | 0, _ => none
  | fuel + 1, bs =>
    match line c bs with
    | none => none
    | some (l, rest) =>
      if l.isEmpty then some rest
      else if (field l).isSome then trailers c fuel rest
      else none

/-- Section 7.1: `chunked-body = *chunk last-chunk trailer-section CRLF`,
`chunk = chunk-size [ chunk-ext ] CRLF chunk-data CRLF`. The data, in
order, and the bytes after the body. A chunk's data is exactly its size in
bytes, then a line terminator. -/
def chunked (c : Choices) : Nat → Bytes → Option (Bytes × Bytes)
  | 0, _ => none
  | fuel + 1, bs =>
    match line c bs with
    | none => none
    | some (l, rest) =>
      match chunkSize l with
      | none => none
      | some 0 => (trailers c rest.length rest).map ([], ·)
      | some n =>
        if rest.length < n then none
        else
          match line c (rest.drop n) with
          | some ([], after) => (chunked c fuel after).map fun (d, r) => (rest.take n ++ d, r)
          | _ => none

/-- The body of a message with framing `f`: its bytes and what follows. A
close-delimited body is all the rest. -/
def body (c : Choices) (f : Framing) (bs : Bytes) : Option (Bytes × Bytes) :=
  match f with
  | .empty => some ([], bs)
  | .length n => if bs.length < n then none else some (bs.take n, bs.drop n)
  | .chunked => chunked c bs.length bs
  | .close => some (bs, [])

/-! ## A request -/

/-- Up to `k` empty lines before the request line. -/
def skipEmpty (c : Choices) : Nat → Bytes → Bytes
  | 0, bs => bs
  | k + 1, bs =>
    match line c bs with
    | some ([], rest) => skipEmpty c k rest
    | _ => bs

/-- What a recipient makes of a request head at the start of `bs`: where
the head ends (empty lines before it included), the method, the body
framing, and the bytes after the head. -/
structure Head where
  headEnd : Nat
  method : Bytes
  framing : Framing
  rest : Bytes
  deriving DecidableEq, Repr

/-- A request head at the start of `bs`, read as `c` reads it, or `none` if
`c` refuses it or it is not all there. -/
def requestHead (c : Choices) (bs : Bytes) : Option Head :=
  match line c (skipEmpty c c.emptyLines bs) with
  | none => none
  | some (first, afterFirst) =>
    match requestLine c first with
    | none => none
    | some (m, minor) =>
      match fieldLines c afterFirst.length afterFirst [] with
      | none => none
      | some (ls, afterHead) =>
        match ls.mapM field with
        | none => none
        | some fs =>
          match requestFraming c minor fs with
          | none => none
          | some f => some { headEnd := bs.length - afterHead.length, method := m, framing := f,
                             rest := afterHead }

/-- A whole request: its head, its body, and the bytes after the message. -/
structure Request where
  head : Head
  body : Bytes
  rest : Bytes
  deriving DecidableEq, Repr

/-- A request at the start of `bs`, read as `c` reads it. -/
def request (c : Choices) (bs : Bytes) : Option Request :=
  match requestHead c bs with
  | none => none
  | some h =>
    match body c h.framing h.rest with
    | none => none
    | some (b, rest) => some { head := h, body := b, rest }

end Http.Rfc
