namespace Http

/-!
The response framing of `src/stdlib/web/httpd`: the shared length policy
in `httpd/response.rs`, the HTTP/1 head writer and body writer in
`httpd/native.rs`, and the HTTP/2 head writer (`Respond::start` in
`httpd/http2/respond.rs`). Each
definition names the Rust it follows. The theorems are the rules of
RFC 9110 sections 8.6 and 9.3.6, RFC 9112 section 6, and RFC 9113
section 8.1, and the agreement between what the server writes and what an
RFC 9112 reader (`http1::response_framing`) makes of it.
-/

/-- `Asked` in `response.rs`: what the request's method asks of the body. -/
inductive Asked
  | body
  | head
  | tunnel
  deriving DecidableEq, Repr

/-- A response status, by the classes the framing rules tell apart. 101 is
informational too; it stands apart only for the `Connection` line. -/
inductive Status
  | informational
  | switching
  | success
  | noContent
  | redirectOrError
  | notModified
  deriving DecidableEq, Repr

/-- The handler's `Content-Length` field as `ResponsePolicy::new` and
`http2::content_length` read it: absent, a valid number, or unparsable. -/
inductive Supplied
  | none
  | valid (n : Nat)
  | invalid
  deriving DecidableEq, Repr

/-- The body's `size_hint().exact()`. -/
inductive Hint
  | exact (n : Nat)
  | unknown
  deriving DecidableEq, Repr

/-- `ResponsePolicy` in `response.rs`. -/
structure Policy where
  bodiless : Bool
  len : Option Nat
  deriving DecidableEq, Repr

def Status.isInformational : Status → Bool
  | .informational | .switching => true
  | _ => false

def Status.isSuccess : Status → Bool
  | .success | .noContent => true
  | _ => false

def Hint.len : Hint → Option Nat
  | .exact n => some n
  | .unknown => none

/-- The `no_body` test in `ResponsePolicy::new`. -/
def noBody (st : Status) (asked : Asked) : Bool :=
  st.isInformational || st == .noContent || st == .notModified
    || (asked == .tunnel && st.isSuccess)

/-- The length `ResponsePolicy::new` picks for a response that has a body
or whose HEAD head stands for one. -/
def policyLen (hint : Hint) (asked : Asked) (supplied : Supplied) : Option Nat :=
  if asked == .head then
    match supplied with
    | .valid n => some n
    | _ => hint.len
  else hint.len

/-- `ResponsePolicy::new`. -/
def policy (st : Status) (hint : Hint) (asked : Asked) (supplied : Supplied) : Policy :=
  { bodiless := asked == .head || noBody st asked,
    len := if noBody st asked then none else policyLen hint asked supplied }

/-- The body bytes the server writes after the head: none when the policy
says bodiless, else what the body yields (`Http1::start` and
`Respond::start` both drop the body when `policy.bodiless`). -/
def written (p : Policy) (actual : Nat) : Nat :=
  if p.bodiless then 0 else actual

/-- A body keeps the `http_body` contract: an exact size hint is the number
of bytes it yields. -/
def Hint.yields : Hint → Nat → Prop
  | .exact n, actual => actual = n
  | .unknown, _ => True

theorem policy_no_body (st : Status) (hint : Hint) (asked : Asked) (supplied : Supplied)
    (h : noBody st asked = true) :
    policy st hint asked supplied = { bodiless := true, len := none } := by
  simp [policy, h]

/-- A response with a body is to a GET-like request and not to one of the
statuses defined to have none, and its length is the body's. -/
theorem not_bodiless (st : Status) (hint : Hint) (asked : Asked) (supplied : Supplied)
    (h : (policy st hint asked supplied).bodiless = false) :
    asked ≠ .head ∧ noBody st asked = false ∧ st ≠ .notModified
      ∧ (policy st hint asked supplied).len = hint.len := by
  cases st <;> cases asked <;> simp_all [policy, policyLen, noBody, Status.isInformational,
    Status.isSuccess]

-- HTTP/1 ---------------------------------------------------------------------

inductive Version
  | h10
  | h11
  deriving DecidableEq, Repr

/-- The `Connection` line `native::encode` writes. -/
inductive ConnectionLine
  | none
  | close
  | keepAlive
  | upgrade
  deriving DecidableEq, Repr

/-- The framing fields of an HTTP/1 response head, as `native::encode`
writes them, and whether the connection closes after the body. -/
structure Head1 where
  contentLength : Option Nat
  chunked : Bool
  connection : ConnectionLine
  close : Bool
  deriving DecidableEq, Repr

/-- The `match policy.len` in `native::encode`: a body with no length is
chunked on HTTP/1.1 and ends with the connection on HTTP/1.0. -/
def unknownLength (p : Policy) : Bool :=
  p.len == none && !p.bodiless

/-- Whether `native::encode` closes the connection after the response:
`close` is the request's close decision from `Http1::dispatch`,
`handlerClose` whether the handler's `Connection` field names `close`. -/
def closeAfter (v : Version) (st : Status) (p : Policy) (close handlerClose : Bool) : Bool :=
  close || (st != .switching && handlerClose) || (unknownLength p && v == .h10)

/-- The `Connection` line `native::encode` writes when the connection
closes (`c`) or not. -/
def connectionLine (v : Version) (st : Status) (c : Bool) : ConnectionLine :=
  if st == .switching then .upgrade
  else if c && v != .h10 then .close
  else if !c && v == .h10 then .keepAlive
  else .none

/-- `native::encode`. -/
def encode1 (v : Version) (st : Status) (p : Policy) (close handlerClose : Bool) : Head1 :=
  { contentLength := p.len,
    chunked := unknownLength p && v == .h11,
    connection := connectionLine v st (closeAfter v st p close handlerClose),
    close := closeAfter v st p close handlerClose }

/-- `http1::Framing`: how a reader delimits the body. -/
inductive Framing
  | empty
  | length (n : Nat)
  | chunked
  | close
  deriving DecidableEq, Repr

/-- The responses `http1::response_framing` reads no body for: RFC 9112
section 6.3 items 1 and 2. -/
def readerNoBody (method : Asked) (st : Status) : Bool :=
  st.isInformational || st == .noContent || method == .head || st == .notModified
    || (method == .tunnel && st.isSuccess)

/-- `http1::response_framing`, the RFC 9112 section 6.3 rules a client
applies to a response head given the method it sent. -/
def readerFraming (method : Asked) (st : Status) (h : Head1) : Framing :=
  if readerNoBody method st then .empty
  else if h.chunked then .chunked
  else
    match h.contentLength with
    | some n => .length n
    | none => .close

/-- The reader's "no body" rule names the same responses as the policy's. -/
theorem reader_no_body_is_bodiless (st : Status) (asked : Asked) (hint : Hint)
    (supplied : Supplied) :
    readerNoBody asked st = (policy st hint asked supplied).bodiless := by
  cases st <;> cases asked <;> rfl

/-- `http1::fields`: whether a reader of the head expects the connection
to close after this response. -/
def readerClose (v : Version) (h : Head1) : Bool :=
  match v with
  | .h11 => h.connection == .close
  | .h10 => h.connection != .keepAlive

/-- What the reader's framing means for the body bytes it accepts. -/
def Framing.delimits (f : Framing) (v : Version) (h : Head1) (bytes : Nat) : Prop :=
  match f with
  | .empty => bytes = 0
  | .length n => bytes = n
  | .chunked => v = .h11
  | .close => h.close = true

/-- The HTTP/1 writer and an RFC 9112 reader agree on where the body ends:
the reader takes exactly the bytes the server writes, and a body with no
length ends with the connection the server closes. -/
theorem reader_agrees (v : Version) (st : Status) (hint : Hint) (asked : Asked)
    (supplied : Supplied) (close handlerClose : Bool) (actual : Nat)
    (hy : hint.yields actual) :
    Framing.delimits
      (readerFraming asked st (encode1 v st (policy st hint asked supplied) close handlerClose))
      v (encode1 v st (policy st hint asked supplied) close handlerClose)
      (written (policy st hint asked supplied) actual) := by
  have hr := reader_no_body_is_bodiless st asked hint supplied
  by_cases hb : (policy st hint asked supplied).bodiless = true
  · simp [readerFraming, Framing.delimits, written, hr, hb]
  · have hb' : (policy st hint asked supplied).bodiless = false := by simpa using hb
    obtain ⟨_, _, _, hlen⟩ := not_bodiless st hint asked supplied hb'
    cases v <;> cases hint <;> simp_all [readerFraming, encode1, unknownLength, closeAfter,
      written, Framing.delimits, Hint.len, Hint.yields]

/-- RFC 9110 section 8.6: no `Content-Length` in a 1xx or 204 response;
RFC 9112 section 6.1: no `Transfer-Encoding` in them either. -/
theorem no_length_on_informational_or_204 (v : Version) (st : Status) (hint : Hint)
    (asked : Asked) (supplied : Supplied) (close handlerClose : Bool)
    (hs : (st.isInformational || st == .noContent) = true) :
    (encode1 v st (policy st hint asked supplied) close handlerClose).contentLength = none
      ∧ (encode1 v st (policy st hint asked supplied) close handlerClose).chunked = false := by
  have : noBody st asked = true := by simp [noBody, hs]
  simp [encode1, unknownLength, policy_no_body st hint asked supplied this]

/-- RFC 9110 section 9.3.6: no `Transfer-Encoding` or `Content-Length` in a
2xx response to CONNECT. -/
theorem connect_success_has_no_framing (v : Version) (st : Status) (hint : Hint)
    (supplied : Supplied) (close handlerClose : Bool) (hs : st.isSuccess = true) :
    (encode1 v st (policy st hint .tunnel supplied) close handlerClose).contentLength = none
      ∧ (encode1 v st (policy st hint .tunnel supplied) close handlerClose).chunked = false := by
  have : noBody st .tunnel = true := by simp [noBody, hs]
  simp [encode1, unknownLength, policy_no_body st hint .tunnel supplied this]

/-- RFC 9112 section 6.1: never both `Content-Length` and `Transfer-Encoding`. -/
theorem never_both (v : Version) (st : Status) (p : Policy) (close handlerClose : Bool) :
    ¬ ((encode1 v st p close handlerClose).contentLength.isSome
      ∧ (encode1 v st p close handlerClose).chunked) := by
  cases hl : p.len <;> simp [encode1, unknownLength, hl]

/-- RFC 9112 section 6.1: an HTTP/1.0 reader knows no transfer coding. -/
theorem http10_never_chunked (st : Status) (p : Policy) (close handlerClose : Bool) :
    (encode1 .h10 st p close handlerClose).chunked = false := by
  simp [encode1]

/-- RFC 9112 section 6.3 item 8: an HTTP/1.0 body of unknown length ends
with the connection, so the server closes it. -/
theorem http10_unknown_length_closes (st : Status) (p : Policy) (close handlerClose : Bool)
    (hb : p.bodiless = false) (hl : p.len = none) :
    (encode1 .h10 st p close handlerClose).close = true := by
  simp [encode1, closeAfter, unknownLength, hb, hl]

/-- RFC 9112 section 6.1: an HTTP/1.1 body that is not bodiless is
delimited by a length or by chunks, never by the connection alone. -/
theorem http11_body_is_delimited (st : Status) (p : Policy) (close handlerClose : Bool)
    (hb : p.bodiless = false) :
    (encode1 .h11 st p close handlerClose).contentLength.isSome
      ∨ (encode1 .h11 st p close handlerClose).chunked = true := by
  cases hl : p.len <;> simp [encode1, unknownLength, hb, hl]

/-- RFC 9110 section 9.3.2: the head of a HEAD response is the head a GET
would get when the handler sets no length of its own, so the lengths match. -/
theorem head_length_is_get_length (v : Version) (st : Status) (hint : Hint)
    (close handlerClose : Bool) :
    (encode1 v st (policy st hint .head .none) close handlerClose).contentLength
      = (encode1 v st (policy st hint .body .none) close handlerClose).contentLength := by
  cases st <;> simp [encode1, policy, policyLen, noBody, Status.isInformational, Status.isSuccess]

/-- A handler that drops the HEAD body may name the GET length itself. -/
theorem head_keeps_supplied_length (v : Version) (st : Status) (hint : Hint) (n : Nat)
    (close handlerClose : Bool) (h : noBody st .head = false) :
    (encode1 v st (policy st hint .head (.valid n)) close handlerClose).contentLength = some n := by
  simp [encode1, policy, policyLen, h]

/-- The reader's close expectation is the server's close decision, for every
response but the 101 that hands the connection on. -/
theorem reader_close_agrees (v : Version) (st : Status) (p : Policy) (close handlerClose : Bool)
    (hs : st ≠ .switching) :
    readerClose v (encode1 v st p close handlerClose) = (encode1 v st p close handlerClose).close := by
  have : (st == .switching) = false := by simpa using hs
  simp only [encode1, readerClose]
  generalize closeAfter v st p close handlerClose = c
  cases v <;> cases c <;> simp [connectionLine, this]

-- HTTP/2 ---------------------------------------------------------------------

/-- The framing of an HTTP/2 response as `Respond::start` writes it: the
`content-length` field, END_STREAM on the HEADERS frame, and the DATA
payload bytes that follow. -/
structure Head2 where
  contentLength : Option Nat
  endStream : Bool
  data : Nat
  deriving DecidableEq, Repr

/-- The `content-length` field `Respond::start` writes: the handler's
value when it is valid and agrees with the policy or the status is 304, else
the policy's length. -/
def contentLength2 (st : Status) (p : Policy) (supplied : Supplied) : Option Nat :=
  match supplied with
  | .valid n => if p.len == some n || st == .notModified then some n else p.len
  | _ => p.len

/-- `Respond::start` (`httpd/http2/respond.rs`) from `ResponsePolicy::new` to the HEADERS frame.
`endsNow` is `body.is_end_stream()` when the head is written. -/
def headers2 (st : Status) (hint : Hint) (asked : Asked) (supplied : Supplied)
    (endsNow : Bool) (actual : Nat) : Head2 :=
  { contentLength := contentLength2 st (policy st hint asked supplied) supplied,
    endStream := (policy st hint asked supplied).bodiless || endsNow,
    data := written (policy st hint asked supplied) actual }

/-- A body that says it has ended yields nothing. -/
def endsNowYields (endsNow : Bool) (actual : Nat) : Prop :=
  endsNow = true → actual = 0

theorem content_length2_with_body (st : Status) (p : Policy) (supplied : Supplied)
    (hs : st ≠ .notModified) : contentLength2 st p supplied = p.len := by
  have : (st == .notModified) = false := by simpa using hs
  cases supplied with
  | valid n => by_cases hp : p.len = some n <;> simp [contentLength2, this, hp]
  | none => rfl
  | invalid => rfl

/-- RFC 9110 section 8.6 for HTTP/2: no `content-length` in a 1xx or 204
response. -/
theorem no_length_on_informational_or_204_h2 (st : Status) (hint : Hint) (asked : Asked)
    (supplied : Supplied) (endsNow : Bool) (actual : Nat)
    (hs : (st.isInformational || st == .noContent) = true) :
    (headers2 st hint asked supplied endsNow actual).contentLength = none := by
  have hn : noBody st asked = true := by simp [noBody, hs]
  have hs' : st ≠ .notModified := by
    cases st <;> simp_all [Status.isInformational]
  simp [headers2, policy_no_body st hint asked supplied hn, content_length2_with_body _ _ _ hs']

/-- RFC 9110 section 9.3.6 for HTTP/2: no `content-length` in a 2xx response
to CONNECT, and the HEADERS frame ends the stream since the server does not
tunnel. -/
theorem connect_success_has_no_length_h2 (st : Status) (hint : Hint) (supplied : Supplied)
    (endsNow : Bool) (actual : Nat) (hs : st.isSuccess = true) :
    (headers2 st hint .tunnel supplied endsNow actual).contentLength = none
      ∧ (headers2 st hint .tunnel supplied endsNow actual).endStream = true
      ∧ (headers2 st hint .tunnel supplied endsNow actual).data = 0 := by
  have hn : noBody st .tunnel = true := by simp [noBody, hs]
  have hs' : st ≠ .notModified := by
    cases st <;> simp_all [Status.isSuccess]
  simp [headers2, written, policy_no_body st hint .tunnel supplied hn,
    content_length2_with_body _ _ _ hs']

/-- RFC 9113 section 8.1: END_STREAM on the HEADERS frame means no DATA follows. -/
theorem end_stream_means_no_data (st : Status) (hint : Hint) (asked : Asked)
    (supplied : Supplied) (endsNow : Bool) (actual : Nat)
    (he : endsNowYields endsNow actual)
    (hend : (headers2 st hint asked supplied endsNow actual).endStream = true) :
    (headers2 st hint asked supplied endsNow actual).data = 0 := by
  simp only [headers2, written] at hend ⊢
  by_cases hb : (policy st hint asked supplied).bodiless = true
  · simp [hb]
  · simp_all [endsNowYields]

/-- RFC 9113 section 8.1.1: a `content-length` is the sum of the DATA
payloads, unless the message has no content. -/
theorem length_matches_data (st : Status) (hint : Hint) (asked : Asked) (supplied : Supplied)
    (endsNow : Bool) (actual : Nat) (n : Nat) (hy : hint.yields actual)
    (hb : (policy st hint asked supplied).bodiless = false)
    (hl : (headers2 st hint asked supplied endsNow actual).contentLength = some n) :
    (headers2 st hint asked supplied endsNow actual).data = n := by
  obtain ⟨_, _, hs, hlen⟩ := not_bodiless st hint asked supplied hb
  simp only [headers2, written, hb] at hl ⊢
  rw [content_length2_with_body _ _ _ hs, hlen] at hl
  cases hint <;> simp_all [Hint.len, Hint.yields]

/-- Bodiless responses end the stream on their HEADERS frame. -/
theorem bodiless_ends_stream (st : Status) (hint : Hint) (asked : Asked) (supplied : Supplied)
    (endsNow : Bool) (actual : Nat) (hb : (policy st hint asked supplied).bodiless = true) :
    (headers2 st hint asked supplied endsNow actual).endStream = true := by
  simp [headers2, hb]

/-- The HTTP/2 head of a HEAD response carries the length the GET would,
when the handler sets no length of its own. -/
theorem head_length_is_get_length_h2 (st : Status) (hint : Hint) (endsNow : Bool)
    (actual : Nat) :
    (headers2 st hint .head .none endsNow actual).contentLength
      = (headers2 st hint .body .none endsNow actual).contentLength := by
  cases st <;> simp [headers2, contentLength2, policy, policyLen, noBody, Status.isInformational,
    Status.isSuccess]

/-- The documented HTTP/2 exception: on 304 a valid handler length is kept,
since it describes the selected representation. -/
theorem not_modified_keeps_supplied_length (hint : Hint) (asked : Asked) (n : Nat)
    (endsNow : Bool) (actual : Nat) :
    (headers2 .notModified hint asked (.valid n) endsNow actual).contentLength = some n := by
  simp [headers2, contentLength2]

/-- Before the fix, `Sending` carried only `head_only: bool`, so a CONNECT
request reached the policy as `Asked::Body`. This is the mapping it applied. -/
def askedBeforeFix : Asked → Asked
  | .head => .head
  | _ => .body

/-- The bug the model exposed: with the old mapping, a 2xx to CONNECT with a
four-byte body went out with `content-length: 4` and DATA, against
RFC 9110 section 9.3.6. -/
theorem connect_leaked_length_before_fix :
    (headers2 .success (.exact 4) (askedBeforeFix .tunnel) .none false 4).contentLength = some 4
      ∧ (headers2 .success (.exact 4) (askedBeforeFix .tunnel) .none false 4).endStream = false
      ∧ (headers2 .success (.exact 4) (askedBeforeFix .tunnel) .none false 4).data = 4 := by
  decide

end Http
