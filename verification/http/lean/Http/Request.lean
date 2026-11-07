import Http.Framing

namespace Http

/-!
The request framing an HTTP/1 server applies, from `http1::fields` and
`http1::request_framing` in `src/stdlib/protocols/http1.rs`, and the status
`Http1::on_fail` in `httpd/native.rs` answers a refused head with. The
theorems are the rules of RFC 9112 sections 6.1 and 6.3 for requests.

Empty `Transfer-Encoding` list elements are skipped by `fields`, so a coding
list here holds only the codings that were named, with `true` for `chunked`.
A `Content-Length` list element is parsed by `ascii::decimal`, which refuses
an empty element, so each is `some n` or `none` for one that is not a number.
Header names are tokens and values are field bytes here; `fields` refuses
others before it reads them.
-/

/-- Why `fields` or `request_framing` refuses a head, as `http1::Error`. -/
inductive Reject
  | transferEncodingAndContentLength
  | contentLength
  | conflictingContentLength
  | http10TransferEncoding
  | chunkedNotLast
  | transferEncoding
  | requestTransferEncoding
  | unsupportedTransferCoding
  deriving DecidableEq, Repr

/-- The status `Http1::on_fail` answers with: 501 for a transfer coding the
server does not implement, 400 for every other refusal. -/
def Reject.status : Reject → Nat
  | .unsupportedTransferCoding => 501
  | _ => 400

/-- The `transfer-encoding` arm of the loop in `fields`, over the codings in
order: `c` is `result.chunked`, `u` is `result.unsupported_transfer_coding`.
Returns them for the list, or the refusal of a coding after `chunked`. -/
def scanCodings : List Bool → Bool → Bool → Except Reject (Bool × Bool)
  | [], c, u => .ok (c, u)
  | x :: rest, c, u => if c then .error .chunkedNotLast else scanCodings rest x (u || !x)

/-- The `content-length` arm of the loop in `fields`: every element is a
number, and all are the same number. -/
def scanLengths : List (Option Nat) → Option Nat → Except Reject (Option Nat)
  | [], acc => .ok acc
  | none :: _, _ => .error .contentLength
  | some n :: rest, acc =>
    if acc.any (· != n) then .error .conflictingContentLength else scanLengths rest (some n)

/-- `fields` then `request_framing` for a head with a `Transfer-Encoding`
field and no `Content-Length`. -/
def codingsFraming (v : Version) (codings : List Bool) : Except Reject Framing :=
  if v == .h10 then .error .http10TransferEncoding
  else
    match scanCodings codings false false with
    | .error e => .error e
    | .ok (chunked, unsupported) =>
      if codings.isEmpty then .error .transferEncoding
      else if !chunked then .error .requestTransferEncoding
      else if unsupported then .error .unsupportedTransferCoding
      else .ok .chunked

/-- `fields` then `request_framing`: the body framing of a request head with
version `v`, the named transfer codings `te` (`none` without the field) and
the `Content-Length` elements `cl` (`none` without the field). -/
def requestFraming (v : Version) (te : Option (List Bool)) (cl : Option (List (Option Nat))) :
    Except Reject Framing :=
  match te, cl with
  | some _, some _ => .error .transferEncodingAndContentLength
  | none, none => .ok .empty
  | none, some lengths =>
    match scanLengths lengths none with
    | .error e => .error e
    | .ok (some n) => .ok (.length n)
    | .ok none => .ok .empty
  | some codings, none => codingsFraming v codings

/-- RFC 9112 section 6.3 item 3: a request with both fields is refused. -/
theorem both_fields_refused (v : Version) (te : List Bool) (cl : List (Option Nat)) :
    requestFraming v (some te) (some cl) = .error .transferEncodingAndContentLength := by
  rfl

/-- RFC 9112 section 6.1: an HTTP/1.0 message with `Transfer-Encoding` is
refused as faulty framing. -/
theorem http10_transfer_encoding_refused (te : List Bool) :
    requestFraming .h10 (some te) none = .error .http10TransferEncoding := by
  simp [requestFraming, codingsFraming]

theorem scan_codings_after_chunked (xs : List Bool) (y : Bool) (ys : List Bool) (c u : Bool) :
    scanCodings (xs ++ true :: y :: ys) c u = .error .chunkedNotLast := by
  induction xs generalizing c u with
  | nil => cases c <;> simp [scanCodings]
  | cons x xs ih => cases c <;> simp [scanCodings, ih]

/-- RFC 9112 section 6.1: `chunked` that is not the final coding is refused
with 400, whatever comes before or after it. -/
theorem chunked_not_final_refused (xs : List Bool) (y : Bool) (ys : List Bool) :
    requestFraming .h11 (some (xs ++ true :: y :: ys)) none = .error .chunkedNotLast
      ∧ Reject.chunkedNotLast.status = 400 := by
  simp [requestFraming, codingsFraming, scan_codings_after_chunked, Reject.status]

theorem scan_codings_without_chunked (k : Nat) (c u : Bool) :
    scanCodings (List.replicate (k + 1) false) c u
      = if c then .error .chunkedNotLast else .ok (false, true) := by
  induction k generalizing c u with
  | zero => cases c <;> simp [scanCodings]
  | succ k ih =>
    rw [List.replicate_succ, scanCodings]
    cases c <;> simp [ih]

/-- RFC 9112 section 6.1: a request whose codings do not end in `chunked`
has no reliable length and is refused with 400. -/
theorem no_chunked_refused (k : Nat) :
    requestFraming .h11 (some (List.replicate (k + 1) false)) none
      = .error .requestTransferEncoding
      ∧ Reject.requestTransferEncoding.status = 400 := by
  simp [requestFraming, codingsFraming, scan_codings_without_chunked, Reject.status]

/-- A `Transfer-Encoding` field naming no coding is refused. -/
theorem empty_codings_refused :
    requestFraming .h11 (some []) none = .error .transferEncoding := by
  rfl

/-- RFC 9112 section 6.1: `chunked` as the only coding frames the body by
its chunks. -/
theorem chunked_alone_is_chunked : requestFraming .h11 (some [true]) none = .ok .chunked := by
  rfl

theorem scan_codings_others_then_chunked (k : Nat) (u : Bool) :
    scanCodings (List.replicate k false ++ [true]) false u = .ok (true, u || decide (0 < k)) := by
  induction k generalizing u with
  | zero => simp [scanCodings]
  | succ k ih => simp [List.replicate, scanCodings, ih]

/-- RFC 9112 section 6.1: a coding the server does not implement before the
final `chunked` is refused with 501. -/
theorem unsupported_coding_refused (k : Nat) :
    requestFraming .h11 (some (List.replicate (k + 1) false ++ [true])) none
      = .error .unsupportedTransferCoding
      ∧ Reject.unsupportedTransferCoding.status = 501 := by
  simp [requestFraming, codingsFraming, scan_codings_others_then_chunked, Reject.status]

theorem scan_lengths_same (k : Nat) (n : Nat) (acc : Option Nat) (h : acc = none ∨ acc = some n) :
    scanLengths (List.replicate k (some n)) acc = .ok (if k = 0 then acc else some n) := by
  induction k generalizing acc with
  | zero => simp [scanLengths]
  | succ k ih =>
    rcases h with rfl | rfl
    · simp [List.replicate, scanLengths, ih (some n) (.inr rfl)]
    · simp [List.replicate, scanLengths, ih (some n) (.inr rfl)]

/-- RFC 9112 section 6.3 item 5: one `Content-Length`, or several with the
same value, gives the body that many bytes. -/
theorem same_lengths_accepted (v : Version) (k n : Nat) :
    requestFraming v none (some (List.replicate (k + 1) (some n))) = .ok (.length n) := by
  simp [requestFraming, scan_lengths_same (k + 1) n none (.inl rfl)]

/-- RFC 9112 section 6.3 item 4: differing `Content-Length` values are
refused. -/
theorem differing_lengths_refused (v : Version) (a b : Nat) (rest : List (Option Nat))
    (h : a ≠ b) :
    requestFraming v none (some (some a :: some b :: rest)) = .error .conflictingContentLength := by
  simp [requestFraming, scanLengths, h]

theorem scan_lengths_with_invalid (l : List (Option Nat)) (acc : Option Nat) (h : none ∈ l) :
    ∃ e, scanLengths l acc = .error e := by
  induction l generalizing acc with
  | nil => simp at h
  | cons x rest ih =>
    cases x with
    | none => exact ⟨_, rfl⟩
    | some m =>
      have hrest : none ∈ rest := by simpa using h
      by_cases hc : acc.any (· != m)
      · exact ⟨.conflictingContentLength, by simp [scanLengths, hc]⟩
      · obtain ⟨e, he⟩ := ih (some m) hrest
        exact ⟨e, by simp [scanLengths, hc, he]⟩

/-- RFC 9112 section 6.3 item 4: a `Content-Length` list with an element
that is not a number is refused. -/
theorem invalid_length_refused (v : Version) (l : List (Option Nat)) (h : none ∈ l) :
    ∃ e, requestFraming v none (some l) = .error e := by
  obtain ⟨e, he⟩ := scan_lengths_with_invalid l none h
  exact ⟨e, by simp [requestFraming, he]⟩

theorem scan_lengths_same_then_invalid (xs rest : List (Option Nat)) (n : Nat)
    (h : ∀ x ∈ xs, x = some n) (acc : Option Nat) (hacc : acc = none ∨ acc = some n) :
    scanLengths (xs ++ none :: rest) acc = .error .contentLength := by
  induction xs generalizing acc with
  | nil => simp [scanLengths]
  | cons x xs ih =>
    have hx : x = some n := h x (by simp)
    subst hx
    have hrest : ∀ y ∈ xs, y = some n := fun y hy => h y (by simp [hy])
    rcases hacc with rfl | rfl <;> simp [scanLengths, ih hrest (some n) (.inr rfl)]

/-- The refusal names the element that is not a number when the elements
before it agree. -/
theorem invalid_length_after_same_refused (v : Version) (xs rest : List (Option Nat)) (n : Nat)
    (h : ∀ x ∈ xs, x = some n) :
    requestFraming v none (some (xs ++ none :: rest)) = .error .contentLength := by
  simp [requestFraming, scan_lengths_same_then_invalid xs rest n h none (.inl rfl)]

/-- RFC 9112 section 6.3 item 7: a request with neither field has no body. -/
theorem no_fields_no_body (v : Version) : requestFraming v none none = .ok .empty := by
  rfl

end Http
