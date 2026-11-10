/-
  The checks a received TLS record passes before it is decrypted or parsed: its content type,
  its legacy version, its length, and empty fragments.

  `check` is the rule, as RFC 8446 (TLS 1.3) and RFC 5246 (TLS 1.2) set it, with one rule of
  rustls's own (`badVersion`). The Rust code it describes, in the vendored rustls at
  `rustls/src`:

  * `msgs/message/outbound.rs`, `read_opaque_message_header`: unknown type, version, empty
    fragment, and the 2^14 + 2048 header limit;
  * `msgs/deframer/mod.rs`, `DeframerIter::next`: maps those to errors (record_overflow for the
    length);
  * `record_layer.rs`, `decrypt_incoming`: an unprotected record of more than 2^14 bytes;
  * `conn.rs`, `process_more_input`: an unprotected record taken in TLS 1.3 (change_cipher_spec)
    held to 2^14, and a protected TLS 1.3 record of more than 2^14 + 256 bytes, both before
    decryption;
  * `msgs/message/mod.rs`, `MessagePayload::new`, with `error.rs`'s
    `From<InvalidMessage> for AlertDescription`: a heartbeat record that reaches parsing.

  `Gen.lean` writes vectors of `check` that `rustls/src/budget/record_vectors.rs` replays against
  a real server connection in each read state.
-/
namespace TlsRecord

/-- The read state a record arrives in: before any keys, or under TLS 1.2 or TLS 1.3 traffic
keys. -/
inductive Prot where
  | plain
  | tls12
  | tls13
deriving DecidableEq, Repr, Inhabited

/-- What the record layer does with a record before decryption. -/
inductive Verdict where
  /-- Passes: an unprotected record goes on to parsing, a protected one to decryption. -/
  | accept
  /-- record_overflow: RFC 8446 sections 5.1 and 5.2, RFC 5246 sections 6.2.1 to 6.2.3. -/
  | recordOverflow
  /-- unexpected_message for a record type it does not know: RFC 8446 section 5, RFC 5246
  section 6. -/
  | unexpectedType
  /-- rustls's own rule: the legacy record version's high byte must be 3. RFC 8446 section 5.1
  says legacy_record_version "MUST be ignored for all purposes"; rustls refuses other values
  to tell TLS from other protocols early. A deliberate departure. -/
  | badVersion
  /-- A zero-length fragment of a type other than application data: RFC 8446 section 5.1,
  RFC 5246 section 6.2.1. -/
  | emptyFragment
deriving DecidableEq, Repr, Inhabited

structure Header where
  typ : Nat
  version : Nat
  len : Nat
deriving DecidableEq, Repr, Inhabited

def changeCipherSpec : Nat := 20
def alert : Nat := 21
def handshake : Nat := 22
def applicationData : Nat := 23
/-- RFC 6520's heartbeat: a registered type, which rustls does not implement. -/
def heartbeat : Nat := 24

/-- TLSPlaintext.length: at most 2^14 (RFC 8446 section 5.1, RFC 5246 section 6.2.1). -/
def plainMax : Nat := 2 ^ 14
/-- TLSCiphertext.length in TLS 1.3: at most 2^14 + 256 (RFC 8446 section 5.2). -/
def tls13Max : Nat := 2 ^ 14 + 256
/-- TLSCiphertext.length in TLS 1.2: at most 2^14 + 2048 (RFC 5246 section 6.2.3). -/
def tls12Max : Nat := 2 ^ 14 + 2048

/-- A type the record layer knows. -/
def known (t : Nat) : Bool :=
  t == changeCipherSpec || t == alert || t == handshake || t == applicationData || t == heartbeat

/-- Whether a record of type `t` arriving in state `p` is protected. In TLS 1.3 a
change_cipher_spec record is always unprotected (RFC 8446 section 5). In TLS 1.2 the only
change_cipher_spec a connection takes is the one before the peer's new keys (RFC 5246
section 7.1), and rustls supports no renegotiation, so it reads every change_cipher_spec
record unprotected (`conn.rs`, `process_more_input`, `allowed_plaintext`). A later one fails
as an unexpected message either way. The first replay of the vectors found this: the model
first had TLS 1.2 change_cipher_spec records protected. -/
def isProtected (p : Prot) (t : Nat) : Bool :=
  match p with
  | .plain => false
  | .tls12 | .tls13 => t != changeCipherSpec

/-- The most a record of type `t` arriving in state `p` may hold. -/
def limit (p : Prot) (t : Nat) : Nat :=
  if !isProtected p t then plainMax
  else match p with
    | .tls13 => tls13Max
    | _ => tls12Max

/-- The rule. The order is the order of the checks; for a record that breaks two rules it
decides which alert the peer hears. -/
def check (p : Prot) (h : Header) : Verdict :=
  if !known h.typ then .unexpectedType
  else if h.version / 256 != 3 then .badVersion
  else if h.typ != applicationData && h.len == 0 then .emptyFragment
  else if h.len > limit p h.typ then .recordOverflow
  else if h.typ == heartbeat && !isProtected p h.typ then .unexpectedType
  else .accept

/-! ## What the rule guarantees -/

theorem limits : plainMax = 16384 ∧ tls13Max = 16640 ∧ tls12Max = 18432 := by
  decide

/-- The limits are ordered: TLS 1.3's is the tightest on ciphertext, and both allow at least
a full plaintext record. -/
theorem limits_ordered : plainMax < tls13Max ∧ tls13Max < tls12Max := by
  decide

theorem limit_le (p : Prot) (t : Nat) : limit p t ≤ tls12Max := by
  unfold limit
  cases p <;> simp [isProtected, plainMax, tls12Max, tls13Max] <;> split <;> simp

/-- An accepted record is no longer than its state allows. -/
theorem accept_within_limit {p : Prot} {h : Header} (hc : check p h = .accept) :
    h.len ≤ limit p h.typ := by
  unfold check at hc
  repeat' split at hc
  all_goals first | contradiction | omega

/-- An accepted unprotected record holds at most 2^14 bytes, in every state. -/
theorem accept_unprotected {p : Prot} {h : Header} (hc : check p h = .accept)
    (hp : isProtected p h.typ = false) : h.len ≤ plainMax := by
  have := accept_within_limit hc
  simp [limit, hp] at this
  exact this

/-- An accepted protected TLS 1.3 record holds at most 2^14 + 256 bytes. -/
theorem accept_tls13 {h : Header} (hc : check .tls13 h = .accept)
    (hp : isProtected .tls13 h.typ = true) : h.len ≤ tls13Max := by
  have := accept_within_limit hc
  simp [limit, hp] at this
  exact this

/-- An accepted record has a type the record layer knows, and is not a heartbeat taken
unprotected. -/
theorem accept_known {p : Prot} {h : Header} (hc : check p h = .accept) :
    known h.typ = true ∧ ¬(h.typ = heartbeat ∧ isProtected p h.typ = false) := by
  unfold check at hc
  repeat' split at hc
  all_goals first | contradiction | skip
  rename_i h1 _ _ _ h5
  refine ⟨by simpa using h1, ?_⟩
  intro ⟨ht, hp⟩
  rw [ht] at hp h5
  simp [hp] at h5

/-- An accepted record is not empty unless it is application data. -/
theorem accept_nonempty {p : Prot} {h : Header} (hc : check p h = .accept) :
    h.typ = applicationData ∨ 0 < h.len := by
  unfold check at hc
  repeat' split at hc
  all_goals first | contradiction | skip
  rename_i _ _ h3 _ _
  by_cases ht : h.typ = applicationData
  · exact Or.inl ht
  · right
    have : ¬ h.len = 0 := by
      intro hz
      simp [ht, hz] at h3
    omega

/-- A known, well-versioned, non-empty record is refused for its length exactly when it is
longer than its state allows. -/
theorem overflow_iff {p : Prot} {h : Header} (hk : known h.typ = true)
    (hv : h.version / 256 = 3) (he : h.typ = applicationData ∨ 0 < h.len) :
    check p h = .recordOverflow ↔ limit p h.typ < h.len := by
  have he' : (h.typ != applicationData && h.len == 0) = false := by
    cases hh : (h.typ != applicationData && h.len == 0)
    · rfl
    · simp at hh
      rcases he with he | he
      · exact absurd he hh.1
      · omega
  have hk' : (!known h.typ) = false := by simp [hk]
  have hv' : (h.version / 256 != 3) = false := by simp [hv]
  unfold check
  rw [hk', hv', he']
  simp only [Bool.false_eq_true, ↓reduceIte]
  by_cases hl : h.len > limit p h.typ
  · simp [hl]
  · simp only [hl, ↓reduceIte]
    constructor
    · intro hc
      split at hc <;> contradiction
    · intro hl'
      exact absurd hl' (by simp)

/-- Shortening an accepted record (to a length its type allows) keeps it accepted. -/
theorem accept_shorter {p : Prot} {h : Header} (hc : check p h = .accept) (n : Nat)
    (hn : n ≤ h.len) (he : h.typ = applicationData ∨ 0 < n) :
    check p { h with len := n } = .accept := by
  unfold check at hc ⊢
  simp only at hc ⊢
  repeat' split at hc
  all_goals first | contradiction | skip
  rename_i h1 h2 h3 h4 h5
  have he' : ¬ (h.typ != applicationData && n == 0) = true := by
    intro hh
    simp at hh
    rcases he with he | he
    · exact hh.1 he
    · omega
  simp only [h1, h2, he', h5]
  have : ¬ n > limit p h.typ := by omega
  simp [this]

end TlsRecord
