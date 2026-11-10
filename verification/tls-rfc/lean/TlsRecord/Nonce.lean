/-
  The sending side of the record layer: which (key, sequence number) pairs are handed to the
  AEAD, and which records reach the wire, through budget refusals and key updates.

  The model is the vendored rustls's code, in `rustls/src`, as of commit 1f181ea41:

  * `record_layer.rs`, `encrypt_outgoing`: every encryption takes `write_seq` and bumps it;
    `prepare_message_encrypter` (through `set_message_encrypter`) resets it to 0 for a new key.
  * `common_state.rs`, `send_single_fragment`: nothing once the connection failed
    (`output_unpaid`); pays for the record first (a refusal, `Outcome.refused`, changes nothing);
    then encrypts and queues it with `queue_paid`. A record that cannot be queued once encrypted
    (`push_paid` refusing an allocation larger than was paid, `Outcome.dropped`) fails the
    connection.
  * `common_state.rs`, `queue_paid` and `perhaps_write_key_update`: a KeyUpdate notification
    waiting goes first; if it cannot be queued, the connection fails and the record is not queued.
  * `common_state.rs`, `enqueue_key_update_notification`, with `tls13/key_schedule.rs`'s
    `update_encrypter_and_notify`: the reply to a peer's update_requested (`Op.reply`) is
    encrypted at once under the current key and waits for the next record; the key changes at
    once. A refusal to pay for it fails the connection (it is made while processing a received
    message, which cannot be undone), and the key still changes. `should_update_key` makes no
    second reply while one waits.
  * `conn.rs`, `refresh_traffic_keys`, with `request_key_update_and_update_encrypter`: a
    KeyUpdate request (`Op.request`) is sent with room for one control record charged first;
    without room nothing happens. Otherwise it is sent through `send_single_fragment` and the
    key changes.

  An application data record is `Op.send`. Every record is one fragment: fragmentation only
  repeats `send_single_fragment`. Sequence-number exhaustion (`check_pre_encrypt_action`) is left
  out: the keys are far from their limit.

  `old` below is the code before 1f181ea41, and its two counterexamples are the holes that
  commit closed. `Gen.lean` writes vectors of `run` that `rustls/src/common_state/nonce_vectors.rs`
  replays against the real `CommonState`.
-/
namespace TlsRecord.Nonce

inductive Kind where
  | data
  | keyUpdate
deriving DecidableEq, Repr, Inhabited

/-- A record: the key it was encrypted under (the number of key changes before it) and its
sequence number under that key. -/
structure Rec where
  epoch : Nat
  seq : Nat
  kind : Kind
deriving DecidableEq, Repr, Inhabited

/-- What the budget does with one record. -/
inductive Outcome where
  /-- paid for and queued -/
  | queued
  /-- refused before encryption -/
  | refused
  /-- paid for and encrypted, then refused by `push_paid` -/
  | dropped
deriving DecidableEq, Repr, Inhabited

inductive Op where
  | send (o : Outcome)
  | request (o : Outcome)
  | reply (o : Outcome)
deriving DecidableEq, Repr, Inhabited

structure St where
  epoch : Nat := 0
  seq : Nat := 0
  failed : Bool := false
  /-- The KeyUpdate notification waiting, and whether `push_paid` will take it. -/
  pending : Option (Rec × Bool) := none
  /-- Every record handed to the encrypter, newest first. -/
  used : List Rec := []
  /-- Every record queued for the wire, newest first. -/
  wire : List Rec := []
deriving Repr, Inhabited

def encrypt (s : St) (k : Kind) : St :=
  { s with seq := s.seq + 1, used := ⟨s.epoch, s.seq, k⟩ :: s.used }

/-- `perhaps_write_key_update`. -/
def flush (s : St) : St :=
  match s.pending with
  | none => s
  | some (k, true) => { s with pending := none, wire := k :: s.wire }
  | some (_, false) => { s with pending := none, failed := true }

/-- `queue_paid` for the record `r`, which `push_paid` takes if `ok`. -/
def queueFlushed (s : St) (r : Rec) (ok : Bool) : St :=
  if s.failed then s
  else if ok then { s with wire := r :: s.wire }
  else { s with failed := true }

def queue (s : St) (r : Rec) (ok : Bool) : St := queueFlushed (flush s) r ok

/-- `send_single_fragment`. -/
def sendSingle (s : St) (k : Kind) : Outcome → St
  | .refused => s
  | .queued => if s.failed then s else queue (encrypt s k) ⟨s.epoch, s.seq, k⟩ true
  | .dropped => if s.failed then s else queue (encrypt s k) ⟨s.epoch, s.seq, k⟩ false

def switchKey (s : St) : St := { s with epoch := s.epoch + 1, seq := 0 }

/-- `enqueue_key_update_notification`. -/
def notify (s : St) : Outcome → St
  | .refused => { s with failed := true }
  | .queued => if s.failed then s else { encrypt s .keyUpdate with pending := some (⟨s.epoch, s.seq, .keyUpdate⟩, true) }
  | .dropped => if s.failed then s else { encrypt s .keyUpdate with pending := some (⟨s.epoch, s.seq, .keyUpdate⟩, false) }

def step (s : St) : Op → St
  | .send o => sendSingle s .data o
  | .request .refused => s
  | .request o => switchKey (sendSingle s .keyUpdate o)
  | .reply o => if s.pending.isSome then s else switchKey (notify s o)

def run (ops : List Op) : St := ops.foldl step {}

/-! ## The properties -/

/-- No two records share a (key, sequence number) pair: no AEAD nonce is used twice
(RFC 8446 section 5.3). Newest first. -/
def Distinct : List Rec → Prop
  | [] => True
  | a :: l => (∀ b ∈ l, ¬(b.epoch = a.epoch ∧ b.seq = a.seq)) ∧ Distinct l

/-- `b` may follow `a` on the wire: the next sequence number under the same key, or the first
under the next key right after a KeyUpdate (RFC 8446 sections 5.3 and 4.6.3). -/
def Next (a b : Rec) : Prop :=
  (b.epoch = a.epoch ∧ b.seq = a.seq + 1) ∨ (a.kind = .keyUpdate ∧ b.epoch = a.epoch + 1 ∧ b.seq = 0)

/-- A sequence of records, newest first, that starts at key 0, sequence number 0, and in which
each record may follow the one before: no sequence number skipped, and a key changes only
right after a KeyUpdate. -/
def RChain : List Rec → Prop
  | [] => True
  | [a] => a.epoch = 0 ∧ a.seq = 0
  | b :: a :: l => Next a b ∧ RChain (a :: l)

def pendingList : Option (Rec × Bool) → List Rec
  | none => []
  | some (k, _) => [k]

/-- Where the next encryption lands follows the last one. -/
def Ready (s : St) : Prop :=
  match s.used with
  | [] => s.epoch = 0 ∧ s.seq = 0
  | a :: _ => Next a ⟨s.epoch, s.seq, .data⟩

/-- Every record used is behind the next position. -/
def Fresh (s : St) : Prop :=
  ∀ r ∈ s.used, r.epoch < s.epoch ∨ (r.epoch = s.epoch ∧ r.seq < s.seq)

structure Inv (s : St) : Prop where
  fresh : Fresh s
  distinct : Distinct s.used
  chain : RChain s.used
  suffix : ∃ t, s.used = t ++ s.wire
  live : s.failed = false → s.used = pendingList s.pending ++ s.wire
  ready : s.failed = false → Ready s

/-! ## Proofs -/

theorem next_kind (a : Rec) (e q : Nat) (k : Kind) :
    Next a ⟨e, q, k⟩ ↔ Next a ⟨e, q, .data⟩ := by
  simp [Next]

theorem rchain_tail {x : Rec} {l : List Rec} (h : RChain (x :: l)) : RChain l := by
  cases l with
  | nil => trivial
  | cons a l => exact h.2

theorem rchain_suffix (t l : List Rec) (h : RChain (t ++ l)) : RChain l := by
  induction t with
  | nil => exact h
  | cons x t ih => exact ih (rchain_tail h)

theorem inv_init : Inv ({} : St) := by
  refine ⟨?_, ?_, ?_, ⟨[], rfl⟩, ?_, ?_⟩ <;> simp [Fresh, Distinct, RChain, pendingList, Ready]


theorem encrypt_fresh {s : St} (k : Kind) (hf : Fresh s) : Fresh (encrypt s k) := by
  intro r hr
  simp only [encrypt, List.mem_cons] at hr
  rcases hr with h | h
  · subst h; simp [encrypt]
  · rcases hf r h with h1 | h1
    · left; simpa [encrypt] using h1
    · right; simp only [encrypt]; omega

theorem encrypt_distinct {s : St} (k : Kind) (hf : Fresh s) (hd : Distinct s.used) :
    Distinct (encrypt s k).used := by
  simp only [encrypt, Distinct]
  refine ⟨?_, hd⟩
  intro b hb ⟨he, hs⟩
  rcases hf b hb with h1 | h1 <;> simp_all

theorem encrypt_chain {s : St} (k : Kind) (hc : RChain s.used) (hr : Ready s) :
    RChain (encrypt s k).used := by
  simp only [encrypt]
  unfold Ready at hr
  revert hc hr
  cases s.used with
  | nil => intro _ hr; simp [RChain, hr.1, hr.2]
  | cons a l =>
    intro hc hr
    exact ⟨by simpa [Next] using hr, hc⟩

theorem ready_encrypt (s : St) (k : Kind) : Ready (encrypt s k) := by
  simp [Ready, encrypt, Next]

theorem ready_switch_keyUpdate (s : St) : Ready (switchKey (encrypt s .keyUpdate)) := by
  simp [Ready, switchKey, encrypt, Next]

theorem fresh_switch {s : St} (hf : Fresh s) : Fresh (switchKey s) := by
  intro r hr
  rcases hf r hr with h | h
  · left; simp only [switchKey]; omega
  · left; simp only [switchKey]; omega

/-- The parts of `Inv` that only `used`, `epoch` and `seq` decide. -/
structure UsedInv (s : St) : Prop where
  fresh : Fresh s
  distinct : Distinct s.used
  chain : RChain s.used

theorem usedInv_encrypt {s : St} (k : Kind) (h : UsedInv s) (hr : Ready s) :
    UsedInv (encrypt s k) :=
  ⟨encrypt_fresh k h.fresh, encrypt_distinct k h.fresh h.distinct, encrypt_chain k h.chain hr⟩

theorem usedInv_switch {s : St} (h : UsedInv s) : UsedInv (switchKey s) :=
  ⟨fresh_switch h.fresh, h.distinct, h.chain⟩

theorem flush_fields (s : St) :
    (flush s).used = s.used ∧ (flush s).epoch = s.epoch ∧ (flush s).seq = s.seq := by
  unfold flush; split <;> simp

theorem queue_fields (s : St) (r : Rec) (ok : Bool) :
    (queue s r ok).used = s.used ∧ (queue s r ok).epoch = s.epoch ∧ (queue s r ok).seq = s.seq := by
  have := flush_fields s
  unfold queue queueFlushed
  split
  · exact this
  · split <;> simp [this.1, this.2.1, this.2.2]

theorem usedInv_of_fields {s s' : St} (h : UsedInv s) (hu : s'.used = s.used)
    (he : s'.epoch = s.epoch) (hs : s'.seq = s.seq) : UsedInv s' := by
  refine ⟨?_, ?_, ?_⟩
  · intro r hr; rw [hu] at hr; rw [he, hs]; exact h.fresh r hr
  · rw [hu]; exact h.distinct
  · rw [hu]; exact h.chain

/-- Queuing the record `r` just encrypted, at the front of `used`, over a live state whose
older records are all on the wire or waiting: afterwards the wire is still a suffix of `used`,
and a live state still loses nothing. -/
theorem queue_wire {s : St} (r : Rec) (ok : Bool) (hlive : s.used = r :: (pendingList s.pending ++ s.wire)) :
    (∃ t, (queue s r ok).used = t ++ (queue s r ok).wire) ∧
      ((queue s r ok).failed = false →
        (queue s r ok).used = pendingList (queue s r ok).pending ++ (queue s r ok).wire) := by
  unfold queue
  cases hp : s.pending with
  | none =>
    have hfl : flush s = s := by simp [flush, hp]
    rw [hfl]
    simp only [hp, pendingList, List.nil_append] at hlive
    unfold queueFlushed
    cases hf : s.failed
    · cases ok
      · simp only [Bool.false_eq_true, ↓reduceIte]
        exact ⟨⟨[r], by simp [hlive]⟩, fun h => by simp at h⟩
      · simp only [Bool.false_eq_true, ↓reduceIte]
        exact ⟨⟨[], by simp [hlive]⟩, fun _ => by simp [hlive, hp, pendingList]⟩
    · simp only [↓reduceIte]
      exact ⟨⟨[r], by simp [hlive]⟩, fun h => by simp [hf] at h⟩
  | some kb =>
    obtain ⟨k, b⟩ := kb
    simp only [hp, pendingList, List.singleton_append] at hlive
    cases b
    · have hfl : flush s = { s with pending := none, failed := true } := by simp [flush, hp]
      rw [hfl]
      unfold queueFlushed
      simp only [↓reduceIte]
      exact ⟨⟨[r, k], by simp [hlive]⟩, fun h => by simp at h⟩
    · have hfl : flush s = { s with pending := none, wire := k :: s.wire } := by simp [flush, hp]
      rw [hfl]
      unfold queueFlushed
      cases hf : s.failed
      · cases ok
        · simp only [Bool.false_eq_true, ↓reduceIte]
          exact ⟨⟨[r], by simp [hlive]⟩, fun h => by simp at h⟩
        · simp only [Bool.false_eq_true, ↓reduceIte]
          exact ⟨⟨[], by simp [hlive]⟩, fun _ => by simp [hlive, pendingList]⟩
      · simp only [↓reduceIte]
        exact ⟨⟨[r], by simp [hlive]⟩, fun h => by simp at h⟩

theorem sendSingle_inv {s : St} (k : Kind) (o : Outcome) (h : Inv s) :
    UsedInv (sendSingle s k o) ∧ (∃ t, (sendSingle s k o).used = t ++ (sendSingle s k o).wire) ∧
      ((sendSingle s k o).failed = false →
        (sendSingle s k o).used = pendingList (sendSingle s k o).pending ++ (sendSingle s k o).wire) ∧
      ((sendSingle s k o).failed = false → Ready (sendSingle s k o)) ∧
      ((sendSingle s k o).failed = false → o ≠ .refused →
        ∃ q, (sendSingle s k o).used.head? = some ⟨s.epoch, q, k⟩ ∧ (sendSingle s k o).epoch = s.epoch) := by
  have hu : UsedInv s := ⟨h.fresh, h.distinct, h.chain⟩
  cases o with
  | refused =>
    exact ⟨hu, h.suffix, h.live, h.ready, fun _ hne => absurd rfl hne⟩
  | queued | dropped =>
    simp only [sendSingle]
    cases hfl : s.failed with
    | true =>
      simp only [↓reduceIte]
      refine ⟨hu, h.suffix, fun hf => ?_, fun hf => ?_, fun hf => ?_⟩ <;> simp_all
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte]
      have he := usedInv_encrypt k hu (h.ready hfl)
      have hq := queue_fields (encrypt s k) ⟨s.epoch, s.seq, k⟩
      have hlive : (encrypt s k).used = ⟨s.epoch, s.seq, k⟩ :: (pendingList (encrypt s k).pending ++ (encrypt s k).wire) := by
        simp [encrypt, h.live hfl]
      refine ⟨?_, (queue_wire _ _ hlive).1, (queue_wire _ _ hlive).2, fun _ => ?_, fun _ _ => ?_⟩
      · exact usedInv_of_fields he (hq _).1 (hq _).2.1 (hq _).2.2
      · have hr := ready_encrypt s k
        unfold Ready at hr ⊢
        rw [(hq _).1, (hq _).2.1, (hq _).2.2]
        exact hr
      · refine ⟨s.seq, ?_, ?_⟩
        · rw [(hq _).1]; simp [encrypt]
        · rw [(hq _).2.1]; simp [encrypt]

/-- After a KeyUpdate request is encrypted and the key changes, the next record follows it. -/
theorem request_inv {s : St} {o : Outcome} (hne : o ≠ .refused) (h : Inv s) :
    Inv (switchKey (sendSingle s .keyUpdate o)) := by
  obtain ⟨u, sfx, live, _, head⟩ := sendSingle_inv .keyUpdate o h
  have u' := usedInv_switch u
  refine ⟨u'.fresh, u'.distinct, u'.chain, sfx, live, fun hf => ?_⟩
  obtain ⟨q, hh, he⟩ := head hf hne
  unfold Ready
  simp only [switchKey]
  revert hh
  cases (sendSingle s .keyUpdate o).used with
  | nil => intro hh; simp at hh
  | cons a l =>
    intro hh
    simp at hh
    subst hh
    simp [Next, he]

theorem step_inv {s : St} (op : Op) (h : Inv s) : Inv (step s op) := by
  have hu : UsedInv s := ⟨h.fresh, h.distinct, h.chain⟩
  cases op with
  | send o =>
    obtain ⟨u, sfx, live, ready, _⟩ := sendSingle_inv .data o h
    exact ⟨u.fresh, u.distinct, u.chain, sfx, live, ready⟩
  | request o =>
    cases o with
    | refused => exact h
    | queued => exact request_inv (by simp) h
    | dropped => exact request_inv (by simp) h
  | reply o =>
    simp only [step]
    cases hp : s.pending.isSome with
    | true => simp only [↓reduceIte]; exact h
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte]
      have hpn : s.pending = none := by
        cases hq : s.pending <;> simp_all
      cases o with
      | refused =>
        exact ⟨fresh_switch h.fresh, h.distinct, h.chain, h.suffix, by simp [notify, switchKey],
          by simp [notify, switchKey]⟩
      | queued | dropped =>
        simp only [notify]
        cases hfl : s.failed with
        | true =>
          simp only [↓reduceIte]
          exact ⟨fresh_switch h.fresh, h.distinct, h.chain, h.suffix, by simp [switchKey, hfl],
            by simp [switchKey, hfl]⟩
        | false =>
          simp only [Bool.false_eq_true, ↓reduceIte]
          have he := usedInv_switch (usedInv_encrypt .keyUpdate hu (h.ready hfl))
          have hlive := h.live hfl
          rw [hpn] at hlive
          simp only [pendingList, List.nil_append] at hlive
          refine ⟨he.fresh, he.distinct, he.chain, ⟨[⟨s.epoch, s.seq, .keyUpdate⟩], ?_⟩, fun _ => ?_,
            fun _ => ready_switch_keyUpdate s⟩
          · simp [switchKey, encrypt, hlive]
          · simp [switchKey, encrypt, hlive, pendingList]

theorem run_inv_from (ops : List Op) : ∀ s, Inv s → Inv (ops.foldl step s) := by
  induction ops with
  | nil => intro s h; exact h
  | cons op ops ih => intro s h; exact ih _ (step_inv op h)

theorem run_inv (ops : List Op) : Inv (run ops) := run_inv_from ops {} inv_init

/-- No (key, sequence number) pair is handed to the AEAD twice, whatever the budget refuses
and wherever the key updates fall. -/
theorem nonce_unique (ops : List Op) : Distinct (run ops).used := (run_inv ops).distinct

/-- What reaches the wire, in order, starts at key 0, sequence number 0, skips no sequence
number, and changes key only right after a KeyUpdate. -/
theorem wire_chain (ops : List Op) : RChain (run ops).wire := by
  obtain ⟨t, ht⟩ := (run_inv ops).suffix
  have := (run_inv ops).chain
  rw [ht] at this
  exact rchain_suffix t _ this

/-- The wire is the oldest part of what was encrypted: nothing reaches it after a record that
was encrypted and lost. -/
theorem wire_suffix (ops : List Op) : ∃ t, (run ops).used = t ++ (run ops).wire :=
  (run_inv ops).suffix

/-- While the connection has not failed, every record encrypted is on the wire, or is the one
KeyUpdate notification waiting to go before the next record. -/
theorem live_loses_nothing (ops : List Op) (h : (run ops).failed = false) :
    (run ops).used = pendingList (run ops).pending ++ (run ops).wire :=
  (run_inv ops).live h

/-- A refusal before encryption changes nothing, for a record and for a KeyUpdate request. -/
theorem refused_changes_nothing (s : St) :
    step s (.send .refused) = s ∧ step s (.request .refused) = s := by
  simp [step, sendSingle]

/-! ## The code before 1f181ea41 -/

namespace old

/-- `queue_paid` before: a dropped KeyUpdate failed the connection, but the record after it
was queued all the same. -/
def queue (s : St) (r : Rec) (ok : Bool) : St :=
  let s := flush s
  if ok then { s with wire := r :: s.wire } else s

/-- `send_appdata_encrypt` before: no check of `output_unpaid`, and a record dropped after
encryption returned without failing the connection. -/
def send (s : St) : Outcome → St
  | .refused => s
  | .queued => queue (encrypt s .data) ⟨s.epoch, s.seq, .data⟩ true
  | .dropped => queue (encrypt s .data) ⟨s.epoch, s.seq, .data⟩ false

def step (s : St) : Op → St
  | .send o => send s o
  | op => Nonce.step s op

def run (ops : List Op) : St := ops.foldl step {}

/-- A record dropped after encryption, then the same bytes written again: the second goes out
under sequence number 1 with nothing under 0, and the connection has not failed. -/
theorem hole_after_drop :
    (run [.send .dropped, .send .queued]).wire = [⟨0, 1, .data⟩] ∧
      (run [.send .dropped, .send .queued]).failed = false ∧
      ¬ RChain (run [.send .dropped, .send .queued]).wire := by
  refine ⟨by rfl, by rfl, ?_⟩
  show ¬ RChain [⟨0, 1, .data⟩]
  simp [RChain]

/-- A KeyUpdate reply dropped: the next record goes out under the new key with no KeyUpdate
before it. -/
theorem record_without_key_update :
    (run [.reply .dropped, .send .queued]).wire = [⟨1, 0, .data⟩] ∧
      ¬ RChain (run [.reply .dropped, .send .queued]).wire := by
  refine ⟨by rfl, ?_⟩
  show ¬ RChain [⟨1, 0, .data⟩]
  simp [RChain]

end old

end TlsRecord.Nonce
