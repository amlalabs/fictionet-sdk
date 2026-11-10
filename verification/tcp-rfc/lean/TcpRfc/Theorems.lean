import TcpRfc.Arrive

/-!
# What `arrive` guarantees

Theorems about the RFC's segment arrival as `arrive` writes it, for every
set of departures unless one is named, every 32-bit sequence number and
every segment.
-/

namespace TcpRfc

/-! ## Each departure changes only its own segments

For each departure flag: on any record and segment outside the flag's
case, `arrive` gives the same result with the flag on as with it off,
whatever the other flags are. -/

theorem local_repeatSynAck (d : Departures) (t : Tcb) (s : Segment)
    (h : repeatSynAckCase t s = false) :
    arrive { d with repeatSynAck := true } t s = arrive { d with repeatSynAck := false } t s := by
  unfold arrive otherArrive checks accepted proceed synSentArrive finIn
  simp only [h, Bool.and_false]

theorem local_ackBeforeSeqInSynReceived (d : Departures) (t : Tcb) (s : Segment)
    (h : ackBeforeSeqCase t s = false) :
    arrive { d with ackBeforeSeqInSynReceived := true } t s =
      arrive { d with ackBeforeSeqInSynReceived := false } t s := by
  unfold arrive otherArrive checks accepted proceed synSentArrive finIn
  simp only [h, Bool.and_false]

theorem local_challengeSynInSynReceived (d : Departures) (t : Tcb) (s : Segment)
    (h : challengeSynCase t s = false) :
    arrive { d with challengeSynInSynReceived := true } t s =
      arrive { d with challengeSynInSynReceived := false } t s := by
  unfold arrive otherArrive checks accepted proceed synSentArrive finIn
  simp only [h, Bool.and_false]

theorem local_noAckDroppedFirst (d : Departures) (t : Tcb) (s : Segment)
    (h : noAckCase t s = false) :
    arrive { d with noAckDroppedFirst := true } t s =
      arrive { d with noAckDroppedFirst := false } t s := by
  unfold arrive otherArrive checks accepted proceed synSentArrive finIn
  simp only [h, Bool.and_false]

theorem local_ackCheckedBeforeSeq (d : Departures) (t : Tcb) (s : Segment)
    (h : ackAheadCase t s = false) :
    arrive { d with ackCheckedBeforeSeq := true } t s =
      arrive { d with ackCheckedBeforeSeq := false } t s := by
  unfold arrive otherArrive checks accepted proceed synSentArrive finIn
  simp only [h, Bool.and_false]

theorem local_rateLimitEmptyOutOfWindow (d : Departures) (t : Tcb) (s : Segment)
    (h : emptyOutOfWindowCase t s = false) :
    arrive { d with rateLimitEmptyOutOfWindow := true } t s =
      arrive { d with rateLimitEmptyOutOfWindow := false } t s := by
  unfold arrive otherArrive checks accepted proceed synSentArrive finIn
  simp only [h, Bool.and_false]

theorem local_emptyAckAtRightEdge (d : Departures) (t : Tcb) (s : Segment)
    (h : emptyRightEdgeCase t s = false) :
    arrive { d with emptyAckAtRightEdge := true } t s =
      arrive { d with emptyAckAtRightEdge := false } t s := by
  unfold arrive otherArrive checks accepted proceed synSentArrive finIn
  simp only [h, Bool.and_false]

theorem local_finAtRightEdge (d : Departures) (t : Tcb) (s : Segment)
    (h : finEdgeCase t s = false) :
    arrive { d with finAtRightEdge := true } t s =
      arrive { d with finAtRightEdge := false } t s := by
  unfold arrive otherArrive checks accepted proceed synSentArrive finIn
  simp only [h, Bool.and_false]

theorem local_textOnSynDropped (d : Departures) (t : Tcb) (s : Segment)
    (h : synTextCase t s = false) :
    arrive { d with textOnSynDropped := true } t s =
      arrive { d with textOnSynDropped := false } t s := by
  unfold arrive otherArrive checks accepted proceed synSentArrive finIn
  simp only [h, Bool.and_false]



/-! ## The pieces of `proceed` -/

theorem adv_zero (a : Seq) : adv a 0 = a := by
  rw [seq_eq_iff, adv_toNat]; have := lt_M a; seq_omega

theorem ackIf_cases (c : Bool) (x y : Seq) : ackIf c x y = .none ∨ ackIf c x y = .ack x y := by
  cases c <;> simp [ackIf]

theorem finIn_true (d : Departures) (t : Tcb) (s : Segment) :
    finIn d true t s = true ↔ s.ctl = .fin ∧ (s.text - back t s < t.rcvWnd ∨
      (d.finAtRightEdge = true ∧ otherState t = true ∧ back t s + t.rcvWnd = s.text)) := by
  simp [finIn, finEdgeCase]
  intro _
  constructor <;> intro h <;> simp_all

/-- How far RCV.NXT moves: `n` octets of text and `f` for a FIN. -/
theorem move_facts (d : Departures) (ord : Bool) (t : Tcb) (s : Segment) :
    let n := taken ord t s
    let f := if finIn d ord t s then 1 else 0
    f ≤ 1 ∧ n ≤ t.rcvWnd ∧ n ≤ s.text - back t s ∧
    (n + f ≠ 0 → ord = true) ∧
    (f = 1 → s.ctl = .fin ∧ n = s.text - back t s) ∧
    (n + f ≤ t.rcvWnd ∨ (d.finAtRightEdge = true ∧ f = 1 ∧ n = t.rcvWnd)) := by
  intro n f
  cases ord
  · simp [n, f, taken, finIn]
  · by_cases hP : finIn d true t s = true
    · have h2 := (finIn_true d t s).1 hP
      have hn : n = min (s.text - back t s) t.rcvWnd := by simp [n, taken]
      have hf : f = 1 := by simp [f, hP]
      refine ⟨by omega, by omega, by omega, fun _ => rfl, fun _ => ⟨h2.1, ?_⟩, ?_⟩
      · rcases h2.2 with h | ⟨_, _, h⟩ <;> omega
      · rcases h2.2 with h | ⟨hd, _, h⟩
        · left; omega
        · right; exact ⟨hd, hf, by omega⟩
    · have hn : n = min (s.text - back t s) t.rcvWnd := by simp [n, taken]
      have hf : f = 0 := by simp [f, hP]
      refine ⟨by omega, by omega, by omega, fun _ => rfl, fun h => by omega, by omega⟩

/-- `proceed` sends nothing, so SND.NXT stays; SND.UNA moves only to an
    acceptable ACK. -/
theorem proceed_send (d : Departures) (t : Tcb) (s : Segment) (a : Seq) (st1 : State)
    (zw : Bool) :
    let r := (proceed d t s a st1 zw).1
    r.sndNxt = t.sndNxt ∧ r.iss = t.iss ∧
      (r.sndUna = t.sndUna ∨ (ltLe t.sndUna a t.sndNxt = true ∧ r.sndUna = a)) := by
  intro r
  simp only [r, proceed]
  split <;>
    (refine ⟨rfl, rfl, ?_⟩; by_cases hn : ltLe t.sndUna a t.sndNxt = true <;> simp [hn])

/-- `proceed` moves RCV.NXT by the text it takes and a FIN, and its reply
    is nothing or the ACK of the new RCV.NXT. -/
theorem proceed_receive (d : Departures) (t : Tcb) (s : Segment) (a : Seq) (st1 : State)
    (zw : Bool) :
    let r := proceed d t s a st1 zw
    ∃ ord : Bool,
      (ord = true → inOrder t s = true ∧ t.peerFin = false) ∧
      r.1.rcvNxt = adv t.rcvNxt (taken ord t s + if finIn d ord t s then 1 else 0) ∧
      r.1.peerFin = (t.peerFin || finIn d ord t s) ∧
      r.1.rcvWnd = t.rcvWnd - taken ord t s ∧
      r.1.sndNxt = t.sndNxt ∧
      (r.2 = .none ∨ r.2 = .ack r.1.sndNxt r.1.rcvNxt) := by
  intro r
  simp only [r, proceed]
  split
  · refine ⟨false, by simp, ?_, ?_, ?_, rfl, ackIf_cases _ _ _⟩
    · simp [taken, finIn, adv_zero]
    · simp [finIn]
    · simp [taken]
  · refine ⟨_, fun h => ?_, rfl, rfl, rfl, rfl, ackIf_cases _ _ _⟩
    simp_all

/-! ## The shape of the 3.10.7.4 states -/

/-- `checks` either leaves the record as it is with a reply that carries
    no new numbers, deletes it or returns it to LISTEN on a RST at RCV.NXT,
    or runs `proceed` on a segment with an ACK and no RST. -/
theorem checks_shape (d : Departures) (t : Tcb) (s : Segment) :
    (checks d t s).1 = t ∧ ((checks d t s).2 = .none ∨ (checks d t s).2 = ackOf t ∨
      (checks d t s).2 = challengeOf t ∨ ∃ a, (checks d t s).2 = .rst a) ∨
    (∃ st, (checks d t s).1 = { t with state := st } ∧ (checks d t s).2 = .none ∧
      s.ctl = .rst ∧ s.seq = t.rcvNxt) ∨
    (∃ a st1 zw, s.ack = some a ∧ s.ctl ≠ .rst ∧ (ltLe t.sndUna a t.sndNxt = true ∨ ¬ ahead a t.sndNxt) ∧
      checks d t s = proceed d t s a st1 zw) := by
  unfold checks
  repeat' split
  all_goals first
    | (left; simp_all; done)
    | (right; left; simp_all; done)
    | (right; right; refine ⟨_, _, _, by assumption, by simp_all, by simp_all, rfl⟩)

/-- The same for every 3.10.7.4 state, with the departures that come
    before the first check. -/
theorem otherArrive_shape (d : Departures) (t : Tcb) (s : Segment) :
    (otherArrive d t s).1 = t ∧ ((otherArrive d t s).2 = .none ∨
      (otherArrive d t s).2 = ackOf t ∨ (otherArrive d t s).2 = challengeOf t ∨
      ∃ a, (otherArrive d t s).2 = .rst a) ∨
    (∃ st, (otherArrive d t s).1 = { t with state := st } ∧ (otherArrive d t s).2 = .none ∧
      ((s.ctl = .rst ∧ s.seq = t.rcvNxt) ∨ s.ctl = .syn)) ∨
    (∃ a st1 zw, s.ack = some a ∧ s.ctl ≠ .rst ∧ s.ctl ≠ .syn ∧ (ltLe t.sndUna a t.sndNxt = true ∨ ¬ ahead a t.sndNxt) ∧
      otherArrive d t s = proceed d t s a st1 zw) := by
  unfold otherArrive
  by_cases hsyn : s.ctl = .syn
  · simp only [hsyn]
    repeat' split
    all_goals first
      | (left; simp_all; done)
      | (right; left; simp_all; done)
  · have hc : (s.ctl == Ctl.syn) = false := by simp [hsyn]
    simp only [hc, Bool.false_and, Bool.false_eq_true, ite_false]
    have key := checks_shape d t s
    repeat' split
    all_goals first
      | (left; simp_all; done)
      | skip
    all_goals rcases key with h | ⟨st, h1, h2, h3, h4⟩ | ⟨a, st1, zw, h1, h2, h3, h4⟩
    all_goals first
      | (left; exact h)
      | (right; left; exact ⟨st, h1, h2, Or.inl ⟨h3, h4⟩⟩)
      | (right; right; exact ⟨a, st1, zw, h1, h2, hsyn, h3, h4⟩)


theorem arrive_other (d : Departures) (t : Tcb) (s : Segment) (ho : otherState t = true) :
    arrive d t s = otherArrive d t s := by
  unfold otherState at ho
  unfold arrive
  cases h : t.state <;> simp_all [State.synchronized]

theorem adv_back (t : Tcb) (s : Segment) (h : back t s ≤ s.text) :
    adv t.rcvNxt (s.text - back t s + 1) = adv s.seq (s.text + 1) := by
  simp only [back, dist_eq] at *
  rw [seq_eq_iff, adv_toNat, adv_toNat]
  have := lt_M t.rcvNxt; have := lt_M s.seq
  seq_omega

/-! ## Headline theorems -/

/-- RFC 5961 section 3.2: a RST that does not sit exactly at RCV.NXT never
    changes a SYN-RECEIVED or synchronized connection; it is dropped or
    answered with a challenge ACK. -/
theorem rst_off_rcvNxt_keeps_connection (d : Departures) (t : Tcb) (s : Segment)
    (ho : otherState t = true) (hr : s.ctl = .rst) (hs : s.seq ≠ t.rcvNxt) :
    (arrive d t s).1 = t ∧ ((arrive d t s).2 = .none ∨ (arrive d t s).2 = challengeOf t) := by
  rw [arrive_other d t s ho]
  unfold otherArrive checks
  simp only [hr, noAckCase, ackBeforeSeqCase, ackAheadCase, repeatSynAckCase, challengeSynCase]
  simp [hs]
  all_goals (repeat' split) <;> simp

/-- A RST or a SYN never moves RCV.NXT, SND.UNA or SND.NXT in SYN-RECEIVED
    or a synchronized state: at most it deletes the connection or sends it
    back to LISTEN. -/
theorem rst_or_syn_keeps_numbers (d : Departures) (t : Tcb) (s : Segment)
    (ho : otherState t = true) (hc : s.ctl = .rst ∨ s.ctl = .syn) :
    (arrive d t s).1.rcvNxt = t.rcvNxt ∧ (arrive d t s).1.sndUna = t.sndUna ∧
      (arrive d t s).1.sndNxt = t.sndNxt := by
  rw [arrive_other d t s ho]
  rcases otherArrive_shape d t s with ⟨h, _⟩ | ⟨st, h, _⟩ | ⟨a, st1, zw, _, h2, h3, _⟩
  · simp [h]
  · simp [h]
  · rcases hc with hc | hc <;> simp_all

/-- Segment arrival sends nothing of its own, so SND.NXT stays, outside
    LISTEN, where the connection is made. -/
theorem sndNxt_kept (d : Departures) (t : Tcb) (s : Segment) (hl : t.state ≠ .listen) :
    (arrive d t s).1.sndNxt = t.sndNxt := by
  by_cases ho : otherState t = true
  · rw [arrive_other d t s ho]
    rcases otherArrive_shape d t s with ⟨h, _⟩ | ⟨st, h, _⟩ | ⟨a, st1, zw, _, _, _, _, h⟩
    · simp [h]
    · simp [h]
    · rw [h]; exact (proceed_send d t s a st1 zw).1
  · unfold otherState at ho
    unfold arrive
    cases hs : t.state <;> simp_all [State.synchronized, closedArrive, synSentArrive] <;>
      (repeat' split) <;> simp_all

/-- SND.UNA moves only to the ACK of a segment, and only when that ACK is
    acceptable: SND.UNA < SEG.ACK =< SND.NXT as offsets from SND.UNA
    (3.4, 3.10.7.4 fifth). In SYN-SENT SND.UNA is the ISS. -/
theorem sndUna_offset_rule (d : Departures) (t : Tcb) (s : Segment) (hl : t.state ≠ .listen)
    (hiss : t.state = .synSent → t.sndUna = t.iss) :
    (arrive d t s).1.sndUna = t.sndUna ∨
      ∃ a, s.ack = some a ∧ ltLe t.sndUna a t.sndNxt = true ∧ (arrive d t s).1.sndUna = a := by
  by_cases ho : otherState t = true
  · rw [arrive_other d t s ho]
    rcases otherArrive_shape d t s with ⟨h, _⟩ | ⟨st, h, _⟩ | ⟨a, st1, zw, ha, _, _, _, h⟩
    · simp [h]
    · simp [h]
    · rw [h]
      rcases (proceed_send d t s a st1 zw).2.2 with e | ⟨e1, e2⟩
      · left; exact e
      · right; exact ⟨a, ha, e1, e2⟩
  · by_cases hss : t.state = .synSent
    · have e : arrive d t s = synSentArrive d t s := by unfold arrive; simp [hss]
      have hi := hiss hss
      rw [e]
      unfold synSentArrive
      repeat' split
      all_goals simp_all
    · have hcl : t.state = .closed := by
        unfold otherState at ho
        cases h : t.state <;> simp_all [State.synchronized]
      have e : arrive d t s = closedArrive t s := by unfold arrive; simp [hcl]
      rw [e]
      unfold closedArrive
      repeat' split
      all_goals simp

/-- Hence SND.UNA never passes SND.NXT: the offset from SND.UNA to SND.NXT
    only shrinks. -/
theorem sndUna_never_passes_sndNxt (d : Departures) (t : Tcb) (s : Segment)
    (hl : t.state ≠ .listen) (hiss : t.state = .synSent → t.sndUna = t.iss) :
    dist (arrive d t s).1.sndUna (arrive d t s).1.sndNxt ≤ dist t.sndUna t.sndNxt := by
  rw [sndNxt_kept d t s hl]
  rcases sndUna_offset_rule d t s hl hiss with h | ⟨a, _, h1, h2⟩
  · rw [h]; exact Nat.le_refl _
  · rw [h2]
    unfold ltLe at h1
    simp only [decide_eq_true_eq] at h1
    have := dist_trans t.sndUna a t.sndNxt
    have := dist_lt a t.sndNxt
    seq_omega

/-- RCV.NXT moves only by text taken in order and one for a FIN, in
    SYN-RECEIVED and the synchronized states: `n` octets of the segment's
    text from RCV.NXT on, no more than RCV.WND, and `f` = 1 only for a FIN
    right after the segment's last octet. Without `finAtRightEdge`, RCV.NXT
    stays inside the window; with it, one past, for the FIN. Nothing moves
    after the peer's FIN. -/
theorem rcvNxt_moves_by_text (d : Departures) (t : Tcb) (s : Segment)
    (ho : otherState t = true) :
    ∃ n f, (arrive d t s).1.rcvNxt = adv t.rcvNxt (n + f) ∧ f ≤ 1 ∧ n ≤ t.rcvWnd ∧
      (n + f ≠ 0 → back t s ≤ s.text ∧ n ≤ s.text - back t s ∧ t.peerFin = false) ∧
      (f = 1 → s.ctl = .fin ∧ n = s.text - back t s) ∧
      (n + f ≤ t.rcvWnd ∨ (d.finAtRightEdge = true ∧ f = 1 ∧ n = t.rcvWnd)) := by
  rw [arrive_other d t s ho]
  rcases otherArrive_shape d t s with ⟨h, _⟩ | ⟨st, h, _⟩ | ⟨a, st1, zw, _, _, _, _, h⟩
  · exact ⟨0, 0, by simp [h, adv_zero], by omega, by omega, by simp, by simp, Or.inl (by omega)⟩
  · exact ⟨0, 0, by simp [h, adv_zero], by omega, by omega, by simp, by simp, Or.inl (by omega)⟩
  · rw [h]
    obtain ⟨ord, hord, hr, -⟩ := proceed_receive d t s a st1 zw
    obtain ⟨f1, n1, n2, n3, n4, n5⟩ := move_facts d ord t s
    refine ⟨_, _, hr, f1, n1, fun hm => ?_, n4, n5⟩
    have ho' := hord (n3 hm)
    simp only [inOrder, decide_eq_true_eq] at ho'
    exact ⟨ho'.1, n2, ho'.2⟩

/-- No reply acknowledges past what was taken: every ACK or challenge ACK
    carries the record's SND.NXT and RCV.NXT after the step, and a SYN-ACK
    the ISS and RCV.NXT. With `rcvNxt_moves_by_text`, an ACK never covers
    an octet that did not arrive in order. -/
theorem replies_ack_rcvNxt (d : Departures) (t : Tcb) (s : Segment) (x y : Seq) :
    ((arrive d t s).2 = .ack x y ∨ (arrive d t s).2 = .challenge x y →
      x = (arrive d t s).1.sndNxt ∧ y = (arrive d t s).1.rcvNxt) ∧
    ((arrive d t s).2 = .synAck x y → x = (arrive d t s).1.iss ∧ y = (arrive d t s).1.rcvNxt) := by
  by_cases ho : otherState t = true
  · rw [arrive_other d t s ho]
    rcases otherArrive_shape d t s with ⟨h, h2⟩ | ⟨st, h, h2, _⟩ | ⟨a, st1, zw, _, _, _, _, h⟩
    · rw [h]; rcases h2 with e | e | e | ⟨b, e⟩ <;> simp [e, ackOf, challengeOf] <;>
        (try (intro h1 h2; exact ⟨h1.symm, h2.symm⟩))
    · simp [h2]
    · rw [h]
      obtain ⟨_, _, _, _, _, _, hrep⟩ := proceed_receive d t s a st1 zw
      rcases hrep with e | e <;> simp [e] <;> (try (intro h1 h2; exact ⟨h1.symm, h2.symm⟩))
  · unfold otherState at ho
    unfold arrive
    cases hs : t.state <;> simp_all [State.synchronized, closedArrive, listenArrive, synSentArrive]
    all_goals (repeat' split) <;> simp_all

/-- The peer's FIN is taken only in order: the segment reaches RCV.NXT,
    and RCV.NXT lands just past the FIN, at SEG.SEQ+SEG.LEN. -/
theorem fin_only_in_order (d : Departures) (t : Tcb) (s : Segment) (ho : otherState t = true)
    (hp : t.peerFin = false) (hf : (arrive d t s).1.peerFin = true) :
    s.ctl = .fin ∧ back t s ≤ s.text ∧ (arrive d t s).1.rcvNxt = adv s.seq (s.text + 1) := by
  rw [arrive_other d t s ho] at *
  rcases otherArrive_shape d t s with ⟨h, _⟩ | ⟨st, h, _⟩ | ⟨a, st1, zw, _, _, _, _, h⟩
  · simp_all
  · simp_all
  · rw [h] at hf ⊢
    obtain ⟨ord, hord, hr, hpf, -⟩ := proceed_receive d t s a st1 zw
    have hfi : finIn d ord t s = true := by simp_all
    have hord' : ord = true := by cases ord <;> simp_all [finIn]
    obtain ⟨-, -, -, -, n4, -⟩ := move_facts d ord t s
    obtain ⟨hc, hn⟩ := n4 (by simp [hfi])
    have hin := (hord hord').1
    simp only [inOrder, decide_eq_true_eq] at hin
    refine ⟨hc, hin, ?_⟩
    rw [hr, hn, hfi]
    simp only [ite_true]
    exact adv_back t s hin

/-- After the peer's FIN nothing moves RCV.NXT: text is ignored and a
    further FIN changes nothing (3.10.7.4, seventh and eighth). -/
theorem nothing_taken_after_fin (d : Departures) (t : Tcb) (s : Segment)
    (ho : otherState t = true) (hp : t.peerFin = true) :
    (arrive d t s).1.rcvNxt = t.rcvNxt := by
  obtain ⟨n, f, h, _, _, h3, _, _⟩ := rcvNxt_moves_by_text d t s ho
  by_cases hz : n + f = 0
  · rw [h, hz, adv_zero]
  · simp_all

/-- The right edge of the window, RCV.NXT+RCV.WND, never moves left: taken
    text moves RCV.NXT and shrinks RCV.WND alike, a FIN moves it one on
    (3.10.7.4, seventh: "the total of RCV.NXT and RCV.WND should not be
    reduced"). -/
theorem right_edge_kept (d : Departures) (t : Tcb) (s : Segment) (ho : otherState t = true) :
    ∃ f, f ≤ 1 ∧ adv (arrive d t s).1.rcvNxt (arrive d t s).1.rcvWnd = adv t.rcvNxt (t.rcvWnd + f) := by
  rw [arrive_other d t s ho]
  rcases otherArrive_shape d t s with ⟨h, _⟩ | ⟨st, h, _⟩ | ⟨a, st1, zw, _, _, _, _, h⟩
  · exact ⟨0, by omega, by simp [h]⟩
  · exact ⟨0, by omega, by simp [h]⟩
  · rw [h]
    obtain ⟨ord, -, hr, -, hw, -⟩ := proceed_receive d t s a st1 zw
    obtain ⟨f1, n1, -⟩ := move_facts d ord t s
    refine ⟨_, f1, ?_⟩
    rw [hr, hw, seq_eq_iff, adv_toNat, adv_toNat, adv_toNat]
    have := lt_M t.rcvNxt
    seq_omega

/-- With the RFC as written, an unacceptable segment with no RST and no
    SYN is answered with `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>` and changes
    nothing (3.10.7.4, first check). -/
theorem rfc_unacceptable_acked (t : Tcb) (s : Segment) (ho : otherState t = true)
    (hc : s.ctl = .none ∨ s.ctl = .fin)
    (hacc : acceptable t.rcvNxt t.rcvWnd s.seq s.len = false)
    (hz : zeroWindowText t s = false) :
    arrive .rfc t s = (t, ackOf t) := by
  rw [arrive_other _ t s ho]
  unfold otherArrive checks accepted
  rcases hc with hc | hc <;> simp [hc, hacc, hz, Departures.rfc] <;> split <;> rfl

/-- RFC 9293 3.10.7.3: in SYN-SENT an ACK outside ISS < SEG.ACK =< SND.NXT
    draws `<SEQ=SEG.ACK><CTL=RST>` whatever the segment carries but a RST:
    text, FIN or SYN. -/
theorem syn_sent_bad_ack_reset (d : Departures) (t : Tcb) (s : Segment) (a : Seq)
    (hs : t.state = .synSent) (ha : s.ack = some a) (hb : ltLe t.iss a t.sndNxt = false)
    (hr : s.ctl ≠ .rst) :
    arrive d t s = (t, .rst a) := by
  unfold arrive synSentArrive
  simp [hs, ha, hb, hr]

/-- An ACK half the sequence space past SND.UNA is never taken, in any
    synchronized state, while less than half the space is in flight: the
    record stays as it was. (`SeqNumber` leaves such a pair unordered;
    smoltcp once took it as new.) -/
theorem half_space_ack_not_taken (d : Departures) (t : Tcb) (s : Segment)
    (hst : t.state.synchronized = true) (hf : dist t.sndUna t.sndNxt < H)
    (ha : s.ack = some (adv t.sndUna H)) (hc : s.ctl = .none ∨ s.ctl = .fin) :
    (arrive d t s).1 = t := by
  have ho : otherState t = true := by simp [otherState, hst]
  rw [arrive_other d t s ho]
  rcases otherArrive_shape d t s with ⟨h, _⟩ | ⟨st, h, _, h3⟩ | ⟨a, st1, zw, ha', _, _, h4, _⟩
  · exact h
  · rcases hc with hc | hc <;> simp_all
  · rw [ha] at ha'
    have hae : a = adv t.sndUna H := (Option.some.inj ha').symm
    rw [hae] at h4
    have hd := dist_adv t.sndUna H
    rcases h4 with h4 | h4
    · unfold ltLe at h4
      simp only [decide_eq_true_eq] at h4
      seq_omega
    · apply absurd _ h4
      unfold ahead
      have := dist_trans t.sndUna t.sndNxt (adv t.sndUna H)
      have := dist_lt t.sndNxt (adv t.sndUna H)
      seq_omega

/-- RFC 9293 3.10.7.4 TIME-WAIT: the peer's FIN sent again (its FIN just
    before RCV.NXT) is acknowledged and changes nothing, with every set of
    departures. An earlier smoltcp rate-limited this ACK. -/
theorem time_wait_fin_again_acked (d : Departures) (t : Tcb) (s : Segment) (a : Seq)
    (hs : t.state = .timeWait) (hc : s.ctl = .fin) (ha : s.ack = some a)
    (hna : ¬ ahead a t.sndNxt) (hpos : adv s.seq (s.text + 1) = t.rcvNxt)
    (hw : t.rcvWnd < H) (ht : s.text < H) :
    arrive d t s = (t, ackOf t) := by
  have ho : otherState t = true := by simp [otherState, hs, State.synchronized]
  have hseq := congrArg UInt32.toNat hpos
  rw [adv_toNat] at hseq
  have h1 := lt_M s.seq; have h2 := lt_M t.rcvNxt
  have hacc : acceptable t.rcvNxt t.rcvWnd s.seq s.len = false := by
    unfold acceptable
    simp only [Segment.len, hc, dist_eq, adv_toNat]
    by_cases hw0 : t.rcvWnd = 0 <;> simp [hw0] <;> seq_omega
  have ht' : s.text < 2147483648 := ht
  have hne : s.seq ≠ t.rcvNxt := by
    intro e
    rw [seq_eq_iff] at e
    seq_omega
  have hz : zeroWindowText t s = false := by simp [zeroWindowText, hne]
  have hedge : finEdgeCase t s = false := by
    unfold finEdgeCase back
    simp only [dist_eq, Bool.and_eq_false_iff, beq_eq_false_iff_ne]
    right; seq_omega
  rw [arrive_other d t s ho]
  unfold otherArrive checks accepted
  simp [hc, ha, hacc, hz, hedge, hs, noAckCase, ackBeforeSeqCase, ackAheadCase,
    repeatSynAckCase, challengeSynCase, emptyRightEdgeCase, emptyOutOfWindowCase, hna]

/-! ## Each departure is used

For each flag, a record and segment in its case on which turning it on
alone changes what the RFC does. -/

/-- A record in ESTABLISHED: 5 octets in flight from 100, RCV.NXT 1000,
    RCV.WND 10. -/
def estab (wnd : Nat) : Tcb :=
  { state := .established, iss := 99, irs := 999, sndUna := 100, sndNxt := 105,
    rcvNxt := 1000, rcvWnd := wnd, synSent := true, finSent := false, peerFin := false,
    passive := true }

/-- A passive SYN-RECEIVED record. -/
def synRcvd : Tcb :=
  { state := .synReceived, iss := 100, irs := 999, sndUna := 100, sndNxt := 101,
    rcvNxt := 1000, rcvWnd := 10, synSent := true, finSent := false, peerFin := false,
    passive := true }

/-- A SYN-SENT record. -/
def synSentRec : Tcb :=
  { state := .synSent, iss := 100, irs := 0, sndUna := 100, sndNxt := 101,
    rcvNxt := 0, rcvWnd := 10, synSent := true, finSent := false, peerFin := false,
    passive := false }

theorem used_repeatSynAck :
    let s : Segment := { seq := 999, ack := none, ctl := .syn, text := 0 }
    repeatSynAckCase synRcvd s = true ∧
      arrive { Departures.rfc with repeatSynAck := true } synRcvd s ≠ arrive .rfc synRcvd s := by
  decide

theorem used_ackBeforeSeqInSynReceived :
    let s : Segment := { seq := 5000, ack := some 7, ctl := .none, text := 0 }
    ackBeforeSeqCase synRcvd s = true ∧
      arrive { Departures.rfc with ackBeforeSeqInSynReceived := true } synRcvd s ≠
        arrive .rfc synRcvd s := by
  decide

theorem used_challengeSynInSynReceived :
    let s : Segment := { seq := 1000, ack := none, ctl := .syn, text := 0 }
    challengeSynCase synRcvd s = true ∧
      arrive { Departures.rfc with challengeSynInSynReceived := true } synRcvd s ≠
        arrive .rfc synRcvd s := by
  decide

theorem used_noAckDroppedFirst :
    let s : Segment := { seq := 5000, ack := none, ctl := .none, text := 0 }
    noAckCase (estab 10) s = true ∧
      arrive { Departures.rfc with noAckDroppedFirst := true } (estab 10) s ≠
        arrive .rfc (estab 10) s := by
  decide

theorem used_ackCheckedBeforeSeq :
    let s : Segment := { seq := 5000, ack := some 200, ctl := .none, text := 1 }
    ackAheadCase (estab 10) s = true ∧
      arrive { Departures.rfc with ackCheckedBeforeSeq := true } (estab 10) s ≠
        arrive .rfc (estab 10) s := by
  decide

theorem used_rateLimitEmptyOutOfWindow :
    let s : Segment := { seq := 5000, ack := some 105, ctl := .none, text := 0 }
    emptyOutOfWindowCase (estab 10) s = true ∧
      arrive { Departures.rfc with rateLimitEmptyOutOfWindow := true } (estab 10) s ≠
        arrive .rfc (estab 10) s := by
  decide

theorem used_emptyAckAtRightEdge :
    let s : Segment := { seq := 1010, ack := some 103, ctl := .none, text := 0 }
    emptyRightEdgeCase (estab 10) s = true ∧
      arrive { Departures.rfc with emptyAckAtRightEdge := true } (estab 10) s ≠
        arrive .rfc (estab 10) s := by
  decide

theorem used_finAtRightEdge :
    let s : Segment := { seq := 1000, ack := some 105, ctl := .fin, text := 0 }
    finEdgeCase (estab 0) s = true ∧
      arrive { Departures.rfc with finAtRightEdge := true } (estab 0) s ≠
        arrive .rfc (estab 0) s := by
  decide

theorem used_textOnSynDropped :
    let s : Segment := { seq := 7, ack := some 101, ctl := .syn, text := 3 }
    synTextCase synSentRec s = true ∧
      arrive { Departures.rfc with textOnSynDropped := true } synSentRec s ≠
        arrive .rfc synSentRec s := by
  decide

end TcpRfc
