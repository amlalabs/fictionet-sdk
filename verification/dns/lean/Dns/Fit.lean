/-
  RRset-aware truncation: header, question, and OPT first; answer and authority RRsets whole; then
  the required additional RRsets (in-domain glue, RFC 9471 §3.1); then the optional ones. TC is set only
  when something required does not fit (RFC 2181 §9); optional additional data that does not fit is dropped
  without TC. The OPT record is always kept (RFC 6891 §7).

  Sizes are those of `Wire.encode` with compression, so a candidate fits when its whole encoded message,
  OPT included, is within the limit.

  Rust: `protocols::dns::fit::{Response, Limit, fit}`.
-/
import Dns.Wire

namespace Dns.Fit
open Wire

/-- The records of one owner, type, and class. -/
abbrev RRset := List RR

/-- A response before truncation. The first `required` additional RRsets are required. -/
structure Resp where
  header : Header
  question : List Question
  answer : List RRset
  authority : List RRset
  additional : List RRset
  required : Nat
  opt : Option RR
deriving Repr

inductive Limit where
  | udp512
  | udpEdns (size : Nat)
  | stream
deriving DecidableEq, Repr

/-- The limit in octets. A UDP payload size below 512 counts as 512 (RFC 6891 §6.2.5), as Rust's
`Limit::octets` reads it. -/
def Limit.size : Limit → Nat
  | .udp512 => 512
  | .udpEdns n => max 512 n
  | .stream => 65535

/-- The limit for a request: streams take a whole message; a UDP query without EDNS takes 512 octets; one
with EDNS takes min(max(512, its payload), the server's) (RFC 6891 §6.2.5). -/
def Limit.forRequest (stream : Bool) (payload : Option Nat) (server : Nat) : Limit :=
  if stream then .stream else
  match payload with
  | none => .udp512
  | some p => .udpEdns (min (max 512 p) server)

/-- The size a reply may take: a stream carries 65535 octets, the most its two-octet length says (RFC 1035
§4.2.2, RFC 7766 §8); a UDP reply to a query without EDNS takes at most 512 octets (RFC 1035 §2.3.4, §4.2.1);
with EDNS, at least 512 (RFC 6891 §6.2.5) and never more than the requestor's payload size, or 512 when that
is smaller (§6.2.3), nor than the server's own. -/
theorem forRequest_size (stream : Bool) (payload : Option Nat) (server : Nat) :
    (stream = true → (Limit.forRequest stream payload server).size = 65535) ∧
      (stream = false → payload = none → (Limit.forRequest stream payload server).size = 512) ∧
      512 ≤ (Limit.forRequest stream payload server).size ∧
      (stream = false → ∀ p, payload = some p →
        (Limit.forRequest stream payload server).size ≤ max 512 p ∧
        (Limit.forRequest stream payload server).size ≤ max 512 server) := by
  cases stream <;> cases payload <;> simp [Limit.forRequest, Limit.size] <;> omega

/-- The flags word with TC set to `tc`. -/
def setTc (flags : Nat) (tc : Bool) : Nat := flags - flags / 512 % 2 * 512 + b2n tc * 512

/-- The message made of the kept RRsets, with the OPT record last. -/
def message (r : Resp) (an au ad : List RRset) (tc : Bool) : Message :=
  ⟨⟨r.header.id, setTc r.header.flags tc⟩, r.question, an.flatten, au.flatten, ad.flatten ++ r.opt.toList⟩

def fits (r : Resp) (lim : Limit) (an au ad : List RRset) : Bool :=
  (encode true (message r an au ad false)).length ≤ lim.size

/-- Takes RRsets in order while the candidate fits; the flag says whether it took them all. -/
def takeFit (ok : List RRset → Bool) (kept : List RRset) : List RRset → List RRset × Bool
  | [] => (kept, true)
  | s :: rest => if ok (kept ++ [s]) then takeFit ok (kept ++ [s]) rest else (kept, false)

/-- What `fit` keeps, section by section, and whether it sets TC. -/
structure Plan where
  answer : List RRset
  authority : List RRset
  additional : List RRset
  tc : Bool
deriving Repr

def plan (r : Resp) (lim : Limit) : Plan :=
  let A := takeFit (fun a => fits r lim a [] []) [] r.answer
  if !A.2 then ⟨A.1, [], [], true⟩ else
  let N := takeFit (fun n => fits r lim A.1 n []) [] r.authority
  if !N.2 then ⟨A.1, N.1, [], true⟩ else
  let D := takeFit (fun d => fits r lim A.1 N.1 d) [] (r.additional.take r.required)
  if !D.2 then ⟨A.1, N.1, D.1, true⟩ else
  let O := takeFit (fun d => fits r lim A.1 N.1 (D.1 ++ d)) [] (r.additional.drop r.required)
  ⟨A.1, N.1, D.1 ++ O.1, false⟩

/-- The octets sent and whether TC is set. -/
def fit (r : Resp) (lim : Limit) : Bytes × Bool :=
  let p := plan r lim
  (encode true (message r p.answer p.authority p.additional p.tc), p.tc)

/-! ## Facts about `takeFit` -/

theorem takeFit_spec (ok : List RRset → Bool) (l : List RRset) : ∀ kept,
    ∃ p, (takeFit ok kept l).1 = kept ++ p ∧ p <+: l ∧ ((takeFit ok kept l).2 = true ↔ p = l) ∧
      (ok (takeFit ok kept l).1 = true ∨ p = []) := by
  induction l with
  | nil => intro kept; exact ⟨[], by simp [takeFit]⟩
  | cons s rest ih =>
    intro kept
    simp only [takeFit]
    split
    · rename_i hok
      obtain ⟨p, h1, h2, h3, h4⟩ := ih (kept ++ [s])
      refine ⟨s :: p, by simp [h1], List.cons_prefix_cons.mpr ⟨rfl, h2⟩, by simp [h3], ?_⟩
      rcases h4 with h4 | h4
      · exact Or.inl h4
      · subst h4; left; simpa [h1] using hok
    · exact ⟨[], by simp, List.nil_prefix, by simp, Or.inr rfl⟩

/-- Whatever `takeFit` keeps either was accepted or is what it started with. -/
theorem takeFit_ok (ok : List RRset → Bool) (kept l : List RRset) :
    ok (takeFit ok kept l).1 = true ∨ (takeFit ok kept l).1 = kept := by
  obtain ⟨p, h1, _, _, h4⟩ := takeFit_spec ok l kept
  rcases h4 with h4 | h4
  · exact Or.inl h4
  · right; simp [h1, h4]

theorem takeFit_nil (ok : List RRset → Bool) (l : List RRset) :
    (takeFit ok [] l).1 <+: l ∧ ((takeFit ok [] l).2 = true ↔ (takeFit ok [] l).1 = l) := by
  obtain ⟨p, h1, h2, h3, _⟩ := takeFit_spec ok l []
  simp only [List.nil_append] at h1
  rw [h1]; exact ⟨h2, h3⟩

theorem encode_tc (r : Resp) (an au ad : List RRset) (tc : Bool) :
    (encode true (message r an au ad tc)).length = (encode true (message r an au ad false)).length := by
  simp [encode, message, encHeader]

/-! ## The headline theorems -/

/-- When the header, question, and OPT fit at all, the output is within the limit. -/
theorem fit_size_le (r : Resp) (lim : Limit) (hbase : fits r lim [] [] [] = true) :
    (fit r lim).1.length ≤ lim.size := by
  simp only [fit, encode_tc]
  suffices fits r lim (plan r lim).answer (plan r lim).authority (plan r lim).additional = true by
    simpa [fits] using this
  simp only [plan]
  have hA := takeFit_ok (fun a => fits r lim a [] []) [] r.answer
  generalize takeFit (fun a => fits r lim a [] []) [] r.answer = A at *
  have fA : fits r lim A.1 [] [] = true := by rcases hA with h | h <;> simp_all
  have hN := takeFit_ok (fun n => fits r lim A.1 n []) [] r.authority
  generalize takeFit (fun n => fits r lim A.1 n []) [] r.authority = N at *
  have fN : fits r lim A.1 N.1 [] = true := by rcases hN with h | h <;> simp_all
  have hD := takeFit_ok (fun d => fits r lim A.1 N.1 d) [] (r.additional.take r.required)
  generalize takeFit (fun d => fits r lim A.1 N.1 d) [] (r.additional.take r.required) = D at *
  have fD : fits r lim A.1 N.1 D.1 = true := by rcases hD with h | h <;> simp_all
  have hO := takeFit_ok (fun d => fits r lim A.1 N.1 (D.1 ++ d)) [] (r.additional.drop r.required)
  generalize takeFit (fun d => fits r lim A.1 N.1 (D.1 ++ d)) [] (r.additional.drop r.required) = O at *
  have fO : fits r lim A.1 N.1 (D.1 ++ O.1) = true := by rcases hO with h | h <;> simp_all
  split
  · exact fA
  split
  · exact fN
  split
  · exact fD
  · exact fO

/-- A reply fitted to the limit of the request it answers takes no more than the request can receive:
512 octets over UDP without EDNS (RFC 1035 §4.2.1), the requestor's payload size or 512 with EDNS
(RFC 6891 §6.2.3, §6.2.5), and 65535 over a stream (RFC 1035 §4.2.2), when the header, question, and OPT fit
at all. -/
theorem fit_within_request (r : Resp) (stream : Bool) (payload : Option Nat) (server : Nat)
    (hbase : fits r (Limit.forRequest stream payload server) [] [] [] = true) :
    (fit r (Limit.forRequest stream payload server)).1.length ≤
      (if stream then 65535 else max 512 (payload.getD 512)) := by
  have h := fit_size_le r _ hbase
  obtain ⟨hs, hn, _, hp⟩ := forRequest_size stream payload server
  cases stream with
  | true => simp only [↓reduceIte]; rw [← hs rfl]; exact h
  | false =>
    simp only [Bool.false_eq_true, ↓reduceIte]
    cases payload with
    | none => rw [← hn rfl rfl]; simpa using h
    | some p => exact Nat.le_trans h (by simpa using (hp rfl p rfl).1)

/-- The output is the encoding of whole RRsets: a prefix of each section, never part of an RRset. -/
theorem fit_whole_rrsets (r : Resp) (lim : Limit) :
    (plan r lim).answer <+: r.answer ∧ (plan r lim).authority <+: r.authority ∧
      (plan r lim).additional <+: r.additional ∧
      (fit r lim).1 = encode true (message r (plan r lim).answer (plan r lim).authority (plan r lim).additional
        (plan r lim).tc) := by
  refine ⟨?_, ?_, ?_, rfl⟩ <;> simp only [plan]
  · have := (takeFit_nil (fun a => fits r lim a [] []) r.answer).1
    split
    · exact this
    split
    · exact this
    split <;> exact this
  · split
    · exact List.nil_prefix
    have := (takeFit_nil (fun n => fits r lim (takeFit (fun a => fits r lim a [] []) [] r.answer).1 n [])
      r.authority).1
    split
    · exact this
    split <;> exact this
  · split
    · exact List.nil_prefix
    split
    · exact List.nil_prefix
    generalize hA : (takeFit (fun a => fits r lim a [] []) [] r.answer).1 = A
    generalize hN : (takeFit (fun n => fits r lim A n []) [] r.authority).1 = N
    have hD := takeFit_nil (fun d => fits r lim A N d) (r.additional.take r.required)
    have hO := (takeFit_nil (fun d => fits r lim A N ((takeFit (fun d => fits r lim A N d) []
      (r.additional.take r.required)).1 ++ d)) (r.additional.drop r.required)).1
    split
    · exact hD.1.trans (List.take_prefix _ _)
    · rename_i hd
      simp only [Bool.not_eq_true', Bool.not_eq_false] at hd
      dsimp only
      have e := hD.2.mp (by simpa using hd)
      rw [e] at hO ⊢
      have h2 := (List.prefix_append_right_inj (r.additional.take r.required)).mpr hO
      rw [List.take_append_drop] at h2
      exact h2

/-- The OPT record is always the last record of the output. -/
theorem fit_keeps_opt (r : Resp) (lim : Limit) (o : RR) (h : r.opt = some o) :
    ∃ m, (fit r lim).1 = encode true m ∧ m.additional.getLast? = some o := by
  refine ⟨_, rfl, ?_⟩
  simp [message, h]

/-- TC is set exactly when an answer RRset, an authority RRset, or a required additional RRset was dropped. -/
theorem tc_iff_required_dropped (r : Resp) (lim : Limit) :
    (plan r lim).tc = true ↔ ¬ ((plan r lim).answer = r.answer ∧ (plan r lim).authority = r.authority ∧
      r.additional.take r.required <+: (plan r lim).additional) := by
  simp only [plan]
  have hA := takeFit_nil (fun a => fits r lim a [] []) r.answer
  generalize takeFit (fun a => fits r lim a [] []) [] r.answer = A at *
  have hN := takeFit_nil (fun n => fits r lim A.1 n []) r.authority
  generalize takeFit (fun n => fits r lim A.1 n []) [] r.authority = N at *
  have hD := takeFit_nil (fun d => fits r lim A.1 N.1 d) (r.additional.take r.required)
  generalize takeFit (fun d => fits r lim A.1 N.1 d) [] (r.additional.take r.required) = D at *
  by_cases a2 : A.2 = true
  · simp only [a2, Bool.not_true, Bool.false_eq_true, ↓reduceIte]
    by_cases n2 : N.2 = true
    · simp only [n2, Bool.not_true, Bool.false_eq_true, ↓reduceIte]
      by_cases d2 : D.2 = true
      · simp only [d2, Bool.not_true, Bool.false_eq_true, ↓reduceIte, false_iff, Classical.not_not]
        exact ⟨hA.2.mp a2, hN.2.mp n2, by rw [hD.2.mp d2]; exact List.prefix_append _ _⟩
      · simp only [d2, Bool.not_false, ↓reduceIte, true_iff, not_and]
        intro _ _ hp
        have hne : D.1 ≠ r.additional.take r.required := fun h => d2 (hD.2.mpr h)
        exact hne (List.IsPrefix.eq_of_length hD.1 (Nat.le_antisymm hD.1.length_le hp.length_le))
    · simp only [n2, Bool.not_false, ↓reduceIte, true_iff, not_and]
      exact fun _ h _ => n2 (hN.2.mpr h)
  · simp only [a2, Bool.not_false, ↓reduceIte, true_iff, not_and]
    exact fun h => absurd (hA.2.mpr h) a2

/-- Optional additional data never changes TC, or what is kept of the answer and authority sections. -/
theorem additional_drop_no_tc (r : Resp) (lim : Limit) :
    let r' := { r with additional := r.additional.take r.required }
    (plan r lim).tc = (plan r' lim).tc ∧ (plan r lim).answer = (plan r' lim).answer ∧
      (plan r lim).authority = (plan r' lim).authority := by
  intro r'
  have hf : fits r' lim = fits r lim := rfl
  have ht : r'.additional.take r'.required = r.additional.take r.required := by
    simp [r', List.take_take]
  have ha : r'.answer = r.answer := rfl
  have hau : r'.authority = r.authority := rfl
  simp only [plan, hf, ht, ha, hau]
  split
  · simp
  split
  · simp
  split <;> simp

end Dns.Fit
