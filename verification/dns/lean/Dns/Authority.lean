/-
  Servers of learned zones: the zone a world's server copies from what the real servers of the zone answered,
  the server's step for one request, and the engine's loop that looks up what the zone lacks, files what came
  back, and asks again.

  A learned zone holds filings, each what one response of a real server showed: the node at a name, or that
  nothing is at or below a name, with the denial records the response carried. Its view knows those facts and
  no others, so an answer from it rests only on what real servers said. When every filing is true of the real
  zone (`Copied`), an answer from the view is the real zone's answer but for optional additional data the copy
  does not hold (`learned_answer_upstream`), so a negative from the copy is the real zone's negative; a fact
  the copy does not hold ends the answer unknown, never negative (`learned_unknown_never_negative`); NXDOMAIN
  rests on a filed denial, with the denial records it came with (`learned_nxdomain_proved`); and filing more
  never changes an answer the copy gave (`learned_answer_stable`). The engine looks a request up at most once
  (`serve_one_lookup`), and what it replies keeps the same properties (`serve_reply_upstream`,
  `serve_nxdomain_proved`).

  Rust: `services::dns::zone::Learned`, `services::dns::lookup::{Lookup, Looked}`, and
  `services::dns::authority::{Step, Zones, AuthorityEngine}`.
-/
import Dns.Partial

namespace Dns.Authority
open Zone

/-! ## Learned zones -/

/-- What one response of a real server showed about one name. -/
inductive Filing where
  /-- The node at `n`. -/
  | node (n : Name) (nd : Node)
  /-- Nothing at or below `n` (RFC 8020), with the denial records the response carried: NSEC or NSEC3 records
  with their RRSIGs, none from an unsigned zone. -/
  | denied (n : Name) (proof : List RRset)
deriving DecidableEq, Repr

/-- Whether the filing is true of the zone `z`. -/
def Filing.holds (z : Zone) : Filing → Bool
  | .node n nd => z.look n == .present nd
  | .denied n _ => z.look n == .absent

/-- Whether the filing shows nothing at or below `n`: it denies `n` or a name above it. -/
def Filing.denies (n : Name) : Filing → Bool
  | .node .. => false
  | .denied m _ => under n m

/-- The node the filing shows at `n`, if it shows one there. -/
def Filing.nodeAt (n : Name) : Filing → Option Node
  | .node m nd => if m = n then some nd else none
  | .denied .. => none

/-- A zone learned from the servers of one real zone: its apex and SOA, every filing so far, the newest first,
and its revision, which each response filed makes new. -/
structure Learned where
  apex : Name
  soa : RRset
  filings : List Filing
  revision : Nat
deriving DecidableEq, Repr

/-- What the zone knows about `n`: absent when a filing denies it, the node a filing shows there, and otherwise
unknown. -/
def Learned.fact (L : Learned) (n : Name) : Fact Node :=
  if L.filings.any (·.denies n) then .absent
  else match L.filings.findSome? (·.nodeAt n) with
    | some nd => .present nd
    | none => .unknown

/-- The view of every question: the zone's facts, at its revision. -/
def Learned.view (L : Learned) : View := ⟨L.apex, L.soa, L.fact, L.revision⟩

/-- Every filing of `L` is true of the real zone `z`, whose apex and SOA `L` has. -/
def Copied (z : Zone) (L : Learned) : Prop :=
  L.apex = z.apex ∧ L.soa = z.soa ∧ L.filings.all (·.holds z) = true

theorem Copied.holds {z : Zone} {L : Learned} (h : Copied z L) {f : Filing} (hf : f ∈ L.filings) :
    f.holds z = true :=
  List.all_eq_true.mp h.2.2 f hf

/-- In a complete zone nothing is below a name that is absent. -/
theorem look_absent_below {z : Zone} {m n : Name} (h : z.look m = .absent) (hn : under n m = true) :
    z.look n = .absent := by
  rw [Zone.look_absent_iff] at h ⊢
  cases hp : z.presentB n with
  | false => rfl
  | true =>
    have := z.presentB_mono ((under_iff n m).mp hn) hp
    rw [h] at this
    cases this

/-- A learned zone's facts are the real zone's wherever it knows them. -/
theorem fact_refines {z : Zone} {L : Learned} (h : Copied z L) : Refines L.fact z.look := by
  intro n hk
  unfold Learned.fact at hk ⊢
  by_cases hd : L.filings.any (·.denies n) = true
  · simp only [hd, ↓reduceIte]
    obtain ⟨f, hf, hfd⟩ := List.any_eq_true.mp hd
    cases f with
    | node m nd => simp [Filing.denies] at hfd
    | denied m p =>
      have hh := h.holds hf
      simp only [Filing.holds, beq_iff_eq] at hh
      exact look_absent_below hh hfd
  · simp only [hd, Bool.false_eq_true, ↓reduceIte] at hk ⊢
    cases hs : L.filings.findSome? (·.nodeAt n) with
    | none => rw [hs] at hk; exact absurd rfl hk
    | some nd =>
      obtain ⟨f, hf, hfn⟩ := List.exists_of_findSome?_eq_some hs
      cases f with
      | denied => simp [Filing.nodeAt] at hfn
      | node m nd' =>
        simp only [Filing.nodeAt] at hfn
        by_cases hm : m = n
        · simp only [hm, ↓reduceIte] at hfn
          cases hfn
          subst hm
          have hh := h.holds hf
          simp only [Filing.holds, beq_iff_eq] at hh
          simpa using hh
        · simp only [hm, ↓reduceIte] at hfn
          cases hfn

theorem learned_agrees {z : Zone} {L : Learned} (h : Copied z L) : Agrees L.view z :=
  ⟨h.1, h.2.1, fact_refines h⟩

/-- An answer from the facts a learned zone holds is the real zone's answer to the question, but for optional
additional data the copy does not hold: the same RCODE, AA, answer, and authority sections. So every NXDOMAIN
and NODATA a copy gives is the real zone's. -/
theorem learned_answer_upstream {z : Zone} {L : Learned} (h : Copied z L) (req : Request) (any : AnyResponse)
    {r : Response} (ha : answerPartial L.view req any = .response r) :
    ∃ r', answer z req any = .response r' ∧ r.Grows r' :=
  answer_partial_sound L.view req any r ha z (learned_agrees h)

/-- A fact the zone does not hold ends the answer with that name, never with NXDOMAIN or NODATA: the question's
name when the walk reaches it, or the wildcard when the name is known absent and the wildcard is not known. -/
theorem learned_unknown_never_negative (L : Learned) (req : Request) (any : AnyResponse)
    (hq : L.apex <:+ req.qname) (hr : L.view.Reaches req.qname) :
    (L.fact req.qname = .unknown → answerPartial L.view req any = .unknown req.qname) ∧
    (∀ l p, req.qname = l :: p → req.qname ≠ L.apex → L.fact req.qname = .absent →
      L.fact (wild p) = .unknown → answerPartial L.view req any = .unknown (wild p)) :=
  unknown_never_negative L.view req any hq hr

/-! ## NXDOMAIN rests on a name read absent -/

/-- Whether a step finished with NXDOMAIN. -/
def isNx : Out → Bool
  | .done .nxdomain .. => true
  | _ => false

theorem referral_not_nx {look : Name → Fact Node} {apex m : Name} {ns : RRset} {g : List RRset} {o : Out}
    (h : referral look apex m ns g = .ok o) : isNx o = false := by
  unfold referral at h
  split at h
  · cases h; rfl
  · cases h

theorem exact_not_nx {look : Name → Fact Node} {apex : Name} {soa : RRset} {any : AnyResponse} {q : Name}
    {qtype : Nat} {sets : List RRset} {o : Out} (h : exact look apex soa any q qtype sets = .ok o) :
    isNx o = false := by
  unfold exact at h
  split at h
  · split at h <;> (cases h; rfl)
  · split at h
    · split at h
      · cases h; rfl
      · cases h
    · split at h
      · split at h <;> (cases h; rfl)
      · cases h; rfl

theorem step_nx {look : Name → Fact Node} {apex : Name} {soa : RRset} {any : AnyResponse} {q : Name}
    {qtype : Nat} {o : Out} (h : step look apex soa any q qtype = .ok o) (hx : isNx o = true) :
    ∃ n, look n = .absent := by
  unfold step at h
  split at h
  · cases h
  · cases h; cases hx
  · split at h
    · split at h <;> (cases h; cases hx)
    · rw [referral_not_nx h] at hx; cases hx
  · split at h
    · dsimp only at h
      split at h <;> (cases h; cases hx)
    · cases h; cases hx
  · rw [exact_not_nx h] at hx; cases hx
  · rename_i ce _
    split at h
    · cases h
    · rename_i hg
      refine ⟨wild ce, ?_⟩
      cases hl : look (wild ce) with
      | present => simp [Zone.get, hl] at hg
      | absent => rfl
      | unknown => simp [Zone.get, hl] at hg
    · rw [referral_not_nx h] at hx; cases hx
    · rw [exact_not_nx h] at hx; cases hx

theorem chase_nx {look : Name → Fact Node} {apex : Name} {soa : RRset} {any : AnyResponse} {qtype : Nat} :
    ∀ f seen acc q r, chase look apex soa any qtype f seen acc q = .ok r → r.rcode = .nxdomain →
      ∃ n, look n = .absent := by
  intro f
  induction f with
  | zero => intro _ _ _ r h hr; simp only [chase] at h; cases h; cases hr
  | succ f ih =>
    intro seen acc q r h hr
    unfold chase at h
    split at h
    · cases h
    · rename_i rc aa an au ad req hs
      cases h
      simp only at hr
      subst hr
      exact step_nx hs rfl
    · split at h
      · cases h; cases hr
      · exact ih _ _ _ _ h hr

/-- NXDOMAIN from any view rests on a name the view read absent. -/
theorem answer_nx {look : Name → Fact Node} {apex : Name} {soa : RRset} {any : AnyResponse} {req : Request}
    {r : Response} (h : answerWith look apex soa any req = .response r) (hx : r.rcode = .nxdomain) :
    ∃ n, look n = .absent := by
  unfold answerWith at h
  split at h
  · cases h; cases hx
  · split at h
    · rename_i hc; cases h; exact chase_nx _ _ _ _ _ hc hx
    · cases h

theorem fact_absent {L : Learned} {n : Name} (h : L.fact n = .absent) :
    ∃ m p, Filing.denied m p ∈ L.filings ∧ m <:+ n := by
  unfold Learned.fact at h
  by_cases hd : L.filings.any (·.denies n) = true
  · obtain ⟨f, hf, hfd⟩ := List.any_eq_true.mp hd
    cases f with
    | node => simp [Filing.denies] at hfd
    | denied m p => exact ⟨m, p, hf, (under_iff n m).mp hfd⟩
  · simp only [hd, Bool.false_eq_true, ↓reduceIte] at h
    split at h <;> cases h

/-- A learned zone answers NXDOMAIN only with a filed denial: a response of a real server showed nothing at or
below a name, and the zone holds the denial records that came with it. -/
theorem learned_nxdomain_proved {L : Learned} {req : Request} {any : AnyResponse} {r : Response}
    (h : answerPartial L.view req any = .response r) (hx : r.rcode = .nxdomain) :
    ∃ n m p, Filing.denied m p ∈ L.filings ∧ m <:+ n ∧ L.fact n = .absent := by
  obtain ⟨n, hn⟩ := answer_nx h hx
  obtain ⟨m, p, hm, hs⟩ := fact_absent hn
  exact ⟨n, m, p, hm, hs, hn⟩

/-! ## Filing -/

/-- One question put to a real server of a zone: the server, the zone the response is filed into, and the
client's question. -/
structure Lookup where
  server : Nat
  zone : Name
  req : Request
deriving DecidableEq, Repr

/-- What a lookup gave: the filings of the server's response, or nothing, when the server could not be reached,
did not reply, or the world's policy kept the question from leaving. -/
inductive Looked where
  | response (filings : List Filing)
  | nothing
deriving DecidableEq, Repr

/-- Files what a lookup gave. A response is a new revision; nothing changes nothing. -/
def Learned.file (L : Learned) : Looked → Learned
  | .response fs => { L with filings := fs ++ L.filings, revision := L.revision + 1 }
  | .nothing => L

/-- What a real server of the zone `z` can give: filings true of `z`, or nothing. -/
def Looked.of (z : Zone) : Looked → Bool
  | .response fs => fs.all (·.holds z)
  | .nothing => true

theorem file_apex (L : Learned) (lk : Looked) : (L.file lk).apex = L.apex := by
  cases lk <;> rfl

theorem file_copied {z : Zone} {L : Learned} {lk : Looked} (h : Copied z L) (hl : lk.of z = true) :
    Copied z (L.file lk) := by
  cases lk with
  | nothing => exact h
  | response fs =>
    refine ⟨h.1, h.2.1, ?_⟩
    simp only [Learned.file, List.all_append, Bool.and_eq_true]
    exact ⟨hl, h.2.2⟩

theorem fact_known_file {L : Learned} {n : Name} (lk : Looked) (hk : L.fact n ≠ .unknown) :
    (L.file lk).fact n ≠ .unknown := by
  cases lk with
  | nothing => exact hk
  | response fs =>
    intro hu
    apply hk
    unfold Learned.fact at hu ⊢
    simp only [Learned.file, List.any_append, List.findSome?_append] at hu
    by_cases hd : L.filings.any (·.denies n) = true
    · simp [hd] at hu
    · simp only [hd, Bool.false_eq_true, ↓reduceIte]
      cases hs : L.filings.findSome? (·.nodeAt n) with
      | none => rfl
      | some nd =>
        exfalso
        cases hf : fs.findSome? (·.nodeAt n) <;> by_cases hd' : fs.any (·.denies n) = true <;>
          simp [hd', hd, hs, hf] at hu

/-- Filing a response true of the zone only adds facts: every fact the zone knew stays as it was. -/
theorem file_refines {z : Zone} {L : Learned} {lk : Looked} (h : Copied z L) (hl : lk.of z = true) :
    Refines L.fact (L.file lk).fact := by
  intro n hk
  rw [← fact_refines (file_copied h hl) n (fact_known_file lk hk)]
  exact fact_refines h n hk

/-- An answer a learned zone gave stays its answer after any filing true of the zone, but for optional
additional data the new facts may add. -/
theorem learned_answer_stable {z : Zone} {L : Learned} {lk : Looked} (h : Copied z L) (hl : lk.of z = true)
    {req : Request} {any : AnyResponse} {r : Response} (ha : answerPartial L.view req any = .response r) :
    ∃ r', answerPartial (L.file lk).view req any = .response r' ∧ r.Grows r' := by
  have hr := file_refines h hl
  cases lk <;> exact answerWith_ref hr ha

/-! ## The server and the engine -/

inductive Step where
  | reply (r : Response)
  | need (l : Lookup)
  | silent
deriving DecidableEq, Repr

/-- `Zones` over one learned zone, at the server with address `addr`: the answer from the zone's view, or, when
the view lacks a fact, a lookup of the client's question at the server's own address. -/
def respond (any : AnyResponse) (addr : Nat) (L : Learned) (req : Request) : Step :=
  match answerPartial L.view req any with
  | .response r => .reply r
  | .unknown _ => .need ⟨addr, L.apex, req⟩

/-- The engine's loop for one request: on a `Need` for a lookup it has not made for the request, the upstream
answers it (`up`), the engine files what came back and asks again; on a `Need` for one it made, the server stays
silent, as a server that cannot answer does. The fuel only makes the definition total (`serve_one_lookup`). -/
def serve (any : AnyResponse) (addr : Nat) (up : Lookup → Looked) :
    Nat → Learned → List Lookup → Request → Learned × Step
  | 0, L, _, _ => (L, .silent)
  | f + 1, L, looked, req =>
    match respond any addr L req with
    | .need l => if l ∈ looked then (L, .silent) else serve any addr up f (L.file (up l)) (l :: looked) req
    | s => (L, s)

theorem respond_need {any : AnyResponse} {addr : Nat} {L : Learned} {req : Request} {l : Lookup}
    (h : respond any addr L req = .need l) : l = ⟨addr, L.apex, req⟩ := by
  unfold respond at h
  split at h <;> cases h
  rfl

theorem respond_reply {any : AnyResponse} {addr : Nat} {L : Learned} {req : Request} {r : Response}
    (h : respond any addr L req = .reply r) : answerPartial L.view req any = .response r := by
  unfold respond at h
  split at h
  · rename_i hr; cases h; exact hr
  · cases h

/-- One step of the loop, by what the server's step is. -/
theorem serve_succ (any : AnyResponse) (addr : Nat) (up : Lookup → Looked) (f : Nat) (L : Learned)
    (looked : List Lookup) (req : Request) :
    serve any addr up (f + 1) L looked req =
      match respond any addr L req with
      | .reply r => (L, .reply r)
      | .silent => (L, .silent)
      | .need l => if l ∈ looked then (L, .silent) else serve any addr up f (L.file (up l)) (l :: looked) req := by
  conv => lhs; unfold serve
  cases respond any addr L req <;> rfl

/-- The loop never ends on a `Need`. -/
theorem serve_not_need (any : AnyResponse) (addr : Nat) (up : Lookup → Looked) (req : Request) (l : Lookup) :
    ∀ f L looked, (serve any addr up f L looked req).2 ≠ .need l := by
  intro f
  induction f with
  | zero => intro L looked h; cases h
  | succ f ih =>
    intro L looked
    rw [serve_succ]
    cases respond any addr L req with
    | reply r => intro h; cases h
    | silent => intro h; cases h
    | need l' =>
      dsimp only
      by_cases hm : l' ∈ looked
      · simp only [hm, ↓reduceIte]; intro h; cases h
      · simp only [hm, ↓reduceIte]; exact ih _ _

/-- After its lookup, a request needs no other: the server replies, or stays silent. -/
theorem serve_after_lookup (any : AnyResponse) (addr : Nat) (up : Lookup → Looked) (f : Nat) (L : Learned)
    (req : Request) (l : Lookup) (hl : l = ⟨addr, L.apex, req⟩) :
    serve any addr up (f + 1) L [l] req =
      match respond any addr L req with
      | .reply r => (L, .reply r)
      | _ => (L, .silent) := by
  rw [serve_succ]
  cases h : respond any addr L req with
  | need l' => simp [respond_need h, hl]
  | reply r => rfl
  | silent => rfl

/-- The engine looks a request up at most once: with any fuel from 2 up, it gives what it gives with 2. -/
theorem serve_one_lookup (any : AnyResponse) (addr : Nat) (up : Lookup → Looked) (f : Nat) (L : Learned)
    (req : Request) : serve any addr up (f + 2) L [] req = serve any addr up 2 L [] req := by
  rw [serve_succ, serve_succ]
  cases h : respond any addr L req with
  | reply r => rfl
  | silent => rfl
  | need l =>
    have hl : l = ⟨addr, (L.file (up l)).apex, req⟩ := by rw [file_apex]; exact respond_need h
    simp only [List.not_mem_nil, ↓reduceIte]
    rw [serve_after_lookup any addr up f _ req l hl, serve_after_lookup any addr up 0 _ req l hl]

theorem serve_copied {z : Zone} {any : AnyResponse} {addr : Nat} {up : Lookup → Looked}
    (hup : ∀ l, (up l).of z = true) {req : Request} :
    ∀ f L looked, Copied z L → Copied z (serve any addr up f L looked req).1 := by
  intro f
  induction f with
  | zero => intro L _ h; exact h
  | succ f ih =>
    intro L looked h
    rw [serve_succ]
    cases respond any addr L req with
    | reply r => exact h
    | silent => exact h
    | need l =>
      dsimp only
      by_cases hm : l ∈ looked
      · simp only [hm, ↓reduceIte]; exact h
      · simp only [hm, ↓reduceIte]; exact ih _ _ (file_copied h (hup _))

theorem serve_reply {any : AnyResponse} {addr : Nat} {up : Lookup → Looked} {req : Request} :
    ∀ f L looked r, (serve any addr up f L looked req).2 = .reply r →
      answerPartial (serve any addr up f L looked req).1.view req any = .response r := by
  intro f
  induction f with
  | zero => intro L looked r h; cases h
  | succ f ih =>
    intro L looked r
    rw [serve_succ]
    cases hr : respond any addr L req with
    | reply r' => intro h; cases h; exact respond_reply hr
    | silent => intro h; cases h
    | need l =>
      dsimp only
      by_cases hm : l ∈ looked
      · simp only [hm, ↓reduceIte]; intro h; cases h
      · simp only [hm, ↓reduceIte]; exact ih _ _ _

/-- Whatever the engine replies over a copy of `z`, with an upstream whose responses are true of `z`, is `z`'s
answer to the question, but for optional additional data: never a guess, and never a negative `z` does not
give. -/
theorem serve_reply_upstream {z : Zone} {any : AnyResponse} {addr : Nat} {up : Lookup → Looked}
    (hup : ∀ l, (up l).of z = true) {f : Nat} {L : Learned} {looked : List Lookup} {req : Request} {r : Response}
    (hc : Copied z L) (h : (serve any addr up f L looked req).2 = .reply r) :
    ∃ r', answer z req any = .response r' ∧ r.Grows r' :=
  learned_answer_upstream (serve_copied hup f L looked hc) req any (serve_reply f L looked r h)

/-- The engine replies NXDOMAIN only from a filed denial, held with the denial records it came with. -/
theorem serve_nxdomain_proved {any : AnyResponse} {addr : Nat} {up : Lookup → Looked} {f : Nat} {L : Learned}
    {looked : List Lookup} {req : Request} {r : Response} (h : (serve any addr up f L looked req).2 = .reply r)
    (hx : r.rcode = .nxdomain) :
    ∃ n m p, Filing.denied m p ∈ (serve any addr up f L looked req).1.filings ∧ m <:+ n ∧
      (serve any addr up f L looked req).1.fact n = .absent :=
  learned_nxdomain_proved (serve_reply f L looked r h) hx

end Dns.Authority
