/-
  Servers of learned zones: the zone a world's server copies from what the real servers of the zone answered,
  the server's step for one request, the engine's loop that looks up what the zone lacks, files what came back,
  and asks again, and overlays that invent zones below a learned one.

  A learned zone holds filings, each what one response of a real server showed: the node at a name, or that
  nothing is at or below a name, with the denial records the response carried. Its view knows those facts and
  no others, so an answer from it rests only on what real servers said. When every filing is true of the real
  zone and its denial records are the ones the real zone's servers send (`Copied`), an answer from the view is
  the real zone's answer but for optional additional data the copy does not hold (`learned_answer_upstream`),
  so a negative from the copy is the real zone's negative; a fact the copy does not hold ends the answer
  unknown, never negative (`learned_unknown_never_negative`); NXDOMAIN rests on a filed denial whose records the
  copy holds, and they are the real zone's records for that name (`learned_nxdomain_proved`); and filing more
  never changes an answer the copy gave (`learned_answer_stable`). The engine's loop ends within one more step
  than an authority has distinct lookups for a request (`loop_bounded`), so it looks a request up at most once
  (`serve_one_lookup`), and what it replies keeps the same properties (`serve_reply_upstream`,
  `serve_nxdomain_proved`). An overlay over a learned zone needs at most two lookups for a request, the
  parent's `<apex> DS` and the question itself (`overlay_needs`, `overlay_loop_bounded`), and a reply it gave
  stays its reply as the zone learns more (`overlay_reply_stable`).

  The answers here carry no denial records: this model's answer is the unsigned one of `Dns/Zone.lean`. What
  the copy holds is modelled; that a signed copy sends the records it holds, and the real servers' NODATA
  proofs, are checked by the differential test's `learned_signed` vectors against `Dns/Dnssec.lean`.

  Rust: `services::dns::zone::Learned`, `services::dns::lookup::{Lookup, Looked}`, and
  `services::dns::authority::{Step, Copies, AuthorityEngine, Overlay}`.
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

/-- The denial records a real zone's servers send to show that nothing is at or below a name: NSEC or NSEC3
records with their RRSIGs, none for an unsigned zone. -/
abbrev Proofs := Name → List RRset

/-- Whether the filing is true of the zone `z`, whose servers send the denial records `proofs`: the node is
`z`'s, or nothing is at or below the name in `z` and the records are the ones `z`'s servers send for it. -/
def Filing.holds (z : Zone) (proofs : Proofs) : Filing → Bool
  | .node n nd => z.look n == .present nd
  | .denied n p => z.look n == .absent && p == proofs n

/-- Whether the filing shows nothing at or below `n`: it denies `n` or a name above it. -/
def Filing.denies (n : Name) : Filing → Bool
  | .node .. => false
  | .denied m _ => under n m

/-- The node the filing shows at `n`, if it shows one there. -/
def Filing.nodeAt (n : Name) : Filing → Option Node
  | .node m nd => if m = n then some nd else none
  | .denied .. => none

/-- The denial records the filing holds for `n`, if it denies `n` itself. -/
def Filing.proofAt (n : Name) : Filing → Option (List RRset)
  | .node .. => none
  | .denied m p => if m = n then some p else none

/-- A zone learned from the servers of one real zone: its apex and SOA, every filing so far, the newest first,
its revision, which each response filed makes new, and the questions a server answered with an error RCODE
that gives no facts, by server, with that RCODE. Rust: `Learned::failed`. -/
structure Learned where
  apex : Name
  soa : RRset
  filings : List Filing
  revision : Nat
  failed : List (Nat × Request × Rcode)
deriving DecidableEq, Repr

/-- What the zone knows about `n`: absent when a filing denies it, the node a filing shows there, and otherwise
unknown. -/
def Learned.fact (L : Learned) (n : Name) : Fact Node :=
  if L.filings.any (·.denies n) then .absent
  else match L.filings.findSome? (·.nodeAt n) with
    | some nd => .present nd
    | none => .unknown

/-- The denial records the zone holds for `n`: those of the newest filing that denies `n` itself. Rust:
`View::denial` for `Denied::Name`. -/
def Learned.proof (L : Learned) (n : Name) : Option (List RRset) :=
  L.filings.findSome? (·.proofAt n)

/-- The view of every question: the zone's facts, at its revision. -/
def Learned.view (L : Learned) : View := ⟨L.apex, L.soa, L.fact, L.revision⟩

/-- Every filing of `L` is true of the real zone `z`, whose apex and SOA `L` has, and whose servers send the
denial records `proofs`, and no server answered a question of it with an error. -/
def Copied (z : Zone) (proofs : Proofs) (L : Learned) : Prop :=
  L.apex = z.apex ∧ L.soa = z.soa ∧ L.filings.all (·.holds z proofs) = true ∧ L.failed = []

theorem Copied.holds {z : Zone} {proofs : Proofs} {L : Learned} (h : Copied z proofs L) {f : Filing}
    (hf : f ∈ L.filings) : f.holds z proofs = true :=
  List.all_eq_true.mp h.2.2.1 f hf

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
theorem fact_refines {z : Zone} {proofs : Proofs} {L : Learned} (h : Copied z proofs L) :
    Refines L.fact z.look := by
  intro n hk
  unfold Learned.fact at hk ⊢
  by_cases hd : L.filings.any (·.denies n) = true
  · simp only [hd, ↓reduceIte]
    obtain ⟨f, hf, hfd⟩ := List.any_eq_true.mp hd
    cases f with
    | node m nd => simp [Filing.denies] at hfd
    | denied m p =>
      have hh := h.holds hf
      simp only [Filing.holds, Bool.and_eq_true, beq_iff_eq] at hh
      exact look_absent_below hh.1 hfd
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

theorem learned_agrees {z : Zone} {proofs : Proofs} {L : Learned} (h : Copied z proofs L) : Agrees L.view z :=
  ⟨h.1, h.2.1, fact_refines h⟩

/-- An answer from the facts a learned zone holds is the real zone's answer to the question, but for optional
additional data the copy does not hold: the same RCODE, AA, answer, and authority sections. So every NXDOMAIN
and NODATA a copy gives is the real zone's. -/
theorem learned_answer_upstream {z : Zone} {proofs : Proofs} {L : Learned} (h : Copied z proofs L)
    (req : Request) (any : AnyResponse) {r : Response} (ha : answerPartial L.view req any = .response r) :
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

theorem findSome?_isSome_of_mem {α β : Type} {f : α → Option β} :
    ∀ {l : List α} {a : α} {b : β}, a ∈ l → f a = some b → ∃ b', l.findSome? f = some b' := by
  intro l
  induction l with
  | nil => intro a b ha; cases ha
  | cons x xs ih =>
    intro a b ha hf
    rw [List.findSome?_cons]
    cases hx : f x with
    | some b' => exact ⟨b', rfl⟩
    | none =>
      rcases List.mem_cons.mp ha with rfl | ha
      · rw [hf] at hx; cases hx
      · exact ih ha hf

/-- A copy holds, for every name it filed a denial of, the denial records the real zone's servers send for it. -/
theorem proof_held {z : Zone} {proofs : Proofs} {L : Learned} (h : Copied z proofs L) {m : Name}
    {p : List RRset} (hm : Filing.denied m p ∈ L.filings) : L.proof m = some (proofs m) := by
  obtain ⟨p', hp'⟩ := findSome?_isSome_of_mem (f := (·.proofAt m)) (b := p) hm (by simp [Filing.proofAt])
  obtain ⟨f, hf, hfp⟩ := List.exists_of_findSome?_eq_some hp'
  cases f with
  | node => simp [Filing.proofAt] at hfp
  | denied m' q =>
    simp only [Filing.proofAt] at hfp
    by_cases he : m' = m
    · simp only [he, ↓reduceIte, Option.some.injEq] at hfp
      subst he hfp
      have hh := h.holds hf
      simp only [Filing.holds, Bool.and_eq_true, beq_iff_eq] at hh
      unfold Learned.proof
      rw [hp', hh.2]
    · simp [he] at hfp

/-- A learned zone answers NXDOMAIN only from a filed denial whose records it holds: a response of a real
server showed nothing at or below a name `m` at or above a name the answer read absent, and the records the
zone holds for `m` are the ones the real zone's servers send for it. -/
theorem learned_nxdomain_proved {z : Zone} {proofs : Proofs} {L : Learned} {req : Request} {any : AnyResponse}
    {r : Response} (hc : Copied z proofs L) (h : answerPartial L.view req any = .response r)
    (hx : r.rcode = .nxdomain) : ∃ n m, L.fact n = .absent ∧ m <:+ n ∧ L.proof m = some (proofs m) := by
  obtain ⟨n, hn⟩ := answer_nx h hx
  obtain ⟨m, p, hm, hs⟩ := fact_absent hn
  exact ⟨n, m, hn, hs, proof_held hc hm⟩

/-! ## Filing -/

/-- One question put to a real server of a zone: the server, the zone the response is filed into, and the
client's question. -/
structure Lookup where
  server : Nat
  zone : Name
  req : Request
deriving DecidableEq, Repr

/-- What a lookup gave: the filings of the server's response; that the server at `server` answered `req` with
an error RCODE other than REFUSED, such as SERVFAIL, which gives no facts (RFC 8906 §3.1); or nothing, when the
server could not be reached, did not reply, or the world's policy kept the question from leaving. -/
inductive Looked where
  | response (filings : List Filing)
  | failed (server : Nat) (req : Request) (rcode : Rcode)
  | nothing
deriving DecidableEq, Repr

/-- Files what a lookup gave. A response is a new revision; an error RCODE is kept apart from the facts, and
nothing changes nothing. -/
def Learned.file (L : Learned) : Looked → Learned
  | .response fs => { L with filings := fs ++ L.filings, revision := L.revision + 1 }
  | .failed s q rc => { L with failed := (s, q, rc) :: L.failed }
  | .nothing => L

/-- What a real server of the zone `z`, whose servers send the denial records `proofs`, gives when it answers
every question from `z`: filings true of `z`, or nothing. -/
def Looked.of (z : Zone) (proofs : Proofs) : Looked → Bool
  | .response fs => fs.all (·.holds z proofs)
  | .failed .. => false
  | .nothing => true

theorem file_apex (L : Learned) (lk : Looked) : (L.file lk).apex = L.apex := by
  cases lk <;> rfl

theorem file_copied {z : Zone} {proofs : Proofs} {L : Learned} {lk : Looked} (h : Copied z proofs L)
    (hl : lk.of z proofs = true) : Copied z proofs (L.file lk) := by
  cases lk with
  | nothing => exact h
  | failed => cases hl
  | response fs =>
    refine ⟨h.1, h.2.1, ?_, h.2.2.2⟩
    simp only [Learned.file, List.all_append, Bool.and_eq_true]
    exact ⟨hl, h.2.2.1⟩

theorem fact_known_file {L : Learned} {n : Name} (lk : Looked) (hk : L.fact n ≠ .unknown) :
    (L.file lk).fact n ≠ .unknown := by
  cases lk with
  | nothing => exact hk
  | failed => exact hk
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
theorem file_refines {z : Zone} {proofs : Proofs} {L : Learned} {lk : Looked} (h : Copied z proofs L)
    (hl : lk.of z proofs = true) : Refines L.fact (L.file lk).fact := by
  intro n hk
  rw [← fact_refines (file_copied h hl) n (fact_known_file lk hk)]
  exact fact_refines h n hk

/-- An answer a learned zone gave stays its answer after any filing true of the zone, but for optional
additional data the new facts may add. -/
theorem learned_answer_stable {z : Zone} {proofs : Proofs} {L : Learned} {lk : Looked} (h : Copied z proofs L)
    (hl : lk.of z proofs = true) {req : Request} {any : AnyResponse} {r : Response}
    (ha : answerPartial L.view req any = .response r) :
    ∃ r', answerPartial (L.file lk).view req any = .response r' ∧ r.Grows r' := by
  have hr := file_refines h hl
  cases lk <;> exact answerWith_ref hr ha

/-! ## The engine's loop -/

inductive Step where
  | reply (r : Response)
  | need (l : Lookup)
  | silent
deriving DecidableEq, Repr

/-- The engine's loop for one request to an authority `R` over a learned zone: on a `Need` for a lookup it has
not made for the request, the upstream answers it (`up`), the engine files what came back and asks again; on a
`Need` for one it made, the server stays silent, as a server that cannot answer does. The fuel only makes the
definition total (`loop_bounded`). -/
def loop (R : Learned → Request → Step) (up : Lookup → Looked) :
    Nat → Learned → List Lookup → Request → Learned × Step
  | 0, L, _, _ => (L, .silent)
  | f + 1, L, looked, req =>
    match R L req with
    | .need l => if l ∈ looked then (L, .silent) else loop R up f (L.file (up l)) (l :: looked) req
    | s => (L, s)

/-- One step of the loop, by what the authority's step is. -/
theorem loop_succ (R : Learned → Request → Step) (up : Lookup → Looked) (f : Nat) (L : Learned)
    (looked : List Lookup) (req : Request) :
    loop R up (f + 1) L looked req =
      match R L req with
      | .reply r => (L, .reply r)
      | .silent => (L, .silent)
      | .need l => if l ∈ looked then (L, .silent) else loop R up f (L.file (up l)) (l :: looked) req := by
  conv => lhs; unfold loop
  cases R L req <;> rfl

/-- The loop never ends on a `Need`. -/
theorem loop_not_need (R : Learned → Request → Step) (up : Lookup → Looked) (req : Request) (l : Lookup) :
    ∀ f L looked, (loop R up f L looked req).2 ≠ .need l := by
  intro f
  induction f with
  | zero => intro L looked h; cases h
  | succ f ih =>
    intro L looked
    rw [loop_succ]
    cases R L req with
    | reply r => intro h; cases h
    | silent => intro h; cases h
    | need l' =>
      dsimp only
      by_cases hm : l' ∈ looked
      · simp only [hm, ↓reduceIte]; intro h; cases h
      · simp only [hm, ↓reduceIte]; exact ih _ _

/-- Every lookup `R` needs for `req`, over any learned zone with apex `a`, is one of `asks`. -/
def Needs (R : Learned → Request → Step) (a : Name) (req : Request) (asks : List Lookup) : Prop :=
  ∀ L l, L.apex = a → R L req = .need l → l ∈ asks

theorem loop_fuel (R : Learned → Request → Step) (up : Lookup → Looked) (req : Request) (a : Name)
    (asks : List Lookup) (hn : Needs R a req asks) :
    ∀ f g L looked, L.apex = a → looked.Nodup → (∀ l ∈ looked, l ∈ asks) → asks.length + 1 ≤ f + looked.length →
      loop R up (f + g) L looked req = loop R up f L looked req := by
  intro f
  induction f with
  | zero =>
    intro g L looked _ hnd hsub hlen
    have : looked.length ≤ asks.length := List.Nodup.length_le_of_subset hnd (fun l hl => hsub l hl)
    omega
  | succ f ih =>
    intro g L looked ha hnd hsub hlen
    rw [show f + 1 + g = (f + g) + 1 by omega, loop_succ, loop_succ]
    cases hr : R L req with
    | reply r => rfl
    | silent => rfl
    | need l =>
      dsimp only
      by_cases hm : l ∈ looked
      · simp only [hm, ↓reduceIte]
      · simp only [hm, ↓reduceIte]
        refine ih g _ _ (by rw [file_apex]; exact ha) (List.nodup_cons.mpr ⟨hm, hnd⟩) (fun l' h' => ?_)
          (by simp only [List.length_cons]; omega)
        rcases List.mem_cons.mp h' with rfl | h'
        · exact hn L l' ha hr
        · exact hsub l' h'

/-- With every lookup an authority needs for a request among `asks`, the loop replies or stays silent within
one more step than there are asks: more fuel changes nothing. -/
theorem loop_bounded (R : Learned → Request → Step) (up : Lookup → Looked) (req : Request) (L : Learned)
    (asks : List Lookup) (hn : Needs R L.apex req asks) (g : Nat) :
    loop R up (asks.length + 1 + g) L [] req = loop R up (asks.length + 1) L [] req :=
  loop_fuel R up req L.apex asks hn (asks.length + 1) g L [] rfl List.nodup_nil (by simp) (by simp)

theorem loop_copied {z : Zone} {proofs : Proofs} {R : Learned → Request → Step} {up : Lookup → Looked}
    (hup : ∀ l, (up l).of z proofs = true) {req : Request} :
    ∀ f L looked, Copied z proofs L → Copied z proofs (loop R up f L looked req).1 := by
  intro f
  induction f with
  | zero => intro L _ h; exact h
  | succ f ih =>
    intro L looked h
    rw [loop_succ]
    cases R L req with
    | reply r => exact h
    | silent => exact h
    | need l =>
      dsimp only
      by_cases hm : l ∈ looked
      · simp only [hm, ↓reduceIte]; exact h
      · simp only [hm, ↓reduceIte]; exact ih _ _ (file_copied h (hup _))

/-- What the loop replies, the authority replied over the zone the loop leaves behind. -/
theorem loop_reply {R : Learned → Request → Step} {up : Lookup → Looked} {req : Request} :
    ∀ f L looked r, (loop R up f L looked req).2 = .reply r → R (loop R up f L looked req).1 req = .reply r := by
  intro f
  induction f with
  | zero => intro L looked r h; cases h
  | succ f ih =>
    intro L looked r
    rw [loop_succ]
    cases hr : R L req with
    | reply r' => intro h; cases h; exact hr
    | silent => intro h; cases h
    | need l =>
      dsimp only
      by_cases hm : l ∈ looked
      · simp only [hm, ↓reduceIte]; intro h; cases h
      · simp only [hm, ↓reduceIte]; exact ih _ _ _

/-! ## The server of a learned zone -/

/-- A reply with RCODE `rc` and nothing else, without AA. -/
def bare (rc : Rcode) : Response := ⟨rc, false, [], [], [], 0⟩

/-- `Copies` serving one learned zone, at the server with address `addr`: the answer from the zone's view, or,
when the view lacks a fact, the error RCODE the real server at `addr` answered the client's question with, which
a server sends rather than no reply (RFC 8906 §3.1), or else a lookup of the question at that address. -/
def respond (any : AnyResponse) (addr : Nat) (L : Learned) (req : Request) : Step :=
  match answerPartial L.view req any with
  | .response r => .reply r
  | .unknown _ =>
    match L.failed.find? (fun e => e.1 == addr && e.2.1 == req) with
    | some (_, _, rc) => .reply (bare rc)
    | none => .need ⟨addr, L.apex, req⟩

/-- The engine running `Copies` over one learned zone. -/
def serve (any : AnyResponse) (addr : Nat) (up : Lookup → Looked) :
    Nat → Learned → List Lookup → Request → Learned × Step :=
  loop (respond any addr) up

theorem respond_need {any : AnyResponse} {addr : Nat} {L : Learned} {req : Request} {l : Lookup}
    (h : respond any addr L req = .need l) : l = ⟨addr, L.apex, req⟩ := by
  unfold respond at h
  split at h
  · cases h
  · split at h
    · cases h
    · cases h; rfl

/-- Over a zone no server answered with an error, a reply is the answer from the zone's view. -/
theorem respond_reply {any : AnyResponse} {addr : Nat} {L : Learned} {req : Request} {r : Response}
    (h : respond any addr L req = .reply r) (hf : L.failed = []) : answerPartial L.view req any = .response r := by
  unfold respond at h
  split at h
  · rename_i hr; cases h; exact hr
  · split at h
    · rename_i hfind; rw [hf] at hfind; cases hfind
    · cases h

/-- A question the real server at `addr` answered with an error RCODE, which the zone's view does not answer,
gets that RCODE, never silence (RFC 8906 §3.1). -/
theorem respond_failed {any : AnyResponse} {addr : Nat} {L : Learned} {req : Request} {n : Name} {rc : Rcode}
    (hu : answerPartial L.view req any = .unknown n) (hf : L.failed.find? (fun e => e.1 == addr && e.2.1 == req) =
      some (addr, req, rc)) : respond any addr L req = .reply (bare rc) := by
  unfold respond
  rw [hu]
  simp only [hf]

theorem respond_needs (any : AnyResponse) (addr : Nat) (a : Name) (req : Request) :
    Needs (respond any addr) a req [⟨addr, a, req⟩] := by
  intro L l ha h
  rw [respond_need h, ha]
  exact List.mem_singleton.mpr rfl

/-- A reply the server gave stays its reply after any filing true of the zone, but for optional additional
data. -/
theorem respond_stable {z : Zone} {proofs : Proofs} {L : Learned} {lk : Looked} (h : Copied z proofs L)
    (hl : lk.of z proofs = true) {any : AnyResponse} {addr : Nat} {req : Request} {r : Response}
    (hr : respond any addr L req = .reply r) :
    ∃ r', respond any addr (L.file lk) req = .reply r' ∧ r.Grows r' := by
  obtain ⟨r', ha, hg⟩ := learned_answer_stable h hl (respond_reply hr h.2.2.2)
  exact ⟨r', by unfold respond; rw [ha], hg⟩

/-- The engine looks a request up at most once: with any fuel from 2 up, it gives what it gives with 2. -/
theorem serve_one_lookup (any : AnyResponse) (addr : Nat) (up : Lookup → Looked) (f : Nat) (L : Learned)
    (req : Request) : serve any addr up (f + 2) L [] req = serve any addr up 2 L [] req := by
  have h := loop_bounded (respond any addr) up req L _ (respond_needs any addr L.apex req) f
  simp only [List.length_singleton] at h
  unfold serve
  rw [show f + 2 = 1 + 1 + f by omega, h]

/-- Whatever the engine replies over a copy of `z`, with an upstream whose responses are true of `z`, is `z`'s
answer to the question, but for optional additional data: never a guess, and never a negative `z` does not
give. -/
theorem serve_reply_upstream {z : Zone} {proofs : Proofs} {any : AnyResponse} {addr : Nat}
    {up : Lookup → Looked} (hup : ∀ l, (up l).of z proofs = true) {f : Nat} {L : Learned} {looked : List Lookup}
    {req : Request} {r : Response} (hc : Copied z proofs L) (h : (serve any addr up f L looked req).2 = .reply r) :
    ∃ r', answer z req any = .response r' ∧ r.Grows r' :=
  have hc' := loop_copied hup f L looked hc
  learned_answer_upstream hc' req any (respond_reply (loop_reply f L looked r h) hc'.2.2.2)

/-- The engine replies NXDOMAIN only from a filed denial, held with the real zone's denial records for it. -/
theorem serve_nxdomain_proved {z : Zone} {proofs : Proofs} {any : AnyResponse} {addr : Nat}
    {up : Lookup → Looked} (hup : ∀ l, (up l).of z proofs = true) {f : Nat} {L : Learned} {looked : List Lookup}
    {req : Request} {r : Response} (hc : Copied z proofs L) (h : (serve any addr up f L looked req).2 = .reply r)
    (hx : r.rcode = .nxdomain) :
    ∃ n m, (serve any addr up f L looked req).1.fact n = .absent ∧ m <:+ n ∧
      (serve any addr up f L looked req).1.proof m = some (proofs m) :=
  have hc' := loop_copied hup f L looked hc
  learned_nxdomain_proved hc' (respond_reply (loop_reply f L looked r h) hc'.2.2.2) hx

/-! ## Overlays -/

/-- Zones invented below a learned zone, as `Overlay` serves them at one server: whether the server is one of
an invented zone's own name servers (an address its glue gives), that zone's answer from the data it holds,
which never needs a lookup, which questions are at or below its apex, and `<apex> DS` with DO. `serves` says
whether the base's reply to that question comes from a server of the parent (AA, and the DS RRset or the
parent's SOA); `referral` is the referral to the invented zone, with the denial records of the base's reply;
and `unsigned` is the answer to `<apex> DS` from the base's reply, NODATA where the base denies the apex. -/
structure Overlay where
  own : Bool
  inner : Request → Response
  below : Request → Bool
  ds : Request
  serves : Response → Bool
  referral : Request → Response → Response
  unsigned : Request → Response → Response

/-- The overlay's step over the authority `base`: as `base` above the invented zone; the invented zone's own
answer at its own name servers; `<apex> DS` from `base`'s answer to it; elsewhere below the apex, a referral
when `base`'s answer to `<apex> DS` comes from a server of the parent, and otherwise `base`'s answer, since only
the parent's servers refer to a child (RFC 1034 §4.2.1). A lookup `base` needs, the overlay needs. -/
def overlay (o : Overlay) (base : Learned → Request → Step) (L : Learned) (req : Request) : Step :=
  if !o.below req then base L req
  else if o.own then .reply (o.inner req)
  else if req = o.ds then
    match base L req with
    | .reply r => .reply (o.unsigned req r)
    | s => s
  else
    match base L o.ds with
    | .reply r => if o.serves r then .reply (o.referral req r) else base L req
    | s => s

/-- Over a learned zone, an overlay needs at most two lookups for a request: `<apex> DS`, and the question. -/
theorem overlay_needs (o : Overlay) (any : AnyResponse) (addr : Nat) (a : Name) (req : Request) :
    Needs (overlay o (respond any addr)) a req [⟨addr, a, o.ds⟩, ⟨addr, a, req⟩] := by
  intro L l ha h
  have hreq : respond any addr L req = .need l → l ∈ [⟨addr, a, o.ds⟩, ⟨addr, a, req⟩] := fun h' => by
    rw [respond_need h', ha]; simp
  unfold overlay at h
  split at h
  · exact hreq h
  · split at h
    · cases h
    · split at h
      · split at h
        · cases h
        · exact hreq h
      · split at h
        · split at h
          · cases h
          · exact hreq h
        · rw [respond_need h, ha]; simp

/-- The engine running an overlay over a learned zone replies or stays silent within three steps. -/
theorem overlay_loop_bounded (o : Overlay) (any : AnyResponse) (addr : Nat) (up : Lookup → Looked) (f : Nat)
    (L : Learned) (req : Request) :
    loop (overlay o (respond any addr)) up (f + 3) L [] req = loop (overlay o (respond any addr)) up 3 L [] req := by
  have h := loop_bounded _ up req L _ (overlay_needs o any addr L.apex req) f
  simp only [List.length_cons, List.length_nil] at h
  rw [show f + 3 = 0 + 1 + 1 + 1 + f by omega, h]

theorem Response.grows_refl (r : Response) : r.Grows r :=
  ⟨rfl, rfl, rfl, rfl, List.Sublist.refl _, rfl⟩

/-- The overlay reads of the base's replies only what a reply keeps as the zone learns more: RCODE, AA, and the
answer and authority sections. -/
def Overlay.Stable (o : Overlay) : Prop :=
  (∀ r r', r.Grows r' → o.serves r' = o.serves r) ∧
  (∀ q r r', r.Grows r' → o.referral q r' = o.referral q r) ∧
  (∀ q r r', r.Grows r' → (o.unsigned q r).Grows (o.unsigned q r'))

/-- A reply an overlay over a learned zone gave stays its reply after any filing true of the zone, but for
optional additional data: the zone learning more never turns a referral into another answer, or the reverse. -/
theorem overlay_reply_stable {z : Zone} {proofs : Proofs} {L : Learned} {lk : Looked} (h : Copied z proofs L)
    (hl : lk.of z proofs = true) {o : Overlay} (ho : o.Stable) {any : AnyResponse} {addr : Nat} {req : Request}
    {r : Response} (hr : overlay o (respond any addr) L req = .reply r) :
    ∃ r', overlay o (respond any addr) (L.file lk) req = .reply r' ∧ r.Grows r' := by
  unfold overlay at hr ⊢
  by_cases hb : o.below req = false
  · simp only [hb, Bool.not_false, ↓reduceIte] at hr ⊢
    exact respond_stable h hl hr
  · have hb' : o.below req = true := by simpa using hb
    simp only [hb', Bool.not_true, Bool.false_eq_true, ↓reduceIte] at hr ⊢
    by_cases hown : o.own = true
    · simp only [hown, ↓reduceIte] at hr ⊢
      exact ⟨r, hr, Response.grows_refl r⟩
    · simp only [hown, Bool.false_eq_true, ↓reduceIte] at hr ⊢
      by_cases hds : req = o.ds
      · simp only [hds, ↓reduceIte] at hr ⊢
        cases hq : respond any addr L o.ds with
        | reply b =>
          rw [hq] at hr
          cases hr
          obtain ⟨b', hb'', hg⟩ := respond_stable h hl hq
          rw [hb'']
          exact ⟨_, rfl, ho.2.2 o.ds b b' hg⟩
        | need l => rw [hq] at hr; cases hr
        | silent => rw [hq] at hr; cases hr
      · simp only [hds, ↓reduceIte] at hr ⊢
        cases hq : respond any addr L o.ds with
        | reply b =>
          rw [hq] at hr
          obtain ⟨b', hb'', hg⟩ := respond_stable h hl hq
          rw [hb'']
          simp only at hr ⊢
          rw [ho.1 b b' hg]
          by_cases hs : o.serves b = true
          · simp only [hs, ↓reduceIte] at hr ⊢
            cases hr
            exact ⟨_, by rw [ho.2.1 req b b' hg], Response.grows_refl _⟩
          · simp only [hs, Bool.false_eq_true, ↓reduceIte] at hr ⊢
            exact respond_stable h hl hr
        | need l => rw [hq] at hr; cases hr
        | silent => rw [hq] at hr; cases hr

end Dns.Authority
