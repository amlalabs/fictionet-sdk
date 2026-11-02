/-
  Authorities (§7.1, §7.4): `respond : Req → Known → Step`, the engine's loop that asks for each `Need` and
  calls `respond` again with the observation, `Relay`, and `Overlay`.

  An authority is written as a tree of asks: finished (a reply or silence), or ask one server and go on with
  what a client of that server saw. Every Rust `Authority` whose `respond` reads `known` only through
  `Known::get` and returns `Need` only for an ask it has not seen is such a tree. The tree form makes
  `respond_monotone` hold for every authority; `loop_terminates` needs the asks of one request to lie in a
  finite list.

  Rust: `services::dns::authority::{Authority, Ask, Observed, Known, Step, Relay, Overlay}`.
-/
import Dns.Wire

namespace Dns.Authority
open Wire

/-- The same question, as bytes, sent to one server. -/
structure Ask where
  server : Nat
  stream : Bool
  query : Bytes
deriving DecidableEq, Repr

/-- What a client of that server saw. -/
inductive Observed where
  | reply (bytes : Bytes)
  | unreachable
  | timeout
deriving DecidableEq, Repr

/-- Observations obtained so far for one request: a finite map that only grows. -/
abbrev Known := List (Ask × Observed)

def Known.get (k : Known) (a : Ask) : Option Observed := k.lookup a

/-- `k'` knows everything `k` knows. -/
def Known.Extends (k k' : Known) : Prop := ∀ a o, k.get a = some o → k'.get a = some o

/-- Observations added after the ones already known never hide them. -/
theorem Known.extends_append (k k' : Known) : k.Extends (k ++ k') := by
  intro a o h
  induction k with
  | nil => simp [Known.get, List.lookup] at h
  | cons e es ih =>
    obtain ⟨b, w⟩ := e
    unfold Known.get at h ih ⊢
    cases hab : (a == b) with
    | true => simp only [List.lookup, List.cons_append, hab] at h ⊢; exact h
    | false => simp only [List.lookup, List.cons_append, hab] at h ⊢; exact ih h

inductive Step where
  | reply (bytes : Bytes)
  | need (a : Ask)
  | silent
deriving DecidableEq, Repr

/-- An authority's decision for one request: finished with a reply (`some`) or silence (`none`), or an ask and
what to do with each observation. -/
inductive Prog where
  | done (reply : Option Bytes)
  | ask (a : Ask) (k : Observed → Prog)

/-- One request as the server sees it: the query octets, the address it arrived at (Rust's `local`), and its
transport. -/
structure Req where
  query : Bytes
  addr : Nat
  stream : Bool
deriving DecidableEq, Repr

/-- World code: trusted. -/
abbrev Authority := Req → Prog

def run : Prog → Known → Step
  | .done (some b), _ => .reply b
  | .done none, _ => .silent
  | .ask a k, known =>
    match known.get a with
    | some o => run (k o) known
    | none => .need a

def respond (A : Authority) (req : Req) (known : Known) : Step := run (A req) known

/-! ## More observations never undo a reply -/

theorem run_monotone : ∀ (p : Prog) (k k' : Known), k.Extends k' → (∀ a, run p k ≠ .need a) →
    run p k' = run p k := by
  intro p
  induction p with
  | done r => intro k k' _ _; cases r <;> rfl
  | ask a f ih =>
    intro k k' hext hn
    simp only [run] at hn ⊢
    cases hg : k.get a with
    | none => rw [hg] at hn; exact absurd rfl (hn a)
    | some o =>
      rw [hext a o hg]
      rw [hg] at hn
      exact ih o k k' hext hn

/-- An authority asks only what it does not know yet. -/
theorem need_unknown : ∀ (p : Prog) (k : Known) (a : Ask), run p k = .need a → k.get a = none := by
  intro p
  induction p with
  | done r => intro k a h; cases r <;> simp [run] at h
  | ask b f ih =>
    intro k a h
    simp only [run] at h
    cases hg : k.get b with
    | none => rw [hg] at h; cases h; exact hg
    | some o => rw [hg] at h; exact ih o k a h

/-- Once `respond` replies or stays silent, more observations never change that, so it never turns into a
`Need` again. -/
theorem respond_monotone (A : Authority) (req : Req) (k k' : Known) (hext : k.Extends k')
    (hdone : ∀ a, respond A req k ≠ .need a) : respond A req k' = respond A req k :=
  run_monotone (A req) k k' hext hdone

/-! ## The engine's loop ends -/

/-- The engine's loop for one request: on `Need a` it obtains what a client of that server sees (`world a`),
adds it to what it knows, and calls `respond` again. -/
def loop (A : Authority) (req : Req) (world : Ask → Observed) : Nat → Known → Option Step
  | 0, _ => none
  | f + 1, known =>
    match respond A req known with
    | .need a => loop A req world f ((a, world a) :: known)
    | s => some s

/-- Every ask `A` can issue for `req` lies in `asks`. -/
def Asks (A : Authority) (req : Req) (asks : List Ask) : Prop :=
  ∀ known a, respond A req known = .need a → a ∈ asks

theorem loop_ends (A : Authority) (req : Req) (world : Ask → Observed) (asks : List Ask) (hfin : Asks A req asks) :
    ∀ f known, (known.map Prod.fst).Nodup → (∀ e ∈ known, e.1 ∈ asks) → asks.length + 1 ≤ f + known.length →
      ∃ s, loop A req world f known = some s ∧ ∀ a, s ≠ .need a := by
  intro f
  induction f with
  | zero =>
    intro known hnd hsub hlen
    have : (known.map Prod.fst).length ≤ asks.length :=
      List.Nodup.length_le_of_subset hnd (fun a ha => by
        obtain ⟨e, he, rfl⟩ := List.mem_map.mp ha; exact hsub e he)
    simp at this; omega
  | succ f ih =>
    intro known hnd hsub hlen
    simp only [loop]
    cases hr : respond A req known with
    | need a =>
      have ha := hfin known a hr
      have hnone := need_unknown (A req) known a hr
      have hnot : a ∉ known.map Prod.fst := by
        intro hm
        obtain ⟨e, he, rfl⟩ := List.mem_map.mp hm
        rw [Known.get, List.lookup_eq_none_iff] at hnone
        have := hnone e he
        simp at this
      refine ih _ (by simp [List.nodup_cons, hnot, hnd]) (fun e he => ?_) (by simp; omega)
      simp only [List.mem_cons] at he
      rcases he with rfl | he
      · exact ha
      · exact hsub e he
    | reply b => exact ⟨_, rfl, fun _ h => by cases h⟩
    | silent => exact ⟨_, rfl, fun _ h => by cases h⟩

/-- With the asks of a request in a finite list, the loop replies or stays silent within one more step than
there are asks. -/
theorem loop_terminates (A : Authority) (req : Req) (world : Ask → Observed) (asks : List Ask)
    (hfin : Asks A req asks) : ∃ s, loop A req world (asks.length + 1) [] = some s ∧ ∀ a, s ≠ .need a :=
  loop_ends A req world asks hfin _ [] (by simp) (by simp) (by simp)

/-! ## Relay -/

def relayAsk (req : Req) : Ask := ⟨req.addr, req.stream, req.query⟩

/-- Asks the real server at its own address the client's exact question, and sends back what it said with the
client's ID and question case (`restore`). A timeout or an unreachable server is a silent simulated server. -/
def relay : Authority := fun req =>
  .ask (relayAsk req) fun
    | .reply b =>
      match restore b req.query with
      | .ok r => .done (some r)
      | .error _ => .done none
    | _ => .done none

theorem relay_asks (req : Req) : Asks relay req [relayAsk req] := by
  intro known a h
  simp only [respond, relay, run] at h
  cases hg : known.get (relayAsk req) with
  | none => rw [hg] at h; cases h; simp
  | some o =>
    rw [hg] at h
    cases o with
    | reply b =>
      simp only at h
      split at h <;> simp [run] at h
    | unreachable => simp [run] at h
    | timeout => simp [run] at h

/-- A relay never invents a reply: whatever it sends is the restore of a reply the real server actually gave
to this exact question, so it differs from that reply only in the ID and the question's case. -/
theorem relay_never_guesses (req : Req) (known : Known) (b : Bytes) (h : respond relay req known = .reply b) :
    ∃ obs, known.get (relayAsk req) = some (.reply obs) ∧ restore obs req.query = .ok b ∧
      b.length = obs.length ∧ b.take 2 = req.query.take 2 := by
  simp only [respond, relay, run] at h
  cases hg : known.get (relayAsk req) with
  | none => rw [hg] at h; cases h
  | some o =>
    rw [hg] at h
    cases o with
    | reply obs =>
      simp only at h
      split at h
      · rename_i r hr
        simp only [run, Step.reply.injEq] at h
        subst h
        obtain ⟨h1, h2, _⟩ := restore_changes_only_id_and_case obs req.query r hr
        exact ⟨obs, rfl, hr, h1, h2⟩
      · simp [run] at h
    | unreachable => simp [run] at h
    | timeout => simp [run] at h

/-! ## Overlay -/

/-- An overlay: questions at or below `apex` go to `inner`. A question asked of a parent server that crosses
`apex` from above gets a referral composed from `inner`'s apex NS set and glue; with DO=1 the overlay first
asks `base` for `<apex> DS` and puts the denial records of that reply in the referral. Everything else goes
to `base`. -/
structure Overlay where
  base : Authority
  inner : Authority
  below : Req → Bool
  crossing : Req → Bool
  wantsDs : Req → Bool
  dsAsk : Req → Ask
  referral : Req → Option Bytes → Bytes

def overlay (o : Overlay) : Authority := fun req =>
  if o.below req then o.inner req
  else if o.crossing req then
    if o.wantsDs req then
      .ask (o.dsAsk req) fun
        | .reply b => .done (some (o.referral req (some b)))
        | _ => .done none
    else .done (some (o.referral req none))
  else o.base req

theorem overlay_asks (o : Overlay) (req : Req) (ab ai : List Ask) (hb : Asks o.base req ab)
    (hi : Asks o.inner req ai) : Asks (overlay o) req (ai ++ o.dsAsk req :: ab) := by
  intro known a h
  simp only [respond, overlay] at h
  split at h
  · simp [hi known a h]
  · split at h
    · split at h
      · simp only [run] at h
        cases hg : known.get (o.dsAsk req) with
        | none => rw [hg] at h; cases h; simp
        | some ob => rw [hg] at h; cases ob <;> simp [run] at h
      · simp [run] at h
    · simp [hb known a h]

/-- A zone authority answers from data it holds and never asks. -/
def zones (f : Req → Option Bytes) : Authority := fun req => .done (f req)

theorem zones_asks (f : Req → Option Bytes) (req : Req) : Asks (zones f) req [] := by
  intro known a h
  simp only [respond, zones] at h
  cases hf : f req <;> simp [hf, run] at h

/-- Relay issues one ask per request. -/
theorem relay_loop_terminates (req : Req) (world : Ask → Observed) :
    ∃ s, loop relay req world 2 [] = some s ∧ ∀ a, s ≠ .need a :=
  loop_terminates relay req world _ (relay_asks req)

/-- An overlay of a zone authority on a relay issues at most two distinct asks per request: the DS question
and the relayed question. -/
theorem overlay_loop_terminates (o : Overlay) (f : Req → Option Bytes) (ho : o.base = relay)
    (hi : o.inner = zones f) (req : Req) (world : Ask → Observed) :
    ∃ s, loop (overlay o) req world 3 [] = some s ∧ ∀ a, s ≠ .need a := by
  have h := overlay_asks o req [relayAsk req] [] (ho ▸ relay_asks req) (hi ▸ zones_asks f req)
  exact loop_terminates (overlay o) req world _ h

theorem relay_monotone (req : Req) (k k' : Known) (hext : k.Extends k')
    (hdone : ∀ a, respond relay req k ≠ .need a) : respond relay req k' = respond relay req k :=
  respond_monotone relay req k k' hext hdone

theorem overlay_monotone (o : Overlay) (req : Req) (k k' : Known) (hext : k.Extends k')
    (hdone : ∀ a, respond (overlay o) req k ≠ .need a) : respond (overlay o) req k' = respond (overlay o) req k :=
  respond_monotone (overlay o) req k k' hext hdone

end Dns.Authority
