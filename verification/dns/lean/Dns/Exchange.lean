/-
  Exchanges, tokens, and generations (§6): the matching rule of the step contract (§6.2 rules 3 to 5).

  The engine issues a token for each outstanding exchange, made of the namespace generation and an exchange
  number. A reply changes state only if its token is outstanding and current, it came from where the
  transmit went over the same transport, and its ID, QNAME, QCLASS, and QTYPE equal the query's
  (RFC 5452 §9.1). A session change advances the generation: every outstanding exchange is abandoned and the
  cache and everything derived from it are dropped.

  Rust: `services::dns::exchange::{Generation, Token, Transmit, Input, Action, Engine}`.
-/
import Dns.Name

namespace Dns.Exchange

structure Token where
  generation : Nat
  exchange : Nat
deriving DecidableEq, Repr

/-- What a reply must match: where the query went, how, and the query's ID and question. -/
structure Tuple where
  to : Nat
  stream : Bool
  id : Nat
  qname : Name
  qclass : Nat
  qtype : Nat
deriving DecidableEq, Repr

structure Pending where
  token : Token
  tuple : Tuple
deriving DecidableEq, Repr

/-- State derived from a reply, tagged with the generation it was learned in. -/
structure Entry where
  generation : Nat
  data : Bytes
deriving DecidableEq, Repr

structure State where
  generation : Nat
  next : Nat
  pending : List Pending
  cache : List Entry
  /-- Client queries still waiting for an answer; a new generation restarts them. -/
  waiting : List Nat
deriving DecidableEq, Repr

structure Reply where
  token : Token
  source : Nat
  stream : Bool
  id : Nat
  qname : Name
  qclass : Nat
  qtype : Nat
  payload : Bytes
deriving DecidableEq, Repr

inductive Outcome where
  | accepted
  | ignored
deriving DecidableEq, Repr

/-- Starts an exchange: a fresh token in the current generation. -/
def send (s : State) (t : Tuple) : State × Token :=
  let tok : Token := ⟨s.generation, s.next⟩
  ({ s with next := s.next + 1, pending := ⟨tok, t⟩ :: s.pending }, tok)

/-- The reply matches the exchange `p` (RFC 5452 §9.1). With 0x20 on (`exactCase`), QNAME must match octet for
octet; otherwise up to case. -/
def tupleMatches (exactCase : Bool) (p : Pending) (r : Reply) : Bool :=
  r.source == p.tuple.to && r.stream == p.tuple.stream && r.id == p.tuple.id &&
    (if exactCase then r.qname == p.tuple.qname else Name.eqCI r.qname p.tuple.qname) &&
    r.qclass == p.tuple.qclass && r.qtype == p.tuple.qtype

def onReply (exactCase : Bool) (s : State) (r : Reply) : State × Outcome :=
  if r.token.generation = s.generation then
    match s.pending.find? (·.token == r.token) with
    | some p =>
      if tupleMatches exactCase p r then
        ({ s with pending := s.pending.filter (·.token != r.token), cache := ⟨s.generation, r.payload⟩ :: s.cache },
          .accepted)
      else (s, .ignored)
    | none => (s, .ignored)
  else (s, .ignored)

/-- A new session. `g` must be above the current generation; every outstanding exchange is abandoned (the
second component lists their tokens) and the cache is dropped. Waiting client queries stay, to be restarted
under `g`. -/
def advance (s : State) (g : Nat) : State × List Token :=
  if s.generation < g then ({ s with generation := g, pending := [], cache := [] }, s.pending.map (·.token))
  else (s, [])

/-- A reply whose token is of another generation is ignored and changes nothing. -/
theorem obsolete_ignored (x : Bool) (s : State) (r : Reply) (h : r.token.generation ≠ s.generation) :
    onReply x s r = (s, .ignored) := by
  simp [onReply, h]

/-- A reply changes state only if its token is outstanding and current and it tupleMatches the whole tuple; any
other reply leaves state unchanged. -/
theorem match_requires_tuple (x : Bool) (s : State) (r : Reply) :
    ((onReply x s r).2 = .accepted →
      ∃ p ∈ s.pending, p.token = r.token ∧ r.token.generation = s.generation ∧ r.source = p.tuple.to ∧
        r.stream = p.tuple.stream ∧ r.id = p.tuple.id ∧
        (x = true → r.qname = p.tuple.qname) ∧ Name.fold r.qname = Name.fold p.tuple.qname ∧
        r.qclass = p.tuple.qclass ∧ r.qtype = p.tuple.qtype) ∧
    ((onReply x s r).2 = .ignored → (onReply x s r).1 = s) := by
  unfold onReply
  by_cases hg : r.token.generation = s.generation
  · simp only [hg, ↓reduceIte]
    cases hf : s.pending.find? (·.token == r.token) with
    | none => simp
    | some p =>
      simp only
      by_cases hm : tupleMatches x p r = true
      · simp only [hm, ↓reduceIte, true_implies, reduceCtorEq, false_implies, and_true]
        have hmem := List.mem_of_find?_eq_some hf
        have htok : p.token = r.token := by simpa using List.find?_some hf
        simp only [tupleMatches, Bool.and_eq_true, beq_iff_eq] at hm
        obtain ⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩ := hm
        refine ⟨p, hmem, htok, trivial, h1, h2, h3, ?_, ?_, h5, h6⟩
        · intro hx; subst hx; simpa using h4
        · cases x
          · simpa [Name.eqCI_iff_fold_eq] using h4
          · simp at h4; rw [h4]
      · simp [hm]
  · simp [hg]

/-- After a session change, nothing outstanding is left, the cache is empty, every old token was abandoned,
and every reply bearing an old token is ignored. -/
theorem advance_clears (x : Bool) (s : State) (g : Nat) (hg : s.generation < g) :
    (advance s g).1.generation = g ∧ (advance s g).1.pending = [] ∧ (advance s g).1.cache = [] ∧
      (advance s g).1.waiting = s.waiting ∧ (advance s g).2 = s.pending.map (·.token) ∧
      ∀ p ∈ s.pending, ∀ r : Reply, r.token = p.token → (∀ p ∈ s.pending, p.token.generation = s.generation) →
        onReply x (advance s g).1 r = ((advance s g).1, .ignored) := by
  simp only [advance, hg, ↓reduceIte, true_and]
  intro p hp r hr hgen
  apply obsolete_ignored
  show r.token.generation ≠ g
  rw [hr, hgen p hp]; omega

/-! ## Nothing derived from an old generation survives -/

/-- Every cache entry is of the current generation, and every outstanding token is current and below the
next exchange number. -/
def Inv (s : State) : Prop :=
  (∀ e ∈ s.cache, e.generation = s.generation) ∧
    ∀ p ∈ s.pending, p.token.generation = s.generation ∧ p.token.exchange < s.next

theorem inv_send (s : State) (t : Tuple) (h : Inv s) : Inv (send s t).1 ∧ ∀ p ∈ s.pending, p.token ≠ (send s t).2 := by
  obtain ⟨h1, h2⟩ := h
  refine ⟨⟨h1, fun p hp => ?_⟩, fun p hp he => ?_⟩
  · simp only [send, List.mem_cons] at hp
    rcases hp with rfl | hp
    · simp [send]
    · have := h2 p hp; simp only [send]; omega
  · have := (h2 p hp).2
    simp only [send] at he
    rw [he] at this; simp at this

theorem inv_onReply (x : Bool) (s : State) (r : Reply) (h : Inv s) : Inv (onReply x s r).1 := by
  obtain ⟨h1, h2⟩ := h
  unfold onReply
  split
  · split
    · split
      · refine ⟨fun e he => ?_, fun p hp => ?_⟩
        · simp only [List.mem_cons] at he
          rcases he with rfl | he
          · rfl
          · exact h1 e he
        · exact h2 p (List.mem_filter.mp hp).1
      · exact ⟨h1, h2⟩
    · exact ⟨h1, h2⟩
  · exact ⟨h1, h2⟩

theorem inv_advance (s : State) (g : Nat) (h : Inv s) : Inv (advance s g).1 := by
  unfold advance
  split
  · exact ⟨fun e he => by simp at he, fun p hp => by simp at hp⟩
  · exact h

end Dns.Exchange
