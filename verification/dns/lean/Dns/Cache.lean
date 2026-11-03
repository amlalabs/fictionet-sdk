/-
  The resolver's cache: entries with a rank, an expiry, a validation, and the generation that wrote
  them; failures cached apart from negatives (RFC 9520).

  Times are seconds on one clock, the run's `Instant`. An RRSIG's expiration reaches the cache already
  converted to that clock by the resolver's `WallClock`. Names are lowercase and the class is IN, so a key is
  a name and a type.

  Rust: `services::dns::resolver::cache::{Cache, Entry, Rank, Negative, FailureKind}`.
-/
import Dns.Dnssec

namespace Dns.Cache
open Dns.Zone Dns.Dnssec

/-- Trustworthiness of cached data, lowest first (RFC 2181 §5.4.1). -/
inductive Rank where
  | glue
  | nonAuthAuthority
  | nonAuthAnswer
  | authAuthority
  | authAnswer
deriving DecidableEq, Repr

def Rank.level : Rank → Nat
  | .glue => 0 | .nonAuthAuthority => 1 | .nonAuthAnswer => 2 | .authAuthority => 3 | .authAnswer => 4

inductive Negative where
  | nxDomain
  | noData
deriving DecidableEq, Repr

inductive FailureKind where
  | noReachableAuthority
  | workExceeded
  | unknown
deriving DecidableEq, Repr

structure Key where
  name : Name
  rtype : Nat
deriving DecidableEq, Repr

inductive Body where
  | positive (set : RRset) (rank : Rank) (validation : Validation)
  | negative (kind : Negative) (soa : RRset) (rank : Rank) (validation : Validation)
  | failure (why : FailureKind)
deriving DecidableEq, Repr

/-- A cached entry: what it holds, when it was stored, when it expires, the TTL it was offered with, and the
generation that wrote it. -/
structure Entry where
  key : Key
  body : Body
  stored : Nat
  expires : Nat
  original : Nat
  generation : Nat
deriving DecidableEq, Repr

structure Cache where
  generation : Nat
  entries : List Entry
deriving DecidableEq, Repr

/-- The resolver's knobs that bound what the cache keeps. -/
structure Limits where
  /-- RFC 8767 §4: at most 604800 seconds. -/
  maxTtl : Nat
  /-- RFC 9520 §3.2: 1 to 300 seconds. -/
  failureTtl : Nat
deriving DecidableEq, Repr

/-- What a resolution offers the cache, with what validation established about it. -/
inductive Offer where
  /-- An RRset with its rank and validation, the first expiration and the smallest Original TTL of the RRSIGs
  that validated it, and whether the reply was truncated. -/
  | positive (set : RRset) (rank : Rank) (validation : Validation) (sigExpires : Option Nat)
      (originalTtl : Option Nat) (truncated : Bool)
  /-- A negative answer for a key, with the SOA it came with, the rank of the answer it came in, the NSEC or
  NSEC3 TTL when the denial was proven, its validation, the first expiration and the smallest Original TTL of
  the RRSIGs that validated it, and whether the reply was truncated. -/
  | negative (key : Key) (kind : Negative) (soa : Option RRset) (rank : Rank) (denialTtl : Option Nat)
      (validation : Validation) (sigExpires : Option Nat) (originalTtl : Option Nat) (truncated : Bool)
  | failure (key : Key) (why : FailureKind)
deriving DecidableEq, Repr

def Offer.key : Offer → Key
  | .positive s _ _ _ _ _ => ⟨s.owner, s.rtype⟩
  | .negative k _ _ _ _ _ _ _ _ => k
  | .failure k _ => k

/-- The rank an entry holds its key at. A negative answer ranks as the answer it came in; a failure is no data
and ranks lowest. -/
def Body.rank : Body → Rank
  | .positive _ r _ => r
  | .negative _ _ r _ => r
  | .failure _ => .glue

/-- Whether a new entry with body `new` takes the key from a live entry with body `old`: data at equal or higher
rank (RFC 2181 §5.4.1), and a failure over anything that does not answer clients, so a failure is cached
whenever a resolution fails (RFC 9520 §3.2). -/
def Body.replaces (new old : Body) : Bool :=
  match new with
  | .failure _ => old.rank.level < Rank.nonAuthAnswer.level
  | _ => old.rank.level ≤ new.rank.level

/-- A TTL with the top bit set reads as zero (RFC 2181 §8). -/
def readTtl (ttl : Nat) : Nat := if 2147483648 ≤ ttl then 0 else ttl

/-- When an entry stored at `now` to expire at `exp` expires once validation is done: a Secure one no later than
its RRSIGs' first expiration, nor than their smallest Original TTL after `now` (RFC 4035 §5.3.3); a Bogus or
Indeterminate one no later than `failureTtl` after `now`, when it is fetched and validated again
(RFC 9520 §3.2, RFC 4035 §4.7). -/
def validatedCap (now : Nat) (lim : Limits) (v : Validation) (sig orig : Option Nat) (exp : Nat) : Nat :=
  match v with
  | .secure =>
    let exp := match sig with
      | some x => min exp x
      | none => exp
    match orig with
    | some o => min exp (now + readTtl o)
    | none => exp
  | .bogus _ | .indeterminate => min exp (now + lim.failureTtl)
  | .notPerformed | .insecure _ => exp

theorem validatedCap_le (now : Nat) (lim : Limits) (v : Validation) (sig orig : Option Nat) (exp : Nat) :
    validatedCap now lim v sig orig exp ≤ exp := by
  unfold validatedCap
  cases v with
  | secure => cases sig <;> cases orig <;> (try simp only) <;> omega
  | bogus _ => exact Nat.min_le_left _ _
  | indeterminate => exact Nat.min_le_left _ _
  | notPerformed => exact Nat.le_refl _
  | insecure _ => exact Nat.le_refl _

/-- The entry an offer makes at `now`, or none when the offer may not be cached: truncated replies
(RFC 2181 §9), TTL zero (RFC 1035 §7.4), negatives without an SOA (RFC 2308 §5). TTLs are capped at
`maxTtl` (RFC 8767 §4), and positive and negative entries by their validation (`validatedCap`); a proven
negative uses min(SOA TTL, MINIMUM, NSEC TTL) (RFC 9077 §3); a failure lives `failureTtl` (RFC 9520 §3.2). -/
def entryFor (now : Nat) (lim : Limits) (g : Nat) : Offer → Option Entry
  | .positive s r v sig orig tc =>
    let ttl := min (readTtl s.ttl) lim.maxTtl
    if tc || ttl == 0 then none
    else some ⟨⟨s.owner, s.rtype⟩, .positive s r v, now, validatedCap now lim v sig orig (now + ttl), s.ttl, g⟩
  | .negative k kind soa r nsec v sig orig tc =>
    match soa with
    | none => none
    | some soa =>
      let base := negTtl { soa with ttl := readTtl soa.ttl }
      let ttl := min (match nsec with
        | some n => min base (readTtl n)
        | none => base) lim.maxTtl
      if tc || ttl == 0 then none
      else some ⟨k, .negative kind soa r v, now, validatedCap now lim v sig orig (now + ttl), soa.ttl, g⟩
  | .failure k why => some ⟨k, .failure why, now, now + lim.failureTtl, lim.failureTtl, g⟩

/-- The entry lives at `now`: written in the current generation and not expired. -/
def live (c : Cache) (now : Nat) (e : Entry) : Bool := e.generation == c.generation && now < e.expires

/-- Offers an answer to the cache at `now`. An entry takes the key from the live entry for it only when it
`replaces` it; expired entries and entries of older generations for the key are dropped. -/
def insert (now : Nat) (lim : Limits) (c : Cache) (o : Offer) : Cache :=
  match entryFor now lim c.generation o with
  | none => c
  | some e =>
    match c.entries.find? (fun x => x.key == e.key && live c now x) with
    | some old => if e.body.replaces old.body then ⟨c.generation, e :: c.entries.filter (·.key != e.key)⟩
        else c
    | none => ⟨c.generation, e :: c.entries.filter (·.key != e.key)⟩

/-- A session change: a new generation, and nothing of the old one survives. -/
def advance (c : Cache) : Cache := ⟨c.generation + 1, []⟩

/-- What the cache serves for a key, with TTLs counted down (RFC 2308 §6). -/
inductive Served where
  | positive (set : RRset) (validation : Validation)
  | negative (kind : Negative) (soa : RRset) (validation : Validation)
  /-- SERVFAIL with EDE 13, Cached Error, next to the failure's own code (RFC 8914 §4.14). -/
  | failure (why : FailureKind)
deriving DecidableEq, Repr

def render (now : Nat) (e : Entry) : Served :=
  match e.body with
  | .positive s _ v => .positive { s with ttl := e.expires - now } v
  | .negative kind soa _ v => .negative kind { soa with ttl := e.expires - now } v
  | .failure why => .failure why

/-- `Cache.serve`: the live entry for the key, rendered for `now`. -/
def serve (now : Nat) (c : Cache) (k : Key) : Option Served :=
  (c.entries.find? fun x => x.key == k && live c now x).map (render now)

/-! ## What the cache keeps -/

/-- One entry per key. -/
def Unique (c : Cache) : Prop := (c.entries.map (·.key)).Nodup

/-- Each entry expires no later than its offered TTL after it was stored, was stored no later than `now`, and
a positive entry's offered TTL is its RRset's. -/
def WellTimed (c : Cache) (now : Nat) : Prop :=
  ∀ e ∈ c.entries, e.expires ≤ e.stored + e.original ∧ e.stored ≤ now ∧
    ∀ s r v, e.body = .positive s r v → e.original = s.ttl

theorem entryFor_spec {now : Nat} {lim : Limits} {g : Nat} {o : Offer} {e : Entry}
    (h : entryFor now lim g o = some e) :
    e.key = o.key ∧ e.stored = now ∧ e.generation = g ∧ e.expires ≤ now + e.original ∧
      ∀ s r v, e.body = .positive s r v → e.original = s.ttl := by
  unfold entryFor at h
  cases o with
  | positive s r v sig orig tc =>
    simp only at h
    split at h
    · cases h
    · cases h
      refine ⟨rfl, rfl, rfl, ?_, fun s' r' v' hb => by cases hb; rfl⟩
      have : min (readTtl s.ttl) lim.maxTtl ≤ s.ttl := by
        unfold readTtl; split <;> omega
      have := validatedCap_le now lim v sig orig (now + min (readTtl s.ttl) lim.maxTtl)
      simp only
      omega
  | negative k kind soa r nsec v sig orig tc =>
    simp only at h
    cases soa with
    | none => cases h
    | some soa =>
      simp only at h
      have hb : negTtl { soa with ttl := readTtl soa.ttl } ≤ soa.ttl := by
        unfold negTtl readTtl
        split <;> (simp only; split <;> omega)
      cases nsec with
      | none =>
        simp only at h
        split at h
        · cases h
        · cases h
          have := validatedCap_le now lim v sig orig
            (now + min (negTtl { soa with ttl := readTtl soa.ttl }) lim.maxTtl)
          exact ⟨rfl, rfl, rfl, by simp only; omega, fun _ _ _ hb => by cases hb⟩
      | some n =>
        simp only at h
        split at h
        · cases h
        · cases h
          have := validatedCap_le now lim v sig orig
            (now + min (min (negTtl { soa with ttl := readTtl soa.ttl }) (readTtl n)) lim.maxTtl)
          exact ⟨rfl, rfl, rfl, by simp only; omega, fun _ _ _ hb => by cases hb⟩
  | failure k why => cases h; exact ⟨rfl, rfl, rfl, Nat.le_refl _, fun _ _ _ hb => by cases hb⟩

theorem insert_entries (now : Nat) (lim : Limits) (c : Cache) (o : Offer) :
    (insert now lim c o).generation = c.generation ∧
      ((insert now lim c o).entries = c.entries ∨ ∃ e, entryFor now lim c.generation o = some e ∧
        (insert now lim c o).entries = e :: c.entries.filter (·.key != e.key)) := by
  unfold insert
  cases he : entryFor now lim c.generation o with
  | none => exact ⟨rfl, Or.inl rfl⟩
  | some e =>
    simp only
    split
    · split
      · exact ⟨rfl, Or.inr ⟨e, rfl, rfl⟩⟩
      · exact ⟨rfl, Or.inl rfl⟩
    · exact ⟨rfl, Or.inr ⟨e, rfl, rfl⟩⟩

theorem nodup_filter_cons {e : Entry} {l : List Entry} (h : (l.map (·.key)).Nodup) :
    ((e :: l.filter (·.key != e.key)).map (·.key)).Nodup := by
  rw [List.map_cons, List.nodup_cons]
  constructor
  · intro hm
    obtain ⟨x, hx, hxk⟩ := List.mem_map.mp hm
    have := (List.mem_filter.mp hx).2
    simp [hxk] at this
  · exact List.Nodup.sublist (List.Sublist.map _ List.filter_sublist) h

theorem insert_unique {now : Nat} {lim : Limits} {c : Cache} {o : Offer} (h : Unique c) :
    Unique (insert now lim c o) := by
  rcases (insert_entries now lim c o).2 with he | ⟨e, _, he⟩
  · unfold Unique; rw [he]; exact h
  · unfold Unique; rw [he]; exact nodup_filter_cons h

theorem insert_wellTimed {now : Nat} {lim : Limits} {c : Cache} {o : Offer} {t : Nat} (h : WellTimed c t)
    (ht : t ≤ now) : WellTimed (insert now lim c o) now := by
  rcases (insert_entries now lim c o).2 with he | ⟨e, hfor, he⟩
  · intro x hx; rw [he] at hx
    obtain ⟨h1, h2, h3⟩ := h x hx
    exact ⟨h1, Nat.le_trans h2 ht, h3⟩
  · intro x hx
    rw [he] at hx
    rcases List.mem_cons.mp hx with rfl | hx
    · obtain ⟨_, hs, _, hexp, horig⟩ := entryFor_spec hfor; exact ⟨by omega, by omega, horig⟩
    · obtain ⟨h1, h2, h3⟩ := h x (List.mem_filter.mp hx).1
      exact ⟨h1, Nat.le_trans h2 ht, h3⟩

theorem wellTimed_mono {c : Cache} {t t' : Nat} (h : WellTimed c t) (ht : t ≤ t') : WellTimed c t' := by
  intro e he
  obtain ⟨h1, h2, h3⟩ := h e he
  exact ⟨h1, Nat.le_trans h2 ht, h3⟩

/-- A session change leaves nothing to serve. -/
theorem advance_clears (c : Cache) (now : Nat) (k : Key) :
    serve now (advance c) k = none ∧ Unique (advance c) ∧ ∀ t, WellTimed (advance c) t :=
  ⟨rfl, List.nodup_nil, fun _ _ h => by simp [advance] at h⟩

theorem unique_key {l : List Entry} (h : (l.map (·.key)).Nodup) {a b : Entry} (ha : a ∈ l) (hb : b ∈ l)
    (hk : a.key = b.key) : a = b := by
  induction l with
  | nil => cases ha
  | cons x xs ih =>
    rw [List.map_cons, List.nodup_cons] at h
    rcases List.mem_cons.mp ha with hax | ha
    · rcases List.mem_cons.mp hb with hbx | hb
      · rw [hax, hbx]
      · rw [hax] at hk
        exact absurd (List.mem_map.mpr ⟨b, hb, hk.symm⟩ : x.key ∈ xs.map (·.key)) h.1
    · rcases List.mem_cons.mp hb with hbx | hb
      · rw [hbx] at hk
        exact absurd (List.mem_map.mpr ⟨a, ha, hk⟩ : x.key ∈ xs.map (·.key)) h.1
      · exact ih h.2 ha hb

theorem serve_some {now : Nat} {c : Cache} {k : Key} {s : Served} (h : serve now c k = some s) :
    ∃ e ∈ c.entries, e.key = k ∧ live c now e = true ∧ s = render now e := by
  unfold serve at h
  cases hf : c.entries.find? (fun x => x.key == k && live c now x) with
  | none => rw [hf] at h; cases h
  | some e =>
    rw [hf] at h
    simp only [Option.map_some, Option.some.injEq] at h
    have hp := List.find?_some hf
    simp only [Bool.and_eq_true, beq_iff_eq] at hp
    exact ⟨e, List.mem_of_find?_eq_some hf, hp.1, hp.2, h.symm⟩

/-- With one entry per key, the cache serves the live entry for a key. -/
theorem serve_entry {now : Nat} {c : Cache} {k : Key} {e : Entry} (hu : Unique c) (he : e ∈ c.entries)
    (hk : e.key = k) (hl : live c now e = true) : serve now c k = some (render now e) := by
  unfold serve
  cases hf : c.entries.find? (fun x => x.key == k && live c now x) with
  | none =>
    exact absurd (List.find?_eq_none.mp hf e he) (by simp [hk, hl])
  | some e' =>
    have hp := List.find?_some hf
    simp only [Bool.and_eq_true, beq_iff_eq] at hp
    rw [unique_key hu (List.mem_of_find?_eq_some hf) he (hp.1.trans hk.symm)]
    rfl

/-! ## The headline theorems -/

/-- An entry is served only while it lives: written in the current generation and not yet expired. -/
theorem expired_never_served {now : Nat} {c : Cache} {k : Key} {s : Served} (h : serve now c k = some s) :
    ∃ e ∈ c.entries, e.key = k ∧ e.generation = c.generation ∧ now < e.expires := by
  obtain ⟨e, he, hk, hl, _⟩ := serve_some h
  simp only [live, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hl
  exact ⟨e, he, hk, hl.1, hl.2⟩

/-- A served RRset's TTL, counted down, is never above the TTL it was offered with. -/
theorem served_ttl_le_original {now : Nat} {c : Cache} {k : Key} {s : RRset} {v : Validation}
    (hw : WellTimed c now) (h : serve now c k = some (.positive s v)) :
    ∃ e ∈ c.entries, ∃ s₀ r, e.key = k ∧ e.body = .positive s₀ r v ∧ s.ttl ≤ s₀.ttl ∧
      s.owner = s₀.owner ∧ s.rtype = s₀.rtype ∧ s.rdata = s₀.rdata := by
  obtain ⟨e, he, hk, _, hs⟩ := serve_some h
  obtain ⟨h1, h2, h3⟩ := hw e he
  unfold render at hs
  cases hb : e.body with
  | positive s₀ r v₀ =>
    rw [hb] at hs
    simp only [Served.positive.injEq] at hs
    obtain ⟨rfl, rfl⟩ := hs
    have := h3 s₀ r _ hb
    exact ⟨e, he, s₀, r, hk, hb, by simp only; omega, rfl, rfl, rfl⟩
  | negative _ _ _ _ => rw [hb] at hs; cases hs
  | failure _ => rw [hb] at hs; cases hs

/-- A cached failure never answers as a negative: it answers SERVFAIL (RFC 9520). -/
theorem failure_never_negative {now : Nat} {c : Cache} {k : Key} {e : Entry} {why : FailureKind} (hu : Unique c)
    (he : e ∈ c.entries) (hk : e.key = k) (hb : e.body = .failure why) :
    (∀ kind soa v, serve now c k ≠ some (.negative kind soa v)) ∧
      (live c now e = true → serve now c k = some (.failure why)) := by
  refine ⟨fun kind soa v h => ?_, fun hl => ?_⟩
  · obtain ⟨e', he', hk', _, hs⟩ := serve_some h
    rw [unique_key hu he' he (hk'.trans hk.symm)] at hs
    simp [render, hb] at hs
  · rw [serve_entry hu he hk hl]
    simp [render, hb]

/-- A Secure RRset lives no longer than its RRSIG (RFC 4035 §5.3.3), so it is never served at or after the
RRSIG's expiration. -/
theorem rrsig_caps_ttl {now : Nat} {lim : Limits} {g : Nat} {s : RRset} {r : Rank} {x : Nat} {orig : Option Nat}
    {tc : Bool} {e : Entry} (h : entryFor now lim g (.positive s r .secure (some x) orig tc) = some e) :
    e.expires ≤ x := by
  unfold entryFor at h
  simp only at h
  split at h
  · cases h
  · cases h
    simp only [validatedCap]
    cases orig <;> simp only <;> omega

/-- An offer that does not replace the live entry for its key changes nothing: data at a lower rank
(RFC 2181 §5.4.1), or a failure over data that answers clients. -/
theorem rank_monotone {now : Nat} {lim : Limits} {c : Cache} {o : Offer} {e : Entry} (hu : Unique c)
    (he : e ∈ c.entries) (hk : e.key = o.key) (hl : live c now e = true)
    (hr : ∀ e', entryFor now lim c.generation o = some e' → e'.body.replaces e.body = false) :
    insert now lim c o = c := by
  unfold insert
  cases hfor : entryFor now lim c.generation o with
  | none => rfl
  | some e' =>
    simp only
    have hk' : e'.key = e.key := (entryFor_spec hfor).1.trans hk.symm
    cases hf : c.entries.find? (fun x => x.key == e'.key && live c now x) with
    | none => exact absurd (List.find?_eq_none.mp hf e he) (by simp [hk', hl])
    | some old =>
      have hp := List.find?_some hf
      simp only [Bool.and_eq_true, beq_iff_eq] at hp
      have hold : old = e := unique_key hu (List.mem_of_find?_eq_some hf) he (hp.1.trans hk')
      subst hold
      simp [hr e' hfor]

end Dns.Cache
