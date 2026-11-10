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
  /-- A failed resolution of a key, with how long the failure before it lasted when the resolution began while
  that one persisted (`persisting`). -/
  | failure (key : Key) (why : FailureKind) (follows : Option Nat)
deriving DecidableEq, Repr


/-- QTYPE ANY (RFC 1035 §3.2.3). An NXDOMAIN says the name holds no type, so it is kept under ANY, where every
question at the name finds it (RFC 2308 §5), as Rust's `Cache` keeps it. -/
def anyType : Nat := 255

/-- The key a negative answer for `k` is kept under: the name with ANY for NXDOMAIN, which answers every type, and
the name and type for NODATA, which answers only that type (RFC 2308 §5). -/
def negKey (k : Key) : Negative → Key
  | .nxDomain => ⟨k.name, anyType⟩
  | .noData => k

def Offer.key : Offer → Key
  | .positive s _ _ _ _ _ => ⟨s.owner, s.rtype⟩
  | .negative k kind _ _ _ _ _ _ _ => negKey k kind
  | .failure k _ _ => k

/-- An NXDOMAIN is kept under the type it answered too, as Rust keeps it, so that it replaces what was there. -/
def Offer.copyKey : Offer → Option Key
  | .negative k .nxDomain _ _ _ _ _ _ _ => if k.rtype = anyType then none else some k
  | _ => none

/-- The rank an entry holds its key at. A negative answer ranks as the answer it came in; a failure is no data
and ranks lowest. -/
def Body.rank : Body → Rank
  | .positive _ r _ => r
  | .negative _ _ r _ => r
  | .failure _ => .glue

/-- The entry is an NXDOMAIN. -/
def Body.isNx : Body → Bool
  | .negative .nxDomain _ _ _ => true
  | _ => false

/-- The entry shows that its name exists: data, or NODATA (RFC 8020 §2). -/
def Body.showsName : Body → Bool
  | .positive _ _ _ => true
  | .negative .noData _ _ _ => true
  | _ => false

/-- The entry validated Secure. -/
def Body.secure : Body → Bool
  | .positive _ _ v => v == .secure
  | .negative _ _ _ v => v == .secure
  | .failure _ => false

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
negative uses min(SOA TTL, MINIMUM, NSEC TTL) (RFC 2308 §5, RFC 9077 §3); a failure lives `failureTtl`, or twice
as long as the failure it follows, up to 300 seconds unless `failureTtl` is longer (RFC 9520 §3.2). The entry's
offered TTL is how long the failure lasts. A negative is kept under `negKey`. -/
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
      else some ⟨negKey k kind, .negative kind soa r v, now, validatedCap now lim v sig orig (now + ttl), soa.ttl, g⟩
  | .failure k why follows =>
    let lasts := match follows with
      | some l => min (2 * l) (max 300 lim.failureTtl)
      | none => lim.failureTtl
    some ⟨k, .failure why, now, now + lasts, lasts, g⟩

/-- How long the failure cached for `k` lasts, when a resolution of `k` that begins at `now` finds it persisting:
it is served still, or ended less than its own length ago (RFC 9520 §3.2). A resolution reads it when it begins and
offers it with its failure. -/
def persisting (now : Nat) (c : Cache) (k : Key) : Option Nat :=
  match c.entries.find? (·.key == k) with
  | some ⟨_, .failure _, _, exp, lasts, g⟩ => if g == c.generation && now < exp + lasts then some lasts else none
  | _ => none

/-- The entry lives at `now`: written in the current generation and not expired. -/
def live (c : Cache) (now : Nat) (e : Entry) : Bool := e.generation == c.generation && now < e.expires

/-- `e` in place of every entry with its key. -/
def put (c : Cache) (e : Entry) : Cache := ⟨c.generation, e :: c.entries.filter (·.key != e.key)⟩

/-- Live data or NODATA ranked above `e`, at `e`'s name or below it, shows that the name exists, so an NXDOMAIN
`e` is not kept (Rust's `Cache::shows_exists`, RFC 8020 §2). -/
def showsExists (c : Cache) (now : Nat) (e : Entry) : Bool :=
  c.entries.any fun x => live c now x && under x.key.name e.key.name && x.body.showsName &&
    decide (e.body.rank.level < x.body.rank.level)

/-- Drops every live NXDOMAIN at `n` or above it whose rank is at most `r`, under whatever type it is kept: data
at `n` shows that `n` and every name above it exist (RFC 8020 §2, Rust's `Cache::exists`). -/
def dropNxAbove (c : Cache) (now : Nat) (n : Name) (r : Rank) : Cache :=
  ⟨c.generation, c.entries.filter fun x =>
    !(live c now x && under n x.key.name && x.body.isNx && decide (x.body.rank.level ≤ r.level))⟩

/-- Stores the entry `e` an offer `o` made: data or NODATA ends the NXDOMAINs at or above its name first, and an
NXDOMAIN goes under the type it answered as well as under ANY. -/
def store (now : Nat) (c : Cache) (o : Offer) (e : Entry) : Cache :=
  let c1 := if e.body.showsName then dropNxAbove c now e.key.name e.body.rank else c
  let c2 := match o.copyKey with
    | some k => put c1 { e with key := k }
    | none => c1
  put c2 e

/-- Offers an answer to the cache at `now`. An NXDOMAIN that live data of higher rank at or below its name
contradicts is not kept. Otherwise an entry takes the key from the live entry for it only when it `replaces` it;
expired entries and entries of older generations for the key are dropped. -/
def insert (now : Nat) (lim : Limits) (c : Cache) (o : Offer) : Cache :=
  match entryFor now lim c.generation o with
  | none => c
  | some e =>
    if e.body.isNx && showsExists c now e then c
    else match c.entries.find? (fun x => x.key == e.key && live c now x) with
      | some old => if e.body.replaces old.body then store now c o e else c
      | none => store now c o e

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

/-- The live NXDOMAIN kept under ANY at `m` that answers for `n`: at `n` itself, or, when it validated Secure, at
a name above it (RFC 8020 §2). Rust trusts only a Secure NXDOMAIN for the names below it, as Unbound's
`harden-below-nxdomain` does, which RFC 8020 §4 allows. -/
def nxAt (now : Nat) (c : Cache) (n m : Name) : Option Entry :=
  c.entries.find? fun x => x.key == ⟨m, anyType⟩ && live c now x && x.body.isNx && (m == n || x.body.secure)

/-- `Cache::nxdomain_above`: the first such NXDOMAIN from `n` up to the root. -/
def nxAbove (now : Nat) (c : Cache) (n : Name) : Option Entry := (n :: ancestors n).findSome? (nxAt now c n)

/-- What the cache answers for a key, as the resolver asks it (`Resolver::cached`): an NXDOMAIN at the name or a
Secure one above it, then the live entry for the key, rendered for `now`. -/
def serve (now : Nat) (c : Cache) (k : Key) : Option Served :=
  match nxAbove now c k.name with
  | some e => some (render now e)
  | none => (c.entries.find? fun x => x.key == k && live c now x).map (render now)

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
  | failure k why follows => cases h; exact ⟨rfl, rfl, rfl, Nat.le_refl _, fun _ _ _ hb => by cases hb⟩

theorem entryFor_negative {now : Nat} {lim : Limits} {g : Nat} {k : Key} {kind : Negative} {soa : Option RRset}
    {r : Rank} {nsec : Option Nat} {v : Validation} {sig orig : Option Nat} {tc : Bool} {e : Entry}
    (h : entryFor now lim g (.negative k kind soa r nsec v sig orig tc) = some e) :
    ∃ soa', e.body = .negative kind soa' r v := by
  unfold entryFor at h
  simp only at h
  cases soa with
  | none => cases h
  | some soa =>
    simp only at h
    cases nsec with
    | none =>
      simp only at h
      split at h
      · cases h
      · cases h; exact ⟨_, rfl⟩
    | some n =>
      simp only at h
      split at h
      · cases h
      · cases h; exact ⟨_, rfl⟩

theorem nodup_filter_cons {e : Entry} {l : List Entry} (h : (l.map (·.key)).Nodup) :
    ((e :: l.filter (·.key != e.key)).map (·.key)).Nodup := by
  rw [List.map_cons, List.nodup_cons]
  constructor
  · intro hm
    obtain ⟨x, hx, hxk⟩ := List.mem_map.mp hm
    have := (List.mem_filter.mp hx).2
    simp [hxk] at this
  · exact List.Nodup.sublist (List.Sublist.map _ List.filter_sublist) h

theorem put_unique {c : Cache} {e : Entry} (h : Unique c) : Unique (put c e) := nodup_filter_cons h

theorem mem_put {c : Cache} {e x : Entry} (h : x ∈ (put c e).entries) : x = e ∨ x ∈ c.entries := by
  rcases List.mem_cons.mp h with h | h
  · exact Or.inl h
  · exact Or.inr (List.mem_filter.mp h).1

theorem drop_unique {c : Cache} {now : Nat} {n : Name} {r : Rank} (h : Unique c) :
    Unique (dropNxAbove c now n r) :=
  List.Nodup.sublist (List.Sublist.map _ List.filter_sublist) h

theorem mem_drop {c : Cache} {now : Nat} {n : Name} {r : Rank} {x : Entry}
    (h : x ∈ (dropNxAbove c now n r).entries) : x ∈ c.entries := (List.mem_filter.mp h).1

theorem store_unique {now : Nat} {c : Cache} {o : Offer} {e : Entry} (h : Unique c) :
    Unique (store now c o e) := by
  dsimp only [store]
  apply put_unique
  have h1 : Unique (if e.body.showsName then dropNxAbove c now e.key.name e.body.rank else c) := by
    split
    · exact drop_unique h
    · exact h
  split
  · exact put_unique h1
  · exact h1

theorem mem_store {now : Nat} {c : Cache} {o : Offer} {e x : Entry} (h : x ∈ (store now c o e).entries) :
    x = e ∨ (∃ k, x = { e with key := k }) ∨ x ∈ c.entries := by
  dsimp only [store] at h
  have h1 : ∀ y, y ∈ (if e.body.showsName then dropNxAbove c now e.key.name e.body.rank else c).entries →
      y ∈ c.entries := by
    intro y hy
    split at hy
    · exact mem_drop hy
    · exact hy
  rcases mem_put h with h | h
  · exact Or.inl h
  · split at h
    · rcases mem_put h with h | h
      · exact Or.inr (Or.inl ⟨_, h⟩)
      · exact Or.inr (Or.inr (h1 _ h))
    · exact Or.inr (Or.inr (h1 _ h))

theorem store_generation {now : Nat} {c : Cache} {o : Offer} {e : Entry} :
    (store now c o e).generation = c.generation := by
  dsimp only [store]
  split <;> split <;> rfl

theorem insert_entries (now : Nat) (lim : Limits) (c : Cache) (o : Offer) :
    (insert now lim c o).generation = c.generation ∧
      (insert now lim c o = c ∨ ∃ e, entryFor now lim c.generation o = some e ∧ insert now lim c o = store now c o e) := by
  unfold insert
  cases he : entryFor now lim c.generation o with
  | none => exact ⟨rfl, Or.inl rfl⟩
  | some e =>
    simp only
    split
    · exact ⟨rfl, Or.inl rfl⟩
    · split
      · split
        · exact ⟨store_generation, Or.inr ⟨e, rfl, rfl⟩⟩
        · exact ⟨rfl, Or.inl rfl⟩
      · exact ⟨store_generation, Or.inr ⟨e, rfl, rfl⟩⟩

theorem insert_unique {now : Nat} {lim : Limits} {c : Cache} {o : Offer} (h : Unique c) :
    Unique (insert now lim c o) := by
  rcases (insert_entries now lim c o).2 with he | ⟨e, _, he⟩
  · rw [he]; exact h
  · rw [he]; exact store_unique h

theorem insert_wellTimed {now : Nat} {lim : Limits} {c : Cache} {o : Offer} {t : Nat} (h : WellTimed c t)
    (ht : t ≤ now) : WellTimed (insert now lim c o) now := by
  rcases (insert_entries now lim c o).2 with he | ⟨e, hfor, he⟩
  · intro x hx; rw [he] at hx
    obtain ⟨h1, h2, h3⟩ := h x hx
    exact ⟨h1, Nat.le_trans h2 ht, h3⟩
  · intro x hx
    rw [he] at hx
    obtain ⟨_, hs, _, hexp, horig⟩ := entryFor_spec hfor
    rcases mem_store hx with rfl | ⟨k, rfl⟩ | hx
    · exact ⟨by omega, by omega, horig⟩
    · exact ⟨by simp only; omega, by simp only; omega, fun s r v hb => horig s r v hb⟩
    · obtain ⟨h1, h2, h3⟩ := h x hx
      exact ⟨h1, Nat.le_trans h2 ht, h3⟩

theorem wellTimed_mono {c : Cache} {t t' : Nat} (h : WellTimed c t) (ht : t ≤ t') : WellTimed c t' := by
  intro e he
  obtain ⟨h1, h2, h3⟩ := h e he
  exact ⟨h1, Nat.le_trans h2 ht, h3⟩

/-- A session change leaves nothing to serve. -/
theorem advance_clears (c : Cache) (now : Nat) (k : Key) :
    serve now (advance c) k = none ∧ Unique (advance c) ∧ ∀ t, WellTimed (advance c) t := by
  refine ⟨?_, List.nodup_nil, fun _ _ h => by simp [advance] at h⟩
  have : nxAbove now (advance c) k.name = none := by
    unfold nxAbove
    apply List.findSome?_eq_none_iff.mpr
    intro m _
    rfl
  unfold serve
  rw [this]
  rfl

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

theorem nxAt_some {now : Nat} {c : Cache} {n m : Name} {e : Entry} (h : nxAt now c n m = some e) :
    e ∈ c.entries ∧ e.key = ⟨m, anyType⟩ ∧ live c now e = true ∧ e.body.isNx = true ∧
      (m = n ∨ e.body.secure = true) := by
  unfold nxAt at h
  have hp := List.find?_some h
  simp only [Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq] at hp
  exact ⟨List.mem_of_find?_eq_some h, hp.1.1.1, hp.1.1.2, hp.1.2, hp.2⟩

theorem nxAbove_some {now : Nat} {c : Cache} {n : Name} {e : Entry} (h : nxAbove now c n = some e) :
    ∃ m, under n m = true ∧ e ∈ c.entries ∧ e.key = ⟨m, anyType⟩ ∧ live c now e = true ∧ e.body.isNx = true ∧
      (m = n ∨ e.body.secure = true) := by
  unfold nxAbove at h
  obtain ⟨m, hm, hs⟩ := List.exists_of_findSome?_eq_some h
  refine ⟨m, ?_, nxAt_some hs⟩
  rcases List.mem_cons.mp hm with rfl | hm
  · exact (under_iff _ _).mpr (List.suffix_refl _)
  · obtain ⟨i, _, rfl⟩ := List.mem_map.mp hm
    exact (under_iff _ _).mpr (List.drop_suffix _ _)

theorem serve_some {now : Nat} {c : Cache} {k : Key} {s : Served} (h : serve now c k = some s) :
    ∃ e ∈ c.entries, live c now e = true ∧ s = render now e ∧
      (e.key = k ∨ ∃ m, under k.name m = true ∧ e.key = ⟨m, anyType⟩ ∧ e.body.isNx = true) := by
  unfold serve at h
  cases hn : nxAbove now c k.name with
  | some e =>
    rw [hn] at h
    obtain ⟨m, hm, he, hk, hl, hnx, _⟩ := nxAbove_some hn
    exact ⟨e, he, hl, (Option.some.inj h).symm, Or.inr ⟨m, hm, hk, hnx⟩⟩
  | none =>
    rw [hn] at h
    simp only at h
    cases hf : c.entries.find? (fun x => x.key == k && live c now x) with
    | none => rw [hf] at h; cases h
    | some e =>
      rw [hf] at h
      simp only [Option.map_some, Option.some.injEq] at h
      have hp := List.find?_some hf
      simp only [Bool.and_eq_true, beq_iff_eq] at hp
      exact ⟨e, List.mem_of_find?_eq_some hf, hp.2, h.symm, Or.inl hp.1⟩

/-- With one entry per key and no NXDOMAIN at or above the name, the cache serves the live entry for a key. -/
theorem serve_entry {now : Nat} {c : Cache} {k : Key} {e : Entry} (hu : Unique c) (he : e ∈ c.entries)
    (hk : e.key = k) (hl : live c now e = true) (hn : nxAbove now c k.name = none) :
    serve now c k = some (render now e) := by
  unfold serve
  rw [hn]
  simp only
  cases hf : c.entries.find? (fun x => x.key == k && live c now x) with
  | none =>
    exact absurd (List.find?_eq_none.mp hf e he) (by simp [hk, hl])
  | some e' =>
    have hp := List.find?_some hf
    simp only [Bool.and_eq_true, beq_iff_eq] at hp
    rw [unique_key hu (List.mem_of_find?_eq_some hf) he (hp.1.trans hk.symm)]
    rfl

theorem render_positive {now : Nat} {e : Entry} {s : RRset} {v : Validation}
    (h : render now e = .positive s v) : ∃ s₀ r, e.body = .positive s₀ r v ∧ s = { s₀ with ttl := e.expires - now } := by
  unfold render at h
  cases hb : e.body with
  | positive s₀ r v₀ => rw [hb] at h; cases h; exact ⟨s₀, r, rfl, rfl⟩
  | negative _ _ _ _ => rw [hb] at h; cases h
  | failure _ => rw [hb] at h; cases h

/-! ## The headline theorems -/

/-- An entry is served only while it lives: written in the current generation and not yet expired. It is the
entry for the key, or an NXDOMAIN kept under ANY at the name or above it. -/
theorem expired_never_served {now : Nat} {c : Cache} {k : Key} {s : Served} (h : serve now c k = some s) :
    ∃ e ∈ c.entries, e.generation = c.generation ∧ now < e.expires ∧
      (e.key = k ∨ ∃ m, under k.name m = true ∧ e.key = ⟨m, anyType⟩ ∧ e.body.isNx = true) := by
  obtain ⟨e, he, hl, _, hk⟩ := serve_some h
  simp only [live, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hl
  exact ⟨e, he, hl.1, hl.2, hk⟩

/-- A served RRset's TTL, counted down, is never above the TTL it was offered with. -/
theorem served_ttl_le_original {now : Nat} {c : Cache} {k : Key} {s : RRset} {v : Validation}
    (hw : WellTimed c now) (h : serve now c k = some (.positive s v)) :
    ∃ e ∈ c.entries, ∃ s₀ r, e.key = k ∧ e.body = .positive s₀ r v ∧ s.ttl ≤ s₀.ttl ∧
      s.owner = s₀.owner ∧ s.rtype = s₀.rtype ∧ s.rdata = s₀.rdata := by
  obtain ⟨e, he, _, hs, hk⟩ := serve_some h
  obtain ⟨h1, h2, h3⟩ := hw e he
  obtain ⟨s₀, r, hb, rfl⟩ := render_positive hs.symm
  have := h3 s₀ r _ hb
  have hk : e.key = k := by
    rcases hk with hk | ⟨_, _, _, hnx⟩
    · exact hk
    · simp [Body.isNx, hb] at hnx
  exact ⟨e, he, s₀, r, hk, hb, by simp only; omega, rfl, rfl, rfl⟩

/-- A cached failure never answers as a negative: with a failure cached for the key, a negative answer only
ever comes from a live NXDOMAIN at the name or above it, and with none there the failure answers SERVFAIL
(RFC 9520). -/
theorem failure_never_negative {now : Nat} {c : Cache} {k : Key} {e : Entry} {why : FailureKind} (hu : Unique c)
    (he : e ∈ c.entries) (hk : e.key = k) (hb : e.body = .failure why) :
    (∀ kind soa v, serve now c k = some (.negative kind soa v) → nxAbove now c k.name ≠ none) ∧
      (live c now e = true → nxAbove now c k.name = none → serve now c k = some (.failure why)) := by
  refine ⟨fun kind soa v h hn => ?_, fun hl hn => ?_⟩
  · unfold serve at h
    rw [hn] at h
    simp only at h
    cases hf : c.entries.find? (fun x => x.key == k && live c now x) with
    | none => rw [hf] at h; cases h
    | some e' =>
      rw [hf] at h
      have hp := List.find?_some hf
      simp only [Bool.and_eq_true, beq_iff_eq] at hp
      rw [unique_key hu (List.mem_of_find?_eq_some hf) he (hp.1.trans hk.symm)] at h
      simp [render, hb] at h
  · rw [serve_entry hu he hk hl hn]
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
    split
    · rfl
    have hk' : e'.key = e.key := (entryFor_spec hfor).1.trans hk.symm
    cases hf : c.entries.find? (fun x => x.key == e'.key && live c now x) with
    | none => exact absurd (List.find?_eq_none.mp hf e he) (by simp [hk', hl])
    | some old =>
      have hp := List.find?_some hf
      simp only [Bool.and_eq_true, beq_iff_eq] at hp
      have hold : old = e := unique_key hu (List.mem_of_find?_eq_some hf) he (hp.1.trans hk')
      subst hold
      simp [hr e' hfor]

/-- An NXDOMAIN answers every type at its name (RFC 2308 §5): a live NXDOMAIN kept under ANY at `n` is what the
cache serves for `n` with any type, whatever is cached under that type. -/
theorem nxdomain_every_type {now : Nat} {c : Cache} {n : Name} {e : Entry} (hu : Unique c) (he : e ∈ c.entries)
    (hk : e.key = ⟨n, anyType⟩) (hl : live c now e = true) (hnx : e.body.isNx = true) (t : Nat) :
    serve now c ⟨n, t⟩ = some (render now e) := by
  have hat : nxAt now c n n = some e := by
    unfold nxAt
    cases hf : c.entries.find? (fun x => x.key == ⟨n, anyType⟩ && live c now x && x.body.isNx &&
        (n == n || x.body.secure)) with
    | none => exact absurd (List.find?_eq_none.mp hf e he) (by simp [hk, hl, hnx])
    | some e' =>
      have hp := List.find?_some hf
      simp only [Bool.and_eq_true, beq_iff_eq] at hp
      rw [unique_key hu (List.mem_of_find?_eq_some hf) he (hp.1.1.1.trans hk.symm)]
  simp [serve, nxAbove, List.findSome?_cons, hat]

/-- Nothing exists below a name that does not exist (RFC 8020 §2): a live NXDOMAIN at `m` that validated Secure
answers every question for a name below `m`, by that NXDOMAIN or one closer to the name. -/
theorem nxdomain_below {now : Nat} {c : Cache} {m : Name} {e : Entry} (hu : Unique c) (he : e ∈ c.entries)
    (hk : e.key = ⟨m, anyType⟩) (hl : live c now e = true) (hnx : e.body.isNx = true)
    (hsec : e.body.secure = true) (k : Key) (hb : under k.name m = true) :
    ∃ e' ∈ c.entries, e'.body.isNx = true ∧ serve now c k = some (render now e') := by
  have hat : nxAt now c k.name m = some e := by
    unfold nxAt
    cases hf : c.entries.find? (fun x => x.key == ⟨m, anyType⟩ && live c now x && x.body.isNx &&
        (m == k.name || x.body.secure)) with
    | none => exact absurd (List.find?_eq_none.mp hf e he) (by simp [hk, hl, hnx, hsec])
    | some e' =>
      have hp := List.find?_some hf
      simp only [Bool.and_eq_true, beq_iff_eq] at hp
      rw [unique_key hu (List.mem_of_find?_eq_some hf) he (hp.1.1.1.trans hk.symm)]
  have hmem : m ∈ k.name :: ancestors k.name := by
    obtain ⟨p, hp⟩ := (under_iff _ _).mp hb
    cases p with
    | nil =>
      simp only [List.nil_append] at hp
      exact List.mem_cons.mpr (Or.inl hp)
    | cons a p' =>
      refine List.mem_cons_of_mem _ (List.mem_map.mpr ⟨p'.length, List.mem_range.mpr ?_, ?_⟩)
      · rw [← hp]; simp only [List.cons_append, List.length_cons, List.length_append]; omega
      · show k.name.drop (p'.length + 1) = m
        rw [← hp]; simp
  cases hn : nxAbove now c k.name with
  | none =>
    unfold nxAbove at hn
    have := List.findSome?_eq_none_iff.mp hn m hmem
    rw [hat] at this; cases this
  | some e' =>
    obtain ⟨_, _, he', _, _, hnx', _⟩ := nxAbove_some hn
    exact ⟨e', he', hnx', by simp [serve, hn]⟩

/-- Data, or NODATA, at a name ends every NXDOMAIN at that name or above it of no higher rank, under every type it
was kept under, since the name and the names above it exist after all (RFC 8020 §2). This is the rule Rust's
`Cache::exists` keeps, the copies of an NXDOMAIN under the types it answered included. -/
theorem data_ends_nxdomain {now : Nat} {lim : Limits} {c : Cache} {o : Offer} {e : Entry}
    (hfor : entryFor now lim c.generation o = some e) (hs : e.body.showsName = true)
    (hr : ∀ old ∈ c.entries, old.key = e.key → live c now old = true → e.body.replaces old.body = true) :
    ∀ x ∈ (insert now lim c o).entries, live (insert now lim c o) now x = true → under e.key.name x.key.name = true →
      x.body.isNx = true → e.body.rank.level < x.body.rank.level := by
  have hnx : e.body.isNx = false := by
    cases hb : e.body with
    | positive => rfl
    | negative kind _ _ _ => cases kind <;> simp_all [Body.isNx, Body.showsName]
    | failure => simp_all [Body.showsName]
  have hins : insert now lim c o = store now c o e := by
    unfold insert
    rw [hfor]
    simp only [hnx, Bool.false_and, Bool.false_eq_true, ↓reduceIte]
    cases hf : c.entries.find? (fun x => x.key == e.key && live c now x) with
    | none => rfl
    | some old =>
      have hp := List.find?_some hf
      simp only [Bool.and_eq_true, beq_iff_eq] at hp
      simp [hr old (List.mem_of_find?_eq_some hf) hp.1 hp.2]
  have hcopy : o.copyKey = none := by
    cases o with
    | negative k kind _ _ _ _ _ _ _ =>
      cases kind
      · obtain ⟨_, hb⟩ := entryFor_negative hfor
        rw [hb] at hnx
        simp [Body.isNx] at hnx
      · rfl
    | positive => rfl
    | failure => rfl
  rw [hins]
  intro x hx hl hu hxnx
  dsimp only [store] at hx hl
  simp only [hs, ↓reduceIte, hcopy] at hx hl
  rcases mem_put hx with rfl | hx
  · rw [hnx] at hxnx; cases hxnx
  · have hkeep := (List.mem_filter.mp hx).2
    simp only [put, dropNxAbove, live] at hl hkeep
    simp only [live, hl, hu, hxnx, Bool.true_and, Bool.not_eq_true', decide_eq_false_iff_not] at hkeep
    omega

/-- A NODATA answers only the type it was given for (RFC 2308 §5): the cache serves NODATA for a key only from an
entry kept under that very key. -/
theorem nodata_keyed_by_type {now : Nat} {c : Cache} {k : Key} {soa : RRset} {v : Validation}
    (h : serve now c k = some (.negative .noData soa v)) :
    ∃ e ∈ c.entries, e.key = k ∧ live c now e = true ∧ ∃ soa₀ r, e.body = .negative .noData soa₀ r v := by
  obtain ⟨e, he, hl, hs, hk⟩ := serve_some h
  unfold render at hs
  cases hb : e.body with
  | positive => rw [hb] at hs; cases hs
  | failure => rw [hb] at hs; cases hs
  | negative kind soa₀ r v₀ =>
    rw [hb] at hs
    simp only [Served.negative.injEq] at hs
    obtain ⟨rfl, _, rfl⟩ := hs
    rcases hk with hk | ⟨_, _, _, hnx⟩
    · exact ⟨e, he, hk, hl, soa₀, r, hb⟩
    · simp [hb, Body.isNx] at hnx

end Dns.Cache
