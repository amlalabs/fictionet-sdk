/-
  Zones and the answer algorithm of RFC 1034 §4.3.2: nodes, cuts with in-domain and
  sibling glue, empty non-terminals, wildcards (RFC 4592), CNAME chains, DNAME (RFC 6672), negative answers
  (RFC 2308), and the builder's checks.

  The algorithm is written once, over a function `look` that says for each name whether a node is present,
  known absent, or unknown. A complete `Zone` gives a `look` that is never unknown; a partial view
  (`Dns/Partial.lean`) gives one that may be. Names in a zone, and the question name, are lowercase (Rust's
  `LowerName`), so names compare as plain label lists here.

  Rust: `services::dns::zone::{Fact, Node, Zone, ZoneBuilder, ZoneError, answer, Answered, AnyResponse}`.
-/
import Dns.Name

namespace Dns.Zone

/-- What a zone knows about one fact. -/
inductive Fact (α : Type) where
  | present (a : α)
  | absent
  | unknown
deriving DecidableEq, Repr

/-! ## Records -/

/-- Record data the answer algorithm reads. -/
inductive RData where
  | a (addr : List Nat)
  | aaaa (addr : List Nat)
  | ns (target : Name)
  | cname (target : Name)
  | dname (target : Name)
  | ptr (target : Name)
  | mx (pref : Nat) (target : Name)
  | srv (prio weight port : Nat) (target : Name)
  | txt (strings : List (List Nat))
  | hinfo (cpu os : List Nat)
  | soa (mname rname : Name) (serial refresh retry expire minimum : Nat)
  | ds (tag alg dtype : Nat) (digest : List Nat)
  | other (rtype : Nat) (bytes : List Nat)
deriving DecidableEq, Repr, Inhabited

namespace RType
def A := 1
def NS := 2
def CNAME := 5
def SOA := 6
def PTR := 12
def HINFO := 13
def MX := 15
def TXT := 16
def AAAA := 28
def SRV := 33
def DNAME := 39
def DS := 43
def ANY := 255
end RType

def RData.rtype : RData → Nat
  | .a _ => 1 | .aaaa _ => 28 | .ns _ => 2 | .cname _ => 5 | .dname _ => 39 | .ptr _ => 12
  | .mx _ _ => 15 | .srv _ _ _ _ => 33 | .txt _ => 16 | .hinfo _ _ => 13 | .soa _ _ _ _ _ _ _ => 6
  | .ds _ _ _ _ => 43 | .other t _ => t

/-- The records of one owner and type. -/
structure RRset where
  owner : Name
  rtype : Nat
  ttl : Nat
  rdata : List RData
deriving DecidableEq, Repr, Inhabited

/-! ## Zones -/

inductive Node where
  /-- Authoritative RRsets, at most one per type. -/
  | data (sets : List RRset)
  /-- A zone cut: the NS set, the DS set if the child is signed, and glue below the cut. -/
  | cut (ns : RRset) (ds : Option RRset) (glue : List RRset)
  /-- A DNAME and the other RRsets at its owner. -/
  | dname (d : RRset) (sets : List RRset)
  /-- An empty non-terminal (RFC 8020): nothing here, names below. -/
  | empty
deriving DecidableEq, Repr, Inhabited

structure Zone where
  apex : Name
  soa : RRset
  nodes : List (Name × Node)
deriving Repr

/-- `a` is at or below `b`: `b`'s labels end `a`'s. -/
def under (a b : Name) : Bool := b.isSuffixOf a

theorem under_iff (a b : Name) : under a b = true ↔ b <:+ a := List.isSuffixOf_iff_suffix

/-- The node held at exactly `n`. -/
def Zone.node (z : Zone) (n : Name) : Option Node := z.nodes.lookup n

/-- Whether `z` holds a node at or below `n`. -/
def Zone.presentB (z : Zone) (n : Name) : Bool := z.nodes.any fun p => under p.1 n

/-- What a complete zone knows about `n`: its node; an empty non-terminal when it holds only names below `n`;
otherwise known absent. Never unknown. -/
def Zone.look (z : Zone) (n : Name) : Fact Node :=
  match z.node n with
  | some nd => .present nd
  | none => if z.presentB n then .present .empty else .absent

/-! ## Questions and responses -/

structure Request where
  qname : Name
  qtype : Nat
deriving DecidableEq, Repr

inductive Rcode where
  | noerror
  | nxdomain
  | yxdomain
  | refused
  | servfail
deriving DecidableEq, Repr

structure Response where
  rcode : Rcode
  aa : Bool
  answer : List RRset
  authority : List RRset
  additional : List RRset
  /-- The first `required` additional RRsets are required glue (RFC 9471 §3.1). -/
  required : Nat
deriving DecidableEq, Repr

inductive Answered where
  | response (r : Response)
  | unknown (name : Name)
deriving DecidableEq, Repr

/-- What a server sends for QTYPE ANY (RFC 8482 §4). -/
inductive AnyResponse where
  | hinfo
  | oneRrset
  | all
deriving DecidableEq, Repr

/-! ## The algorithm

Computations run in `Except Name`: an unknown fact ends the answer with that name. -/

abbrev M := Except Name

/-- The node at `n`, `none` when known absent, or the end of the answer when unknown. -/
def get (look : Name → Fact Node) (n : Name) : M (Option Node) :=
  match look n with
  | .present nd => .ok (some nd)
  | .absent => .ok none
  | .unknown => .error n

/-- Where the walk from the apex toward a name stops. -/
inductive Loc where
  | outside
  /-- The walk reached the name itself, which has this node. -/
  | node (n : Name) (nd : Node)
  /-- A cut at `m`, strictly below the apex and at or above the name. -/
  | cut (m : Name) (ns : RRset) (ds : Option RRset) (glue : List RRset)
  /-- A DNAME at `m`, strictly above the name. -/
  | dname (m : Name) (d : RRset)
  /-- No node at the name or below it; `ce` is the closest encloser. -/
  | absent (ce : Name)
deriving DecidableEq, Repr

def atApex (look : Name → Fact Node) (apex : Name) : M Loc :=
  match get look apex with
  | .ok (some nd) => .ok (.node apex nd)
  | .ok none => .ok (.absent apex)
  | .error e => .error e

/-- One step down the walk, from `p` to its child `q`, when `p` does not divert it. -/
def child (look : Name → Fact Node) (q p : Name) : M Loc :=
  match get look q with
  | .ok none => .ok (.absent p)
  | .ok (some (.cut ns ds g)) => .ok (.cut q ns ds g)
  | .ok (some nd) => .ok (.node q nd)
  | .error e => .error e

/-- Walks from the apex down to `q`, asking `look` at each name (the answer's steps 1 to 5, without the
wildcard). -/
def locate (look : Name → Fact Node) (apex : Name) : Name → M Loc
  | [] => if ([] : Name) = apex then atApex look apex else .ok .outside
  | l :: p =>
    if l :: p = apex then atApex look apex else
    match locate look apex p with
    | .ok (.node _ (.dname d _)) => .ok (.dname p d)
    | .ok (.node _ _) => child look (l :: p) p
    | .ok r => .ok r
    | .error e => .error e

/-- The wildcard name at a closest encloser. -/
def wild (ce : Name) : Name := [42] :: ce

def negTtl (soa : RRset) : Nat :=
  match soa.rdata with
  | [.soa _ _ _ _ _ _ m] => min soa.ttl m
  | _ => soa.ttl

/-- The SOA for a negative answer, with TTL min(SOA TTL, MINIMUM) (RFC 2308 §3). -/
def negSoa (soa : RRset) : RRset := { soa with ttl := negTtl soa }

def withOwner (o : Name) (s : RRset) : RRset := { s with owner := o }

def isAddr (s : RRset) : Bool := s.rtype == 1 || s.rtype == 28

/-- Names whose addresses go in the additional section: NS, MX, and SRV targets (RFC 1034 §4.3.2 step 6). -/
def targets (s : RRset) : List Name :=
  s.rdata.filterMap fun
    | .ns t => some t
    | .mx _ t => some t
    | .srv _ _ _ t => some t
    | _ => none

def cnameTarget (s : RRset) : Option Name :=
  match s.rdata with
  | .cname t :: _ => some t
  | _ => none

def dnameTarget (s : RRset) : Option Name :=
  match s.rdata with
  | .dname t :: _ => some t
  | _ => none

def nodeSets : Node → List RRset
  | .data sets => sets
  | .dname d sets => d :: sets
  | .cut ns ds _ => ns :: ds.toList
  | .empty => []

def collect (f : Name → M (List RRset)) : List Name → M (List RRset)
  | [] => .ok []
  | t :: ts =>
    match f t with
    | .ok a =>
      match collect f ts with
      | .ok b => .ok (a ++ b)
      | .error e => .error e
    | .error e => .error e

/-- The address RRsets at a target's own node in this zone. They are optional additional data
(RFC 2181 §5.4.1, RFC 9471 §3.2), so no answer rests on them: a target whose node is unknown has none. -/
def addrsOf (look : Name → Fact Node) (apex t : Name) : M (List RRset) :=
  if under t apex then
    match locate look apex t with
    | .ok (.node _ nd) => .ok ((nodeSets nd).filter isAddr)
    | _ => .ok []
  else .ok []

/-- Sibling glue for a referral at `m`: addresses of a target held under another cut of this zone
(RFC 9471 §3.2), as the root holds `gtld-servers.net` addresses for its `com` referral. It is optional
additional data too, so a target whose cut is unknown has none. -/
def siblingGlue (look : Name → Fact Node) (apex m t : Name) : M (List RRset) :=
  if under t apex && !under t m then
    match locate look apex t with
    | .ok (.cut _ _ _ g) => .ok (g.filter fun s => isAddr s && s.owner == t)
    | _ => .ok []
  else .ok []

/-- One step's outcome: a finished response, or a CNAME (written or synthesized) and its target. -/
inductive Out where
  | done (rcode : Rcode) (aa : Bool) (answer authority additional : List RRset) (required : Nat)
  | restart (answer : List RRset) (target : Name)
deriving DecidableEq, Repr

def nodata (soa : RRset) : Out := .done .noerror true [] [negSoa soa] [] 0

/-- A referral to the cut at `m`: AA=0, the NS set in authority, in-domain glue as required additional data,
and sibling glue after it as optional additional data (step 2 of the answer). -/
def referral (look : Name → Fact Node) (apex m : Name) (ns : RRset) (glue : List RRset) : M Out :=
  let inDomain := glue.filter fun s => isAddr s && (targets ns).contains s.owner && under s.owner m
  match collect (siblingGlue look apex m) (targets ns) with
  | .ok sib => .ok (.done .noerror false [] [ns] (inDomain ++ sib) inDomain.length)
  | .error e => .error e

/-- The synthesized HINFO answer to QTYPE ANY (RFC 8482 §4.2), with the smallest TTL among the name's RRsets. -/
def hinfoAnswer (q : Name) (sets : List RRset) : RRset :=
  ⟨q, 13, ((sets.map (·.ttl)).min?).getD 0, [.hinfo [82, 70, 67, 56, 52, 56, 50] []]⟩

/-- The answer to QTYPE ANY. No HINFO is made up at a CNAME (RFC 8482 §4.2), which leaves room for no other data
(RFC 1034 §3.6.2): the answer is the CNAME. -/
def anySets (any : AnyResponse) (q : Name) (sets : List RRset) : List RRset :=
  match any with
  | .hinfo =>
    match sets.find? (·.rtype == 5) with
    | some c => [withOwner q c]
    | none => [hinfoAnswer q sets]
  | .oneRrset => (sets.take 1).map (withOwner q)
  | .all => sets.map (withOwner q)

/-- The answer from the RRsets matched at `q`, its own node's or a wildcard's (steps 4 and 5 of the answer). Owners are
`q`. A CNAME restarts the walk; no RRset of the type is NODATA. -/
def exact (look : Name → Fact Node) (apex : Name) (soa : RRset) (any : AnyResponse) (q : Name) (qtype : Nat)
    (sets : List RRset) : M Out :=
  if qtype = 255 then
    if sets = [] then .ok (nodata soa) else .ok (.done .noerror true (anySets any q sets) [] [] 0)
  else
    match sets.find? (·.rtype == qtype) with
    | some s =>
      match collect (addrsOf look apex) (targets s) with
      | .ok add => .ok (.done .noerror true [withOwner q s] [] add 0)
      | .error e => .error e
    | none =>
      match sets.find? (·.rtype == 5) with
      | some c =>
        match cnameTarget c with
        | some t => .ok (.restart [withOwner q c] t)
        | none => .ok (.done .noerror true [withOwner q c] [] [] 0)
      | none => .ok (nodata soa)

/-- One pass of the answer's steps for the name `q`. -/
def step (look : Name → Fact Node) (apex : Name) (soa : RRset) (any : AnyResponse) (q : Name) (qtype : Nat) :
    M Out :=
  match locate look apex q with
  | .error e => .error e
  | .ok .outside => .ok (.done .refused false [] [] [] 0)
  | .ok (.cut m ns ds g) =>
    if m = q ∧ qtype = 43 then
      -- DS is answered from the parent side of the cut (RFC 4035 §3.1.4.1)
      match ds with
      | some s => .ok (.done .noerror true [s] [] [] 0)
      | none => .ok (nodata soa)
    else referral look apex m ns g
  | .ok (.dname m d) =>
    match dnameTarget d with
    | some dt =>
      let t := q.take (q.length - m.length) ++ dt
      if 255 < Name.wireLen t then .ok (.done .yxdomain true [d] [] [] 0)
      else .ok (.restart [d, ⟨q, 5, d.ttl, [.cname t]⟩] t)
    | none => .ok (.done .noerror true [d] [] [] 0)
  | .ok (.node _ nd) => exact look apex soa any q qtype (nodeSets nd)
  | .ok (.absent ce) =>
    match get look (wild ce) with
    | .error e => .error e
    | .ok none => .ok (.done .nxdomain true [] [negSoa soa] [] 0)
    | .ok (some (.cut ns _ g)) => referral look apex (wild ce) ns g
    | .ok (some nd) => exact look apex soa any q qtype (nodeSets nd)

/-- The bound that makes the chase total. Every step of a chain visits a new name, which is a CNAME target the
zone holds or a DNAME substitution of at most 255 octets, so a chain ends by repeating a name, leaving the
zone, or YXDOMAIN long before this many steps. -/
def chainFuel : Nat := 256 ^ 256

/-- `acc` followed by the RRsets of `an` with an owner and type `acc` does not hold yet. Two records with the same
owner, class, type, and data are one (RFC 2181 §5), so an RRset a chain reaches twice, such as a DNAME it passes
again, goes out once. -/
def addNew (acc an : List RRset) : List RRset :=
  acc ++ an.filter fun s => !acc.any fun x => x.owner == s.owner && x.rtype == s.rtype

@[simp] theorem addNew_nil (an : List RRset) : addNew [] an = an := by
  simp [addNew]

theorem mem_addNew {acc an : List RRset} {s : RRset} (h : s ∈ addNew acc an) : s ∈ acc ∨ s ∈ an := by
  unfold addNew at h
  rcases List.mem_append.mp h with h | h
  · exact Or.inl h
  · exact Or.inr (List.mem_filter.mp h).1

theorem addNew_ne_nil {acc an : List RRset} (h : an ≠ []) : addNew acc an ≠ [] := by
  cases acc with
  | nil => simpa using h
  | cons x xs => simp [addNew]

/-- Follows CNAMEs inside the zone, stopping at the first repeated name (RFC 1034 §4.3.2 step 3a). The RCODE is the
last name's (RFC 6604 §2). -/
def chase (look : Name → Fact Node) (apex : Name) (soa : RRset) (any : AnyResponse) (qtype : Nat) :
    Nat → List Name → List RRset → Name → M Response
  | 0, _, acc, _ => .ok ⟨.servfail, false, acc, [], [], 0⟩
  | f + 1, seen, acc, q =>
    match step look apex soa any q qtype with
    | .error e => .error e
    | .ok (.done rc aa an au ad req) => .ok ⟨rc, aa || !acc.isEmpty, addNew acc an, au, ad, req⟩
    | .ok (.restart an t) =>
      if t ∈ q :: seen ∨ ¬ under t apex = true then .ok ⟨.noerror, true, addNew acc an, [], [], 0⟩
      else chase look apex soa any qtype f (q :: seen) (addNew acc an) t

/-- RFC 1034 §4.3.2 over any `look`. -/
def answerWith (look : Name → Fact Node) (apex : Name) (soa : RRset) (any : AnyResponse) (req : Request) :
    Answered :=
  if ¬ under req.qname apex = true then .response ⟨.refused, false, [], [], [], 0⟩ else
  match chase look apex soa any req.qtype chainFuel [] [] req.qname with
  | .ok r => .response r
  | .error n => .unknown n

/-- The answer of a complete zone. -/
def answer (z : Zone) (req : Request) (any : AnyResponse) : Answered :=
  answerWith z.look z.apex z.soa any req

/-! ## Facts about complete zones -/

theorem lookup_mem {l : List (Name × Node)} {k : Name} {v : Node} (h : l.lookup k = some v) : (k, v) ∈ l := by
  induction l with
  | nil => simp [List.lookup] at h
  | cons e es ih =>
    obtain ⟨k', v'⟩ := e
    simp only [List.lookup] at h
    split at h
    · rename_i hk; simp at hk h; subst hk; subst h; simp
    · exact List.mem_cons_of_mem _ (ih h)

theorem Zone.presentB_iff (z : Zone) (n : Name) : z.presentB n = true ↔ ∃ p ∈ z.nodes, n <:+ p.1 := by
  simp [Zone.presentB, under_iff]

theorem Zone.node_present {z : Zone} {n : Name} {nd : Node} (h : z.node n = some nd) : z.presentB n = true :=
  (z.presentB_iff n).mpr ⟨(n, nd), lookup_mem h, List.suffix_refl _⟩

theorem Zone.presentB_mono {z : Zone} {a b : Name} (hab : a <:+ b) (h : z.presentB b = true) :
    z.presentB a = true := by
  obtain ⟨p, hp, hs⟩ := (z.presentB_iff b).mp h
  exact (z.presentB_iff a).mpr ⟨p, hp, hab.trans hs⟩

theorem Zone.look_ne_unknown (z : Zone) (n : Name) : z.look n ≠ .unknown := by
  unfold Zone.look; split
  · simp
  · split <;> simp

theorem Zone.look_absent_iff (z : Zone) (n : Name) : z.look n = .absent ↔ z.presentB n = false := by
  unfold Zone.look
  cases h : z.node n with
  | some nd => simp [z.node_present h]
  | none => by_cases hp : z.presentB n <;> simp [hp]

theorem Zone.look_present {z : Zone} {n : Name} {nd : Node} (h : z.look n = .present nd) :
    z.presentB n = true ∧ (z.node n = some nd ∨ (z.node n = none ∧ nd = .empty)) := by
  unfold Zone.look at h
  cases hn : z.node n with
  | some nd' => rw [hn] at h; cases h; exact ⟨z.node_present hn, Or.inl rfl⟩
  | none =>
    rw [hn] at h
    by_cases hp : z.presentB n
    · simp [hp] at h; exact ⟨hp, Or.inr ⟨rfl, h.symm⟩⟩
    · simp [hp] at h

theorem Zone.look_of_node {z : Zone} {n : Name} {nd : Node} (h : z.node n = some nd) : z.look n = .present nd := by
  simp [Zone.look, h]

theorem get_total {look : Name → Fact Node} (ht : ∀ n, look n ≠ .unknown) (n : Name) :
    ∃ o, get look n = .ok o := by
  unfold get
  cases h : look n with
  | present nd => exact ⟨_, rfl⟩
  | absent => exact ⟨_, rfl⟩
  | unknown => exact absurd h (ht n)

/-! ## Where the walk stops in a complete zone -/

/-- `m` is a proper ancestor of `q`, at or below the apex. -/
def Zone.Above (z : Zone) (m q : Name) : Prop := m ≠ q ∧ m <:+ q ∧ z.apex <:+ m

/-- A node at `m` diverts a walk that passes through it: a DNAME, or a cut below the apex. -/
def Zone.stops (z : Zone) (m : Name) : Bool :=
  match z.node m with
  | some (.dname _ _) => true
  | some (.cut _ _ _) => m != z.apex
  | _ => false

/-- Nothing above `q` diverts the walk to it. -/
def Zone.NoStop (z : Zone) (q : Name) : Prop := ∀ m, z.Above m q → z.stops m = false

/-- `q` is at or below the cut at `m`, the highest cut on its path, with no DNAME above it. -/
def Zone.BelowCut (z : Zone) (q m : Name) (ns : RRset) (ds : Option RRset) (g : List RRset) : Prop :=
  z.node m = some (.cut ns ds g) ∧ m <:+ q ∧ z.apex <:+ m ∧ m ≠ z.apex ∧ z.NoStop m

/-- A DNAME at `m`, strictly above `q`, is the first thing that diverts the walk to `q`. -/
def Zone.DnameAbove (z : Zone) (q m : Name) (d : RRset) (s : List RRset) : Prop :=
  z.node m = some (.dname d s) ∧ z.Above m q ∧ z.NoStop m

/-- The closest encloser: the nearest proper ancestor of `q` at or below the apex that has a node at or below
it (RFC 4592 §3.3.1), or the apex. -/
def Zone.closest (z : Zone) : Name → Name
  | [] => z.apex
  | _ :: p => if under p z.apex then (if z.presentB p then p else z.closest p) else z.apex

theorem suffix_cons_ne {l : Label} {p a : Name} (h1 : a <:+ l :: p) (h2 : a ≠ l :: p) : a <:+ p :=
  (List.suffix_cons_iff.mp h1).resolve_left h2

theorem Zone.above_cons {z : Zone} {l : Label} {p m : Name} (h : z.Above m (l :: p)) :
    m = p ∨ z.Above m p := by
  obtain ⟨h1, h2, h3⟩ := h
  have := suffix_cons_ne h2 h1
  by_cases hm : m = p
  · exact Or.inl hm
  · exact Or.inr ⟨hm, this, h3⟩

theorem not_suffix_longer {a b : Name} (h : b.length < a.length) : ¬ a <:+ b := fun h' =>
  absurd h'.length_le (by omega)

theorem Zone.noStop_cons {z : Zone} {l : Label} {p : Name} (h1 : z.stops p = false)
    (h2 : z.NoStop p) : z.NoStop (l :: p) := by
  intro m hm
  rcases z.above_cons hm with rfl | hm'
  · exact h1
  · exact h2 m hm'

theorem Zone.noStop_apex (z : Zone) : z.NoStop z.apex := by
  intro m ⟨h1, h2, h3⟩
  exact absurd (List.IsSuffix.eq_of_length h2 (Nat.le_antisymm h2.length_le h3.length_le)) h1

theorem Zone.stops_cut {z : Zone} {m : Name} {ns : RRset} {ds : Option RRset} {g : List RRset}
    (h : z.node m = some (.cut ns ds g)) (hm : m ≠ z.apex) : z.stops m = true := by
  simp [Zone.stops, h, hm]

theorem Zone.stops_dname {z : Zone} {m : Name} {d : RRset} {s : List RRset} (h : z.node m = some (.dname d s)) :
    z.stops m = true := by
  simp [Zone.stops, h]

/-- The outcome of the walk in a complete zone. -/
def Zone.LocSpec (z : Zone) (q : Name) : Loc → Prop
  | .outside => False
  | .node n nd => n = q ∧ z.NoStop q ∧ z.look q = .present nd ∧ (q ≠ z.apex → ∀ ns ds g, nd ≠ .cut ns ds g)
  | .absent c => z.NoStop q ∧ z.presentB q = false ∧ c = z.closest q ∧ z.apex <:+ c
  | .cut m ns ds g => z.BelowCut q m ns ds g
  | .dname m d => ∃ s, z.DnameAbove q m d s

theorem Zone.atApex_spec (z : Zone) : ∃ L, atApex z.look z.apex = .ok L ∧ z.LocSpec z.apex L := by
  unfold atApex get
  cases h : z.look z.apex with
  | present nd =>
    exact ⟨.node z.apex nd, rfl, rfl, z.noStop_apex, h, fun h' => absurd rfl h'⟩
  | absent =>
    refine ⟨.absent z.apex, rfl, z.noStop_apex, (z.look_absent_iff _).mp h, ?_, List.suffix_refl _⟩
    cases ha : z.apex with
    | nil => simp [Zone.closest, ha]
    | cons l p =>
      have : ¬ under p (l :: p) = true := by
        rw [under_iff]; exact not_suffix_longer (by simp)
      simp [Zone.closest, ha, this]
  | unknown => exact absurd h (z.look_ne_unknown _)

/-- A walk through a node that does not divert it goes on to the child. -/
theorem locate_cons_node {look : Name → Fact Node} {apex : Name} {l : Label} {p n : Name} {nd : Node}
    (heq : l :: p ≠ apex) (hl : locate look apex p = .ok (.node n nd)) (hnd : ∀ d s, nd ≠ .dname d s) :
    locate look apex (l :: p) = child look (l :: p) p := by
  cases nd with
  | dname d s => exact absurd rfl (hnd d s)
  | data _ => simp [locate, heq, hl]
  | cut _ _ _ => simp [locate, heq, hl]
  | empty => simp [locate, heq, hl]

theorem Zone.child_spec (z : Zone) {l : Label} {p : Name} (hq : z.apex <:+ l :: p) (heq : l :: p ≠ z.apex)
    (hp : z.apex <:+ p) (hns : z.NoStop (l :: p)) (hpres : z.presentB p = true) :
    ∃ L, child z.look (l :: p) p = .ok L ∧ z.LocSpec (l :: p) L := by
  unfold child get
  cases hg : z.look (l :: p) with
  | present nd =>
    obtain ⟨_, hnode⟩ := z.look_present hg
    cases nd with
    | cut ns ds g =>
      have hn : z.node (l :: p) = some (.cut ns ds g) := by
        rcases hnode with h | ⟨_, h⟩
        · exact h
        · cases h
      exact ⟨.cut (l :: p) ns ds g, rfl, hn, List.suffix_refl _, hq, heq, hns⟩
    | data s => exact ⟨.node (l :: p) _, rfl, rfl, hns, hg, fun _ _ _ _ h => by cases h⟩
    | dname d s => exact ⟨.node (l :: p) _, rfl, rfl, hns, hg, fun _ _ _ _ h => by cases h⟩
    | empty => exact ⟨.node (l :: p) _, rfl, rfl, hns, hg, fun _ _ _ _ h => by cases h⟩
  | absent =>
    refine ⟨.absent p, rfl, hns, (z.look_absent_iff _).mp hg, ?_, hp⟩
    simp [Zone.closest, (under_iff _ _).mpr hp, hpres]
  | unknown => exact absurd hg (z.look_ne_unknown _)

theorem Zone.locate_spec (z : Zone) : ∀ q, z.apex <:+ q →
    ∃ L, locate z.look z.apex q = .ok L ∧ z.LocSpec q L := by
  intro q
  induction q with
  | nil =>
    intro h
    have ha : z.apex = [] := List.eq_nil_of_suffix_nil h
    obtain ⟨L, h1, h2⟩ := z.atApex_spec
    rw [ha] at h1 h2
    exact ⟨L, by simp [locate, ha, h1], h2⟩
  | cons l p ih =>
    intro hq
    by_cases heq : l :: p = z.apex
    · obtain ⟨L, h1, h2⟩ := z.atApex_spec
      refine ⟨L, by simp [locate, heq, h1], ?_⟩
      rw [heq]; exact h2
    have hp : z.apex <:+ p := suffix_cons_ne hq (Ne.symm heq)
    obtain ⟨Lp, hl, hs⟩ := ih hp
    have hne : p ≠ l :: p := (List.cons_ne_self l p).symm
    cases Lp with
    | outside => exact absurd hs id
    | node n nd =>
      obtain ⟨hn, hns, hlook, hcut⟩ := hs
      subst n
      obtain ⟨hpres, hnode⟩ := z.look_present hlook
      by_cases hd : ∃ d s, nd = .dname d s
      · obtain ⟨d, s, rfl⟩ := hd
        refine ⟨.dname p d, by simp [locate, heq, hl], s, ?_, ⟨hne, List.suffix_cons _ _, hp⟩, hns⟩
        rcases hnode with h | ⟨_, h⟩
        · exact h
        · cases h
      · have hnd : ∀ d s, nd ≠ .dname d s := fun d s h => hd ⟨d, s, h⟩
        have hstop : z.stops p = false := by
          rcases hnode with h | ⟨h, rfl⟩
          · unfold Zone.stops; rw [h]
            cases nd with
            | dname d' s' => exact absurd rfl (hnd d' s')
            | cut ns ds g =>
              by_cases ha : p = z.apex
              · simp [ha]
              · exact absurd rfl (hcut ha ns ds g)
            | data _ => rfl
            | empty => rfl
          · simp [Zone.stops, h]
        rw [locate_cons_node heq hl hnd]
        exact z.child_spec hq heq hp (z.noStop_cons hstop hns) hpres
    | absent c =>
      obtain ⟨hns, hpres, rfl, hc⟩ := hs
      have hnone : z.node p = none := by
        cases h : z.node p with
        | none => rfl
        | some nd => rw [z.node_present h] at hpres; cases hpres
      have hstop : z.stops p = false := by simp [Zone.stops, hnone]
      refine ⟨.absent (z.closest p), by simp [locate, heq, hl], z.noStop_cons hstop hns, ?_, ?_, hc⟩
      · cases h : z.presentB (l :: p) with
        | false => rfl
        | true => rw [z.presentB_mono (List.suffix_cons l p) h] at hpres; cases hpres
      · simp [Zone.closest, (under_iff _ _).mpr hp, hpres]
    | cut m ns ds g =>
      obtain ⟨h1, h2, h3, h4, h5⟩ := hs
      exact ⟨.cut m ns ds g, by simp [locate, heq, hl], h1, h2.trans (List.suffix_cons _ _), h3, h4, h5⟩
    | dname m d =>
      obtain ⟨s, h1, ⟨h2, h3, h4⟩, h5⟩ := hs
      refine ⟨.dname m d, by simp [locate, heq, hl], s, h1, ⟨?_, h3.trans (List.suffix_cons _ _), h4⟩, h5⟩
      intro hm; subst hm
      exact absurd h3.length_le (by simp)

/-! ## The walk's outcome is unique -/

theorem Zone.no_stop_between {z : Zone} {m1 m2 : Name} (h12 : m1 <:+ m2) (hne : m1 ≠ m2)
    (ha : z.apex <:+ m1) (hns : z.NoStop m2) (hs : z.stops m1 = true) : False := by
  rw [hns m1 ⟨hne, h12, ha⟩] at hs; cases hs

/-- Two stopping nodes on the same path, each with nothing stopping above it, are the same node. -/
theorem Zone.stop_unique {z : Zone} {q m1 m2 : Name} (h1 : m1 <:+ q) (h2 : m2 <:+ q) (ha1 : z.apex <:+ m1)
    (ha2 : z.apex <:+ m2) (hn1 : z.NoStop m1) (hn2 : z.NoStop m2) (hs1 : z.stops m1 = true)
    (hs2 : z.stops m2 = true) : m1 = m2 := by
  rcases List.suffix_or_suffix_of_suffix h1 h2 with h | h
  · by_cases hne : m1 = m2
    · exact hne
    · exact (z.no_stop_between h hne ha1 hn2 hs1).elim
  · by_cases hne : m1 = m2
    · exact hne
    · exact (z.no_stop_between h (Ne.symm hne) ha2 hn1 hs2).elim

theorem Zone.locSpec_unique (z : Zone) {q : Name} {L1 L2 : Loc} (h1 : z.LocSpec q L1) (h2 : z.LocSpec q L2) :
    L1 = L2 := by
  -- every stopping node strictly above `q` contradicts `NoStop q`; one at `q` contradicts the node's kind
  have cutAt : ∀ {m ns ds g}, z.BelowCut q m ns ds g → z.NoStop q → m = q := by
    intro m ns ds g ⟨hn, hm, ha, hne, _⟩ hns
    by_cases h : m = q
    · exact h
    · have := hns m ⟨h, hm, ha⟩
      rw [z.stops_cut hn hne] at this; cases this
  have dnameNo : ∀ {m d s}, z.DnameAbove q m d s → z.NoStop q → False := by
    intro m d s ⟨hn, hab, _⟩ hns
    exact absurd (hns m hab) (by simp [Zone.stops, hn])
  cases L1 with
  | outside => exact absurd h1 id
  | node n1 nd1 =>
    obtain ⟨rfl, hns, hl1, hc1⟩ := h1
    cases L2 with
    | outside => exact absurd h2 id
    | node n2 nd2 =>
      obtain ⟨rfl, _, hl2, _⟩ := h2
      rw [hl1] at hl2; cases hl2; rfl
    | absent c =>
      obtain ⟨_, hp, _⟩ := h2
      rw [(z.look_present hl1).1] at hp; cases hp
    | cut m ns ds g =>
      have hm := cutAt h2 hns; subst hm
      obtain ⟨hn, _, _, hne, _⟩ := h2
      rw [z.look_of_node hn] at hl1; cases hl1
      exact absurd rfl (hc1 hne ns ds g)
    | dname m d => obtain ⟨s, hd⟩ := h2; exact (dnameNo hd hns).elim
  | absent c1 =>
    obtain ⟨hns, hp1, rfl, _⟩ := h1
    cases L2 with
    | outside => exact absurd h2 id
    | node n2 nd2 =>
      obtain ⟨rfl, _, hl2, _⟩ := h2
      rw [(z.look_present hl2).1] at hp1; cases hp1
    | absent c2 => obtain ⟨_, _, rfl, _⟩ := h2; rfl
    | cut m ns ds g =>
      have hm := cutAt h2 hns; subst hm
      rw [z.node_present h2.1] at hp1; cases hp1
    | dname m d => obtain ⟨s, hd⟩ := h2; exact (dnameNo hd hns).elim
  | cut m1 ns1 ds1 g1 =>
    cases L2 with
    | outside => exact absurd h2 id
    | node n2 nd2 =>
      obtain ⟨rfl, hns, hl2, hc2⟩ := h2
      have hm := cutAt h1 hns; subst hm
      obtain ⟨hn, _, _, hne, _⟩ := h1
      rw [z.look_of_node hn] at hl2; cases hl2
      exact absurd rfl (hc2 hne ns1 ds1 g1)
    | absent c =>
      obtain ⟨hns, hp, _⟩ := h2
      have hm := cutAt h1 hns; subst hm
      rw [z.node_present h1.1] at hp; cases hp
    | cut m2 ns2 ds2 g2 =>
      obtain ⟨hn1, hm1, ha1, hne1, hns1⟩ := h1
      obtain ⟨hn2, hm2, ha2, hne2, hns2⟩ := h2
      have := z.stop_unique hm1 hm2 ha1 ha2 hns1 hns2 (z.stops_cut hn1 hne1) (z.stops_cut hn2 hne2)
      subst this
      rw [hn1] at hn2; cases hn2; rfl
    | dname m2 d =>
      obtain ⟨s, hn2, ⟨_, hm2, ha2⟩, hns2⟩ := h2
      obtain ⟨hn1, hm1, ha1, hne1, hns1⟩ := h1
      have := z.stop_unique hm1 hm2 ha1 ha2 hns1 hns2 (z.stops_cut hn1 hne1) (z.stops_dname hn2)
      subst this
      rw [hn1] at hn2; cases hn2
  | dname m1 d1 =>
    obtain ⟨s1, hn1, ⟨_, hm1, ha1⟩, hns1⟩ := h1
    cases L2 with
    | outside => exact absurd h2 id
    | node n2 nd2 =>
      obtain ⟨rfl, hns, _, _⟩ := h2
      exact (dnameNo ⟨hn1, ⟨‹_›, hm1, ha1⟩, hns1⟩ hns).elim
    | absent c =>
      obtain ⟨hns, _⟩ := h2
      exact (dnameNo ⟨hn1, ⟨‹_›, hm1, ha1⟩, hns1⟩ hns).elim
    | cut m2 ns2 ds2 g2 =>
      obtain ⟨hn2, hm2, ha2, hne2, hns2⟩ := h2
      have := z.stop_unique hm1 hm2 ha1 ha2 hns1 hns2 (z.stops_dname hn1) (z.stops_cut hn2 hne2)
      subst this
      rw [hn1] at hn2; cases hn2
    | dname m2 d2 =>
      obtain ⟨s2, hn2, ⟨_, hm2, ha2⟩, hns2⟩ := h2
      have := z.stop_unique hm1 hm2 ha1 ha2 hns1 hns2 (z.stops_dname hn1) (z.stops_dname hn2)
      subst this
      rw [hn1] at hn2; cases hn2; rfl

/-- The walk ends exactly where `LocSpec` says. -/
theorem Zone.locate_eq (z : Zone) {q : Name} (hq : z.apex <:+ q) {L : Loc} (h : z.LocSpec q L) :
    locate z.look z.apex q = .ok L := by
  obtain ⟨L', h1, h2⟩ := z.locate_spec q hq
  rw [h1, z.locSpec_unique h2 h]

/-! ## Complete data never makes the answer unknown -/

section Total
variable {look : Name → Fact Node} (ht : ∀ n, look n ≠ .unknown)
include ht

theorem atApex_total (apex : Name) : ∃ L, atApex look apex = .ok L := by
  obtain ⟨o, ho⟩ := get_total ht apex
  unfold atApex; rw [ho]; cases o <;> exact ⟨_, rfl⟩

theorem child_total (q p : Name) : ∃ L, child look q p = .ok L := by
  obtain ⟨o, ho⟩ := get_total ht q
  unfold child; rw [ho]
  cases o with
  | none => exact ⟨_, rfl⟩
  | some nd => cases nd <;> exact ⟨_, rfl⟩

theorem locate_total (apex : Name) : ∀ q, ∃ L, locate look apex q = .ok L := by
  intro q
  induction q with
  | nil =>
    unfold locate; split
    · exact atApex_total ht apex
    · exact ⟨_, rfl⟩
  | cons l p ih =>
    unfold locate; split
    · exact atApex_total ht apex
    · obtain ⟨L, hL⟩ := ih
      rw [hL]
      cases L with
      | node n nd =>
        cases nd with
        | dname d s => exact ⟨_, rfl⟩
        | data _ => exact child_total ht _ _
        | cut _ _ _ => exact child_total ht _ _
        | empty => exact child_total ht _ _
      | _ => exact ⟨_, rfl⟩

omit ht in
theorem collect_total (f : Name → M (List RRset)) (hf : ∀ t, ∃ a, f t = .ok a) :
    ∀ ts, ∃ a, collect f ts = .ok a := by
  intro ts
  induction ts with
  | nil => exact ⟨_, rfl⟩
  | cons t ts ih =>
    obtain ⟨a, ha⟩ := hf t
    obtain ⟨b, hb⟩ := ih
    exact ⟨a ++ b, by simp [collect, ha, hb]⟩

theorem addrsOf_total (apex t : Name) : ∃ a, addrsOf look apex t = .ok a := by
  unfold addrsOf; split
  · obtain ⟨L, hL⟩ := locate_total ht apex t
    rw [hL]
    cases L with
    | node n nd => cases nd <;> exact ⟨_, rfl⟩
    | _ => exact ⟨_, rfl⟩
  · exact ⟨_, rfl⟩

theorem siblingGlue_total (apex m t : Name) : ∃ a, siblingGlue look apex m t = .ok a := by
  unfold siblingGlue; split
  · obtain ⟨L, hL⟩ := locate_total ht apex t
    rw [hL]; cases L <;> exact ⟨_, rfl⟩
  · exact ⟨_, rfl⟩

theorem referral_total (apex m : Name) (ns : RRset) (g : List RRset) :
    ∃ ad req, referral look apex m ns g = .ok (.done .noerror false [] [ns] ad req) := by
  obtain ⟨sib, hs⟩ := collect_total _ (siblingGlue_total ht apex m) (targets ns)
  refine ⟨(g.filter fun s => isAddr s && (targets ns).contains s.owner && under s.owner m) ++ sib,
    (g.filter fun s => isAddr s && (targets ns).contains s.owner && under s.owner m).length, ?_⟩
  unfold referral
  rw [hs]

theorem exact_total (apex : Name) (soa : RRset) (any : AnyResponse) (q : Name) (qtype : Nat)
    (sets : List RRset) : ∃ o, exact look apex soa any q qtype sets = .ok o := by
  unfold exact
  split
  · split <;> exact ⟨_, rfl⟩
  · split
    · obtain ⟨a, ha⟩ := collect_total _ (addrsOf_total ht apex) (targets ‹_›)
      rw [ha]; exact ⟨_, rfl⟩
    · split
      · split <;> exact ⟨_, rfl⟩
      · exact ⟨_, rfl⟩

theorem step_total (apex : Name) (soa : RRset) (any : AnyResponse) (q : Name) (qtype : Nat) :
    ∃ o, step look apex soa any q qtype = .ok o := by
  obtain ⟨L, hL⟩ := locate_total ht apex q
  unfold step; rw [hL]
  cases L with
  | outside => exact ⟨_, rfl⟩
  | cut m ns ds g =>
    simp only
    split
    · split <;> exact ⟨_, rfl⟩
    · obtain ⟨ad, req, h⟩ := referral_total ht apex m ns g
      exact ⟨_, h⟩
  | dname m d =>
    simp only
    split
    · split <;> exact ⟨_, rfl⟩
    · exact ⟨_, rfl⟩
  | node n nd => exact exact_total ht _ _ _ _ _ _
  | absent c =>
    simp only
    obtain ⟨o, ho⟩ := get_total ht (wild c)
    rw [ho]
    cases o with
    | none => exact ⟨_, rfl⟩
    | some nd =>
      cases nd with
      | cut ns ds g => obtain ⟨ad, req, h⟩ := referral_total ht apex _ ns g; exact ⟨_, h⟩
      | _ => exact exact_total ht _ _ _ _ _ _

theorem chase_total (apex : Name) (soa : RRset) (any : AnyResponse) (qtype : Nat) :
    ∀ f seen acc q, ∃ r, chase look apex soa any qtype f seen acc q = .ok r := by
  intro f
  induction f with
  | zero => intro _ _ _; exact ⟨_, rfl⟩
  | succ f ih =>
    intro seen acc q
    obtain ⟨o, ho⟩ := step_total ht apex soa any q qtype
    unfold chase; rw [ho]
    cases o with
    | done rc aa an au ad req => exact ⟨_, rfl⟩
    | restart an t =>
      simp only
      split
      · exact ⟨_, rfl⟩
      · exact ih _ _ _

end Total

theorem answer_never_unknown (z : Zone) (q : Request) (any : AnyResponse) (n : Name) :
    answer z q any ≠ .unknown n := by
  unfold answer answerWith
  split
  · simp
  · obtain ⟨r, hr⟩ := chase_total z.look_ne_unknown z.apex z.soa any q.qtype chainFuel [] [] q.qname
    rw [hr]; simp

/-! ## Steps and chains -/

theorem chainFuel_succ : chainFuel = (chainFuel - 1) + 1 := by
  have : 0 < chainFuel := Nat.pow_pos (by decide)
  omega

theorem exact_out {look : Name → Fact Node} {apex : Name} {soa : RRset} {any : AnyResponse} {q : Name}
    {qtype : Nat} {sets : List RRset} {o : Out} (h : exact look apex soa any q qtype sets = .ok o) :
    o = nodata soa ∨ (∃ an ad, o = .done .noerror true an [] ad 0 ∧ an ≠ []) ∨
      (∃ an t, o = .restart an t ∧ an ≠ []) := by
  unfold exact at h
  split at h
  · split at h
    · cases h; exact Or.inl rfl
    · cases h; refine Or.inr (Or.inl ⟨_, _, rfl, ?_⟩)
      rename_i hs
      cases any with
      | hinfo => simp only [anySets]; split <;> simp
      | oneRrset =>
        cases sets with
        | nil => exact absurd rfl hs
        | cons _ _ => simp [anySets]
      | all => simpa [anySets] using hs
  · split at h
    · split at h
      · cases h; exact Or.inr (Or.inl ⟨_, _, rfl, by simp⟩)
      · cases h
    · split at h
      · split at h
        · cases h; exact Or.inr (Or.inr ⟨_, _, rfl, by simp⟩)
        · cases h; exact Or.inr (Or.inl ⟨_, _, rfl, by simp⟩)
      · cases h; exact Or.inl rfl

theorem step_restart_ne {look : Name → Fact Node} {apex : Name} {soa : RRset} {any : AnyResponse} {q : Name}
    {qtype : Nat} {an : List RRset} {t : Name} (h : step look apex soa any q qtype = .ok (.restart an t)) :
    an ≠ [] := by
  unfold step at h
  split at h
  · cases h
  · cases h
  · split at h
    · split at h <;> cases h
    · obtain ⟨_, _, h'⟩ := referral_total' h; cases h'
  · split at h
    · dsimp only at h
      split at h
      · cases h
      · cases h; simp
    · cases h
  · rcases exact_out h with h' | ⟨_, _, h', _⟩ | ⟨_, _, h', hne⟩ <;> cases h'
    exact hne
  · split at h
    · cases h
    · cases h
    · obtain ⟨_, _, h'⟩ := referral_total' h; cases h'
    · rcases exact_out h with h' | ⟨_, _, h', _⟩ | ⟨_, _, h', hne⟩ <;> cases h'
      exact hne
where
  referral_total' {look apex m ns g o} (h : referral look apex m ns g = .ok o) :
      ∃ ad req, o = .done .noerror false [] [ns] ad req := by
    unfold referral at h
    split at h
    · cases h; exact ⟨_, _, rfl⟩
    · cases h

theorem referral_out {look : Name → Fact Node} {apex m : Name} {ns : RRset} {g : List RRset} {o : Out}
    (h : referral look apex m ns g = .ok o) : ∃ ad req, o = .done .noerror false [] [ns] ad req :=
  step_restart_ne.referral_total' h

/-- A chain only adds to the answer it was given. -/
theorem chase_acc {look : Name → Fact Node} {apex : Name} {soa : RRset} {any : AnyResponse} {qtype : Nat} :
    ∀ f seen acc q r, chase look apex soa any qtype f seen acc q = .ok r → acc <+: r.answer := by
  intro f
  induction f with
  | zero => intro _ acc _ r h; simp [chase] at h; subst h; exact List.prefix_refl _
  | succ f ih =>
    intro seen acc q r h
    unfold chase at h
    split at h
    · cases h
    · cases h; exact List.prefix_append _ _
    · split at h
      · cases h; exact List.prefix_append _ _
      · exact (List.prefix_append acc _).trans (ih _ _ _ _ h)

/-- How a chain ends: a step's finished response after the answers gathered so far, a stop at a repeated name
or a name outside the zone, or running out of steps. -/
theorem chase_cases {look : Name → Fact Node} {apex : Name} {soa : RRset} {any : AnyResponse} {qtype : Nat} :
    ∀ f seen acc q r, chase look apex soa any qtype f seen acc q = .ok r →
      (∃ q' rc aa an au ad req acc', step look apex soa any q' qtype = .ok (.done rc aa an au ad req) ∧
        r = ⟨rc, aa || !acc'.isEmpty, addNew acc' an, au, ad, req⟩) ∨
      (r.rcode = .noerror ∧ r.aa = true ∧ r.authority = [] ∧ r.answer ≠ []) ∨
      (r.rcode = .servfail ∧ r.authority = []) := by
  intro f
  induction f with
  | zero => intro _ _ _ r h; simp [chase] at h; subst h; exact Or.inr (Or.inr ⟨rfl, rfl⟩)
  | succ f ih =>
    intro seen acc q r h
    unfold chase at h
    split at h
    · cases h
    · rename_i rc aa an au ad req hs
      cases h
      exact Or.inl ⟨q, rc, aa, an, au, ad, req, acc, hs, rfl⟩
    · rename_i an t hs
      have hne := step_restart_ne hs
      split at h
      · cases h; exact Or.inr (Or.inl ⟨rfl, rfl, rfl, addNew_ne_nil hne⟩)
      · exact ih _ _ _ _ h

/-- The answer when the question's first step finishes. -/
theorem answer_done (z : Zone) (q : Request) (any : AnyResponse) (hq : z.apex <:+ q.qname)
    {rc : Rcode} {aa : Bool} {an au ad : List RRset} {req : Nat}
    (h : step z.look z.apex z.soa any q.qname q.qtype = .ok (.done rc aa an au ad req)) :
    answer z q any = .response ⟨rc, aa, an, au, ad, req⟩ := by
  unfold answer answerWith
  rw [chainFuel_succ]
  simp only [(under_iff _ _).mpr hq, not_true_eq_false, ↓reduceIte]
  simp [chase, h]

/-- The answer when the question's first step is a CNAME: it begins with that CNAME. -/
theorem answer_restart (z : Zone) (q : Request) (any : AnyResponse) (hq : z.apex <:+ q.qname)
    {an : List RRset} {t : Name} (h : step z.look z.apex z.soa any q.qname q.qtype = .ok (.restart an t)) :
    ∃ r, answer z q any = .response r ∧ an <+: r.answer := by
  obtain ⟨r, hr⟩ := chase_total z.look_ne_unknown z.apex z.soa any q.qtype chainFuel [] [] q.qname
  refine ⟨r, by simp [answer, answerWith, (under_iff _ _).mpr hq, hr], ?_⟩
  rw [chainFuel_succ] at hr
  unfold chase at hr
  rw [h] at hr
  simp only at hr
  split at hr
  · cases hr; simp
  · simpa using chase_acc _ _ _ _ _ hr

/-! ## The headline theorems for complete zones -/

theorem get_none_iff {look : Name → Fact Node} {n : Name} : get look n = .ok none ↔ look n = .absent := by
  unfold get; cases look n <;> simp

theorem get_some_iff {look : Name → Fact Node} {n : Name} {nd : Node} :
    get look n = .ok (some nd) ↔ look n = .present nd := by
  unfold get; cases look n <;> simp

theorem Zone.closest_under (z : Zone) : ∀ q, z.apex <:+ z.closest q := by
  intro q
  induction q with
  | nil => exact List.suffix_refl _
  | cons l p ih =>
    unfold Zone.closest
    split
    · split
      · exact (under_iff _ _).mp ‹_›
      · exact ih
    · exact List.suffix_refl _

theorem Zone.wild_under {z : Zone} {c : Name} (h : z.apex <:+ c) : z.apex <:+ wild c :=
  h.trans (List.suffix_cons _ _)

/-- What a finished step puts in authority for a negative answer: the SOA, with its negative TTL. -/
theorem step_done_soa {look : Name → Fact Node} {apex : Name} {soa : RRset} {any : AnyResponse} {q : Name}
    {qtype : Nat} {rc : Rcode} {aa : Bool} {an au ad : List RRset} {req : Nat}
    (h : step look apex soa any q qtype = .ok (.done rc aa an au ad req)) :
    (rc = .nxdomain → au = [negSoa soa]) ∧ (rc = .noerror → an = [] → aa = true → au = [negSoa soa]) := by
  have ofExact : ∀ {sets}, exact look apex soa any q qtype sets = .ok (.done rc aa an au ad req) →
      (rc = .nxdomain → au = [negSoa soa]) ∧ (rc = .noerror → an = [] → aa = true → au = [negSoa soa]) := by
    intro sets he
    rcases exact_out he with h' | ⟨an', ad', h', hne⟩ | ⟨_, _, h', _⟩
    · simp only [nodata, Out.done.injEq] at h'
      obtain ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩ := h'
      exact ⟨(fun h => by cases h), fun _ _ _ => rfl⟩
    · simp only [Out.done.injEq] at h'
      obtain ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩ := h'
      exact ⟨(fun h => by cases h), fun _ h => absurd h hne⟩
    · cases h'
  have ofReferral : ∀ {m ns g}, referral look apex m ns g = .ok (.done rc aa an au ad req) →
      (rc = .nxdomain → au = [negSoa soa]) ∧ (rc = .noerror → an = [] → aa = true → au = [negSoa soa]) := by
    intro m ns g hr
    obtain ⟨_, _, h'⟩ := referral_out hr
    simp only [Out.done.injEq] at h'
    obtain ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩ := h'
    exact ⟨(fun h => by cases h), fun _ _ h => by cases h⟩
  unfold step at h
  split at h
  · cases h
  · cases h; exact ⟨(fun h => by cases h), fun h => by cases h⟩
  · split at h
    · split at h
      · cases h; exact ⟨(fun h => by cases h), fun _ h => by cases h⟩
      · cases h; exact ⟨(fun h => by cases h), fun _ _ _ => rfl⟩
    · exact ofReferral h
  · split at h
    · (try dsimp only at h)
      split at h
      · cases h; exact ⟨(fun h => by cases h), fun h => by cases h⟩
      · cases h
    · cases h; exact ⟨(fun h => by cases h), fun _ h => by cases h⟩
  · exact ofExact h
  · split at h
    · cases h
    · cases h; exact ⟨fun _ => rfl, (fun h => by cases h)⟩
    · exact ofReferral h
    · exact ofExact h

/-- NXDOMAIN with an empty answer exactly when nothing above the name diverts the walk, no node is at or
below the name, and no wildcard is at its closest encloser (RFC 1034 §4.3.2, RFC 4592, RFC 8020). -/
theorem nxdomain_iff (z : Zone) (q : Request) (any : AnyResponse) (hq : z.apex <:+ q.qname) :
    (∃ r, answer z q any = .response r ∧ r.rcode = .nxdomain ∧ r.answer = []) ↔
      (z.NoStop q.qname ∧ z.presentB q.qname = false ∧ z.presentB (wild (z.closest q.qname)) = false) := by
  constructor
  · rintro ⟨r, hr, hrc, han⟩
    obtain ⟨L, hL, hs⟩ := z.locate_spec q.qname hq
    obtain ⟨o, ho⟩ := step_total z.look_ne_unknown z.apex z.soa any q.qname q.qtype
    cases o with
    | restart an t =>
      obtain ⟨r', hr', hp⟩ := answer_restart z q any hq ho
      rw [hr] at hr'; cases hr'
      rw [han] at hp; exact absurd (List.eq_nil_of_prefix_nil hp) (step_restart_ne ho)
    | done rc aa an au ad req =>
      rw [answer_done z q any hq ho] at hr; cases hr
      simp only at hrc han; subst hrc; subst han
      unfold step at ho; rw [hL] at ho
      cases L with
      | outside => exact absurd hs id
      | cut m ns ds g =>
        simp only at ho
        split at ho
        · split at ho
          · cases ho
          · simp [nodata] at ho
        · obtain ⟨_, _, h'⟩ := referral_out ho; cases h'
      | dname m d =>
        simp only at ho
        split at ho
        · (try dsimp only at ho); split at ho <;> cases ho
        · cases ho
      | node n nd =>
        simp only at ho
        rcases exact_out ho with h' | ⟨_, _, h', _⟩ | ⟨_, _, h', _⟩
        · simp [nodata] at h'
        · cases h'
        · cases h'
      | absent c =>
        obtain ⟨hns, hp, rfl, _⟩ := hs
        simp only at ho
        refine ⟨hns, hp, ?_⟩
        cases hg : get z.look (wild (z.closest q.qname)) with
        | error e => rw [hg] at ho; cases ho
        | ok o =>
          rw [hg] at ho
          cases o with
          | none => exact (z.look_absent_iff _).mp (get_none_iff.mp hg)
          | some nd =>
            cases nd with
            | cut ns ds g => obtain ⟨_, _, h'⟩ := referral_out ho; cases h'
            | _ =>
              simp only at ho
              rcases exact_out ho with h' | ⟨_, _, h', _⟩ | ⟨_, _, h', _⟩
              · simp [nodata] at h'
              · cases h'
              · cases h'
  · rintro ⟨hns, hp, hw⟩
    have hL := z.locate_eq hq (L := .absent (z.closest q.qname)) ⟨hns, hp, rfl, z.closest_under _⟩
    have hg : get z.look (wild (z.closest q.qname)) = .ok none :=
      get_none_iff.mpr ((z.look_absent_iff _).mpr hw)
    have hs : step z.look z.apex z.soa any q.qname q.qtype =
        .ok (.done .nxdomain true [] [negSoa z.soa] [] 0) := by
      unfold step; rw [hL]; simp only; rw [hg]
    exact ⟨_, answer_done z q any hq hs, rfl, rfl⟩

/-- An empty non-terminal answers NODATA: no records, the SOA in authority (RFC 8020, RFC 2308 §2.2). -/
theorem ent_is_nodata (z : Zone) (q : Request) (any : AnyResponse) (hq : z.apex <:+ q.qname)
    (hns : z.NoStop q.qname) (hnone : z.node q.qname = none) (hpres : z.presentB q.qname = true) :
    answer z q any = .response ⟨.noerror, true, [], [negSoa z.soa], [], 0⟩ := by
  have hlook : z.look q.qname = .present .empty := by simp [Zone.look, hnone, hpres]
  have hL := z.locate_eq hq (L := .node q.qname .empty) ⟨rfl, hns, hlook, fun _ _ _ _ h => by cases h⟩
  have hs : step z.look z.apex z.soa any q.qname q.qtype = .ok (nodata z.soa) := by
    unfold step; rw [hL]; simp only [nodeSets]; unfold exact
    split
    · simp
    · simp
  exact answer_done z q any hq hs

/-- A response is a referral (NOERROR, no answer, AA=0) exactly when the name is at or below a cut that the
walk reaches, other than a DS question at the cut itself, or matches a wildcard that is a cut. -/
theorem referral_iff_below_cut (z : Zone) (q : Request) (any : AnyResponse) (hq : z.apex <:+ q.qname) :
    (∃ r, answer z q any = .response r ∧ r.rcode = .noerror ∧ r.answer = [] ∧ r.aa = false) ↔
      ((∃ m ns ds g, z.BelowCut q.qname m ns ds g ∧ ¬ (m = q.qname ∧ q.qtype = 43)) ∨
        (z.NoStop q.qname ∧ z.presentB q.qname = false ∧
          ∃ ns ds g, z.node (wild (z.closest q.qname)) = some (.cut ns ds g))) := by
  constructor
  · rintro ⟨r, hr, hrc, han, haa⟩
    obtain ⟨L, hL, hs⟩ := z.locate_spec q.qname hq
    obtain ⟨o, ho⟩ := step_total z.look_ne_unknown z.apex z.soa any q.qname q.qtype
    cases o with
    | restart an t =>
      obtain ⟨r', hr', hp⟩ := answer_restart z q any hq ho
      rw [hr] at hr'; cases hr'
      rw [han] at hp; exact absurd (List.eq_nil_of_prefix_nil hp) (step_restart_ne ho)
    | done rc aa an au ad req =>
      rw [answer_done z q any hq ho] at hr; cases hr
      simp only at hrc han haa; subst hrc; subst han; subst haa
      unfold step at ho; rw [hL] at ho
      cases L with
      | outside => exact absurd hs id
      | cut m ns ds g =>
        simp only at ho
        split at ho
        · split at ho
          · cases ho
          · simp [nodata] at ho
        · rename_i hds; exact Or.inl ⟨m, ns, ds, g, hs, hds⟩
      | dname m d =>
        simp only at ho
        split at ho
        · (try dsimp only at ho); split at ho <;> cases ho
        · cases ho
      | node n nd =>
        simp only at ho
        rcases exact_out ho with h' | ⟨_, _, h', _⟩ | ⟨_, _, h', _⟩
        · simp [nodata] at h'
        · cases h'
        · cases h'
      | absent c =>
        obtain ⟨hns, hp, rfl, _⟩ := hs
        simp only at ho
        cases hg : get z.look (wild (z.closest q.qname)) with
        | error e => rw [hg] at ho; cases ho
        | ok o =>
          rw [hg] at ho
          cases o with
          | none => cases ho
          | some nd =>
            cases nd with
            | cut ns ds g =>
              refine Or.inr ⟨hns, hp, ns, ds, g, ?_⟩
              obtain ⟨_, h⟩ := z.look_present (get_some_iff.mp hg)
              rcases h with h | ⟨_, h⟩
              · exact h
              · cases h
            | _ =>
              simp only at ho
              rcases exact_out ho with h' | ⟨_, _, h', _⟩ | ⟨_, _, h', _⟩
              · simp [nodata] at h'
              · cases h'
              · cases h'
  · rintro (⟨m, ns, ds, g, hb, hds⟩ | ⟨hns, hp, ns, ds, g, hw⟩)
    · have hL := z.locate_eq hq (L := .cut m ns ds g) hb
      obtain ⟨ad, req, hr⟩ := referral_total z.look_ne_unknown z.apex m ns g
      have hs : step z.look z.apex z.soa any q.qname q.qtype = .ok (.done .noerror false [] [ns] ad req) := by
        unfold step; rw [hL]; simp only [hds, ↓reduceIte, hr]
      exact ⟨_, answer_done z q any hq hs, rfl, rfl, rfl⟩
    · have hL := z.locate_eq hq (L := .absent (z.closest q.qname)) ⟨hns, hp, rfl, z.closest_under _⟩
      have hg : get z.look (wild (z.closest q.qname)) = .ok (some (.cut ns ds g)) :=
        get_some_iff.mpr (z.look_of_node hw)
      obtain ⟨ad, req, hr⟩ := referral_total z.look_ne_unknown z.apex (wild (z.closest q.qname)) ns g
      have hs : step z.look z.apex z.soa any q.qname q.qtype = .ok (.done .noerror false [] [ns] ad req) := by
        unfold step; rw [hL]; simp only; rw [hg]; exact hr
      exact ⟨_, answer_done z q any hq hs, rfl, rfl, rfl⟩

/-- A referral is not authoritative: AA=0, no answer, and the cut's NS set in authority (RFC 1034 §4.3.2
step 3b). -/
theorem referral_aa_false (z : Zone) (q : Request) (any : AnyResponse) (hq : z.apex <:+ q.qname)
    {m : Name} {ns : RRset} {ds : Option RRset} {g : List RRset} (hb : z.BelowCut q.qname m ns ds g)
    (hds : ¬ (m = q.qname ∧ q.qtype = 43)) :
    ∃ r, answer z q any = .response r ∧ r.aa = false ∧ r.answer = [] ∧ r.authority = [ns] ∧
      r.rcode = .noerror := by
  have hL := z.locate_eq hq (L := .cut m ns ds g) hb
  obtain ⟨ad, req, hr⟩ := referral_total z.look_ne_unknown z.apex m ns g
  have hs : step z.look z.apex z.soa any q.qname q.qtype = .ok (.done .noerror false [] [ns] ad req) := by
    unfold step; rw [hL]; simp only [hds, ↓reduceIte, hr]
  exact ⟨_, answer_done z q any hq hs, rfl, rfl, rfl, rfl⟩

/-- A negative answer (NXDOMAIN, or NODATA: NOERROR with no answer and AA=1) carries the zone's SOA in
authority (RFC 2308 §3). -/
theorem negative_has_soa (z : Zone) (q : Request) (any : AnyResponse) {r : Response}
    (h : answer z q any = .response r)
    (hneg : r.rcode = .nxdomain ∨ (r.rcode = .noerror ∧ r.answer = [] ∧ r.aa = true)) :
    negSoa z.soa ∈ r.authority := by
  unfold answer answerWith at h
  split at h
  · cases h; simp at hneg
  · split at h
    · rename_i r' hc
      cases h
      rcases chase_cases _ _ _ _ _ hc with ⟨q', rc, aa, an, au, ad, req, acc', hs, rfl⟩ | h' | h'
      · obtain ⟨h1, h2⟩ := step_done_soa hs
        rcases hneg with hn | ⟨hn, ha, hb⟩
        · rw [h1 hn]; simp
        · simp only [addNew, List.append_eq_nil_iff] at ha
          obtain ⟨rfl, ha⟩ := ha
          simp only [List.any_nil, Bool.not_false] at ha
          rw [List.filter_eq_self.mpr (fun _ _ => rfl)] at ha
          subst ha
          simp only [List.isEmpty_nil, Bool.not_true, Bool.or_false] at hb
          rw [h2 hn rfl hb]; simp
      · obtain ⟨h1, _, _, h4⟩ := h'
        rcases hneg with hn | ⟨_, ha, _⟩
        · rw [h1] at hn; cases hn
        · exact absurd ha h4
      · obtain ⟨h1, _⟩ := h'
        rcases hneg with hn | ⟨hn, _⟩ <;> rw [h1] at hn <;> cases hn
    · cases h

/-- The SOA of a negative answer has TTL min(SOA TTL, MINIMUM) (RFC 2308 §3, §5). -/
theorem neg_ttl_min (z : Zone) (q : Request) (any : AnyResponse) {r : Response}
    {mn rn : Name} {serial refresh retry expire minimum : Nat}
    (hsoa : z.soa.rdata = [.soa mn rn serial refresh retry expire minimum])
    (h : answer z q any = .response r)
    (hneg : r.rcode = .nxdomain ∨ (r.rcode = .noerror ∧ r.answer = [] ∧ r.aa = true)) :
    ∃ s ∈ r.authority, s.owner = z.soa.owner ∧ s.rtype = z.soa.rtype ∧ s.ttl = min z.soa.ttl minimum :=
  ⟨negSoa z.soa, negative_has_soa z q any h hneg, rfl, rfl, by simp [negSoa, negTtl, hsoa]⟩

/-- A node at QNAME answers with its own RRset, whatever wildcard the zone holds: the node blocks it
(RFC 4592 §2.2.2). -/
theorem wildcard_blocked_by_node (z : Zone) (q : Request) (any : AnyResponse) (hq : z.apex <:+ q.qname)
    (hns : z.NoStop q.qname) {sets : List RRset} {s : RRset} (hn : z.node q.qname = some (.data sets))
    (ht : q.qtype ≠ 255) (hs : sets.find? (·.rtype == q.qtype) = some s) :
    ∃ r, answer z q any = .response r ∧ r.rcode = .noerror ∧ r.aa = true ∧
      r.answer = [withOwner q.qname s] := by
  have hL := z.locate_eq hq (L := .node q.qname (.data sets))
    ⟨rfl, hns, z.look_of_node hn, fun _ _ _ _ h => by cases h⟩
  obtain ⟨add, ha⟩ := collect_total _ (addrsOf_total z.look_ne_unknown z.apex) (targets s)
  have hst : step z.look z.apex z.soa any q.qname q.qtype =
      .ok (.done .noerror true [withOwner q.qname s] [] add 0) := by
    unfold step; rw [hL]; simp only [nodeSets]; unfold exact
    simp only [ht, ↓reduceIte, hs, ha]
  exact ⟨_, answer_done z q any hq hst, rfl, rfl, rfl⟩

/-- Below a DNAME, the answer is YXDOMAIN with just the DNAME exactly when the substituted name would pass
255 octets (RFC 6672 §2.2). -/
theorem dname_yx_iff_long (z : Zone) (q : Request) (any : AnyResponse) (hq : z.apex <:+ q.qname)
    {m : Name} {d : RRset} {s : List RRset} {dt : Name} (hd : z.DnameAbove q.qname m d s)
    (ht : dnameTarget d = some dt) :
    (∃ r, answer z q any = .response r ∧ r.rcode = .yxdomain ∧ r.answer = [d]) ↔
      255 < Name.wireLen (q.qname.take (q.qname.length - m.length) ++ dt) := by
  have hL := z.locate_eq hq (L := .dname m d) ⟨s, hd⟩
  by_cases hlong : 255 < Name.wireLen (q.qname.take (q.qname.length - m.length) ++ dt)
  · have hs : step z.look z.apex z.soa any q.qname q.qtype = .ok (.done .yxdomain true [d] [] [] 0) := by
      unfold step; rw [hL]; simp only [ht]; (try dsimp only); simp only [hlong, ↓reduceIte]
    exact ⟨fun _ => hlong, fun _ => ⟨_, answer_done z q any hq hs, rfl, rfl⟩⟩
  · have hs : step z.look z.apex z.soa any q.qname q.qtype =
        .ok (.restart [d, ⟨q.qname, 5, d.ttl, [.cname (q.qname.take (q.qname.length - m.length) ++ dt)]⟩]
          (q.qname.take (q.qname.length - m.length) ++ dt)) := by
      unfold step; rw [hL]; simp only [ht]; (try dsimp only); simp only [hlong, ↓reduceIte]
    refine ⟨fun ⟨r, hr, _, han⟩ => ?_, fun h => absurd h hlong⟩
    obtain ⟨r', hr', hp⟩ := answer_restart z q any hq hs
    rw [hr] at hr'; cases hr'
    rw [han] at hp
    exact absurd hp.length_le (by simp)

/-! ## Every owner is in the zone -/

/-- Owners match the names their nodes are held at, and the SOA is at the apex. -/
def Zone.WF (z : Zone) : Prop :=
  z.soa.owner = z.apex ∧ ∀ n nd, z.node n = some nd →
    match nd with
    | .data sets => ∀ s ∈ sets, s.owner = n
    | .dname d sets => d.owner = n ∧ ∀ s ∈ sets, s.owner = n
    | .cut ns ds _ => ns.owner = n ∧ ∀ s ∈ ds, s.owner = n
    | .empty => True

def OwnersIn (apex : Name) (l : List RRset) : Prop := ∀ s ∈ l, apex <:+ s.owner

theorem collect_owners {apex : Name} {f : Name → M (List RRset)}
    (hf : ∀ t a, f t = .ok a → OwnersIn apex a) : ∀ ts b, collect f ts = .ok b → OwnersIn apex b := by
  intro ts
  induction ts with
  | nil => intro b h; cases h; intro s hs; cases hs
  | cons t ts ih =>
    intro b h
    unfold collect at h
    cases ha : f t with
    | error e => simp only [ha] at h; cases h
    | ok a =>
      cases hc : collect f ts with
      | error e => simp only [ha, hc] at h; cases h
      | ok c =>
        simp only [ha, hc, Except.ok.injEq] at h
        subst h
        intro s hs
        rcases List.mem_append.mp hs with hs | hs
        · exact hf t a ha s hs
        · exact ih c hc s hs

theorem siblingGlue_owners {look : Name → Fact Node} {apex m t : Name} {a : List RRset}
    (h : siblingGlue look apex m t = .ok a) : OwnersIn apex a := by
  unfold siblingGlue at h
  split at h
  · rename_i hc
    simp only [Bool.and_eq_true, Bool.not_eq_true'] at hc
    split at h
    · cases h
      intro s hs
      simp only [List.mem_filter, Bool.and_eq_true, beq_iff_eq] at hs
      rw [hs.2.2]; exact (under_iff _ _).mp hc.1
    · cases h; intro s hs; cases hs
  · cases h; intro s hs; cases hs

theorem referral_owners {look : Name → Fact Node} {apex m : Name} {ns : RRset} {g : List RRset}
    {rc : Rcode} {aa : Bool} {an au ad : List RRset} {req : Nat} (hm : apex <:+ m) (hns : apex <:+ ns.owner)
    (h : referral look apex m ns g = .ok (.done rc aa an au ad req)) : OwnersIn apex (an ++ au ++ ad) := by
  unfold referral at h
  split at h
  · rename_i sib hs
    cases h
    intro s hs'
    simp only [List.nil_append, List.mem_append, List.mem_singleton, List.mem_filter, Bool.and_eq_true] at hs'
    rcases hs' with rfl | ⟨_, _, hu⟩ | hs'
    · exact hns
    · exact hm.trans ((under_iff _ _).mp hu)
    · exact collect_owners (fun t a h => siblingGlue_owners h) _ _ hs s hs'
  · cases h

/-- The owners a step writes: for a finished step, every section; for a CNAME, the answer so far. -/
def outOwners (apex : Name) : Out → Prop
  | .done _ _ an au ad _ => OwnersIn apex (an ++ au ++ ad)
  | .restart an _ => OwnersIn apex an

theorem exact_owners {look : Name → Fact Node} {apex : Name} {soa : RRset} {any : AnyResponse} {q : Name}
    {qtype : Nat} {sets : List RRset} {o : Out} (hq : apex <:+ q) (hsoa : apex <:+ soa.owner)
    (hadd : ∀ t a, addrsOf look apex t = .ok a → OwnersIn apex a)
    (h : exact look apex soa any q qtype sets = .ok o) : outOwners apex o := by
  unfold exact at h
  split at h
  · split at h
    · cases h; intro s hs; simp [negSoa] at hs; subst hs; exact hsoa
    · cases h
      intro s hs
      simp only [List.append_nil, anySets] at hs
      cases any with
      | hinfo =>
        dsimp only at hs
        split at hs <;> (simp only [List.mem_singleton] at hs; subst hs; exact hq)
      | oneRrset => obtain ⟨x, _, rfl⟩ := List.mem_map.mp hs; exact hq
      | all => obtain ⟨x, _, rfl⟩ := List.mem_map.mp hs; exact hq
  · split at h
    · split at h
      · rename_i add hc
        cases h
        intro s hs
        simp only [List.append_nil, List.singleton_append, List.mem_cons] at hs
        rcases hs with rfl | hs
        · exact hq
        · exact collect_owners hadd _ _ hc s hs
      · cases h
    · split at h
      · split at h
        · cases h; intro s hs; simp [withOwner] at hs; subst hs; exact hq
        · cases h; intro s hs; simp [withOwner] at hs; subst hs; exact hq
      · cases h; intro s hs; simp [negSoa] at hs; subst hs; exact hsoa

theorem Zone.nodeSets_owner (z : Zone) (hwf : z.WF) {n : Name} {nd : Node} (hn : z.node n = some nd) :
    ∀ s ∈ nodeSets nd, s.owner = n := by
  have hw := hwf.2 n nd hn
  cases nd with
  | data sets => exact hw
  | dname d sets =>
    intro s hs
    simp only [nodeSets, List.mem_cons] at hs
    rcases hs with rfl | hs
    · exact hw.1
    · exact hw.2 s hs
  | cut ns ds g =>
    intro s hs
    simp only [nodeSets, List.mem_cons] at hs
    rcases hs with rfl | hs
    · exact hw.1
    · exact hw.2 s (by simpa using hs)
  | empty => intro s hs; cases hs

theorem Zone.addrsOf_owners (z : Zone) (hwf : z.WF) (t : Name) (a : List RRset)
    (h : addrsOf z.look z.apex t = .ok a) : OwnersIn z.apex a := by
  unfold addrsOf at h
  split at h
  · rename_i ht
    obtain ⟨L, hL, hs⟩ := z.locate_spec t ((under_iff _ _).mp ht)
    rw [hL] at h
    cases L with
    | node n nd =>
      obtain ⟨rfl, _, hlook, _⟩ := hs
      cases h
      obtain ⟨_, hn⟩ := z.look_present hlook
      intro s hs
      rcases hn with hn | ⟨_, rfl⟩
      · rw [z.nodeSets_owner hwf hn s (List.mem_filter.mp hs).1]; exact (under_iff _ _).mp ht
      · simp [nodeSets] at hs
    | _ => cases h; intro s hs; cases hs
  · cases h; intro s hs; cases hs

theorem Zone.step_owners (z : Zone) (hwf : z.WF) (any : AnyResponse) (q : Name) (qtype : Nat)
    (hq : z.apex <:+ q) (o : Out) (h : step z.look z.apex z.soa any q qtype = .ok o) : outOwners z.apex o := by
  have hsoa : z.apex <:+ z.soa.owner := by rw [hwf.1]; exact List.suffix_refl _
  have hadd := z.addrsOf_owners hwf
  obtain ⟨L, hL, hs⟩ := z.locate_spec q hq
  unfold step at h; rw [hL] at h
  cases L with
  | outside => exact absurd hs id
  | cut m ns ds g =>
    obtain ⟨hn, _, hm, _, _⟩ := hs
    have hw := hwf.2 m _ hn
    simp only at hw h
    split at h
    · split at h
      · rename_i s0 hds
        cases h
        intro s hs'
        simp at hs'; subst hs'
        rw [hw.2 s (by simp)]; exact hm
      · cases h; intro s hs'; simp [negSoa] at hs'; subst hs'; exact hsoa
    · obtain ⟨ad, req, rfl⟩ := referral_out h
      exact referral_owners hm (by rw [hw.1]; exact hm) h
  | dname m d =>
    obtain ⟨s0, hn, ⟨_, _, hm⟩, _⟩ := hs
    have hw := hwf.2 m _ hn
    simp only at hw h
    split at h
    · (try dsimp only at h)
      split at h
      · cases h; intro s hs'; simp at hs'; subst hs'; rw [hw.1]; exact hm
      · cases h; intro s hs'; simp at hs'
        rcases hs' with rfl | rfl
        · rw [hw.1]; exact hm
        · exact hq
    · cases h; intro s hs'; simp at hs'; subst hs'; rw [hw.1]; exact hm
  | node n nd => exact exact_owners hq hsoa hadd h
  | absent c =>
    obtain ⟨_, _, _, hc⟩ := hs
    simp only at h
    split at h
    · cases h
    · cases h; intro s hs'; simp [negSoa] at hs'; subst hs'; exact hsoa
    · rename_i ns ds g hg
      obtain ⟨_, hn⟩ := z.look_present (get_some_iff.mp hg)
      rcases hn with hn | ⟨_, hn⟩
      · have hw := hwf.2 _ _ hn
        simp only at hw
        obtain ⟨ad, req, rfl⟩ := referral_out h
        exact referral_owners (z.wild_under hc) (by rw [hw.1]; exact z.wild_under hc) h
      · cases hn
    · exact exact_owners hq hsoa hadd h

theorem Zone.chase_owners (z : Zone) (hwf : z.WF) (any : AnyResponse) (qtype : Nat) :
    ∀ f seen acc q r, OwnersIn z.apex acc → z.apex <:+ q →
      chase z.look z.apex z.soa any qtype f seen acc q = .ok r →
      OwnersIn z.apex (r.answer ++ r.authority ++ r.additional) := by
  intro f
  induction f with
  | zero => intro _ acc _ r hacc _ h; cases h; simpa using hacc
  | succ f ih =>
    intro seen acc q r hacc hq h
    unfold chase at h
    split at h
    · cases h
    · rename_i rc aa an au ad req hs
      cases h
      have := z.step_owners hwf any q qtype hq _ hs
      intro s hs'
      simp only [List.append_assoc, List.mem_append] at hs'
      rcases hs' with hs' | hs'
      · rcases mem_addNew hs' with h' | h'
        · exact hacc s h'
        · exact this s (by simp only [List.append_assoc, List.mem_append]; exact Or.inl h')
      · exact this s (by simp only [List.append_assoc, List.mem_append]; exact Or.inr hs')
    · rename_i an t hs
      have hown := z.step_owners hwf any q qtype hq _ hs
      have hacc' : OwnersIn z.apex (addNew acc an) := by
        intro s hs'; rcases mem_addNew hs' with h' | h'
        · exact hacc s h'
        · exact hown s h'
      split at h
      · cases h; simpa using hacc'
      · rename_i hc
        simp only [not_or, Decidable.not_not] at hc
        exact ih _ _ _ _ hacc' ((under_iff _ _).mp hc.2) h

/-- Every RRset in every section of an answer has its owner at or below the apex. -/
theorem answer_in_zone (z : Zone) (hwf : z.WF) (q : Request) (any : AnyResponse) {r : Response}
    (h : answer z q any = .response r) : ∀ s ∈ r.answer ++ r.authority ++ r.additional, z.apex <:+ s.owner := by
  unfold answer answerWith at h
  split at h
  · cases h; intro s hs; simp at hs
  · rename_i hu
    split at h
    · rename_i r' hc
      cases h
      exact z.chase_owners hwf any q.qtype chainFuel [] [] q.qname _ (fun s hs => by cases hs)
        ((under_iff _ _).mp (by simpa using hu)) hc
    · cases h

/-! ## The builder

A zone is built from its RRsets and its delegations. `build` checks every rule and fails with the first one
broken; `builder_rejects_iff` says it fails exactly when the rules, stated as propositions, do not all hold. -/

structure Delegation where
  child : Name
  nsTtl : Nat
  targets : List Name
  glue : List RRset
  ds : Option (Nat × List RData)
deriving DecidableEq, Repr

structure Spec where
  apex : Name
  soaTtl : Nat
  soa : RData
  sets : List RRset
  delegations : List Delegation
deriving Repr

inductive ZoneError where
  | outOfZone (owner : Name)
  /-- RFC 1034 §3.6.2, RFC 2181 §10.1. -/
  | cnameWithOtherData (owner : Name)
  /-- RFC 1912 §2.4. -/
  | cnameAtApex
  /-- RFC 6672 §2.4: DNAME is a singleton type, so an owner holds one DNAME record. -/
  | twoDnames (owner : Name)
  /-- RFC 6672 §2.4. -/
  | dataBelowDname (owner : Name)
  /-- Only glue lies below a cut. -/
  | dataBelowCut (owner cut : Name)
  /-- RFC 4035 §2.4: DS RRsets appear only at delegation points, which a spec holds apart from its RRsets. -/
  | dsNotAtCut (owner : Name)
  /-- RFC 9471 §3.1. -/
  | missingInDomainGlue (child ns : Name)
  /-- RFC 2181 §10.3. -/
  | targetIsAlias (owner target : Name)
  /-- RFC 2181 §5.2. -/
  | rrsetTtlsDiffer (owner : Name) (rtype : Nat)
  /-- RFC 2181 §8. -/
  | ttlTooLarge (owner : Name) (ttl : Nat)
  /-- RFC 1034 §4.2.1. -/
  | missingApexNs
deriving DecidableEq, Repr

/-- `a` is strictly below `b`. -/
def strictly (a b : Name) : Bool := under a b && a != b

/-- RFC 2181 §8: TTLs are below 2^31. -/
def maxTtl : Nat := 2147483648

def nsTargets (d : Delegation) : List Name := d.targets

/-! ### The rules -/

def Spec.R1 (sp : Spec) : Prop :=
  (∀ s ∈ sp.sets, sp.apex <:+ s.owner) ∧ ∀ d ∈ sp.delegations, sp.apex <:+ d.child ∧ d.child ≠ sp.apex
def Spec.R2 (sp : Spec) : Prop :=
  ∀ s ∈ sp.sets, s.rtype = 5 → ∀ s' ∈ sp.sets, s'.owner = s.owner → s'.rtype = 5
def Spec.R3 (sp : Spec) : Prop := ∀ s ∈ sp.sets, s.rtype = 5 → s.owner ≠ sp.apex
def Spec.R4 (sp : Spec) : Prop :=
  ∀ s ∈ sp.sets, s.rtype = 39 →
    (∀ s' ∈ sp.sets, ¬ (s.owner <:+ s'.owner ∧ s'.owner ≠ s.owner)) ∧
      ∀ d ∈ sp.delegations, ¬ (s.owner <:+ d.child ∧ d.child ≠ s.owner)
def Spec.R5 (sp : Spec) : Prop :=
  ∀ d ∈ sp.delegations, (∀ s ∈ sp.sets, ¬ d.child <:+ s.owner) ∧
    ∀ d' ∈ sp.delegations, d' ≠ d → ¬ d.child <:+ d'.child
def Spec.R6 (sp : Spec) : Prop :=
  ∀ d ∈ sp.delegations, ∀ t ∈ d.targets, d.child <:+ t → ∃ g ∈ d.glue, g.owner = t ∧ isAddr g = true
def Spec.R7 (sp : Spec) : Prop :=
  (∀ s ∈ sp.sets, ∀ t ∈ targets s, ∀ s' ∈ sp.sets, s'.owner = t → s'.rtype ≠ 5) ∧
    ∀ d ∈ sp.delegations, ∀ t ∈ d.targets, ∀ s' ∈ sp.sets, s'.owner = t → s'.rtype ≠ 5
def Spec.R8 (sp : Spec) : Prop :=
  ∀ s ∈ sp.sets, ∀ s' ∈ sp.sets, s.owner = s'.owner → s.rtype = s'.rtype → s.ttl = s'.ttl
def Spec.R9 (sp : Spec) : Prop :=
  sp.soaTtl < maxTtl ∧ (∀ s ∈ sp.sets, s.ttl < maxTtl) ∧
    ∀ d ∈ sp.delegations, d.nsTtl < maxTtl ∧ (∀ g ∈ d.glue, g.ttl < maxTtl) ∧ ∀ x ∈ d.ds, x.1 < maxTtl
def Spec.R10 (sp : Spec) : Prop := ∃ s ∈ sp.sets, s.owner = sp.apex ∧ s.rtype = 2
def Spec.R11 (sp : Spec) : Prop := ∀ s ∈ sp.sets, s.rtype ≠ 43
/-- One DNAME record at an owner: every DNAME record there is the same. -/
def Spec.R12 (sp : Spec) : Prop :=
  ∀ s ∈ sp.sets, s.rtype = 39 → ∀ s' ∈ sp.sets, s'.owner = s.owner → s'.rtype = 39 →
    ∀ r ∈ s.rdata, ∀ r' ∈ s'.rdata, r = r'

/-- Every rule of `ZoneError` holds. -/
def Spec.Valid (sp : Spec) : Prop :=
  sp.R1 ∧ sp.R2 ∧ sp.R3 ∧ sp.R4 ∧ sp.R5 ∧ sp.R6 ∧ sp.R7 ∧ sp.R8 ∧ sp.R9 ∧ sp.R10 ∧ sp.R11 ∧ sp.R12

/-! ### The checks, as an implementation computes them -/

def Spec.ok1 (sp : Spec) : Bool :=
  sp.sets.all (fun s => under s.owner sp.apex) &&
    sp.delegations.all fun d => under d.child sp.apex && d.child != sp.apex
def Spec.ok2 (sp : Spec) : Bool :=
  sp.sets.all fun s => s.rtype != 5 || sp.sets.all fun s' => s'.owner != s.owner || s'.rtype == 5
def Spec.ok3 (sp : Spec) : Bool := sp.sets.all fun s => s.rtype != 5 || s.owner != sp.apex
def Spec.ok4 (sp : Spec) : Bool :=
  sp.sets.all fun s => s.rtype != 39 ||
    (sp.sets.all (fun s' => !strictly s'.owner s.owner) && sp.delegations.all fun d => !strictly d.child s.owner)
def Spec.ok5 (sp : Spec) : Bool :=
  sp.delegations.all fun d => sp.sets.all (fun s => !under s.owner d.child) &&
    sp.delegations.all fun d' => d' == d || !under d'.child d.child
def Spec.ok6 (sp : Spec) : Bool :=
  sp.delegations.all fun d => d.targets.all fun t =>
    !under t d.child || d.glue.any fun g => g.owner == t && isAddr g
def Spec.ok7 (sp : Spec) : Bool :=
  let alias (t : Name) := sp.sets.any fun s' => s'.owner == t && s'.rtype == 5
  sp.sets.all (fun s => (targets s).all fun t => !alias t) &&
    sp.delegations.all fun d => d.targets.all fun t => !alias t
def Spec.ok8 (sp : Spec) : Bool :=
  sp.sets.all fun s => sp.sets.all fun s' => s.owner != s'.owner || s.rtype != s'.rtype || s.ttl == s'.ttl
def Spec.ok9 (sp : Spec) : Bool :=
  decide (sp.soaTtl < maxTtl) && sp.sets.all (fun s => decide (s.ttl < maxTtl)) &&
    sp.delegations.all fun d => decide (d.nsTtl < maxTtl) && d.glue.all (fun g => decide (g.ttl < maxTtl)) &&
      d.ds.all fun x => decide (x.1 < maxTtl)
def Spec.ok10 (sp : Spec) : Bool := sp.sets.any fun s => s.owner == sp.apex && s.rtype == 2
def Spec.ok11 (sp : Spec) : Bool := sp.sets.all fun s => s.rtype != 43
def Spec.ok12 (sp : Spec) : Bool :=
  sp.sets.all fun s => s.rtype != 39 || sp.sets.all fun s' => s'.owner != s.owner || s'.rtype != 39 ||
    s.rdata.all fun r => s'.rdata.all (· == r)

theorem Spec.ok1_iff (sp : Spec) : sp.ok1 = true ↔ sp.R1 := by
  simp [Spec.ok1, Spec.R1, under_iff]

theorem Spec.ok2_iff (sp : Spec) : sp.ok2 = true ↔ sp.R2 := by
  simp only [Spec.ok2, Spec.R2, List.all_eq_true, Bool.or_eq_true, bne_iff_ne, ne_eq, beq_iff_eq]
  constructor
  · intro h s hs h5 s' hs' ho
    rcases h s hs with h' | h'
    · exact absurd h5 h'
    · rcases h' s' hs' with h'' | h''
      · exact absurd ho h''
      · exact h''
  · intro h s hs
    by_cases h5 : s.rtype = 5
    · exact Or.inr fun s' hs' => by
        by_cases ho : s'.owner = s.owner
        · exact Or.inr (h s hs h5 s' hs' ho)
        · exact Or.inl ho
    · exact Or.inl h5

theorem Spec.ok3_iff (sp : Spec) : sp.ok3 = true ↔ sp.R3 := by
  simp only [Spec.ok3, Spec.R3, List.all_eq_true, Bool.or_eq_true, bne_iff_ne, ne_eq]
  constructor
  · intro h s hs h5; rcases h s hs with h' | h'
    · exact absurd h5 h'
    · exact h'
  · intro h s hs
    by_cases h5 : s.rtype = 5
    · exact Or.inr (h s hs h5)
    · exact Or.inl h5

theorem Spec.ok4_iff (sp : Spec) : sp.ok4 = true ↔ sp.R4 := by
  simp only [Spec.ok4, Spec.R4, strictly, List.all_eq_true, Bool.or_eq_true, bne_iff_ne, ne_eq,
    Bool.and_eq_true, Bool.not_eq_true', Bool.and_eq_false_imp, under_iff]
  constructor
  · intro h s hs h39
    rcases h s hs with h' | ⟨h1, h2⟩
    · exact absurd h39 h'
    · refine ⟨fun s' hs' ⟨ha, hb⟩ => ?_, fun d hd ⟨ha, hb⟩ => ?_⟩
      · have := h1 s' hs' ha; simp [hb] at this
      · have := h2 d hd ha; simp [hb] at this
  · intro h s hs
    by_cases h39 : s.rtype = 39
    · obtain ⟨h1, h2⟩ := h s hs h39
      refine Or.inr ⟨fun s' hs' ha => ?_, fun d hd ha => ?_⟩
      · simpa using fun hb => h1 s' hs' ⟨ha, hb⟩
      · simpa using fun hb => h2 d hd ⟨ha, hb⟩
    · exact Or.inl h39

theorem Spec.ok5_iff (sp : Spec) : sp.ok5 = true ↔ sp.R5 := by
  simp only [Spec.ok5, Spec.R5, List.all_eq_true, Bool.and_eq_true, Bool.not_eq_true', Bool.or_eq_true,
    beq_iff_eq]
  constructor
  · intro h d hd
    obtain ⟨h1, h2⟩ := h d hd
    refine ⟨fun s hs hu => ?_, fun d' hd' hne hu => ?_⟩
    · have := h1 s hs; rw [(under_iff _ _).mpr hu] at this; cases this
    · rcases h2 d' hd' with h' | h'
      · exact hne h'
      · rw [(under_iff _ _).mpr hu] at h'; cases h'
  · intro h d hd
    obtain ⟨h1, h2⟩ := h d hd
    refine ⟨fun s hs => ?_, fun d' hd' => ?_⟩
    · cases hu : under s.owner d.child with
      | false => rfl
      | true => exact absurd ((under_iff _ _).mp hu) (h1 s hs)
    · by_cases hne : d' = d
      · exact Or.inl hne
      · right
        cases hu : under d'.child d.child with
        | false => rfl
        | true => exact absurd ((under_iff _ _).mp hu) (h2 d' hd' hne)

theorem Spec.ok6_iff (sp : Spec) : sp.ok6 = true ↔ sp.R6 := by
  simp only [Spec.ok6, Spec.R6, List.all_eq_true, Bool.or_eq_true, Bool.not_eq_true', List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq]
  constructor
  · intro h d hd t ht hu
    rcases h d hd t ht with h' | h'
    · rw [(under_iff _ _).mpr hu] at h'; cases h'
    · exact h'
  · intro h d hd t ht
    cases hu : under t d.child with
    | false => exact Or.inl rfl
    | true => exact Or.inr (h d hd t ht ((under_iff _ _).mp hu))

theorem Spec.ok7_iff (sp : Spec) : sp.ok7 = true ↔ sp.R7 := by
  simp only [Spec.ok7, Spec.R7, List.all_eq_true, Bool.and_eq_true, Bool.not_eq_true', List.any_eq_false,
    beq_iff_eq, not_and]

theorem Spec.ok8_iff (sp : Spec) : sp.ok8 = true ↔ sp.R8 := by
  simp only [Spec.ok8, Spec.R8, List.all_eq_true, Bool.or_eq_true, bne_iff_ne, ne_eq, beq_iff_eq]
  constructor
  · intro h s hs s' hs' ho ht
    rcases h s hs s' hs' with (h' | h') | h'
    · exact absurd ho h'
    · exact absurd ht h'
    · exact h'
  · intro h s hs s' hs'
    by_cases ho : s.owner = s'.owner
    · by_cases ht : s.rtype = s'.rtype
      · exact Or.inr (h s hs s' hs' ho ht)
      · exact Or.inl (Or.inr ht)
    · exact Or.inl (Or.inl ho)

theorem Spec.ok9_iff (sp : Spec) : sp.ok9 = true ↔ sp.R9 := by
  simp [Spec.ok9, Spec.R9, Option.all_eq_true, and_assoc]

theorem Spec.ok10_iff (sp : Spec) : sp.ok10 = true ↔ sp.R10 := by
  simp [Spec.ok10, Spec.R10]

theorem Spec.ok11_iff (sp : Spec) : sp.ok11 = true ↔ sp.R11 := by
  simp [Spec.ok11, Spec.R11]

theorem Spec.ok12_iff (sp : Spec) : sp.ok12 = true ↔ sp.R12 := by
  simp only [Spec.ok12, Spec.R12, List.all_eq_true, Bool.or_eq_true, bne_iff_ne, ne_eq, beq_iff_eq]
  constructor
  · intro h s hs h39 s' hs' ho h39' r hr r' hr'
    rcases h s hs with h1 | h1
    · exact absurd h39 h1
    · rcases h1 s' hs' with (h2 | h2) | h2
      · exact absurd ho h2
      · exact absurd h39' h2
      · exact (h2 r hr r' hr').symm
  · intro h s hs
    by_cases h39 : s.rtype = 39
    · refine Or.inr fun s' hs' => ?_
      by_cases ho : s'.owner = s.owner
      · by_cases h39' : s'.rtype = 39
        · exact Or.inr fun r hr r' hr' => (h s hs h39 s' hs' ho h39' r hr r' hr').symm
        · exact Or.inl (Or.inr h39')
      · exact Or.inl (Or.inl ho)
    · exact Or.inl h39

/-! ### Assembling the nodes -/

def unionR (a b : List RData) : List RData := b.foldl (fun acc r => if acc.contains r then acc else acc ++ [r]) a

/-- Adds an RRset, merging it into one of the same type; duplicate records collapse (RFC 2181 §5). -/
def addSet (s : RRset) : List RRset → List RRset
  | [] => [s]
  | x :: xs => if x.rtype == s.rtype then { x with rdata := unionR x.rdata s.rdata } :: xs else x :: addSet s xs

def mergeSets (l : List RRset) : List RRset :=
  l.foldl (fun acc s => addSet { s with rdata := unionR [] s.rdata } acc) []

def dedupNames (l : List Name) : List Name := l.foldl (fun acc n => if acc.contains n then acc else acc ++ [n]) []

def nodeAt (sets : List RRset) : Node :=
  match sets.find? (·.rtype == 39) with
  | some d => .dname d (sets.filter (·.rtype != 39))
  | none => .data sets

def Spec.soaSet (sp : Spec) : RRset := ⟨sp.apex, 6, sp.soaTtl, [sp.soa]⟩

def Spec.setsAt (sp : Spec) (o : Name) : List RRset := mergeSets (sp.sets.filter (·.owner == o))

def cutNode (d : Delegation) : Name × Node :=
  (d.child, .cut ⟨d.child, 2, d.nsTtl, d.targets.map .ns⟩ (d.ds.map fun x => ⟨d.child, 43, x.1, x.2⟩) d.glue)

def Spec.assemble (sp : Spec) : Zone :=
  let owners := (dedupNames (sp.sets.map (·.owner))).filter (· != sp.apex)
  ⟨sp.apex, sp.soaSet, (sp.apex, nodeAt (mergeSets (sp.soaSet :: sp.sets.filter (·.owner == sp.apex)))) ::
    owners.map (fun o => (o, nodeAt (sp.setsAt o))) ++ sp.delegations.map cutNode⟩

/-- The first rule broken, as its error, naming what breaks it. -/
def Spec.firstError (sp : Spec) : ZoneError :=
  let alias (t : Name) := sp.sets.any fun s' => s'.owner == t && s'.rtype == 5
  let dnames := (sp.sets.filter (·.rtype == 39)).map (·.owner)
  let belowDname (o : Name) := dnames.any (strictly o ·)
  if !sp.ok1 then
    match sp.sets.find? (fun s => !under s.owner sp.apex) with
    | some s => .outOfZone s.owner
    | none => .outOfZone ((sp.delegations.find? fun d => !(under d.child sp.apex && d.child != sp.apex)).map
        (·.child) |>.getD [])
  else if !sp.ok3 then .cnameAtApex
  else if !sp.ok2 then
    .cnameWithOtherData ((sp.sets.find? fun s => s.rtype == 5 &&
      sp.sets.any fun s' => s'.owner == s.owner && s'.rtype != 5).map (·.owner) |>.getD [])
  else if !sp.ok12 then
    .twoDnames ((sp.sets.find? fun s => s.rtype == 39 && !(sp.sets.all fun s' =>
      s'.owner != s.owner || s'.rtype != 39 || s.rdata.all fun r => s'.rdata.all (· == r))).map (·.owner)
      |>.getD [])
  else if !sp.ok4 then
    match sp.sets.find? (belowDname ·.owner) with
    | some s => .dataBelowDname s.owner
    | none => .dataBelowDname ((sp.delegations.find? (belowDname ·.child)).map (·.child) |>.getD [])
  else if !sp.ok5 then
    match sp.delegations.find? fun d => !(sp.sets.all fun s => !under s.owner d.child) with
    | some d => .dataBelowCut ((sp.sets.find? fun s => under s.owner d.child).map (·.owner) |>.getD []) d.child
    | none =>
      match sp.delegations.find? fun d => sp.delegations.any fun d' => d' != d && under d'.child d.child with
      | some d => .dataBelowCut ((sp.delegations.find? fun d' => d' != d && under d'.child d.child).map (·.child)
          |>.getD []) d.child
      | none => .dataBelowCut [] []
  else if !sp.ok11 then .dsNotAtCut ((sp.sets.find? (·.rtype == 43)).map (·.owner) |>.getD [])
  else if !sp.ok6 then
    let missing (d : Delegation) (t : Name) := under t d.child && !(d.glue.any fun g => g.owner == t && isAddr g)
    match sp.delegations.find? fun d => d.targets.any (missing d) with
    | some d => .missingInDomainGlue d.child ((d.targets.find? (missing d)).getD [])
    | none => .missingInDomainGlue [] []
  else if !sp.ok7 then
    match sp.sets.find? fun s => (targets s).any alias with
    | some s => .targetIsAlias s.owner (((targets s).find? alias).getD [])
    | none =>
      match sp.delegations.find? fun d => d.targets.any alias with
      | some d => .targetIsAlias d.child ((d.targets.find? alias).getD [])
      | none => .targetIsAlias [] []
  else if !sp.ok8 then
    match sp.sets.find? fun s => sp.sets.any fun s' => s.owner == s'.owner && s.rtype == s'.rtype && s.ttl != s'.ttl
    with
    | some s => .rrsetTtlsDiffer s.owner s.rtype
    | none => .rrsetTtlsDiffer [] 0
  else if !sp.ok9 then
    let tooLarge (s : RRset) := maxTtl ≤ s.ttl
    let delegationSets (d : Delegation) : List RRset :=
      ⟨d.child, 2, d.nsTtl, []⟩ :: d.glue ++ (d.ds.map fun x => [⟨d.child, 43, x.1, []⟩]).getD []
    if maxTtl ≤ sp.soaTtl then .ttlTooLarge sp.apex sp.soaTtl else
    match (sp.sets ++ sp.delegations.flatMap delegationSets).find? tooLarge with
    | some s => .ttlTooLarge s.owner s.ttl
    | none => .ttlTooLarge [] 0
  else .missingApexNs

def Spec.okAll (sp : Spec) : Bool :=
  sp.ok1 && sp.ok2 && sp.ok3 && sp.ok4 && sp.ok5 && sp.ok6 && sp.ok7 && sp.ok8 && sp.ok9 && sp.ok10 && sp.ok11 &&
    sp.ok12

def build (sp : Spec) : Except ZoneError Zone :=
  if sp.okAll then .ok sp.assemble else .error sp.firstError

/-- The builder rejects a zone exactly when one of the rules fails, and accepts it exactly when all hold. -/
theorem builder_rejects_iff (sp : Spec) : (∃ e, build sp = .error e) ↔ ¬ sp.Valid := by
  have hv : sp.okAll = true ↔ sp.Valid := by
    simp only [Spec.okAll, Bool.and_eq_true, Spec.ok1_iff, Spec.ok2_iff, Spec.ok3_iff, Spec.ok4_iff,
      Spec.ok5_iff, Spec.ok6_iff, Spec.ok7_iff, Spec.ok8_iff, Spec.ok9_iff, Spec.ok10_iff, Spec.ok11_iff,
      Spec.ok12_iff,
      Spec.Valid, and_assoc]
  unfold build
  constructor
  · rintro ⟨e, he⟩ hval
    simp only [hv.mpr hval, ↓reduceIte] at he; cases he
  · intro hval
    have : sp.okAll = false := by
      cases h : sp.okAll with
      | false => rfl
      | true => exact absurd (hv.mp h) hval
    exact ⟨_, by rw [this]; rfl⟩

theorem addSet_owner {o : Name} {s : RRset} (hs : s.owner = o) :
    ∀ acc, (∀ x ∈ acc, x.owner = o) → ∀ x ∈ addSet s acc, x.owner = o := by
  intro acc
  induction acc with
  | nil => intro _ x hx; simp [addSet] at hx; rw [hx, hs]
  | cons y ys ih =>
    intro h x hx
    simp only [addSet] at hx
    split at hx
    · simp at hx
      rcases hx with rfl | hx
      · exact h y (by simp)
      · exact h x (by simp [hx])
    · simp at hx
      rcases hx with rfl | hx
      · exact h x (by simp)
      · exact ih (fun z hz => h z (by simp [hz])) x hx

theorem mergeSets_owner {o : Name} (l : List RRset) (hl : ∀ s ∈ l, s.owner = o) :
    ∀ x ∈ mergeSets l, x.owner = o := by
  unfold mergeSets
  suffices ∀ acc, (∀ x ∈ acc, x.owner = o) →
      ∀ x ∈ l.foldl (fun acc s => addSet { s with rdata := unionR [] s.rdata } acc) acc, x.owner = o from
    this [] (by simp)
  induction l with
  | nil => intro acc h; simpa using h
  | cons s ss ih =>
    intro acc h
    simp only [List.foldl_cons]
    exact ih (fun s' hs' => hl s' (by simp [hs'])) _
      (addSet_owner (by simp [hl s (by simp)]) acc h)

theorem nodeAt_owner {o : Name} {sets : List RRset} (h : ∀ s ∈ sets, s.owner = o) :
    match nodeAt sets with
    | .data sets => ∀ s ∈ sets, s.owner = o
    | .dname d sets => d.owner = o ∧ ∀ s ∈ sets, s.owner = o
    | .cut ns ds _ => ns.owner = o ∧ ∀ s ∈ ds, s.owner = o
    | .empty => True := by
  cases hf : sets.find? (·.rtype == 39) with
  | some d =>
    simp only [nodeAt, hf]
    exact ⟨h d (List.mem_of_find?_eq_some hf), fun s hs => h s (List.mem_filter.mp hs).1⟩
  | none => simp only [nodeAt, hf]; exact h

/-- What the builder makes is well formed: every owner is the name its node is held at. -/
theorem build_wf (sp : Spec) (z : Zone) (h : build sp = .ok z) : z.WF := by
  unfold build at h
  split at h
  · cases h
    refine ⟨rfl, fun n nd hn => ?_⟩
    have hm := lookup_mem hn
    simp only [Spec.assemble, List.mem_cons, List.mem_append] at hm
    rcases hm with (hm | hm) | hm
    · simp only [Prod.mk.injEq] at hm
      obtain ⟨rfl, rfl⟩ := hm
      apply nodeAt_owner
      apply mergeSets_owner
      intro s hs
      simp only [List.mem_cons, List.mem_filter, beq_iff_eq] at hs
      rcases hs with rfl | ⟨_, h⟩
      · rfl
      · exact h
    · obtain ⟨o, _, ho⟩ := List.mem_map.mp hm
      simp only [Prod.mk.injEq] at ho
      obtain ⟨rfl, rfl⟩ := ho
      apply nodeAt_owner
      apply mergeSets_owner
      intro s hs
      exact beq_iff_eq.mp (List.mem_filter.mp hs).2
    · obtain ⟨d, _, hd⟩ := List.mem_map.mp hm
      simp only [cutNode, Prod.mk.injEq] at hd
      obtain ⟨rfl, rfl⟩ := hd
      refine ⟨rfl, fun s hs => ?_⟩
      cases hds : d.ds with
      | none => simp [hds] at hs
      | some x => simp [hds] at hs; rw [← hs]
  · cases h

/-! ## Unfolding `answerWith` -/

theorem answerWith_outside {look : Name → Fact Node} {apex : Name} {soa : RRset} {any : AnyResponse}
    {req : Request} (hu : ¬ under req.qname apex = true) :
    answerWith look apex soa any req = .response ⟨.refused, false, [], [], [], 0⟩ := by
  unfold answerWith
  rw [ite_eq_left_of_eq_true _ _ (eq_true hu)]

theorem answerWith_inside {look : Name → Fact Node} {apex : Name} {soa : RRset} {any : AnyResponse}
    {req : Request} (hu : under req.qname apex = true) :
    answerWith look apex soa any req =
      match chase look apex soa any req.qtype chainFuel [] [] req.qname with
      | .ok r => .response r
      | .error n => .unknown n := by
  unfold answerWith
  rw [ite_eq_right_of_eq_false _ _ (eq_false (by simp [hu]))]

/-- The walk's outcome in a complete zone, read off a computed result. -/
theorem Zone.spec_of_locate (z : Zone) {q : Name} (hq : z.apex <:+ q) {L : Loc}
    (h : locate z.look z.apex q = .ok L) : z.LocSpec q L := by
  obtain ⟨L', h1, h2⟩ := z.locate_spec q hq
  rw [h1] at h; cases h; exact h2

end Dns.Zone
