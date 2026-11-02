/-
  The recursive resolver as `step : State → Event → State × List Out`, over correct servers that answer
  with `Zone.answer`.

  A resolution starts from a cached answer, or from the deepest cached cut at or above the name (the root hints
  when there is none), asks that cut's servers one at a time, follows referrals that go strictly down toward
  the name, tries the next server when a query is lost or a referral is bizarre, and gives up with
  SERVFAIL when no server is left (RFC 9520 §3.1) or the work bound is spent (RFC 1034 §5.3.3). Referral NS
  sets are cached at rank non-authoritative authority and their glue at rank glue; final answers at rank
  authoritative answer (RFC 2181 §5.4.1).

  `resolve_correct`: whatever is lost, the answer is the hierarchy's answer to the question, or SERVFAIL; with
  nothing lost and enough work it is the hierarchy's answer. `glue_never_served`: every RRset in an answer is in
  the answer section of the authoritative server's answer to that question. `measure_decreases` and
  `resolve_terminates`: every step spends work or finishes, so a resolution always ends.

  CNAME and DNAME targets outside the answering zone are not chased, glueless NS addresses are not resolved,
  and servers are named by the NS targets with no addresses; the hierarchy's answer is defined the same way.

  Rust: `services::dns::resolver::{Resolver, resolution}`.
-/
import Dns.Zone
import Dns.Cache

namespace Dns.Resolver
open Dns.Zone Dns.Cache

/-! ## The hierarchy -/

/-- The servers: one complete zone per apex, each served by every name its NS sets list. -/
abbrev Net := List Zone

def zoneAt (net : Net) (m : Name) : Option Zone := net.find? (·.apex == m)

def servfail : Response := ⟨.servfail, false, [], [], [], 0⟩

/-- A correct server's reply: its zone's answer. -/
def reply (any : AnyResponse) (z : Zone) (q : Request) : Response :=
  match answer z q any with
  | .response r => r
  | .unknown _ => servfail

/-- The NS set of a referral: NOERROR, AA=0, no answer, and one NS set in authority. -/
def cutOf (r : Response) : Option RRset :=
  match r.authority with
  | [ns] => if r.rcode = .noerror ∧ r.aa = false ∧ r.answer = [] ∧ ns.rtype = 2 then some ns else none
  | _ => none

/-- A referral the resolver follows from the cut `c`: strictly below it, at or above the name,
and naming servers. -/
def descends (c : Name) (q : Request) (ns : RRset) : Bool :=
  strictly ns.owner c && under q.qname ns.owner && !(targets ns).isEmpty

theorem descends_len {c : Name} {q : Request} {ns : RRset} (h : descends c q ns = true) :
    c.length < ns.owner.length ∧ ns.owner.length ≤ q.qname.length := by
  simp only [descends, strictly, Bool.and_eq_true, bne_iff_ne, ne_eq] at h
  obtain ⟨⟨⟨h1, h2⟩, h3⟩, _⟩ := h
  have s1 := (under_iff _ _).mp h1
  have s3 := (under_iff _ _).mp h3
  refine ⟨?_, s3.length_le⟩
  rcases Nat.lt_or_ge c.length ns.owner.length with h | h
  · exact h
  · exact absurd (s1.eq_of_length (Nat.le_antisymm s1.length_le h)).symm h2

theorem zoneAt_apex {net : Net} {m : Name} {z : Zone} (h : zoneAt net m = some z) : z.apex = m ∧ z ∈ net := by
  have := List.find?_some h
  simp only [beq_iff_eq] at this
  exact ⟨this, List.mem_of_find?_eq_some h⟩

/-- The hierarchy's answer from the zone `z` down: the first answer that is not a referral; SERVFAIL for a
referral the resolver would not follow or one to a cut with no servers. -/
def follow (net : Net) (any : AnyResponse) (q : Request) (z : Zone) : Response :=
  match cutOf (reply any z q) with
  | none => reply any z q
  | some ns =>
    if _hd : descends z.apex q ns = true then
      match _hz : zoneAt net ns.owner with
      | some z' => follow net any q z'
      | none => servfail
    else servfail
termination_by q.qname.length + 1 - z.apex.length
decreasing_by
  have h1 := descends_len _hd
  have h2 := congrArg List.length (zoneAt_apex _hz).1
  simp_wf
  omega

/-- The hierarchy's answer to `q`: from the root zone down. -/
def spec (net : Net) (any : AnyResponse) (q : Request) : Response :=
  match zoneAt net [] with
  | some root => follow net any q root
  | none => servfail

/-! ## The resolver -/

inductive Item where
  | cut (ns : RRset)
  | glue (s : RRset)
  | answer (q : Request) (r : Response)
deriving DecidableEq, Repr

/-- A cached item and the rank it was stored at. -/
structure Stored where
  rank : Rank
  item : Item
deriving DecidableEq, Repr

/-- A resolution in progress: the question, the cut whose servers it asks, the servers not yet given up on (the
first is being asked), and the work left. -/
structure Res where
  q : Request
  cut : Name
  servers : List Name
  work : Nat
deriving DecidableEq, Repr

structure State where
  cache : List Stored
  res : Option Res
deriving DecidableEq, Repr

structure Config where
  hints : List Name
  /-- Queries one resolution may send (RFC 1034 §5.3.3). -/
  work : Nat
deriving DecidableEq, Repr

/-- What happened to the query in flight. -/
inductive Event where
  | reply (r : Response)
  | lost
deriving DecidableEq, Repr

inductive Out where
  | send (server : Name) (cut : Name) (q : Request)
  | answer (r : Response)
deriving DecidableEq, Repr

/-- The answer an item holds for exactly this question, when it holds one at the authoritative-answer rank. -/
def answerOf (q : Request) : Stored → Option Response
  | ⟨.authAnswer, .answer q' r⟩ => if q' = q then some r else none
  | _ => none

/-- A cached authoritative answer to exactly this question. -/
def cachedAnswer (cache : List Stored) (q : Request) : Option Response := cache.findSome? (answerOf q)

/-- A cached cut a resolution for `q` may start from: at or above the name, and not the name itself for DS,
which its parent answers (RFC 4035 §3.1.4.1). -/
def startsAt (q : Request) (ns : RRset) : Bool :=
  under q.qname ns.owner && !(ns.owner == q.qname && q.qtype == 43)

/-- The deepest cached cut a resolution may start from, with its servers; the root hints when there is none. -/
def closestCut (cfg : Config) (cache : List Stored) (q : Request) : Name × List Name :=
  cache.foldl (fun best st =>
    match st.item with
    | .cut ns => if startsAt q ns && best.1.length < ns.owner.length then (ns.owner, targets ns) else best
    | _ => best) ([], cfg.hints)

def finish (st : State) (r : Response) : State × List Out := ({ st with res := none }, [.answer r])

/-- Asks the first server left, or gives up: no server left, or no work left. -/
def sendNext (st : State) (res : Res) : State × List Out :=
  match res.servers with
  | [] => finish st servfail
  | s :: _ =>
    if res.work = 0 then finish st servfail
    else ({ st with res := some { res with work := res.work - 1 } }, [.send s res.cut res.q])

/-- A new question: a cached answer, or a resolution from the closest cached cut. -/
def start (cfg : Config) (st : State) (q : Request) : State × List Out :=
  match cachedAnswer st.cache q with
  | some r => ({ st with res := none }, [.answer r])
  | none => sendNext st ⟨q, (closestCut cfg st.cache q).1, (closestCut cfg st.cache q).2, cfg.work⟩

/-- In-domain glue of a referral: address records for its NS targets below its cut (RFC 9471 §3.1). -/
def glueOf (r : Response) (ns : RRset) : List RRset :=
  r.additional.filter fun s => isAddr s && (targets ns).contains s.owner && under s.owner ns.owner

/-- `step`: one event for the resolution in progress. -/
def step (st : State) (e : Event) : State × List Out :=
  match st.res with
  | none => (st, [])
  | some res =>
    match e with
    | .lost => sendNext st { res with servers := res.servers.drop 1 }
    | .reply r =>
      match cutOf r with
      | some ns =>
        if descends res.cut res.q ns then
          let cached := ⟨.nonAuthAuthority, .cut ns⟩ :: ((glueOf r ns).map fun g => ⟨.glue, .glue g⟩) ++ st.cache
          sendNext { st with cache := cached } ⟨res.q, ns.owner, targets ns, res.work⟩
        else sendNext st { res with servers := res.servers.drop 1 }
      | none => finish { st with cache := ⟨.authAnswer, .answer res.q r⟩ :: st.cache } r

/-! ## Running it over the hierarchy -/

/-- What the network does with one query: lost, or answered by a correct server of the cut; a cut with no
servers never answers. -/
def deliver (net : Net) (any : AnyResponse) (cut : Name) (q : Request) (lost : Bool) : Event :=
  if lost then .lost
  else match zoneAt net cut with
    | some z => .reply (reply any z q)
    | none => .lost

/-- Feeds the resolver's sends to the network, one loss decision each from the script, until it answers. -/
def drive (net : Net) (any : AnyResponse) :
    Nat → State × List Out → List Bool → Option (Response × State × List Bool)
  | _, (st, [.answer r]), ls => some (r, st, ls)
  | fuel + 1, (st, [.send _ c q]), ls => drive net any fuel (step st (deliver net any c q (ls.headD false))) ls.tail
  | _, _, _ => none

/-- `Resolver.run` for one question: the answer, the state after it, and the losses not yet used. -/
def run (net : Net) (any : AnyResponse) (cfg : Config) (st : State) (q : Request) (losses : List Bool) :
    Option (Response × State × List Bool) :=
  drive net any (cfg.work + 1) (start cfg st q) losses

/-! ## A referral is the same for every name below its cut -/

theorem answer_reply (any : AnyResponse) (z : Zone) (q : Request) : answer z q any = .response (reply any z q) := by
  unfold reply
  cases h : answer z q any with
  | response r => rfl
  | unknown n => exact absurd h (answer_never_unknown z q any n)

theorem reply_eq {any : AnyResponse} {z : Zone} {q : Request} {r : Response} (h : answer z q any = .response r) :
    reply any z q = r := by
  simp [reply, h]

theorem cutOf_some {r : Response} {ns : RRset} (h : cutOf r = some ns) :
    r.authority = [ns] ∧ r.rcode = .noerror ∧ r.aa = false ∧ r.answer = [] ∧ ns.rtype = 2 := by
  unfold cutOf at h
  split at h
  · rename_i ns' hauth
    split at h
    · rename_i hc; cases h; exact ⟨hauth, hc.1, hc.2.1, hc.2.2.1, hc.2.2.2⟩
    · cases h
  · cases h

theorem cutOf_of {r : Response} {ns : RRset} (h1 : r.authority = [ns]) (h2 : r.rcode = .noerror)
    (h3 : r.aa = false) (h4 : r.answer = []) (h5 : ns.rtype = 2) : cutOf r = some ns := by
  simp [cutOf, h1, h2, h3, h4, h5]

/-- In a well-formed complete zone, a referral to the cut `m` that lies at or above the question name is not a DS
question at `m`, and the zone gives the same referral for every name at or below `m` (other than DS at `m`):
the walk stops at the highest cut on the path, wherever below it the name is. -/
theorem referral_stable (z : Zone) (hwf : z.WF) (any : AnyResponse) {q : Request} (hq : z.apex <:+ q.qname)
    {ns : RRset} (hc : cutOf (reply any z q) = some ns) (hu : ns.owner <:+ q.qname) :
    ¬ (ns.owner = q.qname ∧ q.qtype = 43) ∧ z.apex <:+ ns.owner ∧ ns.owner ≠ z.apex ∧
      ∀ q' : Request, ns.owner <:+ q'.qname → ¬ (ns.owner = q'.qname ∧ q'.qtype = 43) →
        cutOf (reply any z q') = some ns := by
  obtain ⟨hauth, hrc, haa, han, hty⟩ := cutOf_some hc
  have href : ∃ r, answer z q any = .response r ∧ r.rcode = .noerror ∧ r.answer = [] ∧ r.aa = false :=
    ⟨_, answer_reply any z q, hrc, han, haa⟩
  rcases (referral_iff_below_cut z q any hq).mp href with ⟨m, ns', ds, g, hb, hds⟩ | ⟨hns, hp, ns', ds, g, hw⟩
  · obtain ⟨r', hr', _, _, hau', _⟩ := referral_aa_false z q any hq hb hds
    rw [reply_eq hr', hau'] at hauth
    simp only [List.cons.injEq, and_true] at hauth
    subst hauth
    obtain ⟨hnode, hmq, ham, hmne, hnsm⟩ := hb
    have hwm := hwf.2 m _ hnode
    simp only at hwm
    have hown : ns'.owner = m := hwm.1
    rw [hown]
    refine ⟨hds, ham, hmne, fun q' hm' hds' => ?_⟩
    have hq' : z.apex <:+ q'.qname := ham.trans hm'
    obtain ⟨r'', hr'', haa'', han'', hau'', hrc''⟩ :=
      referral_aa_false z q' any hq' (m := m) ⟨hnode, hm', ham, hmne, hnsm⟩ hds'
    rw [reply_eq hr'']
    exact cutOf_of hau'' hrc'' haa'' han'' hty
  · exfalso
    -- the wildcard below the closest encloser is a cut: the referral names it, and it is not above the name
    have hL := z.locate_eq hq (L := .absent (z.closest q.qname)) ⟨hns, hp, rfl, z.closest_under _⟩
    have hg : get z.look (wild (z.closest q.qname)) = .ok (some (.cut ns' ds g)) :=
      get_some_iff.mpr (z.look_of_node hw)
    obtain ⟨ad, req, hr⟩ := referral_total z.look_ne_unknown z.apex (wild (z.closest q.qname)) ns' g
    have hs : Zone.step z.look z.apex z.soa any q.qname q.qtype =
        .ok (.done .noerror false [] [ns'] ad req) := by
      unfold Zone.step; rw [hL]; simp only; rw [hg]; exact hr
    rw [reply_eq (answer_done z q any hq hs)] at hauth
    simp only [List.cons.injEq, and_true] at hauth
    subst hauth
    have hwm := hwf.2 _ _ hw
    simp only at hwm
    rw [hwm.1] at hu
    have hwu : z.apex <:+ wild (z.closest q.qname) := Zone.wild_under (z.closest_under _)
    by_cases heq : wild (z.closest q.qname) = q.qname
    · rw [heq] at hw; rw [z.node_present hw] at hp; cases hp
    · have hstop := hns _ ⟨heq, hu, hwu⟩
      have hne : wild (z.closest q.qname) ≠ z.apex := by
        intro h
        have h1 := (z.closest_under q.qname).length_le
        have h2 := congrArg List.length h
        simp [wild] at h2
        omega
      rw [z.stops_cut hw hne] at hstop; cases hstop

/-! ## The hierarchy's answer, unfolded -/

theorem follow_final {net : Net} {any : AnyResponse} {q : Request} {z : Zone} (h : cutOf (reply any z q) = none) :
    follow net any q z = reply any z q := by
  rw [follow]; simp [h]

theorem follow_referral {net : Net} {any : AnyResponse} {q : Request} {z : Zone} {ns : RRset}
    (h : cutOf (reply any z q) = some ns) (hd : descends z.apex q ns = true) :
    follow net any q z = match zoneAt net ns.owner with
      | some z' => follow net any q z'
      | none => servfail := by
  rw [follow]
  simp only [h, hd, ↓reduceDIte]
  split
  · next z' hz => rw [hz]
  · next hz => rw [hz]

theorem follow_bizarre {net : Net} {any : AnyResponse} {q : Request} {z : Zone} {ns : RRset}
    (h : cutOf (reply any z q) = some ns) (hd : descends z.apex q ns = false) : follow net any q z = servfail := by
  rw [follow]; simp [h, hd]

/-! ## Invariants -/

/-- `q` is not a DS question at the cut `c` below the root: DS lives at the parent (RFC 4035 §3.1.4.1). -/
def NotDsAt (c : Name) (q : Request) : Prop := c = [] ∨ ¬ (c = q.qname ∧ q.qtype = 43)

/-- What the hierarchy answers for each name at or below the cut `c` is what `c`'s zone answers from there down,
or SERVFAIL when `c` has no servers. -/
def AtCut (net : Net) (any : AnyResponse) (c : Name) : Prop :=
  (∃ zc, zoneAt net c = some zc ∧ ∀ q, c <:+ q.qname → NotDsAt c q → spec net any q = follow net any q zc) ∨
    (zoneAt net c = none ∧ ∀ q, c <:+ q.qname → NotDsAt c q → spec net any q = servfail)

/-- Each cached answer is the hierarchy's answer, and each cached cut names servers and satisfies `AtCut`. -/
def CacheOk (net : Net) (any : AnyResponse) (cache : List Stored) : Prop :=
  ∀ st ∈ cache, match st.item with
    | .answer q r => r = spec net any q
    | .cut ns => AtCut net any ns.owner ∧ targets ns ≠ []
    | .glue _ => True

/-- The resolution is at a cut at or above its name, not the name itself for DS, that satisfies `AtCut`. -/
def ResOk (net : Net) (any : AnyResponse) (res : Res) : Prop :=
  res.cut <:+ res.q.qname ∧ NotDsAt res.cut res.q ∧ AtCut net any res.cut

theorem atCut_root (net : Net) (any : AnyResponse) : AtCut net any [] := by
  unfold AtCut spec
  cases h : zoneAt net [] with
  | some root => exact Or.inl ⟨root, rfl, fun q _ _ => by simp⟩
  | none => exact Or.inr ⟨rfl, fun q _ _ => by simp⟩

theorem cachedAnswer_some {cache : List Stored} {q : Request} {r : Response} (h : cachedAnswer cache q = some r) :
    ∃ st ∈ cache, st.item = .answer q r := by
  have hof : ∀ st r, answerOf q st = some r → st.item = .answer q r := by
    intro st r h
    unfold answerOf at h
    split at h
    · split at h
      · rename_i hq; cases h; subst hq; rfl
      · cases h
    · cases h
  induction cache with
  | nil => simp [cachedAnswer] at h
  | cons st sts ih =>
    unfold cachedAnswer at h
    rw [List.findSome?_cons] at h
    split at h
    · rename_i r' hst
      cases h
      exact ⟨st, List.mem_cons_self, hof st _ hst⟩
    · obtain ⟨st', h1, h2⟩ := ih h
      exact ⟨st', List.mem_cons_of_mem _ h1, h2⟩

theorem closestCut_ok {net : Net} {any : AnyResponse} {cfg : Config} {cache : List Stored}
    (hc : CacheOk net any cache) (q : Request) :
    (closestCut cfg cache q).1 <:+ q.qname ∧ NotDsAt (closestCut cfg cache q).1 q ∧
      AtCut net any (closestCut cfg cache q).1 ∧ (cfg.hints ≠ [] → (closestCut cfg cache q).2 ≠ []) := by
  unfold closestCut
  have key : ∀ (l : List Stored) (init : Name × List Name), (∀ st ∈ l, st ∈ cache) →
      (init.1 <:+ q.qname ∧ NotDsAt init.1 q ∧ AtCut net any init.1 ∧ (cfg.hints ≠ [] → init.2 ≠ [])) →
      let r := l.foldl (fun best st =>
        match st.item with
        | .cut ns => if startsAt q ns && best.1.length < ns.owner.length then (ns.owner, targets ns) else best
        | _ => best) init
      r.1 <:+ q.qname ∧ NotDsAt r.1 q ∧ AtCut net any r.1 ∧ (cfg.hints ≠ [] → r.2 ≠ []) := by
    intro l
    induction l with
    | nil => intro init _ h; exact h
    | cons st sts ih =>
      intro init hsub h
      simp only [List.foldl_cons]
      apply ih _ (fun s hs => hsub s (List.mem_cons_of_mem _ hs))
      cases hi : st.item with
      | cut ns =>
        simp only
        split
        · rename_i hcond
          simp only [Bool.and_eq_true, startsAt, Bool.not_eq_true', Bool.and_eq_false_iff, beq_eq_false_iff_ne,
            ne_eq, decide_eq_true_eq] at hcond
          have hok := hc st (hsub st List.mem_cons_self)
          rw [hi] at hok
          refine ⟨(under_iff _ _).mp hcond.1.1, Or.inr ?_, hok.1, fun _ => hok.2⟩
          rintro ⟨h1, h2⟩
          rcases hcond.1.2 with h' | h'
          · exact h' h1
          · exact h' h2
        · exact h
      | glue _ => exact h
      | answer _ _ => exact h
  exact key cache ([], cfg.hints) (fun _ h => h) ⟨List.nil_suffix, Or.inl rfl, atCut_root net any, id⟩

/-! ## Soundness -/

theorem sendNext_cases (st : State) (res : Res) :
    sendNext st res = finish st servfail ∨
      ∃ s rest, res.servers = s :: rest ∧ res.work ≠ 0 ∧
        sendNext st res = ({ st with res := some { res with work := res.work - 1 } }, [.send s res.cut res.q]) := by
  unfold sendNext
  cases hs : res.servers with
  | nil => exact Or.inl rfl
  | cons s rest =>
    simp only
    split
    · exact Or.inl rfl
    · rename_i hw; exact Or.inr ⟨s, rest, rfl, hw, rfl⟩

/-- What one step keeps: the cache invariant, the resolution invariant for the same question, and answers that
are the hierarchy's answer or SERVFAIL. -/
def Sound (net : Net) (any : AnyResponse) (q : Request) (p : State × List Out) : Prop :=
  CacheOk net any p.1.cache ∧ (∀ res, p.1.res = some res → ResOk net any res ∧ res.q = q) ∧
    (∀ s c q', p.2 = [.send s c q'] → ∃ res, p.1.res = some res ∧ res.cut = c ∧ res.q = q') ∧
    ∀ r, p.2 = [.answer r] → r = spec net any q ∨ r = servfail

theorem sendNext_sound {net : Net} {any : AnyResponse} {q : Request} {st : State} {res : Res}
    (hc : CacheOk net any st.cache) (hr : ResOk net any res) (hq : res.q = q) :
    Sound net any q (sendNext st res) := by
  rcases sendNext_cases st res with h | ⟨s, rest, _, _, h⟩
  · rw [h]
    refine ⟨hc, fun res' h' => by simp [finish] at h', fun _ _ _ h' => by simp [finish] at h', fun r h' => ?_⟩
    simp only [finish, List.cons.injEq, Out.answer.injEq, and_true] at h'
    exact Or.inr h'.symm
  · rw [h]
    refine ⟨hc, fun res' h' => ?_, fun s' c q' h' => ?_, fun r h' => by simp at h'⟩
    · simp only [Option.some.injEq] at h'; subst h'; exact ⟨hr, hq⟩
    · simp only [List.cons.injEq, Out.send.injEq, and_true] at h'
      obtain ⟨_, rfl, rfl⟩ := h'
      exact ⟨_, rfl, rfl, rfl⟩

theorem step_sound {net : Net} {any : AnyResponse} (hwf : ∀ z ∈ net, z.WF) {q : Request} {st : State} {res : Res}
    (hst : st.res = some res) (hc : CacheOk net any st.cache) (hr : ResOk net any res) (hq : res.q = q)
    (lost : Bool) : Sound net any q (step st (deliver net any res.cut res.q lost)) := by
  obtain ⟨hcq, hnd, hat⟩ := hr
  have hres : ResOk net any res := ⟨hcq, hnd, hat⟩
  have hlost : step st .lost = sendNext st { res with servers := res.servers.drop 1 } := by
    simp [step, hst]
  unfold deliver
  by_cases hl : lost = true
  · simp only [hl, ↓reduceIte, hlost]; exact sendNext_sound hc hres hq
  · simp only [Bool.not_eq_true] at hl
    simp only [hl, Bool.false_eq_true, ↓reduceIte]
    cases hz : zoneAt net res.cut with
    | none => simp only [hlost]; exact sendNext_sound hc hres hq
    | some z =>
      simp only
      obtain ⟨hza, hzn⟩ := zoneAt_apex hz
      have hspec : spec net any res.q = follow net any res.q z := by
        rcases hat with ⟨zc, hzc, hgen⟩ | ⟨hzc, _⟩
        · rw [hz] at hzc; cases hzc; exact hgen res.q hcq hnd
        · rw [hz] at hzc; cases hzc
      unfold step
      rw [hst]
      simp only
      cases hcut : cutOf (reply any z res.q) with
      | none =>
        simp only [finish]
        refine ⟨fun s hs => ?_, fun _ h => by simp at h, fun _ _ _ h => by simp at h, fun r h => ?_⟩
        · rcases List.mem_cons.mp hs with rfl | hs
          · simp only; rw [hspec, follow_final hcut]
          · exact hc s hs
        · simp only [List.cons.injEq, Out.answer.injEq, and_true] at h
          subst h; left; rw [← hq, hspec, follow_final hcut]
      | some ns =>
        simp only
        split
        · rename_i hd
          have hzq : z.apex <:+ res.q.qname := by rw [hza]; exact hcq
          simp only [descends, Bool.and_eq_true] at hd
          have hnsu : ns.owner <:+ res.q.qname := (under_iff _ _).mp hd.1.2
          obtain ⟨hnds, hapex, hne, hsame⟩ := referral_stable z (hwf z hzn) any hzq hcut hnsu
          have hd' : descends res.cut res.q ns = true := by simp [descends, hd]
          have hcutns : res.cut <:+ ns.owner := hza ▸ hapex
          have hlen := (descends_len hd').1
          -- what the hierarchy answers below the new cut
          have hgen : ∀ q', ns.owner <:+ q'.qname → NotDsAt ns.owner q' →
              spec net any q' = follow net any q' z := by
            intro q' hq' _
            rcases hat with ⟨zc, hzc, hgenc⟩ | ⟨hzc, _⟩
            · rw [hz] at hzc; cases hzc
              apply hgenc q' (hcutns.trans hq')
              right; rintro ⟨h1, _⟩
              have := hq'.length_le
              rw [h1] at hlen; omega
            · rw [hz] at hzc; cases hzc
          have hfol : ∀ q', ns.owner <:+ q'.qname → NotDsAt ns.owner q' →
              follow net any q' z = match zoneAt net ns.owner with
                | some z' => follow net any q' z'
                | none => servfail := by
            intro q' hq' hnd'
            have hnot : ¬ (ns.owner = q'.qname ∧ q'.qtype = 43) := by
              rcases hnd' with h0 | h0
              · rw [h0] at hlen; simp at hlen
              · exact h0
            apply follow_referral (hsame q' hq' hnot)
            simp only [descends, Bool.and_eq_true]
            exact ⟨⟨by rw [hza]; exact hd.1.1, (under_iff _ _).mpr hq'⟩, hd.2⟩
          have hat' : AtCut net any ns.owner := by
            cases hzm : zoneAt net ns.owner with
            | some zm =>
              refine Or.inl ⟨zm, hzm, fun q' hq' hnd' => ?_⟩
              rw [hgen q' hq' hnd', hfol q' hq' hnd', hzm]
            | none =>
              refine Or.inr ⟨hzm, fun q' hq' hnd' => ?_⟩
              rw [hgen q' hq' hnd', hfol q' hq' hnd', hzm]
          apply sendNext_sound
          · intro s hs
            rcases List.mem_cons.mp hs with rfl | hs
            · exact ⟨hat', by simpa using hd.2⟩
            · rcases List.mem_append.mp hs with hs | hs
              · obtain ⟨g, _, rfl⟩ := List.mem_map.mp hs; trivial
              · exact hc s hs
          · exact ⟨hnsu, Or.inr hnds, hat'⟩
          · exact hq
        · exact sendNext_sound hc hres hq

theorem drive_sound {net : Net} {any : AnyResponse} (hwf : ∀ z ∈ net, z.WF) {q : Request} :
    ∀ fuel p ls r st' ls', Sound net any q p → drive net any fuel p ls = some (r, st', ls') →
      (r = spec net any q ∨ r = servfail) ∧ CacheOk net any st'.cache := by
  intro fuel
  induction fuel with
  | zero =>
    intro p ls r st' ls' hs h
    obtain ⟨st, outs⟩ := p
    match outs, hs, h with
    | [.answer r0], hs, h =>
      simp only [drive, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      exact ⟨hs.2.2.2 r0 rfl, hs.1⟩
    | [.send _ _ _], _, h => simp [drive] at h
    | [], _, h => simp [drive] at h
    | _ :: _ :: _, _, h => simp [drive] at h
  | succ f ih =>
    intro p ls r st' ls' hs h
    obtain ⟨st, outs⟩ := p
    match outs, hs, h with
    | [.answer r0], hs, h =>
      simp only [drive, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      exact ⟨hs.2.2.2 r0 rfl, hs.1⟩
    | [.send s c q'], hs, h =>
      simp only [drive] at h
      obtain ⟨res, hres, hc, hq'⟩ := hs.2.2.1 s c q' rfl
      obtain ⟨hrok, hrq⟩ := hs.2.1 res hres
      rw [← hc, ← hq'] at h
      exact ih _ _ r st' ls' (step_sound hwf hres hs.1 hrok hrq _) h
    | [], _, h => simp [drive] at h
    | _ :: _ :: _, _, h => simp [drive] at h

/-! ## The headline theorems -/

/-- The measure of a state: the work left in the resolution in progress, plus one. -/
def measure (st : State) : Nat :=
  match st.res with
  | none => 0
  | some r => r.work + 1

/-- The resolver's output: an answer with nothing in progress, or one send for the resolution in progress. -/
def Shape (p : State × List Out) : Prop :=
  (∃ r, p.2 = [.answer r] ∧ p.1.res = none) ∨ (∃ s c q res, p.2 = [.send s c q] ∧ p.1.res = some res)

theorem sendNext_measure (st : State) (res : Res) :
    measure (sendNext st res).1 < res.work + 1 ∧ Shape (sendNext st res) := by
  rcases sendNext_cases st res with h | ⟨s, rest, _, hw, h⟩
  · rw [h]; exact ⟨by simp [finish, measure], Or.inl ⟨_, rfl, rfl⟩⟩
  · rw [h]; exact ⟨by simp only [measure]; omega, Or.inr ⟨_, _, _, _, rfl, rfl⟩⟩

/-- Every step of a resolution spends work or finishes it, and leaves the resolver sending one query or
answering. -/
theorem measure_decreases {st : State} {res : Res} (h : st.res = some res) (e : Event) :
    measure (step st e).1 < measure st ∧ Shape (step st e) := by
  have hm : measure st = res.work + 1 := by simp [measure, h]
  rw [hm]
  unfold step
  rw [h]
  simp only
  cases e with
  | lost => exact sendNext_measure _ _
  | reply r =>
    simp only
    cases cutOf r with
    | some ns =>
      simp only
      split
      · exact sendNext_measure _ ⟨res.q, ns.owner, targets ns, res.work⟩
      · exact sendNext_measure _ { res with servers := res.servers.drop 1 }
    | none => exact ⟨by simp [finish, measure], Or.inl ⟨_, rfl, rfl⟩⟩

theorem drive_some {net : Net} {any : AnyResponse} :
    ∀ fuel p ls, Shape p → measure p.1 ≤ fuel → ∃ r st ls', drive net any fuel p ls = some (r, st, ls') := by
  intro fuel
  induction fuel with
  | zero =>
    intro p ls hs hm
    obtain ⟨st, outs⟩ := p
    rcases hs with ⟨r, rfl, _⟩ | ⟨s, c, q, res, rfl, hres⟩
    · exact ⟨r, st, ls, by simp [drive]⟩
    · dsimp only at hm hres; simp [measure, hres] at hm
  | succ f ih =>
    intro p ls hs hm
    obtain ⟨st, outs⟩ := p
    rcases hs with ⟨r, rfl, _⟩ | ⟨s, c, q, res, rfl, hres⟩
    · exact ⟨r, st, ls, by simp [drive]⟩
    · dsimp only at hm hres
      obtain ⟨hlt, hsh⟩ := measure_decreases hres (deliver net any c q (ls.headD false))
      have : measure (step st (deliver net any c q (ls.headD false))).1 ≤ f := by omega
      obtain ⟨r, st', ls', h⟩ := ih _ ls.tail hsh this
      exact ⟨r, st', ls', by simp only [drive]; exact h⟩

/-- A resolution always ends, whatever the network loses. -/
theorem resolve_terminates (net : Net) (any : AnyResponse) (cfg : Config) (st : State) (q : Request)
    (losses : List Bool) : ∃ r st' ls', run net any cfg st q losses = some (r, st', ls') := by
  unfold run start
  cases cachedAnswer st.cache q with
  | some r => exact drive_some _ _ _ (Or.inl ⟨r, rfl, rfl⟩) (by simp [measure])
  | none =>
    simp only
    obtain ⟨hm, hs⟩ :=
      sendNext_measure st ⟨q, (closestCut cfg st.cache q).1, (closestCut cfg st.cache q).2, cfg.work⟩
    exact drive_some _ _ _ hs (by simp only at hm; omega)

theorem run_sound {net : Net} {any : AnyResponse} (hwf : ∀ z ∈ net, z.WF) {cfg : Config} {st : State} {q : Request}
    {losses : List Bool} {r : Response} {st' : State} {ls' : List Bool} (hc : CacheOk net any st.cache)
    (h : run net any cfg st q losses = some (r, st', ls')) :
    (r = spec net any q ∨ r = servfail) ∧ CacheOk net any st'.cache := by
  unfold run start at h
  cases ha : cachedAnswer st.cache q with
  | some r' =>
    rw [ha] at h
    refine drive_sound hwf _ _ _ _ _ _ ⟨hc, fun _ h => by simp at h, fun _ _ _ h => by simp at h, fun r h => ?_⟩ h
    simp only [List.cons.injEq, Out.answer.injEq, and_true] at h
    subst h
    obtain ⟨s, hs, hi⟩ := cachedAnswer_some ha
    have := hc s hs
    rw [hi] at this
    exact Or.inl this
  | none =>
    rw [ha] at h
    simp only at h
    obtain ⟨h1, h2, h3, _⟩ := closestCut_ok (cfg := cfg) hc q
    exact drive_sound hwf _ _ _ _ _ _ (sendNext_sound hc ⟨h1, h2, h3⟩ rfl) h

/-! ## Completeness: with nothing lost and enough work, the hierarchy's answer -/

theorem headD_false {ls : List Bool} (h : ∀ b ∈ ls, b = false) :
    ls.headD false = false ∧ ∀ b ∈ ls.tail, b = false := by
  cases ls with
  | nil => simp
  | cons b bs => exact ⟨h b List.mem_cons_self, fun x hx => h x (List.mem_cons_of_mem _ hx)⟩

theorem drive_answer {net : Net} {any : AnyResponse} (fuel : Nat) (st : State) (r : Response) (ls : List Bool) :
    drive net any fuel (st, [.answer r]) ls = some (r, st, ls) := by
  cases fuel <;> rfl

theorem drive_send {net : Net} {any : AnyResponse} (f : Nat) (st : State) (s c : Name) (q : Request)
    (ls : List Bool) :
    drive net any (f + 1) (st, [.send s c q]) ls =
      drive net any f (step st (deliver net any c q (ls.headD false))) ls.tail :=
  rfl

theorem sendNext_send {st : State} {res : Res} {t : Name} {ts : List Name} (hs : res.servers = t :: ts)
    (hw : res.work ≠ 0) :
    sendNext st res = ({ st with res := some { res with work := res.work - 1 } }, [.send t res.cut res.q]) := by
  simp [sendNext, hs, hw]

theorem sendNext_finish {st : State} {res : Res} (h : res.servers = [] ∨ res.work = 0) :
    sendNext st res = finish st servfail := by
  unfold sendNext
  rcases h with h | h
  · simp [h]
  · cases res.servers <;> simp [h]

/-- When every server of a resolution gives an answer that makes the resolver try the next one, it ends with
SERVFAIL. -/
theorem exhaust {net : Net} {any : AnyResponse} {c : Name} {q : Request}
    (hE : ∀ st res, st.res = some res → res.cut = c → res.q = q →
      step st (deliver net any c q false) = sendNext st { res with servers := res.servers.drop 1 }) :
    ∀ (rest : List Name) fuel (st : State) (res : Res) s ls, st.res = some res → res.cut = c → res.q = q →
      res.servers = s :: rest → res.work + 1 ≤ fuel → (∀ b ∈ ls, b = false) →
      ∃ st' ls', drive net any fuel (st, [.send s c q]) ls = some (servfail, st', ls') := by
  intro rest
  induction rest with
  | nil =>
    intro fuel st res s ls hst hc hq hs hf hls
    obtain ⟨f, rfl⟩ : ∃ f, fuel = f + 1 := ⟨fuel - 1, by omega⟩
    rw [drive_send, (headD_false hls).1, hE st res hst hc hq,
      sendNext_finish (res := { res with servers := res.servers.drop 1 }) (by simp [hs])]
    exact ⟨_, _, drive_answer _ _ _ _⟩
  | cons s' rest ih =>
    intro fuel st res s ls hst hc hq hs hf hls
    subst hc; subst hq
    obtain ⟨f, rfl⟩ : ∃ f, fuel = f + 1 := ⟨fuel - 1, by omega⟩
    obtain ⟨hhead, htail⟩ := headD_false hls
    rw [drive_send, hhead, hE st res hst rfl rfl]
    by_cases hw : res.work = 0
    · rw [sendNext_finish (res := { res with servers := res.servers.drop 1 }) (Or.inr hw)]
      exact ⟨_, _, drive_answer _ _ _ _⟩
    · rw [sendNext_send (res := { res with servers := res.servers.drop 1 }) (t := s') (ts := rest) (by simp [hs]) hw]
      exact ih f _ _ s' ls.tail rfl rfl rfl (by simp [hs]) (by simp only; omega) htail

/-- With nothing lost, a resolution at a cut whose zone exists, with enough work left, answers what the
hierarchy answers from that zone down. -/
theorem drive_complete {net : Net} {any : AnyResponse} {q : Request} :
    ∀ n (zc : Zone), q.qname.length + 1 - zc.apex.length = n → zc ∈ net → zoneAt net zc.apex = some zc →
      ∀ fuel (st : State) (res : Res) s ls, st.res = some res → res.cut = zc.apex → res.q = q →
        res.servers.head? = some s → zc.apex <:+ q.qname → q.qname.length - zc.apex.length ≤ res.work →
        res.work + 1 ≤ fuel → (∀ b ∈ ls, b = false) →
        ∃ st' ls', drive net any fuel (st, [.send s zc.apex q]) ls = some (follow net any q zc, st', ls') := by
  intro n
  induction n using Nat.strongRecOn with
  | ind n ih =>
    intro zc hn hzc hzat fuel st res s ls hst hcut hq hs hzq hw hf hls
    obtain ⟨f, rfl⟩ : ∃ f, fuel = f + 1 := ⟨fuel - 1, by omega⟩
    obtain ⟨hhead, htail⟩ := headD_false hls
    have hdel : deliver net any zc.apex q false = .reply (reply any zc q) := by simp [deliver, hzat]
    rw [drive_send, hhead, hdel]
    cases hcutof : cutOf (reply any zc q) with
    | none =>
      have hstep : step st (.reply (reply any zc q)) =
          finish { st with cache := ⟨.authAnswer, .answer res.q (reply any zc q)⟩ :: st.cache }
            (reply any zc q) := by
        simp [step, hst, hcutof]
      rw [hstep, follow_final hcutof]
      exact ⟨_, _, drive_answer _ _ _ _⟩
    | some ns =>
      by_cases hd : descends zc.apex q ns = true
      · have hd' : descends res.cut res.q ns = true := by rw [hcut, hq]; exact hd
        have hstep : step st (.reply (reply any zc q)) =
            sendNext { st with cache := ⟨.nonAuthAuthority, .cut ns⟩ ::
              ((glueOf (reply any zc q) ns).map fun g => ⟨.glue, .glue g⟩) ++ st.cache }
              ⟨res.q, ns.owner, targets ns, res.work⟩ := by
          simp [step, hst, hcutof, hd']
        rw [hstep, follow_referral hcutof hd]
        have hlen := descends_len hd
        have hdd := hd
        simp only [descends, Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff] at hdd
        obtain ⟨⟨_, hu⟩, htg⟩ := hdd
        obtain ⟨t, ts, htts⟩ := List.exists_cons_of_ne_nil htg
        have hwork : res.work ≠ 0 := by omega
        rw [sendNext_send (res := ⟨res.q, ns.owner, targets ns, res.work⟩) htts hwork]
        simp only
        cases hzm : zoneAt net ns.owner with
        | some zm =>
          obtain ⟨hzma, hzmn⟩ := zoneAt_apex hzm
          simp only
          rw [hq, ← hzma]
          exact ih _ (by rw [hzma]; omega) zm rfl hzmn (by rw [hzma]; exact hzm) f _
            ⟨q, zm.apex, targets ns, res.work - 1⟩ t ls.tail rfl rfl rfl (by simp [htts])
            (by rw [hzma]; exact (under_iff _ _).mp hu) (by simp only; rw [hzma]; omega) (by simp only; omega) htail
        | none =>
          simp only
          refine exhaust (c := ns.owner) (q := res.q) ?_ ts f _ _ t ls.tail rfl rfl rfl (by simp [htts])
            (by simp only; omega) htail
          intro st' res' hst' _ _
          simp [step, hst', deliver, hzm]
      · have hd' : descends res.cut res.q ns = false := by rw [hcut, hq]; simpa using hd
        have hstep : step st (.reply (reply any zc q)) = sendNext st { res with servers := res.servers.drop 1 } := by
          simp [step, hst, hcutof, hd']
        rw [hstep, follow_bizarre hcutof (by simpa using hd)]
        obtain ⟨rest, hrest⟩ : ∃ rest, res.servers = s :: rest := by
          cases h : res.servers with
          | nil => rw [h] at hs; cases hs
          | cons s' rest =>
            rw [h] at hs; simp only [List.head?_cons, Option.some.injEq] at hs; exact ⟨rest, by rw [hs]⟩
        cases rest with
        | nil =>
          rw [sendNext_finish (res := { res with servers := res.servers.drop 1 }) (by simp [hrest])]
          exact ⟨_, _, drive_answer _ _ _ _⟩
        | cons s' rest' =>
          by_cases hw0 : res.work = 0
          · rw [sendNext_finish (res := { res with servers := res.servers.drop 1 }) (Or.inr hw0)]
            exact ⟨_, _, drive_answer _ _ _ _⟩
          · rw [sendNext_send (res := { res with servers := res.servers.drop 1 }) (t := s') (ts := rest')
              (by simp [hrest]) hw0]
            refine exhaust (c := res.cut) (q := res.q) ?_ rest' f _ _ s' ls.tail rfl rfl rfl (by simp [hrest])
              (by simp only; omega) htail
            intro st' res' hst' hc' hq'
            have hdel' : deliver net any res.cut res.q false = .reply (reply any zc q) := by
              rw [hcut, hq]; exact hdel
            rw [hdel']
            have hd'' : descends res'.cut res'.q ns = false := by rw [hc', hq']; exact hd'
            simp [step, hst', hcutof, hd'']

theorem resolve_complete {net : Net} {any : AnyResponse} {cfg : Config} {st : State} {q : Request}
    {losses : List Bool} (hc : CacheOk net any st.cache) (hh : cfg.hints ≠ []) (hw : q.qname.length + 1 ≤ cfg.work)
    (hls : ∀ b ∈ losses, b = false) :
    ∃ st' ls', run net any cfg st q losses = some (spec net any q, st', ls') := by
  unfold run start
  cases ha : cachedAnswer st.cache q with
  | some r =>
    obtain ⟨s, hs, hi⟩ := cachedAnswer_some ha
    have := hc s hs
    rw [hi] at this
    simp only at this
    rw [← this]
    exact ⟨_, _, drive_answer _ _ _ _⟩
  | none =>
    simp only
    obtain ⟨h1, h2, h3, h4⟩ := closestCut_ok (cfg := cfg) hc q
    obtain ⟨t, ts, hts⟩ := List.exists_cons_of_ne_nil (h4 hh)
    have hwork : cfg.work ≠ 0 := by omega
    rw [sendNext_send (res := ⟨q, (closestCut cfg st.cache q).1, (closestCut cfg st.cache q).2, cfg.work⟩) hts hwork]
    simp only
    generalize (closestCut cfg st.cache q).1 = c at h1 h2 h3 ⊢
    rcases h3 with ⟨zc, hzc, hgen⟩ | ⟨hzc, hgen⟩
    · obtain ⟨hza, hzn⟩ := zoneAt_apex hzc
      rw [hgen q h1 h2, ← hza]
      exact drive_complete _ zc rfl hzn (by rw [hza]; exact hzc) (cfg.work + 1) _
        ⟨q, zc.apex, (closestCut cfg st.cache q).2, cfg.work - 1⟩ t losses rfl rfl rfl (by simp [hts])
        (by rw [hza]; exact h1) (by simp only; omega) (by simp only; omega) hls
    · rw [hgen q h1 h2]
      refine exhaust (c := c) (q := q) ?_ ts _ _ _ t losses rfl rfl rfl (by simp [hts]) (by simp only; omega) hls
      intro st' res' hst' _ _
      simp [step, hst', deliver, hzc]

/-! ## The headline theorems about answers -/

/-- What a resolver answers, whatever is lost, is the hierarchy's answer to the question or SERVFAIL; with
nothing lost, root hints, and work for one query per label and one more, it is the hierarchy's answer. -/
theorem resolve_correct {net : Net} {any : AnyResponse} (hwf : ∀ z ∈ net, z.WF) {cfg : Config} {st : State}
    {q : Request} (hc : CacheOk net any st.cache) :
    (∀ losses r st' ls', run net any cfg st q losses = some (r, st', ls') →
      (r = spec net any q ∨ r = servfail) ∧ CacheOk net any st'.cache) ∧
    (cfg.hints ≠ [] → q.qname.length + 1 ≤ cfg.work → ∀ losses, (∀ b ∈ losses, b = false) →
      ∃ st' ls', run net any cfg st q losses = some (spec net any q, st', ls')) :=
  ⟨fun _ _ _ _ h => run_sound hwf hc h, fun hh hw _ hls => resolve_complete hc hh hw hls⟩

theorem follow_from {net : Net} {any : AnyResponse} {q : Request} :
    ∀ n (z : Zone), q.qname.length + 1 - z.apex.length = n → z ∈ net →
      follow net any q z = servfail ∨ ∃ z' ∈ net, follow net any q z = reply any z' q := by
  intro n
  induction n using Nat.strongRecOn with
  | ind n ih =>
    intro z hn hz
    cases hcut : cutOf (reply any z q) with
    | none => exact Or.inr ⟨z, hz, follow_final hcut⟩
    | some ns =>
      by_cases hd : descends z.apex q ns = true
      · rw [follow_referral hcut hd]
        cases hzm : zoneAt net ns.owner with
        | some zm =>
          obtain ⟨hzma, hzmn⟩ := zoneAt_apex hzm
          have hlen := descends_len hd
          exact ih _ (by rw [hzma]; omega) zm rfl hzmn
        | none => exact Or.inl rfl
      · exact Or.inl (follow_bizarre hcut (by simpa using hd))

/-- A resolver never serves glue: every RRset in an answer it gives is in the answer section of the answer the
authoritative server of some zone gives to that very question. -/
theorem glue_never_served {net : Net} {any : AnyResponse} (hwf : ∀ z ∈ net, z.WF) {cfg : Config} {st : State}
    {q : Request} {losses : List Bool} {r : Response} {st' : State} {ls' : List Bool} (hc : CacheOk net any st.cache)
    (h : run net any cfg st q losses = some (r, st', ls')) :
    ∀ s ∈ r.answer, ∃ z ∈ net, ∃ resp, answer z q any = .response resp ∧ s ∈ resp.answer := by
  intro s hs
  rcases (run_sound hwf hc h).1 with rfl | rfl
  · unfold spec at hs
    cases hroot : zoneAt net [] with
    | none => rw [hroot] at hs; simp [servfail] at hs
    | some root =>
      rw [hroot] at hs
      simp only at hs
      rcases follow_from _ root rfl (zoneAt_apex hroot).2 with h' | ⟨z', hz', h'⟩
      · rw [h'] at hs; simp [servfail] at hs
      · rw [h'] at hs; exact ⟨z', hz', _, answer_reply any z' q, hs⟩
  · simp [servfail] at hs

/-- Several questions in turn, sharing the cache and the loss script. -/
def runAll (net : Net) (any : AnyResponse) (cfg : Config) : State → List Request → List Bool →
    List (Option Response) × State
  | st, [], _ => ([], st)
  | st, q :: qs, ls =>
    match run net any cfg st q ls with
    | some (r, st', ls') =>
      let (rs, st'') := runAll net any cfg st' qs ls'
      (some r :: rs, st'')
    | none => ([none], st)

end Dns.Resolver
