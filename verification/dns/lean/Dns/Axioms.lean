/-
  The axioms each headline theorem depends on, and an example applying each theorem to a concrete input.

  Expected: every `#print axioms` line lists only `propext`, `Quot.sound`, and `Classical.choice`, Lean's
  standard axioms, or a subset of them. `sorryAx` would mean an unfinished proof. Facts about concrete inputs
  are checked by the kernel (`decide +kernel`), which adds no axiom.
-/
import Dns.Name
import Dns.Wire
import Dns.Fit
import Dns.Zone
import Dns.Partial
import Dns.Authority
import Dns.Exchange

namespace Dns.Examples
open Dns

/-- Whether a computation finished with `a`. `Except` has no decidable equality, so examples check this. -/
def isOk {ε α : Type} [BEq α] (x : Except ε α) (a : α) : Bool :=
  match x with
  | .ok b => b == a
  | .error _ => false

theorem eq_ok_of_isOk {ε α : Type} [BEq α] [LawfulBEq α] {x : Except ε α} {a : α} (h : isOk x a = true) :
    x = .ok a := by
  unfold isOk at h
  split at h
  · rw [beq_iff_eq.mp h]
  · cases h

/-! ## Labels used below -/

def EX : Label := [101, 120, 97, 109, 112, 108, 101]
def COM : Label := [99, 111, 109]
def WWW : Label := [119, 119, 119]
def WWWmixed : Label := [87, 119, 87]
def NS : Label := [110, 115]
def NS1 : Label := [110, 115, 49]
def SUB : Label := [115, 117, 98]
def MAIL : Label := [109, 97, 105, 108]
def LA : Label := [97]
def LB : Label := [98]
def LD : Label := [100]
def LX : Label := [120]
def HOST : Label := [104, 111, 115, 116, 109, 97, 115, 116, 101, 114]
def STAR : Label := [42]

/-! ## `Dns/Name.lean` -/

#print axioms Name.fold_idem
example : Name.fold (Name.fold [WWWmixed, EX, COM]) = Name.fold [WWWmixed, EX, COM] := Name.fold_idem _

#print axioms Name.eqCI_iff_fold_eq
example : Name.eqCI [WWWmixed, EX, COM] [WWW, EX, COM] = true :=
  (Name.eqCI_iff_fold_eq _ _).mpr (by decide +kernel)

#print axioms Name.canon_total
example : Name.canonLt [EX, COM] [WWW, EX, COM] = true ∨ Name.fold [EX, COM] = Name.fold [WWW, EX, COM] ∨
    Name.canonLt [WWW, EX, COM] [EX, COM] = true := Name.canon_total _ _

#print axioms Name.canon_lt_trans
example : Name.canonLt [COM] [WWW, EX, COM] = true :=
  Name.canon_lt_trans [COM] [EX, COM] [WWW, EX, COM] (by decide +kernel) (by decide +kernel)

#print axioms Name.below_trans
example : Name.below [WWWmixed, EX, COM] [COM] = true :=
  Name.below_trans _ [EX, COM] _ (by decide +kernel) (by decide +kernel)

#print axioms Name.wire_len_le_255
example : Name.wireLen [WWW, EX, COM] ≤ 255 :=
  (Name.wire_len_le_255 [WWW, EX, COM] _ (by decide +kernel)).1

/-! ## `Dns/Wire.lean` -/

section Wire
open Wire

/-- `www.example.com. IN A` with a CNAME answer to `example.com.` and an A record. -/
def msg : Message :=
  ⟨⟨4660, 33152⟩, [⟨[WWW, EX, COM], 1, 1⟩],
    [⟨[WWW, EX, COM], 5, 1, 300, .names [] [[EX, COM]] []⟩, ⟨[EX, COM], 1, 1, 300, .octets [192, 0, 2, 1]⟩],
    [], []⟩

theorem msg_wf : msg.WF := by
  refine ⟨by decide, by decide, by decide, by decide, by decide, by decide, ?_, ?_, ?_, ?_⟩
  · intro q hq; simp [msg] at hq; subst hq; exact ⟨by decide +kernel, by decide, by decide⟩
  · intro r hr
    simp [msg] at hr
    rcases hr with rfl | rfl
    · exact ⟨by decide +kernel, by decide, by decide, by decide,
        ⟨rfl, fun n hn => by simp at hn; subst hn; decide +kernel, by decide +kernel⟩⟩
    · exact ⟨by decide +kernel, by decide, by decide, by decide, ⟨rfl, by decide⟩⟩
  · intro r hr; simp [msg] at hr
  · intro r hr; simp [msg] at hr

#print axioms decode_encode
example : decode (encode true msg) = .ok msg := decode_encode true msg msg_wf

#print axioms decode_terminates
example : decode [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 192, 12, 0, 1, 0, 1] ≠ .error .exhausted :=
  decode_terminates _

/-- A question whose name is a pointer to itself. -/
def loopMsg : Bytes := [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 192, 12, 0, 1, 0, 1]

#print axioms decode_rejects_forward_pointer
example : readName 5 loopMsg loopMsg.length 12 = .error .forwardPointer :=
  decode_rejects_forward_pointer 4 loopMsg _ 12 192 12 (by decide) (by decide +kernel) (by decide +kernel)
    (by decide) (by decide)

#print axioms compress_only_rfc1035_types
example : (encRData true 40 [([EX, COM], 12)] 16 (.names [] [[EX, COM]] [])).1 =
    (encRData true 0 [] 16 (.names [] [[EX, COM]] [])).1 :=
  (compress_only_rfc1035_types true 40 _ 16 _ rfl).1

#print axioms unknown_rdata_verbatim
example : (encRData true 7 [([EX, COM], 12)] 99 (.octets [2, 3, 4])).1 = slice [1, 2, 3, 4, 5] 1 3 :=
  (unknown_rdata_verbatim [1, 2, 3, 4, 5] 99 1 3 (.octets [2, 3, 4]) true 7 _ rfl
    (eq_ok_of_isOk (by decide +kernel))).2

/-- A query for `WwW.example.com. A` with ID 0x1234, and a reply with ID 0xabcd that says `www`. -/
def query : Bytes := [18, 52, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0] ++
  [3, 87, 119, 87, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1]
def reply : Bytes := [171, 205, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0] ++
  [3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1] ++
  [192, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1]
def restored : Bytes := [18, 52, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0] ++
  [3, 87, 119, 87, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1] ++
  [192, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1]

#print axioms restore_changes_only_id_and_case
example : restored.length = reply.length ∧ restored.take 2 = query.take 2 :=
  let h := restore_changes_only_id_and_case reply query restored (eq_ok_of_isOk (by decide +kernel))
  ⟨h.1, h.2.1⟩

end Wire

/-! ## `Dns/Fit.lean` -/

section Fit
open Wire Fit

def rrA (n : Name) : RR := ⟨n, 1, 1, 300, .octets [192, 0, 2, 1]⟩
def rrTxt (n : Name) (k : Nat) : RR := ⟨n, 16, 1, 300, .octets (List.replicate k 65)⟩
def optRR : RR := ⟨[], 41, 1232, 0, .octets []⟩

/-- An answer that fits in 512 octets, required glue that fits, and optional data that does not. -/
def resp : Resp :=
  ⟨⟨1, 33152⟩, [⟨[WWW, EX, COM], 1, 1⟩], [[rrA [WWW, EX, COM]]], [], [[rrA [NS, EX, COM]], [rrTxt [EX, COM] 600]],
    1, some optRR⟩

theorem resp_base : fits resp .udp512 [] [] [] = true := by decide +kernel

#print axioms fit_size_le
example : (fit resp .udp512).1.length ≤ 512 := fit_size_le resp .udp512 resp_base

#print axioms fit_whole_rrsets
example : (plan resp .udp512).additional <+: resp.additional := (fit_whole_rrsets resp .udp512).2.2.1

#print axioms fit_keeps_opt
example : ∃ m, (fit resp .udp512).1 = encode true m ∧ m.additional.getLast? = some optRR :=
  fit_keeps_opt resp .udp512 optRR rfl

#print axioms tc_iff_required_dropped
example : (plan resp .udp512).tc = false := by
  cases h : (plan resp .udp512).tc with
  | false => rfl
  | true =>
    exact absurd ⟨by decide +kernel, by decide +kernel, by decide +kernel⟩
      ((tc_iff_required_dropped resp .udp512).mp h)

#print axioms additional_drop_no_tc
example : (plan resp .udp512).tc = (plan { resp with additional := resp.additional.take resp.required } .udp512).tc :=
  (additional_drop_no_tc resp .udp512).1

end Fit


/-! ## `Dns/Zone.lean` -/

section Zone
open Zone

def apex : Name := [EX, COM]
def soaData : Zone.RData := .soa [NS, EX, COM] [HOST, EX, COM] 1 7200 3600 1209600 300
def L61 : Label := List.replicate 61 120
/-- A DNAME target of 249 octets: a one-label name below `d.example.com.` substitutes to more than 255. -/
def longTarget : Name := [L61, L61, L61, L61]
def wwwTxt : RRset := ⟨[WWW, EX, COM], 16, 300, [.txt [[104, 105]]]⟩
def dSet : RRset := ⟨[LD, EX, COM], 39, 100, [.dname longTarget]⟩
def subNs : RRset := ⟨[SUB, EX, COM], 2, 86400, [.ns [NS1, SUB, EX, COM]]⟩
def subGlue : List RRset := [⟨[NS1, SUB, EX, COM], 1, 86400, [.a [192, 0, 2, 53]]⟩]

/-- `example.com.`: an apex NS with in-zone address, `www` TXT, a wildcard TXT, `a.b` (so `b` is an empty
non-terminal), a DNAME at `d` to a long target, an MX, and a delegation of `sub` with in-domain glue. -/
def spec : Spec := ⟨apex, 3600, soaData, [
    ⟨apex, 2, 3600, [.ns [NS, EX, COM]]⟩,
    ⟨[NS, EX, COM], 1, 3600, [.a [192, 0, 2, 1]]⟩,
    wwwTxt,
    ⟨[STAR, EX, COM], 16, 60, [.txt [[119]]]⟩,
    ⟨[LA, LB, EX, COM], 1, 60, [.a [192, 0, 2, 2]]⟩,
    dSet,
    ⟨[MAIL, EX, COM], 15, 300, [.mx 10 [NS, EX, COM]]⟩],
  [⟨[SUB, EX, COM], 86400, [[NS1, SUB, EX, COM]], subGlue, none⟩]⟩

def zone : Zone := spec.assemble

theorem spec_ok : spec.okAll = true := by decide +kernel
theorem build_spec : build spec = .ok zone := by simp [build, spec_ok, zone]
theorem zone_wf : zone.WF := build_wf spec zone build_spec
theorem zone_apex : zone.apex = apex := rfl

theorem under_apex {q : Name} (h : apex <:+ q) : zone.apex <:+ q := h

/-- `x.b.example.com.`: `b` exists (it has a name below it), so it is the closest encloser and blocks the apex
wildcard; there is no `*.b`. -/
def qNx : Request := ⟨[LX, LB, EX, COM], 1⟩
theorem nx_answer : answer zone qNx .all = .response ⟨.nxdomain, true, [], [negSoa zone.soa], [], 0⟩ := by
  decide +kernel

#print axioms nxdomain_iff
example : zone.NoStop qNx.qname ∧ zone.presentB qNx.qname = false ∧
    zone.presentB (wild (zone.closest qNx.qname)) = false :=
  (nxdomain_iff zone qNx .all (by decide +kernel)).mp ⟨_, nx_answer, rfl, rfl⟩

#print axioms ent_is_nodata
example : answer zone ⟨[LB, EX, COM], 1⟩ .all = .response ⟨.noerror, true, [], [negSoa zone.soa], [], 0⟩ :=
  have hq : zone.apex <:+ [LB, EX, COM] := by decide +kernel
  have hs := zone.spec_of_locate hq (L := .node [LB, EX, COM] .empty) (eq_ok_of_isOk (by decide +kernel))
  ent_is_nodata zone ⟨[LB, EX, COM], 1⟩ .all hq hs.2.1 (by decide +kernel) (by decide +kernel)

def qSub : Request := ⟨[WWW, SUB, EX, COM], 1⟩
theorem sub_below : zone.BelowCut qSub.qname [SUB, EX, COM] subNs none subGlue :=
  zone.spec_of_locate (by decide +kernel) (L := .cut [SUB, EX, COM] subNs none subGlue)
    (eq_ok_of_isOk (by decide +kernel))

#print axioms referral_iff_below_cut
example : ∃ r, answer zone qSub .all = .response r ∧ r.rcode = .noerror ∧ r.answer = [] ∧ r.aa = false :=
  (referral_iff_below_cut zone qSub .all (by decide +kernel)).mpr
    (Or.inl ⟨_, _, _, _, sub_below, by decide⟩)

#print axioms referral_aa_false
example : ∃ r, answer zone qSub .all = .response r ∧ r.aa = false ∧ r.answer = [] ∧ r.authority = [subNs] ∧
    r.rcode = .noerror :=
  referral_aa_false zone qSub .all (by decide +kernel) sub_below (by decide)

#print axioms negative_has_soa
example : negSoa zone.soa ∈ [negSoa zone.soa] := negative_has_soa zone qNx .all nx_answer (Or.inl rfl)

#print axioms neg_ttl_min
example : ∃ s ∈ [negSoa zone.soa], s.owner = zone.soa.owner ∧ s.rtype = zone.soa.rtype ∧ s.ttl = min 3600 300 :=
  neg_ttl_min zone qNx .all (minimum := 300) rfl nx_answer (Or.inl rfl)

#print axioms answer_in_zone
example (r : Response) (h : answer zone ⟨[MAIL, EX, COM], 15⟩ .all = .response r) :
    ∀ s ∈ r.answer ++ r.authority ++ r.additional, apex <:+ s.owner :=
  answer_in_zone zone zone_wf _ .all h

#print axioms wildcard_blocked_by_node
/-- `www.example.com. TXT` answers with `www`'s own TXT, not the wildcard's. -/
example : ∃ r, answer zone ⟨[WWW, EX, COM], 16⟩ .all = .response r ∧ r.rcode = .noerror ∧ r.aa = true ∧
    r.answer = [withOwner [WWW, EX, COM] wwwTxt] :=
  have hq : zone.apex <:+ [WWW, EX, COM] := by decide +kernel
  have hs := zone.spec_of_locate hq (L := .node [WWW, EX, COM] (.data [wwwTxt]))
    (eq_ok_of_isOk (by decide +kernel))
  wildcard_blocked_by_node zone ⟨[WWW, EX, COM], 16⟩ .all hq hs.2.1 (sets := [wwwTxt]) (by decide +kernel) (by decide)
    (by decide +kernel)

#print axioms dname_yx_iff_long
example : ∃ r, answer zone ⟨[HOST, LD, EX, COM], 1⟩ .all = .response r ∧ r.rcode = .yxdomain ∧ r.answer = [dSet] :=
  have hq : zone.apex <:+ [HOST, LD, EX, COM] := by decide +kernel
  have hs := zone.spec_of_locate hq (L := .dname [LD, EX, COM] dSet) (eq_ok_of_isOk (by decide +kernel))
  have ⟨s, hd⟩ := hs
  (dname_yx_iff_long zone ⟨[HOST, LD, EX, COM], 1⟩ .all hq hd (dt := longTarget) rfl).mpr (by decide +kernel)

/-- A CNAME at the apex is rejected; the example zone is accepted, so it satisfies every rule. -/
def badSpec : Spec := { spec with sets := ⟨apex, 5, 300, [.cname [WWW, EX, COM]]⟩ :: spec.sets }

#print axioms builder_rejects_iff
example : ¬ badSpec.Valid :=
  (builder_rejects_iff badSpec).mp ⟨badSpec.firstError, by simp [build, show badSpec.okAll = false by decide +kernel]⟩
example : spec.Valid :=
  Classical.byContradiction fun h =>
    have ⟨e, he⟩ := (builder_rejects_iff spec).mpr h
    by rw [build_spec] at he; cases he

end Zone

/-! ## `Dns/Partial.lean` -/

section Partial
open Zone

def apexNode : Node := nodeAt (mergeSets (spec.soaSet :: spec.sets.filter (·.owner == apex)))

/-- What a lazy authority knew when asked `x.b.example.com.`: the apex, `b` exists, `x.b` and `*.b` do not. -/
def facts : List (Name × Fact Node) :=
  [(apex, .present apexNode), ([LB, EX, COM], .present .empty), ([LX, LB, EX, COM], .absent),
    (wild [LB, EX, COM], .absent)]
def view : View := View.ofFacts apex zone.soa facts 1

theorem view_answer : answerPartial view qNx .all = .response ⟨.nxdomain, true, [], [negSoa zone.soa], [], 0⟩ := by
  decide +kernel

#print axioms answer_partial_sound
example : ∀ z, Agrees view z → answer z qNx .all = .response ⟨.nxdomain, true, [], [negSoa zone.soa], [], 0⟩ :=
  answer_partial_sound view qNx .all _ view_answer

#print axioms agreeing_zone_exists
example : ∃ z, Agrees view z := agreeing_zone_exists apex zone.soa facts 1 (by unfold Consistent; decide +kernel)

/-- A view that knows only the apex: `www.example.com.` is unknown, so the answer is unknown, not NXDOMAIN. -/
def apexOnly : View := View.ofFacts apex zone.soa [(apex, .present apexNode)] 1

theorem apexOnly_reaches : apexOnly.Reaches [WWW, EX, COM] := by
  intro m h1 h2 h3
  have hm : m <:+ [EX, COM] := suffix_cons_ne h2 h1
  have : m = apex := List.IsSuffix.eq_of_length hm (Nat.le_antisymm hm.length_le h3.length_le)
  subst this
  have hb : (match apexNode with | .dname _ _ => true | _ => false) = false := by decide +kernel
  exact ⟨apexNode, by decide +kernel, (fun d s h => by rw [h] at hb; cases hb), fun h => absurd rfl h⟩

#print axioms unknown_never_negative
example : answerPartial apexOnly ⟨[WWW, EX, COM], 1⟩ .all = .unknown [WWW, EX, COM] :=
  (unknown_never_negative apexOnly ⟨[WWW, EX, COM], 1⟩ .all (by decide +kernel) apexOnly_reaches).1
    (by decide +kernel)

/-- A provider that knows `www.example.com.` and says everything else is absent. -/
def provider : Provider := fun n => if n = [WWW, EX, COM] then .present [wwwTxt] else .absent
def lazy0 : Lazy := ⟨apex, zone.soa, [(apex, apexNode)], 0⟩

#print axioms lazy_view_one_revision
example : Agrees (lazyView provider lazy0 [WWW, EX, COM]).1 (lazyView provider lazy0 [WWW, EX, COM]).2.zone ∧
    (lazyView provider lazy0 [WWW, EX, COM]).2.revision = 1 :=
  ⟨(lazy_view_one_revision provider lazy0 [WWW, EX, COM]).2.1, by decide +kernel⟩

end Partial

/-! ## `Dns/Authority.lean` -/

section Authority
open Authority

def req : Req := ⟨query, 7, false⟩
def known : Known := [(relayAsk req, .reply reply)]

theorem relay_replies : respond relay req known = .reply restored := by decide +kernel

#print axioms respond_monotone
example : respond relay req (known ++ [(⟨9, true, []⟩, .timeout)]) = .reply restored := by
  rw [respond_monotone relay req known _ (Known.extends_append _ _) (by rw [relay_replies]; intro a h; cases h),
    relay_replies]

#print axioms loop_terminates
example : ∃ s, loop relay req (fun _ => .reply reply) 2 [] = some s ∧ ∀ a, s ≠ .need a :=
  relay_loop_terminates req _

/-- An overlay that answers `fict.com.` itself on a relayed `com.`. -/
def fict : Overlay :=
  ⟨relay, zones fun _ => some [0], fun r => r.addr == 1, fun r => r.addr == 2, fun _ => true,
    fun r => ⟨r.addr, r.stream, [1]⟩, fun _ ds => ds.getD [2]⟩

example : ∃ s, loop (overlay fict) req (fun _ => .timeout) 3 [] = some s ∧ ∀ a, s ≠ .need a :=
  overlay_loop_terminates fict _ rfl rfl req _

#print axioms relay_never_guesses
example : ∃ obs, known.get (relayAsk req) = some (.reply obs) ∧ Wire.restore obs req.query = .ok restored ∧
    restored.length = obs.length ∧ restored.take 2 = req.query.take 2 :=
  relay_never_guesses req known restored relay_replies

end Authority

/-! ## `Dns/Exchange.lean` -/

section Exchange
open Exchange

def tup : Tuple := ⟨53, false, 4660, [WWW, EX, COM], 1, 1⟩
def st : State := ⟨2, 5, [⟨⟨2, 4⟩, tup⟩], [], [1]⟩
def good : Reply := ⟨⟨2, 4⟩, 53, false, 4660, [WWW, EX, COM], 1, 1, [1, 2, 3]⟩
/-- The same reply bearing a token from the session before. -/
def stale : Reply := { good with token := ⟨1, 4⟩ }

#print axioms obsolete_ignored
example : onReply true st stale = (st, .ignored) := obsolete_ignored true st stale (by decide)

#print axioms match_requires_tuple
example : ∃ p ∈ st.pending, p.token = good.token ∧ good.source = p.tuple.to :=
  have ⟨p, hp, h1, _, h3, _⟩ := (match_requires_tuple true st good).1 (by decide)
  ⟨p, hp, h1, h3⟩

#print axioms advance_clears
example : (advance st 3).1.pending = [] ∧ (advance st 3).1.cache = [] ∧ (advance st 3).2 = [⟨2, 4⟩] :=
  have h := advance_clears true st 3 (by decide)
  ⟨h.2.1, h.2.2.1, h.2.2.2.2.1⟩

end Exchange

end Dns.Examples
