/-
  The axioms each headline theorem depends on, and an example applying each theorem to a concrete input.

  Expected: every `#print axioms` line lists only `propext`, `Quot.sound`, and `Classical.choice`, Lean's
  standard axioms, or a subset of them. `sorryAx` would mean an unfinished proof. Facts about concrete inputs
  are checked by the kernel (`decide +kernel`), which adds no axiom. The DNSSEC examples use the concrete
  signature scheme `Dnssec.Symbolic.scheme`.
-/
import Dns.Name
import Dns.Wire
import Dns.Fit
import Dns.Zone
import Dns.Partial
import Dns.Authority
import Dns.Exchange
import Dns.Dnssec
import Dns.Policy
import Dns.Records
import Dns.Chain
import Dns.Cache
import Dns.Resolver

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
example : ∀ z, Agrees view z → ∃ r, answer z qNx .all = .response r ∧
    Response.Grows ⟨.nxdomain, true, [], [negSoa zone.soa], [], 0⟩ r :=
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
open Authority Zone

/-- What a real server of `example.com.` sent when asked `x.b.example.com.`: the apex, `b` (an empty
non-terminal), and that `x.b` and `*.b` do not exist, with no denial records, as the zone is unsigned. -/
def filed : List Filing :=
  [.node apex apexNode, .node [LB, EX, COM] .empty, .denied [LX, LB, EX, COM] [], .denied (wild [LB, EX, COM]) []]

/-- The denial records the servers of the unsigned `example.com.` send: none. -/
def noProofs : Proofs := fun _ => []

/-- A copy of `example.com.` that has filed that response. -/
def copy : Learned := ⟨apex, zone.soa, filed, 1, []⟩

theorem filed_true : (Looked.response filed).of zone noProofs = true := by decide +kernel
theorem copy_copied : Copied zone noProofs copy := ⟨rfl, rfl, by decide +kernel, rfl⟩

/-- Were the zone signed, its servers would send an NSEC record for `x.b.example.com.`, and a filing without it
would not be true of the zone. -/
def nsecProofs : Proofs := fun n => [⟨n, 47, 300, []⟩]
example : (Looked.response filed).of zone nsecProofs = false := by decide +kernel

def nxResponse : Response := ⟨.nxdomain, true, [], [negSoa zone.soa], [], 0⟩

theorem copy_answer : answerPartial copy.view qNx .all = .response nxResponse := by decide +kernel

#print axioms learned_answer_upstream
example : ∃ r, answer zone qNx .all = .response r ∧ nxResponse.Grows r :=
  learned_answer_upstream copy_copied qNx .all copy_answer

#print axioms learned_nxdomain_proved
example : ∃ n m, copy.fact n = .absent ∧ m <:+ n ∧ copy.proof m = some (noProofs m) :=
  learned_nxdomain_proved copy_copied copy_answer rfl

/-- A copy that has filed only the apex: `www.example.com.` is unknown, so the answer is unknown, not
NXDOMAIN. -/
def apexCopy : Learned := ⟨apex, zone.soa, [.node apex apexNode], 1, []⟩

theorem apexCopy_reaches : apexCopy.view.Reaches [WWW, EX, COM] := by
  intro m h1 h2 h3
  have hm : m <:+ [EX, COM] := suffix_cons_ne h2 h1
  have : m = apex := List.IsSuffix.eq_of_length hm (Nat.le_antisymm hm.length_le h3.length_le)
  subst this
  have hb : (match apexNode with | .dname _ _ => true | _ => false) = false := by decide +kernel
  exact ⟨apexNode, by decide +kernel, (fun d s h => by rw [h] at hb; cases hb), fun h => absurd rfl h⟩

#print axioms learned_unknown_never_negative
example : answerPartial apexCopy.view ⟨[WWW, EX, COM], 1⟩ .all = .unknown [WWW, EX, COM] :=
  (learned_unknown_never_negative apexCopy ⟨[WWW, EX, COM], 1⟩ .all (by decide +kernel) apexCopy_reaches).1
    (by decide +kernel)

/-- The real server, answering every lookup with the response above. -/
def upstream : Lookup → Looked := fun _ => .response filed

#print axioms learned_answer_stable
example : ∃ r, answerPartial (copy.file (upstream ⟨1, apex, qNx⟩)).view qNx .all = .response r ∧
    nxResponse.Grows r :=
  learned_answer_stable copy_copied filed_true copy_answer

/-- The server at address 1, holding only the apex, looks `x.b.example.com.` up once and answers NXDOMAIN. -/
theorem serve_nx : (serve .all 1 upstream 2 apexCopy [] qNx).2 = .reply nxResponse := by decide +kernel

#print axioms loop_bounded
example : loop (respond .all 1) upstream 9 apexCopy [] qNx = loop (respond .all 1) upstream 2 apexCopy [] qNx :=
  loop_bounded (respond .all 1) upstream qNx apexCopy _ (respond_needs .all 1 apex qNx) 7

#print axioms serve_one_lookup
example : (serve .all 1 upstream 7 apexCopy [] qNx).2 = .reply nxResponse := by
  rw [serve_one_lookup .all 1 upstream 5]; exact serve_nx

/-- With the real server unreachable, the server stays silent rather than guess. -/
example : (serve .all 1 (fun _ => .nothing) 2 apexCopy [] qNx).2 = .silent := by decide +kernel

/-- With the real server answering SERVFAIL, the server answers SERVFAIL too, never silence (RFC 8906 §3.1). -/
example : (serve .all 1 (fun l => .failed l.server l.req .servfail) 2 apexCopy [] qNx).2 =
    .reply (bare .servfail) := by decide +kernel

theorem apexCopy_copied : Copied zone noProofs apexCopy := ⟨rfl, rfl, by decide +kernel, rfl⟩

#print axioms serve_reply_upstream
example : ∃ r, answer zone qNx .all = .response r ∧ nxResponse.Grows r :=
  serve_reply_upstream (fun _ => filed_true) apexCopy_copied serve_nx

#print axioms serve_nxdomain_proved
example : ∃ n m, (serve .all 1 upstream 2 apexCopy [] qNx).1.fact n = .absent ∧ m <:+ n ∧
    (serve .all 1 upstream 2 apexCopy [] qNx).1.proof m = some (noProofs m) :=
  serve_nxdomain_proved (fun _ => filed_true) apexCopy_copied serve_nx rfl

/-- A zone invented at `b.example.com.` below the copy of `example.com.`, at a server that is not one of its
name servers. The parent's servers answer `b.example.com. DS` with AA, so the overlay refers questions below
`b` with the authority section of that answer. -/
def invented : Overlay where
  own := false
  inner := fun _ => nxResponse
  below := fun q => [LB, EX, COM].isSuffixOf q.qname
  ds := ⟨[LB, EX, COM], 43⟩
  serves := fun r => r.aa
  referral := fun _ r => ⟨.noerror, false, [], r.authority, [], 0⟩
  unsigned := fun _ r => r

theorem invented_stable : invented.Stable :=
  ⟨fun _ _ h => h.2.1.symm, fun _ _ _ h => by simp only [invented, h.2.2.2.1], fun _ _ _ h => h⟩

def qBelow : Request := ⟨[WWW, LB, EX, COM], 1⟩
def referralToB : Response := ⟨.noerror, false, [], [negSoa zone.soa], [], 0⟩

#print axioms overlay_needs
example : Needs (overlay invented (respond .all 1)) apex qBelow [⟨1, apex, invented.ds⟩, ⟨1, apex, qBelow⟩] :=
  overlay_needs invented .all 1 apex qBelow

/-- Holding only the apex, the overlay looks `b.example.com. DS` up once and refers the question. -/
theorem overlay_refers : (loop (overlay invented (respond .all 1)) upstream 3 apexCopy [] qBelow).2 =
    .reply referralToB := by decide +kernel

#print axioms overlay_loop_bounded
example : (loop (overlay invented (respond .all 1)) upstream 8 apexCopy [] qBelow).2 = .reply referralToB := by
  rw [overlay_loop_bounded invented .all 1 upstream 5]; exact overlay_refers

theorem copy_refers : overlay invented (respond .all 1) copy qBelow = .reply referralToB := by decide +kernel

#print axioms overlay_reply_stable
example : ∃ r, overlay invented (respond .all 1) (copy.file (upstream ⟨1, apex, qBelow⟩)) qBelow = .reply r ∧
    referralToB.Grows r :=
  overlay_reply_stable copy_copied filed_true invented_stable copy_refers

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

/-! ## `Dns/Dnssec.lean` -/

section Dnssec
open Zone Dnssec

abbrev Sch := Symbolic.scheme

/-- A KSK and a ZSK with ECDSA P-256 (algorithm 13), holding private keys 7 and 8. -/
def ksk : Signer Sch := Signer.ofPriv (S := Sch) (7 : Nat) 13 true
def zsk : Signer Sch := Signer.ofPriv (S := Sch) (8 : Nat) 13 false

/-- The example zone signed with NSEC, its signatures valid from 100 to 200. -/
def signedZone : SignedZone Sch := ⟨zone, [ksk, zsk], ⟨100, 200⟩, .nsec⟩

theorem honest_ofPriv (p alg : Nat) (sep : Bool) : (Signer.ofPriv (S := Sch) p alg sep).Honest :=
  ⟨p, rfl, fun _ => rfl⟩

theorem signedZone_well : SignsWell signedZone Policy.iana 150 := by
  refine ⟨fun s hs => ?_, ⟨zsk, by simp [signedZone, dataSigners, ksk, zsk, Signer.ofPriv], by decide⟩, by decide⟩
  simp only [signedZone, List.mem_cons, List.mem_nil_iff, or_false] at hs
  rcases hs with rfl | rfl <;> exact honest_ofPriv _ _ _

#print axioms signed_answers_validate
/-- `www.example.com. TXT`, with the RRSIGs the signed zone serves, validates Secure under its anchor. -/
theorem www_secure : validateRrset (some [signedZone.anchor 2]) Policy.iana 150 [signedZone.link] wwwTxt
    (signedZone.sigsFor wwwTxt) [] = .secure :=
  signed_answers_validate signedZone Policy.iana 150 2 signedZone_well (by decide)
    ⟨ksk, by simp [signedZone], rfl, by decide⟩
    zone_wf [] (nd := .data [wwwTxt]) (by decide +kernel) (by intro _ _ _ h; cases h)
    ⟨wwwTxt, by simp [nodeSets], rfl, rfl⟩ (by decide)

#print axioms secure_sound
/-- So the TXT records were signed with the private key of a key vouched for from the anchor. -/
example : ∃ apex k p r x, Vouched [signedZone.anchor 2] [signedZone.link] apex k ∧ Sch.pub p = k.pub ∧
    r ∈ signedZone.sigsFor wwwTxt ∧ expanded r.hdr wwwTxt = some x ∧ x.rdata = wwwTxt.rdata ∧
    r.sig = Sch.sign p ⟨r.hdr, .rrset x⟩ :=
  have ⟨apex, k, p, r, x, hv, hp, hr, _, _, hx, _, hd, hs⟩ := secure_sound www_secure
  ⟨apex, k, p, r, x, hv, hp, hr, hx, hd, hs⟩

/-- `x.example.com. TXT` is expanded from `*.example.com.`; the NSEC that proves no closer name exists comes with
it, and the answer validates Secure. -/
example : (signedZone.answerDo ⟨[LX, EX, COM], 16⟩ .all).2.map (fun sa =>
    (validateAnswer (some [signedZone.anchor 2]) Policy.iana 150 [signedZone.link] ⟨[LX, EX, COM], 16⟩ sa).1) =
    some [.secure] := by
  decide +kernel

#print axioms secure_complete
example : validateRrset (some [signedZone.anchor 2]) Policy.iana 150 [signedZone.link] wwwTxt
    (signedZone.signSet wwwTxt).sigs [] = .secure :=
  secure_complete ⟨signedZone.link, [], signedZone.keys, signedZone.apex, signedZone.keys,
    ⟨_, anchorFor_zone signedZone 2 (by decide), rfl, rfl,
      anchor_keys signedZone_well (by decide) (s0 := ksk) (by simp [signedZone]) rfl (by decide)⟩,
    .nil, signSet_final signedZone_well [] rfl rfl rfl⟩

/-- An anchor whose only DS names an RSASHA1 key (algorithm 5), and a chain whose DNSKEY fetch failed. -/
def sha1Anchor : Anchor := ⟨apex, [⟨5, 2, [1, 2, 3]⟩]⟩
def brokenChain : Chain Sch := [⟨apex, none, none⟩]

#print axioms insecure_needs_proof
/-- Insecure, and the reason is the unsupported DS set, although the DNSKEY set is missing. -/
example : InsecureCase [sha1Anchor] Policy.iana 150 wwwTxt.owner brokenChain .unsupportedAlgorithm :=
  (insecure_needs_proof (set := wwwTxt) (sigs := []) (ds := [])
    (Policy.sha1_ds_insecure (a := sha1Anchor) (l0 := ⟨apex, none, none⟩) (ls0 := []) (by decide) rfl rfl (by decide)
      (by decide))).resolve_right fun h => nomatch h.1

#print axioms insecure_complete
/-- With no anchor at or above the name, the answer is Insecure. -/
example : ∃ w, validateRrset (some []) Policy.iana 150 brokenChain wwwTxt [] ([] : List (Signed Sch)) =
    .insecure w :=
  insecure_complete (Or.inl ⟨rfl, rfl⟩)

/-- The zone signed with NSEC3 and opt-out, and a denial made of one opt-out NSEC3. -/
def optOutZone : SignedZone Sch := ⟨zone, [ksk, zsk], ⟨100, 200⟩, .nsec3 true⟩
def optOutRecord : Nsec3 := ⟨apex, 5, 9, [], true, 0⟩
def optOutDenial : List (Signed Sch) := [optOutZone.signNsec3 optOutRecord]

#print axioms optout_never_secure_denial
example : validateDenial (some [optOutZone.anchor 2]) Policy.iana 150 [optOutZone.link] ⟨[LX, EX, COM], 1⟩
    .nxdomain optOutDenial ≠ .secure := by
  have hw : walk [optOutZone.anchor 2] Policy.iana 150 [LX, EX, COM] [optOutZone.link] =
      .trusted apex optOutZone.keys := by decide +kernel
  have hn : nsecs (verified Policy.iana 150 apex optOutZone.keys optOutDenial) = [] := by decide +kernel
  have h3 : nsec3s (verified Policy.iana 150 apex optOutZone.keys optOutDenial) = [optOutRecord] := by
    decide +kernel
  refine optout_never_secure_denial rfl hw (by rw [hn]; rfl) fun _ _ r hr _ => ?_
  rw [h3, List.mem_singleton] at hr
  rw [hr]; rfl

#print axioms optout_wildcard_insecure
/-- In the opt-out zone, `x.example.com. TXT` is expanded from `*.example.com.`, and only an opt-out NSEC3
backs the expansion, so the answer is Insecure. -/
example : (optOutZone.answerDo ⟨[LX, EX, COM], 16⟩ .all).2.map (fun sa =>
    (validateAnswer (some [optOutZone.anchor 2]) Policy.iana 150 [optOutZone.link] ⟨[LX, EX, COM], 16⟩ sa).1) =
    some [.insecure .optOutCovered] := by
  decide +kernel

#print axioms nsec_cover_sound
/-- An NSEC of the complete chain covers `x.b.example.com.`, so nothing is at or below it. -/
example : zone.presentB [LX, LB, EX, COM] = false := by
  obtain ⟨r, hr, hc⟩ : ∃ r ∈ signedZone.nsecChain, nsecNone r [LX, LB, EX, COM] = true := by decide +kernel
  exact nsec_cover_sound signedZone hr hc

#print axioms white_lie_covers_only_qname
example {x : Nat} (hx : x < Sch.hashSpace)
    (h : covers3 (whiteLie (S := Sch) apex true [WWW, EX, COM]).hash
      (whiteLie (S := Sch) apex true [WWW, EX, COM]).next x = true) : x = Sch.hash [WWW, EX, COM] :=
  white_lie_covers_only_qname apex true _ hx h

/-- A view that knows only the apex. -/
def apexView (n : Name) : Fact Node := if n = apex then .present apexNode else .unknown

#print axioms cover_unknown_is_unknown
example : cover (S := Sch) apexView apex .nsec [WWW, EX, COM] .name = .unknown :=
  (cover_unknown_is_unknown apexView apex .nsec [WWW, EX, COM] .name).1 (by decide)

end Dnssec

/-! ## `Dns/Policy.lean` -/

section Policy
open Zone Dnssec

/-- An RSASHA1 key (algorithm 5), and the zone signed only with it. -/
def rsaSha1 : Signer Sch := Signer.ofPriv (S := Sch) (9 : Nat) 5 true
def sha1Zone : SignedZone Sch := ⟨zone, [rsaSha1], ⟨100, 200⟩, .nsec⟩

#print axioms Policy.iana_matches_registry
#print axioms Policy.sha1_never_secure
example : validateRrset (some [sha1Zone.anchor 1]) Policy.iana 150 [sha1Zone.link] wwwTxt
    (sha1Zone.signSet wwwTxt).sigs [] ≠ .secure :=
  Policy.sha1_never_secure (by decide +kernel)

#print axioms Policy.unsupported_is_insecure_not_bogus
example : validateRrset (some [sha1Anchor]) Policy.iana 150 brokenChain wwwTxt [] [] =
    .insecure (unsupportedWhy Policy.iana sha1Anchor.ds) :=
  Policy.unsupported_is_insecure_not_bogus (by decide) rfl rfl (by decide) (by decide)

#print axioms Policy.not_performed_never_ad
example : adBit (validateRrset none Policy.iana 150 [signedZone.link] wwwTxt (signedZone.sigsFor wwwTxt) [])
    true false = false := by
  have h := Policy.not_performed_never_ad Policy.iana 150 [signedZone.link] wwwTxt (signedZone.sigsFor wwwTxt) []
    ⟨apex, 1⟩ .noerror true false
  rw [h.1]; exact h.2.2.1

end Policy

/-! ## `Dns/Records.lean` -/

section Records
open Zone Dnssec Records

def ORG : Label := [111, 114, 103]
def orgApex : Name := [EX, ORG]

/-- `example.org.`: an apex NS with an address, `www` A, and an MX whose target has an address. -/
def orgSpec : Spec := ⟨orgApex, 3600, .soa [NS, EX, ORG] [HOST, EX, ORG] 1 7200 3600 1209600 300, [
    ⟨orgApex, 2, 3600, [.ns [NS, EX, ORG]]⟩,
    ⟨[NS, EX, ORG], 1, 3600, [.a [192, 0, 2, 7]]⟩,
    ⟨[WWW, EX, ORG], 1, 300, [.a [192, 0, 2, 8]]⟩,
    ⟨[MAIL, EX, ORG], 15, 300, [.mx 10 [NS, EX, ORG]]⟩], []⟩

def orgZone : Zone := orgSpec.assemble
def orgApexNode : Node := nodeAt (mergeSets (orgSpec.soaSet :: orgSpec.sets.filter (·.owner == orgApex)))

/-- A lazy zone that starts with only the apex node and asks its provider for the rest. -/
def orgLazy : Lazy := ⟨orgZone.apex, orgZone.soa, [(orgZone.apex, orgApexNode)], 0⟩

theorem orgLazy_holds : HoldsPart orgLazy orgZone :=
  holdsPart_apex orgZone orgApexNode 0 (by decide +kernel) (by decide +kernel)

theorem orgLazy_describable : Describable orgLazy orgZone := describable_of _ _ (by decide +kernel)

#print axioms lazy_agrees_complete
/-- The MX question reads the MX target's address, which the lazy zone gets from its provider. -/
example : lazyAnswer (zoneProvider orgZone) orgLazy ⟨[MAIL, EX, ORG], 15⟩ .all =
    answer orgZone ⟨[MAIL, EX, ORG], 15⟩ .all :=
  lazy_agrees_complete orgLazy_holds orgLazy_describable (zoneProvider_agrees _ _) _ _

example : answer orgZone ⟨[MAIL, EX, ORG], 15⟩ .all = .response ⟨.noerror, true,
    [⟨[MAIL, EX, ORG], 15, 300, [.mx 10 [NS, EX, ORG]]⟩], [],
    [⟨[NS, EX, ORG], 1, 3600, [.a [192, 0, 2, 7]]⟩], 0⟩ := by
  decide +kernel

/-- A second implementation of `Sign`: a bare private key with its algorithm and SEP bit. -/
structure RawKey where
  priv : Nat
  alg : Nat
  sep : Bool

instance : Sign RawKey Sch := ⟨fun k => ⟨Sch.pub k.priv, k.alg, k.sep⟩, fun k => Sch.sign k.priv⟩

def rawKeys : List RawKey := [⟨7, 13, true⟩, ⟨8, 13, false⟩]

theorem keys_agnostic : Agnostic (S := Sch) [ksk, zsk] rawKeys :=
  .cons rfl (fun _ => rfl) (.cons rfl (fun _ => rfl) .nil)

#print axioms signer_agnostic
example : publish (S := Sch) [ksk, zsk] orgZone.look orgApex orgZone.soa .all .nsec ⟨100, 200⟩ ⟨[WWW, EX, ORG], 1⟩ =
    publish (S := Sch) rawKeys orgZone.look orgApex orgZone.soa .all .nsec ⟨100, 200⟩ ⟨[WWW, EX, ORG], 1⟩ :=
  signer_agnostic keys_agnostic _ _ _ _ _ _ _

#print axioms validate_records_only
/-- The lazy zone signed by the `Signer`s and the complete zone signed by the raw keys lead the validator to the
same result. -/
example : validatePublished (some []) Policy.iana 150 [] none orgLazy.apex ⟨[MAIL, EX, ORG], 15⟩
      (publish (S := Sch) [ksk, zsk] (onDemand (zoneProvider orgZone) orgLazy) orgLazy.apex orgLazy.soa .all .nsec
        ⟨100, 200⟩ ⟨[MAIL, EX, ORG], 15⟩) =
    validatePublished (some []) Policy.iana 150 [] none orgZone.apex ⟨[MAIL, EX, ORG], 15⟩
      (publish (S := Sch) rawKeys orgZone.look orgZone.apex orgZone.soa .all .nsec ⟨100, 200⟩
        ⟨[MAIL, EX, ORG], 15⟩) :=
  validate_records_only orgLazy_holds orgLazy_describable (zoneProvider_agrees _ _) keys_agnostic _ _ _ _ _ _ _ _ _

end Records

/-! ## `Dns/Chain.lean` -/

section Chain
open Zone Dnssec Chain

/-- A KSK and a ZSK for `sub.example.com.`, holding private keys 17 and 18. -/
def childKsk : Signer Sch := Signer.ofPriv (S := Sch) (17 : Nat) 13 true
def childZsk : Signer Sch := Signer.ofPriv (S := Sch) (18 : Nat) 13 false
def subApex : Name := [SUB, EX, COM]

/-- The parent's DS record for the child's KSK: digest type 2 and the symbolic digest. -/
def subDs : Zone.RData := .ds 0 13 2 (Sch.digest subApex childKsk.dnskey)

/-- `example.com.` with a DS record at its `sub` delegation, and `sub.example.com.` itself. -/
def parentSpec : Spec :=
  { spec with delegations := [⟨subApex, 86400, [[NS1, SUB, EX, COM]], subGlue, some (86400, [subDs])⟩] }
def childSpec : Spec := ⟨subApex, 3600, .soa [NS1, SUB, EX, COM] [HOST, SUB, EX, COM] 1 7200 3600 1209600 300, [
    ⟨subApex, 2, 3600, [.ns [NS1, SUB, EX, COM]]⟩,
    ⟨[NS1, SUB, EX, COM], 1, 3600, [.a [192, 0, 2, 53]]⟩,
    ⟨[WWW, SUB, EX, COM], 1, 300, [.a [192, 0, 2, 80]]⟩], []⟩

def parentZone : SignedZone Sch := ⟨parentSpec.assemble, [ksk, zsk], ⟨100, 200⟩, .nsec⟩
def childZone : SignedZone Sch := ⟨childSpec.assemble, [childKsk, childZsk], ⟨100, 200⟩, .nsec⟩
def tree : Tree Sch := [parentZone, childZone]
def wwwSub : RRset := ⟨[WWW, SUB, EX, COM], 1, 300, [.a [192, 0, 2, 80]]⟩

theorem tree_check : check tree Policy.iana 150 = [] := by decide +kernel

theorem tree_wf : WellFormed tree := by
  refine ⟨fun z hz s hs => ?_, dsSets_of (by decide +kernel)⟩
  simp only [tree, List.mem_cons, List.mem_nil_iff, or_false] at hz
  rcases hz with rfl | rfl <;>
    (simp only [parentZone, childZone, List.mem_cons, List.mem_nil_iff, or_false] at hs
     rcases hs with rfl | rfl <;> exact honest_ofPriv _ _ _)

theorem childSpec_ok : childSpec.okAll = true := by decide +kernel
theorem child_wf : childZone.zone.WF := build_wf childSpec _ (by simp [build, childSpec_ok]; rfl)

theorem tree_path : Descends tree parentZone [childZone] childZone :=
  .cons (by simp [tree]) rfl .nil

/-- Each zone's ZSK, which signs its data, uses algorithm 13. -/
theorem tree_data : DataAlgorithms tree Policy.iana := by
  intro z hz _
  simp only [tree, List.mem_cons, List.mem_nil_iff, or_false] at hz
  rcases hz with rfl | rfl
  · exact ⟨zsk, by simp [parentZone, dataSigners, ksk, zsk, Signer.ofPriv], by decide⟩
  · exact ⟨childZsk, by simp [childZone, dataSigners, childKsk, childZsk, Signer.ofPriv], by decide⟩

#print axioms check_sound
/-- With no problem reported, `www.sub.example.com. A` validates Secure or Insecure down the chain. -/
example : validateRrset (some [parentZone.anchor 2]) Policy.iana 150 (chainOf parentZone [childZone]) wwwSub
      (childZone.sigsFor wwwSub) [] = .secure ∨
    ∃ w, validateRrset (some [parentZone.anchor 2]) Policy.iana 150 (chainOf parentZone [childZone]) wwwSub
      (childZone.sigsFor wwwSub) [] = .insecure w :=
  check_sound tree_check tree_wf tree_data (by decide) (by simp [tree])
    ⟨ksk, by simp [parentZone], rfl, by decide⟩ tree_path child_wf []
    (nd := .data [wwwSub]) (by decide +kernel) (by intro _ _ _ h; cases h) ⟨wwwSub, by simp [nodeSets], rfl, rfl⟩
    (by decide)

/-- And it is in fact Secure. -/
example : validateRrset (some [parentZone.anchor 2]) Policy.iana 150 (chainOf parentZone [childZone]) wwwSub
    (childZone.sigsFor wwwSub) [] = .secure := by
  decide +kernel

#print axioms check_complete
/-- At time 300 the parent's signatures have expired, and the check says so. -/
theorem window_reported : Problem.windowClosed apex 300 ∈ check [parentZone] Policy.iana 300 :=
  check_complete ⟨parentZone, List.mem_singleton_self _, rfl, rfl, by simp [parentZone], by decide⟩

#print axioms check_reports_real
/-- And what it reports is so: a zone of the tree has signers and a window that is closed at 300. -/
example : Holds [parentZone] Policy.iana 300 (.windowClosed apex 300) := check_reports_real window_reported

end Chain

/-! ## `Dns/Cache.lean` -/

section Cache
open Zone Dnssec Cache

def limits : Limits := ⟨604800, 30⟩
def wwwKey : Cache.Key := ⟨[WWW, EX, COM], 16⟩

/-- `www.example.com. TXT`, validated Secure with an RRSIG that expires at 400, cached at time 100. -/
def cache1 : Cache := insert 100 limits ⟨0, []⟩ (.positive wwwTxt .authAnswer .secure (some 400) none false)

theorem cache1_timed : WellTimed cache1 150 :=
  wellTimed_mono (insert_wellTimed (t := 0) (fun _ h => by cases h) (by decide)) (by decide)

theorem cache1_unique : Unique cache1 := insert_unique (c := ⟨0, []⟩) (by simp [Unique])

#print axioms served_ttl_le_original
example : ∃ e ∈ cache1.entries, ∃ s₀ r, e.key = wwwKey ∧ e.body = .positive s₀ r .secure ∧
    250 ≤ s₀.ttl ∧ [WWW, EX, COM] = s₀.owner ∧ 16 = s₀.rtype ∧ [.txt [[104, 105]]] = s₀.rdata :=
  served_ttl_le_original (s := { wwwTxt with ttl := 250 }) cache1_timed (by decide +kernel)

#print axioms expired_never_served
example : ∃ e ∈ cache1.entries, e.key = wwwKey ∧ e.generation = cache1.generation ∧ 150 < e.expires :=
  expired_never_served (s := .positive { wwwTxt with ttl := 250 } .secure) (by decide +kernel)

#print axioms rrsig_caps_ttl
example : ∀ e, entryFor 100 limits 0 (.positive wwwTxt .authAnswer .secure (some 400) none false) = some e →
    e.expires ≤ 400 :=
  fun _ h => rrsig_caps_ttl h

/-- A failure cached for the key. -/
def cache2 : Cache := insert 100 limits ⟨0, []⟩ (.failure wwwKey .noReachableAuthority)

#print axioms failure_never_negative
example : ∀ kind soa v, serve 110 cache2 wwwKey ≠ some (.negative kind soa v) :=
  (failure_never_negative (insert_unique (c := ⟨0, []⟩) (by simp [Unique]))
    (e := ⟨wwwKey, .failure .noReachableAuthority, 100, 130, 30, 0⟩)
    (by decide) rfl rfl).1

#print axioms rank_monotone
/-- The same TXT records offered as glue at time 120 change nothing. -/
example : insert 120 limits cache1 (.positive wwwTxt .glue .notPerformed none none false) = cache1 :=
  rank_monotone cache1_unique (e := ⟨wwwKey, .positive wwwTxt .authAnswer .secure, 100, 400, 300, 0⟩)
    (by decide +kernel) rfl (by decide)
    (fun e h => by
      simp only [entryFor] at h
      split at h
      · cases h
      · cases h; decide)

end Cache

/-! ## `Dns/Resolver.lean` -/

section Resolver
open Zone Resolver

def TEST : Label := [116, 101, 115, 116]

/-- The root zone, served by `a.`, delegating `test.` to `ns.test.` with glue; and the `test.` zone. -/
def rootSpec : Spec := ⟨[], 86400, .soa [LA] [HOST] 1 1800 900 604800 86400, [
    ⟨[], 2, 518400, [.ns [LA]]⟩, ⟨[LA], 1, 518400, [.a [198, 41, 0, 4]]⟩],
  [⟨[TEST], 172800, [[NS, TEST]], [⟨[NS, TEST], 1, 172800, [.a [192, 0, 2, 9]]⟩], none⟩]⟩
def testSpec : Spec := ⟨[TEST], 3600, .soa [NS, TEST] [HOST, TEST] 1 7200 3600 1209600 300, [
    ⟨[TEST], 2, 3600, [.ns [NS, TEST]]⟩, ⟨[NS, TEST], 1, 3600, [.a [192, 0, 2, 9]]⟩,
    ⟨[WWW, TEST], 1, 300, [.a [192, 0, 2, 10]]⟩], []⟩

def net : Net := [rootSpec.assemble, testSpec.assemble]
def config : Config := ⟨[[LA]], 8⟩
def state0 : State := ⟨[], none⟩
def qWww : Request := ⟨[WWW, TEST], 1⟩

theorem rootSpec_ok : rootSpec.okAll = true := by decide +kernel
theorem testSpec_ok : testSpec.okAll = true := by decide +kernel

theorem net_wf : ∀ z ∈ net, z.WF := by
  intro z hz
  simp only [net, List.mem_cons, List.mem_nil_iff, or_false] at hz
  rcases hz with rfl | rfl
  · exact build_wf rootSpec _ (by simp [build, rootSpec_ok])
  · exact build_wf testSpec _ (by simp [build, testSpec_ok])

theorem cache0_ok : CacheOk net .all state0.cache := fun _ h => by cases h

#print axioms resolve_correct
/-- With nothing lost, the resolver answers what the hierarchy answers. -/
example : ∃ st' ls', run net .all config state0 qWww [false, false] = some (Resolver.spec net .all qWww, st', ls') :=
  (resolve_correct (cfg := config) (q := qWww) net_wf cache0_ok).2 (by decide) (by decide) _ (by decide)

/-- That answer is `www.test.`'s A record, after a referral from the root. -/
example : (run net .all config state0 qWww []).map (·.1) =
    some ⟨.noerror, true, [⟨[WWW, TEST], 1, 300, [.a [192, 0, 2, 10]]⟩], [], [], 0⟩ := by
  decide +kernel

/-- With the only root server's reply lost, it is SERVFAIL. -/
example : (run net .all config state0 qWww [true]).map (·.1) = some servfail := by
  decide +kernel

#print axioms measure_decreases
example : measure (Resolver.step ⟨[], some ⟨qWww, [], [[LA]], 3⟩⟩ .lost).1 < 4 :=
  (measure_decreases (res := ⟨qWww, [], [[LA]], 3⟩) rfl .lost).1

#print axioms resolve_terminates
example : ∃ r st' ls', run net .all config state0 qWww [true, false, true] = some (r, st', ls') :=
  resolve_terminates _ _ _ _ _ _

#print axioms glue_never_served
example : ∀ r st' ls', run net .all config state0 qWww [false, true] = some (r, st', ls') →
    ∀ s ∈ r.answer, ∃ z ∈ net, ∃ resp, answer z qWww .all = .response resp ∧ s ∈ resp.answer :=
  fun _ _ _ h => glue_never_served net_wf cache0_ok h

end Resolver

end Dns.Examples
