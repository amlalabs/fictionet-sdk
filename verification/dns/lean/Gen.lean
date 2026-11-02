/-
  Test vectors for the differential test (§18.3). Every expected value is computed by the executable Lean
  definitions whose properties `Dns/*.lean` proves:

  * `names.json`: `Name.canonCmp`, `Name.eqCI`, `Name.wireLen`;
  * `wire.json`: `Wire.decode`, and `Wire.encode false` for the canonical (uncompressed) octets;
  * `restore.json`: `Wire.restore`;
  * `fit.json`: `Fit.plan` and `Fit.fit`;
  * `respond.json`: `Wire.parse` and `Wire.respondHeader`;
  * `zone.json`: `Zone.build` and `Zone.answer`;
  * `partial.json`: `Zone.answerPartial` over a zone with some facts made unknown.

  Usage: `lake exe gen <dir> <seed>`. The output depends only on the seed.

  Names are presentation strings with a trailing dot, records are presentation-format lines (RDATA of types
  this model does not name in presentation form uses the RFC 3597 `\#` form), and octets are lowercase hex.
-/
import Dns.Name
import Dns.Wire
import Dns.Fit
import Dns.Zone
import Dns.Partial

open Dns

/-! ## Randomness (splitmix64) -/

structure Rng where
  s : UInt64

def Rng.next (r : Rng) : UInt64 × Rng :=
  let s := r.s + 0x9E3779B97F4A7C15
  let z := (s ^^^ (s >>> 30)) * 0xBF58476D1CE4E5B9
  let z := (z ^^^ (z >>> 27)) * 0x94D049BB133111EB
  (z ^^^ (z >>> 31), ⟨s⟩)

abbrev G := StateM Rng

def rand : G UInt64 := modifyGet fun r => r.next
def rNat (n : Nat) : G Nat := do
  if n == 0 then return 0
  return (← rand).toNat % n
def rRange (lo hi : Nat) : G Nat := do return lo + (← rNat (hi + 1 - lo))
def chance (k : Nat) : G Bool := do return (← rNat k) == 0
def pick {α : Type} [Inhabited α] (xs : Array α) : G α := do return xs[← rNat xs.size]!
def rBytes (n : Nat) : G (List Nat) := do
  let mut out := #[]
  for _ in [0:n] do out := out.push (← rNat 256)
  return out.toList
def rList {α : Type} (n : Nat) (g : G α) : G (List α) := do
  let mut out := #[]
  for _ in [0:n] do out := out.push (← g)
  return out.toList

/-! ## JSON and presentation format -/

def hexDigit (n : Nat) : Char := "0123456789abcdef".toList[n]!
def hex (bs : List Nat) : String := String.ofList (bs.flatMap fun b => [hexDigit (b / 16 % 16), hexDigit (b % 16)])

def jesc (s : String) : String :=
  String.join (s.toList.map fun c =>
    if c == '"' then "\\\"" else if c == '\\' then "\\\\" else String.singleton c)
def jstr (s : String) : String := "\"" ++ jesc s ++ "\""
def jarr (xs : List String) : String := "[" ++ ",".intercalate xs ++ "]"
def jnat (n : Nat) : String := toString n
def jint (n : Int) : String := toString n
def jbool (b : Bool) : String := if b then "true" else "false"
def jobj (kvs : List (String × String)) : String :=
  "{" ++ ",".intercalate (kvs.map fun (k, v) => jstr k ++ ":" ++ v) ++ "}"

def toBytes (s : String) : List Nat := s.toUTF8.toList.map (·.toNat)

def pad3 (n : Nat) : String :=
  let s := toString n
  String.ofList (List.replicate (3 - s.length) '0') ++ s

/-- Octets that stand for themselves in a label; every other octet is written `\DDD`. -/
def plainLabelByte (b : Nat) : Bool :=
  (48 ≤ b && b ≤ 57) || (65 ≤ b && b ≤ 90) || (97 ≤ b && b ≤ 122) || b == 45 || b == 95 || b == 42

def labelStr (l : Label) : String :=
  String.join (l.map fun b => if plainLabelByte b then String.singleton (Char.ofNat b) else "\\" ++ pad3 b)

def nameStr (n : Name) : String :=
  if n.isEmpty then "." else ".".intercalate (n.map labelStr) ++ "."

def charString (s : List Nat) : String :=
  "\"" ++ String.join (s.map fun b =>
    if b == 34 || b == 92 then "\\" ++ String.singleton (Char.ofNat b)
    else if 32 ≤ b && b ≤ 126 then String.singleton (Char.ofNat b)
    else "\\" ++ pad3 b) ++ "\""

def typeStr : Nat → String
  | 1 => "A" | 2 => "NS" | 3 => "MD" | 4 => "MF" | 5 => "CNAME" | 6 => "SOA" | 7 => "MB" | 8 => "MG"
  | 9 => "MR" | 12 => "PTR" | 13 => "HINFO" | 14 => "MINFO" | 15 => "MX" | 16 => "TXT" | 28 => "AAAA"
  | 33 => "SRV" | 39 => "DNAME" | 41 => "OPT" | 43 => "DS" | 251 => "IXFR" | 252 => "AXFR"
  | 253 => "MAILB" | 254 => "MAILA" | 255 => "ANY"
  | t => "TYPE" ++ toString t

def classStr : Nat → String
  | 1 => "IN" | 3 => "CH" | 4 => "HS" | 254 => "NONE" | 255 => "ANY"
  | c => "CLASS" ++ toString c

def dotted (bs : List Nat) : String := ".".intercalate (bs.map toString)

def aaaaStr (bs : List Nat) : String :=
  let rec groups : List Nat → List String
    | a :: b :: rest => String.ofList (Nat.toDigits 16 (a * 256 + b)) :: groups rest
    | _ => []
  ":".intercalate (groups bs)

def generic (bs : List Nat) : String :=
  if bs.isEmpty then "\\# 0" else "\\# " ++ toString bs.length ++ " " ++ hex bs

/-! ## Zone records in presentation form -/

section ZoneText
open Zone

def zRdataStr : RData → String
  | .a addr => dotted addr
  | .aaaa addr => aaaaStr addr
  | .ns t | .cname t | .dname t | .ptr t => nameStr t
  | .mx p t => s!"{p} {nameStr t}"
  | .srv p w port t => s!"{p} {w} {port} {nameStr t}"
  | .txt ss => " ".intercalate (ss.map charString)
  | .hinfo cpu os => charString cpu ++ " " ++ charString os
  | .soa m r a b c d e => s!"{nameStr m} {nameStr r} {a} {b} {c} {d} {e}"
  | .ds tag alg dt dig => s!"{tag} {alg} {dt} {hex dig}"
  | .other _ bytes => generic bytes

def rrsetLines (s : RRset) : List String :=
  s.rdata.map fun rd => s!"{nameStr s.owner} {s.ttl} IN {typeStr s.rtype} {zRdataStr rd}"

def setsJson (l : List RRset) : String := jarr ((l.flatMap rrsetLines).map jstr)

def rcodeStr : Rcode → String
  | .noerror => "NOERROR" | .nxdomain => "NXDOMAIN" | .yxdomain => "YXDOMAIN" | .refused => "REFUSED"
  | .servfail => "SERVFAIL"

def responseJson (r : Response) : String :=
  jobj [("rcode", jstr (rcodeStr r.rcode)), ("aa", jbool r.aa), ("answer", setsJson r.answer),
    ("authority", setsJson r.authority), ("additional", setsJson r.additional),
    ("required_additional", jnat r.required)]

def anyStr : AnyResponse → String
  | .hinfo => "hinfo" | .oneRrset => "one_rrset" | .all => "all"

/-- The zone as master-file lines: the SOA, every RRset, and each delegation's NS, DS, and glue. -/
def specLines (sp : Spec) : List String :=
  rrsetLines sp.soaSet ++ sp.sets.flatMap rrsetLines ++ sp.delegations.flatMap fun d =>
    let c := cutNode d
    match c.2 with
    | .cut ns ds g => rrsetLines ns ++ (ds.map rrsetLines).getD [] ++ g.flatMap rrsetLines
    | _ => []

def specJson (sp : Spec) : String :=
  jobj [("apex", jstr (nameStr sp.apex)), ("records", jarr ((specLines sp).map jstr))]

end ZoneText

/-! ## Wire records in presentation form -/

section WireText
open Wire

def be32of (bs : List Nat) : Nat := bs.foldl (fun acc b => acc * 256 + b) 0

def wRdataStr (t : Nat) : RData → String
  | .names pre ns post =>
    match t with
    | 15 => s!"{be32of pre} {" ".intercalate (ns.map nameStr)}"
    | 6 =>
      " ".intercalate (ns.map nameStr) ++ " " ++
        " ".intercalate ((List.range 5).map fun i => toString (be32of ((post.drop (4 * i)).take 4)))
    | _ => " ".intercalate (ns.map nameStr)
  | .octets bs =>
    if t == 1 && bs.length == 4 then dotted bs
    else if t == 28 && bs.length == 16 then aaaaStr bs
    else generic bs

def rrLine (r : RR) : String :=
  s!"{nameStr r.owner} {r.ttl} {classStr r.rclass} {typeStr r.rtype} {wRdataStr r.rtype r.rdata}"

def questionLine (q : Question) : String := s!"{nameStr q.name} {classStr q.qclass} {typeStr q.qtype}"

def messageJson (m : Message) : String :=
  jobj [("header", jobj [("id", jnat m.header.id), ("flags", jnat m.header.flags)]),
    ("question", jarr (m.question.map (jstr ∘ questionLine))),
    ("answer", jarr (m.answer.map (jstr ∘ rrLine))),
    ("authority", jarr (m.authority.map (jstr ∘ rrLine))),
    ("additional", jarr (m.additional.map (jstr ∘ rrLine)))]

def errStr : Err → String
  | .exhausted => "exhausted" | .bounds => "bounds" | .forwardPointer => "forward_pointer"
  | .labelType => "label_type" | .badName => "bad_name" | .rdataLength => "rdata_length" | .short => "short"

end WireText

/-! ## Random names -/

def labelPool : Array String :=
  #["www", "mail", "ns1", "ns2", "a", "b", "c", "example", "com", "net", "org", "test", "x", "api", "cdn", "edge",
    "sub", "zone", "d", "deep"]

def mixCase (l : Label) : G Label := do
  let mut out := #[]
  for b in l do
    if 97 ≤ b && b ≤ 122 && (← chance 3) then out := out.push (b - 32) else out := out.push b
  return out.toList

def rLabel (mixed : Bool) : G Label := do
  let l := toBytes (← pick labelPool)
  if mixed && (← chance 3) then mixCase l else return l

def rName (maxLabels : Nat) (mixed : Bool) : G Name := do
  let n ← rNat (maxLabels + 1)
  rList n (rLabel mixed)

/-- Labels with any octets, for the name vectors: escapes, dots and backslashes inside labels, and case. -/
def rWildLabel : G Label := do
  match ← rNat 4 with
  | 0 => do
    let n ← rRange 1 6
    rList n (pick #[0, 9, 32, 34, 40, 46, 59, 64, 65, 90, 92, 97, 122, 127, 128, 200, 255])
  | 1 => rLabel true
  | 2 => do mixCase (toBytes (← pick labelPool))
  | _ => do let n ← rRange 1 3; rList n (pick #[65, 66, 97, 98, 90, 122, 91, 96, 123])

/-! ## names.json -/

def namesCase : G String := do
  let a ← do let n ← rNat 4; rList n rWildLabel
  let b ← match ← rNat 6 with
    | 0 => do Name.fold <$> pure a
    | 1 => do mixCase' a
    | _ => do let n ← rNat 4; rList n rWildLabel
  return jobj [("input", jobj [("a", jstr (nameStr a)), ("b", jstr (nameStr b))]),
    ("expected", jobj [("cmp", jint (Name.canonCmp a b)), ("eq_ci", jbool (Name.eqCI a b)),
      ("wire_len", jarr [jnat (Name.wireLen a), jnat (Name.wireLen b)])])]
where
  mixCase' (n : Name) : G Name := n.mapM mixCase

/-! ## Random messages -/

section Msgs
open Wire

def rRData (t : Nat) : G RData := do
  match t with
  | 1 => return .octets (← rBytes 4)
  | 28 => return .octets (← rBytes 16)
  | 2 | 5 | 12 => return .names [] [← rName 3 true] []
  | 15 => return .names (← rBytes 2) [← rName 3 true] []
  | 6 => return .names [] [← rName 3 true, ← rName 3 true] (← rBytes 20)
  | 16 => do
    let n ← rRange 0 30
    return .octets (n :: (← rBytes n))
  | _ => do let n ← rRange 0 12; return .octets (← rBytes n)

def rType : G Nat := pick #[1, 1, 28, 2, 5, 15, 6, 12, 16, 33, 65280]

def rRR (owner : Option Name) (t : Option Nat) : G RR := do
  let t ← match t with | some t => pure t | none => rType
  let owner ← match owner with | some o => pure o | none => rName 3 true
  let cls ← pick #[1, 1, 1, 3]
  return ⟨owner, t, cls, ← rNat 100000, ← rRData t⟩

def rMessage : G Message := do
  let q ← do
    let n ← pick #[0, 1, 1, 1, 2]
    rList n (do return (⟨← rName 3 true, ← pick #[1, 28, 15, 16, 2, 255], ← pick #[1, 1, 3]⟩ : Question))
  let an ← do let n ← rNat 4; rList n (rRR none none)
  let ns ← do let n ← rNat 3; rList n (rRR none none)
  let ar ← do let n ← rNat 3; rList n (rRR none none)
  return ⟨⟨← rNat 65536, ← rNat 65536⟩, q, an, ns, ar⟩

def setAt (bs : List Nat) (i v : Nat) : List Nat := bs.set i v

def corrupt (bs : List Nat) : G (List Nat) := do
  match ← rNat 10 with
  | 0 => return bs.take (← rNat bs.length)
  | 1 => do
    if bs.length ≤ 12 then return bs
    let i ← rRange 12 (bs.length - 1)
    return setAt bs i (← rNat 256)
  | 2 => do
    if bs.length ≤ 13 then return bs
    let i ← rRange 12 (bs.length - 2)
    let t ← rRange i (bs.length + 4)
    return setAt (setAt bs i (192 + t / 256 % 64)) (i + 1) (t % 256)
  | 3 => return bs ++ (← rBytes (← rRange 1 4))
  | _ => return bs

def wireCase : G String := do
  let m ← rMessage
  let bytes ← corrupt (encode true m)
  let expected := match decode bytes with
    | .ok d => jobj [("ok", jbool true), ("message", messageJson d), ("canonical", jstr (hex (encode false d)))]
    | .error e => jobj [("ok", jbool false), ("error", jstr (errStr e))]
  return jobj [("input", jobj [("bytes", jstr (hex bytes))]), ("expected", expected)]

/-! ## restore.json -/

def restoreCase : G String := do
  let qname ← rName 3 false
  let qtype ← pick #[1, 28, 15, 16]
  let qn ← qname.mapM mixCase
  let query := encode true ⟨⟨← rNat 65536, 256⟩, [⟨qn, qtype, 1⟩], [], [], []⟩
  let rn ← match ← rNat 6 with
    | 0 => rName 3 false
    | _ => qname.mapM mixCase
  let rt ← if (← chance 8) then pick #[1, 28, 15, 16] else pure qtype
  let rc ← if (← chance 10) then pure 3 else pure 1
  let answers ← do let n ← rNat 3; rList n (rRR (some rn) (some rt))
  let reply := encode true ⟨⟨← rNat 65536, 33152⟩, [⟨rn, rt, rc⟩], answers, [], []⟩
  let reply ← if (← chance 8) then corrupt reply else pure reply
  let query ← if (← chance 12) then corrupt query else pure query
  let expected := match restore reply query with
    | .ok out => jobj [("restored", jstr (hex out))]
    | .error .questionMismatch => jobj [("error", jstr "question_mismatch")]
    | .error .malformed => jobj [("error", jstr "malformed")]
  return jobj [("input", jobj [("reply", jstr (hex reply)), ("query", jstr (hex query))]), ("expected", expected)]

/-! ## fit.json -/

def rRRset : G (List RR) := do
  let owner ← rName 3 false
  let t ← pick #[1, 28, 16, 16, 2, 15, 65280]
  let n ← rRange 1 3
  let mut out := #[]
  for _ in [0:n] do
    let rd ← if t == 16 then do
        let k ← pick #[10, 50, 120, 250]
        pure (RData.octets (k :: List.replicate k 97))
      else rRData t
    out := out.push (⟨owner, t, 1, 300, rd⟩ : RR)
  return out.toList

def limitJson : Fit.Limit → String
  | .udp512 => jobj [("kind", jstr "udp512")]
  | .udpEdns n => jobj [("kind", jstr "udp_edns"), ("size", jnat n)]
  | .stream => jobj [("kind", jstr "stream")]

def rrsetsJson (l : List (List RR)) : String := jarr (l.map fun s => jarr (s.map (jstr ∘ rrLine)))

def fitCase : G String := do
  let an ← do let n ← rNat 4; rList n rRRset
  let au ← do let n ← rNat 3; rList n rRRset
  let ad ← do let n ← rNat 5; rList n rRRset
  let req ← rNat (ad.length + 1)
  let opt : Option RR ← if (← chance 4) then pure none
    else pure (some ⟨[], 41, ← pick #[512, 1232, 4096], 0, .octets []⟩)
  let r : Fit.Resp := ⟨⟨← rNat 65536, 33152⟩, [⟨← rName 3 false, 1, 1⟩], an, au, ad, req, opt⟩
  let lim ← match ← rNat 3 with
    | 0 => pure Fit.Limit.udp512
    | 1 => do pure (Fit.Limit.udpEdns (← pick #[512, 700, 1232, 1400, 4096]))
    | _ => pure Fit.Limit.stream
  let p := Fit.plan r lim
  let out := Fit.fit r lim
  return jobj [
    ("input", jobj [("response", jobj [("header", jobj [("id", jnat r.header.id), ("flags", jnat r.header.flags)]),
        ("question", jarr (r.question.map (jstr ∘ questionLine))), ("answer", rrsetsJson an),
        ("authority", rrsetsJson au), ("additional", rrsetsJson ad), ("required_additional", jnat req),
        ("opt", match opt with | some o => jstr (rrLine o) | none => "null")]),
      ("limit", limitJson lim)]),
    ("expected", jobj [("size_le", jnat lim.size), ("fits", jbool (Fit.fits r lim [] [] [])),
      ("length", jnat out.1.length), ("tc", jbool out.2),
      ("kept", jobj [("answer", jnat p.answer.length), ("authority", jnat p.authority.length),
        ("additional", jnat p.additional.length)])])]

/-! ## respond.json -/

def flagsJson (h : Header) : String :=
  jobj [("qr", jbool h.qr), ("opcode", jnat h.opcode), ("aa", jbool h.aa), ("tc", jbool h.tc), ("rd", jbool h.rd),
    ("ra", jbool h.ra), ("z", jbool h.z), ("ad", jbool h.ad), ("cd", jbool h.cd), ("rcode", jnat h.rcode)]

def rOpt : G RR := do
  let version ← pick #[0, 0, 0, 1]
  let dnssec ← chance 2
  let other ← if (← chance 6) then pure 1 else pure 0
  let opts ← match ← rNat 5 with
    | 0 => pure [0, 3, 0, 0]
    | 1 => do pure ([0, 10, 0, 8] ++ (← rBytes 8))
    | 2 => if (← chance 3) then pure [0, 3, 0] else pure []
    | _ => pure []
  return ⟨[], 41, ← pick #[512, 1232, 4096], version * 65536 + (if dnssec then 32768 else 0) + other, .octets opts⟩

def respondCase : G String := do
  let udp ← chance 3 |>.map not
  let bytes ← match ← rNat 12 with
    | 0 => rBytes (← rNat 12)
    | _ => do
      let qr ← chance 12
      let opcode ← if (← chance 8) then pick #[1, 2, 4, 5] else pure 0
      let rd ← chance 2
      let cd ← chance 4
      let ad ← chance 4
      let z ← chance 10
      let flags := Wire.flagsOf qr opcode false false rd false z ad cd 0
      let qd ← pick #[1, 1, 1, 1, 1, 1, 1, 0, 2]
      let qs ← rList qd (do return (⟨← rName 3 true, ← pick #[1, 1, 28, 15, 41, 251, 252, 253, 254, 255], 1⟩ :
        Question))
      let nopt ← pick #[0, 0, 1, 1, 1, 1, 2]
      let opts ← rList nopt rOpt
      let opts ← if (← chance 10) then pure (opts.map fun o => { o with owner := [toBytes "x"] }) else pure opts
      let m : Message := ⟨⟨← rNat 65536, flags⟩, qs, [], [], opts⟩
      let b := encode true m
      if (← chance 10) then corrupt b else pure b
  let expected := match parse bytes udp with
    | .silent => jobj [("parsed", jstr "silent")]
    | .reject r => jobj [("parsed", jstr "reject"), ("rcode", jnat r.rcode), ("flags", flagsJson r.header),
        ("opt", match r.opt with | some v => jobj [("version", jnat v)] | none => "null")]
    | .request q => jobj [("parsed", jstr "request"), ("rd", jbool q.header.rd), ("cd", jbool q.header.cd),
        ("ad", jbool q.header.ad), ("question", jstr (questionLine q.question)),
        ("edns", match q.edns with
          | some e => jobj [("payload", jnat e.payload), ("version", jnat e.version), ("do", jbool e.dnssecOk),
              ("nsid", jbool e.nsid)]
          | none => "null")]
  return jobj [("input", jobj [("bytes", jstr (hex bytes)), ("transport", jstr (if udp then "udp" else "tcp"))]),
    ("expected", expected)]

end Msgs

/-! ## Random zones -/

section Zones
open Zone

def lb (s : String) : Label := toBytes s

def rTtl : G Nat := pick #[60, 300, 3600, 86400]

def rAddrSet (owner : Name) : G RRset := do
  if (← chance 3) then return ⟨owner, 28, ← rTtl, [.aaaa ((← rBytes 16))]⟩
  return ⟨owner, 1, ← rTtl, [.a (← rBytes 4)]⟩

/-- A target name: inside the zone, under a delegation, or elsewhere. -/
def rTarget (apex : Name) (inside : List Name) : G Name := do
  match ← rNat 3 with
  | 0 => do return [lb "ns", lb "other", lb "org"]
  | _ => if inside.isEmpty then return lb "ns1" :: apex else pick inside.toArray

def rDataSets (owner : Name) (apex : Name) (inside : List Name) : G (List RRset) := do
  match ← rNat 9 with
  | 0 => return [⟨owner, 5, ← rTtl, [.cname (← rTarget apex inside)]⟩]
  | 1 => return [⟨owner, 15, ← rTtl, [.mx (← rNat 50) (← rTarget apex inside)]⟩, ← rAddrSet owner]
  | 2 => return [⟨owner, 16, ← rTtl, [.txt [toBytes "v=1"], .txt [toBytes "hello"]]⟩]
  | 3 => return [⟨owner, 13, ← rTtl, [.hinfo (toBytes "PC") (toBytes "BSD")]⟩, ← rAddrSet owner]
  | 4 => return [⟨owner, 33, ← rTtl, [.srv 1 2 443 (← rTarget apex inside)]⟩]
  | 5 => return [⟨owner, 65400, ← rTtl, [.other 65400 (← rBytes 3)]⟩]
  | _ => do
    let a ← rAddrSet owner
    if (← chance 2) then return [a, ⟨owner, 16, ← rTtl, [.txt [toBytes "x"]]⟩] else return [a]

def rSpec : G Spec := do
  let apex ← pick #[[lb "example", lb "com"], [lb "test"], [lb "zone", lb "example"]]
  let soa : RData := .soa (lb "ns1" :: apex) (lb "hostmaster" :: apex) (← rNat 100000) 7200 3600 1209600
    (← pick #[60, 300, 3600])
  let ns1 := lb "ns1" :: apex
  let names : List Name := [lb "www" :: apex, lb "mail" :: apex, lb "api" :: apex, [lb "a", lb "b"] ++ apex,
    lb "x" :: apex, lb "cdn" :: apex]
  let count ← rRange 1 names.length
  let chosen := names.take count
  let mut sets : List RRset := [⟨apex, 2, 3600, [.ns ns1]⟩, ⟨ns1, 1, 3600, [.a [192, 0, 2, 1]]⟩]
  for n in chosen do
    sets := sets ++ (← rDataSets n apex (ns1 :: chosen))
  if (← chance 2) then sets := sets ++ (← rDataSets (lb "*" :: apex) apex [ns1])
  if (← chance 3) then sets := sets ++ (← rDataSets ([lb "*", lb "b"] ++ apex) apex [ns1])
  if (← chance 2) then
    let target ← pick #[[lb "example", lb "net"], [lb "other", lb "org"], lb "deep" :: apex,
      List.replicate 4 (List.replicate 61 120), List.replicate 4 (List.replicate 61 120)]
    sets := sets ++ [⟨lb "d" :: apex, 39, 300, [.dname target]⟩]
  let mut dels : List Delegation := []
  let cut1 := lb "sub" :: apex
  let cut2 := lb "zone" :: apex
  if (← chance 2) then
    let sibling ← chance 2
    let targets := [lb "ns" :: cut1] ++ (if sibling then [lb "ns" :: cut2] else []) ++
      (if (← chance 2) then [[lb "ns", lb "other", lb "org"]] else [])
    let digest ← rBytes 8
    let ds := if (← chance 2) then some (86400, [RData.ds 12345 13 2 digest]) else none
    dels := dels ++ [⟨cut1, 86400, targets, [⟨lb "ns" :: cut1, 1, 86400, [.a [192, 0, 2, 53]]⟩], ds⟩]
    if sibling then
      dels := dels ++ [⟨cut2, 86400, [lb "ns" :: cut2], [⟨lb "ns" :: cut2, 1, 86400, [.a [192, 0, 2, 54]]⟩], none⟩]
  return ⟨apex, 3600, soa, sets, dels⟩

/-- A zone the builder accepts. Draws until one is accepted. -/
def rZone : G (Spec × Zone) := do
  let mut tries := 0
  while tries < 1000 do
    tries := tries + 1
    let sp ← rSpec
    match build sp with
    | .ok z => return (sp, z)
    | .error _ => pure ()
  let sp : Spec := ⟨[lb "test"], 3600, .soa [lb "ns1", lb "test"] [lb "h", lb "test"] 1 2 3 4 5,
    [⟨[lb "test"], 2, 3600, [.ns [lb "ns1", lb "test"]]⟩], []⟩
  return (sp, sp.assemble)

def rQname (z : Zone) : G Name := do
  let held := z.nodes.map (·.1)
  match ← rNat 8 with
  | 0 => return lb "nope" :: z.apex
  | 1 => do return lb "q" :: (← pick held.toArray)
  | 2 => return [lb "www", lb "sub"] ++ z.apex
  | 3 => do return [← pick #[lb "h", lb "a-label-long-enough"], lb "d"] ++ z.apex
  | 4 => return [lb "r", lb "b"] ++ z.apex
  | 5 => return [lb "elsewhere", lb "org"]
  | _ => pick held.toArray

def rQtype : G Nat := pick #[1, 1, 28, 2, 15, 16, 5, 6, 43, 255, 13, 33, 39, 99]

instance : Inhabited AnyResponse := ⟨.all⟩

def rAny : G AnyResponse := pick #[.hinfo, .oneRrset, .all]


def zoneCase : G String := do
  let (sp, z) ← rZone
  let q : Request := ⟨← rQname z, ← rQtype⟩
  let any ← rAny
  let expected := match answer z q any with
    | .response r => responseJson r
    | .unknown n => jobj [("unknown", jstr (nameStr n))]
  return jobj [("input", jobj [("zone", specJson sp), ("any", jstr (anyStr any)),
      ("request", jobj [("qname", jstr (nameStr q.qname)), ("qtype", jstr (typeStr q.qtype))])]),
    ("expected", expected)]

def ancestorsIn (apex q : Name) : List Name :=
  (List.range (q.length + 1)).map (q.drop ·) |>.filter fun m => apex.isSuffixOf m

def partialCase : G String := do
  let (sp, z) ← rZone
  let q : Request := ⟨← rQname z, ← rQtype⟩
  let any ← rAny
  let candidates := ancestorsIn z.apex q.qname ++ (ancestorsIn z.apex q.qname).map wild ++ z.nodes.map (·.1)
  let mut unknown : List Name := []
  for c in candidates do
    if (← chance 6) && !unknown.contains c then unknown := unknown ++ [c]
  let v : View := ⟨z.apex, z.soa, fun n => if unknown.contains n then .unknown else z.look n, 0⟩
  let expected := match answerPartial v q any with
    | .response r => jobj [("response", responseJson r)]
    | .unknown n => jobj [("unknown", jstr (nameStr n))]
  return jobj [("input", jobj [("zone", specJson sp), ("unknown", jarr (unknown.map (jstr ∘ nameStr))),
      ("any", jstr (anyStr any)),
      ("request", jobj [("qname", jstr (nameStr q.qname)), ("qtype", jstr (typeStr q.qtype))])]),
    ("expected", expected)]

end Zones

/-! ## Output -/

def cases (n : Nat) (g : G String) : G (List String) := rList n g

def kinds : List (String × Nat × G String) :=
  [("names", 400, namesCase), ("wire", 400, wireCase), ("restore", 300, restoreCase), ("fit", 300, fitCase),
    ("respond", 400, respondCase), ("zone", 400, zoneCase), ("partial", 300, partialCase)]

def main (args : List String) : IO UInt32 := do
  match args with
  | [dir, seedStr] =>
    match seedStr.toNat? with
    | none =>
      IO.eprintln s!"gen: the seed must be a number, not {seedStr}"
      return 2
    | some seed =>
      IO.FS.createDirAll dir
      let mut rng : Rng := ⟨seed.toUInt64⟩
      for (kind, n, g) in kinds do
        let (out, rng') := (cases n g).run rng
        rng := rng'
        IO.FS.writeFile (System.FilePath.mk dir / s!"{kind}.json") (jarr out ++ "\n")
        IO.println s!"{kind}.json: {n} cases"
      return 0
  | _ =>
    IO.eprintln "usage: lake exe gen <dir> <seed>"
    return 2
