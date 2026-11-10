/-
  Test vectors for the differential test. Every expected value is computed by the executable Lean
  definitions whose properties `Dns/*.lean` proves:

  * `names.json`: `Name.canonCmp`, `Name.eqCI`, `Name.wireLen`;
  * `wire.json`: `Wire.decode`, and `Wire.encode false` for the canonical (uncompressed) octets;
  * `fit.json`: `Fit.plan` and `Fit.fit`;
  * `respond.json`: `Wire.parse` and `Wire.respondHeader`;
  * `zone.json`: `Zone.build` and `Zone.answer`;
  * `partial.json`: `Zone.answerPartial` over a zone with some facts made unknown;
  * `signed.json`: `Dnssec.SignedZone.answerDo` and `Dnssec.validateAnswer`;
  * `policy.json`: `Dnssec.AlgorithmPolicy.treat`, over `Policy.iana` and other policies;
  * `chain.json`: `Chain.check`;
  * `cache.json`: `Cache.insert`, `Cache.advance`, and `Cache.serve`;
  * `resolver.json`: `Resolver.runAll` over a hierarchy of zones with scripted losses, and with some servers dead;
  * `framing.json`: `Wire.unframeAll` over messages framed for a stream.

  Usage: `lake exe gen <dir> <seed>`. The output depends only on the seed.

  Names are presentation strings with a trailing dot, records are presentation-format lines (RDATA of types
  this model does not name in presentation form uses the RFC 3597 `\#` form), and octets are lowercase hex.
-/
import Dns.Name
import Dns.Wire
import Dns.Fit
import Dns.Zone
import Dns.Partial
import Dns.Dnssec
import Dns.Policy
import Dns.Chain
import Dns.Cache
import Dns.Resolver

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
  | 33 => "SRV" | 39 => "DNAME" | 41 => "OPT" | 43 => "DS" | 46 => "RRSIG" | 47 => "NSEC" | 48 => "DNSKEY"
  | 50 => "NSEC3" | 251 => "IXFR" | 252 => "AXFR"
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
  | .hinfo _ => "hinfo" | .oneRrset => "one_rrset" | .all => "all"

/-- The input fields that say what a server sends for QTYPE ANY: `any`, and for `hinfo` its TTL, `hinfo_ttl`. -/
def anyFields (any : AnyResponse) : List (String × String) :=
  ("any", jstr (anyStr any)) :: match any with
    | .hinfo ttl => [("hinfo_ttl", jnat ttl)]
    | _ => []

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
  -- SRV: the priority, weight, and port, then the target uncompressed (RFC 2782); now and then octets that do
  -- not read as SRV, which hickory refuses.
  | 33 => do
    if ← chance 8 then let n ← rRange 0 12; return .octets (← rBytes n)
    return .octets ((← rBytes 6) ++ Dnssec.Symbolic.wire (← rName 3 true))
  | _ => do let n ← rRange 0 12; return .octets (← rBytes n)

def rType : G Nat := pick #[1, 1, 28, 2, 5, 15, 6, 12, 16, 33, 65280, 48, 50, 50, 51]

def rRR (owner : Option Name) (t : Option Nat) : G RR := do
  let t ← match t with | some t => pure t | none => rType
  let owner ← match owner with | some o => pure o | none => rName 3 true
  let cls ← pick #[1, 1, 1, 3]
  return ⟨owner, t, cls, ← rNat 100000, ← rRData t⟩

/-- A name of three or four labels of 60 to 64 octets: near the 255-octet limit of a name, or past it, and
now and then with a label past the 63-octet limit of a label (RFC 1035 §2.3.4). -/
def rLongName : G Name := do
  let k ← pick #[60, 61, 62, 62, 63, 64]
  let n ← pick #[3, 4, 4]
  return List.replicate n (List.replicate k 97)

def rMessage : G Message := do
  let q ← do
    let n ← pick #[0, 1, 1, 1, 2]
    rList n (do return (⟨← rName 3 true, ← pick #[1, 28, 15, 16, 2, 255], ← pick #[1, 1, 3]⟩ : Question))
  -- now and then a long question name, and an owner one label longer, which the encoder writes as a label
  -- and a pointer to the question's name, so the owner reaches 255 octets, or passes it, only through the
  -- pointer
  let q ← if (← chance 5) then do
      let long ← rLongName
      pure (q.map fun x => { x with name := long })
    else pure q
  let an ← do let n ← rNat 4; rList n (rRR none none)
  let an ← match q with
    | x :: _ => if (← chance 3) then do pure ((← rRR (some ((← rLabel false) :: x.name)) none) :: an) else pure an
    | [] => pure an
  let ns ← do let n ← rNat 3; rList n (rRR none none)
  let ar ← do let n ← rNat 3; rList n (rRR none none)
  return ⟨⟨← rNat 65536, ← rNat 65536⟩, q, an, ns, ar⟩

def setAt (bs : List Nat) (i v : Nat) : List Nat := bs.set i v

def corrupt (bs : List Nat) : G (List Nat) := do
  match ← rNat 12 with
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
  -- a pointer back to any earlier octet: a prior name, the middle of a label, or an earlier octet of the
  -- name that holds it (RFC 1035 §4.1.4)
  | 4 | 5 => do
    if bs.length ≤ 14 then return bs
    let i ← rRange 13 (bs.length - 2)
    let t ← rRange 12 (i - 1)
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
    -- payload sizes below 512 count as 512 (RFC 6891 §6.2.5)
    | 1 => do pure (Fit.Limit.udpEdns (← pick #[512, 700, 1232, 1400, 4096, 100, 511]))
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
  jobj [("id", jnat h.id), ("qr", jbool h.qr), ("opcode", jnat h.opcode), ("aa", jbool h.aa), ("tc", jbool h.tc),
    ("rd", jbool h.rd), ("ra", jbool h.ra), ("z", jbool h.z), ("ad", jbool h.ad), ("cd", jbool h.cd),
    ("rcode", jnat h.rcode)]

def rOpt : G RR := do
  let version ← pick #[0, 0, 0, 1]
  let dnssec ← chance 2
  let other ← if (← chance 6) then pure 1 else pure 0
  let opts ← match ← rNat 5 with
    | 0 => pure [0, 3, 0, 0]
    | 1 => do pure ([0, 10, 0, 8] ++ (← rBytes 8))
    | 2 => if (← chance 3) then pure [0, 3, 0] else pure []
    | _ => pure []
  -- payload sizes below 512 count as 512 (RFC 6891 §6.2.5)
  return ⟨[], 41, ← pick #[512, 1232, 4096, 1232, 0, 100, 511], version * 65536 + (if dnssec then 32768 else 0) +
    other, .octets opts⟩

def respondCase : G String := do
  let udp ← chance 3 |>.map not
  let bytes ← match ← rNat 12 with
    | 0 => rBytes (← rNat 12)
    | _ => do
      let qr ← chance 12
      -- IQUERY, STATUS, NOTIFY, UPDATE, DSO, and opcodes no RFC assigns
      let opcode ← if (← chance 8) then pick #[1, 2, 3, 4, 5, 6, 7, 11, 15] else pure 0
      let rd ← chance 2
      let cd ← chance 4
      let ad ← chance 4
      let z ← chance 10
      let flags := Wire.flagsOf qr opcode false false rd false z ad cd 0
      let qd ← pick #[1, 1, 1, 1, 1, 1, 1, 0, 2]
      let qs ← rList qd (do return (⟨← rName 3 true,
        ← pick #[1, 1, 28, 15, 41, 249, 250, 251, 252, 253, 254, 255], 1⟩ : Question))
      let nopt ← pick #[0, 0, 1, 1, 1, 1, 2]
      let opts ← rList nopt rOpt
      let opts ← if (← chance 10) then pure (opts.map fun o => { o with owner := [toBytes "x"] }) else pure opts
      -- a TSIG record (RFC 8945 §4.2): HMAC-SHA256, a time, a fudge of 300, a MAC, the original ID, no error
      let mac ← pick #[0, 0, 32]
      let fields := [0, 0, 104, 0, 0, 1, 1, 44, 0, mac] ++ List.replicate mac 42 ++ [18, 52, 0, 0, 0, 0]
      let fields := if (← chance 6) then fields.dropLast else fields
      let tsig : RR := ⟨[toBytes "key"], 250, 255, 0,
        .octets (Dnssec.Symbolic.wire [toBytes "hmac-sha256"] ++ fields)⟩
      -- last, as it belongs, or before the OPT records, or twice, or alone in the answer section
      let (answer, additional) ← match ← rNat 9 with
        | 0 | 1 => pure ([], opts ++ [tsig])
        | 2 => pure ([], tsig :: opts)
        | 3 => pure ([], opts ++ [tsig, tsig])
        | 4 => pure ([tsig], opts)
        | _ => pure ([], opts)
      let m : Message := ⟨⟨← rNat 65536, flags⟩, qs, answer, [], additional⟩
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
          | none => "null"),
        -- the header and OPT of an authoritative NOERROR answer to it, through the server front
        ("answer", flagsJson (respondHeader q.header 0 true false)),
        ("answer_opt", match q.edns with
          | some e => jobj [("version", jnat 0), ("do", jbool e.dnssecOk)]
          | none => "null")]
  return jobj [("input", jobj [("bytes", jstr (hex bytes)), ("transport", jstr (if udp then "udp" else "tcp"))]),
    ("expected", expected)]

/-! ## framing.json -/

/-- Messages after their two-octet lengths as a stream carries them (RFC 1035 §4.2.2), then sometimes part of
one more; or now and then octets of no such shape. `cuts` are where the stream is split into the chunks it
arrives in. -/
def framingCase : G String := do
  let stream ← if (← chance 5) then do rList (← rNat 40) (pick #[0, 0, 0, 1, 2, 3, 5, 7, 200]) else do
    let ms ← rList (← rNat 4) (do rBytes (← pick #[0, 1, 3, 12, 30, 300]))
    let tail ← match ← rNat 3 with
      | 0 => pure []
      | 1 => do let m ← rBytes (← rRange 1 20); pure ((frame m).take (← rRange 1 (m.length + 1)))
      | _ => do pure [← rNat 256]
    pure ((ms.map frame).flatten ++ tail)
  let cuts ← rList (← rNat 5) (rNat (stream.length + 1))
  let (ms, rest) := unframeAll stream
  let cuts := Dnssec.sortBy (· < ·) cuts
  return jobj [("input", jobj [("bytes", jstr (hex stream)), ("cuts", jarr (cuts.map jnat))]),
    ("expected", jobj [("messages", jarr (ms.map (jstr ∘ hex))), ("rest", jnat rest.length)])]

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
  -- A CNAME at the wildcard to a name it answers for is a loop through the wildcard.
  if (← chance 2) then sets := sets ++ (← rDataSets (lb "*" :: apex) apex [ns1, lb "loop" :: apex])
  if (← chance 3) then sets := sets ++ (← rDataSets ([lb "*", lb "b"] ++ apex) apex [ns1])
  if (← chance 2) then
    let target ← pick #[[lb "example", lb "net"], [lb "other", lb "org"], lb "deep" :: apex,
      List.replicate 4 (List.replicate 61 120), List.replicate 4 (List.replicate 61 120)]
    -- Now and then a second DNAME record at the owner, which the builder refuses (RFC 6672 §2.4).
    let second : List RData := if ← chance 4 then [.dname [lb "second", lb "org"]] else []
    sets := sets ++ [⟨lb "d" :: apex, 39, 300, .dname target :: second⟩]
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

def rAny : G AnyResponse := do pick #[.hinfo (← rTtl), .oneRrset, .all]


def zoneErrorStr : ZoneError → String
  | .outOfZone _ => "out_of_zone"
  | .cnameWithOtherData _ => "cname_with_other_data"
  | .cnameAtApex => "cname_at_apex"
  | .twoDnames _ => "two_dnames"
  | .dataBelowDname _ => "data_below_dname"
  | .dataBelowCut _ _ => "data_below_cut"
  | .dsNotAtCut _ => "ds_not_at_cut"
  | .missingInDomainGlue _ _ => "missing_in_domain_glue"
  | .targetIsAlias _ _ => "target_is_alias"
  | .rrsetTtlsDiffer _ _ => "rrset_ttls_differ"
  | .ttlTooLarge _ _ => "ttl_too_large"
  | .missingApexNs => "missing_apex_ns"

/-- A zone the builder refuses: an accepted zone changed to break one of the 12 rules, each as often as the
others. Each change breaks only its own rule, so it is the one the builder reports. -/
def rBroken : G Spec := do
  let (sp, _) ← rZone
  let apex := sp.apex
  let other : Name := [lb "example", lb "net"]
  let cut := lb "cut" :: apex
  let addr (owner : Name) (ttl : Nat) : RRset := ⟨owner, 1, ttl, [.a [192, 0, 2, 9]]⟩
  let add (sets : List RRset) : Spec := { sp with sets := sp.sets ++ sets }
  match ← rNat 12 with
  -- RFC 1034 §4.2: a record outside the zone.
  | 0 => return add [addr [lb "elsewhere", lb "org"] 300]
  -- RFC 1034 §3.6.2: a CNAME beside an address.
  | 1 => return add [⟨lb "both" :: apex, 5, 300, [.cname other]⟩, addr (lb "both" :: apex) 300]
  -- RFC 1912 §2.4: a CNAME at the apex.
  | 2 => return add [⟨apex, 5, 300, [.cname other]⟩]
  -- RFC 6672 §2.4: two DNAME records at one owner.
  | 3 => return add [⟨lb "e" :: apex, 39, 300, [.dname other, .dname [lb "other", lb "org"]]⟩]
  -- RFC 6672 §2.4: data below a DNAME.
  | 4 => return add [⟨lb "e" :: apex, 39, 300, [.dname other]⟩, addr ([lb "x", lb "e"] ++ apex) 300]
  -- RFC 1034 §4.2.1: data that is not glue below a cut.
  | 5 => return { add [⟨lb "x" :: cut, 16, 300, [.txt [toBytes "x"]]⟩] with
      delegations := sp.delegations ++ [⟨cut, 86400, [[lb "ns", lb "other", lb "org"]], [], none⟩] }
  -- RFC 4035 §2.4: a DS RRset at a name that is no cut.
  | 6 => return add [⟨lb "dsx" :: apex, 43, 300, [.ds 12345 13 2 (← rBytes 8)]⟩]
  -- RFC 9471 §3.1: a nameserver below its own cut with no glue.
  | 7 => return { sp with delegations := sp.delegations ++ [⟨cut, 86400, [lb "ns" :: cut], [], none⟩] }
  -- RFC 2181 §10.3: an MX target that is an alias, the owner of a CNAME or a name below a DNAME
  -- (RFC 6672 §2.2).
  | 8 =>
    if ← chance 2 then
      return add [⟨lb "alias" :: apex, 5, 300, [.cname other]⟩,
        ⟨lb "mx2" :: apex, 15, 300, [.mx 10 (lb "alias" :: apex)]⟩]
    else
      return add [⟨lb "moved" :: apex, 39, 300, [.dname other]⟩,
        ⟨lb "mx2" :: apex, 15, 300, [.mx 10 ([lb "mail", lb "moved"] ++ apex)]⟩]
  -- RFC 2181 §5.2: two TTLs in one RRset.
  | 9 => return add [addr (lb "ttl" :: apex) 300, ⟨lb "ttl" :: apex, 1, 600, [.a [192, 0, 2, 10]]⟩]
  -- RFC 2181 §8: a TTL of 2^31.
  | 10 => return add [addr (lb "big" :: apex) maxTtl]
  -- RFC 1034 §4.2.1: no NS RRset at the apex.
  | _ => return { sp with sets := sp.sets.filter fun s => !(s.owner == apex && s.rtype == 2) }

/-- A zone question, or now and then a zone the builder refuses, with the rule it breaks first. -/
def zoneCase : G String := do
  if ← chance 8 then
    let sp ← rBroken
    if let .error e := build sp then
      return jobj [("input", jobj [("zone", specJson sp)]), ("expected", jobj [("error", jstr (zoneErrorStr e))])]
  let (sp, z) ← rZone
  let q : Request := ⟨← rQname z, ← rQtype⟩
  let any ← rAny
  let expected := match answer z q any with
    | .response r => responseJson r
    | .unknown n => jobj [("unknown", jstr (nameStr n))]
  return jobj [("input", jobj ([("zone", specJson sp)] ++ anyFields any ++
      [("request", jobj [("qname", jstr (nameStr q.qname)), ("qtype", jstr (typeStr q.qtype))])])),
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
  return jobj [("input", jobj ([("zone", specJson sp), ("unknown", jarr (unknown.map (jstr ∘ nameStr)))] ++
      anyFields any ++
      [("request", jobj [("qname", jstr (nameStr q.qname)), ("qtype", jstr (typeStr q.qtype))])])),
    ("expected", expected)]

end Zones

/-! ## DNSSEC records in presentation form

Keys and signatures are symbolic. A key is a number below 256; its DNSKEY's public key field is the
base64 of that one octet, and its key tag is the number. A signature made with private key `p` has the key
tag of its RRSIG, and signature field the base64 of `p` as two octets; it verifies exactly when `p` is the
key, below 256, and it covers the records shown, key tag included. A corrupted key signs with `p = key + 1000`.
A mistagged key's RRSIGs carry key tag `key + 512`, which names no key. A DS digest is the hex of the identity
encoding of the owner and key (`Dnssec.Symbolic.scheme.digest`). NSEC3 hashes are real SHA-1 with an empty
salt and no extra iterations, written in base32hex. -/

section DnssecText
open Zone Dnssec

abbrev Sch := Symbolic.scheme

def b64ch (i : Nat) : Char :=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toList[i % 64]!

def b64go : List Nat → List Char
  | a :: b :: c :: rest =>
    let n := a * 65536 + b * 256 + c
    [b64ch (n / 262144), b64ch (n / 4096), b64ch (n / 64), b64ch n] ++ b64go rest
  | [a, b] => let n := a * 65536 + b * 256; [b64ch (n / 262144), b64ch (n / 4096), b64ch (n / 64), '=']
  | [a] => let n := a * 65536; [b64ch (n / 262144), b64ch (n / 4096), '=', '=']
  | [] => []

/-- Base64 (RFC 4648 §4). -/
def base64 (bs : List Nat) : String := String.ofList (b64go bs)

/-- A 160-bit NSEC3 hash in base32hex (RFC 4648 §7), lowercase. -/
def b32hex (n : Nat) : String :=
  String.ofList ((List.range 32).map fun i => "0123456789abcdefghijklmnopqrstuv".toList[n / 2 ^ (155 - 5 * i) % 32]!)

def bitmapStr (ts : List Nat) : String := " ".intercalate ((sortBy (· < ·) ts).map typeStr)

def nsec3Owner (r : Nsec3) : Name := toBytes (b32hex r.hash) :: r.zone

def payloadOwner : Payload → Name
  | .rrset s => s.owner
  | .keys o _ => o
  | .nsec r => r.owner
  | .nsec3 r => nsec3Owner r

def covered : Payload → Nat
  | .rrset s => s.rtype
  | .keys _ _ => 48
  | .nsec _ => 47
  | .nsec3 _ => 50

def keyLine (o : Name) (ttl : Nat) (k : Key) : String :=
  s!"{nameStr o} {ttl} IN DNSKEY {if k.sep then 257 else 256} 3 {k.alg} {base64 k.pub}"

def payloadLines (ttl : Nat) : Payload → List String
  | .rrset s => rrsetLines s
  | .keys o ks => ks.map (keyLine o ttl)
  | .nsec r => [s!"{nameStr r.owner} {ttl} IN NSEC {nameStr r.next} {bitmapStr r.types}"]
  | .nsec3 r =>
    [s!"{nameStr (nsec3Owner r)} {ttl} IN NSEC3 1 {if r.optOut then 1 else 0} {r.iterations} - {b32hex r.next}" ++
      (if r.types.isEmpty then "" else " " ++ bitmapStr r.types)]

def rrsigLine (owner : Name) (ttl cov : Nat) (r : Rrsig Sch) : String :=
  let p := (r.sig : Nat × Tbs).1
  s!"{nameStr owner} {ttl} IN RRSIG {typeStr cov} {r.hdr.alg} {r.hdr.labels} {r.hdr.ttl} " ++
    s!"{r.hdr.expiration} {r.hdr.inception} {r.hdr.tag} {nameStr r.hdr.signer} {base64 [p / 256 % 256, p % 256]}"

/-- The lines of records and the RRSIGs over them; RRSIGs take the TTL of the records they cover. -/
def signedLines (ttl : Nat) (d : Signed Sch) : List String :=
  payloadLines ttl d.data ++ d.sigs.map (rrsigLine (payloadOwner d.data) ttl (covered d.data))

def setWithSigsLines (p : RRset × List (Rrsig Sch)) : List String :=
  rrsetLines p.1 ++ p.2.map (rrsigLine p.1.owner p.1.ttl p.1.rtype)

def insecureStr : Insecure → String
  | .provenNoDs => "proven_no_ds" | .optOutCovered => "opt_out_covered" | .noAnchor => "no_anchor"
  | .unsupportedAlgorithm => "unsupported_algorithm" | .unsupportedDigest => "unsupported_digest"
  | .nsec3Iterations => "nsec3_iterations"

def validationJson : Validation → String
  | .notPerformed => jobj [("result", jstr "not_performed")]
  | .secure => jobj [("result", jstr "secure")]
  | .insecure w => jobj [("result", jstr "insecure"), ("why", jstr (insecureStr w))]
  | .bogus e => jobj [("result", jstr "bogus"), ("ede", jnat e.code)]
  | .indeterminate => jobj [("result", jstr "indeterminate")]

def denialJson : Denial → String
  | .nsec => jobj [("kind", jstr "nsec")]
  | .nsec3 o => jobj [("kind", jstr "nsec3"), ("opt_out", jbool o)]

def windowJson (w : Window) : String := jobj [("inception", jnat w.inception), ("expiration", jnat w.expiration)]

def policyJson (P : AlgorithmPolicy) : String :=
  jobj [("validate", jarr (P.validate.map jnat)), ("digests", jarr (P.digests.map jnat)),
    ("max_nsec3_iterations", jnat P.maxIterations)]

/-- `Policy.iana` by name, so the test runs Rust's own `AlgorithmPolicy::iana` against it rather than a copy of
its lists. -/
def ianaJson : String := jstr "iana"

end DnssecText

/-! ## Signed zones -/

section Signed
open Zone Dnssec

/-- A symbolic key as the vectors give it. A corrupted key's signatures do not verify. A mistagged key's
RRSIGs reach the validator with a key tag that names no key, as a broken server may send them, signed over
that tag, so only the key tag check tells them apart. -/
structure KeySpec where
  id : Nat
  alg : Nat
  sep : Bool
  corrupt : Bool
  mistag : Bool

def KeySpec.signer (k : KeySpec) : Signer Sch :=
  if k.corrupt then ⟨⟨Sch.pub k.id, k.alg, k.sep⟩, fun m => ((k.id + 1000 : Nat), m)⟩
  else Signer.ofPriv (S := Sch) k.id k.alg k.sep

def keysJson (ks : List KeySpec) : String :=
  jarr (ks.map fun k =>
    jobj [("id", jnat k.id), ("alg", jnat k.alg), ("sep", jbool k.sep), ("corrupt", jbool k.corrupt),
      ("mistag", jbool k.mistag)])

/-- A KSK and, often, a ZSK, with algorithms the policy validates and sometimes RSASHA1. With `mistag`, a key
is sometimes mistagged. -/
def rKeys (mistag : Bool := false) : G (List KeySpec) := do
  let id1 ← rRange 1 127
  let alg ← pick #[13, 13, 8, 15, 14, 5]
  let k1 : KeySpec := ⟨id1, alg, true, ← chance 8, mistag && (← chance 8)⟩
  if ← chance 3 then return [k1]
  let k2 : KeySpec := ⟨id1 + 128, alg, false, ← chance 8, mistag && (← chance 8)⟩
  return [k1, k2]

/-- An RRSIG as it reaches the validator: a mistagged key's carries key tag `key + 512`, and its signature is
over that tag. -/
def retag (ks : List KeySpec) (r : Rrsig Sch) : Rrsig Sch :=
  let p := (r.sig : Nat × Tbs).1
  if ks.any (fun k => k.mistag && k.id == p % 1000) then
    let h := { r.hdr with tag := p % 1000 + 512 }
    ⟨h, (p, { (r.sig : Nat × Tbs).2 with hdr := h })⟩
  else r

def retagSigned (ks : List KeySpec) (d : Signed Sch) : Signed Sch := { d with sigs := d.sigs.map (retag ks) }

def retagAnswer (ks : List KeySpec) (sa : SignedAnswer Sch) : SignedAnswer Sch :=
  let pair := fun (p : RRset × List (Rrsig Sch)) => (p.1, p.2.map (retag ks))
  { sa with answer := sa.answer.map pair, anyExtra := sa.anyExtra.map (retagSigned ks),
            authority := sa.authority.map pair, denial := sa.denial.map (retagSigned ks) }

/-- The lines of a DNSSEC RRset an answer to ANY carries, owned by `owner`, with its RRSIGs. -/
def extraLines (sz : SignedZone Sch) (owner : Name) (d : Signed Sch) : List String :=
  let (data, ttl) : Payload × Nat := match d.data with
    | .nsec r => (.nsec { r with owner := owner }, sz.denialTtl)
    | .keys _ ks => (.keys owner ks, sz.zone.soa.ttl)
    | p => (p, sz.denialTtl)
  payloadLines ttl data ++ d.sigs.map (rrsigLine owner ttl (covered d.data))

/-- A zone the builder accepts, without DNAME: a CNAME a DNAME synthesizes has no RRSIG, and its validation
goes through the DNAME, which this model does not do. -/
def rSignedZone : G (Spec × Zone) := do
  let mut tries := 0
  while tries < 1000 do
    tries := tries + 1
    let sp ← rSpec
    let sp := { sp with sets := sp.sets.filter (·.rtype != 39) }
    match build sp with
    | .ok z => return (sp, z)
    | .error _ => pure ()
  rZone

instance : Inhabited Denial := ⟨.nsec⟩

def rDenial : G Denial := pick #[.nsec, .nsec, .nsec3 false, .nsec3 true]

/-- A signed parent of `z` at the name above its apex, delegating to it: the parent's DS set at the cut names
`z`'s KSK (most often), names it with a wrong digest or with RSASHA1, or is absent, so the chain from the
parent's anchor down to `z` is Secure, Bogus, or Insecure by the parent's proof. -/
def rParent (z : Zone) (keys : List KeySpec) : G (Spec × List KeySpec × Denial) := do
  let papex := z.apex.drop 1
  let ksk := keys.find? (·.sep)
  let kskAlg := (ksk.map (·.alg)).getD 13
  let kskKey : Key := (ksk.map fun k => (⟨Sch.pub k.id, k.alg, true⟩ : Key)).getD ⟨[0], 13, true⟩
  let ds : Option (Nat × List Zone.RData) := match ← rNat 5 with
    | 0 => none
    | 1 | 2 => some (86400, [.ds 0 kskAlg 2 (Sch.digest z.apex kskKey)])
    | 3 => some (86400, [.ds 0 kskAlg 2 [1, 2, 3, 4]])
    | _ => some (86400, [.ds 0 5 2 (Sch.digest z.apex { kskKey with alg := 5 })])
  let soa : Zone.RData := .soa (lb "ns1" :: papex) (lb "hostmaster" :: papex) 1 7200 3600 1209600 300
  let ns := lb "ns1" :: z.apex
  let parent : Spec := ⟨papex, 3600, soa, [⟨papex, 2, 3600, [.ns (lb "ns1" :: papex)]⟩,
      ⟨lb "ns1" :: papex, 1, 3600, [.a [192, 0, 2, 2]]⟩],
    [⟨z.apex, 86400, [ns], [⟨ns, 1, 86400, [.a [192, 0, 2, 1]]⟩], ds⟩]⟩
  return (parent, ← rKeys, ← rDenial)

/-- A signed answer to `q` as the vectors give it: its RCODE and AA, each section's lines with their RRSIGs,
and the denial records. -/
def signedAnswerFields (sz : SignedZone Sch) (q : Request) (sa : SignedAnswer Sch) : List (String × String) :=
  [("rcode", jstr (rcodeStr sa.rcode)), ("aa", jbool sa.aa),
    ("answer", jarr ((sa.answer.flatMap setWithSigsLines ++ sa.anyExtra.flatMap (extraLines sz q.qname)).map jstr)),
    ("authority", jarr ((sa.authority.flatMap setWithSigsLines).map jstr)),
    ("additional", setsJson sa.additional),
    ("denial", jarr ((sa.denial.flatMap (signedLines sz.denialTtl)).map jstr))]

def signedCase : G String := do
  let (sp, z) ← rSignedZone
  let keys ← rKeys true
  let denial ← rDenial
  -- RRSIG times are serial numbers (RFC 4034 §3.1.5): some windows end 2^31 or more after they begin, some
  -- times are more than 2^31 past the expiration, which serial arithmetic reads as before the inception, and
  -- some cases move window and time past 2^32, where the RRSIG fields wrap.
  let w : Window := ⟨100, ← pick #[200, 200, 200, 200, 150, 300, 100 + 2147483648, 100 + 2147483658]⟩
  let t ← pick #[50, 100, 150, 150, 150, 199, 200, 250, 200 + 2147483649]
  let shift ← pick #[0, 0, 4294967146]
  let w : Window := ⟨w.inception + shift, w.expiration + shift⟩
  let t := t + shift
  let q : Request := ⟨← rQname z, ← rQtype⟩
  let sz : SignedZone Sch := SignedZone.make z (keys.map (·.signer)) w denial
  -- The zone's DNSKEY set as it reaches the validator.
  let keySet := retagSigned keys sz.keySet
  -- Half the zones that can have a parent get one, so the validation walks down a delegation from the
  -- parent's anchor; the rest are anchored at their own apex.
  let parent : Option (Spec × List KeySpec × Denial) ←
    if 2 ≤ z.apex.length && (← chance 2) then some <$> rParent z keys else pure none
  let below := parent.map fun ((psp, pkeys, pd) : Spec × List KeySpec × Denial) =>
    let pz : SignedZone Sch := SignedZone.make psp.assemble (pkeys.map KeySpec.signer) w pd
    (pz, { Dns.Chain.linkBelow pz sz with keys := some keySet })
  let (anchors, chain) := match below with
    | some (pz, link) => ([pz.anchor 2], [pz.link, link])
    | none => ([sz.anchor 2], [{ sz.link with keys := some keySet }])
  let delegation : List String := match below with
    | some (pz, link) => match link.parent with
      | some (.ds sd) => signedLines 86400 sd
      | some (.noDs ds) => ds.flatMap (signedLines pz.denialTtl)
      | none => []
    | none => []
  let parentOut : List (String × String) := match below with
    | some (pz, _) => [("parent_dnskey", jarr ((signedLines pz.zone.soa.ttl pz.keySet).map jstr)),
        ("delegation", jarr (delegation.map jstr))]
    | none => []
  -- Sometimes the SOA RRset of the answer reaches the validator without its RRSIGs, so a negative answer
  -- whose denial records verify still fails on its SOA.
  let stripSoa ← chance 6
  let expected := match sz.answerDo q .all with
    | (.response _, some sa) =>
      let sa := retagAnswer keys sa
      let sa := if stripSoa then
        { sa with authority := sa.authority.map fun (s, sigs) => (s, if s.rtype == 6 then [] else sigs) }
        else sa
      let (vs, dv) := validateAnswer (some anchors) Policy.iana t chain q sa
      jobj (signedAnswerFields sz q sa ++ [
        ("dnskey", jarr ((signedLines z.soa.ttl keySet).map jstr)),
        ("validation", jobj [("answer", jarr (vs.map validationJson)),
          ("denial", (dv.map validationJson).getD "null")])] ++ parentOut)
    | (.unknown n, _) => jobj [("unknown", jstr (nameStr n))]
    | (.response _, none) => "null"
  let parentIn : List (String × String) := match parent with
    | some (psp, pkeys, pd) =>
      [("parent", jobj [("zone", specJson psp), ("keys", keysJson pkeys), ("denial", denialJson pd)])]
    | none => []
  return jobj [("input", jobj ([("zone", specJson sp), ("keys", keysJson keys), ("window", windowJson w),
      ("denial", denialJson denial), ("request", jobj [("qname", jstr (nameStr q.qname)),
        ("qtype", jstr (typeStr q.qtype))]), ("time", jnat t), ("policy", ianaJson),
      ("anchor_digest_type", jnat 2), ("strip_soa", jbool stripSoa)] ++ parentIn)),
    ("expected", expected)]

end Signed

/-! ## The algorithm policy -/

section PolicyVectors
open Dnssec

def treatmentStr : Treatment → String
  | .supported => "supported" | .unsupportedAlgorithm => "unsupported_algorithm"
  | .unsupportedDigest => "unsupported_digest"

def rSubset (xs : List Nat) : G (List Nat) := do
  let mut out := []
  for x in xs do
    if ← chance 2 then out := out ++ [x]
  return out

def policyCase : G String := do
  let (P, named) ← if ← chance 2 then pure (Policy.iana, ianaJson)
    else do
      let v ← rSubset [5, 7, 8, 10, 13, 14, 15, 16]
      let d ← rSubset [1, 2, 3, 4]
      let P : AlgorithmPolicy := { validate := v, digests := d, sign := [], delegate := [], maxIterations := 100 }
      pure (P, policyJson P)
  let alg ← pick #[1, 3, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16, 17, 23, 253]
  let dt ← pick #[0, 1, 2, 3, 4, 5, 6]
  return jobj [("input", jobj [("algorithm", jnat alg), ("digest", jnat dt), ("policy", named)]),
    ("expected", jobj [("treatment", jstr (treatmentStr (P.treat alg dt)))])]

end PolicyVectors

/-! ## Chains -/

section ChainVectors
open Zone Dnssec Chain

def problemJson : Problem → String
  | .dsMismatch p c => jobj [("kind", jstr "ds_mismatch"), ("parent", jstr (nameStr p)), ("child", jstr (nameStr c))]
  | .noDsProofMissing p c =>
    jobj [("kind", jstr "no_ds_proof_missing"), ("parent", jstr (nameStr p)), ("child", jstr (nameStr c))]
  | .windowClosed a t => jobj [("kind", jstr "window_closed"), ("apex", jstr (nameStr a)), ("time", jnat t)]
  | .unsupportedAlgorithm a alg =>
    jobj [("kind", jstr "unsupported_algorithm"), ("apex", jstr (nameStr a)), ("algorithm", jnat alg)]

/-- The keys of a zone in a chain: those of `rKeys`, and half the time a second set of the same shape in another
algorithm, so the zone is signed with two and one validated algorithm is enough for a path (RFC 6840 §5.11).
With the same shape, each algorithm signs the zone's data, as `DataAlgorithms` asks. -/
def rChainKeys : G (List KeySpec) := do
  let keys ← rKeys
  if ← chance 2 then return keys
  let first := (keys.head?.map (·.alg)).getD 13
  let alg ← pick (#[13, 8, 15, 14, 5].filter (· != first))
  return keys ++ keys.map fun k => { k with alg := alg }

/-- A parent with a delegation to `sub` and the child zone: the parent's DS set at the cut names the child's
KSK, names it with a wrong digest or an unsupported algorithm or digest type, names it beside a record of an
algorithm the policy does not validate, names every KSK of the child, or is absent. -/
def chainCase : G String := do
  let apex : Name := [lb "example", lb "com"]
  let child : Name := lb "sub" :: apex
  let parentKeys ← rChainKeys
  let childKeys ← do if ← chance 4 then pure [] else rChainKeys
  let choice ← rNat 7
  let kskAlg := ((childKeys.find? (·.sep)).map (·.alg)).getD 13
  let kskKey : Key :=
    ((childKeys.find? (·.sep)).map fun k => (⟨Sch.pub k.id, k.alg, true⟩ : Key)).getD ⟨[0], 13, true⟩
  let named (k : KeySpec) : Zone.RData := .ds 0 k.alg 2 (Sch.digest child ⟨Sch.pub k.id, k.alg, true⟩)
  let ksks := childKeys.filter (·.sep)
  let ds : Option (Nat × List Zone.RData) := match choice with
    | 0 => none
    | 1 => some (86400, [.ds 0 kskAlg 2 (Sch.digest child kskKey)])
    | 2 => some (86400, [.ds 0 kskAlg 2 [1, 2, 3, 4]])
    | 3 => some (86400, [.ds 0 5 2 (Sch.digest child { kskKey with alg := 5 })])
    | 4 => some (86400, [.ds 0 kskAlg 2 (Sch.digest child kskKey),
        .ds 0 5 2 (Sch.digest child { kskKey with alg := 5 })])
    | 5 => some (86400, if ksks.isEmpty then [.ds 0 kskAlg 2 (Sch.digest child kskKey)] else ksks.map named)
    | _ => some (86400, [.ds 0 kskAlg 3 (Sch.digest child kskKey)])
  let soa (a : Name) : Zone.RData := .soa (lb "ns1" :: a) (lb "hostmaster" :: a) 1 7200 3600 1209600 300
  let parentSpec : Spec := ⟨apex, 3600, soa apex, [⟨apex, 2, 3600, [.ns (lb "ns1" :: apex)]⟩,
      ⟨lb "ns1" :: apex, 1, 3600, [.a [192, 0, 2, 1]]⟩, ⟨lb "www" :: apex, 1, 300, [.a [192, 0, 2, 2]]⟩],
    [⟨child, 86400, [lb "ns" :: child], [⟨lb "ns" :: child, 1, 86400, [.a [192, 0, 2, 53]]⟩], ds⟩]⟩
  let childSpec : Spec := ⟨child, 3600, soa child, [⟨child, 2, 3600, [.ns (lb "ns" :: child)]⟩,
      ⟨lb "ns" :: child, 1, 3600, [.a [192, 0, 2, 53]]⟩, ⟨lb "www" :: child, 1, 300, [.a [192, 0, 2, 80]]⟩], []⟩
  -- As in `signedCase`, some windows and times reach past 2^32, where RRSIG times wrap (RFC 4034 §3.1.5).
  let shift ← pick #[0, 0, 0, 4294967146]
  let pw : Window := ⟨100 + shift, (← pick #[200, 200, 120, 100 + 2147483648]) + shift⟩
  let cw : Window := ⟨100 + shift, (← pick #[200, 200, 120]) + shift⟩
  let pd ← rDenial
  let cd ← rDenial
  let t := (← pick #[150, 150, 110, 250]) + shift
  let pz : SignedZone Sch := ⟨parentSpec.assemble, parentKeys.map (·.signer), pw, pd⟩
  let cz : SignedZone Sch := ⟨childSpec.assemble, childKeys.map (·.signer), cw, cd⟩
  let zoneIn (sp : Spec) (ks : List KeySpec) (w : Window) (d : Denial) : String :=
    jobj [("zone", specJson sp), ("keys", keysJson ks), ("window", windowJson w), ("denial", denialJson d)]
  return jobj [("input", jobj [("tree", jarr [zoneIn parentSpec parentKeys pw pd, zoneIn childSpec childKeys cw cd]),
      ("time", jnat t), ("policy", ianaJson)]),
    ("expected", jobj [("problems", jarr ((check [pz, cz] Policy.iana t).map problemJson))])]

end ChainVectors

/-! ## The cache -/

section CacheVectors
open Zone Dnssec Cache

def rankStr : Rank → String
  | .glue => "glue" | .nonAuthAuthority => "non_auth_authority" | .nonAuthAnswer => "non_auth_answer"
  | .authAuthority => "auth_authority" | .authAnswer => "auth_answer"

def negativeStr : Negative → String
  | .nxDomain => "nxdomain" | .noData => "nodata"

def failureJson : FailureKind → String
  | .noReachableAuthority => jobj [("kind", jstr "no_reachable_authority")]
  | .workExceeded => jobj [("kind", jstr "work_exceeded")]
  | .unknown => jobj [("kind", jstr "unknown")]

def keyJson (k : Cache.Key) : String := jobj [("name", jstr (nameStr k.name)), ("type", jstr (typeStr k.rtype))]

def optNat : Option Nat → String
  | some n => jnat n
  | none => "null"

def offerJson : Offer → String
  | .positive s r v sig orig tc =>
    jobj [("kind", jstr "positive"), ("set", setsJson [s]), ("rank", jstr (rankStr r)),
      ("validation", validationJson v), ("sig_expires", optNat sig), ("original_ttl", optNat orig),
      ("truncated", jbool tc)]
  | .negative k kind soa r nsec v sig orig tc =>
    jobj [("kind", jstr "negative"), ("key", keyJson k), ("negative", jstr (negativeStr kind)),
      ("soa", (soa.map fun s => setsJson [s]).getD "null"), ("rank", jstr (rankStr r)),
      ("denial_ttl", optNat nsec),
      ("validation", validationJson v), ("sig_expires", optNat sig), ("original_ttl", optNat orig),
      ("truncated", jbool tc)]
  | .failure k why _ => jobj [("kind", jstr "failure"), ("key", keyJson k), ("why", failureJson why)]

def servedJson : Option Served → String
  | none => "null"
  | some (.positive s v) => jobj [("positive", setsJson [s]), ("validation", validationJson v)]
  | some (.negative kind soa v) =>
    jobj [("negative", jstr (negativeStr kind)), ("soa", setsJson [soa]), ("validation", validationJson v)]
  | some (.failure why) => jobj [("failure", failureJson why)]

instance : Inhabited Rank := ⟨.glue⟩
instance : Inhabited Validation := ⟨.notPerformed⟩
instance : Inhabited Cache.Key := ⟨⟨[], 1⟩⟩

/-- The keys offers are made for: one type at each name, the names in a line from `example.` down to
`x.nope.example.`, so an NXDOMAIN at one name answers for the names below it (RFC 8020 §2) and data at one name
ends an NXDOMAIN above it. -/
def cacheKeys : Array Cache.Key := #[⟨[lb "www", lb "example"], 1⟩, ⟨[lb "mail", lb "example"], 15⟩,
  ⟨[lb "nope", lb "example"], 1⟩, ⟨[lb "x", lb "nope", lb "example"], 1⟩, ⟨[lb "example"], 1⟩]

/-- The keys served: those, other types at their names, which an NXDOMAIN answers too (RFC 2308 §5), and a name
below them all. -/
def serveKeys : Array Cache.Key := cacheKeys ++ #[⟨[lb "www", lb "example"], 16⟩, ⟨[lb "nope", lb "example"], 15⟩,
  ⟨[lb "y", lb "x", lb "nope", lb "example"], 1⟩]

instance : Inhabited Negative := ⟨.nxDomain⟩
instance : Inhabited FailureKind := ⟨.unknown⟩

def rOption {α : Type} (g : G α) : G (Option α) := do
  if ← chance 2 then return some (← g) else return none

def rOffer : G Offer := do
  let k ← pick cacheKeys
  let ttl ← pick #[0, 60, 300, 300, 86400, 2147483653, 1000000]
  let v ← pick #[Validation.secure, .secure, .notPerformed, .insecure .provenNoDs, .bogus .expired,
    .indeterminate]
  -- The first RRSIG expiration and the smallest Original TTL validation found.
  let sig ← rOption (pick #[150, 500, 2000])
  let orig ← rOption (pick #[30, 300, 2147483653])
  match ← rNat 5 with
  | 0 | 1 =>
    let octet ← rNat 256
    let rd : Zone.RData := if k.rtype == 15 then .mx 10 [lb "mx", lb "example"] else .a [192, 0, 2, octet]
    let rank ← pick #[.authAnswer, .nonAuthAnswer, .glue, .nonAuthAuthority, .authAuthority]
    return .positive ⟨k.name, k.rtype, ttl, [rd]⟩ rank v sig orig (← chance 8)
  | 2 | 3 =>
    let minimum ← pick #[30, 300, 3600]
    let soa : RRset :=
      ⟨[lb "example"], 6, ttl, [.soa [lb "ns", lb "example"] [lb "h", lb "example"] 1 2 3 4 minimum]⟩
    let kind ← pick #[.nxDomain, .noData]
    let soa? := if ← chance 6 then none else some soa
    let denialTtl ← rOption (pick #[10, 100, 7200])
    -- An authoritative server's negative, or a forwarder's.
    let rank ← pick #[.authAnswer, .nonAuthAnswer]
    return .negative k kind soa? rank denialTtl v sig orig (← chance 8)
  | _ => return .failure k (← pick #[.noReachableAuthority, .workExceeded, .unknown]) none

def cacheCase : G String := do
  let lim : Limits := ⟨← pick #[3600, 604800], ← pick #[5, 30, 300]⟩
  let n ← rRange 3 20
  let mut c : Cache := ⟨0, []⟩
  let mut now := 0
  let mut ops : Array String := #[]
  let mut results : Array String := #[]
  for _ in [0:n] do
    -- A step past one failure TTL lands where a failure that persisted outlasts the one before it.
    now := now + (← pick #[0, 1, 10, 100, 1000, lim.failureTtl + 1])
    match ← rNat 6 with
    | 0 | 1 | 2 =>
      -- A failed resolution begins and ends at `now`.
      let o := match ← rOffer with
        | .failure k why _ => .failure k why (persisting now c k)
        | o => o
      c := insert now lim c o
      ops := ops.push (jobj [("op", jstr "offer"), ("time", jnat now), ("offer", offerJson o)])
    | 3 =>
      c := advance c
      ops := ops.push (jobj [("op", jstr "advance"), ("time", jnat now)])
    | _ =>
      let k ← pick serveKeys
      ops := ops.push (jobj [("op", jstr "serve"), ("time", jnat now), ("key", keyJson k)])
      results := results.push (servedJson (serve now c k))
  return jobj [("input", jobj [("limits", jobj [("max_ttl", jnat lim.maxTtl), ("failure_ttl", jnat lim.failureTtl)]),
      ("ops", jarr ops.toList)]),
    ("expected", jobj [("served", jarr results.toList)])]

end CacheVectors

/-! ## The resolver -/

section ResolverVectors
open Zone Resolver

def itemJson (st : Stored) : String :=
  match st.item with
  | .cut ns => jobj [("rank", jstr (rankStr st.rank)), ("cut", setsJson [ns])]
  | .glue s => jobj [("rank", jstr (rankStr st.rank)), ("glue", setsJson [s])]
  | .answer q r => jobj [("rank", jstr (rankStr st.rank)), ("question", jobj [("qname", jstr (nameStr q.qname)),
      ("qtype", jstr (typeStr q.qtype))]), ("response", responseJson r)]

instance : Inhabited Request := ⟨⟨[], 1⟩⟩

/-- Each server name of the resolver vectors at an address of its own, so a server lost or dead is one
address in Rust too. -/
def addrOf (n : Name) : List Nat :=
  match nameStr n with
  | "a." => [198, 41, 0, 4]
  | "b." => [170, 247, 170, 2]
  | "ns1.test." => [192, 0, 2, 11]
  | "ns2.test." => [192, 0, 2, 12]
  | "ns1.example." => [192, 0, 2, 21]
  | "ns.sub.example." => [192, 0, 2, 31]
  | _ => [192, 0, 2, 99]

/-- Feeds the resolver's sends to the network, where the servers in `dead` never answer and every other server
answers, until it answers. -/
def driveDead (net : Net) (dead : List Name) : Nat → State × List Resolver.Out → Option (Response × State)
  | _, (st, [.answer r]) => some (r, st)
  | fuel + 1, (st, [.send s c q]) => driveDead net dead fuel (step st (deliver net .all c q (dead.contains s)))
  | _, _ => none

/-- Several questions in turn, sharing the cache, with the servers in `dead` never answering. -/
def runDead (net : Net) (cfg : Config) (dead : List Name) : State → List Request → List (Option Response)
  | _, [] => []
  | st, q :: qs =>
    match driveDead net dead (cfg.work + 1) (start cfg st q) with
    | some (r, st') => some r :: runDead net cfg dead st' qs
    | none => [none]

/-- Feeds the resolver's sends to the network, one loss decision each from the script, until it answers, and
gathers the servers it gave up on because a query to them was lost. -/
def driveLossy (net : Net) :
    Nat → State × List Resolver.Out → List Bool → List Name → Option (Response × State × List Bool × List Name)
  | _, (st, [.answer r]), ls, gone => some (r, st, ls, gone)
  | fuel + 1, (st, [.send s c q]), ls, gone =>
    let lost := ls.headD false
    driveLossy net fuel (step st (deliver net .all c q lost)) ls.tail (if lost then s :: gone else gone)
  | _, _, _, _ => none

/-- Several questions in turn, sharing the cache and one loss script, each with its answer and the servers the
script's losses made it give up on. -/
def runLossy (net : Net) (cfg : Config) : State → List Request → List Bool → List (Option (Response × List Name))
  | _, [], _ => []
  | st, q :: qs, ls =>
    match driveLossy net (cfg.work + 1) (start cfg st q) ls [] with
    | some (r, st', ls', gone) => some (r, gone) :: runLossy net cfg st' qs ls'
    | none => [none]

/-- A root zone delegating `test.` and `example.`; `example.` delegating `sub.example.`; each zone with a few
names. Some zones may have no servers, and the root may have one or two. -/
def resolverCase : G String := do
  let test : Name := [lb "test"]
  let ex : Name := [lb "example"]
  let sub : Name := lb "sub" :: ex
  let soa (a : Name) : Zone.RData := .soa (lb "ns1" :: a) (lb "hostmaster" :: a) 1 7200 3600 1209600 300
  let rootNs : List Name := if ← chance 2 then [[lb "a"]] else [[lb "a"], [lb "b"]]
  let testNs : List Name := if ← chance 2 then [lb "ns1" :: test] else [lb "ns1" :: test, lb "ns2" :: test]
  let glueFor (ns : List Name) : List RRset := ns.map fun n => ⟨n, 1, 86400, [.a (addrOf n)]⟩
  let rootSpec : Spec := ⟨[], 86400, soa [], ⟨[], 2, 518400, rootNs.map .ns⟩ ::
      rootNs.map (fun n => ⟨n, 1, 518400, [.a (addrOf n)]⟩),
    [⟨test, 172800, testNs, glueFor testNs, none⟩, ⟨ex, 172800, [lb "ns1" :: ex], glueFor [lb "ns1" :: ex], none⟩]⟩
  let testSpec : Spec := ⟨test, 3600, soa test, ⟨test, 2, 3600, testNs.map .ns⟩ :: glueFor testNs ++
      [⟨lb "www" :: test, 1, 300, [.a [192, 0, 2, 10]]⟩, ⟨lb "mail" :: test, 15, 300, [.mx 10 (lb "www" :: test)]⟩,
       ⟨lb "alias" :: test, 5, 300, [.cname (lb "www" :: test)]⟩], []⟩
  let exSpec : Spec := ⟨ex, 3600, soa ex, [⟨ex, 2, 3600, [.ns (lb "ns1" :: ex)]⟩] ++ glueFor [lb "ns1" :: ex] ++
      [⟨lb "www" :: ex, 1, 300, [.a [192, 0, 2, 20]]⟩],
    [⟨sub, 86400, [lb "ns" :: sub], glueFor [lb "ns" :: sub],
      if ← chance 2 then some (86400, [.ds 1 13 2 [7]]) else none⟩]⟩
  let subSpec : Spec := ⟨sub, 3600, soa sub, [⟨sub, 2, 3600, [.ns (lb "ns" :: sub)]⟩] ++ glueFor [lb "ns" :: sub] ++
      [⟨lb "www" :: sub, 1, 300, [.a [192, 0, 2, 30]]⟩], []⟩
  let mut specs : List Spec := [rootSpec, testSpec]
  if !(← chance 5) then specs := specs ++ [exSpec]
  if !(← chance 4) then specs := specs ++ [subSpec]
  let net : Net := specs.map Spec.assemble
  let pool : Array Request := #[⟨lb "www" :: test, 1⟩, ⟨lb "mail" :: test, 15⟩, ⟨lb "nope" :: test, 1⟩,
    ⟨lb "alias" :: test, 1⟩, ⟨test, 2⟩, ⟨lb "www" :: ex, 1⟩, ⟨lb "www" :: sub, 1⟩, ⟨sub, 43⟩,
    ⟨lb "x" :: sub, 16⟩, ⟨[lb "nowhere"], 1⟩, ⟨lb "www" :: test, 28⟩]
  let qs ← rList (← rRange 1 4) (pick pool)
  let losses ← rList (← rRange 0 6) (chance 3)
  let cfg : Config := ⟨rootNs, ← pick #[2, 3, 5, 8]⟩
  let (answers, final) := runAll net .all cfg ⟨[], none⟩ qs losses
  -- Servers that never answer, and the answers with them dead and work to spare.
  let servers : List Name := rootNs ++ testNs ++ [lb "ns1" :: ex, lb "ns" :: sub]
  let dead ← servers.filterM fun _ => chance 3
  let deadAnswers := runDead net ⟨rootNs, 64⟩ dead ⟨[], none⟩ qs
  -- The loss script with work to spare: each answer, and the servers its losses made the question give up on.
  let lossy := runLossy net ⟨rootNs, 64⟩ ⟨[], none⟩ qs losses
  let lossyJson : Option (Response × List Name) → String
    | some (r, gone) => jobj [("response", responseJson r), ("gone", jarr (gone.map (jstr ∘ nameStr)))]
    | none => "null"
  return jobj [("input", jobj [("zones", jarr (specs.map specJson)), ("hints", jarr (rootNs.map (jstr ∘ nameStr))),
      ("work", jnat cfg.work), ("any", jstr "all"),
      ("questions", jarr (qs.map fun q =>
        jobj [("qname", jstr (nameStr q.qname)), ("qtype", jstr (typeStr q.qtype))])),
      ("losses", jarr (losses.map jbool)), ("dead", jarr (dead.map (jstr ∘ nameStr)))]),
    ("expected", jobj [("answers", jarr (answers.map fun a => (a.map responseJson).getD "null")),
      ("dead_answers", jarr (deadAnswers.map fun a => (a.map responseJson).getD "null")),
      ("lossy_answers", jarr (lossy.map lossyJson)),
      ("cache", jarr (final.cache.map itemJson))])]

end ResolverVectors

/-! ## Key tags and QNAME minimisation -/

section KeyTagVectors
open Dnssec

/-- A DNSKEY's flags, algorithm, and public key, and its key tag (RFC 4034 Appendix B, RFC 6840 §5.5). The
lengths reach the empty key, keys shorter than the three octets algorithm 1 reads, odd and even lengths, and
keys long enough that the sum carries past 16 bits. -/
def keytagCase : G String := do
  let flags ← pick #[256, 257, 384, 385, 0, 1, 65535, ← rNat 65536]
  let alg ← pick #[1, 1, 5, 8, 13, 15, 16, 253, ← rNat 256]
  let len ← pick #[0, 1, 2, 3, 4, 31, 32, 64, 65, 96, 128, 260, 513]
  let pub ← rBytes len
  return jobj [("input", jobj [("flags", jnat flags), ("algorithm", jnat alg), ("public_key", jstr (hex pub))]),
    ("expected", jobj [("tag", jnat (keyTagOf flags alg pub))])]

end KeyTagVectors

section MinimiseVectors
open Resolver

instance : Inhabited Resolver.Minimise := ⟨⟨10, 4⟩⟩

/-- One minimised query: the bounds, the labels known and in all, the queries before it, and the labels it
shows (`Resolver.Minimise.next`), or null for the whole question. -/
def minimiseCase : G String := do
  let m : Resolver.Minimise ← pick #[⟨10, 4⟩, ⟨10, 4⟩, ⟨3, 1⟩, ⟨5, 5⟩, ⟨1, 0⟩, ⟨0, 0⟩, ⟨← rNat 12, ← rNat 12⟩]
  let total ← rRange 0 40
  let known ← rNat (total + 2)
  let steps ← rNat (m.maxQueries + 3)
  return jobj [("input", jobj [("max_queries", jnat m.maxQueries), ("one_label", jnat m.oneLabel),
      ("known", jnat known), ("total", jnat total), ("steps", jnat steps)]),
    ("expected", jobj [("labels", optNat (m.next known total steps))])]

end MinimiseVectors

/-! ## Output -/

def cases (n : Nat) (g : G String) : G (List String) := rList n g

def kinds : List (String × Nat × G String) :=
  [("names", 400, namesCase), ("wire", 400, wireCase), ("fit", 300, fitCase),
    ("respond", 400, respondCase), ("zone", 400, zoneCase), ("partial", 300, partialCase),
    ("signed", 300, signedCase), ("policy", 200, policyCase), ("chain", 200, chainCase),
    ("cache", 200, cacheCase), ("resolver", 200, resolverCase),
    ("keytag", 300, keytagCase), ("minimise", 300, minimiseCase),
    ("framing", 300, framingCase)]

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
