/-
  The message format of RFC 1035 §4: header, questions, resource records, and name compression; the
  decoder, the encoder, and the server front's request check and reply header.

  Rust: hickory's `BinEncoder` and `BinDecoder` under `protocols::dns`, and
  `protocols::dns::request::Request::parse`.
-/
import Dns.Name

namespace Dns.Wire
open Name

/-! ## Octets -/

def be16 (n : Nat) : Bytes := [n / 256 % 256, n % 256]
def be32 (n : Nat) : Bytes := [n / 16777216 % 256, n / 65536 % 256, n / 256 % 256, n % 256]

@[simp] theorem be16_length (n : Nat) : (be16 n).length = 2 := rfl
@[simp] theorem be32_length (n : Nat) : (be32 n).length = 4 := rfl

/-- `n` octets of `msg` from position `p`. -/
def slice (msg : Bytes) (p n : Nat) : Bytes := (msg.drop p).take n

def rd16 (msg : Bytes) (p : Nat) : Option Nat :=
  match msg[p]?, msg[p + 1]? with
  | some a, some b => some (a * 256 + b)
  | _, _ => none

def rd32 (msg : Bytes) (p : Nat) : Option Nat :=
  match rd16 msg p, rd16 msg (p + 2) with
  | some a, some b => some (a * 65536 + b)
  | _, _ => none

/-! ## Messages -/

/-- The fixed header. The flags word holds QR, OPCODE, AA, TC, RD, RA, Z, AD, CD, and RCODE in the layout of
RFC 1035 §4.1.1 and RFC 4035 §3.2. The four counts are not stored: they are the lengths of the sections. -/
structure Header where
  id : Nat
  flags : Nat
deriving DecidableEq, Repr, Inhabited

namespace Header
def bit (h : Header) (k : Nat) : Bool := h.flags / 2 ^ k % 2 == 1
def qr (h : Header) : Bool := h.bit 15
def opcode (h : Header) : Nat := h.flags / 2048 % 16
def aa (h : Header) : Bool := h.bit 10
def tc (h : Header) : Bool := h.bit 9
def rd (h : Header) : Bool := h.bit 8
def ra (h : Header) : Bool := h.bit 7
def z (h : Header) : Bool := h.bit 6
def ad (h : Header) : Bool := h.bit 5
def cd (h : Header) : Bool := h.bit 4
def rcode (h : Header) : Nat := h.flags % 16
end Header

def b2n (b : Bool) : Nat := if b then 1 else 0

/-- The flags word from its fields. -/
def flagsOf (qr : Bool) (opcode : Nat) (aa tc rd ra z ad cd : Bool) (rcode : Nat) : Nat :=
  b2n qr * 32768 + opcode % 16 * 2048 + b2n aa * 1024 + b2n tc * 512 + b2n rd * 256 + b2n ra * 128 +
    b2n z * 64 + b2n ad * 32 + b2n cd * 16 + rcode % 16

structure Question where
  name : Name
  qtype : Nat
  qclass : Nat
deriving DecidableEq, Repr, Inhabited

/-- RDATA as the codec sees it. The RFC 1035 types whose RDATA holds domain names are `names`: some fixed
octets, the names, and more fixed octets. Every other type is `octets`, carried octet for octet (RFC 3597). -/
inductive RData where
  | names (pre : Bytes) (ns : List Name) (post : Bytes)
  | octets (bytes : Bytes)
deriving DecidableEq, Repr, Inhabited

structure RR where
  owner : Name
  rtype : Nat
  rclass : Nat
  ttl : Nat
  rdata : RData
deriving DecidableEq, Repr, Inhabited

structure Message where
  header : Header
  question : List Question
  answer : List RR
  authority : List RR
  additional : List RR
deriving DecidableEq, Repr, Inhabited

/-- The types of RFC 1035 whose RDATA names may be compressed (RFC 3597 §4), with their layout: octets
before the names, the number of names, and octets after. NS, MD, MF, CNAME, MB, MG, MR, and PTR hold one
name; SOA holds two names and 20 octets; MINFO holds two names; MX holds a preference and one name. -/
def compressible : Nat → Option (Nat × Nat × Nat)
  | 2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 => some (0, 1, 0)
  | 6 => some (0, 2, 20)
  | 14 => some (0, 2, 0)
  | 15 => some (2, 1, 0)
  | _ => none

/-! ## Encoding

The encoder keeps a table of the names it has written with their offsets. A name, or the rest of a name
after some labels, that is already in the table becomes a pointer to it. Offsets above 16383 cannot be
pointed to (RFC 1035 §4.1.4), so they are never entered. With `comp` false nothing is compressed. -/

abbrev Table := List (Name × Nat)

/-- The octets of one name written at offset `base`, and the table after it. A name enters the table after
its rest is written, at the offset of its first label. -/
def encName (comp : Bool) (base : Nat) (tbl : Table) : Name → Bytes × Table
  | [] => ([0], tbl)
  | l :: r =>
    match (if comp then tbl.lookup (l :: r) else none) with
    | some o => ([192 + o / 256, o % 256], tbl)
    | none =>
      let rest := encName comp (base + 1 + l.length) tbl r
      ((l.length :: l) ++ rest.1, if comp && decide (base < 16384) then (l :: r, base) :: rest.2 else rest.2)

def encList {α : Type} (f : Nat → Table → α → Bytes × Table) (base : Nat) (tbl : Table) :
    List α → Bytes × Table
  | [] => ([], tbl)
  | x :: xs =>
    let r := f base tbl x
    let rs := encList f (base + r.1.length) r.2 xs
    (r.1 ++ rs.1, rs.2)

/-- RDATA at offset `base`. Names inside it are compressed only for the RFC 1035 types. -/
def encRData (comp : Bool) (base : Nat) (tbl : Table) (t : Nat) : RData → Bytes × Table
  | .names pre ns post =>
    let r := encList (encName (comp && (compressible t).isSome)) (base + pre.length) tbl ns
    (pre ++ r.1 ++ post, r.2)
  | .octets bs => (bs, tbl)

def encQuestion (comp : Bool) (base : Nat) (tbl : Table) (q : Question) : Bytes × Table :=
  let o := encName comp base tbl q.name
  (o.1 ++ be16 q.qtype ++ be16 q.qclass, o.2)

def encRR (comp : Bool) (base : Nat) (tbl : Table) (rr : RR) : Bytes × Table :=
  let o := encName comp base tbl rr.owner
  let d := encRData comp (base + o.1.length + 10) o.2 rr.rtype rr.rdata
  (o.1 ++ (be16 rr.rtype ++ be16 rr.rclass ++ be32 rr.ttl ++ be16 d.1.length) ++ d.1, d.2)

def encHeader (m : Message) : Bytes :=
  be16 m.header.id ++ be16 m.header.flags ++ be16 m.question.length ++ be16 m.answer.length ++
    be16 m.authority.length ++ be16 m.additional.length

def encode (comp : Bool) (m : Message) : Bytes :=
  let q := encList (encQuestion comp) 12 [] m.question
  let a := encList (encRR comp) (12 + q.1.length) q.2 m.answer
  let n := encList (encRR comp) (12 + q.1.length + a.1.length) a.2 m.authority
  let d := encList (encRR comp) (12 + q.1.length + a.1.length + n.1.length) n.2 m.additional
  encHeader m ++ q.1 ++ a.1 ++ n.1 ++ d.1

/-! ## Decoding -/

inductive Err where
  | exhausted
  | bounds
  | forwardPointer
  | labelType
  | badName
  | rdataLength
  | short
deriving DecidableEq, Repr

/-- Reads a name at `pos`. Every octet read lies before `lim`. A pointer must point before itself, and the
name it points to is read with the pointer's own position as the new limit, so each jump lands strictly
earlier than every octet read since the last one. Returns the name and the position after it in the
original stream. `fuel` bounds the steps; `decode_terminates` shows the fuel `decode` gives always
suffices. -/
def readName : Nat → Bytes → Nat → Nat → Except Err (Name × Nat)
  | 0, _, _, _ => .error .exhausted
  | f + 1, msg, lim, pos =>
    if lim ≤ pos then .error .bounds else
    match msg[pos]? with
    | none => .error .bounds
    | some b =>
      if b = 0 then .ok ([], pos + 1)
      else if b < 64 then
        if pos + 1 + b ≤ lim then
          match readName f msg lim (pos + 1 + b) with
          | .ok (r, e) => .ok (slice msg (pos + 1) b :: r, e)
          | .error err => .error err
        else .error .bounds
      else if 192 ≤ b then
        if pos + 1 < lim then
          match msg[pos + 1]? with
          | none => .error .bounds
          | some c =>
            if (b - 192) * 256 + c < pos then
              match readName f msg pos ((b - 192) * 256 + c) with
              | .ok (r, _) => .ok (r, pos + 2)
              | .error err => .error err
            else .error .forwardPointer
        else .error .bounds
      else .error .labelType

/-- Enough steps for any name in `msg`: see `readName_fuel`. -/
def fuel (msg : Bytes) : Nat := msg.length * msg.length + msg.length + 256

/-- A name, checked against the label and length limits (RFC 1035 §2.3.4). -/
def name (msg : Bytes) (lim pos : Nat) : Except Err (Name × Nat) :=
  match readName (fuel msg) msg lim pos with
  | .ok (n, e) =>
    match Name.ofLabels? n with
    | some n => .ok (n, e)
    | none => .error .badName
  | .error err => .error err

def readList {α : Type} (f : Nat → Except Err (α × Nat)) : Nat → Nat → Except Err (List α × Nat)
  | 0, pos => .ok ([], pos)
  | k + 1, pos =>
    match f pos with
    | .ok (x, e) =>
      match readList f k e with
      | .ok (xs, e') => .ok (x :: xs, e')
      | .error err => .error err
    | .error err => .error err

/-- RDATA of type `t`, `len` octets from `start`. Names inside it stay inside it. -/
def readRData (msg : Bytes) (t start len : Nat) : Except Err RData :=
  if msg.length < start + len then .error .bounds else
  match compressible t with
  | some (p, k, q) =>
    if start + len < start + p then .error .rdataLength else
    match readList (name msg (start + len)) k (start + p) with
    | .ok (ns, e) =>
      if e + q = start + len then .ok (.names (slice msg start p) ns (slice msg e q))
      else .error .rdataLength
    | .error err => .error err
  | none => .ok (.octets (slice msg start len))

def readQuestion (msg : Bytes) (pos : Nat) : Except Err (Question × Nat) :=
  match name msg msg.length pos with
  | .ok (n, e) =>
    match rd16 msg e, rd16 msg (e + 2) with
    | some t, some c => .ok (⟨n, t, c⟩, e + 4)
    | _, _ => .error .short
  | .error err => .error err

def readRR (msg : Bytes) (pos : Nat) : Except Err (RR × Nat) :=
  match name msg msg.length pos with
  | .ok (n, e) =>
    match rd16 msg e, rd16 msg (e + 2), rd32 msg (e + 4), rd16 msg (e + 8) with
    | some t, some c, some ttl, some len =>
      match readRData msg t (e + 10) len with
      | .ok rd => .ok (⟨n, t, c, ttl, rd⟩, e + 10 + len)
      | .error err => .error err
    | _, _, _, _ => .error .short
  | .error err => .error err

/-- Decodes a whole message. Octets after the last record are ignored. -/
def decode (msg : Bytes) : Except Err Message :=
  match rd16 msg 0, rd16 msg 2, rd16 msg 4, rd16 msg 6, rd16 msg 8, rd16 msg 10 with
  | some id, some fl, some qd, some an, some ns, some ar =>
    match readList (readQuestion msg) qd 12 with
    | .ok (q, p1) =>
      match readList (readRR msg) an p1 with
      | .ok (a, p2) =>
        match readList (readRR msg) ns p2 with
        | .ok (n, p3) =>
          match readList (readRR msg) ar p3 with
          | .ok (d, _) => .ok ⟨⟨id, fl⟩, q, a, n, d⟩
          | .error err => .error err
        | .error err => .error err
      | .error err => .error err
    | .error err => .error err
  | _, _, _, _, _, _ => .error .short

/-! ## Well-formed messages -/

def RData.WF (t : Nat) : RData → Prop
  | .names pre ns post =>
    compressible t = some (pre.length, ns.length, post.length) ∧ (∀ n ∈ ns, Name.valid n = true) ∧
      pre.length + (ns.map wireLen).sum + post.length < 65536
  | .octets bs => compressible t = none ∧ bs.length < 65536

def RR.WF (rr : RR) : Prop :=
  Name.valid rr.owner = true ∧ rr.rtype < 65536 ∧ rr.rclass < 65536 ∧ rr.ttl < 4294967296 ∧
    RData.WF rr.rtype rr.rdata

def Question.WF (q : Question) : Prop := Name.valid q.name = true ∧ q.qtype < 65536 ∧ q.qclass < 65536

def Message.WF (m : Message) : Prop :=
  m.header.id < 65536 ∧ m.header.flags < 65536 ∧ m.question.length < 65536 ∧ m.answer.length < 65536 ∧
    m.authority.length < 65536 ∧ m.additional.length < 65536 ∧ (∀ q ∈ m.question, q.WF) ∧
    (∀ r ∈ m.answer, r.WF) ∧ (∀ r ∈ m.authority, r.WF) ∧ (∀ r ∈ m.additional, r.WF)

/-! ## Positions in a message

`bs <+: msg.drop p` says `msg` holds `bs` at position `p`. -/

theorem at_cons {msg : Bytes} {p b : Nat} {bs : Bytes} (h : (b :: bs) <+: msg.drop p) :
    msg[p]? = some b ∧ bs <+: msg.drop (p + 1) := by
  obtain ⟨t, ht⟩ := h
  constructor
  · have : (msg.drop p)[0]? = some b := by rw [← ht]; rfl
    simpa [List.getElem?_drop] using this
  · refine ⟨t, ?_⟩
    rw [← List.drop_drop, ← ht]; rfl

theorem at_append {msg : Bytes} {p : Nat} {a b : Bytes} :
    (a ++ b) <+: msg.drop p ↔ a <+: msg.drop p ∧ b <+: msg.drop (p + a.length) := by
  constructor
  · rintro ⟨t, ht⟩
    refine ⟨⟨b ++ t, by simp [← ht]⟩, ⟨t, ?_⟩⟩
    rw [← List.drop_drop, ← ht]; simp
  · rintro ⟨⟨t1, h1⟩, ⟨t2, h2⟩⟩
    have : t1 = b ++ t2 := by
      rw [h2, ← List.drop_drop, ← h1]; simp
    exact ⟨t2, by rw [← h1, this, List.append_assoc]⟩

theorem at_slice {msg : Bytes} {p : Nat} {bs : Bytes} (h : bs <+: msg.drop p) :
    slice msg p bs.length = bs := by
  obtain ⟨t, ht⟩ := h
  simp [slice, ← ht]

theorem at_be16 {msg : Bytes} {p x : Nat} (hx : x < 65536) (h : be16 x <+: msg.drop p) :
    rd16 msg p = some x := by
  obtain ⟨h0, h1⟩ := at_cons h
  obtain ⟨h1, _⟩ := at_cons h1
  simp only [rd16, h0, h1, Option.some.injEq]
  omega

theorem at_be32 {msg : Bytes} {p x : Nat} (hx : x < 4294967296) (h : be32 x <+: msg.drop p) :
    rd32 msg p = some x := by
  obtain ⟨h0, h⟩ := at_cons h
  obtain ⟨h1, h⟩ := at_cons h
  obtain ⟨h2, h⟩ := at_cons h
  obtain ⟨h3, _⟩ := at_cons h
  simp only [rd32, rd16, h0, h1, show p + 2 = p + 1 + 1 by omega, h2,
    h3, Option.some.injEq]
  omega

theorem at_length {msg : Bytes} {p : Nat} {b : Nat} {bs : Bytes} (h : (b :: bs) <+: msg.drop p) :
    p + (b :: bs).length ≤ msg.length := by
  have := h.length_le
  simp only [List.length_drop, List.length_cons] at this ⊢
  have h0 := (at_cons h).1
  have : p < msg.length := by
    rcases Nat.lt_or_ge p msg.length with h' | h'
    · exact h'
    · simp [List.getElem?_eq_none h'] at h0
  omega

/-! ## Facts about the encoder -/

theorem mem_of_lookup {tbl : Table} {k : Name} {o : Nat} (h : tbl.lookup k = some o) : (k, o) ∈ tbl := by
  induction tbl with
  | nil => simp [List.lookup] at h
  | cons e es ih =>
    obtain ⟨k', o'⟩ := e
    simp only [List.lookup] at h
    split at h
    · rename_i hk; simp at hk h; subst hk; subst h; simp
    · exact List.mem_cons_of_mem _ (ih h)

theorem encName_length (comp : Bool) (base : Nat) (tbl : Table) (n : Name) :
    (encName comp base tbl n).1.length ≤ wireLen n := by
  induction n generalizing base tbl with
  | nil => simp [encName]
  | cons l r ih =>
    simp only [encName]
    split
    · simp; have : 1 ≤ wireLen r := by unfold wireLen; omega
      omega
    · simp only [List.length_append, List.length_cons, wireLen_cons]
      have := ih (base + 1 + l.length) tbl; omega

theorem encList_names_length (c : Bool) (base : Nat) (tbl : Table) (ns : List Name) :
    (encList (encName c) base tbl ns).1.length ≤ (ns.map wireLen).sum := by
  induction ns generalizing base tbl with
  | nil => simp [encList]
  | cons n ns ih =>
    simp only [encList, List.length_append, List.map_cons, List.sum_cons]
    have := encName_length c base tbl n
    have := ih (base + (encName c base tbl n).1.length) (encName c base tbl n).2
    omega

/-- Without compression the table plays no part in a name's octets. -/
theorem encName_nocomp (base base' : Nat) (tbl tbl' : Table) (n : Name) :
    (encName false base tbl n).1 = (encName false base' tbl' n).1 ∧ (encName false base tbl n).2 = tbl := by
  induction n generalizing base base' tbl tbl' with
  | nil => simp [encName]
  | cons l r ih =>
    simp only [encName, Bool.false_eq_true, ↓reduceIte, Bool.false_and]
    exact ⟨by rw [(ih _ (base' + 1 + l.length) tbl tbl').1], (ih _ base tbl tbl).2⟩

theorem encList_nocomp (base base' : Nat) (tbl tbl' : Table) (ns : List Name) :
    (encList (encName false) base tbl ns).1 = (encList (encName false) base' tbl' ns).1 ∧
      (encList (encName false) base tbl ns).2 = tbl := by
  induction ns generalizing base base' tbl tbl' with
  | nil => simp [encList]
  | cons n ns ih =>
    simp only [encList]
    have h1 := encName_nocomp base base' tbl tbl' n
    rw [h1.1, h1.2]
    refine ⟨?_, (ih _ 0 tbl tbl).2⟩
    rw [(ih (base + (encName false base' tbl' n).1.length) (base' + (encName false base' tbl' n).1.length)
      tbl (encName false base' tbl' n).2).1, (encName_nocomp base' base' tbl' tbl' n).2]

/-! ## Decoding what the encoder wrote

`TblOK msg tbl base` says every table entry lies before `base`, can be pointed to, and reads back as its
name from `msg` under any limit at or after `base`. -/

def TblOK (msg : Bytes) (tbl : Table) (base : Nat) : Prop :=
  ∀ s o, (s, o) ∈ tbl → o < base ∧ o < 16384 ∧
    ∀ lim f, base ≤ lim → lim ≤ msg.length → 2 * s.length ≤ f → ∃ e, readName f msg lim o = .ok (s, e)

theorem TblOK.mono {msg : Bytes} {tbl : Table} {b b' : Nat} (h : TblOK msg tbl b) (hb : b ≤ b') :
    TblOK msg tbl b' := by
  intro s o hm
  obtain ⟨h1, h2, h3⟩ := h s o hm
  exact ⟨by omega, h2, fun lim f hl hl' hf => h3 lim f (by omega) hl' hf⟩

theorem TblOK.nil (msg : Bytes) (b : Nat) : TblOK msg [] b := by intro s o h; simp at h

/-- The main lemma: a name written at `base` reads back from `base`, ending where its octets end, and the
table stays good. -/
theorem encName_ok (comp : Bool) (msg : Bytes) (n : Name) : ∀ (base : Nat) (tbl : Table),
    (∀ l ∈ n, 0 < l.length ∧ l.length < 64) → TblOK msg tbl base →
    (encName comp base tbl n).1 <+: msg.drop base →
    TblOK msg (encName comp base tbl n).2 (base + (encName comp base tbl n).1.length) ∧
    ∀ lim f, base + (encName comp base tbl n).1.length ≤ lim → lim ≤ msg.length → 2 * n.length + 1 ≤ f →
      readName f msg lim base = .ok (n, base + (encName comp base tbl n).1.length) := by
  induction n with
  | nil =>
    intro base tbl _ hT hP
    simp only [encName] at hP ⊢
    refine ⟨hT.mono (by omega), ?_⟩
    intro lim f h1 _ h3
    obtain ⟨f', rfl⟩ : ∃ f', f = f' + 1 := ⟨f - 1, by omega⟩
    have hb := (at_cons hP).1
    simp [readName, hb, show ¬ lim ≤ base by simp at h1; omega]
  | cons l r ih =>
    intro base tbl hl hT hP
    have hl0 := hl l (List.mem_cons_self ..)
    have hr : ∀ l' ∈ r, 0 < l'.length ∧ l'.length < 64 := fun l' h => hl l' (List.mem_cons_of_mem _ h)
    cases ho : (if comp then tbl.lookup (l :: r) else none) with
    | some o =>
      -- a pointer to an entry already written
      simp only [encName, ho] at hP ⊢
      have hmem : (l :: r, o) ∈ tbl := by
        cases comp
        · simp at ho
        · exact mem_of_lookup (by simpa using ho)
      obtain ⟨hob, ho16, hdec⟩ := hT _ _ hmem
      simp only [List.length_cons, List.length_nil] at hP ⊢
      refine ⟨hT.mono (by omega), ?_⟩
      intro lim f h1 h2 h3
      obtain ⟨f', rfl⟩ : ∃ f', f = f' + 1 := ⟨f - 1, by omega⟩
      obtain ⟨hb0, hP1⟩ := at_cons hP
      have hb1 := (at_cons hP1).1
      have hlen : base ≤ msg.length := by have := at_length hP; simp at this; omega
      obtain ⟨e, he⟩ := hdec base f' (Nat.le_refl _) hlen (by simp at h3; omega)
      have ht : (192 + o / 256 - 192) * 256 + o % 256 = o := by omega
      simp only [readName, show ¬ lim ≤ base by omega, ↓reduceIte, hb0, hb1,
        show ¬ (192 + o / 256 = 0) by omega, show ¬ (192 + o / 256 < 64) by omega,
        show 192 ≤ 192 + o / 256 by omega, show base + 1 < lim by omega, ht, hob, he]
    | none =>
      -- labels, then the rest of the name
      simp only [encName, ho] at hP ⊢
      obtain ⟨hPl, hPr⟩ := at_append.mp hP
      have hPr' : (encName comp (base + 1 + l.length) tbl r).1 <+: msg.drop (base + 1 + l.length) := by
        simpa [Nat.add_assoc, Nat.add_comm 1] using hPr
      obtain ⟨hT', hdec⟩ := ih (base + 1 + l.length) tbl hr (hT.mono (by omega)) hPr'
      have hlab : slice msg (base + 1) l.length = l := by
        obtain ⟨_, h1⟩ := at_cons hPl
        exact at_slice (by simpa using h1)
      have hb0 := (at_cons hPl).1
      have hend : base + ((l.length :: l) ++ (encName comp (base + 1 + l.length) tbl r).1).length =
          base + 1 + l.length + (encName comp (base + 1 + l.length) tbl r).1.length := by
        simp; omega
      -- the name reads back from `base` with one step fewer than a pointer to it would need
      have key : ∀ lim f, base + 1 + l.length + (encName comp (base + 1 + l.length) tbl r).1.length ≤ lim →
          lim ≤ msg.length → 2 * (l :: r).length ≤ f →
          readName f msg lim base =
            .ok (l :: r, base + 1 + l.length + (encName comp (base + 1 + l.length) tbl r).1.length) := by
        intro lim f h1 h2 h3
        obtain ⟨f', rfl⟩ : ∃ f', f = f' + 1 := ⟨f - 1, by simp at h3; omega⟩
        have := hdec lim f' h1 h2 (by simp at h3; omega)
        simp only [readName, show ¬ lim ≤ base by omega, ↓reduceIte, hb0,
          show ¬ (l.length = 0) by omega, show l.length < 64 by omega,
          show base + 1 + l.length ≤ lim by omega, this, hlab]
      rw [hend]
      refine ⟨?_, fun lim f h1 h2 h3 => key lim f h1 h2 (by omega)⟩
      split
      · intro s o hm
        simp only [List.mem_cons, Prod.mk.injEq] at hm
        rcases hm with ⟨rfl, rfl⟩ | hm
        · refine ⟨by omega, by simp_all, fun lim f h1 h2 h3 => ⟨_, key lim f h1 h2 h3⟩⟩
        · exact hT' s o hm
      · exact hT'

/-- A list written by `enc` reads back with `dec`, provided each element does. -/
theorem list_ok {α : Type} (msg : Bytes) (enc : Nat → Table → α → Bytes × Table)
    (dec : Nat → Except Err (α × Nat)) (P : α → Prop) (bound : Nat)
    (h : ∀ x base tbl, P x → TblOK msg tbl base → (enc base tbl x).1 <+: msg.drop base →
      base + (enc base tbl x).1.length ≤ bound →
      TblOK msg (enc base tbl x).2 (base + (enc base tbl x).1.length) ∧
        dec base = .ok (x, base + (enc base tbl x).1.length)) :
    ∀ (xs : List α) base tbl, (∀ x ∈ xs, P x) → TblOK msg tbl base →
      (encList enc base tbl xs).1 <+: msg.drop base → base + (encList enc base tbl xs).1.length ≤ bound →
      TblOK msg (encList enc base tbl xs).2 (base + (encList enc base tbl xs).1.length) ∧
        readList dec xs.length base = .ok (xs, base + (encList enc base tbl xs).1.length) := by
  intro xs
  induction xs with
  | nil => intro base tbl _ hT _ _; simp [encList, readList]; simpa using hT
  | cons x xs ih =>
    intro base tbl hP hT hAt hB
    simp only [encList, List.length_append] at hAt hB ⊢
    obtain ⟨hx, hxs⟩ := at_append.mp hAt
    obtain ⟨hT1, hd⟩ := h x base tbl (hP x (List.mem_cons_self ..)) hT hx (by omega)
    obtain ⟨hT2, hd2⟩ := ih _ _ (fun y hy => hP y (List.mem_cons_of_mem _ hy)) hT1 hxs (by omega)
    refine ⟨by simpa [Nat.add_assoc] using hT2, ?_⟩
    simp only [List.length_cons, readList, hd, hd2, Nat.add_assoc]

theorem valid_labels {n : Name} (h : Name.valid n = true) : ∀ l ∈ n, 0 < l.length ∧ l.length < 64 := by
  intro l hl
  simp only [Name.valid, Bool.and_eq_true, List.all_eq_true] at h
  have := h.1 l hl
  simp only [Name.labelOk, Bool.and_eq_true, decide_eq_true_eq] at this
  omega

theorem valid_length {n : Name} (h : Name.valid n = true) : 2 * n.length + 1 ≤ 255 := by
  have hl := valid_labels h
  simp only [Name.valid, Bool.and_eq_true, decide_eq_true_eq] at h
  have : 2 * n.length + 1 ≤ wireLen n := by
    clear h; induction n with
    | nil => simp
    | cons l r ih =>
      have := hl l (List.mem_cons_self ..)
      have := ih (fun l' h' => hl l' (List.mem_cons_of_mem _ h'))
      simp; omega
  omega

/-- A valid name written at `base` reads back through `name`. -/
theorem name_ok (comp : Bool) (msg : Bytes) (n : Name) (base lim : Nat) (tbl : Table) (hv : Name.valid n = true)
    (hT : TblOK msg tbl base) (hP : (encName comp base tbl n).1 <+: msg.drop base)
    (h1 : base + (encName comp base tbl n).1.length ≤ lim) (h2 : lim ≤ msg.length) :
    TblOK msg (encName comp base tbl n).2 (base + (encName comp base tbl n).1.length) ∧
      name msg lim base = .ok (n, base + (encName comp base tbl n).1.length) := by
  obtain ⟨hT', hd⟩ := encName_ok comp msg n base tbl (valid_labels hv) hT hP
  refine ⟨hT', ?_⟩
  have := valid_length hv
  simp only [name, hd lim (fuel msg) h1 h2 (by unfold fuel; omega), Name.ofLabels?_complete n hv]

theorem rdata_ok (comp : Bool) (msg : Bytes) (t : Nat) (rd : RData) (base : Nat) (tbl : Table)
    (hw : RData.WF t rd) (hT : TblOK msg tbl base) (hP : (encRData comp base tbl t rd).1 <+: msg.drop base)
    (hB : base + (encRData comp base tbl t rd).1.length ≤ msg.length) :
    TblOK msg (encRData comp base tbl t rd).2 (base + (encRData comp base tbl t rd).1.length) ∧
      readRData msg t base (encRData comp base tbl t rd).1.length = .ok rd := by
  cases rd with
  | octets bs =>
    obtain ⟨hc, _⟩ := hw
    simp only [encRData] at hP hB ⊢
    refine ⟨hT.mono (by omega), ?_⟩
    simp [readRData, hc, at_slice hP, show ¬ msg.length < base + bs.length by omega]
  | names pre ns post =>
    obtain ⟨hc, hv, _⟩ := hw
    simp only [encRData, List.length_append] at hP hB ⊢
    generalize hc' : (comp && (compressible t).isSome) = c at *
    generalize hE : encList (encName c) (base + pre.length) tbl ns = E at *
    obtain ⟨hP', hPpost⟩ := at_append.mp hP
    obtain ⟨hPpre, hPns⟩ := at_append.mp hP'
    simp only [List.length_append] at hPpost
    have hl := list_ok msg (encName c) (name msg (base + (pre.length + E.1.length + post.length)))
      (fun n => Name.valid n = true) (base + (pre.length + E.1.length + post.length))
      (fun x b tb hx hTb hAt hBd => name_ok c msg x b _ tb hx hTb hAt hBd (by omega))
      ns (base + pre.length) tbl hv (hT.mono (by omega)) (by rw [hE]; exact hPns) (by rw [hE]; omega)
    rw [hE] at hl
    obtain ⟨hT', hd⟩ := hl
    refine ⟨hT'.mono (by omega), ?_⟩
    have hpost : slice msg (base + pre.length + E.1.length) post.length = post := by
      rw [show base + pre.length + E.1.length = base + (pre.length + E.1.length) by omega]
      exact at_slice hPpost
    have e1 : ¬ msg.length < base + (pre.length + E.1.length + post.length) := by omega
    have e2 : ¬ base + (pre.length + E.1.length + post.length) < base + pre.length := by omega
    have e3 : base + pre.length + E.1.length + post.length = base + (pre.length + E.1.length + post.length) := by
      omega
    simp only [readRData, e1, ↓reduceIte, hc, e2, hd, e3, at_slice hPpre, hpost]

theorem rdata_length (comp : Bool) (t : Nat) (rd : RData) (base : Nat) (tbl : Table) (hw : RData.WF t rd) :
    (encRData comp base tbl t rd).1.length < 65536 := by
  cases rd with
  | octets bs => exact hw.2
  | names pre ns post =>
    simp only [encRData, List.length_append]
    have := encList_names_length (comp && (compressible t).isSome) (base + pre.length) tbl ns
    have := hw.2.2; omega

theorem question_ok (comp : Bool) (msg : Bytes) (q : Question) (base : Nat) (tbl : Table) (hw : q.WF)
    (hT : TblOK msg tbl base) (hP : (encQuestion comp base tbl q).1 <+: msg.drop base)
    (hB : base + (encQuestion comp base tbl q).1.length ≤ msg.length) :
    TblOK msg (encQuestion comp base tbl q).2 (base + (encQuestion comp base tbl q).1.length) ∧
      readQuestion msg base = .ok (q, base + (encQuestion comp base tbl q).1.length) := by
  obtain ⟨hv, ht, hc⟩ := hw
  simp only [encQuestion, List.length_append, be16_length] at hP hB ⊢
  generalize hO : encName comp base tbl q.name = O at *
  obtain ⟨hP', hPc⟩ := at_append.mp hP
  obtain ⟨hPn, hPt⟩ := at_append.mp hP'
  simp only [List.length_append, be16_length] at hPc
  obtain ⟨hT', hn⟩ := name_ok comp msg q.name base msg.length tbl hv hT (by rw [hO]; exact hPn)
    (by rw [hO]; omega) (Nat.le_refl _)
  rw [hO] at hT' hn
  refine ⟨hT'.mono (by omega), ?_⟩
  have h2 : rd16 msg (base + O.1.length + 2) = some q.qclass := at_be16 hc (by rwa [Nat.add_assoc])
  simp only [readQuestion, hn, at_be16 ht hPt, h2, Except.ok.injEq, Prod.mk.injEq]
  exact ⟨trivial, by omega⟩

theorem rr_ok (comp : Bool) (msg : Bytes) (rr : RR) (base : Nat) (tbl : Table) (hw : rr.WF)
    (hT : TblOK msg tbl base) (hP : (encRR comp base tbl rr).1 <+: msg.drop base)
    (hB : base + (encRR comp base tbl rr).1.length ≤ msg.length) :
    TblOK msg (encRR comp base tbl rr).2 (base + (encRR comp base tbl rr).1.length) ∧
      readRR msg base = .ok (rr, base + (encRR comp base tbl rr).1.length) := by
  obtain ⟨hv, ht, hc, httl, hrd⟩ := hw
  simp only [encRR, List.length_append, be16_length, be32_length] at hP hB ⊢
  generalize hO : encName comp base tbl rr.owner = O at *
  generalize hD : encRData comp (base + O.1.length + 10) O.2 rr.rtype rr.rdata = D at *
  have hDl : D.1.length < 65536 := by rw [← hD]; exact rdata_length _ _ _ _ _ hrd
  obtain ⟨hP', hPd⟩ := at_append.mp hP
  obtain ⟨hPo, hPf⟩ := at_append.mp hP'
  obtain ⟨hPf', hf4⟩ := at_append.mp hPf
  obtain ⟨hPf'', hf3⟩ := at_append.mp hPf'
  obtain ⟨hf1, hf2⟩ := at_append.mp hPf''
  simp only [List.length_append, be16_length, be32_length] at hPd hf2 hf3 hf4
  obtain ⟨hT1, hn⟩ := name_ok comp msg rr.owner base msg.length tbl hv hT (by rw [hO]; exact hPo)
    (by rw [hO]; omega) (Nat.le_refl _)
  rw [hO] at hT1 hn
  have r1 := at_be16 ht hf1
  have r2 : rd16 msg (base + O.1.length + 2) = some rr.rclass := at_be16 hc (by rwa [Nat.add_assoc])
  have r3 : rd32 msg (base + O.1.length + 4) = some rr.ttl := at_be32 httl (by rwa [Nat.add_assoc])
  have r4 : rd16 msg (base + O.1.length + 8) = some D.1.length := at_be16 hDl (by rwa [Nat.add_assoc])
  obtain ⟨hT2, hr⟩ := rdata_ok comp msg rr.rtype rr.rdata (base + O.1.length + 10) O.2 hrd
    (hT1.mono (by omega)) (by rw [hD]; rwa [show base + O.1.length + 10 = base + (O.1.length + 10) by omega])
    (by rw [hD]; omega)
  rw [hD] at hT2 hr
  refine ⟨hT2.mono (by omega), ?_⟩
  simp only [readRR, hn, r1, r2, r3, r4, hr, Except.ok.injEq, Prod.mk.injEq]
  exact ⟨trivial, by omega⟩

/-- Decoding inverts encoding for every well-formed message, with or without compression. -/
theorem decode_encode (comp : Bool) (m : Message) (hw : m.WF) : decode (encode comp m) = .ok m := by
  obtain ⟨hid, hfl, hqd, han, hns, har, hq, ha, hn, hd⟩ := hw
  generalize hQ : encList (encQuestion comp) 12 [] m.question = Q
  generalize hA : encList (encRR comp) (12 + Q.1.length) Q.2 m.answer = A
  generalize hN : encList (encRR comp) (12 + Q.1.length + A.1.length) A.2 m.authority = N
  generalize hD : encList (encRR comp) (12 + Q.1.length + A.1.length + N.1.length) N.2 m.additional = D
  have henc : encode comp m = encHeader m ++ Q.1 ++ A.1 ++ N.1 ++ D.1 := by
    simp only [encode, hQ, hA, hN, hD]
  rw [henc]
  generalize hM : encHeader m ++ Q.1 ++ A.1 ++ N.1 ++ D.1 = msg
  have hHl : (encHeader m).length = 12 := by simp [encHeader, be16]
  have hlen : msg.length = 12 + Q.1.length + A.1.length + N.1.length + D.1.length := by
    rw [← hM]; simp [hHl]; omega
  have at0 : (encHeader m ++ Q.1 ++ A.1 ++ N.1 ++ D.1) <+: msg.drop 0 := by rw [hM]; simp
  obtain ⟨at1, atD⟩ := at_append.mp at0
  obtain ⟨at2, atN⟩ := at_append.mp at1
  obtain ⟨at3, atA⟩ := at_append.mp at2
  obtain ⟨atH, atQ⟩ := at_append.mp at3
  simp only [List.length_append, hHl, Nat.zero_add] at atQ atA atN atD
  -- the header
  have hH := atH
  simp only [encHeader] at hH
  obtain ⟨h01, h2⟩ := at_append.mp hH
  obtain ⟨h01, h3⟩ := at_append.mp h01
  obtain ⟨h01, h4⟩ := at_append.mp h01
  obtain ⟨h01, h5⟩ := at_append.mp h01
  obtain ⟨h0, h1⟩ := at_append.mp h01
  simp only [be16_length, List.length_append, Nat.zero_add] at h1 h2 h3 h4 h5
  -- the sections
  obtain ⟨tQ, rQ⟩ := list_ok msg (encQuestion comp) (readQuestion msg) Question.WF msg.length
    (fun x b tb hx hT hAt hB => question_ok comp msg x b tb hx hT hAt hB) m.question 12 []
    hq (TblOK.nil _ _) (by rw [hQ]; exact atQ) (by rw [hQ]; omega)
  rw [hQ] at tQ rQ
  obtain ⟨tA, rA⟩ := list_ok msg (encRR comp) (readRR msg) RR.WF msg.length
    (fun x b tb hx hT hAt hB => rr_ok comp msg x b tb hx hT hAt hB) m.answer (12 + Q.1.length) Q.2
    ha tQ (by rw [hA]; exact atA) (by rw [hA]; omega)
  rw [hA] at tA rA
  obtain ⟨tN, rN⟩ := list_ok msg (encRR comp) (readRR msg) RR.WF msg.length
    (fun x b tb hx hT hAt hB => rr_ok comp msg x b tb hx hT hAt hB) m.authority
    (12 + Q.1.length + A.1.length) A.2 hn tA (by rw [hN]; exact atN) (by rw [hN]; omega)
  rw [hN] at tN rN
  obtain ⟨_, rD⟩ := list_ok msg (encRR comp) (readRR msg) RR.WF msg.length
    (fun x b tb hx hT hAt hB => rr_ok comp msg x b tb hx hT hAt hB) m.additional
    (12 + Q.1.length + A.1.length + N.1.length) N.2 hd tN (by rw [hD]; exact atD) (by rw [hD]; omega)
  rw [hD] at rD
  simp only [decode, at_be16 hid h0, at_be16 hfl (by simpa using h1), at_be16 hqd (by simpa using h5),
    at_be16 han (by simpa using h4), at_be16 hns (by simpa using h3), at_be16 har (by simpa using h2),
    rQ, rA, rN, rD]

/-! ## Termination of the decoder -/

theorem readName_fuel (msg : Bytes) : ∀ f lim pos, lim ≤ msg.length → lim * lim + (lim - pos) + 1 ≤ f →
    readName f msg lim pos ≠ .error .exhausted := by
  intro f
  induction f with
  | zero => intro lim pos _ h; omega
  | succ f ih =>
    intro lim pos hl hf
    unfold readName
    by_cases h1 : lim ≤ pos
    · simp [h1]
    simp only [h1, ↓reduceIte]
    cases hb : msg[pos]? with
    | none => simp
    | some b =>
      simp only
      by_cases h0 : b = 0
      · simp [h0]
      by_cases h64 : b < 64
      · simp only [h0, h64, ↓reduceIte]
        by_cases hlim : pos + 1 + b ≤ lim
        · have := ih lim (pos + 1 + b) hl (by omega)
          simp only [hlim, ↓reduceIte]
          cases hr : readName f msg lim (pos + 1 + b) with
          | ok v => simp
          | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact this hr
        · simp [hlim]
      by_cases h192 : 192 ≤ b
      · simp only [h0, h64, h192, ↓reduceIte]
        by_cases hp : pos + 1 < lim
        · simp only [hp, ↓reduceIte]
          cases hc : msg[pos + 1]? with
          | none => simp
          | some c =>
            simp only
            by_cases ht : (b - 192) * 256 + c < pos
            · simp only [ht, ↓reduceIte]
              have hsq : (pos + 1) * (pos + 1) ≤ lim * lim := Nat.mul_le_mul (by omega) (by omega)
              have hexp : (pos + 1) * (pos + 1) = pos * pos + 2 * pos + 1 := by
                simp only [Nat.add_mul, Nat.mul_add, Nat.mul_one, Nat.one_mul]; omega
              have := ih pos ((b - 192) * 256 + c) (by omega) (by omega)
              cases hr : readName f msg pos ((b - 192) * 256 + c) with
              | ok v => simp
              | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact this hr
            · simp [ht]
        · simp [hp]
      · simp [h0, h64, h192]

theorem name_fuel (msg : Bytes) (lim pos : Nat) (hl : lim ≤ msg.length) :
    name msg lim pos ≠ .error .exhausted := by
  have := readName_fuel msg (fuel msg) lim pos hl (by
    unfold fuel
    have : lim * lim ≤ msg.length * msg.length := Nat.mul_le_mul hl hl
    omega)
  unfold name
  cases hr : readName (fuel msg) msg lim pos with
  | ok v => simp only; split <;> simp
  | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact this hr

theorem readList_fuel {α : Type} (f : Nat → Except Err (α × Nat)) (hf : ∀ p, f p ≠ .error .exhausted) :
    ∀ k p, readList f k p ≠ .error .exhausted := by
  intro k
  induction k with
  | zero => intro p; simp [readList]
  | succ k ih =>
    intro p
    simp only [readList]
    cases hx : f p with
    | ok v =>
      simp only
      cases hr : readList f k v.2 with
      | ok w => simp
      | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact ih _ hr
    | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact hf p hx

theorem readRData_fuel (msg : Bytes) (t start len : Nat) : readRData msg t start len ≠ .error .exhausted := by
  unfold readRData
  by_cases h : msg.length < start + len
  · simp [h]
  simp only [h, ↓reduceIte]
  cases hc : compressible t with
  | none => simp
  | some v =>
    obtain ⟨p, k, q⟩ := v
    simp only
    by_cases h2 : start + len < start + p
    · simp [h2]
    simp only [h2, ↓reduceIte]
    have := readList_fuel _ (fun p => name_fuel msg (start + len) p (by omega)) k (start + p)
    cases hr : readList (name msg (start + len)) k (start + p) with
    | ok w => simp only; split <;> simp
    | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact this hr

theorem readRR_fuel (msg : Bytes) (pos : Nat) : readRR msg pos ≠ .error .exhausted := by
  unfold readRR
  cases hn : name msg msg.length pos with
  | ok v =>
    simp only
    split
    · cases hr : readRData msg _ _ _ with
      | ok w => simp
      | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact readRData_fuel _ _ _ _ hr
    · simp
  | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact name_fuel msg _ pos (Nat.le_refl _) hn

theorem readQuestion_fuel (msg : Bytes) (pos : Nat) : readQuestion msg pos ≠ .error .exhausted := by
  unfold readQuestion
  cases hn : name msg msg.length pos with
  | ok v => simp only; split <;> simp
  | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact name_fuel msg _ pos (Nat.le_refl _) hn

/-- The decoder never runs out of steps: on every input it returns a message or a real error, after at most
quadratically many steps per name. -/
theorem decode_terminates (msg : Bytes) : decode msg ≠ .error .exhausted := by
  have hq := readList_fuel _ (readQuestion_fuel msg)
  have hr := readList_fuel _ (readRR_fuel msg)
  unfold decode
  split
  · rename_i qd an ns ar _ _ _ _ _ _
    cases h1 : readList (readQuestion msg) qd 12 with
    | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact hq _ _ h1
    | ok v1 =>
      simp only
      cases h2 : readList (readRR msg) an v1.2 with
      | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact hr _ _ h2
      | ok v2 =>
        simp only
        cases h3 : readList (readRR msg) ns v2.2 with
        | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact hr _ _ h3
        | ok v3 =>
          simp only
          cases h4 : readList (readRR msg) ar v3.2 with
          | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact hr _ _ h4
          | ok v4 => simp
  · simp

/-- A pointer that does not point strictly before itself is rejected. -/
theorem decode_rejects_forward_pointer (f : Nat) (msg : Bytes) (lim pos b c : Nat) (hpos : pos + 1 < lim)
    (hb : msg[pos]? = some b) (hc : msg[pos + 1]? = some c) (hb192 : 192 ≤ b)
    (hfwd : pos ≤ (b - 192) * 256 + c) :
    readName (f + 1) msg lim pos = .error .forwardPointer := by
  simp only [readName, show ¬ lim ≤ pos by omega, ↓reduceIte, hb, show ¬ b = 0 by omega,
    show ¬ b < 64 by omega, hb192, hpos, hc, show ¬ ((b - 192) * 256 + c < pos) by omega]

/-! ## Compression only where RFC 1035 allows it -/

/-- Names already written change a record's RDATA octets only for the RFC 1035 types, and only those types
add names to the table: every other type's RDATA is written the same whatever came before it. -/
theorem compress_only_rfc1035_types (comp : Bool) (base : Nat) (tbl : Table) (t : Nat) (rd : RData)
    (h : compressible t = none) :
    (encRData comp base tbl t rd).1 = (encRData comp 0 [] t rd).1 ∧ (encRData comp base tbl t rd).2 = tbl := by
  cases rd with
  | octets bs => simp [encRData]
  | names pre ns post =>
    simp only [encRData, h, Option.isSome_none, Bool.and_false]
    exact ⟨by rw [(encList_nocomp (base + pre.length) (0 + pre.length) tbl [] ns).1],
      (encList_nocomp _ 0 tbl [] ns).2⟩

/-- The RDATA of a type outside RFC 1035's name-bearing types is kept octet for octet: decoding it and writing
it again gives the same octets, at any position and after any names. -/
theorem unknown_rdata_verbatim (msg : Bytes) (t start len : Nat) (rd : RData) (comp : Bool) (base : Nat)
    (tbl : Table) (h : compressible t = none) (hd : readRData msg t start len = .ok rd) :
    rd = .octets (slice msg start len) ∧ (encRData comp base tbl t rd).1 = slice msg start len := by
  unfold readRData at hd
  split at hd
  · cases hd
  · rw [h] at hd
    simp only [Except.ok.injEq] at hd
    subst hd
    simp [encRData]

/-! ## The server front: the request check and the reply header -/

/-- The header of a reply to `q`: QR set; ID, OPCODE, RD, and CD copied; RA, Z, and AD zero (RFC 1035
§4.1.1, RFC 6895 §2). -/
def respondHeader (q : Header) (rcode : Nat) (aa tc : Bool) : Header :=
  ⟨q.id, flagsOf true q.opcode aa tc q.rd false false false q.cd rcode⟩

/-- What the query's OPT record says (RFC 6891 §6.1.3). -/
structure EdnsIn where
  payload : Nat
  version : Nat
  dnssecOk : Bool
  nsid : Bool
deriving DecidableEq, Repr

structure Request where
  header : Header
  question : Question
  edns : Option EdnsIn
deriving DecidableEq, Repr

/-- A rejection: the extended RCODE, the reply header, and the version of the reply's OPT if it has one. -/
structure Reject where
  rcode : Nat
  header : Header
  opt : Option Nat
deriving DecidableEq, Repr

inductive Parsed where
  | silent
  | reject (r : Reject)
  | request (r : Request)
deriving DecidableEq, Repr

/-- EDNS options as code, length, and value (RFC 6891 §6.1.2); `none` when the octets do not split. -/
def options : Bytes → Option (List (Nat × Bytes))
  | [] => some []
  | a :: b :: c :: d :: rest =>
    let len := c * 256 + d
    if len ≤ rest.length then
      match options (rest.drop len) with
      | some os => some ((a * 256 + b, rest.take len) :: os)
      | none => none
    else none
  | _ => none
termination_by bs => bs.length
decreasing_by simp; omega

def optRR (r : RR) : Bool := r.rtype == 41

/-- From the record at `pos`, the `i`-th of the message, over `k` more records: whether the record that stops
the message from decoding is an OPT record, one whose octets do not read or one among the first `outside`
records, outside the additional section. -/
def optFault (msg : Bytes) (outside : Nat) : Nat → Nat → Nat → Bool
  | 0, _, _ => false
  | k + 1, i, pos =>
    let opt := match name msg msg.length pos with
      | .ok (_, e) => rd16 msg e == some 41
      | .error _ => false
    match readRR msg pos with
    | .error _ => opt
    | .ok (_, e) => if opt && i < outside then true else optFault msg outside k (i + 1) e

/-- Whether a message that does not decode fails at an OPT record, so its FORMERR carries an OPT (RFC 6891
§7), as `fault_in_opt` decides. -/
def faultInOpt (msg : Bytes) : Bool :=
  match rd16 msg 4, rd16 msg 6, rd16 msg 8, rd16 msg 10 with
  | some qd, some an, some ns, some ar =>
    match readList (readQuestion msg) qd 12 with
    | .ok (_, p) => optFault msg (an + ns) (an + ns + ar) 0 p
    | .error _ => false
  | _, _, _, _ => false

/-- `Request::parse`'s fixed order. `udp` says whether the query came over UDP. -/
def parse (bytes : Bytes) (udp : Bool) : Parsed :=
  match rd16 bytes 0, rd16 bytes 2 with
  | some id, some fl =>
    let h : Header := ⟨id, fl⟩
    if bytes.length < 12 || h.qr then .silent else
    let rej (rc : Nat) (opt : Option Nat) : Parsed := .reject ⟨rc, respondHeader h (rc % 16) false false, opt⟩
    match decode bytes with
    | .error _ => rej 1 (if faultInOpt bytes then some 0 else none)
    | .ok m =>
      -- an OPT record belongs in the additional section alone (RFC 6891 §6.1.1)
      if (m.answer ++ m.authority).any optRR then rej 1 (some 0) else
      match m.additional.filter optRR with
      | _ :: _ :: _ => rej 1 (some 0)
      | os =>
        let opt := os.head?
        let optBad := match opt with
          | some o => o.owner != [] || (match o.rdata with
              | .octets bs => (options bs).isNone
              | _ => true)
          | none => false
        if optBad then rej 1 (some 0) else
        let edns : Option EdnsIn := opt.map fun o =>
          ⟨o.rclass, o.ttl / 65536 % 256, o.ttl / 32768 % 2 == 1,
            match o.rdata with
            | .octets bs => ((options bs).getD []).any (·.1 == 3)
            | _ => false⟩
        -- the reply carries an OPT of version 0 exactly when the query had one (RFC 6891 §7)
        let optOut : Option Nat := edns.map fun _ => 0
        if 0 < ((edns.map (·.version)).getD 0) then rej 16 (some 0) else
        if h.opcode != 0 then rej 4 optOut else
        match m.question with
        | [q] =>
          if q.qtype == 41 then rej 1 optOut
          else if udp && (q.qtype == 251 || q.qtype == 252) then rej 1 optOut
          else if q.qtype == 253 || q.qtype == 254 then rej 4 optOut
          else .request ⟨h, q, edns⟩
        | _ => rej 1 optOut
  | _, _ => .silent

end Dns.Wire
