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

/-- Reads a name at `pos`. `seg` is where the part of the name being read starts: the name's first octet, or
the target of the last pointer followed. Every label octet read lies before `lim`. A pointer points to a
prior occurrence of the rest of the name (RFC 1035 §4.1.4), so it must point strictly before `seg`: never
forward, never at itself, and never into the labels of the part that holds it. The name it points to is
read with `seg` as the new limit, so it ends before the part that pointed to it, and each jump lands
strictly earlier than every octet read since the last one. This is hickory's rule (`read_inner` in
`rr/domain/name.rs`: the target before `name_start`, then `ptr_max_idx`). Returns the name and the position
after it in the original stream. `fuel` bounds the steps; `decode_terminates` shows the fuel `decode` gives
always suffices. -/
def readName : Nat → Bytes → Nat → Nat → Nat → Except Err (Name × Nat)
  | 0, _, _, _, _ => .error .exhausted
  | f + 1, msg, lim, seg, pos =>
    if lim ≤ pos then .error .bounds else
    match msg[pos]? with
    | none => .error .bounds
    | some b =>
      if b = 0 then .ok ([], pos + 1)
      else if b < 64 then
        if pos + 1 + b ≤ lim then
          match readName f msg lim seg (pos + 1 + b) with
          | .ok (r, e) => .ok (slice msg (pos + 1) b :: r, e)
          | .error err => .error err
        else .error .bounds
      else if 192 ≤ b then
        match msg[pos + 1]? with
        | none => .error .bounds
        | some c =>
          if (b - 192) * 256 + c < seg then
            match readName f msg seg ((b - 192) * 256 + c) ((b - 192) * 256 + c) with
            | .ok (r, _) => .ok (r, pos + 2)
            | .error err => .error err
          else .error .forwardPointer
      else .error .labelType

/-- Enough steps for any name in `msg`: see `readName_fuel`. -/
def fuel (msg : Bytes) : Nat := msg.length * msg.length + msg.length + 256

/-- A name, checked against the label and length limits (RFC 1035 §2.3.4). -/
def name (msg : Bytes) (lim pos : Nat) : Except Err (Name × Nat) :=
  match readName (fuel msg) msg lim pos pos with
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
name from `msg`, as the target of a pointer, under any limit at or after `base`. -/

def TblOK (msg : Bytes) (tbl : Table) (base : Nat) : Prop :=
  ∀ s o, (s, o) ∈ tbl → o < base ∧ o < 16384 ∧
    ∀ lim f, base ≤ lim → lim ≤ msg.length → 2 * s.length ≤ f → ∃ e, readName f msg lim o o = .ok (s, e)

theorem TblOK.mono {msg : Bytes} {tbl : Table} {b b' : Nat} (h : TblOK msg tbl b) (hb : b ≤ b') :
    TblOK msg tbl b' := by
  intro s o hm
  obtain ⟨h1, h2, h3⟩ := h s o hm
  exact ⟨by omega, h2, fun lim f hl hl' hf => h3 lim f (by omega) hl' hf⟩

theorem TblOK.nil (msg : Bytes) (b : Nat) : TblOK msg [] b := by intro s o h; simp at h

/-- The main lemma: a name written at `base` reads back from `base`, ending where its octets end, and the
table stays good. The name is read as part of a name whose current part starts at any `seg` from `s0` to
`base`, where the table is good at `s0`: so it reads back both from its own first octet and as the rest
of a name whose labels were written before it. -/
theorem encName_ok (comp : Bool) (msg : Bytes) (n : Name) : ∀ (base s0 : Nat) (tbl : Table),
    (∀ l ∈ n, 0 < l.length ∧ l.length < 64) → s0 ≤ base → TblOK msg tbl s0 →
    (encName comp base tbl n).1 <+: msg.drop base →
    TblOK msg (encName comp base tbl n).2 (base + (encName comp base tbl n).1.length) ∧
    ∀ seg lim f, s0 ≤ seg → seg ≤ base → base + (encName comp base tbl n).1.length ≤ lim →
      lim ≤ msg.length → 2 * n.length + 1 ≤ f →
      readName f msg lim seg base = .ok (n, base + (encName comp base tbl n).1.length) := by
  induction n with
  | nil =>
    intro base s0 tbl _ hs hT hP
    simp only [encName] at hP ⊢
    refine ⟨hT.mono (by omega), ?_⟩
    intro seg lim f _ _ h1 _ h3
    obtain ⟨f', rfl⟩ : ∃ f', f = f' + 1 := ⟨f - 1, by omega⟩
    have hb := (at_cons hP).1
    simp [readName, hb, show ¬ lim ≤ base by simp at h1; omega]
  | cons l r ih =>
    intro base s0 tbl hl hs hT hP
    have hl0 := hl l (List.mem_cons_self ..)
    have hr : ∀ l' ∈ r, 0 < l'.length ∧ l'.length < 64 := fun l' h => hl l' (List.mem_cons_of_mem _ h)
    cases ho : (if comp then tbl.lookup (l :: r) else none) with
    | some o =>
      -- a pointer to an entry already written, before the part of the name that holds it
      simp only [encName, ho] at hP ⊢
      have hmem : (l :: r, o) ∈ tbl := by
        cases comp
        · simp at ho
        · exact mem_of_lookup (by simpa using ho)
      obtain ⟨hob, ho16, hdec⟩ := hT _ _ hmem
      simp only [List.length_cons, List.length_nil] at hP ⊢
      refine ⟨hT.mono (by omega), ?_⟩
      intro seg lim f hs1 hs2 h1 h2 h3
      obtain ⟨f', rfl⟩ : ∃ f', f = f' + 1 := ⟨f - 1, by omega⟩
      obtain ⟨hb0, hP1⟩ := at_cons hP
      have hb1 := (at_cons hP1).1
      obtain ⟨e, he⟩ := hdec seg f' hs1 (by omega) (by simp at h3; omega)
      have ht : (192 + o / 256 - 192) * 256 + o % 256 = o := by omega
      simp only [readName, show ¬ lim ≤ base by omega, ↓reduceIte, hb0, hb1,
        show ¬ (192 + o / 256 = 0) by omega, show ¬ (192 + o / 256 < 64) by omega,
        show 192 ≤ 192 + o / 256 by omega, ht, show o < seg by omega, he]
    | none =>
      -- labels, then the rest of the name
      simp only [encName, ho] at hP ⊢
      obtain ⟨hPl, hPr⟩ := at_append.mp hP
      have hPr' : (encName comp (base + 1 + l.length) tbl r).1 <+: msg.drop (base + 1 + l.length) := by
        simpa [Nat.add_assoc, Nat.add_comm 1] using hPr
      obtain ⟨hT', hdec⟩ := ih (base + 1 + l.length) s0 tbl hr (by omega) hT hPr'
      have hlab : slice msg (base + 1) l.length = l := by
        obtain ⟨_, h1⟩ := at_cons hPl
        exact at_slice (by simpa using h1)
      have hb0 := (at_cons hPl).1
      have hend : base + ((l.length :: l) ++ (encName comp (base + 1 + l.length) tbl r).1).length =
          base + 1 + l.length + (encName comp (base + 1 + l.length) tbl r).1.length := by
        simp; omega
      -- the name reads back from `base` with one step fewer than a pointer to it would need
      have key : ∀ seg lim f, s0 ≤ seg → seg ≤ base →
          base + 1 + l.length + (encName comp (base + 1 + l.length) tbl r).1.length ≤ lim →
          lim ≤ msg.length → 2 * (l :: r).length ≤ f →
          readName f msg lim seg base =
            .ok (l :: r, base + 1 + l.length + (encName comp (base + 1 + l.length) tbl r).1.length) := by
        intro seg lim f hs1 hs2 h1 h2 h3
        obtain ⟨f', rfl⟩ : ∃ f', f = f' + 1 := ⟨f - 1, by simp at h3; omega⟩
        have := hdec seg lim f' hs1 (by omega) h1 h2 (by simp at h3; omega)
        simp only [readName, show ¬ lim ≤ base by omega, ↓reduceIte, hb0,
          show ¬ (l.length = 0) by omega, show l.length < 64 by omega,
          show base + 1 + l.length ≤ lim by omega, this, hlab]
      rw [hend]
      refine ⟨?_, fun seg lim f hs1 hs2 h1 h2 h3 => key seg lim f hs1 hs2 h1 h2 (by omega)⟩
      split
      · intro s o hm
        simp only [List.mem_cons, Prod.mk.injEq] at hm
        rcases hm with ⟨rfl, ho⟩ | hm
        · rw [ho]
          exact ⟨by omega, by simp_all, fun lim f h1 h2 h3 => ⟨_, key base lim f hs (Nat.le_refl _) h1 h2 h3⟩⟩
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
  obtain ⟨hT', hd⟩ := encName_ok comp msg n base base tbl (valid_labels hv) (Nat.le_refl _) hT hP
  refine ⟨hT', ?_⟩
  have := valid_length hv
  simp only [name, hd base lim (fuel msg) (Nat.le_refl _) (Nat.le_refl _) h1 h2 (by unfold fuel; omega),
    Name.ofLabels?_complete n hv]

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

theorem readName_fuel (msg : Bytes) : ∀ f lim seg pos, lim ≤ msg.length → seg ≤ pos →
    lim * lim + (lim - pos) + 1 ≤ f → readName f msg lim seg pos ≠ .error .exhausted := by
  intro f
  induction f with
  | zero => intro lim seg pos _ _ h; omega
  | succ f ih =>
    intro lim seg pos hl hs hf
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
        · have := ih lim seg (pos + 1 + b) hl (by omega) (by omega)
          simp only [hlim, ↓reduceIte]
          cases hr : readName f msg lim seg (pos + 1 + b) with
          | ok v => simp
          | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact this hr
        · simp [hlim]
      by_cases h192 : 192 ≤ b
      · simp only [h0, h64, h192, ↓reduceIte]
        cases hc : msg[pos + 1]? with
        | none => simp
        | some c =>
          simp only
          by_cases ht : (b - 192) * 256 + c < seg
          · simp only [ht, ↓reduceIte]
            have hsq : (pos + 1) * (pos + 1) ≤ lim * lim := Nat.mul_le_mul (by omega) (by omega)
            have hexp : (pos + 1) * (pos + 1) = pos * pos + 2 * pos + 1 := by
              simp only [Nat.add_mul, Nat.mul_add, Nat.mul_one, Nat.one_mul]; omega
            have hss : seg * seg ≤ pos * pos := Nat.mul_le_mul hs hs
            have := ih seg ((b - 192) * 256 + c) ((b - 192) * 256 + c) (by omega) (Nat.le_refl _) (by omega)
            cases hr : readName f msg seg ((b - 192) * 256 + c) ((b - 192) * 256 + c) with
            | ok v => simp
            | error e => simp only [ne_eq, Except.error.injEq]; rintro rfl; exact this hr
          · simp [ht]
      · simp [h0, h64, h192]

theorem name_fuel (msg : Bytes) (lim pos : Nat) (hl : lim ≤ msg.length) :
    name msg lim pos ≠ .error .exhausted := by
  have := readName_fuel msg (fuel msg) lim pos pos hl (Nat.le_refl _) (by
    unfold fuel
    have : lim * lim ≤ msg.length * msg.length := Nat.mul_le_mul hl hl
    omega)
  unfold name
  cases hr : readName (fuel msg) msg lim pos pos with
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

/-! ## What the decoder returns is well formed -/

/-- Every element is an octet. -/
def Octets (msg : Bytes) : Prop := ∀ b ∈ msg, b < 256

theorem octet_at {msg : Bytes} (h : Octets msg) {p b : Nat} (hb : msg[p]? = some b) : b < 256 :=
  h b (List.mem_of_getElem? hb)

theorem rd16_lt {msg : Bytes} (h : Octets msg) {p v : Nat} (hr : rd16 msg p = some v) : v < 65536 := by
  unfold rd16 at hr
  split at hr
  · rename_i a b ha hb
    have := octet_at h ha; have := octet_at h hb
    simp only [Option.some.injEq] at hr; omega
  · cases hr

theorem rd32_lt {msg : Bytes} (h : Octets msg) {p v : Nat} (hr : rd32 msg p = some v) : v < 4294967296 := by
  unfold rd32 at hr
  split at hr
  · rename_i a b ha hb
    have := rd16_lt h ha; have := rd16_lt h hb
    simp only [Option.some.injEq] at hr; omega
  · cases hr

theorem name_valid {msg : Bytes} {lim pos : Nat} {n : Name} {e : Nat} (h : name msg lim pos = .ok (n, e)) :
    Name.valid n = true := by
  unfold name at h
  split at h
  · split at h
    · rename_i hl; cases h; exact (Name.wire_len_le_255 _ _ hl).2.2
    · cases h
  · cases h

theorem readList_spec {α : Type} {f : Nat → Except Err (α × Nat)} {P : α → Prop}
    (hf : ∀ p x e, f p = .ok (x, e) → P x) :
    ∀ k p xs e, readList f k p = .ok (xs, e) → xs.length = k ∧ ∀ x ∈ xs, P x := by
  intro k
  induction k with
  | zero => intro p xs e h; simp only [readList, Except.ok.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, _⟩ := h; simp
  | succ k ih =>
    intro p xs e h
    simp only [readList] at h
    split at h
    · rename_i x e1 hx
      split at h
      · rename_i xs' e2 hxs
        simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, _⟩ := h
        obtain ⟨h1, h2⟩ := ih _ _ _ hxs
        refine ⟨by simp [h1], fun y hy => ?_⟩
        simp only [List.mem_cons] at hy
        rcases hy with rfl | hy
        · exact hf _ _ _ hx
        · exact h2 y hy
      · cases h
    · cases h

theorem compressible_small {t p k q : Nat} (h : compressible t = some (p, k, q)) : p ≤ 2 ∧ k ≤ 2 ∧ q ≤ 20 := by
  unfold compressible at h
  split at h <;> simp only [Option.some.injEq, Prod.mk.injEq, reduceCtorEq] at h <;> omega

theorem sum_wireLen_le (ns : List Name) (h : ∀ n ∈ ns, Name.valid n = true) :
    (ns.map wireLen).sum ≤ 255 * ns.length := by
  induction ns with
  | nil => simp
  | cons n ns ih =>
    have hn := h n (List.mem_cons_self ..)
    simp only [Name.valid, Bool.and_eq_true, decide_eq_true_eq] at hn
    have := ih (fun m hm => h m (List.mem_cons_of_mem _ hm))
    simp only [List.map_cons, List.sum_cons, List.length_cons]; omega

theorem readRData_wf {msg : Bytes} {t start len : Nat} {rd : RData} (hlen : len < 65536)
    (h : readRData msg t start len = .ok rd) : RData.WF t rd := by
  unfold readRData at h
  split at h
  · cases h
  rename_i hb
  split at h
  · rename_i p k q hc
    split at h
    · cases h
    rename_i hp
    split at h
    · rename_i ns e hns
      split at h
      · rename_i he
        simp only [Except.ok.injEq] at h
        subst h
        obtain ⟨hk, hv⟩ := readList_spec (fun _ x _ hx => name_valid hx) _ _ _ _ hns
        obtain ⟨hp2, hk2, hq20⟩ := compressible_small hc
        have hsum := sum_wireLen_le ns hv
        refine ⟨?_, hv, ?_⟩
        · have e1 : (slice msg start p).length = p := by
            simp only [slice, List.length_take, List.length_drop]; omega
          have e2 : (slice msg e q).length = q := by
            simp only [slice, List.length_take, List.length_drop]; omega
          show compressible t = some ((slice msg start p).length, ns.length, (slice msg e q).length)
          rw [e1, e2, hk]; exact hc
        · have h1 : (slice msg start p).length ≤ 2 := by
            simp only [slice, List.length_take]; omega
          have h2 : (slice msg e q).length ≤ 20 := by
            simp only [slice, List.length_take]; omega
          have h3 : (ns.map wireLen).sum ≤ 510 := by rw [hk] at hsum; omega
          show (slice msg start p).length + (ns.map wireLen).sum + (slice msg e q).length < 65536
          omega
      · cases h
    · cases h
  · rename_i hc
    simp only [Except.ok.injEq] at h
    subst h
    exact ⟨hc, by simp only [slice, List.length_take, List.length_drop]; omega⟩

theorem readQuestion_wf {msg : Bytes} (ho : Octets msg) {pos : Nat} {q : Question} {e : Nat}
    (h : readQuestion msg pos = .ok (q, e)) : q.WF := by
  unfold readQuestion at h
  split at h
  · rename_i n e1 hn
    split at h
    · rename_i t c ht hc
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, _⟩ := h
      exact ⟨name_valid hn, rd16_lt ho ht, rd16_lt ho hc⟩
    · cases h
  · cases h

theorem readRR_wf {msg : Bytes} (ho : Octets msg) {pos : Nat} {r : RR} {e : Nat}
    (h : readRR msg pos = .ok (r, e)) : r.WF := by
  unfold readRR at h
  split at h
  · rename_i n e1 hn
    split at h
    · rename_i t c ttl len ht hc httl hl
      split at h
      · rename_i rd hrd
        simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, _⟩ := h
        exact ⟨name_valid hn, rd16_lt ho ht, rd16_lt ho hc, rd32_lt ho httl, readRData_wf (rd16_lt ho hl) hrd⟩
      · cases h
    · cases h
  · cases h

/-- What the decoder returns from octets is well formed: every name in it has labels of 1 to 63 octets and
takes at most 255 octets (RFC 1035 §2.3.4, §3.1), every number fits its field, the RDATA of the RFC 1035
name-bearing types has the layout of its type, and each section is shorter than its 16-bit count allows
(§4.1.1). -/
theorem decode_wf (msg : Bytes) (ho : Octets msg) (m : Message) (h : decode msg = .ok m) : m.WF := by
  unfold decode at h
  split at h
  · rename_i id fl qd an ns ar hid hfl hqd han hns har
    split at h
    · rename_i q p1 hq
      split at h
      · rename_i a p2 ha
        split at h
        · rename_i n p3 hn
          split at h
          · rename_i d p4 hd
            simp only [Except.ok.injEq] at h
            subst h
            obtain ⟨lq, wq⟩ := readList_spec (fun _ x _ hx => readQuestion_wf ho hx) _ _ _ _ hq
            obtain ⟨la, wa⟩ := readList_spec (fun _ x _ hx => readRR_wf ho hx) _ _ _ _ ha
            obtain ⟨ln, wn⟩ := readList_spec (fun _ x _ hx => readRR_wf ho hx) _ _ _ _ hn
            obtain ⟨ld, wd⟩ := readList_spec (fun _ x _ hx => readRR_wf ho hx) _ _ _ _ hd
            refine ⟨rd16_lt ho hid, rd16_lt ho hfl, ?_, ?_, ?_, ?_, wq, wa, wn, wd⟩
            · rw [lq]; exact rd16_lt ho hqd
            · rw [la]; exact rd16_lt ho han
            · rw [ln]; exact rd16_lt ho hns
            · rw [ld]; exact rd16_lt ho har
          · cases h
        · cases h
      · cases h
    · cases h
  · cases h

/-- Compression is transparent: a message decoded from octets, written again with or without compression,
decodes to the same message (RFC 1035 §4.1.4). -/
theorem decode_reencode (msg : Bytes) (ho : Octets msg) (m : Message) (h : decode msg = .ok m) (comp : Bool) :
    decode (encode comp m) = .ok m :=
  decode_encode comp m (decode_wf msg ho m h)

/-- A pointer that does not point strictly before the part of the name that holds it, the name's first
octet or the target of the pointer that led there, is rejected (RFC 1035 §4.1.4: a pointer names a prior
occurrence). That covers a pointer forward, one to itself, and one into the labels before it in the same
name; with `decode_terminates`, no chain of pointers loops. -/
theorem decode_rejects_forward_pointer (f : Nat) (msg : Bytes) (lim seg pos b c : Nat) (hpos : pos < lim)
    (hb : msg[pos]? = some b) (hc : msg[pos + 1]? = some c) (hb192 : 192 ≤ b)
    (hfwd : seg ≤ (b - 192) * 256 + c) :
    readName (f + 1) msg lim seg pos = .error .forwardPointer := by
  simp only [readName, show ¬ lim ≤ pos by omega, ↓reduceIte, hb, show ¬ b = 0 by omega,
    show ¬ b < 64 by omega, hb192, hc, show ¬ ((b - 192) * 256 + c < seg) by omega]

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

/-- A reply's header copies the query's ID, OPCODE, and RD, and sets QR (RFC 1035 §4.1.1); it copies CD
(RFC 4035 §3.2.2); RA is clear, as an authoritative server offers no recursion, and Z, which must be zero in
all messages, is clear (RFC 1035 §4.1.1); AD is clear (RFC 4035 §3.2.3); AA, TC, and RCODE are the
reply's own; and the flags fit their 16 bits. -/
theorem respondHeader_fields (q : Header) (rc : Nat) (aa tc : Bool) :
    (respondHeader q rc aa tc).id = q.id ∧ (respondHeader q rc aa tc).qr = true ∧
      (respondHeader q rc aa tc).opcode = q.opcode ∧ (respondHeader q rc aa tc).aa = aa ∧
      (respondHeader q rc aa tc).tc = tc ∧ (respondHeader q rc aa tc).rd = q.rd ∧
      (respondHeader q rc aa tc).ra = false ∧ (respondHeader q rc aa tc).z = false ∧
      (respondHeader q rc aa tc).ad = false ∧ (respondHeader q rc aa tc).cd = q.cd ∧
      (respondHeader q rc aa tc).rcode = rc % 16 ∧ (respondHeader q rc aa tc).flags < 65536 := by
  have ho : q.opcode < 16 := Nat.mod_lt _ (by decide)
  simp only [respondHeader]
  generalize q.opcode = o at *
  generalize q.rd = r
  generalize q.cd = c
  cases aa <;> cases tc <;> cases r <;> cases c <;>
    simp only [Header.qr, Header.opcode, Header.aa, Header.tc, Header.rd, Header.ra, Header.z, Header.ad,
      Header.cd, Header.rcode, Header.bit, flagsOf, b2n, Bool.false_eq_true, ↓reduceIte, true_and,
      Nat.reducePow, beq_iff_eq, beq_eq_false_iff_ne, ne_eq] <;> omega

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

/-- The first fault among `rs`, a message's records in order, of the kinds a message that decodes may still
have: an OPT record among the first `outside` records, outside the additional section (RFC 6891 §6.1.1)
(`some true`), or a TSIG record that is not the last record of the additional section (RFC 8945 §5.1)
(`some false`). -/
def placementFault (outside : Nat) : List RR → Nat → Option Bool
  | [], _ => none
  | r :: rs, i =>
    if r.rtype == 41 && i < outside then some true
    else if r.rtype == 250 && (decide (i < outside) || !rs.isEmpty) then some false
    else placementFault outside rs (i + 1)

/-- Where the record after the next `k` records from `pos` starts, each read as `readRR` reads it. -/
def skipRRs (msg : Bytes) : Nat → Nat → Option Nat
  | 0, pos => some pos
  | k + 1, pos =>
    match readRR msg pos with
    | .ok (_, e) => skipRRs msg k e
    | .error _ => none

/-- Whether the TSIG record at `pos` reads (RFC 8945 §4.2): its RDATA is the algorithm name, which may point
to a name earlier in the message, then the time signed (6 octets), the fudge, the MAC size and the MAC, the
original ID, the error, and the other length and other data, ending where the RDATA ends. -/
def tsigReads (msg : Bytes) (pos : Nat) : Bool :=
  match name msg msg.length pos with
  | .error _ => false
  | .ok (_, e) =>
    match rd16 msg (e + 8) with
    | none => false
    | some len =>
      let start := e + 10
      let finish := start + len
      match name msg finish start with
      | .error _ => false
      | .ok (_, a) =>
        match rd16 msg (a + 8) with
        | none => false
        | some mac =>
          match rd16 msg (a + 10 + mac + 4) with
          | none => false
          | some other => a + 10 + mac + 6 + other == finish && finish ≤ msg.length

/-- What the query's OPT record says, the payload size below 512 read as 512 (RFC 6891 §6.2.5). -/
def ednsOf (o : RR) : EdnsIn :=
  ⟨max 512 o.rclass, o.ttl / 65536 % 256, o.ttl / 32768 % 2 == 1,
    match o.rdata with
    | .octets bs => ((options bs).getD []).any (·.1 == 3)
    | _ => false⟩

/-- Whether the query's OPT record is at fault: an owner other than the root, or options that do not split
(RFC 6891 §6.1.2). -/
def optBad (opt : Option RR) : Bool :=
  opt.any fun o => o.owner != [] || (match o.rdata with
    | .octets bs => (options bs).isNone
    | _ => true)

/-- Where the message's last record starts, read as `readRR` reads it. -/
def tsigAt (bytes : Bytes) (m : Message) : Option Nat :=
  match readList (readQuestion bytes) m.question.length 12 with
  | .ok (_, p) => skipRRs bytes ((m.answer ++ m.authority ++ m.additional).length - 1) p
  | .error _ => none

/-- `Request::parse`'s checks after the header, in its fixed order, for a query with header `h`: the
request, or the rejection's extended RCODE and the version of its OPT, if it carries one. `udp` says
whether the query came over UDP. -/
def check (h : Header) (bytes : Bytes) (udp : Bool) : Except (Nat × Option Nat) Request :=
  match decode bytes with
  | .error _ => .error (1, if faultInOpt bytes then some 0 else none)
  | .ok m =>
    let records := m.answer ++ m.authority ++ m.additional
    -- a FORMERR carries an OPT when the query has one (RFC 6891 §7)
    let anyOpt : Option Nat := if records.any optRR then some 0 else none
    -- an OPT record belongs in the additional section alone (RFC 6891 §6.1.1), and a TSIG record is the last
    -- record of the additional section (RFC 8945 §5.1)
    match placementFault (m.answer.length + m.authority.length) records 0 with
    | some true => .error (1, some 0)
    | some false => .error (1, anyOpt)
    | none =>
    if 2 ≤ (m.additional.filter optRR).length then .error (1, some 0) else
    let opt := (m.additional.filter optRR).head?
    if optBad opt then .error (1, some 0) else
    let signed := m.additional.getLast?.any (·.rtype == 250)
    -- a TSIG record that does not read is a fault in the message (RFC 8945 §5.2)
    if signed && !(tsigAt bytes m).any (tsigReads bytes) then .error (1, anyOpt) else
    let edns : Option EdnsIn := opt.map ednsOf
    -- the reply carries an OPT of version 0 exactly when the query had one (RFC 6891 §7)
    let optOut : Option Nat := edns.map fun _ => 0
    if 0 < ((edns.map (·.version)).getD 0) then .error (16, some 0) else
    -- signed with a key a server here does not hold: NOTAUTH, with a TSIG of error BADKEY (RFC 8945 §5.2.1)
    if signed then .error (9, optOut) else
    if h.opcode != 0 then .error (4, optOut) else
    match m.question with
    | [q] =>
      -- OPT, TSIG, and TKEY are meta-types, records of one message, never data to ask for (RFC 6891
      -- §6.1.1, RFC 6895 §3.1)
      if q.qtype == 41 || q.qtype == 250 || q.qtype == 249 then .error (1, optOut)
      -- AXFR is not defined over UDP (RFC 5936 §4.2); IXFR is (RFC 1995 §2)
      else if udp && q.qtype == 252 then .error (1, optOut)
      else if q.qtype == 253 || q.qtype == 254 then .error (4, optOut)
      else .ok ⟨h, q, edns⟩
    | _ => .error (1, optOut)

/-- `Request::parse`: silence for fewer than 12 octets or a response, then `check`. A rejection's header is
the reply header to the query's (`respondHeader`) with the low four bits of its RCODE. -/
def parse (bytes : Bytes) (udp : Bool) : Parsed :=
  match rd16 bytes 0, rd16 bytes 2 with
  | some id, some fl =>
    let h : Header := ⟨id, fl⟩
    if bytes.length < 12 || h.qr then .silent else
    match check h bytes udp with
    | .error (rc, opt) => .reject ⟨rc, respondHeader h (rc % 16) false false, opt⟩
    | .ok q => .request q
  | _, _ => .silent

/-! ### What `parse` guarantees -/

/-- A message with QR set is a response, and a server sends no reply to it (RFC 1035 §4.1.1: a reply
answers a query), which also keeps two servers from answering each other forever. -/
theorem parse_response_silent (bytes : Bytes) (udp : Bool) (id fl : Nat) (h0 : rd16 bytes 0 = some id)
    (h2 : rd16 bytes 2 = some fl) (hqr : (⟨id, fl⟩ : Header).qr = true) : parse bytes udp = .silent := by
  simp [parse, h0, h2, hqr]

/-- Every rejection is a reply to the query: its header copies the query's ID, OPCODE, RD, and CD, sets QR,
and clears AA, TC, RA, Z, and AD (`respondHeader_fields`, RFC 1035 §4.1.1), with the low bits of the RCODE;
and the query was not a response. -/
theorem parse_reject_header (bytes : Bytes) (udp : Bool) (r : Reject) (hp : parse bytes udp = .reject r) :
    ∃ id fl, rd16 bytes 0 = some id ∧ rd16 bytes 2 = some fl ∧ (⟨id, fl⟩ : Header).qr = false ∧
      r.header = respondHeader ⟨id, fl⟩ (r.rcode % 16) false false ∧
      check ⟨id, fl⟩ bytes udp = .error (r.rcode, r.opt) := by
  unfold parse at hp
  split at hp
  · rename_i id fl h0 h2
    refine ⟨id, fl, h0, h2, ?_⟩
    dsimp only at hp
    split at hp
    · cases hp
    · rename_i hs
      simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Bool.not_eq_true] at hs
      split at hp
      · rename_i rc opt hc
        simp only [Parsed.reject.injEq] at hp
        subst hp
        exact ⟨hs.2, rfl, hc⟩
      · cases hp
  · cases hp

theorem parse_request (bytes : Bytes) (udp : Bool) (q : Request) (hp : parse bytes udp = .request q) :
    ∃ id fl, rd16 bytes 0 = some id ∧ rd16 bytes 2 = some fl ∧ (⟨id, fl⟩ : Header).qr = false ∧
      12 ≤ bytes.length ∧ check ⟨id, fl⟩ bytes udp = .ok q := by
  unfold parse at hp
  split at hp
  · rename_i id fl h0 h2
    refine ⟨id, fl, h0, h2, ?_⟩
    dsimp only at hp
    split at hp
    · cases hp
    · rename_i hs
      simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Bool.not_eq_true] at hs
      split at hp
      · cases hp
      · rename_i q' hc
        simp only [Parsed.request.injEq] at hp
        subst hp
        exact ⟨hs.2, by omega, hc⟩
  · cases hp

theorem placementFault_true {o : Nat} : ∀ (rs : List RR) (i : Nat), placementFault o rs i = some true →
    rs.any optRR = true := by
  intro rs
  induction rs with
  | nil => intro i h; simp [placementFault] at h
  | cons r rs ih =>
    intro i h
    simp only [placementFault] at h
    split at h
    · rename_i hr
      simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hr
      simp [optRR, hr.1]
    · split at h
      · cases h
      · simp [ih _ h]

/-- With no fault found, no OPT record lies among the first `o - i` records. -/
theorem placementFault_none {o : Nat} : ∀ (a b : List RR) (i : Nat), placementFault o (a ++ b) i = none →
    i + a.length ≤ o → a.any optRR = false := by
  intro a
  induction a with
  | nil => intro _ _ _ _; rfl
  | cons r rs ih =>
    intro b i h hl
    simp only [List.cons_append, placementFault] at h
    split at h
    · cases h
    · rename_i hr
      split at h
      · cases h
      · simp only [List.length_cons] at hl
        have h1 : r.rtype ≠ 41 := by
          intro he; apply hr; simp [he]; omega
        simp only [List.any_cons, optRR, Bool.or_eq_false_iff, beq_eq_false_iff_ne, ne_eq]
        exact ⟨h1, by simpa [optRR] using ih b (i + 1) h (by omega)⟩

/-- A section has an OPT record exactly when its first OPT record exists. -/
theorem head_filter_isSome (l : List RR) : (l.filter optRR).head?.isSome = l.any optRR := by
  induction l with
  | nil => rfl
  | cons r rs ih =>
    by_cases h : optRR r = true
    · rw [List.filter_cons_of_pos h]; simp [h]
    · rw [List.filter_cons_of_neg h, ih]; simp [h]

/-- What `check` decides for a message that decodes and has no misplaced OPT or TSIG record, with its
OPT records `os` and its first one `opt`. -/
theorem check_placed (h : Header) (bytes : Bytes) (udp : Bool) (m : Message) (hd : decode bytes = .ok m)
    (hpf : placementFault (m.answer.length + m.authority.length) (m.answer ++ m.authority ++ m.additional) 0 = none) :
    check h bytes udp =
      if 2 ≤ (m.additional.filter optRR).length then .error (1, some 0) else
      if optBad (m.additional.filter optRR).head? then .error (1, some 0) else
      if (m.additional.getLast?.any (·.rtype == 250)) && !(tsigAt bytes m).any (tsigReads bytes) then
        .error (1, if (m.answer ++ m.authority ++ m.additional).any optRR then some 0 else none) else
      if 0 < ((((m.additional.filter optRR).head?.map ednsOf).map (·.version)).getD 0) then .error (16, some 0) else
      if m.additional.getLast?.any (·.rtype == 250) then
        .error (9, ((m.additional.filter optRR).head?.map ednsOf).map fun _ => 0) else
      if h.opcode != 0 then .error (4, ((m.additional.filter optRR).head?.map ednsOf).map fun _ => 0) else
      match m.question with
      | [q] =>
        if q.qtype == 41 || q.qtype == 250 || q.qtype == 249 then
          .error (1, ((m.additional.filter optRR).head?.map ednsOf).map fun _ => 0)
        else if udp && q.qtype == 252 then .error (1, ((m.additional.filter optRR).head?.map ednsOf).map fun _ => 0)
        else if q.qtype == 253 || q.qtype == 254 then
          .error (4, ((m.additional.filter optRR).head?.map ednsOf).map fun _ => 0)
        else .ok ⟨h, q, (m.additional.filter optRR).head?.map ednsOf⟩
      | _ => .error (1, ((m.additional.filter optRR).head?.map ednsOf).map fun _ => 0) := by
  unfold check
  rw [hd]
  simp only [hpf]
  try rfl

/-- A request is a QUERY with one question (RFC 1035 §4.1.2, RFC 9619) of a type one may ask for, in a
message that decodes, with at most one OPT record (RFC 6891 §6.1.1), of version 0 (§6.1.3), and a payload
size of at least 512 (§6.2.5), present exactly when the query has an OPT record, and no TSIG record. -/
theorem check_request (h : Header) (bytes : Bytes) (udp : Bool) (q : Request) (hc : check h bytes udp = .ok q) :
    ∃ m, decode bytes = .ok m ∧ q.header = h ∧ h.opcode = 0 ∧ m.question = [q.question] ∧
      q.question.qtype ∉ [41, 249, 250, 253, 254] ∧ (udp = true → q.question.qtype ≠ 252) ∧
      (m.additional.filter optRR).length ≤ 1 ∧
      (q.edns.isSome = (m.answer ++ m.authority ++ m.additional).any optRR) ∧
      (∀ e, q.edns = some e → e.version = 0 ∧ 512 ≤ e.payload) ∧
      (m.additional.getLast?.any (·.rtype == 250)) = false := by
  cases hd : decode bytes with
  | error e => unfold check at hc; rw [hd] at hc; simp at hc
  | ok m =>
  refine ⟨m, rfl, ?_⟩
  cases hpf : placementFault (m.answer.length + m.authority.length) (m.answer ++ m.authority ++ m.additional) 0 with
  | some b =>
    unfold check at hc; rw [hd] at hc; simp only [hpf] at hc
    cases b <;> simp at hc
  | none =>
  have hout := placementFault_none (m.answer ++ m.authority) m.additional 0
    (by simpa [List.append_assoc] using hpf) (by simp)
  rw [check_placed h bytes udp m hd hpf] at hc
  by_cases h2 : 2 ≤ (m.additional.filter optRR).length
  · simp only [h2, ↓reduceIte, Bool.false_eq_true, Bool.false_and, reduceCtorEq] at hc
    try (split at hc <;> simp at hc)
  by_cases hb : optBad (m.additional.filter optRR).head? = true
  · simp only [h2, hb, ↓reduceIte, Bool.false_eq_true, Bool.false_and, reduceCtorEq] at hc
    try (split at hc <;> simp at hc)
  by_cases ht : ((m.additional.getLast?.any (·.rtype == 250)) && !(tsigAt bytes m).any (tsigReads bytes)) = true
  · simp only [h2, hb, ht, ↓reduceIte, Bool.false_eq_true, Bool.false_and, reduceCtorEq] at hc
    try (split at hc <;> simp at hc)
  by_cases hv : 0 < ((((m.additional.filter optRR).head?.map ednsOf).map (·.version)).getD 0)
  · simp only [h2, hb, ht, hv, ↓reduceIte, Bool.false_eq_true, Bool.false_and, reduceCtorEq] at hc
    try (split at hc <;> simp at hc)
  by_cases hs : (m.additional.getLast?.any (·.rtype == 250)) = true
  · simp only [h2, hb, ht, hv, hs, ↓reduceIte, Bool.false_eq_true, Bool.false_and, reduceCtorEq] at hc
    try (split at hc <;> simp at hc)
  by_cases hop : (h.opcode != 0) = true
  · simp only [h2, hb, ht, hv, hs, hop, ↓reduceIte, Bool.false_eq_true, Bool.false_and, reduceCtorEq] at hc
    try (split at hc <;> simp at hc)
  simp only [h2, hb, ht, hv, hs, hop, ↓reduceIte, Bool.false_eq_true, Bool.false_and] at hc
  cases hq : m.question with
  | nil => rw [hq] at hc; simp at hc
  | cons qq rest =>
  cases rest with
  | cons _ _ => rw [hq] at hc; simp at hc
  | nil =>
  rw [hq] at hc
  by_cases t1 : (qq.qtype == 41 || qq.qtype == 250 || qq.qtype == 249) = true
  · simp only [t1, ↓reduceIte, Bool.false_eq_true, Bool.false_and, reduceCtorEq] at hc
    try (split at hc <;> simp at hc)
  by_cases t2 : (udp && qq.qtype == 252) = true
  · simp only [t1, t2, ↓reduceIte, Bool.false_eq_true, Bool.false_and, reduceCtorEq] at hc
    try (split at hc <;> simp at hc)
  by_cases t3 : (qq.qtype == 253 || qq.qtype == 254) = true
  · simp only [t1, t2, t3, ↓reduceIte, Bool.false_eq_true, Bool.false_and, reduceCtorEq] at hc
    try (split at hc <;> simp at hc)
  simp only [t1, t2, t3, ↓reduceIte, Bool.false_eq_true, Except.ok.injEq] at hc
  subst hc
  simp only [bne_iff_ne, ne_eq, Decidable.not_not, Bool.not_eq_true] at hop
  simp only [Bool.or_eq_true, beq_iff_eq, not_or] at t1 t3
  simp only [Bool.and_eq_true, beq_iff_eq, not_and] at t2
  refine ⟨rfl, by simpa using hop, rfl, ?_, t2, by omega, ?_, ?_, by simpa using hs⟩
  · simp only [List.mem_cons, List.not_mem_nil, or_false, not_or]
    exact ⟨t1.1.1, t1.2, t1.1.2, t3.1, t3.2⟩
  · simp only [List.any_append, Bool.or_eq_false_iff] at hout
    simp only [Option.isSome_map, head_filter_isSome, List.any_append, hout.1, hout.2, Bool.false_or]
  · intro e he
    simp only [Option.map_eq_some_iff] at he
    obtain ⟨o, ho, rfl⟩ := he
    simp only [ho, Option.map_some, Option.getD_some, Nat.not_lt, Nat.le_zero] at hv
    exact ⟨hv, Nat.le_max_left _ _⟩

/-- RFC 6891 §7: a rejection of a query that decodes carries an OPT record exactly when the query has one.
A query without an OPT gets a FORMERR, NOTIMP, NOTAUTH, or other rejection without one; a query with one,
even one whose OPT or TSIG is at fault, gets an OPT back. -/
theorem check_opt_iff (h : Header) (bytes : Bytes) (udp : Bool) (m : Message) (hd : decode bytes = .ok m)
    (rc : Nat) (opt : Option Nat) (hc : check h bytes udp = .error (rc, opt)) :
    opt.isSome = (m.answer ++ m.authority ++ m.additional).any optRR := by
  cases hpf : placementFault (m.answer.length + m.authority.length) (m.answer ++ m.authority ++ m.additional) 0 with
  | some b =>
    unfold check at hc; rw [hd] at hc; simp only [hpf] at hc
    cases b with
    | true =>
      simp only [Except.error.injEq, Prod.mk.injEq] at hc
      rw [← hc.2, Option.isSome_some]
      exact (placementFault_true _ _ hpf).symm
    | false =>
      simp only [Except.error.injEq, Prod.mk.injEq] at hc
      rw [← hc.2]; split <;> simp_all
  | none =>
  have hout := placementFault_none (m.answer ++ m.authority) m.additional 0
    (by simpa [List.append_assoc] using hpf) (by simp)
  simp only [List.any_append, Bool.or_eq_false_iff] at hout
  -- with no fault found, an OPT record of the query is in the additional section
  have hrec : (m.answer ++ m.authority ++ m.additional).any optRR = (m.additional.filter optRR).head?.isSome := by
    rw [head_filter_isSome]; simp [List.any_append, hout.1, hout.2]
  rw [check_placed h bytes udp m hd hpf, hrec] at hc
  rw [hrec]
  by_cases h2 : 2 ≤ (m.additional.filter optRR).length
  · simp only [h2, ↓reduceIte, Except.error.injEq, Prod.mk.injEq] at hc
    rw [← hc.2]
    cases hf : m.additional.filter optRR with
    | nil => rw [hf] at h2; simp at h2
    | cons x xs => rfl
  simp only [h2, ↓reduceIte] at hc
  cases hh : (m.additional.filter optRR).head? with
  | none =>
    simp only [hh] at hc
    repeat' split at hc
    all_goals first
      | (simp only [Except.error.injEq, Prod.mk.injEq] at hc; obtain ⟨-, rfl⟩ := hc; first | rfl | simp_all [optBad])
      | simp at hc
  | some o =>
    simp only [hh] at hc
    repeat' split at hc
    all_goals first
      | (simp only [Except.error.injEq, Prod.mk.injEq] at hc; obtain ⟨-, rfl⟩ := hc; first | rfl | simp_all [optBad])
      | simp at hc

/-! ## Messages on a stream

Over TCP, and over TLS, each message follows its length as two octets in network order (RFC 1035 §4.2.2,
RFC 7766 §8). `unframe` is Rust's `Queries::decode` under `Framing::Stream` (`protocols/dns/framing.rs`):
the first message and the octets it took, or `none` when the length or the message is not all there yet,
which asks for more. -/

/-- A message after its length, as a stream carries it. -/
def frame (m : Bytes) : Bytes := be16 m.length ++ m

def unframe : Bytes → Option (Bytes × Nat)
  | a :: b :: rest =>
    if a * 256 + b ≤ rest.length then some (rest.take (a * 256 + b), 2 + (a * 256 + b)) else none
  | _ => none

theorem unframe_some {input m : Bytes} {n : Nat} (h : unframe input = some (m, n)) :
    2 ≤ n ∧ n ≤ input.length ∧ m.length + 2 = n := by
  unfold unframe at h
  split at h
  · rename_i a b rest
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      simp only [List.length_cons, List.length_take]; omega
    · cases h
  · cases h

/-- Every whole message at the front of `input`, in order, and the octets after them. -/
def unframeAll (input : Bytes) : List Bytes × Bytes :=
  match h : unframe input with
  | some (m, n) =>
    let r := unframeAll (input.drop n)
    (m :: r.1, r.2)
  | none => ([], input)
termination_by input.length
decreasing_by have := unframe_some h; (try simp only [List.length_drop]); omega

theorem unframe_frame (m rest : Bytes) (hm : m.length < 65536) :
    unframe (frame m ++ rest) = some (m, 2 + m.length) := by
  have e : m.length / 256 % 256 * 256 + m.length % 256 = m.length := by omega
  simp [frame, be16, unframe, e]

/-- The length counts the octets after it: `none`, asking for more, exactly when the two octets of the
length or the message they count are not all there. -/
theorem unframe_none_iff (input : Bytes) :
    unframe input = none ↔ ∀ a b rest, input = a :: b :: rest → rest.length < a * 256 + b := by
  unfold unframe
  split
  · rename_i a b rest
    constructor
    · intro h a' b' rest' he
      simp only [List.cons.injEq] at he
      obtain ⟨rfl, rfl, rfl⟩ := he
      split at h
      · cases h
      · omega
    · intro h
      have := h a b rest rfl
      simp [show ¬ a * 256 + b ≤ rest.length by omega]
  · rename_i hn
    simp only [true_iff]
    intro a b rest he
    exact absurd he (hn a b rest)

/-- A stream of framed messages reads back as exactly those messages, in order, and what follows the last
whole one, a message not yet all there, waits for more octets (RFC 1035 §4.2.2, RFC 7766 §8). -/
theorem unframeAll_frames (ms : List Bytes) (rest : Bytes) (hm : ∀ m ∈ ms, m.length < 65536)
    (hr : unframe rest = none) : unframeAll ((ms.map frame).flatten ++ rest) = (ms, rest) := by
  induction ms with
  | nil => simp only [List.map_nil, List.flatten_nil, List.nil_append]; rw [unframeAll]; split <;> simp_all
  | cons m ms ih =>
    have hm0 := hm m (List.mem_cons_self ..)
    have ih' := ih (fun x hx => hm x (List.mem_cons_of_mem _ hx))
    have hu : unframe ((((m :: ms).map frame).flatten ++ rest)) = some (m, 2 + m.length) := by
      simp only [List.map_cons, List.flatten_cons, List.append_assoc]
      exact unframe_frame m _ hm0
    rw [unframeAll]
    split
    · rename_i m' n hu'
      rw [hu] at hu'
      simp only [Option.some.injEq, Prod.mk.injEq] at hu'
      obtain ⟨rfl, rfl⟩ := hu'
      have hd : (((m :: ms).map frame).flatten ++ rest).drop (2 + m.length) =
          (ms.map frame).flatten ++ rest := by
        simp only [List.map_cons, List.flatten_cons, List.append_assoc, frame, be16]
        rw [show 2 + m.length = m.length + 1 + 1 by omega]
        simp only [List.cons_append, List.nil_append, List.drop_succ_cons, List.drop_left]
      simp only [hd, ih']
    · rename_i hn
      rw [hu] at hn; cases hn

end Dns.Wire
