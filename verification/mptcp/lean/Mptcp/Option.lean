/-
  The MPTCP option codec of RFC 8684, modelling `MptcpOption` in
  `src/stdlib/protocols/mptcp.rs`.

  An option's wire form is TCP option kind 30, a Length, then the option's
  data: a first byte whose top 4 bits are the subtype and bottom 4 bits are
  flags or a version, then whatever the subtype and the Length call for. This
  file models the data, the bytes after Kind and Length, exactly as Rust's
  `MptcpOption::parse` reads them and `MptcpOption::write` writes them.

  Octets are `Nat`. A value is well formed (`Wf`) when its octet fields are
  octets (each below 256) of the lengths the wire form fixes, and its bit
  fields are in range. The multi-octet fields RFC 8684 treats as opaque
  (keys, tokens, HMACs, sequence numbers, the data-level length, checksums,
  addresses, ports) are kept as octet lists, since the codec never reads them
  as numbers; `token`, `idsn`, `join_hmac` and `dss_checksum` are modelled
  in `Pure.lean`. Bit fields (the version, the MP_CAPABLE flags and
  algorithms, the DSS flags) are `Nat` read with division and remainder.
-/
namespace Mptcp

abbrev Octets := List Nat

/-- An octet list of a fixed length whose entries are all octets. -/
def IsOctets (bs : Octets) (len : Nat) : Prop := bs.length = len ∧ ∀ b ∈ bs, b < 256

/-! ## The option types, mirroring the Rust enums. -/

/-- What follows MP_CAPABLE's flags, which its Length decides. -/
inductive Keys where
  | absent
  | sender (key : Octets)
  | both (sender receiver : Octets)
  | data (sender receiver : Octets) (dll : Octets) (checksum : Option Octets)
  deriving DecidableEq, Repr

/-- Whether the keys carry a sender's key, which version 0 requires. -/
def Keys.hasKey : Keys → Bool
  | .sender _ => true
  | .both _ _ => true
  | _ => false

/-- MP_CAPABLE (RFC 8684 §3.1). `version` is 4 bits, `algorithms` 5 bits. -/
structure Capable where
  version : Nat
  checksumRequired : Bool
  extensibility : Bool
  noNewSubflows : Bool
  algorithms : Nat
  keys : Keys
  deriving DecidableEq, Repr

/-- MP_JOIN (RFC 8684 §3.2): the form per packet, told apart by Length. -/
inductive Join where
  | syn (backup : Bool) (addressId : Nat) (token : Octets) (random : Octets)
  | synAck (backup : Bool) (addressId : Nat) (hmac : Octets) (random : Octets)
  | ack (hmac : Octets)
  deriving DecidableEq, Repr

/-- A data sequence number or Data ACK, 4 or 8 octets. -/
inductive Sequence where
  | short (v : Octets)
  | long (v : Octets)
  deriving DecidableEq, Repr

/-- A data sequence mapping (RFC 8684 §3.3.1). -/
structure Mapping where
  dsn : Sequence
  subflowSeq : Octets
  dll : Octets
  checksum : Option Octets
  deriving DecidableEq, Repr

/-- DSS (RFC 8684 §3.3): a Data ACK, a mapping, both or neither, and F. -/
structure Dss where
  dataAck : Option Sequence
  mapping : Option Mapping
  dataFin : Bool
  deriving DecidableEq, Repr

/-- An address an ADD_ADDR carries. -/
inductive Addr where
  | v4 (o : Octets)
  | v6 (o : Octets)
  deriving DecidableEq, Repr

/-- ADD_ADDR (RFC 8684 §3.4.1). `hmac = none` is the echo (flag E). -/
structure AddAddr where
  addressId : Nat
  address : Addr
  port : Option Octets
  hmac : Option Octets
  deriving DecidableEq, Repr

/-- One MPTCP option, from its subtype on. -/
inductive Opt where
  | capable (c : Capable)
  | join (j : Join)
  | dss (d : Dss)
  | addAddr (a : AddAddr)
  | removeAddr (ids : Octets)
  | prio (backup : Bool)
  | fail (dsn : Octets)
  | fastClose (receiverKey : Octets)
  | tcpRst (transient : Bool) (reason : Nat)
  deriving DecidableEq, Repr

/-- Why an option cannot be read or written. -/
inductive Error where
  | unwritable
  | noSubtype
  | tooLong (length : Nat)
  | subtype (sub : Nat)
  | length (sub : Nat) (length : Nat)
  | noAlgorithm
  deriving DecidableEq, Repr

/-- The longest option Length: a TCP header has 40 bytes for options. -/
def MAX_LEN : Nat := 40
/-- HMAC-SHA256, bit H, the only algorithm RFC 8684 assigns. -/
def HMAC_SHA256 : Nat := 1
/-- All of the algorithm bits D to H. -/
def ALG_ALL : Nat := 31
/-- The MPTCP version this module follows. -/
def VERSION : Nat := 1

@[simp] def b2n (b : Bool) : Nat := if b then 1 else 0

@[simp] theorem b2n_le (b : Bool) : b2n b ≤ 1 := by cases b <;> simp
@[simp] theorem b2n_lt (b : Bool) : b2n b < 2 := by cases b <;> simp

/-! ## Parsing -/

/-- Builds the flags/version byte's decoded MP_CAPABLE, after the Length arm
    chose `keys`: version-0 needs a key, and no algorithm bit is an error. -/
def buildCapable (low flags : Nat) (keys : Keys) (bad : Error) : Except Error Opt :=
  if low == 0 && !keys.hasKey then
    .error bad
  else
    let algorithms := flags % 32
    if algorithms == 0 then .error .noAlgorithm
    else .ok (.capable
      { version := low
        checksumRequired := flags / 128 % 2 == 1
        extensibility := flags / 64 % 2 == 1
        noNewSubflows := flags / 32 % 2 == 1
        algorithms := algorithms
        keys := keys })

/-- MP_CAPABLE: the keys come from the option's Length (`body` is the bytes
    after the flags byte). -/
def parseCapable (low : Nat) (rest : Octets) (bad : Error) : Except Error Opt :=
  match rest with
  | [] => .error bad
  | flags :: body =>
    if body.length == 0 then buildCapable low flags .absent bad
    else if body.length == 8 then buildCapable low flags (.sender body) bad
    else if body.length == 16 then
      buildCapable low flags (.both (body.take 8) (body.drop 8)) bad
    else if body.length == 18 then
      buildCapable low flags
        (.data (body.take 8) ((body.drop 8).take 8) ((body.drop 16).take 2) none) bad
    else if body.length == 20 then
      buildCapable low flags
        (.data (body.take 8) ((body.drop 8).take 8) ((body.drop 16).take 2)
          (some ((body.drop 18).take 2))) bad
    else .error bad

/-- MP_JOIN: the form comes from the option's Length. -/
def parseJoin (low : Nat) (rest : Octets) (bad : Error) : Except Error Opt :=
  let backup := low % 2 == 1
  if rest.length == 9 then
    .ok (.join (.syn backup (rest.headD 0) ((rest.drop 1).take 4) ((rest.drop 5).take 4)))
  else if rest.length == 13 then
    .ok (.join (.synAck backup (rest.headD 0) ((rest.drop 1).take 8) ((rest.drop 9).take 4)))
  else if rest.length == 21 then
    .ok (.join (.ack ((rest.drop 1).take 20)))
  else .error bad

/-- DSS: the flags byte says which of the Data ACK and the mapping are there
    and their octet sizes; the option's Length says whether a checksum is. -/
def parseDss (rest : Octets) (bad : Error) : Except Error Opt :=
  match rest with
  | [] => .error bad
  | flags :: body =>
    let dataFin := flags / 16 % 2 == 1
    let longDsn := flags / 8 % 2 == 1
    let hasMap := flags / 4 % 2 == 1
    let longAck := flags / 2 % 2 == 1
    let hasAck := flags % 2 == 1
    let ackLen := if !hasAck then 0 else if longAck then 8 else 4
    let dsnLen : Option Nat := if !hasMap then none else if longDsn then some 8 else some 4
    let checksum? : Option Bool :=
      match dsnLen with
      | none => if body.length == ackLen then some false else none
      | some n =>
        if body.length == ackLen + n + 6 then some false
        else if body.length == ackLen + n + 8 then some true
        else none
    match checksum? with
    | none => .error bad
    | some cksum =>
      let dataAck : Option Sequence :=
        if ackLen == 0 then none
        else if ackLen == 4 then some (.short (body.take 4))
        else some (.long (body.take 8))
      let mapping : Option Mapping :=
        match dsnLen with
        | none => none
        | some n =>
          let m := body.drop ackLen
          let dsn := if n == 4 then Sequence.short (m.take 4) else Sequence.long (m.take 8)
          let m2 := m.drop n
          some { dsn := dsn
                 subflowSeq := m2.take 4
                 dll := (m2.drop 4).take 2
                 checksum := if cksum then some ((m2.drop 6).take 2) else none }
      .ok (.dss { dataAck := dataAck, mapping := mapping, dataFin := dataFin })

/-- ADD_ADDR: flag E on the first byte's low nibble, then the Address ID,
    the address, maybe a port, and the HMAC unless this is an echo. -/
def parseAddAddr (low : Nat) (rest : Octets) (bad : Error) : Except Error Opt :=
  let echo := low % 2 == 1
  match rest with
  | [] => .error bad
  | aid :: body =>
    let hmacLen := if echo then 0 else 8
    let after := body.length - hmacLen
    let describe : Option (Bool × Bool) :=
      if after == 4 then some (false, false)
      else if after == 6 then some (false, true)
      else if after == 16 then some (true, false)
      else if after == 18 then some (true, true)
      else none
    match describe with
    | none => .error bad
    | some (v6, hasPort) =>
      if after + hmacLen != body.length then .error bad
      else
        let addrLen := if v6 then 16 else 4
        let address := if v6 then Addr.v6 (body.take 16) else Addr.v4 (body.take 4)
        let afterAddr := body.drop addrLen
        let port := if hasPort then some (afterAddr.take 2) else none
        let portLen := if hasPort then 2 else 0
        let hmac := if echo then none else some ((afterAddr.drop portLen).take 8)
        .ok (.addAddr { addressId := aid, address := address, port := port, hmac := hmac })

/-- MP_FAIL and MP_FASTCLOSE: Length 12, a reserved byte, then an 8-octet
    value. `isFail` picks which option is built. -/
def parseFailLike (isFail : Bool) (rest : Octets) (bad : Error) : Except Error Opt :=
  if rest.length == 9 then
    let value := (rest.drop 1).take 8
    .ok (if isFail then .fail value else .fastClose value)
  else .error bad

/-- Dispatches on the subtype `sub` (the first byte's top nibble) with the
    low nibble `low`, the bytes after the first byte `rest`, and the option's
    `length`. -/
def dispatch (sub low : Nat) (rest : Octets) (length : Nat) : Except Error Opt :=
  let bad := Error.length sub length
  match sub with
  | 0 => parseCapable low rest bad
  | 1 => parseJoin low rest bad
  | 2 => parseDss rest bad
  | 3 => parseAddAddr low rest bad
  | 4 => match rest with
         | [] => .error bad
         | _ => .ok (.removeAddr rest)
  | 5 => match rest with
         | [] => .ok (.prio (low % 2 == 1))
         | _ => .error bad
  | 6 => parseFailLike true rest bad
  | 7 => parseFailLike false rest bad
  | 8 => match rest with
         | [r] => .ok (.tcpRst (low % 2 == 1) r)
         | _ => .error bad
  | other => .error (.subtype other)

/-- Reads one option from its data, as `MptcpOption::parse` does. -/
def parse (data : Octets) : Except Error Opt :=
  let length := data.length + 2
  if length > MAX_LEN then .error (.tooLong length)
  else
    match data with
    | [] => .error .noSubtype
    | first :: rest => dispatch (first / 16) (first % 16) rest length

/-! ## Totality

    `parse` is a total function into `Except`, so every input gives a typed
    option or a typed error. -/

theorem parse_total (data : Octets) :
    (∃ o, parse data = .ok o) ∨ (∃ e, parse data = .error e) := by
  cases h : parse data with
  | ok o => exact Or.inl ⟨o, rfl⟩
  | error e => exact Or.inr ⟨e, rfl⟩

/-! ## Writing -/

/-- The octets of a sequence number, as stored. -/
def seqBytes : Sequence → Octets
  | .short v => v
  | .long v => v

/-- The data bytes of `keys`, after the flags byte. -/
def keysBytes : Keys → Octets
  | .absent => []
  | .sender k => k
  | .both s r => s ++ r
  | .data s r dll c => s ++ r ++ dll ++ (c.getD [])

/-- The DSS flags byte for `d`. -/
def dssFlags (d : Dss) : Nat :=
  (if d.dataFin then 16 else 0)
  + (match d.mapping with | some m => (match m.dsn with | .long _ => 8 | .short _ => 0) + 4 | none => 0)
  + (match d.dataAck with | some s => (match s with | .long _ => 2 | .short _ => 0) + 1 | none => 0)

/-- The mapping's bytes, after the Data ACK. -/
def mapBytes (m : Mapping) : Octets :=
  seqBytes m.dsn ++ m.subflowSeq ++ m.dll ++ (m.checksum.getD [])

/-- Appends the option's data, as `MptcpOption::write` does; errors where it
    does. The first byte's top nibble is the subtype. -/
def emit : Opt → Except Error Octets
  | .capable c =>
    if c.version > 15 || c.algorithms == 0 || c.algorithms > ALG_ALL then .error .unwritable
    else if c.version == 0 && !c.keys.hasKey then
      .error .unwritable
    else
      let flags := c.algorithms + b2n c.noNewSubflows * 32 + b2n c.extensibility * 64
        + b2n c.checksumRequired * 128
      .ok ((0 * 16 + c.version) :: flags :: keysBytes c.keys)
  | .join (.syn backup aid token random) =>
    .ok ((16 + b2n backup) :: aid :: (token ++ random))
  | .join (.synAck backup aid hmac random) =>
    .ok ((16 + b2n backup) :: aid :: (hmac ++ random))
  | .join (.ack hmac) => .ok (16 :: 0 :: hmac)
  | .dss d => .ok (32 :: dssFlags d :: ((d.dataAck.map seqBytes).getD [] ++ (d.mapping.map mapBytes).getD []))
  | .addAddr a =>
    let addrBytes := match a.address with | .v4 o => o | .v6 o => o
    .ok ((48 + b2n a.hmac.isNone) :: a.addressId ::
      (addrBytes ++ (a.port.getD []) ++ (a.hmac.getD [])))
  | .removeAddr ids =>
    if ids.length == 0 || ids.length > MAX_LEN - 3 then .error .unwritable
    else .ok (64 :: ids)
  | .prio backup => .ok [80 + b2n backup]
  | .fail v => .ok (96 :: 0 :: v)
  | .fastClose v => .ok (112 :: 0 :: v)
  | .tcpRst transient reason => .ok ((128 + b2n transient) :: [reason])

end Mptcp
