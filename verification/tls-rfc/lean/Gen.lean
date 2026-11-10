/-
  Vectors for the differential tests of the vendored rustls. Every expected value is computed
  by the definitions whose properties `TlsRecord/*.lean` proves:

  * `header.txt`: `Header.check` and `Header.isProtected`, over every combination of a few
    content types, legacy versions and lengths at each limit, in each read state. Replayed by
    `rustls/src/budget/record_vectors.rs`.
  * `nonce.txt`: `Nonce.run` over random sequences of records, KeyUpdate requests and replies,
    each with a budget outcome. Replayed by `rustls/src/common_state/nonce_vectors.rs`.

  Usage: `lake exe gen <dir> <seed>`. The output depends only on the seed (`header.txt` not at
  all).

  Line formats, one case per line, fields separated by spaces:

  * header: `<state> <type> <version> <length> <verdict> <protected>`, with state `plain`,
    `tls12` or `tls13`, numbers in decimal, verdict one of `accept`, `record_overflow`,
    `unexpected_type`, `bad_version`, `empty_fragment`, and protected `0` or `1`.
  * nonce: `<ops> | <wire> | <failed> <used>`: ops are `send.<o>`, `request.<o>` or
    `reply.<o>` with o one of `queued`, `refused`, `dropped`; the wire is the records queued, oldest
    first, as `<key>.<seq>.<kind>` with kind `data` or `key_update` (`-` for none); failed is `0`
    or `1`; used is how many records were encrypted.
-/
import TlsRecord.Header
import TlsRecord.Nonce

open TlsRecord

/-! ## Randomness (splitmix64) -/

structure Rng where
  s : UInt64

def Rng.next (r : Rng) : UInt64 × Rng :=
  let s := r.s + 0x9E3779B97F4A7C15
  let z := (s ^^^ (s >>> 30)) * 0xBF58476D1CE4E5B9
  let z := (z ^^^ (z >>> 27)) * 0x94D049BB133111EB
  (z ^^^ (z >>> 31), ⟨s⟩)

abbrev G := StateM Rng

def rNat (n : Nat) : G Nat := do
  if n == 0 then return 0
  return (← modifyGet fun r => r.next).toNat % n

/-! ## header.txt -/

def protName : Prot → String
  | .plain => "plain"
  | .tls12 => "tls12"
  | .tls13 => "tls13"

def verdictName : Verdict → String
  | .accept => "accept"
  | .recordOverflow => "record_overflow"
  | .unexpectedType => "unexpected_type"
  | .badVersion => "bad_version"
  | .emptyFragment => "empty_fragment"

def headerLines : List String := Id.run do
  let types := [20, 21, 22, 23, 24, 0, 25, 99, 255]
  let versions := [0x0301, 0x0303, 0x03ff, 0x0200, 0x0403]
  let b := 2 ^ 14
  let lens := [0, 1, 2, b - 1, b, b + 1, b + 255, b + 256, b + 257, b + 2047, b + 2048, b + 2049,
    0xffff]
  let mut out := #[]
  for p in [Prot.plain, .tls12, .tls13] do
    for t in types do
      for v in versions do
        for n in lens do
          let h : Header := ⟨t, v, n⟩
          let prot := if isProtected p t then "1" else "0"
          out := out.push s!"{protName p} {t} {v} {n} {verdictName (check p h)} {prot}"
  return out.toList

/-! ## nonce.txt -/

open Nonce in
def outcomeName : Outcome → String
  | .queued => "queued"
  | .refused => "refused"
  | .dropped => "dropped"

open Nonce in
def opName : Op → String
  | .send o => s!"send.{outcomeName o}"
  | .request o => s!"request.{outcomeName o}"
  | .reply o => s!"reply.{outcomeName o}"

open Nonce in
def recName (r : Rec) : String :=
  let k := match r.kind with
    | .data => "data"
    | .keyUpdate => "key_update"
  s!"{r.epoch}.{r.seq}.{k}"

open Nonce in
def rOutcome : G Outcome := do
  let n ← rNat 10
  return if n < 7 then .queued else if n < 9 then .refused else .dropped

open Nonce in
def rOp : G Op := do
  let n ← rNat 10
  let o ← rOutcome
  return if n < 6 then .send o else if n < 8 then .request o else .reply o

open Nonce in
def nonceLine : G String := do
  let len := 1 + (← rNat 12)
  let mut ops := #[]
  for _ in [0:len] do
    ops := ops.push (← rOp)
  let st := run ops.toList
  let wire := st.wire.reverse.map recName
  let wire := if wire.isEmpty then "-" else " ".intercalate wire
  let failed := if st.failed then "1" else "0"
  return s!"{" ".intercalate (ops.toList.map opName)} | {wire} | {failed} {st.used.length}"

def nonceLines (seed : Nat) (count : Nat) : List String :=
  let go : G (List String) := do
    let mut out := #[]
    for _ in [0:count] do
      out := out.push (← nonceLine)
    return out.toList
  (go.run ⟨seed.toUInt64⟩).1

def main (args : List String) : IO UInt32 := do
  match args with
  | [dir, seed] =>
    let some seed := seed.toNat? | IO.eprintln "seed must be a number"; return 2
    IO.FS.createDirAll dir
    IO.FS.writeFile (dir ++ "/header.txt") ("\n".intercalate headerLines ++ "\n")
    IO.FS.writeFile (dir ++ "/nonce.txt") ("\n".intercalate (nonceLines seed 2000) ++ "\n")
    return 0
  | _ =>
    IO.eprintln "usage: gen <dir> <seed>"
    return 2
