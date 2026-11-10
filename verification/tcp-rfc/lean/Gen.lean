import TcpRfc

/-!
Reference vectors for `smoltcp/src/socket/tcp/rfc_vectors.rs`: each line is
a connection record and a segment, then the record and reply `arrive` gives
with smoltcp's departures. `gen <dir> <seed>` writes `<dir>/arrive.txt`:
every boundary case, then random cases drawn from the seed.

A line is whitespace-separated numbers:

    state iss irs una nxt rcvNxt wnd synSent finSent peerFin passive
    seq hasAck ack ctl text
    state' una' nxt' rcvNxt' wnd' peerFin' passive'
    reply r1 r2

States count from 0 in the order of `State`, controls in the order of
`Ctl`, replies in the order of `Reply` (`r1`, `r2` are its fields, 0 when
absent). Booleans are 0 or 1.
-/

open TcpRfc

def stateNum : State → Nat
  | .closed => 0 | .listen => 1 | .synSent => 2 | .synReceived => 3
  | .established => 4 | .finWait1 => 5 | .finWait2 => 6 | .closeWait => 7
  | .closing => 8 | .lastAck => 9 | .timeWait => 10

def ctlNum : Ctl → Nat
  | .none => 0 | .syn => 1 | .fin => 2 | .rst => 3

def replyNums : Reply → List Nat
  | .none => [0, 0, 0]
  | .ack s a => [1, s.toNat, a.toNat]
  | .challenge s a => [2, s.toNat, a.toNat]
  | .rst s => [3, s.toNat, 0]
  | .rstAck a => [4, 0, a.toNat]
  | .synAck s a => [5, s.toNat, a.toNat]

def b2n (b : Bool) : Nat := if b then 1 else 0

def line (t : Tcb) (s : Segment) : String :=
  let (t', r) := arrive .smoltcp t s
  let nums :=
    [stateNum t.state, t.iss.toNat, t.irs.toNat, t.sndUna.toNat, t.sndNxt.toNat,
     t.rcvNxt.toNat, t.rcvWnd, b2n t.synSent, b2n t.finSent, b2n t.peerFin, b2n t.passive,
     s.seq.toNat, b2n s.ack.isSome, (s.ack.getD 0).toNat, ctlNum s.ctl, s.text,
     stateNum t'.state, t'.sndUna.toNat, t'.sndNxt.toNat, t'.rcvNxt.toNat, t'.rcvWnd,
     b2n t'.peerFin, b2n t'.passive] ++ replyNums r
  " ".intercalate (nums.map toString)

/-- The initial sequence number smoltcp's test interface gives every
    connection (`LOCAL_SEQ`, -34801502 as an unsigned number): a socket in
    LISTEN takes it for its SYN-ACK. -/
def testIss : Seq := 4260165794

def before (a : Seq) (n : Nat) : Seq := a - UInt32.ofNat n

/-- A record in state `st`: our numbers start at `una` with `n` octets of
    text in flight (all of it sent), the peer's at `rcv` with a window of
    `wnd`. -/
def record (st : State) (una rcv : Seq) (n wnd : Nat) (passive : Bool) : Tcb :=
  let base : Tcb := {
    state := st, iss := before una 1, irs := before rcv 1, sndUna := una,
    sndNxt := adv una n, rcvNxt := rcv, rcvWnd := wnd, synSent := true, finSent := false,
    peerFin := false, passive := passive }
  match st with
  | .listen =>
    { base with
      iss := testIss, sndUna := 0, sndNxt := 0, rcvNxt := 0, irs := 0,
      synSent := false, passive := true }
  | .synSent => { base with iss := una, sndNxt := adv una 1, rcvNxt := 0, irs := 0, passive := false }
  | .synReceived => { base with iss := una, sndNxt := adv una 1 }
  | .finWait1 | .closing | .lastAck =>
      { base with
        sndNxt := adv una (n + 1), finSent := true,
        peerFin := st == .closing || st == .lastAck }
  | .finWait2 => { base with sndNxt := una, finSent := true }
  | .timeWait => { base with sndNxt := una, finSent := true, peerFin := true }
  | .closeWait => { base with peerFin := true }
  | _ => base

def allStates : List State :=
  [.closed, .listen, .synSent, .synReceived, .established, .finWait1, .finWait2,
   .closeWait, .closing, .lastAck, .timeWait]

def allCtls : List Ctl := [.none, .syn, .fin, .rst]

/-- Sequence numbers at the boundaries: 0, 2^31 and 2^32 - 1, and their
    neighbours. -/
def edges : List Seq := [0, 1, 2147483647, 2147483648, 2147483649, 4294967294, 4294967295]

/-- Acknowledgment numbers around SND.UNA and SND.NXT, and half the space
    away from each. -/
def acks (t : Tcb) : List (Option Seq) :=
  let u := t.sndUna
  let x := t.sndNxt
  [none, some (before u 1), some u, some (adv u 1), some x, some (adv x 1),
   some (adv u (H - 1)), some (adv u H), some (adv u (H + 1)), some (adv x H)]

/-- Sequence numbers around the receive window's edges, half the space
    away, and the two places where a FIN after `text` octets lands at
    RCV.NXT and at the right edge. -/
def seqs (t : Tcb) (text : Nat) : List Seq :=
  let r := t.rcvNxt
  let w := t.rcvWnd
  [before r 2, before r 1, r, adv r 1, before (adv r w) 1, adv r w, adv r (w + 1),
   adv r (H - 1), adv r H, adv r (H + 1), before r text, before (adv r w) text]

def step (n : Nat) : Nat := (n * 6364136223846793005 + 1442695040888963407) % 18446744073709551616

def draw (s : Nat) (bound : Nat) : Nat := (s / 4294967296) % bound

def boundary (emit : String → IO Unit) : IO Unit := do
  -- Pairs (SND.UNA, RCV.NXT) that put each side on a boundary.
  let pairs : List (Seq × Seq) :=
    [(0, 4294967295), (4294967295, 2147483648), (2147483647, 0), (2147483648, 2147483647),
     (4294967294, 1), (1234567, 4294967290)]
  for (u, r) in pairs do
    for st in allStates do
      for n in (if st == .finWait2 || st == .timeWait then [0] else [0, 3]) do
        for wnd in [0, 1, 4] do
          for passive in (if st == .synReceived then [true, false] else [true]) do
            let t := record st u r n wnd passive
            for text in [0, 1, 2, wnd, wnd + 1].eraseDups do
              for seq in seqs t text do
                for ack in acks t do
                  for ctl in allCtls do
                    emit (line t { seq, ack, ctl, text })

def random (seed count : Nat) (emit : String → IO Unit) : IO Unit := do
  let mut s := step (seed + 1)
  for _ in [:count] do
    s := step s
    let st := allStates[draw s allStates.length]!
    s := step s
    let u : Seq := if draw s 4 == 0 then edges[draw (step s) edges.length]! else UInt32.ofNat (draw (step s) M)
    s := step (step s)
    let r : Seq := if draw s 4 == 0 then edges[draw (step s) edges.length]! else UInt32.ofNat (draw (step s) M)
    s := step (step s)
    let n := if st == .finWait2 || st == .timeWait then 0 else draw s 9
    s := step s
    let wnd := if draw s 5 == 0 then 0 else draw (step s) 64
    s := step (step s)
    let t := record st u r n wnd (draw s 2 == 0)
    s := step s
    let text := if draw s 3 == 0 then 0 else draw (step s) (wnd + 6)
    s := step (step s)
    let near := seqs t text
    let seq := if draw s 2 == 0 then near[draw (step s) near.length]!
      else adv t.rcvNxt (draw (step s) (2 * wnd + 8)) - UInt32.ofNat (wnd + 4)
    s := step (step s)
    let as := acks t
    let ack := if draw s 3 == 0 then some (UInt32.ofNat (draw (step s) M))
      else as[draw (step s) as.length]!
    s := step (step s)
    let ctl := allCtls[draw s 4]!
    emit (line t { seq, ack, ctl, text })

def main (args : List String) : IO UInt32 := do
  let (dir, seed) ← match args with
    | [d, s] => pure (d, s.toNat!)
    | [d] => pure (d, 1)
    | _ => do IO.eprintln "usage: gen <dir> [seed]"; return 1
  let path := System.FilePath.mk dir / "arrive.txt"
  let h ← IO.FS.Handle.mk path .write
  let count ← IO.mkRef (0 : Nat)
  let emit (l : String) : IO Unit := do h.putStrLn l; count.modify (· + 1)
  boundary emit
  random seed 50000 emit
  h.flush
  IO.println s!"arrive.txt: {← count.get} vectors"
  return 0
