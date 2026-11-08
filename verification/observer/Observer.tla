------------------------------ MODULE Observer ------------------------------
(***************************************************************************)
(* One connection as the passive TCP observer follows it: the reassembly   *)
(* of each direction (Flow in src/stdlib/network/observer/flow.rs) and     *)
(* what goes up to its child (Observer in src/stdlib/network/observer.rs), *)
(* until the child has every event and is closed.                          *)
(*                                                                         *)
(* Model                 source (lines at the commit that adds this)       *)
(*   Seg                  Observer::segment 332 -> Flow::push 209           *)
(*     Deliver            Flow::deliver 441 (capped at the FIN)             *)
(*     Hold, Drop         push 258-285 (bounded by Limits::segments)        *)
(*     RecordFin          Flow::record_fin 356                              *)
(*     Drain              push 293-318 and Flow::drain_first 405            *)
(*     Mark               push 319-332 (the place of dropped bytes)         *)
(*     ReachFin           push 336-349                                      *)
(*     Reset              segment 486-501                                   *)
(*   LetGo                Observer::let_go 565 (Evicted, Replaced)          *)
(*   MakeRoom             Observer::make_room 617                           *)
(*   CaptureEnds          Observer::finish 661 and Flow::finish 191         *)
(*   Take, Closed         Observer::take_event 814                          *)
(*   CloseAbove           on_command, MuxOp::Close 787                      *)
(*                                                                         *)
(* Positions are unwrapped sequence positions of one direction, 0..N-1 for *)
(* the sender's bytes and N for its FIN.  The capture may lose, repeat,    *)
(* reorder and overlap segments.  The wire's 32-bit wrap and the byte      *)
(* values themselves are left to the Kani harnesses in kani/, which run    *)
(* the real Flow.  The byte bound (Limits::buffered) works as the segment *)
(* bound does and is left out; credit is left out: the child takes events  *)
(* in order whenever it likes.                                             *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
  N,            \* bytes each sender sends before its FIN
  SegLimit,     \* Limits::segments
  MaxLen,       \* the longest captured payload
  \* Each TRUE for the code.  FALSE keeps a rule as an endpoint has it, or
  \* weakens it.
  Passive,          \* the observer never sends
  TrimDelivered,    \* push skips bytes already delivered
  FinInOrder,       \* a FIN ends its direction only once reached
  HolesTruncate,    \* the capture's end with a hole is Truncated
  EndOnlyOpen,      \* let_go ends only directions not ended
  EvictEnds,        \* make_room puts an Evicted end in place of what it drops
  FinishCloses      \* finish closes the child once its events are taken

Dirs == {"F", "R"}
NoFin == N + 1
Causes == {"Fin", "Reset", "Truncated", "Evicted", "Replaced", "Finalized"}

VARIABLES
  pos,      \* Flow::position
  held,     \* Flow::held: records [at, len, data]; data FALSE is a marker
  fin,      \* Flow::fin, NoFin when none was seen
  ended,    \* Connection::ended
  pending,  \* Output::pending: events waiting for the child
  closing,  \* Output::closing
  log,      \* what the child took, per direction
  closed,   \* how many times Closed went up
  detached, \* the connection let go of its child (Connection::child None)
  finished, \* the capture ended
  sent,     \* packets the observer put on the wire
  above     \* the layer above closed the child

vars == <<pos, held, fin, ended, pending, closing, log, closed, detached,
          finished, sent, above>>

Data(d, from, to) == [k |-> "data", d |-> d, from |-> from, to |-> to]
Gap(d, from, to) == [k |-> "gap", d |-> d, from |-> from, to |-> to]
\* `holed` is bookkeeping of the model: the capture ended with bytes of the
\* direction known to be missing.
End(d, c) == [k |-> "end", d |-> d, cause |-> c, holed |-> FALSE]
OtherDir(d) == IF d = "F" THEN "R" ELSE "F"

Init ==
  /\ pos = [d \in Dirs |-> 0] /\ held = [d \in Dirs |-> {}]
  /\ fin = [d \in Dirs |-> NoFin] /\ ended = [d \in Dirs |-> FALSE]
  /\ pending = << >> /\ closing = FALSE
  /\ log = [d \in Dirs |-> << >>] /\ closed = 0
  /\ detached = FALSE /\ finished = FALSE /\ sent = 0 /\ above = FALSE

Min(S) == CHOOSE x \in S : \A y \in S : x <= y
Keys(h) == {r.at : r \in h}
DataKeys(h) == {r.at : r \in {x \in h : x.data}}

(***************************************************************************)
(* Flow::push as one function of the direction's state and one segment of  *)
(* payload [s, s+len) with a FIN after it or not.  It returns the new      *)
(* state and the steps it gives up, in order.                              *)
(***************************************************************************)

\* deliver: in-order bytes from the position, up to the FIN.
Deliver(st, s, len) ==
  LET to == IF s + len < st.fin THEN s + len ELSE st.fin
  IN IF to > st.pos
     THEN [st EXCEPT !.pos = to, !.out = Append(st.out, Data(st.d, st.pos, to))]
     ELSE st

\* drain_first: the first held entry starts at or before the position.
DrainFirst(st) ==
  LET k == Min(Keys(st.held))
      r == CHOOSE x \in st.held : x.at = k
      rest == [st EXCEPT !.held = st.held \ {r}]
  IN IF r.data THEN Deliver(rest, k, r.len)
     ELSE IF k + r.len > rest.pos
          THEN [rest EXCEPT !.pos = k + r.len,
                            !.out = Append(rest.out, Gap(st.d, rest.pos, k + r.len))]
          ELSE rest

\* A gap joined to one just before it, as `gap` does.
AddGap(out, d, from, to) ==
  IF Len(out) > 0 /\ out[Len(out)].k = "gap" /\ out[Len(out)].to = from
  THEN [out EXCEPT ![Len(out)].to = to]
  ELSE Append(out, Gap(d, from, to))

\* The drain loop, at most SegLimit + 1 rounds (each takes an entry).
RECURSIVE Drain(_, _, _)
Drain(st, overflow, fuel) ==
  IF fuel = 0 \/ st.held = {} THEN st
  ELSE LET k == Min(Keys(st.held)) IN
    IF k > st.pos
    THEN IF ~overflow \/ DataKeys(st.held) = {} THEN st
         ELSE LET t == Min(DataKeys(st.held))
                  kept == {r \in st.held : r.at >= t}
                  jumped == [st EXCEPT !.held = kept, !.pos = t,
                                       !.out = AddGap(st.out, st.d, st.pos, t)]
              IN Drain(DrainFirst(jumped), FALSE, fuel - 1)
    ELSE Drain(DrainFirst(st), overflow, fuel - 1)

Push(d, s, len, hasFin) ==
  LET st0 == [d |-> d, pos |-> pos[d], held |-> held[d], fin |-> fin[d],
              out |-> << >>]
      \* The payload: delivered, held, or dropped.
      inOrder == s <= st0.pos
      late == st0.fin # NoFin /\ s >= st0.fin
      room == Cardinality(st0.held) < SegLimit
      st1 == IF len = 0 THEN st0
             ELSE IF inOrder
                  THEN IF TrimDelivered THEN Deliver(st0, st0.pos, s + len - st0.pos)
                       ELSE [st0 EXCEPT !.pos = s + len,
                                        !.out = Append(st0.out, Data(d, s, s + len))]
             ELSE IF late THEN st0
             ELSE IF room
                  THEN [st0 EXCEPT !.held = {r \in st0.held : r.at # s}
                                            \cup {[at |-> s, len |-> len, data |-> TRUE]}]
             ELSE st0
      overflow == len > 0 /\ ~inOrder /\ ~late /\ ~room
      \* record_fin: a FIN at s + len, not behind the position, the first.
      fat == s + len
      st2 == IF hasFin /\ fat >= st1.pos /\ st1.fin = NoFin
             THEN [st1 EXCEPT !.fin = fat,
                              !.held = {r \in st1.held : r.at < fat}]
             ELSE st1
      st3 == Drain(st2, overflow, SegLimit + 1)
      \* The place of the dropped bytes, kept as a marker.
      st4 == IF overflow /\ s > st3.pos /\ Cardinality(st3.held) < SegLimit
                /\ s \notin Keys(st3.held)
             THEN [st3 EXCEPT !.held = st3.held \cup {[at |-> s, len |-> len, data |-> FALSE]}]
             ELSE st3
      \* With FinInOrder FALSE, a FIN ends the direction when it is seen.
      reached == IF FinInOrder THEN st4.fin = st4.pos ELSE st4.fin # NoFin
  IN [st |-> st4, fin |-> reached]

-----------------------------------------------------------------------------
\* Queue events for the child while it is attached.
Queue(evs) == IF detached THEN pending ELSE pending \o evs

Holed(d) == held[d] # {} \/ (fin[d] # NoFin /\ fin[d] > pos[d])

\* A captured segment in direction d: payload [s, s+len), perhaps a FIN
\* after it (only the sender's own FIN, at N), perhaps a RST.
Seg(d, s, len, hasFin, rst) ==
  /\ ~finished
  /\ IF ended[d]
     THEN \* What comes for an ended direction is late; a RST still ends
          \* the other one.
          LET evs == IF rst THEN [i \in 1..(IF ended[OtherDir(d)] THEN 0 ELSE 1) |->
                                    End(OtherDir(d), "Reset")]
                     ELSE << >>
          IN /\ ended' = [x \in Dirs |-> ended[x] \/ rst]
             /\ held' = IF rst THEN [x \in Dirs |-> {}] ELSE held
             /\ pending' = Queue(evs)
             /\ closing' = (closing \/ (~detached /\ ended' = [x \in Dirs |-> TRUE]))
             /\ UNCHANGED <<pos, fin>>
     ELSE
       LET p == Push(d, s, len, hasFin)
           evs1 == p.st.out \o (IF p.fin THEN << End(d, "Fin") >> ELSE << >>)
           e1 == [ended EXCEPT ![d] = p.fin]
           resets == IF rst THEN SelectSeq(<< End("F", "Reset"), End("R", "Reset") >>,
                                           LAMBDA e : ~e1[e.d])
                     ELSE << >>
           e2 == IF rst THEN [x \in Dirs |-> TRUE] ELSE e1
       IN /\ pos' = [pos EXCEPT ![d] = p.st.pos]
          /\ fin' = [fin EXCEPT ![d] = p.st.fin]
          /\ held' = [x \in Dirs |-> IF e2[x] THEN {}
                                     ELSE IF x = d THEN p.st.held ELSE held[x]]
          /\ ended' = e2
          /\ pending' = Queue(evs1 \o resets)
          /\ closing' = (closing \/ (~detached /\ e2 = [x \in Dirs |-> TRUE]))
  /\ UNCHANGED <<log, closed, detached, finished, sent, above>>

\* An endpoint would acknowledge what it put in order.  Only with Passive
\* FALSE.
Acknowledge ==
  /\ ~Passive /\ \E d \in Dirs : pos[d] > 0
  /\ sent' = sent + 1
  /\ UNCHANGED <<pos, held, fin, ended, pending, closing, log, closed, detached, finished, above>>

\* let_go: the connection is evicted for the connection bound, or replaced
\* by a new SYN on its endpoints.
LetGo(cause) ==
  /\ ~detached
  /\ LET evs == SelectSeq(<< End("F", cause), End("R", cause) >>,
                          LAMBDA e : ~EndOnlyOpen \/ ~ended[e.d])
     IN /\ pending' = pending \o evs
  /\ ended' = [x \in Dirs |-> TRUE] /\ held' = [x \in Dirs |-> {}]
  /\ closing' = TRUE /\ detached' = TRUE
  /\ UNCHANGED <<pos, fin, log, closed, finished, sent, above>>

Delivered(d) == \E i \in 1..Len(log[d]) : log[d][i].k = "end"

\* make_room: the child waited too long for its events; what waits is
\* dropped and each direction whose end did not go up ends Evicted.
MakeRoom ==
  /\ ~detached /\ pending # << >>
  /\ pending' = IF EvictEnds
                  THEN SelectSeq(<< End("F", "Evicted"), End("R", "Evicted") >>,
                                 LAMBDA e : ~Delivered(e.d))
                  ELSE << >>
  /\ ended' = [x \in Dirs |-> TRUE] /\ held' = [x \in Dirs |-> {}]
  /\ closing' = TRUE /\ detached' = TRUE
  /\ UNCHANGED <<pos, fin, log, closed, finished, sent, above>>

\* finish for one direction: held bytes past their holes, then the end.
RECURSIVE FinishDrain(_, _)
FinishDrain(st, fuel) ==
  IF fuel = 0 \/ st.held = {} THEN st
  ELSE LET k == Min(Keys(st.held))
           st1 == IF k > st.pos
                  THEN [st EXCEPT !.pos = k, !.out = AddGap(st.out, st.d, st.pos, k)]
                  ELSE st
       IN FinishDrain(DrainFirst(st1), fuel - 1)

FinishDir(d) ==
  IF ended[d] THEN << >>
  ELSE LET st == FinishDrain([d |-> d, pos |-> pos[d], held |-> held[d],
                              fin |-> fin[d], out |-> << >>], SegLimit + 1)
       IN st.out \o << [k |-> "end", d |-> d, holed |-> Holed(d),
                       cause |-> IF Holed(d) /\ HolesTruncate THEN "Truncated"
                                 ELSE "Finalized"] >>

CaptureEnds ==
  /\ ~finished
  /\ finished' = TRUE
  /\ IF detached THEN UNCHANGED <<pending, closing, ended, held>>
     ELSE /\ pending' = pending \o FinishDir("F") \o FinishDir("R")
          /\ ended' = [x \in Dirs |-> TRUE] /\ held' = [x \in Dirs |-> {}]
          /\ closing' = FinishCloses
  /\ UNCHANGED <<pos, fin, log, closed, detached, sent, above>>

\* The child takes the next event; Closed goes up once nothing waits.
Take ==
  /\ closed = 0 /\ pending # << >>
  /\ log' = [log EXCEPT ![Head(pending).d] = Append(@, Head(pending))]
  /\ pending' = Tail(pending)
  /\ UNCHANGED <<pos, held, fin, ended, closing, closed, detached, finished, sent, above>>

Closed ==
  /\ closed = 0 /\ closing /\ pending = << >>
  /\ closed' = 1
  /\ UNCHANGED <<pos, held, fin, ended, pending, closing, log, detached, finished, sent, above>>

\* The layer above closes the child: it gets nothing more.
CloseAbove ==
  /\ closed = 0 /\ ~detached
  /\ closed' = 1 /\ pending' = << >> /\ detached' = TRUE /\ above' = TRUE
  /\ ended' = [x \in Dirs |-> TRUE] /\ held' = [x \in Dirs |-> {}]
  /\ UNCHANGED <<pos, fin, closing, log, finished, sent>>

Next ==
  \/ \E d \in Dirs, s \in 0..(N - 1), len \in 0..MaxLen, f \in BOOLEAN, r \in BOOLEAN :
       /\ s + len <= N
       /\ f => s + len = N
       /\ Seg(d, s, len, f, r)
  \/ Acknowledge \/ LetGo("Evicted") \/ LetGo("Replaced") \/ MakeRoom
  \/ CaptureEnds \/ Take \/ Closed

\* The capture ends and the child takes what it is given.
Spec == Init /\ [][Next \/ CloseAbove]_vars
        /\ WF_vars(CaptureEnds) /\ WF_vars(Take) /\ WF_vars(Closed)

-----------------------------------------------------------------------------
\* The observer never puts a packet on the wire.
NeverSends == sent = 0

\* In each direction, what the child got is contiguous from its first
\* position: every position appears once, in data or inside a gap, never
\* twice, and no data or gap passes the FIN.
Contiguous ==
  \A d \in Dirs :
    LET l == SelectSeq(log[d], LAMBDA e : e.k # "end") IN
    \A i \in 1..Len(l) :
      /\ l[i].from < l[i].to /\ l[i].to <= N
      /\ IF i = 1 THEN l[i].from = 0 ELSE l[i].from = l[i - 1].to

\* Each direction ends once, and nothing follows its end.
EndOnce ==
  \A d \in Dirs :
    \A i \in 1..Len(log[d]) : log[d][i].k = "end" => i = Len(log[d])

\* A clean end only at the sender's FIN, reached in order: every position
\* before it was delivered or inside a gap.
FinIsReached ==
  \A d \in Dirs :
    \A i \in 1..Len(log[d]) :
      (log[d][i].k = "end" /\ log[d][i].cause = "Fin")
        => /\ i > 1 /\ log[d][i - 1].k # "end" /\ log[d][i - 1].to = N

\* A capture that ends before a direction's FIN was reached never ends it
\* clean, and one that ends with bytes of it known to be missing (a hole
\* before held bytes, or before a FIN seen) says Truncated, not
\* Finalized.
CutShortIncomplete ==
  \A d \in Dirs :
    \A i \in 1..Len(log[d]) :
      log[d][i].k = "end" /\ log[d][i].holed => log[d][i].cause = "Truncated"

\* The child is closed only once both
\* directions' ends reached it, unless it closed itself.
ClosedAfterEnds ==
  (closed = 1 /\ ~above) => \A d \in Dirs : Delivered(d)

\* Every child is eventually closed: the capture ends.
EventuallyClosed == <>(closed = 1)
=============================================================================
