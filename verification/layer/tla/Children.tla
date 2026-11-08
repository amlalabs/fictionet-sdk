----------------------------- MODULE Children -----------------------------
(* Children<B, K> on a multiplexed connection (src/stdlib/layer/          *)
(* children.rs), with the mux below it keeping its children in Slots      *)
(* (carrier.rs): credit both ways, the queue of commands for the mux with *)
(* its places reserved for connection control and credit, children        *)
(* opened, refused, failed and closed, and slots given to successors.     *)
(*                                                                       *)
(* A child id is <<slot, generation>>. The mux is any mux that keeps its  *)
(* children in Slots: it opens a child in any free slot, sends a child's  *)
(* events, grants a child command credit, closes a child when its peer    *)
(* resets it, and takes Children's commands, applying each to the child   *)
(* whose id it names. Each child's layer is abstract: it may take its     *)
(* next event or refuse it, hand over a command of any cost, or fail.     *)
(* Every Children entry point is one atomic action, as each is one        *)
(* synchronous call in Rust; the mux and the layer above act between      *)
(* calls in any order.                                                    *)
(*                                                                       *)
(* Source correspondence:                                                *)
(*   Opened, MuxSend, MuxCredit, MuxPeerClose: Children::on_event            *)
(*   OfferControl: Children::on_command                                    *)
(*   LateResult: Children::on_timer and Children::on_done                    *)
(*   Advance, Visit: Children::advance and Children::visit_child             *)
(*   MuxTake: Children::take_command and Slots generation checks             *)
(*   ExtractWork: Children::take_work and Jobs::take                         *)
(*   PollWork, FinishWork: WorkOwner and Jobs::poll                           *)
(*   MuxWritten, Release: urgent slot and Chunk credit-return lease          *)
(*                                                                       *)
(* Flags keep a part of the code as it is (TRUE) or break it (FALSE):    *)
(*   CheckOverrun        an event past its child's credit is an Overrun  *)
(*   CheckCommandCredit  a command waits for the mux's credit            *)
(*   ReserveForControl   children's commands leave R places free         *)
(*   MuxChecksGeneration Slots compare the generation of an id           *)
(*   KeyByWholeId        Children keys its children by the whole id      *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS NS,          \* the mux's slots
          G,           \* the last generation a slot may reach
          Limit,       \* Children::new's `limit`
          W,           \* Children::new's `window`
          Q, R,        \* QUEUE and RESERVE
          MaxCredit,   \* the most command credit the mux has out per child
          Costs,       \* what a child's command may cost
          Stalled,     \* children's layers never take an event
          HonestMux,   \* the mux sends events only within credit
          CheckWorkOwnership, CheckUrgent, CheckJobLimit, JobLimit,
          Readiness,    \* retained buffers and completion traffic
          MayFail,     \* children's layers may fail
          Control,     \* the layer above sends control commands
          CheckOverrun, CheckCommandCredit, ReserveForControl,
          MuxChecksGeneration, KeyByWholeId

Slots == 1..NS
Ids == Slots \X (0..G)
NoId == <<0, 0>>
Key(id) == id[1] * (G + 1) + id[2]
Max0(n) == IF n < 0 THEN 0 ELSE n

VARIABLES mlive, mgen, mEv, mCmd,   \* the mux's slots
          kids,                     \* Children's children, by id
          down,                     \* Children::down, its commands for the mux
          turn,                     \* Children::turn
          ctrlPending,              \* the layer above holds a control command
          misdelivered, overspent, overrun, jobs, polledClosed
vars == <<mlive, mgen, mEv, mCmd, kids, down, turn, ctrlPending,
          misdelivered, overspent, overrun, jobs, polledClosed>>

Dead == [live |-> FALSE, granted |-> 0, owed |-> 0, inbox |-> 0,
         credit |-> 0, outbox |-> 0, held |-> 0, empty |-> 0, waiting |-> FALSE, urgent |-> FALSE]
Fresh == [Dead EXCEPT !.live = TRUE, !.owed = W]   \* Children
Cmd(op, id, n) == [op |-> op, id |-> id, n |-> n]
Live(ks) == {id \in Ids : ks[id].live}
SendRoom == IF ReserveForControl THEN Q - R ELSE Q
\* The child in a slot that the mux would reach with `id`.
Current(id) == <<id[1], mgen[id[1]]>>

Init == /\ mlive = [s \in Slots |-> FALSE]
        /\ mgen = [s \in Slots |-> 0]
        /\ mEv = [s \in Slots |-> 0]
        /\ mCmd = [s \in Slots |-> 0]
        /\ kids = [id \in Ids |-> Dead]
        /\ down = <<>>
        /\ turn = NoId
        /\ ctrlPending = FALSE
        /\ jobs = {} /\ polledClosed = FALSE
        /\ misdelivered = FALSE /\ overspent = FALSE /\ overrun = FALSE

---------------------------------------------------------------------------
(* The mux: events up to Children.                                         *)

\* The mux opens a child in a free slot (Slots::insert) and hands up its
\* handle; Children makes its layer, or closes it at once at the limit.
Opened(s) ==
  LET id == <<s, mgen[s]>> IN
  /\ ~overrun /\ ~mlive[s] /\ mgen[s] <= G
  /\ mlive' = [mlive EXCEPT ![s] = TRUE]
  /\ mEv' = [mEv EXCEPT ![s] = 0] /\ mCmd' = [mCmd EXCEPT ![s] = 0]
  /\ IF Cardinality(Live(kids)) >= Limit
       THEN down' = Append(down, Cmd("Close", id, 0)) /\ UNCHANGED kids
       ELSE kids' = [kids EXCEPT ![id] = Fresh] /\ UNCHANGED down
  /\ UNCHANGED <<mgen, turn, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed>>

\* The mux sends a child an event of one credit unit.
MuxSend(s) ==
  LET id == <<s, mgen[s]>>
      kid == kids[id] IN
  /\ ~overrun /\ mlive[s] /\ (mEv[s] >= 1 \/ ~HonestMux)
  /\ (~Readiness \/ kid.inbox + kid.empty < Q)
  /\ mEv' = [mEv EXCEPT ![s] = Max0(mEv[s] - 1)]
  /\ IF ~kid.live
       THEN UNCHANGED <<kids, overrun, jobs, polledClosed>>   \* a child already gone
     ELSE IF kid.granted < 1 /\ CheckOverrun
       THEN overrun' = TRUE /\ UNCHANGED kids
     ELSE /\ kids' = [kids EXCEPT ![id].granted = Max0(kid.granted - 1),
                                  ![id].inbox = kid.inbox + 1]
          /\ UNCHANGED overrun
  /\ UNCHANGED <<mlive, mgen, mCmd, down, turn, ctrlPending, misdelivered, overspent, jobs, polledClosed>>

\* The mux lets a child send one more credit unit, within its window.
MuxCredit(s) ==
  LET id == <<s, mgen[s]>> IN
  /\ ~overrun /\ mlive[s] /\ mCmd[s] < MaxCredit
  /\ mCmd' = [mCmd EXCEPT ![s] = mCmd[s] + 1]
  /\ kids' = IF kids[id].live THEN [kids EXCEPT ![id].credit = kids[id].credit + 1]
                              ELSE kids
  /\ UNCHANGED <<mlive, mgen, mEv, down, turn, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed>>

\* The peer resets a child: the mux removes it (Slots::remove, a new
\* generation for the slot) and says Closed.
MuxPeerClose(s) ==
  LET id == <<s, mgen[s]>> IN
  /\ ~overrun /\ mlive[s]
  /\ mlive' = [mlive EXCEPT ![s] = FALSE]
  /\ mgen' = [mgen EXCEPT ![s] = mgen[s] + 1]
  /\ kids' = [kids EXCEPT ![id] = Dead]
  /\ UNCHANGED <<mEv, mCmd, down, turn, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed>>

---------------------------------------------------------------------------
(* The mux takes Children's next command and applies it to the child its  *)
(* id names, if Slots finds one.                                          *)

MuxTake ==
  LET c == Head(down)
      s == c.id[1]
      found == c.op # "Control" /\ mlive[s] /\ (mgen[s] = c.id[2] \/ ~MuxChecksGeneration)
      stale == c.op # "Control" /\ mgen[s] # c.id[2] IN
  /\ ~overrun /\ down # <<>>
  /\ down' = Tail(down)
  /\ misdelivered' = (misdelivered \/ (found /\ stale /\ c.op # "Control"))
  /\ IF found /\ c.op = "Send"
       THEN /\ overspent' = (overspent \/ c.n > mCmd[s])
            /\ mCmd' = [mCmd EXCEPT ![s] = Max0(mCmd[s] - c.n)]
       ELSE UNCHANGED <<overspent, mCmd>>
  /\ IF found /\ c.op = "Credit"
       THEN mEv' = [mEv EXCEPT ![s] = mEv[s] + c.n]
       ELSE UNCHANGED mEv
  /\ IF found /\ c.op = "Close"
       THEN /\ mlive' = [mlive EXCEPT ![s] = FALSE]
            /\ mgen' = [mgen EXCEPT ![s] = mgen[s] + 1]
            \* A stale close reaches the successor, which goes too.
            /\ kids' = [kids EXCEPT ![Current(c.id)] = Dead]
       ELSE UNCHANGED <<mlive, mgen, kids>>
  /\ UNCHANGED <<turn, ctrlPending, overrun, jobs, polledClosed>>

---------------------------------------------------------------------------
(* The layer above, and results that arrive late.                          *)

\* Children: a control command, taken while the queue has room.
OfferControl ==
  /\ ~overrun /\ ctrlPending /\ Len(down) < Q
  /\ down' = Append(down, Cmd("Control", NoId, 0))
  /\ ctrlPending' = FALSE
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, kids, turn, misdelivered, overspent, overrun, jobs, polledClosed>>

NewControl ==
  /\ Control /\ ~ctrlPending
  /\ ctrlPending' = TRUE
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, kids, down, turn, misdelivered, overspent, overrun, jobs, polledClosed>>

\* Children: a timer or a work result keyed by an id the mux
\* handed out at some point, which may have closed since. It reaches the
\* child Children keys it to, whose layer may fail on it.
LateResult(id) ==
  LET target == IF KeyByWholeId
                  THEN IF kids[id].live THEN id ELSE NoId
                  ELSE IF kids[Current(id)].live THEN Current(id) ELSE NoId IN
  /\ ~overrun /\ id[2] <= mgen[id[1]]
  /\ target # NoId
  /\ misdelivered' = (misdelivered \/ target # id)
  /\ \/ UNCHANGED <<kids, down>>
     \/ /\ MayFail
        /\ kids' = [kids EXCEPT ![target] = Dead]
        /\ down' = Append(down, Cmd("Close", target, 0))
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, turn, ctrlPending, overspent, overrun, jobs, polledClosed>>

---------------------------------------------------------------------------
(* Children Children::advance: every child once, in id order   *)
(* starting after the one visited first last time.                        *)

RECURSIVE Sorted(_)
Sorted(set) == IF set = {} THEN <<>>
               ELSE LET m == CHOOSE x \in set : \A y \in set : Key(x) <= Key(y)
                    IN <<m>> \o Sorted(set \ {m})

VisitOrder(ks) ==
  IF turn = NoId THEN Sorted(Live(ks))
  ELSE Sorted({i \in Live(ks) : Key(i) > Key(turn)})
       \o Sorted({i \in Live(ks) : Key(i) <= Key(turn)})

\* Children visit_child, every way it can go, as pairs of the
\* children and the queue after it.
Visit(ks, d, id) ==
  LET kid == ks[id] IN
  IF ~kid.live THEN {<<ks, d>>}
  ELSE
    \* Children::advance, on_event and fail: the layer fails.
    (IF MayFail THEN {<<[ks EXCEPT ![id] = Dead], Append(d, Cmd("Close", id, 0))>>}
                ELSE {})
    \cup
    UNION {
      LET ready == ~kid.waiting \/ (CheckUrgent /\ kid.urgent)
          inbox1 == IF take THEN kid.inbox - 1 ELSE kid.inbox
          owed1 == IF take /\ ~Readiness THEN kid.owed + 1 ELSE kid.owed
          sent == IF CheckCommandCredit THEN IF cmd < kid.credit THEN cmd ELSE kid.credit ELSE cmd
          canSend == /\ sent > 0
                     /\ Len(d) < SendRoom
          d1 == IF canSend THEN Append(d, Cmd("Send", id, sent)) ELSE d
          grant == owed1 > 0 /\ Len(d1) < Q
          d2 == IF grant THEN Append(d1, Cmd("Credit", id, owed1)) ELSE d1
          kid2 == [live |-> TRUE,
                   granted |-> kid.granted + (IF grant THEN owed1 ELSE 0),
                   owed |-> IF grant THEN 0 ELSE owed1,
                   inbox |-> inbox1,
                   credit |-> IF canSend THEN Max0(kid.credit - sent) ELSE kid.credit,
                   outbox |-> IF canSend THEN cmd - sent ELSE cmd,
                   held |-> kid.held + (IF take /\ Readiness THEN 1 ELSE 0),
                   empty |-> IF ready /\ kid.empty > 0 THEN kid.empty - 1 ELSE kid.empty,
                   waiting |-> (kid.waiting /\ ~(CheckUrgent /\ kid.urgent)) \/ (Readiness /\ canSend),
                   urgent |-> IF CheckUrgent THEN FALSE ELSE kid.urgent]
      IN {<<[ks EXCEPT ![id] = kid2], d2>>}
      \* Children: the layer takes its next event, or not.
      : take \in (IF kid.inbox > 0 /\ ~Stalled /\ (~kid.waiting \/ (CheckUrgent /\ kid.urgent)) THEN BOOLEAN ELSE {FALSE}),
      \* Children: a command waiting, or the layer's next one.
        cmd \in (IF kid.outbox = 0 THEN {0} \cup Costs ELSE {kid.outbox})
    }

RECURSIVE VisitAll(_, _, _)
VisitAll(ks, d, order) ==
  IF order = <<>> THEN {<<ks, d>>}
  ELSE UNION {VisitAll(r[1], r[2], Tail(order)) : r \in Visit(ks, d, Head(order))}

Advance ==
  LET order == VisitOrder(kids) IN
  /\ ~overrun
  /\ turn' = IF order = <<>> THEN NoId ELSE Head(order)
  /\ \E r \in VisitAll(kids, down, order) : kids' = r[1] /\ down' = r[2]
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed>>

---------------------------------------------------------------------------

\* Empty data consumes an item slot even though it consumes no byte credit.
MuxEmpty(id) ==
  /\ Readiness /\ ~overrun /\ kids[id].live
  /\ kids[id].empty + kids[id].inbox < Q
  /\ kids' = [kids EXCEPT ![id].empty = @ + 1]
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, down, turn, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed>>

\* Completion has one reserved slot and bypasses refused ordinary data.
MuxWritten(id) ==
  /\ Readiness /\ ~overrun /\ kids[id].live /\ kids[id].waiting /\ ~kids[id].urgent
  /\ kids' = [kids EXCEPT ![id].urgent = TRUE]
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, down, turn, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed>>

Release(id) ==
  /\ Readiness /\ ~overrun /\ kids[id].live /\ kids[id].held > 0
  /\ kids' = [kids EXCEPT ![id].held = @ - 1, ![id].owed = @ + 1]
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, down, turn, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed>>

\* Work stays in the runtime after close until the next bounded poll.
ExtractWork(id) ==
  /\ Readiness /\ ~overrun /\ kids[id].live /\ id \notin jobs /\ (Cardinality(jobs) < JobLimit \/ ~CheckJobLimit)
  /\ jobs' = jobs \cup {id}
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, kids, down, turn, ctrlPending, misdelivered, overspent, overrun, polledClosed>>

PollWork(id) ==
  /\ id \in jobs /\ ~kids[id].live
  /\ jobs' = jobs \ {id}
  /\ polledClosed' = (polledClosed \/ (~kids[id].live /\ ~CheckWorkOwnership))
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, kids, down, turn, ctrlPending, misdelivered, overspent, overrun>>

\* A live operation may finish, but no fairness assumption requires it.
FinishWork(id) ==
  /\ id \in jobs /\ kids[id].live
  /\ jobs' = jobs \ {id}
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, kids, down, turn, ctrlPending, misdelivered, overspent, overrun, polledClosed>>

Next == \/ Advance \/ MuxTake \/ OfferControl \/ NewControl
        \/ \E s \in Slots : Opened(s) \/ MuxSend(s) \/ MuxCredit(s) \/ MuxPeerClose(s)
        \/ \E id \in Ids : LateResult(id) \/ MuxEmpty(id) \/ MuxWritten(id) \/ Release(id) \/ ExtractWork(id) \/ PollWork(id) \/ FinishWork(id)

\* The driver keeps advancing, the mux keeps taking commands, and the
\* layer above keeps offering its control command.
Spec == Init /\ [][Next]_vars /\ WF_vars(Advance) /\ WF_vars(MuxTake) /\ WF_vars(OfferControl)
        /\ \A id \in Ids : WF_vars(PollWork(id))
\* The same, with a peer that keeps reading each child: the mux grants
\* command credit whenever its window has room.
ReadingSpec == Spec /\ \A s \in Slots : WF_vars(MuxCredit(s))

---------------------------------------------------------------------------
(* Properties.                                                           *)

SendsIn(d, id) == {i \in DOMAIN d : d[i].op = "Send" /\ d[i].id = id}
CostIn(d, id, op) == LET is == {i \in DOMAIN d : d[i].op = op /\ d[i].id = id}
                         RECURSIVE Sum(_)
                         Sum(set) == IF set = {} THEN 0
                                     ELSE LET i == CHOOSE x \in set : TRUE
                                          IN d[i].n + Sum(set \ {i})
                     IN Sum(is)
\* The mux and Children name the same child, generation included.
Agreed(id) == kids[id].live /\ mlive[id[1]] /\ mgen[id[1]] = id[2]

\* A command, timer or result for a child that is gone never reaches the
\* child that has its slot now, or any other.
NoStaleDelivery == ~misdelivered

\* A child's event credit is all in one place: granted to the mux, in its
\* inbox, or owed back. So a child that stops reading holds at most W.
EventCredit == \A id \in Live(kids) : kids[id].granted + kids[id].inbox + kids[id].owed + kids[id].held = W

\* With a mux that keeps to its credit, the mux's credit for a child is
\* what Children granted less what is still on its way.
MuxEventCredit == HonestMux =>
  \A id \in Ids : Agreed(id) => mEv[id[1]] + CostIn(down, id, "Credit") = kids[id].granted

\* A child sends the mux no more than the mux granted it.
CommandCredit ==
  /\ ~overspent
  /\ \A id \in Ids : Agreed(id) => kids[id].credit + CostIn(down, id, "Send") = mCmd[id[1]]

\* Children's commands never take the places kept for control and credit.
SendsLeaveReserve == Cardinality({i \in DOMAIN down : down[i].op = "Send"}) <= Q - R

\* A control command is taken eventually, whatever the children do.
ControlProgress == ctrlPending ~> ~ctrlPending

\* A child's command reaches the mux eventually, while the child lives.
CommandsGo == \A id \in Ids : (kids[id].live /\ kids[id].outbox > 0)
                                ~> (~kids[id].live \/ kids[id].outbox = 0)
BoundedJobs == Cardinality(jobs) <= JobLimit
NoCancelledPoll == ~polledClosed
CancelledWorkLeaves == \A id \in Ids : (~kids[id].live /\ id \in jobs) ~> (id \notin jobs)
BoundedItems == \A id \in Live(kids) : kids[id].inbox + kids[id].empty <= Q
CompletionProgress == \A id \in Ids : (kids[id].live /\ kids[id].urgent) ~> (~kids[id].live \/ ~kids[id].urgent)
=============================================================================
