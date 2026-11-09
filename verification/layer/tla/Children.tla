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
(* The mux's events go up in one order, as they do through Chain: an      *)
(* event Children hands back (Blocked) waits at the head, and nothing     *)
(* behind it moves. While it waits the mux reads no input either, as the  *)
(* HTTP/2 connection stops reading once its events back up (http2.rs,     *)
(* Http2::read), so the connection's own traffic (SETTINGS, PING,         *)
(* WINDOW_UPDATE) waits with it.                                          *)
(*                                                                       *)
(* Source correspondence:                                                *)
(*   Opened, MuxSend, MuxCredit, MuxPeerClose: Children::on_event            *)
(*   Budget refusal includes the selected child's budget: budgets()       *)
(*   chooses it before receive storage or application construction.       *)
(*   Arrivals: Children::on_event for MuxEvent::Child, Children::full,     *)
(*             Children::refuse                                           *)
(*   MuxRetry: Chain offering a held event again                           *)
(*   MuxControl: the mux's own connection traffic, which reads input       *)
(*   OfferControl: Children::on_command                                    *)
(*   LateResult: Children::on_timer and Children::on_done                    *)
(*   Advance, Visit: Children::advance and Children::visit                   *)
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
(*   Isolate             a full place gets its child one visit, then the *)
(*                       child is refused; Children never hands a        *)
(*                       child's event back to the mux                   *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS NS,          \* the mux's slots
          G,           \* the last generation a slot may reach
          Limit,       \* Children::new's `limit`
          W,           \* Children::new's `window`
          Q, R,        \* QUEUE and RESERVE
          MaxCredit,   \* the most command credit the mux has out per child
          Costs,       \* what a child's command may cost
          Stalled,     \* children's layers never take an event
          StuckSlots,  \* the layers of the children in these slots never
                       \* take an event: any child the user installs
          HonestMux,   \* the mux sends events only within credit
          Overload,    \* the mux sends a child's events whatever its place
                       \* holds, as a wire mux parsing frames does
          CheckWorkOwnership, CheckUrgent, CheckJobLimit, JobLimit,
          Readiness,    \* retained buffers and completion traffic
          Wakes,       \* what keeps or makes a child ready for a visit,
                       \* beyond its events, timers and work: a subset of
                       \* {"credit", "waiting", "release"}
          MayFail,     \* children's layers may fail or finish
          BudgetRefuses, \* child factory, place, inbox or payload may be refused
          Control,     \* the layer above sends control commands
          Connection,  \* the peer sends the mux connection traffic
          CheckOverrun, CheckCommandCredit, ReserveForControl,
          MuxChecksGeneration, KeyByWholeId, Isolate

Slots == 1..NS
Ids == Slots \X (0..G)
NoId == <<0, 0>>
Key(id) == id[1] * (G + 1) + id[2]
Max0(n) == IF n < 0 THEN 0 ELSE n

VARIABLES mlive, mgen, mEv, mCmd,   \* the mux's slots
          mHeld,                    \* the mux's event Children handed back
          ctrlIn,                   \* the mux has connection traffic to read
          kids,                     \* Children's children, by id
          down,                     \* Children::down, its commands for the mux
          ctrlPending,              \* the layer above holds a control command
          misdelivered, overspent, overrun, jobs, polledClosed
vars == <<mlive, mgen, mEv, mCmd, mHeld, ctrlIn, kids, down, ctrlPending,
          misdelivered, overspent, overrun, jobs, polledClosed>>
muxIn == <<mHeld, ctrlIn>>

Dead == [live |-> FALSE, granted |-> 0, owed |-> 0, inbox |-> 0,
         credit |-> 0, outbox |-> 0, held |-> 0, empty |-> 0, waiting |-> FALSE, urgent |-> FALSE,
         woken |-> FALSE]
Fresh == [Dead EXCEPT !.live = TRUE, !.owed = W, !.woken = TRUE]   \* Children
Cmd(op, id, n) == [op |-> op, id |-> id, n |-> n]
Live(ks) == {id \in Ids : ks[id].live}
SendRoom == IF ReserveForControl THEN Q - R ELSE Q
\* The child in a slot that the mux would reach with `id`.
Current(id) == <<id[1], mgen[id[1]]>>
NoHeld == [id |-> NoId, kind |-> "none"]
Stuck(id) == Stalled \/ id[1] \in StuckSlots

Init == /\ mlive = [s \in Slots |-> FALSE]
        /\ mgen = [s \in Slots |-> 0]
        /\ mEv = [s \in Slots |-> 0]
        /\ mCmd = [s \in Slots |-> 0]
        /\ mHeld = NoHeld
        /\ ctrlIn = FALSE
        /\ kids = [id \in Ids |-> Dead]
        /\ down = <<>>
        /\ ctrlPending = FALSE
        /\ jobs = {} /\ polledClosed = FALSE
        /\ misdelivered = FALSE /\ overspent = FALSE /\ overrun = FALSE

---------------------------------------------------------------------------
(* Children::advance: every ready child once, in any order: Rust visits   *)
(* them in the order they joined its ready list. A child is ready when    *)
(* opened, when an event, a timer, a work result or handed-out work       *)
(* reached it, when the mux grants it credit ("credit"), when payload it  *)
(* holds is released ("release"), and while its visits move or find no    *)
(* room in the queue ("waiting").                                         *)

Ready(ks) == {i \in Live(ks) : ks[i].woken}

\* Every sequence of the elements of `set`, each once.
Orders(set) == {f \in [1..Cardinality(set) -> set] :
                  \A i, j \in 1..Cardinality(set) : i # j => f[i] # f[j]}

Wake(ks, id) == IF ks[id].live THEN [ks EXCEPT ![id].woken = TRUE] ELSE ks

\* Children::visit_kid, every way it can go, as pairs of the
\* children and the queue after it.
Visit(ks, d, id) ==
  LET kid == ks[id]
      stuck == Stuck(id) IN
  IF ~kid.live THEN {<<ks, d>>}
  ELSE
    \* The layer fails or becomes terminal. Terminal completion is a subset
    \* of this nondeterministic close: Rust waits for the outbox to drain.
    (IF MayFail THEN {<<[ks EXCEPT ![id] = Dead], Append(d, Cmd("Close", id, 0))>>}
                ELSE {})
    \cup
    UNION {
      LET passes == CheckUrgent /\ kid.urgent /\ ~stuck   \* the layer takes it
          ready == ~kid.waiting \/ passes
          inbox1 == IF take THEN kid.inbox - 1 ELSE kid.inbox
          owed1 == IF take /\ ~Readiness THEN kid.owed + 1 ELSE kid.owed
          sent == IF CheckCommandCredit THEN IF cmd < kid.credit THEN cmd ELSE kid.credit ELSE cmd
          canSend == /\ sent > 0
                     /\ Len(d) < SendRoom
          d1 == IF canSend THEN Append(d, Cmd("Send", id, sent)) ELSE d
          grant == owed1 > 0 /\ Len(d1) < Q
          d2 == IF grant THEN Append(d1, Cmd("Credit", id, owed1)) ELSE d1
          consumed == ready /\ ~stuck /\ kid.empty > 0
          moved == take \/ passes \/ consumed \/ canSend \/ grant
                   \/ (kid.outbox = 0 /\ cmd > 0)
          \* No room for the command it holds, or for the credit it owes.
          full == (cmd > 0 /\ Len(d) >= SendRoom) \/ (owed1 > 0 /\ ~grant)
          kid2 == [live |-> TRUE,
                   woken |-> moved \/ (full /\ "waiting" \in Wakes),
                   granted |-> kid.granted + (IF grant THEN owed1 ELSE 0),
                   owed |-> IF grant THEN 0 ELSE owed1,
                   inbox |-> inbox1,
                   credit |-> IF canSend THEN Max0(kid.credit - sent) ELSE kid.credit,
                   outbox |-> IF canSend THEN cmd - sent ELSE cmd,
                   held |-> kid.held + (IF take /\ Readiness THEN 1 ELSE 0),
                   empty |-> IF consumed THEN kid.empty - 1 ELSE kid.empty,
                   waiting |-> (kid.waiting /\ ~passes) \/ (Readiness /\ canSend),
                   urgent |-> IF passes THEN FALSE ELSE kid.urgent]
      IN {<<[ks EXCEPT ![id] = kid2], d2>>}
      \* Children: the layer takes its next event, or not.
      : take \in (IF kid.inbox > 0 /\ ~stuck /\ (~kid.waiting \/ (CheckUrgent /\ kid.urgent))
                    THEN BOOLEAN ELSE {FALSE}),
      \* Children: a command waiting, or the layer's next one.
        cmd \in (IF kid.outbox = 0 THEN {0} \cup Costs ELSE {kid.outbox})
    }

RECURSIVE VisitAll(_, _, _)
VisitAll(ks, d, order) ==
  IF order = <<>> THEN {<<ks, d>>}
  ELSE UNION {VisitAll(r[1], r[2], Tail(order)) : r \in Visit(ks, d, Head(order))}

---------------------------------------------------------------------------
(* Children::on_event for an event for live child `id`: one of a credit   *)
(* unit ("data"), one with no credit ("empty": empty data, an end), or a  *)
(* completion ("urgent"), which has its own place.                        *)

Full(ks, id, k) == IF k = "urgent" THEN ks[id].urgent
                   ELSE ks[id].inbox + ks[id].empty >= Q

Place(ks, id, k) ==
  CASE k = "data" -> [ks EXCEPT ![id].granted = Max0(ks[id].granted - 1),
                                ![id].inbox = @ + 1, ![id].woken = TRUE]
    [] k = "empty" -> [ks EXCEPT ![id].empty = @ + 1, ![id].woken = TRUE]
    [] k = "urgent" -> [ks EXCEPT ![id].urgent = TRUE, ![id].woken = TRUE]

\* Every way it can go, as the children, the queue, and whether Children
\* took the event. A full place gets the child one visit; a child still
\* full is refused and closed, and the event goes with it. Without
\* Isolate, Children hands the event back.
Arrivals(ks, d, id, k) ==
  IF ~Full(ks, id, k) THEN {<<Place(ks, id, k), d, TRUE>>}
  ELSE IF ~Isolate THEN {<<ks, d, FALSE>>}
  ELSE {IF ~r[1][id].live THEN <<r[1], r[2], TRUE>>
        ELSE IF Full(r[1], id, k)
          THEN <<[r[1] EXCEPT ![id] = Dead], Append(r[2], Cmd("Close", id, 0)), TRUE>>
        ELSE <<Place(r[1], id, k), r[2], TRUE>>
        : r \in Visit(ks, d, id)}

Deliver(id, k) ==
  \E r \in Arrivals(kids, down, id, k) :
    IF r[3] THEN kids' = r[1] /\ down' = r[2] /\ mHeld' = NoHeld
            ELSE mHeld' = [id |-> id, kind |-> k] /\ UNCHANGED <<kids, down>>

---------------------------------------------------------------------------
(* The mux: events up to Children.                                         *)

\* The mux opens a child in a free slot (Slots::insert) and hands up its
\* handle; Children makes its layer, or closes it at once at the limit or
\* when the budget cannot hold its place (Children::make_room).
Opened(s) ==
  LET id == <<s, mgen[s]>> IN
  /\ ~overrun /\ mHeld = NoHeld /\ ~mlive[s] /\ mgen[s] <= G
  /\ mlive' = [mlive EXCEPT ![s] = TRUE]
  /\ mEv' = [mEv EXCEPT ![s] = 0] /\ mCmd' = [mCmd EXCEPT ![s] = 0]
  /\ \E refused \in (IF BudgetRefuses THEN BOOLEAN ELSE {FALSE}) :
       IF Cardinality(Live(kids)) >= Limit \/ refused
         THEN down' = Append(down, Cmd("Close", id, 0)) /\ UNCHANGED kids
         ELSE kids' = [kids EXCEPT ![id] = Fresh] /\ UNCHANGED down
  /\ UNCHANGED <<mgen, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed>>
  /\ UNCHANGED muxIn

\* The mux sends a child an event of one credit unit.
MuxSend(s) ==
  LET id == <<s, mgen[s]>>
      kid == kids[id] IN
  /\ ~overrun /\ mHeld = NoHeld /\ mlive[s] /\ (mEv[s] >= 1 \/ ~HonestMux)
  /\ (~Readiness \/ Overload \/ kid.inbox + kid.empty < Q)
  /\ mEv' = [mEv EXCEPT ![s] = Max0(mEv[s] - 1)]
  /\ IF ~kid.live
       THEN UNCHANGED <<kids, down, overrun, mHeld>>   \* a child already gone
     ELSE IF kid.granted < 1 /\ CheckOverrun
       THEN overrun' = TRUE /\ UNCHANGED <<kids, down, mHeld>>
     ELSE /\ UNCHANGED overrun
          /\ \/ Deliver(id, "data")
             \* The budget cannot hold the inbox's growth: the child is
             \* refused and closed, and its siblings go on.
             \/ /\ BudgetRefuses
                /\ kids' = [kids EXCEPT ![id] = Dead]
                /\ down' = Append(down, Cmd("Close", id, 0))
                /\ UNCHANGED mHeld
  /\ UNCHANGED <<mlive, mgen, mCmd, ctrlPending, misdelivered, overspent, jobs, polledClosed, ctrlIn>>

\* The mux lets a child send one more credit unit, within its window: the
\* peer's WINDOW_UPDATE, read as input.
MuxCredit(s) ==
  LET id == <<s, mgen[s]>> IN
  /\ ~overrun /\ mHeld = NoHeld /\ mlive[s] /\ mCmd[s] < MaxCredit
  /\ mCmd' = [mCmd EXCEPT ![s] = mCmd[s] + 1]
  /\ kids' = IF kids[id].live
               THEN [kids EXCEPT ![id].credit = kids[id].credit + 1,
                                 ![id].woken = (@ \/ "credit" \in Wakes)]
               ELSE kids
  /\ UNCHANGED <<mlive, mgen, mEv, down, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed>>
  /\ UNCHANGED muxIn

\* The peer resets a child: the mux removes it (Slots::remove, a new
\* generation for the slot) and says Closed.
MuxPeerClose(s) ==
  LET id == <<s, mgen[s]>> IN
  /\ ~overrun /\ mHeld = NoHeld /\ mlive[s]
  /\ mlive' = [mlive EXCEPT ![s] = FALSE]
  /\ mgen' = [mgen EXCEPT ![s] = mgen[s] + 1]
  /\ kids' = [kids EXCEPT ![id] = Dead]
  /\ UNCHANGED <<mEv, mCmd, down, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed>>
  /\ UNCHANGED muxIn

\* The event Children handed back is offered again. A child gone since
\* has nothing to deliver to.
MuxRetry ==
  /\ ~overrun /\ mHeld # NoHeld
  /\ IF kids[mHeld.id].live
       THEN Deliver(mHeld.id, mHeld.kind)
       ELSE mHeld' = NoHeld /\ UNCHANGED <<kids, down>>
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed, ctrlIn>>

\* The peer sends connection traffic: a PING, SETTINGS or WINDOW_UPDATE.
NewConnection ==
  /\ Connection /\ ~ctrlIn
  /\ ctrlIn' = TRUE
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, mHeld, kids, down, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed>>

\* The mux reads and answers it, unless its events are backed up.
MuxControl ==
  /\ ~overrun /\ ctrlIn /\ mHeld = NoHeld
  /\ ctrlIn' = FALSE
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, mHeld, kids, down, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed>>

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
  /\ UNCHANGED <<ctrlPending, overrun, jobs, polledClosed>>
  /\ UNCHANGED muxIn

---------------------------------------------------------------------------
(* The layer above, and results that arrive late.                          *)

\* Children: a control command, taken while the queue has room.
OfferControl ==
  /\ ~overrun /\ ctrlPending /\ Len(down) < Q
  /\ down' = Append(down, Cmd("Control", NoId, 0))
  /\ ctrlPending' = FALSE
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, kids, misdelivered, overspent, overrun, jobs, polledClosed>>
  /\ UNCHANGED muxIn

NewControl ==
  /\ Control /\ ~ctrlPending
  /\ ctrlPending' = TRUE
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, kids, down, misdelivered, overspent, overrun, jobs, polledClosed>>
  /\ UNCHANGED muxIn

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
  /\ \/ kids' = Wake(kids, target) /\ UNCHANGED down
     \/ /\ MayFail
        /\ kids' = [kids EXCEPT ![target] = Dead]
        /\ down' = Append(down, Cmd("Close", target, 0))
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, ctrlPending, overspent, overrun, jobs, polledClosed>>
  /\ UNCHANGED muxIn

---------------------------------------------------------------------------

Advance ==
  /\ ~overrun
  /\ \E order \in Orders(Ready(kids)) :
       \E r \in VisitAll(kids, down, order) : kids' = r[1] /\ down' = r[2]
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed>>
  /\ UNCHANGED muxIn

---------------------------------------------------------------------------

\* Empty data consumes an item slot even though it consumes no byte credit.
MuxEmpty(id) ==
  /\ Readiness /\ ~overrun /\ mHeld = NoHeld /\ kids[id].live
  /\ (Overload \/ kids[id].empty + kids[id].inbox < Q)
  /\ Deliver(id, "empty")
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed, ctrlIn>>

\* Completion has one reserved slot and bypasses refused ordinary data.
MuxWritten(id) ==
  /\ Readiness /\ ~overrun /\ mHeld = NoHeld /\ kids[id].live /\ kids[id].waiting
  /\ (Overload \/ ~kids[id].urgent)
  /\ Deliver(id, "urgent")
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed, ctrlIn>>

Release(id) ==
  /\ Readiness /\ ~overrun /\ kids[id].live /\ kids[id].held > 0
  /\ kids' = [kids EXCEPT ![id].held = @ - 1, ![id].owed = @ + 1,
                          ![id].woken = (@ \/ "release" \in Wakes)]
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, down, ctrlPending, misdelivered, overspent, overrun, jobs, polledClosed>>
  /\ UNCHANGED muxIn

\* Work stays in the runtime after close until the next bounded poll.
ExtractWork(id) ==
  /\ Readiness /\ ~overrun /\ kids[id].live /\ id \notin jobs /\ (Cardinality(jobs) < JobLimit \/ ~CheckJobLimit)
  /\ jobs' = jobs \cup {id}
  /\ kids' = Wake(kids, id)
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, down, ctrlPending, misdelivered, overspent, overrun, polledClosed>>
  /\ UNCHANGED muxIn

PollWork(id) ==
  /\ id \in jobs /\ ~kids[id].live
  /\ jobs' = jobs \ {id}
  /\ polledClosed' = (polledClosed \/ (~kids[id].live /\ ~CheckWorkOwnership))
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, kids, down, ctrlPending, misdelivered, overspent, overrun>>
  /\ UNCHANGED muxIn

\* A live operation may finish, but no fairness assumption requires it.
FinishWork(id) ==
  /\ id \in jobs /\ kids[id].live
  /\ jobs' = jobs \ {id}
  /\ kids' = Wake(kids, id)
  /\ UNCHANGED <<mlive, mgen, mEv, mCmd, down, ctrlPending, misdelivered, overspent, overrun, polledClosed>>
  /\ UNCHANGED muxIn

Next == \/ Advance \/ MuxTake \/ OfferControl \/ NewControl
        \/ MuxRetry \/ NewConnection \/ MuxControl
        \/ \E s \in Slots : Opened(s) \/ MuxSend(s) \/ MuxCredit(s) \/ MuxPeerClose(s)
        \/ \E id \in Ids : LateResult(id) \/ MuxEmpty(id) \/ MuxWritten(id) \/ Release(id) \/ ExtractWork(id) \/ PollWork(id) \/ FinishWork(id)

\* The driver keeps advancing, the mux keeps taking commands and offering a
\* held event again, and the layer above keeps offering its control
\* command. The mux reads connection traffic whenever it can, even if its
\* events back up now and then; only an event held for good stops it.
Spec == Init /\ [][Next]_vars /\ WF_vars(Advance) /\ WF_vars(MuxTake) /\ WF_vars(OfferControl)
        /\ WF_vars(MuxRetry) /\ SF_vars(MuxControl)
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
\* Credit the mux spent on an event Children handed back.
HeldCredit(id) == IF mHeld.id = id /\ mHeld.kind = "data" THEN 1 ELSE 0

\* A command, timer or result for a child that is gone never reaches the
\* child that has its slot now, or any other.
NoStaleDelivery == ~misdelivered

\* A child's event credit is all in one place: granted to the mux, in its
\* inbox, or owed back. So a child that stops reading holds at most W.
EventCredit == \A id \in Live(kids) : kids[id].granted + kids[id].inbox + kids[id].owed + kids[id].held = W

\* With a mux that keeps to its credit, the mux's credit for a child is
\* what Children granted less what is still on its way.
MuxEventCredit == HonestMux =>
  \A id \in Ids : Agreed(id) =>
    mEv[id[1]] + CostIn(down, id, "Credit") + HeldCredit(id) = kids[id].granted

\* A child sends the mux no more than the mux granted it.
CommandCredit ==
  /\ ~overspent
  /\ \A id \in Ids : Agreed(id) => kids[id].credit + CostIn(down, id, "Send") = mCmd[id[1]]

\* Children's commands never take the places kept for control and credit.
SendsLeaveReserve == Cardinality({i \in DOMAIN down : down[i].op = "Send"}) <= Q - R

\* A control command is taken eventually, whatever the children do.
ControlProgress == ctrlPending ~> ~ctrlPending

\* Children never hands a child's event back, so the mux never waits on
\* any child, whatever its layer does.
MuxNeverHeld == mHeld = NoHeld

\* The connection's own traffic is read eventually, whatever the children
\* do.
ConnectionProgress == ctrlIn ~> ~ctrlIn

\* A child's command reaches the mux eventually, while the child lives.
CommandsGo == \A id \in Ids : (kids[id].live /\ kids[id].outbox > 0)
                                ~> (~kids[id].live \/ kids[id].outbox = 0)
BoundedJobs == Cardinality(jobs) <= JobLimit
NoCancelledPoll == ~polledClosed
CancelledWorkLeaves == \A id \in Ids : (~kids[id].live /\ id \in jobs) ~> (id \notin jobs)
BoundedItems == \A id \in Live(kids) : kids[id].inbox + kids[id].empty <= Q
CompletionProgress == \A id \in Ids : (kids[id].live /\ kids[id].urgent) ~> (~kids[id].live \/ ~kids[id].urgent)
\* Credit a child owes the mux goes back eventually, while the child lives:
\* credit its layer took or its released payload returned.
CreditReturns == \A id \in Ids : (kids[id].live /\ kids[id].owed > 0)
                                    ~> (~kids[id].live \/ kids[id].owed = 0)
=============================================================================
