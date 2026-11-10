---------------------------- MODULE ChildMemory ----------------------------
(* How Children (src/stdlib/layer/children.rs) handles memory for its    *)
(* children, and the cause it gives each close: the budget-leftovers     *)
(* rules. Line numbers are those of the worktree comp/fv-layer, from     *)
(* main at 3db7a847e.                                                    *)
(*                                                                       *)
(* Each child asks through a view of its own on one shared budget        *)
(* (`budget.view()` at Opened, children.rs:1098-1101), so its refusals   *)
(* are its own record and not the stack's, which the runner reads.       *)
(*                                                                       *)
(*   Open      MuxEvent::Opened (children.rs:1085-1155): past the limit  *)
(*             or a factory that says no is Prohibited; a place or       *)
(*             receive window the budget cannot hold is ResourceShortage;*)
(*             either closes the child at once with that cause and       *)
(*             reports Refused with the same cause (:1112-1117).         *)
(*   Charge    a charge of the child's, in a visit (`visit`, :907-930),  *)
(*             an event's place or payload (:1226-1236), a timer or a    *)
(*             result (:1301-1360). Within the limit a refusal closes    *)
(*             nothing: the child waits on its view (`wait_for_memory`,  *)
(*             :415-422) and is told to the runner (`Kid::memory`,       *)
(*             `Children::waits_for_memory`). Past the whole limit       *)
(*             (Starved on the child's view) only that child is closed,  *)
(*             as failed (`refuse(.., Closing::Failed)`).                *)
(*   Wake      the release that leaves room for the child's need wakes   *)
(*             its waiter (`ChildWaker`, :573-600), which queues the     *)
(*             child, and its next visit tries again (:907-912).         *)
(*   Done      a finished child is closed as Done (:1050-1054).          *)
(*   Fail      a layer error closes the child as failed and reports      *)
(*             Failed (`fail`, :855-870).                                *)
(*                                                                       *)
(* What the model leaves out: the mux's credit, inboxes, commands and    *)
(* generations (Children.tla has them); the wake's own atomics           *)
(* (BudgetWake.tla); byte sizes, abstracted to whole units of memory;    *)
(* an event handed back to the mux (the mux offers it again after the    *)
(* wake, which here is the child's retry); the muxes' mapping of each    *)
(* cause to its wire (SSH reason codes, HTTP/2 error codes), which is    *)
(* read in ssh.rs and http2.rs, not modeled.                             *)
(*                                                                       *)
(* Flags keep a part of the code as it is (TRUE) or break it (FALSE):    *)
(*   WaitOnRefusal  a refusal within the limit waits; FALSE closes the   *)
(*                  child as failed, as before the leftovers             *)
(*   OwnView        each child charges through a view of its own; FALSE  *)
(*                  charges the stack's view, so a child's Starved ends  *)
(*                  the run                                              *)
(*   SameCause      Refused carries the cause of the Close; FALSE        *)
(*                  reports every admission refusal as Prohibited        *)
(*   WakeOnRelease  the release that makes room wakes a waiting child   *)
(*   TellEvent      a wait begun by an event's charge is told to the     *)
(*                  runner, as one begun in a visit is                   *)
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS Need1, Need2, Need3, \* what each of three children charges once open
          Window,     \* what a child's receive window costs at Opened
          Limit,      \* the shared budget's limit
          ChildLimit, \* Children's limit on open children
          Others,     \* units other connections may hold, and give back
          WaitOnRefusal, OwnView, SameCause, WakeOnRelease, TellEvent

ASSUME Limit \in Nat /\ Window \in Nat /\ Others \in Nat /\ ChildLimit \in Nat

Kids == {1, 2, 3}
Need == [k \in Kids |-> CASE k = 1 -> Need1 [] k = 2 -> Need2 [] k = 3 -> Need3]

Causes == {"Done", "Prohibited", "ResourceShortage", "Failed"}

VARIABLES
  used,       \* the shared count
  others,     \* what other connections hold now
  st,         \* each child: "new", "open", "waiting", "ready", "got", "closed"
  held,       \* what each child holds
  told,       \* Kid::memory: the child's wait is told to the runner
  told_n,     \* Children::memory: how many are told
  down,       \* the commands the router queued for the mux: Close(id, cause)
  reports,    \* what the router reported: Refused(id, cause) or Failed(id)
  why,        \* why each child was closed, as the code decided it
  path,       \* how each waiting child's wait began: "visit" or "event"
  runEnded,   \* the runner ended the run: StreamEnd::Budget
  stackStarved \* the stack's own view recorded Starved

vars == <<used, others, st, held, told, told_n, down, reports, why, path, runEnded,
          stackStarved>>

Room == Limit - used
Open(k) == st[k] \in {"open", "waiting", "ready", "got"}
OpenCount == Cardinality({k \in Kids : Open(k)})

Init ==
  /\ used = 0 /\ others = 0
  /\ st = [k \in Kids |-> "new"]
  /\ held = [k \in Kids |-> 0]
  /\ told = [k \in Kids |-> FALSE] /\ told_n = 0
  /\ down = <<>> /\ reports = {}
  /\ why = [k \in Kids |-> "none"]
  /\ path = [k \in Kids |-> "none"]
  /\ runEnded = FALSE /\ stackStarved = FALSE

Live == ~runEnded
(* Gives back what child k holds. A release that leaves room for a      *)
(* waiting child's need wakes it.                                       *)
Wakes(u) ==
  [k \in Kids |-> IF st[k] = "waiting" /\ WakeOnRelease /\ Need[k] <= Limit - u
                  THEN "ready" ELSE st[k]]


(* Child k gives back what it holds, as dropping its Kid does.          *)
Release(k) == used' = used - held[k] /\ held' = [held EXCEPT ![k] = 0]


(* Closes child k for cause c: the Close goes down with c, and a refused *)
(* child is reported with the cause the code gives it.                  *)
CloseAs(k, c, report, base) ==
  /\ down' = Append(down, [id |-> k, cause |-> c])
  /\ reports' = reports \cup
       (IF report = "refused"
        THEN {[id |-> k, kind |-> "Refused",
               cause |-> IF SameCause \/ c # "ResourceShortage" THEN c ELSE "Prohibited"]}
        ELSE IF report = "failed" THEN {[id |-> k, kind |-> "Failed", cause |-> c]}
        ELSE {})
  /\ why' = [why EXCEPT ![k] = c]
  /\ st' = [base EXCEPT ![k] = "closed"]

(* Told(k, b): Kid::memory set to b, and the count kept with it.        *)
Told(k, b) ==
  /\ told' = [told EXCEPT ![k] = b]
  /\ told_n' = told_n + (IF b /\ ~told[k] THEN 1 ELSE IF ~b /\ told[k] THEN -1 ELSE 0)

(* MuxEvent::Opened: the limit, the window and the factory.             *)
OpenKid(k) ==
  /\ Live /\ st[k] = "new"
  /\ \E factorySaysNo \in BOOLEAN :
     IF OpenCount >= ChildLimit \/ factorySaysNo
     THEN /\ CloseAs(k, "Prohibited", "refused", st)
          /\ UNCHANGED <<used, held, told, told_n, path>>
     ELSE IF Window > Room
     THEN /\ CloseAs(k, "ResourceShortage", "refused", st)
          /\ UNCHANGED <<used, held, told, told_n, path>>
     ELSE /\ used' = used + Window
          /\ held' = [held EXCEPT ![k] = Window]
          /\ st' = [st EXCEPT ![k] = "open"]
          /\ UNCHANGED <<down, reports, why, told, told_n, path>>
  /\ UNCHANGED <<others, runEnded, stackStarved>>

(* A charge of the child's, in a visit or for an event. A visit ends a  *)
(* told wait and begins it again if refused (children.rs:907-930).      *)
ChargeKid(k, via) ==
  /\ Live /\ st[k] \in {"open", "ready"}
  /\ via \in {"visit", "event"}
  /\ IF Need[k] <= Room
     THEN /\ used' = used + Need[k]
          /\ held' = [held EXCEPT ![k] = @ + Need[k]]
          /\ st' = [st EXCEPT ![k] = "got"]
          /\ IF via = "visit" THEN Told(k, FALSE) ELSE UNCHANGED <<told, told_n>>
          /\ UNCHANGED <<down, reports, why, path, runEnded, stackStarved>>
     ELSE IF Need[k] > Limit
     THEN \* Starved. Through its own view only the child is closed; through
          \* the stack's view the runner ends the run.
          IF OwnView
          THEN /\ CloseAs(k, "Failed", "refused", Wakes(used - held[k]))
               /\ Told(k, FALSE)
               /\ Release(k) /\ UNCHANGED <<path, runEnded, stackStarved>>
          ELSE /\ stackStarved' = TRUE /\ runEnded' = TRUE
               /\ UNCHANGED <<used, held, st, told, told_n, down, reports, why, path>>
     ELSE IF WaitOnRefusal
     THEN /\ st' = [st EXCEPT ![k] = "waiting"]
          /\ path' = [path EXCEPT ![k] = via]
          /\ Told(k, via = "visit" \/ TellEvent)
          /\ UNCHANGED <<used, held, down, reports, why, runEnded, stackStarved>>
     ELSE /\ CloseAs(k, "Failed", "refused", Wakes(used - held[k]))
          /\ Told(k, FALSE)
          /\ Release(k) /\ UNCHANGED <<path, runEnded, stackStarved>>
  /\ UNCHANGED others

(* A finished child gives its memory back and is closed as Done.        *)
DoneKid(k) ==
  /\ Live /\ st[k] = "got"
  /\ used' = used - held[k]
  /\ held' = [held EXCEPT ![k] = 0]
  /\ down' = Append(down, [id |-> k, cause |-> "Done"])
  /\ why' = [why EXCEPT ![k] = "Done"]
  /\ st' = [Wakes(used - held[k]) EXCEPT ![k] = "closed"]
  /\ Told(k, FALSE)
  /\ UNCHANGED <<others, reports, path, runEnded, stackStarved>>

(* A child that got its memory through an event's charge while its wait  *)
(* was told is still queued by the wake, and its visit ends the tell.    *)
VisitGot(k) ==
  /\ Live /\ st[k] = "got" /\ told[k]
  /\ Told(k, FALSE)
  /\ UNCHANGED <<used, others, st, held, down, reports, why, path, runEnded, stackStarved>>

(* A layer error: closed as failed, its memory given back.              *)
FailKid(k) ==
  /\ Live /\ Open(k)
  /\ used' = used - held[k]
  /\ held' = [held EXCEPT ![k] = 0]
  /\ down' = Append(down, [id |-> k, cause |-> "Failed"])
  /\ reports' = reports \cup {[id |-> k, kind |-> "Failed", cause |-> "Failed"]}
  /\ why' = [why EXCEPT ![k] = "Failed"]
  /\ st' = [Wakes(used - held[k]) EXCEPT ![k] = "closed"]
  /\ Told(k, FALSE)
  /\ UNCHANGED <<others, path, runEnded, stackStarved>>

(* Other connections charge the shared budget and give it back.         *)
OthersTake ==
  /\ Live /\ others = 0 /\ Others > 0 /\ Others <= Room
  /\ others' = Others /\ used' = used + Others
  /\ UNCHANGED <<st, held, told, told_n, down, reports, why, path, runEnded, stackStarved>>

OthersGive ==
  /\ others > 0
  /\ others' = 0 /\ used' = used - others
  /\ st' = Wakes(used - others)
  /\ UNCHANGED <<held, told, told_n, down, reports, why, path, runEnded, stackStarved>>

Next ==
  \/ \E k \in Kids : OpenKid(k) \/ ChargeKid(k, "visit") \/ ChargeKid(k, "event")
                     \/ DoneKid(k) \/ FailKid(k) \/ VisitGot(k)
  \/ OthersTake \/ OthersGive

(* Children visit a ready child, finished children finish, and memory    *)
(* others hold comes back. A layer error is not assumed to happen.       *)
Spec == Init /\ [][Next]_vars
        /\ \A k \in Kids : WF_vars(ChargeKid(k, "visit")) /\ WF_vars(DoneKid(k))
                          /\ WF_vars(VisitGot(k))
        /\ WF_vars(OthersGive)

----------------------------------------------------------------------------
(* Properties *)

TypeOK ==
  /\ used \in 0..Limit
  /\ st \in [Kids -> {"new", "open", "waiting", "ready", "got", "closed"}]
  /\ \A i \in 1..Len(down) : down[i].cause \in Causes

(* Every Close carries the cause Children decided for that child, and a  *)
(* refused child is reported with the cause of its Close.                *)
CauseMatches ==
  /\ \A i \in 1..Len(down) : down[i].cause = why[down[i].id]
  /\ \A r \in reports :
       r.kind = "Refused" => \E i \in 1..Len(down) : down[i].id = r.id /\ down[i].cause = r.cause

(* A child is closed once, and never for memory it could get: within the *)
(* limit a refusal closes nothing. Failed is for a layer error or a need *)
(* past the whole limit; ResourceShortage only at Opened.                *)
MemoryClosesNothing ==
  /\ \A i, j \in 1..Len(down) : i # j => down[i].id # down[j].id
  /\ \A k \in Kids :
       why[k] = "Failed" =>
         (Need[k] > Limit \/ \E r \in reports : r.id = k /\ r.kind = "Failed")

(* A child's need past the whole limit closes that child alone: the run *)
(* goes on, and the stack's own view records nothing.                    *)
StarvedClosesAlone == ~runEnded /\ ~stackStarved

(* While a child waits for memory, the router tells its runner so.       *)
WaitTold ==
  /\ told_n = Cardinality({k \in Kids : told[k]})
  /\ \A k \in Kids : st[k] = "waiting" => told_n > 0

(* No lost wake: a child that waits for memory within the limit is       *)
(* visited again, whatever its siblings and other connections charge and *)
(* give back meanwhile.                                                  *)
ChildWakes == \A k \in Kids : (st[k] = "waiting") ~> (st[k] # "waiting")

(* A tell ends: a child told as waiting that no longer waits is visited, *)
(* and the visit ends the tell, so the runner's idle clock runs again.   *)
TellEnds == \A k \in Kids : told[k] ~> (~told[k] \/ st[k] = "waiting")
=============================================================================
