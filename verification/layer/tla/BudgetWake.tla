----------------------------- MODULE BudgetWake -----------------------------
(* The wake of a Budget (src/stdlib/layer/budget.rs): runners, each      *)
(* charging through a view of its own on one shared count, that wait     *)
(* for memory after a refusal and are woken by the release that leaves  *)
(* room for the least refused need.                                      *)
(*                                                                       *)
(* Each step is one atomic operation of the code, so the threads of a    *)
(* runtime interleave between them as they can in Rust:                  *)
(*                                                                       *)
(*   Mark      Budget::refusals                       budget.rs:291-296  *)
(*   Try1      take_with's first try_take (one CAS)   budget.rs:384      *)
(*   Refuse    refused += 1; a need past the limit                       *)
(*             records Starved and returns            budget.rs:387-394  *)
(*   Note      wanted lowered to the need (one CAS)   budget.rs:399-404  *)
(*   Try2      the last try_take                      budget.rs:405      *)
(*   Register  wake_when_freed, with waiters locked   budget.rs:324-340  *)
(*   Rel1      release: fetch_sub of used             budget.rs:426      *)
(*   Rel2      release: wanted cleared if room ≥ it   budget.rs:428-433  *)
(*   Rel3      release: wakes += 1, waiters taken,                       *)
(*             with waiters locked                    budget.rs:437-441  *)
(*   Rel4      release: each taken waiter woken       budget.rs:442-444  *)
(*                                                                       *)
(* A runner (a stack's runner, or Children for one child) marks, charges *)
(* its need, and if refused registers its waiter and sleeps until woken; *)
(* then it marks and tries again. Once charged it holds the bytes for a  *)
(* while and releases them, and goes round again, `Rounds` times in all. *)
(* Runners hold nothing between rounds, so every runner whose need fits  *)
(* the limit can be served.                                              *)
(*                                                                       *)
(* `refused` and `wakes` are counters in the code, read only to compare  *)
(* with a mark; here each runner keeps what the comparison would say     *)
(* (refusedSince, wokenSince), which keeps the state space finite.      *)
(* Register is one step: the code holds the waiters' lock across it, and *)
(* the steps it races with (Rel2, a charge) are lock-free, so reading    *)
(* wanted, wakes and room in one step only hides interleavings among     *)
(* those three reads, in which a later read sees a later release.        *)
(*                                                                       *)
(* Four runners, a to d, each with a need of its own; d's may pass the    *)
(* limit. Two specifications: Spec, where every runner holds its bytes   *)
(* only for a while (weak fairness of every step), for AllServed; and    *)
(* SpinSpec, where a runner may hold its bytes for ever (no fairness on  *)
(* Hold), as a long-lived connection holds memory, for NoSpin.           *)
(*                                                                       *)
(* Flags keep a part of the code as it is (TRUE) or break it (FALSE):    *)
(*   LastTry   take_with tries once more after noting its need           *)
(*   RoomCheck Register wakes at once when the room already covers the   *)
(*             least refused need                                        *)
(*   WokenMark Register wakes at once when a release woke since the mark *)
(*   OwedWake  in the RoomCheck case, Register pays the wake a release   *)
(*             owed: clears wanted, wakes += 1 and wakes the list too.   *)
(*             FALSE is the code before this model (budget.rs at         *)
(*             3db7a847e), which woke only the registering runner.       *)
EXTENDS Integers, FiniteSets

CONSTANTS NeedA, NeedB, NeedC, NeedD,  \* each runner's need, every round
          Limit,    \* the budget's limit
          Rounds,   \* how many times each runner charges and releases
          LastTry, RoomCheck, WokenMark, OwedWake

Runners == {"a", "b", "c", "d"}
Need == [r \in Runners |-> CASE r = "a" -> NeedA [] r = "b" -> NeedB
                              [] r = "c" -> NeedC [] r = "d" -> NeedD]

ASSUME \A r \in Runners : Need[r] \in Nat \ {0}
ASSUME Limit \in Nat /\ Rounds \in Nat \ {0}

VARIABLES
  used,         \* BudgetInner::used
  wanted,       \* BudgetInner::wanted, 0 for none
  waiters,      \* BudgetInner::waiters, the runners on the list
  pc,           \* each runner's place
  refusedSince, \* view.refused != mark.refused
  starvedSince, \* view.starved > mark.refused
  wokenSince,   \* inner.wakes != mark.wakes
  woken,        \* a wake reached the runner's waiter and it will run
  taken,        \* the waiters a release took, to wake in Rel4
  relRoom,      \* the room a release computed from its fetch_sub
  left,         \* rounds still to run
  frees         \* releases so far, mod 2: changes at every Rel1

vars == <<used, wanted, waiters, pc, refusedSince, starvedSince, wokenSince,
          woken, taken, relRoom, left, frees>>

Room == Limit - used

TypeOK ==
  /\ used \in 0..Limit
  /\ wanted \in 0..Limit
  /\ waiters \subseteq Runners
  /\ pc \in [Runners -> {"mark", "try1", "note", "try2", "register", "sleep",
                         "hold", "rel1", "rel2", "rel3", "rel4", "next", "done",
                         "starved"}]

Init ==
  /\ used = 0 /\ wanted = 0 /\ waiters = {}
  /\ pc = [r \in Runners |-> "mark"]
  /\ refusedSince = [r \in Runners |-> FALSE]
  /\ starvedSince = [r \in Runners |-> FALSE]
  /\ wokenSince = [r \in Runners |-> FALSE]
  /\ woken = [r \in Runners |-> FALSE]
  /\ taken = [r \in Runners |-> {}]
  /\ relRoom = [r \in Runners |-> 0]
  /\ left = [r \in Runners |-> Rounds]
  /\ frees = 0

Go(r, to) == pc' = [pc EXCEPT ![r] = to]

(* Budget::refusals: the mark the runner compares with after its round. *)
Mark(r) ==
  /\ pc[r] = "mark"
  /\ refusedSince' = [refusedSince EXCEPT ![r] = FALSE]
  /\ starvedSince' = [starvedSince EXCEPT ![r] = FALSE]
  /\ wokenSince' = [wokenSince EXCEPT ![r] = FALSE]
  /\ Go(r, "try1")
  /\ UNCHANGED <<used, wanted, waiters, woken, taken, relRoom, left, frees>>

(* The first try_take, and on refusal the count and, for a need past the *)
(* limit, the Starved record: that refusal ends the round, notes no need *)
(* and is never woken for.                                               *)
Try1(r) ==
  /\ pc[r] = "try1"
  /\ IF Need[r] <= Room
     THEN /\ used' = used + Need[r] /\ Go(r, "hold")
          /\ UNCHANGED <<refusedSince, starvedSince>>
     ELSE /\ refusedSince' = [refusedSince EXCEPT ![r] = TRUE]
          /\ IF Need[r] > Limit
             THEN /\ starvedSince' = [starvedSince EXCEPT ![r] = TRUE]
                  /\ Go(r, "register")
             ELSE /\ Go(r, "note") /\ UNCHANGED starvedSince
          /\ UNCHANGED used
  /\ UNCHANGED <<wanted, waiters, wokenSince, woken, taken, relRoom, left, frees>>

Note(r) ==
  /\ pc[r] = "note"
  /\ wanted' = IF wanted = 0 \/ Need[r] < wanted THEN Need[r] ELSE wanted
  /\ Go(r, IF LastTry THEN "try2" ELSE "register")
  /\ UNCHANGED <<used, waiters, refusedSince, starvedSince, wokenSince, woken, taken,
                 relRoom, left, frees>>

Try2(r) ==
  /\ pc[r] = "try2"
  /\ IF Need[r] <= Room
     THEN used' = used + Need[r] /\ Go(r, "hold")
     ELSE UNCHANGED used /\ Go(r, "register")
  /\ UNCHANGED <<wanted, waiters, refusedSince, starvedSince, wokenSince, woken, taken,
                 relRoom, left, frees>>

(* Wakes each waiter in S: sets its wake. A runner that is not asleep    *)
(* yet keeps the wake for its next sleep, as a Waker that is woken       *)
(* before its task sleeps gets the task polled again.                    *)
WakeAll(S) == [w \in Runners |-> IF w \in S THEN TRUE ELSE woken[w]]

(* Budget::wake_when_freed, with the waiters locked.                     *)
Register(r) ==
  /\ pc[r] = "register"
  /\ IF ~refusedSince[r]
     THEN /\ Go(r, "mark")   \* not reached: Register follows a refusal
          /\ UNCHANGED <<wanted, waiters, wokenSince, woken>>
     ELSE IF starvedSince[r]
     THEN /\ Go(r, "starved")  \* the runner ends: Starved
          /\ UNCHANGED <<wanted, waiters, wokenSince, woken>>
     ELSE IF (WokenMark /\ wokenSince[r]) \/ wanted = 0
     THEN /\ woken' = [woken EXCEPT ![r] = TRUE] /\ Go(r, "sleep")
          /\ UNCHANGED <<wanted, waiters, wokenSince>>
     ELSE IF RoomCheck /\ Room >= wanted
     THEN IF OwedWake
          THEN \* the wake a release owed: what Rel2..Rel4 would have done
               /\ wanted' = 0
               /\ wokenSince' = [w \in Runners |-> TRUE]
               /\ waiters' = {}
               /\ woken' = [WakeAll(waiters) EXCEPT ![r] = TRUE]
               /\ Go(r, "sleep")
          ELSE /\ woken' = [woken EXCEPT ![r] = TRUE] /\ Go(r, "sleep")
               /\ UNCHANGED <<wanted, waiters, wokenSince>>
     ELSE /\ waiters' = waiters \cup {r} /\ Go(r, "sleep")
          /\ UNCHANGED <<wanted, wokenSince, woken>>
  /\ UNCHANGED <<used, refusedSince, starvedSince, taken, relRoom, left, frees>>

(* The runner is polled again once its waiter was woken.                 *)
Wake(r) ==
  /\ pc[r] = "sleep" /\ woken[r]
  /\ woken' = [woken EXCEPT ![r] = FALSE]
  /\ Go(r, "mark")
  /\ UNCHANGED <<used, wanted, waiters, refusedSince, starvedSince, wokenSince, taken,
                 relRoom, left, frees>>

(* Holding the bytes for a while, then the release, step by step.        *)
Hold(r) ==
  /\ pc[r] = "hold" /\ Go(r, "rel1")
  /\ UNCHANGED <<used, wanted, waiters, refusedSince, starvedSince, wokenSince, woken,
                 taken, relRoom, left, frees>>

Rel1(r) ==
  /\ pc[r] = "rel1"
  /\ used' = used - Need[r]
  /\ relRoom' = [relRoom EXCEPT ![r] = Limit - (used - Need[r])]
  /\ frees' = 1 - frees
  /\ Go(r, "rel2")
  /\ UNCHANGED <<wanted, waiters, refusedSince, starvedSince, wokenSince, woken, taken,
                 left>>

Rel2(r) ==
  /\ pc[r] = "rel2"
  /\ IF wanted # 0 /\ wanted <= relRoom[r]
     THEN wanted' = 0 /\ Go(r, "rel3")
     ELSE UNCHANGED wanted /\ Go(r, "next")
  /\ UNCHANGED <<used, waiters, refusedSince, starvedSince, wokenSince, woken, taken,
                 relRoom, left, frees>>

Rel3(r) ==
  /\ pc[r] = "rel3"
  /\ wokenSince' = [w \in Runners |-> TRUE]
  /\ taken' = [taken EXCEPT ![r] = waiters]
  /\ waiters' = {}
  /\ Go(r, "rel4")
  /\ UNCHANGED <<used, wanted, refusedSince, starvedSince, woken, relRoom, left, frees>>

Rel4(r) ==
  /\ pc[r] = "rel4"
  /\ woken' = WakeAll(taken[r])
  /\ taken' = [taken EXCEPT ![r] = {}]
  /\ Go(r, "next")
  /\ UNCHANGED <<used, wanted, waiters, refusedSince, starvedSince, wokenSince, relRoom,
                 left, frees>>

NextRound(r) ==
  /\ pc[r] = "next"
  /\ left' = [left EXCEPT ![r] = @ - 1]
  /\ Go(r, IF left[r] > 1 THEN "mark" ELSE "done")
  /\ UNCHANGED <<used, wanted, waiters, refusedSince, starvedSince, wokenSince, woken,
                 taken, relRoom, frees>>

Step(r) ==
  \/ Mark(r) \/ Try1(r) \/ Note(r) \/ Try2(r) \/ Register(r) \/ Wake(r)
  \/ Hold(r) \/ Rel1(r) \/ Rel2(r) \/ Rel3(r) \/ Rel4(r) \/ NextRound(r)

Next == \E r \in Runners : Step(r)

Spec == Init /\ [][Next]_vars /\ \A r \in Runners : WF_vars(Step(r))

(* A runner may hold its bytes for ever: every step but Hold is fair.    *)
SpinSpec == Init /\ [][Next]_vars
            /\ \A r \in Runners : WF_vars(Step(r) /\ pc[r] # "hold")

----------------------------------------------------------------------------
(* Properties *)

(* Memory is never passed: the count stays within the limit.             *)
WithinLimit == used <= Limit

(* A need past the limit is never waited for: its runner ends, never     *)
(* joins the list and never lowers the least refused need.               *)
StarvedNeverWaits ==
  \A r \in Runners :
    /\ (pc[r] = "starved" => r \notin waiters)
    /\ (Need[r] > Limit => wanted # Need[r])

(* No lost wake: every runner whose need fits the limit is served all its *)
(* rounds, whatever the others charge and release around it; one whose   *)
(* need passes the limit ends as starved. A refused runner left asleep   *)
(* while memory for it frees would stop here.                            *)
AllServed ==
  <>(\A r \in Runners : pc[r] = IF Need[r] <= Limit THEN "done" ELSE "starved")

(* No lost wake, even while others hold memory for ever (SpinSpec): a     *)
(* runner whose need fits is never left asleep for good while the room   *)
(* covers its need. AllServed cannot see a wake that comes only with a   *)
(* later, unrelated release; this can.                                   *)
WakeWhenRoom ==
  \A r \in Runners :
    Need[r] <= Limit => ~<>[](pc[r] = "sleep" /\ Room >= Need[r])

(* No spin: a runner is not woken over and over while nothing frees. A   *)
(* wake that a release did not cause, repeated for ever with no release, *)
(* is a runner that polls in a loop.                                     *)
NoSpin ==
  \A r \in Runners :
    ([]<><<Wake(r)>>_vars) => ([]<><<\E w \in Runners : Rel1(w)>>_vars)
=============================================================================
