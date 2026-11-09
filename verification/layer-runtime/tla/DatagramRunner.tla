--------------------------- MODULE DatagramRunner ---------------------------
(* `services::stack::datagrams` (src/stdlib/services/stack/mod.rs:319-342, *)
(* `run_datagrams` at 344-475): one layer stack holds a UDP socket's       *)
(* conversation for the socket's whole life. One iteration of its `loop`  *)
(* (mod.rs:361-474) is SettleRound* (the `for _ in 0..FAIR` rounds at      *)
(* 375-405), AfterSettle (406-420), and Wait (422-473). Line numbers are   *)
(* those of commit e2858ccc4.                                              *)
(*                                                                         *)
(* The stack asks for no work: the `jobs` of the runner stay empty, so    *)
(* `jobs.is_empty()` holds wherever the code asks it, `jobs.poll` (mod.rs: *)
(* 367-372, 435-437) and `jobs.take` (377) move nothing, and the           *)
(* `jobs.close_completed()` calls (363-365, 409, 432-434) do nothing.      *)
(*                                                                         *)
(* The stack is abstract, with the shape of the Search time server         *)
(* (demos/search/world/src/ntp.rs:74-129): it answers a datagram it takes  *)
(* with at most one reply. The time server refuses the next datagram      *)
(* (`Blocked`) while a reply waits to be taken, but under this runner a   *)
(* reply never waits: the sink takes every Send at once (mod.rs:391-395), *)
(* so `outq` is empty at the start of every round and that refusal does   *)
(* not arise here (the Kani harness                                        *)
(* `one_conversation_answers_each_request_in_turn` exercises it on the    *)
(* real server). The refusal this model exercises is the pause below.     *)
(* It may also arm a timer on a datagram whose                             *)
(* firing sends one more datagram, may close the socket itself            *)
(* (DatagramCommand::End), and when it hears that the socket closed it     *)
(* has `Backlog` replies left to send, one per step of its own, as a stack *)
(* that drains a queue through one slot does. Datagrams are numbered in    *)
(* the order they reach the socket.                                        *)
(*                                                                         *)
(* The switches are the rules of the code. TRUE is the code as it is,      *)
(* including `SettleBeforeClose`, the fix of comp/v-framed's commit        *)
(* 1a183c83e, ported to the split runner in 33fd898e0.                    *)
(* The explicit allocation budget (the charge of a received datagram's   *)
(* capacity at mod.rs:454-457, whose refusal ends the run with           *)
(* StackError::Budget), per-job cancellable regions and the cancel checks *)
(* (mod.rs:411-413, 429-431, 467) are outside this model. Datagrams are   *)
(* atomic numbered items here. The production runner polls jobs during   *)
(* busy visits as well as waits, and gives completions directly to the   *)
(* driver without an intermediate result vector. Runtime tests cover     *)
(* those resource and work paths.                                        *)
EXTENDS Integers, Sequences

CONSTANTS Datagrams,      \* datagrams that reach the socket in all
          Backlog,        \* replies the stack still sends after it hears Ended
          Fair,           \* FAIR (mod.rs:68): rounds before the runner yields
          Delay,          \* ticks of the stack's timer; 0 for no timer
          StackMayEnd,    \* the stack may close the socket itself
          ReceiveOnlyWhenTaken, \* `receive = input.is_none() && ..` (mod.rs:424)
          OneConversation,      \* one stack for the socket's life: one `Driver::new` before the loop (mod.rs:356)
          DeadlineInWait,       \* the wait sleeps until the stack's deadline (mod.rs:422, 426, 441-446)
          EndClosesOutput,      \* `_ if ended => Admit::Closed` (mod.rs:390)
          SendEachDatagram,     \* `socket.send_to(&payload, to)` (mod.rs:393)
          ReturnOnClose,        \* `socket_closed && input.is_none()` returns (mod.rs:408)
          SettleBeforeClose     \* return on a closed socket only once settled (`settled &&` at mod.rs:408, the fix)

ASSUME Datagrams \in Nat /\ Backlog \in Nat /\ Fair \in Nat \ {0} /\ Delay \in Nat

None == -1
END == -2    \* DatagramCommand::End in the stack's output
TICK == -3   \* the datagram the stack's timer sends

VARIABLES pc,          \* "settle", "after", "wait" or "done"
          now,
          input,       \* `input`: None, a datagram's number, or 0 for DatagramEvent::Ended
          socketClosed,\* `socket_closed`
          ended,       \* the `ended` of this iteration (mod.rs:373)
          rounds,      \* rounds of the current `settle`
          settled,     \* what `settle` returned
          \* the socket
          arrived,     \* datagrams that reached the socket
          queue,       \* those not yet received, in order
          closed,      \* the socket is closed: `recv` answers Closed once the queue is empty
          \* the stack
          seen,        \* datagrams the stack took, in order
          outq,        \* output it has not handed down: replies, END, TICK
          owe,         \* replies it still has to queue after the socket closed
          heardEnded,
          timer,       \* when its timer is due, or None
          paused,      \* it refuses datagrams until that timer goes off
          \* history
          produced,    \* everything the stack queued, in order
          sent,        \* what went to the socket, in order
          afterEnd     \* a datagram went out after the stack closed the socket

vars == <<pc, now, input, socketClosed, ended, rounds, settled, arrived, queue, closed,
          seen, outq, owe, heardEnded, timer, paused, produced, sent, afterEnd>>

Upto(n) == [i \in 1..n |-> i]

TypeOK ==
  /\ pc \in {"settle", "after", "wait", "done"}
  /\ input \in {None, 0} \cup 1..Datagrams
  /\ rounds \in 0..Fair /\ arrived \in 0..Datagrams /\ owe \in 0..Backlog

Init ==
  /\ pc = "settle" /\ now = 0 /\ input = None /\ socketClosed = FALSE /\ ended = FALSE
  /\ rounds = 0 /\ settled = TRUE
  /\ arrived = 0 /\ queue = <<>> /\ closed = FALSE
  /\ seen = <<>> /\ outq = <<>> /\ owe = 0 /\ heardEnded = FALSE /\ timer = None
  /\ paused = FALSE
  /\ produced = <<>> /\ sent = <<>> /\ afterEnd = FALSE

(* `Driver::send_below` with the sink of mod.rs:389-400: it takes the      *)
(* stack's output in order until there is none; after END, the rest is     *)
(* refused as closed.                                                      *)
RECURSIVE Drain(_, _, _, _)
Drain(q, s, e, bad) ==
  IF q = <<>> THEN [s |-> s, e |-> e, bad |-> bad]
  ELSE IF Head(q) = END THEN Drain(Tail(q), s, TRUE, bad)
  ELSE IF e /\ EndClosesOutput THEN Drain(Tail(q), s, e, bad)
  ELSE IF ~SendEachDatagram THEN Drain(Tail(q), s, e, bad)
  ELSE Drain(Tail(q), Append(s, Head(q)), e, bad \/ e)

(* One round (mod.rs:376-404): the offer of the held input, then          *)
(* `Driver::run` (due timer first, then one step of the stack's own),     *)
(* then `send_below`, which takes everything the stack has. Because it    *)
(* does, `outq` is always <<>> when a round starts, and `blocked` below   *)
(* reduces to the pause.                                                  *)
SettleRound ==
  /\ pc = "settle"
  /\ \E answers, pause \in BOOLEAN, arm \in (IF Delay > 0 /\ timer = None THEN BOOLEAN ELSE {FALSE}),
        bye \in (IF StackMayEnd THEN BOOLEAN ELSE {FALSE}) :
     LET isDg == input \notin {None, 0}
         blocked == isDg /\ ~heardEnded /\ (outq # <<>> \/ paused)
         takes == isDg /\ ~heardEnded /\ ~blocked
         \* A fresh stack per datagram knows nothing of the ones before.
         seen1 == IF takes THEN (IF OneConversation THEN Append(seen, input) ELSE <<input>>)
                  ELSE seen
         reply == IF takes /\ answers THEN <<input>> ELSE <<>>
         goodbye == IF takes /\ bye THEN <<END, TICK>> ELSE <<>>
         q1 == outq \o reply \o goodbye
         timer1 == IF takes /\ ~OneConversation THEN (IF arm THEN now + Delay ELSE None)
                   ELSE IF takes /\ arm THEN now + Delay ELSE timer
         ended1 == heardEnded \/ input = 0
         owe1 == IF input = 0 /\ ~heardEnded THEN Backlog ELSE owe
         m1 == input # None /\ ~blocked
         \* Driver::run
         fires == timer1 # None /\ timer1 <= now
         q2 == IF fires THEN <<TICK>> ELSE <<>>
         step == ~fires /\ owe1 > 0
         q3 == IF step THEN <<owe1>> ELSE <<>>
         \* send_below
         d == Drain(q1 \o q2 \o q3, sent, ended, afterEnd)
         m2 == q1 \o q2 \o q3 # <<>>
         moved == m1 \/ m2 \/ fires \/ step
     IN
     /\ input' = IF blocked THEN input ELSE None
     /\ seen' = seen1
     /\ heardEnded' = ended1
     /\ sent' = d.s /\ ended' = d.e /\ afterEnd' = d.bad
     /\ outq' = <<>>
     /\ produced' = produced \o reply \o goodbye \o q2 \o q3
     /\ timer' = IF fires THEN None ELSE timer1
     /\ paused' = IF fires THEN FALSE ELSE IF takes /\ arm THEN pause
                  ELSE IF takes /\ ~OneConversation THEN FALSE ELSE paused
     /\ owe' = IF step THEN owe1 - 1 ELSE owe1
     /\ IF ~moved
        THEN /\ settled' = TRUE /\ rounds' = 0 /\ pc' = "after"
        ELSE IF rounds + 1 = Fair
        THEN /\ settled' = FALSE /\ rounds' = 0 /\ pc' = "after"
        ELSE /\ rounds' = rounds + 1 /\ UNCHANGED settled /\ UNCHANGED pc
  /\ UNCHANGED <<now, socketClosed, arrived, queue, closed>>

(* mod.rs:406-420. A runner that has not settled yields and settles       *)
(* again.                                                                 *)
AfterSettle ==
  /\ pc = "after"
  /\ pc' = IF ended \/ (ReturnOnClose /\ socketClosed /\ input = None
                         /\ (settled \/ ~SettleBeforeClose))
           THEN "done"
           ELSE IF ~settled THEN "settle"
           ELSE "wait"
  /\ ended' = FALSE
  /\ UNCHANGED <<now, input, socketClosed, rounds, settled, arrived, queue, closed, seen,
                 outq, owe, heardEnded, timer, paused, produced, sent, afterEnd>>

Receiving == ~socketClosed /\ (input = None \/ ~ReceiveOnlyWhenTaken)

(* The `poll_fn` of mod.rs:428-450 and what follows it (452-473).         *)
Wait ==
  /\ pc = "wait"
  /\ LET due == DeadlineInWait /\ timer # None /\ now >= timer
         gotDg == Receiving /\ queue # <<>>
         gotClose == Receiving /\ queue = <<>> /\ closed
     IN
     /\ gotDg \/ gotClose \/ due
     /\ IF gotDg
        THEN /\ input' = Head(queue) /\ queue' = Tail(queue)
             /\ UNCHANGED socketClosed
        ELSE IF gotClose
        THEN /\ input' = 0 /\ socketClosed' = TRUE /\ UNCHANGED queue
        ELSE UNCHANGED <<input, socketClosed, queue>>
     /\ pc' = "settle"
  /\ UNCHANGED <<now, ended, rounds, settled, arrived, closed, seen, outq, owe, heardEnded,
                 timer, paused, produced, sent, afterEnd>>

(* The environment: datagrams reach the socket, the socket closes, time   *)
(* passes while the runner waits on a deadline.                           *)
Arrive ==
  /\ arrived < Datagrams /\ ~closed
  /\ arrived' = arrived + 1 /\ queue' = Append(queue, arrived + 1)
  /\ UNCHANGED <<pc, now, input, socketClosed, ended, rounds, settled, closed, seen, outq,
                 owe, heardEnded, timer, paused, produced, sent, afterEnd>>

Close ==
  /\ ~closed /\ closed' = TRUE
  /\ UNCHANGED <<pc, now, input, socketClosed, ended, rounds, settled, arrived, queue, seen,
                 outq, owe, heardEnded, timer, paused, produced, sent, afterEnd>>

Tick ==
  /\ pc = "wait" /\ timer # None /\ now < timer
  /\ now' = now + 1
  /\ UNCHANGED <<pc, input, socketClosed, ended, rounds, settled, arrived, queue, closed,
                 seen, outq, owe, heardEnded, timer, paused, produced, sent, afterEnd>>

Next == SettleRound \/ AfterSettle \/ Wait \/ Arrive \/ Close \/ Tick

Spec == Init /\ [][Next]_vars
        /\ WF_vars(SettleRound) /\ WF_vars(AfterSettle) /\ WF_vars(Wait) /\ WF_vars(Tick)

----------------------------------------------------------------------------
(* Properties *)

Pending == IF input \notin {None, 0} THEN <<input>> ELSE <<>>

(* One conversation: the stack has taken every datagram the socket got,  *)
(* in order, each once, except the one it holds and those still queued.  *)
InOrderOnce == pc # "done" => seen \o Pending \o queue = Upto(arrived)

(* Each datagram the stack hands down goes to the socket at once, once,  *)
(* in order.                                                             *)
SentInOrder ==
  (pc # "done" /\ ~ended) => sent \o outq = SelectSeq(produced, LAMBDA x : x # END)

(* Nothing goes out after the stack closed the socket.                   *)
NothingAfterEnd == ~afterEnd

(* When the socket closes, the stack hears Ended and sends everything it *)
(* still has before the runner returns.                                  *)
CloseFlushes ==
  (pc = "done" /\ socketClosed /\ ~ended) => heardEnded /\ outq = <<>> /\ owe = 0

(* A timer the stack armed goes off, even if no datagram comes.          *)
TimerFires == [](timer # None => <>(timer = None \/ pc = "done"))

(* Once the socket closes, the runner returns.                           *)
CloseEnds == [](closed => <>(pc = "done"))
=============================================================================
