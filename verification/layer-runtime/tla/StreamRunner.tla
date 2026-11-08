---------------------------- MODULE StreamRunner ----------------------------
(* `services::stack::stream` in src/stdlib/services/stack.rs: the loop      *)
(* that reads a live connection into a layer stack's byte stream and       *)
(* writes what the stack gives back. One iteration of its `loop` is        *)
(* Settle* (stack.rs:179-204, `settle` at 362-385), Check (205-247),       *)
(* Poll (the `poll_fn` at 248-318, then 320-355). `EndBroken` is           *)
(* `end_broken` (388-400). The `Driver` (src/stdlib/layer/driver.rs)       *)
(* holds at most one command below (`held`), as `Driver::send_below` and   *)
(* `send` (driver.rs:180-244) do.                                          *)
(*                                                                         *)
(* The stack is abstract: an echo with room for `Room` bytes of input that *)
(* it moves to its output when it runs, asks to end its direction once it  *)
(* heard the end of its input, may refuse input for `Pause` ticks on a     *)
(* timer of its own, and may ask for a reset. That is the shape of         *)
(* `Chain<Framed, PlcServer>`, plus the timer and the reset that other     *)
(* stacks have. Bytes are counted, not carried. Time is in ticks.          *)
(*                                                                         *)
(* The switches are the rules of the code. TRUE is the code as it is,      *)
(* including `RestartIdleOnWait`, the fix of commit 1a183c83e; the       *)
(* `_without_` configs turn one off and name the property that must fail.  *)
EXTENDS Integers

CONSTANTS PeerBytes,      \* bytes the peer sends in all
          Room,           \* bytes the stack takes before it must run
          Idle,           \* StreamLimits::idle, in ticks, or NoLimit
          WriteTimeout,   \* StreamLimits::write_timeout, in ticks, or NoLimit
          Pause,          \* ticks the stack may refuse input on its own timer; 0 for never
          StackMayReset,  \* the stack may hand down StreamCommand::Reset
          StackMayEndEarly, \* the stack may end its direction before its input is over
          PeerMayReset,   \* the peer may reset the connection
          PeerMayStall,   \* the peer may stop reading: its transport takes no more bytes
          BudgetMayFail,  \* a read's charge may not fit (stack.rs:333)
          ReadOnlyWhenTakenRule, \* `reading` needs `input.is_none()` (stack.rs:227)
          ReportOnceRule,        \* `written = 0` once delivered (stack.rs:185)
          StallResetOnProgress,  \* `stalled_since = None` on bytes taken (stack.rs:323)
          IdleResetOnRead,       \* `idle_from = now` on bytes read (stack.rs:340)
          ResetOnBreak,          \* `end_broken` offers StreamEvent::Reset (stack.rs:394-398)
          WriteBeforeEnd,        \* the layer hands writes before its End (framed.rs:183-195)
          KeepPartialRest,       \* `Admit::Partial(rest) => input = Some(rest)` (stack.rs:195)
          FinishNeedsInputOver,  \* `if shut && input_over` (stack.rs:210)
          RestartIdleOnWait      \* restart `idle_from` when waiting resumes (stack.rs:229-233, the fix)

ASSUME PeerBytes \in Nat /\ Room \in Nat \ {0} /\ Pause \in Nat
NoLimit == -1  \* stands for `None`; set a limit to it with `<- NoLimit`
ASSUME Idle \in Nat \cup {NoLimit} /\ WriteTimeout \in Nat \cup {NoLimit}

None == -1

VARIABLES pc,          \* "settle", "check", "poll" or "done"
          now,         \* fcx.now()
          inKind, inN, \* `input`: "none", "data" with inN bytes, or "ended"
          written,     \* `written`: taken by the transport, not yet reported
          inputOver,   \* `input_over`
          shut,        \* `shut`
          idled,       \* `idled`
          idleFrom,    \* `idle_from`
          stalledSince,\* `stalled_since`, or None
          deadline,    \* the deadline the wait sleeps until, or None
          hKind, hN,   \* `Driver::below`: "none", "write" of hN bytes, "end" or "reset"
          ret,         \* what `stream` returned, once pc = "done"
          \* the abstract stack
          sbuf,        \* input taken and not yet run
          sout,        \* output queued in the stack, not yet handed down
          sEnd,        \* "no", "asked" or "given": its MessageCommand::End through Framed
          sReset,      \* "no", "asked" or "given"
          sOver,       \* its input is over: it answers Closed
          heardEnded,  \* it took StreamEvent::Ended
          heardReset,  \* it took StreamEvent::Reset
          sTimer,      \* its timer, or None; while armed it refuses input
          pausesLeft,
          \* the peer
          peerLeft,    \* bytes the peer has yet to send
          peerFin,     \* the peer ends its direction after them
          gone,        \* the peer reset the connection
          peerStalled, \* the peer stopped reading for good
          \* history, for the properties
          readTotal,   \* bytes read from the connection
          took,        \* bytes the stack took
          refused,     \* bytes the stack refused as Closed
          transportTook, \* bytes the transport took
          reported,    \* bytes reported to the stack as Written
          stackOut,    \* bytes the stack handed down in writes
          offeredReset,\* times the runner offered StreamEvent::Reset
          badRead,     \* a read happened while input was held or over
          wasWaiting, quietFrom, earlyIdle,
          wasHolding, stuckFrom, earlyStall

runner == <<pc, now, inKind, inN, written, inputOver, shut, idled, idleFrom, stalledSince,
            deadline, hKind, hN, ret>>
stack == <<sbuf, sout, sEnd, sReset, sOver, heardEnded, heardReset, sTimer, pausesLeft>>
peer == <<peerLeft, peerFin, gone, peerStalled>>
hist == <<readTotal, took, refused, transportTook, reported, stackOut, offeredReset, badRead,
          wasWaiting, quietFrom, earlyIdle, wasHolding, stuckFrom, earlyStall>>
vars == <<runner, stack, peer, hist>>

Min(a, b) == IF a < b THEN a ELSE b
MinOf(S) == CHOOSE x \in S : \A y \in S : x <= y

TypeOK ==
  /\ pc \in {"settle", "check", "poll", "done"}
  /\ inKind \in {"none", "data", "ended"} /\ inN \in 0..PeerBytes
  /\ hKind \in {"none", "write", "end", "reset"}
  /\ sEnd \in {"no", "asked", "given"} /\ sReset \in {"no", "asked", "given"}
  /\ ret \in {"none", "finished", "idle", "reset", "budget", "conn"}
  /\ written \in Nat /\ sbuf \in 0..Room /\ offeredReset \in 0..1

Init ==
  /\ pc = "settle" /\ now = 0
  /\ inKind = "none" /\ inN = 0 /\ written = 0
  /\ inputOver = FALSE /\ shut = FALSE /\ idled = FALSE
  /\ idleFrom = 0 /\ stalledSince = None /\ deadline = None
  /\ hKind = "none" /\ hN = 0 /\ ret = "none"
  /\ sbuf = 0 /\ sout = 0 /\ sEnd = "no" /\ sReset = "no" /\ sOver = FALSE
  /\ heardEnded = FALSE /\ heardReset = FALSE /\ sTimer = None
  /\ pausesLeft = IF Pause > 0 THEN 1 ELSE 0
  /\ peerLeft \in 0..PeerBytes /\ peerFin \in BOOLEAN /\ gone = FALSE
  /\ peerStalled \in (IF PeerMayStall THEN BOOLEAN ELSE {FALSE})
  /\ readTotal = 0 /\ took = 0 /\ refused = 0 /\ transportTook = 0 /\ reported = 0
  /\ stackOut = 0 /\ offeredReset = 0 /\ badRead = FALSE
  /\ wasWaiting = FALSE /\ quietFrom = 0 /\ earlyIdle = FALSE
  /\ wasHolding = FALSE /\ stuckFrom = 0 /\ earlyStall = FALSE

(* The stack's `take_command`, through Framed: writes first, then its     *)
(* reset or end (framed.rs:183-195). Nothing after it heard a reset.      *)
NextCmd(o, e, r, hr) ==
  IF hr THEN "none"
  ELSE IF o > 0 /\ (WriteBeforeEnd \/ e # "asked") THEN "write"
  ELSE IF r = "asked" THEN "reset"
  ELSE IF e = "asked" THEN "end"
  ELSE "none"

(* `end_broken` (stack.rs:388-400): the stack is offered a reset, which   *)
(* Framed takes unless its input is over (framed.rs:123, 145-150), and    *)
(* the runner returns.                                                    *)
EndBroken(why) ==
  /\ offeredReset' = IF ResetOnBreak THEN offeredReset + 1 ELSE offeredReset
  /\ heardReset' = (heardReset \/ (ResetOnBreak /\ ~sOver))
  /\ sOver' = (sOver \/ ResetOnBreak)
  /\ pc' = "done" /\ ret' = why

(* One round of `settle` (stack.rs:362-385) with the offer of stack.rs:   *)
(* 180-203: the write report, the held input, then `Driver::run`.         *)
Settle ==
  /\ pc = "settle"
  /\ LET m1 == written > 0
     IN
     /\ reported' = IF m1 THEN reported + written ELSE reported
     /\ written' = IF m1 /\ ReportOnceRule THEN 0 ELSE written
     /\ \E arm \in (IF pausesLeft > 0 THEN BOOLEAN ELSE {FALSE}),
           askReset \in (IF StackMayReset /\ sReset = "no" /\ ~heardReset THEN BOOLEAN ELSE {FALSE}),
           early \in (IF StackMayEndEarly /\ sEnd = "no" /\ ~heardReset THEN BOOLEAN ELSE {FALSE}) :
        \* The offer of the held input.
        LET blocked == inKind = "data" /\ ~sOver /\ (sTimer # None \/ sbuf = Room)
            closed == inKind # "none" /\ sOver
            j == IF inKind = "data" /\ ~sOver /\ ~blocked THEN Min(inN, Room - sbuf) ELSE 0
            m2 == inKind # "none" /\ ~blocked
            arms == arm /\ j > 0
            sbuf1 == sbuf + j
            sTimer1 == IF arms THEN now + Pause ELSE sTimer
            ended1 == heardEnded \/ (inKind = "ended" /\ ~sOver)
            over1 == sOver \/ (inKind = "ended")
            \* `Driver::run`: due timers first, then the stack's own steps.
            fires == sTimer1 # None /\ sTimer1 <= now
            askEnd == (ended1 \/ early) /\ sEnd = "no" /\ ~heardReset
            runMoved == fires \/ sbuf1 > 0 \/ askEnd \/ askReset
        IN
        /\ inKind' = IF closed THEN "none"
                     ELSE IF inKind = "ended" THEN "none"
                     ELSE IF inKind = "data" /\ ~blocked /\ j = inN THEN "none"
                     ELSE IF inKind = "data" /\ ~blocked /\ ~KeepPartialRest THEN "none"
                     ELSE inKind
        /\ inN' = IF inKind = "data" /\ ~closed /\ (blocked \/ KeepPartialRest)
                  THEN inN - j ELSE 0
        /\ inputOver' = (inputOver \/ closed \/ inKind = "ended")
        /\ refused' = IF closed /\ inKind = "data" THEN refused + inN ELSE refused
        /\ took' = took + j
        /\ heardEnded' = ended1
        /\ sOver' = over1
        /\ pausesLeft' = IF arms THEN pausesLeft - 1 ELSE pausesLeft
        /\ sTimer' = IF fires THEN None ELSE sTimer1
        \* After its End the stack's output is refused (framed.rs:159-160).
        /\ sout' = IF sEnd = "no" THEN sout + sbuf1 ELSE sout
        /\ sbuf' = 0
        /\ sEnd' = IF askEnd THEN "asked" ELSE sEnd
        /\ sReset' = IF askReset THEN "asked" ELSE sReset
        /\ pc' = IF m1 \/ m2 \/ runMoved THEN "settle" ELSE "check"
  /\ UNCHANGED <<now, shut, idled, idleFrom, stalledSince, deadline, hKind, hN, ret,
                 heardReset, peer, transportTook, stackOut, offeredReset, badRead, readTotal,
                 wasWaiting, quietFrom, earlyIdle, wasHolding, stuckFrom, earlyStall>>

(* stack.rs:210-247: the end, the write limit, the idle limit, and the    *)
(* deadline of the wait.                                                  *)
Check ==
  /\ pc = "check"
  /\ IF shut /\ (inputOver \/ ~FinishNeedsInputOver)
     THEN /\ pc' = "done" /\ ret' = IF idled THEN "idle" ELSE "finished"
          /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, idleFrom,
                         stalledSince, deadline, hKind, hN, stack, peer, hist>>
     ELSE
     LET holds == hKind # "none"
         since == IF holds THEN (IF stalledSince = None THEN now ELSE stalledSince) ELSE None
         timedOut == holds /\ WriteTimeout # NoLimit /\ now >= since + WriteTimeout
         reading == ~inputOver /\ (inKind = "none" \/ ~ReadOnlyWhenTakenRule)
         waiting == reading /\ ~holds
         resumes == waiting /\ ~wasWaiting
         from == IF RestartIdleOnWait /\ resumes THEN now ELSE idleFrom
         idleDue == waiting /\ Idle # NoLimit /\ now >= from + Idle
         quiet == IF resumes THEN now ELSE quietFrom
         stuck == IF holds /\ ~wasHolding THEN now ELSE stuckFrom
         dl == ({sTimer} \ {None})
               \cup (IF waiting /\ Idle # NoLimit THEN {from + Idle} ELSE {})
               \cup (IF since # None /\ WriteTimeout # NoLimit THEN {since + WriteTimeout} ELSE {})
     IN
     /\ stalledSince' = since /\ idleFrom' = from
     /\ wasWaiting' = waiting /\ quietFrom' = quiet
     /\ wasHolding' = holds /\ stuckFrom' = stuck
     /\ IF timedOut
        THEN /\ earlyStall' = (now - stuck < WriteTimeout)
             /\ EndBroken("conn")
             /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, deadline,
                            hKind, hN, sbuf, sout, sEnd, sReset, heardEnded, sTimer,
                            pausesLeft, peer, readTotal, took, refused, transportTook,
                            reported, stackOut, badRead, earlyIdle>>
        ELSE IF idleDue
        THEN /\ idled' = TRUE /\ inKind' = "ended" /\ inN' = 0
             /\ earlyIdle' = (earlyIdle \/ now - quiet < Idle)
             /\ pc' = "settle"
             /\ UNCHANGED <<now, written, inputOver, shut, deadline, hKind, hN, ret, stack,
                            peer, readTotal, took, refused, transportTook, reported, stackOut,
                            offeredReset, badRead, earlyStall>>
        ELSE /\ deadline' = IF dl = {} THEN None ELSE MinOf(dl)
             /\ pc' = "poll"
             /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, hKind, hN,
                            ret, stack, peer, readTotal, took, refused, transportTook,
                            reported, stackOut, offeredReset, badRead, earlyIdle, earlyStall>>

(* The `poll_fn` of stack.rs:254-316 begins with `Driver::send_below`     *)
(* (driver.rs:180-185) into the sink of stack.rs:259-297: `send`          *)
(* (driver.rs:214-244) offers the held command, or takes the next from    *)
(* the stack, until the sink hands one back. `ws` is what the transport   *)
(* answers to the first and the second write of this poll (a held write   *)
(* and then a new one), `sd` what it answers to the shutdown. A write     *)
(* that is ready takes at least one byte, as `Connection::poll_write`     *)
(* does for a non-empty buffer.                                           *)
RECURSIVE SendLoop(_, _, _, _)
SendLoop(st, ws, sd, fuel) ==
  IF fuel = 0 \/ st.stop THEN st
  ELSE
  LET first == st.hk = "none"
      k == IF first THEN NextCmd(st.o, st.e, st.r, heardReset) ELSE st.hk
  IN
  IF k = "none" THEN st
  ELSE
  LET n == IF first /\ k = "write" THEN st.o ELSE st.hn
      s1 == [st EXCEPT !.o = IF first /\ k = "write" THEN 0 ELSE @,
                       !.e = IF first /\ k = "end" THEN "given" ELSE @,
                       !.r = IF first /\ k = "reset" THEN "given" ELSE @,
                       !.out = IF first /\ k = "write" THEN @ + n ELSE @,
                       !.moved = @ \/ first,
                       !.hk = "none", !.hn = 0]
      closed == shut \/ st.pshut \/ st.preset \/ st.pfailed
      w == ws[IF st.wi > 2 THEN 2 ELSE st.wi]
  IN
  IF closed THEN SendLoop([s1 EXCEPT !.moved = TRUE], ws, sd, fuel - 1)
  ELSE CASE k = "write" ->
              CASE w = "pending" -> [s1 EXCEPT !.hk = "write", !.hn = n, !.stop = TRUE]
                [] w = "partial" /\ n > 1 ->
                     [s1 EXCEPT !.hk = "write", !.hn = n - 1, !.pw = @ + 1,
                                !.moved = TRUE, !.stop = TRUE]
                [] w = "error" ->
                     SendLoop([s1 EXCEPT !.pfailed = TRUE, !.moved = TRUE, !.wi = @ + 1],
                              ws, sd, fuel - 1)
                [] OTHER ->
                     SendLoop([s1 EXCEPT !.pw = @ + n, !.moved = TRUE, !.wi = @ + 1],
                              ws, sd, fuel - 1)
         [] k = "end" ->
              CASE sd = "pending" -> [s1 EXCEPT !.hk = "end", !.stop = TRUE]
                [] sd = "ok" -> SendLoop([s1 EXCEPT !.pshut = TRUE, !.moved = TRUE], ws, sd, fuel - 1)
                [] OTHER -> SendLoop([s1 EXCEPT !.pfailed = TRUE, !.moved = TRUE], ws, sd, fuel - 1)
         [] OTHER -> SendLoop([s1 EXCEPT !.preset = TRUE, !.moved = TRUE], ws, sd, fuel - 1)

Send(ws, sd) ==
  LET st == SendLoop([hk |-> hKind, hn |-> hN, o |-> sout, e |-> sEnd, r |-> sReset,
                      out |-> stackOut, pw |-> 0, pshut |-> FALSE, preset |-> FALSE,
                      pfailed |-> FALSE, moved |-> FALSE, wi |-> 1, stop |-> FALSE],
                     ws, sd, 5)
  IN [moved |-> st.moved, pw |-> st.pw, pshut |-> st.pshut, preset |-> st.preset,
      pfailed |-> st.pfailed, held |-> <<st.hk, st.hn>>, sout |-> st.o, sEnd |-> st.e,
      sReset |-> st.r, stackOut |-> st.out]


Reading == ~inputOver /\ (inKind = "none" \/ ~ReadOnlyWhenTakenRule)

ReadChoices(failed) ==
  IF ~Reading \/ failed THEN {None - 1}  \* not polled
  ELSE {None} \cup (IF peerLeft > 0 THEN 1..peerLeft ELSE {})
       \cup (IF peerLeft = 0 /\ peerFin THEN {0} ELSE {})

Poll ==
  /\ pc = "poll"
  /\ \E w1, w2 \in (IF peerStalled THEN {"pending"} ELSE {"pending", "partial", "full", "error"}),
        sd \in {"pending", "ok", "error"},
        budgetFails \in (IF BudgetMayFail THEN BOOLEAN ELSE {FALSE}) :
     LET p == Send(<<w1, w2>>, sd)
         failed == p.pfailed \/ gone
     IN \E rd \in ReadChoices(p.pfailed) :
     LET got == rd > 0
         due == deadline # None /\ now >= deadline
         ready == p.moved \/ rd >= 0 \/ failed \/ p.preset \/ due
     IN
     /\ ready
     \* What the poll moved, kept whatever the runner does next.
     /\ hKind' = p.held[1] /\ hN' = p.held[2]
     /\ sout' = p.sout /\ sEnd' = p.sEnd /\ sReset' = p.sReset /\ stackOut' = p.stackOut
     /\ transportTook' = transportTook + p.pw
     \* stack.rs:320-325
     /\ written' = written + p.pw
     /\ shut' = (shut \/ p.pshut)
     /\ stalledSince' = IF p.pw > 0 /\ StallResetOnProgress THEN None ELSE stalledSince
     /\ stuckFrom' = IF p.pw > 0 THEN now ELSE stuckFrom
     \* the read, stack.rs:329-345
     /\ badRead' = (badRead \/ (rd >= 0 /\ (inKind # "none" \/ inputOver)))
     /\ readTotal' = IF got THEN readTotal + rd ELSE readTotal
     /\ peerLeft' = IF got THEN peerLeft - rd ELSE peerLeft
     /\ inKind' = IF rd = 0 THEN "ended" ELSE IF got THEN "data" ELSE inKind
     /\ inN' = IF got THEN rd ELSE IF rd = 0 THEN 0 ELSE inN
     /\ idleFrom' = IF (got /\ IdleResetOnRead) \/ p.pw > 0 THEN now ELSE idleFrom
     /\ quietFrom' = IF got \/ p.pw > 0 THEN now ELSE quietFrom
     /\ IF p.preset
        THEN /\ pc' = "done" /\ ret' = "reset"
             /\ UNCHANGED <<offeredReset, heardReset, sOver>>
        ELSE IF got /\ budgetFails
        THEN EndBroken("budget")
        ELSE IF failed
        THEN EndBroken("conn")
        ELSE /\ pc' = "settle" /\ UNCHANGED <<ret, offeredReset, heardReset, sOver>>
  /\ UNCHANGED <<now, inputOver, idled, deadline, sbuf, heardEnded, sTimer, pausesLeft,
                 peerFin, gone, peerStalled, took, refused, reported, wasWaiting, earlyIdle, wasHolding,
                 earlyStall>>

(* Time passes while the wait is pending. The wait's first poll takes a   *)
(* new command from the stack at once, so time does not pass over one.    *)
Tick ==
  /\ pc = "poll"
  /\ deadline # None /\ now < deadline
  /\ ~(hKind = "none" /\ NextCmd(sout, sEnd, sReset, heardReset) # "none")
  /\ now' = now + 1
  /\ UNCHANGED <<pc, inKind, inN, written, inputOver, shut, idled, idleFrom, stalledSince,
                 deadline, hKind, hN, ret, stack, peer, hist>>

PeerReset ==
  /\ PeerMayReset /\ pc = "poll" /\ ~gone
  /\ gone' = TRUE
  /\ UNCHANGED <<runner, stack, peerLeft, peerFin, peerStalled, hist>>

Next == Settle \/ Check \/ Poll \/ Tick \/ PeerReset

Spec == Init /\ [][Next]_vars
        /\ WF_vars(Settle) /\ WF_vars(Check) /\ WF_vars(Poll) /\ WF_vars(Tick)

----------------------------------------------------------------------------
(* Properties *)

(* The runner reads only while the stack has taken everything it read     *)
(* before, and its input is not over.                                     *)
ReadOnlyWhenTaken == ~badRead

(* Every byte read is taken by the stack, still held for it, or refused   *)
(* by it as closed. Nothing read is dropped or counted twice.             *)
InputKept == readTotal = took + (IF inKind = "data" THEN inN ELSE 0) + refused

(* Each byte the transport took is reported to the stack once.            *)
WrittenOnce == reported + written = transportTook

(* The end of the stack's direction goes out after every byte it wrote.   *)
EndAfterWrites == shut => transportTook = stackOut + sout

(* The idle limit ends input only after the peer had the whole idle time  *)
(* to speak while the runner waited for it with nothing to write.         *)
IdleNeedsQuiet == ~earlyIdle

(* The write limit gives up only after the runner held output that the    *)
(* transport took nothing of for the whole limit.                         *)
StallNeedsNoProgress == ~earlyStall

(* A broken connection is reported to the stack once, as a reset; a       *)
(* connection that ends any other way is not.                             *)
ResetHeardOnBreak ==
  pc = "done" => /\ (ret \in {"conn", "budget"} => offeredReset = 1)
                 /\ (ret \in {"finished", "idle", "reset"} => offeredReset = 0)

(* A finished connection has both directions ended; a reset return comes  *)
(* only from the stack's own reset.                                       *)
EndsAreEarned ==
  pc = "done" => /\ (ret \in {"finished", "idle"} => shut /\ inputOver)
                 /\ (ret = "idle" => idled)
                 /\ (ret = "finished" => ~idled)
                 /\ (ret = "reset" => sReset = "given")

(* With both limits set, every connection ends.                           *)
Terminates == <>(pc = "done")
=============================================================================
