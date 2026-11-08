---------------------------- MODULE StreamRunner ----------------------------
(* `services::stack::stream` in src/stdlib/services/stack/mod.rs drives   *)
(* Live::step in src/stdlib/services/stack/live.rs. Round reads, reports   *)
(* writes, offers held input, calls Driver::run and sends output. A round *)
(* with progress repeats; a settled round checks deadlines and sleeps.   *)
(* After Pending, stream checks Live::finished and transport poll_gone.   *)
(* EndBroken corresponds to Live::broken. Driver holds one refused       *)
(* command below, retaining partial output until the transport takes it. *)
(*                                                                     *)
(* The stack is abstract: an echo with room for `Room` bytes of input that *)
(* it moves to its output when it runs, asks to end its direction once it  *)
(* heard the end of its input, may refuse input for `Pause` ticks on a     *)
(* timer of its own, and may ask for a reset. That is the shape of         *)
(* `Chain<Framed, PlcServer>`, plus the timer and the reset that other     *)
(* stacks have. It asks for no work: `jobs` stays empty, so the            *)
(* `jobs.is_empty()` of `waiting` and `finished` always holds. Bytes are   *)
(* counted, not carried. Time is in ticks, and passes only while the      *)
(* runner waits. The ROUNDS bound on one poll  only  *)
(* yields to the rest of the world, and is left out.                      *)
(*                                                                         *)
(* The switches are the rules of the code. TRUE is the production rule.  *)
(* This abstract stack never declares its whole lifetime terminal: ending *)
(* writes alone leaves input live. The runner must therefore wait for     *)
(* inputOver as well. Terminal application layers, such as HTTP closing   *)
(* after its final response, are covered by the executable stack tests.   *)
(* The _without_ configs turn one rule off and must violate its property. *)
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
          BudgetMayFail,  \* a read's charge may not fit
          ReadOnlyWhenTakenRule, \* read only if `input.is_none()`
          ReportOnceRule,        \* `unreported = 0` once delivered
          StallResetOnProgress,  \* `stalled_since = None` on bytes taken
          IdleResetOnRead,       \* `idle_from = now` on bytes read
          ResetOnBreak,          \* `broken` offers StreamEvent::Reset
          WriteBeforeEnd,        \* the layer hands writes before its End (framed.rs:183-195)
          KeepPartialRest,       \* `Admit::Partial(rest) => input = Some(rest)`
          FinishNeedsInputOver,  \* `finished` needs input over for a nonterminal layer
          RestartIdleOnWait      \* restart `idle_from` when waiting begins

ASSUME PeerBytes \in Nat /\ Room \in Nat \ {0} /\ Pause \in Nat
NoLimit == -1  \* stands for `None`; set a limit to it with `<- NoLimit`
ASSUME Idle \in Nat \cup {NoLimit} /\ WriteTimeout \in Nat \cup {NoLimit}

None == -1  \* also `poll_read` answering Pending
Skip == -2  \* `poll_read` not called
Err == -3   \* `poll_read` failed

VARIABLES pc,          \* "round", "check", "wait" or "done"
          now,         \* fcx.now()
          inKind, inN, \* `input`: "none", "data" with inN bytes, or "ended"
          written,     \* `unreported`: taken by the transport, not yet reported
          inputOver,   \* `input_over`
          shut,        \* `shut`
          idled,       \* `idled`
          idleFrom,    \* `idle_from`
          stalledSince,\* `stalled_since`, or None
          deadline,    \* `armed`: the deadline the wait sleeps until, or None
          hKind, hN,   \* `Driver::below`: "none", "write" of hN bytes, "end" or "reset"
          ret,         \* how the run ended, once pc = "done"
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
          wasWaiting,  \* `was_waiting` , also used by the history
          quietFrom, earlyIdle,
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
  /\ pc \in {"round", "check", "wait", "done"}
  /\ inKind \in {"none", "data", "ended"} /\ inN \in 0..PeerBytes
  /\ hKind \in {"none", "write", "end", "reset"}
  /\ sEnd \in {"no", "asked", "given"} /\ sReset \in {"no", "asked", "given"}
  /\ ret \in {"none", "finished", "idle", "reset", "budget", "conn"}
  /\ written \in Nat /\ sbuf \in 0..Room /\ offeredReset \in 0..1

Init ==
  /\ pc = "round" /\ now = 0
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

(* `Live::broken` : the stack is offered a reset, which  *)
(* Framed takes unless its input is over (framed.rs:125, 147-152), and    *)
(* the run ends. `stream` calls it for a failed read or write             *)
(* (mod.rs:188, 198) and for a peer that is gone (mod.rs:194); `Live`     *)
(* calls it itself for the budget  and the write limit   *)
(* .                                                     *)
EndBroken(why, over) ==
  /\ offeredReset' = IF ResetOnBreak THEN offeredReset + 1 ELSE offeredReset
  /\ heardReset' = (heardReset \/ (ResetOnBreak /\ ~over))
  /\ sOver' = (over \/ ResetOnBreak)
  /\ pc' = "done" /\ ret' = why

(* `Driver::send_below` (driver.rs:190-195, `send` at 246-276) into the   *)
(* sink of live.rs:264-308: `send` offers the held command, or takes the  *)
(* next from the stack, until the sink hands one back. `ws` is what the   *)
(* transport answers to the first and the second write of this round (a   *)
(* held write and then a new one), `sd` what it answers to the shutdown.  *)
(* A write that is ready takes at least one byte, as                      *)
(* `Connection::poll_write` does for a non-empty buffer; one that takes   *)
(* none is the "error" answer . A failed write or        *)
(* shutdown stays held  and `send` stops.       *)
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
                     [s1 EXCEPT !.hk = "write", !.hn = n, !.pfailed = TRUE, !.stop = TRUE]
                [] OTHER ->
                     SendLoop([s1 EXCEPT !.pw = @ + n, !.moved = TRUE, !.wi = @ + 1],
                              ws, sd, fuel - 1)
         [] k = "end" ->
              CASE sd = "pending" -> [s1 EXCEPT !.hk = "end", !.stop = TRUE]
                [] sd = "ok" -> SendLoop([s1 EXCEPT !.pshut = TRUE, !.moved = TRUE], ws, sd, fuel - 1)
                [] OTHER -> [s1 EXCEPT !.hk = "end", !.pfailed = TRUE, !.stop = TRUE]
         [] OTHER -> SendLoop([s1 EXCEPT !.preset = TRUE, !.moved = TRUE], ws, sd, fuel - 1)

Send(ws, sd) ==
  LET st == SendLoop([hk |-> hKind, hn |-> hN, o |-> sout, e |-> sEnd, r |-> sReset,
                      out |-> stackOut, pw |-> 0, pshut |-> FALSE, preset |-> FALSE,
                      pfailed |-> FALSE, moved |-> FALSE, wi |-> 1, stop |-> FALSE],
                     ws, sd, 5)
  IN st

Reading == ~inputOver /\ (inKind = "none" \/ ~ReadOnlyWhenTakenRule)

(* What `poll_read` answers: not polled, Pending (None), n bytes, the end *)
(* (0), or a failure (Err) once the peer is gone.                         *)
ReadChoices ==
  IF ~Reading THEN {Skip}
  ELSE IF gone THEN {Err}
  ELSE {None} \cup (IF peerLeft > 0 THEN 1..peerLeft ELSE {})
       \cup (IF peerLeft = 0 /\ peerFin THEN {0} ELSE {})

(* One round of `Live::step` . From "wait" a round runs  *)
(* only if something can move: what woke the runner .        *)
Round ==
  /\ pc \in {"round", "wait"}
  /\ \E rd \in ReadChoices,
        budgetFails \in (IF BudgetMayFail THEN BOOLEAN ELSE {FALSE}),
        w1, w2 \in (IF peerStalled THEN {"pending"} ELSE {"pending", "partial", "full", "error"}),
        sd \in {"pending", "ok", "error"},
        arm \in (IF pausesLeft > 0 THEN BOOLEAN ELSE {FALSE}),
        askReset \in (IF StackMayReset /\ sReset = "no" /\ ~heardReset THEN BOOLEAN ELSE {FALSE}),
        early \in (IF StackMayEndEarly /\ sEnd = "no" /\ ~heardReset THEN BOOLEAN ELSE {FALSE}) :
     LET got == rd > 0
         \* the read, live.rs:202-221
         k0 == IF rd = 0 THEN "ended" ELSE IF got THEN "data" ELSE inKind
         n0 == IF got THEN rd ELSE IF rd = 0 THEN 0 ELSE inN
         readMoved == rd >= 0
         \* the write report, live.rs:229-239
         m1 == written > 0
         \* the held input, live.rs:240-257
         blocked == k0 = "data" /\ ~sOver /\ (sTimer # None \/ sbuf = Room)
         closed == k0 # "none" /\ sOver
         j == IF k0 = "data" /\ ~sOver /\ ~blocked THEN Min(n0, Room - sbuf) ELSE 0
         m2 == k0 # "none" /\ ~blocked
         arms == arm /\ j > 0
         sbuf1 == sbuf + j
         sTimer1 == IF arms THEN now + Pause ELSE sTimer
         ended1 == heardEnded \/ (k0 = "ended" /\ ~sOver)
         over1 == sOver \/ (k0 = "ended")
         \* `Driver::run`: due timers first, then the stack's own steps.
         fires == sTimer1 # None /\ sTimer1 <= now
         askEnd == (ended1 \/ early) /\ sEnd = "no" /\ ~heardReset
         runMoved == fires \/ sbuf1 > 0 \/ askEnd \/ askReset
         sout1 == IF sEnd = "no" THEN sout + sbuf1 ELSE sout
         sEnd1 == IF askEnd THEN "asked" ELSE sEnd
         sReset1 == IF askReset THEN "asked" ELSE sReset
         \* `send_below`, live.rs:262-308
         p == SendLoop([hk |-> hKind, hn |-> hN, o |-> sout1, e |-> sEnd1, r |-> sReset1,
                        out |-> stackOut, pw |-> 0, pshut |-> FALSE, preset |-> FALSE,
                        pfailed |-> FALSE, moved |-> FALSE, wi |-> 1, stop |-> FALSE],
                       <<w1, w2>>, sd, 5)
         moved == readMoved \/ m1 \/ m2 \/ runMoved \/ p.moved
         due == deadline # None /\ now >= deadline
         stops == (got /\ budgetFails) \/ p.preset \/ p.pfailed \/ rd = Err
     IN
     /\ pc = "wait" => (moved \/ stops \/ due)
     /\ badRead' = (badRead \/ (readMoved /\ (inKind # "none" \/ inputOver)))
     /\ readTotal' = IF got THEN readTotal + rd ELSE readTotal
     /\ peerLeft' = IF got THEN peerLeft - rd ELSE peerLeft
     /\ IF got /\ budgetFails
        THEN \* live.rs:207-210: the round ends at the read.
             /\ EndBroken("budget", sOver)
             /\ idleFrom' = IF IdleResetOnRead THEN now ELSE idleFrom
             /\ quietFrom' = now
             /\ inKind' = "data" /\ inN' = rd
             /\ UNCHANGED <<now, written, inputOver, shut, idled, stalledSince, deadline,
                            hKind, hN, sbuf, sout, sEnd, sReset, heardEnded, sTimer,
                            pausesLeft, peerFin, gone, peerStalled, took, refused,
                            transportTook, reported, stackOut, wasWaiting, earlyIdle,
                            wasHolding, stuckFrom, earlyStall>>
        ELSE
        /\ reported' = IF m1 THEN reported + written ELSE reported
        /\ inKind' = IF closed THEN "none"
                     ELSE IF k0 = "ended" THEN "none"
                     ELSE IF k0 = "data" /\ ~blocked /\ j = n0 THEN "none"
                     ELSE IF k0 = "data" /\ ~blocked /\ ~KeepPartialRest THEN "none"
                     ELSE k0
        /\ inN' = IF k0 = "data" /\ ~closed /\ (blocked \/ KeepPartialRest)
                  THEN n0 - j ELSE 0
        /\ inputOver' = (inputOver \/ closed \/ k0 = "ended")
        /\ refused' = IF closed /\ k0 = "data" THEN refused + n0 ELSE refused
        /\ took' = took + j
        /\ heardEnded' = ended1
        /\ pausesLeft' = IF arms THEN pausesLeft - 1 ELSE pausesLeft
        /\ sTimer' = IF fires THEN None ELSE sTimer1
        \* After its End the stack's output is refused (framed.rs:161-162).
        /\ sbuf' = 0
        /\ hKind' = p.hk /\ hN' = p.hn
        /\ sout' = p.o /\ sEnd' = p.e /\ sReset' = p.r /\ stackOut' = p.out
        /\ transportTook' = transportTook + p.pw
        /\ shut' = (shut \/ p.pshut)
        \* live.rs:312-323: what the transport took is owed to the stack.
        /\ written' = (IF m1 /\ ReportOnceRule THEN 0 ELSE written) + p.pw
        /\ stalledSince' = IF (p.pw > 0 /\ StallResetOnProgress) \/ p.hk = "none"
                           THEN None ELSE stalledSince
        /\ stuckFrom' = IF p.pw > 0 THEN now ELSE stuckFrom
        /\ idleFrom' = IF (got /\ IdleResetOnRead) \/ p.pw > 0 THEN now ELSE idleFrom
        /\ quietFrom' = IF got \/ p.pw > 0 THEN now ELSE quietFrom
        /\ IF p.preset
           THEN /\ pc' = "done" /\ ret' = "reset"
                /\ sOver' = over1 /\ UNCHANGED <<offeredReset, heardReset>>
           ELSE IF p.pfailed \/ rd = Err
           THEN /\ EndBroken("conn", over1)
           ELSE /\ sOver' = over1
                /\ pc' = IF moved THEN "round" ELSE "check"
                /\ UNCHANGED <<ret, offeredReset, heardReset>>
        /\ UNCHANGED <<now, idled, deadline, peerFin, gone, peerStalled, wasWaiting,
                       earlyIdle, wasHolding, earlyStall>>

(* The limits and the sleep , then, when `step` returns  *)
(* Pending, what `stream` does with it (mod.rs:190-196).                  *)
Check ==
  /\ pc = "check"
  /\ LET holds == hKind # "none"
         since == IF holds THEN (IF stalledSince = None THEN now ELSE stalledSince) ELSE None
         timedOut == holds /\ WriteTimeout # NoLimit /\ now >= since + WriteTimeout
         waiting == inKind = "none" /\ ~inputOver /\ ~holds
         resumes == waiting /\ ~wasWaiting
         from == IF RestartIdleOnWait /\ resumes THEN now ELSE idleFrom
         idleDue == waiting /\ Idle # NoLimit /\ now >= from + Idle
         quiet == IF resumes THEN now ELSE quietFrom
         stuck == IF holds /\ ~wasHolding THEN now ELSE stuckFrom
         dl == ({sTimer} \ {None})
               \cup (IF waiting /\ Idle # NoLimit THEN {from + Idle} ELSE {})
               \cup (IF since # None /\ WriteTimeout # NoLimit THEN {since + WriteTimeout} ELSE {})
         armed == IF dl = {} THEN None ELSE MinOf(dl)
         finished == shut /\ ~holds /\ (inputOver \/ ~FinishNeedsInputOver)
     IN
     /\ wasHolding' = holds /\ stuckFrom' = stuck
     /\ IF timedOut
        THEN /\ stalledSince' = since
             /\ earlyStall' = (now - stuck < WriteTimeout)
             /\ EndBroken("conn", sOver)
             /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, idleFrom,
                            deadline, hKind, hN, sbuf, sout, sEnd, sReset, heardEnded,
                            sTimer, pausesLeft, peer, readTotal, took, refused,
                            transportTook, reported, stackOut, badRead, wasWaiting,
                            quietFrom, earlyIdle>>
        ELSE
        /\ stalledSince' = since /\ idleFrom' = from
        /\ wasWaiting' = waiting /\ quietFrom' = quiet
        /\ IF idleDue
           THEN /\ idled' = TRUE /\ inKind' = "ended" /\ inN' = 0
                /\ earlyIdle' = (earlyIdle \/ now - quiet < Idle)
                /\ pc' = "round"
                /\ UNCHANGED <<now, written, inputOver, shut, deadline, hKind, hN, ret,
                               stack, peer, readTotal, took, refused, transportTook,
                               reported, stackOut, offeredReset, badRead, earlyStall>>
           ELSE IF armed # None /\ now >= armed
           THEN \* The sleep is due: round again .
                /\ deadline' = None /\ pc' = "round"
                /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, hKind,
                               hN, ret, stack, peer, readTotal, took, refused,
                               transportTook, reported, stackOut, offeredReset, badRead,
                               earlyIdle, earlyStall>>
           ELSE IF finished
           THEN /\ pc' = "done" /\ ret' = IF idled THEN "idle" ELSE "finished"
                /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, deadline,
                               hKind, hN, stack, peer, readTotal, took, refused,
                               transportTook, reported, stackOut, offeredReset, badRead,
                               earlyIdle, earlyStall>>
           ELSE IF gone
           THEN /\ EndBroken("conn", sOver)
                /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, deadline,
                               hKind, hN, sbuf, sout, sEnd, sReset, heardEnded, sTimer,
                               pausesLeft, peer, readTotal, took, refused, transportTook,
                               reported, stackOut, badRead, earlyIdle, earlyStall>>
           ELSE /\ deadline' = armed /\ pc' = "wait"
                /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, hKind,
                               hN, ret, stack, peer, readTotal, took, refused,
                               transportTook, reported, stackOut, offeredReset, badRead,
                               earlyIdle, earlyStall>>

(* Time passes while the runner waits. A round takes a new command from   *)
(* the stack at once, so time does not pass over one.                     *)
Tick ==
  /\ pc = "wait"
  /\ deadline # None /\ now < deadline
  /\ ~(hKind = "none" /\ NextCmd(sout, sEnd, sReset, heardReset) # "none")
  /\ now' = now + 1
  /\ UNCHANGED <<pc, inKind, inN, written, inputOver, shut, idled, idleFrom, stalledSince,
                 deadline, hKind, hN, ret, stack, peer, hist>>

PeerReset ==
  /\ PeerMayReset /\ pc = "wait" /\ ~gone
  /\ gone' = TRUE
  /\ UNCHANGED <<runner, stack, peerLeft, peerFin, peerStalled, hist>>

(* `stream` polls `poll_gone` when the runner waits (mod.rs:194): a peer  *)
(* that is gone ends the run even if no read or write tries.              *)
Gone ==
  /\ pc = "wait" /\ gone
  /\ EndBroken("conn", sOver)
  /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, idleFrom, stalledSince,
                 deadline, hKind, hN, sbuf, sout, sEnd, sReset, heardEnded, sTimer,
                 pausesLeft, peer, readTotal, took, refused, transportTook, reported,
                 stackOut, badRead, wasWaiting, quietFrom, earlyIdle, wasHolding,
                 stuckFrom, earlyStall>>

Next == Round \/ Check \/ Tick \/ PeerReset \/ Gone

Spec == Init /\ [][Next]_vars
        /\ WF_vars(Round) /\ WF_vars(Check) /\ WF_vars(Tick) /\ WF_vars(Gone)

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

(* A finished connection has the stack's direction ended; a reset return  *)
(* comes only from the stack's own reset.                                 *)
EndsAreEarned ==
  pc = "done" => /\ (ret \in {"finished", "idle"} => shut)
                 /\ (ret = "idle" => idled)
                 /\ (ret = "finished" => ~idled)
                 /\ (ret = "reset" => sReset = "given")

(* A run finishes only once both directions are over: the stack ended its *)
(* own and its input ended too. `StreamCommand::End` leaves the other     *)
(* direction open, so a stack that ends its direction first may still be  *)
(* reading. Together with EndsAreEarned this is the old model's           *)
(* EndsAreEarned.                                                         *)
FinishNeedsInput ==
  pc = "done" => (ret \in {"finished", "idle"} => inputOver)

(* With both limits set, every connection ends.                           *)
Terminates == <>(pc = "done")
=============================================================================
