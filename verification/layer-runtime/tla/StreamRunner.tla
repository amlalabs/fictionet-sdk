---------------------------- MODULE StreamRunner ----------------------------
(* `services::stack::stream` (src/stdlib/services/stack/mod.rs:255-301)   *)
(* drives Live::step (src/stdlib/services/stack/live.rs:200-433). Round   *)
(* reads, reports writes, offers held input, calls Driver::run and sends  *)
(* output: one pass of the `for _ in 0..ROUNDS` at live.rs:214-432. A    *)
(* round with progress repeats; a settled round checks the limits and     *)
(* sleeps (live.rs:380-428), with the clocks of Lifetime                  *)
(* (lifetime.rs:110-151). After Pending, stream checks Live::finished     *)
(* (live.rs:155-165, mod.rs:289) and the transport's poll_gone            *)
(* (mod.rs:293). EndBroken corresponds to Live::broken (live.rs:475-505). *)
(* Driver holds one refused command below (`below`; `send` in driver.rs), *)
(* retaining partial output until the transport takes it. Line numbers   *)
(* are those of the worktree comp/fv-layer, from main at 3db7a847e.      *)
(*                                                                       *)
(* The stack is abstract: an echo with room for `Room` bytes of input that *)
(* it moves to its output when it runs, asks to end its direction once it  *)
(* heard the end of its input, may refuse input for `Pause` ticks on a     *)
(* timer of its own, and may ask for a reset. That is the shape of         *)
(* `Chain<Framed, PlcServer>`, plus the timer and the reset that other     *)
(* stacks have. It asks for no work: `jobs` stays empty, so the            *)
(* `jobs.is_empty()` of `waiting` and `finished` always holds. Bytes are   *)
(* counted, not carried. Time is in ticks, and passes only while the      *)
(* runner waits. The ROUNDS bound on one poll (live.rs:22, 428-432) only  *)
(* yields to the rest of the world, and is left out. So are the           *)
(* `jobs.close_completed()` call of a round, which touches only work,     *)
(* and the cancel checks of `stream` and of a read: cancellation is       *)
(* outside.                                                               *)
(*                                                                       *)
(* Memory (rule 9 of src/stdlib/layer/mod.rs). The budget is shared with  *)
(* other connections: `full` says it has no room now; Fill (at most       *)
(* `Fills` times) and Free are the others' charges and releases. Free is  *)
(* fair: memory others hold is given back in the end. A round's own       *)
(* refusals are those of the runner's view: the read buffer it pays for   *)
(* before a read (live.rs:228-230), the copy that pays for bytes read     *)
(* (`pay`, live.rs:441-470: refused, the buffer goes with the bytes), and *)
(* a charge of the stack's, which then takes no input in that round. A    *)
(* refused round that moved is tried again at once; one that settles has  *)
(* the runner wait for memory (`wake_when_freed`, live.rs:411, 417) and   *)
(* stops the idle clock (`Outstanding::memory`, live.rs:384). The stack   *)
(* may also ask for more than the whole limit (Starved): the run ends     *)
(* with StreamEnd::Budget at the end of that round (live.rs:373-375),     *)
(* and the stack hears no reset. A child of the stack (a Children child, *)
(* on a view of its own the runner does not read) may wait for memory;    *)
(* the release that makes room wakes the runner through the child's      *)
(* waiter, and Layer::waits_for_memory tells the runner it waits.         *)
(* BudgetWake.tla in verification/layer checks the wake itself; here a    *)
(* release that comes while the runner or a child waits simply wakes.    *)
(*                                                                       *)
(* The switches are the rules of the code. TRUE is the production rule.  *)
(* This abstract stack never declares its whole lifetime terminal: ending *)
(* writes alone leaves input live. The runner must therefore wait for     *)
(* inputOver as well. Terminal application layers, such as HTTP closing   *)
(* after its final response, are covered by the executable stack tests.   *)
(* The _without_ configs turn one rule off and must violate its property. *)
(* Session's output_end, input_end and pending writes use the same       *)
(* completion conjunction. Its enclosing child router and jobs are      *)
(* outside this model; this is a projection, not a model of that driver. *)
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
          Fills,          \* times the others may fill the budget; 0 for never
          StackMayStarve, \* the stack may ask for more than the budget's whole limit
          ChildMayWait,   \* a child of the stack may wait for memory on its own view
          StackMaySpeak,  \* the stack may write a byte of its own when its timer fires
          ReadOnlyWhenTakenRule, \* read only if `input.is_none()`
          ReportOnceRule,        \* `unreported = 0` once delivered
          StallResetOnProgress,  \* `stalled_since = None` on bytes taken
          IdleResetOnRead,       \* `took_input`: `idle_from = None` on bytes read
          IdleResetOnWrite,      \* `wrote`: `idle_from = None` on bytes written
          ResetOnBreak,          \* `broken` offers StreamEvent::Reset
          WriteBeforeEnd,        \* the layer hands writes before its End (framed.rs:183-195)
          KeepPartialRest,       \* `Admit::Partial(rest) => input = Some(rest)`
          FinishNeedsInputOver,  \* `finished` needs input over for a nonterminal layer
          RestartIdleOnWait,     \* `settle`: `idle_from = None` while not waiting
          MemoryStopsIdle,       \* `Outstanding::memory` from the round's refusals
          ChildWaitTold,         \* `memory` also when `waits_for_memory()` (live.rs:384-385)
          WakeOnRelease,         \* the release that makes room wakes the waiting runner
          StarvedEnds            \* a need past the limit ends the run (live.rs:373)

ASSUME PeerBytes \in Nat /\ Room \in Nat \ {0} /\ Pause \in Nat /\ Fills \in Nat
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
          idleFrom,    \* `idle_from`, or None
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
          \* memory
          full,        \* the budget has no room now
          fillsLeft,   \* how many more times the others may fill it
          buf,         \* `buf`: the read buffer, paid for
          refusedLast, \* the last round's view was refused (`refused_since`)
          memWait,     \* the runner asked to be woken when memory frees
          memWoken,    \* a release woke the runner
          childWaits,  \* a child waits for memory on its own view
          starving,    \* the stack asked for more than the whole limit
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
          quietFrom,   \* the first settle that found the run waiting for its peer, or None
          earlyIdle,
          wasHolding, stuckFrom, earlyStall

runner == <<pc, now, inKind, inN, written, inputOver, shut, idled, idleFrom, stalledSince,
            deadline, hKind, hN, ret>>
stack == <<sbuf, sout, sEnd, sReset, sOver, heardEnded, heardReset, sTimer, pausesLeft>>
mem == <<full, fillsLeft, buf, refusedLast, memWait, memWoken, childWaits, starving>>
peer == <<peerLeft, peerFin, gone, peerStalled>>
hist == <<readTotal, took, refused, transportTook, reported, stackOut, offeredReset, badRead,
          quietFrom, earlyIdle, wasHolding, stuckFrom, earlyStall>>
vars == <<runner, stack, mem, peer, hist>>

Min(a, b) == IF a < b THEN a ELSE b
MinOf(S) == CHOOSE x \in S : \A y \in S : x <= y

TypeOK ==
  /\ pc \in {"round", "check", "wait", "done"}
  /\ inKind \in {"none", "data", "ended"} /\ inN \in 0..PeerBytes
  /\ hKind \in {"none", "write", "end", "reset"}
  /\ sEnd \in {"no", "asked", "given"} /\ sReset \in {"no", "asked", "given"}
  /\ ret \in {"none", "finished", "idle", "reset", "budget", "conn"}
  /\ written \in Nat /\ sbuf \in 0..Room /\ offeredReset \in 0..1
  /\ full \in BOOLEAN /\ buf \in BOOLEAN /\ childWaits \in BOOLEAN

Init ==
  /\ pc = "round" /\ now = 0
  /\ inKind = "none" /\ inN = 0 /\ written = 0
  /\ inputOver = FALSE /\ shut = FALSE /\ idled = FALSE
  /\ idleFrom = None /\ stalledSince = None /\ deadline = None
  /\ hKind = "none" /\ hN = 0 /\ ret = "none"
  /\ sbuf = 0 /\ sout = 0 /\ sEnd = "no" /\ sReset = "no" /\ sOver = FALSE
  /\ heardEnded = FALSE /\ heardReset = FALSE /\ sTimer = None
  /\ pausesLeft = IF Pause > 0 THEN 1 ELSE 0
  \* `Live::new` pays for nothing: the first round pays for the buffer.
  /\ full \in (IF Fills > 0 THEN BOOLEAN ELSE {FALSE})
  /\ fillsLeft = Fills /\ buf = FALSE
  /\ refusedLast = FALSE /\ memWait = FALSE /\ memWoken = FALSE
  /\ childWaits = FALSE /\ starving = FALSE
  /\ peerLeft \in 0..PeerBytes /\ peerFin \in BOOLEAN /\ gone = FALSE
  /\ peerStalled \in (IF PeerMayStall THEN BOOLEAN ELSE {FALSE})
  /\ readTotal = 0 /\ took = 0 /\ refused = 0 /\ transportTook = 0 /\ reported = 0
  /\ stackOut = 0 /\ offeredReset = 0 /\ badRead = FALSE
  /\ quietFrom = None /\ earlyIdle = FALSE
  /\ wasHolding = FALSE /\ stuckFrom = 0 /\ earlyStall = FALSE

(* The stack's `take_command`, through Framed: writes first, then its     *)
(* reset or end (framed.rs:251-263). Nothing after it heard a reset.      *)
NextCmd(o, e, r, hr) ==
  IF hr THEN "none"
  ELSE IF o > 0 /\ (WriteBeforeEnd \/ e # "asked") THEN "write"
  ELSE IF r = "asked" THEN "reset"
  ELSE IF e = "asked" THEN "end"
  ELSE "none"

(* `Live::broken` (live.rs:475-505): the stack is offered a reset, which  *)
(* Framed takes unless its input is over (framed.rs:186, 208-213), and    *)
(* the run ends. `stream` calls it for a failed read or write (Halt::Conn *)
(* at mod.rs:286, broken at 297) and for a peer that is gone (mod.rs:293); *)
(* `Live` calls it itself for the write limit (live.rs:388-392); a need  *)
(* past the budget ends the run without it. The code also clears `input` *)
(* and sets `input_over` there; the model leaves them as they           *)
(* were, which no property reads once pc = "done".                        *)
EndBroken(why, over) ==
  /\ offeredReset' = IF ResetOnBreak THEN offeredReset + 1 ELSE offeredReset
  /\ heardReset' = (heardReset \/ (ResetOnBreak /\ ~over))
  /\ sOver' = (over \/ ResetOnBreak)
  /\ pc' = "done" /\ ret' = why

(* `Driver::send_below` (driver.rs:267-272, `send` at 327-358) into the   *)
(* sink of live.rs:296-340: `send` offers the held command, or takes the  *)
(* next from the stack, until the sink hands one back. `ws` is what the   *)
(* transport answers to the first and the second write of this round (a   *)
(* held write and then a new one), `sd` what it answers to the shutdown.  *)
(* A write that is ready takes at least one byte, as                      *)
(* `Connection::poll_write` does for a non-empty buffer; one that takes   *)
(* none is the "error" answer (`Ok(0)`, live.rs:281-284). A failed write  *)
(* or shutdown stays held (`Blocked`, live.rs:283, 297, 309; driver.rs:   *)
(* 351-354) and `send` stops.                                             *)
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

(* The read buffer is paid for before a read (live.rs:228-230): kept from *)
(* the last read, or paid for now if there is room. Without it the bytes  *)
(* stay in the connection.                                                *)
HasBuf == buf \/ ~full

(* What `poll_read` answers: not polled, Pending (None), n bytes, the end *)
(* (0), or a failure (Err) once the peer is gone.                         *)
ReadChoices ==
  IF ~Reading \/ ~HasBuf THEN {Skip}
  ELSE IF gone THEN {Err}
  ELSE {None} \cup (IF peerLeft > 0 THEN 1..peerLeft ELSE {})
       \cup (IF peerLeft = 0 /\ peerFin THEN {0} ELSE {})

(* One round of `Live::step` (live.rs:214-379). From "wait" a round runs  *)
(* only if something can move: what woke the runner (the read, a write,   *)
(* the sleep of live.rs:415-427, a release of memory, or poll_gone).      *)
Round ==
  /\ pc \in {"round", "wait"}
  /\ \E rd \in ReadChoices,
        w1, w2 \in (IF peerStalled THEN {"pending"} ELSE {"pending", "partial", "full", "error"}),
        sd \in {"pending", "ok", "error"},
        arm \in (IF pausesLeft > 0 THEN BOOLEAN ELSE {FALSE}),
        askReset \in (IF StackMayReset /\ sReset = "no" /\ ~heardReset THEN BOOLEAN ELSE {FALSE}),
        early \in (IF StackMayEndEarly /\ sEnd = "no" /\ ~heardReset THEN BOOLEAN ELSE {FALSE}),
        stackRefuses \in (IF full THEN BOOLEAN ELSE {FALSE}),
        starve \in (IF StackMayStarve /\ ~starving THEN BOOLEAN ELSE {FALSE}),
        speak \in (IF StackMaySpeak THEN BOOLEAN ELSE {FALSE}),
        childBegins \in (IF ChildMayWait /\ full /\ ~childWaits /\ sEnd = "no" /\ ~heardReset
                         THEN BOOLEAN ELSE {FALSE}) :
     LET got == rd > 0
         \* the runner's own refusals in this round
         bufRefused == Reading /\ ~buf /\ full
         payRefused == got /\ full
         \* a stack that starved and is not ended asks again in every round
         stackRef == stackRefuses \/ starve \/ (starving /\ ~StarvedEnds)
         refusedNow == bufRefused \/ payRefused \/ stackRef
         \* a child that waits gets its memory once there is room, and then moves
         childGets == childWaits /\ ~full
         childWaits1 == (childWaits /\ full) \/ childBegins
         \* the read, live.rs:220-245
         k0 == IF rd = 0 THEN "ended" ELSE IF got THEN "data" ELSE inKind
         n0 == IF got THEN rd ELSE IF rd = 0 THEN 0 ELSE inN
         readMoved == rd >= 0
         \* the write report, live.rs:259-270; Framed always takes a Written
         \* (framed.rs:185), so the `Blocked` arm is never taken here
         m1 == written > 0
         \* the held input, live.rs:271-292; a stack whose charge was
         \* refused takes no input in that round
         blocked == k0 = "data" /\ ~sOver /\ (sTimer # None \/ sbuf = Room \/ stackRef)
         closed == k0 # "none" /\ sOver
         j == IF k0 = "data" /\ ~sOver /\ ~blocked THEN Min(n0, Room - sbuf) ELSE 0
         m2 == k0 # "none" /\ ~blocked
         arms == arm /\ j > 0
         sbuf1 == sbuf + j
         sTimer1 == IF arms THEN now + Pause ELSE sTimer
         ended1 == heardEnded \/ (k0 = "ended" /\ ~sOver)
         over1 == sOver \/ (k0 = "ended")
         \* `Driver::run`: due timers first, then the stack's own steps. Its
         \* end waits for a child that waits for memory.
         fires == sTimer1 # None /\ sTimer1 <= now
         askEnd == (ended1 \/ early) /\ sEnd = "no" /\ ~heardReset /\ ~childWaits1
         runMoved == fires \/ sbuf1 > 0 \/ askEnd \/ askReset \/ childGets
         \* a stack that speaks on its timer queues a byte of its own
         sout1 == IF sEnd = "no" THEN sout + sbuf1 + (IF speak /\ fires THEN 1 ELSE 0) ELSE sout
         sEnd1 == IF askEnd THEN "asked" ELSE sEnd
         sReset1 == IF askReset THEN "asked" ELSE sReset
         \* `send_below`, live.rs:296-340
         p == SendLoop([hk |-> hKind, hn |-> hN, o |-> sout1, e |-> sEnd1, r |-> sReset1,
                        out |-> stackOut, pw |-> 0, pshut |-> FALSE, preset |-> FALSE,
                        pfailed |-> FALSE, moved |-> FALSE, wi |-> 1, stop |-> FALSE],
                       <<w1, w2>>, sd, 5)
         moved == readMoved \/ m1 \/ m2 \/ runMoved \/ p.moved
         due == deadline # None /\ now >= deadline
         stops == p.preset \/ p.pfailed \/ rd = Err
     IN
     /\ pc = "wait" => (moved \/ stops \/ due \/ memWoken)
     /\ badRead' = (badRead \/ (readMoved /\ (inKind # "none" \/ inputOver)))
     /\ readTotal' = IF got THEN readTotal + rd ELSE readTotal
     /\ peerLeft' = IF got THEN peerLeft - rd ELSE peerLeft
     \* the buffer: paid for now if there is room; gone with bytes whose
     \* copy the budget refused (`pay`, live.rs:441-470)
     /\ buf' = IF payRefused THEN FALSE ELSE IF Reading /\ ~full THEN TRUE ELSE buf
     /\ refusedLast' = refusedNow
     /\ memWait' = FALSE /\ memWoken' = FALSE
     /\ childWaits' = childWaits1
     /\ starving' = (starving \/ starve)
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
     \* After its End the stack's output is refused (framed.rs:222-224).
     /\ sbuf' = 0
     /\ hKind' = p.hk /\ hN' = p.hn
     /\ sout' = p.o /\ sEnd' = p.e /\ sReset' = p.r /\ stackOut' = p.out
     /\ transportTook' = transportTook + p.pw
     /\ shut' = (shut \/ p.pshut)
     \* live.rs:344-366: what the transport took is owed to the stack.
     /\ written' = (IF m1 /\ ReportOnceRule THEN 0 ELSE written) + p.pw
     \* `wrote` (live.rs:354) restarts the write limit, and the idle clock below
     /\ stalledSince' = IF (p.pw > 0 /\ StallResetOnProgress) \/ p.hk = "none"
                        THEN None ELSE stalledSince
     \* `took_input` (live.rs:238) and `wrote` (live.rs:354): a byte read or
     \* written restarts the idle clock from the next settle
     /\ idleFrom' = IF (got /\ IdleResetOnRead) \/ (p.pw > 0 /\ IdleResetOnWrite)
                    THEN None ELSE idleFrom
     /\ quietFrom' = IF got \/ p.pw > 0 THEN None ELSE quietFrom
     /\ stuckFrom' = IF p.pw > 0 THEN now ELSE stuckFrom
     /\ IF p.preset
        THEN /\ pc' = "done" /\ ret' = "reset"
             /\ sOver' = over1 /\ UNCHANGED <<offeredReset, heardReset>>
        ELSE IF p.pfailed \/ rd = Err
        THEN /\ EndBroken("conn", over1)
        ELSE IF starve /\ StarvedEnds
        THEN \* live.rs:373-375: the run ends; the stack hears no reset
             /\ pc' = "done" /\ ret' = "budget"
             /\ sOver' = over1 /\ UNCHANGED <<offeredReset, heardReset>>
        ELSE /\ sOver' = over1
             /\ pc' = IF moved THEN "round" ELSE "check"
             /\ UNCHANGED <<ret, offeredReset, heardReset>>
     /\ UNCHANGED <<now, idled, deadline, full, fillsLeft, peerFin, gone, peerStalled,
                    earlyIdle, wasHolding, earlyStall>>

(* The limits and the sleep (live.rs:380-427), with Lifetime's clocks     *)
(* (lifetime.rs:110-151), then, when `step` returns Pending, what         *)
(* `stream` does with it (mod.rs:289-296). `Live::finished` also needs    *)
(* `unreported == 0` (live.rs:157); a settled round has `written = 0`    *)
(* here, since a Written is always taken (see Round), so that conjunct is *)
(* implied.                                                               *)
Check ==
  /\ pc = "check"
  /\ LET holds == hKind # "none"
         since == IF holds THEN (IF stalledSince = None THEN now ELSE stalledSince) ELSE None
         timedOut == holds /\ WriteTimeout # NoLimit /\ now >= since + WriteTimeout
         \* `Outstanding::memory` (live.rs:384-385)
         memory == (MemoryStopsIdle /\ refusedLast) \/ (ChildWaitTold /\ childWaits)
         \* `Lifetime::settle`: the idle clock counts only while the run waits
         \* for its peer, from the first settle that found it so
         notWaiting == holds \/ inputOver \/ inKind # "none" \/ memory
         from == IF notWaiting THEN (IF RestartIdleOnWait THEN None ELSE idleFrom)
                 ELSE IF idleFrom = None THEN now ELSE idleFrom
         \* `Lifetime::deadline`: the write limit, else the idle limit
         idleDue == ~holds /\ from # None /\ Idle # NoLimit /\ now >= from + Idle
         \* what the property calls waiting for the peer: nothing to write,
         \* no input held or over, no memory waited for by the stack or a child
         busy == holds \/ inputOver \/ inKind # "none" \/ refusedLast \/ childWaits
         quiet == IF busy THEN None ELSE IF quietFrom = None THEN now ELSE quietFrom
         stuck == IF holds /\ ~wasHolding THEN now ELSE stuckFrom
         dl == ({sTimer} \ {None})
               \cup (IF ~holds /\ from # None /\ Idle # NoLimit THEN {from + Idle} ELSE {})
               \cup (IF since # None /\ WriteTimeout # NoLimit THEN {since + WriteTimeout} ELSE {})
         armed == IF dl = {} THEN None ELSE MinOf(dl)
         finished == shut /\ ~holds /\ (inputOver \/ ~FinishNeedsInputOver)
         \* `wake_when_freed` (live.rs:411, 417): a refusal of the runner's own
         \* view registers it, a starved one does not; room already there
         \* wakes it at once
         registers == refusedLast /\ ~starving
     IN
     /\ wasHolding' = holds /\ stuckFrom' = stuck
     /\ IF timedOut
        THEN /\ stalledSince' = since
             /\ earlyStall' = (now - stuck < WriteTimeout)
             /\ EndBroken("conn", sOver)
             /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, idleFrom,
                            deadline, hKind, hN, sbuf, sout, sEnd, sReset, heardEnded,
                            sTimer, pausesLeft, mem, peer, readTotal, took, refused,
                            transportTook, reported, stackOut, badRead, quietFrom, earlyIdle>>
        ELSE
        /\ stalledSince' = since /\ idleFrom' = from
        /\ quietFrom' = quiet
        /\ IF idleDue
           THEN /\ idled' = TRUE /\ inKind' = "ended" /\ inN' = 0
                /\ earlyIdle' = (earlyIdle \/ quiet = None \/ now - quiet < Idle)
                /\ pc' = "round"
                /\ UNCHANGED <<now, written, inputOver, shut, deadline, hKind, hN, ret,
                               stack, mem, peer, readTotal, took, refused, transportTook,
                               reported, stackOut, offeredReset, badRead, earlyStall>>
           ELSE IF armed # None /\ now >= armed
           THEN \* The sleep is due: round again (live.rs:415-427).
                /\ deadline' = None /\ pc' = "round"
                /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, hKind,
                               hN, ret, stack, mem, peer, readTotal, took, refused,
                               transportTook, reported, stackOut, offeredReset, badRead,
                               earlyIdle, earlyStall>>
           ELSE IF finished
           THEN /\ pc' = "done" /\ ret' = IF idled THEN "idle" ELSE "finished"
                /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, deadline,
                               hKind, hN, stack, mem, peer, readTotal, took, refused,
                               transportTook, reported, stackOut, offeredReset, badRead,
                               earlyIdle, earlyStall>>
           ELSE IF gone
           THEN /\ EndBroken("conn", sOver)
                /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, deadline,
                               hKind, hN, sbuf, sout, sEnd, sReset, heardEnded, sTimer,
                               pausesLeft, mem, peer, readTotal, took, refused, transportTook,
                               reported, stackOut, badRead, earlyIdle, earlyStall>>
           ELSE /\ deadline' = armed /\ pc' = "wait"
                /\ memWait' = registers
                /\ memWoken' = (memWoken \/ (registers /\ ~full))
                /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, hKind,
                               hN, ret, stack, full, fillsLeft, buf, refusedLast,
                               childWaits, starving, peer, readTotal, took, refused,
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
                 deadline, hKind, hN, ret, stack, mem, peer, hist>>

(* Other connections on the budget charge it full...                      *)
Fill ==
  /\ fillsLeft > 0 /\ ~full /\ pc # "done"
  /\ full' = TRUE /\ fillsLeft' = fillsLeft - 1
  /\ UNCHANGED <<runner, stack, buf, refusedLast, memWait, memWoken, childWaits, starving,
                 peer, hist>>

(* ... and give it back. The release wakes a runner that asked to be      *)
(* woken, and a child's waiter wakes the runner the child runs in, also   *)
(* while the runner is settling.                                          *)
Free ==
  /\ full
  /\ full' = FALSE
  /\ memWoken' = (memWoken \/ (WakeOnRelease /\ ((pc = "wait" /\ memWait)
                                                \/ (pc \in {"check", "wait"} /\ childWaits))))
  /\ UNCHANGED <<runner, stack, fillsLeft, buf, refusedLast, memWait, childWaits, starving,
                 peer, hist>>

PeerReset ==
  /\ PeerMayReset /\ pc = "wait" /\ ~gone
  /\ gone' = TRUE
  /\ UNCHANGED <<runner, stack, mem, peerLeft, peerFin, peerStalled, hist>>

(* `stream` polls `poll_gone` when the runner waits (mod.rs:293): a peer  *)
(* that is gone ends the run even if no read or write tries.              *)
Gone ==
  /\ pc = "wait" /\ gone
  /\ EndBroken("conn", sOver)
  /\ UNCHANGED <<now, inKind, inN, written, inputOver, shut, idled, idleFrom, stalledSince,
                 deadline, hKind, hN, sbuf, sout, sEnd, sReset, heardEnded, sTimer,
                 pausesLeft, mem, peer, readTotal, took, refused, transportTook, reported,
                 stackOut, badRead, quietFrom, earlyIdle, wasHolding, stuckFrom, earlyStall>>

Next == Round \/ Check \/ Tick \/ Fill \/ Free \/ PeerReset \/ Gone

Spec == Init /\ [][Next]_vars
        /\ WF_vars(Round) /\ WF_vars(Check) /\ WF_vars(Tick) /\ WF_vars(Gone) /\ WF_vars(Free)

----------------------------------------------------------------------------
(* Properties *)

(* The runner reads only while the stack has taken everything it read     *)
(* before, and its input is not over.                                     *)
ReadOnlyWhenTaken == ~badRead

(* Every byte read is taken by the stack, still held for it, or refused   *)
(* by it as closed. Nothing read is dropped or counted twice, a read      *)
(* whose copy the budget refused included.                                *)
InputKept == readTotal = took + (IF inKind = "data" THEN inN ELSE 0) + refused

(* Each byte the transport took is reported to the stack once.            *)
WrittenOnce == reported + written = transportTook

(* The end of the stack's direction goes out after every byte it wrote.   *)
EndAfterWrites == shut => transportTook = stackOut + sout

(* The idle limit ends input only after no byte moved either way for the *)
(* whole idle time while the runner waited with nothing to write, and    *)
(* neither the stack nor a child of it waited for memory meanwhile.       *)
IdleNeedsQuiet == ~earlyIdle

(* The write limit gives up only after the runner held output that the    *)
(* transport took nothing of for the whole limit.                         *)
StallNeedsNoProgress == ~earlyStall

(* A broken connection is reported to the stack once, as a reset; a       *)
(* connection that ends any other way is not. A run that ends starved     *)
(* drops the stack with the run.                                          *)
ResetHeardOnBreak ==
  pc = "done" => /\ (ret = "conn" => offeredReset = 1)
                 /\ (ret \in {"finished", "idle", "reset", "budget"} => offeredReset = 0)

(* A finished connection has the stack's direction ended; a reset return  *)
(* comes only from the stack's own reset; the budget ends a run only for  *)
(* a need past its whole limit, never for memory that may free.           *)
EndsAreEarned ==
  pc = "done" => /\ (ret \in {"finished", "idle"} => shut)
                 /\ (ret = "idle" => idled)
                 /\ (ret = "finished" => ~idled)
                 /\ (ret = "reset" => sReset = "given")
                 /\ (ret = "budget" => starving)

(* A run finishes only once both directions are over: the stack ended its *)
(* own and its input ended too. `StreamCommand::End` leaves the other     *)
(* direction open, so a stack that ends its direction first may still be  *)
(* reading.                                                               *)
FinishNeedsInput ==
  pc = "done" => (ret \in {"finished", "idle"} => inputOver)

(* With both limits set, every connection ends: a wait for memory ends    *)
(* with the release, and a need past the limit ends the run.              *)
Terminates == <>(pc = "done")
=============================================================================
