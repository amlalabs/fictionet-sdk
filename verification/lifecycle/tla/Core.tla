----------------------------- MODULE Core -----------------------------
(***************************************************************************)
(* The serving state machine of src/stdlib/services/serve.rs: `Core`, as   *)
(* `run` drives it over one connection.  The core is a record `c`; each    *)
(* operator below is named after the Rust function it stands for, and the  *)
(* actions compose them as `run` and `advance` do.                         *)
(*                                                                         *)
(*   Finish / EndNow / Broken / Apply / Call / Collect / Recharge          *)
(*     Core::finish, end_now, broken, apply, call, collect, recharge        *)
(*   Advance*            Core::advance, one case each, in its order        *)
(*   Ending*             Core::ending                                       *)
(*   Wait*               the poll_fn of `run`'s Next::Wait arm, and        *)
(*                       Core::poll_work                                    *)
(*   WriteStep           the write loop at the top of `run`'s loop          *)
(*   YieldCancel         Next::Again's yield_now observing a cancel        *)
(*   CloseReturn         Next::Closed: shutdown, then what `run` returns    *)
(*   UpgradeReturn       Next::Upgrade                                      *)
(*                                                                         *)
(* The service is abstract: every call may append a reply, defer ordered   *)
(* or keyed work, arm the timer, and hand back any Flow or an error.       *)
(* Bytes are counted, not carried.  Writes to the connection take no time  *)
(* (the write limit is the connection's affair); a write may still fail.  *)
(* The budget blows up nondeterministically.  The TLS handshake and        *)
(* `connection`'s region wrapper are outside this module.                  *)
(*                                                                         *)
(* IdleLimit is ServeOptions::idle in ticks; 0 means none.  SuspendIdle    *)
(* FALSE is the code before the fix: the idle clock restarts only on the   *)
(* client's bytes and when keyed work ends.  TRUE restarts it whenever the *)
(* driver resumes waiting for the client after deferred work of either     *)
(* kind.  TotalBroken FALSE is `broken` before the fix, which does nothing *)
(* in Upgrading; TRUE ends the connection there too.                       *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS MaxWork, MaxOut, MaxInput, IdleLimit, SuspendIdle, TotalBroken

Min(a, b) == IF a < b THEN a ELSE b

\* `Ended`.  Conn stands for every ConnError: reset, closed, timed out, broken.
Ends == {"Eof", "Closed", "Failed", "Idle", "Budget", "Conn", "Cancelled"}
Writable(e) == e \in {"Eof", "Closed", "Failed", "Idle", "Budget"}
\* `Flow`, with `Err` for a call that returns the service's error.
Flows == {"Continue", "Close", "Tls", "Handoff", "Decoder", "Err"}
Defers == {"none", "ordered", "keyed"}

VARIABLES
  c,          \* the Core
  pc,         \* "Step": write what is out, then advance.  "Wait".  "Done".
  waitKind,   \* "client": Wait{read: ~eof, wake: TRUE}.  "work": neither.
  input,      \* items the decoder can still yield
  eof,        \* the client half-closed
  timer,      \* "none" | "armed" | "due"
  woken,      \* WakeInner::woken
  cancelled,  \* the region is cancelled
  observed,   \* a wait of the driver returned the cancel
  returned,   \* what `run` returned: "None" until it does
  elapsed,    \* ticks since idle_from
  quiet,      \* ticks the driver waited for the client since its last bytes
  suspended,  \* SuspendIdle: the idle clock was suspended at the last advance
  charged     \* the holding at the last recharge that fit: Charge::now

vars == <<c, pc, waitKind, input, eof, timer, woken, cancelled, observed,
          returned, elapsed, quiet, suspended, charged>>

CoreRecords == [
  state: {"Running", "Ending", "Upgrading", "Ended"},
  end: Ends \cup {"None"},
  called: BOOLEAN,              \* Ending: on_end ran
  how: {"None", "Tls", "Handoff"},
  heldFlow: {"None", "Close", "Tls", "Handoff", "Decoder"},
  ordered: 0..MaxWork,
  keyed: 0..MaxWork,
  out: 0..MaxOut,
  wakeClosed: BOOLEAN,
  failure: BOOLEAN,
  onEnd: 0..2,                  \* on_end calls
  late: 0..1                    \* service calls after Ended
]

HasWork(cc) == cc.ordered > 0 \/ cc.keyed > 0

\* Core::holding, less what never changes: the reply bytes waiting, what
\* deferred work holds, and the bytes read but not decoded.
Holding(cc, inp) == cc.out + cc.ordered + cc.keyed + inp
MaxHolding == MaxOut + 2 * MaxWork + MaxInput

-----------------------------------------------------------------------------
\* Core::end_now
EndNow(cc, e) ==
  [cc EXCEPT !.out = 0, !.heldFlow = "None", !.wakeClosed = TRUE,
             !.state = "Ended", !.end = e]

\* Core::finish
Finish(cc, e) ==
  IF cc.state # "Running" THEN cc ELSE
  [cc EXCEPT !.heldFlow = "None", !.wakeClosed = TRUE, !.keyed = 0,
             !.ordered = IF Writable(e) THEN cc.ordered ELSE 0,
             !.out = IF Writable(e) THEN cc.out ELSE 0,
             !.state = "Ending", !.end = e, !.called = FALSE]

\* Core::cancel_all
CancelAll(cc, ordered) ==
  [cc EXCEPT !.keyed = 0, !.ordered = IF ordered THEN 0 ELSE cc.ordered]

\* Core::broken
Broken(cc, e) ==
  LET c1 == [cc EXCEPT !.out = 0]
  IN IF c1.state = "Ending" \/ (TotalBroken /\ c1.state = "Upgrading")
     THEN EndNow(CancelAll(c1, TRUE), e)
     ELSE Finish(c1, e)

\* Core::collect: the reply and the deferred work of a call
Collect(cc, reply, defer) ==
  [cc EXCEPT !.out = Min(cc.out + reply, MaxOut),
             !.ordered = IF defer = "ordered" THEN Min(cc.ordered + 1, MaxWork) ELSE cc.ordered,
             !.keyed = IF defer = "keyed" THEN Min(cc.keyed + 1, MaxWork) ELSE cc.keyed]

\* Core::call: the service's call, its collected output, and the flow held
Call(cc, flow, reply, defer) ==
  LET c1 == [Collect(cc, reply, defer) EXCEPT
               !.late = IF cc.state = "Ended" THEN 1 ELSE cc.late]
  IN IF flow = "Err" THEN Finish([c1 EXCEPT !.failure = TRUE], "Closed")
     ELSE IF c1.state = "Running" /\ flow # "Continue" /\ c1.heldFlow = "None"
     THEN [c1 EXCEPT !.heldFlow = flow]
     ELSE c1

\* Core::apply
Apply(cc, flow) ==
  CASE flow = "Continue" -> cc
    [] flow = "Close" -> Finish(cc, "Closed")
    [] flow = "Decoder" -> cc
    [] OTHER -> [CancelAll(cc, TRUE) EXCEPT !.state = "Upgrading", !.how = flow]

\* Core::finish_after_work
FinishAfterWork(cc) ==
  IF cc.state # "Running" THEN cc ELSE Finish([cc EXCEPT !.ordered = 0], "Closed")

\* Core::recharge, past the budget
Recharge(cc) ==
  LET c1 == CancelAll([cc EXCEPT !.out = 0], TRUE)
  IN CASE c1.state = "Running" -> Finish(c1, "Budget")
       [] c1.state = "Ending" /\ ~c1.called -> [c1 EXCEPT !.end = "Budget"]
       [] OTHER -> EndNow(c1, "Budget")

-----------------------------------------------------------------------------
Init ==
  /\ c = [state |-> "Running", end |-> "None", called |-> FALSE, how |-> "None",
          heldFlow |-> "None", ordered |-> 0, keyed |-> 0, out |-> 0,
          wakeClosed |-> FALSE, failure |-> FALSE, onEnd |-> 0, late |-> 0]
  /\ pc = "Step"
  /\ waitKind = "client"
  /\ input = 0
  /\ eof = FALSE
  /\ timer = "none"
  /\ woken = FALSE
  /\ cancelled = FALSE
  /\ observed = FALSE
  /\ returned = "None"
  /\ elapsed = 0
  /\ quiet = 0
  /\ suspended = FALSE
  /\ charged = 0

Idle == IdleLimit > 0

-----------------------------------------------------------------------------
\* run: write what is out.  Either every byte is taken, or the write fails.
WriteStep ==
  /\ pc = "Step" /\ c.out > 0
  /\ \/ c' = [c EXCEPT !.out = 0] /\ observed' = observed
     \/ c' = Broken(c, "Conn") /\ observed' = observed
     \/ cancelled /\ observed' = TRUE /\ c' = Broken(c, "Cancelled")
  /\ UNCHANGED <<pc, waitKind, input, eof, timer, woken, cancelled, returned,
                 elapsed, quiet, suspended>>
  /\ charged' = Holding(c, input)

\* run and advance: recharge.  Charge::set refuses only a charge that grew
\* past the budget, so a blow takes a holding above the last one that fit;
\* every other step is a recharge that fit.  What is left still counts.
BudgetBlow ==
  /\ pc = "Step" /\ c.state \notin {"Ended", "Upgrading"}
  /\ Holding(c, input) > charged
  /\ c' = Recharge(c)
  /\ charged' = Holding(c', input)
  /\ UNCHANGED <<pc, waitKind, input, eof, timer, woken, cancelled, observed,
                 returned, elapsed, quiet, suspended>>

\* run: Next::Again every so often yields, and a yield sees the cancel.
YieldCancel ==
  /\ pc = "Step" /\ c.out = 0 /\ cancelled /\ c.state # "Ended"
  /\ observed' = TRUE
  /\ c' = Broken(c, "Cancelled")
  /\ UNCHANGED <<pc, waitKind, input, eof, timer, woken, cancelled, returned,
                 elapsed, quiet, suspended>>
  /\ charged' = Holding(c, input)

Ready == pc = "Step" /\ c.out = 0

\* advance: State::Ended, then run's Next::Closed
CloseReturn ==
  /\ Ready /\ c.state = "Ended"
  /\ pc' = "Done"
  /\ \E shutdownCancelled \in BOOLEAN :
       /\ shutdownCancelled => (Writable(c.end) /\ cancelled)
       /\ returned' = IF c.failure THEN "Failure"
                      ELSE IF c.end = "Cancelled" \/ shutdownCancelled THEN "Cancelled"
                      ELSE "Closed"
  /\ UNCHANGED <<c, waitKind, input, eof, timer, woken, cancelled, observed,
                 elapsed, quiet, suspended>>
  /\ charged' = Holding(c, input)

\* advance: State::Upgrading, then run's Next::Upgrade
UpgradeReturn ==
  /\ Ready /\ c.state = "Upgrading"
  /\ pc' = "Done"
  /\ returned' = "Upgraded"
  /\ c' = [c EXCEPT !.wakeClosed = c.wakeClosed \/ c.how = "Handoff"]
  /\ UNCHANGED <<waitKind, input, eof, timer, woken, cancelled, observed,
                 elapsed, quiet, suspended>>
  /\ charged' = Holding(c, input)

\* advance: State::Ending, Core::ending
EndingWaits ==
  /\ Ready /\ c.state = "Ending" /\ c.ordered > 0
  /\ pc' = "Wait" /\ waitKind' = "work"
  /\ UNCHANGED <<c, input, eof, timer, woken, cancelled, observed, returned,
                 elapsed, quiet, suspended>>
  /\ charged' = Holding(c, input)

EndingEnds ==
  /\ Ready /\ c.state = "Ending" /\ c.ordered = 0 /\ c.called
  /\ c' = [c EXCEPT !.state = "Ended"]
  /\ UNCHANGED <<pc, waitKind, input, eof, timer, woken, cancelled, observed,
                 returned, elapsed, quiet, suspended>>
  /\ charged' = Holding(c, input)

\* on_end: its reply and ordered work are kept for a writable end; keyed
\* requests are dropped either way.
EndingCalls ==
  /\ Ready /\ c.state = "Ending" /\ c.ordered = 0 /\ ~c.called
  /\ \E flow \in {"Continue", "Err"}, reply \in 0..1, defer \in {"none", "ordered"} :
       LET c1 == [c EXCEPT !.called = TRUE, !.onEnd = c.onEnd + 1,
                           !.failure = c.failure \/ flow = "Err"]
       IN c' = IF Writable(c.end) THEN Collect(c1, reply, defer) ELSE c1
  /\ UNCHANGED <<pc, waitKind, input, eof, timer, woken, cancelled, observed, returned,
                 elapsed, quiet, suspended>>
  /\ charged' = Holding(c, input)

\* advance: State::Running.  The idle clock first (SuspendIdle), then the
\* cases of `advance` in order; each is enabled only when those before
\* it are not.
Running == Ready /\ c.state = "Running"

\* The idle clock as SuspendIdle has it: restarted when the driver resumes
\* waiting for the client after deferred work.
IdleClock(resumed) == IF SuspendIdle /\ resumed THEN 0 ELSE elapsed
Resumed == ~HasWork(c) /\ suspended
IdleSuspendedNow == IF SuspendIdle THEN HasWork(c) ELSE c.keyed > 0

AdvanceOrdered ==
  /\ Running /\ c.ordered > 0
  /\ pc' = "Wait" /\ waitKind' = "work"
  /\ suspended' = HasWork(c) /\ elapsed' = IdleClock(Resumed)
  /\ UNCHANGED <<c, input, eof, timer, woken, cancelled, observed, returned, quiet>>
  /\ charged' = Holding(c, input)

AdvanceHeld ==
  /\ Running /\ c.ordered = 0 /\ c.heldFlow # "None"
  /\ c' = Apply([c EXCEPT !.heldFlow = "None"], c.heldFlow)
  /\ suspended' = HasWork(c) /\ elapsed' = IdleClock(Resumed)
  /\ UNCHANGED <<pc, waitKind, input, eof, timer, woken, cancelled, observed, returned, quiet>>
  /\ charged' = Holding(c, input)

AdvanceTimer ==
  /\ Running /\ c.ordered = 0 /\ c.heldFlow = "None" /\ timer = "due"
  /\ \E flow \in Flows, reply \in 0..1, defer \in Defers, arm \in BOOLEAN :
       /\ c' = Call(c, flow, reply, defer)
       /\ timer' = IF arm THEN "armed" ELSE "none"
  /\ suspended' = HasWork(c) /\ elapsed' = IdleClock(Resumed)
  /\ UNCHANGED <<pc, waitKind, input, eof, woken, cancelled, observed, returned, quiet>>
  /\ charged' = Holding(c, input)

AdvanceWake ==
  /\ Running /\ c.ordered = 0 /\ c.heldFlow = "None" /\ timer # "due" /\ woken
  /\ woken' = FALSE
  /\ \E flow \in Flows, reply \in 0..1, defer \in Defers, arm \in BOOLEAN :
       /\ c' = Call(c, flow, reply, defer)
       /\ timer' = IF arm THEN "armed" ELSE timer
  /\ suspended' = HasWork(c) /\ elapsed' = IdleClock(Resumed)
  /\ UNCHANGED <<pc, waitKind, input, eof, cancelled, observed, returned, quiet>>
  /\ charged' = Holding(c, input)

Quiet == c.ordered = 0 /\ c.heldFlow = "None" /\ timer # "due" /\ ~woken

IdleDue == Idle /\ ~IdleSuspendedNow /\ IdleClock(Resumed) >= IdleLimit

AdvanceIdle ==
  /\ Running /\ Quiet /\ IdleDue
  /\ c' = Finish(c, "Idle")
  /\ suspended' = HasWork(c) /\ elapsed' = IdleClock(Resumed)
  /\ UNCHANGED <<pc, waitKind, input, eof, timer, woken, cancelled, observed, returned, quiet>>
  /\ charged' = Holding(c, input)

\* An item, a decoder failure (on_fail, then Ended::Failed), or the decoder's
\* end (on_decoder_end, whose Continue is Upgrade::Decoder).
AdvanceItem ==
  /\ Running /\ Quiet /\ ~IdleDue /\ input > 0
  /\ input' = input - 1
  /\ \/ \E flow \in Flows, reply \in 0..1, defer \in Defers, arm \in BOOLEAN :
          /\ c' = Call(c, flow, reply, defer)
          /\ timer' = IF arm THEN "armed" ELSE timer
     \/ \E reply \in 0..1, defer \in Defers, err \in BOOLEAN :
          LET c1 == [Collect(c, reply, defer) EXCEPT !.failure = c.failure \/ err]
          IN /\ c' = Finish(c1, "Failed")
             /\ timer' = timer
     \/ \E flow \in Flows \ {"Continue"}, reply \in 0..1, defer \in Defers :
          /\ c' = Call(c, flow, reply, defer)
          /\ timer' = timer
  /\ suspended' = HasWork(c) /\ elapsed' = IdleClock(Resumed)
  /\ UNCHANGED <<pc, waitKind, eof, woken, cancelled, observed, returned, quiet>>
  /\ charged' = Holding(c, input)

AdvanceEof ==
  /\ Running /\ Quiet /\ ~IdleDue /\ input = 0 /\ eof
  /\ c' = Finish(c, "Eof")
  /\ suspended' = HasWork(c) /\ elapsed' = IdleClock(Resumed)
  /\ UNCHANGED <<pc, waitKind, input, eof, timer, woken, cancelled, observed, returned, quiet>>
  /\ charged' = Holding(c, input)

AdvanceWaits ==
  /\ Running /\ Quiet /\ ~IdleDue /\ input = 0 /\ ~eof
  /\ pc' = "Wait" /\ waitKind' = "client"
  /\ suspended' = HasWork(c) /\ elapsed' = IdleClock(Resumed)
  /\ UNCHANGED <<c, input, eof, timer, woken, cancelled, observed, returned, quiet>>
  /\ charged' = Holding(c, input)

-----------------------------------------------------------------------------
\* The wait.  The poll checks the cancel first, so nothing else happens
\* while the region is cancelled.
Waiting == pc = "Wait" /\ ~cancelled

WaitCancelled ==
  /\ pc = "Wait" /\ cancelled
  /\ observed' = TRUE
  /\ c' = Broken(c, "Cancelled")
  /\ pc' = "Step"
  /\ UNCHANGED <<waitKind, input, eof, timer, woken, cancelled, returned, elapsed, quiet, suspended>>
  /\ UNCHANGED charged

\* Bytes from the client: idle_from = now.
WaitInput ==
  /\ Waiting /\ waitKind = "client" /\ ~eof /\ input < MaxInput
  /\ input' = input + 1 /\ elapsed' = 0 /\ quiet' = 0
  /\ pc' = "Step"
  /\ UNCHANGED <<c, waitKind, eof, timer, woken, cancelled, observed, returned, suspended>>
  /\ UNCHANGED charged

WaitEof ==
  /\ Waiting /\ waitKind = "client" /\ ~eof
  /\ eof' = TRUE /\ pc' = "Step"
  /\ UNCHANGED <<c, waitKind, input, timer, woken, cancelled, observed, returned, elapsed, quiet, suspended>>
  /\ UNCHANGED charged

\* A read error, or the gone watch: the peer reset the connection.
WaitBroken ==
  /\ Waiting
  /\ c' = Broken(c, "Conn") /\ pc' = "Step"
  /\ UNCHANGED <<waitKind, input, eof, timer, woken, cancelled, observed, returned, elapsed, quiet, suspended>>
  /\ UNCHANGED charged

WaitWake ==
  /\ Waiting /\ waitKind = "client" /\ woken
  /\ pc' = "Step"
  /\ UNCHANGED <<c, waitKind, input, eof, timer, woken, cancelled, observed, returned, elapsed, quiet, suspended>>
  /\ UNCHANGED charged

WaitTimer ==
  /\ Waiting /\ waitKind = "client" /\ timer = "due"
  /\ pc' = "Step"
  /\ UNCHANGED <<c, waitKind, input, eof, timer, woken, cancelled, observed, returned, elapsed, quiet, suspended>>
  /\ UNCHANGED charged

\* The idle deadline.
WaitIdle ==
  /\ Waiting /\ waitKind = "client" /\ Idle /\ ~IdleSuspendedNow /\ elapsed >= IdleLimit
  /\ pc' = "Step"
  /\ UNCHANGED <<c, waitKind, input, eof, timer, woken, cancelled, observed, returned, elapsed, quiet, suspended>>
  /\ UNCHANGED charged

\* poll_work: the ordered work in front.
WaitOrderedBytes ==
  /\ Waiting /\ c.ordered > 0
  /\ c' = [c EXCEPT !.out = Min(c.out + 1, MaxOut)] /\ pc' = "Step"
  /\ UNCHANGED <<waitKind, input, eof, timer, woken, cancelled, observed, returned, elapsed, quiet, suspended>>
  /\ UNCHANGED charged

WaitOrderedDone ==
  /\ Waiting /\ c.ordered > 0
  /\ \E close \in BOOLEAN :
       LET c1 == [c EXCEPT !.ordered = c.ordered - 1]
       IN c' = IF close THEN FinishAfterWork(c1) ELSE c1
  /\ pc' = "Step"
  /\ UNCHANGED <<waitKind, input, eof, timer, woken, cancelled, observed, returned, elapsed, quiet, suspended>>
  /\ UNCHANGED charged

WaitOrderedErr ==
  /\ Waiting /\ c.ordered > 0
  /\ c' = Finish([c EXCEPT !.ordered = 0, !.failure = TRUE], "Closed") /\ pc' = "Step"
  /\ UNCHANGED <<waitKind, input, eof, timer, woken, cancelled, observed, returned, elapsed, quiet, suspended>>
  /\ UNCHANGED charged

\* poll_work: keyed work, polled only while Running.
WaitKeyedBytes ==
  /\ Waiting /\ c.keyed > 0 /\ c.state = "Running"
  /\ c' = [c EXCEPT !.out = Min(c.out + 1, MaxOut)] /\ pc' = "Step"
  /\ UNCHANGED <<waitKind, input, eof, timer, woken, cancelled, observed, returned, elapsed, quiet, suspended>>
  /\ UNCHANGED charged

\* Keyed work ends: on_done, then finish_after_work if it asked to close.
\* Before the fix, idle_from = now here.
WaitKeyedDone ==
  /\ Waiting /\ c.keyed > 0 /\ c.state = "Running"
  /\ \E close \in BOOLEAN, flow \in Flows, reply \in 0..1, defer \in Defers, arm \in BOOLEAN :
       LET c1 == Call([c EXCEPT !.keyed = c.keyed - 1], flow, reply, defer)
       IN /\ c' = IF close THEN FinishAfterWork(c1) ELSE c1
          /\ timer' = IF arm THEN "armed" ELSE timer
  /\ elapsed' = IF SuspendIdle THEN elapsed ELSE 0
  /\ pc' = "Step"
  /\ UNCHANGED <<waitKind, input, eof, woken, cancelled, observed, returned, quiet, suspended>>
  /\ UNCHANGED charged

\* Time passes while the driver waits.  The client's quiet time counts
\* only while the driver reads.
Tick ==
  /\ pc = "Wait" /\ Idle
  /\ elapsed' = Min(elapsed + 1, IdleLimit)
  /\ quiet' = IF waitKind = "client" /\ ~eof THEN Min(quiet + 1, IdleLimit) ELSE quiet
  /\ UNCHANGED <<c, pc, waitKind, input, eof, timer, woken, cancelled, observed, returned, suspended>>
  /\ UNCHANGED charged

-----------------------------------------------------------------------------
\* The world: a cancel, a wake, a timer coming due.
Cancel ==
  /\ ~cancelled /\ cancelled' = TRUE
  /\ UNCHANGED <<c, pc, waitKind, input, eof, timer, woken, observed, returned, elapsed, quiet, suspended>>
  /\ UNCHANGED charged

\* WakeHandle::wake does nothing once closed.
Wake ==
  /\ ~c.wakeClosed /\ ~woken /\ woken' = TRUE
  /\ UNCHANGED <<c, pc, waitKind, input, eof, timer, cancelled, observed, returned, elapsed, quiet, suspended>>
  /\ UNCHANGED charged

TimerFires ==
  /\ timer = "armed" /\ timer' = "due"
  /\ UNCHANGED <<c, pc, waitKind, input, eof, woken, cancelled, observed, returned, elapsed, quiet, suspended>>
  /\ UNCHANGED charged

-----------------------------------------------------------------------------
Driver ==
  \/ WriteStep \/ BudgetBlow \/ YieldCancel
  \/ CloseReturn \/ UpgradeReturn
  \/ EndingWaits \/ EndingEnds \/ EndingCalls
  \/ AdvanceOrdered \/ AdvanceHeld \/ AdvanceTimer \/ AdvanceWake \/ AdvanceIdle
  \/ AdvanceItem \/ AdvanceEof \/ AdvanceWaits
  \/ WaitCancelled \/ WaitInput \/ WaitEof \/ WaitBroken \/ WaitWake \/ WaitTimer \/ WaitIdle
  \/ WaitOrderedBytes \/ WaitOrderedDone \/ WaitOrderedErr
  \/ WaitKeyedBytes \/ WaitKeyedDone

Next == Driver \/ Tick \/ Cancel \/ Wake \/ TimerFires

\* The driver keeps stepping.  Deferred work ends eventually, however many
\* frames it writes first (strong: writing a frame leaves the wait).  A
\* run of Next::Again yields every 64th time, so a yield sees a cancel
\* eventually, however busy the service's wakes and timers keep the driver.
WorkEnds == WaitOrderedDone \/ WaitOrderedErr \/ WaitKeyedDone
Fairness == WF_vars(Driver) /\ SF_vars(WorkEnds) /\ SF_vars(YieldCancel)

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
TypeOK ==
  /\ c \in CoreRecords
  /\ pc \in {"Step", "Wait", "Done"}
  /\ waitKind \in {"client", "work"}
  /\ input \in 0..MaxInput
  /\ eof \in BOOLEAN
  /\ timer \in {"none", "armed", "due"}
  /\ woken \in BOOLEAN /\ cancelled \in BOOLEAN /\ observed \in BOOLEAN
  /\ returned \in {"None", "Closed", "Upgraded", "Cancelled", "Failure"}
  /\ elapsed \in 0..IdleLimit /\ quiet \in 0..IdleLimit
  /\ suspended \in BOOLEAN
  /\ charged \in 0..MaxHolding

\* on_end is called at most once, and never after the connection ended.
OnEndOnce == c.onEnd <= 1
NoLateCalls == c.late = 0

\* The wake handle is open exactly while the service runs, and after a
\* STARTTLS handoff, which goes on with the same handle.
WakeHandle ==
  /\ c.state \in {"Ending", "Ended"} => c.wakeClosed
  /\ c.state = "Running" => ~c.wakeClosed
  /\ returned = "Upgraded" => (c.wakeClosed <=> c.how = "Handoff")

\* No deferred work outlives the connection; keyed work ends with Running.
WorkAtEnd ==
  /\ c.state = "Ended" => c.ordered = 0 /\ c.keyed = 0
  /\ c.state \in {"Ending", "Upgrading"} => c.keyed = 0
  /\ c.state = "Upgrading" => c.ordered = 0

\* An end the connection cannot take a reply for writes nothing more.
Unwritable ==
  (c.state \in {"Ending", "Ended"} /\ ~Writable(c.end)) => c.out = 0 /\ c.ordered = 0

\* A writable end always reached on_end.
WritableEndHeard == (c.state = "Ended" /\ Writable(c.end)) => c.onEnd = 1

\* Once the driver has seen the cancel, it returns it, unless a failure
\* wins, or the budget blows while the connection ends: `recharge` then
\* renames the end, which takes a service whose `held` grows in `on_end`.
ObservedCancel ==
  (observed /\ returned # "None") => returned \in {"Cancelled", "Failure"} \/ c.end = "Budget"

\* An idle end only after the client had the whole idle time to speak
\* while the driver listened.
IdleNeedsQuiet ==
  [][(c.state = "Running" /\ c'.state = "Ending" /\ c'.end = "Idle") => quiet >= IdleLimit]_vars

\* Liveness: an ending connection ends; a cancelled one returns.
EndingTerminates == (c.state = "Ending") ~> (c.state = "Ended")
CancelReturns == cancelled ~> (returned # "None")
=============================================================================
