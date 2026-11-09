---------------------------- MODULE RouteTrace ----------------------------
(* Replays a log of the Rust routing code against Route.                 *)
(*                                                                       *)
(* The log comes from src/stdlib/layer/route_trace.rs, which runs the    *)
(* real Chain<L, Switch<A, B>> and Driver with abstract layers whose     *)
(* every answer is drawn from a seed: the owner's actions with their     *)
(* answers, and every call into a layer while the stack runs, with the   *)
(* bytes offered and the answer given. Each step below is the Route step *)
(* of the same name with its choices pinned to the log entry it accounts *)
(* for: the bytes offered must be the ones the model holds there, and    *)
(* the answer must be the one the code gave. Steps the code makes        *)
(* without calling a layer (the chain taking an item into its slot, the  *)
(* switch refusing input while leftovers wait) consume no entry.         *)
(*                                                                       *)
(* The log is a behavior of the model when every entry is consumed and   *)
(* Route's invariants hold throughout. A log the model cannot follow has *)
(* no next step, so TLC reports a deadlock at the entry where the code   *)
(* and the model disagree. `cargo xtask layer-verify trace` makes the    *)
(* logs and runs this.                                                   *)
EXTENDS Route

CONSTANT Log
VARIABLE i

tvars == <<vars, urgentVars, i>>

InLog == i <= Len(Log)
Entry == Log[i]
Consume == i' = i + 1
Keep == UNCHANGED i

\* `s` cut into chunks of the lengths `lens`, as the code chunked it.
RECURSIVE SplitBy(_, _)
SplitBy(s, lens) ==
  IF lens = <<>> THEN <<>>
  ELSE <<SubSeq(s, 1, Head(lens))>>
       \o SplitBy(SubSeq(s, Head(lens) + 1, Len(s)), Tail(lens))

---------------------------------------------------------------------------
(* The owner's actions, each pinned to its entry.                        *)

TInjectUp == /\ InLog /\ Entry.a = "InjectUp"
             /\ InjectUp /\ nextUp' = nextUp + Entry.k
             /\ Consume
TInjectDown == /\ InLog /\ Entry.a = "InjectDown"
               /\ InjectDown /\ nextDown' = nextDown + Entry.k
               /\ Consume
TDeliver == /\ InLog /\ Entry.a = "Deliver"
            /\ inQ # <<>> /\ Head(inQ) = Entry.c
            /\ Deliver
            /\ lIn' = Took(lIn, Head(inQ), Entry.k)
            /\ upDropped' = Dropped(upDropped, Head(inQ), Entry.k)
            /\ Consume
TCommand == /\ InLog /\ Entry.a = "Command"
            /\ cmdQ # <<>> /\ Head(cmdQ) = Entry.c
            /\ Command
            /\ IF phase = "First" THEN aCmdIn' = Took(aCmdIn, Head(cmdQ), Entry.k)
                                  ELSE bCmdIn' = Took(bCmdIn, Head(cmdQ), Entry.k)
            /\ downDropped' = Dropped(downDropped, Head(cmdQ), Entry.k)
            /\ Consume
TSendBelow == /\ InLog /\ Entry.a = "SendBelow"
              /\ LET item == IF dBelow # None THEN dBelow ELSE Head(lCmdOut) IN
                 /\ (dBelow # None \/ lCmdOut # <<>>)
                 /\ item = Entry.c
                 /\ SendBelow
                 /\ bottomOut' = Took(bottomOut, item, Entry.k)
                 /\ downDropped' = Dropped(downDropped, item, Entry.k)
              /\ Consume
TSendAbove == /\ InLog /\ Entry.a = "SendAbove"
              /\ LET source == IF phase = "First" THEN aOut ELSE bOut
                     item == IF dAbove # None THEN dAbove ELSE Head(source) IN
                 /\ (dAbove # None \/ source # <<>>)
                 /\ item = Entry.c
                 /\ SendAbove
                 /\ topOut' = Took(topOut, item, Entry.k)
                 /\ upDropped' = Dropped(upDropped, item, Entry.k)
              /\ Consume
TStartRun == /\ InLog /\ Entry.a = "Run"
             /\ StartRun
             /\ Consume

TOwner == TInjectUp \/ TInjectDown \/ TDeliver \/ TCommand
          \/ TSendBelow \/ TSendAbove \/ TStartRun

---------------------------------------------------------------------------
(* One Chain::advance, each statement pinned to the call it made.        *)

\* L::advance: which buffer it moved and how much.
TStepL == /\ pc = "L" /\ InLog /\ Entry.a = "LAdvance"
          /\ StepL
          /\ CASE Entry.w = "up" -> /\ lOut' = Append(lOut, Pre(lIn, Entry.k))
                                    /\ lIn' = Rest(lIn, Entry.k)
               [] Entry.w = "down" -> /\ lCmdOut' = Append(lCmdOut, Pre(lCmdIn, Entry.k))
                                      /\ lCmdIn' = Rest(lCmdIn, Entry.k)
               [] OTHER -> UNCHANGED <<lIn, lOut, lCmdIn, lCmdOut>>
          /\ Consume

\* A::advance before the switch, B::advance after it.
TStepS == /\ pc = "S" /\ InLog
          /\ StepS
          /\ IF phase = "First"
               THEN /\ Entry.a = "AAdvance"
                    /\ CASE Entry.w = "use" -> /\ aUsed' = aUsed \cup Range(Pre(aIn, Entry.k))
                                               /\ aIn' = Rest(aIn, Entry.k)
                                               /\ UNCHANGED aOut
                         [] Entry.w = "up" -> /\ aOut' = Append(aOut, Pre(aIn, Entry.k))
                                              /\ aIn' = Rest(aIn, Entry.k)
                                              /\ UNCHANGED aUsed
                         [] Entry.w = "down" -> /\ aCmdOut' = Append(aCmdOut, Pre(aCmdIn, Entry.k))
                                                /\ aCmdIn' = Rest(aCmdIn, Entry.k)
                         [] Entry.w = "done" -> aDone' = TRUE /\ ~aDone
                         [] OTHER -> UNCHANGED <<aIn, aOut, aUsed, aCmdIn, aCmdOut, aDone>>
               ELSE /\ Entry.a = "BAdvance"
                    /\ CASE Entry.w = "up" -> /\ bOut' = Append(bOut, Pre(bIn, Entry.k))
                                              /\ bIn' = Rest(bIn, Entry.k)
                         [] Entry.w = "down" -> /\ bCmdOut' = Append(bCmdOut, Pre(bCmdIn, Entry.k))
                                                /\ bCmdIn' = Rest(bCmdIn, Entry.k)
                         [] OTHER -> UNCHANGED <<bIn, bOut, bCmdIn, bCmdOut>>
          /\ Consume

\* The handover, when A is past its boundary with its output taken: the
\* code's chunking of the leftovers. Otherwise nothing was called.
TStepH == /\ pc = "H"
          /\ IF aDone /\ aOut = <<>> /\ aCmdOut = <<>>
               THEN /\ InLog /\ Entry.a = "Handover"
                    /\ StepH
                    /\ swBelow' = swBelow \o SplitBy(aIn, Entry.sb)
                    /\ swAbove' = swAbove \o SplitBy(aCmdIn, Entry.sa)
                    /\ Consume
               ELSE StepH /\ Keep

\* The first leftover from below offered to B.
TStepSB == /\ pc = "SB"
           /\ IF swBelow # <<>>
                THEN /\ InLog /\ Entry.a = "BEvent" /\ Entry.c = Head(swBelow)
                     /\ StepSB
                     /\ bIn' = Took(bIn, Head(swBelow), Entry.k)
                     /\ upDropped' = Dropped(upDropped, Head(swBelow), Entry.k)
                     /\ Consume
                ELSE StepSB /\ Keep

\* The first leftover from above offered to B.
TStepSA == /\ pc = "SA"
           /\ IF swAbove # <<>>
                THEN /\ InLog /\ Entry.a = "BCommand" /\ Entry.c = Head(swAbove)
                     /\ StepSA
                     /\ bCmdIn' = Took(bCmdIn, Head(swAbove), Entry.k)
                     /\ downDropped' = Dropped(downDropped, Head(swAbove), Entry.k)
                     /\ Consume
                ELSE StepSA /\ Keep

TStepTU == pc = "TU" /\ StepTU /\ Keep

\* The slot's event offered to the switch. While leftovers wait, the
\* switch refuses it without calling B (switch.rs Switch::on_event), so
\* nothing is logged; otherwise A or B answered.
TStepOU == /\ pc = "OU"
           /\ IF cUp # None /\ ~(phase = "Then" /\ swBelow # <<>>)
                THEN /\ InLog
                     /\ Entry.a = IF phase = "First" THEN "AEvent" ELSE "BEvent"
                     /\ Entry.c = cUp
                     /\ StepOU
                     /\ IF phase = "First" THEN aIn' = Took(aIn, cUp, Entry.k)
                                           ELSE bIn' = Took(bIn, cUp, Entry.k)
                     /\ upDropped' = Dropped(upDropped, cUp, Entry.k)
                     /\ Consume
                ELSE StepOU /\ Keep

TStepTD == pc = "TD" /\ StepTD /\ Keep

\* The slot's command offered to L.
TStepOD == /\ pc = "OD"
           /\ IF cDown # None
                THEN /\ InLog /\ Entry.a = "LCommand" /\ Entry.c = cDown
                     /\ StepOD
                     /\ lCmdIn' = Took(lCmdIn, cDown, Entry.k)
                     /\ downDropped' = Dropped(downDropped, cDown, Entry.k)
                     /\ Consume
                ELSE StepOD /\ Keep

TStepE == pc = "E" /\ StepE /\ Keep

TRunStep == running /\ (TStepL \/ TStepS \/ TStepH \/ TStepSB \/ TStepSA
                        \/ TStepTU \/ TStepOU \/ TStepTD \/ TStepOD \/ TStepE)

\* The whole log consumed and the run over: the behavior stutters from
\* here. Until then exactly one step is possible, so a log the model
\* cannot follow deadlocks at its first unexplained entry, and a log that
\* ends while the model is still running deadlocks at the entry it lacks.
LogDone == ~InLog /\ ~running /\ UNCHANGED <<vars, i>>

TraceNext == TOwner \/ TRunStep \/ LogDone

TraceSpec == Init /\ UrgentInit /\ i = 1
             /\ [][TraceNext /\ UNCHANGED urgentVars]_tvars
=============================================================================
