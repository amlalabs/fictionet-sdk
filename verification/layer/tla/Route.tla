------------------------------ MODULE Route ------------------------------
(* How Chain and Switch route items between layers, driven by a Driver.  *)
(*                                                                       *)
(* The stack is Chain<L, Switch<A, B>> (src/stdlib/layer/chain.rs,       *)
(* switch.rs) run by a Driver (driver.rs) whose owner is a harness       *)
(* (harness.rs): the owner offers byte-stream chunks from below          *)
(* (Driver::deliver), commands from above (Driver::command), takes       *)
(* output each way (Driver::send_below, Driver::send_above), and runs    *)
(* the stack (Driver::run).                                              *)
(*                                                                       *)
(* Every byte is a token: the n-th byte from below is n, and so is the  *)
(* n-th byte from above. A chunk is a sequence of tokens. The layers are *)
(* abstract: every entry point may answer an offer in any way rule 1     *)
(* allows (take all, take a prefix and hand back the rest, refuse it     *)
(* whole as Blocked or as Closed), and every advance may move any prefix *)
(* of what a layer holds to its output. L and B pass bytes through. A is *)
(* a protocol that may use bytes from below itself (a CONNECT request),  *)
(* pass bytes on either way, and reach its boundary at any moment. At    *)
(* the boundary it takes nothing more, and once its own output has been  *)
(* taken it hands over what it took and did not use (Handoff::handover). *)
(*                                                                       *)
(* No layer here has urgent events: `take_urgent` answers None, as the   *)
(* trait's default does, so the urgent slot of Chain (chain.rs:140-149)  *)
(* and of the Driver (driver.rs:206-224) stays empty and the code runs   *)
(* exactly the statements below. A layer with urgent events (TlsLayer's  *)
(* Written credit) can pass a refused event; this model does not cover   *)
(* that ordering.                                                        *)
(*                                                                       *)
(* Source correspondence (file:line in src/stdlib/layer/):               *)
(*   Offer, the caller side of an answer   chain.rs:62 `offer`           *)
(*   RunStep "L","S","TU","OU","TD","OD"   chain.rs:133 Chain::advance   *)
(*   RunStep "S" and "H" in First          switch.rs:195-205             *)
(*   RunStep "S","SB","SA" in Then         switch.rs:207-223, `feed` :101*)
(*   SwitchEvent, SwitchCommand            switch.rs:128-159             *)
(*   StartRun, RunStep "E"                 driver.rs:168 Driver::run     *)
(*   SendBelow, SendAbove                  driver.rs:190-226, `send` :246*)
(*   Deliver                               driver.rs:142, harness.rs:249 *)
(*   Command                               driver.rs:151                 *)
(*                                                                       *)
(* Flags keep a part of the code as it is (TRUE) or break it (FALSE):    *)
(*   KeepBlocked     offer keeps an item refused as Blocked              *)
(*   KeepRest        offer keeps only the rest of a partly taken item    *)
(*   BlockedIsStill  offer reports a Blocked answer as no progress       *)
(*   LeftoversFirst  Switch refuses new input while leftovers remain     *)
(*   RestFirst       feed puts the rest back at the front of the queue   *)
(*   MoveAbove       the switch moves the handover's commands to B       *)
(*   SwitchOnce      the switch drops A and runs B after the handover    *)
(*   DriverKeepsRest Driver's send keeps the rest the carrier handed back*)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS NU,   \* bytes the peer sends from below
          ND,   \* bytes the application sends from above
          KeepBlocked, KeepRest, BlockedIsStill, LeftoversFirst,
          RestFirst, MoveAbove, SwitchOnce, DriverKeepsRest, UrgentBypass

VARIABLES
  \* from below, upward
  nextUp, inQ, lIn, lOut, cUp, aIn, aOut, aUsed, swBelow, bIn, bOut,
  dAbove, topOut, upDropped,
  \* from above, downward
  nextDown, cmdQ, aCmdIn, aCmdOut, swAbove, bCmdIn, bCmdOut, cDown,
  lCmdIn, lCmdOut, dBelow, bottomOut, downDropped,
  \* control
  phase, aDone, handovers, running, pc, moved

upVars == <<nextUp, inQ, lIn, lOut, cUp, aIn, aOut, aUsed, swBelow, bIn,
            bOut, dAbove, topOut, upDropped>>
downVars == <<nextDown, cmdQ, aCmdIn, aCmdOut, swAbove, bCmdIn, bCmdOut,
              cDown, lCmdIn, lCmdOut, dBelow, bottomOut, downDropped>>
ctlVars == <<phase, aDone, handovers, running, pc, moved>>
vars == <<upVars, downVars, ctlVars>>

None == <<>>   \* an empty Option<T> slot; chunks are never empty

RECURSIVE Flat(_)
Flat(q) == IF q = <<>> THEN <<>> ELSE Head(q) \o Flat(Tail(q))

\* Every way to cut a sequence into nonempty chunks, in order.
RECURSIVE Splits(_)
Splits(s) == IF s = <<>> THEN {<<>>}
             ELSE UNION {{<<SubSeq(s, 1, k)>> \o r : r \in Splits(SubSeq(s, k + 1, Len(s)))}
                         : k \in 1..Len(s)}

Range(s) == {s[i] : i \in DOMAIN s}
Increasing(s) == \A i \in 1..(Len(s) - 1) : s[i] < s[i + 1]
Pre(c, k) == SubSeq(c, 1, k)
Rest(c, k) == SubSeq(c, k + 1, Len(c))
Run(from, k) == [i \in 1..k |-> from + i - 1]

\* The answers a layer may give to chunk c (rule 1): -1 is Closed, 0 is
\* Blocked, Len(c) is Taken, anything between is Partial with the rest.
Answers(c, mayClose) == (0..Len(c)) \cup (IF mayClose THEN {-1} ELSE {})
Took(buf, c, k) == IF k > 0 THEN buf \o Pre(c, k) ELSE buf
Dropped(set, c, k) == IF k = -1 THEN set \cup Range(c) ELSE set

\* chain.rs:62 `offer`: what the slot holds after answer k to item c, and
\* whether anything moved.
OfferSlot(c, k) ==
  CASE k = 0 -> IF KeepBlocked THEN c ELSE None
    [] k > 0 /\ k < Len(c) -> IF KeepRest THEN Rest(c, k) ELSE c
    [] OTHER -> None
OfferMoved(c, k) == IF k = 0 THEN ~BlockedIsStill ELSE TRUE

\* switch.rs:101 `feed`: the queue after answer k to its first item.
FeedQueue(q, k) ==
  LET c == Head(q) IN
  CASE k = 0 -> q
    [] k > 0 /\ k < Len(c) -> IF RestFirst THEN <<Rest(c, k)>> \o Tail(q)
                              ELSE Tail(q) \o <<Rest(c, k)>>
    [] OTHER -> Tail(q)

\* What the owner keeps of the first of its queue (harness.rs:249-263).
OwnerQueue(q, k) ==
  LET c == Head(q) IN
  CASE k = 0 -> q
    [] k > 0 /\ k < Len(c) -> <<Rest(c, k)>> \o Tail(q)
    [] OTHER -> Tail(q)

Init ==
  /\ nextUp = 1 /\ inQ = <<>> /\ lIn = <<>> /\ lOut = <<>> /\ cUp = None
  /\ aIn = <<>> /\ aOut = <<>> /\ aUsed = {} /\ swBelow = <<>>
  /\ bIn = <<>> /\ bOut = <<>> /\ dAbove = None /\ topOut = <<>>
  /\ upDropped = {}
  /\ nextDown = 1 /\ cmdQ = <<>> /\ aCmdIn = <<>> /\ aCmdOut = <<>>
  /\ swAbove = <<>> /\ bCmdIn = <<>> /\ bCmdOut = <<>> /\ cDown = None
  /\ lCmdIn = <<>> /\ lCmdOut = <<>> /\ dBelow = None /\ bottomOut = <<>>
  /\ downDropped = {}
  /\ phase = "First" /\ aDone = FALSE /\ handovers = 0
  /\ running = FALSE /\ pc = "idle" /\ moved = FALSE

---------------------------------------------------------------------------
(* The owner, between runs.                                               *)

\* The peer sends the next k bytes as one chunk; the application asks to
\* send the next k bytes.
InjectUp == /\ nextUp <= NU
            /\ \E k \in 1..(NU - nextUp + 1) :
                 /\ inQ' = Append(inQ, Run(nextUp, k))
                 /\ nextUp' = nextUp + k
            /\ UNCHANGED <<lIn, lOut, cUp, aIn, aOut, aUsed, swBelow, bIn, bOut,
                           dAbove, topOut, upDropped, downVars, ctlVars>>
InjectDown == /\ nextDown <= ND
              /\ \E k \in 1..(ND - nextDown + 1) :
                   /\ cmdQ' = Append(cmdQ, Run(nextDown, k))
                   /\ nextDown' = nextDown + k
              /\ UNCHANGED <<aCmdIn, aCmdOut, swAbove, bCmdIn, bCmdOut, cDown,
                             lCmdIn, lCmdOut, dBelow, bottomOut, downDropped,
                             upVars, ctlVars>>

\* driver.rs:142 Driver::deliver -> Chain::on_event -> L::on_event; the
\* harness keeps what is handed back and drops what a closed input refuses.
Deliver == /\ inQ # <<>>
           /\ LET c == Head(inQ) IN
              \E k \in Answers(c, TRUE) :
                /\ lIn' = Took(lIn, c, k)
                /\ inQ' = OwnerQueue(inQ, k)
                /\ upDropped' = Dropped(upDropped, c, k)
           /\ UNCHANGED <<nextUp, lOut, cUp, aIn, aOut, aUsed, swBelow, bIn, bOut,
                          dAbove, topOut, downVars, ctlVars>>

\* switch.rs:145 Switch::on_command, reached through Chain::on_command:
\* A takes nothing past its boundary, and B nothing while A's leftovers wait.
CommandAnswers(c) ==
  IF phase = "First"
    THEN IF aDone THEN {0} ELSE Answers(c, FALSE)
    ELSE IF swAbove # <<>> /\ LeftoversFirst THEN {0} ELSE Answers(c, TRUE)

Command == /\ cmdQ # <<>>
           /\ LET c == Head(cmdQ) IN
              \E k \in CommandAnswers(c) :
                /\ IF phase = "First"
                     THEN aCmdIn' = Took(aCmdIn, c, k) /\ UNCHANGED bCmdIn
                     ELSE bCmdIn' = Took(bCmdIn, c, k) /\ UNCHANGED aCmdIn
                /\ cmdQ' = OwnerQueue(cmdQ, k)
                /\ downDropped' = Dropped(downDropped, c, k)
           /\ UNCHANGED <<nextDown, aCmdOut, swAbove, bCmdOut, cDown, lCmdIn,
                          lCmdOut, dBelow, bottomOut, upVars, ctlVars>>

\* driver.rs:246 `send`, one turn of its loop: the held item, else the
\* stack's next one, offered to a carrier that may take any part of it.
SendBelow ==
  /\ dBelow # None \/ lCmdOut # <<>>
  /\ LET item == IF dBelow # None THEN dBelow ELSE Head(lCmdOut) IN
     \E k \in Answers(item, TRUE) :
       /\ lCmdOut' = IF dBelow # None THEN lCmdOut ELSE Tail(lCmdOut)
       /\ bottomOut' = Took(bottomOut, item, k)
       /\ dBelow' = CASE k = 0 -> item
                      [] k > 0 /\ k < Len(item) -> IF DriverKeepsRest THEN Rest(item, k) ELSE None
                      [] OTHER -> None
       /\ downDropped' = Dropped(downDropped, item, k)
  /\ UNCHANGED <<nextDown, cmdQ, aCmdIn, aCmdOut, swAbove, bCmdIn, bCmdOut,
                 cDown, lCmdIn, upVars, ctlVars>>

\* The same above; Chain::take_event is Switch::take_event (switch.rs:235).
SendAbove ==
  LET source == IF phase = "First" THEN aOut ELSE bOut IN
  /\ dAbove # None \/ source # <<>>
  /\ LET item == IF dAbove # None THEN dAbove ELSE Head(source)
         left == IF dAbove # None THEN source ELSE Tail(source) IN
     \E k \in Answers(item, TRUE) :
       /\ IF phase = "First" THEN aOut' = left /\ UNCHANGED bOut
                             ELSE bOut' = left /\ UNCHANGED aOut
       /\ topOut' = Took(topOut, item, k)
       /\ dAbove' = CASE k = 0 -> item
                      [] k > 0 /\ k < Len(item) -> IF DriverKeepsRest THEN Rest(item, k) ELSE None
                      [] OTHER -> None
       /\ upDropped' = Dropped(upDropped, item, k)
  /\ UNCHANGED <<nextUp, inQ, lIn, lOut, cUp, aIn, aUsed, swBelow, bIn,
                 downVars, ctlVars>>

\* driver.rs:168 Driver::run starts: advance until nothing moves.
StartRun == /\ ~running
            /\ running' = TRUE /\ pc' = "L" /\ moved' = FALSE
            /\ UNCHANGED <<upVars, downVars, phase, aDone, handovers>>

Owner == /\ ~running
         /\ \/ InjectUp \/ InjectDown \/ Deliver \/ Command
            \/ SendBelow \/ SendAbove \/ StartRun

---------------------------------------------------------------------------
(* One Chain::advance, a statement at a time (chain.rs:133-171).          *)

\* chain.rs:134-136: L::advance moves any prefix of either buffer, or nothing.
StepL ==
  /\ pc = "L" /\ pc' = "S"
  /\ \/ /\ lIn # <<>>
        /\ \E k \in 1..Len(lIn) : lOut' = Append(lOut, Pre(lIn, k)) /\ lIn' = Rest(lIn, k)
        /\ moved' = TRUE
        /\ UNCHANGED <<lCmdIn, lCmdOut>>
     \/ /\ lCmdIn # <<>>
        /\ \E k \in 1..Len(lCmdIn) : lCmdOut' = Append(lCmdOut, Pre(lCmdIn, k)) /\ lCmdIn' = Rest(lCmdIn, k)
        /\ moved' = TRUE
        /\ UNCHANGED <<lIn, lOut>>
     \/ UNCHANGED <<lIn, lOut, lCmdIn, lCmdOut, moved>>
  /\ UNCHANGED <<nextUp, inQ, cUp, aIn, aOut, aUsed, swBelow, bIn, bOut, dAbove,
                 topOut, upDropped, nextDown, cmdQ, aCmdIn, aCmdOut, swAbove,
                 bCmdIn, bCmdOut, cDown, dBelow, bottomOut, downDropped,
                 phase, aDone, handovers, running>>

\* chain.rs:137-139 -> switch.rs:195-197 (A::advance) or :207-209 (B::advance).
AAdvance ==
  /\ \/ /\ ~aDone /\ aIn # <<>>   \* A uses bytes as its own protocol
        /\ \E k \in 1..Len(aIn) : aUsed' = aUsed \cup Range(Pre(aIn, k)) /\ aIn' = Rest(aIn, k)
        /\ moved' = TRUE /\ UNCHANGED <<aOut, aCmdIn, aCmdOut, aDone>>
     \/ /\ ~aDone /\ aIn # <<>>   \* A passes bytes up
        /\ \E k \in 1..Len(aIn) : aOut' = Append(aOut, Pre(aIn, k)) /\ aIn' = Rest(aIn, k)
        /\ moved' = TRUE /\ UNCHANGED <<aUsed, aCmdIn, aCmdOut, aDone>>
     \/ /\ ~aDone /\ aCmdIn # <<>> \* A passes commands down
        /\ \E k \in 1..Len(aCmdIn) : aCmdOut' = Append(aCmdOut, Pre(aCmdIn, k)) /\ aCmdIn' = Rest(aCmdIn, k)
        /\ moved' = TRUE /\ UNCHANGED <<aIn, aOut, aUsed, aDone>>
     \/ /\ ~aDone                  \* A reaches its boundary
        /\ aDone' = TRUE /\ moved' = TRUE
        /\ UNCHANGED <<aIn, aOut, aUsed, aCmdIn, aCmdOut>>
     \/ UNCHANGED <<aIn, aOut, aUsed, aCmdIn, aCmdOut, aDone, moved>>
  /\ UNCHANGED <<bIn, bOut, bCmdIn, bCmdOut>>
BAdvance ==
  /\ \/ /\ bIn # <<>>
        /\ \E k \in 1..Len(bIn) : bOut' = Append(bOut, Pre(bIn, k)) /\ bIn' = Rest(bIn, k)
        /\ moved' = TRUE /\ UNCHANGED <<bCmdIn, bCmdOut>>
     \/ /\ bCmdIn # <<>>
        /\ \E k \in 1..Len(bCmdIn) : bCmdOut' = Append(bCmdOut, Pre(bCmdIn, k)) /\ bCmdIn' = Rest(bCmdIn, k)
        /\ moved' = TRUE /\ UNCHANGED <<bIn, bOut>>
     \/ UNCHANGED <<bIn, bOut, bCmdIn, bCmdOut, moved>>
  /\ UNCHANGED <<aIn, aOut, aUsed, aCmdIn, aCmdOut, aDone>>
StepS ==
  /\ pc = "S"
  /\ IF phase = "First" THEN AAdvance /\ pc' = "H" ELSE BAdvance /\ pc' = "SB"
  /\ UNCHANGED <<nextUp, inQ, lIn, lOut, cUp, swBelow, dAbove, topOut, upDropped,
                 nextDown, cmdQ, swAbove, cDown, lCmdIn, lCmdOut, dBelow,
                 bottomOut, downDropped, phase, handovers, running>>

\* switch.rs:199-205: once A is past its boundary with its output taken,
\* its leftovers join the switch's queues, in any chunking, and B runs.
\* Switch::advance then returns true without feeding.
StepH ==
  /\ pc = "H" /\ pc' = "TU"
  /\ IF aDone /\ aOut = <<>> /\ aCmdOut = <<>>
       THEN \E sb \in Splits(aIn), sa \in Splits(aCmdIn) :
              /\ swBelow' = swBelow \o sb
              /\ swAbove' = IF MoveAbove THEN swAbove \o sa ELSE swAbove
              /\ phase' = IF SwitchOnce THEN "Then" ELSE phase
              \* A is dropped; kept, it would hand the same leftovers over again.
              /\ aIn' = IF SwitchOnce THEN <<>> ELSE aIn
              /\ aCmdIn' = IF SwitchOnce THEN <<>> ELSE aCmdIn
              /\ handovers' = handovers + 1
              /\ moved' = TRUE
       ELSE UNCHANGED <<swBelow, swAbove, phase, aIn, aCmdIn, handovers, moved>>
  /\ UNCHANGED <<nextUp, inQ, lIn, lOut, cUp, aOut, aUsed, bIn, bOut, dAbove,
                 topOut, upDropped, nextDown, cmdQ, aCmdOut, bCmdIn, bCmdOut,
                 cDown, lCmdIn, lCmdOut, dBelow, bottomOut, downDropped, aDone,
                 running>>

\* switch.rs:211-216: the first leftover from below, offered to B.
StepSB ==
  /\ pc = "SB" /\ pc' = "SA"
  /\ IF swBelow # <<>>
       THEN LET c == Head(swBelow) IN
            \E k \in Answers(c, TRUE) :
              /\ bIn' = Took(bIn, c, k)
              /\ swBelow' = FeedQueue(swBelow, k)
              /\ upDropped' = Dropped(upDropped, c, k)
              /\ moved' = (moved \/ k # 0)
       ELSE UNCHANGED <<bIn, swBelow, upDropped, moved>>
  /\ UNCHANGED <<nextUp, inQ, lIn, lOut, cUp, aIn, aOut, aUsed, bOut, dAbove,
                 topOut, downVars, phase, aDone, handovers, running>>

\* switch.rs:217-222: the first leftover from above, offered to B.
StepSA ==
  /\ pc = "SA" /\ pc' = "TU"
  /\ IF swAbove # <<>>
       THEN LET c == Head(swAbove) IN
            \E k \in Answers(c, TRUE) :
              /\ bCmdIn' = Took(bCmdIn, c, k)
              /\ swAbove' = FeedQueue(swAbove, k)
              /\ downDropped' = Dropped(downDropped, c, k)
              /\ moved' = (moved \/ k # 0)
       ELSE UNCHANGED <<bCmdIn, swAbove, downDropped, moved>>
  /\ UNCHANGED <<nextDown, cmdQ, aCmdIn, aCmdOut, bCmdOut, cDown, lCmdIn,
                 lCmdOut, dBelow, bottomOut, upVars, phase, aDone, handovers,
                 running>>

\* chain.rs:150-153: with the slot empty, take L's next event.
StepTU ==
  /\ pc = "TU" /\ pc' = "OU"
  /\ IF cUp = None /\ lOut # <<>>
       THEN cUp' = Head(lOut) /\ lOut' = Tail(lOut) /\ moved' = TRUE
       ELSE UNCHANGED <<cUp, lOut, moved>>
  /\ UNCHANGED <<nextUp, inQ, lIn, aIn, aOut, aUsed, swBelow, bIn, bOut, dAbove,
                 topOut, upDropped, downVars, phase, aDone, handovers, running>>

\* chain.rs:154-159 -> switch.rs:128-143: offer the slot's event to the
\* switch, and keep what it hands back.
EventAnswers(c) ==
  IF phase = "First"
    THEN IF aDone THEN {0} ELSE Answers(c, FALSE)
    ELSE IF swBelow # <<>> /\ LeftoversFirst THEN {0} ELSE Answers(c, TRUE)
StepOU ==
  /\ pc = "OU" /\ pc' = "TD"
  /\ IF cUp # None
       THEN \E k \in EventAnswers(cUp) :
              /\ IF phase = "First"
                   THEN aIn' = Took(aIn, cUp, k) /\ UNCHANGED bIn
                   ELSE bIn' = Took(bIn, cUp, k) /\ UNCHANGED aIn
              /\ cUp' = OfferSlot(cUp, k)
              /\ upDropped' = Dropped(upDropped, cUp, k)
              /\ moved' = (moved \/ OfferMoved(cUp, k))
       ELSE UNCHANGED <<aIn, bIn, cUp, upDropped, moved>>
  /\ UNCHANGED <<nextUp, inQ, lIn, lOut, aOut, aUsed, swBelow, bOut, dAbove,
                 topOut, downVars, phase, aDone, handovers, running>>

\* chain.rs:160-163: with the slot empty, take the switch's next command.
StepTD ==
  LET source == IF phase = "First" THEN aCmdOut ELSE bCmdOut IN
  /\ pc = "TD" /\ pc' = "OD"
  /\ IF cDown = None /\ source # <<>>
       THEN /\ cDown' = Head(source) /\ moved' = TRUE
            /\ IF phase = "First" THEN aCmdOut' = Tail(aCmdOut) /\ UNCHANGED bCmdOut
                                  ELSE bCmdOut' = Tail(bCmdOut) /\ UNCHANGED aCmdOut
       ELSE UNCHANGED <<cDown, aCmdOut, bCmdOut, moved>>
  /\ UNCHANGED <<nextDown, cmdQ, aCmdIn, swAbove, bCmdIn, lCmdIn, lCmdOut,
                 dBelow, bottomOut, downDropped, upVars, phase, aDone,
                 handovers, running>>

\* chain.rs:164-169: offer the slot's command to L.
StepOD ==
  /\ pc = "OD" /\ pc' = "E"
  /\ IF cDown # None
       THEN \E k \in Answers(cDown, TRUE) :
              /\ lCmdIn' = Took(lCmdIn, cDown, k)
              /\ cDown' = OfferSlot(cDown, k)
              /\ downDropped' = Dropped(downDropped, cDown, k)
              /\ moved' = (moved \/ OfferMoved(cDown, k))
       ELSE UNCHANGED <<lCmdIn, cDown, downDropped, moved>>
  /\ UNCHANGED <<nextDown, cmdQ, aCmdIn, aCmdOut, swAbove, bCmdIn, bCmdOut,
                 lCmdOut, dBelow, bottomOut, upVars, phase, aDone, handovers,
                 running>>

\* driver.rs:178-182: advance again while something moved.
StepE ==
  /\ pc = "E"
  /\ IF moved THEN pc' = "L" /\ moved' = FALSE /\ UNCHANGED running
              ELSE pc' = "idle" /\ running' = FALSE /\ UNCHANGED moved
  /\ UNCHANGED <<upVars, downVars, phase, aDone, handovers>>

RunStep == running /\ (StepL \/ StepS \/ StepH \/ StepSB \/ StepSA \/ StepTU
                       \/ StepOU \/ StepTD \/ StepOD \/ StepE)

Next == Owner \/ RunStep

---------------------------------------------------------------------------
(* Properties.                                                           *)

\* Every byte from below, in the order it now sits along the stack, from
\* what the top took down to what the owner still holds.
UpLine == topOut \o dAbove \o Flat(bOut) \o bIn \o Flat(swBelow) \o Flat(aOut)
          \o aIn \o cUp \o Flat(lOut) \o lIn \o Flat(inQ)
\* Every byte from above, from what the bottom took up to the owner.
DownLine == bottomOut \o dBelow \o Flat(lCmdOut) \o lCmdIn \o cDown
            \o Flat(bCmdOut) \o bCmdIn \o Flat(swAbove) \o Flat(aCmdOut)
            \o aCmdIn \o Flat(cmdQ)

\* No byte lost, duplicated or reordered: every byte sent is in exactly
\* one place, either on its line, used by A, or refused by a closed input,
\* and the line keeps the order the bytes were sent in.
UpConserved ==
  /\ Increasing(UpLine)
  /\ Range(UpLine) \cap aUsed = {}
  /\ Range(UpLine) \cap upDropped = {}
  /\ aUsed \cap upDropped = {}
  /\ Range(UpLine) \cup aUsed \cup upDropped = 1..(nextUp - 1)
DownConserved ==
  /\ Increasing(DownLine)
  /\ Range(DownLine) \cap downDropped = {}
  /\ Range(DownLine) \cup downDropped = 1..(nextDown - 1)

\* The handover happens at most once.
HandoverOnce == handovers <= 1

\* A run of the driver ends with nothing moving: the routing loop needs no
\* step limit to stop.
RunEnds == running ~> ~running

---------------------------------------------------------------------------
(* Checked separately: both normal edges hold data until Written arrives. *)
(* Only urgent acceptance and fair runner visits are assumed. No eventual *)
(* acceptance of normal data by a stalled peer is assumed. *)
VARIABLES urgentLower, urgentChain, urgentUpper, urgentDriver, delivered,
          childWaiting, topWaiting, childData, topData
urgentVars == <<urgentLower, urgentChain, urgentUpper, urgentDriver,
                delivered, childWaiting, topWaiting, childData, topData>>
UrgentInit ==
  /\ urgentLower = 1 /\ urgentChain = 0 /\ urgentUpper = 0
  /\ urgentDriver = 0 /\ delivered = 0
  /\ childWaiting = TRUE /\ topWaiting = TRUE
  /\ childData = TRUE /\ topData = TRUE
TakeChainUrgent ==
  /\ urgentLower = 1 /\ urgentChain = 0
  /\ UrgentBypass \/ ~childData
  /\ urgentLower' = 0 /\ urgentChain' = 1
  /\ UNCHANGED <<urgentUpper, urgentDriver, delivered, childWaiting,
                  topWaiting, childData, topData>>
OfferChainUrgent ==
  /\ urgentChain = 1 /\ urgentUpper = 0
  /\ urgentChain' = 0 /\ urgentUpper' = 1 /\ childWaiting' = FALSE
  /\ UNCHANGED <<urgentLower, urgentDriver, delivered, topWaiting,
                  childData, topData>>
TakeDriverUrgent ==
  /\ urgentUpper = 1 /\ urgentDriver = 0
  /\ UrgentBypass \/ ~topData
  /\ urgentUpper' = 0 /\ urgentDriver' = 1
  /\ UNCHANGED <<urgentLower, urgentChain, delivered, childWaiting,
                  topWaiting, childData, topData>>
OfferDriverUrgent ==
  /\ urgentDriver = 1
  /\ urgentDriver' = 0 /\ delivered' = delivered + 1 /\ topWaiting' = FALSE
  /\ UNCHANGED <<urgentLower, urgentChain, urgentUpper, childWaiting,
                  childData, topData>>
OfferChildData ==
  /\ childData /\ ~childWaiting /\ childData' = FALSE
  /\ UNCHANGED <<urgentLower, urgentChain, urgentUpper, urgentDriver,
                  delivered, childWaiting, topWaiting, topData>>
OfferTopData ==
  /\ topData /\ ~topWaiting /\ topData' = FALSE
  /\ UNCHANGED <<urgentLower, urgentChain, urgentUpper, urgentDriver,
                  delivered, childWaiting, topWaiting, childData>>
UrgentNext == TakeChainUrgent \/ OfferChainUrgent \/ TakeDriverUrgent
              \/ OfferDriverUrgent \/ OfferChildData \/ OfferTopData
UrgentSpec == Init /\ UrgentInit /\ [][UrgentNext /\ UNCHANGED vars]_<<vars, urgentVars>>
  /\ WF_urgentVars(TakeChainUrgent) /\ WF_urgentVars(OfferChainUrgent)
  /\ WF_urgentVars(TakeDriverUrgent) /\ WF_urgentVars(OfferDriverUrgent)
  /\ WF_urgentVars(OfferChildData) /\ WF_urgentVars(OfferTopData)
UrgentConserved == urgentLower + urgentChain + urgentUpper + urgentDriver + delivered = 1
UrgentProgress == <> (delivered = 1 /\ ~childData /\ ~topData)
Spec == Init /\ UrgentInit /\ [][Next /\ UNCHANGED urgentVars]_<<vars, urgentVars>> /\ WF_vars(RunStep)
=============================================================================
