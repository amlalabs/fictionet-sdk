------------------------- MODULE LayerFlight -------------------------
EXTENDS Naturals, Sequences

(* QuicLayer's take_command and on_event(Sent): preparation, ownership
   handoff and completion are separate. Receive refusal is independent
   of completion. The carrier may drop a datagram at retirement.
   This model excludes packet contents, timers and engine allocations. *)
CONSTANTS Limit, Gate, Urgent
VARIABLES made, handed, retired, completed, prepared, receiveBlocked
vars == <<made, handed, retired, completed, prepared, receiveBlocked>>

Init == /\ made = 0 /\ handed = 0 /\ retired = 0 /\ completed = 0
        /\ prepared = FALSE /\ receiveBlocked \in BOOLEAN

Prepare == /\ ~prepared /\ made < Limit
           /\ made' = made + 1 /\ prepared' = TRUE
           /\ UNCHANGED <<handed, retired, completed, receiveBlocked>>

Handoff == /\ prepared /\ (~Gate \/ handed = completed)
           /\ handed' = handed + 1 /\ prepared' = FALSE
           /\ UNCHANGED <<made, retired, completed, receiveBlocked>>

Retire == /\ retired < handed /\ retired' = retired + 1
          /\ UNCHANGED <<made, handed, completed, prepared, receiveBlocked>>

Complete == /\ completed < retired /\ (Urgent \/ ~receiveBlocked)
            /\ completed' = completed + 1
            /\ UNCHANGED <<made, handed, retired, prepared, receiveBlocked>>

Next == Prepare \/ Handoff \/ Retire \/ Complete
Spec == Init /\ [][Next]_vars /\ WF_vars(Retire) /\ WF_vars(Complete)

OneOutstanding == handed - completed <= 1
Ownership == /\ completed <= retired /\ retired <= handed
             /\ handed <= made /\ made = handed + (IF prepared THEN 1 ELSE 0)
Completes == (handed > completed) ~> (handed = completed)
=====================================================================
