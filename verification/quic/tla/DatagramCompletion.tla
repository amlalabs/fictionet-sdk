----------------------- MODULE DatagramCompletion -----------------------
EXTENDS Naturals, Sequences

(* UdpLayer's ordered down queue, socket.completed counter, and urgent
   completion extraction. run_datagrams uses the same handoff/delivery
   order with one pending completion. A local drop is a retired attempt,
   not evidence of delivery. Receive credit is independent of both.
   Application closure and physical network delivery are outside this model. *)
CONSTANTS Limit, CompleteAtAdmission, ClearAfterDelivery, Urgent
VARIABLES admitted, retired, notified, queued, pending, tracked, receiveBlocked
vars == <<admitted, retired, notified, queued, pending, tracked, receiveBlocked>>

Init == /\ admitted = 0 /\ retired = <<>> /\ notified = <<>>
        /\ queued = <<>> /\ pending = <<>> /\ tracked = {}
        /\ receiveBlocked \in BOOLEAN

Admit == /\ admitted < Limit
         /\ \E wants \in BOOLEAN:
             /\ queued' = Append(queued, admitted + 1)
             /\ tracked' = IF wants THEN tracked \cup {admitted + 1} ELSE tracked
             /\ pending' = IF wants /\ CompleteAtAdmission
                            THEN Append(pending, admitted + 1) ELSE pending
         /\ admitted' = admitted + 1
         /\ UNCHANGED <<retired, notified, receiveBlocked>>

Handoff == /\ queued # <<>>
           /\ retired' = Append(retired, Head(queued))
           /\ pending' = IF Head(queued) \in tracked /\ ~CompleteAtAdmission
                          THEN Append(pending, Head(queued)) ELSE pending
           /\ queued' = Tail(queued)
           /\ UNCHANGED <<admitted, notified, tracked, receiveBlocked>>

Complete == /\ pending # <<>> /\ (Urgent \/ ~receiveBlocked)
            /\ notified' = notified \o pending
            /\ pending' = IF ClearAfterDelivery THEN <<>> ELSE pending
            /\ UNCHANGED <<admitted, retired, queued, tracked, receiveBlocked>>

Next == Admit \/ Handoff \/ Complete
Spec == Init /\ [][Next]_vars /\ WF_vars(Handoff) /\ WF_vars(Complete)

Tracked(s) == SelectSeq(s, LAMBDA id: id \in tracked)
AfterHandoff == \A i \in 1..Len(notified): notified[i] \in {retired[j]: j \in 1..Len(retired)}
OnceInOrder == /\ Len(notified) <= Len(Tracked(retired))
               /\ notified = SubSeq(Tracked(retired), 1, Len(notified))
Bounded == Len(queued) + Len(pending) <= Limit
CompletionsProgress == (pending # <<>>) ~> (pending = <<>>)
=============================================================================
