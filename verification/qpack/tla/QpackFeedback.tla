----------------------------- MODULE QpackFeedback -----------------------------
EXTENDS Naturals, Sequences

(* Decoding a dynamic section updates Table.reported immediately. The
   caller therefore owns its acknowledgment until it reaches the peer.
   A subsequent increment is relative to that updated reported count.
   Cancelling a stream must not discard an acknowledgment already made. *)
CONSTANTS PreserveAck, Ordered, QueueBound
VARIABLES inserted, reported, known, pending
vars == <<inserted, reported, known, pending>>
Apply(count, instruction) ==
    IF instruction.ack THEN IF instruction.value > count THEN instruction.value ELSE count
                       ELSE count + instruction.value
RECURSIVE Replay(_, _)
Replay(count, queue) == IF Len(queue) = 0 THEN count
                       ELSE Replay(Apply(count, Head(queue)), Tail(queue))
Init == /\ inserted = 0 /\ reported = 0 /\ known = 0 /\ pending = <<>>
Room == ~QueueBound \/ Len(pending) < 2
Insert == /\ inserted < 3 /\ inserted' = inserted + 1
          /\ UNCHANGED <<reported, known, pending>>
Decode(required) ==
    /\ required \in 1..inserted /\ Room /\ Len(pending) < 3
    /\ reported' = IF required > reported THEN required ELSE reported
    /\ pending' = Append(pending, [ack |-> TRUE, value |-> required])
    /\ UNCHANGED <<inserted, known>>
Increment == /\ inserted > reported /\ Room /\ Len(pending) < 3
             /\ pending' = Append(pending, [ack |-> FALSE, value |-> inserted - reported])
             /\ reported' = inserted
             /\ UNCHANGED <<inserted, known>>
Send == /\ Len(pending) > 0
        /\ LET at == IF Ordered THEN 1 ELSE Len(pending)
           IN /\ known' = Apply(known, pending[at])
              /\ pending' = SubSeq(pending, 1, at - 1) \o SubSeq(pending, at + 1, Len(pending))
        /\ UNCHANGED <<inserted, reported>>
Cancel == /\ ~PreserveAck /\ \E i \in 1..Len(pending) : pending[i].ack
          /\ pending' = SelectSeq(pending, LAMBDA x : ~x.ack)
          /\ UNCHANGED <<inserted, reported, known>>
Next == Insert \/ (\E n \in 1..3 : Decode(n)) \/ Increment \/ Send \/ Cancel
Spec == Init /\ [][Next]_vars
FeedbackAccounts == Replay(known, pending) = reported
KnownBound == known <= inserted
PendingBound == Len(pending) <= 2
=============================================================================
