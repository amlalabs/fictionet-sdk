------------------------------ MODULE QpackSync ------------------------------
EXTENDS Naturals, Sequences, FiniteSets

(* The acknowledged-entry encoder in protocols/qpack.rs. Entries have
   absolute indices; table capacity is two entries and the session makes
   at most four insertions. Sections retain their oldest referenced entry.
   Strings, integer coding and QUIC delivery are outside this model. *)
CONSTANTS Acknowledged, ProtectReferences, ProtectReceived, IncrementBound,
          AckOrder, CancelCount
VARIABLES inserted, known, dropped, outstanding, unsafeReference, wrongAck,
          cancelAdvanced
vars == <<inserted, known, dropped, outstanding, unsafeReference, wrongAck,
          cancelAdvanced>>
Streams == {0, 4}
Indices == 0..3
Sections == [stream : Streams, index : Indices]
Init == /\ inserted = 0 /\ known = 0 /\ dropped = 0
        /\ outstanding = <<>> /\ unsafeReference = FALSE
        /\ wrongAck = FALSE /\ cancelAdvanced = FALSE

Insert == /\ inserted < 4
          /\ LET nextDrop == IF inserted - dropped = 2 THEN dropped + 1 ELSE dropped
             IN /\ (~ProtectReceived \/ nextDrop <= known)
                /\ (~ProtectReferences \/
                    \A i \in 1..Len(outstanding) : outstanding[i].index >= nextDrop)
                /\ dropped' = nextDrop
          /\ inserted' = inserted + 1
          /\ UNCHANGED <<known, outstanding, unsafeReference, wrongAck, cancelAdvanced>>

Section(s, index) ==
    /\ Len(outstanding) < 3 /\ index \in dropped..(inserted - 1)
    /\ (~Acknowledged \/ index < known)
    /\ outstanding' = Append(outstanding, [stream |-> s, index |-> index])
    /\ unsafeReference' = (unsafeReference \/ index >= known)
    /\ UNCHANGED <<inserted, known, dropped, wrongAck, cancelAdvanced>>

Increment(n) == /\ known < 5 /\ n \in 1..2
                /\ (~IncrementBound \/ known + n <= inserted)
                /\ known' = known + n
                /\ UNCHANGED <<inserted, dropped, outstanding, unsafeReference,
                                wrongAck, cancelAdvanced>>

Without(q, at) == SubSeq(q, 1, at - 1) \o SubSeq(q, at + 1, Len(q))
Ack(s, at) ==
    /\ at \in 1..Len(outstanding) /\ outstanding[at].stream = s
    /\ LET first == \A j \in 1..(at - 1) : outstanding[j].stream # s
       IN /\ (~AckOrder \/ first)
          /\ wrongAck' = (wrongAck \/ ~first)
    /\ known' = IF outstanding[at].index + 1 > known
                  THEN outstanding[at].index + 1 ELSE known
    /\ outstanding' = Without(outstanding, at)
    /\ UNCHANGED <<inserted, dropped, unsafeReference, cancelAdvanced>>

Cancel(s) == /\ \E i \in 1..Len(outstanding) : outstanding[i].stream = s
             /\ outstanding' = SelectSeq(outstanding, LAMBDA x : x.stream # s)
             /\ known' = IF CancelCount THEN known ELSE inserted
             /\ cancelAdvanced' = (cancelAdvanced \/ (~CancelCount /\ inserted > known))
             /\ UNCHANGED <<inserted, dropped, unsafeReference, wrongAck>>

Next == Insert \/ (\E s \in Streams, i \in Indices : Section(s, i))
        \/ (\E n \in 1..2 : Increment(n))
        \/ (\E s \in Streams, at \in 1..3 : Ack(s, at))
        \/ (\E s \in Streams : Cancel(s))
Spec == Init /\ [][Next]_vars
KnownBound == known <= inserted
NoBlocking == ~unsafeReference
ReferencesRetained == \A i \in 1..Len(outstanding) : outstanding[i].index >= dropped
UnreceivedRetained == dropped <= known
AcknowledgmentsOrdered == ~wrongAck
CancellationPreservesCount == ~cancelAdvanced
=============================================================================
