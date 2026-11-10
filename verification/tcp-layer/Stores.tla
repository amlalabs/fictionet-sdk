------------------------------- MODULE Stores -------------------------------
EXTENDS FiniteSets

(* Finite backing slots abstract the receive and transmit stores and the
   engine's separate control reserve. The wire may hold control packets;
   returning one makes its slot available again without freeing budget.
   The switches remove reserve separation or control-only dispatch. *)
CONSTANTS ReceiveSlots, TransmitSlots, ControlSlots, SeparateControls, ControlFirst
ASSUME /\ IsFiniteSet(ReceiveSlots) /\ IsFiniteSet(TransmitSlots)
       /\ IsFiniteSet(ControlSlots) /\ ControlSlots # {}
       /\ ReceiveSlots \intersect TransmitSlots = {}
       /\ ReceiveSlots \intersect ControlSlots = {}
       /\ TransmitSlots \intersect ControlSlots = {}

VARIABLES received, queued, wire, pending
vars == <<received, queued, wire, pending>>

Init == /\ received = {} /\ queued = {} /\ wire = {} /\ pending = FALSE

Receive == \E s \in ReceiveSlots \ received:
    /\ received' = received \union {s}
    /\ pending' = TRUE
    /\ UNCHANGED <<queued, wire>>

Write == \E s \in (IF SeparateControls THEN TransmitSlots
                  ELSE TransmitSlots \union ControlSlots) \ (queued \union wire):
    /\ queued' = queued \union {s}
    /\ UNCHANGED <<received, wire, pending>>

Read == \E s \in received:
    /\ received' = received \ {s}
    /\ UNCHANGED <<queued, wire, pending>>

DataAcknowledged == \E s \in queued:
    /\ queued' = queued \ {s}
    /\ UNCHANGED <<received, wire, pending>>

SendAck == /\ pending
           /\ (ControlFirst \/ queued = {})
           /\ \E s \in ControlSlots \ (queued \union wire):
                /\ wire' = wire \union {s}
                /\ pending' = FALSE
                /\ UNCHANGED <<received, queued>>

ReturnControl == \E s \in wire:
    /\ wire' = wire \ {s}
    /\ UNCHANGED <<received, queued, pending>>

Next == Receive \/ Write \/ Read \/ DataAcknowledged \/ SendAck \/ ReturnControl
Spec == Init /\ [][Next]_vars

TypeOK == /\ received \subseteq ReceiveSlots
          /\ queued \subseteq TransmitSlots \union ControlSlots
          /\ wire \subseteq ControlSlots
          /\ pending \in BOOLEAN
          /\ queued \intersect wire = {}

DataCannotSpendControls == queued \intersect ControlSlots = {}
AckDespiteFullData ==
    (pending /\ received = ReceiveSlots /\ TransmitSlots \subseteq queued
             /\ wire = {}) => ENABLED SendAck
=============================================================================
