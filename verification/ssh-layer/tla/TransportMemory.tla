------------------------- MODULE TransportMemory -------------------------
(***************************************************************************)
(* Sources: src/stdlib/services/ssh/transport.rs, StandardTransport::push   *)
(* and poll; src/stdlib/protocols/ssh/transport.rs, Transport::most_held,    *)
(* scratch, Decode::held, Direction::read and unpad.                       *)
(* One unit is one scaled byte of allocation capacity. State is charged   *)
(* once before decoding. A copy is charged for min(buffered, packet cap)  *)
(* before allocation. Opening and unpadding reuse that vector. Handling   *)
(* raises its charge to capacity plus scratch before allocating scratch. *)
(* A refusal leaves the payload and its charge held back. Scratch is     *)
(* freed before returning, state may grow, and the payload leaves.        *)
(* In the code an application payload leaves with a split charge rather  *)
(* than being freed. Here leaving the transport ends its accounting.     *)
(* PacketMax stands for MAX_PACKET + 16. Actual cipher copies can be     *)
(* smaller than the wire total; total here is the copied capacity.       *)
(* Input buffer storage, output, version observations, crypto internals,  *)
(* state replacement during rekey and allocation rounding are omitted.   *)
(* MostHeld is assumed to bound all state, including preexisting local   *)
(* identification and proposal. Their construction precedes this model. *)
(* Charge returns are separate steps so Paid sees each allocation peak   *)
(* before Release reduces the reservation. No liveness is asserted.     *)
(***************************************************************************)
EXTENDS Integers, Resources
CONSTANTS Limit, MostHeld, PacketMax, ScratchMax, ChargeCopyFirst, ChargeScratch
VARIABLE x
Max(a, b) == IF a > b THEN a ELSE b
Min(a, b) == IF a < b THEN a ELSE b
Fresh == [x EXCEPT !.state = Begin(@), !.packet = Begin(@)]
Init == x = [state |-> Store(0), packet |-> Store(0), stateBytes |-> 0,
             payload |-> 0, copy |-> 0, scratch |-> 0, phase |-> "state"]

ChargeState ==
    /\ x.phase = "state" /\ MostHeld <= Limit
    /\ x' = [Fresh EXCEPT !.state = Reserve(Begin(x.state), MostHeld), !.phase = "ready"]

Decode(total, buffered, scratch) ==
    /\ x.phase = "ready" /\ total <= buffered
    /\ LET copy == Min(buffered, PacketMax)
       IN IF ChargeCopyFirst /\ x.state.reserved + copy > Limit
          THEN x' = Fresh
          ELSE x' = [Fresh EXCEPT !.payload = total, !.copy = copy, !.scratch = scratch,
              !.packet = Grow(IF ChargeCopyFirst THEN Reserve(Begin(x.packet), copy)
                              ELSE Begin(x.packet), total),
              !.phase = IF ChargeCopyFirst THEN "scratch" ELSE "copy"]

LateCopyCharge ==
    /\ x.phase = "copy"
    /\ IF x.state.reserved + x.copy <= Limit
       THEN x' = [Fresh EXCEPT !.packet = Reserve(Begin(x.packet), x.copy), !.phase = "scratch"]
       ELSE x' = [Fresh EXCEPT !.packet = Shrink(Begin(x.packet), x.payload),
                              !.payload = 0, !.phase = "release"]

ChargeHandling ==
    /\ x.phase = "scratch"
    /\ LET need == x.payload + IF ChargeScratch THEN x.scratch ELSE 0
       IN IF x.state.reserved + Max(x.packet.reserved, need) > Limit
          THEN x' = Fresh
          ELSE x' = [Fresh EXCEPT
              !.packet = Release(ReserveTo(Begin(x.packet), need),
                                 Max(x.packet.reserved, need) - need),
                                 !.phase = "handle"]

Handle(more) ==
    /\ x.phase = "handle" /\ x.stateBytes + more <= MostHeld
    /\ x' = [Fresh EXCEPT
        !.packet = Shrink(Shrink(Grow(Begin(x.packet), x.scratch), x.scratch), x.payload),
        !.state = Grow(Begin(x.state), more), !.stateBytes = @ + more,
        !.payload = 0, !.phase = "release"]

ReturnCharge ==
    /\ x.phase = "release"
    /\ x' = [Fresh EXCEPT !.packet = Release(Begin(x.packet), x.packet.reserved),
        !.copy = 0, !.scratch = 0, !.phase = "ready"]

Next == ChargeState
        \/ (\E total \in 1..PacketMax, buffered \in 1..(PacketMax + 1),
               scratch \in 0..ScratchMax : Decode(total, buffered, scratch))
        \/ LateCopyCharge \/ ChargeHandling
        \/ (\E more \in 0..MostHeld : Handle(more)) \/ ReturnCharge \/ x' = Fresh
Spec == Init /\ [][Next]_x
StatePaid == Paid(x.state)
PacketPaid == Paid(x.packet)
BudgetWithinLimit == x.state.reserved + x.packet.reserved <= Limit
StateWithinLimit == WithinLimit(x.state, MostHeld)
StateTracks == Tracks(x.state, x.stateBytes)
PacketTracks == Tracks(x.packet, x.payload)
Shape == x.stateBytes \in 0..MostHeld /\ x.payload \in 0..PacketMax
=============================================================================
