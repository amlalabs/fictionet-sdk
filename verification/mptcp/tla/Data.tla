------------------------------- MODULE Data -------------------------------
(***************************************************************************)
(* The receive side of DataLevel in src/stdlib/protocols/mptcp.rs, with    *)
(* one-byte mappings over three subflow slots and three data offsets.      *)
(*                                                                         *)
(*   Map       Receiver::received: a DSS mapping, or the MP_CAPABLE with   *)
(*             data; PreserveMapping is its conflict check against an      *)
(*             existing ReceivedMapping                                    *)
(*   Arrive    Receiver::arrived completing a mapping; CheckChecksum is    *)
(*             its dss_checksum comparison                                 *)
(*   Deliver   DataStream::deliver; WaitForGap is its in-order search,     *)
(*             RespectFin stands for the boundary DataStream::admit and    *)
(*             DataRange::within enforce before data is queued             *)
(*   DataFin   DataStream::admit of a mapping with DATA_FIN fixing `fin`   *)
(*   FallBack  Receiver::fallback; SafeFallback is its check that nothing  *)
(*             is queued and no FIN is fixed, else DataError::Mapping      *)
(*                                                                         *)
(* Where the model disables a step, the code fails the connection.         *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences
CONSTANTS Limit, PreserveMapping, WaitForGap, RespectFin, CheckChecksum,
          SafeFallback
VARIABLES mapping, received, ready, output, fin, fallback, corrupt, changed
vars == <<mapping, received, ready, output, fin, fallback, corrupt, changed>>
Slots == 0..(Limit - 1)
Init == /\ mapping = [s \in Slots |-> Limit]
        /\ received = {} /\ ready = {} /\ output = <<>> /\ fin = Limit
        /\ fallback = FALSE /\ corrupt = FALSE /\ changed = FALSE
Map(s, d) ==
    /\ ~fallback /\ s \notin received
    /\ mapping[s] = Limit \/ mapping[s] = d \/ ~PreserveMapping
    /\ mapping' = [mapping EXCEPT ![s] = d]
    /\ changed' = (changed \/ (mapping[s] # Limit /\ mapping[s] # d))
    /\ UNCHANGED <<received, ready, output, fin, fallback, corrupt>>
Arrive(s, valid) ==
    /\ ~fallback /\ s \notin received /\ mapping[s] # Limit
    /\ valid \/ ~CheckChecksum
    /\ received' = received \cup {s}
    /\ ready' = ready \cup {mapping[s]}
    /\ corrupt' = (corrupt \/ ~valid)
    /\ UNCHANGED <<mapping, output, fin, fallback, changed>>
Deliver(d) ==
    /\ d \in ready /\ ~fallback
    /\ d = Len(output) \/ (~WaitForGap /\ d >= Len(output))
    /\ d < fin \/ ~RespectFin
    /\ output' = Append(output, d) /\ ready' = ready \ {d}
    /\ UNCHANGED <<mapping, received, fin, fallback, corrupt, changed>>
DataFin(d) ==
    /\ ~fallback /\ fin = Limit /\ d >= Len(output)
    /\ fin' = d
    /\ UNCHANGED <<mapping, received, ready, output, fallback, corrupt, changed>>
FallBack ==
    /\ ~fallback /\ ((ready = {} /\ fin = Limit) \/ ~SafeFallback)
    /\ fallback' = TRUE
    /\ UNCHANGED <<mapping, received, ready, output, fin, corrupt, changed>>
Next == (\E s, d \in Slots : Map(s, d))
        \/ (\E s \in Slots, valid \in BOOLEAN : Arrive(s, valid))
        \/ (\E d \in Slots : Deliver(d) \/ DataFin(d)) \/ FallBack
Spec == Init /\ [][Next]_vars
MappingImmutable == ~changed
Ordered == \A i \in 1..Len(output) : output[i] = i - 1
FinBoundary == \A i \in 1..Len(output) : output[i] < fin
ChecksumSound == ~corrupt
FallbackPreservesData == fallback => ready = {} /\ fin = Limit
=============================================================================
