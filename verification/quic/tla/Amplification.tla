-------------------------- MODULE Amplification --------------------------
EXTENDS Naturals

(* Connection::poll_transmit reserves whole segments before building them.
   PathData::total_sent moves only when the batch leaves poll_transmit.
   pending represents buf_capacity, including room for padding. The last
   datagram can be shorter than its reservation. A refusal is stuttering.
   Units are scaled bytes; cryptographic handshake behavior is abstract. *)
CONSTANTS MaxReceived, Mtu, WholeSegment, CountPending
VARIABLES received, sent, validated, pending
vars == <<received, sent, validated, pending>>

Init == /\ received = 0 /\ sent = 0 /\ validated = FALSE /\ pending = 0
Receive == /\ pending = 0
           /\ received < MaxReceived
           /\ received' \in (received + 1)..MaxReceived
           /\ UNCHANGED <<sent, validated, pending>>
Build == /\ pending < 3 * Mtu
         /\ \E size \in 1..Mtu:
               /\ validated \/ sent + (IF CountPending THEN pending ELSE 0)
                    + (IF WholeSegment THEN size ELSE 1) <= 3 * received
               /\ pending' = pending + size
         /\ UNCHANGED <<received, sent, validated>>
Transmit == /\ pending > 0
            /\ sent' \in (sent + 1)..(sent + pending)
            /\ sent' <= 3 * MaxReceived + 3 * Mtu
            /\ pending' = 0
            /\ UNCHANGED <<received, validated>>
Validate == /\ ~validated /\ pending = 0 /\ validated' = TRUE
            /\ UNCHANGED <<received, sent, pending>>
Next == Receive \/ Build \/ Transmit \/ Validate
Spec == Init /\ [][Next]_vars

Rfc == INSTANCE RfcAmplification
Refines == Rfc!Spec
WithinCredit == validated \/ sent + pending <= 3 * received
TypeOK == /\ received \in 0..MaxReceived /\ sent \in Nat
          /\ validated \in BOOLEAN /\ pending \in Nat
=============================================================================
