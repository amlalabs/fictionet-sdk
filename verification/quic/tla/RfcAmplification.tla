------------------------ MODULE RfcAmplification ------------------------
EXTENDS Naturals

(* Address validation during connection establishment in RFC 9000 section
   8.1. UDP payload bytes include every coalesced packet and its padding.
   Successful validation removes the restriction. No cryptography, loss
   recovery, or migration is represented here. *)
VARIABLES received, sent, validated
vars == <<received, sent, validated>>

Init == /\ received = 0 /\ sent = 0 /\ validated = FALSE
Receive == /\ received' > received /\ UNCHANGED <<sent, validated>>
Send == /\ sent' > sent
        /\ validated \/ sent' <= 3 * received
        /\ UNCHANGED <<received, validated>>
Validate == /\ ~validated /\ validated' = TRUE
            /\ UNCHANGED <<received, sent>>
Spec == Init /\ [][Receive \/ Send \/ Validate]_vars
WithinCredit == validated \/ sent <= 3 * received
=============================================================================
