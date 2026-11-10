---------------------------- MODULE Rfc6455Check ----------------------------
EXTENDS Rfc6455

(* Checks that Rfc6455's named rules follow from its own Safety and Spec,
   so a rule cannot fail under a refinement mapping for a reason the RFC
   spec itself allows. The bounds keep the state space finite: at most
   MaxRx frames received and MaxTx data frames sent.
*)
CONSTANTS MaxRx, MaxTx
Bound == rxN <= MaxRx /\ txData <= MaxTx
=============================================================================
