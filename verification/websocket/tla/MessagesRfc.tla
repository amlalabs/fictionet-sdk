----------------------------- MODULE MessagesRfc -----------------------------
EXTENDS Messages

(* Messages refines the receive side of Rfc6455. The decoder never sends
   and owns no TCP connection, so the send variables map to constants and
   only Safety and the receive rules are checked here; sending and the
   close handshake are checked in EchoRfc.

   Mapping:
   - each Receive step is one R receive step (count is rxN);
   - an accepted frame is delivered, a frame refused because a Close came
     first is discarded (the decoder returns End, line 998), and any other
     refused frame fails the connection (the decoder's error ends the
     stream, and the caller then fails the connection);
   - partial is rxMsg and closed is rxClose.
*)
NoFrame == [op |-> "none", fin |-> TRUE, len |-> 0, fate |-> "none"]
Fate == IF last.stopped THEN "discard"
        ELSE IF last.accepted THEN "deliver"
        ELSE "fail"

R == INSTANCE Rfc6455 WITH
       Lens <- Nat,
       rxN <- count,
       rxLast <- IF count = 0 THEN NoFrame
                 ELSE [op |-> last.op, fin |-> last.fin, len |-> last.len,
                       fate |-> Fate],
       rxMsg <- partial,
       rxClose <- closed,
       failing <- failed /\ ~last.stopped,
       txData <- 0,
       txClose <- 0,
       tcp <- "open"

RfcSafety == R!Safety
RfcFragmentOrder == R!FragmentOrder
RfcControlFrames == R!ControlFrames
RfcCloseBody == R!CloseBody
RfcControlInsideMessage == R!ControlInsideMessage
RfcValidControlAccepted == R!ValidControlAccepted
RfcDiscardAfterClose == R!DiscardAfterClose
=============================================================================
