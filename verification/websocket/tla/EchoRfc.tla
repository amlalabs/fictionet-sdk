------------------------------- MODULE EchoRfc -------------------------------
EXTENDS Echo

(* Echo, the server handlers after the HTTP switch, refines Rfc6455 in
   the server role: safety, the send rules and both liveness rules.

   Mapping:
   - ReadText delivers a final data frame and ReadClose delivers a Close
     (read records which; the lengths are any valid ones). Messages are
     whole, so no fragment is in progress (rxMsg is FALSE).
   - WriteText sends a data frame (echoed counts them) and WriteClose a
     Close (sent counts them).
   - Return closes the TCP connection from the server's side: the
     handler's future completes and the server drops the connection.
   - The handlers never fail the connection in this model, and the peer
     never drops it (writes are assumed to succeed).

   SpecLazyReply and SpecLazyReturn drop one fairness condition each:
   a handler that may wait forever before replying to a Close, and one
   that may wait forever after replying instead of closing the
   connection (waiting for the client to close it first).
*)
R == INSTANCE Rfc6455 WITH
       Lens <- Nat,
       rxN <- count,
       rxLast <- CASE read = "none" ->
                        [op |-> "none", fin |-> TRUE, len |-> 0, fate |-> "none"]
                   [] read = "text" ->
                        [op |-> "data", fin |-> TRUE, len |-> 1, fate |-> "deliver"]
                   [] read = "close" ->
                        [op |-> "close", fin |-> TRUE, len |-> 0, fate |-> "deliver"],
       rxMsg <- FALSE,
       rxClose <- received,
       failing <- FALSE,
       txData <- echoed,
       txClose <- sent,
       tcp <- IF phase = "ended" THEN "self" ELSE "open"

SpecLazyReply == Init /\ [][Next]_vars /\ WF_vars(WriteText) /\ WF_vars(Return)
SpecLazyReturn == Init /\ [][Next]_vars /\ WF_vars(WriteText) /\ WF_vars(WriteClose)

RfcSafety == R!Safety
RfcDiscardAfterClose == R!DiscardAfterClose
RfcNoDataAfterClose == R!NoDataAfterClose
RfcOneClose == R!OneClose
RfcTcpClosedAfterHandshake == R!TcpClosedAfterHandshake
RfcCloseAnswered == R!CloseAnswered
RfcServerClosesTcp == R!ServerClosesTcp
=============================================================================
