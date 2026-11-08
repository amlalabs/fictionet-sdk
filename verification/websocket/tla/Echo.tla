-------------------------------- MODULE Echo --------------------------------
EXTENDS Naturals
(* The test server, not a production WebSocket session API:
   tests/support/response.rs EchoSocket::call lines 129-161 installs the
   raw-stream UpgradeHandler. Each message is handled serially; write_all
   finishes before the next message is read. The close branch replies with
   the received payload and returns after that write. Messages::decode in
   protocols/websocket.rs lines 959-960 independently stops after close.
   StopAfterClose disables both stop rules, allowing adversarial later
   messages to expose duplicate close replies and data after a close.
   ReplyClose = FALSE models the old handler's non-text early return.
   Writes are assumed to succeed and weakly fair; transport failures and
   peer disappearance can prevent a handshake, and are outside liveness.
*)
CONSTANTS Steps, ReplyClose, StopAfterClose
VARIABLES phase, received, sent, count, dataAfterClose
vars == <<phase, received, sent, count, dataAfterClose>>
Init == /\ phase = "reading" /\ received = FALSE /\ sent = 0
        /\ count = 0 /\ dataAfterClose = FALSE
ReadText == /\ phase = "reading" /\ count < Steps
            /\ ~(StopAfterClose /\ received)
            /\ phase' = "text" /\ count' = count + 1
            /\ UNCHANGED <<received, sent, dataAfterClose>>
ReadClose == /\ phase = "reading" /\ count < Steps
             /\ ~(StopAfterClose /\ received)
             /\ received' = TRUE /\ count' = count + 1
             /\ phase' = IF ReplyClose THEN "close" ELSE "ended"
             /\ UNCHANGED <<sent, dataAfterClose>>
WriteText == /\ phase = "text" /\ phase' = "reading"
             /\ dataAfterClose' = (dataAfterClose \/ sent > 0)
             /\ UNCHANGED <<received, sent, count>>
WriteClose == /\ phase = "close" /\ sent' = sent + 1
              /\ phase' = IF StopAfterClose THEN "ended" ELSE "reading"
              /\ UNCHANGED <<received, count, dataAfterClose>>
Next == ReadText \/ ReadClose \/ WriteText \/ WriteClose
Spec == Init /\ [][Next]_vars /\ WF_vars(WriteText) /\ WF_vars(WriteClose)
OneCloseEachWay == sent <= 1
NoDataAfterClose == ~dataAfterClose
CloseIsAnswered == received ~> (sent = 1)
=============================================================================
