-------------------------------- MODULE Echo --------------------------------
EXTENDS Naturals
(* The test handlers, not a production WebSocket session API:
   tests/support/response.rs EchoSocket::call lines 129-163 installs a
   raw-stream UpgradeHandler. tests/it/features.rs lines 249-275 defines
   the local echo used by websocket_continuation_exchanges_messages_through_server
   at line 243, installed as an UpgradeHandler at lines 284-286.
   Both handlers reply to Ping with Pong, ignore Pong, and return after
   writing the Close reply. Each message is handled serially; write_all
   finishes before the next message is read. The close branch replies with
   the received payload and returns after that write. Messages::decode in
   protocols/websocket.rs lines 997-998 independently stops after close.
   StopAfterClose disables both stop rules, allowing adversarial later
   messages to expose duplicate close replies and data after a close.
   ReplyClose = FALSE models the old support handler's non-text early return.
   Ping followed by its Pong write and an unsolicited Pong leave this
   close-state projection unchanged; they are stuttering steps. Fragment
   state is checked in Messages.tla; payload preservation and ping response
   are checked by the integration regressions, not by this model. The
   feature regression sends text, Ping and unsolicited Pong with the
   upgrade, then requires an exact unmasked code-1000 close reply and EOF.
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
