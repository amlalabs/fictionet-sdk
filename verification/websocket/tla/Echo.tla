-------------------------------- MODULE Echo --------------------------------
EXTENDS Naturals
(* The test handlers, not a production WebSocket session API:
   tests/support/response.rs EchoSocket::call, lines 111-163, installs a
   raw-stream UpgradeHandler (lines 129-161). tests/it/features.rs lines 249-275 defines
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
   EchoSocket still returns without a reply on a Binary message or a decode
   error (response.rs line 144); the model has no Binary token.
   Line numbers checked against e2858ccc4 on 2026-11-09.
   Ping followed by its Pong write and an unsolicited Pong leave this
   close-state projection unchanged; they are stuttering steps. Fragment
   state is checked in Messages.tla; payload preservation and ping response
   are checked by the integration regressions, not by this model. The
   feature regression sends text, Ping and unsolicited Pong with the
   upgrade, then requires an exact unmasked code-1000 close reply and EOF.
   Writes are assumed to succeed and weakly fair; transport failures and
   peer disappearance can prevent a handshake, and are outside liveness.
   Returning is its own step (phase "returning" to "ended"): the handler
   returns after the write, and the connection is dropped, closing TCP
   from the server's side, when it does. read (the last message read)
   and echoed (texts written) are history variables for the refinement
   mapping in EchoRfc.tla; they never constrain a step.
*)
CONSTANTS Steps, ReplyClose, StopAfterClose
VARIABLES phase, received, sent, count, dataAfterClose, read, echoed
vars == <<phase, received, sent, count, dataAfterClose, read, echoed>>
Init == /\ phase = "reading" /\ received = FALSE /\ sent = 0
        /\ count = 0 /\ dataAfterClose = FALSE
        /\ read = "none" /\ echoed = 0
ReadText == /\ phase = "reading" /\ count < Steps
            /\ ~(StopAfterClose /\ received)
            /\ phase' = "text" /\ count' = count + 1 /\ read' = "text"
            /\ UNCHANGED <<received, sent, dataAfterClose, echoed>>
ReadClose == /\ phase = "reading" /\ count < Steps
             /\ ~(StopAfterClose /\ received)
             /\ received' = TRUE /\ count' = count + 1 /\ read' = "close"
             /\ phase' = IF ReplyClose THEN "close" ELSE "returning"
             /\ UNCHANGED <<sent, dataAfterClose, echoed>>
WriteText == /\ phase = "text" /\ phase' = "reading"
             /\ dataAfterClose' = (dataAfterClose \/ sent > 0)
             /\ echoed' = echoed + 1
             /\ UNCHANGED <<received, sent, count, read>>
WriteClose == /\ phase = "close" /\ sent' = sent + 1
              /\ phase' = IF StopAfterClose THEN "returning" ELSE "reading"
              /\ UNCHANGED <<received, count, dataAfterClose, read, echoed>>
Return == /\ phase = "returning" /\ phase' = "ended"
          /\ UNCHANGED <<received, sent, count, dataAfterClose, read, echoed>>
Next == ReadText \/ ReadClose \/ WriteText \/ WriteClose \/ Return
Spec == Init /\ [][Next]_vars /\ WF_vars(WriteText) /\ WF_vars(WriteClose)
        /\ WF_vars(Return)
OneCloseEachWay == sent <= 1
NoDataAfterClose == ~dataAfterClose
CloseIsAnswered == received ~> (sent = 1)
=============================================================================
