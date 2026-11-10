------------------------------ MODULE Rfc6455 ------------------------------
EXTENDS Naturals

(* One WebSocket endpoint after the opening handshake, written from the
   text of RFC 6455, not from the code. Section numbers are the RFC's.

   The endpoint receives frames from its peer and sends data and Close
   frames. Frames are abstract: an opcode class, the FIN bit and the
   payload length. Text and binary are one class, "data" (5.6); UTF-8,
   masking, reserved bits, reserved opcodes, length encodings and close
   codes are wire details checked elsewhere.

   rxN      frames received so far; each receive step adds one
   rxLast   the last frame received and its fate: "deliver" (passed on),
            "discard" (dropped after a received Close, 1.4) or "fail"
            (the endpoint fails the connection on it, 7.1.7)
   rxMsg    a fragmented message is in progress (5.4)
   rxClose  a Close frame has been received
   failing  the endpoint has failed the connection (7.1.7)
   txData   data frames sent so far
   txClose  Close frames sent so far
   tcp      "open", "self" (this endpoint closed the TCP connection) or
            "peer" (the peer or the network closed it)

   Receive rules:
   - 5.4: an unfragmented message is one frame with FIN set and a
     nonzero opcode; a fragmented one starts with a nonzero opcode and
     FIN clear and continues with opcode 0 until FIN is set. So a
     continuation is valid only inside a message, and a new data frame
     only outside one.
   - 5.5: control frames carry at most 125 bytes and are never
     fragmented.
   - 5.5.1: a Close body, if present, starts with a 2-byte status code,
     so a 1-byte body is invalid.
   - 5.4: control frames may arrive in the middle of a fragmented
     message, and an endpoint MUST be able to handle them; the message
     goes on after them. A valid control frame is therefore never a
     reason to fail.
   - 10.4: an endpoint may refuse a data frame or message too large for
     it, so any data frame may be failed.
   - 1.4: after receiving a Close, a peer discards any further data.
   - 7.1.7: after failing the connection, an endpoint MUST NOT process
     more data from the peer.

   Send and TCP rules:
   - 5.5.1: no data frames after sending a Close.
   - 5.5.1: an endpoint that receives a Close and has not sent one MUST
     send a Close in response. A Close is sent once (5.5.1 "did not
     previously send"; 7.1.5 NOTE: endpoints that have sent and received
     a Close "will not send further Close frames").
   - 5.5.1, 7.1.2: after both sending and receiving a Close, the endpoint
     MUST close the TCP connection; the server MUST do so immediately,
     and 7.1.1 says the server SHOULD close it first.
   - 7.1.7: failing the connection means closing the TCP connection,
     with a Close frame first if it can (SHOULD).
   - 7.3: an endpoint starts a closure with the closing handshake. This
     spec reads that as: an endpoint closes the TCP connection only after
     the handshake or when it fails the connection. The peer may drop
     the connection at any time (7.2.1).

   State is the connection state of 7.1.3 and 7.1.4. The spec is one
   endpoint in the server role: the TCP close obligation of 5.5.1 is the
   server's.
*)

CONSTANT Lens   \* payload lengths a frame may carry

VARIABLES rxN, rxLast, rxMsg, rxClose, failing, txData, txClose, tcp
vars == <<rxN, rxLast, rxMsg, rxClose, failing, txData, txClose, tcp>>

Ops == {"data", "continuation", "ping", "pong", "close"}
Fates == {"deliver", "discard", "fail"}
Control(op) == op \in {"ping", "pong", "close"}
NoFrame == [op |-> "none", fin |-> TRUE, len |-> 0, fate |-> "none"]
Received == [op : Ops, fin : BOOLEAN, len : Lens, fate : Fates]

InOrder(op, inMsg) ==
    IF op = "continuation" THEN inMsg
    ELSE IF op = "data" THEN ~inMsg
    ELSE TRUE
WellFormed(f) ==
    /\ Control(f.op) => f.fin /\ f.len <= 125
    /\ f.op = "close" => f.len # 1
Valid(f, inMsg) == InOrder(f.op, inMsg) /\ WellFormed(f)

State == IF tcp # "open" THEN "CLOSED"
         ELSE IF rxClose \/ txClose > 0 THEN "CLOSING"
         ELSE "OPEN"

Init == /\ rxN = 0 /\ rxLast = NoFrame /\ rxMsg = FALSE
        /\ rxClose = FALSE /\ failing = FALSE
        /\ txData = 0 /\ txClose = 0 /\ tcp = "open"

Receive ==
    /\ tcp = "open" /\ ~failing
    /\ rxN' = rxN + 1
    /\ rxLast' \in Received
    /\ LET f == rxLast' IN
       \/ /\ f.fate = "discard" /\ rxClose
          /\ UNCHANGED <<rxMsg, rxClose, failing>>
       \/ /\ f.fate = "deliver" /\ ~rxClose /\ Valid(f, rxMsg)
          /\ rxMsg' = IF f.op = "close" THEN FALSE
                      ELSE IF Control(f.op) THEN rxMsg
                      ELSE ~f.fin
          /\ rxClose' = (f.op = "close")
          /\ UNCHANGED failing
       \/ /\ f.fate = "fail" /\ ~rxClose
          /\ (~Valid(f, rxMsg) \/ ~Control(f.op))
          /\ failing' = TRUE
          /\ UNCHANGED <<rxMsg, rxClose>>
    /\ UNCHANGED <<txData, txClose, tcp>>

SendData ==
    /\ tcp = "open" /\ ~failing /\ txClose = 0
    /\ txData' = txData + 1
    /\ UNCHANGED <<rxN, rxLast, rxMsg, rxClose, failing, txClose, tcp>>

SendClose ==
    /\ tcp = "open" /\ txClose = 0
    /\ txClose' = 1
    /\ UNCHANGED <<rxN, rxLast, rxMsg, rxClose, failing, txData, tcp>>

CloseTcp ==
    /\ tcp = "open" /\ ((rxClose /\ txClose > 0) \/ failing)
    /\ tcp' = "self"
    /\ UNCHANGED <<rxN, rxLast, rxMsg, rxClose, failing, txData, txClose>>

PeerDrops ==
    /\ tcp = "open" /\ tcp' = "peer"
    /\ UNCHANGED <<rxN, rxLast, rxMsg, rxClose, failing, txData, txClose>>

Next == Receive \/ SendData \/ SendClose \/ CloseTcp \/ PeerDrops

Safety == Init /\ [][Next]_vars
Spec == Safety /\ WF_vars(rxClose /\ SendClose) /\ WF_vars(CloseTcp)

\* Each rule below follows from Safety; checked under a refinement
\* mapping, each one names the RFC sentence a model breaks.
NewFrame == rxN' # rxN
Delivered == NewFrame /\ rxLast'.fate = "deliver"

FragmentOrder == [][Delivered => InOrder(rxLast'.op, rxMsg)]_vars            \* 5.4
ControlFrames == [][Delivered /\ Control(rxLast'.op) =>
                        rxLast'.fin /\ rxLast'.len <= 125]_vars              \* 5.5
CloseBody == [][Delivered /\ rxLast'.op = "close" => rxLast'.len # 1]_vars   \* 5.5.1
ControlInsideMessage ==
    [][Delivered /\ rxLast'.op \in {"ping", "pong"} => rxMsg' = rxMsg]_vars  \* 5.4
ValidControlAccepted ==
    [][NewFrame /\ rxLast'.fate = "fail" =>
           ~(Control(rxLast'.op) /\ Valid(rxLast', rxMsg))]_vars             \* 5.4, 5.5
DiscardAfterClose == [][NewFrame /\ rxClose => rxLast'.fate = "discard"]_vars \* 1.4
NoDataAfterClose == [][txData' # txData => txClose = 0]_vars                 \* 5.5.1
OneClose == txClose <= 1                                                     \* 5.5.1
TcpClosedAfterHandshake ==
    [][tcp = "open" /\ tcp' = "self" =>
           (rxClose /\ txClose > 0) \/ failing]_vars                         \* 5.5.1, 7.1.7
CloseAnswered == rxClose ~> (txClose > 0 \/ tcp = "peer")                    \* 5.5.1
ServerClosesTcp == (rxClose /\ txClose > 0) ~> (tcp # "open")                \* 5.5.1, 7.1.1
FailCloses == failing ~> (tcp # "open")                                      \* 7.1.7
StateOrder == [][State' = State \/ (State = "OPEN" /\ State' # "OPEN")
                 \/ State' = "CLOSED"]_vars                                  \* 7.1.3, 7.1.4
=============================================================================
