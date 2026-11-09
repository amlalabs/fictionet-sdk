------------------------------ MODULE Messages ------------------------------
EXTENDS Naturals

(* Source: src/stdlib/protocols/websocket.rs at comp/v-ws-http1.
   Receive models Messages::decode, lines 957-1022, with complete frames:
   Header::parse lines 394-403 checks control FIN and length;
   lines 959-960 stop after close; 966-970 check continuation order;
   973-974 charge the aggregate before Frames::decode copies the payload;
   987-988 preserve a partial message across ping/pong; 989-992 clear it
   on close; 994-1004 append; 1011-1019 finish and clear the partial.
   UTF-8 and raw-byte parsing are deliberately left to the Rust harnesses.
   Failed decode calls terminate through codec::Stream; no next call is
   modeled after failure. CheckBeforeGrowth bounds the logical aggregate
   before copying, represented by charged, including final frames that
   immediately release. It does not bound total transient allocation.
*)
CONSTANTS Limit, Steps, CheckOrder, CheckControl, CheckBeforeGrowth,
          StopAfterClose, PreservePartial
VARIABLES partial, held, closed, failed, count, closes, charged, last
vars == <<partial, held, closed, failed, count, closes, charged, last>>
Ops == {"data", "continuation", "ping", "pong", "close"}
Control(op) == op \in {"ping", "pong", "close"}
Order(op, before) == IF op = "continuation" THEN before
                    ELSE IF op = "data" THEN ~before ELSE TRUE
Init == /\ partial = FALSE /\ held = 0 /\ closed = FALSE
        /\ failed = FALSE /\ count = 0 /\ closes = 0 /\ charged = 0
        /\ last = [accepted |-> FALSE, op |-> "data", fin |-> TRUE,
                    len |-> 0, before |-> FALSE, bytes |-> 0,
                    wasClosed |-> FALSE]
Receive(op, fin, len) ==
    LET accept == ~(StopAfterClose /\ closed)
                  /\ (~CheckOrder \/ Order(op, partial))
                  /\ (~CheckControl \/ ~Control(op) \/ (fin /\ len <= 125))
                  /\ (~CheckBeforeGrowth \/ Control(op) \/ held + len <= Limit)
    IN /\ ~failed /\ count < Steps
       /\ count' = count + 1
       /\ last' = [accepted |-> accept, op |-> op, fin |-> fin,
                    len |-> len, before |-> partial, bytes |-> held,
                    wasClosed |-> closed]
       /\ failed' = ~accept /\ closed' = (closed \/ (accept /\ op = "close"))
       /\ closes' = closes + (IF accept /\ op = "close" THEN 1 ELSE 0)
       /\ charged' = IF accept /\ ~Control(op) THEN held + len ELSE 0
       /\ partial' = IF ~accept THEN partial
                      ELSE IF op = "close" THEN FALSE
                      ELSE IF Control(op) THEN (partial /\ PreservePartial)
                      ELSE ~fin
       /\ held' = IF ~accept THEN held
                   ELSE IF op = "close" THEN 0
                   ELSE IF Control(op) THEN IF PreservePartial THEN held ELSE 0
                   ELSE IF fin THEN 0 ELSE held + len
Next == \E op \in Ops, fin \in BOOLEAN, len \in {0, 1, 2, 125, 126}:
            Receive(op, fin, len)
Spec == Init /\ [][Next]_vars
ContinuationOrder == last.accepted => Order(last.op, last.before)
ControlAtomic == last.accepted /\ Control(last.op) => last.fin /\ last.len <= 125
ChargedBeforeGrowth == charged <= Limit
ControlPreservesPartial == last.accepted /\ last.op \in {"ping", "pong"} =>
                            partial = last.before /\ held = last.bytes
ReceiveEndsAtClose == last.accepted => ~last.wasClosed
OneReceivedClose == closes <= 1
=============================================================================
