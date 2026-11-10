------------------------------ MODULE Messages ------------------------------
EXTENDS Naturals

(* Source: src/stdlib/protocols/websocket.rs at comp/v-ws-http1.
   Receive models Messages::check_header, lines 960-979, and decode,
   lines 995-1047, with complete frames. Header::parse lines 394-403
   checks control FIN and length; 997-998 stop after close; 965-969
   check continuation order; 972-975 check the aggregate before
   Frames::decode at 1001 copies the payload. Lines 1011-1012 preserve
   partial data across ping/pong; 1013-1016 clear it on close; 1018-1027
   append; 1035-1043 finish and clear the partial.
   UTF-8 and raw-byte parsing are deliberately left to the Rust harnesses.
   Failed decode calls terminate through codec::Stream; no next call is
   modeled after failure. CheckBeforeGrowth bounds the logical aggregate
   before copying, represented by charged, including final frames that
   immediately release. It does not bound total transient allocation.
   charged is the decoder's own sum, held plus the frame length, that
   check_header compares with its limit at 972-976; no layer::Budget is
   involved anywhere in websocket.rs. Frames::decode at 1001 then
   allocates the frame's payload (Frame::from_header, 877) and decode
   appends it to the partial message (1027), so a message briefly costs
   its held bytes plus twice the frame.
   Line numbers checked against e2858ccc4 on 2026-11-09: all hold.
   Frames::decode, line 881, refuses a Close whose payload parse_close
   refuses; the model keeps only the length rule, a 1-byte body
   (CheckCloseBody). Codes and UTF-8 reasons are left to Kani. Control
   frames are never charged against the limit: Frames::header line 854
   and check_header line 972 both skip them (ChargeControl = FALSE).
   last.stopped marks a frame refused only because a Close came first;
   the decoder returns End there, not an error.
*)
CONSTANTS Limit, Steps, CheckOrder, CheckControl, CheckBeforeGrowth,
          StopAfterClose, PreservePartial, CheckCloseBody, ChargeControl
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
                    wasClosed |-> FALSE, stopped |-> FALSE]
Receive(op, fin, len) ==
    LET stopped == StopAfterClose /\ closed
        accept == ~stopped
                  /\ (~CheckOrder \/ Order(op, partial))
                  /\ (~CheckControl \/ ~Control(op) \/ (fin /\ len <= 125))
                  /\ (~CheckCloseBody \/ op # "close" \/ len # 1)
                  /\ (~CheckBeforeGrowth \/ (Control(op) /\ ~ChargeControl)
                      \/ held + len <= Limit)
    IN /\ ~failed /\ count < Steps
       /\ count' = count + 1
       /\ last' = [accepted |-> accept, op |-> op, fin |-> fin,
                    len |-> len, before |-> partial, bytes |-> held,
                    wasClosed |-> closed, stopped |-> stopped]
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
