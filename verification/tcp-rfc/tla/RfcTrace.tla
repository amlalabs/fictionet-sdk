------------------------------ MODULE RfcTrace ------------------------------
(* Replays a log of the real smoltcp socket against Rfc9293.               *)
(*                                                                         *)
(* The log comes from smoltcp/src/socket/tcp/rfc_trace.rs, which drives a  *)
(* real `Socket` with a seeded mix of user calls (listen, connect, send,   *)
(* recv, close, abort), dispatches, time, and peer segments drawn around   *)
(* the numbers that matter (the window's edges, SND.UNA and SND.NXT, one   *)
(* past and one short of each), with every control. After each step it     *)
(* writes the step's name, the segment if one arrived, the reply, and the  *)
(* socket's fields read as the RFC's variables: RCV.NXT is remote_seq_no + *)
(* rx_buffer.len(), the window's edge receive_window_end(), SND.UNA        *)
(* local_seq_no, SND.NXT local_seq_max, and so on, as Engine.tla maps      *)
(* them. Send-side numbers are written as offsets from the ISS, peer-side  *)
(* numbers as offsets from the IRS plus one minus one, so the IRS is N - 1 *)
(* as the configs of Engine have it. The driver keeps every number it      *)
(* draws within a few hundred of those it aims at, so comparisons modulo N *)
(* = 2^20 here agree with the code's modulo 2^32; the ISS and IRS are      *)
(* drawn near 2^32, so the code's own numbers wrap. What happens exactly   *)
(* half the space away is the Lean vectors' and Engine.tla's to check.     *)
(*                                                                         *)
(* Each step below is the Rfc9293 action of the same name with the logged  *)
(* state as its next state. A log Rfc9293 cannot follow has no next step   *)
(* at that entry, and TLC reports a deadlock there. `cargo xtask           *)
(* tcp-rfc-verify trace` makes the logs and runs this.                     *)
EXTENDS Rfc9293, Sequences

CONSTANT Log
VARIABLE i

tvars == <<vars, i>>

Post(e) ==
  /\ st' = e.st /\ passive' = e.passive /\ una' = e.una /\ nxt' = e.nxt
  /\ queued' = e.queued /\ finQ' = e.finQ /\ rnxt' = e.rnxt
  /\ redge' = e.redge /\ rbuf' = e.rbuf /\ held' = e.held /\ sfin' = e.sfin
  /\ out' = e.out

Act(e) ==
  CASE e.a = "Arrive" -> seg' = e.seg /\ Arrive(e.seg)
    [] e.a = "SendNext" -> seg' = NoSeg /\ SendNext
    [] e.a = "Advertise" -> seg' = NoSeg /\ Advertise
    [] e.a = "Listen" -> seg' = NoSeg /\ Listen
    [] e.a = "Connect" -> seg' = NoSeg /\ Connect
    [] e.a = "Send" -> seg' = NoSeg /\ Send
    [] e.a = "Receive" -> seg' = NoSeg /\ Receive
    [] e.a = "Close" -> seg' = NoSeg /\ Close
    [] e.a = "Abort" -> seg' = NoSeg /\ Abort
    [] e.a = "TimeWaitEnds" -> seg' = NoSeg /\ TimeWaitEnds

Replay == /\ i <= Len(Log) /\ Act(Log[i]) /\ Post(Log[i]) /\ i' = i + 1
\* Once the log is consumed the trace may stop; this keeps TLC from
\* calling the end a deadlock.
Done == i > Len(Log) /\ UNCHANGED tvars

TInit == Init /\ i = 1
TSpec == TInit /\ [][Replay \/ Done]_tvars
=============================================================================
