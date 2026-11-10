--------------------------- MODULE HandshakeTrace ---------------------------
(* Checks that a log of a real handshake is a behavior of Handshake, the  *)
(* RFC spec. The logs come from rustls/src/server/hs_trace.rs, which runs *)
(* the crate's client against the vendored server in memory and opens    *)
(* every record with the secrets both sides logged, so each entry's epoch *)
(* is the key the record actually decrypted under.                        *)
(*                                                                        *)
(* Each "recv" entry is one Recv of the record it names; each "send"      *)
(* entry is one Emit, which must put exactly that message, epoch and kind *)
(* on the wire. The server's own decisions (queueing application data,    *)
(* tickets, KeyUpdates, an abort) are spec steps that consume no entry;   *)
(* TLC tries them all.                                                    *)
(*                                                                        *)
(* The log is a behavior of the spec iff a state with every entry         *)
(* consumed is reachable, so TLC reports the invariant LogUnfinished as   *)
(* violated exactly when the log is accepted. A log the spec cannot       *)
(* follow leaves TLC with "No error has been found": that is the failure. *)
(* `cargo xtask tls-verify handshake-trace` makes the logs and runs this. *)
EXTENDS Handshake

CONSTANT Log
VARIABLE i

Entry == Log[i]
RecOf(en) == [m |-> en.m, e |-> en.e, x |-> en.x, co |-> en.co, ch |-> en.ch]

TRecv ==
  /\ i <= Len(Log) /\ Entry.d = "recv"
  /\ Recv(RecOf(Entry))
  /\ i' = i + 1

TSend ==
  /\ i <= Len(Log) /\ Entry.d = "send"
  /\ Emit
  /\ h'.ev.m = Entry.m /\ h'.ev.e = Entry.e /\ h'.ev.x = Entry.x
  /\ i' = i + 1

TServer ==
  /\ (SendAD \/ SendNST \/ SendKU("req") \/ SendKU("noreq") \/ Abort)
  /\ UNCHANGED i

TraceInit == Init /\ i = 1
TraceNext == TRecv \/ TSend \/ TServer

LogUnfinished == i <= Len(Log)
=============================================================================
