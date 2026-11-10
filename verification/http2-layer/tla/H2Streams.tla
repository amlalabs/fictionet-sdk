----------------------------- MODULE H2Streams -----------------------------
(* The stream rules of the server layer `Http2`                           *)
(* (src/stdlib/web/httpd/http2.rs), checked against the RFC's rules in    *)
(* `StreamRules.tla`. Each client frame is one step: the CONTINUATION     *)
(* count in `on_frame`, the header block in `HeaderBlocks::read_fragment` *)
(* (src/stdlib/protocols/http2.rs), then the arm of `dispatch`, or        *)
(* `on_input` for a PRIORITY the frame decoder refused with stream scope. *)
(* The server's own steps: a response's END_STREAM written (`written`,    *)
(* with a NO_ERROR reset if the request is still open), a reset for a     *)
(* child's cause, graceful shutdown, and the close of a drained           *)
(* connection.                                                            *)
(*                                                                        *)
(* Source lines, at the commit in README.md:                              *)
(*   Http2::upgraded (stream 1 after h2c)     http2.rs 502-516            *)
(*   Http2::goaway, fail, finish              http2.rs 680-699, 748-769   *)
(*   Http2::write_reset, write_rst, reset,    http2.rs 773-848            *)
(*     reset_closed, client_error, ignored                                *)
(*   Http2::admit (Children may refuse)       http2.rs 855-935            *)
(*   Http2::end_stream                        http2.rs 1088-1117          *)
(*   Http2::headers_on, on_headers            http2.rs 1125-1247          *)
(*   Http2::on_data (stream states)           http2.rs 1249-1307          *)
(*   Http2::on_frame (CONTINUATION count)     http2.rs 1330-1350          *)
(*   Http2::dispatch                          http2.rs 1361-1497          *)
(*   Http2::on_input (refused frames)         http2.rs 1499-1540          *)
(*   Http2::written (the end of a response)   http2.rs 1913-1973          *)
(*   Http2::advance (shutdown, drain)         http2.rs 2123-2179          *)
(*   HeaderBlocks::read_parsed, read_fragment protocols/http2.rs 1299-1388 *)
(*   Inputs::decode (PRIORITY scope)          protocols/http2.rs 884-965  *)
(*                                                                        *)
(* Left out: flow control (Flow.tla) and the DATA and HEADERS refusals it *)
(* and content-length drive; request validation (a malformed request is   *)
(* reset with PROTOCOL_ERROR before `admit`); SETTINGS (Settings.tla);    *)
(* budgets, the pending-reset and error-reset limits; stream 0, which the *)
(* frame decoder refuses before any of this (`FrameHeader::validate`,     *)
(* checked by Rust tests); PING other than the shutdown PING's ACK.       *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Odd, Even, MaxOpen, Top, H2c,
          MaxFrames,     \* how many frames the client sends
          RMax,          \* RESET_MAX, the places in the reset list
          ContMax,       \* the CONTINUATION frames `on_frame` takes in a row
          Refusable,     \* streams whose child `Children` may refuse
          ResetsByChild, \* streams a child may reset for a cause of its own
          Shutdown,      \* graceful shutdown may begin
          HVariants,     \* what may be wrong with a HEADERS frame
          CVariants,     \* ... with a CONTINUATION frame
          PVariants,     \* ... with a PRIORITY frame
          Kinds,         \* the frame types the client sends
          \* The code's rules; each control turns one off.
          KeepResets,      \* the reset list keeps entries until it is full (no expiry)
          EvictOldest,     \* a full list forgets its oldest entry for the new one
          ListOnlyNew,     \* a reset of a stream already closed is not remembered
          IgnoreList,      \* frames on a stream in the reset list are ignored
          EvenCheck,       \* `headers_on` refuses even streams
          BelowLast,       \* `headers_on` refuses streams at or below `last_stream`
          RecordLast,      \* `on_headers` records a new stream as `last_stream`
          ClosedCheck,     \* a half-closed (remote) stream refuses DATA and HEADERS
          IdleCheck,       \* DATA, WINDOW_UPDATE, RST_STREAM on an idle stream end the connection
          WuClosedIgnore,  \* WINDOW_UPDATE on a closed stream is ignored
          ClosedDataRefused, \* DATA on a closed stream is a stream error
          Limit,           \* a new stream past `Limits::streams` is refused
          RefuseDraining,  \* a new stream while draining is refused
          MinGoaway,       \* `goaway` never sends a larger last stream than before
          InterleaveCheck, \* `read_fragment` refuses frames inside a block
          ContCheck,       \* `read_fragment` refuses CONTINUATION without a block
          CompressionCheck,\* a block HPACK cannot decode ends the connection
          DecodeFirst,     \* every block is decoded before its stream is judged
          End431,          \* no reset after a 431 that ends a request that ended
          PriorityScope,   \* a refused PRIORITY is a stream error, not ignored
          PriorityIdleOk,  \* PRIORITY on an idle stream is ignored
          SelfDep,         \* self-dependent HEADERS is a stream error
          PushRefused,     \* PUSH_PROMISE from the client ends the connection
          TrailersEnd,     \* trailers without END_STREAM are a stream error
          NoRstForRst      \* the RST_STREAM arm writes no reset

Ids == Odd \cup Even
ASSUME RMax >= 1 /\ ContMax >= 1

Min(a, b) == IF a < b THEN a ELSE b
NoHb == [s |-> 0, es |-> FALSE, bad |-> FALSE, big |-> FALSE, self |-> FALSE]

VARIABLES smap,     \* Http2::streams: absent ("none"), open, or receive.closed ("hcr")
          last,     \* Http2::last_stream
          rl,       \* Http2::resets, oldest first
          draining, \* Http2::draining
          gl,       \* Http2::goaway_last, Top for none
          shut,     \* graceful shutdown: none, pinged (GOAWAY 2^31 - 1 and PING out), done
          phase,    \* open or closed
          hb,       \* HeaderBlocks::pending: stream, END_STREAM, and (ghost) what its block holds
          cont,     \* Http2::continuations
          hist,     \* ghost: how a stream closed, for the refinement mapping
          taken,    \* ghost: streams admitted
          rx        \* ghost: the last frame and the reaction, as StreamRules has it

vars == <<smap, last, rl, draining, gl, shut, phase, hb, cont, hist, taken, rx>>

\* The refinement mapping. A stream is idle above `last_stream` and closed
\* at or below it, unless it is in the map; even streams are always idle.
MapSt == [i \in Ids |->
  CASE i \in Even /\ smap[i] = "none" -> "idle"
    [] smap[i] = "open" -> "open"
    [] smap[i] = "hcr" -> "hcr"
    [] i > last -> "idle"
    [] OTHER -> "closed"]
MapHow == [i \in Ids |->
  IF MapSt[i] = "closed" THEN (IF hist[i] = "-" THEN "skipped" ELSE hist[i]) ELSE "-"]
MapBlk == IF phase = "open" /\ hb.s # 0 THEN hb ELSE NoHb

S == INSTANCE StreamRules WITH st <- MapSt, how <- MapHow, highest <- last,
       blk <- MapBlk, ga <- gl, taken <- taken, up <- phase, rx <- rx

-----------------------------------------------------------------------------
(* The code, as functions from a state record to an outcome *)

State == [smap |-> smap, last |-> last, rl |-> rl, draining |-> draining,
          gl |-> gl, shut |-> shut, phase |-> phase, hb |-> hb, cont |-> cont,
          hist |-> hist, taken |-> taken]
Out(o, r, dec) == [o |-> o, r |-> r, dec |-> dec]

Live(o) == {i \in Ids : o.smap[i] # "none"}
Ign(o, i) == IgnoreList /\ \E k \in 1..Len(o.rl) : o.rl[k] = i
InList(o, i) == \E k \in 1..Len(o.rl) : o.rl[k] = i
Idle(o, i) == i > o.last \/ i \in Even

\* `write_reset`: ends a live stream and remembers the reset, unless the
\* connection is closing or the stream is in the list already.
Remember(o, i) ==
  IF o.phase # "open" \/ InList(o, i) THEN o.rl
  ELSE IF Len(o.rl) < RMax THEN Append(o.rl, i)
  ELSE IF EvictOldest THEN Append(Tail(o.rl), i)
  ELSE o.rl
WriteReset(o, i, c, dec) ==
  Out([o EXCEPT !.smap = [@ EXCEPT ![i] = "none"],
                !.hist = [@ EXCEPT ![i] = "sentRst"],
                !.rl = Remember(o, i)], S!Rst(c), dec)
\* `reset_closed`: RST_STREAM on a stream already closed, not remembered.
ResetClosed(o, i, c, dec) ==
  IF ListOnlyNew THEN Out(o, S!Rst(c), dec)
  ELSE Out([o EXCEPT !.rl = Remember(o, i)], S!Rst(c), dec)
\* `fail`: GOAWAY with the code, then the end.
Fail(o, c) ==
  Out([o EXCEPT !.phase = "closed", !.gl = Min(o.last, o.gl)], S!Conn(c), FALSE)
\* `goaway` as a drain sends it.
Goaway(o) == IF MinGoaway THEN Min(o.last, o.gl) ELSE o.last

\* `on_headers` for a block on stream i that ended.
OnHeaders(o, i, es, big, refuse, dec) ==
  CASE i \in Even /\ EvenCheck -> Fail(o, "PROTOCOL_ERROR")
    [] Ign(o, i) -> Out(o, S!Drop, dec)
    [] o.smap[i] # "none" ->
         CASE o.smap[i] = "hcr" /\ ClosedCheck -> WriteReset(o, i, "STREAM_CLOSED", dec)
           [] (~es /\ TrailersEnd) \/ big -> WriteReset(o, i, "PROTOCOL_ERROR", dec)
           [] OTHER -> Out([o EXCEPT !.smap = [@ EXCEPT ![i] = "hcr"]], S!Take, dec)
    [] i <= o.last /\ BelowLast -> Fail(o, "PROTOCOL_ERROR")
    [] OTHER ->
         LET o1 == IF RecordLast THEN [o EXCEPT !.last = i] ELSE o
         IN CASE (o.draining /\ RefuseDraining) \/ (Cardinality(Live(o)) >= MaxOpen /\ Limit) ->
                   WriteReset(o1, i, "REFUSED_STREAM", dec)
              [] big ->
                   IF es /\ End431
                   THEN Out([o1 EXCEPT !.hist = [@ EXCEPT ![i] = "ended"]], S!R431("-"), dec)
                   ELSE LET w == WriteReset(o1, i, "REFUSED_STREAM", dec)
                        IN [w EXCEPT !.r = S!R431("REFUSED_STREAM")]
              [] i \in Refusable /\ refuse -> WriteReset(o1, i, "REFUSED_STREAM", dec)
              [] OTHER ->
                   Out([o1 EXCEPT !.smap = [@ EXCEPT ![i] = IF es THEN "hcr" ELSE "open"],
                                  !.taken = @ \cup {i}], S!Take, dec)

\* The self-dependent HEADERS arm of `dispatch`, on the frame itself.
SelfHeaders(o, i, eh, dec) ==
  CASE i \in Even -> Fail(o, "PROTOCOL_ERROR")
    [] Ign(o, i) -> Out(o, IF eh THEN S!Drop ELSE S!Wait, dec)
    [] o.smap[i] # "none" -> WriteReset(o, i, "PROTOCOL_ERROR", dec)
    [] i <= o.last -> Fail(o, "PROTOCOL_ERROR")
    [] OTHER -> WriteReset([o EXCEPT !.last = i], i, "PROTOCOL_ERROR", dec)

OnData(o, i, es) ==
  CASE Ign(o, i) -> Out(o, S!Drop, FALSE)
    [] o.smap[i] = "none" ->
         IF Idle(o, i) /\ IdleCheck THEN Fail(o, "PROTOCOL_ERROR")
         ELSE IF ClosedDataRefused THEN ResetClosed(o, i, "STREAM_CLOSED", FALSE)
         ELSE Out(o, S!Take, FALSE)
    [] o.smap[i] = "hcr" /\ ClosedCheck -> WriteReset(o, i, "STREAM_CLOSED", FALSE)
    [] OTHER ->
         Out([o EXCEPT !.smap = [@ EXCEPT ![i] = IF es THEN "hcr" ELSE @]], S!Take, FALSE)

OnWu(o, i) ==
  CASE o.smap[i] # "none" -> Out(o, S!Take, FALSE)
    [] Idle(o, i) /\ IdleCheck -> Fail(o, "PROTOCOL_ERROR")
    [] ~WuClosedIgnore /\ ~InList(o, i) -> Fail(o, "STREAM_CLOSED")
    [] OTHER -> Out(o, S!Drop, FALSE)

OnRst(o, i) ==
  CASE Idle(o, i) /\ IdleCheck -> Fail(o, "PROTOCOL_ERROR")
    [] o.smap[i] # "none" ->
         Out([o EXCEPT !.smap = [@ EXCEPT ![i] = "none"],
                       !.hist = [@ EXCEPT ![i] = "recvRst"]],
             IF NoRstForRst THEN S!Take ELSE S!Rst("STREAM_CLOSED"), FALSE)
    [] OTHER -> Out(o, S!Drop, FALSE)

\* `on_input` for a PRIORITY `Inputs` refused with stream scope.
OnRefused(o, f) ==
  LET c == IF f.v = "len" THEN "FRAME_SIZE_ERROR" ELSE "PROTOCOL_ERROR"
      i == f.s
  IN CASE o.hb.s # 0 -> Fail(o, "PROTOCOL_ERROR")
       [] ~PriorityScope -> Out(o, S!Drop, FALSE)
       [] Idle(o, i) -> Fail(o, c)
       [] Ign(o, i) -> Out(o, S!Drop, FALSE)
       [] o.smap[i] # "none" -> WriteReset(o, i, c, FALSE)
       [] OTHER -> ResetClosed(o, i, c, FALSE)

\* The arm of `dispatch` after the block is read.
Act(o, f, bs, es, big, refuse, dec) ==
  CASE f.t = "PUSH" -> IF PushRefused THEN Fail(o, "PROTOCOL_ERROR") ELSE Out(o, S!Drop, dec)
    [] f.t = "HEADERS" /\ f.v = "self" /\ SelfDep -> SelfHeaders(o, f.s, f.eh, dec)
    [] f.t \in {"HEADERS", "CONT"} ->
         IF f.eh THEN OnHeaders(o, bs, es, big, refuse, dec) ELSE Out(o, S!Wait, FALSE)
    [] f.t = "DATA" -> OnData(o, f.s, f.es)
    [] f.t = "WU" -> OnWu(o, f.s)
    [] f.t = "RST" -> OnRst(o, f.s)
    [] f.t = "PINGACK" ->
         IF o.shut = "pinged"
         THEN Out([o EXCEPT !.shut = "done", !.draining = TRUE, !.gl = Goaway(o)], S!Drain, FALSE)
         ELSE Out(o, S!Drop, FALSE)
    [] f.t = "GOAWAY" -> Out([o EXCEPT !.draining = TRUE, !.gl = Goaway(o)], S!Drain, FALSE)
    [] f.t = "PRIORITY" /\ ~PriorityIdleOk /\ Idle(o, f.s) -> Fail(o, "PROTOCOL_ERROR")
    [] OTHER -> Out(o, S!Drop, FALSE)

\* `dispatch`: the block first, in `read_fragment`, then the arm.
Dispatch(o, f, refuse) ==
  CASE o.hb.s # 0 /\ (f.t # "CONT" \/ f.s # o.hb.s) /\ InterleaveCheck ->
         Fail(o, "PROTOCOL_ERROR")
    [] o.hb.s = 0 /\ f.t = "CONT" /\ ContCheck -> Fail(o, "PROTOCOL_ERROR")
    [] f.t \in {"HEADERS", "PUSH", "CONT"} ->
         LET inblk == f.t = "CONT" /\ o.hb.s # 0
             bs == IF inblk THEN o.hb.s ELSE f.s
             es == IF inblk THEN o.hb.es ELSE (f.t = "HEADERS" /\ f.es)
             bad == (inblk /\ o.hb.bad) \/ f.v = "bad"
             big == (inblk /\ o.hb.big) \/ f.v = "big"
             self == IF inblk THEN o.hb.self ELSE f.v = "self"
             dec == DecodeFirst \/ ~InList(o, bs)
         IN IF ~f.eh
            THEN Act([o EXCEPT !.hb = [s |-> bs, es |-> es, bad |-> bad, big |-> big,
                                      self |-> self]], f, bs, es, big, refuse, FALSE)
            ELSE IF bad /\ CompressionCheck /\ dec THEN Fail([o EXCEPT !.hb = NoHb], "COMPRESSION_ERROR")
            ELSE Act([o EXCEPT !.hb = NoHb], f, bs, es, big, refuse, dec)
    [] OTHER -> Act(o, f, f.s, FALSE, FALSE, refuse, FALSE)

\* One client frame: `on_frame`'s count, then `dispatch`, or `on_input`'s
\* refusal arm for a PRIORITY the decoder refused.
Handle(o, f, refuse) ==
  IF f.t = "PRIORITY" /\ f.v \in {"len", "self"} THEN OnRefused(o, f)
  ELSE IF f.t = "CONT" /\ o.cont + 1 > ContMax
  THEN Fail([o EXCEPT !.cont = @ + 1], "ENHANCE_YOUR_CALM")
  ELSE Dispatch([o EXCEPT !.cont = IF f.t = "CONT" THEN @ + 1 ELSE 0], f, refuse)

Gen ==
  (IF "DATA" \in Kinds THEN [t : {"DATA"}, s : Ids, es : BOOLEAN, eh : {FALSE}, v : {"ok"}] ELSE {})
  \cup (IF "HEADERS" \in Kinds THEN [t : {"HEADERS"}, s : Ids, es : BOOLEAN, eh : BOOLEAN, v : HVariants] ELSE {})
  \cup (IF "CONT" \in Kinds THEN [t : {"CONT"}, s : Ids, es : {FALSE}, eh : BOOLEAN, v : CVariants] ELSE {})
  \cup (IF "PRIORITY" \in Kinds THEN [t : {"PRIORITY"}, s : Ids, es : {FALSE}, eh : {FALSE}, v : PVariants] ELSE {})
  \cup [t : Kinds \cap {"RST", "WU"}, s : Ids, es : {FALSE}, eh : {FALSE}, v : {"ok"}]
  \cup [t : Kinds \cap {"PUSH", "UNKNOWN"}, s : {CHOOSE i \in Odd : \A j \in Odd : i <= j},
        es : {FALSE}, eh : {TRUE}, v : {"ok"}]
  \cup [t : Kinds \cap {"PINGACK", "GOAWAY"}, s : {0}, es : {FALSE}, eh : {FALSE}, v : {"ok"}]

Apply(out, f) ==
  /\ smap' = out.o.smap /\ last' = out.o.last /\ rl' = out.o.rl
  /\ draining' = out.o.draining /\ gl' = out.o.gl /\ shut' = out.o.shut
  /\ phase' = out.o.phase /\ hb' = out.o.hb /\ cont' = out.o.cont
  /\ hist' = out.o.hist /\ taken' = out.o.taken
  /\ rx' = [n |-> rx.n + 1, f |-> f, r |-> out.r, dec |-> out.dec]

Recv(f, refuse) ==
  /\ phase = "open"
  /\ rx.n < MaxFrames
  /\ Apply(Handle(State, f, refuse), f)

-----------------------------------------------------------------------------
(* The server's own steps *)

\* `written`: a response's END_STREAM is out; a request still open gets a
\* NO_ERROR reset.
Answer(i) ==
  /\ phase = "open"
  /\ smap[i] # "none"
  /\ smap' = [smap EXCEPT ![i] = "none"]
  /\ IF smap[i] = "hcr"
     THEN hist' = [hist EXCEPT ![i] = "ended"] /\ UNCHANGED rl
     ELSE hist' = [hist EXCEPT ![i] = "sentRst"] /\ rl' = Remember(State, i)
  /\ UNCHANGED rx
  /\ UNCHANGED <<last, draining, gl, shut, phase, hb, cont, taken>>

\* A child's cause resets its stream (`write_reset` from `on_child`).
ChildReset(i) ==
  /\ phase = "open"
  /\ i \in ResetsByChild
  /\ smap[i] # "none"
  /\ smap' = [smap EXCEPT ![i] = "none"]
  /\ hist' = [hist EXCEPT ![i] = "sentRst"]
  /\ rl' = Remember(State, i)
  /\ UNCHANGED rx
  /\ UNCHANGED <<last, draining, gl, shut, phase, hb, cont, taken>>

\* `advance`: graceful shutdown sends GOAWAY with 2^31 - 1 and a PING.
BeginShutdown ==
  /\ Shutdown /\ phase = "open" /\ shut = "none" /\ ~draining
  /\ shut' = "pinged"
  /\ gl' = Min(Top, gl)
  /\ UNCHANGED rx
  /\ UNCHANGED <<smap, last, rl, draining, phase, hb, cont, hist, taken>>

\* `advance`: a draining connection with no stream left closes.
DrainClose ==
  /\ phase = "open" /\ draining /\ Live(State) = {}
  /\ phase' = "closed"
  /\ UNCHANGED rx
  /\ UNCHANGED <<smap, last, rl, draining, gl, shut, hb, cont, hist, taken>>

\* The code before this model: `on_timer` forgot a reset one second after it.
Expire ==
  /\ ~KeepResets /\ phase = "open" /\ rl # <<>>
  /\ rl' = Tail(rl)
  /\ UNCHANGED <<smap, last, draining, gl, shut, phase, hb, cont, hist, taken, rx>>

Init ==
  /\ smap = [i \in Ids |-> IF H2c /\ i = 1 THEN "hcr" ELSE "none"]
  /\ last = IF H2c THEN 1 ELSE 0
  /\ rl = <<>>
  /\ draining = FALSE
  /\ gl = Top
  /\ shut = "none"
  /\ phase = "open"
  /\ hb = NoHb
  /\ cont = 0
  /\ hist = [i \in Ids |-> "-"]
  /\ taken = IF H2c THEN {1} ELSE {}
  /\ rx = [n |-> 0, f |-> S!NoFrame, r |-> S!Drop, dec |-> FALSE]

Next ==
  \/ \E f \in Gen, refuse \in BOOLEAN : Recv(f, refuse)
  \/ \E i \in Ids : Answer(i) \/ ChildReset(i)
  \/ BeginShutdown
  \/ DrainClose
  \/ Expire

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties: the RFC's rules through the mapping, one at a time *)

TypeOK == S!TypeOK
GoawayCovers == [][S!GoawayCovers]_vars
Refines == S!Spec

IdleFrames == [][S!IdleFrames]_vars
EvenHeaders == [][S!EvenHeaders]_vars
LowerIdHeaders == [][S!LowerIdHeaders]_vars
HalfClosedRemote == [][S!HalfClosedRemote]_vars
ServerResetDiscarded == [][S!ServerResetDiscarded]_vars
ClosedAfterEnd == [][S!ClosedAfterEnd]_vars
ClosedData == [][S!ClosedData]_vars
Concurrency == [][S!Concurrency]_vars
NoRstForRst_ == [][S!NoRstForRst]_vars
GoawayRefuses == [][S!GoawayRefuses]_vars
GoawayNeverGrows == [][S!GoawayNeverGrows]_vars
Interleave == [][S!Interleave]_vars
ContWithoutBlock == [][S!ContWithoutBlock]_vars
Compression == [][S!Compression]_vars
BlocksDecoded == [][S!BlocksDecoded]_vars
HeaderListSize == [][S!HeaderListSize]_vars
PriorityAnyState == [][S!PriorityAnyState]_vars
PriorityMalformed == [][S!PriorityMalformed]_vars
SelfDependentHeaders == [][S!SelfDependentHeaders]_vars
PushRefused_ == [][S!PushRefused]_vars
TrailersEnd_ == [][S!TrailersEnd]_vars

=============================================================================
