--------------------------- MODULE SessionStreams ---------------------------
(* The stream rules of the sans-I/O `Session` (src/stdlib/protocols/      *)
(* http2.rs) reading the client's direction (`Session::client_side`),     *)
(* checked against `StreamRules.tla`.                                     *)
(*                                                                        *)
(* `Session` tracks one direction and leaves part of the rules to its     *)
(* caller, as its module documentation says: "Idle-stream checks and      *)
(* stream ownership belong to the caller", "The caller coordinates        *)
(* request IDs", and GOAWAY. So this model checks the rules `Session`     *)
(* owns, and leaves out `IdleFrames` (RST_STREAM and WINDOW_UPDATE on an  *)
(* idle stream come out as events), `EvenHeaders`, `LowerIdHeaders`,      *)
(* `Concurrency` (its stream limit is a memory bound), `GoawayRefuses`,   *)
(* `GoawayNeverGrows` and `GoawayCovers` (it sends nothing), and          *)
(* `Refines` as a whole. An error of `Session` stops the direction, a     *)
(* connection error in the RFC's terms (section 5.4.1 allows it for a     *)
(* stream error), except a stream-scope refusal outside a header block,   *)
(* which comes out as `Event::StreamError`: the caller resets the stream, *)
(* or ends the connection when the stream is idle (`Step` says how).      *)
(*                                                                        *)
(* The caller's steps: the server resets a stream (`peer_reset`), the     *)
(* server's END_STREAM (which only the other direction sees), and         *)
(* `retire` once both halves are over. The RFC's view of the streams is   *)
(* kept beside `Session` as a history: `StreamRules`' own variables,      *)
(* moved by its `Effect` with the reaction `Session` gave and by its      *)
(* `Finish` and `Reset` for the caller's steps.                           *)
(*                                                                        *)
(* Source lines, at the commit in README.md:                              *)
(*   Inputs::decode (refusals)              protocols/http2.rs 884-965    *)
(*   HeaderBlocks::read_parsed, read_fragment  protocols/http2.rs 1320-1409 *)
(*   Session::retire                        protocols/http2.rs 1583-1592  *)
(*   Session::open_stream, retired          protocols/http2.rs 1611-1622  *)
(*   Session::peer_reset, reset_by_peer     protocols/http2.rs 1632-1659  *)
(*   Session::stream_state                  protocols/http2.rs 1811-1824  *)
(*   Session::step                          protocols/http2.rs 1859-2011  *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Odd, Even, Top,
          MaxFrames,  \* how many frames the client sends
          SMax,       \* Limits::streams: stream states, and peer-reset ids kept
          HVariants, CVariants, PVariants, Kinds,
          \* The code's rules; each control turns one off.
          PushFirst,        \* a client PUSH_PROMISE is refused on its frame
          ResetDrops,       \* frames on a stream the caller reset are dropped
          ClosedCheck,      \* HEADERS and DATA on an ended stream are refused
          InterleaveCheck,  \* `read_fragment` refuses frames inside a block
          DecodeFirst,      \* a block on a reset stream is decoded
          TrailersEnd,      \* trailers without END_STREAM are refused
          SelfDep,          \* self-dependent HEADERS is refused
          ContCheck,        \* CONTINUATION without a block is refused
          CompressionCheck, \* a block HPACK cannot decode is refused
          PriorityScope,    \* a PRIORITY the decoder refused is an error
          PriorityIdleOk    \* PRIORITY on an idle stream is an event

Ids == Odd \cup Even
Parity(i) == i % 2
Max(a, b) == IF a > b THEN a ELSE b
NoHb == [s |-> 0, es |-> FALSE, bad |-> FALSE, big |-> FALSE, self |-> FALSE, push |-> FALSE]

VARIABLES tracked,   \* Session::streams has the stream
          hdr,       \* StreamState::headers
          cl,        \* StreamState::closed
          rbp,       \* StreamState::reset_by_peer
          retiredB,  \* Session::retired_before, per parity
          presets,   \* Session::peer_resets
          resetB,    \* Session::reset_before, per parity
          hb,        \* HeaderBlocks::pending, with (ghost) what the block holds
          stopped,   \* Session::stopped
          \* The RFC's view, kept as a history.
          gst, ghow, ghi, gblk, gga, gtaken, gup,
          rx

vars == <<tracked, hdr, cl, rbp, retiredB, presets, resetB, hb, stopped,
          gst, ghow, ghi, gblk, gga, gtaken, gup, rx>>

G == INSTANCE StreamRules WITH st <- gst, how <- ghow, highest <- ghi,
       blk <- gblk, ga <- gga, taken <- gtaken, up <- gup, rx <- rx, MaxOpen <- 1000,
       H2c <- FALSE

-----------------------------------------------------------------------------
(* The code *)

State == [tracked |-> tracked, hdr |-> hdr, cl |-> cl, rbp |-> rbp,
          retiredB |-> retiredB, presets |-> presets, resetB |-> resetB,
          hb |-> hb, stopped |-> stopped]
Out(o, r, dec) == [o |-> o, r |-> r, dec |-> dec]
Fail(o, c) == Out([o EXCEPT !.stopped = TRUE], G!Conn(c), FALSE)

ResetByPeer(o, i) ==
  IF o.tracked[i] THEN o.rbp[i]
  ELSE i \in o.presets \/ i <= o.resetB[Parity(i)]
Retired(o, i) == ~o.tracked[i] /\ i <= o.retiredB[Parity(i)]

\* `peer_reset`: the caller tells this direction the server reset stream i.
Reset(o, i) ==
  LET p0 == IF i > o.resetB[Parity(i)] THEN o.presets \cup {i} ELSE o.presets
      oldest == CHOOSE j \in p0 : \A k \in p0 : j <= k
      p1 == IF Cardinality(p0) > SMax THEN p0 \ {oldest} ELSE p0
      b1 == IF Cardinality(p0) > SMax
            THEN [o.resetB EXCEPT ![Parity(oldest)] = Max(@, oldest)]
            ELSE o.resetB
  IN [o EXCEPT !.cl = IF o.tracked[i] THEN [@ EXCEPT ![i] = TRUE] ELSE @,
               !.rbp = IF o.tracked[i] THEN [@ EXCEPT ![i] = TRUE] ELSE @,
               !.presets = p1, !.resetB = b1]

\* `stream_state` then the checks of `step` for a block that ended.
Headed(o, i, es, dec) ==
  CASE Retired(o, i) -> Fail(o, "STREAM_CLOSED")
    [] ~o.tracked[i] /\ Cardinality({j \in Ids : o.tracked[j]}) >= SMax ->
         Fail(o, "ENHANCE_YOUR_CALM")
    [] o.tracked[i] /\ o.cl[i] /\ ClosedCheck -> Fail(o, "STREAM_CLOSED")
    [] o.tracked[i] /\ o.hdr[i] /\ ~es /\ TrailersEnd -> Fail(o, "PROTOCOL_ERROR")
    [] OTHER ->
         Out([o EXCEPT !.tracked = [@ EXCEPT ![i] = TRUE],
                       !.hdr = [@ EXCEPT ![i] = TRUE],
                       !.cl = [@ EXCEPT ![i] = es],
                       !.rbp = [@ EXCEPT ![i] = IF o.tracked[i] THEN @ ELSE FALSE]],
             G!Take, dec)

Data(o, i, es) ==
  CASE ResetByPeer(o, i) /\ ResetDrops -> Out(o, G!Drop, FALSE)
    [] ~o.tracked[i] -> Fail(o, "PROTOCOL_ERROR")
    [] o.cl[i] /\ ClosedCheck -> Fail(o, "STREAM_CLOSED")
    [] ~o.hdr[i] -> Fail(o, "PROTOCOL_ERROR")
    [] OTHER -> Out([o EXCEPT !.cl = [@ EXCEPT ![i] = es]], G!Take, FALSE)

\* An event that is no error: taken on a live stream, else dropped.
Event(o, f) ==
  IF f.s \in Ids /\ gst[f.s] \in {"open", "hcl", "hcr"} /\ f.t \in {"RST", "WU"}
  THEN Out(o, G!Take, FALSE) ELSE Out(o, G!Drop, FALSE)

Step(o, f) ==
  IF f.t = "PRIORITY" /\ f.v \in {"len", "self"}
  THEN LET c == IF f.v = "len" THEN "FRAME_SIZE_ERROR" ELSE "PROTOCOL_ERROR"
       IN CASE o.hb.s # 0 -> Fail(o, c)
            [] ~PriorityScope -> Out(o, G!Drop, FALSE)
            \* `Event::StreamError`; the caller resets an open or closed
            \* stream, and routes the reset through `peer_reset`; it ends
            \* the connection for an idle stream (idle checks are its), and
            \* does nothing for a stream it reset.
            [] gst[f.s] = "idle" -> Fail(o, c)
            [] G!MustDiscard(f.s) -> Out(o, G!Drop, FALSE)
            [] OTHER -> Out(Reset(o, f.s), G!Rst(c), FALSE)
  ELSE IF f.t = "PRIORITY" /\ ~PriorityIdleOk /\ gst[f.s] = "idle" THEN Fail(o, "PROTOCOL_ERROR")
  ELSE IF f.t = "PUSH" /\ PushFirst THEN Fail(o, "PROTOCOL_ERROR")
  ELSE IF o.hb.s # 0 /\ (f.t # "CONT" \/ f.s # o.hb.s) /\ InterleaveCheck
  THEN Fail(o, "PROTOCOL_ERROR")
  ELSE IF o.hb.s = 0 /\ f.t = "CONT" /\ ContCheck THEN Fail(o, "PROTOCOL_ERROR")
  ELSE IF f.t \in {"HEADERS", "PUSH", "CONT"} THEN
    LET inblk == f.t = "CONT" /\ o.hb.s # 0
        bs == IF inblk THEN o.hb.s ELSE f.s
        es == IF inblk THEN o.hb.es ELSE (f.t = "HEADERS" /\ f.es)
        bad == (inblk /\ o.hb.bad) \/ f.v = "bad"
        big == (inblk /\ o.hb.big) \/ f.v = "big"
        push == IF inblk THEN o.hb.push ELSE f.t = "PUSH"
        o1 == [o EXCEPT !.hb = IF f.eh THEN NoHb
                               ELSE [s |-> bs, es |-> es, bad |-> bad, big |-> big,
                                     self |-> IF inblk THEN o.hb.self ELSE f.v = "self",
                                     push |-> push]]
        dec == DecodeFirst \/ ~ResetByPeer(o, bs)
    IN CASE f.eh /\ bad /\ dec /\ CompressionCheck -> Fail(o1, "COMPRESSION_ERROR")
         [] f.eh /\ big -> Fail(o1, "ENHANCE_YOUR_CALM")
         [] f.t = "HEADERS" /\ f.v = "self" /\ SelfDep -> Fail(o1, "PROTOCOL_ERROR")
         [] ResetByPeer(o, f.s) /\ ResetDrops -> Out(o1, IF f.eh THEN G!Drop ELSE G!Wait, f.eh /\ dec)
         [] ~f.eh -> Out(o1, G!Wait, FALSE)
         [] push -> Fail(o1, "PROTOCOL_ERROR")
         [] OTHER -> Headed(o1, bs, es, f.eh)
  ELSE IF f.t = "DATA" THEN Data(o, f.s, f.es)
  ELSE IF f.t = "RST" /\ o.tracked[f.s]
  THEN [Event(o, f) EXCEPT !.o.cl = [@ EXCEPT ![f.s] = TRUE]]
  ELSE Event(o, f)

Gen ==
  (IF "DATA" \in Kinds THEN [t : {"DATA"}, s : Odd, es : BOOLEAN, eh : {FALSE}, v : {"ok"}] ELSE {})
  \cup (IF "HEADERS" \in Kinds THEN [t : {"HEADERS"}, s : Odd, es : BOOLEAN, eh : BOOLEAN, v : HVariants] ELSE {})
  \cup (IF "CONT" \in Kinds THEN [t : {"CONT"}, s : Odd, es : {FALSE}, eh : BOOLEAN, v : CVariants] ELSE {})
  \cup (IF "PRIORITY" \in Kinds THEN [t : {"PRIORITY"}, s : Ids, es : {FALSE}, eh : {FALSE}, v : PVariants] ELSE {})
  \cup [t : Kinds \cap {"RST", "WU"}, s : Odd, es : {FALSE}, eh : {FALSE}, v : {"ok"}]
  \cup [t : Kinds \cap {"PUSH"}, s : Odd, es : {FALSE}, eh : BOOLEAN, v : {"ok"}]

Apply(out) ==
  /\ tracked' = out.o.tracked /\ hdr' = out.o.hdr /\ cl' = out.o.cl
  /\ rbp' = out.o.rbp /\ retiredB' = out.o.retiredB /\ presets' = out.o.presets
  /\ resetB' = out.o.resetB /\ hb' = out.o.hb /\ stopped' = out.o.stopped

Recv(f) ==
  /\ ~stopped
  /\ rx.n < MaxFrames
  /\ LET out == Step(State, f)
     IN /\ Apply(out)
        /\ rx' = [n |-> rx.n + 1, f |-> f, r |-> out.r, dec |-> out.dec]
        \* The RFC's view moves with the reaction `Session` gave.
        /\ G!Effect(f, out.r)
        /\ gga' = gga

\* The caller: the server reset stream i, so the caller tells this
\* direction (`peer_reset`).
PeerReset(i) ==
  /\ ~stopped /\ gst[i] \in {"open", "hcl", "hcr"}
  /\ G!Reset(i)
  /\ LET o == Reset(State, i)
     IN cl' = o.cl /\ rbp' = o.rbp /\ presets' = o.presets /\ resetB' = o.resetB
  /\ UNCHANGED <<tracked, hdr, retiredB, hb, stopped>>

\* The server's END_STREAM, which only the other direction reads.
ServerEnd(i) ==
  /\ ~stopped /\ gst[i] \in {"open", "hcr"}
  /\ G!Finish(i, FALSE)
  /\ UNCHANGED <<tracked, hdr, cl, rbp, retiredB, presets, resetB, hb, stopped>>

\* Both halves are over: the caller retires the stream (`retire`).
Retire(i) ==
  /\ ~stopped /\ gst[i] = "closed" /\ tracked[i] /\ cl[i]
  /\ tracked' = [tracked EXCEPT ![i] = FALSE]
  /\ retiredB' = [retiredB EXCEPT ![Parity(i)] = Max(@, i)]
  /\ UNCHANGED <<hdr, cl, rbp, presets, resetB, hb, stopped,
                 gst, ghow, ghi, gblk, gga, gtaken, gup, rx>>

Init ==
  /\ tracked = [i \in Ids |-> FALSE]
  /\ hdr = [i \in Ids |-> FALSE]
  /\ cl = [i \in Ids |-> FALSE]
  /\ rbp = [i \in Ids |-> FALSE]
  /\ retiredB = [p \in {0, 1} |-> 0]
  /\ presets = {}
  /\ resetB = [p \in {0, 1} |-> 0]
  /\ hb = NoHb
  /\ stopped = FALSE
  /\ G!Init

Next ==
  \/ \E f \in Gen : Recv(f)
  \/ \E i \in Odd : PeerReset(i) \/ ServerEnd(i) \/ Retire(i)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* The rules `Session` owns *)

HalfClosedRemote == [][G!HalfClosedRemote]_vars
ServerResetDiscarded == [][G!ServerResetDiscarded]_vars
Interleave == [][G!Interleave]_vars
ContWithoutBlock == [][G!ContWithoutBlock]_vars
Compression == [][G!Compression]_vars
BlocksDecoded == [][G!BlocksDecoded]_vars
PriorityAnyState == [][G!PriorityAnyState]_vars
PriorityMalformed == [][G!PriorityMalformed]_vars
SelfDependentHeaders == [][G!SelfDependentHeaders]_vars
PushRefused_ == [][G!PushRefused]_vars
TrailersEnd_ == [][G!TrailersEnd]_vars

=============================================================================
