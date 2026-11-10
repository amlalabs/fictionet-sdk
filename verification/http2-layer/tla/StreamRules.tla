---------------------------- MODULE StreamRules ----------------------------
(* RFC 9113's rules for the streams of one connection, as the server sees *)
(* them: what each frame the client sends does to a stream, and what the  *)
(* server may answer. Written from the RFC text, not from the code; the   *)
(* implementation models (`H2Streams.tla`, `SessionStreams.tla`) instance *)
(* it and check each rule as its own property.                            *)
(*                                                                        *)
(* Stream states (section 5.1): idle, open, half closed (local) "hcl",    *)
(* half closed (remote) "hcr", closed. A closed stream remembers how it   *)
(* closed: the server reset it ("sentRst"), the client reset it           *)
(* ("recvRst"), both sides ended it ("ended"), or the client skipped its  *)
(* identifier when it opened a higher one ("skipped", section 5.1.1).     *)
(* The reserved states are not here: a client cannot push (section 8.4),  *)
(* so a server reaches neither; a PUSH_PROMISE from the client is a       *)
(* connection error, which `PushRefused` checks.                          *)
(*                                                                        *)
(* A frame is a record: type, stream, END_STREAM, END_HEADERS and a       *)
(* variant naming what is wrong with it, if anything: "self" a priority   *)
(* that names its own stream, "len" a PRIORITY whose length is not 5,     *)
(* "big" a header list over the server's SETTINGS_MAX_HEADER_LIST_SIZE,   *)
(* "bad" a header block fragment HPACK cannot decode. Each step that      *)
(* receives a frame records it with the server's reaction in `rx`:        *)
(*   take    processed: a stream opens, a body or trailers go up          *)
(*   wait    a header block goes on in CONTINUATION; nothing yet          *)
(*   drop    processed as far as connection state needs, then discarded   *)
(*   rst     a stream error: RST_STREAM with the code                     *)
(*   conn    a connection error: GOAWAY with the code, then the end       *)
(*   r431    a 431 response, then RST_STREAM with the code, or none ("-") *)
(*   drain   GOAWAY with NO_ERROR: no new streams                         *)
(* and whether a header block the frame completed was decoded.            *)
(*                                                                        *)
(* Codes: section 5.4 lets PROTOCOL_ERROR stand for any more specific     *)
(* code, and section 5.4.1 lets an endpoint treat a stream error as a     *)
(* connection error; `StreamErr` allows both. On an idle stream a stream  *)
(* error can only be a connection error: RST_STREAM must not name an idle *)
(* stream (section 6.4).                                                  *)
(*                                                                        *)
(* Two choices the RFC leaves open are fixed here, both stricter than it: *)
(* a server may refuse any new stream with REFUSED_STREAM (section 8.7),  *)
(* so `take` is never required of a new stream; and section 5.1 lets an   *)
(* endpoint stop ignoring frames on a stream it reset once "other         *)
(* signals" show the client saw the reset. The code uses no such signal,  *)
(* so here a stream the server reset ignores its frames for good.         *)
(* ENHANCE_YOUR_CALM (section 10.5) is allowed only on CONTINUATION and   *)
(* on a header list over the limit, where the code uses it.               *)
EXTENDS Naturals, FiniteSets

CONSTANTS Odd,      \* client stream identifiers in the model
          Even,     \* even identifiers, which a client may not open
          MaxOpen,  \* SETTINGS_MAX_CONCURRENT_STREAMS the server sent
          Top,      \* 2^31 - 1, above every identifier
          H2c       \* the connection began with an HTTP/1 Upgrade: h2c, whose
                    \* request is stream 1, half closed (remote) (RFC 7540 3.2)

Ids == Odd \cup Even
ASSUME \A i \in Odd : i % 2 = 1 /\ i < Top
ASSUME H2c => 1 \in Odd
ASSUME \A i \in Even : i % 2 = 0 /\ i > 0 /\ i < Top

States == {"idle", "open", "hcl", "hcr", "closed"}
Hows == {"-", "sentRst", "recvRst", "ended", "skipped"}
Types == {"DATA", "HEADERS", "CONT", "PRIORITY", "RST", "WU", "PUSH",
          "UNKNOWN", "PINGACK", "GOAWAY"}
Variants == {"ok", "self", "len", "big", "bad"}
Codes == {"NO_ERROR", "PROTOCOL_ERROR", "STREAM_CLOSED", "REFUSED_STREAM",
          "FRAME_SIZE_ERROR", "COMPRESSION_ERROR", "ENHANCE_YOUR_CALM"}

\* Stream 0 only for the connection's frames, PING and GOAWAY.
Frames == [t : Types, s : Ids \cup {0}, es : BOOLEAN, eh : BOOLEAN, v : Variants]
Reactions == [k : {"take", "wait", "drop", "rst", "conn", "r431", "drain"},
              c : Codes \cup {"-"}]
NoBlock == [s |-> 0, es |-> FALSE, bad |-> FALSE, big |-> FALSE, self |-> FALSE]
Blocks == {NoBlock} \cup
          [s : Ids, es : BOOLEAN, bad : BOOLEAN, big : BOOLEAN, self : BOOLEAN]
NoFrame == [t |-> "UNKNOWN", s |-> CHOOSE i \in Ids : TRUE, es |-> FALSE,
            eh |-> FALSE, v |-> "ok"]
Take == [k |-> "take", c |-> "-"]
Wait == [k |-> "wait", c |-> "-"]
Drop == [k |-> "drop", c |-> "-"]
Drain == [k |-> "drain", c |-> "-"]
Rst(c) == [k |-> "rst", c |-> c]
Conn(c) == [k |-> "conn", c |-> c]
R431(c) == [k |-> "r431", c |-> c]

VARIABLES st,      \* each stream's state
          how,     \* how a closed stream closed
          highest, \* the highest stream the client opened, 0 for none
          blk,     \* the header block in progress: its stream (0 for none), END_STREAM, and what is wrong
          ga,      \* the last stream of the last GOAWAY the server sent; Top for none
          taken,   \* streams the server processed (section 6.8's sense)
          up,      \* the connection: open or closed
          rx       \* the last frame received: how many so far, the frame, the reaction, whether a block was decoded

vars == <<st, how, highest, blk, ga, taken, up, rx>>

TypeOK ==
  /\ st \in [Ids -> States]
  /\ how \in [Ids -> Hows]
  /\ highest \in {0} \cup Ids
  /\ blk \in Blocks
  /\ ga \in 0..Top
  /\ taken \subseteq Ids
  /\ up \in {"open", "closed"}
  /\ rx \in [n : Nat, f : Frames, r : Reactions, dec : BOOLEAN]

-----------------------------------------------------------------------------
(* Reactions the RFC allows *)

Active == {i \in Ids : st[i] \in {"open", "hcl", "hcr"}}
Generic(c) == {c, "PROTOCOL_ERROR"}
OpenErr(cs) == {Rst(c) : c \in cs} \cup {Conn(c) : c \in cs}
StreamErr(i, cs) == IF st[i] = "idle" THEN {Conn(c) : c \in cs} ELSE OpenErr(cs)
\* Section 5.1, closed: frames on a stream the server reset must be
\* processed as connection state needs, then discarded.
MustDiscard(i) == st[i] = "closed" /\ how[i] = "sentRst"
\* Closed otherwise: a connection error STREAM_CLOSED is allowed, and so is
\* the minimal processing section 5.1 allows for all closed streams.
ClosedLax(i) == {Drop} \cup {Conn(c) : c \in Generic("STREAM_CLOSED")}

\* A header block on stream i, judged by the stream's state.
HeadersAllowed(i, es, big, self) ==
  CASE i \in Even -> {Conn("PROTOCOL_ERROR")}                 \* 5.1 idle, 5.1.1
    [] st[i] = "idle" ->
         IF i > ga THEN {Rst("REFUSED_STREAM")} \cup OpenErr({"PROTOCOL_ERROR"})  \* 6.8
         ELSE IF self THEN OpenErr({"PROTOCOL_ERROR"})        \* 5.3.1 of RFC 7540
         ELSE IF Cardinality(Active) >= MaxOpen
           THEN OpenErr({"REFUSED_STREAM", "PROTOCOL_ERROR"}) \* 5.1.2
         ELSE IF big
           THEN (IF es THEN {R431("-")}                       \* 10.5.1; 5.1: no frame on a closed stream
                       ELSE {R431("-"), R431("NO_ERROR"), R431("REFUSED_STREAM")})
                \cup {Rst("REFUSED_STREAM"), Conn("ENHANCE_YOUR_CALM")} \cup OpenErr({"PROTOCOL_ERROR"})  \* 10.5
         ELSE {Take, Rst("REFUSED_STREAM")}                   \* 8.7
    [] st[i] \in {"open", "hcl"} ->                            \* trailers
         IF self THEN OpenErr({"PROTOCOL_ERROR"})
         ELSE IF ~es THEN OpenErr({"PROTOCOL_ERROR"})         \* 8.1: trailers end the stream
         ELSE IF big THEN {Take, Conn("ENHANCE_YOUR_CALM")} \cup OpenErr({"PROTOCOL_ERROR", "REFUSED_STREAM"})
         ELSE {Take}
    [] st[i] = "hcr" -> OpenErr({"STREAM_CLOSED", "PROTOCOL_ERROR"})  \* 5.1 hcr
    [] MustDiscard(i) -> {Drop}
    [] how[i] = "skipped" -> {Conn("PROTOCOL_ERROR")}         \* 5.1.1
    [] OTHER -> ClosedLax(i) \cup {Rst("STREAM_CLOSED")}

\* A block that ends: one HPACK cannot decode is a connection error.
BlockDone(i, es, bad, big, self) ==
  IF bad THEN {Conn("COMPRESSION_ERROR")}
  ELSE HeadersAllowed(i, es, big, self) \cup (IF big THEN {Conn("ENHANCE_YOUR_CALM")} ELSE {})

\* The first frame of a block that CONTINUATION frames finish: the server
\* may wait for the end, or give an error the frame already shows.
Opening(i, es, big, self) ==
  {Wait} \cup {r \in HeadersAllowed(i, es, big, self) : r.k \in {"rst", "conn"}}

\* Section 10.5: a run of CONTINUATION may be judged suspicious. Where a
\* frame is two errors at once, section 5.4 lets the server report either.
Calm(f) == IF f.t = "CONT" THEN {Conn("ENHANCE_YOUR_CALM")} ELSE {}
\* A frame that is malformed as well as out of place may be reported for
\* either error (section 5.4).
Also(f) == IF f.v \in {"len", "self"} THEN {Conn(c) : c \in Codes} ELSE {}

PriorityBad(i, c) ==
  IF MustDiscard(i) THEN {Drop} \cup {Conn(x) : x \in Generic(c)}  \* 5.4.1: the frame is malformed wherever it is
  ELSE IF st[i] = "closed" THEN StreamErr(i, Generic(c)) \cup {Drop}
  ELSE StreamErr(i, Generic(c))

Allowed(f) ==
  IF blk.s # 0 THEN
    IF f.t = "CONT" /\ f.s = blk.s
    THEN IF f.eh
         THEN BlockDone(blk.s, blk.es, blk.bad \/ f.v = "bad", blk.big, blk.self)
              \cup {Conn("ENHANCE_YOUR_CALM")}
         ELSE {Wait, Conn("ENHANCE_YOUR_CALM")}
    ELSE {Conn("PROTOCOL_ERROR")} \cup Calm(f) \cup Also(f)       \* 4.3, 6.10
  ELSE CASE f.t = "CONT" -> {Conn("PROTOCOL_ERROR")} \cup Calm(f)  \* 6.10
    [] f.t = "PUSH" -> {Conn("PROTOCOL_ERROR")}               \* 8.4
    [] f.t = "HEADERS" ->
         IF f.eh THEN BlockDone(f.s, f.es, f.v = "bad", f.v = "big", f.v = "self")
         ELSE Opening(f.s, f.es, f.v = "big", f.v = "self")
    [] f.t = "PRIORITY" ->
         CASE f.v = "len" -> PriorityBad(f.s, "FRAME_SIZE_ERROR")  \* 6.3
           [] f.v = "self" -> PriorityBad(f.s, "PROTOCOL_ERROR")   \* 5.3.1 of RFC 7540
           [] OTHER -> {Drop}                                       \* 5.3.2, 6.3
    [] f.t \in {"DATA", "RST", "WU"} /\ (f.s \in Even \/ st[f.s] = "idle") ->
         {Conn("PROTOCOL_ERROR")}                             \* 5.1 idle, 6.4
    [] f.t = "DATA" ->
         CASE st[f.s] \in {"open", "hcl"} -> {Take}
           [] st[f.s] = "hcr" -> OpenErr({"STREAM_CLOSED", "PROTOCOL_ERROR"})
           [] MustDiscard(f.s) -> {Drop}
           [] OTHER -> ClosedLax(f.s) \cup {Rst("STREAM_CLOSED")}     \* 6.1
    [] f.t = "RST" ->
         IF st[f.s] = "closed"
         THEN IF how[f.s] \in {"sentRst", "ended"} THEN {Drop} ELSE ClosedLax(f.s)
         ELSE {Take}
    [] f.t = "WU" ->
         IF st[f.s] = "closed"
         THEN IF how[f.s] \in {"sentRst", "ended"} THEN {Drop} ELSE ClosedLax(f.s)
         ELSE {Take}
    [] f.t \in {"PINGACK", "GOAWAY"} -> {Drop, Drain}
    [] OTHER -> {Drop}                                        \* 5.5

\* Whether the frame ends a header block.
Completes(f) ==
  \/ blk.s # 0 /\ f.t = "CONT" /\ f.s = blk.s /\ f.eh
  \/ blk.s = 0 /\ f.t = "HEADERS" /\ f.eh

-----------------------------------------------------------------------------
(* What a received frame does to the streams *)

\* Stream i opens: every idle client stream below it closes (5.1.1).
Skip(i) ==
  [j \in Ids |-> IF j \in Odd /\ j < i /\ st[j] = "idle" THEN "closed" ELSE st[j]]
SkipHow(i) ==
  [j \in Ids |-> IF j \in Odd /\ j < i /\ st[j] = "idle" THEN "skipped" ELSE how[j]]

\* Stream i closes, unless it is closed already.
Close(i, why) ==
  /\ st' = [st EXCEPT ![i] = "closed"]
  /\ how' = IF st[i] = "closed" THEN how ELSE [how EXCEPT ![i] = why]

\* The END_STREAM flag a frame carries arrives on stream i.
Ending(i, es) ==
  CASE ~es -> UNCHANGED <<st, how>>
    [] st[i] = "open" -> st' = [st EXCEPT ![i] = "hcr"] /\ UNCHANGED how
    [] st[i] = "hcl" -> Close(i, "ended")
    [] OTHER -> UNCHANGED <<st, how>>

\* A header block on stream i ends with reaction r.
Headed(i, es, r) ==
  IF st[i] = "idle" /\ i \in Odd THEN
    /\ highest' = i
    /\ LET s1 == Skip(i)
           h1 == SkipHow(i)
       IN CASE r.k = "take" ->
                 /\ st' = [s1 EXCEPT ![i] = IF es THEN "hcr" ELSE "open"]
                 /\ how' = h1
                 /\ taken' = taken \cup {i}
            [] r.k = "rst" \/ (r.k = "r431" /\ r.c # "-") ->
                 /\ st' = [s1 EXCEPT ![i] = "closed"]
                 /\ how' = [h1 EXCEPT ![i] = "sentRst"]
                 /\ UNCHANGED taken
            [] r.k = "r431" ->
                 /\ st' = [s1 EXCEPT ![i] = IF es THEN "closed" ELSE "hcl"]
                 /\ how' = [h1 EXCEPT ![i] = IF es THEN "ended" ELSE "-"]
                 /\ UNCHANGED taken
            [] OTHER -> st' = s1 /\ how' = h1 /\ UNCHANGED taken
  ELSE
    /\ UNCHANGED <<highest, taken>>
    /\ CASE r.k = "take" -> Ending(i, es)
         [] r.k = "rst" -> Close(i, "sentRst")
         [] OTHER -> UNCHANGED <<st, how>>

\* The state a frame f with reaction r leaves; a connection error or a
\* drain also sends a GOAWAY that may not grow and must cover every stream
\* processed.
Effect(f, r) ==
  IF r.k \in {"conn", "drain"} THEN
    /\ \E g \in 0..ga : ga' = g
    /\ up' = IF r.k = "conn" THEN "closed" ELSE up
    /\ blk' = IF r.k = "conn" THEN NoBlock ELSE blk
    /\ UNCHANGED <<st, how, highest, taken>>
  ELSE
    /\ UNCHANGED <<ga, up>>
    /\ IF blk.s # 0 THEN
         /\ blk' = IF f.eh THEN NoBlock ELSE [blk EXCEPT !.bad = @ \/ f.v = "bad"]
         /\ IF f.eh THEN Headed(blk.s, blk.es, r)
            ELSE UNCHANGED <<st, how, highest, taken>>
       ELSE CASE f.t = "HEADERS" ->
                   /\ blk' = IF f.eh THEN NoBlock
                             ELSE [s |-> f.s, es |-> f.es, bad |-> f.v = "bad",
                                   big |-> f.v = "big", self |-> f.v = "self"]
                   /\ IF f.eh \/ r.k = "rst" THEN Headed(f.s, f.es, r)
                      ELSE UNCHANGED <<st, how, highest, taken>>
              [] f.t = "DATA" ->
                   /\ UNCHANGED <<blk, highest, taken>>
                   /\ CASE r.k = "take" -> Ending(f.s, f.es)
                        [] r.k = "rst" -> Close(f.s, "sentRst")
                        [] OTHER -> UNCHANGED <<st, how>>
              [] f.t = "RST" ->
                   /\ UNCHANGED <<blk, highest, taken>>
                   /\ IF r.k = "take" THEN Close(f.s, "recvRst")
                      ELSE UNCHANGED <<st, how>>
              [] OTHER ->
                   /\ UNCHANGED <<blk, highest, taken>>
                   /\ IF r.k = "rst" THEN Close(f.s, "sentRst")
                      ELSE UNCHANGED <<st, how>>

Receive(f, r, dec) ==
  /\ f \in Frames /\ r \in Reactions
  /\ (f.s = 0) = (f.t \in {"PINGACK", "GOAWAY"})
  /\ up = "open"
  /\ r \in Allowed(f)
  /\ Completes(f) /\ r.k # "conn" => dec
  /\ Effect(f, r)
  /\ rx' = [n |-> rx.n + 1, f |-> f, r |-> r, dec |-> dec]

-----------------------------------------------------------------------------
(* What the server does on its own *)

\* Its response ends with END_STREAM, then, if the request is still open,
\* a reset (section 8.1 suggests NO_ERROR).
Finish(i, reset) ==
  /\ up = "open"
  /\ st[i] \in {"open", "hcr"}
  /\ IF st[i] = "hcr" THEN Close(i, "ended")
     ELSE IF reset THEN Close(i, "sentRst")
     ELSE st' = [st EXCEPT ![i] = "hcl"] /\ UNCHANGED how
  /\ UNCHANGED <<highest, blk, ga, taken, up>>
  /\ UNCHANGED rx

\* It resets a stream for a cause of its own.
Reset(i) ==
  /\ up = "open"
  /\ st[i] \in {"open", "hcl", "hcr"}
  /\ Close(i, "sentRst")
  /\ UNCHANGED <<highest, blk, ga, taken, up>>
  /\ UNCHANGED rx

\* GOAWAY: its last stream never grows (6.8).
Goaway(g) ==
  /\ up = "open"
  /\ g <= ga
  /\ ga' = g
  /\ UNCHANGED <<st, how, highest, blk, taken, up>>
  /\ UNCHANGED rx

\* The connection ends (an endpoint can end a connection at any time).
End ==
  /\ up = "open"
  /\ up' = "closed"
  /\ blk' = NoBlock
  /\ UNCHANGED <<st, how, highest, ga, taken>>
  /\ UNCHANGED rx

Init ==
  /\ st = [i \in Ids |-> IF H2c /\ i = 1 THEN "hcr" ELSE "idle"]
  /\ how = [i \in Ids |-> "-"]
  /\ highest = IF H2c THEN 1 ELSE 0
  /\ blk = NoBlock
  /\ ga = Top
  /\ taken = IF H2c THEN {1} ELSE {}
  /\ up = "open"
  /\ rx = [n |-> 0, f |-> NoFrame, r |-> Drop, dec |-> FALSE]

\* A receiving step names its frame, reaction and decoding in rx', so the
\* step is `Receive(rx'.f, rx'.r, rx'.dec)`: the same as
\* `\E f \in Frames, r \in Reactions, dec \in BOOLEAN : Receive(f, r, dec)`,
\* without TLC trying every frame when it checks a step against `Next`.
Next ==
  \/ rx'.n # rx.n /\ Receive(rx'.f, rx'.r, rx'.dec)
  \/ \E i \in Ids, reset \in BOOLEAN : Finish(i, reset)
  \/ \E i \in Ids : Reset(i)
  \/ \E g \in 0..Top : Goaway(g)
  \/ End

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* The rules one at a time. Each is an action: in a step that receives a  *)
(* frame (rx'.n moves), the frame rx'.f must get a reaction rx'.r the     *)
(* rule allows, judged in the state before the step. The implementation   *)
(* models check each as a property, and all of them together as `Next`.   *)

F == rx'.f
R == rx'.r
Got == rx'.n # rx.n
NoBlockOpen == blk.s = 0
\* The block the frame ends, when it ends one: its stream, END_STREAM, and
\* what is wrong with it.
BS == IF NoBlockOpen THEN F.s ELSE blk.s
BEs == IF NoBlockOpen THEN F.es ELSE blk.es
BBig == IF NoBlockOpen THEN F.v = "big" ELSE blk.big
BSelf == IF NoBlockOpen THEN F.v = "self" ELSE blk.self
BBad == IF NoBlockOpen THEN F.v = "bad" ELSE blk.bad \/ F.v = "bad"
Done == Got /\ Completes(F)

\* 5.1 idle, 6.4: DATA, RST_STREAM and WINDOW_UPDATE on an idle stream.
IdleFrames ==
  Got /\ NoBlockOpen /\ F.t \in {"DATA", "RST", "WU"} /\ (F.s \in Even \/ st[F.s] = "idle")
    => R = Conn("PROTOCOL_ERROR")
\* 5.1, 5.1.1: a client opens only odd streams.
EvenHeaders ==
  Done /\ BS \in Even
    => R \in {Conn("PROTOCOL_ERROR"), Conn("COMPRESSION_ERROR"), Conn("ENHANCE_YOUR_CALM")}
\* 5.1.1: a new stream's identifier is above every stream opened; a lower
\* identifier the client skipped is a connection error.
LowerIdHeaders ==
  Done /\ st[BS] = "closed" /\ how[BS] = "skipped" => R.k = "conn"
\* 5.1, half closed (remote): DATA or HEADERS is a stream error STREAM_CLOSED.
HalfClosedRemote ==
  \/ Got /\ NoBlockOpen /\ F.t = "DATA" /\ F.s \in Odd /\ st[F.s] = "hcr"
  \/ Done /\ BS \in Odd /\ st[BS] = "hcr"
  => R \in OpenErr({"STREAM_CLOSED", "PROTOCOL_ERROR"})
           \cup {Conn("COMPRESSION_ERROR"), Conn("ENHANCE_YOUR_CALM")}
\* 5.1, closed: a frame on a stream the server reset is discarded. Only a
\* frame that is an error of its own may end the connection: one inside
\* another stream's block, a CONTINUATION with no block, a malformed one,
\* a push, a block HPACK cannot decode or one over the header list limit,
\* or a CONTINUATION run judged suspicious.
Clean ==
  /\ F.v = "ok" /\ F.t # "PUSH"
  /\ (NoBlockOpen /\ F.t # "CONT") \/ (F.t = "CONT" /\ F.s = blk.s /\ ~blk.bad /\ ~blk.big)
ServerResetDiscarded ==
  Got /\ F.s \in Odd /\ MustDiscard(F.s) /\ Clean
      /\ ~(F.t = "CONT" /\ R = Conn("ENHANCE_YOUR_CALM"))
    => R \in {Drop, Wait}
\* 5.1, closed: WINDOW_UPDATE and RST_STREAM after the server ended or
\* reset the stream are expected; they are no error.
ClosedAfterEnd ==
  Got /\ NoBlockOpen /\ F.t \in {"WU", "RST"} /\ F.s \in Odd /\ st[F.s] = "closed"
      /\ how[F.s] \in {"sentRst", "ended"}
    => R = Drop
\* 6.1: DATA on a stream neither open nor half closed (local).
ClosedData ==
  Got /\ NoBlockOpen /\ F.t = "DATA" /\ F.s \in Odd /\ st[F.s] = "closed"
    => R \in ClosedLax(F.s) \cup {Rst("STREAM_CLOSED")}
\* 5.1.2: a stream past SETTINGS_MAX_CONCURRENT_STREAMS is refused.
Concurrency ==
  Done /\ BS \in Odd /\ st[BS] = "idle" /\ Cardinality(Active) >= MaxOpen
    => R.k \in {"rst", "conn"}
\* 5.4.2: never answer RST_STREAM with RST_STREAM.
NoRstForRst ==
  Got /\ F.t = "RST" => R.k # "rst"
\* 6.8: a stream above the last stream of a GOAWAY sent is not processed.
GoawayRefuses ==
  Done /\ BS \in Odd /\ st[BS] = "idle" /\ BS > ga => R.k # "take"
\* 6.8: the last stream of a GOAWAY never grows, and covers every stream
\* processed.
GoawayNeverGrows == ga' <= ga
GoawayCovers ==
  (Got /\ R.k \in {"conn", "drain"}) \/ ga' # ga => \A i \in taken' : i <= ga'
\* 4.3, 6.10: nothing but CONTINUATION on the same stream inside a block.
Interleave ==
  Got /\ ~NoBlockOpen /\ ~(F.t = "CONT" /\ F.s = blk.s)
    => R \in {Conn("PROTOCOL_ERROR")} \cup Calm(F) \cup Also(F)
\* 6.10: CONTINUATION must follow a block that has not ended.
ContWithoutBlock ==
  Got /\ NoBlockOpen /\ F.t = "CONT" => R \in {Conn("PROTOCOL_ERROR")} \cup Calm(F)
\* 4.3: a block HPACK cannot decode is a connection error COMPRESSION_ERROR.
Compression ==
  Done /\ BBad => R \in {Conn("COMPRESSION_ERROR"), Conn("ENHANCE_YOUR_CALM")}
\* 4.3, 10.5.1: every block is decoded, even one discarded, unless the
\* connection ends.
BlocksDecoded ==
  Done /\ R.k # "conn" => rx'.dec
\* 10.5.1: a header list over the limit gets a 431 or a reset; after a 431
\* that ends a request that ended, nothing more goes on the closed stream.
HeaderListSize ==
  Done /\ BS \in Odd /\ st[BS] = "idle" /\ BBig /\ ~BSelf /\ ~BBad /\ BS <= ga
       /\ Cardinality(Active) < MaxOpen
    => /\ R.k # "take"
       /\ R.k = "r431" /\ BEs => R.c = "-"
\* 5.3.2, 6.3: a well-formed PRIORITY is allowed in every state and changes
\* nothing.
PriorityAnyState ==
  Got /\ NoBlockOpen /\ F.t = "PRIORITY" /\ F.v = "ok" => R = Drop
\* 6.3: PRIORITY of the wrong length is a stream error FRAME_SIZE_ERROR; one
\* that depends on its own stream, PROTOCOL_ERROR.
PriorityMalformed ==
  Got /\ NoBlockOpen /\ F.t = "PRIORITY" /\ F.v \in {"len", "self"}
    => R \in PriorityBad(F.s, IF F.v = "len" THEN "FRAME_SIZE_ERROR" ELSE "PROTOCOL_ERROR")
\* 5.3.1 of RFC 7540: HEADERS whose priority names its own stream is a stream
\* error PROTOCOL_ERROR.
SelfDependentHeaders ==
  Got /\ NoBlockOpen /\ F.t = "HEADERS" /\ F.v = "self" /\ F.eh /\ F.s \in Odd
      /\ st[F.s] \in {"idle", "open", "hcl"}
    => R.k \in {"rst", "conn"}
\* 8.4: a client cannot push.
PushRefused ==
  Got /\ F.t = "PUSH" => R = Conn("PROTOCOL_ERROR")
\* 8.1: trailers end the stream.
TrailersEnd ==
  Done /\ BS \in Odd /\ st[BS] \in {"open", "hcl"} /\ ~BEs => R.k \in {"rst", "conn"}


\* Every rule at once, as one step.
Rules ==
  /\ IdleFrames /\ EvenHeaders /\ LowerIdHeaders /\ HalfClosedRemote
  /\ ServerResetDiscarded /\ ClosedAfterEnd /\ ClosedData /\ Concurrency
  /\ NoRstForRst /\ GoawayRefuses /\ GoawayNeverGrows /\ Interleave
  /\ ContWithoutBlock /\ Compression /\ BlocksDecoded /\ HeaderListSize
  /\ PriorityAnyState /\ PriorityMalformed /\ SelfDependentHeaders
  /\ PushRefused /\ TrailersEnd

=============================================================================
