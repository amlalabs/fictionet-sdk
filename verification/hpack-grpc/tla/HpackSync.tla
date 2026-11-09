---------------------------- MODULE HpackSync ----------------------------
(***************************************************************************)
(* One direction of HPACK on an HTTP/2 connection: an encoder writing     *)
(* header blocks, the decoder reading them, and the SETTINGS_HEADER_TABLE *)
(* _SIZE changes the decoding endpoint announces, which the encoder        *)
(* applies when it receives them and acknowledges later.                  *)
(*                                                                         *)
(* Source, at the commit named in verification/hpack-grpc/README.md:      *)
(*   src/stdlib/protocols/hpack.rs                                         *)
(*     DynamicTable::insert, ::evict          lines 476-493                *)
(*     DynamicTable::get, ::name              lines 435-473                *)
(*     Representations::read                  lines 361-401 (update order) *)
(*     Table::new, ::set_settings_limit       lines 574-591                *)
(*     Table::decode_block, ::read_block      lines 617-685                *)
(*     Encoder::new, ::set_settings_limit,                                 *)
(*       ::set_capacity, ::resize             lines 705-748                *)
(*     Encoder::write_block                   lines 781-837                *)
(*   src/stdlib/protocols/http2.rs (Session, the decoding endpoint)        *)
(*     Session::new: table_limit 4096, Table::new(4096)                    *)
(*     apply_peer: table_min, raise at once   lines 1542-1584              *)
(*     acknowledge_settings                   lines 1613-1634              *)
(*   src/stdlib/web/httpd/http2.rs, peer_setting: the server's encoder     *)
(*     applies each SETTINGS entry in order when it arrives (line 835),    *)
(*     and on_frame queues the ACK right after (lines 897-911).            *)
(*                                                                         *)
(* Sizes are scaled: Initial stands for 4096, MaxTable for MAX_TABLE, and *)
(* an entry costs its name and value lengths (0 or 1 here) plus 1 for the *)
(* 32 octets of ENTRY_OVERHEAD. The static table is one entry, s: "".     *)
(* Frames between the two sides keep their order (one TCP stream each     *)
(* way). With ImmediateAck, as in the server, the ACK goes out as the     *)
(* SETTINGS are applied, before any later block; without it, the encoder  *)
(* may write blocks in between.                                           *)
(*                                                                         *)
(* With Adversary FALSE the blocks come from the Encoder; with Adversary  *)
(* TRUE from any encoder, as a block of up to two arbitrary                *)
(* representations, and only the decoder's own guarantees are checked.    *)
(*                                                                         *)
(* Each flag below is TRUE in the code; a *_without_<flag>.cfg sets one   *)
(* FALSE and must violate the invariant its first comment line names.     *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Initial,          \* the table size both sides start with (4096)
    MaxTable,         \* MAX_TABLE: every settings limit is capped here
    SettingsVals,     \* values a SETTINGS_HEADER_TABLE_SIZE entry may carry
    MaxBlocks,        \* header blocks sent in one run
    MaxSettings,      \* SETTINGS frames sent in one run
    MaxCaps,          \* Encoder::set_capacity calls in one run
    Adversary,
    ImmediateAck,     \* the encoder acknowledges SETTINGS as it applies them
    MinPending,       \* resize: pending_min keeps the smallest capacity
    SecondUpdate,     \* write_block: the final capacity follows the minimum
    EncEvict,         \* write_block: evict after inserting
    ResizeOnLower,    \* Encoder::set_settings_limit shrinks a larger table
    RaiseOnSend,      \* apply_peer: an increase applies at once
    MinOnAck,         \* acknowledge_settings: the frame's minimum first
    CheckSettings,    \* read_block: an update above the settings is refused
    RequireReduction, \* read_block: a reduction owed must come first
    UpdatesFirst      \* Representations: no update after a field

None == -1
Big == MaxTable + 100

Len01(x) == IF x = "" THEN 0 ELSE 1
Size(e) == Len01(e.name) + Len01(e.value) + 1
RECURSIVE Sum(_)
Sum(t) == IF t = <<>> THEN 0 ELSE Size(Head(t)) + Sum(Tail(t))
Min2(a, b) == IF a < b THEN a ELSE b
Max2(a, b) == IF a > b THEN a ELSE b
SetMin(S) == CHOOSE x \in S : \A y \in S : x <= y
SetMax(S) == CHOOSE x \in S : \A y \in S : x >= y
Cap(l) == Min2(l, MaxTable)

Static == << [name |-> "s", value |-> ""] >>
Entries(t) == Static \o t

\* DynamicTable::evict: the oldest entries leave until the rest fit.
RECURSIVE Evict(_, _)
Evict(t, c) == IF Sum(t) <= c THEN t ELSE Evict(SubSeq(t, 1, Len(t) - 1), c)

\* Blocks of one field, any of eight, or of two fields that are not never
\* indexed (two fields let a block evict, or name, what it inserted itself).
Fields == [name : {"s", "a"}, value : {"", "v"}, never : BOOLEAN]
Indexed == {f \in Fields : ~f.never}
Blocks == {<<f>> : f \in Fields} \cup {<<f, g>> : f, g \in Indexed}

\* One representation. n is the size of an update, the index of an
\* indexed field, or the name index of a literal (0: the name is carried).
Rep(k, n, nm, v, ix) ==
    [kind |-> k, n |-> n, name |-> nm, value |-> v, indexing |-> ix]
Upd(s) == Rep("update", s, "", "", "none")
Idx(i) == Rep("indexed", i, "", "", "none")
Lit(i, nm, v, ix) == Rep("literal", i, IF i = 0 THEN nm ELSE "", v, ix)

AdvReps == {Upd(s) : s \in 0..(MaxTable + 1)} \cup {Idx(i) : i \in 1..3}
           \cup {Lit(0, "a", "v", ix) : ix \in {"inc", "without"}}
           \cup {Lit(1, "", "v", "inc")}
AdvBlocks == {<<r>> : r \in AdvReps} \cup {<<r, q>> : r, q \in AdvReps}

-----------------------------------------------------------------------------
(* The Encoder.                                                            *)

\* Encoder::resize
Resize(e, c) ==
    [e EXCEPT !.pending = IF ~MinPending \/ e.pending = None THEN c
                          ELSE Min2(e.pending, c),
              !.max = c,
              !.table = Evict(e.table, c)]

\* Encoder::set_settings_limit
EncLimit(e, l) ==
    LET e1 == [e EXCEPT !.settings = Cap(l)]
    IN IF ResizeOnLower /\ e1.max > Cap(l) THEN Resize(e1, Cap(l)) ELSE e1

RECURSIVE EncLimits(_, _)
EncLimits(e, vals) ==
    IF vals = <<>> THEN e ELSE EncLimits(EncLimit(e, Head(vals)), Tail(vals))

FirstOf(t, P(_)) ==
    LET E == Entries(t)
        S == {i \in 1..Len(E) : P(E[i])}
    IN IF S = {} THEN 0 ELSE SetMin(S)

\* One field of write_block: the first exact match (not for a never-indexed
\* field), else a literal naming the first entry with the name.
EncField(e, f) ==
    LET exact == FirstOf(e.table, LAMBDA x : x.name = f.name /\ x.value = f.value)
        named == FirstOf(e.table, LAMBDA x : x.name = f.name)
    IN IF exact # 0 /\ ~f.never
       THEN [rep |-> Idx(exact), enc |-> e]
       ELSE LET ix == IF f.never THEN "never"
                      ELSE IF e.max = 0 THEN "without" ELSE "inc"
                ins == ~f.never /\ e.max # 0
                t1 == IF ins THEN <<[name |-> f.name, value |-> f.value]>> \o e.table
                      ELSE e.table
                t2 == IF ins /\ EncEvict THEN Evict(t1, e.max) ELSE t1
            IN [rep |-> Lit(named, f.name, f.value, ix),
                enc |-> [e EXCEPT !.table = t2]]

RECURSIVE EncFields(_, _, _)
EncFields(e, fs, reps) ==
    IF fs = <<>> THEN [reps |-> reps, enc |-> e]
    ELSE LET r == EncField(e, Head(fs))
         IN EncFields(r.enc, Tail(fs), Append(reps, r.rep))

\* write_block: the pending minimum, then the capacity if it differs.
EncBlock(e, fs) ==
    LET prefix == IF e.pending = None THEN <<>>
                  ELSE IF SecondUpdate /\ e.max # e.pending
                       THEN <<Upd(e.pending), Upd(e.max)>>
                       ELSE <<Upd(e.pending)>>
    IN EncFields([e EXCEPT !.pending = None], fs, prefix)

-----------------------------------------------------------------------------
(* The decoder.                                                            *)

\* Table::set_settings_limit
DecLimit(d, l) ==
    [d EXCEPT !.settings = Cap(l),
              !.required = IF Cap(l) < d.max
                           THEN IF d.required = None THEN Cap(l)
                                ELSE Min2(d.required, Cap(l))
                           ELSE d.required]

InRange(t, i) == i >= 1 /\ i <= Len(Static) + Len(t)

Fail(st) == [st EXCEPT !.ok = FALSE]

\* One representation of read_block. lowest is a ghost: the least table
\* maximum from the block's start to its first field.
DecRep(st, r) ==
    IF ~st.ok THEN st
    ELSE IF r.kind = "update" THEN
        IF UpdatesFirst /\ st.started THEN Fail(st)
        ELSE IF st.updates = 2 \/ (st.updates = 1 /\ r.n < st.previous) THEN Fail(st)
        ELSE IF CheckSettings /\ r.n > st.dec.settings THEN Fail(st)
        ELSE IF RequireReduction /\ st.dec.required # None /\ r.n > st.dec.required
             THEN Fail(st)
        ELSE [st EXCEPT !.dec = [st.dec EXCEPT !.required = None, !.max = r.n,
                                               !.table = Evict(st.dec.table, r.n)],
                        !.updates = st.updates + 1,
                        !.previous = r.n,
                        !.lowest = IF st.started THEN st.lowest ELSE Min2(st.lowest, r.n),
                        !.order = (st.order /\ ~st.started)]
    ELSE IF RequireReduction /\ st.dec.required # None THEN Fail(st)
    ELSE IF r.kind = "indexed" THEN
        IF ~InRange(st.dec.table, r.n) THEN Fail(st)
        ELSE LET x == Entries(st.dec.table)[r.n]
             IN [st EXCEPT !.started = TRUE,
                           !.fields = Append(st.fields,
                               [name |-> x.name, value |-> x.value, never |-> FALSE])]
    ELSE IF r.n # 0 /\ ~InRange(st.dec.table, r.n) THEN Fail(st)
    ELSE LET nm == IF r.n = 0 THEN r.name ELSE Entries(st.dec.table)[r.n].name
             t1 == IF r.indexing = "inc"
                   THEN Evict(<<[name |-> nm, value |-> r.value]>> \o st.dec.table,
                              st.dec.max)
                   ELSE st.dec.table
         IN [st EXCEPT !.started = TRUE,
                       !.fields = Append(st.fields,
                           [name |-> nm, value |-> r.value, never |-> r.indexing = "never"]),
                       !.dec = [st.dec EXCEPT !.table = t1]]

RECURSIVE DecReps(_, _)
DecReps(st, reps) ==
    IF reps = <<>> THEN st ELSE DecReps(DecRep(st, Head(reps)), Tail(reps))

\* decode_block: the end of the block, then a failure clears the table.
DecBlock(d, reps) ==
    LET st0 == [dec |-> d, ok |-> TRUE, updates |-> 0, previous |-> 0,
                started |-> FALSE, fields |-> <<>>, lowest |-> d.max, order |-> TRUE]
        st1 == DecReps(st0, reps)
        st2 == IF RequireReduction /\ st1.ok /\ st1.dec.required # None
               THEN Fail(st1) ELSE st1
    IN IF st2.ok THEN st2
       ELSE [st2 EXCEPT !.dec = [st2.dec EXCEPT !.table = <<>>]]

-----------------------------------------------------------------------------

VARIABLES
    enc,        \* [table, max, settings, pending]
    dec,        \* [table, max, settings, required]
    tableLimit, \* Session::table_limit
    peerSize,   \* Session::peer.header_table_size
    pend,       \* Session::settings_updates: [min, final] per SETTINGS
    toEnc,      \* SETTINGS frames on their way to the encoder
    acksOwed,   \* SETTINGS the encoder applied and has not acknowledged
    toDec,      \* blocks and ACKs on their way to the decoder
    ackedMin,   \* ghost: least limit acknowledged since the last block
    sent,       \* [blocks, settings, caps] counts
    failed,     \* a block failed to decode
    roundTrip,  \* every decoded block gave back the fields encoded
    inStep,     \* every decoded block left the decoder's table as the encoder's
    reduced,    \* every accepted block shrank to the least acknowledged limit
    ordered     \* every accepted block had its updates first

vars == <<enc, dec, tableLimit, peerSize, pend, toEnc, acksOwed, toDec,
          ackedMin, sent, failed, roundTrip, inStep, reduced, ordered>>

Msg(k, reps, fs, t, m) == [kind |-> k, reps |-> reps, fields |-> fs, table |-> t, max |-> m]

Init ==
    \* Encoder::new(4096) and Session::new.
    /\ enc = [table |-> <<>>, max |-> Initial, settings |-> Initial, pending |-> None]
    /\ dec = [table |-> <<>>, max |-> Initial, settings |-> Initial, required |-> None]
    /\ tableLimit = Initial
    /\ peerSize = Initial
    /\ pend = <<>>
    /\ toEnc = <<>>
    /\ acksOwed = 0
    /\ toDec = <<>>
    /\ ackedMin = Big
    /\ sent = [blocks |-> 0, settings |-> 0, caps |-> 0]
    /\ failed = FALSE
    /\ roundTrip = TRUE
    /\ inStep = TRUE
    /\ reduced = TRUE
    /\ ordered = TRUE

Frames == {<<v>> : v \in SettingsVals} \cup {<<v, w>> : v, w \in SettingsVals}

\* The decoding endpoint sends SETTINGS: Session::apply_peer.
SendSettings(vals) ==
    /\ sent.settings < MaxSettings
    /\ LET final == vals[Len(vals)]
           least == SetMin({vals[i] : i \in 1..Len(vals)})
       IN /\ peerSize' = final
          /\ IF RaiseOnSend /\ final > tableLimit
             THEN tableLimit' = final /\ dec' = DecLimit(dec, final)
             ELSE UNCHANGED <<tableLimit, dec>>
          /\ pend' = Append(pend, [min |-> least, final |-> final])
    /\ toEnc' = Append(toEnc, vals)
    /\ sent' = [sent EXCEPT !.settings = @ + 1]
    /\ UNCHANGED <<enc, acksOwed, toDec, ackedMin, failed, roundTrip, inStep,
                   reduced, ordered>>

\* The encoder receives SETTINGS and applies each entry in order.
EncReceive ==
    /\ toEnc # <<>>
    /\ enc' = EncLimits(enc, Head(toEnc))
    /\ toEnc' = Tail(toEnc)
    /\ IF ImmediateAck
       THEN /\ toDec' = Append(toDec, Msg("ack", <<>>, <<>>, <<>>, 0))
            /\ UNCHANGED acksOwed
       ELSE /\ acksOwed' = acksOwed + 1
            /\ UNCHANGED toDec
    /\ UNCHANGED <<dec, tableLimit, peerSize, pend, ackedMin, sent, failed,
                   roundTrip, inStep, reduced, ordered>>

EncAck ==
    /\ ~ImmediateAck
    /\ acksOwed > 0
    /\ acksOwed' = acksOwed - 1
    /\ toDec' = Append(toDec, Msg("ack", <<>>, <<>>, <<>>, 0))
    /\ UNCHANGED <<enc, dec, tableLimit, peerSize, pend, toEnc, ackedMin, sent,
                   failed, roundTrip, inStep, reduced, ordered>>

\* Encoder::set_capacity, within the settings it has.
EncCapacity(c) ==
    /\ ~Adversary
    /\ sent.caps < MaxCaps
    /\ c <= enc.settings /\ c <= MaxTable
    /\ enc' = Resize(enc, c)
    /\ sent' = [sent EXCEPT !.caps = @ + 1]
    /\ UNCHANGED <<dec, tableLimit, peerSize, pend, toEnc, acksOwed, toDec, ackedMin,
                   failed, roundTrip, inStep, reduced, ordered>>

EncSend(fs) ==
    /\ ~Adversary
    /\ sent.blocks < MaxBlocks
    /\ LET r == EncBlock(enc, fs)
       IN /\ enc' = r.enc
          /\ toDec' = Append(toDec, Msg("block", r.reps, fs, r.enc.table, r.enc.max))
    /\ sent' = [sent EXCEPT !.blocks = @ + 1]
    /\ UNCHANGED <<dec, tableLimit, peerSize, pend, toEnc, acksOwed, ackedMin,
                   failed, roundTrip, inStep, reduced, ordered>>

AdvSend(reps) ==
    /\ Adversary
    /\ sent.blocks < MaxBlocks
    /\ toDec' = Append(toDec, Msg("block", reps, <<>>, <<>>, 0))
    /\ sent' = [sent EXCEPT !.blocks = @ + 1]
    /\ UNCHANGED <<enc, dec, tableLimit, peerSize, pend, toEnc, acksOwed, ackedMin,
                   failed, roundTrip, inStep, reduced, ordered>>

\* The decoding endpoint reads its peer's ACK: Session::acknowledge_settings.
DecAck ==
    /\ toDec # <<>> /\ Head(toDec).kind = "ack"
    /\ pend # <<>>
    /\ LET u == Head(pend)
           rest == Tail(pend)
           d1 == IF MinOnAck THEN DecLimit(dec, u.min) ELSE dec
           tl == SetMax({u.final} \cup {rest[i].final : i \in 1..Len(rest)})
       IN /\ dec' = DecLimit(d1, tl)
          /\ tableLimit' = tl
          /\ pend' = rest
          /\ ackedMin' = Min2(ackedMin, Cap(u.min))
    /\ toDec' = Tail(toDec)
    /\ UNCHANGED <<enc, peerSize, toEnc, acksOwed, sent, failed, roundTrip, inStep,
                   reduced, ordered>>

DecRead ==
    /\ toDec # <<>> /\ Head(toDec).kind = "block"
    /\ ~failed
    /\ LET m == Head(toDec)
           st == DecBlock(dec, m.reps)
       IN /\ dec' = st.dec
          /\ failed' = ~st.ok
          /\ roundTrip' = (roundTrip /\ (Adversary \/ (st.ok /\ st.fields = m.fields)))
          /\ inStep' = (inStep /\ (Adversary \/ (st.dec.table = m.table /\ st.dec.max = m.max)))
          /\ reduced' = (reduced /\ (~st.ok \/ st.lowest <= ackedMin))
          /\ ordered' = (ordered /\ (~st.ok \/ st.order))
    /\ ackedMin' = Big
    /\ toDec' = Tail(toDec)
    /\ UNCHANGED <<enc, tableLimit, peerSize, pend, toEnc, acksOwed, sent>>

Next ==
    \/ \E vals \in Frames : SendSettings(vals)
    \/ EncReceive
    \/ EncAck
    \/ \E c \in 0..MaxTable : EncCapacity(c)
    \/ \E fs \in Blocks : EncSend(fs)
    \/ \E reps \in AdvBlocks : AdvSend(reps)
    \/ DecAck
    \/ DecRead

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                             *)

\* Every block from the Encoder decodes without error ...
NoError == failed = FALSE
\* ... to exactly the fields encoded, never-indexed flags included ...
RoundTrip == roundTrip
\* ... and leaves the decoder's table and maximum as the encoder's were.
InStep == inStep
\* The tables fit their maxima, and the encoder's maximum its settings.
WithinMax ==
    /\ Sum(enc.table) <= enc.max
    /\ enc.max <= enc.settings
    /\ Sum(dec.table) <= dec.max
\* With no reduction owed, the decoder's maximum is within its settings.
Settled == dec.required = None => dec.max <= dec.settings
\* Every accepted block brought the table down to the least limit
\* acknowledged since the block before, before its first field.
Reduced == reduced
\* Every accepted block had its size updates before its fields.
Ordered == ordered
=============================================================================
