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
(*       ::set_capacity, ::resize             lines 705-752                *)
(*     Encoder::write_block                   lines 785-841                *)
(*   src/stdlib/protocols/http2.rs (Session, the decoding endpoint)        *)
(*     Session::new: table_limit 4096 (line 1369); HeaderBlocks::          *)
(*       with_limits: Table::new(4096) (line 1158)                         *)
(*     apply_peer: table_min, raise at once   lines 1542-1585              *)
(*     acknowledge_settings                   lines 1613-1634              *)
(*   src/stdlib/web/httpd/http2.rs, the server's encoder:                  *)
(*     Http2::new builds it as Encoder::new(0) (line 221), so its table    *)
(*     stays at capacity 0 and its first block carries a size update of   *)
(*     0 (header_block, lines 1169-1172); nothing in the server calls     *)
(*     set_capacity. peer_setting applies each SETTINGS entry in order     *)
(*     when it arrives (line 835), and on_frame queues the ACK right      *)
(*     after (lines 897-911) on the one FIFO every frame takes (queue,    *)
(*     lines 357-375), so no block encoded after the values is written    *)
(*     before the ACK.                                                     *)
(*                                                                         *)
(* Sizes are scaled: Initial stands for 4096, MaxTable for MAX_TABLE, and *)
(* an entry costs its name and value lengths (0 or 1 here) plus 1 for the *)
(* 32 octets of ENTRY_OVERHEAD. The static table is one entry, s: "".     *)
(* EncoderInit is the settings limit Encoder::new is given: Initial for   *)
(* the Encoder at its default (Encoder::new(4096), as the tests and the   *)
(* other users build it), 0 for the server's. Frames between the two      *)
(* sides keep their order (one TCP stream each way). With ImmediateAck,   *)
(* as in the server, the ACK goes out as the SETTINGS are applied, before *)
(* any later block; without it, the encoder may write blocks in between.  *)
(*                                                                         *)
(* With Adversary FALSE the blocks come from the Encoder; with Adversary  *)
(* TRUE from any encoder, as a block of up to two arbitrary                *)
(* representations, and only the decoder's own guarantees are checked.    *)
(*                                                                         *)
(* Each flag below is TRUE in the code; a *_without_<flag>.cfg sets one   *)
(* FALSE and must violate the invariant its first comment line names.     *)
(*                                                                         *)
(* Resources (verification/resources/tla/Resources.tla). Each table's     *)
(* storage is a store threaded through every eviction and insertion in    *)
(* the code's order, so a transient inside a step shows. One unit is an   *)
(* entry's size, as above; the entry slots, which DynamicTable::most_held *)
(* adds, are the Kani harnesses' (kani/resources.rs). The decoder's       *)
(* reservation is Table::most_held: the larger of its settings limit and  *)
(* its maximum, raised when either rises (the server charges it when the  *)
(* connection opens, Input::open in web/httpd/http2.rs, and never raises  *)
(* its own limit). The encoder's is Encoder::most_held, its capacity.     *)
(*   Table::index                            hpack.rs, after read_block   *)
(*   Encoder::write_block                    the insertion at its end     *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, Resources

CONSTANTS
    Initial,          \* the table size both sides start with (4096)
    EncoderInit,      \* the settings limit Encoder::new is given
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
    UpdatesFirst,     \* Representations: no update after a field
    EvictFirst,       \* Table::index: evict to make room, then insert
    EncEvictFirst     \* write_block: evict to make room, then insert

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

\* Entry e added with incremental indexing to table t at capacity c, its
\* storage s threaded through: [table, store]. With evictFirst (both ends
\* now) an entry larger than c empties the table and is not added, and
\* otherwise the oldest entries leave until it fits, then it goes in.
\* Without it, it goes in first and the table is evicted after. The table
\* that results is the same; only the storage on the way differs.
AddEntry(t, s, e, c, evictFirst) ==
    IF evictFirst
    THEN IF Size(e) > c
         THEN [table |-> <<>>, store |-> SetHeld(s, 0)]
         ELSE LET kept == Evict(t, c - Size(e))
              IN [table |-> <<e>> \o kept,
                  store |-> Grow(SetHeld(s, Sum(kept)), Size(e))]
    ELSE LET t1 == Evict(<<e>> \o t, c)
         IN [table |-> t1, store |-> SetHeld(Grow(s, Size(e)), Sum(t1))]

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

\* Encoder::resize; a capacity that rises raises the charge.
Resize(e, c) ==
    [e EXCEPT !.pending = IF ~MinPending \/ e.pending = None THEN c
                          ELSE Min2(e.pending, c),
              !.max = c,
              !.table = Evict(e.table, c),
              !.store = ReserveTo(SetHeld(e.store, Sum(Evict(e.table, c))), c)]

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
                new == [name |-> f.name, value |-> f.value]
                added == IF ins /\ EncEvict
                         THEN AddEntry(e.table, e.store, new, e.max, EncEvictFirst)
                         ELSE IF ins
                         THEN [table |-> <<new>> \o e.table,
                               store |-> Grow(e.store, Size(new))]
                         ELSE [table |-> e.table, store |-> e.store]
            IN [rep |-> Lit(named, f.name, f.value, ix),
                enc |-> [e EXCEPT !.table = added.table, !.store = added.store]]

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

\* Table::set_settings_limit; a limit that rises raises the charge.
DecLimit(d, l) ==
    [d EXCEPT !.settings = Cap(l),
              !.store = ReserveTo(d.store, Max2(Cap(l), d.max)),
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
                                               !.table = Evict(st.dec.table, r.n),
                                               !.store = SetHeld(st.dec.store,
                                                   Sum(Evict(st.dec.table, r.n)))],
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
             added == IF r.indexing = "inc"
                      THEN AddEntry(st.dec.table, st.dec.store,
                                    [name |-> nm, value |-> r.value], st.dec.max, EvictFirst)
                      ELSE [table |-> st.dec.table, store |-> st.dec.store]
         IN [st EXCEPT !.started = TRUE,
                       !.fields = Append(st.fields,
                           [name |-> nm, value |-> r.value, never |-> r.indexing = "never"]),
                       !.dec = [st.dec EXCEPT !.table = added.table, !.store = added.store]]

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
       ELSE [st2 EXCEPT !.dec = [st2.dec EXCEPT !.table = <<>>,
                                                !.store = SetHeld(st2.dec.store, 0)]]

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
    \* Encoder::new(EncoderInit): Table::default() at 4096, then
    \* set_settings_limit(EncoderInit) (hpack.rs lines 705-713); and
    \* Session::new.
    /\ enc = EncLimit([table |-> <<>>, max |-> Initial, settings |-> Initial, pending |-> None,
                       store |-> Store(Initial)],
                      EncoderInit)
    /\ dec = [table |-> <<>>, max |-> Initial, settings |-> Initial, required |-> None,
              store |-> Store(Initial)]
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
    /\ LET r == EncBlock([enc EXCEPT !.store = Begin(enc.store)], fs)
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
           st == DecBlock([dec EXCEPT !.store = Begin(dec.store)], m.reps)
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
\* No moment of a step held more than the table's charge ...
DecoderPaid == Paid(dec.store)
EncoderPaid == Paid(enc.store)
\* ... the charges stay within MAX_TABLE ...
ChargedWithinLimit == WithinLimit(dec.store, MaxTable) /\ WithinLimit(enc.store, MaxTable)
\* ... and each store holds what its table does.
StoresTrack == Tracks(dec.store, Sum(dec.table)) /\ Tracks(enc.store, Sum(enc.table))
=============================================================================
