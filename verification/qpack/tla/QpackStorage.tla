----------------------------- MODULE QpackStorage -----------------------------
EXTENDS Naturals, Sequences, FiniteSets, Resources

(* Storage units are abstract. A blocked body costs zero to two units and
   each section descriptor costs one. Three descriptor slots are retained
   even after a cancellation. A temporary input body and its owned copy
   coexist during admission. Output is a bounded queue of feedback values.
   These are admission/lifetime properties, not allocator byte bounds. *)
CONSTANTS ChargeFirst, ChargeCopy, BoundBytes, BoundSections, BoundStreams,
          BoundOutput, ChargeSlots
VARIABLES allocated, sections, output, store
vars == <<allocated, sections, output, store>>
Streams == {0, 4, 8}
Bodies == 0..2
RECURSIVE Bytes(_)
Bytes(q) == IF Len(q) = 0 THEN 0 ELSE Head(q).bytes + Bytes(Tail(q))
StreamSet(q) == {q[i].stream : i \in 1..Len(q)}
Resident == (IF allocated THEN 3 ELSE 0) + Bytes(sections) + output
Init == /\ allocated = FALSE /\ sections = <<>> /\ output = 0 /\ store = Store(0)

Allocate == /\ ~allocated
            /\ LET s == Begin(store)
                   paid == IF ChargeFirst THEN Reserve(s, IF ChargeSlots THEN 3 ELSE 0) ELSE s
               IN store' = Grow(paid, 3)
            /\ allocated' = TRUE
            /\ UNCHANGED <<sections, output>>

Block(s, n) ==
    /\ allocated /\ Len(sections) < 4
    /\ (~BoundSections \/ Len(sections) < 3)
    /\ (~BoundBytes \/ Bytes(sections) + n <= 4)
    /\ (~BoundStreams \/ Cardinality(StreamSet(sections) \cup {s}) <= 2)
    /\ LET old == Begin(store)
           (* Scratch pays for source and copy before decoding. Acquire
              the retained-body charge before releasing that scratch. *)
           input == Grow(Reserve(old, 2 * n), n)
           copied == Grow(input, n)
           retained == IF ChargeCopy THEN Reserve(copied, n) ELSE copied
           released == Shrink(retained, n)
       IN store' = Release(released, 2 * n)
    /\ sections' = Append(sections, [stream |-> s, bytes |-> n])
    /\ UNCHANGED <<allocated, output>>

Cancel(s) ==
    /\ allocated /\ s \in StreamSet(sections)
    /\ LET kept == SelectSeq(sections, LAMBDA x : x.stream # s)
           freed == Bytes(sections) - Bytes(kept)
       IN /\ sections' = kept
          /\ store' = Release(Shrink(Begin(store), freed), freed)
    /\ UNCHANGED <<allocated, output>>

Feedback == /\ allocated /\ output < 3 /\ (~BoundOutput \/ output < 2)
            /\ output' = output + 1
            /\ store' = Grow(Reserve(Begin(store), 1), 1)
            /\ UNCHANGED <<allocated, sections>>
Drain == /\ output > 0 /\ output' = output - 1
         /\ store' = Release(Shrink(Begin(store), 1), 1)
         /\ UNCHANGED <<allocated, sections>>

Next == Allocate \/ (\E s \in Streams, n \in Bodies : Block(s, n))
        \/ (\E s \in Streams : Cancel(s)) \/ Feedback \/ Drain
Spec == Init /\ [][Next]_vars
StoragePaid == Paid(store)
StorageTracked == Tracks(store, Resident)
BodiesBounded == Bytes(sections) <= 4
SectionsBounded == Len(sections) <= 3
StreamsBounded == Cardinality(StreamSet(sections)) <= 2
FeedbackBounded == output <= 2
StorageBounded == WithinLimit(store, 9)
=============================================================================
