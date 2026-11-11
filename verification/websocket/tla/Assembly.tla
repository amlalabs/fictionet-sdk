---------------------------- MODULE Assembly ----------------------------
(***************************************************************************)
(* Source: src/stdlib/protocols/websocket.rs, Messages::check_header,        *)
(* Messages::decode and held, Partial::append, Frames::decode,              *)
(* Frame::from_header.                                                      *)
(* One unit is one scaled payload byte. A header checks message length    *)
(* before the frame copy. The first vector becomes the partial message.   *)
(* Continuations allocate the new capacity before freeing the old one.    *)
(* The frame vector is freed after copying. Final output leaves this      *)
(* decoder's ownership. held() reports capacity.                          *)
(* ClampToLimit FALSE and HeldIsCapacity FALSE are the code before the   *)
(* fix: Vec::extend_from_slice's growth, and held() as the length.        *)
(* Control frames, invalid text, masking, incomplete input and            *)
(* allocator rounding are omitted. The input buffer is outside the model. *)
(* Retained reserves L. Step reserves n + L after the header passes.      *)
(* Moving a vector between stores transfers ownership, not an allocation. *)
(* Each allocation/free sequence ends before its charge return, so Paid   *)
(* checks the peak against the reservation that covered that sequence.    *)
(***************************************************************************)
EXTENDS Integers, Resources
CONSTANTS L, MaxFrames, MaxPayload, ClampToLimit, CheckFirst, HeldIsCapacity
VARIABLE x
Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b
Fresh == [x EXCEPT !.retained = Begin(@), !.step = Begin(@)]
Init == x = [len |-> 0, cap |-> 0, partial |-> FALSE, reported |-> 0,
             frames |-> 0, n |-> 0, final |-> FALSE, frame |-> 0,
             phase |-> "ready", retained |-> Store(L), step |-> Store(0)]

Start(n, final) ==
    /\ x.phase = "ready" /\ x.frames < MaxFrames
    /\ IF CheckFirst /\ x.len + n > L
       THEN x' = [Fresh EXCEPT !.phase = "done", !.frames = @ + 1]
       ELSE x' = [Fresh EXCEPT !.frames = @ + 1, !.n = n, !.final = final,
           !.frame = n, !.phase = IF CheckFirst THEN "assemble" ELSE "check",
           !.step = Grow(IF CheckFirst THEN Reserve(Begin(x.step), n + L)
                         ELSE Begin(x.step), n)]

LateCheck ==
    /\ x.phase = "check"
    /\ IF x.len + x.n > L
       THEN x' = [Fresh EXCEPT !.step = Shrink(Begin(x.step), x.frame),
                              !.frame = 0, !.phase = "done"]
       ELSE x' = [Fresh EXCEPT !.step = Reserve(Begin(x.step), x.n + L),
                              !.phase = "assemble"]

Assemble ==
    /\ x.phase = "assemble"
    /\ LET len == x.len + x.n
           raw == Max(2 * x.cap, len)
           cap == IF ~x.partial THEN x.n
                  ELSE IF len <= x.cap THEN x.cap
                  ELSE IF ClampToLimit THEN Min(raw, L) ELSE raw
           grows == x.partial /\ len > x.cap
           copied == IF grows THEN Grow(Begin(x.step), cap) ELSE Begin(x.step)
           moved == IF grows THEN Shrink(copied, cap) ELSE copied
           retained == IF ~x.partial THEN Grow(Begin(x.retained), cap)
                       ELSE IF grows THEN Grow(Shrink(Begin(x.retained), x.cap), cap)
                       ELSE Begin(x.retained)
       IN x' = [Fresh EXCEPT !.len = len, !.cap = cap, !.partial = TRUE,
           !.reported = IF HeldIsCapacity THEN cap ELSE len,
           !.retained = retained, !.step = Shrink(moved, x.frame),
           !.frame = 0, !.phase = "finish"]

Finish ==
    /\ x.phase = "finish"
    /\ x' = [Fresh EXCEPT !.step = Release(Begin(x.step), x.step.reserved),
        !.retained = IF x.final THEN Shrink(Begin(x.retained), x.cap) ELSE Begin(x.retained),
        !.len = IF x.final THEN 0 ELSE @, !.cap = IF x.final THEN 0 ELSE @,
        !.reported = IF x.final THEN 0 ELSE @,
        !.partial = ~x.final, !.phase = "ready"]

Next == (\E n \in 0..MaxPayload, final \in BOOLEAN : Start(n, final))
        \/ LateCheck \/ Assemble \/ Finish \/ x' = Fresh
Spec == Init /\ [][Next]_x
RetainedPaid == Paid(x.retained)
StepPaid == Paid(x.step)
RetainedWithinLimit == WithinLimit(x.retained, L) /\ x.cap <= L
StepWithinLimit == WithinLimit(x.step, MaxPayload + L)
RetainedTracks == Tracks(x.retained, x.cap)
StepTracks == Tracks(x.step, x.frame)
HeldTracks == x.reported = x.retained.held
Shape == /\ x.len \in 0..x.cap /\ x.frames \in 0..MaxFrames
         /\ x.frame \in 0..MaxPayload
=============================================================================
