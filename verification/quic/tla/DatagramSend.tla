--------------------------- MODULE DatagramSend ----------------------------
EXTENDS Integers, Resources

(* One charged application backing, DatagramSlot::admit, packet construction *)
(* and DatagramSend's lower completion. Queue metadata is inline. The wire  *)
(* output is reserved before copying. The caller pays the input beforehand. *)
CONSTANTS Capacity, Wire, CopyOnAdmit, CompleteOnPacket, RepeatCompletion
VARIABLES phase, source, output, tracked, reports, lowerRetired, packetSent
vars == <<phase, source, output, tracked, reports, lowerRetired, packetSent>>

Init == /\ phase = "source"
        /\ source = Grow(Reserve(Store(0), Capacity), Capacity)
        /\ output = Store(0)
        /\ tracked \in BOOLEAN
        /\ reports = 0 /\ lowerRetired = FALSE /\ packetSent = FALSE

Admit == /\ phase = "source"
         /\ phase' = "queued"
         /\ source' = IF CopyOnAdmit
                      THEN Shrink(Grow(Begin(source), Capacity), Capacity)
                      ELSE Begin(source)
         /\ UNCHANGED <<output, tracked, reports, lowerRetired, packetSent>>

Refuse == /\ phase = "source"
          /\ UNCHANGED vars

Encode == /\ phase = "queued"
          /\ output' = Grow(Reserve(Begin(output), Wire), Wire)
          /\ source' = Shrink(Begin(source), Capacity)
          /\ packetSent' = TRUE
          /\ phase' = IF CompleteOnPacket THEN "ready" ELSE "flight"
          /\ UNCHANGED <<tracked, reports, lowerRetired>>

Drop == /\ phase = "queued"
        /\ source' = Shrink(Begin(source), Capacity)
        /\ phase' = "ready"
        /\ UNCHANGED <<output, tracked, reports, lowerRetired, packetSent>>

Retire == /\ phase = "flight"
          /\ output' = Shrink(Begin(output), Wire)
          /\ phase' = "ready" /\ lowerRetired' = TRUE
          /\ UNCHANGED <<source, tracked, reports, packetSent>>

Report == /\ phase = "ready"
          /\ reports < 2
          /\ reports' = reports + IF tracked THEN 1 ELSE 0
          /\ phase' = IF RepeatCompletion THEN "ready" ELSE "done"
          /\ UNCHANGED <<source, output, tracked, lowerRetired, packetSent>>

ReleaseStorage == /\ (source.held = 0 /\ source.reserved > 0) \/ (output.held = 0 /\ output.reserved > 0)
                  /\ source' = IF source.held = 0 THEN Release(Begin(source), source.reserved) ELSE Begin(source)
                  /\ output' = IF output.held = 0 THEN Release(Begin(output), output.reserved) ELSE Begin(output)
                  /\ UNCHANGED <<phase, tracked, reports, lowerRetired, packetSent>>

Next == Admit \/ Refuse \/ Encode \/ Drop \/ Retire \/ Report \/ ReleaseStorage
Spec == Init /\ [][Next]_vars
PaidBacking == Paid(source) /\ Paid(output)
Bounded == WithinLimit(source, Capacity) /\ WithinLimit(output, Wire)
TracksStorage == /\ Tracks(source, IF phase \in {"source", "queued"} THEN Capacity ELSE 0)
                 /\ Tracks(output, IF packetSent /\ ~lowerRetired THEN Wire ELSE 0)
AfterRetirement == reports > 0 => (~packetSent \/ lowerRetired)
Once == reports <= 1 /\ (~tracked => reports = 0)
NoReport == reports = 0
=============================================================================
