---------------------------- MODULE RegionTree ----------------------------
\* Region::try_start_task reserves ancestors before the local counter.
\* Region::task_done releases local accounting before its ancestors.
\* Each locked counter operation is a step, so completion may race admission.
\* Futures have already been dropped when finishing begins. Local failures
\* cancel their subtree; releasing ancestor counts never propagates errors.
EXTENDS Naturals, FiniteSets, Sequences
CONSTANTS CountAncestors, CheckAncestors, Rollback, PropagateErrors
Regions == {"root", "middle", "leaf", "sibling"}
Tasks == {1, 2}
Paths == [r \in Regions |-> CASE r = "root" -> <<"root">>
                          [] r = "middle" -> <<"root", "middle">>
                          [] r = "leaf" -> <<"root", "middle", "leaf">>
                          [] OTHER -> <<"root", "sibling">>]
Ancestors(r) == {Paths[r][i] : i \in 1..Len(Paths[r])}
VARIABLES owner, phase, cursor, reserved, live, closed, cancelled, failed
vars == <<owner, phase, cursor, reserved, live, closed, cancelled, failed>>
Init == /\ owner \in [Tasks -> Regions]
        /\ phase = [t \in Tasks |-> "admit"]
        /\ cursor = [t \in Tasks |-> 1]
        /\ reserved = [t \in Tasks |-> {}]
        /\ live = [r \in Regions |-> 0]
        /\ closed = {} /\ cancelled = {} /\ failed = {}
Reserve(t) ==
    /\ phase[t] = "admit"
    /\ cursor[t] <= Len(Paths[owner[t]])
    /\ LET r == Paths[owner[t]][cursor[t]] IN
       IF r \in closed /\ (CheckAncestors \/ r = owner[t])
       THEN /\ phase' = [phase EXCEPT ![t] = IF Rollback THEN "release" ELSE "done"]
            /\ UNCHANGED <<cursor, reserved, live>>
       ELSE /\ cursor' = [cursor EXCEPT ![t] = @ + 1]
            /\ IF CountAncestors \/ r = owner[t]
               THEN /\ reserved' = [reserved EXCEPT ![t] = @ \cup {r}]
                    /\ live' = [live EXCEPT ![r] = @ + 1]
               ELSE UNCHANGED <<reserved, live>>
            /\ UNCHANGED phase
    /\ UNCHANGED <<owner, closed, cancelled, failed>>
Commit(t) ==
    /\ phase[t] = "admit" /\ cursor[t] > Len(Paths[owner[t]])
    /\ phase' = [phase EXCEPT ![t] = "running"]
    /\ UNCHANGED <<owner, cursor, reserved, live, closed, cancelled, failed>>
Finish(t) ==
    /\ phase[t] = "running"
    /\ phase' = [phase EXCEPT ![t] = "release"]
    /\ UNCHANGED <<owner, cursor, reserved, live, closed, cancelled, failed>>
Fail(t) ==
    /\ phase[t] = "running"
    /\ phase' = [phase EXCEPT ![t] = "release"]
    /\ failed' = failed \cup {owner[t]}
    /\ cancelled' = cancelled \cup (IF PropagateErrors THEN Regions
                                  ELSE {r \in Regions : owner[t] \in Ancestors(r)})
    /\ UNCHANGED <<owner, cursor, reserved, live, closed>>
Release(t) ==
    /\ phase[t] = "release"
    /\ IF reserved[t] = {}
       THEN /\ phase' = [phase EXCEPT ![t] = "done"]
            /\ UNCHANGED <<reserved, live>>
       ELSE /\ \E r \in reserved[t] :
                   /\ ~\E later \in reserved[t] \ {r} : r \in Ancestors(later)
                   /\ reserved' = [reserved EXCEPT ![t] = @ \ {r}]
                   /\ live' = [live EXCEPT ![r] = @ - 1]
            /\ UNCHANGED phase
    /\ UNCHANGED <<owner, cursor, closed, cancelled, failed>>
Join(r) ==
    /\ r \notin closed /\ live[r] = 0
    /\ closed' = closed \cup {r}
    /\ UNCHANGED <<owner, phase, cursor, reserved, live, cancelled, failed>>
TaskStep(t) == Reserve(t) \/ Commit(t) \/ Finish(t) \/ Fail(t) \/ Release(t)
Next == (\E t \in Tasks : TaskStep(t)) \/ (\E r \in Regions : Join(r))
Spec == Init /\ [][Next]_vars /\ (\A t \in Tasks : WF_vars(TaskStep(t)))
Counts == \A r \in Regions : live[r] = Cardinality({t \in Tasks : r \in reserved[t]})
ClosedCounts == \A r \in closed : live[r] = 0
NoTaskOutlives == \A t \in Tasks : phase[t] = "running" => Ancestors(owner[t]) \cap closed = {}
NoLeakedReservations == \A t \in Tasks : phase[t] = "done" => reserved[t] = {}
ErrorIsolation == \A r \in cancelled : \E f \in failed : f \in Ancestors(r)
Settles == <> (\A t \in Tasks : phase[t] = "done")
=============================================================================
