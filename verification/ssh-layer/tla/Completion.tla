---------------------------- MODULE Completion ----------------------------
\* Source: src/stdlib/services/ssh.rs:710-713 (Flight), :1533-1557
\* (partial Written, pop once, child credit), :1718-1728 (flight ownership);
\* src/stdlib/layer/children.rs:484-502 (retired child discards notifications).
EXTENDS Naturals, Sequences
CONSTANT Mutation
VARIABLES flights, issued, delivered, credited, taken, settled, cancelled, live
vars == <<flights, issued, delivered, credited, taken, settled, cancelled, live>>
\* ssh.rs Flight, take_command and on_event(Written): encoded byte flights
\* own one child completion; control flights have zero application credit.
\* A retired child's notifications are discarded by Children::on_event.
Init == /\ flights = <<>> /\ issued = 0 /\ delivered = 0 /\ credited = 0
        /\ taken = 0 /\ settled = 0 /\ cancelled = 0 /\ live = TRUE
Send(n) == /\ live /\ issued < 3 /\ n \in 0..1
           /\ flights' = Append(flights, [left |-> 2, credit |-> n])
           /\ issued' = issued + 1
           /\ UNCHANGED <<delivered, credited, taken, settled, cancelled, live>>
Complete == /\ Len(flights) > 0
            /\ LET f == Head(flights)
                   due == IF f.left = 1 THEN f.credit ELSE 0
                   notify == IF f.left = 1 \/ Mutation = "fence" THEN f.credit ELSE 0
               IN /\ delivered' = delivered + IF Mutation = "count" THEN 2 ELSE 1
                  /\ flights' = IF f.left = 1 THEN Tail(flights)
                                ELSE <<[f EXCEPT !.left = @ - 1]>> \o Tail(flights)
                  /\ settled' = settled + due
                  /\ credited' = credited + IF live THEN notify ELSE 0
                  /\ cancelled' = cancelled + IF live THEN 0 ELSE due
            /\ UNCHANGED <<issued, taken, live>>
Take == /\ credited > 0 /\ taken < 7
        /\ taken' = taken + credited
        /\ credited' = IF Mutation = "take" THEN credited ELSE 0
        /\ UNCHANGED <<flights, issued, delivered, settled, cancelled, live>>
Retire == /\ live /\ live' = FALSE /\ cancelled' = cancelled + credited /\ credited' = 0
          /\ UNCHANGED <<flights, issued, delivered, taken, settled>>
Next == (\E n \in 0..1: Send(n)) \/ Complete \/ Take \/ Retire
Fence == taken + credited + cancelled <= settled
Exact == taken + credited + cancelled = settled
RECURSIVE SumLeft(_)
SumLeft(s) == IF s = <<>> THEN 0 ELSE Head(s).left + SumLeft(Tail(s))
WireConservation == delivered + SumLeft(flights) = 2 * issued
=============================================================================
