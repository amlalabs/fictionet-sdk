---------------------------- MODULE JobContext ----------------------------
\* Projection of Jobs::poll and Cx's counted job-context lease. One runner
\* reference is implicit. Borrowed contexts can start work after Work::Ready.
\* The model bounds external references at two and active tasks at one.
EXTENDS Naturals
CONSTANT RespectBorrow
VARIABLES borrowed, returned, live, closed, cancelled, retired
vars == <<borrowed, returned, live, closed, cancelled, retired>>
Init == /\ borrowed = 0 /\ returned = FALSE /\ live = 0
        /\ closed = FALSE /\ cancelled = FALSE /\ retired = FALSE
Borrow == /\ ~retired /\ ~cancelled /\ borrowed < 2
          /\ (~returned \/ borrowed > 0)
          /\ borrowed' = borrowed + 1
          /\ UNCHANGED <<returned, live, closed, cancelled, retired>>
Release == /\ borrowed > 0 /\ borrowed' = borrowed - 1
           /\ UNCHANGED <<returned, live, closed, cancelled, retired>>
Return == /\ ~returned /\ returned' = TRUE
          /\ UNCHANGED <<borrowed, live, closed, cancelled, retired>>
Start == /\ borrowed > 0 /\ ~closed /\ ~cancelled /\ live = 0
         /\ live' = 1
         /\ UNCHANGED <<borrowed, returned, closed, cancelled, retired>>
Finish == /\ live = 1 /\ live' = 0
          /\ UNCHANGED <<borrowed, returned, closed, cancelled, retired>>
Cancel == /\ ~cancelled /\ cancelled' = TRUE
          /\ UNCHANGED <<borrowed, returned, live, closed, retired>>
Reap == /\ ~retired /\ (returned \/ cancelled) /\ live = 0
        /\ (~RespectBorrow \/ borrowed = 0 \/ cancelled)
        /\ closed' = TRUE /\ retired' = TRUE
        /\ UNCHANGED <<borrowed, returned, live, cancelled>>
Next == Borrow \/ Release \/ Return \/ Start \/ Finish \/ Cancel \/ Reap
Spec == Init /\ [][Next]_vars
BorrowKeepsAdmission == borrowed > 0 /\ ~cancelled => ~closed
RetirementDrainsTasks == retired => live = 0
=============================================================================
