---------------------------- MODULE JobContext ----------------------------
\* Projection of Jobs::poll (src/stdlib/services/stack/job.rs) and Cx's
\* counted job-context lease (ContextLease in src/cx.rs). One runner
\* reference is implicit. Borrowed contexts can start work after Work::Ready.
\* The model bounds external references at two and active tasks at one.
\*   borrowed   ContextLease references beyond the runner's own
\*   returned   Running::completed: the work gave its result
\*   live       RegionState::live of the job's region
\*   closed     RegionState::completed, set by Region::poll_done at live = 0
\*   cancelled  Region::cancelled of the job's region
\*   retired    the Running was removed from Jobs::running
\* A cancel closes nothing by itself: Cx::clone and Cx::spawn check neither
\* `cancelled` nor the lease, so a borrow and a task start are allowed after
\* a cancel until the region completes (Region::try_start_task refuses only
\* a completed region).
EXTENDS Naturals
CONSTANT RespectBorrow
VARIABLES borrowed, returned, live, closed, cancelled, retired
vars == <<borrowed, returned, live, closed, cancelled, retired>>
Init == /\ borrowed = 0 /\ returned = FALSE /\ live = 0
        /\ closed = FALSE /\ cancelled = FALSE /\ retired = FALSE
Borrow == /\ ~retired /\ borrowed < 2
          /\ (~returned \/ borrowed > 0)
          /\ borrowed' = borrowed + 1
          /\ UNCHANGED <<returned, live, closed, cancelled, retired>>
Release == /\ borrowed > 0 /\ borrowed' = borrowed - 1
           /\ UNCHANGED <<returned, live, closed, cancelled, retired>>
Return == /\ ~returned /\ returned' = TRUE
          /\ UNCHANGED <<borrowed, live, closed, cancelled, retired>>
Start == /\ borrowed > 0 /\ ~closed /\ live = 0
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
