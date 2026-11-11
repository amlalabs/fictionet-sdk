------------------------- MODULE VersionInformation -------------------------
EXTENDS Integers, Sequences, Resources

CONSTANTS CheckZero, CheckChosen, CheckConnection, CheckDuplicate, CheckAll,
          CopyList
VARIABLES connection, server, chosen, available, validLength, duplicate,
          pos, includes, phase, result, store
vars == <<connection, server, chosen, available, validLength, duplicate,
          pos, includes, phase, result, store>>

(* The wire decoder supplies an integral list of four-byte versions. A bad
   length represents either a short chosen version or a partial entry.
   The connection profile neither switches versions nor retries after VN.
   See RFC 9368 section 4. The Rust parser borrows its input. *)
Init == /\ connection \in 1..2 /\ server \in BOOLEAN
        /\ chosen \in 0..2
        /\ available \in UNION {[1..n -> 0..2] : n \in 0..2}
        /\ validLength \in BOOLEAN /\ duplicate \in BOOLEAN
        /\ pos = 1 /\ includes = FALSE /\ phase = "length"
        /\ result = "pending" /\ store = Store(0)

Length == /\ phase = "length"
          /\ phase' = IF ~validLength \/ (CheckZero /\ chosen = 0)
                       THEN "done" ELSE "list"
          /\ result' = IF phase' = "done" THEN "parameters" ELSE result
          /\ store' = IF CopyList THEN Grow(Begin(store), 4 * (1 + Len(available)))
                      ELSE Begin(store)
          /\ UNCHANGED <<connection, server, chosen, available, validLength,
                         duplicate, pos, includes>>

Entry == /\ phase = "list" /\ pos <= Len(available)
         /\ LET entry == available[pos] IN
            /\ includes' = (includes \/ entry = chosen)
            /\ phase' = IF CheckZero /\ entry = 0 THEN "done"
                         ELSE IF ~CheckAll /\ includes' THEN "validate"
                         ELSE "list"
            /\ result' = IF phase' = "done" THEN "parameters" ELSE result
         /\ pos' = pos + 1 /\ store' = Begin(store)
         /\ UNCHANGED <<connection, server, chosen, available, validLength, duplicate>>

End == /\ phase = "list" /\ pos > Len(available)
       /\ phase' = "validate" /\ store' = Begin(store)
       /\ UNCHANGED <<connection, server, chosen, available, validLength,
                      duplicate, pos, includes, result>>

Validate == /\ phase = "validate" /\ phase' = "done"
            /\ result' = IF CheckChosen /\ server /\ ~includes THEN "parameters"
                          ELSE IF CheckConnection /\ chosen # connection THEN "version"
                          ELSE IF CheckDuplicate /\ duplicate THEN "parameters"
                          ELSE "accepted"
            /\ store' = Begin(store)
            /\ UNCHANGED <<connection, server, chosen, available, validLength,
                           duplicate, pos, includes>>

Next == Length \/ Entry \/ End \/ Validate
Spec == Init /\ [][Next]_vars

WellFormed == validLength /\ chosen # 0
              /\ (\A i \in 1..Len(available): available[i] # 0)
              /\ (~server \/ (\E i \in 1..Len(available): available[i] = chosen))
Expected == IF ~WellFormed THEN "parameters"
            ELSE IF chosen # connection THEN "version"
            ELSE IF duplicate THEN "parameters" ELSE "accepted"
Decision == phase = "done" => result = Expected
PaidStorage == Paid(store) /\ WithinLimit(store, 0) /\ Tracks(store, 0)
NoAcceptance == result # "accepted"
=============================================================================
