--------------------------- MODULE TokenVersions ---------------------------
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS CheckClient, CheckServer, RemoveTaken
VARIABLES issued, origin, cache, taken, once, clientBound, serverBound, validated
vars == <<issued, origin, cache, taken, once, clientBound, serverBound, validated>>

(* Each token has an immutable authenticated version. Authentication itself
   is an assumption, not a cryptographic proof. The cache models one server
   with two slots shared by all versions. Tokens have distinct identities. *)
Init == /\ issued = {} /\ origin \in [1..3 -> 1..2]
        /\ cache = <<>> /\ taken = {}
        /\ once = TRUE /\ clientBound = TRUE /\ serverBound = TRUE
        /\ validated = FALSE

Issue(id) == /\ id \in (1..3) \ issued
             /\ issued' = issued \cup {id}
             /\ cache' = Append(IF Len(cache) = 2 THEN Tail(cache) ELSE cache, id)
             /\ UNCHANGED <<origin, taken, once, clientBound, serverBound, validated>>

Take(version) ==
    LET matching == {i \in 1..Len(cache): ~CheckClient \/ origin[cache[i]] = version}
    IN /\ matching # {}
       /\ LET pos == CHOOSE i \in matching: \A j \in matching: i <= j
              id == cache[pos]
          IN /\ cache' = IF RemoveTaken
                          THEN SubSeq(cache, 1, pos - 1) \o SubSeq(cache, pos + 1, Len(cache))
                          ELSE cache
             /\ once' = (once /\ id \notin taken)
             /\ taken' = taken \cup {id}
             /\ clientBound' = (clientBound /\ origin[id] = version)
       /\ UNCHANGED <<issued, origin, serverBound, validated>>

(* A peer can present any issued token under either version, independently
   of the honest client's cache selection. A rejection does not validate. *)
Receive(id, version) ==
    /\ id \in issued
    /\ LET accepts == ~CheckServer \/ origin[id] = version
       IN /\ validated' = accepts
          /\ serverBound' = (serverBound /\ (accepts => origin[id] = version))
    /\ UNCHANGED <<issued, origin, cache, taken, once, clientBound>>

Next == (\E id \in 1..3: Issue(id))
        \/ (\E v \in 1..2: Take(v))
        \/ (\E id \in 1..3, v \in 1..2: Receive(id, v))
Spec == Init /\ [][Next]_vars
ClientVersion == clientBound
ServerVersion == serverBound
TakenOnce == once
BoundedCount == Len(cache) <= 2
NoValidation == ~validated
=============================================================================
