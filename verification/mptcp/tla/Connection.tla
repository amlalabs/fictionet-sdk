---------------------------- MODULE Connection ----------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Authenticate, KeepCookie, CheckFastClose, ForbidJoinFallback
VARIABLES phase, cookie, kept, authenticated, joined, reason, closeKey,
          capableData, firstMapped
vars == <<phase, cookie, kept, authenticated, joined, reason, closeKey,
          capableData, firstMapped>>
Init == /\ phase = "syn"
        /\ cookie \in BOOLEAN /\ kept = FALSE /\ authenticated = FALSE
        /\ joined = FALSE /\ reason = "none" /\ closeKey = TRUE
        /\ capableData = FALSE /\ firstMapped = FALSE
Capable(data, option) ==
    /\ phase = "syn"
    /\ phase' = IF option THEN "open" ELSE "plain"
    /\ capableData' = data /\ firstMapped' = (data /\ option)
    /\ UNCHANGED <<cookie, kept, authenticated, joined, reason, closeKey>>
JoinSyn == /\ phase = "open"
           /\ kept' = TRUE /\ phase' = "join"
           /\ UNCHANGED <<cookie, authenticated, joined, reason, closeKey,
                          capableData, firstMapped>>
Evict == /\ phase = "join" /\ cookie /\ kept
         /\ kept' = FALSE
         /\ UNCHANGED <<phase, cookie, authenticated, joined, reason, closeKey,
                        capableData, firstMapped>>
JoinAck(mac, option) ==
    /\ phase = "join"
    /\ LET have == (~cookie \/ kept \/ ~KeepCookie)
           accept == have /\ option /\ (mac \/ ~Authenticate)
       IN /\ phase' = IF ~have THEN "dropped"
                       ELSE IF accept THEN "joined"
                       ELSE IF (~option /\ ~ForbidJoinFallback) THEN "plainJoin"
                       ELSE "refused"
          /\ joined' = accept
          /\ authenticated' = (mac /\ option /\ (~cookie \/ kept))
          /\ reason' = IF accept \/ ~have THEN "none"
                        ELSE IF ~option THEN "mptcp" ELSE "prohibited"
    /\ UNCHANGED <<cookie, kept, closeKey, capableData, firstMapped>>
FastClose(key) ==
    /\ phase \in {"open", "joined"}
    /\ phase' = IF key \/ ~CheckFastClose THEN "closed" ELSE phase
    /\ closeKey' = key
    /\ UNCHANGED <<cookie, kept, authenticated, joined, reason,
                   capableData, firstMapped>>
Next == (\E d, o \in BOOLEAN : Capable(d, o)) \/ JoinSyn \/ Evict
        \/ (\E m, o \in BOOLEAN : JoinAck(m, o))
        \/ (\E k \in BOOLEAN : FastClose(k))
Spec == Init /\ [][Next]_vars
JoinAuthenticated == joined => authenticated
CookieRetained == joined /\ cookie => kept
FastCloseAuthenticated == phase = "closed" => closeKey
JoinNeverPlain == phase # "plainJoin"
ThirdAckMapped == phase \in {"open", "join", "joined", "closed"}
                  /\ capableData => firstMapped
ResetReason == phase = "refused" => reason \in {"mptcp", "prohibited"}
=============================================================================
