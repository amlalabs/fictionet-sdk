---------------------------- MODULE Connection ----------------------------
(***************************************************************************)
(* One MPTCP connection and one join at the listener in                    *)
(* extras/src/linux/mptcp.rs (moved from demos/honeypot/src/mptcp.rs in    *)
(* 5494f1ad1), with the first mapping DataLevel::new seeds in              *)
(* src/stdlib/protocols/mptcp.rs.                                          *)
(*                                                                         *)
(*   Capable    complete and read_ack on the third ACK of an MP_CAPABLE    *)
(*              handshake: Keys::Both on a pure ACK or Keys::Data with     *)
(*              data count, anything else is plain TCP; DataLevel::new     *)
(*              seeds a mapping for the data (ReceivedMapping::seeded)     *)
(*   JoinSyn    answer_syn's MP_JOIN branch; Answers::syn saves a          *)
(*              JoinCookie when the SYN gets a SYN cookie                  *)
(*   Evict      JoinCookies::save writing over the slot, or take           *)
(*   JoinAck    Answers::cookie, complete and answer_ack: Drop when        *)
(*              nothing was kept (Completion::Join(None)), Refuse with     *)
(*              MPTCP_SPECIFIC when the ACK has no MP_JOIN, with           *)
(*              ADMINISTRATIVELY_PROHIBITED on a bad HMAC, Accept on a     *)
(*              matching one. A cookie-answered join whose ACK carries no  *)
(*              MP_JOIN is taken as plain TCP: Answers::cookie looks for   *)
(*              the kept join only when the ACK has MP_JOIN, so complete   *)
(*              sees a plain SYN cookie return (phase "plainCookie")       *)
(*   FastClose  Dss::received's MP_FASTCLOSE check against the key         *)
(*                                                                         *)
(* Authenticate is the HMAC comparison in answer_ack, KeepCookie the join  *)
(* cookie table, CheckFastClose the key comparison, ForbidJoinFallback the *)
(* refusal of a join ACK without MP_JOIN.                                  *)
(***************************************************************************)
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
           \* After a SYN cookie, an ACK without MP_JOIN is never looked up
           \* as a join: the server takes it as plain TCP (Answers::cookie).
           unseen == (cookie /\ ~option)
           accept == have /\ option /\ (mac \/ ~Authenticate)
       IN /\ phase' = IF unseen THEN "plainCookie"
                       ELSE IF ~have THEN "dropped"
                       ELSE IF accept THEN "joined"
                       ELSE IF (~option /\ ~ForbidJoinFallback) THEN "plainJoin"
                       ELSE "refused"
          /\ joined' = accept
          /\ authenticated' = (mac /\ option /\ (~cookie \/ kept))
          /\ reason' = IF accept \/ ~have \/ unseen THEN "none"
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
