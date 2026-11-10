---------------------------- MODULE Auth ----------------------------
\* RFC 4252 user authentication between the server as written and any
\* client the RFC allows.
\* Server source: src/stdlib/services/ssh.rs `packet` (SERVICE_REQUEST
\* for ssh-userauth once; USERAUTH_REQUEST and INFO_RESPONSE only before
\* success; a USERAUTH_REQUEST after success is dropped; connection
\* messages only after success, UNIMPLEMENTED before), `authentication`
\* (a request with a signature that does not verify; the handler's Accept,
\* Reject with partial success and delay, or Challenge; PK_OK for a probe;
\* SUCCESS sets the user), `progress` (no packet is taken while a delayed
\* failure waits; the failure goes out when its timer fires), `on_timer`.
\* Client: RFC 4252 section 5 (requests may be sent without waiting for
\* the replies, and each is answered in turn; requests after SUCCESS are
\* ignored), 5.1 (FAILURE with partial success, SUCCESS once), 5.3 (no
\* service before success), 7 (a probe is answered with PK_OK or FAILURE;
\* a signed request is answered with SUCCESS or FAILURE, and a signature
\* that is not correct never authenticates); RFC 4256 section 3 (an
\* INFO_REQUEST is answered with one INFO_RESPONSE before anything else).
\* Abstractions. A request is its kind: "none", a good or bad password,
\* a public key probe, a correctly signed request ("signed"), a request
\* whose signature does not verify ("forged"), a keyboard-interactive start
\* ("kbd"), or the answers to its challenge ("answer"). The handler's
\* policy is any decision its contract allows for that kind. User and
\* service names never change, and the attempt limit is not reached
\* (MaxReq is below max_attempts); both are disconnects the RFC allows.
EXTENDS Naturals, Sequences
CONSTANTS Mutation, MaxReq, Early, BadHandler

Kinds == {"none", "pwgood", "pwbad", "probe", "signed", "forged", "kbd"}

VARIABLES c2s, s2c, sService, sUser, sSuccess, sFailure, sChallenge,
          sFault, delivered, cAccepted, cOut, cSent, cAuth, cInfo, cViol,
          early, forgedSuccess
vars == <<c2s, s2c, sService, sUser, sSuccess, sFailure, sChallenge, sFault,
          delivered, cAccepted, cOut, cSent, cAuth, cInfo, cViol, early,
          forgedSuccess>>

Init == /\ c2s = <<"svc">> /\ s2c = <<>>
        /\ sService = FALSE /\ sUser = FALSE /\ sSuccess = FALSE
        /\ sFailure = FALSE /\ sChallenge = FALSE /\ sFault = FALSE
        /\ delivered = FALSE /\ cAccepted = FALSE /\ cOut = <<>> /\ cSent = 0
        /\ cAuth = FALSE /\ cInfo = FALSE /\ cViol = {} /\ early = FALSE
        /\ forgedSuccess = FALSE

\* The decisions a handler may return for each kind (Handler::authenticate).
\* A forged signature is passed as signature_verified = false, which the
\* handler's contract rejects; BadHandler lets it accept anyway.
Decisions(k) ==
  CASE k = "none" -> {"reject"}
    [] k = "pwgood" -> {"accept", "partial"}
    [] k = "pwbad" -> {"reject"}
    [] k = "probe" -> {"accept", "reject"}
    [] k = "signed" -> {"accept", "partial"}
    [] k = "forged" -> IF BadHandler THEN {"accept", "reject"} ELSE {"reject"}
    [] k = "kbd" -> {"challenge", "reject"}
    [] k = "answer" -> {"accept", "reject", "partial"}

Fault == /\ sFault' = TRUE
         /\ UNCHANGED <<s2c, sService, sUser, sSuccess, sFailure, sChallenge,
                        delivered, forgedSuccess>>

\* One packet through `packet`/`authentication`. While a delayed failure
\* waits, `progress` takes no packet; "nowait" is the code before that.
ServerRecv ==
  /\ ~sFault /\ c2s # <<>>
  /\ (~sFailure \/ Mutation = "nowait")
  /\ LET m == Head(c2s) IN
     /\ c2s' = Tail(c2s)
     /\ IF m = "svc" THEN
          IF sService THEN Fault
          ELSE /\ sService' = TRUE /\ s2c' = Append(s2c, "accept_service")
               /\ UNCHANGED <<sUser, sSuccess, sFailure, sChallenge, sFault,
                              delivered, forgedSuccess>>
        ELSE IF m = "conn" THEN
          IF sUser \/ Mutation = "deliver"
          THEN /\ delivered' = TRUE
               /\ UNCHANGED <<s2c, sService, sUser, sSuccess, sFailure,
                              sChallenge, sFault, forgedSuccess>>
          ELSE /\ s2c' = Append(s2c, "unimplemented")
               /\ UNCHANGED <<sService, sUser, sSuccess, sFailure, sChallenge,
                              sFault, delivered, forgedSuccess>>
        ELSE IF sUser /\ Mutation # "answerafter" THEN
          \* A USERAUTH_REQUEST after success is dropped; INFO_RESPONSE
          \* (61) falls to UNIMPLEMENTED.
          /\ s2c' = IF m = "answer" THEN Append(s2c, "unimplemented") ELSE s2c
          /\ UNCHANGED <<sService, sUser, sSuccess, sFailure, sChallenge,
                         sFault, delivered, forgedSuccess>>
        ELSE IF ~sService \/ sFailure THEN Fault
        ELSE IF m = "answer" /\ ~sChallenge THEN Fault
        ELSE
          \E d \in Decisions(m), delay \in BOOLEAN :
            \* A signature that does not verify fails the connection before
            \* the decision is used ("strictsig", the code before the fix),
            \* or only when the handler accepted it.
            IF m = "forged" /\ (d = "accept" \/ Mutation = "strictsig")
               /\ Mutation # "trustsig"
            THEN Fault
            ELSE
            /\ sChallenge' = (d = "challenge")
            /\ CASE d = "accept" /\ m = "probe" ->
                      /\ s2c' = Append(s2c, "pk_ok")
                      /\ UNCHANGED <<sUser, sSuccess, sFailure, forgedSuccess>>
                 [] d = "accept" ->
                      /\ s2c' = Append(s2c, "success")
                      /\ sUser' = TRUE /\ sSuccess' = TRUE
                      /\ forgedSuccess' = (forgedSuccess \/ m = "forged")
                      /\ UNCHANGED sFailure
                 [] d = "challenge" ->
                      /\ s2c' = Append(s2c, "info_request")
                      /\ UNCHANGED <<sUser, sSuccess, sFailure, forgedSuccess>>
                 [] OTHER ->
                      \* Reject: FAILURE now, or after the handler's delay.
                      /\ IF delay THEN /\ sFailure' = TRUE /\ UNCHANGED s2c
                         ELSE /\ s2c' = Append(s2c, IF d = "partial"
                                                    THEN "partial" ELSE "failure")
                              /\ UNCHANGED sFailure
                      /\ UNCHANGED <<sUser, sSuccess, forgedSuccess>>
            /\ UNCHANGED <<sService, sFault, delivered>>
  /\ UNCHANGED <<cAccepted, cOut, cSent, cAuth, cInfo, cViol, early>>

\* Timer::Failure fired: the delayed FAILURE goes out.
ServerTimer ==
  /\ ~sFault /\ sFailure
  /\ sFailure' = FALSE /\ s2c' = Append(s2c, "failure")
  /\ UNCHANGED <<c2s, sService, sUser, sSuccess, sChallenge, sFault,
                 delivered, cAccepted, cOut, cSent, cAuth, cInfo, cViol,
                 early, forgedSuccess>>

\* Client. Requests may be pipelined; a keyboard-interactive exchange is
\* conversational, so nothing is sent while one is outstanding.
Conversing == \E i \in 1..Len(cOut) : cOut[i] \in {"kbd", "answer"}

ClientRequest ==
  /\ cAccepted /\ ~cAuth /\ ~cInfo /\ cSent < MaxReq /\ ~Conversing
  /\ \E k \in Kinds :
       /\ c2s' = Append(c2s, k) /\ cOut' = Append(cOut, k)
  /\ cSent' = cSent + 1
  /\ UNCHANGED <<s2c, sService, sUser, sSuccess, sFailure, sChallenge, sFault,
                 delivered, cAccepted, cAuth, cInfo, cViol, early,
                 forgedSuccess>>

ClientAnswer ==
  /\ cInfo /\ cOut = <<>>
  /\ c2s' = Append(c2s, "answer") /\ cOut' = <<"answer">> /\ cInfo' = FALSE
  /\ UNCHANGED <<s2c, sService, sUser, sSuccess, sFailure, sChallenge, sFault,
                 delivered, cAccepted, cSent, cAuth, cViol, early, forgedSuccess>>

\* Section 5.3: the connection protocol after success.
ClientConn ==
  /\ (cAuth \/ (Early /\ cAccepted /\ ~early)) /\ ~delivered
  /\ \A i \in 1..Len(c2s) : c2s[i] # "conn"
  /\ c2s' = Append(c2s, "conn") /\ early' = (early \/ ~cAuth)
  /\ UNCHANGED <<s2c, sService, sUser, sSuccess, sFailure, sChallenge, sFault,
                 delivered, cAccepted, cOut, cSent, cAuth, cInfo, cViol,
                 forgedSuccess>>

\* Which replies answer which request.
Fits(k, r) ==
  \/ r \in {"failure", "partial"}
  \/ r = "success" /\ k \in {"pwgood", "signed", "answer"}
  \/ r = "pk_ok" /\ k = "probe"
  \/ r = "info_request" /\ k = "kbd"

ClientRecv ==
  /\ s2c # <<>>
  /\ LET r == Head(s2c) IN
     /\ s2c' = Tail(s2c)
     /\ IF r = "accept_service" THEN
          /\ cAccepted' = TRUE
          /\ UNCHANGED <<cOut, cAuth, cInfo, cViol>>
        ELSE IF r = "unimplemented" THEN
          /\ cViol' = IF early THEN cViol ELSE cViol \cup {"unimplemented"}
          /\ UNCHANGED <<cAccepted, cOut, cAuth, cInfo>>
        ELSE IF cOut = <<>> THEN
          /\ cViol' = cViol \cup {"unsolicited"}
          /\ UNCHANGED <<cAccepted, cOut, cAuth, cInfo>>
        ELSE
          /\ cViol' = IF Fits(Head(cOut), r) THEN cViol ELSE cViol \cup {"reply"}
          \* After SUCCESS the requests still in flight are ignored.
          /\ cOut' = IF r = "success" THEN <<>> ELSE Tail(cOut)
          /\ cAuth' = (cAuth \/ r = "success")
          /\ cInfo' = (r = "info_request")
          /\ UNCHANGED cAccepted
  /\ UNCHANGED <<c2s, sService, sUser, sSuccess, sFailure, sChallenge, sFault,
                 delivered, cSent, early, forgedSuccess>>

Next == ServerRecv \/ ServerTimer \/ ClientRequest \/ ClientAnswer
        \/ ClientConn \/ ClientRecv
Spec == Init /\ [][Next]_vars /\ WF_vars(ServerRecv) /\ WF_vars(ServerTimer)
        /\ WF_vars(ClientRecv) /\ WF_vars(ClientAnswer)

NoServerFault == ~sFault
\* Section 5: each request before success is answered once, in order, by
\* a reply its method allows; nothing is answered after success.
AnsweredInOrder == cViol \cap {"unsolicited", "reply", "unimplemented"} = {}
\* Section 5.3: no connection message reaches the service before success.
NoServiceBeforeSuccess == delivered => sSuccess
\* Section 7: a signature that does not verify never authenticates.
NoSuccessWithoutProof == ~forgedSuccess
\* Every request is answered, or overtaken by success.
RequestsAnswered == (cOut # <<>>) ~> (cOut = <<>> \/ cAuth)
\* Coverage, expected to be violated: success after pipelined requests.
NoPipelinedSuccess == ~(cAuth /\ cSent = MaxReq /\ delivered)
=============================================================================
