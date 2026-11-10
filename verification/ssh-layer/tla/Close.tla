---------------------------- MODULE Close ----------------------------
\* RFC 4254 channel open replies, requests, EOF and CLOSE, between the
\* server as written and any client the RFC allows, over two FIFO links.
\* Server source: src/stdlib/services/ssh.rs `connection_message`
\* (CHANNEL_OPEN past the channel limit or with max_packet 0 is refused,
\* an opening the budget cannot hold is refused for resource shortage;
\* data, requests, EOF and CLOSE on the channel), `refuse` (Closing to
\* reason code), `on_command` (Close of an unconfirmed channel refuses it
\* with the receiver's cause; Accept(false) is prohibited; local EOF,
\* local CLOSE, replies and exit status), `progress` (confirmation once
\* accepted with receive credit); src/stdlib/layer/children.rs (a child
\* past the limit or one the factory declines is Prohibited, one the
\* budget cannot reserve is ResourceShortage, one that fails before it is
\* confirmed is Failed); src/stdlib/services/ssh/session.rs (replies in
\* request order; exit status, then EOF, then CLOSE).
\* Client: RFC 4254 sections 5.1 (one OPEN_CONFIRMATION or OPEN_FAILURE
\* per CHANNEL_OPEN, with a reason code: 1 administratively prohibited,
\* 2 connect failed, 4 resource shortage), 5.3 (no data after EOF; a
\* CLOSE is answered with CLOSE unless one was sent; nothing is sent on a
\* channel after its CLOSE; the channel stays open for a party until it
\* has both sent and received CLOSE), 5.4 (a request with want_reply is
\* answered with SUCCESS or FAILURE, in order), 6.10 (exit status before
\* the channel closes).
\* Abstractions. One channel; its window is Channel.tla's subject and is
\* never short here. Data carries no bytes. Causes of refusal stand for
\* the code paths named above. The mapping of each cause to a reason code
\* follows RFC 4254 section 5.1's names and OpenSSH's choice of 1 for its
\* session limit (MaxSessions).
EXTENDS Naturals, Sequences
CONSTANTS Mutation, MaxData, MaxReq

Causes == {"limit", "memory_open", "memory_child", "declined", "app_no",
           "failed"}
Expected(c) == CASE c \in {"limit", "declined", "app_no"} -> 1
                 [] c = "failed" -> 2
                 [] c \in {"memory_open", "memory_child"} -> 4

VARIABLES c2s, s2c, sPhase, cause, sSentEof, sSentClose, sGotEof, sExit,
          sData, sFault, cPhase, cSentEof, cSentClose, cGotEof, cGotClose,
          cGotExit, cData, cReq, cWant, cViol, code
vars == <<c2s, s2c, sPhase, cause, sSentEof, sSentClose, sGotEof, sExit,
          sData, sFault, cPhase, cSentEof, cSentClose, cGotEof, cGotClose,
          cGotExit, cData, cReq, cWant, cViol, code>>
srv == <<sPhase, cause, sSentEof, sSentClose, sGotEof, sExit, sData, sFault>>
cli == <<cPhase, cSentEof, cSentClose, cGotEof, cGotClose, cGotExit, cData,
         cReq, cWant, cViol, code>>

Init == /\ c2s = <<[t |-> "open"]>> /\ s2c = <<>>
        /\ sPhase = "none" /\ cause = "none" /\ sSentEof = FALSE
        /\ sSentClose = FALSE /\ sGotEof = FALSE /\ sExit = FALSE
        /\ sData = 0 /\ sFault = FALSE
        /\ cPhase = "opening" /\ cSentEof = FALSE /\ cSentClose = FALSE
        /\ cGotEof = FALSE /\ cGotClose = FALSE /\ cGotExit = FALSE
        /\ cData = 0 /\ cReq = 0 /\ cWant = 0 /\ cViol = {} /\ code = 0

\* refuse: Closing to reason code. "allone" is the code before 96688e01c.
Reason(c) == IF Mutation = "allone" THEN 1
             ELSE CASE c \in {"limit", "declined", "app_no"} -> 1
                    [] c = "memory_open" -> 4
                    [] c = "memory_child" -> 4
                    [] c = "failed" -> 2

Out(m) == s2c' = Append(s2c, m)
Refuse(c) == /\ Out([t |-> "open_failure", reason |-> Reason(c)])
             /\ sPhase' = "refused" /\ cause' = c

\* Messages that arrive after our CLOSE were sent before the peer had it:
\* they are dropped ("latefault" is the code before, which failed the
\* connection on data or a request; "replyafter" answers requests).
Late == sSentClose /\ Mutation # "replyafter"

ServerRecv ==
  /\ ~sFault /\ c2s # <<>>
  /\ LET m == Head(c2s) IN
     /\ c2s' = Tail(c2s)
     /\ CASE m.t = "open" ->
               \/ /\ \E c \in {"limit", "memory_open"} : Refuse(c)
                  /\ UNCHANGED <<sSentEof, sSentClose, sGotEof, sExit, sData,
                                 sFault>>
               \/ /\ sPhase' = "opening"
                  /\ UNCHANGED <<s2c, cause, sSentEof, sSentClose, sGotEof,
                                 sExit, sData, sFault>>
          [] m.t = "data" ->
               IF sSentClose /\ Mutation = "latefault" THEN
                 /\ sFault' = TRUE
                 /\ UNCHANGED <<s2c, sPhase, cause, sSentEof, sSentClose,
                                sGotEof, sExit, sData>>
               ELSE IF sGotEof \/ sPhase # "open" THEN
                 /\ sFault' = TRUE
                 /\ UNCHANGED <<s2c, sPhase, cause, sSentEof, sSentClose,
                                sGotEof, sExit, sData>>
               ELSE (UNCHANGED srv /\ UNCHANGED s2c)
          [] m.t = "request" ->
               IF sSentClose /\ Mutation = "latefault" THEN
                 /\ sFault' = TRUE
                 /\ UNCHANGED <<s2c, sPhase, cause, sSentEof, sSentClose,
                                sGotEof, sExit, sData>>
               ELSE IF Late \/ ~m.want THEN (UNCHANGED srv /\ UNCHANGED s2c)
               ELSE /\ \E ok \in BOOLEAN : Out([t |-> IF ok THEN "success"
                                                      ELSE "failure"])
                    /\ UNCHANGED srv
          [] m.t = "eof" ->
               IF sGotEof THEN
                 /\ sFault' = TRUE
                 /\ UNCHANGED <<s2c, sPhase, cause, sSentEof, sSentClose,
                                sGotEof, sExit, sData>>
               ELSE /\ sGotEof' = TRUE
                    /\ UNCHANGED <<s2c, sPhase, cause, sSentEof, sSentClose,
                                   sExit, sData, sFault>>
          [] m.t = "close" ->
               \* The channel is gone once CLOSE went both ways.
               /\ IF sSentClose /\ Mutation # "doubleclose"
                  THEN UNCHANGED s2c ELSE Out([t |-> "close"])
               /\ sSentClose' = TRUE /\ sPhase' = "gone"
               /\ UNCHANGED <<cause, sSentEof, sGotEof, sExit, sData, sFault>>
  /\ UNCHANGED cli

\* Children and the application decide on the opening.
ServerDecide ==
  /\ ~sFault /\ sPhase = "opening"
  /\ \/ /\ \E c \in {"memory_child", "declined", "app_no", "failed"} : Refuse(c)
     \/ /\ Out([t |-> "confirm"]) /\ sPhase' = "open"
        /\ UNCHANGED cause
  /\ UNCHANGED <<c2s, sSentEof, sSentClose, sGotEof, sExit, sData, sFault, cli>>

Open == ~sFault /\ sPhase = "open" /\ ~sSentClose

ServerData ==
  /\ Open /\ ~sSentEof /\ sData < MaxData
  /\ Out([t |-> "data"]) /\ sData' = sData + 1
  /\ UNCHANGED <<c2s, sPhase, cause, sSentEof, sSentClose, sGotEof, sExit,
                 sFault, cli>>

\* The session ends: exit status, then EOF, then CLOSE.
ServerExit ==
  /\ Open /\ ~sExit /\ ~sSentEof
  /\ Out([t |-> "exit"]) /\ sExit' = TRUE
  /\ UNCHANGED <<c2s, sPhase, cause, sSentEof, sSentClose, sGotEof, sData,
                 sFault, cli>>
ServerEof ==
  /\ Open /\ ~sSentEof
  /\ Out([t |-> "eof"]) /\ sSentEof' = TRUE
  /\ UNCHANGED <<c2s, sPhase, cause, sSentClose, sGotEof, sExit, sData,
                 sFault, cli>>
ServerClose ==
  /\ Open
  /\ Out([t |-> "close"]) /\ sSentClose' = TRUE
  /\ UNCHANGED <<c2s, sPhase, cause, sSentEof, sGotEof, sExit, sData,
                 sFault, cli>>

\* Client.
CIn(m) == c2s' = Append(c2s, m)
COpen == cPhase = "open" /\ ~cSentClose

ClientData ==
  /\ COpen /\ ~cSentEof /\ cData < MaxData
  /\ CIn([t |-> "data"]) /\ cData' = cData + 1
  /\ UNCHANGED <<s2c, srv, cPhase, cSentEof, cSentClose, cGotEof, cGotClose,
                 cGotExit, cReq, cWant, cViol, code>>
ClientRequest ==
  /\ COpen /\ cReq < MaxReq
  /\ \E w \in BOOLEAN : /\ CIn([t |-> "request", want |-> w])
                        /\ cWant' = IF w THEN cWant + 1 ELSE cWant
  /\ cReq' = cReq + 1
  /\ UNCHANGED <<s2c, srv, cPhase, cSentEof, cSentClose, cGotEof, cGotClose,
                 cGotExit, cData, cViol, code>>
ClientEof ==
  /\ COpen /\ ~cSentEof
  /\ CIn([t |-> "eof"]) /\ cSentEof' = TRUE
  /\ UNCHANGED <<s2c, srv, cPhase, cSentClose, cGotEof, cGotClose, cGotExit,
                 cData, cReq, cWant, cViol, code>>
ClientClose ==
  /\ COpen
  /\ CIn([t |-> "close"]) /\ cSentClose' = TRUE
  /\ UNCHANGED <<s2c, srv, cPhase, cSentEof, cGotEof, cGotClose, cGotExit,
                 cData, cReq, cWant, cViol, code>>

ClientRecv ==
  /\ s2c # <<>>
  /\ LET m == Head(s2c)
         after == IF cGotClose THEN {"afterclose"} ELSE {}
     IN
     /\ s2c' = Tail(s2c)
     /\ CASE m.t = "confirm" ->
               /\ cViol' = cViol \cup (IF cPhase = "opening" THEN {} ELSE {"reply"})
               /\ cPhase' = "open"
               /\ UNCHANGED <<c2s, cSentEof, cSentClose, cGotEof, cGotClose,
                              cGotExit, cData, cReq, cWant, code>>
          [] m.t = "open_failure" ->
               /\ cViol' = cViol \cup (IF cPhase = "opening" THEN {} ELSE {"reply"})
               /\ cPhase' = "refused" /\ code' = m.reason
               /\ UNCHANGED <<c2s, cSentEof, cSentClose, cGotEof, cGotClose,
                              cGotExit, cData, cReq, cWant>>
          [] m.t = "data" ->
               /\ cViol' = cViol \cup after \cup
                           (IF cGotEof THEN {"aftereof"} ELSE {})
               /\ UNCHANGED <<c2s, cPhase, cSentEof, cSentClose, cGotEof,
                              cGotClose, cGotExit, cData, cReq, cWant, code>>
          [] m.t = "exit" ->
               /\ cViol' = cViol \cup after
               /\ cGotExit' = TRUE
               /\ UNCHANGED <<c2s, cPhase, cSentEof, cSentClose, cGotEof,
                              cGotClose, cData, cReq, cWant, code>>
          [] m.t = "eof" ->
               /\ cViol' = cViol \cup after \cup
                           (IF cGotEof THEN {"eoftwice"} ELSE {})
               /\ cGotEof' = TRUE
               /\ UNCHANGED <<c2s, cPhase, cSentEof, cSentClose, cGotClose,
                              cGotExit, cData, cReq, cWant, code>>
          [] m.t \in {"success", "failure"} ->
               /\ cViol' = cViol \cup after \cup
                           (IF cWant = 0 THEN {"unsolicited"} ELSE {})
               /\ cWant' = IF cWant > 0 THEN cWant - 1 ELSE 0
               /\ UNCHANGED <<c2s, cPhase, cSentEof, cSentClose, cGotEof,
                              cGotClose, cGotExit, cData, cReq, code>>
          [] m.t = "close" ->
               /\ cViol' = cViol \cup after
               /\ cGotClose' = TRUE
               \* Section 5.3: answer a CLOSE unless one was sent.
               /\ IF cSentClose THEN UNCHANGED <<c2s, cSentClose>>
                  ELSE /\ CIn([t |-> "close"]) /\ cSentClose' = TRUE
               /\ UNCHANGED <<cPhase, cSentEof, cGotEof, cGotExit, cData, cReq,
                              cWant, code>>
  /\ UNCHANGED srv

Next == ServerRecv \/ ServerDecide \/ ServerData \/ ServerExit \/ ServerEof
        \/ ServerClose \/ ClientData \/ ClientRequest \/ ClientEof
        \/ ClientClose \/ ClientRecv
Spec == Init /\ [][Next]_vars /\ WF_vars(ServerRecv) /\ WF_vars(ServerDecide)
        /\ WF_vars(ClientRecv)

NoServerFault == ~sFault
\* Section 5.1: one reply to the open, and a refusal names its cause.
OneOpenReply == "reply" \notin cViol
ReasonCode == cPhase = "refused" => code = Expected(cause)
\* Section 5.3: nothing after CLOSE, no data after EOF, EOF once.
NothingAfterClose == "afterclose" \notin cViol
NoDataAfterEof == cViol \cap {"aftereof", "eoftwice"} = {}
\* Section 5.4: every reply answers a request that asked for one.
RepliesSolicited == "unsolicited" \notin cViol
\* A CLOSE is answered, and the channel is then gone on both sides.
CloseAnswered == (sSentClose \/ cSentClose) ~> (cGotClose /\ sPhase = "gone")
\* Coverage, expected to be violated: data and a request with want_reply
\* from the client wait to be read after the server sent CLOSE.
NoLateArrival == ~(sSentClose /\ sPhase = "open" /\ Len(c2s) >= 2
                   /\ \E i, j \in 1..Len(c2s) :
                        c2s[i].t = "data" /\ c2s[j].t = "request" /\ c2s[j].want)
=============================================================================
