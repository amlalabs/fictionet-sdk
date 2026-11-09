------------------------------ MODULE Pairing ------------------------------
(* Which request each HTTP/1 response answers, as the passive HTTP/1      *)
(* reader keeps it (src/stdlib/dissect/protocols/http1.rs): the request   *)
(* direction queues each request's method, and the response direction     *)
(* takes one for each response, since a response to HEAD has no body and  *)
(* a 2xx to CONNECT starts a tunnel. Either direction may miss bytes: its  *)
(* reader starts over at the next head, and tells the queue.              *)
(*                                                                        *)
(* The client sends N requests, each HEAD or GET (the solver chooses);    *)
(* the server answers each in order with a response whose body framing    *)
(* depends on the method, as a 200 with a length does. A response the     *)
(* reader cannot pair is shown, and its direction is not read further     *)
(* (`Http1State::ToClose`).                                               *)
(*                                                                        *)
(* Source lines, at the commit in README.md:                              *)
(*   Methods::push, request, answer,     http1.rs 326-401                 *)
(*     missed, forget                                                     *)
(*   Http1::miss                         http1.rs 92-96                   *)
(*   Http1::decode (a head read or not;  http1.rs 128-190                 *)
(*     which way the direction carries)                                   *)
(*   Http1::reset, malformed             http1.rs 282, 291-296            *)
(*   read_head (answer, unpaired)        http1.rs 459-501                 *)
(*                                                                        *)
(* Left out: the bytes and bodies themselves, 1xx responses (which take   *)
(* no method), and a response read before its request when the request   *)
(* is held behind a hole that later fills: with no request waiting, the   *)
(* reader takes the request to be neither HEAD nor CONNECT, as for a      *)
(* capture that began after it. The model reads each response only after  *)
(* its request was read or missed.                                        *)
EXTENDS Naturals, Sequences

CONSTANTS N,              \* requests the client sends
          Max,            \* methods the queue keeps (64 in the code)
          MaxGaps,        \* gaps, over both directions
          MarkRequestGap, \* a missed request leaves Lost after those waiting
          ForgetOnResponseGap, \* a missed response makes the pairing unknown
          NoHeadForgets,  \* a direction that read no head counts as one of responses
          MarkFull,       \* a full queue marks its newest entry Lost (the code before: drops the oldest)
          Sticky,         \* once unknown, the pairing stays unknown
          PopEach         \* each response takes its method off the queue

VARIABLES reqs,      \* reqs[k]: the method of request k
          reqNext,   \* the next request the request reader comes to
          respNext,  \* the next response the response reader comes to
          reqRole,   \* the request direction read a head (Http1::requests)
          respRole,  \* the response direction read a head
          queue,     \* Methods::waiting
          unknown,   \* Methods::unknown
          framed,    \* framed[k]: the method response k was framed by, or "unknown"
          stopped,   \* the response direction is not read further
          gaps,      \* gaps so far
          missed,    \* a request or response was missed
          full       \* the queue was ever full
vars == <<reqs, reqNext, respNext, reqRole, respRole, queue, unknown, framed, stopped, gaps,
          missed, full>>

Init == /\ reqs \in [1..N -> {"HEAD", "GET"}]
        /\ reqNext = 1 /\ respNext = 1 /\ reqRole = FALSE /\ respRole = FALSE
        /\ queue = <<>> /\ unknown = FALSE /\ framed = <<>> /\ stopped = FALSE
        /\ gaps = 0 /\ missed = FALSE /\ full = FALSE

(* Methods::push *)
Push(q, m) ==
  IF unknown \/ (q # <<>> /\ q[Len(q)] = "lost") THEN q
  ELSE IF Len(q) >= Max
       THEN IF MarkFull THEN [q EXCEPT ![Len(q)] = "lost"] ELSE Append(Tail(q), m)
       ELSE Append(q, m)

(* The request reader reads request reqNext. *)
ReadRequest ==
  /\ reqNext <= N
  /\ queue' = Push(queue, reqs[reqNext])
  /\ full' = (full \/ Len(queue) >= Max)
  /\ reqNext' = reqNext + 1 /\ reqRole' = TRUE
  /\ UNCHANGED <<reqs, respNext, respRole, unknown, framed, stopped, gaps, missed>>

(* Methods::missed, as Http1::miss calls it: a direction that read a     *)
(* head of requests leaves Lost; one of responses, or one that read no    *)
(* head, forgets.                                                         *)
Missed(asRequests) ==
  IF asRequests
  THEN /\ queue' = IF MarkRequestGap THEN Push(queue, "lost") ELSE queue
       /\ UNCHANGED unknown
  ELSE /\ queue' = IF ForgetOnResponseGap THEN <<>> ELSE queue
       /\ unknown' = (unknown \/ ForgetOnResponseGap)

(* Http1::miss for the request direction: requests from reqNext on, up to *)
(* `upto`, are missed.                                                    *)
MissRequests(upto) ==
  /\ reqNext <= upto /\ upto <= N /\ gaps < MaxGaps
  /\ Missed(reqRole \/ ~NoHeadForgets)
  /\ reqNext' = upto + 1 /\ gaps' = gaps + 1 /\ missed' = TRUE
  /\ UNCHANGED <<reqs, respNext, reqRole, respRole, framed, stopped, full>>

(* Methods::answer *)
Answer == IF unknown /\ Sticky THEN [m |-> "lost", q |-> queue, u |-> TRUE]
          ELSE IF queue = <<>> THEN [m |-> "GET", q |-> queue, u |-> unknown]
          ELSE IF Head(queue) = "lost" THEN [m |-> "lost", q |-> <<>>, u |-> TRUE]
          ELSE [m |-> Head(queue), q |-> IF PopEach THEN Tail(queue) ELSE queue, u |-> unknown]

(* The response reader reads response respNext, once its request was read *)
(* or missed. Its body is framed by the method; without one it is shown   *)
(* and the direction stops.                                               *)
ReadResponse ==
  /\ ~stopped /\ respNext <= N /\ respNext < reqNext
  /\ LET a == Answer
     IN /\ queue' = a.q /\ unknown' = a.u
        /\ framed' = Append(framed, IF a.m = "lost" THEN "unknown" ELSE a.m)
        /\ stopped' = (a.m = "lost")
  /\ respNext' = respNext + 1 /\ respRole' = TRUE
  /\ UNCHANGED <<reqs, reqNext, reqRole, gaps, missed, full>>

(* Http1::miss for the response direction: responses from respNext on, up *)
(* to `upto`, are missed; the reader starts over at the next head.        *)
MissResponses(upto) ==
  /\ ~stopped /\ respNext <= upto /\ upto <= N /\ upto < reqNext /\ gaps < MaxGaps
  /\ Missed(~respRole /\ ~NoHeadForgets)
  /\ framed' = framed \o [k \in 1..upto - respNext + 1 |-> "missed"]
  /\ respNext' = upto + 1 /\ gaps' = gaps + 1 /\ missed' = TRUE
  /\ UNCHANGED <<reqs, reqNext, reqRole, respRole, stopped, full>>

Next == \/ ReadRequest
        \/ \E u \in 1..N : MissRequests(u) \/ MissResponses(u)
        \/ ReadResponse

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Every response read is framed by the method of the request it answers, *)
(* or by none.                                                            *)
FramedByItsRequest ==
  \A k \in DOMAIN framed : framed[k] \in {reqs[k], "unknown", "missed"}

(* With nothing missed and the queue never full, every response read is   *)
(* framed by its request's method.                                        *)
PairedWithoutLoss ==
  (~missed /\ ~full) => \A k \in DOMAIN framed : framed[k] = reqs[k]
=============================================================================
