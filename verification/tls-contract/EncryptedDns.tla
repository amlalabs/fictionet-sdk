------------------------- MODULE EncryptedDns -------------------------
EXTENDS Naturals, Sequences, FiniteSets
CONSTANTS Queries, Mode, Gate, Fifo, Identity, Consume, Prefix
VARIABLES handshake, next, asking, completed, queue, sent, wire, badTiming
vars == <<handshake,next,asking,completed,queue,sent,wire,badTiming>>

\* Sources: world/net/hosts.rs 1942-1946 builds the application after Secure
\* reports Established. services/tls/secure.rs 123-138 gates construction.
\* world/net/dns/encrypted.rs 531-551 admits and numbers DoT queries;
\* 581-586 removes the matching generation and queues its answer;
\* 607-609 pops the oldest answer, then Framed emits its bytes in order.
\* 730-739 closes over each DoH request's query and returns that answer.
\* web/httpd/native.rs 525-544, 621-630 waits on one response;
\* 776-790, 1065-1073 admits the next request only after it (HTTP/1);
\* web/httpd/http2/respond.rs 509-524 accepts the matching response once;
\* web/httpd/http2.rs 1220-1237 sends prefixes of each stream's front buffer.
\* TLS cryptography, framing lengths and HTTP parsing are abstracted out.
\* Secure supplies the establishment gate; handshake success/failure are
\* alternative terminal outcomes here, not post-establishment transport loss.
\* Two distinguishable bytes per answer expose reorder, replay and misrouting.
\* DoT orders by completion, HTTP/1 by request, HTTP/2 within each exchange.
Init == /\ handshake = "pending" /\ next = 1 /\ asking = {}
        /\ completed = <<>> /\ queue = <<>> /\ wire = <<>>
        /\ sent = [q \in 1..Queries |-> 0] /\ badTiming = FALSE
Settle(s) == /\ handshake = "pending" /\ handshake' = s
             /\ UNCHANGED <<next,asking,completed,queue,sent,wire,badTiming>>
Admit == /\ next <= Queries /\ (~Gate \/ handshake = "established")
         /\ (Mode # "doh1" \/ (asking = {} /\ queue = <<>>))
         /\ asking' = asking \cup {next} /\ next' = next+1
         /\ badTiming' = (badTiming \/ handshake # "established")
         /\ UNCHANGED <<handshake,completed,queue,sent,wire>>
Complete(q) == /\ q \in asking /\ Len(completed) < Queries+1
               /\ asking' = IF Consume THEN asking \ {q} ELSE asking
               /\ completed' = Append(completed,q)
               /\ queue' = Append(queue,q)
               /\ UNCHANGED <<handshake,next,sent,wire,badTiming>>
Remove(s,q) == SelectSeq(s,LAMBDA x: x # q)
Send(q) ==
    /\ q \in {queue[i]: i \in 1..Len(queue)}
    /\ (Mode = "doh2" \/ ~Fifo \/ q = Head(queue))
    /\ sent[q] < 2
    /\ sent' = [sent EXCEPT ![q] = @+1]
    /\ wire' = Append(wire,[query |-> q, byte |-> IF Prefix THEN sent[q]+1 ELSE 2-sent[q],
                            target |-> IF Identity THEN q ELSE (q % Queries)+1])
    /\ queue' = IF sent[q] = 1 THEN Remove(queue,q) ELSE queue
    /\ badTiming' = (badTiming \/ handshake # "established")
    /\ UNCHANGED <<handshake,next,asking,completed>>
Next == Settle("established") \/ Settle("failed") \/ Admit
        \/ (\E q \in 1..Queries: Complete(q) \/ Send(q))
Spec == Init /\ [][Next]_vars
EstablishedOnly == ~badTiming
CompletedOnce == Len(completed) = Cardinality({completed[i]: i \in 1..Len(completed)})
ResponseIdentity == \A i \in 1..Len(wire): wire[i].query = wire[i].target
ByteOrder == \A q \in 1..Queries:
    LET bytes == SelectSeq(wire,LAMBDA b: b.query = q)
    IN \A i \in 1..Len(bytes): bytes[i].byte = i
ResponseOrder == Mode = "doh2" \/
    \A i \in 1..Len(wire): wire[i].query = completed[((i-1) \div 2)+1]
\* This stronger requested reading is false without changing the code:
\* independent DoT work and HTTP/2 streams need not finish in query order.
RequestOrder == \A i \in 1..Len(wire):
    wire[i].query = ((i-1) \div 2)+1
=======================================================================
