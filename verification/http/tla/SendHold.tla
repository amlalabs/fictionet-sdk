---------------------------- MODULE SendHold ----------------------------
(***************************************************************************)
(* Response bodies and received DATA in src/stdlib/web/httpd/http2.rs.    *)
(* ChildData is on_child(Data): a child's already charged chunk moves    *)
(* into Response::queue, spending credit_bytes. SendOne is send_one and   *)
(* grant/more_credit: sendable bounds a frame by both windows and resets  *)
(* stalled_since. NoteStalls is Response::note_stall after advance, for   *)
(* every stream, including ones blocked by another stream's frame.       *)
(* WindowUpdate is the client's WINDOW_UPDATE; withholding one needs no  *)
(* action. Timer is stalled/on_timer, dropping timed out streams with    *)
(* CANCEL. Tick follows Http2::deadline and the runner's timer deadline.  *)
(* ReceiveData, Deliver and ReturnCredit are data/read, deliver and       *)
(* release: accepted DATA spends both receive windows; only bytes no     *)
(* longer held can earn WINDOW_UPDATE. Over-window input is refused and  *)
(* has no accepted transition.                                           *)
(*                                                                       *)
(* A storage unit stands for some payload bytes, a tick for some time.  *)
(* SendCredit scales SEND_CREDIT, ReceiveWindow scales WINDOW (65,535).   *)
(* Each stream is already open, with its response head sent. Queue       *)
(* storage counts the payload owned by this stage, not queue slots or    *)
(* backing allocations shared with output after a chunk is split. The    *)
(* receive reservation is the advertised allowance, including held DATA *)
(* and credit awaiting a WINDOW_UPDATE. Real chunks carry memory charges *)
(* independently; this store checks the receive-window obligation.       *)
(* Bodies, input and time have explicit finite exploration bounds.       *)
(***************************************************************************)
EXTENDS Integers, Sequences, Resources

CONSTANTS Ids, SendCredit, ReceiveWindow, MaxWindow, Frame,
          BodyUnits, ReceiveUnits, WriteTimeout, TimeLimit,
          StallDeadline, TopUpCredit, ReturnCreditWhenFreed

ASSUME /\ Ids # {} /\ SendCredit > 0 /\ ReceiveWindow > 0
       /\ MaxWindow > 0 /\ Frame > 0 /\ WriteTimeout > 0
       /\ BodyUnits > 0 /\ ReceiveUnits > 0 /\ TimeLimit > WriteTimeout

None == -1
Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b
RECURSIVE Sum(_)
Sum(s) == IF s = <<>> THEN 0 ELSE Head(s) + Sum(Tail(s))

VARIABLES queue, credit, bodyLeft, window, connectionWindow, since, live,
          stores, received, recvWindow, recvConnection, recvLeft,
          returnable, receiveStore, now

vars == <<queue, credit, bodyLeft, window, connectionWindow, since, live,
          stores, received, recvWindow, recvConnection, recvLeft,
          returnable, receiveStore, now>>

\* The configs use two streams; this sum also admits arbitrary finite Ids.
RECURSIVE Held(_)
Held(ids) == IF ids = {} THEN 0
             ELSE LET i == CHOOSE j \in ids : TRUE
                  IN received[i] + Held(ids \ {i})

NoteStalls(q, w, c, old) ==
    [i \in Ids |-> IF q[i] = <<>> \/ (w[i] > 0 /\ c > 0) THEN None
                  ELSE IF old[i] = None THEN now ELSE old[i]]

Init ==
    /\ queue = [i \in Ids |-> <<>>]
    /\ credit = [i \in Ids |-> SendCredit]
    /\ bodyLeft = [i \in Ids |-> BodyUnits]
    /\ window \in [Ids -> 0..MaxWindow]
    /\ connectionWindow \in 0..MaxWindow
    /\ since = [i \in Ids |-> None]
    /\ live = [i \in Ids |-> TRUE]
    /\ stores = [i \in Ids |-> Store(SendCredit)]
    /\ received = [i \in Ids |-> 0]
    /\ recvWindow = [i \in Ids |-> ReceiveWindow]
    /\ recvConnection = ReceiveWindow
    /\ recvLeft = [i \in Ids |-> ReceiveUnits]
    /\ returnable = [i \in Ids |-> 0]
    /\ receiveStore = Store(ReceiveWindow)
    /\ now = 0

\* The child has permission and reserves before making its chunk. The
\* reservation here includes its outstanding permission and queued bytes.
ChildData(i, n) ==
    /\ live[i] /\ n <= credit[i] /\ n <= bodyLeft[i]
    /\ queue' = [queue EXCEPT ![i] = Append(@, n)]
    /\ credit' = [credit EXCEPT ![i] = @ - n]
    /\ bodyLeft' = [bodyLeft EXCEPT ![i] = @ - n]
    /\ stores' = [stores EXCEPT ![i] = Grow(Begin(@), n)]
    /\ since' = NoteStalls(queue', window, connectionWindow, since)
    /\ UNCHANGED <<window, connectionWindow, live, received, recvWindow,
                   recvConnection, recvLeft, returnable, receiveStore, now>>

SendOne(i) ==
    /\ live[i] /\ queue[i] # <<>>
    /\ window[i] > 0 /\ connectionWindow > 0
    /\ LET n == Min(Head(queue[i]), Min(Frame, Min(window[i], connectionWindow)))
           rest == IF n = Head(queue[i]) THEN Tail(queue[i])
                   ELSE <<Head(queue[i]) - n>> \o Tail(queue[i])
           more == Max(0, SendCredit - credit[i]
                            - (IF TopUpCredit THEN Sum(rest) ELSE 0))
           sent == Shrink(Begin(stores[i]), n)
           freed == Release(sent, n)
       IN /\ queue' = [queue EXCEPT ![i] = rest]
          /\ window' = [window EXCEPT ![i] = @ - n]
          /\ connectionWindow' = connectionWindow - n
          /\ credit' = [credit EXCEPT ![i] = @ + more]
          /\ stores' = [stores EXCEPT ![i] = Reserve(freed, more)]
          /\ since' = NoteStalls(queue', window', connectionWindow',
                                  [since EXCEPT ![i] = None])
    /\ UNCHANGED <<bodyLeft, live, received, recvWindow, recvConnection,
                   recvLeft, returnable, receiveStore, now>>

WindowUpdate ==
    /\ \/ /\ \E i \in Ids, n \in 1..MaxWindow :
                  /\ live[i] /\ window[i] + n <= MaxWindow
                  /\ window' = [window EXCEPT ![i] = @ + n]
           /\ UNCHANGED connectionWindow
        \/ /\ \E n \in 1..MaxWindow :
                  /\ connectionWindow + n <= MaxWindow
                  /\ connectionWindow' = connectionWindow + n
           /\ UNCHANGED window
    /\ since' = NoteStalls(queue, window', connectionWindow', since)
    /\ UNCHANGED <<queue, credit, bodyLeft, live, stores, received,
                   recvWindow, recvConnection, recvLeft, returnable,
                   receiveStore, now>>

Timer(i) ==
    /\ StallDeadline /\ live[i] /\ since[i] # None
    /\ now >= since[i] + WriteTimeout
    /\ queue' = [queue EXCEPT ![i] = <<>>]
    /\ credit' = [credit EXCEPT ![i] = 0]
    /\ live' = [live EXCEPT ![i] = FALSE]
    /\ since' = [since EXCEPT ![i] = None]
    \* The queue's chunks go, then their charge and the credit.
    /\ stores' = [stores EXCEPT ![i] =
           Release(Shrink(Begin(@), Sum(queue[i])), @.reserved)]
    /\ receiveStore' = Shrink(Begin(receiveStore), received[i])
    /\ received' = [received EXCEPT ![i] = 0]
    /\ returnable' = IF ReturnCreditWhenFreed
                     THEN [returnable EXCEPT ![i] = @ + received[i]] ELSE returnable
    /\ UNCHANGED <<bodyLeft, window, connectionWindow, recvWindow,
                   recvConnection, recvLeft, now>>

Tick ==
    /\ now < TimeLimit
    /\ ~StallDeadline \/
          \A i \in Ids : since[i] = None \/ now + 1 <= since[i] + WriteTimeout
    /\ now' = now + 1
    /\ UNCHANGED <<queue, credit, bodyLeft, window, connectionWindow, since,
                   live, stores, received, recvWindow, recvConnection,
                   recvLeft, returnable, receiveStore>>

ReceiveData(i, n) ==
    /\ live[i] /\ n <= recvLeft[i] /\ n <= recvWindow[i] /\ n <= recvConnection
    /\ received' = [received EXCEPT ![i] = @ + n]
    /\ recvLeft' = [recvLeft EXCEPT ![i] = @ - n]
    /\ recvWindow' = [recvWindow EXCEPT ![i] = @ - n]
    /\ recvConnection' = recvConnection - n
    /\ receiveStore' = Grow(Begin(receiveStore), n)
    /\ returnable' = IF ReturnCreditWhenFreed THEN returnable
                     ELSE [returnable EXCEPT ![i] = @ + n]
    /\ UNCHANGED <<queue, credit, bodyLeft, window, connectionWindow,
                   since, live, stores, now>>

Deliver(i, n) ==
    /\ n <= received[i]
    /\ received' = [received EXCEPT ![i] = @ - n]
    /\ returnable' = IF ReturnCreditWhenFreed
                     THEN [returnable EXCEPT ![i] = @ + n] ELSE returnable
    /\ receiveStore' = Shrink(Begin(receiveStore), n)
    /\ UNCHANGED <<queue, credit, bodyLeft, window, connectionWindow,
                   since, live, stores, recvWindow, recvConnection, recvLeft, now>>

\* A batch may return any earned credit. The real half-window batching
\* only delays this action and cannot increase held DATA. In the control,
\* the new advertised credit adds an obligation while old DATA is held.
ReturnCredit(i, n) ==
    /\ n <= returnable[i]
    /\ returnable' = [returnable EXCEPT ![i] = @ - n]
    /\ recvWindow' = [recvWindow EXCEPT ![i] = @ + n]
    /\ recvConnection' = recvConnection + n
    \* What the client may now send, with what is held, is what the
    \* connection must be able to hold: its reservation rises to it.
    /\ receiveStore' = ReserveTo(Begin(receiveStore), Held(Ids) + recvConnection')
    /\ UNCHANGED <<queue, credit, bodyLeft, window, connectionWindow,
                   since, live, stores, received, recvLeft, now>>

Next == \/ \E i \in Ids, n \in 1..BodyUnits : ChildData(i, n)
        \/ \E i \in Ids : SendOne(i) \/ Timer(i)
        \/ WindowUpdate \/ Tick
        \/ \E i \in Ids, n \in 1..ReceiveUnits :
               ReceiveData(i, n) \/ Deliver(i, n) \/ ReturnCredit(i, n)

Spec == Init /\ [][Next]_vars
QueuePaid == \A i \in Ids : Paid(stores[i])
QueueWithinCredit == \A i \in Ids : WithinLimit(stores[i], SendCredit)
ReceivePaid == Paid(receiveStore)
ReceiveWithinWindow == WithinLimit(receiveStore, ReceiveWindow)
QueuesTrack == \A i \in Ids : Tracks(stores[i], Sum(queue[i]))
ReceiveTracks == Tracks(receiveStore, Held(Ids))
HoldBounded == \A i \in Ids :
    (queue[i] # <<>> /\ (window[i] <= 0 \/ connectionWindow <= 0)) =>
        (since[i] # None /\ now - since[i] <= WriteTimeout)
=============================================================================
