---------------------------- MODULE Window ----------------------------
\* RFC 4254 section 5.2 flow control on echo channels, between the server
\* as written and a russh client that queues a bounded number of messages
\* per channel.
\* Server source: src/stdlib/services/ssh.rs `Channel::consume_receive`
\* (data within the advertised window), `Channel::adjustment` (the room
\* owed, once it is at least what the peer has left), `progress` (one
\* confirmation, adjustment or credit per step, round robin over the
\* channels), `on_command` (Credit from Children raises `receive`),
\* `connection_message` (EOF, data, channel requests);
\* src/stdlib/services/ssh/session.rs (the reply to exec; each input
\* callback's echo is one output chunk, so one CHANNEL_DATA; exit status,
\* EOF and CLOSE after the output); src/stdlib/layer/children.rs (credit
\* comes back when the child has taken the data).
\* Client: russh 0.64 `client` session loop. One loop reads the socket and
\* pushes each channel message, WINDOW_ADJUST included, into that
\* channel's queue of channel_buffer_size (100) places; while a push waits
\* for room, the loop sends nothing either. The application of the test
\* `full_windows_on_open_channels_finish_with_an_adjustment_per_half_window`
\* opens every channel with exec (want_reply), then for each channel in
\* turn sends S bytes and EOF before it reads that channel's queue to
\* CLOSE ("batch"); or it reads every queue while it sends ("reads").
\* Abstractions. One unit is one client packet; the client's packets are
\* all one unit (the test's 1 KiB blocks) and each is echoed as one unit.
\* The server's send window and the output limit are taken as never
\* binding: russh's default window is 2 MiB and the output limit 256 KiB,
\* both above the echo of one 64 KiB window. Q is the client queue scaled
\* with the window: the real test has W = 64 units and Q = 100.
EXTENDS Naturals, Sequences
CONSTANTS Mutation, N, W, S, Q, Batch

Ch == 1..N
NoMsg == [ch |-> 0, t |-> "none", n |-> 0]

VARIABLES c2s, s2c, adv, rcv, held, out, gotEof, stage, fault, adjusts,
          cwin, sent, sentEof, queue, closeIn, done, pushing, cur
vars == <<c2s, s2c, adv, rcv, held, out, gotEof, stage, fault, adjusts,
          cwin, sent, sentEof, queue, closeIn, done, pushing, cur>>

Init == /\ c2s = [i \in 1..N |-> [ch |-> i, t |-> "exec"]] /\ s2c = <<>>
        \* Confirmed with the full window: Children lent W of credit.
        /\ adv = [i \in Ch |-> W] /\ rcv = [i \in Ch |-> W]
        /\ held = [i \in Ch |-> 0] /\ out = [i \in Ch |-> 0]
        /\ gotEof = [i \in Ch |-> FALSE] /\ stage = [i \in Ch |-> 0]
        /\ fault = FALSE /\ adjusts = [i \in Ch |-> 0]
        /\ cwin = [i \in Ch |-> W] /\ sent = [i \in Ch |-> 0]
        /\ sentEof = [i \in Ch |-> FALSE] /\ queue = [i \in Ch |-> 0]
        /\ closeIn = [i \in Ch |-> FALSE] /\ done = [i \in Ch |-> FALSE]
        /\ pushing = NoMsg /\ cur = 1

\* Channel::adjustment, and the per-packet policy it replaced ("perpacket").
Owed(i) == rcv[i] - adv[i]
Due(i) == IF Mutation = "perpacket" THEN Owed(i) > 0
          ELSE IF Mutation = "never" THEN FALSE
          ELSE Owed(i) > 0 /\ Owed(i) >= adv[i]
Amount(i) == IF Mutation = "over" THEN Owed(i) + 1 ELSE Owed(i)

Send(m) == s2c' = Append(s2c, m)
Msg(i, t, n) == [ch |-> i, t |-> t, n |-> n]

\* The connection takes one client message.
ServerRecv ==
  /\ ~fault /\ c2s # <<>>
  /\ LET m == Head(c2s) IN
     /\ c2s' = Tail(c2s)
     /\ CASE m.t = "exec" ->
               /\ Send(Msg(m.ch, "reply", 0))
               /\ UNCHANGED <<adv, rcv, held, gotEof, fault>>
          [] m.t = "data" ->
               \* consume_receive: within the advertised window and credit.
               IF adv[m.ch] = 0 \/ rcv[m.ch] = 0 \/ gotEof[m.ch]
               THEN /\ fault' = TRUE
                    /\ UNCHANGED <<s2c, adv, rcv, held, gotEof>>
               ELSE /\ adv' = [adv EXCEPT ![m.ch] = @ - 1]
                    /\ rcv' = [rcv EXCEPT ![m.ch] = @ - 1]
                    /\ held' = [held EXCEPT ![m.ch] = @ + 1]
                    /\ UNCHANGED <<s2c, gotEof, fault>>
          [] m.t = "eof" ->
               /\ gotEof' = [gotEof EXCEPT ![m.ch] = TRUE]
               /\ UNCHANGED <<s2c, adv, rcv, held, fault>>
  /\ UNCHANGED <<out, stage, adjusts, cwin, sent, sentEof, queue, closeIn, done,
                 pushing, cur>>

\* progress: an adjustment when one is due.
ServerAdjust(i) ==
  /\ ~fault /\ stage[i] < 3 /\ Due(i)
  /\ Send(Msg(i, "adjust", Amount(i)))
  /\ adv' = [adv EXCEPT ![i] = @ + Amount(i)]
  /\ adjusts' = [adjusts EXCEPT ![i] = @ + 1]
  /\ UNCHANGED <<c2s, rcv, held, out, gotEof, stage, fault, cwin, sent, sentEof,
                 queue, closeIn, done, pushing, cur>>

\* The child takes one unit and echoes it; Children gives the credit back.
ChildTake(i) ==
  /\ ~fault /\ held[i] > 0
  /\ held' = [held EXCEPT ![i] = @ - 1] /\ rcv' = [rcv EXCEPT ![i] = @ + 1]
  /\ out' = [out EXCEPT ![i] = @ + 1]
  /\ UNCHANGED <<c2s, s2c, adv, gotEof, stage, fault, adjusts, cwin, sent,
                 sentEof, queue, closeIn, done, pushing, cur>>

\* One echo chunk goes out as one CHANNEL_DATA.
ServerData(i) ==
  /\ ~fault /\ out[i] > 0
  /\ Send(Msg(i, "data", 1)) /\ out' = [out EXCEPT ![i] = @ - 1]
  /\ UNCHANGED <<c2s, adv, rcv, held, gotEof, stage, fault, adjusts, cwin, sent,
                 sentEof, queue, closeIn, done, pushing, cur>>

\* After EOF and its output, exit status, EOF and CLOSE, in that order.
ServerExit(i) ==
  /\ ~fault /\ gotEof[i] /\ held[i] = 0 /\ out[i] = 0 /\ stage[i] < 3
  /\ Send(Msg(i, CASE stage[i] = 0 -> "exit" [] stage[i] = 1 -> "eof"
                      [] stage[i] = 2 -> "close", 0))
  /\ stage' = [stage EXCEPT ![i] = @ + 1]
  /\ UNCHANGED <<c2s, adv, rcv, held, out, gotEof, fault, adjusts, cwin, sent,
                 sentEof, queue, closeIn, done, pushing, cur>>

\* The russh loop reads the next message from the socket.
LoopRead ==
  /\ pushing = NoMsg /\ s2c # <<>>
  /\ pushing' = Head(s2c) /\ s2c' = Tail(s2c)
  /\ UNCHANGED <<c2s, adv, rcv, held, out, gotEof, stage, fault, adjusts, cwin,
                 sent, sentEof, queue, closeIn, done, cur>>

\* ... and pushes it into its channel's queue once there is a place.
LoopPush ==
  /\ pushing # NoMsg /\ queue[pushing.ch] < Q
  /\ queue' = [queue EXCEPT ![pushing.ch] = @ + 1]
  /\ cwin' = IF pushing.t = "adjust"
             THEN [cwin EXCEPT ![pushing.ch] = @ + pushing.n] ELSE cwin
  /\ closeIn' = IF pushing.t = "close"
                THEN [closeIn EXCEPT ![pushing.ch] = TRUE] ELSE closeIn
  /\ pushing' = NoMsg
  /\ UNCHANGED <<c2s, s2c, adv, rcv, held, out, gotEof, stage, fault, adjusts,
                 sent, sentEof, done, cur>>

\* Which channels the application is working on.
Active(i) == IF Batch THEN i = cur ELSE TRUE

\* channel.data(): one unit within the window, through the loop.
AppSend(i) ==
  /\ Active(i) /\ pushing = NoMsg /\ sent[i] < S /\ cwin[i] > 0
  /\ c2s' = Append(c2s, [ch |-> i, t |-> "data"])
  /\ sent' = [sent EXCEPT ![i] = @ + 1] /\ cwin' = [cwin EXCEPT ![i] = @ - 1]
  /\ UNCHANGED <<s2c, adv, rcv, held, out, gotEof, stage, fault, adjusts,
                 sentEof, queue, closeIn, done, pushing, cur>>

AppEof(i) ==
  /\ Active(i) /\ pushing = NoMsg /\ sent[i] = S /\ ~sentEof[i]
  /\ c2s' = Append(c2s, [ch |-> i, t |-> "eof"])
  /\ sentEof' = [sentEof EXCEPT ![i] = TRUE]
  /\ UNCHANGED <<s2c, adv, rcv, held, out, gotEof, stage, fault, adjusts, cwin,
                 sent, queue, closeIn, done, pushing, cur>>

\* channel.wait(): batch reads only after its EOF; CLOSE is read last.
AppRead(i) ==
  /\ Active(i) /\ (Batch => sentEof[i]) /\ queue[i] > 0
  /\ queue' = [queue EXCEPT ![i] = @ - 1]
  /\ LET fin == closeIn[i] /\ queue[i] = 1 IN
     /\ done' = IF fin THEN [done EXCEPT ![i] = TRUE] ELSE done
     /\ cur' = IF fin /\ Batch /\ cur < N THEN cur + 1 ELSE cur
  /\ UNCHANGED <<c2s, s2c, adv, rcv, held, out, gotEof, stage, fault, adjusts,
                 cwin, sent, sentEof, closeIn, pushing>>

Server == ServerRecv \/ \E i \in Ch : ServerAdjust(i) \/ ChildTake(i)
          \/ ServerData(i) \/ ServerExit(i)
Client == LoopRead \/ LoopPush \/ \E i \in Ch : AppSend(i) \/ AppEof(i) \/ AppRead(i)
Next == Server \/ Client
Spec == Init /\ [][Next]_vars /\ WF_vars(Server) /\ WF_vars(LoopRead)
        /\ WF_vars(LoopPush) /\ \A i \in Ch : WF_vars(AppSend(i))
        /\ WF_vars(AppEof(i)) /\ WF_vars(AppRead(i))
        /\ WF_vars(ServerAdjust(i)) /\ WF_vars(ChildTake(i))
        /\ WF_vars(ServerData(i)) /\ WF_vars(ServerExit(i))

InFlight(i, t) == Len(SelectSeq(c2s, LAMBDA m : m.ch = i /\ m.t = t))
AdjustInFlight(i) ==
  LET f[k \in 0..Len(s2c)] ==
        IF k = 0 THEN 0
        ELSE f[k - 1] + (IF s2c[k].ch = i /\ s2c[k].t = "adjust" THEN s2c[k].n ELSE 0)
  IN f[Len(s2c)] + (IF pushing.ch = i /\ pushing.t = "adjust" THEN pushing.n ELSE 0)

\* Section 5.2, receiver: data never arrives past the advertised window.
ReceiveWindow == ~fault
\* What the peer may send is what it was told, less what is on the way,
\* plus adjustments it has not read yet.
WindowAccounting == \A i \in Ch :
  cwin[i] + InFlight(i, "data") + AdjustInFlight(i) = adv[i]
\* The server never tells the peer of room it does not have: advertised
\* stays within the credit Children lent (adv <= receive in the code).
AdvertisedWithinCredit == \A i \in Ch : adv[i] <= rcv[i]
\* Every channel's echo, exit status and CLOSE reach the application.
AllClosed == <>(\A i \in Ch : done[i])
=============================================================================
