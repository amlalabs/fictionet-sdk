---------------------------- MODULE Adjust ----------------------------
\* How many WINDOW_ADJUST messages one channel sends while its peer sends
\* S bytes into a window of W, over every order of the server's steps.
\* Source: src/stdlib/services/ssh.rs `Channel::adjustment` (owed =
\* receive - advertised, due once owed > 0 and owed >= advertised),
\* `Channel::consume_receive` (data lowers advertised and receive),
\* `progress` (an adjustment raises advertised by what is owed),
\* `on_command` (Credit from Children raises receive once the child has
\* taken the data); src/stdlib/layer/children.rs (credit is lent per
\* child: receive + held = W).
\* Units are 1 KiB, the test's client packets: W = 64 is the server's
\* 64 KiB window and S = W the test's full window, at full scale.
\* The schedule is free: the child may lag behind the connection by any
\* amount, and an adjustment may go out at any step where it is due.
\* This bounds the messages a russh client queues for the channel before
\* it reads (Window.tla): one reply, S echoes and at most Most(W)
\* adjustments, against its 100 places.
EXTENDS Naturals
CONSTANTS Mutation, W, S

VARIABLES consumed, held, adv, adjusts
vars == <<consumed, held, adv, adjusts>>

\* floor(log2 n) + 1 for n >= 1.
RECURSIVE Bits(_)
Bits(n) == IF n <= 1 THEN 1 ELSE 1 + Bits(n \div 2)

Init == consumed = 0 /\ held = 0 /\ adv = W /\ adjusts = 0

Owed == (W - held) - adv
Due == IF Mutation = "perpacket" THEN Owed > 0 ELSE Owed > 0 /\ Owed >= adv

\* The peer never sends past what it was told.
Consume == /\ consumed < S /\ adv > 0
           /\ consumed' = consumed + 1 /\ held' = held + 1 /\ adv' = adv - 1
           /\ UNCHANGED adjusts
Take == /\ held > 0 /\ held' = held - 1
        /\ UNCHANGED <<consumed, adv, adjusts>>
Adjust == /\ Due /\ adv' = W - held /\ adjusts' = adjusts + 1
          /\ UNCHANGED <<consumed, held>>

Next == Consume \/ Take \/ Adjust
Spec == Init /\ [][Next]_vars

\* At most floor(log2 W) + 1 adjustments for one window: 7 for 64.
Few == adjusts <= Bits(W)
\* The policy never runs the peer dry while room is owed.
NeverDry == (adv = 0 /\ held < W) => Due
\* advertised never passes the credit lent.
WithinCredit == adv <= W - held
\* Coverage, expected to be violated: the bound is reached.
BelowBound == adjusts < Bits(W)
=============================================================================
