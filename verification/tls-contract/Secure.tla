---------------------------- MODULE Secure ----------------------------
EXTENDS Naturals, Sequences, TLC
CONSTANTS Bound, WaitEstablished, StopFailed, TakeFactory, TakeBuffer, FIFO, Drain, CaptureNegotiated, Construct
VARIABLES state, queue, slot, produced, received, builds, earlyBuild, badDelivery,
          chosen, negotiated
vars == <<state, queue, slot, produced, received, builds, earlyBuild,
          badDelivery, chosen, negotiated>>

\* Paths below are relative to src/stdlib.
\* services/tls/secure.rs:123-138 drives the lower layer, checks
\* Handshake, consumes make, then drives Chain. Driven::step (189-200)
\* stages output before the guard; extraction (260-266) only moves snapshots.
\* Driven uses Layer's no-op advance (layer/mod.rs:414-416).
\* Chain::advance (layer/chain.rs:143-181) holds one refused event; offer (71-83) preserves its suffix.
\* Later (choice.rs 173-199, 222-231) refuses until set. Lower protocol
\* processing is abstracted by Establish/Fail; early bytes may already be
\* emitted by a replacement. Byte identities represent their stream offsets.
\* The lower contract is FIFO, no loss, and sticky failure. Backpressure is
\* arbitrary. Liveness additionally assumes fair scheduling and no failure.
Init == /\ state = "pending" /\ queue = <<>> /\ slot = <<>>
        /\ produced = <<>> /\ received = <<>> /\ builds = 0
        /\ earlyBuild = FALSE /\ badDelivery = FALSE
        /\ chosen = "unset" /\ negotiated = "unset"
Input == /\ Len(produced) < Bound /\ state # "failed"
         /\ produced' = Append(produced, Len(produced) + 1)
         /\ queue' = Append(queue, Len(produced) + 1)
         /\ UNCHANGED <<state, slot, received, builds, earlyBuild,
                         badDelivery, chosen, negotiated>>
Establish == /\ state = "pending"
             /\ state' = "established" /\ negotiated' \in {"h2", "dns", "none"}
             /\ UNCHANGED <<queue, slot, produced, received, builds,
                             earlyBuild, badDelivery, chosen>>
Fail == /\ state # "failed" /\ state' = "failed"
        /\ UNCHANGED <<queue, slot, produced, received, builds, earlyBuild,
                        badDelivery, chosen, negotiated>>
Build == /\ Construct
         /\ (state = "established" \/ ~WaitEstablished)
         /\ (builds = 0 \/ ~TakeFactory) /\ builds < 2
         /\ builds' = builds + 1 /\ chosen' = IF CaptureNegotiated THEN negotiated ELSE "wrong"
         /\ earlyBuild' = (earlyBuild \/ state # "established")
         /\ UNCHANGED <<state, queue, slot, produced, received, badDelivery, negotiated>>
Move == /\ slot = <<>> /\ queue # <<>>
        /\ slot' = <<IF FIFO THEN Head(queue) ELSE queue[Len(queue)]>>
        /\ queue' = IF FIFO THEN Tail(queue) ELSE SubSeq(queue, 1, Len(queue)-1)
        /\ UNCHANGED <<state, produced, received, builds, earlyBuild,
                        badDelivery, chosen, negotiated>>
Deliver == /\ builds > 0 /\ slot # <<>> /\ Drain
           /\ (state # "failed" \/ ~StopFailed)
           /\ Len(received) < Bound + 1
           /\ received' = Append(received, Head(slot))
           /\ slot' = IF TakeBuffer THEN <<>> ELSE slot
           /\ badDelivery' = (badDelivery \/ state # "established")
           /\ UNCHANGED <<state, queue, produced, builds, earlyBuild, chosen, negotiated>>
Next == Input \/ Establish \/ Fail \/ Build \/ Move \/ Deliver
Spec == Init /\ [][Next]_vars
LiveSpec == Spec /\ WF_vars(Build) /\ WF_vars(Move) /\ WF_vars(Deliver)
Deferred == ~earlyBuild
NoPlaintextOutsideEstablished == ~badDelivery
FactoryOnce == builds <= 1
NegotiatedValue == builds > 0 => chosen = negotiated
ExactlyOnce == \A i,j \in 1..Len(received): received[i] = received[j] => i = j
InOrder == received = SubSeq(produced, 1, Len(received))
\* Every accepted offset eventually appears unless negotiation fails.
Progress == \A n \in 1..Bound: (n <= Len(produced) /\ state = "established") ~> (state = "failed" \/ n <= Len(received))
FactoryProgress == (state = "established") ~> (builds > 0 \/ state = "failed")
=============================================================================
